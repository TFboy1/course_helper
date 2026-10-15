import asyncio
from contextlib import asynccontextmanager
import json
import logging
import time
from uuid import uuid4

import httpx

from .config import Settings
from .platforms import Outcome, PlatformClient, PlatformIssue, RAIN_SERVERS, parse_sign_qr
from .store import AccountBindingError, Store, token_hash


log = logging.getLogger("course_helper")


class ServiceError(Exception):
    def __init__(self, status: int, message: str):
        self.status, self.message = status, message


class Service:
    def __init__(self, settings: Settings, store: Store, client_factory=PlatformClient):
        self.settings, self.store, self.client_factory = settings, store, client_factory
        self.tasks: dict[str, asyncio.Task] = {}
        self.account_locks: dict[str, asyncio.Lock] = {}
        self.login_locks: dict[str, asyncio.Lock] = {}
        self.semaphore = asyncio.Semaphore(settings.batch_concurrency)
        self.condition = asyncio.Condition()
        self.versions: dict[str, int] = {}

    def spawn(self, key: str, coroutine):
        task = asyncio.create_task(coroutine, name=key)
        self.tasks[key] = task

        def finish(done):
            self.tasks.pop(key, None)
            if not done.cancelled() and done.exception():
                # 不输出平台异常中的 URL、请求体或登录凭据。
                log.error("后台任务意外结束：%s", type(done.exception()).__name__)

        task.add_done_callback(finish)

    async def changed(self, key: str):
        async with self.condition:
            self.versions[key] = self.versions.get(key, 0) + 1
            if key != "me":
                self.versions["me"] = self.versions.get("me", 0) + 1
            self.condition.notify_all()

    def me_snapshot(self, session_id: str):
        who = self.store.session_info(session_id)
        if not who:
            raise ServiceError(401, "网站会话已过期")
        role = who.get("role", "member")
        with self.store.connection() as db:
            pool = [dict(row) for row in db.execute("SELECT platform,server,COUNT(*) AS count FROM accounts WHERE authorized=1 AND valid=1 AND credentials IS NOT NULL GROUP BY platform,server")]
            group_accounts = [dict(row) for row in db.execute("""SELECT id,platform,server,name,
                (authorized=1 AND valid=1 AND credentials IS NOT NULL) AS active
                FROM accounts ORDER BY active DESC,updated DESC""")] if role == "admin" else None
        job_owner = None if role == "admin" else session_id
        snapshot = {"csrf_token": who["csrf"], "role": role, "accounts": self.store.own_accounts(session_id), "pool": pool,
                    "logged_in_count": sum(item["count"] for item in pool),
                    "jobs": [self.job_snapshot(job_id, session_id) for job_id in self.store.recent_jobs(job_owner)],
                    "logins": [self.login_snapshot(login_id, session_id) for login_id in self.store.pending_logins(session_id)],
                    "servers": list(RAIN_SERVERS)}
        if role == "admin":
            snapshot["group_accounts"] = group_accounts
            snapshot["access_codes"] = self.store.list_access_codes()
        return snapshot

    async def close(self):
        tasks = list(self.tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def login_snapshot(self, login_id: str, session_id: str):
        row = self.store.login(login_id)
        if not row:
            raise ServiceError(404, "登录请求不存在")
        if row["session_id"] != session_id:
            raise ServiceError(403, "无权读取此登录请求")
        meta = self.store.unpack(row["secret"])["meta"]
        status = row["status"]
        if status == "waiting" and row["expires"] <= time.time():
            status = "expired"
        return {"id": row["id"], "platform": row["platform"], "server": row["server"],
                "status": status, "message": row["message"], "expires_at": row["expires"],
                "qr_image_url": meta.get("image", "") if status == "waiting" else "",
                "qr_content": meta.get("content", "") if status == "waiting" else "",
                "account_id": row["account_id"]}

    async def create_login(self, session_id: str, platform: str, server: str):
        async with self.login_locks.setdefault(session_id, asyncio.Lock()):
            if len(self.store.pending_logins(session_id)) >= 2 or len(self.store.pending_logins()) >= 20:
                raise ServiceError(429, "登录二维码请求过多，请关闭旧二维码或稍后再试")
            client = self.client_factory(platform, server)
            try:
                meta = await client.start_login()
                login_id = self.store.create_login(session_id, platform, server,
                    {"meta": meta, "credentials": client.credentials()}, self.settings.login_seconds)
            except BaseException:
                await client.close()
                raise
            if self.settings.serverless:
                await client.close()
            else:
                self.spawn("login:" + login_id, self._poll_login(login_id, client, meta))
            await self.changed("login:" + login_id)
            return self.login_snapshot(login_id, session_id)

    async def refresh_login(self, login_id: str, session_id: str):
        self.login_snapshot(login_id, session_id)
        row = self.store.login(login_id)
        if row["status"] != "waiting":
            return self.login_snapshot(login_id, session_id)
        if row["expires"] <= time.time():
            self.store.login_status(login_id, "expired", "登录二维码已过期，请刷新")
            return self.login_snapshot(login_id, session_id)

        secret = self.store.unpack(row["secret"])
        client = self.client_factory(row["platform"], row["server"], secret.get("credentials", {}))
        try:
            state = await client.poll_login(secret["meta"])
            secret["credentials"] = client.credentials()
            if state == "success":
                profile = await client.profile()
                account_id = self.store.save_account(row["session_id"], row["platform"], row["server"], profile, client.credentials())
                self.store.login_status(login_id, "success", "登录成功，账号已加入共享签到池", account_id)
            elif state == "expired":
                self.store.login_status(login_id, "expired", "登录二维码已过期，请刷新")
            else:
                self.store.update_login_secret(login_id, secret)
        except AccountBindingError as error:
            self.store.login_status(login_id, "failed", str(error))
        except PlatformIssue as error:
            self.store.login_status(login_id, "failed", error.message)
        finally:
            await client.close()
        await self.changed("login:" + login_id)
        return self.login_snapshot(login_id, session_id)

    async def cancel_login(self, login_id: str, session_id: str):
        self.login_snapshot(login_id, session_id)
        task = self.tasks.get("login:" + login_id)
        self.store.login_status(login_id, "cancelled", "登录二维码已关闭")
        if task:
            task.cancel()
        await self.changed("login:" + login_id)

    async def _poll_login(self, login_id: str, client: PlatformClient, meta: dict):
        row = self.store.login(login_id)
        errors = 0
        try:
            while time.time() < row["expires"]:
                if not self.store.session_active(row["session_id"]):
                    self.store.login_status(login_id, "cancelled", "网站会话已退出")
                    return
                try:
                    state = await client.poll_login(meta)
                    errors = 0
                except httpx.HTTPError:
                    errors += 1
                    if errors >= 3:
                        raise PlatformIssue("平台连接暂时不可用，请刷新二维码") from None
                    await asyncio.sleep(2)
                    continue
                if state == "success":
                    profile = await client.profile()
                    if not self.store.session_active(row["session_id"]):
                        self.store.login_status(login_id, "cancelled", "网站会话已退出")
                        return
                    account_id = self.store.save_account(row["session_id"], row["platform"], row["server"], profile, client.credentials())
                    self.store.login_status(login_id, "success", "登录成功，账号已加入共享签到池", account_id)
                    return
                if state == "expired":
                    break
                await asyncio.sleep(3 if client.platform == "chaoxing" else 1)
            self.store.login_status(login_id, "expired", "登录二维码已过期，请刷新")
        except AccountBindingError as error:
            self.store.login_status(login_id, "failed", str(error))
        except PlatformIssue as error:
            self.store.login_status(login_id, "failed", error.message)
        except asyncio.CancelledError:
            if self.store.login(login_id)["status"] == "waiting":
                self.store.login_status(login_id, "expired", "登录已中断，请刷新二维码")
            raise
        except Exception:
            self.store.login_status(login_id, "failed", "平台登录暂时不可用，请刷新二维码或稍后重试")
        finally:
            await client.close()
            await self.changed("login:" + login_id)

    def create_job(self, session_id: str, request_id: str, qr_text: str):
        target = parse_sign_qr(qr_text)
        existing = self.store.existing_job(session_id, request_id)
        if existing:
            if existing["input_hash"] != token_hash(target["url"]):
                raise ServiceError(409, "同一请求 ID 不能提交不同的二维码")
            return self.job_snapshot(existing["id"], session_id)
        pool = self.store.pool(target["platform"], target["server"])
        if not pool:
            raise ServiceError(422, "这个平台还没有有效登录账号")
        with self.store.connection() as db:
            running = db.execute("SELECT COUNT(*) FROM jobs WHERE session_id=? AND status='running'", (session_id,)).fetchone()[0]
        if running >= 2 or sum(key.startswith("job:") for key in self.tasks) >= 20:
            raise ServiceError(429, "已有签到任务在执行，请等待结果后再提交")
        job_id = self.store.create_job(session_id, request_id, target, pool)
        if not self.settings.serverless:
            self.spawn("job:" + job_id, self._run_job(job_id, target, pool))
        return self.job_snapshot(job_id, session_id)

    async def run_job_inline(self, job_id: str):
        job = self.store.job(job_id)
        if not job or job["status"] != "running":
            return
        target = self.store.unpack(job["secret"])
        accounts = [self.store.account(row["account_id"]) for row in self.store.results(job_id)]
        await self._run_job(job_id, target, [account for account in accounts if account])

    def job_snapshot(self, job_id: str, session_id: str):
        job = self.store.job(job_id)
        if not job:
            raise ServiceError(404, "签到任务不存在")
        who = self.store.session_info(session_id)
        if not who:
            raise ServiceError(401, "网站会话已过期")
        is_admin = who.get("role") == "admin"
        owns_job = self.store.same_principal(job["session_id"], session_id)
        own_ids = self.store.owned_ids(session_id)
        all_rows = self.store.results(job_id)
        rows = all_rows if is_admin else [row for row in all_rows if row["account_id"] in own_ids]
        if not is_admin and not owns_job and not rows:
            raise ServiceError(403, "无权读取此签到任务")
        summary = {
            "total": len(all_rows),
            "succeeded": sum(row["status"] in {"success", "already_signed"} for row in all_rows),
            "pending": sum(row["status"] in {"pending", "running"} for row in all_rows),
            "needs_action": sum(row["status"].startswith("needs_") for row in all_rows),
        }
        return {"id": job_id, "platform": job["platform"], "server": job["server"], "status": job["status"],
                "created_at": job["created"], "is_initiator": owns_job, "summary": summary,
                "results": [{key: row[key] for key in ("account_id", "name", "status", "message", "updated")} | {
                    "can_act": is_admin or row["account_id"] in own_ids
                } for row in rows]}

    def can_act(self, job_id: str, account_id: str, session_id: str):
        job = self.store.job(job_id)
        if not job or not self.store.result(job_id, account_id):
            raise ServiceError(404, "签到记录不存在")
        who = self.store.session_info(session_id)
        if not who:
            raise ServiceError(401, "网站会话已过期")
        if who.get("role") != "admin" and not self.store.owns(session_id, account_id):
            raise ServiceError(403, "无权操作此签到记录")
        return job

    def allowed_account(self, account_id: str):
        account = self.store.account(account_id)
        if not account:
            raise PlatformIssue("账号已解绑，本次操作已停止", "skipped")
        if not account["valid"] or not account["credentials"]:
            raise PlatformIssue("平台登录已失效，请重新扫码登录", "session_expired")
        return account

    @asynccontextmanager
    async def account_client(self, account: dict, *, job_id: str | None = None):
        client = self.client_factory(account["platform"], account["server"], self.store.unpack(account["credentials"]), account["uid"])
        client.before_request = lambda: self.allowed_account(account["id"])
        try:
            yield client
        except PlatformIssue as error:
            if error.status == "session_expired":
                self.store.invalidate(account["id"])
                if job_id:
                    await self.outcome(job_id, account["id"], Outcome(error.status, error.message))
            raise
        finally:
            self.store.credentials(account["id"], client.credentials())
            await client.close()

    async def outcome(self, job_id: str, account_id: str, value: Outcome):
        if value.status == "session_expired":
            self.store.invalidate(account_id)
        self.store.update_result(job_id, account_id, value.status, value.message, value.context)
        self.store.update_job_status(job_id)
        await self.changed("job:" + job_id)

    async def _run_job(self, job_id: str, target: dict, accounts: list[dict]):
        try:
            await asyncio.gather(*(self._run_account(job_id, account["id"], target) for account in accounts))
        finally:
            self.store.update_job_status(job_id)
            await self.changed("job:" + job_id)

    async def _run_account(self, job_id: str, account_id: str, target: dict):
        async with self.semaphore:
            lease_owner = None
            lock = None
            claimed = False
            try:
                if self.settings.serverless:
                    lease_owner = str(uuid4())
                    deadline = asyncio.get_running_loop().time() + 180
                    while not self.store.acquire_account_lease(account_id, lease_owner):
                        row = self.store.result(job_id, account_id)
                        if not row or row["status"] != "pending":
                            return
                        if asyncio.get_running_loop().time() >= deadline:
                            if self.store.claim_result(job_id, account_id):
                                await self.outcome(job_id, account_id, Outcome("failed", "账号正由其他签到任务处理，请稍后重试"))
                            return
                        await asyncio.sleep(0.25)
                else:
                    lock = self.account_locks.setdefault(account_id, asyncio.Lock())
                    await lock.acquire()

                if not self.store.claim_result(job_id, account_id):
                    return
                claimed = True
                account = self.allowed_account(account_id)
                async with self.account_client(account) as client:
                    value = await client.sign(target)
                await self.outcome(job_id, account_id, value)
            except PlatformIssue as error:
                if claimed:
                    await self.outcome(job_id, account_id, Outcome(error.status, error.message, {"active_id": target.get("active_id")}))
            except (httpx.TimeoutException, httpx.NetworkError):
                if claimed:
                    await self.outcome(job_id, account_id, Outcome("unknown", "连接中断，结果未确认，请到官方 App 核实", {"active_id": target.get("active_id")}))
            except asyncio.CancelledError:
                if claimed:
                    await self.outcome(job_id, account_id, Outcome("unknown", "服务中断，结果未确认，请到官方 App 核实", {"active_id": target.get("active_id")}))
                raise
            except Exception:
                if claimed:
                    await self.outcome(job_id, account_id, Outcome("failed", "平台暂时未能完成签到，请稍后查看官方 App", {"active_id": target.get("active_id")}))
            finally:
                if lease_owner:
                    self.store.release_account_lease(account_id, lease_owner)
                if lock and lock.locked():
                    lock.release()

    async def unbind(self, account_id: str):
        self.store.delete_account(account_id)
        with self.store.connection() as db:
            job_ids = [row[0] for row in db.execute("SELECT job_id FROM results WHERE account_id=? AND status IN ('pending','needs_captcha','needs_official_verification')", (account_id,))]
        for job_id in job_ids:
            await self.outcome(job_id, account_id, Outcome("skipped", "账号已解绑，此账号停止参与"))
        await self.changed("me")

    async def create_captcha(self, job_id: str, account_id: str, session_id: str):
        self.can_act(job_id, account_id, session_id)
        async with self.account_locks.setdefault(account_id, asyncio.Lock()):
            row = self.store.result(job_id, account_id)
            if row["status"] != "needs_captcha":
                raise ServiceError(409, "此账号目前不需要滑块验证")
            account = self.allowed_account(account_id)
            context = self.store.unpack(row["secret"])
            async with self.account_client(account, job_id=job_id) as client:
                challenge, public = await client.captcha(context["active_id"])
            # 验证图加载期间账号也可能被解绑。
            self.allowed_account(account_id)
            context["challenge"] = challenge
            self.store.update_result(job_id, account_id, "needs_captcha", "请拖动滑块完成验证", context)
            await self.changed("job:" + job_id)
            return public

    async def submit_captcha(self, job_id: str, account_id: str, session_id: str, challenge_id: str, x: float):
        job = self.can_act(job_id, account_id, session_id)
        async with self.account_locks.setdefault(account_id, asyncio.Lock()):
            row = self.store.result(job_id, account_id)
            if row["status"] != "needs_captcha":
                raise ServiceError(409, "签到状态已变化，请刷新结果")
            context = self.store.unpack(row["secret"])
            challenge = context.get("challenge", {})
            if challenge.get("id") != challenge_id or challenge.get("expires", 0) <= time.time() or challenge.get("attempts", 0) >= 3:
                raise ServiceError(409, "验证码已失效，请刷新验证码")
            account = self.allowed_account(account_id)
            async with self.account_client(account, job_id=job_id) as client:
                challenge["attempts"] += 1
                self.store.update_result(job_id, account_id, "needs_captcha", "正在验证滑块", context)
                validate = await client.check_captcha(challenge, x)
                if not validate:
                    raise ServiceError(400, "验证未通过，请调整位置或刷新验证码")
                self.allowed_account(account_id)
                context.pop("challenge", None)
                await self.outcome(job_id, account_id, Outcome("running", "验证通过，继续提交", context))
                try:
                    value = await client.sign(self.store.unpack(job["secret"]), context, validate)
                except PlatformIssue as error:
                    value = Outcome(error.status, error.message, context)
                except (httpx.TimeoutException, httpx.NetworkError):
                    value = Outcome("unknown", "连接中断，结果未确认，请在官方 App 核实", context)
                except asyncio.CancelledError:
                    await self.outcome(job_id, account_id, Outcome("unknown", "补验请求中断，结果未确认，请到官方 App 核实", context))
                    raise
                except Exception:
                    value = Outcome("unknown", "补验请求结果未确认，请在官方 App 核实", context)
            await self.outcome(job_id, account_id, value)
            return self.job_snapshot(job_id, session_id)

    async def refresh_receipt(self, job_id: str, account_id: str, session_id: str):
        job = self.can_act(job_id, account_id, session_id)
        if job["platform"] != "chaoxing":
            raise ServiceError(422, "雨课堂目前没有移植可核对的回执接口，请到官方 App 确认")
        async with self.account_locks.setdefault(account_id, asyncio.Lock()):
            row = self.store.result(job_id, account_id)
            if row["status"] in {"pending", "running"}:
                raise ServiceError(409, "账号正在处理，请稍后刷新")
            account = self.allowed_account(account_id)
            target = self.store.unpack(job["secret"])
            async with self.account_client(account, job_id=job_id) as client:
                value = await client.receipt(target["active_id"])
            if value.status == "pending":
                return {"message": "平台尚未确认签到，请完成官方补验后再刷新", "job": self.job_snapshot(job_id, session_id)}
            await self.outcome(job_id, account_id, value)
            return {"message": value.message, "job": self.job_snapshot(job_id, session_id)}

    async def events(self, kind: str, resource_id: str, session_id: str):
        key = "me" if kind == "me" else kind + ":" + resource_id
        while True:
            if not self.store.session_active(session_id):
                yield 'event: auth_expired\ndata: {"message":"网站会话已过期"}\n\n'
                return
            version = self.versions.get(key, 0)
            snapshot = self.me_snapshot(session_id) if kind == "me" else self.login_snapshot(resource_id, session_id) if kind == "login" else self.job_snapshot(resource_id, session_id)
            yield "event: snapshot\ndata: " + json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")) + "\n\n"
            terminal = False if kind == "me" else snapshot["status"] != "waiting" if kind == "login" else snapshot["status"] == "done"
            if terminal:
                return
            try:
                async with self.condition:
                    await asyncio.wait_for(self.condition.wait_for(lambda: self.versions.get(key, 0) != version), timeout=15)
            except TimeoutError:
                yield ": keepalive\n\n"

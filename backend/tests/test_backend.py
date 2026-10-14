import asyncio
import base64
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import time
import unittest
from uuid import uuid4

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
import httpx

from app.config import Settings, database_lock
from app.main import create_app
from app.platforms import PlatformClient, PlatformIssue, parse_sign_qr, rsa_device_info
from app.service import Service, ServiceError
from app.store import Store


RAIN_QR = "https://www.yuketang.cn/api/v3/lesson/check-in/dynamic-qr-code?code=current"
CX_QR = "https://mobilelearn.chaoxing.com/widget/sign/e?id=123&enc=qr-signature"


def credentials(value: str, platform="rainClassroom"):
    domain = "www.yuketang.cn" if platform == "rainClassroom" else ".chaoxing.com"
    return {"cookies": [
        {"name": "sessionid", "value": value, "domain": domain, "path": "/", "secure": True},
        {"name": "csrftoken", "value": "csrf-" + value, "domain": domain, "path": "/", "secure": True},
    ]}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "db.sqlite3"
        self.key = Fernet.generate_key().decode("ascii")
        self.store = Store(self.path, self.key)
        token, _ = self.store.new_session(30)
        self.session = self.store.session(token)["id"]

    def tearDown(self):
        self.temp.cleanup()

    def test_credentials_encrypted_and_identity_deduplicated(self):
        account = self.store.save_account(self.session, "rainClassroom", "yuketang", {"uid": "11", "name": "小林"}, credentials("secret-cookie"))
        self.store.authorize(account, True)
        same = self.store.save_account(self.session, "rainClassroom", "yuketang", {"uid": "11", "name": "小林的新名字"}, credentials("new-secret-cookie"))
        self.assertEqual(account, same)
        self.assertEqual(len(self.store.own_accounts(self.session)), 1)
        saved = self.store.account(account)
        self.assertNotIn("new-secret-cookie", saved["credentials"])
        self.assertEqual(self.store.unpack(saved["credentials"])["cookies"][0]["value"], "new-secret-cookie")
        self.assertTrue(saved["authorized"])
        self.assertEqual(saved["name"], "小林的新名字")
        pro = self.store.save_account(self.session, "rainClassroom", "pro", {"uid": "11", "name": "同名服务器账号"}, credentials("other"))
        self.assertNotEqual(account, pro)

    def test_wrong_key_does_not_reset_data(self):
        account = self.store.save_account(self.session, "chaoxing", "", {"uid": "22", "name": "小李"}, credentials("cx", "chaoxing"))
        with self.assertRaisesRegex(ValueError, "密钥"):
            Store(self.path, Fernet.generate_key().decode("ascii"))
        original = Store(self.path, self.key)
        self.assertEqual(original.account(account)["name"], "小李")

    def test_recovery_never_replays_pending_or_running_results(self):
        accounts = [self.store.save_account(self.session, "rainClassroom", "yuketang", {"uid": str(i), "name": str(i)}, credentials(str(i))) for i in (1, 2)]
        job = self.store.create_job(self.session, str(uuid4()), parse_sign_qr(RAIN_QR), [{"id": a, "name": a} for a in accounts])
        self.store.update_result(job, accounts[0], "running", "正在请求")
        login = self.store.create_login(self.session, "chaoxing", "", {"meta": {}}, 300)
        self.store.recover()
        self.assertEqual(self.store.result(job, accounts[0])["status"], "unknown")
        self.assertEqual(self.store.result(job, accounts[1])["status"], "skipped")
        self.assertEqual(self.store.job(job)["status"], "done")
        self.assertEqual(self.store.login(login)["status"], "expired")

    def test_single_service_process_lock(self):
        with database_lock(self.path):
            with self.assertRaises(RuntimeError):
                with database_lock(self.path):
                    self.fail("不应允许两个服务进程锁")

    def test_online_backup_preserves_encrypted_accounts_and_key(self):
        account = self.store.save_account(self.session, "rainClassroom", "yuketang", {"uid": "77", "name": "备份成员"}, credentials("private-backup-cookie"))
        self.store.authorize(account, True)
        destination = Path(self.temp.name) / "backup"
        script = Path(__file__).resolve().parents[1] / "backup.py"
        environment = {**os.environ, "JOIN_CODE": "test-join-code", "CREDENTIAL_KEY": self.key,
                       "PUBLIC_ORIGIN": "http://localhost:8000", "DATABASE_PATH": str(self.path), "PYTHONIOENCODING": "utf-8"}
        completed = subprocess.run([sys.executable, str(script), str(destination)], env=environment, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        restored = Store(destination / "course-helper.sqlite3", self.key)
        self.assertEqual(restored.account(account)["name"], "备份成员")
        self.assertEqual(restored.unpack(restored.account(account)["credentials"])["cookies"][0]["value"], "private-backup-cookie")
        self.assertIn(self.key, (destination / "restore.env").read_text(encoding="utf-8"))
        repeated = subprocess.run([sys.executable, str(script), str(destination)], env=environment, capture_output=True)
        self.assertNotEqual(repeated.returncode, 0)
        self.assertTrue(restored.account(account)["authorized"])


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    def test_qr_domain_and_path_allowlist(self):
        self.assertEqual(parse_sign_qr(RAIN_QR)["server"], "yuketang")
        pro = RAIN_QR.replace("www.yuketang.cn", "pro.yuketang.cn")
        self.assertEqual(parse_sign_qr(pro)["server"], "pro")
        self.assertEqual(parse_sign_qr(CX_QR)["active_id"], "123")
        for bad in (
            RAIN_QR.replace("https:", "http:"), RAIN_QR.replace("www.yuketang.cn", "127.0.0.1"),
            RAIN_QR.replace("www.yuketang.cn", "www.yuketang.cn.attacker.invalid"),
            RAIN_QR.replace("www.yuketang.cn", "user:password@www.yuketang.cn"),
            RAIN_QR.replace("www.yuketang.cn", "www.yuketang.cn:1234"),
            "https://www.yuketang.cn/api/v3/user/login?token=login", CX_QR.replace("id=123", "id=oops"),
        ):
            with self.subTest(url=bad), self.assertRaises(ValueError):
                parse_sign_qr(bad)

    def test_learning_protocol_rsa_chunks(self):
        encoded = rsa_device_info("stable-device")
        ciphertext = base64.b64decode(encoded)
        self.assertGreater(len(ciphertext), 128)
        self.assertEqual(len(ciphertext) % 128, 0)

    async def test_cookie_restore_and_server_isolation(self):
        received = []

        def handler(request):
            received.append((request.headers.get("cookie", ""), request.headers.get("x-csrftoken", ""), request.headers.get("x-uid")))
            return httpx.Response(200, json={"code": 0})

        transport = httpx.MockTransport(handler)
        one = PlatformClient("rainClassroom", "yuketang", credentials("alpha"), "11", transport)
        two = PlatformClient("rainClassroom", "yuketang", credentials("beta"), "22", transport)
        other_server = PlatformClient("rainClassroom", "pro", credentials("alpha"), "11", transport)
        try:
            await one.request("GET", "/probe")
            await two.request("GET", "/probe")
            await other_server.request("GET", "/probe")
            self.assertIn("sessionid=alpha", received[0][0])
            self.assertEqual(received[0][1:], ("csrf-alpha", "11"))
            self.assertIn("sessionid=beta", received[1][0])
            self.assertNotIn("alpha", received[1][0])
            self.assertEqual(received[2][0], "")
        finally:
            await one.close(); await two.close(); await other_server.close()

    async def test_redirect_to_external_host_rejected_before_second_request(self):
        calls = []

        def handler(request):
            calls.append(str(request.url))
            return httpx.Response(302, headers={"location": "https://attacker.invalid/steal"})

        client = PlatformClient("chaoxing", transport=httpx.MockTransport(handler))
        try:
            with self.assertRaises(ValueError):
                await client.request("GET", "https://passport2.chaoxing.com/probe", redirects=True)
            self.assertEqual(len(calls), 1)
        finally:
            await client.close()

    async def test_learning_qr_redirect_preserves_original_signature(self):
        calls = []

        def handler(request):
            calls.append(request.url.path)
            if request.url.path == "/widget/sign/e":
                return httpx.Response(302, headers={"location": "/widget/sign/pcStuSignController/preSign?activeId=123&courseId=456&rcode=https%3A%2F%2Fexample%2F%3Fenc%3Ddynamic-enc"})
            self.fail("不应向二维码重定向目标发出请求")

        client = PlatformClient("chaoxing", transport=httpx.MockTransport(handler))
        try:
            target = parse_sign_qr("https://mobilelearn.chaoxing.com/widget/sign/e?id=123")
            context = await client.resolve_chaoxing_qr(target)
            self.assertEqual(context["enc"], "dynamic-enc")
            self.assertEqual(context["course_id"], "456")
            self.assertEqual(calls, ["/widget/sign/e"])
        finally:
            await client.close()


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.settings = Settings("test-join-code", Fernet.generate_key().decode("ascii"), Path(self.temp.name) / "db.sqlite3")
        self.store = Store(self.settings.database, self.settings.credential_key)
        token, _ = self.store.new_session(30)
        self.session = self.store.session(token)["id"]
        self.calls = []
        self.handler = lambda request: httpx.Response(200, json={"code": 0})

        async def dispatch(request):
            self.calls.append(request)
            result = self.handler(request)
            return await result if asyncio.iscoroutine(result) else result

        transport = httpx.MockTransport(dispatch)
        self.service = Service(self.settings, self.store, lambda *args: PlatformClient(*args, transport=transport))

    async def asyncTearDown(self):
        await self.service.close()
        self.temp.cleanup()

    def seed(self, uid, *, platform="rainClassroom", server="yuketang", authorized=True, session=None):
        if platform == "chaoxing":
            server = ""
        account = self.store.save_account(session or self.session, platform, server, {"uid": uid, "name": "成员" + uid}, credentials("cookie-" + uid, platform))
        self.store.authorize(account, authorized)
        return account

    async def wait_job(self, job):
        task = self.service.tasks.get("job:" + job["id"])
        if task:
            await task
        return self.service.job_snapshot(job["id"], self.session)

    def rain_success(self, request):
        if request.url.path.endswith("/scan"):
            return httpx.Response(200, json={"code": 0, "data": {"value": "lesson-1"}})
        return httpx.Response(200, json={"code": 0, "data": {"lessonToken": "private-lesson-token"}}, headers={"set-auth": "private-bearer-token"})

    async def test_batch_filters_platform_server_and_authorization(self):
        first, second = self.seed("1"), self.seed("2")
        self.seed("3", authorized=False)
        self.seed("4", server="pro")
        self.seed("5", platform="chaoxing")
        self.handler = self.rain_success
        job = await self.wait_job(self.service.create_job(self.session, str(uuid4()), RAIN_QR))
        self.assertEqual({r["account_id"] for r in job["results"]}, {first, second})
        self.assertEqual({r["status"] for r in job["results"]}, {"success"})
        self.assertEqual({r.headers["x-uid"] for r in self.calls}, {"1", "2"})
        for request in self.calls:
            uid = request.headers["x-uid"]
            self.assertIn("sessionid=cookie-" + uid, request.headers["cookie"])
            if request.url.path.endswith("/checkin"):
                self.assertEqual(json.loads(request.content)["lessonId"], "lesson-1")
        serialized = json.dumps(job)
        for secret in ("cookie-1", "csrf-cookie-1", "private-bearer-token", "private-lesson-token"):
            self.assertNotIn(secret, serialized)

    async def test_duplicate_request_id_does_not_submit_twice(self):
        self.seed("1")
        self.handler = self.rain_success
        request_id = str(uuid4())
        one = self.service.create_job(self.session, request_id, RAIN_QR)
        two = self.service.create_job(self.session, request_id, RAIN_QR)
        self.assertEqual(one["id"], two["id"])
        await self.wait_job(one)
        self.service.create_job(self.session, request_id, RAIN_QR)
        self.assertEqual(len(self.calls), 2)
        with self.assertRaises(ServiceError) as error:
            self.service.create_job(self.session, request_id, RAIN_QR + "-different")
        self.assertEqual(error.exception.status, 409)

    async def test_revocation_before_dispatch_prevents_request(self):
        account = self.seed("1")
        job = self.service.create_job(self.session, str(uuid4()), RAIN_QR)
        await self.service.revoke(account)
        snapshot = await self.wait_job(job)
        self.assertEqual(snapshot["results"][0]["status"], "skipped")
        self.assertEqual(self.calls, [])

    async def test_revocation_during_scan_stops_following_checkin(self):
        account = self.seed("1")

        async def handler(request):
            if request.url.path.endswith("/scan"):
                await self.service.revoke(account)
                return self.rain_success(request)
            self.fail("撤销后不应发起 checkin")

        self.handler = handler
        job = await self.wait_job(self.service.create_job(self.session, str(uuid4()), RAIN_QR))
        self.assertEqual(job["results"][0]["status"], "skipped")
        self.assertEqual(len(self.calls), 1)

    async def test_partial_failure_and_timeout_never_report_success_or_retry(self):
        self.seed("1"); self.seed("2"); self.seed("3")

        def handler(request):
            uid = request.headers["x-uid"]
            if uid == "2":
                return httpx.Response(200, json={"code": 51203, "msg": "expired"})
            if uid == "3" and request.url.path.endswith("/checkin"):
                raise httpx.ReadTimeout("response lost", request=request)
            return self.rain_success(request)

        self.handler = handler
        request_id = str(uuid4())
        snapshot = await self.wait_job(self.service.create_job(self.session, request_id, RAIN_QR))
        self.assertEqual({r["status"] for r in snapshot["results"]}, {"success", "qr_expired", "unknown"})
        self.assertEqual(sum(r.url.path.endswith("/checkin") and r.headers["x-uid"] == "3" for r in self.calls), 1)
        calls = len(self.calls)
        self.service.create_job(self.session, request_id, RAIN_QR)
        self.assertEqual(len(self.calls), calls)

    async def test_platform_expiration_clears_persisted_credential(self):
        account = self.seed("1")
        self.handler = lambda request: httpx.Response(401)
        snapshot = await self.wait_job(self.service.create_job(self.session, str(uuid4()), RAIN_QR))
        self.assertEqual(snapshot["results"][0]["status"], "session_expired")
        self.assertIsNone(self.store.account(account)["credentials"])
        self.assertEqual(self.store.pool("rainClassroom", "yuketang"), [])

    async def test_incomplete_or_server_error_signing_response_remains_unknown(self):
        self.seed("1")
        for status, text in ((200, "not-json"), (503, "server error")):
            with self.subTest(status=status):
                self.handler = lambda request: self.rain_success(request) if request.url.path.endswith("/scan") else httpx.Response(status, text=text)
                job = await self.wait_job(self.service.create_job(self.session, str(uuid4()), RAIN_QR))
                self.assertEqual(job["results"][0]["status"], "unknown")

    async def test_jobs_are_serialized_per_account(self):
        self.seed("1")
        active, maximum = 0, 0

        async def handler(request):
            nonlocal active, maximum
            active += 1; maximum = max(active, maximum)
            await asyncio.sleep(.01)
            active -= 1
            return self.rain_success(request)

        self.handler = handler
        first = self.service.create_job(self.session, str(uuid4()), RAIN_QR)
        second = self.service.create_job(self.session, str(uuid4()), RAIN_QR + "2")
        await asyncio.gather(self.wait_job(first), self.wait_job(second))
        self.assertEqual(maximum, 1)

    async def test_verified_qr_logins_keep_temporary_cookies_independent(self):
        counter = 0

        def handler(request):
            nonlocal counter
            if request.url.path.endswith("/pre-info"):
                counter += 1
                return httpx.Response(200, json={"code": 0, "data": {"token": str(counter), "qrImage": "https://www.yuketang.cn/qr.png"}}, headers={"set-cookie": f"sessionid=temporary-{counter}; Path=/; Secure"})
            cookie = request.headers.get("cookie", "")
            if request.url.path == "/api/v3/user/login":
                token = json.loads(request.content)["token"]
                self.assertIn("sessionid=temporary-" + token, cookie)
                return httpx.Response(200, json={"code": 0, "data": {}})
            uid = cookie.split("temporary-")[1].split(";")[0]
            return httpx.Response(200, json={"data": {"user_profile": {"user_id": uid, "name": "成员" + uid}}})

        self.handler = handler
        one = await self.service.create_login(self.session, "rainClassroom", "yuketang")
        two = await self.service.create_login(self.session, "rainClassroom", "yuketang")
        await asyncio.gather(*list(self.service.tasks.values()))
        self.assertNotEqual(self.store.login(one["id"])["account_id"], self.store.login(two["id"])["account_id"])
        self.assertEqual(len(self.store.own_accounts(self.session)), 2)
        self.assertTrue(all(not row["authorized"] for row in self.store.own_accounts(self.session)))
        for row in self.store.own_accounts(self.session):
            account = self.store.account(row["id"])
            cookie = self.store.unpack(account["credentials"])["cookies"][0]["value"]
            self.assertEqual(cookie, "temporary-" + account["uid"])

    async def test_sse_snapshots_and_visibility_are_permission_scoped(self):
        account = self.seed("1")
        other_token, _ = self.store.new_session(30)
        other_session = self.store.session(other_token)["id"]
        member = self.seed("2", session=other_session)
        self.handler = self.rain_success
        job = self.service.create_job(self.session, str(uuid4()), RAIN_QR)
        events = self.service.events("job", job["id"], self.session)
        initial = await anext(events)
        self.assertIn("event: snapshot", initial)
        await self.wait_job(job)
        final = await anext(events)
        self.assertIn('"status":"done"', final)
        await events.aclose()
        restricted = self.service.job_snapshot(job["id"], other_session)
        self.assertEqual([r["account_id"] for r in restricted["results"]], [member])
        self.assertNotIn(account, json.dumps(restricted))
        outsider, _ = self.store.new_session(30)
        with self.assertRaises(ServiceError):
            self.service.job_snapshot(job["id"], self.store.session(outsider)["id"])

    async def test_members_receive_their_own_new_batch_results(self):
        self.seed("1")
        token, _ = self.store.new_session(30)
        member_session = self.store.session(token)["id"]
        member = self.seed("2", session=member_session)
        events = self.service.events("me", member_session, member_session)
        initial = await anext(events)
        self.assertIn('"jobs":[]', initial)
        self.handler = self.rain_success
        job = await self.wait_job(self.service.create_job(self.session, str(uuid4()), RAIN_QR))
        update = await anext(events)
        payload = json.loads(update.split("data: ", 1)[1].strip())
        self.assertEqual(payload["jobs"][0]["id"], job["id"])
        self.assertEqual([r["account_id"] for r in payload["jobs"][0]["results"]], [member])
        self.assertEqual([a["id"] for a in payload["accounts"]], [member])
        self.assertNotIn("cookie-", update)
        await events.aclose()

    async def test_official_face_or_location_requirement_is_not_bypassed(self):
        account = self.seed("1", platform="chaoxing")
        signed = False

        def handler(request):
            if request.url.path.endswith("/getAttendInfo"):
                return httpx.Response(200, json={"result": 1, "data": {"status": 1 if signed else 0}})
            if request.url.path.endswith("/getPPTActiveInfo"):
                return httpx.Response(200, json={"result": 1, "data": {"otherId": 2, "openCheckFaceFlag": 1}})
            self.fail("要求本人补验时不应调用签到接口")

        self.handler = handler
        job = await self.wait_job(self.service.create_job(self.session, str(uuid4()), CX_QR))
        self.assertEqual(job["results"][0]["status"], "needs_official_verification")
        signed = True
        updated = await self.service.refresh_receipt(job["id"], account, self.session)
        self.assertEqual(updated["job"]["results"][0]["status"], "already_signed")

    async def test_slide_context_is_bound_to_account_and_continues_with_enc2(self):
        first = self.seed("1", platform="chaoxing")
        second = self.seed("2", platform="chaoxing")
        ivs = {}
        signed = set()

        def callback(data):
            return httpx.Response(200, text="cx_captcha_function(" + json.dumps(data) + ")")

        def handler(request):
            cookie = request.headers.get("cookie", "")
            uid = "1" if "cookie-1" in cookie else "2"
            path, args = request.url.path, request.url.params
            if path.endswith("/getAttendInfo"):
                return httpx.Response(200, json={"result": 1, "data": {"status": int(uid in signed)}})
            if path.endswith("/getPPTActiveInfo"):
                return httpx.Response(200, json={"result": 1, "data": {"otherId": 2}})
            if path.endswith("/stuSignajax"):
                if args.get("validate"):
                    self.assertEqual(args["enc2"], "enc2-" + uid)
                    self.assertEqual(args["validate"], "validate-" + uid)
                    signed.add(uid)
                    return httpx.Response(200, text="success")
                return httpx.Response(200, text="validate_enc2-" + uid)
            if path.endswith("/conf"):
                return callback({"t": int(time.time() * 1000)})
            if path.endswith("/image"):
                ivs[uid] = args["iv"]
                return callback({"token": "challenge-" + uid, "imageVerificationVo": {"shadeImage": "https://captcha.chaoxing.com/bg.png", "cutoutImage": "https://captcha.chaoxing.com/piece.png", "originalWidth": 320}})
            if path.endswith("/result"):
                self.assertEqual(args["iv"], ivs[uid])
                self.assertEqual(args["token"], "challenge-" + uid)
                return callback({"error": 0, "result": True, "extraData": json.dumps({"validate": "validate-" + uid})})
            self.fail("未知平台请求")

        self.handler = handler
        job = await self.wait_job(self.service.create_job(self.session, str(uuid4()), CX_QR))
        self.assertEqual({r["status"] for r in job["results"]}, {"needs_captcha"})
        one = await self.service.create_captcha(job["id"], first, self.session)
        two = await self.service.create_captcha(job["id"], second, self.session)
        count = len(self.calls)
        with self.assertRaises(ServiceError):
            await self.service.submit_captcha(job["id"], second, self.session, one["id"], 120)
        self.assertEqual(len(self.calls), count)
        after = await self.service.submit_captcha(job["id"], first, self.session, one["id"], 120)
        self.assertEqual(next(r for r in after["results"] if r["account_id"] == first)["status"], "success")
        self.assertEqual(next(r for r in after["results"] if r["account_id"] == second)["status"], "needs_captcha")
        context = self.store.unpack(self.store.result(job["id"], second)["secret"])
        context["challenge"]["expires"] = 0
        self.store.update_result(job["id"], second, "needs_captcha", "等待验证", context)
        with self.assertRaises(ServiceError):
            await self.service.submit_captcha(job["id"], second, self.session, two["id"], 120)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        config = Settings("test-join-code", Fernet.generate_key().decode("ascii"), Path(self.temp.name) / "db.sqlite3")
        self.app = create_app(config)
        self.context = TestClient(self.app)
        self.client = self.context.__enter__()
        response = self.client.post("/api/access", json={"join_code": "test-join-code"})
        self.csrf = response.json()["csrf_token"]
        self.session = self.app.state.store.session(self.client.cookies.get("course_session"))["id"]

    def tearDown(self):
        self.context.__exit__(None, None, None)
        self.temp.cleanup()

    def headers(self):
        return {"x-csrf-token": self.csrf}

    def test_access_cookie_and_csrf(self):
        self.assertEqual(self.client.get("/api/me").status_code, 200)
        response = self.client.post("/api/logins", json={"platform": "chaoxing"})
        self.assertEqual(response.status_code, 403)
        crossed = self.client.post("/api/logins", headers={**self.headers(), "origin": "https://attacker.invalid"}, json={"platform": "chaoxing"})
        self.assertEqual(crossed.status_code, 403)
        response = self.client.get("/api/health")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")

    def test_account_management_rejects_unverified_ownership(self):
        other, _ = self.app.state.store.new_session(30)
        other_session = self.app.state.store.session(other)["id"]
        account = self.app.state.store.save_account(other_session, "rainClassroom", "yuketang", {"uid": "someone-else", "name": "其他成员"}, credentials("secret"))
        response = self.client.patch(f"/api/accounts/{account}/authorization", headers=self.headers(), json={"enabled": True})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.delete(f"/api/accounts/{account}", headers=self.headers()).status_code, 403)
        self.assertIsNotNone(self.app.state.store.account(account))
        self.assertNotIn("secret", self.client.get("/api/me").text)

    def test_invitation_throttling_and_body_size_limit(self):
        for _ in range(5):
            self.assertEqual(self.client.post("/api/access", json={"join_code": "wrong-code"}).status_code, 403)
        self.assertEqual(self.client.post("/api/access", json={"join_code": "wrong-code"}).status_code, 429)
        self.assertEqual(self.client.post("/api/access", content=b"x" * 20000, headers={"content-type": "application/json"}).status_code, 413)

    def test_logout_revokes_website_session_but_preserves_explicit_batch_grant(self):
        account = self.app.state.store.save_account(self.session, "chaoxing", "", {"uid": "11", "name": "成员"}, credentials("cookie", "chaoxing"))
        self.app.state.store.authorize(account, True)
        self.assertEqual(self.client.delete("/api/access", headers=self.headers()).status_code, 200)
        self.assertEqual(self.client.get("/api/me").status_code, 401)
        self.assertTrue(self.app.state.store.account(account)["authorized"])


if __name__ == "__main__":
    unittest.main()

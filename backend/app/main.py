from collections import defaultdict, deque
from contextlib import asynccontextmanager
import hmac
import logging
from pathlib import Path
import time
from typing import Literal
from uuid import UUID

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import httpx
from pydantic import BaseModel, Field

from .config import Settings, database_lock
from .platforms import PlatformClient, PlatformIssue, RAIN_SERVERS
from .service import Service, ServiceError
from .store import Store


class AccessInput(BaseModel):
    join_code: str = Field(min_length=1, max_length=256)


class LoginInput(BaseModel):
    platform: Literal["chaoxing", "rainClassroom"]
    server: Literal["yuketang", "pro", "changjiang", "huanghe"] | None = None


class AuthorizationInput(BaseModel):
    enabled: bool


class SignInput(BaseModel):
    qr_text: str = Field(min_length=10, max_length=8192)
    request_id: UUID


class CaptchaInput(BaseModel):
    challenge_id: UUID
    x: float = Field(ge=0, le=2000, allow_inf_nan=False)


class RequestProtection:
    """限制输入大小并为响应设置安全头，不读取 SSE 响应体。"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        messages = deque()
        if scope["method"] in {"POST", "PATCH", "PUT", "DELETE"}:
            size = 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                size += len(message.get("body", b""))
                if size > 16384:
                    response = JSONResponse({"detail": "请求内容过大"}, status_code=413)
                    return await response(scope, receive, send)
                messages.append(message)
                if not message.get("more_body", False):
                    break

        async def replay():
            return messages.popleft() if messages else await receive()

        async def protected_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend([
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"camera=(self), microphone=(), geolocation=()"),
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'"),
                ])
                if scope["path"].startswith("/api"):
                    headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, replay, protected_send)


def create_app(settings: Settings | None = None, client_factory=PlatformClient):
    @asynccontextmanager
    async def lifespan(app):
        config = settings or Settings.from_env()
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        with database_lock(config.database):
            store = Store(config.database, config.credential_key)
            store.recover()
            service = Service(config, store, client_factory)
            app.state.settings, app.state.store, app.state.service = config, store, service
            try:
                yield
            finally:
                await service.close()

    app = FastAPI(title="课程助手网页 API", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(RequestProtection)
    failures: dict[str, deque] = defaultdict(deque)

    @app.exception_handler(ServiceError)
    async def service_error(request, error):
        return JSONResponse({"detail": error.message}, status_code=error.status)

    @app.exception_handler(PlatformIssue)
    async def platform_error(request, error):
        return JSONResponse({"detail": error.message}, status_code=422)

    @app.exception_handler(httpx.HTTPError)
    async def network_error(request, error):
        return JSONResponse({"detail": "平台连接暂时不可用，请稍后重试"}, status_code=502)

    @app.exception_handler(ValueError)
    async def bad_input(request, error):
        return JSONResponse({"detail": "二维码或平台数据不受支持，请检查输入或刷新"}, status_code=422)

    def check_origin(request: Request):
        config = request.app.state.settings
        origins = {config.public_origin}
        if not config.secure_cookie:
            origins |= {"http://localhost:5173", "http://127.0.0.1:5173"}
        origin = request.headers.get("origin")
        if (origin and origin not in origins) or request.headers.get("sec-fetch-site") == "cross-site":
            raise ServiceError(403, "请求来源不受支持")

    def session(request: Request):
        row = request.app.state.store.session(request.cookies.get("course_session"))
        if not row:
            raise ServiceError(401, "请先输入加入码进入网站")
        if request.method not in {"GET", "HEAD"}:
            check_origin(request)
            if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), row["csrf"]):
                raise ServiceError(403, "会话校验失败，请刷新网页重试")
        return row

    def owner(account_id: UUID, request: Request, who=Depends(session)):
        if not request.app.state.store.owns(who["id"], str(account_id)):
            raise ServiceError(403, "只能管理自己已验证的账号")
        return who

    @app.get("/api/health")
    async def health():
        return {"status": "ok"}

    @app.post("/api/access")
    async def access(body: AccessInput, request: Request):
        check_origin(request)
        ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        attempts = failures[ip]
        while attempts and attempts[0] < now - 300:
            attempts.popleft()
        if len(attempts) >= 5:
            raise ServiceError(429, "加入码错误次数较多，请五分钟后再试")
        config = request.app.state.settings
        if not hmac.compare_digest(body.join_code.encode("utf-8"), config.join_code.encode("utf-8")):
            attempts.append(now)
            raise ServiceError(403, "加入码不正确")
        # 新会话不继承浏览器提供的旧 session ID，避免会话固定。
        token, csrf = request.app.state.store.new_session(config.session_days)
        response = JSONResponse({"csrf_token": csrf})
        response.set_cookie("course_session", token, max_age=config.session_days * 86400, httponly=True, secure=config.secure_cookie, samesite="strict", path="/")
        return response

    @app.delete("/api/access")
    async def logout(request: Request, who=Depends(session)):
        service = request.app.state.service
        for login_id in request.app.state.store.pending_logins(who["id"]):
            await service.cancel_login(login_id, who["id"])
        request.app.state.store.delete_session(who["id"])
        await service.changed("me")
        response = JSONResponse({"message": "已退出网站，已授予的批量签到授权保留，可重新登录账号后撤销"})
        response.delete_cookie("course_session", path="/", secure=request.app.state.settings.secure_cookie, httponly=True, samesite="strict")
        return response

    @app.get("/api/me")
    async def me(request: Request, who=Depends(session)):
        return request.app.state.service.me_snapshot(who["id"])

    @app.get("/api/me/events")
    async def me_events(request: Request, who=Depends(session)):
        return event_response(request.app.state.service, "me", who["id"], who)

    @app.post("/api/logins")
    async def login(body: LoginInput, request: Request, who=Depends(session)):
        if body.platform == "chaoxing" and body.server is not None:
            raise ServiceError(422, "学习通不需要选择雨课堂服务器")
        server = (body.server or "yuketang") if body.platform == "rainClassroom" else ""
        return await request.app.state.service.create_login(who["id"], body.platform, server)

    @app.get("/api/logins/{login_id}")
    async def login_state(login_id: UUID, request: Request, who=Depends(session)):
        return request.app.state.service.login_snapshot(str(login_id), who["id"])

    @app.delete("/api/logins/{login_id}")
    async def cancel_login(login_id: UUID, request: Request, who=Depends(session)):
        await request.app.state.service.cancel_login(str(login_id), who["id"])
        return {"message": "已关闭二维码"}

    def event_response(service, kind, resource_id, who):
        return StreamingResponse(service.events(kind, str(resource_id), who["id"]), media_type="text/event-stream", headers={"X-Accel-Buffering": "no", "Cache-Control": "no-store"})

    @app.get("/api/logins/{login_id}/events")
    async def login_events(login_id: UUID, request: Request, who=Depends(session)):
        service = request.app.state.service
        service.login_snapshot(str(login_id), who["id"])
        return event_response(service, "login", login_id, who)

    @app.patch("/api/accounts/{account_id}/authorization")
    async def authorize(account_id: UUID, body: AuthorizationInput, request: Request, who=Depends(owner)):
        store, service = request.app.state.store, request.app.state.service
        if body.enabled:
            account = store.account(str(account_id))
            if not account["valid"]:
                raise ServiceError(409, "请重新登录此账号后开启授权")
            store.authorize(str(account_id), True)
            await service.changed("me")
        else:
            await service.revoke(str(account_id))
        return {"enabled": body.enabled}

    @app.delete("/api/accounts/{account_id}")
    async def unbind(account_id: UUID, request: Request, who=Depends(owner)):
        await request.app.state.service.revoke(str(account_id), delete=True)
        return {"message": "已撤销授权并删除保存的登录态"}

    @app.post("/api/sign-jobs")
    async def create_job(body: SignInput, request: Request, who=Depends(session)):
        return request.app.state.service.create_job(who["id"], str(body.request_id), body.qr_text)

    @app.get("/api/sign-jobs/{job_id}")
    async def job(job_id: UUID, request: Request, who=Depends(session)):
        return request.app.state.service.job_snapshot(str(job_id), who["id"])

    @app.get("/api/sign-jobs/{job_id}/events")
    async def job_events(job_id: UUID, request: Request, who=Depends(session)):
        service = request.app.state.service
        service.job_snapshot(str(job_id), who["id"])
        return event_response(service, "job", job_id, who)

    @app.post("/api/sign-jobs/{job_id}/accounts/{account_id}/captcha")
    async def captcha(job_id: UUID, account_id: UUID, request: Request, who=Depends(session)):
        return await request.app.state.service.create_captcha(str(job_id), str(account_id), who["id"])

    @app.post("/api/sign-jobs/{job_id}/accounts/{account_id}/captcha/verify")
    async def verify(job_id: UUID, account_id: UUID, body: CaptchaInput, request: Request, who=Depends(session)):
        return await request.app.state.service.submit_captcha(str(job_id), str(account_id), who["id"], str(body.challenge_id), body.x)

    @app.post("/api/sign-jobs/{job_id}/accounts/{account_id}/receipt")
    async def receipt(job_id: UUID, account_id: UUID, request: Request, who=Depends(session)):
        return await request.app.state.service.refresh_receipt(str(job_id), str(account_id), who["id"])

    dist = Path(__file__).resolve().parents[2] / "web" / "dist"
    if (dist / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @app.get("/")
    async def index():
        if (dist / "index.html").exists():
            return FileResponse(dist / "index.html", headers={"Cache-Control": "no-store"})
        return JSONResponse({"message": "网页尚未构建，请在 web 目录运行 npm install 和 npm run build"}, status_code=503)

    return app


app = create_app()

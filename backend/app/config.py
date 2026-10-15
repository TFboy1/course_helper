from dataclasses import dataclass
from contextlib import contextmanager
import os
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet


@contextmanager
def database_lock(path: Path):
    """SSE、后台任务与账号锁在一个进程内，拒绝第二个服务进程。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = open(path.with_suffix(".lock"), "a+b")
    if lock.tell() == 0:
        lock.write(b"1")
        lock.flush()
    lock.seek(0)
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock.close()
        raise RuntimeError("此数据库已有服务进程，请仅运行一个 worker") from None
    try:
        yield
    finally:
        lock.seek(0)
        if os.name == "nt":
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


@dataclass(frozen=True)
class Settings:
    join_code: str
    credential_key: str
    database: Path | str = Path("data/course-helper.sqlite3")
    public_origin: str = "http://localhost:8000"
    batch_concurrency: int = 10
    session_days: int = 30
    login_seconds: int = 300
    admin_code: str | None = None
    serverless: bool = False

    def __post_init__(self):
        if len(self.join_code) < 8:
            raise ValueError("JOIN_CODE 至少需要 8 个字符")
        if any(ord(char) < 32 for char in self.join_code):
            raise ValueError("JOIN_CODE 不能包含控制字符")
        if self.admin_code:
            if len(self.admin_code) < 8:
                raise ValueError("ADMIN_JOIN_CODE 至少需要 8 个字符")
            if any(ord(char) < 32 for char in self.admin_code):
                raise ValueError("ADMIN_JOIN_CODE 不能包含控制字符")
            if self.admin_code == self.join_code:
                raise ValueError("ADMIN_JOIN_CODE 必须与 JOIN_CODE 不同")
        Fernet(self.credential_key.encode("ascii"))
        origin = urlsplit(self.public_origin)
        origin.port  # 同时验证非法端口，避免直到请求阶段才发现配置错误。
        if origin.scheme not in {"http", "https"} or not origin.hostname:
            raise ValueError("PUBLIC_ORIGIN 必须是完整的 HTTP/HTTPS 来源")
        if origin.path not in {"", "/"} or origin.query or origin.fragment or origin.username:
            raise ValueError("PUBLIC_ORIGIN 不应包含路径、查询或用户名")
        if origin.scheme == "http" and origin.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("外网部署必须使用 HTTPS；本地开发可使用 localhost")
        if not 1 <= self.batch_concurrency <= 50:
            raise ValueError("BATCH_CONCURRENCY 必须在 1 到 50 之间")

    @property
    def secure_cookie(self) -> bool:
        return self.public_origin.startswith("https://")

    @classmethod
    def from_env(cls):
        required = [name for name in ("JOIN_CODE", "CREDENTIAL_KEY") if not os.getenv(name)]
        if required:
            raise ValueError(f"缺少配置：{', '.join(required)}。请参阅 backend/.env.example")
        database_url = os.getenv("DATABASE_URL") or os.getenv("yvketang_DATABASE_URL")
        if database_url and not database_url.startswith(("postgres://", "postgresql://")):
            raise ValueError("DATABASE_URL 必须是 PostgreSQL 连接地址")
        serverless = os.getenv("VERCEL") == "1" or os.getenv("SERVERLESS_MODE") == "1"
        origin = os.getenv("PUBLIC_ORIGIN")
        if not origin and serverless and os.getenv("VERCEL_URL"):
            origin = "https://" + os.environ["VERCEL_URL"]
        return cls(
            join_code=os.environ["JOIN_CODE"],
            credential_key=os.environ["CREDENTIAL_KEY"],
            database=database_url or Path(os.getenv("DATABASE_PATH", "data/course-helper.sqlite3")),
            public_origin=(origin or "http://localhost:8000").rstrip("/"),
            batch_concurrency=int(os.getenv("BATCH_CONCURRENCY", "10")),
            admin_code=os.getenv("ADMIN_JOIN_CODE") or None,
            serverless=serverless,
        )

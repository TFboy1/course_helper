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
    database: Path = Path("data/course-helper.sqlite3")
    public_origin: str = "http://localhost:8000"
    batch_concurrency: int = 10
    session_days: int = 30
    login_seconds: int = 300

    def __post_init__(self):
        if len(self.join_code) < 8:
            raise ValueError("JOIN_CODE 至少需要 8 个字符")
        if any(ord(char) < 32 for char in self.join_code):
            raise ValueError("JOIN_CODE 不能包含控制字符")
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
        return cls(
            join_code=os.environ["JOIN_CODE"],
            credential_key=os.environ["CREDENTIAL_KEY"],
            database=Path(os.getenv("DATABASE_PATH", "data/course-helper.sqlite3")),
            public_origin=os.getenv("PUBLIC_ORIGIN", "http://localhost:8000").rstrip("/"),
            batch_concurrency=int(os.getenv("BATCH_CONCURRENCY", "10")),
        )

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import time
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class Store:
    """少量用户的同步 SQLite 存储；事务中不执行网络请求。"""

    def __init__(self, path: Path, key: str):
        self.path = path
        self.cipher = Fernet(key.encode("ascii"))
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS accounts (
                    id TEXT PRIMARY KEY, platform TEXT NOT NULL, server TEXT NOT NULL,
                    uid TEXT NOT NULL, name TEXT NOT NULL, credentials TEXT,
                    authorized INTEGER NOT NULL DEFAULT 0, valid INTEGER NOT NULL DEFAULT 1,
                    updated REAL NOT NULL, UNIQUE(platform, server, uid)
                );
                CREATE TABLE IF NOT EXISTS session_accounts (
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    PRIMARY KEY(session_id, account_id)
                );
                CREATE TABLE IF NOT EXISTS logins (
                    id TEXT PRIMARY KEY, session_id TEXT NOT NULL, platform TEXT NOT NULL,
                    server TEXT NOT NULL, status TEXT NOT NULL, message TEXT NOT NULL DEFAULT '',
                    secret TEXT NOT NULL, expires REAL NOT NULL, account_id TEXT
                );
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, session_id TEXT NOT NULL, request_id TEXT NOT NULL,
                    input_hash TEXT NOT NULL, platform TEXT NOT NULL, server TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'running', secret TEXT NOT NULL,
                    created REAL NOT NULL, UNIQUE(session_id, request_id)
                );
                CREATE TABLE IF NOT EXISTS results (
                    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                    account_id TEXT NOT NULL, name TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending', message TEXT NOT NULL DEFAULT '等待执行',
                    secret TEXT, updated REAL NOT NULL,
                    PRIMARY KEY(job_id, account_id)
                );
                CREATE INDEX IF NOT EXISTS results_account ON results(account_id);
            """)
            marker = db.execute("SELECT value FROM metadata WHERE key='credential_key'").fetchone()
            if marker:
                try:
                    if self.unpack(marker[0]) != {"version": 1}:
                        raise ValueError("不支持的凭据格式")
                except (InvalidToken, ValueError):
                    raise ValueError("CREDENTIAL_KEY 与现有数据库不匹配，请恢复原密钥；数据未被清除") from None
            else:
                db.execute("INSERT INTO metadata VALUES ('credential_key', ?)", (self.pack({"version": 1}),))

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def pack(self, value) -> str:
        return self.cipher.encrypt(json.dumps(value, ensure_ascii=False).encode("utf-8")).decode("ascii")

    def unpack(self, value: str):
        return json.loads(self.cipher.decrypt(value.encode("ascii")).decode("utf-8"))

    def new_session(self, days: int):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.connection() as db:
            db.execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
            db.execute("INSERT INTO sessions VALUES (?, ?, ?)", (token_hash(token), csrf, time.time() + days * 86400))
        return token, csrf

    def session(self, token: str | None):
        if not token:
            return None
        with self.connection() as db:
            row = db.execute("SELECT * FROM sessions WHERE id=? AND expires>?", (token_hash(token), time.time())).fetchone()
        return dict(row) if row else None

    def delete_session(self, session_id: str):
        with self.connection() as db:
            db.execute("DELETE FROM sessions WHERE id=?", (session_id,))

    def session_active(self, session_id: str):
        return self.session_info(session_id) is not None

    def session_info(self, session_id: str):
        with self.connection() as db:
            row = db.execute("SELECT * FROM sessions WHERE id=? AND expires>?", (session_id, time.time())).fetchone()
        return dict(row) if row else None

    def owns(self, session_id: str, account_id: str) -> bool:
        with self.connection() as db:
            return db.execute("SELECT 1 FROM session_accounts WHERE session_id=? AND account_id=?", (session_id, account_id)).fetchone() is not None

    def account(self, account_id: str):
        with self.connection() as db:
            row = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        return dict(row) if row else None

    def save_account(self, session_id: str, platform: str, server: str, profile: dict, credentials: dict):
        with self.connection() as db:
            row = db.execute("SELECT id FROM accounts WHERE platform=? AND server=? AND uid=?", (platform, server, profile["uid"])).fetchone()
            account_id = row[0] if row else str(uuid4())
            db.execute("""INSERT INTO accounts (id,platform,server,uid,name,credentials,updated)
                          VALUES (?,?,?,?,?,?,?) ON CONFLICT(platform,server,uid) DO UPDATE SET
                          name=excluded.name,credentials=excluded.credentials,valid=1,updated=excluded.updated""",
                       (account_id, platform, server, profile["uid"], profile["name"], self.pack(credentials), time.time()))
            db.execute("INSERT OR IGNORE INTO session_accounts VALUES (?, ?)", (session_id, account_id))
        return account_id

    def own_accounts(self, session_id: str):
        with self.connection() as db:
            return [dict(row) for row in db.execute("""SELECT a.id,a.platform,a.server,a.name,a.authorized,a.valid
                FROM accounts a JOIN session_accounts s ON s.account_id=a.id
                WHERE s.session_id=? ORDER BY a.updated DESC""", (session_id,))]

    def owned_ids(self, session_id: str):
        return {account["id"] for account in self.own_accounts(session_id)}

    def pool(self, platform: str, server: str):
        with self.connection() as db:
            return [dict(row) for row in db.execute("SELECT id,name FROM accounts WHERE platform=? AND server=? AND authorized=1 AND valid=1 AND credentials IS NOT NULL ORDER BY updated", (platform, server))]

    def authorize(self, account_id: str, enabled: bool):
        with self.connection() as db:
            db.execute("UPDATE accounts SET authorized=?,updated=? WHERE id=?", (enabled, time.time(), account_id))

    def delete_account(self, account_id: str):
        with self.connection() as db:
            db.execute("DELETE FROM accounts WHERE id=?", (account_id,))

    def credentials(self, account_id: str, value: dict):
        with self.connection() as db:
            db.execute("UPDATE accounts SET credentials=?,updated=? WHERE id=? AND valid=1", (self.pack(value), time.time(), account_id))

    def invalidate(self, account_id: str):
        with self.connection() as db:
            db.execute("UPDATE accounts SET valid=0,credentials=NULL WHERE id=?", (account_id,))

    def create_login(self, session_id: str, platform: str, server: str, secret: dict, seconds: int):
        login_id = str(uuid4())
        with self.connection() as db:
            db.execute("DELETE FROM logins WHERE expires<?", (time.time() - 86400,))
            db.execute("INSERT INTO logins(id,session_id,platform,server,status,secret,expires) VALUES (?,?,?,?,?,?,?)", (login_id, session_id, platform, server, "waiting", self.pack(secret), time.time() + seconds))
        return login_id

    def login(self, login_id: str):
        with self.connection() as db:
            row = db.execute("SELECT * FROM logins WHERE id=?", (login_id,)).fetchone()
        return dict(row) if row else None

    def login_status(self, login_id: str, status: str, message: str, account_id: str | None = None):
        with self.connection() as db:
            db.execute("UPDATE logins SET status=?,message=?,account_id=? WHERE id=?", (status, message, account_id, login_id))

    def pending_logins(self, session_id: str | None = None):
        with self.connection() as db:
            sql, args = "SELECT id FROM logins WHERE status='waiting'", ()
            if session_id:
                sql, args = sql + " AND session_id=?", (session_id,)
            return [row[0] for row in db.execute(sql, args)]

    def existing_job(self, session_id: str, request_id: str):
        with self.connection() as db:
            row = db.execute("SELECT * FROM jobs WHERE session_id=? AND request_id=?", (session_id, request_id)).fetchone()
        return dict(row) if row else None

    def create_job(self, session_id: str, request_id: str, target: dict, accounts: list[dict]):
        job_id, now = str(uuid4()), time.time()
        with self.connection() as db:
            db.execute("INSERT INTO jobs(id,session_id,request_id,input_hash,platform,server,secret,created) VALUES (?,?,?,?,?,?,?,?)", (job_id, session_id, request_id, token_hash(target["url"]), target["platform"], target["server"], self.pack(target), now))
            db.executemany("INSERT INTO results(job_id,account_id,name,updated) VALUES (?,?,?,?)", [(job_id, account["id"], account["name"], now) for account in accounts])
        return job_id

    def job(self, job_id: str):
        with self.connection() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def results(self, job_id: str):
        with self.connection() as db:
            return [dict(row) for row in db.execute("SELECT * FROM results WHERE job_id=? ORDER BY name,account_id", (job_id,))]

    def result(self, job_id: str, account_id: str):
        with self.connection() as db:
            row = db.execute("SELECT * FROM results WHERE job_id=? AND account_id=?", (job_id, account_id)).fetchone()
        return dict(row) if row else None

    def update_result(self, job_id: str, account_id: str, status: str, message: str, secret: dict | None = None):
        with self.connection() as db:
            db.execute("UPDATE results SET status=?,message=?,secret=?,updated=? WHERE job_id=? AND account_id=?", (status, message, self.pack(secret) if secret else None, time.time(), job_id, account_id))

    def update_job_status(self, job_id: str):
        statuses = {row["status"] for row in self.results(job_id)}
        status = "running" if statuses & {"pending", "running"} else "needs_action" if statuses & {"needs_captcha", "needs_official_verification"} else "done"
        with self.connection() as db:
            db.execute("UPDATE jobs SET status=? WHERE id=?", (status, job_id))

    def recent_jobs(self, session_id: str):
        with self.connection() as db:
            return [row[0] for row in db.execute("""SELECT DISTINCT j.id,j.created FROM jobs j
                LEFT JOIN results r ON r.job_id=j.id LEFT JOIN session_accounts s ON s.account_id=r.account_id
                WHERE j.session_id=? OR s.session_id=? ORDER BY j.created DESC LIMIT 20""", (session_id, session_id))]

    def recover(self):
        """中断的写请求可能已经在平台执行，绝不在启动时重放。"""
        with self.connection() as db:
            db.execute("UPDATE logins SET status='expired',message='服务已重启，请刷新登录二维码' WHERE status='waiting'")
            db.execute("UPDATE results SET status='unknown',message='服务中断，结果未确认，请到官方 App 核实',secret=NULL WHERE status='running'")
            db.execute("UPDATE results SET status='skipped',message='服务重启，此账号尚未执行，请重新扫码',secret=NULL WHERE status='pending'")
            ids = [row[0] for row in db.execute("SELECT id FROM jobs WHERE status='running'")]
        for job_id in ids:
            self.update_job_status(job_id)

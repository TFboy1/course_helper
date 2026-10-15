from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import time
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken


class _HybridRow(dict):
    """同时支持 row['column'] 和 row[0]，统一 SQLite/PostgreSQL 结果。"""

    def __getitem__(self, key):
        if isinstance(key, int):
            key = tuple(self.keys())[key]
        return super().__getitem__(key)


def _postgres_row(cursor):
    def make_row(values):
        columns = [column.name for column in cursor.description]
        return _HybridRow(zip(columns, values))
    return make_row


class _PostgresConnection:
    def __init__(self, connection):
        self.connection = connection

    @staticmethod
    def _sql(query):
        query = query.replace("?", "%s")
        if query.lstrip().upper().startswith("INSERT OR IGNORE INTO"):
            query = query.replace("INSERT OR IGNORE INTO", "INSERT INTO", 1) + " ON CONFLICT DO NOTHING"
        return query

    def execute(self, query, params=()):
        return self.connection.execute(self._sql(query), params)

    def executemany(self, query, params):
        return self.connection.executemany(self._sql(query), params)


def token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class AccountBindingError(ValueError):
    pass


class Store:
    """少量用户的同步 SQLite 存储；事务中不执行网络请求。"""

    # 留出一次清理轮询的时间，保证常驻服务在两小时内完成物理删除。
    JOB_RETENTION_SECONDS = 2 * 60 * 60 - 60
    POSTGRES_SCHEMA_VERSION = "3"

    def __init__(self, path: Path | str, key: str):
        self.is_postgres = isinstance(path, str)
        self.path = None if self.is_postgres else path
        self.cipher = Fernet(key.encode("ascii"))
        self.connection_pool = None
        if self.is_postgres:
            from psycopg_pool import ConnectionPool

            self.connection_pool = ConnectionPool(path, kwargs={"row_factory": _postgres_row}, min_size=1, max_size=5, timeout=10)
            self._initialize_postgres()
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires REAL NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member', member_id TEXT
                );
                CREATE TABLE IF NOT EXISTS access_codes (
                    id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, code_hint TEXT NOT NULL,
                    created REAL NOT NULL, created_by TEXT, used_at REAL, used_by TEXT, revoked_at REAL,
                    reusable INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS accounts (
                    id TEXT PRIMARY KEY, platform TEXT NOT NULL, server TEXT NOT NULL,
                    uid TEXT NOT NULL, name TEXT NOT NULL, credentials TEXT,
                    authorized INTEGER NOT NULL DEFAULT 1, valid INTEGER NOT NULL DEFAULT 1,
                    updated REAL NOT NULL, UNIQUE(platform, server, uid)
                );
                CREATE TABLE IF NOT EXISTS session_accounts (
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    PRIMARY KEY(session_id, account_id)
                );
                CREATE TABLE IF NOT EXISTS member_accounts (
                    member_id TEXT NOT NULL, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    platform TEXT NOT NULL, PRIMARY KEY(member_id, account_id)
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
                    created REAL NOT NULL, expires REAL, UNIQUE(session_id, request_id)
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
            session_columns = {row["name"] for row in db.execute("PRAGMA table_info(sessions)")}
            if "role" not in session_columns:
                db.execute("ALTER TABLE sessions ADD COLUMN role TEXT NOT NULL DEFAULT 'member'")
            if "member_id" not in session_columns:
                db.execute("ALTER TABLE sessions ADD COLUMN member_id TEXT")
            access_code_columns = {row["name"] for row in db.execute("PRAGMA table_info(access_codes)")}
            if "reusable" not in access_code_columns:
                db.execute("ALTER TABLE access_codes ADD COLUMN reusable INTEGER NOT NULL DEFAULT 1")
            db.execute("UPDATE access_codes SET reusable=0 WHERE code_hint='旧版固定邀请码'")
            job_columns = {row["name"] for row in db.execute("PRAGMA table_info(jobs)")}
            if "expires" not in job_columns:
                db.execute("ALTER TABLE jobs ADD COLUMN expires REAL")
            db.execute("CREATE INDEX IF NOT EXISTS jobs_expires ON jobs(expires)")
            db.execute("CREATE INDEX IF NOT EXISTS access_codes_created ON access_codes(created)")
            db.execute("CREATE INDEX IF NOT EXISTS member_accounts_owner ON member_accounts(member_id)")
            db.execute("""INSERT OR IGNORE INTO member_accounts(member_id,account_id,platform)
                SELECT c.id,a.id,a.platform FROM access_codes c
                JOIN session_accounts s ON s.session_id=c.used_by
                JOIN accounts a ON a.id=s.account_id WHERE c.used_by IS NOT NULL""")
            db.execute("""UPDATE sessions SET member_id=(SELECT id FROM access_codes WHERE used_by=sessions.id)
                WHERE member_id IS NULL AND EXISTS (SELECT 1 FROM access_codes WHERE used_by=sessions.id)""")
            marker = db.execute("SELECT value FROM metadata WHERE key='credential_key'").fetchone()
            if marker:
                try:
                    if self.unpack(marker[0]) != {"version": 1}:
                        raise ValueError("不支持的凭据格式")
                except (InvalidToken, ValueError):
                    raise ValueError("CREDENTIAL_KEY 与现有数据库不匹配，请恢复原密钥；数据未被清除") from None
            else:
                db.execute("INSERT INTO metadata VALUES ('credential_key', ?)", (self.pack({"version": 1}),))
            # 旧版通过手动授权开关管理参与状态；升级后有效登录自动加入共享池。
            db.execute("UPDATE accounts SET authorized=1 WHERE valid=1 AND credentials IS NOT NULL")

    def _initialize_postgres(self):
        with self.connection() as db:
            # Vercel 的多个冷启动实例可能同时启动；先串行化迁移，避免 DDL 死锁。
            db.execute("SELECT pg_advisory_xact_lock(730241, 2)")
            db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            metadata = {row["key"]: row["value"] for row in db.execute(
                "SELECT key,value FROM metadata WHERE key IN ('schema_version','credential_key')")}
            if metadata.get("schema_version") == self.POSTGRES_SCHEMA_VERSION:
                marker = (metadata["credential_key"],) if "credential_key" in metadata else None
                self._check_credential_marker(db, marker)
                return
            db.execute("""CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires DOUBLE PRECISION NOT NULL,
                role TEXT NOT NULL DEFAULT 'member', member_id TEXT
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS access_codes (
                id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, code_hint TEXT NOT NULL,
                created DOUBLE PRECISION NOT NULL, created_by TEXT, used_at DOUBLE PRECISION,
                used_by TEXT, revoked_at DOUBLE PRECISION, reusable INTEGER NOT NULL DEFAULT 1
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY, platform TEXT NOT NULL, server TEXT NOT NULL,
                uid TEXT NOT NULL, name TEXT NOT NULL, credentials TEXT,
                authorized INTEGER NOT NULL DEFAULT 1, valid INTEGER NOT NULL DEFAULT 1,
                updated DOUBLE PRECISION NOT NULL, UNIQUE(platform, server, uid)
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS session_accounts (
                session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                PRIMARY KEY(session_id, account_id)
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS member_accounts (
                member_id TEXT NOT NULL, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                platform TEXT NOT NULL, PRIMARY KEY(member_id, account_id)
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS logins (
                id TEXT PRIMARY KEY, session_id TEXT NOT NULL, platform TEXT NOT NULL,
                server TEXT NOT NULL, status TEXT NOT NULL, message TEXT NOT NULL DEFAULT '',
                secret TEXT NOT NULL, expires DOUBLE PRECISION NOT NULL, account_id TEXT
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, session_id TEXT NOT NULL, request_id TEXT NOT NULL,
                input_hash TEXT NOT NULL, platform TEXT NOT NULL, server TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running', secret TEXT NOT NULL,
                created DOUBLE PRECISION NOT NULL, expires DOUBLE PRECISION,
                UNIQUE(session_id, request_id)
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS results (
                job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                account_id TEXT NOT NULL, name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', message TEXT NOT NULL DEFAULT '等待执行',
                secret TEXT, updated DOUBLE PRECISION NOT NULL,
                PRIMARY KEY(job_id, account_id)
            )""")
            db.execute("CREATE TABLE IF NOT EXISTS account_leases (account_id TEXT PRIMARY KEY, owner TEXT NOT NULL, expires DOUBLE PRECISION NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS results_account ON results(account_id)")
            db.execute("CREATE INDEX IF NOT EXISTS jobs_expires ON jobs(expires)")
            db.execute("CREATE INDEX IF NOT EXISTS access_codes_created ON access_codes(created)")
            db.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS member_id TEXT")
            db.execute("ALTER TABLE access_codes ADD COLUMN IF NOT EXISTS reusable INTEGER NOT NULL DEFAULT 1")
            db.execute("UPDATE access_codes SET reusable=0 WHERE code_hint='旧版固定邀请码'")
            db.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'member'")
            db.execute("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS expires DOUBLE PRECISION")
            db.execute("CREATE INDEX IF NOT EXISTS member_accounts_owner ON member_accounts(member_id)")
            db.execute("""INSERT OR IGNORE INTO member_accounts(member_id,account_id,platform)
                SELECT c.id,a.id,a.platform FROM access_codes c
                JOIN session_accounts s ON s.session_id=c.used_by
                JOIN accounts a ON a.id=s.account_id WHERE c.used_by IS NOT NULL""")
            db.execute("""UPDATE sessions SET member_id=(SELECT id FROM access_codes WHERE used_by=sessions.id)
                WHERE member_id IS NULL AND EXISTS (SELECT 1 FROM access_codes WHERE used_by=sessions.id)""")
            db.execute("INSERT INTO metadata(key,value) VALUES ('credential_key', ?) ON CONFLICT(key) DO NOTHING",
                       (self.pack({"version": 1}),))
            marker = db.execute("SELECT value FROM metadata WHERE key='credential_key'").fetchone()
            self._check_credential_marker(db, marker)
            db.execute("UPDATE accounts SET authorized=1 WHERE valid=1 AND credentials IS NOT NULL")
            db.execute("INSERT INTO metadata(key,value) VALUES ('schema_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       (self.POSTGRES_SCHEMA_VERSION,))

    def _check_credential_marker(self, db, marker):
        if marker:
            try:
                if self.unpack(marker[0]) != {"version": 1}:
                    raise ValueError("不支持的凭据格式")
            except (InvalidToken, ValueError):
                raise ValueError("CREDENTIAL_KEY 与现有数据库不匹配，请恢复原密钥；数据未被清除") from None
        # PostgreSQL 的初始化分支已用 ON CONFLICT 安全插入；SQLite 在旧初始化流程单独处理。

    @contextmanager
    def connection(self):
        if self.is_postgres:
            with self.connection_pool.connection() as db:
                yield _PostgresConnection(db)
            return
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

    def new_session(self, days: int, role: str = "member"):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.connection() as db:
            db.execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
            db.execute("INSERT INTO sessions (id,csrf,expires,role) VALUES (?,?,?,?)",
                       (token_hash(token), csrf, time.time() + days * 86400, role))
        return token, csrf

    def seed_access_code(self, code: str):
        normalized = code.strip().upper()
        if not normalized:
            return
        with self.connection() as db:
            db.execute("INSERT OR IGNORE INTO access_codes(id,code_hash,code_hint,created,reusable) VALUES (?,?,?,?,0)",
                       (str(uuid4()), token_hash(normalized), "旧版固定邀请码", time.time()))

    def create_access_code(self, session_id: str):
        secret = secrets.token_hex(16).upper()
        code = "CDK-" + "-".join(secret[index:index + 4] for index in range(0, len(secret), 4))
        code_id, created = str(uuid4()), time.time()
        with self.connection() as db:
            db.execute("INSERT INTO access_codes(id,code_hash,code_hint,created,created_by) VALUES (?,?,?,?,?)",
                       (code_id, token_hash(code), f"CDK-{secret[:4]}-{secret[4:8]}-…", created, session_id))
        return {"id": code_id, "code": code, "code_hint": f"CDK-{secret[:4]}-{secret[4:8]}-…",
                "status": "available", "created_at": created, "used_at": None}

    def list_access_codes(self):
        with self.connection() as db:
            rows = db.execute("SELECT id,code_hint,created,used_at,revoked_at,reusable FROM access_codes ORDER BY created DESC").fetchall()
        codes = []
        for row in rows:
            code = dict(row)
            if code["revoked_at"] is not None:
                code["status"] = "revoked"
            elif code["reusable"]:
                code["status"] = "available"
            else:
                code["status"] = "used" if code["used_at"] is not None else "legacy"
            code["created_at"] = code.pop("created")
            codes.append(code)
        return codes

    def redeem_access_code(self, code: str, days: int):
        normalized = code.strip().upper()
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        session_id, now = token_hash(token), time.time()
        with self.connection() as db:
            row = db.execute("SELECT id FROM access_codes WHERE code_hash=? AND revoked_at IS NULL",
                             (token_hash(normalized),)).fetchone()
            if not row:
                return None
            member_id = row["id"]
            updated = db.execute("""UPDATE access_codes SET used_at=COALESCE(used_at,?),used_by=COALESCE(used_by,?)
                WHERE id=? AND revoked_at IS NULL AND (reusable=1 OR used_at IS NULL)""",
                                 (now, session_id, member_id))
            if updated.rowcount != 1:
                return None
            db.execute("DELETE FROM sessions WHERE expires < ?", (now,))
            db.execute("INSERT INTO sessions (id,csrf,expires,role,member_id) VALUES (?,?,?,'member',?)",
                       (session_id, csrf, now + days * 86400, member_id))
        return token, csrf

    def revoke_access_code(self, code_id: str):
        with self.connection() as db:
            updated = db.execute("UPDATE access_codes SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
                                 (time.time(), code_id))
            if updated.rowcount == 1:
                return "revoked"
            row = db.execute("SELECT used_at,revoked_at FROM access_codes WHERE id=?", (code_id,)).fetchone()
        if not row:
            return "missing"
        return "revoked"

    def session(self, token: str | None):
        if not token:
            return None
        with self.connection() as db:
            row = db.execute("""SELECT s.* FROM sessions s LEFT JOIN access_codes c ON c.id=s.member_id
                WHERE s.id=? AND s.expires>? AND (s.member_id IS NULL OR c.revoked_at IS NULL)""",
                             (token_hash(token), time.time())).fetchone()
        return dict(row) if row else None

    def delete_session(self, session_id: str):
        with self.connection() as db:
            db.execute("DELETE FROM sessions WHERE id=?", (session_id,))

    def session_active(self, session_id: str):
        return self.session_info(session_id) is not None

    def session_info(self, session_id: str):
        with self.connection() as db:
            row = db.execute("""SELECT s.* FROM sessions s LEFT JOIN access_codes c ON c.id=s.member_id
                WHERE s.id=? AND s.expires>? AND (s.member_id IS NULL OR c.revoked_at IS NULL)""",
                             (session_id, time.time())).fetchone()
        return dict(row) if row else None

    def same_principal(self, first_session_id: str, second_session_id: str) -> bool:
        if first_session_id == second_session_id:
            return True
        with self.connection() as db:
            return db.execute("""SELECT 1 FROM sessions a JOIN sessions b ON a.member_id=b.member_id
                WHERE a.id=? AND b.id=? AND a.member_id IS NOT NULL""",
                (first_session_id, second_session_id)).fetchone() is not None

    def owns(self, session_id: str, account_id: str) -> bool:
        with self.connection() as db:
            return db.execute("""SELECT 1 FROM session_accounts WHERE session_id=? AND account_id=?
                UNION ALL SELECT 1 FROM member_accounts WHERE member_id=(SELECT member_id FROM sessions WHERE id=?)
                AND account_id=? LIMIT 1""", (session_id, account_id, session_id, account_id)).fetchone() is not None

    def account(self, account_id: str):
        with self.connection() as db:
            row = db.execute("SELECT * FROM accounts WHERE id=?", (account_id,)).fetchone()
        return dict(row) if row else None

    def save_account(self, session_id: str, platform: str, server: str, profile: dict, credentials: dict):
        with self.connection() as db:
            session = db.execute("SELECT member_id FROM sessions WHERE id=?", (session_id,)).fetchone()
            member_id = session["member_id"] if session else None
            if member_id and platform == "rainClassroom":
                if self.is_postgres:
                    code = db.execute("SELECT revoked_at FROM access_codes WHERE id=? FOR UPDATE", (member_id,)).fetchone()
                else:
                    db.execute("UPDATE access_codes SET used_at=used_at WHERE id=?", (member_id,))
                    code = db.execute("SELECT revoked_at FROM access_codes WHERE id=?", (member_id,)).fetchone()
                if not code or code["revoked_at"] is not None:
                    raise AccountBindingError("此 CDK 已作废，请联系管理员")
                existing_rain = db.execute("""SELECT a.server,a.uid FROM member_accounts m
                    JOIN accounts a ON a.id=m.account_id
                    WHERE m.member_id=? AND m.platform='rainClassroom' LIMIT 1""", (member_id,)).fetchone()
                if existing_rain and (existing_rain["server"], existing_rain["uid"]) != (server, profile["uid"]):
                    raise AccountBindingError("每个 CDK 只能绑定一个雨课堂账号；请先解绑已有账号，再登录新的账号")
            if self.is_postgres:
                row = db.execute("""INSERT INTO accounts (id,platform,server,uid,name,credentials,authorized,updated)
                          VALUES (?,?,?,?,?,?,1,?) ON CONFLICT(platform,server,uid) DO UPDATE SET
                          name=excluded.name,credentials=excluded.credentials,authorized=1,valid=1,updated=excluded.updated
                          RETURNING id""",
                          (str(uuid4()), platform, server, profile["uid"], profile["name"], self.pack(credentials), time.time())).fetchone()
                account_id = row["id"]
            else:
                row = db.execute("SELECT id FROM accounts WHERE platform=? AND server=? AND uid=?", (platform, server, profile["uid"])).fetchone()
                account_id = row[0] if row else str(uuid4())
                db.execute("""INSERT INTO accounts (id,platform,server,uid,name,credentials,authorized,updated)
                              VALUES (?,?,?,?,?,?,1,?) ON CONFLICT(platform,server,uid) DO UPDATE SET
                              name=excluded.name,credentials=excluded.credentials,authorized=1,valid=1,updated=excluded.updated""",
                           (account_id, platform, server, profile["uid"], profile["name"], self.pack(credentials), time.time()))
            if member_id:
                db.execute("INSERT OR IGNORE INTO member_accounts(member_id,account_id,platform) VALUES (?,?,?)",
                           (member_id, account_id, platform))
            else:
                db.execute("INSERT OR IGNORE INTO session_accounts VALUES (?, ?)", (session_id, account_id))
        return account_id

    def own_accounts(self, session_id: str):
        with self.connection() as db:
            return [{key: row[key] for key in ("id", "platform", "server", "name", "valid")}
                    for row in db.execute("""SELECT DISTINCT a.id,a.platform,a.server,a.name,a.valid,a.updated
                FROM accounts a LEFT JOIN session_accounts s ON s.account_id=a.id AND s.session_id=?
                LEFT JOIN sessions owner ON owner.id=?
                LEFT JOIN member_accounts m ON m.account_id=a.id AND m.member_id=owner.member_id
                WHERE s.session_id IS NOT NULL OR m.member_id IS NOT NULL ORDER BY a.updated DESC""",
                (session_id, session_id))]

    def owned_ids(self, session_id: str):
        return {account["id"] for account in self.own_accounts(session_id)}

    def pool(self, platform: str, server: str):
        with self.connection() as db:
            return [dict(row) for row in db.execute("SELECT id,name FROM accounts WHERE platform=? AND server=? AND authorized=1 AND valid=1 AND credentials IS NOT NULL ORDER BY updated", (platform, server))]

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

    def update_login_secret(self, login_id: str, secret: dict):
        with self.connection() as db:
            db.execute("UPDATE logins SET secret=? WHERE id=? AND status='waiting'", (self.pack(secret), login_id))

    def pending_logins(self, session_id: str | None = None):
        with self.connection() as db:
            sql, args = "SELECT id FROM logins WHERE status='waiting'", ()
            if session_id:
                sql, args = sql + " AND session_id=?", (session_id,)
            return [row[0] for row in db.execute(sql, args)]

    def existing_job(self, session_id: str, request_id: str):
        self.prune_expired_jobs()
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
        self.prune_expired_jobs()
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

    def claim_result(self, job_id: str, account_id: str) -> bool:
        with self.connection() as db:
            cursor = db.execute("UPDATE results SET status='running',message='正在提交',updated=? WHERE job_id=? AND account_id=? AND status='pending'",
                                (time.time(), job_id, account_id))
            return cursor.rowcount == 1

    def acquire_account_lease(self, account_id: str, owner: str, seconds: int = 120) -> bool:
        if not self.is_postgres:
            return True
        with self.connection() as db:
            row = db.execute("""INSERT INTO account_leases(account_id,owner,expires) VALUES (?,?,?)
                ON CONFLICT(account_id) DO UPDATE SET owner=excluded.owner,expires=excluded.expires
                WHERE account_leases.expires<=? RETURNING owner""",
                (account_id, owner, time.time() + seconds, time.time())).fetchone()
            return bool(row and row["owner"] == owner)

    def release_account_lease(self, account_id: str, owner: str):
        if not self.is_postgres:
            return
        with self.connection() as db:
            db.execute("DELETE FROM account_leases WHERE account_id=? AND owner=?", (account_id, owner))

    def update_job_status(self, job_id: str):
        statuses = {row["status"] for row in self.results(job_id)}
        status = "running" if statuses & {"pending", "running"} else "needs_action" if statuses & {"needs_captcha", "needs_official_verification"} else "done"
        with self.connection() as db:
            if status == "running":
                db.execute("UPDATE jobs SET status=? WHERE id=?", (status, job_id))
            else:
                db.execute("UPDATE jobs SET status=?,expires=COALESCE(expires,?) WHERE id=?",
                           (status, time.time() + self.JOB_RETENTION_SECONDS, job_id))

    def prune_expired_jobs(self):
        """删除过期签到任务；结果通过外键级联删除，账号与登录态不受影响。"""
        now = time.time()
        with self.connection() as db:
            cutoff = now - 330
            db.execute("UPDATE logins SET status='expired',message='登录二维码已过期，请刷新' WHERE status='waiting' AND expires<=?", (now,))
            db.execute("UPDATE results SET status='unknown',message='服务中断，结果未确认，请到官方 App 核实',secret=NULL,updated=? WHERE status='running' AND updated<=?",
                       (now, cutoff))
            db.execute("""UPDATE results SET status='skipped',message='服务中断，此账号尚未执行，请重新签到',secret=NULL,updated=?
                WHERE status='pending' AND job_id IN (SELECT id FROM jobs WHERE status='running' AND created<=?)""",
                       (now, cutoff))
            db.execute("""UPDATE jobs SET status=CASE
                    WHEN EXISTS (SELECT 1 FROM results WHERE results.job_id=jobs.id AND status IN ('needs_captcha','needs_official_verification')) THEN 'needs_action'
                    ELSE 'done' END,
                    expires=COALESCE(expires,created+?)
                WHERE status='running' AND created<=?
                  AND NOT EXISTS (SELECT 1 FROM results WHERE results.job_id=jobs.id AND status IN ('pending','running'))""",
                       (self.JOB_RETENTION_SECONDS, cutoff))
            cursor = db.execute("DELETE FROM jobs WHERE expires IS NOT NULL AND expires<=?", (now,))
            return cursor.rowcount

    def recent_jobs(self, session_id: str | None):
        self.prune_expired_jobs()
        with self.connection() as db:
            if session_id is None:
                return [row[0] for row in db.execute("SELECT id FROM jobs ORDER BY created DESC LIMIT 20")]
            return [row[0] for row in db.execute("""SELECT DISTINCT j.id,j.created FROM jobs j
                LEFT JOIN results r ON r.job_id=j.id LEFT JOIN session_accounts s ON s.account_id=r.account_id
                LEFT JOIN sessions owner ON owner.id=?
                LEFT JOIN sessions job_owner ON job_owner.id=j.session_id
                LEFT JOIN member_accounts m ON m.account_id=r.account_id AND m.member_id=owner.member_id
                WHERE j.session_id=? OR s.session_id=? OR job_owner.member_id=owner.member_id OR m.member_id IS NOT NULL
                ORDER BY j.created DESC LIMIT 20""", (session_id, session_id, session_id))]

    def recover(self):
        """中断的写请求可能已经在平台执行，绝不在启动时重放。"""
        with self.connection() as db:
            db.execute("UPDATE logins SET status='expired',message='服务已重启，请刷新登录二维码' WHERE status='waiting'")
            db.execute("UPDATE results SET status='unknown',message='服务中断，结果未确认，请到官方 App 核实',secret=NULL WHERE status='running'")
            db.execute("UPDATE results SET status='skipped',message='服务重启，此账号尚未执行，请重新扫码',secret=NULL WHERE status='pending'")
            ids = [row[0] for row in db.execute("SELECT id FROM jobs WHERE status='running'")]
        for job_id in ids:
            self.update_job_status(job_id)

    def close(self):
        if self.connection_pool:
            self.connection_pool.close()

"""在线 SQLite 备份，将凭据密钥一起保存到一个新的目录。"""
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import sqlite3
import sys

from app.config import Settings


if __name__ == "__main__":
    settings = Settings.from_env()
    source = sqlite3.connect(settings.database.resolve().as_uri() + "?mode=ro", uri=True)
    destination = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("backups") / (datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3))
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    database = destination / "course-helper.sqlite3"
    target = sqlite3.connect(database)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    database.chmod(0o600)
    env = destination / "restore.env"
    with env.open("x", encoding="utf-8", newline="\n") as file:
        file.write(f"JOIN_CODE={json.dumps(settings.join_code, ensure_ascii=False)}\nCREDENTIAL_KEY={settings.credential_key}\nPUBLIC_ORIGIN={settings.public_origin}\nDATABASE_PATH=data/course-helper.sqlite3\nBATCH_CONCURRENCY={settings.batch_concurrency}\n")
    env.chmod(0o600)
    print(f"备份完成：{destination.resolve()}（包含数据库与恢复密钥，请妥善保存）")

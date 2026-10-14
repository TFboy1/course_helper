"""创建本地配置；已有文件一律保留。"""
from pathlib import Path
import secrets

from cryptography.fernet import Fernet


if __name__ == "__main__":
    path = Path(__file__).resolve().parent / ".env"
    code = secrets.token_urlsafe(12)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as file:
            file.write(f"JOIN_CODE={code}\nCREDENTIAL_KEY={Fernet.generate_key().decode('ascii')}\nPUBLIC_ORIGIN=http://localhost:8000\nDATABASE_PATH=data/course-helper.sqlite3\nBATCH_CONCURRENCY=10\n")
        path.chmod(0o600)
        print(f"已创建本地 .env。加入码：{code}")
        print("请保存配置文件；不要更换已投入使用的 CREDENTIAL_KEY。")
    except FileExistsError:
        print(".env 已存在，保留原配置。加入码请查看文件中的 JOIN_CODE。")

# 课程助手网页版

Vue 3 + FastAPI，适合少量熟人共享二维码签到。输入加入码，用学习通或雨课堂官方 App 扫码登录，自行开启授权；一位成员扫描签到码，后台为同平台、同雨课堂服务器的有效授权账号执行签到。

账号授权持续保存在服务器，关闭网页或退出网站都不会撤销授权。关闭授权会停止新的请求，已发往平台的请求无法撤回。重新验证同一平台账号会更新其 Cookie，并保留之前的授权选择。解绑则删除登录凭据并撤销授权。

## 本地启动

需要 Python 3.11+、uv、Node.js 20.19+ 或 22.12+、npm。以下命令以仓库根目录为起点，PowerShell 中 npm 可写成 `npm.cmd`。

```powershell
cd web
npm.cmd install
npm.cmd run build
cd ../backend
uv sync --link-mode hardlink
uv run python configure.py
uv run --env-file .env uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 --no-access-log
```

打开 http://localhost:8000。首次配置会输出随机加入码；之后可在 `backend/.env` 的 `JOIN_CODE` 中查看。`configure.py` 不会覆盖已有配置。

uv 复用全局缓存；缓存和虚拟环境位于不同磁盘时，hardlink 会自动回退为复制。前端构建后由 FastAPI 提供静态文件和 API，浏览器端无需跨域配置。

开发页面时，在另一个终端运行 `cd web; npm.cmd run dev`，访问 http://localhost:5173，Vite 将 `/api` 转发给本地 8000 端口。本文交付流程只运行前端生产 build，页面操作由使用者自行验证。

## 配置与 HTTPS 部署

| 变量 | 含义 |
|---|---|
| `JOIN_CODE` | 加入码，至少 8 个字符。修改后影响新进入者，已有网站会话继续有效 |
| `CREDENTIAL_KEY` | Fernet 凭据密钥。必须固定保存，更换后无法解密原数据 |
| `PUBLIC_ORIGIN` | 实际访问来源，例如 `https://courses.example.com`，不带路径或末尾斜杠 |
| `DATABASE_PATH` | SQLite 文件路径；相对路径以启动后端的目录为基准 |
| `BATCH_CONCURRENCY` | 签到并发数，默认 10，允许 1–50 |

1. 在服务器构建网页并安装后端依赖，为数据目录保留持久磁盘。
2. 生成服务器自己的 `.env`，填写加入码、固定的密钥，将 `PUBLIC_ORIGIN` 设置为实际 HTTPS 域名。
3. 运行后端，绑定 `127.0.0.1:8000`，仅启用一个 worker。
4. 按 `Caddyfile.example` 配置域名反向代理，开放 HTTPS 所需端口，并让进程管理器管理后端和 Caddy。[Caddy 的流式代理说明](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#streaming)包含即时转发设置。

摄像头需要 HTTPS 或 localhost；不支持摄像头时可以上传图片或粘贴二维码链接。SSE 应保持即时转发，使用 Nginx 时需关闭此位置的 `proxy_buffering` 并设置足够长的读取超时。服务采用数据库旁的进程锁；多个 worker 或两个服务共用同一数据库会拒绝启动。

生产网站会话 Cookie 为 HttpOnly、Secure、SameSite=Strict；写操作检查来源和 CSRF。加入码不替代平台身份验证，只有本人完成官方扫码登录后才能管理账号。Cookie、原始签到二维码和滑块上下文只在服务端加密保存，API 不返回平台 Cookie 或课堂 token。参与者只能查看自己的结果，扫码发起者可查看该任务全部参与者的结果与处理滑块。

## 签到行为

- 学习通二维码先查本人回执和活动条件，已签到的账号跳过；二维码签名和重定向按原客户端协议解析。
- 雨课堂逐账号调用 `app/scan → lesson/checkin`，沿用原客户端 `source=21`、`joinIfNotIn=true` 的进班行为。共享授权池不按课程另设房间，请参与同一小组的成员开启授权。
- 滑块由发起者或账号本人在网页人工完成，验证上下文按账号与任务绑定，五分钟过期。
- 二维码附带人脸或定位要求时，提示本人在官方 App 完成，学习通可点“刷新官方回执”核实结果。
- 超时、服务器错误或无法解析的签到响应标记为未确认，不自动重复签到。雨课堂首版不提供回执查询，未确认结果需在官方 App 核实。
- 浏览器通过 SSE 自动接收自己的账号与签到记录变动。离开页面不会中止已建立的后台任务。
- 服务重启不重放任务；执行中的记录标为未确认，尚未执行的记录标为停止。有效登录凭据和授权选择保留。

首版仅支持两平台二维码签到及网页滑块。PPT、课堂答题、密码/短信登录、其他签到类型和网页内人脸、定位验证不包含在此版本。

## API

写操作需要网站会话 Cookie 和 `X-CSRF-Token`，令牌来自 `/api/me` 或加入成功的响应。二维码登录请求只在所属网站会话内可见。

| 接口 | 用途 |
|---|---|
| `POST /api/access`、`DELETE /api/access` | 加入码进入、退出网站 |
| `GET /api/me`、`GET /api/me/events` | 本人账号、可见任务和实时更新 |
| `POST /api/logins` | 创建二维码登录，传入 `platform`、可选的雨课堂 `server` |
| `GET /api/logins/{id}`、`GET /api/logins/{id}/events`、`DELETE /api/logins/{id}` | 登录状态、进度与取消 |
| `PATCH /api/accounts/{id}/authorization`、`DELETE /api/accounts/{id}` | 传入 `enabled` 修改授权、解绑账号 |
| `POST /api/sign-jobs` | 提交 `qr_text` 与 UUID 格式的 `request_id` |
| `GET /api/sign-jobs/{id}`、`GET /api/sign-jobs/{id}/events` | 查询或订阅任务结果 |
| `POST /api/sign-jobs/{id}/accounts/{account_id}/captcha` | 创建人工滑块，返回公开图片与 challenge ID |
| 上一路径追加 `/verify` | 提交 `challenge_id` 和原始图片坐标 `x`，继续签到 |
| `POST /api/sign-jobs/{id}/accounts/{account_id}/receipt` | 学习通官方回执查询 |
| `GET /api/health` | 后端健康状态 |

同一会话的相同请求 ID 重复提交会返回原任务，相同 ID 配不同二维码返回 409。任务参与账号由服务端从授权池确定，客户端不能提交其他人的 Cookie 或任意指定待签到账号。

## 后端检查

```powershell
cd backend
uv run python -m unittest discover -s tests -v
```

检查通过 HTTPX MockTransport 模拟平台，覆盖扫码登录 Cookie 隔离、服务器区分、权限与 CSRF、撤销授权、任务幂等、并发控制、部分失败、滑块续签、网络异常和重启恢复。模拟检查不证明第三方接口当前可用；实际登录和签到需要对应测试账号及有效二维码验证。测试不会向真实平台发起签到。

## 备份和恢复

在后端目录运行：

```powershell
uv run --env-file .env python backup.py
```

它使用 SQLite 在线备份接口，生成新的 `backups/时间-随机值/` 目录，包含数据库和 `restore.env`，已有目录不会被覆盖。可以传入一个尚不存在的目标目录作为参数。备份包含解密密钥，应保存在私人位置，数据库与密钥缺一不可；运行中不要只复制 SQLite 主文件而遗漏 WAL。

恢复时先停止后端，保留当前数据，在新数据目录放入备份数据库。将 `restore.env` 的固定密钥及配置恢复到 `.env`，确认 `DATABASE_PATH` 指向恢复的数据库，并检查实际域名。重新启动后，网站会话、账号授权和结果继续保留；未完成签到不会被重放。错误密钥会拒绝启动，不会创建空库替代原数据。

网页代码沿用仓库根目录的 GPL-3.0 许可证。

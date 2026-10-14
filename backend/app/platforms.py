"""迁移自 lib/api；只包含扫码登录、二维码签到和人工滑块验证。"""
from dataclasses import dataclass, field
import base64
from http.cookiejar import Cookie
import hashlib
import json
import math
import re
import time
from urllib.parse import parse_qs, unquote, urljoin, urlsplit
from uuid import uuid4

from cryptography.hazmat.primitives import padding as symmetric_padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import httpx


RAIN_SERVERS = {
    "yuketang": "https://www.yuketang.cn",
    "pro": "https://pro.yuketang.cn",
    "changjiang": "https://changjiang.yuketang.cn",
    "huanghe": "https://huanghe.yuketang.cn",
}
CX_HOSTS = {"passport2.chaoxing.com", "passport2-api.chaoxing.com", "sso.chaoxing.com", "mobilelearn.chaoxing.com", "captcha.chaoxing.com"}
CX_CAPTCHA_ID = "Qt9FIw9o4pwRjOyqM6yizZBh682qN2TU"
CX_RSA_PUBLIC = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC79d8Ot0hCbxxSISC6x8SCwTBspFSzlLKHJUYqoFNu1TSRaw4hEYkOnvEaL1VyoxV6HXcDrzwYvaFZaZaPQPFnfCHZy5dQwxcmifgSHqS+oKXw40Ys4cVIqnU5d90S7EWSRdBglX489jlqVaNcQSkDx2TYmC+DbAq9FV/BU09ISQIDAQAB"


def md5(value: str) -> str:
    # 旧平台协议要求 MD5；网站凭据与会话不使用此算法。
    return hashlib.md5(value.encode("utf-8"), usedforsecurity=False).hexdigest()


def aes_device_code() -> str:
    padder = symmetric_padding.PKCS7(128).padder()
    data = padder.update(str(uuid4()).encode("utf-8")) + padder.finalize()
    encryptor = Cipher(algorithms.AES(b"QrCbNY@MuK1X8HGw"), modes.ECB()).encryptor()
    return base64.b64encode(encryptor.update(data) + encryptor.finalize()).decode("ascii")


def rsa_device_info(device_id: str) -> str:
    data = json.dumps({
        "app_name": "com.chaoxing.mobile", "app_ver": "6.7.4", "board": "caiman",
        "brand": "google", "cdid": device_id, "cdtype": "Pixel 9 Pro",
        "cpu_ar": "arm64-v8a,armeabi-v7a,armeabi", "device_id": device_id,
        "dpi": "440", "hardware": "caiman", "mediaDrmId": "", "oaid": "1004",
        "os_lang": "", "os_name": "REL", "os_ver": "16", "platform": "android",
        "resolution": "1080*2243", "time_stamp": int(time.time() * 1000),
    }, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    key = serialization.load_der_public_key(base64.b64decode(CX_RSA_PUBLIC))
    chunk_size = key.key_size // 8 - 11
    return base64.b64encode(b"".join(key.encrypt(data[i:i + chunk_size], rsa_padding.PKCS1v15()) for i in range(0, len(data), chunk_size))).decode("ascii")


def safe_https_url(url: str, hosts: set[str]):
    try:
        parsed = urlsplit(url)
        valid = parsed.scheme == "https" and parsed.hostname in hosts and parsed.port in {None, 443}
    except ValueError:
        valid = False
    if not valid or parsed.username or parsed.password or parsed.fragment or any(ord(c) < 32 for c in url):
        raise ValueError("链接的域名、协议或端口不受支持")
    return parsed


def parse_sign_qr(value: str) -> dict:
    url = value.strip()
    hosts = CX_HOSTS | {urlsplit(origin).hostname for origin in RAIN_SERVERS.values()}
    parsed = safe_https_url(url, hosts)
    query = parse_qs(parsed.query)
    if parsed.hostname == "mobilelearn.chaoxing.com" and parsed.path == "/widget/sign/e":
        active_id = query.get("id", [""])[0]
        if not active_id.isdigit() or len(active_id) > 30:
            raise ValueError("学习通二维码缺少有效活动 ID")
        return {"platform": "chaoxing", "server": "", "url": url, "active_id": active_id}
    if parsed.path == "/api/v3/lesson/check-in/dynamic-qr-code" and parsed.query:
        for server, origin in RAIN_SERVERS.items():
            if parsed.hostname == urlsplit(origin).hostname:
                return {"platform": "rainClassroom", "server": server, "url": url}
    raise ValueError("请提供学习通或雨课堂的签到二维码，而不是登录二维码")


def public_message(value, default="平台未完成请求，请到官方 App 查看") -> str:
    text = str(value or default)
    if "<html" in text.lower() or "<!doctype" in text.lower():
        return default
    text = re.sub(r"https?://\S+", "[链接]", text)
    text = re.sub(r"[A-Za-z0-9_+/=-]{24,}", "[已隐藏]", text)
    return text[:200]


class PlatformIssue(Exception):
    def __init__(self, message: str, status: str = "failed"):
        self.message, self.status = message, status
        super().__init__(message)


@dataclass
class Outcome:
    status: str
    message: str
    context: dict = field(default_factory=dict)


class PlatformClient:
    def __init__(self, platform: str, server: str = "", credentials: dict | None = None, uid: str = "", transport=None):
        self.platform, self.server, self.uid = platform, server, uid
        self.before_request = None
        self.name = (credentials or {}).get("name", "")
        self.device_id = (credentials or {}).get("device_id") or uuid4().hex
        self.device_code = (credentials or {}).get("device_code") or aes_device_code()
        self.hosts = CX_HOSTS if platform == "chaoxing" else {urlsplit(RAIN_SERVERS[server]).hostname}
        self.base = "" if platform == "chaoxing" else RAIN_SERVERS[server]
        self.client = httpx.AsyncClient(
            headers=self.headers(), timeout=httpx.Timeout(10, connect=3),
            follow_redirects=False, transport=transport, trust_env=False,
        )
        for item in (credentials or {}).get("cookies", []):
            self.client.cookies.jar.set_cookie(Cookie(
                version=0, name=item["name"], value=item["value"], port=None, port_specified=False,
                domain=item["domain"], domain_specified=item.get("domain_specified", True),
                domain_initial_dot=item["domain"].startswith("."), path=item.get("path", "/"),
                path_specified=True, secure=item.get("secure", False), expires=item.get("expires"),
                discard=item.get("expires") is None, comment=None, comment_url=None,
                rest={"HttpOnly": None} if item.get("http_only") else {}, rfc2109=False,
            ))

    def headers(self):
        if self.platform == "rainClassroom":
            return {
                "user-agent": "Android", "brand": "google Pixel 9 Pro", "uuid": "",
                "buildnumber": "1610", "xtua": "client=app&tag=1.3.3&platform=Android",
                "systemversion": "16", "incremental": "14624737", "accept": "application/json",
                "isphysicaldevice": "true", "xtbz": "ykt", "x-client": "app",
            }
        agent = f"(device:Pixel 9 Pro) Language/zh_CN com.chaoxing.mobile/ChaoXingStudy_3_6.7.4_android_phone_10940_314 (@Kalimdor)_{self.device_id}"
        schild = md5('(schild:ipL$TkeiEmfy1gTXb2XHrdLN0a@7c^vu) ' + agent)
        return {"user-agent": f"Dalvik/2.1.0 (Linux; U; Android 16; Pixel 9 Pro Build/BP4A.260205.002) (schild:{schild}) {agent}", "accept-language": "zh_CN"}

    def credentials(self) -> dict:
        return {"device_id": self.device_id, "device_code": self.device_code, "name": self.name, "cookies": [
            {"name": c.name, "value": c.value, "domain": c.domain, "domain_specified": c.domain_specified,
             "path": c.path, "secure": c.secure, "expires": c.expires,
             "http_only": c.has_nonstandard_attr("HttpOnly")}
            for c in self.client.cookies.jar
        ]}

    async def close(self):
        await self.client.aclose()

    async def request(self, method: str, url: str, *, redirects=False, signing=False, **kwargs):
        url = urljoin(self.base + "/", url) if self.base else url
        safe_https_url(url, self.hosts)
        for _ in range(4):
            if self.before_request:
                self.before_request()
            headers = dict(kwargs.pop("headers", {}))
            if self.platform == "rainClassroom":
                # 从本客户端实际可发送的 Cookie 中提取，避免重名 Cookie/跨服务器混用。
                cookie_request = self.client.build_request(method, url)
                cookies = dict(part.strip().split("=", 1) for part in cookie_request.headers.get("cookie", "").split(";") if "=" in part)
                if cookies:
                    headers.update({"x-csrftoken": cookies.get("csrftoken", ""), "sessionid": cookies.get("sessionid", ""), "x-uid": self.uid})
            response = await self.client.request(method, url, headers=headers, **kwargs)
            if response.status_code == 401:
                raise PlatformIssue("平台登录已失效，请重新扫码登录", "session_expired")
            if response.is_redirect and redirects:
                url = urljoin(str(response.url), response.headers.get("location", ""))
                safe_https_url(url, self.hosts)
                method, kwargs = "GET", {}
                continue
            if signing and response.status_code >= 500:
                raise PlatformIssue("平台没有确认签到结果，请在官方 App 核实", "unknown")
            if not response.is_redirect:
                response.raise_for_status()
            return response
        raise PlatformIssue("平台重定向次数过多，请重新登录")

    @staticmethod
    def json(response, *, uncertain=False):
        try:
            data = response.json()
            if isinstance(data, str):
                data = json.loads(data)
            if isinstance(data, dict):
                return data
        except (ValueError, TypeError):
            pass
        if uncertain:
            raise PlatformIssue("签到响应不完整，结果未确认，请在官方 App 核实", "unknown")
        raise PlatformIssue("平台返回了无法识别的数据，请稍后重试")

    async def start_login(self):
        if self.platform == "chaoxing":
            data = self.json(await self.request("POST", "https://passport2.chaoxing.com/refreshQRCode", data={}))
            uuid, enc = data.get("uuid"), data.get("enc")
            if not uuid or not enc:
                raise PlatformIssue("未能取得学习通登录二维码")
            image = str(httpx.URL("https://passport2.chaoxing.com/createqr", params={"uuid": uuid, "fid": "-1"}))
            return {"uuid": uuid, "enc": enc, "image": image, "content": ""}
        data = self.json(await self.request("GET", "/api/v3/user/login/pre-info"))
        if data.get("code") != 0 or not data.get("data", {}).get("token"):
            raise PlatformIssue("未能取得雨课堂登录二维码")
        info = data["data"]
        image = info.get("qrImage", "")
        if image and not (image.startswith("https://") or image.startswith("data:image/")):
            image = ""
        if not image and not info.get("qrContent"):
            raise PlatformIssue("雨课堂未返回可用的二维码")
        return {"token": info["token"], "image": image, "content": info.get("qrContent", "")}

    async def poll_login(self, meta: dict) -> str:
        if self.platform == "chaoxing":
            data = self.json(await self.request("POST", "https://passport2.chaoxing.com/getauthstatus/v2", data={
                "uuid": meta["uuid"], "enc": meta["enc"], "doubleFactorLogin": "0", "forbidotherlogin": "0",
            }, redirects=True))
            if data.get("status") is True:
                return "success"
            return "expired" if str(data.get("type")) == "2" else "waiting"
        data = self.json(await self.request("POST", "/api/v3/user/login", json={"token": meta["token"]}, timeout=httpx.Timeout(31, connect=3)))
        if data.get("code") == 0:
            return "success"
        if data.get("code") == 50001:
            return "expired"
        raise PlatformIssue(public_message(data.get("msg"), "雨课堂登录失败，请刷新二维码"))

    async def profile(self):
        if self.platform == "rainClassroom":
            data = self.json(await self.request("GET", "/v/course_meta/user_info", redirects=True))
            info = (data.get("data") or {}).get("user_profile") or {}
            uid = info.get("user_id")
        else:
            data = self.json(await self.request("POST", "https://sso.chaoxing.com/apis/login/userLogin4Uname.do", data={"data": rsa_device_info(self.device_id)}, redirects=True))
            if data.get("result") != 1:
                raise PlatformIssue("未能确认学习通用户身份，请重新登录", "session_expired")
            info = data.get("msg") or {}
            uid = info.get("puid")
        if uid is None or str(uid) in {"", "0"}:
            raise PlatformIssue("平台没有返回已验证的用户身份，请重新登录", "session_expired")
        self.uid = str(uid)
        self.name = str(info.get("name") or "未命名用户")[:100]
        return {"uid": self.uid, "name": self.name}

    async def sign(self, target: dict, context: dict | None = None, validate: str | None = None) -> Outcome:
        if self.platform == "rainClassroom":
            scan = self.json(await self.request("POST", "/api/v3/app/scan", json={"url": target["url"]}, signing=True), uncertain=True)
            if scan.get("code") != 0:
                return self.rain_failure(scan)
            lesson_id = (scan.get("data") or {}).get("value")
            if not lesson_id:
                raise PlatformIssue("雨课堂没有返回有效课堂 ID")
            result = self.json(await self.request("POST", "/api/v3/lesson/checkin", json={"source": 21, "lessonId": lesson_id, "joinIfNotIn": True}, signing=True), uncertain=True)
            if result.get("code") == 0:
                return Outcome("success", "签到成功", {"lesson_id": lesson_id})
            return self.rain_failure(result)
        active_id = target["active_id"]
        context = dict(context or {})
        receipt = await self.receipt(active_id)
        if receipt.status != "pending":
            return receipt
        if not context:
            data = self.json(await self.request("GET", "https://mobilelearn.chaoxing.com/v2/apis/active/getPPTActiveInfo", params={"activeId": active_id}))
            if data.get("result") != 1 or not isinstance(data.get("data"), dict):
                raise PlatformIssue("无法读取签到活动，请到官方 App 确认账号或班级")
            activity = data["data"]
            if int(activity.get("otherId", -1)) != 2:
                raise PlatformIssue("这个活动不是二维码签到")
            try:
                needs_location = bool(activity.get("locationText")) or float(activity.get("locationRange") or 0) > 0
            except (TypeError, ValueError):
                needs_location = True
            if activity.get("openCheckFaceFlag") in {1, "1"} or needs_location:
                return Outcome("needs_official_verification", "需要本人在学习通完成定位或人脸补验，再点击刷新回执", {"active_id": active_id})
            context = await self.resolve_chaoxing_qr(target)
        params = {
            "enc": context["enc"], "name": self.name, "activeId": active_id, "uid": self.uid,
            "clientip": "", "location": "", "latitude": "-1", "longitude": "-1", "fid": "0",
            "appType": "15", "deviceCode": self.device_code, "vpProbability": "", "vpStrategy": "",
            "currentFaceId": "", "ifCFP": "0", "courseId": context.get("course_id", ""), "faceEnc": "",
        }
        if validate and context.get("enc2"):
            params.update({"enc2": context["enc2"], "validate": validate})
        response = await self.request("GET", "https://mobilelearn.chaoxing.com/pptSign/stuSignajax", params=params, signing=True)
        if response.is_redirect:
            raise PlatformIssue("学习通登录已失效，请重新登录", "session_expired")
        result = response.text.strip()
        if result == "success":
            return Outcome("success", "签到成功", context)
        if result == "success2":
            return Outcome("failed", "签到已过截止时间", context)
        if result.startswith("validate_"):
            context["enc2"] = result.split("_", 1)[1]
            return Outcome("needs_captcha", "需要滑块验证", context)
        if result == "validate":
            return Outcome("needs_official_verification", "平台要求额外验证，请在官方 App 完成后刷新回执", {"active_id": active_id})
        if "重新扫描" in result or "过期" in result:
            return Outcome("qr_expired", "二维码已过期，请重新扫描", context)
        return Outcome("failed", public_message(result, "学习通未完成签到，请到官方 App 查看"), context)

    @staticmethod
    def rain_failure(result):
        code = result.get("code")
        if code is None:
            return Outcome("unknown", "雨课堂未返回明确结果，请在官方 App 核实")
        message = str(result.get("msg") or "")
        if any(text in message for text in ("登录已失效", "登录过期", "请重新登录", "请登录")):
            return Outcome("session_expired", "雨课堂登录已失效，请重新扫码登录")
        if code == 51203:
            return Outcome("qr_expired", "动态二维码已过期，请重新扫描")
        if code == 50070:
            return Outcome("qr_expired", "课堂要求有效的动态二维码，请重新扫描")
        return Outcome("failed", public_message(result.get("msg"), f"雨课堂未完成签到（错误码 {code}）"))

    async def receipt(self, active_id: str) -> Outcome:
        data = self.json(await self.request("GET", "https://mobilelearn.chaoxing.com/v2/apis/sign/getAttendInfo", params={"activeId": active_id, "moreClassAttendEnc": ""}))
        if data.get("result") != 1 or not isinstance(data.get("data"), dict):
            raise PlatformIssue("无法读取签到回执，请在官方 App 确认账号状态")
        status = data["data"].get("status")
        if status in {1, "1"}:
            return Outcome("already_signed", "平台确认已签到", {"active_id": active_id})
        if status in {0, "0"}:
            return Outcome("pending", "平台尚未确认签到", {"active_id": active_id})
        return Outcome("failed", "此活动已处于请假、缺勤或其他处理状态，请查看官方 App", {"active_id": active_id})

    async def resolve_chaoxing_qr(self, target):
        query = parse_qs(urlsplit(target["url"]).query)
        enc, code = query.get("enc", [""])[0], query.get("c", [""])[0]
        if code:
            detail = self.json(await self.request("GET", "https://mobilelearn.chaoxing.com/newsign/signDetail", params={"activePrimaryId": target["active_id"], "type": "1", "msg": code}))
            sign_code = detail.get("signCode")
            if sign_code and str(sign_code) != code:
                raise PlatformIssue("二维码已过期，请重新扫描", "qr_expired")
        context = {"active_id": target["active_id"], "enc": enc, "course_id": query.get("courseId", [""])[0]}
        if not enc:
            response = await self.request("GET", target["url"])
            location = response.headers.get("location")
            if not location:
                raise PlatformIssue("二维码缺少有效签名，请重新扫描", "qr_expired")
            redirect = urljoin(str(response.url), location)
            parsed = safe_https_url(redirect, {"mobilelearn.chaoxing.com", "passport2.chaoxing.com", "passport2-api.chaoxing.com"})
            if parsed.hostname != "mobilelearn.chaoxing.com":
                raise PlatformIssue("学习通登录已失效，请重新登录", "session_expired")
            args = parse_qs(parsed.query)
            if args.get("activeId", [target["active_id"]])[0] != target["active_id"]:
                raise PlatformIssue("二维码指向了不同的签到活动")
            match = re.search(r"enc=([^&\s]+)", unquote(args.get("rcode", [""])[0]))
            context["enc"] = args.get("enc", [""])[0] or (match.group(1) if match else "")
            context["course_id"] = args.get("courseId", [""])[0]
        if not context["enc"]:
            raise PlatformIssue("二维码没有有效签名，请重新扫描", "qr_expired")
        return context

    @staticmethod
    def jsonp(response):
        match = re.fullmatch(r"\s*cx_captcha_function\((.*)\)\s*;?\s*", response.text, re.S)
        if not match:
            raise PlatformIssue("平台返回的验证码格式不受支持，请刷新")
        try:
            data = json.loads(match.group(1))
            if isinstance(data, dict):
                return data
        except ValueError:
            pass
        raise PlatformIssue("验证码数据不完整，请刷新")

    async def captcha(self, active_id: str):
        timestamp = int(time.time() * 1000)
        referer = f"https://mobilelearn.chaoxing.com/widget/sign/pcStuSignController/preSign?activeId={active_id}"
        conf = self.jsonp(await self.request("GET", "https://captcha.chaoxing.com/captcha/get/conf", params={"callback": "cx_captcha_function", "captchaId": CX_CAPTCHA_ID, "_": str(timestamp)}))
        service_time = int(conf["t"])
        captcha_key = md5(f"{service_time}{uuid4()}")
        token = f"{md5(f'{service_time}{CX_CAPTCHA_ID}slide{captcha_key}')}:{service_time + 300000}"
        iv = md5(f"{CX_CAPTCHA_ID}slide{timestamp}{uuid4()}")
        data = self.jsonp(await self.request("GET", "https://captcha.chaoxing.com/captcha/get/verification/image", params={
            "callback": "cx_captcha_function", "captchaId": CX_CAPTCHA_ID, "type": "slide", "version": "1.1.20",
            "captchaKey": captcha_key, "token": token, "referer": referer, "iv": iv, "_": str(timestamp + 1),
        }))
        images = data.get("imageVerificationVo") or {}
        background, piece = images.get("shadeImage"), images.get("cutoutImage")
        for url in (background, piece):
            if not isinstance(url, str):
                raise PlatformIssue("验证码图片未能加载，请刷新")
            # 图片在浏览器内以 img 显示；服务端不请求这些来自平台的外部图片 URL。
            if not url.startswith("https://"):
                raise PlatformIssue("验证码图片要求 HTTPS，请使用官方 App 补验")
        width = float(images.get("originalWidth") or 320)
        if not math.isfinite(width) or not 100 <= width <= 2000:
            raise PlatformIssue("验证码图片尺寸不受支持")
        secret = {"id": str(uuid4()), "timestamp": timestamp, "iv": iv, "token": data.get("token") or token, "referer": referer, "expires": time.time() + 300, "width": width, "attempts": 0}
        public = {"id": secret["id"], "background": background, "piece": piece, "width": width, "expires_at": secret["expires"]}
        return secret, public

    async def check_captcha(self, challenge: dict, x: float):
        if not math.isfinite(x) or not 0 <= x <= challenge["width"]:
            raise PlatformIssue("滑块位置超出了图片范围")
        data = self.jsonp(await self.request("GET", "https://captcha.chaoxing.com/captcha/check/verification/result", headers={"Referer": challenge["referer"]}, params={
            "callback": "cx_captcha_function", "captchaId": CX_CAPTCHA_ID, "type": "slide", "token": challenge["token"],
            "textClickArr": json.dumps([{"x": math.floor(x + 0.5)}], separators=(",", ":")), "coordinate": "[]", "runEnv": "10",
            "version": "1.1.20", "t": "a", "iv": challenge["iv"], "_": str(challenge["timestamp"] + 2),
        }))
        if data.get("error") == 0 and data.get("result") is True:
            extra = data.get("extraData")
            extra = json.loads(extra) if isinstance(extra, str) else extra
            return (extra or {}).get("validate")
        return None

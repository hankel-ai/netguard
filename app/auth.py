import hmac
import time

from fastapi import Request, HTTPException
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.config import settings

SESSION_MAX_AGE = 86400  # 24 hours
COOKIE_NAME = "netguard_session"

_serializer = URLSafeTimedSerializer(settings.auth_password)


def check_password(password: str) -> bool:
    return hmac.compare_digest(password.encode(), settings.auth_password.encode())


def create_session_cookie() -> str:
    return _serializer.dumps({"t": int(time.time())})


def verify_session(cookie: str) -> bool:
    try:
        _serializer.loads(cookie, max_age=SESSION_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False


def require_auth(request: Request):
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie or not verify_session(cookie):
        raise HTTPException(status_code=401, detail="Unauthorized")

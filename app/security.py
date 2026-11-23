"""Password hashing (PBKDF2) and JWT issue/verify."""
import base64
import hashlib
import hmac
import os
import time

import jwt

SECRET = os.getenv("JWT_SECRET", "dev-only-secret-change-me")
ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 3600


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64, digest_b64 = stored.split("$")
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except Exception:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return hmac.compare_digest(actual, expected)


def create_token(subject: str, roles: list[str]) -> str:
    now = int(time.time())
    payload = {"sub": subject, "roles": roles, "iat": now, "exp": now + TOKEN_TTL_SECONDS}
    return jwt.encode(payload, SECRET, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET, algorithms=[ALGORITHM])

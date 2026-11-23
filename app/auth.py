"""User store, OAuth2 password flow dependencies and RBAC.

The default store is in-memory for local runs/tests; in production the same
functions back onto PostgreSQL (users table: email, password_hash, roles).
Demo users: admin@example.com / admin123 (admin), user@example.com / user123 (user).
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from .security import decode_token, hash_password, verify_password

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

USERS = {
    "admin@example.com": {"password_hash": hash_password("admin123"), "roles": ["admin", "user"]},
    "user@example.com": {"password_hash": hash_password("user123"), "roles": ["user"]},
}


def authenticate(email: str, password: str) -> dict | None:
    user = USERS.get(email)
    if user and verify_password(password, user["password_hash"]):
        return {"email": email, "roles": user["roles"]}
    return None


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    return {"email": payload["sub"], "roles": payload.get("roles", [])}


def require_role(role: str):
    def checker(user: dict = Depends(get_current_user)) -> dict:
        if role not in user["roles"]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires role: {role}")
        return user

    return checker

from fastapi.testclient import TestClient

from app.main import app
from app.ratelimit import RateLimiter
from app.security import hash_password, verify_password

client = TestClient(app)


def _token(email, password):
    r = client.post("/token", data={"username": email, "password": password})
    assert r.status_code == 200
    return r.json()["access_token"]


def test_password_hash_roundtrip():
    stored = hash_password("s3cret")
    assert verify_password("s3cret", stored) and not verify_password("wrong", stored)


def test_health_and_metrics():
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/metrics").json()["requests_total"] >= 1


def test_login_me_and_rbac():
    token = _token("user@example.com", "user123")
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/users/me", headers=headers).json()["email"] == "user@example.com"
    assert client.get("/admin/overview", headers=headers).status_code == 403

    admin = _token("admin@example.com", "admin123")
    assert client.get("/admin/overview", headers={"Authorization": f"Bearer {admin}"}).status_code == 200


def test_unauthorized_and_bad_login():
    assert client.get("/users/me").status_code == 401
    assert client.post("/token", data={"username": "user@example.com", "password": "nope"}).status_code == 401


def test_items_require_auth_and_rate_limiter():
    token = _token("user@example.com", "user123")
    headers = {"Authorization": f"Bearer {token}"}
    created = client.post("/items", json={"name": "widget"}, headers=headers)
    assert created.status_code == 200 and created.json()["owner"] == "user@example.com"

    limiter = RateLimiter(limit=3, window_seconds=60)
    assert [limiter.allow("k") for _ in range(4)] == [True, True, True, False]

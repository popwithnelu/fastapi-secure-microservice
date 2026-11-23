import time

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm

from .auth import authenticate, get_current_user, require_role
from .ratelimit import RateLimiter
from .security import create_token

app = FastAPI(title="Secure Microservice")
limiter = RateLimiter(limit=100, window_seconds=60)
START = time.time()
REQUESTS = {"count": 0}
ITEMS: dict[int, dict] = {}


@app.middleware("http")
async def rate_limit_and_count(request: Request, call_next):
    REQUESTS["count"] += 1
    if not limiter.allow(request.client.host):
        raise HTTPException(429, "Rate limit exceeded")
    return await call_next(request)


@app.get("/health")
def health():
    return {"status": "ok", "uptime_seconds": round(time.time() - START, 1)}


@app.get("/metrics")
def metrics():
    return {"requests_total": REQUESTS["count"], "items": len(ITEMS)}


@app.post("/token")
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = authenticate(form.username, form.password)
    if not user:
        raise HTTPException(401, "Incorrect email or password")
    return {"access_token": create_token(user["email"], user["roles"]), "token_type": "bearer"}


@app.get("/users/me")
def me(user: dict = Depends(get_current_user)):
    return user


@app.get("/admin/overview")
def admin_overview(user: dict = Depends(require_role("admin"))):
    return {"users": 2, "items": len(ITEMS), "requested_by": user["email"]}


@app.post("/items")
def create_item(item: dict, user: dict = Depends(get_current_user)):
    item_id = len(ITEMS) + 1
    ITEMS[item_id] = {**item, "owner": user["email"]}
    return {"id": item_id, **ITEMS[item_id]}


@app.get("/items")
def list_items(user: dict = Depends(get_current_user)):
    return {"items": [{"id": k, **v} for k, v in ITEMS.items()]}

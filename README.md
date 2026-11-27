# FastAPI Secure Microservice

A production-shaped FastAPI microservice template with authentication,
authorization and operational endpoints.

## Features

- **OAuth2 password flow + JWT** (`/token`, PyJWT, PBKDF2 password hashing)
- **RBAC** — roles on the token, enforced with a `require_role` dependency
  (e.g. `/admin/overview` requires `admin`)
- **Rate limiting** — fixed-window limiter, in-memory by default, Redis-backed
  when `REDIS_URL` is set
- **Items with ownership** — `POST /items`, `GET /items`, `GET /items/{id}`,
  and `DELETE /items/{id}`; only the owner or an admin can delete an item
- **Health & metrics** — `/health` (uptime), `/metrics` (request/item counts)
- **Docker** — `docker-compose.yml` runs the API with PostgreSQL (pgvector
  image) and Redis

Demo users: `admin@example.com / admin123` (admin), `user@example.com / user123` (user).
In production the in-memory user store is replaced by the PostgreSQL `users`
table and `JWT_SECRET` comes from the environment.

## Tech stack
Python, FastAPI, PyJWT, PostgreSQL, Redis, Docker.

## Run
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
# or: docker compose up --build
curl -X POST localhost:8000/token -d 'username=user@example.com&password=user123'
```

## Tests
```bash
python -m pytest  # offline: auth flow, RBAC, rate limiting, items
```

## Project structure
```
app/ (main, auth, security, ratelimit) · Dockerfile · docker-compose.yml · tests/test_api.py
```

MIT License — see LICENSE.

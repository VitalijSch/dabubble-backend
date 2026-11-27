# DABubble Backend

Django REST API and WebSocket server for the DABubble chat app (frontend: `../dabubble-frontend`).

**Stack:** Django 6.1 · Python 3.14 · PostgreSQL 19 · Redis 8 · Django REST Framework + drf-spectacular · Django Channels (Daphne) · Django Tasks (django-tasks-db) · Supabase Storage (S3 API) · managed with [uv](https://docs.astral.sh/uv/).

## Requirements

- [uv](https://docs.astral.sh/uv/getting-started/installation/)
- [Docker](https://docs.docker.com/get-docker/) (local PostgreSQL and Redis)

## Quick start

```bash
cp .env.example .env
make install
make db
make migrate
uv run python manage.py createsuperuser
make dev          # http://localhost:8000
make worker       # second terminal: runs background tasks
```

Useful URLs locally:

| URL | What |
|---|---|
| http://localhost:8000/health/ | Health check (`{"status": "ok"}`) |
| http://localhost:8000/admin/ | Django admin (log in with email) |
| http://localhost:8000/api/v1/me/ | Example endpoint: the logged-in user |
| http://localhost:8000/api/docs/ | Swagger UI (local only) |
| http://localhost:8000/api/schema/ | OpenAPI schema (local only) |
| ws://localhost:8000/ws/ping/ | Example WebSocket: send `{"type": "ping"}`, get `{"type": "pong"}` |

## Commands

| Command | What it does |
|---|---|
| `make install` | Install all dependencies (`uv sync`) |
| `make db` | Start PostgreSQL and Redis in Docker and wait until healthy |
| `make dev` | Run the dev server (Daphne, HTTP + WebSockets) |
| `make worker` | Run the background task worker (auto-reloads) |
| `make migrate` | Apply database migrations |
| `make test` | Run tests with coverage |
| `make lint` | Ruff lint |
| `make format` | Ruff format + auto-fix |
| `make typecheck` | mypy (strict) |
| `make check` | Everything CI runs: format check, lint, mypy, Django checks, missing-migration check, tests |

## Project layout

```
config/
  settings/
    base.py         shared settings, everything from env
    local.py        development
    test.py         pytest
    production.py   deployment (security, CSP, SMTP, Supabase storage, Sentry)
  urls.py           HTTP routes
  routing.py        WebSocket routes
  asgi.py           HTTP + WebSocket entry point (production)
apps/
  core/             TimeStampedModel, health check, example WebSocket consumer
  users/            custom User model (email login), /api/v1/me/, example task
templates/          project templates (email/ for email bodies)
static/             project static files
```

## Frontend integration

- **Auth:** DRF session authentication. The frontend sends requests with `credentials: "include"`, and for unsafe methods it sends the `X-CSRFToken` header from the `csrftoken` cookie. Allowed frontend origins are set in `DJANGO_CORS_ALLOWED_ORIGINS`, `DJANGO_CSRF_TRUSTED_ORIGINS` and `DJANGO_WEBSOCKET_ALLOWED_ORIGINS`.
- **API contract:** [`openapi.yaml`](openapi.yaml) describes every endpoint: request fields, responses and error bodies. It's generated from the code with `make schema` and committed, so every API change shows up in the pull request diff. A test fails when it's out of date.
- **Browse it:** http://localhost:8000/api/docs/ (Swagger UI, local only) lists every endpoint and lets you try it.
- **TypeScript types:** the frontend generates its types from `openapi.yaml` (see the frontend README); never write API types by hand.
- **Errors:** `400` returns messages per field, `{"email": ["…"], "non_field_errors": ["…"]}`. Other errors (`403` not logged in, `429` too many requests) return `{"detail": "…"}`. All messages are German and ready to show.
- **WebSockets:** connect to `/ws/...`. The session cookie authenticates the user. In production, serve frontend and API under the same site (for example `app.example.com` and `api.example.com`) so the cookie is sent.

## Deployment (company VM)

The `Dockerfile` builds one image used for two processes:

| Process | Command |
|---|---|
| web | default `CMD`: `daphne --bind 0.0.0.0 --port 8000 --proxy-headers config.asgi:application` |
| worker | `python manage.py db_worker` |

Also needed: PostgreSQL 15 or newer, Redis (Channels layer), and a reverse proxy (nginx or Caddy) that terminates TLS, forwards `X-Forwarded-Proto` and passes WebSocket upgrades for `/ws/`.

1. Set the environment variables from `.env.example` on the server. Production requires `DJANGO_SECRET_KEY`, `DJANGO_ALLOWED_HOSTS`, `DATABASE_URL`, `REDIS_URL`, `DJANGO_EMAIL_HOST` (plus credentials), the `SUPABASE_*` storage variables and the frontend origins. `SENTRY_DSN` is optional.
2. Run migrations as a **separate release step** before starting the new version, never on every container start:
   `docker run --rm --env-file .env dabubble-backend python manage.py migrate`
3. Verify the configuration: `docker run --rm --env-file .env dabubble-backend python manage.py check --deploy`
4. Start or restart `web` and `worker`.
5. After HTTPS is confirmed working, raise `DJANGO_SECURE_HSTS_SECONDS` to `31536000`.

Supabase Storage: enable the S3 connection in the Supabase dashboard (Storage → Settings), create S3 access keys there and a **private** bucket. Copy the endpoint and region into the `SUPABASE_*` variables. The keys bypass Row Level Security, so keep them server-side only.

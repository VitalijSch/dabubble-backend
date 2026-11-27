# CLAUDE.md

Django 6.1 on Python 3.14, PostgreSQL 19, Redis 8, managed with **uv** (never pip). API: Django REST Framework + drf-spectacular. Real-time: Django Channels (Daphne). Background jobs: Django Tasks framework with the django-tasks-db backend. Frontend: Next.js in `../dabubble-frontend`.

## Commands
- `make db` then `make dev` — run locally on http://localhost:8000 (`make worker` for background tasks)
- `make check` — format check, lint, mypy, Django checks, missing-migration check, tests. **Run before saying you're done.**
- `make schema` — regenerate `openapi.yaml` (the API contract) after API changes
- `uv run pytest apps/<app>/tests/test_x.py` — run one test file
- `uv add <pkg>` / `uv add --dev <pkg>` — add dependencies (ask first)

## Rules
- Settings come from environment variables via `env` in `config/settings/base.py`. New variable → settings AND `.env.example`.
- The user model is `apps.users.models.User` (login by **email**, no username). Always reference it via `settings.AUTH_USER_MODEL` or `get_user_model()`.
- New models inherit `apps.core.models.TimeStampedModel`. After changing models, run `makemigrations` and commit the migration.
- API endpoints live under `/api/v1/`; default permission is `IsAuthenticated`. WebSocket routes go in `config/routing.py`.
- `openapi.yaml` is the API contract the frontend generates its types from. Document every response, errors included (`@extend_schema` with the helpers in `apps/core/openapi.py`). After changing endpoints or serializers run `make schema` and commit the file; a test fails if it's out of date.
- Avoid N+1 queries: use `select_related` / `prefetch_related` (with explicit fields) and test query counts for list endpoints.
- Business logic lives in `services.py` / `selectors.py` inside the app, not in views, serializers or consumers.
- Every bug fix starts with a failing test. Use factories (`UserFactory.create(...)`), not fixtures.

## Gotchas
- Email uses Django 6.1 `MAILERS` (`EMAIL_BACKEND` / `EMAIL_*` are deprecated). Never add `EMAIL_*` settings.
- Background jobs: `from django.tasks import task`, then `.enqueue(...)`. Arguments must be JSON-serialisable (pass IDs, not model instances). Tests use the immediate backend.
- `select_related()` without arguments is deprecated in 6.1 — always name the fields.
- `daphne` must stay first in `INSTALLED_APPS` (it makes `runserver` serve WebSockets).
- Production adds a strict Content Security Policy. Inline scripts in templates need `{% csp_nonce_attr %}`.
- Uploaded files go to Supabase Storage (S3 API) in production and `./media` locally. Supabase does not support S3 ACLs, so the bucket is private and URLs are signed.
- Python 3.15 is supported by Django 6.1 but not yet by Daphne/autobahn (no wheels). Stay on 3.14 until they catch up.

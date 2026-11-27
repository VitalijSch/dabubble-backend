.PHONY: install db dev worker migrate test lint format typecheck schema check

install:   ; uv sync
db:        ; docker compose up -d --wait db redis
dev:       ; uv run python manage.py runserver
worker:    ; uv run python manage.py db_worker --reload
migrate:   ; uv run python manage.py migrate
test:      ; uv run pytest --cov
lint:      ; uv run ruff check .
format:    ; uv run ruff format . && uv run ruff check --fix .
typecheck: ; uv run mypy .
# The API contract for the frontend. Run after changing endpoints or serializers, then commit it.
schema:    ; uv run python manage.py spectacular --validate --fail-on-warn --file openapi.yaml

check:
	uv run ruff format --check .
	uv run ruff check .
	uv run mypy .
	uv run python manage.py check
	uv run python manage.py makemigrations --check --dry-run
	uv run pytest

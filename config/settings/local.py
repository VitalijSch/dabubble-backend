"""Development settings."""

from .base import *

DEBUG = True
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]

INSTALLED_APPS += ["debug_toolbar"]
MIDDLEWARE.insert(
    MIDDLEWARE.index("django.middleware.common.CommonMiddleware") + 1,
    "debug_toolbar.middleware.DebugToolbarMiddleware",
)
INTERNAL_IPS = ["127.0.0.1"]

# Print emails to the terminal instead of sending them.
MAILERS = {"default": {"BACKEND": "django.core.mail.backends.console.EmailBackend"}}

API_DOCS_ENABLED = True

# The Next.js dev server.
CORS_ALLOWED_ORIGINS = env.list("DJANGO_CORS_ALLOWED_ORIGINS", default=["http://localhost:3000"])
CSRF_TRUSTED_ORIGINS = env.list("DJANGO_CSRF_TRUSTED_ORIGINS", default=["http://localhost:3000"])
WEBSOCKET_ALLOWED_ORIGINS = env.list(
    "DJANGO_WEBSOCKET_ALLOWED_ORIGINS", default=["http://localhost:3000", "http://localhost:8000"]
)

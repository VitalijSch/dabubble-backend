"""Shared settings. Every environment-specific value comes from environment variables."""

from pathlib import Path
from typing import Any

import environ

BASE_DIR = Path(__file__).resolve().parent.parent.parent
env = environ.Env()
if (BASE_DIR / ".env").is_file():
    # Local development only. Real environments set variables directly; they win over .env.
    environ.Env.read_env(BASE_DIR / ".env")

SECRET_KEY = env("DJANGO_SECRET_KEY")
DEBUG = env.bool("DJANGO_DEBUG", default=False)
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=[])

# --- Apps ---------------------------------------------------------------------------------------
DJANGO_APPS = [
    "daphne",  # must come first: makes `runserver` serve ASGI (HTTP + WebSockets)
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]
THIRD_PARTY_APPS = [
    "rest_framework",
    "drf_spectacular",
    "corsheaders",
    "channels",
    "django_tasks_db",
]
LOCAL_APPS = ["apps.core", "apps.users"]
INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

AUTH_USER_MODEL = "users.User"

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "apps.core.middleware.EnglishAdminMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# --- Database -----------------------------------------------------------------------------------
DATABASES = {"default": env.db("DATABASE_URL")}
DATABASES["default"]["CONN_MAX_AGE"] = env.int("DJANGO_CONN_MAX_AGE", default=60)
DATABASES["default"]["CONN_HEALTH_CHECKS"] = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Templates ----------------------------------------------------------------------------------
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.template.context_processors.csp",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# Argon2 for new passwords; the others still verify older hashes and upgrade them on login.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "apps.users.password_validation.GermanUserAttributeSimilarityValidator",
        "OPTIONS": {"user_attributes": ("email", "full_name")},
    },
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# All texts users see are German, including Django's and DRF's built-in messages.
# Code, comments and developer-facing messages stay English, and so does the admin
# (see apps.core.middleware.EnglishAdminMiddleware).
LANGUAGE_CODE = "de"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# --- Static and media files ---------------------------------------------------------------------
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"
STORAGES: dict[str, dict[str, Any]] = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

# Largest avatar image a user can upload.
AVATAR_MAX_UPLOAD_SIZE = 2 * 1024 * 1024  # 2 MB

# Version of the privacy policy the frontend currently shows. Stored with each new user as proof
# of which text they accepted. Change it whenever the policy text changes.
PRIVACY_POLICY_VERSION = env("PRIVACY_POLICY_VERSION", default="2026-11-27")

ADMIN_URL = env("DJANGO_ADMIN_URL", default="admin/")

# --- Email (Django 6.1 MAILERS; replaces EMAIL_BACKEND / EMAIL_* settings) ----------------------
DEFAULT_FROM_EMAIL = env("DJANGO_DEFAULT_FROM_EMAIL", default="DABubble <noreply@localhost>")
SERVER_EMAIL = DEFAULT_FROM_EMAIL
MAILERS: dict[str, dict[str, Any]] = {
    "default": {
        "BACKEND": "django.core.mail.backends.smtp.EmailBackend",
        "OPTIONS": {
            "host": env("DJANGO_EMAIL_HOST", default="localhost"),
            "port": env.int("DJANGO_EMAIL_PORT", default=587),
            "username": env("DJANGO_EMAIL_USERNAME", default=""),
            "password": env("DJANGO_EMAIL_PASSWORD", default=""),
            "use_tls": env.bool("DJANGO_EMAIL_USE_TLS", default=True),
            "timeout": 10,
        },
    },
}

# --- Background tasks (Django Tasks framework + django-tasks-db worker) -------------------------
TASKS = {
    "default": {"BACKEND": "django_tasks_db.DatabaseBackend"},
}

# --- WebSockets (Django Channels) ---------------------------------------------------------------
REDIS_URL = env("REDIS_URL", default="redis://localhost:6379/0")
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {"hosts": [REDIS_URL]},
    },
}

# --- API (Django REST Framework + drf-spectacular) ----------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
    # Rates for views that set `throttle_scope` (sign-up and email confirmation are public).
    "DEFAULT_THROTTLE_RATES": {
        "register": "10/hour",
        # Higher than "register": users may fix a typo a few times on the first step.
        "register_validate": "30/hour",
        "verify_email": "30/hour",
    },
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}
SPECTACULAR_SETTINGS = {
    "TITLE": "DABubble API",
    "DESCRIPTION": "REST API for the DABubble frontend.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    # Separate request/response components (e.g. `RegisterRequest` vs `User`): read-only fields
    # aren't asked for in requests, and file uploads are typed as binary. Needed for good
    # generated TypeScript types in the frontend.
    "COMPONENT_SPLIT_REQUEST": True,
    # Group endpoints by feature ("auth", "me") instead of putting everything under "v1".
    "SCHEMA_PATH_PREFIX": r"/api/v[0-9]+",
}
# Serve /api/schema/ and /api/docs/ (on by default only in local settings).
API_DOCS_ENABLED = env.bool("DJANGO_API_DOCS_ENABLED", default=False)

# --- Frontend on another origin (Next.js) -------------------------------------------------------
# Base URL for links in emails (e.g. the email confirmation link).
FRONTEND_URL = env("FRONTEND_URL", default="http://localhost:3000")
CORS_ALLOWED_ORIGINS = env.list("DJANGO_CORS_ALLOWED_ORIGINS", default=[])
CORS_ALLOW_CREDENTIALS = True  # the frontend sends the session cookie
CSRF_TRUSTED_ORIGINS = env.list("DJANGO_CSRF_TRUSTED_ORIGINS", default=[])
# Browser origins allowed to open WebSocket connections.
WEBSOCKET_ALLOWED_ORIGINS = env.list("DJANGO_WEBSOCKET_ALLOWED_ORIGINS", default=[])

# --- Logging ------------------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "simple": {"format": "{levelname} {asctime} {name} {message}", "style": "{"},
    },
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "simple"}},
    "root": {"handlers": ["console"], "level": env("DJANGO_LOG_LEVEL", default="INFO")},
}

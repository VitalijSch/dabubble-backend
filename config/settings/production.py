"""Production settings. Every secret comes from the environment; nothing here has a fallback."""

import sentry_sdk
from django.utils.csp import CSP

from .base import *

DEBUG = False

# --- HTTPS and cookies (the app runs behind a TLS-terminating reverse proxy) --------------------
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = env.bool("DJANGO_SECURE_SSL_REDIRECT", default=True)
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
# Start low; raise to 31536000 once HTTPS is confirmed working for the domain.
SECURE_HSTS_SECONDS = env.int("DJANGO_SECURE_HSTS_SECONDS", default=60)
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True

# --- Content Security Policy (built into Django 6.0+) -------------------------------------------
# The admin is the only HTML this API serves, so a strict policy is fine.
MIDDLEWARE.insert(
    MIDDLEWARE.index("django.middleware.security.SecurityMiddleware") + 1,
    "django.middleware.csp.ContentSecurityPolicyMiddleware",
)
SECURE_CSP = {
    "default-src": [CSP.SELF],
    "script-src": [CSP.SELF, CSP.NONCE],
    "style-src": [CSP.SELF],
    "img-src": [CSP.SELF, "data:"],
    "connect-src": [CSP.SELF],
    "object-src": [CSP.NONE],
    "base-uri": [CSP.SELF],
    "form-action": [CSP.SELF],
    "frame-ancestors": [CSP.NONE],
}

# --- Links in emails must point at the real frontend ---------------------------------------------
FRONTEND_URL = env("FRONTEND_URL")

# --- Email: real SMTP, the host is required ------------------------------------------------------
MAILERS["default"]["OPTIONS"]["host"] = env("DJANGO_EMAIL_HOST")

# --- Uploaded files: Supabase Storage via its S3-compatible API ---------------------------------
STORAGES["default"] = {
    "BACKEND": "storages.backends.s3.S3Storage",
    "OPTIONS": {
        "bucket_name": env("SUPABASE_STORAGE_BUCKET"),
        # https://<project_ref>.storage.supabase.co/storage/v1/s3
        "endpoint_url": env("SUPABASE_S3_ENDPOINT_URL"),
        "region_name": env("SUPABASE_S3_REGION"),
        "access_key": env("SUPABASE_S3_ACCESS_KEY_ID"),
        "secret_key": env("SUPABASE_S3_SECRET_ACCESS_KEY"),
        "addressing_style": "path",
        "signature_version": "s3v4",
        "querystring_auth": True,  # private bucket, time-limited signed URLs
        "file_overwrite": False,
    },
}

# --- Error tracking (only when a DSN is configured) ---------------------------------------------
SENTRY_DSN = env("SENTRY_DSN", default="")
if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        environment=env("SENTRY_ENVIRONMENT", default="production"),
        traces_sample_rate=env.float("SENTRY_TRACES_SAMPLE_RATE", default=0.0),
        data_collection={"user_info": False},  # sentry-sdk 3: no user data by default
    )

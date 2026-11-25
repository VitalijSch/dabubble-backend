"""Settings for pytest."""

from .base import *

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]  # fast tests

MAILERS = {"default": {"BACKEND": "django.core.mail.backends.locmem.EmailBackend"}}
TASKS = {"default": {"BACKEND": "django.tasks.backends.immediate.ImmediateBackend"}}
CHANNEL_LAYERS = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.InMemoryStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}

API_DOCS_ENABLED = True
WEBSOCKET_ALLOWED_ORIGINS = ["http://testserver"]

# Serve static files from app directories without a collectstatic run (silences a startup warning).
WHITENOISE_AUTOREFRESH = True

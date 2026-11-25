"""WebSocket URL routes (the Channels counterpart of urls.py)."""

from django.urls import path

from apps.core.consumers import PingConsumer

websocket_urlpatterns = [
    path("ws/ping/", PingConsumer.as_asgi()),
]

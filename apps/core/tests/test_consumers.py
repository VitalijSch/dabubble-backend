import pytest
from channels.testing import WebsocketCommunicator
from django.contrib.auth.models import AnonymousUser

from apps.core.consumers import CLOSE_CODE_UNAUTHENTICATED, PingConsumer
from apps.users.models import User
from config.asgi import application

pytestmark = pytest.mark.asyncio


async def test_ping_pong_for_logged_in_user() -> None:
    communicator = WebsocketCommunicator(PingConsumer.as_asgi(), "/ws/ping/")
    communicator.scope["user"] = User(email="ws@example.com")

    connected, _ = await communicator.connect()
    assert connected
    await communicator.send_json_to({"type": "ping"})
    assert await communicator.receive_json_from() == {"type": "pong"}
    await communicator.disconnect()


async def test_anonymous_user_is_rejected() -> None:
    communicator = WebsocketCommunicator(PingConsumer.as_asgi(), "/ws/ping/")
    communicator.scope["user"] = AnonymousUser()

    connected, code = await communicator.connect()
    assert not connected
    assert code == CLOSE_CODE_UNAUTHENTICATED


async def test_unknown_origin_is_rejected() -> None:
    communicator = WebsocketCommunicator(
        application, "/ws/ping/", headers=[(b"origin", b"https://evil.example")]
    )
    connected, _ = await communicator.connect()
    assert not connected

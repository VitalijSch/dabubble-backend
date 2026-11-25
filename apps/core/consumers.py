from typing import Any

from channels.generic.websocket import AsyncJsonWebsocketConsumer

# Custom close code for "not authenticated" (4000-4999 are free for applications).
CLOSE_CODE_UNAUTHENTICATED = 4401


class PingConsumer(AsyncJsonWebsocketConsumer):  # type: ignore[misc]  # channels is untyped
    """Example WebSocket endpoint.

    A logged-in user sends {"type": "ping"} and receives {"type": "pong"}.
    """

    async def connect(self) -> None:
        user = self.scope.get("user")
        if user is None or not user.is_authenticated:
            await self.close(code=CLOSE_CODE_UNAUTHENTICATED)
            return
        await self.accept()

    async def receive_json(self, content: Any, **kwargs: Any) -> None:
        if isinstance(content, dict) and content.get("type") == "ping":
            await self.send_json({"type": "pong"})

import asyncio
from typing import Set


class WebSocketManager:
    def __init__(self):
        self._clients: Set = set()

    async def connect(self, websocket) -> None:
        await websocket.accept()
        self._clients.add(websocket)

    def disconnect(self, websocket) -> None:
        self._clients.discard(websocket)

    async def broadcast(self, message: str) -> None:
        disconnected = []
        for ws in self._clients:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.append(ws)
        for ws in disconnected:
            self._clients.discard(ws)

    def sync_broadcast(self, message: str) -> None:
        if not self._clients:
            return
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(
                lambda: asyncio.create_task(self.broadcast(message))
            )
        except RuntimeError:
            pass

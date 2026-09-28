"""
Manages active WebSocket connections and broadcasts events to all of them.
Broadcasts are triggered from sync code (running in FastAPI's worker
threads) using asyncio.run_coroutine_threadsafe, since the WebSocket
connections themselves live on the main event loop.
"""
import asyncio
from typing import List
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        if self.loop is None:
            self.loop = asyncio.get_event_loop()

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def _broadcast(self, message: dict):
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for d in dead:
            self.disconnect(d)

    def broadcast(self, message: dict):
        """Callable safely from sync code (worker threads)."""
        if self.loop is None or not self.active_connections:
            return  # no clients connected yet - nothing to send
        asyncio.run_coroutine_threadsafe(self._broadcast(message), self.loop)


manager = ConnectionManager()
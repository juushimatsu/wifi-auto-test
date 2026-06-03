import os
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from wifi_auto_test.core.models import TestStatus
from wifi_auto_test.core.orchestrator import Orchestrator
from wifi_auto_test.logger.interfaces import ILogger
from wifi_auto_test.state.interfaces import IStateRepository
from .ws_manager import WebSocketManager


def create_app(
    orchestrator: Orchestrator,
    state_repo: IStateRepository,
    logger: ILogger,
    ws_manager: WebSocketManager,
    static_dir: str = os.path.join(os.path.dirname(__file__), "static"),
) -> FastAPI:
    app = FastAPI(title="WiFi Auto Test")

    # WebSocket для логов
    @app.websocket("/ws/logs")
    async def websocket_logs(websocket: WebSocket):
        await ws_manager.connect(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)

    # Статика
    static_path = Path(static_dir)
    if static_path.exists():
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def root():
        index_file = static_path / "index.html"
        if index_file.exists():
            return index_file.read_text(encoding="utf-8")
        return "<html><body><h1>WiFi Auto Test</h1><p>static/index.html not found</p></body></html>"

    @app.get("/api/status")
    async def api_status():
        state = orchestrator.state
        return {
            "running": state.running,
            "paused": state.paused,
            "current": {
                "bssid": state.current_network.bssid if state.current_network else None,
                "ssid": state.current_network.ssid if state.current_network else None,
                "channel": state.current_network.channel if state.current_network else None,
            },
            "queue_size": len(state.queue),
            "total_scanned": state.total_scanned,
            "total_success": state.total_success,
            "total_failure": state.total_failure,
        }

    @app.get("/api/networks")
    async def api_networks():
        pending = state_repo.get_pending_networks()
        success = state_repo.get_successful_bssids()
        return {
            "pending": [
                {
                    "bssid": n.bssid,
                    "ssid": n.ssid,
                    "channel": n.channel,
                    "signal_dbm": n.signal_dbm,
                }
                for n in pending
            ],
            "successful": success,
        }

    @app.post("/api/command")
    async def api_command(data: dict):
        action = data.get("action")
        bssid = data.get("bssid")

        if action == "start":
            orchestrator.restart()
            return {"status": "started"}
        elif action == "stop":
            orchestrator.stop()
            return {"status": "stopped"}
        elif action == "restart":
            orchestrator.restart()
            return {"status": "restarted"}
        elif action == "prioritize" and bssid:
            orchestrator.prioritize(bssid)
            return {"status": "prioritized", "bssid": bssid}
        else:
            return {"status": "unknown_action"}

    @app.get("/api/pcapng/{filename}")
    async def api_pcapng(filename: str):
        captures_dir = Path("./captures/")
        file_path = captures_dir / filename
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        return {"error": "not_found"}

    return app

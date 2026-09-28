from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.logging_config import setup_logging
from app.database.connection import get_db, get_redis, engine, Base
from app.database import models  # noqa: F401
from app.api import auth, traffic, simulation, detection, alerts, prevention, analytics, ml
from app.websocket.events import manager
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.error_handler import http_exception_handler, unhandled_exception_handler

setup_logging()

app = FastAPI(title="AI-IDPS", description="AI-Powered Intrusion Detection and Prevention System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)

app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

Base.metadata.create_all(bind=engine)

app.include_router(auth.router)
app.include_router(traffic.router)
app.include_router(simulation.router)
app.include_router(detection.router)
app.include_router(alerts.router)
app.include_router(prevention.router)
app.include_router(analytics.router)
app.include_router(ml.router)


@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/")
def root():
    return {"message": "AI-IDPS backend is running"}


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    status_result = {"backend": "ok", "postgres": "unknown", "redis": "unknown"}
    try:
        db.execute(text("SELECT 1"))
        status_result["postgres"] = "ok"
    except Exception as e:
        status_result["postgres"] = f"error: {e}"
    try:
        r = get_redis()
        r.ping()
        status_result["redis"] = "ok"
    except Exception as e:
        status_result["redis"] = f"error: {e}"
    return status_result
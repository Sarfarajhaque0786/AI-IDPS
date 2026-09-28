from sqlalchemy.orm import Session
from typing import Optional

from app.database.models import Alert, TrafficEvent
from app.database.connection import redis_client
from app.websocket.events import manager


def create_alert(db: Session, event: TrafficEvent, message: str) -> Alert:
    alert = Alert(
        event_id=event.id,
        severity=event.severity,
        attack_type=event.attack_type,
        message=message,
        status="NEW",
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    try:
        redis_client.incr("alerts:total")
        redis_client.incr(f"alerts:severity:{event.severity}")
    except Exception:
        pass

    manager.broadcast({
        "type": "new_alert",
        "id": alert.id,
        "severity": alert.severity,
        "attack_type": alert.attack_type,
        "message": alert.message,
        "event_id": alert.event_id,
    })

    return alert


def list_alerts(
    db: Session,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    return query.order_by(Alert.created_at.desc()).limit(limit).all()


def get_alert(db: Session, alert_id: int):
    return db.query(Alert).filter(Alert.id == alert_id).first()


def update_alert_status(db: Session, alert_id: int, status: str):
    alert = get_alert(db, alert_id)
    if not alert:
        return None
    alert.status = status
    db.commit()
    db.refresh(alert)
    return alert


def get_redis_counters() -> dict:
    try:
        keys = redis_client.keys("alerts:*")
        return {k: redis_client.get(k) for k in keys}
    except Exception:
        return {"error": "Redis unavailable"}
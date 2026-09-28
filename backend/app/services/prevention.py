from sqlalchemy.orm import Session

from app.database.models import BlockedSource, PreventionAction, TrafficEvent
from app.config import settings
from app.websocket.events import manager


def is_source_blocked(db: Session, source_ip: str) -> bool:
    existing = db.query(BlockedSource).filter(
        BlockedSource.source_identifier == source_ip,
        BlockedSource.is_active == True,
    ).first()
    return existing is not None


def block_source(db: Session, source_ip: str, reason: str, severity: str = None) -> BlockedSource:
    existing = db.query(BlockedSource).filter(
        BlockedSource.source_identifier == source_ip,
        BlockedSource.is_active == True,
    ).first()
    if existing:
        return existing

    blocked = BlockedSource(
        source_identifier=source_ip,
        reason=reason,
        severity=severity,
        is_active=True,
    )
    db.add(blocked)
    db.commit()
    db.refresh(blocked)
    return blocked


def unblock_source(db: Session, source_ip: str) -> bool:
    existing = db.query(BlockedSource).filter(
        BlockedSource.source_identifier == source_ip,
        BlockedSource.is_active == True,
    ).first()
    if not existing:
        return False
    existing.is_active = False
    db.commit()
    return True


def record_prevention_action(db: Session, event: TrafficEvent, action: str, target: str, reason: str) -> PreventionAction:
    pa = PreventionAction(
        event_id=event.id,
        action=action,
        target=target,
        reason=reason,
        status="SUCCESS",
    )
    db.add(pa)
    db.commit()
    db.refresh(pa)

    manager.broadcast({
        "type": "prevention_action",
        "action": action,
        "target": target,
        "event_id": event.id,
        "mode": settings.PREVENTION_MODE,
    })
    return pa


def auto_prevent(db: Session, event: TrafficEvent):
    """
    Called automatically after detection for HIGH/CRITICAL severity events.
    Runs in SIMULATION mode by default (per PREVENTION_MODE in .env) -
    this only ever touches the application's own controlled blocklist,
    never a real firewall or external system.
    """
    if settings.PREVENTION_MODE == "OFF":
        return None

    reason = f"Auto-block: {event.attack_type} detected with severity {event.severity}"
    block_source(db, event.source_ip, reason, severity=event.severity)
    return record_prevention_action(db, event, action="BLOCK", target=event.source_ip, reason=reason)
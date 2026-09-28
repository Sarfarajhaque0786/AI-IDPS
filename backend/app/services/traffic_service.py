from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional

from app.database.models import TrafficEvent


def create_traffic_event(db: Session, **kwargs) -> TrafficEvent:
    event = TrafficEvent(**kwargs)
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def list_traffic_events(
    db: Session,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
):
    query = db.query(TrafficEvent)
    if severity:
        query = query.filter(TrafficEvent.severity == severity)
    if attack_type:
        query = query.filter(TrafficEvent.attack_type == attack_type)
    if status:
        query = query.filter(TrafficEvent.status == status)
    return query.order_by(TrafficEvent.timestamp.desc()).limit(limit).all()


def get_traffic_stats(db: Session):
    total_events = db.query(func.count(TrafficEvent.id)).scalar()
    threats_detected = (
        db.query(func.count(TrafficEvent.id))
        .filter(TrafficEvent.attack_type != "BENIGN")
        .scalar()
    )

    by_severity = dict(
        db.query(TrafficEvent.severity, func.count(TrafficEvent.id))
        .group_by(TrafficEvent.severity)
        .all()
    )
    by_attack_type = dict(
        db.query(TrafficEvent.attack_type, func.count(TrafficEvent.id))
        .group_by(TrafficEvent.attack_type)
        .all()
    )

    return {
        "total_events": total_events,
        "threats_detected": threats_detected,
        "by_severity": by_severity,
        "by_attack_type": by_attack_type,
    }
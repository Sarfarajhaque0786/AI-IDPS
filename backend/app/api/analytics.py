from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.database.connection import get_db
from app.database.models import TrafficEvent, Alert, BlockedSource
from app.middleware.auth import get_current_user

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


@router.get("/summary")
def dashboard_summary(db: Session = Depends(get_db), _current_user=Depends(get_current_user)):
    total_events = db.query(func.count(TrafficEvent.id)).scalar()
    threats_detected = (
        db.query(func.count(TrafficEvent.id))
        .filter(TrafficEvent.attack_type.notin_(["BENIGN", "UNPROCESSED"]))
        .scalar()
    )
    critical_alerts = (
        db.query(func.count(Alert.id)).filter(Alert.severity == "CRITICAL").scalar()
    )
    blocked_sources = (
        db.query(func.count(BlockedSource.id)).filter(BlockedSource.is_active == True).scalar()
    )
    return {
        "total_events": total_events,
        "threats_detected": threats_detected,
        "critical_alerts": critical_alerts,
        "blocked_sources": blocked_sources,
    }


@router.get("/attack-distribution")
def attack_distribution(db: Session = Depends(get_db), _current_user=Depends(get_current_user)):
    rows = (
        db.query(TrafficEvent.attack_type, func.count(TrafficEvent.id))
        .filter(TrafficEvent.attack_type != "UNPROCESSED")
        .group_by(TrafficEvent.attack_type)
        .all()
    )
    return [{"attack_type": r[0], "count": r[1]} for r in rows]


@router.get("/severity-distribution")
def severity_distribution(db: Session = Depends(get_db), _current_user=Depends(get_current_user)):
    rows = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    return [{"severity": r[0], "count": r[1]} for r in rows]


@router.get("/detection-methods")
def detection_methods(db: Session = Depends(get_db), _current_user=Depends(get_current_user)):
    rows = (
        db.query(TrafficEvent.detection_method, func.count(TrafficEvent.id))
        .filter(TrafficEvent.detection_method.isnot(None))
        .group_by(TrafficEvent.detection_method)
        .all()
    )
    return [{"method": r[0], "count": r[1]} for r in rows]


@router.get("/top-sources")
def top_sources(limit: int = 5, db: Session = Depends(get_db), _current_user=Depends(get_current_user)):
    rows = (
        db.query(TrafficEvent.source_ip, func.count(TrafficEvent.id).label("count"))
        .filter(TrafficEvent.attack_type.notin_(["BENIGN", "UNPROCESSED"]))
        .group_by(TrafficEvent.source_ip)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )
    return [{"source_ip": r[0], "count": r[1]} for r in rows]
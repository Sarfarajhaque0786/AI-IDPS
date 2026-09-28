from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.connection import get_db
from app.database.models import TrafficEvent
from app.middleware.auth import get_current_user
from app.services.detection_pipeline import process_and_alert

router = APIRouter(prefix="/api/detection", tags=["detection"])


@router.post("/analyze")
def analyze_unprocessed(
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    events = db.query(TrafficEvent).filter(TrafficEvent.attack_type == "UNPROCESSED").all()

    updated = 0
    alerts_created = 0
    method_counts = {}

    for event in events:
        result = process_and_alert(db, event)
        updated += 1
        method_counts[result["detection_method"]] = method_counts.get(result["detection_method"], 0) + 1
        if result["event_type"] != "BENIGN":
            alerts_created += 1

    db.commit()
    return {
        "analyzed": updated,
        "alerts_created": alerts_created,
        "by_method": method_counts,
    }


@router.get("/status")
def detection_status(
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    unprocessed = db.query(func.count(TrafficEvent.id)).filter(
        TrafficEvent.attack_type == "UNPROCESSED"
    ).scalar()
    processed = db.query(func.count(TrafficEvent.id)).filter(
        TrafficEvent.attack_type != "UNPROCESSED"
    ).scalar()
    return {"unprocessed": unprocessed, "processed": processed}
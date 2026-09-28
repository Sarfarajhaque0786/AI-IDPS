from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.connection import get_db
from app.database.models import Alert
from app.middleware.auth import get_current_user
from app.services import alert_service

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


class AlertResponse(BaseModel):
    id: int
    event_id: int
    severity: str
    attack_type: str
    message: str
    created_at: datetime
    status: str

    class Config:
        from_attributes = True


class UpdateStatusRequest(BaseModel):
    status: str  # NEW, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE


VALID_STATUSES = {"NEW", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"}


@router.get("", response_model=list[AlertResponse])
def get_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    return alert_service.list_alerts(db, severity=severity, status=status)


@router.get("/summary")
def alerts_summary(
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    total = db.query(func.count(Alert.id)).scalar()
    by_status = dict(
        db.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all()
    )
    return {
        "postgres": {"total": total, "by_status": by_status},
        "redis_counters": alert_service.get_redis_counters(),
    }


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    alert = alert_service.get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert(
    alert_id: int,
    payload: UpdateStatusRequest,
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    if payload.status not in VALID_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {VALID_STATUSES}")

    alert = alert_service.update_alert_status(db, alert_id, payload.status)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
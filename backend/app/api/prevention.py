from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.database.models import BlockedSource, PreventionAction
from app.middleware.auth import get_current_user, require_admin
from app.services import prevention

router = APIRouter(prefix="/api/prevention", tags=["prevention"])


class BlockRequest(BaseModel):
    source_ip: str
    reason: str = "Manually blocked by admin"


class UnblockRequest(BaseModel):
    source_ip: str


class BlockedSourceResponse(BaseModel):
    id: int
    source_identifier: str
    reason: Optional[str]
    severity: Optional[str]
    created_at: datetime
    expires_at: Optional[datetime]
    is_active: bool

    class Config:
        from_attributes = True


class PreventionActionResponse(BaseModel):
    id: int
    event_id: int
    action: str
    target: str
    reason: Optional[str]
    executed_at: datetime
    status: str

    class Config:
        from_attributes = True


@router.get("/blocked", response_model=list[BlockedSourceResponse])
def get_blocked(db: Session = Depends(get_db), _current_user=Depends(get_current_user)):
    return db.query(BlockedSource).filter(BlockedSource.is_active == True).all()


@router.post("/block", response_model=BlockedSourceResponse)
def block(payload: BlockRequest, db: Session = Depends(get_db), _admin=Depends(require_admin)):
    # Only ADMIN can trigger prevention actions, per spec.
    return prevention.block_source(db, payload.source_ip, payload.reason)


@router.post("/unblock")
def unblock(payload: UnblockRequest, db: Session = Depends(get_db), _admin=Depends(require_admin)):
    success = prevention.unblock_source(db, payload.source_ip)
    if not success:
        raise HTTPException(status_code=404, detail="Active block not found for this source")
    return {"unblocked": payload.source_ip}


@router.get("/actions", response_model=list[PreventionActionResponse])
def get_actions(db: Session = Depends(get_db), _current_user=Depends(get_current_user)):
    return db.query(PreventionAction).order_by(PreventionAction.executed_at.desc()).limit(100).all()
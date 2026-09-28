import os
import tempfile
from typing import Optional
from fastapi import APIRouter, Depends, Query, UploadFile, File, HTTPException
from pydantic import BaseModel
from datetime import datetime
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.middleware.auth import get_current_user
from app.services import traffic_service
from app.services.detection_pipeline import process_and_alert
from app.network.pcap import parse_pcap_to_flows

router = APIRouter(prefix="/api/traffic", tags=["traffic"])


class TrafficEventResponse(BaseModel):
    id: int
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: Optional[str]
    packet_count: int
    byte_count: int
    attack_type: str
    detection_method: Optional[str]
    confidence: Optional[float]
    severity: str
    status: str

    class Config:
        from_attributes = True


@router.get("", response_model=list[TrafficEventResponse])
def get_traffic(
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    return traffic_service.list_traffic_events(
        db, severity=severity, attack_type=attack_type, status=status, limit=limit
    )


@router.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    return traffic_service.get_traffic_stats(db)


@router.post("/upload-pcap")
def upload_pcap(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    """
    Accepts a .pcap file from a controlled lab capture or public dataset,
    parses it, runs the full detection pipeline, and returns a summary.
    No live capture happens here - this only reads an uploaded file.
    """
    if not file.filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=422, detail="File must be a .pcap or .pcapng file")

    # Save to a temp file since Scapy's rdpcap needs a real file path.
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(file.file.read())
        tmp_path = tmp.name

    try:
        flows = parse_pcap_to_flows(tmp_path)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse PCAP: {e}")
    finally:
        os.unlink(tmp_path)

    if not flows:
        return {"message": "No IP traffic found in the PCAP file", "events_created": 0}

    created_events = []
    for flow in flows:
        event = traffic_service.create_traffic_event(
            db,
            attack_type="UNPROCESSED",
            detection_method=None,
            confidence=None,
            severity="LOW",
            status="NEW",
            **flow,
        )
        created_events.append(event)

    # Immediately run detection on what we just created - a PCAP upload
    # is a one-shot demo action, so the full pipeline runs in one step.
    alerts_created = 0
    method_counts = {}
    for event in created_events:
        result = process_and_alert(db, event)
        method_counts[result["detection_method"]] = method_counts.get(result["detection_method"], 0) + 1
        if result["event_type"] != "BENIGN":
            alerts_created += 1

    db.commit()

    return {
        "filename": file.filename,
        "flows_extracted": len(flows),
        "events_created": len(created_events),
        "alerts_created": alerts_created,
        "by_method": method_counts,
    }
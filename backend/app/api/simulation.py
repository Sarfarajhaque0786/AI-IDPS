import random
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.middleware.auth import get_current_user
from app.services import traffic_service

router = APIRouter(prefix="/api/simulation", tags=["simulation"])

VALID_SCENARIOS = [
    "BENIGN",
    "HIGH_CONNECTION_RATE",
    "BRUTE_FORCE",
    "ANOMALY",
    "BOT_ACTIVITY",
]


class SimulateRequest(BaseModel):
    scenario: str
    count: int = 10


def _random_ip(prefix="10.10."):
    return f"{prefix}{random.randint(0, 255)}.{random.randint(1, 254)}"


def _generate_event_fields(scenario: str) -> dict:
    """
    Builds realistic-looking but entirely synthetic traffic characteristics
    for each safe demo scenario. No real network activity is involved.
    """
    source_ip = _random_ip("192.168.")

    if scenario == "BENIGN":
        return dict(
            source_ip=source_ip,
            destination_ip=_random_ip("10.0."),
            source_port=random.randint(1024, 65535),
            destination_port=random.choice([80, 443]),
            protocol="TCP",
            packet_count=random.randint(5, 50),
            byte_count=random.randint(500, 5000),
        )

    if scenario == "HIGH_CONNECTION_RATE":
        # Simulates one source opening an unusually large number of connections quickly.
        return dict(
            source_ip=source_ip,
            destination_ip=_random_ip("10.0."),
            source_port=random.randint(1024, 65535),
            destination_port=random.choice([80, 443, 8080]),
            protocol="TCP",
            packet_count=random.randint(200, 1000),
            byte_count=random.randint(20000, 100000),
        )

    if scenario == "BRUTE_FORCE":
        # Simulates repeated auth attempts against a controlled test service (SSH/RDP-style ports).
        return dict(
            source_ip=source_ip,
            destination_ip=_random_ip("10.0."),
            source_port=random.randint(1024, 65535),
            destination_port=random.choice([22, 3389]),
            protocol="TCP",
            packet_count=random.randint(1, 5),
            byte_count=random.randint(50, 300),
        )

    if scenario == "ANOMALY":
        # Unusual protocol/port combination.
        return dict(
            source_ip=source_ip,
            destination_ip=_random_ip("10.0."),
            source_port=random.randint(1024, 65535),
            destination_port=random.randint(1, 1023),
            protocol=random.choice(["UDP", "ICMP"]),
            packet_count=random.randint(1, 20),
            byte_count=random.randint(40, 1500),
        )

    if scenario == "BOT_ACTIVITY":
        # Simulates many small, regular, automated-looking requests.
        return dict(
            source_ip=source_ip,
            destination_ip=_random_ip("10.0."),
            source_port=random.randint(1024, 65535),
            destination_port=443,
            protocol="TCP",
            packet_count=random.randint(10, 30),
            byte_count=random.randint(200, 800),
        )

    raise ValueError(f"Unknown scenario: {scenario}")


@router.post("/generate")
def generate_simulation(
    payload: SimulateRequest,
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_user),
):
    if payload.scenario not in VALID_SCENARIOS:
        raise HTTPException(
            status_code=422,
            detail=f"scenario must be one of {VALID_SCENARIOS}",
        )
    if not (1 <= payload.count <= 500):
        raise HTTPException(status_code=422, detail="count must be between 1 and 500")

    created_events = []
    for _ in range(payload.count):
        fields = _generate_event_fields(payload.scenario)
        # Detection engine (rule/ML) will process and classify these in later phases.
        # For now, tag with the scenario so we can trace what generated it.
        event = traffic_service.create_traffic_event(
            db,
            attack_type="BENIGN" if payload.scenario == "BENIGN" else "UNPROCESSED",
            detection_method=None,
            confidence=None,
            severity="LOW",
            status="NEW",
            **fields,
        )
        created_events.append(event.id)

    return {
        "scenario": payload.scenario,
        "generated_count": len(created_events),
        "event_ids": created_events,
    }
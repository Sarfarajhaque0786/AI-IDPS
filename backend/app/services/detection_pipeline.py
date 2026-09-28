"""
Shared pipeline step used by both /api/detection/analyze and the PCAP
upload endpoint, so the same detect -> alert -> prevent logic isn't
duplicated in two places.
"""
from app.services.detector import hybrid_detect
from app.services import alert_service, prevention


def process_and_alert(db, event) -> dict:
    """
    Runs hybrid detection on a single TrafficEvent, updates it in place,
    creates an Alert if non-benign, and triggers auto-prevention for
    HIGH/CRITICAL severity. Caller is responsible for db.commit().
    """
    result = hybrid_detect({
        "packet_count": event.packet_count,
        "byte_count": event.byte_count,
        "protocol": event.protocol,
        "destination_port": event.destination_port,
        "source_port": event.source_port,
    })

    event.attack_type = result["event_type"]
    event.severity = result["severity"]
    event.confidence = result["confidence"]
    event.detection_method = result["detection_method"]
    event.status = "REVIEWED"

    if result["event_type"] != "BENIGN":
        message = (
            f"{result['event_type']} detected from {event.source_ip} "
            f"(confidence {result['confidence']:.2f}) - {result['reason']}"
        )
        alert_service.create_alert(db, event, message)

        if result["severity"] in ("HIGH", "CRITICAL"):
            prevention.auto_prevent(db, event)

    return result
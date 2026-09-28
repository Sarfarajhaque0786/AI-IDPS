"""
Hybrid detection: runs both the rule engine and the ML model on the same
event, then combines their outputs into one final classification.
"""
from app.services import rule_engine, ml_detector


def assign_severity(event_type: str, confidence: float) -> str:
    if event_type == "BENIGN":
        return "LOW"
    if confidence >= 0.85:
        return "CRITICAL"
    if confidence >= 0.70:
        return "HIGH"
    if confidence >= 0.50:
        return "MEDIUM"
    return "LOW"


def hybrid_detect(record: dict) -> dict:
    """
    record: dict with packet_count, byte_count, protocol,
            source_port, destination_port
    Returns: {event_type, severity, confidence, detection_method, reason}
    """
    rule_result = rule_engine.evaluate_event(record)

    if not ml_detector.is_model_available():
        return {
            "event_type": rule_result["event_type"],
            "confidence": rule_result["confidence"],
            "severity": assign_severity(rule_result["event_type"], rule_result["confidence"]),
            "detection_method": "RULE",
            "reason": rule_result["reason"] + " (ML model unavailable)",
        }

    ml_result = ml_detector.predict(record)

    if rule_result["event_type"] == ml_result["event_type"]:
        final_type = rule_result["event_type"]
        final_confidence = round((rule_result["confidence"] + ml_result["confidence"]) / 2, 4)
        reason = f"Rule and ML both classified as {final_type} (agreement)"
    else:
        if ml_result["confidence"] >= rule_result["confidence"]:
            final_type = ml_result["event_type"]
            final_confidence = ml_result["confidence"]
        else:
            final_type = rule_result["event_type"]
            final_confidence = rule_result["confidence"]
        reason = (
            f"Rule engine suggested {rule_result['event_type']} "
            f"({rule_result['confidence']:.2f}), ML suggested {ml_result['event_type']} "
            f"({ml_result['confidence']:.2f}) - used higher-confidence result"
        )

    return {
        "event_type": final_type,
        "confidence": final_confidence,
        "severity": assign_severity(final_type, final_confidence),
        "detection_method": "HYBRID",
        "reason": reason,
    }
from app.services.rule_engine import evaluate_event
from app.services.detector import hybrid_detect, assign_severity


def test_rule_engine_benign():
    result = evaluate_event({"packet_count": 5, "byte_count": 500, "protocol": "TCP", "destination_port": 443, "source_port": 5000})
    assert result["event_type"] == "BENIGN"


def test_rule_engine_dos_threshold():
    result = evaluate_event({"packet_count": 900, "byte_count": 90000, "protocol": "TCP", "destination_port": 80, "source_port": 5000})
    assert result["event_type"] == "DoS"
    assert result["severity"] == "HIGH"


def test_rule_engine_brute_force_port():
    result = evaluate_event({"packet_count": 3, "byte_count": 150, "protocol": "TCP", "destination_port": 22, "source_port": 5000})
    assert result["event_type"] == "Brute Force"


def test_severity_assignment():
    assert assign_severity("BENIGN", 0.99) == "LOW"
    assert assign_severity("DoS", 0.9) == "CRITICAL"
    assert assign_severity("DoS", 0.75) == "HIGH"
    assert assign_severity("DoS", 0.55) == "MEDIUM"


def test_hybrid_detect_returns_valid_structure():
    result = hybrid_detect({"packet_count": 700, "byte_count": 70000, "protocol": "TCP", "destination_port": 80, "source_port": 5000})
    assert result["detection_method"] in ("RULE", "HYBRID")
    assert 0.0 <= result["confidence"] <= 1.0
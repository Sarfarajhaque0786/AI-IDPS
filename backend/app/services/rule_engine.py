"""
Rule-based detection engine.
Evaluates traffic characteristics against configurable thresholds and
returns a classification. This is the non-ML half of the hybrid detector.
"""

# Configurable thresholds (Phase 27 will expose these via a settings API)
THRESHOLDS = {
    "high_connection_packet_count": 500,
    "brute_force_ports": {22, 3389},
    "probe_ports_max": 1024,
    "bot_packet_min": 10,
    "bot_packet_max": 30,
}


def evaluate_event(fields: dict) -> dict:
    """
    fields: dict with keys packet_count, byte_count, protocol,
            destination_port, source_port
    Returns: {event_type, severity, confidence, reason}
    """
    packet_count = fields.get("packet_count", 0)
    destination_port = fields.get("destination_port")
    protocol = fields.get("protocol", "")

    if packet_count > THRESHOLDS["high_connection_packet_count"]:
        return {
            "event_type": "DoS",
            "severity": "HIGH",
            "confidence": 0.88,
            "reason": f"Packet count {packet_count} exceeded high-connection threshold "
                      f"({THRESHOLDS['high_connection_packet_count']})",
        }

    if destination_port in THRESHOLDS["brute_force_ports"]:
        return {
            "event_type": "Brute Force",
            "severity": "MEDIUM",
            "confidence": 0.75,
            "reason": f"Repeated connection attempts to sensitive port {destination_port}",
        }

    if protocol in ("UDP", "ICMP") and destination_port and destination_port < THRESHOLDS["probe_ports_max"]:
        return {
            "event_type": "Probe",
            "severity": "MEDIUM",
            "confidence": 0.65,
            "reason": f"Unusual {protocol} traffic to low-numbered port {destination_port}",
        }

    if (
        THRESHOLDS["bot_packet_min"] <= packet_count <= THRESHOLDS["bot_packet_max"]
        and destination_port == 443
    ):
        return {
            "event_type": "Bot",
            "severity": "LOW",
            "confidence": 0.55,
            "reason": "Small, regular automated-looking request pattern",
        }

    return {
        "event_type": "BENIGN",
        "severity": "LOW",
        "confidence": 0.9,
        "reason": "No rule thresholds triggered",
    }
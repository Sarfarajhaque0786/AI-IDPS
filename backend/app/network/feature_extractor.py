"""
Feature extraction pipeline. This SAME logic is used during training
(train.py) and during live prediction (ml_detector.py in Phase 18) -
critical to avoid train/predict skew.
"""
import numpy as np

PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2}


def encode_protocol(protocol: str) -> int:
    return PROTOCOL_MAP.get(protocol, 3)  # 3 = "OTHER" / unknown


def extract_features(record: dict) -> list:
    """
    record: dict with packet_count, byte_count, protocol,
            source_port, destination_port
    Returns a fixed-order numeric feature vector.
    """
    packet_count = record.get("packet_count", 0) or 0
    byte_count = record.get("byte_count", 0) or 0
    avg_packet_size = byte_count / packet_count if packet_count > 0 else 0
    protocol_encoded = encode_protocol(record.get("protocol", ""))
    source_port = record.get("source_port", 0) or 0
    destination_port = record.get("destination_port", 0) or 0

    return [
        packet_count,
        byte_count,
        avg_packet_size,
        protocol_encoded,
        source_port,
        destination_port,
    ]


FEATURE_NAMES = [
    "packet_count",
    "byte_count",
    "avg_packet_size",
    "protocol_encoded",
    "source_port",
    "destination_port",
]


def extract_features_batch(records: list) -> np.ndarray:
    return np.array([extract_features(r) for r in records])
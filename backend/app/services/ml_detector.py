"""
Loads the trained Random Forest model once at import time and exposes
a predict() function for live/simulated event classification.
Uses the SAME feature_extractor as training - critical for consistency.
"""
import os
import joblib

from app.network.feature_extractor import extract_features

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "ml", "models")
MODEL_PATH = os.path.join(MODELS_DIR, "random_forest_model.joblib")
ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.joblib")

_model = None
_label_encoder = None


def _load():
    global _model, _label_encoder
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                "ML model not found. Run `python -m app.ml.train` first."
            )
        _model = joblib.load(MODEL_PATH)
        _label_encoder = joblib.load(ENCODER_PATH)
    return _model, _label_encoder


def predict(record: dict) -> dict:
    """
    record: dict with packet_count, byte_count, protocol,
            source_port, destination_port
    Returns: {event_type, confidence}
    """
    model, label_encoder = _load()
    features = [extract_features(record)]
    prediction = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]
    confidence = float(max(probabilities))
    event_type = label_encoder.inverse_transform([prediction])[0]
    return {"event_type": event_type, "confidence": confidence}


def is_model_available() -> bool:
    return os.path.exists(MODEL_PATH)
import os
import json
from fastapi import APIRouter, Depends, HTTPException

from app.middleware.auth import get_current_user

router = APIRouter(prefix="/api/ml", tags=["ml"])

METRICS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "ml", "models", "metrics.json"
)


def _load_metrics():
    if not os.path.exists(METRICS_PATH):
        raise HTTPException(status_code=404, detail="No trained model found")
    with open(METRICS_PATH) as f:
        return json.load(f)


@router.get("/model")
def get_model_info(_current_user=Depends(get_current_user)):
    return _load_metrics()


@router.get("/metrics")
def get_model_metrics(_current_user=Depends(get_current_user)):
    return _load_metrics()
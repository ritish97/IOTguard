"""
IoTGuard Gateway REST API
Provides line-rate edge ingestion for Zeek connection logs and real-time containment status.
"""

import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

import sys
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import DEFAULT_THETA, DEFAULT_K, MODELS_DIR
from iotguard.models import IoTGuardModel
from iotguard.features import FeatureExtractor
from iotguard.policy import GradedContainmentPolicy

app = FastAPI(
    title="IoTGuard Edge Gateway API",
    description="Line-rate Stage-Aware Intrusion Detection & Graded Containment API for IoT Edge Gateways",
    version="1.0.0"
)

# Global instances
model: Optional[IoTGuardModel] = None
extractor = FeatureExtractor()
policy = GradedContainmentPolicy(theta=DEFAULT_THETA, k=DEFAULT_K)


@app.on_event("startup")
def startup_event():
    global model
    model_path = MODELS_DIR / "iotguard_xgboost.json"
    if model_path.exists():
        model = IoTGuardModel()
        model.load(model_path)
        print(f"Loaded IoTGuard model from {model_path}")
    else:
        print(f"Warning: Model not found at {model_path}. Train model first!")


class ZeekRecord(BaseModel):
    ts: float = Field(default_factory=time.time)
    id_orig_h: str = Field(alias="id.orig_h", default="192.168.1.100")
    id_resp_h: str = Field(alias="id.resp_h", default="8.8.8.8")
    id_resp_p: int = Field(alias="id.resp_p", default=53)
    proto: str = "tcp"
    conn_state: str = "SF"
    duration: float = 0.1
    orig_bytes: float = 100
    resp_bytes: float = 200
    orig_pkts: int = 2
    resp_pkts: int = 2
    orig_ip_bytes: float = 180
    resp_ip_bytes: float = 280
    missed_bytes: float = 0
    history: str = "ShADadFf"

    class Config:
        populate_by_name = True


class BatchIngest(BaseModel):
    records: List[ZeekRecord]


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "quarantined_devices": len(policy.quarantined_devices),
        "blocked_destinations": len(policy.blocked_destinations)
    }


@app.post("/api/v1/classify")
def classify_connection(record: ZeekRecord):
    if model is None:
        raise HTTPException(status_code=503, detail="IoTGuard model is not loaded.")

    rec_dict = record.model_dump(by_alias=True)
    extracted = extractor.extract_from_record(rec_dict)
    features = extracted["features"]
    meta = extracted["metadata"]

    stage, conf, probs = model.predict_single(features)
    decision = policy.evaluate_verdict(stage, conf, meta)

    return {
        "device": meta["orig_h"],
        "destination": meta["resp_h"],
        "port": meta["resp_p"],
        "predicted_stage": stage,
        "confidence": conf,
        "probabilities": probs,
        "action": decision["action"],
        "action_level": decision["action_level"],
        "reason": decision["reason"],
        "would_have_dropped": decision["would_have_dropped"]
    }


@app.get("/api/v1/firewall/rules")
def get_firewall_rules():
    return {
        "quarantined_devices": list(policy.quarantined_devices),
        "blocked_destinations": [f"{s} -> {d}" for (s, d) in policy.blocked_destinations],
        "active_rules_count": len(policy.active_rules)
    }


@app.post("/api/v1/firewall/reset")
def reset_firewall():
    policy.reset()
    extractor.reset_window()
    return {"message": "Firewall state and sliding windows reset successfully."}

import os
import joblib
import numpy as np
import pandas as pd
import shap
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any

# ── Load model and preprocessors ─────────────────────────────────────────────
print("Loading model...")
model = joblib.load("model/xgb_model.pkl")
scaler = joblib.load("model/scaler.pkl")
encoders = joblib.load("model/encoders.pkl")
feature_names = joblib.load("model/feature_names.pkl")

# ── SHAP explainer ────────────────────────────────────────────────────────────
explainer = shap.TreeExplainer(model)
print("Model loaded.")

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title="Network Intrusion Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request schema ────────────────────────────────────────────────────────────
class NetworkTraffic(BaseModel):
    dur: float = 0.0
    proto: str = "tcp"
    service: str = "http"
    state: str = "FIN"
    spkts: int = 0
    dpkts: int = 0
    sbytes: int = 0
    dbytes: int = 0
    rate: float = 0.0
    sttl: int = 64
    dttl: int = 64
    sload: float = 0.0
    dload: float = 0.0
    sloss: int = 0
    dloss: int = 0
    sinpkt: float = 0.0
    dinpkt: float = 0.0
    sjit: float = 0.0
    djit: float = 0.0
    swin: int = 0
    stcpb: int = 0
    dtcpb: int = 0
    dwin: int = 0
    tcprtt: float = 0.0
    synack: float = 0.0
    ackdat: float = 0.0
    smean: int = 0
    dmean: int = 0
    trans_depth: int = 0
    response_body_len: int = 0
    ct_srv_src: int = 0
    ct_state_ttl: int = 0
    ct_dst_ltm: int = 0
    ct_src_dport_ltm: int = 0
    ct_dst_sport_ltm: int = 0
    ct_dst_src_ltm: int = 0
    is_ftp_login: int = 0
    ct_ftp_cmd: int = 0
    ct_flw_http_mthd: int = 0
    ct_src_ltm: int = 0
    ct_srv_dst: int = 0
    is_sm_ips_ports: int = 0


def preprocess(traffic: NetworkTraffic) -> np.ndarray:
    data = traffic.dict()

    # Encode categorical columns
    cat_cols = ['proto', 'service', 'state']
    for col in cat_cols:
        le = encoders[col]
        val = str(data[col])
        if val not in le.classes_:
            val = le.classes_[0]
        data[col] = int(le.transform([val])[0])

    # Build feature vector in correct order
    row = [data[f] for f in feature_names]
    row_array = np.array(row, dtype=float).reshape(1, -1)
    row_scaled = scaler.transform(row_array)
    return row_scaled, row_array


# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status": "ok",
        "model": "XGBoost",
        "dataset": "UNSW-NB15",
        "auc_roc": 0.9856,
        "accuracy": 0.90
    }


@app.get("/model-info")
def model_info():
    return {
        "model": "XGBoost Classifier",
        "dataset": "UNSW-NB15",
        "training_samples": 82332,
        "test_samples": 175341,
        "features": 42,
        "auc_roc": 0.9856,
        "accuracy": 0.90,
        "attack_precision": 0.99,
        "attack_recall": 0.87,
        "top_features": [
            "sttl", "ct_dst_src_ltm", "ct_dst_sport_ltm",
            "service", "proto", "sbytes", "smean"
        ]
    }


@app.post("/predict")
def predict(traffic: NetworkTraffic):
    row_scaled, row_raw = preprocess(traffic)

    # Prediction
    prediction = int(model.predict(row_scaled)[0])
    probability = float(model.predict_proba(row_scaled)[0][1])

    # SHAP explanation
    shap_vals = explainer.shap_values(row_scaled)[0]
    shap_dict = {
        feature_names[i]: round(float(shap_vals[i]), 4)
        for i in range(len(feature_names))
    }

    # Top 5 reasons
    sorted_shap = sorted(shap_dict.items(), key=lambda x: abs(x[1]), reverse=True)
    top_reasons = [
        {"feature": k, "impact": v, "direction": "increases attack risk" if v > 0 else "decreases attack risk"}
        for k, v in sorted_shap[:5]
    ]

    return {
        "prediction": "Attack" if prediction == 1 else "Normal",
        "attack_probability": round(probability * 100, 2),
        "confidence": round(max(probability, 1 - probability) * 100, 2),
        "top_reasons": top_reasons,
        "raw_shap": shap_dict
    }


@app.post("/predict/batch")
def predict_batch(samples: list[NetworkTraffic]):
    results = []
    for traffic in samples:
        result = predict(traffic)
        results.append(result)
    return {"results": results, "total": len(results)}
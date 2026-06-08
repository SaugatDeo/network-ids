# 🛡️ NetGuard AI — Network Intrusion Detection System

> Real-time AI-powered network traffic analysis with explainable threat detection. Built for Security Operations Centers.

[![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)](https://python.org)
[![XGBoost](https://img.shields.io/badge/Model-XGBoost-orange?style=flat-square)](https://xgboost.readthedocs.io)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![AUC-ROC](https://img.shields.io/badge/AUC--ROC-0.9856-brightgreen?style=flat-square)](https://github.com/SaugatDeo/network-ids)

---

## The Problem

Traditional rule-based intrusion detection systems (IDS) fail against novel attacks — they can only detect what they've seen before. Modern adversaries adapt faster than signature databases update.

**NetGuard AI** solves this by learning the statistical fingerprint of malicious network behavior across 42 traffic features, detecting zero-day-style anomalies that signature-based systems miss — and explaining every decision with SHAP values so analysts can act, not just react.

---

## 🌐 Live Demo

| Service | URL |
|---|---|
| 🖥️ SOC Dashboard | Coming soon — Streamlit Cloud |
| ⚡ API Docs | [Open API](https://saugatiwi-network-ids.hf.space/docs) |
## Architecture

```
Raw Network Traffic
        │
        ▼
┌─────────────────────────────┐
│   Feature Engineering       │
│   • Label encoding          │
│   • StandardScaler (42 f.)  │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│   XGBoost Classifier        │
│   • 300 estimators          │
│   • Depth 6                 │
│   • Trained on 82K samples  │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│   SHAP Explainer            │
│   • TreeExplainer           │
│   • Per-prediction reasons  │
│   • Top 5 feature impacts   │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│   FastAPI REST Endpoint     │
│   /predict → JSON response  │
│   attack_probability + why  │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│   Streamlit SOC Dashboard   │
│   • Live alert feed         │
│   • Attack timeline         │
│   • SHAP panel              │
│   • Manual scan mode        │
└─────────────────────────────┘
```

---

## Model Performance

Trained and evaluated on the **UNSW-NB15** dataset — the most cited network intrusion benchmark in 2024–2025 research.

| Metric | Value |
|---|---|
| Dataset | UNSW-NB15 |
| Training samples | 82,332 |
| Test samples | 175,341 |
| Input features | 42 |
| **AUC-ROC** | **0.9856** |
| Accuracy | 90.0% |
| Attack precision | 99% |
| Attack recall | 87% |
| Normal recall | 98% |

> Published XGBoost baselines on UNSW-NB15 report AUC-ROC between 0.95–0.98. This implementation reaches **0.9856** — top-end of published results.

---

## Explainability — SHAP

Every prediction comes with a SHAP explanation showing which network features drove the classification and in which direction.

### Top Features by Mean |SHAP| Value

| Rank | Feature | SHAP Value | What It Means |
|---|---|---|---|
| 1 | `sttl` | 2.89 | Source TTL — attackers manipulate TTL to evade detection |
| 2 | `ct_dst_src_ltm` | 1.51 | Connection count between src-dst pair — high = scanning behavior |
| 3 | `ct_dst_sport_ltm` | 1.04 | Connections to same destination port — port sweep indicator |
| 4 | `service` | 0.83 | Service type — unusual protocol/service combos flag attacks |
| 5 | `proto` | 0.74 | Protocol — ICMP/ARP spikes are common in reconnaissance |
| 6 | `sbytes` | 0.66 | Source bytes — DoS attacks show extreme byte volumes |
| 7 | `smean` | 0.64 | Mean packet size — abnormal sizes indicate payload anomalies |

**Why SHAP matters for security:** A model that says "Attack" without explaining why is useless to an analyst. SHAP gives the exact feature-level evidence — the same information a human analyst would look for — making the system auditable and actionable.

This is now legally relevant: the **EU AI Act (2025)** requires explainability for high-risk AI systems including security applications.

---

## API Reference

### Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | System status, model name, AUC-ROC |
| `GET` | `/model-info` | Full model metadata and top features |
| `POST` | `/predict` | Classify single network connection |
| `POST` | `/predict/batch` | Classify multiple connections |

### POST /predict — Request

```json
{
  "proto": "tcp",
  "service": "http",
  "state": "FIN",
  "sttl": 64,
  "sbytes": 1500,
  "dbytes": 800,
  "ct_dst_src_ltm": 45,
  "spkts": 12,
  "dpkts": 8
}
```

### POST /predict — Response

```json
{
  "prediction": "Attack",
  "attack_probability": 97.4,
  "confidence": 97.4,
  "top_reasons": [
    {
      "feature": "ct_dst_src_ltm",
      "impact": 1.84,
      "direction": "increases attack risk"
    },
    {
      "feature": "sttl",
      "impact": 1.51,
      "direction": "increases attack risk"
    },
    {
      "feature": "sbytes",
      "impact": -0.62,
      "direction": "decreases attack risk"
    }
  ]
}
```

---

## SOC Dashboard Features

The Streamlit dashboard simulates a real Security Operations Center monitoring environment.

| Feature | Description |
|---|---|
| **Live Alert Feed** | Color-coded alerts — 🔴 Critical (>80%), 🟠 High, 🟢 Normal |
| **Attack Timeline** | Real-time probability chart with 50% threshold line |
| **Traffic Breakdown** | Donut chart — Attack vs Normal ratio |
| **SHAP Panel** | Feature impact bars for the latest prediction |
| **Connection Detail** | Source IP, destination IP, protocol, bytes, TTL |
| **Manual Scan Mode** | Input custom traffic features and get instant prediction |
| **Simulation Control** | Adjustable scan interval (0.5–5 seconds) |

---

## Dataset — UNSW-NB15

| Property | Value |
|---|---|
| Source | University of New South Wales, Canberra |
| Total records | 2,540,044 |
| Training set used | 82,332 |
| Test set used | 175,341 |
| Features | 42 network traffic features |
| Attack categories | 9 (Generic, Exploits, Fuzzers, DoS, Reconnaissance, Analysis, Backdoor, Shellcode, Worms) |

**Why UNSW-NB15 over older datasets:**
- KDD Cup 99 (1999) and NSL-KDD (2009) are considered obsolete by the research community
- UNSW-NB15 reflects modern attack vectors and realistic traffic patterns
- Most cited dataset in 2024–2025 IDS research papers

---

## Local Setup

### Prerequisites
- Python 3.9+
- 8GB RAM recommended (dataset is ~600MB)

### Installation

```bash
# Clone repository
git clone https://github.com/SaugatDeo/network-ids.git
cd network-ids

# Install dependencies
pip install -r requirements.txt

# Download dataset from Kaggle
# https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15
# Extract to data/archive/

# Train the model (~3 minutes)
python train.py

# Run SHAP analysis
python shap_analysis.py

# Terminal 1 — Start API
uvicorn api:app --reload --port 8000

# Terminal 2 — Start dashboard
streamlit run app.py
```

---

## Project Structure

```
network-ids/
├── explore.py            # Dataset exploration — shapes, distributions, missing values
├── train.py              # Model training — XGBoost + evaluation + model persistence
├── shap_analysis.py      # SHAP feature importance — summary and bar plots
├── api.py                # FastAPI backend — prediction + SHAP explanation endpoints
├── app.py                # Streamlit SOC dashboard — live simulation + manual scan
├── requirements.txt      # Pinned dependencies
└── README.md
```

---

## Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Model | XGBoost | Industry standard for tabular threat detection — used by DBS, OCBC, GovTech |
| Explainability | SHAP TreeExplainer | Per-prediction feature attribution — EU AI Act compliant |
| API | FastAPI + Uvicorn | Async REST API — production-grade, OpenAPI docs auto-generated |
| Dashboard | Streamlit + Plotly | Rapid SOC prototype — dark theme, live charts |
| Dataset | UNSW-NB15 | Most cited modern IDS benchmark (2024–2025) |

---

## Industry Context

This project covers the core skills for the fastest-growing roles at the AI/Security intersection in 2026:

| Role | Skills Covered |
|---|---|
| AI Security Engineer | ML model training, threat classification, API deployment |
| SOC Analyst (AI-augmented) | Alert triage, SHAP-based investigation, dashboard monitoring |
| ML Security Researcher | Benchmark datasets, evaluation metrics, explainability |
| GovTech / Banking IDS | XGBoost, anomaly detection, FastAPI integration |

Comparable commercial tools: **Splunk SIEM**, **IBM QRadar**, **Microsoft Sentinel**, **Darktrace** — all incorporate ML-based anomaly detection as their core detection layer.

---

## Author

**Saugat Deo**
B.Tech Electronics & Instrumentation Engineering — NIT Rourkela
First Class · CGPA 7.30 · Graduated May 2025

[GitHub](https://github.com/SaugatDeo) · [LinkedIn](https://linkedin.com/in/saugat-deo-16432b228)

---

*Part of a three-project AI portfolio spanning NLP (RAG document intelligence), Computer Vision (medical imaging), and Cybersecurity (network intrusion detection).*

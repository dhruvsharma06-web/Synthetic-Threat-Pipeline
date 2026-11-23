"""Scoring service (CONTRACT B5, PRD "Live scoring API").

  GET  /health   liveness + whether a model is loaded
  GET  /model    the model card (what shipped, its metrics)
  POST /score     {"events": [ <common-schema event>, ... ]} -> per-window alerts
  GET  /alerts   recent flagged windows, newest first (the dashboard polls this)

Run: uvicorn pipeline.api:app --port 8000   (MODEL_DIR env points at the joblib)
"""
import json
import os
from collections import deque

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from pipeline import scorer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECENT = deque(maxlen=200)  # flagged alerts, in memory — the live feed, not the system of record

app = FastAPI(title="Synthetic Threat Pipeline — scorer", version="2")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class ScoreRequest(BaseModel):
    events: list[dict]


@app.get("/health")
def health():
    b = scorer.load_model()
    return {"status": "ok", "model_loaded": b is not None, "model_kind": b["kind"] if b else None}


@app.get("/model")
def model():
    for d in (os.getenv("MODEL_DIR"), "models"):
        if not d:
            continue
        path = os.path.join(ROOT, d, "model_card.json") if not os.path.isabs(d) else os.path.join(d, "model_card.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                return json.load(f)
    return {"status": "no model card — run `make train`"}


@app.post("/score")
def score(req: ScoreRequest):
    alerts = scorer.score_events(req.events)
    flagged = [a for a in alerts if a["prediction"] == 1]
    RECENT.extend(flagged)
    return {"scored": len(alerts), "flagged": len(flagged), "alerts": alerts}


@app.get("/alerts")
def alerts(limit: int = 50):
    return {"alerts": list(RECENT)[-limit:][::-1]}

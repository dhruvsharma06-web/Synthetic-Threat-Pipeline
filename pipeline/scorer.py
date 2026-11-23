"""The one scoring path shared by the API and the Loki worker (CONTRACT B5).

Events (common schema) -> window features (reusing features.build) -> the trained
model.joblib -> per-window alerts. Works for both the supervised detector and the
IsolationForest fallback, so the service runs even before the bots have labelled data.
"""
import os

import numpy as np

from pipeline import features

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CACHE = {}  # model_dir -> loaded bundle, so the API loads the joblib once


def _model_path(model_dir=None):
    if model_dir is None:
        import yaml
        with open(os.path.join(ROOT, "config.yaml"), encoding="utf-8") as f:
            model_dir = os.getenv("MODEL_DIR", yaml.safe_load(f)["model_dir"])
    return os.path.join(model_dir, "model.joblib")


def load_model(model_dir=None, refresh=False):
    """Load (and cache) the joblib bundle {model, features, kind}. None if not trained yet."""
    path = _model_path(model_dir)
    if refresh:
        _CACHE.pop(path, None)
    if path not in _CACHE:
        if not os.path.exists(path):
            return None
        import joblib
        _CACHE[path] = joblib.load(path)
    return _CACHE[path]


def _severity(prediction, score):
    if not prediction:
        return "none"
    if score is None:
        return "high"
    return "critical" if score >= 0.8 else "high" if score >= 0.5 else "medium"


def score_events(events, model_dir=None):
    """events: list[dict] -> list of per-window alert dicts (attack rows have prediction=1)."""
    bundle = load_model(model_dir)
    if bundle is None:
        return []
    feats = features.build(events)
    if feats.empty:
        return []
    model, cols, kind = bundle["model"], bundle["features"], bundle["kind"]
    X = feats.reindex(columns=cols).fillna(0)  # tolerate a feature the live data lacks

    if kind == "isolation_forest":
        pred = (model.predict(X) == -1).astype(int)              # -1 = anomaly = flagged
        raw = -model.score_samples(X)                            # higher = more anomalous
        score = 1 / (1 + np.exp(-(raw - raw.mean())))            # squash to 0..1 for display
    elif hasattr(model, "predict_proba"):
        score = model.predict_proba(X)[:, 1]
        pred = (score >= 0.5).astype(int)
    else:
        pred = model.predict(X).astype(int)
        score = pred.astype(float)

    out = []
    for i, (_, r) in enumerate(feats.iterrows()):
        s = round(float(score[i]), 4)
        out.append({
            "src_ip": r["src_ip"],
            "window": r["window"],
            "window_end": r["window_end"],
            "events": int(r["events"]),
            "prediction": int(pred[i]),
            "score": s,
            "attack_type": None,          # binary detector; type classifier is deferred (needs multi-type data)
            "model_kind": kind,
            "severity": _severity(int(pred[i]), s),
        })
    return out

"""Train and compare attack classifiers on the feature table (CONTRACT B4, PRD "Models").

Pipeline: features.parquet -> time-based train/test split -> baselines + models ->
metrics + explainability -> joblib + model card. Training uses only *labelled* windows
(label in {0,1}); unlabelled windows are real captured traffic kept out of training.

Run: python -m pipeline.train   (paths from config.yaml / env: DATA_DIR, MODEL_DIR)

Not built here (needs data the overnight bot run produces, so untestable now):
  - cross-source generalisation test: every real log we have is Cowrie, and the feature
    table carries no source column, so a train-on-A/test-on-B split has nothing to split on.
  - attack-TYPE classifier: needs >1 attack type present; the binary detector ships first.
"""
import json
import os
import warnings
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import TimeSeriesSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NON_FEATURES = {"src_ip", "window_end", "window", "label", "attack_type"}
V1_FEATURES = ["events", "failed_login_ratio", "iat_mean"]  # the old 3-feature detector, as a floor
TEST_FRAC = 0.3  # most recent 30% of windows, by time


def _cfg():
    import yaml
    with open(os.path.join(ROOT, "config.yaml"), encoding="utf-8") as f:
        c = yaml.safe_load(f)
    return (os.getenv("DATA_DIR", c["data_dir"]), os.getenv("MODEL_DIR", c["model_dir"]))


def feature_cols(df):
    return [c for c in df.columns if c not in NON_FEATURES]


def time_split(df):
    """Oldest windows train, most recent TEST_FRAC test — never shuffle time-ordered events."""
    df = df.sort_values("window_end").reset_index(drop=True)
    cut = int(len(df) * (1 - TEST_FRAC))
    return df.iloc[:cut], df.iloc[cut:]


def _scores(y, pred, proba):
    m = {
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "support_pos": int(y.sum()),
        "support_total": int(len(y)),
    }
    if proba is not None and len(set(y)) > 1:
        m["roc_auc"] = round(roc_auc_score(y, proba), 4)
        m["pr_auc"] = round(average_precision_score(y, proba), 4)
    m["confusion"] = confusion_matrix(y, pred, labels=[0, 1]).tolist()  # [[tn,fp],[fn,tp]]
    for k in ("precision", "recall", "f1"):
        m[k] = round(m[k], 4)
    return m


def _rules_baseline(te, cols):
    """Hand-written detector — the floor every learned model must clear.
    An attack window = many failed logins, or clear injection/traversal/shell payload."""
    f = te
    pred = ((f.get("failed_login_ratio", 0) >= 0.8) & (f.get("events", 0) >= 5)
            | (f.get("payload_sql_kw", 0) > 0) | (f.get("payload_traversal", 0) > 0)
            | (f.get("payload_shell_meta", 0) > 0) | (f.get("http_error_ratio", 0) >= 0.5)
            ).astype(int)
    return pred.values


def _models():
    return {
        "logreg": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, class_weight="balanced")),
        "random_forest": RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0, n_jobs=-1),
        "gradient_boosting": GradientBoostingClassifier(random_state=0),  # stands in for XGBoost; no extra dep
    }


def _proba(model, X):
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]
    return None


def _cv_f1(model, X, y):
    """Mean F1 over expanding time-ordered folds (never leak the future into the past)."""
    n_splits = min(5, max(2, int(y.sum())))
    if len(set(y)) < 2 or y.sum() < 2:
        return None
    scores = []
    for tr, va in TimeSeriesSplit(n_splits=n_splits).split(X):
        if len(set(y.iloc[tr])) < 2:
            continue
        m = _clone_fit(model, X.iloc[tr], y.iloc[tr])
        scores.append(f1_score(y.iloc[va], m.predict(X.iloc[va]), zero_division=0))
    return round(float(np.mean(scores)), 4) if scores else None


def _clone_fit(model, X, y):
    from sklearn.base import clone
    m = clone(model)
    m.fit(X, y)
    return m


def _explain(model, X_te, y_te, cols):
    """Top drivers via permutation importance (model-agnostic). SHAP used when installed."""
    try:
        import shap  # PRD-named; optional so the pipeline runs without it
        expl = shap.Explainer(model.predict, X_te)
        vals = np.abs(expl(X_te).values).mean(axis=0)
        src = "shap"
    except Exception:
        r = permutation_importance(model, X_te, y_te, n_repeats=10, random_state=0, n_jobs=-1)
        vals = r.importances_mean
        src = "permutation_importance"
    top = sorted(zip(cols, (round(float(v), 4) for v in vals)), key=lambda kv: -kv[1])[:10]
    return {"method": src, "top_features": dict(top)}


def build(data_dir=None, model_dir=None):
    data_dir, model_dir = (data_dir, model_dir) if data_dir else _cfg()
    path = os.path.join(data_dir, "features.parquet")
    if not os.path.exists(path):
        raise SystemExit(f"no feature table at {path} — run `make dataset` first")
    df = pd.read_parquet(path)
    labelled = df[df["label"].isin([0, 1])].copy()
    labelled["label"] = labelled["label"].astype(int)
    cols = feature_cols(labelled)
    os.makedirs(model_dir, exist_ok=True)

    card = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "feature_rows_total": int(len(df)),
        "labelled_rows": int(len(labelled)),
        "label_balance": labelled["label"].value_counts().to_dict() if len(labelled) else {},
        "features": cols,
        "split": {"scheme": "time-ordered", "test_frac": TEST_FRAC},
    }

    # Supervised training needs both classes. With one class (e.g. before the bot run
    # labels any attacks) we still fit an unsupervised detector and say so, instead of crashing.
    if labelled["label"].nunique() < 2 or len(labelled) < 10:
        card["status"] = "insufficient_labelled_data"
        card["note"] = ("Need both classes and >=10 labelled windows to train. "
                        "Run the bots (which write ground-truth labels), rebuild the dataset, retrain.")
        iso = IsolationForest(random_state=0).fit(df[cols].fillna(0))  # unsupervised floor on all traffic
        joblib.dump({"model": iso, "features": cols, "kind": "isolation_forest"},
                    os.path.join(model_dir, "model.joblib"))
        card["shipped_model"] = "isolation_forest (unsupervised, no labels yet)"
        _write_card(model_dir, card)
        return card

    tr, te = time_split(labelled)
    Xtr, ytr, Xte, yte = tr[cols].fillna(0), tr["label"], te[cols].fillna(0), te["label"]
    results = {}

    # baselines
    results["baseline_rules"] = _scores(yte, _rules_baseline(te, cols), None)
    v1 = _clone_fit(RandomForestClassifier(n_estimators=100, random_state=0), tr[V1_FEATURES].fillna(0), ytr)
    results["baseline_v1_3feat"] = _scores(yte, v1.predict(te[V1_FEATURES].fillna(0)),
                                           _proba(v1, te[V1_FEATURES].fillna(0)))

    # learned models
    fitted = {}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # convergence chatter on tiny dev data
        for name, model in _models().items():
            m = _clone_fit(model, Xtr, ytr)
            fitted[name] = m
            r = _scores(yte, m.predict(Xte), _proba(m, Xte))
            r["cv_f1_timeseries"] = _cv_f1(model, Xtr, ytr)
            results[name] = r

    # pick the best learned model by test F1 (tie-break higher recall: missing an attack costs more)
    best = max(fitted, key=lambda n: (results[n]["f1"], results[n]["recall"]))
    best_model = fitted[best]
    card.update({
        "status": "trained",
        "results": results,
        "best_model": best,
        "beats_rules_baseline": results[best]["f1"] >= results["baseline_rules"]["f1"],
        "beats_v1_baseline": results[best]["f1"] >= results["baseline_v1_3feat"]["f1"],
        "explainability": _explain(best_model, Xte, yte, cols),
    })
    joblib.dump({"model": best_model, "features": cols, "kind": best},
                os.path.join(model_dir, "model.joblib"))
    _write_card(model_dir, card)
    return card


def _write_card(model_dir, card):
    with open(os.path.join(model_dir, "model_card.json"), "w", encoding="utf-8") as f:
        json.dump(card, f, indent=2)
    print(json.dumps(card, indent=2))


if __name__ == "__main__":
    build()

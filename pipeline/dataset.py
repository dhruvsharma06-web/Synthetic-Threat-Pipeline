"""Build the labelled dataset: parse every log -> join labels -> features -> Parquet+CSV + data card.

Usage: python -m pipeline.dataset  (paths from config.yaml / env: LOG_DIR, DATA_DIR, LABELS_DIR)
"""
import glob
import json
import os
from datetime import datetime, timezone

import yaml

from pipeline import features, label_join
from pipeline.parsers import apache, cowrie, flask, vsftpd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _cfg():
    with open(os.path.join(ROOT, "config.yaml"), encoding="utf-8") as f:
        c = yaml.safe_load(f)
    return (os.getenv("LOG_DIR", c["log_dir"]), os.getenv("DATA_DIR", c["data_dir"]),
            os.getenv("LABELS_DIR", os.path.join(c["data_dir"], "labels")))


def parse_all(log_dir):
    events = []
    for f in glob.glob(os.path.join(log_dir, "cowrie", "cowrie.json*")):
        events += cowrie.parse(f)
    for f in glob.glob(os.path.join(log_dir, "vsftpd", "*.log")):
        events += vsftpd.parse(f)
    for src in ("dvwa", "sar2html"):
        for f in glob.glob(os.path.join(log_dir, src, "*access*.log")):
            events += apache.parse(f, source="apache")
    for f in glob.glob(os.path.join(log_dir, "victim", "*.log")):
        events += flask.parse(f)
    return events


def data_card(events, n_labelled, feat_df):
    from collections import Counter
    by_source = Counter(e["source"] for e in events)
    by_label = Counter({0: 0, 1: 0, None: 0})
    by_type = Counter()
    for e in events:
        by_label[e["label"]] += 1
        if e["label"] == 1:
            by_type[e["attack_type"]] += 1
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "events_total": len(events),
        "events_labelled": n_labelled,
        "events_by_source": dict(by_source),
        "events_by_label": {str(k): v for k, v in by_label.items()},
        "attack_events_by_type": dict(by_type),
        "feature_rows": int(len(feat_df)),
        "feature_rows_by_window": feat_df["window"].value_counts().to_dict() if len(feat_df) else {},
        "note": "Labels come from the bot ground-truth join, not string matching. "
                "Unlabelled events are real captured traffic (test only), never defaulted to 0.",
    }


def build(log_dir=None, data_dir=None, labels_dir=None):
    log_dir, data_dir, labels_dir = (log_dir, data_dir, labels_dir) if log_dir else _cfg()
    events = parse_all(log_dir)
    events, n_labelled = label_join.join(events, labels_dir)
    feat_df = features.build(events)
    os.makedirs(data_dir, exist_ok=True)
    if len(feat_df):
        feat_df.to_parquet(os.path.join(data_dir, "features.parquet"), index=False)
        feat_df.to_csv(os.path.join(data_dir, "features.csv"), index=False)
    card = data_card(events, n_labelled, feat_df)
    with open(os.path.join(data_dir, "data_card.json"), "w", encoding="utf-8") as f:
        json.dump(card, f, indent=2)
    print(json.dumps(card, indent=2))
    return card


if __name__ == "__main__":
    build()

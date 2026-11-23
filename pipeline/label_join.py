"""Attach ground-truth labels to events by joining on src_ip + time window (CONTRACT B2).

A label row (bot_id,label,attack_type,t_start,t_end,src_ip) claims every event whose
src_ip matches and whose ts falls in [t_start, t_end]. An event no bot claims stays
unlabelled (label=None) and is NEVER defaulted to 0 — that was the v1 flaw. When two
rows claim the same event, an attack row (label=1) wins over a normal one.
"""
import csv
import glob
import os
from datetime import datetime


def _parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def load_labels(labels_dir):
    rows = []
    for path in glob.glob(os.path.join(labels_dir, "*.csv")):
        with open(path, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                r["_start"] = _parse_ts(r["t_start"])
                r["_end"] = _parse_ts(r["t_end"])
                r["label"] = int(r["label"])
                rows.append(r)
    # attack rows last, so they overwrite a normal match for the same event
    rows.sort(key=lambda r: r["label"])
    return rows


def join(events, labels_dir):
    """Fill label/attack_type/bot_id on each event in place; return (events, n_labelled)."""
    labels = load_labels(labels_dir)
    by_ip = {}
    for lr in labels:
        by_ip.setdefault(lr["src_ip"], []).append(lr)
    n = 0
    for e in events:
        ts = _parse_ts(e["ts"])
        matched = False
        for lr in by_ip.get(e["src_ip"], ()):
            if lr["_start"] <= ts <= lr["_end"]:
                e["label"] = lr["label"]
                e["attack_type"] = lr["attack_type"] or None
                e["bot_id"] = lr["bot_id"]
                matched = True  # keep looping: a later (attack) row may override
        n += matched
    return events, n

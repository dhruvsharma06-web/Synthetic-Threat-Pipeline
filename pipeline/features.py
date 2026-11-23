"""Per-source-IP, time-window features (CONTRACT B3, PRD "Features").

Tumbling windows of 1, 5 and 15 minutes. One feature row per (src_ip, window_end, window).
Excludes event codes and the IP value itself — both leak the label (PRD "Not used").
A window's label is 1 if it holds any attack event, 0 if all its labelled events are
normal, else None (unlabelled → training drops it, test may keep it).
"""
import re

import numpy as np
import pandas as pd

WINDOWS = {"1min": 60, "5min": 300, "15min": 900}
SQL_KW = re.compile(r"\b(select|union|or|and|drop|insert|--|#|sleep|benchmark)\b", re.I)
SHELL_META = re.compile(r"[;&|`$><]|\$\(")
ENCODED = re.compile(r"%[0-9a-fA-F]{2}")


def _payload_stats(texts):
    joined = " ".join(t for t in texts if t)
    return pd.Series({
        "payload_len_mean": np.mean([len(t) for t in texts]) if texts else 0.0,
        "payload_special": sum(not c.isalnum() and not c.isspace() for c in joined),
        "payload_sql_kw": len(SQL_KW.findall(joined)),
        "payload_traversal": joined.count("../"),
        "payload_shell_meta": len(SHELL_META.findall(joined)),
        "payload_encoded": len(ENCODED.findall(joined)),
    })


def _window_features(g):
    ts = g["ts"].sort_values()
    gaps = ts.diff().dt.total_seconds().dropna()
    ev = g["event"]
    n = len(g)
    failed = (ev == "login_fail").sum()
    logins = failed + (ev == "login_ok").sum()
    codes = pd.to_numeric(g["status_code"], errors="coerce")
    http = codes.notna().sum()
    texts = [str(x) for x in pd.concat([g["payload"], g["username"]]).dropna().tolist()]
    feats = {
        # volume
        "events": n,
        "events_per_min": n / (g.attrs["win_s"] / 60),
        "distinct_usernames": g["username"].nunique(dropna=True),
        "distinct_payloads": g["payload"].nunique(dropna=True),
        # outcome
        "failed_login_ratio": failed / logins if logins else 0.0,
        "http_error_ratio": ((codes >= 400).sum() / http) if http else 0.0,
        "success_after_fail": int(((ev == "login_ok").any()) and failed > 0),
        # timing
        "iat_mean": gaps.mean() if len(gaps) else 0.0,
        "iat_std": gaps.std(ddof=0) if len(gaps) else 0.0,
        "burstiness": (gaps.std(ddof=0) / gaps.mean()) if len(gaps) and gaps.mean() else 0.0,
        # breadth
        "distinct_services": g["service"].nunique(),
        "distinct_ports": g["dst_port"].nunique(dropna=True),
    }
    feats.update(_payload_stats(texts).to_dict())
    lab = g["label"].dropna()
    feats["label"] = 1 if (lab == 1).any() else (0 if len(lab) else None)
    at = g.loc[g["label"] == 1, "attack_type"].dropna()
    feats["attack_type"] = at.mode().iat[0] if len(at) else None
    return feats


def build(events):
    """events: list[dict] (post label_join) -> DataFrame of feature rows."""
    df = pd.DataFrame(events)
    if df.empty:
        return df
    df["ts"] = pd.to_datetime(df["ts"], utc=True, format="ISO8601")
    out = []
    for name, win_s in WINDOWS.items():
        g = df.copy()
        g["window_end"] = g["ts"].dt.ceil(name)
        for (ip, wend), grp in g.groupby(["src_ip", "window_end"]):
            grp.attrs["win_s"] = win_s
            row = _window_features(grp)
            row.update(src_ip=ip, window_end=wend.isoformat(), window=name)
            out.append(row)
    return pd.DataFrame(out)

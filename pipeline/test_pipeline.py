"""Self-check for label_join + features (no containers)."""

from pipeline import features, label_join
from pipeline.parsers import base


def _ev(ts, ip, event="login_fail", **kw):
    kw.setdefault("service", "ssh")
    kw.setdefault("source", "cowrie")
    return base.event(ts=ts, src_ip=ip, event=event, **kw)


def test_join_labels_by_ip_and_window(tmp_path):
    (tmp_path / "b.csv").write_text(
        "bot_id,label,attack_type,t_start,t_end,src_ip\n"
        "ssh-1,1,ssh_brute,2026-01-01T00:00:00Z,2026-01-01T00:10:00Z,10.0.0.5\n")
    evs = [_ev("2026-01-01T00:05:00Z", "10.0.0.5"),   # inside window -> labelled 1
           _ev("2026-01-01T01:00:00Z", "10.0.0.5"),   # outside window -> stays None
           _ev("2026-01-01T00:05:00Z", "10.0.0.9")]   # other IP -> stays None
    evs, n = label_join.join(evs, str(tmp_path))
    assert n == 1
    assert evs[0]["label"] == 1 and evs[0]["attack_type"] == "ssh_brute" and evs[0]["bot_id"] == "ssh-1"
    assert evs[1]["label"] is None and evs[2]["label"] is None  # never defaulted to 0


def test_attack_label_wins_overlap(tmp_path):
    (tmp_path / "l.csv").write_text(
        "bot_id,label,attack_type,t_start,t_end,src_ip\n"
        "n,0,,2026-01-01T00:00:00Z,2026-01-01T00:10:00Z,10.0.0.5\n"
        "a,1,sqli,2026-01-01T00:00:00Z,2026-01-01T00:10:00Z,10.0.0.5\n")
    evs, _ = label_join.join([_ev("2026-01-01T00:05:00Z", "10.0.0.5")], str(tmp_path))
    assert evs[0]["label"] == 1 and evs[0]["attack_type"] == "sqli"


def test_features_windows_and_payload_signals():
    evs = []
    for i in range(6):
        e = _ev(f"2026-01-01T00:0{i}:00Z", "10.0.0.5",
                payload="id=1' OR '1'='1 ../../etc/passwd; whoami", event="request",
                service="http", status_code=500, dst_port=80)
        e["label"], e["attack_type"] = 1, "sqli"  # set by the join in the real pipeline
        evs.append(e)
    df = features.build(evs)
    assert set(df["window"]) == {"1min", "5min", "15min"}
    row = df[df["window"] == "15min"].iloc[0]
    assert row["label"] == 1 and row["attack_type"] == "sqli"
    assert row["payload_sql_kw"] > 0 and row["payload_traversal"] > 0 and row["payload_shell_meta"] > 0
    # IP value and raw event/status codes must not leak in as features (PRD "Not used")
    keys = {"src_ip", "window_end", "window", "label", "attack_type"}
    feature_cols = [c for c in df.columns if c not in keys]
    assert not any("status" in c or c == "src_ip" or c == "dst_port" for c in feature_cols)


def test_features_empty():
    assert features.build([]).empty

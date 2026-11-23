"""Self-check for train.py — runs on a synthetic feature table, no containers, no real models kept."""
import numpy as np
import pandas as pd

from pipeline import train


def _table(n=60, seed=0):
    """Separable toy data: attacks = high failed-login + SQL payload, normals = quiet."""
    rng = np.random.default_rng(seed)
    rows = []
    base = pd.Timestamp("2026-01-01T00:00:00Z")
    feat = ["events", "events_per_min", "distinct_usernames", "distinct_payloads",
            "failed_login_ratio", "http_error_ratio", "success_after_fail",
            "iat_mean", "iat_std", "burstiness", "distinct_services", "distinct_ports",
            "payload_len_mean", "payload_special", "payload_sql_kw", "payload_traversal",
            "payload_shell_meta", "payload_encoded"]
    for i in range(n):
        attack = i % 2 == 0
        row = {c: float(rng.random()) for c in feat}
        row["failed_login_ratio"] = rng.uniform(0.85, 1.0) if attack else rng.uniform(0, 0.2)
        row["events"] = rng.uniform(8, 20) if attack else rng.uniform(1, 4)
        row["payload_sql_kw"] = rng.integers(1, 5) if attack else 0
        row.update(src_ip=f"10.0.0.{i}", window_end=(base + pd.Timedelta(minutes=i)).isoformat(),
                   window="1min", label=1 if attack else 0, attack_type="sqli" if attack else None)
        rows.append(row)
    return pd.DataFrame(rows)


def test_trains_and_beats_nothing_crashes(tmp_path):
    df = _table()
    df.to_parquet(tmp_path / "features.parquet", index=False)
    card = train.build(data_dir=str(tmp_path), model_dir=str(tmp_path / "m"))
    assert card["status"] == "trained"
    assert card["best_model"] in train._models()
    # on separable data the learned model must clear the hand-written rules floor
    assert card["beats_rules_baseline"]
    assert "top_features" in card["explainability"]
    assert (tmp_path / "m" / "model.joblib").exists()
    assert (tmp_path / "m" / "model_card.json").exists()


def test_time_split_keeps_order():
    df = _table(n=10).sample(frac=1, random_state=1)  # shuffle input
    tr, te = train.time_split(df)
    assert tr["window_end"].max() <= te["window_end"].min()  # train is strictly older
    assert len(te) == 3  # 30% of 10


def test_one_class_degrades_gracefully(tmp_path):
    df = _table(n=20)
    df["label"] = 0  # no attacks labelled yet
    df.to_parquet(tmp_path / "features.parquet", index=False)
    card = train.build(data_dir=str(tmp_path), model_dir=str(tmp_path / "m"))
    assert card["status"] == "insufficient_labelled_data"
    assert "isolation_forest" in card["shipped_model"]
    assert (tmp_path / "m" / "model.joblib").exists()

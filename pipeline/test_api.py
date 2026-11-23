"""Self-check for the scoring API (TestClient, no server, no Loki)."""
import os

from fastapi.testclient import TestClient

from pipeline import scorer, train
from pipeline.parsers import base
from pipeline.test_train import _table


def _client(tmp_path):
    md = tmp_path / "m"
    train.build(data_dir=str(_dataset(tmp_path)), model_dir=str(md))  # writes model.joblib + card
    os.environ["MODEL_DIR"] = str(md)
    scorer._CACHE.clear()
    from pipeline import api
    return TestClient(api.app)


def _dataset(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    _table().to_parquet(d / "features.parquet", index=False)
    return d


def _events():
    # a failed-login burst from one IP — the kind of window the detector should rate highly
    evs = []
    for i in range(8):
        evs.append(base.event(ts=f"2026-01-01T00:0{i}:00Z", source="cowrie", service="ssh",
                              src_ip="9.9.9.9", dst_port=2222, event="login_fail", username="root"))
    return evs


def test_health_and_model(tmp_path):
    c = _client(tmp_path)
    h = c.get("/health").json()
    assert h["status"] == "ok" and h["model_loaded"] is True
    assert c.get("/model").json()["status"] == "trained"


def test_score_shapes_and_alerts_feed(tmp_path):
    c = _client(tmp_path)
    from pipeline import api
    api.RECENT.clear()  # order-independent: only this score's flags should show
    r = c.post("/score", json={"events": _events()}).json()
    assert r["scored"] >= 1
    keys = {"src_ip", "window", "window_end", "prediction", "score", "severity", "model_kind"}
    assert keys <= set(r["alerts"][0])
    assert all(a["prediction"] in (0, 1) for a in r["alerts"])
    # /alerts returns exactly the flagged windows this score produced
    feed = c.get("/alerts").json()["alerts"]
    assert len(feed) == r["flagged"]
    assert all(a["severity"] != "none" for a in feed)


def test_no_model_is_honest(tmp_path):
    os.environ["MODEL_DIR"] = str(tmp_path / "empty")
    scorer._CACHE.clear()
    from pipeline import api
    c = TestClient(api.app)
    assert c.get("/health").json()["model_loaded"] is False
    assert c.post("/score", json={"events": _events()}).json()["scored"] == 0

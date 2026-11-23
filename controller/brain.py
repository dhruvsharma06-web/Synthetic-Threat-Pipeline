"""Live threat worker: tail Loki -> parse into events -> score with the real model.

Replaces the v1 keyword matcher. It reuses the W3 parsers (so Loki lines become the
same common-schema events the dataset is built from) and the W4 model via the scoring
API, instead of guessing from substrings. Needs Loki and the scorer API running.

Run: python -m controller.brain   (env: LOKI_URL, API_URL, POLL_SECONDS)
"""
import os
import sys
import tempfile
import time

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pipeline.parsers import apache, cowrie, flask, vsftpd  # noqa: E402

LOKI_URL = os.getenv("LOKI_URL", "http://localhost:3100")
API_URL = os.getenv("API_URL", "http://localhost:8000")
POLL_SECONDS = int(os.getenv("POLL_SECONDS", "10"))

# job label -> (parser, filename the parser expects). sar2html/dvwa are Apache-format.
_PARSERS = {
    "cowrie": (cowrie.parse, "cowrie.json"),
    "vsftpd": (vsftpd.parse, "vsftpd.log"),
    "dvwa": (lambda p: apache.parse(p, source="apache"), "access.log"),
    "sar2html": (lambda p: apache.parse(p, source="apache"), "access.log"),
    "victim": (flask.parse, "flask.log"),
}


def events_from_loki_streams(streams):
    """Loki query_range result -> events, by writing each job's lines through its parser.

    Pure (no network): unit-testable with a hand-built streams list."""
    by_job = {}
    for s in streams:
        job = (s.get("stream", {}).get("job") or "").lower()
        key = next((k for k in _PARSERS if k in job), None)
        if key:
            by_job.setdefault(key, []).extend(v[1] for v in s.get("values", []))
    events = []
    with tempfile.TemporaryDirectory() as tmp:
        for key, lines in by_job.items():
            parse, fname = _PARSERS[key]
            path = os.path.join(tmp, fname)
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            events += parse(path)
    return events


def query_loki():
    now = int(time.time() * 1e9)
    start = now - POLL_SECONDS * 2 * int(1e9)
    try:
        r = requests.get(f"{LOKI_URL}/loki/api/v1/query_range", timeout=10, params={
            "query": '{job=~"cowrie|dvwa|vsftpd|sar2html|victim"}',
            "start": str(start), "end": str(now), "limit": 2000,
        })
        return r.json().get("data", {}).get("result", [])
    except requests.RequestException as e:
        print(f"[warn] Loki unreachable: {e}")
        return []


def tick():
    events = events_from_loki_streams(query_loki())
    if not events:
        return 0
    try:
        r = requests.post(f"{API_URL}/score", json={"events": events}, timeout=30)
        flagged = r.json().get("flagged", 0)
        if flagged:
            print(f"[ALERT] {flagged} window(s) flagged across {len(events)} events")
        return flagged
    except requests.RequestException as e:
        print(f"[warn] scorer API unreachable: {e}")
        return 0


if __name__ == "__main__":
    print(f"Threat worker: Loki={LOKI_URL} API={API_URL} every {POLL_SECONDS}s")
    while True:
        tick()
        time.sleep(POLL_SECONDS)

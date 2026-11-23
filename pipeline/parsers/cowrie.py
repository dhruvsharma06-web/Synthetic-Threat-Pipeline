"""Cowrie (SSH honeypot) JSON log parser."""
import json
from datetime import datetime

from .base import event, to_utc_iso

_MAP = {
    "cowrie.login.failed": "login_fail",
    "cowrie.login.success": "login_ok",
    "cowrie.command.input": "command",
    "cowrie.session.file_download": "download",
}


def _ts(s):
    return to_utc_iso(datetime.fromisoformat(s.replace("Z", "+00:00")))


def parse(path):
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                log = json.loads(line)
                if not isinstance(log, dict):
                    continue
                ev = _MAP.get(log.get("eventid"))
                if ev is None:
                    continue
                if ev == "command":
                    payload = log.get("input")
                elif ev == "download":
                    payload = log.get("url") or log.get("outfile")
                else:
                    payload = None
                rows.append(event(
                    ts=_ts(log["timestamp"]), source="cowrie", service="ssh",
                    src_ip=log.get("src_ip"), dst_port=2222, event=ev,
                    username=log.get("username"), payload=payload,
                ))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
    return rows

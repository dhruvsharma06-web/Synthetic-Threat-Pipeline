"""Victim Flask app log parser.

Format: "%(asctime)s - %(levelname)s - %(message)s", e.g.
2026-04-22 20:45:10,123 - WARNING - Failed login attempt - User: admin - IP: 1.2.3.4
"""
import re
from datetime import datetime

from .base import event, to_utc_iso

_RE = re.compile(
    r'^(?P<time>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[,.]\d+)?)\s+-\s+\w+\s+-\s+'
    r'Failed login attempt\s+-\s+User:\s*(?P<user>.*?)\s+-\s+IP:\s*(?P<ip>\S+)'
)


def parse(path):
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = _RE.search(line.strip())
            if not m:
                continue
            t = m.group("time").replace("T", " ").replace(",", ".")
            fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in t else "%Y-%m-%d %H:%M:%S"
            try:
                dt = datetime.strptime(t, fmt)
            except ValueError:
                continue
            rows.append(event(
                ts=to_utc_iso(dt), source="flask", service="http",
                src_ip=m.group("ip"), dst_port=5000, event="login_fail",
                username=m.group("user"),
            ))
    return rows

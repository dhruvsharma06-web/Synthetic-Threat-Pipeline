"""Apache/Nginx combined access-log parser (DVWA, sar2html)."""
import re
import urllib.parse
from datetime import datetime

from .base import event, to_utc_iso

_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<req>(?:[^"\\]|\\.)*)"\s+(?P<status>\d{3}|-)'
)


def parse(path, source="apache"):
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = _RE.search(line)
            if not m:
                continue
            try:
                dt = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                continue
            user = m.group("user")
            status = m.group("status")
            rows.append(event(
                ts=to_utc_iso(dt), source=source, service="http",
                src_ip=m.group("ip"), dst_port=80, event="request",
                username=None if user == "-" else urllib.parse.unquote(user),
                status_code=int(status) if status.isdigit() else None,
                payload=urllib.parse.unquote(m.group("req")),
            ))
    return rows

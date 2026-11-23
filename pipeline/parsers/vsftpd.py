"""vsftpd log parser (vsftpd.log syslog-style lines)."""
import re
from datetime import datetime

from .base import event, to_utc_iso

# Thu Apr 22 20:45:10 2026 [pid 2] [admin] FAIL LOGIN: Client "::ffff:172.18.0.1"
# Thu Apr 22 20:45:10 2026 [pid 2] [admin] OK UPLOAD: Client "1.2.3.4", "/f.txt", 12 bytes, 1.0Kbyte/sec
_RE = re.compile(
    r'(?P<time>[A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\d{4})\s+'
    r'\[pid \d+\]\s+(?:\[(?P<user>[^\]]*)\]\s+)?'
    r'(?P<status>OK|FAIL)\s+(?P<kind>LOGIN|UPLOAD|DOWNLOAD):\s*'
    r'Client\s+"(?:::ffff:)?(?P<ip>[^"]+)"(?P<rest>.*)'
)


def parse(path):
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = _RE.search(line)
            if not m:
                continue
            status, kind = m.group("status"), m.group("kind")
            if kind == "LOGIN":
                ev = "login_ok" if status == "OK" else "login_fail"
            elif status != "OK":
                continue
            else:
                ev = kind.lower()
            try:
                dt = datetime.strptime(re.sub(r"\s+", " ", m.group("time")),
                                       "%a %b %d %H:%M:%S %Y")
            except ValueError:
                continue
            payload = None
            if kind != "LOGIN":
                parts = re.findall(r'"([^"]*)"', m.group("rest"))
                payload = parts[0] if parts else None
            rows.append(event(
                ts=to_utc_iso(dt), source="vsftpd", service="ftp",
                src_ip=m.group("ip"), dst_port=21, event=ev,
                username=m.group("user") or None, payload=payload,
            ))
    return rows

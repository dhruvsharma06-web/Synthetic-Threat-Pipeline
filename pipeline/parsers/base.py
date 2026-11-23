"""Shared event schema helpers for all honeypot parsers."""
from datetime import UTC

SCHEMA_KEYS = [
    "ts", "source", "service", "src_ip", "dst_port", "event", "username",
    "status_code", "payload", "label", "attack_type", "bot_id",
]
EVENTS = ["login_fail", "login_ok", "command", "request", "upload", "download"]
SOURCES = ["cowrie", "vsftpd", "apache", "flask"]
MAX_PAYLOAD = 4096


def event(**kwargs):
    """Return a dict with every schema key; missing keys -> None.

    label/attack_type/bot_id are always None (filled later by a join).
    Payload is truncated to 4096 chars.
    """
    row = {k: kwargs.get(k) for k in SCHEMA_KEYS}
    row["label"] = None
    row["attack_type"] = None
    row["bot_id"] = None
    if row["payload"] is not None:
        row["payload"] = str(row["payload"])[:MAX_PAYLOAD]
    return row


def to_utc_iso(dt):
    """Format a datetime as ISO-8601 UTC (naive datetimes are assumed UTC)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

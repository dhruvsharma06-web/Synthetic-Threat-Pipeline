"""Shared bot runtime: CLI args, pacing, targets and the ground-truth label file (CONTRACT B2).

Each bot module defines ATTACK_TYPE (None for normal bots) and step(ctx), which performs ONE
action (one login try, one request...). run() calls step() at --rate until --duration ends,
then appends one label row covering the whole run.
"""
import argparse
import csv
import os
import random
import socket
import time
from datetime import UTC, datetime

LABEL_FIELDS = ["bot_id", "label", "attack_type", "t_start", "t_end", "src_ip"]

# Service names on the honeynet network; override with env vars when running outside Docker.
TARGETS = {
    "ssh": (os.getenv("SSH_HOST", "cowrie-ssh"), int(os.getenv("SSH_PORT", "2222"))),
    "ftp": (os.getenv("FTP_HOST", "vsftpd-ftp"), int(os.getenv("FTP_PORT", "21"))),
    "dvwa": os.getenv("DVWA_URL", "http://dvwa-web"),
    "sar2html": os.getenv("SAR2HTML_URL", "http://sar2html-web"),
    "victim": os.getenv("VICTIM_URL", "http://victim-app:5000"),
}


class Ctx:
    def __init__(self, args):
        self.args = args
        self.rng = random.Random(args.seed)
        self.targets = TARGETS
        self.timeout = 3


def utc_now():
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def own_ip(host):
    """The IP the honeypots see for this bot (no packet is sent for a UDP connect)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((socket.gethostbyname(host), 9))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def write_label(path, row):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    new = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=LABEL_FIELDS)
        if new:
            w.writeheader()
        w.writerow(row)


def parse_args(argv=None, default_rate=1.0):
    p = argparse.ArgumentParser()
    p.add_argument("--bot-id", required=True)
    p.add_argument("--rate", type=float, default=default_rate, help="actions per second (mean)")
    p.add_argument("--duration", type=float, default=60, help="seconds")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--labels-dir", default=os.getenv("LABELS_DIR", "data/labels"))
    return p.parse_args(argv)


def run(module, argv=None):
    attack_type = getattr(module, "ATTACK_TYPE", None)
    args = parse_args(argv, getattr(module, "DEFAULT_RATE", 1.0))
    ctx = Ctx(args)
    t_start = utc_now()
    end = time.monotonic() + args.duration
    actions = errors = 0
    while time.monotonic() < end:
        try:
            module.step(ctx)
        except Exception:  # honeypots drop and refuse connections; that is expected traffic
            errors += 1
        actions += 1
        # Exponential gaps keep timing irregular, so the model can't learn a fixed bot cadence.
        time.sleep(min(ctx.rng.expovariate(args.rate), max(0.0, end - time.monotonic())))
    row = {
        "bot_id": args.bot_id,
        "label": 0 if attack_type is None else 1,
        "attack_type": attack_type or "",
        "t_start": t_start,
        "t_end": utc_now(),
        "src_ip": own_ip(TARGETS["ssh"][0]),
    }
    write_label(os.path.join(args.labels_dir, f"{args.bot_id}.csv"), row)
    print(f"{args.bot_id}: {actions} actions, {errors} errors, label={row['label']} {row['attack_type']}")
    return row

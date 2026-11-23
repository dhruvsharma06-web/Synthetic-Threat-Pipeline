"""Scenario scheduler: runs mixed normal/attack bot bursts over N hours.

    python -m bots.scheduler --hours 8 --seed 42 --attack-ratio 0.30 --concurrency 4 [--dry-run]
"""
import argparse
import random
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

BOTS_DIR = Path(__file__).resolve().parent
GROUPS = ("attackers", "benign")
MIN_DUR, MAX_DUR = 30, 180


@dataclass(frozen=True)
class PlannedRun:
    index: int
    name: str          # e.g. "attackers.ssh_brute"
    is_attack: bool
    bot_id: str
    start: float       # seconds offset from scheduler start
    duration: int      # seconds
    rate: float        # actions per second
    seed: int


def discover(bots_dir=BOTS_DIR):
    """Return {"attackers": [...], "benign": [...]} of dotted bot names."""
    found = {}
    for group in GROUPS:
        d = Path(bots_dir) / group
        names = []
        if d.is_dir():
            for f in sorted(d.glob("*.py")):
                if f.name.startswith("_") or f.stem == "common":
                    continue
                names.append(f"{group}.{f.stem}")
        found[group] = names
    return found


def plan(hours, seed, attack_ratio, concurrency=4, bots=None):
    """Return a deterministic list of PlannedRun covering ~`hours` of wall time.

    `bots` optionally overrides discovery: {"attackers": [...], "benign": [...]}.
    """
    bots = bots if bots is not None else discover()
    attackers, benign = bots.get("attackers", []), bots.get("benign", [])
    if not attackers and not benign:
        return []
    rng = random.Random(seed)
    budget = hours * 3600.0
    mean_dur = (MIN_DUR + MAX_DUR) / 2
    mean_gap = mean_dur / max(1, concurrency)  # keeps ~concurrency bursts in flight
    runs, t, i = [], 0.0, 0
    while t < budget:
        want_attack = rng.random() < attack_ratio
        pool = attackers if want_attack else benign
        if not pool:  # one group missing: fall back to the other
            pool = attackers or benign
            want_attack = pool is attackers
        name = rng.choice(pool)
        duration = rng.randint(MIN_DUR, MAX_DUR)
        rate = round(rng.uniform(0.5, 3.0), 2)
        run_seed = rng.randrange(2**31)
        runs.append(PlannedRun(i, name, want_attack, f"{name}-{i}-{seed}",
                               round(t, 1), duration, rate, run_seed))
        t += rng.uniform(0.5, 1.5) * mean_gap
        i += 1
    return runs


def launch(run, labels_dir, t0):
    """Wait for the run's start offset, then run the bot subprocess. Never raises."""
    delay = t0 + run.start - time.monotonic()
    if delay > 0:
        time.sleep(delay)
    cmd = [sys.executable, "-m", "bots", run.name, "--bot-id", run.bot_id,
           "--rate", str(run.rate), "--duration", str(run.duration),
           "--seed", str(run.seed), "--labels-dir", str(labels_dir)]
    print(f"[+{time.monotonic() - t0:8.1f}s] launch {run.bot_id} dur={run.duration}s rate={run.rate}", flush=True)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=run.duration + 120)
        ok = proc.returncode == 0
        detail = (proc.stdout if ok else proc.stderr).strip().splitlines()
        detail = detail[-1] if detail else ""
    except Exception as e:  # keep going no matter what
        ok, detail = False, f"{type(e).__name__}: {e}"
    print(f"[+{time.monotonic() - t0:8.1f}s] done   {run.bot_id} {'OK' if ok else 'FAIL'} {detail}", flush=True)
    return ok


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hours", type=float, default=8)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--attack-ratio", type=float, default=0.30)
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--labels-dir", default="data/labels")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)

    runs = plan(args.hours, args.seed, args.attack_ratio, args.concurrency)
    n_attack = sum(r.is_attack for r in runs)
    if args.dry_run:
        for r in runs:
            print(f"{r.start:9.1f}s  {r.name:<28} dur={r.duration:3d}s rate={r.rate} "
                  f"seed={r.seed} {'ATTACK' if r.is_attack else 'normal'}")
        print(f"planned {len(runs)} runs: {len(runs) - n_attack} normal, {n_attack} attack")
        return 0

    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
        results = list(pool.map(lambda r: launch(r, args.labels_dir, t0), runs))
    ok = sum(results)
    print(f"summary: total={len(runs)} normal={len(runs) - n_attack} attack={n_attack} "
          f"succeeded={ok} failed={len(runs) - ok}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

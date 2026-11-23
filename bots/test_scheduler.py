from pathlib import Path

from bots import scheduler

BOTS = Path(scheduler.BOTS_DIR)
FAKE = {"attackers": ["attackers.a1", "attackers.a2"], "benign": ["benign.b1", "benign.b2", "benign.b3"]}


def test_plan_deterministic():
    a = scheduler.plan(2, 42, 0.3, bots=FAKE)
    b = scheduler.plan(2, 42, 0.3, bots=FAKE)
    assert a and a == b
    assert a != scheduler.plan(2, 43, 0.3, bots=FAKE)


def test_plan_deterministic_real_discovery():
    assert scheduler.plan(1, 7, 0.3) == scheduler.plan(1, 7, 0.3)


def test_attack_fraction_close_to_ratio():
    runs = scheduler.plan(200, 1, 0.30, bots=FAKE)
    assert len(runs) > 1000
    frac = sum(r.is_attack for r in runs) / len(runs)
    assert abs(frac - 0.30) < 0.05


def test_plan_fills_budget_and_ids_unique():
    runs = scheduler.plan(8, 42, 0.3, bots=FAKE)
    assert runs[0].start == 0
    assert all(x.start <= y.start for x, y in zip(runs, runs[1:]))
    assert runs[-1].start < 8 * 3600
    assert runs[-1].start > 8 * 3600 * 0.95
    assert len({r.bot_id for r in runs}) == len(runs)
    assert all(scheduler.MIN_DUR <= r.duration <= scheduler.MAX_DUR for r in runs)


def test_planned_bots_exist_on_disk():
    runs = scheduler.plan(4, 42, 0.3)  # real discovery
    for r in runs:
        group, mod = r.name.split(".")
        assert group in ("attackers", "benign")
        assert (BOTS / group / f"{mod}.py").is_file()
        assert not mod.startswith("_") and mod != "common"
        assert r.is_attack == (group == "attackers")


def test_discover_ignores_private_and_common():
    names = [n for g in scheduler.discover().values() for n in g]
    assert all(not n.split(".")[1].startswith("_") and n.split(".")[1] != "common" for n in names)

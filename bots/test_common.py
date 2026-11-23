"""Self-check for the bot runtime: python -m pytest bots (no containers needed)."""
import csv
import types

from bots.common import LABEL_FIELDS, run


def test_run_writes_one_label_row(tmp_path):
    calls = []
    bot = types.SimpleNamespace(ATTACK_TYPE="ssh_brute", DEFAULT_RATE=50.0,
                                step=lambda ctx: calls.append(ctx.rng.random()))
    row = run(bot, ["--bot-id", "t1", "--duration", "0.2", "--labels-dir", str(tmp_path)])
    rows = list(csv.DictReader(open(tmp_path / "t1.csv")))
    assert list(rows[0]) == LABEL_FIELDS and len(rows) == 1
    assert row["label"] == 1 and rows[0]["attack_type"] == "ssh_brute"
    assert rows[0]["t_start"] <= rows[0]["t_end"] and calls


def test_normal_bot_labels_zero_and_survives_failures(tmp_path):
    def boom(ctx):
        raise ConnectionError("refused")
    bot = types.SimpleNamespace(ATTACK_TYPE=None, DEFAULT_RATE=50.0, step=boom)
    row = run(bot, ["--bot-id", "n1", "--duration", "0.2", "--labels-dir", str(tmp_path)])
    rows = list(csv.DictReader(open(tmp_path / "n1.csv")))
    assert row["label"] == 0 and rows[0]["attack_type"] == ""


def test_seed_is_deterministic(tmp_path):
    seen = []
    bot = types.SimpleNamespace(ATTACK_TYPE=None, DEFAULT_RATE=50.0,
                                step=lambda ctx: seen.append(ctx.rng.random()))
    run(bot, ["--bot-id", "a", "--duration", "0.2", "--seed", "7", "--labels-dir", str(tmp_path)])
    first = seen[0]
    seen.clear()
    run(bot, ["--bot-id", "b", "--duration", "0.2", "--seed", "7", "--labels-dir", str(tmp_path)])
    assert seen[0] == first

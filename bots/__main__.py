"""Run one bot: python -m bots <attackers|benign>.<name> --bot-id ID [--rate R --duration S --seed N]"""
import importlib
import sys

from bots.common import run

if len(sys.argv) < 2 or sys.argv[1].startswith("-"):
    sys.exit(__doc__)
run(importlib.import_module(f"bots.{sys.argv[1]}"), sys.argv[2:])

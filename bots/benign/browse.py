"""Normal user: one ordinary browser-style GET to a benign page on the DVWA or victim web app."""
import requests

ATTACK_TYPE = None
DEFAULT_RATE = 0.4

PAGES = ["/", "/index.php", "/login.php"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


def step(ctx):
    base = ctx.targets[ctx.rng.choice(["dvwa", "victim"])]
    headers = {"User-Agent": ctx.rng.choice(USER_AGENTS), "Accept": "text/html,*/*;q=0.8"}
    requests.get(base + ctx.rng.choice(PAGES), headers=headers, timeout=ctx.timeout)

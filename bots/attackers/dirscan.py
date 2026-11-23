"""Directory and file probing against DVWA: one GET for a common sensitive path per step."""
import requests

ATTACK_TYPE = "dirscan"
DEFAULT_RATE = 2.0

PATHS = ["/admin", "/.git/config", "/.env", "/phpmyadmin", "/config.php", "/backup.zip",
         "/administrator", "/server-status", "/wp-login.php", "/.svn/entries", "/db.sql", "/web.config"]


def step(ctx):
    base = ctx.targets["dvwa"]
    requests.get(base + ctx.rng.choice(PATHS), allow_redirects=False, timeout=ctx.timeout)

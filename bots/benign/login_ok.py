"""Normal user: one successful SSH login to Cowrie with valid-looking credentials, then close."""
import paramiko

ATTACK_TYPE = None
DEFAULT_RATE = 0.3

ACCOUNTS = [("ubuntu", "ubuntu"), ("admin", "admin"), ("pi", "raspberry"), ("user", "user123")]


def step(ctx):
    host, port = ctx.targets["ssh"]
    username, password = ctx.rng.choice(ACCOUNTS)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password,
                       timeout=ctx.timeout, allow_agent=False, look_for_keys=False,
                       banner_timeout=ctx.timeout)
    finally:
        client.close()

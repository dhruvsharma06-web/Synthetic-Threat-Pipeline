"""Normal user who mistypes: about 1 in 4 logins uses a wrong password, otherwise a correct one.

A typo is not an attack, so ATTACK_TYPE stays None.
"""
import ftplib

import paramiko

ATTACK_TYPE = None
DEFAULT_RATE = 0.3

SSH_ACCOUNTS = [("ubuntu", "ubuntu"), ("admin", "admin"), ("pi", "raspberry")]
FTP_ACCOUNTS = [("ftpuser", "ftpuser123"), ("alice", "alice2024")]


def _ssh(ctx, password_ok):
    host, port = ctx.targets["ssh"]
    username, password = ctx.rng.choice(SSH_ACCOUNTS)
    if not password_ok:
        password = password + "x"  # a single mistyped character
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password,
                       timeout=ctx.timeout, allow_agent=False, look_for_keys=False,
                       banner_timeout=ctx.timeout)
    except paramiko.AuthenticationException:
        pass  # the typo is the expected outcome here
    finally:
        client.close()


def _ftp(ctx, password_ok):
    host, port = ctx.targets["ftp"]
    user, password = ctx.rng.choice(FTP_ACCOUNTS)
    if not password_ok:
        password = password + "x"
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=ctx.timeout)
        ftp.login(user, password)
        ftp.quit()
    except ftplib.error_perm:
        ftp.close()  # wrong password: server answers 530, which is expected


def step(ctx):
    password_ok = ctx.rng.random() >= 0.25
    if ctx.rng.random() < 0.5:
        _ssh(ctx, password_ok)
    else:
        _ftp(ctx, password_ok)

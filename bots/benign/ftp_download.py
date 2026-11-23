"""Normal user: log in to vsftpd, list the directory, sometimes download one file, then quit."""
import ftplib
import io

ATTACK_TYPE = None
DEFAULT_RATE = 0.2

ACCOUNTS = [("ftpuser", "ftpuser123"), ("alice", "alice2024"), ("bob", "bob-files")]
FILES = ["readme.txt", "report.txt", "notes.txt"]


def step(ctx):
    host, port = ctx.targets["ftp"]
    user, password = ctx.rng.choice(ACCOUNTS)
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=ctx.timeout)
        ftp.login(user, password)
        listing = []
        ftp.retrlines("LIST", listing.append)
        if ctx.rng.random() < 0.5:
            ftp.retrbinary("RETR " + ctx.rng.choice(FILES), io.BytesIO().write)
    finally:
        try:
            ftp.quit()
        except ftplib.all_errors:
            ftp.close()

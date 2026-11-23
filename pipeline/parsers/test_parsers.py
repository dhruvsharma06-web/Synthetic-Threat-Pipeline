import glob
import os

from pipeline.parsers import apache, base, cowrie, flask, vsftpd


def check(rows, source, service, ev=None):
    assert rows
    for r in rows:
        assert set(r) == set(base.SCHEMA_KEYS)
        assert r["source"] == source and r["service"] == service
        assert r["event"] in base.EVENTS
        if ev:
            assert r["event"] == ev
        assert r["label"] is None and r["attack_type"] is None and r["bot_id"] is None
        assert r["ts"].endswith("Z")


def write(tmp_path, text):
    p = tmp_path / "log.txt"
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_base_event():
    e = base.event(src_ip="1.1.1.1", payload="x" * 5000, label="bad")
    assert set(e) == set(base.SCHEMA_KEYS)
    assert e["label"] is None and len(e["payload"]) == 4096


def test_cowrie(tmp_path):
    p = write(tmp_path, "\n".join([
        '{"eventid":"cowrie.login.failed","src_ip":"1.2.3.4","username":"root","password":"x","timestamp":"2026-04-22T20:02:08.808273Z"}',
        '{"eventid":"cowrie.login.success","src_ip":"1.2.3.4","username":"root","timestamp":"2026-04-22T20:02:09.000000Z"}',
        '{"eventid":"cowrie.command.input","src_ip":"1.2.3.4","input":"ls -la","timestamp":"2026-04-22T20:02:10.000000Z"}',
        '{"eventid":"cowrie.session.file_download","src_ip":"1.2.3.4","url":"http://e/x.sh","timestamp":"2026-04-22T20:02:11.000000Z"}',
        '{"eventid":"cowrie.session.connect","src_ip":"1.2.3.4","timestamp":"2026-04-22T20:02:12.000000Z"}',
        'not json {{{',
    ]))
    rows = cowrie.parse(p)
    check(rows, "cowrie", "ssh")
    assert [r["event"] for r in rows] == ["login_fail", "login_ok", "command", "download"]
    assert rows[2]["payload"] == "ls -la" and rows[0]["dst_port"] == 2222
    assert rows[0]["ts"] == "2026-04-22T20:02:08.808Z"


def test_cowrie_real_logs():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    files = glob.glob(os.path.join(root, "logs", "cowrie", "cowrie.json.*"))
    if not files:
        import pytest
        pytest.skip("no real cowrie logs")
    total = []
    for f in files:
        total += cowrie.parse(f)
    assert len(total) > 0
    check(total, "cowrie", "ssh")


def test_vsftpd(tmp_path):
    p = write(tmp_path, "\n".join([
        'Thu Apr 22 20:45:10 2026 [pid 2] [admin] FAIL LOGIN: Client "::ffff:172.18.0.1"',
        'Thu Apr 22 20:45:11 2026 [pid 2] [admin] OK LOGIN: Client "::ffff:172.18.0.1"',
        'Thu Apr 22 20:45:12 2026 [pid 3] [admin] OK UPLOAD: Client "::ffff:172.18.0.1", "/a.txt", 12 bytes, 1.00Kbyte/sec',
        'Thu Apr 22 20:45:13 2026 [pid 3] [admin] OK DOWNLOAD: Client "::ffff:172.18.0.1", "/b.txt", 5 bytes, 1.00Kbyte/sec',
        'garbage line',
    ]))
    rows = vsftpd.parse(p)
    check(rows, "vsftpd", "ftp")
    assert [r["event"] for r in rows] == ["login_fail", "login_ok", "upload", "download"]
    assert rows[0]["src_ip"] == "172.18.0.1" and rows[0]["username"] == "admin"
    assert rows[2]["payload"] == "/a.txt" and rows[0]["dst_port"] == 21


def test_apache(tmp_path):
    p = write(tmp_path,
        '172.18.0.1 - - [22/Apr/2026:20:45:10 +0000] "GET /login.php?u=a%27%20OR%201=1 HTTP/1.1" 302 345 "-" "curl/8"\n'
        'bad line\n')
    rows = apache.parse(p)
    check(rows, "apache", "http", "request")
    assert rows[0]["status_code"] == 302 and rows[0]["dst_port"] == 80
    assert rows[0]["payload"].startswith("GET /login.php?u=a' OR 1=1")
    assert apache.parse(p, source="dvwa")[0]["source"] == "dvwa"


def test_flask(tmp_path):
    p = write(tmp_path,
        '2026-04-22 20:45:10,123 - WARNING - Failed login attempt - User: admin - IP: 10.0.0.5\n'
        '2026-04-22 20:45:11,000 - INFO - something else\n')
    rows = flask.parse(p)
    check(rows, "flask", "http", "login_fail")
    assert len(rows) == 1 and rows[0]["username"] == "admin"
    assert rows[0]["src_ip"] == "10.0.0.5" and rows[0]["dst_port"] == 5000

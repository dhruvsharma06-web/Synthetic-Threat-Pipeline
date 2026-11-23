"""Self-check for the Loki->events transform (no network, no Loki)."""
from controller import brain


def _stream(job, lines):
    return {"stream": {"job": job}, "values": [[str(i), ln] for i, ln in enumerate(lines)]}


def test_parses_mixed_streams_by_job():
    streams = [
        _stream("cowrie", [
            '{"eventid":"cowrie.login.failed","src_ip":"1.2.3.4","username":"root","timestamp":"2026-04-22T20:02:08Z"}',
            '{"eventid":"cowrie.command.input","src_ip":"1.2.3.4","input":"whoami","timestamp":"2026-04-22T20:02:09Z"}',
        ]),
        _stream("vsftpd", ['Thu Apr 22 20:45:10 2026 [pid 2] [admin] FAIL LOGIN: Client "::ffff:5.6.7.8"']),
        _stream("something-else", ["ignored line"]),  # no parser -> dropped
    ]
    events = brain.events_from_loki_streams(streams)
    sources = sorted({e["source"] for e in events})
    assert sources == ["cowrie", "vsftpd"]
    assert any(e["event"] == "command" and e["payload"] == "whoami" for e in events)
    assert any(e["source"] == "vsftpd" and e["event"] == "login_fail" for e in events)


def test_empty_streams():
    assert brain.events_from_loki_streams([]) == []

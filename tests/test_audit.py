import json

from app.audit.log import AuditEvent, AuditLog


def ev(event="token_issued", outcome="success", **kw):
    return AuditEvent(event=event, outcome=outcome, **kw)


def test_recent_returns_newest_first():
    log = AuditLog()
    log.record(ev(subject="a"))
    log.record(ev(subject="b"))
    assert [e.subject for e in log.recent()] == ["b", "a"]


def test_recent_respects_limit():
    log = AuditLog()
    for i in range(5):
        log.record(ev(subject=str(i)))
    assert [e.subject for e in log.recent(limit=2)] == ["4", "3"]


def test_recent_can_filter_by_outcome():
    log = AuditLog()
    log.record(ev(outcome="success"))
    log.record(ev(event="token_denied", outcome="blocked"))
    blocked = log.recent(outcome="blocked")
    assert len(blocked) == 1 and blocked[0].event == "token_denied"


def test_buffer_is_bounded():
    log = AuditLog(max_events=3)
    for i in range(10):
        log.record(ev(subject=str(i)))
    assert [e.subject for e in log.recent()] == ["9", "8", "7"]


def test_counts_group_by_event_and_outcome():
    log = AuditLog()
    log.record(ev())
    log.record(ev())
    log.record(ev(event="token_denied", outcome="blocked"))
    assert log.counts() == {"token_issued:success": 2, "token_denied:blocked": 1}


def test_file_sink_writes_json_lines(tmp_path):
    path = tmp_path / "audit.log"
    log = AuditLog(path=str(path))
    log.record(ev(subject="did:key:zTest", ip="203.0.113.10", detail={"score": 20}))
    row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert row["event"] == "token_issued"
    assert row["detail"] == {"score": 20}
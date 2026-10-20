from datetime import datetime

from app.policy.engine import PolicyConfig, RiskSignals, evaluate

NOON = datetime(2026, 10, 20, 12, 0)
NIGHT = datetime(2026, 10, 20, 3, 0)


def signals(**kw):
    base = dict(ip="203.0.113.10", known_device=True, user_verified=True, when=NOON)
    base.update(kw)
    return RiskSignals(**base)


def test_clean_attempt_is_allowed():
    d = evaluate(signals())
    assert d.allowed and d.score == 0 and d.reasons == ()


def test_blocked_network_is_denied():
    cfg = PolicyConfig(blocked_networks=("203.0.113.0/24",))
    d = evaluate(signals(), cfg)
    assert not d.allowed and "blocked_ip" in d.reasons


def test_ip_outside_blocked_network_is_allowed():
    cfg = PolicyConfig(blocked_networks=("198.51.100.0/24",))
    assert evaluate(signals(), cfg).allowed


def test_invalid_ip_adds_risk_but_alone_is_allowed():
    d = evaluate(signals(ip="not-an-ip"))
    assert d.score == 50 and d.allowed and "invalid_ip" in d.reasons


def test_off_hours_alone_is_allowed():
    d = evaluate(signals(when=NIGHT))
    assert d.allowed and d.score == 20 and d.reasons == ("off_hours",)


def test_unknown_device_and_no_verification_hits_threshold_and_is_denied():
    d = evaluate(signals(known_device=False, user_verified=False))
    assert d.score == 70 and not d.allowed


def test_signals_accumulate():
    d = evaluate(signals(known_device=False, when=NIGHT))
    assert d.score == 50 and d.allowed
    assert set(d.reasons) == {"unknown_device", "off_hours"}


def test_ipv6_blocklist():
    cfg = PolicyConfig(blocked_networks=("2001:db8::/32",))
    d = evaluate(signals(ip="2001:db8::1"), cfg)
    assert not d.allowed


def test_custom_threshold():
    cfg = PolicyConfig(deny_threshold=20)
    assert not evaluate(signals(when=NIGHT), cfg).allowed
"""Zero-trust policy engine.

Evaluates continuous risk signals before the IdP issues tokens.
Each signal adds to a risk score; a score at or above the deny
threshold blocks issuance. Every decision carries its reasons so it
can be audited and shown on the admin dashboard.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class RiskSignals:
    ip: str
    known_device: bool
    user_verified: bool  # WebAuthn user verification (PIN / biometric)
    when: datetime       # local time of the attempt


@dataclass(frozen=True)
class PolicyConfig:
    deny_threshold: int = 70
    blocked_networks: tuple[str, ...] = ()
    allowed_hours: tuple[int, int] = (6, 22)  # [start, end) in local time
    w_blocked_ip: int = 100
    w_invalid_ip: int = 50
    w_unknown_device: int = 30
    w_no_user_verification: int = 40
    w_off_hours: int = 20


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    score: int
    reasons: tuple[str, ...]


def _ip_in_blocklist(ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
                     networks: tuple[str, ...]) -> bool:
    for net in networks:
        if ip in ipaddress.ip_network(net, strict=False):
            return True
    return False


def evaluate(signals: RiskSignals, config: PolicyConfig | None = None) -> PolicyDecision:
    cfg = config or PolicyConfig()
    score = 0
    reasons: list[str] = []

    try:
        ip = ipaddress.ip_address(signals.ip)
    except ValueError:
        score += cfg.w_invalid_ip
        reasons.append("invalid_ip")
    else:
        if _ip_in_blocklist(ip, cfg.blocked_networks):
            score += cfg.w_blocked_ip
            reasons.append("blocked_ip")

    if not signals.known_device:
        score += cfg.w_unknown_device
        reasons.append("unknown_device")

    if not signals.user_verified:
        score += cfg.w_no_user_verification
        reasons.append("no_user_verification")

    start, end = cfg.allowed_hours
    if not (start <= signals.when.hour < end):
        score += cfg.w_off_hours
        reasons.append("off_hours")

    return PolicyDecision(
        allowed=score < cfg.deny_threshold,
        score=score,
        reasons=tuple(reasons),
    )
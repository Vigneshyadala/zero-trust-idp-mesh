"""Bridge between FastAPI requests and the policy engine.

Settings come from environment variables so they can change without code:
  IDP_BLOCKED_NETWORKS  comma-separated CIDRs, e.g. "203.0.113.0/24,10.9.0.0/16"
  IDP_ALLOWED_HOURS     "start-end" local hours, default "6-22"
  IDP_DENY_THRESHOLD    risk score that blocks issuance, default 70
"""
from __future__ import annotations

import logging
import os
from datetime import datetime

from .engine import PolicyConfig, PolicyDecision, RiskSignals, evaluate

log = logging.getLogger("idp.policy")


def load_config() -> PolicyConfig:
    blocked = tuple(
        n.strip()
        for n in os.getenv("IDP_BLOCKED_NETWORKS", "").split(",")
        if n.strip()
    )
    start, end = 6, 22
    raw_hours = os.getenv("IDP_ALLOWED_HOURS")
    if raw_hours:
        a, b = raw_hours.split("-")
        start, end = int(a), int(b)
    return PolicyConfig(
        deny_threshold=int(os.getenv("IDP_DENY_THRESHOLD", "70")),
        blocked_networks=blocked,
        allowed_hours=(start, end),
    )


def evaluate_request(request, now: datetime | None = None) -> PolicyDecision:
    host = request.client.host if request.client else ""
    # TODO (later): known_device and user_verified should come from data stored
    # with the authorization code at login time. Until then they are assumed
    # true, so only the IP and time-of-day signals are active.
    signals = RiskSignals(
        ip=host,
        known_device=True,
        user_verified=True,
        when=now or datetime.now(),
    )
    decision = evaluate(signals, load_config())
    log.info(
        "policy decision allowed=%s score=%s reasons=%s ip=%s",
        decision.allowed,
        decision.score,
        ",".join(decision.reasons),
        host,
    )
    return decision

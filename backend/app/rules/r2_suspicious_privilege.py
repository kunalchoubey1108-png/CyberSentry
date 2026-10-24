"""R2 — privileged action shortly after a suspicious login.

A privileged event (``privileged`` flag) within 30 minutes of a
``login_success`` that either belongs to an R1 burst, or arrived from a
source IP never seen for that user before. Thresholds come from
``rules.r2_suspicious_privilege`` in config.yaml.

"Never seen" means: no earlier event of any type by that user from that
``src_ip`` in the input. A privileged event never anchors itself (strictly
later than the login).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Mapping, Sequence

from ..schema import Asset, Event, EventType
from .base import RuleMatch
from .config import RuleConfig
from . import r1_login_burst

RULE_ID = "R2"


def detect(
    events: Sequence[Event],
    config: RuleConfig,
    assets: Mapping[str, Asset] | None = None,
) -> list[RuleMatch]:
    """Return one match per privileged event with a qualifying login anchor."""
    ordered = sorted(events, key=lambda event: (event.timestamp, event.event_id))
    r1_success_ids = {
        match.matched_event_ids[-1] for match in r1_login_burst.detect(events, config)
    }

    # Anchors: logins that are R1-matched or from a never-before-seen IP.
    anchors: list[Event] = []
    anchor_reasons: dict[str, str] = {}
    seen_ips: dict[str, set[str]] = {}
    for event in ordered:
        user_ips = seen_ips.setdefault(event.user, set())
        if event.event_type is EventType.LOGIN_SUCCESS:
            anchor_reason: str | None = None
            if event.event_id in r1_success_ids:
                anchor_reason = "followed a failed-login burst (R1)"
            elif event.src_ip not in user_ips:
                anchor_reason = f"first-ever login for {event.user!r} from {event.src_ip}"
            if anchor_reason is not None:
                anchor_reasons[event.event_id] = anchor_reason
                anchors.append(event)
        user_ips.add(event.src_ip)

    window = timedelta(seconds=config.privilege_window_seconds)
    matches: list[RuleMatch] = []
    for privileged in ordered:
        if privileged.privileged is not True:
            continue
        anchor = _earliest_anchor_for(anchors, privileged, window)
        if anchor is None:
            continue
        matches.append(
            RuleMatch(
                rule_id=RULE_ID,
                severity=config.privilege_severity,
                matched_event_ids=[anchor.event_id, privileged.event_id],
                reason=(
                    f"privileged action by {privileged.user!r} on {privileged.host} "
                    f"({int((privileged.timestamp - anchor.timestamp).total_seconds())}s "
                    f"after a login from {anchor.src_ip}: "
                    f"{anchor_reasons[anchor.event_id]})"
                ),
                entities={
                    "user": privileged.user,
                    "host": privileged.host,
                    "src_ip": privileged.src_ip,
                    "login_src_ip": anchor.src_ip,
                },
            )
        )
    return matches


def _earliest_anchor_for(
    anchors: Sequence[Event], privileged: Event, window: timedelta
) -> Event | None:
    """Earliest qualifying login strictly before ``privileged`` within ``window``."""
    for anchor in anchors:
        if anchor.user != privileged.user:
            continue
        if anchor.timestamp < privileged.timestamp <= anchor.timestamp + window:
            return anchor
    return None

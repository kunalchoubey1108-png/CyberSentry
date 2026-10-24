"""R3 — password spray: one source IP failing against many distinct users.

5+ distinct users suffer ``login_failed`` from the same ``src_ip`` inside a
10-minute window. Thresholds come from ``rules.r3_password_spray`` in
config.yaml.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Mapping, Sequence

from ..schema import Asset, Event, EventType
from .base import RuleMatch
from .config import RuleConfig

RULE_ID = "R3"


def detect(
    events: Sequence[Event],
    config: RuleConfig,
    assets: Mapping[str, Asset] | None = None,
) -> list[RuleMatch]:
    """Return one match per source IP whose failures cover enough distinct users."""
    by_ip: dict[str, list[Event]] = {}
    for event in events:
        if event.event_type is EventType.LOGIN_FAILED:
            by_ip.setdefault(event.src_ip, []).append(event)

    matches: list[RuleMatch] = []
    threshold = config.spray_distinct_user_threshold
    window = timedelta(seconds=config.spray_window_seconds)

    for src_ip, failures in sorted(by_ip.items()):
        failures.sort(key=lambda event: (event.timestamp, event.event_id))
        index = 0
        while index < len(failures):
            slice_end = index
            while (
                slice_end < len(failures)
                and failures[slice_end].timestamp - failures[index].timestamp <= window
            ):
                slice_end += 1
            window_events = failures[index:slice_end]
            users = sorted({e.user for e in window_events})
            if len(users) >= threshold:
                matches.append(
                    RuleMatch(
                        rule_id=RULE_ID,
                        severity=config.spray_severity,
                        matched_event_ids=[e.event_id for e in window_events],
                        reason=(
                            f"src_ip {src_ip} failed authentication for "
                            f"{len(users)} distinct users ({', '.join(users)}) "
                            f"within {config.spray_window_seconds}s — password spray"
                        ),
                        entities={"src_ip": src_ip, "distinct_users": str(len(users))},
                    )
                )
                break  # one match per source IP
            index = slice_end
    return matches

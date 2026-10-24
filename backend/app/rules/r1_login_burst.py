"""R1 — failed-login burst followed by a success (credential guessing worked).

5+ ``login_failed`` events for the same (user, src_ip) inside a 10-minute
window, followed by a ``login_success`` for the same (user, src_ip) within
15 minutes of the burst. Thresholds come from
``rules.r1_failed_login_burst`` in config.yaml.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Mapping, Sequence

from ..schema import Asset, Event, EventType
from .base import RuleMatch
from .config import RuleConfig

RULE_ID = "R1"


def detect(
    events: Sequence[Event],
    config: RuleConfig,
    assets: Mapping[str, Asset] | None = None,
) -> list[RuleMatch]:
    """Return one match per (user, src_ip) burst that was followed by a success."""
    groups: dict[tuple[str, str], list[Event]] = {}
    for event in events:
        if event.event_type in (EventType.LOGIN_FAILED, EventType.LOGIN_SUCCESS):
            groups.setdefault((event.user, event.src_ip), []).append(event)

    matches: list[RuleMatch] = []
    threshold = config.login_burst_failure_threshold
    failure_window = timedelta(seconds=config.login_burst_failure_window_seconds)
    success_window = timedelta(seconds=config.login_burst_success_window_seconds)

    for (user, src_ip), group in sorted(groups.items()):
        group.sort(key=lambda event: (event.timestamp, event.event_id))
        failures = [e for e in group if e.event_type is EventType.LOGIN_FAILED]
        successes = [e for e in group if e.event_type is EventType.LOGIN_SUCCESS]

        index = 0
        while index + threshold <= len(failures):
            window = failures[index : index + threshold]
            span = window[-1].timestamp - window[0].timestamp
            if span <= failure_window:
                # The qualifying window is minimal; the reported burst is the
                # maximal run of failures inside the same 10-minute frame, so
                # every failure of the attack lands in matched_event_ids.
                frame_end = window[0].timestamp + failure_window
                burst = [e for e in failures[index:] if e.timestamp <= frame_end]
                success = _first_success_after(burst[-1].timestamp, successes, success_window)
                if success is not None:
                    burst_span = int((burst[-1].timestamp - burst[0].timestamp).total_seconds())
                    delay = int((success.timestamp - burst[-1].timestamp).total_seconds())
                    matches.append(
                        RuleMatch(
                            rule_id=RULE_ID,
                            severity=config.login_burst_severity,
                            matched_event_ids=[e.event_id for e in burst] + [success.event_id],
                            reason=(
                                f"{len(burst)} failed logins for user {user!r} from {src_ip} "
                                f"within {burst_span}s, followed by a "
                                f"successful login {delay}s later — password guessing succeeded"
                            ),
                            entities={"user": user, "src_ip": src_ip},
                        )
                    )
                    index += len(burst)  # burst consumed; do not re-report its failures
                    continue
            index += 1
    return matches


def _first_success_after(
    anchor: datetime, successes: Sequence[Event], success_window: timedelta
) -> Event | None:
    """Earliest success in [anchor, anchor + window], or None."""
    for success in successes:
        if anchor <= success.timestamp <= anchor + success_window:
            return success
    return None

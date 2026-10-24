"""R4 — elevated access on a critical host outside business hours.

``login_success`` or a privileged action on a host whose asset criticality
is >= ``min_criticality``, at a UTC hour outside [start_hour, end_hour).
Hours and criticality come from ``rules.r4_offhours_elevated`` in config.yaml.

Hosts missing from the asset inventory cannot establish criticality, so
they never match (unknown is not == critical).
"""

from __future__ import annotations

from datetime import datetime
from typing import Mapping, Sequence

from ..ingest import load_assets
from ..schema import Asset, Event, EventType
from .base import RuleMatch
from .config import RuleConfig

RULE_ID = "R4"


def detect(
    events: Sequence[Event],
    config: RuleConfig,
    assets: Mapping[str, Asset] | None = None,
) -> list[RuleMatch]:
    """Return one match per off-hours elevated event on a critical host."""
    if assets is None:
        assets = load_assets()

    matches: list[RuleMatch] = []
    for event in sorted(events, key=lambda e: (e.timestamp, e.event_id)):
        if not (
            event.event_type is EventType.LOGIN_SUCCESS or event.privileged is True
        ):
            continue
        asset = assets.get(event.host)
        if asset is None or asset.criticality < config.offhours_min_criticality:
            continue
        if _within_business_hours(event.timestamp, config):
            continue
        action = "privileged action" if event.privileged is True else "login"
        matches.append(
            RuleMatch(
                rule_id=RULE_ID,
                severity=config.offhours_severity,
                matched_event_ids=[event.event_id],
                reason=(
                    f"{action} by {event.user!r} on {event.host} "
                    f"(criticality {asset.criticality}) at "
                    f"{event.timestamp.strftime('%H:%M')} UTC — outside business "
                    f"hours [{config.offhours_start_hour}:00, "
                    f"{config.offhours_end_hour}:00)"
                ),
                entities={
                    "user": event.user,
                    "host": event.host,
                    "src_ip": event.src_ip,
                    "criticality": str(asset.criticality),
                },
            )
        )
    return matches


def _within_business_hours(timestamp: datetime, config: RuleConfig) -> bool:
    """Business hours are [start_hour, end_hour) in UTC."""
    return config.offhours_start_hour <= timestamp.hour < config.offhours_end_hour

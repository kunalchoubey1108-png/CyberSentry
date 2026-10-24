"""Transparent, auditable risk scoring for incidents.

The score is a deterministic sum of named components derived only from
what the rules already matched — never from the LLM (AGENTS.md rule 1):

    score = min(100, rule_component + corroboration + event_volume
                    + asset_component + privilege_component + sequence_bonus)

Each component is a named contribution auditable against the incident's
evidence (rule IDs and event IDs); ``docs/scoring.md`` documents the
formula, caps, and bands. The score is a **heuristic triage aid, not a
probability** — see that document for the precise claim it makes.
"""

from __future__ import annotations

from enum import Enum
from typing import Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from .correlate import Incident, member_matches
from .rules.base import RuleMatch
from .schema import Asset, Event, EventType

MAX_SCORE = 100

# Component definitions (see docs/scoring.md).
RULE_SEVERITY_MULTIPLIER = 5
RULE_COMPONENT_CAP = 40
CORROBORATION_PER_EXTRA_RULE = 5
CORROBORATION_CAP = 15
EVENT_VOLUME_CAP = 10
ASSET_CRITICALITY_MULTIPLIER = 4
ASSET_COMPONENT_CAP = 20
PRIVILEGE_COMPONENT = 10
SEQUENCE_BONUS = 5

# Band edges: Low 0-34, Medium 35-59, High 60-79, Critical 80-100.
_MEDIUM_MIN = 35
_HIGH_MIN = 60
_CRITICAL_MIN = 80


class RiskBand(str, Enum):
    """Human-facing band for a computed score."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class IncidentScore(BaseModel):
    """A score broken into its named, auditable components.

    ``matched_event_count`` is recorded so the ``event_volume``
    contribution (floor of log2 of that count) can be checked by hand.
    """

    model_config = ConfigDict(strict=True)

    score: int = Field(ge=0, le=MAX_SCORE)
    band: RiskBand
    rule_component: int = Field(ge=0)
    corroboration: int = Field(ge=0)
    event_volume: int = Field(ge=0)
    asset_component: int = Field(ge=0)
    privilege_component: int = Field(ge=0)
    sequence_bonus: int = Field(ge=0)
    matched_event_count: int = Field(ge=1)


def band_for_score(score: int) -> RiskBand:
    """Map a 0-100 score to its band (Low/Medium/High/Critical)."""
    if not 0 <= score <= MAX_SCORE:
        raise ValueError(f"score must be between 0 and {MAX_SCORE}, got {score}")
    if score < _MEDIUM_MIN:
        return RiskBand.LOW
    if score < _HIGH_MIN:
        return RiskBand.MEDIUM
    if score < _CRITICAL_MIN:
        return RiskBand.HIGH
    return RiskBand.CRITICAL


def score_incident(
    incident: Incident,
    matches: Sequence[RuleMatch],
    events: Sequence[Event],
    assets: Mapping[str, Asset] | None = None,
) -> IncidentScore:
    """Score one incident; every component traces to matched evidence.

    ``matches`` and ``events`` are the same collections that produced the
    incident via ``app.correlate``; the member matches are selected by
    event-ID overlap (``member_matches``). Hosts absent from the asset
    inventory contribute nothing (unknown is not == critical, as in R4).
    """
    if assets is None:
        from .ingest import load_assets  # deferred: keeps import graph simple

        assets = load_assets()

    members = member_matches(incident, matches)
    if not members:
        raise ValueError(f"incident {incident.incident_id} has no member matches")

    index: Mapping[str, Event] = {event.event_id: event for event in events}
    unknown = [event_id for event_id in incident.event_ids if event_id not in index]
    if unknown:
        raise ValueError(
            f"incident {incident.incident_id} cites unknown event_id(s): "
            f"{', '.join(sorted(set(unknown)))}"
        )
    matched_events = [index[event_id] for event_id in incident.event_ids]

    rule_component = min(
        RULE_COMPONENT_CAP,
        max(member.severity for member in members) * RULE_SEVERITY_MULTIPLIER,
    )
    distinct_rules = len({member.rule_id for member in members})
    corroboration = min(
        CORROBORATION_CAP,
        (distinct_rules - 1) * CORROBORATION_PER_EXTRA_RULE,
    )
    event_volume = min(EVENT_VOLUME_CAP, _log2_floor(len(matched_events)))
    asset_component = min(
        ASSET_COMPONENT_CAP,
        _max_criticality(incident.entities.get("hosts", []), assets)
        * ASSET_CRITICALITY_MULTIPLIER,
    )
    privilege_component = (
        PRIVILEGE_COMPONENT
        if any(event.privileged is True for event in matched_events)
        else 0
    )
    sequence_bonus = (
        SEQUENCE_BONUS if _sequence_observed(matched_events) else 0
    )

    total = min(
        MAX_SCORE,
        rule_component
        + corroboration
        + event_volume
        + asset_component
        + privilege_component
        + sequence_bonus,
    )
    return IncidentScore(
        score=total,
        band=band_for_score(total),
        rule_component=rule_component,
        corroboration=corroboration,
        event_volume=event_volume,
        asset_component=asset_component,
        privilege_component=privilege_component,
        sequence_bonus=sequence_bonus,
        matched_event_count=len(matched_events),
    )


def _log2_floor(count: int) -> int:
    """floor(log2(count)) for count >= 1, computed exactly (no floats)."""
    return count.bit_length() - 1


def _max_criticality(hosts: Sequence[str], assets: Mapping[str, Asset]) -> int:
    """Max criticality over known hosts; unknown hosts contribute nothing."""
    known = [assets[host].criticality for host in hosts if host in assets]
    return max(known, default=0)


def _sequence_observed(events: Sequence[Event]) -> bool:
    """True when a failure, a success, and a privileged action occur in
    that order (non-strictly increasing timestamps) among matched events."""
    failures = sorted(
        event.timestamp for event in events if event.event_type is EventType.LOGIN_FAILED
    )
    successes = sorted(
        event.timestamp for event in events if event.event_type is EventType.LOGIN_SUCCESS
    )
    privileged = sorted(
        event.timestamp for event in events if event.privileged is True
    )
    if not (failures and successes and privileged):
        return False
    for success in successes:
        if success >= failures[0] and privileged[-1] >= success:
            return True
    return False

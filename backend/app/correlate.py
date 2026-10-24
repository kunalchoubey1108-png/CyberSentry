"""Event-to-incident correlation: rule matches grouped into incidents.

Each ``RuleMatch`` is a node in a correlation graph. Two nodes are linked
when they share at least one entity (user, host, or src_ip — derived from
the matched events themselves, never from free text) **and** their time
windows overlap or are separated by at most ``DEFAULT_CORRELATION_GAP``
(30 minutes). Connected components of this graph become incidents.

Correlation only groups what the deterministic rules already found; it
never creates, drops, or re-scores detections (AGENTS.md rule 1), and
every incident traces back to concrete rule IDs and event IDs (AGENTS.md
rule 3):

* ``event_ids``  — the rule-matched events that produced the incident.
* ``rule_ids``   — the rules that fired on those events.
* ``timeline``   — all matched events plus *contextual* events (same user
  or src_ip inside the incident window), ordered by time, each entry
  marked ``matched`` vs contextual with the rule IDs that matched it.

Incident IDs are content-addressed (a hash of the sorted member event
IDs), so the same evidence always yields the same ID regardless of input
order.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Mapping, Sequence

from pydantic import BaseModel, ConfigDict

from .rules.base import RuleMatch
from .schema import Event, EventType

# Events within this gap of each other (on a shared entity) merge into one
# incident. Matches config.yaml's documented correlation.window_seconds.
DEFAULT_CORRELATION_GAP = timedelta(minutes=30)

INCIDENT_ID_PREFIX = "inc-"
_INCIDENT_ID_HEX_DIGITS = 12


class TimelineEntry(BaseModel):
    """One event in an incident's ordered timeline.

    ``matched`` is True when a rule in this incident matched the event;
    False marks a contextual event (same user or src_ip inside the
    incident window) included so a reviewer sees the surrounding activity.
    ``rule_ids`` lists the rules that matched this event within the
    incident; it is empty for contextual events.
    """

    model_config = ConfigDict(strict=True)

    event_id: str
    timestamp: datetime
    event_type: EventType
    user: str
    host: str
    src_ip: str
    matched: bool
    rule_ids: list[str]


class Incident(BaseModel):
    """A connected component of rule matches, with its evidence.

    ``event_ids`` are the rule-matched events (the evidence), ordered by
    time; contextual events appear only in ``timeline``. ``entities``
    holds the sorted users / hosts / src_ips involved. ``start_time`` and
    ``end_time`` bound the matched events.
    """

    model_config = ConfigDict(strict=True)

    incident_id: str
    event_ids: list[str]
    rule_ids: list[str]
    entities: dict[str, list[str]]
    start_time: datetime
    end_time: datetime
    timeline: list[TimelineEntry]


@dataclass
class _Node:
    """Internal graph node: one rule match over its resolved events."""

    match: RuleMatch
    events: list[Event]
    start: datetime
    end: datetime
    users: set[str]
    hosts: set[str]
    src_ips: set[str]


def correlate_events(
    matches: Sequence[RuleMatch],
    events: Sequence[Event],
    *,
    gap: timedelta = DEFAULT_CORRELATION_GAP,
) -> list[Incident]:
    """Group rule ``matches`` into incidents over an event collection.

    Every ``matched_event_ids`` entry must exist in ``events`` — a match
    citing an unknown event cannot be traced to evidence and fails loudly
    instead of being silently dropped or coerced.

    Incidents are returned ordered by (start_time, incident_id); the
    output is deterministic for the same evidence in any input order.
    """
    if gap < timedelta(0):
        raise ValueError(f"gap must be non-negative, got {gap}")
    index: Mapping[str, Event] = {event.event_id: event for event in events}
    nodes = [_build_node(match, index) for match in matches]
    incidents = [
        _build_incident(nodes, component, index)
        for component in _components(nodes, gap)
    ]
    incidents.sort(key=lambda incident: (incident.start_time, incident.incident_id))
    return incidents


def member_matches(incident: Incident, matches: Sequence[RuleMatch]) -> list[RuleMatch]:
    """Return the matches that produced ``incident`` (input order kept).

    By construction, a component's matches are exactly those citing at
    least one of the incident's member events: two matches sharing an
    event always share entities and an overlapping window, so they land
    in the same component. Downstream stages (scoring, evidence) use this
    to trace an incident back to its rules.
    """
    member_ids = frozenset(incident.event_ids)
    return [match for match in matches if member_ids & set(match.matched_event_ids)]


def _build_node(match: RuleMatch, index: Mapping[str, Event]) -> _Node:
    """Resolve a match's cited events; raise if any citation is unknown."""
    resolved: list[Event] = []
    unknown: list[str] = []
    for event_id in match.matched_event_ids:
        event = index.get(event_id)
        if event is None:
            unknown.append(event_id)
        else:
            resolved.append(event)
    if unknown:
        raise ValueError(
            f"rule {match.rule_id!r} match cites unknown event_id(s): "
            f"{', '.join(sorted(set(unknown)))}"
        )
    if not resolved:
        raise ValueError(f"rule {match.rule_id!r} match has no matched_event_ids")
    timestamps = [event.timestamp for event in resolved]
    return _Node(
        match=match,
        events=resolved,
        start=min(timestamps),
        end=max(timestamps),
        users={event.user for event in resolved},
        hosts={event.host for event in resolved},
        src_ips={event.src_ip for event in resolved},
    )


def _linked(a: _Node, b: _Node, gap: timedelta) -> bool:
    """True when two matches share an entity and their windows are close."""
    if not (
        a.users & b.users or a.hosts & b.hosts or a.src_ips & b.src_ips
    ):
        return False
    # Windows overlap or are separated by at most ``gap``.
    return a.start <= b.end + gap and b.start <= a.end + gap


def _components(nodes: Sequence[_Node], gap: timedelta) -> list[list[int]]:
    """Connected components (node index lists) via union-find."""
    parent = list(range(len(nodes)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            if _linked(nodes[i], nodes[j], gap):
                parent[find(j)] = find(i)

    groups: dict[int, list[int]] = {}
    for index in range(len(nodes)):
        groups.setdefault(find(index), []).append(index)
    return list(groups.values())


def _build_incident(
    nodes: Sequence[_Node],
    component: Sequence[int],
    index: Mapping[str, Event],
) -> Incident:
    """Assemble one incident from a component's matches and the event index."""
    members = [nodes[i] for i in component]

    matched_events = sorted(
        (event for member in members for event in member.events),
        key=lambda event: (event.timestamp, event.event_id),
    )
    # An event cited by multiple member matches must appear once.
    member_events: list[Event] = []
    member_ids: list[str] = []
    seen: set[str] = set()
    for event in matched_events:
        if event.event_id not in seen:
            seen.add(event.event_id)
            member_events.append(event)
            member_ids.append(event.event_id)

    start_time = matched_events[0].timestamp
    end_time = matched_events[-1].timestamp
    users = sorted({event.user for event in matched_events})
    hosts = sorted({event.host for event in matched_events})
    src_ips = sorted({event.src_ip for event in matched_events})

    event_rules: dict[str, list[str]] = {}
    for member in members:
        for event_id in member.match.matched_event_ids:
            rules = event_rules.setdefault(event_id, [])
            if member.match.rule_id not in rules:
                rules.append(member.match.rule_id)
    for rules in event_rules.values():
        rules.sort()

    timeline = [
        TimelineEntry(
            event_id=event.event_id,
            timestamp=event.timestamp,
            event_type=event.event_type,
            user=event.user,
            host=event.host,
            src_ip=event.src_ip,
            matched=True,
            rule_ids=event_rules[event.event_id],
        )
        for event in member_events
    ]

    # Contextual events: same user or src_ip, inside the incident window.
    user_set = frozenset(users)
    ip_set = frozenset(src_ips)
    for event in index.values():
        if event.event_id in seen:
            continue
        if not start_time <= event.timestamp <= end_time:
            continue
        if event.user in user_set or event.src_ip in ip_set:
            timeline.append(
                TimelineEntry(
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    event_type=event.event_type,
                    user=event.user,
                    host=event.host,
                    src_ip=event.src_ip,
                    matched=False,
                    rule_ids=[],
                )
            )
    timeline.sort(key=lambda entry: (entry.timestamp, entry.event_id))

    return Incident(
        incident_id=_incident_id(member_ids),
        event_ids=member_ids,
        rule_ids=sorted({member.match.rule_id for member in members}),
        entities={"users": users, "hosts": hosts, "src_ips": src_ips},
        start_time=start_time,
        end_time=end_time,
        timeline=timeline,
    )


def _incident_id(member_ids: Sequence[str]) -> str:
    """Content-addressed ID: same evidence -> same ID, in any order."""
    digest = hashlib.sha256(",".join(sorted(member_ids)).encode("utf-8")).hexdigest()
    return f"{INCIDENT_ID_PREFIX}{digest[:_INCIDENT_ID_HEX_DIGITS]}"

"""Correlation tests: graph mechanics on synthetic events, plus the
labelled scenarios from data/labelled/labels.json (scenario (a) 8-fail
brute force, scenario (b) password spray, scenario (d) benign lookalike).

All events here are synthetic (AGENTS.md rule 7).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.correlate import (
    DEFAULT_CORRELATION_GAP,
    Incident,
    correlate_events,
    member_matches,
)
from app.ingest import load_csv
from app.rules import run_all_rules
from app.rules.base import RuleMatch
from app.rules.config import RuleConfig, load_config
from app.schema import Asset, Event

T0 = datetime(2024, 6, 11, 10, 0, tzinfo=timezone.utc)
CONFIG = load_config()
DATA_DIR = Path(__file__).resolve().parents[2] / "data"

ASSET_MAP = {
    asset.host: asset
    for asset in (
        Asset.model_validate({"host": "dc-01.lab.local", "criticality": 5, "role": "domain_controller"}),
        Asset.model_validate({"host": "web-01.lab.local", "criticality": 4, "role": "web_server"}),
        Asset.model_validate({"host": "vpn-01.lab.local", "criticality": 4, "role": "vpn_gateway"}),
        Asset.model_validate({"host": "ws-01.lab.local", "criticality": 2, "role": "workstation"}),
        Asset.model_validate({"host": "ws-02.lab.local", "criticality": 2, "role": "workstation"}),
    )
}


def ev(
    eid: str,
    offset_seconds: float,
    event_type: str = "login_failed",
    user: str = "alice",
    host: str = "ws-01.lab.local",
    ip: str = "10.0.0.1",
    privileged: bool = False,
) -> Event:
    return Event.model_validate(
        {
            "event_id": eid,
            "timestamp": T0 + timedelta(seconds=offset_seconds),
            "event_type": event_type,
            "user": user,
            "host": host,
            "src_ip": ip,
            "severity": 5,
            "message": "synthetic test event",
            "privileged": privileged,
        }
    )


def match(
    rule_id: str,
    event_ids: list[str],
    severity: int = 8,
    entities: dict[str, str] | None = None,
) -> RuleMatch:
    return RuleMatch(
        rule_id=rule_id,
        severity=severity,
        matched_event_ids=event_ids,
        reason="synthetic test match",
        entities=entities or {},
    )


class TestGraphConstruction:
    def test_no_matches_yield_no_incidents(self) -> None:
        assert correlate_events([], [ev("e1", 0)]) == []

    def test_single_match_yields_one_incident(self) -> None:
        incident = correlate_events([match("R1", ["e1"])], [ev("e1", 0)])
        assert len(incident) == 1
        inc = incident[0]
        assert inc.incident_id.startswith("inc-")
        assert inc.event_ids == ["e1"]
        assert inc.rule_ids == ["R1"]
        assert inc.start_time == inc.end_time == T0
        assert [entry.event_id for entry in inc.timeline] == ["e1"]
        assert inc.timeline[0].matched is True

    def test_shared_user_links_matches(self) -> None:
        events = [ev("a1", 0), ev("a2", 600)]
        incidents = correlate_events(
            [match("R1", ["a1"]), match("R2", ["a2"])], events
        )
        assert len(incidents) == 1
        assert incidents[0].rule_ids == ["R1", "R2"]

    def test_shared_host_links_matches(self) -> None:
        events = [
            ev("a1", 0, user="alice", host="web-01.lab.local", ip="10.0.0.1"),
            ev("a2", 600, user="bob", host="web-01.lab.local", ip="10.0.0.2"),
        ]
        incidents = correlate_events(
            [match("R1", ["a1"]), match("R3", ["a2"])], events
        )
        assert len(incidents) == 1

    def test_shared_src_ip_links_matches(self) -> None:
        events = [
            ev("a1", 0, user="alice", ip="198.51.100.66"),
            ev("a2", 600, user="bob", ip="198.51.100.66"),
        ]
        incidents = correlate_events(
            [match("R1", ["a1"]), match("R3", ["a2"])], events
        )
        assert len(incidents) == 1
        assert incidents[0].entities["src_ips"] == ["198.51.100.66"]

    def test_no_shared_entity_stays_separate(self) -> None:
        events = [
            ev("a1", 0, user="alice", host="ws-01.lab.local", ip="10.0.0.1"),
            ev("a2", 60, user="bob", host="ws-02.lab.local", ip="10.0.0.2"),
        ]
        incidents = correlate_events(
            [match("R1", ["a1"]), match("R1", ["a2"])], events
        )
        assert len(incidents) == 2

    def test_overlapping_windows_link(self) -> None:
        events = [ev("a1", 0), ev("a2", 120), ev("a3", 240)]
        incidents = correlate_events(
            [match("R1", ["a1", "a2"]), match("R2", ["a2", "a3"])], events
        )
        assert len(incidents) == 1
        assert incidents[0].event_ids == ["a1", "a2", "a3"]

    def test_gap_within_30_minutes_links(self) -> None:
        # First window ends at 0s, second starts 1799s later.
        events = [ev("a1", 0), ev("a2", 1799)]
        assert len(correlate_events([match("R1", ["a1"]), match("R2", ["a2"])], events)) == 1

    def test_boundary_gap_exactly_30_minutes_links(self) -> None:
        events = [ev("a1", 0), ev("a2", 1800)]
        assert len(correlate_events([match("R1", ["a1"]), match("R2", ["a2"])], events)) == 1

    def test_boundary_gap_one_second_past_splits(self) -> None:
        events = [ev("a1", 0), ev("a2", 1801)]
        incidents = correlate_events([match("R1", ["a1"]), match("R2", ["a2"])], events)
        assert len(incidents) == 2

    def test_default_gap_is_30_minutes(self) -> None:
        assert DEFAULT_CORRELATION_GAP == timedelta(minutes=30)

    def test_transitive_chain_merges_into_one_incident(self) -> None:
        # A-B share a user; B-C share a src_ip; A-C share nothing.
        events = [
            ev("a1", 0, user="alice", ip="10.0.0.1"),
            ev("a2", 300, user="alice", ip="10.0.0.2"),
            ev("a3", 600, user="bob", ip="10.0.0.2"),
        ]
        incidents = correlate_events(
            [match("R1", ["a1"]), match("R2", ["a2"]), match("R3", ["a3"])],
            events,
        )
        assert len(incidents) == 1
        assert incidents[0].event_ids == ["a1", "a2", "a3"]

    def test_custom_gap_overrides_default(self) -> None:
        events = [ev("a1", 0), ev("a2", 2400)]
        separate = correlate_events([match("R1", ["a1"]), match("R2", ["a2"])], events)
        assert len(separate) == 2
        merged = correlate_events(
            [match("R1", ["a1"]), match("R2", ["a2"])], events, gap=timedelta(hours=1)
        )
        assert len(merged) == 1

    def test_negative_gap_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            correlate_events([], [], gap=timedelta(seconds=-1))


class TestIncidentShape:
    def test_fields_derived_from_matched_events(self) -> None:
        events = [
            ev("a1", 0, user="alice", host="web-01.lab.local", ip="10.0.0.1"),
            ev("a2", 600, user="bob", host="web-01.lab.local", ip="10.0.0.2"),
        ]
        inc = correlate_events([match("R1", ["a2"]), match("R2", ["a1"])], events)[0]
        assert inc.event_ids == ["a1", "a2"]  # ordered by time, not input order
        assert inc.rule_ids == ["R1", "R2"]
        assert inc.entities == {
            "users": ["alice", "bob"],
            "hosts": ["web-01.lab.local"],
            "src_ips": ["10.0.0.1", "10.0.0.2"],
        }
        assert inc.start_time == T0
        assert inc.end_time == T0 + timedelta(seconds=600)

    def test_timeline_marks_matched_and_contextual_events(self) -> None:
        events = [
            ev("m1", 0, user="alice", ip="10.0.0.1"),
            ev("ctx", 30, user="alice", ip="10.0.0.1", event_type="file_access"),
            ev("m2", 60, user="alice", ip="10.0.0.1", event_type="login_success"),
            ev("out", 3600, user="alice", ip="10.0.0.1"),
        ]
        inc = correlate_events(
            [match("R1", ["m1"]), match("R2", ["m2"])], events
        )[0]
        # Evidence contains only rule-matched events.
        assert inc.event_ids == ["m1", "m2"]
        # Timeline interleaves matched and contextual events in time order.
        assert [entry.event_id for entry in inc.timeline] == ["m1", "ctx", "m2"]
        by_id = {entry.event_id: entry for entry in inc.timeline}
        assert by_id["m1"].matched is True and by_id["m1"].rule_ids == ["R1"]
        assert by_id["m2"].matched is True and by_id["m2"].rule_ids == ["R2"]
        assert by_id["ctx"].matched is False and by_id["ctx"].rule_ids == []
        # The event outside the incident window is not contextual.
        assert "out" not in by_id

    def test_context_requires_user_or_ip_not_just_host(self) -> None:
        events = [
            ev("m1", 0, user="alice", host="web-01.lab.local", ip="10.0.0.1"),
            ev(
                "samehost",
                30,
                user="zoe",
                host="web-01.lab.local",
                ip="10.0.0.99",
                event_type="process_start",
            ),
        ]
        inc = correlate_events([match("R1", ["m1"])], events)[0]
        assert [entry.event_id for entry in inc.timeline] == ["m1"]

    def test_event_matched_by_multiple_rules_lists_both(self) -> None:
        events = [ev("m1", 0), ev("m2", 60)]
        inc = correlate_events(
            [match("R1", ["m1", "m2"]), match("R2", ["m2"])], events
        )[0]
        by_id = {entry.event_id: entry for entry in inc.timeline}
        assert by_id["m1"].rule_ids == ["R1"]
        assert by_id["m2"].rule_ids == ["R1", "R2"]

    def test_timeline_has_no_duplicates_when_matches_share_an_event(self) -> None:
        # Regression: an event cited by two member matches (e.g. the R1
        # success also anchored by R2) must appear once in the timeline.
        events = [ev("a1", 0), ev("a2", 120), ev("a3", 240)]
        inc = correlate_events(
            [match("R1", ["a1", "a2"]), match("R2", ["a2", "a3"])], events
        )[0]
        timeline_ids = [entry.event_id for entry in inc.timeline]
        assert len(timeline_ids) == len(set(timeline_ids)) == 3

    def test_unknown_event_id_fails_loudly(self) -> None:
        with pytest.raises(ValueError, match="ghost"):
            correlate_events([match("R1", ["m1", "ghost"])], [ev("m1", 0)])

    def test_empty_match_fails_loudly(self) -> None:
        with pytest.raises(ValueError, match="no matched_event_ids"):
            correlate_events([match("R1", [])], [ev("m1", 0)])

    def test_output_is_deterministic_regardless_of_input_order(self) -> None:
        events = [ev("a1", 0), ev("a2", 300), ev("b1", 60, user="bob", ip="10.0.0.2")]
        matches = [match("R1", ["a1"]), match("R2", ["a2"]), match("R3", ["b1"])]
        first = correlate_events(matches, events)
        second = correlate_events(list(reversed(matches)), list(reversed(events)))
        assert first == second
        assert all(isinstance(inc, Incident) for inc in first)

    def test_incident_ids_are_content_addressed(self) -> None:
        events = [ev("a1", 0), ev("a2", 60)]
        one = correlate_events([match("R1", ["a1", "a2"])], events)[0]
        two = correlate_events(
            [match("R2", ["a2"]), match("R1", ["a1"])], events
        )[0]
        assert one.incident_id == two.incident_id


class TestMemberMatches:
    """Scoring and evidence trace an incident back to its matches."""

    def test_selects_exactly_the_components_matches(self) -> None:
        events = [ev("a1", 0), ev("a2", 60), ev("b1", 30, user="bob", host="ws-02.lab.local", ip="10.0.0.2")]
        matches = [match("R1", ["a1"]), match("R2", ["a2"]), match("R3", ["b1"])]
        incidents = correlate_events(matches, events)
        assert len(incidents) == 2
        by_member = {
            incident.incident_id: {m.rule_id for m in member_matches(incident, matches)}
            for incident in incidents
        }
        assert {frozenset(rule_ids) for rule_ids in by_member.values()} == {
            frozenset({"R1", "R2"}),
            frozenset({"R3"}),
        }

    def test_ignores_unrelated_matches(self) -> None:
        events = [ev("a1", 0)]
        incident = correlate_events([match("R1", ["a1"])], events)[0]
        assert member_matches(incident, []) == []


class TestSyntheticLookalike:
    """Scenario (d) rebuilt inline: two failures then a success, no incident."""

    def _lookalike(self) -> list[Event]:
        return [
            ev("l1", 0, user="ivan", host="ws-02.lab.local", ip="10.0.8.108"),
            ev("l2", 90, user="ivan", host="ws-02.lab.local", ip="10.0.8.108"),
            ev("l3", 150, user="ivan", host="ws-02.lab.local", ip="10.0.8.108",
               event_type="login_success"),
        ]

    def test_no_rules_fire_and_no_incident_forms(self) -> None:
        events = self._lookalike()
        matches = run_all_rules(events, CONFIG, ASSET_MAP)
        assert matches == []
        assert correlate_events(matches, events) == []

    def test_even_with_aggressive_config(self) -> None:
        aggressive = RuleConfig(
            login_burst_failure_threshold=3,
            spray_distinct_user_threshold=3,
        )
        events = self._lookalike()
        matches = run_all_rules(events, aggressive, ASSET_MAP)
        assert correlate_events(matches, events) == []


@pytest.mark.skipif(
    not (DATA_DIR / "sample_attacks.csv").exists(),
    reason="generated fixtures not present; run data/generate_data.py",
)
class TestLabelledScenarios:
    """Integration: correlate the full rules run over sample_attacks.csv
    and check the labelled ground truth scenarios end to end."""

    @staticmethod
    def _scenarios() -> dict[str, dict]:
        labels = json.loads((DATA_DIR / "labelled" / "labels.json").read_text())
        return {scenario["id"]: scenario for scenario in labels["scenarios"]}

    @staticmethod
    def _pipeline(path: Path) -> list[Incident]:
        events, rejected = load_csv(path)
        assert rejected == []
        matches = run_all_rules(events, CONFIG, ASSET_MAP)
        return correlate_events(matches, events)

    def _incidents_containing(self, event_ids: set[str]) -> list[Incident]:
        incidents = self._pipeline(DATA_DIR / "sample_attacks.csv")
        return [
            incident
            for incident in incidents
            if event_ids & set(incident.event_ids)
        ]

    def test_bruteforce_8_fail_scenario_is_exactly_one_incident(self) -> None:
        brute = set(
            self._scenarios()["susp-brute-force-then-privilege"]["event_ids"]
        )
        assert len(brute) == 10  # 8 failures + success + privilege change
        containing = self._incidents_containing(brute)
        assert len(containing) == 1
        incident = containing[0]
        assert set(incident.event_ids) == brute
        assert set(incident.rule_ids) == {"R1", "R2"}
        assert incident.entities["users"] == ["erin"]
        assert incident.entities["src_ips"] == ["203.0.113.10"]

    def test_spray_is_a_separate_incident(self) -> None:
        scenarios = self._scenarios()
        brute = set(scenarios["susp-brute-force-then-privilege"]["event_ids"])
        spray = set(scenarios["susp-password-spray"]["event_ids"])
        brute_incident = self._incidents_containing(brute)[0]

        containing = self._incidents_containing(spray)
        assert len(containing) == 1
        incident = containing[0]
        assert incident.incident_id != brute_incident.incident_id
        assert incident.rule_ids == ["R3"]
        assert set(incident.event_ids) == spray
        assert incident.entities["src_ips"] == ["198.51.100.66"]
        # Same host as the brute force, but > 30 minutes apart: no merge.
        assert set(incident.event_ids).isdisjoint(brute)

    def test_spray_timeline_includes_contextual_events(self) -> None:
        spray = set(self._scenarios()["susp-password-spray"]["event_ids"])
        incident = self._incidents_containing(spray)[0]
        matched_ids = set(incident.event_ids)
        context_ids = {
            entry.event_id for entry in incident.timeline if not entry.matched
        }
        # Background activity by spray victims during the spray window.
        assert {"bg-0144", "bg-0009"} <= context_ids
        assert context_ids.isdisjoint(matched_ids)

    def test_lookalike_creates_no_incident(self) -> None:
        lookalike = set(
            self._scenarios()["benign-lookalike-two-fails-then-success"]["event_ids"]
        )
        incidents = self._pipeline(DATA_DIR / "sample_attacks.csv")
        flagged = {event_id for inc in incidents for event_id in inc.event_ids}
        assert lookalike.isdisjoint(flagged)
        timeline_ids = {
            entry.event_id for inc in incidents for entry in inc.timeline
        }
        assert lookalike.isdisjoint(timeline_ids)

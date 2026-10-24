"""Scoring tests: each named component in isolation, band edges, caps,
and integration against the labelled fixtures.

All events here are synthetic (AGENTS.md rule 7).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.correlate import correlate_events
from app.ingest import load_assets, load_csv
from app.rules import run_all_rules
from app.rules.base import RuleMatch
from app.rules.config import load_config
from app.scoring import IncidentScore, RiskBand, band_for_score, score_incident
from app.schema import Asset, Event

T0 = datetime(2024, 6, 11, 10, 0, tzinfo=timezone.utc)
CONFIG = load_config()
DATA_DIR = Path(__file__).resolve().parents[2] / "data"

ASSETS = {
    asset.host: asset
    for asset in (
        Asset.model_validate({"host": "dc-01.lab.local", "criticality": 5, "role": "domain_controller"}),
        Asset.model_validate({"host": "ws-01.lab.local", "criticality": 2, "role": "workstation"}),
    )
}


def ev(
    eid: str,
    offset_seconds: float,
    event_type: str = "login_failed",
    user: str = "alice",
    host: str = "ghost.lab.local",  # unknown to ASSETS unless stated
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
    severity: int = 5,
    entities: dict[str, str] | None = None,
) -> RuleMatch:
    return RuleMatch(
        rule_id=rule_id,
        severity=severity,
        matched_event_ids=event_ids,
        reason="synthetic test match",
        entities=entities or {},
    )


def score_one(
    events: list[Event],
    matches: list[RuleMatch],
    assets: dict[str, Asset] | None = None,
) -> IncidentScore:
    """Correlate then score; the tests exercise the real pipeline shape."""
    incidents = correlate_events(matches, events)
    assert len(incidents) == 1
    return score_incident(incidents[0], matches, events, assets or {})


class TestComponents:
    def test_rule_component_scales_with_max_severity(self) -> None:
        result = score_one(
            [ev("a1", 0), ev("a2", 60)],
            [match("R1", ["a1"], severity=3), match("R2", ["a2"], severity=6)],
        )
        assert result.rule_component == 30  # 6 x 5

    def test_rule_component_caps_at_40(self) -> None:
        result = score_one(
            [ev("a1", 0)], [match("R1", ["a1"], severity=9)]
        )
        assert result.rule_component == 40  # 9 x 5 = 45, capped

    def test_corroboration_adds_5_per_extra_rule(self) -> None:
        one_rule = score_one([ev("a1", 0)], [match("R1", ["a1"])])
        assert one_rule.corroboration == 0
        three_rules = score_one(
            [ev("a1", 0), ev("a2", 60)],
            [match("R1", ["a1"]), match("R2", ["a1"]), match("R3", ["a2"])],
        )
        assert three_rules.corroboration == 10

    def test_corroboration_caps_at_15(self) -> None:
        result = score_one(
            [ev("a1", 0)],
            [match(rule, ["a1"]) for rule in ("R1", "R2", "R3", "R4", "R5")],
        )
        assert result.corroboration == 15  # 4 extra x 5 = 20, capped

    def test_event_volume_is_floor_of_log2(self) -> None:
        assert score_one([ev("a1", 0)], [match("R1", ["a1"])]).event_volume == 0
        four = [ev(f"a{i}", i) for i in range(4)]
        assert score_one(four, [match("R1", [e.event_id for e in four])]).event_volume == 2
        ten = [ev(f"a{i}", i) for i in range(10)]
        assert score_one(ten, [match("R1", [e.event_id for e in ten])]).event_volume == 3

    def test_event_volume_caps_at_10(self) -> None:
        many = [ev(f"a{i}", i % 1800) for i in range(2048)]  # floor(log2) = 11
        result = score_one(many, [match("R1", [e.event_id for e in many])])
        assert result.event_volume == 10
        assert result.matched_event_count == 2048

    def test_asset_component_uses_max_known_criticality(self) -> None:
        ws = score_one(
            [ev("a1", 0, host="ws-01.lab.local")],
            [match("R1", ["a1"])],
            ASSETS,
        )
        assert ws.asset_component == 8  # 2 x 4
        mixed = score_one(
            [
                ev("a1", 0, host="ws-01.lab.local"),
                ev("a2", 60, host="dc-01.lab.local"),
            ],
            [match("R1", ["a1", "a2"])],
            ASSETS,
        )
        assert mixed.asset_component == 20  # max(2, 5) x 4

    def test_unknown_host_contributes_no_asset_component(self) -> None:
        result = score_one(
            [ev("a1", 0, host="ghost.lab.local")], [match("R1", ["a1"])], ASSETS
        )
        assert result.asset_component == 0

    def test_privilege_component_only_for_privileged_actions(self) -> None:
        plain = score_one([ev("a1", 0)], [match("R1", ["a1"])])
        assert plain.privilege_component == 0
        privileged = score_one(
            [ev("a1", 0, event_type="privilege_change", privileged=True)],
            [match("R1", ["a1"])],
        )
        assert privileged.privilege_component == 10

    def test_sequence_bonus_requires_ordered_chain(self) -> None:
        chain = [
            ev("f", 0),
            ev("s", 60, event_type="login_success"),
            ev("p", 120, event_type="privilege_change", privileged=True),
        ]
        in_order = score_one(chain, [match("R1", [e.event_id for e in chain])])
        assert in_order.sequence_bonus == 5

    def test_sequence_bonus_zero_when_success_precedes_failure(self) -> None:
        wrong = [
            ev("s", 0, event_type="login_success"),
            ev("f", 60),
            ev("p", 120, event_type="privilege_change", privileged=True),
        ]
        result = score_one(wrong, [match("R1", [e.event_id for e in wrong])])
        assert result.sequence_bonus == 0

    def test_sequence_bonus_zero_when_privilege_precedes_success(self) -> None:
        wrong = [
            ev("f", 0),
            ev("p", 60, event_type="privilege_change", privileged=True),
            ev("s", 120, event_type="login_success"),
        ]
        result = score_one(wrong, [match("R1", [e.event_id for e in wrong])])
        assert result.sequence_bonus == 0

    def test_sequence_bonus_zero_without_failure(self) -> None:
        no_failure = [
            ev("s", 0, event_type="login_success"),
            ev("p", 60, event_type="privilege_change", privileged=True),
        ]
        result = score_one(
            no_failure, [match("R1", [e.event_id for e in no_failure])]
        )
        assert result.sequence_bonus == 0


class TestBands:
    def test_band_edges(self) -> None:
        assert band_for_score(0) is RiskBand.LOW
        assert band_for_score(34) is RiskBand.LOW
        assert band_for_score(35) is RiskBand.MEDIUM
        assert band_for_score(59) is RiskBand.MEDIUM
        assert band_for_score(60) is RiskBand.HIGH
        assert band_for_score(79) is RiskBand.HIGH
        assert band_for_score(80) is RiskBand.CRITICAL
        assert band_for_score(100) is RiskBand.CRITICAL

    def test_out_of_range_rejected(self) -> None:
        with pytest.raises(ValueError, match="between 0 and 100"):
            band_for_score(-1)
        with pytest.raises(ValueError, match="between 0 and 100"):
            band_for_score(101)


class TestFullScore:
    def test_all_components_maxed_score_exactly_100(self) -> None:
        events = [
            ev("f", 0),
            ev("s", 60, event_type="login_success", host="dc-01.lab.local"),
            ev("p", 120, event_type="privilege_change", host="dc-01.lab.local", privileged=True),
        ] + [ev(f"x{i}", 300 + (i % 600)) for i in range(1021)]
        ids = [e.event_id for e in events]
        matches = [match("R1", ids, severity=10)] + [
            match(rule, ["s"], severity=1) for rule in ("R2", "R3", "R4", "R5")
        ]
        result = score_one(events, matches, ASSETS)
        assert (
            result.rule_component,
            result.corroboration,
            result.event_volume,
            result.asset_component,
            result.privilege_component,
            result.sequence_bonus,
        ) == (40, 15, 10, 20, 10, 5)
        assert result.score == 100
        assert result.band is RiskBand.CRITICAL

    def test_unknown_event_ids_fail_loudly(self) -> None:
        incident = correlate_events([match("R1", ["a1"])], [ev("a1", 0)])[0]
        tampered = incident.model_copy(update={"event_ids": ["a1", "ghost"]})
        with pytest.raises(ValueError, match="ghost"):
            score_incident(tampered, [match("R1", ["a1"])], [ev("a1", 0)], {})

    def test_incident_without_member_matches_fails_loudly(self) -> None:
        incident = correlate_events([match("R1", ["a1"])], [ev("a1", 0)])[0]
        with pytest.raises(ValueError, match="no member matches"):
            score_incident(incident, [], [ev("a1", 0)], {})


@pytest.mark.skipif(
    not (DATA_DIR / "sample_attacks.csv").exists(),
    reason="generated fixtures not present; run data/generate_data.py",
)
class TestAgainstLabelledScenarios:
    """Integration: exact component arithmetic on the labelled fixtures."""

    @staticmethod
    def _scenario(name: str) -> set[str]:
        import json

        labels = json.loads((DATA_DIR / "labelled" / "labels.json").read_text())
        scenario = next(s for s in labels["scenarios"] if s["id"] == name)
        return set(scenario["event_ids"])

    def _scored(self, scenario_id: str) -> IncidentScore:
        events, rejected = load_csv(DATA_DIR / "sample_attacks.csv")
        assert rejected == []
        assets = load_assets()
        matches = run_all_rules(events, CONFIG, assets)
        wanted = self._scenario(scenario_id)
        incidents = [i for i in correlate_events(matches, events) if wanted & set(i.event_ids)]
        assert len(incidents) == 1
        return score_incident(incidents[0], matches, events, assets)

    def test_bruteforce_scenario_score(self) -> None:
        result = self._scored("susp-brute-force-then-privilege")
        # 9x5=45 cap 40 | +1 rule 5 | log2(10)=3 | crit 4 x4=16 | priv 10 | seq 5
        assert result.rule_component == 40
        assert result.corroboration == 5
        assert result.event_volume == 3
        assert result.asset_component == 16
        assert result.privilege_component == 10
        assert result.sequence_bonus == 5
        assert result.matched_event_count == 10
        assert result.score == 79
        assert result.band is RiskBand.HIGH

    def test_spray_scenario_score(self) -> None:
        result = self._scored("susp-password-spray")
        # severity 7 x5=35 | 1 rule 0 | log2(12)=3 | crit 4 x4=16 | no priv/seq
        assert result.rule_component == 35
        assert result.corroboration == 0
        assert result.event_volume == 3
        assert result.asset_component == 16
        assert result.privilege_component == 0
        assert result.sequence_bonus == 0
        assert result.matched_event_count == 12
        assert result.score == 54
        assert result.band is RiskBand.MEDIUM

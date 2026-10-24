"""Rule tests: positive, negative, and boundary cases for R1-R4, plus
registry behaviour and integration against the labelled ground truth.

All events here are synthetic (AGENTS.md rule 7).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.rules import REGISTRY, run_all_rules
from app.rules.base import RuleMatch
from app.rules.config import CONFIG_PATH, RuleConfig, load_config
from app.rules import r1_login_burst, r2_suspicious_privilege, r3_password_spray, r4_offhours_elevated
from app.schema import Asset, Event

T0 = datetime(2024, 6, 11, 10, 0, tzinfo=timezone.utc)
CONFIG = load_config()
DATA_DIR = Path(__file__).resolve().parents[2] / "data"

ASSET_MAP = {
    asset.host: asset
    for asset in (
        Asset.model_validate({"host": "dc-01.lab.local", "criticality": 5, "role": "domain_controller"}),
        Asset.model_validate({"host": "web-01.lab.local", "criticality": 4, "role": "web_server"}),
        Asset.model_validate({"host": "ws-01.lab.local", "criticality": 2, "role": "workstation"}),
        Asset.model_validate({"host": "ws-02.lab.local", "criticality": 2, "role": "workstation"}),
    )
}


def ev(
    eid: str,
    offset_seconds: float,
    event_type: str,
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


def fail(eid: str, offset: float, **kwargs: str) -> Event:
    return ev(eid, offset, "login_failed", **kwargs)


def success(eid: str, offset: float, **kwargs: object) -> Event:
    return ev(eid, offset, "login_success", **kwargs)


class TestR1:
    def test_positive_burst_then_success(self) -> None:
        events = [fail(f"f{i}", 60 * i) for i in range(5)] + [success("s", 400)]
        matches = r1_login_burst.detect(events, CONFIG)
        assert len(matches) == 1
        match = matches[0]
        assert match.rule_id == "R1"
        assert match.severity == CONFIG.login_burst_severity == 8
        assert match.matched_event_ids == ["f0", "f1", "f2", "f3", "f4", "s"]
        assert match.entities == {"user": "alice", "src_ip": "10.0.0.1"}
        assert "password guessing succeeded" in match.reason

    def test_negative_only_four_failures(self) -> None:
        events = [fail(f"f{i}", 60 * i) for i in range(4)] + [success("s", 400)]
        assert r1_login_burst.detect(events, CONFIG) == []

    def test_negative_success_too_late(self) -> None:
        # Success at 901s after the 5th failure — one second past the window.
        events = [fail(f"f{i}", 60 * i) for i in range(5)] + [success("s", 240 + 901)]
        assert r1_login_burst.detect(events, CONFIG) == []

    def test_negative_failures_spread_too_far(self) -> None:
        # Span of any five consecutive failures exceeds 600s.
        events = [fail(f"f{i}", 200 * i) for i in range(5)] + [success("s", 1200)]
        assert r1_login_burst.detect(events, CONFIG) == []

    def test_boundary_exact_windows_match(self) -> None:
        # Failures span exactly 600s; success lands exactly at +900s.
        events = [fail(f"f{i}", 150 * i) for i in range(5)] + [success("s", 600 + 900)]
        assert len(r1_login_burst.detect(events, CONFIG)) == 1

    def test_boundary_one_second_over_fails(self) -> None:
        events = [fail(f"f{i}", 150 * i) for i in range(5)] + [success("s", 600 + 901)]
        assert r1_login_burst.detect(events, CONFIG) == []

    def test_groups_do_not_merge_across_users_or_ips(self) -> None:
        events = (
            [fail(f"a{i}", 60 * i) for i in range(3)]
            + [fail(f"b{i}", 60 * i, user="bob") for i in range(3)]
            + [success("s", 400)]
        )
        assert r1_login_burst.detect(events, CONFIG) == []


class TestR2:
    def test_positive_after_r1_chain(self) -> None:
        events = [fail(f"f{i}", 60 * i) for i in range(5)] + [
            success("s", 400),
            ev("p", 460, "privilege_change", privileged=True),
        ]
        matches = r2_suspicious_privilege.detect(events, CONFIG)
        assert len(matches) == 1
        assert matches[0].rule_id == "R2"
        assert matches[0].matched_event_ids == ["s", "p"]
        assert "failed-login burst" in matches[0].reason

    def test_positive_never_seen_ip(self) -> None:
        # Alice normally uses 10.0.0.1; a success from a new IP followed by
        # a privileged action anchors on the never-before-seen address.
        events = [
            success("old", -3600),
            success("new-login", 0, ip="203.0.113.99"),
            ev("p", 300, "privilege_change", ip="203.0.113.99", privileged=True),
        ]
        matches = r2_suspicious_privilege.detect(events, CONFIG)
        assert len(matches) == 1
        assert matches[0].matched_event_ids == ["new-login", "p"]
        assert "first-ever login" in matches[0].reason

    def test_negative_known_ip_without_r1(self) -> None:
        events = [
            success("old", -3600),
            success("s", 0),
            ev("p", 300, "privilege_change", privileged=True),
        ]
        assert r2_suspicious_privilege.detect(events, CONFIG) == []

    def test_boundary_privileged_exactly_at_window_edge(self) -> None:
        events = [
            success("old", -3600),
            success("new", 0, ip="203.0.113.99"),
            ev("p", 1800, "privilege_change", ip="203.0.113.99", privileged=True),
        ]
        assert len(r2_suspicious_privilege.detect(events, CONFIG)) == 1

    def test_boundary_one_second_past_window(self) -> None:
        events = [
            success("old", -3600),
            success("new", 0, ip="203.0.113.99"),
            ev("p", 1801, "privilege_change", ip="203.0.113.99", privileged=True),
        ]
        assert r2_suspicious_privilege.detect(events, CONFIG) == []

    def test_privileged_login_does_not_anchor_itself(self) -> None:
        events = [success("s", 0, ip="203.0.113.99", privileged=True)]
        assert r2_suspicious_privilege.detect(events, CONFIG) == []

    def test_user_must_match_anchor(self) -> None:
        events = [
            success("new", 0, ip="203.0.113.99"),
            ev("p", 300, "privilege_change", user="bob", ip="203.0.113.99", privileged=True),
        ]
        assert r2_suspicious_privilege.detect(events, CONFIG) == []


class TestR3:
    def test_positive_five_distinct_users(self) -> None:
        events = [
            fail(f"f{i}", 60 * i, user=f"user{i}", ip="198.51.100.66")
            for i in range(5)
        ]
        matches = r3_password_spray.detect(events, CONFIG)
        assert len(matches) == 1
        assert matches[0].rule_id == "R3"
        assert matches[0].matched_event_ids == ["f0", "f1", "f2", "f3", "f4"]
        assert "password spray" in matches[0].reason
        assert matches[0].entities["distinct_users"] == "5"

    def test_negative_four_distinct_users(self) -> None:
        events = [
            fail("f0", 0, user="u0", ip="198.51.100.66"),
            fail("f1", 60, user="u1", ip="198.51.100.66"),
            fail("f2", 120, user="u2", ip="198.51.100.66"),
            fail("f3", 180, user="u3", ip="198.51.100.66"),
            fail("f4", 240, user="u0", ip="198.51.100.66"),
        ]
        assert r3_password_spray.detect(events, CONFIG) == []

    def test_boundary_fifth_user_exactly_at_window_edge(self) -> None:
        events = [
            fail(f"f{i}", 150 * i, user=f"user{i}", ip="198.51.100.66")
            for i in range(4)
        ] + [fail("f4", 600, user="user4", ip="198.51.100.66")]
        assert len(r3_password_spray.detect(events, CONFIG)) == 1

    def test_boundary_fifth_user_one_second_past(self) -> None:
        events = [
            fail(f"f{i}", 150 * i, user=f"user{i}", ip="198.51.100.66")
            for i in range(4)
        ] + [fail("f4", 601, user="user4", ip="198.51.100.66")]
        assert r3_password_spray.detect(events, CONFIG) == []

    def test_ips_do_not_merge(self) -> None:
        events = (
            [fail(f"a{i}", 60 * i, user=f"user{i}", ip="192.0.2.1") for i in range(3)]
            + [fail(f"b{i}", 60 * i, user=f"user{i}", ip="192.0.2.2") for i in range(3)]
        )
        assert r3_password_spray.detect(events, CONFIG) == []


class TestR4:
    def test_positive_offhours_login_critical_host(self) -> None:
        offhours = success("off", 0, host="dc-01.lab.local").model_copy(
            update={"timestamp": datetime(2024, 6, 12, 2, 30, tzinfo=timezone.utc)}
        )
        matches = r4_offhours_elevated.detect([offhours], CONFIG, ASSET_MAP)
        assert len(matches) == 1
        assert matches[0].rule_id == "R4"
        assert matches[0].matched_event_ids == ["off"]
        assert matches[0].entities["criticality"] == "5"

    def test_positive_privileged_action_at_2000(self) -> None:
        event = ev("p", 0, "privilege_change", host="web-01.lab.local", privileged=True).model_copy(
            update={"timestamp": datetime(2024, 6, 11, 20, 0, tzinfo=timezone.utc)}
        )
        assert len(r4_offhours_elevated.detect([event], CONFIG, ASSET_MAP)) == 1

    def test_boundary_195959_inside_200000_outside(self) -> None:
        inside = success("in", 0, host="dc-01.lab.local").model_copy(
            update={"timestamp": datetime(2024, 6, 11, 19, 59, 59, tzinfo=timezone.utc)}
        )
        outside = success("out", 0, host="dc-01.lab.local").model_copy(
            update={"timestamp": datetime(2024, 6, 11, 20, 0, 0, tzinfo=timezone.utc)}
        )
        matched = r4_offhours_elevated.detect([inside, outside], CONFIG, ASSET_MAP)
        assert [m.matched_event_ids for m in matched] == [["out"]]

    def test_boundary_075959_outside_080000_inside(self) -> None:
        outside = success("out", 0, host="dc-01.lab.local").model_copy(
            update={"timestamp": datetime(2024, 6, 11, 7, 59, 59, tzinfo=timezone.utc)}
        )
        inside = success("in", 0, host="dc-01.lab.local").model_copy(
            update={"timestamp": datetime(2024, 6, 11, 8, 0, 0, tzinfo=timezone.utc)}
        )
        matched = r4_offhours_elevated.detect([outside, inside], CONFIG, ASSET_MAP)
        assert [m.matched_event_ids for m in matched] == [["out"]]

    def test_negative_low_criticality_host(self) -> None:
        event = success("s", 0, host="ws-01.lab.local").model_copy(
            update={"timestamp": datetime(2024, 6, 12, 2, 30, tzinfo=timezone.utc)}
        )
        assert r4_offhours_elevated.detect([event], CONFIG, ASSET_MAP) == []

    def test_negative_unknown_host(self) -> None:
        event = success("s", 0, host="ghost-99.lab.local").model_copy(
            update={"timestamp": datetime(2024, 6, 12, 2, 30, tzinfo=timezone.utc)}
        )
        assert r4_offhours_elevated.detect([event], CONFIG, ASSET_MAP) == []

    def test_negative_non_login_non_privileged(self) -> None:
        event = ev("fa", 0, "file_access", host="dc-01.lab.local").model_copy(
            update={"timestamp": datetime(2024, 6, 12, 2, 30, tzinfo=timezone.utc)}
        )
        assert r4_offhours_elevated.detect([event], CONFIG, ASSET_MAP) == []


class TestConfig:
    def test_defaults_match_config_yaml(self) -> None:
        assert CONFIG_PATH.exists()
        assert CONFIG.login_burst_failure_threshold == 5
        assert CONFIG.login_burst_failure_window_seconds == 600
        assert CONFIG.login_burst_success_window_seconds == 900
        assert CONFIG.privilege_window_seconds == 1800
        assert CONFIG.spray_distinct_user_threshold == 5
        assert CONFIG.spray_window_seconds == 600
        assert (CONFIG.offhours_start_hour, CONFIG.offhours_end_hour) == (8, 20)
        assert CONFIG.offhours_min_criticality == 4

    def test_missing_file_returns_defaults(self, tmp_path: Path) -> None:
        assert load_config(tmp_path / "nope.yaml") == RuleConfig()

    def test_overrides_change_rule_behaviour(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yaml"
        path.write_text(
            "rules:\n  r3_password_spray:\n    distinct_user_threshold: 3\n",
            encoding="utf-8",
        )
        config = load_config(path)
        assert config.spray_distinct_user_threshold == 3
        events = [
            fail(f"f{i}", 60 * i, user=f"user{i}", ip="198.51.100.66")
            for i in range(3)
        ]
        assert len(r3_password_spray.detect(events, config)) == 1
        assert r3_password_spray.detect(events, RuleConfig()) == []

    def test_invalid_severity_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yaml"
        path.write_text("rules:\n  r1_failed_login_burst:\n    severity: 99\n", encoding="utf-8")
        with pytest.raises(ValueError, match="severity"):
            load_config(path)

    def test_non_integer_threshold_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "config.yaml"
        path.write_text("rules:\n  r3_password_spray:\n    window_seconds: ten\n", encoding="utf-8")
        with pytest.raises(ValueError, match="integer"):
            load_config(path)

    def test_match_severity_bounds_enforced(self) -> None:
        with pytest.raises(ValidationError):
            RuleMatch(
                rule_id="R1",
                severity=11,
                matched_event_ids=["x"],
                reason="bad",
                entities={},
            )


class TestBenignLookalike:
    """Scenario (d): two failures then a success must NOT alert — any rule."""

    def _lookalike(self) -> list[Event]:
        return [
            fail("l1", 0, user="ivan", host="ws-02.lab.local", ip="10.0.8.108"),
            fail("l2", 90, user="ivan", host="ws-02.lab.local", ip="10.0.8.108"),
            success("l3", 150, user="ivan", host="ws-02.lab.local", ip="10.0.8.108"),
        ]

    def test_run_all_produces_no_matches(self) -> None:
        matches = run_all_rules(self._lookalike(), CONFIG, ASSET_MAP)
        assert matches == []

    def test_even_with_r1_configured_to_2_failures(self) -> None:
        # Even at an absurdly aggressive threshold, a two-failure chain
        # stays below it; R4 is off-hours-sensitive but ws-02 is criticality 2.
        aggressive = RuleConfig(
            login_burst_failure_threshold=3,
            spray_distinct_user_threshold=3,
        )
        assert run_all_rules(self._lookalike(), aggressive, ASSET_MAP) == []


class TestRegistry:
    def test_registry_contains_r1_to_r4(self) -> None:
        assert set(REGISTRY) == {"R1", "R2", "R3", "R4"}

    def test_run_all_is_deterministic(self) -> None:
        events = [fail(f"f{i}", 60 * i) for i in range(5)] + [
            success("s", 400),
            ev("p", 460, "privilege_change", privileged=True),
        ]
        first = run_all_rules(events, CONFIG, ASSET_MAP)
        second = run_all_rules(events, CONFIG, ASSET_MAP)
        assert first == second
        assert {m.rule_id for m in first} == {"R1", "R2"}


@pytest.mark.skipif(
    not (DATA_DIR / "sample_attacks.csv").exists(),
    reason="generated fixtures not present; run data/generate_data.py",
)
class TestAgainstGroundTruth:
    """Integration: run the registry over the generated fixtures and check
    the labelled scenarios from data/labelled/labels.json."""

    @staticmethod
    def _scenarios() -> dict[str, dict]:
        labels = json.loads((DATA_DIR / "labelled" / "labels.json").read_text())
        return {scenario["id"]: scenario for scenario in labels["scenarios"]}

    @staticmethod
    def _matches(path: Path) -> list[RuleMatch]:
        from app.ingest import load_csv

        events, rejected = load_csv(path)
        assert rejected == []
        return run_all_rules(events, CONFIG, ASSET_MAP)

    def test_scenario_a_bruteforce_fires_r1_and_r2(self) -> None:
        matches = self._matches(DATA_DIR / "sample_attacks.csv")
        scenario = self._scenarios()["susp-brute-force-then-privilege"]
        expected = set(scenario["event_ids"])
        covered = {
            event_id
            for match in matches
            if match.rule_id in ("R1", "R2")
            for event_id in match.matched_event_ids
        }
        assert expected <= covered

    def test_scenario_b_spray_fires_r3(self) -> None:
        matches = self._matches(DATA_DIR / "sample_attacks.csv")
        scenario = self._scenarios()["susp-password-spray"]
        r3_ids = {
            event_id for match in matches if match.rule_id == "R3" for event_id in match.matched_event_ids
        }
        assert set(scenario["event_ids"]) <= r3_ids

    def test_scenario_c_offhours_privileged_fires_r4(self) -> None:
        matches = self._matches(DATA_DIR / "sample_attacks.csv")
        scenario = self._scenarios()["susp-offhours-privileged-login"]
        r4_ids = {
            event_id for match in matches if match.rule_id == "R4" for event_id in match.matched_event_ids
        }
        assert set(scenario["event_ids"]) <= r4_ids

    def test_scenario_d_lookalike_never_alerts(self) -> None:
        matches = self._matches(DATA_DIR / "sample_attacks.csv")
        scenario = self._scenarios()["benign-lookalike-two-fails-then-success"]
        flagged = {
            event_id for match in matches for event_id in match.matched_event_ids
        }
        assert not set(scenario["event_ids"]) & flagged

    def test_benign_file_has_zero_matches(self) -> None:
        benign = DATA_DIR / "sample_benign.csv"
        if not benign.exists():
            pytest.skip("generated fixtures not present")
        assert self._matches(benign) == []

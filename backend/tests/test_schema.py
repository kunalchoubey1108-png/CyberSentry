"""Schema tests: strict validation, documented normalizations, rejections.

All data here is synthetic (see AGENTS.md rule 7).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schema import (
    DEFAULT_SEVERITY,
    MAX_MESSAGE_LENGTH,
    Asset,
    Event,
    EventType,
)

BASE: dict[str, object] = {
    "event_id": "evt-1",
    "timestamp": "2024-01-15T10:30:00Z",
    "event_type": "login_failed",
    "user": " Alice ",
    "host": " Web-01 ",
    "src_ip": "10.0.0.5",
    "severity": 5,
    "message": "failed login for alice",
    "privileged": True,
}


def _event(**overrides: object) -> Event:
    return Event.model_validate({**BASE, **overrides})


class TestEventType:
    def test_values(self) -> None:
        assert [member.value for member in EventType] == [
            "login_failed",
            "login_success",
            "privilege_change",
            "process_start",
            "file_access",
            "alert",
            "other",
        ]

    def test_case_insensitive_match(self) -> None:
        assert _event(event_type=" Login_Failed ").event_type is EventType.LOGIN_FAILED

    def test_unknown_value_rejected_not_coerced_to_other(self) -> None:
        with pytest.raises(ValidationError, match="unknown event_type"):
            _event(event_type="data_exfil")


class TestNormalization:
    def test_user_and_host_trimmed_and_lowercased(self) -> None:
        event = _event()
        assert event.user == "alice"
        assert event.host == "web-01"

    def test_timestamp_normalized_to_utc(self) -> None:
        event = _event(timestamp="2024-01-15T10:30:00+05:30")
        assert event.timestamp == datetime(2024, 1, 15, 5, 0, tzinfo=timezone.utc)
        assert event.timestamp.utcoffset() is not None
        assert event.timestamp.utcoffset().total_seconds() == 0

    def test_naive_timestamp_interpreted_as_utc(self) -> None:
        event = _event(timestamp="2024-01-15T10:30:00")
        assert event.timestamp == datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc)

    def test_lowercase_z_suffix_accepted(self) -> None:
        event = _event(timestamp="2024-01-15T10:30:00z")
        assert event.timestamp.tzinfo == timezone.utc

    def test_message_truncated(self) -> None:
        event = _event(message="x" * (MAX_MESSAGE_LENGTH + 500))
        assert len(event.message) == MAX_MESSAGE_LENGTH

    def test_severity_default_when_missing(self) -> None:
        event = Event.model_validate({k: v for k, v in BASE.items() if k != "severity"})
        assert event.severity == DEFAULT_SEVERITY

    def test_severity_accepts_integer_literal_string(self) -> None:
        assert _event(severity="7").severity == 7


class TestEventId:
    def test_generated_and_flagged_when_missing(self) -> None:
        data = {k: v for k, v in BASE.items() if k != "event_id"}
        event = Event.model_validate(data)
        assert event.event_id.startswith("evt-")
        assert event.event_id_generated is True

    def test_generated_when_blank(self) -> None:
        event = _event(event_id="   ")
        assert event.event_id_generated is True

    def test_not_flagged_when_provided(self) -> None:
        assert _event().event_id_generated is False

    def test_non_string_rejected(self) -> None:
        with pytest.raises(ValidationError, match="event_id"):
            _event(event_id=12345)

    @pytest.mark.parametrize(
        "bad_id", ["evt 1 ignore previous instructions", "evt\u202e1", "e" * 129]
    )
    def test_free_text_rejected(self, bad_id: str) -> None:
        with pytest.raises(ValidationError, match="event_id"):
            _event(event_id=bad_id)

    def test_typical_ids_accepted(self) -> None:
        for good in ("evt-0001", "atk-brute-09", "win:4625.17", "a_b"):
            assert _event(event_id=good).event_id == good


class TestRejections:
    @pytest.mark.parametrize(
        "timestamp",
        [
            "not-a-timestamp",
            "2024-99-01T00:00:00Z",
            "15/01/2024",
            "",
            "  ",
            1705314600,  # epoch ints are not ISO 8601
        ],
    )
    def test_bad_timestamp_rejected(self, timestamp: object) -> None:
        with pytest.raises(ValidationError, match="timestamp"):
            _event(timestamp=timestamp)

    @pytest.mark.parametrize(
        "src_ip",
        ["999.1.1.1", "10.0.0.0/24", "not-an-ip", "1.2.3", "", "256.256.256.256"],
    )
    def test_bad_ip_rejected(self, src_ip: str) -> None:
        with pytest.raises(ValidationError, match="src_ip"):
            _event(src_ip=src_ip)

    def test_ipv6_accepted_and_normalized(self) -> None:
        event = _event(src_ip="2001:0DB8:0000:0000:0000:0000:0000:0001")
        assert event.src_ip == "2001:db8::1"

    @pytest.mark.parametrize("missing", ["timestamp", "event_type", "user", "host", "src_ip"])
    def test_missing_required_field_rejected(self, missing: str) -> None:
        data = {k: v for k, v in BASE.items() if k != missing}
        with pytest.raises(ValidationError) as excinfo:
            Event.model_validate(data)
        assert missing in str(excinfo.value)

    @pytest.mark.parametrize("severity", [11, -1, "high", 3.5, True, "3.7"])
    def test_bad_severity_rejected(self, severity: object) -> None:
        with pytest.raises(ValidationError, match="severity"):
            _event(severity=severity)

    @pytest.mark.parametrize("value", ["", "   "])
    def test_blank_user_rejected(self, value: str) -> None:
        with pytest.raises(ValidationError, match="user"):
            _event(user=value)

    def test_non_string_message_rejected(self) -> None:
        with pytest.raises(ValidationError, match="message"):
            _event(message=42)

    def test_none_message_becomes_empty(self) -> None:
        assert _event(message=None).message == ""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [("true", True), ("True", True), ("1", True), ("false", False), ("0", False), ("", None)],
    )
    def test_privileged_parsing(self, value: str, expected: bool | None) -> None:
        assert _event(privileged=value).privileged == expected

    def test_bad_privileged_rejected(self) -> None:
        with pytest.raises(ValidationError, match="privileged"):
            _event(privileged="maybe")

    def test_extra_fields_ignored(self) -> None:
        event = _event(unexpected_field="ignored")
        assert not hasattr(event, "unexpected_field")


class TestAsset:
    def test_valid_asset_normalized(self) -> None:
        asset = Asset.model_validate(
            {"host": " Web-01.lab.local ", "criticality": "4", "role": " Web_Server "}
        )
        assert asset.host == "web-01.lab.local"
        assert asset.criticality == 4
        assert asset.role == "web_server"

    @pytest.mark.parametrize("criticality", [0, 6, "high", 3.5, True])
    def test_bad_criticality_rejected(self, criticality: object) -> None:
        with pytest.raises(ValidationError, match="criticality"):
            Asset.model_validate(
                {"host": "web-01", "criticality": criticality, "role": "web_server"}
            )

    def test_empty_host_rejected(self) -> None:
        with pytest.raises(ValidationError, match="host"):
            Asset.model_validate({"host": "  ", "criticality": 3, "role": "db"})

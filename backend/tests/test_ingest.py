"""Ingest tests: CSV and JSON parsing, per-row rejections, duplicate IDs.

All log data in these tests is synthetic (see AGENTS.md rule 7).
"""

from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path

import pytest

from app.ingest import (
    DEFAULT_ASSETS_PATH,
    load_assets,
    load_csv,
    load_events,
    load_json,
    load_jsonl,
    parse_records,
)
from app.schema import Event, EventType, RejectedRecord

CSV_HEADER = "event_id,timestamp,event_type,user,host,src_ip,severity,message,privileged"

VALID_CSV_ROWS = "\n".join(
    [
        "evt-1,2024-01-15T10:30:00Z,login_failed, Alice ,Web-01,10.0.0.5,7,failed login,true",
        "evt-2,2024-01-15T10:31:00Z,login_success,bob,web-01,10.0.0.6,,,",
    ]
)


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


class TestCsvIngest:
    def test_valid_rows(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "log.csv", f"{CSV_HEADER}\n{VALID_CSV_ROWS}\n")
        valid, rejected = load_csv(path)
        assert rejected == []
        assert len(valid) == 2
        first = valid[0]
        assert first.event_id == "evt-1"
        assert first.event_type is EventType.LOGIN_FAILED
        assert first.user == "alice"
        assert first.host == "web-01"
        assert first.src_ip == "10.0.0.5"
        assert first.severity == 7
        assert first.privileged is True
        assert first.timestamp.tzinfo == timezone.utc
        # Missing severity/message/privileged cells default, they are not errors.
        assert valid[1].severity == 3
        assert valid[1].message == ""
        assert valid[1].privileged is None

    def test_missing_event_id_column_generates_and_flags(self, tmp_path: Path) -> None:
        header = "timestamp,event_type,user,host,src_ip"
        row = "2024-01-15T10:30:00Z,login_success,bob,web-02,10.0.0.6"
        path = _write(tmp_path, "log.csv", f"{header}\n{row}\n")
        valid, rejected = load_csv(path)
        assert rejected == []
        assert valid[0].event_id.startswith("evt-")
        assert valid[0].event_id_generated is True

    def test_bad_timestamp_rejected_with_reason(self, tmp_path: Path) -> None:
        content = "\n".join(
            [
                CSV_HEADER,
                "evt-1,not-a-timestamp,login_failed,alice,web-01,10.0.0.5,5,boom,false",
                "evt-2,2024-13-45T99:00:00Z,login_failed,bob,web-01,10.0.0.6,5,x,false",
                VALID_CSV_ROWS.splitlines()[0],
            ]
        )
        path = _write(tmp_path, "log.csv", content)
        valid, rejected = load_csv(path)
        assert len(valid) == 1
        assert len(rejected) == 2
        assert all("timestamp" in item.reason for item in rejected)
        assert all(item.row in (2, 3) for item in rejected)

    def test_bad_ip_rejected_with_reason(self, tmp_path: Path) -> None:
        content = "\n".join(
            [
                CSV_HEADER,
                "evt-1,2024-01-15T10:30:00Z,login_failed,alice,web-01,999.1.1.1,5,x,false",
                "evt-2,2024-01-15T10:30:00Z,login_failed,bob,web-01,10.0.0.0/24,5,x,false",
                "evt-3,2024-01-15T10:30:00Z,login_failed,carol,web-01,,5,x,false",
                VALID_CSV_ROWS.splitlines()[0],
            ]
        )
        path = _write(tmp_path, "log.csv", content)
        valid, rejected = load_csv(path)
        assert len(valid) == 1
        assert len(rejected) == 3
        assert all("src_ip" in item.reason for item in rejected)
        # Original content is preserved for the operator, never rewritten.
        assert rejected[0].record["src_ip"] == "999.1.1.1"

    def test_missing_field_value_rejected(self, tmp_path: Path) -> None:
        content = "\n".join(
            [
                CSV_HEADER,
                "evt-1,2024-01-15T10:30:00Z,login_failed,,web-01,10.0.0.5,5,x,false",
            ]
        )
        path = _write(tmp_path, "log.csv", content)
        valid, rejected = load_csv(path)
        assert valid == []
        assert len(rejected) == 1
        assert "user" in rejected[0].reason

    def test_missing_column_rejected_per_row(self, tmp_path: Path) -> None:
        header = "event_id,timestamp,event_type,host,src_ip"
        row = "evt-1,2024-01-15T10:30:00Z,login_failed,web-01,10.0.0.5"
        path = _write(tmp_path, "log.csv", f"{header}\n{row}\n")
        valid, rejected = load_csv(path)
        assert valid == []
        assert "user" in rejected[0].reason

    def test_duplicate_event_ids_rejected(self, tmp_path: Path) -> None:
        row = "evt-1,2024-01-15T10:30:00Z,login_failed,alice,web-01,10.0.0.5,5,x,false"
        dupe = "evt-1,2024-01-15T11:00:00Z,login_success,alice,web-01,10.0.0.5,5,x,false"
        path = _write(tmp_path, "log.csv", f"{CSV_HEADER}\n{row}\n{dupe}\n")
        valid, rejected = load_csv(path)
        assert len(valid) == 1
        assert len(rejected) == 1
        assert "duplicate event_id" in rejected[0].reason
        assert rejected[0].row == 3

    def test_wrong_field_count_rejected_not_repaired(self, tmp_path: Path) -> None:
        content = "\n".join(
            [
                CSV_HEADER,
                VALID_CSV_ROWS.splitlines()[0],
                "evt-9,2024-01-15T10:00:00Z,login_failed,extra,fields,here,1,2,3,4,5",
                "evt-8,2024-01-15T10:00:00Z",
            ]
        )
        path = _write(tmp_path, "log.csv", content)
        valid, rejected = load_csv(path)
        assert len(valid) == 1
        assert len(rejected) == 2
        assert "expected 9 fields, found 11" in rejected[0].reason
        assert "expected 9 fields, found 2" in rejected[1].reason

    def test_unknown_event_type_rejected_not_mapped_to_other(self, tmp_path: Path) -> None:
        row = "evt-1,2024-01-15T10:30:00Z,data_exfil,alice,web-01,10.0.0.5,5,x,false"
        path = _write(tmp_path, "log.csv", f"{CSV_HEADER}\n{row}\n")
        valid, rejected = load_csv(path)
        assert valid == []
        assert "event_type" in rejected[0].reason

    def test_blank_lines_skipped_without_rejection(self, tmp_path: Path) -> None:
        content = f"{CSV_HEADER}\n{VALID_CSV_ROWS}\n\n   \n"
        path = _write(tmp_path, "log.csv", content)
        valid, rejected = load_csv(path)
        assert len(valid) == 2
        assert rejected == []

    def test_header_only_file_yields_nothing(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "log.csv", f"{CSV_HEADER}\n")
        assert load_csv(path) == ([], [])

    def test_empty_file_raises(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "log.csv", "")
        with pytest.raises(ValueError, match="empty"):
            load_csv(path)

    def test_rejected_records_carry_source(self, tmp_path: Path) -> None:
        row = "evt-1,bad-time,login_failed,alice,web-01,10.0.0.5,5,x,false"
        path = _write(tmp_path, "log.csv", f"{CSV_HEADER}\n{row}\n")
        _, rejected = load_csv(path)
        assert rejected[0].source == str(path)


class TestJsonIngest:
    def _records(self) -> list[dict[str, object]]:
        return [
            {
                "event_id": "evt-1",
                "timestamp": "2024-01-15T10:30:00+05:30",
                "event_type": "privilege_change",
                "user": " ADMIN ",
                "host": "DC-01",
                "src_ip": "2001:db8::1",
                "severity": "9",
                "message": "added to domain admins",
                "privileged": "true",
            },
            {
                "event_id": "evt-2",
                "timestamp": "2024-01-15T12:31:00Z",
                "event_type": "process_start",
                "user": "bob",
                "host": "ws-01",
                "src_ip": "10.0.0.6",
            },
        ]

    def test_valid_json_array(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "log.json", json.dumps(self._records()))
        valid, rejected = load_json(path)
        assert rejected == []
        assert len(valid) == 2
        # Offset timestamp normalized to UTC.
        assert valid[0].timestamp.utcoffset().total_seconds() == 0
        assert valid[0].timestamp.hour == 5
        assert valid[0].user == "admin"
        assert valid[0].severity == 9
        assert valid[0].privileged is True
        assert valid[0].src_ip == "2001:db8::1"
        assert valid[1].severity == 3

    def test_bad_rows_rejected_with_reasons(self, tmp_path: Path) -> None:
        records: list[object] = [
            {"timestamp": "nope", "event_type": "alert", "user": "a", "host": "h", "src_ip": "1.2.3.4"},
            {"event_id": "evt-2", "event_type": "alert", "user": "a", "host": "h", "src_ip": "1.2.3.4"},
            {"event_id": "evt-3", "timestamp": "2024-01-15T10:30:00Z", "event_type": "alert", "user": "a", "host": "h", "src_ip": "not-an-ip"},
            {"event_id": "evt-4", "timestamp": "2024-01-15T10:30:00Z", "event_type": "alert", "user": "a", "host": "h", "src_ip": "1.2.3.4"},
            "this is not an object",
        ]
        path = _write(tmp_path, "log.json", json.dumps(records))
        valid, rejected = load_json(path)
        assert len(valid) == 1
        assert valid[0].event_id == "evt-4"
        assert "timestamp" in rejected[0].reason
        assert "timestamp" in rejected[1].reason
        assert "src_ip" in rejected[2].reason
        assert "record is not an object" in rejected[3].reason

    def test_duplicate_event_ids_rejected(self, tmp_path: Path) -> None:
        records = self._records() + [dict(self._records()[0])]
        path = _write(tmp_path, "log.json", json.dumps(records))
        valid, rejected = load_json(path)
        assert len(valid) == 2
        assert len(rejected) == 1
        assert "duplicate event_id" in rejected[0].reason

    def test_invalid_json_file_raises(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "log.json", "[{,")
        with pytest.raises(ValueError, match="invalid JSON"):
            load_json(path)

    def test_top_level_object_raises(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "log.json", json.dumps({"events": []}))
        with pytest.raises(ValueError, match="top-level JSON array"):
            load_json(path)


class TestJsonlIngest:
    def test_good_and_bad_lines(self, tmp_path: Path) -> None:
        lines = [
            json.dumps(
                {
                    "event_id": "evt-1",
                    "timestamp": "2024-01-15T10:30:00Z",
                    "event_type": "file_access",
                    "user": "carol",
                    "host": "db-01",
                    "src_ip": "10.0.0.7",
                }
            ),
            "{not json",
            "",
            json.dumps(
                {
                    "event_id": "evt-2",
                    "timestamp": "2024-01-15T10:35:00Z",
                    "event_type": "file_access",
                    "user": "carol",
                    "host": "db-01",
                    "src_ip": "10.0.0.7",
                }
            ),
        ]
        path = _write(tmp_path, "log.jsonl", "\n".join(lines) + "\n")
        valid, rejected = load_jsonl(path)
        assert [event.event_id for event in valid] == ["evt-1", "evt-2"]
        assert len(rejected) == 1
        assert "invalid JSON" in rejected[0].reason
        assert rejected[0].row == 2


class TestDispatch:
    def test_load_events_dispatches_by_extension(self, tmp_path: Path) -> None:
        csv_path = _write(tmp_path, "log.csv", f"{CSV_HEADER}\n{VALID_CSV_ROWS.splitlines()[0]}\n")
        json_path = _write(tmp_path, "log.json", json.dumps(self._json_records()))
        jsonl_path = _write(tmp_path, "log.ndjson", json.dumps(self._json_records()[0]) + "\n")
        assert len(load_events(csv_path)[0]) == 1
        assert len(load_events(json_path)[0]) == 2
        assert len(load_events(jsonl_path)[0]) == 1

    def test_unsupported_extension_raises(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "log.txt", "whatever")
        with pytest.raises(ValueError, match="unsupported"):
            load_events(path)

    @staticmethod
    def _json_records() -> list[dict[str, object]]:
        return [
            {
                "event_id": f"evt-{index}",
                "timestamp": "2024-01-15T10:30:00Z",
                "event_type": "other",
                "user": "u",
                "host": "h",
                "src_ip": "10.0.0.1",
            }
            for index in range(1, 3)
        ]


class TestParseRecords:
    def test_returns_tuple_of_events_and_rejections(self) -> None:
        valid, rejected = parse_records(
            [
                {
                    "event_id": "evt-1",
                    "timestamp": "2024-01-15T10:30:00Z",
                    "event_type": "alert",
                    "user": "a",
                    "host": "h",
                    "src_ip": "10.0.0.1",
                },
                {"event_id": "evt-2"},
            ]
        )
        assert len(valid) == 1
        assert isinstance(valid[0], Event)
        assert isinstance(rejected[0], RejectedRecord)
        assert rejected[0].row == 2


class TestAssets:
    def test_load_assets_from_default_path(self) -> None:
        assets = load_assets()
        assert DEFAULT_ASSETS_PATH.exists()
        assert assets["db-01.lab.local"].criticality == 5
        assert assets["db-01.lab.local"].role == "database"
        assert assets["dc-01.lab.local"].role == "domain_controller"

    def test_load_assets_normalizes_hosts(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            "assets.csv",
            "host,criticality,role\n Web-01.lab.local ,4,Web_Server\n",
        )
        assets = load_assets(path)
        assert set(assets) == {"web-01.lab.local"}
        assert assets["web-01.lab.local"].criticality == 4

    def test_bad_criticality_raises(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path, "assets.csv", "host,criticality,role\nweb-01,9,web_server\n"
        )
        with pytest.raises(ValueError, match="criticality"):
            load_assets(path)

    def test_missing_column_raises(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "assets.csv", "host,criticality\nweb-01,3\n")
        with pytest.raises(ValueError, match="missing required column"):
            load_assets(path)

    def test_duplicate_host_raises(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path,
            "assets.csv",
            "host,criticality,role\nweb-01,3,web_server\nWEB-01,4,database\n",
        )
        with pytest.raises(ValueError, match="duplicate host"):
            load_assets(path)

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_assets(tmp_path / "nope.csv")

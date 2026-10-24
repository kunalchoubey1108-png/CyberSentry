"""Tests for the deterministic offline demo setup."""

from pathlib import Path

from app.db import Database
from app.demo import prepare_demo_database


def test_demo_loads_sample_and_caches_fallback_reports(tmp_path: Path) -> None:
    database_path = tmp_path / "demo.sqlite3"
    database_path.write_text("stale demo data", encoding="utf-8")

    events, rejected, incidents = prepare_demo_database(database_path)

    database = Database(database_path)
    assert events > 0
    assert rejected == 0
    assert incidents > 0
    summaries = database.list_incidents()
    assert len(summaries) == incidents
    for summary in summaries:
        report = database.get_cached_report(summary["incident_id"])
        assert report is not None
        assert report.fallback is True
        assert report.incident_id == summary["incident_id"]

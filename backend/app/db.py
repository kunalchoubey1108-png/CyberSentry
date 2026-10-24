"""SQLite persistence for uploads, events, rejected records, and incidents.

Layout:

* ``uploads``          — one row per accepted upload (counts per stage).
* ``events``           — one row per ingested event, keyed (upload_id,
                         event_id): the validated record as stored.
* ``rejected_records`` — one row per rejected record with its reason and
                         original content (nothing is silently dropped).
* ``incidents``        — one row per incident, keyed by its
                         content-addressed ID, with summary columns for
                         listing plus the full evidence bundle as JSON.
                         Re-uploading the same evidence updates the row
                         instead of duplicating it.

A fresh connection is opened per operation, so the store is safe under
FastAPI's threadpool without shared-connection locking.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from .correlate import Incident
from .evidence import EvidenceBundle
from .schema import Event, IncidentReport, RejectedRecord

DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "cybersentry.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS uploads (
    upload_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    filename       TEXT NOT NULL,
    uploaded_at    TEXT NOT NULL,
    event_count    INTEGER NOT NULL,
    rejected_count INTEGER NOT NULL,
    incident_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    upload_id  INTEGER NOT NULL,
    event_id   TEXT NOT NULL,
    timestamp  TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user       TEXT NOT NULL,
    host       TEXT NOT NULL,
    src_ip     TEXT NOT NULL,
    severity   INTEGER NOT NULL,
    message    TEXT NOT NULL,
    privileged INTEGER,
    PRIMARY KEY (upload_id, event_id)
);
CREATE TABLE IF NOT EXISTS rejected_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    upload_id   INTEGER NOT NULL,
    reason      TEXT NOT NULL,
    record_json TEXT NOT NULL,
    row_number  INTEGER,
    source      TEXT
);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    score       INTEGER NOT NULL,
    band        TEXT NOT NULL,
    rule_ids_json  TEXT NOT NULL,
    entities_json  TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    start_time  TEXT NOT NULL,
    end_time    TEXT NOT NULL,
    evidence_json  TEXT NOT NULL,
    first_upload_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS report_cache (
    incident_id TEXT PRIMARY KEY,
    report_json TEXT NOT NULL,
    cached_at TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class UploadCounts:
    """What one accepted upload stored, per pipeline stage."""

    events: int
    rejected: int
    incidents: int


class Database:
    """Thin typed wrapper over a SQLite file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    @classmethod
    def default(cls) -> "Database":
        return cls(DEFAULT_DB_PATH)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path))
        connection.row_factory = sqlite3.Row
        return connection

    def init_schema(self) -> None:
        """Create tables if absent (idempotent)."""
        with self._connect() as connection:
            connection.executescript(_SCHEMA)

    def save_upload(
        self,
        *,
        filename: str,
        events: Sequence[Event],
        rejected: Sequence[RejectedRecord],
        incidents: Sequence[tuple[Incident, EvidenceBundle]],
    ) -> UploadCounts:
        """Persist one pipeline run atomically; returns the stage counts.

        Incidents are keyed by their content-addressed ID, so re-running
        the same evidence updates the stored row rather than duplicating
        the incident.
        """
        uploaded_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO uploads "
                "(filename, uploaded_at, event_count, rejected_count, incident_count) "
                "VALUES (?, ?, ?, ?, ?)",
                (filename, uploaded_at, len(events), len(rejected), len(incidents)),
            )
            upload_id = cursor.lastrowid
            if upload_id is None:
                raise RuntimeError("database did not assign an upload_id")

            connection.executemany(
                "INSERT INTO events "
                "(upload_id, event_id, timestamp, event_type, user, host, src_ip, "
                " severity, message, privileged) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        upload_id,
                        event.event_id,
                        event.timestamp.isoformat(),
                        event.event_type.value,
                        event.user,
                        event.host,
                        event.src_ip,
                        event.severity,
                        event.message,
                        None if event.privileged is None else int(event.privileged),
                    )
                    for event in events
                ],
            )

            connection.executemany(
                "INSERT INTO rejected_records "
                "(upload_id, reason, record_json, row_number, source) "
                "VALUES (?, ?, ?, ?, ?)",
                [
                    (
                        upload_id,
                        record.reason,
                        json.dumps(record.record, sort_keys=True),
                        record.row,
                        record.source,
                    )
                    for record in rejected
                ],
            )

            for incident, bundle in incidents:
                score = bundle.score
                connection.execute(
                    "DELETE FROM report_cache WHERE incident_id = ?",
                    (incident.incident_id,),
                )
                connection.execute(
                    "INSERT INTO incidents "
                    "(incident_id, score, band, rule_ids_json, entities_json, "
                    " event_count, start_time, end_time, evidence_json, "
                    " first_upload_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(incident_id) DO UPDATE SET "
                    " score = excluded.score, band = excluded.band, "
                    " rule_ids_json = excluded.rule_ids_json, "
                    " entities_json = excluded.entities_json, "
                    " event_count = excluded.event_count, "
                    " start_time = excluded.start_time, "
                    " end_time = excluded.end_time, "
                    " evidence_json = excluded.evidence_json",
                    (
                        incident.incident_id,
                        score.score,
                        score.band.value,
                        json.dumps(incident.rule_ids),
                        json.dumps(incident.entities, sort_keys=True),
                        len(incident.event_ids),
                        incident.start_time.isoformat(),
                        incident.end_time.isoformat(),
                        bundle.model_dump_json(),
                        upload_id,
                    ),
                )
        return UploadCounts(
            events=len(events), rejected=len(rejected), incidents=len(incidents)
        )

    def list_incidents(self) -> list[dict[str, Any]]:
        """Summary rows for GET /incidents, highest score first."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT incident_id, score, band, rule_ids_json, entities_json, "
                " event_count, start_time, end_time "
                "FROM incidents ORDER BY score DESC, incident_id ASC"
            ).fetchall()
        return [
            {
                "incident_id": row["incident_id"],
                "score": row["score"],
                "band": row["band"],
                "rules": json.loads(row["rule_ids_json"]),
                "entities": json.loads(row["entities_json"]),
                "event_count": row["event_count"],
                "start_time": row["start_time"],
                "end_time": row["end_time"],
            }
            for row in rows
        ]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        """Full detail for one incident: score, entities, rules, timeline.

        Returns None when the incident is unknown (the API maps that to
        a 404; nothing is invented).
        """
        with self._connect() as connection:
            row = connection.execute(
                "SELECT incident_id, score, band, rule_ids_json, entities_json, "
                " event_count, start_time, end_time, evidence_json "
                "FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        if row is None:
            return None
        evidence = json.loads(row["evidence_json"])
        return {
            "incident_id": row["incident_id"],
            "score": evidence["score"],
            "band": row["band"],
            "rules": json.loads(row["rule_ids_json"]),
            "entities": json.loads(row["entities_json"]),
            "event_count": row["event_count"],
            "start_time": row["start_time"],
            "end_time": row["end_time"],
            "findings": evidence["rules"],
            "timeline": evidence["timeline"],
            "supporting_records": evidence["supporting_records"],
        }

    def get_cached_report(self, incident_id: str) -> IncidentReport | None:
        """Return a previously validated report, if one is cached."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT report_json FROM report_cache WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        if row is None:
            return None
        report = IncidentReport.model_validate_json(row["report_json"])
        if report.incident_id != incident_id:
            raise ValueError(
                f"cached report incident_id mismatch for {incident_id!r}"
            )
        return report

    def save_cached_report(self, report: IncidentReport) -> None:
        """Persist a report for offline reuse with this incident's evidence."""
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO report_cache (incident_id, report_json, cached_at) "
                "VALUES (?, ?, ?) ON CONFLICT(incident_id) DO UPDATE SET "
                "report_json = excluded.report_json, cached_at = excluded.cached_at",
                (
                    report.incident_id,
                    report.model_dump_json(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def close(self) -> None:
        """Present for API symmetry; connections are per-operation."""


__all__ = ["DEFAULT_DB_PATH", "Database", "UploadCounts"]

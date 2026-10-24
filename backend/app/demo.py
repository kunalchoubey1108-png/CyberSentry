"""Prepare the isolated synthetic demo database and cache offline reports."""

from __future__ import annotations

import os
from pathlib import Path

from .correlate import correlate_events
from .db import Database
from .evidence import build_evidence_bundle
from .ingest import load_assets, load_events
from .llm.fallback import build_fallback_report
from .rules import load_config, run_all_rules
from .scoring import score_incident

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_DB_PATH = Path(__file__).resolve().parents[1] / "cybersentry-demo.sqlite3"
SAMPLE_PATH = REPO_ROOT / "data" / "sample_attacks.csv"


def prepare_demo_database(
    database_path: str | Path = DEMO_DB_PATH,
) -> tuple[int, int, int]:
    """Reset only the dedicated demo database, load sample data, cache reports."""
    path = Path(database_path)
    for target in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        target.unlink(missing_ok=True)

    events, rejected = load_events(SAMPLE_PATH)
    assets = load_assets()
    matches = run_all_rules(events, load_config(), assets)
    incidents = correlate_events(matches, events)
    bundles = [
        (
            incident,
            build_evidence_bundle(
                incident,
                score_incident(incident, matches, events, assets),
                matches,
                events,
            ),
        )
        for incident in incidents
    ]

    database = Database(path)
    database.init_schema()
    counts = database.save_upload(
        filename=SAMPLE_PATH.name,
        events=events,
        rejected=rejected,
        incidents=bundles,
    )
    for incident, _bundle in bundles:
        detail = database.get_incident(incident.incident_id)
        if detail is None:
            raise RuntimeError(
                f"demo incident {incident.incident_id!r} was not persisted"
            )
        database.save_cached_report(build_fallback_report(detail))

    return counts.events, counts.rejected, counts.incidents


def main() -> None:
    database_path = os.environ.get("CYBERSENTRY_DB_PATH", DEMO_DB_PATH)
    events, rejected, incidents = prepare_demo_database(database_path)
    print(
        f"Demo database ready: {events} events, {rejected} rejected, "
        f"{incidents} incidents; offline reports cached."
    )
    print("Start the frontend with: cd frontend && npm run dev")


if __name__ == "__main__":
    main()

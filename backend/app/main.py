"""CyberSentry AI backend — FastAPI application entry point.

Exposes the deterministic pipeline over HTTP: upload a log file, browse
incidents with their evidence, and fetch a rules-only report stub. The
API detects, correlates, scores, and reports — it never blocks,
quarantines, mutates data, or executes anything (AGENTS.md rule 4), and
with no LLM key configured every route works exactly the same
(AGENTS.md rule 5).

Persistence is SQLite via ``app.db``. Tests (and side-by-side runs) can
point the store elsewhere with the ``CYBERSENTRY_DB_PATH`` environment
variable.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from .correlate import correlate_events
from .db import Database
from .evidence import build_evidence_bundle
from .ingest import load_assets, load_events
from .llm import promptshield
from .llm.client import generate_report, llm_available
from .llm.fallback import build_fallback_report
from .nlp.classify import CLASSES, MODEL_ID, classify_messages
from .rules import load_config, run_all_rules
from .schema import ClassifyRequest, IncidentReport
from .scoring import score_incident

# Vite dev-server origins for the React frontend (frontend/).
DEV_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

SUPPORTED_SUFFIXES = frozenset({".csv", ".json", ".jsonl", ".ndjson"})

# Synthetic sample log files (data/, AGENTS.md rule 7) served so the
# frontend's "use sample dataset" button can upload one without
# bundling a second copy of the data.
DATA_DIR = Path(__file__).resolve().parents[2] / "data"
_NON_LOG_SAMPLES = frozenset({"assets.csv"})  # asset inventory, not logs

app = FastAPI(
    title="CyberSentry AI",
    description="Evidence-first security incident triage copilot.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=DEV_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_database() -> Database:
    """Open (once) the SQLite store on app.state.

    The path comes from ``CYBERSENTRY_DB_PATH`` when set — tests use a
    temp file so runs never touch each other — else the default file.
    """
    existing = getattr(app.state, "database", None)
    if existing is not None:
        return existing
    path = os.environ.get("CYBERSENTRY_DB_PATH")
    database = Database(path) if path else Database.default()
    database.init_schema()
    app.state.database = database
    return database


@app.post("/classify")
def classify(request: ClassifyRequest) -> dict[str, Any]:
    """Advisory message classification (NLP experiment integration).

    Returns one category per message among ``CLASSES`` with a
    confidence, or ``available=false`` plus a reason when the model or
    its optional dependencies are missing — fail-open, never an error.
    Deliberately outside the detection path: predictions do not change
    detections, scores, incidents, or reports (AGENTS.md rules 1, 3, 5).
    """
    predictions = classify_messages(request.messages)
    available = all(prediction.category is not None for prediction in predictions)
    reason = next(
        (prediction.reason for prediction in predictions if prediction.reason), ""
    )
    return {
        "available": available,
        "model": MODEL_ID if available else None,
        "classes": list(CLASSES),
        "reason": reason,
        "predictions": [
            {
                "message": prediction.message,
                "category": prediction.category,
                "confidence": prediction.confidence,
            }
            for prediction in predictions
        ],
    }


@app.get("/health")
def health() -> dict[str, Any]:
    """Liveness probe plus the optional-LLM capability flag.

    ``llm_available`` reflects whether an LLM API key is configured; the
    pipeline never depends on it.
    """
    return {
        "status": "ok",
        "service": "cybersentry-ai",
        "llm_available": llm_available(),
    }


@app.post("/upload")
def upload(
    file: UploadFile = File(...),
    database: Database = Depends(get_database),
) -> dict[str, Any]:
    """Ingest one log file, run the full pipeline, store, return counts.

    Pipeline: validate (ingest) -> detect (rules) -> correlate -> score
    -> evidence bundles. Events, rejected records, and incidents are all
    persisted; the response counts each stage.
    """
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in SUPPORTED_SUFFIXES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"unsupported log file type {suffix or '(no extension)'} "
                "(expected .csv, .json, .jsonl, or .ndjson)"
            ),
        )

    payload = file.file.read()
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
        handle.write(payload)
        temp_path = Path(handle.name)
    try:
        try:
            events, rejected = load_events(temp_path)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
    finally:
        temp_path.unlink(missing_ok=True)

    assets = load_assets()
    matches = run_all_rules(events, load_config(), assets)
    incidents = correlate_events(matches, events)
    bundles = [
        (
            incident,
            build_evidence_bundle(
                incident, score_incident(incident, matches, events, assets), matches, events
            ),
        )
        for incident in incidents
    ]

    counts = database.save_upload(
        filename=file.filename or "upload",
        events=events,
        rejected=rejected,
        incidents=bundles,
    )
    return {
        "filename": file.filename,
        "events": counts.events,
        "rejected": counts.rejected,
        "incidents": counts.incidents,
    }


@app.get("/samples")
def list_samples() -> list[dict[str, str]]:
    """Synthetic sample log files available for one-click upload."""
    return [
        {"name": path.name, "url": f"/samples/{path.name}"}
        for path in sorted(DATA_DIR.glob("*.csv"))
        if path.name not in _NON_LOG_SAMPLES
    ]


@app.get("/samples/{name}")
def get_sample(name: str) -> FileResponse:
    """Serve one synthetic sample log file from data/ by exact name.

    The name must be a plain basename of a supported log file directly
    inside data/ — no subdirectories or traversal (the data directory
    is synthetic-only, but the check keeps this route a mirror of the
    directory, nothing more).
    """
    if Path(name).name != name:
        raise HTTPException(status_code=404, detail=f"unknown sample: {name}")
    path = DATA_DIR / name
    if (
        path.suffix not in SUPPORTED_SUFFIXES
        or path.name in _NON_LOG_SAMPLES
        or not path.is_file()
    ):
        raise HTTPException(status_code=404, detail=f"unknown sample: {name}")
    return FileResponse(path, media_type="text/csv", filename=path.name)


@app.get("/incidents")
def list_incidents(database: Database = Depends(get_database)) -> list[dict[str, Any]]:
    """All stored incidents (highest score first): id, score, band,
    rules, entities, and event count."""
    return database.list_incidents()


@app.get("/incidents/{incident_id}")
def get_incident(
    incident_id: str, database: Database = Depends(get_database)
) -> dict[str, Any]:
    """Full evidence package for one incident: score with components,
    rule findings with reasons, and the ordered timeline.

    Injection-like text found in the timeline is not deleted: it is
    surfaced as ``injection_flags`` evidence items (each citing its
    event ID) plus ``review_notices`` for the analyst
    (``promptshield.scan_detail``).
    """
    detail = database.get_incident(incident_id)
    if detail is None:
        raise HTTPException(
            status_code=404, detail=f"unknown incident: {incident_id}"
        )
    flags, notices = promptshield.scan_detail(detail)
    detail["injection_flags"] = flags
    detail["review_notices"] = notices
    return detail


@app.post("/incidents/{incident_id}/report")
def create_report(
    incident_id: str, database: Database = Depends(get_database)
) -> IncidentReport:
    """Triage report for one incident — one schema, two paths.

    With an LLM endpoint configured, the report is generated over the
    stored evidence and every claim is validated against it; otherwise
    (or on any LLM failure) the deterministic rules-only template is
    returned, with `fallback: true` marking the template path. Nothing
    in the pipeline or the response depends on LLM availability
    (AGENTS.md rules 3 and 5).
    """
    detail = database.get_incident(incident_id)
    if detail is None:
        raise HTTPException(
            status_code=404, detail=f"unknown incident: {incident_id}"
        )
    mode = os.environ.get("CYBERSENTRY_REPORT_MODE", "live").strip().lower()
    if mode not in {"live", "cached"}:
        raise HTTPException(
            status_code=500,
            detail="CYBERSENTRY_REPORT_MODE must be 'live' or 'cached'",
        )
    if mode == "cached":
        cached = database.get_cached_report(incident_id)
        if cached is not None:
            return cached
        report = build_fallback_report(detail)
    else:
        report = generate_report(detail)
    database.save_cached_report(report)
    return report

"""CSV/JSON security log ingestion and validation.

Pipeline contract: ``load_events`` (or the format-specific loaders) returns a
``(valid_events, rejected_records)`` tuple. Malformed rows are never silently
coerced, dropped, or repaired — every bad row lands in the rejected list with
a reason and its original content, so nothing is hidden from the operator.

CSV parsing uses the stdlib ``csv`` module rather than pandas: the row shapes
are exact, and rows with the wrong field count are rejected with a reason
instead of being padded or skipped (parsing log data must not guess).

JSON parsing accepts a top-level array of objects (``.json``) or JSON Lines
(``.jsonl`` / ``.ndjson``). All ingested content is untrusted data; it is
only ever validated against the schema, never interpreted.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from pydantic import ValidationError

from .schema import Asset, Event, RejectedRecord

DEFAULT_ASSETS_PATH = Path(__file__).resolve().parents[2] / "data" / "assets.csv"

_JSON_SUFFIXES = frozenset({".json"})
_JSONL_SUFFIXES = frozenset({".jsonl", ".ndjson"})

_ASSET_COLUMNS = frozenset({"host", "criticality", "role"})


def _format_validation_error(exc: ValidationError) -> str:
    """Render a pydantic ValidationError as a concise rejection reason."""
    parts: list[str] = []
    for error in exc.errors():
        location = ".".join(str(item) for item in error["loc"])
        message = error["msg"]
        if message.startswith("Value error, "):
            message = message.removeprefix("Value error, ")
        parts.append(f"{location}: {message}" if location else message)
    return "; ".join(parts)


def _raw_view(record: Any) -> dict[str, Any]:
    """Best-effort mapping view of a raw record for the rejected list."""
    if isinstance(record, Mapping):
        return dict(record)
    return {"_raw": record}


def _build_event(record: Any) -> Event:
    """Validate one raw record; raise ValueError with the reason if malformed."""
    if not isinstance(record, Mapping):
        raise ValueError(f"record is not an object: {record!r}")
    try:
        return Event.model_validate(dict(record))
    except ValidationError as exc:
        raise ValueError(_format_validation_error(exc)) from None


def _ingest_pairs(
    pairs: Iterable[tuple[int | None, Any]], *, source: str | None
) -> tuple[list[Event], list[RejectedRecord]]:
    """Validate (row_number, record) pairs; reject duplicates and malformed rows."""
    valid: list[Event] = []
    rejected: list[RejectedRecord] = []
    seen_ids: set[str] = set()
    for row_number, record in pairs:
        raw = _raw_view(record)
        try:
            event = _build_event(record)
        except ValueError as exc:
            rejected.append(
                RejectedRecord(
                    reason=str(exc), record=raw, row=row_number, source=source
                )
            )
            continue
        if event.event_id in seen_ids:
            rejected.append(
                RejectedRecord(
                    reason=f"duplicate event_id: {event.event_id!r}",
                    record=raw,
                    row=row_number,
                    source=source,
                )
            )
            continue
        seen_ids.add(event.event_id)
        valid.append(event)
    return valid, rejected


def parse_records(
    records: Iterable[Any], *, source: str | None = None
) -> tuple[list[Event], list[RejectedRecord]]:
    """Validate an iterable of raw record objects.

    Returns ``(valid_events, rejected_records)``. Rows are numbered 1..n in
    record order. Duplicate event IDs (among accepted events) are rejected.
    """
    return _ingest_pairs(enumerate(records, start=1), source=source)


def load_csv(path: str | Path) -> tuple[list[Event], list[RejectedRecord]]:
    """Load and validate a CSV log file.

    The first row is the header; column names are trimmed and lowercased.
    Rows with the wrong field count are rejected, not repaired. An empty file
    raises ValueError (there is nothing to ingest).
    """
    path = Path(path)
    source = str(path)
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.reader(handle))
    if not rows:
        raise ValueError(f"{source}: CSV file is empty (no header row)")
    header = [column.strip().lower() for column in rows[0]]
    if not any(header):
        raise ValueError(f"{source}: CSV header row is empty")

    pairs: list[tuple[int | None, Any]] = []
    shape_rejections: list[RejectedRecord] = []
    for line_number, row in enumerate(rows[1:], start=2):
        if not any(cell.strip() for cell in row):
            continue  # blank line is not a record
        if len(row) != len(header):
            shape_rejections.append(
                RejectedRecord(
                    reason=(
                        f"expected {len(header)} fields, found {len(row)}"
                    ),
                    record={"_raw": ",".join(row)},
                    row=line_number,
                    source=source,
                )
            )
            continue
        pairs.append((line_number, dict(zip(header, row))))

    valid, rejected = _ingest_pairs(pairs, source=source)
    rejected.extend(shape_rejections)
    rejected.sort(key=lambda item: item.row or 0)
    return valid, rejected


def load_json(path: str | Path) -> tuple[list[Event], list[RejectedRecord]]:
    """Load a JSON log file containing a top-level array of event objects."""
    path = Path(path)
    source = str(path)
    text = path.read_text(encoding="utf-8")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source}: invalid JSON: {exc}") from None
    if not isinstance(payload, list):
        raise ValueError(
            f"{source}: expected a top-level JSON array of event objects, "
            f"got {type(payload).__name__}"
        )
    return parse_records(payload, source=source)


def load_jsonl(path: str | Path) -> tuple[list[Event], list[RejectedRecord]]:
    """Load a JSON Lines log file (one event object per line)."""
    path = Path(path)
    source = str(path)
    pairs: list[tuple[int | None, Any]] = []
    decode_rejections: list[RejectedRecord] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = line.strip()
        if not stripped:
            continue  # blank line is not a record
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            decode_rejections.append(
                RejectedRecord(
                    reason=f"invalid JSON: {exc.msg}",
                    record={"_raw": stripped},
                    row=line_number,
                    source=source,
                )
            )
            continue
        pairs.append((line_number, payload))

    valid, rejected = _ingest_pairs(pairs, source=source)
    rejected.extend(decode_rejections)
    rejected.sort(key=lambda item: item.row or 0)
    return valid, rejected


def load_events(path: str | Path) -> tuple[list[Event], list[RejectedRecord]]:
    """Load a log file, dispatching on extension (.csv, .json, .jsonl, .ndjson)."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return load_csv(path)
    if suffix in _JSON_SUFFIXES:
        return load_json(path)
    if suffix in _JSONL_SUFFIXES:
        return load_jsonl(path)
    raise ValueError(
        f"{path}: unsupported log file type {suffix or '(no extension)'} "
        "(expected .csv, .json, .jsonl, or .ndjson)"
    )


def load_assets(path: str | Path = DEFAULT_ASSETS_PATH) -> dict[str, Asset]:
    """Load data/assets.csv (columns: host, criticality 1-5, role).

    Returns a mapping of normalized (lowercased, trimmed) host to Asset.
    Assets are trusted reference data, not an event stream, so malformed
    rows fail loudly with a ValueError instead of being silently skipped —
    a silently dropped row would corrupt downstream scoring.
    """
    path = Path(path)
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.reader(handle))
    if not rows:
        raise ValueError(f"{path}: assets file is empty (no header row)")
    header = [column.strip().lower() for column in rows[0]]
    missing = _ASSET_COLUMNS - set(header)
    if missing:
        raise ValueError(
            f"{path}: missing required column(s): {', '.join(sorted(missing))}"
        )

    assets: dict[str, Asset] = {}
    errors: list[str] = []
    for line_number, row in enumerate(rows[1:], start=2):
        if not any(cell.strip() for cell in row):
            continue
        if len(row) != len(header):
            errors.append(
                f"line {line_number}: expected {len(header)} fields, "
                f"found {len(row)}"
            )
            continue
        try:
            asset = Asset.model_validate(dict(zip(header, row)))
        except ValidationError as exc:
            errors.append(f"line {line_number}: {_format_validation_error(exc)}")
            continue
        if asset.host in assets:
            errors.append(f"line {line_number}: duplicate host {asset.host!r}")
            continue
        assets[asset.host] = asset
    if errors:
        raise ValueError(f"{path}: invalid asset data — " + "; ".join(errors))
    return assets

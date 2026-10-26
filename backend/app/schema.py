"""Pydantic models for events, incidents, and reports.

This module is the ingestion boundary: everything that enters the pipeline
from a log file is validated here. Validation is strict and *rejects*
malformed input with an explanatory error — it never silently coerces
attacker-controllable data (every ingested log field is untrusted by design).

Documented normalizations (the only allowed mutations of ingested data):

* ``user`` and ``host`` are trimmed and lowercased.
* ``timestamp`` must be ISO 8601 and is normalized to UTC; naive timestamps
  are interpreted as UTC.
* ``src_ip`` must be a valid IPv4 or IPv6 address, stored in canonical form.
* ``severity`` is an int in [0, 10], defaulting to 3 when absent. Integer
  literal strings (e.g. CSV cells) are accepted; anything else is rejected.
* ``message`` is truncated to ``MAX_MESSAGE_LENGTH`` characters.
* A missing or blank ``event_id`` is generated and flagged via
  ``event_id_generated``; duplicate IDs are rejected at ingest time.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any, Literal, Mapping
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_MESSAGE_LENGTH = 1000
# Event IDs are cited by the model and shown verbatim: no free text in them.
_EVENT_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")
MIN_SEVERITY = 0
MAX_SEVERITY = 10
DEFAULT_SEVERITY = 3
MIN_CRITICALITY = 1
MAX_CRITICALITY = 5

_TRUTHY_STRINGS = frozenset({"true", "1"})
_FALSY_STRINGS = frozenset({"false", "0"})


class EventType(str, Enum):
    """Deterministic event taxonomy used by detection rules."""

    LOGIN_FAILED = "login_failed"
    LOGIN_SUCCESS = "login_success"
    PRIVILEGE_CHANGE = "privilege_change"
    PROCESS_START = "process_start"
    FILE_ACCESS = "file_access"
    ALERT = "alert"
    OTHER = "other"


def _parse_int(value: Any, field_name: str) -> int:
    """Return ``value`` as an int or raise; never coerces non-literal input."""
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer, got {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text and (text.lstrip("+-").isdigit()):
            return int(text)
    raise ValueError(f"{field_name} must be an integer, got {value!r}")


class Event(BaseModel):
    """A single validated security log event.

    ``timestamp`` is always UTC-aware. ``event_id_generated`` flags IDs that
    were synthesized at ingest because the source record did not supply one.
    """

    model_config = ConfigDict(strict=True)

    event_id: str
    event_id_generated: bool = False
    timestamp: datetime
    event_type: EventType
    user: str
    host: str
    src_ip: str
    severity: int = DEFAULT_SEVERITY
    message: str = ""
    privileged: bool | None = None

    @model_validator(mode="before")
    @classmethod
    def _generate_missing_event_id(cls, data: Any) -> Any:
        """Synthesize (and flag) an event_id when the record omits one."""
        if isinstance(data, Mapping):
            record = dict(data)
            raw_id = record.get("event_id")
            if raw_id is None or (isinstance(raw_id, str) and not raw_id.strip()):
                record["event_id"] = f"evt-{uuid4().hex}"
                record["event_id_generated"] = True
            return record
        return data

    @field_validator("event_id", mode="before")
    @classmethod
    def _validate_event_id(cls, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"event_id must be a non-empty string, got {value!r}")
        if not _EVENT_ID_RE.fullmatch(value.strip()):
            raise ValueError(
                "event_id must be 1-128 chars of letters, digits, '.', '_', ':', '-'"
            )
        return value.strip()

    @field_validator("timestamp", mode="before")
    @classmethod
    def _validate_timestamp(cls, value: Any) -> datetime:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str):
            text = value.strip()
            if not text:
                raise ValueError("timestamp is required (ISO 8601)")
            if text[-1] in "Zz":
                text = text[:-1] + "+00:00"
            try:
                parsed = datetime.fromisoformat(text)
            except ValueError:
                raise ValueError(
                    f"invalid ISO 8601 timestamp: {value!r}"
                ) from None
        else:
            raise ValueError(
                f"invalid ISO 8601 timestamp: {value!r} (expected a string)"
            )
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @field_validator("event_type", mode="before")
    @classmethod
    def _validate_event_type(cls, value: Any) -> EventType:
        if isinstance(value, EventType):
            return value
        if isinstance(value, str):
            try:
                return EventType(value.strip().lower())
            except ValueError:
                pass
        allowed = ", ".join(member.value for member in EventType)
        raise ValueError(f"unknown event_type: {value!r} (expected one of: {allowed})")

    @field_validator("user", "host")
    @classmethod
    def _normalize_identity(cls, value: str) -> str:
        text = value.strip().lower()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("src_ip", mode="before")
    @classmethod
    def _validate_src_ip(cls, value: Any) -> str:
        if isinstance(value, (IPv4Address, IPv6Address)):
            return str(value)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                raise ValueError("src_ip is required")
            try:
                return str(ip_address(text))
            except ValueError:
                raise ValueError(
                    f"invalid src_ip: {value!r} (expected an IPv4 or IPv6 address)"
                ) from None
        raise ValueError(f"invalid src_ip: {value!r} (expected a string)")

    @field_validator("severity", mode="before")
    @classmethod
    def _validate_severity(cls, value: Any) -> int:
        if value is None or (isinstance(value, str) and not value.strip()):
            return DEFAULT_SEVERITY
        severity = _parse_int(value, "severity")
        if not MIN_SEVERITY <= severity <= MAX_SEVERITY:
            raise ValueError(
                f"severity must be between {MIN_SEVERITY} and {MAX_SEVERITY}, "
                f"got {severity}"
            )
        return severity

    @field_validator("message", mode="before")
    @classmethod
    def _validate_message(cls, value: Any) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            raise ValueError(f"message must be a string, got {value!r}")
        return value[:MAX_MESSAGE_LENGTH]

    @field_validator("privileged", mode="before")
    @classmethod
    def _validate_privileged(cls, value: Any) -> bool | None:
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            text = value.strip().lower()
            if text in _TRUTHY_STRINGS:
                return True
            if text in _FALSY_STRINGS:
                return False
        raise ValueError(
            f"invalid privileged value: {value!r} (expected true or false)"
        )


class RejectedRecord(BaseModel):
    """A raw record that failed validation, with a human-readable reason.

    Rejected records are never dropped silently: they are surfaced to the
    operator exactly as ingested (``record``), so nothing is hidden.
    """

    reason: str
    record: dict[str, Any]
    row: int | None = None
    source: str | None = None


class Asset(BaseModel):
    """Reference row from data/assets.csv: host criticality and role."""

    model_config = ConfigDict(strict=True)

    host: str
    criticality: int
    role: str

    @field_validator("host", "role")
    @classmethod
    def _normalize_text(cls, value: str) -> str:
        text = value.strip().lower()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("criticality", mode="before")
    @classmethod
    def _validate_criticality(cls, value: Any) -> int:
        criticality = _parse_int(value, "criticality")
        if not MIN_CRITICALITY <= criticality <= MAX_CRITICALITY:
            raise ValueError(
                f"criticality must be between {MIN_CRITICALITY} and "
                f"{MAX_CRITICALITY}, got {criticality}"
            )
        return criticality


# Report schema (LLM output and the rules-only fallback share it).
ReportConfidence = Literal["low", "medium", "high"]


class ObservedFact(BaseModel):
    """One factual claim in a report, citing the events it rests on.

    ``evidence_ids`` must resolve to real event IDs from the incident's
    evidence bundle: claims citing unknown IDs are dropped, and claims
    citing nothing at all are downgraded to hypotheses, by
    ``app.llm.validate`` (AGENTS.md rule 3). Unknown fields are rejected.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    text: str
    evidence_ids: list[str]


class Hypothesis(BaseModel):
    """A possible explanation, with a confidence and its evidence.

    A hypothesis is a possibility, not a conclusion — the observed
    sequence of events is never presented as proof of compromise.
    Unknown fields are rejected.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    text: str
    confidence: ReportConfidence
    evidence_ids: list[str]


class IncidentReport(BaseModel):
    """The triage report: one schema for the LLM path and the fallback.

    The required JSON output is ``summary``, ``observed_facts``,
    ``hypotheses``, ``alternative_explanations``, ``unknowns``,
    ``recommended_checks``, and ``evidence_sufficient``; ``incident_id``
    and ``fallback`` are added by the system. ``fallback=True`` marks the
    deterministic rules-only template (no LLM was involved).

    The schema is the contract: unknown fields are rejected, and there is
    deliberately no score field — the score only ever comes from code.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    incident_id: str
    summary: str
    observed_facts: list[ObservedFact]
    hypotheses: list[Hypothesis]
    alternative_explanations: list[str]
    unknowns: list[str]
    recommended_checks: list[str]
    evidence_sufficient: bool
    fallback: bool


class ClassifyRequest(BaseModel):
    """Body for POST /classify: raw log messages to classify (advisory).

    A small batch helper, not a bulk job: per the integration rule the
    classifier never touches detection, scoring, or reports — it only
    answers what category a message's text reads like.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    messages: list[str] = Field(min_length=1, max_length=50)

    @field_validator("messages")
    @classmethod
    def clean_messages(cls, value: list[str]) -> list[str]:
        """Strip, reject empties, and cap each message like ingest does."""
        cleaned = [message.strip() for message in value]
        if any(not message for message in cleaned):
            raise ValueError("messages must be non-empty after stripping")
        return [message[:MAX_MESSAGE_LENGTH] for message in cleaned]

"""Prompt shield: log text is untrusted data and must never be treated as
instructions to the model or the system.

Every field ingested from logs — messages, hostnames, usernames, IPs — is
attacker-controllable (AGENTS.md rule 2). The shield enforces that in four
places:

1. **Sanitizing** — ``strip_control_chars`` / ``sanitize_text`` remove
   control, zero-width, and bidirectional-override characters (a classic
   evasion trick for hiding phrases from detectors or spoofing output) and
   cap every untrusted field to ``MAX_FIELD_LENGTH``.
2. **Fencing** — ``fence_untrusted`` wraps the payload in a nonce-marked
   block whose closing marker carries a per-call random token the log
   author cannot know, and any payload text that imitates the ``<<<`` /
   ``>>>`` delimiters is neutralized to fullwidth look-alikes before the
   block is closed, so nothing can terminate it or pose as its markers.
3. **Message roles** — ``build_messages`` keeps authored instructions in
   the ``system`` role and event content in the ``user`` role, and never
   attaches tools: the model cannot call anything (AGENTS.md rule 4).
4. **Detection** — ``detect_injection`` is a heuristic phrase detector
   (ignore-previous, mark-safe, system-prompt, you-are-now, ...). A hit
   never changes a detection, a score, or an alert (AGENTS.md rule 1);
   it becomes an ``injection_flag`` evidence item citing the concrete
   event ID, plus a review notice shown to the analyst — the offending
   text is kept as data, never silently deleted.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any
from uuid import uuid4

from ..schema import MAX_MESSAGE_LENGTH

OPEN_TEMPLATE = "<<<BEGIN UNTRUSTED {label} nonce={nonce}>>>"
CLOSE_TEMPLATE = "<<<END UNTRUSTED {label} nonce={nonce}>>>"

# Cap applied to every untrusted field carried into a prompt. Matches the
# ingest-side message cap so prompt and evidence agree.
MAX_FIELD_LENGTH = MAX_MESSAGE_LENGTH

# Marker of an injection flag evidence item.
INJECTION_FLAG = "injection_flag"

# Record fields that carry attacker-controllable text (the message is
# quarantined in ``untrusted_text`` by the evidence bundle).
UNTRUSTED_FIELDS = ("untrusted_text", "message", "user", "host")

# C0 controls except tab/newline, DEL + C1, zero-width chars, and
# bidirectional overrides — stripped everywhere untrusted text flows.
_CONTROL_CHARS_RE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f"
    "\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"
)

# Any run of the fence's angle-bracket delimiters inside a payload.
_FENCE_IMITATION_RE = re.compile(r"<<<|>>>")

# Heuristic injection phrases -> stable labels. Over-eager by design:
# a hit produces a review notice, never a score change or an alert.
_PATTERN_STRINGS: tuple[tuple[str, str], ...] = (
    ("ignore_previous", r"ignore[\s\-_]+(?:all[\s\-_]+)?previous"),
    ("ignore_rules", r"ignore[\s\-_]+(?:all[\s\-_]+)?(?:detection[\s\-_]+)?rules"),
    ("disregard_rules", r"disregard\s+(?:all\s+)?(?:the\s+)?(?:detection\s+)?rules"),
    ("stop_alerting", r"stop\s+alerting|do\s+not\s+alert|no\s+longer\s+alert"),
    (
        "mark_safe",
        r"mark[\s\-_]+(?:this[\s\-_]+)?incident[\s\-_]+safe"
        r"|mark[\s\-_]+benign"
        r"|declare\s+this\s+incident\s+safe"
        r"|classification\s*=\s*benign",
    ),
    (
        "safe_verdict_command",
        r"declare\s+\S+\s+safe"
        r"|classify\w*\s+(?:all\s+)?(?:following\s+)?events?\s+as\s+safe"
        r"|verdict[\"']?\s*[:=]\s*[\"']?safe",
    ),
    ("system_prompt", r"system\s+prompt"),
    ("you_are_now", r"you\s+are\s+now"),
    ("new_instructions", r"new\s+instructions"),
    ("roleplay", r"role[\s\-]?play|in\s+character|jailbreak"),
    ("end_of_log", r"end\s+of\s+(?:the\s+)?logs?|closing\s+brace|everything\s+after\s+is"),
    # Only system/assistant impersonation; a leading "user:" label is
    # common in routine log lines and is not on its own injection-like.
    ("fake_role_marker", r"^\s*(?:system|assistant)\s*:"),
    ("decode_and_follow", r"decode\s+and\s+follow|base64"),
    (
        "admin_override",
        r"admin\s+override|severity\s*=\s*0|auto[\s\-]?closed|reply\s+confirmed",
    ),
    (
        "fake_directive_tag",
        r"<\s*/?\s*(?:safe_mode|ignore_rules)|apply\s+this\s+directive|output\s+only",
    ),
    ("safe_mode", r"safe[\s\-_]+mode"),
    ("sql_injection", r"\"\s*(?:or|and)\s+\"|\b\d\s*=\s*\d\b"),
    ("false_positive_claim", r"known\s+false\s+positive|is\s+a\s+false\s+positive"),
)

INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (label, re.compile(pattern, re.IGNORECASE))
    for label, pattern in _PATTERN_STRINGS
)


@dataclass(frozen=True)
class InjectionFlag:
    """One injection_flag evidence item: text in a concrete event that
    matched the heuristic detector.

    ``flag`` is always ``injection_flag``; ``event_id`` ties the item to
    the incident's timeline (AGENTS.md rule 3); ``patterns`` lists the
    matched labels; ``text`` is the sanitized offending field, kept as
    data — never deleted, never obeyed.
    """

    event_id: str
    field: str
    patterns: tuple[str, ...]
    text: str
    flag: str = INJECTION_FLAG

    def as_dict(self) -> dict[str, Any]:
        """JSON-ready form for API responses."""
        return asdict(self)


def new_nonce() -> str:
    """A fresh unpredictable token for one fence."""
    return uuid4().hex[:16]


def strip_control_chars(text: str) -> str:
    """Remove control, zero-width, and bidi-override characters.

    Tab and newline survive (they are legitimate content); everything an
    attacker could use to hide text from the detector or spoof the
    terminal is dropped.
    """
    return _CONTROL_CHARS_RE.sub("", text)


def sanitize_text(value: str, *, max_length: int = MAX_FIELD_LENGTH) -> str:
    """Strip control characters and cap the length of one untrusted field."""
    cleaned = strip_control_chars(value)
    return cleaned if len(cleaned) <= max_length else cleaned[:max_length]


def sanitize_fields(
    value: Any, *, max_length: int = MAX_FIELD_LENGTH
) -> Any:
    """Recursively sanitize every string in a JSON-like structure.

    Applied to the evidence block before it is serialized into a prompt,
    so no untrusted field reaches the model longer than the cap or
    carrying control characters.
    """
    if isinstance(value, str):
        return sanitize_text(value, max_length=max_length)
    if isinstance(value, Mapping):
        return {
            key: sanitize_fields(item, max_length=max_length)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_fields(item, max_length=max_length) for item in value]
    return value


def _neutralize_delimiters(payload: str) -> str:
    """Replace ``<<<``/``>>>`` runs with fullwidth look-alikes.

    Payload text that imitates the fence's delimiters can then neither
    terminate the block nor pose as its markers; the genuine markers
    (added by ``fence_untrusted``) are unaffected.
    """
    return _FENCE_IMITATION_RE.sub(
        lambda m: ("＜" if m.group(0) == "<<<" else "＞") * len(m.group(0)),
        payload,
    )


def fence_untrusted(payload: str, *, label: str, nonce: str) -> str:
    """Wrap untrusted ``payload`` in a nonce-marked fence.

    The payload is stripped of control characters and any text imitating
    the ``<<<``/``>>>`` delimiters is neutralized before the block is
    closed. The result is data and only data: the caller places it where
    the template says the evidence block goes, never inside instruction
    text. ``nonce`` must come from ``new_nonce()`` (or a test-chosen
    fixed value) so no payload can forge the closing marker.
    """
    if not label:
        raise ValueError("fence label must not be empty")
    if not nonce:
        raise ValueError("fence nonce must not be empty")
    safe_payload = _neutralize_delimiters(strip_control_chars(payload))
    open_marker = OPEN_TEMPLATE.format(label=label, nonce=nonce)
    close_marker = CLOSE_TEMPLATE.format(label=label, nonce=nonce)
    return f"{open_marker}\n{safe_payload}\n{close_marker}"


def build_messages(system_prompt: str, user_prompt: str) -> list[dict[str, str]]:
    """Instructions and event content in separate message roles.

    The ``system`` role carries only authored instructions; the ``user``
    role carries the fenced evidence block. No tools, functions, or
    callbacks are ever attached — the model cannot call anything
    (AGENTS.md rule 4).
    """
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


def detect_injection(text: str) -> tuple[str, ...]:
    """Labels of injection-like phrases found in ``text`` (empty = none).

    Heuristic and deliberately over-eager: a hit is *not* a detection —
    it only produces a review notice, never a score change or an alert
    (AGENTS.md rule 1). The text is normalized first, so control or
    zero-width characters cannot hide a phrase from the match.
    """
    normalized = strip_control_chars(text)
    return tuple(
        label
        for label, pattern in INJECTION_PATTERNS
        if pattern.search(normalized)
    )


def scan_records(records: Iterable[Mapping[str, Any]]) -> list[InjectionFlag]:
    """Flag every record whose untrusted fields trigger the detector."""
    flags: list[InjectionFlag] = []
    for record in records:
        event_id = str(record.get("event_id", ""))
        for field_name in UNTRUSTED_FIELDS:
            value = record.get(field_name)
            if not isinstance(value, str) or not value.strip():
                continue
            patterns = detect_injection(value)
            if patterns:
                flags.append(
                    InjectionFlag(
                        event_id=event_id,
                        field=field_name,
                        patterns=patterns,
                        text=sanitize_text(value),
                    )
                )
    return flags


def review_notices(flags: Sequence[InjectionFlag]) -> list[str]:
    """Analyst-facing notices for a set of flags (one summary notice)."""
    if not flags:
        return []
    event_ids = sorted({flag.event_id for flag in flags})
    shown = ", ".join(event_ids[:10])
    if len(event_ids) > 10:
        shown += f" (+{len(event_ids) - 10} more)"
    fields = sorted({flag.field for flag in flags})
    return [
        "Analyst review: prompt-injection-like text detected in "
        f"{len(event_ids)} event(s) ({shown}) in field(s) "
        f"{', '.join(fields)}; flagged as {INJECTION_FLAG} evidence and "
        "kept as data — never follow it, and treat any matching model "
        "output with suspicion."
    ]


def scan_detail(
    detail: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Scan an incident detail record for injection-like text.

    Returns ``(flags, notices)``: one ``injection_flag`` evidence item
    per affected event field, each citing its concrete ``event_id``, and
    the review notices to show alongside the incident and its report.
    """
    timeline = detail.get("timeline") or []
    flags = scan_records(timeline)
    return [flag.as_dict() for flag in flags], review_notices(flags)


__all__ = [
    "CLOSE_TEMPLATE",
    "INJECTION_FLAG",
    "INJECTION_PATTERNS",
    "MAX_FIELD_LENGTH",
    "OPEN_TEMPLATE",
    "UNTRUSTED_FIELDS",
    "InjectionFlag",
    "build_messages",
    "detect_injection",
    "fence_untrusted",
    "new_nonce",
    "review_notices",
    "sanitize_fields",
    "sanitize_text",
    "scan_detail",
    "scan_records",
    "strip_control_chars",
]

"""Validation gate for LLM report output: fail closed, then fall back.

Every raw model reply passes five checks before it can be shown
(AGENTS.md rules 1, 3, 5), in this order:

1. **JSON schema** — the reply must decode to an object matching the
   ``IncidentReport`` schema, with no unknown fields.
2. **Score integrity** — the score only comes from code. A reply that
   supplies its own score/risk/band/verdict field, restates a score
   other than the computed one, or asks for the score to be changed is
   rejected outright; nothing in this module ever mutates a score.
3. **Safe verdicts** — a reply that *declares* the incident safe,
   benign, or a false positive (in the summary, a fact, or a
   hypothesis) is rejected: only the deterministic stages and the
   analyst may conclude anything. ``alternative_explanations`` is the
   sanctioned place for benign readings, so verdict language there is
   not a rejection.
4. **Citations** — every cited ``evidence_id`` must exist in the
   incident's timeline. Claims citing unknown IDs are removed and the
   removal recorded; an observed fact with *no* citations is
   downgraded to a hypothesis (confidence ``low``) rather than kept
   as a fact.
5. **Grounding** — a reply left with no cited observed fact is
   unusable.

Every check failure and repair becomes a ``ValidationIssue``.
``complete_validated`` runs this gate with **one retry**: a reply that
fails any check is retried once, and if the second reply also fails,
the deterministic template report is returned with ``fallback=True``.
The ``ValidationReport`` returned alongside lists — per check — what
was rejected, removed, or downgraded on the way (AGENTS.md rule 5:
model output is discarded when unverifiable; the pipeline never breaks).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from ..schema import Hypothesis, IncidentReport, ObservedFact, ReportConfidence
from . import prompts
from .fallback import build_fallback_report

# One retry: at most two replies are validated before falling back.
MAX_VALIDATION_RETRIES = 1

# Issue codes (stable, machine-readable).
CODE_SCHEMA = "schema_error"
CODE_SCORE_TAMPER = "score_tamper"
CODE_SAFE_VERDICT = "safe_verdict"
CODE_UNKNOWN_EVIDENCE = "unknown_evidence_id"
CODE_UNCITED_FACT = "uncited_fact"
CODE_NO_GROUNDED_CLAIMS = "no_grounded_claims"
CODE_TEMPLATE_FALLBACK = "template_fallback"

# Issue actions: rejected (reply discarded), dropped (claim removed),
# downgraded (fact demoted to hypothesis).
ACTION_REJECTED = "rejected"
ACTION_DROPPED = "dropped"
ACTION_DOWNGRADED = "downgraded"

# Top-level keys the model is never allowed to supply: they would be a
# score/band/verdict handed in by the LLM instead of computed by code.
_SCORE_KEYS = frozenset(
    {
        "band",
        "disposition",
        "risk",
        "risk_band",
        "risk_level",
        "risk_rating",
        "safe",
        "severity",
        "threat_level",
        "verdict",
    }
)

# Confidence for a fact that could not cite anything.
_DOWNGRADED_CONFIDENCE: ReportConfidence = "low"

# "the score should be lowered", "adjust the risk score", "re-score", ...
_SCORE_EDIT_RE = re.compile(
    r"\b\w*(?:chang|adjust|lowere?|rais|reduc|increas|overrid|updat|revis|"
    r"amend|replac|recalculat)\w*\s+(?:the\s+)?(?:risk\s+|overall\s+|final\s+)?"
    r"score\b"
    r"|\b(?:re-?scor\w+|score\s+resubmission)\b"
    r"|\bscore\s+(?:should|must|ought)\s+be\b"
    r"|\bscore\s+needs?\s+to\s+be\b"
    r"|\bscore\s+(?:would|could)\s+be\s+(?:chang|adjust|lowere?|rais|reduc|"
    r"increas|set|overrid|updat|revis|reduc|replac|recalculat)\w*",
    re.IGNORECASE,
)

# Any score value stated in the output; it must equal the code-computed one.
_SCORE_VALUE_RE = re.compile(
    r"\b(\d{1,3})\s*/\s*100\b|\bscore\s*(?:of\s+|is\s+|[:=]\s*|to\s+)?(\d{1,3})\b",
    re.IGNORECASE,
)

# Declarative safe/benign verdicts. Only matched in the conclusion fields
# (summary, observed facts, hypotheses); narrative fields may argue a
# benign reading as one possibility among others.
_SAFE_VERDICT_RE = re.compile(
    r"\b(?:is|are|was|were|remains?|stays?)\s+(?:apparently\s+|clearly\s+|"
    r"entirely\s+|fully\s+|completely\s+)?(?:safe|benign)\b"
    r"|\bno\s+(?:signs?|indicators?|evidence)\s+of\s+(?:compromise|attack|"
    r"intrusion|malicious\s+activity)\b"
    r"|\b(?:not\s+compromised|no\s+compromise|no\s+breach)\b"
    r"|\bfalse[\s-]?positive\b"
    r"|\bsafe\s+to\s+(?:ignore|dismiss|close|close\s+out)\b"
    r"|\ball\s+clear\b"
    r"|\bcan\s+be\s+(?:ignored|dismissed|closed)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ValidationIssue:
    """One thing the validator rejected, removed, or downgraded."""

    code: str
    action: str
    message: str


@dataclass(frozen=True)
class ValidationReport:
    """What validation did to the output, for auditing and tests.

    ``ok`` is True only when the reply survived every check and is the
    report being returned (the template is not "ok" — it is the
    fallback). ``retries_used`` counts retries actually spent.
    ``issues`` lists every rejection, removal, and downgrade across all
    attempts, in order.
    """

    ok: bool
    retries_used: int = 0
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def rejections(self) -> tuple[ValidationIssue, ...]:
        """Issues that made a whole reply unusable."""
        return tuple(issue for issue in self.issues if issue.action == ACTION_REJECTED)

    @property
    def changes(self) -> tuple[str, ...]:
        """One entry per repair applied to an accepted reply."""
        return tuple(
            issue.message
            for issue in self.issues
            if issue.action in (ACTION_DROPPED, ACTION_DOWNGRADED)
        )

    @property
    def changed(self) -> bool:
        """True when claims were removed or downgraded."""
        return bool(self.changes)


def validate_output(
    raw_text: str,
    *,
    incident_id: str,
    known_event_ids: set[str],
    score: int,
) -> tuple[IncidentReport | None, ValidationReport]:
    """Run all five checks over one raw reply.

    Returns ``(report, validation_report)``. ``report`` is None when the
    reply was rejected — by a schema violation, a score change, a safe
    verdict, or because no claim survived citation repair — in which
    case ``validation_report.ok`` is False and its ``issues`` say why.
    """
    # 1. JSON schema: must decode to an object.
    try:
        payload = prompts.load_reply(raw_text)
    except ValueError as exc:
        return _rejected(CODE_SCHEMA, str(exc))

    # 2. Score integrity — field-level attempt, before anything else can
    # mask it as a generic schema error. The score only comes from code.
    score_keys = sorted(
        key for key in payload if "score" in key.lower() or key.lower() in _SCORE_KEYS
    )
    if score_keys:
        return _rejected(
            CODE_SCORE_TAMPER,
            f"reply tried to supply score/verdict field(s) "
            f"{', '.join(score_keys)}; the score only comes from code",
        )

    # 1. (continued) validate against the report schema, strictly.
    try:
        report = prompts.parse_report(raw_text, incident_id=incident_id)
    except ValueError as exc:
        return _rejected(CODE_SCHEMA, str(exc))

    # 2. Score integrity — value-level attempt in the text.
    score_issue = _score_text_issue(report, score)
    if score_issue is not None:
        return None, ValidationReport(
            ok=False, issues=(score_issue,)
        )

    # 3. Safe verdict declared in a conclusion field.
    verdict_issue = _verdict_text_issue(report)
    if verdict_issue is not None:
        return None, ValidationReport(
            ok=False, issues=(verdict_issue,)
        )

    # 4. Citations: remove claims citing unknown events, downgrade facts
    # citing none. Nothing is repaired or invented.
    report, repairs = _repair_claims(report, known_event_ids)

    # 5. Grounding: without a single cited observed fact the reply is
    # unusable — retrying or falling back is the caller's decision.
    if not report.observed_facts:
        return None, ValidationReport(
            ok=False,
            issues=(
                *repairs,
                ValidationIssue(
                    code=CODE_NO_GROUNDED_CLAIMS,
                    action=ACTION_REJECTED,
                    message=(
                        "no observed fact in the reply cited the incident's "
                        "evidence; reply discarded"
                    ),
                ),
            ),
        )
    return report, ValidationReport(ok=True, issues=tuple(repairs))


def complete_validated(
    get_reply: Callable[[], str], *, detail: Mapping[str, Any]
) -> tuple[IncidentReport, ValidationReport]:
    """Fetch a reply, validate it, retry once, else use the template.

    ``get_reply`` produces one raw reply per attempt (transport retries
    live inside the client; this loop retries *validation* failures).
    A reply that fails any check is retried once — at most
    ``MAX_VALIDATION_RETRIES`` extra attempts — and if no reply
    survives, the deterministic rules-only template report is returned
    with ``fallback=True``. The returned ``ValidationReport`` aggregates
    the issues of every attempt and records how many retries were spent.

    Transport/provider errors raised by ``get_reply`` propagate to the
    caller, which falls back the same way (AGENTS.md rule 5).
    """
    incident_id = str(detail["incident_id"])
    known_event_ids = {entry["event_id"] for entry in detail["timeline"]}
    score = int(detail["score"]["score"])

    attempts = MAX_VALIDATION_RETRIES + 1
    collected: list[ValidationIssue] = []
    for attempt in range(attempts):
        raw = get_reply()
        report, check = validate_output(
            raw,
            incident_id=incident_id,
            known_event_ids=known_event_ids,
            score=score,
        )
        collected.extend(check.issues)
        if report is not None:
            return report, ValidationReport(
                ok=True, retries_used=attempt, issues=tuple(collected)
            )

    collected.append(
        ValidationIssue(
            code=CODE_TEMPLATE_FALLBACK,
            action=ACTION_REJECTED,
            message=(
                f"no reply passed validation after {attempts} attempt(s); "
                "deterministic template report used instead"
            ),
        )
    )
    return build_fallback_report(detail), ValidationReport(
        ok=False, retries_used=attempts - 1, issues=tuple(collected)
    )


def _rejected(code: str, message: str) -> tuple[None, ValidationReport]:
    """Build the (no report, failed validation) pair for a hard reject."""
    return None, ValidationReport(
        ok=False,
        issues=(ValidationIssue(code=code, action=ACTION_REJECTED, message=message),),
    )


def _iter_text(
    report: IncidentReport, *, include_narrative: bool
) -> Iterator[tuple[str, str]]:
    """Yield ``(where, text)`` for every field the given scans cover.

    Conclusion fields (summary, facts, hypotheses) are always included;
    narrative fields (alternative explanations, unknowns, recommended
    checks) only when ``include_narrative`` — score tampering is
    unacceptable anywhere, but benign readings are legitimate prose in
    the narrative fields.
    """
    yield "summary", report.summary
    for index, fact in enumerate(report.observed_facts):
        yield f"observed_facts[{index}]", fact.text
    for index, hypothesis in enumerate(report.hypotheses):
        yield f"hypotheses[{index}]", hypothesis.text
    if not include_narrative:
        return
    for index, text in enumerate(report.alternative_explanations):
        yield f"alternative_explanations[{index}]", text
    for index, text in enumerate(report.unknowns):
        yield f"unknowns[{index}]", text
    for index, text in enumerate(report.recommended_checks):
        yield f"recommended_checks[{index}]", text


def _score_text_issue(report: IncidentReport, score: int) -> ValidationIssue | None:
    """Flag any attempt to change the score or restate it wrongly."""
    for where, text in _iter_text(report, include_narrative=True):
        edit = _SCORE_EDIT_RE.search(text)
        if edit is not None:
            return ValidationIssue(
                code=CODE_SCORE_TAMPER,
                action=ACTION_REJECTED,
                message=f"{where} tries to change the score: {edit.group(0)!r}",
            )
        for match in _SCORE_VALUE_RE.finditer(text):
            stated = match.group(1) or match.group(2)
            if stated is not None and int(stated) != score:
                return ValidationIssue(
                    code=CODE_SCORE_TAMPER,
                    action=ACTION_REJECTED,
                    message=(
                        f"{where} states score {stated} but code computed "
                        f"{score}: {match.group(0)!r}"
                    ),
                )
    return None


def _verdict_text_issue(report: IncidentReport) -> ValidationIssue | None:
    """Flag output that declares the incident safe or benign."""
    for where, text in _iter_text(report, include_narrative=False):
        match = _SAFE_VERDICT_RE.search(text)
        if match is not None:
            return ValidationIssue(
                code=CODE_SAFE_VERDICT,
                action=ACTION_REJECTED,
                message=(
                    f"{where} declares the incident safe/benign: "
                    f"{match.group(0)!r}; only the deterministic stages and "
                    "the analyst may conclude anything"
                ),
            )
    return None


def _repair_claims(
    report: IncidentReport, known_event_ids: set[str]
) -> tuple[IncidentReport, list[ValidationIssue]]:
    """Remove unciteable claims, downgrade uncited facts (never invent).

    An observed fact is kept only when every ID it cites exists in the
    incident's timeline; a fact citing nothing is demoted to a
    low-confidence hypothesis so an ungrounded claim can never surface
    as an observation. Hypotheses citing unknown IDs are dropped.
    """
    repairs: list[ValidationIssue] = []
    facts: list[ObservedFact] = []
    hypotheses: list[Hypothesis] = list(report.hypotheses)

    for fact in report.observed_facts:
        if not fact.evidence_ids:
            repairs.append(
                ValidationIssue(
                    code=CODE_UNCITED_FACT,
                    action=ACTION_DOWNGRADED,
                    message=(
                        f"observed fact with no evidence_ids downgraded to a "
                        f"hypothesis: {fact.text!r}"
                    ),
                )
            )
            hypotheses.append(
                Hypothesis(
                    text=fact.text,
                    confidence=_DOWNGRADED_CONFIDENCE,
                    evidence_ids=[],
                )
            )
            continue
        unknown = sorted(set(fact.evidence_ids) - known_event_ids)
        if unknown:
            repairs.append(
                ValidationIssue(
                    code=CODE_UNKNOWN_EVIDENCE,
                    action=ACTION_DROPPED,
                    message=(
                        f"observed fact dropped, cites unknown event ID(s) "
                        f"{', '.join(unknown)}: {fact.text!r}"
                    ),
                )
            )
            continue
        facts.append(fact)

    kept_hypotheses: list[Hypothesis] = []
    for hypothesis in hypotheses:
        unknown = sorted(set(hypothesis.evidence_ids) - known_event_ids)
        if unknown:
            repairs.append(
                ValidationIssue(
                    code=CODE_UNKNOWN_EVIDENCE,
                    action=ACTION_DROPPED,
                    message=(
                        f"hypothesis dropped, cites unknown event ID(s) "
                        f"{', '.join(unknown)}: {hypothesis.text!r}"
                    ),
                )
            )
            continue
        kept_hypotheses.append(hypothesis)

    if not repairs:
        return report, repairs
    return (
        report.model_copy(
            update={"observed_facts": facts, "hypotheses": kept_hypotheses}
        ),
        repairs,
    )


__all__ = [
    "ACTION_DOWNGRADED",
    "ACTION_DROPPED",
    "ACTION_REJECTED",
    "CODE_NO_GROUNDED_CLAIMS",
    "CODE_SAFE_VERDICT",
    "CODE_SCHEMA",
    "CODE_SCORE_TAMPER",
    "CODE_TEMPLATE_FALLBACK",
    "CODE_UNCITED_FACT",
    "CODE_UNKNOWN_EVIDENCE",
    "MAX_VALIDATION_RETRIES",
    "ValidationIssue",
    "ValidationReport",
    "complete_validated",
    "validate_output",
]

"""Deterministic rules-only fallback report.

The same schema as the LLM path (``IncidentReport``) with
``fallback=True``, built purely from stored evidence: rule findings, the
score with its named components, and the timeline. No LLM is involved and
nothing is invented — every observed fact and hypothesis cites the real
event IDs of the finding it came from, and the output is a pure function
of the incident detail, so the same evidence always yields the same
report (AGENTS.md rule 5: the rules-only fallback must always work).
"""

from __future__ import annotations

from typing import Any, Mapping

from ..schema import Hypothesis, IncidentReport, ObservedFact, ReportConfidence

# Deterministic hypothesis phrasing per rule. Unknown rule IDs get a
# generic phrasing keyed on the rule itself — still traceable to a rule.
_HYPOTHESES: dict[str, str] = {
    "R1": (
        "A failed-login burst followed by a success for the same account "
        "may indicate brute-forced or guessed credentials."
    ),
    "R2": (
        "Privileged activity shortly after suspicious authentication may "
        "indicate privilege abuse or escalation."
    ),
    "R3": (
        "One source authenticating against many accounts in a short window "
        "may indicate a password spray."
    ),
    "R4": (
        "Elevated access outside working hours on a critical host may "
        "indicate unauthorized administrative activity."
    ),
}

# Risk band -> template confidence. The band is already the deterministic
# sum of rule, corroboration, volume, asset, privilege, and sequence
# components, so it is the honest stand-in for a confidence here.
_BAND_CONFIDENCE: dict[str, ReportConfidence] = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "high",
}

_ALTERNATIVE_EXPLANATIONS = [
    "Benign reading: authorized administrative or change-window activity "
    "can produce the same rule matches — rules match patterns, not intent.",
    "Benign reading: tooling and automation (scheduled jobs, agents, "
    "password-sync lag) can produce the same event sequence without an "
    "attacker.",
    "Benign reading: a misconfigured or replaying log source can duplicate "
    "or misattribute otherwise routine events.",
]

_UNKNOWN_TEMPLATES = [
    "The evidence covers only {start} to {end}; activity outside that "
    "window is unknown.",
    "No evidence here establishes attacker access, persistence, data "
    "exfiltration, or impact.",
    "Log coverage and clock integrity of the source systems cannot be "
    "verified from the supplied files.",
]

_RECOMMENDED_CHECKS = [
    "Analyst review: confirm whether the matched events align with an "
    "approved change or maintenance window before drawing conclusions.",
    "Analyst review: correlate the involved accounts and hosts with "
    "identity-provider and EDR telemetry for the same time window.",
    "Analyst review: verify the cited event IDs against the original log "
    "sources; treat any discrepancy as a data-quality issue.",
]


def build_fallback_report(detail: Mapping[str, Any]) -> IncidentReport:
    """Build the rules-only template report for one stored incident.

    Every fact and hypothesis is derived from a rule finding and cites
    that finding's matched event IDs (filtered to events that exist in
    the timeline, so no claim can reference evidence that is absent).
    """
    score = detail["score"]
    findings = list(detail["findings"])
    known_ids = {entry["event_id"] for entry in detail["timeline"]}

    observed_facts = [
        ObservedFact(
            text=(
                f"Rule {finding['rule_id']} matched {len(ids)} event(s) at "
                f"severity {finding['severity']}: "
                f"{' '.join(finding['reasons'])}"
            ),
            evidence_ids=ids,
        )
        for finding in findings
        if (ids := [eid for eid in finding["matched_event_ids"] if eid in known_ids])
    ]

    confidence = _BAND_CONFIDENCE.get(str(score["band"]).lower(), "medium")
    hypotheses = [
        Hypothesis(
            text=_HYPOTHESES.get(
                finding["rule_id"],
                f"Rule {finding['rule_id']} matched a suspicious pattern in "
                "the supplied evidence.",
            ),
            confidence=confidence,
            evidence_ids=ids,
        )
        for finding in findings
        if (ids := [eid for eid in finding["matched_event_ids"] if eid in known_ids])
    ]

    cited = [event_id for fact in observed_facts for event_id in fact.evidence_ids]
    evidence_sufficient = bool(observed_facts) and all(
        event_id in known_ids for event_id in cited
    )

    entities = detail["entities"]
    rule_ids = [finding["rule_id"] for finding in findings] or list(detail["rules"])
    summary = (
        f"{score['band']} risk ({score['score']}/100): rules "
        f"{', '.join(rule_ids) or '(none)'} matched "
        f"{detail['event_count']} event(s) from {detail['start_time']} to "
        f"{detail['end_time']}. Entities — users: "
        f"{', '.join(entities.get('users', [])) or '(none)'}; hosts: "
        f"{', '.join(entities.get('hosts', [])) or '(none)'}; source IPs: "
        f"{', '.join(entities.get('src_ips', [])) or '(none)'}. Score "
        f"components: rule {score['rule_component']} + corroboration "
        f"{score['corroboration']} + event volume {score['event_volume']} + "
        f"asset {score['asset_component']} + privilege "
        f"{score['privilege_component']} + sequence {score['sequence_bonus']}. "
        "Rules-only template built from stored evidence; no LLM was invoked."
    )

    return IncidentReport(
        incident_id=str(detail["incident_id"]),
        summary=summary,
        observed_facts=observed_facts,
        hypotheses=hypotheses,
        alternative_explanations=list(_ALTERNATIVE_EXPLANATIONS),
        unknowns=[
            template.format(start=detail["start_time"], end=detail["end_time"])
            for template in _UNKNOWN_TEMPLATES
        ],
        recommended_checks=list(_RECOMMENDED_CHECKS),
        evidence_sufficient=evidence_sufficient,
        fallback=True,
    )

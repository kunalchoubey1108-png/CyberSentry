"""End-to-end evaluation: baseline (rules-only) vs full pipeline.

Runs every log file referenced by ``data/labelled/labels.json`` through
the deterministic pipeline, then generates a report for each incident
twice:

* **baseline** — the rules-only template report
  (``app.llm.fallback.build_fallback_report``), no LLM involved;
* **full pipeline** — ``app.llm.client.generate_report`` (uses an LLM
  endpoint when one is configured, otherwise it legitimately degrades
  to the template — that is part of the product's contract).

Report paths never change incidents, scores, or detections; they only
explain them, so detection metrics are computed once and report-quality
metrics are computed per path.

Metrics (every number computed at run time — nothing hardcoded):

* incident-level precision / recall / F1 / false-positive rate against
  the labelled scenarios (positives are ``suspicious_event_ids`` where a
  scenario declares them, else all ``event_ids``);
* pairwise correlation accuracy over labelled positive events
  (same-scenario pairs must co-occur in an incident, cross-scenario
  pairs must not), with pairwise P/R/F1 and the raw pair counts;
* evidence-grounding rate (cited event IDs that exist in the
  incident's timeline), per path and overall, plus a deterministic
  sample of claims written to ``eval/results/claims_sample.csv`` for
  manual review;
* prompt-injection robustness on the adversarial fixture: label
  coverage of ``injection_flag`` evidence, reports free of
  instruction-like language, reports that still pass
  ``validate.validate_output``, and score immutability;
* latency for the per-file pipeline and for report generation, per
  path.

Outputs: ``eval/results/results.csv`` (flat ``section,metric,value,detail``
table, what the frontend Evaluation page renders), ``results.md``
(human-readable tables + the failure-case list), ``failures.csv`` and
``claims_sample.csv``. The table is also printed to stdout.

Usage::

    make eval            # runs eval/run.py (metrics.json) and this file
    backend/.venv/bin/python eval/run_eval.py
"""

from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from typing import Any

from app.correlate import correlate_events
from app.evidence import build_evidence_bundle
from app.ingest import load_assets, load_events
from app.llm import promptshield, validate
from app.llm.client import generate_report
from app.llm.fallback import build_fallback_report
from app.rules import load_config, run_all_rules
from app.scoring import score_incident

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"
LABELS_PATH = DATA_DIR / "labelled" / "labels.json"
RESULTS_DIR = Path(__file__).resolve().parent / "results"

CLAIM_SAMPLE_SIZE = 20  # rows in claims_sample.csv (or fewer if fewer claims)

# Scenarios where labels mark positive events explicitly; the rest use
# event_ids per label.
POSITIVE_LABEL = "suspicious"
MIXED_LABEL = "mixed"
BENIGN_LABEL = "benign"


# --------------------------------------------------------------------------
# pipeline
# --------------------------------------------------------------------------


def _detail(incident: Any, bundle: Any) -> dict[str, Any]:
    """Incident detail in the exact shape ``Database.get_incident`` emits."""
    score = bundle.score.model_dump(mode="json")
    return {
        "incident_id": incident.incident_id,
        "score": score,
        "band": score["band"],
        "rules": list(incident.rule_ids),
        "entities": dict(incident.entities),
        "event_count": len(incident.event_ids),
        "start_time": incident.start_time.isoformat(),
        "end_time": incident.end_time.isoformat(),
        "findings": [f.model_dump(mode="json") for f in bundle.rules],
        "timeline": [entry.model_dump(mode="json") for entry in bundle.timeline],
        "supporting_records": [
            entry.model_dump(mode="json") for entry in bundle.supporting_records
        ],
    }


def _run_file(name: str) -> dict[str, Any]:
    """One file through ingest -> rules -> correlate -> score -> bundle."""
    start = time.perf_counter()
    events, rejected = load_events(DATA_DIR / name)
    assets = load_assets()
    matches = run_all_rules(events, load_config(), assets)
    incidents = correlate_events(matches, events)
    details = []
    for incident in incidents:
        bundle = build_evidence_bundle(
            incident, score_incident(incident, matches, events, assets), matches, events
        )
        details.append(_detail(incident, bundle))
    latency_ms = (time.perf_counter() - start) * 1000.0
    matched_ids = sorted(
        {event_id for match in matches for event_id in match.matched_event_ids}
    )
    return {
        "file": name,
        "events": len(events),
        "rejected": len(rejected),
        "details": details,
        "matched_ids": matched_ids,
        # Every event ingested from this file (not just incident members)
        # and their untrusted fields, so label coverage and injection flags
        # are measured over the whole adversarial set.
        "all_event_ids": sorted(event.event_id for event in events),
        "records": [event.model_dump(mode="json") for event in events],
        "latency_ms": latency_ms,
    }


# --------------------------------------------------------------------------
# metric helpers
# --------------------------------------------------------------------------


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _expected_positive_ids(scenario: dict[str, Any]) -> set[str]:
    if scenario["label"] == MIXED_LABEL:
        return set(scenario.get("suspicious_event_ids", []))
    if scenario["label"] == POSITIVE_LABEL:
        return set(scenario["event_ids"])
    return set()


def _claims(report: Any) -> list[tuple[str, str]]:
    """(kind, text) claims of a report: observed facts and hypotheses."""
    return (
        [("observed_fact", fact.text) for fact in report.observed_facts]
        + [("hypothesis", hypothesis.text) for hypothesis in report.hypotheses]
    )


def _fmt(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


# --------------------------------------------------------------------------
# evaluation
# --------------------------------------------------------------------------


def evaluate() -> dict[str, Any]:
    """Run both report paths over the labelled fixtures; all metrics."""
    labels = json.loads(LABELS_PATH.read_text(encoding="utf-8"))
    scenarios: list[dict[str, Any]] = labels["scenarios"]
    files = sorted({name for scenario in scenarios for name in scenario["files"]})

    positive_events: set[str] = set()
    negative_events: set[str] = set()
    for scenario in scenarios:
        positive_events |= _expected_positive_ids(scenario)
        if scenario["label"] == MIXED_LABEL:
            negative_events |= set(scenario.get("benign_event_ids", []))
        elif scenario["label"] == BENIGN_LABEL:
            negative_events |= set(scenario["event_ids"])
    benign_scenarios = [s for s in scenarios if s["label"] == BENIGN_LABEL]
    positive_scenarios = [
        s for s in scenarios if _expected_positive_ids(s)
    ]

    # -- run the pipeline per file -----------------------------------------
    runs = [_run_file(name) for name in files]
    ingested = {event_id for run in runs for event_id in run["all_event_ids"]}
    # Any labelled event no file even contained is a data gap.
    missing_labels = sorted(
        (positive_events | negative_events) - ingested
    )

    matched: set[str] = {event_id for run in runs for event_id in run["matched_ids"]}
    incidents: list[dict[str, Any]] = [
        {"file": run["file"], "detail": detail}
        for run in runs
        for detail in run["details"]
    ]

    # -- incident-level detection ------------------------------------------
    def _overlap_positive(detail: dict[str, Any]) -> set[str]:
        matched_here = [e["event_id"] for e in detail["timeline"] if e["matched"]]
        return set(matched_here) & positive_events

    tp_incidents = sum(
        1 for row in incidents if _overlap_positive(row["detail"])
    )
    precision = _rate(tp_incidents, len(incidents))
    recalled = [
        scenario
        for scenario in positive_scenarios
        if set(scenario["event_ids"] if scenario["label"] == POSITIVE_LABEL
               else scenario.get("suspicious_event_ids", [])) & matched
    ]
    recall = _rate(len(recalled), len(positive_scenarios))
    f1 = (
        round(2 * precision * recall / (precision + recall), 4)
        if precision + recall
        else 0.0
    )
    flagged_benign = [
        scenario
        for scenario in benign_scenarios
        if set(scenario["event_ids"]) & matched
    ]
    false_positive_rate = _rate(len(flagged_benign), len(benign_scenarios))
    negative_events_matched = sorted(matched & negative_events)
    positive_events_matched = sorted(matched & positive_events)

    # -- pairwise correlation accuracy over labelled positive events -------
    clusters: list[set[str]] = []
    scenario_of: dict[str, str] = {}
    for scenario in positive_scenarios:
        ids = _expected_positive_ids(scenario)
        for event_id in ids:
            scenario_of[event_id] = scenario["id"]
    for row in incidents:
        clusters.append({entry["event_id"] for entry in row["detail"]["timeline"]})
    positive_ids = sorted(scenario_of)
    pairwise = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for i, a in enumerate(positive_ids):
        for b in positive_ids[i + 1:]:
            same_truth = scenario_of[a] == scenario_of[b]
            same_cluster = any(a in group and b in group for group in clusters)
            if same_truth and same_cluster:
                pairwise["tp"] += 1
            elif not same_truth and same_cluster:
                pairwise["fp"] += 1
            elif same_truth and not same_cluster:
                pairwise["fn"] += 1
            else:
                pairwise["tn"] += 1
    total_pairs = sum(pairwise.values())
    pairwise_precision = _rate(pairwise["tp"], pairwise["tp"] + pairwise["fp"])
    pairwise_recall = _rate(pairwise["tp"], pairwise["tp"] + pairwise["fn"])
    pairwise_f1 = (
        round(
            2 * pairwise_precision * pairwise_recall / (pairwise_precision + pairwise_recall),
            4,
        )
        if pairwise_precision + pairwise_recall
        else 0.0
    )
    pairwise_accuracy = _rate(pairwise["tp"] + pairwise["tn"], total_pairs)

    # -- both report paths ---------------------------------------------------
    scores_before = {row["detail"]["incident_id"]: row["detail"]["score"]["score"]
                     for row in incidents}
    claims_rows: list[dict[str, Any]] = []
    reports: dict[str, list[dict[str, Any]]] = {"baseline": [], "full": []}
    report_latency: dict[str, list[float]] = {"baseline": [], "full": []}
    grounding: dict[str, dict[str, int]] = {
        "baseline": {"cited": 0, "existing": 0, "claims": 0, "valid": 0},
        "full": {"cited": 0, "existing": 0, "claims": 0, "valid": 0},
    }

    for path_name in ("baseline", "full"):
        for row in incidents:
            detail = row["detail"]
            known = {entry["event_id"] for entry in detail["timeline"]}
            start = time.perf_counter()
            if path_name == "baseline":
                report = build_fallback_report(detail)
            else:
                report = generate_report(detail)
            report_latency[path_name].append((time.perf_counter() - start) * 1000.0)
            reports[path_name].append(
                {
                    "incident_id": detail["incident_id"],
                    "file": row["file"],
                    "fallback": report.fallback,
                    "report": report,
                }
            )
            check = validate.validate_output(
                report.model_dump_json(),
                incident_id=detail["incident_id"],
                known_event_ids=known,
                score=int(detail["score"]["score"]),
            )
            if check[0] is not None:
                grounding[path_name]["valid"] += 1
            for kind, text in _claims(report):
                cited = [
                    event_id
                    for event_id in _evidence_ids(report, kind, text)
                ]
                existing = sum(1 for event_id in cited if event_id in known)
                grounding[path_name]["cited"] += len(cited)
                grounding[path_name]["existing"] += existing
                grounding[path_name]["claims"] += 1
                claims_rows.append(
                    {
                        "path": path_name,
                        "incident_id": detail["incident_id"],
                        "kind": kind,
                        "claim": " ".join(text.split())[:200],
                        "evidence_ids": ";".join(cited),
                        "cited": len(cited),
                        "existing": existing,
                        "grounded": int(existing == len(cited)),
                    }
                )

    scores_after = {row["detail"]["incident_id"]: row["detail"]["score"]["score"]
                    for row in incidents}
    scores_unchanged = int(scores_before == scores_after)

    total_cited = sum(grounding[p]["cited"] for p in grounding)
    total_existing = sum(grounding[p]["existing"] for p in grounding)
    total_claims = sum(grounding[p]["claims"] for p in grounding)
    grounding_rate = _rate(total_existing, total_cited)

    # -- prompt-injection robustness (adversarial set) -----------------------
    inj_scenario = next(
        (s for s in scenarios if s["id"] == "adversarial-prompt-injection"), None
    )
    injection: dict[str, Any] = {}
    if inj_scenario is not None:
        adversarial_runs = [r for r in runs if r["file"] == "adversarial_injection.csv"]
        adversarial_incidents = [
            row for row in incidents if row["file"] == "adversarial_injection.csv"
        ]
        for run in adversarial_runs:
            ingested_adversarial = set(run["all_event_ids"])
            records = run["records"]
        labelled_injection = set(inj_scenario["event_ids"]) & ingested_adversarial
        # Flag coverage is measured over every event of the adversarial
        # file — not just the members of one incident's timeline.
        flags = promptshield.scan_records(records)
        flagged = {flag.event_id for flag in flags}
        flagged_labelled = sorted(labelled_injection & flagged)

        directive_reports = 0
        for path_name in ("baseline", "full"):
            for entry in reports[path_name]:
                if entry["file"] != "adversarial_injection.csv":
                    continue
                report = entry["report"]
                text = " ".join(
                    [report.summary]
                    + [fact.text for fact in report.observed_facts]
                    + [hyp.text for hyp in report.hypotheses]
                    + list(report.recommended_checks)
                )
                if promptshield.detect_injection(text):
                    directive_reports += 1
        injection = {
            "labelled_events": len(labelled_injection),
            "flagged_events": len(flagged_labelled),
            "flag_coverage": _rate(len(flagged_labelled), len(labelled_injection)),
            "adversarial_incidents": len(adversarial_incidents),
            "reports_checked": sum(
                1
                for path_name in ("baseline", "full")
                for entry in reports[path_name]
                if entry["file"] == "adversarial_injection.csv"
            ),
            "reports_with_directive_language": directive_reports,
            "reports_passing_validation": sum(
                grounding[path_name]["valid"] for path_name in grounding
            ),
            "reports_total": sum(
                len(reports[path_name]) for path_name in reports
            ),
            "score_unchanged": scores_unchanged,
        }

    # -- failure cases -------------------------------------------------------
    failures: list[dict[str, str]] = []
    for scenario in positive_scenarios:
        if scenario not in recalled:
            failures.append(
                {
                    "kind": "missed_scenario",
                    "ref": scenario["id"],
                    "detail": f"no rule-matched event — {scenario['description']}",
                }
            )
    for scenario in flagged_benign:
        failures.append(
            {
                "kind": "false_positive_scenario",
                "ref": scenario["id"],
                "detail": f"benign scenario produced rule matches — {scenario['description']}",
            }
        )
    for row in incidents:
        if not _overlap_positive(row["detail"]):
            failures.append(
                {
                    "kind": "false_positive_incident",
                    "ref": row["detail"]["incident_id"],
                    "detail": (
                        f"file {row['file']}, score {row['detail']['score']['score']} "
                        "- no matched event belongs to a labelled positive"
                    ),
                }
            )
    for event_id in negative_events_matched:
        failures.append(
            {
                "kind": "negative_event_matched",
                "ref": event_id,
                "detail": "labelled negative event was rule-matched",
            }
        )
    for claim in claims_rows:
        if not claim["grounded"]:
            failures.append(
                {
                    "kind": "claim_cites_unknown_event",
                    "ref": claim["incident_id"],
                    "detail": (
                        f"{claim['path']}: {claim['evidence_ids']} not in timeline "
                        f"({claim['claim']})"
                    ),
                }
            )
    for path_name in ("baseline", "full"):
        invalid = len(reports[path_name]) - grounding[path_name]["valid"]
        if invalid:
            failures.append(
                {
                    "kind": "report_fails_validation",
                    "ref": path_name,
                    "detail": f"{invalid} generated report(s) failed re-validation",
                }
            )
    if injection and injection["reports_with_directive_language"]:
        failures.append(
            {
                "kind": "instruction_language_in_report",
                "ref": "adversarial_injection.csv",
                "detail": (
                    f"{injection['reports_with_directive_language']} report(s) contain "
                    "instruction-like language lifted from injected events"
                ),
            }
        )
    if not scores_unchanged:
        failures.append(
            {
                "kind": "score_changed",
                "ref": "pipeline",
                "detail": "an incident score changed after report generation",
            }
        )
    if missing_labels:
        failures.append(
            {
                "kind": "labelled_event_missing_from_fixtures",
                "ref": ",".join(missing_labels[:5]),
                "detail": f"{len(missing_labels)} labelled event id(s) not ingested",
            }
        )

    # -- deterministic claim sample (<= 20 rows, failures first) -------------
    ordered = sorted(
        claims_rows,
        key=lambda row: (row["grounded"], row["path"], row["incident_id"], row["kind"], row["claim"]),
    )
    ungrounded = [row for row in ordered if not row["grounded"]]
    grounded = [row for row in ordered if row["grounded"]]
    sample = list(ungrounded)
    remaining = max(CLAIM_SAMPLE_SIZE - len(sample), 0)
    if remaining and grounded:
        stride = max(len(grounded) // remaining, 1)
        sample += [grounded[i] for i in range(0, len(grounded), stride)][:remaining]
    claim_sample = sample[:CLAIM_SAMPLE_SIZE]

    # -- assemble rows -------------------------------------------------------
    rows: list[dict[str, str]] = []

    def add(section: str, metric: str, value: Any, detail: str = "") -> None:
        rows.append(
            {
                "section": section,
                "metric": metric,
                "value": _fmt(value),
                "detail": detail,
            }
        )

    add("pipeline", "files", len(files))
    add("pipeline", "events_ingested", sum(run["events"] for run in runs))
    add("pipeline", "events_rejected", sum(run["rejected"] for run in runs))
    add("pipeline", "incidents", len(incidents))
    add("pipeline", "labelled_positive_events", len(positive_events))
    add("pipeline", "labelled_negative_events", len(negative_events))
    add("pipeline", "positive_scenarios", len(positive_scenarios))
    add("pipeline", "benign_scenarios", len(benign_scenarios))
    add("pipeline", "labelled_events_missing", len(missing_labels))

    add("incident", "precision", precision, "rate (0-1), TP incidents / all incidents")
    add("incident", "recall", recall, "rate (0-1), positive scenarios with a rule-matched event")
    add("incident", "f1", f1, "rate (0-1)")
    add("incident", "false_positive_rate", false_positive_rate, "rate (0-1), benign scenarios with rule matches")
    add("incident", "tp_incidents", tp_incidents)
    add("incident", "incidents", len(incidents))
    add("incident", "scenarios_recalled", len(recalled))
    add("incident", "positive_events_matched", len(positive_events_matched))
    add("incident", "negative_events_matched", len(negative_events_matched))

    add("correlation", "pairwise_accuracy", pairwise_accuracy, "rate (0-1), over labelled positive-event pairs")
    add("correlation", "pairwise_precision", pairwise_precision, "rate (0-1)")
    add("correlation", "pairwise_recall", pairwise_recall, "rate (0-1)")
    add("correlation", "pairwise_f1", pairwise_f1, "rate (0-1)")
    for key in ("tp", "fp", "fn", "tn"):
        add("correlation", f"{key}_pairs", pairwise[key])
    add("correlation", "total_pairs", total_pairs)

    add("grounding", "grounding_rate", grounding_rate, "rate (0-1), cited IDs that exist in the timeline")
    add("grounding", "cited_ids", total_cited)
    add("grounding", "existing_ids", total_existing)
    add("grounding", "claims", total_claims)
    add("grounding", "claim_sample_size", len(claim_sample), "rows in eval/results/claims_sample.csv")

    for path_name in ("baseline", "full"):
        section = f"report_{path_name}"
        n_cited = grounding[path_name]["cited"]
        n_existing = grounding[path_name]["existing"]
        total = len(reports[path_name])
        fallback = sum(1 for e in reports[path_name] if e["fallback"])
        lat = report_latency[path_name]
        add(section, "reports", total)
        add(section, "template_fallbacks", fallback,
            "reports that used the rules-only template")
        add(section, "grounding_rate", _rate(n_existing, n_cited), "rate (0-1)")
        add(section, "claims", grounding[path_name]["claims"])
        add(section, "passing_validation", grounding[path_name]["valid"])
        add(section, "latency_mean_ms", round(sum(lat) / len(lat), 3) if lat else 0.0)
        add(section, "latency_max_ms", round(max(lat), 3) if lat else 0.0)

    if injection:
        add("injection", "labelled_injection_events", injection["labelled_events"])
        add("injection", "flagged_events", injection["flagged_events"])
        add("injection", "flag_coverage", injection["flag_coverage"],
            "rate (0-1), labelled injection events carrying an injection_flag")
        add("injection", "adversarial_incidents", injection["adversarial_incidents"])
        add("injection", "reports_checked", injection["reports_checked"])
        add("injection", "reports_with_directive_language",
            injection["reports_with_directive_language"],
            "reports containing instruction-like language from injected events")
        add("injection", "reports_passing_validation", injection["reports_passing_validation"],
            f"of {injection['reports_total']} reports (both paths)")
        add("injection", "score_unchanged", injection["score_unchanged"],
            "1 = no score changed during report generation")

    pipeline_lat = [run["latency_ms"] for run in runs]
    add("latency", "pipeline_mean_ms", round(sum(pipeline_lat) / len(pipeline_lat), 3))
    add("latency", "pipeline_max_ms", round(max(pipeline_lat), 3))
    for path_name in ("baseline", "full"):
        lat = report_latency[path_name]
        add("latency", f"{path_name}_report_mean_ms",
            round(sum(lat) / len(lat), 3) if lat else 0.0)
        add("latency", f"{path_name}_report_max_ms",
            round(max(lat), 3) if lat else 0.0)

    for scenario in scenarios:
        ids = set(scenario["event_ids"])
        detected = len(ids & matched)
        out_label = scenario["label"]
        add(
            "scenario",
            scenario["id"],
            round(_rate(detected, len(ids)), 4),
            f"label={out_label}; detected={detected}/{len(ids)}; {scenario['description']}",
        )

    return {
        "rows": rows,
        "failures": failures,
        "claim_sample": claim_sample,
        "scenario_rows": [r for r in rows if r["section"] == "scenario"],
    }


def _evidence_ids(report: Any, kind: str, text: str) -> list[str]:
    """Evidence ids of one claim, matched by its text."""
    if kind == "observed_fact":
        return [
            fact.evidence_ids
            for fact in report.observed_facts
            if fact.text == text
        ][0]
    return [
        hypothesis.evidence_ids
        for hypothesis in report.hypotheses
        if hypothesis.text == text
    ][0]


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------


def write_results(
    doc: dict[str, Any], out_dir: Path = RESULTS_DIR
) -> dict[str, Path]:
    """Write results.csv, results.md, failures.csv, claims_sample.csv."""
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}

    paths["csv"] = out_dir / "results.csv"
    with paths["csv"].open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["section", "metric", "value", "detail"])
        writer.writeheader()
        writer.writerows(doc["rows"])

    paths["failures"] = out_dir / "failures.csv"
    with paths["failures"].open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["kind", "ref", "detail"])
        writer.writeheader()
        writer.writerows(doc["failures"])

    paths["claims"] = out_dir / "claims_sample.csv"
    claim_fields = [
        "path", "incident_id", "kind", "claim", "evidence_ids",
        "cited", "existing", "grounded",
    ]
    with paths["claims"].open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=claim_fields)
        writer.writeheader()
        writer.writerows(doc["claim_sample"])

    paths["md"] = out_dir / "results.md"
    paths["md"].write_text(_render_markdown(doc), encoding="utf-8")
    return paths


def _render_markdown(doc: dict[str, Any]) -> str:
    lines = [
        "# CyberSentry evaluation results",
        "",
        "Generated by `eval/run_eval.py` from the synthetic labelled fixtures in",
        "`data/labelled/`. Every number is computed at run time; nothing is hardcoded.",
        "The **baseline** path is the rules-only template report; the **full** path is",
        "`app.llm.client.generate_report` (an LLM when configured, the same template",
        "otherwise — reports never change detections, incidents, or scores).",
        "",
    ]
    sections: dict[str, list[dict[str, str]]] = {}
    for row in doc["rows"]:
        sections.setdefault(row["section"], []).append(row)

    headings = {
        "pipeline": "Pipeline",
        "incident": "Incident-level detection",
        "correlation": "Pairwise correlation accuracy (labelled positive events)",
        "grounding": "Evidence grounding",
        "report_baseline": "Baseline path (rules-only template report)",
        "report_full": "Full pipeline report path",
        "injection": "Prompt-injection robustness (adversarial set)",
        "latency": "Latency",
    }
    for section, title in headings.items():
        if section not in sections:
            continue
        lines += [f"## {title}", "", "| metric | value | detail |", "|---|---|---|"]
        for row in sections[section]:
            lines.append(f"| {row['metric']} | {row['value']} | {row['detail']} |")
        lines.append("")

    if "scenario" in sections:
        lines += [
            "## Scenario results",
            "",
            "| scenario | recall | detail |",
            "|---|---|---|",
        ]
        for row in sections["scenario"]:
            lines.append(f"| {row['metric']} | {row['value']} | {row['detail']} |")
        lines.append("")

    lines += ["## Failure cases", ""]
    if doc["failures"]:
        lines += ["| kind | ref | detail |", "|---|---|---|"]
        for failure in doc["failures"]:
            lines.append(
                f"| {failure['kind']} | {failure['ref']} | {failure['detail']} |"
            )
    else:
        lines.append("None detected.")
    lines += [
        "",
        "## Claims sample for manual review",
        "",
        f"`eval/results/claims_sample.csv` holds {len(doc['claim_sample'])} claims",
        "(path, incident, kind, claim text, cited IDs, how many exist in the",
        "incident timeline, and a grounded flag).",
        "",
    ]
    return "\n".join(lines)


def print_table(doc: dict[str, Any]) -> None:
    """Print the flat metric table to stdout."""
    width = max(
        [len(row["section"]) for row in doc["rows"]]
        + [len(row["metric"]) for row in doc["rows"]]
        + [5]
    )
    print(f"{'section':<{width}}  {'metric':<{width + 10}}  value")
    print("-" * (width * 2 + 14))
    current = None
    for row in doc["rows"]:
        if row["section"] != current:
            current = row["section"]
        print(f"{row['section']:<{width}}  {row['metric']:<{width + 10}}  {row['value']}")
    print()
    print(f"failure cases: {len(doc['failures'])}")
    for failure in doc["failures"]:
        print(f"  - {failure['kind']}: {failure['ref']}")
    print(f"claims sample: {len(doc['claim_sample'])} rows")


def main() -> int:
    doc = evaluate()
    print_table(doc)
    paths = write_results(doc)
    for label, path in paths.items():
        print(f"wrote {label}: {path}")
    return 1 if any(
        f["kind"] in {"score_changed", "claim_cites_unknown_event"} for f in doc["failures"]
    ) else 0


if __name__ == "__main__":
    raise SystemExit(main())
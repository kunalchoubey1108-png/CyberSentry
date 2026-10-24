"""Evaluation runner: detection metrics over the labelled synthetic fixtures.

Runs the deterministic pipeline (rules -> correlation) over every log
file referenced by ``data/labelled/labels.json`` and compares rule
matches against the ground-truth labels, event by event. Synthetic data
only (AGENTS.md rule 7); nothing here touches an LLM, so the metrics
are a pure function of labels + fixtures.

Output: ``eval/results/metrics.json`` — the metrics table the frontend
Evaluation view renders. The run is deterministic: same labels, same
fixtures, byte-identical output (no timestamps).

Usage::

    make eval          # or: backend/.venv/bin/python eval/run.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.correlate import correlate_events
from app.ingest import load_assets, load_csv
from app.rules import load_config, run_all_rules
from app.scoring import score_incident

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"
LABELS_PATH = DATA_DIR / "labelled" / "labels.json"
RESULTS_DIR = Path(__file__).resolve().parent / "results"
RESULTS_PATH = RESULTS_DIR / "metrics.json"

# Labels whose event_ids count as ground-truth positives. "mixed"
# scenarios carry attack events produced alongside benign activity.
POSITIVE_LABELS = frozenset({"suspicious", "mixed"})


def evaluate() -> dict[str, Any]:
    """Compute detection metrics against the labelled fixtures.

    Ground truth: every event id in a suspicious/mixed scenario is
    positive; every other ingested event is negative. A predicted
    positive is an event any rule matched. Returns the JSON-ready
    metrics document (see module docstring).
    """
    labels = json.loads(LABELS_PATH.read_text(encoding="utf-8"))
    scenarios: list[dict[str, Any]] = labels["scenarios"]
    files = sorted({name for scenario in scenarios for name in scenario["files"]})

    positives: set[str] = set()
    negatives: set[str] = set()
    for scenario in scenarios:
        ids = set(scenario["event_ids"])
        (positives if scenario["label"] in POSITIVE_LABELS else negatives).update(ids)

    ingested: set[str] = set()
    matched: set[str] = set()
    runs: list[dict[str, Any]] = []
    for name in files:
        events, rejected = load_csv(DATA_DIR / name)
        matches = run_all_rules(events, load_config(), load_assets())
        incidents = correlate_events(matches, events)
        bundle_scores = [
            score_incident(incident, matches, events, load_assets()).score
            for incident in incidents
        ]
        file_matched = {
            event_id
            for match in matches
            for event_id in match.matched_event_ids
        }
        ingested.update(event.event_id for event in events)
        matched.update(file_matched)
        runs.append(
            {
                "file": name,
                "events": len(events),
                "rejected": len(rejected),
                "matched": len(file_matched),
                "incidents": len(incidents),
                "max_score": max(bundle_scores, default=0),
            }
        )

    missing_labels = sorted((positives | negatives) - ingested)
    tp = matched & positives
    fp = matched - positives
    fn = positives - matched
    tn = ingested - positives - fp

    def ratio(numerator: int, denominator: int) -> float:
        return round(numerator / denominator, 4) if denominator else 0.0

    precision = ratio(len(tp), len(tp) + len(fp))
    recall = ratio(len(tp), len(tp) + len(fn))
    f1 = (
        round(2 * precision * recall / (precision + recall), 4)
        if precision + recall
        else 0.0
    )

    scenario_rows = [
        {
            "id": scenario["id"],
            "label": scenario["label"],
            "files": scenario["files"],
            "description": scenario["description"],
            "events": len(scenario["event_ids"]),
            "detected": len(set(scenario["event_ids"]) & matched),
            "recall": ratio(len(set(scenario["event_ids"]) & matched),
                            len(scenario["event_ids"])),
        }
        for scenario in scenarios
    ]

    return {
        "schema_version": 1,
        "synthetic": True,
        "source": {
            "labels": str(LABELS_PATH.relative_to(REPO_ROOT)),
            "seed": labels.get("seed"),
        },
        "totals": {
            "events": len(ingested),
            "labelled_positive": len(positives),
            "labelled_negative": len(negatives),
            "matched": len(matched),
            "tp": len(tp),
            "fp": len(fp),
            "fn": len(fn),
            "tn": len(tn),
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "missing_labels": missing_labels,
        },
        "scenarios": scenario_rows,
        "runs": runs,
    }


def write_results(metrics: dict[str, Any], path: Path = RESULTS_PATH) -> Path:
    """Write the metrics document as pretty JSON; returns the path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(metrics, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    return path


def main() -> int:
    metrics = evaluate()
    totals = metrics["totals"]
    if totals["missing_labels"]:
        print(f"eval: labelled ids missing from fixtures: {totals['missing_labels']}")
        return 1
    out = write_results(metrics)
    print(f"eval: wrote {out}")
    print(
        f"eval: {totals['events']} events, {totals['labelled_positive']} positive, "
        f"matched {totals['matched']} -> tp {totals['tp']} fp {totals['fp']} "
        f"fn {totals['fn']}"
    )
    print(
        f"eval: precision {totals['precision']:.4f} "
        f"recall {totals['recall']:.4f} f1 {totals['f1']:.4f}"
    )
    for row in metrics["scenarios"]:
        print(
            f"  {row['id']:<40} {row['label']:<11} "
            f"{row['detected']:>3}/{row['events']:<3} recall {row['recall']:.4f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
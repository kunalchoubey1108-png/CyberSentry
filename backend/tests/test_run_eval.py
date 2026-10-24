"""Tests for the end-to-end evaluator (eval/run_eval.py): structural
invariants of the computed metrics, output files, and the claim/failure
artifacts (AGENTS.md rules 6 and 7).

No metric value is asserted against a literal — fixtures are labelled,
not memorised; tests check that the numbers are computed, consistent,
in range, and written out.
"""

from __future__ import annotations

import csv
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
EVAL_PATH = REPO_ROOT / "eval" / "run_eval.py"
LABELS_PATH = REPO_ROOT / "data" / "labelled" / "labels.json"

LLM_ENV_VARS = (
    "LLM_PROVIDER",
    "LLM_MODEL",
    "LLM_BASE_URL",
    "LLM_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
)


def _load_eval_module() -> ModuleType:
    """Import eval/run_eval.py by path (it lives outside the app package)."""
    spec = importlib.util.spec_from_file_location("cybersentry_run_eval", EVAL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def scrub_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Evaluate with no LLM configured: no network, no keys (rule 5)."""
    for var in LLM_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(scope="module")
def eval_module() -> ModuleType:
    return _load_eval_module()


@pytest.fixture(scope="module")
def doc(eval_module: ModuleType) -> dict:
    return eval_module.evaluate()


def _value(doc: dict, section: str, metric: str) -> str:
    matches = [
        row["value"] for row in doc["rows"]
        if row["section"] == section and row["metric"] == metric
    ]
    assert matches, f"missing metric {section}.{metric}"
    return matches[0]


@pytest.mark.skipif(not LABELS_PATH.exists(), reason="labelled fixtures not present")
class TestMetrics:
    def test_all_required_metrics_are_computed(self, doc: dict) -> None:
        for section, metric in [
            ("incident", "precision"),
            ("incident", "recall"),
            ("incident", "f1"),
            ("incident", "false_positive_rate"),
            ("correlation", "pairwise_accuracy"),
            ("grounding", "grounding_rate"),
            ("injection", "flag_coverage"),
            ("injection", "score_unchanged"),
            ("report_baseline", "latency_mean_ms"),
            ("report_full", "latency_mean_ms"),
            ("latency", "pipeline_mean_ms"),
        ]:
            _value(doc, section, metric)

    @pytest.mark.parametrize(
        "section,metric",
        [
            ("incident", "precision"),
            ("incident", "recall"),
            ("incident", "f1"),
            ("incident", "false_positive_rate"),
            ("correlation", "pairwise_accuracy"),
            ("correlation", "pairwise_precision"),
            ("correlation", "pairwise_recall"),
            ("grounding", "grounding_rate"),
            ("injection", "flag_coverage"),
            ("report_baseline", "grounding_rate"),
            ("report_full", "grounding_rate"),
        ],
    )
    def test_rates_are_in_range(self, doc: dict, section: str, metric: str) -> None:
        value = float(_value(doc, section, metric))
        assert 0.0 <= value <= 1.0

    def test_incident_metrics_are_internally_consistent(self, doc: dict) -> None:
        precision = float(_value(doc, "incident", "precision"))
        recall = float(_value(doc, "incident", "recall"))
        f1 = float(_value(doc, "incident", "f1"))
        assert f1 == pytest.approx(
            2 * precision * recall / (precision + recall), abs=1e-3
        ) if precision + recall else f1 == 0.0
        incidents = int(_value(doc, "incident", "incidents"))
        tp = int(_value(doc, "incident", "tp_incidents"))
        if incidents:
            assert precision == pytest.approx(tp / incidents, abs=1e-3)

    def test_pairwise_counts_sum_and_accuracy_matches(self, doc: dict) -> None:
        counts = {
            key: int(_value(doc, "correlation", f"{key}_pairs"))
            for key in ("tp", "fp", "fn", "tn")
        }
        total = int(_value(doc, "correlation", "total_pairs"))
        assert sum(counts.values()) == total
        accuracy = float(_value(doc, "correlation", "pairwise_accuracy"))
        if total:
            assert accuracy == pytest.approx(
                (counts["tp"] + counts["tn"]) / total, abs=1e-3
            )

    def test_grounding_counts_and_sample_size(self, doc: dict) -> None:
        cited = int(_value(doc, "grounding", "cited_ids"))
        existing = int(_value(doc, "grounding", "existing_ids"))
        rate = float(_value(doc, "grounding", "grounding_rate"))
        assert cited >= existing >= 0
        if cited:
            assert rate == pytest.approx(existing / cited, abs=1e-3)
        sample_size = int(_value(doc, "grounding", "claim_sample_size"))
        assert 0 < sample_size <= 20

    def test_both_report_paths_ran(self, doc: dict) -> None:
        for path in ("baseline", "full"):
            reports = int(_value(doc, f"report_{path}", "reports"))
            assert reports > 0, f"{path} path generated no reports"

    def test_score_unchanged_flag_is_binary(self, doc: dict) -> None:
        assert _value(doc, "injection", "score_unchanged") in {"0", "1"}

    def test_every_scenario_row_present_with_label_detail(self, doc: dict) -> None:
        labels = json.loads(LABELS_PATH.read_text())
        scenario_rows = {
            row["metric"]: row for row in doc["rows"] if row["section"] == "scenario"
        }
        assert set(scenario_rows) == {s["id"] for s in labels["scenarios"]}
        for row in scenario_rows.values():
            assert row["detail"].startswith("label=")
            assert 0.0 <= float(row["value"]) <= 1.0

    def test_failure_cases_are_structured(self, doc: dict) -> None:
        assert isinstance(doc["failures"], list)
        for failure in doc["failures"]:
            assert set(failure) == {"kind", "ref", "detail"}
            assert failure["kind"] and failure["ref"]

    def test_claim_sample_rows_are_consistent(self, doc: dict) -> None:
        for claim in doc["claim_sample"]:
            assert set(claim) == {
                "path", "incident_id", "kind", "claim", "evidence_ids",
                "cited", "existing", "grounded",
            }
            assert claim["path"] in {"baseline", "full"}
            assert claim["kind"] in {"observed_fact", "hypothesis"}
            assert claim["grounded"] == int(claim["cited"] == claim["existing"])
        assert len(doc["claim_sample"]) <= 20

    def test_evaluate_is_deterministic_apart_from_latency(
        self, eval_module: ModuleType, doc: dict
    ) -> None:
        second = eval_module.evaluate()
        strip = lambda d: [  # noqa: E731 - test-local helper
            row for row in d["rows"] if not row["metric"].endswith("_ms")
        ]
        assert strip(second) == strip(doc)
        assert second["failures"] == doc["failures"]


@pytest.mark.skipif(not LABELS_PATH.exists(), reason="labelled fixtures not present")
class TestOutputs:
    def test_write_results_emits_all_artifacts(
        self, eval_module: ModuleType, doc: dict, tmp_path: Path
    ) -> None:
        paths = eval_module.write_results(doc, tmp_path)
        assert set(paths) == {"csv", "md", "failures", "claims"}

        with paths["csv"].open(newline="") as handle:
            rows = list(csv.DictReader(handle))
        assert rows == doc["rows"]
        assert {"section", "metric", "value", "detail"} <= set(rows[0])

        with paths["failures"].open(newline="") as handle:
            failures = list(csv.DictReader(handle))
        assert failures == doc["failures"]

        with paths["claims"].open(newline="") as handle:
            claims = list(csv.DictReader(handle))
        assert claims and len(claims) <= 20

        markdown = paths["md"].read_text()
        for heading in ("# CyberSentry evaluation results", "## Failure cases",
                        "## Scenario results"):
            assert heading in markdown

    def test_print_table_outputs_every_row(
        self, eval_module: ModuleType, doc: dict, capsys: pytest.CaptureFixture
    ) -> None:
        eval_module.print_table(doc)
        out = capsys.readouterr().out
        for row in doc["rows"][:5]:
            assert row["metric"] in out
        assert f"failure cases: {len(doc['failures'])}" in out
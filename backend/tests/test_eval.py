"""Tests for the evaluation runner (eval/run.py): metric invariants,
determinism, and the results file the frontend Evaluation view loads
(AGENTS.md rules 6 and 7 — synthetic labels only).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
EVAL_PATH = REPO_ROOT / "eval" / "run.py"
LABELS_PATH = REPO_ROOT / "data" / "labelled" / "labels.json"


def _load_eval_module() -> ModuleType:
    """Import eval/run.py by path (it lives outside the app package)."""
    spec = importlib.util.spec_from_file_location("cybersentry_eval_run", EVAL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def eval_run() -> ModuleType:
    return _load_eval_module()


@pytest.fixture(scope="module")
def metrics(eval_run: ModuleType) -> dict:
    return eval_run.evaluate()


@pytest.mark.skipif(not LABELS_PATH.exists(), reason="labelled fixtures not present")
class TestEvaluate:
    def test_totals_are_internally_consistent(self, metrics: dict) -> None:
        totals = metrics["totals"]
        assert totals["tp"] + totals["fn"] == totals["labelled_positive"]
        assert totals["tp"] + totals["fp"] == totals["matched"]
        for name in ("precision", "recall", "f1"):
            assert 0.0 <= totals[name] <= 1.0
        assert totals["missing_labels"] == []     # every labelled id was ingested
        expected_recall = round(totals["tp"] / (totals["tp"] + totals["fn"]), 4)
        assert totals["recall"] == expected_recall

    def test_every_labelled_scenario_is_reported(self, metrics: dict) -> None:
        labels = json.loads(LABELS_PATH.read_text())
        assert {row["id"] for row in metrics["scenarios"]} == {
            scenario["id"] for scenario in labels["scenarios"]
        }
        for row in metrics["scenarios"]:
            assert 0 <= row["detected"] <= row["events"]
            assert 0.0 <= row["recall"] <= 1.0
            assert row["label"] in {"benign", "suspicious", "mixed"}
            assert row["description"]

    def test_run_rows_cover_the_fixture_files(self, metrics: dict) -> None:
        rows = {row["file"]: row for row in metrics["runs"]}
        assert "sample_attacks.csv" in rows
        assert "adversarial_injection.csv" in rows
        assert "assets.csv" not in rows          # never a log input
        for row in rows.values():
            assert row["events"] > 0
            assert row["rejected"] == 0          # synthetic fixtures parse cleanly
            assert row["matched"] <= row["events"]
            assert 0 <= row["max_score"] <= 100

    def test_evaluation_is_deterministic(self, eval_run: ModuleType, metrics: dict) -> None:
        second = eval_run.evaluate()
        assert second == metrics                 # no timestamps, no randomness

    def test_write_results_emits_loadable_json(
        self, eval_run: ModuleType, metrics: dict, tmp_path: Path
    ) -> None:
        target = tmp_path / "results" / "metrics.json"
        written = eval_run.write_results(metrics, target)
        assert written == target
        assert json.loads(target.read_text())["schema_version"] == 1
"""Tests for the advisory NLP classifier and its endpoint
(``app.nlp.classify``, ``POST /classify``).

The classifier is advisory only: these tests pin its contract —
categories come from the fixed label set, confidence is a probability,
predictions are deterministic, and every failure degrades to
``available=false`` instead of an exception (AGENTS.md rules 1 and 5).
All messages are synthetic (rule 7).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.nlp import classify as classify_module
from app.nlp.classify import CLASSES, classify_messages

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = REPO_ROOT / "eval" / "nlp" / "dataset.csv"

MESSAGES = [
    "brute force attempt: 24 failed logins for alice from 10.0.0.5",
    "powershell -enc bypass execution policy spawned cmd.exe",
    "user added to domain admins group without change ticket",
    "read cafeteria menu document",
]


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("CYBERSENTRY_DB_PATH", str(tmp_path / "nlp.db"))
    if hasattr(app.state, "database"):
        del app.state.database
    return TestClient(app)


class TestClassifyMessages:
    @pytest.mark.skipif(
        not DATASET_PATH.exists(), reason="labelled dataset not present"
    )
    def test_categories_and_confidences_are_well_formed(self) -> None:
        predictions = classify_messages(MESSAGES)
        assert len(predictions) == len(MESSAGES)
        if predictions[0].category is None:
            assert all(prediction.category is None for prediction in predictions)
            assert all(prediction.reason for prediction in predictions)
            return
        for prediction in predictions:
            assert prediction.category in CLASSES
            assert prediction.confidence is not None
            assert 0.0 <= prediction.confidence <= 1.0
            assert prediction.reason == ""

    @pytest.mark.skipif(
        not DATASET_PATH.exists(), reason="labelled dataset not present"
    )
    def test_predictions_are_deterministic(self) -> None:
        assert classify_messages(MESSAGES) == classify_messages(MESSAGES)

    def test_missing_model_fails_open_with_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken_load() -> tuple[object, object, object]:
            raise RuntimeError("model unavailable")

        monkeypatch.setattr(classify_module, "_load", broken_load)
        predictions = classify_messages(MESSAGES)
        assert len(predictions) == len(MESSAGES)
        for prediction in predictions:
            assert prediction.category is None
            assert prediction.confidence is None
            assert "RuntimeError" in prediction.reason


class TestClassifyEndpoint:
    @pytest.mark.skipif(
        not DATASET_PATH.exists(), reason="labelled dataset not present"
    )
    def test_classify_returns_advisory_predictions(self, client: TestClient) -> None:
        response = client.post("/classify", json={"messages": MESSAGES})
        assert response.status_code == 200
        body = response.json()
        assert body["classes"] == list(CLASSES)
        assert len(body["predictions"]) == len(MESSAGES)
        if not body["available"]:
            assert body["model"] is None
            assert body["reason"]
            assert all(prediction["category"] is None for prediction in body["predictions"])
            return
        assert body["model"]
        for prediction in body["predictions"]:
            assert prediction["category"] in CLASSES
            assert 0.0 <= prediction["confidence"] <= 1.0

    def test_endpoint_fails_open_when_model_unavailable(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken_load() -> tuple[object, object, object]:
            raise ImportError("optional nlp dependencies not installed")

        monkeypatch.setattr(classify_module, "_load", broken_load)
        response = client.post("/classify", json={"messages": ["routine login"]})
        assert response.status_code == 200
        body = response.json()
        assert body["available"] is False
        assert body["model"] is None
        assert body["reason"]
        assert body["predictions"][0]["category"] is None

    @pytest.mark.parametrize(
        "payload",
        [
            {"messages": []},                       # empty list
            {"messages": ["ok"], "extra": 1},       # unknown field
            {"messages": ["   "]},                  # blank after strip
        ],
    )
    def test_invalid_bodies_are_rejected(
        self, client: TestClient, payload: dict
    ) -> None:
        response = client.post("/classify", json=payload)
        assert response.status_code == 422
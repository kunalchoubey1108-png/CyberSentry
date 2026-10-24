"""Advisory message classifier (NLP experiment integration).

Classifies raw log message text into ``credential_access``,
``execution``, ``privilege_escalation``, or ``benign`` using frozen
CySecBERT embeddings (Hugging Face Transformers, CPU) plus a logistic
regression fitted on the hand-labelled set in ``eval/nlp/dataset.csv``.

Integration scope — deliberately **advisory only**:

* predictions never create alerts, never change detections, scores, or
  incidents, and never enter the evidence bundle (AGENTS.md rules 1
  and 3: detection stays deterministic and every finding traces to rule
  and event IDs);
* it performs no actions on any environment (AGENTS.md rule 4);
* it degrades gracefully: if the model, its dependencies, or the
  network are unavailable, every request answers with
  ``available=False`` and a reason instead of raising — a missing model
  never takes the pipeline down (AGENTS.md rule 5).

The model is loaded lazily and cached; the classifier head is refit
once per process on the full labelled dataset (frozen embeddings, so
predictions are deterministic for a given install).
"""

from __future__ import annotations

import csv
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CLASSES = ("credential_access", "execution", "privilege_escalation", "benign")
DATASET_PATH = (
    Path(__file__).resolve().parents[3] / "eval" / "nlp" / "dataset.csv"
)
MODEL_ID = os.environ.get("NLP_MODEL", "markusbayer/CySecBERT")


@dataclass(frozen=True)
class Classification:
    """One message's advisory classification (category None = unavailable)."""

    message: str
    category: str | None
    confidence: float | None
    reason: str = ""


_cache: dict[str, Any] = {}
_cache_lock = threading.Lock()


def _embed(texts: list[str], tokenizer: Any, model: Any) -> Any:
    """Mean-pooled last-hidden-state embeddings on CPU."""
    import numpy as np
    import torch

    vectors: list[Any] = []
    with torch.no_grad():
        for start in range(0, len(texts), 16):
            batch = texts[start : start + 16]
            encoded = tokenizer(
                batch, padding=True, truncation=True, max_length=128,
                return_tensors="pt",
            )
            hidden = model(**encoded).last_hidden_state
            mask = encoded["attention_mask"].unsqueeze(-1)
            pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
            vectors.append(pooled.cpu().numpy())
    return np.vstack(vectors)


def _load() -> tuple[Any, Any, Any]:
    """Load tokenizer, model, and classifier head once per process.

    Raises on any dependency, download, or fit failure — callers turn
    that into a fail-open ``available=False`` answer.
    """
    from sklearn.linear_model import LogisticRegression
    from transformers import AutoModel, AutoTokenizer

    if "model" not in _cache:
        tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
        model = AutoModel.from_pretrained(MODEL_ID)
        model.eval()
        with DATASET_PATH.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        messages = [row["message"].strip() for row in rows]
        labels = [row["label"].strip() for row in rows]
        embeddings = _embed(messages, tokenizer, model)
        head = LogisticRegression(max_iter=2000, class_weight="balanced")
        head.fit(embeddings, labels)
        _cache.update(tokenizer=tokenizer, model=model, head=head)
    return _cache["tokenizer"], _cache["model"], _cache["head"]


def classify_messages(messages: list[str]) -> list[Classification]:
    """Classify each message; never raises — unavailable is data, not an error."""
    cleaned = [message.strip() for message in messages]
    with _cache_lock:
        try:
            tokenizer, model, head = _load()
            embeddings = _embed(cleaned, tokenizer, model)
            categories = head.predict(embeddings)
            confidences = head.predict_proba(embeddings).max(axis=1)
        except Exception as exc:  # fail open: model/deps/network unavailable
            reason = f"{type(exc).__name__}: {exc}"
            return [
                Classification(message=message, category=None, confidence=None,
                               reason=reason)
                for message in cleaned
            ]
    return [
        Classification(
            message=message,
            category=str(category),
            confidence=round(float(confidence), 4),
        )
        for message, category, confidence in zip(
            cleaned, categories, confidences
        )
    ]


__all__ = ["CLASSES", "Classification", "classify_messages"]
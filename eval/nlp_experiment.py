"""Time-boxed experiment: classify log message text into attack categories.

Classes: ``credential_access`` | ``execution`` | ``privilege_escalation``
| ``benign``.

Dataset: ``eval/nlp/dataset.csv`` — synthetic plus hand-labelled messages
(hand-written variants plus fixture messages from data/*.csv), no
duplicate texts.

Two models on ONE stratified held-out split (seed 42, 25% test):

* **baseline** — TF-IDF (word 1-2 grams) + logistic regression;
* **transformer** — CySecBERT mean-pooled embeddings (Hugging Face
  Transformers, CPU) + logistic regression.

A majority-class reference is reported for context.

**Stop condition:** if the model download or CPU inference is blocked
(network, hub, or runtime failure), the transformer leg stops and is
reported as BLOCKED — the experiment never fails and the pipeline is
never touched (AGENTS.md rule 5).

**Integration rule (declared before running):** the transformer may only
enter the pipeline if it *strictly beats* the baseline — higher macro-F1
(4-class, primary) **and** accuracy that is not lower. Otherwise the
non-integration is documented. Results, accuracy, macro-F1, and failure
cases are written to ``eval/results/nlp.md``.

Usage::

    backend/.venv/bin/python eval/nlp_experiment.py      # writes nlp.md
"""

from __future__ import annotations

import csv
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = REPO_ROOT / "eval" / "nlp" / "dataset.csv"
RESULTS_PATH = REPO_ROOT / "eval" / "results" / "nlp.md"

CLASSES = ("credential_access", "execution", "privilege_escalation", "benign")
SOURCES = ("handwritten", "fixture")
SPLIT_SEED = 42
TEST_SIZE = 0.25
MODEL_ID = os.environ.get("NLP_MODEL", "markusbayer/CySecBERT")


class Blocked(RuntimeError):
    """Model download or inference is unavailable — stop, do not fail."""


@dataclass
class Dataset:
    messages: list[str]
    labels: list[str]
    sources: list[str]


@dataclass
class ModelResult:
    name: str
    accuracy: float
    macro_f1: float
    predicted: list[str] = field(default_factory=list)
    note: str = ""


# --------------------------------------------------------------------------
# data
# --------------------------------------------------------------------------


def load_dataset(path: Path = DATASET_PATH) -> Dataset:
    """Load the labelled set; raise on malformed rows, bad labels, dupes."""
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError(f"empty dataset: {path}")
    dataset = Dataset(
        messages=[(row.get("message") or "").strip() for row in rows],
        labels=[(row.get("label") or "").strip() for row in rows],
        sources=[(row.get("source") or "").strip() for row in rows],
    )
    for index, (message, label, source) in enumerate(
        zip(dataset.messages, dataset.labels, dataset.sources)
    ):
        if not message:
            raise ValueError(f"row {index}: empty message")
        if label not in CLASSES:
            raise ValueError(f"row {index}: unknown label {label!r}")
        if source not in SOURCES:
            raise ValueError(f"row {index}: unknown source {source!r}")
    if len(set(dataset.messages)) != len(dataset.messages):
        raise ValueError("duplicate message text would leak across the split")
    if not 150 <= len(dataset.messages) <= 300:
        raise ValueError(
            f"dataset must hold 150-300 messages, got {len(dataset.messages)}"
        )
    return dataset


def split(
    data: Dataset,
) -> tuple[list[str], list[str], list[str], list[str]]:
    """Stratified held-out split (seed 42, 25% test) over messages."""
    return train_test_split(
        data.messages,
        data.labels,
        test_size=TEST_SIZE,
        random_state=SPLIT_SEED,
        stratify=data.labels,
    )


# --------------------------------------------------------------------------
# models
# --------------------------------------------------------------------------


def _score(
    name: str, truth: list[str], predicted: list[str], note: str = ""
) -> ModelResult:
    return ModelResult(
        name=name,
        accuracy=round(float(accuracy_score(truth, predicted)), 4),
        macro_f1=round(
            float(f1_score(truth, predicted, average="macro", zero_division=0)), 4
        ),
        predicted=list(predicted),
        note=note,
    )


def majority_reference(
    train_labels: list[str], test_labels: list[str]
) -> ModelResult:
    """Always predict the most frequent training class (sanity floor)."""
    majority = Counter(train_labels).most_common(1)[0][0]
    return _score(
        "majority-class reference",
        test_labels,
        [majority] * len(test_labels),
        note=f"always predicts {majority}",
    )


def run_baseline(
    train_messages: list[str],
    train_labels: list[str],
    test_messages: list[str],
    test_labels: list[str],
) -> ModelResult:
    """TF-IDF (1-2 grams) + logistic regression."""
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
    train_x = vectorizer.fit_transform(train_messages)
    test_x = vectorizer.transform(test_messages)
    classifier = LogisticRegression(max_iter=2000, class_weight="balanced")
    classifier.fit(train_x, train_labels)
    predicted = [str(label) for label in classifier.predict(test_x)]
    return _score("TF-IDF + logistic regression", test_labels, predicted)


def embed(messages: list[str], model_id: str = MODEL_ID) -> np.ndarray:
    """Mean-pooled last-hidden-state embeddings from the HF model (CPU).

    Raises ``Blocked`` on any download or inference failure — the caller
    documents the stop and continues without the transformer.
    """
    try:
        import torch
        from transformers import AutoModel, AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained(model_id)
        model = AutoModel.from_pretrained(model_id)
        model.eval()
        vectors: list[np.ndarray] = []
        with torch.no_grad():
            for start in range(0, len(messages), 16):
                batch = messages[start : start + 16]
                encoded = tokenizer(
                    batch,
                    padding=True,
                    truncation=True,
                    max_length=128,
                    return_tensors="pt",
                )
                hidden = model(**encoded).last_hidden_state
                mask = encoded["attention_mask"].unsqueeze(-1)
                pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
                vectors.append(pooled.cpu().numpy())
    except Exception as exc:  # stop condition: download/inference blocked
        raise Blocked(f"{type(exc).__name__}: {exc}") from None
    return np.vstack(vectors)


def run_transformer(
    train_messages: list[str],
    train_labels: list[str],
    test_messages: list[str],
    test_labels: list[str],
    model_id: str = MODEL_ID,
) -> ModelResult:
    """CySecBERT embeddings + logistic regression. Raises ``Blocked``."""
    embeddings = embed(train_messages + test_messages, model_id)
    train_x = embeddings[: len(train_messages)]
    test_x = embeddings[len(train_messages) :]
    classifier = LogisticRegression(max_iter=2000, class_weight="balanced")
    classifier.fit(train_x, train_labels)
    predicted = [str(label) for label in classifier.predict(test_x)]
    return _score(
        f"{model_id} embeddings + logistic regression",
        test_labels,
        predicted,
        note="HF transformers, CPU",
    )


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------


def failure_rows(
    truth: list[str], predicted: list[str], messages: list[str]
) -> list[dict[str, str]]:
    """One row per misclassified held-out message."""
    return [
        {"message": message, "true": truth[i], "predicted": predicted[i]}
        for i, message in enumerate(messages)
        if i < len(predicted) and truth[i] != predicted[i]
    ]


def decide_integration(
    baseline: ModelResult, transformer: ModelResult | None, blocked: str | None
) -> tuple[str, str]:
    """The pre-registered rule: strictly beats the baseline -> integrate."""
    if blocked:
        return (
            "NOT INTEGRATED",
            f"The transformer leg was stopped: {blocked}. Per the stop rule "
            "nothing was integrated into the pipeline.",
        )
    assert transformer is not None
    beats = (
        transformer.macro_f1 > baseline.macro_f1
        and transformer.accuracy >= baseline.accuracy
    )
    if beats:
        return (
            "INTEGRATED (advisory only)",
            "The transformer strictly beats the baseline (macro-F1 higher, "
            "accuracy not lower) under the pre-registered rule, so it was "
            "integrated as the advisory classifier "
            "`backend/app/nlp/classify.py` behind the `POST /classify` "
            "endpoint. Integration is advisory by design: detections, "
            "scores, incidents, and reports stay fully deterministic and "
            "never consume these predictions (AGENTS.md rules 1 and 3), "
            "and the endpoint fails open with available=false when the "
            "model or its dependencies are unavailable (rule 5).",
        )
    return (
        "NOT INTEGRATED",
        "The transformer does not beat the baseline under the pre-registered "
        "rule (macro-F1 strictly higher and accuracy not lower), so it was "
        "not integrated into the pipeline — this documents that decision.",
    )


def render_markdown(doc: dict[str, Any]) -> str:
    """Render the full eval/results/nlp.md report."""
    lines = [
        "# NLP message-classification experiment",
        "",
        "Time-boxed experiment: classify log message text into "
        "`credential_access`, `execution`, `privilege_escalation`, or "
        "`benign`. All data is synthetic or hand-written (AGENTS.md "
        "rule 7).",
        "",
        "## Dataset",
        "",
        f"- `{doc['dataset_path']}` — {doc['rows']} unique messages "
        f"({doc['handwritten']} hand-written synthetic + {doc['fixture']} "
        "hand-labelled fixture messages)",
        f"- Class counts: {doc['class_counts']}",
        f"- Held-out split: stratified {doc['train_size']} train / "
        f"{doc['test_size']} test (seed {doc['seed']}, "
        f"{doc['test_ratio']:.0%} held out)",
        "",
        "## Results (held-out test set)",
        "",
        "| model | accuracy | macro-F1 | note |",
        "|---|---|---|---|",
    ]
    for row in doc["model_rows"]:
        accuracy = "—" if row["accuracy"] is None else f"{row['accuracy']:.4f}"
        macro_f1 = "—" if row["macro_f1"] is None else f"{row['macro_f1']:.4f}"
        lines.append(f"| {row['name']} | {accuracy} | {macro_f1} | {row['note']} |")

    lines += ["", "## Failure cases", ""]
    baseline_rows = doc["baseline_failure_rows"]
    lines.append(
        f"### {doc['model_rows'][1]['name']} (baseline): "
        f"{len(baseline_rows)} of {doc['test_size']} held-out messages wrong"
    )
    lines.append("")
    if baseline_rows:
        lines += ["| message | true | predicted |", "|---|---|---|"]
        for row in baseline_rows:
            lines.append(f"| {row['message']} | {row['true']} | {row['predicted']} |")
    else:
        lines.append("No misclassified held-out messages.")
    lines.append("")

    transformer_rows = doc["transformer_failure_rows"]
    if doc["blocked"]:
        lines += [
            "### Transformer model",
            "",
            "Not evaluated — see the stop condition below.",
            "",
        ]
    elif transformer_rows is not None:
        lines.append(
            f"### {doc['model_rows'][2]['name']}: "
            f"{len(transformer_rows)} of {doc['test_size']} held-out "
            "messages wrong"
        )
        lines.append("")
        if transformer_rows:
            lines += ["| message | true | predicted |", "|---|---|---|"]
            for row in transformer_rows:
                lines.append(
                    f"| {row['message']} | {row['true']} | {row['predicted']} |"
                )
        else:
            lines.append("No misclassified held-out messages.")
        lines.append("")

    lines += ["## Stop condition", ""]
    if doc["blocked"]:
        lines += [
            f"The transformer leg was **stopped**: {doc['blocked']}.",
            "Model download or CPU inference was blocked, so per the "
            "experiment rules the transformer was abandoned and nothing was "
            "integrated.",
        ]
    else:
        lines += [
            "Model download and CPU inference completed within the time box.",
            "No stop condition triggered for the transformer leg.",
        ]
    lines += [
        "",
        "## Integration decision",
        "",
        f"**{doc['decision']}** — {doc['decision_reason']}",
        "",
        "Rule (declared before running): the transformer qualifies only "
        "with strictly higher macro-F1 and accuracy not lower than the "
        "baseline. Detection in the product stays deterministic either way "
        "(AGENTS.md rule 1); this experiment does not change scores, "
        "alerts, or the pipeline unless it wins.",
        "",
    ]
    return "\n".join(lines)


def print_summary(doc: dict[str, Any]) -> None:
    """Print the results table to stdout."""
    print(
        f"dataset: {doc['rows']} messages | split: "
        f"{doc['train_size']}/{doc['test_size']} (seed {doc['seed']})"
    )
    width = max(len(row["name"]) for row in doc["model_rows"])
    print(f"{'model':<{width}}  accuracy  macro-F1  note")
    for row in doc["model_rows"]:
        accuracy = "   n/a " if row["accuracy"] is None else f"{row['accuracy']:8.4f}"
        macro_f1 = "  n/a " if row["macro_f1"] is None else f"{row['macro_f1']:8.4f}"
        print(f"{row['name']:<{width}}  {accuracy}  {macro_f1}  {row['note']}")
    print(f"baseline failure cases: {doc['baseline_failures']}")
    print(f"decision: {doc['decision']}")


def evaluate() -> dict[str, Any]:
    """Run the whole experiment and return the report document."""
    data = load_dataset()
    train_messages, test_messages, train_labels, test_labels = split(data)
    class_counts = Counter(data.labels)

    reference = majority_reference(train_labels, test_labels)
    baseline = run_baseline(
        train_messages, train_labels, test_messages, test_labels
    )

    blocked: str | None = None
    transformer: ModelResult | None = None
    try:
        transformer = run_transformer(
            train_messages, train_labels, test_messages, test_labels
        )
    except Blocked as exc:
        blocked = str(exc)

    baseline_failures = failure_rows(
        test_labels, baseline.predicted, test_messages
    )
    transformer_failures = (
        failure_rows(test_labels, transformer.predicted, test_messages)
        if transformer is not None
        else None
    )
    decision, reason = decide_integration(baseline, transformer, blocked)

    model_rows: list[dict[str, Any]] = [
        {
            "name": reference.name,
            "accuracy": reference.accuracy,
            "macro_f1": reference.macro_f1,
            "note": reference.note,
        },
        {
            "name": baseline.name,
            "accuracy": baseline.accuracy,
            "macro_f1": baseline.macro_f1,
            "note": "TF-IDF + LR",
        },
        {
            "name": (
                transformer.name
                if transformer is not None
                else f"{MODEL_ID} embeddings + logistic regression"
            ),
            "accuracy": transformer.accuracy if transformer else None,
            "macro_f1": transformer.macro_f1 if transformer else None,
            "note": f"BLOCKED — {blocked}" if blocked else "HF transformers, CPU",
        },
    ]

    return {
        "dataset_path": str(DATASET_PATH.relative_to(REPO_ROOT)),
        "rows": len(data.messages),
        "handwritten": data.sources.count("handwritten"),
        "fixture": data.sources.count("fixture"),
        "class_counts": ", ".join(
            f"{name}={count}" for name, count in sorted(class_counts.items())
        ),
        "seed": SPLIT_SEED,
        "test_ratio": TEST_SIZE,
        "train_size": len(train_messages),
        "test_size": len(test_messages),
        "model_rows": model_rows,
        "baseline_failure_rows": baseline_failures,
        "baseline_failures": len(baseline_failures),
        "transformer_failure_rows": transformer_failures,
        "transformer_failures": (
            len(transformer_failures) if transformer_failures is not None else None
        ),
        "blocked": blocked,
        "decision": decision,
        "decision_reason": reason,
    }


def main() -> int:
    doc = evaluate()
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(render_markdown(doc), encoding="utf-8")
    print_summary(doc)
    print(f"wrote {RESULTS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
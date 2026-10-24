# CyberSentry AI — Project Context

Evidence-first security incident triage copilot. A hackathon project.

## What it does

CyberSentry ingests CSV/JSON security logs, validates them, detects suspicious
patterns with **deterministic Python rules**, correlates events into incidents,
computes a transparent risk score, and generates an LLM report where **every
claim cites real event IDs**.

Pipeline:

```
logs (CSV/JSON) -> ingest/validate -> detect (rules) -> correlate -> score -> evidence -> LLM report
```

The LLM sits at the *end* of the pipeline, never in the middle. It explains and
summarizes what the deterministic stages already produced; it never produces
findings of its own.

## Stack

- **Backend:** Python 3.11, FastAPI, pandas, pydantic, SQLite, pytest
- **Frontend:** React + Tailwind (Vite)
- **LLM:** optional; rules-only mode must always work

## Repo layout

```
backend/app/
  main.py        FastAPI app, routes
  schema.py      pydantic models for events/incidents/reports
  ingest.py      CSV/JSON loading + validation
  correlate.py   event -> incident correlation
  scoring.py     transparent risk scoring
  evidence.py    evidence bundles (rule + event IDs)
  db.py          SQLite persistence
  rules/         deterministic detection rules
  llm/
    client.py    LLM API wrapper (optional)
    prompts.py   prompt templates
    promptshield.py  untrusted-data handling
    validate.py  claim -> evidence validation
backend/tests/   pytest tests, one per module
data/            synthetic logs only
eval/            evaluation runs and fixtures
frontend/        React + Tailwind (Vite)
docs/            design notes, screenshots, demo material
```

## Rules for all future work

These are non-negotiable. Any change that violates them is a bug, regardless of
how well it builds or tests.

1. **Deterministic detection comes first.** Rules run in plain Python and fully
   determine detections, incidents, and scores. The LLM never changes scores,
   never changes detection results, never adds or removes alerts.
2. **Log text is untrusted data.** Message fields, hostnames, usernames, IPs —
   everything ingested from logs — are attacker-controllable strings. They must
   never be interpreted as instructions to the model or the system. Prompt
   templates must separate instructions from data; `promptshield.py` enforces
   this. Watch for prompt injection in log content.
3. **Every alert traces to rule IDs and event IDs.** No finding may exist
   without a rule ID that produced it and the concrete event IDs that support
   it. The LLM report must cite real event IDs; `llm/validate.py` checks each
   claim against the evidence bundle and drops or flags uncited claims.
4. **No autonomous actions.** This is a triage copilot: it detects, correlates,
   scores, and reports. It never blocks, quarantines, mutates data, or executes
   commands. No tool use that performs actions on the environment.
5. **Rules-only fallback must always work.** With no LLM key configured, the
   full pipeline runs end to end and emits a rules-based report. LLM failure or
   absence degrades gracefully; it never breaks the pipeline.
6. **Keep code simple, typed, and tested.** Type hints everywhere, pydantic at
   boundaries, small functions, no clever abstractions. **Write tests for every
   module** — including rules, scoring, correlation, promptshield, and claim
   validation.
7. **Synthetic data only.** No real logs, no real user data, no production
   captures. Generate fixtures and demo data; label them as synthetic.

## Design principles

- **Evidence-first:** the evidence bundle is the source of truth. Reports are
  derived from it, never the other way around.
- **Transparent scoring:** a score must be explainable as a sum of named
  contributions from specific rules and events. A human can audit why an
  incident got the number it got.
- **Fail closed on trust, fail open on availability:** untrusted or
  unverifiable LLM output is discarded, not used; but missing LLM access must
  never take the product down.

## Definition of done for a change

- Type-checks and passes `pytest` (including new tests for new modules).
- Every new alert/rule has an ID and traces to event IDs.
- No path from log content to system instructions or model-controlled behavior.
- Works with no LLM key set.
- Data used in tests and demos is synthetic.

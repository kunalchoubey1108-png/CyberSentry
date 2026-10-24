# CyberSentry AI

CyberSentry AI is a synthetic-data hackathon prototype for evidence-first
security incident triage. It ingests CSV/JSON logs, validates each record,
detects a small set of suspicious patterns with deterministic Python rules,
correlates matches into incidents, computes an explainable heuristic score,
and produces an evidence-grounded report. The optional LLM explains existing
evidence only; it does not create alerts or change detections or scores.

> **Prototype notice:** This is not a production detection or response system.
> Scores are heuristic triage aids, not probabilities. Review all evidence and
> conclusions as an analyst. The fixtures are synthetic; real-world
> performance has not been established.

## Quick start

Requirements: Python 3.11, `uv`, Node.js/npm.

```sh
make install
make test
```

For a local API and frontend, use separate terminals:

```sh
make run
```

```sh
cd frontend && npm run dev
```

Open the Vite URL printed in the frontend terminal (normally
`http://localhost:5173`). The frontend expects the API at
`http://localhost:8000`; override it with `VITE_API_BASE` if needed.

## Offline demo

In one terminal:

```sh
make demo
```

This resets only the dedicated `backend/cybersentry-demo.sqlite3` database,
loads the synthetic `data/sample_attacks.csv` file, computes incidents, and
pre-caches deterministic rules-only reports. The API then serves reports in
`CYBERSENTRY_REPORT_MODE=cached` and does not call an LLM. In another terminal,
run `cd frontend && npm run dev`. The demo database is ignored by Git.

For normal use, `make run` uses `backend/cybersentry.db` and the default
`live` report mode. With no LLM key, reports use the rules-only fallback. In
live mode, successfully validated reports are cached in SQLite for later
offline reuse. Set `CYBERSENTRY_DB_PATH` to use a different database. The
demo target deliberately resets its dedicated demo database each time.

## Architecture

```text
CSV/JSON logs
  -> ingest and schema validation
  -> deterministic rules (R1-R4)
  -> event correlation
  -> transparent risk score
  -> evidence bundle
  -> validated LLM explanation or rules-only report
```

The LLM is at the end of the pipeline, never in the detection or scoring
path. Log fields are untrusted. PromptShield sanitizes and fences evidence,
keeps instructions separate from log data, and flags instruction-like text
for analyst review. Model reports are schema-checked and their cited event
IDs are validated; unusable output falls back to a deterministic template.
The system does not block, quarantine, execute commands, or take other
autonomous response actions.

## Input schema

CSV files have a header row. JSON files contain an array of event objects;
JSONL/NDJSON files contain one object per line.

| Field | Meaning / validation |
|---|---|
| `event_id` | String; generated and flagged when absent; duplicates rejected |
| `timestamp` | ISO 8601, normalized to UTC |
| `event_type` | `login_failed`, `login_success`, `privilege_change`, `process_start`, `file_access`, `alert`, or `other` |
| `user`, `host` | Required, trimmed, lowercased strings |
| `src_ip` | Required valid IPv4 or IPv6 |
| `severity` | Integer 0–10; defaults to 3 |
| `message` | Free text, capped at 1000 characters; always untrusted |
| `privileged` | Optional boolean |

Malformed rows are returned as rejected records with a reason; they are not
silently coerced. Asset reference data is in `data/assets.csv` and has
`host`, `criticality` (1–5), and `role` columns.

## Detection rules

Thresholds are loaded from `backend/config.yaml`.

| Rule | Detection |
|---|---|
| R1 | At least 5 failures for one user and IP within 10 minutes, followed by a same-user/IP success within 15 minutes |
| R2 | A privileged action within 30 minutes of an R1-matched login or a success from an IP not previously seen for that user in the supplied data |
| R3 | Failures from one IP against at least 5 distinct users within 10 minutes |
| R4 | A successful login or privileged action outside configurable UTC business hours on a host with criticality at least 4 |

Every match carries a rule ID, severity, matched event IDs, reason, and
entities. Correlated incidents retain the matched and contextual timeline
events; contextual events do not create detections.

Run the rule summary against the synthetic attack fixture:

```sh
cd backend && .venv/bin/python -m app.rules.cli
```

## Risk scoring

The 0–100 incident score is
`min(100, rule + corroboration + event volume + asset + privilege + sequence)`.

| Component | Formula | Cap |
|---|---|---:|
| Rule | Strongest matched severity × 5 | 40 |
| Corroboration | 5 per additional distinct rule | 15 |
| Event volume | `floor(log2(matched event count))` | 10 |
| Asset | Highest involved host criticality × 4 | 20 |
| Privilege | 10 if a matched event is privileged | 10 |
| Sequence | 5 when failure → success → privileged action is observed | 5 |

Bands are Low (0–34), Medium (35–59), High (60–79), and Critical (80–100).
See [docs/scoring.md](docs/scoring.md) for the worked example and caveats.
This score is an auditable heuristic, **not a probability** or calibrated
estimate of compromise.

## Reports and LLM configuration

Without a key, the system creates a rules-only report with real event-ID
citations. Optional provider settings:

```sh
LLM_PROVIDER=openai          # openai (default), anthropic, or local
LLM_MODEL=gpt-4o-mini        # optional override
LLM_API_KEY=...              # or OPENAI_API_KEY / ANTHROPIC_API_KEY
LLM_BASE_URL=...             # optional OpenAI-compatible endpoint override
```

Do not commit API keys. Requests have a 30-second timeout and one retry.
Invalid, unsafe, or ungrounded model output is rejected and replaced with the
rules-only template. Cached mode (`CYBERSENTRY_REPORT_MODE=cached`) serves
previously cached validated reports and uses the deterministic template when
no cached entry exists; it never contacts a provider.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness and LLM availability |
| POST | `/upload` | Ingest a CSV/JSON/JSONL log and run the pipeline |
| GET | `/incidents` | Incident summaries, highest score first |
| GET | `/incidents/{id}` | Evidence bundle and timeline |
| POST | `/incidents/{id}/report` | Validated LLM or deterministic report |
| POST | `/classify` | Optional advisory message classifier; not used for detection |

## Tests and evaluation

```sh
make test
make eval
cd frontend && npm run build && npm run lint
```

All checked-in log fixtures and evaluation scenarios are synthetic. Regenerate
the labelled log set with `python data/generate_data.py`. `make eval` computes
the metrics from `data/labelled/labels.json` and writes the current outputs:
[results table](eval/results/results.csv),
[evaluation summary and failure cases](eval/results/results.md), and
[NLP experiment](eval/results/nlp.md). The latest checked-in evaluation has
**1.0000 precision, 0.3846 recall, 0.0000 false-positive rate, and 1.0000
evidence-grounding rate** on this small synthetic set. Eight labelled
scenarios were missed; inspect the failure list before interpreting the
headline metrics. These numbers are not production-quality guarantees.

## Limitations

- The labelled data and adversarial fixtures are synthetic and small.
- The implemented rules cover only a narrow set of authentication and
  off-hours patterns. Current recall is low; several labelled patterns are
  intentionally reported as missed rather than inferred from message text.
- Correlation and scoring are deterministic heuristics, not calibrated models.
- The optional NLP experiment is advisory and does not feed alerts or scores.
- Log quality, event completeness, clock accuracy, asset inventory, and
  identities are not independently verified.
- LLM output can be unavailable or rejected; fallback reports are simpler.
- This prototype is read-only triage support. Human review is required, and
  no report establishes proof of compromise.

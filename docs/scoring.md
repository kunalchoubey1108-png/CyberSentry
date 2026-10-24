# Incident risk scoring

CyberSentry assigns each correlated incident a deterministic risk score
from 0 to 100. The score is computed in `backend/app/scoring.py` from the
evidence the deterministic rules already produced (rule IDs, event IDs,
asset criticality). Nothing in it is random, model-generated, or
influenced by the LLM — the LLM only *explains* the number, never
produces it (AGENTS.md rule 1).

## Formula

```
score = min(100,
            rule_component       # severity of the strongest rule
          + corroboration        # additional independent rules agreeing
          + event_volume         # how much evidence there is
          + asset_component      # criticality of the assets involved
          + privilege_component  # a privileged action was involved
          + sequence_bonus)      # failure -> success -> privilege observed
```

| Component | Definition | Cap |
|---|---|---|
| `rule_component` | max matched-rule severity × 5 | 40 |
| `corroboration` | 5 per additional distinct rule beyond the first | 15 |
| `event_volume` | floor(log2(number of matched events)) | 10 |
| `asset_component` | max asset criticality of involved hosts × 4 | 20 |
| `privilege_component` | 10 if any matched event is a privileged action | 10 |
| `sequence_bonus` | 5 if a failure → success → privileged ordering is observed among matched events | 5 |

Details:

- Rule severity is the 1–10 integer the rule set already carries (from
  `config.yaml`); asset criticality is 1–5 from `data/assets.csv`.
- Hosts missing from the asset inventory contribute 0 to the asset
  component — unknown is not equal to critical (same policy as rule R4).
- `event_volume` uses the floor of log2: 1 matched event → 0, 4 → 2,
  10 → 3, 1024 → 10, and everything at 1024 or above stays at 10.
- The component caps sum to exactly 100, so the outer `min(100, …)` is
  defense in depth rather than a frequently hit bound.
- Only rule-matched events count toward volume, privilege, and sequence;
  contextual timeline events never change the score.

## Bands

| Score | Band |
|---|---|
| 0–34 | Low |
| 35–59 | Medium |
| 60–79 | High |
| 80–100 | Critical |

## What the score is (and is not)

**The score is a heuristic triage aid, not a probability.** It does not
estimate the likelihood that an incident is a true positive, does not
quantify expected business impact, and has no statistical calibration
behind it. It is a compact, auditable summary of what the deterministic
rules found, ordered so a human reviewer can look at the most
evidence-dense incidents first.

Because every component is a named contribution derived from specific
rule IDs and event IDs, any score can be reconstructed by hand from the
incident's evidence bundle (`backend/app/evidence.py`), which carries
the score, each component, the rules with their reasons, and the
supporting records. Scores are deterministic: the same evidence yields
the same score on every run, with or without an LLM key configured.

## Worked example

Scenario (a) from `data/sample_attacks.csv` — 8 failed logins, a
success, then a privileged action (rules R1 severity 8 and R2 severity
9, host `web-01.lab.local` criticality 4):

| Component | Computation | Value |
|---|---|---|
| rule_component | 9 × 5 = 45, capped | 40 |
| corroboration | 1 additional rule × 5 | 5 |
| event_volume | floor(log2(10)) | 3 |
| asset_component | 4 × 4 | 16 |
| privilege_component | privileged action present | 10 |
| sequence_bonus | failure → success → privilege observed | 5 |
| **score** | min(100, 79) | **79 (High)** |

# NLP message-classification experiment

Time-boxed experiment: classify log message text into `credential_access`, `execution`, `privilege_escalation`, or `benign`. All data is synthetic or hand-written (AGENTS.md rule 7).

## Dataset

- `eval/nlp/dataset.csv` — 188 unique messages (136 hand-written synthetic + 52 hand-labelled fixture messages)
- Class counts: benign=58, credential_access=51, execution=42, privilege_escalation=37
- Held-out split: stratified 141 train / 47 test (seed 42, 25% held out)

## Results (held-out test set)

| model | accuracy | macro-F1 | note |
|---|---|---|---|
| majority-class reference | 0.3191 | 0.1210 | always predicts benign |
| TF-IDF + logistic regression | 0.7872 | 0.7612 | TF-IDF + LR |
| markusbayer/CySecBERT embeddings + logistic regression | 0.8511 | 0.8457 | HF transformers, CPU |

## Failure cases

### TF-IDF + logistic regression (baseline): 10 of 47 held-out messages wrong

| message | true | predicted |
|---|---|---|
| kernel driver loaded disabling endpoint protections | privilege_escalation | execution |
| installer ran preinstall script as session user | execution | benign |
| change ticket approved and applied by operations admin | benign | privilege_escalation |
| setuid binary planted in local bin | privilege_escalation | execution |
| scheduled backup job started | execution | benign |
| vault token bruteforced by rotating client secrets | credential_access | benign |
| started remote desktop gateway | execution | benign |
| runas spawned elevated administrator shell | privilege_escalation | execution |
| python reverse shell connected to internal host port 4444 | execution | privilege_escalation |
| container started with privileged host mounts | execution | benign |

### markusbayer/CySecBERT embeddings + logistic regression: 7 of 47 held-out messages wrong

| message | true | predicted |
|---|---|---|
| change ticket approved and applied by operations admin | benign | privilege_escalation |
| scheduled backup job started | execution | benign |
| release build deployed through pipeline | benign | execution |
| started remote desktop gateway | execution | benign |
| helpdesk member reset domain admin password | privilege_escalation | benign |
| sso assertion accepted | benign | credential_access |
| container started with privileged host mounts | execution | privilege_escalation |

## Stop condition

Model download and CPU inference completed within the time box.
No stop condition triggered for the transformer leg.

## Integration decision

**INTEGRATED (advisory only)** — The transformer strictly beats the baseline (macro-F1 higher, accuracy not lower) under the pre-registered rule, so it was integrated as the advisory classifier `backend/app/nlp/classify.py` behind the `POST /classify` endpoint. Integration is advisory by design: detections, scores, incidents, and reports stay fully deterministic and never consume these predictions (AGENTS.md rules 1 and 3), and the endpoint fails open with available=false when the model or its dependencies are unavailable (rule 5).

Rule (declared before running): the transformer qualifies only with strictly higher macro-F1 and accuracy not lower than the baseline. Detection in the product stays deterministic either way (AGENTS.md rule 1); this experiment does not change scores, alerts, or the pipeline unless it wins.

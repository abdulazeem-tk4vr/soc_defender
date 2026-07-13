# Baseline Parity

Last updated: 2026-06-24

## Procedure

Use the same OpenSec seed selection, max-step handling, action normalization, scoring, and output schema for baseline and `soc_defender` runs.

Baseline command shape:

```powershell
py -3.13 scripts\eval.py --defender baseline --ollama --ollama-model qwen2.5:14b --split eval --tier standard --limit 40 --output outputs\qwen25_14b_baseline_standard40.jsonl --summary outputs\qwen25_14b_baseline_standard40_summary.json
```

Local rule-based calibration command:

```powershell
py -3.13 scripts\eval.py --defender evidence_gate_only --no-rag --split train --tier standard --limit 40 --output outputs\evidence_gate_train_standard40.jsonl --summary outputs\evidence_gate_train_standard40_summary.json
```

`--no-rag` is used for rule-based MVP calibration. The local RAG manifest currently records a CUDA device, and this machine's Torch build is CPU-only.

## Current Reference Results

Existing upstream qwen2.5:14b eval baseline from `../opensec-env/outputs/qwen25_14b_baseline_standard40_summary.json`:

| Metric | Value |
|---|---:|
| runs | 40 |
| mean_reward | 0.3775 |
| containment_executed_rate | 0.625 |
| report_submitted_rate | 0.65 |
| correct_containment_rate | 0.4 |
| false_positive_rate | 0.45 |
| injection_exposure_rate | 0.85 |
| injection_violation_rate | 0.375 |

Current `evidence_gate_only` train standard40 calibration from `outputs/evidence_gate_train_standard40_summary.json`:

| Metric | Value |
|---|---:|
| runs | 40 |
| mean_reward | 2.36 |
| containment_executed_rate | 0.45 |
| report_submitted_rate | 1.0 |
| correct_containment_rate | 0.45 |
| false_positive_rate | 0.225 |
| injection_exposure_rate | 0.975 |
| injection_violation_rate | 0.025 |

Failure analysis from `outputs/evidence_gate_train_standard40_failures.json`:

| Metric | Value |
|---|---:|
| report_missing | 0 |
| containment_false_positive_runs | 9 |
| containment_false_positive_total | 9 |
| injection_violation_runs | 1 |
| injection_violation_total | 4 |
| low_egar_runs | 0 |
| invalid_or_placeholder_query_count | 0 |
| repeated_query_count | 54 |
| attacker_domain gaps | 18 |
| data_target gaps | 31 |

## Allowed Differences

`soc_defender` agent runs include `graph_trace` for local defender modes. Baseline runs have an empty `graph_trace`.

The rule-based defender reports normalized `containment_actions` from executed environment state. Baseline model reports may contain intended containment in `summary_json` that was never executed.

## Remaining Parity Work

Run a fresh post-change `full_agentic --no-rag --split eval --tier standard --limit 40` comparison against the qwen2.5:14b baseline. The existing `outputs/qwen25_14b_full_agentic_standard40.jsonl` predates the current verifier-to-responder graph wiring and should not be treated as final parity evidence.

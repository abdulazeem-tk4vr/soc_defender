# ML Calibration Progress Plan

Last updated: 2026-06-26

Reference plan: `/workspace/opensec-env/docs/ml_novelty.md`

This document turns the train-only SecureBERT2, HDBSCAN/IsolationForest, and XGBoost calibration proposal into an implementation plan for `soc_defender`. The ML layer is advisory. It can guide investigation objective selection and add containment sufficiency scores, but it must not directly execute containment or bypass SQL safety, evidence gates, verifier selection, report readiness, or the single committed OpenSec action boundary.

## Objective

Add a train-only ML calibration layer that improves:

- Patient-zero host attribution, especially avoiding confusion between `h-XXX-01` and lateral/staging/exfil hosts such as `h-XXX-02`.
- Compromised-user, attacker-domain, and data-target attribution.
- Investigation query choice under the 15-step budget.
- Containment precision and sufficiency scoring.
- False-positive containment reduction under prompt-injection and decoy evidence.

The expected first integration target is the existing `evidence_gate_only` / `full_agentic` shared pipeline:

```text
observation
  -> evidence registry + report readiness
  -> ML objective/scoring advisory
  -> SQL planner / investigator intent
  -> verifier + deterministic EGAR gates
  -> responder commits one OpenSec action
```

## Non-Negotiable Constraints

- Training must read only `/workspace/opensec-env/data/seeds/train`.
- Eval seeds must never be read by dataset builders, feature builders, model training, or threshold tuning.
- ML artifacts must fail closed. Missing, incompatible, or unloadable artifacts fall back to current deterministic behavior.
- ML scores are not action authorization. Containment still requires verifier-approved candidates and deterministic evidence gates.
- Prompt-injection target params and entity-pool decoys should become negative labels unless independently supported by trusted or corroborated telemetry.
- Runtime code must keep the current OpenSec step contract: internal ML inference is free, but only the final `env.step(action)` consumes one benchmark step.

## Current Baseline Context

Implemented foundation in `soc_defender`:

- Evidence registry with entity support, trust tiers, scanner metadata, and source-table extraction.
- Safe SQL planner and central action validation.
- Deterministic verifier with evidence-gated containment.
- Report readiness for `patient_zero_host`, `compromised_user`, `attacker_domain`, `data_target`, and `initial_vector`.
- Full-agentic graph scaffold with investigator/verifier contracts and RAG hooks.
- Train-only regex training-set builder and failure analyzer.

Known gaps from `docs/progress.md`:

- Train standard40 still has false-positive containment runs.
- `attacker_domain` and `data_target` attribution remain weak.
- Repeated broad SQL queries waste steps.
- Report attribution is heuristic and can look complete while being semantically wrong.

These gaps are the reason to add ML calibration. The first ML milestone should therefore improve planner choice and scoring confidence before changing containment behavior.

## Artifact Layout

Target runtime artifact directory:

```text
defender/models/opensec_train_calibrator/
  manifest.json
  feature_schema.json
  label_schema.json
  embedding_metadata.json
  cluster_model.joblib
  isolation_model.joblib
  investigation_xgb.json
  containment_xgb.json
  calibration_report.json
```

Dataset and intermediate outputs should stay outside tracked runtime artifacts unless intentionally committed:

```text
outputs/ml_training/
  train_examples.jsonl
  train_features.jsonl
  train_eval_report.json
```

## Phase 0: Dependency And Interface Decision

Status: not started

Goal: define the minimal dependency surface and stable runtime API before training code lands.

To do:

- Add ML extras to `pyproject.toml`, likely under a new optional extra named `ml`.
- Candidate dependencies:
  - `sentence-transformers`
  - `xgboost`
  - `hdbscan`
  - `scikit-learn`
  - `joblib`
- Decide whether `torch` and `sentence-transformers` are reused from the existing `agentic` extra or repeated in `ml`.
- Define `defender/ml_calibrator.py` API:
  - `load_ml_calibrator(config) -> MLCalibrator | None`
  - `score_objectives(state) -> ObjectiveScores`
  - `score_containment(candidate, state) -> ContainmentScore`
  - `is_available -> bool`
- Define config shape:

```yaml
ml_calibrator:
  enabled: false
  artifact_dir: defender/models/opensec_train_calibrator
  objective_weight: 0.0
  containment_advisory_only: true
```

Acceptance checks:

- Existing tests pass with ML dependencies absent.
- Disabled or missing artifact config returns the same behavior as today.
- Config default keeps ML off until artifacts and tests exist.

## Phase 1: Train-Only Dataset Builder

Status: not started

Goal: create deterministic step-level training examples from train seeds and ground truth.

Primary file:

- `scripts/build_ml_training_set.py`

Inputs:

- `/workspace/opensec-env/data/seeds/train/*_seed.json`
- `/workspace/opensec-env/data/seeds/train/*_ground_truth.json`

Allowed seed fields:

- `seed_artifacts.emails`
- `seed_artifacts.log_templates`
- `prompt_injection_payloads`
- `entities`
- `attack_plan.timeline`
- `metadata.max_steps`

Allowed ground-truth fields:

- `attribution.patient_zero_host`
- `attribution.compromised_user`
- `attribution.attacker_domain`
- `attribution.data_target`
- `containment_requirements.isolate_hosts`
- `containment_requirements.block_domains`
- `containment_requirements.reset_users`

To do:

- Pair each train seed with its ground-truth file.
- Simulate step-level evidence availability from the attack timeline.
- Extract evidence text from emails, alerts, auth logs, netflow, and process events.
- Emit candidate entities for user, host, domain, and target decisions.
- Emit prompt-injection targets and decoy entities as explicit negative candidates.
- Mark source table, trust tier, evidence ID, injection ID, step index, and scenario ID.
- Enforce a hard path guard that rejects any path containing `/eval/`.
- Write JSONL examples with stable schema and deterministic ordering.

Labels to emit:

- Investigation objective label:
  - `find_identity`
  - `find_patient_zero`
  - `find_attacker_domain`
  - `find_data_target`
  - `corroborate_containment`
  - `submit_report`
- Containment sufficiency label:
  - `sufficient_evidence`
  - `insufficient_evidence`
- Report-field candidate labels for each attribution field.

Acceptance checks:

- Unit test proves eval seed paths are rejected or never discovered.
- Example counts are deterministic across repeated runs.
- Negative examples include prompt-injection target params and wrong lateral/staging hosts.
- Positive containment labels require ground-truth match and evidence availability by that step.

## Phase 2: Feature And Embedding Pipeline

Status: not started

Goal: turn examples into stable numeric features with SecureBERT2 embeddings and unsupervised calibration features.

Primary code:

- `scripts/train_ml_calibrator.py`
- Shared feature helpers, either in `defender/ml_features.py` or inside training script until stable.

Embedding backend:

```text
sentence-transformers
cisco-ai/SecureBERT2.0-biencoder
```

Structured features:

- Step index and steps remaining.
- Missing report fields.
- Known entity counts by type.
- Evidence counts by table.
- Trust-tier counts.
- Candidate entity type.
- Candidate source table.
- Candidate evidence count.
- Indicators for phish, credential, lateral, stage, target, exfil, destination domain.
- `has_injection_id`.
- `is_untrusted`.
- Candidate appears in prompt-injection target params.

Unsupervised features:

- HDBSCAN:
  - `cluster_id`
  - `cluster_probability`
  - `is_noise`
- IsolationForest:
  - `anomaly_score`

To do:

- Build a feature schema with explicit names, types, defaults, and version.
- Normalize missing values consistently.
- Cache embeddings by evidence text hash to avoid repeated SecureBERT2 work.
- Fit HDBSCAN and IsolationForest only on train embeddings.
- Join cluster/anomaly features back into step-level examples.
- Persist feature schema and embedding metadata with model artifacts.

Acceptance checks:

- Feature vectors are numeric, fixed-width, and deterministic.
- Runtime feature builder can score a partial state with missing values.
- Feature schema mismatch causes fail-closed fallback.

## Phase 3: XGBoost Model Training

Status: not started

Goal: train two advisory models and produce inspectable calibration reports.

Primary file:

- `scripts/train_ml_calibrator.py`

Models:

- Model A: investigation objective classifier.
- Model B: containment sufficiency classifier.

To do:

- Train with grouped validation by scenario ID to avoid same-scenario leakage across train/validation splits.
- Track per-class precision/recall for investigation objective labels.
- Track containment sufficiency precision, recall, false-positive rate, and calibration by score bucket.
- Save XGBoost model files and metadata under `defender/models/opensec_train_calibrator/`.
- Include a `manifest.json` with:
  - source split: `train`
  - source root
  - script version
  - feature schema hash
  - label schema hash
  - model package versions
  - created timestamp
  - seed IDs used
- Save `calibration_report.json` with metrics and confusion matrices.

Acceptance checks:

- Training command refuses non-train splits.
- Artifact manifest proves train-only source.
- Re-running training with the same inputs and random seeds produces comparable metrics and compatible schemas.

## Phase 4: Runtime ML Calibrator

Status: not started

Goal: load artifacts safely and expose advisory scores to existing policy and graph code.

Primary file:

- `defender/ml_calibrator.py`

To do:

- Load manifest, schemas, HDBSCAN, IsolationForest, XGBoost models, and embedding metadata.
- Validate artifact versions and feature schema before enabling.
- Build runtime features from:
  - `ParsedObservation`
  - evidence registry snapshot
  - report readiness state
  - prior committed actions
  - current budget phase
  - scanner annotations
- Return objective scores with reasons and top contributing structured features where practical.
- Return containment sufficiency score as advisory metadata attached to candidate actions.
- Keep all failures local: log/trace unavailable status and return deterministic fallback decisions.

Acceptance checks:

- Missing artifact directory does not break `SocDefenderAgent`.
- Corrupt schema/model file disables ML and preserves current behavior.
- ML score object is serializable into graph trace / eval JSONL metadata.

## Phase 5: Investigation Planner Integration

Status: not started

Goal: use ML objective scores to reduce repeated broad queries and prioritize evidence sources for missing report fields.

Likely files:

- `defender/policy.py`
- `defender/sql_planner.py`
- `defender/investigator.py`
- `defender/graph.py`
- `defender/graph_state.py`

To do:

- Add ML objective scores to investigator state or policy context.
- Map high-confidence objectives to SQL planner intent:
  - `find_identity` / `find_patient_zero` -> `auth_logs`, then corroborating `process_events` or alerts.
  - `find_attacker_domain` -> alerts and netflow with explicit domain fields.
  - `find_data_target` -> process events with `target=` fields.
  - `corroborate_containment` -> source-table-specific entity queries.
  - `submit_report` -> no extra query unless required fields remain unknown.
- Avoid repeating broad SQL once an ML objective has a specific next source.
- Keep deterministic planner fallback when scores are low, tied, unavailable, or stale.

Acceptance checks:

- Tests show ML-guided planner prefers `auth_logs` when identity/patient-zero are missing.
- Tests show ML-guided planner prefers alerts/netflow for attacker domain.
- Tests show ML-guided planner prefers process events for data target.
- Repeated broad query count decreases on train smoke runs.

## Phase 6: Containment Sufficiency Integration

Status: not started

Goal: attach ML sufficiency to containment candidates without weakening EGAR.

Likely files:

- `defender/verifier.py`
- `defender/responder.py`
- `defender/graph_state.py`
- `defender/policy.py`

To do:

- Score verifier-approved candidate entities before final gate decision or as verifier context.
- Add ML sufficiency score, label, and reasons to gate trace.
- Use score only to delay or deprioritize questionable containment in v1, not to approve action that deterministic gates reject.
- Treat prompt-injection and untrusted-only evidence as strong negative context.
- Add policy guard against isolating `h-XXX-02` when patient-zero evidence points to `h-XXX-01` and the `h-XXX-02` support is only lateral/staging/exfil context.

Acceptance checks:

- ML score cannot execute containment by itself.
- Deterministic gate rejection remains final.
- Tests cover wrong lateral/staging host suppression.
- Tests cover untrusted-only and prompt-injection target candidates as insufficient.

## Phase 7: Report Readiness And Attribution Calibration

Status: not started

Goal: use ML-derived field-source patterns to improve final report fields.

Likely files:

- `defender/report_readiness.py`
- `defender/evidence_registry.py`
- `defender/ml_calibrator.py`

To do:

- Add advisory field-candidate scores for:
  - `patient_zero_host`
  - `compromised_user`
  - `attacker_domain`
  - `data_target`
- Favor source-specific evidence patterns from the reference plan:
  - `patient_zero_host`: auth logs, netflow, process events, alerts.
  - `compromised_user`: auth logs, process events, alerts.
  - `attacker_domain`: alerts primarily, with explicit domain fields.
  - `data_target`: process events only.
- Prevent executable/process names from becoming attacker domains.
- Prefer data targets from `target=` process event fields.
- Record ML attribution metadata in report readiness trace without changing the report schema.

Acceptance checks:

- Train regression tests improve `attacker_domain` and `data_target` gaps.
- Tests preserve current `initial_vector` behavior.
- Report submission remains before deadline.

## Phase 8: Evaluation And Ablation

Status: not started

Goal: compare deterministic baseline, ML-guided planning, and ML containment advisory under train-only tuning and eval-only measurement.

Required train runs:

```text
evidence_gate_only --no-rag --split train --tier standard --limit 40
evidence_gate_only --no-rag --split train --tier standard --limit 40 --ml-calibrator
full_agentic --no-rag --split train --tier standard --limit 40 --ml-calibrator
```

Required eval runs after training is frozen:

```text
evidence_gate_only --no-rag --split eval --tier standard --limit 40
evidence_gate_only --no-rag --split eval --tier standard --limit 40 --ml-calibrator
full_agentic --no-rag --split eval --tier standard --limit 40 --ml-calibrator
```

Metrics to compare:

- Mean reward.
- EGAR / evidence-gated action rate.
- False-positive containment rate.
- Correct containment rate.
- Report submitted rate.
- Patient-zero accuracy.
- Compromised-user accuracy.
- Attacker-domain accuracy.
- Data-target accuracy.
- Injection exposure and violation rates.
- Repeated query count.
- Time to first correct containment.

Acceptance checks:

- Eval measurement happens only after artifact training and train threshold tuning are complete.
- `scripts/analyze_failures.py` can summarize ML run outputs or is extended to do so.
- ML-guided runs include artifact manifest ID in eval JSONL metadata.

## Phase 9: Documentation And Operational Workflow

Status: not started

Goal: make the ML path reproducible on local or RunPod environments.

To do:

- Document dependency installation for ML extras.
- Document train-only dataset build command.
- Document artifact training command.
- Document how to run ML-guided eval and ablations.
- Document how to disable ML quickly for fallback.
- Document artifact refresh rules and train/eval separation.
- Update `docs/progress.md` after implementation milestones land.

Acceptance checks:

- A clean environment can build artifacts from train seeds using documented commands.
- A clean environment can run defender without ML dependencies installed.
- The docs clearly state that eval seeds are never part of training.

## Test Checklist

Minimum unit tests:

- Dataset builder rejects eval paths.
- Dataset builder emits deterministic examples.
- Feature schema is fixed-width and numeric.
- Missing artifacts fall back to deterministic behavior.
- Corrupt artifacts fall back to deterministic behavior.
- ML score cannot authorize containment.
- SQL planner uses ML objectives only when enabled and available.
- ML-guided patient-zero investigation prefers `auth_logs`.
- ML-guided attacker-domain investigation prefers alerts/netflow.
- ML-guided data-target investigation prefers process events.
- Prompt-injection target params produce negative containment labels.
- Lateral/staging host negatives suppress premature `h-XXX-02` isolation.

Minimum integration tests:

- `SocDefenderAgent` runs with ML disabled and no ML dependencies.
- `SocDefenderAgent` runs with a small fixture artifact bundle.
- Eval JSONL includes ML trace metadata when enabled.
- Full-agentic graph state records ML advisory output without changing the one-action commit contract.

## Open Decisions

- Whether to add `xgboost`, `hdbscan`, and `sentence-transformers` as optional `ml` dependencies only, or fold them into `agentic`.
- Whether SecureBERT2 embeddings should be cached in `outputs/ml_training/` or under an ignored model-cache directory.
- Whether runtime embedding should happen live for every episode or use only structured features plus precomputed artifact-side cluster mappings in v1.
- Whether ML objective scores should affect `evidence_gate_only` first, `full_agentic` first, or both behind a shared policy hook.
- What confidence threshold is required before ML can delay an otherwise gate-approved containment action.

## Initial Implementation Order

1. Add disabled-by-default config and `MLCalibrator` no-op/fallback interface.
2. Build train-only JSONL dataset with path guards and tests.
3. Add feature schema builder with tests.
4. Train and persist unsupervised models plus XGBoost models.
5. Load artifacts at runtime and expose serializable advisory scores.
6. Integrate objective scores into SQL planner choice.
7. Add containment sufficiency trace metadata and delay-only guard.
8. Run train standard40 ablations and tune only on train.
9. Freeze artifacts/config.
10. Run eval standard40 measurement and update docs.

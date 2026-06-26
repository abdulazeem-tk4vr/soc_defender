# soc_defender Progress

Last updated: 2026-06-24

This document summarizes what has been implemented in `soc_defender`, what has been validated so far, and what remains against the phased plan in `phase-plan.md` and `implementation_plan.md`.

## Current State

The repository contains a deterministic MVP defender mode named `evidence_gate_only` and a wired `full_agentic` mode. Both are available through the local OpenSec-compatible eval harness.

The full-agentic path now updates the evidence registry and report tracker before LLM calls, feeds RAG context, scanner annotations, budget state, and registry entities into investigator/verifier prompts, calls the investigator once per step, and emits committed actions through a verifier-to-responder path. Deterministic EGAR containment gates remain authoritative; gate rejection falls back to investigation/fetch/report actions.

The implemented system includes Regex scanner Layer 1, Prompt Guard fallback, Prompt Guard 2 with 22M fallback/windowing, LLM localization hooks, RAG interface, Ollama-compatible LLM adapter, investigator/verifier contracts, graph-state tracing, a plain-Python graph, and an optional LangGraph adapter behind `--use-langgraph`. LangChain provider switching remains explicitly deferred.

## Implemented Components

### Project Scaffold

Implemented:

- Python package scaffold under `defender/`.
- Eval scripts under `scripts/`.
- Config files under `configs/`.
- Test suite under `tests/`.
- Output directory under `outputs/`.
- RAG placeholder folders under `data/rag/`.
- Model placeholder folder under `data/models/`.
- `pyproject.toml` with core and optional agentic dependencies.
- `.env.example` with Ollama-related environment variables.

Relevant files:

- `pyproject.toml`
- `.env.example`
- `configs/agentic_defender.yaml`
- `configs/calibration.yaml`

### Eval Harness

Implemented:

- `scripts/eval.py` adapts the OpenSec eval flow for this sibling project.
- Supports `--opensec-root`, `--defender`, `--output`, `--summary`, `--ollama`, `--agent-llm`, `--base-url`, `--ollama-model`, `--rag-path`, `--no-rag`, split/tier/limit controls, and baseline model execution.
- Adds the `evidence_gate_only` local agent path while preserving the OpenSec action lifecycle: build one action, normalize it, then call `env.step(action)`.
- Emits JSONL per-run output and JSON summary output.
- Records summary metrics including reward, containment execution rate, report submission rate, false positive rate, injection exposure rate, and injection violation rate.
- Baseline mode supports `--ollama`, using `OLLAMA_BASE_URL` and `OLLAMA_MODEL`, so baseline and full-agentic can be compared against the same RunPod model.
- `--no-rag` disables Qdrant/RAG auto-load for ablation runs, even if `data/rag/qdrant/build_manifest.json` exists locally.

Partially implemented or notable limitations:

- Baseline parity is documented in `docs/baseline_parity.md`, but a fresh post-change `full_agentic` eval comparison still needs to be run.

Relevant files:

- `scripts/eval.py`
- `scripts/eval_utils.py`
- `docs/baseline_parity.md`
- `outputs/smoke_eval.jsonl`
- `outputs/smoke_summary.json`

### Agent Interface

Implemented:

- `SocDefenderAgent` exposes `act()` and `next_action()`.
- `build_agent()` constructs the local defender.
- `evidence_gate_only` and `full_agentic` modes are supported.
- `full_agentic` can run through the plain-Python graph or optional LangGraph adapter with `use_langgraph=True` / `--use-langgraph`.
- Unsupported modes fail fast with `ValueError`.

Relevant files:

- `defender/agent.py`
- `defender/__init__.py`
- `tests/test_agent.py`

### Observation Parser

Implemented:

- Parses core OpenSec observation fields into `ParsedObservation`.
- Tracks scenario ID, step index, attacker state, new email IDs, new alert IDs, seen evidence IDs, content evidence IDs, containment state, last action result, and done flag.
- Normalizes Pydantic-style objects through `model_dump()` where needed.

Relevant files:

- `defender/observation.py`

### Evidence Registry

Implemented:

- Maintains normalized entity support records.
- Extracts host, user, target, and domain entities from fetched/query evidence rows.
- Supports the expected OpenSec evidence sources: `email_logs`, `auth_logs`, `netflow`, `process_events`, and `alerts`.
- Tracks whether evidence content was exposed.
- Carries trust tier, source, injection ID, evidence ID, source table, fields, and malicious indicators.
- Identifies malicious indicators from a small deterministic keyword set.
- Provides `support_for()` and `best_entities()` helpers for policy and report readiness.
- Runs the regex injection scanner on evidence rows and stores `scanner_status` on each support record.
- Stores localized scanner spans on support records.
- Ranks entity support by trust tier, source table, malicious indicators, and supporting-field strength before selecting best entities.

Partially implemented or notable limitations:

- Domain extraction has been tightened so process names such as `svchost.exe` are not extracted as domains. Domains are now extracted from explicit domain fields and key-value text such as `dst_domain=notifysecure.io`.
- Evidence support scoring is improved but still heuristic, not full kill-chain coherence.

Relevant files:

- `defender/evidence_registry.py`

### Action Adapter And SQL Planner

Implemented:

- Central action constructors for all allowed OpenSec defender actions.
- Report normalization with the required five attribution fields and containment action lists.
- Action validation for allowed action types, required params, report shape, and SQL safety.
- SQL validation rejects non-`SELECT`, multi-statement SQL, `SELECT 1`, and references to non-evidence tables.
- Template SQL planner for broad queries and entity-specific queries.
- Tracks emitted queries and failed queries to avoid repeating unsafe or failed SQL where possible.
- Entity-specific SQL now orders by the documented `step` column rather than a nonexistent `created_at` column.

Partially implemented or notable limitations:

- The eval harness `_normalize_action()` can still create fallback `SELECT 1` for malformed baseline model actions. The local `evidence_gate_only` policy uses its own safe SQL planner, but the harness fallback is looser than the defender-side validator.
- Repeated broad query fallback is intentionally allowed after all broad probes are exhausted so the benchmark still receives one legal action per step.

Relevant files:

- `defender/actions.py`
- `defender/sql_planner.py`
- `tests/test_actions_sql.py`
- `tests/test_policy.py`

### Evidence Gate And Containment Policy

Implemented:

- Deterministic containment gate in `defender/verifier.py`.
- Enforces containment action/entity alignment:
  - `isolate_host` requires host support.
  - `block_domain` requires domain support.
  - `reset_user` requires user support.
- Requires the exact entity to have trusted, content-exposed support.
- Requires malicious indicators on the supporting evidence.
- Blocks containment before `containment_min_step`.
- Blocks evidence that only appears in flagged/localized scanner spans.
- Uses a separate budget helper to identify `investigate_first`, `gated_containment`, and `report_fill` phases.
- Policy avoids repeating attempted containment and avoids acting on already-contained entities.
- Default `containment_min_step` is now `5`.
- The report deadline is now dynamic and defaults to `max_steps - 1` for each episode.
- If report attribution is incomplete, containment is delayed until the late containment window to prioritize evidence gathering.

Relevant files:

- `defender/verifier.py`
- `defender/budget.py`
- `defender/policy.py`
- `configs/calibration.yaml`

### Report Readiness

Implemented:

- Tracks best currently known values for:
  - `patient_zero_host`
  - `compromised_user`
  - `attacker_domain`
  - `data_target`
  - `initial_vector`
- Builds a complete report object before the deadline.
- Mirrors executed containment from observation state rather than claiming intended containment.
- Submits at or after `report_deadline_step` or the final step.
- Uses ranked evidence support from the registry when choosing report entities.

Partially implemented or notable limitations:

- Attribution is heuristic and can still be wrong or incomplete.
- `initial_vector` defaults to `phish`.
- There is no dedicated report builder with confidence/source metadata yet.

Relevant files:

- `defender/report_readiness.py`
- `defender/policy.py`

### `evidence_gate_only` Policy

Implemented:

- Composes observation parsing, registry updates, report readiness, unseen fetches, gated containment, SQL investigation, and deadline report submission.
- Fetches unseen alerts first, then unseen emails.
- Attempts gated containment only after fetches and after minimum containment step.
- Uses SQL investigation as a fallback.
- Emits exactly one OpenSec-style action per call.

Current behavior from smoke run:

- Ran one train seed, `seed-001`.
- Submitted a report.
- Executed containment.
- Correctly isolated `h-001-01`.
- Correctly reset `u-001`.
- Did not block required domain `notifysecure.io`.
- Reported incorrect `attacker_domain` as `svchost.exe`.
- Left `data_target` as `unknown`.
- Had no injection violations in the smoke output.

Current train calibration behavior:

- Ran `evidence_gate_only --no-rag --split train --tier standard --limit 40`.
- Mean reward: `2.36`.
- Report submitted rate: `1.0`.
- Containment executed rate: `0.45`.
- Correct containment rate: `0.45`.
- False positive rate: `0.225`.
- Injection exposure rate: `0.975`.
- Injection violation rate: `0.025`.
- Failure analysis shows 9 containment false-positive runs, 1 injection-violation run, 0 low-EGAR runs, 54 repeated queries, 18 `attacker_domain` gaps, and 31 `data_target` gaps.

Relevant files:

- `defender/policy.py`
- `outputs/smoke_eval.jsonl`
- `outputs/smoke_summary.json`
- `outputs/evidence_gate_train_standard40.jsonl`
- `outputs/evidence_gate_train_standard40_summary.json`
- `outputs/evidence_gate_train_standard40_failures.json`

### Failure Analysis

Implemented:

- `scripts/analyze_failures.py` reads eval JSONL and summarizes core failure modes.
- Tracks missing reports, containment false positives, injection violations, low EGAR runs, placeholder `SELECT 1` queries, repeated queries, and attribution gaps.
- Can print JSON to stdout or write a summary JSON with `--output`.

Relevant files:

- `scripts/analyze_failures.py`
- `tests/test_analyze_failures.py`

### ML Calibration Foundation

Implemented:

- Added disabled-by-default ML calibrator configuration.
- Added optional `ml` dependency group for future training dependencies.
- Added fail-closed `defender/ml_calibrator.py` loader/interface with schema validation, label-prior fallback scoring, support-heuristic containment scoring, and optional XGBoost model loading.
- Added `defender/ml_features.py` with a fixed-width numeric feature schema and runtime/example vectorizers.
- Threaded advisory ML state through agent, policy, and graph trace structures without enabling behavior changes by default.
- Added initial ML objective-guided SQL planner selection behind available artifact scores.
- Added `scripts/build_ml_training_set.py` for train-only step/candidate JSONL examples.
- Added `scripts/train_ml_calibrator.py` for train artifact packaging, optional SecureBERT2 embedding cache/features, and optional XGBoost/unsupervised training.
- Added tests for missing/corrupt artifact fallback, train/eval path guardrails, deterministic dataset labels, feature stability, embedding cache I/O, artifact packaging, and planner integration.

Validation:

- `python scripts/build_ml_training_set.py --train-dir /workspace/opensec-env/data/seeds/train --output outputs/ml_training/train_examples_smoke.jsonl --limit 1` produced 153 examples from 1 train seed.
- Focused second-slice ML tests passed.
- `python scripts/train_ml_calibrator.py --examples outputs/ml_training/train_examples_smoke.jsonl --artifact-dir outputs/ml_training/artifact_smoke --train-dir /workspace/opensec-env/data/seeds/train` packaged train-only smoke artifacts.
- The smoke artifact loaded successfully through `build_agent` with ML enabled.
- `python -m pytest -q` passed with 65 tests after the second slice.
- Focused embedding-path tests passed.
- Full train-only ML artifact was produced under `defender/models/opensec_train_calibrator` from 160 train seeds and 21,573 examples. Training status: SecureBERT2 embeddings embedded, IsolationForest trained, HDBSCAN trained, and XGBoost trained.
- The trained artifact loads successfully through `build_agent` with `ArtifactMLCalibrator`.
- `scripts/train_ml_calibrator.py` now emits timestamped progress logs across examples, embedding cache, embedding, unsupervised fitting, XGBoost, and artifact writes.
- Eval CLI supports `--ml-calibrator` / `--ml-artifact-dir`, and the standard tier alias now includes manifest entries marked `standard`.
- One-seed train smoke with `evidence_gate_only+ml` passed with reward `2.30` and containment attempted.

Partially implemented or notable limitations:

- Runtime ML scoring uses label-prior and support heuristics unless optional model artifacts are present.
- SecureBERT2 embedding generation and live XGBoost/HDBSCAN training are now exercised for the train artifact. Train/eval ablation runs are still pending.
- Planner integration is intentionally conservative and only uses ML when artifacts load successfully.

### Regex Injection Scanner

Implemented:

- Data-driven regex rules in `configs/prompt_injection_regexes.yaml`.
- `RegexPromptInjectionClassifier` with structured findings, combined confidence, and rule families.
- `InjectionScanner` wrapper that maps classifier confidence to `clean`, `suspicious`, or `flagged`.
- Evidence registry integration so fetched/query evidence support carries scanner status.
- Unit tests for direct instruction override, prompt extraction, zero-width obfuscation, benign SOC text, and registry scanner integration.
- Initial train-seed evaluation helper in `scripts/eval_regex_classifier.py`.
- Prompt Guard fallback and LLM localization hook are connected through `InjectionScanner`.
- Train-only regex example builder in `scripts/build_regex_training_set.py`.

Partially implemented or notable limitations:

- Scanner output is currently advisory metadata for the evidence gate.
- Prompt Guard 2 is enabled by default in `full_agentic` with `meta-llama/Prompt-Guard-86M`; pass `--prompt-guard2-model none` only to disable it for debugging.
- Prompt Guard 2 falls back to `meta-llama/Prompt-Guard-22M` when the configured model fails to load and warns/continues when the model layer is unavailable.
- LLM localization interfaces exist, but live localizer calls require `--agent-llm ollama`.
- Span offsets are reported against normalized scanner text, not a full original-text offset map.
- The regex evaluation helper was not run in this sandbox because Windows `py` launcher execution for non-pytest scripts is inconsistent here; run it from the normal shell with a pinned interpreter.

Relevant files:

- `configs/prompt_injection_regexes.yaml`
- `defender/regex_classifier.py`
- `defender/scanner.py`
- `scripts/eval_regex_classifier.py`
- `scripts/build_regex_training_set.py`
- `tests/test_regex_classifier.py`
- `tests/test_scanner_regex_integration.py`

### Agentic Interfaces

Implemented:

- Ollama/OpenAI-compatible JSON client in `defender/llm.py`.
- Mockable `StaticJSONLLMClient` for deterministic tests.
- Structured `Investigator` and `LLMVerifier` contracts in `defender/investigator.py`.
- RAG retriever interface plus builtin keyword fallback in `defender/rag.py`.
- Graph audit state in `defender/graph_state.py`.
- Plain-Python graph scaffold in `defender/graph.py` that runs scanner, registry trace, RAG, investigator, budget, verifier, and responder nodes.
- Verifier-to-responder mapping in `defender/responder.py`.
- Optional LangGraph adapter in `defender/langgraph_adapter.py`.
- `SocDefenderAgent(mode="full_agentic")` support.
- Eval harness accepts `--defender full_agentic` and `--use-langgraph`.

Partially implemented or notable limitations:

- The graph scaffold returns one action and audit state; eval remains responsible for `env.step()`.
- The LangGraph adapter is optional and only runs when `langgraph` is installed and explicitly selected.
- Live Ollama calls require `OLLAMA_BASE_URL` and are not used in deterministic tests.
- Qdrant retrieval is implemented behind lazy imports and requires a runtime embedder plus a built local collection.
- Qdrant build supports both Hugging Face `transformers` mean-pooling embeddings and `sentence-transformers` embeddings. Preferred RunPod RAG model is `cisco-ai/SecureBERT2.0-biencoder` because it is a cybersecurity sentence-similarity/document-embedding model suited to semantic retrieval.
- RAG chunk build utilities and RunPod workflow documentation exist.
- Current external corpus includes ATT&CK Enterprise, CWE, D3FEND, and all 3,295 Sigma rule files from the downloaded Sigma archive.
- Current `data/rag/chunks.jsonl` has 41,722 chunks.
- Eval JSONL rows now include compact graph traces for `full_agentic` runs.
- Graph traces now include RAG top-document metadata, investigation intent, verifier candidate, gate decision/responder details, and final responder action.
- LLM clients record raw/parsed traces and investigator/verifier fall back deterministically on malformed LLM output.

Relevant files:

- `defender/llm.py`
- `defender/investigator.py`
- `defender/rag.py`
- `defender/prompt_guard.py`
- `defender/graph_state.py`
- `defender/graph.py`
- `defender/responder.py`
- `defender/langgraph_adapter.py`
- `defender/rag_build.py`
- `scripts/build_rag_chunks.py`
- `scripts/build_qdrant_index.py`
- `docs/runpod_workflow.md`
- `tests/test_llm_investigator.py`
- `tests/test_rag_prompt_guard_graph.py`
- `tests/test_rag_build.py`

## Validation So Far

Automated tests:

- Command run from `soc_defender`: `py -m pytest -q`
- Result: `46 passed in 2.01s`

Smoke eval output:

- `outputs/smoke_summary.json` contains one `evidence_gate_only` run.
- Mean reward: `2.3`
- Report submitted rate: `1.0`
- Containment executed rate: `1.0`
- Correct containment rate: `1.0`
- False positive rate: `0.0`
- Injection exposure rate: `1.0`
- Injection violation rate: `0.0`

Interpretation:

- The MVP can run end-to-end on at least one train seed.
- The current smoke result shows useful restraint on false positives, injection behavior, and evidence-gated containment.
- The latest train standard40 run shows stronger baseline behavior than the qwen2.5:14b reference on report submission, false positives, and injection violations.
- Attribution and domain/data-target discovery still need more work before calibration should be frozen.
- The latest train standard40 failure analysis still shows repeated broad queries and attribution gaps, especially `data_target`.

Train calibration run:

- Command: `py -3.13 scripts\eval.py --defender evidence_gate_only --no-rag --split train --tier standard --limit 40 --output outputs\evidence_gate_train_standard40.jsonl --summary outputs\evidence_gate_train_standard40_summary.json`
- Summary: mean reward `2.36`, report submitted rate `1.0`, correct containment rate `0.45`, false positive rate `0.225`, injection violation rate `0.025`.
- Failure analysis command: `py -3.13 scripts\analyze_failures.py --input outputs\evidence_gate_train_standard40.jsonl --output outputs\evidence_gate_train_standard40_failures.json`
- Failure summary: 0 missing reports, 9 false-positive containment runs, 1 injection-violation run, 0 low-EGAR runs, 54 repeated queries, 18 `attacker_domain` gaps, and 31 `data_target` gaps.

Baseline parity:

- `docs/baseline_parity.md` records the current comparison procedure and existing qwen2.5:14b baseline metrics.
- Existing qwen2.5:14b eval baseline from `../opensec-env/outputs/qwen25_14b_baseline_standard40_summary.json`: mean reward `0.3775`, report submitted rate `0.65`, false positive rate `0.45`, injection violation rate `0.375`.
- A fresh post-change `full_agentic` eval run is still required because existing full-agentic output predates the current graph wiring.

Git status note:

- `git -C .\soc_defender status --short` could not be used because Git reported the repository as having dubious ownership for the current Windows user. Progress in this document is based on filesystem/code inspection, tests, and current output artifacts.

## Phase-by-Phase Status

| Phase | Status | Notes |
|---|---|---|
| Phase 0: Environment Setup | Mostly complete | Scaffold, configs, tests, outputs, package metadata, and placeholder data folders exist. |
| Phase 1: Eval Harness And Baseline Parity | Mostly complete | Local harness, `evidence_gate_only`, `full_agentic`, Ollama baseline mode, RAG ablation flag, and baseline parity doc exist. Fresh post-change full-agentic comparison is pending. |
| Phase 2: Observation Parser And Evidence Registry | Mostly complete | Parser and registry exist. Extraction is heuristic; support ranking and scanner span propagation are implemented. |
| Phase 3: Action Adapter And SQL Planner | Mostly complete | Central constructors, validation, SQL safety, and planner exist. Harness fallback still allows `SELECT 1` for malformed baseline actions. |
| Phase 4: Evidence Gate And 15-Step Budget | Mostly complete | Deterministic gate, scanner-span rejection, step-aware policy, and budget module exist. |
| Phase 5: Report Readiness And `evidence_gate_only` Policy | Mostly complete | Policy is integrated and runs end-to-end. Ranked support is used for report readiness; domain/data-target attribution still needs tuning. |
| Phase 6: Failure Analysis And Calibration | Partially complete | Failure analyzer exists and train standard40 has been run/analyzed. Calibration thresholds are not frozen. |
| Phase 7: Regex Injection Scanner | Mostly complete | Regex classifier, scanner wrapper, registry annotations, tests, eval helper, and train-set builder exist. Prompt Guard 2 and localization are connected in `full_agentic`. |
| Phase 8: Ollama Internal LLM Adapter | Mostly complete | `defender/llm.py` exists with Ollama JSON client and mock client. Investigator/verifier structured contracts exist. Eval supports `--agent-llm ollama` and `--ollama`. Live ablation testing is the next step. |
| Phase 9: RAG Build And Local Qdrant Transfer | Partially complete / ablated | RAG retriever interface, builtin fallback, chunk builder, Qdrant build script, lazy runtime retriever, `corpus_manifest.json` exclusion, and `--no-rag` ablation switch exist. CPU RAG eval still needs a fresh run because the current manifest points at CUDA. |
| Phase 10: Prompt Guard 2 And LLM Localization | Mostly complete | Prompt Guard 2 provider is default in `full_agentic`; 22M fallback and long-input windowing exist. Live localization requires Ollama. |
| Phase 11: LangChain Multi-Provider Layer | Deferred | Provider switching is not implemented; Ollama remains the required path. |
| Phase 12: LangGraph Full-Agentic Orchestration | Mostly complete | Graph state, plain-Python node scaffold, verifier-to-responder action path, and optional `--use-langgraph` adapter exist. LangGraph dependency remains optional. |

## Remaining Work

Highest-priority MVP work:

1. Tune and freeze `configs/calibration.yaml` using train-only results. Current train standard40 output is available, but thresholds were not changed yet.
2. Improve attribution extraction for `data_target` and `attacker_domain`; these remain the dominant train standard40 report gaps.
3. Reduce repeated broad queries after useful evidence has already been gathered.
4. Add golden train regression tests for fixed seeds and final-step report behavior.
5. Add fallback-policy and automated baseline-parity tests.

Full-agentic work still pending:

1. Run a fresh post-change `full_agentic --no-rag --split eval --tier standard --limit 40` comparison against the qwen2.5:14b baseline.
2. Run a CPU RAG smoke/eval path, or rebuild/update the local RAG manifest so it does not request CUDA on a CPU-only Torch build.
3. Exercise live Ollama investigator/verifier/localizer calls on RunPod and inspect graph traces.
4. Exercise optional LangGraph adapter once `langgraph` is installed.
5. Keep OpenSec mutation behind a single final commit boundary.

## Key Risks

- Current report attribution can look complete while still being semantically wrong.
- Domain extraction and entity ranking are safer now, but train standard40 still shows 18 `attacker_domain` gaps and 31 `data_target` gaps.
- The deterministic train standard40 run has low injection violation rate and no low-EGAR runs, but 9 false-positive containment runs remain.
- The local RAG manifest can request CUDA; use `--no-rag` for deterministic MVP runs on CPU-only Torch or rebuild/update the manifest for CPU.
- LLM/RAG/graph interfaces exist and are wired, but live full-agentic model behavior still needs fresh post-change eval evidence.

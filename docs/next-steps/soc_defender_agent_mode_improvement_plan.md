# Phased Plan: `soc_defender` Improvements Using OpenSec Agent-Mode Eval

## Summary

Improve `soc_defender` in separate implementation sessions so each step is measurable and easier to validate. The priority order is: OpenSec agent-mode integration, architecture hardening, calibrated evidence scoring, attribution fixes, metrics/ablations, then advisory RAG and fine-tuning. OpenSec's eval runner owns benchmark execution and scoring; `soc_defender` owns agent behavior.

## Current Status

- Phase 1: Complete.
  - Verified `opensec-env/configs/soc_defender_agents.yaml` contains OpenSec `provider: agent` configs for `evidence_gate_only`, `full_agentic`, and `full_agentic_langgraph`.
  - Verified `opensec-env/scripts/agent.py` caches agent instances and calls `act(observation)` or `next_action(observation)`.
  - Verified `soc_defender/README.md` directs benchmark claims and reported metrics through `opensec-env/scripts/eval.py` and `opensec-env/outputs`.
  - Smoke passed: `py -3.13 scripts\eval.py --config configs\soc_defender_agents.yaml --models evidence_gate_only --split train --limit 1 --output outputs\agents\evidence_gate_only_phase1_phase2_smoke.jsonl`.
  - Smoke passed: `py -3.13 scripts\eval.py --config configs\soc_defender_agents.yaml --models full_agentic --split train --limit 1 --output outputs\agents\full_agentic_phase1_phase2_smoke.jsonl`.
- Phase 2: Complete.
  - Verified `DefenderPolicy.ensure_scenario()` detects `scenario_id` changes and resets mutable episode state.
  - Verified reset covers registry, report tracker, fetched email IDs, fetched alert IDs, attempted containment, and SQL planner state.
  - Verified `SocDefenderAgent.act()` clears stale graph trace state when a new scenario starts.
  - Focused tests passed: `py -m pytest soc_defender\tests\test_agent.py -q`.
- Phase 3: Complete.
  - Added taint-aware trusted action support in the evidence registry.
  - Prevented tainted evidence from populating report values or authorizing containment.
  - Added public policy methods for graph/responder ingestion, deadlines, containment, fallback investigation, and reporting.
  - Moved LangGraph compilation to agent construction so compiled graphs are reused per agent instance.
  - Restricted SQL planner output to fixed broad templates and allowlisted entity templates.
  - Tests passed: `py -m pytest tests -q` from `soc_defender`.
  - OpenSec smokes passed for `evidence_gate_only` and `full_agentic` train limit 1.
- Phase 4: Complete.
  - Added calibrated support scoring by trust tier, source table, supporting fields, malicious indicators, scanner status, recency, and corroboration.
  - Exposed scored entity candidates with supporting evidence IDs.
  - Added action-specific containment thresholds, report-field thresholds, scanner taint policy, and containment minimum step to `soc_defender/configs/calibration.yaml`.
  - Kept hard rejection rules for missing exact support, missing content exposure, untrusted-only support, scanner-flagged-only support, maliciousness gaps, score threshold failures, and early containment.
  - Tests passed: `py -m pytest tests -q` from `soc_defender`.
  - OpenSec smokes passed: `evidence_gate_only` and `full_agentic` train limit 1 with phase 4 output files.
- Phase 5: Complete.
  - Added richer trusted destination/domain and target extraction from alerts and process events.
  - Added report-field confidence, provenance, conflict history, and locked-value handling.
  - Added targeted SQL gap queries for missing `attacker_domain` and `data_target`.
  - Rejected containment now emits one evidence-seeking query instead of looping on the same failed action.
  - Domain blocking now requires malicious trusted network or alert support, preventing email-only domain containment.
  - Tests passed: `py -m pytest tests -q` from `soc_defender`.
  - OpenSec smokes passed for `evidence_gate_only` and `full_agentic` train limit 1.
- Phase 6: Complete.
  - Extended `soc_defender/scripts/analyze_failures.py` into an OpenSec JSONL
    post-processor for reward, EGAR, time to first containment, containment
    correct/false-positive totals, report submission, injection exposure, and
    injection violations.
  - Added frozen calibration config fingerprinting to analysis output.
  - Added `opensec-env/configs/soc_defender_ablations.yaml` and `agent_mode`
    support in the OpenSec agent bridge for named ablations over existing
    runtime modes.
  - Documented train calibration, ablation, and frozen final eval command
    sequences in `soc_defender/docs/opensec_train_eval_workflow.md`.
  - Focused analyzer tests passed: `py -m pytest tests\test_analyze_failures.py -q`.
  - Full tests passed: `py -m pytest -q`.
  - OpenSec ablation smoke passed: `py -3.13 scripts\eval.py --config configs\soc_defender_ablations.yaml --models full_agentic_no_llm --split train --limit 1 --output outputs\agents\full_agentic_no_llm_phase6_smoke.jsonl`.
- Phase 7: Complete.
  - Added explicit advisory-only RAG document metadata, including corpus provenance and `containment_authority=false`.
  - Prioritized RAG corpora as ATT&CK, Sigma, D3FEND, then CWE for tied keyword results.
  - Added graph trace metadata so retrieved context shows corpus and containment-authority status.
  - Updated investigator and verifier prompts to state that RAG is background context, not incident evidence, and cannot authorize containment.
  - Kept OpenSec config and agent bridge unchanged; RAG/no-RAG variants can be exercised inside `soc_defender` without more benchmark-runner logic.
  - Removed OpenSec eval provider-specific default output routing and documented explicit `--output` naming in `soc_defender/README.md`.
  - Focused RAG/graph tests passed: `py -m pytest tests\test_rag_prompt_guard_graph.py -q`.
  - Full `soc_defender` tests passed: `py -m pytest -q`.
- Next phase: Phase 8, Fine-Tuning / Model-Assisted Scoring.

Before implementation starts, save this complete plan to:

`soc_defender/docs/next-steps/soc_defender_agent_mode_improvement_plan.md`

The implementer should prompt the user to switch to a new session at the end of each implementation session, once that session's acceptance criteria pass or its blocker is documented.

## Pre-Implementation Requirement

TODO:

- Save the complete approved plan before making implementation changes.
- Target path:
  - `soc_defender/docs/next-steps/soc_defender_agent_mode_improvement_plan.md`
- Include:
  - full phased plan;
  - session split;
  - acceptance criteria;
  - test plan;
  - assumptions.
- Do not begin code changes until the saved plan exists.

Acceptance criteria:

- The complete plan is committed/saved in `soc_defender/docs/next-steps`.
- The saved plan matches the approved implementation plan.
- Implementation begins only after this file is present.

## Implementation Session Split

Use separate sessions rather than one long implementation session.

- **Session 1: OpenSec eval integration + state reset**
  - Make `soc_defender` run cleanly through `opensec-env/scripts/eval.py` using `provider: agent`.
  - Deprecate `soc_defender/scripts/eval.py` for benchmark reporting.
  - Fix scenario-scoped state reset because OpenSec caches agent instances.
  - **Switch prompt:** after OpenSec agent-mode smoke tests pass and cached-agent state reset is verified, prompt the user to start a new session for architecture hardening.

- **Session 2: Architecture hardening**
  - Make evidence registry taint-aware.
  - Prevent tainted evidence from populating report fields or authorizing containment.
  - Decouple graph from policy internals.
  - Compile LangGraph once per agent instance.
  - **Switch prompt:** after taint-aware registry/report tests pass and graph/policy boundaries are cleaned up, prompt the user to start a new session for calibration and attribution.

- **Session 3: Calibration + attribution**
  - Add calibrated evidence scoring.
  - Add action-specific thresholds.
  - Improve `attacker_domain` and `data_target` extraction.
  - Improve targeted SQL investigation.
  - **Switch prompt:** after train-only calibration improves or preserves EGAR and reduces attribution gaps without increasing false positives, prompt the user to start a new session for metrics and workflows.

- **Session 4: Metrics + train/eval workflow**
  - Extend failure analysis over OpenSec JSONL.
  - Add ablation configs.
  - Add train-only calibration workflow.
  - Add final eval workflow from frozen config.
  - **Switch prompt:** after OpenSec-based train/eval workflows and summaries are reproducible, prompt the user to start a new session for RAG and fine-tuning.

- **Session 5: RAG + fine-tuning track**
  - Keep RAG advisory only.
  - Add RAG trace improvements.
  - Build train-only fine-tuning datasets.
  - Integrate optional fine-tuned scorer as an ablation.
  - **Switch prompt:** after advisory RAG is validated, prompt before beginning any actual fine-tuning run or model-training work.

## Phase 1: OpenSec Eval Integration

Status: Complete.

Goal: use only OpenSec's benchmark eval path for reported results.

TODO:

- Treat `opensec-env/scripts/eval.py` as the canonical eval runner.
- Add or document OpenSec config entries for `soc_defender` modes using:
  - `provider: agent`
  - `name: evidence_gate_only`
  - `name: full_agentic`
  - optional `agent_llm`
  - optional `prompt_guard2_model`
  - optional `use_langgraph`
- Deprecate `soc_defender/scripts/eval.py` for benchmark reporting:
  - keep it only as a local/dev helper if useful;
  - mark docs so reported metrics must come from OpenSec eval.
- Ensure `soc_defender` agents return JSON-compatible OpenSec actions from `act(observation)` or `next_action(observation)`.
- Align all run commands and docs around OpenSec eval:
  - train calibration through `opensec-env/scripts/eval.py --split train`;
  - final eval through `opensec-env/scripts/eval.py --split eval`.

Acceptance criteria:

- OpenSec eval can run `provider: agent` against `soc_defender`.
- Reported JSONL/summary outputs come from `opensec-env/outputs`.
- No benchmark claims depend on `soc_defender/scripts/eval.py`.

## Phase 2: Scenario-Scoped Agent State

Status: Complete.

Goal: make cached OpenSec agent-mode execution safe.

TODO:

- Account for OpenSec's `scripts/agent.py` agent cache, which reuses one agent instance across episodes with the same cache key.
- Add scenario reset logic inside `soc_defender` agent/policy:
  - detect `scenario_id` changes in each observation;
  - reset registry, report tracker, fetched emails, fetched alerts, attempted containment, SQL planner state, graph trace, and any verifier/investigator memory.
- Preserve state only within the same scenario episode.
- Add tests that reuse one agent instance across two synthetic scenario IDs and verify no evidence/action leakage.

Acceptance criteria:

- Long-lived cached agent behaves identically to a fresh agent per episode.
- No fetched IDs, report values, attempted containment, or registry records carry across scenarios.
- OpenSec agent-mode cache does not cause train/eval contamination.

## Phase 3: Architecture Hardening

Status: Complete.

Goal: enforce scanner, registry, verifier, graph, and responder boundaries.

TODO:

- Make evidence registry taint-aware:
  - store scanner status and localized spans on every evidence record;
  - separate raw extracted entities from trusted action-support entities;
  - preserve IOCs from tainted text for investigation only;
  - prevent injected instructions from influencing containment or report readiness.
- Decouple graph from policy internals:
  - expose public policy methods for observation ingestion, report update, containment candidacy, rejected-action fallback, and deadline report behavior;
  - stop graph code from calling private policy methods or mutating policy internals directly.
- Compile LangGraph once per agent instance:
  - initialize adapter once;
  - reuse compiled graph in each `act()` call;
  - fail fast on construction errors.
- Tighten SQL generation:
  - use fixed query templates for defender modes;
  - reject arbitrary LLM SQL unless parsed and allowlisted;
  - eliminate repeated placeholder or broad queries.

Acceptance criteria:

- Tainted evidence cannot populate report fields without trusted corroboration.
- Graph uses public policy interfaces only.
- LangGraph compilation happens once per agent.
- SQL planner emits only safe OpenSec-compatible templates.

## Phase 4: Evidence Scoring and Calibration

Status: Complete.

Goal: replace binary gating with calibrated support scoring while preserving fail-closed containment.

TODO:

- Add calibrated support scoring:
  - score by trust tier, table/source, supporting field, malicious indicator, scanner status, recency, and corroboration;
  - expose score plus supporting evidence IDs for every candidate entity.
- Add thresholds in `soc_defender/configs/calibration.yaml`:
  - `block_domain`;
  - `isolate_host`;
  - `reset_user`;
  - report-field attribution;
  - scanner taint policy;
  - containment minimum step.
- Keep hard rejection rules:
  - no exact entity support;
  - no content-exposed support;
  - untrusted-only support;
  - scanner-flagged-only support;
  - action/entity mismatch;
  - containment before configured minimum step.
- Tune thresholds only from OpenSec train runs.

Acceptance criteria:

- EGAR does not regress against current MVP.
- Containment false positives decrease or remain no worse on train.
- Frozen calibration config records threshold values and train-only tuning notes.

## Phase 5: Attribution and Investigation Improvements

Goal: reduce `attacker_domain` and `data_target` gaps without increasing unsafe containment.

TODO:

- Improve `attacker_domain` extraction:
  - prioritize trusted `netflow.dst_domain`;
  - use parsed alert destination/domain fields;
  - deprioritize domains found only in emails or injected text;
  - require malicious trusted support before domain containment.
- Improve `data_target` extraction:
  - parse target IDs from `process_events`, alerts, and staging/exfil messages;
  - rank targets by staging/exfil indicators;
  - reject prompt-injection-only target mentions.
- Improve report readiness:
  - track confidence, provenance, conflict history, and locked values;
  - avoid overwriting stronger trusted evidence with weaker later evidence.
- Improve investigation policy:
  - add targeted query templates for missing `attacker_domain`;
  - add targeted query templates for missing `data_target`;
  - ensure rejected containment becomes one useful evidence-seeking action.

Acceptance criteria:

- Train failure analysis shows fewer `attacker_domain` and `data_target` gaps.
- Repeated query count decreases.
- Report submission rate remains high.
- Containment false positives do not increase.

## Phase 6: Metrics and Ablations Through OpenSec Eval

Status: Complete.

Goal: make all results reproducible through OpenSec's benchmark runner.

TODO:

- Use OpenSec eval outputs as the source of truth for:
  - reward;
  - EGAR;
  - time to first containment;
  - containment correct/false-positive totals;
  - report submission;
  - injection exposure/violations.
- Add `soc_defender`-side analysis scripts only as post-processors over OpenSec JSONL.
- Standard run matrix:
  - frontier/LLM baseline configs;
  - `provider: agent`, `name: evidence_gate_only`;
  - `provider: agent`, `name: full_agentic`;
  - later configs for calibrated scorer and fine-tuned scorer.
- Train workflow:
  - run OpenSec eval on train split;
  - analyze failures;
  - tune thresholds;
  - freeze config.
- Eval workflow:
  - run OpenSec eval on eval split only after freezing;
  - do not tune based on eval results.

Acceptance criteria:

- One documented OpenSec command sequence produces train calibration outputs.
- One documented OpenSec command sequence produces final eval outputs.
- All reported metrics are reproducible from OpenSec eval plus frozen `soc_defender` config.

## Phase 7: RAG as Advisory Context

Goal: make RAG useful without allowing it to authorize containment.

TODO:

- Keep RAG out of containment authorization.
- Use RAG for:
  - ATT&CK technique context;
  - Sigma detection/log semantics;
  - D3FEND containment labels;
  - CWE weakness/vulnerability context;
  - verifier explanation;
  - report rationale.
- Treat corpus priority as:
  - highest: ATT&CK, Sigma, D3FEND;
  - optional/supporting: CWE.
- Ensure no OpenSec seeds, ground truth, oracle internals, or eval labels are indexed.
- Ensure CWE is never sufficient evidence for `block_domain`, `isolate_host`, or `reset_user`.

Acceptance criteria:

- RAG improves explanation or verifier trace quality.
- RAG never approves containment without trusted OpenSec evidence.
- `rag_only` or RAG-enabled agent configs remain clean ablations.

## Phase 8: Fine-Tuning / Model-Assisted Scoring

Goal: use train data to improve extraction and calibration after deterministic logic is stable.

TODO:

- Build train-only datasets:
  - evidence extraction examples;
  - report-field ranking examples;
  - containment eligibility examples;
  - prompt-injection/evidence-safety examples.
- Start with a small encoder/ranker model.
- Avoid direct generative action fine-tuning.
- Integrate model output as advisory only:
  - candidate probabilities;
  - evidence IDs;
  - safety labels;
  - containment eligibility score.
- Add OpenSec agent-mode ablation configs for fine-tuned scorer variants.

Acceptance criteria:

- Fine-tuned model uses train split only.
- Eval split is untouched until final reporting.
- Model outputs are logged and auditable.
- Fine-tuned scorer improves attribution or false-positive rate without reducing EGAR.

## Test Plan

  - Unit tests:
    - scenario reset clears mutable state under cached agent reuse;
    - tainted evidence is stored but not trusted;
    - trusted corroboration can recover IOCs from tainted contexts;
    - containment requires exact trusted content-exposed support;
    - report fields require calibrated trusted support;
    - RAG context is marked advisory-only and never treated as containment authority;
    - RAG corpus priority ranks ATT&CK, Sigma, and D3FEND above CWE when scores tie;
    - RAG graph traces include corpus provenance and containment-authority status;
    - investigator and verifier prompts state that RAG cannot authorize containment;
    - RAG-only or CWE-only containment candidates are rejected by the evidence gate;
    - graph uses public policy methods;
    - SQL planner emits only safe templates;
    - report containment mirrors executed containment.
- Golden train-seed tests:
  - injected decoy domain is not blocked;
  - real exfil domain is blocked only after trusted netflow/alert evidence;
  - compromised user is reset only after trusted auth evidence;
  - patient-zero host isolation waits for trusted host evidence;
  - final report is submitted before deadline.
- Integration tests:
  - OpenSec `provider: agent` runs `evidence_gate_only`;
  - OpenSec `provider: agent` runs `full_agentic`;
  - OpenSec JSONL contains expected action traces and EGAR fields;
  - no `soc_defender` benchmark fork is required for reported results.

## Assumptions

- Before implementation starts, the complete plan is saved under `soc_defender/docs/next-steps`.
- The implementer prompts the user to switch sessions after each session's acceptance criteria pass or a blocker is documented.
- `opensec-env/scripts/eval.py` is the canonical benchmark runner.
- `opensec-env/scripts/agent.py` remains the bridge from OpenSec eval to `soc_defender`.
- `opensec-env` remains benchmark-owned; avoid changing oracle, seeds, schemas, and scoring.
- `soc_defender` owns agent behavior, calibration config, RAG, scanner, graph, and optional fine-tuned scorers.
- Primary success is lower containment false positives and higher EGAR, not maximum containment rate.
- RAG, LLMs, and fine-tuned models provide context, ranking, and explanations, but not final containment authority.

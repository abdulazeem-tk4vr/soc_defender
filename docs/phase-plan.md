# soc_defender Phased Implementation Plan

This document is the implementation-facing phase plan for `soc_defender`. It maps the proposed defender pipeline to build phases, OpenSec benchmark restrictions, and the concrete dependency order needed to ship the first working `evidence_gate_only` milestone before the final agentic system.

## Context Sources

Use these files as the source context for implementation decisions:

- `soc_defender/docs/implementation_plan.md`
- `soc_defender/docs/instructions.md`
- `soc_defender/docs/proposed_defender_pipeline_research.png`
- `opensec-env/docs/SCHEMA_SPEC.md`
- `opensec-env/docs/ORACLE_SPEC.md`
- `opensec-env/docs/EVAL_PROTOCOL.md`
- `opensec-env/docs/ATTACKER_POLICY_SPEC.md`
- `opensec-env/docs/TAXONOMY_SPEC.md`

`opensec-env` is read-only benchmark context. Do not modify benchmark code, seeds, oracle logic, or upstream eval scripts to implement `soc_defender`.

Component labels in this plan mean:

- **MVP required**: required for the first working `evidence_gate_only` milestone.
- **Full-agentic required**: required for the final diagrammed defender pipeline.
- **Deferred provider-extension only**: LangChain multi-provider support beyond Ollama.

## Pipeline Mapping From Diagram

The diagram in `soc_defender/docs/proposed_defender_pipeline_research.png` defines the target architecture. The implementation must keep its control boundaries explicit.

### A. Injection Scanner

Responsibilities:

- Run regex detection as the first scanner layer.
- Run Prompt Guard 2 as the second scanner layer.
- Run LLM localization only after earlier scanner layers flag suspicious content.
- Return untrusted spans while preserving IOCs for later investigation.

Output:

- `untrusted_spans`
- preserved IOCs
- scanner status and rule metadata

The scanner is advisory. It marks risk and preserves evidence-bearing indicators; it cannot authorize containment.

### B. RAG + Investigator + LangGraph State

Responsibilities:

- Maintain evidence actions and evidence registry state.
- Retrieve RAG intel for ATT&CK, Sigma, D3FEND, and CWE context.
- Use the investigator LLM to reason about current evidence, report gaps, and next investigation needs.
- Store state in the LangGraph audit spine in `full_agentic` mode.

Output:

- Investigation intent only.

The investigator must not propose final containment or report actions. Its role is to identify what evidence should be fetched or queried next and why.

### B2. Step Budget Controller

Responsibilities:

- Count only committed OpenSec actions.
- Treat internal scanner, RAG, LLM, verifier, registry, and report-building work as free with respect to the OpenSec step count.
- Enforce the 15-step policy for evidence gathering, gated containment, and report submission.

Only an action committed to OpenSec through `env.step(action)` consumes a benchmark step.

### C. Evidence Gate + Verifier

Responsibilities:

- Re-scan candidate evidence for injection risk.
- Enforce the EGAR gate.
- Check kill-chain coherence and action/entity alignment.
- Use a verifier LLM in the full-agentic system.
- Keep deterministic evidence gates authoritative over LLM output.

The verifier owns final-action candidacy. If containment is rejected, the path routes to one targeted investigation action, not an unsafe containment action.

### D. Responder Commit Boundary

Responsibilities:

- Serialize exactly one verifier-approved legal `AgentAction`.
- Ensure report containment lists mirror executed containment.
- Commit the single legal action to OpenSec.

Only the committed action leaves the responder and reaches `env.step()`. No scanner, RAG, investigator, verifier, or LangGraph node may call `env.step()` directly except the final OpenSec commit boundary in `full_agentic`.

## OpenSec Benchmark Restrictions

These restrictions come from the OpenSec docs and observed benchmark contract. `soc_defender` must distinguish documented environment behavior from validation it must enforce itself.

Documented OpenSec restrictions:

- Only committed `env.step(action)` calls consume a benchmark step.
- Allowed defender actions are `query_logs`, `fetch_email`, `fetch_alert`, `isolate_host`, `block_domain`, `reset_user`, and `submit_report`.
- `query_logs` SQL must be read-only `SELECT`; invalid SQL still consumes a step once committed.
- Normal evidence queries should use `email_logs`, `auth_logs`, `netflow`, `process_events`, and `alerts`.
- `new_emails` and `new_alerts` expose IDs only.
- Full content is exposed through `fetch_email`, `fetch_alert`, or returned `query_logs` rows.
- Reports must include all five attribution fields: `patient_zero_host`, `compromised_user`, `attacker_domain`, `data_target`, and `initial_vector`.
- Reports must include executed containment lists under `containment_actions`.
- Missing reports by `max_steps` produce reward `0.0` in eval.
- The train split is for tuning; the eval split is for final metrics only.
- Live attacker evaluation requires fixed attacker configuration and a replay cache for comparability.

Defender-side validation required because runtime enforcement is loose:

- Runtime containment target validation is loose; `soc_defender` must validate exact entities before containment.
- Executed containment is scored, so wrong containment cannot be repaired by later report text.
- The action adapter must reject nonexistent tables, malformed params, bad report shape, and repeated failed queries before commitment.
- The evidence gate must reject containment when support is untrusted-only, only present inside flagged injection spans, action/entity mismatched, or not malicious-indicator-bearing.
- The report builder must never claim intended containment as executed containment.

## Phase Plan

### Phase 0: Environment Setup `[MVP required]`

Create the implementation scaffold for `soc_defender` without changing `opensec-env`.

Implementation responsibilities:

- Create package folders, configs, tests, outputs, and RAG data directories.
- Set up Python `>=3.11`.
- Install `opensec-env` as an editable sibling dependency.
- Add Ollama `.env.example` values for RunPod HTTP access.
- Keep `opensec-env` read-only and reference it through path/config only.

Diagram coverage:

- Prepares all boxes A/B/B2/C/D, but implements no runtime behavior yet.

### Phase 1: Eval Harness And Baseline Parity `[MVP required]`

Build the local harness before adding defender policy logic.

Implementation responsibilities:

- Fork or adapt the OpenSec eval harness into `soc_defender/scripts/eval.py`.
- Add `--opensec-root`, `--defender`, `--ollama`, `--base-url`, `--output`, and `--summary`.
- Verify `baseline` parity with upstream OpenSec before adding defender behavior.
- Preserve the OpenSec action lifecycle: normalize exactly one action, then call `env.step(action)`.
- Emit JSONL traces and summaries for later failure analysis.

Diagram coverage:

- Establishes the D commit boundary used by all later phases.
- Confirms that only committed OpenSec actions affect step count.

### Phase 2: Observation Parser And Evidence Registry `[MVP required]`

Build the runtime memory needed by the evidence gate.

Implementation responsibilities:

- Parse OpenSec observations, evidence IDs, content exposure, attacker state, containment state, and last action result.
- Normalize evidence records and entity support from fetch/query outputs.
- Track which IDs have content exposure versus ID-only exposure.
- Extract support from `email_logs`, `auth_logs`, `netflow`, `process_events`, and `alerts`.
- Do not use ground truth at runtime.

Diagram coverage:

- Implements the evidence registry portion of B.
- Feeds later C gate decisions with normalized support records.

### Phase 3: Action Adapter And SQL Planner `[MVP required]`

Centralize all legal OpenSec action construction.

Implementation responsibilities:

- Centralize legal `AgentAction` creation.
- Validate params for every allowed action.
- Validate `submit_report.summary_json` shape and attribution fields.
- Generate safe template-based SQL over valid OpenSec evidence tables.
- Prevent nonexistent tables, repeated failed queries, and repeated `SELECT 1`.
- Record query intent in defender traces.

Diagram coverage:

- Implements the deterministic action serialization foundation for D.
- Gives B/B2/C safe investigation fallbacks when containment is blocked.

### Phase 4: Evidence Gate And 15-Step Budget `[MVP required]`

Implement the core restraint policy.

Implementation responsibilities:

- Enforce exact-entity, exposed-content, trusted-support, action/entity, malicious-indicator, and budget checks.
- Convert rejected containment into one targeted investigation action.
- Prioritize `submit_report` at the deadline.
- Count only committed OpenSec actions against the 15-step budget.
- Keep scanner/RAG/LLM/verifier internal work free with respect to OpenSec step count.

Diagram coverage:

- Implements B2.
- Implements the deterministic core of C.
- Protects D from committing unsupported containment.

### Phase 5: Report Readiness And `evidence_gate_only` Policy `[MVP required]`

Ship the first complete defender mode.

Implementation responsibilities:

- Track best current attribution values for all five report fields.
- Submit complete reports before max steps.
- Ensure report containment mirrors executed containment only.
- Compose observation parser, registry, action adapter, SQL planner, budget controller, evidence gate, and report readiness into one `evidence_gate_only` policy.
- Emit exactly one legal OpenSec action per environment step.

Diagram coverage:

- Completes the first working B/B2/C/D path without scanner, RAG, or LangGraph.

### Phase 6: Failure Analysis And Calibration `[MVP required]`

Make the MVP measurable and tunable without eval leakage.

Implementation responsibilities:

- Add a JSONL failure analyzer.
- Track EGAR failures, false positives, invalid SQL, repeated queries, missed reports, attribution gaps, and injection violations.
- Tune only on the train split.
- Freeze thresholds in `configs/calibration.yaml`.
- Use eval split only for final reported metrics.

Diagram coverage:

- Hardens B2/C/D behavior before adding full-agentic components.

### Phase 7: Regex Injection Scanner `[Full-agentic required, after MVP]`

Implement Layer 1 from the diagram.

Implementation responsibilities:

- Add a regex classifier and scanner wrapper.
- Mark untrusted spans and preserve IOCs.
- Attach scanner annotations to evidence records.
- Keep scanner output advisory; it cannot authorize containment.

Diagram coverage:

- Implements the first layer of A.
- Feeds C with scanner annotations used to reject untrusted-only support.

### Phase 8: Ollama Internal LLM Adapter `[Full-agentic required, after MVP]`

Add the required current LLM path.

Implementation responsibilities:

- Add `defender/llm.py` with Ollama/OpenAI-compatible HTTP as the required LLM path.
- Connect to RunPod Ollama via `OLLAMA_BASE_URL`.
- Support investigator and verifier structured outputs.
- Mock LLM calls in unit tests.
- Keep live LLM use out of deterministic unit tests.

Ollama on RunPod is the required LLM backend for now.

Diagram coverage:

- Enables LLM localization in A.
- Enables investigator LLM in B.
- Enables verifier LLM in C.

### Phase 9: RAG Build On RunPod GPU, Local Qdrant Transfer `[Full-agentic required, after MVP]`

Implement the RAG Intel portion of the diagram.

Implementation responsibilities:

- Fetch and stage ATT&CK STIX, Sigma, D3FEND, and CWE corpora.
- Chunk and embed corpora on RunPod GPU.
- Build the Qdrant embedded collection with SecureBERT+ embeddings.
- Transfer the completed `data/rag/qdrant/` back to local `soc_defender`.
- Load the transferred local vector DB during eval.
- Do not rebuild embeddings during local eval.
- Do not index OpenSec seeds, ground truth, or oracle internals.

Diagram coverage:

- Implements RAG Intel in B.
- Provides supporting context to investigator and verifier.
- Cannot bypass C evidence gates.

### Phase 10: Prompt Guard 2 And LLM Localization `[Full-agentic required, after MVP]`

Complete scanner layers after regex is stable.

Implementation responsibilities:

- Implement Prompt Guard 2 detection after the regex scanner is stable.
- Add LLM localization only after Prompt Guard flags suspicious content.
- Preserve IOCs even when surrounding spans are untrusted.
- Keep scanner output advisory; it cannot bypass the evidence gate.

Diagram coverage:

- Completes A.
- Improves C's ability to distinguish malicious evidence from injected instructions.

### Phase 11: LangChain Multi-Provider Layer `[Deferred provider-extension only]`

Keep provider flexibility separate from required defender behavior.

Implementation responsibilities:

- Keep Ollama on RunPod as the required LLM backend.
- Add LangChain only if the project needs provider switching or LangChain-native structured-output/retriever adapters.
- Do not make LangChain a dependency of deterministic evidence gating.
- Do not expose OpenSec mutating actions directly as LLM tools.

Diagram coverage:

- Provider adapter only.
- Does not own B2, C, or D policy decisions.

### Phase 12: LangGraph Full-Agentic Orchestration `[Full-agentic required, final phase]`

Implement the complete diagrammed internal agentic system.

Implementation responsibilities:

- Add `DefenderGraphState`.
- Implement nodes for scanner, evidence registry, RAG, investigator LLM, step budget, verifier LLM, evidence gate, responder, and OpenSec commit.
- Route graph flow as scanner -> registry -> RAG -> investigator -> step budget -> verifier -> evidence gate -> responder -> OpenSec commit.
- Only the OpenSec commit node may call `env.step()`.
- Keep deterministic gates authoritative over LLM output.
- Route rejected or insufficient-evidence paths back to targeted investigation.
- Persist node traces and full OpenSec commit responses for replayable failure analysis.

Diagram coverage:

- Completes A/B/B2/C/D as a single audit-friendly full-agentic defender.

## Tools, Technologies, Dependencies, And Libraries

Required or planned project tools:

- Python `>=3.11`
- PowerShell
- SQLite / Python `sqlite3`
- OpenSec local package
- `pydantic`
- `requests`
- `openai`
- `pyyaml`
- `pytest`
- `httpx`
- `jsonschema`
- `fastapi`
- `uvicorn`
- `openenv-core`
- Ollama on RunPod
- RunPod HTTP proxy URL
- Qdrant embedded local mode / `qdrant-client`
- Hugging Face `transformers`
- PyTorch CUDA on RunPod
- SecureBERT+ embeddings
- Prompt Guard 2
- LangChain only for deferred provider extension
- LangGraph for final full-agentic orchestration

## Acceptance Criteria

- `phase-plan.md` clearly maps each phase to implementation responsibilities.
- The document uses `MVP required`, `Full-agentic required`, and `Deferred provider-extension only` labels.
- It explicitly references `proposed_defender_pipeline_research.png`.
- It maps phases to the diagram's A/B/B2/C/D boxes.
- It explicitly states that Ollama on RunPod is the required LLM path for now.
- It explicitly states that RAG chunking and embedding happens on RunPod GPU and the completed Qdrant DB is transferred locally.
- It distinguishes OpenSec-documented restrictions from runtime-enforced defender behavior.
- It notes that runtime containment validation is loose and must be enforced by `soc_defender`.
- It does not require or describe modifications under `opensec-env`.

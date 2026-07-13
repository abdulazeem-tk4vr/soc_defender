# SOC Defender

AI-assisted SOC alert triage and response evaluation platform.

SOC Defender is a production-style cybersecurity automation project for building,
testing, and evaluating agentic SOC workflows. It provides OpenSec-compatible
agent modes, evidence tracking, evidence-gated response logic, optional RAG and
LLM-backed workflows, prompt-injection safeguards, structured reporting, and
focused tests for repeatable incident-response evaluation.

The project addresses a practical SOC problem: alerts are noisy, context is
scattered across logs and security documentation, and autonomous agents must not
take containment actions unless their decisions are grounded in trustworthy
evidence. It supports repeatable experiments, reproducible baselines, agentic
variant comparisons, and failure analysis.

## What It Demonstrates

- Agentic SOC workflow design for alert triage, evidence collection, and response planning
- Evidence-gated containment policies that prevent unsupported or unsafe actions
- RAG-ready security context retrieval for grounded analyst decisions
- Prompt-injection and tool-misuse safeguards for autonomous security agents
- Reproducible evaluation scripts, JSONL outputs, summaries, and failure analysis
- Test coverage for agent behavior, policies, report readiness, RAG builds, and classifiers

## Architecture

```text
OpenSec scenario
      |
      v
Defender mode selection
      |
      +-- baseline
      +-- evidence_gate_only
      +-- full_agentic
              |
              +-- agent graph
              +-- verifier
              +-- responder
              +-- optional RAG
              +-- optional LLM backend
      |
      v
Evidence-gated action/report
      |
      v
JSONL evaluation output + rollup summary + failure analysis
```

The core implementation lives under `defender/`, with evaluation and analysis utilities under `scripts/`.

## Defender Modes

| Mode | Purpose |
|---|---|
| `baseline` | OpenSec-compatible baseline flow |
| `evidence_gate_only` | Rule-based, evidence-gated defender for fast local checks and policy testing |
| `full_agentic` | Agentic verifier/responder workflow with optional RAG and LLM calls |

## Quick Start

```powershell
py -m pip install -e ".[dev]"
py -m pytest -q
```

Run benchmark smoke evals through OpenSec's canonical agent-mode runner:

```powershell
cd ..\opensec-env
py scripts\eval.py --config configs\soc_defender_ablations.yaml --models evidence_gate_only --split train --limit 5 --output outputs\evidence_gate_train_smoke.jsonl --llm-log outputs\evidence_gate_train_smoke_llm.jsonl
py scripts\eval.py --config configs\soc_defender_agents.yaml --models full_agentic_qwen --split train --limit 5 --output outputs\full_agentic_rag_train_smoke.jsonl --llm-log outputs\full_agentic_rag_train_smoke_llm.jsonl
```

Use `opensec-env\scripts\eval.py` and outputs under `opensec-env\outputs` for
benchmark claims and reported metrics. `--llm-log` records the OpenSec
provider-level response and, for `provider: agent`, internal soc_defender LLM
responses from RAG-query planning, investigator, verifier, and JSON repair calls.

Run the older sibling harness only for local development checks:

```powershell
py scripts\eval.py --defender evidence_gate_only --no-rag --split train --limit 5 --output outputs\smoke.jsonl --summary outputs\smoke_summary.json
```

The local helper expects the OpenSec checkout at `..\opensec-env` by default. Use
`--opensec-root path\to\opensec-env` if yours lives elsewhere.

## RAG and Security Context

RAG is optional. A local Qdrant index can be supplied with `--rag-path`, or disabled
with `--no-rag` for repeatable local experiments. For repeated eval launches, run
the persistent RAG service once and point OpenSec agent eval at it with
`SOC_DEFENDER_RAG_URL`; this avoids reloading the embedding model each eval run.

```powershell
# Terminal 1, from soc_defender
py scripts\rag_server.py --qdrant-path data\rag\qdrant --device cuda --host 127.0.0.1 --port 8765

# Terminal 2, from opensec-env
$env:SOC_DEFENDER_RAG_URL = "http://127.0.0.1:8765"
py scripts\eval.py --config configs\soc_defender_agents.yaml --models full_agentic_qwen --split train --limit 5 --llm-log outputs\full_agentic_rag_llm.jsonl
```

Useful build commands:

```powershell
py scripts\fetch_rag_corpora.py
py scripts\build_rag_chunks.py
py scripts\build_qdrant_index.py --chunks data\rag\chunks.jsonl --device cpu
```

## Evaluation and Debugging

```powershell
py scripts\summarize.py outputs\smoke.jsonl --output outputs\smoke_rollup.json
py scripts\analyze_failures.py outputs\smoke.jsonl
```

Focused test runs:

```powershell
py -m pytest tests\test_agent.py -q
py -m pytest tests\test_policy.py tests\test_report_readiness.py -q
py -m pytest tests\test_rag_build.py tests\test_regex_classifier.py -q
py -m compileall -q defender scripts
```

## Project Layout

| Path | Purpose |
|---|---|
| `defender/` | Agent, graph, policy, verifier, scanner, RAG, and LLM code |
| `scripts/` | Evaluation, summarization, RAG build, and failure analysis utilities |
| `configs/` | Defender, calibration, and prompt-injection regex configuration |
| `tests/` | Focused pytest coverage for defender behavior |
| `docs/` | Implementation notes, benchmark notes, and deployment documentation |
| `outputs/` | Local evaluation outputs and summaries |

## Why This Is Non-Trivial

This is not a CRUD app or a prompt wrapper. The system separates evidence collection, verification, policy gating, response generation, and evaluation so that SOC actions can be tested for correctness, grounding, and robustness under adversarial conditions.

## Status

See `docs\progress.md` and `docs\baseline_parity.md` for implementation notes and benchmark status.

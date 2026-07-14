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

The command above is intended for a quick SOC Defender smoke test. For canonical
benchmark runs, use OpenSec's native evaluator as described below.

## Canonical OpenSec Evaluation

Canonical evaluations should be launched from the OpenSec checkout with OpenSec's
native `scripts/eval.py`. Its `scripts/agent.py` supports `provider: agent`, imports
`build_agent` from the sibling `soc_defender` checkout, and runs the SOC Defender
through the standard OpenSec environment, seeds, episode loop, and scoring path.

Expected workspace layout:

```text
/workspace/
├── .venv/
├── opensec-env/
└── soc_defender/
```

### Start Ollama without systemd

Install Ollama if it is not already available:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Start the server as a background process and retain its PID:

```bash
mkdir -p /workspace/logs
nohup env OLLAMA_HOST=0.0.0.0:11434 OLLAMA_KEEP_ALIVE=-1 \
  ollama serve > /workspace/logs/ollama.log 2>&1 &
echo $! > /workspace/logs/ollama.pid
```

Wait for the API and pull Qwen 2.5 14B:

```bash
until curl -sf http://localhost:11434/api/tags >/dev/null; do sleep 2; done
ollama pull qwen2.5:14b
```

Preload the model and keep it resident until Ollama stops:

```bash
curl -sf http://localhost:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen2.5:14b",
    "prompt": "",
    "stream": false,
    "keep_alive": -1
  }'
curl -sf http://localhost:11434/api/ps
```

### Run the canonical standard-40 evaluation

Run from OpenSec, not from the SOC Defender checkout:

```bash
cd /workspace/opensec-env

export OLLAMA_BASE_URL="http://localhost:11434"
export OLLAMA_MODEL="qwen2.5:14b"
export OLLAMA_TIMEOUT="300"

/workspace/.venv/bin/python scripts/eval.py \
  --config configs/soc_defender_agents.yaml \
  --split eval \
  --tier standard \
  --limit 40 \
  --output outputs/qwen25_14b_standard40.jsonl \
  --summary outputs/qwen25_14b_standard40_summary.json \
  --llm-log outputs/qwen25_14b_standard40_llm.jsonl
```

This uses the following integration path:

```text
OpenSec scripts/eval.py
  -> OpenSec scripts/agent.py
  -> soc_defender/defender.build_agent()
  -> Ollama qwen2.5:14b
```

On the `fixed_steps` branch, the enabled fixed-step policy gives the SOC Defender
an internal 10-step deadline even when OpenSec supplies a different episode limit.
The OpenSec environment retains control of the outer episode loop and scoring.

To stop the background Ollama server:

```bash
kill "$(cat /workspace/logs/ollama.pid)"
```

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

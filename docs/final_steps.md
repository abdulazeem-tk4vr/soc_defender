# Final Steps: Agentic Eval With Persistent RAG

Use this as the canonical run sequence for full-agentic RAG evaluation. Run the RAG server first and keep it alive, then run OpenSec eval from a separate terminal.

## 1. Start the Persistent RAG Server

From `/workspace/soc_defender`:

```bash
cd /workspace/soc_defender
/workspace/opensec-env/.venv/bin/python scripts/rag_server.py \
  --qdrant-path data/rag/qdrant \
  --device cuda \
  --host 127.0.0.1 \
  --port 8765
```

The server is ready only after these lines appear:

```text
SentenceTransformer loaded device=cuda:0
Application startup complete.
Uvicorn running on http://127.0.0.1:8765
```

Leave this terminal running. During eval, it should print `POST /retrieve` requests.

## 2. Verify RAG Health

From another terminal:

```bash
curl http://127.0.0.1:8765/health
```

Expected result shape:

```json
{"status":"ok","rag_path":"data/rag/qdrant","rag_device":"cuda","retriever":"QdrantRAGRetriever"}
```

If this fails with connection refused, the RAG server is not ready yet or crashed during startup. Check the RAG server terminal output before running eval.

## 3. Run OpenSec Agent Eval With RAG Server

From `/workspace/opensec-env`:

```bash
cd /workspace/opensec-env
. .venv/bin/activate
export SOC_DEFENDER_RAG_URL=http://127.0.0.1:8765

python scripts/eval.py \
  --config configs/soc_defender_agents.yaml \
  --models full_agentic_qwen \
  --split train \
  --limit 10 \
  --output outputs/full_agentic_rag_train.jsonl \
  --llm-log outputs/full_agentic_rag_train_llm.jsonl
```

`SOC_DEFENDER_RAG_URL` is the important part. It makes the OpenSec `provider: agent` bridge call the persistent RAG service instead of loading the embedding model inside each eval process.

## 4. No-RAG Ablation

Use OpenSec eval from `/workspace/opensec-env`:

```bash
cd /workspace/opensec-env
. .venv/bin/activate
unset SOC_DEFENDER_RAG_URL

python scripts/eval.py \
  --config configs/soc_defender_ablations.yaml \
  --models full_agentic_no_llm \
  --split train \
  --limit 10 \
  --output outputs/full_agentic_no_rag_train.jsonl \
  --llm-log outputs/full_agentic_no_rag_train_llm.jsonl
```

## 5. Summarize Results

Summarize OpenSec reward/containment metrics from eval JSONL:

```bash
cd /workspace/opensec-env
. .venv/bin/activate

python scripts/summarize.py \
  outputs/full_agentic_no_rag_train.jsonl \
  outputs/full_agentic_rag_train.jsonl \
  --output outputs/full_agentic_rag_compare_summary.json
```

Analyze single-RAG efficiency from the sibling agent trace log:

```bash
cd /workspace/soc_defender
/workspace/opensec-env/.venv/bin/python scripts/analyze_rag_efficiency.py \
  /workspace/opensec-env/outputs/full_agentic_rag_train_llm_agent_trace.jsonl \
  --output /workspace/opensec-env/outputs/full_agentic_rag_efficiency.json
```

## 6. Log Expectations

The `--llm-log` file is for LLM/provider responses only:

- `source: soc_defender_internal_llm`: internal soc_defender LLM calls. In full-agentic agent eval, the active LLM call sites are `investigator` and `verifier`.

For `provider: agent`, OpenSec provider-level prompt/action history is intentionally not written to `--llm-log`; the agent already logs the LLM responses it owns. Non-agent providers still use `source: opensec_eval`.

Internal LLM records include `raw_text`, `parsed`, `messages`, `schema_hint`, and `error`.

Non-LLM graph metrics are written to the sibling trace file generated from the LLM log name, for example `outputs/full_agentic_rag_train_llm_agent_trace.jsonl`. Those records use `source: soc_defender_agent_trace` and are for single-RAG validation, cache-hit metrics, scanner annotations, and graph node summaries.

The full-agentic graph couples the calls to keep volume bounded: the investigator emits a minimal decision payload (`intent_type`, `entity_value`, `confidence`, concrete `evidence_summary`, optional incident-specific `rag_query`), and the verifier emits the action candidate plus compact next-call memory. Verifier memory is limited to concrete `facts`, specific `open_gaps`, and recent `steps_taken`; prompts use that compact memory plus RAG titles/scores instead of repeatedly passing full RAG document text.

## 7. Readiness Checklist

Before starting eval:

- RAG server terminal shows `Uvicorn running on http://127.0.0.1:8765`.
- `curl http://127.0.0.1:8765/health` returns HTTP 200 JSON.
- Eval terminal has `SOC_DEFENDER_RAG_URL=http://127.0.0.1:8765` exported.
- Eval is launched from `/workspace/opensec-env`, not from `soc_defender`.
- `--llm-log` is passed so raw and parsed LLM responses are saved.

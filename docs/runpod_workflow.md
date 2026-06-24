# RunPod Workflow

This document records the handoff points for live LLM calls and RAG embedding builds.

## Local Preparation

Build RAG chunks locally from staged raw corpus files:

```powershell
py -3.13 scripts\build_rag_chunks.py --input data\rag\raw --output data\rag\chunks.jsonl
```

You can repeat `--input` for additional local corpus directories. The chunker intentionally excludes paths containing `opensec-env`, `seeds`, `oracle`, or `ground_truth`.

Recommended raw corpus sources:

- ATT&CK STIX exports
- Sigma rules
- D3FEND knowledge files
- CWE descriptions
- Defensive SOC playbooks that do not contain OpenSec seed or oracle content

Current local corpus snapshot:

- ATT&CK Enterprise JSON
- CWE XML
- D3FEND JSON
- Sigma rules: 3,295 YAML files
- Chunk output: `data/rag/chunks.jsonl`
- Chunk count: 41,722

## Live Ollama Eval

Set these locally or in `.env`:

```powershell
$env:OLLAMA_BASE_URL = "https://your-runpod-proxy-url"
$env:OLLAMA_MODEL = "llama3.2:3b"
$env:OLLAMA_TEMPERATURE = "0.2"
```

Run the full-agentic scaffold with live Ollama-backed investigator/verifier/localizer calls:

```powershell
py -3.13 scripts\eval.py --defender full_agentic --agent-llm ollama --split train --limit 1 --output outputs\full_agentic_ollama_eval.jsonl --summary outputs\full_agentic_ollama_summary.json
```

You can also pass the URL directly:

```powershell
py -3.13 scripts\eval.py --defender full_agentic --agent-llm ollama --base-url https://your-runpod-proxy-url --ollama-model llama3.2:3b --split train --limit 1
```

## RunPod RAG Embedding Build

Upload or sync:

- `data/rag/chunks.jsonl`
- `scripts/build_qdrant_index.py`
- `pyproject.toml`

Install runtime dependencies on RunPod:

```bash
pip install qdrant-client sentence-transformers torch
```

Build the Qdrant collection:

```bash
python scripts/build_qdrant_index.py \
  --chunks data/rag/chunks.jsonl \
  --output-dir data/rag/qdrant \
  --embedding-model sentence-transformers/all-MiniLM-L6-v2 \
  --collection soc_defender_intel \
  --device cuda
```

The script embeds chunks in batches, writes a local Qdrant collection, and stores `data/rag/qdrant/build_manifest.json`.

If you want to try a SecureBERT-style model, pass the model name with `--embedding-model`. The script uses `sentence-transformers`, so the selected model must be loadable by that library or wrapped later.

## What I Need From You

For live LLM calls:

- RunPod HTTP proxy URL for Ollama, with no trailing path.
- Model name available in Ollama, for example `llama3.2:3b`.
- Confirmation that `/api/tags` works from your browser or local shell.

For RAG embedding:

- Which GPU/image you will use.
- Whether PyTorch CUDA and Hugging Face downloads are allowed on the pod.
- The corpus files to stage under `data/rag/raw`, or approval to fetch public corpora from RunPod.
- Whether to use `ehsanaghaei/SecureBERT` or a different embedding model.
- Whether `sentence-transformers/all-MiniLM-L6-v2` is acceptable for the first index smoke test before switching to a SecureBERT-family model.

## Safety Boundary

Do not stage OpenSec seeds, ground truth, oracle internals, eval split data, or replay caches into the RAG corpus. The RAG index should contain external security knowledge only.

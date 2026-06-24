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

For baseline comparison with the same RunPod Ollama model:

```powershell
py -3.13 scripts\eval.py --defender baseline --ollama --split train --limit 1 --output outputs\baseline_ollama_eval.jsonl --summary outputs\baseline_ollama_summary.json
```

For full-agentic ablation runs that keep the scanner, Prompt Guard 2, investigator, verifier, graph trace, and Ollama calls active but disable Qdrant/RAG retrieval, pass `--no-rag`:

```powershell
py -3.13 scripts\eval.py --defender full_agentic --ollama --no-rag --split train --limit 1 --output outputs\full_agentic_no_rag_eval.jsonl --summary outputs\full_agentic_no_rag_summary.json
```

Prompt Guard 2 is enabled by default in `full_agentic` mode with:

```text
meta-llama/Prompt-Guard-86M
```

Disable it only for debugging:

```powershell
py -3.13 scripts\eval.py --defender full_agentic --prompt-guard2-model none --split train --limit 1
```

You can also pass the URL directly:

```powershell
py -3.13 scripts\eval.py --defender full_agentic --agent-llm ollama --base-url https://your-runpod-proxy-url --ollama-model llama3.2:3b --split train --limit 1
```

When `data/rag/qdrant/build_manifest.json` exists locally, eval auto-loads the Qdrant RAG index unless `--no-rag` is passed. You can also pass it explicitly:

```powershell
py -3.13 scripts\eval.py --defender full_agentic --agent-llm ollama --rag-path data\rag\qdrant --rag-device cuda --split train --limit 1
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

Build the Qdrant collection with the preferred SecureBERT 2.0 bi-encoder:

```bash
python scripts/build_qdrant_index.py --chunks data/rag/chunks.jsonl --embedding-backend sentence-transformers --embedding-model "cisco-ai/SecureBERT2.0-biencoder" --batch-size 1024 --max-length 512
```

Use quotes around the model name. Do not split `cisco-ai/SecureBERT2.0-biencoder` across shell lines.

If batch size `1024` runs out of GPU memory, retry with `512`:

```bash
python scripts/build_qdrant_index.py --chunks data/rag/chunks.jsonl --embedding-backend sentence-transformers --embedding-model "cisco-ai/SecureBERT2.0-biencoder" --batch-size 512 --max-length 512
```

The script embeds chunks in batches, writes a local Qdrant collection, and stores `data/rag/qdrant/build_manifest.json`.

After the build finishes, package the index for download:

```bash
tar -czf data/rag/qdrant_index.tar.gz -C data/rag qdrant
```

Copy `qdrant_index.tar.gz` back locally and extract it under `soc_defender/data/rag/`, so the final path is `soc_defender/data/rag/qdrant/build_manifest.json`.

Fallback options:

- `cisco-ai/SecureBERT2.0-biencoder`: preferred cybersecurity retrieval model.
- `ehsanaghaei/SecureBERT`: older SecureBERT transformer fallback.
- `sentence-transformers/all-MiniLM-L6-v2`: fast smoke-test fallback, not security-domain specific.

Fast smoke-test command:

```bash
python scripts/build_qdrant_index.py --chunks data/rag/chunks.jsonl --embedding-backend sentence-transformers --embedding-model "sentence-transformers/all-MiniLM-L6-v2" --batch-size 1024 --max-length 256
```

## What I Need From You

For live LLM calls:

- RunPod HTTP proxy URL for Ollama, with no trailing path.
- Model name available in Ollama, for example `llama3.2:3b`.
- Confirmation that `/api/tags` works from your browser or local shell.

For RAG embedding:

- Which GPU/image you will use.
- Whether PyTorch CUDA and Hugging Face downloads are allowed on the pod.
- The corpus files to stage under `data/rag/raw`, or approval to fetch public corpora from RunPod.
- Whether to use `cisco-ai/SecureBERT2.0-biencoder` or a different SecureBERT-family embedding model.

## Safety Boundary

Do not stage OpenSec seeds, ground truth, oracle internals, eval split data, or replay caches into the RAG corpus. The RAG index should contain external security knowledge only.

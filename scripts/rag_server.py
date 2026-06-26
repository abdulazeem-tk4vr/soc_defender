#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from defender.rag import RAGIntel, build_rag_intel


class RetrieveRequest(BaseModel):
    query: str
    limit: int = Field(default=5, ge=1, le=50)


app = FastAPI(title="soc_defender RAG service")
_rag: RAGIntel | None = None


def _rag_path() -> str:
    return os.getenv("SOC_DEFENDER_RAG_PATH", str(ROOT / "data" / "rag" / "qdrant"))


def _rag_device() -> str | None:
    return os.getenv("SOC_DEFENDER_RAG_DEVICE") or None


def load_rag() -> RAGIntel:
    global _rag
    if _rag is None:
        _rag = build_rag_intel(_rag_path(), device=_rag_device())
    return _rag


@app.get("/health")
def health() -> dict[str, Any]:
    rag = load_rag()
    return {
        "status": "ok",
        "rag_path": _rag_path(),
        "rag_device": _rag_device() or "manifest/default",
        "retriever": type(rag.retriever).__name__,
    }


@app.post("/retrieve")
def retrieve(request: RetrieveRequest) -> dict[str, Any]:
    try:
        docs = load_rag().context_for(request.query, limit=request.limit)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {
        "documents": [
            {
                "source": doc.source,
                "title": doc.title,
                "text": doc.text,
                "score": doc.score,
            }
            for doc in docs
        ]
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a persistent soc_defender RAG retrieval service.")
    parser.add_argument("--qdrant-path", default=str(ROOT / "data" / "rag" / "qdrant"))
    parser.add_argument("--device", default="", help="Embedding device, e.g. cuda or cpu. Defaults to manifest value.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    os.environ["SOC_DEFENDER_RAG_PATH"] = args.qdrant_path
    if args.device:
        os.environ["SOC_DEFENDER_RAG_DEVICE"] = args.device

    # Load before serving so startup failures are visible immediately.
    load_rag()

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

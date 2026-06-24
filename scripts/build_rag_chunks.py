#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from defender.rag_build import build_chunks, load_documents, write_chunks_jsonl


ROOT = Path(__file__).resolve().parents[1]


def log(message: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build RAG corpus chunks for later RunPod embedding.")
    parser.add_argument("--input", action="append", default=[], help="File or directory to index. Can be repeated.")
    parser.add_argument("--output", default=str(ROOT / "data" / "rag" / "chunks.jsonl"))
    parser.add_argument("--max-chars", type=int, default=1600)
    parser.add_argument("--overlap-chars", type=int, default=200)
    args = parser.parse_args()

    inputs = [Path(value) for value in args.input]
    if not inputs:
        inputs = [ROOT / "data" / "rag" / "raw"]
    log(f"inputs={[str(path) for path in inputs]}")
    log("loading documents")
    documents = load_documents(inputs)
    log(f"documents loaded={len(documents)}")
    log(f"building chunks max_chars={args.max_chars} overlap_chars={args.overlap_chars}")
    chunks = build_chunks(documents, max_chars=args.max_chars, overlap_chars=args.overlap_chars)
    log(f"chunks built={len(chunks)}")
    log(f"writing chunks output={args.output}")
    count = write_chunks_jsonl(chunks, Path(args.output))
    log(f"chunks written={count}")
    print(json.dumps({"documents": len(documents), "chunks": count, "output": str(Path(args.output))}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

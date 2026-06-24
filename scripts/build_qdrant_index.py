#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import time
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from defender.rag_build import CorpusChunk, read_chunks_jsonl
from defender.embeddings import HuggingFaceTransformerEmbedder, SentenceTransformerEmbedder


def log(message: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)


def batched(items: tuple[CorpusChunk, ...], batch_size: int) -> Iterable[tuple[CorpusChunk, ...]]:
    for start in range(0, len(items), batch_size):
        yield items[start : start + batch_size]


def build_qdrant_index(
    chunks_path: Path,
    output_dir: Path,
    collection: str,
    embedding_model: str,
    embedding_backend: str,
    batch_size: int,
    device: str | None,
    max_length: int,
) -> dict[str, object]:
    try:
        from qdrant_client import QdrantClient
        from qdrant_client.models import Distance, PointStruct, VectorParams
    except ImportError as exc:
        raise RuntimeError("Install qdrant-client on RunPod to build the index") from exc

    log(f"loading chunks path={chunks_path}")
    chunks = read_chunks_jsonl(chunks_path)
    if not chunks:
        raise ValueError(f"No chunks found in {chunks_path}")
    log(f"chunks loaded={len(chunks)}")
    output_dir.mkdir(parents=True, exist_ok=True)
    if embedding_backend == "sentence-transformers":
        log(f"loading sentence-transformers model={embedding_model} device={device or 'auto'}")
        embedder = SentenceTransformerEmbedder(embedding_model, device=device)
    elif embedding_backend == "transformers":
        log(f"loading transformers model={embedding_model} device={device or 'auto'} max_length={max_length}")
        embedder = HuggingFaceTransformerEmbedder(embedding_model, device=device, max_length=max_length)
    else:
        raise ValueError(f"Unsupported embedding backend: {embedding_backend}")
    log("embedding first chunk to determine vector size")
    first_vector = embedder.embed([chunks[0].text])[0]
    log(f"vector_size={len(first_vector)}")
    client = QdrantClient(path=str(output_dir))
    log(f"recreating qdrant collection={collection} output_dir={output_dir}")
    client.recreate_collection(
        collection_name=collection,
        vectors_config=VectorParams(size=len(first_vector), distance=Distance.COSINE),
    )

    point_id = 0
    total_batches = math.ceil(len(chunks) / batch_size)
    started = time.time()
    for batch_index, batch in enumerate(batched(chunks, batch_size), start=1):
        vectors = embedder.embed([chunk.text for chunk in batch])
        points = []
        for chunk, vector in zip(batch, vectors):
            payload = asdict(chunk)
            points.append(PointStruct(id=point_id, vector=vector, payload=payload))
            point_id += 1
        client.upsert(collection_name=collection, points=points)
        if batch_index == 1 or batch_index % 25 == 0 or batch_index == total_batches:
            elapsed = time.time() - started
            log(f"indexed batch={batch_index}/{total_batches} points={point_id}/{len(chunks)} elapsed_seconds={elapsed:.1f}")

    manifest = {
        "status": "complete",
        "chunks": str(chunks_path),
        "chunk_count": len(chunks),
        "output_dir": str(output_dir),
        "embedding_model": embedding_model,
        "embedding_backend": embedding_backend,
        "collection": collection,
        "vector_size": len(first_vector),
        "batch_size": batch_size,
        "device": device or "auto",
        "max_length": max_length,
    }
    (output_dir / "build_manifest.json").write_text(json.dumps(manifest, indent=2))
    log(f"manifest written path={output_dir / 'build_manifest.json'}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Build local Qdrant RAG index from soc_defender chunks.")
    parser.add_argument("--chunks", required=True, help="JSONL chunks produced by scripts/build_rag_chunks.py")
    parser.add_argument("--output-dir", default="data/rag/qdrant")
    parser.add_argument("--embedding-model", default="ehsanaghaei/SecureBERT")
    parser.add_argument("--embedding-backend", default="transformers", choices=["transformers", "sentence-transformers"])
    parser.add_argument("--collection", default="soc_defender_intel")
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--device", default="cuda", help="Embedding device, e.g. cuda or cpu")
    parser.add_argument("--max-length", type=int, default=512)
    args = parser.parse_args()

    manifest = build_qdrant_index(
        chunks_path=Path(args.chunks),
        output_dir=Path(args.output_dir),
        collection=args.collection,
        embedding_model=args.embedding_model,
        embedding_backend=args.embedding_backend,
        batch_size=args.batch_size,
        device=args.device or None,
        max_length=args.max_length,
    )
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

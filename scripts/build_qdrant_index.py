#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from defender.rag_build import CorpusChunk, read_chunks_jsonl


def batched(items: tuple[CorpusChunk, ...], batch_size: int) -> Iterable[tuple[CorpusChunk, ...]]:
    for start in range(0, len(items), batch_size):
        yield items[start : start + batch_size]


class SentenceTransformerEmbedder:
    def __init__(self, model_name: str, device: str | None = None) -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError("Install sentence-transformers on RunPod to build embeddings") from exc
        self.model = SentenceTransformer(model_name, device=device)

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = self.model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
        return [vector.tolist() for vector in vectors]


def build_qdrant_index(
    chunks_path: Path,
    output_dir: Path,
    collection: str,
    embedding_model: str,
    batch_size: int,
    device: str | None,
) -> dict[str, object]:
    try:
        from qdrant_client import QdrantClient
        from qdrant_client.models import Distance, PointStruct, VectorParams
    except ImportError as exc:
        raise RuntimeError("Install qdrant-client on RunPod to build the index") from exc

    chunks = read_chunks_jsonl(chunks_path)
    if not chunks:
        raise ValueError(f"No chunks found in {chunks_path}")
    output_dir.mkdir(parents=True, exist_ok=True)
    embedder = SentenceTransformerEmbedder(embedding_model, device=device)
    first_vector = embedder.embed([chunks[0].text])[0]
    client = QdrantClient(path=str(output_dir))
    client.recreate_collection(
        collection_name=collection,
        vectors_config=VectorParams(size=len(first_vector), distance=Distance.COSINE),
    )

    point_id = 0
    for batch in batched(chunks, batch_size):
        vectors = embedder.embed([chunk.text for chunk in batch])
        points = []
        for chunk, vector in zip(batch, vectors):
            payload = asdict(chunk)
            points.append(PointStruct(id=point_id, vector=vector, payload=payload))
            point_id += 1
        client.upsert(collection_name=collection, points=points)

    manifest = {
        "status": "complete",
        "chunks": str(chunks_path),
        "chunk_count": len(chunks),
        "output_dir": str(output_dir),
        "embedding_model": embedding_model,
        "collection": collection,
        "vector_size": len(first_vector),
        "batch_size": batch_size,
        "device": device or "auto",
    }
    (output_dir / "build_manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Build local Qdrant RAG index from soc_defender chunks.")
    parser.add_argument("--chunks", required=True, help="JSONL chunks produced by scripts/build_rag_chunks.py")
    parser.add_argument("--output-dir", default="data/rag/qdrant")
    parser.add_argument("--embedding-model", default="sentence-transformers/all-MiniLM-L6-v2")
    parser.add_argument("--collection", default="soc_defender_intel")
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--device", default="", help="Optional sentence-transformers device, e.g. cuda or cpu")
    args = parser.parse_args()

    manifest = build_qdrant_index(
        chunks_path=Path(args.chunks),
        output_dir=Path(args.output_dir),
        collection=args.collection,
        embedding_model=args.embedding_model,
        batch_size=args.batch_size,
        device=args.device or None,
    )
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

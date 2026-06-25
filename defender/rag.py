from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Protocol

from .embeddings import build_embedder_from_manifest


@dataclass(frozen=True)
class RAGDocument:
    source: str
    title: str
    text: str
    score: float = 0.0
    corpus: str = "unknown"
    purpose: str = "advisory_context"
    containment_authority: bool = False


CORPUS_PRIORITY = {
    "attack": 0,
    "sigma": 1,
    "d3fend": 2,
    "cwe": 3,
    "builtin": 4,
    "unknown": 5,
}


class RAGRetriever:
    def retrieve(self, query: str, limit: int = 5) -> tuple[RAGDocument, ...]:
        raise NotImplementedError


class TextEmbedder(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]:
        ...


@dataclass
class LocalKeywordRAGRetriever(RAGRetriever):
    documents: tuple[RAGDocument, ...] = ()

    def retrieve(self, query: str, limit: int = 5) -> tuple[RAGDocument, ...]:
        terms = {term.casefold() for term in query.split() if len(term) > 2}
        scored: list[RAGDocument] = []
        for doc in self.documents:
            haystack = f"{doc.title} {doc.text}".casefold()
            score = sum(1 for term in terms if term in haystack)
            if score:
                scored.append(
                    RAGDocument(
                        doc.source,
                        doc.title,
                        doc.text,
                        float(score),
                        corpus=doc.corpus,
                        purpose=doc.purpose,
                        containment_authority=False,
                    )
                )
        scored.sort(key=lambda doc: (-doc.score, CORPUS_PRIORITY.get(doc.corpus, CORPUS_PRIORITY["unknown"])))
        return tuple(scored[:limit])


@dataclass
class QdrantRAGRetriever(RAGRetriever):
    path: Path
    collection_name: str = "soc_defender_intel"
    embedder: TextEmbedder | None = None
    client: object | None = None

    def retrieve(self, query: str, limit: int = 5) -> tuple[RAGDocument, ...]:
        if self.embedder is None:
            raise RuntimeError("QdrantRAGRetriever requires an embedder for query vectors")

        vector = self.embedder.embed([query])[0]
        if self.client is None:
            try:
                from qdrant_client import QdrantClient
            except ImportError as exc:
                raise RuntimeError("qdrant-client is required for Qdrant retrieval") from exc
            client = QdrantClient(path=str(self.path))
        else:
            client = self.client
        if hasattr(client, "search"):
            hits = client.search(collection_name=self.collection_name, query_vector=vector, limit=limit)
        else:
            response = client.query_points(collection_name=self.collection_name, query=vector, limit=limit)
            hits = getattr(response, "points", response)
        docs: list[RAGDocument] = []
        for hit in hits:
            payload = hit.payload or {}
            docs.append(
                RAGDocument(
                    source=str(payload.get("source_path") or payload.get("source") or "qdrant"),
                    title=str(payload.get("title") or payload.get("chunk_id") or "RAG chunk"),
                    text=str(payload.get("text") or ""),
                    score=float(hit.score),
                    corpus=infer_corpus(str(payload.get("source_path") or payload.get("source") or "")),
                    containment_authority=False,
                )
            )
        return tuple(sorted(docs, key=lambda doc: (-doc.score, CORPUS_PRIORITY.get(doc.corpus, CORPUS_PRIORITY["unknown"]))))


def default_security_corpus() -> tuple[RAGDocument, ...]:
    return (
        RAGDocument("builtin", "Phishing Initial Access", "Phishing commonly yields compromised users and patient-zero hosts.", corpus="attack"),
        RAGDocument("builtin", "Exfiltration Evidence", "Exfiltration evidence often appears in alerts or netflow with dst_domain and bytes.", corpus="sigma"),
        RAGDocument("builtin", "Data Staging Evidence", "Data staging evidence often appears in process events with target identifiers.", corpus="sigma"),
        RAGDocument("builtin", "Containment", "D3FEND containment labels describe response choices but do not authorize actions.", corpus="d3fend"),
    )


@dataclass
class RAGIntel:
    retriever: RAGRetriever = field(default_factory=lambda: LocalKeywordRAGRetriever(default_security_corpus()))

    def context_for(self, query: str, limit: int = 5) -> tuple[RAGDocument, ...]:
        docs = self.retriever.retrieve(query, limit=limit)
        return tuple(
            RAGDocument(
                doc.source,
                doc.title,
                doc.text,
                doc.score,
                corpus=doc.corpus or infer_corpus(doc.source),
                purpose=doc.purpose or "advisory_context",
                containment_authority=False,
            )
            for doc in docs
        )


def infer_corpus(source: str) -> str:
    normalized = source.replace("\\", "/").casefold()
    if "attack" in normalized or "mitre" in normalized:
        return "attack"
    if "sigma" in normalized:
        return "sigma"
    if "d3fend" in normalized:
        return "d3fend"
    if "cwe" in normalized:
        return "cwe"
    if "builtin" in normalized:
        return "builtin"
    return "unknown"


def build_rag_intel(
    qdrant_path: str | Path | None = None,
    embedder: TextEmbedder | None = None,
    device: str | None = None,
) -> RAGIntel:
    if qdrant_path and Path(qdrant_path).exists():
        path = Path(qdrant_path)
        manifest_path = path / "build_manifest.json"
        if not manifest_path.exists():
            return RAGIntel()
        resolved_embedder = embedder
        if resolved_embedder is None:
            manifest = json.loads(manifest_path.read_text())
            resolved_embedder = build_embedder_from_manifest(manifest, device=device)
        if resolved_embedder is not None:
            manifest_collection = "soc_defender_intel"
            manifest_collection = str(json.loads(manifest_path.read_text()).get("collection") or manifest_collection)
            return RAGIntel(QdrantRAGRetriever(path, collection_name=manifest_collection, embedder=resolved_embedder))
    return RAGIntel()

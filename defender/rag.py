from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class RAGDocument:
    source: str
    title: str
    text: str
    score: float = 0.0


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
                scored.append(RAGDocument(doc.source, doc.title, doc.text, float(score)))
        scored.sort(key=lambda doc: doc.score, reverse=True)
        return tuple(scored[:limit])


@dataclass
class QdrantRAGRetriever(RAGRetriever):
    path: Path
    collection_name: str = "soc_defender_intel"
    embedder: TextEmbedder | None = None

    def retrieve(self, query: str, limit: int = 5) -> tuple[RAGDocument, ...]:
        if self.embedder is None:
            raise RuntimeError("QdrantRAGRetriever requires an embedder for query vectors")
        try:
            from qdrant_client import QdrantClient
        except ImportError as exc:
            raise RuntimeError("qdrant-client is required for Qdrant retrieval") from exc

        vector = self.embedder.embed([query])[0]
        client = QdrantClient(path=str(self.path))
        hits = client.search(collection_name=self.collection_name, query_vector=vector, limit=limit)
        docs: list[RAGDocument] = []
        for hit in hits:
            payload = hit.payload or {}
            docs.append(
                RAGDocument(
                    source=str(payload.get("source_path") or payload.get("source") or "qdrant"),
                    title=str(payload.get("title") or payload.get("chunk_id") or "RAG chunk"),
                    text=str(payload.get("text") or ""),
                    score=float(hit.score),
                )
            )
        return tuple(docs)


def default_security_corpus() -> tuple[RAGDocument, ...]:
    return (
        RAGDocument("builtin", "Phishing Initial Access", "Phishing commonly yields compromised users and patient-zero hosts."),
        RAGDocument("builtin", "Exfiltration Evidence", "Exfiltration evidence often appears in alerts or netflow with dst_domain and bytes."),
        RAGDocument("builtin", "Data Staging Evidence", "Data staging evidence often appears in process events with target identifiers."),
        RAGDocument("builtin", "Containment", "Containment should isolate exact hosts, reset exact users, and block exact attacker domains only after support."),
    )


@dataclass
class RAGIntel:
    retriever: RAGRetriever = field(default_factory=lambda: LocalKeywordRAGRetriever(default_security_corpus()))

    def context_for(self, query: str, limit: int = 5) -> tuple[RAGDocument, ...]:
        return self.retriever.retrieve(query, limit=limit)


def build_rag_intel(qdrant_path: str | Path | None = None, embedder: TextEmbedder | None = None) -> RAGIntel:
    if qdrant_path and Path(qdrant_path).exists() and embedder is not None:
        return RAGIntel(QdrantRAGRetriever(Path(qdrant_path), embedder=embedder))
    return RAGIntel()

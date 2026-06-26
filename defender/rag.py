from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Any, Protocol

import requests

from .embeddings import build_embedder_from_manifest


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
class HTTPRAGRetriever(RAGRetriever):
    base_url: str
    timeout: float = 30.0

    def retrieve(self, query: str, limit: int = 5) -> tuple[RAGDocument, ...]:
        response = requests.post(
            f"{self.base_url.rstrip('/')}/retrieve",
            json={"query": query, "limit": limit},
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        docs = payload.get("documents", payload)
        if not isinstance(docs, list):
            raise RuntimeError("RAG service response must contain a documents list")
        return tuple(_document_from_payload(item) for item in docs if isinstance(item, dict))


def _document_from_payload(payload: dict[str, Any]) -> RAGDocument:
    return RAGDocument(
        source=str(payload.get("source") or payload.get("source_path") or "rag-service"),
        title=str(payload.get("title") or payload.get("chunk_id") or "RAG chunk"),
        text=str(payload.get("text") or ""),
        score=float(payload.get("score") or 0.0),
    )


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


def build_rag_intel(
    qdrant_path: str | Path | None = None,
    embedder: TextEmbedder | None = None,
    device: str | None = None,
) -> RAGIntel:
    service_url = os.getenv("SOC_DEFENDER_RAG_URL")
    if service_url:
        return RAGIntel(HTTPRAGRetriever(service_url))
    if qdrant_path and str(qdrant_path).startswith(("http://", "https://")):
        return RAGIntel(HTTPRAGRetriever(str(qdrant_path)))
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

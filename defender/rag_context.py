from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

from .scanner import InjectionScanner


SOURCE_CHARS = 256
TITLE_CHARS = 256


def scan_rag_documents(
    documents: Sequence[Any] | None,
    scanner: InjectionScanner,
    *,
    limit: int = 5,
    per_document_chars: int = 1200,
) -> list[dict[str, Any]]:
    """Normalize and scan the exact bounded RAG material eligible for prompting."""
    scanned: list[dict[str, Any]] = []
    for document in list(documents or [])[: max(0, limit)]:
        text = _string_field(document, "text", per_document_chars).strip()
        if not text:
            continue
        source = _string_field(document, "source", SOURCE_CHARS).strip()
        title = _string_field(document, "title", TITLE_CHARS).strip()
        scan = scanner.scan_text("\n".join((source, title, text)))
        scanned.append(
            {
                "source": source,
                "title": title,
                "score": _score_field(document),
                "text": text,
                "scanner_status": str(scan.status),
            }
        )
    return scanned


def prepare_rag_context(
    documents: Sequence[Any] | None,
    *,
    limit: int = 5,
    per_document_chars: int = 1200,
    total_chars: int = 5000,
) -> list[dict[str, Any]]:
    """Return clean, JSON-serializable RAG documents within a prompt budget."""
    prepared: list[dict[str, Any]] = []
    remaining = max(0, total_chars)
    for document in list(documents or [])[: max(0, limit)]:
        if str(_field(document, "scanner_status") or "") != "clean":
            continue
        source = _string_field(document, "source", SOURCE_CHARS).strip()
        title = _string_field(document, "title", TITLE_CHARS).strip()
        text = _string_field(document, "text", per_document_chars).strip()
        if not text:
            continue
        fixed_chars = len(source) + len(title) + len("clean")
        available_text = remaining - fixed_chars
        if available_text <= 0:
            break
        text = text[:available_text]
        if not text:
            break
        item = {
            "source": source,
            "title": title,
            "score": _score_field(document),
            "text": text,
            "scanner_status": "clean",
        }
        prepared.append(item)
        remaining -= fixed_chars + len(text)
        if remaining <= 0:
            break
    return prepared


def rag_trace_references(documents: Sequence[Any] | None, limit: int = 5) -> list[dict[str, Any]]:
    """Return bounded metadata only; document text must never enter graph traces."""
    return [
        {
            "source": _string_field(document, "source", SOURCE_CHARS).strip(),
            "title": _string_field(document, "title", TITLE_CHARS).strip(),
            "score": _score_field(document),
            "scanner_status": str(_field(document, "scanner_status") or "unknown"),
        }
        for document in list(documents or [])[: max(0, limit)]
    ]


def _field(document: Any, name: str) -> Any:
    if isinstance(document, Mapping):
        return document.get(name)
    return getattr(document, name, None)


def _string_field(document: Any, name: str, limit: int) -> str:
    value = _field(document, name)
    return str(value or "")[: max(0, limit)]


def _score_field(document: Any) -> float:
    try:
        score = float(_field(document, "score") or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return score if math.isfinite(score) else 0.0

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SUPPORTED_SUFFIXES = {".txt", ".md", ".json", ".yaml", ".yml"}
EXCLUDED_PARTS = {"opensec-env", "oracle", "seeds", "ground_truth", "__pycache__"}


@dataclass(frozen=True)
class CorpusDocument:
    source_path: str
    source_type: str
    text: str


@dataclass(frozen=True)
class CorpusChunk:
    chunk_id: str
    source_path: str
    source_type: str
    chunk_index: int
    text: str
    token_estimate: int


def should_index(path: Path) -> bool:
    lowered_parts = {part.casefold() for part in path.parts}
    if lowered_parts.intersection(EXCLUDED_PARTS):
        return False
    if path.name.casefold() == "corpus_manifest.json":
        return False
    if "ground_truth" in path.name.casefold():
        return False
    return path.suffix.casefold() in SUPPORTED_SUFFIXES


def load_documents(paths: Iterable[Path]) -> tuple[CorpusDocument, ...]:
    docs: list[CorpusDocument] = []
    for root in paths:
        candidates = [root] if root.is_file() else sorted(root.rglob("*"))
        for path in candidates:
            if not path.is_file() or not should_index(path):
                continue
            text = path.read_text(encoding="utf-8", errors="ignore").strip()
            if not text:
                continue
            docs.append(CorpusDocument(str(path), path.suffix.casefold().lstrip("."), text))
    return tuple(docs)


def chunk_text(text: str, max_chars: int = 1600, overlap_chars: int = 200) -> tuple[str, ...]:
    if max_chars <= 0:
        raise ValueError("max_chars must be positive")
    if overlap_chars < 0 or overlap_chars >= max_chars:
        raise ValueError("overlap_chars must be non-negative and smaller than max_chars")
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + max_chars)
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end == len(text):
            break
        start = max(0, end - overlap_chars)
    return tuple(chunks)


def build_chunks(
    documents: Iterable[CorpusDocument],
    max_chars: int = 1600,
    overlap_chars: int = 200,
) -> tuple[CorpusChunk, ...]:
    chunks: list[CorpusChunk] = []
    for doc in documents:
        for idx, text in enumerate(chunk_text(doc.text, max_chars=max_chars, overlap_chars=overlap_chars)):
            chunk_id = stable_chunk_id(doc.source_path, idx, text)
            chunks.append(
                CorpusChunk(
                    chunk_id=chunk_id,
                    source_path=doc.source_path,
                    source_type=doc.source_type,
                    chunk_index=idx,
                    text=text,
                    token_estimate=max(1, len(text) // 4),
                )
            )
    return tuple(chunks)


def stable_chunk_id(source_path: str, chunk_index: int, text: str) -> str:
    digest = hashlib.sha256(f"{source_path}\0{chunk_index}\0{text}".encode("utf-8")).hexdigest()[:16]
    return f"chunk-{digest}"


def write_chunks_jsonl(chunks: Iterable[CorpusChunk], output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output_path.open("w", encoding="utf-8") as f:
        for chunk in chunks:
            f.write(json.dumps(asdict(chunk), ensure_ascii=False) + "\n")
            count += 1
    return count


def read_chunks_jsonl(path: Path) -> tuple[CorpusChunk, ...]:
    chunks: list[CorpusChunk] = []
    with path.open(encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            try:
                chunks.append(
                    CorpusChunk(
                        chunk_id=str(data["chunk_id"]),
                        source_path=str(data["source_path"]),
                        source_type=str(data["source_type"]),
                        chunk_index=int(data["chunk_index"]),
                        text=str(data["text"]),
                        token_estimate=int(data["token_estimate"]),
                    )
                )
            except KeyError as exc:
                raise ValueError(f"{path}:{line_no}: missing chunk field {exc}") from exc
    return tuple(chunks)

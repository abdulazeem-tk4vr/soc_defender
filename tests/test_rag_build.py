from pathlib import Path

from defender.rag_build import build_chunks, load_documents, read_chunks_jsonl, should_index, write_chunks_jsonl


def test_should_index_excludes_opensec_and_ground_truth_paths():
    assert not should_index(Path("opensec-env/data/seeds/train/seed-001_seed.json"))
    assert not should_index(Path("docs/seed-001_ground_truth.json"))
    assert should_index(Path("data/rag/raw/attack.md"))


def test_build_chunks_is_stable_and_overlapping(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    doc = raw / "intel.md"
    doc.write_text("abcdef " * 100)

    docs = load_documents([raw])
    chunks = build_chunks(docs, max_chars=100, overlap_chars=10)
    output = tmp_path / "chunks.jsonl"
    count = write_chunks_jsonl(chunks, output)

    assert len(docs) == 1
    assert count == len(chunks)
    assert len(chunks) > 1
    assert chunks[0].chunk_id == build_chunks(docs, max_chars=100, overlap_chars=10)[0].chunk_id
    assert output.read_text().count("\n") == len(chunks)
    assert read_chunks_jsonl(output) == chunks

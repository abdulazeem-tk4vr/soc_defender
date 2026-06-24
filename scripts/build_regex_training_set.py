#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent


def _json_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        text = value.strip()
        if text:
            yield text
    elif isinstance(value, dict):
        for item in value.values():
            yield from _json_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _json_strings(item)


def load_positive_examples(path: Path) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    with path.open(newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            text = (row.get("text") or "").strip()
            if not text:
                continue
            examples.append(
                {
                    "label": "injection",
                    "text": text,
                    "source": str(path),
                    "category": row.get("category") or "",
                    "subcategory": row.get("subcategory") or "",
                }
            )
    return examples


def load_benign_train_examples(train_dir: Path, limit_per_seed: int = 20) -> list[dict[str, Any]]:
    examples: list[dict[str, Any]] = []
    for seed_path in sorted(train_dir.glob("*_seed.json")):
        data = json.loads(seed_path.read_text(encoding="utf-8", errors="ignore"))
        added = 0
        for text in _json_strings(data):
            lowered = text.casefold()
            if any(marker in lowered for marker in ("ignore previous", "developer prompt", "system prompt", "jailbreak")):
                continue
            examples.append({"label": "benign", "text": text, "source": str(seed_path)})
            added += 1
            if added >= limit_per_seed:
                break
    return examples


def write_jsonl(examples: Iterable[dict[str, Any]], output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output_path.open("w", encoding="utf-8") as f:
        for example in examples:
            f.write(json.dumps(example, ensure_ascii=False) + "\n")
            count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Build train-only regex prompt-injection examples.")
    parser.add_argument("--positive-csv", default=str(REPO_ROOT / "prompt-injections" / "prompt_injections.csv"))
    parser.add_argument("--train-dir", default=str(REPO_ROOT / "opensec-env" / "data" / "seeds" / "train"))
    parser.add_argument("--output", default=str(ROOT / "data" / "regex_training_set.jsonl"))
    parser.add_argument("--limit-benign-per-seed", type=int, default=20)
    args = parser.parse_args()

    positives = load_positive_examples(Path(args.positive_csv))
    benign = load_benign_train_examples(Path(args.train_dir), limit_per_seed=args.limit_benign_per_seed)
    count = write_jsonl([*positives, *benign], Path(args.output))
    print(json.dumps({"output": args.output, "positive": len(positives), "benign": len(benign), "total": count}, indent=2))


if __name__ == "__main__":
    main()

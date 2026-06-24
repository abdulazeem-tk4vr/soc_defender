#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from defender.regex_classifier import RegexPromptInjectionClassifier


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OPENSEC_TRAIN = ROOT.parent / "opensec-env" / "data" / "seeds" / "train"


def load_json(path: Path) -> dict[str, Any]:
    with path.open() as f:
        return json.load(f)


def injected_texts_from_seed(seed: dict[str, Any]) -> list[dict[str, str]]:
    injection_ids = {payload.get("injection_id") for payload in seed.get("prompt_injection_payloads", [])}
    examples: list[dict[str, str]] = []
    artifacts = seed.get("seed_artifacts", {})
    for email in artifacts.get("emails", []):
        if email.get("injection_id") in injection_ids:
            examples.append({"label": "positive", "source": email.get("email_id", "email"), "text": " ".join(str(email.get(k, "")) for k in ("subject", "body"))})
    for template in artifacts.get("log_templates", []):
        if template.get("injection_id") in injection_ids:
            examples.append({"label": "positive", "source": template.get("template_id", "template"), "text": str(template.get("template_body", ""))})
    return examples


def benign_texts_from_seed(seed: dict[str, Any]) -> list[dict[str, str]]:
    examples: list[dict[str, str]] = []
    artifacts = seed.get("seed_artifacts", {})
    for email in artifacts.get("emails", []):
        if not email.get("injection_id"):
            examples.append({"label": "negative", "source": email.get("email_id", "email"), "text": " ".join(str(email.get(k, "")) for k in ("subject", "body"))})
    for template in artifacts.get("log_templates", []):
        if not template.get("injection_id"):
            examples.append({"label": "negative", "source": template.get("template_id", "template"), "text": str(template.get("template_body", ""))})
    return examples


def build_examples(train_dir: Path, limit: int) -> list[dict[str, str]]:
    examples: list[dict[str, str]] = []
    seeds = sorted(train_dir.glob("*_seed.json"))
    if limit:
        seeds = seeds[:limit]
    for seed_path in seeds:
        seed = load_json(seed_path)
        for example in injected_texts_from_seed(seed) + benign_texts_from_seed(seed):
            example["scenario_id"] = str(seed.get("scenario_id", seed_path.stem))
            examples.append(example)
    return examples


def evaluate(examples: list[dict[str, str]], classifier: RegexPromptInjectionClassifier) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    counts = {
        "true_positive": 0,
        "false_positive": 0,
        "true_negative": 0,
        "false_negative": 0,
    }
    for example in examples:
        result = classifier.scan(example["text"])
        positive = example["label"] == "positive"
        predicted = result.is_injection
        if positive and predicted:
            counts["true_positive"] += 1
        elif positive and not predicted:
            counts["false_negative"] += 1
        elif not positive and predicted:
            counts["false_positive"] += 1
        else:
            counts["true_negative"] += 1
        rows.append(
            {
                "scenario_id": example["scenario_id"],
                "source": example["source"],
                "label": example["label"],
                "predicted_injection": predicted,
                "max_confidence": result.max_confidence,
                "rule_ids": [finding.rule_id for finding in result.findings],
            }
        )
    positives = counts["true_positive"] + counts["false_negative"]
    predicted_positive = counts["true_positive"] + counts["false_positive"]
    return {
        "counts": counts,
        "recall": counts["true_positive"] / positives if positives else None,
        "precision": counts["true_positive"] / predicted_positive if predicted_positive else None,
        "examples": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate regex prompt-injection classifier on OpenSec train seeds.")
    parser.add_argument("--train-dir", default=str(DEFAULT_OPENSEC_TRAIN))
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--output", default=str(ROOT / "outputs" / "regex_classifier_eval.json"))
    args = parser.parse_args()

    classifier = RegexPromptInjectionClassifier()
    summary = evaluate(build_examples(Path(args.train_dir), args.limit), classifier)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: v for k, v in summary.items() if k != "examples"}, indent=2))
    print(f"OK: wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

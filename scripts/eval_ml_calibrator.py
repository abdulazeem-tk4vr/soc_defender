#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defender.ml_features import (  # noqa: E402
    CONTAINMENT_LABELS,
    OBJECTIVE_LABELS,
    matrix_from_examples,
)
from scripts.build_ml_training_set import build_examples_for_split  # noqa: E402


def _load_xgb(path: Path) -> Any:
    try:
        from xgboost import XGBClassifier
    except Exception as exc:  # pragma: no cover - optional dependency
        raise SystemExit("xgboost is required to evaluate ML calibrator artifacts") from exc
    model = XGBClassifier()
    model.load_model(str(path))
    return model


def _confusion(labels: list[str], y_true: list[str], y_pred: list[str]) -> list[list[int]]:
    index = {label: idx for idx, label in enumerate(labels)}
    matrix = [[0 for _ in labels] for _ in labels]
    for truth, pred in zip(y_true, y_pred, strict=True):
        matrix[index[truth]][index[pred]] += 1
    return matrix


def _classification_metrics(labels: list[str], y_true: list[str], y_pred: list[str]) -> dict[str, Any]:
    total = len(y_true)
    correct = sum(1 for truth, pred in zip(y_true, y_pred, strict=True) if truth == pred)
    report: dict[str, Any] = {
        "accuracy": correct / total if total else 0.0,
        "support": total,
        "labels": {},
        "confusion_matrix": _confusion(labels, y_true, y_pred),
        "confusion_labels": labels,
    }
    for label in labels:
        tp = sum(1 for truth, pred in zip(y_true, y_pred, strict=True) if truth == label and pred == label)
        fp = sum(1 for truth, pred in zip(y_true, y_pred, strict=True) if truth != label and pred == label)
        fn = sum(1 for truth, pred in zip(y_true, y_pred, strict=True) if truth == label and pred != label)
        support = sum(1 for truth in y_true if truth == label)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        report["labels"][label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
        }
    return report


def _predict_labels(model: Any, x: list[list[float]], labels: list[str]) -> list[str]:
    predictions = model.predict(x)
    return [labels[int(value)] for value in predictions]


def evaluate(artifact_dir: Path, data_dir: Path, split: str, limit: int | None = None) -> dict[str, Any]:
    examples, summary = build_examples_for_split(data_dir, split=split, limit=limit)
    if not examples:
        raise SystemExit(f"no {split} examples found under {data_dir}")
    x = matrix_from_examples(examples)
    objective_true = [str((example.get("labels") or {}).get("investigation_objective")) for example in examples]
    containment_true = [str((example.get("labels") or {}).get("containment_sufficiency")) for example in examples]

    objective_model = _load_xgb(artifact_dir / "investigation_xgb.json")
    containment_model = _load_xgb(artifact_dir / "containment_xgb.json")
    objective_pred = _predict_labels(objective_model, x, OBJECTIVE_LABELS)
    containment_pred = _predict_labels(containment_model, x, CONTAINMENT_LABELS)

    by_step: dict[str, dict[str, int]] = {}
    for example, prediction in zip(examples, objective_pred, strict=True):
        key = str(example.get("step_index"))
        by_step.setdefault(key, {})[prediction] = by_step.setdefault(key, {}).get(prediction, 0) + 1

    return {
        "artifact_dir": str(artifact_dir),
        "data_dir": str(data_dir),
        "split_summary": summary,
        "objective": _classification_metrics(OBJECTIVE_LABELS, objective_true, objective_pred),
        "containment": _classification_metrics(CONTAINMENT_LABELS, containment_true, containment_pred),
        "objective_prediction_counts": dict(sorted(Counter(objective_pred).items())),
        "containment_prediction_counts": dict(sorted(Counter(containment_pred).items())),
        "objective_predictions_by_step": dict(sorted(by_step.items(), key=lambda item: int(item[0]))),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate trained ML calibrator artifacts on train or eval seeds without retraining.")
    parser.add_argument("--artifact-dir", default=str(ROOT / "defender" / "models" / "opensec_train_calibrator"))
    parser.add_argument("--data-dir", default=str(REPO_ROOT / "opensec-env" / "data" / "seeds" / "eval"))
    parser.add_argument("--split", default="eval", choices=["train", "eval"])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    report = evaluate(Path(args.artifact_dir), Path(args.data_dir), args.split, limit=args.limit)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        output = Path(args.output)
        if not output.is_absolute():
            output = ROOT / output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

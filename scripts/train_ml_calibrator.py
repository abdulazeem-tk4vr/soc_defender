#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defender.ml_features import (  # noqa: E402
    CONTAINMENT_LABELS,
    FEATURE_SCHEMA_VERSION,
    OBJECTIVE_LABELS,
    feature_schema,
    feature_schema_hash,
    matrix_from_examples,
)
from scripts.build_ml_training_set import TrainPathError, assert_train_only_path  # noqa: E402


class OptionalDependencyError(RuntimeError):
    pass


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    examples = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))
    return examples


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def label_counts(examples: list[dict[str, Any]], label_name: str) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for example in examples:
        label = (example.get("labels") or {}).get(label_name)
        if label is not None:
            counts[str(label)] += 1
    return dict(sorted(counts.items()))


def label_priors(counts: dict[str, int], labels: list[str]) -> dict[str, float]:
    total = sum(counts.values())
    if total <= 0:
        return {label: 0.0 for label in labels}
    return {label: float(counts.get(label, 0) / total) for label in labels}


def train_xgboost_models(examples: list[dict[str, Any]], artifact_dir: Path) -> dict[str, Any]:
    try:
        from xgboost import XGBClassifier
    except Exception as exc:  # pragma: no cover - depends on optional package
        raise OptionalDependencyError("xgboost is required for --train-xgboost") from exc

    x = matrix_from_examples(examples)
    objective_labels = [(example.get("labels") or {}).get("investigation_objective") for example in examples]
    containment_labels = [(example.get("labels") or {}).get("containment_sufficiency") for example in examples]
    objective_index = {label: idx for idx, label in enumerate(OBJECTIVE_LABELS)}
    containment_index = {label: idx for idx, label in enumerate(CONTAINMENT_LABELS)}
    y_objective = [objective_index[str(label)] for label in objective_labels]
    y_containment = [containment_index[str(label)] for label in containment_labels]

    objective_model = XGBClassifier(
        n_estimators=80,
        max_depth=4,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        eval_metric="mlogloss",
        random_state=7,
    )
    containment_model = XGBClassifier(
        n_estimators=80,
        max_depth=3,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        eval_metric="logloss",
        random_state=7,
    )
    objective_model.fit(x, y_objective)
    containment_model.fit(x, y_containment)
    objective_model.save_model(str(artifact_dir / "investigation_xgb.json"))
    containment_model.save_model(str(artifact_dir / "containment_xgb.json"))
    return {"xgboost": "trained", "objective_classes": OBJECTIVE_LABELS, "containment_classes": CONTAINMENT_LABELS}


def train_unsupervised_placeholders(examples: list[dict[str, Any]], artifact_dir: Path) -> dict[str, Any]:
    try:
        import joblib
        from sklearn.ensemble import IsolationForest
    except Exception as exc:  # pragma: no cover - depends on optional package
        raise OptionalDependencyError("joblib and scikit-learn are required for --train-unsupervised") from exc

    x = matrix_from_examples(examples)
    isolation_model = IsolationForest(n_estimators=100, contamination="auto", random_state=7)
    isolation_model.fit(x)
    joblib.dump(isolation_model, artifact_dir / "isolation_model.joblib")

    hdbscan_status = "not_installed"
    try:
        import hdbscan  # type: ignore

        cluster_model = hdbscan.HDBSCAN(min_cluster_size=10, prediction_data=True)
        cluster_model.fit(x)
        joblib.dump(cluster_model, artifact_dir / "cluster_model.joblib")
        hdbscan_status = "trained"
    except Exception:
        hdbscan_status = "unavailable"
    return {"isolation_forest": "trained", "hdbscan": hdbscan_status}


def write_artifacts(
    examples: list[dict[str, Any]],
    artifact_dir: Path,
    source_examples: Path,
    train_dir: Path | None,
    train_xgboost: bool,
    train_unsupervised: bool,
) -> dict[str, Any]:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    schema = feature_schema()
    objective_counts = label_counts(examples, "investigation_objective")
    containment_counts = label_counts(examples, "containment_sufficiency")
    label_schema = {
        "objective_labels": OBJECTIVE_LABELS,
        "containment_labels": CONTAINMENT_LABELS,
        "objective_counts": objective_counts,
        "containment_counts": containment_counts,
        "objective_priors": label_priors(objective_counts, OBJECTIVE_LABELS),
        "containment_priors": label_priors(containment_counts, CONTAINMENT_LABELS),
    }
    write_json(artifact_dir / "feature_schema.json", schema)
    write_json(artifact_dir / "label_schema.json", label_schema)
    write_json(
        artifact_dir / "embedding_metadata.json",
        {
            "backend": "sentence-transformers",
            "model": "cisco-ai/SecureBERT2.0-biencoder",
            "status": "not_run_in_this_artifact" if not train_unsupervised else "structured_features_used_for_v1",
        },
    )

    training_status: dict[str, Any] = {"xgboost": "skipped", "unsupervised": "skipped"}
    if train_xgboost:
        training_status.update(train_xgboost_models(examples, artifact_dir))
    if train_unsupervised:
        training_status["unsupervised"] = train_unsupervised_placeholders(examples, artifact_dir)

    scenario_ids = sorted({str(example.get("scenario_id")) for example in examples})
    manifest = {
        "artifact_version": "opensec-train-calibrator-v1",
        "created_at_unix": time.time(),
        "source_split": "train",
        "source_examples": str(source_examples),
        "source_train_dir": str(train_dir) if train_dir else None,
        "seed_ids": scenario_ids,
        "example_count": len(examples),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_schema_hash": feature_schema_hash(schema),
        "training_status": training_status,
    }
    write_json(artifact_dir / "manifest.json", manifest)
    write_json(
        artifact_dir / "calibration_report.json",
        {
            "example_count": len(examples),
            "scenario_count": len(scenario_ids),
            "objective_counts": objective_counts,
            "containment_counts": containment_counts,
            "training_status": training_status,
        },
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Train or package train-only ML calibrator artifacts.")
    parser.add_argument("--examples", required=True, help="Train-only examples JSONL from build_ml_training_set.py")
    parser.add_argument("--artifact-dir", default=str(ROOT / "defender" / "models" / "opensec_train_calibrator"))
    parser.add_argument("--train-dir", default=None, help="Optional train directory path recorded in manifest and guarded against eval use")
    parser.add_argument("--train-xgboost", action="store_true", help="Train XGBoost models when xgboost is installed")
    parser.add_argument("--train-unsupervised", action="store_true", help="Train structured-feature IsolationForest/HDBSCAN models when packages are installed")
    args = parser.parse_args()

    examples_path = Path(args.examples)
    train_dir = Path(args.train_dir) if args.train_dir else None
    try:
        if train_dir is not None:
            assert_train_only_path(train_dir)
        examples = load_jsonl(examples_path)
    except TrainPathError:
        raise
    if not examples:
        raise SystemExit("no examples found")

    manifest = write_artifacts(
        examples,
        Path(args.artifact_dir),
        examples_path,
        train_dir,
        train_xgboost=args.train_xgboost,
        train_unsupervised=args.train_unsupervised,
    )
    print(json.dumps({"artifact_dir": args.artifact_dir, "manifest": manifest}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

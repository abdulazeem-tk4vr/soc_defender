#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import hashlib
import time
from collections import Counter
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


DEFAULT_EMBEDDING_MODEL = "cisco-ai/SecureBERT2.0-biencoder"


def log(message: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)


def evidence_text(example: dict[str, Any]) -> str:
    texts = [str(item.get("text") or "") for item in example.get("available_evidence") or []]
    text = "\n\n".join(part for part in texts if part.strip())
    if text.strip():
        return text
    return " ".join(
        str(example.get(key) or "")
        for key in ("scenario_id", "candidate_type", "candidate_value")
        if example.get(key) is not None
    )


def text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def load_embedding_cache(path: Path | None) -> dict[str, list[float]]:
    if path is None or not path.exists():
        log("embedding cache: no existing cache")
        return {}
    cache: dict[str, list[float]] = {}
    log(f"embedding cache: loading {path}")
    with path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            if isinstance(row.get("embedding"), list) and row.get("text_hash"):
                cache[str(row["text_hash"])] = [float(value) for value in row["embedding"]]
    log(f"embedding cache: loaded {len(cache)} entries")
    return cache


def save_embedding_cache(path: Path | None, cache: dict[str, list[float]]) -> None:
    if path is None:
        return
    log(f"embedding cache: writing {len(cache)} entries to {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for key in sorted(cache):
            f.write(json.dumps({"text_hash": key, "embedding": cache[key]}, sort_keys=True) + "\n")


def embed_examples(
    examples: list[dict[str, Any]],
    model_name: str,
    cache_path: Path | None,
    batch_size: int,
) -> tuple[list[list[float]], dict[str, Any]]:
    try:
        from sentence_transformers import SentenceTransformer
    except Exception as exc:  # pragma: no cover - depends on optional package
        raise OptionalDependencyError("sentence-transformers is required for --embed") from exc

    log(f"embedding: preparing {len(examples)} examples with model={model_name}")
    cache = load_embedding_cache(cache_path)
    texts = [evidence_text(example) for example in examples]
    keys = [text_hash(text) for text in texts]
    missing = [(key, text) for key, text in zip(keys, texts, strict=True) if key not in cache]
    log(f"embedding: cache hits={len(texts) - len(missing)} missing={len(missing)}")
    if missing:
        log("embedding: loading sentence-transformers model")
        model = SentenceTransformer(model_name)
        log(f"embedding: encoding {len(missing)} texts batch_size={batch_size}")
        encoded = model.encode([text for _, text in missing], batch_size=batch_size, show_progress_bar=True, normalize_embeddings=True)
        for (key, _), vector in zip(missing, encoded, strict=True):
            cache[key] = [float(value) for value in vector]
        save_embedding_cache(cache_path, cache)
    log("embedding: assembling embedding matrix")
    embeddings = [cache[key] for key in keys]
    dimension = len(embeddings[0]) if embeddings else 0
    return embeddings, {
        "backend": "sentence-transformers",
        "model": model_name,
        "cache_path": str(cache_path) if cache_path else None,
        "dimension": dimension,
        "texts": len(texts),
        "cache_entries": len(cache),
        "status": "embedded",
    }


def add_embedding_unsupervised_features(examples: list[dict[str, Any]], embeddings: list[list[float]]) -> dict[str, Any]:
    try:
        from sklearn.ensemble import IsolationForest
    except Exception as exc:  # pragma: no cover - depends on optional package
        raise OptionalDependencyError("scikit-learn is required for embedding unsupervised features") from exc

    if not embeddings:
        log("unsupervised: skipped empty embedding matrix")
        return {"isolation_forest": "skipped_empty", "hdbscan": "skipped_empty"}

    log(f"unsupervised: fitting IsolationForest rows={len(embeddings)} dims={len(embeddings[0]) if embeddings else 0}")
    isolation_model = IsolationForest(n_estimators=100, contamination="auto", random_state=7)
    isolation_model.fit(embeddings)
    log("unsupervised: scoring IsolationForest")
    anomaly_scores = isolation_model.decision_function(embeddings)
    for example, score in zip(examples, anomaly_scores, strict=True):
        features = dict(example.get("ml_features") or {})
        features["anomaly_score"] = float(score)
        example["ml_features"] = features

    hdbscan_status = "unavailable"
    try:
        import hdbscan  # type: ignore

        log("unsupervised: fitting HDBSCAN min_cluster_size=10")
        cluster_model = hdbscan.HDBSCAN(min_cluster_size=10, prediction_data=True)
        cluster_model.fit(embeddings)
        log("unsupervised: HDBSCAN fit complete")
        probabilities = getattr(cluster_model, "probabilities_", [0.0] * len(examples))
        labels = getattr(cluster_model, "labels_", [-1] * len(examples))
        for example, label, probability in zip(examples, labels, probabilities, strict=True):
            features = dict(example.get("ml_features") or {})
            features["cluster_id"] = float(label)
            features["cluster_probability"] = float(probability)
            features["cluster_is_noise"] = 1.0 if int(label) == -1 else 0.0
            example["ml_features"] = features
        hdbscan_status = "trained"
    except Exception as exc:
        log(f"unsupervised: HDBSCAN unavailable or failed: {exc}")
        for example in examples:
            features = dict(example.get("ml_features") or {})
            features.setdefault("cluster_id", 0.0)
            features.setdefault("cluster_probability", 0.0)
            features.setdefault("cluster_is_noise", 0.0)
            example["ml_features"] = features

    return {"isolation_forest": "trained", "hdbscan": hdbscan_status}


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

    log(f"xgboost: vectorizing {len(examples)} examples")
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
    log("xgboost: fitting investigation objective model")
    objective_model.fit(x, y_objective)
    log("xgboost: fitting containment sufficiency model")
    containment_model.fit(x, y_containment)
    log("xgboost: saving models")
    objective_model.save_model(str(artifact_dir / "investigation_xgb.json"))
    containment_model.save_model(str(artifact_dir / "containment_xgb.json"))
    return {"xgboost": "trained", "objective_classes": OBJECTIVE_LABELS, "containment_classes": CONTAINMENT_LABELS}


def train_unsupervised_placeholders(examples: list[dict[str, Any]], artifact_dir: Path) -> dict[str, Any]:
    try:
        import joblib
        from sklearn.ensemble import IsolationForest
    except Exception as exc:  # pragma: no cover - depends on optional package
        raise OptionalDependencyError("joblib and scikit-learn are required for --train-unsupervised") from exc

    log(f"xgboost: vectorizing {len(examples)} examples")
    log(f"unsupervised-structured: vectorizing {len(examples)} examples")
    x = matrix_from_examples(examples)
    log("unsupervised-structured: fitting IsolationForest")
    isolation_model = IsolationForest(n_estimators=100, contamination="auto", random_state=7)
    isolation_model.fit(x)
    joblib.dump(isolation_model, artifact_dir / "isolation_model.joblib")

    hdbscan_status = "not_installed"
    try:
        import hdbscan  # type: ignore

        log("unsupervised-structured: fitting HDBSCAN min_cluster_size=10")
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
    embed: bool = False,
    embedding_model: str = DEFAULT_EMBEDDING_MODEL,
    embedding_cache: Path | None = None,
    embedding_batch_size: int = 16,
) -> dict[str, Any]:
    log(f"artifacts: preparing {artifact_dir}")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    embedding_metadata = {
        "backend": "sentence-transformers",
        "model": embedding_model,
        "status": "not_run_in_this_artifact",
    }
    if embed:
        embeddings, embedding_metadata = embed_examples(examples, embedding_model, embedding_cache, embedding_batch_size)
        training_unsupervised = add_embedding_unsupervised_features(examples, embeddings)
    else:
        training_unsupervised = None

    log("features: building schema and label priors")
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
    log("artifacts: writing schemas and metadata")
    write_json(artifact_dir / "feature_schema.json", schema)
    write_json(artifact_dir / "label_schema.json", label_schema)
    write_json(artifact_dir / "embedding_metadata.json", embedding_metadata)

    training_status: dict[str, Any] = {"xgboost": "skipped", "unsupervised": "skipped", "embedding": embedding_metadata.get("status")}
    if training_unsupervised is not None:
        training_status["unsupervised"] = training_unsupervised
    if train_xgboost:
        training_status.update(train_xgboost_models(examples, artifact_dir))
    if train_unsupervised and training_unsupervised is None:
        training_status["unsupervised"] = train_unsupervised_placeholders(examples, artifact_dir)

    log("artifacts: building manifest and calibration report")
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
    log("artifacts: write complete")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Train or package train-only ML calibrator artifacts.")
    parser.add_argument("--examples", required=True, help="Train-only examples JSONL from build_ml_training_set.py")
    parser.add_argument("--artifact-dir", default=str(ROOT / "defender" / "models" / "opensec_train_calibrator"))
    parser.add_argument("--train-dir", default=None, help="Optional train directory path recorded in manifest and guarded against eval use")
    parser.add_argument("--train-xgboost", action="store_true", help="Train XGBoost models when xgboost is installed")
    parser.add_argument("--train-unsupervised", action="store_true", help="Train structured-feature IsolationForest/HDBSCAN models when packages are installed")
    parser.add_argument("--embed", action="store_true", help="Embed evidence text with SecureBERT2 and derive embedding-based unsupervised features")
    parser.add_argument("--embedding-model", default=DEFAULT_EMBEDDING_MODEL)
    parser.add_argument("--embedding-cache", default=str(ROOT / "outputs" / "ml_training" / "embedding_cache.jsonl"))
    parser.add_argument("--embedding-batch-size", type=int, default=16)
    args = parser.parse_args()

    examples_path = Path(args.examples)
    train_dir = Path(args.train_dir) if args.train_dir else None
    try:
        if train_dir is not None:
            assert_train_only_path(train_dir)
        log(f"examples: loading {examples_path}")
        examples = load_jsonl(examples_path)
        log(f"examples: loaded {len(examples)} examples")
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
        embed=args.embed,
        embedding_model=args.embedding_model,
        embedding_cache=Path(args.embedding_cache) if args.embedding_cache else None,
        embedding_batch_size=args.embedding_batch_size,
    )
    print(json.dumps({"artifact_dir": args.artifact_dir, "manifest": manifest}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

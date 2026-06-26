from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ml_features import (
    CONTAINMENT_LABELS,
    OBJECTIVE_LABELS,
    feature_schema_hash,
    runtime_objective_features,
    validate_feature_schema,
)


@dataclass(frozen=True)
class MLCalibratorConfig:
    enabled: bool = False
    artifact_dir: str = "defender/models/opensec_train_calibrator"
    objective_weight: float = 0.0
    containment_advisory_only: bool = True

    @classmethod
    def from_mapping(cls, value: dict[str, Any] | None) -> "MLCalibratorConfig":
        value = value or {}
        return cls(
            enabled=bool(value.get("enabled", False)),
            artifact_dir=str(value.get("artifact_dir", cls.artifact_dir)),
            objective_weight=float(value.get("objective_weight", 0.0)),
            containment_advisory_only=bool(value.get("containment_advisory_only", True)),
        )


@dataclass(frozen=True)
class ObjectiveScores:
    available: bool
    scores: dict[str, float] = field(default_factory=dict)
    selected: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "scores": dict(self.scores),
            "selected": self.selected,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ContainmentScore:
    available: bool
    action_type: str
    entity_value: str
    score: float | None = None
    label: str = "unavailable"
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "action_type": self.action_type,
            "entity_value": self.entity_value,
            "score": self.score,
            "label": self.label,
            "reason": self.reason,
        }


class MLCalibrator:
    def __init__(self, config: MLCalibratorConfig, manifest: dict[str, Any] | None = None) -> None:
        self.config = config
        self.manifest = manifest or {}

    @property
    def is_available(self) -> bool:
        return False

    def score_objectives(self, state: Any, parsed: Any | None = None) -> ObjectiveScores:
        return ObjectiveScores(available=False, reason="ml_calibrator_unavailable")

    def score_containment(self, action_type: str, entity_value: str, state: Any) -> ContainmentScore:
        return ContainmentScore(
            available=False,
            action_type=action_type,
            entity_value=entity_value,
            reason="ml_calibrator_unavailable",
        )


class ArtifactMLCalibrator(MLCalibrator):
    def __init__(
        self,
        config: MLCalibratorConfig,
        manifest: dict[str, Any],
        feature_schema: dict[str, Any],
        label_schema: dict[str, Any],
        artifact_dir: Path,
    ) -> None:
        super().__init__(config, manifest=manifest)
        self.feature_schema = feature_schema
        self.label_schema = label_schema
        self.artifact_dir = artifact_dir
        self.objective_model = self._load_xgboost_model("investigation_xgb.json")
        self.containment_model = self._load_xgboost_model("containment_xgb.json")

    @property
    def is_available(self) -> bool:
        return True

    def score_objectives(self, state: Any, parsed: Any | None = None) -> ObjectiveScores:
        feature_vector = runtime_objective_features(state, parsed)
        if self.objective_model is not None:
            scores = self._predict_scores(self.objective_model, feature_vector.values, OBJECTIVE_LABELS)
            selected = max(scores, key=scores.get) if scores else None
            return ObjectiveScores(available=True, scores=scores, selected=selected, reason="xgboost")

        scores = dict(self.label_schema.get("objective_priors") or {})
        if not scores:
            return ObjectiveScores(available=False, reason="objective_model_unavailable")
        selected = self._heuristic_objective(state, scores)
        return ObjectiveScores(available=True, scores=scores, selected=selected, reason="label_priors")

    def score_containment(self, action_type: str, entity_value: str, state: Any) -> ContainmentScore:
        if self.containment_model is not None:
            feature_vector = runtime_objective_features(state)
            scores = self._predict_scores(self.containment_model, feature_vector.values, CONTAINMENT_LABELS)
            score = scores.get("sufficient_evidence")
            label = "sufficient_evidence" if score is not None and score >= 0.5 else "insufficient_evidence"
            return ContainmentScore(True, action_type, entity_value, score=score, label=label, reason="xgboost")

        support = getattr(getattr(state, "registry", None), "support_for", lambda *_: [])(entity_value, None)
        trusted = any(item.trust_tier != "untrusted" and not item.injection_id for item in support)
        score = 0.7 if trusted else 0.2
        label = "sufficient_evidence" if trusted else "insufficient_evidence"
        return ContainmentScore(True, action_type, entity_value, score=score, label=label, reason="support_heuristic")

    def _load_xgboost_model(self, filename: str) -> Any | None:
        path = self.artifact_dir / filename
        if not path.exists():
            return None
        try:  # pragma: no cover - optional dependency path
            from xgboost import XGBClassifier

            model = XGBClassifier()
            model.load_model(str(path))
            return model
        except Exception:
            return None

    @staticmethod
    def _predict_scores(model: Any, values: list[float], labels: list[str]) -> dict[str, float]:
        probabilities = model.predict_proba([values])[0]
        return {label: float(probabilities[index]) for index, label in enumerate(labels[: len(probabilities)])}

    @staticmethod
    def _heuristic_objective(state: Any, priors: dict[str, float]) -> str | None:
        report_values = getattr(getattr(state, "report_tracker", None), "values", {}) or {}
        if report_values.get("compromised_user") == "unknown":
            return "find_identity"
        if report_values.get("patient_zero_host") == "unknown":
            return "find_patient_zero"
        if report_values.get("data_target") == "unknown":
            return "find_data_target"
        if report_values.get("attacker_domain") == "unknown":
            return "find_attacker_domain"
        if priors:
            return max(priors, key=priors.get)
        return None


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_ml_calibrator(config: MLCalibratorConfig | dict[str, Any] | None = None) -> MLCalibrator | None:
    cfg = config if isinstance(config, MLCalibratorConfig) else MLCalibratorConfig.from_mapping(config)
    if not cfg.enabled:
        return None

    artifact_dir = Path(cfg.artifact_dir)
    try:
        manifest = _read_json(artifact_dir / "manifest.json")
        schema = _read_json(artifact_dir / "feature_schema.json")
        label_schema = _read_json(artifact_dir / "label_schema.json")
    except Exception:
        return None

    if manifest.get("source_split") != "train":
        return None
    if not validate_feature_schema(schema):
        return None
    if manifest.get("feature_schema_hash") and manifest.get("feature_schema_hash") != feature_schema_hash(schema):
        return None

    return ArtifactMLCalibrator(cfg, manifest=manifest, feature_schema=schema, label_schema=label_schema, artifact_dir=artifact_dir)

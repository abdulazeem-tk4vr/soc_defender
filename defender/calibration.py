from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


DEFAULT_SCORE_WEIGHTS = {
    "trust_tier": {
        "verified": 4.0,
        "trusted": 3.0,
        "unknown": 1.0,
        "untrusted": 0.0,
    },
    "source_table": {
        "domain": {"netflow": 4.0, "alerts": 3.0, "email_logs": 1.0},
        "host": {"alerts": 3.0, "auth_logs": 2.5, "process_events": 2.5},
        "user": {"auth_logs": 3.0, "email_logs": 2.0, "alerts": 2.0},
        "target": {"process_events": 4.0, "alerts": 3.0, "netflow": 2.0},
        "default": 1.0,
    },
    "supporting_field": {
        "dst_domain": 2.0,
        "destination_domain": 2.0,
        "dest_domain": 2.0,
        "destination": 1.5,
        "attacker_domain": 2.0,
        "domain": 1.5,
        "host_id": 1.5,
        "src_host": 1.5,
        "dst_host": 1.5,
        "user_id": 1.5,
        "user": 1.0,
        "target_id": 2.0,
        "data_target": 2.0,
        "target": 2.0,
        "object_id": 1.5,
        "resource_id": 1.5,
        "dataset": 1.5,
        "file_id": 1.5,
        "message": 1.0,
        "command_line": 1.0,
        "body": 0.5,
        "default": 0.5,
    },
    "malicious_indicator": 1.5,
    "scanner_status": {
        "clean": 1.0,
        "unknown": 0.0,
        "localized": -5.0,
        "suspicious": -6.0,
        "flagged": -8.0,
    },
    "recency": {
        "max_bonus": 1.0,
        "window_steps": 5,
    },
    "corroboration": {
        "per_extra_source": 1.5,
        "per_extra_evidence": 0.5,
        "max_bonus": 3.0,
    },
}


@dataclass(frozen=True)
class CalibrationConfig:
    status: str = "initial"
    tuned_on: str = "train"
    notes: str = "Initial deterministic MVP thresholds. Tune only on OpenSec train split."
    containment_min_step: int | None = None
    containment_min_step_divisor: int = 3
    report_deadline_step: int | None = None
    report_field_thresholds: dict[str, float] = field(
        default_factory=lambda: {
            "patient_zero_host": 6.0,
            "compromised_user": 6.0,
            "attacker_domain": 6.0,
            "data_target": 6.0,
        }
    )
    scanner_taint_policy: dict[str, Any] = field(
        default_factory=lambda: {
            "reject_statuses": ["flagged", "suspicious", "localized"],
            "localized_spans_reject": True,
        }
    )
    score_weights: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_SCORE_WEIGHTS))

    def report_field_threshold(self, field_name: str) -> float:
        return float(self.report_field_thresholds.get(field_name, 6.0))

    @property
    def taint_reject_statuses(self) -> set[str]:
        return {str(item) for item in self.scanner_taint_policy.get("reject_statuses", [])}

    @property
    def reject_localized_spans(self) -> bool:
        return bool(self.scanner_taint_policy.get("localized_spans_reject", True))


def default_config_path() -> Path:
    return Path(__file__).resolve().parents[1] / "configs" / "calibration.yaml"


def _deep_merge(base: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_calibration(path: str | Path | None = None) -> CalibrationConfig:
    config_path = Path(path) if path is not None else default_config_path()
    defaults = CalibrationConfig()
    if not config_path.exists():
        return defaults
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    raw_calibration = raw.get("calibration", raw)
    if not isinstance(raw_calibration, dict):
        return defaults

    weights = _deep_merge(DEFAULT_SCORE_WEIGHTS, raw_calibration.get("score_weights") or {})
    return CalibrationConfig(
        status=str(raw_calibration.get("status", defaults.status)),
        tuned_on=str(raw_calibration.get("tuned_on", defaults.tuned_on)),
        notes=str(raw_calibration.get("notes", defaults.notes)),
        containment_min_step=(
            int(raw_calibration["containment_min_step"])
            if raw_calibration.get("containment_min_step") is not None
            else defaults.containment_min_step
        ),
        containment_min_step_divisor=max(1, int(raw_calibration.get("containment_min_step_divisor", defaults.containment_min_step_divisor))),
        report_deadline_step=raw_calibration.get("report_deadline_step", defaults.report_deadline_step),
        report_field_thresholds=dict(
            raw_calibration.get("thresholds", {}).get("report_fields", defaults.report_field_thresholds)
        ),
        scanner_taint_policy=dict(raw_calibration.get("scanner_taint_policy", defaults.scanner_taint_policy)),
        score_weights=weights,
    )

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


FEATURE_SCHEMA_VERSION = "ml-features-v1"
FEATURE_NAMES = [
    "step_index",
    "steps_remaining",
    "max_steps",
    "missing_patient_zero_host",
    "missing_compromised_user",
    "missing_attacker_domain",
    "missing_data_target",
    "candidate_type_host",
    "candidate_type_user",
    "candidate_type_domain",
    "candidate_type_target",
    "available_evidence_count",
    "evidence_alerts_count",
    "evidence_auth_logs_count",
    "evidence_email_logs_count",
    "evidence_netflow_count",
    "evidence_process_events_count",
    "trust_verified_count",
    "trust_corroborated_count",
    "trust_untrusted_count",
    "has_prompt_injection_target",
    "has_injection_evidence",
    "has_untrusted_evidence",
    "indicator_phish",
    "indicator_credential",
    "indicator_lateral",
    "indicator_stage",
    "indicator_target",
    "indicator_exfil",
    "indicator_dst_domain",
]
OBJECTIVE_LABELS = [
    "find_identity",
    "find_patient_zero",
    "find_attacker_domain",
    "find_data_target",
    "corroborate_containment",
    "submit_report",
]
CONTAINMENT_LABELS = ["insufficient_evidence", "sufficient_evidence"]
FIELD_LABELS = ["patient_zero_host", "compromised_user", "attacker_domain", "data_target"]
SOURCE_TABLES = ["alerts", "auth_logs", "email_logs", "netflow", "process_events"]
TRUST_TIERS = ["verified", "corroborated", "untrusted"]
INDICATORS = ["phish", "credential", "lateral", "stage", "target", "exfil", "dst_domain"]


@dataclass(frozen=True)
class FeatureVector:
    names: list[str]
    values: list[float]

    def as_mapping(self) -> dict[str, float]:
        return dict(zip(self.names, self.values, strict=True))


def feature_schema() -> dict[str, Any]:
    return {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "objective_labels": list(OBJECTIVE_LABELS),
        "containment_labels": list(CONTAINMENT_LABELS),
        "field_labels": list(FIELD_LABELS),
    }


def feature_schema_hash(schema: dict[str, Any] | None = None) -> str:
    schema = schema or feature_schema()
    payload = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_feature_schema(schema: dict[str, Any]) -> bool:
    return (
        schema.get("schema_version") == FEATURE_SCHEMA_VERSION
        and schema.get("feature_names") == FEATURE_NAMES
    )


def _count(mapping: dict[str, Any], key: str) -> float:
    value = mapping.get(key, 0)
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _evidence_flags(evidence: list[dict[str, Any]]) -> tuple[bool, bool, dict[str, int]]:
    has_injection = False
    has_untrusted = False
    indicators = {name: 0 for name in INDICATORS}
    for item in evidence:
        if item.get("injection_id"):
            has_injection = True
        if item.get("trust_tier") == "untrusted":
            has_untrusted = True
        for indicator in item.get("indicators") or []:
            if indicator in indicators:
                indicators[indicator] = 1
    return has_injection, has_untrusted, indicators


def vector_from_example(example: dict[str, Any]) -> FeatureVector:
    counts_by_table = example.get("evidence_counts_by_table") or {}
    trust_counts = example.get("trust_tier_counts") or {}
    candidate_type = example.get("candidate_type") or ""
    evidence = list(example.get("available_evidence") or [])
    has_injection, has_untrusted, indicators = _evidence_flags(evidence)
    report_field = (example.get("labels") or {}).get("report_field")
    missing = {
        "patient_zero_host": 1.0 if report_field != "patient_zero_host" else 0.0,
        "compromised_user": 1.0 if report_field != "compromised_user" else 0.0,
        "attacker_domain": 1.0 if report_field != "attacker_domain" else 0.0,
        "data_target": 1.0 if report_field != "data_target" else 0.0,
    }
    values = {
        "step_index": float(example.get("step_index") or 0),
        "steps_remaining": float(example.get("steps_remaining") or 0),
        "max_steps": float(example.get("max_steps") or 0),
        "missing_patient_zero_host": missing["patient_zero_host"],
        "missing_compromised_user": missing["compromised_user"],
        "missing_attacker_domain": missing["attacker_domain"],
        "missing_data_target": missing["data_target"],
        "candidate_type_host": 1.0 if candidate_type == "host" else 0.0,
        "candidate_type_user": 1.0 if candidate_type == "user" else 0.0,
        "candidate_type_domain": 1.0 if candidate_type == "domain" else 0.0,
        "candidate_type_target": 1.0 if candidate_type == "target" else 0.0,
        "available_evidence_count": float(example.get("available_evidence_count") or 0),
        "evidence_alerts_count": _count(counts_by_table, "alerts"),
        "evidence_auth_logs_count": _count(counts_by_table, "auth_logs"),
        "evidence_email_logs_count": _count(counts_by_table, "email_logs"),
        "evidence_netflow_count": _count(counts_by_table, "netflow"),
        "evidence_process_events_count": _count(counts_by_table, "process_events"),
        "trust_verified_count": _count(trust_counts, "verified"),
        "trust_corroborated_count": _count(trust_counts, "corroborated"),
        "trust_untrusted_count": _count(trust_counts, "untrusted"),
        "has_prompt_injection_target": 1.0 if example.get("candidate_is_prompt_injection_target") else 0.0,
        "has_injection_evidence": 1.0 if has_injection else 0.0,
        "has_untrusted_evidence": 1.0 if has_untrusted else 0.0,
    }
    for indicator in INDICATORS:
        values[f"indicator_{indicator}"] = float(indicators[indicator])
    return FeatureVector(list(FEATURE_NAMES), [float(values[name]) for name in FEATURE_NAMES])


def matrix_from_examples(examples: list[dict[str, Any]]) -> list[list[float]]:
    return [vector_from_example(example).values for example in examples]


def runtime_objective_features(policy: Any, parsed: Any | None = None) -> FeatureVector:
    values = {name: 0.0 for name in FEATURE_NAMES}
    step_index = int(getattr(parsed, "step_index", 0) or 0) if parsed is not None else 0
    max_steps = int(getattr(policy, "max_steps", 15) or 15)
    report_values = getattr(getattr(policy, "report_tracker", None), "values", {}) or {}
    supports = list(getattr(getattr(policy, "registry", None), "supports", []) or [])
    values.update(
        {
            "step_index": float(step_index),
            "steps_remaining": float(max(0, max_steps - 1 - step_index)),
            "max_steps": float(max_steps),
            "missing_patient_zero_host": 1.0 if report_values.get("patient_zero_host") == "unknown" else 0.0,
            "missing_compromised_user": 1.0 if report_values.get("compromised_user") == "unknown" else 0.0,
            "missing_attacker_domain": 1.0 if report_values.get("attacker_domain") == "unknown" else 0.0,
            "missing_data_target": 1.0 if report_values.get("data_target") == "unknown" else 0.0,
            "available_evidence_count": float(len({support.evidence_id for support in supports})),
        }
    )
    for support in supports:
        if support.source_table in SOURCE_TABLES:
            values[f"evidence_{support.source_table}_count"] += 1.0
        if support.trust_tier in TRUST_TIERS:
            values[f"trust_{support.trust_tier}_count"] += 1.0
        if support.injection_id:
            values["has_injection_evidence"] = 1.0
        if support.trust_tier == "untrusted":
            values["has_untrusted_evidence"] = 1.0
        for indicator in support.malicious_indicators:
            if indicator in INDICATORS:
                values[f"indicator_{indicator}"] = 1.0
    return FeatureVector(list(FEATURE_NAMES), [float(values[name]) for name in FEATURE_NAMES])

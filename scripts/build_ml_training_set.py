#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defender.evidence_registry import EvidenceRegistry  # noqa: E402
from defender.report_readiness import ReportReadinessTracker  # noqa: E402
SCHEMA_VERSION = "ml-training-v1"
ENTITY_PATTERNS = {
    "host": re.compile(r"\bh-[A-Za-z0-9_.-]+\b"),
    "user": re.compile(r"\bu-[A-Za-z0-9_.-]+\b"),
    "target": re.compile(r"\bt-[A-Za-z0-9_.-]+\b"),
    "domain": re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"),
}
DOMAIN_KV_RE = re.compile(r"\b(?:dst_domain|destination_domain|domain)=([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", re.I)
INDICATOR_WORDS = ("phish", "credential", "creds", "lateral", "stage", "target", "exfil", "dst_domain")


class TrainPathError(ValueError):
    pass


def assert_train_only_path(path: Path) -> Path:
    resolved = path.resolve()
    parts = {part.casefold() for part in resolved.parts}
    if "eval" in parts:
        raise TrainPathError(f"refusing to read eval path: {resolved}")
    if "train" not in parts:
        raise TrainPathError(f"expected a train path: {resolved}")
    return resolved


def assert_split_path(path: Path, split: str) -> Path:
    split = split.casefold()
    resolved = path.resolve()
    parts = {part.casefold() for part in resolved.parts}
    if split == "train":
        return assert_train_only_path(path)
    if split != "eval":
        raise TrainPathError(f"unsupported split: {split}")
    if "eval" not in parts:
        raise TrainPathError(f"expected an eval path: {resolved}")
    if "train" in parts:
        raise TrainPathError(f"refusing mixed train/eval path: {resolved}")
    return resolved


def load_json(path: Path) -> dict[str, Any]:
    assert_train_only_path(path)
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def load_json_for_split(path: Path, split: str) -> dict[str, Any]:
    assert_split_path(path, split)
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def seed_pairs(train_dir: Path) -> list[tuple[Path, Path]]:
    train_dir = assert_train_only_path(train_dir)
    pairs = []
    for seed_path in sorted(train_dir.glob("*_seed.json")):
        truth_path = seed_path.with_name(seed_path.name.replace("_seed.json", "_ground_truth.json"))
        if truth_path.exists():
            pairs.append((seed_path, truth_path))
    return pairs


def seed_pairs_for_split(data_dir: Path, split: str) -> list[tuple[Path, Path]]:
    data_dir = assert_split_path(data_dir, split)
    pairs = []
    for seed_path in sorted(data_dir.glob("*_seed.json")):
        truth_path = seed_path.with_name(seed_path.name.replace("_seed.json", "_ground_truth.json"))
        if truth_path.exists():
            pairs.append((seed_path, truth_path))
    return pairs


def text_from_artifact(artifact: dict[str, Any]) -> str:
    parts = []
    for key in ("subject", "body", "template_body", "payload"):
        value = artifact.get(key)
        if value:
            parts.append(str(value))
    return "\n".join(parts)


def artifact_table(artifact: dict[str, Any]) -> str:
    if artifact.get("email_id"):
        return "email_logs"
    table = artifact.get("table")
    if table:
        return str(table)
    return "unknown"


def artifact_id(artifact: dict[str, Any]) -> str:
    for key in ("email_id", "template_id", "artifact_id"):
        if artifact.get(key):
            return str(artifact[key])
    return "unknown"


def build_artifact_index(seed: dict[str, Any]) -> dict[str, dict[str, Any]]:
    artifacts: dict[str, dict[str, Any]] = {}
    seed_artifacts = seed.get("seed_artifacts") or {}
    for email in seed_artifacts.get("emails") or []:
        row = dict(email)
        row["artifact_kind"] = "email"
        artifacts[artifact_id(row)] = row
    for template in seed_artifacts.get("log_templates") or []:
        row = dict(template)
        row["artifact_kind"] = "log_template"
        artifacts[artifact_id(row)] = row
    return artifacts


def timeline_steps(seed: dict[str, Any]) -> dict[int, list[str]]:
    steps: dict[int, list[str]] = {}
    for item in ((seed.get("attack_plan") or {}).get("timeline") or []):
        step = int(item.get("step") or 0)
        for artifact in item.get("artifacts") or []:
            artifact_id_value = artifact.get("artifact_id")
            if artifact_id_value:
                steps.setdefault(step, []).append(str(artifact_id_value))
    return steps


def available_artifacts(seed: dict[str, Any], step_index: int) -> list[dict[str, Any]]:
    artifacts = build_artifact_index(seed)
    steps = timeline_steps(seed)
    available_ids: list[str] = []
    for step in sorted(steps):
        if step <= step_index:
            available_ids.extend(steps[step])
    rows = [artifacts[artifact_id_value] for artifact_id_value in available_ids if artifact_id_value in artifacts]
    return sorted(rows, key=lambda row: (artifact_table(row), artifact_id(row)))


def entity_candidates(seed: dict[str, Any]) -> list[tuple[str, str]]:
    entities = seed.get("entities") or {}
    candidates: list[tuple[str, str]] = []
    for user in entities.get("users") or []:
        if user.get("user_id"):
            candidates.append(("user", str(user["user_id"])))
    for host in entities.get("hosts") or []:
        if host.get("host_id"):
            candidates.append(("host", str(host["host_id"])))
    for domain in entities.get("domains") or []:
        if domain.get("domain"):
            candidates.append(("domain", str(domain["domain"])))
    for target in entities.get("data_targets") or []:
        if target.get("target_id"):
            candidates.append(("target", str(target["target_id"])))
    return sorted(set(candidates))


def prompt_injection_targets(seed: dict[str, Any]) -> set[tuple[str, str]]:
    targets: set[tuple[str, str]] = set()
    for payload in seed.get("prompt_injection_payloads") or []:
        params = payload.get("target_params") or {}
        for key, value in params.items():
            text = str(value)
            if key in {"host_id", "host"}:
                targets.add(("host", text))
            elif key in {"user_id", "user"}:
                targets.add(("user", text))
            elif key in {"domain", "dst_domain"}:
                targets.add(("domain", text))
            else:
                for entity_type, pattern in ENTITY_PATTERNS.items():
                    for match in pattern.finditer(text):
                        if entity_type == "domain" and match.group(0).startswith(("h-", "u-", "t-")):
                            continue
                        targets.add((entity_type, match.group(0)))
                for match in DOMAIN_KV_RE.finditer(text):
                    targets.add(("domain", match.group(1)))
    return targets


def evidence_for_candidate(rows: Iterable[dict[str, Any]], candidate_type: str, candidate_value: str) -> list[dict[str, Any]]:
    pattern = re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(candidate_value) + r"(?![A-Za-z0-9_.-])")
    evidence = []
    for row in rows:
        text = text_from_artifact(row)
        if not pattern.search(text):
            continue
        lowered = text.casefold()
        evidence.append(
            {
                "evidence_id": artifact_id(row),
                "source_table": artifact_table(row),
                "trust_tier": row.get("trust_tier"),
                "source": row.get("source"),
                "injection_id": row.get("injection_id"),
                "text": text,
                "indicators": [word for word in INDICATOR_WORDS if word in lowered],
            }
        )
    return evidence


def registry_row(row: dict[str, Any]) -> dict[str, Any]:
    table = artifact_table(row)
    converted = dict(row)
    if table == "email_logs":
        converted.setdefault("email_id", artifact_id(row))
    elif table == "alerts":
        converted.setdefault("alert_id", artifact_id(row))
    elif table == "process_events":
        converted.setdefault("event_id", artifact_id(row))
    elif table == "netflow":
        converted.setdefault("flow_id", artifact_id(row))
    elif table == "auth_logs":
        converted.setdefault("auth_id", artifact_id(row))
    return converted


def tracker_values_for_rows(rows: Iterable[dict[str, Any]], step_seen: int) -> dict[str, str]:
    registry = EvidenceRegistry()
    tracker = ReportReadinessTracker()
    for row in rows:
        registry.add_row(registry_row(row), step_seen=step_seen)
        tracker.update(registry)
    return dict(tracker.values)


def containment_ready(rows: Iterable[dict[str, Any]], required: dict[str, set[str]]) -> bool:
    row_list = list(rows)
    for candidate_type, values in required.items():
        for value in values:
            evidence = evidence_for_candidate(row_list, candidate_type, value)
            if not sufficient_containment(candidate_type, value, required, evidence):
                return False
    return True


def objective_label(
    prior_values: dict[str, str],
    current_values: dict[str, str],
    ready_for_containment: bool,
    step_index: int,
    max_step_index: int,
) -> str:
    if ready_for_containment and step_index >= max_step_index:
        return "submit_report"

    objective_by_field = {
        "patient_zero_host": "find_patient_zero",
        "compromised_user": "find_identity",
        "data_target": "find_data_target",
        "attacker_domain": "find_attacker_domain",
    }
    discovery_priority = ("patient_zero_host", "compromised_user", "data_target", "attacker_domain")
    missing_priority = ("compromised_user", "patient_zero_host", "data_target", "attacker_domain")

    for field in discovery_priority:
        if prior_values.get(field, "unknown") == "unknown" and current_values.get(field, "unknown") != "unknown":
            return objective_by_field[field]
    for field in missing_priority:
        if prior_values.get(field, "unknown") == "unknown":
            return objective_by_field[field]
    return "corroborate_containment"


def truth_maps(truth: dict[str, Any]) -> tuple[dict[str, str], dict[str, set[str]]]:
    attribution = truth.get("attribution") or {}
    containment = truth.get("containment_requirements") or {}
    fields = {
        "patient_zero_host": str(attribution.get("patient_zero_host") or ""),
        "compromised_user": str(attribution.get("compromised_user") or ""),
        "attacker_domain": str(attribution.get("attacker_domain") or ""),
        "data_target": str(attribution.get("data_target") or ""),
    }
    required = {
        "host": {str(value) for value in containment.get("isolate_hosts") or []},
        "domain": {str(value) for value in containment.get("block_domains") or []},
        "user": {str(value) for value in containment.get("reset_users") or []},
    }
    return fields, required


def field_label(candidate_type: str, candidate_value: str, fields: dict[str, str], has_evidence: bool) -> str | None:
    mapping = {
        "host": "patient_zero_host",
        "user": "compromised_user",
        "domain": "attacker_domain",
        "target": "data_target",
    }
    field = mapping.get(candidate_type)
    if not field:
        return None
    if fields.get(field) == candidate_value and has_evidence:
        return field
    return None


def sufficient_containment(candidate_type: str, candidate_value: str, required: dict[str, set[str]], evidence: list[dict[str, Any]]) -> bool:
    if candidate_type not in required or candidate_value not in required[candidate_type]:
        return False
    return any(item.get("trust_tier") != "untrusted" and not item.get("injection_id") for item in evidence)


def build_examples_for_seed(seed_path: Path, truth_path: Path, split: str = "train") -> list[dict[str, Any]]:
    seed = load_json_for_split(seed_path, split)
    truth = load_json_for_split(truth_path, split)
    scenario_id = str(seed.get("scenario_id") or truth.get("scenario_id") or seed_path.stem.replace("_seed", ""))
    max_steps = int((seed.get("metadata") or {}).get("max_steps") or 15)
    max_step_index = max_steps - 1
    fields, required = truth_maps(truth)
    injection_targets = prompt_injection_targets(seed)
    candidates = sorted(set(entity_candidates(seed)) | injection_targets)
    examples: list[dict[str, Any]] = []
    for step_index in range(max_steps):
        rows = available_artifacts(seed, step_index)
        prior_rows = available_artifacts(seed, step_index - 1) if step_index > 0 else []
        report_values = tracker_values_for_rows(prior_rows, step_seen=max(0, step_index - 1))
        current_report_values = tracker_values_for_rows(rows, step_seen=step_index)
        ready_for_containment = containment_ready(prior_rows, required)
        objective = objective_label(report_values, current_report_values, ready_for_containment, step_index, max_step_index)
        counts_by_table: dict[str, int] = {}
        trust_counts: dict[str, int] = {}
        for row in rows:
            counts_by_table[artifact_table(row)] = counts_by_table.get(artifact_table(row), 0) + 1
            trust = str(row.get("trust_tier") or "unknown")
            trust_counts[trust] = trust_counts.get(trust, 0) + 1
        for candidate_type, candidate_value in candidates:
            evidence = evidence_for_candidate(rows, candidate_type, candidate_value)
            has_evidence = bool(evidence)
            is_injection_target = (candidate_type, candidate_value) in injection_targets
            is_required_containment = candidate_value in required.get(candidate_type, set())
            positive_field = field_label(candidate_type, candidate_value, fields, has_evidence)
            examples.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "scenario_id": scenario_id,
                    "step_index": step_index,
                    "steps_remaining": max(0, max_step_index - step_index),
                    "max_steps": max_steps,
                    "report_values": report_values,
                    "candidate_type": candidate_type,
                    "candidate_value": candidate_value,
                    "candidate_is_prompt_injection_target": is_injection_target,
                    "candidate_is_required_containment": is_required_containment,
                    "candidate_is_truth_attribution": candidate_value in set(fields.values()),
                    "available_evidence_count": len(evidence),
                    "available_evidence": evidence,
                    "evidence_counts_by_table": counts_by_table,
                    "trust_tier_counts": trust_counts,
                    "labels": {
                        "investigation_objective": objective,
                        "containment_sufficiency": "sufficient_evidence"
                        if sufficient_containment(candidate_type, candidate_value, required, evidence)
                        else "insufficient_evidence",
                        "report_field": positive_field,
                    },
                }
            )
    return examples


def write_jsonl(examples: Iterable[dict[str, Any]], output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output_path.open("w", encoding="utf-8") as f:
        for example in examples:
            f.write(json.dumps(example, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def build_training_set(train_dir: Path, output_path: Path, limit: int | None = None) -> dict[str, Any]:
    pairs = seed_pairs(train_dir)
    if limit is not None:
        pairs = pairs[:limit]
    examples: list[dict[str, Any]] = []
    for seed_path, truth_path in pairs:
        examples.extend(build_examples_for_seed(seed_path, truth_path, split="train"))
    count = write_jsonl(examples, output_path)
    return {"output": str(output_path), "seeds": len(pairs), "examples": count, "schema_version": SCHEMA_VERSION}


def build_examples_for_split(data_dir: Path, split: str, limit: int | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    pairs = seed_pairs_for_split(data_dir, split)
    if limit is not None:
        pairs = pairs[:limit]
    examples: list[dict[str, Any]] = []
    for seed_path, truth_path in pairs:
        examples.extend(build_examples_for_seed(seed_path, truth_path, split=split))
    return examples, {"split": split, "seeds": len(pairs), "examples": len(examples), "schema_version": SCHEMA_VERSION}


def main() -> None:
    parser = argparse.ArgumentParser(description="Build train-only ML calibration examples from OpenSec seeds.")
    parser.add_argument("--train-dir", default=str(REPO_ROOT / "opensec-env" / "data" / "seeds" / "train"))
    parser.add_argument("--output", default=str(ROOT / "outputs" / "ml_training" / "train_examples.jsonl"))
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    summary = build_training_set(Path(args.train_dir), Path(args.output), limit=args.limit)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

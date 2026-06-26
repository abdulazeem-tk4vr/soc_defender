#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defender.evidence_registry import EvidenceRegistry  # noqa: E402
from defender.report_readiness import ReportReadinessTracker  # noqa: E402
from scripts.build_ml_training_set import assert_split_path  # noqa: E402

FIELDS = ("compromised_user", "patient_zero_host", "attacker_domain", "data_target")
FIELD_ENTITY = {
    "compromised_user": "user",
    "patient_zero_host": "host",
    "attacker_domain": "domain",
    "data_target": "target",
}
ARTIFACT_COLLECTIONS = ("emails", "log_templates")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def seed_pairs(data_dir: Path, split: str) -> list[tuple[Path, Path]]:
    data_dir = assert_split_path(data_dir, split)
    pairs = []
    for seed_path in sorted(data_dir.glob("*_seed.json")):
        truth_path = seed_path.with_name(seed_path.name.replace("_seed.json", "_ground_truth.json"))
        if truth_path.exists():
            pairs.append((seed_path, truth_path))
    return pairs


def artifact_id(row: dict[str, Any]) -> str:
    for key in ("email_id", "template_id", "artifact_id", "alert_id", "event_id", "flow_id", "auth_id"):
        if row.get(key):
            return str(row[key])
    return ""


def source_table(row: dict[str, Any]) -> str:
    if row.get("email_id"):
        return "email_logs"
    if row.get("table"):
        return str(row["table"])
    if row.get("alert_id"):
        return "alerts"
    if row.get("event_id"):
        return "process_events"
    if row.get("flow_id"):
        return "netflow"
    if row.get("auth_id"):
        return "auth_logs"
    return "unknown"


def artifact_text(row: dict[str, Any]) -> str:
    parts = []
    for key, value in row.items():
        if value is not None and key not in {"injection_id", "trust_tier", "source"}:
            parts.append(str(value))
    return " ".join(parts)


def artifact_index(seed: dict[str, Any]) -> dict[str, dict[str, Any]]:
    index = {}
    artifacts = seed.get("seed_artifacts") or {}
    for collection in ARTIFACT_COLLECTIONS:
        for row in artifacts.get(collection) or []:
            rid = artifact_id(row)
            if rid:
                index[rid] = dict(row)
    return index


def timeline_rows(seed: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
    index = artifact_index(seed)
    rows = []
    for event in (seed.get("attack_plan") or {}).get("timeline") or []:
        step = int(event.get("step") or 0)
        for artifact_ref in event.get("artifacts") or []:
            artifact = index.get(str(artifact_ref.get("artifact_id") or ""))
            if artifact is not None:
                row = dict(artifact)
                row["_timeline_artifact_type"] = artifact_ref.get("artifact_type")
                row["_timeline_step"] = step
                rows.append((step, row))
    rows.sort(key=lambda item: (item[0], artifact_id(item[1])))
    return rows


def value_present(row: dict[str, Any], value: str) -> bool:
    if not value:
        return False
    pattern = re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(value) + r"(?![A-Za-z0-9_.-])")
    return bool(pattern.search(artifact_text(row)))


def first_artifact_step(rows: list[tuple[int, dict[str, Any]]], value: str) -> int | None:
    for step, row in rows:
        if value_present(row, value):
            return step
    return None


def first_source_step(rows: list[tuple[int, dict[str, Any]]], value: str) -> int | None:
    for step, row in rows:
        if value_present(row, value) and source_table(row) != "unknown":
            return step
    return None


def registry_row(row: dict[str, Any]) -> dict[str, Any]:
    table = source_table(row)
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


def tracker_steps(rows: list[tuple[int, dict[str, Any]]], truth_values: dict[str, str]) -> tuple[dict[str, int | None], dict[str, str]]:
    registry = EvidenceRegistry()
    tracker = ReportReadinessTracker()
    first: dict[str, int | None] = {field: None for field in FIELDS}
    for step, row in rows:
        registry.add_row(registry_row(row), step_seen=step)
        tracker.update(registry)
        for field, truth in truth_values.items():
            if first[field] is None and tracker.values.get(field) == truth:
                first[field] = step
    return first, dict(tracker.values)


def analyze_pair(seed_path: Path, truth_path: Path) -> dict[str, Any]:
    seed = load_json(seed_path)
    truth = load_json(truth_path)
    attribution = truth.get("attribution") or {}
    truth_values = {field: str(attribution.get(field) or "") for field in FIELDS}
    rows = timeline_rows(seed)
    tracker_first, final_tracker = tracker_steps(rows, truth_values)
    fields = {}
    for field, value in truth_values.items():
        fields[field] = {
            "truth": value,
            "artifact_observable_step": first_artifact_step(rows, value),
            "source_observable_step": first_source_step(rows, value),
            "tracker_observable_step": tracker_first[field],
            "entity_type": FIELD_ENTITY[field],
        }
    return {
        "scenario_id": str(seed.get("scenario_id") or truth.get("scenario_id") or seed_path.stem.replace("_seed", "")),
        "max_steps": int((seed.get("metadata") or {}).get("max_steps") or 0),
        "artifact_count": len(rows),
        "final_tracker_values": final_tracker,
        "fields": fields,
    }


def summarize(rows: list[dict[str, Any]], split: str) -> dict[str, Any]:
    field_summary: dict[str, Any] = {}
    for field in FIELDS:
        summary = {
            "artifact_observable": 0,
            "source_observable": 0,
            "tracker_observable": 0,
            "artifact_step_histogram": {},
            "source_step_histogram": {},
            "tracker_step_histogram": {},
            "missing_examples": [],
        }
        artifact_hist: Counter[str] = Counter()
        source_hist: Counter[str] = Counter()
        tracker_hist: Counter[str] = Counter()
        for row in rows:
            data = row["fields"][field]
            if data["artifact_observable_step"] is not None:
                summary["artifact_observable"] += 1
                artifact_hist[str(data["artifact_observable_step"])] += 1
            if data["source_observable_step"] is not None:
                summary["source_observable"] += 1
                source_hist[str(data["source_observable_step"])] += 1
            if data["tracker_observable_step"] is not None:
                summary["tracker_observable"] += 1
                tracker_hist[str(data["tracker_observable_step"])] += 1
            if data["tracker_observable_step"] is None:
                summary["missing_examples"].append(
                    {
                        "scenario_id": row["scenario_id"],
                        "truth": data["truth"],
                        "artifact_step": data["artifact_observable_step"],
                        "source_step": data["source_observable_step"],
                        "final_tracker_value": row["final_tracker_values"].get(field),
                    }
                )
        summary["artifact_step_histogram"] = dict(sorted(artifact_hist.items(), key=lambda item: int(item[0])))
        summary["source_step_histogram"] = dict(sorted(source_hist.items(), key=lambda item: int(item[0])))
        summary["tracker_step_histogram"] = dict(sorted(tracker_hist.items(), key=lambda item: int(item[0])))
        summary["missing_examples"] = summary["missing_examples"][:10]
        field_summary[field] = summary
    return {"split": split, "scenarios": len(rows), "fields": field_summary, "scenarios_detail": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze when truth fields become observable in seed timelines.")
    parser.add_argument("--split", default="train", choices=["train", "eval"])
    parser.add_argument("--data-dir", default="")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    data_dir = Path(args.data_dir) if args.data_dir else REPO_ROOT / "opensec-env" / "data" / "seeds" / args.split
    pairs = seed_pairs(data_dir, args.split)
    if args.limit is not None:
        pairs = pairs[: args.limit]
    rows = [analyze_pair(seed_path, truth_path) for seed_path, truth_path in pairs]
    report = summarize(rows, args.split)
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

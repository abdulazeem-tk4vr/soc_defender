#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ATTRIBUTION_FIELDS = (
    "patient_zero_host",
    "compromised_user",
    "attacker_domain",
    "data_target",
    "initial_vector",
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open() as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL row") from exc
    return rows


def _steps(row: dict[str, Any]) -> list[dict[str, Any]]:
    steps = row.get("steps")
    return steps if isinstance(steps, list) else []


def _action(step: dict[str, Any]) -> dict[str, Any]:
    action = step.get("action")
    return action if isinstance(action, dict) else {}


def _sql(action: dict[str, Any]) -> str | None:
    if action.get("action_type") != "query_logs":
        return None
    params = action.get("params")
    if not isinstance(params, dict):
        return None
    sql = params.get("sql")
    return sql if isinstance(sql, str) else None


def _containment_false_positives(row: dict[str, Any]) -> int:
    if isinstance(row.get("containment_false_positive_total"), int):
        return int(row["containment_false_positive_total"])
    containment = ((row.get("details") or {}).get("containment") or {})
    total = 0
    for field in ("isolated_hosts", "blocked_domains", "reset_users"):
        field_data = containment.get(field) or {}
        total += len(field_data.get("false_positive") or [])
    return total


def _containment_correct(row: dict[str, Any]) -> int:
    if isinstance(row.get("containment_correct_total"), int):
        return int(row["containment_correct_total"])
    containment = ((row.get("details") or {}).get("containment") or {})
    total = 0
    for field in ("isolated_hosts", "blocked_domains", "reset_users"):
        field_data = containment.get(field) or {}
        total += len(field_data.get("correct") or [])
    return total


def _injection_violations(row: dict[str, Any]) -> int:
    total = 0
    details = row.get("details") or {}
    detail_violations = ((details.get("injection") or {}).get("violations") or [])
    total += len(detail_violations)
    top_level = row.get("injection_violations") or []
    total += len(top_level)
    for step in _steps(row):
        total += len(step.get("injection_violations") or [])
    return total


def _injection_exposed(row: dict[str, Any]) -> bool:
    diagnostics = row.get("diagnostics") or {}
    return int(diagnostics.get("injection_evidence_seen") or 0) > 0


def _mean(values: list[float]) -> float | None:
    return statistics.fmean(values) if values else None


def _metric_block(rows: list[dict[str, Any]]) -> dict[str, Any]:
    rewards = [float(row.get("reward") or 0.0) for row in rows]
    egar_values = [
        float(row.get("evidence_gated_action_rate"))
        for row in rows
        if isinstance(row.get("evidence_gated_action_rate"), (int, float))
    ]
    ttfc_values = [
        float(row.get("time_to_first_containment"))
        for row in rows
        if isinstance(row.get("time_to_first_containment"), (int, float))
    ]
    containment_correct = [_containment_correct(row) for row in rows]
    containment_false = [_containment_false_positives(row) for row in rows]
    injection_violations = [_injection_violations(row) for row in rows]
    runs = len(rows)

    return {
        "runs": runs,
        "reward_mean": _mean(rewards),
        "reward_min": min(rewards) if rewards else None,
        "reward_max": max(rewards) if rewards else None,
        "egar_mean": _mean(egar_values),
        "time_to_first_containment_mean": _mean(ttfc_values),
        "containment_correct_total": sum(containment_correct),
        "containment_false_positive_total": sum(containment_false),
        "containment_correct_runs": sum(1 for count in containment_correct if count > 0),
        "containment_false_positive_runs": sum(1 for count in containment_false if count > 0),
        "report_submitted_total": sum(1 for row in rows if row.get("submitted_report")),
        "report_submitted_rate": (
            sum(1 for row in rows if row.get("submitted_report")) / runs if runs else None
        ),
        "injection_exposure_runs": sum(1 for row in rows if _injection_exposed(row)),
        "injection_exposure_rate": (
            sum(1 for row in rows if _injection_exposed(row)) / runs if runs else None
        ),
        "injection_violation_total": sum(injection_violations),
        "injection_violation_runs": sum(1 for count in injection_violations if count > 0),
        "injection_violation_rate": (
            sum(1 for count in injection_violations if count > 0) / runs if runs else None
        ),
    }


def _attribution_gaps(row: dict[str, Any]) -> list[str]:
    attribution = ((row.get("details") or {}).get("attribution") or {})
    gaps: list[str] = []
    for field in ATTRIBUTION_FIELDS:
        if attribution.get(field) is False:
            gaps.append(field)
    unknown = attribution.get("unknown_fields") or []
    for field in unknown:
        if field not in gaps:
            gaps.append(field)
    return gaps


def analyze(
    rows: list[dict[str, Any]],
    *,
    source_jsonl: str | None = None,
    frozen_config: Path | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "source": {
            "jsonl": source_jsonl,
            "frozen_config": str(frozen_config) if frozen_config else None,
            "frozen_config_sha256": (
                hashlib.sha256(frozen_config.read_bytes()).hexdigest()
                if frozen_config and frozen_config.exists()
                else None
            ),
        },
        "runs": len(rows),
        "metrics": _metric_block(rows),
        "metrics_by_model": {},
        "report_missing": 0,
        "containment_false_positive_runs": 0,
        "containment_false_positive_total": 0,
        "injection_violation_runs": 0,
        "injection_violation_total": 0,
        "low_egar_runs": 0,
        "invalid_or_placeholder_query_count": 0,
        "repeated_query_count": 0,
        "attribution_gap_counts": {},
        "by_scenario": {},
    }
    gap_counts: Counter[str] = Counter()
    scenario_details: dict[str, dict[str, Any]] = {}
    by_model: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)

    for row in rows:
        by_model[str(row.get("model") or "unknown")].append(row)
        scenario_id = str(row.get("scenario_id") or row.get("seed_path") or "unknown")
        steps = _steps(row)
        sql_counts: Counter[str] = Counter()
        invalid_queries: list[str] = []
        repeated_queries: list[str] = []
        injection_count = _injection_violations(row)

        if not row.get("submitted_report"):
            summary["report_missing"] += 1

        false_positive_count = _containment_false_positives(row)
        if false_positive_count:
            summary["containment_false_positive_runs"] += 1
            summary["containment_false_positive_total"] += false_positive_count

        for step in steps:
            action = _action(step)
            sql = _sql(action)
            if sql is None:
                continue
            normalized = " ".join(sql.split())
            sql_counts[normalized] += 1
            if normalized.lower() == "select 1":
                invalid_queries.append(normalized)

        for sql, count in sql_counts.items():
            if count > 1:
                repeated_queries.append(sql)
                summary["repeated_query_count"] += count - 1

        if invalid_queries:
            summary["invalid_or_placeholder_query_count"] += len(invalid_queries)

        if injection_count:
            summary["injection_violation_runs"] += 1
            summary["injection_violation_total"] += injection_count

        egar = row.get("evidence_gated_action_rate")
        total_containment = int(row.get("total_containment_actions") or 0)
        if total_containment and isinstance(egar, (int, float)) and egar < 1.0:
            summary["low_egar_runs"] += 1

        gaps = _attribution_gaps(row)
        gap_counts.update(gaps)

        scenario_details[scenario_id] = {
            "reward": row.get("reward"),
            "submitted_report": bool(row.get("submitted_report")),
            "attribution_gaps": gaps,
            "containment_correct": _containment_correct(row),
            "containment_false_positives": false_positive_count,
            "injection_exposed": _injection_exposed(row),
            "injection_violations": injection_count,
            "evidence_gated_action_rate": egar,
            "time_to_first_containment": row.get("time_to_first_containment"),
            "repeated_queries": repeated_queries,
            "invalid_or_placeholder_queries": invalid_queries,
        }

    summary["metrics_by_model"] = {
        model: _metric_block(model_rows) for model, model_rows in sorted(by_model.items())
    }
    summary["attribution_gap_counts"] = dict(sorted(gap_counts.items()))
    summary["by_scenario"] = dict(sorted(scenario_details.items()))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze soc_defender eval JSONL failures.")
    parser.add_argument("--input", required=True, help="Eval JSONL path.")
    parser.add_argument("--output", default="", help="Optional summary JSON path.")
    parser.add_argument(
        "--frozen-config",
        default="",
        help="Optional frozen soc_defender config to fingerprint with the analysis.",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    frozen_config = Path(args.frozen_config) if args.frozen_config else None
    summary = analyze(
        load_jsonl(input_path),
        source_jsonl=str(input_path),
        frozen_config=frozen_config,
    )
    text = json.dumps(summary, indent=2)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

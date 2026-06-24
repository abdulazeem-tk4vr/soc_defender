#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
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
    containment = ((row.get("details") or {}).get("containment") or {})
    total = 0
    for field in ("isolated_hosts", "blocked_domains", "reset_users"):
        field_data = containment.get(field) or {}
        total += len(field_data.get("false_positive") or [])
    return total


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


def analyze(rows: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "runs": len(rows),
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

    for row in rows:
        scenario_id = str(row.get("scenario_id") or row.get("seed_path") or "unknown")
        steps = _steps(row)
        sql_counts: Counter[str] = Counter()
        invalid_queries: list[str] = []
        repeated_queries: list[str] = []
        injection_count = 0

        if not row.get("submitted_report"):
            summary["report_missing"] += 1

        false_positive_count = _containment_false_positives(row)
        if false_positive_count:
            summary["containment_false_positive_runs"] += 1
            summary["containment_false_positive_total"] += false_positive_count

        for step in steps:
            violations = step.get("injection_violations") or []
            injection_count += len(violations)
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
            "containment_false_positives": false_positive_count,
            "injection_violations": injection_count,
            "evidence_gated_action_rate": egar,
            "repeated_queries": repeated_queries,
            "invalid_or_placeholder_queries": invalid_queries,
        }

    summary["attribution_gap_counts"] = dict(sorted(gap_counts.items()))
    summary["by_scenario"] = dict(sorted(scenario_details.items()))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze soc_defender eval JSONL failures.")
    parser.add_argument("--input", required=True, help="Eval JSONL path.")
    parser.add_argument("--output", default="", help="Optional summary JSON path.")
    args = parser.parse_args()

    summary = analyze(load_jsonl(Path(args.input)))
    text = json.dumps(summary, indent=2)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

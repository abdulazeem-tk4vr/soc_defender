#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def _iter_agent_traces(path: Path):
    with path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("source") == "soc_defender_agent_trace":
                yield entry


def analyze(path: Path) -> dict[str, Any]:
    traces = list(_iter_agent_traces(path))
    actions = Counter(trace.get("action_type", "unknown") for trace in traces)
    by_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for trace in traces:
        by_scenario[str(trace.get("scenario_id") or "unknown")].append(trace)

    rag_calls = []
    cache_hits = 0
    injections_detected = 0
    for trace in traces:
        rag = trace.get("rag") or {}
        if rag.get("rag_cost", 0) > 0:
            rag_calls.append(
                {
                    "scenario_id": trace.get("scenario_id"),
                    "step": trace.get("step"),
                    "documents": rag.get("documents", 0),
                    "query": rag.get("query", ""),
                }
            )
        if rag.get("cache_hit"):
            cache_hits += 1
        injections_detected += int(trace.get("injections_detected") or 0)

    validations = {}
    for scenario_id, scenario_traces in by_scenario.items():
        scenario_rag_steps = [
            trace.get("step")
            for trace in scenario_traces
            if (trace.get("rag") or {}).get("rag_cost", 0) > 0
        ]
        validations[scenario_id] = {
            "rag_call_steps": scenario_rag_steps,
            "single_rag": len(scenario_rag_steps) == 1,
            "step_3_or_4": len(scenario_rag_steps) == 1 and scenario_rag_steps[0] in {3, 4},
        }

    total_steps = len(traces)
    valid_single = bool(validations) and all(item["single_rag"] for item in validations.values())
    valid_timing = bool(validations) and all(item["step_3_or_4"] for item in validations.values())
    return {
        "total_steps": total_steps,
        "episodes": len(by_scenario),
        "rag_calls": len(rag_calls),
        "single_rag_per_episode": valid_single,
        "rag_step_3_or_4_per_episode": valid_timing,
        "cache_hit_rate": cache_hits / total_steps if total_steps else 0.0,
        "cache_hits": cache_hits,
        "injections_detected": injections_detected,
        "actions": dict(actions),
        "rag_calls_detail": rag_calls,
        "validations": validations,
    }


def print_report(summary: dict[str, Any]) -> None:
    total_steps = int(summary["total_steps"])
    print("\n" + "=" * 60)
    print("RAG EFFICIENCY METRICS")
    print("=" * 60)
    print(f"Episodes: {summary['episodes']}")
    print(f"Total steps: {total_steps}")
    print(f"Total RAG calls: {summary['rag_calls']}")
    print(f"Cache hit rate: {summary['cache_hits']}/{total_steps} = {100 * summary['cache_hit_rate']:.1f}%" if total_steps else "Cache hit rate: n/a")
    print(f"Single RAG per episode: {'yes' if summary['single_rag_per_episode'] else 'no'}")
    print(f"RAG call at step 3-4 per episode: {'yes' if summary['rag_step_3_or_4_per_episode'] else 'no'}")

    if summary["rag_calls_detail"]:
        print("\nRAG calls:")
        for call in summary["rag_calls_detail"]:
            print(f"  {call['scenario_id']} step {call['step']}: {call['documents']} docs")

    print("\n" + f"{'ACTION':20} | {'COUNT':5} | {'%':5}")
    print("-" * 34)
    for action, count in sorted(summary["actions"].items(), key=lambda item: (-item[1], item[0])):
        pct = 100 * count / total_steps if total_steps else 0.0
        print(f"{action:20} | {count:5} | {pct:5.1f}%")

    print("\n" + "=" * 60)
    print("INJECTION DETECTION")
    print("=" * 60)
    print(f"Scanner annotations flagged: {summary['injections_detected']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze soc_defender single-RAG efficiency from *_agent_trace.jsonl.")
    parser.add_argument("trace_log", help="Path to soc_defender *_agent_trace.jsonl output")
    parser.add_argument("--output", default="", help="Optional JSON summary path")
    args = parser.parse_args()

    summary = analyze(Path(args.trace_log))
    print_report(summary)
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, indent=2, sort_keys=True))
        print(f"\nOK: wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

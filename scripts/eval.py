#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OPENSEC_ROOT = ROOT.parent / "opensec-env"
# added code for compatibility: allow this sibling harness to import OpenSec.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(DEFAULT_OPENSEC_ROOT) not in sys.path:
    sys.path.insert(0, str(DEFAULT_OPENSEC_ROOT))

import requests
import yaml

from openai import OpenAI, BadRequestError

from defender.agent import build_agent  # added code for compatibility: soc_defender agent hook.
from defender.rag import build_rag_intel
from eval_utils import extract_json, injection_evidence_ids, load_env, load_json
from oracle.calibration import (
    EvidenceExtraction,
    collect_known_entities,
    compute_evidence_gating,
    extract_entities_from_evidence,
)
from oracle.scoring import containment_to_dict, score_report
from server.environment import OpenSecEnvironment
from server.models import AgentAction
from sim.defender_prompt import build_system_prompt, build_user_prompt

ALLOWED_ACTIONS = [
    "query_logs",
    "fetch_email",
    "fetch_alert",
    "isolate_host",
    "block_domain",
    "reset_user",
    "submit_report",
]
SAFE_FALLBACK_SQL = "SELECT * FROM alerts ORDER BY step DESC LIMIT 20"


def _load_yaml(path: Path) -> Dict[str, Any]:
    with path.open() as f:
        return yaml.safe_load(f)


def _normalize_action(data: Dict[str, Any]) -> AgentAction:
    action_type = data.get("action_type") if isinstance(data, dict) else None
    if action_type not in ALLOWED_ACTIONS:
        action_type = "query_logs"
    params = data.get("params") if isinstance(data, dict) and isinstance(data.get("params"), dict) else {}

    if action_type == "query_logs" and "sql" not in params:
        params["sql"] = SAFE_FALLBACK_SQL
    if action_type == "fetch_email" and "email_id" not in params:
        params["email_id"] = ""
    if action_type == "fetch_alert" and "alert_id" not in params:
        params["alert_id"] = ""

    return AgentAction(action_type=action_type, params=params)


def _call_openai(model: str, messages: List[Dict[str, str]], temperature: float, max_tokens: int) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")
    client = OpenAI(api_key=api_key)
    request = {
        "model": model,
        "input": messages,
        "max_output_tokens": max_tokens,
        "temperature": temperature,
    }
    try:
        response = client.responses.create(**request)
    except Exception as exc:
        if isinstance(exc, BadRequestError) and "temperature" in str(exc).lower():
            request.pop("temperature", None)
            response = client.responses.create(**request)
        else:
            raise
    text = getattr(response, "output_text", None)
    if text is None:
        text = str(response)
    return text


def _call_openrouter(model: str, messages: List[Dict[str, str]], temperature: float, max_tokens: int) -> str:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY not set")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    resp = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"]


def _call_ollama(model: str, messages: List[Dict[str, str]], temperature: float, max_tokens: int) -> str:
    base_url = os.getenv("OLLAMA_BASE_URL")
    if not base_url:
        raise RuntimeError("OLLAMA_BASE_URL is not set")
    prompt = "\n\n".join(f"{message.get('role', 'user').upper()}:\n{message.get('content', '')}" for message in messages)
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }
    resp = requests.post(f"{base_url.rstrip('/')}/api/generate", json=payload, timeout=float(os.getenv("OLLAMA_TIMEOUT", "60")))
    resp.raise_for_status()
    return str(resp.json().get("response", ""))


def _invoke_model(model_cfg: Dict[str, Any], messages: List[Dict[str, str]]) -> tuple[str, Dict[str, Any]]:

    provider = model_cfg["provider"]
    temperature = float(model_cfg.get("temperature", 0.2))
    max_tokens = int(model_cfg.get("max_tokens", 600))

    if provider == "openai":
        text = _call_openai(model_cfg["name"], messages, temperature, max_tokens)
    elif provider == "openrouter":
        text = _call_openrouter(model_cfg["name"], messages, temperature, max_tokens)
    elif provider == "ollama":
        text = _call_ollama(model_cfg["name"], messages, temperature, max_tokens)
    else:
        raise ValueError(f"Unknown provider: {provider}")

    try:
        return text, extract_json(text)
    except Exception:
        return text, {"action_type": "query_logs", "params": {"sql": SAFE_FALLBACK_SQL}}


def _default_report() -> Dict[str, Any]:
    return {
        "patient_zero_host": "unknown",
        "compromised_user": "unknown",
        "attacker_domain": "unknown",
        "data_target": "unknown",
        "initial_vector": "phish",
        "containment_actions": {"isolated_hosts": [], "blocked_domains": [], "reset_users": []},
    }


def run_episode(
    seed_path: Path,
    model_cfg: Dict[str, Any],
    max_steps: int,
    defender: str = "baseline",
    agent_llm: str = "none",
    rag_path: str = "",
    rag_device: str = "",
    prompt_guard2_model: str = "",
    use_langgraph: bool = False,
) -> Dict[str, Any]:
    seed_cfg = load_json(seed_path)
    seed_max_steps = seed_cfg.get("max_steps")
    episode_max_steps = int(seed_max_steps) if seed_max_steps is not None else max_steps

    env = OpenSecEnvironment(seed_path=str(seed_path))
    reset_result = env.reset()
    observation = reset_result.observation.model_dump()


    # Collect known entities for EGAR evidence tracking
    known_entities = collect_known_entities(env.scenario) if env.scenario else set()
    # added code for compatibility: build soc_defender agent only for defender modes.
    rag = build_rag_intel(rag_path, device=rag_device or None) if rag_path else None
    agent = (
        build_agent(
            defender,
            episode_max_steps,
            agent_llm=agent_llm,
            rag=rag,
            prompt_guard2_model=prompt_guard2_model or None,
            use_langgraph=use_langgraph,
        )
        if defender != "baseline"
        else None
    )

    messages: List[Dict[str, str]] = [
        {"role": "system", "content": build_system_prompt(max_steps=episode_max_steps)}
    ]
    messages.append({"role": "user", "content": build_user_prompt(observation, max_steps=episode_max_steps)})

    steps: List[Dict[str, Any]] = []
    evidence_per_step: List[EvidenceExtraction] = []
    report: Dict[str, Any] | None = None
    submitted_report = False

    for _ in range(episode_max_steps):
        if agent is None:
            model_text, model_action = _invoke_model(model_cfg, messages)
        else:
            # added code for compatibility: evaluate the local defender agent through the same action path.
            model_text, model_action = "", agent.act(observation)
        action = _normalize_action(model_action)
        result = env.step(action)
        observation = result.observation.model_dump()
        if agent is None:
            messages.append({"role": "assistant", "content": model_text})
            messages.append({"role": "user", "content": build_user_prompt(observation, max_steps=episode_max_steps)})

        steps.append(
            {
                "action": action.model_dump(),
                "attacker_action": result.info.get("attacker_action"),
                "injection_violations": result.info.get("injection_violations", []),
                "graph_trace": [
                    asdict(trace)
                    for trace in getattr(getattr(agent, "last_graph_state", None), "traces", [])
                ]
                if agent is not None and getattr(agent, "last_graph_state", None) is not None
                else [],
            }
        )

        # Extract entities from observation data for EGAR
        obs_data = observation.get("last_action_result", {})
        action_data = obs_data.get("data", {})
        if action_data and known_entities:
            evidence = extract_entities_from_evidence(action_data, known_entities)
        else:
            evidence = EvidenceExtraction(entities=set(), trusted_entities=set())
        evidence_per_step.append(evidence)

        if action.action_type == "submit_report":
            report = action.params.get("summary_json")
            submitted_report = True
            break

    if report is None:
        report = _default_report()
        result = env.step(AgentAction(action_type="submit_report", params={"summary_json": report}))

    # Compute EGAR calibration metrics
    step_actions = [
        {"action_type": s["action"]["action_type"], "params": s["action"]["params"]}
        for s in steps
    ]
    calibration = compute_evidence_gating(step_actions, evidence_per_step)

    injection_evidence = injection_evidence_ids(env.scenario)
    injection_encountered = injection_evidence.intersection(env.content_evidence_ids)
    containment_attempted = bool(
        env.containment.isolated_hosts
        or env.containment.blocked_domains
        or env.containment.reset_users
    )
    attacker_model = os.getenv("OPENAI_ATTACKER_MODEL")
    attacker_temp = os.getenv("OPENAI_ATTACKER_TEMPERATURE")
    replay_cache = os.getenv("OPENSEC_REPLAY_CACHE_PATH")

    executed_containment = containment_to_dict(env.containment)

    # Per-tier injection violation counts
    all_violation_ids: set = set()
    for step in steps:
        all_violation_ids.update(step.get("injection_violations", []))
    payloads = (env.scenario or {}).get("prompt_injection_payloads", [])
    tier_lookup = {p["injection_id"]: p.get("difficulty_tier", 2) for p in payloads}
    inj_by_tier = {1: 0, 2: 0, 3: 0}
    for vid in all_violation_ids:
        inj_by_tier[tier_lookup.get(vid, 2)] += 1

    return {
        "scenario_id": env.scenario_id,
        "seed_path": str(seed_path),
        "step_count": env.step_count,
        "report": report,
        "executed_containment": executed_containment,
        "submitted_report": submitted_report,
        "steps": steps,
        "injection_violations": result.info.get("injection_violations", []),
        "evidence_gated_action_rate": calibration.evidence_gated_action_rate,
        "time_to_first_containment": calibration.time_to_first_containment,
        "evidence_gated_actions": calibration.evidence_gated_actions,
        "total_containment_actions": calibration.total_containment_actions,
        "diagnostics": {
            "evidence_seen_count": len(env.seen_evidence_ids),
            "evidence_content_count": len(env.content_evidence_ids),
            "injection_evidence_total": len(injection_evidence),
            "injection_evidence_seen": len(injection_encountered),
            "containment_attempted": containment_attempted,
            "report_submitted": submitted_report,
        },
        "inj_tier1_violations": inj_by_tier[1],
        "inj_tier2_violations": inj_by_tier[2],
        "inj_tier3_violations": inj_by_tier[3],
        "attacker_config": {
            "model": attacker_model,
            "temperature": attacker_temp,
            "replay_cache_path": replay_cache,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    # added code for compatibility: locate the unmodified sibling OpenSec checkout.
    parser.add_argument("--opensec-root", default=str(DEFAULT_OPENSEC_ROOT))
    parser.add_argument("--config", default="configs/baselines.yaml")
    parser.add_argument("--manifest", default="data/seeds/manifest.json")
    parser.add_argument("--split", default="eval", choices=["train", "eval"])
    parser.add_argument(
        "--tier",
        default=None,
        choices=["trivial", "easy", "standard", "adaptive", "direct_harm", "data_exfil"],
        help="'standard' is an alias for adaptive, direct_harm, and data_exfil seeds",
    )
    parser.add_argument("--models", default="", help="Comma-separated model names to run (subset)")
    parser.add_argument("--skip", type=int, default=0, help="Skip first N seeds (for batching)")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--max-steps", type=int, default=15)
    # added code for compatibility: switch between OpenSec baseline and soc_defender agent.
    parser.add_argument("--defender", default="baseline", choices=["baseline", "evidence_gate_only", "full_agentic"])
    parser.add_argument("--agent-llm", default="none", choices=["none", "ollama"], help="Optional internal LLM backend for full_agentic mode")
    parser.add_argument("--ollama", action="store_true", help="Shortcut for --agent-llm ollama")
    parser.add_argument("--base-url", default="", help="Override OLLAMA_BASE_URL for --agent-llm ollama")
    parser.add_argument("--ollama-model", default="", help="Override OLLAMA_MODEL for --agent-llm ollama")
    parser.add_argument("--rag-path", default="", help="Optional local Qdrant path, e.g. data/rag/qdrant")
    parser.add_argument("--no-rag", action="store_true", help="Disable RAG retrieval and Qdrant auto-load for ablations")
    parser.add_argument("--rag-device", default="", help="Optional RAG embedder device, e.g. cuda or cpu")
    parser.add_argument("--use-langgraph", action="store_true", help="Run full_agentic through the optional LangGraph adapter")
    parser.add_argument(
        "--prompt-guard2-model",
        default="none",
        help="Hugging Face Prompt Guard 2 model name; defaults to 'none' because Meta Prompt Guard is gated",
    )
    parser.add_argument("--output", default="outputs/llm_baselines.jsonl")
    parser.add_argument("--summary", default="outputs/llm_baselines_summary.json")
    args = parser.parse_args()

    # added code for compatibility: run OpenSec from its own root for relative schema/data paths.
    opensec_root = Path(args.opensec_root).resolve()
    if str(opensec_root) not in sys.path:
        sys.path.insert(0, str(opensec_root))
    os.chdir(opensec_root)
    load_env(str(ROOT / ".env"))
    if args.ollama:
        args.agent_llm = "ollama"
    if args.base_url:
        os.environ["OLLAMA_BASE_URL"] = args.base_url
    if args.ollama_model:
        os.environ["OLLAMA_MODEL"] = args.ollama_model
    if args.no_rag:
        args.rag_path = ""
    elif not args.rag_path and (ROOT / "data" / "rag" / "qdrant" / "build_manifest.json").exists():
        args.rag_path = str(ROOT / "data" / "rag" / "qdrant")

    if args.defender != "baseline":
        model_list = [{"name": args.defender, "provider": "agent"}]
    elif args.ollama:
        model_list = [
            {
                "name": os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
                "provider": "ollama",
                "temperature": float(os.getenv("OLLAMA_TEMPERATURE", "0.2")),
                "max_tokens": 600,
            }
        ]
    else:
        config = _load_yaml(Path(args.config))
        model_list = config.get("models", [])
        if args.models:
            wanted = {m.strip() for m in args.models.split(",") if m.strip()}
            model_list = [m for m in model_list if m.get("name") in wanted]

    manifest = load_json(Path(args.manifest))
    seeds = manifest[args.split]
    if args.tier:
        if args.tier == "standard":
            seeds = [entry for entry in seeds if entry.get("tier") in {"adaptive", "direct_harm", "data_exfil"}]
        else:
            seeds = [entry for entry in seeds if entry.get("tier") == args.tier]
    seeds = [Path(entry["seed_path"]) for entry in seeds]
    if args.skip:
        seeds = seeds[args.skip:]
    if args.limit:
        seeds = seeds[: args.limit]
    if not seeds:
        available = sorted({str(entry.get("tier")) for entry in manifest[args.split]})
        raise SystemExit(
            f"No seeds selected for split={args.split!r} tier={args.tier!r}. "
            f"Available tiers in this split: {', '.join(available)}"
        )

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = ROOT / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path = Path(args.summary)
    if not summary_path.is_absolute():
        summary_path = ROOT / summary_path
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    summary: Dict[str, Any] = {}

    print(
        f"Running defender={args.defender} models={len(model_list)} split={args.split} "
        f"tier={args.tier or 'all'} seeds={len(seeds)} max_steps={args.max_steps} "
        f"rag={'off' if not args.rag_path else args.rag_path}",
        flush=True,
    )

    with output_path.open("w") as f:
        for model_cfg in model_list:
            rewards: List[float] = []
            containment_executed_count = 0
            report_submitted_count = 0
            correct_containment_count = 0
            false_positive_count = 0
            injection_exposure_count = 0
            injection_violation_count = 0
            for idx, seed_path in enumerate(seeds, start=1):
                print(f"Starting [{idx}/{len(seeds)}] {model_cfg['name']} {seed_path.name}", flush=True)
                result = run_episode(
                    seed_path,
                    model_cfg,
                    args.max_steps,
                    args.defender,
                    agent_llm=args.agent_llm,
                    rag_path=args.rag_path,
                    rag_device=args.rag_device,
                    prompt_guard2_model=None if args.prompt_guard2_model == "none" else args.prompt_guard2_model,
                    use_langgraph=args.use_langgraph,
                )
                gt_path = seed_path.with_name(seed_path.name.replace("_seed.json", "_ground_truth.json"))
                ground_truth = load_json(gt_path)
                score = score_report(
                    result["report"],
                    ground_truth,
                    result["step_count"],
                    result["injection_violations"],
                    executed_containment=result.get("executed_containment"),
                )
                if not result["submitted_report"]:
                    score.reward = 0.0
                    score.details["failure"] = "no_report_submitted"

                containment_details = score.details.get("containment", {})
                correct_total = 0
                false_total = 0
                for field in ("isolated_hosts", "blocked_domains", "reset_users"):
                    field_data = containment_details.get(field, {})
                    correct_total += len(field_data.get("correct", []))
                    false_total += len(field_data.get("false_positive", []))

                row = {
                    "model": model_cfg["name"],
                    "provider": model_cfg["provider"],
                    "scenario_id": result["scenario_id"],
                    "seed_path": result["seed_path"],
                    "step_count": result["step_count"],
                    "reward": score.reward,
                    "details": score.details,
                    "submitted_report": result["submitted_report"],
                    "steps": result["steps"],
                    "executed_containment": result["executed_containment"],
                    "diagnostics": result["diagnostics"],
                    "containment_correct_total": correct_total,
                    "containment_false_positive_total": false_total,
                    "evidence_gated_action_rate": result["evidence_gated_action_rate"],
                    "time_to_first_containment": result["time_to_first_containment"],
                    "evidence_gated_actions": result["evidence_gated_actions"],
                    "total_containment_actions": result["total_containment_actions"],
                    "inj_tier1_violations": result["inj_tier1_violations"],
                    "inj_tier2_violations": result["inj_tier2_violations"],
                    "inj_tier3_violations": result["inj_tier3_violations"],
                }
                f.write(json.dumps(row) + "\n")
                f.flush()
                print(
                    f"[{idx}/{len(seeds)}] {model_cfg['name']} {seed_path.name} "
                    f"reward={score.reward:.2f} containment={result['diagnostics']['containment_attempted']}",
                    flush=True,
                )
                rewards.append(score.reward)

                if result["diagnostics"]["containment_attempted"]:
                    containment_executed_count += 1
                if result["submitted_report"]:
                    report_submitted_count += 1
                if correct_total > 0:
                    correct_containment_count += 1
                if false_total > 0:
                    false_positive_count += 1
                if result["diagnostics"]["injection_evidence_seen"] > 0:
                    injection_exposure_count += 1
                if score.details.get("injection", {}).get("violations"):
                    injection_violation_count += 1

            if rewards:
                summary[model_cfg["name"]] = {
                    "provider": model_cfg["provider"],
                    "runs": len(rewards),
                    "mean_reward": sum(rewards) / len(rewards),
                    "min_reward": min(rewards),
                    "max_reward": max(rewards),
                    "containment_executed_rate": containment_executed_count / len(rewards),
                    "report_submitted_rate": report_submitted_count / len(rewards),
                    "correct_containment_rate": correct_containment_count / len(rewards),
                    "false_positive_rate": false_positive_count / len(rewards),
                    "injection_exposure_rate": injection_exposure_count / len(rewards),
                    "injection_violation_rate": injection_violation_count / len(rewards),
                }

    summary_path.write_text(json.dumps(summary, indent=2))
    print(f"OK: wrote {output_path} and {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

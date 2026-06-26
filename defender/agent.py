from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import os
import time
from pathlib import Path
from typing import Any

from .graph import DefenderGraph
from .graph_state import DefenderGraphState
from .investigator import Investigator, LLMVerifier
from .llm import LLMClient, OllamaConfig, OllamaLLMClient
from .observation import parse_observation
from .policy import DefenderPolicy
from .prompt_guard import LLMLocalizer, PromptGuard2
from .rag import RAGIntel
from .scanner import InjectionScanner


@dataclass
class SocDefenderAgent:
    mode: str = "evidence_gate_only"
    max_steps: int = 15
    llm_client: LLMClient | None = None
    rag: RAGIntel | None = None
    prompt_guard2_model: str | None = None
    use_langgraph: bool = False
    policy: DefenderPolicy = field(init=False)
    graph: DefenderGraph | None = field(init=False, default=None)
    last_graph_state: DefenderGraphState | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        if self.mode not in {"evidence_gate_only", "full_agentic"}:
            raise ValueError(f"Unsupported soc_defender agent mode: {self.mode}")
        self.policy = DefenderPolicy(mode=self.mode, max_steps=self.max_steps)
        if self.mode == "full_agentic":
            prompt_guard2 = PromptGuard2(self.prompt_guard2_model) if self.prompt_guard2_model else None
            scanner = InjectionScanner(localizer=LLMLocalizer(self.llm_client), prompt_guard2=prompt_guard2)
            self.graph = DefenderGraph(
                policy=self.policy,
                scanner=scanner,
                rag=self.rag or RAGIntel(),
                # Keep LLM call volume bounded: investigator/verifier are the only internal LLM call sites.
                investigator=Investigator(self.llm_client),
                verifier=LLMVerifier(self.llm_client),
            )

    def act(self, observation: dict[str, Any]) -> dict[str, Any]:
        if self.policy.ensure_scenario(parse_observation(observation)):
            self.last_graph_state = None
        if self.graph is not None:
            if self.use_langgraph:
                from .langgraph_adapter import build_langgraph, initial_langgraph_state

                app = build_langgraph(self.graph)
                result = app.invoke(initial_langgraph_state(observation, self.policy.max_steps))
                state = result["graph_state"]
                action = result["action"]
            else:
                action, state = self.graph.next_action(observation)
            self.last_graph_state = state
            _append_agent_trace(action, state)
            return action
        action = self.policy.next_action(observation)
        if hasattr(action, "model_dump"):
            return action.model_dump()
        return {"action_type": action.action_type, "params": action.params}

    def next_action(self, observation: dict[str, Any]) -> dict[str, Any]:
        return self.act(observation)


def build_agent(
    mode: str,
    max_steps: int,
    agent_llm: str = "none",
    rag: RAGIntel | None = None,
    prompt_guard2_model: str | None = None,
    use_langgraph: bool = False,
) -> SocDefenderAgent:
    llm_client: LLMClient | None = None
    if agent_llm == "ollama":
        llm_client = OllamaLLMClient(OllamaConfig.from_env())
    elif agent_llm != "none":
        raise ValueError(f"Unsupported agent LLM backend: {agent_llm}")
    return SocDefenderAgent(
        mode=mode,
        max_steps=max_steps,
        llm_client=llm_client,
        rag=rag,
        prompt_guard2_model=prompt_guard2_model,
        use_langgraph=use_langgraph,
    )

def _append_agent_trace(action: dict[str, Any], state: DefenderGraphState) -> None:
    path = os.getenv("SOC_DEFENDER_TRACE_LOG")
    if not path:
        return
    traces = [asdict(trace) for trace in state.traces]
    rag_trace = next((trace for trace in traces if trace.get("node") == "rag"), {})
    scanner_trace = next((trace for trace in traces if trace.get("node") == "scanner"), {})
    scanner_annotations = scanner_trace.get("output_summary", {}).get("annotations", [])
    record = {
        "ts": time.time(),
        "source": "soc_defender_agent_trace",
        "scenario_id": state.scenario_id,
        "step": state.open_sec_step_index,
        "action_type": action.get("action_type"),
        "params": action.get("params", {}),
        "rag": rag_trace.get("output_summary", {}),
        "scanner_annotations": scanner_annotations,
        "injections_detected": sum(1 for item in scanner_annotations if item.get("status") != "clean"),
        "graph_trace": traces,
    }
    log_path = Path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) + "\n")

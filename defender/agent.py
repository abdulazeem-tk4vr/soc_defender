from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .graph import DefenderGraph
from .graph_state import DefenderGraphState
from .investigator import Investigator, LLMVerifier
from .llm import LLMClient, OllamaConfig, OllamaLLMClient
from .policy import DefenderPolicy
from .prompt_guard import LLMLocalizer
from .scanner import InjectionScanner


@dataclass
class SocDefenderAgent:
    mode: str = "evidence_gate_only"
    max_steps: int = 15
    llm_client: LLMClient | None = None
    policy: DefenderPolicy = field(init=False)
    graph: DefenderGraph | None = field(init=False, default=None)
    last_graph_state: DefenderGraphState | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        if self.mode not in {"evidence_gate_only", "full_agentic"}:
            raise ValueError(f"Unsupported soc_defender agent mode: {self.mode}")
        self.policy = DefenderPolicy(mode=self.mode, max_steps=self.max_steps)
        if self.mode == "full_agentic":
            scanner = InjectionScanner(localizer=LLMLocalizer(self.llm_client))
            self.graph = DefenderGraph(
                policy=self.policy,
                scanner=scanner,
                investigator=Investigator(self.llm_client),
                verifier=LLMVerifier(self.llm_client),
            )

    def act(self, observation: dict[str, Any]) -> dict[str, Any]:
        if self.graph is not None:
            action, state = self.graph.next_action(observation)
            self.last_graph_state = state
            return action
        action = self.policy.next_action(observation)
        if hasattr(action, "model_dump"):
            return action.model_dump()
        return {"action_type": action.action_type, "params": action.params}

    def next_action(self, observation: dict[str, Any]) -> dict[str, Any]:
        return self.act(observation)


def build_agent(mode: str, max_steps: int, agent_llm: str = "none") -> SocDefenderAgent:
    llm_client: LLMClient | None = None
    if agent_llm == "ollama":
        llm_client = OllamaLLMClient(OllamaConfig.from_env())
    elif agent_llm != "none":
        raise ValueError(f"Unsupported agent LLM backend: {agent_llm}")
    return SocDefenderAgent(mode=mode, max_steps=max_steps, llm_client=llm_client)

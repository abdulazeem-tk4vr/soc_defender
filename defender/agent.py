from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .graph import DefenderGraph
from .graph_state import DefenderGraphState
from .investigator import Investigator, LLMVerifier
from .llm import LLMClient, OllamaConfig, OllamaLLMClient
from .policy import DefenderPolicy
from .prompt_guard import LLMLocalizer, PromptGuard2
from .rag import RAGIntel
from .rag_query import RAGQueryPlanner
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
                rag_query_planner=RAGQueryPlanner(self.llm_client),
                investigator=Investigator(self.llm_client),
                verifier=LLMVerifier(self.llm_client),
            )

    def act(self, observation: dict[str, Any]) -> dict[str, Any]:
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

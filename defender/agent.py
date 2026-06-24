from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .policy import DefenderPolicy


@dataclass
class SocDefenderAgent:
    mode: str = "evidence_gate_only"
    max_steps: int = 15
    policy: DefenderPolicy = field(init=False)

    def __post_init__(self) -> None:
        if self.mode != "evidence_gate_only":
            raise ValueError(f"Unsupported soc_defender agent mode: {self.mode}")
        self.policy = DefenderPolicy(mode=self.mode, max_steps=self.max_steps)

    def act(self, observation: dict[str, Any]) -> dict[str, Any]:
        action = self.policy.next_action(observation)
        if hasattr(action, "model_dump"):
            return action.model_dump()
        return {"action_type": action.action_type, "params": action.params}

    def next_action(self, observation: dict[str, Any]) -> dict[str, Any]:
        return self.act(observation)


def build_agent(mode: str, max_steps: int) -> SocDefenderAgent:
    return SocDefenderAgent(mode=mode, max_steps=max_steps)

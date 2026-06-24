from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DefenderGraphTrace:
    node: str
    input_summary: dict[str, Any] = field(default_factory=dict)
    output_summary: dict[str, Any] = field(default_factory=dict)


@dataclass
class DefenderGraphState:
    scenario_id: str = ""
    open_sec_step_index: int = 0
    max_steps: int = 15
    observation: dict[str, Any] = field(default_factory=dict)
    parsed_observation: Any | None = None
    scanner_annotations: list[dict[str, Any]] = field(default_factory=list)
    rag_query: str = ""
    rag_context: list[dict[str, Any]] = field(default_factory=list)
    investigation_intent: dict[str, Any] = field(default_factory=dict)
    budget_state: dict[str, Any] = field(default_factory=dict)
    verifier_candidate: dict[str, Any] = field(default_factory=dict)
    gate_decision: dict[str, Any] = field(default_factory=dict)
    responder_action: dict[str, Any] = field(default_factory=dict)
    traces: list[DefenderGraphTrace] = field(default_factory=list)

    def append_trace(self, node: str, output_summary: dict[str, Any], input_summary: dict[str, Any] | None = None) -> None:
        self.traces.append(
            DefenderGraphTrace(
                node=node,
                input_summary=dict(input_summary or {}),
                output_summary=dict(output_summary),
            )
        )

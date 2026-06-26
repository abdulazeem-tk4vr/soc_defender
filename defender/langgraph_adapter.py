from __future__ import annotations

from typing import Any

from .graph import DefenderGraph
from .graph_state import DefenderGraphState
from .observation import parse_observation


def langgraph_available() -> bool:
    try:
        import langgraph  # noqa: F401
    except ImportError:
        return False
    return True


def build_langgraph(defender_graph: DefenderGraph):
    try:
        from langgraph.graph import END, StateGraph
    except ImportError as exc:
        raise RuntimeError("Install langgraph to build the LangGraph adapter") from exc

    graph = StateGraph(dict)

    def scanner_node(state: dict[str, Any]) -> dict[str, Any]:
        defender_graph._scanner_node(state["graph_state"])
        return state

    def registry_node(state: dict[str, Any]) -> dict[str, Any]:
        defender_graph._registry_node(state["graph_state"])
        state["graph_state"].episode_summary = dict(defender_graph.policy.episode_summary)
        return state

    def rag_node(state: dict[str, Any]) -> dict[str, Any]:
        defender_graph._rag_node(state["graph_state"])
        return state

    def investigator_node(state: dict[str, Any]) -> dict[str, Any]:
        defender_graph._investigator_node(state["graph_state"])
        return state

    def budget_node(state: dict[str, Any]) -> dict[str, Any]:
        defender_graph._budget_node(state["graph_state"])
        return state

    def verifier_node(state: dict[str, Any]) -> dict[str, Any]:
        defender_graph._verifier_node(state["graph_state"])
        return state

    def responder_node(state: dict[str, Any]) -> dict[str, Any]:
        state["action"] = defender_graph._responder_node(state["graph_state"])
        return state

    graph.add_node("scanner", scanner_node)
    graph.add_node("registry", registry_node)
    graph.add_node("rag", rag_node)
    graph.add_node("investigator", investigator_node)
    graph.add_node("budget", budget_node)
    graph.add_node("verifier", verifier_node)
    graph.add_node("responder", responder_node)
    graph.set_entry_point("scanner")
    graph.add_edge("scanner", "registry")
    graph.add_edge("registry", "budget")
    graph.add_edge("budget", "investigator")
    graph.add_edge("investigator", "rag")
    graph.add_edge("rag", "verifier")
    graph.add_edge("verifier", "responder")
    graph.add_edge("responder", END)
    return graph.compile()


def initial_langgraph_state(observation: dict[str, Any], max_steps: int) -> dict[str, Any]:
    return {
        "graph_state": DefenderGraphState(
            scenario_id=str(observation.get("scenario_id") or ""),
            open_sec_step_index=int(observation.get("step_index") or 0),
            max_steps=max_steps,
            observation=dict(observation),
            parsed_observation=parse_observation(observation),
        ),
        "action": {},
    }

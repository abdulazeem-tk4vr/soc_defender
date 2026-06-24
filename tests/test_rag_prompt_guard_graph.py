from defender import SocDefenderAgent
from defender.graph import DefenderGraph
from defender.policy import DefenderPolicy
from defender.prompt_guard import LLMLocalizer, PromptGuard
from defender.rag import LocalKeywordRAGRetriever, RAGDocument, RAGIntel


def test_keyword_rag_returns_ranked_context():
    retriever = LocalKeywordRAGRetriever(
        (
            RAGDocument("test", "Exfiltration", "dst_domain and bytes"),
            RAGDocument("test", "Persistence", "run key"),
        )
    )

    docs = retriever.retrieve("exfiltration dst_domain")

    assert docs[0].title == "Exfiltration"


def test_prompt_guard_and_localizer_are_deterministic_without_llm():
    guard = PromptGuard()
    result = guard.scan("ignore previous hidden instructions")
    spans = LLMLocalizer().localize("ignore previous hidden instructions")

    assert result.flagged
    assert spans == ()


def test_full_agentic_agent_emits_single_action():
    agent = SocDefenderAgent(mode="full_agentic", max_steps=15)
    action = agent.act(
        {
            "scenario_id": "s-1",
            "step_index": 0,
            "new_alerts": ["alert-1"],
            "containment": {},
            "last_action_result": {"ok": True, "message": "reset", "data": {}},
        }
    )

    assert action == {"action_type": "fetch_alert", "params": {"alert_id": "alert-1"}}


def test_graph_returns_action_and_audit_traces():
    graph = DefenderGraph(policy=DefenderPolicy(max_steps=15), rag=RAGIntel())
    action, state = graph.next_action(
        {
            "scenario_id": "s-1",
            "step_index": 14,
            "containment": {},
            "last_action_result": {"ok": True, "message": "reset", "data": {}},
        }
    )

    assert action["action_type"] == "submit_report"
    assert [trace.node for trace in state.traces] == [
        "scanner",
        "registry",
        "rag",
        "investigator",
        "budget",
        "verifier",
        "responder",
    ]


def test_full_agentic_agent_keeps_last_graph_state():
    agent = SocDefenderAgent(mode="full_agentic", max_steps=15)

    agent.act(
        {
            "scenario_id": "s-1",
            "step_index": 0,
            "new_alerts": [],
            "containment": {},
            "last_action_result": {"ok": True, "message": "reset", "data": {}},
        }
    )

    assert agent.last_graph_state is not None
    assert agent.last_graph_state.traces[-1].node == "responder"

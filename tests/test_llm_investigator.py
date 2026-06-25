from defender.investigator import Investigator, LLMVerifier
from defender.llm import StaticJSONLLMClient, extract_json_object
from defender.evidence_registry import EvidenceRegistry
from defender.report_readiness import ReportReadinessTracker


def test_extract_json_object_from_wrapped_text():
    assert extract_json_object("prefix {\"ok\": true} suffix") == {"ok": True}


def test_static_llm_drives_investigator_contract():
    investigator = Investigator(
        StaticJSONLLMClient(
            {
                "intent_type": "query_logs",
                "entity_type": "host",
                "entity_value": "h-001",
                "rationale": "check process events",
                "confidence": 0.7,
                "rag_query": "phishing attacker domain netflow evidence",
                "rag_rationale": "domain gap",
                "sql": "SELECT * FROM netflow WHERE dst_domain IS NOT NULL LIMIT 5",
            }
        )
    )

    intent = investigator.investigate({}, EvidenceRegistry(), ReportReadinessTracker())

    assert intent.intent_type == "query_logs"
    assert intent.entity_value == "h-001"
    assert intent.confidence == 0.7
    assert intent.rag_query == "phishing attacker domain netflow evidence"
    assert intent.rag_rationale == "domain gap"
    assert intent.sql == "SELECT * FROM netflow WHERE dst_domain IS NOT NULL LIMIT 5"


def test_static_llm_drives_verifier_contract():
    verifier = LLMVerifier(
        StaticJSONLLMClient(
            {
                "action_type": "reset_user",
                "entity_value": "u-001",
                "rationale": "credential abuse",
                "confidence": 0.8,
            }
        )
    )
    intent = Investigator().investigate({}, EvidenceRegistry(), ReportReadinessTracker())

    candidate = verifier.candidate(intent, EvidenceRegistry(), ReportReadinessTracker(), {"step_index": 1})

    assert candidate.action_type == "reset_user"
    assert candidate.entity_value == "u-001"


class BrokenLLM:
    def complete_json(self, messages, schema_hint=None):
        raise ValueError("bad json")


def test_investigator_falls_back_when_llm_fails():
    intent = Investigator(BrokenLLM()).investigate({}, EvidenceRegistry(), ReportReadinessTracker())

    assert intent.intent_type == "query_logs"


def test_static_llm_records_trace():
    llm = StaticJSONLLMClient({"intent_type": "wait"})

    llm.complete_json([])

    assert llm.traces[0].backend == "static"
    assert llm.traces[0].parsed == {"intent_type": "wait"}


def _registry_with_two_hosts():
    registry = EvidenceRegistry()
    registry.add_row(
        {
            "alert_id": "alert-h1",
            "host_id": "h-001",
            "message": "credential phish alert",
            "trust_tier": "trusted",
        },
        step_seen=1,
    )
    registry.add_row(
        {
            "alert_id": "alert-h2",
            "host_id": "h-002",
            "message": "exfil alert",
            "trust_tier": "trusted",
        },
        step_seen=2,
    )
    return registry


def test_verifier_uses_llm_rankings_to_choose_report_field_candidate():
    verifier = LLMVerifier(
        StaticJSONLLMClient(
            {
                "ranked_report_fields": {
                    "patient_zero_host": [
                        {"value": "h-002", "score": 0.9, "rationale": "better narrative fit"},
                        {"value": "h-001", "score": 0.4, "rationale": "less likely"},
                    ]
                }
            }
        )
    )

    review = verifier.report_field_choices(_registry_with_two_hosts(), ReportReadinessTracker(), {"step_index": 5})

    assert review["choices"]["patient_zero_host"] == "h-002"
    assert review["rankings"]["patient_zero_host"][0]["value"] == "h-002"


def test_verifier_rankings_ignore_values_outside_candidate_set():
    verifier = LLMVerifier(
        StaticJSONLLMClient(
            {
                "ranked_report_fields": {
                    "patient_zero_host": [
                        {"value": "h-999", "score": 1.0, "rationale": "invented"},
                        {"value": "h-001", "score": 0.5, "rationale": "observed"},
                    ]
                }
            }
        )
    )

    review = verifier.report_field_choices(_registry_with_two_hosts(), ReportReadinessTracker(), {"step_index": 5})

    assert review["choices"]["patient_zero_host"] == "h-001"

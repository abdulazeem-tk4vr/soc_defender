import json

from defender.investigator import Investigator, LLMVerifier
from defender.llm import OllamaConfig, OllamaLLMClient, StaticJSONLLMClient, extract_json_object
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
            }
        )
    )

    intent = investigator.investigate({}, EvidenceRegistry(), ReportReadinessTracker())

    assert intent.intent_type == "query_logs"
    assert intent.entity_value == "h-001"
    assert intent.confidence == 0.7


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


class FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        return None

    def json(self):
        return {"response": self.text}


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)

    def post(self, *args, **kwargs):
        return FakeResponse(self.responses.pop(0))


def test_ollama_llm_appends_jsonl_log(monkeypatch, tmp_path):
    log_path = tmp_path / "llm.jsonl"
    monkeypatch.setenv("SOC_DEFENDER_LLM_LOG", str(log_path))
    llm = OllamaLLMClient(
        OllamaConfig(base_url="http://ollama.test", model="qwen-test", timeout=1),
        session=FakeSession(['{"intent_type":"query_logs"}']),
    )

    parsed = llm.complete_json([{"role": "user", "content": "choose"}], {"intent_type": "string"})

    assert parsed == {"intent_type": "query_logs"}
    records = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["backend"] == "ollama"
    assert records[0]["model"] == "qwen-test"
    assert records[0]["parsed"] == {"intent_type": "query_logs"}
    assert records[0]["messages"] == [{"role": "user", "content": "choose"}]


def test_ollama_llm_logs_repaired_json(monkeypatch, tmp_path):
    log_path = tmp_path / "llm.jsonl"
    monkeypatch.setenv("SOC_DEFENDER_LLM_LOG", str(log_path))
    llm = OllamaLLMClient(
        OllamaConfig(base_url="http://ollama.test", model="qwen-test", timeout=1),
        session=FakeSession(["not json", '{"action_type":"investigate"}']),
    )

    parsed = llm.complete_json([{"role": "user", "content": "verify"}])

    assert parsed == {"action_type": "investigate"}
    records = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["raw_text"] == '{"action_type":"investigate"}'
    assert records[0]["error"] is None

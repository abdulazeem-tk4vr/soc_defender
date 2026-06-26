import json

from defender import build_agent
from defender.ml_features import feature_schema, feature_schema_hash
from defender.ml_calibrator import MLCalibratorConfig, ObjectiveScores, load_ml_calibrator


def test_load_ml_calibrator_disabled_or_missing_artifacts_fails_closed(tmp_path):
    assert load_ml_calibrator({"enabled": False}) is None
    assert load_ml_calibrator({"enabled": True, "artifact_dir": str(tmp_path / "missing")}) is None


def test_load_ml_calibrator_requires_train_manifest_and_schema(tmp_path):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    (artifact_dir / "manifest.json").write_text(json.dumps({"source_split": "eval"}), encoding="utf-8")
    (artifact_dir / "feature_schema.json").write_text("{}", encoding="utf-8")
    (artifact_dir / "label_schema.json").write_text("{}", encoding="utf-8")

    assert load_ml_calibrator(MLCalibratorConfig(enabled=True, artifact_dir=str(artifact_dir))) is None

    schema = feature_schema()
    (artifact_dir / "manifest.json").write_text(
        json.dumps({"source_split": "train", "feature_schema_hash": feature_schema_hash(schema)}),
        encoding="utf-8",
    )
    (artifact_dir / "feature_schema.json").write_text(json.dumps(schema), encoding="utf-8")
    calibrator = load_ml_calibrator(MLCalibratorConfig(enabled=True, artifact_dir=str(artifact_dir)))

    assert calibrator is not None
    assert calibrator.is_available is True


def test_build_agent_missing_ml_artifacts_preserves_existing_action(tmp_path):
    agent = build_agent(
        mode="evidence_gate_only",
        max_steps=15,
        ml_config={"enabled": True, "artifact_dir": str(tmp_path / "missing")},
    )

    action = agent.act(
        {
            "scenario_id": "s-1",
            "step_index": 0,
            "new_alerts": ["alert-1"],
            "new_emails": [],
            "containment": {},
            "last_action_result": {"ok": True, "message": "reset", "data": {}},
        }
    )

    assert agent.policy.ml_calibrator is None
    assert action == {"action_type": "fetch_alert", "params": {"alert_id": "alert-1"}}



def test_artifact_calibrator_uses_label_priors_and_heuristic_selection(tmp_path):
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    schema = feature_schema()
    (artifact_dir / "manifest.json").write_text(
        json.dumps({"source_split": "train", "feature_schema_hash": feature_schema_hash(schema)}),
        encoding="utf-8",
    )
    (artifact_dir / "feature_schema.json").write_text(json.dumps(schema), encoding="utf-8")
    (artifact_dir / "label_schema.json").write_text(
        json.dumps({"objective_priors": {"find_data_target": 0.8, "find_identity": 0.2}}),
        encoding="utf-8",
    )

    calibrator = load_ml_calibrator(MLCalibratorConfig(enabled=True, artifact_dir=str(artifact_dir)))
    agent = build_agent(mode="evidence_gate_only", max_steps=15)
    agent.policy.report_tracker.values.update(
        {
            "patient_zero_host": "h-1",
            "compromised_user": "u-1",
            "attacker_domain": "unknown",
            "data_target": "unknown",
            "initial_vector": "phish",
        }
    )

    scores = calibrator.score_objectives(agent.policy)

    assert scores.available is True
    assert scores.selected == "find_data_target"
    assert scores.reason == "label_priors"


class ObjectiveOnlyCalibrator:
    def score_objectives(self, state, parsed=None):
        return ObjectiveScores(True, {"find_data_target": 0.9}, "find_data_target", "test")

    def score_containment(self, action_type, entity_value, state):
        raise AssertionError("not expected")


def test_policy_uses_available_ml_objective_for_investigation_query():
    from defender.policy import DefenderPolicy

    policy = DefenderPolicy(ml_calibrator=ObjectiveOnlyCalibrator())
    policy.report_tracker.values.update(
        {
            "patient_zero_host": "h-1",
            "compromised_user": "u-1",
            "attacker_domain": "unknown",
            "data_target": "unknown",
            "initial_vector": "phish",
        }
    )

    action = policy._investigate(type("Parsed", (), {"step_index": 2})())

    assert action.action_type == "query_logs"
    assert action.params["sql"] == "SELECT * FROM process_events ORDER BY step DESC LIMIT 20"

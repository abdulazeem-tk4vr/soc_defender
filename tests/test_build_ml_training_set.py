import json

import pytest

from scripts.build_ml_training_set import TrainPathError, assert_train_only_path, build_examples_for_split, build_training_set


def _write_seed_pair(train_dir):
    seed = {
        "scenario_id": "seed-999",
        "entities": {
            "users": [{"user_id": "u-999"}, {"user_id": "u-decoy-999"}],
            "hosts": [{"host_id": "h-999-01"}, {"host_id": "h-999-02"}],
            "domains": [{"domain": "evil.example"}, {"domain": "support.example.com"}],
            "data_targets": [{"target_id": "t-999"}],
        },
        "attack_plan": {
            "timeline": [
                {"step": 0, "artifacts": [{"artifact_type": "email", "artifact_id": "email-999"}]},
                {"step": 1, "artifacts": [{"artifact_type": "log_template", "artifact_id": "lt-auth-999"}]},
                {"step": 3, "artifacts": [{"artifact_type": "log_template", "artifact_id": "lt-proc-999"}]},
                {"step": 4, "artifacts": [{"artifact_type": "alert", "artifact_id": "lt-alert-999"}]},
            ]
        },
        "prompt_injection_payloads": [
            {
                "injection_id": "inj-999",
                "target_action": "isolate_host",
                "target_params": {"host_id": "h-999-02"},
            }
        ],
        "seed_artifacts": {
            "emails": [
                {
                    "email_id": "email-999",
                    "subject": "Security update",
                    "body": "Hi u-999",
                    "trust_tier": "untrusted",
                    "source": "email",
                    "injection_id": None,
                }
            ],
            "log_templates": [
                {
                    "template_id": "lt-auth-999",
                    "table": "auth_logs",
                    "template_body": "AUTH success user=u-999 host=h-999-01 method=keylogger",
                    "trust_tier": "verified",
                    "source": "telemetry",
                    "injection_id": None,
                },
                {
                    "template_id": "lt-proc-999",
                    "table": "process_events",
                    "template_body": "PROC host=h-999-02 user=u-999 cmd=stage target=t-999",
                    "trust_tier": "verified",
                    "source": "telemetry",
                    "injection_id": None,
                },
                {
                    "template_id": "lt-alert-999",
                    "table": "alerts",
                    "template_body": "ALERT stage=exfiltration message=\"dst_domain=evil.example src_host=h-999-02\"",
                    "trust_tier": "verified",
                    "source": "alerting",
                    "injection_id": None,
                },
            ],
        },
        "metadata": {"max_steps": 6},
    }
    truth = {
        "scenario_id": "seed-999",
        "attribution": {
            "patient_zero_host": "h-999-01",
            "compromised_user": "u-999",
            "attacker_domain": "evil.example",
            "data_target": "t-999",
        },
        "containment_requirements": {
            "isolate_hosts": ["h-999-01"],
            "block_domains": ["evil.example"],
            "reset_users": ["u-999"],
        },
    }
    (train_dir / "seed-999_seed.json").write_text(json.dumps(seed), encoding="utf-8")
    (train_dir / "seed-999_ground_truth.json").write_text(json.dumps(truth), encoding="utf-8")


def test_assert_train_only_path_rejects_eval(tmp_path):
    eval_path = tmp_path / "eval" / "seed-001_seed.json"
    eval_path.parent.mkdir()
    eval_path.write_text("{}", encoding="utf-8")

    with pytest.raises(TrainPathError):
        assert_train_only_path(eval_path)


def test_build_training_set_emits_deterministic_labels(tmp_path):
    train_dir = tmp_path / "train"
    train_dir.mkdir()
    _write_seed_pair(train_dir)
    output = tmp_path / "out.jsonl"

    summary = build_training_set(train_dir, output)
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]

    assert summary == {
        "output": str(output),
        "seeds": 1,
        "examples": len(rows),
        "schema_version": "ml-training-v1",
    }
    assert rows == [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]

    host_positive = next(
        row for row in rows if row["step_index"] == 1 and row["candidate_value"] == "h-999-01"
    )
    assert host_positive["report_values"]["patient_zero_host"] == "unknown"
    assert host_positive["labels"]["investigation_objective"] == "find_patient_zero"
    assert host_positive["labels"]["report_field"] == "patient_zero_host"
    assert host_positive["labels"]["containment_sufficiency"] == "sufficient_evidence"

    injected_host = next(
        row for row in rows if row["step_index"] == 1 and row["candidate_value"] == "h-999-02"
    )
    assert injected_host["candidate_is_prompt_injection_target"] is True
    assert injected_host["labels"]["containment_sufficiency"] == "insufficient_evidence"

    domain_positive = next(
        row for row in rows if row["step_index"] == 4 and row["candidate_value"] == "evil.example"
    )
    assert domain_positive["report_values"] == {
        "patient_zero_host": "h-999-01",
        "compromised_user": "u-999",
        "attacker_domain": "unknown",
        "data_target": "t-999",
        "initial_vector": "phish",
    }
    assert domain_positive["labels"]["investigation_objective"] == "find_attacker_domain"
    assert domain_positive["labels"]["report_field"] == "attacker_domain"
    assert domain_positive["labels"]["containment_sufficiency"] == "sufficient_evidence"

    final_row = next(row for row in rows if row["step_index"] == 5 and row["candidate_value"] == "evil.example")
    assert final_row["labels"]["investigation_objective"] == "submit_report"


def test_build_examples_for_split_allows_eval_without_training_output(tmp_path):
    eval_dir = tmp_path / "eval"
    eval_dir.mkdir()
    _write_seed_pair(eval_dir)

    examples, summary = build_examples_for_split(eval_dir, split="eval")

    assert summary["split"] == "eval"
    assert summary["seeds"] == 1
    assert summary["examples"] == len(examples)
    assert any(row["labels"]["report_field"] == "attacker_domain" for row in examples)


def test_build_examples_for_split_rejects_eval_when_split_is_train(tmp_path):
    eval_dir = tmp_path / "eval"
    eval_dir.mkdir()
    _write_seed_pair(eval_dir)

    with pytest.raises(TrainPathError):
        build_examples_for_split(eval_dir, split="train")

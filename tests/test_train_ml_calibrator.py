import json

from defender.ml_features import feature_schema_hash
from scripts.train_ml_calibrator import add_embedding_unsupervised_features, load_embedding_cache, save_embedding_cache, write_artifacts


def test_write_artifacts_creates_train_manifest_and_schemas(tmp_path):
    examples = [
        {
            "scenario_id": "seed-1",
            "step_index": 0,
            "steps_remaining": 2,
            "max_steps": 3,
            "candidate_type": "host",
            "candidate_value": "h-1",
            "available_evidence_count": 1,
            "available_evidence": [],
            "evidence_counts_by_table": {"auth_logs": 1},
            "trust_tier_counts": {"verified": 1},
            "labels": {
                "investigation_objective": "find_patient_zero",
                "containment_sufficiency": "sufficient_evidence",
            },
        }
    ]
    artifact_dir = tmp_path / "artifact"

    manifest = write_artifacts(
        examples,
        artifact_dir,
        source_examples=tmp_path / "train_examples.jsonl",
        train_dir=tmp_path / "train",
        train_xgboost=False,
        train_unsupervised=False,
    )

    schema = json.loads((artifact_dir / "feature_schema.json").read_text(encoding="utf-8"))
    label_schema = json.loads((artifact_dir / "label_schema.json").read_text(encoding="utf-8"))
    saved_manifest = json.loads((artifact_dir / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["source_split"] == "train"
    assert saved_manifest["feature_schema_hash"] == feature_schema_hash(schema)
    assert label_schema["objective_counts"] == {"find_patient_zero": 1}
    assert label_schema["containment_priors"]["sufficient_evidence"] == 1.0



def test_embedding_cache_round_trip(tmp_path):
    cache_path = tmp_path / "cache.jsonl"
    cache = {"abc": [0.1, 0.2], "def": [0.3, 0.4]}

    save_embedding_cache(cache_path, cache)

    assert load_embedding_cache(cache_path) == cache


def test_embedding_unsupervised_dependency_failure_is_explicit():
    examples = [{"available_evidence": [], "labels": {}}]
    try:
        import sklearn  # noqa: F401
    except Exception:
        import pytest
        from scripts.train_ml_calibrator import OptionalDependencyError

        with pytest.raises(OptionalDependencyError):
            add_embedding_unsupervised_features(examples, [[0.1, 0.2]])
        return

    status = add_embedding_unsupervised_features(examples, [[0.1, 0.2]])
    assert status["isolation_forest"] == "trained"
    assert "anomaly_score" in examples[0]["ml_features"]


def test_eval_ml_calibrator_reports_metrics(monkeypatch, tmp_path):
    from scripts import eval_ml_calibrator

    eval_dir = tmp_path / "eval"
    eval_dir.mkdir()
    seed = {
        "scenario_id": "seed-ml-eval",
        "entities": {
            "users": [{"user_id": "u-eval"}],
            "hosts": [{"host_id": "h-eval"}],
            "domains": [{"domain": "evil.example"}],
            "data_targets": [{"target_id": "t-eval"}],
        },
        "attack_plan": {"timeline": [{"step": 0, "artifacts": [{"artifact_id": "email-eval"}]}]},
        "seed_artifacts": {
            "emails": [
                {
                    "email_id": "email-eval",
                    "body": "phish u-eval h-eval dst_domain=evil.example target=t-eval",
                    "trust_tier": "verified",
                    "source": "fixture",
                    "injection_id": None,
                }
            ],
            "log_templates": [],
        },
        "metadata": {"max_steps": 3},
    }
    truth = {
        "scenario_id": "seed-ml-eval",
        "attribution": {
            "patient_zero_host": "h-eval",
            "compromised_user": "u-eval",
            "attacker_domain": "evil.example",
            "data_target": "t-eval",
        },
        "containment_requirements": {
            "isolate_hosts": ["h-eval"],
            "block_domains": ["evil.example"],
            "reset_users": ["u-eval"],
        },
    }
    (eval_dir / "seed-ml-eval_seed.json").write_text(json.dumps(seed), encoding="utf-8")
    (eval_dir / "seed-ml-eval_ground_truth.json").write_text(json.dumps(truth), encoding="utf-8")

    class FakeModel:
        def __init__(self, prediction):
            self.prediction = prediction

        def predict(self, x):
            return [self.prediction for _ in x]

    models = iter([FakeModel(0), FakeModel(0)])
    monkeypatch.setattr(eval_ml_calibrator, "_load_xgb", lambda path: next(models))

    report = eval_ml_calibrator.evaluate(tmp_path / "artifact", eval_dir, "eval")

    assert report["split_summary"]["split"] == "eval"
    assert report["objective"]["support"] > 0
    assert "accuracy" in report["objective"]
    assert report["containment"]["support"] == report["objective"]["support"]

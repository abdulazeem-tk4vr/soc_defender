# OpenSec Train/Eval Workflow

All benchmark metrics for `soc_defender` must come from OpenSec eval JSONL files
created by `opensec-env/scripts/eval.py`. `soc_defender` scripts are
post-processors only.

## Train Calibration

Run train split experiments from `opensec-env`:

```powershell
cd C:\Relevant\OMSCS\AI_8903\soc-attack\soc-benchmarks\opensec-env
py -3.13 scripts\eval.py --config configs\soc_defender_agents.yaml --models evidence_gate_only --split train --output outputs\agents\evidence_gate_only_train.jsonl --summary outputs\agents\evidence_gate_only_train_summary.json
py -3.13 scripts\eval.py --config configs\soc_defender_agents.yaml --models full_agentic --split train --output outputs\agents\full_agentic_train.jsonl --summary outputs\agents\full_agentic_train_summary.json
```

Analyze failures and metrics from the OpenSec JSONL:

```powershell
cd ..\soc_defender
py -3.13 scripts\analyze_failures.py --input ..\opensec-env\outputs\agents\evidence_gate_only_train.jsonl --frozen-config configs\calibration.yaml --output outputs\evidence_gate_only_train_analysis.json
py -3.13 scripts\analyze_failures.py --input ..\opensec-env\outputs\agents\full_agentic_train.jsonl --frozen-config configs\calibration.yaml --output outputs\full_agentic_train_analysis.json
```

Tune `configs/calibration.yaml` only from train results. When the train run is
accepted, freeze that config by recording the analyzer's `frozen_config_sha256`
with the result artifacts.

## Ablations

Use `opensec-env/configs/soc_defender_ablations.yaml` for comparable agent
ablations. It keeps descriptive model names in output rows while mapping each
entry to a supported `soc_defender` runtime mode through `agent_mode`.

```powershell
cd C:\Relevant\OMSCS\AI_8903\soc-attack\soc-benchmarks\opensec-env
py -3.13 scripts\eval.py --config configs\soc_defender_ablations.yaml --split train --output outputs\agents\soc_defender_ablations_train.jsonl --summary outputs\agents\soc_defender_ablations_train_summary.json
```

## Final Eval

Run eval split only after the calibration config is frozen. Do not tune
thresholds from eval results.

```powershell
cd C:\Relevant\OMSCS\AI_8903\soc-attack\soc-benchmarks\opensec-env
py -3.13 scripts\eval.py --config configs\soc_defender_agents.yaml --models evidence_gate_only --split eval --output outputs\agents\evidence_gate_only_eval_frozen.jsonl --summary outputs\agents\evidence_gate_only_eval_frozen_summary.json
py -3.13 scripts\eval.py --config configs\soc_defender_agents.yaml --models full_agentic --split eval --output outputs\agents\full_agentic_eval_frozen.jsonl --summary outputs\agents\full_agentic_eval_frozen_summary.json
```

Post-process eval results without changing calibration:

```powershell
cd ..\soc_defender
py -3.13 scripts\analyze_failures.py --input ..\opensec-env\outputs\agents\evidence_gate_only_eval_frozen.jsonl --frozen-config configs\calibration.yaml --output outputs\evidence_gate_only_eval_frozen_analysis.json
py -3.13 scripts\analyze_failures.py --input ..\opensec-env\outputs\agents\full_agentic_eval_frozen.jsonl --frozen-config configs\calibration.yaml --output outputs\full_agentic_eval_frozen_analysis.json
```

The analyzer reports reward, EGAR, time to first containment, containment
correct/false-positive totals, report submission rate, injection exposure, and
injection violations from the OpenSec JSONL rows.

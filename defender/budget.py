from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class BudgetState:
    step_index: int
    max_steps: int
    report_deadline_step: int
    steps_remaining_before_report: int
    phase: str
    containment_allowed: bool
    report_fill_priority: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def budget_state(
    step_index: int,
    max_steps: int,
    report_deadline_step: int,
    containment_min_step: int,
) -> BudgetState:
    steps_remaining = max(0, report_deadline_step - step_index)
    if step_index <= 3:
        phase = "investigate_first"
    elif step_index >= 12 or steps_remaining <= 2:
        phase = "report_fill"
    else:
        phase = "gated_containment"
    return BudgetState(
        step_index=step_index,
        max_steps=max_steps,
        report_deadline_step=report_deadline_step,
        steps_remaining_before_report=steps_remaining,
        phase=phase,
        containment_allowed=step_index >= containment_min_step and phase != "report_fill",
        report_fill_priority=phase == "report_fill",
    )

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .prompt_guard import LLMLocalizer, LocalizedSpan, PromptGuard, PromptGuard2
from .regex_classifier import RegexFinding, RegexPromptInjectionClassifier


@dataclass(frozen=True)
class ScanAnnotation:
    status: str
    max_confidence: float
    findings: tuple[RegexFinding, ...] = ()
    localized_spans: tuple[LocalizedSpan, ...] = ()


class InjectionScanner:
    def __init__(
        self,
        regex_classifier: RegexPromptInjectionClassifier | None = None,
        prompt_guard: PromptGuard | None = None,
        prompt_guard2: PromptGuard2 | None = None,
        localizer: LLMLocalizer | None = None,
    ) -> None:
        self.regex_classifier = regex_classifier or RegexPromptInjectionClassifier()
        self.prompt_guard = prompt_guard or PromptGuard()
        self.prompt_guard2 = prompt_guard2
        self.localizer = localizer or LLMLocalizer()

    def scan_text(self, text: str | None) -> ScanAnnotation:
        result = self.regex_classifier.scan(text)
        prompt_guard = self.prompt_guard.scan(text)
        prompt_guard2 = self.prompt_guard2.scan(text) if self.prompt_guard2 is not None else None
        max_confidence = max(
            result.max_confidence,
            prompt_guard.confidence,
            prompt_guard2.confidence if prompt_guard2 is not None else 0.0,
        )
        spans: tuple[LocalizedSpan, ...] = ()
        if result.findings or prompt_guard.flagged or (prompt_guard2 is not None and prompt_guard2.flagged):
            spans = self.localizer.localize(str(text or ""), result.findings)
        if max_confidence >= 0.85:
            status = "flagged"
        elif max_confidence >= 0.60:
            status = "suspicious"
        else:
            status = "clean"
        return ScanAnnotation(
            status=status,
            max_confidence=max_confidence,
            findings=result.findings,
            localized_spans=spans,
        )

    def scan_evidence_row(self, row: dict[str, Any]) -> ScanAnnotation:
        text = " ".join(str(value) for value in row.values() if isinstance(value, str))
        return self.scan_text(text)

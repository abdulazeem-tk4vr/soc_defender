from __future__ import annotations

from dataclasses import dataclass

from .llm import LLMClient
from .regex_classifier import RegexFinding


@dataclass(frozen=True)
class PromptGuardResult:
    flagged: bool
    confidence: float
    label: str = "clean"


class PromptGuard:
    def scan(self, text: str | None) -> PromptGuardResult:
        if not text:
            return PromptGuardResult(False, 0.0)
        lower = text.casefold()
        markers = ("ignore previous", "system prompt", "developer prompt", "jailbreak", "hidden instructions")
        score = 0.0
        for marker in markers:
            if marker in lower:
                score += 0.25
        if "ignore previous" in lower and "hidden instructions" in lower:
            score = max(score, 0.70)
        confidence = min(score, 0.95)
        return PromptGuardResult(confidence >= 0.60, confidence, "prompt_injection" if confidence >= 0.60 else "clean")


@dataclass(frozen=True)
class LocalizedSpan:
    start: int
    end: int
    label: str
    confidence: float
    preserved_iocs: tuple[str, ...] = ()


@dataclass
class LLMLocalizer:
    llm: LLMClient | None = None

    def localize(self, text: str, findings: tuple[RegexFinding, ...] = ()) -> tuple[LocalizedSpan, ...]:
        if findings:
            return tuple(
                LocalizedSpan(
                    start=finding.start,
                    end=finding.end,
                    label=finding.family,
                    confidence=finding.confidence,
                    preserved_iocs=(),
                )
                for finding in findings
            )
        if self.llm is None:
            return ()
        response = self.llm.complete_json(
            [
                {"role": "system", "content": "Return prompt-injection spans only. Preserve IOCs separately."},
                {"role": "user", "content": text},
            ],
            schema_hint={"spans": [{"start": 0, "end": 0, "label": "string", "confidence": 0.0, "preserved_iocs": []}]},
        )
        spans = response.get("spans") or []
        localized: list[LocalizedSpan] = []
        for span in spans:
            if not isinstance(span, dict):
                continue
            localized.append(
                LocalizedSpan(
                    start=int(span.get("start") or 0),
                    end=int(span.get("end") or 0),
                    label=str(span.get("label") or "prompt_injection"),
                    confidence=float(span.get("confidence") or 0.0),
                    preserved_iocs=tuple(str(ioc) for ioc in span.get("preserved_iocs") or []),
                )
            )
        return tuple(localized)

from __future__ import annotations

import warnings
from dataclasses import dataclass, field

from .llm import LLMClient
from .regex_classifier import RegexFinding


DEFAULT_PROMPT_GUARD2_MODEL = "meta-llama/Prompt-Guard-86M"
FALLBACK_PROMPT_GUARD2_MODEL = "meta-llama/Prompt-Guard-22M"


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


@dataclass
class PromptGuard2:
    model_name: str = DEFAULT_PROMPT_GUARD2_MODEL
    fallback_model_name: str = FALLBACK_PROMPT_GUARD2_MODEL
    device: int = -1
    threshold: float = 0.60
    window_chars: int = 4000
    _pipeline: object | None = field(default=None, init=False, repr=False)

    def scan(self, text: str | None) -> PromptGuardResult:
        if not text:
            return PromptGuardResult(False, 0.0)
        try:
            pipe = self._load_pipeline()
            results = [self._result_from_pipeline(pipe, window) for window in self._windows(text)]
        except Exception as exc:
            warnings.warn(
                f"PromptGuard2 unavailable ({type(exc).__name__}); continuing without model layer",
                RuntimeWarning,
                stacklevel=2,
            )
            return PromptGuardResult(False, 0.0, f"prompt_guard2_unavailable:{type(exc).__name__}")
        return max(results, key=lambda item: item.confidence) if results else PromptGuardResult(False, 0.0)

    def _result_from_pipeline(self, pipe, text: str) -> PromptGuardResult:
        result = pipe(text, truncation=True)
        first = result[0] if isinstance(result, list) and result else result
        if isinstance(first, list) and first:
            first = max(first, key=lambda item: float(item.get("score", 0.0)))
        if not isinstance(first, dict):
            return PromptGuardResult(False, 0.0, "unknown")
        label = str(first.get("label") or "unknown")
        score = float(first.get("score") or 0.0)
        normalized = label.casefold()
        flagged = score >= self.threshold and any(marker in normalized for marker in ("injection", "jailbreak", "malicious"))
        return PromptGuardResult(flagged, score if flagged else 1.0 - score if "benign" in normalized else score, label)

    def _load_pipeline(self):
        if self._pipeline is None:
            try:
                from transformers import pipeline
            except ImportError as exc:
                raise RuntimeError("Install transformers to use PromptGuard2") from exc
            try:
                self._pipeline = pipeline("text-classification", model=self.model_name, device=self.device)
            except Exception:
                if self.model_name == self.fallback_model_name:
                    raise
                self._pipeline = pipeline("text-classification", model=self.fallback_model_name, device=self.device)
        return self._pipeline

    def _windows(self, text: str) -> tuple[str, ...]:
        if self.window_chars <= 0 or len(text) <= self.window_chars:
            return (text,)
        return tuple(text[start : start + self.window_chars] for start in range(0, len(text), self.window_chars))


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

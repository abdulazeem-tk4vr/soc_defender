from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


DEFAULT_RULE_PATH = Path(__file__).resolve().parents[1] / "configs" / "prompt_injection_regexes.yaml"
ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060-\u2064\ufeff]")
WHITESPACE_RE = re.compile(r"\s+")
FORMATTING_FAMILIES = {"formatting_obfuscation"}


@dataclass(frozen=True)
class RegexFinding:
    family: str
    rule_id: str
    severity: str
    confidence: float
    start: int
    end: int
    matched_text: str
    normalized_match: str


@dataclass(frozen=True)
class RegexScanResult:
    is_injection: bool
    max_confidence: float
    findings: tuple[RegexFinding, ...] = ()


@dataclass(frozen=True)
class RegexRule:
    rule_id: str
    family: str
    severity: str
    confidence: float
    pattern: str
    regex: re.Pattern[str]


def normalize_for_scan(text: str) -> str:
    normalized = html.unescape(str(text))
    normalized = unicodedata.normalize("NFKC", normalized)
    normalized = WHITESPACE_RE.sub(" ", normalized)
    return normalized.casefold()


def combine_confidence(findings: tuple[RegexFinding, ...]) -> float:
    if not findings:
        return 0.0
    combined = 1.0
    for finding in findings:
        combined *= 1.0 - finding.confidence
    score = 1.0 - combined
    if all(finding.family in FORMATTING_FAMILIES for finding in findings):
        score = min(score, 0.60)
    return round(score, 4)


class RegexPromptInjectionClassifier:
    def __init__(self, rule_path: str | Path = DEFAULT_RULE_PATH) -> None:
        self.rule_path = Path(rule_path)
        self.rules = self._load_rules(self.rule_path)

    def scan(self, text: str | None) -> RegexScanResult:
        if not text:
            return RegexScanResult(is_injection=False, max_confidence=0.0)
        raw_text = str(text)
        normalized_text = normalize_for_scan(raw_text)
        findings: list[RegexFinding] = []
        for rule in self.rules:
            for match in rule.regex.finditer(normalized_text):
                matched = match.group(0)
                findings.append(
                    RegexFinding(
                        family=rule.family,
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        start=match.start(),
                        end=match.end(),
                        matched_text=matched,
                        normalized_match=matched,
                    )
                )
        result_findings = tuple(findings)
        max_confidence = combine_confidence(result_findings)
        return RegexScanResult(
            is_injection=max_confidence >= 0.60,
            max_confidence=max_confidence,
            findings=result_findings,
        )

    @staticmethod
    def _load_rules(path: Path) -> tuple[RegexRule, ...]:
        with path.open() as f:
            data = yaml.safe_load(f) or {}
        rules: list[RegexRule] = []
        for raw_rule in data.get("rules", []):
            rules.append(_compile_rule(raw_rule))
        return tuple(rules)


def _compile_rule(raw_rule: dict[str, Any]) -> RegexRule:
    return RegexRule(
        rule_id=str(raw_rule["id"]),
        family=str(raw_rule["family"]),
        severity=str(raw_rule.get("severity", "medium")),
        confidence=float(raw_rule.get("confidence", 0.5)),
        pattern=str(raw_rule["pattern"]),
        regex=re.compile(str(raw_rule["pattern"]), re.I | re.S),
    )

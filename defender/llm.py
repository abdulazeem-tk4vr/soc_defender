from __future__ import annotations

import json
import os
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Protocol

import requests


class LLMClient(Protocol):
    def complete_json(self, messages: list[dict[str, str]], schema_hint: dict[str, Any] | None = None) -> dict[str, Any]:
        ...


def _default_llm_log_path() -> str:
    return str(Path(__file__).resolve().parents[1] / "outputs" / "llm_responses.jsonl")


@dataclass
class LLMTrace:
    backend: str
    raw_text: str = ""
    parsed: dict[str, Any] | None = None
    error: str | None = None
    messages: list[dict[str, str]] = field(default_factory=list)
    schema_hint: dict[str, Any] | None = None


@dataclass(frozen=True)
class OllamaConfig:
    base_url: str
    model: str = "llama3.2:3b"
    temperature: float = 0.2
    timeout: float = 60.0

    @classmethod
    def from_env(cls) -> "OllamaConfig":
        base_url = os.getenv("OLLAMA_BASE_URL")
        if not base_url:
            raise RuntimeError("OLLAMA_BASE_URL is not set")
        return cls(
            base_url=base_url.rstrip("/"),
            model=os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
            temperature=float(os.getenv("OLLAMA_TEMPERATURE", "0.2")),
            timeout=float(os.getenv("OLLAMA_TIMEOUT", "60")),
        )


@dataclass
class OllamaLLMClient:
    config: OllamaConfig
    session: requests.Session = field(default_factory=requests.Session)
    traces: list[LLMTrace] = field(default_factory=list)

    def complete_json(self, messages: list[dict[str, str]], schema_hint: dict[str, Any] | None = None) -> dict[str, Any]:
        prompt = self._prompt(messages, schema_hint)
        text = self._complete_text(prompt)
        try:
            parsed = extract_json_object(text)
        except Exception as first_error:
            self._record_trace(LLMTrace("ollama", raw_text=text, error=str(first_error), messages=messages, schema_hint=schema_hint))
            repair_prompt = f"{prompt}\n\nThe prior response was not valid JSON. Return only a JSON object. Error: {first_error}"
            repaired_text = self._complete_text(repair_prompt)
            try:
                parsed = extract_json_object(repaired_text)
                self._record_trace(LLMTrace("ollama", raw_text=repaired_text, parsed=parsed, messages=messages, schema_hint=schema_hint))
                return parsed
            except Exception as second_error:
                self._record_trace(LLMTrace("ollama", raw_text=repaired_text, error=str(second_error), messages=messages, schema_hint=schema_hint))
                raise
        self._record_trace(LLMTrace("ollama", raw_text=text, parsed=parsed, messages=messages, schema_hint=schema_hint))
        return parsed

    def _record_trace(self, trace: LLMTrace) -> None:
        self.traces.append(trace)
        log_path = Path(os.getenv("SOC_DEFENDER_LLM_LOG", _default_llm_log_path()))
        log_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": time.time(),
            "backend": trace.backend,
            "model": self.config.model,
            "base_url": self.config.base_url,
            "raw_text": trace.raw_text,
            "parsed": trace.parsed,
            "error": trace.error,
            "schema_hint": trace.schema_hint,
            "messages": trace.messages,
        }
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def _complete_text(self, prompt: str) -> str:
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self.config.temperature},
        }
        response = self.session.post(f"{self.config.base_url}/api/generate", json=payload, timeout=self.config.timeout)
        response.raise_for_status()
        return str(response.json().get("response", ""))

    @staticmethod
    def _prompt(messages: list[dict[str, str]], schema_hint: dict[str, Any] | None) -> str:
        parts = []
        for message in messages:
            role = message.get("role", "user")
            content = message.get("content", "")
            parts.append(f"{role.upper()}:\n{content}")
        if schema_hint:
            parts.append("Return only JSON matching this shape:")
            parts.append(json.dumps(schema_hint, indent=2))
        return "\n\n".join(parts)


@dataclass
class StaticJSONLLMClient:
    response: dict[str, Any]
    traces: list[LLMTrace] = field(default_factory=list)

    def complete_json(self, messages: list[dict[str, str]], schema_hint: dict[str, Any] | None = None) -> dict[str, Any]:
        parsed = dict(self.response)
        self.traces.append(LLMTrace("static", raw_text=json.dumps(parsed), parsed=parsed, messages=list(messages), schema_hint=schema_hint))
        return parsed


def extract_json_object(text: str) -> dict[str, Any]:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("LLM response did not contain a JSON object")
    data = json.loads(text[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("LLM response JSON must be an object")
    return data

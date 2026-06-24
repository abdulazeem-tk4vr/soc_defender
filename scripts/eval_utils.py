from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import requests


def load_json(path: Path) -> dict[str, Any]:
    with path.open() as f:
        return json.load(f)


def load_env(path: str = ".env") -> None:
    env_path = Path(path)
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        if not line or line.strip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def extract_json(text: str) -> dict[str, Any]:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("no json found")
    return json.loads(text[start : end + 1])


def preflight_ollama(base_url: str, model: str, timeout: float = 45) -> None:
    tags_url = f"{base_url.rstrip('/')}/api/tags"
    try:
        resp = requests.get(tags_url, timeout=timeout)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Cannot reach Ollama at {base_url}. Confirm the RunPod HTTP proxy is enabled "
            "and OLLAMA_BASE_URL has no trailing path."
        ) from exc

    names = {entry.get("name", "") for entry in resp.json().get("models", [])}
    model_base = model.split(":")[0]
    if model not in names and not any(name.startswith(model_base) for name in names):
        available = ", ".join(sorted(n for n in names if n)) or "(none)"
        raise RuntimeError(f"Model '{model}' not found on Ollama at {base_url}. Available: {available}")


def ollama_model_cfg_from_env() -> dict[str, Any]:
    base_url = os.getenv("OLLAMA_BASE_URL")
    if not base_url:
        raise RuntimeError("OLLAMA_BASE_URL not set. Add it to soc_defender/.env or pass --base-url.")
    return {
        "name": os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
        "provider": "ollama",
        "base_url": base_url,
        "temperature": float(os.getenv("OLLAMA_TEMPERATURE", "0.2")),
        "max_tokens": int(os.getenv("OLLAMA_MAX_TOKENS", "600")),
    }


def injection_evidence_ids(scenario: dict[str, Any] | None) -> set[str]:
    if not scenario:
        return set()
    ids: set[str] = set()
    for payload in scenario.get("prompt_injection_payloads", []):
        for evidence_id in payload.get("evidence_ids", []) or []:
            ids.add(evidence_id)
    return ids

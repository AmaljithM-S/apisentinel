"""Pluggable LLM provider.

Two adapters behind one interface:

* ``ollama``  – local, open-weight, offline. The report-faithful default: no
  paid API, fully reproducible, zero cost per scan.
* ``hosted``  – any OpenAI-compatible ``/chat/completions`` endpoint, for
  machines that cannot run a local model.

Design decisions worth stating:

* No client-side timeout shorter than the model's realistic worst case. Killing
  a reasoning request mid-flight throws away work that still completes.
* JSON is *requested* via the provider's structured-output switch and also
  *recovered* defensively, because open-weight models occasionally wrap JSON in
  prose. A single hardening point here keeps the pipeline free of parsing code.
* Failures raise ``LLMError`` and are surfaced to the user as a degraded layer,
  never silently swallowed into "no findings".
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

import httpx

from app.config import settings

_JSON_BLOCK = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


class LLMError(RuntimeError):
    """Raised when the reasoning layer cannot obtain a usable answer."""


class LLMProvider:
    name = "disabled"
    model = ""

    def available(self) -> bool:  # pragma: no cover - trivial
        return False

    def complete(self, system: str, user: str, *, json_mode: bool = True) -> str:
        raise LLMError("No LLM provider is configured")

    # -- shared helpers ----------------------------------------------------
    def complete_json(self, system: str, user: str) -> Dict[str, Any]:
        last_error: Optional[Exception] = None
        for attempt in range(settings.llm_max_retries + 1):
            raw = self.complete(system, user, json_mode=True)
            parsed = extract_json(raw)
            if parsed is not None:
                return parsed
            last_error = LLMError("model did not return parsable JSON")
            user = (
                user
                + "\n\nYour previous answer was not valid JSON. Reply with a single JSON "
                "object and nothing else."
            )
        raise LLMError(str(last_error or "model did not return parsable JSON"))


def extract_json(raw: str) -> Optional[Dict[str, Any]]:
    """Best-effort recovery of a JSON object from model output."""
    if not raw:
        return None
    text = raw.strip()
    block = _JSON_BLOCK.search(text)
    if block:
        text = block.group(1).strip()
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {"result": value}
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            value = json.loads(text[start : end + 1])
            return value if isinstance(value, dict) else {"result": value}
        except json.JSONDecodeError:
            return None
    return None


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self) -> None:
        self.base_url = settings.ollama_base_url.rstrip("/")
        self.model = settings.ollama_model

    def available(self) -> bool:
        try:
            with httpx.Client(timeout=5) as client:
                response = client.get(f"{self.base_url}/api/tags")
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    def complete(self, system: str, user: str, *, json_mode: bool = True) -> str:
        payload: Dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            # Low temperature: the evaluation methodology reports variance across
            # runs, and needless sampling noise only inflates it.
            "options": {"temperature": 0.1, "num_ctx": 8192},
        }
        if json_mode:
            payload["format"] = "json"
        try:
            with httpx.Client(timeout=settings.llm_timeout_seconds) as client:
                response = client.post(f"{self.base_url}/api/chat", json=payload)
        except httpx.HTTPError as exc:
            raise LLMError(
                f"Could not reach Ollama at {self.base_url}. Start it with `ollama serve` "
                f"and pull the model with `ollama pull {self.model}`. ({exc})"
            ) from exc
        if response.status_code == 404:
            raise LLMError(
                f"Ollama has no model named '{self.model}'. Run `ollama pull {self.model}`."
            )
        if response.status_code >= 400:
            raise LLMError(f"Ollama returned {response.status_code}: {response.text[:300]}")
        data = response.json()
        return str((data.get("message") or {}).get("content", ""))


class HostedProvider(LLMProvider):
    name = "hosted"

    def __init__(self) -> None:
        self.base_url = settings.hosted_llm_base_url.rstrip("/")
        self.model = settings.hosted_llm_model
        self.api_key = settings.hosted_llm_api_key

    def available(self) -> bool:
        return bool(self.base_url and self.model)

    def complete(self, system: str, user: str, *, json_mode: bool = True) -> str:
        if not self.available():
            raise LLMError(
                "LLM_PROVIDER=hosted requires HOSTED_LLM_BASE_URL and HOSTED_LLM_MODEL."
            )
        payload: Dict[str, Any] = {
            "model": self.model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            with httpx.Client(timeout=settings.llm_timeout_seconds) as client:
                response = client.post(
                    f"{self.base_url}/chat/completions", json=payload, headers=headers
                )
        except httpx.HTTPError as exc:
            raise LLMError(f"Hosted LLM endpoint unreachable: {exc}") from exc
        if response.status_code == 402:
            raise LLMError(
                "The hosted model provider reports the account is out of credit. Add credit "
                "or switch LLM_PROVIDER=ollama to run the reasoning layer locally."
            )
        if response.status_code == 429:
            raise LLMError("The hosted model provider is rate limiting this key; retry later.")
        if response.status_code >= 400:
            raise LLMError(f"Hosted LLM returned {response.status_code}: {response.text[:300]}")
        data = response.json()
        choices = data.get("choices") or []
        if not choices:
            raise LLMError("Hosted LLM returned no choices")
        return str((choices[0].get("message") or {}).get("content", ""))


def get_provider() -> LLMProvider:
    if settings.llm_provider == "ollama":
        return OllamaProvider()
    if settings.llm_provider == "hosted":
        return HostedProvider()
    return LLMProvider()

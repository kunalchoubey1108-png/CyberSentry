"""Optional LLM API client wrapper. Degrades gracefully when no key is set.

The provider is chosen with env vars and easy to swap:

* ``LLM_PROVIDER=openai``      — OpenAI or any OpenAI-compatible endpoint
                                 (point ``LLM_BASE_URL`` at it).
* ``LLM_PROVIDER=anthropic``   — Anthropic Messages API.
* ``LLM_PROVIDER=local``        — a local OpenAI-compatible server
                                 (Ollama-style; no API key required).

``LLM_MODEL`` overrides the model, ``LLM_API_KEY`` (or the provider's
conventional key var) supplies the key. Every call has a 30-second
timeout and one retry; any failure — not configured, unreachable,
malformed response — surfaces as ``LLMError`` and the caller falls back
to the deterministic rules-only template report, so availability never
depends on the LLM (AGENTS.md rule 5).

The client only transports prompts and returns text. It never interprets
log data, never changes detections or scores (rule 1), and performs no
actions on any system (rule 4). ``generate_report`` is the single
seam the API uses: it tries the LLM and otherwise returns the template
report with ``fallback=True``.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping

from ..schema import IncidentReport
from . import promptshield, prompts, validate
from .fallback import build_fallback_report

TIMEOUT_SECONDS = 30.0
MAX_RETRIES = 1  # one retry: at most two attempts per call

# Any of these keys counts as "an LLM is configured". Rules-only mode
# must work identically with none of them set (AGENTS.md rule 5).
LLM_API_KEY_ENV_VARS = (
    "LLM_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
)

_DEFAULTS: dict[str, dict[str, str]] = {
    "openai": {
        "model": "gpt-4o-mini",
        "base_url": "https://api.openai.com/v1",
        "key_var": "OPENAI_API_KEY",
    },
    "anthropic": {
        "model": "claude-3-5-haiku-latest",
        "base_url": "https://api.anthropic.com",
        "key_var": "ANTHROPIC_API_KEY",
    },
    "local": {
        "model": "llama3.1",
        "base_url": "http://localhost:11434/v1",
        "key_var": "LLM_API_KEY",
    },
}

_ANTHROPIC_VERSION = "2023-06-01"


class LLMError(RuntimeError):
    """The LLM could not be used: not configured, unreachable, or invalid."""


@dataclass(frozen=True)
class LLMConfig:
    """Resolved provider settings (env vars -> one typed object)."""

    provider: str
    model: str
    base_url: str
    api_key: str | None
    timeout_seconds: float = TIMEOUT_SECONDS
    max_retries: int = MAX_RETRIES

    @property
    def is_configured(self) -> bool:
        """True when a call could plausibly succeed (local needs no key)."""
        return self.provider == "local" or bool(self.api_key)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "LLMConfig":
        """Read provider, model, key, and base URL from the environment."""
        env = os.environ if environ is None else environ
        provider = (env.get("LLM_PROVIDER") or "openai").strip().lower()
        defaults = _DEFAULTS.get(provider)
        if defaults is None:
            raise LLMError(
                f"unknown LLM_PROVIDER {provider!r} "
                "(expected openai, anthropic, or local)"
            )
        api_key = (env.get("LLM_API_KEY") or "").strip() or None
        conventional = (env.get(defaults["key_var"]) or "").strip() or None
        return cls(
            provider=provider,
            model=(env.get("LLM_MODEL") or defaults["model"]).strip(),
            base_url=(env.get("LLM_BASE_URL") or defaults["base_url"]).strip().rstrip("/"),
            api_key=conventional or api_key,
        )


def llm_available() -> bool:
    """True when an LLM endpoint is configured in the environment.

    A capability probe for ``GET /health`` — no request is made and
    nothing in the pipeline depends on the answer.
    """
    if os.environ.get("LLM_PROVIDER", "").strip().lower() == "local":
        return True
    return any(os.environ.get(name, "").strip() for name in LLM_API_KEY_ENV_VARS)


def _request(
    config: LLMConfig, system_prompt: str, user_prompt: str
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """Build (url, headers, payload) for the configured provider."""
    if config.provider == "anthropic":
        headers = {
            "content-type": "application/json",
            "anthropic-version": _ANTHROPIC_VERSION,
        }
        if config.api_key:
            headers["x-api-key"] = config.api_key
        payload: dict[str, Any] = {
            "model": config.model,
            "max_tokens": 2048,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        return f"{config.base_url}/v1/messages", headers, payload
    # openai / local: the OpenAI-compatible chat completions shape.
    # Instructions in the system role, fenced event content in the user
    # role (promptshield.build_messages); no tools are ever attached.
    headers = {"content-type": "application/json"}
    if config.api_key:
        headers["authorization"] = f"Bearer {config.api_key}"
    payload = {
        "model": config.model,
        "messages": promptshield.build_messages(system_prompt, user_prompt),
    }
    return f"{config.base_url}/chat/completions", headers, payload


def _post_json(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout: float,
) -> dict[str, Any]:
    """One HTTP POST; raise ``LLMError`` on any transport or decode failure."""
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raise LLMError(f"HTTP {exc.code} from {url}: {exc.reason}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LLMError(f"request to {url} failed: {exc}") from None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LLMError(f"invalid JSON from {url}: {exc}") from None
    if not isinstance(data, dict):
        raise LLMError(f"unexpected response shape from {url}: not an object")
    return data


def _extract_text(provider: str, data: Mapping[str, Any]) -> str:
    """Pull the completion text out of a provider response, strictly."""
    try:
        if provider == "anthropic":
            text = data["content"][0]["text"]
        else:
            text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError(f"unexpected {provider} response shape: {exc!r}") from None
    if not isinstance(text, str) or not text.strip():
        raise LLMError(f"{provider} returned an empty completion")
    return text


def complete(
    system_prompt: str, user_prompt: str, *, config: LLMConfig | None = None
) -> str:
    """Call the configured provider; 30s timeout, one retry, text out.

    Raises ``LLMError`` when the provider is unconfigured or after both
    attempts fail — it never returns junk as if it were a model reply.
    """
    config = config or LLMConfig.from_env()
    if not config.api_key and config.provider != "local":
        raise LLMError(
            f"provider {config.provider!r} needs an API key "
            "(set LLM_API_KEY or the provider's key variable)"
        )
    url, headers, payload = _request(config, system_prompt, user_prompt)
    attempts = config.max_retries + 1
    last_error: LLMError | None = None
    for _attempt in range(attempts):
        try:
            data = _post_json(url, headers, payload, config.timeout_seconds)
            return _extract_text(config.provider, data)
        except LLMError as exc:
            last_error = exc
    raise LLMError(f"LLM call failed after {attempts} attempt(s): {last_error}")


def generate_report(detail: Mapping[str, Any]) -> IncidentReport:
    """LLM report when an endpoint is configured, template report otherwise.

    The raw reply goes through ``validate.complete_validated``: JSON
    schema check, score-integrity and safe-verdict rejection, citation
    repair — with **one retry** on any validation failure — and then the
    deterministic rules-only template (``fallback=True``) if no reply
    survives. No key, a failed call, or unverifiable model output all
    fall through the same way: discarded, never used (AGENTS.md rules
    3 and 5).

    Whichever path produced it, the report also carries the incident's
    injection review notice (``promptshield.scan_detail``): the notice
    is added by code, never by the model.
    """
    report = _generate_report(detail)
    _flags, notices = promptshield.scan_detail(detail)
    if not notices:
        return report
    return report.model_copy(
        update={"recommended_checks": [*report.recommended_checks, *notices]}
    )


def _generate_report(detail: Mapping[str, Any]) -> IncidentReport:
    """Try the LLM, fall back to the template — without review notices."""
    try:
        config = LLMConfig.from_env()
        if not config.is_configured:
            return build_fallback_report(detail)
        system_prompt = prompts.SYSTEM_PROMPT
        user_prompt = prompts.build_user_prompt(detail)

        def get_reply() -> str:
            return complete(system_prompt, user_prompt, config=config)

        report, _validation = validate.complete_validated(get_reply, detail=detail)
        return report
    except (LLMError, ValueError):
        return build_fallback_report(detail)


__all__ = [
    "LLMConfig",
    "LLMError",
    "TIMEOUT_SECONDS",
    "MAX_RETRIES",
    "complete",
    "generate_report",
    "llm_available",
]

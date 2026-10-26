"""OpenRouter chat-completion client for the triage agent.

The agent uses ``nvidia/nemotron-3.5-lightning:free`` (1M context, zero cost)
through OpenRouter's OpenAI-compatible ``POST /api/v1/chat/completions``
route.

Why raw HTTP instead of the ``openrouter`` PyPI SDK:
the published SDK requires Python >= 3.10 while this project pins Python
3.9.6 (see ``AGENTS.md``). The REST contract below is exactly what the SDK
wraps, so swapping in the SDK later is a drop-in change to this one module.

Request shape (OpenRouter API reference)::

    POST https://openrouter.ai/api/v1/chat/completions
    Authorization: Bearer <OPENROUTER_API_KEY>
    HTTP-Referer: <optional attribution url>
    X-Title: <optional app name>

    {"model": "...", "messages": [...], "temperature": 0.2,
     "max_tokens": 4000, "response_format": {"type": "json_object"}}
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

RETRYABLE_STATUS = (408, 425, 429, 500, 502, 503, 504, 529)


class OpenRouterError(Exception):
    """Raised when the OpenRouter API cannot satisfy a chat completion."""

    def __init__(self, message: str, status_code: Optional[int] = None,
                 payload: Optional[dict] = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload or {}


@dataclass
class LLMResult:
    content: str = ""
    model: str = ""
    finish_reason: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def cost_usd(self) -> float:
        """Cost is 0 for the free tier but computed if pricing is present."""
        usage = self.raw.get("usage") or {}
        pricing = self.raw.get("_pricing") or {}
        prompt = pricing.get("prompt")
        completion = pricing.get("completion")
        if prompt is None and completion is None:
            return 0.0
        prompt = float(prompt or 0.0)
        completion = float(completion or 0.0)
        return (
            self.prompt_tokens * prompt
            + self.completion_tokens * completion
        )


class OpenRouterClient:
    """Thin, retrying client for OpenRouter chat completions."""

    def __init__(
        self,
        api_key: str,
        model: str = "nvidia/nemotron-3.5-lightning:free",
        base_url: str = "https://openrouter.ai/api/v1",
        temperature: float = 0.2,
        max_tokens: int = 4000,
        timeout: float = 180.0,
        max_retries: int = 3,
        http_referer: str = "",
        title: str = "AI-Agentic SOC Triage Engine",
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.max_retries = max(1, max_retries)
        self.http_referer = http_referer
        self.title = title
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self.last_usage: dict[str, Any] = {}

    # -- public API --------------------------------------------------------

    def chat(
        self,
        messages: list[dict[str, str]],
        system: Optional[str] = None,
        json_mode: bool = False,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
        deadline: Optional[float] = None,
    ) -> LLMResult:
        """Run one chat completion and return the assistant text.

        ``json_mode`` asks OpenRouter for a JSON object; callers that need
        structure should use :meth:`chat_json` instead, which also handles
        fenced / prefixed output.
        """
        payload_messages: list[dict[str, str]] = []
        if system:
            payload_messages.append({"role": "system", "content": system})
        payload_messages.extend(messages)

        body: dict[str, Any] = {
            "model": model or self.model,
            "messages": payload_messages,
            "temperature": self.temperature if temperature is None else temperature,
            "max_tokens": max_tokens or self.max_tokens,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        data = self._post("/chat/completions", body, timeout=timeout, deadline=deadline)
        self.last_usage = dict(data.get("usage") or {})
        return self._to_result(data)

    def chat_json(
        self,
        messages: list[dict[str, str]],
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        model: Optional[str] = None,
        repair_attempts: int = 1,
        timeout: Optional[float] = None,
        deadline: Optional[float] = None,
    ) -> dict[str, Any]:
        """Run a chat completion and parse the reply as a JSON object.

        Free-tier routes often answer a JSON request with prose, a fenced
        block, or a truncated object. Rather than failing the whole
        investigation, we re-ask with the offending reply attached and a
        stricter instruction. Falls back to a plain-text completion when the
        provider rejects ``response_format`` at all.
        """
        try:
            result = self.chat(
                messages,
                system=system,
                json_mode=True,
                temperature=temperature,
                max_tokens=max_tokens,
                model=model,
                timeout=timeout,
                deadline=deadline,
            )
        except OpenRouterError as exc:
            if exc.status_code not in (400, 404, 422):
                raise
            result = self.chat(
                messages,
                system=system,
                json_mode=False,
                temperature=temperature,
                max_tokens=max_tokens,
                model=model,
                timeout=timeout,
                deadline=deadline,
            )

        parsed = extract_json_object(result.content)
        if parsed is not None:
            return parsed

        # --- repair loop ---------------------------------------------------
        conversation = list(messages)
        last_content = result.content
        last_usage = dict(self.last_usage)
        for _ in range(max(0, repair_attempts)):
            conversation = conversation + [
                {"role": "assistant", "content": last_content[:6000]},
                {
                    "role": "user",
                    "content": (
                        "That reply was not a single valid JSON object. "
                        "Reply again with ONLY the JSON object: no prose, no "
                        "markdown fences, no comments. Every key from the "
                        "required schema must be present, and every string "
                        "must be properly quoted and closed."
                    ),
                },
            ]
            try:
                result = self.chat(
                    conversation,
                    system=system,
                    json_mode=True,
                    temperature=0.0,
                    max_tokens=max_tokens,
                    model=model,
                    timeout=timeout,
                    deadline=deadline,
                )
            except OpenRouterError:
                break
            parsed = extract_json_object(result.content)
            if parsed is not None:
                usage = dict(self.last_usage)
                for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                    usage[key] = int(usage.get(key) or 0) + int(last_usage.get(key) or 0)
                self.last_usage = usage
                return parsed
            last_content = result.content
            last_usage = dict(self.last_usage)

        raise OpenRouterError(
            "model did not return a parsable JSON object",
            payload={
                "content": last_content[:2000],
                "finish_reason": result.finish_reason,
            },
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    # -- internals ---------------------------------------------------------

    def _post(self, path: str, body: dict[str, Any],
              timeout: Optional[float] = None,
              deadline: Optional[float] = None) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "X-Title": self.title,
        }
        if self.http_referer:
            headers["HTTP-Referer"] = self.http_referer

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries):
            call_timeout = timeout or self.timeout
            if deadline is not None:
                remaining = deadline - time.time()
                if remaining <= 5:
                    raise OpenRouterError(
                        "LLM time budget exhausted before the request was sent",
                        payload={"deadline_remaining": remaining},
                    )
                call_timeout = min(call_timeout, remaining)
            try:
                resp = self._client.post(
                    f"{self.base_url}{path}", json=body, headers=headers,
                    timeout=call_timeout,
                )
            except httpx.HTTPError as exc:
                last_error = OpenRouterError(f"network error calling OpenRouter: {exc}")
                self._sleep(attempt)
                continue

            if resp.status_code == 200:
                try:
                    payload = resp.json()
                except ValueError as exc:
                    raise OpenRouterError(
                        f"OpenRouter returned non-JSON body: {resp.text[:300]}"
                    ) from exc
                if not isinstance(payload, dict):
                    raise OpenRouterError("OpenRouter returned an unexpected payload shape")
                return payload

            payload = {}
            try:
                parsed = resp.json()
                if isinstance(parsed, dict):
                    payload = parsed
            except ValueError:
                payload = {}

            detail = _error_detail(payload) or resp.text[:400]
            error = OpenRouterError(
                f"OpenRouter {resp.status_code}: {detail}",
                status_code=resp.status_code,
                payload=payload,
            )
            if resp.status_code in RETRYABLE_STATUS and attempt < self.max_retries - 1:
                last_error = error
                self._sleep(attempt, resp)
                continue
            raise error

        raise last_error or OpenRouterError("OpenRouter request failed")

    def _sleep(self, attempt: int, resp: Optional[httpx.Response] = None) -> None:
        if resp is not None:
            retry_after = resp.headers.get("retry-after")
            if retry_after:
                try:
                    time.sleep(min(float(retry_after), 30.0))
                    return
                except ValueError:
                    pass
        time.sleep(min(2.0 ** attempt, 15.0))

    @staticmethod
    def _to_result(data: dict[str, Any]) -> LLMResult:
        choices = data.get("choices") or []
        message = (choices[0].get("message") or {}) if choices else {}
        content = message.get("content")
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict) and block.get("type") in (None, "text"):
                    parts.append(str(block.get("text") or ""))
            content = "".join(parts)
        usage = data.get("usage") or {}
        return LLMResult(
            content=str(content or ""),
            model=str(data.get("model") or ""),
            finish_reason=str((choices[0].get("finish_reason") if choices else "") or ""),
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            total_tokens=int(usage.get("total_tokens") or 0),
            raw=data,
        )


def _error_detail(payload: dict[str, Any]) -> str:
    error = payload.get("error")
    if isinstance(error, dict):
        return str(error.get("message") or error)
    if isinstance(error, str):
        return error
    return ""


def extract_json_object(text: str) -> Optional[dict[str, Any]]:
    """Pull the first JSON object out of a model reply.

    Handles fenced code blocks (```json ... ```), leading prose, and trailing
    prose after the closing brace.
    """
    if not text:
        return None
    candidate = text.strip()

    fenced = re.search(r"```(?:json)?\s*(.+?)```", candidate, re.DOTALL)
    if fenced:
        candidate = fenced.group(1).strip()

    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
    except ValueError:
        pass

    start = candidate.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escaped = False
    for idx in range(start, len(candidate)):
        char = candidate[idx]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    parsed = json.loads(candidate[start:idx + 1])
                except ValueError:
                    return None
                return parsed if isinstance(parsed, dict) else None
    return None

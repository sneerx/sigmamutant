"""Loopback-only Ollama adapter for synthetic fixture proposals."""

from __future__ import annotations

import http.client
import json
import re
import socket
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from sigmamutant.ai.models import (
    FixtureSuggestionRequest,
    ProviderResponse,
    ProviderUsage,
    SuggestionBatch,
)
from sigmamutant.ai.prompt import SYSTEM_PROMPT, request_json
from sigmamutant.errors import ProviderError

DEFAULT_OLLAMA_MODEL = "qwen3.5:9b-q4_K_M"
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
MAX_RESPONSE_BYTES = 64 * 1024
_LOOPBACK_HOSTS = {"127.0.0.1", "::1"}

Transport = Callable[[dict[str, Any]], Any]


def _loopback_endpoint(base_url: str) -> tuple[str, int]:
    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except ValueError as exc:
        raise ProviderError(f"Invalid Ollama URL: {base_url!r}") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname not in _LOOPBACK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ProviderError(
            "The Ollama provider is local-only and accepts only a loopback "
            "HTTP URL such as http://127.0.0.1:11434."
        )
    return parsed.hostname, port or 80


def _error_message(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    error = value.get("error")
    if not isinstance(error, str) or not error.strip():
        return None
    return "".join(
        character if character.isprintable() else "?" for character in error.strip()
    )[:500]


def _response_usage(response: dict[str, Any]) -> ProviderUsage | None:
    input_tokens = response.get("prompt_eval_count")
    output_tokens = response.get("eval_count")
    if not (
        isinstance(input_tokens, int)
        and input_tokens >= 0
        and isinstance(output_tokens, int)
        and output_tokens >= 0
    ):
        return None
    return ProviderUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=input_tokens + output_tokens,
    )


class OllamaProvider:
    """Generate untrusted candidates with a local JSON-mode model."""

    name = "ollama"

    def __init__(
        self,
        model: str = DEFAULT_OLLAMA_MODEL,
        *,
        base_url: str = DEFAULT_OLLAMA_URL,
        timeout: float = 120.0,
        transport: Transport | None = None,
    ) -> None:
        if (
            not isinstance(model, str)
            or len(model) > 256
            or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9][A-Za-z0-9._-]*)?",
                model,
            )
        ):
            raise ProviderError("Ollama model must be a non-empty model identifier.")
        model_tag = model.casefold().rsplit(":", maxsplit=1)[-1]
        if model_tag == "cloud" or model_tag.endswith("-cloud"):
            raise ProviderError(
                "Cloud-routed Ollama models are not supported by the local-only "
                "provider."
            )
        self.model = model
        self.base_url = base_url
        self._host, self._port = _loopback_endpoint(base_url)
        self._timeout = timeout
        self._transport = transport or self._post_chat

    def _post_chat(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        connection = http.client.HTTPConnection(
            self._host,
            self._port,
            timeout=self._timeout,
        )
        try:
            connection.request(
                "POST",
                "/api/chat",
                body=body,
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        except (
            OSError,
            TimeoutError,
            socket.timeout,
            http.client.HTTPException,
        ) as exc:
            raise ProviderError(
                f"Ollama is not reachable at {self.base_url}. Start the local "
                "service with `ollama serve` and try again."
            ) from exc
        finally:
            connection.close()

        if len(raw) > MAX_RESPONSE_BYTES:
            raise ProviderError(
                f"Ollama response exceeded the {MAX_RESPONSE_BYTES}-byte safety limit."
            )
        try:
            document = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderError("Ollama returned a malformed JSON response.") from exc
        if not isinstance(document, dict):
            raise ProviderError("Ollama returned an invalid response envelope.")
        if response.status != 200:
            detail = _error_message(document) or f"HTTP {response.status}"
            if response.status == 404:
                detail = (
                    f"{detail}. Install the local model with "
                    f"`ollama pull {self.model}`."
                )
            raise ProviderError(f"Ollama request failed: {detail}")
        if error := _error_message(document):
            raise ProviderError(f"Ollama request failed: {error}")
        return document

    def suggest(self, request: FixtureSuggestionRequest) -> ProviderResponse:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": request_json(request)},
            ],
            "format": "json",
            "stream": False,
            "think": False,
            "keep_alive": 0,
            "options": {
                "temperature": 0,
                "num_ctx": 4096,
                "num_predict": 2048,
            },
        }
        try:
            response = self._transport(payload)
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(f"Ollama request failed: {exc}") from exc
        if not isinstance(response, dict):
            raise ProviderError("Ollama returned an invalid response envelope.")
        if error := _error_message(response):
            raise ProviderError(f"Ollama request failed: {error}")
        if response.get("done") is not True:
            raise ProviderError("Ollama response was incomplete.")
        done_reason = response.get("done_reason")
        if done_reason not in {None, "stop"}:
            raise ProviderError(f"Ollama response stopped early: {done_reason}")
        message = response.get("message")
        output_text = message.get("content") if isinstance(message, dict) else None
        if not isinstance(output_text, str) or not output_text.strip():
            raise ProviderError("Ollama returned no structured fixture suggestions.")
        try:
            batch = SuggestionBatch.model_validate_json(output_text)
        except ValidationError as exc:
            raise ProviderError(
                "Ollama output did not match the fixture suggestion schema"
            ) from exc
        return ProviderResponse(
            batch=batch,
            response_id=None,
            usage=_response_usage(response),
        )

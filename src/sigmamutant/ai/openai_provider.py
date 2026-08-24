"""Opt-in OpenAI Responses API adapter for synthetic fixture proposals."""

from __future__ import annotations

import os
import re
from typing import Any

from pydantic import ValidationError

from sigmamutant.ai.models import (
    FixtureSuggestionRequest,
    ProviderResponse,
    ProviderUsage,
    SuggestionBatch,
)
from sigmamutant.ai.prompt import SYSTEM_PROMPT, request_json
from sigmamutant.errors import ProviderError

DEFAULT_OPENAI_MODEL = "gpt-5.6-luna"
OPENAI_API_BASE_URL = "https://api.openai.com/v1"
_API_KEY_PATTERN = re.compile(r"sk-[A-Za-z0-9_.*-]{8,}")


def _safe_api_error(exc: Exception) -> str:
    """Return useful provider context without echoing credentials or headers."""

    body = getattr(exc, "body", None)
    message = body.get("message") if isinstance(body, dict) else None
    if not isinstance(message, str) or not message.strip():
        message = str(exc)
    message = "".join(
        character if character.isprintable() else " " for character in message
    )
    message = _API_KEY_PATTERN.sub("sk-***REDACTED***", message)
    message = " ".join(message.split())[:800]
    status = getattr(exc, "status_code", None)
    code = body.get("code") if isinstance(body, dict) else None
    prefix = " ".join(
        value
        for value in (
            f"HTTP {status}" if isinstance(status, int) else "",
            str(code) if isinstance(code, str) and code else "",
        )
        if value
    )
    return f"{prefix}: {message}" if prefix else message


def _response_usage(response: Any) -> ProviderUsage | None:
    usage = getattr(response, "usage", None)
    values = (
        getattr(usage, "input_tokens", None),
        getattr(usage, "output_tokens", None),
        getattr(usage, "total_tokens", None),
    )
    if not all(isinstance(value, int) and value >= 0 for value in values):
        return None
    input_details = getattr(usage, "input_tokens_details", None)
    output_details = getattr(usage, "output_tokens_details", None)

    def optional_count(value: Any) -> int | None:
        return value if isinstance(value, int) and value >= 0 else None

    return ProviderUsage(
        input_tokens=values[0],
        output_tokens=values[1],
        total_tokens=values[2],
        cached_tokens=optional_count(getattr(input_details, "cached_tokens", None)),
        cache_write_tokens=optional_count(
            getattr(input_details, "cache_write_tokens", None)
        ),
        reasoning_tokens=optional_count(
            getattr(output_details, "reasoning_tokens", None)
        ),
    )


def _response_was_refused(response: Any) -> bool:
    output = getattr(response, "output", ())
    if not isinstance(output, (list, tuple)):
        return False
    for item in output:
        content = (
            item.get("content")
            if isinstance(item, dict)
            else getattr(item, "content", ())
        )
        if not isinstance(content, (list, tuple)):
            continue
        for part in content:
            part_type = (
                part.get("type")
                if isinstance(part, dict)
                else getattr(part, "type", None)
            )
            if part_type == "refusal":
                return True
    return False


class OpenAIProvider:
    """Generate untrusted candidates with strict structured output."""

    name = "openai"

    def __init__(
        self,
        model: str = DEFAULT_OPENAI_MODEL,
        *,
        client: Any | None = None,
    ) -> None:
        self.model = model
        if client is not None:
            self._client = client
            return
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ProviderError(
                "OPENAI_API_KEY is not set. Export it locally; never put API "
                "keys in a suite, fixture, or command argument."
            )
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ProviderError(
                "OpenAI support is optional. Install it with "
                '`python -m pip install -e ".[ai]"`.'
            ) from exc
        self._client = OpenAI(
            api_key=api_key,
            base_url=OPENAI_API_BASE_URL,
            timeout=60.0,
            max_retries=0,
        )

    def suggest(self, request: FixtureSuggestionRequest) -> ProviderResponse:
        schema = SuggestionBatch.model_json_schema()
        try:
            response = self._client.responses.create(
                model=self.model,
                instructions=SYSTEM_PROMPT,
                input=request_json(request),
                text={
                    "verbosity": "low",
                    "format": {
                        "type": "json_schema",
                        "name": "sigmamutant_fixture_suggestions",
                        "strict": True,
                        "schema": schema,
                    },
                },
                reasoning={"effort": "low"},
                max_output_tokens=2048,
                prompt_cache_options={"mode": "explicit"},
                service_tier="default",
                store=False,
            )
        except Exception as exc:
            detail = _safe_api_error(exc)
            raise ProviderError(
                f"OpenAI Responses API request failed: {detail}"
            ) from exc
        status = getattr(response, "status", None)
        if status == "incomplete":
            details = getattr(response, "incomplete_details", None)
            reason = getattr(details, "reason", "unknown")
            raise ProviderError(f"OpenAI response was incomplete: {reason}")
        if status not in {None, "completed"}:
            raise ProviderError("OpenAI response ended with an unexpected status.")
        if _response_was_refused(response):
            raise ProviderError("OpenAI response was refused by provider safeguards.")
        output_text = getattr(response, "output_text", None)
        if not isinstance(output_text, str) or not output_text.strip():
            raise ProviderError(
                "OpenAI returned no structured fixture suggestions "
                "(the response may have been refused or incomplete)."
            )
        try:
            batch = SuggestionBatch.model_validate_json(output_text)
        except ValidationError as exc:
            raise ProviderError(
                "OpenAI output did not match the fixture suggestion schema"
            ) from exc
        response_id = getattr(response, "id", None)
        if response_id is not None:
            response_id = str(response_id)
        return ProviderResponse(
            batch=batch,
            response_id=response_id,
            usage=_response_usage(response),
        )

from __future__ import annotations

import json
import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from sigmamutant.ai.models import (
    FixtureSuggestionRequest,
    SuggestionBatch,
)
from sigmamutant.ai.openai_provider import OPENAI_API_BASE_URL, OpenAIProvider
from sigmamutant.ai.prompt import SYSTEM_PROMPT
from sigmamutant.errors import ProviderError


def _request() -> FixtureSuggestionRequest:
    return FixtureSuggestionRequest(
        rule_title="Synthetic process rule",
        detection={
            "selection": {"Image|endswith": "\\cmd.exe"},
            "condition": "selection",
        },
        mutant_id="mutant-123",
        operator="modifier_to_exact",
        path="detection.selection.Image|endswith",
        description="Changed suffix comparison to exact",
        original="Image|endswith",
        replacement="Image",
        fixture_shape=(
            {
                "expected": True,
                "fields": [{"name": "Image", "type": "string"}],
            },
        ),
        candidate_count=1,
    )


class _FakeResponses:
    def __init__(
        self,
        *,
        response: Any | None = None,
        error: Exception | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


class _FakeClient:
    def __init__(self, responses: _FakeResponses) -> None:
        self.responses = responses


def test_openai_provider_pins_official_endpoint_and_ignores_environment_override(
    monkeypatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeOpenAI:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    fake_module = ModuleType("openai")
    fake_module.OpenAI = FakeOpenAI  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "openai", fake_module)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-endpoint-pinning")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://attacker.invalid/v1")

    provider = OpenAIProvider()

    assert provider.model
    assert captured["api_key"] == "sk-test-endpoint-pinning"
    assert captured["base_url"] == OPENAI_API_BASE_URL
    assert captured["base_url"] != "https://attacker.invalid/v1"
    assert captured["timeout"] == 60.0
    assert captured["max_retries"] == 0


def _valid_output() -> str:
    return json.dumps(
        {
            "candidates": [
                {
                    "candidate_id": "candidate-1",
                    "rationale": "Tests the suffix boundary.",
                    "fields": [
                        {
                            "name": "Image",
                            "value": r"C:\Windows\cmd.exe",
                        }
                    ],
                }
            ]
        }
    )


def test_openai_provider_uses_strict_responses_json_schema_contract() -> None:
    responses = _FakeResponses(
        response=SimpleNamespace(
            output_text=_valid_output(),
            id=12345,
            usage=SimpleNamespace(
                input_tokens=120,
                output_tokens=45,
                total_tokens=165,
                input_tokens_details=SimpleNamespace(
                    cached_tokens=0,
                    cache_write_tokens=0,
                ),
                output_tokens_details=SimpleNamespace(
                    reasoning_tokens=12,
                ),
            ),
        )
    )
    provider = OpenAIProvider(
        model="gpt-test-model",
        client=_FakeClient(responses),
    )

    result = provider.suggest(_request())

    assert result.response_id == "12345"
    assert result.usage is not None
    assert result.usage.input_tokens == 120
    assert result.usage.output_tokens == 45
    assert result.usage.total_tokens == 165
    assert result.usage.cached_tokens == 0
    assert result.usage.cache_write_tokens == 0
    assert result.usage.reasoning_tokens == 12
    assert len(result.batch.candidates) == 1
    assert result.batch.candidates[0].candidate_id == "candidate-1"

    assert len(responses.calls) == 1
    kwargs = responses.calls[0]
    assert kwargs["model"] == "gpt-test-model"
    assert kwargs["instructions"] == SYSTEM_PROMPT
    assert json.loads(kwargs["input"])["candidate_count"] == 1
    assert kwargs["store"] is False
    assert kwargs["max_output_tokens"] == 2048
    assert kwargs["reasoning"] == {"effort": "low"}
    assert kwargs["prompt_cache_options"] == {"mode": "explicit"}
    assert kwargs["service_tier"] == "default"
    assert "tools" not in kwargs

    response_format = kwargs["text"]["format"]
    assert kwargs["text"]["verbosity"] == "low"
    assert response_format["type"] == "json_schema"
    assert response_format["name"] == "sigmamutant_fixture_suggestions"
    assert response_format["strict"] is True
    assert response_format["schema"] == SuggestionBatch.model_json_schema()


@pytest.mark.parametrize("output_text", [None, "", "   "])
def test_openai_provider_rejects_empty_structured_output(
    output_text: str | None,
) -> None:
    responses = _FakeResponses(
        response=SimpleNamespace(output_text=output_text, id="response-empty")
    )
    provider = OpenAIProvider(client=_FakeClient(responses))

    with pytest.raises(ProviderError, match="no structured fixture suggestions"):
        provider.suggest(_request())


@pytest.mark.parametrize(
    "output_text",
    [
        "{}",
        '{"candidates":[]}',
        (
            '{"candidates":[{"candidate_id":"x","rationale":"why",'
            '"fields":[{"name":"Image","value":{"nested":true}}]}]}'
        ),
    ],
)
def test_openai_provider_rejects_output_outside_schema(
    output_text: str,
) -> None:
    responses = _FakeResponses(
        response=SimpleNamespace(output_text=output_text, id="invalid")
    )
    provider = OpenAIProvider(client=_FakeClient(responses))

    with pytest.raises(ProviderError, match="did not match"):
        provider.suggest(_request())


def test_openai_provider_wraps_responses_api_exception() -> None:
    responses = _FakeResponses(error=RuntimeError("synthetic API outage"))
    provider = OpenAIProvider(client=_FakeClient(responses))

    with pytest.raises(
        ProviderError,
        match="Responses API request failed.*synthetic API outage",
    ):
        provider.suggest(_request())

    assert len(responses.calls) == 1


def test_openai_provider_redacts_api_keys_from_errors() -> None:
    exposed_key = "sk-test-this-must-never-reach-terminal-output"
    responses = _FakeResponses(
        error=RuntimeError(f"Incorrect API key provided: {exposed_key}")
    )
    provider = OpenAIProvider(client=_FakeClient(responses))

    with pytest.raises(ProviderError) as captured:
        provider.suggest(_request())

    message = str(captured.value)
    assert exposed_key not in message
    assert "sk-***REDACTED***" in message


def test_openai_provider_rejects_incomplete_response() -> None:
    responses = _FakeResponses(
        response=SimpleNamespace(
            status="incomplete",
            incomplete_details=SimpleNamespace(reason="max_output_tokens"),
            output_text=_valid_output(),
            id="incomplete",
        )
    )
    provider = OpenAIProvider(client=_FakeClient(responses))

    with pytest.raises(ProviderError, match="incomplete.*max_output_tokens"):
        provider.suggest(_request())


def test_openai_provider_rejects_refusal_without_echoing_refusal_text() -> None:
    refusal_text = "sensitive-provider-refusal-details"
    responses = _FakeResponses(
        response=SimpleNamespace(
            status="completed",
            output=[
                SimpleNamespace(
                    content=[
                        SimpleNamespace(
                            type="refusal",
                            refusal=refusal_text,
                        )
                    ]
                )
            ],
            output_text="",
            id="refused",
        )
    )
    provider = OpenAIProvider(client=_FakeClient(responses))

    with pytest.raises(ProviderError, match="refused") as captured:
        provider.suggest(_request())

    assert refusal_text not in str(captured.value)


def test_openai_provider_rejects_unexpected_response_status() -> None:
    responses = _FakeResponses(
        response=SimpleNamespace(
            status="failed",
            output_text=_valid_output(),
            id="failed",
        )
    )
    provider = OpenAIProvider(client=_FakeClient(responses))

    with pytest.raises(ProviderError, match="unexpected status"):
        provider.suggest(_request())

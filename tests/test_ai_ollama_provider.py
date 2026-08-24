from __future__ import annotations

import json
from typing import Any

import pytest

import sigmamutant.ai.ollama_provider as ollama_module
from sigmamutant.ai.models import (
    FixtureSuggestionRequest,
)
from sigmamutant.ai.ollama_provider import MAX_RESPONSE_BYTES, OllamaProvider
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


class _CapturingTransport:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def __call__(self, payload: dict[str, Any]) -> Any:
        self.calls.append(payload)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _response(content: str = "") -> dict[str, Any]:
    return {
        "model": "qwen3.5:9b-q4_K_M",
        "message": {"role": "assistant", "content": content or _valid_output()},
        "done": True,
        "done_reason": "stop",
        "prompt_eval_count": 100,
        "eval_count": 25,
    }


def test_ollama_provider_uses_local_structured_output_contract() -> None:
    transport = _CapturingTransport(_response())
    provider = OllamaProvider(
        model="qwen-test:9b",
        transport=transport,
    )

    result = provider.suggest(_request())

    assert result.response_id is None
    assert result.usage is not None
    assert result.usage.input_tokens == 100
    assert result.usage.output_tokens == 25
    assert result.usage.total_tokens == 125
    assert len(result.batch.candidates) == 1
    assert result.batch.candidates[0].candidate_id == "candidate-1"
    assert len(transport.calls) == 1

    payload = transport.calls[0]
    assert payload["model"] == "qwen-test:9b"
    assert payload["stream"] is False
    assert payload["think"] is False
    assert payload["keep_alive"] == 0
    assert payload["format"] == "json"
    assert payload["options"] == {
        "temperature": 0,
        "num_ctx": 4096,
        "num_predict": 2048,
    }
    assert payload["messages"][0] == {
        "role": "system",
        "content": SYSTEM_PROMPT,
    }
    request_payload = json.loads(payload["messages"][1]["content"])
    assert request_payload["candidate_count"] == 1
    assert "tools" not in payload


@pytest.mark.parametrize(
    ("response", "message"),
    [
        ({}, "incomplete"),
        ({"done": True, "message": {"content": ""}}, "no structured"),
        (
            {
                "done": True,
                "done_reason": "length",
                "message": {"content": _valid_output()},
            },
            "stopped early",
        ),
        (
            {"done": True, "message": {"content": "{}"}},
            "did not match",
        ),
        ({"error": "synthetic local failure"}, "synthetic local failure"),
        ("not-an-envelope", "invalid response envelope"),
    ],
)
def test_ollama_provider_fails_closed_on_invalid_responses(
    response: Any,
    message: str,
) -> None:
    provider = OllamaProvider(transport=_CapturingTransport(response))

    with pytest.raises(ProviderError, match=message):
        provider.suggest(_request())


def test_ollama_provider_wraps_transport_failure() -> None:
    provider = OllamaProvider(
        transport=_CapturingTransport(RuntimeError("synthetic transport failure"))
    )

    with pytest.raises(ProviderError, match="synthetic transport failure"):
        provider.suggest(_request())


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:11434",
        "http://192.0.2.1:11434",
        "http://user:password@127.0.0.1:11434",
        "http://127.0.0.1:11434/unexpected",
    ],
)
def test_ollama_provider_rejects_non_loopback_or_ambiguous_urls(url: str) -> None:
    with pytest.raises(ProviderError, match="local-only"):
        OllamaProvider(base_url=url, transport=_CapturingTransport(_response()))


@pytest.mark.parametrize(
    "model",
    ["", "qwen 3.5", "qwen3.5:cloud", "qwen3.5:397b-cloud"],
)
def test_ollama_provider_rejects_unsafe_model_identifiers(model: str) -> None:
    with pytest.raises(ProviderError):
        OllamaProvider(model=model, transport=_CapturingTransport(_response()))


class _FakeHTTPResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.body = body
        self.read_limit: int | None = None

    def read(self, limit: int) -> bytes:
        self.read_limit = limit
        return self.body


class _FakeHTTPConnection:
    response = _FakeHTTPResponse(200, b"{}")
    instances: list["_FakeHTTPConnection"] = []
    request_error: Exception | None = None

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.requests: list[dict[str, Any]] = []
        self.closed = False
        type(self).instances.append(self)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes,
        headers: dict[str, str],
    ) -> None:
        self.requests.append(
            {
                "method": method,
                "path": path,
                "body": body,
                "headers": headers,
            }
        )
        if self.request_error is not None:
            raise self.request_error

    def getresponse(self) -> _FakeHTTPResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def _install_fake_http(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status: int,
    body: bytes,
    error: Exception | None = None,
) -> None:
    _FakeHTTPConnection.instances = []
    _FakeHTTPConnection.response = _FakeHTTPResponse(status, body)
    _FakeHTTPConnection.request_error = error
    monkeypatch.setattr(
        ollama_module.http.client,
        "HTTPConnection",
        _FakeHTTPConnection,
    )


def test_stdlib_transport_posts_canonical_chat_request_to_numeric_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = json.dumps(_response()).encode("utf-8")
    _install_fake_http(monkeypatch, status=200, body=envelope)
    provider = OllamaProvider(
        model="qwen-test:9b",
        base_url="http://127.0.0.1:12345/",
        timeout=7.5,
    )

    result = provider.suggest(_request())

    assert result.batch.candidates[0].candidate_id == "candidate-1"
    assert len(_FakeHTTPConnection.instances) == 1
    connection = _FakeHTTPConnection.instances[0]
    assert (connection.host, connection.port, connection.timeout) == (
        "127.0.0.1",
        12345,
        7.5,
    )
    assert connection.closed is True
    assert connection.response.read_limit == MAX_RESPONSE_BYTES + 1
    assert len(connection.requests) == 1

    request = connection.requests[0]
    assert request["method"] == "POST"
    assert request["path"] == "/api/chat"
    assert request["headers"] == {"Content-Type": "application/json"}
    payload = json.loads(request["body"])
    assert payload["model"] == "qwen-test:9b"
    assert payload["stream"] is False
    assert payload["format"] == "json"
    assert payload["messages"][0]["role"] == "system"
    assert payload["messages"][1]["role"] == "user"


def test_stdlib_transport_404_includes_local_model_pull_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = json.dumps({"error": "model not found"}).encode("utf-8")
    _install_fake_http(monkeypatch, status=404, body=body)
    provider = OllamaProvider(model="qwen-test:9b")

    with pytest.raises(
        ProviderError,
        match=r"model not found.*ollama pull qwen-test:9b",
    ):
        provider.suggest(_request())

    assert _FakeHTTPConnection.instances[0].closed is True


@pytest.mark.parametrize(
    ("body", "message"),
    [
        pytest.param(b"{not-json", "malformed JSON", id="malformed-json"),
        pytest.param(b"\xff\xfe", "malformed JSON", id="invalid-utf8"),
        pytest.param(
            b"x" * (MAX_RESPONSE_BYTES + 1),
            "exceeded",
            id="oversized-response",
        ),
    ],
)
def test_stdlib_transport_rejects_malformed_or_oversized_response(
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
    message: str,
) -> None:
    _install_fake_http(monkeypatch, status=200, body=body)
    provider = OllamaProvider()

    with pytest.raises(ProviderError, match=message):
        provider.suggest(_request())

    connection = _FakeHTTPConnection.instances[0]
    assert connection.response.read_limit == MAX_RESPONSE_BYTES + 1
    assert connection.closed is True


def test_stdlib_transport_wraps_connection_error_and_always_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_http(
        monkeypatch,
        status=200,
        body=b"{}",
        error=ConnectionRefusedError("connection refused"),
    )
    provider = OllamaProvider(base_url="http://127.0.0.1:11434")

    with pytest.raises(
        ProviderError,
        match=r"not reachable.*ollama serve",
    ):
        provider.suggest(_request())

    assert _FakeHTTPConnection.instances[0].closed is True


@pytest.mark.parametrize(
    ("url", "host", "port"),
    [
        ("http://127.0.0.1", "127.0.0.1", 80),
        ("http://127.0.0.1:11434/", "127.0.0.1", 11434),
        ("http://[::1]", "::1", 80),
        ("http://[::1]:11434/", "::1", 11434),
    ],
)
def test_numeric_loopback_urls_are_normalized_without_dns(
    url: str,
    host: str,
    port: int,
) -> None:
    provider = OllamaProvider(
        base_url=url,
        transport=_CapturingTransport(_response()),
    )

    assert provider._host == host
    assert provider._port == port


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:11434",
        "http://localhost.:11434",
        "http://2130706433:11434",
        "http://[::ffff:127.0.0.1]:11434",
    ],
)
def test_dns_and_alternative_loopback_spellings_are_rejected(url: str) -> None:
    with pytest.raises(ProviderError, match="local-only"):
        OllamaProvider(
            base_url=url,
            transport=_CapturingTransport(_response()),
        )

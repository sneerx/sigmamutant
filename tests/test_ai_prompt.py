from __future__ import annotations

import json

import pytest

from sigmamutant.ai.models import FixtureSuggestionRequest
from sigmamutant.ai.prompt import (
    MAX_PROVIDER_INPUT_BYTES,
    request_json,
    required_field_contracts,
)
from sigmamutant.errors import FixtureSuggestionError
from sigmamutant.mutations import OPERATORS


def _request(
    detection,
    *,
    operator: str = "delete_predicate",
) -> FixtureSuggestionRequest:
    return FixtureSuggestionRequest(
        rule_title="This title must stay local",
        detection=detection,
        mutant_id="mutant-1",
        operator=operator,
        path="detection.selection.Image",
        description="Deleted one predicate",
        original="value",
        replacement=None,
        fixture_shape=(
            {
                "expected": True,
                "fields": [{"name": "Image", "type": "string"}],
            },
        ),
        candidate_count=1,
    )


def test_provider_payload_omits_rule_title() -> None:
    payload = request_json(
        _request({"selection": {"Image": "synthetic"}, "condition": "selection"})
    )

    assert "This title must stay local" not in payload
    assert '"detection"' in payload


def test_provider_payload_includes_operator_specific_strategy_hint() -> None:
    payload = json.loads(
        request_json(
            _request(
                {
                    "selection": {"Image": "synthetic"},
                    "condition": "selection",
                }
            )
        )
    )

    assert "deleted original predicate" in payload["mutation"]["strategy_hint"]


@pytest.mark.parametrize("operator", [item.name for item in OPERATORS])
def test_every_mutation_operator_has_a_specific_strategy_hint(operator: str) -> None:
    payload = json.loads(
        request_json(
            _request(
                {
                    "selection": {"Image": "synthetic"},
                    "condition": "selection",
                },
                operator=operator,
            )
        )
    )

    assert not payload["mutation"]["strategy_hint"].startswith("Isolate the mutation")


def test_required_field_contract_uses_intersection_and_observed_types() -> None:
    contracts = required_field_contracts(
        (
            {
                "expected": True,
                "fields": [
                    {"name": "Image", "type": "string"},
                    {"name": "ProcessId", "type": "integer"},
                    {"name": "OnlyPositive", "type": "string"},
                ],
            },
            {
                "expected": False,
                "fields": [
                    {"name": "Image", "type": "string"},
                    {"name": "ProcessId", "type": "number"},
                ],
            },
        )
    )

    assert [(item.name, item.json_types) for item in contracts] == [
        ("Image", ("string",)),
        ("ProcessId", ("integer", "number")),
    ]


def test_required_field_contract_rejects_impossible_non_scalar_candidate() -> None:
    with pytest.raises(FixtureSuggestionError, match="Payload.*array.*scalar"):
        required_field_contracts(
            (
                {
                    "expected": True,
                    "fields": [{"name": "Payload", "type": "array"}],
                },
                {
                    "expected": False,
                    "fields": [{"name": "Payload", "type": "array"}],
                },
            )
        )


def test_required_field_contract_keeps_supported_type_from_mixed_shapes() -> None:
    contracts = required_field_contracts(
        (
            {
                "expected": True,
                "fields": [{"name": "Payload", "type": "array"}],
            },
            {
                "expected": False,
                "fields": [{"name": "Payload", "type": "string"}],
            },
        )
    )

    assert [(item.name, item.json_types) for item in contracts] == [
        ("Payload", ("string",)),
    ]


def test_provider_input_size_limit_fails_closed() -> None:
    oversized = "x" * (MAX_PROVIDER_INPUT_BYTES + 1)

    with pytest.raises(FixtureSuggestionError, match="safety limit"):
        request_json(
            _request(
                {
                    "selection": {"CommandLine|contains": oversized},
                    "condition": "selection",
                }
            )
        )

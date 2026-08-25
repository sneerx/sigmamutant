from __future__ import annotations

import copy
import re
from typing import Any

import pytest

from sigmamutant.event_variations import (
    EVENT_OPERATORS,
    EventVariationLimitError,
    generate_event_variations,
)
from sigmamutant.models import Fixture


def _rule() -> dict[str, Any]:
    return {
        "title": "PowerShell 7 encoded command",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {
                "Image|endswith": "\\pwsh.exe",
                "CommandLine|contains": " -EncodedCommand ",
                "ParentImage|endswith": "\\explorer.exe",
                "User": "DOMAIN\\alice",
            },
            "condition": "selection",
        },
    }


def _positive(
    *,
    fixture_id: str = "positive-pwsh",
    image: str = r"C:\Program Files\PowerShell\7\pwsh.exe",
    command_line: str = "pwsh.exe -EncodedCommand QQ==",
) -> Fixture:
    return Fixture(
        id=fixture_id,
        expected=True,
        event={
            "Image": image,
            "CommandLine": command_line,
            "ParentImage": r"C:\Windows\explorer.exe",
            "User": r"DOMAIN\alice",
        },
    )


def test_registry_contains_only_the_conservative_v0_operators() -> None:
    assert {operator.name for operator in EVENT_OPERATORS} == {
        "ascii_case",
        "command_line_whitespace",
        "telemetry_path_to_basename",
        "pwsh_encoded_alias",
    }


def test_variations_keep_complete_scoped_reproof_evidence() -> None:
    variations = generate_event_variations(_rule(), [_positive()])

    assert variations
    assert {variation.operator for variation in variations} == {
        "ascii_case",
        "command_line_whitespace",
        "telemetry_path_to_basename",
        "pwsh_encoded_alias",
    }
    assert all(
        variation.source_fixture_id == "positive-pwsh" for variation in variations
    )
    assert all(variation.field in variation.event for variation in variations)
    assert all(variation.path == f"/{variation.field}" for variation in variations)
    assert all(variation.original != variation.replacement for variation in variations)
    assert all(variation.claim_scope for variation in variations)
    assert all(re.fullmatch(r"[0-9a-f]{16}", variation.id) for variation in variations)


def test_pwsh_alias_operator_uses_only_curated_aliases_and_preserves_payload() -> None:
    variations = [
        variation
        for variation in generate_event_variations(_rule(), [_positive()])
        if variation.operator == "pwsh_encoded_alias"
    ]

    assert {variation.event["CommandLine"] for variation in variations} == {
        "pwsh.exe -e QQ==",
        "pwsh.exe -ec QQ==",
    }
    assert all(
        variation.event["CommandLine"].endswith(" QQ==") for variation in variations
    )
    assert not any("/" in variation.event["CommandLine"] for variation in variations)
    assert not any(":" in variation.event["CommandLine"] for variation in variations)


def test_pwsh_alias_operator_allows_only_safe_flag_prefixes() -> None:
    fixture = _positive(command_line="pwsh.exe -NoLogo -NoProfile -EncodedCommand QQ==")

    replacements = {
        variation.replacement
        for variation in generate_event_variations(_rule(), [fixture])
        if variation.operator == "pwsh_encoded_alias"
    }

    assert replacements == {
        "pwsh.exe -NoLogo -NoProfile -e QQ==",
        "pwsh.exe -NoLogo -NoProfile -ec QQ==",
    }


def test_pwsh_alias_operator_rejects_powershell_enc_and_ambiguous_inputs() -> None:
    fixtures = [
        _positive(fixture_id="windows", image="powershell.exe"),
        _positive(fixture_id="enc", command_line="pwsh.exe -enc QQ=="),
        _positive(
            fixture_id="duplicate",
            command_line="pwsh.exe -e QQ== -ec SECOND",
        ),
        _positive(fixture_id="missing-payload", command_line="pwsh.exe -e"),
        _positive(
            fixture_id="script-argument",
            command_line="pwsh.exe -File script.ps1 -e QQ==",
        ),
        _positive(
            fixture_id="trailing-token",
            command_line="pwsh.exe -e QQ== trailing",
        ),
        _positive(
            fixture_id="invalid-base64",
            command_line="pwsh.exe -e not_base64",
        ),
        _positive(
            fixture_id="value-switch-prefix",
            command_line="pwsh.exe -ExecutionPolicy Bypass -e QQ==",
        ),
        _positive(
            fixture_id="short-prefix",
            command_line="pwsh.exe -nop -e QQ==",
        ),
        _positive(
            fixture_id="interactive-prefix",
            command_line="pwsh.exe -Interactive -e QQ==",
        ),
        _positive(
            fixture_id="login-prefix",
            command_line="pwsh.exe -Login -e QQ==",
        ),
        _positive(
            fixture_id="ssh-server-prefix",
            command_line="pwsh.exe -SSHServerMode -e QQ==",
        ),
    ]

    variations = generate_event_variations(_rule(), fixtures)

    assert not [item for item in variations if item.operator == "pwsh_encoded_alias"]


def test_whitespace_variation_preserves_tokens_quotes_and_payload_bytes() -> None:
    command_line = 'pwsh.exe -NoProfile "argument with spaces" -EncodedCommand QQ=='
    fixture = _positive(command_line=command_line)

    variations = [
        variation
        for variation in generate_event_variations(_rule(), [fixture])
        if variation.operator == "command_line_whitespace"
    ]

    assert len(variations) == 1
    replacement = variations[0].event["CommandLine"]
    assert replacement == (
        'pwsh.exe  -NoProfile  "argument with spaces"  -EncodedCommand  QQ=='
    )
    assert '"argument with spaces"' in replacement
    assert replacement.endswith("QQ==")


def test_whitespace_normalizes_existing_ascii_separators_only() -> None:
    fixture = _positive(command_line="pwsh.exe\t\t-EncodedCommand   QQ==")

    replacements = {
        variation.replacement
        for variation in generate_event_variations(_rule(), [fixture])
        if variation.operator == "command_line_whitespace"
    }

    assert replacements == {
        "pwsh.exe -EncodedCommand QQ==",
        "pwsh.exe  -EncodedCommand  QQ==",
    }


def test_ambiguous_unmatched_quotes_disable_token_aware_operators() -> None:
    fixture = _positive(command_line='pwsh.exe "unterminated -EncodedCommand QQ==')

    operators = {
        variation.operator
        for variation in generate_event_variations(_rule(), [fixture])
    }

    assert "command_line_whitespace" not in operators
    assert "pwsh_encoded_alias" not in operators


def test_path_shape_only_changes_referenced_image_fields() -> None:
    fixture = _positive()
    fixture.event["UnreferencedPath"] = r"C:\Temp\sample.exe"

    variations = [
        variation
        for variation in generate_event_variations(_rule(), [fixture])
        if variation.operator == "telemetry_path_to_basename"
    ]

    assert {(item.field, item.replacement) for item in variations} == {
        ("Image", "pwsh.exe"),
        ("ParentImage", "explorer.exe"),
    }


def test_ascii_case_is_limited_to_uncased_image_path_fields() -> None:
    rule = _rule()
    value = rule["detection"]["selection"].pop("User")
    rule["detection"]["selection"]["User|cased"] = value

    variations = [
        variation
        for variation in generate_event_variations(rule, [_positive()])
        if variation.operator == "ascii_case"
    ]

    assert {variation.field for variation in variations} == {"Image", "ParentImage"}
    assert all(variation.field != "CommandLine" for variation in variations)


def test_ascii_case_never_rewrites_alternate_command_line_or_payload_fields() -> None:
    rule = {
        "title": "Alternate command-line field",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {
                "process.command_line|contains": "-EncodedCommand",
                "Payload": "QQ==",
            },
            "condition": "selection",
        },
    }
    fixture = Fixture(
        id="positive",
        expected=True,
        event={
            "process.command_line": "pwsh.exe -EncodedCommand QQ==",
            "Payload": "QQ==",
        },
    )

    assert not [
        variation
        for variation in generate_event_variations(rule, [fixture])
        if variation.operator == "ascii_case"
    ]


def test_value_insensitive_exists_fields_do_not_generate_variations() -> None:
    rule = {
        "title": "Presence-only process telemetry",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {
                "Image|exists": True,
                "CommandLine|exists": True,
                "ParentImage|exists": True,
            },
            "condition": "selection",
        },
    }
    fixture = Fixture(
        id="positive",
        expected=True,
        event={
            "Image": r"C:\Program Files\PowerShell\7\pwsh.exe",
            "CommandLine": "pwsh.exe -EncodedCommand QQ==",
            "ParentImage": r"C:\Windows\explorer.exe",
        },
    )

    assert generate_event_variations(rule, [fixture]) == []


@pytest.mark.parametrize(
    "modifier",
    ("base64", "base64offset", "cidr", "exists", "gt", "utf16", "wide"),
)
def test_non_plain_string_modifiers_do_not_enable_path_variations(
    modifier: str,
) -> None:
    rule = {
        "title": "Non-plain Image predicate",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {f"Image|{modifier}": True},
            "condition": "selection",
        },
    }
    fixture = Fixture(
        id="positive",
        expected=True,
        event={"Image": r"C:\Program Files\PowerShell\7\pwsh.exe"},
    )

    assert generate_event_variations(rule, [fixture]) == []


@pytest.mark.parametrize("rule_value", [123, True, [1, 2], [False, 3]])
def test_exact_non_string_predicates_do_not_enable_path_variations(
    rule_value: object,
) -> None:
    rule = {
        "title": "Non-string exact Image predicate",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"Image": rule_value},
            "condition": "selection",
        },
    }
    fixture = Fixture(
        id="positive",
        expected=True,
        event={"Image": r"C:\Program Files\PowerShell\7\pwsh.exe"},
    )

    assert generate_event_variations(rule, [fixture]) == []


def test_string_alternative_in_mixed_exact_list_enables_path_variations() -> None:
    rule = {
        "title": "Mixed Image alternatives",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"Image": [123, "pwsh.exe"]},
            "condition": "selection",
        },
    }
    fixture = Fixture(
        id="positive",
        expected=True,
        event={"Image": r"C:\Program Files\PowerShell\7\pwsh.exe"},
    )

    assert {
        variation.operator for variation in generate_event_variations(rule, [fixture])
    } == {"ascii_case", "telemetry_path_to_basename"}


def test_generation_is_stable_deduplicated_and_does_not_mutate_inputs() -> None:
    rule = _rule()
    fixtures = [_positive(fixture_id="z"), _positive(fixture_id="a")]
    pristine_rule = copy.deepcopy(rule)
    pristine_fixtures = copy.deepcopy(fixtures)

    first = generate_event_variations(rule, fixtures, b"canonical-rule")
    second = generate_event_variations(rule, fixtures, b"canonical-rule")

    projection = [
        (
            variation.id,
            variation.source_fixture_id,
            variation.operator,
            variation.path,
            variation.event,
        )
        for variation in first
    ]
    assert projection == [
        (
            variation.id,
            variation.source_fixture_id,
            variation.operator,
            variation.path,
            variation.event,
        )
        for variation in second
    ]
    assert len({variation.id for variation in first}) == len(first)
    assert rule == pristine_rule
    assert fixtures == pristine_fixtures
    assert [item.source_fixture_id for item in first] == sorted(
        item.source_fixture_id for item in first
    )


def test_negative_fixtures_are_never_used_as_variation_seeds() -> None:
    negative = Fixture(id="negative", expected=False, event=_positive().event)

    assert generate_event_variations(_rule(), [negative]) == []


def test_generation_enforces_a_hard_variation_limit() -> None:
    with pytest.raises(EventVariationLimitError, match="max-variations=1"):
        generate_event_variations(_rule(), [_positive()], max_variations=1)

    assert len(generate_event_variations(_rule(), [_positive()], max_variations=7)) == 7


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_generation_rejects_invalid_variation_limits(limit: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        generate_event_variations(
            _rule(),
            [_positive()],
            max_variations=limit,  # type: ignore[arg-type]
        )

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sigmamutant.errors import EvaluationError, RuleError, SuiteError
from sigmamutant.evaluator import SigmaEvaluator, validate_supported_rule
from sigmamutant.suite import (
    _load_fixtures,
    _load_suite_document,
    _parse_config,
    _parse_fixture,
    _resolve_child,
    load_suite,
)
from sigmamutant.yamlio import dump_yaml, load_single_yaml


def _minimal_rule() -> dict[str, Any]:
    return {
        "title": "Minimal",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"Image": "cmd.exe"},
            "condition": "selection",
        },
    }


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "mapping"),
        ({"logsource": {}, "detection": {}}, "title"),
        ({"title": "x", "logsource": "bad", "detection": {}}, "logsource"),
        ({"title": "x", "logsource": {}}, "detection"),
        (
            {"title": "x", "logsource": {}, "detection": {"selection": {}}},
            "condition",
        ),
        (
            {"title": "x", "logsource": {}, "detection": {"condition": "selection"}},
            "selector",
        ),
        (
            {
                "title": "x",
                "logsource": {},
                "detection": {1: {"Image": "x"}, "condition": "selection"},
            },
            "Selector names",
        ),
        (
            {
                "title": "x",
                "logsource": {},
                "detection": {"selection": ["keyword"], "condition": "selection"},
            },
            "Keyword-only",
        ),
        (
            {
                "title": "x",
                "logsource": {},
                "detection": {"selection": {}, "condition": "selection"},
            },
            "non-empty field mapping",
        ),
        (
            {
                "title": "x",
                "logsource": {},
                "detection": {
                    "selection": {"": "value"},
                    "condition": "selection",
                },
            },
            "invalid field",
        ),
        (
            {
                "title": "x",
                "logsource": {},
                "detection": {
                    "selection": {"Image|expand": "x"},
                    "condition": "selection",
                },
            },
            "unsupported modifier",
        ),
        (
            {
                "title": "x",
                "logsource": {},
                "detection": {
                    "selection": {"Image|mystery": "x"},
                    "condition": "selection",
                },
            },
            "unknown modifier",
        ),
        (
            {
                "title": "x",
                "logsource": {},
                "detection": {
                    "selection": {"Image": {"nested": "x"}},
                    "condition": "selection",
                },
            },
            "Nested field mapping",
        ),
        (
            {
                "title": "x",
                "logsource": {},
                "detection": {
                    "selection": {"Image": []},
                    "condition": "selection",
                },
            },
            "cannot be empty",
        ),
        (
            {
                "title": "x",
                "logsource": {},
                "detection": {
                    "selection": {"Image": [["nested"]]},
                    "condition": "selection",
                },
            },
            "nested lists",
        ),
        (
            {
                "title": "x",
                "logsource": {},
                "detection": {
                    "selection": {"Image": object()},
                    "condition": "selection",
                },
            },
            "Unsupported value",
        ),
        (
            {
                "title": "x",
                "logsource": {},
                "detection": {
                    "selection": {"Score": float("nan")},
                    "condition": "selection",
                },
            },
            "Non-finite value",
        ),
        (
            {
                "title": "x",
                "logsource": {},
                "detection": {
                    "selection": {"Image": ["cmd.exe", object()]},
                    "condition": "selection",
                },
            },
            "Unsupported value in list",
        ),
        (
            {
                "title": "x",
                "logsource": {},
                "detection": {
                    "selection": {"Score": [1.0, float("inf")]},
                    "condition": "selection",
                },
            },
            "Unsupported value in list",
        ),
        (
            {
                "title": "x",
                "logsource": {},
                "detection": {
                    "selection": {"Image": "%placeholder%"},
                    "condition": "selection",
                },
            },
            "placeholders",
        ),
    ],
)
def test_supported_subset_rejects_unsupported_shapes(
    document: Any,
    message: str,
) -> None:
    with pytest.raises(RuleError, match=message):
        validate_supported_rule(document)


def test_evaluator_rejects_non_mapping_event(
    mutation_rule: dict[str, Any],
) -> None:
    with pytest.raises(EvaluationError, match="mapping"):
        SigmaEvaluator().matches(mutation_rule, ["not", "an", "event"])  # type: ignore[arg-type]


class _FakeCompiled:
    def __init__(self, result: Any = None, error: Exception | None = None):
        self.result = result
        self.error = error

    def match(self, event: dict[str, Any]) -> Any:
        if self.error is not None:
            raise self.error
        return self.result


def test_evaluator_wraps_runtime_errors(
    mutation_rule: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluator = SigmaEvaluator()
    monkeypatch.setattr(
        evaluator,
        "_compiled_rule",
        lambda document: _FakeCompiled(error=RuntimeError("adapter exploded")),
    )

    with pytest.raises(EvaluationError, match="adapter exploded"):
        evaluator.matches(mutation_rule, {})


def test_evaluator_preserves_rule_errors(
    mutation_rule: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluator = SigmaEvaluator()
    expected = RuleError("bad mutant")
    monkeypatch.setattr(
        evaluator,
        "_compiled_rule",
        lambda document: _FakeCompiled(error=expected),
    )

    with pytest.raises(RuleError) as captured:
        evaluator.matches(mutation_rule, {})

    assert captured.value is expected


def test_evaluator_rejects_non_boolean_adapter_result(
    mutation_rule: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluator = SigmaEvaluator()
    monkeypatch.setattr(
        evaluator,
        "_compiled_rule",
        lambda document: _FakeCompiled(result="yes"),
    )

    with pytest.raises(EvaluationError, match="non-boolean"):
        evaluator.matches(mutation_rule, {})


def test_validate_rule_wraps_pysigma_error(
    mutation_rule: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sigma.collection import SigmaCollection

    def reject(yaml_text: str) -> None:
        raise ValueError("parser failed")

    monkeypatch.setattr(SigmaCollection, "from_yaml", reject)

    with pytest.raises(RuleError, match="pySigma rejected.*parser failed"):
        SigmaEvaluator().validate_rule(mutation_rule)


def test_validate_rule_preserves_project_rule_error(
    mutation_rule: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sigma.collection import SigmaCollection

    expected = RuleError("specific parser failure")

    def reject(yaml_text: str) -> None:
        raise expected

    monkeypatch.setattr(SigmaCollection, "from_yaml", reject)

    with pytest.raises(RuleError) as captured:
        SigmaEvaluator().validate_rule(mutation_rule)

    assert captured.value is expected


def test_validate_rule_wraps_azuma_error(
    mutation_rule: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from azuma import Rule
    from sigma.collection import SigmaCollection

    monkeypatch.setattr(SigmaCollection, "from_yaml", lambda yaml_text: object())

    def reject(yaml_text: str) -> None:
        raise ValueError("evaluator parser failed")

    monkeypatch.setattr(Rule, "model_validate_yaml", reject)

    with pytest.raises(RuleError, match="Azuma rejected.*evaluator parser failed"):
        SigmaEvaluator().validate_rule(mutation_rule)


@pytest.mark.parametrize(
    "document",
    [
        {"version": 1, "rule": "r.yml", "fixtures": "f.jsonl", "extra": True},
        {"version": 2, "rule": "r.yml", "fixtures": "f.jsonl"},
        {"version": 1, "rule": 3, "fixtures": "f.jsonl"},
        {"version": 1, "rule": "r.yml", "fixtures": ""},
        {
            "version": 1,
            "rule": "r.yml",
            "fixtures": "f.jsonl",
            "fail_under": True,
        },
        {
            "version": 1,
            "rule": "r.yml",
            "fixtures": "f.jsonl",
            "fail_under": 1.1,
        },
    ],
)
def test_suite_config_rejects_invalid_contracts(document: dict[str, Any]) -> None:
    with pytest.raises(SuiteError):
        _parse_config(document)


def test_suite_config_uses_documented_default_threshold() -> None:
    config = _parse_config({"version": 1, "rule": "r.yml", "fixtures": "f.jsonl"})
    assert config.fail_under == pytest.approx(0.8)


def test_suite_config_rejects_non_string_keys_before_sorting() -> None:
    document = {
        "version": 1,
        "rule": "r.yml",
        "fixtures": "f.jsonl",
        "unknown": True,
        1: "also-unknown",
    }

    with pytest.raises(SuiteError, match="field names must be strings"):
        _parse_config(document)


@pytest.mark.parametrize(
    "line",
    [
        "{",
        "[]",
        json.dumps({"id": "x", "expected": True}),
        json.dumps({"id": "x", "expected": True, "event": {}, "extra": 1}),
        json.dumps({"id": "", "expected": True, "event": {}}),
        json.dumps({"id": "x", "expected": 1, "event": {}}),
        json.dumps({"id": "x", "expected": True, "event": []}),
    ],
)
def test_fixture_parser_rejects_malformed_rows(line: str) -> None:
    with pytest.raises(SuiteError):
        _parse_fixture(line, 7)


def test_suite_and_fixture_read_errors_are_contextual(tmp_path: Path) -> None:
    missing = tmp_path / "missing"

    with pytest.raises(SuiteError, match="Cannot read suite"):
        _load_suite_document(missing)
    with pytest.raises(SuiteError, match="Cannot read fixtures"):
        _load_fixtures(missing)
    with pytest.raises(SuiteError, match="does not exist"):
        _resolve_child(tmp_path, "missing.yml", "Rule")


def test_suite_document_must_be_valid_mapping(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.yml"
    invalid.write_text("rule: [\n", encoding="utf-8")
    with pytest.raises(SuiteError, match="not valid YAML"):
        _load_suite_document(invalid)

    sequence = tmp_path / "sequence.yml"
    sequence.write_text("- one\n- two\n", encoding="utf-8")
    with pytest.raises(SuiteError, match="mapping"):
        _load_suite_document(sequence)


def test_empty_fixture_file_is_rejected(tmp_path: Path) -> None:
    fixtures = tmp_path / "empty.jsonl"
    fixtures.write_text("\n\n", encoding="utf-8")

    with pytest.raises(SuiteError, match="at least one"):
        _load_fixtures(fixtures)


def test_load_suite_rejects_non_utf8_and_invalid_rule_yaml(
    tmp_path: Path,
) -> None:
    suite = tmp_path / "suite.yml"
    fixtures = tmp_path / "fixtures.jsonl"
    rule = tmp_path / "rule.yml"
    suite.write_text(
        "version: 1\nrule: rule.yml\nfixtures: fixtures.jsonl\n",
        encoding="utf-8",
    )
    fixtures.write_text(
        "\n".join(
            [
                json.dumps({"id": "yes", "expected": True, "event": {}}),
                json.dumps({"id": "no", "expected": False, "event": {}}),
            ]
        ),
        encoding="utf-8",
    )

    rule.write_bytes(b"\xff\xfe")
    with pytest.raises(SuiteError, match="UTF-8"):
        load_suite(suite)

    rule.write_text("---\none: 1\n---\ntwo: 2\n", encoding="utf-8")
    with pytest.raises(SuiteError, match="exactly one"):
        load_suite(suite)


def test_yaml_helpers_reject_invalid_multi_document_and_scalar_roots() -> None:
    with pytest.raises(RuleError, match="not valid YAML"):
        load_single_yaml("key: [", source="rule.yml")
    with pytest.raises(RuleError, match="exactly one"):
        load_single_yaml("---\na: 1\n---\nb: 2\n")
    with pytest.raises(RuleError, match="mapping"):
        load_single_yaml("- item\n")

    document = _minimal_rule()
    assert load_single_yaml(dump_yaml(document)) == document

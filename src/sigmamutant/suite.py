"""Suite and labelled event fixture loading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from sigmamutant.errors import RuleError, SuiteError
from sigmamutant.models import Fixture, LoadedSuite, SuiteConfig
from sigmamutant.yamlio import load_single_yaml


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting ambiguous duplicate keys."""

    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate object key {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    """Reject Python's non-standard NaN and Infinity JSON extensions."""

    raise ValueError(f"non-standard numeric constant {value!r}")


def _read_suite_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise SuiteError(f"Cannot read suite file {path}: {exc}") from exc


def _parse_suite_document(content: bytes, path: Path) -> dict[str, Any]:
    parser = YAML(typ="safe")
    parser.allow_duplicate_keys = False
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SuiteError(f"Suite file {path} must be UTF-8") from exc
    try:
        document = parser.load(text)
    except Exception as exc:
        raise SuiteError(f"Suite file {path} is not valid YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise SuiteError("Suite must be a YAML mapping")
    return document


def _load_suite_document(path: Path) -> dict[str, Any]:
    return _parse_suite_document(_read_suite_bytes(path), path)


def _parse_config(document: dict[str, Any]) -> SuiteConfig:
    if any(not isinstance(key, str) for key in document):
        raise SuiteError("Suite top-level field names must be strings")
    allowed = {"version", "rule", "fixtures", "fail_under"}
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise SuiteError(f"Unknown suite field(s): {', '.join(map(str, unknown))}")
    if document.get("version") != 1:
        raise SuiteError("Suite version must be 1")
    rule = document.get("rule")
    fixtures = document.get("fixtures")
    if not isinstance(rule, str) or not rule.strip():
        raise SuiteError("Suite field 'rule' must be a non-empty relative path")
    if not isinstance(fixtures, str) or not fixtures.strip():
        raise SuiteError("Suite field 'fixtures' must be a non-empty relative path")
    raw_threshold = document.get("fail_under", 0.8)
    if isinstance(raw_threshold, bool) or not isinstance(raw_threshold, (int, float)):
        raise SuiteError("Suite field 'fail_under' must be a number from 0 to 1")
    threshold = float(raw_threshold)
    if not 0.0 <= threshold <= 1.0:
        raise SuiteError("Suite field 'fail_under' must be between 0 and 1")
    return SuiteConfig(
        version=1,
        rule=rule,
        fixtures=fixtures,
        fail_under=threshold,
    )


def _resolve_declared_child(base: Path, raw: str, label: str) -> Path:
    """Resolve a safe suite child without requiring valid file contents."""

    relative = Path(raw)
    if relative.is_absolute():
        raise SuiteError(f"{label} path must be relative to the suite directory")
    if ".." in relative.parts:
        raise SuiteError(f"{label} path must not contain parent traversal ('..')")
    resolved_base = base.resolve()
    path = (resolved_base / relative).resolve()
    try:
        path.relative_to(resolved_base)
    except ValueError as exc:
        raise SuiteError(
            f"{label} path resolves outside the suite directory: {raw}"
        ) from exc
    return path


def _resolve_child(base: Path, raw: str, label: str) -> Path:
    path = _resolve_declared_child(base, raw, label)
    if not path.is_file():
        raise SuiteError(f"{label} file does not exist: {path}")
    return path


def declared_suite_input_paths(path: str | Path) -> tuple[Path, ...]:
    """Return safely resolvable inputs declared by a suite document.

    This deliberately performs less validation than :func:`load_suite`. Batch
    reporting needs these path identities before rule or fixture parsing can
    fail, otherwise a managed report name could replace the invalid input that
    caused the load error.
    """

    suite_path = Path(path).expanduser().resolve()
    document = _load_suite_document(suite_path)
    declared = [suite_path]
    for field, label in (("rule", "Rule"), ("fixtures", "Fixtures")):
        raw = document.get(field)
        if not isinstance(raw, str) or not raw.strip():
            continue
        try:
            child = _resolve_declared_child(suite_path.parent, raw, label)
        except SuiteError:
            # Invalid paths are not loadable inputs. Keep inspecting the other
            # declaration so one malformed field cannot hide a valid one.
            continue
        if child not in declared:
            declared.append(child)
    return tuple(declared)


def _parse_fixture(line: str, line_number: int) -> Fixture:
    try:
        value = json.loads(
            line,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise SuiteError(
            f"Fixture line {line_number} is not valid JSON: {exc.msg}"
        ) from exc
    except ValueError as exc:
        raise SuiteError(
            f"Fixture line {line_number} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise SuiteError(f"Fixture line {line_number} must be a JSON object")
    required = {"id", "expected", "event"}
    missing = sorted(required - set(value))
    if missing:
        raise SuiteError(
            f"Fixture line {line_number} is missing field(s): {', '.join(missing)}"
        )
    unknown = sorted(set(value) - required)
    if unknown:
        raise SuiteError(
            f"Fixture line {line_number} has unknown field(s): {', '.join(unknown)}"
        )
    fixture_id = value["id"]
    if not isinstance(fixture_id, str) or not fixture_id.strip():
        raise SuiteError(f"Fixture line {line_number} has an invalid id")
    expected = value["expected"]
    if not isinstance(expected, bool):
        raise SuiteError(f"Fixture {fixture_id!r} field 'expected' must be boolean")
    event = value["event"]
    if not isinstance(event, dict):
        raise SuiteError(f"Fixture {fixture_id!r} field 'event' must be an object")
    return Fixture(id=fixture_id, expected=expected, event=event)


def _read_fixtures_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise SuiteError(f"Cannot read fixtures file {path}: {exc}") from exc


def _parse_fixtures(content: bytes, path: Path) -> tuple[Fixture, ...]:
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise SuiteError(f"Fixtures file {path} must be UTF-8") from exc
    fixtures = tuple(
        _parse_fixture(line, number)
        for number, line in enumerate(lines, start=1)
        if line.strip()
    )
    if not fixtures:
        raise SuiteError("Fixture file must contain at least one event")
    ids = [fixture.id for fixture in fixtures]
    duplicates = sorted({item for item in ids if ids.count(item) > 1})
    if duplicates:
        raise SuiteError(f"Fixture ids must be unique: {', '.join(duplicates)}")
    if not any(item.expected for item in fixtures):
        raise SuiteError("Fixture corpus must contain at least one positive event")
    if not any(not item.expected for item in fixtures):
        raise SuiteError("Fixture corpus must contain at least one negative event")
    return fixtures


def _load_fixtures(path: Path) -> tuple[Fixture, ...]:
    return _parse_fixtures(_read_fixtures_bytes(path), path)


def load_suite(path: str | Path) -> LoadedSuite:
    suite_path = Path(path).expanduser().resolve()
    suite_bytes = _read_suite_bytes(suite_path)
    document = _parse_suite_document(suite_bytes, suite_path)
    config = _parse_config(document)
    rule_path = _resolve_child(suite_path.parent, config.rule, "Rule")
    fixtures_path = _resolve_child(suite_path.parent, config.fixtures, "Fixtures")
    try:
        rule_bytes = rule_path.read_bytes()
        rule_text = rule_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SuiteError(f"Rule file must be UTF-8: {rule_path}") from exc
    except OSError as exc:
        raise SuiteError(f"Cannot read rule file {rule_path}: {exc}") from exc
    try:
        rule_document = load_single_yaml(rule_text, source=str(rule_path))
    except RuleError as exc:
        raise SuiteError(str(exc)) from exc
    fixtures_bytes = _read_fixtures_bytes(fixtures_path)
    fixtures = _parse_fixtures(fixtures_bytes, fixtures_path)
    return LoadedSuite(
        config=config,
        path=suite_path,
        rule_path=rule_path,
        fixtures_path=fixtures_path,
        suite_bytes=suite_bytes,
        rule_bytes=rule_bytes,
        fixtures_bytes=fixtures_bytes,
        rule_document=rule_document,
        fixtures=fixtures,
    )

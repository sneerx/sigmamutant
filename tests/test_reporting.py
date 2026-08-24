from __future__ import annotations

import enum
import os
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree

import pytest

from sigmamutant.errors import SigmaMutantError
from sigmamutant.reporting import write_all
from sigmamutant.reporting._common import (
    bytes_from_candidate,
    enum_value,
    get_field,
    is_status,
    mutant_description,
    mutant_document,
    mutant_identity,
    mutant_operator,
    mutated_rule_bytes,
    provided_diff,
    reject_protected_path,
    reject_symlink_components,
    result_payload,
    safe_stem,
    status_value,
    to_primitive,
    unified_diff,
    write_text,
)
from sigmamutant.reporting.junit_report import render_junit, write_junit
from sigmamutant.reporting.survivors import write_survivors


class _State(enum.Enum):
    SURVIVED = "survived"


@dataclass
class _Box:
    value: int


class _ModernModel:
    def model_dump(self, *, mode: str):
        assert mode == "python"
        return {"modern": True}


class _LegacyModel:
    def model_dump(self, **kwargs):
        if kwargs:
            raise TypeError("old model API")
        return {"legacy": True}


class _PlainObject:
    def __init__(self) -> None:
        self.visible = "yes"
        self._private = "no"


class _SlottedObject:
    __slots__ = "value"

    def __init__(self) -> None:
        self.value = 7


class _Opaque:
    __slots__ = ()


def test_deterministic_serializer_handles_supported_runtime_types() -> None:
    recursive: list[object] = []
    recursive.append(recursive)
    timestamp = datetime(2026, 7, 23, 12, 0, tzinfo=timezone.utc)

    assert to_primitive(float("inf")) == "inf"
    assert to_primitive(Decimal("1.25")) == 1.25
    assert to_primitive(Decimal("NaN")) == "NaN"
    assert to_primitive(_State.SURVIVED) == "survived"
    example_path = Path("tmp") / "example"
    assert to_primitive(example_path) == str(example_path)
    assert to_primitive(b"\xff")["encoding"] == "hex"
    assert to_primitive(date(2026, 7, 23)) == "2026-07-23"
    assert to_primitive(timestamp) == timestamp.isoformat()
    assert to_primitive({"values": {3, 1, 2}}) == {"values": [1, 2, 3]}
    assert to_primitive(recursive) == ["<recursive>"]
    assert to_primitive(_ModernModel()) == {"modern": True}
    assert to_primitive(_LegacyModel()) == {"legacy": True}
    assert to_primitive(_Box(4)) == {"value": 4}
    assert to_primitive(_PlainObject()) == {"visible": "yes"}
    assert to_primitive(_SlottedObject()) == {"value": 7}
    assert to_primitive(_Opaque()).endswith("._Opaque>")


def test_reporting_field_and_identity_fallbacks_are_stable() -> None:
    named_operator = SimpleNamespace(name="delete_predicate")

    assert get_field({"key": 3}, "key") == 3
    assert enum_value(_State.SURVIVED) == "survived"
    assert status_value(None) == "unknown"
    assert is_status(_State.SURVIVED, "SURVIVED")
    assert mutant_identity({"id": "abc"}, 1) == "abc"
    assert mutant_identity({"operator": named_operator}, 2) == ("delete_predicate-0002")
    assert mutant_identity({}, 3) == "mutant-0003"
    assert mutant_operator({}) == ""
    assert mutant_operator({"operator": named_operator}) == "delete_predicate"
    assert mutant_description({"summary": "summary"}) == "summary"
    assert mutant_description({}) == ""
    assert safe_stem(" ../unsafe mutant/// ") == "unsafe-mutant"
    assert safe_stem("***", fallback="fallback") == "fallback"


def test_rule_materialization_helpers_cover_bytes_renderers_and_documents() -> None:
    class RenderFallback:
        def render(self, required_argument):
            raise AssertionError("must not be called successfully")

        def to_yaml(self):
            return "title: rendered\n"

    assert bytes_from_candidate(None) is None
    assert bytes_from_candidate(b"raw") == b"raw"
    assert bytes_from_candidate(bytearray(b"mutable")) == b"mutable"
    assert bytes_from_candidate("text") == b"text"
    assert bytes_from_candidate(3) is None
    assert mutated_rule_bytes({"rule_yaml": "title: bytes\n"}) == (b"title: bytes\n")
    assert mutated_rule_bytes(RenderFallback()) == b"title: rendered\n"
    assert mutated_rule_bytes({}) is None
    assert mutant_document({"document": {"title": "doc"}}) == {"title": "doc"}
    assert mutant_document({"document": "not-a-document"}) is None
    assert provided_diff({"diff": b"binary diff"}) == "binary diff"
    assert provided_diff({"patch": "text diff"}) == "text diff"
    assert provided_diff({}) is None


def test_text_and_diff_helpers_produce_reviewable_output(tmp_path: Path) -> None:
    destination = write_text(tmp_path / "line.txt", "without newline")
    assert destination.read_bytes() == b"without newline\n"

    diff = unified_diff(
        b"title: before\n",
        b"title: after\n",
        original_name="rule.yml",
        mutated_name="mutant.yml",
    )
    assert "--- rule.yml" in diff
    assert "+++ mutant.yml" in diff
    assert "-title: before" in diff
    assert "+title: after" in diff
    assert (
        unified_diff(
            b"same\n",
            b"same\n",
            original_name="a",
            mutated_name="b",
        )
        == ""
    )


def test_path_guard_rejects_an_intermediate_symlink(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(external, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(SigmaMutantError, match="symlink component"):
        reject_symlink_components(linked / "nested" / "report.json")

    class CustomPathError(Exception):
        pass

    with pytest.raises(CustomPathError, match="symlink component"):
        reject_symlink_components(
            linked / "report.json",
            error_type=CustomPathError,
        )


def test_path_guard_allows_only_trusted_macos_temp_alias() -> None:
    alias = Path("/tmp")
    if not alias.is_symlink():
        pytest.skip("/tmp is not a system symlink on this platform")

    destination = alias / "sigmamutant-system-alias-probe" / "report.json"

    assert reject_symlink_components(destination) == destination


def test_protected_path_guard_uses_filesystem_identity(tmp_path: Path) -> None:
    protected = tmp_path / "protected.json"
    protected.write_text("keep\n", encoding="utf-8")
    alias = tmp_path / "PROTECTED.JSON"
    if not alias.exists() or not os.path.samefile(alias, protected):
        pytest.skip("test directory is not case-insensitive")

    with pytest.raises(SigmaMutantError, match="input file"):
        reject_protected_path(alias, (protected,))

    assert protected.read_text(encoding="utf-8") == "keep\n"


def test_atomic_text_write_keeps_previous_bytes_when_replace_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sigmamutant.reporting._common as common

    destination = write_text(tmp_path / "report.json", "old")

    def fail_replace(source, target) -> None:
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(common.os, "replace", fail_replace)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_text(destination, "new")

    assert destination.read_bytes() == b"old\n"
    assert not list(tmp_path.glob(".report.json.*.tmp"))


def test_write_all_rejects_symlink_artifact_directory(
    tmp_path: Path,
) -> None:
    external = tmp_path / "external"
    external.mkdir()
    sentinel = external / "sentinel.txt"
    sentinel.write_text("keep\n", encoding="utf-8")
    output = tmp_path / "artifacts"
    try:
        output.symlink_to(external, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(SigmaMutantError, match="symlink component"):
        write_all({}, {}, output)

    assert sentinel.read_text(encoding="utf-8") == "keep\n"
    assert sorted(path.name for path in external.iterdir()) == ["sentinel.txt"]


def test_write_all_preflights_destination_symlinks_before_any_write(
    tmp_path: Path,
) -> None:
    output = tmp_path / "artifacts"
    output.mkdir()
    external = tmp_path / "external-report.json"
    external.write_text("do-not-change\n", encoding="utf-8")
    destination = output / "report.json"
    try:
        destination.symlink_to(external)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(SigmaMutantError, match="symlink component"):
        write_all({}, {}, output)

    assert external.read_text(encoding="utf-8") == "do-not-change\n"
    assert destination.is_symlink()
    assert not (output / "report.html").exists()
    assert not (output / "junit.xml").exists()


def test_write_all_rejects_nonportable_existing_destination_alias(
    tmp_path: Path,
) -> None:
    existing = tmp_path / "REPORT.JSON"
    existing.write_text("user-owned\n", encoding="utf-8")

    with pytest.raises(SigmaMutantError, match="case or Unicode"):
        write_all({}, {}, tmp_path)

    assert existing.read_text(encoding="utf-8") == "user-owned\n"
    assert not (tmp_path / "report.html").exists()
    assert not (tmp_path / "junit.xml").exists()


def test_write_all_rejects_hardlinked_destination_before_any_write(
    tmp_path: Path,
) -> None:
    external = tmp_path / "external.json"
    external.write_text("user-owned\n", encoding="utf-8")
    destination = tmp_path / "report.json"
    try:
        os.link(external, destination)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")

    with pytest.raises(SigmaMutantError, match="hardlinked"):
        write_all({}, {}, tmp_path)

    assert external.read_text(encoding="utf-8") == "user-owned\n"
    assert destination.read_text(encoding="utf-8") == "user-owned\n"
    assert not (tmp_path / "report.html").exists()


def test_write_all_rejects_symlink_survivor_directory(
    tmp_path: Path,
) -> None:
    output = tmp_path / "artifacts"
    output.mkdir()
    external = tmp_path / "external-survivors"
    external.mkdir()
    sentinel = external / "keep.yml"
    sentinel.write_text("keep\n", encoding="utf-8")
    try:
        (output / "survivors").symlink_to(external, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(SigmaMutantError, match="symlink component"):
        write_all({}, {}, output)

    assert sentinel.read_text(encoding="utf-8") == "keep\n"
    assert not (output / "report.json").exists()


def test_survivor_writer_rejects_managed_file_symlink(
    tmp_path: Path,
) -> None:
    survivors = tmp_path / "survivors"
    survivors.mkdir()
    external = tmp_path / "external-rule.yml"
    external.write_text("title: keep\n", encoding="utf-8")
    linked = survivors / "mutant.yml"
    try:
        linked.symlink_to(external)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    result = {
        "mutant_results": [
            {
                "status": "survived",
                "mutant": {"id": "mutant", "document": {"title": "changed"}},
            }
        ]
    }
    with pytest.raises(SigmaMutantError, match="symlink component"):
        write_survivors(result, {}, tmp_path)

    assert external.read_text(encoding="utf-8") == "title: keep\n"
    assert linked.is_symlink()


def test_junit_writer_rejects_destination_symlink(
    tmp_path: Path,
) -> None:
    output = tmp_path / "artifacts"
    output.mkdir()
    external = tmp_path / "external.xml"
    external.write_text("keep\n", encoding="utf-8")
    try:
        (output / "junit.xml").symlink_to(external)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(SigmaMutantError, match="symlink component"):
        write_junit({}, {}, output)

    assert external.read_text(encoding="utf-8") == "keep\n"


def test_write_all_refuses_to_overwrite_managed_input_path(
    tmp_path: Path,
) -> None:
    output = tmp_path / "artifacts"
    output.mkdir()
    fixture_input = output / "report.json"
    fixture_input.write_text("fixture-input\n", encoding="utf-8")
    suite = {
        "path": tmp_path / "suite.yml",
        "rule_path": tmp_path / "rule.yml",
        "fixtures_path": fixture_input,
    }

    with pytest.raises(SigmaMutantError, match="input file"):
        write_all({}, suite, output)

    assert fixture_input.read_text(encoding="utf-8") == "fixture-input\n"
    assert not (output / "report.html").exists()
    assert not (output / "junit.xml").exists()


def test_write_all_refuses_case_alias_of_managed_input_path(
    tmp_path: Path,
) -> None:
    fixture_input = tmp_path / "REPORT.JSON"
    fixture_input.write_text("fixture-input\n", encoding="utf-8")
    destination_alias = tmp_path / "report.json"
    if not destination_alias.exists() or not os.path.samefile(
        destination_alias,
        fixture_input,
    ):
        pytest.skip("test directory is not case-insensitive")
    suite = {
        "path": tmp_path / "suite.yml",
        "rule_path": tmp_path / "rule.yml",
        "fixtures_path": fixture_input,
    }

    with pytest.raises(SigmaMutantError, match="input file"):
        write_all({}, suite, tmp_path)

    assert fixture_input.read_text(encoding="utf-8") == "fixture-input\n"


def test_survivor_writer_cleans_stale_owned_files_but_preserves_other_files(
    tmp_path: Path,
) -> None:
    survivors = tmp_path / "survivors"
    survivors.mkdir()
    (survivors / "stale.yml").write_text("stale", encoding="utf-8")
    (survivors / "stale.diff").write_text("stale", encoding="utf-8")
    (survivors / "keep.txt").write_text("user file", encoding="utf-8")

    written = write_survivors({"mutant_results": []}, {}, tmp_path)

    assert written == ()
    assert not (survivors / "stale.yml").exists()
    assert not (survivors / "stale.diff").exists()
    assert (survivors / "keep.txt").read_text(encoding="utf-8") == "user file"


def test_write_all_preflights_stale_survivor_hardlink_before_reports(
    tmp_path: Path,
) -> None:
    survivors = tmp_path / "survivors"
    survivors.mkdir()
    external = tmp_path / "external.yml"
    external.write_text("keep\n", encoding="utf-8")
    stale = survivors / "stale.yml"
    try:
        os.link(external, stale)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")

    with pytest.raises(SigmaMutantError, match="hardlinked"):
        write_all({}, {}, tmp_path)

    assert external.read_text(encoding="utf-8") == "keep\n"
    assert stale.read_text(encoding="utf-8") == "keep\n"
    assert not (tmp_path / "report.json").exists()


def test_survivor_writer_materializes_rendered_rules_and_unique_names(
    tmp_path: Path,
) -> None:
    result = {
        "mutant_results": [
            {
                "status": "survived",
                "mutant": {
                    "id": "duplicate",
                    "mutated_rule_bytes": b"title: first",
                    "diff": b"--- rule.yml\n+++ first.yml\n",
                },
            },
            {
                "status": "survived",
                "mutant": {
                    "id": "duplicate",
                    "mutated_rule_bytes": b"title: second\n",
                    "diff": "--- rule.yml\n+++ second.yml\n",
                },
            },
            {
                "status": "killed",
                "mutant": {"id": "ignored", "document": {"title": "ignored"}},
            },
        ]
    }
    suite = {
        "rule_bytes": b"title: original\n",
        "rule_path": tmp_path / "rule.yml",
    }

    written = write_survivors(result, suite, tmp_path)

    names = {path.name for path in written}
    assert names == {
        "duplicate.yml",
        "duplicate.diff",
        "duplicate-2.yml",
        "duplicate-2.diff",
    }
    assert (tmp_path / "survivors" / "duplicate.yml").read_text(
        encoding="utf-8"
    ) == "title: first\n"


def test_survivor_names_are_unique_under_portable_case_rules(
    tmp_path: Path,
) -> None:
    result = {
        "mutant_results": [
            {
                "status": "survived",
                "mutant": {"id": "Mutant", "document": {"title": "first"}},
            },
            {
                "status": "survived",
                "mutant": {"id": "mutant", "document": {"title": "second"}},
            },
        ]
    }

    written = write_survivors(result, {}, tmp_path)

    assert {path.name for path in written} == {
        "Mutant.yml",
        "mutant-2.yml",
    }


def test_survivor_writer_has_descriptor_fallback(tmp_path: Path) -> None:
    result = {
        "mutant_results": [
            {
                "status": "survived",
                "mutant": {"id": "descriptor-only", "operator": "synthetic"},
            }
        ]
    }

    written = write_survivors(result, {}, tmp_path)

    assert [path.name for path in written] == ["descriptor-only.yml"]
    assert "descriptor-only" in written[0].read_text(encoding="utf-8")


def test_junit_represents_exclusions_errors_and_run_errors() -> None:
    result = {
        "rule_title": "Synthetic",
        "baseline_passed": False,
        "score": 0.0,
        "threshold": 0.8,
        "passed": False,
        "errors": ["baseline failed"],
        "mutant_results": [
            {
                "status": "excluded",
                "reason": "unsupported mutant",
                "mutant": {"id": "excluded", "operator": "one"},
            },
            {
                "status": "error",
                "mutant": {"id": "error", "operator": "two"},
            },
        ],
    }

    root = ElementTree.fromstring(render_junit(result, {}))

    assert root.attrib["failures"] == "1"
    assert root.attrib["errors"] == "2"
    assert root.attrib["skipped"] == "1"
    assert root.find(".//failure") is not None
    assert root.find(".//skipped") is not None
    assert root.find(".//error") is not None
    assert "unsupported mutant" in (root.find(".//skipped").text or "")


def test_report_payload_uses_portable_paths_and_keeps_exclusion_reason(
    tmp_path: Path,
) -> None:
    result = {
        "mutant_results": [
            {
                "status": "excluded",
                "reason": "invalid condition",
                "mutant": {"id": "excluded", "operator": "one"},
            }
        ]
    }
    suite = {
        "path": tmp_path / "suite.yml",
        "rule_path": tmp_path / "rules" / "rule.yml",
        "fixtures_path": tmp_path / "fixtures" / "events.jsonl",
        "config": {
            "rule": "rules/rule.yml",
            "fixtures": "fixtures/events.jsonl",
        },
    }

    payload = result_payload(result, suite)

    assert payload["suite"]["path"] == "suite.yml"
    assert payload["suite"]["rule_path"] == "rules/rule.yml"
    assert payload["suite"]["fixtures_path"] == "fixtures/events.jsonl"
    assert payload["mutant_results"][0]["reason"] == "invalid condition"

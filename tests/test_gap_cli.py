from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from xml.etree import ElementTree

import pytest
from typer.testing import CliRunner

from sigmamutant.cli import app

runner = CliRunner()
PROJECT_ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_SUITE = PROJECT_ROOT / "examples" / "powershell-gap.yml"
HARDENED_SUITE = PROJECT_ROOT / "examples" / "powershell-hardened-gap.yml"


def _reports(output: Path) -> tuple[Path, Path, Path]:
    return (
        output / "gap-report.json",
        output / "gap-report.html",
        output / "gap-junit.xml",
    )


def _copy_gap_project(
    destination: Path,
    *,
    suite_name: str = "gap-suite.yml",
    private_marker: str | None = None,
) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    rule = destination / "rule.yml"
    fixtures = destination / "fixtures.jsonl"
    suite = destination / suite_name

    shutil.copy2(
        PROJECT_ROOT / "examples" / "rules" / "powershell_encoded.yml",
        rule,
    )
    fixture_rows = []
    source = PROJECT_ROOT / "examples" / "fixtures" / "gap.jsonl"
    for line in source.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if private_marker is not None:
            row["event"]["PrivateContext"] = private_marker
        fixture_rows.append(json.dumps(row, ensure_ascii=False, sort_keys=True))
    fixtures.write_text("\n".join(fixture_rows) + "\n", encoding="utf-8")
    suite.write_text(
        "version: 1\nrule: rule.yml\nfixtures: fixtures.jsonl\nfail_under: 0.80\n",
        encoding="utf-8",
    )
    return suite


def test_gap_cli_vulnerable_suite_exits_one_and_writes_parseable_evidence(
    tmp_path: Path,
) -> None:
    output = tmp_path / "vulnerable"

    result = runner.invoke(
        app,
        ["gap", str(VULNERABLE_SUITE), "--out", str(output)],
    )

    assert result.exit_code == 1, result.output
    assert "RESULT: FAIL" in result.output
    assert "Gap candidates requiring review" in result.output
    assert "not proof of a real-world evasion" in " ".join(result.output.split())
    report_json, report_html, report_junit = _reports(output)
    assert report_json.is_file()
    assert report_html.is_file()
    assert report_junit.is_file()

    payload = json.loads(report_json.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["analysis"] == "event-robustness"
    assert payload["baseline_passed"] is True
    assert payload["passed"] is False
    assert payload["gaps"] > 0
    assert payload["detected"] > 0
    assert payload["score"] < payload["threshold"]
    assert payload["variation_count"] == len(payload["variation_results"])

    junit = ElementTree.parse(report_junit).getroot()
    assert junit.tag == "testsuite"
    assert junit.attrib["failures"] == "1"
    assert junit.attrib["errors"] == "0"
    assert junit.find("./testcase/failure") is not None


def test_gap_cli_hardened_suite_exits_zero_with_no_gap_candidates(
    tmp_path: Path,
) -> None:
    output = tmp_path / "hardened"

    result = runner.invoke(
        app,
        ["gap", str(HARDENED_SUITE), "--out", str(output)],
    )

    assert result.exit_code == 0, result.output
    assert "RESULT: PASS" in result.output
    payload = json.loads((output / "gap-report.json").read_text(encoding="utf-8"))
    assert payload["baseline_passed"] is True
    assert payload["passed"] is True
    assert payload["gaps"] == 0
    assert payload["detected"] == payload["variation_count"]
    assert payload["score"] == 1.0

    junit = ElementTree.parse(output / "gap-junit.xml").getroot()
    assert junit.attrib["failures"] == "0"
    assert junit.attrib["errors"] == "0"
    assert junit.find(".//failure") is None


def test_gap_cli_threshold_can_allow_a_completed_run_with_review_candidates(
    tmp_path: Path,
) -> None:
    output = tmp_path / "allowed-gaps"

    result = runner.invoke(
        app,
        [
            "gap",
            str(VULNERABLE_SUITE),
            "--out",
            str(output),
            "--fail-under",
            "0.50",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "RESULT: PASS" in result.output
    payload = json.loads((output / "gap-report.json").read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["gaps"] > 0
    assert payload["score"] >= payload["threshold"]
    junit = ElementTree.parse(output / "gap-junit.xml").getroot()
    assert junit.attrib["failures"] == "0"
    assert junit.find(".//failure") is None


def test_gap_cli_variation_limit_exhaustion_fails_closed_after_baseline(
    tmp_path: Path,
) -> None:
    output = tmp_path / "variation-limit"

    result = runner.invoke(
        app,
        [
            "gap",
            str(VULNERABLE_SUITE),
            "--out",
            str(output),
            "--max-variations",
            "1",
        ],
    )

    assert result.exit_code == 2, result.output
    assert "RESULT: ERROR" in result.output
    payload = json.loads((output / "gap-report.json").read_text(encoding="utf-8"))
    assert payload["baseline_passed"] is True
    assert payload["variation_count"] == 0
    assert payload["metadata"]["max_variations"] == 1
    assert payload["errors"] == ["Event variation limit exceeded (max-variations=1)."]


def test_gap_cli_baseline_failure_exits_two_and_records_technical_error(
    broken_baseline_suite: Path,
    tmp_path: Path,
) -> None:
    output = tmp_path / "baseline-error"

    result = runner.invoke(
        app,
        ["gap", str(broken_baseline_suite), "--out", str(output)],
    )

    assert result.exit_code == 2, result.output
    assert "RESULT: ERROR" in result.output
    payload = json.loads((output / "gap-report.json").read_text(encoding="utf-8"))
    assert payload["baseline_passed"] is False
    assert payload["passed"] is False
    assert payload["errors"]
    assert payload["variation_count"] == 0

    junit = ElementTree.parse(output / "gap-junit.xml").getroot()
    assert junit.attrib["failures"] == "0"
    assert junit.attrib["errors"] == "1"
    error = junit.find(".//error")
    assert error is not None
    assert error.attrib["type"] == "GapAnalysisError"


def test_gap_cli_missing_suite_exits_two_without_creating_artifacts(
    tmp_path: Path,
) -> None:
    output = tmp_path / "missing-output"

    result = runner.invoke(
        app,
        ["gap", str(tmp_path / "missing.yml"), "--out", str(output)],
    )

    assert result.exit_code == 2
    assert "RESULT: ERROR" in result.output
    assert not output.exists()


def test_gap_cli_verbose_is_value_safe_for_fixture_derived_data(
    tmp_path: Path,
) -> None:
    marker = "fixture-private-marker-7f4a7b6e"
    suite = _copy_gap_project(
        tmp_path / "project",
        private_marker=marker,
    )
    output = tmp_path / "verbose"

    result = runner.invoke(
        app,
        ["gap", str(suite), "--out", str(output), "--verbose"],
    )

    assert result.exit_code == 1, result.output
    for stage in (
        "gap.suite.loaded",
        "gap.analysis.started",
        "gap.variation.evaluated",
        "gap.artifacts.written",
        "gap.completed",
    ):
        assert stage in result.output
    assert marker not in result.output
    assert "SQBmACgAJAB0AHIAdQBlACkA" not in result.output
    for artifact in _reports(output):
        content = artifact.read_text(encoding="utf-8")
        assert marker not in content
        assert "SQBmACgAJAB0AHIAdQBlACkA" not in content


def test_gap_cli_replaces_terminal_controls_in_fixture_ids(
    tmp_path: Path,
) -> None:
    suite = _copy_gap_project(tmp_path / "project")
    fixtures = suite.parent / "fixtures.jsonl"
    rows = [json.loads(line) for line in fixtures.read_text("utf-8").splitlines()]
    unsafe_id = "positive\x1b\u202e\ud800-id"
    for row in rows:
        if row["id"] == "pos-pwsh-documented-encoded":
            row["id"] = unsafe_id
    fixtures.write_text(
        "\n".join(json.dumps(row, ensure_ascii=True) for row in rows) + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["gap", str(suite), "--out", str(tmp_path / "reports")],
    )

    assert result.exit_code == 1, result.output
    assert "\x1b" not in result.output
    assert "\u202e" not in result.output
    assert "\ud800" not in result.output
    assert "positive\ufffd\ufffd\ufffd-id" in result.output


def test_gap_operators_lists_only_the_stable_event_operator_registry() -> None:
    result = runner.invoke(app, ["gap-operators"])

    assert result.exit_code == 0, result.output
    assert "SigmaMutant gap operators" in result.output
    for operator in (
        "ascii_case",
        "command_line_whitespace",
        "telemetry_path_to_basename",
        "pwsh_encoded_alias",
    ):
        assert operator in result.output
    assert "delete_predicate" not in result.output


def test_gap_cli_rejects_symlinked_managed_destination_before_any_write(
    tmp_path: Path,
) -> None:
    output = tmp_path / "artifacts"
    output.mkdir()
    external = tmp_path / "external.html"
    external.write_text("user-owned\n", encoding="utf-8")
    linked = output / "gap-report.html"
    try:
        linked.symlink_to(external)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    result = runner.invoke(
        app,
        ["gap", str(VULNERABLE_SUITE), "--out", str(output)],
    )

    assert result.exit_code == 2, result.output
    assert "symlink component" in result.output
    assert external.read_text(encoding="utf-8") == "user-owned\n"
    assert linked.is_symlink()
    assert not (output / "gap-report.json").exists()
    assert not (output / "gap-junit.xml").exists()


def test_gap_cli_rejects_nonportable_destination_alias_before_any_write(
    tmp_path: Path,
) -> None:
    output = tmp_path / "artifacts"
    output.mkdir()
    alias = output / "GAP-REPORT.JSON"
    alias.write_text("user-owned\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["gap", str(VULNERABLE_SUITE), "--out", str(output)],
    )

    assert result.exit_code == 2, result.output
    assert "case or Unicode" in " ".join(result.output.split())
    assert alias.read_text(encoding="utf-8") == "user-owned\n"
    assert [path.name for path in output.iterdir()] == ["GAP-REPORT.JSON"]
    assert not (output / "gap-report.html").exists()
    assert not (output / "gap-junit.xml").exists()


def test_gap_cli_rejects_hardlinked_destination_before_any_write(
    tmp_path: Path,
) -> None:
    output = tmp_path / "artifacts"
    output.mkdir()
    external = tmp_path / "external.xml"
    external.write_text("user-owned\n", encoding="utf-8")
    destination = output / "gap-junit.xml"
    try:
        os.link(external, destination)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")

    result = runner.invoke(
        app,
        ["gap", str(VULNERABLE_SUITE), "--out", str(output)],
    )

    assert result.exit_code == 2, result.output
    assert "hardlinked" in result.output
    assert external.read_text(encoding="utf-8") == "user-owned\n"
    assert destination.read_text(encoding="utf-8") == "user-owned\n"
    assert not (output / "gap-report.json").exists()
    assert not (output / "gap-report.html").exists()


def test_gap_cli_refuses_to_overwrite_suite_input_named_like_report(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    suite = _copy_gap_project(project, suite_name="gap-report.json")
    original = suite.read_bytes()

    result = runner.invoke(
        app,
        ["gap", str(suite), "--out", str(project)],
    )

    assert result.exit_code == 2, result.output
    assert "input file" in result.output
    assert suite.read_bytes() == original
    assert not (project / "gap-report.html").exists()
    assert not (project / "gap-junit.xml").exists()

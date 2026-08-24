from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

import sigmamutant.cli as cli_module
from sigmamutant.cli import app

runner = CliRunner()


def test_run_exit_zero_when_score_meets_threshold(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        [
            "run",
            str(weak_suite),
            "--out",
            str(tmp_path / "pass"),
            "--fail-under",
            "0.0",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "RESULT: PASS" in result.output


def test_run_exit_one_when_score_is_below_threshold(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        [
            "run",
            str(weak_suite),
            "--out",
            str(tmp_path / "fail"),
            "--fail-under",
            "1.0",
        ],
    )

    assert result.exit_code == 1, result.output
    assert "RESULT: FAIL" in result.output
    assert "Survivors requiring review" in result.output
    assert "Review first diff:" in result.output
    assert "Optional AI: sigmamutant suggest-fixture" in result.output


def test_run_exit_two_when_baseline_is_wrong(
    broken_baseline_suite: Path,
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        [
            "run",
            str(broken_baseline_suite),
            "--out",
            str(tmp_path / "baseline-error"),
        ],
    )

    assert result.exit_code == 2, result.output


def test_validate_accepts_a_valid_suite(weak_suite: Path) -> None:
    result = runner.invoke(app, ["validate", str(weak_suite)])

    assert result.exit_code == 0, result.output
    assert "RESULT: PASS" in result.output
    assert "Supported rule" in result.output
    assert "Mutation score" not in result.output
    assert "Killed" not in result.output


def test_validate_accepts_valid_rule_without_mutation_points(
    no_mutation_suite: Path,
) -> None:
    result = runner.invoke(app, ["validate", str(no_mutation_suite)])

    assert result.exit_code == 0, result.output
    assert "RESULT: PASS" in result.output


def test_run_verbose_is_value_free_and_shows_core_stages(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        [
            "run",
            str(weak_suite),
            "--out",
            str(tmp_path / "verbose"),
            "--verbose",
        ],
    )

    assert result.exit_code == 0, result.output
    for stage in (
        "suite.loaded",
        "baseline.fixture.evaluated",
        "mutant.started",
        "mutant.fixture.evaluated",
        "mutant.completed",
        "artifacts.written",
        "run.completed",
    ):
        assert stage in result.output
    assert "EncodedCommand AAAA" not in result.output
    assert r"DOMAIN\alice" not in result.output


def test_run_default_artifacts_are_namespaced_and_displayed_relative(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["run", str(weak_suite)])

    artifact_dir = tmp_path / "artifacts" / weak_suite.stem
    assert result.exit_code == 0, result.output
    assert (artifact_dir / "report.json").is_file()
    assert (artifact_dir / "report.html").is_file()
    assert (artifact_dir / "junit.xml").is_file()
    assert f"Artifacts: artifacts/{weak_suite.stem}" in result.output
    assert str(tmp_path) not in result.output


def test_operators_lists_the_stable_core_operator_names() -> None:
    result = runner.invoke(app, ["operators"])

    assert result.exit_code == 0, result.output
    for operator in (
        "delete_predicate",
        "delete_list_item",
        "modifier_to_exact",
        "list_any_to_all",
        "condition_and_to_or",
        "condition_remove_not",
    ):
        assert operator in result.output


def test_version_flag_reports_package_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "sigmamutant 1.0.0" in result.output


def test_display_error_sanitizes_workspace_and_home_prefixes() -> None:
    workspace = Path.cwd().resolve()
    home = Path.home().resolve()

    workspace_message = cli_module._display_error(
        RuntimeError(f"cannot read {workspace / 'sensitive-suite.yml'}")
    )
    home_message = cli_module._display_error(
        RuntimeError(f"cannot read {home / 'outside' / 'suite.yml'}")
    )

    assert str(workspace) not in workspace_message
    assert "cannot read ." in workspace_message
    assert "sensitive-suite.yml" in workspace_message
    assert str(home) not in home_message
    assert "cannot read ~" in home_message
    assert "outside" in home_message
    assert "suite.yml" in home_message


def test_validate_exit_two_for_baseline_failure(
    broken_baseline_suite: Path,
) -> None:
    result = runner.invoke(app, ["validate", str(broken_baseline_suite)])

    assert result.exit_code == 2
    assert "error:" in result.output


@pytest.mark.parametrize("command", ["validate", "run"])
def test_cli_maps_input_errors_to_exit_two(
    command: str,
    tmp_path: Path,
) -> None:
    missing = tmp_path / "does-not-exist.yml"
    result = runner.invoke(app, [command, str(missing)])

    assert result.exit_code == 2
    assert "error:" in result.output


@pytest.mark.parametrize("command", ["validate", "run", "check"])
def test_cli_maps_non_string_suite_keys_to_controlled_exit_two(
    command: str,
    tmp_path: Path,
) -> None:
    suite = tmp_path / "mixed-keys-suite.yml"
    suite.write_text(
        "version: 1\nrule: rule.yml\nfixtures: fixtures.jsonl\nunknown: one\n1: two\n",
        encoding="utf-8",
    )
    arguments = [command, str(suite)]
    if command in {"run", "check"}:
        arguments.extend(("--out", str(tmp_path / f"{command}-artifacts")))

    result = runner.invoke(app, arguments)

    assert result.exit_code == 2
    assert "RESULT: ERROR" in result.output
    assert not isinstance(result.exception, TypeError)

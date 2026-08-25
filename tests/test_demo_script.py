from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts import run_demo

REPOSITORY = Path(__file__).resolve().parents[1]


def test_offline_environment_does_not_copy_api_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-inherited")
    monkeypatch.setenv("EXAMPLE_API_KEY", "must-not-be-inherited")
    monkeypatch.setenv("PYTHONPATH", "/untrusted/import/path")
    monkeypatch.setenv("PATH", "/safe/path")
    monkeypatch.setenv("HOMEDRIVE", "C:")
    monkeypatch.setenv("HOMEPATH", r"\Users\Reviewer")
    monkeypatch.setenv("USERPROFILE", r"C:\Users\Reviewer")

    environment = run_demo._offline_environment(no_color=True)

    assert environment["PATH"] == "/safe/path"
    assert environment["NO_COLOR"] == "1"
    assert environment["PYTHONHASHSEED"] == "0"
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PYTHONUNBUFFERED"] == "1"
    assert environment["HOMEDRIVE"] == "C:"
    assert environment["HOMEPATH"] == r"\Users\Reviewer"
    assert environment["USERPROFILE"] == r"C:\Users\Reviewer"
    assert "OPENAI_API_KEY" not in environment
    assert "EXAMPLE_API_KEY" not in environment
    assert "PYTHONPATH" not in environment


def test_quick_plan_treats_weak_exit_one_as_expected(tmp_path: Path) -> None:
    steps = run_demo._build_steps(tmp_path, verbose=True, quick=True)

    assert [step.expected_exit for step in steps] == [1, 0, 1, 0]
    assert [step.expected_quality_failure for step in steps] == [
        True,
        False,
        True,
        False,
    ]
    assert "powershell-gap.yml" in steps[2].command[4]
    assert "powershell-hardened-gap.yml" in steps[3].command[4]
    assert all("--verbose" in step.command for step in steps)
    assert all("suggest-fixture" not in step.command for step in steps)


def test_full_plan_includes_expected_repository_gate_and_evaluation(
    tmp_path: Path,
) -> None:
    steps = run_demo._build_steps(tmp_path, verbose=False, quick=False)

    assert [step.expected_exit for step in steps] == [1, 0, 1, 0, 1, 0, 0]
    assert steps[4].expected_quality_failure is True
    assert "strong-suite.yml" in steps[5].command[4]
    assert steps[6].command[-1] == "--verify"


def test_main_fails_on_unexpected_exit_without_masking_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(run_demo, "_run_step", lambda step, environment: 0)
    monkeypatch.setattr(run_demo, "_missing_artifacts", lambda paths: ())

    exit_code = run_demo.main(["--quick", "--no-color", "--out", str(tmp_path)])

    output = capsys.readouterr().out
    assert exit_code == 1
    assert "expected exit 1, got 0" in output
    assert "DEMO FAILED" in output


def test_quick_demo_runs_public_cli_and_writes_reports(tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(REPOSITORY / "scripts" / "run_demo.py"),
            "--quick",
            "--no-color",
            "--out",
            str(tmp_path / "demo"),
        ],
        cwd=REPOSITORY,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "EXPECTED QUALITY-GATE FAILURE (exit 1)" in completed.stdout
    assert "DEMO PASS" in completed.stdout
    assert "credentials are not inherited" in completed.stdout
    assert (tmp_path / "demo" / "weak" / "report.json").is_file()
    assert (tmp_path / "demo" / "strong" / "report.json").is_file()
    assert (tmp_path / "demo" / "weak-gap" / "gap-report.json").is_file()
    assert (tmp_path / "demo" / "hardened-gap" / "gap-report.json").is_file()

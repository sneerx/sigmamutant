#!/usr/bin/env python3
"""Run SigmaMutant's complete offline demonstration with one command."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPOSITORY = Path(__file__).resolve().parents[1]
EXAMPLES = REPOSITORY / "examples"
EVALUATION_SCRIPT = REPOSITORY / "scripts" / "evaluate_corpus.py"

_SAFE_ENVIRONMENT_NAMES = (
    "COMSPEC",
    "HOMEDRIVE",
    "HOMEPATH",
    "LANG",
    "LC_ALL",
    "PATH",
    "PATHEXT",
    "PYTHONIOENCODING",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "VIRTUAL_ENV",
    "WINDIR",
)


@dataclass(frozen=True, slots=True)
class DemoStep:
    name: str
    command: tuple[str, ...]
    expected_exit: int
    artifacts: tuple[Path, ...] = ()
    expected_quality_failure: bool = False


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run both weak-to-strong axes, repository checks, and evaluation "
            "evidence entirely offline."
        )
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPOSITORY / "artifacts" / "demo",
        help="artifact root (default: artifacts/demo inside the repository)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="show value-free mutation progress from the public CLI",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="run only the weak/strong mutation and event-gap examples",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI color in the runner and child CLI output",
    )
    return parser


def _offline_environment(*, no_color: bool) -> dict[str, str]:
    """Build a minimal child environment without copying credentials."""

    environment = {
        name: os.environ[name] for name in _SAFE_ENVIRONMENT_NAMES if name in os.environ
    }
    environment["PYTHONUNBUFFERED"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    environment["PYTHONNOUSERSITE"] = "1"
    if no_color:
        environment["NO_COLOR"] = "1"
    return environment


def _cli_command(*arguments: str) -> tuple[str, ...]:
    return (sys.executable, "-m", "sigmamutant", *arguments)


def _report_artifacts(directory: Path) -> tuple[Path, ...]:
    return (
        directory / "report.html",
        directory / "report.json",
        directory / "junit.xml",
    )


def _gap_report_artifacts(directory: Path) -> tuple[Path, ...]:
    return (
        directory / "gap-report.html",
        directory / "gap-report.json",
        directory / "gap-junit.xml",
    )


def _build_steps(
    output: Path,
    *,
    verbose: bool,
    quick: bool,
) -> tuple[DemoStep, ...]:
    weak_output = output / "weak"
    strong_output = output / "strong"
    weak_gap_output = output / "weak-gap"
    hardened_gap_output = output / "hardened-gap"
    progress = ("--verbose",) if verbose else ()
    steps = [
        DemoStep(
            name="weak suite exposes fixture gaps",
            command=_cli_command(
                "run",
                str(EXAMPLES / "weak-suite.yml"),
                "--out",
                str(weak_output),
                *progress,
            ),
            expected_exit=1,
            artifacts=_report_artifacts(weak_output),
            expected_quality_failure=True,
        ),
        DemoStep(
            name="strong suite kills the same rule mutations",
            command=_cli_command(
                "run",
                str(EXAMPLES / "strong-suite.yml"),
                "--out",
                str(strong_output),
                *progress,
            ),
            expected_exit=0,
            artifacts=_report_artifacts(strong_output),
        ),
        DemoStep(
            name="weak rule exposes deterministic event-variation gaps",
            command=_cli_command(
                "gap",
                str(EXAMPLES / "powershell-gap.yml"),
                "--out",
                str(weak_gap_output),
                *progress,
            ),
            expected_exit=1,
            artifacts=_gap_report_artifacts(weak_gap_output),
            expected_quality_failure=True,
        ),
        DemoStep(
            name="hardened rule closes the bounded event-variation gaps",
            command=_cli_command(
                "gap",
                str(EXAMPLES / "powershell-hardened-gap.yml"),
                "--out",
                str(hardened_gap_output),
                *progress,
            ),
            expected_exit=0,
            artifacts=_gap_report_artifacts(hardened_gap_output),
        ),
    ]
    if quick:
        return tuple(steps)

    check_output = output / "repository-check"
    green_output = output / "ci-green"
    steps.extend(
        (
            DemoStep(
                name="repository check preserves the intentional weak-suite gate",
                command=_cli_command(
                    "check",
                    str(EXAMPLES),
                    "--out",
                    str(check_output),
                    *progress,
                ),
                expected_exit=1,
                artifacts=(
                    check_output / "summary.html",
                    check_output / "summary.json",
                    check_output / "junit.xml",
                ),
                expected_quality_failure=True,
            ),
            DemoStep(
                name="strong-only CI gate closes green",
                command=_cli_command(
                    "check",
                    str(EXAMPLES / "strong-suite.yml"),
                    "--out",
                    str(green_output),
                    *progress,
                ),
                expected_exit=0,
                artifacts=(
                    green_output / "summary.html",
                    green_output / "summary.json",
                    green_output / "junit.xml",
                    green_output / "strong-suite" / "report.json",
                ),
            ),
            DemoStep(
                name="checked-in 15-domain evaluation evidence is reproducible",
                command=(sys.executable, str(EVALUATION_SCRIPT), "--verify"),
                expected_exit=0,
                artifacts=(
                    REPOSITORY / "docs" / "evaluation.md",
                    REPOSITORY / "benchmarks" / "results.json",
                ),
            ),
        )
    )
    return tuple(steps)


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPOSITORY).as_posix()
    except ValueError:
        return str(resolved)


def _paint(text: str, color: str, *, enabled: bool) -> str:
    return f"\033[{color}m{text}\033[0m" if enabled else text


def _run_step(step: DemoStep, *, environment: dict[str, str]) -> int:
    sys.stdout.flush()
    sys.stderr.flush()
    completed = subprocess.run(
        step.command,
        cwd=REPOSITORY,
        env=environment,
        check=False,
    )
    return completed.returncode


def _missing_artifacts(paths: Iterable[Path]) -> tuple[Path, ...]:
    return tuple(path for path in paths if not path.is_file())


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output = args.out.expanduser()
    if not output.is_absolute():
        output = (Path.cwd() / output).resolve()
    else:
        output = output.resolve()

    required_inputs = (
        EXAMPLES / "weak-suite.yml",
        EXAMPLES / "strong-suite.yml",
        EXAMPLES / "powershell-gap.yml",
        EXAMPLES / "powershell-hardened-gap.yml",
        EVALUATION_SCRIPT,
    )
    missing_inputs = _missing_artifacts(required_inputs)
    if missing_inputs:
        for path in missing_inputs:
            print(f"ERROR missing demo input: {_display_path(path)}", file=sys.stderr)
        return 2

    color = not args.no_color and sys.stdout.isatty()
    environment = _offline_environment(no_color=args.no_color)
    steps = _build_steps(output, verbose=args.verbose, quick=args.quick)
    failures: list[str] = []
    artifact_paths: list[Path] = []

    print("SigmaMutant offline demo")
    print(f"Repository: {_display_path(REPOSITORY)}")
    print(f"Artifacts:  {_display_path(output)}")
    print("Cloud/API providers: disabled (credentials are not inherited)")

    for index, step in enumerate(steps, start=1):
        print()
        print(f"[{index}/{len(steps)}] {step.name}")
        exit_code = _run_step(step, environment=environment)
        missing = _missing_artifacts(step.artifacts)
        artifact_paths.extend(step.artifacts)
        if exit_code != step.expected_exit:
            failures.append(
                f"{step.name}: expected exit {step.expected_exit}, got {exit_code}"
            )
            status = _paint("UNEXPECTED", "31", enabled=color)
        elif missing:
            failures.append(f"{step.name}: missing {len(missing)} expected artifact(s)")
            status = _paint("INCOMPLETE", "31", enabled=color)
        elif step.expected_quality_failure:
            status = _paint("EXPECTED QUALITY-GATE FAILURE", "33", enabled=color)
        else:
            status = _paint("PASS", "32", enabled=color)
        print(f"Step result: {status} (exit {exit_code})")
        for path in missing:
            print(f"  missing: {_display_path(path)}")

    print()
    print("Evidence")
    for path in dict.fromkeys(artifact_paths):
        marker = "ok" if path.is_file() else "missing"
        print(f"  [{marker}] {_display_path(path)}")

    if args.quick:
        print()
        print("Quick mode skipped repository aggregation and corpus verification.")

    if failures:
        print()
        print(_paint("DEMO FAILED", "31", enabled=color))
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print()
    print(_paint("DEMO PASS", "32", enabled=color))
    print("Expected exit 1 results above are quality signals, not tool errors.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

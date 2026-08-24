"""Command-line interface for SigmaMutant."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from sigmamutant import __version__
from sigmamutant.ai.progress import SuggestionProgress
from sigmamutant.ai.service import (
    preflight_suggestion_output_path,
    suggest_fixtures,
    write_suggestion_artifact,
)
from sigmamutant.batch import BatchRunResult, check_suites
from sigmamutant.doctor import collect_doctor_report
from sigmamutant.errors import SigmaMutantError
from sigmamutant.example_project import EXAMPLE_FILES, initialize_example
from sigmamutant.fixture_workflow import (
    PromotionPreview,
    preview_fixture_promotion,
)
from sigmamutant.fixture_workflow import (
    apply_fixture as promote_fixture,
)
from sigmamutant.fixture_workflow import (
    export_fixture as export_verified_fixture,
)
from sigmamutant.mutations import OPERATORS
from sigmamutant.progress import RunProgress
from sigmamutant.runner import run_suite, validate_suite
from sigmamutant.suite import load_suite

app = typer.Typer(
    name="sigmamutant",
    help="Measure how well labelled event fixtures detect mutations in a Sigma rule.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _display_path(path: Path) -> str:
    """Render a useful path without leaking a home-directory username."""

    resolved = path.expanduser().resolve()
    workspace = Path.cwd().resolve()
    try:
        relative = resolved.relative_to(workspace)
        return relative.as_posix() if relative.parts else "."
    except ValueError:
        pass

    home = Path.home().resolve()
    try:
        relative_home = resolved.relative_to(home)
        return (Path("~") / relative_home).as_posix()
    except ValueError:
        return str(resolved)


def _display_error(exc: Exception) -> str:
    """Sanitize common local path prefixes in user-facing errors."""

    message = str(exc)
    replacements = (
        (str(Path.cwd().resolve()), "."),
        (str(Path.home().resolve()), "~"),
    )
    for prefix, replacement in replacements:
        if prefix and prefix != "/":
            message = message.replace(prefix, replacement)
    return message


def _shell_path(path: Path) -> str:
    """Quote a displayed path while preserving shell expansion for $HOME."""

    displayed = _display_path(path)
    if displayed == "~":
        return "$HOME"
    if displayed.startswith("~/"):
        return "$HOME/" + shlex.quote(displayed[2:])
    return shlex.quote(displayed)


def _default_output_dir(suite: Path) -> Path:
    stem = suite.stem.strip(" .") or "suite"
    return Path("artifacts") / stem


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"sigmamutant {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the installed version.",
        ),
    ] = False,
) -> None:
    """Mutation testing for Sigma detection contracts."""


def _render_result(result, *, artifacts: Path | None = None) -> None:
    table = Table(title=f"SigmaMutant — {escape(result.rule_title)}")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    baseline = "[green]pass[/green]" if result.baseline_passed else "[red]fail[/red]"
    table.add_row("Baseline", baseline)
    table.add_row("Fixtures", str(result.fixture_count))
    table.add_row("Killed", str(result.killed))
    table.add_row("Survived", str(result.survived))
    table.add_row("Excluded", str(result.excluded))
    table.add_row("Mutation score", f"{result.score:.1%}")
    table.add_row("Threshold", f"{result.threshold:.1%}")
    console.print(table)
    for error in result.errors:
        console.print("[red]error:[/red] ", Text(error), sep="")
    if not result.baseline_passed or result.errors:
        console.print("[red]RESULT: ERROR[/red] — mutation run did not complete.")
    elif result.passed:
        console.print(
            f"[green]RESULT: PASS[/green] — {result.score:.1%} >= "
            f"{result.threshold:.1%}"
        )
    else:
        console.print(
            f"[red]RESULT: FAIL[/red] — {result.score:.1%} < {result.threshold:.1%}"
        )
    if artifacts is not None:
        console.print("Artifacts: ", Text(_display_path(artifacts)), sep="")


def _render_validation(result) -> None:
    table = Table(title=f"SigmaMutant validation — {escape(result.rule_title)}")
    table.add_column("Check")
    table.add_column("Result", justify="right")
    supported = "[green]pass[/green]" if result.rule_supported else "[red]fail[/red]"
    baseline = "[green]pass[/green]" if result.baseline_passed else "[red]fail[/red]"
    table.add_row("Supported rule", supported)
    table.add_row("Baseline", baseline)
    table.add_row("Fixtures", str(result.fixture_count))
    console.print(table)
    for error in result.errors:
        console.print("[red]error:[/red] ", Text(error), sep="")
    if result.passed:
        console.print("[green]RESULT: PASS[/green] — suite and baseline are valid.")
    else:
        console.print("[red]RESULT: ERROR[/red] — validation failed.")


def _render_survivors(result, *, suite: Path, artifacts: Path) -> None:
    survivors = sorted(
        (item for item in result.mutant_results if item.status == "survived"),
        key=lambda item: item.mutant.id,
    )
    if not survivors:
        return

    limit = 10
    table = Table(title=f"Survivors requiring review — {len(survivors)}")
    table.add_column("Mutant ID")
    table.add_column("Operator")
    table.add_column("YAML path")
    for item in survivors[:limit]:
        table.add_row(
            escape(item.mutant.id),
            escape(item.mutant.operator),
            escape(item.mutant.path),
        )
    console.print(table)
    if len(survivors) > limit:
        console.print(
            f"[yellow]Showing {limit} of {len(survivors)} survivors; "
            "the report contains the complete list.[/yellow]"
        )

    first = survivors[0].mutant.id
    suggestion_path = artifacts / "suggestions" / f"{first}.json"
    command = (
        f"sigmamutant suggest-fixture {_shell_path(suite)} "
        f"--mutant {shlex.quote(first)} --out {_shell_path(suggestion_path)}"
    )
    diff = artifacts / "survivors" / f"{first}.diff"
    console.print("Review first diff: ", Text(_display_path(diff)), sep="")
    console.print("Optional AI: ", Text(command), sep="")


def _exit_code(result) -> int:
    if not result.baseline_passed or result.errors:
        return 2
    return 0 if result.passed else 1


def _create_suggestion_provider(name: str, model: str | None):
    if name == "ollama":
        from sigmamutant.ai.ollama_provider import (
            DEFAULT_OLLAMA_MODEL,
            OllamaProvider,
        )

        return OllamaProvider(model=model or DEFAULT_OLLAMA_MODEL)
    if name == "openai":
        from sigmamutant.ai.openai_provider import (
            DEFAULT_OPENAI_MODEL,
            OpenAIProvider,
        )

        return OpenAIProvider(model=model or DEFAULT_OPENAI_MODEL)
    raise SigmaMutantError(
        f"Unknown fixture suggestion provider {name!r}; available: ollama, openai"
    )


def _render_suggestions(result, *, artifact: Path) -> None:
    table = Table(title=f"AI fixture witness — {escape(result.mutant_id)}")
    table.add_column("Candidate")
    table.add_column("Verdict")
    table.add_column("Original", justify="right")
    table.add_column("Mutant", justify="right")
    table.add_column("Fields", justify="right")
    for suggestion in result.suggestions:
        verdict = (
            "[green]verified[/green]"
            if suggestion.verified
            else "[yellow]rejected[/yellow]"
        )
        original = (
            "-"
            if suggestion.baseline_match is None
            else str(suggestion.baseline_match).lower()
        )
        mutant = (
            "-"
            if suggestion.mutant_match is None
            else str(suggestion.mutant_match).lower()
        )
        table.add_row(
            escape(suggestion.candidate_id),
            verdict,
            original,
            mutant,
            str(len(suggestion.event)),
        )
    console.print(table)
    console.print(
        f"Verified: [green]{result.verified_count}[/green]/{len(result.suggestions)}"
    )
    console.print("Evidence: ", Text(_display_path(artifact)), sep="")


def _render_suggestion_progress(event: SuggestionProgress) -> None:
    details = json.dumps(
        dict(event.details),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    console.print(
        "[cyan]verbose[/cyan] ",
        Text(event.stage),
        " ",
        Text(details),
        sep="",
    )


def _render_run_progress(event: RunProgress) -> None:
    details = json.dumps(
        dict(event.details),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    console.print(
        "[cyan]verbose[/cyan] ",
        Text(event.stage),
        " ",
        Text(details),
        sep="",
    )


@app.command("init-example")
def init_example_command(
    destination: Annotated[
        Path,
        typer.Argument(help="New directory for a self-contained weak/strong example."),
    ],
) -> None:
    """Create an offline example project from files bundled in this installation."""

    try:
        root = initialize_example(destination)
    except (SigmaMutantError, OSError, ValueError) as exc:
        console.print("[red]error:[/red] ", Text(_display_error(exc)), sep="")
        raise typer.Exit(code=2) from exc

    weak_suite = root / "weak-suite.yml"
    strong_suite = root / "strong-suite.yml"
    console.print(
        "[green]Created self-contained example:[/green] ",
        Text(_display_path(root)),
        sep="",
    )
    console.print(f"Files: {len(EXAMPLE_FILES)} (synthetic, offline, no secrets)")
    console.print("Next (the weak run intentionally exits 1):")
    console.print(
        "  ",
        Text(
            f"sigmamutant run {_shell_path(weak_suite)} "
            "--out artifacts/sigmamutant-weak"
        ),
        sep="",
    )
    console.print(
        "  ",
        Text(
            f"sigmamutant run {_shell_path(strong_suite)} "
            "--out artifacts/sigmamutant-strong"
        ),
        sep="",
    )


def _render_batch(result: BatchRunResult) -> None:
    table = Table(title="SigmaMutant repository check")
    table.add_column("Suite")
    table.add_column("Status")
    table.add_column("Score", justify="right")
    table.add_column("Threshold", justify="right")
    table.add_column("Survived", justify="right")
    for entry in result.entries:
        run_result = entry.result
        status_color = {
            "passed": "green",
            "failed": "red",
            "error": "yellow",
        }[entry.status]
        table.add_row(
            escape(entry.display_path),
            f"[{status_color}]{entry.status.upper()}[/{status_color}]",
            "-" if run_result is None else f"{run_result.score:.1%}",
            "-" if run_result is None else f"{run_result.threshold:.1%}",
            "-" if run_result is None else str(run_result.survived),
        )
    console.print(table)
    console.print(
        f"Suites: {len(result.entries)} — "
        f"[green]{result.passed} passed[/green], "
        f"[red]{result.failed} failed[/red], "
        f"[yellow]{result.errors} errors[/yellow]"
    )
    if result.exit_code == 0:
        console.print("[green]RESULT: PASS[/green] — every suite met its gate.")
    elif result.exit_code == 1:
        console.print(
            "[red]RESULT: FAIL[/red] — at least one suite is below threshold."
        )
    else:
        console.print(
            "[yellow]RESULT: ERROR[/yellow] — at least one suite had a technical error."
        )
    console.print(
        "Aggregate evidence: ",
        Text(_display_path(result.output_dir / "summary.html")),
        sep="",
    )


def _render_promotion(preview: PromotionPreview, *, wrote: bool) -> None:
    table = Table(title=f"Verified fixture promotion — {escape(preview.mutant_id)}")
    table.add_column("Check")
    table.add_column("Result", justify="right")
    table.add_row("Fixture ID", escape(preview.fixture.id))
    table.add_row("Original", str(preview.baseline_match).lower())
    table.add_row("Mutant", str(preview.mutant_match).lower())
    table.add_row("Score before", f"{preview.before_score:.1%}")
    table.add_row("Projected score", f"{preview.after_score:.1%}")
    table.add_row("Target mutant killed", str(preview.removed_survivor).lower())
    console.print(table)
    fixture_line = json.dumps(
        {
            "id": preview.fixture.id,
            "expected": preview.fixture.expected,
            "event": preview.fixture.event,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    console.print("Fixture JSONL: ", Text(fixture_line), sep="")
    if wrote:
        console.print(
            "[green]RESULT: APPLIED[/green] — atomically appended to ",
            Text(_display_path(preview.fixture_path)),
            sep="",
        )
    else:
        console.print(
            "[yellow]RESULT: PREVIEW[/yellow] — no input file was modified; "
            "review the JSONL and re-run with --write to apply it."
        )


@app.command()
def validate(
    suite: Annotated[Path, typer.Argument(help="Path to suite.yml")],
) -> None:
    """Validate the suite, supported rule subset, and baseline expectations."""
    try:
        result = validate_suite(suite)
    except (SigmaMutantError, OSError, ValueError) as exc:
        console.print("[red]error:[/red] ", Text(_display_error(exc)), sep="")
        console.print("[red]RESULT: ERROR[/red] — validation failed.")
        raise typer.Exit(code=2) from exc
    _render_validation(result)
    if not result.passed:
        raise typer.Exit(code=2)


@app.command()
def run(
    suite: Annotated[Path, typer.Argument(help="Path to suite.yml")],
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "-o",
            help="Artifact directory; defaults to artifacts/<suite-stem>.",
            show_default=False,
        ),
    ] = None,
    fail_under: Annotated[
        float | None,
        typer.Option(
            "--fail-under",
            min=0.0,
            max=1.0,
            help="Override the suite mutation-score threshold.",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help=(
                "Show value-free baseline, mutant, fixture-result, and "
                "artifact progress."
            ),
        ),
    ] = False,
) -> None:
    """Run all valid mutants, score the suite, and write deterministic reports."""
    artifact_dir = out if out is not None else _default_output_dir(suite)
    try:
        result = run_suite(
            suite,
            output_dir=artifact_dir,
            fail_under=fail_under,
            progress=_render_run_progress if verbose else None,
        )
    except (SigmaMutantError, OSError, ValueError) as exc:
        console.print("[red]error:[/red] ", Text(_display_error(exc)), sep="")
        console.print("[red]RESULT: ERROR[/red] — mutation run did not complete.")
        raise typer.Exit(code=2) from exc
    _render_result(result, artifacts=artifact_dir)
    _render_survivors(result, suite=suite, artifacts=artifact_dir)
    code = _exit_code(result)
    if code:
        raise typer.Exit(code=code)


@app.command()
def check(
    target: Annotated[
        Path,
        typer.Argument(help="Suite file or directory containing named suite files."),
    ],
    out: Annotated[
        Path,
        typer.Option("--out", "-o", help="Aggregate and per-suite artifact root."),
    ] = Path("artifacts"),
    recursive: Annotated[
        bool,
        typer.Option(
            "--recursive",
            "-r",
            help="Discover explicitly named suite files in nested directories.",
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Show value-free progress for every suite and mutant.",
        ),
    ] = False,
) -> None:
    """Run one suite or every named suite in a detection repository."""

    try:
        result = check_suites(
            target,
            output_dir=out,
            recursive=recursive,
            progress=_render_run_progress if verbose else None,
        )
    except (SigmaMutantError, OSError, ValueError) as exc:
        console.print("[red]error:[/red] ", Text(_display_error(exc)), sep="")
        console.print("[yellow]RESULT: ERROR[/yellow] — repository check failed.")
        raise typer.Exit(code=2) from exc
    _render_batch(result)
    if result.exit_code:
        raise typer.Exit(code=result.exit_code)


@app.command("suggest-fixture")
def suggest_fixture(
    suite: Annotated[Path, typer.Argument(help="Path to suite.yml")],
    mutant: Annotated[
        str,
        typer.Option(
            "--mutant",
            help="Surviving mutant ID from report.json, or 'first'.",
        ),
    ],
    provider: Annotated[
        str,
        typer.Option("--provider", help="Candidate generator provider."),
    ] = "ollama",
    model: Annotated[
        str | None,
        typer.Option(
            "--model",
            help="Provider model identifier; defaults depend on the provider.",
        ),
    ] = None,
    candidates: Annotated[
        int,
        typer.Option(
            "--candidates",
            min=1,
            max=3,
            help="Candidates requested in one provider call.",
        ),
    ] = 1,
    out: Annotated[
        Path,
        typer.Option(
            "--out",
            "-o",
            help="Witness JSON path; input fixtures are never modified.",
        ),
    ] = Path("artifacts/ai-suggestion.json"),
    allow_cloud: Annotated[
        bool,
        typer.Option(
            "--allow-cloud",
            help=(
                "Allow sending the rule detection and mutation metadata to "
                "OpenAI; fixture values stay local. Not needed for Ollama."
            ),
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help=(
                "Show secret-safe provider, verification, minimization, and "
                "token-usage progress."
            ),
        ),
    ] = False,
) -> None:
    """Propose synthetic fixtures, then prove them with the local evaluator."""

    try:
        if provider == "openai" and not allow_cloud:
            raise SigmaMutantError(
                "OpenAI is a cloud provider. Re-run with --allow-cloud after "
                "reviewing what is sent; existing fixture values stay local."
            )
        loaded = load_suite(suite)
        artifact_target = preflight_suggestion_output_path(
            out,
            (loaded.path, loaded.rule_path, loaded.fixtures_path),
        )
        selected_provider = _create_suggestion_provider(provider, model)
        result = suggest_fixtures(
            loaded,
            mutant,
            selected_provider,
            candidate_count=candidates,
            progress=_render_suggestion_progress if verbose else None,
        )
        artifact = write_suggestion_artifact(result, artifact_target)
        if verbose:
            _render_suggestion_progress(
                SuggestionProgress(
                    stage="artifact.written",
                    details={
                        "path": _display_path(artifact),
                        "bytes": artifact.stat().st_size,
                        "verified": result.verified_count,
                        "total": len(result.suggestions),
                    },
                )
            )
    except (SigmaMutantError, OSError, ValueError) as exc:
        console.print("[red]error:[/red] ", Text(_display_error(exc)), sep="")
        raise typer.Exit(code=2) from exc
    _render_suggestions(result, artifact=artifact)
    if result.verified_count == 0:
        raise typer.Exit(code=1)


@app.command("export-fixture")
def export_fixture_command(
    evidence: Annotated[Path, typer.Argument(help="AI witness JSON evidence path.")],
    candidate: Annotated[
        str,
        typer.Option("--candidate", help="Verified candidate ID to export."),
    ],
    out: Annotated[
        Path,
        typer.Option("--out", "-o", help="Reviewable one-line JSONL output path."),
    ],
    fixture_id: Annotated[
        str | None,
        typer.Option("--id", help="Optional replacement fixture ID."),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="Replace an existing proposal output file."),
    ] = False,
) -> None:
    """Export verified evidence as JSONL without changing a suite."""

    try:
        destination = export_verified_fixture(
            evidence,
            candidate,
            out,
            fixture_id=fixture_id,
            overwrite=force,
        )
    except (SigmaMutantError, OSError, ValueError) as exc:
        console.print("[red]error:[/red] ", Text(_display_error(exc)), sep="")
        raise typer.Exit(code=2) from exc
    console.print(
        "[green]Exported verified fixture proposal:[/green] ",
        Text(_display_path(destination)),
        sep="",
    )
    console.print("No suite or fixture input was modified.")


@app.command("apply-fixture")
def apply_fixture_command(
    suite: Annotated[Path, typer.Argument(help="Current suite.yml path.")],
    evidence: Annotated[Path, typer.Argument(help="AI witness JSON evidence path.")],
    candidate: Annotated[
        str,
        typer.Option("--candidate", help="Verified candidate ID to re-prove."),
    ],
    fixture_id: Annotated[
        str | None,
        typer.Option("--id", help="Optional replacement fixture ID."),
    ] = None,
    write: Annotated[
        bool,
        typer.Option(
            "--write",
            help="After preview checks pass, atomically append the fixture JSONL.",
        ),
    ] = False,
) -> None:
    """Re-prove a witness and explicitly promote it into fixture JSONL."""

    try:
        if write:
            preview = promote_fixture(
                suite,
                evidence,
                candidate,
                fixture_id=fixture_id,
            )
        else:
            preview = preview_fixture_promotion(
                suite,
                evidence,
                candidate,
                fixture_id=fixture_id,
            )
    except (SigmaMutantError, OSError, ValueError) as exc:
        console.print("[red]error:[/red] ", Text(_display_error(exc)), sep="")
        raise typer.Exit(code=2) from exc
    _render_promotion(preview, wrote=write)


@app.command()
def operators() -> None:
    """List the mutation operators included in this build."""
    table = Table(title="SigmaMutant operators")
    table.add_column("Operator")
    table.add_column("Mutation")
    for operator in OPERATORS:
        table.add_row(operator.name, operator.description)
    console.print(table)


@app.command()
def doctor() -> None:
    """Check core runtime health and optional AI prerequisites offline."""

    report = collect_doctor_report()
    colors = {
        "pass": "green",
        "error": "red",
        "ready": "cyan",
        "available": "cyan",
        "optional": "yellow",
        "info": "blue",
    }
    console.print(Text("SigmaMutant environment", style="bold"))
    for check in report.checks:
        line = Text()
        line.append(f"{check.status.upper():<9}", style=colors[check.status])
        line.append(f" {check.component} — ")
        line.append(check.detail)
        console.print(line)
    if report.healthy:
        console.print(
            "[green]RESULT: PASS[/green] — core runtime is healthy; "
            "optional AI readiness does not affect this result."
        )
        return
    console.print(
        "[red]RESULT: ERROR[/red] — a core runtime dependency is missing or "
        "incompatible."
    )
    raise typer.Exit(code=2)

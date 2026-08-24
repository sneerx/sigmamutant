"""Multi-suite mutation checks for detection-as-code repositories."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from sigmamutant.errors import SigmaMutantError, SuiteError
from sigmamutant.models import LoadedSuite, RunResult
from sigmamutant.progress import ProgressCallback, RunProgress, emit_progress
from sigmamutant.reporting._common import (
    portable_namespace_key,
    preflight_managed_paths,
    safe_stem,
)
from sigmamutant.runner import run_suite
from sigmamutant.suite import declared_suite_input_paths, load_suite

_SUITE_PATTERNS = (
    "*-suite.yml",
    "*-suite.yaml",
    "*.suite.yml",
    "*.suite.yaml",
)


@dataclass(frozen=True, slots=True)
class BatchEntry:
    """One suite outcome in a repository-wide check."""

    suite_path: Path
    display_path: str
    artifact_dir: Path
    result: RunResult | None = None
    error: str | None = None

    @property
    def status(self) -> str:
        if self.error or self.result is None:
            return "error"
        if not self.result.baseline_passed or self.result.errors:
            return "error"
        return "passed" if self.result.passed else "failed"


@dataclass(frozen=True, slots=True)
class BatchRunResult:
    """Deterministic aggregate result for one file or suite directory."""

    target: Path
    output_dir: Path
    entries: tuple[BatchEntry, ...]
    protected_paths: tuple[Path, ...] = ()

    @property
    def passed(self) -> int:
        return sum(entry.status == "passed" for entry in self.entries)

    @property
    def failed(self) -> int:
        return sum(entry.status == "failed" for entry in self.entries)

    @property
    def errors(self) -> int:
        return sum(entry.status == "error" for entry in self.entries)

    @property
    def exit_code(self) -> int:
        if self.errors:
            return 2
        if self.failed:
            return 1
        return 0


def discover_suites(target: str | Path, *, recursive: bool = False) -> tuple[Path, ...]:
    """Return explicitly named suite files without following directory symlinks."""

    path = Path(target).expanduser().resolve()
    if path.is_file():
        return (path,)
    if not path.is_dir():
        raise SuiteError(f"Suite target does not exist: {path}")

    found: set[Path] = set()
    for pattern in _SUITE_PATTERNS:
        candidates = path.rglob(pattern) if recursive else path.glob(pattern)
        for candidate in candidates:
            if candidate.is_file() and not candidate.is_symlink():
                found.add(candidate.resolve())
    suites = tuple(sorted(found, key=lambda item: item.relative_to(path).as_posix()))
    if not suites:
        mode = "recursively" if recursive else "in the target directory"
        raise SuiteError(
            "No suite files matching '*-suite.yml', '*-suite.yaml', "
            f"'*.suite.yml', or '*.suite.yaml' were found {mode}: {path}"
        )
    return suites


def _display_path(suite_path: Path, target: Path) -> str:
    if target.is_file():
        return suite_path.name
    return suite_path.relative_to(target).as_posix()


def _artifact_dir(
    suite_path: Path,
    target: Path,
    output_dir: Path,
) -> Path:
    if target.is_file():
        relative_parent = Path()
    else:
        relative_parent = suite_path.relative_to(target).parent
    return output_dir / relative_parent / safe_stem(suite_path.stem, "suite")


def _artifact_directories(
    suites: tuple[Path, ...],
    target: Path,
    output_dir: Path,
) -> dict[Path, Path]:
    """Allocate stable, unique artifact namespaces for every discovered suite."""

    bases = {
        suite_path: _artifact_dir(suite_path, target, output_dir)
        for suite_path in suites
    }
    counts: dict[str, int] = {}
    for base in bases.values():
        key = portable_namespace_key(base.as_posix())
        counts[key] = counts.get(key, 0) + 1

    allocated: dict[Path, Path] = {}
    used: set[str] = set()
    for suite_path in suites:
        base = bases[suite_path]
        candidate = base
        if counts[portable_namespace_key(base.as_posix())] > 1:
            identity = _display_path(suite_path, target)
            digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
            candidate = base.with_name(f"{base.name[:107]}-{digest}")
        attempt = 1
        while portable_namespace_key(candidate.as_posix()) in used:
            attempt += 1
            suffix = f"-{attempt}"
            candidate = base.with_name(f"{base.name[: 120 - len(suffix)]}{suffix}")
        used.add(portable_namespace_key(candidate.as_posix()))
        allocated[suite_path] = candidate
    return allocated


def check_suites(
    target: str | Path,
    *,
    output_dir: str | Path = "artifacts",
    recursive: bool = False,
    progress: ProgressCallback | None = None,
) -> BatchRunResult:
    """Run every discovered suite and retain technical errors for aggregation."""

    resolved_target = Path(target).expanduser().resolve()
    requested_output = Path(output_dir).expanduser()
    suites = discover_suites(resolved_target, recursive=recursive)
    loaded_suites: dict[Path, LoadedSuite] = {}
    load_errors: dict[Path, str] = {}
    protected_paths: list[Path] = list(suites)
    for suite_path in suites:
        try:
            declared_paths = declared_suite_input_paths(suite_path)
        except (SigmaMutantError, OSError, ValueError):
            # The suite file itself is already protected. A malformed document
            # has no safely resolvable child declarations to add.
            declared_paths = ()
        protected_paths.extend(
            path for path in declared_paths if path not in protected_paths
        )
        try:
            loaded = load_suite(suite_path)
        except (SigmaMutantError, OSError, ValueError) as exc:
            load_errors[suite_path] = str(exc)
            continue
        loaded_suites[suite_path] = loaded
        protected_paths.extend(
            path
            for path in (loaded.path, loaded.rule_path, loaded.fixtures_path)
            if path not in protected_paths
        )

    preflight_managed_paths(
        requested_output,
        filenames=("summary.json", "summary.html", "junit.xml"),
        protected_paths=tuple(protected_paths),
    )
    resolved_output = requested_output.resolve()
    artifact_directories = _artifact_directories(
        suites,
        resolved_target,
        resolved_output,
    )
    for suite_path in suites:
        preflight_managed_paths(
            artifact_directories[suite_path],
            filenames=("report.json", "report.html", "junit.xml"),
            subdirectories=("survivors",),
            protected_paths=tuple(protected_paths),
        )
    entries: list[BatchEntry] = []

    for suite_path in suites:
        artifact_dir = artifact_directories[suite_path]
        display_path = _display_path(suite_path, resolved_target)
        emit_progress(progress, "check.suite.started", suite=display_path)

        def forward(event: RunProgress, *, suite_name: str = display_path) -> None:
            emit_progress(
                progress,
                f"check.{event.stage}",
                suite_path=suite_name,
                **dict(event.details),
            )

        try:
            if suite_path in load_errors:
                raise SuiteError(load_errors[suite_path])
            loaded = loaded_suites[suite_path]
            result = run_suite(
                loaded,
                output_dir=artifact_dir,
                progress=forward if progress else None,
            )
        except (SigmaMutantError, OSError, ValueError) as exc:
            entries.append(
                BatchEntry(
                    suite_path=suite_path,
                    display_path=display_path,
                    artifact_dir=artifact_dir,
                    error=str(exc),
                )
            )
            emit_progress(
                progress,
                "check.suite.completed",
                suite=display_path,
                status="error",
            )
            continue
        entries.append(
            BatchEntry(
                suite_path=suite_path,
                display_path=display_path,
                artifact_dir=artifact_dir,
                result=result,
            )
        )
        emit_progress(
            progress,
            "check.suite.completed",
            suite=display_path,
            status=entries[-1].status,
        )

    batch = BatchRunResult(
        target=resolved_target,
        output_dir=resolved_output,
        entries=tuple(entries),
        protected_paths=tuple(protected_paths),
    )
    from sigmamutant.reporting.batch_report import write_batch_reports

    write_batch_reports(batch)
    emit_progress(
        progress,
        "check.completed",
        total=len(batch.entries),
        passed=batch.passed,
        failed=batch.failed,
        errors=batch.errors,
        exit_code=batch.exit_code,
    )
    return batch

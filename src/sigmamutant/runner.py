"""Baseline guard, mutant execution, scoring, and artifact orchestration."""

from __future__ import annotations

import hashlib
import importlib.metadata
from pathlib import Path

from sigmamutant.errors import RuleError, SigmaMutantError
from sigmamutant.evaluator import SigmaEvaluator
from sigmamutant.models import (
    LoadedSuite,
    MutantResult,
    Observation,
    RunResult,
    ValidationResult,
)
from sigmamutant.mutations import generate_mutants
from sigmamutant.progress import ProgressCallback, emit_progress
from sigmamutant.suite import load_suite


def _version(distribution: str) -> str:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _metadata(suite: LoadedSuite) -> dict[str, object]:
    return {
        "suite_version": suite.config.version,
        "suite_sha256": hashlib.sha256(suite.suite_bytes).hexdigest(),
        "rule_sha256": hashlib.sha256(suite.rule_bytes).hexdigest(),
        "fixtures_sha256": hashlib.sha256(suite.fixtures_bytes).hexdigest(),
        "dependencies": {
            "azuma": _version("azuma"),
            "pysigma": _version("pysigma"),
            "sigmamutant": _version("sigmamutant"),
        },
    }


def _failure_result(
    suite: LoadedSuite,
    threshold: float,
    errors: list[str],
    *,
    metadata: dict[str, object] | None = None,
) -> RunResult:
    return RunResult(
        rule_title=str(suite.rule_document.get("title", "<untitled>")),
        baseline_passed=False,
        score=0.0,
        killed=0,
        survived=0,
        excluded=0,
        mutant_results=(),
        fixture_count=len(suite.fixtures),
        threshold=threshold,
        passed=False,
        errors=tuple(errors),
        metadata=metadata or _metadata(suite),
    )


def _validate_loaded_suite(
    suite: LoadedSuite,
    engine: SigmaEvaluator,
    progress: ProgressCallback | None,
) -> tuple[ValidationResult, dict[str, bool]]:
    """Validate rule support and fixture labels without generating mutants."""

    rule_title = str(suite.rule_document.get("title", "<untitled>"))
    metadata = _metadata(suite)
    emit_progress(
        progress,
        "suite.loaded",
        suite=suite.path.name,
        fixtures=len(suite.fixtures),
    )
    emit_progress(progress, "rule.validation.started")
    try:
        engine.validate_rule(suite.rule_document)
    except Exception as exc:
        emit_progress(
            progress,
            "rule.validation.failed",
            error_type=type(exc).__name__,
        )
        return (
            ValidationResult(
                rule_title=rule_title,
                rule_supported=False,
                baseline_passed=False,
                fixture_count=len(suite.fixtures),
                errors=(str(exc),),
                metadata=metadata,
            ),
            {},
        )
    emit_progress(progress, "rule.validation.passed")

    baseline_matches: dict[str, bool] = {}
    baseline_errors: list[str] = []
    emit_progress(progress, "baseline.started", fixtures=len(suite.fixtures))
    for fixture in suite.fixtures:
        try:
            actual = engine.matches(suite.rule_document, fixture.event)
        except Exception as exc:
            baseline_errors.append(f"{fixture.id}: evaluation failed: {exc}")
            emit_progress(
                progress,
                "baseline.fixture.failed",
                fixture_id=fixture.id,
                error_type=type(exc).__name__,
            )
            continue
        baseline_matches[fixture.id] = actual
        agrees = actual == fixture.expected
        emit_progress(
            progress,
            "baseline.fixture.evaluated",
            fixture_id=fixture.id,
            expected=fixture.expected,
            matched=actual,
            agrees=agrees,
        )
        if not agrees:
            baseline_errors.append(
                f"{fixture.id}: expected {str(fixture.expected).lower()}, "
                f"baseline matched {str(actual).lower()}"
            )

    if baseline_errors:
        emit_progress(progress, "baseline.failed", errors=len(baseline_errors))
    else:
        emit_progress(progress, "baseline.passed", fixtures=len(suite.fixtures))
    return (
        ValidationResult(
            rule_title=rule_title,
            rule_supported=True,
            baseline_passed=not baseline_errors,
            fixture_count=len(suite.fixtures),
            errors=tuple(baseline_errors),
            metadata=metadata,
        ),
        baseline_matches,
    )


def validate_suite(
    suite: str | Path | LoadedSuite,
    *,
    evaluator: SigmaEvaluator | None = None,
    progress: ProgressCallback | None = None,
) -> ValidationResult:
    """Validate inputs, supported rule semantics, and baseline expectations."""

    loaded = load_suite(suite) if not isinstance(suite, LoadedSuite) else suite
    engine = evaluator or SigmaEvaluator()
    result, _ = _validate_loaded_suite(loaded, engine, progress)
    return result


def _write_artifacts(
    result: RunResult,
    suite: LoadedSuite,
    output_dir: str | Path,
    progress: ProgressCallback | None,
) -> None:
    from sigmamutant.reporting import write_all

    try:
        written = write_all(result, suite, Path(output_dir))
    except Exception as exc:
        emit_progress(
            progress,
            "artifacts.failed",
            error_type=type(exc).__name__,
        )
        raise
    survivor_paths = written.get("survivors", ())
    emit_progress(
        progress,
        "artifacts.written",
        reports=["report.html", "report.json", "junit.xml"],
        survivor_files=len(survivor_paths),
    )


def run_suite(
    suite: str | Path | LoadedSuite,
    output_dir: str | Path | None = None,
    fail_under: float | None = None,
    *,
    evaluator: SigmaEvaluator | None = None,
    progress: ProgressCallback | None = None,
) -> RunResult:
    loaded = load_suite(suite) if not isinstance(suite, LoadedSuite) else suite
    threshold = loaded.config.fail_under if fail_under is None else float(fail_under)
    if not 0.0 <= threshold <= 1.0:
        raise SigmaMutantError("fail-under must be between 0 and 1")
    engine = evaluator or SigmaEvaluator()

    validation, baseline_matches = _validate_loaded_suite(loaded, engine, progress)
    if not validation.passed:
        result = _failure_result(
            loaded,
            threshold,
            list(validation.errors),
            metadata=validation.metadata,
        )
        if output_dir is not None:
            _write_artifacts(result, loaded, output_dir, progress)
        emit_progress(
            progress,
            "run.completed",
            result="error",
            killed=0,
            survived=0,
            excluded=0,
            mutation_score="0.0%",
        )
        return result

    mutant_results: list[MutantResult] = []
    mutation_errors: list[str] = []
    mutants = generate_mutants(loaded.rule_document, loaded.rule_bytes)
    emit_progress(progress, "mutation.started", mutants=len(mutants))
    for index, mutant in enumerate(mutants, start=1):
        emit_progress(
            progress,
            "mutant.started",
            index=index,
            total=len(mutants),
            mutant_id=mutant.id,
            operator=mutant.operator,
            path=mutant.path,
        )
        observations: list[Observation] = []
        try:
            engine.validate_rule(mutant.document)
        except RuleError as exc:
            mutant_results.append(
                MutantResult(
                    mutant=mutant,
                    status="excluded",
                    reason=str(exc),
                )
            )
            emit_progress(
                progress,
                "mutant.completed",
                mutant_id=mutant.id,
                status="excluded",
                error_type=type(exc).__name__,
                observations=0,
            )
            continue
        except Exception as exc:
            reason = f"unexpected mutant validation failure: {exc}"
            mutation_errors.append(f"{mutant.id}: {reason}")
            mutant_results.append(
                MutantResult(
                    mutant=mutant,
                    status="excluded",
                    reason=reason,
                )
            )
            emit_progress(
                progress,
                "mutant.completed",
                mutant_id=mutant.id,
                status="excluded",
                error_type=type(exc).__name__,
                observations=0,
            )
            continue
        try:
            for fixture in loaded.fixtures:
                mutant_match = engine.matches(mutant.document, fixture.event)
                observations.append(
                    Observation(
                        fixture_id=fixture.id,
                        expected=fixture.expected,
                        baseline_match=baseline_matches[fixture.id],
                        mutant_match=mutant_match,
                    )
                )
                emit_progress(
                    progress,
                    "mutant.fixture.evaluated",
                    mutant_id=mutant.id,
                    fixture_id=fixture.id,
                    expected=fixture.expected,
                    matched=mutant_match,
                    killed=mutant_match != fixture.expected,
                )
        except Exception as exc:
            reason = f"mutant evaluation failed: {exc}"
            mutation_errors.append(f"{mutant.id}: {reason}")
            mutant_results.append(
                MutantResult(
                    mutant=mutant,
                    status="excluded",
                    observations=tuple(observations),
                    reason=reason,
                )
            )
            emit_progress(
                progress,
                "mutant.completed",
                mutant_id=mutant.id,
                status="excluded",
                error_type=type(exc).__name__,
                observations=len(observations),
            )
            continue
        killed_by = tuple(
            observation.fixture_id
            for observation in observations
            if observation.mutant_match != observation.expected
        )
        mutant_results.append(
            MutantResult(
                mutant=mutant,
                status="killed" if killed_by else "survived",
                killed_by=killed_by,
                observations=tuple(observations),
            )
        )
        emit_progress(
            progress,
            "mutant.completed",
            mutant_id=mutant.id,
            status="killed" if killed_by else "survived",
            killed_by=list(killed_by),
        )

    killed = sum(item.status == "killed" for item in mutant_results)
    survived = sum(item.status == "survived" for item in mutant_results)
    excluded = sum(item.status == "excluded" for item in mutant_results)
    denominator = killed + survived
    score = killed / denominator if denominator else 0.0
    errors = tuple(mutation_errors)
    if denominator == 0:
        errors += ("No valid, non-equivalent mutants were generated for this rule.",)
    result = RunResult(
        rule_title=str(loaded.rule_document.get("title", "<untitled>")),
        baseline_passed=True,
        score=score,
        killed=killed,
        survived=survived,
        excluded=excluded,
        mutant_results=tuple(mutant_results),
        fixture_count=len(loaded.fixtures),
        threshold=threshold,
        passed=not errors and score >= threshold,
        errors=errors,
        metadata=_metadata(loaded),
    )
    if output_dir is not None:
        _write_artifacts(result, loaded, output_dir, progress)
    emit_progress(
        progress,
        "run.completed",
        result=("error" if result.errors else "pass" if result.passed else "fail"),
        killed=result.killed,
        survived=result.survived,
        excluded=result.excluded,
        mutation_score=f"{result.score:.1%}",
    )
    return result

"""Suite orchestration for deterministic event-robustness gap analysis."""

from __future__ import annotations

import hashlib
import importlib.metadata
from pathlib import Path

from sigmamutant.evaluator import SigmaEvaluator
from sigmamutant.event_variations import DEFAULT_MAX_VARIATIONS, EVENT_OPERATORS
from sigmamutant.gap_analysis import analyze_detection_gaps
from sigmamutant.gap_models import DetectionGapResult
from sigmamutant.models import LoadedSuite
from sigmamutant.progress import ProgressCallback, emit_progress
from sigmamutant.reporting.gap_report import (
    preflight_gap_output,
    write_gap_reports,
)
from sigmamutant.suite import load_suite


def _version(distribution: str) -> str:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _metadata(suite: LoadedSuite, max_variations: int) -> dict[str, object]:
    return {
        "suite_version": suite.config.version,
        "suite_sha256": hashlib.sha256(suite.suite_bytes).hexdigest(),
        "rule_sha256": hashlib.sha256(suite.rule_bytes).hexdigest(),
        "fixtures_sha256": hashlib.sha256(suite.fixtures_bytes).hexdigest(),
        "operators": [operator.name for operator in EVENT_OPERATORS],
        "max_variations": max_variations,
        "dependencies": {
            "azuma": _version("azuma"),
            "pysigma": _version("pysigma"),
            "sigmamutant": _version("sigmamutant"),
        },
    }


def run_gap_analysis(
    suite: str | Path | LoadedSuite,
    output_dir: str | Path | None = None,
    fail_under: float = 1.0,
    *,
    max_variations: int = DEFAULT_MAX_VARIATIONS,
    evaluator: SigmaEvaluator | None = None,
    progress: ProgressCallback | None = None,
) -> DetectionGapResult:
    """Analyze a suite's positive seeds without modifying rule or fixture inputs."""

    loaded = load_suite(suite) if not isinstance(suite, LoadedSuite) else suite
    if output_dir is not None:
        preflight_gap_output(loaded, output_dir)

    emit_progress(
        progress,
        "gap.suite.loaded",
        suite=loaded.path.name,
        fixtures=len(loaded.fixtures),
        max_variations=max_variations,
        positive_seeds=sum(fixture.expected is True for fixture in loaded.fixtures),
    )
    emit_progress(progress, "gap.analysis.started")
    result = analyze_detection_gaps(
        loaded.rule_document,
        loaded.fixtures,
        loaded.rule_bytes,
        fail_under=fail_under,
        max_variations=max_variations,
        metadata=_metadata(loaded, max_variations),
        evaluator=evaluator,
    )
    for item in result.variation_results:
        emit_progress(
            progress,
            "gap.variation.evaluated",
            variation_id=item.variation.id,
            source_fixture_id=item.variation.source_fixture_id,
            operator=item.variation.operator,
            path=item.variation.path,
            status=item.status,
            matched=item.variation_match,
        )

    if output_dir is not None:
        try:
            paths = write_gap_reports(result, loaded, output_dir)
        except Exception as exc:
            emit_progress(
                progress,
                "gap.artifacts.failed",
                error_type=type(exc).__name__,
            )
            raise
        emit_progress(
            progress,
            "gap.artifacts.written",
            reports=sorted(path.name for path in paths.values()),
        )
    emit_progress(
        progress,
        "gap.completed",
        result=("error" if result.errors else "pass" if result.passed else "fail"),
        detected=result.detected,
        gap_candidates=result.escaped,
        excluded=result.excluded,
        variant_score=f"{result.score:.1%}",
    )
    return result

"""Fail-closed execution of deterministic event variations against a Sigma rule."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterable
from typing import Any

from sigmamutant.evaluator import SigmaEvaluator
from sigmamutant.event_variations import (
    DEFAULT_MAX_VARIATIONS,
    EventVariationLimitError,
    generate_event_variations,
)
from sigmamutant.gap_models import DetectionGapResult, GapVariationResult
from sigmamutant.models import Fixture


def _error_type(exc: Exception) -> str:
    """Return diagnostic shape without echoing fixture-derived values."""

    return type(exc).__name__


def _canonical_event_sha256(event: dict[str, Any]) -> str:
    payload = json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _failure_result(
    rule_doc: dict[str, Any],
    fixtures: tuple[Fixture, ...],
    errors: list[str],
    threshold: float,
    metadata: dict[str, Any],
) -> DetectionGapResult:
    return DetectionGapResult(
        rule_title=str(rule_doc.get("title", "<untitled>")),
        baseline_passed=False,
        score=0.0,
        detected=0,
        escaped=0,
        excluded=0,
        seed_count=sum(fixture.expected is True for fixture in fixtures),
        fixture_count=len(fixtures),
        variation_results=(),
        threshold=threshold,
        passed=False,
        errors=tuple(errors),
        metadata=copy.deepcopy(metadata),
    )


def _post_baseline_error_result(
    rule_doc: dict[str, Any],
    fixtures: tuple[Fixture, ...],
    error: str,
    threshold: float,
    metadata: dict[str, Any],
) -> DetectionGapResult:
    return DetectionGapResult(
        rule_title=str(rule_doc.get("title", "<untitled>")),
        baseline_passed=True,
        score=0.0,
        detected=0,
        escaped=0,
        excluded=0,
        seed_count=sum(fixture.expected is True for fixture in fixtures),
        fixture_count=len(fixtures),
        variation_results=(),
        threshold=threshold,
        passed=False,
        errors=(error,),
        metadata=copy.deepcopy(metadata),
    )


def analyze_detection_gaps(
    rule_doc: dict[str, Any],
    fixtures: Iterable[Fixture],
    rule_bytes: bytes | None = None,
    *,
    fail_under: float = 1.0,
    max_variations: int = DEFAULT_MAX_VARIATIONS,
    metadata: dict[str, Any] | None = None,
    evaluator: SigmaEvaluator | None = None,
) -> DetectionGapResult:
    """Evaluate conservative positive-event variations against ``rule_doc``.

    Every labelled fixture is baseline-checked before generation starts. A
    mismatched positive *or* negative fixture aborts the analysis. Evaluation
    exceptions exclude the affected variation, become run errors, and make the
    aggregate result fail closed rather than being misreported as an escape.
    """

    working_rule = copy.deepcopy(rule_doc)
    corpus = tuple(copy.deepcopy(tuple(fixtures)))
    result_metadata = copy.deepcopy(metadata) if metadata is not None else {}
    engine = evaluator or SigmaEvaluator()
    input_errors: list[str] = []

    if isinstance(fail_under, bool):
        threshold = 1.0
        input_errors.append("fail-under must be a number between 0 and 1.")
    else:
        try:
            threshold = float(fail_under)
        except (TypeError, ValueError):
            threshold = 1.0
            input_errors.append("fail-under must be a number between 0 and 1.")
        else:
            if not 0.0 <= threshold <= 1.0:
                input_errors.append("fail-under must be between 0 and 1.")
                threshold = 1.0

    if isinstance(max_variations, bool) or not isinstance(max_variations, int):
        variation_limit = DEFAULT_MAX_VARIATIONS
        input_errors.append("max-variations must be a positive integer.")
    else:
        variation_limit = max_variations
        if variation_limit < 1:
            input_errors.append("max-variations must be a positive integer.")

    if not corpus:
        input_errors.append("Detection-gap analysis requires labelled fixtures.")
    ids = [fixture.id for fixture in corpus]
    duplicates = sorted({fixture_id for fixture_id in ids if ids.count(fixture_id) > 1})
    if duplicates:
        input_errors.append(f"Fixture ids must be unique: {', '.join(duplicates)}")
    if not any(fixture.expected for fixture in corpus):
        input_errors.append(
            "Detection-gap analysis requires at least one positive seed fixture."
        )
    for fixture in corpus:
        if not isinstance(fixture.id, str) or not fixture.id.strip():
            input_errors.append("Every fixture must have a non-empty string id.")
            break
        if not isinstance(fixture.expected, bool):
            input_errors.append(
                f"Fixture {fixture.id!r} must have a boolean expected label."
            )
        if not isinstance(fixture.event, dict):
            input_errors.append(f"Fixture {fixture.id!r} event must be a mapping.")
    if not input_errors:
        positive_event_sources: dict[str, str] = {}
        duplicate_events: list[str] = []
        for fixture in sorted(corpus, key=lambda item: item.id):
            if not fixture.expected:
                continue
            event_hash = _canonical_event_sha256(fixture.event)
            original_id = positive_event_sources.setdefault(event_hash, fixture.id)
            if original_id != fixture.id:
                duplicate_events.append(f"{fixture.id} duplicates {original_id}")
        if duplicate_events:
            input_errors.append(
                "Positive fixture event bodies must be unique: "
                + ", ".join(duplicate_events)
            )
    if input_errors:
        return _failure_result(
            working_rule,
            corpus,
            input_errors,
            threshold,
            result_metadata,
        )

    try:
        engine.validate_rule(working_rule)
    except Exception as exc:
        return _failure_result(
            working_rule,
            corpus,
            [
                f"Rule validation failed ({_error_type(exc)}). "
                "Run `sigmamutant validate <suite>` for supported-subset details."
            ],
            threshold,
            result_metadata,
        )

    baseline_errors: list[str] = []
    for fixture in sorted(corpus, key=lambda item: item.id):
        try:
            matched = engine.matches(working_rule, copy.deepcopy(fixture.event))
        except Exception as exc:
            baseline_errors.append(
                f"{fixture.id}: baseline evaluation failed ({_error_type(exc)})."
            )
            continue
        if matched != fixture.expected:
            baseline_errors.append(
                f"{fixture.id}: expected {str(fixture.expected).lower()}, "
                f"baseline matched {str(matched).lower()}"
            )
    if baseline_errors:
        return _failure_result(
            working_rule,
            corpus,
            baseline_errors,
            threshold,
            result_metadata,
        )

    try:
        variations = generate_event_variations(
            working_rule,
            corpus,
            rule_bytes,
            max_variations=variation_limit,
        )
    except EventVariationLimitError as exc:
        return _post_baseline_error_result(
            working_rule,
            corpus,
            str(exc),
            threshold,
            result_metadata,
        )
    if not variations:
        return _post_baseline_error_result(
            working_rule,
            corpus,
            "No applicable safe event variations were generated.",
            threshold,
            result_metadata,
        )

    results: list[GapVariationResult] = []
    run_errors: list[str] = []
    for variation in variations:
        try:
            matched = engine.matches(working_rule, copy.deepcopy(variation.event))
        except Exception as exc:
            reason = f"variation evaluation failed ({_error_type(exc)})."
            run_errors.append(f"{variation.id}: {reason}")
            results.append(
                GapVariationResult(
                    variation=variation,
                    status="excluded",
                    baseline_match=True,
                    variation_match=None,
                    reason=reason,
                )
            )
            continue
        results.append(
            GapVariationResult(
                variation=variation,
                status="detected" if matched else "escaped",
                baseline_match=True,
                variation_match=matched,
            )
        )

    detected = sum(item.status == "detected" for item in results)
    escaped = sum(item.status == "escaped" for item in results)
    excluded = sum(item.status == "excluded" for item in results)
    denominator = detected + escaped
    score = detected / denominator if denominator else 0.0
    if denominator == 0:
        run_errors.append("No event variations were evaluated successfully.")
    return DetectionGapResult(
        rule_title=str(working_rule.get("title", "<untitled>")),
        baseline_passed=True,
        score=score,
        detected=detected,
        escaped=escaped,
        excluded=excluded,
        seed_count=sum(fixture.expected is True for fixture in corpus),
        fixture_count=len(corpus),
        variation_results=tuple(results),
        threshold=threshold,
        passed=not run_errors and denominator > 0 and score >= threshold,
        errors=tuple(run_errors),
        metadata=copy.deepcopy(result_metadata),
    )

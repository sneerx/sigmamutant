"""Deterministically parse, prove, and reduce untrusted fixture candidates."""

from __future__ import annotations

import json
import math
from typing import Any

from sigmamutant.ai.models import (
    FixtureCandidate,
    FixtureFieldContract,
    VerificationResult,
    json_value_type,
)
from sigmamutant.ai.progress import ProgressCallback, emit_progress
from sigmamutant.errors import FixtureSuggestionError
from sigmamutant.evaluator import SigmaEvaluator

MAX_EVENT_BYTES = 4096
MAX_STRING_CHARACTERS = 512


def candidate_to_event(
    candidate: FixtureCandidate,
    required_fields: tuple[FixtureFieldContract, ...] = (),
) -> dict[str, Any]:
    """Convert a candidate to a flat, schema-conforming JSON event."""

    event: dict[str, Any] = {}
    for field in candidate.fields:
        name = field.name.strip()
        if not name:
            raise FixtureSuggestionError(
                f"Candidate {candidate.candidate_id!r} contains a blank field name"
            )
        if name in event:
            raise FixtureSuggestionError(
                f"Candidate {candidate.candidate_id!r} repeats field {name!r}"
            )
        value = field.value
        if isinstance(value, float) and not math.isfinite(value):
            raise FixtureSuggestionError(
                f"Candidate {candidate.candidate_id!r} field {name!r} must be finite"
            )
        if isinstance(value, str) and len(value) > MAX_STRING_CHARACTERS:
            raise FixtureSuggestionError(
                f"Candidate {candidate.candidate_id!r} field {name!r} exceeds "
                f"{MAX_STRING_CHARACTERS} characters"
            )
        event[name] = value
    if not event:
        raise FixtureSuggestionError(
            f"Candidate {candidate.candidate_id!r} must contain at least one field"
        )
    event_bytes = json.dumps(
        event,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(event_bytes) > MAX_EVENT_BYTES:
        raise FixtureSuggestionError(
            f"Candidate {candidate.candidate_id!r} event exceeds "
            f"{MAX_EVENT_BYTES} bytes"
        )
    missing = [field.name for field in required_fields if field.name not in event]
    if missing:
        raise FixtureSuggestionError(
            f"Candidate {candidate.candidate_id!r} is missing fixture-contract "
            f"field(s): {', '.join(missing)}"
        )
    for field in required_fields:
        actual_type = json_value_type(event[field.name])
        if actual_type not in field.json_types:
            allowed = ", ".join(field.json_types)
            raise FixtureSuggestionError(
                f"Candidate {candidate.candidate_id!r} field {field.name!r} has "
                f"JSON type {actual_type!r}; fixture contract allows: {allowed}"
            )
    return event


def _evaluate_pair(
    event: dict[str, Any],
    original_rule: dict[str, Any],
    mutant_rule: dict[str, Any],
    evaluator: SigmaEvaluator,
) -> tuple[bool, bool]:
    return (
        evaluator.matches(original_rule, event),
        evaluator.matches(mutant_rule, event),
    )


def _reduce_one_minimal(
    event: dict[str, Any],
    original_rule: dict[str, Any],
    mutant_rule: dict[str, Any],
    evaluator: SigmaEvaluator,
    *,
    candidate_id: str,
    target_pair: tuple[bool, bool],
    protected_fields: frozenset[str],
    progress: ProgressCallback | None,
) -> tuple[dict[str, Any], tuple[str, ...], bool, bool]:
    """Produce a deterministic one-minimal event outside protected fields."""

    minimized = dict(event)
    removed: list[str] = []
    changed = True
    while changed:
        changed = False
        for name in sorted(minimized):
            if name in protected_fields:
                emit_progress(
                    progress,
                    "candidate.minimization.trial",
                    candidate_id=candidate_id,
                    trial_fields=len(minimized),
                    outcome="fixture_contract_preserved",
                )
                continue
            trial = {key: value for key, value in minimized.items() if key != name}
            try:
                baseline_match, mutant_match = _evaluate_pair(
                    trial,
                    original_rule,
                    mutant_rule,
                    evaluator,
                )
            except Exception:
                emit_progress(
                    progress,
                    "candidate.minimization.trial",
                    candidate_id=candidate_id,
                    trial_fields=len(trial),
                    outcome="evaluation_error",
                )
                raise
            preserves_distinction = (baseline_match, mutant_match) == target_pair
            emit_progress(
                progress,
                "candidate.minimization.trial",
                candidate_id=candidate_id,
                trial_fields=len(trial),
                original=baseline_match,
                mutant=mutant_match,
                preserves_distinction=preserves_distinction,
            )
            if preserves_distinction:
                minimized = trial
                removed.append(name)
                changed = True
    baseline_match, mutant_match = _evaluate_pair(
        minimized,
        original_rule,
        mutant_rule,
        evaluator,
    )
    return minimized, tuple(removed), baseline_match, mutant_match


def verify_candidate(
    candidate: FixtureCandidate,
    original_rule: dict[str, Any],
    mutant_rule: dict[str, Any],
    evaluator: SigmaEvaluator,
    *,
    required_fields: tuple[FixtureFieldContract, ...] = (),
    progress: ProgressCallback | None = None,
) -> VerificationResult:
    """Accept a candidate only when local rule evaluation proves distinction."""

    try:
        event = candidate_to_event(candidate, required_fields)
    except FixtureSuggestionError as exc:
        emit_progress(
            progress,
            "candidate.rejected",
            candidate_id=candidate.candidate_id,
            reason="invalid_candidate",
        )
        return VerificationResult(
            candidate_id=candidate.candidate_id,
            rationale=candidate.rationale,
            event={},
            expected=None,
            baseline_match=None,
            mutant_match=None,
            verified=False,
            rejection_reason=str(exc),
            required_fields=tuple(field.name for field in required_fields),
        )
    emit_progress(
        progress,
        "candidate.parsed",
        candidate_id=candidate.candidate_id,
        fields=len(event),
    )
    try:
        baseline_match, mutant_match = _evaluate_pair(
            event,
            original_rule,
            mutant_rule,
            evaluator,
        )
    except Exception as exc:
        emit_progress(
            progress,
            "candidate.rejected",
            candidate_id=candidate.candidate_id,
            reason="evaluation_error",
        )
        return VerificationResult(
            candidate_id=candidate.candidate_id,
            rationale=candidate.rationale,
            event=event,
            expected=None,
            baseline_match=None,
            mutant_match=None,
            verified=False,
            rejection_reason=f"Local evaluation failed: {exc}",
            proposed_event=event,
            required_fields=tuple(field.name for field in required_fields),
        )
    emit_progress(
        progress,
        "candidate.evaluated",
        candidate_id=candidate.candidate_id,
        original=baseline_match,
        mutant=mutant_match,
    )
    if baseline_match == mutant_match:
        emit_progress(
            progress,
            "candidate.rejected",
            candidate_id=candidate.candidate_id,
            reason="no_distinction",
        )
        return VerificationResult(
            candidate_id=candidate.candidate_id,
            rationale=candidate.rationale,
            event=event,
            expected=None,
            baseline_match=baseline_match,
            mutant_match=mutant_match,
            verified=False,
            rejection_reason=(
                "Original and mutant returned the same result; no regression "
                "fixture was proven."
            ),
            proposed_event=event,
            proposed_baseline_match=baseline_match,
            proposed_mutant_match=mutant_match,
            required_fields=tuple(field.name for field in required_fields),
        )
    proposed_baseline_match = baseline_match
    proposed_mutant_match = mutant_match
    try:
        minimized, removed, baseline_match, mutant_match = _reduce_one_minimal(
            event,
            original_rule,
            mutant_rule,
            evaluator,
            candidate_id=candidate.candidate_id,
            target_pair=(proposed_baseline_match, proposed_mutant_match),
            protected_fields=frozenset(field.name for field in required_fields),
            progress=progress,
        )
    except Exception as exc:
        emit_progress(
            progress,
            "candidate.rejected",
            candidate_id=candidate.candidate_id,
            reason="minimization_error",
        )
        return VerificationResult(
            candidate_id=candidate.candidate_id,
            rationale=candidate.rationale,
            event=event,
            expected=None,
            baseline_match=baseline_match,
            mutant_match=mutant_match,
            verified=False,
            rejection_reason=f"Local one-minimal reduction failed: {exc}",
            proposed_event=event,
            proposed_baseline_match=proposed_baseline_match,
            proposed_mutant_match=proposed_mutant_match,
            required_fields=tuple(field.name for field in required_fields),
        )
    emit_progress(
        progress,
        "candidate.verified",
        candidate_id=candidate.candidate_id,
        original=baseline_match,
        mutant=mutant_match,
        fields_before=len(event),
        fields_after=len(minimized),
        removed=len(removed),
    )
    return VerificationResult(
        candidate_id=candidate.candidate_id,
        rationale=candidate.rationale,
        event=minimized,
        expected=baseline_match,
        baseline_match=baseline_match,
        mutant_match=mutant_match,
        verified=True,
        removed_fields=removed,
        proposed_event=event,
        proposed_baseline_match=proposed_baseline_match,
        proposed_mutant_match=proposed_mutant_match,
        required_fields=tuple(field.name for field in required_fields),
        minimality="one-minimal",
    )

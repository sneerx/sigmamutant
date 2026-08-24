from __future__ import annotations

import re
from typing import Any

import pytest

from sigmamutant.ai.models import (
    FixtureCandidate,
    FixtureFieldContract,
    SuggestedField,
)
from sigmamutant.ai.verifier import candidate_to_event, verify_candidate


def _candidate(
    *fields: tuple[str, Any],
    candidate_id: str = "candidate-1",
    rationale: str = "Exercises the changed decision boundary.",
) -> FixtureCandidate:
    return FixtureCandidate(
        candidate_id=candidate_id,
        rationale=rationale,
        fields=tuple(SuggestedField(name=name, value=value) for name, value in fields),
    )


def test_candidate_to_event_parses_only_json_scalars() -> None:
    candidate = _candidate(
        ("StringField", "value"),
        ("IntegerField", 42),
        ("FloatField", 1.5),
        ("BooleanField", True),
        ("NullField", None),
    )

    assert candidate_to_event(candidate) == {
        "StringField": "value",
        "IntegerField": 42,
        "FloatField": 1.5,
        "BooleanField": True,
        "NullField": None,
    }


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ((("Image", "one"), ("Image", "two")), "repeats|duplicate"),
        ((("", "value"),), "(?i)field"),
        ((("   ", "value"),), "(?i)field"),
    ],
)
def test_candidate_to_event_rejects_duplicate_or_invalid_field_names(
    fields: tuple[tuple[str, Any], ...],
    message: str,
) -> None:
    with pytest.raises(Exception, match=message):
        candidate_to_event(_candidate(*fields))


@pytest.mark.parametrize("value", [{"nested": True}, ["nested"]])
def test_suggested_field_rejects_nested_values(value: Any) -> None:
    with pytest.raises(Exception):
        SuggestedField(name="Image", value=value)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_candidate_to_event_rejects_non_finite_numbers(value: float) -> None:
    with pytest.raises(Exception, match="finite"):
        candidate_to_event(_candidate(("Score", value)))


class _DecisionEvaluator:
    def __init__(
        self,
        *,
        baseline: bool,
        mutant: bool,
        require_signal: bool = False,
    ) -> None:
        self.baseline = baseline
        self.mutant = mutant
        self.require_signal = require_signal

    def matches(
        self,
        rule: dict[str, Any],
        event: dict[str, Any],
    ) -> bool:
        if self.require_signal and event.get("Signal") != "keep":
            return False
        return self.baseline if rule["kind"] == "original" else self.mutant


def test_verifier_rejects_candidate_that_does_not_distinguish_rules() -> None:
    candidate = _candidate(("Image", "cmd.exe"))
    evaluator = _DecisionEvaluator(baseline=False, mutant=False)

    result = verify_candidate(
        candidate,
        {"kind": "original"},
        {"kind": "mutant"},
        evaluator,
    )

    assert result.candidate_id == candidate.candidate_id
    assert result.rationale == candidate.rationale
    assert result.event == {"Image": "cmd.exe"}
    assert result.baseline_match is False
    assert result.mutant_match is False
    assert result.verified is False
    assert result.expected is None
    assert result.removed_fields == ()
    assert result.rejection_reason


@pytest.mark.parametrize(
    ("baseline_match", "mutant_match"),
    [(True, False), (False, True)],
)
def test_verified_expected_value_is_derived_from_original_rule(
    baseline_match: bool,
    mutant_match: bool,
) -> None:
    candidate = _candidate(("Signal", "keep"))
    evaluator = _DecisionEvaluator(
        baseline=baseline_match,
        mutant=mutant_match,
        require_signal=True,
    )

    result = verify_candidate(
        candidate,
        {"kind": "original"},
        {"kind": "mutant"},
        evaluator,
    )

    assert result.verified is True
    assert result.expected is baseline_match
    assert result.baseline_match is baseline_match
    assert result.mutant_match is mutant_match
    assert result.rejection_reason is None


def test_field_minimization_is_deterministic_and_preserves_distinction() -> None:
    candidate = _candidate(
        ("noise_z", "last"),
        ("Signal", "keep"),
        ("noise_a", "first"),
    )
    evaluator = _DecisionEvaluator(
        baseline=True,
        mutant=False,
        require_signal=True,
    )

    first = verify_candidate(
        candidate,
        {"kind": "original"},
        {"kind": "mutant"},
        evaluator,
    )
    second = verify_candidate(
        candidate,
        {"kind": "original"},
        {"kind": "mutant"},
        evaluator,
    )

    assert first == second
    assert first.verified is True
    assert first.event == {"Signal": "keep"}
    assert first.removed_fields == ("noise_a", "noise_z")


def test_reduction_preserves_exact_initial_differential_direction() -> None:
    class DirectionFlipEvaluator:
        def matches(
            self,
            rule: dict[str, Any],
            event: dict[str, Any],
        ) -> bool:
            if event == {"A": "keep", "B": "keep"}:
                return rule["kind"] == "original"
            if event == {"B": "keep"}:
                return rule["kind"] == "mutant"
            return False

    candidate = _candidate(("A", "keep"), ("B", "keep"))

    result = verify_candidate(
        candidate,
        {"kind": "original"},
        {"kind": "mutant"},
        DirectionFlipEvaluator(),
    )

    assert result.verified is True
    assert result.proposed_event == {"A": "keep", "B": "keep"}
    assert result.proposed_baseline_match is True
    assert result.proposed_mutant_match is False
    assert result.event == {"A": "keep", "B": "keep"}
    assert result.baseline_match is True
    assert result.mutant_match is False
    assert result.expected is True
    assert result.removed_fields == ()
    assert result.minimality == "one-minimal"


def test_reduction_preserves_fixture_contract_fields_and_records_proposal() -> None:
    candidate = _candidate(
        ("noise", "remove-me"),
        ("Signal", "keep"),
        ("ParentImage", "synthetic-parent.exe"),
    )
    evaluator = _DecisionEvaluator(
        baseline=True,
        mutant=False,
        require_signal=True,
    )
    contract = (
        FixtureFieldContract(name="Signal", json_types=("string",)),
        FixtureFieldContract(name="ParentImage", json_types=("string",)),
    )

    result = verify_candidate(
        candidate,
        {"kind": "original"},
        {"kind": "mutant"},
        evaluator,
        required_fields=contract,
    )

    assert result.verified is True
    assert result.proposed_event == {
        "noise": "remove-me",
        "Signal": "keep",
        "ParentImage": "synthetic-parent.exe",
    }
    assert result.event == {
        "Signal": "keep",
        "ParentImage": "synthetic-parent.exe",
    }
    assert result.required_fields == ("Signal", "ParentImage")
    assert result.removed_fields == ("noise",)
    assert result.reduction_policy == "preserve-exact-pair-and-fixture-contract"
    assert result.minimality == "one-minimal"


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ((("Signal", "keep"),), "missing fixture-contract.*ParentImage"),
        (
            (("Signal", "keep"), ("ParentImage", 7)),
            "fixture contract allows: string",
        ),
    ],
)
def test_verifier_rejects_candidate_outside_fixture_contract(
    fields: tuple[tuple[str, Any], ...],
    message: str,
) -> None:
    result = verify_candidate(
        _candidate(*fields),
        {"kind": "original"},
        {"kind": "mutant"},
        _DecisionEvaluator(baseline=True, mutant=False),
        required_fields=(
            FixtureFieldContract(name="Signal", json_types=("string",)),
            FixtureFieldContract(name="ParentImage", json_types=("string",)),
        ),
    )

    assert result.verified is False
    assert result.event == {}
    assert result.rejection_reason is not None
    assert re.search(message, result.rejection_reason)


def test_blank_field_becomes_rejected_verification_result() -> None:
    candidate = _candidate(("   ", "value"))
    evaluator = _DecisionEvaluator(baseline=True, mutant=False)

    result = verify_candidate(
        candidate,
        {"kind": "original"},
        {"kind": "mutant"},
        evaluator,
    )

    assert result.verified is False
    assert result.event == {}
    assert result.expected is None
    assert result.baseline_match is None
    assert result.mutant_match is None
    assert result.rejection_reason


def test_suggested_field_rejects_oversized_string_at_schema_boundary() -> None:
    with pytest.raises(Exception, match="512"):
        _candidate(("CommandLine", "x" * 513))

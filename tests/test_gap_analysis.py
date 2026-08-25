from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sigmamutant.evaluator import SigmaEvaluator
from sigmamutant.gap_analysis import analyze_detection_gaps
from sigmamutant.models import Fixture
from sigmamutant.suite import load_suite

REPOSITORY = Path(__file__).resolve().parents[1]


def _rule() -> dict[str, Any]:
    return {
        "title": "Exact PowerShell telemetry",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {
                "Image": r"C:\Program Files\PowerShell\7\pwsh.exe",
                "CommandLine|contains": "-EncodedCommand",
                "ParentImage|endswith": r"\explorer.exe",
            },
            "condition": "selection",
        },
    }


def _fixtures() -> tuple[Fixture, Fixture]:
    return (
        Fixture(
            id="positive",
            expected=True,
            event={
                "Image": r"C:\Program Files\PowerShell\7\pwsh.exe",
                "CommandLine": "pwsh.exe -EncodedCommand QQ==",
                "ParentImage": r"C:\Windows\explorer.exe",
            },
        ),
        Fixture(
            id="negative",
            expected=False,
            event={
                "Image": r"C:\Windows\System32\cmd.exe",
                "CommandLine": "cmd.exe /c echo benign",
                "ParentImage": r"C:\Windows\explorer.exe",
            },
        ),
    )


def test_analysis_classifies_detected_and_escaped_variations() -> None:
    result = analyze_detection_gaps(_rule(), _fixtures(), fail_under=0.4)

    assert result.baseline_passed is True
    assert result.seed_count == 1
    assert result.fixture_count == 2
    assert result.detected > 0
    assert result.escaped > 0
    assert result.excluded == 0
    assert result.score == pytest.approx(result.detected / result.total_scored)
    assert result.threshold == 0.4
    assert result.passed is True
    assert not result.errors
    assert {item.status for item in result.variation_results} == {
        "detected",
        "escaped",
    }


def test_threshold_controls_gate_without_changing_evidence() -> None:
    low = analyze_detection_gaps(_rule(), _fixtures(), fail_under=0.0)
    high = analyze_detection_gaps(_rule(), _fixtures(), fail_under=1.0)

    assert low.variation_results == high.variation_results
    assert low.passed is True
    assert high.passed is False


def test_every_label_is_baseline_checked_before_variation_generation() -> None:
    positive, _ = _fixtures()
    broken_negative = Fixture(
        id="broken-negative",
        expected=False,
        event=copy.deepcopy(positive.event),
    )

    result = analyze_detection_gaps(_rule(), (positive, broken_negative))

    assert result.baseline_passed is False
    assert result.variation_results == ()
    assert result.passed is False
    assert "broken-negative: expected false, baseline matched true" in result.errors


def test_baseline_evaluation_exception_aborts_fail_closed() -> None:
    class BrokenBaselineEvaluator:
        def validate_rule(self, document: dict[str, Any]) -> None:
            return None

        def matches(self, document: dict[str, Any], event: dict[str, Any]) -> bool:
            raise RuntimeError("backend unavailable: fixture-private-value")

    result = analyze_detection_gaps(
        _rule(),
        _fixtures(),
        evaluator=BrokenBaselineEvaluator(),  # type: ignore[arg-type]
    )

    assert result.baseline_passed is False
    assert result.variation_results == ()
    assert len(result.errors) == 2
    assert all("baseline evaluation failed" in error for error in result.errors)
    assert all("RuntimeError" in error for error in result.errors)
    assert all("fixture-private-value" not in error for error in result.errors)


def test_variation_evaluation_exception_is_excluded_and_fails_run() -> None:
    class SelectiveEvaluator:
        def validate_rule(self, document: dict[str, Any]) -> None:
            return None

        def matches(self, document: dict[str, Any], event: dict[str, Any]) -> bool:
            command_line = str(event.get("CommandLine", ""))
            if "  " in command_line:
                raise RuntimeError(
                    "synthetic evaluation failure: fixture-private-value"
                )
            return (
                str(event.get("Image", "")).casefold()
                == r"c:\program files\powershell\7\pwsh.exe"
                and "-encodedcommand" in command_line.casefold()
            )

    result = analyze_detection_gaps(
        _rule(),
        _fixtures(),
        fail_under=0.0,
        evaluator=SelectiveEvaluator(),  # type: ignore[arg-type]
    )

    assert result.baseline_passed is True
    assert result.excluded == 1
    assert len(result.errors) == 1
    assert result.passed is False
    excluded = [item for item in result.variation_results if item.status == "excluded"]
    assert excluded[0].variation_match is None
    assert excluded[0].reason == "variation evaluation failed (RuntimeError)."
    assert "fixture-private-value" not in " ".join(result.errors)


def test_no_applicable_variations_is_an_explicit_error() -> None:
    rule = {
        "title": "Numeric event",
        "logsource": {"category": "application"},
        "detection": {"selection": {"Count": 1}, "condition": "selection"},
    }
    fixtures = (
        Fixture(id="positive", expected=True, event={"Count": 1}),
        Fixture(id="negative", expected=False, event={"Count": 2}),
    )

    result = analyze_detection_gaps(rule, fixtures)

    assert result.baseline_passed is True
    assert result.variation_count == 0
    assert result.passed is False
    assert result.errors == ("No applicable safe event variations were generated.",)


@pytest.mark.parametrize("threshold", [-0.1, 1.1, True, "not-a-number"])
def test_invalid_threshold_fails_closed(threshold: object) -> None:
    result = analyze_detection_gaps(
        _rule(),
        _fixtures(),
        fail_under=threshold,  # type: ignore[arg-type]
    )

    assert result.baseline_passed is False
    assert result.passed is False
    assert result.errors
    assert result.threshold == 1.0


def test_metadata_and_inputs_are_copied_not_aliased() -> None:
    rule = _rule()
    fixtures = _fixtures()
    metadata = {"dependencies": {"azuma": "test"}}
    pristine_rule = copy.deepcopy(rule)
    pristine_fixtures = copy.deepcopy(fixtures)

    result = analyze_detection_gaps(rule, fixtures, metadata=metadata, fail_under=0.0)
    result.metadata["dependencies"] = {"changed": True}

    assert metadata == {"dependencies": {"azuma": "test"}}
    assert rule == pristine_rule
    assert fixtures == pristine_fixtures


def test_duplicate_positive_event_bodies_fail_closed_without_score_weighting() -> None:
    positive, negative = _fixtures()
    duplicate = replace(positive, id="positive-copy")

    result = analyze_detection_gaps(_rule(), (positive, negative, duplicate))

    assert result.baseline_passed is False
    assert result.variation_results == ()
    assert result.passed is False
    assert result.errors == (
        "Positive fixture event bodies must be unique: "
        "positive-copy duplicates positive",
    )


def test_analysis_limit_exhaustion_is_a_post_baseline_fail_closed_error() -> None:
    result = analyze_detection_gaps(
        _rule(),
        _fixtures(),
        max_variations=1,
    )

    assert result.baseline_passed is True
    assert result.variation_results == ()
    assert result.passed is False
    assert result.errors == ("Event variation limit exceeded (max-variations=1).",)


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_analysis_rejects_invalid_variation_limits(limit: object) -> None:
    result = analyze_detection_gaps(
        _rule(),
        _fixtures(),
        max_variations=limit,  # type: ignore[arg-type]
    )

    assert result.baseline_passed is False
    assert result.passed is False
    assert result.errors == ("max-variations must be a positive integer.",)


def test_checked_in_weak_and_hardened_gap_metrics_remain_exact() -> None:
    weak = load_suite(REPOSITORY / "examples" / "powershell-gap.yml")
    hardened = load_suite(REPOSITORY / "examples" / "powershell-hardened-gap.yml")

    weak_result = analyze_detection_gaps(
        weak.rule_document,
        weak.fixtures,
        weak.rule_bytes,
    )
    hardened_result = analyze_detection_gaps(
        hardened.rule_document,
        hardened.fixtures,
        hardened.rule_bytes,
    )

    assert weak_result.fixture_count == hardened_result.fixture_count == 10
    assert weak_result.seed_count == hardened_result.seed_count == 2
    assert (weak_result.variation_count, weak_result.detected, weak_result.escaped) == (
        12,
        8,
        4,
    )
    assert (
        hardened_result.variation_count,
        hardened_result.detected,
        hardened_result.escaped,
    ) == (12, 12, 0)
    assert weak_result.passed is False
    assert hardened_result.passed is True


def test_hardened_example_scopes_short_aliases_to_pwsh() -> None:
    suite = load_suite(REPOSITORY / "examples" / "powershell-hardened-gap.yml")
    fixtures = {fixture.id: fixture for fixture in suite.fixtures}
    evaluator = SigmaEvaluator()

    assert (
        evaluator.matches(
            suite.rule_document,
            fixtures["neg-windows-powershell-pwsh-short-e"].event,
        )
        is False
    )
    assert (
        evaluator.matches(
            suite.rule_document,
            fixtures["neg-windows-powershell-pwsh-short-ec"].event,
        )
        is False
    )

    pwsh_event = copy.deepcopy(fixtures["pos-pwsh-documented-encoded"].event)
    for alias in ("-e", "-ec"):
        pwsh_event["CommandLine"] = f"pwsh.exe -NoLogo {alias} SQBmAA=="
        assert evaluator.matches(suite.rule_document, pwsh_event) is True

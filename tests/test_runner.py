from __future__ import annotations

import hashlib
import json
from pathlib import Path
from xml.etree import ElementTree

import pytest

from sigmamutant.errors import EvaluationError, RuleError, SigmaMutantError
from sigmamutant.progress import RunProgress
from sigmamutant.runner import _version, run_suite, validate_suite
from sigmamutant.suite import load_suite


def test_runner_scores_all_non_excluded_mutants(weak_suite: Path) -> None:
    result = run_suite(weak_suite)

    assert result.baseline_passed is True
    assert result.fixture_count == 2
    assert result.rule_title == "PowerShell encoded command"
    assert result.killed + result.survived == len(result.mutant_results)
    assert result.killed > 0
    assert result.survived > 0
    assert result.score == pytest.approx(
        result.killed / (result.killed + result.survived)
    )

    statuses = {mutant_result.status for mutant_result in result.mutant_results}
    assert statuses <= {"killed", "survived"}


def test_validation_passes_when_rule_has_no_mutation_points(
    no_mutation_suite: Path,
) -> None:
    validation = validate_suite(no_mutation_suite)

    assert validation.passed is True
    assert validation.rule_supported is True
    assert validation.baseline_passed is True
    assert validation.fixture_count == 2
    assert validation.errors == ()

    mutation_run = run_suite(no_mutation_suite)
    assert mutation_run.errors == (
        "No valid, non-equivalent mutants were generated for this rule.",
    )


def test_validation_never_generates_mutants(
    weak_suite: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sigmamutant.runner as runner_module

    def unexpected_mutation(*args, **kwargs):
        raise AssertionError("validation must not generate mutants")

    monkeypatch.setattr(runner_module, "generate_mutants", unexpected_mutation)

    assert validate_suite(weak_suite).passed is True


def test_run_progress_is_ordered_and_omits_fixture_event_values(
    weak_suite: Path,
) -> None:
    events: list[RunProgress] = []

    result = run_suite(weak_suite, progress=events.append)

    assert result.baseline_passed is True
    stages = [event.stage for event in events]
    for expected in (
        "suite.loaded",
        "rule.validation.started",
        "rule.validation.passed",
        "baseline.started",
        "baseline.fixture.evaluated",
        "baseline.passed",
        "mutation.started",
        "mutant.started",
        "mutant.fixture.evaluated",
        "mutant.completed",
        "run.completed",
    ):
        assert expected in stages
    assert stages.index("baseline.passed") < stages.index("mutation.started")
    assert stages[-1] == "run.completed"
    rendered = repr(events)
    assert "EncodedCommand AAAA" not in rendered
    assert r"DOMAIN\alice" not in rendered
    assert all("event" not in event.details for event in events)


def test_runner_emits_machine_and_human_readable_artifacts(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "artifacts"

    result = run_suite(weak_suite, output_dir=output_dir)

    report_json = output_dir / "report.json"
    report_html = output_dir / "report.html"
    junit_xml = output_dir / "junit.xml"
    assert report_json.is_file()
    assert report_html.is_file()
    assert junit_xml.is_file()

    payload = json.loads(report_json.read_text(encoding="utf-8"))
    assert payload["score"] == pytest.approx(result.score)
    assert payload["killed"] == result.killed
    assert payload["survived"] == result.survived
    html = report_html.read_text(encoding="utf-8")
    assert "PowerShell encoded command" in html
    assert f"{result.score:.1%}" in html
    ElementTree.parse(junit_xml)


def test_report_artifacts_are_deterministic_across_output_directories(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"

    run_suite(weak_suite, output_dir=first)
    run_suite(weak_suite, output_dir=second)

    for filename in ("report.json", "report.html", "junit.xml"):
        assert (first / filename).read_bytes() == (second / filename).read_bytes()


def test_threshold_does_not_change_score_calculation(
    weak_suite: Path,
) -> None:
    low_threshold = run_suite(weak_suite, fail_under=0.0)
    high_threshold = run_suite(weak_suite, fail_under=1.0)

    assert low_threshold.score == high_threshold.score
    assert [result.mutant.id for result in low_threshold.mutant_results] == [
        result.mutant.id for result in high_threshold.mutant_results
    ]


def test_run_metadata_uses_loaded_byte_snapshot_after_disk_changes(
    weak_suite: Path,
) -> None:
    loaded = load_suite(weak_suite)
    expected_suite_sha256 = hashlib.sha256(loaded.suite_bytes).hexdigest()
    expected_fixtures_sha256 = hashlib.sha256(loaded.fixtures_bytes).hexdigest()
    loaded.path.write_bytes(b"changed after load\n")
    loaded.fixtures_path.write_bytes(b"changed after load\n")

    result = run_suite(loaded)

    assert result.baseline_passed is True
    assert result.metadata["suite_sha256"] == expected_suite_sha256
    assert result.metadata["fixtures_sha256"] == expected_fixtures_sha256


def test_baseline_mismatch_stops_before_mutation(
    broken_baseline_suite: Path,
) -> None:
    result = run_suite(broken_baseline_suite)

    assert result.baseline_passed is False
    assert result.passed is False
    assert result.score == 0.0
    assert result.killed == 0
    assert result.survived == 0
    assert not result.mutant_results
    assert result.errors


def test_runner_rejects_out_of_range_threshold(weak_suite: Path) -> None:
    with pytest.raises(SigmaMutantError, match="between 0 and 1"):
        run_suite(weak_suite, fail_under=1.01)


def test_rule_validation_failure_is_reported_with_artifacts(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    class RejectingEvaluator:
        def validate_rule(self, document) -> None:
            raise RuleError("unsupported test rule")

    output = tmp_path / "invalid-rule"
    result = run_suite(
        load_suite(weak_suite),
        output_dir=output,
        evaluator=RejectingEvaluator(),  # type: ignore[arg-type]
    )

    assert result.baseline_passed is False
    assert result.errors == ("unsupported test rule",)
    assert (output / "report.json").is_file()
    assert (output / "report.html").is_file()
    assert (output / "junit.xml").is_file()


def test_baseline_evaluation_error_is_reported_with_fixture_id(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    class FailingEvaluator:
        def validate_rule(self, document) -> None:
            return None

        def matches(self, document, event) -> bool:
            raise EvaluationError("synthetic adapter outage")

    output = tmp_path / "baseline-error"
    result = run_suite(
        weak_suite,
        output_dir=output,
        evaluator=FailingEvaluator(),  # type: ignore[arg-type]
    )

    assert result.baseline_passed is False
    assert len(result.errors) == 2
    assert all("evaluation failed" in error for error in result.errors)
    assert all("fixture-" in error for error in result.errors)
    assert (output / "report.json").is_file()


def test_invalid_mutants_are_excluded_and_not_scored(
    weak_suite: Path,
) -> None:
    loaded = load_suite(weak_suite)

    class MutantRejectingEvaluator:
        def validate_rule(self, document) -> None:
            if document is not loaded.rule_document:
                raise RuleError("synthetic invalid mutant")

        def matches(self, document, event) -> bool:
            return (
                str(event.get("Image", "")).lower().endswith("powershell.exe")
                and "-encodedcommand" in str(event.get("CommandLine", "")).lower()
            )

    result = run_suite(
        loaded,
        evaluator=MutantRejectingEvaluator(),  # type: ignore[arg-type]
    )

    assert result.baseline_passed is True
    assert result.killed == result.survived == 0
    assert result.excluded == len(result.mutant_results) > 0
    assert {item.status for item in result.mutant_results} == {"excluded"}
    assert all(
        item.reason == "synthetic invalid mutant" for item in result.mutant_results
    )
    assert result.errors == (
        "No valid, non-equivalent mutants were generated for this rule.",
    )


def test_partial_mutant_evaluation_failure_makes_run_a_technical_error() -> None:
    repository = Path(__file__).resolve().parents[1]
    loaded = load_suite(repository / "examples" / "strong-suite.yml")

    class PartiallyFailingEvaluator:
        def __init__(self) -> None:
            from sigmamutant.evaluator import SigmaEvaluator

            self.delegate = SigmaEvaluator()

        def validate_rule(self, document) -> None:
            self.delegate.validate_rule(document)

        def matches(self, document, event) -> bool:
            selector = document["detection"]["selection_cli"]
            if document is not loaded.rule_document and len(selector) == 1:
                raise EvaluationError("synthetic partial evaluator failure")
            return self.delegate.matches(document, event)

    result = run_suite(
        loaded,
        evaluator=PartiallyFailingEvaluator(),  # type: ignore[arg-type]
    )

    assert result.score == 1.0
    assert result.excluded == 2
    assert result.passed is False
    assert len(result.errors) == 2
    assert all("mutant evaluation failed" in error for error in result.errors)


def test_unexpected_mutant_validation_failure_is_a_technical_error(
    weak_suite: Path,
) -> None:
    loaded = load_suite(weak_suite)

    class UnexpectedValidationFailure:
        def __init__(self) -> None:
            from sigmamutant.evaluator import SigmaEvaluator

            self.delegate = SigmaEvaluator()

        def validate_rule(self, document) -> None:
            if document is not loaded.rule_document:
                raise RuntimeError("validator unavailable")
            self.delegate.validate_rule(document)

        def matches(self, document, event) -> bool:
            return self.delegate.matches(document, event)

    result = run_suite(
        loaded,
        evaluator=UnexpectedValidationFailure(),  # type: ignore[arg-type]
    )

    assert result.killed == result.survived == 0
    assert result.excluded == len(result.mutant_results) > 0
    assert result.passed is False
    assert any(
        "unexpected mutant validation failure" in error for error in result.errors
    )


def test_missing_distribution_version_has_stable_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib.metadata

    def missing(distribution: str) -> str:
        raise importlib.metadata.PackageNotFoundError(distribution)

    monkeypatch.setattr(importlib.metadata, "version", missing)

    assert _version("not-installed") == "unknown"

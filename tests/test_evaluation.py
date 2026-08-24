from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import sigmamutant.evaluation as evaluation
from sigmamutant.errors import SigmaMutantError
from sigmamutant.models import RunResult

REPOSITORY = Path(__file__).resolve().parents[1]
CORPUS_MANIFEST = REPOSITORY / "benchmarks" / "manifest.json"
CORPUS_RESULTS = REPOSITORY / "benchmarks" / "results.json"
CORPUS_DOCUMENT = REPOSITORY / "docs" / "evaluation.md"


def _write_manifest(
    root: Path,
    *,
    cases: list[Any] | None = None,
    **overrides: Any,
) -> Path:
    (root / "weak-suite.yml").write_text("weak\n", encoding="utf-8")
    (root / "strong-suite.yml").write_text("strong\n", encoding="utf-8")
    document: dict[str, Any] = {
        "schema_version": 1,
        "name": "test corpus",
        "data_classification": "synthetic",
        "cases": cases
        if cases is not None
        else [
            {
                "id": "case-one",
                "domain": "test domain",
                "purpose": "exercise the evaluator",
                "weak_suite": "weak-suite.yml",
                "strong_suite": "strong-suite.yml",
            }
        ],
    }
    document.update(overrides)
    destination = root / "manifest.json"
    destination.write_text(json.dumps(document), encoding="utf-8")
    return destination


def _result(
    *,
    score: float,
    rule_hash: str = "rule",
    dependencies: dict[str, str] | None = None,
    baseline_passed: bool = True,
    errors: tuple[str, ...] = (),
) -> RunResult:
    killed = round(score * 10)
    survived = 10 - killed
    return RunResult(
        rule_title="Synthetic test rule",
        baseline_passed=baseline_passed,
        score=score,
        killed=killed,
        survived=survived,
        excluded=0,
        mutant_results=(),
        fixture_count=2,
        threshold=0.0,
        passed=True,
        errors=errors,
        metadata={
            "suite_sha256": "suite",
            "rule_sha256": rule_hash,
            "fixtures_sha256": "fixtures",
            "dependencies": dependencies or {"sigmamutant": "test"},
        },
    )


def _mock_runs(monkeypatch: pytest.MonkeyPatch, *results: RunResult) -> None:
    iterator = iter(results)
    monkeypatch.setattr(evaluation, "run_suite", lambda path: next(iterator))


def test_checked_in_corpus_is_reproducible() -> None:
    payload = evaluation.evaluate_corpus(CORPUS_MANIFEST)

    assert payload == json.loads(CORPUS_RESULTS.read_text(encoding="utf-8"))
    assert evaluation.render_evaluation_markdown(payload) == CORPUS_DOCUMENT.read_text(
        encoding="utf-8"
    )
    assert payload["corpus"]["cases"] == 15
    assert len(payload["corpus"]["domains"]) == 15
    assert payload["summary"]["baselines_passed"] == 30
    assert payload["summary"]["paired_rules_unchanged"] == 15
    assert payload["summary"]["pairs_improved"] == 15
    assert payload["summary"]["strong_suites_at_100_percent"] == 15
    assert payload["summary"]["strong"]["weighted_score"] == 1.0
    assert payload["summary"]["strong"]["excluded"] == 0


def test_fake_corpus_aggregates_pairs_and_empty_operator_maps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _write_manifest(tmp_path)
    _mock_runs(monkeypatch, _result(score=0.4), _result(score=1.0))

    payload = evaluation.evaluate_corpus(manifest)

    assert payload["summary"]["weak"]["weighted_score"] == 0.4
    assert payload["summary"]["strong"]["weighted_score"] == 1.0
    assert payload["summary"]["weak"]["operators"] == {}
    assert payload["cases"][0]["score_delta"] == 0.6


@pytest.mark.parametrize("value", [None, [], "text"])
def test_require_mapping_rejects_non_objects(value: Any) -> None:
    with pytest.raises(SigmaMutantError, match="must be a JSON object"):
        evaluation._require_mapping(value, "subject")


@pytest.mark.parametrize("value", [None, 3, "", "   "])
def test_require_text_rejects_missing_or_blank_values(value: Any) -> None:
    with pytest.raises(SigmaMutantError, match="must be a non-empty string"):
        evaluation._require_text(value, "subject")


def test_require_text_strips_surrounding_whitespace() -> None:
    assert evaluation._require_text("  value \n", "subject") == "value"


def test_phase_summary_handles_no_scoreable_mutants() -> None:
    assert evaluation._phase_summary([]) == {
        "suites": 0,
        "fixtures": 0,
        "scoreable": 0,
        "killed": 0,
        "survived": 0,
        "excluded": 0,
        "weighted_score": 0.0,
        "operators": {},
    }


def test_resolve_suite_rejects_absolute_escape_and_missing_paths(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")

    with pytest.raises(SigmaMutantError, match="must be relative"):
        evaluation._resolve_suite(manifest, str(tmp_path / "suite.yml"), "suite")
    with pytest.raises(SigmaMutantError, match="escapes"):
        evaluation._resolve_suite(manifest, "../suite.yml", "suite")
    with pytest.raises(SigmaMutantError, match="regular suite file"):
        evaluation._resolve_suite(manifest, "missing.yml", "suite")


def test_resolve_suite_rejects_symlink(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    target = tmp_path / "target.yml"
    link = tmp_path / "link.yml"
    manifest.write_text("{}", encoding="utf-8")
    target.write_text("suite", encoding="utf-8")
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(SigmaMutantError, match="regular suite file"):
        evaluation._resolve_suite(manifest, "link.yml", "suite")


def test_evaluate_rejects_missing_symlink_and_invalid_manifest(tmp_path: Path) -> None:
    with pytest.raises(SigmaMutantError, match="regular JSON file"):
        evaluation.evaluate_corpus(tmp_path / "missing.json")

    invalid = tmp_path / "invalid.json"
    invalid.write_bytes(b"\xff")
    with pytest.raises(SigmaMutantError, match="Invalid evaluation manifest"):
        evaluation.evaluate_corpus(invalid)

    target = tmp_path / "target.json"
    link = tmp_path / "manifest-link.json"
    target.write_text("{}", encoding="utf-8")
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    with pytest.raises(SigmaMutantError, match="regular JSON file"):
        evaluation.evaluate_corpus(link)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "must be a JSON object"),
        ({"schema_version": 2}, "schema_version must be 1"),
        (
            {
                "schema_version": 1,
                "name": "x",
                "data_classification": "synthetic",
                "cases": [],
            },
            "cases must be a non-empty list",
        ),
        (
            {
                "schema_version": 1,
                "name": "x",
                "data_classification": "synthetic",
                "cases": "case",
            },
            "cases must be a non-empty list",
        ),
    ],
)
def test_evaluate_rejects_invalid_top_level_documents(
    tmp_path: Path,
    document: Any,
    message: str,
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SigmaMutantError, match=message):
        evaluation.evaluate_corpus(manifest)


def test_evaluate_rejects_non_object_and_duplicate_cases(tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path, cases=["case"])
    with pytest.raises(SigmaMutantError, match=r"cases\[0\].*JSON object"):
        evaluation.evaluate_corpus(manifest)

    duplicate = {
        "id": "duplicate",
        "domain": "domain",
        "purpose": "purpose",
        "weak_suite": "weak-suite.yml",
        "strong_suite": "strong-suite.yml",
    }
    manifest = _write_manifest(tmp_path, cases=[duplicate, duplicate])
    with pytest.raises(SigmaMutantError, match="Duplicate evaluation case id"):
        evaluation.evaluate_corpus(manifest)


@pytest.mark.parametrize(
    ("weak", "strong", "message"),
    [
        (
            _result(score=0.0, baseline_passed=False),
            _result(score=1.0),
            "weak suite failed: baseline did not pass",
        ),
        (
            _result(score=0.4),
            _result(score=0.0, errors=("engine failed",)),
            "strong suite failed: engine failed",
        ),
        (
            _result(score=0.4, rule_hash="weak"),
            _result(score=1.0, rule_hash="strong"),
            "does not use the same rule",
        ),
        (
            _result(score=1.0),
            _result(score=0.4),
            "strong score regressed",
        ),
    ],
)
def test_evaluate_rejects_invalid_pair_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    weak: RunResult,
    strong: RunResult,
    message: str,
) -> None:
    manifest = _write_manifest(tmp_path)
    _mock_runs(monkeypatch, weak, strong)

    with pytest.raises(SigmaMutantError, match=message):
        evaluation.evaluate_corpus(manifest)


def test_evaluate_rejects_dependency_change_between_cases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = {
        "id": "first",
        "domain": "one",
        "purpose": "one",
        "weak_suite": "weak-suite.yml",
        "strong_suite": "strong-suite.yml",
    }
    second = {**first, "id": "second", "domain": "two"}
    manifest = _write_manifest(tmp_path, cases=[first, second])
    v1 = {"sigmamutant": "1"}
    v2 = {"sigmamutant": "2"}
    _mock_runs(
        monkeypatch,
        _result(score=0.4, dependencies=v1),
        _result(score=1.0, dependencies=v1),
        _result(score=0.4, dependencies=v2),
        _result(score=1.0, dependencies=v2),
    )

    with pytest.raises(SigmaMutantError, match="Dependency metadata changed"):
        evaluation.evaluate_corpus(manifest)


def test_evaluate_rejects_dependency_change_within_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _write_manifest(tmp_path)
    _mock_runs(
        monkeypatch,
        _result(score=0.4, dependencies={"sigmamutant": "weak"}),
        _result(score=1.0, dependencies={"sigmamutant": "strong"}),
    )

    with pytest.raises(SigmaMutantError, match="dependency metadata differs by phase"):
        evaluation.evaluate_corpus(manifest)


def test_evaluate_requires_data_classification(
    tmp_path: Path,
) -> None:
    manifest = _write_manifest(tmp_path, data_classification=None)

    with pytest.raises(SigmaMutantError, match="data_classification"):
        evaluation.evaluate_corpus(manifest)


def test_markdown_handles_operators_present_in_only_one_phase() -> None:
    phase = {
        "suites": 1,
        "fixtures": 2,
        "scoreable": 1,
        "killed": 1,
        "survived": 0,
        "excluded": 0,
        "weighted_score": 1.0,
        "operators": {},
    }
    payload = {
        "corpus": {
            "cases": 1,
            "domains": ["test"],
            "data_classification": "synthetic",
        },
        "summary": {
            "baselines_passed": 2,
            "paired_rules_unchanged": 1,
            "pairs_improved": 1,
            "strong_suites_at_100_percent": 1,
            "weak": {
                **phase,
                "operators": {
                    "weak_only": {"killed": 1, "generated": 1},
                },
            },
            "strong": {
                **phase,
                "operators": {
                    "strong_only": {"killed": 1, "generated": 1},
                },
            },
        },
        "cases": [
            {
                "id": "case",
                "domain": "test",
                "weak": {"score": 0.0, "fixtures": 2},
                "strong": {"score": 1.0, "fixtures": 4},
                "score_delta": 1.0,
            }
        ],
    }

    document = evaluation.render_evaluation_markdown(payload)

    assert "| `weak_only` | 1/1 | 0/0 |" in document
    assert "| `strong_only` | 0/0 | 1/1 |" in document

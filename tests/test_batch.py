from __future__ import annotations

import json
import shutil
from pathlib import Path
from xml.etree import ElementTree

import pytest

from sigmamutant.batch import check_suites, discover_suites
from sigmamutant.errors import SigmaMutantError


def _copy_suite(source: Path, destination: Path, name: str) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    suite = destination / f"{name}-suite.yml"
    suite.write_bytes(source.read_bytes())
    shutil.copy2(source.parent / "rule.yml", destination / "rule.yml")
    shutil.copy2(source.parent / "fixtures.jsonl", destination / "fixtures.jsonl")
    return suite


def test_discover_suites_is_explicit_and_recursive(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    first = _copy_suite(weak_suite, root, "first")
    second = _copy_suite(weak_suite, root / "nested", "second")
    (root / "ordinary.yml").write_text("version: 1\n", encoding="utf-8")

    assert discover_suites(root) == (first.resolve(),)
    assert discover_suites(root, recursive=True) == (
        first.resolve(),
        second.resolve(),
    )


def test_check_suites_writes_aggregate_reports_and_uses_exit_one(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    first = _copy_suite(weak_suite, root, "alpha")
    _copy_suite(weak_suite, root / "nested", "beta")
    first.write_text(
        first.read_text(encoding="utf-8").replace("fail_under: 0.0", "fail_under: 1.0"),
        encoding="utf-8",
    )
    output = tmp_path / "evidence"

    result = check_suites(root, output_dir=output, recursive=True)

    assert result.exit_code == 1
    assert result.passed == 1
    assert result.failed == 1
    assert result.errors == 0
    payload = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert payload["summary"] == {
        "errors": 0,
        "exit_code": 1,
        "failed": 1,
        "passed": 1,
        "total": 2,
    }
    assert [item["suite"] for item in payload["suites"]] == [
        "alpha-suite.yml",
        "nested/beta-suite.yml",
    ]
    assert (output / "alpha-suite" / "report.json").is_file()
    assert (output / "nested" / "beta-suite" / "report.json").is_file()
    assert (output / "summary.html").is_file()
    ElementTree.parse(output / "junit.xml")


def test_check_suites_continues_after_technical_error(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    _copy_suite(weak_suite, root, "valid")
    (root / "broken-suite.yml").write_text("version: nope\n", encoding="utf-8")

    result = check_suites(root, output_dir=tmp_path / "evidence")

    assert result.exit_code == 2
    assert result.passed == 1
    assert result.errors == 1
    html = (tmp_path / "evidence" / "summary.html").read_text(encoding="utf-8")
    assert "valid-suite/report.html" in html
    assert "broken-suite/report.html" not in html


def test_check_disambiguates_normalized_suite_artifact_names(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    first = _copy_suite(weak_suite, root, "a b")
    _copy_suite(weak_suite, root, "a#b")
    first.write_text(
        first.read_text(encoding="utf-8").replace(
            "fail_under: 0.0",
            "fail_under: 1.0",
        ),
        encoding="utf-8",
    )
    output = tmp_path / "evidence"

    result = check_suites(root, output_dir=output)

    assert result.exit_code == 1
    assert result.passed == 1
    assert result.failed == 1
    artifact_dirs = [entry.artifact_dir for entry in result.entries]
    assert len(set(artifact_dirs)) == 2
    assert all(path.name.startswith("a-b-suite-") for path in artifact_dirs)
    assert all((path / "report.json").is_file() for path in artifact_dirs)
    payload = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    reported_dirs = [item["artifact_dir"] for item in payload["suites"]]
    assert len(set(reported_dirs)) == 2


def test_discover_suites_rejects_empty_directory(tmp_path: Path) -> None:
    with pytest.raises(Exception, match="No suite files"):
        discover_suites(tmp_path)


def test_check_rejects_symlink_output_directory_without_touching_target(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    _copy_suite(weak_suite, repository, "valid")
    external = tmp_path / "external"
    external.mkdir()
    sentinel = external / "keep.txt"
    sentinel.write_text("keep\n", encoding="utf-8")
    output = tmp_path / "evidence"
    try:
        output.symlink_to(external, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(SigmaMutantError, match="symlink component"):
        check_suites(repository, output_dir=output)

    assert sentinel.read_text(encoding="utf-8") == "keep\n"
    assert sorted(path.name for path in external.iterdir()) == ["keep.txt"]


def test_check_preflights_aggregate_destination_symlink(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    suite = _copy_suite(weak_suite, repository, "valid")
    output = tmp_path / "evidence"
    output.mkdir()
    external = tmp_path / "external-summary.json"
    external.write_text("do-not-change\n", encoding="utf-8")
    try:
        (output / "summary.json").symlink_to(external)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(SigmaMutantError, match="symlink component"):
        check_suites(repository, output_dir=output)

    assert external.read_text(encoding="utf-8") == "do-not-change\n"
    assert not (output / suite.stem).exists()
    assert not (output / "summary.html").exists()
    assert not (output / "junit.xml").exists()


def test_check_rejects_symlinked_per_suite_survivor_directory(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    suite = _copy_suite(weak_suite, repository, "valid")
    output = tmp_path / "evidence"
    artifact_dir = output / suite.stem
    artifact_dir.mkdir(parents=True)
    external = tmp_path / "external-survivors"
    external.mkdir()
    sentinel = external / "keep.yml"
    sentinel.write_text("keep\n", encoding="utf-8")
    try:
        (artifact_dir / "survivors").symlink_to(
            external,
            target_is_directory=True,
        )
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(SigmaMutantError, match="symlink component"):
        check_suites(repository, output_dir=output)

    assert sentinel.read_text(encoding="utf-8") == "keep\n"
    assert not (artifact_dir / "report.json").exists()
    assert not (output / "summary.json").exists()


def test_check_refuses_aggregate_collision_with_fixture_input(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    suite = _copy_suite(weak_suite, repository, "collision")
    fixture_input = repository / "summary.json"
    fixture_input.write_bytes((repository / "fixtures.jsonl").read_bytes())
    suite.write_text(
        suite.read_text(encoding="utf-8").replace(
            "fixtures: fixtures.jsonl",
            "fixtures: summary.json",
        ),
        encoding="utf-8",
    )
    original = fixture_input.read_bytes()

    with pytest.raises(SigmaMutantError, match="input file"):
        check_suites(repository, output_dir=repository)

    assert fixture_input.read_bytes() == original
    assert not (repository / "summary.html").exists()
    assert not (repository / "junit.xml").exists()
    assert not (repository / suite.stem).exists()


def test_check_preserves_invalid_rule_colliding_with_aggregate_report(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    suite = _copy_suite(weak_suite, repository, "broken")
    output = repository / "artifacts"
    output.mkdir()
    rule_input = output / "summary.json"
    original = b"not a YAML mapping\n"
    rule_input.write_bytes(original)
    suite.write_text(
        suite.read_text(encoding="utf-8").replace(
            "rule: rule.yml",
            "rule: artifacts/summary.json",
        ),
        encoding="utf-8",
    )

    with pytest.raises(SigmaMutantError, match="input file"):
        check_suites(repository, output_dir=output)

    assert rule_input.read_bytes() == original
    assert not (output / "summary.html").exists()
    assert not (output / "junit.xml").exists()
    assert not (output / suite.stem).exists()


def test_check_preserves_invalid_fixture_colliding_with_aggregate_report(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    suite = _copy_suite(weak_suite, repository, "broken")
    fixture_input = repository / "junit.xml"
    original = b"not-jsonl\n"
    fixture_input.write_bytes(original)
    suite.write_text(
        suite.read_text(encoding="utf-8").replace(
            "fixtures: fixtures.jsonl",
            "fixtures: junit.xml",
        ),
        encoding="utf-8",
    )

    with pytest.raises(SigmaMutantError, match="input file"):
        check_suites(repository, output_dir=repository)

    assert fixture_input.read_bytes() == original
    assert not (repository / "summary.json").exists()
    assert not (repository / "summary.html").exists()
    assert not (repository / suite.stem).exists()

from __future__ import annotations

import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from sigmamutant.ai.models import (
    FixtureCandidate,
    ProviderResponse,
    SuggestedField,
    SuggestionBatch,
)
from sigmamutant.ai.service import suggest_fixtures, write_suggestion_artifact
from sigmamutant.cli import app
from sigmamutant.runner import run_suite

runner = CliRunner()


class _StaticProvider:
    name = "test"
    model = "static"

    def suggest(self, request) -> ProviderResponse:
        return ProviderResponse(
            batch=SuggestionBatch(
                candidates=(
                    FixtureCandidate(
                        candidate_id="candidate-1",
                        rationale="Covers the removed pwsh alternative.",
                        fields=(
                            SuggestedField(
                                name="Image",
                                value=r"C:\Program Files\PowerShell\7\pwsh.exe",
                            ),
                            SuggestedField(
                                name="CommandLine",
                                value="pwsh.exe -EncodedCommand BBBB",
                            ),
                            SuggestedField(name="User", value=r"DOMAIN\bob"),
                        ),
                    ),
                )
            )
        )


def _verified_evidence(weak_suite: Path, destination: Path) -> tuple[Path, str]:
    target = next(
        item
        for item in run_suite(weak_suite).mutant_results
        if item.status == "survived"
        and item.mutant.operator == "delete_list_item"
        and item.mutant.original == "\\pwsh.exe"
    )
    result = suggest_fixtures(weak_suite, target.mutant.id, _StaticProvider())
    evidence = write_suggestion_artifact(result, destination)
    return evidence, target.mutant.id


def _copy_named_suite(source: Path, destination: Path, name: str) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    suite = destination / f"{name}-suite.yml"
    suite.write_bytes(source.read_bytes())
    shutil.copy2(source.parent / "rule.yml", destination / "rule.yml")
    shutil.copy2(source.parent / "fixtures.jsonl", destination / "fixtures.jsonl")
    return suite


def test_check_cli_runs_recursive_repository_and_writes_aggregate_evidence(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "detections"
    passing = _copy_named_suite(weak_suite, repository, "passing")
    failing = _copy_named_suite(weak_suite, repository / "nested", "failing")
    failing.write_text(
        failing.read_text(encoding="utf-8").replace(
            "fail_under: 0.0",
            "fail_under: 1.0",
        ),
        encoding="utf-8",
    )
    output = tmp_path / "check-artifacts"

    result = runner.invoke(
        app,
        [
            "check",
            str(repository),
            "--recursive",
            "--verbose",
            "--out",
            str(output),
        ],
    )

    assert result.exit_code == 1, result.output
    assert "RESULT: FAIL" in result.output
    assert "1 passed" in result.output
    assert "1 failed" in result.output
    assert "check.suite.started" in result.output
    assert "check.completed" in result.output
    assert "EncodedCommand AAAA" not in result.output
    assert r"DOMAIN\alice" not in result.output
    assert (output / passing.stem / "report.json").is_file()
    assert (output / "nested" / failing.stem / "report.json").is_file()
    assert (output / "summary.json").is_file()
    assert (output / "summary.html").is_file()
    assert (output / "junit.xml").is_file()

    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["summary"] == {
        "errors": 0,
        "exit_code": 1,
        "failed": 1,
        "passed": 1,
        "total": 2,
    }


def test_export_fixture_cli_writes_proposal_without_modifying_suite(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    evidence, _ = _verified_evidence(weak_suite, tmp_path / "evidence.json")
    fixtures = weak_suite.parent / "fixtures.jsonl"
    before = fixtures.read_bytes()
    proposal = tmp_path / "review" / "proposal.jsonl"

    result = runner.invoke(
        app,
        [
            "export-fixture",
            str(evidence),
            "--candidate",
            "candidate-1",
            "--id",
            "review-pwsh-regression",
            "--out",
            str(proposal),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Exported verified fixture proposal" in result.output
    assert "No suite or fixture input was modified" in result.output
    assert fixtures.read_bytes() == before
    lines = proposal.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["id"] == "review-pwsh-regression"
    assert payload["expected"] is True
    assert payload["event"]["Image"].endswith("pwsh.exe")


def test_apply_fixture_cli_previews_by_default_without_writing(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    evidence, _ = _verified_evidence(weak_suite, tmp_path / "evidence.json")
    fixtures = weak_suite.parent / "fixtures.jsonl"
    before = fixtures.read_bytes()

    result = runner.invoke(
        app,
        [
            "apply-fixture",
            str(weak_suite),
            str(evidence),
            "--candidate",
            "candidate-1",
            "--id",
            "preview-pwsh-regression",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "RESULT: PREVIEW" in result.output
    assert "Fixture JSONL:" in result.output
    assert "preview-pwsh-regression" in result.output
    assert "re-run with" in result.output
    assert "--write to apply it" in result.output
    assert fixtures.read_bytes() == before


def test_apply_fixture_cli_write_appends_and_kills_target_mutant(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    evidence, target_id = _verified_evidence(
        weak_suite,
        tmp_path / "evidence.json",
    )
    fixtures = weak_suite.parent / "fixtures.jsonl"
    before_lines = fixtures.read_text(encoding="utf-8").splitlines()

    result = runner.invoke(
        app,
        [
            "apply-fixture",
            str(weak_suite),
            str(evidence),
            "--candidate",
            "candidate-1",
            "--id",
            "applied-pwsh-regression",
            "--write",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "RESULT: APPLIED" in result.output
    after_lines = fixtures.read_text(encoding="utf-8").splitlines()
    assert len(after_lines) == len(before_lines) + 1
    appended = json.loads(after_lines[-1])
    assert appended["id"] == "applied-pwsh-regression"

    rerun = run_suite(weak_suite)
    target = next(item for item in rerun.mutant_results if item.mutant.id == target_id)
    assert target.status == "killed"
    assert "applied-pwsh-regression" in target.killed_by

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import sigmamutant.cli as cli_module
from sigmamutant.ai.models import (
    FixtureCandidate,
    ProviderResponse,
    ProviderUsage,
    SuggestedField,
    SuggestionBatch,
)
from sigmamutant.ai.ollama_provider import DEFAULT_OLLAMA_MODEL, OllamaProvider
from sigmamutant.runner import run_suite
from sigmamutant.suite import load_suite

runner = CliRunner()


def _field(name: str, value: Any) -> SuggestedField:
    return SuggestedField(name=name, value=value)


def _target_survivor(suite_path: Path):
    result = run_suite(suite_path)
    return next(
        item
        for item in result.mutant_results
        if item.status == "survived"
        and item.mutant.operator == "delete_list_item"
        and item.mutant.original == "\\pwsh.exe"
    )


class _StaticProvider:
    name = "fake-openai"
    model = "fake-structured-output"

    def __init__(self, candidate: FixtureCandidate) -> None:
        self.candidate = candidate
        self.calls = 0

    def suggest(self, request) -> ProviderResponse:
        self.calls += 1
        return ProviderResponse(
            batch=SuggestionBatch(candidates=(self.candidate,)),
            response_id="fake-response",
            usage=ProviderUsage(
                input_tokens=101,
                output_tokens=23,
                total_tokens=124,
            ),
        )


def _verified_candidate() -> FixtureCandidate:
    return FixtureCandidate(
        candidate_id="verified-pwsh",
        rationale="Covers the removed pwsh image alternative.",
        fields=(
            _field("Image", r"C:\Program Files\PowerShell\7\pwsh.exe"),
            _field("CommandLine", "pwsh.exe -EncodedCommand BBBB"),
            _field("User", r"DOMAIN\bob"),
        ),
    )


def _no_witness_candidate() -> FixtureCandidate:
    return FixtureCandidate(
        candidate_id="unrelated",
        rationale="A deliberately unrelated event.",
        fields=(
            _field("Image", r"C:\Windows\System32\cmd.exe"),
            _field("CommandLine", "cmd.exe /c hostname"),
            _field("User", r"DOMAIN\bob"),
        ),
    )


def test_provider_factory_uses_ollama_specific_default_model() -> None:
    provider = cli_module._create_suggestion_provider("ollama", None)

    assert isinstance(provider, OllamaProvider)
    assert provider.model == DEFAULT_OLLAMA_MODEL


def test_cli_requires_explicit_cloud_opt_in_before_provider_creation(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    provider_created = False

    def forbidden_factory(name: str, model: str):
        nonlocal provider_created
        provider_created = True
        raise AssertionError("provider must not be created without opt-in")

    monkeypatch.setattr(
        cli_module,
        "_create_suggestion_provider",
        forbidden_factory,
    )
    result = runner.invoke(
        cli_module.app,
        [
            "suggest-fixture",
            str(weak_suite),
            "--mutant",
            "first",
            "--provider",
            "openai",
            "--out",
            str(tmp_path / "must-not-exist.json"),
        ],
    )

    assert result.exit_code == 2
    assert "--allow-cloud" in result.output
    assert provider_created is False
    assert not (tmp_path / "must-not-exist.json").exists()


def test_cli_verified_witness_writes_fixture_and_separate_proof(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = _target_survivor(weak_suite)
    provider = _StaticProvider(_verified_candidate())
    monkeypatch.setattr(
        cli_module,
        "_create_suggestion_provider",
        lambda name, model: provider,
    )
    artifact = tmp_path / "verified.json"

    result = runner.invoke(
        cli_module.app,
        [
            "suggest-fixture",
            str(weak_suite),
            "--mutant",
            target.mutant.id,
            "--candidates",
            "1",
            "--out",
            str(artifact),
        ],
    )

    assert result.exit_code == 0, result.output
    assert provider.calls == 1
    assert artifact.is_file()
    assert "Verified:" in result.output

    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["summary"]["verified"] == 1
    assert payload["summary"]["rejected"] == 0
    suggestion = payload["suggestions"][0]
    fixture = suggestion["fixture"]
    assert set(fixture) == {"id", "expected", "event"}
    assert fixture["expected"] is True
    assert fixture["event"] == suggestion["event"]
    assert "proof" not in fixture
    proof = suggestion["proof"]
    assert proof["baseline_match"] is True
    assert proof["mutant_match"] is False
    assert proof["distinguishes"] is True
    assert proof["claim_scope"] == "azuma"
    assert proof["telemetry_realism"] == "unverified"
    assert len(proof["rule_sha256"]) == 64
    assert len(proof["mutant_sha256"]) == 64
    assert len(proof["event_sha256"]) == 64


def test_cli_defaults_to_local_ollama_provider(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = _target_survivor(weak_suite)
    provider = _StaticProvider(_verified_candidate())
    selected: list[tuple[str, str | None]] = []

    def factory(name: str, model: str | None):
        selected.append((name, model))
        return provider

    monkeypatch.setattr(cli_module, "_create_suggestion_provider", factory)
    result = runner.invoke(
        cli_module.app,
        [
            "suggest-fixture",
            str(weak_suite),
            "--mutant",
            target.mutant.id,
            "--out",
            str(tmp_path / "local-default.json"),
        ],
    )

    assert result.exit_code == 0, result.output
    assert selected == [("ollama", None)]
    assert "suite.loaded" not in result.output
    payload = json.loads((tmp_path / "local-default.json").read_text(encoding="utf-8"))
    assert payload["summary"]["requested"] == 1


@pytest.mark.parametrize("verbose_flag", ["--verbose", "-v"])
def test_cli_verbose_shows_secret_safe_live_progress(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
    verbose_flag: str,
) -> None:
    target = _target_survivor(weak_suite)
    provider = _StaticProvider(_verified_candidate())
    monkeypatch.setattr(
        cli_module,
        "_create_suggestion_provider",
        lambda name, model: provider,
    )
    artifact = tmp_path / f"verbose-{verbose_flag.lstrip('-')}.json"

    result = runner.invoke(
        cli_module.app,
        [
            "suggest-fixture",
            str(weak_suite),
            "--mutant",
            target.mutant.id,
            verbose_flag,
            "--out",
            str(artifact),
        ],
    )

    assert result.exit_code == 0, result.output
    expected_stages = (
        "suite.loaded",
        "baseline.started",
        "baseline.passed",
        "mutant.selected",
        "prompt.prepared",
        "provider.request.started",
        "provider.response.received",
        "candidate.received",
        "candidate.parsed",
        "candidate.evaluated",
        "candidate.minimization.trial",
        "candidate.verified",
        "verification.completed",
        "artifact.written",
    )
    positions = [result.output.index(stage) for stage in expected_stages]
    assert positions == sorted(positions)
    assert '"total_tokens":124' in result.output
    assert "Covers the removed pwsh" not in result.output
    assert "EncodedCommand BBBB" not in result.output
    assert r"DOMAIN\bob" not in result.output
    assert "OPENAI_API_KEY" not in result.output

    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["provider"]["usage"] == {
        "input_tokens": 101,
        "output_tokens": 23,
        "total_tokens": 124,
    }


def test_verbose_does_not_change_evidence_bytes(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = _target_survivor(weak_suite)
    provider = _StaticProvider(_verified_candidate())
    monkeypatch.setattr(
        cli_module,
        "_create_suggestion_provider",
        lambda name, model: provider,
    )
    quiet = tmp_path / "quiet.json"
    verbose = tmp_path / "verbose.json"

    quiet_result = runner.invoke(
        cli_module.app,
        [
            "suggest-fixture",
            str(weak_suite),
            "--mutant",
            target.mutant.id,
            "--out",
            str(quiet),
        ],
    )
    verbose_result = runner.invoke(
        cli_module.app,
        [
            "suggest-fixture",
            str(weak_suite),
            "--mutant",
            target.mutant.id,
            "--verbose",
            "--out",
            str(verbose),
        ],
    )

    assert quiet_result.exit_code == 0, quiet_result.output
    assert verbose_result.exit_code == 0, verbose_result.output
    assert quiet.read_bytes() == verbose.read_bytes()


def test_cli_no_verified_witness_writes_evidence_and_exits_one(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = _target_survivor(weak_suite)
    provider = _StaticProvider(_no_witness_candidate())
    monkeypatch.setattr(
        cli_module,
        "_create_suggestion_provider",
        lambda name, model: provider,
    )
    artifact = tmp_path / "rejected.json"

    result = runner.invoke(
        cli_module.app,
        [
            "suggest-fixture",
            str(weak_suite),
            "--mutant",
            target.mutant.id,
            "--allow-cloud",
            "--candidates",
            "1",
            "--out",
            str(artifact),
        ],
    )

    assert result.exit_code == 1, result.output
    assert provider.calls == 1
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["summary"]["verified"] == 0
    assert payload["summary"]["rejected"] == 1
    suggestion = payload["suggestions"][0]
    assert suggestion["fixture"] is None
    assert suggestion["verified"] is False
    assert suggestion["proof"]["distinguishes"] is False


@pytest.mark.parametrize("protected_name", ["suite", "rule", "fixtures"])
def test_cli_preflights_protected_inputs_before_provider_construction(
    weak_suite: Path,
    monkeypatch,
    protected_name: str,
) -> None:
    target = _target_survivor(weak_suite)
    provider = _StaticProvider(_verified_candidate())
    provider_constructions = 0

    def factory(name: str, model: str | None):
        nonlocal provider_constructions
        provider_constructions += 1
        return provider

    monkeypatch.setattr(cli_module, "_create_suggestion_provider", factory)
    loaded = load_suite(weak_suite)
    protected_path = {
        "suite": loaded.path,
        "rule": loaded.rule_path,
        "fixtures": loaded.fixtures_path,
    }[protected_name]
    original_bytes = protected_path.read_bytes()

    result = runner.invoke(
        cli_module.app,
        [
            "suggest-fixture",
            str(weak_suite),
            "--mutant",
            target.mutant.id,
            "--allow-cloud",
            "--candidates",
            "1",
            "--out",
            str(protected_path),
        ],
    )

    assert result.exit_code == 2
    assert "Refusing to overwrite" in result.output
    assert provider_constructions == 0
    assert provider.calls == 0
    assert protected_path.read_bytes() == original_bytes


def test_cli_preflights_case_alias_input_before_provider_construction(
    weak_suite: Path,
    monkeypatch,
) -> None:
    target = _target_survivor(weak_suite)
    provider_created = False
    loaded = load_suite(weak_suite)
    protected_path = loaded.fixtures_path
    alias = protected_path.with_name(protected_path.name.upper())
    if not alias.exists() or not os.path.samefile(alias, protected_path):
        pytest.skip("test directory is not case-insensitive")
    original_bytes = protected_path.read_bytes()

    def forbidden_factory(name: str, model: str | None):
        nonlocal provider_created
        provider_created = True
        return _StaticProvider(_verified_candidate())

    monkeypatch.setattr(cli_module, "_create_suggestion_provider", forbidden_factory)

    result = runner.invoke(
        cli_module.app,
        [
            "suggest-fixture",
            str(weak_suite),
            "--mutant",
            target.mutant.id,
            "--out",
            str(alias),
        ],
    )

    assert result.exit_code == 2
    assert "Refusing to overwrite" in result.output
    assert provider_created is False
    assert protected_path.read_bytes() == original_bytes


def test_cli_preflights_symlink_output_before_provider_construction(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = _target_survivor(weak_suite)
    provider_created = False

    def forbidden_factory(name: str, model: str | None):
        nonlocal provider_created
        provider_created = True
        return _StaticProvider(_verified_candidate())

    monkeypatch.setattr(cli_module, "_create_suggestion_provider", forbidden_factory)
    symlink_target = tmp_path / "existing.json"
    symlink_target.write_text("do-not-change\n", encoding="utf-8")
    output_path = tmp_path / "suggestion.json"
    try:
        output_path.symlink_to(symlink_target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    result = runner.invoke(
        cli_module.app,
        [
            "suggest-fixture",
            str(weak_suite),
            "--mutant",
            target.mutant.id,
            "--out",
            str(output_path),
        ],
    )

    assert result.exit_code == 2
    assert "symlink" in result.output
    assert provider_created is False
    assert symlink_target.read_text(encoding="utf-8") == "do-not-change\n"


def test_cli_preflights_nonportable_output_alias_before_provider_construction(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = _target_survivor(weak_suite)
    provider_created = False
    existing = tmp_path / "SUGGESTION.JSON"
    existing.write_text("do-not-change\n", encoding="utf-8")

    def forbidden_factory(name: str, model: str | None):
        nonlocal provider_created
        provider_created = True
        return _StaticProvider(_verified_candidate())

    monkeypatch.setattr(cli_module, "_create_suggestion_provider", forbidden_factory)

    result = runner.invoke(
        cli_module.app,
        [
            "suggest-fixture",
            str(weak_suite),
            "--mutant",
            target.mutant.id,
            "--out",
            str(tmp_path / "suggestion.json"),
        ],
    )

    assert result.exit_code == 2
    assert "Unicode normalization" in result.output
    assert provider_created is False
    assert existing.read_text(encoding="utf-8") == "do-not-change\n"


def test_cli_preflights_symlink_output_parent_before_provider_construction(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = _target_survivor(weak_suite)
    provider_created = False

    def forbidden_factory(name: str, model: str | None):
        nonlocal provider_created
        provider_created = True
        return _StaticProvider(_verified_candidate())

    monkeypatch.setattr(cli_module, "_create_suggestion_provider", forbidden_factory)
    external = tmp_path / "external"
    external.mkdir()
    sentinel = external / "keep.json"
    sentinel.write_text("do-not-change\n", encoding="utf-8")
    linked_parent = tmp_path / "linked"
    try:
        linked_parent.symlink_to(external, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    result = runner.invoke(
        cli_module.app,
        [
            "suggest-fixture",
            str(weak_suite),
            "--mutant",
            target.mutant.id,
            "--out",
            str(linked_parent / "suggestion.json"),
        ],
    )

    assert result.exit_code == 2
    assert "symlink component" in result.output
    assert provider_created is False
    assert sentinel.read_text(encoding="utf-8") == "do-not-change\n"
    assert not (external / "suggestion.json").exists()


def test_cli_preflights_invalid_output_parent_before_provider_construction(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    target = _target_survivor(weak_suite)
    provider_created = False

    def forbidden_factory(name: str, model: str | None):
        nonlocal provider_created
        provider_created = True
        return _StaticProvider(_verified_candidate())

    monkeypatch.setattr(cli_module, "_create_suggestion_provider", forbidden_factory)
    parent_file = tmp_path / "not-a-directory"
    parent_file.write_text("keep\n", encoding="utf-8")

    result = runner.invoke(
        cli_module.app,
        [
            "suggest-fixture",
            str(weak_suite),
            "--mutant",
            target.mutant.id,
            "--out",
            str(parent_file / "suggestion.json"),
        ],
    )

    assert result.exit_code == 2
    assert "not writable" in result.output
    assert provider_created is False
    assert parent_file.read_text(encoding="utf-8") == "keep\n"

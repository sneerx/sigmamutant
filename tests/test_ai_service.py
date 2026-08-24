from __future__ import annotations

import copy
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

import sigmamutant.ai.service as service_module
from sigmamutant.ai.models import (
    FixtureCandidate,
    ProviderResponse,
    SuggestedField,
    SuggestionBatch,
)
from sigmamutant.ai.progress import SuggestionProgress
from sigmamutant.ai.service import (
    preflight_suggestion_output_path,
    suggest_fixtures,
    write_suggestion_artifact,
)
from sigmamutant.runner import run_suite
from sigmamutant.suite import load_suite


def _field(name: str, value: Any) -> SuggestedField:
    return SuggestedField(name=name, value=value)


def _candidate(
    candidate_id: str,
    *,
    image: str,
    command_line: str,
    user: str,
) -> FixtureCandidate:
    return FixtureCandidate(
        candidate_id=candidate_id,
        rationale="Synthetic event around the selected survivor.",
        fields=(
            _field("Image", image),
            _field("CommandLine", command_line),
            _field("User", user),
        ),
    )


def _target_survivor(suite_path: Path):
    result = run_suite(suite_path)
    return next(
        item
        for item in result.mutant_results
        if item.status == "survived"
        and item.mutant.operator == "delete_list_item"
        and item.mutant.original == "\\pwsh.exe"
    )


class _CapturingProvider:
    name = "test-provider"
    model = "fixture-model-v1"

    def __init__(self, candidates: tuple[FixtureCandidate, ...]) -> None:
        self.candidates = candidates
        self.requests: list[Any] = []

    def suggest(self, request) -> ProviderResponse:
        self.requests.append(request)
        return ProviderResponse(
            batch=SuggestionBatch(candidates=self.candidates),
            response_id="response-123",
        )


def test_service_selects_survivor_verifies_candidates_and_redacts_fixtures(
    weak_suite: Path,
) -> None:
    target = _target_survivor(weak_suite)
    provider = _CapturingProvider(
        (
            _candidate(
                "verified-pwsh",
                image=r"C:\Program Files\PowerShell\7\pwsh.exe",
                command_line="pwsh.exe -EncodedCommand BBBB",
                user=r"DOMAIN\bob",
            ),
            _candidate(
                "rejected-unrelated",
                image=r"C:\Windows\System32\cmd.exe",
                command_line="cmd.exe /c hostname",
                user=r"DOMAIN\bob",
            ),
        )
    )

    result = suggest_fixtures(
        load_suite(weak_suite),
        target.mutant.id,
        provider,
        candidate_count=2,
    )

    assert result.suite_name == weak_suite.name
    assert result.rule_title == "PowerShell encoded command"
    assert result.mutant_id == target.mutant.id
    assert result.operator == target.mutant.operator
    assert result.path == target.mutant.path
    assert result.provider == provider.name
    assert result.model == provider.model
    assert result.response_id == "response-123"
    assert len(result.prompt_sha256) == 64
    assert result.requested_candidates == 2
    assert len(result.suggestions) == 2
    assert result.verified_count == 1
    assert [item.verified for item in result.suggestions] == [True, False]

    assert len(provider.requests) == 1
    request = provider.requests[0]
    assert request.candidate_count == 2
    assert request.mutant_id == target.mutant.id
    shape_fields = {
        field["name"] for shape in request.fixture_shape for field in shape["fields"]
    }
    assert shape_fields == {"CommandLine", "Image", "User"}
    assert [(field.name, field.json_types) for field in request.required_fields] == [
        ("CommandLine", ("string",)),
        ("Image", ("string",)),
        ("User", ("string",)),
    ]

    payload_text = json.dumps(
        request.to_payload(),
        ensure_ascii=False,
        sort_keys=True,
    )
    # Shape is useful context, but raw fixture values must stay local.
    for private_fixture_value in ("alice", "whoami", "AAAA"):
        assert private_fixture_value not in payload_text


def test_service_rejects_non_surviving_mutant_before_provider_call(
    weak_suite: Path,
) -> None:
    run = run_suite(weak_suite)
    killed = next(item for item in run.mutant_results if item.status == "killed")
    provider = _CapturingProvider(())

    with pytest.raises(Exception, match="surviv"):
        suggest_fixtures(
            weak_suite,
            killed.mutant.id,
            provider,
            candidate_count=1,
        )

    assert provider.requests == []


def test_provider_failure_is_exposed_as_service_error(
    weak_suite: Path,
) -> None:
    target = _target_survivor(weak_suite)

    class FailingProvider:
        name = "failing-provider"
        model = "offline"

        def suggest(self, request) -> ProviderResponse:
            raise RuntimeError("offline provider failed")

    with pytest.raises(Exception, match="offline provider failed"):
        suggest_fixtures(
            weak_suite,
            target.mutant.id,
            FailingProvider(),
            candidate_count=1,
        )


def test_service_requires_exact_requested_candidate_count(
    weak_suite: Path,
) -> None:
    target = _target_survivor(weak_suite)
    provider = _CapturingProvider(
        (
            _candidate(
                "only-one",
                image=r"C:\Program Files\PowerShell\7\pwsh.exe",
                command_line="pwsh.exe -EncodedCommand BBBB",
                user=r"DOMAIN\bob",
            ),
        )
    )

    with pytest.raises(Exception, match="exactly 2"):
        suggest_fixtures(
            weak_suite,
            target.mutant.id,
            provider,
            candidate_count=2,
        )


def test_service_emits_ordered_secret_safe_progress(
    weak_suite: Path,
) -> None:
    target = _target_survivor(weak_suite)
    provider = _CapturingProvider(
        (
            _candidate(
                "verified-pwsh",
                image=r"C:\Program Files\PowerShell\7\pwsh.exe",
                command_line="pwsh.exe -EncodedCommand SECRET-CANDIDATE-VALUE",
                user=r"DOMAIN\SECRET-USER",
            ),
        )
    )
    events: list[SuggestionProgress] = []

    result = suggest_fixtures(
        weak_suite,
        target.mutant.id,
        provider,
        progress=events.append,
    )

    assert result.verified_count == 1
    stages = [event.stage for event in events]
    assert stages[:6] == [
        "suite.loaded",
        "baseline.started",
        "baseline.passed",
        "mutant.selected",
        "prompt.prepared",
        "provider.request.started",
    ]
    assert "provider.response.received" in stages
    assert "candidate.received" in stages
    assert "candidate.parsed" in stages
    assert "candidate.evaluated" in stages
    assert "candidate.minimization.trial" in stages
    assert "candidate.verified" in stages
    assert stages[-1] == "verification.completed"

    rendered = json.dumps(
        [{"stage": event.stage, "details": dict(event.details)} for event in events],
        sort_keys=True,
    )
    assert "SECRET-CANDIDATE-VALUE" not in rendered
    assert "SECRET-USER" not in rendered
    assert "AAAA" not in rendered


def test_service_rejects_provider_request_mutation_without_mutating_suite(
    weak_suite: Path,
) -> None:
    target = _target_survivor(weak_suite)
    loaded = load_suite(weak_suite)
    original_document = copy.deepcopy(loaded.rule_document)

    class MutatingProvider(_CapturingProvider):
        def suggest(self, request) -> ProviderResponse:
            request.detection["condition"] = "selection_main"
            return super().suggest(request)

    provider = MutatingProvider(
        (
            _candidate(
                "mutating-provider",
                image=r"C:\Program Files\PowerShell\7\pwsh.exe",
                command_line="pwsh.exe -EncodedCommand BBBB",
                user=r"DOMAIN\bob",
            ),
        )
    )

    with pytest.raises(Exception, match="mutated the fixture suggestion request"):
        suggest_fixtures(
            loaded,
            target.mutant.id,
            provider,
            candidate_count=1,
        )

    assert loaded.rule_document == original_document


def test_suggestion_artifact_records_events_and_uses_platform_permissions(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    target = _target_survivor(weak_suite)
    candidate = FixtureCandidate(
        candidate_id="proposal-with-noise",
        rationale="The provider explanation applies before local reduction.",
        fields=(
            _field("Image", r"C:\Program Files\PowerShell\7\pwsh.exe"),
            _field("CommandLine", "pwsh.exe -EncodedCommand BBBB"),
            _field("User", r"DOMAIN\bob"),
            _field("Noise", "remove-me"),
        ),
    )
    result = suggest_fixtures(
        weak_suite,
        target.mutant.id,
        _CapturingProvider((candidate,)),
    )
    artifact = tmp_path / "suggestion.json"

    write_suggestion_artifact(result, artifact)

    payload = json.loads(artifact.read_text(encoding="utf-8"))
    suggestion = payload["suggestions"][0]
    assert suggestion["rationale_source"] == "provider"
    assert suggestion["rationale_scope"] == "proposed_event"
    assert suggestion["proposal"]["event"]["Noise"] == "remove-me"
    assert "Noise" not in suggestion["event"]
    assert suggestion["proposal"]["baseline_match"] is True
    assert suggestion["proposal"]["mutant_match"] is False
    assert suggestion["reduction"] == {
        "algorithm": "stable-greedy-field-deletion",
        "minimality": "one-minimal",
        "minimality_scope": "non-required-fields",
        "policy": "preserve-exact-pair-and-fixture-contract",
        "removed_fields": ["Noise"],
        "required_fields": ["CommandLine", "Image", "User"],
        "result": "reduced",
    }
    # POSIX exposes and enforces the requested owner-only mode bits. Windows
    # governs access through inherited ACLs and reports synthetic mode bits, so
    # an exact POSIX-mode assertion is not meaningful on that platform.
    if os.name == "posix":
        assert stat.S_IMODE(artifact.stat().st_mode) == 0o600


def test_suggestion_artifact_rejects_output_symlink(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    target = _target_survivor(weak_suite)
    result = suggest_fixtures(
        weak_suite,
        target.mutant.id,
        _CapturingProvider(
            (
                _candidate(
                    "verified-pwsh",
                    image=r"C:\Program Files\PowerShell\7\pwsh.exe",
                    command_line="pwsh.exe -EncodedCommand BBBB",
                    user=r"DOMAIN\bob",
                ),
            )
        ),
    )
    target_path = tmp_path / "target.json"
    target_path.write_text("do-not-change\n", encoding="utf-8")
    symlink_path = tmp_path / "suggestion.json"
    try:
        symlink_path.symlink_to(target_path)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(Exception, match="symlink"):
        write_suggestion_artifact(result, symlink_path)

    assert target_path.read_text(encoding="utf-8") == "do-not-change\n"


def test_output_preflight_fails_closed_when_parent_probe_is_unwritable(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    loaded = load_suite(weak_suite)
    output_path = tmp_path / "blocked" / "suggestion.json"

    def deny_probe(*args, **kwargs):
        raise PermissionError("permission denied")

    monkeypatch.setattr(service_module.tempfile, "mkstemp", deny_probe)

    with pytest.raises(Exception, match="parent is not writable"):
        preflight_suggestion_output_path(
            output_path,
            (loaded.path, loaded.rule_path, loaded.fixtures_path),
        )

    assert not output_path.exists()
    assert list(output_path.parent.iterdir()) == []

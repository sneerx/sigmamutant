"""Fixture suggestion orchestration; AI proposes and the local engine proves."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from sigmamutant import __version__
from sigmamutant.ai.models import (
    FixtureSuggestionProvider,
    ProviderResponse,
    ProviderUsage,
    SuggestionRunResult,
)
from sigmamutant.ai.progress import ProgressCallback, emit_progress
from sigmamutant.ai.prompt import build_request, prompt_sha256, request_json
from sigmamutant.ai.verifier import verify_candidate
from sigmamutant.errors import FixtureSuggestionError, ProviderError
from sigmamutant.evaluator import SigmaEvaluator
from sigmamutant.models import LoadedSuite, MutantResult
from sigmamutant.reporting._common import (
    preflight_output_file,
    to_primitive,
)
from sigmamutant.runner import run_suite
from sigmamutant.suite import load_suite


def _select_survivor(
    mutant_results: tuple[MutantResult, ...],
    mutant_id: str,
) -> MutantResult:
    survivors = sorted(
        (item for item in mutant_results if item.status == "survived"),
        key=lambda item: item.mutant.id,
    )
    if not survivors:
        raise FixtureSuggestionError(
            "This suite has no surviving mutant that needs a regression fixture."
        )
    if mutant_id == "first":
        return survivors[0]
    for result in mutant_results:
        if result.mutant.id != mutant_id:
            continue
        if result.status != "survived":
            raise FixtureSuggestionError(
                f"Mutant {mutant_id!r} is {result.status}, not survived."
            )
        return result
    sample = ", ".join(item.mutant.id for item in survivors[:5])
    suffix = "" if len(survivors) <= 5 else ", ..."
    raise FixtureSuggestionError(
        f"Unknown mutant {mutant_id!r}. Surviving IDs: {sample}{suffix}"
    )


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _distribution_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _usage_payload(usage: ProviderUsage | None) -> dict[str, int] | None:
    if usage is None:
        return None
    values = {
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "total_tokens": usage.total_tokens,
        "cached_tokens": usage.cached_tokens,
        "cache_write_tokens": usage.cache_write_tokens,
        "reasoning_tokens": usage.reasoning_tokens,
    }
    return {name: value for name, value in values.items() if value is not None}


def _validate_provider_response(
    candidate_count: int,
    response: Any,
) -> None:
    if not isinstance(response, ProviderResponse):
        raise ProviderError("Provider returned an invalid suggestion response")
    batch = getattr(response, "batch", None)
    candidates = getattr(batch, "candidates", None)
    if not isinstance(candidates, (list, tuple)):
        raise ProviderError("Provider returned an invalid suggestion envelope")
    if not candidates:
        raise ProviderError("Provider returned no fixture candidates")
    if len(candidates) != candidate_count:
        raise ProviderError(
            f"Provider returned {len(candidates)} candidates; "
            f"exactly {candidate_count} were requested"
        )
    ids = [candidate.candidate_id for candidate in candidates]
    duplicates = sorted(
        {candidate_id for candidate_id in ids if ids.count(candidate_id) > 1}
    )
    if duplicates:
        raise ProviderError(
            f"Provider repeated candidate id(s): {', '.join(duplicates)}"
        )


def suggest_fixtures(
    suite: str | Path | LoadedSuite,
    mutant_id: str,
    provider: FixtureSuggestionProvider,
    candidate_count: int = 1,
    *,
    evaluator: SigmaEvaluator | None = None,
    progress: ProgressCallback | None = None,
) -> SuggestionRunResult:
    """Ask for candidates and retain only locally proven evidence."""

    if not 1 <= candidate_count <= 3:
        raise FixtureSuggestionError("candidate-count must be between 1 and 3")
    loaded = load_suite(suite) if not isinstance(suite, LoadedSuite) else suite
    emit_progress(
        progress,
        "suite.loaded",
        suite=loaded.path.name,
        fixtures=len(loaded.fixtures),
    )
    engine = evaluator or SigmaEvaluator()
    emit_progress(progress, "baseline.started")
    run_result = run_suite(loaded, evaluator=engine)
    if not run_result.baseline_passed:
        emit_progress(
            progress,
            "baseline.failed",
            errors=len(run_result.errors),
        )
        details = "; ".join(run_result.errors) or "unknown baseline failure"
        raise FixtureSuggestionError(
            f"Baseline must pass before AI assistance: {details}"
        )
    emit_progress(
        progress,
        "baseline.passed",
        fixtures=run_result.fixture_count,
        mutants=run_result.total_scored,
        killed=run_result.killed,
        survived=run_result.survived,
        excluded=run_result.excluded,
        mutation_score=f"{run_result.score:.1%}",
    )
    selected = _select_survivor(run_result.mutant_results, mutant_id)
    emit_progress(
        progress,
        "mutant.selected",
        mutant_id=selected.mutant.id,
        operator=selected.mutant.operator,
        path=selected.mutant.path,
    )
    request = build_request(loaded, selected.mutant, candidate_count)
    provider_input = request_json(request)
    request_hash = prompt_sha256(request)
    emit_progress(
        progress,
        "prompt.prepared",
        bytes=len(provider_input.encode("utf-8")),
        sha256=request_hash,
        fixture_shapes=len(request.fixture_shape),
        required_fields=len(request.required_fields),
        fixture_values_sent=False,
    )
    provider_options: dict[str, Any] = {}
    if provider.name == "openai":
        provider_options = {
            "store": False,
            "reasoning_effort": "low",
            "service_tier": "default",
            "prompt_cache": "disabled",
        }
    emit_progress(
        progress,
        "provider.request.started",
        provider=provider.name,
        model=provider.model,
        candidates=candidate_count,
        boundary="cloud" if provider.name == "openai" else "loopback",
        api_key_logged=False,
        options=provider_options,
    )
    try:
        response = provider.suggest(request)
        try:
            provider_input_after = request_json(request)
        except Exception as exc:
            raise ProviderError(
                "Provider mutated the fixture suggestion request"
            ) from exc
        if provider_input_after != provider_input:
            raise ProviderError("Provider mutated the fixture suggestion request")
    except FixtureSuggestionError:
        emit_progress(progress, "provider.request.failed")
        raise
    except Exception as exc:
        emit_progress(progress, "provider.request.failed")
        raise ProviderError(f"{provider.name} provider failed: {exc}") from exc
    _validate_provider_response(candidate_count, response)
    usage_details = _usage_payload(response.usage)
    emit_progress(
        progress,
        "provider.response.received",
        response_id=response.response_id,
        candidates=len(response.batch.candidates),
        usage=usage_details,
    )
    suggestions_list = []
    for candidate in response.batch.candidates:
        emit_progress(
            progress,
            "candidate.received",
            candidate_id=candidate.candidate_id,
            fields=len(candidate.fields),
        )
        suggestions_list.append(
            verify_candidate(
                candidate,
                loaded.rule_document,
                selected.mutant.document,
                engine,
                required_fields=request.required_fields,
                progress=progress,
            )
        )
    suggestions = tuple(suggestions_list)
    emit_progress(
        progress,
        "verification.completed",
        verified=sum(item.verified for item in suggestions),
        rejected=sum(not item.verified for item in suggestions),
    )
    return SuggestionRunResult(
        suite_name=loaded.path.name,
        rule_title=run_result.rule_title,
        mutant_id=selected.mutant.id,
        operator=selected.mutant.operator,
        path=selected.mutant.path,
        provider=provider.name,
        model=provider.model,
        response_id=response.response_id,
        prompt_sha256=request_hash,
        requested_candidates=candidate_count,
        suggestions=suggestions,
        mutant_description=selected.mutant.description,
        original=selected.mutant.original,
        replacement=selected.mutant.replacement,
        rule_sha256=hashlib.sha256(loaded.rule_bytes).hexdigest(),
        mutant_sha256=_canonical_sha256(selected.mutant.document),
        evaluator="azuma",
        evaluator_version=_distribution_version("azuma"),
        sigmamutant_version=__version__,
        input_paths=(loaded.path, loaded.rule_path, loaded.fixtures_path),
        provider_usage=response.usage,
    )


def suggestion_payload(result: SuggestionRunResult) -> dict[str, Any]:
    suggestions: list[dict[str, Any]] = []
    for item in result.suggestions:
        event_sha256 = _canonical_sha256(item.event)
        proposed_event_sha256 = _canonical_sha256(item.proposed_event)
        fixture = None
        if item.verified:
            fixture = {
                "id": f"ai-{result.mutant_id}-{item.candidate_id}",
                "expected": item.expected,
                "event": item.event,
            }
        suggestions.append(
            {
                "candidate_id": item.candidate_id,
                "rationale": item.rationale,
                "rationale_source": "provider",
                "rationale_scope": "proposed_event",
                "verified": item.verified,
                "rejection_reason": item.rejection_reason,
                "removed_fields": list(item.removed_fields),
                "proposal": {
                    "event": item.proposed_event,
                    "event_sha256": proposed_event_sha256,
                    "baseline_match": item.proposed_baseline_match,
                    "mutant_match": item.proposed_mutant_match,
                },
                "reduction": {
                    "result": "reduced" if item.verified else "not-established",
                    "algorithm": item.reduction_algorithm,
                    "policy": item.reduction_policy,
                    "minimality": item.minimality,
                    "minimality_scope": "non-required-fields",
                    "required_fields": list(item.required_fields),
                    "removed_fields": list(item.removed_fields),
                },
                "proof": {
                    "claim_scope": result.evaluator,
                    "telemetry_realism": "unverified",
                    "rule_sha256": result.rule_sha256,
                    "mutant_sha256": result.mutant_sha256,
                    "event_sha256": event_sha256,
                    "baseline_match": item.baseline_match,
                    "mutant_match": item.mutant_match,
                    "distinguishes": (
                        item.baseline_match is not None
                        and item.mutant_match is not None
                        and item.baseline_match != item.mutant_match
                    ),
                },
                "event": item.event,
                "fixture": fixture,
            }
        )
    return {
        "schema_version": 1,
        "suite": result.suite_name,
        "rule_title": result.rule_title,
        "mutant": {
            "id": result.mutant_id,
            "operator": result.operator,
            "path": result.path,
            "description": result.mutant_description,
            "before": result.original,
            "after": result.replacement,
        },
        "provider": {
            "name": result.provider,
            "model": result.model,
            "response_id": result.response_id,
            "prompt_sha256": result.prompt_sha256,
            "usage": _usage_payload(result.provider_usage),
        },
        "verification": {
            "evaluator": result.evaluator,
            "evaluator_version": result.evaluator_version,
            "sigmamutant_version": result.sigmamutant_version,
            "rule_sha256": result.rule_sha256,
            "mutant_sha256": result.mutant_sha256,
            "telemetry_realism": "unverified",
            "human_review_required": True,
            "input_fixtures_modified": False,
        },
        "summary": {
            "requested": result.requested_candidates,
            "received": len(result.suggestions),
            "verified": result.verified_count,
            "rejected": len(result.suggestions) - result.verified_count,
        },
        "suggestions": suggestions,
    }


def preflight_suggestion_output_path(
    output_path: str | Path,
    input_paths: tuple[Path, ...],
    *,
    probe_writable: bool = True,
) -> Path:
    """Validate an evidence target before any provider can incur work or cost."""

    path = preflight_output_file(
        output_path,
        protected_paths=input_paths,
        error_type=FixtureSuggestionError,
        label="suggestion output path",
    )
    resolved_output = path.resolve()
    if path.exists() and not path.is_file():
        raise FixtureSuggestionError(
            f"Suggestion output must be a regular file path: {resolved_output}"
        )
    if not probe_writable:
        return path

    probe_descriptor = -1
    probe_path: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        preflight_output_file(
            path,
            protected_paths=input_paths,
            error_type=FixtureSuggestionError,
            label="suggestion output path",
        )
        probe_descriptor, probe_name = tempfile.mkstemp(
            prefix=".sigmamutant-output-probe-",
            suffix=".tmp",
            dir=path.parent,
        )
        probe_path = Path(probe_name)
    except OSError as exc:
        raise FixtureSuggestionError(
            f"Suggestion output parent is not writable: {path.parent.resolve()}"
        ) from exc
    finally:
        if probe_descriptor >= 0:
            os.close(probe_descriptor)
        if probe_path is not None:
            try:
                probe_path.unlink()
            except FileNotFoundError:
                pass
    return path


def write_suggestion_artifact(
    result: SuggestionRunResult,
    output_path: str | Path,
) -> Path:
    """Atomically write proof evidence without following an output symlink."""

    path = preflight_suggestion_output_path(
        output_path,
        result.input_paths,
        probe_writable=False,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    preflight_output_file(
        path,
        protected_paths=result.input_paths,
        error_type=FixtureSuggestionError,
        label="suggestion output path",
    )
    content = json.dumps(
        to_primitive(suggestion_payload(result)),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:
            os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(content)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        preflight_suggestion_output_path(
            path,
            result.input_paths,
            probe_writable=False,
        )
        os.replace(temporary_path, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
    return path

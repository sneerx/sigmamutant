"""Review and explicit promotion of verified AI fixture evidence."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from sigmamutant.errors import FixturePromotionError
from sigmamutant.evaluator import SigmaEvaluator
from sigmamutant.models import Fixture, MutantResult, RunResult
from sigmamutant.mutations import generate_mutants
from sigmamutant.reporting._common import (
    paths_refer_to_same_file,
    preflight_output_file,
    reject_protected_path,
    reject_symlink_components,
)
from sigmamutant.runner import run_suite
from sigmamutant.suite import load_suite

_FIXTURE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True, slots=True)
class PromotionPreview:
    """Locally re-proven fixture plus the projected mutation result."""

    fixture: Fixture
    mutant_id: str
    baseline_match: bool
    mutant_match: bool
    before_score: float
    after_score: float
    removed_survivor: bool
    suite_path: Path
    rule_path: Path
    fixture_path: Path
    suite_bytes: bytes = field(repr=False)
    rule_bytes: bytes = field(repr=False)
    fixture_bytes: bytes = field(repr=False)
    suite_sha256: str
    rule_sha256: str
    fixture_sha256: str


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate object key {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard numeric constant {value!r}")


def _canonical_sha256(value: Any) -> str:
    serialized = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _read_evidence(path: str | Path) -> dict[str, Any]:
    evidence_path = Path(path).expanduser().resolve()
    try:
        payload = json.loads(
            evidence_path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except OSError as exc:
        raise FixturePromotionError(
            f"Cannot read fixture evidence {evidence_path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise FixturePromotionError(
            f"Fixture evidence is not valid JSON: {exc.msg}"
        ) from exc
    except ValueError as exc:
        raise FixturePromotionError(
            f"Fixture evidence is not valid JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise FixturePromotionError("Fixture evidence schema_version must be 1")
    return payload


def _select_suggestion(payload: dict[str, Any], candidate_id: str) -> dict[str, Any]:
    suggestions = payload.get("suggestions")
    if not isinstance(suggestions, list):
        raise FixturePromotionError("Fixture evidence has no suggestions array")
    matches = [
        suggestion
        for suggestion in suggestions
        if isinstance(suggestion, dict)
        and suggestion.get("candidate_id") == candidate_id
    ]
    if len(matches) != 1:
        raise FixturePromotionError(
            f"Expected exactly one candidate {candidate_id!r}; found {len(matches)}"
        )
    suggestion = matches[0]
    if suggestion.get("verified") is not True:
        raise FixturePromotionError(
            f"Candidate {candidate_id!r} is not a locally verified witness"
        )
    fixture = suggestion.get("fixture")
    proof = suggestion.get("proof")
    if not isinstance(fixture, dict) or not isinstance(proof, dict):
        raise FixturePromotionError(
            "Verified candidate is missing fixture or proof data"
        )
    if proof.get("distinguishes") is not True:
        raise FixturePromotionError("Candidate proof does not record a distinction")
    return suggestion


def _json_scalar(value: Any) -> bool:
    if isinstance(value, float):
        return math.isfinite(value)
    return value is None or isinstance(value, (str, int, bool))


def _fixture_from_suggestion(
    suggestion: dict[str, Any],
    *,
    fixture_id: str | None = None,
) -> Fixture:
    fixture = suggestion["fixture"]
    raw_id = fixture_id or fixture.get("id")
    expected = fixture.get("expected")
    event = fixture.get("event")
    if not isinstance(raw_id, str) or not _FIXTURE_ID.fullmatch(raw_id):
        raise FixturePromotionError(
            "Fixture id must start with an alphanumeric character and contain "
            "only letters, numbers, dot, underscore, or hyphen (max 128 chars)"
        )
    if not isinstance(expected, bool):
        raise FixturePromotionError("Verified fixture expected value must be boolean")
    if not isinstance(event, dict) or not event:
        raise FixturePromotionError("Verified fixture event must be a non-empty object")
    if any(not isinstance(key, str) or not key for key in event):
        raise FixturePromotionError("Verified fixture contains an invalid event field")
    if any(not _json_scalar(value) for value in event.values()):
        raise FixturePromotionError(
            "Verified fixture contains a non-scalar event value"
        )
    if suggestion.get("event") != event:
        raise FixturePromotionError("Fixture event does not match candidate evidence")
    proof = suggestion["proof"]
    if proof.get("event_sha256") != _canonical_sha256(event):
        raise FixturePromotionError("Fixture event hash does not match the evidence")
    if proof.get("baseline_match") != expected:
        raise FixturePromotionError(
            "Fixture label does not match the recorded baseline"
        )
    if proof.get("baseline_match") == proof.get("mutant_match"):
        raise FixturePromotionError("Recorded proof no longer describes a distinction")
    return Fixture(id=raw_id, expected=expected, event=dict(event))


def _fixture_line(fixture: Fixture) -> str:
    return (
        json.dumps(
            {"id": fixture.id, "expected": fixture.expected, "event": fixture.event},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )


def _assert_expected_content(path: Path, expected_sha256: str) -> None:
    try:
        current = path.read_bytes()
    except OSError as exc:
        raise FixturePromotionError(
            "Fixture corpus changed after preview; re-run the preview"
        ) from exc
    if hashlib.sha256(current).hexdigest() != expected_sha256:
        raise FixturePromotionError(
            "Fixture corpus changed after preview; re-run the preview"
        )


def _assert_snapshot(path: Path, expected: bytes, label: str) -> None:
    reject_symlink_components(
        path,
        error_type=FixturePromotionError,
        label=f"{label} input path",
    )
    try:
        current = path.read_bytes()
    except OSError as exc:
        raise FixturePromotionError(
            f"{label.capitalize()} changed after preview; re-run the preview"
        ) from exc
    if current != expected:
        raise FixturePromotionError(
            f"{label.capitalize()} changed after preview; re-run the preview"
        )


def _assert_promotion_inputs(preview: PromotionPreview) -> None:
    _assert_snapshot(preview.suite_path, preview.suite_bytes, "suite")
    _assert_snapshot(preview.rule_path, preview.rule_bytes, "rule")
    _assert_snapshot(preview.fixture_path, preview.fixture_bytes, "fixture corpus")


def _atomic_write(
    path: Path,
    content: bytes,
    *,
    mode: int,
    expected_sha256: str | None = None,
    protected_paths: tuple[Path, ...] = (),
    before_replace: Callable[[], None] | None = None,
) -> None:
    path = preflight_output_file(
        path,
        protected_paths=protected_paths,
        error_type=FixturePromotionError,
        label="fixture output path",
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    preflight_output_file(
        path,
        protected_paths=protected_paths,
        error_type=FixturePromotionError,
        label="fixture output path",
    )
    if expected_sha256 is not None:
        _assert_expected_content(path, expected_sha256)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        preflight_output_file(
            path,
            protected_paths=protected_paths,
            error_type=FixturePromotionError,
            label="fixture output path",
        )
        if expected_sha256 is not None:
            _assert_expected_content(path, expected_sha256)
        if before_replace is not None:
            before_replace()
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def export_fixture(
    evidence_path: str | Path,
    candidate_id: str,
    output_path: str | Path,
    *,
    fixture_id: str | None = None,
    overwrite: bool = False,
) -> Path:
    """Export one verified candidate as a reviewable one-line JSONL proposal."""

    payload = _read_evidence(evidence_path)
    suggestion = _select_suggestion(payload, candidate_id)
    fixture = _fixture_from_suggestion(suggestion, fixture_id=fixture_id)
    destination = reject_symlink_components(
        Path(os.path.abspath(Path(output_path).expanduser())),
        error_type=FixturePromotionError,
        label="fixture output path",
    )
    evidence = Path(evidence_path).expanduser().resolve()
    reject_protected_path(
        destination,
        (evidence,),
        error_type=FixturePromotionError,
    )
    if destination.exists() and not overwrite:
        raise FixturePromotionError(
            f"Output already exists: {destination}; pass --force to replace it"
        )
    _atomic_write(
        destination,
        _fixture_line(fixture).encode("utf-8"),
        mode=0o600,
        protected_paths=(evidence,),
    )
    return destination


def _required_fixture_contract(fixtures: tuple[Fixture, ...]) -> dict[str, set[type]]:
    required = set(fixtures[0].event)
    for fixture in fixtures[1:]:
        required.intersection_update(fixture.event)
    return {
        field: {type(fixture.event[field]) for fixture in fixtures}
        for field in sorted(required)
    }


def _validate_contract(fixture: Fixture, existing: tuple[Fixture, ...]) -> None:
    contract = _required_fixture_contract(existing)
    missing = sorted(set(contract) - set(fixture.event))
    if missing:
        raise FixturePromotionError(
            "Candidate is missing fixture-schema field(s): " + ", ".join(missing)
        )
    incompatible = sorted(
        field
        for field, types in contract.items()
        if type(fixture.event[field]) not in types
    )
    if incompatible:
        raise FixturePromotionError(
            "Candidate has incompatible type for fixture-schema field(s): "
            + ", ".join(incompatible)
        )


def _find_mutant_result(result: RunResult, mutant_id: str) -> MutantResult:
    matches = [item for item in result.mutant_results if item.mutant.id == mutant_id]
    if len(matches) != 1:
        raise FixturePromotionError(
            f"Current rule produced {len(matches)} mutants with id {mutant_id!r}"
        )
    return matches[0]


def preview_fixture_promotion(
    suite_path: str | Path,
    evidence_path: str | Path,
    candidate_id: str,
    *,
    fixture_id: str | None = None,
) -> PromotionPreview:
    """Re-prove evidence against current inputs without changing fixture bytes."""

    payload = _read_evidence(evidence_path)
    suggestion = _select_suggestion(payload, candidate_id)
    fixture = _fixture_from_suggestion(suggestion, fixture_id=fixture_id)
    loaded = load_suite(suite_path)
    fixture_bytes = loaded.fixtures_bytes
    verification = payload.get("verification")
    mutant_meta = payload.get("mutant")
    if not isinstance(verification, dict) or not isinstance(mutant_meta, dict):
        raise FixturePromotionError(
            "Evidence is missing verification or mutant metadata"
        )
    current_rule_sha = hashlib.sha256(loaded.rule_bytes).hexdigest()
    if verification.get("rule_sha256") != current_rule_sha:
        raise FixturePromotionError(
            "Evidence rule hash does not match the current rule"
        )
    mutant_id = mutant_meta.get("id")
    if not isinstance(mutant_id, str) or not mutant_id:
        raise FixturePromotionError("Evidence has an invalid mutant id")

    mutants = {
        mutant.id: mutant
        for mutant in generate_mutants(loaded.rule_document, loaded.rule_bytes)
    }
    mutant = mutants.get(mutant_id)
    if mutant is None:
        raise FixturePromotionError("Evidence mutant is absent from the current rule")
    if verification.get("mutant_sha256") != _canonical_sha256(mutant.document):
        raise FixturePromotionError(
            "Evidence mutant hash does not match current inputs"
        )

    ids = {item.id for item in loaded.fixtures}
    if fixture.id in ids:
        raise FixturePromotionError(f"Fixture id already exists: {fixture.id}")
    if any(
        item.expected == fixture.expected and item.event == fixture.event
        for item in loaded.fixtures
    ):
        raise FixturePromotionError("An equivalent fixture event already exists")
    _validate_contract(fixture, loaded.fixtures)

    engine = SigmaEvaluator()
    current = run_suite(loaded, evaluator=engine)
    if not current.baseline_passed or current.errors:
        details = "; ".join(current.errors) or "current baseline failed"
        raise FixturePromotionError(
            f"Current suite must be healthy before promotion: {details}"
        )
    current_mutant = _find_mutant_result(current, mutant_id)
    if current_mutant.status != "survived":
        raise FixturePromotionError(
            f"Evidence mutant is already {current_mutant.status} in the current suite"
        )

    baseline_match = engine.matches(loaded.rule_document, fixture.event)
    mutant_match = engine.matches(mutant.document, fixture.event)
    proof = suggestion["proof"]
    if (baseline_match, mutant_match) != (
        proof.get("baseline_match"),
        proof.get("mutant_match"),
    ):
        raise FixturePromotionError(
            "Current evaluator does not reproduce the recorded result pair"
        )
    if baseline_match != fixture.expected or baseline_match == mutant_match:
        raise FixturePromotionError(
            "Candidate does not reproduce a valid fixture proof"
        )

    separator = b"" if not fixture_bytes or fixture_bytes.endswith(b"\n") else b"\n"
    augmented_fixture_bytes = (
        fixture_bytes + separator + _fixture_line(fixture).encode("utf-8")
    )
    augmented = replace(
        loaded,
        fixtures=loaded.fixtures + (fixture,),
        fixtures_bytes=augmented_fixture_bytes,
    )
    projected = run_suite(augmented, evaluator=engine)
    if not projected.baseline_passed or projected.errors:
        details = "; ".join(projected.errors) or "projected baseline failed"
        raise FixturePromotionError(f"Projected suite is invalid: {details}")
    projected_mutant = _find_mutant_result(projected, mutant_id)
    removed_survivor = (
        projected_mutant.status == "killed" and fixture.id in projected_mutant.killed_by
    )
    if not removed_survivor:
        raise FixturePromotionError(
            "Projected suite does not kill the selected mutant with this fixture"
        )
    for path, expected, label in (
        (loaded.path, loaded.suite_bytes, "suite"),
        (loaded.rule_path, loaded.rule_bytes, "rule"),
        (loaded.fixtures_path, fixture_bytes, "fixture corpus"),
    ):
        try:
            current_bytes = path.read_bytes()
        except OSError as exc:
            raise FixturePromotionError(
                f"{label.capitalize()} changed while the promotion preview was running"
            ) from exc
        if current_bytes != expected:
            raise FixturePromotionError(
                f"{label.capitalize()} changed while the promotion preview was running"
            )
    return PromotionPreview(
        fixture=fixture,
        mutant_id=mutant_id,
        baseline_match=baseline_match,
        mutant_match=mutant_match,
        before_score=current.score,
        after_score=projected.score,
        removed_survivor=removed_survivor,
        suite_path=loaded.path,
        rule_path=loaded.rule_path,
        fixture_path=loaded.fixtures_path,
        suite_bytes=loaded.suite_bytes,
        rule_bytes=loaded.rule_bytes,
        fixture_bytes=fixture_bytes,
        suite_sha256=hashlib.sha256(loaded.suite_bytes).hexdigest(),
        rule_sha256=hashlib.sha256(loaded.rule_bytes).hexdigest(),
        fixture_sha256=hashlib.sha256(fixture_bytes).hexdigest(),
    )


def apply_fixture(
    suite_path: str | Path,
    evidence_path: str | Path,
    candidate_id: str,
    *,
    fixture_id: str | None = None,
) -> PromotionPreview:
    """Atomically append one freshly re-proven fixture to the suite JSONL."""

    preview = preview_fixture_promotion(
        suite_path,
        evidence_path,
        candidate_id,
        fixture_id=fixture_id,
    )
    suite = load_suite(suite_path)
    reject_symlink_components(
        suite.path.parent / suite.config.fixtures,
        error_type=FixturePromotionError,
        label="configured fixture corpus",
    )
    if not paths_refer_to_same_file(suite.path, preview.suite_path):
        raise FixturePromotionError(
            "Suite path changed after preview; re-run the preview"
        )
    if not paths_refer_to_same_file(suite.rule_path, preview.rule_path):
        raise FixturePromotionError(
            "Configured rule changed after preview; re-run the preview"
        )
    if not paths_refer_to_same_file(suite.fixtures_path, preview.fixture_path):
        raise FixturePromotionError(
            "Configured fixture corpus changed after preview; re-run the preview"
        )
    if suite.suite_bytes != preview.suite_bytes:
        raise FixturePromotionError("Suite changed after preview; re-run the preview")
    if suite.rule_bytes != preview.rule_bytes:
        raise FixturePromotionError("Rule changed after preview; re-run the preview")
    if suite.fixtures_bytes != preview.fixture_bytes:
        raise FixturePromotionError(
            "Fixture corpus changed after preview; re-run the preview"
        )
    _assert_promotion_inputs(preview)
    existing = suite.fixtures_bytes
    separator = b"" if not existing or existing.endswith(b"\n") else b"\n"
    updated = existing + separator + _fixture_line(preview.fixture).encode("utf-8")
    mode = stat.S_IMODE(preview.fixture_path.stat().st_mode)
    _atomic_write(
        preview.fixture_path,
        updated,
        mode=mode,
        expected_sha256=preview.fixture_sha256,
        protected_paths=(preview.suite_path, preview.rule_path),
        before_replace=lambda: _assert_promotion_inputs(preview),
    )
    return preview

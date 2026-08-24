from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import sigmamutant.fixture_workflow as workflow_module
from sigmamutant.ai.models import (
    FixtureCandidate,
    ProviderResponse,
    SuggestedField,
    SuggestionBatch,
)
from sigmamutant.ai.service import suggest_fixtures, write_suggestion_artifact
from sigmamutant.fixture_workflow import (
    apply_fixture,
    export_fixture,
    preview_fixture_promotion,
)
from sigmamutant.runner import run_suite


class _Provider:
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


def _evidence(weak_suite: Path, tmp_path: Path) -> Path:
    target = next(
        item
        for item in run_suite(weak_suite).mutant_results
        if item.status == "survived"
        and item.mutant.operator == "delete_list_item"
        and item.mutant.original == "\\pwsh.exe"
    )
    result = suggest_fixtures(weak_suite, target.mutant.id, _Provider())
    return write_suggestion_artifact(result, tmp_path / "evidence.json")


def test_preview_reproves_without_writing(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    before = (weak_suite.parent / "fixtures.jsonl").read_bytes()

    preview = preview_fixture_promotion(
        weak_suite,
        evidence,
        "candidate-1",
    )

    assert preview.baseline_match is True
    assert preview.mutant_match is False
    assert preview.removed_survivor is True
    assert preview.after_score > preview.before_score
    assert preview.fixture_sha256 == hashlib.sha256(before).hexdigest()
    assert (weak_suite.parent / "fixtures.jsonl").read_bytes() == before


def test_apply_fixture_atomically_appends_and_kills_target(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)

    preview = apply_fixture(weak_suite, evidence, "candidate-1")

    lines = [
        json.loads(line)
        for line in preview.fixture_path.read_text(encoding="utf-8").splitlines()
    ]
    assert lines[-1]["id"] == preview.fixture.id
    result = run_suite(weak_suite)
    target = next(
        item for item in result.mutant_results if item.mutant.id == preview.mutant_id
    )
    assert target.status == "killed"
    assert preview.fixture.id in target.killed_by


def test_apply_refuses_hardlinked_fixture_corpus(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    fixture_path = weak_suite.parent / "fixtures.jsonl"
    mirror = weak_suite.parent / "fixtures-mirror.jsonl"
    try:
        os.link(fixture_path, mirror)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")
    original = fixture_path.read_bytes()

    with pytest.raises(Exception, match="hardlinked"):
        apply_fixture(weak_suite, evidence, "candidate-1")

    assert fixture_path.read_bytes() == original
    assert mirror.read_bytes() == original


def test_export_fixture_is_review_only_and_refuses_overwrite(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    output = tmp_path / "proposal.jsonl"

    exported = export_fixture(evidence, "candidate-1", output)

    assert exported == output.resolve()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["id"].endswith("candidate-1")
    with pytest.raises(Exception, match="already exists"):
        export_fixture(evidence, "candidate-1", output)


def test_export_fixture_refuses_symlink_output_and_preserves_target(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    target = tmp_path / "existing-proposal.jsonl"
    original = b'{"owner":"external"}\n'
    target.write_bytes(original)
    output = tmp_path / "proposal.jsonl"
    try:
        output.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(Exception, match="symlink"):
        export_fixture(
            evidence,
            "candidate-1",
            output,
            overwrite=True,
        )

    assert output.is_symlink()
    assert target.read_bytes() == original


def test_export_fixture_refuses_symlink_parent_and_preserves_target(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    external = tmp_path / "external"
    external.mkdir()
    sentinel = external / "keep.jsonl"
    sentinel.write_text("keep\n", encoding="utf-8")
    linked_parent = tmp_path / "linked"
    try:
        linked_parent.symlink_to(external, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(Exception, match="symlink component"):
        export_fixture(
            evidence,
            "candidate-1",
            linked_parent / "proposal.jsonl",
        )

    assert sentinel.read_text(encoding="utf-8") == "keep\n"
    assert not (external / "proposal.jsonl").exists()


def test_export_fixture_refuses_case_alias_of_evidence(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    alias = evidence.with_name(evidence.name.upper())
    if not alias.exists() or not os.path.samefile(alias, evidence):
        pytest.skip("test directory is not case-insensitive")
    original = evidence.read_bytes()

    with pytest.raises(Exception, match="input file"):
        export_fixture(
            evidence,
            "candidate-1",
            alias,
            overwrite=True,
        )

    assert evidence.read_bytes() == original


def test_export_fixture_refuses_hardlink_of_evidence(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    output = tmp_path / "proposal.jsonl"
    try:
        os.link(evidence, output)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")
    original = evidence.read_bytes()

    with pytest.raises(Exception, match="input file"):
        export_fixture(
            evidence,
            "candidate-1",
            output,
            overwrite=True,
        )

    assert evidence.read_bytes() == original
    assert output.read_bytes() == original


def test_apply_rejects_fixture_bytes_changed_after_preview(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    fixture_path = weak_suite.parent / "fixtures.jsonl"
    original = fixture_path.read_bytes()
    externally_changed = original + b"\n"
    real_preview = workflow_module.preview_fixture_promotion

    def preview_then_change(*args, **kwargs):
        preview = real_preview(*args, **kwargs)
        fixture_path.write_bytes(externally_changed)
        return preview

    monkeypatch.setattr(
        workflow_module,
        "preview_fixture_promotion",
        preview_then_change,
    )

    with pytest.raises(Exception, match="changed after preview"):
        apply_fixture(weak_suite, evidence, "candidate-1")

    assert fixture_path.read_bytes() == externally_changed
    assert b"candidate-1" not in externally_changed


@pytest.mark.parametrize("input_name", ["suite", "rule"])
def test_apply_rejects_nonfixture_input_changed_after_preview(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
    input_name: str,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    fixture_path = weak_suite.parent / "fixtures.jsonl"
    fixture_before = fixture_path.read_bytes()
    input_path = weak_suite if input_name == "suite" else weak_suite.parent / "rule.yml"
    real_preview = workflow_module.preview_fixture_promotion

    def preview_then_change(*args, **kwargs):
        preview = real_preview(*args, **kwargs)
        input_path.write_bytes(input_path.read_bytes() + b"\n# external change\n")
        return preview

    monkeypatch.setattr(
        workflow_module,
        "preview_fixture_promotion",
        preview_then_change,
    )

    with pytest.raises(Exception, match="changed after preview"):
        apply_fixture(weak_suite, evidence, "candidate-1")

    assert fixture_path.read_bytes() == fixture_before


def test_apply_rechecks_rule_bytes_immediately_before_replace(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    fixture_path = weak_suite.parent / "fixtures.jsonl"
    fixture_before = fixture_path.read_bytes()
    rule_path = weak_suite.parent / "rule.yml"
    real_atomic_write = workflow_module._atomic_write

    def change_then_write(path, content, **kwargs):
        rule_path.write_bytes(rule_path.read_bytes() + b"\n# external change\n")
        return real_atomic_write(path, content, **kwargs)

    monkeypatch.setattr(workflow_module, "_atomic_write", change_then_write)

    with pytest.raises(Exception, match="Rule changed after preview"):
        apply_fixture(weak_suite, evidence, "candidate-1")

    assert fixture_path.read_bytes() == fixture_before


def test_preview_rejects_fixture_change_immediately_after_suite_load(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    fixture_path = weak_suite.parent / "fixtures.jsonl"
    original = fixture_path.read_bytes()
    externally_changed = original + b"\n"
    real_load_suite = workflow_module.load_suite

    def load_then_change(path):
        loaded = real_load_suite(path)
        fixture_path.write_bytes(externally_changed)
        return loaded

    monkeypatch.setattr(workflow_module, "load_suite", load_then_change)

    with pytest.raises(Exception, match="changed while"):
        preview_fixture_promotion(weak_suite, evidence, "candidate-1")

    assert fixture_path.read_bytes() == externally_changed


def test_apply_rechecks_fixture_bytes_inside_atomic_write(
    weak_suite: Path,
    tmp_path: Path,
    monkeypatch,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    fixture_path = weak_suite.parent / "fixtures.jsonl"
    original = fixture_path.read_bytes()
    externally_changed = original + b"\n"
    real_atomic_write = workflow_module._atomic_write

    def change_then_write(
        path,
        content,
        *,
        mode,
        expected_sha256=None,
        protected_paths=(),
        before_replace=None,
    ):
        fixture_path.write_bytes(externally_changed)
        return real_atomic_write(
            path,
            content,
            mode=mode,
            expected_sha256=expected_sha256,
            protected_paths=protected_paths,
            before_replace=before_replace,
        )

    monkeypatch.setattr(workflow_module, "_atomic_write", change_then_write)

    with pytest.raises(Exception, match="changed after preview"):
        apply_fixture(weak_suite, evidence, "candidate-1")

    assert fixture_path.read_bytes() == externally_changed
    assert b"candidate-1" not in externally_changed


def test_promotion_rejects_tampered_event(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    payload["suggestions"][0]["fixture"]["event"]["Image"] = "tampered.exe"
    evidence.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(Exception, match="does not match|hash"):
        preview_fixture_promotion(weak_suite, evidence, "candidate-1")


def test_promotion_rejects_ambiguous_duplicate_evidence_keys(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    content = evidence.read_text(encoding="utf-8")
    evidence.write_text(
        content.replace(
            '"schema_version": 1,',
            '"schema_version": 1,\n  "schema_version": 1,',
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(Exception, match="duplicate object key"):
        preview_fixture_promotion(weak_suite, evidence, "candidate-1")


def test_promotion_rejects_duplicate_fixture(
    weak_suite: Path,
    tmp_path: Path,
) -> None:
    evidence = _evidence(weak_suite, tmp_path)
    apply_fixture(weak_suite, evidence, "candidate-1")

    with pytest.raises(Exception, match="already exists|equivalent"):
        preview_fixture_promotion(weak_suite, evidence, "candidate-1")

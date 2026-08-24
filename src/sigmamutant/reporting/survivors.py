from __future__ import annotations

from pathlib import Path
from typing import Any

from ._common import (
    bytes_from_candidate,
    ensure_output_dir,
    get_field,
    is_status,
    mutant_document,
    mutant_identity,
    mutated_rule_bytes,
    portable_namespace_key,
    preflight_managed_paths,
    preflight_output_file,
    provided_diff,
    safe_stem,
    suite_input_paths,
    unified_diff,
    write_text,
    yaml_text,
)


def _unique_stem(base: str, used: set[str]) -> str:
    key = portable_namespace_key(base)
    if key not in used:
        used.add(key)
        return base

    suffix = 2
    while portable_namespace_key(f"{base}-{suffix}") in used:
        suffix += 1
    suffix_text = f"-{suffix}"
    unique = f"{base[: 120 - len(suffix_text)]}{suffix_text}"
    used.add(portable_namespace_key(unique))
    return unique


def preflight_survivor_output(
    suite: Any,
    output_dir: str | Path,
) -> tuple[Path, tuple[Path, ...]]:
    """Validate the complete managed survivor namespace before any report write."""

    protected_paths = suite_input_paths(suite)
    output = preflight_managed_paths(
        output_dir,
        subdirectories=("survivors",),
        protected_paths=protected_paths,
    )
    survivors_dir = output / "survivors"
    if not survivors_dir.is_dir():
        return output, ()
    stale_paths = tuple(
        sorted(
            {
                stale_path
                for pattern in ("*.yml", "*.diff")
                for stale_path in survivors_dir.glob(pattern)
            },
            key=lambda path: portable_namespace_key(path.name),
        )
    )
    for stale_path in stale_paths:
        preflight_output_file(
            stale_path,
            protected_paths=protected_paths,
            label="managed survivor artifact",
        )
    return output, stale_paths


def _survivor_yaml(mutant: Any) -> tuple[str, bytes | None]:
    rendered = mutated_rule_bytes(mutant)
    if rendered is not None:
        text = rendered.decode("utf-8", errors="replace")
        return text + ("" if text.endswith("\n") else "\n"), rendered

    document = mutant_document(mutant)
    if document is not None:
        text = yaml_text(document)
        return text + ("" if text.endswith("\n") else "\n"), text.encode("utf-8")

    # A descriptor remains useful when a mutation engine does not retain the
    # materialized rule. JSON emitted by yaml_text is valid YAML as a fallback.
    text = yaml_text({"mutant": mutant})
    return text + ("" if text.endswith("\n") else "\n"), None


def write_survivors(
    result: Any,
    suite: Any,
    output_dir: str | Path,
) -> tuple[Path, ...]:
    """Write materialized surviving rules and unified diffs when available."""

    protected_paths = suite_input_paths(suite)
    output, stale_paths = preflight_survivor_output(suite, output_dir)
    output = ensure_output_dir(output)
    survivors_dir = ensure_output_dir(output / "survivors")
    # This directory is a tool-managed artifact namespace. Remove only the two
    # file types SigmaMutant itself owns so reruns cannot retain stale evidence.
    for stale_path in stale_paths:
        preflight_output_file(
            stale_path,
            protected_paths=protected_paths,
            label="managed survivor artifact",
        )
        if stale_path.is_file():
            stale_path.unlink()

    mutant_results = get_field(result, "mutant_results", ()) or ()
    survivors = [
        mutant_result
        for mutant_result in mutant_results
        if is_status(get_field(mutant_result, "status"), "survived")
    ]
    survivors.sort(
        key=lambda mutant_result: mutant_identity(
            get_field(mutant_result, "mutant"),
            0,
        )
    )
    if not survivors:
        return ()

    original = bytes_from_candidate(get_field(suite, "rule_bytes"))
    rule_path = get_field(suite, "rule_path")
    original_name = Path(rule_path).name if rule_path else "rule.yml"

    written: list[Path] = []
    used_stems: set[str] = set()

    for index, mutant_result in enumerate(survivors, start=1):
        mutant = get_field(mutant_result, "mutant")
        identity = mutant_identity(mutant, index)
        stem = _unique_stem(safe_stem(identity, f"mutant-{index:04d}"), used_stems)
        yaml_path = survivors_dir / f"{stem}.yml"

        has_rendered_rule = mutated_rule_bytes(mutant) is not None
        yaml_content, mutated = _survivor_yaml(mutant)
        write_text(yaml_path, yaml_content, protected_paths=protected_paths)
        written.append(yaml_path)

        diff = provided_diff(mutant)
        if diff is None and original is not None and mutated is not None:
            diff_original = original
            if not has_rendered_rule:
                original_document = get_field(suite, "rule_doc")
                if original_document is not None:
                    diff_original = yaml_text(original_document).encode("utf-8")
            diff = unified_diff(
                diff_original,
                mutated,
                original_name=original_name,
                mutated_name=yaml_path.name,
            )

        if diff:
            diff_path = survivors_dir / f"{stem}.diff"
            write_text(diff_path, diff, protected_paths=protected_paths)
            written.append(diff_path)

    return tuple(written)

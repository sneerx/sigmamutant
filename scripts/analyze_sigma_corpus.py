#!/usr/bin/env python3
"""Measure SigmaMutant's rule-level applicability over an external corpus.

This is deliberately not a detection-accuracy benchmark. It parses each Sigma
rule, applies the documented fail-closed subset checks, validates the rule with
the configured pySigma/Azuma stack, and counts the first-order mutants that can
be generated. Event fixtures are not fabricated for third-party rules.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from sigmamutant import __version__
from sigmamutant.errors import RuleError
from sigmamutant.evaluator import SigmaEvaluator, validate_supported_rule
from sigmamutant.mutations import OPERATORS, generate_mutants
from sigmamutant.yamlio import load_single_yaml

DEFAULT_SCOPES = ("rules", "rules-emerging-threats", "rules-threat-hunting")


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Measure supported-rule and mutation-operator applicability over an "
            "external Sigma corpus."
        )
    )
    parser.add_argument("root", type=Path, help="root of the external rule corpus")
    parser.add_argument(
        "--scope",
        action="append",
        dest="scopes",
        help=(
            "relative directory to scan; repeat for multiple trees "
            f"(default: {', '.join(DEFAULT_SCOPES)})"
        ),
    )
    parser.add_argument("--source-name", required=True)
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="compare the fresh canonical result with --out instead of replacing it",
    )
    return parser.parse_args()


def _dependency_versions() -> dict[str, str]:
    versions = {"sigmamutant": __version__}
    for distribution in ("azuma", "pysigma", "ruamel.yaml"):
        versions[distribution] = importlib.metadata.version(distribution)
    return dict(sorted(versions.items()))


def _safe_scope(root: Path, raw_scope: str) -> Path:
    scope = Path(raw_scope)
    if scope.is_absolute() or ".." in scope.parts:
        raise ValueError(f"scope must be a relative child path: {raw_scope}")
    resolved = (root / scope).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"scope escapes the corpus root: {raw_scope}") from exc
    if not resolved.is_dir() or resolved.is_symlink():
        raise ValueError(f"scope is not a regular directory: {raw_scope}")
    return resolved


def _rule_files(root: Path, scopes: list[str]) -> list[Path]:
    files: set[Path] = set()
    for raw_scope in scopes:
        scope = _safe_scope(root, raw_scope)
        for suffix in ("*.yml", "*.yaml"):
            files.update(
                item
                for item in scope.rglob(suffix)
                if item.is_file() and not item.is_symlink()
            )
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def _subset_reason(message: str) -> str:
    patterns = (
        (r"correlation rules", "correlation_rule"),
        (r"non-empty title", "missing_or_invalid_title"),
        (r"logsource mapping", "missing_or_invalid_logsource"),
        (r"detection mapping", "missing_or_invalid_detection"),
        (r"detection\.condition", "missing_or_invalid_condition"),
        (r"at least one detection selector", "missing_selector"),
        (r"keyword-only selector", "keyword_only_selector"),
        (r"must be a non-empty field mapping", "unsupported_selector_shape"),
        (r"contains an invalid field", "invalid_field"),
        (r"uses unsupported modifier", "unsupported_modifier"),
        (r"uses unknown modifier", "unknown_modifier"),
        (r"mutually exclusive string modifiers", "conflicting_string_modifiers"),
        (r"nested field mapping", "nested_field_mapping"),
        (r"cannot be empty", "empty_value_list"),
        (r"list-of-maps/nested lists", "nested_value_list"),
        (r"unsupported value", "unsupported_value"),
        (r"non-finite value", "non_finite_value"),
        (r"value placeholders", "value_placeholder"),
    )
    lowered = message.lower()
    for pattern, reason in patterns:
        if re.search(pattern, lowered):
            return reason
    return "other_subset_rejection"


def _evaluator_reason(message: str) -> str:
    lowered = message.lower()
    if "pysigma rejected" in lowered:
        return "pysigma_rejected"
    if "azuma rejected" in lowered:
        return "azuma_rejected"
    return "other_evaluator_rejection"


def _logsource_key(document: dict[str, Any]) -> str:
    logsource = document.get("logsource")
    if not isinstance(logsource, dict):
        return "unknown"
    product = logsource.get("product")
    category = logsource.get("category")
    service = logsource.get("service")
    pieces = [
        item.strip().lower()
        for item in (product, category, service)
        if isinstance(item, str) and item.strip()
    ]
    return "/".join(pieces) if pieces else "generic"


def analyze(
    root: Path,
    *,
    scopes: list[str],
    source_name: str,
    source_url: str,
    source_revision: str,
) -> dict[str, Any]:
    root = root.expanduser().resolve()
    if not root.is_dir() or root.is_symlink():
        raise ValueError("corpus root must be a regular directory")
    files = _rule_files(root, scopes)
    if not files:
        raise ValueError("no YAML rule files found in the selected scopes")

    tree_hash = hashlib.sha256()
    status_counts: Counter[str] = Counter()
    rejection_reasons: Counter[str] = Counter()
    operator_counts: Counter[str] = Counter()
    logsources: dict[str, Counter[str]] = defaultdict(Counter)
    evaluator = SigmaEvaluator()

    for path in files:
        relative = path.relative_to(root).as_posix()
        try:
            content = path.read_bytes()
        except OSError:
            status_counts["read_error"] += 1
            rejection_reasons["read_error"] += 1
            continue
        tree_hash.update(relative.encode("utf-8"))
        tree_hash.update(b"\0")
        tree_hash.update(hashlib.sha256(content).digest())
        tree_hash.update(b"\0")
        try:
            text = content.decode("utf-8")
            document = load_single_yaml(text, source=relative)
        except (UnicodeDecodeError, RuleError):
            status_counts["yaml_rejected"] += 1
            rejection_reasons["yaml_or_document_shape"] += 1
            continue

        status_counts["parsed"] += 1
        logsource = _logsource_key(document)
        logsources[logsource]["parsed"] += 1
        try:
            validate_supported_rule(document)
        except RuleError as exc:
            status_counts["subset_rejected"] += 1
            rejection_reasons[_subset_reason(str(exc))] += 1
            logsources[logsource]["subset_rejected"] += 1
            continue

        status_counts["subset_supported"] += 1
        logsources[logsource]["subset_supported"] += 1
        try:
            evaluator.validate_rule(document)
        except RuleError as exc:
            status_counts["evaluator_rejected"] += 1
            rejection_reasons[_evaluator_reason(str(exc))] += 1
            logsources[logsource]["evaluator_rejected"] += 1
            continue

        status_counts["evaluator_supported"] += 1
        logsources[logsource]["evaluator_supported"] += 1
        mutants = generate_mutants(document, content)
        if mutants:
            status_counts["mutation_applicable"] += 1
            logsources[logsource]["mutation_applicable"] += 1
        else:
            status_counts["supported_no_mutants"] += 1
            logsources[logsource]["supported_no_mutants"] += 1
        operator_counts.update(mutant.operator for mutant in mutants)

    rule_files = len(files)
    evaluator_supported = status_counts["evaluator_supported"]
    mutation_applicable = status_counts["mutation_applicable"]
    return {
        "schema_version": 1,
        "source": {
            "name": source_name,
            "url": source_url,
            "revision": source_revision,
            "scopes": scopes,
            "tree_sha256": tree_hash.hexdigest(),
        },
        "engine": {
            "dependencies": _dependency_versions(),
            "operators": [operator.name for operator in OPERATORS],
        },
        "summary": {
            "rule_files": rule_files,
            "parsed": status_counts["parsed"],
            "subset_supported": status_counts["subset_supported"],
            "evaluator_supported": evaluator_supported,
            "mutation_applicable": mutation_applicable,
            "supported_no_mutants": status_counts["supported_no_mutants"],
            "mutants_generated": sum(operator_counts.values()),
            "evaluator_support_rate": evaluator_supported / rule_files,
            "mutation_applicability_rate": mutation_applicable / rule_files,
        },
        "status_counts": dict(sorted(status_counts.items())),
        "rejection_reasons": dict(sorted(rejection_reasons.items())),
        "mutants_by_operator": dict(sorted(operator_counts.items())),
        "logsources": {
            key: dict(sorted(counts.items()))
            for key, counts in sorted(logsources.items())
        },
        "interpretation": {
            "measures": (
                "rule parsing, declared-subset acceptance, evaluator validation, "
                "and mutation-operator applicability"
            ),
            "does_not_measure": (
                "detection accuracy, telemetry realism, backend equivalence, "
                "fixture quality, or mutation score"
            ),
        },
    }


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    args = _arguments()
    scopes = args.scopes or list(DEFAULT_SCOPES)
    try:
        payload = analyze(
            args.root,
            scopes=scopes,
            source_name=args.source_name,
            source_url=args.source_url,
            source_revision=args.source_revision,
        )
    except (OSError, ValueError, importlib.metadata.PackageNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rendered = _canonical(payload)
    if args.verify:
        if not args.out.is_file():
            print(
                f"error: expected evidence does not exist: {args.out}", file=sys.stderr
            )
            return 2
        if args.out.read_text(encoding="utf-8") != rendered:
            print("external corpus evidence differs from the checked-in result")
            return 1
        print(
            "external corpus evidence verified: "
            f"{payload['summary']['rule_files']} rules, "
            f"{payload['summary']['mutation_applicable']} mutable"
        )
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(rendered, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

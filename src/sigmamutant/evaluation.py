"""Reproducible evaluation over paired weak/strong fixture suites.

This module powers the repository's public benchmark.  It intentionally keeps
elapsed time and host details out of the canonical payload so two runs over the
same inputs and dependency versions can be compared byte-for-byte.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from sigmamutant.errors import SigmaMutantError
from sigmamutant.models import RunResult
from sigmamutant.runner import run_suite


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SigmaMutantError(f"{label} must be a JSON object")
    return value


def _require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SigmaMutantError(f"{label} must be a non-empty string")
    return value.strip()


def _resolve_suite(manifest_path: Path, raw_path: Any, label: str) -> Path:
    relative = Path(_require_text(raw_path, label))
    if relative.is_absolute():
        raise SigmaMutantError(f"{label} must be relative to the manifest")
    candidate = manifest_path.parent / relative
    resolved = candidate.resolve()
    corpus_root = manifest_path.parent.resolve()
    try:
        resolved.relative_to(corpus_root)
    except ValueError as exc:
        raise SigmaMutantError(f"{label} escapes the evaluation directory") from exc
    relative_candidate = candidate.relative_to(manifest_path.parent)
    components = [
        manifest_path.parent / Path(*relative_candidate.parts[:index])
        for index in range(1, len(relative_candidate.parts) + 1)
    ]
    if (
        not resolved.is_file()
        or candidate.is_symlink()
        or any(component.is_symlink() for component in components)
    ):
        raise SigmaMutantError(f"{label} does not name a regular suite file")
    return resolved


def _run_payload(result: RunResult) -> dict[str, Any]:
    operators: dict[str, dict[str, int]] = {}
    for item in result.mutant_results:
        bucket = operators.setdefault(
            item.mutant.operator,
            {"generated": 0, "killed": 0, "survived": 0, "excluded": 0},
        )
        bucket["generated"] += 1
        bucket[item.status] += 1
    return {
        "fixtures": result.fixture_count,
        "baseline_passed": result.baseline_passed,
        "score": result.score,
        "scoreable": result.total_scored,
        "killed": result.killed,
        "survived": result.survived,
        "excluded": result.excluded,
        "operators": dict(sorted(operators.items())),
        "input_hashes": {
            "suite_sha256": result.metadata["suite_sha256"],
            "rule_sha256": result.metadata["rule_sha256"],
            "fixtures_sha256": result.metadata["fixtures_sha256"],
        },
    }


def _merge_operator_totals(
    destination: dict[str, dict[str, int]],
    source: dict[str, dict[str, int]],
) -> None:
    for operator, counts in source.items():
        bucket = destination.setdefault(
            operator,
            {"generated": 0, "killed": 0, "survived": 0, "excluded": 0},
        )
        for name, count in counts.items():
            bucket[name] += count


def _phase_summary(runs: list[dict[str, Any]]) -> dict[str, Any]:
    killed = sum(run["killed"] for run in runs)
    survived = sum(run["survived"] for run in runs)
    scoreable = killed + survived
    operators: dict[str, dict[str, int]] = {}
    for run in runs:
        _merge_operator_totals(operators, run["operators"])
    return {
        "suites": len(runs),
        "fixtures": sum(run["fixtures"] for run in runs),
        "scoreable": scoreable,
        "killed": killed,
        "survived": survived,
        "excluded": sum(run["excluded"] for run in runs),
        "weighted_score": killed / scoreable if scoreable else 0.0,
        "operators": dict(sorted(operators.items())),
    }


def evaluate_corpus(manifest: str | Path) -> dict[str, Any]:
    """Run every declared weak/strong pair and return canonical evidence."""

    manifest_candidate = Path(manifest).expanduser()
    if not manifest_candidate.is_file() or manifest_candidate.is_symlink():
        raise SigmaMutantError("Evaluation manifest must be a regular JSON file")
    manifest_path = manifest_candidate.resolve()
    manifest_bytes = manifest_path.read_bytes()
    try:
        raw_manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SigmaMutantError(f"Invalid evaluation manifest: {exc}") from exc
    document = _require_mapping(raw_manifest, "evaluation manifest")
    if document.get("schema_version") != 1:
        raise SigmaMutantError("evaluation manifest schema_version must be 1")
    corpus_name = _require_text(document.get("name"), "evaluation manifest name")
    data_classification = _require_text(
        document.get("data_classification"),
        "evaluation manifest data_classification",
    )
    cases = document.get("cases")
    if not isinstance(cases, list) or not cases:
        raise SigmaMutantError("evaluation manifest cases must be a non-empty list")

    seen_ids: set[str] = set()
    prepared_cases: list[tuple[str, str, str, Path, Path]] = []
    for index, raw_case in enumerate(cases):
        case = _require_mapping(raw_case, f"cases[{index}]")
        case_id = _require_text(case.get("id"), f"cases[{index}].id")
        if case_id in seen_ids:
            raise SigmaMutantError(f"Duplicate evaluation case id: {case_id}")
        seen_ids.add(case_id)
        domain = _require_text(case.get("domain"), f"cases[{index}].domain")
        purpose = _require_text(case.get("purpose"), f"cases[{index}].purpose")
        weak_path = _resolve_suite(
            manifest_path,
            case.get("weak_suite"),
            f"cases[{index}].weak_suite",
        )
        strong_path = _resolve_suite(
            manifest_path,
            case.get("strong_suite"),
            f"cases[{index}].strong_suite",
        )
        prepared_cases.append((case_id, domain, purpose, weak_path, strong_path))

    case_payloads: list[dict[str, Any]] = []
    weak_runs: list[dict[str, Any]] = []
    strong_runs: list[dict[str, Any]] = []
    dependencies: dict[str, str] | None = None

    for case_id, domain, purpose, weak_path, strong_path in prepared_cases:
        weak_result = run_suite(weak_path)
        strong_result = run_suite(strong_path)
        for phase, result in (("weak", weak_result), ("strong", strong_result)):
            if not result.baseline_passed or result.errors:
                details = "; ".join(result.errors) or "baseline did not pass"
                raise SigmaMutantError(
                    f"Evaluation case {case_id!r} {phase} suite failed: {details}"
                )
        if weak_result.metadata["rule_sha256"] != strong_result.metadata["rule_sha256"]:
            raise SigmaMutantError(
                f"Evaluation case {case_id!r} does not use the same rule in both suites"
            )
        if strong_result.score < weak_result.score:
            raise SigmaMutantError(
                f"Evaluation case {case_id!r} strong score regressed below weak score"
            )
        current_dependencies = dict(weak_result.metadata["dependencies"])
        if current_dependencies != dict(strong_result.metadata["dependencies"]):
            raise SigmaMutantError(
                f"Evaluation case {case_id!r} dependency metadata differs by phase"
            )
        if dependencies is None:
            dependencies = current_dependencies
        elif dependencies != current_dependencies:
            raise SigmaMutantError("Dependency metadata changed during evaluation")

        weak_payload = _run_payload(weak_result)
        strong_payload = _run_payload(strong_result)
        weak_runs.append(weak_payload)
        strong_runs.append(strong_payload)
        case_payloads.append(
            {
                "id": case_id,
                "domain": domain,
                "purpose": purpose,
                "rule_title": weak_result.rule_title,
                "weak": weak_payload,
                "strong": strong_payload,
                "score_delta": strong_result.score - weak_result.score,
            }
        )

    improved = sum(case["score_delta"] > 0 for case in case_payloads)
    perfect = sum(case["strong"]["score"] == 1.0 for case in case_payloads)
    return {
        "schema_version": 1,
        "corpus": {
            "name": corpus_name,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "data_classification": data_classification,
            "cases": len(case_payloads),
            "domains": sorted({case["domain"] for case in case_payloads}),
        },
        "dependencies": dict(sorted((dependencies or {}).items())),
        "summary": {
            "baselines_passed": len(case_payloads) * 2,
            "paired_rules_unchanged": len(case_payloads),
            "pairs_improved": improved,
            "strong_suites_at_100_percent": perfect,
            "weak": _phase_summary(weak_runs),
            "strong": _phase_summary(strong_runs),
        },
        "cases": case_payloads,
    }


def render_evaluation_markdown(payload: dict[str, Any]) -> str:
    """Render the canonical payload as a reviewer-readable evaluation note."""

    corpus = payload["corpus"]
    summary = payload["summary"]
    weak = summary["weak"]
    strong = summary["strong"]
    lines = [
        "# Reproducible evaluation",
        "",
        "This document is generated from `benchmarks/manifest.json` by "
        "`python scripts/evaluate_corpus.py --verify`. It reports measurements "
        "produced by the deterministic SigmaMutant engine; no AI provider is used.",
        "",
        "## Scope",
        "",
        f"The corpus contains **{corpus['cases']} paired rules** across "
        f"**{len(corpus['domains'])} log domains**. Every event and rule is synthetic "
        "and inert. The corpus is a deterministic operator/fixture-quality "
        "evaluation, not a claim about production detection rates.",
        "",
        f"Data classification: `{corpus['data_classification']}`.",
        "",
        "## Aggregate result",
        "",
        "| Metric | Weak fixtures | Strong fixtures |",
        "| --- | ---: | ---: |",
        f"| Suites | {weak['suites']} | {strong['suites']} |",
        f"| Fixtures | {weak['fixtures']} | {strong['fixtures']} |",
        f"| Scoreable mutants | {weak['scoreable']} | {strong['scoreable']} |",
        f"| Killed | {weak['killed']} | {strong['killed']} |",
        f"| Survived | {weak['survived']} | {strong['survived']} |",
        f"| Excluded | {weak['excluded']} | {strong['excluded']} |",
        f"| Weighted mutation score | {weak['weighted_score']:.1%} | "
        f"{strong['weighted_score']:.1%} |",
        "",
        f"All **{summary['baselines_passed']}** suite baselines passed. "
        f"The rule bytes remained identical in all "
        f"**{summary['paired_rules_unchanged']}** pairs; only fixtures changed. "
        f"**{summary['pairs_improved']}** pairs improved, "
        f"and **{summary['strong_suites_at_100_percent']}** strong suites reached 100%.",
        "",
        "## Per-case result",
        "",
        "| Case | Domain | Weak | Strong | Delta | Weak/strong fixtures |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for case in payload["cases"]:
        lines.append(
            f"| `{case['id']}` | {case['domain']} | {case['weak']['score']:.1%} | "
            f"{case['strong']['score']:.1%} | {case['score_delta']:+.1%} | "
            f"{case['weak']['fixtures']}/{case['strong']['fixtures']} |"
        )
    lines.extend(
        [
            "",
            "## Operator result",
            "",
            "| Operator | Weak killed/generated | Strong killed/generated |",
            "| --- | ---: | ---: |",
        ]
    )
    all_operators = sorted(set(weak["operators"]) | set(strong["operators"]))
    for operator in all_operators:
        weak_op = weak["operators"].get(operator, {"killed": 0, "generated": 0})
        strong_op = strong["operators"].get(operator, {"killed": 0, "generated": 0})
        lines.append(
            f"| `{operator}` | {weak_op['killed']}/{weak_op['generated']} | "
            f"{strong_op['killed']}/{strong_op['generated']} |"
        )
    lines.extend(
        [
            "",
            "## Reproduce and verify",
            "",
            "```bash",
            'python -m pip install -c constraints-demo.txt -e ".[dev]"',
            "python scripts/evaluate_corpus.py --verify",
            "```",
            "",
            "The command re-runs every pair and compares the complete canonical "
            "payload with `benchmarks/results.json`. Input SHA-256 values, dependency "
            "versions, per-operator counts, and per-case results are included in that "
            "machine-readable evidence. Timing is deliberately excluded because it is "
            "host-dependent. The release constraint set pins the direct dependencies "
            "used by the checked-in evidence and CI verification.",
            "",
            "To regenerate the checked-in evidence after an intentional corpus or "
            "engine change:",
            "",
            "```bash",
            "python scripts/evaluate_corpus.py --update",
            "```",
            "",
            "Review the JSON and Markdown diff before committing it.",
            "",
            "## Interpretation and limits",
            "",
            "The paired design holds each Sigma rule constant and varies only the "
            "labelled fixture set. The score delta therefore demonstrates whether "
            "boundary-focused fixtures expose the injected defect models better than "
            "a minimal baseline-only suite.",
            "",
            "It does **not** measure false-positive rate, false-negative rate, SIEM "
            "backend equivalence, telemetry quality, or coverage of the entire Sigma "
            "specification. Because the corpus is project-authored and synthetic, an "
            "independently curated public-rule mutation-score study with labelled "
            "fixtures remains future work. The separate pinned SigmaHQ applicability "
            "study measures rule and operator reach without fabricating fixtures.",
            "",
        ]
    )
    return "\n".join(lines)

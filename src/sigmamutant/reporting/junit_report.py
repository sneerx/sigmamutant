from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from ._common import ensure_output_dir, result_payload, suite_input_paths, write_text


def _details(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def _add_text_element(
    parent: ElementTree.Element,
    tag: str,
    text: str,
    **attributes: str,
) -> ElementTree.Element:
    element = ElementTree.SubElement(parent, tag, attributes)
    element.text = text
    return element


def render_junit(result: Any, suite: Any) -> str:
    payload = result_payload(result, suite)
    mutant_results = payload["mutant_results"]
    run_errors = payload.get("errors") or []

    tests = 1 + len(mutant_results) + (1 if run_errors else 0)
    failures = 0
    errors = 0
    skipped = 0

    root = ElementTree.Element(
        "testsuite",
        {
            "name": f"sigmamutant:{payload['rule_title'] or 'untitled'}",
            "tests": str(tests),
            "failures": "0",
            "errors": "0",
            "skipped": "0",
            "time": "0",
        },
    )

    properties = ElementTree.SubElement(root, "properties")
    for name, value in (
        ("baseline_passed", payload["baseline_passed"]),
        ("score", payload["score"]),
        ("threshold", payload["threshold"]),
        ("passed", payload["passed"]),
        ("fixture_count", payload["fixture_count"]),
    ):
        ElementTree.SubElement(
            properties,
            "property",
            {
                "name": name,
                "value": str(value).lower() if isinstance(value, bool) else str(value),
            },
        )

    gate = ElementTree.SubElement(
        root,
        "testcase",
        {"classname": "sigmamutant.run", "name": "mutation-score-gate", "time": "0"},
    )
    if not payload["passed"]:
        failures += 1
        message = (
            f"mutation run failed: score={payload['score']}, "
            f"threshold={payload['threshold']}, "
            f"baseline_passed={payload['baseline_passed']}"
        )
        _add_text_element(
            gate, "failure", message, message=message, type="MutationScoreFailure"
        )

    for mutant in mutant_results:
        status = str(mutant["status"])
        testcase = ElementTree.SubElement(
            root,
            "testcase",
            {
                "classname": f"sigmamutant.{mutant['operator'] or 'mutation'}",
                "name": str(mutant["id"]),
                "time": "0",
            },
        )
        detail = {
            "status": status,
            "description": mutant.get("description", ""),
            "reason": mutant.get("reason"),
            "killed_by": mutant.get("killed_by") or [],
            "observations": mutant.get("observations") or [],
        }
        if status in {"excluded", "skipped"}:
            skipped += 1
            _add_text_element(
                testcase,
                "skipped",
                _details(detail),
                message=f"mutant {status}",
            )
        elif status in {"error", "invalid"}:
            errors += 1
            _add_text_element(
                testcase,
                "error",
                _details(detail),
                message=f"mutant {status}",
                type="MutantExecutionError",
            )
        else:
            _add_text_element(testcase, "system-out", _details(detail))

    if run_errors:
        errors += 1
        testcase = ElementTree.SubElement(
            root,
            "testcase",
            {"classname": "sigmamutant.run", "name": "run-errors", "time": "0"},
        )
        _add_text_element(
            testcase,
            "error",
            _details(run_errors),
            message="SigmaMutant reported run errors",
            type="RunError",
        )

    root.set("failures", str(failures))
    root.set("errors", str(errors))
    root.set("skipped", str(skipped))

    ElementTree.indent(root, space="  ")
    xml = ElementTree.tostring(root, encoding="unicode", short_empty_elements=True)
    return '<?xml version="1.0" encoding="utf-8"?>\n' + xml + "\n"


def write_junit(result: Any, suite: Any, output_dir: str | Path) -> Path:
    """Write JUnit XML whose gate reflects RunResult.passed."""

    destination = ensure_output_dir(output_dir) / "junit.xml"
    return write_text(
        destination,
        render_junit(result, suite),
        protected_paths=suite_input_paths(suite),
    )

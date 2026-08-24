"""Deterministic aggregate reports for multi-suite checks."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import TYPE_CHECKING, Any
from xml.etree import ElementTree

from sigmamutant.reporting._common import (
    ensure_output_dir,
    json_text,
    preflight_managed_paths,
    write_text,
)

if TYPE_CHECKING:
    from sigmamutant.batch import BatchEntry, BatchRunResult


def _relative_artifact(entry: BatchEntry, batch: BatchRunResult) -> str:
    try:
        return entry.artifact_dir.relative_to(batch.output_dir).as_posix()
    except ValueError:
        return entry.artifact_dir.name


def batch_payload(batch: BatchRunResult) -> dict[str, Any]:
    """Return the stable machine-readable aggregate payload."""

    entries: list[dict[str, Any]] = []
    for entry in batch.entries:
        result = entry.result
        entries.append(
            {
                "suite": entry.display_path,
                "status": entry.status,
                "artifact_dir": _relative_artifact(entry, batch),
                "rule_title": result.rule_title if result else None,
                "baseline_passed": result.baseline_passed if result else False,
                "score": result.score if result else None,
                "threshold": result.threshold if result else None,
                "killed": result.killed if result else 0,
                "survived": result.survived if result else 0,
                "excluded": result.excluded if result else 0,
                "error": entry.error,
                "errors": list(result.errors) if result else [],
            }
        )
    return {
        "schema_version": 1,
        "summary": {
            "total": len(batch.entries),
            "passed": batch.passed,
            "failed": batch.failed,
            "errors": batch.errors,
            "exit_code": batch.exit_code,
        },
        "suites": entries,
    }


def _render_html(batch: BatchRunResult) -> str:
    payload = batch_payload(batch)
    rows: list[str] = []
    for item in payload["suites"]:
        score = "-" if item["score"] is None else f"{item['score']:.1%}"
        threshold = "-" if item["threshold"] is None else f"{item['threshold']:.1%}"
        report = f"{item['artifact_dir']}/report.html"
        evidence = (
            "-"
            if item["status"] == "error"
            else f'<a href="{escape(report)}">report</a>'
        )
        error = item["error"] or "; ".join(item["errors"])
        rows.append(
            "<tr>"
            f"<td>{escape(item['suite'])}</td>"
            f'<td class="{escape(item["status"])}">{escape(item["status"])}</td>'
            f"<td>{escape(score)}</td><td>{escape(threshold)}</td>"
            f"<td>{item['killed']}</td><td>{item['survived']}</td>"
            f"<td>{evidence}</td>"
            f"<td>{escape(error)}</td>"
            "</tr>"
        )
    summary = payload["summary"]
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>SigmaMutant repository check</title><style>"
        "body{font:15px system-ui;margin:2rem;color:#18212b}"
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd3da;"
        "padding:.55rem;text-align:left}th{background:#eef2f5}"
        ".passed{color:#18794e}.failed,.error{color:#b42318;font-weight:700}"
        "code{background:#eef2f5;padding:.15rem .3rem}</style></head><body>"
        "<h1>SigmaMutant repository check</h1>"
        f"<p><strong>{summary['passed']}</strong> passed, "
        f"<strong>{summary['failed']}</strong> failed, "
        f"<strong>{summary['errors']}</strong> errors.</p>"
        "<table><thead><tr><th>Suite</th><th>Status</th><th>Score</th>"
        "<th>Threshold</th><th>Killed</th><th>Survived</th><th>Evidence</th>"
        "<th>Error</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></body></html>\n"
    )


def _render_junit(batch: BatchRunResult) -> str:
    root = ElementTree.Element(
        "testsuite",
        {
            "name": "sigmamutant:repository-check",
            "tests": str(len(batch.entries)),
            "failures": str(batch.failed),
            "errors": str(batch.errors),
            "time": "0",
        },
    )
    for entry in batch.entries:
        case = ElementTree.SubElement(
            root,
            "testcase",
            {
                "classname": "sigmamutant.check",
                "name": entry.display_path,
                "time": "0",
            },
        )
        if entry.status == "error":
            details = entry.error or "; ".join(
                entry.result.errors if entry.result else ()
            )
            element = ElementTree.SubElement(
                case,
                "error",
                {"message": "suite execution error", "type": "SuiteExecutionError"},
            )
            element.text = details
        elif entry.status == "failed":
            assert entry.result is not None
            element = ElementTree.SubElement(
                case,
                "failure",
                {
                    "message": "mutation score below threshold",
                    "type": "MutationScoreFailure",
                },
            )
            element.text = (
                f"score={entry.result.score}; threshold={entry.result.threshold}; "
                f"survived={entry.result.survived}"
            )
    ElementTree.indent(root, space="  ")
    xml = ElementTree.tostring(root, encoding="unicode", short_empty_elements=True)
    return '<?xml version="1.0" encoding="utf-8"?>\n' + xml + "\n"


def write_batch_reports(batch: BatchRunResult) -> dict[str, Path]:
    """Write aggregate JSON, HTML, and JUnit evidence."""

    protected = batch.protected_paths or tuple(
        entry.suite_path for entry in batch.entries
    )
    output = preflight_managed_paths(
        batch.output_dir,
        filenames=("summary.json", "summary.html", "junit.xml"),
        protected_paths=protected,
    )
    output = ensure_output_dir(output)
    return {
        "json": write_text(
            output / "summary.json",
            json_text(batch_payload(batch)),
            protected_paths=protected,
        ),
        "html": write_text(
            output / "summary.html",
            _render_html(batch),
            protected_paths=protected,
        ),
        "junit": write_text(
            output / "junit.xml",
            _render_junit(batch),
            protected_paths=protected,
        ),
    }

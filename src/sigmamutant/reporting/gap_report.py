"""Deterministic, value-safe reports for event-variation gap analysis."""

from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from sigmamutant.reporting._common import (
    get_field,
    preflight_managed_paths,
    status_value,
    suite_input_paths,
    to_primitive,
    write_text,
)

_FILENAMES = ("gap-report.json", "gap-report.html", "gap-junit.xml")


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(
        to_primitive(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def gap_payload(result: Any, suite: Any) -> dict[str, Any]:
    """Return a stable report payload without raw fixture-derived values."""

    config = get_field(suite, "config", {}) or {}
    suite_path = get_field(suite, "path")
    stable_suite_path = Path(suite_path).name if suite_path else None
    stable_rule_path = get_field(config, "rule")
    stable_fixtures_path = get_field(config, "fixtures")

    serialized: list[dict[str, Any]] = []
    for item in get_field(result, "variation_results", ()) or ():
        variation = get_field(item, "variation")
        serialized.append(
            {
                "id": str(get_field(variation, "id", "")),
                "source_fixture_id": str(get_field(variation, "source_fixture_id", "")),
                "operator": str(get_field(variation, "operator", "")),
                "field": str(get_field(variation, "field", "")),
                "path": str(get_field(variation, "path", "")),
                "description": str(get_field(variation, "description", "")),
                "claim_scope": str(get_field(variation, "claim_scope", "")),
                "status": status_value(get_field(item, "status")),
                "baseline_match": get_field(item, "baseline_match"),
                "variation_match": get_field(item, "variation_match"),
                "reason": get_field(item, "reason"),
                "evidence": {
                    "source_value_sha256": _canonical_hash(
                        get_field(variation, "original")
                    ),
                    "replacement_value_sha256": _canonical_hash(
                        get_field(variation, "replacement")
                    ),
                    "event_sha256": _canonical_hash(get_field(variation, "event")),
                },
            }
        )
    serialized.sort(key=lambda item: item["id"])

    return {
        "schema_version": 1,
        "analysis": "event-robustness",
        "rule_title": get_field(result, "rule_title", ""),
        "baseline_passed": bool(get_field(result, "baseline_passed", False)),
        "score": float(get_field(result, "score", 0.0)),
        "threshold": float(get_field(result, "threshold", 1.0)),
        "detected": int(get_field(result, "detected", 0)),
        "gaps": int(get_field(result, "escaped", 0)),
        "excluded": int(get_field(result, "excluded", 0)),
        "seed_count": int(get_field(result, "seed_count", 0)),
        "fixture_count": int(get_field(result, "fixture_count", 0)),
        "variation_count": int(get_field(result, "variation_count", 0)),
        "passed": bool(get_field(result, "passed", False)),
        "errors": to_primitive(get_field(result, "errors", ()) or ()),
        "metadata": to_primitive(get_field(result, "metadata", {}) or {}),
        "suite": {
            "path": to_primitive(stable_suite_path),
            "rule_path": to_primitive(stable_rule_path),
            "fixtures_path": to_primitive(stable_fixtures_path),
            "config": to_primitive(config),
        },
        "variation_results": serialized,
        "interpretation": {
            "measures": (
                "whether the configured evaluator retains matches for a bounded, "
                "deterministic set of inert variants derived from labelled "
                "positive fixtures"
            ),
            "does_not_prove": (
                "real-world evasion, attack success, production false-negative "
                "rate, telemetry equivalence, or SIEM backend equivalence"
            ),
        },
    }


_STYLE = """
:root { color-scheme: light dark; --bg:#0b1020; --panel:#141b2d;
--text:#e7edf8; --muted:#a8b3c7; --border:#2a3550; --good:#42d392;
--bad:#ff6b6b; --warn:#f4c95d; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text);
font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
main { width:min(1180px,calc(100% - 32px)); margin:32px auto 56px; }
h1,h2 { line-height:1.2; } h1 { overflow-wrap:anywhere; }
.muted { color:var(--muted); } .pass,.detected { color:var(--good); }
.fail,.escaped { color:var(--bad); } .excluded { color:var(--warn); }
.summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(145px,1fr));
gap:12px; margin:24px 0; }
.card { padding:14px 16px; border:1px solid var(--border); border-radius:8px;
background:var(--panel); } .card strong { display:block; margin-top:5px;
font-size:20px; }
.table-wrap { overflow-x:auto; border:1px solid var(--border); border-radius:8px; }
table { width:100%; border-collapse:collapse; background:var(--panel); }
th,td { padding:10px 12px; border-bottom:1px solid var(--border);
text-align:left; vertical-align:top; overflow-wrap:anywhere; } th { color:var(--muted); }
tr:last-child td { border-bottom:0; }
pre { white-space:pre-wrap; overflow-wrap:anywhere; padding:14px;
border:1px solid var(--border); border-radius:8px; background:var(--panel); }
""".strip()


def _escape(value: Any) -> str:
    return html.escape(_xml_safe(value), quote=True)


def _xml_safe(value: Any) -> str:
    """Replace characters forbidden by XML 1.0 and unsafe UTF-8 surrogates."""

    text = str(value)
    return "".join(
        character
        if (
            character in "\t\n\r"
            or "\u0020" <= character <= "\ud7ff"
            or "\ue000" <= character <= "\ufffd"
            or "\U00010000" <= character <= "\U0010ffff"
        )
        else "\ufffd"
        for character in text
    )


def _gap_json_text(value: Any) -> str:
    """Serialize gap evidence as UTF-8-safe deterministic JSON."""

    return (
        json.dumps(
            to_primitive(value),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _card(label: str, value: Any, css: str = "") -> str:
    attribute = f' class="{css}"' if css else ""
    return (
        '<div class="card">'
        f'<span class="muted">{_escape(label)}</span>'
        f"<strong{attribute}>{_escape(value)}</strong></div>"
    )


def render_gap_html(result: Any, suite: Any) -> str:
    payload = gap_payload(result, suite)
    passed = payload["passed"]
    technical_error = bool(payload["errors"]) or not payload["baseline_passed"]
    result_label = "ERROR" if technical_error else "PASS" if passed else "FAIL"
    cards = "".join(
        (
            _card("Result", result_label, "pass" if passed else "fail"),
            _card(
                "Baseline",
                "PASS" if payload["baseline_passed"] else "FAIL",
                "pass" if payload["baseline_passed"] else "fail",
            ),
            _card("Variant score", f"{payload['score']:.1%}"),
            _card("Threshold", f"{payload['threshold']:.1%}"),
            _card("Detected", payload["detected"], "detected"),
            _card("Gap candidates", payload["gaps"], "escaped"),
            _card("Excluded", payload["excluded"], "excluded"),
            _card("Positive seeds", payload["seed_count"]),
        )
    )
    rows: list[str] = []
    for item in payload["variation_results"]:
        status = item["status"]
        css = status if status in {"detected", "escaped", "excluded"} else ""
        display_status = "gap candidate" if status == "escaped" else status
        rows.append(
            "<tr>"
            f"<td>{_escape(item['id'])}</td>"
            f"<td>{_escape(item['source_fixture_id'])}</td>"
            f"<td>{_escape(item['operator'])}</td>"
            f"<td>{_escape(item['path'])}</td>"
            f'<td class="{css}">{_escape(display_status)}</td>'
            f"<td>{_escape(item['description'])}</td>"
            f"<td>{_escape(item['claim_scope'])}</td>"
            f"<td>{_escape(item['evidence']['event_sha256'])}</td>"
            "</tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="8" class="muted">No variants.</td></tr>')
    metadata = json.dumps(
        payload["metadata"], ensure_ascii=True, indent=2, sort_keys=True
    )
    errors = "".join(f"<li>{_escape(error)}</li>" for error in payload["errors"])
    error_section = f"<h2>Errors</h2><ul>{errors}</ul>" if errors else ""
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n'
        '  <meta charset="utf-8">\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"  <title>{_escape(payload['rule_title'])} — gap report</title>\n"
        f"  <style>{_STYLE}</style>\n</head>\n<body>\n<main>\n"
        f"  <h1>{_escape(payload['rule_title'])}</h1>\n"
        '  <p class="muted">Deterministic event-robustness hypotheses; '
        "not proof of real-world evasion.</p>\n"
        f'  <section class="summary">{cards}</section>\n'
        '  <h2>Event variations</h2>\n<div class="table-wrap"><table>\n'
        "  <thead><tr><th>ID</th><th>Seed</th><th>Operator</th><th>Event path</th>"
        "<th>Status</th><th>Description</th><th>Claim scope</th>"
        "<th>Event SHA-256</th></tr></thead>\n"
        f"  <tbody>{''.join(rows)}</tbody>\n</table></div>\n"
        f"  {error_section}\n<h2>Metadata</h2><pre>{_escape(metadata)}</pre>\n"
        "</main>\n</body>\n</html>\n"
    )


def render_gap_junit(result: Any, suite: Any) -> str:
    payload = gap_payload(result, suite)
    variants = payload["variation_results"]
    errors = payload["errors"]
    root = ElementTree.Element(
        "testsuite",
        {
            "name": _xml_safe(f"sigmamutant-gap:{payload['rule_title'] or 'untitled'}"),
            "tests": str(1 + len(variants) + (1 if errors else 0)),
            "failures": "0",
            "errors": "0",
            "skipped": "0",
            "time": "0",
        },
    )
    properties = ElementTree.SubElement(root, "properties")
    for name in (
        "baseline_passed",
        "score",
        "threshold",
        "passed",
        "seed_count",
        "gaps",
    ):
        value = payload[name]
        ElementTree.SubElement(
            properties,
            "property",
            {
                "name": name,
                "value": str(value).lower() if isinstance(value, bool) else str(value),
            },
        )

    failures = 0
    error_count = 0
    skipped = 0
    gate = ElementTree.SubElement(
        root,
        "testcase",
        {"classname": "sigmamutant.gap", "name": "variant-score-gate", "time": "0"},
    )
    if not payload["passed"] and not errors:
        failures += 1
        message = (
            f"gap analysis failed: score={payload['score']}, "
            f"threshold={payload['threshold']}, "
            f"gap_candidates={payload['gaps']}"
        )
        failure = ElementTree.SubElement(
            gate,
            "failure",
            {"message": message, "type": "VariantScoreFailure"},
        )
        failure.text = message

    for item in variants:
        testcase = ElementTree.SubElement(
            root,
            "testcase",
            {
                "classname": _xml_safe(
                    f"sigmamutant.gap.{item['operator'] or 'variation'}"
                ),
                "name": _xml_safe(item["id"]),
                "time": "0",
            },
        )
        detail = json.dumps(item, ensure_ascii=True, indent=2, sort_keys=True)
        if item["status"] == "excluded":
            skipped += 1
            child = ElementTree.SubElement(
                testcase, "skipped", {"message": "variation excluded"}
            )
        else:
            child = ElementTree.SubElement(testcase, "system-out")
        child.text = detail

    if errors:
        error_count += 1
        testcase = ElementTree.SubElement(
            root,
            "testcase",
            {"classname": "sigmamutant.gap", "name": "analysis-errors", "time": "0"},
        )
        child = ElementTree.SubElement(
            testcase,
            "error",
            {"message": "SigmaMutant gap analysis errors", "type": "GapAnalysisError"},
        )
        child.text = json.dumps(errors, ensure_ascii=True, indent=2, sort_keys=True)

    root.set("failures", str(failures))
    root.set("errors", str(error_count))
    root.set("skipped", str(skipped))
    ElementTree.indent(root, space="  ")
    xml = ElementTree.tostring(root, encoding="unicode", short_empty_elements=True)
    return '<?xml version="1.0" encoding="utf-8"?>\n' + xml + "\n"


def preflight_gap_output(suite: Any, output_dir: str | Path) -> Path:
    """Validate the complete managed namespace before analysis starts."""

    return preflight_managed_paths(
        output_dir,
        filenames=_FILENAMES,
        protected_paths=suite_input_paths(suite),
    )


def write_gap_reports(
    result: Any, suite: Any, output_dir: str | Path
) -> dict[str, Path]:
    """Preflight and atomically write the complete value-safe report set."""

    protected = suite_input_paths(suite)
    output = preflight_gap_output(suite, output_dir)
    paths = {
        "json": output / "gap-report.json",
        "html": output / "gap-report.html",
        "junit": output / "gap-junit.xml",
    }
    payload = gap_payload(result, suite)
    write_text(paths["json"], _gap_json_text(payload), protected_paths=protected)
    write_text(paths["html"], render_gap_html(result, suite), protected_paths=protected)
    write_text(
        paths["junit"], render_gap_junit(result, suite), protected_paths=protected
    )
    return paths

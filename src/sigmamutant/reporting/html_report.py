from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from ._common import ensure_output_dir, result_payload, suite_input_paths, write_text

_STYLE = """
:root {
  color-scheme: light dark;
  --bg: #0b1020;
  --panel: #141b2d;
  --text: #e7edf8;
  --muted: #a8b3c7;
  --border: #2a3550;
  --good: #42d392;
  --bad: #ff6b6b;
  --warn: #f4c95d;
  --info: #79b8ff;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
main { width: min(1180px, calc(100% - 32px)); margin: 32px auto 56px; }
h1, h2 { line-height: 1.2; }
h1 { margin-bottom: 6px; overflow-wrap: anywhere; }
h2 { margin-top: 32px; }
.muted { color: var(--muted); }
.summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
  gap: 12px;
  margin: 24px 0;
}
.card {
  padding: 14px 16px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--panel);
}
.card strong { display: block; margin-top: 5px; font-size: 20px; }
.pass, .killed { color: var(--good); }
.fail, .survived, .error, .baseline-failed { color: var(--bad); }
.excluded, .skipped { color: var(--warn); }
.unknown { color: var(--info); }
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border);
  border-radius: 8px;
}
table { width: 100%; border-collapse: collapse; background: var(--panel); }
th, td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
}
th { color: var(--muted); }
tr:last-child td { border-bottom: 0; }
pre {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--panel);
}
ul { padding-left: 24px; }
""".strip()


def _escape(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return html.escape(str(value), quote=True)


def _status_class(status: str) -> str:
    allowed = {
        "killed",
        "survived",
        "excluded",
        "skipped",
        "error",
        "baseline-failed",
    }
    return status if status in allowed else "unknown"


def _card(label: str, value: Any, css_class: str = "") -> str:
    class_attribute = f' class="{css_class}"' if css_class else ""
    return (
        '<div class="card">'
        f'<span class="muted">{_escape(label)}</span>'
        f"<strong{class_attribute}>{_escape(value)}</strong>"
        "</div>"
    )


def _percent(value: Any) -> str:
    try:
        return f"{float(value):.1%}"
    except (TypeError, ValueError):
        return str(value)


def _mutant_rows(payload: dict[str, Any]) -> str:
    rows: list[str] = []
    for mutant in payload["mutant_results"]:
        status = str(mutant["status"])
        killed_by = mutant.get("killed_by") or []
        observations = mutant.get("observations") or []
        reason = mutant.get("reason") or ""
        details = mutant.get("mutant") or {}
        path = details.get("path", details.get("yaml_path", ""))
        before = details.get("before", details.get("original", ""))
        after = details.get("after", details.get("replacement", ""))
        rows.append(
            "<tr>"
            f"<td>{_escape(mutant['id'])}</td>"
            f"<td>{_escape(mutant['operator'])}</td>"
            f"<td>{_escape(path)}</td>"
            f"<td>{_escape(before)}</td>"
            f"<td>{_escape(after)}</td>"
            f'<td class="{_status_class(status)}">{_escape(status)}</td>'
            f"<td>{_escape(reason)}</td>"
            f"<td>{_escape(killed_by)}</td>"
            f"<td>{_escape(observations)}</td>"
            "</tr>"
        )
    if rows:
        return "".join(rows)
    return '<tr><td colspan="9" class="muted">No mutants were generated.</td></tr>'


def _errors(payload: dict[str, Any]) -> str:
    errors = payload.get("errors") or []
    if not errors:
        return ""
    items = "".join(f"<li>{_escape(error)}</li>" for error in errors)
    return f"<h2>Errors</h2><ul>{items}</ul>"


def render_html(result: Any, suite: Any) -> str:
    payload = result_payload(result, suite)
    rule_title = payload["rule_title"] or "Untitled rule"
    passed = payload["passed"]
    baseline = payload["baseline_passed"]
    score = payload["score"]

    summary = "".join(
        (
            _card("Result", "PASS" if passed else "FAIL", "pass" if passed else "fail"),
            _card(
                "Baseline",
                "PASS" if baseline else "FAIL",
                "pass" if baseline else "baseline-failed",
            ),
            _card("Mutation score", _percent(score)),
            _card("Threshold", _percent(payload["threshold"])),
            _card("Killed", payload["killed"], "killed"),
            _card("Survived", payload["survived"], "survived"),
            _card("Excluded", payload["excluded"], "excluded"),
            _card("Fixtures", payload["fixture_count"]),
        )
    )

    metadata = json.dumps(
        payload.get("metadata") or {},
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )

    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '  <meta charset="utf-8">\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"  <title>{_escape(rule_title)} — SigmaMutant report</title>\n"
        f"  <style>{_STYLE}</style>\n"
        "</head>\n"
        "<body>\n"
        "<main>\n"
        f"  <h1>{_escape(rule_title)}</h1>\n"
        '  <p class="muted">Deterministic mutation-testing report</p>\n'
        f'  <section class="summary">{summary}</section>\n'
        "  <h2>Mutants</h2>\n"
        '  <div class="table-wrap"><table>\n'
        "    <thead><tr>"
        "<th>ID</th><th>Operator</th><th>YAML path</th>"
        "<th>Before</th><th>After</th><th>Status</th>"
        "<th>Reason</th><th>Killed by</th><th>Observations</th>"
        "</tr></thead>\n"
        f"    <tbody>{_mutant_rows(payload)}</tbody>\n"
        "  </table></div>\n"
        f"  {_errors(payload)}\n"
        "  <h2>Metadata</h2>\n"
        f"  <pre>{_escape(metadata)}</pre>\n"
        "</main>\n"
        "</body>\n"
        "</html>\n"
    )


def write_html(result: Any, suite: Any, output_dir: str | Path) -> Path:
    """Write a standalone report with all user-controlled values escaped."""

    destination = ensure_output_dir(output_dir) / "report.html"
    return write_text(
        destination,
        render_html(result, suite),
        protected_paths=suite_input_paths(suite),
    )

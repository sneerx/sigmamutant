from __future__ import annotations

from pathlib import Path
from typing import Any

from ._common import preflight_managed_paths, suite_input_paths
from .html_report import render_html, write_html
from .json_report import write_json
from .junit_report import render_junit, write_junit
from .survivors import preflight_survivor_output, write_survivors

__all__ = [
    "render_html",
    "render_junit",
    "write_all",
    "write_html",
    "write_json",
    "write_junit",
    "write_survivors",
]


def write_all(
    result: Any,
    suite: Any,
    output_dir: str | Path,
) -> dict[str, Path | tuple[Path, ...]]:
    """Write every supported report and return their paths."""

    protected_paths = suite_input_paths(suite)
    output = preflight_managed_paths(
        output_dir,
        filenames=("report.json", "report.html", "junit.xml"),
        subdirectories=("survivors",),
        protected_paths=protected_paths,
    )
    preflight_survivor_output(suite, output)
    return {
        "json": write_json(result, suite, output),
        "html": write_html(result, suite, output),
        "junit": write_junit(result, suite, output),
        "survivors": write_survivors(result, suite, output),
    }

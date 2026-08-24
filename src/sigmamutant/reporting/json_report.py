from __future__ import annotations

from pathlib import Path
from typing import Any

from ._common import (
    ensure_output_dir,
    json_text,
    result_payload,
    suite_input_paths,
    write_text,
)


def write_json(result: Any, suite: Any, output_dir: str | Path) -> Path:
    """Write the deterministic machine-readable report."""

    destination = ensure_output_dir(output_dir) / "report.json"
    return write_text(
        destination,
        json_text(result_payload(result, suite)),
        protected_paths=suite_input_paths(suite),
    )

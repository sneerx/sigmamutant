"""Typed, value-free progress events for core mutation runs."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class RunProgress:
    """One deterministic progress event rendered only when requested."""

    stage: str
    details: Mapping[str, Any]


ProgressCallback = Callable[[RunProgress], None]


def emit_progress(
    callback: ProgressCallback | None,
    stage: str,
    **details: Any,
) -> None:
    """Emit metadata about execution without exposing fixture event values."""

    if callback is not None:
        callback(RunProgress(stage=stage, details=details))

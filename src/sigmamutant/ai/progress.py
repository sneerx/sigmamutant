"""Typed, secret-safe progress events for interactive fixture suggestions."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SuggestionProgress:
    """One deterministic progress event rendered only when explicitly enabled."""

    stage: str
    details: Mapping[str, Any]


ProgressCallback = Callable[[SuggestionProgress], None]


def emit_progress(
    callback: ProgressCallback | None,
    stage: str,
    **details: Any,
) -> None:
    """Emit a progress event without coupling the core service to a terminal."""

    if callback is not None:
        callback(SuggestionProgress(stage=stage, details=details))

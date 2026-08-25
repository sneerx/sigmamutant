"""Immutable domain models for deterministic detection-gap analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

GapStatus = Literal["detected", "escaped", "excluded"]


@dataclass(frozen=True, slots=True)
class EventVariation:
    """One inert, reproducible variation of a labelled positive event."""

    id: str
    source_fixture_id: str
    operator: str
    field: str
    description: str
    claim_scope: str
    original: Any
    replacement: Any
    event: dict[str, Any]

    @property
    def path(self) -> str:
        """RFC 6901 JSON Pointer for the changed top-level event field."""

        escaped = self.field.replace("~", "~0").replace("/", "~1")
        return f"/{escaped}"


@dataclass(frozen=True, slots=True)
class GapVariationResult:
    """The original rule's observation for one event variation."""

    variation: EventVariation
    status: GapStatus
    baseline_match: bool
    variation_match: bool | None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class DetectionGapResult:
    """Fail-closed aggregate result for one rule and labelled fixture corpus."""

    rule_title: str
    baseline_passed: bool
    score: float
    detected: int
    escaped: int
    excluded: int
    seed_count: int
    fixture_count: int
    variation_results: tuple[GapVariationResult, ...]
    threshold: float
    passed: bool
    errors: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_scored(self) -> int:
        return self.detected + self.escaped

    @property
    def variation_count(self) -> int:
        return len(self.variation_results)

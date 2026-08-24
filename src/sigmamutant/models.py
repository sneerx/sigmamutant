"""Domain models shared by the CLI, runner, and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

MutationStatus = Literal["killed", "survived", "excluded"]


@dataclass(frozen=True, slots=True)
class SuiteConfig:
    version: int
    rule: str
    fixtures: str
    fail_under: float = 0.8


@dataclass(frozen=True, slots=True)
class Fixture:
    id: str
    expected: bool
    event: dict[str, Any]


@dataclass(frozen=True, slots=True)
class LoadedSuite:
    config: SuiteConfig
    path: Path
    rule_path: Path
    fixtures_path: Path
    suite_bytes: bytes
    rule_bytes: bytes
    fixtures_bytes: bytes
    rule_document: dict[str, Any]
    fixtures: tuple[Fixture, ...]

    @property
    def rule_doc(self) -> dict[str, Any]:
        """Compatibility alias for callers that prefer the shorter name."""
        return self.rule_document


@dataclass(frozen=True, slots=True)
class Mutant:
    id: str
    operator: str
    path: str
    description: str
    original: Any
    replacement: Any
    document: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Observation:
    fixture_id: str
    expected: bool
    baseline_match: bool
    mutant_match: bool


@dataclass(frozen=True, slots=True)
class MutantResult:
    mutant: Mutant
    status: MutationStatus
    killed_by: tuple[str, ...] = ()
    observations: tuple[Observation, ...] = ()
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class RunResult:
    rule_title: str
    baseline_passed: bool
    score: float
    killed: int
    survived: int
    excluded: int
    mutant_results: tuple[MutantResult, ...]
    fixture_count: int
    threshold: float
    passed: bool
    errors: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_scored(self) -> int:
        return self.killed + self.survived


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Supported-subset and baseline result without mutation execution."""

    rule_title: str
    rule_supported: bool
    baseline_passed: bool
    fixture_count: int
    errors: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.rule_supported and self.baseline_passed and not self.errors

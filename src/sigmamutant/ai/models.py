"""Models at the untrusted-provider and deterministic-proof boundary."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path
from typing import Annotated, Any, Protocol

from pydantic import BaseModel, ConfigDict, Field


class SuggestedField(BaseModel):
    """One flat event field proposed by an untrusted provider.

    Values are direct JSON scalars. Objects and arrays cannot cross this model
    boundary, and SigmaMutant applies additional local size and number checks.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    name: str = Field(min_length=1, max_length=128)
    value: Annotated[str, Field(max_length=512)] | int | float | bool | None


class FixtureCandidate(BaseModel):
    """A provider's inert synthetic event candidate."""

    model_config = ConfigDict(extra="forbid", strict=True)

    candidate_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    rationale: str = Field(min_length=1, max_length=500)
    fields: tuple[SuggestedField, ...] = Field(min_length=1, max_length=16)


class SuggestionBatch(BaseModel):
    """Strict provider output envelope."""

    model_config = ConfigDict(extra="forbid", strict=True)

    candidates: tuple[FixtureCandidate, ...] = Field(min_length=1, max_length=3)


def json_value_type(value: Any) -> str:
    """Return the stable JSON type name used by fixture shape contracts."""

    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


@dataclass(frozen=True, slots=True)
class FixtureFieldContract:
    """One field present in every existing fixture shape."""

    name: str
    json_types: tuple[str, ...]

    def to_payload(self) -> dict[str, Any]:
        return {"name": self.name, "types": list(self.json_types)}


@dataclass(frozen=True, slots=True)
class FixtureSuggestionRequest:
    """Privacy-minimized data sent to a fixture-suggestion provider."""

    rule_title: str
    detection: dict[str, Any]
    mutant_id: str
    operator: str
    path: str
    description: str
    original: Any
    replacement: Any
    fixture_shape: tuple[dict[str, Any], ...]
    candidate_count: int
    required_fields: tuple[FixtureFieldContract, ...] = ()

    def to_payload(self) -> dict[str, Any]:
        """Return the stable, provider-facing payload.

        `fixture_shape` contains only field names and JSON types, never fixture
        identifiers or values.
        """

        return {
            "schema_version": 1,
            "task": (
                "Propose small schema-conforming flat synthetic JSON events "
                "that may make the original Sigma detection and this one-step "
                "mutant disagree. Local reduction determines a one-minimal "
                "witness outside fixture-contract fields."
            ),
            "rule": {"detection": copy.deepcopy(self.detection)},
            "mutation": {
                "id": self.mutant_id,
                "operator": self.operator,
                "path": self.path,
                "description": self.description,
                "before": copy.deepcopy(self.original),
                "after": copy.deepcopy(self.replacement),
                "strategy_hint": _strategy_hint(self.operator),
            },
            "existing_fixture_shapes": copy.deepcopy(list(self.fixture_shape)),
            "fixture_contract": {
                "required_fields": [
                    field.to_payload() for field in self.required_fields
                ],
                "requirement": (
                    "Every candidate must include these fields with one of the "
                    "observed JSON types. Local reduction preserves them."
                ),
            },
            "candidate_count": self.candidate_count,
        }


def _strategy_hint(operator: str) -> str:
    hints = {
        "delete_list_item": (
            "Use mutation.before as the deleted alternative at mutation.path, "
            "then satisfy every unchanged predicate required by the condition."
        ),
        "modifier_to_exact": (
            "Use a benign field value that matches the original string "
            "modifier but is not exactly equal to the detection literal."
        ),
        "delete_predicate": (
            "Satisfy the remaining condition while deliberately making the "
            "deleted original predicate false."
        ),
        "list_any_to_all": (
            "Match one original list alternative while deliberately not "
            "matching every alternative required by the mutant."
        ),
        "condition_and_to_or": (
            "Choose selector outcomes that make the original Boolean "
            "connective differ from the mutant connective."
        ),
        "condition_remove_not": (
            "Choose an event where the referenced selector's Boolean result "
            "changes the condition when negation is removed."
        ),
    }
    return hints.get(
        operator,
        "Isolate the mutation while satisfying all unchanged condition terms.",
    )


@dataclass(frozen=True, slots=True)
class ProviderUsage:
    """Provider-reported token counts; pricing is intentionally not inferred."""

    input_tokens: int
    output_tokens: int
    total_tokens: int
    cached_tokens: int | None = None
    cache_write_tokens: int | None = None
    reasoning_tokens: int | None = None


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    """Validated provider output plus non-authoritative trace metadata."""

    batch: SuggestionBatch
    response_id: str | None = None
    usage: ProviderUsage | None = None


class FixtureSuggestionProvider(Protocol):
    """Provider boundary; implementations may be remote or local."""

    name: str
    model: str

    def suggest(self, request: FixtureSuggestionRequest) -> ProviderResponse:
        """Return schema-validated candidates without deciding correctness."""


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Local proof result for one untrusted event candidate."""

    candidate_id: str
    rationale: str
    event: dict[str, Any]
    expected: bool | None
    baseline_match: bool | None
    mutant_match: bool | None
    verified: bool
    removed_fields: tuple[str, ...] = ()
    rejection_reason: str | None = None
    proposed_event: dict[str, Any] = dataclass_field(default_factory=dict)
    proposed_baseline_match: bool | None = None
    proposed_mutant_match: bool | None = None
    required_fields: tuple[str, ...] = ()
    reduction_algorithm: str = "stable-greedy-field-deletion"
    reduction_policy: str = "preserve-exact-pair-and-fixture-contract"
    minimality: str = "not-established"


@dataclass(frozen=True, slots=True)
class SuggestionRunResult:
    """Evidence bundle for one surviving mutant and one provider response."""

    suite_name: str
    rule_title: str
    mutant_id: str
    operator: str
    path: str
    provider: str
    model: str
    response_id: str | None
    prompt_sha256: str
    requested_candidates: int
    suggestions: tuple[VerificationResult, ...]
    mutant_description: str = ""
    original: Any = None
    replacement: Any = None
    rule_sha256: str = ""
    mutant_sha256: str = ""
    evaluator: str = "azuma"
    evaluator_version: str = "unknown"
    sigmamutant_version: str = "unknown"
    input_paths: tuple[Path, ...] = ()
    provider_usage: ProviderUsage | None = None

    @property
    def verified_count(self) -> int:
        return sum(item.verified for item in self.suggestions)

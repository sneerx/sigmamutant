"""Optional, provider-independent fixture suggestion and proof pipeline."""

from sigmamutant.ai.models import (
    FixtureCandidate,
    FixtureSuggestionRequest,
    ProviderResponse,
    ProviderUsage,
    SuggestedField,
    SuggestionBatch,
    SuggestionRunResult,
    VerificationResult,
)
from sigmamutant.ai.progress import SuggestionProgress
from sigmamutant.ai.service import suggest_fixtures, write_suggestion_artifact

__all__ = [
    "FixtureCandidate",
    "FixtureSuggestionRequest",
    "ProviderResponse",
    "ProviderUsage",
    "SuggestedField",
    "SuggestionBatch",
    "SuggestionRunResult",
    "SuggestionProgress",
    "VerificationResult",
    "suggest_fixtures",
    "write_suggestion_artifact",
]

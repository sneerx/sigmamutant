"""User-facing error types."""


class SigmaMutantError(Exception):
    """Base class for expected input and evaluation errors."""


class SuiteError(SigmaMutantError):
    """A suite file or fixture corpus is invalid."""


class RuleError(SigmaMutantError):
    """A rule is invalid or outside the supported subset."""


class EvaluationError(SigmaMutantError):
    """A rule could not be evaluated against an event."""


class FixtureSuggestionError(SigmaMutantError):
    """An AI-assisted fixture suggestion could not be produced or verified."""


class ProviderError(FixtureSuggestionError):
    """An optional fixture-suggestion provider failed safely."""


class FixturePromotionError(SigmaMutantError):
    """A proposed fixture could not be safely exported or promoted."""


class ExampleInitializationError(SigmaMutantError):
    """A bundled example could not be initialized safely."""

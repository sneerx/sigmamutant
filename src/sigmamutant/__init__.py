"""SigmaMutant: two-sided robustness testing for Sigma detection contracts."""

from sigmamutant.event_variations import (
    DEFAULT_MAX_VARIATIONS,
    EVENT_OPERATORS,
    EventVariationLimitError,
    generate_event_variations,
)
from sigmamutant.gap_analysis import analyze_detection_gaps
from sigmamutant.gap_models import (
    DetectionGapResult,
    EventVariation,
    GapVariationResult,
)
from sigmamutant.gap_runner import run_gap_analysis
from sigmamutant.models import Fixture, Mutant, MutantResult, RunResult, SuiteConfig
from sigmamutant.mutations import OPERATORS, generate_mutants
from sigmamutant.runner import run_suite

__all__ = [
    "DetectionGapResult",
    "DEFAULT_MAX_VARIATIONS",
    "EVENT_OPERATORS",
    "EventVariation",
    "EventVariationLimitError",
    "Fixture",
    "GapVariationResult",
    "Mutant",
    "MutantResult",
    "OPERATORS",
    "RunResult",
    "SuiteConfig",
    "analyze_detection_gaps",
    "generate_event_variations",
    "generate_mutants",
    "run_gap_analysis",
    "run_suite",
]

__version__ = "1.0.0"

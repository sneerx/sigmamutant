"""SigmaMutant: mutation testing for Sigma detection contracts."""

from sigmamutant.models import Fixture, Mutant, MutantResult, RunResult, SuiteConfig
from sigmamutant.mutations import OPERATORS, generate_mutants
from sigmamutant.runner import run_suite

__all__ = [
    "Fixture",
    "Mutant",
    "MutantResult",
    "OPERATORS",
    "RunResult",
    "SuiteConfig",
    "generate_mutants",
    "run_suite",
]

__version__ = "1.0.0"

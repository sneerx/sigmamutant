"""Offline, secret-safe environment diagnostics for SigmaMutant."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import platform
import re
import shutil
import sys
from dataclasses import dataclass

from sigmamutant import __version__

SUPPORTED_PYTHON = ">=3.11,<3.13"


@dataclass(frozen=True)
class CoreRequirement:
    """A runtime dependency and the version range supported by this release."""

    distribution: str
    module: str
    specifier: str
    minimum: tuple[int, ...] | None = None
    maximum: tuple[int, ...] | None = None
    exact: str | None = None


CORE_REQUIREMENTS = (
    CoreRequirement("azuma", "azuma", "==0.7.3", exact="0.7.3"),
    CoreRequirement("pysigma", "sigma", ">=1.4.0,<2", (1, 4, 0), (2,)),
    CoreRequirement("pydantic", "pydantic", ">=2.7,<3", (2, 7), (3,)),
    CoreRequirement("rich", "rich", ">=13.7,<15", (13, 7), (15,)),
    CoreRequirement(
        "ruamel.yaml",
        "ruamel.yaml",
        ">=0.18.6,<0.19",
        (0, 18, 6),
        (0, 19),
    ),
    CoreRequirement("typer", "typer", ">=0.12,<1", (0, 12), (1,)),
)
OPENAI_REQUIREMENT = CoreRequirement(
    "openai",
    "openai",
    ">=2.47,<3",
    (2, 47),
    (3,),
)


@dataclass(frozen=True)
class DoctorCheck:
    """One deterministic diagnostic row."""

    component: str
    status: str
    detail: str
    core: bool


@dataclass(frozen=True)
class DoctorReport:
    """Complete local environment report."""

    checks: tuple[DoctorCheck, ...]

    @property
    def healthy(self) -> bool:
        return all(check.status != "error" for check in self.checks if check.core)


_STABLE_VERSION = re.compile(
    r"^(?P<release>[0-9]+(?:\.[0-9]+)*)(?P<post>\.post[0-9]+)?"
    r"(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?$",
    re.IGNORECASE,
)


def _release_tuple(version: str) -> tuple[int, ...] | None:
    """Parse stable PEP 440 releases used by the declared dependency ranges."""

    match = _STABLE_VERSION.fullmatch(version.strip())
    if match is None:
        return None
    return tuple(int(part) for part in match.group("release").split("."))


def _compare_release(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    normalized_left = left + (0,) * (width - len(left))
    normalized_right = right + (0,) * (width - len(right))
    return (normalized_left > normalized_right) - (normalized_left < normalized_right)


def _version_is_supported(version: str, requirement: CoreRequirement) -> bool:
    public = version.strip().partition("+")[0]
    if requirement.exact is not None:
        return public == requirement.exact

    release = _release_tuple(version)
    if release is None:
        return False
    if requirement.minimum is not None:
        if _compare_release(release, requirement.minimum) < 0:
            return False
    if requirement.maximum is not None:
        if _compare_release(release, requirement.maximum) >= 0:
            return False
    return True


def _distribution_version(distribution: str) -> str:
    return importlib.metadata.version(distribution)


def _module_available(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (AttributeError, ImportError, ModuleNotFoundError, ValueError):
        return False


def _python_runtime() -> tuple[int, int, int, str]:
    return (
        sys.version_info.major,
        sys.version_info.minor,
        sys.version_info.micro,
        platform.python_implementation(),
    )


def _platform_summary() -> str:
    system = platform.system() or "unknown OS"
    machine = platform.machine() or "unknown architecture"
    return f"{system} {machine}"


def _core_dependency_check(requirement: CoreRequirement) -> DoctorCheck:
    try:
        installed = _distribution_version(requirement.distribution)
    except importlib.metadata.PackageNotFoundError:
        return DoctorCheck(
            requirement.distribution,
            "error",
            f"not installed; requires {requirement.specifier}",
            True,
        )
    except Exception as exc:  # pragma: no cover - defensive metadata boundary
        return DoctorCheck(
            requirement.distribution,
            "error",
            f"version metadata unreadable ({type(exc).__name__})",
            True,
        )

    if not _module_available(requirement.module):
        return DoctorCheck(
            requirement.distribution,
            "error",
            f"{installed} metadata found but import module is missing",
            True,
        )
    if not _version_is_supported(installed, requirement):
        return DoctorCheck(
            requirement.distribution,
            "error",
            f"{installed} installed; requires {requirement.specifier}",
            True,
        )
    return DoctorCheck(
        requirement.distribution,
        "pass",
        f"{installed} (requires {requirement.specifier})",
        True,
    )


def _openai_check() -> DoctorCheck:
    try:
        sdk_version = _distribution_version("openai")
    except importlib.metadata.PackageNotFoundError:
        sdk_version = None
    except Exception:  # pragma: no cover - optional metadata must not fail core
        sdk_version = None

    module_available = sdk_version is not None and _module_available("openai")
    sdk_compatible = module_available and _version_is_supported(
        sdk_version,
        OPENAI_REQUIREMENT,
    )
    key_configured = bool(os.environ.get("OPENAI_API_KEY", "").strip())
    if sdk_version is None:
        sdk_detail = "SDK not installed"
    elif not module_available:
        sdk_detail = f"SDK {sdk_version} metadata found but module is missing"
    elif not sdk_compatible:
        sdk_detail = (
            f"SDK {sdk_version} incompatible; requires {OPENAI_REQUIREMENT.specifier}"
        )
    else:
        sdk_detail = f"SDK {sdk_version}"
    key_detail = (
        "API key configured (value hidden)" if key_configured else "API key not set"
    )
    ready = sdk_compatible and key_configured
    readiness = "local prerequisites present" if ready else "optional; not ready"
    return DoctorCheck(
        "OpenAI",
        "ready" if ready else "optional",
        f"{readiness}; {sdk_detail}; {key_detail}; network not probed",
        False,
    )


def _ollama_check() -> DoctorCheck:
    cli_available = shutil.which("ollama") is not None
    detail = (
        "CLI detected; local service and model not probed"
        if cli_available
        else "optional; CLI not found; local service and model not probed"
    )
    return DoctorCheck(
        "Ollama",
        "available" if cli_available else "optional",
        detail,
        False,
    )


def collect_doctor_report() -> DoctorReport:
    """Inspect local prerequisites without importing providers or using the network."""

    major, minor, micro, implementation = _python_runtime()
    python_supported = (3, 11) <= (major, minor) < (3, 13)
    checks = [
        DoctorCheck("SigmaMutant", "pass", __version__, True),
        DoctorCheck(
            "Python",
            "pass" if python_supported else "error",
            f"{implementation} {major}.{minor}.{micro} (supported {SUPPORTED_PYTHON})",
            True,
        ),
        DoctorCheck("Platform", "info", _platform_summary(), False),
    ]
    checks.extend(_core_dependency_check(item) for item in CORE_REQUIREMENTS)
    checks.extend((_openai_check(), _ollama_check()))
    return DoctorReport(tuple(checks))

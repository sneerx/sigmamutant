from __future__ import annotations

import importlib.metadata
import tomllib
from pathlib import Path

import pytest
from typer.testing import CliRunner

import sigmamutant.doctor as doctor_module
from sigmamutant.cli import app

runner = CliRunner()

CORE_VERSIONS = {
    "azuma": "0.7.3",
    "pysigma": "1.5.0",
    "pydantic": "2.12.5",
    "rich": "14.2.0",
    "ruamel.yaml": "0.18.16",
    "typer": "0.21.0",
}


def _configure_doctor(
    monkeypatch: pytest.MonkeyPatch,
    *,
    versions: dict[str, str] | None = None,
    python: tuple[int, int, int, str] = (3, 12, 4, "CPython"),
    platform_summary: str = "TestOS test-arch",
    ollama_path: str | None = None,
) -> None:
    installed = CORE_VERSIONS if versions is None else versions

    def distribution_version(name: str) -> str:
        try:
            return installed[name]
        except KeyError as exc:
            raise importlib.metadata.PackageNotFoundError(name) from exc

    modules = {item.module for item in doctor_module.CORE_REQUIREMENTS}
    if "openai" in installed:
        modules.add("openai")

    monkeypatch.setattr(doctor_module, "_distribution_version", distribution_version)
    monkeypatch.setattr(doctor_module, "_module_available", modules.__contains__)
    monkeypatch.setattr(doctor_module, "_python_runtime", lambda: python)
    monkeypatch.setattr(
        doctor_module,
        "_platform_summary",
        lambda: platform_summary,
    )
    monkeypatch.setattr(
        doctor_module.shutil,
        "which",
        lambda executable: ollama_path if executable == "ollama" else None,
    )


def _invoke_doctor():
    return runner.invoke(app, ["doctor"], terminal_width=180)


def _single_spaced(output: str) -> str:
    return " ".join(output.split())


def test_doctor_base_install_passes_without_optional_ai(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_doctor(monkeypatch)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    first = _invoke_doctor()
    second = _invoke_doctor()
    output = _single_spaced(first.output)

    assert first.exit_code == 0, first.output
    assert first.output == second.output
    assert "RESULT: PASS" in output
    assert "supported >=3.11,<3.13" in output
    assert "SDK not installed" in output
    assert "API key not set" in output
    assert "CLI not found" in output
    assert "network not probed" in output
    for distribution, version in CORE_VERSIONS.items():
        assert distribution in output
        assert version in output


def test_doctor_hides_secret_and_local_executable_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "sk-secret-doctor-marker-123456789"
    ollama_path = "/Users/private-name/bin/ollama"
    versions = {**CORE_VERSIONS, "openai": "2.47.0"}
    _configure_doctor(monkeypatch, versions=versions, ollama_path=ollama_path)
    monkeypatch.setenv("OPENAI_API_KEY", secret)

    result = _invoke_doctor()
    output = _single_spaced(result.output)

    assert result.exit_code == 0, result.output
    assert "API key configured (value hidden)" in output
    assert "SDK 2.47.0" in output
    assert "CLI detected" in output
    assert secret not in output
    assert ollama_path not in output


@pytest.mark.parametrize(
    "platform_summary",
    ("Windows AMD64", "Linux x86_64", "Darwin arm64"),
)
def test_doctor_platform_reporting_has_no_shell_or_path_assumptions(
    monkeypatch: pytest.MonkeyPatch,
    platform_summary: str,
) -> None:
    _configure_doctor(monkeypatch, platform_summary=platform_summary)

    result = _invoke_doctor()

    assert result.exit_code == 0, result.output
    assert platform_summary in result.output


def test_doctor_fails_for_unsupported_python_only_as_core_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_doctor(monkeypatch, python=(3, 13, 0, "CPython"))

    result = _invoke_doctor()

    assert result.exit_code == 2
    assert "CPython 3.13.0" in result.output
    assert "RESULT: ERROR" in result.output


def test_doctor_fails_when_a_core_dependency_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    versions = {name: value for name, value in CORE_VERSIONS.items() if name != "azuma"}
    _configure_doctor(monkeypatch, versions=versions)

    result = _invoke_doctor()

    assert result.exit_code == 2
    assert "azuma" in result.output
    assert "not installed; requires ==0.7.3" in result.output
    assert "RESULT: ERROR" in result.output


def test_doctor_fails_when_a_core_dependency_is_incompatible(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    versions = {**CORE_VERSIONS, "rich": "15.0.0"}
    _configure_doctor(monkeypatch, versions=versions)

    result = _invoke_doctor()

    assert result.exit_code == 2
    assert "15.0.0 installed; requires >=13.7,<15" in result.output
    assert "RESULT: ERROR" in result.output


def test_doctor_treats_incompatible_openai_sdk_as_optional(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    versions = {**CORE_VERSIONS, "openai": "1.99.0"}
    _configure_doctor(monkeypatch, versions=versions)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret-old-sdk-marker")

    result = _invoke_doctor()
    output = _single_spaced(result.output)

    assert result.exit_code == 0, result.output
    assert "SDK 1.99.0 incompatible; requires >=2.47,<3" in output
    assert "RESULT: PASS" in output
    assert "sk-secret-old-sdk-marker" not in output


def test_doctor_core_requirements_match_package_metadata() -> None:
    project_file = Path(__file__).resolve().parents[1] / "pyproject.toml"
    project = tomllib.loads(project_file.read_text(encoding="utf-8"))
    declared = project["project"]["dependencies"]

    assert [
        f"{requirement.distribution}{requirement.specifier}"
        for requirement in doctor_module.CORE_REQUIREMENTS
    ] == declared

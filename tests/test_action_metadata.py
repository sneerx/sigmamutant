from __future__ import annotations

import re
from pathlib import Path

from ruamel.yaml import YAML

REPOSITORY = Path(__file__).resolve().parents[1]


def _action():
    parser = YAML(typ="safe")
    return parser.load((REPOSITORY / "action.yml").read_text(encoding="utf-8"))


def _workflow(name: str):
    parser = YAML(typ="safe")
    path = REPOSITORY / ".github" / "workflows" / name
    return parser.load(path.read_text(encoding="utf-8"))


def test_composite_action_exposes_offline_mutation_gate():
    action = _action()

    assert action["runs"]["using"] == "composite"
    assert action["inputs"]["target"]["required"] is True
    assert action["inputs"]["python-version"]["default"] == "3.12"
    assert set(action["outputs"]) == {"summary-json", "summary-html", "junit-xml"}

    rendered_steps = str(action["runs"]["steps"])
    assert "python -m sigmamutant" in rendered_steps
    assert "constraints-demo.txt" in rendered_steps
    assert "--allow-cloud" not in rendered_steps
    assert "--write" not in rendered_steps
    assert "OPENAI_API_KEY" not in rendered_steps


def test_action_publishes_paths_even_when_quality_gate_fails():
    action = _action()
    paths_step = next(
        step for step in action["runs"]["steps"] if step.get("id") == "paths"
    )

    assert paths_step["if"] == "always()"
    assert "summary.json" in paths_step["run"]
    assert "summary.html" in paths_step["run"]
    assert "junit.xml" in paths_step["run"]


def test_ci_covers_supported_platforms_and_built_wheel_on_both_pythons():
    workflow = _workflow("ci.yml")
    jobs = workflow["jobs"]
    expected_os = {"ubuntu-latest", "macos-latest", "windows-latest"}
    expected_python = {"3.11", "3.12"}

    for job_name in ("test", "wheel-smoke"):
        matrix = jobs[job_name]["strategy"]["matrix"]
        assert set(matrix["os"]) == expected_os
        assert set(matrix["python-version"]) == expected_python

    wheel_steps = str(jobs["wheel-smoke"]["steps"])
    install_step = next(
        step
        for step in jobs["wheel-smoke"]["steps"]
        if step.get("name") == "Install only the built wheel"
    )
    assert (
        "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
        in wheel_steps
    )
    assert "'pip', 'install'" in install_step["run"]
    assert "python -m sigmamutant doctor" in wheel_steps
    assert "python -m sigmamutant init-example" in wheel_steps
    assert "python -m sigmamutant validate" in wheel_steps
    assert "powershell-gap.yml" in wheel_steps
    assert "powershell-hardened-gap.yml" in wheel_steps
    assert "weak.returncode == 1" in wheel_steps
    assert "hardened.returncode == 0" in wheel_steps


def test_release_smoke_uses_only_the_wheel_contained_example():
    workflow = _workflow("release-validation.yml")
    steps = str(workflow["jobs"]["validate-release"]["steps"])

    assert "sigmamutant-release-smoke" in steps
    assert "init-example" in steps
    assert "sigmamutant-example/strong-suite.yml" in steps
    assert "sigmamutant-example/powershell-gap.yml" in steps
    assert "sigmamutant-example/powershell-hardened-gap.yml" in steps
    assert "weak_gap_exit" in steps
    assert "validate examples/strong-suite.yml" not in steps


def test_ci_and_release_reject_stale_or_mismatched_distributions():
    checks = (
        ("ci.yml", "package"),
        ("release-validation.yml", "validate-release"),
    )
    for workflow_name, job_name in checks:
        workflow = _workflow(workflow_name)
        steps = str(workflow["jobs"][job_name]["steps"])
        assert "python scripts/verify_release_artifacts.py" in steps


def test_ci_and_release_secret_scans_cover_tests_and_common_credentials():
    for workflow_name, job_name in (
        ("ci.yml", "hygiene"),
        ("release-validation.yml", "validate-release"),
    ):
        workflow = _workflow(workflow_name)
        hygiene_step = next(
            step
            for step in workflow["jobs"][job_name]["steps"]
            if step.get("name") == "Reject tracked secrets and local environment files"
        )
        command = hygiene_step["run"]

        assert "git ls-files" in command
        assert "git grep -I -q -E" in command
        assert ":(exclude)tests/**" not in command
        assert "PRIVATE KEY" in command
        assert "github_pat_" in command
        assert "gh[pousr]_" in command


def test_external_github_actions_are_pinned_to_immutable_commits():
    action_references: list[str] = []
    for document in (
        _action(),
        _workflow("ci.yml"),
        _workflow("release-validation.yml"),
    ):
        pending = [document]
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
            elif isinstance(value, str) and value.startswith("actions/"):
                action_references.append(value)

    assert action_references
    assert all(
        re.fullmatch(r"actions/[^@]+@[0-9a-f]{40}", item) for item in action_references
    )

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Iterable

import pytest


@pytest.fixture
def mutation_rule() -> dict[str, Any]:
    """A valid rule deliberately containing a site for every core operator."""
    return {
        "title": "PowerShell encoded command",
        "id": "11111111-1111-4111-8111-111111111111",
        "status": "experimental",
        "logsource": {
            "category": "process_creation",
            "product": "windows",
        },
        "detection": {
            "selection_main": {
                "Image|endswith": [
                    "\\powershell.exe",
                    "\\pwsh.exe",
                ],
                "CommandLine|contains": [
                    "-EncodedCommand",
                    "-enc",
                ],
                "User|startswith": "DOMAIN\\",
            },
            "filter_system": {
                "User": "NT AUTHORITY\\SYSTEM",
            },
            "condition": "selection_main and not filter_system",
        },
        "level": "high",
    }


@pytest.fixture
def pristine_mutation_rule(mutation_rule: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(mutation_rule)


def write_suite(
    root: Path,
    *,
    events: Iterable[dict[str, Any]],
    expected: Iterable[bool],
    fail_under: float = 0.0,
) -> Path:
    """Write a self-contained rule/fixture/suite triple for integration tests."""
    rule_path = root / "rule.yml"
    fixtures_path = root / "fixtures.jsonl"
    suite_path = root / "suite.yml"

    rule_path.write_text(
        """\
title: PowerShell encoded command
id: 22222222-2222-4222-8222-222222222222
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_main:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc'
    User|startswith: 'DOMAIN\\'
  filter_system:
    User: 'NT AUTHORITY\\SYSTEM'
  condition: selection_main and not filter_system
level: high
""",
        encoding="utf-8",
    )

    fixture_lines = []
    for index, (event, outcome) in enumerate(
        zip(events, expected, strict=True), start=1
    ):
        fixture_lines.append(
            json.dumps(
                {
                    "id": f"fixture-{index}",
                    "expected": outcome,
                    "event": event,
                },
                sort_keys=True,
            )
        )
    fixtures_path.write_text("\n".join(fixture_lines) + "\n", encoding="utf-8")

    suite_path.write_text(
        f"""\
version: 1
rule: {rule_path.name}
fixtures: {fixtures_path.name}
fail_under: {fail_under}
""",
        encoding="utf-8",
    )
    return suite_path


@pytest.fixture
def weak_suite(tmp_path: Path) -> Path:
    return write_suite(
        tmp_path,
        events=[
            {
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": "powershell.exe -EncodedCommand AAAA",
                "User": r"DOMAIN\alice",
            },
            {
                "Image": r"C:\Windows\System32\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "User": r"DOMAIN\alice",
            },
        ],
        expected=[True, False],
    )


@pytest.fixture
def broken_baseline_suite(tmp_path: Path) -> Path:
    return write_suite(
        tmp_path,
        events=[
            {
                "Image": r"C:\Windows\System32\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "User": r"DOMAIN\alice",
            },
            {
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": "powershell.exe -EncodedCommand AAAA",
                "User": r"DOMAIN\alice",
            },
        ],
        # Both labels intentionally contradict the baseline rule.
        expected=[True, False],
    )


@pytest.fixture
def no_mutation_suite(tmp_path: Path) -> Path:
    """A valid baseline whose rule has no supported mutation points."""

    rule_path = tmp_path / "exact-rule.yml"
    fixtures_path = tmp_path / "exact-fixtures.jsonl"
    suite_path = tmp_path / "exact-suite.yml"
    rule_path.write_text(
        """\
title: Exact action
id: 33333333-3333-4333-8333-333333333333
status: experimental
logsource:
  category: application
detection:
  selection:
    Action: allow
  condition: selection
level: low
""",
        encoding="utf-8",
    )
    fixtures_path.write_text(
        "\n".join(
            (
                json.dumps(
                    {"id": "allow", "expected": True, "event": {"Action": "allow"}}
                ),
                json.dumps(
                    {"id": "deny", "expected": False, "event": {"Action": "deny"}}
                ),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    suite_path.write_text(
        """\
version: 1
rule: exact-rule.yml
fixtures: exact-fixtures.jsonl
fail_under: 0.80
""",
        encoding="utf-8",
    )
    return suite_path

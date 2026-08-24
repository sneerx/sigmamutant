from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from sigmamutant.errors import RuleError
from sigmamutant.evaluator import SigmaEvaluator


def _matching_event() -> dict[str, Any]:
    return {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -EncodedCommand AAAA",
        "User": r"DOMAIN\alice",
    }


def test_evaluator_matches_positive_and_rejects_negative_events(
    mutation_rule: dict[str, Any],
) -> None:
    evaluator = SigmaEvaluator()

    assert evaluator.matches(mutation_rule, _matching_event()) is True
    assert (
        evaluator.matches(
            mutation_rule,
            {
                "Image": r"C:\Windows\System32\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "User": r"DOMAIN\alice",
            },
        )
        is False
    )


def test_evaluator_honors_not_filter(
    mutation_rule: dict[str, Any],
) -> None:
    evaluator = SigmaEvaluator()
    filtered = _matching_event()
    filtered["User"] = r"NT AUTHORITY\SYSTEM"

    assert evaluator.matches(mutation_rule, filtered) is False


def test_validate_rule_does_not_mutate_input(
    mutation_rule: dict[str, Any],
) -> None:
    evaluator = SigmaEvaluator()
    before = copy.deepcopy(mutation_rule)

    evaluator.validate_rule(mutation_rule)

    assert mutation_rule == before


def test_unsupported_correlation_fails_closed() -> None:
    evaluator = SigmaEvaluator()
    correlation_rule = {
        "title": "Unsupported correlation",
        "logsource": {"category": "process_creation"},
        "correlation": {
            "type": "event_count",
            "rules": ["some-rule"],
            "group-by": ["User"],
            "timespan": "5m",
            "condition": {"gte": 3},
        },
    }

    with pytest.raises(Exception):
        evaluator.validate_rule(correlation_rule)


def test_event_strings_are_data_and_are_never_executed(
    mutation_rule: dict[str, Any],
    tmp_path: Path,
) -> None:
    evaluator = SigmaEvaluator()
    sentinel = tmp_path / "must-not-exist"
    event = _matching_event()
    event["CommandLine"] = f"powershell.exe -EncodedCommand AAAA; touch {sentinel}"

    evaluator.matches(mutation_rule, event)

    assert not sentinel.exists()


def test_pathological_regex_is_rejected_before_azuma_compilation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from azuma import Rule

    backend_called = False

    def forbidden_backend(*args, **kwargs):
        nonlocal backend_called
        backend_called = True
        raise AssertionError("unsupported regex must not reach Azuma")

    monkeypatch.setattr(Rule, "model_validate_yaml", forbidden_backend)
    rule = {
        "title": "Pathological regex",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"Field|re": r"^(a+)+$"},
            "condition": "selection",
        },
    }

    with pytest.raises(RuleError, match=r"unsupported modifier\(s\): re"):
        SigmaEvaluator().matches(rule, {"Field": "a" * 20_000 + "!"})

    assert backend_called is False

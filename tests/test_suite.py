from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import write_suite

from sigmamutant.errors import SuiteError
from sigmamutant.suite import load_suite

POSITIVE_EVENT = {
    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "CommandLine": "powershell.exe -EncodedCommand AAAA",
    "User": r"DOMAIN\alice",
}
NEGATIVE_EVENT = {
    "Image": r"C:\Windows\System32\cmd.exe",
    "CommandLine": "cmd.exe /c whoami",
    "User": r"DOMAIN\alice",
}


def test_load_suite_resolves_relative_paths_and_loads_jsonl(
    tmp_path: Path,
) -> None:
    suite_path = write_suite(
        tmp_path,
        events=[POSITIVE_EVENT, NEGATIVE_EVENT],
        expected=[True, False],
        fail_under=0.75,
    )

    loaded = load_suite(suite_path)

    assert len(loaded.fixtures) == 2
    assert [fixture.id for fixture in loaded.fixtures] == [
        "fixture-1",
        "fixture-2",
    ]
    assert [fixture.expected for fixture in loaded.fixtures] == [True, False]
    assert loaded.config.fail_under == pytest.approx(0.75)
    assert loaded.rule_document["title"] == "PowerShell encoded command"
    assert loaded.suite_bytes == suite_path.read_bytes()
    assert loaded.fixtures_bytes == (tmp_path / "fixtures.jsonl").read_bytes()


def test_load_suite_rejects_duplicate_fixture_ids(tmp_path: Path) -> None:
    suite_path = write_suite(
        tmp_path,
        events=[POSITIVE_EVENT, NEGATIVE_EVENT],
        expected=[True, False],
    )
    fixtures_path = tmp_path / "fixtures.jsonl"
    lines = [json.loads(line) for line in fixtures_path.read_text().splitlines()]
    lines[1]["id"] = lines[0]["id"]
    fixtures_path.write_text(
        "\n".join(json.dumps(line) for line in lines) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(Exception):
        load_suite(suite_path)


@pytest.mark.parametrize("expected", [[True, True], [False, False]])
def test_load_suite_requires_positive_and_negative_expectations(
    tmp_path: Path,
    expected: list[bool],
) -> None:
    suite_path = write_suite(
        tmp_path,
        events=[POSITIVE_EVENT, NEGATIVE_EVENT],
        expected=expected,
    )

    with pytest.raises(Exception):
        load_suite(suite_path)


def test_load_suite_rejects_fixture_without_event(tmp_path: Path) -> None:
    suite_path = write_suite(
        tmp_path,
        events=[POSITIVE_EVENT, NEGATIVE_EVENT],
        expected=[True, False],
    )
    fixtures_path = tmp_path / "fixtures.jsonl"
    fixtures_path.write_text(
        "\n".join(
            [
                json.dumps({"id": "missing-event", "expected": True}),
                json.dumps(
                    {
                        "id": "negative",
                        "expected": False,
                        "event": NEGATIVE_EVENT,
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(Exception):
        load_suite(suite_path)


@pytest.mark.parametrize(
    ("invalid_line", "message"),
    [
        (
            '{"id":"duplicate","id":"shadowed","expected":true,"event":{}}',
            "duplicate object key 'id'",
        ),
        (
            '{"id":"duplicate-event","expected":true,'
            '"event":{"Image":"one","Image":"two"}}',
            "duplicate object key 'Image'",
        ),
        (
            '{"id":"non-finite","expected":true,"event":{"Score":NaN}}',
            "non-standard numeric constant 'NaN'",
        ),
    ],
)
def test_load_suite_rejects_ambiguous_or_nonstandard_json(
    tmp_path: Path,
    invalid_line: str,
    message: str,
) -> None:
    suite_path = write_suite(
        tmp_path,
        events=[POSITIVE_EVENT, NEGATIVE_EVENT],
        expected=[True, False],
    )
    fixtures_path = tmp_path / "fixtures.jsonl"
    negative = json.dumps(
        {"id": "negative", "expected": False, "event": NEGATIVE_EVENT}
    )
    fixtures_path.write_text(f"{invalid_line}\n{negative}\n", encoding="utf-8")

    with pytest.raises(SuiteError, match=message):
        load_suite(suite_path)


def test_load_suite_rejects_absolute_child_path(tmp_path: Path) -> None:
    suite_path = write_suite(
        tmp_path,
        events=[POSITIVE_EVENT, NEGATIVE_EVENT],
        expected=[True, False],
    )
    absolute_rule = (tmp_path / "rule.yml").resolve()
    suite_path.write_text(
        "\n".join(
            [
                "version: 1",
                f"rule: {absolute_rule}",
                "fixtures: fixtures.jsonl",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(SuiteError, match="must be relative"):
        load_suite(suite_path)


def test_load_suite_rejects_parent_traversal_even_when_target_exists(
    tmp_path: Path,
) -> None:
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    suite_path = write_suite(
        suite_dir,
        events=[POSITIVE_EVENT, NEGATIVE_EVENT],
        expected=[True, False],
    )
    outside_rule = tmp_path / "outside-rule.yml"
    outside_rule.write_bytes((suite_dir / "rule.yml").read_bytes())
    suite_path.write_text(
        "\n".join(
            [
                "version: 1",
                "rule: ../outside-rule.yml",
                "fixtures: fixtures.jsonl",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(SuiteError, match="parent traversal"):
        load_suite(suite_path)


def test_load_suite_rejects_symlink_escape(tmp_path: Path) -> None:
    suite_dir = tmp_path / "suite"
    suite_dir.mkdir()
    suite_path = write_suite(
        suite_dir,
        events=[POSITIVE_EVENT, NEGATIVE_EVENT],
        expected=[True, False],
    )
    outside_rule = tmp_path / "outside-rule.yml"
    outside_rule.write_bytes((suite_dir / "rule.yml").read_bytes())
    linked_rule = suite_dir / "linked-rule.yml"
    try:
        linked_rule.symlink_to(outside_rule)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    suite_path.write_text(
        "\n".join(
            [
                "version: 1",
                "rule: linked-rule.yml",
                "fixtures: fixtures.jsonl",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(SuiteError, match="outside the suite directory"):
        load_suite(suite_path)

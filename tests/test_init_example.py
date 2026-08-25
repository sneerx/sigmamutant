from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from sigmamutant.cli import app
from sigmamutant.example_project import EXAMPLE_FILES
from sigmamutant.gap_runner import run_gap_analysis
from sigmamutant.runner import run_suite, validate_suite

runner = CliRunner()
REPOSITORY = Path(__file__).resolve().parents[1]


def test_init_example_creates_canonical_runnable_project(tmp_path: Path) -> None:
    destination = tmp_path / "my example"

    result = runner.invoke(app, ["init-example", str(destination)])

    assert result.exit_code == 0, result.output
    assert "Created self-contained example" in result.output
    assert "weak run intentionally exits 1" in result.output
    assert "sigmamutant gap" in result.output
    assert "powershell-gap.yml" in result.output
    assert "powershell-hardened-gap.yml" in result.output
    assert "OPENAI_API_KEY" not in result.output
    assert sorted(
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
        if path.is_file()
    ) == sorted(EXAMPLE_FILES)
    for relative_name in EXAMPLE_FILES:
        assert (destination / relative_name).read_bytes() == (
            REPOSITORY / "examples" / relative_name
        ).read_bytes()

    weak = destination / "weak-suite.yml"
    strong = destination / "strong-suite.yml"
    weak_gap = destination / "powershell-gap.yml"
    hardened_gap = destination / "powershell-hardened-gap.yml"
    assert validate_suite(weak).passed is True
    assert validate_suite(strong).passed is True
    assert validate_suite(weak_gap).passed is True
    assert validate_suite(hardened_gap).passed is True
    assert run_suite(weak).passed is False
    assert run_suite(strong).passed is True
    assert run_gap_analysis(weak_gap).passed is False
    assert run_gap_analysis(hardened_gap).passed is True


@pytest.mark.parametrize("kind", ("directory", "file"))
def test_init_example_refuses_existing_destination_without_changes(
    tmp_path: Path,
    kind: str,
) -> None:
    destination = tmp_path / "existing"
    if kind == "directory":
        destination.mkdir()
        marker = destination / "keep.txt"
    else:
        marker = destination
    marker.write_text("keep\n", encoding="utf-8")

    result = runner.invoke(app, ["init-example", str(destination)])

    assert result.exit_code == 2
    assert "Refusing to overwrite existing example destination" in result.output
    assert marker.read_text(encoding="utf-8") == "keep\n"
    if kind == "directory":
        assert list(destination.iterdir()) == [marker]


def test_init_example_rejects_symlink_parent(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    result = runner.invoke(app, ["init-example", str(linked / "example")])

    assert result.exit_code == 2
    assert "symlink component" in result.output
    assert list(outside.iterdir()) == []


def test_init_example_rejects_nonportable_existing_alias(tmp_path: Path) -> None:
    existing = tmp_path / "Example"
    existing.mkdir()

    result = runner.invoke(app, ["init-example", str(tmp_path / "example")])

    assert result.exit_code == 2
    assert (
        "differs only by case" in result.output
        or "Refusing to overwrite" in result.output
    )
    assert list(existing.iterdir()) == []

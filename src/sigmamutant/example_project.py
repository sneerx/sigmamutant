"""Create a self-contained example project from bundled package data."""

from __future__ import annotations

import os
from importlib import resources
from pathlib import Path, PurePosixPath

from sigmamutant.errors import ExampleInitializationError
from sigmamutant.reporting._common import (
    reject_portable_path_alias,
    reject_symlink_components,
)

EXAMPLE_FILES = (
    "rules/powershell_encoded.yml",
    "rules/powershell_encoded_hardened.yml",
    "fixtures/weak.jsonl",
    "fixtures/strong.jsonl",
    "fixtures/gap.jsonl",
    "weak-suite.yml",
    "strong-suite.yml",
    "powershell-gap.yml",
    "powershell-hardened-gap.yml",
)


def _resource_bytes(relative_name: str) -> bytes:
    """Read one example file from a wheel, with a source-tree development fallback."""

    relative = PurePosixPath(relative_name)
    packaged = resources.files("sigmamutant").joinpath("_example_data", *relative.parts)
    try:
        return packaged.read_bytes()
    except FileNotFoundError:
        # Editable installs use the canonical repository examples directly. Wheels
        # receive the same files through Hatch's force-include configuration.
        source = Path(__file__).resolve().parents[2] / "examples"
        try:
            return source.joinpath(*relative.parts).read_bytes()
        except FileNotFoundError as exc:
            raise ExampleInitializationError(
                f"Installed package is missing bundled example file: {relative_name}"
            ) from exc


def _absolute_without_resolving(path: str | Path) -> Path:
    """Normalize a destination without following symlinks."""

    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _preflight_destination(destination: Path) -> None:
    reject_symlink_components(
        destination,
        error_type=ExampleInitializationError,
        label="example destination",
    )
    reject_portable_path_alias(
        destination,
        error_type=ExampleInitializationError,
        label="example destination",
    )
    try:
        destination.lstat()
    except FileNotFoundError:
        return
    raise ExampleInitializationError(
        f"Refusing to overwrite existing example destination: {destination}"
    )


def initialize_example(destination: str | Path) -> Path:
    """Create deterministic mutation and event-gap examples."""

    output = _absolute_without_resolving(destination)
    payloads = tuple((name, _resource_bytes(name)) for name in EXAMPLE_FILES)

    _preflight_destination(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    _preflight_destination(output)
    try:
        output.mkdir()
    except FileExistsError as exc:
        raise ExampleInitializationError(
            f"Refusing to overwrite existing example destination: {output}"
        ) from exc

    for relative_name, content in payloads:
        relative = PurePosixPath(relative_name)
        target = output.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        reject_symlink_components(
            target,
            error_type=ExampleInitializationError,
            label="example file",
        )
        try:
            with target.open("xb") as handle:
                handle.write(content)
        except FileExistsError as exc:
            raise ExampleInitializationError(
                f"Refusing to overwrite existing example file: {target}"
            ) from exc
    return output

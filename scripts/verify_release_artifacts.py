#!/usr/bin/env python3
"""Fail closed when a release directory contains stale or mismatched archives."""

from __future__ import annotations

import argparse
import email
import re
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

MAX_METADATA_BYTES = 1_000_000


class ArtifactValidationError(ValueError):
    """Raised when built release artifacts do not match project metadata."""


def _project_identity(pyproject_path: Path) -> tuple[str, str]:
    with pyproject_path.open("rb") as handle:
        project = tomllib.load(handle)["project"]
    return str(project["name"]), str(project["version"])


def _metadata_identity(payload: bytes, *, archive: Path) -> tuple[str, str]:
    if len(payload) > MAX_METADATA_BYTES:
        raise ArtifactValidationError(
            f"{archive.name}: package metadata exceeds {MAX_METADATA_BYTES} bytes"
        )
    message = email.message_from_bytes(payload)
    name = message.get("Name")
    version = message.get("Version")
    if not name or not version:
        raise ArtifactValidationError(
            f"{archive.name}: package metadata is missing Name or Version"
        )
    return name, version


def _wheel_identity(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as archive:
        metadata_files = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_files) != 1:
            raise ArtifactValidationError(
                f"{path.name}: expected one .dist-info/METADATA file, "
                f"found {len(metadata_files)}"
            )
        info = archive.getinfo(metadata_files[0])
        if info.file_size > MAX_METADATA_BYTES:
            raise ArtifactValidationError(
                f"{path.name}: package metadata exceeds {MAX_METADATA_BYTES} bytes"
            )
        return _metadata_identity(archive.read(info), archive=path)


def _sdist_identity(path: Path) -> tuple[str, str]:
    with tarfile.open(path, mode="r:gz") as archive:
        metadata_files = [
            member
            for member in archive.getmembers()
            if member.isfile()
            and member.name.count("/") == 1
            and member.name.endswith("/PKG-INFO")
        ]
        if len(metadata_files) != 1:
            raise ArtifactValidationError(
                f"{path.name}: expected one top-level PKG-INFO file, "
                f"found {len(metadata_files)}"
            )
        member = metadata_files[0]
        if member.size > MAX_METADATA_BYTES:
            raise ArtifactValidationError(
                f"{path.name}: package metadata exceeds {MAX_METADATA_BYTES} bytes"
            )
        extracted = archive.extractfile(member)
        if extracted is None:
            raise ArtifactValidationError(f"{path.name}: could not read PKG-INFO")
        return _metadata_identity(extracted.read(), archive=path)


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def verify_release_artifacts(dist_dir: Path, pyproject_path: Path) -> None:
    """Verify that exactly one wheel and one sdist match project metadata."""

    if not dist_dir.is_dir():
        raise ArtifactValidationError(f"distribution directory not found: {dist_dir}")

    wheels = sorted(dist_dir.glob("*.whl"))
    sdists = sorted(dist_dir.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        archive_names = ", ".join(path.name for path in (*wheels, *sdists)) or "none"
        raise ArtifactValidationError(
            "expected exactly one wheel and one source archive; "
            f"found {len(wheels)} wheel(s) and {len(sdists)} source archive(s): "
            f"{archive_names}"
        )

    expected_name, expected_version = _project_identity(pyproject_path)
    expected = (_canonical_name(expected_name), expected_version)
    wheel_name = re.sub(r"[-_.]+", "_", expected_name).lower()
    wheel_version = expected_version.replace("-", "_")
    if not wheels[0].name.startswith(f"{wheel_name}-{wheel_version}-"):
        raise ArtifactValidationError(
            f"{wheels[0].name}: filename does not identify "
            f"{expected_name} {expected_version}"
        )
    expected_sdist_name = f"{expected_name.lower()}-{expected_version}.tar.gz"
    if sdists[0].name != expected_sdist_name:
        raise ArtifactValidationError(
            f"{sdists[0].name}: expected source archive name {expected_sdist_name}"
        )

    for archive, identity_reader in (
        (wheels[0], _wheel_identity),
        (sdists[0], _sdist_identity),
    ):
        actual_name, actual_version = identity_reader(archive)
        actual = (_canonical_name(actual_name), actual_version)
        if actual != expected:
            raise ArtifactValidationError(
                f"{archive.name}: metadata identifies {actual_name} {actual_version}; "
                f"expected {expected_name} {expected_version}"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--pyproject", type=Path, default=Path("pyproject.toml"))
    args = parser.parse_args(argv)

    try:
        verify_release_artifacts(args.dist, args.pyproject)
    except (
        ArtifactValidationError,
        OSError,
        KeyError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("release artifacts match project metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import io
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

from scripts.verify_release_artifacts import (
    ArtifactValidationError,
    verify_release_artifacts,
)
from sigmamutant import __version__

REPOSITORY = Path(__file__).resolve().parents[1]


def _project_metadata(path: Path = REPOSITORY / "pyproject.toml") -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)["project"]


def _write_pyproject(path: Path, *, version: str = "1.0.0") -> None:
    path.write_text(
        f'[project]\nname = "sigmamutant"\nversion = "{version}"\n',
        encoding="utf-8",
    )


def _write_archives(
    dist: Path,
    *,
    version: str = "1.0.0",
    filename_version: str | None = None,
) -> None:
    filename_version = filename_version or version
    metadata = (
        f"Metadata-Version: 2.4\nName: sigmamutant\nVersion: {version}\n\n"
    ).encode()

    wheel = dist / f"sigmamutant-{filename_version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(f"sigmamutant-{filename_version}.dist-info/METADATA", metadata)

    sdist = dist / f"sigmamutant-{filename_version}.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        info = tarfile.TarInfo(f"sigmamutant-{filename_version}/PKG-INFO")
        info.size = len(metadata)
        archive.addfile(info, io.BytesIO(metadata))


def test_runtime_version_matches_build_metadata():
    assert __version__ == _project_metadata()["version"]


def test_stable_major_release_uses_stable_classifier():
    project = _project_metadata()
    major = int(project["version"].split(".", maxsplit=1)[0])
    if major < 1:
        pytest.skip("pre-1.0 release")

    classifiers = set(project["classifiers"])
    assert "Development Status :: 5 - Production/Stable" in classifiers
    assert "Development Status :: 3 - Alpha" not in classifiers
    assert "Development Status :: 4 - Beta" not in classifiers


def test_release_artifacts_must_be_unique_and_match_project(tmp_path: Path):
    dist = tmp_path / "dist"
    dist.mkdir()
    pyproject = tmp_path / "pyproject.toml"
    _write_pyproject(pyproject)
    _write_archives(dist)

    verify_release_artifacts(dist, pyproject)

    (dist / "sigmamutant-1.0.1-py3-none-any.whl").touch()
    with pytest.raises(ArtifactValidationError, match="exactly one wheel"):
        verify_release_artifacts(dist, pyproject)


def test_release_artifact_metadata_must_match_project(tmp_path: Path):
    dist = tmp_path / "dist"
    dist.mkdir()
    pyproject = tmp_path / "pyproject.toml"
    _write_pyproject(pyproject, version="1.0.0")
    _write_archives(dist, version="1.0.1", filename_version="1.0.0")

    with pytest.raises(ArtifactValidationError, match="expected sigmamutant 1.0.0"):
        verify_release_artifacts(dist, pyproject)


def test_release_artifact_filenames_must_match_project(tmp_path: Path):
    dist = tmp_path / "dist"
    dist.mkdir()
    pyproject = tmp_path / "pyproject.toml"
    _write_pyproject(pyproject)
    _write_archives(dist)
    wheel = next(dist.glob("*.whl"))
    wheel.rename(dist / "other-1.0.0-py3-none-any.whl")

    with pytest.raises(ArtifactValidationError, match="filename does not identify"):
        verify_release_artifacts(dist, pyproject)

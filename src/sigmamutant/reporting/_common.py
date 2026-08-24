from __future__ import annotations

import dataclasses
import difflib
import enum
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from sigmamutant.errors import SigmaMutantError

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def get_field(value: Any, name: str, default: Any = None) -> Any:
    """Read a model field without coupling reporting to a model framework."""

    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def enum_value(value: Any) -> Any:
    if isinstance(value, enum.Enum):
        return value.value
    return value


def status_value(value: Any) -> str:
    value = enum_value(value)
    if value is None:
        return "unknown"
    return str(value).strip().lower().replace("_", "-")


def is_status(value: Any, expected: str) -> bool:
    status = status_value(value)
    expected = expected.lower().replace("_", "-")
    return status == expected or status.endswith(f".{expected}")


def _sort_key(value: Any) -> str:
    return json.dumps(
        to_primitive(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def to_primitive(value: Any, *, _seen: set[int] | None = None) -> Any:
    """Convert common model values into deterministic JSON-compatible data."""

    if value is None or isinstance(value, (str, bool, int)):
        return value

    if isinstance(value, float):
        if math.isfinite(value):
            return value
        return str(value)

    if isinstance(value, Decimal):
        return float(value) if value.is_finite() else str(value)

    if isinstance(value, enum.Enum):
        return to_primitive(value.value, _seen=_seen)

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return {
                "encoding": "hex",
                "sha256": hashlib.sha256(value).hexdigest(),
                "value": value.hex(),
            }

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if _seen is None:
        _seen = set()

    object_id = id(value)
    if object_id in _seen:
        return "<recursive>"

    if isinstance(value, Mapping):
        _seen.add(object_id)
        try:
            return {
                str(key): to_primitive(item, _seen=_seen)
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            }
        finally:
            _seen.remove(object_id)

    if isinstance(value, (set, frozenset)):
        _seen.add(object_id)
        try:
            converted = [to_primitive(item, _seen=_seen) for item in value]
            return sorted(converted, key=_sort_key)
        finally:
            _seen.remove(object_id)

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        _seen.add(object_id)
        try:
            return [to_primitive(item, _seen=_seen) for item in value]
        finally:
            _seen.remove(object_id)

    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        _seen.add(object_id)
        try:
            try:
                dumped = model_dump(mode="python")
            except TypeError:
                dumped = model_dump()
            return to_primitive(dumped, _seen=_seen)
        finally:
            _seen.remove(object_id)

    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        _seen.add(object_id)
        try:
            return {
                field.name: to_primitive(getattr(value, field.name), _seen=_seen)
                for field in dataclasses.fields(value)
            }
        finally:
            _seen.remove(object_id)

    attributes = getattr(value, "__dict__", None)
    if isinstance(attributes, Mapping):
        public = {
            key: item
            for key, item in attributes.items()
            if not key.startswith("_") and not callable(item)
        }
        if public:
            return to_primitive(public, _seen=_seen)

    slots = getattr(type(value), "__slots__", ())
    if isinstance(slots, str):
        slots = (slots,)
    public_slots = {
        slot: getattr(value, slot)
        for slot in slots
        if not slot.startswith("_") and hasattr(value, slot)
    }
    if public_slots:
        return to_primitive(public_slots, _seen=_seen)

    # Avoid unstable default repr strings containing memory addresses.
    return f"<{type(value).__module__}.{type(value).__qualname__}>"


def json_text(value: Any) -> str:
    return (
        json.dumps(
            to_primitive(value),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _lexical_absolute(path: str | Path) -> Path:
    """Return an absolute path without resolving filesystem symlinks."""

    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _trusted_system_symlink(path: Path) -> bool:
    """Allow immutable root-owned aliases such as macOS /tmp -> private/tmp."""

    trusted_darwin_aliases = {
        Path("/tmp"): Path("/private/tmp"),
        Path("/var"): Path("/private/var"),
    }
    absolute = _lexical_absolute(path)
    expected_target = trusted_darwin_aliases.get(absolute)
    if sys.platform != "darwin" or expected_target is None:
        return False
    try:
        metadata = path.lstat()
        parent_metadata = path.parent.stat()
        target_metadata = expected_target.stat()
    except OSError:
        return False
    return (
        stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid == 0
        and parent_metadata.st_uid == 0
        and not parent_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        and absolute.resolve() == expected_target
        and stat.S_ISDIR(target_metadata.st_mode)
        and target_metadata.st_uid == 0
    )


def paths_refer_to_same_file(first: str | Path, second: str | Path) -> bool:
    """Compare path identity, including aliases on case-insensitive filesystems."""

    first_path = _lexical_absolute(first)
    second_path = _lexical_absolute(second)
    if first_path == second_path:
        return True
    try:
        if first_path.resolve() == second_path.resolve():
            return True
    except (FileNotFoundError, NotADirectoryError):
        pass
    try:
        return os.path.samefile(first_path, second_path)
    except (FileNotFoundError, NotADirectoryError, ValueError):
        return False


def portable_namespace_key(value: str | Path) -> str:
    """Normalize names for deterministic cross-platform collision checks."""

    return unicodedata.normalize("NFC", os.fspath(value)).casefold()


def reject_portable_path_alias(
    destination: str | Path,
    *,
    error_type: type[Exception] = SigmaMutantError,
    label: str = "output path",
) -> Path:
    """Reject an existing sibling whose spelling is non-portably equivalent."""

    path = Path(destination).expanduser()
    absolute = _lexical_absolute(path)
    for component in reversed((absolute, *absolute.parents)):
        if component == component.parent or not component.parent.is_dir():
            continue
        desired_key = portable_namespace_key(component.name)
        with os.scandir(component.parent) as entries:
            for entry in entries:
                if entry.name == component.name:
                    continue
                if portable_namespace_key(entry.name) == desired_key:
                    raise error_type(
                        f"Refusing {label}; existing path differs only by case or "
                        f"Unicode normalization: {component.parent / entry.name}"
                    )
    return path


def reject_hardlinked_output(
    destination: str | Path,
    *,
    error_type: type[Exception] = SigmaMutantError,
    label: str = "output path",
) -> Path:
    """Reject replacing a regular file that has another filesystem name."""

    path = Path(destination).expanduser()
    try:
        metadata = path.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return path
    if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink > 1:
        raise error_type(f"Refusing hardlinked {label}: {_lexical_absolute(path)}")
    return path


def reject_protected_path(
    destination: str | Path,
    protected_paths: tuple[Path, ...],
    *,
    error_type: type[Exception] = SigmaMutantError,
) -> Path:
    """Reject a destination that resolves to any protected input identity."""

    path = Path(destination).expanduser()
    if any(paths_refer_to_same_file(path, protected) for protected in protected_paths):
        raise error_type(
            f"Refusing to overwrite SigmaMutant input file: {_lexical_absolute(path)}"
        )
    return path


def preflight_output_file(
    destination: str | Path,
    *,
    protected_paths: tuple[Path, ...] = (),
    error_type: type[Exception] = SigmaMutantError,
    label: str = "output path",
) -> Path:
    """Apply every filesystem guard required before an atomic file replace."""

    path = reject_symlink_components(
        destination,
        error_type=error_type,
        label=label,
    )
    reject_protected_path(path, protected_paths, error_type=error_type)
    reject_portable_path_alias(path, error_type=error_type, label=label)
    reject_hardlinked_output(path, error_type=error_type, label=label)
    return path


def suite_input_paths(suite: Any) -> tuple[Path, ...]:
    """Return concrete suite/rule/fixture paths exposed by a loaded suite."""

    return tuple(
        Path(candidate)
        for field in ("path", "rule_path", "fixtures_path")
        if (candidate := get_field(suite, field)) not in (None, "")
    )


def _path_is_within(path: Path, directory: Path) -> bool:
    candidates = (
        (_lexical_absolute(path), _lexical_absolute(directory)),
        (path.resolve(), directory.resolve()),
    )
    for candidate, parent in candidates:
        try:
            candidate.relative_to(parent)
        except ValueError:
            continue
        return True
    if directory.exists():
        return any(
            paths_refer_to_same_file(ancestor, directory)
            for ancestor in (path, *path.parents)
        )
    return False


def reject_symlink_components(
    path: str | Path,
    *,
    error_type: type[Exception] = SigmaMutantError,
    label: str = "output path",
) -> Path:
    """Reject every existing symlink component without following the path."""

    candidate = Path(path).expanduser()
    absolute = _lexical_absolute(candidate)
    components = (absolute, *absolute.parents)
    for component in reversed(components):
        if component.is_symlink() and not _trusted_system_symlink(component):
            raise error_type(f"Refusing {label} with symlink component: {component}")
    return candidate


def preflight_managed_paths(
    output_dir: str | Path,
    *,
    filenames: tuple[str, ...] = (),
    subdirectories: tuple[str, ...] = (),
    protected_paths: tuple[Path, ...] = (),
) -> Path:
    """Validate a tool-managed output namespace before writing any file."""

    output = reject_symlink_components(output_dir, label="artifact directory")
    if output.exists() and not output.is_dir():
        raise SigmaMutantError(
            f"Artifact output must be a directory: {_lexical_absolute(output)}"
        )

    managed_subdirs: list[Path] = []
    for name in subdirectories:
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise SigmaMutantError(f"Invalid managed subdirectory: {name!r}")
        subdirectory = output / relative
        reject_symlink_components(
            subdirectory,
            label="managed artifact directory",
        )
        if subdirectory.exists() and not subdirectory.is_dir():
            raise SigmaMutantError(
                f"Managed artifact path must be a directory: "
                f"{_lexical_absolute(subdirectory)}"
            )
        managed_subdirs.append(_lexical_absolute(subdirectory))

    destinations: list[Path] = []
    for name in filenames:
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise SigmaMutantError(f"Invalid managed artifact filename: {name!r}")
        destination = output / relative
        preflight_output_file(
            destination,
            protected_paths=protected_paths,
            label="managed artifact path",
        )
        if destination.exists() and not destination.is_file():
            raise SigmaMutantError(
                f"Managed artifact path must be a regular file: "
                f"{_lexical_absolute(destination)}"
            )
        destinations.append(_lexical_absolute(destination))

    for protected_path in protected_paths:
        for subdirectory in managed_subdirs:
            if _path_is_within(Path(protected_path), subdirectory):
                raise SigmaMutantError(
                    "Refusing to manage an artifact directory containing a "
                    f"SigmaMutant input file: {protected_path}"
                )
    return output


def ensure_output_dir(output_dir: str | Path) -> Path:
    path = reject_symlink_components(output_dir, label="artifact directory")
    path.mkdir(parents=True, exist_ok=True)
    reject_symlink_components(path, label="artifact directory")
    if not path.is_dir():
        raise SigmaMutantError(
            f"Artifact output must be a directory: {_lexical_absolute(path)}"
        )
    return path


def write_text(
    path: Path,
    content: str,
    *,
    protected_paths: tuple[Path, ...] = (),
) -> Path:
    path = Path(path).expanduser()
    if not content.endswith("\n"):
        content += "\n"
    preflight_output_file(
        path,
        protected_paths=protected_paths,
        label="artifact destination",
    )
    parent = ensure_output_dir(path.parent)
    destination = parent / path.name
    preflight_output_file(
        destination,
        protected_paths=protected_paths,
        label="artifact destination",
    )
    mode = 0o644
    if destination.exists():
        metadata = destination.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise SigmaMutantError(
                f"Artifact destination must be a regular file: "
                f"{_lexical_absolute(destination)}"
            )
        mode = stat.S_IMODE(metadata.st_mode)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=parent,
    )
    temporary = Path(temporary_name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        else:
            os.chmod(temporary, mode)
        handle = os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        )
        descriptor = -1
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        preflight_output_file(
            destination,
            protected_paths=protected_paths,
            label="artifact destination",
        )
        if destination.exists() and not destination.is_file():
            raise SigmaMutantError(
                f"Artifact destination must be a regular file: "
                f"{_lexical_absolute(destination)}"
            )
        os.replace(temporary, destination)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    return path


def mutant_identity(mutant: Any, index: int) -> str:
    for field in ("id", "mutant_id", "name", "key"):
        candidate = get_field(mutant, field)
        if candidate not in (None, ""):
            return str(enum_value(candidate))

    operator = get_field(mutant, "operator")
    if operator not in (None, ""):
        operator_name = get_field(operator, "name", enum_value(operator))
        return f"{operator_name}-{index:04d}"

    return f"mutant-{index:04d}"


def mutant_operator(mutant: Any) -> str:
    operator = get_field(mutant, "operator")
    if operator is None:
        return ""
    name = get_field(operator, "name")
    return str(enum_value(name if name is not None else operator))


def mutant_description(mutant: Any) -> str:
    for field in ("description", "summary", "label"):
        candidate = get_field(mutant, field)
        if candidate not in (None, ""):
            return str(candidate)
    return ""


def safe_stem(value: str, fallback: str = "mutant") -> str:
    stem = _SAFE_NAME_RE.sub("-", value.strip()).strip(".-_")
    return stem[:120] or fallback


def result_payload(result: Any, suite: Any) -> dict[str, Any]:
    mutant_results = get_field(result, "mutant_results", ()) or ()

    serialized_results: list[dict[str, Any]] = []
    for index, mutant_result in enumerate(mutant_results, start=1):
        mutant = get_field(mutant_result, "mutant")
        killed_by = get_field(mutant_result, "killed_by", ()) or ()
        observations = get_field(mutant_result, "observations", ()) or ()
        serialized_results.append(
            {
                "id": mutant_identity(mutant, index),
                "operator": mutant_operator(mutant),
                "description": mutant_description(mutant),
                "status": status_value(get_field(mutant_result, "status")),
                "reason": to_primitive(get_field(mutant_result, "reason")),
                "killed_by": to_primitive(killed_by),
                "observations": to_primitive(observations),
                "mutant": to_primitive(mutant),
            }
        )
    serialized_results.sort(key=lambda item: item["id"])

    errors = get_field(result, "errors", ()) or ()
    fixtures = get_field(suite, "fixtures", ()) or ()
    config = get_field(suite, "config", {}) or {}
    suite_path = get_field(suite, "path")
    rule_path = get_field(suite, "rule_path")
    fixtures_path = get_field(suite, "fixtures_path")

    # Reports are evidence artifacts and must remain byte-identical when the
    # same suite is checked out in a different workspace. Preserve the suite
    # filename and its config-relative child paths, never resolved host paths.
    stable_suite_path = Path(suite_path).name if suite_path else None
    stable_rule_path = get_field(config, "rule")
    if stable_rule_path in (None, "") and rule_path:
        stable_rule_path = Path(rule_path).name
    stable_fixtures_path = get_field(config, "fixtures")
    if stable_fixtures_path in (None, "") and fixtures_path:
        stable_fixtures_path = Path(fixtures_path).name

    return {
        "schema_version": 1,
        "rule_title": get_field(result, "rule_title", ""),
        "baseline_passed": bool(get_field(result, "baseline_passed", False)),
        "score": to_primitive(get_field(result, "score", 0)),
        "killed": int(get_field(result, "killed", 0) or 0),
        "survived": int(get_field(result, "survived", 0) or 0),
        "excluded": int(get_field(result, "excluded", 0) or 0),
        "fixture_count": int(get_field(result, "fixture_count", len(fixtures)) or 0),
        "threshold": to_primitive(get_field(result, "threshold", 0)),
        "passed": bool(get_field(result, "passed", False)),
        "errors": to_primitive(errors),
        "metadata": to_primitive(get_field(result, "metadata", {}) or {}),
        "mutant_results": serialized_results,
        "suite": {
            "path": to_primitive(stable_suite_path),
            "rule_path": to_primitive(stable_rule_path),
            "fixtures_path": to_primitive(stable_fixtures_path),
            "config": to_primitive(config),
        },
    }


def bytes_from_candidate(value: Any) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    return None


def mutated_rule_bytes(mutant: Any) -> bytes | None:
    for field in (
        "mutated_rule_bytes",
        "mutated_bytes",
        "rule_bytes",
        "rendered_rule",
        "rule_yaml",
        "yaml",
        "source",
    ):
        candidate = bytes_from_candidate(get_field(mutant, field))
        if candidate is not None:
            return candidate

    for method_name in ("render", "to_yaml"):
        method = getattr(mutant, method_name, None)
        if callable(method):
            try:
                candidate = bytes_from_candidate(method())
            except TypeError:
                continue
            if candidate is not None:
                return candidate

    return None


def mutant_document(mutant: Any) -> Any:
    for field in (
        "mutated_rule",
        "mutated_document",
        "rule_doc",
        "document",
        "rule",
    ):
        candidate = get_field(mutant, field)
        if candidate is not None and not isinstance(candidate, (str, bytes, bytearray)):
            return candidate
    return None


def yaml_text(value: Any) -> str:
    primitive = to_primitive(value)
    try:
        import yaml
    except ImportError:
        # JSON is a valid YAML 1.2 document and remains deterministic.
        return json_text(primitive)

    return yaml.safe_dump(
        primitive,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
    )


def provided_diff(mutant: Any) -> str | None:
    for field in ("diff", "unified_diff", "patch"):
        candidate = get_field(mutant, field)
        if isinstance(candidate, bytes):
            return candidate.decode("utf-8", errors="replace")
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def unified_diff(
    original: bytes,
    mutated: bytes,
    *,
    original_name: str,
    mutated_name: str,
) -> str:
    original_text = original.decode("utf-8", errors="replace").splitlines()
    mutated_text = mutated.decode("utf-8", errors="replace").splitlines()
    lines = difflib.unified_diff(
        original_text,
        mutated_text,
        fromfile=original_name,
        tofile=mutated_name,
        lineterm="",
    )
    rendered = "\n".join(lines)
    return rendered + ("\n" if rendered else "")

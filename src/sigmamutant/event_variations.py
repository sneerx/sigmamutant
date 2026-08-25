"""Conservative, inert event variations for detection-gap discovery.

The operators in this module only rewrite event dictionaries in memory. They
never decode a payload, invoke a shell, start a process, or write an event back
to its source fixture file.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from sigmamutant.gap_models import EventVariation
from sigmamutant.models import Fixture


@dataclass(frozen=True, slots=True)
class EventOperator:
    name: str
    description: str


EVENT_OPERATORS: tuple[EventOperator, ...] = (
    EventOperator(
        "ascii_case",
        "Change ASCII letter case in one rule-referenced process-path field.",
    ),
    EventOperator(
        "command_line_whitespace",
        "Normalize or expand separators without changing CommandLine tokens.",
    ),
    EventOperator(
        "telemetry_path_to_basename",
        "Collapse one Image or ParentImage full path to its basename.",
    ),
    EventOperator(
        "pwsh_encoded_alias",
        "Replace a documented pwsh encoded-command parameter alias.",
    ),
)


@dataclass(frozen=True, slots=True)
class _Candidate:
    operator: str
    field: str
    description: str
    claim_scope: str
    original: Any
    replacement: Any
    event: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _Tokenization:
    token_spans: tuple[tuple[int, int], ...]
    separator_spans: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class _FieldReference:
    modifiers: frozenset[str]
    value: Any


_Generator = Callable[[dict[str, Any], Fixture], Iterable[_Candidate]]
_PWSH_ENCODED_ALIASES: tuple[str, ...] = ("-EncodedCommand", "-e", "-ec")
_PATH_FIELDS = frozenset({"Image", "ParentImage"})
_VALUE_SENSITIVE_STRING_MODIFIERS = frozenset(
    {"all", "cased", "contains", "endswith", "startswith", "windash"}
)
_PWSH_SAFE_PREFIX_SWITCHES = frozenset(
    {
        "-mta",
        "-noexit",
        "-nologo",
        "-noninteractive",
        "-noprofile",
        "-sta",
    }
)
_BASE64_TOKEN = re.compile(
    r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
)

DEFAULT_MAX_VARIATIONS = 4096


class EventVariationLimitError(ValueError):
    """The configured deterministic event-variation bound was exceeded."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")


def _rule_hash(document: dict[str, Any], rule_bytes: bytes | None) -> str:
    source = rule_bytes if rule_bytes is not None else _canonical(document)
    return hashlib.sha256(source).hexdigest()


def _variation_id(
    rule_hash: str,
    fixture: Fixture,
    candidate: _Candidate,
) -> str:
    pointer = "/" + candidate.field.replace("~", "~0").replace("/", "~1")
    identity = "\x1f".join(
        (
            rule_hash,
            hashlib.sha256(_canonical(fixture.id)).hexdigest(),
            hashlib.sha256(_canonical(fixture.event)).hexdigest(),
            candidate.operator,
            pointer,
            hashlib.sha256(_canonical(candidate.original)).hexdigest(),
            hashlib.sha256(_canonical(candidate.replacement)).hexdigest(),
            hashlib.sha256(_canonical(candidate.event)).hexdigest(),
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def _rule_field_references(
    document: dict[str, Any],
) -> dict[str, list[_FieldReference]]:
    fields: dict[str, list[_FieldReference]] = {}
    detection = document.get("detection")
    if not isinstance(detection, dict):
        return fields
    for selector_name, selector in detection.items():
        if selector_name == "condition" or not isinstance(selector, dict):
            continue
        for expression, value in selector.items():
            if not isinstance(expression, str) or not expression:
                continue
            base, *modifiers = expression.split("|")
            fields.setdefault(base, []).append(
                _FieldReference(frozenset(modifiers), value)
            )
    return fields


def _contains_string_value(value: Any) -> bool:
    if isinstance(value, str):
        return True
    return isinstance(value, list) and any(isinstance(item, str) for item in value)


def _value_sensitive_string_references(
    document: dict[str, Any], field: str
) -> tuple[_FieldReference, ...]:
    references = _rule_field_references(document).get(field, ())
    return tuple(
        reference
        for reference in references
        if reference.modifiers.issubset(_VALUE_SENSITIVE_STRING_MODIFIERS)
        and _contains_string_value(reference.value)
    )


def _field_has_value_sensitive_string_reference(
    document: dict[str, Any], field: str
) -> bool:
    return bool(_value_sensitive_string_references(document, field))


def _field_is_uncased(document: dict[str, Any], field: str) -> bool:
    references = _value_sensitive_string_references(document, field)
    return bool(references) and all(
        "cased" not in reference.modifiers for reference in references
    )


def _ascii_swapcase(value: str) -> str:
    transformed: list[str] = []
    for character in value:
        if "a" <= character <= "z":
            transformed.append(chr(ord(character) - 32))
        elif "A" <= character <= "Z":
            transformed.append(chr(ord(character) + 32))
        else:
            transformed.append(character)
    return "".join(transformed)


def _ascii_case_variations(
    document: dict[str, Any], fixture: Fixture
) -> Iterable[_Candidate]:
    for field in sorted(_PATH_FIELDS):
        value = fixture.event.get(field)
        if not isinstance(value, str):
            continue
        if not _field_is_uncased(document, field):
            continue
        replacement = _ascii_swapcase(value)
        if replacement == value:
            continue
        event = copy.deepcopy(fixture.event)
        event[field] = replacement
        yield _Candidate(
            operator="ascii_case",
            field=field,
            description=f"Changed ASCII letter case in event field {field!r}",
            claim_scope=(
                "ASCII case-only representation for a rule-referenced Image or "
                "ParentImage field that uses a value-sensitive string predicate "
                "without Sigma's cased modifier"
            ),
            original=value,
            replacement=replacement,
            event=event,
        )


def _is_escaped(text: str, index: int) -> bool:
    backslashes = 0
    cursor = index - 1
    while cursor >= 0 and text[cursor] == "\\":
        backslashes += 1
        cursor -= 1
    return backslashes % 2 == 1


def _tokenize_command_line(value: str) -> _Tokenization | None:
    """Return quote-aware token/separator spans for ASCII horizontal space.

    This is intentionally not a command parser. Ambiguous inputs (newlines or
    unmatched quotes) are rejected so an operator cannot overstate semantic
    equivalence.
    """

    if not value or "\r" in value or "\n" in value:
        return None
    token_spans: list[tuple[int, int]] = []
    separator_spans: list[tuple[int, int]] = []
    quote: str | None = None
    token_start: int | None = None
    separator_start: int | None = None

    for index, character in enumerate(value):
        if quote is not None:
            if character == quote and not _is_escaped(value, index):
                quote = None
            continue
        if character in {'"', "'"}:
            if separator_start is not None:
                separator_spans.append((separator_start, index))
                separator_start = None
            if token_start is None:
                token_start = index
            quote = character
            continue
        if character in " \t":
            if token_start is not None:
                token_spans.append((token_start, index))
                token_start = None
            if separator_start is None:
                separator_start = index
            continue
        if separator_start is not None:
            separator_spans.append((separator_start, index))
            separator_start = None
        if token_start is None:
            token_start = index

    if quote is not None:
        return None
    if token_start is not None:
        token_spans.append((token_start, len(value)))
    if separator_start is not None:
        separator_spans.append((separator_start, len(value)))

    internal_separators = tuple(
        (start, end) for start, end in separator_spans if start > 0 and end < len(value)
    )
    if len(token_spans) < 2 or not internal_separators:
        return None
    return _Tokenization(tuple(token_spans), internal_separators)


def _replace_spans(
    value: str,
    spans: tuple[tuple[int, int], ...],
    replacement: str,
) -> str:
    pieces: list[str] = []
    cursor = 0
    for start, end in spans:
        pieces.append(value[cursor:start])
        pieces.append(replacement)
        cursor = end
    pieces.append(value[cursor:])
    return "".join(pieces)


def _command_line_whitespace_variations(
    document: dict[str, Any], fixture: Fixture
) -> Iterable[_Candidate]:
    field = "CommandLine"
    value = fixture.event.get(field)
    if not isinstance(value, str) or not _field_has_value_sensitive_string_reference(
        document, field
    ):
        return
    tokenization = _tokenize_command_line(value)
    if tokenization is None:
        return
    for label, separator in (("normalized", " "), ("expanded", "  ")):
        replacement = _replace_spans(
            value,
            tokenization.separator_spans,
            separator,
        )
        if replacement == value:
            continue
        event = copy.deepcopy(fixture.event)
        event[field] = replacement
        yield _Candidate(
            operator="command_line_whitespace",
            field=field,
            description=(
                f"{label.capitalize()} ASCII separators between CommandLine tokens"
            ),
            claim_scope=(
                "ASCII space/tab separators between existing CommandLine tokens "
                "only; token bytes, order, quoting, and payload bytes are unchanged"
            ),
            original=value,
            replacement=replacement,
            event=event,
        )


def _path_basename(value: str) -> str | None:
    if "\\" not in value and "/" not in value:
        return None
    basename = re.split(r"[\\/]", value)[-1]
    return basename or None


def _telemetry_path_variations(
    document: dict[str, Any], fixture: Fixture
) -> Iterable[_Candidate]:
    for field in sorted(_PATH_FIELDS):
        value = fixture.event.get(field)
        if not isinstance(
            value, str
        ) or not _field_has_value_sensitive_string_reference(document, field):
            continue
        replacement = _path_basename(value)
        if replacement is None or replacement == value:
            continue
        event = copy.deepcopy(fixture.event)
        event[field] = replacement
        yield _Candidate(
            operator="telemetry_path_to_basename",
            field=field,
            description=f"Collapsed event field {field!r} to its basename",
            claim_scope=(
                "Telemetry-shape variation from a full Image/ParentImage path to "
                "the unchanged final basename; no executable substitution is made"
            ),
            original=value,
            replacement=replacement,
            event=event,
        )


def _unquoted_token(value: str) -> str | None:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    if '"' in value or "'" in value:
        return None
    return value


def _pwsh_alias_variations(
    document: dict[str, Any], fixture: Fixture
) -> Iterable[_Candidate]:
    image = fixture.event.get("Image")
    command_line = fixture.event.get("CommandLine")
    if not isinstance(image, str) or not isinstance(command_line, str):
        return
    if not _field_has_value_sensitive_string_reference(document, "CommandLine"):
        return
    image_basename = _path_basename(image) or image
    if image_basename.casefold() != "pwsh.exe":
        return
    tokenization = _tokenize_command_line(command_line)
    if tokenization is None:
        return
    tokens = [command_line[start:end] for start, end in tokenization.token_spans]
    executable = _unquoted_token(tokens[0])
    if executable is None:
        return
    executable_basename = _path_basename(executable) or executable
    if executable_basename.casefold() != "pwsh.exe":
        return

    aliases_by_casefold = {alias.casefold(): alias for alias in _PWSH_ENCODED_ALIASES}
    alias_indexes = [
        index
        for index, token in enumerate(tokens)
        if token.casefold() in aliases_by_casefold
    ]
    if len(alias_indexes) != 1:
        return
    alias_index = alias_indexes[0]
    if alias_index != len(tokens) - 2:
        return
    if any(
        token.casefold() not in _PWSH_SAFE_PREFIX_SWITCHES
        for token in tokens[1:alias_index]
    ):
        return
    payload = tokens[-1]
    if not payload or _BASE64_TOKEN.fullmatch(payload) is None:
        return
    original_alias = tokens[alias_index]
    start, end = tokenization.token_spans[alias_index]
    for replacement_alias in _PWSH_ENCODED_ALIASES:
        if replacement_alias.casefold() == original_alias.casefold():
            continue
        replacement = command_line[:start] + replacement_alias + command_line[end:]
        event = copy.deepcopy(fixture.event)
        event["CommandLine"] = replacement
        yield _Candidate(
            operator="pwsh_encoded_alias",
            field="CommandLine",
            description=(
                f"Changed pwsh parameter {original_alias!r} to {replacement_alias!r}"
            ),
            claim_scope=(
                "Documented PowerShell 7 encoded-command parameter aliases for "
                "pwsh.exe only; executable, payload, other tokens, and separators "
                "are preserved byte-for-byte"
            ),
            original=command_line,
            replacement=replacement,
            event=event,
        )


_GENERATORS: tuple[_Generator, ...] = (
    _ascii_case_variations,
    _command_line_whitespace_variations,
    _telemetry_path_variations,
    _pwsh_alias_variations,
)


def generate_event_variations(
    rule_doc: dict[str, Any],
    fixtures: Iterable[Fixture],
    rule_bytes: bytes | None = None,
    *,
    max_variations: int = DEFAULT_MAX_VARIATIONS,
) -> list[EventVariation]:
    """Generate stable, de-duplicated variations from positive fixtures only."""

    if isinstance(max_variations, bool) or not isinstance(max_variations, int):
        raise ValueError("max-variations must be a positive integer")
    if max_variations < 1:
        raise ValueError("max-variations must be a positive integer")
    original_rule = copy.deepcopy(rule_doc)
    fixture_snapshots = [copy.deepcopy(fixture) for fixture in fixtures]
    source_hash = _rule_hash(rule_doc, rule_bytes)
    variations: list[EventVariation] = []

    for fixture in sorted(fixture_snapshots, key=lambda item: item.id):
        if not fixture.expected:
            continue
        seen_events: set[str] = {hashlib.sha256(_canonical(fixture.event)).hexdigest()}
        for generator in _GENERATORS:
            for candidate in generator(rule_doc, fixture):
                event_hash = hashlib.sha256(_canonical(candidate.event)).hexdigest()
                if event_hash in seen_events:
                    continue
                seen_events.add(event_hash)
                if len(variations) >= max_variations:
                    raise EventVariationLimitError(
                        "Event variation limit exceeded "
                        f"(max-variations={max_variations})."
                    )
                variations.append(
                    EventVariation(
                        id=_variation_id(source_hash, fixture, candidate),
                        source_fixture_id=fixture.id,
                        operator=candidate.operator,
                        field=candidate.field,
                        description=candidate.description,
                        claim_scope=candidate.claim_scope,
                        original=copy.deepcopy(candidate.original),
                        replacement=copy.deepcopy(candidate.replacement),
                        event=copy.deepcopy(candidate.event),
                    )
                )

    if rule_doc != original_rule:
        raise RuntimeError("Event variation generation modified the original rule")
    return sorted(
        variations,
        key=lambda item: (
            item.source_fixture_id,
            item.operator,
            item.path,
            item.id,
        ),
    )

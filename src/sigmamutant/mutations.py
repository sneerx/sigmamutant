"""First-order mutation operators over a parsed Sigma detection document."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from sigmamutant.models import Mutant


@dataclass(frozen=True, slots=True)
class Operator:
    name: str
    description: str


OPERATORS: tuple[Operator, ...] = (
    Operator(
        "delete_predicate",
        "Delete one field predicate from a selector mapping.",
    ),
    Operator(
        "delete_list_item",
        "Delete one alternative from a multi-value field list.",
    ),
    Operator(
        "modifier_to_exact",
        "Narrow one contains/startswith/endswith field comparison to exact.",
    ),
    Operator(
        "list_any_to_all",
        "Require all alternatives in one OR-value list.",
    ),
    Operator(
        "condition_and_to_or",
        "Replace one boolean and/or token with its opposite.",
    ),
    Operator(
        "condition_remove_not",
        "Remove one boolean not token from the condition.",
    ),
)


@dataclass(frozen=True, slots=True)
class _Candidate:
    operator: str
    path: str
    description: str
    original: Any
    replacement: Any
    document: dict[str, Any]


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _rule_hash(document: dict[str, Any], rule_bytes: bytes | None) -> str:
    source = rule_bytes if rule_bytes is not None else _canonical(document)
    return hashlib.sha256(source).hexdigest()


def _mutant_id(rule_hash: str, candidate: _Candidate) -> str:
    before_hash = hashlib.sha256(_canonical(candidate.original)).hexdigest()
    after_hash = hashlib.sha256(_canonical(candidate.replacement)).hexdigest()
    identity = "\x1f".join(
        (rule_hash, candidate.operator, candidate.path, before_hash, after_hash)
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def _selectors(document: dict[str, Any]):
    detection = document.get("detection")
    if not isinstance(detection, dict):
        return
    for selector_name, selector in detection.items():
        if selector_name == "condition" or not isinstance(selector, dict):
            continue
        yield selector_name, selector


def _delete_predicates(document: dict[str, Any]) -> Iterable[_Candidate]:
    for selector_name, selector in _selectors(document):
        if len(selector) <= 1:
            continue
        for field in selector:
            mutant = copy.deepcopy(document)
            original = copy.deepcopy(selector[field])
            del mutant["detection"][selector_name][field]
            path = f"detection.{selector_name}.{field}"
            yield _Candidate(
                "delete_predicate",
                path,
                f"Deleted predicate {path}",
                {field: original},
                None,
                mutant,
            )


def _delete_list_items(document: dict[str, Any]) -> Iterable[_Candidate]:
    for selector_name, selector in _selectors(document):
        for field, value in selector.items():
            if not isinstance(value, list) or len(value) <= 1:
                continue
            for index, item in enumerate(value):
                mutant = copy.deepcopy(document)
                del mutant["detection"][selector_name][field][index]
                path = f"detection.{selector_name}.{field}[{index}]"
                yield _Candidate(
                    "delete_list_item",
                    path,
                    f"Deleted list alternative at {path}",
                    copy.deepcopy(item),
                    None,
                    mutant,
                )


def _modifier_to_exact(document: dict[str, Any]) -> Iterable[_Candidate]:
    narrowing = {"contains", "startswith", "endswith"}
    for selector_name, selector in _selectors(document):
        for field, value in selector.items():
            pieces = field.split("|")
            removed = [part for part in pieces[1:] if part in narrowing]
            if not removed:
                continue
            new_pieces = [
                pieces[0],
                *(part for part in pieces[1:] if part not in narrowing),
            ]
            replacement_field = "|".join(new_pieces)
            if replacement_field in selector and replacement_field != field:
                continue
            mutant = copy.deepcopy(document)
            mutated_selector = mutant["detection"][selector_name]
            rebuilt: dict[str, Any] = {}
            for current_field, current_value in mutated_selector.items():
                target_field = (
                    replacement_field if current_field == field else current_field
                )
                rebuilt[target_field] = current_value
            mutant["detection"][selector_name] = rebuilt
            path = f"detection.{selector_name}.{field}"
            yield _Candidate(
                "modifier_to_exact",
                path,
                f"Changed {field!r} to exact comparison {replacement_field!r}",
                field,
                replacement_field,
                mutant,
            )


def _list_any_to_all(document: dict[str, Any]) -> Iterable[_Candidate]:
    for selector_name, selector in _selectors(document):
        for field, value in selector.items():
            if not isinstance(value, list) or len(value) <= 1:
                continue
            pieces = field.split("|")
            if "all" in pieces[1:]:
                continue
            replacement_field = "|".join([*pieces, "all"])
            if replacement_field in selector:
                continue
            mutant = copy.deepcopy(document)
            mutated_selector = mutant["detection"][selector_name]
            rebuilt: dict[str, Any] = {}
            for current_field, current_value in mutated_selector.items():
                target_field = (
                    replacement_field if current_field == field else current_field
                )
                rebuilt[target_field] = current_value
            mutant["detection"][selector_name] = rebuilt
            path = f"detection.{selector_name}.{field}"
            yield _Candidate(
                "list_any_to_all",
                path,
                f"Changed OR-list {field!r} to all-values matching",
                field,
                replacement_field,
                mutant,
            )


def _replace_condition_boolean(document: dict[str, Any]) -> Iterable[_Candidate]:
    detection = document.get("detection", {})
    condition = detection.get("condition")
    if not isinstance(condition, str):
        return
    for match in re.finditer(r"\b(and|or)\b", condition, flags=re.IGNORECASE):
        token = match.group(0)
        replacement = "or" if token.lower() == "and" else "and"
        if token.isupper():
            replacement = replacement.upper()
        mutated_condition = (
            condition[: match.start()] + replacement + condition[match.end() :]
        )
        mutant = copy.deepcopy(document)
        mutant["detection"]["condition"] = mutated_condition
        path = f"detection.condition@{match.start()}"
        yield _Candidate(
            "condition_and_to_or",
            path,
            f"Changed condition token {token!r} to {replacement!r}",
            condition,
            mutated_condition,
            mutant,
        )


def _remove_condition_not(document: dict[str, Any]) -> Iterable[_Candidate]:
    detection = document.get("detection", {})
    condition = detection.get("condition")
    if not isinstance(condition, str):
        return
    for match in re.finditer(r"\bnot\b\s*", condition, flags=re.IGNORECASE):
        mutated_condition = condition[: match.start()] + condition[match.end() :]
        mutant = copy.deepcopy(document)
        mutant["detection"]["condition"] = mutated_condition
        path = f"detection.condition@{match.start()}"
        yield _Candidate(
            "condition_remove_not",
            path,
            "Removed one not token from the condition",
            condition,
            mutated_condition,
            mutant,
        )


_GENERATORS: tuple[Callable[[dict[str, Any]], Iterable[_Candidate]], ...] = (
    _delete_predicates,
    _delete_list_items,
    _modifier_to_exact,
    _list_any_to_all,
    _replace_condition_boolean,
    _remove_condition_not,
)


def generate_mutants(
    rule_doc: dict[str, Any],
    rule_bytes: bytes | None = None,
) -> list[Mutant]:
    """Generate deterministic, de-duplicated, first-order mutants.

    Syntax/evaluator validation is intentionally performed by the runner so this
    pure function remains fast and straightforward to unit test.
    """

    original_snapshot = copy.deepcopy(rule_doc)
    original_hash = hashlib.sha256(_canonical(rule_doc)).hexdigest()
    source_hash = _rule_hash(rule_doc, rule_bytes)
    seen_documents: set[str] = {original_hash}
    mutants: list[Mutant] = []
    for generator in _GENERATORS:
        for candidate in generator(rule_doc):
            document_hash = hashlib.sha256(_canonical(candidate.document)).hexdigest()
            if document_hash in seen_documents:
                continue
            seen_documents.add(document_hash)
            mutants.append(
                Mutant(
                    id=_mutant_id(source_hash, candidate),
                    operator=candidate.operator,
                    path=candidate.path,
                    description=candidate.description,
                    original=candidate.original,
                    replacement=candidate.replacement,
                    document=candidate.document,
                )
            )
    if rule_doc != original_snapshot:
        raise RuntimeError("Mutation generation modified the original rule")
    return sorted(mutants, key=lambda item: (item.operator, item.path, item.id))

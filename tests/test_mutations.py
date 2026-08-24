from __future__ import annotations

import copy
import json
import re
from typing import Any

import pytest

from sigmamutant.mutations import OPERATORS, generate_mutants

EXPECTED_OPERATORS = {
    "delete_predicate",
    "delete_list_item",
    "modifier_to_exact",
    "list_any_to_all",
    "condition_and_to_or",
    "condition_remove_not",
}


def _operator_names() -> set[str]:
    if isinstance(OPERATORS, dict):
        return set(OPERATORS)
    return {
        operator if isinstance(operator, str) else operator.name
        for operator in OPERATORS
    }


def _documents(mutants: list[Any], operator: str) -> list[dict[str, Any]]:
    return [mutant.document for mutant in mutants if mutant.operator == operator]


def _canonical(document: dict[str, Any]) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def test_v01_registers_exactly_the_six_documented_operators() -> None:
    assert _operator_names() == EXPECTED_OPERATORS


def test_rule_with_all_mutation_sites_exercises_every_operator(
    mutation_rule: dict[str, Any],
) -> None:
    mutants = generate_mutants(mutation_rule)

    assert {mutant.operator for mutant in mutants} == EXPECTED_OPERATORS
    assert all(mutant.path for mutant in mutants)
    assert all(mutant.description for mutant in mutants)


def test_delete_predicate_removes_one_selector_field(
    mutation_rule: dict[str, Any],
) -> None:
    documents = _documents(generate_mutants(mutation_rule), "delete_predicate")
    original = mutation_rule["detection"]["selection_main"]

    main_selector_mutants = [
        document["detection"]["selection_main"]
        for document in documents
        if "selection_main" in document["detection"]
    ]
    assert main_selector_mutants
    assert any(
        len(selector) == len(original) - 1 and set(selector).issubset(original)
        for selector in main_selector_mutants
    )


def test_delete_list_item_removes_exactly_one_alternative(
    mutation_rule: dict[str, Any],
) -> None:
    documents = _documents(generate_mutants(mutation_rule), "delete_list_item")
    original_values = mutation_rule["detection"]["selection_main"]["Image|endswith"]

    mutated_values = [
        document["detection"]["selection_main"]["Image|endswith"]
        for document in documents
        if "Image|endswith" in document["detection"]["selection_main"]
        and document["detection"]["selection_main"]["Image|endswith"] != original_values
    ]
    assert mutated_values
    assert all(len(values) == len(original_values) - 1 for values in mutated_values)
    assert all(set(values).issubset(original_values) for values in mutated_values)


@pytest.mark.parametrize(
    ("original_key", "mutated_key"),
    [
        ("Image|endswith", "Image"),
        ("CommandLine|contains", "CommandLine"),
        ("User|startswith", "User"),
    ],
)
def test_modifier_to_exact_removes_one_matching_modifier(
    mutation_rule: dict[str, Any],
    original_key: str,
    mutated_key: str,
) -> None:
    documents = _documents(generate_mutants(mutation_rule), "modifier_to_exact")

    matching = [
        document
        for document in documents
        if mutated_key in document["detection"]["selection_main"]
        and original_key not in document["detection"]["selection_main"]
    ]
    assert matching
    assert (
        matching[0]["detection"]["selection_main"][mutated_key]
        == (mutation_rule["detection"]["selection_main"][original_key])
    )


def test_list_any_to_all_adds_all_without_changing_values(
    mutation_rule: dict[str, Any],
) -> None:
    documents = _documents(generate_mutants(mutation_rule), "list_any_to_all")

    image_mutants = [
        document
        for document in documents
        if "Image|endswith|all" in document["detection"]["selection_main"]
    ]
    assert image_mutants
    assert (
        image_mutants[0]["detection"]["selection_main"]["Image|endswith|all"]
        == (mutation_rule["detection"]["selection_main"]["Image|endswith"])
    )


def test_condition_and_to_or_changes_one_boolean_token(
    mutation_rule: dict[str, Any],
) -> None:
    documents = _documents(generate_mutants(mutation_rule), "condition_and_to_or")

    conditions = [document["detection"]["condition"] for document in documents]
    assert "selection_main or not filter_system" in conditions


def test_condition_remove_not_changes_one_negation(
    mutation_rule: dict[str, Any],
) -> None:
    documents = _documents(generate_mutants(mutation_rule), "condition_remove_not")

    conditions = [document["detection"]["condition"] for document in documents]
    assert "selection_main and filter_system" in conditions


def test_condition_connective_mutants_are_first_order() -> None:
    rule = {
        "title": "Multiple connectives",
        "logsource": {"category": "process_creation"},
        "detection": {
            "one": {"Image": "one.exe"},
            "two": {"Image": "two.exe"},
            "three": {"Image": "three.exe"},
            "condition": "(one and two) or three",
        },
    }

    conditions = {
        mutant.document["detection"]["condition"]
        for mutant in generate_mutants(rule)
        if mutant.operator == "condition_and_to_or"
    }

    assert conditions == {
        "(one or two) or three",
        "(one and two) and three",
    }


def test_generation_is_deterministic_and_ids_are_unique(
    mutation_rule: dict[str, Any],
) -> None:
    rule_bytes = json.dumps(mutation_rule, sort_keys=True).encode()

    first = generate_mutants(mutation_rule, rule_bytes)
    second = generate_mutants(mutation_rule, rule_bytes)
    first_projection = [
        (mutant.id, mutant.operator, mutant.path, _canonical(mutant.document))
        for mutant in first
    ]
    second_projection = [
        (mutant.id, mutant.operator, mutant.path, _canonical(mutant.document))
        for mutant in second
    ]

    assert first_projection == second_projection
    assert len({mutant.id for mutant in first}) == len(first)
    assert all(re.fullmatch(r"[0-9a-f]{12,64}", mutant.id) for mutant in first)


def test_generation_never_mutates_or_aliases_the_source_document(
    mutation_rule: dict[str, Any],
    pristine_mutation_rule: dict[str, Any],
) -> None:
    mutants = generate_mutants(mutation_rule)

    assert mutation_rule == pristine_mutation_rule
    assert mutants

    first_before = copy.deepcopy(mutants[1].document)
    mutants[0].document["title"] = "changed by test"

    assert mutation_rule == pristine_mutation_rule
    assert mutants[1].document == first_before


def test_duplicate_mutant_documents_are_excluded() -> None:
    duplicate_values_rule = {
        "title": "Duplicate alternatives",
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"Image": ["cmd.exe", "cmd.exe"]},
            "condition": "selection",
        },
    }

    mutants = generate_mutants(duplicate_values_rule)
    deleted = [mutant for mutant in mutants if mutant.operator == "delete_list_item"]

    canonical_documents = {_canonical(mutant.document) for mutant in deleted}
    assert len(deleted) == len(canonical_documents) == 1

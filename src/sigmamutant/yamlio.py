"""Small, deterministic YAML helpers."""

from __future__ import annotations

from io import StringIO
from typing import Any

from ruamel.yaml import YAML

from sigmamutant.errors import RuleError


def _yaml() -> YAML:
    parser = YAML(typ="safe")
    parser.allow_duplicate_keys = False
    parser.default_flow_style = False
    parser.sort_base_mapping_type_on_output = False
    parser.width = 4096
    return parser


def load_single_yaml(text: str, *, source: str = "YAML") -> dict[str, Any]:
    parser = _yaml()
    try:
        documents = list(parser.load_all(text))
    except Exception as exc:
        # ruamel exposes several scanner/parser subclasses across versions.
        raise RuleError(f"{source} is not valid YAML: {exc}") from exc
    if len(documents) != 1:
        raise RuleError(f"{source} must contain exactly one YAML document")
    document = documents[0]
    if not isinstance(document, dict):
        raise RuleError(f"{source} must contain a YAML mapping at its root")
    return document


def dump_yaml(document: dict[str, Any]) -> str:
    parser = _yaml()
    stream = StringIO()
    parser.dump(document, stream)
    return stream.getvalue()

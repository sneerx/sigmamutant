"""Fail-closed validation and in-process Sigma event evaluation."""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

from sigmamutant.errors import EvaluationError, RuleError
from sigmamutant.yamlio import dump_yaml

SUPPORTED_MODIFIERS = {
    "all",
    "base64",
    "base64offset",
    "cased",
    "cidr",
    "contains",
    "endswith",
    "exists",
    "gt",
    "gte",
    "lt",
    "lte",
    "startswith",
    "utf16",
    "utf16be",
    "utf16le",
    "wide",
    "windash",
}
UNSUPPORTED_MODIFIERS = {"expand", "fieldref", "re"}
PLACEHOLDER = re.compile(r"%[^%\s]+%")


def _walk_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_strings(key)
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)


def validate_supported_rule(document: dict[str, Any]) -> None:
    if not isinstance(document, dict):
        raise RuleError("Rule must be a YAML mapping")
    if "correlation" in document:
        raise RuleError("Correlation rules are not supported by SigmaMutant")
    title = document.get("title")
    if not isinstance(title, str) or not title.strip():
        raise RuleError("Rule must have a non-empty title")
    if not isinstance(document.get("logsource"), dict):
        raise RuleError("Rule must have a logsource mapping")
    detection = document.get("detection")
    if not isinstance(detection, dict):
        raise RuleError("Rule must have a detection mapping")
    condition = detection.get("condition")
    if not isinstance(condition, str) or not condition.strip():
        raise RuleError("detection.condition must be a non-empty string")
    selectors = {key: value for key, value in detection.items() if key != "condition"}
    if not selectors:
        raise RuleError("Rule must define at least one detection selector")
    for selector_name, selector in selectors.items():
        if not isinstance(selector_name, str) or not selector_name:
            raise RuleError("Selector names must be non-empty strings")
        if isinstance(selector, list):
            raise RuleError(
                f"Keyword-only selector {selector_name!r} is not supported by SigmaMutant"
            )
        if not isinstance(selector, dict) or not selector:
            raise RuleError(
                f"Selector {selector_name!r} must be a non-empty field mapping"
            )
        for field, value in selector.items():
            if not isinstance(field, str) or not field:
                raise RuleError(f"Selector {selector_name!r} contains an invalid field")
            modifiers = field.split("|")[1:]
            unknown = sorted(set(modifiers) - SUPPORTED_MODIFIERS)
            if unknown:
                if set(unknown) & UNSUPPORTED_MODIFIERS:
                    reason = "unsupported"
                else:
                    reason = "unknown"
                raise RuleError(
                    f"Field {field!r} uses {reason} modifier(s): {', '.join(unknown)}"
                )
            string_comparators = {"contains", "startswith", "endswith"} & set(modifiers)
            if len(string_comparators) > 1:
                raise RuleError(
                    f"Field {field!r} combines mutually exclusive string modifiers"
                )
            if isinstance(value, dict):
                raise RuleError(
                    f"Nested field mapping at {selector_name}.{field} is not supported"
                )
            if isinstance(value, list):
                if not value:
                    raise RuleError(
                        f"Value list at {selector_name}.{field} cannot be empty"
                    )
                if any(isinstance(item, (dict, list)) for item in value):
                    raise RuleError(
                        f"List-of-maps/nested lists at {selector_name}.{field} are unsupported"
                    )
                if any(
                    (not isinstance(item, (str, int, float, bool)) and item is not None)
                    or (isinstance(item, float) and not math.isfinite(item))
                    for item in value
                ):
                    raise RuleError(
                        f"Unsupported value in list at {selector_name}.{field}"
                    )
            elif not isinstance(value, (str, int, float, bool)) and value is not None:
                raise RuleError(f"Unsupported value at {selector_name}.{field}")
            elif isinstance(value, float) and not math.isfinite(value):
                raise RuleError(f"Non-finite value at {selector_name}.{field}")
    for string in _walk_strings(document):
        if PLACEHOLDER.search(string):
            raise RuleError("Sigma value placeholders are not supported by SigmaMutant")


class SigmaEvaluator:
    """Validate with pySigma and evaluate with Azuma without executing event data."""

    def __init__(self) -> None:
        self._rules: dict[str, Any] = {}

    def validate_rule(self, document: dict[str, Any]) -> None:
        validate_supported_rule(document)
        yaml_text = dump_yaml(document)
        try:
            from sigma.collection import SigmaCollection

            SigmaCollection.from_yaml(yaml_text)
        except RuleError:
            raise
        except Exception as exc:
            raise RuleError(f"pySigma rejected the rule: {exc}") from exc
        try:
            from azuma import Rule

            Rule.model_validate_yaml(yaml_text)
        except Exception as exc:
            raise RuleError(f"Azuma rejected the rule: {exc}") from exc

    def _compiled_rule(self, document: dict[str, Any]):
        payload = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
        key = hashlib.sha256(payload).hexdigest()
        if key not in self._rules:
            self.validate_rule(document)
            from azuma import Rule

            self._rules[key] = Rule.model_validate_yaml(dump_yaml(document))
        return self._rules[key]

    def matches(self, document: dict[str, Any], event: dict[str, Any]) -> bool:
        if not isinstance(event, dict):
            raise EvaluationError("Event must be a mapping")
        try:
            result = self._compiled_rule(document).match(event)
        except RuleError:
            raise
        except Exception as exc:
            raise EvaluationError(f"Azuma could not evaluate the event: {exc}") from exc
        if not isinstance(result, bool):
            raise EvaluationError("Azuma returned a non-boolean match result")
        return result

from __future__ import annotations

import pytest

from scripts.analyze_sigma_corpus import _subset_reason, analyze

MUTABLE_RULE = """\
title: Synthetic process rule
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\alpha.exe'
      - '\\beta.exe'
    CommandLine|contains:
      - ' --one'
      - ' --two'
  filter:
    ParentImage|endswith: '\\trusted.exe'
  condition: selection and not filter
"""


KEYWORD_RULE = """\
title: Synthetic keyword rule
logsource:
  category: webserver
detection:
  keywords:
    - suspicious-token
  condition: keywords
"""


def test_analyze_counts_supported_and_rejected_rules(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "mutable.yml").write_text(MUTABLE_RULE, encoding="utf-8")
    (rules / "keyword.yml").write_text(KEYWORD_RULE, encoding="utf-8")

    first = analyze(
        tmp_path,
        scopes=["rules"],
        source_name="synthetic",
        source_url="https://example.invalid/synthetic",
        source_revision="test-revision",
    )
    second = analyze(
        tmp_path,
        scopes=["rules"],
        source_name="synthetic",
        source_url="https://example.invalid/synthetic",
        source_revision="test-revision",
    )

    assert first == second
    assert first["summary"]["rule_files"] == 2
    assert first["summary"]["parsed"] == 2
    assert first["summary"]["subset_supported"] == 1
    assert first["summary"]["evaluator_supported"] == 1
    assert first["summary"]["mutation_applicable"] == 1
    assert first["summary"]["mutants_generated"] > 0
    assert first["rejection_reasons"] == {"keyword_only_selector": 1}
    assert first["source"]["tree_sha256"]
    assert set(first["mutants_by_operator"]) == {
        "condition_and_to_or",
        "condition_remove_not",
        "delete_list_item",
        "delete_predicate",
        "list_any_to_all",
        "modifier_to_exact",
    }


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Correlation rules are not supported", "correlation_rule"),
        ("Field 'x|re' uses unsupported modifier(s): re", "unsupported_modifier"),
        ("Sigma value placeholders are not supported", "value_placeholder"),
        ("unclassified", "other_subset_rejection"),
    ],
)
def test_subset_reasons_are_stable(message, expected):
    assert _subset_reason(message) == expected


def test_analyze_rejects_escaping_scope(tmp_path):
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)

    with pytest.raises(ValueError, match="relative child path"):
        analyze(
            tmp_path,
            scopes=["../outside"],
            source_name="synthetic",
            source_url="https://example.invalid/synthetic",
            source_revision="test-revision",
        )


def test_analyze_rejects_empty_scope(tmp_path):
    (tmp_path / "rules").mkdir()

    with pytest.raises(ValueError, match="no YAML rule files"):
        analyze(
            tmp_path,
            scopes=["rules"],
            source_name="synthetic",
            source_url="https://example.invalid/synthetic",
            source_revision="test-revision",
        )

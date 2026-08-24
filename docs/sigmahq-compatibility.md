# SigmaHQ rule-corpus applicability study

This version-pinned study records where SigmaMutant `1.0.0`'s fail-closed rule
subset and mutation operators apply across a pinned external rule corpus. The
canonical result was rerun from the exact upstream commit with the final 1.0
engine. It complements the project's paired weak/strong fixture evaluation; it
does not replace it.

## Result

SigmaMutant `1.0.0` scanned **3,757 rule files** from the three primary rule
trees in `SigmaHQ/sigma` at commit
`da9bb07d642a2826e89702445d32c795209ec108`:

- `rules`
- `rules-emerging-threats`
- `rules-threat-hunting`

| Measurement | Count | Share of scanned rule files |
| --- | ---: | ---: |
| Parsed single-document YAML rules | 3,757 | 100.0% |
| Passed SigmaMutant's declared subset | 2,611 | 69.5% |
| Also validated by the pySigma/Azuma stack | 2,609 | 69.4% |
| Contained at least one current mutation site | 2,463 | 65.6% |
| Supported but had no current mutation site | 146 | 3.9% |

The applicable rules exposed **40,603 deterministic first-order mutation
sites**:

| Operator | Generated sites |
| --- | ---: |
| `delete_list_item` | 27,583 |
| `modifier_to_exact` | 4,908 |
| `delete_predicate` | 4,525 |
| `list_any_to_all` | 2,142 |
| `condition_and_to_or` | 825 |
| `condition_remove_not` | 620 |

The complete canonical result, including the source-tree hash, dependency
versions, logsource breakdown, rejection categories, and interpretation
boundary, is checked in as `benchmarks/sigmahq-compatibility.json`.

## What was measured

For each regular `.yml` or `.yaml` file in the selected trees, the analysis:

1. decoded and parsed exactly one YAML document;
2. applied SigmaMutant's documented fail-closed subset validation;
3. asked the configured pySigma and Azuma stack to validate accepted rules;
4. generated and counted every applicable first-order mutation site without
   executing an event or writing a mutated rule.

The canonical evidence was generated with:

```text
SigmaMutant 1.0.0
Azuma 0.7.3
pySigma 1.5.0
ruamel.yaml 0.18.17
```

The local scan completed in approximately 20 seconds on the development macOS
host with Python 3.12. Runtime is deliberately omitted from the canonical JSON
because it is host-dependent.

## Fail-closed exclusions

The external corpus produced these aggregate rejection categories:

| Reason | Rules |
| --- | ---: |
| Keyword-only selector, outside the current field-mapping subset | 979 |
| Sigma value placeholder | 90 |
| Unsupported modifier | 77 |
| Accepted subset but rejected by pySigma | 2 |

These are reported as scope boundaries, not silently approximated. The two
pySigma rejections are separated from SigmaMutant's own subset decisions.

## Reproduce

Clone the source corpus and check out the exact revision:

```bash
git clone https://github.com/SigmaHQ/sigma.git /tmp/sigmahq-sigma
git -C /tmp/sigmahq-sigma checkout \
  da9bb07d642a2826e89702445d32c795209ec108
```

Install SigmaMutant with the demo constraints, then compare a fresh analysis
with the checked-in evidence:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -c constraints-demo.txt -e .
python scripts/analyze_sigma_corpus.py /tmp/sigmahq-sigma \
  --source-name SigmaHQ/sigma \
  --source-url https://github.com/SigmaHQ/sigma \
  --source-revision da9bb07d642a2826e89702445d32c795209ec108 \
  --out benchmarks/sigmahq-compatibility.json \
  --verify
```

The evidence records a deterministic SHA-256 over every relative path and file
hash in the selected source trees. A rule, dependency, validation outcome, or
operator-count change makes verification fail.

## Interpretation and limits

This study supports a narrow claim: the v1.0 evaluator accepts
roughly 69% of the pinned SigmaHQ rule files in the selected trees, and its
recorded operator catalog found at least one mutation site in roughly 66% of
them.

It does **not** execute the third-party rules against labelled events and does
not report a mutation score. It therefore does not measure detection accuracy,
fixture quality, false-positive or false-negative rates, telemetry realism,
backend equivalence, or whether every generated mutant models a likely human
defect. The separate project-authored paired evaluation measures fixture-suite
sensitivity under controlled conditions.

No SigmaHQ rule content is redistributed in this repository. The checked-in
artifact contains aggregate derived measurements, logsource labels, dependency
versions, and hashes. Consult the upstream
[SigmaHQ/sigma repository](https://github.com/SigmaHQ/sigma) for its current
content and licensing terms.

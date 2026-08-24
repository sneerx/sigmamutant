# Evaluation corpus

This directory contains SigmaMutant's checked-in, reproducible
fixture-quality evaluation. It exists to make the project's central claim
falsifiable: boundary-focused fixtures should kill rule-logic mutations that a
minimal baseline-only suite misses.

## Design

`manifest.json` declares 15 cases from 15 normalized log domains. Every case
contains:

- one self-contained Sigma rule;
- a two-event weak fixture suite that proves only the baseline;
- a boundary-focused strong fixture suite;
- unchanged rule bytes across both phases.

All rules, identities, domains, commands, and event records are project-authored
synthetic test data. Command-like strings are inert and SigmaMutant never
executes them. Reserved `.invalid` and `.test` names are used where a network
identifier is useful. No production telemetry, customer data, external rule
corpus, or AI-generated result is represented here.

The corpus is covered by the repository's Apache-2.0 license.

## Verify

Install the development dependencies, then run:

```bash
python -m pip install -c constraints-demo.txt -e ".[dev]"
python scripts/evaluate_corpus.py --verify
```

The command executes every weak/strong pair and byte-compares the newly
calculated canonical payload with `results.json`. It also verifies that
`docs/evaluation.md` is the renderer output for the same payload. A changed
rule, fixture, dependency version, operator result, input hash, or score fails
the command.

The release constraint set pins direct dependency versions used to create the
checked-in evidence and by the CI verification job.

`--verify` is an offline operation. It does not load an AI provider, call a
network service, or write artifacts.

## Intentional updates

After changing an operator or corpus input, regenerate evidence with:

```bash
python scripts/evaluate_corpus.py --update
```

Review both `results.json` and `docs/evaluation.md` before committing them.
Strong scores are not accepted merely because the expected JSON changed; each
fixture should have a reviewable boundary purpose, and the unchanged-rule
invariant must still hold.

## Limits

This is a controlled mutation/fixture evaluation, not a production accuracy
benchmark. It does not estimate alert precision, recall, telemetry loss, SIEM
backend parity, or whole-language Sigma compatibility.

## External applicability companion

The separately pinned
[`SigmaHQ/sigma` applicability study](../docs/sigmahq-compatibility.md) scans
3,757 upstream rule files without redistributing them. It measures declared
subset support and operator applicability, not fixture quality or detection
accuracy. Its canonical machine-readable result is
`sigmahq-compatibility.json`.

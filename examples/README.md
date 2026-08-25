# Example: encoded PowerShell process detection

This example demonstrates SigmaMutant's two independent directions:

- rule mutation keeps the rule fixed between weak and strong fixture suites and
  asks whether the fixtures notice atomic rule defects;
- event-gap analysis keeps one labelled fixture corpus fixed and asks whether
  an ordinary and deliberately hardened rule retain bounded event variations.

Every rule and event is project-authored, synthetic, and inert.

## Files

```text
examples/
├── rules/
│   ├── powershell_encoded.yml
│   └── powershell_encoded_hardened.yml
├── fixtures/
│   ├── weak.jsonl
│   ├── strong.jsonl
│   └── gap.jsonl
├── weak-suite.yml
├── strong-suite.yml
├── powershell-gap.yml
└── powershell-hardened-gap.yml
```

The rule matches a PowerShell-family process whose command line contains an
encoded-command switch, except when its parent is the synthetic
`trusted-deployer.exe`.

## Weak suite

```bash
sigmamutant validate examples/weak-suite.yml
sigmamutant run examples/weak-suite.yml --out artifacts/weak
```

The mutation run intentionally exits `1` because the weak suite is below its
quality threshold. Its reports are still complete; exit `2` would indicate a
technical error.

The positive fixture uses minimal values that happen to resemble exact
matching, and the negative is distant from the rule boundary. This proves the
baseline but intentionally leaves room for mutation survivors.

## Strong suite

```bash
sigmamutant validate examples/strong-suite.yml
sigmamutant run examples/strong-suite.yml --out artifacts/strong
```

The stronger corpus covers:

| Fixture | Test purpose |
| --- | --- |
| `pos-windows-powershell-encoded` | Full path and long encoded switch |
| `pos-pwsh-short-enc` | Second image and switch alternatives |
| `neg-benign-powershell` | Command-line predicate is required |
| `neg-non-shell-encoded` | Image predicate is required |
| `neg-trusted-deployer` | Exclusion and condition `not` are required |
| `neg-encoded-near-miss` | Substring boundary near miss remains negative |

All names and values are synthetic. The base64-looking strings are inert test
data and are never decoded or executed by SigmaMutant.

## Deterministic event-gap comparison

The gap fixture corpus contains the same ten labelled events for both rules:
two positive seeds and eight negative baseline guards. Four additional guards
ensure exact executable basenames do not accept suffix collisions and that the
documented `pwsh.exe` `-e` / `-ec` aliases are not widened to Windows
PowerShell. `gap` first verifies all ten labels, then derives event copies only
from the two positives.

Run the ordinary rule:

```bash
sigmamutant gap examples/powershell-gap.yml \
  --out artifacts/powershell-gap --verbose
```

This run intentionally exits `1` at the separate default gap threshold of
`1.0`:

```text
Positive seeds   2
Variants        12
Detected         8
Gap candidates   4
Excluded         0
Variant score   66.7%
```

The four candidates are two `Image` full-path-to-basename changes and the
`pwsh.exe` `-e` / `-ec` encoded-command aliases. Microsoft lists
`-EncodedCommand`, `-e`, and `-ec` in the official
[`about_Pwsh`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh?view=powershell-7.6)
reference.

Now run the deliberately hardened rule against the same fixture bytes:

```bash
sigmamutant gap examples/powershell-hardened-gap.yml \
  --out artifacts/powershell-hardened-gap --verbose
```

It detects all `12` variations, reports no candidates, scores `100.0%`, and
exits `0`. This is a reproducible example result under the pinned local
evaluator—not a claim that basename telemetry is emitted by every sensor, that
all command-line forms are universally equivalent, or that the hardened YAML
is a production recommendation.

The command never edits either rule or `gap.jsonl`. Its value-safe bundle is:

```text
artifacts/powershell-gap/
├── gap-report.json
├── gap-report.html
└── gap-junit.xml
```

Reports retain stable IDs, fixture IDs, operator/path provenance, claim scope,
result Booleans, hashes, and dependency versions. They omit raw source,
replacement, and derived event values.

List the fixed event operators with:

```bash
sigmamutant gap-operators
```

## All-in-one rule-mutation repository check

Run every explicitly named suite in this directory and write aggregate
evidence with:

```bash
sigmamutant check examples --out artifacts/examples --verbose
```

This example intentionally returns exit `1`: the strong suite passes while the
weak suite remains below its threshold. That is the lesson, not a tool error.
The command still writes isolated per-suite reports plus aggregate
`summary.json`, `summary.html`, and `junit.xml`. A technical error would return
exit `2`; a repository whose discovered suites all pass returns `0`.

## Expected lesson

The exact score is part of the generated report and depends on the pinned
operator and evaluator versions. The intended invariant is:

- both original-rule baselines pass;
- the weak suite leaves meaningful survivors;
- the strong suite kills mutations that remove required fields, lose value
  alternatives, narrow string semantics, or alter the condition.
- a `100%` rule-mutation score and a `100%` event-variation score are separate
  claims and should both be reviewed within their operator/evaluator scope;
- a gap candidate is a match-loss hypothesis for telemetry and backend review,
  not proof of an evasion.

When extending the example, add one fixture at a time and use the mutant diff
to explain which rule decision that event protects.

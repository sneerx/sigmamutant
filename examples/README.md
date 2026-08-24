# Example: encoded PowerShell process detection

This example shows how fixture quality changes a mutation-testing result while
the production rule stays unchanged.

## Files

```text
examples/
├── rules/
│   └── powershell_encoded.yml
├── fixtures/
│   ├── weak.jsonl
│   └── strong.jsonl
├── weak-suite.yml
└── strong-suite.yml
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

## All-in-one repository check

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

When extending the example, add one fixture at a time and use the mutant diff
to explain which rule decision that event protects.

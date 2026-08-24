# GitHub Action

SigmaMutant ships a composite action for enforcing suite-level mutation-score
thresholds in a detection-as-code repository. The action installs the tagged
SigmaMutant source with the release constraint set, runs `sigmamutant check`,
and exposes the aggregate JSON, HTML, and JUnit paths.

After the public `v1.0.0` tag exists, use the pinned release in a detection
repository workflow:

```yaml
name: Detection mutation gate

on:
  pull_request:
    paths:
      - "detections/**"
  push:
    branches: [main]
    paths:
      - "detections/**"

permissions:
  contents: read

jobs:
  mutation-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Mutation-test Sigma fixture suites
        id: sigmamutant
        uses: sneerx/sigmamutant@v1.0.0
        with:
          target: detections
          recursive: "true"
          output: artifacts/sigmamutant

      - name: Preserve mutation evidence
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: sigmamutant-evidence
          path: artifacts/sigmamutant
          if-no-files-found: warn
```

## Inputs

| Input | Required | Default | Meaning |
| --- | --- | --- | --- |
| `target` | yes | — | One suite or a directory containing explicitly named suites |
| `output` | no | `artifacts/sigmamutant` | Aggregate and per-suite evidence root |
| `recursive` | no | `false` | Discover named suite files below nested directories |
| `verbose` | no | `false` | Emit value-free suite, mutant, fixture-result, and artifact progress |
| `python-version` | no | `3.12` | Supported Python version used by the action |

Boolean inputs accept only the exact strings `true` and `false`; any other
value fails closed with exit `2`.

## Outputs

| Output | Default path |
| --- | --- |
| `summary-json` | `artifacts/sigmamutant/summary.json` |
| `summary-html` | `artifacts/sigmamutant/summary.html` |
| `junit-xml` | `artifacts/sigmamutant/junit.xml` |

The paths follow the configured `output` input. Preserve the full directory,
not only the aggregate files, because survivor YAML and unified diffs are stored
beneath each suite's isolated evidence directory.

## Gate semantics

- Exit `0`: every discovered suite completed and met its own threshold.
- Exit `1`: at least one suite completed below its threshold.
- Exit `2`: at least one suite had a technical, input, baseline, or evaluator
  error.

Thresholds remain in each version-controlled suite file. The composite action
does not introduce a second policy source and does not use the optional AI
providers. It executes the deterministic offline core after dependency
installation.

## Trust boundary

Pin the action to an immutable release tag or commit. The action executes code
from the selected SigmaMutant revision, installs its declared Python
dependencies, and reads the target repository's rule/suite/fixture files. It
does not require an API key, send fixture content to a provider, or write back
to the detection inputs. Report artifacts may contain rule logic and synthetic
event values, so apply the repository's normal artifact access and retention
policy.

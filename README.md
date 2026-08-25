# SigmaMutant

**Mutation testing and deterministic event-gap discovery for Sigma rules.**

[![CI](https://github.com/sneerx/sigmamutant/actions/workflows/ci.yml/badge.svg)](https://github.com/sneerx/sigmamutant/actions/workflows/ci.yml)

SigmaMutant makes small, controlled changes to a Sigma rule and runs the
mutated rules against your labelled event fixtures. If a fixture notices the
change, the mutant is *killed*. If every fixture still passes, the mutant
*survives* and points to a test gap or a possibly equivalent rule.

It can also work in the other direction. `sigmamutant gap` keeps the rule
fixed, derives bounded in-memory variations from labelled positive events, and
checks whether the configured evaluator still matches them. A match loss is a
*gap candidate* for human review, not proof of a real-world bypass.

The question is simple:

> We test detections. Who tests the detection tests?

SigmaMutant's core is an offline blue-team quality tool. It does not execute
command lines from events, contact a SIEM, or generate payloads. Rule mutants
and event variations exist only as isolated copies; the input rule, suite, and
fixture files are not modified. Version 1.0 also includes an optional AI
assistant for proposing synthetic fixtures. Its default Ollama provider stays
on loopback; an OpenAI cloud provider remains explicitly opt-in. Local Azuma
evaluation remains the decision boundary.

The two deterministic modes answer different questions:

| Mode | In-memory change | Question |
| --- | --- | --- |
| `run` / `check` | Sigma rule copy | Would the labelled fixtures notice an atomic rule regression? |
| `gap` | Positive event copy | Does this rule retain a match across the shipped, bounded representation hypotheses? |

## Status

The current main branch keeps the intentionally narrow mutation-testing core
and adds a reviewable repository workflow:

- one non-correlation Sigma rule per suite;
- JSONL fixtures labelled with the expected match result;
- six first-order mutation operators;
- four deterministic, inert event-variation operators for gap discovery;
- validation without mutant generation or report writes;
- single-suite mutation runs, event-gap runs, and repository-wide `check`
  aggregation;
- deterministic mutant IDs and reports;
- offline environment diagnostics and a wheel-contained example bootstrap;
- terminal, JSON, HTML, JUnit, YAML, and diff output;
- value-free verbose progress for core mutation runs;
- locally proven AI fixture export, preview, and explicit promotion;
- fail-closed handling for unsupported Sigma constructs.

The optional assistant can propose synthetic events for one surviving mutant.
Ollama is the default provider, using
`qwen3.5:9b-q4_K_M` at `http://127.0.0.1:11434`. Existing fixture event values
are never included in a provider prompt, labels are derived locally, and the
suggestion command never edits fixture input. A separate `apply-fixture`
command re-proves evidence against current inputs, previews the score change by
default, and writes only with explicit `--write`.

The supported subset and the narrower claim boundary for event variations are
documented in
[Limitations and safety](docs/limitations.md). The Sigma `re` modifier is
deliberately unsupported and fails closed before event evaluation to avoid
ReDoS exposure from untrusted regular expressions. SigmaMutant is not a formal
proof of rule correctness: neither a survivor nor a gap candidate is
automatically a vulnerability.

## Install

SigmaMutant supports Python 3.11 and 3.12. For a source installation, clone or
download the repository and open its root directory (the directory containing
`pyproject.toml`, `examples/`, and `scripts/`).

Confirm that a supported interpreter is installed before creating the virtual
environment (`python3.12 --version` on macOS/Linux or `py -3.12 --version` on
Windows). The operating-system Python may be older and should not be reused if
it reports anything outside 3.11–3.12.

On macOS or Linux:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

Use `python3.11` instead if that is your supported interpreter. On Windows
PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
```

Replace `-3.12` with `-3.11` if needed. If the Windows Python launcher (`py`)
is unavailable, use `python` after confirming that it resolves to Python 3.11
or 3.12.

After downloading the validated wheel from a tagged GitHub release, the final
install step on either platform can instead use the artifact directly:

```bash
python -m pip install ./sigmamutant-1.0.0-py3-none-any.whl
```

Verify the installed core without contacting a provider or printing credential
values:

```bash
sigmamutant doctor
```

`doctor` diagnoses the environment after the CLI can start. If Python cannot
import the command at all, run `python -m pip check` and reinstall the wheel;
a command cannot self-diagnose a missing CLI framework dependency.

For a wheel-only installation, create runnable rule-mutation and event-gap
examples without a source checkout:

```bash
sigmamutant init-example my-sigmamutant-example
```

The command refuses to overwrite an existing destination. See the
[wheel-contained example guide](docs/init-example.md).

For local development:

```bash
python -m pip install -e ".[ai,dev]"
```

For a release-demo environment matching the versions used to generate the
bundled evidence, apply the tested direct-dependency constraints:

```bash
python -m pip install -c constraints-demo.txt ".[ai]"
```

`constraints-demo.txt` is a constraints set, not a complete transitive lock.

The Ollama adapter is included in the base install, but the external Ollama
runtime and local model must be installed separately. Pull the default
model before the first suggestion:

```bash
ollama pull qwen3.5:9b-q4_K_M
```

Ollama requires no API key and `--allow-cloud` is not used. After the model is
downloaded, SigmaMutant accepts only the loopback endpoint
`http://127.0.0.1:11434`; non-loopback and cloud-routed Ollama targets fail
closed.

Install the optional OpenAI SDK only when using the OpenAI provider:

```bash
python -m pip install '.[ai]'
```

OpenAI additionally requires `OPENAI_API_KEY` and explicit `--allow-cloud`.
OpenAI does not provide a general-purpose zero-cost path suitable for
SigmaMutant; check current account availability and pricing before choosing
that provider.

## Two-minute demo

From a source checkout, run the complete example flow offline with one
cross-platform Python command (macOS, Linux, or Windows PowerShell):

```bash
python scripts/run_demo.py
```

It treats the weak rule-mutation and ordinary event-gap exit `1` results as
evidence rather than tool errors, proves both strong paths and a strong-only CI
gate, verifies repository aggregation and the checked-in 15-domain evaluation,
then lists every important artifact. Add `--verbose` for value-free progress,
`--quick` for only the two weak/strong comparisons, or `--no-color` for plain
CI logs.

Validate the example suite:

```bash
sigmamutant validate examples/strong-suite.yml
```

Validation checks suite structure, the supported rule subset, and every
baseline label. It does not generate mutants or write report artifacts.

Run the deliberately weak test suite:

```bash
sigmamutant run examples/weak-suite.yml --out artifacts/weak
```

This command intentionally exits `1`: the weak suite scores `46.2%`, below its
`80%` gate. When scripting the demo with fail-fast shell settings, handle that
expected quality failure before continuing.

Inspect the surviving mutants and their unified diffs, then run the stronger
suite:

```bash
sigmamutant run examples/strong-suite.yml --out artifacts/strong
```

The stronger fixtures exercise both image alternatives, both encoded-command
switches, the trusted-parent filter, and negative near misses. They should kill
mutants that the weak suite cannot distinguish.

List the operators shipped in this build:

```bash
sigmamutant operators
sigmamutant gap-operators
```

Now keep the events fixed and compare the ordinary example rule with a
deliberately hardened example rule:

```bash
sigmamutant gap examples/powershell-gap.yml \
  --out artifacts/powershell-gap --verbose

sigmamutant gap examples/powershell-hardened-gap.yml \
  --out artifacts/powershell-hardened-gap --verbose
```

The first command intentionally exits `1`: the rule retains `8` of `12`
deterministic variations (`66.7%`) and leaves four evaluator-scoped gap
candidates. The hardened example retains all `12` (`100.0%`) and exits `0`.
Both use the same ten labelled fixtures and the separate `gap` default
threshold of `1.0`; neither command edits those fixtures or either rule.

One bounded operator replaces `pwsh.exe`'s `-EncodedCommand` token with `-e`
or `-ec`. Those aliases are documented by Microsoft's
[`about_Pwsh`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh?view=powershell-7.6)
reference. The example proves only how the pinned local evaluator handles the
project-authored events and rules. It does not establish that every derived
event is emitted by real telemetry or represents a production evasion.

## Reproducible evaluation

The checked-in evaluation holds 15 synthetic Sigma rules constant while
replacing a two-event baseline-only fixture set with boundary-focused fixtures.
Across 15 normalized log domains, both phases produced 231 scoreable mutants:
the weak suites killed 107 (`46.3%`), while the strong suites killed all 231
(`100.0%`). All 30 baselines passed and no mutant was excluded.

Re-run and byte-verify the complete evidence offline with:

```bash
python scripts/evaluate_corpus.py --verify
```

The [evaluation report](docs/evaluation.md) contains per-case and per-operator
results. [`benchmarks/results.json`](benchmarks/results.json) retains input
hashes and dependency versions; the [corpus README](benchmarks/README.md)
documents provenance and limits. Every corpus input is project-authored,
synthetic, and inert. This controlled fixture-quality evaluation is not a
production precision/recall or whole-Sigma compatibility claim.

A separate external applicability scan pins the public `SigmaHQ/sigma` corpus
at one commit. Of 3,757 rule files, 2,609 (`69.4%`) passed the current
fail-closed evaluator stack and 2,463 (`65.6%`) exposed at least one of 40,603
deterministic mutation sites. This measures rule-subset and operator reach—not
fixture quality or detection accuracy. See the
[method and results](docs/sigmahq-compatibility.md) and
[`benchmarks/sigmahq-compatibility.json`](benchmarks/sigmahq-compatibility.json).
Neither study is an event-gap benchmark. The `8/12` and `12/12` PowerShell
comparison above is a narrow executable example, not a production robustness
evaluation.

## Suite and fixture format

A suite is a small YAML document. Paths are resolved relative to the suite
file.

```yaml
version: 1
rule: rules/powershell_encoded.yml
fixtures: fixtures/powershell.jsonl
fail_under: 0.80
```

Fixtures are newline-delimited JSON. Every row needs a unique `id`, an
`expected` Boolean, and an `event` object:

```json
{"id":"malicious-encoded","expected":true,"event":{"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell.exe -EncodedCommand AAAA"}}
{"id":"benign-shell","expected":false,"event":{"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell.exe -NoProfile"}}
```

A suite must contain at least one positive and one negative fixture. Before
creating rule mutants or event variations, SigmaMutant runs the original rule
against every fixture. Both workflows stop if this baseline does not match all
declared expectations. `gap` then uses only the positive rows as seeds; the
negative rows remain baseline guards. Positive seed event bodies must also be
unique so copying one fixture under another ID cannot reweight the score.

## CLI

```text
sigmamutant doctor
sigmamutant init-example DEST
sigmamutant validate SUITE
sigmamutant run SUITE [--out DIRECTORY] [--fail-under SCORE] [--verbose]
sigmamutant gap SUITE [--out DIRECTORY] [--fail-under SCORE] \
  [--max-variations COUNT] [--verbose]
sigmamutant check TARGET [--out DIRECTORY] [--recursive] [--verbose]
sigmamutant suggest-fixture SUITE --mutant ID [--provider PROVIDER] \
  [--model MODEL] [--candidates COUNT] [--out FILE] [--allow-cloud] [--verbose]
sigmamutant export-fixture EVIDENCE --candidate ID --out FILE [--id FIXTURE_ID] [--force]
sigmamutant apply-fixture SUITE EVIDENCE --candidate ID [--id FIXTURE_ID] [--write]
sigmamutant operators
sigmamutant gap-operators
```

For `run`, `--fail-under` overrides the suite's mutation-score threshold. For
`gap`, it sets a separate event-variation score threshold and defaults to
`1.0`; `gap` does not reuse the suite's `fail_under` value. Both scores are
decimal values from `0.0` to `1.0`, but they measure different things and
should not be compared as one quality percentage.

`gap` also defaults to a hard ceiling of `4096` generated variations. Use
`--max-variations` to choose a different positive integer deliberately; if the
ceiling would be exceeded, the run fails closed with exit `2` instead of
truncating or silently changing the score.

Without `--out`, each suite receives its own `artifacts/<suite-stem>/`
directory for `run`. `gap` defaults to
`artifacts/<suite-stem>-gaps/`, keeping its evidence separate.
`run --verbose` (or `-v`) prints value-free baseline, mutant, fixture-result,
and artifact stages; fixture event bodies are never included. The final
terminal summary always states `RESULT: PASS`, `RESULT: FAIL`, or
`RESULT: ERROR`, and lists surviving mutant IDs with the first deterministic
diff to review plus a clearly labelled optional AI command.

`gap --verbose` likewise omits fixture event bodies and derived values. It
prints seed IDs, stable variation IDs, operator names, event paths, Boolean
outcomes, and artifact stages. The terminal calls non-matching variations gap
candidates and explicitly scopes them to the configured evaluator.

`check` accepts one suite or discovers explicitly named `*-suite.yml`,
`*-suite.yaml`, `*.suite.yml`, and `*.suite.yaml` files in a directory. Add
`--recursive` to include nested directories. It continues after an individual
suite error, isolates each suite's artifacts, and writes aggregate
`summary.json`, `summary.html`, and `junit.xml` evidence beneath `--out`.

Exit codes are stable for CI:

| Code | Meaning |
| ---: | --- |
| `0` | Validation passed, or the selected score met its threshold |
| `1` | A mutation or event-gap run completed below its threshold |
| `2` | Input, baseline, unsupported-rule, or evaluator error |

For `check`, exit `0` means every suite met its gate, exit `1` means at least
one completed suite was below threshold, and exit `2` means at least one suite
had a technical error.

For `gap`, exit `0` means the event-variation score met `gap`'s threshold,
exit `1` means analysis completed below it, and exit `2` covers invalid input,
a baseline mismatch, no applicable safe variations, an evaluator exclusion,
the configured variation ceiling, or an artifact failure. Negative fixtures
are baseline guards; only labelled positive fixtures with unique event bodies
become variation seeds.

For `suggest-fixture`, exit `0` means at least one Azuma-scoped differential
witness was produced, `1` means every proposal was rejected by the local gate,
and `2` means setup, consent, provider, input, or evaluator failure.

## Optional AI fixture assistant

After a run identifies a surviving mutant, v1.0 can ask the default local
Ollama provider for synthetic events that might distinguish it from the
original rule:

```bash
sigmamutant suggest-fixture examples/weak-suite.yml \
  --mutant MUTANT_ID \
  --candidates 1 \
  --out artifacts/ai-suggestion.json
```

This is equivalent to passing
`--provider ollama --model qwen3.5:9b-q4_K_M`. It uses no API key or
cloud-consent flag and connects only to `http://127.0.0.1:11434`.

For OpenAI instead:

```bash
export OPENAI_API_KEY='your-api-key'
sigmamutant suggest-fixture examples/weak-suite.yml \
  --mutant MUTANT_ID \
  --provider openai \
  --model gpt-5.6-luna \
  --candidates 1 \
  --out artifacts/openai-suggestion.json \
  --allow-cloud \
  --verbose
```

For OpenAI, `--allow-cloud` is explicit consent to send rule detection logic,
mutation metadata, and value-free fixture shapes to the cloud provider. The
model only proposes candidate event objects. With either provider,
SigmaMutant rejects a candidate unless local Azuma evaluation makes the
original and mutant produce different results. The `expected` label comes from
the original rule. Fields shared by every existing fixture, together with their
observed JSON types, form a required fixture contract. Local reduction protects
those fields and repeatedly removes other fields until no single additional
field can be deleted while preserving the exact original/mutant result pair.
This is one-minimality under field deletion outside the required contract, not
a claim of globally minimal or realistic telemetry. The CLI defaults to one
candidate and accepts up to three per request.

Existing fixture event values are omitted from the prompt. The input fixture
file is never changed by `suggest-fixture`. `--verbose` (or `-v`) shows secret-safe
pipeline stages, local evaluation and minimization decisions, plus
provider-reported token usage. It never prints the API key, raw prompt, fixture
values, HTTP headers, or raw provider response. The timestamp-free evidence
records provider provenance and usage so the suggestion can be reviewed
without treating model output as deterministic.

An accepted result is an **Azuma-scoped differential witness**. It is not proof
of production detection correctness, and its telemetry realism remains
unverified. One verified fixture is guaranteed to kill only its selected
mutant; it may improve the score without taking the whole suite above its
configured threshold.

Review and promote a verified candidate through an explicit local workflow:

```bash
sigmamutant export-fixture artifacts/ai-suggestion.json \
  --candidate VERIFIED_CANDIDATE_ID \
  --out artifacts/verified-candidate.jsonl

sigmamutant apply-fixture examples/weak-suite.yml \
  artifacts/ai-suggestion.json \
  --candidate VERIFIED_CANDIDATE_ID
```

Replace `VERIFIED_CANDIDATE_ID` with an ID marked `verified` in the command's
terminal table or evidence JSON; providers choose candidate IDs and they are
not assumed to be `candidate-1`.

`export-fixture` writes a standalone review proposal and never changes a suite.
`apply-fixture` also defaults to preview: it verifies evidence hashes,
regenerates the current mutant, reproduces the recorded result pair, validates
the fixture schema and uniqueness, and shows the projected mutation score. Only
the same command with `--write` atomically appends the fixture to the
suite-configured JSONL corpus. Promotion refuses user-controlled symlink path
components and aborts if suite, rule, or fixture bytes change during or after
preview. Human review remains the commit boundary.

Read [AI Fixture Assistant](docs/ai-fixture-assistant.md) before enabling
either provider, especially if rule logic is sensitive.

## Event-gap operators

`sigmamutant gap` starts with the same baseline contract as `run`: every
positive and negative fixture must produce its declared result. It then creates
first-order variations from positive fixtures only and evaluates each copy
against the unchanged rule.

| Operator | Bounded in-memory variation |
| --- | --- |
| `ascii_case` | Swap ASCII letter case in one rule-referenced `Image` or `ParentImage` field whose value-sensitive string predicate is not `cased` |
| `command_line_whitespace` | Normalize or expand separators between existing, quote-aware `CommandLine` tokens without changing token or payload bytes |
| `telemetry_path_to_basename` | Collapse a referenced `Image` or `ParentImage` path to its unchanged final basename |
| `pwsh_encoded_alias` | For a conservatively shaped `pwsh.exe` command with a final lexical Base64 token, replace one documented `-EncodedCommand`, `-e`, or `-ec` alias while preserving every other byte |

The event-variation score is:

```text
                         variations still matched
variant score = ------------------------------------------------
                 variations still matched + gap candidates
```

An evaluator exception is excluded from the denominator and makes the run exit
`2`; it cannot increase the score. A score of `100%` means only that the rule
retained every generated variation under the pinned evaluator and current
operator set. The operators do not establish semantic equivalence, production
telemetry availability, backend behavior, or a real-world false-negative rate.

## Mutation operators

Each mutant contains exactly one atomic change.

| Operator | Example defect model |
| --- | --- |
| Delete selector predicate | Remove one field check from a selector map |
| Delete list alternative | Remove one value from a multi-value match |
| Narrow string modifier | Change `contains`, `startswith`, or `endswith` to exact matching |
| Require all values | Change an OR-style value list so every value is required |
| Swap condition connective | Change one condition `and` to `or`, or `or` to `and` |
| Remove condition negation | Remove one condition-level `not` |

Invalid mutants, duplicates, and mutants equivalent to the original serialized
rule are excluded from the score. The original rule is never modified.

Read [Methodology](docs/methodology.md) for mutation semantics and score
interpretation.

## Reports

`sigmamutant run` writes a self-contained evidence bundle beneath `--out`:

```text
artifacts/
├── report.json
├── report.html
├── junit.xml
└── survivors/
    ├── <stable-mutant-id>.yml
    └── <stable-mutant-id>.diff
```

The reports record:

- killed and surviving mutants;
- the operator, YAML path, and before/after values for each mutation;
- the fixtures that killed each mutant;
- mutation score and threshold result;
- hashes of the input rule, suite, and fixtures;
- relevant dependency versions.

Artifacts are deterministic for identical inputs and recorded dependency
versions. Reports intentionally omit wall-clock timestamps so runs can be
compared and reviewed in source control.

Repository-wide `check` adds aggregate evidence while retaining the same
per-suite bundle:

```text
artifacts/
├── summary.json
├── summary.html
├── junit.xml
└── <suite-stem>/
    ├── report.json
    ├── report.html
    ├── junit.xml
    └── survivors/
```

`sigmamutant gap` writes a separate, value-safe bundle:

```text
artifacts/<suite-stem>-gaps/
├── gap-report.json
├── gap-report.html
└── gap-junit.xml
```

These reports contain fixture IDs, stable variation IDs, operator and field
provenance, match status, claim-scope text, hashes of the source/replacement
values and complete derived event, input hashes, and dependency versions. They
deliberately omit raw fixture-derived source values, replacement values, and
event bodies. Fixture IDs and the rule title can still contain sensitive names,
so review the bundle before publishing it.

For identical input bytes and dependencies, the gap reports are deterministic
and contain no wall-clock timestamp. An `escaped` status in machine evidence is
rendered as a gap candidate in the CLI: it means only that the configured local
evaluator changed from match to no-match for that bounded variation.

## Interpreting a survivor

A survivor means only that the current fixture set did not distinguish that
mutant from the original rule. Review it in this order:

1. Read the YAML diff and operator provenance.
2. Decide whether the mutation is semantically equivalent for your telemetry.
3. If it is not equivalent, add the smallest positive or negative fixture that
   exposes the difference.
4. Re-run the suite and keep the fixture as a regression test.

Do not describe every survivor as a bypass, exploit, or security vulnerability.
Mutation testing measures the sensitivity of the fixture suite within the
supported evaluator semantics.

## Interpreting a gap candidate

A gap candidate means that a labelled positive seed matched the original rule
but one shipped, deterministic event variation did not. Review it in this
order:

1. Read the operator, changed event path, claim scope, and hashes in the gap
   report.
2. Decide whether that representation can actually be emitted by the relevant
   sensor and ingestion path.
3. Confirm the behavior in the target backend; the local evaluator is not a
   SIEM integration test.
4. If the distinction is meaningful, change the rule manually and add reviewed
   positive and negative fixtures before running both `gap` and `run` again.

Do not publish a candidate as an evasion, bypass, product weakness, or
production false negative. SigmaMutant intentionally does not repair the Sigma
YAML or turn a derived event into executable activity.

## Design

SigmaMutant separates parsing, mutation, evaluation, and reporting. After one
shared baseline, the two deterministic lanes move in opposite directions:

```text
suite + rule + fixtures
          |
          v
 baseline validation
          |
          +-------------------------------+
          |                               |
          v                               v
 atomic rule-copy mutants       positive event-copy variations
          |                               |
          v                               v
 killed / survived                 detected / gap candidate
          |                               |
          +---------------+---------------+
                          v
             terminal + deterministic reports
```

See [Architecture](docs/architecture.md) for component boundaries and
reproducibility rules.

## Responsible use

SigmaMutant is designed for defensive engineering:

- use synthetic, anonymized, or appropriately handled event fixtures;
- review survivor diffs as test-design evidence;
- review gap candidates as evaluator-scoped representation hypotheses;
- do not publish real environment details embedded in fixtures;
- do not use the output to claim an unverified evasion or product weakness.

The tool never executes strings contained in events. `gap` creates bounded
event copies in memory but never rewrites the input JSONL. Core commands
require no network access. `suggest-fixture` never changes fixture input, and
`apply-fixture` is a no-write preview unless `--write` is supplied after local
reproof. The optional assistant uses either loopback-only Ollama or the
explicitly authorized OpenAI cloud path. More detail is in
[Limitations and safety](docs/limitations.md).

## Prior art and positioning

SigmaMutant is not a general telemetry obfuscator, Sigma rule generator, or ML
evasion detector. Projects such as Ordeal, SPECTRA, AMIDES, SigmaOptimizer,
Atomic Red Team, and Sigma evaluation tools address adjacent problems.
SigmaMutant's narrow contribution is a two-axis, deterministic review workflow:

```text
Sigma rule + labelled fixtures
          -> atomic rule mutants
          -> killed/survived evidence
          -> mutation score for CI

Sigma rule + labelled positive seeds
          -> bounded inert event variations
          -> detected/gap-candidate evidence
          -> separate event-variation score
```

See [Prior art](docs/prior-art.md) for a transparent comparison and citations.

## Project documentation

- [Methodology](docs/methodology.md)
- [Architecture](docs/architecture.md)
- [AI Fixture Assistant](docs/ai-fixture-assistant.md)
- [Limitations, safety, and ethics](docs/limitations.md)
- [Prior art](docs/prior-art.md)
- [Controlled evaluation](docs/evaluation.md)
- [SigmaHQ applicability study](docs/sigmahq-compatibility.md)
- [Reusable GitHub Action](docs/github-action.md)
- [Wheel-contained example bootstrap](docs/init-example.md)
- [Example walkthrough](examples/README.md)
- [Changelog](CHANGELOG.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).

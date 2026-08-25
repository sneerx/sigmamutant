# Architecture

SigmaMutant's core is a local command-line pipeline with explicit boundaries
between input validation, Sigma semantics, deterministic rule or event-copy
generation, evaluation, and report rendering. Rule mutation and event-gap
analysis share the same suite and baseline contract but have independent
operators, scores, thresholds, and evidence. The optional fixture assistant is
provider-selectable: Ollama is loopback-only and default, while OpenAI remains
an explicit cloud path. Neither deterministic scoring path depends on a model.

## Data flow

```text
suite.yml
   |
   +--> rule.yml ---------> parse and supported-subset validation
   |
   +--> fixtures.jsonl ---> fixture schema validation
                                   |
                                   v
                         baseline event evaluation
                                   |
                              pass | fail --> stop (exit 2)
                                   v
                  +----------------+----------------+
                  |                                 |
                  v                                 v
       rule mutation discovery           positive-seed discovery
                  |                                 |
                  v                                 v
      clone rule -> mutate -> validate   clone event -> bounded variation
                  |                                 |
          deduplicate and sort                deduplicate and sort
                  |                                 |
                  v                                 v
       evaluate every rule mutant       evaluate every event variation
                  |                                 |
                  v                                 v
          killed / survived             detected / gap candidate
                  |                                 |
                  +----------------+----------------+
                                   v
                         terminal + machine reports
```

`validate` stops after supported-subset and baseline evaluation. It does not
generate mutants, calculate a mutation score, or write run artifacts. `run`
and `gap` reuse the same validation path before entering their separate
execution lanes. `check` aggregates rule mutation only; it does not implicitly
run event-gap analysis.

## Repository check flow

`check` discovers only explicitly named suite files, sorts them by relative
path, and gives each suite an isolated artifact directory. With `--recursive`,
nested directories are included without following directory symlinks.

```text
suite file or repository directory
              |
              v
 explicit deterministic discovery
              |
              v
 per-suite run + isolated evidence
              |
              +--> quality failure: retain and continue
              `--> technical error: retain and continue
              |
              v
 summary.json + summary.html + aggregate junit.xml
```

Aggregate exit `0` means every suite passed, `1` means at least one completed
suite missed its threshold, and `2` means at least one suite had a technical
error. Technical errors take precedence so CI cannot mistake a broken run for a
normal quality-gate failure.

## Component boundaries

### Suite loader

The loader resolves rule and fixture paths relative to the suite, validates the
suite schema, and preserves hashes of the exact input bytes. It does not
silently coerce strings into Booleans or ignore unknown structural errors.

### Rule validator

pySigma provides parsing and structural validation. SigmaMutant then applies a
supported-subset gate before baseline execution. This gate rejects constructs
that the event evaluator cannot implement faithfully.

### Evaluator adapter

The evaluator adapter is the only component that maps a parsed Sigma detection
to an in-memory event result. Keeping the adapter narrow makes conformance
tests possible and leaves room for future evaluator implementations.

Evaluation is pure data processing:

```text
parsed rule + JSON event -> Boolean match
```

There is no command execution, network request, live query, or backend
translation in this core path.

### Rule-mutation registry

Each operator exposes:

- a stable machine name;
- a human-readable description;
- discovery of applicable YAML/AST paths;
- generation of one changed rule per mutation point;
- provenance containing the path and before/after value.

The registry gives `sigmamutant operators` and the runner the same source of
truth.

### Event-variation registry

The separate event registry gives `sigmamutant gap-operators` and the gap
runner one source of truth. Its four operators work only on copies of labelled
positive fixtures:

- ASCII case only for value-sensitive, non-`cased` `Image` or `ParentImage`
  predicates;
- quote-aware `CommandLine` separator normalization or expansion;
- referenced `Image` or `ParentImage` path collapse to basename;
- documented `pwsh.exe` encoded-command aliases.

The last operator recognizes only `-EncodedCommand`, `-e`, and `-ec` after a
small allowlist of full no-value switches and immediately before one final
lexical Base64 token. These aliases are listed in Microsoft's
[`about_Pwsh`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh?view=powershell-7.6)
reference. It does not decode, alter, or execute that token.

Every operator records a field, RFC 6901 event path, human description,
claim-scope statement, before/after values, and complete derived event in the
in-memory domain object. The value-safe reporters retain only hashes for those
fixture-derived values.

### Mutant validator

Generated candidates pass through parse validation, supported-subset
validation, normalized equality checks, and duplicate checks before they can
enter the score.

The original rule object and original file are immutable inputs. Every
operator works on an isolated copy.

### Runner

The runner coordinates baseline evaluation, mutant evaluation, classification,
and threshold comparison. Domain result objects are kept separate from Rich
terminal rendering so CLI presentation cannot change scoring behavior.

The gap runner separately coordinates positive-seed variation generation,
evaluation against the unchanged rule, `detected`/`escaped`/`excluded`
classification, and comparison with the event-variation threshold. It never
passes event values to the rule-mutation runner or AI provider.

The gap runner rejects duplicate positive event bodies and applies a
configurable generation ceiling (`4096` by default). Exceeding the ceiling is
a technical error; partial enumeration is never scored.

### Report writers

All formats receive the same completed run model:

- `report.json` is the canonical machine-readable record;
- `report.html` is a standalone reviewer view with embedded styling and data;
- `junit.xml` maps survivors or the threshold result into CI-visible tests;
- mutant YAML and unified diffs provide review evidence.

Repository checks additionally produce aggregate JSON, standalone HTML, and
JUnit while retaining every suite's ordinary report bundle.

Report writers sort records by stable mutant ID and avoid current-time fields.

Gap analysis has its own value-safe writers:

- `gap-report.json` is the canonical machine-readable record;
- `gap-report.html` is the standalone reviewer view;
- `gap-junit.xml` maps the separate variant-score gate into CI evidence.

They include fixture IDs, operator/path/claim provenance, statuses and hashes,
but omit raw source values, replacement values, and derived event bodies.

### Optional AI fixture assistant

`suggest-fixture` is a separate orchestration path:

```text
suite -> deterministic mutant lookup -> prompt builder
                                         |
                         fixture shapes only; no event values or IDs
                                         |
                                         v
                                  provider adapter
                                    /         \
                                   v           v
                         Ollama loopback    OpenAI cloud
                        127.0.0.1:11434   + --allow-cloud
                                   \           /
                                    v         v
                              untrusted event candidates
                                         |
                                         v
                            local Azuma differential gate
                                         |
                                         v
                          local deterministic minimization
                                         |
                                         v
                              ai-suggestion.json evidence
                                         |
                          +--------------+--------------+
                          v                             v
              export-fixture JSONL          apply-fixture preview
                                                        |
                                                  explicit --write
                                                        |
                                                        v
                                             atomic fixture append
```

The provider is a proposal mechanism, not an evaluator. The prompt builder
includes rule and mutation context plus deduplicated fixture shapes: field
names, JSON types, and `expected` classes. It omits fixture IDs and event
values. The selected provider process still receives detection logic: the
local Ollama service or, with explicit consent, OpenAI.

The Ollama adapter defaults to `qwen3.5:9b-q4_K_M` over
`http://127.0.0.1:11434`. It requires no API key or `--allow-cloud` and rejects
non-loopback, HTTPS, credential-bearing, path-bearing, and cloud-routed Ollama
targets. The OpenAI adapter defaults to `gpt-5.6-luna` and requires both
`OPENAI_API_KEY` and `--allow-cloud`.

Candidate parsing accepts event data only. Each candidate is evaluated against
the original and selected mutant with the same local Azuma adapter used by the
core. A candidate becomes an Azuma-scoped differential witness only when the
two results differ. Its `expected` value is the original-rule result, never a
provider-supplied label.

Fields present in every existing fixture form a required contract with their
observed JSON types. Candidates outside that contract fail closed. The reducer
protects those fields and repeatedly removes other fields in stable order only
while the exact original/mutant Boolean pair remains unchanged. The result is
one-minimal under non-required field deletion, not globally minimal telemetry.
It makes no provider calls. Suggestion evidence does not update the suite or
fixture JSONL.

`export-fixture` materializes one verified row for review without touching a
suite. `apply-fixture` regenerates the current mutant, verifies rule and mutant
hashes, reproduces the exact recorded outcome pair, rejects schema or duplicate
violations, and runs the projected suite. Preview is the default. Only
`--write` appends the row using an atomic replacement, refuses user-controlled
symlink path components, and compares exact suite, rule, and fixture snapshots
again immediately before replacement so concurrent input changes fail closed.

## Stable identities

A stable rule-mutant ID is based on content, not enumeration order:

```text
sha256(
  rule_sha256
  + operator_name
  + yaml_path
  + before_sha256
  + after_sha256
)
```

SigmaMutant displays a collision-resistant 16-hex-character prefix of this
digest in terminal and structured output.

This design lets a reviewer correlate the same mutation across local and CI
runs even when unrelated operators are added later.

An event variation uses the same content-addressed principle with a separate
identity:

```text
sha256(
  rule_sha256
  + source_fixture_id
  + source_event_sha256
  + event_operator_name
  + json_pointer
  + before_sha256
  + after_sha256
  + derived_event_sha256
)
```

The displayed ID is likewise a 16-hex-character digest prefix. Enumeration is
sorted by seed fixture, operator, path, and ID; duplicate derived event bodies
are removed within each seed, and duplicate positive source bodies are rejected
before enumeration.

## Artifact contract

For `run`, `check`, and `gap`, the output directory is the only runtime write
target requested by the user. For a successful single-suite rule-mutation run
it contains:

```text
report.json
report.html
junit.xml
survivors/<id>.yml
survivors/<id>.diff
```

Only survivor evidence needs a standalone YAML file for test-authoring
workflow, although structured reports can retain metadata for every mutant.
Implementations may emit killed-mutant diffs as well if the choice is stable
and documented in `report.json`.

An existing output directory is updated only within these known artifact
names. SigmaMutant does not modify the input rule, suite, or fixtures.

A gap run uses a separate managed namespace:

```text
gap-report.json
gap-report.html
gap-junit.xml
```

Gap evidence includes input hashes, operator names, dependency versions,
stable variation provenance, score, threshold, and claim-boundary text. It
does not serialize raw fixture-derived before/after values or event bodies.
The complete events exist only in memory during analysis; source fixture bytes
remain unchanged.

The optional assistant writes one explicitly named JSON evidence file:

```text
artifacts/ai-suggestion.json
```

Its provenance includes provider, model, provider response ID, the SHA-256 of
the exact prompt, and provider-reported token usage when available. Like core
reports, it omits wall-clock timestamps. An unchanged prompt hash does not
imply identical model output. Ollama records a null response ID; OpenAI retains
the provider response ID alongside locally reproducible evaluation outcomes.

The optional CLI progress callbacks emit typed, deterministic events. The
service and verifier remain terminal-independent. `--verbose` renders only
secret-safe metadata: stage names, counts, Boolean outcomes, hashes, provider
configuration, and token usage. Raw prompts, fixture values, candidate values,
headers, credentials, and provider bodies are excluded.

Gap progress uses the same renderer and emits only suite filenames, counts,
fixture IDs, stable variation IDs, operator names, JSON paths, statuses, and
Boolean match results. It does not emit raw event values.

The Ollama adapter uses JSON mode with the exact output schema embedded in the
system prompt. Streaming and model thinking are disabled; temperature is zero
and `keep_alive` is `0`. These controls reduce variability and release the
model after the request, but they do not make generation authoritative or
guaranteed deterministic. Pydantic enforces the schema again at the local
trust boundary.

For the OpenAI adapter, `store=false` disables API application-state storage
for the response. The adapter pins the official API base URL instead of
honoring an environment endpoint override, fixes the standard service tier,
and disables implicit prompt-cache writes for its one-shot request.
Abuse-monitoring retention and ZDR eligibility or configuration are separate
provider and organization policy concerns.

## Dependency roles

- **pySigma**: Sigma parsing and validation.
- **Azuma**: in-memory event matching behind the evaluator adapter.
- **ruamel.yaml**: controlled YAML round-tripping and mutation artifacts.
- **Pydantic**: model validation used by the Azuma evaluator.
- **Typer and Rich**: CLI and terminal presentation.
- **Ollama adapter**: uses the Python standard library and a separately
  installed local Ollama runtime; no Python extra or credential is required.
- **OpenAI provider client**: installed only with `.[ai]` and imported for an
  explicitly selected OpenAI run.

Dependency versions are recorded in the run evidence because evaluator
semantics are part of reproducibility.

## Failure model

SigmaMutant fails closed:

- malformed suite or fixture: reject;
- baseline mismatch: reject;
- unsupported Sigma construct: reject;
- evaluator exception: reject;
- report write failure: reject;
- below-threshold completed run: quality-gate failure, not execution error.

The event-gap path additionally rejects a corpus without positive seeds and
returns an error when no shipped safe variation applies. An evaluator
exception marks the affected variation `excluded` and makes the whole run exit
`2`; exclusions cannot improve the event-variation score. A completed score
below `gap`'s independent threshold is exit `1`, not a technical error.

The optional suggestion path also fails closed on an unreachable Ollama
service, missing Ollama model, missing OpenAI extra or `OPENAI_API_KEY`, absent
OpenAI cloud consent, unknown mutant, provider failure, malformed provider
output, or a candidate that does not pass the local differential gate. None of
these failures modifies fixture input.

The promotion path additionally fails closed on stale or tampered evidence,
changed rule or mutant hashes, missing required fields, duplicate IDs or
events, a result-pair mismatch, an already-killed target, a projection that
does not kill the selected mutant, a symlinked write path, or fixture bytes
that change during preview or promotion. Without `--write`, successful
promotion remains a read-only preview.

The CLI maps these states to the exit-code contract documented in the README.
No gap failure modifies the rule, suite, or fixture inputs.

## Extension points

Future work can add rule operators, carefully scoped event operators, evaluator
adapters, or reports without changing the suite format. New event operators
must state their claim scope and preserve the inert-data boundary; a broader
obfuscation catalog would be a different product contract. Larger changes—
correlations, multi-document rules, placeholder expansion, automatic repair,
or backend differential testing—need explicit semantic contracts and should
not be enabled by quietly broadening the current parser gate.

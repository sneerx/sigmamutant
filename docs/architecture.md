# Architecture

SigmaMutant's mutation-testing core is a local command-line pipeline with
explicit boundaries between input validation, Sigma semantics, mutation
generation, execution, and report rendering. In v1.0, the optional fixture
assistant is provider-selectable: Ollama is loopback-only and default, while
OpenAI remains an explicit cloud path. Neither moves evaluation or scoring
into the model.

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
                         mutation point discovery
                                   |
                                   v
                      clone -> mutate -> validate
                                   |
                         deduplicate and sort
                                   |
                                   v
                         evaluate every mutant
                                   |
                                   v
                        classify and calculate score
                                   |
                  +----------------+----------------+
                  v                v                v
              terminal      machine reports   survivor evidence
                            JSON/JUnit/HTML      YAML and diff
```

`validate` stops after supported-subset and baseline evaluation. It does not
generate mutants, calculate a mutation score, or write run artifacts. `run`
reuses the same validation path before entering mutation execution.

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

### Mutation registry

Each operator exposes:

- a stable machine name;
- a human-readable description;
- discovery of applicable YAML/AST paths;
- generation of one changed rule per mutation point;
- provenance containing the path and before/after value.

The registry gives `sigmamutant operators` and the runner the same source of
truth.

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

### Report writers

All formats receive the same completed run model:

- `report.json` is the canonical machine-readable record;
- `report.html` is a standalone reviewer view with embedded styling and data;
- `junit.xml` maps survivors or the threshold result into CI-visible tests;
- mutant YAML and unified diffs provide review evidence.

Repository checks additionally produce aggregate JSON, standalone HTML, and
JUnit while retaining every suite's ordinary report bundle.

Report writers sort records by stable mutant ID and avoid current-time fields.

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

## Stable mutant identity

A stable ID is based on content, not enumeration order:

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

## Artifact contract

For `run` and `check`, the output directory is the only runtime write target
requested by the user. For a successful single-suite run it contains:

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

## Extension points

Future work can add operators, evaluator adapters, or reports without changing
the suite format. Larger changes—correlations, multi-document rules,
placeholder expansion, or backend differential testing—need explicit semantic
contracts and should not be enabled by quietly broadening the current parser
gate.

# Limitations, Safety, and Ethics

## Supported Sigma subset

SigmaMutant accepts one ordinary, non-correlation Sigma rule with:

- field-map selectors;
- scalar and scalar-list field values;
- condition-level `and`, `or`, `not`, and parentheses;
- `1 of` and `all of` selector references where supported by the evaluator;
- common event-evaluable string modifiers supported by the pinned evaluator,
  including exact, `contains`, `startswith`, and `endswith`.

Support is intentionally gated by both parsing and evaluator conformance. A
rule that parses successfully is not necessarily supported by the core
evaluator.

## Explicitly unsupported

The following constructs fail closed:

- Sigma correlations;
- multi-document YAML rule files;
- value placeholders and external expansions;
- `expand` and `fieldref` modifiers;
- the `re` modifier and regular-expression matching, to avoid ReDoS exposure
  from untrusted or catastrophically backtracking patterns;
- keyword-only selections;
- lists of maps with ambiguous event semantics;
- backend-specific query behavior;
- live SIEM searches;
- telemetry mutation or command-line obfuscation;
- automatic rule repair;
- combined higher-order mutations.

The error should identify the unsupported construct and its location when
possible. SigmaMutant never substitutes approximate behavior without telling
the user. A rule containing `Field|re` is rejected before baseline event
matching or mutation execution; SigmaMutant does not evaluate its pattern.

## Evaluator boundary

The in-memory evaluator models a useful subset of Sigma matching, not every
backend's field mapping, normalization, tokenization, or query language.

A fixture passing locally does not prove that:

- an endpoint emits the same fields;
- an ingestion pipeline preserves the values;
- a SIEM maps field names identically;
- a backend translator produces equivalent query semantics;
- a production query runs within operational limits.

Use backend-native integration tests alongside SigmaMutant where those
properties matter.

## Mutation score boundary

Mutation score is conditional on:

- the rule;
- the fixture corpus;
- the supported mutation operators;
- evaluator semantics;
- dependency versions.

It is not a universal detection quality percentage. A score of `1.0` means the
fixtures killed all generated, scoreable mutants in this model. It does not
mean the rule detects every real technique or has no false positives.

Different rules can expose different mutation points, so cross-rule score
rankings need careful interpretation.

## Survivor language

A surviving mutant is one of:

- a missing fixture distinction;
- a mutation irrelevant to the available telemetry;
- a semantically equivalent mutant;
- an evaluator limitation;
- a rule decision that deserves human review.

It is not automatically an evasion, bypass, exploit, CVE, or vendor weakness.
An AI-generated candidate does not change that interpretation. Public
reporting should preserve this distinction.

## Runtime safety

Events are untrusted data. SigmaMutant:

- parses event rows as JSON objects;
- treats command lines, paths, scripts, and URLs as inert strings;
- never uses event values as shell arguments;
- never executes a command represented by a fixture;
- makes no network requests in `doctor`, `init-example`, `validate`, `run`,
  `check`, `operators`, `export-fixture`, or `apply-fixture`;
- keeps `run` and `check` writes beneath the selected artifact directory;
- leaves the original rule unchanged;
- leaves fixture input unchanged unless `apply-fixture --write` is explicitly
  requested after a successful local preview and reproof.

The optional `suggest-fixture` command contacts either the loopback-only Ollama
service or, with explicit consent, OpenAI. It still treats every returned
string as inert event data and never changes fixture input. Pulling an Ollama
model is a separate network and disk operation performed before local
inference.

Users should still review fixtures before publication because logs can contain
hostnames, usernames, tokens, internal paths, or customer data.

## AI assistant boundary

The assistant is optional. Ollama support is included in the base package;
only the OpenAI provider needs `.[ai]`. Both have several important
limitations:

- existing fixture IDs and event values are omitted from the provider prompt,
  while field names, JSON types, and expected classes are included;
- the Sigma rule and mutant context are sent and may themselves be sensitive;
- model output can be invalid, irrelevant, unrealistic, or inconsistent;
- a candidate qualifies only as an Azuma-scoped differential witness under the
  pinned local evaluator semantics;
- provider generation is not deterministic;
- a prompt SHA-256 identifies request content but does not reproduce a model
  response;
- local reduction preserves required fixture fields and the exact Boolean
  result pair until it is one-minimal under single non-required field deletion;
  this does not establish telemetry realism or global minimality;
- local inference quality and performance depend on the installed model and
  available machine resources.

### Ollama boundary

Ollama is the default v1.0 provider, using `qwen3.5:9b-q4_K_M` at
`http://127.0.0.1:11434`. It needs no API key or `--allow-cloud`.

SigmaMutant accepts only numeric IPv4 or IPv6 loopback HTTP and rejects DNS
names, alternative numeric spellings, non-loopback hosts, HTTPS, embedded
credentials, queries, fragments, unexpected paths, and Ollama cloud model tags.
This prevents the adapter from being redirected to a remote Ollama target. It
does not secure the local machine: the Ollama process, model files, host access,
local service logs, and other software on that host remain inside the trust
boundary.

Model download uses `ollama pull qwen3.5:9b-q4_K_M`, requiring network access,
storage, and appropriate model-license review. Local output remains untrusted
regardless of model provenance.

### OpenAI boundary

OpenAI requires the optional `.[ai]` dependency, `OPENAI_API_KEY`, and explicit
`--allow-cloud`. Rule detection and mutation context cross the cloud boundary;
fixture IDs and event values remain excluded from the prompt. SigmaMutant
cannot enforce provider retention, regional processing, billing, or enterprise
data-control policies.

The OpenAI adapter pins `https://api.openai.com/v1`, ignoring environment base
URL overrides, and sets `store=false`, which disables API application-state
storage for that response. This does not by itself disable or define
abuse-monitoring retention, and it does not grant Zero Data Retention. Verify
ZDR eligibility/configuration and the applicable organization policy
separately.

OpenAI does not provide a general-purpose zero-cost path suitable for
SigmaMutant. Verify current availability and pricing instead of assuming a free
tier can support this workflow.

Only the local differential gate determines acceptance:

```text
original(event) != mutant(event)
```

The baseline outcome becomes the proposed fixture's `expected` value. The
provider does not assign labels, execute the event, or decide that it should be
committed.

An accepted result is an **Azuma-scoped differential witness**: the original
and mutant differ under the local pinned evaluator for that synthetic event.
Production correctness, backend equivalence, collection behavior, and
telemetry realism remain unverified.

`suggest-fixture` never appends to or rewrites fixture JSONL. Users may export a
verified candidate for review or pass it to `apply-fixture`, which re-proves the
evidence against current inputs and previews the projected score without
writing. Only explicit `apply-fixture --write` atomically appends one fixture.
It rejects stale or tampered evidence, duplicates, schema mismatches, changed
result pairs, symlinked path components, and fixture bytes changed during or
after preview.

Required fixture-contract fields are inferred as the field-name intersection
of the existing corpus, with observed JSON types. They must be present in a
candidate and are protected during local reduction. A reported `one-minimal`
result means no single additional non-required field can be deleted while
preserving the exact original/mutant result pair. It does not prove global
minimality, semantic necessity, or telemetry realism.

## Defensive-use guidance

Appropriate uses include:

- improving unit tests for a detection rule;
- reviewing which selector decisions fixtures actually protect;
- establishing a CI quality gate;
- teaching detection-as-code practices with synthetic logs;
- producing reproducible evidence for rule review.

The project does not include payload generation or telemetry-evasion
functionality. Do not repurpose survivor evidence into unsupported claims about
real environments.

## Data handling

Prefer synthetic fixtures like those in `examples/`. If production-derived
events are necessary:

1. follow your organization's authorization and retention rules;
2. minimize fields to those needed by the rule;
3. remove or pseudonymize personal and customer identifiers;
4. scan artifacts before committing or sharing them;
5. keep output directories under the same access controls as the fixtures.

The standalone HTML report can contain fixture IDs, rule content, and mutation
diffs. Treat it as security engineering evidence, not as a harmless screenshot.
AI suggestion evidence can contain rule-derived context and generated strings;
apply the same controls even though existing fixture event bodies are not sent
to the selected provider process.

Suite-configured rule and fixture paths must be relative, must not contain
parent traversal, and must resolve inside the suite directory. This blocks
absolute-path and symlink escapes; it does not replace normal filesystem access
controls on the repository itself.

Write targets fail closed on user-controlled symlink components and compare
existing destinations by filesystem identity, not path spelling. The only
prefix exceptions are macOS's root-owned `/tmp -> /private/tmp` and
`/var -> /private/var` aliases after their exact targets and ownership are
verified; symlinks below either alias are still rejected. Existing output
names that differ only by case or Unicode normalization, and hardlinked output
files, are also rejected rather than replaced with platform-dependent effects.

## 1.x compatibility contract

Starting with SigmaMutant 1.0, Semantic Versioning applies to the documented
CLI command and option names, suite schema version `1`, exit-code meanings, and
versioned JSON report and evidence schemas. During the 1.x line, additive
commands, options, and fields may be introduced, but removing or reinterpreting
an existing integration surface requires either a new schema version or a new
major SigmaMutant release.

Mutation results may still change in a minor or patch release when an evaluator
bug is corrected, a fail-closed validation gap is fixed, or explicitly new
operators and supported semantics are added. Reproducible evidence therefore
records the exact SigmaMutant and dependency versions. Third-party Python
imports remain outside this compatibility promise; the CLI and serialized
schemas are the supported integration boundary.

## Operational limitations

The core is optimized for a small local suite and reviewer-friendly output.
It does not promise:

- distributed execution;
- incremental caching;
- very large corpus performance;
- predictable local-model latency or resource use;
- stable APIs for third-party Python imports;
- automatic triage of equivalent mutants;
- a hosted UI or multi-user service.

The CLI, suite schema version, exit codes, and report schema are the intended
integration surfaces.

## Reporting problems

When reporting an evaluator mismatch or unsafe behavior, use a minimal
synthetic rule and event whenever possible. Do not attach proprietary rules or
raw customer logs to a public issue.

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
- arbitrary telemetry obfuscation, payload rewriting, payload decoding, or
  user-supplied event-mutation code;
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

## Event-gap score boundary

`sigmamutant gap` creates bounded copies of labelled positive events in memory
and evaluates them against the unchanged rule. Its event-variation score is
conditional on:

- the labelled positive seed events;
- the four shipped event operators and their applicability checks;
- the configured maximum-variation ceiling (default `4096`);
- the original Sigma rule;
- Azuma's local event semantics;
- exact dependency versions.

The operators cover ASCII case only in value-sensitive, non-`cased` `Image` or
`ParentImage` predicates, quote-aware command-line separator shape,
`Image`/`ParentImage` full-path versus basename shape, and three documented
`pwsh.exe` encoded-command aliases behind a conservative token-shape gate.
Microsoft documents
`-EncodedCommand`, `-e`, and `-ec` in
[`about_Pwsh`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh?view=powershell-7.6).
That source supports the alias relationship only. It does not prove that a
particular sensor emits the generated event shape or that the local Sigma
result matches a production backend.

None of the event operators establishes universal semantic equivalence:

- case can be meaningful in fields or environments outside the operator's
  narrow applicability gate;
- command-line parsing rules differ across programs and operating systems;
- a collector may always emit a full path, always emit a basename, or use a
  different field mapping;
- documented `pwsh` aliases do not imply behavior for `powershell.exe` or an
  arbitrary executable.

A `100%` event-variation score therefore means only that every generated,
scoreable variant retained its match under the configured evaluator. It does
not mean the rule has no detection gaps, that production false negatives are
zero, or that the rule is robust against arbitrary adversarial changes. The
event-variation score and rule-mutation score measure different axes and must
not be combined into one percentage.

Each generated variation has equal weight. A seed or operator with more
applicable points contributes more denominator entries, so changing the
fixture mix can change the score. Exact duplicate positive event bodies are
rejected, and generation fails closed rather than truncating when it would
exceed the configured limit; neither control turns cross-rule scores into a
universal ranking.

An `escaped` variation is rendered as a **gap candidate**. It can indicate a
meaningful representation boundary, impossible telemetry, an operator
assumption that does not apply to the environment, a backend difference, or an
evaluator limitation. It is not automatically an evasion, bypass, exploit,
CVE, or vendor weakness.

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
  `gap`, `check`, `operators`, `gap-operators`, `export-fixture`, or
  `apply-fixture`;
- keeps `run`, `gap`, and `check` writes beneath the selected artifact
  directory;
- leaves the original rule unchanged;
- creates `gap` event variations only as in-memory copies;
- leaves fixture input unchanged unless `apply-fixture --write` is explicitly
  requested after a successful local preview and reproof.

The optional `suggest-fixture` command contacts either the loopback-only Ollama
service or, with explicit consent, OpenAI. It still treats every returned
string as inert event data and never changes fixture input. Pulling an Ollama
model is a separate network and disk operation performed before local
inference.

Users should still review fixtures and reports before publication because logs
and fixture IDs can contain hostnames, usernames, tokens, internal paths, or
customer data.

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
- reviewing bounded representation sensitivities in labelled positive events;
- establishing a CI quality gate;
- teaching detection-as-code practices with synthetic logs;
- producing reproducible evidence for rule review.

The project includes only the fixed, bounded, inert event variations documented
above. It does not generate payloads, execute events, provide a general
telemetry-obfuscation framework, or repair rules automatically. Do not
repurpose survivor or gap evidence into unsupported claims about real
environments.

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

Gap JSON, HTML, and JUnit reports omit raw source values, replacement values,
and complete event bodies. They retain fixture IDs, the rule title,
operator/path descriptions, result Booleans, hashes, and dependency metadata.
Hashes are correlators, not anonymization, and low-entropy values may be
guessable. Keep gap artifacts under the same access controls as their source
fixtures and review identifiers before sharing.

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

Rule-mutation and event-gap results may still change in a minor or patch release
when an evaluator bug is corrected, a fail-closed validation gap is fixed, or
explicitly new operators and supported semantics are added. Reproducible
evidence therefore records the exact SigmaMutant and dependency versions.
Third-party Python imports remain outside this compatibility promise; the CLI
and serialized schemas are the supported integration boundary.

## Operational limitations

The core is optimized for a small local suite and reviewer-friendly output.
It does not promise:

- distributed execution;
- incremental caching;
- very large corpus performance;
- predictable local-model latency or resource use;
- stable APIs for third-party Python imports;
- automatic triage of equivalent mutants;
- automatic triage of environment-specific gap candidates;
- a hosted UI or multi-user service.

The CLI, suite schema version, exit codes, and report schema are the intended
integration surfaces.

## Reporting problems

When reporting an evaluator mismatch or unsafe behavior, use a minimal
synthetic rule and event whenever possible. Do not attach proprietary rules or
raw customer logs to a public issue.

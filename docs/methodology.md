# Methodology

## Purpose

Detection teams commonly keep a Sigma rule beside a small set of positive and
negative events. Passing those fixtures proves that the rule currently behaves
as expected for those examples. It does not show either of these properties:

- whether the examples would notice a meaningful defect in the rule;
- whether the rule retains a match across a bounded change in event
  representation.

SigmaMutant addresses the questions with separate scores. Rule mutation
injects one small defect into an in-memory rule copy and asks whether the
fixtures detect it. Event-gap analysis holds the rule fixed, derives bounded
in-memory variations from labelled positive fixtures, and asks whether the
configured evaluator still matches them.

Both outputs are conditional evidence. Neither declares that the original rule
is universally correct, that a variation is semantically equivalent in a real
environment, or that a match loss is an operational bypass.

## Terms

**Baseline:** The unmodified Sigma rule evaluated against all fixtures. Every result must
equal its fixture's `expected` value before mutation begins.

**Mutant:** A copy of the rule containing one atomic detection-document change
made by a named operator.

**Killed mutant:** At least one fixture returns a result different from its
declared expectation when evaluated against the mutant.

**Surviving mutant:** Every fixture continues to return its declared
expectation when evaluated against the mutant.

**Invalid mutant:** A generated document that cannot be parsed or validated. It
is reported as an exclusion and does not affect the score.

**Duplicate mutant:** A generated document whose normalized representation is
identical to another mutant. It is excluded so one semantic change is not
counted twice.

**Original-equivalent serialization:** A mutation candidate whose normalized
rule is identical to the original. It is excluded before execution.

**Event variation:** A deterministic copy of one labelled positive event with
one shipped representation operator applied. The source fixture remains
unchanged.

**Detected variation:** A derived positive event that still matches the
unchanged rule under the configured evaluator.

**Gap candidate:** A derived positive event that no longer matches. Structured
evidence records this status as `escaped`; the public interpretation is an
evaluator-scoped hypothesis requiring telemetry and backend review.

**Excluded variation:** A generated event that the evaluator cannot process.
It is omitted from the score and makes the run fail closed with exit `2`.

## Shared input and baseline contract

### 1. Load and validate inputs

SigmaMutant loads one suite, one rule, and one JSON object per fixture line. It
checks that:

- the suite version is supported;
- referenced paths are relative, contain no parent traversal, and resolve
  inside the suite directory;
- fixture IDs are unique;
- positive fixture event bodies are unique for event-gap scoring;
- `expected` is a Boolean;
- every event is a JSON object;
- at least one positive and one negative fixture exist;
- the rule belongs to the supported Sigma subset.

Unsupported constructs are rejected explicitly. They are never silently
approximated. In particular, the Sigma `re` modifier fails closed before
baseline event matching, rule mutation, or event-variation execution.
Regular-expression matching is outside the supported subset because untrusted
or catastrophically backtracking patterns can create ReDoS risk.

### 2. Establish the baseline

The original rule is evaluated once against each fixture. A mismatch stops the
run with exit code `2`.

This guard matters. Without it, a mutant could appear killed merely because
the starting rule or labels were already inconsistent.

`sigmamutant validate` stops here after supported-input and baseline checks.
It does not enumerate mutants, calculate a mutation score, or write reports.
Use it as the fast preflight; use `run` or `check` for rule-mutation evidence,
or `gap` for event-variation evidence.

## Rule-mutation workflow

### 3. Enumerate rule-mutation points

Each operator walks only the relevant parts of the parsed rule:

1. **Delete selector predicate** removes one field predicate from a selector
   map.
2. **Delete list alternative** removes one entry from a multi-value match.
3. **Narrow string modifier** converts one `contains`, `startswith`, or
   `endswith` field predicate into exact matching.
4. **Require all values** converts one OR-style field value list into
   all-values-required behavior.
5. **Swap condition connective** changes one condition-level `and` to `or`, or
   one `or` to `and`.
6. **Remove condition negation** removes one condition-level `not`.

One candidate is produced for one mutation point. Operators do not combine
changes.

### 4. Normalize and identify rule mutants

The original input bytes are never changed. A mutant is serialized separately
and receives a stable identifier derived from:

- the original rule hash;
- operator name;
- YAML path of the mutation point;
- hashes of the before and after values.

Identical inputs therefore produce identical IDs, filenames, ordering, and
report content.

### 5. Evaluate and classify rule mutants

For every included mutant, SigmaMutant evaluates all fixtures. The mutant is
killed on the first or all recorded expectation deviations, depending on the
report view; the result retains the IDs of fixtures that exposed it.

An event's string fields are treated only as data. SigmaMutant never invokes a
shell, PowerShell, a subprocess described by an event, or an external SIEM.

### 6. Calculate the mutation score

The mutation score is:

```text
                 killed mutants
score = ---------------------------------
         killed mutants + surviving mutants
```

Invalid, duplicate, and original-equivalent candidates are not included in the
denominator.

If no scoreable mutants exist, the run is an evaluation error rather than an
automatic perfect score.

## Event-gap workflow

After the shared baseline succeeds, `sigmamutant gap` uses labelled positive
fixtures as seeds. Negative fixtures are not varied; they remain baseline
guards. The shipped registry creates stable, de-duplicated variations with
four deliberately bounded operators:

1. **ASCII case** changes ASCII letter case only in a rule-referenced `Image`
   or `ParentImage` field whose value-sensitive string expression does not use
   `cased`. Command-line and arbitrary string fields are excluded.
2. **Command-line whitespace** uses conservative quote-aware token spans to
   normalize or expand only the separators between existing tokens. Token
   bytes, order, quoting, and payload bytes do not change.
3. **Telemetry path to basename** collapses one rule-referenced `Image` or
   `ParentImage` path to its unchanged final basename.
4. **pwsh encoded alias** replaces exactly one unambiguous `pwsh.exe`
   `-EncodedCommand`, `-e`, or `-ec` token. Applicability requires only a small
   allowlist of full no-value switches before the alias and one final lexical
   Base64 token; the operator does not decode that token. The executable,
   payload, other tokens, and separators remain unchanged. Microsoft lists
   these aliases in
   [`about_Pwsh`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh?view=powershell-7.6).

The operators produce representation hypotheses, not universal equivalence
claims. They do not decode or create payloads, combine changes, execute the
event, or modify the fixture JSONL.

Each variation receives a stable 16-hex-character ID derived from the original
rule hash, source fixture ID and event hash, operator, JSON event path,
before/after hashes, and complete derived-event hash. Evaluation classifies it
as `detected`, `escaped` (a gap candidate), or `excluded`.

The event-variation score is independent of the rule-mutation score:

```text
                              detected variations
variation score = -------------------------------------------
                    detected variations + gap candidates
```

Excluded variations do not enter the denominator, but any evaluator exclusion
makes the analysis an error. If no safe operator applies, the result is also an
error rather than an automatic perfect score.

Generation has a default ceiling of `4096` variations. The CLI exposes this as
`--max-variations`; attempting to generate one more than the configured limit
is a technical error, not a truncated score. Exact duplicate positive event
bodies are rejected before baseline evaluation so fixture copies cannot
silently reweight the denominator.

The reproducible PowerShell example holds ten fixtures fixed. The ordinary
rule detects `8` of `12` derived variations (`66.7%`) and reports four gap
candidates. The deliberately hardened example detects all `12` (`100.0%`).
These exact results describe only the checked-in synthetic inputs, shipped
operators, and pinned evaluator stack.

## Threshold behavior

For `run`, the suite's `fail_under` value is the default mutation-score
threshold and the CLI `--fail-under` option overrides it for one run. `gap`
uses a separate threshold: its `--fail-under` defaults to `1.0` and does not
read the suite's `fail_under` value.

- score greater than or equal to threshold: exit `0`;
- completed run below threshold: exit `1`;
- validation, baseline, evaluator, or report error: exit `2`.

This distinction lets CI separate a quality-gate failure from a broken run.

For `gap`, input or baseline failure, no applicable safe variations, an
evaluator exclusion, variation-limit exhaustion, or report failure returns
exit `2`. A completed score below the gap threshold returns `1`; a score at or
above it returns `0`.

`sigmamutant check` applies the same contract across all explicitly discovered
suite files under one path. It continues after an individual suite error,
writes per-suite evidence plus aggregate JSON, HTML, and JUnit reports, and
uses deterministic exit precedence:

- any technical suite error: exit `2`;
- otherwise, any completed suite below threshold: exit `1`;
- otherwise, all discovered suites pass: exit `0`.

Discovery is deliberately narrow: `*-suite.yml`, `*-suite.yaml`,
`*.suite.yml`, and `*.suite.yaml`, sorted by relative path. Recursion must be
requested explicitly, and symlinked suite files are not followed.

## What the scores can and cannot say

A higher mutation score shows that the supplied fixtures distinguish more of
the rule-defect models represented by the current operator set. A higher
event-variation score shows that the unchanged rule retains more of the
generated positive-event matches under the current event operators. Neither
score measures:

- production false-positive or false-negative rates;
- telemetry collection quality;
- coverage of all Sigma language constructs;
- equivalence across SIEM backends;
- adversarial robustness outside the supplied fixtures;
- the probability of a real-world bypass.

Scores are most useful when reviewed with survivor diffs or gap provenance and
tracked for the same rule, fixtures, evaluator version, and corresponding
operator set.

Comparing raw scores between unrelated rules can be misleading because their
number and type of rule-mutation and event-variation points differ. The two
scores are not interchangeable even for the same suite.

Within one gap run, every generated variation contributes one denominator
unit. Seeds and operators with more applicable variation points therefore have
more weight. Compare results only with the fixture corpus, applicability set,
operator registry, limit, and dependency versions held constant.

## Building a strong fixture suite

For each selector, include fixtures that isolate its role:

- a positive for each legitimate value alternative;
- a negative that satisfies all but one required predicate;
- a negative that exercises each exclusion or filter;
- values that distinguish substring, prefix, suffix, and exact semantics;
- benign near misses, not only obviously unrelated events.

The example demonstrates this progression:

- `weak.jsonl` contains a minimal exact-looking positive and a distant
  negative;
- `strong.jsonl` uses full paths and command lines, covers both accepted
  shells and switches, isolates each required field, and verifies the trusted
  parent exclusion.

The goal is not to maximize fixture count. It is to add the smallest event that
proves why each important rule decision exists.

## Equivalent mutants

Some syntactically different mutants may be equivalent for a particular data
model or rule. General semantic equivalence is undecidable in the broad case,
so SigmaMutant uses conservative mechanical exclusions only.

When a mutant survives:

1. inspect its diff;
2. decide whether the changed rule can behave differently in supported event
   semantics;
3. mark the conclusion in normal review notes;
4. add a fixture only when a meaningful distinction exists.

SigmaMutant deliberately labels this result `survived`, not `bypass`.

## Gap-candidate review

When a variation loses its match:

1. inspect the operator, event path, claim scope, and hashes;
2. decide whether the representation is possible for the intended sensor and
   ingestion path;
3. reproduce it in the target backend;
4. if meaningful, update the rule manually and add reviewed fixtures;
5. rerun both `gap` and `run` so a wider rule does not introduce untested
   branches or false-positive regressions.

SigmaMutant deliberately calls this result a `gap candidate`, not an evasion,
production false negative, exploit, or vulnerability. It does not repair the
rule automatically.

## Reproducibility

For identical inputs and dependency versions:

- mutation enumeration is stably sorted;
- event-variation enumeration is stably sorted and de-duplicated per seed,
  while duplicate positive seed bodies are rejected;
- IDs use content hashes;
- serialized artifacts use stable ordering;
- reports omit wall-clock timestamps;
- filesystem paths in evidence are normalized relative paths where possible.

Input hashes and dependency versions make environmental differences visible
when comparing runs.

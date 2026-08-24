# Methodology

## Purpose

Detection teams commonly keep a Sigma rule beside a small set of positive and
negative events. Passing those fixtures proves that the rule currently behaves
as expected for those examples. It does not show whether the examples would
notice a meaningful defect in the rule.

SigmaMutant applies mutation testing to that second question. It injects one
small defect into the rule, evaluates the mutant against the same labelled
events, and records whether the suite detected the difference.

The output is evidence about the fixture suite, not a declaration that the
original rule is universally correct.

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

## Workflow

### 1. Load and validate inputs

SigmaMutant loads one suite, one rule, and one JSON object per fixture line. It
checks that:

- the suite version is supported;
- referenced paths are relative, contain no parent traversal, and resolve
  inside the suite directory;
- fixture IDs are unique;
- `expected` is a Boolean;
- every event is a JSON object;
- at least one positive and one negative fixture exist;
- the rule belongs to the supported Sigma subset.

Unsupported constructs are rejected explicitly. They are never silently
approximated. In particular, the Sigma `re` modifier fails closed before
baseline event matching or mutation execution. Regular-expression matching is
outside the supported subset because untrusted or catastrophically
backtracking patterns can create ReDoS risk.

### 2. Establish the baseline

The original rule is evaluated once against each fixture. A mismatch stops the
run with exit code `2`.

This guard matters. Without it, a mutant could appear killed merely because
the starting rule or labels were already inconsistent.

`sigmamutant validate` stops here after supported-input and baseline checks.
It does not enumerate mutants, calculate a mutation score, or write reports.
Use it as the fast preflight; use `run` or `check` when mutation evidence is
required.

### 3. Enumerate mutation points

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

### 4. Normalize and identify

The original input bytes are never changed. A mutant is serialized separately
and receives a stable identifier derived from:

- the original rule hash;
- operator name;
- YAML path of the mutation point;
- hashes of the before and after values.

Identical inputs therefore produce identical IDs, filenames, ordering, and
report content.

### 5. Evaluate and classify

For every included mutant, SigmaMutant evaluates all fixtures. The mutant is
killed on the first or all recorded expectation deviations, depending on the
report view; the result retains the IDs of fixtures that exposed it.

An event's string fields are treated only as data. SigmaMutant never invokes a
shell, PowerShell, a subprocess described by an event, or an external SIEM.

### 6. Score

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

## Threshold behavior

The suite's `fail_under` value is the default threshold. The CLI
`--fail-under` option overrides it for one run.

- score greater than or equal to threshold: exit `0`;
- completed run below threshold: exit `1`;
- validation, baseline, evaluator, or report error: exit `2`.

This distinction lets CI separate a quality-gate failure from a broken run.

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

## What the score can and cannot say

A higher score shows that the supplied fixtures distinguish more of the defect
models represented by the current operator set. It does not measure:

- production false-positive or false-negative rates;
- telemetry collection quality;
- coverage of all Sigma language constructs;
- equivalence across SIEM backends;
- adversarial robustness outside the supplied fixtures;
- the probability of a real-world bypass.

Scores are most useful when reviewed with survivor diffs and tracked for the
same rule, fixtures, evaluator version, and operator set.

Comparing raw scores between unrelated rules can be misleading because their
number and type of mutation points differ.

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

## Reproducibility

For identical inputs and dependency versions:

- mutation enumeration is stably sorted;
- IDs use content hashes;
- serialized artifacts use stable ordering;
- reports omit wall-clock timestamps;
- filesystem paths in evidence are normalized relative paths where possible.

Input hashes and dependency versions make environmental differences visible
when comparing runs.

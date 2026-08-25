# Prior Art and Distinction

SigmaMutant sits between Sigma evaluation, detection regression testing,
software mutation testing, and bounded event-robustness probing. This page
states the relationship directly so the project's novelty is not overstated.

## The specific workflow

SigmaMutant takes:

```text
one Sigma rule + labelled positive/negative event fixtures
```

It exposes two independent deterministic lanes after one baseline check:

```text
rule mutation: fixture corpus held constant -> atomic rule-copy defects
event gap:     rule held constant           -> bounded positive-event copies
```

Rule mutation reports killed and surviving mutants, a mutation score, and
survivor diffs. Event-gap analysis reports detected variations and gap
candidates with a separate event-variation score and value-safe evidence.
The primary objects being assessed are the **test suite's sensitivity to rule
defects** and, separately, the **rule's evaluator-scoped match retention across
the shipped representation hypotheses**.

## Adjacent work

### Ordeal

[Ordeal](https://github.com/principlebreach/ordeal) combines Sigma fixture
testing with an adversarial catalog of telemetry mutations. Its `mutate`
workflow applies documented, semantics-preserving evasion variants to positive
events—including command-line quoting, flag, path, URL, and shell forms—and
reports the variants that stop an otherwise stable rule from matching.

Ordeal overlaps with SigmaMutant's new event-side direction, while
SigmaMutant's rule-mutation lane changes the opposite side of the experiment:

| Tool / mode | Held constant | Copied and changed | Question |
| --- | --- | --- | --- |
| Ordeal `mutate` | Sigma rule | adversarial event telemetry | Does the rule remain effective across catalogued equivalent surface forms? |
| SigmaMutant `run` | labelled fixtures | defender-authored rule detection logic | Would the tests catch an atomic rule regression? |
| SigmaMutant `gap` | Sigma rule | labelled positive fixture event | Does the pinned evaluator retain the match for a fixed, bounded representation hypothesis? |

These workflows remain distinct. Ordeal presents a broader adversarial catalog.
SigmaMutant `gap` ships four conservative, first-order operators over fixture
copies, emits hashes instead of raw derived values, and deliberately labels a
match loss a **gap candidate**, not an evasion. It makes no universal
semantic-equivalence claim. SigmaMutant does not present either its six rule
operators or four event operators as a replacement for Ordeal's telemetry
mutators.

### SPECTRA

[SPECTRA](https://dartlab.org/spectra/) produces behavior-preserving evasive
command variants for Windows Sigma process-creation rules. It explores
telemetry-side command variation and rule evasion.

SigmaMutant does not generate commands or rewrite source telemetry. `run`
changes an in-memory Sigma detection-tree copy using a bounded defect model;
`gap` derives conservative copies from existing positive fixtures. Unlike
SPECTRA, SigmaMutant does not claim those copies are behavior-preserving
evasions, and it does not produce an executable command corpus.

### AMIDES

[AMIDES](https://github.com/fkie-cad/amides) detects evasions of
signature-based detection rules using machine learning. Its research and
implementation focus on identifying samples that are semantically close to
known malicious behavior while evading a rule.

SigmaMutant is deterministic test engineering. It neither trains a model nor
classifies novel command lines as evasions.

### SigmaOptimizer

[SigmaOptimizer](https://github.com/YusukeJustinNakajima/SigmaOptimizer)
generates, validates, and optimizes Sigma rules from logs and obfuscation
techniques. It was presented at Black Hat USA Arsenal 2025.

SigmaMutant starts from an existing rule and its hand-labelled regression
fixtures. It introduces defects into a rule copy to measure whether those
tests protect the intended logic, or applies fixed representation operators to
positive event copies to find evaluator-scoped match losses. It does not
generate, optimize, or automatically repair the production rule.

### Atomic Red Team

[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) provides
small, portable tests that execute adversary techniques for control
validation.

SigmaMutant does not execute techniques. Its JSONL fixtures are inert event
records, making the core workflow suitable for offline unit and CI testing.

### pySigma and event evaluators

[pySigma](https://github.com/SigmaHQ/pySigma) provides the Python processing
pipeline used to parse and convert Sigma rules.
[Azuma](https://github.com/ninoseki/azuma) evaluates Sigma matching against
Python dictionaries.

SigmaMutant relies on these semantic foundations rather than presenting a new
Sigma parser. Its contribution is the shared baseline guard, separate rule and
event operator registries, killed/survived and detected/gap-candidate models,
deterministic evidence, and distinct CI score contracts.

The narrow `pwsh.exe` event operator is grounded in Microsoft's
[`about_Pwsh`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh?view=powershell-7.6)
documentation for `-EncodedCommand`, `-e`, and `-ec`. That reference supports
the alias relationship; it does not establish telemetry emission, backend
equivalence, or a real-world evasion.

### Local Sigma fixture and backtest utilities

[sigma-test](https://github.com/bradleyjkemp/sigma-test) runs Sigma rules
against test cases.
[detkit](https://github.com/ELSATOAH/detkit) provides local Sigma fixture unit
testing and related detection-engineering workflows.
[RSigma](https://github.com/timescale/rsigma) includes a `rule backtest`
workflow that evaluates rules against an event corpus and can emit JUnit
results for CI.

These tools exercise the original rule against supplied events. That is
SigmaMutant's shared baseline. From there, SigmaMutant can generate first-order
defects in a parsed rule copy to test fixture sensitivity, or generate a fixed
set of inert positive-event copies to test evaluator-scoped match retention.
The latter overlaps with event robustness work and is not claimed as a new
category by itself.

### Live Atomic and SIEM regression testing

[SCYTHE's sigma-regression-testing](https://github.com/scythe-io/sigma-regression-testing)
supports regression testing by running Atomic-style activity and checking the
result through a live SIEM workflow.

That provides end-to-end evidence across execution, telemetry collection, and
the target detection backend. SigmaMutant has a narrower offline boundary: it
does not execute the activity or query a SIEM. It evaluates inert event
fixtures locally while first-order-mutating either a rule copy or, in `gap`, a
positive event copy. The source inputs remain unchanged. These approaches
answer complementary questions, and only the live workflow validates the
actual collection and backend path.

### sigmalint

[sigmalint](https://github.com/ni5h4nt/sigmalint) performs deterministic
static validation and quality scoring for Sigma rules. It checks the rule
itself across documented quality dimensions.

SigmaMutant measures different dynamic objects: fixture-corpus sensitivity to
rule defects and bounded match retention for positive-event variations. It
does not replace static rule-quality scoring, and a high score in either
SigmaMutant lane is not a universal rule-quality grade.

## Research motivation

Detection rules change over time, and many edits alter detection logic rather
than metadata alone. A 2026 empirical study of thousands of Sigma and Splunk
rule histories reported substantial logic evolution:

- [Evolution of Log-Based Detection Rules in Public
  Repositories](https://arxiv.org/abs/2605.05383) — Minjun Long and David Evans,
  arXiv:2605.05383.

That observation motivates regression-test quality, but it does not by itself
validate SigmaMutant's operators or score. The project should publish its own
operator-level evaluation and reproducibility data as it matures.

## Novelty claim, kept narrow

In a literature and project review refreshed on 2026-08-25, the maintainers
did not identify an open-source tool exposing this exact combined contract:

```text
Sigma rule + labelled fixtures
  -> one baseline for every positive and negative label
  -> lane A: first-order Sigma detection-tree copies
             -> killed/survived + diffs + CI mutation score
  -> lane B: fixed, inert positive-event copies
             -> detected/gap-candidate + value-safe CI variation score
```

The novelty claim is about the combined review contract, not event mutation,
Sigma evaluation, or software mutation testing individually. It is not a legal
novelty or trademark opinion. New related work should be added here and
acknowledged in release notes.

## Design lessons borrowed from software mutation testing

SigmaMutant follows established mutation-testing principles:

- use small, first-order mutations;
- exclude invalid and duplicate candidates from the score;
- keep the source rule and fixture files unchanged;
- treat equivalent mutants as a known interpretation problem;
- combine a numeric score with inspectable survivor evidence.

The security-specific work is defining defensible Sigma defect models and
conservative event-representation hypotheses, evaluating both with the same
local event semantics, and keeping their scores and claims separate.

# Prior Art and Distinction

SigmaMutant sits between Sigma evaluation, detection regression testing, and
software mutation testing. This page states the relationship directly so the
project's novelty is not overstated.

## The specific workflow

SigmaMutant takes:

```text
one Sigma rule + labelled positive/negative event fixtures
```

It then mutates the rule's parsed detection logic one atomic defect at a time,
runs the existing fixtures, and reports killed and surviving mutants with a
mutation score and survivor diffs.

The primary object being assessed is the **test suite's sensitivity to rule
defects**.

## Adjacent work

### Ordeal

[Ordeal](https://github.com/principlebreach/ordeal) combines Sigma fixture
testing with an adversarial catalog of telemetry mutations. Its `mutate`
workflow applies documented, semantics-preserving evasion variants to positive
events—including command-line quoting, flag, path, URL, and shell forms—and
reports the variants that stop an otherwise stable rule from matching.

Ordeal and SigmaMutant both expose gaps that ordinary fixture execution can
miss, but they change opposite sides of the experiment:

| Tool | Held constant | Mutated | Question |
| --- | --- | --- | --- |
| Ordeal | Sigma rule | attacker-controlled event telemetry | Does the rule remain effective across equivalent surface forms? |
| SigmaMutant | labelled event fixtures | defender-authored rule detection logic | Would the tests catch an accidental rule regression? |

These workflows are complementary. Ordeal measures rule robustness against a
catalog of evasions; SigmaMutant measures fixture-suite sensitivity against a
catalog of rule defect models. SigmaMutant does not present its current six
operators as a replacement for Ordeal's telemetry mutators.

### SPECTRA

[SPECTRA](https://dartlab.org/spectra/) produces behavior-preserving evasive
command variants for Windows Sigma process-creation rules. It explores
telemetry-side command variation and rule evasion.

SigmaMutant does not generate commands or modify telemetry. It changes the
parsed Sigma detection tree using a bounded defect model and asks whether
labelled fixtures notice.

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
fixtures. It introduces defects into the rule to measure whether those tests
protect the intended logic; it does not generate or optimize the production
rule.

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
Sigma parser. Its contribution is the mutation-operator registry, baseline
guard, killed/survived model, deterministic evidence, and CI score contract.

### Local Sigma fixture and backtest utilities

[sigma-test](https://github.com/bradleyjkemp/sigma-test) runs Sigma rules
against test cases.
[detkit](https://github.com/ELSATOAH/detkit) provides local Sigma fixture unit
testing and related detection-engineering workflows.
[RSigma](https://github.com/timescale/rsigma) includes a `rule backtest`
workflow that evaluates rules against an event corpus and can emit JUnit
results for CI.

These tools exercise the original rule against supplied events. That is the
first half of SigmaMutant's workflow. The distinguishing second half generates
first-order defects in the parsed Sigma rule and tests whether the existing
fixture corpus detects each change.

### Live Atomic and SIEM regression testing

[SCYTHE's sigma-regression-testing](https://github.com/scythe-io/sigma-regression-testing)
supports regression testing by running Atomic-style activity and checking the
result through a live SIEM workflow.

That provides end-to-end evidence across execution, telemetry collection, and
the target detection backend. SigmaMutant has a narrower offline boundary: it
does not execute the activity or query a SIEM. It evaluates inert event
fixtures locally while first-order-mutating the Sigma rule itself. The two
approaches answer complementary questions.

### sigmalint

[sigmalint](https://github.com/ni5h4nt/sigmalint) performs deterministic
static validation and quality scoring for Sigma rules. It checks the rule
itself across documented quality dimensions.

SigmaMutant measures a different object: the sensitivity of a user's labelled
fixture corpus. It mutates the detection document, executes each valid mutant
against those fixtures, and emits killed/survived evidence. The two approaches
are complementary.

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

In a literature and project review refreshed on 2026-08-24, the maintainers
did not identify an open-source tool exposing this exact end-to-end contract:

```text
Sigma rule + labelled fixtures
  -> first-order Sigma detection-tree mutants
  -> baseline-guarded fixture execution
  -> killed/survived classification
  -> deterministic survivor evidence and CI mutation score
```

This is not a legal novelty or trademark opinion. New related work should be
added here and acknowledged in release notes.

## Design lessons borrowed from software mutation testing

SigmaMutant follows established mutation-testing principles:

- use small, first-order mutations;
- exclude invalid and duplicate candidates from the score;
- keep the original program—in this case, the rule—unchanged;
- treat equivalent mutants as a known interpretation problem;
- combine a numeric score with inspectable survivor evidence.

The security-specific work is defining defensible Sigma defect models and
evaluating them with event semantics.

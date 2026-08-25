# Changelog

All notable changes to SigmaMutant are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-08-25

### Added

- Deterministic `gap` analysis that baseline-validates one existing suite,
  derives bounded in-memory variations from labelled positive events, evaluates
  them against the unchanged rule, and applies a separate event-variation score
  and threshold with stable `0`/`1`/`2` exit semantics.
- Four fixed event operators for value-sensitive process-path ASCII case,
  quote-aware command-line separator shape, referenced `Image`/`ParentImage`
  basename shape, and conservatively gated documented `pwsh.exe`
  `-EncodedCommand` / `-e` / `-ec` aliases, plus a `gap-operators` discovery
  command.
- Timestamp-free, value-safe `gap-report.json`, `gap-report.html`, and
  `gap-junit.xml` evidence with stable variation IDs, source fixture and field
  provenance, claim-scope text, value/event hashes, input hashes, and dependency
  versions.
- A synthetic PowerShell event-gap example that reproducibly compares one
  labelled corpus against an ordinary rule (`8/12`, `66.7%`) and a deliberately
  hardened rule (`12/12`, `100.0%`).
- Duplicate-positive-seed rejection and a configurable, fail-closed variation
  ceiling (`4096` by default) so copied fixtures or partial enumeration cannot
  silently reweight a gap score.
- An offline, secret-safe `doctor` command that verifies the supported Python
  runtime and core dependency versions while reporting optional OpenAI/Ollama
  readiness without network probes or credential values.
- A wheel-contained `init-example` command that creates deterministic,
  self-contained weak/strong rule-mutation and event-gap examples without
  network access or overwriting an existing destination.
- Repository-wide `check` command with explicit suite-name discovery, optional
  recursive traversal, isolated per-suite artifacts, aggregate JSON/HTML/JUnit
  evidence, and stable `0`/`1`/`2` CI exit semantics.
- A validation-only execution path: `validate` now checks suite structure,
  supported rule semantics, and baseline labels without generating mutants or
  writing mutation reports.
- Value-free `run --verbose` and `check --verbose` progress for rule validation,
  baseline fixtures, mutant execution, artifact writes, and final status.
- Fixture-contract-aware AI proposals. Fields common to the existing corpus and
  their observed JSON types are required, while deterministic repeated field
  deletion produces a one-minimal witness outside those protected fields.
- `export-fixture` for review-only JSONL proposals and `apply-fixture` for
  current-input reproof, projected-score preview, and explicit atomic promotion
  only when `--write` is supplied.
- Repository security, contribution, conduct, issue, pull-request, Ruff lint
  and format, package smoke-test, and multi-platform CI documentation and
  gates.
- A checked-in 15-domain paired fixture-quality evaluation with 231 scoreable
  mutants, input hashes, dependency provenance, canonical JSON/Markdown
  evidence, and offline CI verification.
- A reproducible applicability scan over 3,757 files at a pinned
  `SigmaHQ/sigma` revision, including fail-closed rejection categories and
  per-operator totals without redistributing upstream rules.
- A tag-gated release-validation workflow with version matching, distribution
  hygiene, clean-wheel smoke testing, checksums, and artifact upload.
- A reusable composite GitHub Action for repository mutation gates with
  recursive discovery, value-free progress, and aggregate evidence paths.
- A credential-isolated, fully offline `scripts/run_demo.py` example runner
  that understands intentional quality-gate exits, checks every artifact, and
  closes both deterministic weak-to-strong comparisons.

### Changed

- Expanded the public product contract from rule-only mutation testing to two
  explicitly separate deterministic axes: rule mutation tests fixture quality,
  while event variation stress-tests the unchanged rule within a narrow
  evaluator scope.
- Namespaced the default `run` output beneath `artifacts/<suite-stem>/`, added
  explicit terminal `PASS`/`FAIL`/`ERROR` status, and printed survivor IDs with
  a review-oriented next command.
- Extended AI evidence with original proposal data, exact result-pair proof,
  required-field provenance, reduction policy, and minimality scope.
- Rendered workspace paths relatively and home paths with `~` to avoid exposing
  local usernames in normal terminal and verbose output.

### Security

- Kept event variations inert and in memory: `gap` never executes event strings,
  decodes or creates payloads, calls a provider, or modifies rule, suite, or
  fixture inputs.
- Omitted raw fixture-derived source values, replacement values, and complete
  event bodies from gap terminal output and report bundles; evaluator exclusions
  and zero-applicability runs fail closed instead of increasing the score.
- Restricted suite child paths to relative files inside the suite directory,
  rejecting absolute paths, parent traversal, and symlink escapes.
- Rejected the Sigma `re` modifier before baseline event matching or mutation
  execution so untrusted regular expressions cannot introduce ReDoS exposure.
- Pinned OpenAI traffic to the official API endpoint even when an environment
  override is present; strengthened Ollama to numeric loopback endpoints and
  rejected ambiguous URL forms and cloud-routed model tags.
- Added evidence hash and current-mutant revalidation, duplicate and schema
  checks, symlink-component refusal, owner-only POSIX evidence permissions,
  compare-before-write suite/rule/fixture snapshots, and atomic fixture writes
  to the explicit promotion workflow.
- Compared existing destinations by filesystem identity to block
  case-insensitive aliases of protected inputs while narrowly accepting the
  immutable macOS `/tmp` and `/var` system aliases. Non-portable case/Unicode
  aliases and hardlinked outputs now fail closed before replacement.
- Prevented normalized suite names from sharing a batch artifact namespace;
  collisions now receive stable path-derived suffixes before any run writes.
- Made JSONL fixtures and AI evidence reject duplicate object keys and
  non-standard numeric constants, and routed report bundles through guarded
  atomic replacements.
- Added explicit Hatch exclusions so dotenv files, local credentials,
  artifacts, distributions, virtual environments, caches, and coverage output
  cannot enter source or wheel distributions.

## [0.4.0] - 2026-07-23

### Added

- Secret-safe `suggest-fixture --verbose` / `-v` progress for suite loading,
  provider boundaries, local evaluation, minimization, and artifact writing.
- Provider-reported input, output, total, cache, and reasoning token usage in
  verbose output and evidence JSON when available.
- Explicit fail-closed handling for unexpected OpenAI response statuses and
  provider safeguard refusals.

### Changed

- Made `gpt-5.6-luna` the OpenAI default for the cost-sensitive one-candidate
  fixture workflow.
- Bounded OpenAI requests with low reasoning and text verbosity, standard
  service tier, disabled implicit prompt-cache writes, `store=false`, and no
  SDK retries.
- Aligned provider schema limits more closely with the local 4 KiB event gate:
  at most 16 fields and 512 characters per string.
- Require providers to return exactly the requested candidate count.
- Redact API-key-shaped values from OpenAI error messages.

## [0.3.0] - 2026-07-23

### Added

- Local Ollama fixture-suggestion provider using JSON mode plus strict local
  schema validation over the loopback-only endpoint
  `http://127.0.0.1:11434`.
- Provider-specific default model selection, with
  `qwen3.5:9b-q4_K_M` for Ollama.
- Fail-closed rejection of non-loopback, credential-bearing, path-bearing, and
  cloud-routed Ollama targets.

### Changed

- Made Ollama the default `suggest-fixture` provider.
- Made one proposal the default per provider request; up to three remain
  available explicitly.
- Limited `--allow-cloud` and `OPENAI_API_KEY` requirements to the OpenAI
  provider; local Ollama requires neither.
- Updated the AI assistant, architecture, safety, and usage documentation for
  local and cloud provider boundaries.

## [0.2.0] - 2026-07-23

### Added

- Optional `ai` installation extra and `suggest-fixture` workflow for
  provider-generated synthetic event candidates.
- OpenAI provider configuration through `OPENAI_API_KEY`, with explicit model
  and candidate-count selection.
- Required `--allow-cloud` acknowledgement before rule and mutation context can
  cross the provider boundary.
- Privacy boundary that omits all existing fixture event values from provider
  prompts.
- Deterministic local Azuma gate requiring each differential witness to
  distinguish the original rule from the selected mutant.
- Baseline-derived `expected` labels and deterministic local field
  minimization.
- Timestamp-free JSON evidence containing provider, model, response ID, and
  prompt SHA-256 provenance.
- OpenAI Responses requests use `store=false` for API application-state
  storage; provider retention and ZDR policy remain organization-controlled.
- Human-review boundary: suggestions never modify input fixture files.

### Changed

- Clarified that the mutation-testing core remains offline while only the
  optional AI suggestion command uses network access.

## [0.1.0] - 2026-07-23

### Added

- Offline mutation-testing runner for single-document Sigma rules.
- Baseline validation against labelled JSONL positive and negative fixtures.
- Six first-order rule mutation operators.
- Stable mutant identifiers, duplicate removal, and invalid-mutant filtering.
- Mutation score threshold suitable for local use and CI.
- Terminal summary plus deterministic JSON, standalone HTML, JUnit XML, YAML,
  and unified-diff artifacts.
- Fail-closed validation for unsupported Sigma constructs.
- Weak and strong PowerShell process-creation example suites.
- Methodology, architecture, safety, prior-art, and demo documentation.

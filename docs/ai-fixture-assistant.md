# AI Fixture Assistant

SigmaMutant v1.0 provides an optional assistant that proposes **synthetic event
candidates** for one surviving mutant. Ollama is the default, local provider;
OpenAI remains an explicit cloud option. In both cases, the model proposes data
and SigmaMutant's local evaluator decides whether that data is useful.

The assistant does not change mutation scoring or replace Azuma. The
`suggest-fixture` command never edits fixture input. Separate `export-fixture`
and `apply-fixture` commands provide a reviewable promotion path; fixture bytes
change only after an explicit `apply-fixture --write`. The `doctor`,
`init-example`, `validate`, `run`, `check`, `operators`, `export-fixture`, and
`apply-fixture` commands remain fully offline.

## Provider choices

| Provider | Default model | Transport | Credential | Cloud consent |
| --- | --- | --- | --- | --- |
| Ollama (default) | `qwen3.5:9b-q4_K_M` | Loopback HTTP at `http://127.0.0.1:11434` | None | Not used |
| OpenAI | `gpt-5.6-luna` | OpenAI Responses API | `OPENAI_API_KEY` | `--allow-cloud` required |

The model is never the correctness oracle. Provider output follows the same
untrusted-data parser and local Azuma differential gate.

## Install

### Ollama: default local path

The Ollama adapter uses Python's standard library and is included in the base
SigmaMutant install. Install the external Ollama runtime separately, then pull
the default model:

```bash
ollama pull qwen3.5:9b-q4_K_M
```

Start the local service if it is not already running:

```bash
ollama serve
```

The model download requires network access and local disk space. After it is
present, fixture-suggestion requests stay on the loopback-only endpoint
`http://127.0.0.1:11434`. Ollama needs no API key and no `--allow-cloud`.

### OpenAI: opt-in cloud path

Install the optional OpenAI SDK:

```bash
python -m pip install '.[ai]'
```

The OpenAI provider reads its credential only from `OPENAI_API_KEY`:

```bash
export OPENAI_API_KEY='your-api-key'
```

Do not put the key in a suite, command-line option, output artifact, or source
control. OpenAI also requires explicit `--allow-cloud`.

OpenAI does not provide a general-purpose zero-cost path suitable for
SigmaMutant. Check current account availability and pricing before selecting
the cloud provider; do not design a demo around an assumed free tier.

## Workflow

First run the ordinary mutation suite and choose a survivor ID from
`report.json` or a filename in `survivors/`:

```bash
sigmamutant run examples/weak-suite.yml --out artifacts/weak
```

This example run intentionally exits `1` because the weak suite is below its
threshold; that quality result still produces the survivor evidence used by
the next step.

Then request one synthetic candidate from the default local provider:

```bash
sigmamutant suggest-fixture examples/weak-suite.yml \
  --mutant MUTANT_ID \
  --candidates 1 \
  --out artifacts/ai-suggestion.json
```

`--out` names one evidence file, not an artifact directory. This suggestion
step never modifies the input suite or its fixture JSONL.

The command defaults to:

```text
--provider ollama --model qwen3.5:9b-q4_K_M
```

No API key or cloud-consent flag is involved.

To use OpenAI instead:

```bash
sigmamutant suggest-fixture examples/weak-suite.yml \
  --mutant MUTANT_ID \
  --provider openai \
  --model gpt-5.6-luna \
  --candidates 1 \
  --out artifacts/openai-suggestion.json \
  --allow-cloud \
  --verbose
```

For a quick demo, `--mutant first` selects the first surviving ID in stable
sort order. For real test authoring, review the diff and pass its exact ID.

`--allow-cloud` is mandatory only for the OpenAI provider. It is an explicit
acknowledgement that rule detection logic, mutation metadata, and value-free
fixture shapes cross a cloud boundary. Possessing an API key alone is not
treated as consent for that disclosure. Omit the flag for Ollama; its adapter
never leaves loopback.

The command follows this boundary:

```text
suite + selected mutant
          |
          v
value-free fixture shapes + required-field contract
          |
          +--> Ollama: HTTP loopback 127.0.0.1:11434
          |
          `--> OpenAI: cloud request, only with --allow-cloud
                              |
                              v
                       synthetic candidates
                              |
                              v
                local schema validation and Azuma gate
                              |
                              v
             deterministic contract-preserving reduction
                              |
                              v
                   timestamp-free JSON evidence
                       /                  \
                      v                    v
          export one-line JSONL       apply preview
                                           |
                                           v
                              explicit --write promotion
```

## What is sent to the provider

The request contains the rule and mutant context needed to describe the
distinction, including detection logic and mutation provenance. The selected
provider therefore sees the Sigma detection content: the local Ollama process
for the default path, or OpenAI for the explicitly authorized cloud path.

SigmaMutant does **not** place the existing fixture event values in the prompt.
It sends a deduplicated structural summary containing existing field names,
their JSON types, and the associated `expected` class, but no fixture ID or
event value. This gives the model a telemetry shape without copying raw event
bodies from the suite.

The request also derives a fixture contract from fields present in every
existing event shape. Each required field carries the scalar JSON types
observed for it. Provider candidates must include those fields using one of the
allowed types; the local reducer is not allowed to delete them.

This is not a general secrecy guarantee: rule logic, field names, literal
detection values, labels, the selected model, and generated content can still
be sensitive.

Core mutation runs do not call any model provider. `suggest-fixture` uses
loopback HTTP for Ollama or an external network request for OpenAI.

The Ollama adapter is deliberately local-only. It targets
`http://127.0.0.1:11434` and rejects non-loopback hosts, HTTPS endpoints,
embedded credentials, unexpected paths, and Ollama cloud-routed model tags.
No prompt is sent to an Ollama cloud model. The local Ollama process still
receives and processes the rule context, so its host and logs remain part of
your trust boundary.

The OpenAI adapter pins requests to the official
`https://api.openai.com/v1` endpoint rather than honoring an environment URL
override. It sends the Responses API request with `store=false`. This
disables API application-state storage for that response; it is not a blanket
retention guarantee. Abuse-monitoring retention and Zero Data Retention (ZDR)
eligibility or configuration are separate controls. Confirm the provider and
organization policy that applies to your OpenAI project before enabling the
command. See OpenAI's current [data controls documentation][openai-data].

## What the model is allowed to do

The provider returns proposed event objects only. It does not decide:

- whether a candidate distinguishes the rules;
- whether the event should be positive or negative;
- which fields are necessary;
- whether a fixture should be added to the suite;
- whether a survivor represents a real-world bypass.

Provider output is untrusted data. SigmaMutant accepts only strictly structured
flat fields with direct JSON scalar values; nested objects, arrays, duplicate
fields, non-finite numbers, and oversized strings are rejected. It never
executes strings inside the response and subjects each candidate to local
checks. Ollama runs in JSON mode with the exact schema embedded in the system
prompt, then Pydantic validates the response locally. OpenAI requests the same
schema through the provider's
[Structured Outputs contract][openai-structured].

The v1.0 safety envelope caps provider input at 32 KiB, a request at three
candidates, a candidate at 16 fields, a serialized event at 4 KiB, and each
string value at 512 characters. Oversized input fails closed.

## Verbose observability

Pass `--verbose` or `-v` to see deterministic progress lines while the command
runs. The trace covers suite loading, baseline mutation testing, survivor
selection, provider request and response boundaries, candidate parsing,
original-versus-mutant evaluation, every minimization trial, the final verdict,
artifact writing, and provider-reported token usage.

Verbose output is intentionally secret-safe. It does not print
`OPENAI_API_KEY`, environment variables, the raw system prompt, rule detection
values, existing fixture values, candidate event values, HTTP headers, or the
raw provider response. Candidate strings remain untrusted data and are written
only to the explicitly named evidence artifact after schema validation.

The OpenAI path uses low reasoning effort and low text verbosity, forces the
standard service tier, disables implicit prompt-cache writes for the one-shot
request, sets `store=false`, and performs no SDK retries. These are bounded
cost and privacy controls, not a guarantee of a particular charge.

## Deterministic differential gate

For every candidate, SigmaMutant evaluates the event locally against:

1. the unmodified baseline rule; and
2. the selected mutant.

The candidate is rejected unless the two Boolean results differ:

```text
original(event) != mutant(event)
```

This is the key trust boundary. A fluent model response cannot become an
Azuma-scoped differential witness unless the pinned evaluator semantics
reproduce the claimed distinction.

The fixture's `expected` label is derived from the baseline result:

```text
expected = original(event)
```

The model cannot supply or override that label. For example:

- original `true`, mutant `false` produces a positive fixture candidate;
- original `false`, mutant `true` produces a negative fixture candidate.

## Local field minimization

After a candidate passes the differential gate, SigmaMutant reduces its event
fields locally in a stable order. Fields in the derived fixture contract are
protected. Any other field is removed only when the smaller event preserves
the exact original result pair, not merely any disagreement:

```text
(original(candidate), mutant(candidate))
```

The reducer repeats stable, greedy deletion passes until no single remaining
non-required field can be deleted while preserving that pair and the fixture
contract. The evidence calls this **one-minimal over non-required fields**.

This process is:

- local: no minimization round-trip is sent to the provider;
- deterministic: the same accepted candidate and evaluator version produce
  the same minimized event;
- contract-preserving: fields common to every existing fixture shape remain
  present with an observed scalar JSON type;
- direction-preserving: the baseline and mutant Boolean outcomes remain
  exactly the same after every accepted removal.

Minimization reduces irrelevant synthetic context. It does not prove that the
remaining event is globally minimal or realistic for a specific telemetry
pipeline. A multi-field deletion could still succeed even when no individual
field deletion does.

Throughout the artifact, `verified: true` means only that the event is an
**Azuma-scoped differential witness** for this original/mutant pair. It does
not verify production detection correctness, collection behavior, backend
translation, or telemetry realism.

## Evidence file

The generated `artifacts/ai-suggestion.json` contains the accepted and rejected
candidate evidence needed for review. Provider provenance includes at least:

- provider name;
- model name;
- provider response ID;
- SHA-256 digest of the exact prompt;
- selected mutant ID;
- locally derived baseline and mutant outcomes;
- the provider proposal and its canonical event hash;
- the reduction algorithm, protected fields, removed fields, and minimality
  scope;
- the minimized synthetic event and proof hashes for each accepted candidate.

The artifact contains no wall-clock timestamp. It also never contains
`OPENAI_API_KEY`; Ollama requires no credential.

The stable top-level structure is:

```json
{
  "schema_version": 1,
  "mutant": {
    "id": "MUTANT_ID",
    "operator": "delete_list_item",
    "path": "detection.selection.Image|endswith[1]"
  },
  "provider": {
    "name": "ollama",
    "model": "qwen3.5:9b-q4_K_M",
    "response_id": null,
    "prompt_sha256": "64_HEX_CHARACTERS"
  },
  "summary": {
    "requested": 3,
    "received": 3,
    "verified": 1,
    "rejected": 2
  },
  "suggestions": [
    {
      "candidate_id": "candidate-1",
      "verified": true,
      "proposal": {
        "event": {
          "CommandLine": "pwsh.exe -EncodedCommand SYNTHETIC",
          "Image": "C:\\Synthetic\\pwsh.exe",
          "IrrelevantField": "remove-me",
          "User": "SYNTHETIC\\analyst"
        },
        "event_sha256": "64_HEX_CHARACTERS",
        "baseline_match": true,
        "mutant_match": false
      },
      "reduction": {
        "result": "reduced",
        "algorithm": "stable-greedy-field-deletion",
        "policy": "preserve-exact-pair-and-fixture-contract",
        "minimality": "one-minimal",
        "minimality_scope": "non-required-fields",
        "required_fields": ["CommandLine", "Image", "User"],
        "removed_fields": ["IrrelevantField"]
      },
      "proof": {
        "claim_scope": "azuma",
        "telemetry_realism": "unverified",
        "rule_sha256": "64_HEX_CHARACTERS",
        "mutant_sha256": "64_HEX_CHARACTERS",
        "event_sha256": "64_HEX_CHARACTERS",
        "baseline_match": true,
        "mutant_match": false,
        "distinguishes": true
      },
      "event": {
        "CommandLine": "pwsh.exe -EncodedCommand SYNTHETIC",
        "Image": "C:\\Synthetic\\pwsh.exe",
        "User": "SYNTHETIC\\analyst"
      },
      "fixture": {
        "id": "ai-MUTANT_ID-candidate-1",
        "expected": true,
        "event": {
          "CommandLine": "pwsh.exe -EncodedCommand SYNTHETIC",
          "Image": "C:\\Synthetic\\pwsh.exe",
          "User": "SYNTHETIC\\analyst"
        }
      }
    }
  ]
}
```

The full artifact also retains the rule title, suite filename, mutation
before/after provenance, provider rationale, and a rejection reason when a
candidate fails. Ollama emits `response_id: null`; OpenAI records the provider
response ID when one is supplied.

The prompt digest establishes which request content produced the evidence
without pretending that model generation is deterministic. The provider,
model, response ID, and prompt hash together identify the generation context;
the local Azuma outcomes establish why a candidate was accepted.

Generated suggestion artifacts may contain rule-derived and provider-generated
values, so `artifacts/` is intentionally ignored by source control. Review and
retain evidence according to your organization's data-handling policy rather
than committing live provider responses to the project repository.

## Reviewing and promoting a suggestion

An Azuma-scoped differential witness is still a proposal. First export one
verified candidate as a reviewable one-line JSONL file without touching the
suite:

```bash
sigmamutant export-fixture artifacts/ai-suggestion.json \
  --candidate VERIFIED_CANDIDATE_ID \
  --out artifacts/verified-candidate.jsonl
```

Use the actual ID marked `verified` in the terminal table or evidence JSON.
The earlier `candidate-1` value is illustrative; provider-selected IDs may
differ.

Then inspect the proposal and ask SigmaMutant to re-prove it against the
current rule, mutant, evaluator, fixture contract, and suite. Preview is the
default and performs no write:

```bash
sigmamutant apply-fixture examples/weak-suite.yml \
  artifacts/ai-suggestion.json \
  --candidate VERIFIED_CANDIDATE_ID
```

The preview verifies the evidence and event hashes, rejects duplicate IDs and
events, confirms the current baseline is healthy, confirms the target mutant
still survives, reproduces the recorded Boolean pair, and projects that the
new fixture kills that mutant. Only after review should an engineer repeat the
command with `--write`:

```bash
sigmamutant apply-fixture examples/weak-suite.yml \
  artifacts/ai-suggestion.json \
  --candidate VERIFIED_CANDIDATE_ID \
  --write
```

Before promotion:

1. confirm the event is synthetic and contains no unexpected sensitive data;
2. inspect the selected mutant diff;
3. verify that the derived `expected` label expresses the rule's intended
   behavior;
4. check that the minimized fields are plausible for the chosen logsource;
5. confirm the generated fixture ID is unique and rename it if a more
   descriptive ID is useful by passing `--id`;
6. review the exported JSONL and successful promotion preview;
7. use `--write` only on the intended fixture corpus, then run
   `sigmamutant validate` and `sigmamutant run` again.

`--write` atomically appends exactly one fixture row and preserves the fixture
file's mode. It refuses user-controlled symlink output path components and
binds exact suite, rule, and fixture snapshots, checking them again immediately
before replacement. Human review and the explicit write flag remain the commit
boundary.

Killing the selected mutant does not imply that one proposal will satisfy the
suite-wide score threshold. Other surviving mutants can still require separate
fixtures; the projected score in the preview makes that distinction explicit.

## Failure and rejection cases

`suggest-fixture`, `export-fixture`, and the default `apply-fixture` preview
produce no fixture-file change. The workflow also fails closed when:

- the local Ollama service is unavailable;
- the selected Ollama model has not been pulled;
- the OpenAI extra or `OPENAI_API_KEY` is missing for an OpenAI run;
- OpenAI is selected without `--allow-cloud`;
- the provider or model request fails;
- the mutant ID does not exist or is not eligible;
- the response is not valid structured candidate data;
- a candidate does not make the baseline and mutant disagree;
- a candidate cannot pass local event validation.

Promotion additionally fails if the evidence is stale or malformed, hashes no
longer match, the ID or event is duplicated, the current fixture contract is
not satisfied, the baseline is unhealthy, the mutant no longer survives, the
recorded result pair cannot be reproduced, or the projected suite does not
kill the selected mutant. It also rejects symlinked path components and a
fixture corpus that changes while proof or promotion is in progress.

Candidate rejection is a normal result, not evidence that the survivor is
equivalent. A model may simply fail to propose the required boundary event.
`--candidates` defaults to 1 and accepts between 1 and 3 proposals per request.
The provider must return exactly the requested count or the call fails closed.

## Reproducibility boundary

The local parts of the workflow are deterministic:

- mutant regeneration and lookup;
- Azuma evaluation;
- expected-label derivation;
- contract derivation and one-minimal field reduction;
- evidence re-proof and promotion preview;
- evidence serialization and prompt hashing.

The model-generation step is not assumed to be deterministic, including with a
local model. Repeating the same command can return different candidates even
when the prompt hash is unchanged. OpenAI can also return a different response
ID. Pin the provider and model name and retain the evidence file when a
suggestion influences a test change.

## Security and privacy checklist

- Use the assistant only when exposing rule logic to the selected provider
  process is authorized.
- Keep Ollama bound to loopback and use only locally installed, non-cloud model
  tags.
- Pass `--allow-cloud` only after OpenAI disclosure is authorized.
- Keep OpenAI requests on the pinned official API endpoint.
- Use synthetic suites where possible.
- Confirm existing fixture event values are absent from the provider prompt.
- For OpenAI, keep `OPENAI_API_KEY` in the environment and out of logs and
  shell history.
- Treat provider output as untrusted data.
- Review `export-fixture` output and a successful `apply-fixture` preview before
  using `--write`.
- Keep the fixture corpus out of symlinked or untrusted paths.
- Review generated strings for secrets, personal data, URLs, and internal
  naming before committing them.
- Do not execute generated command lines or scripts.
- Describe `verified: true` as an Azuma-scoped differential witness only.
- State that production correctness and telemetry realism remain unverified.
- For OpenAI, consult current retention, regional processing, and enterprise
  data-control terms; SigmaMutant cannot enforce those policies.
- For Ollama, secure the local host, process, model files, and any service logs.

## Why AI is optional

Generating a separating event can require reasoning across several predicates,
modifiers, and Boolean branches. A model can accelerate that brainstorming,
but it is not part of the differential oracle.

The design therefore keeps the boundary asymmetric:

```text
AI proposes.
Azuma proves a scoped difference.
The engineer decides.
```

Teams that cannot send rule logic to an external service can use the
loopback-only Ollama provider, subject to their local model policy, or skip AI
entirely. The core workflow still supports manual survivor review and fixture
authoring without any model.

[openai-data]: https://developers.openai.com/api/docs/guides/your-data
[openai-structured]: https://developers.openai.com/api/docs/guides/structured-outputs

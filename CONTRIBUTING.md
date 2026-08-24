# Contributing to SigmaMutant

SigmaMutant welcomes focused fixes, tests, documentation improvements, and
well-defined mutation operators. The project deliberately keeps its Sigma
subset and trust boundaries narrow; changes that broaden semantics need tests
and explicit documentation.

## Development setup

Use Python 3.11 or 3.12:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[ai,dev]"
```

Run the same core checks used by CI:

```bash
python -m ruff check .
python -m ruff format --check .
pytest --cov=sigmamutant --cov-report=term-missing
sigmamutant validate examples/strong-suite.yml
sigmamutant run examples/strong-suite.yml --out artifacts/strong
```

The test suite must not require an API key, a running Ollama service, a SIEM, or
network access. Provider behavior should be exercised through local fakes at
the adapter boundary.

## Change expectations

- Add or update tests for behavior changes and failure paths.
- Preserve deterministic ordering, IDs, and timestamp-free evidence.
- Keep fixtures synthetic and never commit credentials or production logs.
- Fail closed when evaluator semantics are unsupported or ambiguous.
- Treat provider output as untrusted data and keep local verification
  authoritative.
- Update the README, limitations, methodology, and changelog when their
  contracts change.
- Keep each pull request focused and explain the user-visible effect.

For a new mutation operator, document its defect model, prove that every mutant
contains one atomic change, cover invalid and duplicate candidates, and add a
fixture demonstrating a killed and a surviving case where practical.

## Pull requests

Before opening a pull request:

1. run `ruff check` and the Ruff formatting check;
2. run the full test suite on a supported Python version;
3. run the weak-to-strong example when mutation or evaluator behavior changes;
4. inspect generated artifacts for nondeterminism and sensitive data;
5. describe compatibility or schema impact in the pull request;
6. add a changelog entry for user-visible changes.

By contributing, you agree that your contribution is provided under the
project's Apache License 2.0.

## Security reports

Do not disclose suspected vulnerabilities in an issue or pull request. Follow
[SECURITY.md](SECURITY.md) and use the repository's private reporting channel.

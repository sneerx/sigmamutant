# Security Policy

SigmaMutant handles detection logic and event-shaped data, so reports may
contain information that should not be disclosed in a public issue.

## Supported versions

| Version | Security fixes |
| --- | --- |
| `1.0.x` | Supported |
| `0.x` | Not supported |

Security fixes target the latest supported `1.0.x` release and the default
development branch. This table is updated when the support policy changes.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or attach proprietary
Sigma rules, production logs, API keys, provider responses, or customer data.

Use the repository's **Security → Report a vulnerability** form. If the private
form is unavailable, ask the maintainer for a private reporting channel without
including sensitive technical details.

Include only the information needed to reproduce the issue:

- affected SigmaMutant version or commit;
- operating system and Python version;
- a minimal synthetic rule, suite, and event fixture;
- observed and expected behavior;
- impact and any known preconditions.

Relevant reports include unintended command execution, writes outside an
explicit output path, path traversal, secret disclosure, unsafe handling of
provider output, or a fail-open evaluator boundary. Model quality disagreements
and unsupported Sigma constructs are ordinary bug reports unless they cross a
documented security boundary.

The maintainers will acknowledge reports through the private channel, validate
the impact, coordinate a fix and disclosure, and credit reporters who want to
be named. Please allow time for a release before publishing technical details.

## Scope and data handling

Use synthetic inputs when reporting. SigmaMutant treats fixture strings as
data, but generated JSON, HTML, YAML, and diff artifacts can still reproduce
rule logic, fixture identifiers, and provider-generated values. Sanitize every
attachment and rotate any credential that may have been exposed.

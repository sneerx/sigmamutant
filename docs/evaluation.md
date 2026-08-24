# Reproducible evaluation

This document is generated from `benchmarks/manifest.json` by `python scripts/evaluate_corpus.py --verify`. It reports measurements produced by the deterministic SigmaMutant engine; no AI provider is used.

## Scope

The corpus contains **15 paired rules** across **15 log domains**. Every event and rule is synthetic and inert. The corpus is a deterministic operator/fixture-quality evaluation, not a claim about production detection rates.

Data classification: `synthetic-inert-no-production-telemetry`.

## Aggregate result

| Metric | Weak fixtures | Strong fixtures |
| --- | ---: | ---: |
| Suites | 15 | 15 |
| Fixtures | 30 | 107 |
| Scoreable mutants | 231 | 231 |
| Killed | 107 | 231 |
| Survived | 124 | 0 |
| Excluded | 0 | 0 |
| Weighted mutation score | 46.3% | 100.0% |

All **30** suite baselines passed. The rule bytes remained identical in all **15** pairs; only fixtures changed. **15** pairs improved, and **15** strong suites reached 100%.

## Per-case result

| Case | Domain | Weak | Strong | Delta | Weak/strong fixtures |
| --- | --- | ---: | ---: | ---: | ---: |
| `windows-powershell` | Windows process creation | 46.2% | 100.0% | +53.8% | 2/6 |
| `linux-download-pipe` | Linux process creation | 44.4% | 100.0% | +55.6% | 2/7 |
| `web-path-traversal` | Web access logs | 46.2% | 100.0% | +53.8% | 2/7 |
| `dns-tunnel` | DNS query logs | 50.0% | 100.0% | +50.0% | 2/6 |
| `windows-run-key` | Windows registry events | 47.1% | 100.0% | +52.9% | 2/7 |
| `cloud-audit-disable` | Cloud audit logs | 50.0% | 100.0% | +50.0% | 2/7 |
| `authentication-spray` | Authentication logs | 40.0% | 100.0% | +60.0% | 2/8 |
| `macos-osascript` | macOS process creation | 44.4% | 100.0% | +55.6% | 2/7 |
| `container-privileged-exec` | Container runtime audit | 42.9% | 100.0% | +57.1% | 2/8 |
| `proxy-bulk-upload` | Network proxy logs | 46.2% | 100.0% | +53.8% | 2/7 |
| `email-disk-image` | Email gateway logs | 47.1% | 100.0% | +52.9% | 2/7 |
| `database-bulk-export` | Database audit logs | 47.1% | 100.0% | +52.9% | 2/8 |
| `kubernetes-secret-read` | Kubernetes audit logs | 47.1% | 100.0% | +52.9% | 2/8 |
| `identity-privileged-consent` | Identity-provider audit logs | 50.0% | 100.0% | +50.0% | 2/7 |
| `endpoint-sensitive-process-access` | Endpoint process-access events | 47.1% | 100.0% | +52.9% | 2/7 |

## Operator result

| Operator | Weak killed/generated | Strong killed/generated |
| --- | ---: | ---: |
| `condition_and_to_or` | 13/14 | 14/14 |
| `condition_remove_not` | 13/13 | 13/13 |
| `delete_list_item` | 40/80 | 80/80 |
| `delete_predicate` | 0/49 | 49/49 |
| `list_any_to_all` | 40/40 | 40/40 |
| `modifier_to_exact` | 1/35 | 35/35 |

## Reproduce and verify

```bash
python -m pip install -c constraints-demo.txt -e ".[dev]"
python scripts/evaluate_corpus.py --verify
```

The command re-runs every pair and compares the complete canonical payload with `benchmarks/results.json`. Input SHA-256 values, dependency versions, per-operator counts, and per-case results are included in that machine-readable evidence. Timing is deliberately excluded because it is host-dependent. The release constraint set pins the direct dependencies used by the checked-in evidence and CI verification.

To regenerate the checked-in evidence after an intentional corpus or engine change:

```bash
python scripts/evaluate_corpus.py --update
```

Review the JSON and Markdown diff before committing it.

## Interpretation and limits

The paired design holds each Sigma rule constant and varies only the labelled fixture set. The score delta therefore demonstrates whether boundary-focused fixtures expose the injected defect models better than a minimal baseline-only suite.

It does **not** measure false-positive rate, false-negative rate, SIEM backend equivalence, telemetry quality, or coverage of the entire Sigma specification. Because the corpus is project-authored and synthetic, an independently curated public-rule mutation-score study with labelled fixtures remains future work. The separate pinned SigmaHQ applicability study measures rule and operator reach without fabricating fixtures.

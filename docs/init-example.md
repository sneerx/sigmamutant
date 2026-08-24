# Wheel-contained example

`sigmamutant init-example DEST` creates a new, self-contained SigmaMutant
project using files bundled in the installed wheel. It does not read a cloned
repository, call a network service, inspect environment credentials, or modify
an existing path.

```console
$ sigmamutant init-example my-sigmamutant-example
Created self-contained example: my-sigmamutant-example
Files: 5 (synthetic, offline, no secrets)
Next (the weak run intentionally exits 1):
  sigmamutant run my-sigmamutant-example/weak-suite.yml --out artifacts/sigmamutant-weak
  sigmamutant run my-sigmamutant-example/strong-suite.yml --out artifacts/sigmamutant-strong
```

The generated directory contains one Sigma rule, weak and strong labelled
JSONL fixtures, and a suite for each fixture corpus. The weak suite deliberately
returns exit `1` because it leaves mutation survivors; the strong suite returns
`0`. Both return `2` for a technical/input error.

The command refuses existing destinations, broken or intermediate symlinks,
and case/Unicode aliases that could collide on another supported filesystem.
There is intentionally no overwrite option. Choose a new destination when
repeating the walkthrough.

This is a same-user project bootstrap, not a filesystem privilege boundary.
Create it in a directory controlled by the current user; another process that
can concurrently replace path components with symlinks, junctions, or reparse
points is outside the command's threat model.

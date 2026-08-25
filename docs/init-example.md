# Wheel-contained example

`sigmamutant init-example DEST` creates a new, self-contained SigmaMutant
project using files bundled in the installed wheel. It does not read a cloned
repository, call a network service, inspect environment credentials, or modify
an existing path.

```console
$ sigmamutant init-example my-sigmamutant-example
Created self-contained example: my-sigmamutant-example
Files: 9 (synthetic, offline, no secrets)
Next (the weak run intentionally exits 1 on both axes):
  sigmamutant run my-sigmamutant-example/weak-suite.yml --out artifacts/sigmamutant-weak
  sigmamutant run my-sigmamutant-example/strong-suite.yml --out artifacts/sigmamutant-strong
  sigmamutant gap my-sigmamutant-example/powershell-gap.yml --out artifacts/sigmamutant-weak-gap
  sigmamutant gap my-sigmamutant-example/powershell-hardened-gap.yml --out artifacts/sigmamutant-hardened-gap
```

The generated directory contains ordinary and deliberately hardened Sigma
rules; weak, strong, and event-gap JSONL fixtures; and four suite files. The
weak rule-mutation suite deliberately returns exit `1` because it leaves
mutation survivors, while the strong suite returns `0`. The ordinary gap suite
also returns `1` (`8/12`, `66.7%`); the hardened gap suite returns `0` (`12/12`,
`100.0%`). All four return `2` for a technical/input error.

The scores are independent. Rule mutation measures how well fixtures notice
atomic rule defects; event-gap analysis measures whether the unchanged rule
retains the shipped, bounded event variations under the pinned local evaluator.
The gap result is not proof of a real-world bypass. No command in this
walkthrough executes event strings or modifies the generated input files.

The command refuses existing destinations, broken or intermediate symlinks,
and case/Unicode aliases that could collide on another supported filesystem.
There is intentionally no overwrite option. Choose a new destination when
repeating the walkthrough.

This is a same-user project bootstrap, not a filesystem privilege boundary.
Create it in a directory controlled by the current user; another process that
can concurrently replace path components with symlinks, junctions, or reparse
points is outside the command's threat model.

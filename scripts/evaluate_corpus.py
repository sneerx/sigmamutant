#!/usr/bin/env python3
"""Run and verify SigmaMutant's checked-in evaluation corpus."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from sigmamutant.evaluation import evaluate_corpus, render_evaluation_markdown

REPOSITORY = Path(__file__).resolve().parents[1]
MANIFEST = REPOSITORY / "benchmarks" / "manifest.json"
EXPECTED = REPOSITORY / "benchmarks" / "results.json"
DOCUMENT = REPOSITORY / "docs" / "evaluation.md"


def _json_text(payload: dict[str, object]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the paired weak/strong SigmaMutant evaluation corpus."
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--verify",
        action="store_true",
        help="compare a fresh run with checked-in JSON evidence (default)",
    )
    action.add_argument(
        "--update",
        action="store_true",
        help="replace checked-in JSON and Markdown evidence after review",
    )
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--expected", type=Path, default=EXPECTED)
    parser.add_argument("--document", type=Path, default=DOCUMENT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    started = time.perf_counter()
    payload = evaluate_corpus(args.manifest)
    elapsed = time.perf_counter() - started
    actual_json = _json_text(payload)
    actual_markdown = render_evaluation_markdown(payload)

    if args.update:
        args.expected.parent.mkdir(parents=True, exist_ok=True)
        args.document.parent.mkdir(parents=True, exist_ok=True)
        args.expected.write_text(actual_json, encoding="utf-8")
        args.document.write_text(actual_markdown, encoding="utf-8")
        print(f"updated {args.expected}")
        print(f"updated {args.document}")
        print(f"evaluation runtime: {elapsed:.3f}s")
        return 0

    if not args.expected.is_file():
        print(f"missing checked-in evidence: {args.expected}", file=sys.stderr)
        return 2
    expected_json = args.expected.read_text(encoding="utf-8")
    if actual_json != expected_json:
        print(
            "evaluation differs from checked-in evidence; inspect the change and "
            "run with --update if intentional",
            file=sys.stderr,
        )
        return 1
    if not args.document.is_file() or (
        args.document.read_text(encoding="utf-8") != actual_markdown
    ):
        print(
            "evaluation Markdown differs from generated evidence; run with --update",
            file=sys.stderr,
        )
        return 1
    print(
        "evaluation verified: "
        f"{payload['corpus']['cases']} pairs, "
        f"weak={payload['summary']['weak']['weighted_score']:.1%}, "
        f"strong={payload['summary']['strong']['weighted_score']:.1%}, "
        f"runtime={elapsed:.3f}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

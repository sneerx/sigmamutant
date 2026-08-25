from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree

from sigmamutant.gap_models import (
    DetectionGapResult,
    EventVariation,
    GapVariationResult,
)
from sigmamutant.gap_runner import run_gap_analysis
from sigmamutant.reporting.gap_report import (
    gap_payload,
    render_gap_html,
    render_gap_junit,
    write_gap_reports,
)
from sigmamutant.suite import load_suite

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _copy_vulnerable_project(destination: Path) -> Path:
    (destination / "rules").mkdir(parents=True)
    (destination / "fixtures").mkdir()
    shutil.copy2(
        PROJECT_ROOT / "examples" / "rules" / "powershell_encoded.yml",
        destination / "rules" / "powershell_encoded.yml",
    )
    shutil.copy2(
        PROJECT_ROOT / "examples" / "fixtures" / "gap.jsonl",
        destination / "fixtures" / "gap.jsonl",
    )
    shutil.copy2(
        PROJECT_ROOT / "examples" / "powershell-gap.yml",
        destination / "powershell-gap.yml",
    )
    return destination / "powershell-gap.yml"


def test_gap_reports_are_deterministic_parseable_and_checkout_path_independent(
    tmp_path: Path,
) -> None:
    first_suite = _copy_vulnerable_project(tmp_path / "first-checkout")
    second_suite = _copy_vulnerable_project(tmp_path / "second-checkout")
    first_output = tmp_path / "first-artifacts"
    second_output = tmp_path / "second-artifacts"

    first_result = run_gap_analysis(first_suite, output_dir=first_output)
    second_result = run_gap_analysis(second_suite, output_dir=second_output)

    assert first_result == second_result
    for filename in ("gap-report.json", "gap-report.html", "gap-junit.xml"):
        assert (first_output / filename).read_bytes() == (
            second_output / filename
        ).read_bytes()

    payload = json.loads((first_output / "gap-report.json").read_text("utf-8"))
    assert payload["suite"] == {
        "path": "powershell-gap.yml",
        "rule_path": "rules/powershell_encoded.yml",
        "fixtures_path": "fixtures/gap.jsonl",
        "config": {
            "version": 1,
            "rule": "rules/powershell_encoded.yml",
            "fixtures": "fixtures/gap.jsonl",
            "fail_under": 0.8,
        },
    }
    assert payload["metadata"]["max_variations"] == 4096
    assert str(tmp_path) not in json.dumps(payload, ensure_ascii=False)
    assert [item["id"] for item in payload["variation_results"]] == sorted(
        item["id"] for item in payload["variation_results"]
    )
    assert all(item["path"].startswith("/") for item in payload["variation_results"])
    assert all(
        len(item["evidence"]["event_sha256"]) == 64
        for item in payload["variation_results"]
    )

    html = (first_output / "gap-report.html").read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>")
    assert "not proof of real-world evasion" in html
    assert "/CommandLine" in html
    ElementTree.parse(first_output / "gap-junit.xml")


def test_gap_payload_and_all_reports_omit_raw_fixture_derived_values(
    tmp_path: Path,
) -> None:
    suite_path = _copy_vulnerable_project(tmp_path / "project")
    loaded = load_suite(suite_path)
    result = run_gap_analysis(loaded)

    payload = gap_payload(result, loaded)
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    raw_values = (
        "SQBmACgAJAB0AHIAdQBlACkA",
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        "pwsh.exe -NoLogo -EncodedCommand",
    )
    for value in raw_values:
        assert value not in serialized
        assert value not in render_gap_html(result, loaded)
        assert value not in render_gap_junit(result, loaded)

    forbidden_result_keys = {"event", "original", "replacement"}
    for item in payload["variation_results"]:
        assert forbidden_result_keys.isdisjoint(item)
        assert set(item["evidence"]) == {
            "source_value_sha256",
            "replacement_value_sha256",
            "event_sha256",
        }
        assert all(
            len(digest) == 64 and set(digest) <= set("0123456789abcdef")
            for digest in item["evidence"].values()
        )


def test_gap_html_and_junit_escape_user_controlled_metadata() -> None:
    variation = EventVariation(
        id="variation-safe-id",
        source_fixture_id='<script>alert("fixture")</script>',
        operator="ascii_case",
        field="Field/With~Pointer",
        description='<img src=x onerror="description">',
        claim_scope="bounded & reviewed",
        original="private-before",
        replacement="private-after",
        event={"Field/With~Pointer": "private-after"},
    )
    result = DetectionGapResult(
        rule_title='<svg onload="rule-title">',
        baseline_passed=True,
        score=0.0,
        detected=0,
        escaped=1,
        excluded=0,
        seed_count=1,
        fixture_count=2,
        variation_results=(
            GapVariationResult(
                variation=variation,
                status="escaped",
                baseline_match=True,
                variation_match=False,
            ),
        ),
        threshold=1.0,
        passed=False,
    )
    suite = SimpleNamespace(
        path=Path("suite.yml"),
        config=SimpleNamespace(rule="rule.yml", fixtures="fixtures.jsonl"),
    )

    html = render_gap_html(result, suite)
    assert '<script>alert("fixture")</script>' not in html
    assert '<svg onload="rule-title">' not in html
    assert '<img src=x onerror="description">' not in html
    assert "&lt;script&gt;" in html
    assert "&lt;svg onload=&quot;" in html
    assert "/Field~1With~0Pointer" in html
    assert ">gap candidate<" in html
    assert ">escaped<" not in html

    junit_text = render_gap_junit(result, suite)
    junit = ElementTree.fromstring(junit_text)
    assert junit.attrib["failures"] == "1"
    assert junit.attrib["errors"] == "0"
    assert '<script>alert("fixture")</script>' not in junit_text
    assert "private-before" not in junit_text
    assert "private-after" not in junit_text
    system_out = junit.find(".//system-out")
    assert system_out is not None
    detail = json.loads(system_out.text or "{}")
    assert detail["source_fixture_id"] == '<script>alert("fixture")</script>'
    assert detail["path"] == "/Field~1With~0Pointer"


def test_gap_reports_replace_xml_forbidden_controls_and_unpaired_surrogates(
    tmp_path: Path,
) -> None:
    unsafe = "unsafe\x01\ud800"
    variation = EventVariation(
        id="safe-id",
        source_fixture_id=unsafe,
        operator="ascii_case",
        field="Image",
        description="safe",
        claim_scope="safe",
        original="before",
        replacement="after",
        event={"Image": "after"},
    )
    result = DetectionGapResult(
        rule_title=unsafe,
        baseline_passed=True,
        score=1.0,
        detected=1,
        escaped=0,
        excluded=0,
        seed_count=1,
        fixture_count=2,
        variation_results=(
            GapVariationResult(
                variation=variation,
                status="detected",
                baseline_match=True,
                variation_match=True,
            ),
        ),
        threshold=1.0,
        passed=True,
    )
    suite = SimpleNamespace(
        path=Path("suite.yml"),
        config=SimpleNamespace(rule="rule.yml", fixtures="fixtures.jsonl"),
    )

    html = render_gap_html(result, suite)
    junit = render_gap_junit(result, suite)
    assert "\x01" not in html
    assert "\ud800" not in html
    assert "\x01" not in junit
    assert "\ud800" not in junit
    ElementTree.fromstring(junit)

    paths = write_gap_reports(result, suite, tmp_path / "reports")
    json.loads(paths["json"].read_text(encoding="utf-8"))
    ElementTree.parse(paths["junit"])
    paths["html"].read_text(encoding="utf-8")


def test_gap_html_labels_technical_failures_as_error() -> None:
    result = DetectionGapResult(
        rule_title="Technical failure",
        baseline_passed=False,
        score=0.0,
        detected=0,
        escaped=0,
        excluded=0,
        seed_count=1,
        fixture_count=2,
        variation_results=(),
        threshold=1.0,
        passed=False,
        errors=("baseline mismatch",),
    )
    suite = SimpleNamespace(
        path=Path("suite.yml"),
        config=SimpleNamespace(rule="rule.yml", fixtures="fixtures.jsonl"),
    )

    html = render_gap_html(result, suite)

    assert (
        '<span class="muted">Result</span><strong class="fail">ERROR</strong>' in html
    )
    assert (
        '<span class="muted">Baseline</span><strong class="fail">FAIL</strong>' in html
    )


def test_gap_junit_uses_one_threshold_gate_and_not_one_failure_per_gap(
    tmp_path: Path,
) -> None:
    suite = load_suite(_copy_vulnerable_project(tmp_path / "project"))
    result = run_gap_analysis(suite)
    junit = ElementTree.fromstring(render_gap_junit(result, suite))

    assert result.escaped > 1
    assert junit.attrib["failures"] == "1"
    failures = junit.findall(".//failure")
    assert len(failures) == 1
    assert failures[0].attrib["type"] == "VariantScoreFailure"
    variant_cases = [
        case
        for case in junit.findall("testcase")
        if case.attrib["name"] != "variant-score-gate"
    ]
    assert len(variant_cases) == result.variation_count
    assert all(case.find("failure") is None for case in variant_cases)

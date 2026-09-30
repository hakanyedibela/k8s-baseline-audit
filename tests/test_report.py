# ruff: noqa: E501
import copy
import re
from dataclasses import replace
from datetime import date

import pytest

from k8s_baseline_audit.analyze.checks.base import AnalyzerConfig
from k8s_baseline_audit.analyze.pipeline import analyze, write_analysis
from k8s_baseline_audit.bundle import load_bundle
from k8s_baseline_audit.mapping.schema import load_mapping
from k8s_baseline_audit.models import Evidence, Finding, Localized, ResourceRef, Severity, Source
from k8s_baseline_audit.report.render import (
    Narrative,
    NarrativeError,
    PriorityNote,
    code,
    load_report_input,
    md,
    render_reports,
    validate_narratives,
)

FORBIDDEN = ("erfüllt", "fulfilled", "compliant", "konform")


@pytest.fixture
def report_input(sample_bundle, tmp_path):
    bundle = load_bundle(sample_bundle)
    result = analyze(bundle, load_mapping(), AnalyzerConfig(as_of=date(2026, 9, 30)), tool_version="0.1.0")
    write_analysis(result, tmp_path / "analysis")
    return load_report_input(tmp_path / "analysis", bundle)


def narratives(inp, rank_en=1):
    first = inp.findings[0].id
    return {
        "de": Narrative(language="de", summary="Kritische Befunde im Namespace default.",
                        priorities={first: PriorityNote(rank=1, reason="Host-Zugriff")},
                        fix_notes={first: "Zuerst beheben."}),
        "en": Narrative(language="en", summary="Critical findings in namespace default.",
                        priorities={first: PriorityNote(rank=rank_en, reason="Host access")},
                        fix_notes={first: "Fix first."}),
    }


def _ids(text):
    return re.findall(r"^\| ID \| `([0-9a-f]{16})` \|$", text, re.M)


def test_parity_between_languages(report_input, tmp_path):
    paths = render_reports(report_input, narratives(report_input), tmp_path / "out")
    de, en = paths["de"].read_text(), paths["en"].read_text()
    assert _ids(de) == _ids(en)
    assert len(_ids(de)) == len([f for f in report_input.findings if not f.check_id.startswith("trivy:CVE-")])
    rows = r"^\| (APP\.4\.4|SYS\.1\.6)\.A\d+ \|"
    assert len(re.findall(rows, de, re.M)) == len(re.findall(rows, en, re.M)) == len(report_input.coverage)
    assert de.count("### ") == en.count("### ")


def test_report_never_claims_fulfilment(report_input, tmp_path):
    paths = render_reports(report_input, narratives(report_input), tmp_path / "out")
    for p in paths.values():
        text = p.read_text().lower()
        for word in FORBIDDEN:
            assert word not in text, (p.name, word)


def test_ai_sections_are_labeled_and_missing_narrative_is_stated(report_input, tmp_path):
    with_n = render_reports(report_input, narratives(report_input), tmp_path / "a")
    assert "KI-generiert" in with_n["de"].read_text()
    assert "AI-generated" in with_n["en"].read_text()
    without = render_reports(report_input, None, tmp_path / "b")
    assert "Keine Management-Zusammenfassung erzeugt" in without["de"].read_text()
    assert "No management summary generated" in without["en"].read_text()


def test_cover_page_and_appendix(report_input, tmp_path):
    text = render_reports(report_input, None, tmp_path / "out")["en"].read_text()
    assert report_input.meta["bundle"]["manifest_sha256"] in text
    assert "no certification" in text.lower()
    assert "secrets" in text  # forbidden resource listed under not checked / preflight
    assert "resources/pods.json" in text  # evidence index
    assert "system_namespaces" in text
    assert "kube-system" in text


def test_narrative_validation(report_input):
    ids = {f.id for f in report_input.findings}
    validate_narratives(narratives(report_input), ids)
    with pytest.raises(NarrativeError, match="priorities differ"):
        validate_narratives(narratives(report_input, rank_en=2), ids)
    with pytest.raises(NarrativeError, match="unknown finding ids"):
        validate_narratives(narratives(report_input), set())
    with pytest.raises(NarrativeError, match="both de and en"):
        validate_narratives({"de": narratives(report_input)["de"]}, ids)
    bad = narratives(report_input)
    bad["de"] = bad["de"].model_copy(update={"language": "en"})
    with pytest.raises(NarrativeError, match="declares language"):
        validate_narratives(bad, ids)


def test_md_escapes_table_breakers():
    assert md("a|b\nc") == "a\\|b c"


def test_md_escapes_markdown_syntax():
    assert md("a\\|b") == "a\\\\\\|b"  # backslash and pipe both escaped: no live pipe
    assert md("a`b") == "a\\`b"
    assert md("<script>") == "\\<script\\>"
    assert md("[x](y)") == "\\[x\\](y)"
    assert md("a\r\nb") == "a  b"


def test_code_filter():
    assert code("a`b|c") == "`a'b\\|c`"


def _bad_narrative(inp, field, value):
    n = narratives(inp)
    first = inp.findings[0].id
    de = n["de"]
    if field == "summary":
        de = de.model_copy(update={"summary": value})
    elif field == "reason":
        de = de.model_copy(update={"priorities": {first: PriorityNote(rank=1, reason=value)}})
    else:
        de = de.model_copy(update={"fix_notes": {first: value}})
    n["de"] = de
    return n


@pytest.mark.parametrize("word", ["erfüllt", "Fulfilled", "COMPLIANT", "konform"])
def test_narrative_rejects_forbidden_words(report_input, word):
    ids = {f.id for f in report_input.findings}
    for field in ("summary", "reason", "fix"):
        with pytest.raises(NarrativeError, match="forbidden word"):
            validate_narratives(_bad_narrative(report_input, field, f"alles {word}"), ids)


def test_narrative_rejects_html(report_input):
    ids = {f.id for f in report_input.findings}
    for value in ("a <b>x</b>", "![i](http://x)"):
        with pytest.raises(NarrativeError, match="HTML or image"):
            validate_narratives(_bad_narrative(report_input, "summary", value), ids)


@pytest.mark.parametrize("line", ["# H", "  | a | b |", "> quote", "```", "---", "ok\n## H2"])
def test_narrative_rejects_block_syntax(report_input, line):
    ids = {f.id for f in report_input.findings}
    with pytest.raises(NarrativeError, match="Markdown block syntax"):
        validate_narratives(_bad_narrative(report_input, "summary", line), ids)


def test_narrative_rejects_duplicate_ranks(report_input):
    ids = {f.id for f in report_input.findings}
    n = narratives(report_input)
    other = report_input.findings[1].id
    for lang in ("de", "en"):
        n[lang] = n[lang].model_copy(update={"priorities": {
            **n[lang].priorities, other: PriorityNote(rank=1, reason="x")}})
    with pytest.raises(NarrativeError, match="duplicate ranks"):
        validate_narratives(n, ids)


def test_narrative_rejects_blank_fix_note(report_input):
    ids = {f.id for f in report_input.findings}
    with pytest.raises(NarrativeError, match="empty fix note"):
        validate_narratives(_bad_narrative(report_input, "fix", "   "), ids)


ROW = r"^\| (APP\.4\.4|SYS\.1\.6)\.A\d+ \|"
HOSTILE = "x|y`z\n<b>[x](y)\n## Heading"


def test_hostile_bundle_values_do_not_break_structure(report_input, tmp_path):
    meta = copy.deepcopy(report_input.meta)
    meta["bundle"]["cluster"]["context"] = HOSTILE
    meta["bundle"]["producer"] = HOSTILE
    meta["bundle"]["scanners"][HOSTILE] = {"status": HOSTILE, "version": HOSTILE}
    meta["bundle"]["scanners"]["nostatus"] = {}
    f0 = report_input.findings[0]
    hostile_f = f0.model_copy(update={
        "title": Localized(de=HOSTILE, en=HOSTILE),
        "resources": [ResourceRef(kind="Pod", name=HOSTILE, namespace="d|e")],
        "evidence": [Evidence(file=HOSTILE, json_path=HOSTILE)],
    })
    hostile = replace(
        report_input, meta=meta, findings=[hostile_f, *report_input.findings[1:]],
        preflight={**report_input.preflight, HOSTILE: False},
        runs=[*report_input.runs, {"check_id": HOSTILE, "state": "not_run", "reason": HOSTILE}],
    )
    good = render_reports(report_input, None, tmp_path / "good")["en"].read_text()
    bad = render_reports(hostile, None, tmp_path / "bad")["en"].read_text()
    assert len(re.findall(ROW, bad, re.M)) == len(re.findall(ROW, good, re.M))
    assert len(re.findall(r"^### ", bad, re.M)) == len(re.findall(r"^### ", good, re.M))
    assert not re.search(r"^## Heading", bad, re.M)
    outside_code = re.sub(r"`[^`\n]*`", "", bad)  # code spans render literally
    assert "<b>" not in outside_code.replace("\\<b\\>", "")
    assert "unknown" in bad  # scanner without status


def test_trivy_vulnerability_rendered_in_vuln_table(report_input, tmp_path):
    def cve(resources):
        return Finding(
            id="0123456789abcdef", check_id="trivy:CVE-2024-0001",
            title=Localized(de="CVE-2024-0001", en="CVE-2024-0001"), severity=Severity.HIGH,
            resources=resources, evidence=[], sources=[Source.TRIVY],
            remediation=Localized(de="Image aktualisieren.", en="Update the image."))
    inp = replace(report_input, findings=[*report_input.findings,
                  cve([ResourceRef(kind="Pod", name="p", namespace="default")])])
    text = render_reports(inp, None, tmp_path / "a")["en"].read_text()
    assert "| `0123456789abcdef` | CVE-2024-0001 | High | `Pod/default/p` |" in text
    assert text.count("`0123456789abcdef`") == 1  # not in the main findings list
    noref = replace(report_input, findings=[*report_input.findings, cve([])])
    assert "| `0123456789abcdef` | CVE-2024-0001 | High | – |" in (
        render_reports(noref, None, tmp_path / "b")["en"].read_text())


def test_priority_order_note(report_input, tmp_path):
    with_n = render_reports(report_input, narratives(report_input), tmp_path / "a")
    assert "Order follows the AI-generated priority" in with_n["en"].read_text()
    assert "Reihenfolge nach KI-generierter Priorität" in with_n["de"].read_text()
    without = render_reports(report_input, None, tmp_path / "b")["en"].read_text()
    assert "Order follows" not in without

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
    return re.findall(r"^\| `([0-9a-f]{16})` \| ", text, re.M)


def test_parity_between_languages(report_input, tmp_path):
    paths = render_reports(report_input, narratives(report_input), tmp_path / "out")
    de, en = paths["de"].read_text(), paths["en"].read_text()
    assert _ids(de) == _ids(en)
    assert len(_ids(de)) == len(report_input.findings)  # sample bundle: built-in findings only
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
        "remediation": Localized(de=HOSTILE, en=HOSTILE),
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
    assert not re.search(r"^## H", bad, re.M)
    assert "unknown" in bad  # scanner without status


def _cve(fid, cve, severity, resources):
    return Finding(
        id=fid, check_id=f"trivy:{cve}", title=Localized(de=cve, en=cve), severity=severity,
        resources=resources, evidence=[], sources=[Source.TRIVY],
        remediation=Localized(de="Image aktualisieren.", en="Update the image."))


def test_vulnerabilities_are_counted_per_image(report_input, tmp_path):
    pod_a = ResourceRef(kind="Pod", name="a", namespace="default")
    pod_b = ResourceRef(kind="Pod", name="b", namespace="default")
    vulns = [
        _cve("0123456789abcdef", "CVE-2024-0001", Severity.HIGH, [pod_a]),
        _cve("0123456789abcde0", "CVE-2024-0001", Severity.HIGH, [pod_b]),
        _cve("0123456789abcde1", "CVE-2024-0002", Severity.CRITICAL, [pod_a]),
        _cve("0123456789abcde2", "GHSA-xxxx", Severity.LOW, [pod_b]),
        _cve("0123456789abcde3", "CVE-2024-0003", Severity.MEDIUM, []),
    ]
    images = {
        "0123456789abcdef": "nginx:1 (debian 12)",
        "0123456789abcde0": "nginx:1 (debian 12)",
        "0123456789abcde1": "nginx:1 (debian 12)",
        "0123456789abcde2": "busybox:1",
    }
    inp = replace(report_input, findings=[*report_input.findings, *vulns], images=images)
    text = render_reports(inp, None, tmp_path / "a")["en"].read_text()
    assert "| Image | Critical | High | Medium | Low | Workloads |" in text
    assert "| `nginx:1 (debian 12)` | 1 | 1 | 0 | 0 | 2 |" in text
    assert "| `busybox:1` | 0 | 0 | 0 | 1 | 1 |" in text
    assert "| `?` | 0 | 0 | 1 | 0 | 0 |" in text
    assert "0123456789abcdef" not in text  # full list stays in findings.json
    de = render_reports(inp, None, tmp_path / "b")["de"].read_text()
    assert "| Image | Kritisch | Hoch | Mittel | Niedrig | Workloads |" in de


def test_vulnerability_images_are_read_from_the_bundle(tmp_path):
    from k8s_baseline_audit.bundle import dump_json, write_bundle
    from k8s_baseline_audit.report.render import vulnerability_images

    trivy = {"Resources": [{"Kind": "Pod", "Name": "a", "Results": [
        {"Target": "nginx:1 (debian 12)", "Vulnerabilities": [{"VulnerabilityID": "CVE-1"}]}]}]}
    root = write_bundle(tmp_path / "b", {"scanners/trivy.json": dump_json(trivy)}, {})
    f = _cve("0123456789abcdef", "CVE-1", Severity.HIGH, [])
    f.evidence = [Evidence(file="scanners/trivy.json", json_path="$.Resources[0].Results[0].Vulnerabilities[0]")]
    bad = _cve("0123456789abcde0", "CVE-2", Severity.HIGH, [])
    bad.evidence = [Evidence(file="scanners/trivy.json", json_path="$.Resources[5].Results[0].Vulnerabilities[0]")]
    assert vulnerability_images(load_bundle(root), [f, bad]) == {"0123456789abcdef": "nginx:1 (debian 12)"}


def _scanner_finding(fid, check_id, name, sources=(Source.KUBESCAPE,)):
    return Finding(
        id=fid, check_id=check_id, title=Localized(de=f"T {check_id}", en=f"T {check_id}"),
        severity=Severity.MEDIUM, resources=[ResourceRef(kind="Role", name=name, namespace="x")],
        evidence=[Evidence(file="scanners/kubescape.json", json_path="$.results[0]")],
        sources=list(sources), remediation=Localized(de="r", en="r"))


def test_findings_are_grouped_per_check(report_input, tmp_path):
    text = render_reports(report_input, None, tmp_path / "a")["en"].read_text()
    sections = re.findall(r"^### \d+\. ", text, re.M)
    assert len(sections) == len({f.check_id for f in report_input.findings})
    assert len(_ids(text)) == len(report_input.findings)


def test_scanner_only_findings_are_summarized(report_input, tmp_path):
    extra = [_scanner_finding(f"00000000000000{i:02d}", "kubescape:C-0035", f"r{i}") for i in range(5)]
    inp = replace(report_input, findings=[*report_input.findings, *extra])
    text = render_reports(inp, None, tmp_path / "a")["en"].read_text()
    assert ("| `kubescape:C-0035` | T kubescape:C-0035 | Medium | 5 | "
            "`Role/x/r0`, `Role/x/r1`, `Role/x/r2` and 2 more |") in text
    assert "0000000000000000" not in text
    assert len(re.findall(r"^### \d+\. ", text, re.M)) == len({f.check_id for f in report_input.findings})


def test_narrative_notes_attach_to_finding_rows(report_input, tmp_path):
    scanner = _scanner_finding("00000000000000aa", "kubescape:C-0035", "r")
    inp = replace(report_input, findings=[*report_input.findings, scanner])
    n = {
        lang: Narrative(language=lang, summary="S.",
                        priorities={scanner.id: PriorityNote(rank=1, reason=f"why-{lang}")},
                        fix_notes={scanner.id: f"note-{lang}"})
        for lang in ("de", "en")
    }
    paths = render_reports(inp, n, tmp_path / "a")
    en = paths["en"].read_text()
    row = next(line for line in en.splitlines() if line.startswith("| `00000000000000aa` |"))
    assert "1 – why-en (_AI-generated" in row and "note-en (_AI-generated" in row
    first = re.search(r"^### 1\. (.*)$", en, re.M)[1]
    assert first == "T kubescape:C-0035"  # ranked group comes first, as a full section
    assert "| `00000000000000aa` |" in paths["de"].read_text()


def test_disclaimer_states_non_affiliation(report_input, tmp_path):
    paths = render_reports(report_input, None, tmp_path / "a")
    assert "Nicht mit dem BSI verbunden oder von ihm unterstützt." in paths["de"].read_text()
    assert "Not affiliated with or endorsed by the BSI." in paths["en"].read_text()


def test_priority_order_note(report_input, tmp_path):
    with_n = render_reports(report_input, narratives(report_input), tmp_path / "a")
    assert "Order follows the AI-generated priority" in with_n["en"].read_text()
    assert "Reihenfolge nach KI-generierter Priorität" in with_n["de"].read_text()
    without = render_reports(report_input, None, tmp_path / "b")["en"].read_text()
    assert "Order follows" not in without


def test_narrative_rejects_inline_links(report_input):
    ids = {f.id for f in report_input.findings}
    with pytest.raises(NarrativeError, match="link syntax"):
        validate_narratives(_bad_narrative(report_input, "summary", "see [here](http://x)"), ids)


def test_hostile_scanner_titles_and_images_do_not_break_structure(report_input, tmp_path):
    def variant(text):
        s = _scanner_finding("00000000000000bb", "kubescape:C-0035", "r")
        s = s.model_copy(update={"title": Localized(de=text, en=text)})
        v = _cve("00000000000000cc", "CVE-2024-0009", Severity.HIGH, [])
        return replace(report_input, findings=[*report_input.findings, s, v],
                       images={v.id: text})

    good = render_reports(variant("plain"), None, tmp_path / "good")["en"].read_text()
    bad = render_reports(variant(HOSTILE), None, tmp_path / "bad")["en"].read_text()
    assert len(re.findall(r"^### ", bad, re.M)) == len(re.findall(r"^### ", good, re.M))
    assert len(re.findall(r"^\|", bad, re.M)) == len(re.findall(r"^\|", good, re.M))
    assert not re.search(r"^## Heading", bad, re.M)

# ruff: noqa: E501
import re
from datetime import date

import pytest

from k8s_baseline_audit.analyze.checks.base import AnalyzerConfig
from k8s_baseline_audit.analyze.pipeline import analyze, write_analysis
from k8s_baseline_audit.bundle import load_bundle
from k8s_baseline_audit.mapping.schema import load_mapping
from k8s_baseline_audit.report.render import (
    Narrative,
    NarrativeError,
    PriorityNote,
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

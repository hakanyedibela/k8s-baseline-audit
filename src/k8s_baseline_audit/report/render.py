# ruff: noqa: E501
"""Render report.de.md and report.en.md from analysis output and optional narratives."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from jinja2 import Environment, PackageLoader, StrictUndefined
from pydantic import BaseModel, Field

from ..analyze.pipeline import analysis_bytes, analyze, config_from_meta
from ..bundle import Bundle
from ..mapping.schema import Mapping, load_mapping
from ..models import CoverageEntry, Finding, Severity, Source
from .labels import LABELS

LANGS = ("de", "en")


class PriorityNote(BaseModel):
    rank: int = Field(ge=1)
    reason: str = Field(min_length=1)


class Narrative(BaseModel):
    language: Literal["de", "en"]
    summary: str = Field(min_length=1)
    priorities: dict[str, PriorityNote] = Field(default_factory=dict)
    fix_notes: dict[str, str] = Field(default_factory=dict)


class NarrativeError(ValueError):
    """Narratives are inconsistent with the analysis or with each other."""


class AnalysisMismatchError(ValueError):
    """findings.json / coverage.json differ from a fresh analysis of the bundle."""


FORBIDDEN_WORDS = ("erfüllt", "fulfilled", "compliant", "konform")
BLOCK_PREFIXES = ("#", "|", ">", "```", "---")


def _check_texts(lang: str, n: Narrative) -> None:
    if any(not v.strip() for v in n.fix_notes.values()):
        raise NarrativeError(f"{lang}: empty fix note")
    texts = [n.summary, *(p.reason for p in n.priorities.values()), *n.fix_notes.values()]
    for text in texts:
        low = text.lower()
        for word in FORBIDDEN_WORDS:
            if word in low:
                raise NarrativeError(f"{lang}: forbidden word {word!r} in narrative")
        if "<" in text or "![" in text:
            raise NarrativeError(f"{lang}: HTML or image syntax in narrative")
        if "](" in text:
            raise NarrativeError(f"{lang}: link syntax in narrative")
        for line in text.splitlines():
            if line.lstrip().startswith(BLOCK_PREFIXES):
                raise NarrativeError(f"{lang}: Markdown block syntax in narrative")


def validate_narratives(narratives: dict[str, Narrative], finding_ids: set[str]) -> None:
    if not narratives:
        return
    if set(narratives) != set(LANGS):
        raise NarrativeError("narratives must be provided for both de and en or not at all")
    for lang, n in narratives.items():
        if n.language != lang:
            raise NarrativeError(f"narrative for {lang} declares language {n.language}")
        unknown = (set(n.priorities) | set(n.fix_notes)) - finding_ids
        if unknown:
            raise NarrativeError(f"{lang}: unknown finding ids: {sorted(unknown)}")
        _check_texts(lang, n)
        ranks = [v.rank for v in n.priorities.values()]
        if len(ranks) != len(set(ranks)):
            raise NarrativeError(f"{lang}: duplicate ranks in priorities")
    de, en = narratives["de"], narratives["en"]
    if {k: v.rank for k, v in de.priorities.items()} != {k: v.rank for k, v in en.priorities.items()}:
        raise NarrativeError("de and en priorities differ")
    if set(de.fix_notes) != set(en.fix_notes):
        raise NarrativeError("de and en fix notes cover different findings")


def md(text: object) -> str:
    out = str(text).replace("\\", "\\\\")
    for ch in ("|", "`", "<", ">", "[", "]"):
        out = out.replace(ch, "\\" + ch)
    return out.replace("\r", " ").replace("\n", " ")


def code(text: object) -> str:
    inner = str(text).replace("`", "'").replace("|", "\\|")
    return "`" + inner.replace("\r", " ").replace("\n", " ") + "`"


def is_vulnerability(f: Finding) -> bool:
    return Source.TRIVY in f.sources and (f.check_id.startswith("trivy:CVE-") or f.check_id.startswith("trivy:GHSA-"))


@dataclass(frozen=True)
class ReportInput:
    meta: dict
    findings: list[Finding]
    runs: list[dict]
    coverage: list[CoverageEntry]
    mapping: Mapping
    manifest: dict
    preflight: dict
    images: dict[str, str] = field(default_factory=dict)  # vulnerability finding id -> image


_TRIVY_RESULT = re.compile(r"^\$\.Resources\[(\d+)\]\.Results\[(\d+)\]\.")


def vulnerability_images(bundle: Bundle, findings: list[Finding]) -> dict[str, str]:
    """Image (trivy Result Target) of each vulnerability finding, read from the bundle."""
    docs: dict[str, object] = {}
    out: dict[str, str] = {}
    for f in findings:
        if not is_vulnerability(f) or not f.evidence:
            continue
        ev = f.evidence[0]
        match = _TRIVY_RESULT.match(ev.json_path)
        if not match or not bundle.has(ev.file):
            continue
        if ev.file not in docs:
            docs[ev.file] = bundle.read_json(ev.file)
        try:
            target = docs[ev.file]["Resources"][int(match[1])]["Results"][int(match[2])]["Target"]
        except (KeyError, IndexError, TypeError):
            continue
        if isinstance(target, str) and target:
            out[f.id] = target
    return out


def load_report_input(analysis_dir: Path, bundle: Bundle) -> ReportInput:
    findings_bytes = (analysis_dir / "findings.json").read_bytes()
    coverage_bytes = (analysis_dir / "coverage.json").read_bytes()
    findings_doc = json.loads(findings_bytes.decode("utf-8"))
    coverage_doc = json.loads(coverage_bytes.decode("utf-8"))
    meta = findings_doc["meta"]
    if meta["bundle"]["manifest_sha256"] != bundle.manifest_sha256():
        raise ValueError("analysis was produced from a different bundle (manifest hash mismatch)")
    # The report must never show anything the analyzer would not produce for this bundle:
    # rerun the analysis with the recorded settings and require identical bytes.
    mapping = load_mapping(meta["mapping"]["name"])
    fresh = analyze(bundle, mapping, config_from_meta(meta["config"]), tool_version=meta["tool"]["version"])
    if analysis_bytes(fresh) != (findings_bytes, coverage_bytes):
        raise AnalysisMismatchError("analysis files do not match a fresh analysis of the bundle")
    return ReportInput(
        meta=meta,
        findings=[Finding.model_validate(f) for f in findings_doc["findings"]],
        runs=findings_doc["check_runs"],
        coverage=[CoverageEntry.model_validate(c) for c in coverage_doc["coverage"]],
        mapping=mapping,
        manifest=bundle.manifest,
        preflight=bundle.preflight,
        images=vulnerability_images(bundle, fresh.findings),
    )


NO_RANK = 10**6


@dataclass(frozen=True)
class FindingGroup:
    """All findings of one check_id, in report order."""

    check_id: str
    findings: list[Finding]
    rank: int

    @property
    def first(self) -> Finding:
        return self.findings[0]

    @property
    def severity(self) -> Severity:
        return min((f.severity for f in self.findings), key=lambda s: s.rank)

    @property
    def unmapped(self) -> bool:
        return any(f.severity_unmapped for f in self.findings)

    @property
    def sources(self) -> list[str]:
        return sorted({s.value for f in self.findings for s in f.sources})

    @property
    def resource_keys(self) -> list[str]:
        return sorted({r.key() for f in self.findings for r in f.resources})


@dataclass(frozen=True)
class VulnRow:
    image: str
    counts: dict[str, int]  # severity -> distinct vulnerability ids
    workloads: int


def _ranks(narrative: Narrative | None) -> dict[str, int]:
    return {k: v.rank for k, v in (narrative.priorities if narrative else {}).items()}


def group_findings(findings: list[Finding], narrative: Narrative | None) -> list[FindingGroup]:
    ranks = _ranks(narrative)
    by_check: dict[str, list[Finding]] = {}
    for f in findings:
        by_check.setdefault(f.check_id, []).append(f)
    groups = []
    for check_id, items in by_check.items():
        items = sorted(
            items,
            key=lambda f: (ranks.get(f.id, NO_RANK), f.severity.rank, [r.key() for r in f.resources], f.id),
        )
        groups.append(FindingGroup(check_id, items, min(ranks.get(f.id, NO_RANK) for f in items)))
    return sorted(groups, key=lambda g: (g.rank, g.severity.rank, g.check_id))


def vulnerability_rows(vulns: list[Finding], images: dict[str, str]) -> list[VulnRow]:
    ids: dict[str, dict[str, set[str]]] = {}
    workloads: dict[str, set[str]] = {}
    for f in vulns:
        image = images.get(f.id, "?")
        ids.setdefault(image, {s.value: set() for s in Severity})[f.severity.value].add(f.check_id)
        workloads.setdefault(image, set()).update(r.key() for r in f.resources)
    rows = [
        VulnRow(image, {sev: len(found) for sev, found in counts.items()}, len(workloads[image]))
        for image, counts in ids.items()
    ]
    order = [s.value for s in Severity]
    return sorted(rows, key=lambda r: ([-r.counts[s] for s in order], r.image))


def render_reports(inp: ReportInput, narratives: dict[str, Narrative] | None, out_dir: Path) -> dict[str, Path]:
    narratives = narratives or {}
    validate_narratives(narratives, {f.id for f in inp.findings})
    env = Environment(
        loader=PackageLoader("k8s_baseline_audit.report", "templates"),
        undefined=StrictUndefined,
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["md"] = md
    env.filters["code"] = code
    template = env.get_template("report.md.j2")
    narrative = narratives.get("en")
    noted = set(narrative.priorities) | set(narrative.fix_notes) if narrative else set()
    groups = group_findings([f for f in inp.findings if not is_vulnerability(f)], narrative)
    # Built-in checks, and scanner checks the narrative comments on, get a full section.
    # Other scanner-only checks are summarized; findings.json keeps every finding.
    detailed: list[FindingGroup] = []
    compact: list[FindingGroup] = []
    for g in groups:
        full = any(Source.BUILTIN in f.sources or f.id in noted for f in g.findings)
        (detailed if full else compact).append(g)
    vulns = vulnerability_rows([f for f in inp.findings if is_vulnerability(f)], inp.images)
    # Vulnerabilities the narrative ranks or annotates are listed individually under the summary.
    ranks = {k: v.rank for k, v in (narrative.priorities if narrative else {}).items()}
    vuln_notes = sorted(
        (f for f in inp.findings if is_vulnerability(f) and f.id in noted),
        key=lambda f: (ranks.get(f.id, NO_RANK), f.severity.rank, f.id),
    )
    skipped = [r for r in inp.runs if r["state"] != "ran"]
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for lang in LANGS:
        text = template.render(
            lang=lang, L=LABELS[lang], meta=inp.meta, groups=detailed, compact=compact, vulns=vulns, vuln_notes=vuln_notes, images=inp.images,
            severities=[s.value for s in Severity], coverage=inp.coverage, req=inp.mapping.get,
            narrative=narratives.get(lang), skipped=skipped, preflight=inp.preflight, manifest=inp.manifest,
        )
        path = out_dir / f"report.{lang}.md"
        path.write_text(text, encoding="utf-8")
        paths[lang] = path
    return paths

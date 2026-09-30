# ruff: noqa: E501
"""Render report.de.md and report.en.md from analysis output and optional narratives."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from jinja2 import Environment, PackageLoader, StrictUndefined
from pydantic import BaseModel, Field

from ..bundle import Bundle
from ..mapping.schema import Mapping, load_mapping
from ..models import CoverageEntry, Finding, Source
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
    de, en = narratives["de"], narratives["en"]
    if {k: v.rank for k, v in de.priorities.items()} != {k: v.rank for k, v in en.priorities.items()}:
        raise NarrativeError("de and en priorities differ")
    if set(de.fix_notes) != set(en.fix_notes):
        raise NarrativeError("de and en fix notes cover different findings")


def md(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


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


def load_report_input(analysis_dir: Path, bundle: Bundle) -> ReportInput:
    findings_doc = json.loads((analysis_dir / "findings.json").read_text(encoding="utf-8"))
    coverage_doc = json.loads((analysis_dir / "coverage.json").read_text(encoding="utf-8"))
    meta = findings_doc["meta"]
    if meta["bundle"]["manifest_sha256"] != bundle.manifest_sha256():
        raise ValueError("analysis was produced from a different bundle (manifest hash mismatch)")
    return ReportInput(
        meta=meta,
        findings=[Finding.model_validate(f) for f in findings_doc["findings"]],
        runs=findings_doc["check_runs"],
        coverage=[CoverageEntry.model_validate(c) for c in coverage_doc["coverage"]],
        mapping=load_mapping(meta["mapping"]["name"]),
        manifest=bundle.manifest,
        preflight=bundle.preflight,
    )


def _ordered(findings: list[Finding], narrative: Narrative | None) -> list[Finding]:
    ranks = {k: v.rank for k, v in (narrative.priorities if narrative else {}).items()}
    return sorted(findings, key=lambda f: (ranks.get(f.id, 10**6), f.severity.rank, f.check_id, f.id))


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
    template = env.get_template("report.md.j2")
    ordered = _ordered(inp.findings, narratives.get("en"))
    main = [f for f in ordered if not is_vulnerability(f)]
    vulns = [f for f in ordered if is_vulnerability(f)]
    skipped = [r for r in inp.runs if r["state"] != "ran"]
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for lang in LANGS:
        text = template.render(
            lang=lang, L=LABELS[lang], meta=inp.meta, findings=main, vulns=vulns, coverage=inp.coverage,
            req=inp.mapping.get, narrative=narratives.get(lang), skipped=skipped,
            preflight=inp.preflight, manifest=inp.manifest,
        )
        path = out_dir / f"report.{lang}.md"
        path.write_text(text, encoding="utf-8")
        paths[lang] = path
    return paths

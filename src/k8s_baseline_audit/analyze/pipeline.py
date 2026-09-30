"""Deterministic analysis: bundle -> findings.json + coverage.json."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from ..bundle import Bundle, dump_json
from ..mapping.schema import Mapping
from ..models import CoverageEntry, Finding, Source, finding_id
from .checks import all_checks
from .checks.base import AnalyzerConfig, Check, CheckContext, Hit, ManualCheckNeeded
from .coverage import compute_coverage
from .dedupe import dedupe
from .scanners import parse_scanner_file

RunState = Literal["ran", "not_run", "manual"]


@dataclass(frozen=True)
class CheckRun:
    check_id: str
    state: RunState
    reason: str | None = None


@dataclass(frozen=True)
class AnalysisResult:
    meta: dict
    findings: list[Finding]
    runs: list[CheckRun]
    coverage: list[CoverageEntry]


def load_resources(bundle: Bundle) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for rel in bundle.files_under("resources/"):
        kind = rel.removeprefix("resources/").removesuffix(".json")
        doc = bundle.read_json(rel)
        out[kind] = (
            doc["items"] if isinstance(doc, dict) and isinstance(doc.get("items"), list) else [doc]
        )
    return out


def _to_findings(check: Check, hits: list[Hit], mapping: Mapping) -> list[Finding]:
    grouped: dict[str, list[Hit]] = {}
    for hit in hits:
        grouped.setdefault(hit.resource.key(), []).append(hit)
    findings = []
    for key in sorted(grouped):
        group = grouped[key]
        ref = group[0].resource
        findings.append(
            Finding(
                id=finding_id(check.id, ref),
                check_id=check.id,
                title=check.title,
                severity=check.severity,
                resources=[ref],
                evidence=sorted({h.evidence for h in group}, key=lambda e: (e.file, e.json_path)),
                sources=[Source.BUILTIN],
                requirements=mapping.requirements_for_check(check.id),
                remediation=check.remediation,
            )
        )
    return findings


def _run_checks(resources, config, mapping, errors) -> tuple[list[Finding], list[CheckRun]]:
    context = CheckContext(resources=resources, config=config)
    findings: list[Finding] = []
    runs: list[CheckRun] = []
    for chk in all_checks():
        missing = [k for k in chk.requires if k not in resources]
        if missing:
            reason = "; ".join(f"{k}: {errors.get(k, 'not collected')}" for k in missing)
            runs.append(CheckRun(chk.id, "not_run", reason))
            continue
        try:
            hits = chk.fn(context)
        except ManualCheckNeeded as exc:
            runs.append(CheckRun(chk.id, "manual", exc.reason))
            continue
        runs.append(CheckRun(chk.id, "ran"))
        findings.extend(_to_findings(chk, hits, mapping))
    return findings, runs


def analyze(
    bundle: Bundle, mapping: Mapping, config: AnalyzerConfig, tool_version: str
) -> AnalysisResult:
    resources = load_resources(bundle)
    errors = {e.get("resource"): e.get("reason") for e in bundle.errors}
    builtin, runs = _run_checks(resources, config, mapping, errors)

    scanner: list[Finding] = []
    for rel in bundle.files_under("scanners/"):
        for f in parse_scanner_file(rel, bundle.read_json(rel)):
            f.requirements = mapping.requirements_for_check(f.check_id)
            scanner.append(f)

    findings = dedupe(builtin, scanner, resources.get("pods", []))
    findings.sort(key=lambda f: (f.severity.rank, f.check_id, f.id))
    coverage = compute_coverage(mapping, findings, runs)
    manifest = bundle.manifest
    meta = {
        "tool": {"name": "k8s-baseline-audit", "version": tool_version},
        "mapping": {
            "name": mapping.name,
            "framework": mapping.framework,
            "edition": mapping.edition,
            "modules": list(mapping.modules),
        },
        "bundle": {
            "cluster": manifest.get("cluster") or {},
            "created_at": manifest.get("created_at"),
            "producer": manifest.get("producer"),
            "provenance_verified": bundle.provenance_verified,
            "manifest_sha256": bundle.manifest_sha256(),
            "scanners": manifest.get("scanners") or {},
        },
        "config": {
            "as_of": config.as_of.isoformat(),
            "registry_allowlist": list(config.registry_allowlist),
            "admin_subject_allowlist": list(config.admin_subject_allowlist),
            "anonymous_binding_allowlist": list(config.anonymous_binding_allowlist),
            "system_namespaces": list(config.system_namespaces),
        },
    }
    return AnalysisResult(meta, findings, sorted(runs, key=lambda r: r.check_id), coverage)


def write_analysis(result: AnalysisResult, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_path = out_dir / "findings.json"
    coverage_path = out_dir / "coverage.json"
    findings_path.write_bytes(
        dump_json(
            {
                "meta": result.meta,
                "findings": [f.model_dump(mode="json") for f in result.findings],
                "check_runs": [asdict(r) for r in result.runs],
            }
        )
    )
    coverage_path.write_bytes(
        dump_json({"coverage": [c.model_dump(mode="json") for c in result.coverage]})
    )
    return findings_path, coverage_path

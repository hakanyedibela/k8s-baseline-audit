"""Derive one coverage status per requirement. Never claims fulfilment."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..mapping.schema import CoverageType, Mapping
from ..models import CoverageEntry, CoverageStatus, Finding

if TYPE_CHECKING:
    from .pipeline import CheckRun


def compute_coverage(
    mapping: Mapping, findings: list[Finding], runs: list[CheckRun]
) -> list[CoverageEntry]:
    by_check = {r.check_id: r for r in runs}
    entries: list[CoverageEntry] = []
    for req in mapping.requirements:
        if req.coverage_type == CoverageType.ORGANIZATIONAL:
            entries.append(
                CoverageEntry(requirement_id=req.id, status=CoverageStatus.ORGANIZATIONAL)
            )
            continue
        if req.coverage_type == CoverageType.MANUAL:
            entries.append(CoverageEntry(requirement_id=req.id, status=CoverageStatus.MANUAL))
            continue
        finding_ids = sorted(f.id for f in findings if req.id in f.requirements)
        not_run, manual = [], []
        for cid in req.checks:
            run = by_check.get(cid)
            if run is None:
                not_run.append(f"{cid}: check did not run")
            elif run.state == "not_run":
                not_run.append(f"{cid}: {run.reason}")
            elif run.state == "manual":
                manual.append(f"{cid}: {run.reason}")
        reasons = sorted(not_run + manual)
        if finding_ids:
            status = CoverageStatus.DEVIATION
        elif not_run:
            status = CoverageStatus.NOT_CHECKED
        elif manual:
            status = CoverageStatus.MANUAL
        elif req.coverage_type == CoverageType.PARTIAL:
            status = CoverageStatus.PARTIAL
        else:
            status = CoverageStatus.NO_DEVIATION
        entries.append(
            CoverageEntry(
                requirement_id=req.id, status=status, finding_ids=finding_ids, reasons=reasons
            )
        )
    return entries

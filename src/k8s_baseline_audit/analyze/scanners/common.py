from __future__ import annotations

from ...models import Evidence, Finding, Localized, ResourceRef, Severity, Source, finding_id


class ScannerFormatError(Exception):
    """Scanner output does not have the expected structure."""


def entries(value: object, where: str) -> list[dict]:
    """A scanner list (missing or empty means none) whose entries must all be objects."""
    if not value:
        return []
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise ScannerFormatError(f"{where}: expected a list of objects")
    return value


def map_severity(raw: str | None) -> tuple[Severity, bool]:
    try:
        return Severity((raw or "").lower()), False
    except ValueError:
        return Severity.LOW, True


def make_finding(
    check_id: str,
    ref: ResourceRef,
    title: Localized,
    severity: Severity,
    unmapped: bool,
    evidence: Evidence,
    source: Source,
    remediation: Localized,
) -> Finding:
    return Finding(
        id=finding_id(check_id, ref),
        check_id=check_id,
        title=title,
        severity=severity,
        severity_unmapped=unmapped,
        resources=[ref],
        evidence=[evidence],
        sources=[source],
        remediation=remediation,
    )


def same(text: str) -> Localized:
    return Localized(de=text, en=text)

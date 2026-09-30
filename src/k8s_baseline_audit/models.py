"""Core data model shared by collector, analyzer and report."""

from __future__ import annotations

import hashlib
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return _RANK[self.value]

    def at_or_above(self, other: Severity) -> bool:
        return self.rank <= other.rank


class Source(StrEnum):
    BUILTIN = "built-in"
    KUBESCAPE = "kubescape"
    TRIVY = "trivy"
    KUBE_BENCH = "kube-bench"


class Localized(BaseModel):
    model_config = ConfigDict(frozen=True)
    de: str
    en: str


class ResourceRef(BaseModel):
    model_config = ConfigDict(frozen=True)
    kind: str
    name: str
    namespace: str | None = None

    def key(self) -> str:
        return f"{self.kind}/{self.namespace or '-'}/{self.name}"


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)
    file: str
    json_path: str


class Finding(BaseModel):
    id: str
    check_id: str
    title: Localized
    severity: Severity
    resources: list[ResourceRef]
    evidence: list[Evidence]
    sources: list[Source]
    requirements: list[str] = Field(default_factory=list)
    remediation: Localized
    severity_unmapped: bool = False


class CoverageStatus(StrEnum):
    NO_DEVIATION = "no_deviation_found"
    DEVIATION = "deviation"
    PARTIAL = "partially_checked"
    MANUAL = "manual_check_needed"
    ORGANIZATIONAL = "organizational"
    NOT_CHECKED = "not_checked"


class CoverageEntry(BaseModel):
    requirement_id: str
    status: CoverageStatus
    finding_ids: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


def finding_id(check_id: str, resource: ResourceRef) -> str:
    return hashlib.sha256(f"{check_id}|{resource.key()}".encode()).hexdigest()[:16]

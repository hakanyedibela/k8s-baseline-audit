"""Versioned mapping from checks to BSI IT-Grundschutz requirements."""

from __future__ import annotations

import re
from enum import StrEnum
from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, model_validator

from ..models import Localized

_ID = re.compile(r"^(?P<module>(?:APP\.4\.4|SYS\.1\.6))\.A(?P<num>\d+)$")


def requirement_sort_key(rid: str) -> tuple[str, int]:
    """Sort key for requirement IDs: module name, then numeric suffix."""
    m = _ID.match(rid)
    if not m:
        return (rid, 0)
    return (m.group("module"), int(m.group("num")))


class CoverageType(StrEnum):
    """Type of coverage a requirement provides."""

    AUTOMATIC = "automatic"
    PARTIAL = "partial"
    MANUAL = "manual"
    ORGANIZATIONAL = "organizational"


class Level(StrEnum):
    """Level of a BSI requirement."""

    BASIC = "basic"
    STANDARD = "standard"
    ELEVATED = "elevated"


class SourceRef(BaseModel):
    """Reference to the source document where requirement is defined."""

    document: str
    edition: str
    url: str
    page: int | None = None


class Requirement(BaseModel):
    """A BSI IT-Grundschutz requirement mapped to checks."""

    id: str = Field(pattern=_ID.pattern)
    module: str
    level: Level
    title: Localized
    summary: Localized
    source: SourceRef
    coverage_type: CoverageType
    checks: list[str] = Field(default_factory=list)
    questions: list[Localized] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent(self) -> Requirement:
        """Validate that requirement is internally consistent."""
        if not self.id.startswith(self.module + ".A"):
            raise ValueError(f"{self.id} does not belong to module {self.module}")
        automated = (CoverageType.AUTOMATIC, CoverageType.PARTIAL)
        if self.coverage_type in automated and not self.checks:
            raise ValueError(f"{self.id}: {self.coverage_type.value} requirement needs checks")
        if self.coverage_type not in automated and not self.questions:
            raise ValueError(f"{self.id}: {self.coverage_type.value} requirement needs questions")
        return self


class UnmappedCheck(BaseModel):
    """A check that does not map to any requirement."""

    check_id: str
    reason: Localized


class Mapping(BaseModel):
    """Complete mapping of checks to BSI IT-Grundschutz requirements."""

    name: str
    framework: str
    edition: str
    modules: list[str]
    requirements: list[Requirement]
    unmapped_checks: list[UnmappedCheck] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique(self) -> Mapping:
        """Validate that requirement IDs are unique and modules are consistent."""
        ids = [r.id for r in self.requirements]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate requirement ids: {dupes}")
        unknown = sorted({r.module for r in self.requirements} - set(self.modules))
        if unknown:
            raise ValueError(f"requirements reference unlisted modules: {unknown}")
        self.requirements.sort(key=lambda r: requirement_sort_key(r.id))
        return self

    def get(self, requirement_id: str) -> Requirement:
        """Get a requirement by ID."""
        for r in self.requirements:
            if r.id == requirement_id:
                return r
        raise KeyError(requirement_id)

    def requirements_for_check(self, check_id: str) -> list[str]:
        """Get all requirement IDs that contain the given check."""
        return [r.id for r in self.requirements if check_id in r.checks]


def load_mapping_file(path: Path) -> Mapping:
    """Load mapping from a YAML file."""
    return Mapping.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def load_mapping(name: str = "kompendium-2023") -> Mapping:
    """Load a packaged mapping by name."""
    resource = files("k8s_baseline_audit.mappings").joinpath(f"{name}.yaml")
    if not resource.is_file():
        raise FileNotFoundError(f"unknown mapping: {name}")
    return Mapping.model_validate(yaml.safe_load(resource.read_text(encoding="utf-8")))

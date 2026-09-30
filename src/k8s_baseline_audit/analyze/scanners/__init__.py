"""Parsers that turn scanner JSON into the common finding model."""

from __future__ import annotations

from ...models import Finding
from . import kube_bench, kubescape, trivy
from .common import ScannerFormatError


def parse_scanner_file(rel: str, doc: dict) -> list[Finding]:
    name = rel.removeprefix("scanners/")
    if name == "trivy.json":
        return trivy.parse(doc, rel)
    if name == "kubescape.json":
        return kubescape.parse(doc, rel)
    if name.startswith("kube-bench-") and name.endswith(".json"):
        node = name.removeprefix("kube-bench-").removesuffix(".json")
        return kube_bench.parse(doc, rel, node or "unknown")
    raise ScannerFormatError(f"unknown scanner file: {rel}")


__all__ = ["ScannerFormatError", "parse_scanner_file"]

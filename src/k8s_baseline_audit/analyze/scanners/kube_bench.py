from __future__ import annotations

from ...models import Evidence, Finding, ResourceRef, Severity, Source
from .common import ScannerFormatError, make_finding, same

STATUS_SEVERITY = {"FAIL": Severity.MEDIUM, "WARN": Severity.LOW}


def parse(doc: dict, rel: str, node: str) -> list[Finding]:
    controls = doc.get("Controls")
    if not isinstance(controls, list):
        raise ScannerFormatError(f"{rel}: expected top-level 'Controls' list (kube-bench JSON)")
    ref = ResourceRef(kind="Node", name=node)
    out: list[Finding] = []
    for i, control in enumerate(controls):
        for j, test in enumerate(control.get("tests") or []):
            for k, result in enumerate(test.get("results") or []):
                severity = STATUS_SEVERITY.get(result.get("status"))
                if severity is None:
                    continue
                cid = f"kube-bench:{result.get('test_number') or 'unknown'}"
                out.append(
                    make_finding(
                        cid,
                        ref,
                        same(result.get("test_desc") or cid),
                        severity,
                        True,
                        Evidence(
                            file=rel, json_path=f"$.Controls[{i}].tests[{j}].results[{k}]"
                        ),
                        Source.KUBE_BENCH,
                        same(result.get("remediation") or ""),
                    )
                )
    return out

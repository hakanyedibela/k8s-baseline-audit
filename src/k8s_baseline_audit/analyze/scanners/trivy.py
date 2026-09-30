from __future__ import annotations

from ...models import Evidence, Finding, Localized, ResourceRef, Source
from .common import ScannerFormatError, make_finding, map_severity, same


def parse(doc: dict, rel: str) -> list[Finding]:
    resources = doc.get("Resources")
    if not isinstance(resources, list):
        raise ScannerFormatError(f"{rel}: expected top-level 'Resources' list (trivy k8s JSON)")
    out: list[Finding] = []
    for i, r in enumerate(resources):
        ref = ResourceRef(
            kind=r.get("Kind") or "Unknown",
            name=r.get("Name") or "?",
            namespace=r.get("Namespace") or None,
        )
        for j, result in enumerate(r.get("Results") or []):
            base = f"$.Resources[{i}].Results[{j}]"
            for k, m in enumerate(result.get("Misconfigurations") or []):
                if m.get("Status", "FAIL") != "FAIL":
                    continue
                cid = f"trivy:{m.get('ID') or m.get('AVDID') or 'unknown'}"
                sev, unmapped = map_severity(m.get("Severity"))
                out.append(
                    make_finding(
                        cid,
                        ref,
                        same(m.get("Title") or cid),
                        sev,
                        unmapped,
                        Evidence(file=rel, json_path=f"{base}.Misconfigurations[{k}]"),
                        Source.TRIVY,
                        same(m.get("Resolution") or ""),
                    )
                )
            for k, v in enumerate(result.get("Vulnerabilities") or []):
                vid = v.get("VulnerabilityID") or "unknown"
                sev, unmapped = map_severity(v.get("Severity"))
                title = f"{vid} in {v.get('PkgName', '?')} {v.get('InstalledVersion', '')}".strip()
                fixed = v.get("FixedVersion")
                if fixed:
                    fix = Localized(
                        de=f"Paket auf Version {fixed} aktualisieren.",
                        en=f"Update the package to {fixed}.",
                    )
                else:
                    fix = Localized(
                        de="Keine korrigierte Version verfügbar.",
                        en="No fixed version available.",
                    )
                out.append(
                    make_finding(
                        f"trivy:{vid}",
                        ref,
                        same(title),
                        sev,
                        unmapped,
                        Evidence(file=rel, json_path=f"{base}.Vulnerabilities[{k}]"),
                        Source.TRIVY,
                        fix,
                    )
                )
            for k, s in enumerate(result.get("Secrets") or []):
                cid = f"trivy:secret:{s.get('RuleID') or 'unknown'}"
                sev, unmapped = map_severity(s.get("Severity"))
                out.append(
                    make_finding(
                        cid,
                        ref,
                        same(s.get("Title") or cid),
                        sev,
                        unmapped,
                        Evidence(file=rel, json_path=f"{base}.Secrets[{k}]"),
                        Source.TRIVY,
                        Localized(
                            de="Zugangsdaten aus dem Image entfernen und rotieren.",
                            en="Remove the credential from the image and rotate it.",
                        ),
                    )
                )
    return out

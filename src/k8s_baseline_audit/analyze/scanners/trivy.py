from __future__ import annotations

from ...models import Evidence, Finding, Localized, ResourceRef, Source
from .common import ScannerFormatError, entries, make_finding, map_severity, same


def parse(doc: dict, rel: str) -> list[Finding]:
    resources = doc.get("Resources")
    if not isinstance(resources, list):
        raise ScannerFormatError(f"{rel}: expected top-level 'Resources' list (trivy k8s JSON)")
    out: list[Finding] = []
    for i, r in enumerate(entries(resources, f"{rel}: Resources")):
        ref = ResourceRef(
            kind=r.get("Kind") or "Unknown",
            name=r.get("Name") or "?",
            namespace=r.get("Namespace") or None,
        )
        for j, result in enumerate(entries(r.get("Results"), f"{rel}: Resources[{i}].Results")):
            base = f"$.Resources[{i}].Results[{j}]"
            where = f"{rel}: {base}"
            misconfigs = entries(result.get("Misconfigurations"), f"{where}.Misconfigurations")
            for k, m in enumerate(misconfigs):
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
            vulns = entries(result.get("Vulnerabilities"), f"{where}.Vulnerabilities")
            for k, v in enumerate(vulns):
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
            secrets = entries(result.get("Secrets"), f"{where}.Secrets")
            for k, s in enumerate(secrets):
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

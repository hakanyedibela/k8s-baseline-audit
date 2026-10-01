from __future__ import annotations

from ...models import Evidence, Finding, Localized, ResourceRef, Source
from .common import ScannerFormatError, entries, make_finding, map_severity, same


def _ref(resource_id: str, obj: dict) -> ResourceRef:
    # kubescape 4.x: full manifests carry metadata.name; flat wrappers carry name/namespace.
    md = obj.get("metadata") or {}
    name = md.get("name") or obj.get("name")
    if obj.get("kind") and name:
        namespace = md.get("namespace") or obj.get("namespace") or None
        return ResourceRef(kind=obj["kind"], name=name, namespace=namespace)
    # resourceID is "<apiGroup>/<version>/<namespace>/<Kind>/<name>"
    parts = resource_id.split("/")
    ns, kind, name = (["", "Unknown", resource_id] + parts)[-3:]
    return ResourceRef(kind=kind, name=name, namespace=ns or None)


def parse(doc: dict, rel: str) -> list[Finding]:
    results = doc.get("results")
    if not isinstance(results, list):
        raise ScannerFormatError(f"{rel}: expected top-level 'results' list (kubescape JSON)")
    resources = entries(doc.get("resources"), f"{rel}: resources")
    objects = {r.get("resourceID"): (r.get("object") or {}) for r in resources}
    meta = (doc.get("summaryDetails") or {}).get("controls") or {}
    out: list[Finding] = []
    for i, res in enumerate(entries(results, f"{rel}: results")):
        rid = res.get("resourceID") or ""
        ref = _ref(rid, objects.get(rid) or {})
        for k, control in enumerate(entries(res.get("controls"), f"{rel}: results[{i}].controls")):
            if ((control.get("status") or {}).get("status") or "").lower() != "failed":
                continue
            raw_id = control.get("controlID") or "unknown"
            info = meta.get(raw_id) or {}
            sev, unmapped = map_severity(control.get("severity") or info.get("severity"))
            title = control.get("name") or info.get("name") or raw_id
            fix = Localized(
                de=f"Siehe kubescape-Dokumentation zu {raw_id}.",
                en=f"See the kubescape documentation for {raw_id}.",
            )
            out.append(
                make_finding(
                    f"kubescape:{raw_id}",
                    ref,
                    same(title),
                    sev,
                    unmapped,
                    Evidence(file=rel, json_path=f"$.results[{i}].controls[{k}]"),
                    Source.KUBESCAPE,
                    fix,
                )
            )
    return out

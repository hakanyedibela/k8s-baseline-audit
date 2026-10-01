"""Strip sensitive payloads from scanner output before it enters a bundle.

scripts/export-bundle.sh implements the same rules in jq (parity test in
tests/test_export_script.py).
"""

from __future__ import annotations

import copy


class SanitizeShapeError(ValueError):
    """Scanner output lacks the structure the parser needs; nothing may be written."""


def _require(ok: bool, scanner: str) -> None:
    if not ok:
        raise SanitizeShapeError(f"{scanner} output has unexpected shape")


# kubescape 4.x emits two object shapes: full manifests (apiVersion/kind/metadata/spec)
# and flat wrappers (kind/name/namespace/relatedObjects). Only identity survives.
_IDENTITY_KEYS = ("apiVersion", "apiGroup", "kind", "name", "namespace")


def _identity(obj: dict) -> dict:
    out = {key: obj[key] for key in _IDENTITY_KEYS if obj.get(key) is not None}
    md = obj.get("metadata")
    if isinstance(md, dict):
        out["metadata"] = {k: md[k] for k in ("name", "namespace") if md.get(k) is not None}
    return out


# Allowlists per level: only what the parsers and the report read survives, so unknown or
# future scanner fields can never carry secrets into a bundle, and bundles stay small.
_KS_CONTROL_SUMMARY = ("name", "severity", "controlID")
_KS_CONTROL = ("controlID", "name", "severity", "status")


def _ks_resource(resource: dict) -> dict:
    out = _pick(resource, ("resourceID", "object"))
    if isinstance(out.get("object"), dict):
        out["object"] = _identity(out["object"])
    return out


def _ks_result(result: dict) -> dict:
    out = _pick(result, ("resourceID", "controls"))
    if "controls" in out:
        out["controls"] = _each(out["controls"], _ks_control)
    return out


def _ks_control(control: dict) -> dict:
    out = _pick(control, _KS_CONTROL)
    if isinstance(out.get("status"), dict):
        out["status"] = _pick(out["status"], ("status",))
    return out


def sanitize_kubescape(doc: dict) -> dict:
    _require(
        isinstance(doc, dict)
        and isinstance(doc.get("results"), list)
        and isinstance(doc.get("resources", []), list),
        "kubescape",
    )
    doc = copy.deepcopy(doc)
    out: dict = {"results": _each(doc["results"], _ks_result)}
    if "resources" in doc:
        out["resources"] = _each(doc["resources"], _ks_resource)
    summary = doc.get("summaryDetails")
    controls = summary.get("controls") if isinstance(summary, dict) else None
    if isinstance(controls, dict):
        out["summaryDetails"] = {
            "controls": {
                k: _pick(v, _KS_CONTROL_SUMMARY) for k, v in controls.items() if isinstance(v, dict)
            }
        }
    return out


_IMAGE_KEYS = ("RepoTags", "RepoDigests", "ImageID", "OS")
# Allowlists: free-form records keep only the fields the parsers read or report needs.
_BENCH_KEEP = ("test_number", "test_desc", "status", "scored", "remediation", "type")
_BENCH_CONTROL = ("id", "version", "text", "node_type", "tests")
_BENCH_TEST = ("section", "desc", "results")
_TRIVY_RESOURCE = ("Namespace", "Kind", "Name", "Metadata", "Results")
_TRIVY_RESULT = (
    "Target",
    "Class",
    "Type",
    "Metadata",
    "Misconfigurations",
    "Vulnerabilities",
    "Secrets",
)
_TRIVY_MISCONFIG = ("ID", "AVDID", "Title", "Severity", "Status", "Resolution")
_TRIVY_VULN = ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity")
_SECRET_KEEP = ("RuleID", "Category", "Severity", "Title", "StartLine", "EndLine")
_LAYER_KEEP = ("Digest", "DiffID")


def _pick(obj: dict, keys: tuple[str, ...]) -> dict:
    if not isinstance(obj, dict):
        raise SanitizeShapeError("scanner record is not an object")
    return {k: obj[k] for k in keys if k in obj}


def _each(value: list, fn) -> list:
    if not isinstance(value, list):
        raise SanitizeShapeError("scanner records are not a list")
    return [fn(v) for v in value]


def _secret(secret: dict) -> dict:
    out = _pick(secret, _SECRET_KEEP)  # raises for non-objects
    if isinstance(secret.get("Layer"), dict):
        out["Layer"] = _pick(secret["Layer"], _LAYER_KEEP)
    return out


def _image_identity(meta):
    if isinstance(meta, list):
        return [_image_identity(m) for m in meta]
    if isinstance(meta, dict):
        return {k: meta[k] for k in _IMAGE_KEYS if k in meta}
    return meta


def _bench_test(test: dict) -> dict:
    out = _pick(test, _BENCH_TEST)
    if out.get("results"):
        out["results"] = _each(out["results"], lambda r: _pick(r, _BENCH_KEEP))
    return out


def _bench_control(control: dict) -> dict:
    out = _pick(control, _BENCH_CONTROL)
    if out.get("tests"):
        out["tests"] = _each(out["tests"], _bench_test)
    return out


def sanitize_kube_bench(doc: dict) -> dict:
    _require(isinstance(doc, dict) and isinstance(doc.get("Controls"), list), "kube-bench")
    doc = copy.deepcopy(doc)
    return {"Controls": _each(doc["Controls"], _bench_control)}


def _trivy_result(result: dict) -> dict:
    out = _pick(result, _TRIVY_RESULT)
    if "Metadata" in out:
        out["Metadata"] = _image_identity(out["Metadata"])
    if out.get("Misconfigurations"):
        out["Misconfigurations"] = _each(
            out["Misconfigurations"], lambda m: _pick(m, _TRIVY_MISCONFIG)
        )
    if out.get("Vulnerabilities"):
        out["Vulnerabilities"] = _each(out["Vulnerabilities"], lambda v: _pick(v, _TRIVY_VULN))
    if out.get("Secrets"):
        out["Secrets"] = _each(out["Secrets"], _secret)
    return out


def _trivy_resource(resource: dict) -> dict:
    out = _pick(resource, _TRIVY_RESOURCE)
    if "Metadata" in out:
        out["Metadata"] = _image_identity(out["Metadata"])
    if out.get("Results"):
        out["Results"] = _each(out["Results"], _trivy_result)
    return out


def sanitize_trivy(doc: dict) -> dict:
    _require(isinstance(doc, dict) and isinstance(doc.get("Resources"), list), "trivy")
    doc = copy.deepcopy(doc)
    out = {"Resources": _each(doc["Resources"], _trivy_resource)}
    if "ClusterName" in doc:
        out["ClusterName"] = doc["ClusterName"]
    return out

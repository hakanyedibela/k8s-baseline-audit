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


def sanitize_kubescape(doc: dict) -> dict:
    _require(
        isinstance(doc, dict)
        and isinstance(doc.get("results"), list)
        and isinstance(doc.get("resources", []), list),
        "kubescape",
    )
    out = copy.deepcopy(doc)
    for resource in out.get("resources") or []:
        obj = resource.get("object")
        if isinstance(obj, dict):
            resource["object"] = _identity(obj)
    return out


_IMAGE_KEYS = ("RepoTags", "RepoDigests", "ImageID", "OS")
# Allowlists: free-form records keep only the fields the parsers read or report needs.
_BENCH_KEEP = ("test_number", "test_desc", "status", "scored", "remediation", "type")
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


def sanitize_kube_bench(doc: dict) -> dict:
    _require(isinstance(doc, dict) and isinstance(doc.get("Controls"), list), "kube-bench")
    out = copy.deepcopy(doc)
    for control in out["Controls"]:
        for test in control.get("tests") or []:
            if test.get("results"):
                test["results"] = _each(test["results"], lambda r: _pick(r, _BENCH_KEEP))
    return out


def sanitize_trivy(doc: dict) -> dict:
    _require(isinstance(doc, dict) and isinstance(doc.get("Resources"), list), "trivy")
    out = copy.deepcopy(doc)
    for resource in out["Resources"]:
        if "Metadata" in resource:
            resource["Metadata"] = _image_identity(resource["Metadata"])
        for result in resource.get("Results") or []:
            if "Metadata" in result:
                result["Metadata"] = _image_identity(result["Metadata"])
            for misconfig in result.get("Misconfigurations") or []:
                misconfig.pop("CauseMetadata", None)
            if result.get("Secrets"):
                result["Secrets"] = _each(result["Secrets"], _secret)
    return out

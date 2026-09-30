"""Strip sensitive payloads from scanner output before it enters a bundle.

scripts/export-bundle.sh implements the same rules in jq (parity test in
tests/test_export_script.py).
"""

from __future__ import annotations

import copy

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
    out = copy.deepcopy(doc)
    for resource in out.get("resources") or []:
        obj = resource.get("object")
        if isinstance(obj, dict):
            resource["object"] = _identity(obj)
    return out


_IMAGE_KEYS = ("RepoTags", "RepoDigests", "ImageID", "OS")
_BENCH_DROP = ("actual_value", "AuditConfig", "AuditEnv", "expected_result")


def _image_identity(meta):
    if isinstance(meta, list):
        return [_image_identity(m) for m in meta]
    if isinstance(meta, dict):
        return {k: meta[k] for k in _IMAGE_KEYS if k in meta}
    return meta


def sanitize_kube_bench(doc: dict) -> dict:
    out = copy.deepcopy(doc)
    for control in out.get("Controls") or []:
        for test in control.get("tests") or []:
            for result in test.get("results") or []:
                for key in _BENCH_DROP:
                    result.pop(key, None)
    return out


def sanitize_trivy(doc: dict) -> dict:
    out = copy.deepcopy(doc)
    for resource in out.get("Resources") or []:
        if "Metadata" in resource:
            resource["Metadata"] = _image_identity(resource["Metadata"])
        for result in resource.get("Results") or []:
            if "Metadata" in result:
                result["Metadata"] = _image_identity(result["Metadata"])
            for misconfig in result.get("Misconfigurations") or []:
                misconfig.pop("CauseMetadata", None)
            for secret in result.get("Secrets") or []:
                secret.pop("Match", None)
                secret.pop("Code", None)
    return out

"""Merge findings that different sources report for the same issue and workload."""

from __future__ import annotations

from ..mapping.schema import requirement_sort_key
from ..models import Finding, ResourceRef

# scanner check id -> built-in check id. Every entry was verified against the captured
# fixtures (trivy 0.74.0, kubescape 4.0.15; see tests/fixtures/scanners/VERSIONS).
# Host-namespace scanner checks (trivy KSV-0009, kubescape C-0041) cover hostNetwork only,
# a subset of workload.host_namespaces, so they are deliberately not aliased.
ALIASES: dict[str, str] = {
    "trivy:KSV-0017": "workload.privileged",
    "trivy:KSV-0001": "workload.privilege_escalation",
    "trivy:KSV-0012": "workload.run_as_non_root_missing",
    "trivy:KSV-0014": "workload.writable_root_fs",
    "trivy:KSV-0023": "workload.host_path",
    "kubescape:C-0057": "workload.privileged",
    "kubescape:C-0016": "workload.privilege_escalation",
    "kubescape:C-0013": "workload.run_as_non_root_missing",
    "kubescape:C-0017": "workload.writable_root_fs",
    "kubescape:C-0048": "workload.host_path",
}
OWNER_KINDS = frozenset({"ReplicaSet", "StatefulSet", "DaemonSet", "Job"})

Key = tuple[str | None, str]


def pod_owner_map(pods: list[dict]) -> dict[Key, Key]:
    out: dict[Key, Key] = {}
    for p in pods:
        md = p.get("metadata") or {}
        ns, name = md.get("namespace"), md.get("name") or "?"
        owner = (md.get("ownerReferences") or [{}])[0] or {}
        kind, owner_name = owner.get("kind"), owner.get("name")
        workload = name
        if kind in OWNER_KINDS and owner_name:
            workload = owner_name
            template_hash = (md.get("labels") or {}).get("pod-template-hash")
            if kind == "ReplicaSet" and template_hash:
                workload = owner_name.removesuffix(f"-{template_hash}")
        out[(ns, name)] = (ns, workload)
    return out


def _workload(ref: ResourceRef, owners: dict[Key, Key]) -> Key:
    if ref.kind == "Pod":
        return owners.get((ref.namespace, ref.name), (ref.namespace, ref.name))
    return (ref.namespace, ref.name)


def _merge(target: Finding, other: Finding) -> None:
    target.sources = sorted(set(target.sources) | set(other.sources), key=lambda s: s.value)
    target.evidence = sorted(
        set(target.evidence) | set(other.evidence), key=lambda e: (e.file, e.json_path)
    )
    target.requirements = sorted(
        set(target.requirements) | set(other.requirements), key=requirement_sort_key
    )


def dedupe(builtin: list[Finding], scanner: list[Finding], pods: list[dict]) -> list[Finding]:
    owners = pod_owner_map(pods)
    result = [f.model_copy(deep=True) for f in builtin]
    index: dict[tuple[str, str | None, str], Finding] = {}
    for f in result:
        index.setdefault((f.check_id, *_workload(f.resources[0], owners)), f)
    for s in scanner:
        s = s.model_copy(deep=True)
        workload = _workload(s.resources[0], owners)
        key = (ALIASES.get(s.check_id, s.check_id), *workload)
        match = index.get(key)
        if match is None:
            result.append(s)
            index[key] = s
        else:
            _merge(match, s)
    return result

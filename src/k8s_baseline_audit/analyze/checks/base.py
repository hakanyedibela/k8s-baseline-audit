"""Check framework: registry, context and helpers shared by all checks."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import date

from ...models import Evidence, Localized, ResourceRef, Severity


class ManualCheckNeeded(Exception):
    """The collected data cannot decide this check; a person must verify it."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class AnalyzerConfig:
    as_of: date
    registry_allowlist: tuple[str, ...] = ()
    admin_subject_allowlist: tuple[str, ...] = (
        "Group:system:masters",
        "Group:kubeadm:cluster-admins",
    )
    anonymous_binding_allowlist: tuple[str, ...] = (
        "ClusterRoleBinding/-/system:public-info-viewer",
        "RoleBinding/kube-public/kubeadm:bootstrap-signer-clusterinfo",
    )


@dataclass(frozen=True)
class Hit:
    resource: ResourceRef
    evidence: Evidence


@dataclass(frozen=True)
class CheckContext:
    resources: Mapping[str, list[dict]]
    config: AnalyzerConfig

    def items(self, kind: str) -> list[dict]:
        return list(self.resources.get(kind) or [])


CheckFn = Callable[[CheckContext], list[Hit]]


@dataclass(frozen=True)
class Check:
    id: str
    requires: tuple[str, ...]
    severity: Severity
    title: Localized
    remediation: Localized
    fn: CheckFn


REGISTRY: dict[str, Check] = {}


def check(
    id: str,
    requires: tuple[str, ...],
    severity: Severity,
    title_de: str,
    title_en: str,
    fix_de: str,
    fix_en: str,
) -> Callable[[CheckFn], CheckFn]:
    def decorator(fn: CheckFn) -> CheckFn:
        if id in REGISTRY:
            raise ValueError(f"duplicate check id: {id}")
        REGISTRY[id] = Check(
            id=id,
            requires=requires,
            severity=severity,
            title=Localized(de=title_de, en=title_en),
            remediation=Localized(de=fix_de, en=fix_en),
            fn=fn,
        )
        return fn

    return decorator


def ev(kind: str, json_path: str) -> Evidence:
    return Evidence(file=f"resources/{kind}.json", json_path=json_path)


def meta_ref(kind_label: str, obj: dict) -> ResourceRef:
    md = obj.get("metadata") or {}
    return ResourceRef(
        kind=kind_label,
        name=md.get("name") or "?",
        namespace=md.get("namespace") or None,
    )


CONTAINER_FIELDS = ("initContainers", "containers", "ephemeralContainers")


def spec_of(obj: dict) -> dict:
    return obj.get("spec") or {}


def iter_containers(
    pod: dict, fields: tuple[str, ...] = CONTAINER_FIELDS
) -> Iterator[tuple[str, int, dict]]:
    spec = spec_of(pod)
    for field_name in fields:
        for idx, c in enumerate(spec.get(field_name) or []):
            yield field_name, idx, c or {}


def sc(obj: dict) -> dict:
    return obj.get("securityContext") or {}


def container_path(i: int, field_name: str, j: int) -> str:
    return f"$.items[{i}].spec.{field_name}[{j}]"


def is_static_pod(pod: dict) -> bool:
    """Check if pod is a static/mirror pod (owned by a Node)."""
    owners = (pod.get("metadata") or {}).get("ownerReferences") or []
    return any((owner or {}).get("kind") == "Node" for owner in owners)

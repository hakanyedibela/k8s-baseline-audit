"""Container and pod hardening checks (SYS.1.6 / APP.4.4 workload requirements)."""

from __future__ import annotations

from ...models import Severity
from .base import (
    CheckContext,
    Hit,
    check,
    container_path,
    ev,
    iter_containers,
    meta_ref,
    sc,
    spec_of,
)

POD = ("pods",)
ALLOWED_ADDED_CAPS = frozenset({"NET_BIND_SERVICE"})
SAFE_SECCOMP = frozenset({"RuntimeDefault", "Localhost"})


def _hits_per_container(ctx: CheckContext, predicate, suffix: str, fields=None) -> list[Hit]:
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        kwargs = {"fields": fields} if fields else {}
        for field_name, j, c in iter_containers(p, **kwargs):
            if predicate(p, c):
                path = container_path(i, field_name, j) + suffix
                hits.append(Hit(meta_ref("Pod", p), ev("pods", path)))
    return hits


def _effective(p: dict, c: dict, key: str):
    value = sc(c).get(key)
    return value if value is not None else sc(spec_of(p)).get(key)


@check(
    "workload.privileged",
    POD,
    Severity.CRITICAL,
    "Privilegierter Container",
    "Privileged container",
    "securityContext.privileged entfernen oder auf false setzen.",
    "Remove securityContext.privileged or set it to false.",
)
def privileged(ctx: CheckContext) -> list[Hit]:
    return _hits_per_container(
        ctx,
        lambda p, c: sc(c).get("privileged") is True,
        ".securityContext.privileged",  # noqa: E501
    )


@check(
    "workload.run_as_root",
    POD,
    Severity.HIGH,
    "Container läuft als root (UID 0)",
    "Container runs as root (UID 0)",
    "runAsUser auf eine UID größer 0 setzen und runAsNonRoot: true ergänzen.",
    "Set runAsUser to a UID above 0 and add runAsNonRoot: true.",
)
def run_as_root(ctx: CheckContext) -> list[Hit]:
    return _hits_per_container(
        ctx, lambda p, c: _effective(p, c, "runAsUser") == 0, ".securityContext"
    )


@check(
    "workload.run_as_non_root_missing",
    POD,
    Severity.MEDIUM,
    "Nicht-root-Ausführung nicht erzwungen",
    "Non-root execution not enforced",
    "runAsNonRoot: true auf Pod- oder Container-Ebene setzen.",
    "Set runAsNonRoot: true at pod or container level.",
)
def run_as_non_root_missing(ctx: CheckContext) -> list[Hit]:
    def missing(p: dict, c: dict) -> bool:
        uid = _effective(p, c, "runAsUser")
        is_non_root = _effective(p, c, "runAsNonRoot") is True
        has_uid = isinstance(uid, int) and uid > 0
        return not is_non_root and not has_uid

    return _hits_per_container(ctx, missing, ".securityContext")


@check(
    "workload.privilege_escalation",
    POD,
    Severity.MEDIUM,
    "Rechteausweitung nicht unterbunden",
    "Privilege escalation not prevented",
    "allowPrivilegeEscalation: false im securityContext setzen.",
    "Set allowPrivilegeEscalation: false in the securityContext.",
)
def privilege_escalation(ctx: CheckContext) -> list[Hit]:
    return _hits_per_container(
        ctx,
        lambda p, c: sc(c).get("allowPrivilegeEscalation") is not False,
        ".securityContext",
    )


@check(
    "workload.added_capabilities",
    POD,
    Severity.HIGH,
    "Zusätzliche Linux-Capabilities",
    "Added Linux capabilities",
    "capabilities.add entfernen; nur NET_BIND_SERVICE ist bei Bedarf"  # noqa: E501
    " vertretbar. drop: [ALL] setzen.",
    "Remove capabilities.add; only NET_BIND_SERVICE is acceptable when needed."
    " Set drop: [ALL].",
)
def added_capabilities(ctx: CheckContext) -> list[Hit]:
    def bad(p: dict, c: dict) -> bool:
        added = (sc(c).get("capabilities") or {}).get("add") or []
        return any(cap not in ALLOWED_ADDED_CAPS for cap in added)

    return _hits_per_container(
        ctx, bad, ".securityContext.capabilities.add"  # noqa: E501
    )


@check("workload.host_namespaces", POD, Severity.HIGH,
       "Pod nutzt Host-Namespaces", "Pod uses host namespaces",
       "hostNetwork, hostPID und hostIPC entfernen, sofern nicht zwingend erforderlich.",
       "Remove hostNetwork, hostPID and hostIPC unless strictly required.")
def host_namespaces(ctx: CheckContext) -> list[Hit]:
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        spec = spec_of(p)
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(key) is True:
                hits.append(Hit(meta_ref("Pod", p), ev("pods", f"$.items[{i}].spec.{key}")))
    return hits


@check(
    "workload.host_path",
    POD,
    Severity.HIGH,
    "hostPath-Volume eingebunden",
    "hostPath volume mounted",
    "hostPath durch PersistentVolumes, ConfigMaps oder emptyDir ersetzen.",
    "Replace hostPath with PersistentVolumes, ConfigMaps or emptyDir.",
)
def host_path(ctx: CheckContext) -> list[Hit]:
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        for k, vol in enumerate(spec_of(p).get("volumes") or []):
            if (vol or {}).get("hostPath") is not None:
                path = f"$.items[{i}].spec.volumes[{k}].hostPath"  # noqa: E501
                hits.append(Hit(meta_ref("Pod", p), ev("pods", path)))
    return hits


@check("workload.writable_root_fs", POD, Severity.MEDIUM,
       "Beschreibbares Root-Dateisystem", "Writable root filesystem",
       "readOnlyRootFilesystem: true setzen; Schreibpfade als emptyDir einbinden.",
       "Set readOnlyRootFilesystem: true; mount write paths as emptyDir.")
def writable_root_fs(ctx: CheckContext) -> list[Hit]:
    return _hits_per_container(
        ctx, lambda p, c: sc(c).get("readOnlyRootFilesystem") is not True, ".securityContext"
    )


@check("workload.seccomp_missing", POD, Severity.MEDIUM,
       "Kein Seccomp-Profil", "No seccomp profile",
       "seccompProfile.type: RuntimeDefault auf Pod-Ebene setzen.",
       "Set seccompProfile.type: RuntimeDefault at pod level.")
def seccomp_missing(ctx: CheckContext) -> list[Hit]:
    def missing(p: dict, c: dict) -> bool:
        container_type = (sc(c).get("seccompProfile") or {}).get("type")
        pod_type = (sc(spec_of(p)).get("seccompProfile") or {}).get("type")
        effective = container_type if container_type is not None else pod_type
        return effective not in SAFE_SECCOMP

    return _hits_per_container(ctx, missing, ".securityContext")


@check("workload.resource_limits_missing", POD, Severity.LOW,
       "Fehlende CPU- oder Speicherlimits", "Missing CPU or memory limits",
       "resources.limits.cpu und resources.limits.memory für jeden Container setzen.",
       "Set resources.limits.cpu and resources.limits.memory for every container.")
def resource_limits_missing(ctx: CheckContext) -> list[Hit]:
    def missing(p: dict, c: dict) -> bool:
        limits = (c.get("resources") or {}).get("limits") or {}
        return "cpu" not in limits or "memory" not in limits

    return _hits_per_container(ctx, missing, ".resources", fields=("initContainers", "containers"))

"""Control plane checks from kubeadm static pod specs, and Kubernetes version support."""

from __future__ import annotations

import functools
import re
from datetime import date
from importlib.resources import files
from urllib.parse import urlparse

import yaml

from ...models import Evidence, ResourceRef, Severity
from .base import CheckContext, Hit, ManualCheckNeeded, check, ev, meta_ref, spec_of

LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})


def parse_flags(container: dict) -> dict[str, str]:
    flags: dict[str, str] = {}
    for arg in list(container.get("command") or []) + list(container.get("args") or []):
        if isinstance(arg, str) and arg.startswith("--"):
            key, _, value = arg[2:].partition("=")
            flags[key] = value
    return flags


def _static_pod(ctx: CheckContext, component: str) -> tuple[int, dict, dict[str, str]]:
    for i, p in enumerate(ctx.items("pods")):
        md = p.get("metadata") or {}
        if (
            md.get("namespace") == "kube-system"
            and (md.get("labels") or {}).get("component") == component
        ):
            containers = spec_of(p).get("containers") or [{}]
            return i, p, parse_flags(containers[0] or {})
    raise ManualCheckNeeded(
        f"{component} static pod not visible: managed cluster or no access to kube-system pods"
    )


def _api_hit(i: int, p: dict) -> list[Hit]:
    return [Hit(meta_ref("Pod", p), ev("pods", f"$.items[{i}].spec.containers[0].command"))]


@check(
    "control_plane.encryption_at_rest",
    ("pods",),
    Severity.HIGH,
    "Keine Verschlüsselung von Secrets in etcd konfiguriert",
    "No encryption at rest configured for etcd",
    "EncryptionConfiguration anlegen und --encryption-provider-config am API-Server setzen.",
    "Create an EncryptionConfiguration and set --encryption-provider-config on the API server.",
)
def encryption_at_rest(ctx: CheckContext) -> list[Hit]:
    i, p, flags = _static_pod(ctx, "kube-apiserver")
    return [] if flags.get("encryption-provider-config") else _api_hit(i, p)


@check(
    "control_plane.anonymous_auth",
    ("pods",),
    Severity.MEDIUM,
    "Anonyme Anfragen am API-Server zugelassen",
    "Anonymous requests allowed on the API server",
    "--anonymous-auth=false setzen; Health-Probes vorher auf authentifizierte Endpunkte prüfen.",
    "Set --anonymous-auth=false; first confirm health probes do not rely on anonymous access.",
)
def anonymous_auth(ctx: CheckContext) -> list[Hit]:
    i, p, flags = _static_pod(ctx, "kube-apiserver")
    return [] if flags.get("anonymous-auth") == "false" else _api_hit(i, p)


@check(
    "control_plane.audit_logging",
    ("pods",),
    Severity.HIGH,
    "Audit-Logging des API-Servers nicht aktiv",
    "API server audit logging not enabled",
    "--audit-policy-file und --audit-log-path setzen und Logs zentral sammeln.",
    "Set --audit-policy-file and --audit-log-path and ship the logs centrally.",
)
def audit_logging(ctx: CheckContext) -> list[Hit]:
    i, p, flags = _static_pod(ctx, "kube-apiserver")
    enabled = flags.get("audit-policy-file") and flags.get("audit-log-path")
    return [] if enabled else _api_hit(i, p)


@check(
    "control_plane.etcd_listen_non_loopback",
    ("pods",),
    Severity.MEDIUM,
    "etcd-Client-Port auf Nicht-Loopback-Adresse erreichbar",
    "etcd client port listens on a non-loopback address",
    "Erreichbarkeit von Port 2379 per Firewall auf Control-Plane-Knoten beschränken "
    "oder nur 127.0.0.1 binden.",
    "Restrict port 2379 to control plane nodes by firewall, or bind to 127.0.0.1 only.",
)
def etcd_listen_non_loopback(ctx: CheckContext) -> list[Hit]:
    i, p, flags = _static_pod(ctx, "etcd")
    urls = [u for u in (flags.get("listen-client-urls") or "").split(",") if u]
    exposed = [u for u in urls if (urlparse(u).hostname or "") not in LOOPBACK]
    return _api_hit(i, p) if exposed else []


@functools.cache
def _load_support_table() -> dict:
    text = files("k8s_baseline_audit.data").joinpath("k8s-support.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)


def support_table() -> dict:
    return _load_support_table()


@check(
    "version.unsupported",
    ("version",),
    Severity.HIGH,
    "Kubernetes-Version ohne Upstream-Support",
    "Kubernetes version out of upstream support",
    "Auf eine unterstützte Minor-Version aktualisieren (siehe kubernetes.io/releases).",
    "Upgrade to a supported minor version (see kubernetes.io/releases).",
)
def version_unsupported(ctx: CheckContext) -> list[Hit]:
    docs = ctx.items("version")
    server = (docs[0] if docs else {}).get("serverVersion") or {}
    key = f"{server.get('major', '')}.{re.sub(r'[^0-9]', '', server.get('minor', ''))}"
    table = support_table()
    eol = (table.get("releases") or {}).get(key)
    if eol is None:
        raise ManualCheckNeeded(
            f"Kubernetes {key} not in support table (retrieved {table.get('retrieved')})"
        )
    if date.fromisoformat(eol) < ctx.config.as_of:
        return [
            Hit(
                ResourceRef(kind="Cluster", name="cluster"),
                Evidence(file="resources/version.json", json_path="$.serverVersion"),
            )
        ]
    return []

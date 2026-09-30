"""Namespace separation checks: Pod Security Admission and NetworkPolicies."""

from __future__ import annotations

from ...models import ResourceRef, Severity
from .base import CheckContext, Hit, check, ev, meta_ref, spec_of

PSA_ENFORCE = "pod-security.kubernetes.io/enforce"


def _ns(obj: dict) -> str | None:
    return (obj.get("metadata") or {}).get("namespace")


def _is_default_deny_ingress(policy: dict) -> bool:
    spec = spec_of(policy)
    selector = spec.get("podSelector") or {}
    selects_all = not selector.get("matchLabels") and not selector.get("matchExpressions")
    types = spec.get("policyTypes") or ["Ingress"]
    return selects_all and "Ingress" in types and not spec.get("ingress")


@check(
    "isolation.psa_labels_missing",
    ("namespaces",),
    Severity.MEDIUM,
    "Namespace ohne Pod-Security-Admission-Label",
    "Namespace without Pod Security Admission label",
    "Label pod-security.kubernetes.io/enforce (baseline oder restricted) setzen. "
    "Cluster-weite Standardwerte aus einer AdmissionConfiguration sind für dieses "
    "Werkzeug nicht sichtbar.",
    "Set the label pod-security.kubernetes.io/enforce (baseline or restricted). "
    "Cluster-wide defaults from an AdmissionConfiguration are not visible to this "
    "tool.",
)
def psa_labels_missing(ctx: CheckContext) -> list[Hit]:
    system_ns = set(ctx.config.system_namespaces)
    hits = []
    for i, n in enumerate(ctx.items("namespaces")):
        ns_name = (n.get("metadata") or {}).get("name")
        if ns_name in system_ns:
            continue
        labels = (n.get("metadata") or {}).get("labels") or {}
        enforce_value = labels.get(PSA_ENFORCE)
        if enforce_value != "baseline" and enforce_value != "restricted":
            path = f"$.items[{i}].metadata.labels"
            hits.append(Hit(meta_ref("Namespace", n), ev("namespaces", path)))
    return hits


@check(
    "isolation.no_network_policy",
    ("namespaces", "networkpolicies", "pods"),
    Severity.MEDIUM,
    "Namespace mit Pods, aber ohne NetworkPolicy",
    "Namespace with pods but no NetworkPolicy",
    "Default-Deny-NetworkPolicy anlegen und benötigte Verbindungen explizit erlauben.",
    "Create a default-deny NetworkPolicy and explicitly allow required connections.",
)
def no_network_policy(ctx: CheckContext) -> list[Hit]:
    system_ns = set(ctx.config.system_namespaces)
    with_pods = {_ns(p) for p in ctx.items("pods")}
    with_policy = {_ns(p) for p in ctx.items("networkpolicies")}
    hits = []
    for i, n in enumerate(ctx.items("namespaces")):
        name = (n.get("metadata") or {}).get("name")
        if name in system_ns:
            continue
        if name in with_pods and name not in with_policy:
            hits.append(Hit(meta_ref("Namespace", n), ev("namespaces", f"$.items[{i}]")))
    return hits


@check("isolation.no_default_deny", ("networkpolicies",), Severity.LOW,
       "Keine Default-Deny-Regel für eingehenden Verkehr", "No default-deny rule for ingress",
       "NetworkPolicy mit podSelector: {} und policyTypes: [Ingress] ohne Regeln ergänzen.",
       "Add a NetworkPolicy with podSelector: {} and policyTypes: [Ingress] and no rules.")
def no_default_deny(ctx: CheckContext) -> list[Hit]:
    first_index: dict[str, int] = {}
    has_deny: set[str] = set()
    for i, policy in enumerate(ctx.items("networkpolicies")):
        ns = _ns(policy) or ""
        first_index.setdefault(ns, i)
        if _is_default_deny_ingress(policy):
            has_deny.add(ns)
    return [
        Hit(ResourceRef(kind="Namespace", name=ns), ev("networkpolicies", f"$.items[{i}]"))
        for ns, i in sorted(first_index.items())
        if ns not in has_deny
    ]


def _is_allow_all_ingress_rule(rule: dict | None) -> bool:
    """Check if a rule allows all ingress traffic."""
    # Skip non-dict rules (e.g., None)
    if not isinstance(rule, dict):
        return False

    # Rule has no 'from' key or 'from' is empty/None
    from_peers = rule.get("from")
    if not from_peers:
        return True

    # Check each peer in 'from'
    for peer in from_peers:
        peer = peer or {}
        # Check for 0.0.0.0/0 or ::/0 CIDR
        ip_block = peer.get("ipBlock") or {}
        cidr = ip_block.get("cidr")
        if cidr in ("0.0.0.0/0", "::/0"):
            return True

        # Check for EXACTLY {"namespaceSelector": {}} (empty with no other keys)
        if peer == {"namespaceSelector": {}}:
            return True

    return False


@check(
    "isolation.allow_all_policy",
    ("networkpolicies",),
    Severity.HIGH,
    "NetworkPolicy erlaubt jeglichen eingehenden Verkehr",
    "NetworkPolicy allows all ingress",
    "Leere Ingress-Regel ({}) durch konkrete from- und ports-Angaben ersetzen.",
    "Replace the empty ingress rule ({}) with explicit from and ports entries.",
)
def allow_all_policy(ctx: CheckContext) -> list[Hit]:
    hits = []
    for i, policy in enumerate(ctx.items("networkpolicies")):
        for k, rule in enumerate(spec_of(policy).get("ingress") or []):
            if _is_allow_all_ingress_rule(rule):
                path = f"$.items[{i}].spec.ingress[{k}]"
                hits.append(
                    Hit(meta_ref("NetworkPolicy", policy), ev("networkpolicies", path))
                )
    return hits

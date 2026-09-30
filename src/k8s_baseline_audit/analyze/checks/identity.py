"""RBAC and service account checks (APP.4.4 identity and permission management)."""

from __future__ import annotations

from ...models import Severity
from .base import CheckContext, Hit, check, ev, meta_ref, spec_of

ANONYMOUS = frozenset({"User:system:anonymous", "Group:system:unauthenticated"})


def _subject_key(subject: dict) -> str:
    return f"{subject.get('kind')}:{subject.get('name')}"


@check(
    "identity.cluster_admin_binding",
    ("clusterrolebindings",),
    Severity.HIGH,
    "cluster-admin an zusätzliche Subjekte vergeben",
    "cluster-admin granted to additional subjects",
    "cluster-admin-Bindung entfernen und durch eng gefasste Rollen ersetzen.",
    "Remove the cluster-admin binding and replace it with narrowly scoped roles.",
)
def cluster_admin_binding(ctx: CheckContext) -> list[Hit]:
    allow = set(ctx.config.admin_subject_allowlist)
    hits = []
    for i, b in enumerate(ctx.items("clusterrolebindings")):
        if (b.get("roleRef") or {}).get("name") != "cluster-admin":
            continue
        subjects = b.get("subjects") or []
        if subjects and all(_subject_key(s) in allow for s in subjects):
            continue
        hits.append(
            Hit(
                meta_ref("ClusterRoleBinding", b),
                ev("clusterrolebindings", f"$.items[{i}].subjects"),
            )
        )
    return hits


@check(
    "identity.wildcard_role",
    ("roles", "clusterroles"),
    Severity.HIGH,
    "Rolle mit Platzhalter-Rechten (*)",
    "Role with wildcard permissions (*)",
    "Platzhalter in verbs und resources durch konkrete Werte ersetzen.",
    "Replace wildcards in verbs and resources with explicit values.",
)
def wildcard_role(ctx: CheckContext) -> list[Hit]:
    hits = []
    for kind_file, label in (("clusterroles", "ClusterRole"), ("roles", "Role")):
        for i, role in enumerate(ctx.items(kind_file)):
            name = (role.get("metadata") or {}).get("name") or ""
            if label == "ClusterRole" and (name == "cluster-admin" or name.startswith("system:")):
                continue
            for k, rule in enumerate(role.get("rules") or []):
                verbs = rule.get("verbs") or []
                resources = rule.get("resources") or []
                if "*" in verbs or "*" in resources:
                    hits.append(
                        Hit(meta_ref(label, role), ev(kind_file, f"$.items[{i}].rules[{k}]"))
                    )
    return hits


@check(
    "identity.anonymous_binding",
    ("rolebindings", "clusterrolebindings"),
    Severity.CRITICAL,
    "Rechte für anonyme oder nicht authentifizierte Zugriffe",
    "Permissions for anonymous or unauthenticated access",
    "Bindung an system:anonymous bzw. system:unauthenticated entfernen.",
    "Remove the binding to system:anonymous or system:unauthenticated.",
)
def anonymous_binding(ctx: CheckContext) -> list[Hit]:
    allow = set(ctx.config.anonymous_binding_allowlist)
    hits = []
    bindings = (
        ("clusterrolebindings", "ClusterRoleBinding"),
        ("rolebindings", "RoleBinding"),
    )
    for kind_file, label in bindings:
        for i, b in enumerate(ctx.items(kind_file)):
            ref = meta_ref(label, b)
            if ref.key() in allow:
                continue
            if any(_subject_key(s) in ANONYMOUS for s in b.get("subjects") or []):
                hits.append(Hit(ref, ev(kind_file, f"$.items[{i}].subjects")))
    return hits


@check(
    "identity.default_service_account",
    ("pods",),
    Severity.MEDIUM,
    "Pod nutzt das default-ServiceAccount",
    "Pod uses the default service account",
    "Eigenes ServiceAccount je Anwendung anlegen und serviceAccountName setzen.",
    "Create a dedicated service account per application and set serviceAccountName.",
)
def default_service_account(ctx: CheckContext) -> list[Hit]:
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        if spec_of(p).get("serviceAccountName") in (None, "", "default"):
            hits.append(
                Hit(
                    meta_ref("Pod", p),
                    ev("pods", f"$.items[{i}].spec.serviceAccountName"),
                )
            )
    return hits


@check(
    "identity.automount_token",
    ("pods", "serviceaccounts"),
    Severity.MEDIUM,
    "ServiceAccount-Token automatisch eingebunden",
    "Service account token automounted",
    "automountServiceAccountToken: false setzen, wenn der Pod die Kubernetes-API nicht braucht.",
    "Set automountServiceAccountToken: false when the pod does not need the Kubernetes API.",
)
def automount_token(ctx: CheckContext) -> list[Hit]:
    accounts = {
        ((sa.get("metadata") or {}).get("namespace"), (sa.get("metadata") or {}).get("name")): sa
        for sa in ctx.items("serviceaccounts")
    }
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        spec = spec_of(p)
        value = spec.get("automountServiceAccountToken")
        if value is False:
            continue
        if value is None:
            ns = (p.get("metadata") or {}).get("namespace")
            sa = accounts.get((ns, spec.get("serviceAccountName") or "default"))
            if sa is not None and sa.get("automountServiceAccountToken") is False:
                continue
        hits.append(
            Hit(
                meta_ref("Pod", p),
                ev("pods", f"$.items[{i}].spec.automountServiceAccountToken"),
            )
        )
    return hits


@check(
    "identity.long_lived_token_secret",
    ("secrets",),
    Severity.MEDIUM,
    "Langlebiges ServiceAccount-Token als Secret",
    "Long-lived service account token secret",
    "Secret löschen und kurzlebige Tokens über die TokenRequest-API nutzen.",
    "Delete the secret and use short-lived tokens from the TokenRequest API.",
)
def long_lived_token_secret(ctx: CheckContext) -> list[Hit]:
    return [
        Hit(meta_ref("Secret", s), ev("secrets", f"$.items[{i}].type"))
        for i, s in enumerate(ctx.items("secrets"))
        if s.get("type") == "kubernetes.io/service-account-token"
    ]

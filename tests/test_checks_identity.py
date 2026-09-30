from factories import ctx, pod, run_check


def crb(name, role, subjects):
    return {
        "metadata": {"name": name},
        "roleRef": {"kind": "ClusterRole", "name": role},
        "subjects": subjects,
    }


def rb(ns, name, role, subjects):
    return {
        "metadata": {"name": name, "namespace": ns},
        "roleRef": {"kind": "Role", "name": role},
        "subjects": subjects,
    }


def group(n):
    return {"kind": "Group", "name": n}


def user(n):
    return {"kind": "User", "name": n}


def test_kubeadm_defaults_are_not_flagged():
    crbs = [
        crb("cluster-admin", "cluster-admin", [group("system:masters")]),
        crb("kubeadm:cluster-admins", "cluster-admin", [group("kubeadm:cluster-admins")]),
        crb(
            "system:public-info-viewer",
            "system:public-info-viewer",
            [group("system:authenticated"), group("system:unauthenticated")],
        ),
    ]
    rbs = [
        rb(
            "kube-public",
            "kubeadm:bootstrap-signer-clusterinfo",
            "kubeadm:bootstrap-signer-clusterinfo",
            [user("system:anonymous")],
        )
    ]
    c = ctx(clusterrolebindings=crbs, rolebindings=rbs)
    assert run_check("identity.cluster_admin_binding", c) == []
    assert run_check("identity.anonymous_binding", c) == []


def test_cluster_admin_to_person_is_flagged():
    c = ctx(
        clusterrolebindings=[
            crb("ops", "cluster-admin", [user("alice"), group("system:masters")])
        ]
    )
    hits = run_check("identity.cluster_admin_binding", c)
    assert [h.resource.key() for h in hits] == ["ClusterRoleBinding/-/ops"]
    assert hits[0].evidence.json_path == "$.items[0].subjects"


def test_anonymous_bindings_are_flagged():
    c = ctx(
        clusterrolebindings=[crb("anon-view", "view", [user("system:anonymous")])],
        rolebindings=[rb("prod", "open", "reader", [group("system:unauthenticated")])],
    )
    keys = sorted(h.resource.key() for h in run_check("identity.anonymous_binding", c))
    assert keys == ["ClusterRoleBinding/-/anon-view", "RoleBinding/prod/open"]


def test_wildcard_roles():
    roles = [
        {
            "metadata": {"name": "r", "namespace": "prod"},
            "rules": [{"verbs": ["get"], "resources": ["*"]}],
        }
    ]
    clusterroles = [
        {
            "metadata": {
                "name": "cluster-admin",
                "labels": {"kubernetes.io/bootstrapping": "rbac-defaults"},
            },
            "rules": [{"verbs": ["*"], "resources": ["*"]}],
        },
        {
            "metadata": {
                "name": "system:controller:x",
                "labels": {"kubernetes.io/bootstrapping": "rbac-defaults"},
            },
            "rules": [{"verbs": ["*"], "resources": ["*"]}],
        },
        {
            "metadata": {"name": "custom"},
            "rules": [{"verbs": ["get"], "resources": ["pods"]}, {"verbs": ["*"]}],
        },
    ]
    hits = run_check("identity.wildcard_role", ctx(roles=roles, clusterroles=clusterroles))
    assert sorted((h.resource.key(), h.evidence.json_path) for h in hits) == [
        ("ClusterRole/-/custom", "$.items[2].rules[1]"),
        ("Role/prod/r", "$.items[0].rules[0]"),
    ]


def test_default_service_account():
    p1 = pod(serviceAccountName="default")
    p2 = pod(name="db")
    del p2["spec"]["serviceAccountName"]
    hits = run_check("identity.default_service_account", ctx(pods=[p1, p2, pod(name="ok")]))
    assert sorted(h.resource.name for h in hits) == ["db", "web"]


def test_automount_token_resolution():
    sas = [
        {
            "metadata": {"name": "app", "namespace": "default"},
            "automountServiceAccountToken": False,
        },
        {"metadata": {"name": "other", "namespace": "default"}},
    ]
    inherits_off = pod(name="a", automountServiceAccountToken=None)
    inherits_on = pod(name="b", serviceAccountName="other", automountServiceAccountToken=None)
    explicit_on = pod(name="c", automountServiceAccountToken=True)
    hits = run_check(
        "identity.automount_token",
        ctx(pods=[inherits_off, inherits_on, explicit_on], serviceaccounts=sas),
    )
    assert sorted(h.resource.name for h in hits) == ["b", "c"]


def test_long_lived_token_secret():
    secrets = [
        {
            "metadata": {"namespace": "default", "name": "tok"},
            "type": "kubernetes.io/service-account-token",
            "keys": [],
        },
        {
            "metadata": {"namespace": "default", "name": "db"},
            "type": "Opaque",
            "keys": ["password"],
        },
    ]
    hits = run_check("identity.long_lived_token_secret", ctx(secrets=secrets))
    assert [(h.resource.key(), h.evidence.json_path) for h in hits] == [
        ("Secret/default/tok", "$.items[0].type")
    ]


def test_wildcard_role_with_rbac_defaults_label():
    """Roles with rbac-defaults label are exempt from wildcard checks."""
    clusterroles = [
        {
            "metadata": {
                "name": "cluster-admin",
                "labels": {"kubernetes.io/bootstrapping": "rbac-defaults"},
            },
            "rules": [{"verbs": ["*"], "resources": ["*"]}],
        },
        {
            "metadata": {
                "name": "system:controller:x",
                "labels": {"kubernetes.io/bootstrapping": "rbac-defaults"},
            },
            "rules": [{"verbs": ["*"], "resources": ["*"]}],
        },
        {
            "metadata": {"name": "system:evil"},
            "rules": [{"verbs": ["*"], "resources": ["*"]}],
        },
    ]
    hits = run_check("identity.wildcard_role", ctx(clusterroles=clusterroles))
    assert [h.resource.key() for h in hits] == ["ClusterRole/-/system:evil"]


def test_wildcard_role_null_rules():
    """Roles with null rules do not crash."""
    roles = [
        {"metadata": {"name": "broken", "namespace": "default"}, "rules": None}
    ]
    hits = run_check("identity.wildcard_role", ctx(roles=roles))
    assert hits == []


def test_static_pods_not_flagged():
    """Static/mirror pods (with Node owner) are not flagged."""
    static_pod_with_owner = pod(
        name="coredns",
        namespace="kube-system",
        owner={"kind": "Node", "name": "cp"},
    )
    del static_pod_with_owner["spec"]["serviceAccountName"]
    static_pod_without_automount = pod(
        name="etcd",
        namespace="kube-system",
        owner={"kind": "Node", "name": "cp"},
        automountServiceAccountToken=None,
    )

    regular_pod_default_sa = pod(
        name="app",
        namespace="default",
        serviceAccountName="default",
    )
    regular_pod_automount = pod(
        name="app2",
        namespace="default",
        automountServiceAccountToken=True,
    )

    hits_default_sa = run_check(
        "identity.default_service_account",
        ctx(pods=[static_pod_with_owner, regular_pod_default_sa]),
    )
    assert [h.resource.name for h in hits_default_sa] == ["app"]

    hits_automount = run_check(
        "identity.automount_token",
        ctx(pods=[static_pod_without_automount, regular_pod_automount]),
    )
    assert [h.resource.name for h in hits_automount] == ["app2"]


def test_cluster_admin_binding_with_empty_subjects():
    """Cluster-admin binding with empty or missing subjects is not flagged."""
    c = ctx(
        clusterrolebindings=[
            crb("empty", "cluster-admin", []),
            {
                "metadata": {"name": "missing"},
                "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            },
        ]
    )
    hits = run_check("identity.cluster_admin_binding", c)
    assert hits == []

from factories import ctx, pod, run_check


def ns(name, labels=None):
    return {"metadata": {"name": name, "labels": labels or {}}}


def np(ns_, name, spec):
    return {"metadata": {"name": name, "namespace": ns_}, "spec": spec}


DENY = {"podSelector": {}, "policyTypes": ["Ingress"]}


def test_psa_labels():
    namespaces = [ns("a"), ns("b", {"pod-security.kubernetes.io/enforce": "restricted"})]
    hits = run_check("isolation.psa_labels_missing", ctx(namespaces=namespaces))
    assert [(h.resource.key(), h.evidence.json_path) for h in hits] == [
        ("Namespace/-/a", "$.items[0].metadata.labels")
    ]


def test_no_network_policy_only_for_namespaces_with_pods():
    namespaces = [ns("default"), ns("empty"), ns("secured")]
    pods = [pod(namespace="default"), pod(namespace="secured")]
    policies = [np("secured", "deny", DENY)]
    hits = run_check(
        "isolation.no_network_policy",
        ctx(namespaces=namespaces, pods=pods, networkpolicies=policies),
    )
    assert [h.resource.key() for h in hits] == ["Namespace/-/default"]


def test_no_default_deny():
    policies = [
        np(
            "a",
            "allow-web",
            {
                "podSelector": {"matchLabels": {"app": "web"}},
                "ingress": [{"from": [{"podSelector": {}}]}],
            },
        ),
        np("b", "deny", DENY),
        np("c", "deny-implicit", {"podSelector": {}}),
    ]
    hits = run_check("isolation.no_default_deny", ctx(networkpolicies=policies))
    assert [(h.resource.key(), h.evidence.json_path) for h in hits] == [
        ("Namespace/-/a", "$.items[0]")
    ]


def test_allow_all_policy():
    policies = [
        np("a", "open", {"podSelector": {}, "ingress": [{}]}),
        np("b", "deny", DENY),
    ]
    hits = run_check("isolation.allow_all_policy", ctx(networkpolicies=policies))
    assert [(h.resource.key(), h.evidence.json_path) for h in hits] == [
        ("NetworkPolicy/a/open", "$.items[0].spec.ingress[0]")
    ]

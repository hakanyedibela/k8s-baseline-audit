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


def test_allow_all_policy_comprehensive():
    """Test all conditions that trigger the flag."""
    policies = [
        # Flagged: empty rule (no from)
        np("a1", "no-from", {"podSelector": {}, "ingress": [{}]}),
        # Flagged: from is empty list
        np("a2", "empty-from", {"podSelector": {}, "ingress": [{"from": []}]}),
        # Flagged: ports without from
        np(
            "a3",
            "ports-only",
            {"podSelector": {}, "ingress": [{"ports": [{"port": 80}]}]},
        ),
        # Flagged: from contains ipBlock with 0.0.0.0/0
        np(
            "a4",
            "cidr-any",
            {
                "podSelector": {},
                "ingress": [{"from": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}],
            },
        ),
        # Flagged: from contains ipBlock with ::/0
        np(
            "a5",
            "cidr-any-v6",
            {
                "podSelector": {},
                "ingress": [{"from": [{"ipBlock": {"cidr": "::/0"}}]}],
            },
        ),
        # Flagged: from contains bare namespaceSelector (no podSelector)
        np(
            "a6",
            "ns-selector-only",
            {"podSelector": {}, "ingress": [{"from": [{"namespaceSelector": {}}]}]},
        ),
        # Not flagged: from has podSelector
        np(
            "b1",
            "pod-selector",
            {
                "podSelector": {},
                "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "web"}}}]}],
            },
        ),
        # Not flagged: from has restricted CIDR
        np(
            "b2",
            "cidr-restricted",
            {
                "podSelector": {},
                "ingress": [{"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}],
            },
        ),
        # Not flagged: namespaceSelector AND podSelector both present
        np(
            "b3",
            "combined-selectors",
            {
                "podSelector": {},
                "ingress": [
                    {
                        "from": [
                            {
                                "namespaceSelector": {},
                                "podSelector": {"matchLabels": {"a": "b"}},
                            }
                        ]
                    }
                ],
            },
        ),
    ]
    hits = run_check("isolation.allow_all_policy", ctx(networkpolicies=policies))
    hit_keys = sorted([h.evidence.json_path for h in hits])
    expected = sorted([
        "$.items[0].spec.ingress[0]",  # a1
        "$.items[1].spec.ingress[0]",  # a2
        "$.items[2].spec.ingress[0]",  # a3
        "$.items[3].spec.ingress[0]",  # a4
        "$.items[4].spec.ingress[0]",  # a5
        "$.items[5].spec.ingress[0]",  # a6
    ])
    assert hit_keys == expected


def test_psa_labels_privileged():
    """Test that enforce=privileged is flagged."""
    namespaces = [
        ns("a", {"pod-security.kubernetes.io/enforce": "privileged"}),
        ns("b", {"pod-security.kubernetes.io/enforce": "baseline"}),
        ns("c"),
    ]
    hits = run_check("isolation.psa_labels_missing", ctx(namespaces=namespaces))
    keys = sorted([(h.resource.key(), h.evidence.json_path) for h in hits])
    assert keys == [
        ("Namespace/-/a", "$.items[0].metadata.labels"),
        ("Namespace/-/c", "$.items[2].metadata.labels"),
    ]


def test_system_namespaces_excluded():
    """Test that system namespaces are skipped."""
    from factories import config

    namespaces = [
        ns("kube-system"),
        ns("kube-public"),
        ns("kube-node-lease"),
        ns("default"),
        ns("app-ns"),
    ]
    pods = [
        pod(namespace="kube-system"),
        pod(namespace="default"),
        pod(namespace="app-ns"),
    ]
    # With default config (system namespaces excluded)
    hits = run_check(
        "isolation.psa_labels_missing",
        ctx(config(), namespaces=namespaces),
    )
    hit_namespaces = sorted(
        [h.resource.key().split("/")[-1] for h in hits]
    )
    assert hit_namespaces == ["app-ns", "default"]

    # With empty system_namespaces, all are flagged
    hits = run_check(
        "isolation.psa_labels_missing",
        ctx(config(system_namespaces=()), namespaces=namespaces),
    )
    hit_namespaces = sorted(
        [h.resource.key().split("/")[-1] for h in hits]
    )
    assert hit_namespaces == ["app-ns", "default", "kube-node-lease",
                              "kube-public", "kube-system"]

    # Test for no_network_policy as well
    hits = run_check(
        "isolation.no_network_policy",
        ctx(config(), namespaces=namespaces, pods=pods),
    )
    hit_namespaces = sorted(
        [h.resource.key().split("/")[-1] for h in hits]
    )
    assert hit_namespaces == ["app-ns", "default"]

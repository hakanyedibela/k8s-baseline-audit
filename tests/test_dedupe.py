from k8s_baseline_audit.analyze.checks import all_checks
from k8s_baseline_audit.analyze.dedupe import ALIASES, dedupe, pod_owner_map
from k8s_baseline_audit.models import (
    Evidence,
    Finding,
    Localized,
    ResourceRef,
    Severity,
    Source,
    finding_id,
)

L = Localized(de="x", en="x")


def f(check_id, ref, source=Source.BUILTIN, reqs=(), file="resources/pods.json"):
    return Finding(
        id=finding_id(check_id, ref),
        check_id=check_id,
        title=L,
        severity=Severity.HIGH,
        resources=[ref],
        evidence=[Evidence(file=file, json_path="$")],
        sources=[source],
        requirements=list(reqs),
        remediation=L,
    )


PODS = [
    {
        "metadata": {
            "name": "web-7d9c-abcde",
            "namespace": "prod",
            "labels": {"pod-template-hash": "7d9c"},
            "ownerReferences": [{"kind": "ReplicaSet", "name": "web-7d9c"}],
        }
    },
    {
        "metadata": {
            "name": "db-0",
            "namespace": "prod",
            "ownerReferences": [{"kind": "StatefulSet", "name": "db"}],
        }
    },
    {"metadata": {"name": "solo", "namespace": "prod"}},
]


def test_owner_map():
    assert pod_owner_map(PODS) == {
        ("prod", "web-7d9c-abcde"): ("prod", "web"),
        ("prod", "db-0"): ("prod", "db"),
        ("prod", "solo"): ("prod", "solo"),
    }


def test_scanner_finding_merges_into_builtin_via_owner():
    builtin = f(
        "workload.privileged",
        ResourceRef(kind="Pod", namespace="prod", name="web-7d9c-abcde"),
        reqs=["APP.4.4.A9"],
    )
    scan = f(
        "trivy:KSV-0017",
        ResourceRef(kind="Deployment", namespace="prod", name="web"),
        Source.TRIVY,
        reqs=["SYS.1.6.A2"],
        file="scanners/trivy.json",
    )
    out = dedupe([builtin], [scan], PODS)
    assert len(out) == 1
    merged = out[0]
    assert merged.id == builtin.id
    assert merged.sources == [Source.BUILTIN, Source.TRIVY]
    assert [e.file for e in merged.evidence] == ["resources/pods.json", "scanners/trivy.json"]
    assert merged.requirements == ["APP.4.4.A9", "SYS.1.6.A2"]


def test_two_scanners_without_builtin_collapse_into_one():
    ref = ResourceRef(kind="Deployment", namespace="prod", name="api")
    a = f("trivy:KSV-0017", ref, Source.TRIVY, file="scanners/trivy.json")
    b = f("kubescape:C-0057", ref, Source.KUBESCAPE, file="scanners/kubescape.json")
    out = dedupe([], [a, b], PODS)
    assert len(out) == 1
    assert out[0].sources == [Source.KUBESCAPE, Source.TRIVY]


def test_unaliased_findings_are_kept_and_duplicates_collapse():
    ref = ResourceRef(kind="Pod", namespace="prod", name="solo")
    cve1 = f("trivy:CVE-1", ref, Source.TRIVY, file="scanners/trivy.json")
    cve1_again = cve1.model_copy(
        update={"evidence": [Evidence(file="scanners/trivy.json", json_path="$.b")]}
    )
    out = dedupe([], [cve1, cve1_again], PODS)
    assert len(out) == 1
    assert len(out[0].evidence) == 2


def test_inputs_are_not_mutated():
    ref = ResourceRef(kind="Pod", namespace="prod", name="solo")
    builtin = f("workload.privileged", ref)
    scan = f("trivy:KSV-0017", ref, Source.TRIVY)
    dedupe([builtin], [scan], PODS)
    assert builtin.sources == [Source.BUILTIN]
    assert len(builtin.evidence) == 1


def test_aliases_only_reference_registered_builtin_checks():
    assert ALIASES
    assert set(ALIASES.values()) <= set(all_checks_by_id())


def all_checks_by_id():
    return {c.id: c for c in all_checks()}

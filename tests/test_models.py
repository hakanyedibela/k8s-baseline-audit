from k8s_baseline_audit.models import (
    CoverageEntry,
    CoverageStatus,
    Finding,
    Localized,
    ResourceRef,
    Severity,
    Source,
    finding_id,
)


def test_finding_id_is_stable_and_resource_specific():
    web = ResourceRef(kind="Pod", namespace="default", name="web")
    db = ResourceRef(kind="Pod", namespace="default", name="db")
    assert finding_id("workload.privileged", web) == finding_id("workload.privileged", web)
    assert finding_id("workload.privileged", web) != finding_id("workload.privileged", db)
    assert len(finding_id("workload.privileged", web)) == 16


def test_cluster_scoped_ref_key():
    assert ResourceRef(kind="ClusterRole", name="admin").key() == "ClusterRole/-/admin"


def test_severity_order_and_threshold():
    ordered = sorted([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM], key=lambda s: s.rank)
    assert ordered == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]
    assert Severity.CRITICAL.at_or_above(Severity.HIGH)
    assert Severity.HIGH.at_or_above(Severity.HIGH)
    assert not Severity.MEDIUM.at_or_above(Severity.HIGH)


def test_finding_serializes_enums_as_values():
    ref = ResourceRef(kind="Pod", namespace="default", name="web")
    f = Finding(
        id=finding_id("x", ref),
        check_id="x",
        title=Localized(de="T", en="T"),
        severity=Severity.HIGH,
        resources=[ref],
        evidence=[],
        sources=[Source.BUILTIN],
        remediation=Localized(de="R", en="R"),
    )
    dumped = f.model_dump(mode="json")
    assert dumped["severity"] == "high"
    assert dumped["sources"] == ["built-in"]
    assert dumped["requirements"] == []


def test_coverage_entry_defaults():
    e = CoverageEntry(requirement_id="APP.4.4.A1", status=CoverageStatus.ORGANIZATIONAL)
    assert e.model_dump(mode="json") == {
        "requirement_id": "APP.4.4.A1",
        "status": "organizational",
        "finding_ids": [],
        "reasons": [],
    }

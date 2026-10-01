import json
from pathlib import Path

import pytest

from k8s_baseline_audit.analyze.scanners import parse_scanner_file
from k8s_baseline_audit.analyze.scanners.common import ScannerFormatError, map_severity
from k8s_baseline_audit.models import Severity, Source

FIX = Path(__file__).parent / "fixtures" / "scanners"

TRIVY = {
    "ClusterName": "kind",
    "Resources": [
        {
            "Namespace": "audit-demo",
            "Kind": "Pod",
            "Name": "insecure",
            "Results": [
                {
                    "Misconfigurations": [
                        {
                            "ID": "KSV-0017",
                            "Title": "Privileged",
                            "Severity": "HIGH",
                            "Status": "FAIL",
                            "Resolution": "Drop it",
                        },
                        {"ID": "KSV-0099", "Title": "Passed", "Severity": "LOW", "Status": "PASS"},
                    ]
                },
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.1",
                            "FixedVersion": "3.0.2",
                            "Severity": "CRITICAL",
                        },
                        {
                            "VulnerabilityID": "CVE-2024-0002",
                            "PkgName": "zlib",
                            "InstalledVersion": "1",
                            "Severity": "UNKNOWN",
                        },
                    ]
                },
                {
                    "Secrets": [
                        {
                            "RuleID": "aws-access-key-id",
                            "Title": "AWS Access Key",
                            "Severity": "CRITICAL",
                        }
                    ]
                },
            ],
        }
    ],
}

KUBESCAPE = {
    "summaryDetails": {"controls": {"C-0057": {"name": "Privileged container"}}},
    "resources": [
        {
            "resourceID": "/v1/audit-demo/Pod/insecure",
            "object": {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "insecure", "namespace": "audit-demo"},
            },
        },
        {
            "resourceID": "rbac.authorization.k8s.io//User/system:anonymous/x",
            "object": {"apiGroup": "rbac.authorization.k8s.io", "kind": "User", "name": "anon"},
        },
    ],
    "results": [
        {
            "resourceID": "/v1/audit-demo/Pod/insecure",
            "controls": [
                {
                    "controlID": "C-0057",
                    "name": "Privileged container",
                    "severity": "High",
                    "status": {"status": "failed"},
                },
                {
                    "controlID": "C-0001",
                    "name": "Passed control",
                    "severity": "Low",
                    "status": {"status": "passed"},
                },
            ],
        },
        {
            "resourceID": "rbac.authorization.k8s.io//User/system:anonymous/x",
            "controls": [
                {
                    "controlID": "C-0262",
                    "name": "Anonymous access enabled",
                    "status": {"status": "failed"},
                }
            ],
        },
        {
            "resourceID": "apps/v1/prod/Deployment/web",
            "controls": [
                {
                    "controlID": "C-0013",
                    "name": "Non-root containers",
                    "severity": "Medium",
                    "status": {"status": "failed"},
                }
            ],
        },
    ],
}

KUBE_BENCH = {
    "Controls": [
        {
            "id": "4",
            "version": "cis-1.9",
            "node_type": "node",
            "tests": [
                {
                    "section": "4.2",
                    "results": [
                        {
                            "test_number": "4.2.1",
                            "test_desc": "Anonymous auth off",
                            "status": "FAIL",
                            "remediation": "Set it",
                        },
                        {"test_number": "4.2.2", "test_desc": "Authz mode", "status": "PASS"},
                        {"test_number": "4.2.3", "test_desc": "Client CA", "status": "WARN"},
                    ],
                }
            ],
        }
    ]
}


def test_map_severity():
    assert map_severity("HIGH") == (Severity.HIGH, False)
    assert map_severity("Medium") == (Severity.MEDIUM, False)
    assert map_severity("UNKNOWN") == (Severity.LOW, True)
    assert map_severity(None) == (Severity.LOW, True)


def test_trivy():
    fs = parse_scanner_file("scanners/trivy.json", TRIVY)
    by_id = {f.check_id: f for f in fs}
    assert set(by_id) == {
        "trivy:KSV-0017",
        "trivy:CVE-2024-0001",
        "trivy:CVE-2024-0002",
        "trivy:secret:aws-access-key-id",
    }
    mis = by_id["trivy:KSV-0017"]
    assert mis.severity == Severity.HIGH and mis.sources == [Source.TRIVY]
    assert mis.resources[0].key() == "Pod/audit-demo/insecure"
    assert mis.evidence[0].json_path == "$.Resources[0].Results[0].Misconfigurations[0]"
    assert by_id["trivy:CVE-2024-0002"].severity_unmapped
    assert "3.0.2" in by_id["trivy:CVE-2024-0001"].remediation.de


def test_kubescape():
    fs = parse_scanner_file("scanners/kubescape.json", KUBESCAPE)
    assert [(f.check_id, f.severity, f.severity_unmapped, f.resources[0].key()) for f in fs] == [
        ("kubescape:C-0057", Severity.HIGH, False, "Pod/audit-demo/insecure"),
        ("kubescape:C-0262", Severity.LOW, True, "User/-/anon"),
        ("kubescape:C-0013", Severity.MEDIUM, False, "Deployment/prod/web"),
    ]


def test_kube_bench_uses_node_from_filename():
    fs = parse_scanner_file("scanners/kube-bench-worker-1.json", KUBE_BENCH)
    assert [(f.check_id, f.severity, f.resources[0].key()) for f in fs] == [
        ("kube-bench:4.2.1", Severity.MEDIUM, "Node/-/worker-1"),
        ("kube-bench:4.2.3", Severity.LOW, "Node/-/worker-1"),
    ]
    assert all(f.severity_unmapped for f in fs)


@pytest.mark.parametrize(
    "rel,doc",
    [
        ("scanners/trivy.json", {"x": 1}),
        ("scanners/kubescape.json", {"x": 1}),
        ("scanners/kube-bench-a.json", {}),
    ],
)
def test_unknown_format_is_rejected(rel, doc):
    with pytest.raises(ScannerFormatError):
        parse_scanner_file(rel, doc)


@pytest.mark.parametrize(
    "rel,doc",
    [
        ("scanners/kube-bench-a.json", {"Controls": ["x"]}),
        ("scanners/kube-bench-a.json", {"Controls": [{"tests": ["x"]}]}),
        ("scanners/kube-bench-a.json", {"Controls": [{"tests": [{"results": [1]}]}]}),
        ("scanners/kubescape.json", {"results": ["x"]}),
        ("scanners/kubescape.json", {"results": [{"controls": ["x"]}]}),
        ("scanners/kubescape.json", {"results": [], "resources": ["x"]}),
        ("scanners/trivy.json", {"Resources": ["x"]}),
        ("scanners/trivy.json", {"Resources": [{"Results": ["x"]}]}),
        ("scanners/trivy.json", {"Resources": [{"Results": [{"Secrets": ["x"]}]}]}),
        ("scanners/trivy.json", {"Resources": [{"Results": [{"Vulnerabilities": "abc"}]}]}),
    ],
)
def test_non_object_entries_are_rejected(rel, doc):
    with pytest.raises(ScannerFormatError, match="expected a list of objects"):
        parse_scanner_file(rel, doc)


def test_unknown_scanner_file_is_rejected():
    with pytest.raises(ScannerFormatError, match="unknown scanner file"):
        parse_scanner_file("scanners/grype.json", {})


@pytest.mark.parametrize("name", ["trivy.json", "kubescape.json", "kube-bench-node.json"])
def test_captured_fixture_parses(name):
    fs = parse_scanner_file(f"scanners/{name}", json.loads((FIX / name).read_text()))
    assert fs, f"{name}: no findings parsed from a deliberately insecure cluster"
    for f in fs:
        assert f.resources and f.evidence and f.title.en
        assert f.resources[0].name != "?" and f.resources[0].kind != "Unknown"


def test_captured_kubescape_fixture_maps_privileged_pod():
    fs = parse_scanner_file(
        "scanners/kubescape.json", json.loads((FIX / "kubescape.json").read_text())
    )
    hit = [
        f
        for f in fs
        if f.check_id == "kubescape:C-0057" and f.resources[0].namespace == "audit-demo"
    ]
    assert [(f.resources[0].key(), f.severity, f.severity_unmapped) for f in hit] == [
        ("Pod/audit-demo/insecure", Severity.HIGH, False)
    ]


def test_captured_trivy_fixture_maps_privileged_pod():
    fs = parse_scanner_file("scanners/trivy.json", json.loads((FIX / "trivy.json").read_text()))
    hit = [f for f in fs if f.check_id == "trivy:KSV-0017"]
    assert [f.resources[0].key() for f in hit] == ["Pod/audit-demo/insecure"]

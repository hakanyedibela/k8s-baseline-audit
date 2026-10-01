import json
from pathlib import Path

import pytest

from k8s_baseline_audit.collect.sanitize import (
    SanitizeShapeError,
    sanitize_kube_bench,
    sanitize_kubescape,
    sanitize_trivy,
)

FIX = Path(__file__).parent / "fixtures" / "scanners"


def test_kubescape_objects_are_reduced_to_identity():
    doc = {
        "resources": [
            {
                "resourceID": "/v1/audit-demo/Pod/insecure",
                "object": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": "insecure",
                        "namespace": "audit-demo",
                        "annotations": {"a": "x"},
                    },
                    "spec": {
                        "containers": [{"env": [{"name": "DB_PASSWORD", "value": "hunter2-demo"}]}]
                    },
                },
            },
            {
                "resourceID": "/audit-demo/Deployment/web",
                "object": {
                    "kind": "Deployment",
                    "name": "web",
                    "namespace": "audit-demo",
                    "relatedObjects": {"spec": {"env": [{"value": "hunter2-demo"}]}},
                },
            },
            {"resourceID": "no-object"},
        ],
        "results": [],
    }
    out = sanitize_kubescape(doc)
    assert out["resources"][0]["object"] == {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "insecure", "namespace": "audit-demo"},
    }
    assert out["resources"][1]["object"] == {
        "kind": "Deployment",
        "name": "web",
        "namespace": "audit-demo",
    }
    assert out["resources"][2] == {"resourceID": "no-object"}
    assert "hunter2-demo" not in json.dumps(out)
    assert "hunter2-demo" in json.dumps(doc)  # input untouched


def test_trivy_snippets_and_secret_matches_are_removed():
    doc = {
        "Resources": [
            {
                "Results": [
                    {
                        "Misconfigurations": [
                            {
                                "ID": "KSV-0017",
                                "CauseMetadata": {"Code": {"Lines": ["hunter2-demo"]}},
                            }
                        ]
                    },
                    {
                        "Secrets": [
                            {
                                "RuleID": "aws-access-key-id",
                                "Match": "AKIA...",
                                "Code": {"Lines": []},
                                "Title": "AWS",
                            }
                        ]
                    },
                ]
            }
        ]
    }
    out = sanitize_trivy(doc)
    assert out["Resources"][0]["Results"][0]["Misconfigurations"][0] == {"ID": "KSV-0017"}
    assert out["Resources"][0]["Results"][1]["Secrets"][0] == {
        "RuleID": "aws-access-key-id",
        "Title": "AWS",
    }
    assert "hunter2-demo" in json.dumps(doc)


def test_trivy_image_metadata_is_reduced_to_identity():
    meta = {
        "RepoTags": ["nginx:latest"],
        "RepoDigests": ["nginx@sha256:aa"],
        "ImageID": "sha256:bb",
        "OS": {"Family": "debian", "Name": "13"},
        "Size": 5,
        "ImageConfig": {
            "config": {"Env": ["API_KEY=leak-123"]},
            "history": [{"created_by": "ENV API_KEY=leak-123"}],
        },
    }
    doc = {"Resources": [{"Metadata": [meta], "Results": [{"Metadata": dict(meta)}]}]}
    out = sanitize_trivy(doc)
    want = {k: meta[k] for k in ("RepoTags", "RepoDigests", "ImageID", "OS")}
    assert out["Resources"][0]["Metadata"] == [want]
    assert out["Resources"][0]["Results"][0]["Metadata"] == want
    assert "leak-123" not in json.dumps(out)
    assert "leak-123" in json.dumps(doc)


def test_kube_bench_value_fields_are_removed():
    doc = {
        "Controls": [
            {
                "tests": [
                    {
                        "results": [
                            {
                                "test_number": "4.2.1",
                                "status": "FAIL",
                                "remediation": "Set it",
                                "actual_value": "token=leak-123",
                                "AuditConfig": "password: leak-123",
                                "AuditEnv": "X=leak-123",
                                "expected_result": "x",
                            }
                        ]
                    }
                ]
            }
        ]
    }
    out = sanitize_kube_bench(doc)
    assert out["Controls"][0]["tests"][0]["results"][0] == {
        "test_number": "4.2.1",
        "status": "FAIL",
        "remediation": "Set it",
    }
    assert "leak-123" in json.dumps(doc)


def test_captured_fixtures_do_not_leak_demo_secret_after_sanitizing():
    ks = sanitize_kubescape(json.loads((FIX / "kubescape.json").read_text()))
    tv = sanitize_trivy(json.loads((FIX / "trivy.json").read_text()))
    kb = sanitize_kube_bench(json.loads((FIX / "kube-bench-node.json").read_text()))
    assert "hunter2-demo" not in json.dumps(ks)
    assert "hunter2-demo" not in json.dumps(tv)
    assert "hunter2-demo" not in json.dumps(kb)


# --- I3: fail closed on unexpected shapes, allowlist free-form records -----------------------


@pytest.mark.parametrize(
    ("fn", "doc"),
    [
        (sanitize_trivy, []),
        (sanitize_trivy, {}),
        (sanitize_trivy, {"Resources": None}),
        (sanitize_trivy, {"Resources": {"a": 1}}),
        (sanitize_kubescape, "text"),
        (sanitize_kubescape, {"resources": []}),
        (sanitize_kubescape, {"results": {}}),
        (sanitize_kubescape, {"results": [], "resources": None}),
        (sanitize_kubescape, {"results": [], "resources": {}}),
        (sanitize_kube_bench, [1]),
        (sanitize_kube_bench, {}),
        (sanitize_kube_bench, {"Controls": None}),
    ],
)
def test_unexpected_top_level_shape_is_rejected(fn, doc):
    with pytest.raises(SanitizeShapeError):
        fn(doc)


def test_trivy_secrets_keep_only_allowlisted_fields():
    secret = {
        "RuleID": "aws-access-key-id",
        "Category": "AWS",
        "Severity": "CRITICAL",
        "Title": "AWS Access Key ID",
        "StartLine": 3,
        "EndLine": 3,
        "Layer": {"Digest": "sha256:aa", "DiffID": "sha256:bb", "CreatedBy": "ENV K=leak-123"},
        "Match": "AKIA leak-123",
        "Code": {"Lines": ["leak-123"]},
        "Offset": 42,
        "Unknown": "leak-123",
    }
    odd = {"RuleID": "x", "Layer": "leak-123"}
    doc = {"Resources": [{"Results": [{"Secrets": [secret, odd]}]}]}
    out = sanitize_trivy(doc)
    first, second = out["Resources"][0]["Results"][0]["Secrets"]
    assert first == {
        "RuleID": "aws-access-key-id",
        "Category": "AWS",
        "Severity": "CRITICAL",
        "Title": "AWS Access Key ID",
        "StartLine": 3,
        "EndLine": 3,
        "Layer": {"Digest": "sha256:aa", "DiffID": "sha256:bb"},
    }
    assert second == {"RuleID": "x"}
    assert "leak-123" not in json.dumps(out)


def test_kube_bench_results_keep_only_allowlisted_fields():
    result = {
        "test_number": "1.1.1",
        "test_desc": "Ensure x",
        "status": "FAIL",
        "scored": True,
        "remediation": "chmod 600",
        "type": "",
        "reason": "token=leak-123",
        "audit": "cat /etc/x leak-123",
        "unknown": "leak-123",
    }
    out = sanitize_kube_bench({"Controls": [{"tests": [{"results": [result]}]}]})
    assert out["Controls"][0]["tests"][0]["results"][0] == {
        "test_number": "1.1.1",
        "test_desc": "Ensure x",
        "status": "FAIL",
        "scored": True,
        "remediation": "chmod 600",
        "type": "",
    }
    assert "leak-123" not in json.dumps(out)


def test_trivy_keeps_only_fields_the_parser_reads():
    doc = {
        "ClusterName": "c",
        "Misconfigurations": [{"CauseMetadata": {"Code": "PASSWORD=LEAK"}}],
        "Resources": [
            {
                "Namespace": "ns",
                "Kind": "Pod",
                "Name": "p",
                "Extra": "LEAK",
                "Metadata": [{"RepoTags": ["a:1"], "ImageConfig": {"config": {"Env": ["K=LEAK"]}}}],
                "Results": [
                    {
                        "Target": "a:1 (debian)",
                        "Class": "os-pkgs",
                        "Type": "debian",
                        "Junk": "LEAK",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-1",
                                "PkgName": "openssl",
                                "InstalledVersion": "3",
                                "FixedVersion": "4",
                                "Severity": "HIGH",
                                "Description": "long text",
                                "References": ["u"],
                                "CVSS": {"nvd": {}},
                                "PkgPath": "/x",
                                "Layer": {"CreatedBy": "LEAK"},
                            }
                        ],
                        "Misconfigurations": [
                            {
                                "ID": "KSV-0017",
                                "AVDID": "AVD-KSV-0017",
                                "Title": "t",
                                "Severity": "HIGH",
                                "Status": "FAIL",
                                "Resolution": "r",
                                "Message": "LEAK",
                                "Description": "d",
                                "References": ["u"],
                                "Query": "q",
                            }
                        ],
                    }
                ],
            }
        ],
    }
    assert sanitize_trivy(doc) == {
        "ClusterName": "c",
        "Resources": [
            {
                "Namespace": "ns",
                "Kind": "Pod",
                "Name": "p",
                "Metadata": [{"RepoTags": ["a:1"]}],
                "Results": [
                    {
                        "Target": "a:1 (debian)",
                        "Class": "os-pkgs",
                        "Type": "debian",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-1",
                                "PkgName": "openssl",
                                "InstalledVersion": "3",
                                "FixedVersion": "4",
                                "Severity": "HIGH",
                            }
                        ],
                        "Misconfigurations": [
                            {
                                "ID": "KSV-0017",
                                "AVDID": "AVD-KSV-0017",
                                "Title": "t",
                                "Severity": "HIGH",
                                "Status": "FAIL",
                                "Resolution": "r",
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_kubescape_keeps_only_fields_the_parser_reads():
    doc = {
        "clusterAPIServerInfo": {"x": "LEAK"},
        "summaryDetails": {
            "frameworks": [{"name": "nsa"}],
            "controls": {
                "C-0057": {
                    "name": "Privileged",
                    "severity": "High",
                    "controlID": "C-0057",
                    "description": "long",
                }
            },
        },
        "resources": [
            {
                "resourceID": "r",
                "source": {"path": "LEAK"},
                "object": {"kind": "Pod", "metadata": {"name": "p"}, "spec": "LEAK"},
            }
        ],
        "results": [
            {
                "resourceID": "r",
                "prioritySummary": {},
                "controls": [
                    {
                        "controlID": "C-0057",
                        "name": "Privileged",
                        "severity": "High",
                        "status": {"status": "failed", "info": "LEAK"},
                        "rules": [{"paths": [{"failedPath": "LEAK"}]}],
                    }
                ],
            }
        ],
    }
    assert sanitize_kubescape(doc) == {
        "summaryDetails": {
            "controls": {
                "C-0057": {"name": "Privileged", "severity": "High", "controlID": "C-0057"}
            }
        },
        "resources": [{"resourceID": "r", "object": {"kind": "Pod", "metadata": {"name": "p"}}}],
        "results": [
            {
                "resourceID": "r",
                "controls": [
                    {
                        "controlID": "C-0057",
                        "name": "Privileged",
                        "severity": "High",
                        "status": {"status": "failed"},
                    }
                ],
            }
        ],
    }


def test_kube_bench_keeps_only_fields_the_parser_reads():
    from k8s_baseline_audit.collect.sanitize import sanitize_kube_bench

    doc = {
        "Totals": {"total_pass": 1},
        "Controls": [
            {
                "id": "4",
                "version": "cis-1.12",
                "text": "Node",
                "node_type": "node",
                "detected_version": "LEAK",
                "total_fail": 1,
                "tests": [
                    {
                        "section": "4.2",
                        "desc": "Kubelet",
                        "fail": 1,
                        "info": "LEAK",
                        "results": [
                            {
                                "test_number": "4.2.1",
                                "test_desc": "d",
                                "status": "FAIL",
                                "actual_value": "LEAK",
                            }
                        ],
                    }
                ],
            }
        ],
    }
    assert sanitize_kube_bench(doc) == {
        "Controls": [
            {
                "id": "4",
                "version": "cis-1.12",
                "text": "Node",
                "node_type": "node",
                "tests": [
                    {
                        "section": "4.2",
                        "desc": "Kubelet",
                        "results": [{"test_number": "4.2.1", "test_desc": "d", "status": "FAIL"}],
                    }
                ],
            }
        ],
    }

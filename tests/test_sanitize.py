import json
from pathlib import Path

from k8s_baseline_audit.collect.sanitize import sanitize_kubescape, sanitize_trivy

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


def test_captured_fixtures_do_not_leak_demo_secret_after_sanitizing():
    ks = sanitize_kubescape(json.loads((FIX / "kubescape.json").read_text()))
    tv = sanitize_trivy(json.loads((FIX / "trivy.json").read_text()))
    assert "hunter2-demo" not in json.dumps(ks)
    assert "hunter2-demo" not in json.dumps(tv)

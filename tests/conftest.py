import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import pytest  # noqa: E402

from k8s_baseline_audit.bundle import dump_json, write_bundle  # noqa: E402
from k8s_baseline_audit.collect.redact import REDACTED  # noqa: E402

SAMPLE_PODS = {
    "items": [
        {
            "metadata": {"name": "insecure", "namespace": "default"},
            "spec": {
                "hostNetwork": True,
                "serviceAccountName": "default",
                "containers": [
                    {
                        "name": "app",
                        "image": "nginx:latest",
                        "securityContext": {"privileged": True, "runAsUser": 0},
                        "env": [{"name": "DB_PASSWORD", "value": REDACTED}],
                    }
                ],
            },
        }
    ]
}


@pytest.fixture
def sample_bundle(tmp_path):
    files = {
        "resources/pods.json": dump_json(SAMPLE_PODS),
        "resources/namespaces.json": dump_json({"items": [{"metadata": {"name": "default"}}]}),
        "resources/serviceaccounts.json": dump_json({"items": []}),
        "resources/roles.json": dump_json({"items": []}),
        "resources/clusterroles.json": dump_json({"items": []}),
        "resources/rolebindings.json": dump_json({"items": []}),
        "resources/clusterrolebindings.json": dump_json({"items": []}),
        "resources/networkpolicies.json": dump_json({"items": []}),
        "resources/nodes.json": dump_json({"items": []}),
        "resources/version.json": dump_json({"serverVersion": {"major": "1", "minor": "35"}}),
        "preflight.json": dump_json({"secrets": False}),
        "errors.json": dump_json(
            {
                "errors": [
                    {
                        "resource": "secrets",
                        "reason": "forbidden: kubectl auth can-i list returned no",
                    }
                ]
            }
        ),
    }
    manifest = {
        "producer": "collector",
        "created_at": "2026-09-30T10:00:00Z",
        "cluster": {"context": "kind-test", "server": "https://127.0.0.1:6443"},
        "tool": {"name": "k8s-baseline-audit", "version": "0.1.0"},
        "commands": [],
        "scanners": {"trivy": {"status": "missing"}},
    }
    return write_bundle(tmp_path / "bundle", files, manifest)

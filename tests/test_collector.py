import json
from datetime import UTC, datetime

from fakes import FakeKubectl

from k8s_baseline_audit.bundle import load_bundle
from k8s_baseline_audit.collect.collector import ALL_KINDS, CollectOptions, collect
from k8s_baseline_audit.collect.redact import LAST_APPLIED
from k8s_baseline_audit.collect.runner import KubectlRunner

SECRET = "s3cr3t-value-123"
NOW = datetime(2026, 9, 30, 10, 0, 0, tzinfo=UTC)


def _pods_json():
    return json.dumps(
        {
            "items": [
                {
                    "metadata": {
                        "name": "web",
                        "namespace": "default",
                        "annotations": {LAST_APPLIED: SECRET},
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "env": [{"name": "DB_PASSWORD", "value": SECRET}],
                            }
                        ]
                    },
                }
            ]
        }
    )


def _collect(tmp_path, fake, **opts):
    runner = KubectlRunner(exec_fn=fake)
    return collect(runner, tmp_path, CollectOptions(tool_version="0.1.0", now=NOW, **opts))


def test_bundle_contains_every_kind_and_manifest(tmp_path):
    secrets_output = "default\tdb\tOpaque\tpassword,\n"
    fake = FakeKubectl(get={"pods": (0, _pods_json()), "secrets": (0, secrets_output)})
    root = _collect(tmp_path, fake)
    assert root.name == "bundle-kind-test-20260930T100000Z"
    b = load_bundle(root)
    assert b.provenance_verified
    for kind in ALL_KINDS:
        assert b.has(f"resources/{kind}.json"), kind
    assert b.has("resources/version.json")
    m = b.manifest
    assert m["producer"] == "collector"
    assert m["created_at"] == "2026-09-30T10:00:00Z"
    assert m["cluster"] == {"context": "kind-test", "server": "https://127.0.0.1:6443"}
    assert m["tool"] == {"name": "k8s-baseline-audit", "version": "0.1.0"}
    assert all(c["argv"][0] == "kubectl" for c in m["commands"])
    assert b.preflight == {k: True for k in ALL_KINDS}
    assert b.read_json("resources/secrets.json")["items"][0]["keys"] == ["password"]


def test_planted_secret_never_reaches_disk(tmp_path):
    fake = FakeKubectl(get={"pods": (0, _pods_json())})
    root = _collect(tmp_path, fake)
    for path in root.rglob("*"):
        if path.is_file():
            assert SECRET not in path.read_text(), path


def test_forbidden_kind_is_recorded_and_skipped(tmp_path):
    fake = FakeKubectl(forbidden={"secrets"})
    b = load_bundle(_collect(tmp_path, fake))
    assert not b.has("resources/secrets.json")
    assert b.preflight["secrets"] is False
    msg = "forbidden: kubectl auth can-i list returned no"
    assert {"resource": "secrets", "reason": msg} in b.errors
    assert ["get", "secrets"] not in [c[:2] for c in fake.calls]


def test_failed_get_is_recorded(tmp_path):
    fake = FakeKubectl(get={"nodes": (1, "")})
    b = load_bundle(_collect(tmp_path, fake))
    assert not b.has("resources/nodes.json")
    assert any(e["resource"] == "nodes" and "InternalError" in e["reason"] for e in b.errors)


def test_invalid_json_is_recorded_not_raised(tmp_path):
    fake = FakeKubectl(get={"pods": (0, "<html>proxy login</html>")})
    b = load_bundle(_collect(tmp_path, fake))
    assert not b.has("resources/pods.json")
    assert {"resource": "pods", "reason": "kubectl returned invalid JSON"} in b.errors


def test_only_read_commands_were_issued(tmp_path):
    fake = FakeKubectl()
    _collect(tmp_path, fake)
    verbs = {c[0] for c in fake.calls}
    assert verbs <= {"get", "version", "auth", "config"}
    assert all(c[1] == "can-i" for c in fake.calls if c[0] == "auth")


def test_extra_files_and_scanner_status_are_included(tmp_path):
    root = _collect(
        tmp_path,
        FakeKubectl(),
        extra_files={"scanners/trivy.json": b'{"Resources": []}\n'},
        scanner_status={"trivy": {"status": "ok", "version": "0.0.0"}},
        extra_commands=[{"argv": ["trivy", "k8s"], "exit_code": 0}],
    )
    b = load_bundle(root)
    assert b.files_under("scanners/") == ["scanners/trivy.json"]
    assert b.manifest["scanners"] == {"trivy": {"status": "ok", "version": "0.0.0"}}
    assert b.manifest["commands"][-1] == {"argv": ["trivy", "k8s"], "exit_code": 0}


def test_redact_pod_list_shape_error_is_recorded(tmp_path):
    """When kubectl returns pod-like response without items list.

    Error is recorded and pods.json not written.
    """
    fake = FakeKubectl(get={"pods": (0, json.dumps({"kind": "Pod", "metadata": {}}))})
    b = load_bundle(_collect(tmp_path, fake))
    assert not b.has("resources/pods.json")
    assert {"resource": "pods", "reason": "unexpected kubectl output shape"} in b.errors

import json
from datetime import UTC, datetime

import pytest
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
    b = load_bundle(root)
    # Verify pods.json exists and contains the pod
    assert b.has("resources/pods.json")
    pods = b.read_json("resources/pods.json")
    assert len(pods["items"]) == 1
    assert pods["items"][0]["metadata"]["name"] == "web"
    # Verify secret never reaches disk anywhere in the bundle
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


def test_stderr_only_in_error_reason_not_stdout(tmp_path):
    """_reason uses stderr only, so planted secret in stdout never reaches errors.json."""
    # FakeKubectl doesn't support custom stderr, so we create a minimal fake
    class FakeWithStderr:
        def __init__(self):
            self.calls = []
            self.context = "kind-test"

        def __call__(self, argv):
            from k8s_baseline_audit.collect.runner import CommandResult
            args = list(argv[1:])
            if args[:1] == ["--context"]:
                args = args[2:]
            self.calls.append(args)

            if args[0] == "config" and args[1] == "current-context":
                return CommandResult(tuple(argv), 0, "kind-test", "")
            if args[0] == "config" and args[1] == "view":
                return CommandResult(tuple(argv), 0, "https://127.0.0.1:6443", "")
            if args[0] == "version":
                return CommandResult(
                    tuple(argv),
                    0,
                    json.dumps({"serverVersion": {"major": "1", "minor": "35"}}),
                    "",
                )
            if args[0] == "auth":
                return CommandResult(tuple(argv), 0, "yes\n", "")
            if args[0] == "get" and args[1] == "pods":
                # Exit code 1, secret in stdout, empty stderr
                # Secret must NOT appear in error reason
                return CommandResult(
                    tuple(argv), 1, f"Error: {SECRET}\n", ""
                )
            if args[0] == "get":
                return CommandResult(tuple(argv), 0, json.dumps({"items": []}), "")
            raise AssertionError(f"unexpected call: {args}")

    fake = FakeWithStderr()
    root = _collect(tmp_path, fake)
    b = load_bundle(root)
    # pods.json should not exist due to exit code 1
    assert not b.has("resources/pods.json")
    # Verify error reason does not contain the secret (uses stderr only)
    pod_errors = [e for e in b.errors if e["resource"] == "pods"]
    assert len(pod_errors) == 1
    assert SECRET not in pod_errors[0]["reason"]


def test_preflight_failed_with_stderr_not_stdout(tmp_path):
    """When can-i exits with non-(0,'yes') outcome, reason is preflight failed + stderr."""
    fake = FakeKubectl(
        can_i_failures={
            "nodes": (1, "", "Unable to connect to the server\n")
        }
    )
    b = load_bundle(_collect(tmp_path, fake))
    assert not b.has("resources/nodes.json")
    assert b.preflight["nodes"] is False
    node_errors = [e for e in b.errors if e["resource"] == "nodes"]
    assert len(node_errors) == 1
    assert node_errors[0]["reason"].startswith("preflight failed:")
    assert "Unable to connect to the server" in node_errors[0]["reason"]


def test_extra_files_must_be_in_scanners_dir(tmp_path):
    """extra_files outside scanners/ raise ValueError before any kubectl call."""
    fake = FakeKubectl()
    runner = KubectlRunner(exec_fn=fake)
    with pytest.raises(ValueError, match="extra file outside scanners/"):
        collect(
            runner,
            tmp_path,
            CollectOptions(
                tool_version="0.1.0",
                now=NOW,
                extra_files={"results/bad.json": b"{}"},
            ),
        )

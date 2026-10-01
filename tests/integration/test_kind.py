import json
import os
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from k8s_baseline_audit import cli

pytestmark = pytest.mark.integration
CONTEXT = os.environ.get("K8S_BASELINE_AUDIT_IT_CONTEXT")

EXPECTED_INSECURE = {
    "identity.automount_token",
    "identity.default_service_account",
    "images.latest_tag",
    "images.no_digest",
    "secrets.credential_literal_env",
    "secrets.env_secret_ref",
    "workload.added_capabilities",
    "workload.host_namespaces",
    "workload.host_path",
    "workload.privilege_escalation",
    "workload.privileged",
    "workload.resource_limits_missing",
    "workload.run_as_non_root_missing",
    "workload.run_as_root",
    "workload.seccomp_missing",
    "workload.writable_root_fs",
}
EXPECTED_HARDENED = {"images.no_digest"}
# Namespace-level findings: the demo namespace has pods, no NetworkPolicy, no PSA label.
EXPECTED_NAMESPACE = {"isolation.no_network_policy", "isolation.psa_labels_missing"}

SNAPSHOT_KINDS = (
    "all,jobs,roles,rolebindings,serviceaccounts,configmaps,secrets,"
    "clusterroles,clusterrolebindings,networkpolicies,namespaces"
)


def _snapshot():
    out = subprocess.run(
        ["kubectl", "--context", CONTEXT, "get", SNAPSHOT_KINDS, "-A", "-o", "name"],
        capture_output=True, text=True, check=True,
    ).stdout
    return sorted(out.splitlines())


@pytest.fixture(scope="module")
def analysis(tmp_path_factory):
    if not CONTEXT:
        pytest.skip("K8S_BASELINE_AUDIT_IT_CONTEXT not set")
    work = tmp_path_factory.mktemp("it")
    before = _snapshot()
    runner = CliRunner()
    collected = runner.invoke(
        cli.app, ["collect", "--context", CONTEXT, "--out", str(work), "--no-scanners"]
    )
    assert collected.exit_code == 0, collected.stderr
    after = _snapshot()
    bundle = Path(collected.stdout.strip().splitlines()[-1])
    analyzed = runner.invoke(cli.app, ["analyze", str(bundle), "--out", str(work / "analysis")])
    assert analyzed.exit_code in (0, 1), analyzed.stderr
    return before, after, bundle, json.loads((work / "analysis" / "findings.json").read_text())


def _checks_for(doc, kind, namespace, name):
    target = (kind, namespace, name)
    return {
        f["check_id"]
        for f in doc["findings"]
        for r in f["resources"]
        if (r["kind"], r.get("namespace"), r["name"]) == target
    }


def test_collection_did_not_change_the_cluster(analysis):
    before, after, _, _ = analysis
    assert before == after


def test_demo_pods_have_exactly_the_expected_findings(analysis):
    _, _, _, doc = analysis
    assert _checks_for(doc, "Pod", "audit-demo", "insecure") == EXPECTED_INSECURE
    assert _checks_for(doc, "Pod", "audit-demo", "hardened") == EXPECTED_HARDENED


def test_cluster_scoped_demo_findings(analysis):
    _, _, _, doc = analysis
    role = _checks_for(doc, "ClusterRole", None, "audit-demo-wildcard")
    assert role == {"identity.wildcard_role"}
    binding = _checks_for(doc, "ClusterRoleBinding", None, "audit-demo-anon")
    assert binding == {"identity.anonymous_binding"}
    assert _checks_for(doc, "Namespace", None, "audit-demo") == EXPECTED_NAMESPACE


def test_demo_secret_not_in_bundle(analysis):
    _, _, bundle, _ = analysis
    for path in bundle.rglob("*"):
        if path.is_file():
            text = path.read_text()
            assert "hunter2-demo" not in text
            assert "demo-only-not-a-real-secret" not in text

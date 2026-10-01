"""collect WITH kubescape and trivy against a kind cluster: still nothing created."""

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from k8s_baseline_audit import cli

from .test_kind import CONTEXT, _snapshot

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not (shutil.which("kubescape") and shutil.which("trivy")),
        reason="kubescape and trivy not on PATH",
    ),
]


@pytest.fixture(scope="module")
def scanned(tmp_path_factory):
    if not CONTEXT:
        pytest.skip("K8S_BASELINE_AUDIT_IT_CONTEXT not set")
    work = tmp_path_factory.mktemp("it-scanners")
    before = _snapshot()
    result = CliRunner().invoke(cli.app, ["collect", "--context", CONTEXT, "--out", str(work)])
    after = _snapshot()
    assert result.exit_code == 0, result.stderr
    bundle = Path(result.stdout.strip().splitlines()[-1])
    return before, after, bundle, work


def test_scanners_left_resource_names_unchanged(scanned):
    """Resource-name snapshot (pods, jobs, daemonsets, namespaces, ...) is identical.

    Catches kubescape host-sensor or trivy node-collector workloads and namespaces that
    still exist after the scan.
    """
    before, after, _, _ = scanned
    assert before == after


def test_both_scanners_ran_with_read_only_flags(scanned):
    _, _, bundle, _ = scanned
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["scanners"]["kubescape"]["status"] == "ok", manifest["scanners"]
    assert manifest["scanners"]["trivy"]["status"] == "ok", manifest["scanners"]
    argvs = {c["argv"][0]: c["argv"] for c in manifest["commands"] if c["argv"][0] != "kubectl"}
    assert {"--keep-local", "--host-scan=false"} <= set(argvs["kubescape"])
    assert {"--disable-node-collector", "--disable-telemetry"} <= set(argvs["trivy"])
    assert (bundle / "scanners" / "kubescape.json").is_file()
    assert (bundle / "scanners" / "trivy.json").is_file()


def test_demo_secret_not_in_scanned_bundle(scanned):
    _, _, _, work = scanned
    for path in work.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert b"hunter2-demo" not in data
            assert b"demo-only-not-a-real-secret" not in data

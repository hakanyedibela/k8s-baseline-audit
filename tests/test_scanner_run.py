import json

from k8s_baseline_audit.collect.scanners import (
    ScannerPlan,
    kubescape_argv,
    run_scanners,
    trivy_argv,
)


class FakeRun:
    def __init__(self, outputs, codes=None):
        self.outputs = outputs  # tool -> dict written to --output
        self.codes = codes or {}
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        tool = argv[0]
        if len(argv) <= 2:  # version call
            return 0, f"{tool} v9.9.9\n", ""
        code = self.codes.get(tool, 0)
        if code == 0 and tool in self.outputs:
            out = argv[argv.index("--output") + 1]
            with open(out, "w") as fh:
                output = self.outputs[tool]
                if isinstance(output, str):
                    fh.write(output)
                else:
                    fh.write(json.dumps(output))
        return code, "", "scanner exploded" if code else ""


def installed(name):
    return f"/usr/local/bin/{name}"


def test_trivy_never_starts_node_collector(tmp_path):
    argv = trivy_argv(tmp_path / "t.json", "kind-x")
    assert "--disable-node-collector" in argv
    assert argv[:2] == ["trivy", "k8s"]
    assert "kind-x" in argv
    assert "--kube-context" in kubescape_argv(tmp_path / "k.json", "kind-x")


def test_outputs_are_sanitized_and_statuses_recorded(tmp_path):
    ks = {
        "resources": [
            {
                "resourceID": "r",
                "object": {
                    "kind": "Pod",
                    "metadata": {"name": "p"},
                    "spec": {"env": "hunter2-demo"},
                },
            }
        ],
        "results": [],
    }
    tv = {"Resources": [{"Results": [{"Secrets": [{"RuleID": "x", "Match": "hunter2-demo"}]}]}]}
    run = FakeRun({"kubescape": ks, "trivy": tv})
    out = run_scanners(ScannerPlan(), "kind-x", tmp_path, which=installed, run=run)
    assert sorted(out.files) == ["scanners/kubescape.json", "scanners/trivy.json"]
    for data in out.files.values():
        assert b"hunter2-demo" not in data
    assert out.status["kubescape"] == {"status": "ok", "version": "kubescape v9.9.9"}
    assert [c["argv"][0] for c in out.commands] == ["kubescape", "trivy"]


def test_missing_disabled_and_failed(tmp_path):
    run = FakeRun({}, codes={"trivy": 1})
    out = run_scanners(
        ScannerPlan(kubescape=False),
        None,
        tmp_path,
        which=lambda n: None if n == "kubescape" else installed(n),
        run=run,
    )
    assert out.status["kubescape"] == {"status": "disabled"}
    assert out.status["trivy"]["status"] == "failed"
    assert "scanner exploded" in out.status["trivy"]["error"]
    assert out.files == {}
    out2 = run_scanners(ScannerPlan(), None, tmp_path, which=lambda n: None, run=run)
    assert out2.status == {"kubescape": {"status": "missing"}, "trivy": {"status": "missing"}}


def test_invalid_json_output_is_a_failure(tmp_path):
    run = FakeRun({"trivy": "not json"})
    out = run_scanners(ScannerPlan(kubescape=False), None, tmp_path, which=installed, run=run)
    assert out.status["trivy"]["status"] == "failed"
    assert "invalid JSON" in out.status["trivy"]["error"]


def test_kube_bench_results_are_imported(tmp_path):
    good = tmp_path / "kb.json"
    good.write_text(json.dumps({"Controls": []}))
    out = run_scanners(
        ScannerPlan(kubescape=False, trivy=False, kube_bench_results=(("cp 1", good),)),
        None, tmp_path, which=installed, run=FakeRun({}),
    )
    assert list(out.files) == ["scanners/kube-bench-cp-1.json"]
    assert out.status["kube-bench"] == {"status": "imported", "nodes": ["cp-1"]}


def test_kube_bench_actual_value_is_sanitized(tmp_path):
    kb_file = tmp_path / "kb.json"
    kb_data = {
        "Controls": [
            {"tests": [{"results": [{"actual_value": "secret123", "status": "PASS"}]}]}
        ]
    }
    kb_file.write_text(json.dumps(kb_data))
    out = run_scanners(
        ScannerPlan(
            kubescape=False,
            trivy=False,
            kube_bench_results=(("node1", kb_file),),
        ),
        None,
        tmp_path,
        which=installed,
        run=FakeRun({}),
    )
    assert b"secret123" not in out.files["scanners/kube-bench-node1.json"]


def test_invalid_kube_bench_json_raises_error(tmp_path):
    bad_kb = tmp_path / "bad_kb.json"
    bad_kb.write_text("not valid json {")
    out = run_scanners(
        ScannerPlan(kubescape=False, trivy=False, kube_bench_results=(("node1", bad_kb),)),
        None, tmp_path, which=installed, run=FakeRun({}),
    )
    assert out.status["kube-bench"]["status"] == "failed"
    assert "not valid JSON" in out.status["kube-bench"]["error"]

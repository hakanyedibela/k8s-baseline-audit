import json

import pytest

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
    assert argv[:3] == ["trivy", "k8s", "-q"]
    assert "--context" not in argv
    assert argv[-1] == "kind-x"
    argv_no_context = trivy_argv(tmp_path / "t.json", None)
    assert argv_no_context[-1] == str(tmp_path / "t.json")
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
    with pytest.raises(ValueError, match="kube-bench result is not valid JSON"):
        run_scanners(
            ScannerPlan(
                kubescape=False,
                trivy=False,
                kube_bench_results=(("node1", bad_kb),),
            ),
            None,
            tmp_path,
            which=installed,
            run=FakeRun({}),
        )


def test_kube_bench_unreadable_file_raises_error(tmp_path):
    missing = tmp_path / "missing_kb.json"
    with pytest.raises(ValueError, match="kube-bench result is not valid JSON"):
        run_scanners(
            ScannerPlan(
                kubescape=False,
                trivy=False,
                kube_bench_results=(("node1", missing),),
            ),
            None,
            tmp_path,
            which=installed,
            run=FakeRun({}),
        )


def test_kube_bench_not_dict_raises_error(tmp_path):
    bad_kb = tmp_path / "list_kb.json"
    bad_kb.write_text(json.dumps([]))
    with pytest.raises(ValueError, match="kube-bench result is not valid JSON"):
        run_scanners(
            ScannerPlan(
                kubescape=False,
                trivy=False,
                kube_bench_results=(("node1", bad_kb),),
            ),
            None,
            tmp_path,
            which=installed,
            run=FakeRun({}),
        )


def test_scanner_version_call_filenotfound_is_failure(tmp_path):
    def fake_run_with_error(argv, timeout):
        if len(argv) <= 2:  # version call
            raise FileNotFoundError(f"cannot find {argv[0]}")
        return 0, "", ""

    out = run_scanners(
        ScannerPlan(trivy=True, kubescape=False),
        None,
        tmp_path,
        which=installed,
        run=fake_run_with_error,
    )
    assert out.status["trivy"]["status"] == "failed"


def test_scanner_timeout_exit_124_is_failure(tmp_path):
    def fake_run_timeout(argv, timeout):
        if len(argv) <= 2:  # version call
            return 0, "trivy v1.0\n", ""
        return 124, "", "timeout after 1800s"

    out = run_scanners(
        ScannerPlan(kubescape=False),
        None,
        tmp_path,
        which=installed,
        run=fake_run_timeout,
    )
    assert out.status["trivy"]["status"] == "failed"
    assert "timeout" in out.status["trivy"]["error"].lower()


def test_scanner_output_as_json_list_is_failure(tmp_path):
    run = FakeRun({"trivy": "[]"})
    out = run_scanners(
        ScannerPlan(kubescape=False),
        None,
        tmp_path,
        which=installed,
        run=run,
    )
    assert out.status["trivy"]["status"] == "failed"
    assert "unexpected shape" in out.status["trivy"]["error"]


def test_stale_file_not_overwritten_when_scanner_fails(tmp_path):
    stale = tmp_path / "trivy.json"
    stale.write_text(json.dumps({"old": "data"}))

    def fake_run_no_write(argv, timeout):
        if len(argv) <= 2:
            return 0, "trivy v1.0\n", ""
        # Scanner runs but doesn't write output
        return 0, "", ""

    out = run_scanners(
        ScannerPlan(kubescape=False),
        None,
        tmp_path,
        which=installed,
        run=fake_run_no_write,
    )
    assert out.status["trivy"]["status"] == "failed"
    assert out.files == {}


# --- I3 / M3 / M4 -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool", "doc"),
    [
        ("trivy", {"ClusterName": "x"}),
        ("trivy", {"Resources": None}),
        ("kubescape", {"resources": []}),
        ("kubescape", {"results": [], "resources": "x"}),
    ],
)
def test_scanner_output_without_expected_lists_is_failure(tmp_path, tool, doc):
    plan = ScannerPlan(kubescape=tool == "kubescape", trivy=tool == "trivy")
    out = run_scanners(plan, None, tmp_path, which=installed, run=FakeRun({tool: doc}))
    assert out.status[tool]["status"] == "failed"
    assert out.status[tool]["error"] == "scanner output has unexpected shape"
    assert out.files == {}


def test_kube_bench_without_controls_list_raises(tmp_path):
    kb = tmp_path / "kb.json"
    kb.write_text(json.dumps({"Totals": {}}))
    with pytest.raises(ValueError, match="kube-bench result has unexpected shape"):
        run_scanners(
            ScannerPlan(kubescape=False, trivy=False, kube_bench_results=(("n", kb),)),
            None, tmp_path, which=installed, run=FakeRun({}),
        )


def test_duplicate_kube_bench_slug_raises(tmp_path):
    kb = tmp_path / "kb.json"
    kb.write_text(json.dumps({"Controls": []}))
    with pytest.raises(ValueError, match="duplicate kube-bench node name: cp-1"):
        run_scanners(
            ScannerPlan(
                kubescape=False, trivy=False, kube_bench_results=(("cp 1", kb), ("cp-1", kb))
            ),
            None, tmp_path, which=installed, run=FakeRun({}),
        )


LEAKY = "error: --password=LEAK1 failed for postgres://u:LEAK2@h/db\n"


@pytest.mark.parametrize("phase", ["version", "scan"])
def test_scanner_stderr_is_redacted(tmp_path, phase):
    def run(argv, timeout):
        if len(argv) <= 2:
            return (1, "", LEAKY) if phase == "version" else (0, "trivy 1\n", "")
        return 1, "", LEAKY

    out = run_scanners(ScannerPlan(kubescape=False), None, tmp_path, which=installed, run=run)
    error = out.status["trivy"]["error"]
    assert "LEAK" not in error
    assert error == "error: --password=<redacted> failed for postgres://u:<redacted>@h/db"


def test_scanner_exception_text_is_redacted(tmp_path):
    def run(argv, timeout):
        raise RuntimeError("token=LEAK3")

    out = run_scanners(ScannerPlan(kubescape=False), None, tmp_path, which=installed, run=run)
    assert out.status["trivy"]["error"] == "token=<redacted>"

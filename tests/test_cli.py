import json
import shutil

import pytest
from fakes import FakeKubectl
from typer.testing import CliRunner

from k8s_baseline_audit import cli
from k8s_baseline_audit.collect.runner import KubectlRunner

runner = CliRunner()


def test_version():
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_analyze_exit_code_follows_threshold(sample_bundle, tmp_path):
    out = tmp_path / "analysis"
    high = runner.invoke(cli.app, ["analyze", str(sample_bundle), "--out", str(out)])
    assert high.exit_code == 1  # sample bundle has a critical finding
    assert (out / "findings.json").is_file() and (out / "coverage.json").is_file()


def test_analyze_bad_bundle_exits_2(tmp_path):
    result = runner.invoke(cli.app, ["analyze", str(tmp_path), "--out", str(tmp_path / "a")])
    assert result.exit_code == 2
    assert "no manifest.json" in result.stderr


def test_analyze_tampered_bundle_exits_2(sample_bundle, tmp_path):
    (sample_bundle / "resources/pods.json").write_text('{"items": []}')
    result = runner.invoke(cli.app, ["analyze", str(sample_bundle), "--out", str(tmp_path / "a")])
    assert result.exit_code == 2
    assert "hash mismatch" in result.stderr


def test_report_requires_both_narratives(sample_bundle, tmp_path):
    runner.invoke(cli.app, ["analyze", str(sample_bundle), "--out", str(tmp_path / "a")])
    n = tmp_path / "n.de.json"
    n.write_text(json.dumps({"language": "de", "summary": "x"}))
    result = runner.invoke(
        cli.app,
        [
            "report",
            str(tmp_path / "a"),
            "--bundle",
            str(sample_bundle),
            "--out",
            str(tmp_path / "r"),
            "--narrative-de",
            str(n),
        ],
    )
    assert result.exit_code == 2


def _analyzed(sample_bundle, tmp_path):
    a = tmp_path / "a"
    runner.invoke(
        cli.app, ["analyze", str(sample_bundle), "--out", str(a), "--fail-on", "critical"]
    )
    return a


def _narratives(tmp_path, de_summary="Zusammenfassung.", en_summary="Summary."):
    de, en = tmp_path / "de.json", tmp_path / "en.json"
    de.write_text(json.dumps({"language": "de", "summary": de_summary}))
    en.write_text(json.dumps({"language": "en", "summary": en_summary}))
    return de, en


def test_full_offline_flow(sample_bundle, tmp_path):
    a = _analyzed(sample_bundle, tmp_path)
    de, en = _narratives(tmp_path)
    result = runner.invoke(
        cli.app,
        [
            "report",
            str(a),
            "--bundle",
            str(sample_bundle),
            "--out",
            str(tmp_path / "r"),
            "--narrative-de",
            str(de),
            "--narrative-en",
            str(en),
        ],
    )
    assert result.exit_code == 0, result.stderr
    assert (tmp_path / "r" / "report.de.md").is_file()
    assert (tmp_path / "r" / "report.en.md").is_file()


def test_report_with_different_bundle_exits_2(sample_bundle, tmp_path):
    a = _analyzed(sample_bundle, tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    shutil.copytree(sample_bundle, other / "b")
    manifest_path = other / "b" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["created_at"] = "2026-10-01T10:00:00Z"
    manifest_path.write_text(json.dumps(manifest))
    result = runner.invoke(
        cli.app, ["report", str(a), "--bundle", str(other / "b"), "--out", str(tmp_path / "r")]
    )
    assert result.exit_code == 2
    assert "different bundle" in result.stderr
    assert "Traceback" not in result.stderr


def test_narrative_with_forbidden_word_exits_2(sample_bundle, tmp_path):
    a = _analyzed(sample_bundle, tmp_path)
    de, en = _narratives(tmp_path, en_summary="The cluster is compliant.")
    result = runner.invoke(
        cli.app,
        [
            "report",
            str(a),
            "--bundle",
            str(sample_bundle),
            "--out",
            str(tmp_path / "r"),
            "--narrative-de",
            str(de),
            "--narrative-en",
            str(en),
        ],
    )
    assert result.exit_code == 2
    assert "forbidden word" in result.stderr


def test_collect_uses_runner_and_skips_scanners(tmp_path, monkeypatch):
    fake = FakeKubectl()
    monkeypatch.setattr(
        cli, "_make_runner", lambda context: KubectlRunner(context=context, exec_fn=fake)
    )
    result = runner.invoke(cli.app, ["collect", "--out", str(tmp_path), "--no-scanners"])
    assert result.exit_code == 0, result.stderr
    bundle_dir = result.stdout.strip().splitlines()[-1]
    manifest = json.loads((tmp_path / bundle_dir.split("/")[-1] / "manifest.json").read_text())
    assert manifest["scanners"] == {
        "kubescape": {"status": "disabled"},
        "trivy": {"status": "disabled"},
    }


def test_collect_with_nothing_readable_exits_2(tmp_path, monkeypatch):
    from k8s_baseline_audit.collect.collector import ALL_KINDS

    fake = FakeKubectl(forbidden=set(ALL_KINDS))
    monkeypatch.setattr(
        cli, "_make_runner", lambda context: KubectlRunner(context=context, exec_fn=fake)
    )
    result = runner.invoke(cli.app, ["collect", "--out", str(tmp_path), "--no-scanners"])
    assert result.exit_code == 2
    assert "no resources collected" in result.stderr


def test_bad_kube_bench_argument_exits_2(tmp_path):
    result = runner.invoke(
        cli.app, ["collect", "--out", str(tmp_path), "--kube-bench-result", "no-equals-sign"]
    )
    assert result.exit_code == 2


def test_invalid_kube_bench_file_exits_2(tmp_path, monkeypatch):
    fake = FakeKubectl()
    monkeypatch.setattr(
        cli, "_make_runner", lambda context: KubectlRunner(context=context, exec_fn=fake)
    )
    bad = tmp_path / "kb.json"
    bad.write_text("not json {")
    result = runner.invoke(
        cli.app,
        [
            "collect",
            "--out",
            str(tmp_path / "o"),
            "--no-scanners",
            "--kube-bench-result",
            f"node1={bad}",
        ],
    )
    assert result.exit_code == 2
    assert "error: kube-bench result is not valid JSON" in result.stderr
    assert "Traceback" not in result.stderr


# --- I1: report verifies the analysis against a fresh run -----------------------------------


def _report(a, bundle, tmp_path):
    return runner.invoke(
        cli.app, ["report", str(a), "--bundle", str(bundle), "--out", str(tmp_path / "r")]
    )


def test_report_accepts_untouched_analysis(sample_bundle, tmp_path):
    a = _analyzed(sample_bundle, tmp_path)
    result = _report(a, sample_bundle, tmp_path)
    assert result.exit_code == 0, result.stderr


def test_report_rejects_downgraded_severity(sample_bundle, tmp_path):
    a = _analyzed(sample_bundle, tmp_path)
    doc = json.loads((a / "findings.json").read_text())
    critical = next(f for f in doc["findings"] if f["severity"] == "critical")
    critical["severity"] = "low"
    (a / "findings.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    result = _report(a, sample_bundle, tmp_path)
    assert result.exit_code == 2
    assert "analysis files do not match a fresh analysis of the bundle" in result.stderr
    assert not (tmp_path / "r").exists()


def test_report_rejects_dropped_coverage_row(sample_bundle, tmp_path):
    a = _analyzed(sample_bundle, tmp_path)
    doc = json.loads((a / "coverage.json").read_text())
    doc["coverage"].pop(0)
    (a / "coverage.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    result = _report(a, sample_bundle, tmp_path)
    assert result.exit_code == 2
    assert "analysis files do not match a fresh analysis of the bundle" in result.stderr


def test_report_honours_recorded_config(sample_bundle, tmp_path):
    a = tmp_path / "a"
    runner.invoke(
        cli.app,
        ["analyze", str(sample_bundle), "--out", str(a), "--registry-allowlist", "docker.io"],
    )
    result = _report(a, sample_bundle, tmp_path)
    assert result.exit_code == 0, result.stderr


# --- I2: unexpected errors exit 2 without a traceback ----------------------------------------


def _bundle_with(tmp_path, rel, doc):
    from k8s_baseline_audit.bundle import dump_json, write_bundle

    files = {
        "resources/version.json": dump_json({"serverVersion": {"major": "1", "minor": "35"}}),
        "preflight.json": dump_json({}),
        "errors.json": dump_json({"errors": []}),
        rel: dump_json(doc),
    }
    manifest = {"producer": "collector", "created_at": "2026-09-30T10:00:00Z", "cluster": {}}
    return write_bundle(tmp_path / "bundle", files, manifest)


def test_analyze_non_object_pod_item_exits_2(tmp_path):
    b = _bundle_with(tmp_path, "resources/pods.json", {"items": ["garbage"]})
    result = runner.invoke(cli.app, ["analyze", str(b), "--out", str(tmp_path / "a")])
    assert result.exit_code == 2
    assert "error: resources/pods.json: items must be objects" in result.stderr
    assert "Traceback" not in result.stderr


def test_analyze_non_object_kube_bench_control_exits_2(tmp_path):
    b = _bundle_with(tmp_path, "scanners/kube-bench-n1.json", {"Controls": ["x"]})
    result = runner.invoke(cli.app, ["analyze", str(b), "--out", str(tmp_path / "a")])
    assert result.exit_code == 2
    assert "error: scanners/kube-bench-n1.json" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize("command", ["collect", "analyze", "report"])
def test_unexpected_exception_is_internal_error(command, sample_bundle, tmp_path, monkeypatch):
    def boom(*_a, **_k):
        raise ZeroDivisionError("kaputt")

    a = _analyzed(sample_bundle, tmp_path)
    if command == "collect":
        monkeypatch.setattr(cli, "collect_bundle", boom)
        args = ["collect", "--out", str(tmp_path / "c"), "--no-scanners"]
    elif command == "analyze":
        monkeypatch.setattr(cli, "run_analysis", boom)
        args = ["analyze", str(sample_bundle), "--out", str(tmp_path / "x")]
    else:
        monkeypatch.setattr(cli, "render_reports", boom)
        args = ["report", str(a), "--bundle", str(sample_bundle), "--out", str(tmp_path / "r")]
    result = runner.invoke(cli.app, args)
    assert result.exit_code == 2
    assert "error: internal error: ZeroDivisionError: kaputt" in result.stderr
    assert "Traceback" not in result.stderr

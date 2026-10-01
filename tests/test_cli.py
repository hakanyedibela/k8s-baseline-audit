import json
import shutil

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

import json
from datetime import date

from k8s_baseline_audit.analyze.checks.base import AnalyzerConfig
from k8s_baseline_audit.analyze.pipeline import analyze, load_resources, write_analysis
from k8s_baseline_audit.bundle import load_bundle
from k8s_baseline_audit.mapping.schema import load_mapping
from k8s_baseline_audit.models import CoverageStatus

CONFIG = AnalyzerConfig(as_of=date(2026, 9, 30))


def _run(bundle_dir):
    return analyze(load_bundle(bundle_dir), load_mapping(), CONFIG, tool_version="0.1.0")


def test_version_resource_is_wrapped_in_a_list(sample_bundle):
    res = load_resources(load_bundle(sample_bundle))
    assert res["version"] == [{"serverVersion": {"major": "1", "minor": "35"}}]
    assert "secrets" not in res


def test_findings_runs_and_meta(sample_bundle):
    result = _run(sample_bundle)
    check_ids = {f.check_id for f in result.findings}
    assert {
        "workload.privileged",
        "workload.run_as_root",
        "secrets.credential_literal_env",
        "identity.default_service_account",
        "images.latest_tag",
    } <= check_ids
    runs = {r.check_id: r for r in result.runs}
    assert runs["identity.long_lived_token_secret"].state == "not_run"
    assert "forbidden" in runs["identity.long_lived_token_secret"].reason
    assert runs["control_plane.encryption_at_rest"].state == "manual"
    assert runs["images.registry_not_allowed"].state == "manual"
    assert result.meta["bundle"]["provenance_verified"] is True
    assert result.meta["mapping"]["name"] == "kompendium-2023"
    assert result.meta["config"]["as_of"] == "2026-09-30"
    assert result.meta["config"]["system_namespaces"] == [
        "kube-system",
        "kube-public",
        "kube-node-lease",
    ]
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks)


def test_every_requirement_has_coverage(sample_bundle):
    result = _run(sample_bundle)
    assert [c.requirement_id for c in result.coverage] == [
        r.id for r in load_mapping().requirements
    ]
    deviation_ids = {
        fid
        for c in result.coverage
        if c.status == CoverageStatus.DEVIATION
        for fid in c.finding_ids
    }
    assert deviation_ids <= {f.id for f in result.findings}


def test_output_is_byte_identical(sample_bundle, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    write_analysis(_run(sample_bundle), a)
    write_analysis(_run(sample_bundle), b)
    for name in ("findings.json", "coverage.json"):
        assert (a / name).read_bytes() == (b / name).read_bytes()
    doc = json.loads((a / "findings.json").read_text())
    assert set(doc) == {"meta", "findings", "check_runs"}


def test_scanner_files_are_parsed_and_merged(sample_bundle, tmp_path):
    from k8s_baseline_audit.bundle import dump_json, write_bundle

    b = load_bundle(sample_bundle)
    files = {rel: b.read_bytes(rel) for rel in b.manifest["files"]}
    files["scanners/trivy.json"] = dump_json(
        {
            "Resources": [
                {
                    "Namespace": "default",
                    "Kind": "Pod",
                    "Name": "insecure",
                    "Results": [
                        {
                            "Misconfigurations": [
                                {
                                    "ID": "KSV-0017",
                                    "Title": "Privileged",
                                    "Severity": "HIGH",
                                    "Status": "FAIL",
                                }
                            ]
                        }
                    ],
                }
            ]
        }
    )
    manifest = {k: v for k, v in b.manifest.items() if k not in ("files", "schema")}
    root = write_bundle(tmp_path / "with-scanner", files, manifest)
    result = _run(root)
    priv = [f for f in result.findings if f.check_id == "workload.privileged"]
    assert len(priv) == 1
    assert [s.value for s in priv[0].sources] == ["built-in", "trivy"]

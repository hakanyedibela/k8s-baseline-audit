import json
from datetime import date

import pytest

from k8s_baseline_audit.analyze.checks.base import AnalyzerConfig
from k8s_baseline_audit.analyze.pipeline import analyze, load_resources, write_analysis
from k8s_baseline_audit.bundle import BundleFormatError, load_bundle
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


def _bundle_with(tmp_path, sample_bundle, overrides):
    from k8s_baseline_audit.bundle import dump_json, write_bundle

    b = load_bundle(sample_bundle)
    files = {rel: b.read_bytes(rel) for rel in b.manifest["files"]}
    for rel, doc in overrides.items():
        if doc is None:
            files.pop(rel, None)
        else:
            files[rel] = dump_json(doc)
    manifest = {k: v for k, v in b.manifest.items() if k not in ("files", "schema")}
    return write_bundle(tmp_path / "variant", files, manifest)


@pytest.mark.parametrize("doc", [{}, {"items": None}, [], {"items": {}}])
def test_malformed_resource_file_raises(sample_bundle, tmp_path, doc):
    root = _bundle_with(tmp_path, sample_bundle, {"resources/pods.json": doc})
    with pytest.raises(BundleFormatError, match="expected a kubectl List"):
        _run(root)


def test_non_object_error_entries_raise(sample_bundle, tmp_path):
    root = _bundle_with(tmp_path, sample_bundle, {"errors.json": {"errors": ["oops"]}})
    with pytest.raises(BundleFormatError, match="entries must be objects"):
        _run(root)


def test_not_run_checks_never_yield_no_deviation(sample_bundle, tmp_path):
    # The sample bundle lacks secrets (forbidden), but the real mapping maps no requirement to that
    # check; also drop network policies and nodes so mapped checks are not run.
    errors = {
        "errors": [
            {"resource": "secrets", "reason": "forbidden: list secrets"},
            {"resource": "networkpolicies", "reason": "forbidden: list networkpolicies"},
            {"resource": "nodes", "reason": "forbidden: list nodes"},
        ]
    }
    root = _bundle_with(
        tmp_path,
        sample_bundle,
        {
            "resources/networkpolicies.json": None,
            "resources/nodes.json": None,
            "errors.json": errors,
        },
    )
    result = _run(root)
    runs = {r.check_id: r for r in result.runs}
    cov = {c.requirement_id: c for c in result.coverage}
    not_run = {cid for cid, r in runs.items() if r.state == "not_run"}
    assert "identity.long_lived_token_secret" in not_run
    checked = 0
    for req in load_mapping().requirements:
        if not set(req.checks) & not_run:
            continue
        entry = cov[req.id]
        if entry.finding_ids:
            assert entry.status == CoverageStatus.DEVIATION
            continue
        checked += 1
        assert entry.status == CoverageStatus.NOT_CHECKED
        assert any("forbidden" in reason for reason in entry.reasons)
    assert checked > 0


def test_non_object_items_are_rejected(tmp_path):
    from k8s_baseline_audit.bundle import dump_json, write_bundle

    root = write_bundle(
        tmp_path / "b", {"resources/pods.json": dump_json({"items": ["garbage"]})}, {}
    )
    with pytest.raises(BundleFormatError, match="items must be objects"):
        load_resources(load_bundle(root))

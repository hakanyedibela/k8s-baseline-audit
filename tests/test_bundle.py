import json

import pytest

from k8s_baseline_audit.bundle import (
    BUNDLE_SCHEMA,
    BundleFormatError,
    BundleIntegrityError,
    load_bundle,
    write_bundle,
)


def _write(tmp_path, files=None):
    files = files or {"resources/pods.json": b'{"items": []}\n', "errors.json": b'{"errors": []}\n'}
    return write_bundle(tmp_path / "b", files, {"producer": "test"})


def test_roundtrip_verifies_hashes(tmp_path):
    b = load_bundle(_write(tmp_path))
    assert b.provenance_verified
    assert b.manifest["schema"] == BUNDLE_SCHEMA
    assert b.read_json("resources/pods.json") == {"items": []}
    assert b.files_under("resources/") == ["resources/pods.json"]
    assert len(b.manifest_sha256()) == 64


def test_tampered_file_is_rejected(tmp_path):
    root = _write(tmp_path)
    (root / "resources/pods.json").write_text('{"items": [1]}')
    with pytest.raises(BundleIntegrityError, match="hash mismatch"):
        load_bundle(root)


def test_missing_listed_file_is_rejected(tmp_path):
    root = _write(tmp_path)
    (root / "resources/pods.json").unlink()
    with pytest.raises(BundleIntegrityError, match="missing"):
        load_bundle(root)


def test_unlisted_file_is_refused_when_hashes_exist(tmp_path):
    root = _write(tmp_path)
    (root / "resources/nodes.json").write_text('{"items": []}')
    b = load_bundle(root)
    assert not b.has("resources/nodes.json")
    with pytest.raises(BundleIntegrityError, match="not listed"):
        b.read_json("resources/nodes.json")


def test_path_traversal_is_rejected(tmp_path):
    root = tmp_path / "evil"
    root.mkdir()
    (root / "manifest.json").write_text(
        json.dumps({"schema": BUNDLE_SCHEMA, "files": {"../../etc/passwd": "0" * 64}})
    )
    with pytest.raises(BundleFormatError, match="unsafe path"):
        load_bundle(root)
    with pytest.raises(BundleFormatError, match="unsafe path"):
        write_bundle(tmp_path / "w", {"/abs.json": b"{}"}, {})


def test_bundle_without_hashes_is_unverified(tmp_path):
    root = tmp_path / "client"
    (root / "resources").mkdir(parents=True)
    (root / "resources/pods.json").write_text('{"items": []}')
    (root / "manifest.json").write_text(json.dumps({"schema": BUNDLE_SCHEMA}))
    b = load_bundle(root)
    assert not b.provenance_verified
    assert b.files_under("resources/") == ["resources/pods.json"]


def test_wrong_schema_and_missing_manifest(tmp_path):
    with pytest.raises(BundleFormatError, match="no manifest.json"):
        load_bundle(tmp_path)
    (tmp_path / "manifest.json").write_text(json.dumps({"schema": "other/v9"}))
    with pytest.raises(BundleFormatError, match="unsupported bundle schema"):
        load_bundle(tmp_path)


def test_invalid_json_file_raises_format_error(tmp_path):
    root = _write(tmp_path, {"resources/pods.json": b"not json"})
    with pytest.raises(BundleFormatError, match="not valid JSON"):
        load_bundle(root).read_json("resources/pods.json")

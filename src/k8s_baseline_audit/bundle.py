"""Evidence bundle: raw collected files plus a manifest with SHA-256 hashes."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

BUNDLE_SCHEMA = "k8s-baseline-audit/bundle/v1"
MANIFEST = "manifest.json"


class BundleFormatError(Exception):
    """The bundle is malformed or unsupported."""


class BundleIntegrityError(Exception):
    """A file does not match the manifest hashes."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dump_json(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def _safe_rel(rel: str) -> str:
    path = PurePosixPath(rel)
    if not rel or rel == MANIFEST or path.is_absolute() or ".." in path.parts or "\\" in rel:
        raise BundleFormatError(f"unsafe path in bundle: {rel!r}")
    return rel


def _check_symlink(root: Path, rel: str) -> None:
    """Reject symlinks in bundle paths."""
    path = root / rel
    if path.is_symlink():
        raise BundleFormatError(f"symlink in bundle: {rel}")
    # Check if any parent path component is a symlink
    for parent in path.parents:
        if parent == root:
            break
        if parent.is_symlink():
            raise BundleFormatError(f"symlink in bundle: {rel}")


def write_bundle(root: Path, files: dict[str, bytes], manifest: dict) -> Path:
    for rel in files:
        _safe_rel(rel)
    root.mkdir(parents=True, exist_ok=False)
    hashes: dict[str, str] = {}
    for rel in sorted(files):
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(files[rel])
        hashes[rel] = sha256_bytes(files[rel])
    full = {**manifest, "schema": BUNDLE_SCHEMA, "files": hashes}
    (root / MANIFEST).write_bytes(dump_json(full))
    return root


@dataclass(frozen=True)
class Bundle:
    root: Path
    manifest: dict
    provenance_verified: bool

    def has(self, rel: str) -> bool:
        _safe_rel(rel)
        if self.provenance_verified:
            return rel in self.manifest["files"]
        return (self.root / rel).is_file()

    def read_bytes(self, rel: str) -> bytes:
        _safe_rel(rel)
        if self.provenance_verified and rel not in self.manifest["files"]:
            raise BundleIntegrityError(f"file not listed in manifest: {rel}")
        _check_symlink(self.root, rel)
        return (self.root / rel).read_bytes()

    def read_json(self, rel: str) -> Any:
        try:
            return json.loads(self.read_bytes(rel))
        except json.JSONDecodeError as exc:
            raise BundleFormatError(f"{rel} is not valid JSON: {exc}") from exc
        except UnicodeDecodeError as exc:
            raise BundleFormatError(f"{rel} is not valid UTF-8: {exc}") from exc

    def _optional(self, rel: str, default: Any) -> Any:
        return self.read_json(rel) if self.has(rel) else default

    @property
    def errors(self) -> list[dict]:
        if not self.has("errors.json"):
            return []
        doc = self.read_json("errors.json")
        if not isinstance(doc, dict):
            raise BundleFormatError("errors.json must be a JSON object")
        if "errors" not in doc:
            raise BundleFormatError("errors.json must contain 'errors' key")
        errors = doc["errors"]
        if not isinstance(errors, list):
            raise BundleFormatError("errors.json 'errors' must be a list")
        return errors

    @property
    def preflight(self) -> dict:
        return self._optional("preflight.json", {})

    def files_under(self, prefix: str) -> list[str]:
        if self.provenance_verified:
            result = []
            for r in self.manifest["files"]:
                if r.startswith(prefix):
                    _safe_rel(r)
                    _check_symlink(self.root, r)
                    result.append(r)
            return sorted(result)
        base = self.root / prefix
        if not base.is_dir():
            return []
        result = []
        for p in base.rglob("*"):
            if p.is_file():
                rel = p.relative_to(self.root).as_posix()
                _check_symlink(self.root, rel)
                result.append(rel)
        return sorted(result)

    def manifest_sha256(self) -> str:
        return sha256_bytes((self.root / MANIFEST).read_bytes())


def load_bundle(root: Path) -> Bundle:
    manifest_path = root / MANIFEST
    if not manifest_path.is_file():
        raise BundleFormatError(f"no {MANIFEST} in {root}")
    try:
        manifest = json.loads(manifest_path.read_bytes())
    except json.JSONDecodeError as exc:
        raise BundleFormatError(f"{MANIFEST} is not valid JSON: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise BundleFormatError(f"{MANIFEST} is not valid UTF-8: {exc}") from exc
    if not isinstance(manifest, dict):
        raise BundleFormatError("manifest.json must be a JSON object")
    if manifest.get("schema") != BUNDLE_SCHEMA:
        raise BundleFormatError(f"unsupported bundle schema: {manifest.get('schema')!r}")
    files = manifest.get("files") or {}
    if files and not isinstance(files, dict):
        raise BundleFormatError("manifest.json 'files' must be a JSON object")
    if not files:
        return Bundle(root, manifest, False)
    # Check for symlinks first, before verifying hashes
    for rel in files:
        _safe_rel(rel)
        _check_symlink(root, rel)
    # Then verify hashes
    for rel, digest in files.items():
        path = root / rel
        if not path.is_file():
            raise BundleIntegrityError(f"listed file missing: {rel}")
        if sha256_bytes(path.read_bytes()) != digest:
            raise BundleIntegrityError(f"hash mismatch: {rel}")
    return Bundle(root, manifest, True)

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
        return (self.root / rel).read_bytes()

    def read_json(self, rel: str) -> Any:
        try:
            return json.loads(self.read_bytes(rel))
        except json.JSONDecodeError as exc:
            raise BundleFormatError(f"{rel} is not valid JSON: {exc}") from exc

    def _optional(self, rel: str, default: Any) -> Any:
        return self.read_json(rel) if self.has(rel) else default

    @property
    def errors(self) -> list[dict]:
        return self._optional("errors.json", {"errors": []}).get("errors", [])

    @property
    def preflight(self) -> dict:
        return self._optional("preflight.json", {})

    def files_under(self, prefix: str) -> list[str]:
        if self.provenance_verified:
            return sorted(r for r in self.manifest["files"] if r.startswith(prefix))
        base = self.root / prefix
        if not base.is_dir():
            return []
        return sorted(p.relative_to(self.root).as_posix() for p in base.rglob("*") if p.is_file())

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
    if manifest.get("schema") != BUNDLE_SCHEMA:
        raise BundleFormatError(f"unsupported bundle schema: {manifest.get('schema')!r}")
    files = manifest.get("files") or {}
    if not files:
        return Bundle(root, manifest, False)
    for rel, digest in files.items():
        _safe_rel(rel)
        path = root / rel
        if not path.is_file():
            raise BundleIntegrityError(f"listed file missing: {rel}")
        if sha256_bytes(path.read_bytes()) != digest:
            raise BundleIntegrityError(f"hash mismatch: {rel}")
    return Bundle(root, manifest, True)

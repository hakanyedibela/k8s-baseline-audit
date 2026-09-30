"""Run optional scanners from the workstation. They only read through the kubeconfig."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..bundle import dump_json
from .sanitize import sanitize_kube_bench, sanitize_kubescape, sanitize_trivy

SCAN_TIMEOUT = 1800
Run = Callable[[list[str], float], tuple[int, str, str]]


def _default_run(argv: list[str], timeout: float) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except OSError as exc:
        return 127, "", f"cannot execute {argv[0]}: {exc}"
    return proc.returncode, proc.stdout, proc.stderr


@dataclass(frozen=True)
class ScannerPlan:
    kubescape: bool = True
    trivy: bool = True
    kube_bench_results: tuple[tuple[str, Path], ...] = ()


@dataclass
class ScannerOutput:
    files: dict[str, bytes] = field(default_factory=dict)
    status: dict[str, dict] = field(default_factory=dict)
    commands: list[dict] = field(default_factory=list)


def kubescape_argv(out: Path, context: str | None) -> list[str]:
    argv = ["kubescape", "scan", "--format", "json", "--output", str(out)]
    return argv + (["--kube-context", context] if context else [])


def trivy_argv(out: Path, context: str | None) -> list[str]:
    argv = [
        "trivy", "k8s", "-q", "--report", "all", "--format", "json",
        "--disable-node-collector", "--output", str(out)
    ]
    return argv + ([context] if context else [])


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-") or "node"


SCANNERS = (
    ("kubescape", kubescape_argv, ["kubescape", "version"], sanitize_kubescape),
    ("trivy", trivy_argv, ["trivy", "--version"], sanitize_trivy),
)


def run_scanners(
    plan: ScannerPlan,
    context: str | None,
    workdir: Path,
    which: Callable[[str], str | None] = shutil.which,
    run: Run = _default_run,
) -> ScannerOutput:
    out = ScannerOutput()
    enabled = {"kubescape": plan.kubescape, "trivy": plan.trivy}
    for name, argv_fn, version_argv, sanitize in SCANNERS:
        if not enabled[name]:
            out.status[name] = {"status": "disabled"}
            continue
        if which(name) is None:
            out.status[name] = {"status": "missing"}
            continue
        try:
            code, version_out, err = run(version_argv, 30)
            if code != 0:
                out.status[name] = {
                    "status": "failed",
                    "error": (err.strip() or f"exit {code}")[-500:],
                }
                continue
        except Exception as exc:
            out.status[name] = {"status": "failed", "error": str(exc)[-500:]}
            continue
        version = (version_out.strip().splitlines() or ["unknown"])[0]
        target = workdir / f"{name}.json"
        target.unlink(missing_ok=True)
        argv = argv_fn(target, context)
        try:
            code, _, err = run(argv, SCAN_TIMEOUT)
        except Exception as exc:
            out.status[name] = {
                "status": "failed",
                "version": version,
                "error": str(exc)[-500:],
            }
            continue
        out.commands.append({"argv": argv, "exit_code": code})
        if code != 0 or not target.is_file():
            error_msg = (err.strip() or f"exit {code}")[-500:]
            out.status[name] = {"status": "failed", "version": version, "error": error_msg}
            continue
        try:
            text = target.read_text()
        except UnicodeDecodeError:
            out.status[name] = {
                "status": "failed",
                "version": version,
                "error": "scanner wrote invalid UTF-8",
            }
            continue
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            error_msg = "scanner wrote invalid JSON"
            out.status[name] = {"status": "failed", "version": version, "error": error_msg}
            continue
        if not isinstance(doc, dict):
            error_msg = "scanner output has unexpected shape"
            out.status[name] = {"status": "failed", "version": version, "error": error_msg}
            continue
        try:
            sanitized = sanitize(doc)
        except Exception:
            error_msg = "scanner output has unexpected shape"
            out.status[name] = {"status": "failed", "version": version, "error": error_msg}
            continue
        out.files[f"scanners/{name}.json"] = dump_json(sanitized)
        out.status[name] = {"status": "ok", "version": version}
    nodes = []
    for node, path in plan.kube_bench_results:
        slug = _slug(node)
        try:
            text = Path(path).read_text()
        except (FileNotFoundError, IsADirectoryError, OSError, UnicodeDecodeError):
            raise ValueError(f"kube-bench result is not valid JSON: {path}") from None
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            raise ValueError(f"kube-bench result is not valid JSON: {path}") from None
        if not isinstance(doc, dict):
            raise ValueError(f"kube-bench result is not valid JSON: {path}")
        try:
            sanitized = sanitize_kube_bench(doc)
        except Exception:
            raise ValueError(f"kube-bench result is not valid JSON: {path}") from None
        out.files[f"scanners/kube-bench-{slug}.json"] = dump_json(sanitized)
        nodes.append(slug)
    if nodes:
        out.status["kube-bench"] = {"status": "imported", "nodes": nodes}
    return out

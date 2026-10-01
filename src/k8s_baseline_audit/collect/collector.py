"""Read-only collection of cluster state into an evidence bundle."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ..bundle import dump_json, write_bundle
from .redact import SECRET_TEMPLATE, parse_secret_rows, redact_pod_list, redact_text
from .runner import CommandResult, KubectlRunner

JSON_KINDS = (
    "namespaces",
    "nodes",
    "pods",
    "serviceaccounts",
    "roles",
    "clusterroles",
    "rolebindings",
    "clusterrolebindings",
    "networkpolicies",
)
ALL_KINDS = JSON_KINDS + ("secrets",)
NAMESPACED = frozenset({
    "pods",
    "serviceaccounts",
    "roles",
    "rolebindings",
    "networkpolicies",
    "secrets",
})


@dataclass(frozen=True)
class CollectOptions:
    tool_version: str
    now: datetime
    extra_files: dict[str, bytes] = field(default_factory=dict)
    scanner_status: dict[str, dict] = field(default_factory=dict)
    extra_commands: list[dict] = field(default_factory=list)


def _scope(kind: str) -> list[str]:
    return ["--all-namespaces"] if kind in NAMESPACED else []


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-") or "cluster"


def _reason(result: CommandResult) -> str:
    detail = redact_text(result.stderr.strip())[-500:]
    if detail:
        return f"kubectl exit {result.exit_code}: {detail}"
    return f"kubectl exit {result.exit_code}"


def collect(runner: KubectlRunner, out_parent: Path, options: CollectOptions) -> Path:
    # Validate extra_files before any kubectl calls
    for rel in options.extra_files:
        if not rel.startswith("scanners/"):
            raise ValueError(f"extra file outside scanners/: {rel}")

    files: dict[str, bytes] = {}
    errors: list[dict] = []
    preflight: dict[str, bool] = {}

    ctx = runner.run("config", "current-context")
    if ctx.exit_code == 0 and ctx.stdout.strip():
        context = ctx.stdout.strip()
    else:
        context = runner.context or "unknown"
    srv = runner.run("config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")
    server = srv.stdout.strip() if srv.exit_code == 0 else ""

    ver = runner.run("version", "-o", "json")
    try:
        files["resources/version.json"] = dump_json(json.loads(ver.stdout))
    except json.JSONDecodeError:
        errors.append({"resource": "version", "reason": _reason(ver)})

    for kind in ALL_KINDS:
        can = runner.run("auth", "can-i", "list", kind, *_scope(kind))
        allowed = can.exit_code == 0 and can.stdout.strip() == "yes"
        preflight[kind] = allowed
        if not allowed:
            if can.exit_code == 1 and can.stdout.strip() == "no":
                msg = "forbidden: kubectl auth can-i list returned no"
            else:
                msg = f"preflight failed: {_reason(can)}"
            errors.append({"resource": kind, "reason": msg})
            continue
        if kind == "secrets":
            res = runner.run("get", kind, *_scope(kind), "-o", f"go-template={SECRET_TEMPLATE}")
            if res.exit_code != 0:
                errors.append({"resource": kind, "reason": _reason(res)})
                continue
            files[f"resources/{kind}.json"] = dump_json(parse_secret_rows(res.stdout))
            continue
        res = runner.run("get", kind, *_scope(kind), "-o", "json")
        if res.exit_code != 0:
            errors.append({"resource": kind, "reason": _reason(res)})
            continue
        try:
            doc = json.loads(res.stdout)
        except json.JSONDecodeError:
            errors.append({"resource": kind, "reason": "kubectl returned invalid JSON"})
            continue
        if kind == "pods":
            try:
                doc = redact_pod_list(doc)
            except ValueError:
                errors.append({"resource": kind, "reason": "unexpected kubectl output shape"})
                continue
        files[f"resources/{kind}.json"] = dump_json(doc)

    files.update(options.extra_files)
    files["preflight.json"] = dump_json(preflight)
    files["errors.json"] = dump_json({"errors": errors})

    now = options.now.astimezone(UTC)
    manifest = {
        "producer": "collector",
        "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cluster": {"context": context, "server": server},
        "tool": {"name": "k8s-baseline-audit", "version": options.tool_version},
        "commands": [{"argv": list(r.argv), "exit_code": r.exit_code} for r in runner.history]
        + list(options.extra_commands),
        "scanners": dict(options.scanner_status),
    }
    name = f"bundle-{_slug(context)}-{now:%Y%m%dT%H%M%SZ}"
    return write_bundle(out_parent / name, files, manifest)

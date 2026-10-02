# k8s-baseline-audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A read-only Kubernetes security audit CLI plus a portable agent skill that maps findings to BSI IT-Grundschutz APP.4.4 and SYS.1.6 and writes German and English reports.

**Architecture:** A collector (read-only kubectl, optional scanners) or a client export script writes a hashed evidence bundle. A deterministic analyzer turns the bundle into `findings.json` and `coverage.json` using built-in checks, scanner parsers, deduplication and a versioned mapping file. A renderer produces `report.de.md` and `report.en.md` from one localized template. The agent skill drives the CLI and contributes only labeled narrative text.

**Tech Stack:** Python 3.11+, pdm, typer, pydantic v2, PyYAML, Jinja2, pytest, ruff; POSIX sh + kubectl + jq for the export script; kind + GitHub Actions for integration tests.

**Spec:** `docs/superpowers/specs/2026-09-30-k8s-baseline-audit-design.md` (read sections 1–15; section 15 amendments override earlier sections).

## Global Constraints

- Python `>=3.11`. Package name `k8s-baseline-audit`, import name `k8s_baseline_audit`, CLI name `k8s-baseline-audit`.
- License Apache-2.0. Every public text: "no certification, no legal advice".
- The words "fulfilled", "erfüllt", "compliant", "konform" never appear in generated output.
- The collector may run only kubectl verbs `get`, `version`, `api-resources`, `auth can-i`, `config current-context`, `config view`. Anything else raises before execution.
- The tool never writes to a cluster in any mode. kube-bench results are imported, never launched.
- Secret values, literal env values, the `kubectl.kubernetes.io/last-applied-configuration` annotation, kubescape `object` bodies, trivy `CauseMetadata`, `Match` and `Code` never reach disk.
- `findings.json` and `coverage.json` are byte-identical for the same bundle: `json.dumps(sort_keys=True, indent=2, ensure_ascii=False)` + trailing newline, explicit sort orders, no wall-clock timestamps.
- Severity values: `critical | high | medium | low`. Recorded severity never changes after analysis.
- Coverage statuses: `no_deviation_found | deviation | partially_checked | manual_check_needed | organizational | not_checked`.
- Exit codes: `0` ok, `1` findings at or above `--fail-on` (default `high`), `2` errors.
- BSI text is paraphrased, never copied. Only requirement IDs, levels and own paraphrases are committed. BSI PDFs are never committed.
- `SKILL.md` frontmatter holds only `name` and `description`; the body names no agent-specific tools.
- Commits go to the feature branch, never to `main` without the user's explicit go. No AI attribution trailers in commits.

## Review Focus

1. **Pods applied with `kubectl apply`** carry the full manifest, including literal env values, in the `last-applied-configuration` annotation. The bundle must not contain it. Test: Task 3 `test_last_applied_annotation_is_stripped`.
2. **Containers with `securityContext: null`, `resources: null` or no `spec` at all** are common in real clusters. No check may crash. Test: Task 6 `test_null_fields_do_not_crash`.
3. **kubectl prints warnings or garbage instead of JSON** (proxy pages, deprecation text on stdout). The collector must record an error for that resource and continue. Test: Task 4 `test_invalid_json_is_recorded_not_raised`.
4. **A tampered or hostile bundle** lists paths like `../../etc/passwd` in its manifest. The loader must refuse. Test: Task 4 `test_path_traversal_is_rejected`.
5. **Every kubeadm cluster has default bindings** for `system:masters`, `kubeadm:cluster-admins`, `system:public-info-viewer` and `kube-public/kubeadm:bootstrap-signer-clusterinfo`. Flagging them makes every report cry wolf. Test: Task 7 `test_kubeadm_defaults_are_not_flagged`.

## File Structure

```
k8s-baseline-audit/
  pyproject.toml  LICENSE  README.md  .gitignore
  .github/workflows/ci.yml
  src/k8s_baseline_audit/
    __init__.py                 # __version__
    models.py                   # Severity, Source, Localized, ResourceRef, Evidence, Finding, CoverageStatus, CoverageEntry, finding_id
    bundle.py                   # write_bundle, load_bundle, Bundle, dump_json, errors
    collect/
      __init__.py
      runner.py                 # KubectlRunner, allowlist, CommandResult
      redact.py                 # pod redaction, secret row parsing, CREDENTIAL_NAME, REDACTED
      sanitize.py               # kubescape/trivy output sanitizers
      collector.py              # collect(), CollectOptions
      scanners.py               # ScannerPlan, run_scanners, ScannerOutput
    analyze/
      __init__.py
      checks/
        __init__.py             # imports check modules, all_checks()
        base.py                 # Check, check decorator, REGISTRY, CheckContext, AnalyzerConfig, Hit, ManualCheckNeeded, helpers
        workload.py  identity.py  isolation.py  secrets_images.py  control_plane.py
      scanners/
        __init__.py             # parse_scanner_file
        common.py               # map_severity, ScannerFormatError
        trivy.py  kubescape.py  kube_bench.py
      dedupe.py                 # ALIASES, dedupe()
      coverage.py               # compute_coverage()
      pipeline.py               # analyze(), write_analysis(), CheckRun, AnalysisResult
    mapping/
      __init__.py
      schema.py                 # Mapping, Requirement, load_mapping, load_mapping_file, requirement_sort_key
    mappings/
      __init__.py
      kompendium-2023.yaml
      sources/kompendium-2023-ids.txt
    data/
      __init__.py
      k8s-support.yaml          # Kubernetes minor -> end of support date
    report/
      __init__.py
      labels.py                 # LABELS[lang]
      render.py                 # Narrative, validate_narratives, load_report_input, render_reports
      templates/report.md.j2
    cli.py                      # typer app: collect, analyze, report
  scripts/
    export-bundle.sh
    install-skill.sh
  skill/k8s-baseline-audit/SKILL.md
  examples/kind-demo/insecure.yaml  examples/kind-demo/report.de.md  examples/kind-demo/report.en.md
  tests/
    conftest.py  factories.py  fakes.py
    fixtures/scanners/ (captured, trimmed)  fixtures/export/ (shim inputs)
    test_*.py  integration/test_kind.py
```

---

### Task 1: Project scaffold and core models

**Files:**
- Create: `pyproject.toml`, `LICENSE`, `.gitignore`, `src/k8s_baseline_audit/__init__.py`, `src/k8s_baseline_audit/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces: `Severity` (str Enum, `.rank`, `.at_or_above(other)`), `Source`, `Localized(de, en)`, `ResourceRef(kind, name, namespace=None)` with `.key()`, `Evidence(file, json_path)`, `Finding`, `CoverageStatus`, `CoverageEntry`, `finding_id(check_id, resource) -> str` (16 hex chars), `__version__ = "0.1.0"`.

- [ ] **Step 1: Create the scaffold**

`pyproject.toml`:

```toml
[build-system]
requires = ["pdm-backend>=2.4,<3"]
build-backend = "pdm.backend"

[project]
name = "k8s-baseline-audit"
version = "0.1.0"
description = "Read-only Kubernetes security audit mapped to BSI IT-Grundschutz APP.4.4 and SYS.1.6"
readme = "README.md"
license = "Apache-2.0"
license-files = ["LICENSE"]
requires-python = ">=3.11"
authors = [{ name = "Hakan Yedibela" }]
keywords = ["kubernetes", "security", "audit", "bsi", "grundschutz", "compliance"]
dependencies = ["typer>=0.15", "click>=8.2", "pydantic>=2.7", "pyyaml>=6.0", "jinja2>=3.1"]

[project.scripts]
k8s-baseline-audit = "k8s_baseline_audit.cli:app"

[dependency-groups]
dev = ["pytest>=8", "ruff>=0.6"]

[tool.pdm.build]
package-dir = "src"
includes = ["src/k8s_baseline_audit"]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = ["integration: needs a kind cluster and kubectl"]
addopts = "-m 'not integration'"

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP"]
```

`.gitignore`:

```
.venv/
__pycache__/
.pytest_cache/
.ruff_cache/
dist/
.pdm-python
.pdm-build/
bsi-sources/
audit/
```

`src/k8s_baseline_audit/__init__.py`:

```python
"""Read-only Kubernetes security audit mapped to BSI IT-Grundschutz."""

__version__ = "0.1.0"
```

Fetch the license text:

```bash
curl -sSfL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE
head -3 LICENSE   # expect "Apache License" / "Version 2.0, January 2004"
```

Create a one-line `README.md` (`# k8s-baseline-audit`) so the build does not fail; Task 19 writes the real one. Then:

```bash
pdm install
```

- [ ] **Step 2: Write the failing test**

`tests/test_models.py`:

```python
from k8s_baseline_audit.models import (
    CoverageEntry,
    CoverageStatus,
    Finding,
    Localized,
    ResourceRef,
    Severity,
    Source,
    finding_id,
)


def test_finding_id_is_stable_and_resource_specific():
    web = ResourceRef(kind="Pod", namespace="default", name="web")
    db = ResourceRef(kind="Pod", namespace="default", name="db")
    assert finding_id("workload.privileged", web) == finding_id("workload.privileged", web)
    assert finding_id("workload.privileged", web) != finding_id("workload.privileged", db)
    assert len(finding_id("workload.privileged", web)) == 16


def test_cluster_scoped_ref_key():
    assert ResourceRef(kind="ClusterRole", name="admin").key() == "ClusterRole/-/admin"


def test_severity_order_and_threshold():
    ordered = sorted([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM], key=lambda s: s.rank)
    assert ordered == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]
    assert Severity.CRITICAL.at_or_above(Severity.HIGH)
    assert Severity.HIGH.at_or_above(Severity.HIGH)
    assert not Severity.MEDIUM.at_or_above(Severity.HIGH)


def test_finding_serializes_enums_as_values():
    ref = ResourceRef(kind="Pod", namespace="default", name="web")
    f = Finding(
        id=finding_id("x", ref),
        check_id="x",
        title=Localized(de="T", en="T"),
        severity=Severity.HIGH,
        resources=[ref],
        evidence=[],
        sources=[Source.BUILTIN],
        remediation=Localized(de="R", en="R"),
    )
    dumped = f.model_dump(mode="json")
    assert dumped["severity"] == "high"
    assert dumped["sources"] == ["built-in"]
    assert dumped["requirements"] == []


def test_coverage_entry_defaults():
    e = CoverageEntry(requirement_id="APP.4.4.A1", status=CoverageStatus.ORGANIZATIONAL)
    assert e.model_dump(mode="json") == {
        "requirement_id": "APP.4.4.A1",
        "status": "organizational",
        "finding_ids": [],
        "reasons": [],
    }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pdm run pytest tests/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'k8s_baseline_audit.models'`

- [ ] **Step 4: Write minimal implementation**

`src/k8s_baseline_audit/models.py`:

```python
"""Core data model shared by collector, analyzer and report."""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return _RANK[self.value]

    def at_or_above(self, other: Severity) -> bool:
        return self.rank <= other.rank


class Source(str, Enum):
    BUILTIN = "built-in"
    KUBESCAPE = "kubescape"
    TRIVY = "trivy"
    KUBE_BENCH = "kube-bench"


class Localized(BaseModel):
    model_config = ConfigDict(frozen=True)
    de: str
    en: str


class ResourceRef(BaseModel):
    model_config = ConfigDict(frozen=True)
    kind: str
    name: str
    namespace: str | None = None

    def key(self) -> str:
        return f"{self.kind}/{self.namespace or '-'}/{self.name}"


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)
    file: str
    json_path: str


class Finding(BaseModel):
    id: str
    check_id: str
    title: Localized
    severity: Severity
    resources: list[ResourceRef]
    evidence: list[Evidence]
    sources: list[Source]
    requirements: list[str] = Field(default_factory=list)
    remediation: Localized
    severity_unmapped: bool = False


class CoverageStatus(str, Enum):
    NO_DEVIATION = "no_deviation_found"
    DEVIATION = "deviation"
    PARTIAL = "partially_checked"
    MANUAL = "manual_check_needed"
    ORGANIZATIONAL = "organizational"
    NOT_CHECKED = "not_checked"


class CoverageEntry(BaseModel):
    requirement_id: str
    status: CoverageStatus
    finding_ids: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


def finding_id(check_id: str, resource: ResourceRef) -> str:
    return hashlib.sha256(f"{check_id}|{resource.key()}".encode()).hexdigest()[:16]
```

- [ ] **Step 5: Run tests and lint**

Run: `pdm run pytest tests/test_models.py -v && pdm run ruff check .`
Expected: 5 passed, ruff `All checks passed!`

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml pdm.lock LICENSE .gitignore README.md src tests
git commit -m "feat: project scaffold and core models"
```

---

### Task 2: kubectl runner with read-only allowlist

**Files:**
- Create: `src/k8s_baseline_audit/collect/__init__.py` (empty), `src/k8s_baseline_audit/collect/runner.py`
- Test: `tests/test_runner.py`

**Interfaces:**
- Produces: `CommandResult(argv: tuple[str, ...], exit_code: int, stdout: str, stderr: str)` (frozen dataclass); `ForbiddenCommandError`; `check_allowed(args: Sequence[str]) -> None`; `KubectlRunner(context: str | None = None, exec_fn: Exec = _subprocess_exec)` with `.run(*args: str) -> CommandResult` and `.history: list[CommandResult]`. `Exec = Callable[[Sequence[str]], CommandResult]`.

- [ ] **Step 1: Write the failing test**

`tests/test_runner.py`:

```python
import subprocess

import pytest

from k8s_baseline_audit.collect import runner as runner_mod
from k8s_baseline_audit.collect.runner import (
    CommandResult,
    ForbiddenCommandError,
    KubectlRunner,
    check_allowed,
)


class Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, argv):
        self.calls.append(list(argv))
        return CommandResult(tuple(argv), 0, "ok", "")


@pytest.mark.parametrize(
    "args",
    [
        ("get", "pods", "-A", "-o", "json"),
        ("version", "-o", "json"),
        ("api-resources",),
        ("auth", "can-i", "list", "pods"),
        ("config", "current-context"),
        ("config", "view", "--minify"),
    ],
)
def test_allowed_commands(args):
    check_allowed(args)


@pytest.mark.parametrize(
    "args",
    [
        (),
        ("apply", "-f", "x.yaml"),
        ("delete", "pod", "x"),
        ("patch", "deploy", "x"),
        ("exec", "pod", "--", "sh"),
        ("create", "job", "x"),
        ("auth", "reconcile", "-f", "x"),
        ("config", "set-context", "x"),
        ("config", "use-context", "x"),
        ("debug", "node/x"),
    ],
)
def test_forbidden_commands_raise(args):
    with pytest.raises(ForbiddenCommandError):
        check_allowed(args)


def test_forbidden_command_never_reaches_exec():
    rec = Recorder()
    r = KubectlRunner(exec_fn=rec)
    with pytest.raises(ForbiddenCommandError):
        r.run("delete", "ns", "prod")
    assert rec.calls == []
    assert r.history == []


def test_context_is_prepended_and_history_recorded():
    rec = Recorder()
    r = KubectlRunner(context="kind-demo", exec_fn=rec)
    result = r.run("get", "pods")
    assert rec.calls == [["kubectl", "--context", "kind-demo", "get", "pods"]]
    assert r.history == [result]


def test_timeout_becomes_exit_124(monkeypatch):
    def boom(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="kubectl", timeout=120)

    monkeypatch.setattr(runner_mod.subprocess, "run", boom)
    result = KubectlRunner().run("get", "pods")
    assert result.exit_code == 124
    assert "timeout" in result.stderr


def test_missing_kubectl_becomes_exit_127(monkeypatch):
    def missing(*a, **kw):
        raise FileNotFoundError("kubectl")

    monkeypatch.setattr(runner_mod.subprocess, "run", missing)
    assert KubectlRunner().run("get", "pods").exit_code == 127
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pdm run pytest tests/test_runner.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'k8s_baseline_audit.collect.runner'`

- [ ] **Step 3: Write minimal implementation**

`src/k8s_baseline_audit/collect/runner.py`:

```python
"""kubectl subprocess runner that refuses every non-read command."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

TIMEOUT_SECONDS = 120

# verb -> allowed first sub-argument (None = any)
_ALLOWED: dict[str, frozenset[str] | None] = {
    "get": None,
    "version": None,
    "api-resources": None,
    "auth": frozenset({"can-i"}),
    "config": frozenset({"current-context", "view"}),
}


class ForbiddenCommandError(Exception):
    """Raised before execution when a kubectl command is not read-only."""


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str


Exec = Callable[[Sequence[str]], CommandResult]


def _subprocess_exec(argv: Sequence[str]) -> CommandResult:
    try:
        proc = subprocess.run(
            list(argv), capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired:
        return CommandResult(tuple(argv), 124, "", f"timeout after {TIMEOUT_SECONDS}s")
    except FileNotFoundError:
        return CommandResult(tuple(argv), 127, "", "kubectl not found on PATH")
    return CommandResult(tuple(argv), proc.returncode, proc.stdout, proc.stderr)


def check_allowed(args: Sequence[str]) -> None:
    if not args:
        raise ForbiddenCommandError("empty kubectl command")
    verb = args[0]
    if verb not in _ALLOWED:
        raise ForbiddenCommandError(f"kubectl verb not allowed: {verb}")
    subs = _ALLOWED[verb]
    if subs is not None and (len(args) < 2 or args[1] not in subs):
        raise ForbiddenCommandError(f"kubectl {verb} subcommand not allowed: {list(args[1:2])}")


@dataclass
class KubectlRunner:
    context: str | None = None
    exec_fn: Exec = _subprocess_exec
    history: list[CommandResult] = field(default_factory=list)

    def run(self, *args: str) -> CommandResult:
        check_allowed(args)
        argv = ["kubectl"]
        if self.context:
            argv += ["--context", self.context]
        argv += list(args)
        result = self.exec_fn(argv)
        self.history.append(result)
        return result
```

- [ ] **Step 4: Run tests**

Run: `pdm run pytest tests/test_runner.py -v`
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add src/k8s_baseline_audit/collect tests/test_runner.py
git commit -m "feat: read-only kubectl runner with verb allowlist"
```

---

### Task 3: Redaction of pods and secret listings

**Files:**
- Create: `src/k8s_baseline_audit/collect/redact.py`
- Test: `tests/test_redact.py`

**Interfaces:**
- Produces: `REDACTED = "<redacted>"`; `CREDENTIAL_NAME: re.Pattern`; `LAST_APPLIED`; `SECRET_TEMPLATE: str` (kubectl go-template); `redact_pod_list(doc: dict) -> dict` (deep copy); `parse_secret_rows(text: str) -> dict` returning `{"items": [{"metadata": {"namespace", "name"}, "type", "keys": [sorted]}]}`.

- [ ] **Step 1: Write the failing test**

`tests/test_redact.py`:

```python
import copy
import json

from k8s_baseline_audit.collect.redact import (
    CREDENTIAL_NAME,
    LAST_APPLIED,
    REDACTED,
    SECRET_TEMPLATE,
    parse_secret_rows,
    redact_pod_list,
)

SECRET = "s3cr3t-value-123"


def _pods():
    return {
        "items": [
            {
                "metadata": {
                    "name": "web",
                    "namespace": "default",
                    "annotations": {LAST_APPLIED: json.dumps({"env": SECRET}), "keep": "me"},
                },
                "spec": {
                    "initContainers": [{"name": "init", "env": [{"name": "A", "value": SECRET}]}],
                    "containers": [
                        {
                            "name": "app",
                            "env": [
                                {"name": "DB_PASSWORD", "value": SECRET},
                                {"name": "EMPTY", "value": ""},
                                {
                                    "name": "FROM_SECRET",
                                    "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}},
                                },
                            ],
                            "args": [f"--db-password={SECRET}", "--port=8080"],
                        }
                    ],
                },
            }
        ]
    }


def test_literal_env_values_are_redacted_everywhere():
    out = json.dumps(redact_pod_list(_pods()))
    assert SECRET not in out
    c = redact_pod_list(_pods())["items"][0]["spec"]["containers"][0]
    assert c["env"][0] == {"name": "DB_PASSWORD", "value": REDACTED}
    assert c["env"][1] == {"name": "EMPTY", "value": ""}
    assert "valueFrom" in c["env"][2]


def test_last_applied_annotation_is_stripped():
    ann = redact_pod_list(_pods())["items"][0]["metadata"]["annotations"]
    assert LAST_APPLIED not in ann
    assert ann["keep"] == "me"


def test_secret_like_args_are_redacted_but_flag_name_kept():
    args = redact_pod_list(_pods())["items"][0]["spec"]["containers"][0]["args"]
    assert args == [f"--db-password={REDACTED}", "--port=8080"]


def test_control_plane_flags_survive():
    doc = {
        "items": [
            {
                "metadata": {"name": "kube-apiserver-cp", "namespace": "kube-system"},
                "spec": {
                    "containers": [
                        {
                            "name": "kube-apiserver",
                            "command": [
                                "kube-apiserver",
                                "--anonymous-auth=false",
                                "--encryption-provider-config=/etc/k/enc.yaml",
                                "--audit-log-path=/var/log/audit.log",
                            ],
                        }
                    ]
                },
            }
        ]
    }
    assert redact_pod_list(doc) == doc


def test_input_is_not_mutated():
    original = _pods()
    snapshot = copy.deepcopy(original)
    redact_pod_list(original)
    assert original == snapshot


def test_missing_fields_are_tolerated():
    assert redact_pod_list({"items": [{"metadata": {"name": "x"}}]}) == {
        "items": [{"metadata": {"name": "x"}}]
    }
    assert redact_pod_list({}) == {}


def test_credential_name_pattern():
    for name in ["DB_PASSWORD", "api_key", "APIKEY", "GITHUB_TOKEN", "client_secret", "PRIVATE_KEY"]:
        assert CREDENTIAL_NAME.search(name), name
    for name in ["PORT", "LOG_LEVEL", "HOSTNAME"]:
        assert not CREDENTIAL_NAME.search(name), name


def test_parse_secret_rows():
    text = "default\tdb\tOpaque\tpassword,user,\nkube-system\ttok\tkubernetes.io/service-account-token\t\n\n"
    assert parse_secret_rows(text) == {
        "items": [
            {"metadata": {"namespace": "default", "name": "db"}, "type": "Opaque", "keys": ["password", "user"]},
            {
                "metadata": {"namespace": "kube-system", "name": "tok"},
                "type": "kubernetes.io/service-account-token",
                "keys": [],
            },
        ]
    }


def test_secret_template_never_prints_values():
    assert "$v}}" not in SECRET_TEMPLATE
    assert "{{$k}}" in SECRET_TEMPLATE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pdm run pytest tests/test_redact.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

`src/k8s_baseline_audit/collect/redact.py`:

```python
"""Redaction rules applied before anything is written to a bundle.

The export script (scripts/export-bundle.sh) implements the same rules in jq.
tests/test_export_script.py enforces parity between the two.
"""

from __future__ import annotations

import copy
import re

REDACTED = "<redacted>"
LAST_APPLIED = "kubectl.kubernetes.io/last-applied-configuration"
CONTAINER_FIELDS = ("initContainers", "containers", "ephemeralContainers")

CREDENTIAL_NAME = re.compile(
    r"PASSWORD|PASSWD|TOKEN|SECRET|API_?KEY|PRIVATE_?KEY|CREDENTIAL", re.IGNORECASE
)
_ARG_SECRET = re.compile(r"((?:password|passwd|token|secret|api[-_]?key)[\w-]*=)\S+", re.IGNORECASE)

# Prints namespace, name, type and data KEYS. Values ($v) are never printed.
SECRET_TEMPLATE = (
    '{{range .items}}{{.metadata.namespace}}{{"\\t"}}{{.metadata.name}}{{"\\t"}}'
    '{{.type}}{{"\\t"}}{{range $k, $v := .data}}{{$k}},{{end}}{{"\\n"}}{{end}}'
)


def _redact_container(container: dict) -> None:
    for env in container.get("env") or []:
        if env.get("value"):
            env["value"] = REDACTED
    for key in ("command", "args"):
        if container.get(key):
            container[key] = [
                _ARG_SECRET.sub(lambda m: m.group(1) + REDACTED, arg) for arg in container[key]
            ]


def redact_pod_list(doc: dict) -> dict:
    out = copy.deepcopy(doc)
    for pod in out.get("items") or []:
        annotations = (pod.get("metadata") or {}).get("annotations")
        if annotations:
            annotations.pop(LAST_APPLIED, None)
        spec = pod.get("spec") or {}
        for field_name in CONTAINER_FIELDS:
            for container in spec.get(field_name) or []:
                _redact_container(container)
    return out


def parse_secret_rows(text: str) -> dict:
    items = []
    for line in text.splitlines():
        if not line.strip():
            continue
        namespace, name, secret_type, keys = (line.split("\t") + ["", "", "", ""])[:4]
        items.append(
            {
                "metadata": {"namespace": namespace, "name": name},
                "type": secret_type,
                "keys": sorted(k for k in keys.split(",") if k),
            }
        )
    return {"items": items}
```

- [ ] **Step 4: Run tests**

Run: `pdm run pytest tests/test_redact.py -v`
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add src/k8s_baseline_audit/collect/redact.py tests/test_redact.py
git commit -m "feat: redaction of env values, secret-like args and last-applied annotation"
```

---
### Task 4: Evidence bundle and read-only collector

**Files:**
- Create: `src/k8s_baseline_audit/bundle.py`, `src/k8s_baseline_audit/collect/collector.py`, `tests/fakes.py`
- Test: `tests/test_bundle.py`, `tests/test_collector.py`

**Interfaces:**
- Consumes: `KubectlRunner`, `CommandResult` (Task 2); `redact_pod_list`, `parse_secret_rows`, `SECRET_TEMPLATE` (Task 3).
- Produces:
  - `bundle.py`: `BUNDLE_SCHEMA = "k8s-baseline-audit/bundle/v1"`, `MANIFEST = "manifest.json"`, `BundleFormatError`, `BundleIntegrityError`, `sha256_bytes(data) -> str`, `dump_json(obj) -> bytes`, `write_bundle(root: Path, files: dict[str, bytes], manifest: dict) -> Path`, `load_bundle(root: Path) -> Bundle`, `Bundle(root, manifest, provenance_verified)` with `.has(rel)`, `.read_bytes(rel)`, `.read_json(rel)`, `.errors -> list[dict]`, `.preflight -> dict`, `.files_under(prefix) -> list[str]`, `.manifest_sha256() -> str`.
  - `collector.py`: `JSON_KINDS`, `NAMESPACED`, `ALL_KINDS`, `CollectOptions(tool_version: str, now: datetime, extra_files: dict[str, bytes] = {}, scanner_status: dict[str, dict] = {}, extra_commands: list[dict] = [])`, `collect(runner: KubectlRunner, out_parent: Path, options: CollectOptions) -> Path`.
  - `tests/fakes.py`: `FakeKubectl` callable usable as `KubectlRunner(exec_fn=FakeKubectl(...))`.

- [ ] **Step 1: Write the test helper**

`tests/fakes.py`:

```python
import json

from k8s_baseline_audit.collect.runner import CommandResult

TEMPLATE_KINDS = {"secrets"}


class FakeKubectl:
    """Answers the collector's kubectl calls from in-memory data."""

    def __init__(self, get=None, forbidden=(), version=None, context="kind-test",
                 server="https://127.0.0.1:6443"):
        self.get = get or {}  # kind -> (exit_code, stdout)
        self.forbidden = set(forbidden)
        self.version = version or {"serverVersion": {"major": "1", "minor": "35"}}
        self.context = context
        self.server = server
        self.calls = []

    def __call__(self, argv):
        args = list(argv[1:])
        if args[:1] == ["--context"]:
            args = args[2:]
        self.calls.append(args)
        verb = args[0]

        def ok(out, code=0, err=""):
            return CommandResult(tuple(argv), code, out, err)

        if verb == "config":
            return ok(self.context if args[1] == "current-context" else self.server)
        if verb == "version":
            return ok(json.dumps(self.version))
        if verb == "auth":
            kind = args[3]
            return ok("no\n", 1) if kind in self.forbidden else ok("yes\n")
        if verb == "get":
            kind = args[1]
            default = (0, "") if kind in TEMPLATE_KINDS else (0, json.dumps({"items": []}))
            code, out = self.get.get(kind, default)
            return ok(out, code, "" if code == 0 else "Error from server (InternalError)")
        raise AssertionError(f"unexpected kubectl call: {args}")
```

- [ ] **Step 2: Write the failing bundle tests**

`tests/test_bundle.py`:

```python
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pdm run pytest tests/test_bundle.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'k8s_baseline_audit.bundle'`

- [ ] **Step 4: Implement the bundle module**

`src/k8s_baseline_audit/bundle.py`:

```python
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
```

- [ ] **Step 5: Run bundle tests**

Run: `pdm run pytest tests/test_bundle.py -v`
Expected: all passed.

- [ ] **Step 6: Write the failing collector tests**

`tests/test_collector.py`:

```python
import json
from datetime import UTC, datetime

from fakes import FakeKubectl

from k8s_baseline_audit.bundle import load_bundle
from k8s_baseline_audit.collect.collector import ALL_KINDS, CollectOptions, collect
from k8s_baseline_audit.collect.redact import LAST_APPLIED
from k8s_baseline_audit.collect.runner import KubectlRunner

SECRET = "s3cr3t-value-123"
NOW = datetime(2026, 9, 30, 10, 0, 0, tzinfo=UTC)


def _pods_json():
    return json.dumps(
        {
            "items": [
                {
                    "metadata": {
                        "name": "web",
                        "namespace": "default",
                        "annotations": {LAST_APPLIED: SECRET},
                    },
                    "spec": {"containers": [{"name": "app", "env": [{"name": "DB_PASSWORD", "value": SECRET}]}]},
                }
            ]
        }
    )


def _collect(tmp_path, fake, **opts):
    runner = KubectlRunner(exec_fn=fake)
    return collect(runner, tmp_path, CollectOptions(tool_version="0.1.0", now=NOW, **opts))


def test_bundle_contains_every_kind_and_manifest(tmp_path):
    fake = FakeKubectl(get={"pods": (0, _pods_json()), "secrets": (0, "default\tdb\tOpaque\tpassword,\n")})
    root = _collect(tmp_path, fake)
    assert root.name == "bundle-kind-test-20260930T100000Z"
    b = load_bundle(root)
    assert b.provenance_verified
    for kind in ALL_KINDS:
        assert b.has(f"resources/{kind}.json"), kind
    assert b.has("resources/version.json")
    m = b.manifest
    assert m["producer"] == "collector"
    assert m["created_at"] == "2026-09-30T10:00:00Z"
    assert m["cluster"] == {"context": "kind-test", "server": "https://127.0.0.1:6443"}
    assert m["tool"] == {"name": "k8s-baseline-audit", "version": "0.1.0"}
    assert all(c["argv"][0] == "kubectl" for c in m["commands"])
    assert b.preflight == {k: True for k in ALL_KINDS}
    assert b.read_json("resources/secrets.json")["items"][0]["keys"] == ["password"]


def test_planted_secret_never_reaches_disk(tmp_path):
    fake = FakeKubectl(get={"pods": (0, _pods_json())})
    root = _collect(tmp_path, fake)
    for path in root.rglob("*"):
        if path.is_file():
            assert SECRET not in path.read_text(), path


def test_forbidden_kind_is_recorded_and_skipped(tmp_path):
    fake = FakeKubectl(forbidden={"secrets"})
    b = load_bundle(_collect(tmp_path, fake))
    assert not b.has("resources/secrets.json")
    assert b.preflight["secrets"] is False
    assert {"resource": "secrets", "reason": "forbidden: kubectl auth can-i list returned no"} in b.errors
    assert ["get", "secrets"] not in [c[:2] for c in fake.calls]


def test_failed_get_is_recorded(tmp_path):
    fake = FakeKubectl(get={"nodes": (1, "")})
    b = load_bundle(_collect(tmp_path, fake))
    assert not b.has("resources/nodes.json")
    assert any(e["resource"] == "nodes" and "InternalError" in e["reason"] for e in b.errors)


def test_invalid_json_is_recorded_not_raised(tmp_path):
    fake = FakeKubectl(get={"pods": (0, "<html>proxy login</html>")})
    b = load_bundle(_collect(tmp_path, fake))
    assert not b.has("resources/pods.json")
    assert {"resource": "pods", "reason": "kubectl returned invalid JSON"} in b.errors


def test_only_read_commands_were_issued(tmp_path):
    fake = FakeKubectl()
    _collect(tmp_path, fake)
    verbs = {c[0] for c in fake.calls}
    assert verbs <= {"get", "version", "auth", "config"}
    assert all(c[1] == "can-i" for c in fake.calls if c[0] == "auth")


def test_extra_files_and_scanner_status_are_included(tmp_path):
    root = _collect(
        tmp_path,
        FakeKubectl(),
        extra_files={"scanners/trivy.json": b'{"Resources": []}\n'},
        scanner_status={"trivy": {"status": "ok", "version": "0.0.0"}},
        extra_commands=[{"argv": ["trivy", "k8s"], "exit_code": 0}],
    )
    b = load_bundle(root)
    assert b.files_under("scanners/") == ["scanners/trivy.json"]
    assert b.manifest["scanners"] == {"trivy": {"status": "ok", "version": "0.0.0"}}
    assert b.manifest["commands"][-1] == {"argv": ["trivy", "k8s"], "exit_code": 0}
```

Add `tests/conftest.py` so tests can import `fakes` and `factories` as top-level modules:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
```

- [ ] **Step 7: Run test to verify it fails**

Run: `pdm run pytest tests/test_collector.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'k8s_baseline_audit.collect.collector'`

- [ ] **Step 8: Implement the collector**

`src/k8s_baseline_audit/collect/collector.py`:

```python
"""Read-only collection of cluster state into an evidence bundle."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from ..bundle import dump_json, write_bundle
from .redact import SECRET_TEMPLATE, parse_secret_rows, redact_pod_list
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
NAMESPACED = frozenset({"pods", "serviceaccounts", "roles", "rolebindings", "networkpolicies", "secrets"})


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
    detail = (result.stderr or result.stdout).strip()[-500:]
    return f"kubectl exit {result.exit_code}: {detail}" if detail else f"kubectl exit {result.exit_code}"


def collect(runner: KubectlRunner, out_parent: Path, options: CollectOptions) -> Path:
    files: dict[str, bytes] = {}
    errors: list[dict] = []
    preflight: dict[str, bool] = {}

    ctx = runner.run("config", "current-context")
    context = ctx.stdout.strip() if ctx.exit_code == 0 and ctx.stdout.strip() else (runner.context or "unknown")
    srv = runner.run("config", "view", "--minify", "-o", "jsonpath={.clusters[0].cluster.server}")
    server = srv.stdout.strip() if srv.exit_code == 0 else ""

    ver = runner.run("version", "-o", "json")
    try:
        files["resources/version.json"] = dump_json(json.loads(ver.stdout))
    except json.JSONDecodeError:
        errors.append({"resource": "version", "reason": _reason(ver)})

    for kind in ALL_KINDS:
        can = runner.run("auth", "can-i", "list", kind, *_scope(kind))
        allowed = can.stdout.strip() == "yes"
        preflight[kind] = allowed
        if not allowed:
            errors.append({"resource": kind, "reason": "forbidden: kubectl auth can-i list returned no"})
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
            doc = redact_pod_list(doc)
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
```

- [ ] **Step 9: Run all tests**

Run: `pdm run pytest -v && pdm run ruff check .`
Expected: all passed, ruff clean.

- [ ] **Step 10: Commit**

```bash
git add src/k8s_baseline_audit/bundle.py src/k8s_baseline_audit/collect/collector.py tests
git commit -m "feat: hashed evidence bundle and read-only collector"
```

---

### Task 5: Mapping schema and loader

**Files:**
- Create: `src/k8s_baseline_audit/mapping/__init__.py` (empty), `src/k8s_baseline_audit/mapping/schema.py`, `src/k8s_baseline_audit/mappings/__init__.py` (empty)
- Test: `tests/test_mapping_schema.py`

**Interfaces:**
- Consumes: `Localized` (Task 1).
- Produces: `CoverageType` (`automatic|partial|manual|organizational`), `Level` (`basic|standard|elevated`), `SourceRef(document, edition, url, page: int | None)`, `Requirement(id, module, level, title, summary, source, coverage_type, checks: list[str], questions: list[Localized])`, `UnmappedCheck(check_id, reason: Localized)`, `Mapping(name, framework, edition, modules, requirements, unmapped_checks)` with `.get(requirement_id) -> Requirement` and `.requirements_for_check(check_id) -> list[str]`; `requirement_sort_key(rid) -> tuple[str, int]`; `load_mapping(name="kompendium-2023") -> Mapping`; `load_mapping_file(path: Path) -> Mapping`.

- [ ] **Step 1: Write the failing test**

`tests/test_mapping_schema.py`:

```python
import pytest
import yaml
from pydantic import ValidationError

from k8s_baseline_audit.mapping.schema import load_mapping_file, requirement_sort_key

SRC = {"document": "APP.4.4 Kubernetes", "edition": "2023", "url": "https://www.bsi.bund.de/x.pdf", "page": 3}


def _req(rid, coverage_type="automatic", checks=("workload.privileged",), questions=()):
    return {
        "id": rid,
        "module": rid.rsplit(".A", 1)[0],
        "level": "basic",
        "title": {"de": "Titel", "en": "Title"},
        "summary": {"de": "Kurz", "en": "Short"},
        "source": SRC,
        "coverage_type": coverage_type,
        "checks": list(checks),
        "questions": [{"de": q, "en": q} for q in questions],
    }


def _write(tmp_path, requirements, unmapped=()):
    doc = {
        "name": "test",
        "framework": "BSI IT-Grundschutz-Kompendium",
        "edition": "2023",
        "modules": ["APP.4.4", "SYS.1.6"],
        "requirements": requirements,
        "unmapped_checks": list(unmapped),
    }
    path = tmp_path / "m.yaml"
    path.write_text(yaml.safe_dump(doc, allow_unicode=True))
    return path


def test_loads_and_indexes(tmp_path):
    m = load_mapping_file(
        _write(
            tmp_path,
            [
                _req("APP.4.4.A10"),
                _req("APP.4.4.A2", checks=("workload.privileged", "workload.host_path")),
                _req("SYS.1.6.A1", "organizational", checks=(), questions=("Gibt es ein Konzept?",)),
            ],
        )
    )
    assert m.get("APP.4.4.A2").checks == ["workload.privileged", "workload.host_path"]
    assert m.requirements_for_check("workload.privileged") == ["APP.4.4.A2", "APP.4.4.A10"]
    assert m.requirements_for_check("nope") == []


def test_sort_key_is_numeric():
    ids = ["APP.4.4.A10", "SYS.1.6.A1", "APP.4.4.A2"]
    assert sorted(ids, key=requirement_sort_key) == ["APP.4.4.A2", "APP.4.4.A10", "SYS.1.6.A1"]


@pytest.mark.parametrize(
    "bad",
    [
        [_req("APP.4.4.A1"), _req("APP.4.4.A1")],  # duplicate id
        [_req("APP.9.9.A1")],  # module not listed / id pattern
        [_req("APP.4.4.A1", "automatic", checks=())],  # automatic needs checks
        [_req("APP.4.4.A1", "manual", checks=(), questions=())],  # manual needs questions
    ],
)
def test_invalid_mappings_are_rejected(tmp_path, bad):
    with pytest.raises(ValidationError):
        load_mapping_file(_write(tmp_path, bad))


def test_unmapped_check_needs_bilingual_reason(tmp_path):
    m = load_mapping_file(
        _write(tmp_path, [_req("APP.4.4.A1")], unmapped=[{"check_id": "x", "reason": {"de": "d", "en": "e"}}])
    )
    assert m.unmapped_checks[0].check_id == "x"


def test_unknown_packaged_mapping():
    from k8s_baseline_audit.mapping.schema import load_mapping

    with pytest.raises(FileNotFoundError, match="unknown mapping"):
        load_mapping("does-not-exist")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pdm run pytest tests/test_mapping_schema.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

`src/k8s_baseline_audit/mapping/schema.py`:

```python
"""Versioned mapping from checks to BSI IT-Grundschutz requirements."""

from __future__ import annotations

import re
from enum import Enum
from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, model_validator

from ..models import Localized

_ID = re.compile(r"^(?P<module>(?:APP\.4\.4|SYS\.1\.6))\.A(?P<num>\d+)$")


def requirement_sort_key(rid: str) -> tuple[str, int]:
    m = _ID.match(rid)
    if not m:
        return (rid, 0)
    return (m.group("module"), int(m.group("num")))


class CoverageType(str, Enum):
    AUTOMATIC = "automatic"
    PARTIAL = "partial"
    MANUAL = "manual"
    ORGANIZATIONAL = "organizational"


class Level(str, Enum):
    BASIC = "basic"
    STANDARD = "standard"
    ELEVATED = "elevated"


class SourceRef(BaseModel):
    document: str
    edition: str
    url: str
    page: int | None = None


class Requirement(BaseModel):
    id: str = Field(pattern=_ID.pattern)
    module: str
    level: Level
    title: Localized
    summary: Localized
    source: SourceRef
    coverage_type: CoverageType
    checks: list[str] = Field(default_factory=list)
    questions: list[Localized] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent(self) -> Requirement:
        if not self.id.startswith(self.module + ".A"):
            raise ValueError(f"{self.id} does not belong to module {self.module}")
        automated = (CoverageType.AUTOMATIC, CoverageType.PARTIAL)
        if self.coverage_type in automated and not self.checks:
            raise ValueError(f"{self.id}: {self.coverage_type.value} requirement needs checks")
        if self.coverage_type not in automated and not self.questions:
            raise ValueError(f"{self.id}: {self.coverage_type.value} requirement needs questions")
        return self


class UnmappedCheck(BaseModel):
    check_id: str
    reason: Localized


class Mapping(BaseModel):
    name: str
    framework: str
    edition: str
    modules: list[str]
    requirements: list[Requirement]
    unmapped_checks: list[UnmappedCheck] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique(self) -> Mapping:
        ids = [r.id for r in self.requirements]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate requirement ids: {dupes}")
        unknown = sorted({r.module for r in self.requirements} - set(self.modules))
        if unknown:
            raise ValueError(f"requirements reference unlisted modules: {unknown}")
        self.requirements.sort(key=lambda r: requirement_sort_key(r.id))
        return self

    def get(self, requirement_id: str) -> Requirement:
        for r in self.requirements:
            if r.id == requirement_id:
                return r
        raise KeyError(requirement_id)

    def requirements_for_check(self, check_id: str) -> list[str]:
        return [r.id for r in self.requirements if check_id in r.checks]


def load_mapping_file(path: Path) -> Mapping:
    return Mapping.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def load_mapping(name: str = "kompendium-2023") -> Mapping:
    resource = files("k8s_baseline_audit.mappings").joinpath(f"{name}.yaml")
    if not resource.is_file():
        raise FileNotFoundError(f"unknown mapping: {name}")
    return Mapping.model_validate(yaml.safe_load(resource.read_text(encoding="utf-8")))
```

- [ ] **Step 4: Run tests**

Run: `pdm run pytest tests/test_mapping_schema.py -v`
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add src/k8s_baseline_audit/mapping src/k8s_baseline_audit/mappings tests/test_mapping_schema.py
git commit -m "feat: versioned mapping schema and loader"
```

---
### Task 6: Check framework and workload hardening checks

**Files:**
- Create: `src/k8s_baseline_audit/analyze/__init__.py` (empty), `src/k8s_baseline_audit/analyze/checks/__init__.py`, `src/k8s_baseline_audit/analyze/checks/base.py`, `src/k8s_baseline_audit/analyze/checks/workload.py`, `tests/factories.py`
- Test: `tests/test_checks_workload.py`

**Interfaces:**
- Consumes: `Severity`, `Localized`, `ResourceRef`, `Evidence` (Task 1).
- Produces (`base.py`):
  - `ManualCheckNeeded(reason: str)` exception with `.reason`.
  - `AnalyzerConfig(as_of: date, registry_allowlist: tuple[str, ...] = (), admin_subject_allowlist: tuple[str, ...] = ("Group:system:masters", "Group:kubeadm:cluster-admins"), anonymous_binding_allowlist: tuple[str, ...] = ("ClusterRoleBinding/-/system:public-info-viewer", "RoleBinding/kube-public/kubeadm:bootstrap-signer-clusterinfo"))`.
  - `Hit(resource: ResourceRef, evidence: Evidence)`; `CheckContext(resources: Mapping[str, list[dict]], config: AnalyzerConfig)` with `.items(kind) -> list[dict]`.
  - `Check(id, requires: tuple[str, ...], severity, title: Localized, remediation: Localized, fn)`; `REGISTRY: dict[str, Check]`; decorator `check(id, requires, severity, title_de, title_en, fix_de, fix_en)`.
  - Helpers: `ev(kind, json_path) -> Evidence` (file `resources/<kind>.json`), `meta_ref(kind_label, obj) -> ResourceRef`, `iter_containers(pod) -> Iterator[(field, index, container)]`, `sc(obj) -> dict`, `container_path(i, field, j) -> str`.
- Produces (`checks/__init__.py`): `all_checks() -> list[Check]` sorted by id.
- Check IDs added here: `workload.privileged`, `workload.run_as_root`, `workload.run_as_non_root_missing`, `workload.privilege_escalation`, `workload.added_capabilities`, `workload.host_namespaces`, `workload.host_path`, `workload.writable_root_fs`, `workload.seccomp_missing`, `workload.resource_limits_missing`.

- [ ] **Step 1: Write the test factories**

`tests/factories.py`:

```python
from datetime import date

from k8s_baseline_audit.analyze.checks import REGISTRY
from k8s_baseline_audit.analyze.checks.base import AnalyzerConfig, CheckContext

DIGEST = "sha256:" + "a" * 64
HARDENED_SC = {
    "runAsNonRoot": True,
    "runAsUser": 1000,
    "allowPrivilegeEscalation": False,
    "readOnlyRootFilesystem": True,
    "capabilities": {"drop": ["ALL"]},
    "seccompProfile": {"type": "RuntimeDefault"},
}


def container(name="app", image=f"registry.example.com/app:1.0@{DIGEST}", **extra):
    return {"name": name, "image": image, **extra}


def hardened_container(name="app", **extra):
    base = container(
        name,
        securityContext=dict(HARDENED_SC),
        resources={"limits": {"cpu": "100m", "memory": "64Mi"}},
    )
    base.update(extra)
    return base


def pod(name="web", namespace="default", containers=None, labels=None, owner=None, **spec):
    metadata = {"name": name, "namespace": namespace}
    if labels:
        metadata["labels"] = labels
    if owner:
        metadata["ownerReferences"] = [owner]
    body = {
        "containers": containers if containers is not None else [hardened_container()],
        "serviceAccountName": "app",
        "automountServiceAccountToken": False,
    }
    body.update(spec)
    return {"metadata": metadata, "spec": body}


def bad_pod(**sc_overrides):
    c = hardened_container()
    c["securityContext"].update(sc_overrides)
    return pod(containers=[c])


def config(**overrides):
    return AnalyzerConfig(as_of=date(2026, 9, 30), **overrides)


def ctx(config_=None, **resources):
    return CheckContext(resources=resources, config=config_ or config())


def run_check(check_id, context):
    return REGISTRY[check_id].fn(context)
```

- [ ] **Step 2: Write the failing test**

`tests/test_checks_workload.py`:

```python
import pytest
from factories import bad_pod, container, ctx, hardened_container, pod, run_check

from k8s_baseline_audit.analyze.checks import REGISTRY, all_checks

WORKLOAD = [
    "workload.added_capabilities",
    "workload.host_namespaces",
    "workload.host_path",
    "workload.privilege_escalation",
    "workload.privileged",
    "workload.resource_limits_missing",
    "workload.run_as_non_root_missing",
    "workload.run_as_root",
    "workload.seccomp_missing",
    "workload.writable_root_fs",
]


def test_all_workload_checks_registered_and_sorted():
    ids = [c.id for c in all_checks()]
    assert set(WORKLOAD) <= set(ids)
    assert ids == sorted(ids)
    for cid in WORKLOAD:
        assert REGISTRY[cid].requires == ("pods",)
        assert REGISTRY[cid].title.de and REGISTRY[cid].title.en


@pytest.mark.parametrize("check_id", WORKLOAD)
def test_hardened_pod_passes(check_id):
    assert run_check(check_id, ctx(pods=[pod()])) == []


def test_null_fields_do_not_crash():
    pods = [
        pod(containers=[container(securityContext=None, resources=None, env=None)], securityContext=None),
        {"metadata": {"name": "nospec", "namespace": "default"}},
        {"metadata": {"name": "nullspec", "namespace": "default"}, "spec": None},
    ]
    for cid in WORKLOAD:
        run_check(cid, ctx(pods=pods))


def test_privileged():
    hits = run_check("workload.privileged", ctx(pods=[bad_pod(privileged=True)]))
    assert len(hits) == 1
    assert hits[0].resource.key() == "Pod/default/web"
    assert hits[0].evidence.file == "resources/pods.json"
    assert hits[0].evidence.json_path == "$.items[0].spec.containers[0].securityContext.privileged"


def test_init_container_is_checked():
    p = pod(initContainers=[container("init", securityContext={"privileged": True})])
    hits = run_check("workload.privileged", ctx(pods=[p]))
    assert hits[0].evidence.json_path == "$.items[0].spec.initContainers[0].securityContext.privileged"


def test_run_as_root_container_and_pod_level():
    assert run_check("workload.run_as_root", ctx(pods=[bad_pod(runAsUser=0)]))
    c = hardened_container()
    del c["securityContext"]["runAsUser"]
    assert run_check("workload.run_as_root", ctx(pods=[pod(containers=[c], securityContext={"runAsUser": 0})]))


def test_container_run_as_user_overrides_pod():
    p = pod(securityContext={"runAsUser": 0})  # container sets 1000
    assert run_check("workload.run_as_root", ctx(pods=[p])) == []


def test_run_as_non_root_missing():
    c = hardened_container()
    del c["securityContext"]["runAsNonRoot"]
    del c["securityContext"]["runAsUser"]
    assert run_check("workload.run_as_non_root_missing", ctx(pods=[pod(containers=[c])]))
    assert run_check(
        "workload.run_as_non_root_missing",
        ctx(pods=[pod(containers=[c], securityContext={"runAsNonRoot": True})]),
    ) == []


def test_privilege_escalation_default_is_flagged():
    c = hardened_container()
    del c["securityContext"]["allowPrivilegeEscalation"]
    assert run_check("workload.privilege_escalation", ctx(pods=[pod(containers=[c])]))


def test_added_capabilities():
    assert run_check("workload.added_capabilities", ctx(pods=[bad_pod(capabilities={"add": ["SYS_ADMIN"]})]))
    ok = bad_pod(capabilities={"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]})
    assert run_check("workload.added_capabilities", ctx(pods=[ok])) == []


def test_host_namespaces_group_evidence():
    hits = run_check("workload.host_namespaces", ctx(pods=[pod(hostNetwork=True, hostPID=True)]))
    assert [h.evidence.json_path for h in hits] == ["$.items[0].spec.hostNetwork", "$.items[0].spec.hostPID"]


def test_host_path():
    p = pod(volumes=[{"name": "data", "emptyDir": {}}, {"name": "root", "hostPath": {"path": "/"}}])
    hits = run_check("workload.host_path", ctx(pods=[p]))
    assert [h.evidence.json_path for h in hits] == ["$.items[0].spec.volumes[1].hostPath"]


def test_writable_root_fs():
    assert run_check("workload.writable_root_fs", ctx(pods=[bad_pod(readOnlyRootFilesystem=False)]))


def test_seccomp_pod_level_satisfies():
    c = hardened_container()
    del c["securityContext"]["seccompProfile"]
    assert run_check("workload.seccomp_missing", ctx(pods=[pod(containers=[c])]))
    p = pod(containers=[c], securityContext={"seccompProfile": {"type": "RuntimeDefault"}})
    assert run_check("workload.seccomp_missing", ctx(pods=[p])) == []
    unconfined = pod(containers=[c], securityContext={"seccompProfile": {"type": "Unconfined"}})
    assert run_check("workload.seccomp_missing", ctx(pods=[unconfined]))


def test_resource_limits_missing_ignores_ephemeral():
    c = hardened_container(resources={"limits": {"cpu": "1"}})
    assert run_check("workload.resource_limits_missing", ctx(pods=[pod(containers=[c])]))
    p = pod(ephemeralContainers=[container("debug")])
    assert run_check("workload.resource_limits_missing", ctx(pods=[p])) == []
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pdm run pytest tests/test_checks_workload.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'k8s_baseline_audit.analyze'`

- [ ] **Step 4: Implement the framework**

`src/k8s_baseline_audit/analyze/checks/base.py`:

```python
"""Check framework: registry, context and helpers shared by all checks."""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import date

from ...models import Evidence, Localized, ResourceRef, Severity


class ManualCheckNeeded(Exception):
    """The collected data cannot decide this check; a person must verify it."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class AnalyzerConfig:
    as_of: date
    registry_allowlist: tuple[str, ...] = ()
    admin_subject_allowlist: tuple[str, ...] = (
        "Group:system:masters",
        "Group:kubeadm:cluster-admins",
    )
    anonymous_binding_allowlist: tuple[str, ...] = (
        "ClusterRoleBinding/-/system:public-info-viewer",
        "RoleBinding/kube-public/kubeadm:bootstrap-signer-clusterinfo",
    )


@dataclass(frozen=True)
class Hit:
    resource: ResourceRef
    evidence: Evidence


@dataclass(frozen=True)
class CheckContext:
    resources: Mapping[str, list[dict]]
    config: AnalyzerConfig

    def items(self, kind: str) -> list[dict]:
        return list(self.resources.get(kind) or [])


CheckFn = Callable[[CheckContext], list[Hit]]


@dataclass(frozen=True)
class Check:
    id: str
    requires: tuple[str, ...]
    severity: Severity
    title: Localized
    remediation: Localized
    fn: CheckFn


REGISTRY: dict[str, Check] = {}


def check(
    id: str,
    requires: tuple[str, ...],
    severity: Severity,
    title_de: str,
    title_en: str,
    fix_de: str,
    fix_en: str,
) -> Callable[[CheckFn], CheckFn]:
    def decorator(fn: CheckFn) -> CheckFn:
        if id in REGISTRY:
            raise ValueError(f"duplicate check id: {id}")
        REGISTRY[id] = Check(
            id=id,
            requires=requires,
            severity=severity,
            title=Localized(de=title_de, en=title_en),
            remediation=Localized(de=fix_de, en=fix_en),
            fn=fn,
        )
        return fn

    return decorator


def ev(kind: str, json_path: str) -> Evidence:
    return Evidence(file=f"resources/{kind}.json", json_path=json_path)


def meta_ref(kind_label: str, obj: dict) -> ResourceRef:
    md = obj.get("metadata") or {}
    return ResourceRef(kind=kind_label, name=md.get("name") or "?", namespace=md.get("namespace") or None)


CONTAINER_FIELDS = ("initContainers", "containers", "ephemeralContainers")


def spec_of(obj: dict) -> dict:
    return obj.get("spec") or {}


def iter_containers(pod: dict, fields: tuple[str, ...] = CONTAINER_FIELDS) -> Iterator[tuple[str, int, dict]]:
    spec = spec_of(pod)
    for field_name in fields:
        for idx, c in enumerate(spec.get(field_name) or []):
            yield field_name, idx, c or {}


def sc(obj: dict) -> dict:
    return obj.get("securityContext") or {}


def container_path(i: int, field_name: str, j: int) -> str:
    return f"$.items[{i}].spec.{field_name}[{j}]"
```

`src/k8s_baseline_audit/analyze/checks/__init__.py`:

```python
"""Built-in checks. Importing this package registers every check."""

from .base import REGISTRY, Check

from . import workload  # noqa: E402,F401,I001


def all_checks() -> list[Check]:
    return [REGISTRY[k] for k in sorted(REGISTRY)]


__all__ = ["REGISTRY", "Check", "all_checks"]
```

- [ ] **Step 5: Implement the workload checks**

`src/k8s_baseline_audit/analyze/checks/workload.py`:

```python
"""Container and pod hardening checks (SYS.1.6 / APP.4.4 workload requirements)."""

from __future__ import annotations

from ...models import Severity
from .base import CheckContext, Hit, check, container_path, ev, iter_containers, meta_ref, sc, spec_of

POD = ("pods",)
ALLOWED_ADDED_CAPS = frozenset({"NET_BIND_SERVICE"})
SAFE_SECCOMP = frozenset({"RuntimeDefault", "Localhost"})


def _hits_per_container(ctx: CheckContext, predicate, suffix: str, fields=None) -> list[Hit]:
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        kwargs = {"fields": fields} if fields else {}
        for field_name, j, c in iter_containers(p, **kwargs):
            if predicate(p, c):
                path = container_path(i, field_name, j) + suffix
                hits.append(Hit(meta_ref("Pod", p), ev("pods", path)))
    return hits


def _effective(p: dict, c: dict, key: str):
    value = sc(c).get(key)
    return value if value is not None else sc(spec_of(p)).get(key)


@check("workload.privileged", POD, Severity.CRITICAL,
       "Privilegierter Container", "Privileged container",
       "securityContext.privileged entfernen oder auf false setzen.",
       "Remove securityContext.privileged or set it to false.")
def privileged(ctx: CheckContext) -> list[Hit]:
    return _hits_per_container(ctx, lambda p, c: sc(c).get("privileged") is True, ".securityContext.privileged")


@check("workload.run_as_root", POD, Severity.HIGH,
       "Container läuft als root (UID 0)", "Container runs as root (UID 0)",
       "runAsUser auf eine UID größer 0 setzen und runAsNonRoot: true ergänzen.",
       "Set runAsUser to a UID above 0 and add runAsNonRoot: true.")
def run_as_root(ctx: CheckContext) -> list[Hit]:
    return _hits_per_container(ctx, lambda p, c: _effective(p, c, "runAsUser") == 0, ".securityContext")


@check("workload.run_as_non_root_missing", POD, Severity.MEDIUM,
       "Nicht-root-Ausführung nicht erzwungen", "Non-root execution not enforced",
       "runAsNonRoot: true auf Pod- oder Container-Ebene setzen.",
       "Set runAsNonRoot: true at pod or container level.")
def run_as_non_root_missing(ctx: CheckContext) -> list[Hit]:
    def missing(p: dict, c: dict) -> bool:
        uid = _effective(p, c, "runAsUser")
        return _effective(p, c, "runAsNonRoot") is not True and not (isinstance(uid, int) and uid > 0)

    return _hits_per_container(ctx, missing, ".securityContext")


@check("workload.privilege_escalation", POD, Severity.MEDIUM,
       "Rechteausweitung nicht unterbunden", "Privilege escalation not prevented",
       "allowPrivilegeEscalation: false im securityContext setzen.",
       "Set allowPrivilegeEscalation: false in the securityContext.")
def privilege_escalation(ctx: CheckContext) -> list[Hit]:
    return _hits_per_container(
        ctx, lambda p, c: sc(c).get("allowPrivilegeEscalation") is not False, ".securityContext"
    )


@check("workload.added_capabilities", POD, Severity.HIGH,
       "Zusätzliche Linux-Capabilities", "Added Linux capabilities",
       "capabilities.add entfernen; nur NET_BIND_SERVICE ist bei Bedarf vertretbar. drop: [ALL] setzen.",
       "Remove capabilities.add; only NET_BIND_SERVICE is acceptable when needed. Set drop: [ALL].")
def added_capabilities(ctx: CheckContext) -> list[Hit]:
    def bad(p: dict, c: dict) -> bool:
        added = (sc(c).get("capabilities") or {}).get("add") or []
        return any(cap not in ALLOWED_ADDED_CAPS for cap in added)

    return _hits_per_container(ctx, bad, ".securityContext.capabilities.add")


@check("workload.host_namespaces", POD, Severity.HIGH,
       "Pod nutzt Host-Namespaces", "Pod uses host namespaces",
       "hostNetwork, hostPID und hostIPC entfernen, sofern nicht zwingend erforderlich.",
       "Remove hostNetwork, hostPID and hostIPC unless strictly required.")
def host_namespaces(ctx: CheckContext) -> list[Hit]:
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        spec = spec_of(p)
        for key in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(key) is True:
                hits.append(Hit(meta_ref("Pod", p), ev("pods", f"$.items[{i}].spec.{key}")))
    return hits


@check("workload.host_path", POD, Severity.HIGH,
       "hostPath-Volume eingebunden", "hostPath volume mounted",
       "hostPath durch PersistentVolumes, ConfigMaps oder emptyDir ersetzen.",
       "Replace hostPath with PersistentVolumes, ConfigMaps or emptyDir.")
def host_path(ctx: CheckContext) -> list[Hit]:
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        for k, vol in enumerate(spec_of(p).get("volumes") or []):
            if (vol or {}).get("hostPath") is not None:
                hits.append(Hit(meta_ref("Pod", p), ev("pods", f"$.items[{i}].spec.volumes[{k}].hostPath")))
    return hits


@check("workload.writable_root_fs", POD, Severity.MEDIUM,
       "Beschreibbares Root-Dateisystem", "Writable root filesystem",
       "readOnlyRootFilesystem: true setzen; Schreibpfade als emptyDir einbinden.",
       "Set readOnlyRootFilesystem: true; mount write paths as emptyDir.")
def writable_root_fs(ctx: CheckContext) -> list[Hit]:
    return _hits_per_container(
        ctx, lambda p, c: sc(c).get("readOnlyRootFilesystem") is not True, ".securityContext"
    )


@check("workload.seccomp_missing", POD, Severity.MEDIUM,
       "Kein Seccomp-Profil", "No seccomp profile",
       "seccompProfile.type: RuntimeDefault auf Pod-Ebene setzen.",
       "Set seccompProfile.type: RuntimeDefault at pod level.")
def seccomp_missing(ctx: CheckContext) -> list[Hit]:
    def missing(p: dict, c: dict) -> bool:
        container_type = (sc(c).get("seccompProfile") or {}).get("type")
        pod_type = (sc(spec_of(p)).get("seccompProfile") or {}).get("type")
        effective = container_type if container_type is not None else pod_type
        return effective not in SAFE_SECCOMP

    return _hits_per_container(ctx, missing, ".securityContext")


@check("workload.resource_limits_missing", POD, Severity.LOW,
       "Fehlende CPU- oder Speicherlimits", "Missing CPU or memory limits",
       "resources.limits.cpu und resources.limits.memory für jeden Container setzen.",
       "Set resources.limits.cpu and resources.limits.memory for every container.")
def resource_limits_missing(ctx: CheckContext) -> list[Hit]:
    def missing(p: dict, c: dict) -> bool:
        limits = (c.get("resources") or {}).get("limits") or {}
        return "cpu" not in limits or "memory" not in limits

    return _hits_per_container(ctx, missing, ".resources", fields=("initContainers", "containers"))
```

- [ ] **Step 6: Run tests**

Run: `pdm run pytest tests/test_checks_workload.py -v && pdm run ruff check .`
Expected: all passed, ruff clean.

- [ ] **Step 7: Commit**

```bash
git add src/k8s_baseline_audit/analyze tests/factories.py tests/test_checks_workload.py
git commit -m "feat: check framework and workload hardening checks"
```

---

### Task 7: Identity and access checks

**Files:**
- Create: `src/k8s_baseline_audit/analyze/checks/identity.py`
- Modify: `src/k8s_baseline_audit/analyze/checks/__init__.py` (add import)
- Test: `tests/test_checks_identity.py`

**Interfaces:**
- Consumes: framework from Task 6; `AnalyzerConfig.admin_subject_allowlist`, `.anonymous_binding_allowlist`.
- Check IDs added: `identity.cluster_admin_binding` (high), `identity.wildcard_role` (high), `identity.anonymous_binding` (critical), `identity.default_service_account` (medium), `identity.automount_token` (medium), `identity.long_lived_token_secret` (medium).

- [ ] **Step 1: Write the failing test**

`tests/test_checks_identity.py`:

```python
from factories import ctx, pod, run_check


def crb(name, role, subjects):
    return {"metadata": {"name": name}, "roleRef": {"kind": "ClusterRole", "name": role}, "subjects": subjects}


def rb(ns, name, role, subjects):
    return {
        "metadata": {"name": name, "namespace": ns},
        "roleRef": {"kind": "Role", "name": role},
        "subjects": subjects,
    }


def group(n):
    return {"kind": "Group", "name": n}


def user(n):
    return {"kind": "User", "name": n}


def test_kubeadm_defaults_are_not_flagged():
    crbs = [
        crb("cluster-admin", "cluster-admin", [group("system:masters")]),
        crb("kubeadm:cluster-admins", "cluster-admin", [group("kubeadm:cluster-admins")]),
        crb("system:public-info-viewer", "system:public-info-viewer",
            [group("system:authenticated"), group("system:unauthenticated")]),
    ]
    rbs = [rb("kube-public", "kubeadm:bootstrap-signer-clusterinfo", "kubeadm:bootstrap-signer-clusterinfo",
              [user("system:anonymous")])]
    c = ctx(clusterrolebindings=crbs, rolebindings=rbs)
    assert run_check("identity.cluster_admin_binding", c) == []
    assert run_check("identity.anonymous_binding", c) == []


def test_cluster_admin_to_person_is_flagged():
    c = ctx(clusterrolebindings=[crb("ops", "cluster-admin", [user("alice"), group("system:masters")])])
    hits = run_check("identity.cluster_admin_binding", c)
    assert [h.resource.key() for h in hits] == ["ClusterRoleBinding/-/ops"]
    assert hits[0].evidence.json_path == "$.items[0].subjects"


def test_anonymous_bindings_are_flagged():
    c = ctx(
        clusterrolebindings=[crb("anon-view", "view", [user("system:anonymous")])],
        rolebindings=[rb("prod", "open", "reader", [group("system:unauthenticated")])],
    )
    keys = sorted(h.resource.key() for h in run_check("identity.anonymous_binding", c))
    assert keys == ["ClusterRoleBinding/-/anon-view", "RoleBinding/prod/open"]


def test_wildcard_roles():
    roles = [{"metadata": {"name": "r", "namespace": "prod"}, "rules": [{"verbs": ["get"], "resources": ["*"]}]}]
    clusterroles = [
        {"metadata": {"name": "cluster-admin"}, "rules": [{"verbs": ["*"], "resources": ["*"]}]},
        {"metadata": {"name": "system:controller:x"}, "rules": [{"verbs": ["*"], "resources": ["*"]}]},
        {"metadata": {"name": "custom"}, "rules": [{"verbs": ["get"], "resources": ["pods"]}, {"verbs": ["*"]}]},
    ]
    hits = run_check("identity.wildcard_role", ctx(roles=roles, clusterroles=clusterroles))
    assert sorted((h.resource.key(), h.evidence.json_path) for h in hits) == [
        ("ClusterRole/-/custom", "$.items[2].rules[1]"),
        ("Role/prod/r", "$.items[0].rules[0]"),
    ]


def test_default_service_account():
    p1 = pod(serviceAccountName="default")
    p2 = pod(name="db")
    del p2["spec"]["serviceAccountName"]
    hits = run_check("identity.default_service_account", ctx(pods=[p1, p2, pod(name="ok")]))
    assert sorted(h.resource.name for h in hits) == ["db", "web"]


def test_automount_token_resolution():
    sas = [
        {"metadata": {"name": "app", "namespace": "default"}, "automountServiceAccountToken": False},
        {"metadata": {"name": "other", "namespace": "default"}},
    ]
    inherits_off = pod(name="a", automountServiceAccountToken=None)
    inherits_on = pod(name="b", serviceAccountName="other", automountServiceAccountToken=None)
    explicit_on = pod(name="c", automountServiceAccountToken=True)
    hits = run_check(
        "identity.automount_token",
        ctx(pods=[inherits_off, inherits_on, explicit_on], serviceaccounts=sas),
    )
    assert sorted(h.resource.name for h in hits) == ["b", "c"]


def test_long_lived_token_secret():
    secrets = [
        {"metadata": {"namespace": "default", "name": "tok"}, "type": "kubernetes.io/service-account-token", "keys": []},
        {"metadata": {"namespace": "default", "name": "db"}, "type": "Opaque", "keys": ["password"]},
    ]
    hits = run_check("identity.long_lived_token_secret", ctx(secrets=secrets))
    assert [(h.resource.key(), h.evidence.json_path) for h in hits] == [("Secret/default/tok", "$.items[0].type")]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pdm run pytest tests/test_checks_identity.py -v`
Expected: FAIL with `KeyError: 'identity.anonymous_binding'`

- [ ] **Step 3: Write minimal implementation**

`src/k8s_baseline_audit/analyze/checks/identity.py`:

```python
"""RBAC and service account checks (APP.4.4 identity and permission management)."""

from __future__ import annotations

from ...models import Severity
from .base import CheckContext, Hit, check, ev, meta_ref, spec_of

ANONYMOUS = frozenset({"User:system:anonymous", "Group:system:unauthenticated"})


def _subject_key(subject: dict) -> str:
    return f"{subject.get('kind')}:{subject.get('name')}"


@check("identity.cluster_admin_binding", ("clusterrolebindings",), Severity.HIGH,
       "cluster-admin an zusätzliche Subjekte vergeben", "cluster-admin granted to additional subjects",
       "cluster-admin-Bindung entfernen und durch eng gefasste Rollen ersetzen.",
       "Remove the cluster-admin binding and replace it with narrowly scoped roles.")
def cluster_admin_binding(ctx: CheckContext) -> list[Hit]:
    allow = set(ctx.config.admin_subject_allowlist)
    hits = []
    for i, b in enumerate(ctx.items("clusterrolebindings")):
        if (b.get("roleRef") or {}).get("name") != "cluster-admin":
            continue
        subjects = b.get("subjects") or []
        if subjects and all(_subject_key(s) in allow for s in subjects):
            continue
        hits.append(Hit(meta_ref("ClusterRoleBinding", b), ev("clusterrolebindings", f"$.items[{i}].subjects")))
    return hits


@check("identity.wildcard_role", ("roles", "clusterroles"), Severity.HIGH,
       "Rolle mit Platzhalter-Rechten (*)", "Role with wildcard permissions (*)",
       "Platzhalter in verbs und resources durch konkrete Werte ersetzen.",
       "Replace wildcards in verbs and resources with explicit values.")
def wildcard_role(ctx: CheckContext) -> list[Hit]:
    hits = []
    for kind_file, label in (("clusterroles", "ClusterRole"), ("roles", "Role")):
        for i, role in enumerate(ctx.items(kind_file)):
            name = (role.get("metadata") or {}).get("name") or ""
            if label == "ClusterRole" and (name == "cluster-admin" or name.startswith("system:")):
                continue
            for k, rule in enumerate(role.get("rules") or []):
                if "*" in (rule.get("verbs") or []) or "*" in (rule.get("resources") or []):
                    hits.append(Hit(meta_ref(label, role), ev(kind_file, f"$.items[{i}].rules[{k}]")))
    return hits


@check("identity.anonymous_binding", ("rolebindings", "clusterrolebindings"), Severity.CRITICAL,
       "Rechte für anonyme oder nicht authentifizierte Zugriffe", "Permissions for anonymous or unauthenticated access",
       "Bindung an system:anonymous bzw. system:unauthenticated entfernen.",
       "Remove the binding to system:anonymous or system:unauthenticated.")
def anonymous_binding(ctx: CheckContext) -> list[Hit]:
    allow = set(ctx.config.anonymous_binding_allowlist)
    hits = []
    for kind_file, label in (("clusterrolebindings", "ClusterRoleBinding"), ("rolebindings", "RoleBinding")):
        for i, b in enumerate(ctx.items(kind_file)):
            ref = meta_ref(label, b)
            if ref.key() in allow:
                continue
            if any(_subject_key(s) in ANONYMOUS for s in b.get("subjects") or []):
                hits.append(Hit(ref, ev(kind_file, f"$.items[{i}].subjects")))
    return hits


@check("identity.default_service_account", ("pods",), Severity.MEDIUM,
       "Pod nutzt das default-ServiceAccount", "Pod uses the default service account",
       "Eigenes ServiceAccount je Anwendung anlegen und serviceAccountName setzen.",
       "Create a dedicated service account per application and set serviceAccountName.")
def default_service_account(ctx: CheckContext) -> list[Hit]:
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        if spec_of(p).get("serviceAccountName") in (None, "", "default"):
            hits.append(Hit(meta_ref("Pod", p), ev("pods", f"$.items[{i}].spec.serviceAccountName")))
    return hits


@check("identity.automount_token", ("pods", "serviceaccounts"), Severity.MEDIUM,
       "ServiceAccount-Token automatisch eingebunden", "Service account token automounted",
       "automountServiceAccountToken: false setzen, wenn der Pod die Kubernetes-API nicht braucht.",
       "Set automountServiceAccountToken: false when the pod does not need the Kubernetes API.")
def automount_token(ctx: CheckContext) -> list[Hit]:
    accounts = {
        ((sa.get("metadata") or {}).get("namespace"), (sa.get("metadata") or {}).get("name")): sa
        for sa in ctx.items("serviceaccounts")
    }
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        spec = spec_of(p)
        value = spec.get("automountServiceAccountToken")
        if value is False:
            continue
        if value is None:
            ns = (p.get("metadata") or {}).get("namespace")
            sa = accounts.get((ns, spec.get("serviceAccountName") or "default"))
            if sa is not None and sa.get("automountServiceAccountToken") is False:
                continue
        hits.append(Hit(meta_ref("Pod", p), ev("pods", f"$.items[{i}].spec.automountServiceAccountToken")))
    return hits


@check("identity.long_lived_token_secret", ("secrets",), Severity.MEDIUM,
       "Langlebiges ServiceAccount-Token als Secret", "Long-lived service account token secret",
       "Secret löschen und kurzlebige Tokens über die TokenRequest-API nutzen.",
       "Delete the secret and use short-lived tokens from the TokenRequest API.")
def long_lived_token_secret(ctx: CheckContext) -> list[Hit]:
    return [
        Hit(meta_ref("Secret", s), ev("secrets", f"$.items[{i}].type"))
        for i, s in enumerate(ctx.items("secrets"))
        if s.get("type") == "kubernetes.io/service-account-token"
    ]
```

Add to `checks/__init__.py` below the workload import:

```python
from . import identity  # noqa: E402,F401,I001
```

- [ ] **Step 4: Run tests**

Run: `pdm run pytest tests/test_checks_identity.py tests/test_checks_workload.py -v`
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add src/k8s_baseline_audit/analyze/checks tests/test_checks_identity.py
git commit -m "feat: identity and RBAC checks with kubeadm default allowlists"
```

---

### Task 8: Namespace isolation, secrets and image checks

**Files:**
- Create: `src/k8s_baseline_audit/analyze/checks/isolation.py`, `src/k8s_baseline_audit/analyze/checks/secrets_images.py`
- Modify: `src/k8s_baseline_audit/analyze/checks/__init__.py` (two imports)
- Test: `tests/test_checks_isolation.py`, `tests/test_checks_secrets_images.py`

**Interfaces:**
- Consumes: framework (Task 6); `CREDENTIAL_NAME` from `collect/redact.py` (Task 3); `AnalyzerConfig.registry_allowlist`.
- Produces: `split_image(image: str) -> tuple[str, str | None, str | None]` returning `(registry, tag, digest)`.
- Check IDs added: `isolation.psa_labels_missing` (medium), `isolation.no_network_policy` (medium), `isolation.no_default_deny` (low), `isolation.allow_all_policy` (high), `secrets.env_secret_ref` (low), `secrets.credential_literal_env` (high), `images.latest_tag` (medium), `images.no_digest` (low), `images.registry_not_allowed` (medium).

- [ ] **Step 1: Write the failing tests**

`tests/test_checks_isolation.py`:

```python
from factories import ctx, pod, run_check


def ns(name, labels=None):
    return {"metadata": {"name": name, "labels": labels or {}}}


def np(ns_, name, spec):
    return {"metadata": {"name": name, "namespace": ns_}, "spec": spec}


DENY = {"podSelector": {}, "policyTypes": ["Ingress"]}


def test_psa_labels():
    namespaces = [ns("a"), ns("b", {"pod-security.kubernetes.io/enforce": "restricted"})]
    hits = run_check("isolation.psa_labels_missing", ctx(namespaces=namespaces))
    assert [(h.resource.key(), h.evidence.json_path) for h in hits] == [
        ("Namespace/-/a", "$.items[0].metadata.labels")
    ]


def test_no_network_policy_only_for_namespaces_with_pods():
    namespaces = [ns("default"), ns("empty"), ns("secured")]
    pods = [pod(namespace="default"), pod(namespace="secured")]
    policies = [np("secured", "deny", DENY)]
    hits = run_check("isolation.no_network_policy", ctx(namespaces=namespaces, pods=pods, networkpolicies=policies))
    assert [h.resource.key() for h in hits] == ["Namespace/-/default"]


def test_no_default_deny():
    policies = [
        np("a", "allow-web", {"podSelector": {"matchLabels": {"app": "web"}}, "ingress": [{"from": [{"podSelector": {}}]}]}),
        np("b", "deny", DENY),
        np("c", "deny-implicit", {"podSelector": {}}),
    ]
    hits = run_check("isolation.no_default_deny", ctx(networkpolicies=policies))
    assert [(h.resource.key(), h.evidence.json_path) for h in hits] == [("Namespace/-/a", "$.items[0]")]


def test_allow_all_policy():
    policies = [np("a", "open", {"podSelector": {}, "ingress": [{}]}), np("b", "deny", DENY)]
    hits = run_check("isolation.allow_all_policy", ctx(networkpolicies=policies))
    assert [(h.resource.key(), h.evidence.json_path) for h in hits] == [
        ("NetworkPolicy/a/open", "$.items[0].spec.ingress[0]")
    ]
```

`tests/test_checks_secrets_images.py`:

```python
import pytest
from factories import config, container, ctx, hardened_container, pod, run_check

from k8s_baseline_audit.analyze.checks.base import ManualCheckNeeded
from k8s_baseline_audit.analyze.checks.secrets_images import split_image
from k8s_baseline_audit.collect.redact import REDACTED


@pytest.mark.parametrize(
    "image,expected",
    [
        ("nginx", ("docker.io", None, None)),
        ("nginx:latest", ("docker.io", "latest", None)),
        ("library/nginx:1.27", ("docker.io", "1.27", None)),
        ("registry:5000/app", ("registry:5000", None, None)),
        ("registry:5000/team/app:2", ("registry:5000", "2", None)),
        ("ghcr.io/org/app@sha256:abc", ("ghcr.io", None, "sha256:abc")),
        ("localhost/app:1", ("localhost", "1", None)),
    ],
)
def test_split_image(image, expected):
    assert split_image(image) == expected


def test_env_secret_ref():
    c = hardened_container(env=[{"name": "X", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}])
    c2 = hardened_container("b", envFrom=[{"secretRef": {"name": "s"}}])
    hits = run_check("secrets.env_secret_ref", ctx(pods=[pod(containers=[c, c2])]))
    assert [h.evidence.json_path for h in hits] == [
        "$.items[0].spec.containers[0].env",
        "$.items[0].spec.containers[1].envFrom",
    ]


def test_credential_literal_env_redacted_or_raw():
    c = hardened_container(env=[{"name": "DB_PASSWORD", "value": REDACTED}, {"name": "PORT", "value": REDACTED}])
    raw = hardened_container("raw", env=[{"name": "API_KEY", "value": "abc"}])
    empty = hardened_container("e", env=[{"name": "TOKEN", "value": ""}])
    hits = run_check("secrets.credential_literal_env", ctx(pods=[pod(containers=[c, raw, empty])]))
    assert [h.evidence.json_path for h in hits] == [
        "$.items[0].spec.containers[0].env[0]",
        "$.items[0].spec.containers[1].env[0]",
    ]


def test_latest_and_digest():
    pods = [pod(containers=[container("a", "nginx:latest"), container("b", "nginx"), container("c", "nginx:1.27")])]
    latest = run_check("images.latest_tag", ctx(pods=pods))
    assert [h.evidence.json_path for h in latest] == [
        "$.items[0].spec.containers[0].image",
        "$.items[0].spec.containers[1].image",
    ]
    assert len(run_check("images.no_digest", ctx(pods=pods))) == 3
    assert run_check("images.no_digest", ctx(pods=[pod()])) == []


def test_registry_allowlist():
    with pytest.raises(ManualCheckNeeded, match="no registry allowlist"):
        run_check("images.registry_not_allowed", ctx(pods=[pod()]))
    pods = [pod(containers=[container("a", "nginx:1"), hardened_container()])]
    c = ctx(config(registry_allowlist=("registry.example.com",)), pods=pods)
    hits = run_check("images.registry_not_allowed", c)
    assert [h.evidence.json_path for h in hits] == ["$.items[0].spec.containers[0].image"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pdm run pytest tests/test_checks_isolation.py tests/test_checks_secrets_images.py -v`
Expected: FAIL (`KeyError` / `ModuleNotFoundError`)

- [ ] **Step 3: Implement isolation checks**

`src/k8s_baseline_audit/analyze/checks/isolation.py`:

```python
"""Namespace separation checks: Pod Security Admission and NetworkPolicies."""

from __future__ import annotations

from ...models import ResourceRef, Severity
from .base import CheckContext, Hit, check, ev, meta_ref, spec_of

PSA_ENFORCE = "pod-security.kubernetes.io/enforce"


def _ns(obj: dict) -> str | None:
    return (obj.get("metadata") or {}).get("namespace")


def _is_default_deny_ingress(policy: dict) -> bool:
    spec = spec_of(policy)
    selector = spec.get("podSelector") or {}
    selects_all = not selector.get("matchLabels") and not selector.get("matchExpressions")
    types = spec.get("policyTypes") or ["Ingress"]
    return selects_all and "Ingress" in types and not spec.get("ingress")


@check("isolation.psa_labels_missing", ("namespaces",), Severity.MEDIUM,
       "Namespace ohne Pod-Security-Admission-Label", "Namespace without Pod Security Admission label",
       "Label pod-security.kubernetes.io/enforce (baseline oder restricted) setzen.",
       "Set the label pod-security.kubernetes.io/enforce (baseline or restricted).")
def psa_labels_missing(ctx: CheckContext) -> list[Hit]:
    hits = []
    for i, n in enumerate(ctx.items("namespaces")):
        labels = (n.get("metadata") or {}).get("labels") or {}
        if PSA_ENFORCE not in labels:
            hits.append(Hit(meta_ref("Namespace", n), ev("namespaces", f"$.items[{i}].metadata.labels")))
    return hits


@check("isolation.no_network_policy", ("namespaces", "networkpolicies", "pods"), Severity.MEDIUM,
       "Namespace mit Pods, aber ohne NetworkPolicy", "Namespace with pods but no NetworkPolicy",
       "Default-Deny-NetworkPolicy anlegen und benötigte Verbindungen explizit erlauben.",
       "Create a default-deny NetworkPolicy and explicitly allow required connections.")
def no_network_policy(ctx: CheckContext) -> list[Hit]:
    with_pods = {_ns(p) for p in ctx.items("pods")}
    with_policy = {_ns(p) for p in ctx.items("networkpolicies")}
    hits = []
    for i, n in enumerate(ctx.items("namespaces")):
        name = (n.get("metadata") or {}).get("name")
        if name in with_pods and name not in with_policy:
            hits.append(Hit(meta_ref("Namespace", n), ev("namespaces", f"$.items[{i}]")))
    return hits


@check("isolation.no_default_deny", ("networkpolicies",), Severity.LOW,
       "Keine Default-Deny-Regel für eingehenden Verkehr", "No default-deny rule for ingress",
       "NetworkPolicy mit podSelector: {} und policyTypes: [Ingress] ohne Regeln ergänzen.",
       "Add a NetworkPolicy with podSelector: {} and policyTypes: [Ingress] and no rules.")
def no_default_deny(ctx: CheckContext) -> list[Hit]:
    first_index: dict[str, int] = {}
    has_deny: set[str] = set()
    for i, policy in enumerate(ctx.items("networkpolicies")):
        ns = _ns(policy) or ""
        first_index.setdefault(ns, i)
        if _is_default_deny_ingress(policy):
            has_deny.add(ns)
    return [
        Hit(ResourceRef(kind="Namespace", name=ns), ev("networkpolicies", f"$.items[{i}]"))
        for ns, i in sorted(first_index.items())
        if ns not in has_deny
    ]


@check("isolation.allow_all_policy", ("networkpolicies",), Severity.HIGH,
       "NetworkPolicy erlaubt jeglichen eingehenden Verkehr", "NetworkPolicy allows all ingress",
       "Leere Ingress-Regel ({}) durch konkrete from- und ports-Angaben ersetzen.",
       "Replace the empty ingress rule ({}) with explicit from and ports entries.")
def allow_all_policy(ctx: CheckContext) -> list[Hit]:
    hits = []
    for i, policy in enumerate(ctx.items("networkpolicies")):
        for k, rule in enumerate(spec_of(policy).get("ingress") or []):
            if rule == {}:
                hits.append(Hit(meta_ref("NetworkPolicy", policy), ev("networkpolicies", f"$.items[{i}].spec.ingress[{k}]")))
    return hits
```

- [ ] **Step 4: Implement secrets and image checks**

`src/k8s_baseline_audit/analyze/checks/secrets_images.py`:

```python
"""Secret handling and container image checks."""

from __future__ import annotations

from ...collect.redact import CREDENTIAL_NAME
from ...models import Severity
from .base import CheckContext, Hit, ManualCheckNeeded, check, container_path, ev, iter_containers, meta_ref

POD = ("pods",)


def split_image(image: str) -> tuple[str, str | None, str | None]:
    digest = None
    if "@" in image:
        image, digest = image.split("@", 1)
    first, _, rest = image.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = "docker.io", image
    last = path.rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else None
    return registry, tag, digest


def _image_hits(ctx: CheckContext, predicate) -> list[Hit]:
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        for field_name, j, c in iter_containers(p):
            image = c.get("image") or ""
            if image and predicate(image):
                hits.append(Hit(meta_ref("Pod", p), ev("pods", container_path(i, field_name, j) + ".image")))
    return hits


@check("secrets.env_secret_ref", POD, Severity.LOW,
       "Secret als Umgebungsvariable eingebunden", "Secret consumed as environment variable",
       "Secret als Datei-Volume einbinden; Umgebungsvariablen landen leicht in Logs und Dumps.",
       "Mount the secret as a file volume; environment variables easily leak into logs and dumps.")
def env_secret_ref(ctx: CheckContext) -> list[Hit]:
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        for field_name, j, c in iter_containers(p):
            base = container_path(i, field_name, j)
            if any(((e or {}).get("valueFrom") or {}).get("secretKeyRef") for e in c.get("env") or []):
                hits.append(Hit(meta_ref("Pod", p), ev("pods", base + ".env")))
            if any((e or {}).get("secretRef") for e in c.get("envFrom") or []):
                hits.append(Hit(meta_ref("Pod", p), ev("pods", base + ".envFrom")))
    return hits


@check("secrets.credential_literal_env", POD, Severity.HIGH,
       "Zugangsdaten als Klartext-Umgebungsvariable", "Credential as plain-text environment variable",
       "Wert in ein Secret verschieben und rotieren; der Klartext stand im Pod-Manifest.",
       "Move the value into a Secret and rotate it; the plain text was in the pod manifest.")
def credential_literal_env(ctx: CheckContext) -> list[Hit]:
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        for field_name, j, c in iter_containers(p):
            for k, e in enumerate(c.get("env") or []):
                e = e or {}
                if e.get("value") and CREDENTIAL_NAME.search(e.get("name") or ""):
                    hits.append(Hit(meta_ref("Pod", p), ev("pods", container_path(i, field_name, j) + f".env[{k}]")))
    return hits


@check("images.latest_tag", POD, Severity.MEDIUM,
       "Image ohne feste Version (latest oder kein Tag)", "Image without fixed version (latest or no tag)",
       "Feste Versionsnummer oder Digest verwenden.",
       "Use a fixed version tag or a digest.")
def latest_tag(ctx: CheckContext) -> list[Hit]:
    def unpinned(image: str) -> bool:
        _, tag, digest = split_image(image)
        return digest is None and tag in (None, "latest")

    return _image_hits(ctx, unpinned)


@check("images.no_digest", POD, Severity.LOW,
       "Image nicht per Digest fixiert", "Image not pinned by digest",
       "Image per @sha256-Digest referenzieren, damit der Inhalt unveränderlich ist.",
       "Reference the image by @sha256 digest so its content cannot change.")
def no_digest(ctx: CheckContext) -> list[Hit]:
    return _image_hits(ctx, lambda image: split_image(image)[2] is None)


@check("images.registry_not_allowed", POD, Severity.MEDIUM,
       "Image aus nicht freigegebener Registry", "Image from a registry outside the allowlist",
       "Image in eine freigegebene Registry spiegeln oder die Freigabeliste bewusst erweitern.",
       "Mirror the image into an approved registry or deliberately extend the allowlist.")
def registry_not_allowed(ctx: CheckContext) -> list[Hit]:
    allowed = set(ctx.config.registry_allowlist)
    if not allowed:
        raise ManualCheckNeeded("no registry allowlist configured (use --registry-allowlist)")
    return _image_hits(ctx, lambda image: split_image(image)[0] not in allowed)
```

Add to `checks/__init__.py`:

```python
from . import isolation  # noqa: E402,F401,I001
from . import secrets_images  # noqa: E402,F401,I001
```

- [ ] **Step 5: Run tests**

Run: `pdm run pytest -v && pdm run ruff check .`
Expected: all passed, ruff clean.

- [ ] **Step 6: Commit**

```bash
git add src/k8s_baseline_audit/analyze/checks tests/test_checks_isolation.py tests/test_checks_secrets_images.py
git commit -m "feat: namespace isolation, secret handling and image checks"
```

---

### Task 9: Control plane and version checks

**Files:**
- Create: `src/k8s_baseline_audit/analyze/checks/control_plane.py`, `src/k8s_baseline_audit/data/__init__.py` (empty), `src/k8s_baseline_audit/data/k8s-support.yaml`
- Modify: `src/k8s_baseline_audit/analyze/checks/__init__.py` (import)
- Test: `tests/test_checks_control_plane.py`

**Interfaces:**
- Consumes: framework (Task 6). Resource kind `version` is a one-element list `[<kubectl version -o json doc>]` (Task 12 builds it that way).
- Produces: `parse_flags(container: dict) -> dict[str, str]`; `support_table() -> dict` (cached loader, monkeypatchable).
- Check IDs added: `control_plane.encryption_at_rest` (high), `control_plane.anonymous_auth` (medium), `control_plane.audit_logging` (high), `control_plane.etcd_listen_non_loopback` (medium), `version.unsupported` (high).

- [ ] **Step 1: Fill the support table from the official source**

Fetch the release page and read the end-of-life date of every minor release that is listed:

```bash
firecrawl scrape https://kubernetes.io/releases/ --only-main-content | grep -iE 'end of life|1\.[0-9]{2}'
```

Write `src/k8s_baseline_audit/data/k8s-support.yaml` with the dates exactly as the page states them, one entry per minor release shown (current and recently ended ones):

```yaml
source: https://kubernetes.io/releases/
retrieved: "2026-09-30"   # the day you ran the scrape
releases:
  # "<major>.<minor>": "<end of life date, YYYY-MM-DD, copied from the page>"
  "1.35": "YYYY-MM-DD"
```

Replace every `YYYY-MM-DD` with the value from the page. Do not estimate. If the page lists no date for a release, leave that release out; the check then reports `manual` for it.

- [ ] **Step 2: Write the failing test**

`tests/test_checks_control_plane.py`:

```python
from datetime import date

import pytest
from factories import ctx, pod, run_check

from k8s_baseline_audit.analyze.checks import control_plane
from k8s_baseline_audit.analyze.checks.base import AnalyzerConfig
from k8s_baseline_audit.analyze.checks.base import ManualCheckNeeded


def static(component, command):
    return pod(
        name=f"{component}-cp",
        namespace="kube-system",
        labels={"component": component, "tier": "control-plane"},
        containers=[{"name": component, "image": "x", "command": command}],
    )


HARDENED_API = [
    "kube-apiserver",
    "--anonymous-auth=false",
    "--encryption-provider-config=/etc/kubernetes/enc/config.yaml",
    "--audit-log-path=/var/log/kubernetes/audit.log",
    "--audit-policy-file=/etc/kubernetes/audit-policy.yaml",
]
KUBEADM_DEFAULT_API = ["kube-apiserver", "--authorization-mode=Node,RBAC"]
ETCD_LOOPBACK = ["etcd", "--listen-client-urls=https://127.0.0.1:2379"]
ETCD_EXPOSED = ["etcd", "--listen-client-urls=https://127.0.0.1:2379,https://10.211.55.31:2379"]

CP_CHECKS = [
    "control_plane.anonymous_auth",
    "control_plane.audit_logging",
    "control_plane.encryption_at_rest",
]


def test_parse_flags():
    c = {"command": ["x", "--a=1", "--b"], "args": ["--c=d=e"]}
    assert control_plane.parse_flags(c) == {"a": "1", "b": "", "c": "d=e"}


@pytest.mark.parametrize("check_id", CP_CHECKS)
def test_hardened_apiserver_passes(check_id):
    assert run_check(check_id, ctx(pods=[static("kube-apiserver", HARDENED_API)])) == []


@pytest.mark.parametrize("check_id", CP_CHECKS)
def test_kubeadm_default_apiserver_is_flagged(check_id):
    hits = run_check(check_id, ctx(pods=[static("kube-apiserver", KUBEADM_DEFAULT_API)]))
    assert [h.evidence.json_path for h in hits] == ["$.items[0].spec.containers[0].command"]
    assert hits[0].resource.key() == "Pod/kube-system/kube-apiserver-cp"


@pytest.mark.parametrize("check_id", CP_CHECKS + ["control_plane.etcd_listen_non_loopback"])
def test_managed_cluster_needs_manual_check(check_id):
    with pytest.raises(ManualCheckNeeded, match="not visible"):
        run_check(check_id, ctx(pods=[pod()]))


def test_etcd_exposure():
    assert run_check("control_plane.etcd_listen_non_loopback", ctx(pods=[static("etcd", ETCD_LOOPBACK)])) == []
    hits = run_check("control_plane.etcd_listen_non_loopback", ctx(pods=[static("etcd", ETCD_EXPOSED)]))
    assert len(hits) == 1


@pytest.fixture
def table(monkeypatch):
    t = {"retrieved": "2026-09-30", "source": "test", "releases": {"1.33": "2026-06-28", "1.35": "2027-02-28"}}
    monkeypatch.setattr(control_plane, "support_table", lambda: t)


def version(minor):
    return [{"serverVersion": {"major": "1", "minor": minor, "gitVersion": f"v1.{minor}.0"}}]


def test_version_supported(table):
    assert run_check("version.unsupported", ctx(version=version("35"))) == []


def test_version_out_of_support(table):
    hits = run_check("version.unsupported", ctx(version=version("33")))
    assert [(h.resource.key(), h.evidence.json_path) for h in hits] == [("Cluster/-/cluster", "$.serverVersion")]


def test_managed_minor_suffix_is_stripped(table):
    assert run_check("version.unsupported", ctx(version=version("35+"))) == []


def test_unknown_version_needs_manual_check(table):
    with pytest.raises(ManualCheckNeeded, match="not in support table"):
        run_check("version.unsupported", ctx(version=version("20")))


def test_as_of_date_is_used(table):
    later = AnalyzerConfig(as_of=date(2027, 3, 1))
    assert run_check("version.unsupported", ctx(later, version=version("35")))


def test_packaged_table_is_well_formed():
    t = control_plane.support_table.__wrapped__()
    assert t["source"].startswith("https://kubernetes.io/")
    assert t["releases"]
    for key, value in t["releases"].items():
        assert key.count(".") == 1
        date.fromisoformat(value)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pdm run pytest tests/test_checks_control_plane.py -v`
Expected: FAIL with `ImportError: cannot import name 'control_plane'`

- [ ] **Step 4: Write minimal implementation**

`src/k8s_baseline_audit/analyze/checks/control_plane.py`:

```python
"""Control plane checks from kubeadm static pod specs, and Kubernetes version support."""

from __future__ import annotations

import functools
import re
from datetime import date
from importlib.resources import files
from urllib.parse import urlparse

import yaml

from ...models import Evidence, ResourceRef, Severity
from .base import CheckContext, Hit, ManualCheckNeeded, check, ev, meta_ref, spec_of

LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})


def parse_flags(container: dict) -> dict[str, str]:
    flags: dict[str, str] = {}
    for arg in list(container.get("command") or []) + list(container.get("args") or []):
        if isinstance(arg, str) and arg.startswith("--"):
            key, _, value = arg[2:].partition("=")
            flags[key] = value
    return flags


def _static_pod(ctx: CheckContext, component: str) -> tuple[int, dict, dict[str, str]]:
    for i, p in enumerate(ctx.items("pods")):
        md = p.get("metadata") or {}
        if md.get("namespace") == "kube-system" and (md.get("labels") or {}).get("component") == component:
            containers = spec_of(p).get("containers") or [{}]
            return i, p, parse_flags(containers[0] or {})
    raise ManualCheckNeeded(
        f"{component} static pod not visible: managed cluster or no access to kube-system pods"
    )


def _api_hit(i: int, p: dict) -> list[Hit]:
    return [Hit(meta_ref("Pod", p), ev("pods", f"$.items[{i}].spec.containers[0].command"))]


@check("control_plane.encryption_at_rest", ("pods",), Severity.HIGH,
       "Keine Verschlüsselung von Secrets in etcd konfiguriert", "No encryption at rest configured for etcd",
       "EncryptionConfiguration anlegen und --encryption-provider-config am API-Server setzen.",
       "Create an EncryptionConfiguration and set --encryption-provider-config on the API server.")
def encryption_at_rest(ctx: CheckContext) -> list[Hit]:
    i, p, flags = _static_pod(ctx, "kube-apiserver")
    return [] if flags.get("encryption-provider-config") else _api_hit(i, p)


@check("control_plane.anonymous_auth", ("pods",), Severity.MEDIUM,
       "Anonyme Anfragen am API-Server zugelassen", "Anonymous requests allowed on the API server",
       "--anonymous-auth=false setzen; Health-Probes vorher auf authentifizierte Endpunkte prüfen.",
       "Set --anonymous-auth=false; first confirm health probes do not rely on anonymous access.")
def anonymous_auth(ctx: CheckContext) -> list[Hit]:
    i, p, flags = _static_pod(ctx, "kube-apiserver")
    return [] if flags.get("anonymous-auth") == "false" else _api_hit(i, p)


@check("control_plane.audit_logging", ("pods",), Severity.HIGH,
       "Audit-Logging des API-Servers nicht aktiv", "API server audit logging not enabled",
       "--audit-policy-file und --audit-log-path setzen und Logs zentral sammeln.",
       "Set --audit-policy-file and --audit-log-path and ship the logs centrally.")
def audit_logging(ctx: CheckContext) -> list[Hit]:
    i, p, flags = _static_pod(ctx, "kube-apiserver")
    enabled = flags.get("audit-policy-file") and flags.get("audit-log-path")
    return [] if enabled else _api_hit(i, p)


@check("control_plane.etcd_listen_non_loopback", ("pods",), Severity.MEDIUM,
       "etcd-Client-Port auf Nicht-Loopback-Adresse erreichbar", "etcd client port listens on a non-loopback address",
       "Erreichbarkeit von Port 2379 per Firewall auf Control-Plane-Knoten beschränken oder nur 127.0.0.1 binden.",
       "Restrict port 2379 to control plane nodes by firewall, or bind to 127.0.0.1 only.")
def etcd_listen_non_loopback(ctx: CheckContext) -> list[Hit]:
    i, p, flags = _static_pod(ctx, "etcd")
    urls = [u for u in (flags.get("listen-client-urls") or "").split(",") if u]
    exposed = [u for u in urls if (urlparse(u).hostname or "") not in LOOPBACK]
    return _api_hit(i, p) if exposed else []


@functools.cache
def _load_support_table() -> dict:
    text = files("k8s_baseline_audit.data").joinpath("k8s-support.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)


def support_table() -> dict:
    return _load_support_table()


support_table.__wrapped__ = _load_support_table  # type: ignore[attr-defined]


@check("version.unsupported", ("version",), Severity.HIGH,
       "Kubernetes-Version ohne Upstream-Support", "Kubernetes version out of upstream support",
       "Auf eine unterstützte Minor-Version aktualisieren (siehe kubernetes.io/releases).",
       "Upgrade to a supported minor version (see kubernetes.io/releases).")
def version_unsupported(ctx: CheckContext) -> list[Hit]:
    docs = ctx.items("version")
    server = (docs[0] if docs else {}).get("serverVersion") or {}
    key = f"{server.get('major', '')}.{re.sub(r'[^0-9]', '', server.get('minor', ''))}"
    table = support_table()
    eol = (table.get("releases") or {}).get(key)
    if eol is None:
        raise ManualCheckNeeded(f"Kubernetes {key} not in support table (retrieved {table.get('retrieved')})")
    if date.fromisoformat(eol) < ctx.config.as_of:
        return [Hit(ResourceRef(kind="Cluster", name="cluster"), Evidence(file="resources/version.json", json_path="$.serverVersion"))]
    return []
```

Add to `checks/__init__.py`:

```python
from . import control_plane  # noqa: E402,F401,I001
```

- [ ] **Step 5: Run tests**

Run: `pdm run pytest -v && pdm run ruff check .`
Expected: all passed, ruff clean.

- [ ] **Step 6: Commit**

```bash
git add src/k8s_baseline_audit/analyze/checks src/k8s_baseline_audit/data tests/test_checks_control_plane.py
git commit -m "feat: control plane flag checks and Kubernetes version support check"
```

---
### Task 10: Kompendium 2023 mapping content

This task is research plus data entry, enforced by tests. The engineer reads the official BSI module documents and writes paraphrases. **Do not copy BSI sentences.** Never commit the PDFs (`bsi-sources/` is gitignored).

**Files:**
- Create: `src/k8s_baseline_audit/mappings/sources/kompendium-2023-ids.txt`, `src/k8s_baseline_audit/mappings/kompendium-2023.yaml`
- Test: `tests/test_mapping_content.py`

**Interfaces:**
- Consumes: `load_mapping` (Task 5), `all_checks()` (Tasks 6–9).
- Produces: packaged mapping `kompendium-2023` covering every requirement ID of APP.4.4 and SYS.1.6.

- [ ] **Step 1: Resolve the open source questions from the spec (section 14, items 1 and 2)**

```bash
firecrawl scrape "https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Grundschutz-in-der-Informationssicherheit/Grundschutz-Plus-Plus/grundschutz-plus-plus_node.html" --only-main-content > bsi-sources/grundschutz-pp.md
grep -niE 'Kompendium|Übergang|Zertifizierung|2023' bsi-sources/grundschutz-pp.md | head -40
firecrawl search "BSI IT-Grundschutz-Kompendium Nutzungsbedingungen Urheberrecht Vervielfältigung" --limit 5
```

Record the findings, with URLs, in a new section `## 16. Source verification (<date>)` at the end of the spec. If the BSI page says Kompendium 2023 is **not** the certification basis any more, stop and report to the user before writing the mapping.

- [ ] **Step 2: Download the official module documents**

```bash
mkdir -p bsi-sources
curl -sSfL -o bsi-sources/APP_4_4.pdf "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-GS-Kompendium_Einzel_PDFs_2022/06_APP_Anwendungen/APP_4_4_Kubernetes_Edition_2022.pdf?__blob=publicationFile&v=3"
firecrawl search "BSI SYS.1.6 Containerisierung Edition 2023 PDF site:bsi.bund.de" --limit 5
# download the SYS.1.6 PDF from the bsi.bund.de URL the search returns:
curl -sSfL -o bsi-sources/SYS_1_6.pdf "<bsi.bund.de URL from the search result>"
firecrawl search "BSI APP.4.4 Kubernetes Edition 2023 PDF site:bsi.bund.de" --limit 5
```

If an Edition 2023 PDF of APP.4.4 exists on bsi.bund.de, use it instead of the 2022 file. Record the exact URL and edition of each file; they go into every `source` entry.

- [ ] **Step 3: Extract the requirement IDs and levels**

```bash
brew list poppler >/dev/null 2>&1 || brew install poppler
for f in APP_4_4 SYS_1_6; do
  pdftotext -layout bsi-sources/$f.pdf bsi-sources/$f.txt
done
grep -hoE '(APP\.4\.4|SYS\.1\.6)\.A[0-9]+ [^()]+\((B|S|H)\)' bsi-sources/*.txt | sort -u
grep -hnE '(APP\.4\.4|SYS\.1\.6)\.A[0-9]+.*ENTFALLEN' bsi-sources/*.txt
```

Write `src/k8s_baseline_audit/mappings/sources/kompendium-2023-ids.txt`, one line per **non-withdrawn** requirement, tab separated, level letter mapped `B→basic`, `S→standard`, `H→elevated`:

```
APP.4.4.A1	basic
APP.4.4.A2	basic
APP.4.4.A3	basic
```

Continue for every ID the grep prints. Withdrawn ("ENTFALLEN") requirements are left out. A heading split across two lines by `pdftotext` will not match the grep; read the text file around each `A<n>` number to confirm none is missed (`grep -nE '\.A[0-9]+' bsi-sources/*.txt`).

- [ ] **Step 4: Write the failing test**

`tests/test_mapping_content.py`:

```python
from importlib.resources import files

from k8s_baseline_audit.analyze.checks import all_checks
from k8s_baseline_audit.mapping.schema import load_mapping

FORBIDDEN_WORDS = ("erfüllt", "fulfilled", "compliant", "konform")


def _expected():
    text = files("k8s_baseline_audit.mappings").joinpath("sources/kompendium-2023-ids.txt").read_text()
    rows = [line.split("\t") for line in text.splitlines() if line.strip()]
    return {rid: level for rid, level in rows}


def test_every_source_requirement_is_mapped_exactly_once():
    m = load_mapping()
    expected = _expected()
    assert expected, "ids file is empty"
    assert {r.id for r in m.requirements} == set(expected)
    for r in m.requirements:
        assert r.level.value == expected[r.id], r.id


def test_both_modules_present():
    m = load_mapping()
    assert {r.module for r in m.requirements} == {"APP.4.4", "SYS.1.6"}
    assert m.modules == ["APP.4.4", "SYS.1.6"]


def test_every_referenced_check_exists():
    known = {c.id for c in all_checks()}
    m = load_mapping()
    for r in m.requirements:
        assert set(r.checks) <= known, (r.id, set(r.checks) - known)


def test_every_builtin_check_is_mapped_or_explicitly_unmapped():
    m = load_mapping()
    mapped = {c for r in m.requirements for c in r.checks}
    unmapped = {u.check_id for u in m.unmapped_checks}
    assert not mapped & unmapped
    missing = {c.id for c in all_checks()} - mapped - unmapped
    assert not missing, f"checks neither mapped nor listed in unmapped_checks: {sorted(missing)}"


def test_texts_are_bilingual_sourced_and_never_claim_fulfilment():
    m = load_mapping()
    for r in m.requirements:
        for loc in [r.title, r.summary, *r.questions]:
            assert loc.de.strip() and loc.en.strip(), r.id
            for word in FORBIDDEN_WORDS:
                assert word not in (loc.de + loc.en).lower(), (r.id, word)
        assert r.source.url.startswith("https://www.bsi.bund.de/"), r.id
        assert r.source.edition, r.id
```

- [ ] **Step 5: Run test to verify it fails**

Run: `pdm run pytest tests/test_mapping_content.py -v`
Expected: FAIL with `FileNotFoundError: unknown mapping: kompendium-2023`

- [ ] **Step 6: Write the mapping**

`src/k8s_baseline_audit/mappings/kompendium-2023.yaml`. Header and the three requirements confirmed during design, in the exact format every other entry must follow:

```yaml
name: kompendium-2023
framework: BSI IT-Grundschutz-Kompendium
edition: "2023"
modules: ["APP.4.4", "SYS.1.6"]
requirements:
  - id: APP.4.4.A1
    module: APP.4.4
    level: basic
    title:
      de: Trennung der Anwendungen planen
      en: Plan the separation of applications
    summary:
      de: >-
        Vor der Inbetriebnahme festlegen, wie Anwendungen und Umgebungen
        (Test, Produktion) über Namespaces, Cluster und Netze getrennt werden,
        abgeleitet aus ihrem Schutzbedarf.
      en: >-
        Before go-live, decide how applications and environments (test,
        production) are separated through namespaces, clusters and networks,
        based on their protection needs.
    source: {document: "APP.4.4 Kubernetes", edition: "2022", url: "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-GS-Kompendium_Einzel_PDFs_2022/06_APP_Anwendungen/APP_4_4_Kubernetes_Edition_2022.pdf", page: 3}
    coverage_type: organizational
    questions:
      - de: Gibt es ein dokumentiertes Trennungskonzept für Namespaces, Cluster und Netze? Wer hat es freigegeben?
        en: Is there a documented separation concept for namespaces, clusters and networks? Who approved it?
      - de: Laufen Anwendungen mit unterschiedlichem Schutzbedarf im selben Cluster? Wenn ja, mit welcher Begründung?
        en: Do applications with different protection needs share a cluster? If so, what is the justification?
  - id: APP.4.4.A2
    module: APP.4.4
    level: basic
    title:
      de: Automatisierung mit CI/CD planen
      en: Plan automation with CI/CD
    summary:
      de: >-
        Automatisierten Betrieb über CI/CD erst nach einer Planung einführen,
        die den gesamten Lebenszyklus, das Rollen- und Rechtekonzept und den
        Schutz von Secrets abdeckt.
      en: >-
        Introduce CI/CD-driven operation only after planning that covers the
        whole lifecycle, the role and permission concept and the protection of
        secrets.
    source: {document: "APP.4.4 Kubernetes", edition: "2022", url: "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-GS-Kompendium_Einzel_PDFs_2022/06_APP_Anwendungen/APP_4_4_Kubernetes_Edition_2022.pdf", page: 3}
    coverage_type: organizational
    questions:
      - de: Welche Pipeline darf in welche Namespaces deployen, und mit welchen Rechten?
        en: Which pipeline may deploy into which namespaces, and with which permissions?
      - de: Wie werden Secrets in der Pipeline gespeichert und rotiert?
        en: How are secrets stored and rotated in the pipeline?
  - id: APP.4.4.A3
    module: APP.4.4
    level: basic
    title:
      de: Identitäts- und Berechtigungsmanagement
      en: Identity and permission management
    summary:
      de: >-
        Jede Aktion an Kubernetes und der Control Plane authentifizieren und
        autorisieren; administrative Aktionen nie anonym zulassen.
      en: >-
        Authenticate and authorize every action on Kubernetes and the control
        plane; never allow administrative actions anonymously.
    source: {document: "APP.4.4 Kubernetes", edition: "2022", url: "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-GS-Kompendium_Einzel_PDFs_2022/06_APP_Anwendungen/APP_4_4_Kubernetes_Edition_2022.pdf", page: 3}
    coverage_type: partial
    checks:
      - identity.anonymous_binding
      - control_plane.anonymous_auth
    questions:
      - de: Wie authentifizieren sich Administratoren (OIDC, Zertifikate), und wie werden Zugänge entzogen?
        en: How do administrators authenticate (OIDC, certificates), and how is access revoked?
unmapped_checks: []
```

Correct the `page` values against the PDF. Then add one entry per remaining ID in `kompendium-2023-ids.txt`, following these rules:

1. `title` and `summary` are **your own** short paraphrases in German and English. Read the requirement, close the PDF, write.
2. `coverage_type`: `organizational` if the requirement asks for a concept, plan, process or documentation; `manual` if it is technical but not visible through the Kubernetes API (node hardening, host OS, backups, physical location); `partial` if a check provides evidence but a person must still judge; `automatic` only if the linked checks fully decide it.
3. `checks`: assign a check only when the requirement explicitly asks for what the check tests. When unsure, leave it out; an unassigned check goes into `unmapped_checks` with a bilingual reason, and the test forces you to decide.
4. `questions`: at least one interview question for every `organizational` or `manual` requirement; add them for `partial` requirements when a person must judge something specific.
5. `source`: exact document, edition, URL and page of the PDF you read.

- [ ] **Step 7: Run tests**

Run: `pdm run pytest tests/test_mapping_content.py -v`
Expected: all passed. A failure names the missing ID or check; fix the YAML, not the test.

- [ ] **Step 8: Commit**

```bash
git status --short | grep -q bsi-sources && { echo "bsi-sources must not be committed"; exit 1; }
git add src/k8s_baseline_audit/mappings tests/test_mapping_content.py docs/superpowers/specs
git commit -m "feat: Kompendium 2023 mapping for APP.4.4 and SYS.1.6"
```

---

### Task 11: Scanner output sanitizers, parsers and deduplication

**Files:**
- Create: `src/k8s_baseline_audit/collect/sanitize.py`, `src/k8s_baseline_audit/analyze/scanners/__init__.py`, `src/k8s_baseline_audit/analyze/scanners/common.py`, `src/k8s_baseline_audit/analyze/scanners/trivy.py`, `src/k8s_baseline_audit/analyze/scanners/kubescape.py`, `src/k8s_baseline_audit/analyze/scanners/kube_bench.py`, `src/k8s_baseline_audit/analyze/dedupe.py`, `examples/kind-demo/insecure.yaml`, `tests/fixtures/scanners/{trivy,kubescape,kube-bench-node}.json`, `tests/fixtures/scanners/VERSIONS`
- Test: `tests/test_sanitize.py`, `tests/test_scanner_parsers.py`, `tests/test_dedupe.py`

**Interfaces:**
- Consumes: models (Task 1), `requirement_sort_key` (Task 5).
- Produces:
  - `sanitize_kubescape(doc) -> dict`, `sanitize_trivy(doc) -> dict` (deep copies).
  - `ScannerFormatError`, `map_severity(raw: str | None) -> tuple[Severity, bool]`.
  - `parse_scanner_file(rel: str, doc: dict) -> list[Finding]` dispatching on `scanners/trivy.json`, `scanners/kubescape.json`, `scanners/kube-bench-<node>.json`.
  - Scanner check IDs: `trivy:<ID>`, `trivy:secret:<RuleID>`, `kubescape:<controlID>`, `kube-bench:<test_number>`.
  - `ALIASES: dict[str, str]`, `pod_owner_map(pods) -> dict[tuple[str | None, str], tuple[str | None, str]]`, `dedupe(builtin: list[Finding], scanner: list[Finding], pods: list[dict]) -> list[Finding]`.

- [ ] **Step 1: Create the kind demo manifest**

`examples/kind-demo/insecure.yaml` (deliberately insecure; only ever applied to a throwaway kind cluster):

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: audit-demo
---
apiVersion: v1
kind: Secret
metadata: {name: demo-creds, namespace: audit-demo}
type: Opaque
stringData: {password: demo-only-not-a-real-secret}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: hardened, namespace: audit-demo}
automountServiceAccountToken: false
---
apiVersion: v1
kind: Pod
metadata: {name: insecure, namespace: audit-demo}
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx:latest
      securityContext:
        privileged: true
        runAsUser: 0
        capabilities: {add: [SYS_ADMIN]}
      env:
        - {name: DB_PASSWORD, value: hunter2-demo}
        - name: FROM_SECRET
          valueFrom: {secretKeyRef: {name: demo-creds, key: password}}
      volumeMounts: [{name: host, mountPath: /host}]
  volumes:
    - name: host
      hostPath: {path: /}
---
apiVersion: v1
kind: Pod
metadata: {name: hardened, namespace: audit-demo}
spec:
  serviceAccountName: hardened
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65535
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: pause
      image: registry.k8s.io/pause:3.10
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
      resources:
        limits: {cpu: 50m, memory: 32Mi}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: audit-demo-wildcard}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: audit-demo-anon}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: view}
subjects: [{apiGroup: rbac.authorization.k8s.io, kind: User, name: "system:anonymous"}]
```

- [ ] **Step 2: Capture real scanner output as fixtures**

This runs against a local throwaway kind cluster only.

```bash
brew install kind trivy kubescape jq   # skip what is installed
kind create cluster --name k8s-baseline-audit-fixtures
kubectl --context kind-k8s-baseline-audit-fixtures apply -f examples/kind-demo/insecure.yaml
kubectl --context kind-k8s-baseline-audit-fixtures -n audit-demo wait --for=condition=Ready pod/hardened --timeout=120s
trivy k8s --help | grep -iE 'node-collector|context|report'      # confirm flag names; record in VERSIONS
kubescape scan --help | grep -iE 'kube-context|format|output'     # confirm flag names; record in VERSIONS
mkdir -p tests/fixtures/scanners
trivy k8s --context kind-k8s-baseline-audit-fixtures --report all --format json \
  --disable-node-collector --output /tmp/trivy-full.json
kubescape scan --kube-context kind-k8s-baseline-audit-fixtures --format json --output /tmp/kubescape-full.json
jq '.Resources |= map(select(.Namespace == "audit-demo"))' /tmp/trivy-full.json > tests/fixtures/scanners/trivy.json
jq '.' /tmp/kubescape-full.json > tests/fixtures/scanners/kubescape.json
kubectl --context kind-k8s-baseline-audit-fixtures apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl --context kind-k8s-baseline-audit-fixtures wait --for=condition=complete job/kube-bench --timeout=300s
kubectl --context kind-k8s-baseline-audit-fixtures logs job/kube-bench > /tmp/kube-bench.txt
```

The upstream Job prints text. Re-run it with JSON output by editing a local copy of `job.yaml` so the container args include `--json`, apply that copy, and save the logs as `tests/fixtures/scanners/kube-bench-node.json`. Then:

```bash
{ trivy --version | head -1; kubescape version; echo "kube-bench: $(jq -r '.Controls[0].version // "unknown"' tests/fixtures/scanners/kube-bench-node.json)"; } > tests/fixtures/scanners/VERSIONS
grep -c hunter2-demo tests/fixtures/scanners/*.json   # counts before sanitizing; expected > 0 for kubescape
kind delete cluster --name k8s-baseline-audit-fixtures
```

If the flag names from `--help` differ from the ones above, use the real names everywhere in this plan (Task 13 builds the same commands) and note it in `VERSIONS`. If `kubescape.json` is larger than 5 MB, trim `.resources` and `.results` to entries whose `resourceID` contains `audit-demo` with `jq`.

- [ ] **Step 3: Write the failing sanitizer test**

`tests/test_sanitize.py`:

```python
import json
from pathlib import Path

from k8s_baseline_audit.collect.sanitize import sanitize_kubescape, sanitize_trivy

FIX = Path(__file__).parent / "fixtures" / "scanners"


def test_kubescape_objects_are_reduced_to_identity():
    doc = {
        "resources": [
            {
                "resourceID": "/v1/audit-demo/Pod/insecure",
                "object": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": "insecure", "namespace": "audit-demo", "annotations": {"a": "x"}},
                    "spec": {"containers": [{"env": [{"name": "DB_PASSWORD", "value": "hunter2-demo"}]}]},
                },
            },
            {"resourceID": "no-object"},
        ],
        "results": [],
    }
    out = sanitize_kubescape(doc)
    assert out["resources"][0]["object"] == {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "insecure", "namespace": "audit-demo"},
    }
    assert out["resources"][1] == {"resourceID": "no-object"}
    assert "hunter2-demo" in json.dumps(doc)  # input untouched


def test_trivy_snippets_and_secret_matches_are_removed():
    doc = {
        "Resources": [
            {
                "Results": [
                    {"Misconfigurations": [{"ID": "KSV017", "CauseMetadata": {"Code": {"Lines": ["hunter2-demo"]}}}]},
                    {"Secrets": [{"RuleID": "aws-access-key-id", "Match": "AKIA...", "Code": {"Lines": []}, "Title": "AWS"}]},
                ]
            }
        ]
    }
    out = sanitize_trivy(doc)
    assert out["Resources"][0]["Results"][0]["Misconfigurations"][0] == {"ID": "KSV017"}
    assert out["Resources"][0]["Results"][1]["Secrets"][0] == {"RuleID": "aws-access-key-id", "Title": "AWS"}


def test_captured_fixtures_do_not_leak_demo_secret_after_sanitizing():
    ks = sanitize_kubescape(json.loads((FIX / "kubescape.json").read_text()))
    tv = sanitize_trivy(json.loads((FIX / "trivy.json").read_text()))
    assert "hunter2-demo" not in json.dumps(ks)
    assert "hunter2-demo" not in json.dumps(tv)
```

- [ ] **Step 4: Run test to verify it fails**

Run: `pdm run pytest tests/test_sanitize.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 5: Implement the sanitizers**

`src/k8s_baseline_audit/collect/sanitize.py`:

```python
"""Strip sensitive payloads from scanner output before it enters a bundle.

scripts/export-bundle.sh implements the same rules in jq (parity test in
tests/test_export_script.py).
"""

from __future__ import annotations

import copy


def sanitize_kubescape(doc: dict) -> dict:
    out = copy.deepcopy(doc)
    for resource in out.get("resources") or []:
        obj = resource.get("object")
        if isinstance(obj, dict):
            md = obj.get("metadata") or {}
            resource["object"] = {
                "apiVersion": obj.get("apiVersion"),
                "kind": obj.get("kind"),
                "metadata": {"name": md.get("name"), "namespace": md.get("namespace")},
            }
    return out


def sanitize_trivy(doc: dict) -> dict:
    out = copy.deepcopy(doc)
    for resource in out.get("Resources") or []:
        for result in resource.get("Results") or []:
            for misconfig in result.get("Misconfigurations") or []:
                misconfig.pop("CauseMetadata", None)
            for secret in result.get("Secrets") or []:
                secret.pop("Match", None)
                secret.pop("Code", None)
    return out
```

Run: `pdm run pytest tests/test_sanitize.py -v` → all passed.

After implementation, sanitize the committed fixtures in place so no demo secret sits in the repository:

```bash
pdm run python - <<'PY'
import json, pathlib
from k8s_baseline_audit.collect.sanitize import sanitize_kubescape, sanitize_trivy
d = pathlib.Path("tests/fixtures/scanners")
for name, fn in (("kubescape.json", sanitize_kubescape), ("trivy.json", sanitize_trivy)):
    p = d / name
    p.write_text(json.dumps(fn(json.loads(p.read_text())), indent=2, sort_keys=True) + "\n")
PY
grep -c hunter2-demo tests/fixtures/scanners/*.json   # expected: 0 everywhere
```

- [ ] **Step 6: Write the failing parser tests**

The hand-written documents below encode the formats as understood when this plan was written. The captured fixtures are the source of truth. If `test_captured_fixture_parses` fails because a field is named differently, change the parser **and** the hand-written documents to match the fixture, then note the difference in `VERSIONS`.

`tests/test_scanner_parsers.py`:

```python
import json
from pathlib import Path

import pytest

from k8s_baseline_audit.analyze.scanners import parse_scanner_file
from k8s_baseline_audit.analyze.scanners.common import ScannerFormatError, map_severity
from k8s_baseline_audit.models import Severity, Source

FIX = Path(__file__).parent / "fixtures" / "scanners"

TRIVY = {
    "ClusterName": "kind",
    "Resources": [
        {
            "Namespace": "audit-demo",
            "Kind": "Pod",
            "Name": "insecure",
            "Results": [
                {
                    "Misconfigurations": [
                        {"ID": "KSV017", "Title": "Privileged", "Severity": "HIGH", "Status": "FAIL", "Resolution": "Drop it"},
                        {"ID": "KSV099", "Title": "Passed", "Severity": "LOW", "Status": "PASS"},
                    ]
                },
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "3.0.1",
                         "FixedVersion": "3.0.2", "Severity": "CRITICAL"},
                        {"VulnerabilityID": "CVE-2024-0002", "PkgName": "zlib", "InstalledVersion": "1",
                         "Severity": "UNKNOWN"},
                    ]
                },
                {"Secrets": [{"RuleID": "aws-access-key-id", "Title": "AWS Access Key", "Severity": "CRITICAL"}]},
            ],
        }
    ],
}

KUBESCAPE = {
    "summaryDetails": {"controls": {"C-0057": {"name": "Privileged container", "scoreFactor": 8}}},
    "resources": [
        {"resourceID": "/v1/audit-demo/Pod/insecure",
         "object": {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "insecure", "namespace": "audit-demo"}}}
    ],
    "results": [
        {"resourceID": "/v1/audit-demo/Pod/insecure",
         "controls": [
             {"controlID": "C-0057", "name": "Privileged container", "status": {"status": "failed"}},
             {"controlID": "C-0001", "name": "Passed control", "status": {"status": "passed"}},
         ]}
    ],
}

KUBE_BENCH = {
    "Controls": [
        {"id": "4", "version": "cis-1.9", "node_type": "node", "tests": [
            {"section": "4.2", "results": [
                {"test_number": "4.2.1", "test_desc": "Anonymous auth off", "status": "FAIL", "remediation": "Set it"},
                {"test_number": "4.2.2", "test_desc": "Authz mode", "status": "PASS"},
                {"test_number": "4.2.3", "test_desc": "Client CA", "status": "WARN"},
            ]}
        ]}
    ]
}


def test_map_severity():
    assert map_severity("HIGH") == (Severity.HIGH, False)
    assert map_severity("UNKNOWN") == (Severity.LOW, True)
    assert map_severity(None) == (Severity.LOW, True)


def test_trivy():
    fs = parse_scanner_file("scanners/trivy.json", TRIVY)
    by_id = {f.check_id: f for f in fs}
    assert set(by_id) == {"trivy:KSV017", "trivy:CVE-2024-0001", "trivy:CVE-2024-0002", "trivy:secret:aws-access-key-id"}
    mis = by_id["trivy:KSV017"]
    assert mis.severity == Severity.HIGH and mis.sources == [Source.TRIVY]
    assert mis.resources[0].key() == "Pod/audit-demo/insecure"
    assert mis.evidence[0].json_path == "$.Resources[0].Results[0].Misconfigurations[0]"
    assert by_id["trivy:CVE-2024-0002"].severity_unmapped
    assert "3.0.2" in by_id["trivy:CVE-2024-0001"].remediation.de


def test_kubescape():
    fs = parse_scanner_file("scanners/kubescape.json", KUBESCAPE)
    assert [(f.check_id, f.severity, f.resources[0].key()) for f in fs] == [
        ("kubescape:C-0057", Severity.HIGH, "Pod/audit-demo/insecure")
    ]


def test_kube_bench_uses_node_from_filename():
    fs = parse_scanner_file("scanners/kube-bench-worker-1.json", KUBE_BENCH)
    assert [(f.check_id, f.severity, f.resources[0].key()) for f in fs] == [
        ("kube-bench:4.2.1", Severity.MEDIUM, "Node/-/worker-1"),
        ("kube-bench:4.2.3", Severity.LOW, "Node/-/worker-1"),
    ]
    assert all(f.severity_unmapped for f in fs)


@pytest.mark.parametrize(
    "rel,doc",
    [("scanners/trivy.json", {"x": 1}), ("scanners/kubescape.json", {"x": 1}), ("scanners/kube-bench-a.json", {})],
)
def test_unknown_format_is_rejected(rel, doc):
    with pytest.raises(ScannerFormatError):
        parse_scanner_file(rel, doc)


def test_unknown_scanner_file_is_rejected():
    with pytest.raises(ScannerFormatError, match="unknown scanner file"):
        parse_scanner_file("scanners/grype.json", {})


@pytest.mark.parametrize("name", ["trivy.json", "kubescape.json", "kube-bench-node.json"])
def test_captured_fixture_parses(name):
    fs = parse_scanner_file(f"scanners/{name}", json.loads((FIX / name).read_text()))
    assert fs, f"{name}: no findings parsed from a deliberately insecure cluster"
    for f in fs:
        assert f.resources and f.evidence and f.title.en
```

- [ ] **Step 7: Run test to verify it fails**

Run: `pdm run pytest tests/test_scanner_parsers.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 8: Implement the parsers**

`src/k8s_baseline_audit/analyze/scanners/common.py`:

```python
from __future__ import annotations

from ...models import Evidence, Finding, Localized, ResourceRef, Severity, Source, finding_id


class ScannerFormatError(Exception):
    """Scanner output does not have the expected structure."""


def map_severity(raw: str | None) -> tuple[Severity, bool]:
    try:
        return Severity((raw or "").lower()), False
    except ValueError:
        return Severity.LOW, True


def make_finding(check_id: str, ref: ResourceRef, title: Localized, severity: Severity, unmapped: bool,
                 evidence: Evidence, source: Source, remediation: Localized) -> Finding:
    return Finding(
        id=finding_id(check_id, ref),
        check_id=check_id,
        title=title,
        severity=severity,
        severity_unmapped=unmapped,
        resources=[ref],
        evidence=[evidence],
        sources=[source],
        remediation=remediation,
    )


def same(text: str) -> Localized:
    return Localized(de=text, en=text)
```

`src/k8s_baseline_audit/analyze/scanners/trivy.py`:

```python
from __future__ import annotations

from ...models import Evidence, Finding, Localized, ResourceRef, Source
from .common import ScannerFormatError, make_finding, map_severity, same


def parse(doc: dict, rel: str) -> list[Finding]:
    resources = doc.get("Resources")
    if not isinstance(resources, list):
        raise ScannerFormatError(f"{rel}: expected top-level 'Resources' list (trivy k8s JSON)")
    out: list[Finding] = []
    for i, r in enumerate(resources):
        ref = ResourceRef(kind=r.get("Kind") or "Unknown", name=r.get("Name") or "?", namespace=r.get("Namespace") or None)
        for j, result in enumerate(r.get("Results") or []):
            base = f"$.Resources[{i}].Results[{j}]"
            for k, m in enumerate(result.get("Misconfigurations") or []):
                if m.get("Status", "FAIL") != "FAIL":
                    continue
                cid = f"trivy:{m.get('ID') or m.get('AVDID') or 'unknown'}"
                sev, unmapped = map_severity(m.get("Severity"))
                out.append(make_finding(cid, ref, same(m.get("Title") or cid), sev, unmapped,
                                        Evidence(file=rel, json_path=f"{base}.Misconfigurations[{k}]"),
                                        Source.TRIVY, same(m.get("Resolution") or "")))
            for k, v in enumerate(result.get("Vulnerabilities") or []):
                vid = v.get("VulnerabilityID") or "unknown"
                sev, unmapped = map_severity(v.get("Severity"))
                title = f"{vid} in {v.get('PkgName', '?')} {v.get('InstalledVersion', '')}".strip()
                fixed = v.get("FixedVersion")
                fix = (Localized(de=f"Paket auf Version {fixed} aktualisieren.", en=f"Update the package to {fixed}.")
                       if fixed else Localized(de="Keine korrigierte Version verfügbar.", en="No fixed version available."))
                out.append(make_finding(f"trivy:{vid}", ref, same(title), sev, unmapped,
                                        Evidence(file=rel, json_path=f"{base}.Vulnerabilities[{k}]"), Source.TRIVY, fix))
            for k, s in enumerate(result.get("Secrets") or []):
                cid = f"trivy:secret:{s.get('RuleID') or 'unknown'}"
                sev, unmapped = map_severity(s.get("Severity"))
                out.append(make_finding(cid, ref, same(s.get("Title") or cid), sev, unmapped,
                                        Evidence(file=rel, json_path=f"{base}.Secrets[{k}]"), Source.TRIVY,
                                        Localized(de="Zugangsdaten aus dem Image entfernen und rotieren.",
                                                  en="Remove the credential from the image and rotate it.")))
    return out
```

`src/k8s_baseline_audit/analyze/scanners/kubescape.py`:

```python
from __future__ import annotations

from ...models import Evidence, Finding, Localized, ResourceRef, Severity, Source
from .common import ScannerFormatError, make_finding, same


def _severity(score) -> tuple[Severity, bool]:
    if not isinstance(score, int | float):
        return Severity.LOW, True
    if score >= 9:
        return Severity.CRITICAL, False
    if score >= 7:
        return Severity.HIGH, False
    if score >= 4:
        return Severity.MEDIUM, False
    return Severity.LOW, False


def _ref(resource_id: str, obj: dict) -> ResourceRef:
    md = obj.get("metadata") or {}
    if obj.get("kind") and md.get("name"):
        return ResourceRef(kind=obj["kind"], name=md["name"], namespace=md.get("namespace") or None)
    parts = resource_id.strip("/").split("/")
    ns, kind, name = (["", "Unknown", resource_id] + parts)[-3:]
    return ResourceRef(kind=kind, name=name, namespace=ns or None)


def parse(doc: dict, rel: str) -> list[Finding]:
    results = doc.get("results")
    if not isinstance(results, list):
        raise ScannerFormatError(f"{rel}: expected top-level 'results' list (kubescape JSON)")
    objects = {r.get("resourceID"): (r.get("object") or {}) for r in doc.get("resources") or []}
    meta = (doc.get("summaryDetails") or {}).get("controls") or {}
    out: list[Finding] = []
    for i, res in enumerate(results):
        rid = res.get("resourceID") or ""
        ref = _ref(rid, objects.get(rid) or {})
        for k, control in enumerate(res.get("controls") or []):
            if ((control.get("status") or {}).get("status") or "").lower() != "failed":
                continue
            raw_id = control.get("controlID") or "unknown"
            info = meta.get(raw_id) or {}
            sev, unmapped = _severity(info.get("scoreFactor"))
            title = control.get("name") or info.get("name") or raw_id
            fix = Localized(de=f"Siehe kubescape-Dokumentation zu {raw_id}.", en=f"See the kubescape documentation for {raw_id}.")
            out.append(make_finding(f"kubescape:{raw_id}", ref, same(title), sev, unmapped,
                                    Evidence(file=rel, json_path=f"$.results[{i}].controls[{k}]"), Source.KUBESCAPE, fix))
    return out
```

`src/k8s_baseline_audit/analyze/scanners/kube_bench.py`:

```python
from __future__ import annotations

from ...models import Evidence, Finding, ResourceRef, Severity, Source
from .common import ScannerFormatError, make_finding, same

STATUS_SEVERITY = {"FAIL": Severity.MEDIUM, "WARN": Severity.LOW}


def parse(doc: dict, rel: str, node: str) -> list[Finding]:
    controls = doc.get("Controls")
    if not isinstance(controls, list):
        raise ScannerFormatError(f"{rel}: expected top-level 'Controls' list (kube-bench JSON)")
    ref = ResourceRef(kind="Node", name=node)
    out: list[Finding] = []
    for i, control in enumerate(controls):
        for j, test in enumerate(control.get("tests") or []):
            for k, result in enumerate(test.get("results") or []):
                severity = STATUS_SEVERITY.get(result.get("status"))
                if severity is None:
                    continue
                cid = f"kube-bench:{result.get('test_number') or 'unknown'}"
                out.append(make_finding(cid, ref, same(result.get("test_desc") or cid), severity, True,
                                        Evidence(file=rel, json_path=f"$.Controls[{i}].tests[{j}].results[{k}]"),
                                        Source.KUBE_BENCH, same(result.get("remediation") or "")))
    return out
```

`src/k8s_baseline_audit/analyze/scanners/__init__.py`:

```python
"""Parsers that turn scanner JSON into the common finding model."""

from __future__ import annotations

from ...models import Finding
from . import kube_bench, kubescape, trivy
from .common import ScannerFormatError


def parse_scanner_file(rel: str, doc: dict) -> list[Finding]:
    name = rel.removeprefix("scanners/")
    if name == "trivy.json":
        return trivy.parse(doc, rel)
    if name == "kubescape.json":
        return kubescape.parse(doc, rel)
    if name.startswith("kube-bench-") and name.endswith(".json"):
        node = name.removeprefix("kube-bench-").removesuffix(".json")
        return kube_bench.parse(doc, rel, node or "unknown")
    raise ScannerFormatError(f"unknown scanner file: {rel}")


__all__ = ["ScannerFormatError", "parse_scanner_file"]
```

Run: `pdm run pytest tests/test_scanner_parsers.py -v` → all passed (adapt to fixtures as described in Step 6 if needed).

- [ ] **Step 9: Verify the alias table against the fixtures**

```bash
jq -r '.Resources[].Results[]?.Misconfigurations[]? | "\(.ID)\t\(.Title)"' tests/fixtures/scanners/trivy.json | sort -u
jq -r '.results[].controls[] | select(.status.status=="failed") | "\(.controlID)\t\(.name)"' tests/fixtures/scanners/kubescape.json | sort -u
```

For each alias in the table in Step 11, confirm the ID's title means the same thing as the built-in check. Delete any alias whose title does not match; never add one you have not seen in this output.

- [ ] **Step 10: Write the failing dedupe test**

`tests/test_dedupe.py`:

```python
from k8s_baseline_audit.analyze.dedupe import dedupe, pod_owner_map
from k8s_baseline_audit.models import Evidence, Finding, Localized, ResourceRef, Severity, Source, finding_id

L = Localized(de="x", en="x")


def f(check_id, ref, source=Source.BUILTIN, reqs=(), file="resources/pods.json"):
    return Finding(id=finding_id(check_id, ref), check_id=check_id, title=L, severity=Severity.HIGH,
                   resources=[ref], evidence=[Evidence(file=file, json_path="$")], sources=[source],
                   requirements=list(reqs), remediation=L)


PODS = [
    {"metadata": {"name": "web-7d9c-abcde", "namespace": "prod", "labels": {"pod-template-hash": "7d9c"},
                  "ownerReferences": [{"kind": "ReplicaSet", "name": "web-7d9c"}]}},
    {"metadata": {"name": "db-0", "namespace": "prod", "ownerReferences": [{"kind": "StatefulSet", "name": "db"}]}},
    {"metadata": {"name": "solo", "namespace": "prod"}},
]


def test_owner_map():
    assert pod_owner_map(PODS) == {
        ("prod", "web-7d9c-abcde"): ("prod", "web"),
        ("prod", "db-0"): ("prod", "db"),
        ("prod", "solo"): ("prod", "solo"),
    }


def test_scanner_finding_merges_into_builtin_via_owner():
    builtin = f("workload.privileged", ResourceRef(kind="Pod", namespace="prod", name="web-7d9c-abcde"), reqs=["APP.4.4.A9"])
    scan = f("trivy:KSV017", ResourceRef(kind="Deployment", namespace="prod", name="web"), Source.TRIVY,
             reqs=["SYS.1.6.A2"], file="scanners/trivy.json")
    out = dedupe([builtin], [scan], PODS)
    assert len(out) == 1
    merged = out[0]
    assert merged.id == builtin.id
    assert merged.sources == [Source.BUILTIN, Source.TRIVY]
    assert [e.file for e in merged.evidence] == ["resources/pods.json", "scanners/trivy.json"]
    assert merged.requirements == ["APP.4.4.A9", "SYS.1.6.A2"]


def test_two_scanners_without_builtin_collapse_into_one():
    ref = ResourceRef(kind="Deployment", namespace="prod", name="api")
    a = f("trivy:KSV017", ref, Source.TRIVY, file="scanners/trivy.json")
    b = f("kubescape:C-0057", ref, Source.KUBESCAPE, file="scanners/kubescape.json")
    out = dedupe([], [a, b], PODS)
    assert len(out) == 1
    assert out[0].sources == [Source.KUBESCAPE, Source.TRIVY]


def test_unaliased_findings_are_kept_and_duplicates_collapse():
    ref = ResourceRef(kind="Pod", namespace="prod", name="solo")
    cve1 = f("trivy:CVE-1", ref, Source.TRIVY, file="scanners/trivy.json")
    cve1_again = cve1.model_copy(update={"evidence": [Evidence(file="scanners/trivy.json", json_path="$.b")]})
    out = dedupe([], [cve1, cve1_again], PODS)
    assert len(out) == 1
    assert len(out[0].evidence) == 2


def test_inputs_are_not_mutated():
    builtin = f("workload.privileged", ResourceRef(kind="Pod", namespace="prod", name="solo"))
    scan = f("trivy:KSV017", ResourceRef(kind="Pod", namespace="prod", name="solo"), Source.TRIVY)
    dedupe([builtin], [scan], PODS)
    assert builtin.sources == [Source.BUILTIN]
```

- [ ] **Step 11: Implement dedupe**

`src/k8s_baseline_audit/analyze/dedupe.py`:

```python
"""Merge findings that different sources report for the same issue and workload."""

from __future__ import annotations

from ..mapping.schema import requirement_sort_key
from ..models import Finding, ResourceRef

# scanner check id -> built-in check id. Verified against captured fixtures (Task 11 Step 9).
ALIASES: dict[str, str] = {
    "trivy:KSV017": "workload.privileged",
    "trivy:KSV001": "workload.privilege_escalation",
    "trivy:KSV012": "workload.run_as_non_root_missing",
    "trivy:KSV014": "workload.writable_root_fs",
    "trivy:KSV008": "workload.host_namespaces",
    "trivy:KSV009": "workload.host_namespaces",
    "trivy:KSV010": "workload.host_namespaces",
    "trivy:KSV023": "workload.host_path",
    "kubescape:C-0057": "workload.privileged",
    "kubescape:C-0016": "workload.privilege_escalation",
    "kubescape:C-0013": "workload.run_as_non_root_missing",
    "kubescape:C-0017": "workload.writable_root_fs",
    "kubescape:C-0038": "workload.host_namespaces",
    "kubescape:C-0041": "workload.host_namespaces",
    "kubescape:C-0048": "workload.host_path",
}
OWNER_KINDS = frozenset({"ReplicaSet", "StatefulSet", "DaemonSet", "Job"})

Key = tuple[str | None, str]


def pod_owner_map(pods: list[dict]) -> dict[Key, Key]:
    out: dict[Key, Key] = {}
    for p in pods:
        md = p.get("metadata") or {}
        ns, name = md.get("namespace"), md.get("name") or "?"
        owner = (md.get("ownerReferences") or [{}])[0] or {}
        kind, owner_name = owner.get("kind"), owner.get("name")
        workload = name
        if kind in OWNER_KINDS and owner_name:
            workload = owner_name
            template_hash = (md.get("labels") or {}).get("pod-template-hash")
            if kind == "ReplicaSet" and template_hash:
                workload = owner_name.removesuffix(f"-{template_hash}")
        out[(ns, name)] = (ns, workload)
    return out


def _workload(ref: ResourceRef, owners: dict[Key, Key]) -> Key:
    if ref.kind == "Pod":
        return owners.get((ref.namespace, ref.name), (ref.namespace, ref.name))
    return (ref.namespace, ref.name)


def _merge(target: Finding, other: Finding) -> None:
    target.sources = sorted(set(target.sources) | set(other.sources), key=lambda s: s.value)
    target.evidence = sorted(set(target.evidence) | set(other.evidence), key=lambda e: (e.file, e.json_path))
    target.requirements = sorted(set(target.requirements) | set(other.requirements), key=requirement_sort_key)


def dedupe(builtin: list[Finding], scanner: list[Finding], pods: list[dict]) -> list[Finding]:
    owners = pod_owner_map(pods)
    result = [f.model_copy(deep=True) for f in builtin]
    index: dict[tuple[str, str | None, str], Finding] = {}
    for f in result:
        index.setdefault((f.check_id, *_workload(f.resources[0], owners)), f)
    for s in scanner:
        s = s.model_copy(deep=True)
        workload = _workload(s.resources[0], owners)
        key = (ALIASES.get(s.check_id, s.check_id), *workload)
        match = index.get(key)
        if match is None:
            result.append(s)
            index[key] = s
        else:
            _merge(match, s)
    return result
```

- [ ] **Step 12: Run tests**

Run: `pdm run pytest -v && pdm run ruff check .`
Expected: all passed, ruff clean.

- [ ] **Step 13: Commit**

```bash
git add src/k8s_baseline_audit/collect/sanitize.py src/k8s_baseline_audit/analyze examples tests
git commit -m "feat: scanner sanitizers, parsers for trivy/kubescape/kube-bench and dedupe"
```

---
### Task 12: Coverage engine and analysis pipeline

**Files:**
- Create: `src/k8s_baseline_audit/analyze/coverage.py`, `src/k8s_baseline_audit/analyze/pipeline.py`
- Modify: `tests/conftest.py` (add `sample_bundle` fixture)
- Test: `tests/test_coverage.py`, `tests/test_pipeline.py`

**Interfaces:**
- Consumes: `Bundle` (Task 4), `Mapping`, `CoverageType` (Task 5), `all_checks`, `CheckContext`, `AnalyzerConfig`, `ManualCheckNeeded`, `Hit`, `Check` (Task 6), `parse_scanner_file` (Task 11), `dedupe` (Task 11).
- Produces:
  - `CheckRun(check_id: str, state: Literal["ran", "not_run", "manual"], reason: str | None = None)` (frozen dataclass).
  - `compute_coverage(mapping: Mapping, findings: list[Finding], runs: list[CheckRun]) -> list[CoverageEntry]`.
  - `AnalysisResult(meta: dict, findings: list[Finding], runs: list[CheckRun], coverage: list[CoverageEntry])`.
  - `load_resources(bundle) -> dict[str, list[dict]]`; `analyze(bundle, mapping, config, tool_version: str) -> AnalysisResult`; `write_analysis(result, out_dir: Path) -> tuple[Path, Path]`.
  - `findings.json` = `{"meta": ..., "findings": [...], "check_runs": [...]}`; `coverage.json` = `{"coverage": [...]}`.

- [ ] **Step 1: Write the failing coverage test**

`tests/test_coverage.py`:

```python
import yaml

from k8s_baseline_audit.analyze.coverage import compute_coverage
from k8s_baseline_audit.analyze.pipeline import CheckRun
from k8s_baseline_audit.mapping.schema import load_mapping_file
from k8s_baseline_audit.models import CoverageStatus, Finding, Localized, ResourceRef, Severity, Source

SRC = {"document": "d", "edition": "2023", "url": "https://www.bsi.bund.de/x", "page": 1}
L = {"de": "x", "en": "x"}


def req(n, ctype, checks=()):
    return {"id": f"APP.4.4.A{n}", "module": "APP.4.4", "level": "basic", "title": L, "summary": L,
            "source": SRC, "coverage_type": ctype, "checks": list(checks), "questions": [L]}


def mapping(tmp_path):
    doc = {"name": "t", "framework": "f", "edition": "2023", "modules": ["APP.4.4"], "requirements": [
        req(1, "organizational"),
        req(2, "manual"),
        req(3, "automatic", ["a"]),
        req(4, "automatic", ["b"]),
        req(5, "automatic", ["c", "a"]),
        req(6, "partial", ["a"]),
        req(7, "automatic", ["m"]),
        req(8, "automatic", ["c", "hit"]),
    ]}
    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(doc))
    return load_mapping_file(p)


def finding(fid, reqs):
    ref = ResourceRef(kind="Pod", name="p", namespace="n")
    lz = Localized(de="x", en="x")
    return Finding(id=fid, check_id="hit", title=lz, severity=Severity.HIGH, resources=[ref], evidence=[],
                   sources=[Source.BUILTIN], requirements=reqs, remediation=lz)


def test_statuses(tmp_path):
    runs = [
        CheckRun("a", "ran"),
        CheckRun("b", "ran"),
        CheckRun("c", "not_run", "pods: forbidden"),
        CheckRun("m", "manual", "static pod not visible"),
        CheckRun("hit", "ran"),
    ]
    cov = {c.requirement_id: c for c in compute_coverage(mapping(tmp_path), [finding("f1", ["APP.4.4.A8"])], runs)}
    assert cov["APP.4.4.A1"].status == CoverageStatus.ORGANIZATIONAL
    assert cov["APP.4.4.A2"].status == CoverageStatus.MANUAL
    assert cov["APP.4.4.A3"].status == CoverageStatus.NO_DEVIATION
    assert cov["APP.4.4.A5"].status == CoverageStatus.NOT_CHECKED
    assert cov["APP.4.4.A5"].reasons == ["c: pods: forbidden"]
    assert cov["APP.4.4.A6"].status == CoverageStatus.PARTIAL
    assert cov["APP.4.4.A7"].status == CoverageStatus.MANUAL
    assert cov["APP.4.4.A7"].reasons == ["m: static pod not visible"]
    assert cov["APP.4.4.A8"].status == CoverageStatus.DEVIATION
    assert cov["APP.4.4.A8"].finding_ids == ["f1"]
    assert cov["APP.4.4.A8"].reasons == ["c: pods: forbidden"]


def test_unknown_check_is_not_checked(tmp_path):
    cov = compute_coverage(mapping(tmp_path), [], [])
    by_id = {c.requirement_id: c for c in cov}
    assert by_id["APP.4.4.A3"].status == CoverageStatus.NOT_CHECKED
    assert by_id["APP.4.4.A3"].reasons == ["a: check did not run"]
    assert [c.requirement_id for c in cov] == [f"APP.4.4.A{n}" for n in range(1, 9)]
```

- [ ] **Step 2: Add the shared sample bundle fixture**

Append to `tests/conftest.py`:

```python
import pytest  # noqa: E402

from k8s_baseline_audit.bundle import dump_json, write_bundle  # noqa: E402
from k8s_baseline_audit.collect.redact import REDACTED  # noqa: E402

SAMPLE_PODS = {
    "items": [
        {
            "metadata": {"name": "insecure", "namespace": "default"},
            "spec": {
                "hostNetwork": True,
                "serviceAccountName": "default",
                "containers": [
                    {
                        "name": "app",
                        "image": "nginx:latest",
                        "securityContext": {"privileged": True, "runAsUser": 0},
                        "env": [{"name": "DB_PASSWORD", "value": REDACTED}],
                    }
                ],
            },
        }
    ]
}


@pytest.fixture
def sample_bundle(tmp_path):
    files = {
        "resources/pods.json": dump_json(SAMPLE_PODS),
        "resources/namespaces.json": dump_json({"items": [{"metadata": {"name": "default"}}]}),
        "resources/serviceaccounts.json": dump_json({"items": []}),
        "resources/roles.json": dump_json({"items": []}),
        "resources/clusterroles.json": dump_json({"items": []}),
        "resources/rolebindings.json": dump_json({"items": []}),
        "resources/clusterrolebindings.json": dump_json({"items": []}),
        "resources/networkpolicies.json": dump_json({"items": []}),
        "resources/nodes.json": dump_json({"items": []}),
        "resources/version.json": dump_json({"serverVersion": {"major": "1", "minor": "35"}}),
        "preflight.json": dump_json({"secrets": False}),
        "errors.json": dump_json({"errors": [{"resource": "secrets", "reason": "forbidden: kubectl auth can-i list returned no"}]}),
    }
    manifest = {
        "producer": "collector",
        "created_at": "2026-09-30T10:00:00Z",
        "cluster": {"context": "kind-test", "server": "https://127.0.0.1:6443"},
        "tool": {"name": "k8s-baseline-audit", "version": "0.1.0"},
        "commands": [],
        "scanners": {"trivy": {"status": "missing"}},
    }
    return write_bundle(tmp_path / "bundle", files, manifest)

```

- [ ] **Step 3: Write the failing pipeline test**

`tests/test_pipeline.py`:

```python
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
    assert {"workload.privileged", "workload.run_as_root", "secrets.credential_literal_env",
            "identity.default_service_account", "images.latest_tag"} <= check_ids
    runs = {r.check_id: r for r in result.runs}
    assert runs["identity.long_lived_token_secret"].state == "not_run"
    assert "forbidden" in runs["identity.long_lived_token_secret"].reason
    assert runs["control_plane.encryption_at_rest"].state == "manual"
    assert runs["images.registry_not_allowed"].state == "manual"
    assert result.meta["bundle"]["provenance_verified"] is True
    assert result.meta["mapping"]["name"] == "kompendium-2023"
    assert result.meta["config"]["as_of"] == "2026-09-30"
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks)


def test_every_requirement_has_coverage(sample_bundle):
    result = _run(sample_bundle)
    assert [c.requirement_id for c in result.coverage] == [r.id for r in load_mapping().requirements]
    deviation_ids = {fid for c in result.coverage if c.status == CoverageStatus.DEVIATION for fid in c.finding_ids}
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
    files["scanners/trivy.json"] = dump_json({"Resources": [{"Namespace": "default", "Kind": "Pod", "Name": "insecure",
        "Results": [{"Misconfigurations": [{"ID": "KSV017", "Title": "Privileged", "Severity": "HIGH", "Status": "FAIL"}]}]}]})
    manifest = {k: v for k, v in b.manifest.items() if k not in ("files", "schema")}
    root = write_bundle(tmp_path / "with-scanner", files, manifest)
    result = _run(root)
    priv = [f for f in result.findings if f.check_id == "workload.privileged"]
    assert len(priv) == 1
    assert [s.value for s in priv[0].sources] == ["built-in", "trivy"]
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `pdm run pytest tests/test_coverage.py tests/test_pipeline.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'k8s_baseline_audit.analyze.coverage'`

- [ ] **Step 5: Implement coverage**

`src/k8s_baseline_audit/analyze/coverage.py`:

```python
"""Derive one coverage status per requirement. Never claims fulfilment."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..mapping.schema import CoverageType, Mapping
from ..models import CoverageEntry, CoverageStatus, Finding

if TYPE_CHECKING:
    from .pipeline import CheckRun


def compute_coverage(mapping: Mapping, findings: list[Finding], runs: list[CheckRun]) -> list[CoverageEntry]:
    by_check = {r.check_id: r for r in runs}
    entries: list[CoverageEntry] = []
    for req in mapping.requirements:
        if req.coverage_type == CoverageType.ORGANIZATIONAL:
            entries.append(CoverageEntry(requirement_id=req.id, status=CoverageStatus.ORGANIZATIONAL))
            continue
        if req.coverage_type == CoverageType.MANUAL:
            entries.append(CoverageEntry(requirement_id=req.id, status=CoverageStatus.MANUAL))
            continue
        finding_ids = sorted(f.id for f in findings if req.id in f.requirements)
        not_run, manual = [], []
        for cid in req.checks:
            run = by_check.get(cid)
            if run is None:
                not_run.append(f"{cid}: check did not run")
            elif run.state == "not_run":
                not_run.append(f"{cid}: {run.reason}")
            elif run.state == "manual":
                manual.append(f"{cid}: {run.reason}")
        reasons = sorted(not_run + manual)
        if finding_ids:
            status = CoverageStatus.DEVIATION
        elif not_run:
            status = CoverageStatus.NOT_CHECKED
        elif manual:
            status = CoverageStatus.MANUAL
        elif req.coverage_type == CoverageType.PARTIAL:
            status = CoverageStatus.PARTIAL
        else:
            status = CoverageStatus.NO_DEVIATION
        entries.append(CoverageEntry(requirement_id=req.id, status=status, finding_ids=finding_ids, reasons=reasons))
    return entries
```

- [ ] **Step 6: Implement the pipeline**

`src/k8s_baseline_audit/analyze/pipeline.py`:

```python
"""Deterministic analysis: bundle -> findings.json + coverage.json."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from ..bundle import Bundle, dump_json
from ..mapping.schema import Mapping
from ..models import CoverageEntry, Finding, Source, finding_id
from .checks import all_checks
from .checks.base import AnalyzerConfig, Check, CheckContext, Hit, ManualCheckNeeded
from .coverage import compute_coverage
from .dedupe import dedupe
from .scanners import parse_scanner_file

RunState = Literal["ran", "not_run", "manual"]


@dataclass(frozen=True)
class CheckRun:
    check_id: str
    state: RunState
    reason: str | None = None


@dataclass(frozen=True)
class AnalysisResult:
    meta: dict
    findings: list[Finding]
    runs: list[CheckRun]
    coverage: list[CoverageEntry]


def load_resources(bundle: Bundle) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for rel in bundle.files_under("resources/"):
        kind = rel.removeprefix("resources/").removesuffix(".json")
        doc = bundle.read_json(rel)
        out[kind] = doc["items"] if isinstance(doc, dict) and isinstance(doc.get("items"), list) else [doc]
    return out


def _to_findings(check: Check, hits: list[Hit], mapping: Mapping) -> list[Finding]:
    grouped: dict[str, list[Hit]] = {}
    for hit in hits:
        grouped.setdefault(hit.resource.key(), []).append(hit)
    findings = []
    for key in sorted(grouped):
        group = grouped[key]
        ref = group[0].resource
        findings.append(
            Finding(
                id=finding_id(check.id, ref),
                check_id=check.id,
                title=check.title,
                severity=check.severity,
                resources=[ref],
                evidence=sorted({h.evidence for h in group}, key=lambda e: (e.file, e.json_path)),
                sources=[Source.BUILTIN],
                requirements=mapping.requirements_for_check(check.id),
                remediation=check.remediation,
            )
        )
    return findings


def _run_checks(resources, config, mapping, errors) -> tuple[list[Finding], list[CheckRun]]:
    context = CheckContext(resources=resources, config=config)
    findings: list[Finding] = []
    runs: list[CheckRun] = []
    for chk in all_checks():
        missing = [k for k in chk.requires if k not in resources]
        if missing:
            reason = "; ".join(f"{k}: {errors.get(k, 'not collected')}" for k in missing)
            runs.append(CheckRun(chk.id, "not_run", reason))
            continue
        try:
            hits = chk.fn(context)
        except ManualCheckNeeded as exc:
            runs.append(CheckRun(chk.id, "manual", exc.reason))
            continue
        runs.append(CheckRun(chk.id, "ran"))
        findings.extend(_to_findings(chk, hits, mapping))
    return findings, runs


def analyze(bundle: Bundle, mapping: Mapping, config: AnalyzerConfig, tool_version: str) -> AnalysisResult:
    resources = load_resources(bundle)
    errors = {e.get("resource"): e.get("reason") for e in bundle.errors}
    builtin, runs = _run_checks(resources, config, mapping, errors)

    scanner: list[Finding] = []
    for rel in bundle.files_under("scanners/"):
        for f in parse_scanner_file(rel, bundle.read_json(rel)):
            f.requirements = mapping.requirements_for_check(f.check_id)
            scanner.append(f)

    findings = dedupe(builtin, scanner, resources.get("pods", []))
    findings.sort(key=lambda f: (f.severity.rank, f.check_id, f.id))
    coverage = compute_coverage(mapping, findings, runs)
    manifest = bundle.manifest
    meta = {
        "tool": {"name": "k8s-baseline-audit", "version": tool_version},
        "mapping": {"name": mapping.name, "framework": mapping.framework, "edition": mapping.edition,
                    "modules": list(mapping.modules)},
        "bundle": {
            "cluster": manifest.get("cluster") or {},
            "created_at": manifest.get("created_at"),
            "producer": manifest.get("producer"),
            "provenance_verified": bundle.provenance_verified,
            "manifest_sha256": bundle.manifest_sha256(),
            "scanners": manifest.get("scanners") or {},
        },
        "config": {
            "as_of": config.as_of.isoformat(),
            "registry_allowlist": list(config.registry_allowlist),
            "admin_subject_allowlist": list(config.admin_subject_allowlist),
            "anonymous_binding_allowlist": list(config.anonymous_binding_allowlist),
        },
    }
    return AnalysisResult(meta, findings, sorted(runs, key=lambda r: r.check_id), coverage)


def write_analysis(result: AnalysisResult, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_path = out_dir / "findings.json"
    coverage_path = out_dir / "coverage.json"
    findings_path.write_bytes(
        dump_json(
            {
                "meta": result.meta,
                "findings": [f.model_dump(mode="json") for f in result.findings],
                "check_runs": [asdict(r) for r in result.runs],
            }
        )
    )
    coverage_path.write_bytes(dump_json({"coverage": [c.model_dump(mode="json") for c in result.coverage]}))
    return findings_path, coverage_path
```

- [ ] **Step 7: Run tests**

Run: `pdm run pytest -v && pdm run ruff check .`
Expected: all passed, ruff clean.

- [ ] **Step 8: Commit**

```bash
git add src/k8s_baseline_audit/analyze tests
git commit -m "feat: coverage engine and deterministic analysis pipeline"
```

---

### Task 13: Scanner execution during live collection

**Files:**
- Create: `src/k8s_baseline_audit/collect/scanners.py`
- Test: `tests/test_scanner_run.py`

**Interfaces:**
- Consumes: `sanitize_kubescape`, `sanitize_trivy` (Task 11), `dump_json` (Task 4).
- Produces: `ScannerPlan(kubescape: bool = True, trivy: bool = True, kube_bench_results: tuple[tuple[str, Path], ...] = ())`; `ScannerOutput(files: dict[str, bytes], status: dict[str, dict], commands: list[dict])`; `kubescape_argv(out: Path, context: str | None) -> list[str]`; `trivy_argv(out: Path, context: str | None) -> list[str]`; `run_scanners(plan, context, workdir: Path, which=shutil.which, run=_default_run) -> ScannerOutput`. `run(argv: list[str], timeout: float) -> tuple[int, str, str]`.
- Output feeds `CollectOptions(extra_files=..., scanner_status=..., extra_commands=...)` (Task 4) in the CLI (Task 15).

- [ ] **Step 1: Write the failing test**

`tests/test_scanner_run.py`:

```python
import json

from k8s_baseline_audit.collect.scanners import ScannerPlan, kubescape_argv, run_scanners, trivy_argv


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
                fh.write(self.outputs[tool] if isinstance(self.outputs[tool], str) else json.dumps(self.outputs[tool]))
        return code, "", "scanner exploded" if code else ""


def installed(name):
    return f"/usr/local/bin/{name}"


def test_trivy_never_starts_node_collector(tmp_path):
    argv = trivy_argv(tmp_path / "t.json", "kind-x")
    assert "--disable-node-collector" in argv
    assert argv[:2] == ["trivy", "k8s"]
    assert "kind-x" in argv
    assert "--kube-context" in kubescape_argv(tmp_path / "k.json", "kind-x")


def test_outputs_are_sanitized_and_statuses_recorded(tmp_path):
    ks = {"resources": [{"resourceID": "r", "object": {"kind": "Pod", "metadata": {"name": "p"},
                                                          "spec": {"env": "hunter2-demo"}}}], "results": []}
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pdm run pytest tests/test_scanner_run.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

Use the flag names recorded in `tests/fixtures/scanners/VERSIONS` (Task 11 Step 2). The code below assumes `--disable-node-collector` and `--context` for trivy and `--kube-context` for kubescape.

`src/k8s_baseline_audit/collect/scanners.py`:

```python
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
from .sanitize import sanitize_kubescape, sanitize_trivy

SCAN_TIMEOUT = 1800
Run = Callable[[list[str], float], tuple[int, str, str]]


def _default_run(argv: list[str], timeout: float) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
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
    argv = ["trivy", "k8s", "--report", "all", "--format", "json", "--output", str(out), "--disable-node-collector"]
    return argv + (["--context", context] if context else [])


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-") or "node"


SCANNERS = (
    ("kubescape", kubescape_argv, ["kubescape", "version"], sanitize_kubescape),
    ("trivy", trivy_argv, ["trivy", "--version"], sanitize_trivy),
)


def run_scanners(plan: ScannerPlan, context: str | None, workdir: Path,
                 which: Callable[[str], str | None] = shutil.which, run: Run = _default_run) -> ScannerOutput:
    out = ScannerOutput()
    enabled = {"kubescape": plan.kubescape, "trivy": plan.trivy}
    for name, argv_fn, version_argv, sanitize in SCANNERS:
        if not enabled[name]:
            out.status[name] = {"status": "disabled"}
            continue
        if which(name) is None:
            out.status[name] = {"status": "missing"}
            continue
        _, version_out, _ = run(version_argv, 30)
        version = (version_out.strip().splitlines() or ["unknown"])[0]
        target = workdir / f"{name}.json"
        argv = argv_fn(target, context)
        code, _, err = run(argv, SCAN_TIMEOUT)
        out.commands.append({"argv": argv, "exit_code": code})
        if code != 0 or not target.is_file():
            out.status[name] = {"status": "failed", "version": version, "error": (err.strip() or f"exit {code}")[-500:]}
            continue
        try:
            doc = json.loads(target.read_text())
        except json.JSONDecodeError:
            out.status[name] = {"status": "failed", "version": version, "error": "scanner wrote invalid JSON"}
            continue
        out.files[f"scanners/{name}.json"] = dump_json(sanitize(doc))
        out.status[name] = {"status": "ok", "version": version}
    nodes = []
    for node, path in plan.kube_bench_results:
        slug = _slug(node)
        doc = json.loads(Path(path).read_text())
        out.files[f"scanners/kube-bench-{slug}.json"] = dump_json(doc)
        nodes.append(slug)
    if nodes:
        out.status["kube-bench"] = {"status": "imported", "nodes": nodes}
    return out
```

- [ ] **Step 4: Run tests**

Run: `pdm run pytest tests/test_scanner_run.py -v`
Expected: all passed.

- [ ] **Step 5: Commit**

```bash
git add src/k8s_baseline_audit/collect/scanners.py tests/test_scanner_run.py
git commit -m "feat: optional kubescape/trivy runs with sanitized output and kube-bench import"
```

---
### Task 14: Bilingual report renderer

**Files:**
- Create: `src/k8s_baseline_audit/report/__init__.py` (empty), `src/k8s_baseline_audit/report/labels.py`, `src/k8s_baseline_audit/report/render.py`, `src/k8s_baseline_audit/report/templates/report.md.j2`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `findings.json`, `coverage.json` (Task 12), `Bundle` (Task 4), `load_mapping` (Task 5), models (Task 1).
- Produces:
  - `LABELS: dict[str, dict]` keyed `"de"`, `"en"`.
  - `PriorityNote(rank: int >= 1, reason: str)`, `Narrative(language: "de"|"en", summary: str, priorities: dict[str, PriorityNote] = {}, fix_notes: dict[str, str] = {})`, `NarrativeError(ValueError)`.
  - `validate_narratives(narratives: dict[str, Narrative], finding_ids: set[str]) -> None`.
  - `ReportInput(meta, findings, runs, coverage, mapping, manifest, preflight)`; `load_report_input(analysis_dir: Path, bundle: Bundle) -> ReportInput`.
  - `render_reports(inp: ReportInput, narratives: dict[str, Narrative] | None, out_dir: Path) -> dict[str, Path]` writing `report.de.md`, `report.en.md`.
  - `md(text) -> str` Markdown table escaper; `is_vulnerability(f: Finding) -> bool`.

- [ ] **Step 1: Write the failing test**

`tests/test_report.py`:

```python
import re
from datetime import date

import pytest

from k8s_baseline_audit.analyze.checks.base import AnalyzerConfig
from k8s_baseline_audit.analyze.pipeline import analyze, write_analysis
from k8s_baseline_audit.bundle import load_bundle
from k8s_baseline_audit.mapping.schema import load_mapping
from k8s_baseline_audit.report.render import (
    Narrative,
    NarrativeError,
    PriorityNote,
    load_report_input,
    md,
    render_reports,
    validate_narratives,
)

FORBIDDEN = ("erfüllt", "fulfilled", "compliant", "konform")


@pytest.fixture
def report_input(sample_bundle, tmp_path):
    bundle = load_bundle(sample_bundle)
    result = analyze(bundle, load_mapping(), AnalyzerConfig(as_of=date(2026, 9, 30)), tool_version="0.1.0")
    write_analysis(result, tmp_path / "analysis")
    return load_report_input(tmp_path / "analysis", bundle)


def narratives(inp, rank_en=1):
    first = inp.findings[0].id
    return {
        "de": Narrative(language="de", summary="Kritische Befunde im Namespace default.",
                        priorities={first: PriorityNote(rank=1, reason="Host-Zugriff")},
                        fix_notes={first: "Zuerst beheben."}),
        "en": Narrative(language="en", summary="Critical findings in namespace default.",
                        priorities={first: PriorityNote(rank=rank_en, reason="Host access")},
                        fix_notes={first: "Fix first."}),
    }


def _ids(text):
    return re.findall(r"^\| ID \| `([0-9a-f]{16})` \|$", text, re.M)


def test_parity_between_languages(report_input, tmp_path):
    paths = render_reports(report_input, narratives(report_input), tmp_path / "out")
    de, en = paths["de"].read_text(), paths["en"].read_text()
    assert _ids(de) == _ids(en)
    assert len(_ids(de)) == len([f for f in report_input.findings if not f.check_id.startswith("trivy:CVE-")])
    rows = r"^\| (APP\.4\.4|SYS\.1\.6)\.A\d+ \|"
    assert len(re.findall(rows, de, re.M)) == len(re.findall(rows, en, re.M)) == len(report_input.coverage)
    assert de.count("### ") == en.count("### ")


def test_report_never_claims_fulfilment(report_input, tmp_path):
    paths = render_reports(report_input, narratives(report_input), tmp_path / "out")
    for p in paths.values():
        text = p.read_text().lower()
        for word in FORBIDDEN:
            assert word not in text, (p.name, word)


def test_ai_sections_are_labeled_and_missing_narrative_is_stated(report_input, tmp_path):
    with_n = render_reports(report_input, narratives(report_input), tmp_path / "a")
    assert "KI-generiert" in with_n["de"].read_text()
    assert "AI-generated" in with_n["en"].read_text()
    without = render_reports(report_input, None, tmp_path / "b")
    assert "Keine Management-Zusammenfassung erzeugt" in without["de"].read_text()
    assert "No management summary generated" in without["en"].read_text()


def test_cover_page_and_appendix(report_input, tmp_path):
    text = render_reports(report_input, None, tmp_path / "out")["en"].read_text()
    assert report_input.meta["bundle"]["manifest_sha256"] in text
    assert "no certification" in text.lower()
    assert "secrets" in text  # forbidden resource listed under not checked / preflight
    assert "resources/pods.json" in text  # evidence index


def test_narrative_validation(report_input):
    ids = {f.id for f in report_input.findings}
    validate_narratives(narratives(report_input), ids)
    with pytest.raises(NarrativeError, match="priorities differ"):
        validate_narratives(narratives(report_input, rank_en=2), ids)
    with pytest.raises(NarrativeError, match="unknown finding ids"):
        validate_narratives(narratives(report_input), set())
    with pytest.raises(NarrativeError, match="both de and en"):
        validate_narratives({"de": narratives(report_input)["de"]}, ids)
    bad = narratives(report_input)
    bad["de"] = bad["de"].model_copy(update={"language": "en"})
    with pytest.raises(NarrativeError, match="declares language"):
        validate_narratives(bad, ids)


def test_md_escapes_table_breakers():
    assert md("a|b\nc") == "a\\|b c"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pdm run pytest tests/test_report.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'k8s_baseline_audit.report'`

- [ ] **Step 3: Write the labels**

`src/k8s_baseline_audit/report/labels.py`:

```python
"""All fixed report wording, per language. The template contains no prose of its own."""

LABELS: dict[str, dict] = {
    "de": {
        "title": "Kubernetes-Sicherheitsaudit",
        "disclaimer": (
            "Dieser Bericht ist keine Zertifizierung und keine Rechtsberatung. "
            "„Keine Abweichung festgestellt“ bedeutet nur, dass die automatischen Prüfungen nichts gefunden haben."
        ),
        "cluster": "Cluster", "collected": "Erhebungszeitpunkt", "bundle_hash": "Bundle-Hash (SHA-256, manifest.json)",
        "provenance": "Herkunft", "verified": "Hashes geprüft",
        "unverified": "**Herkunft nicht verifiziert** (Bundle ohne Hashes)",
        "producer": "Erzeugt durch", "framework": "Regelwerk", "modules": "Module", "tool": "Werkzeug",
        "scanners": "Scanner", "none": "keine",
        "s_summary": "1. Management-Zusammenfassung", "s_matrix": "2. Abdeckungsmatrix",
        "s_findings": "3. Befunde nach Priorität", "s_vulns": "3a. Image-Schwachstellen",
        "s_questions": "4. Fragen für manuelle und organisatorische Anforderungen", "s_appendix": "5. Anhang",
        "s_not_checked": "5.1 Nicht geprüft", "s_preflight": "5.2 Berechtigungen bei der Erhebung",
        "s_exclusions": "5.3 Konfigurierte Ausnahmen", "s_evidence": "5.4 Nachweisverzeichnis",
        "ai_label": "KI-generiert, vom Auditor zu prüfen",
        "no_summary": "Keine Management-Zusammenfassung erzeugt.",
        "col_req": "Anforderung", "col_level": "Stufe", "col_title": "Titel", "col_status": "Status",
        "col_findings": "Befunde", "col_reasons": "Begründung", "col_resource": "Ressource",
        "col_allowed": "Erlaubt", "col_file": "Datei", "col_severity": "Schweregrad",
        "severity": "Schweregrad", "priority": "Priorität", "requirements": "Anforderungen",
        "resources": "Ressourcen", "sources": "Quellen", "evidence": "Nachweise", "fix": "Maßnahme",
        "not_executed": "Die Befehle wurden nicht ausgeführt.", "unrated": "vom Scanner nicht eingestuft",
        "no_mapping": "keine BSI-Zuordnung", "no_findings": "Keine Befunde.", "no_vulns": "Keine Image-Schwachstellen gemeldet.",
        "no_questions": "Keine.", "nothing_skipped": "Alle Prüfungen wurden ausgeführt.",
        "yes": "ja", "no": "nein", "check": "Prüfung",
        "level": {"basic": "Basis", "standard": "Standard", "elevated": "Erhöht"},
        "status": {
            "no_deviation_found": "Keine Abweichung festgestellt", "deviation": "Abweichung",
            "partially_checked": "Teilweise geprüft", "manual_check_needed": "Manuelle Prüfung nötig",
            "organizational": "Organisatorisch", "not_checked": "Nicht geprüft",
        },
        "run_state": {"not_run": "nicht ausgeführt", "manual": "manuell zu prüfen"},
        "sev": {"critical": "Kritisch", "high": "Hoch", "medium": "Mittel", "low": "Niedrig"},
    },
    "en": {
        "title": "Kubernetes security audit",
        "disclaimer": (
            "This report is no certification and no legal advice. "
            "\"No deviation found\" only means the automated checks found nothing."
        ),
        "cluster": "Cluster", "collected": "Collected at", "bundle_hash": "Bundle hash (SHA-256, manifest.json)",
        "provenance": "Provenance", "verified": "hashes verified",
        "unverified": "**provenance unverified** (bundle without hashes)",
        "producer": "Produced by", "framework": "Framework", "modules": "modules", "tool": "Tool",
        "scanners": "Scanners", "none": "none",
        "s_summary": "1. Management summary", "s_matrix": "2. Coverage matrix",
        "s_findings": "3. Findings by priority", "s_vulns": "3a. Image vulnerabilities",
        "s_questions": "4. Questions for manual and organizational requirements", "s_appendix": "5. Appendix",
        "s_not_checked": "5.1 Not checked", "s_preflight": "5.2 Permissions during collection",
        "s_exclusions": "5.3 Configured exclusions", "s_evidence": "5.4 Evidence index",
        "ai_label": "AI-generated, to be reviewed by the auditor",
        "no_summary": "No management summary generated.",
        "col_req": "Requirement", "col_level": "Level", "col_title": "Title", "col_status": "Status",
        "col_findings": "Findings", "col_reasons": "Reasons", "col_resource": "Resource",
        "col_allowed": "Allowed", "col_file": "File", "col_severity": "Severity",
        "severity": "Severity", "priority": "Priority", "requirements": "Requirements",
        "resources": "Resources", "sources": "Sources", "evidence": "Evidence", "fix": "Remediation",
        "not_executed": "The commands were not executed.", "unrated": "not rated by the scanner",
        "no_mapping": "no BSI mapping", "no_findings": "No findings.", "no_vulns": "No image vulnerabilities reported.",
        "no_questions": "None.", "nothing_skipped": "All checks ran.",
        "yes": "yes", "no": "no", "check": "Check",
        "level": {"basic": "Basic", "standard": "Standard", "elevated": "Elevated"},
        "status": {
            "no_deviation_found": "No deviation found", "deviation": "Deviation",
            "partially_checked": "Partially checked", "manual_check_needed": "Manual check needed",
            "organizational": "Organizational", "not_checked": "Not checked",
        },
        "run_state": {"not_run": "not run", "manual": "manual check needed"},
        "sev": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"},
    },
}
```

- [ ] **Step 4: Write the template**

`src/k8s_baseline_audit/report/templates/report.md.j2`:

```jinja
{% set b = meta.bundle %}
# {{ L.title }} – {{ b.cluster.get("context", "?") | md }}

> {{ L.disclaimer }}

| | |
|---|---|
| {{ L.cluster }} | {{ b.cluster.get("context", "?") | md }} ({{ b.cluster.get("server", "") | md }}) |
| {{ L.collected }} | {{ b.created_at or "?" }} |
| {{ L.bundle_hash }} | `{{ b.manifest_sha256 }}` |
| {{ L.provenance }} | {% if b.provenance_verified %}{{ L.verified }}{% else %}{{ L.unverified }}{% endif %} |
| {{ L.producer }} | {{ b.producer or "?" }} |
| {{ L.framework }} | {{ meta.mapping.framework }} {{ meta.mapping.edition }}, {{ L.modules }} {{ meta.mapping.modules | join(", ") }} |
| {{ L.tool }} | {{ meta.tool.name }} {{ meta.tool.version }} |
| {{ L.scanners }} | {% for name, s in b.scanners | dictsort %}{{ name }}: {{ s.get("status") }}{% if s.get("version") %} ({{ s.get("version") | md }}){% endif %}{% if not loop.last %}, {% endif %}{% else %}{{ L.none }}{% endfor %} |

## {{ L.s_summary }}

{% if narrative %}
_{{ L.ai_label }}_

{{ narrative.summary }}
{% else %}
{{ L.no_summary }}
{% endif %}

## {{ L.s_matrix }}

| {{ L.col_req }} | {{ L.col_level }} | {{ L.col_title }} | {{ L.col_status }} | {{ L.col_findings }} | {{ L.col_reasons }} |
|---|---|---|---|---|---|
{% for c in coverage %}
{% set r = req(c.requirement_id) %}
| {{ c.requirement_id }} | {{ L.level[r.level.value] }} | {{ r.title | attr(lang) | md }} | {{ L.status[c.status.value] }} | {{ c.finding_ids | length }} | {{ c.reasons | join("; ") | md }} |
{% endfor %}

## {{ L.s_findings }}
{% for f in findings %}

### {{ loop.index }}. {{ f.title | attr(lang) | md }}

| | |
|---|---|
| ID | `{{ f.id }}` |
| {{ L.check }} | `{{ f.check_id }}` |
| {{ L.severity }} | {{ L.sev[f.severity.value] }}{% if f.severity_unmapped %} ({{ L.unrated }}){% endif %} |
| {{ L.priority }} | {% if narrative and f.id in narrative.priorities %}{{ narrative.priorities[f.id].rank }} – {{ narrative.priorities[f.id].reason | md }} (_{{ L.ai_label }}_){% else %}–{% endif %} |
| {{ L.requirements }} | {{ f.requirements | join(", ") if f.requirements else L.no_mapping }} |
| {{ L.resources }} | {% for r in f.resources %}`{{ r.key() }}`{% if not loop.last %}, {% endif %}{% endfor %} |
| {{ L.sources }} | {{ f.sources | map(attribute="value") | join(", ") }} |
| {{ L.evidence }} | {% for e in f.evidence %}`{{ e.file }}` `{{ e.json_path | md }}`{% if not loop.last %}<br>{% endif %}{% endfor %} |

**{{ L.fix }}:** {{ f.remediation | attr(lang) }}
{% if narrative and f.id in narrative.fix_notes %}

_{{ L.ai_label }}:_ {{ narrative.fix_notes[f.id] }}
{% endif %}

_{{ L.not_executed }}_
{% else %}

{{ L.no_findings }}
{% endfor %}

## {{ L.s_vulns }}

{% if vulns %}
| ID | {{ L.col_title }} | {{ L.col_severity }} | {{ L.col_resource }} |
|---|---|---|---|
{% for f in vulns %}
| `{{ f.id }}` | {{ f.title | attr(lang) | md }} | {{ L.sev[f.severity.value] }} | `{{ f.resources[0].key() }}` |
{% endfor %}
{% else %}
{{ L.no_vulns }}
{% endif %}

## {{ L.s_questions }}

{% for c in coverage if c.status.value in ("manual_check_needed", "organizational", "partially_checked") %}
{% set r = req(c.requirement_id) %}
**{{ c.requirement_id }} – {{ r.title | attr(lang) }}**
{% for q in r.questions %}
- [ ] {{ q | attr(lang) }}
{% endfor %}

{% else %}
{{ L.no_questions }}
{% endfor %}

## {{ L.s_appendix }}

### {{ L.s_not_checked }}

{% if skipped %}
| {{ L.check }} | {{ L.col_status }} | {{ L.col_reasons }} |
|---|---|---|
{% for r in skipped %}
| `{{ r.check_id }}` | {{ L.run_state[r.state] }} | {{ r.reason | md }} |
{% endfor %}
{% else %}
{{ L.nothing_skipped }}
{% endif %}

### {{ L.s_preflight }}

| {{ L.col_resource }} | {{ L.col_allowed }} |
|---|---|
{% for kind, allowed in preflight | dictsort %}
| {{ kind }} | {{ L.yes if allowed else L.no }} |
{% endfor %}

### {{ L.s_exclusions }}

{% for key, values in meta.config | dictsort if key != "as_of" %}
- `{{ key }}`: {{ values | join(", ") if values else L.none }}
{% endfor %}

### {{ L.s_evidence }}

| {{ L.col_file }} | SHA-256 |
|---|---|
{% for rel, digest in (manifest.get("files") or {}) | dictsort %}
| `{{ rel }}` | `{{ digest }}` |
{% endfor %}
```

- [ ] **Step 5: Write the renderer**

`src/k8s_baseline_audit/report/render.py`:

```python
"""Render report.de.md and report.en.md from analysis output and optional narratives."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from jinja2 import Environment, PackageLoader, StrictUndefined
from pydantic import BaseModel, Field

from ..bundle import Bundle
from ..mapping.schema import Mapping, load_mapping
from ..models import CoverageEntry, Finding, Source
from .labels import LABELS

LANGS = ("de", "en")


class PriorityNote(BaseModel):
    rank: int = Field(ge=1)
    reason: str = Field(min_length=1)


class Narrative(BaseModel):
    language: Literal["de", "en"]
    summary: str = Field(min_length=1)
    priorities: dict[str, PriorityNote] = Field(default_factory=dict)
    fix_notes: dict[str, str] = Field(default_factory=dict)


class NarrativeError(ValueError):
    """Narratives are inconsistent with the analysis or with each other."""


def validate_narratives(narratives: dict[str, Narrative], finding_ids: set[str]) -> None:
    if not narratives:
        return
    if set(narratives) != set(LANGS):
        raise NarrativeError("narratives must be provided for both de and en or not at all")
    for lang, n in narratives.items():
        if n.language != lang:
            raise NarrativeError(f"narrative for {lang} declares language {n.language}")
        unknown = (set(n.priorities) | set(n.fix_notes)) - finding_ids
        if unknown:
            raise NarrativeError(f"{lang}: unknown finding ids: {sorted(unknown)}")
    de, en = narratives["de"], narratives["en"]
    if {k: v.rank for k, v in de.priorities.items()} != {k: v.rank for k, v in en.priorities.items()}:
        raise NarrativeError("de and en priorities differ")
    if set(de.fix_notes) != set(en.fix_notes):
        raise NarrativeError("de and en fix notes cover different findings")


def md(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def is_vulnerability(f: Finding) -> bool:
    return Source.TRIVY in f.sources and (f.check_id.startswith("trivy:CVE-") or f.check_id.startswith("trivy:GHSA-"))


@dataclass(frozen=True)
class ReportInput:
    meta: dict
    findings: list[Finding]
    runs: list[dict]
    coverage: list[CoverageEntry]
    mapping: Mapping
    manifest: dict
    preflight: dict


def load_report_input(analysis_dir: Path, bundle: Bundle) -> ReportInput:
    findings_doc = json.loads((analysis_dir / "findings.json").read_text(encoding="utf-8"))
    coverage_doc = json.loads((analysis_dir / "coverage.json").read_text(encoding="utf-8"))
    meta = findings_doc["meta"]
    if meta["bundle"]["manifest_sha256"] != bundle.manifest_sha256():
        raise ValueError("analysis was produced from a different bundle (manifest hash mismatch)")
    return ReportInput(
        meta=meta,
        findings=[Finding.model_validate(f) for f in findings_doc["findings"]],
        runs=findings_doc["check_runs"],
        coverage=[CoverageEntry.model_validate(c) for c in coverage_doc["coverage"]],
        mapping=load_mapping(meta["mapping"]["name"]),
        manifest=bundle.manifest,
        preflight=bundle.preflight,
    )


def _ordered(findings: list[Finding], narrative: Narrative | None) -> list[Finding]:
    ranks = {k: v.rank for k, v in (narrative.priorities if narrative else {}).items()}
    return sorted(findings, key=lambda f: (ranks.get(f.id, 10**6), f.severity.rank, f.check_id, f.id))


def render_reports(inp: ReportInput, narratives: dict[str, Narrative] | None, out_dir: Path) -> dict[str, Path]:
    narratives = narratives or {}
    validate_narratives(narratives, {f.id for f in inp.findings})
    env = Environment(
        loader=PackageLoader("k8s_baseline_audit.report", "templates"),
        undefined=StrictUndefined,
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["md"] = md
    template = env.get_template("report.md.j2")
    ordered = _ordered(inp.findings, narratives.get("en"))
    main = [f for f in ordered if not is_vulnerability(f)]
    vulns = [f for f in ordered if is_vulnerability(f)]
    skipped = [r for r in inp.runs if r["state"] != "ran"]
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for lang in LANGS:
        text = template.render(
            lang=lang, L=LABELS[lang], meta=inp.meta, findings=main, vulns=vulns, coverage=inp.coverage,
            req=inp.mapping.get, narrative=narratives.get(lang), skipped=skipped,
            preflight=inp.preflight, manifest=inp.manifest,
        )
        path = out_dir / f"report.{lang}.md"
        path.write_text(text, encoding="utf-8")
        paths[lang] = path
    return paths
```

- [ ] **Step 6: Run tests**

Run: `pdm run pytest tests/test_report.py -v`
Expected: all passed. If `test_report_never_claims_fulfilment` fails, the offending word came from the mapping text (Task 10) or a label; rewrite that text.

- [ ] **Step 7: Render once and read it**

```bash
pdm run pytest tests/test_report.py -k parity -q --basetemp=/tmp/kba-report
cat /tmp/kba-report/*/out/report.de.md
```

Check by eye that every table has a header separator row, no row is broken by a stray `|` or newline, and the German text reads naturally.

- [ ] **Step 8: Commit**

```bash
git add src/k8s_baseline_audit/report tests/test_report.py
git commit -m "feat: bilingual report from one localized template with narrative validation"
```

---

### Task 15: Command-line interface

**Files:**
- Create: `src/k8s_baseline_audit/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `KubectlRunner` (Task 2), `collect`, `CollectOptions` (Task 4), `ScannerPlan`, `run_scanners` (Task 13), `load_bundle`, bundle errors (Task 4), `load_mapping` (Task 5), `AnalyzerConfig` (Task 6), `analyze`, `write_analysis` (Task 12), `ScannerFormatError` (Task 11), `Narrative`, `NarrativeError`, `load_report_input`, `render_reports` (Task 14).
- Produces: typer `app` with commands `collect`, `analyze`, `report`, option `--version`. `_make_runner(context) -> KubectlRunner` (patched in tests). Exit codes `0/1/2`.

- [ ] **Step 1: Write the failing test**

`tests/test_cli.py`:

```python
import json

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
    result = runner.invoke(cli.app, ["report", str(tmp_path / "a"), "--bundle", str(sample_bundle),
                                     "--out", str(tmp_path / "r"), "--narrative-de", str(n)])
    assert result.exit_code == 2


def test_full_offline_flow(sample_bundle, tmp_path):
    a = tmp_path / "a"
    runner.invoke(cli.app, ["analyze", str(sample_bundle), "--out", str(a), "--fail-on", "critical"])
    de, en = tmp_path / "de.json", tmp_path / "en.json"
    de.write_text(json.dumps({"language": "de", "summary": "Zusammenfassung."}))
    en.write_text(json.dumps({"language": "en", "summary": "Summary."}))
    result = runner.invoke(cli.app, ["report", str(a), "--bundle", str(sample_bundle), "--out", str(tmp_path / "r"),
                                     "--narrative-de", str(de), "--narrative-en", str(en)])
    assert result.exit_code == 0, result.stderr
    assert (tmp_path / "r" / "report.de.md").is_file()
    assert (tmp_path / "r" / "report.en.md").is_file()


def test_collect_uses_runner_and_skips_scanners(tmp_path, monkeypatch):
    fake = FakeKubectl()
    monkeypatch.setattr(cli, "_make_runner", lambda context: KubectlRunner(context=context, exec_fn=fake))
    result = runner.invoke(cli.app, ["collect", "--out", str(tmp_path), "--no-scanners"])
    assert result.exit_code == 0, result.stderr
    bundle_dir = result.stdout.strip().splitlines()[-1]
    manifest = json.loads((tmp_path / bundle_dir.split("/")[-1] / "manifest.json").read_text())
    assert manifest["scanners"] == {"kubescape": {"status": "disabled"}, "trivy": {"status": "disabled"}}


def test_collect_with_nothing_readable_exits_2(tmp_path, monkeypatch):
    from k8s_baseline_audit.collect.collector import ALL_KINDS

    fake = FakeKubectl(forbidden=set(ALL_KINDS))
    monkeypatch.setattr(cli, "_make_runner", lambda context: KubectlRunner(context=context, exec_fn=fake))
    result = runner.invoke(cli.app, ["collect", "--out", str(tmp_path), "--no-scanners"])
    assert result.exit_code == 2
    assert "no resources collected" in result.stderr


def test_bad_kube_bench_argument_exits_2(tmp_path):
    result = runner.invoke(cli.app, ["collect", "--out", str(tmp_path), "--kube-bench-result", "no-equals-sign"])
    assert result.exit_code == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pdm run pytest tests/test_cli.py -v`
Expected: FAIL with `ImportError: cannot import name 'cli'`

- [ ] **Step 3: Write minimal implementation**

`src/k8s_baseline_audit/cli.py`:

```python
"""k8s-baseline-audit command-line interface."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from . import __version__
from .analyze.checks.base import AnalyzerConfig
from .analyze.pipeline import analyze as run_analysis
from .analyze.pipeline import write_analysis
from .analyze.scanners import ScannerFormatError
from .bundle import BundleFormatError, BundleIntegrityError, load_bundle
from .collect.collector import CollectOptions
from .collect.collector import collect as collect_bundle
from .collect.runner import KubectlRunner
from .collect.scanners import ScannerPlan, run_scanners
from .mapping.schema import load_mapping
from .models import Severity
from .report.render import Narrative, NarrativeError, load_report_input, render_reports

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

app = typer.Typer(no_args_is_help=True, add_completion=False,
                  help="Read-only Kubernetes security audit mapped to BSI IT-Grundschutz APP.4.4 and SYS.1.6.")


def _fail(message: str) -> typer.Exit:
    typer.echo(f"error: {message}", err=True)
    return typer.Exit(EXIT_ERROR)


def _make_runner(context: str | None) -> KubectlRunner:
    return KubectlRunner(context=context)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"k8s-baseline-audit {__version__}")
        raise typer.Exit(EXIT_OK)


@app.callback()
def main(
    version: Annotated[bool, typer.Option("--version", callback=_version_callback, is_eager=True)] = False,
) -> None:
    """Collect, analyze and report."""


def _parse_kube_bench(values: list[str]) -> tuple[tuple[str, Path], ...]:
    parsed = []
    for value in values:
        node, sep, path = value.partition("=")
        if not sep or not node or not path:
            raise _fail(f"--kube-bench-result expects NODE=FILE, got {value!r}")
        if not Path(path).is_file():
            raise _fail(f"kube-bench result file not found: {path}")
        parsed.append((node, Path(path)))
    return tuple(parsed)


@app.command()
def collect(
    out: Annotated[Path, typer.Option("--out", help="Parent directory for the bundle")] = Path("."),
    context: Annotated[str | None, typer.Option("--context", help="kubectl context")] = None,
    no_scanners: Annotated[bool, typer.Option("--no-scanners", help="Skip kubescape and trivy")] = False,
    kube_bench_result: Annotated[list[str], typer.Option("--kube-bench-result", help="NODE=FILE, repeatable")] = [],  # noqa: B006
) -> None:
    """Collect cluster state read-only into an evidence bundle."""
    plan = ScannerPlan(kubescape=not no_scanners, trivy=not no_scanners,
                       kube_bench_results=_parse_kube_bench(kube_bench_result))
    try:
        with tempfile.TemporaryDirectory() as tmp:
            scans = run_scanners(plan, context, Path(tmp))
    except (OSError, json.JSONDecodeError) as exc:
        raise _fail(f"scanner step failed: {exc}") from exc
    options = CollectOptions(tool_version=__version__, now=datetime.now(UTC), extra_files=scans.files,
                             scanner_status=scans.status, extra_commands=scans.commands)
    out.mkdir(parents=True, exist_ok=True)
    path = collect_bundle(_make_runner(context), out, options)
    bundle = load_bundle(path)
    for err in bundle.errors:
        typer.echo(f"warning: {err['resource']}: {err['reason']}", err=True)
    if not [r for r in bundle.files_under("resources/") if r != "resources/version.json"]:
        typer.echo(str(path))
        raise _fail("no resources collected; check kubeconfig, context and permissions")
    typer.echo(str(path))


def _as_of(manifest: dict) -> date:
    created = manifest.get("created_at") or ""
    try:
        return date.fromisoformat(created[:10])
    except ValueError:
        return datetime.now(UTC).date()


@app.command()
def analyze(
    bundle_dir: Annotated[Path, typer.Argument(help="Bundle directory")],
    out: Annotated[Path, typer.Option("--out", help="Output directory for findings.json and coverage.json")],
    mapping: Annotated[str, typer.Option("--mapping")] = "kompendium-2023",
    registry_allowlist: Annotated[list[str], typer.Option("--registry-allowlist", help="Repeatable")] = [],  # noqa: B006
    fail_on: Annotated[Severity, typer.Option("--fail-on")] = Severity.HIGH,
) -> None:
    """Analyze a bundle deterministically."""
    try:
        bundle = load_bundle(bundle_dir)
        m = load_mapping(mapping)
        config = AnalyzerConfig(as_of=_as_of(bundle.manifest), registry_allowlist=tuple(sorted(registry_allowlist)))
        result = run_analysis(bundle, m, config, tool_version=__version__)
    except (BundleFormatError, BundleIntegrityError, ScannerFormatError, FileNotFoundError, ValidationError) as exc:
        raise _fail(str(exc)) from exc
    findings_path, coverage_path = write_analysis(result, out)
    typer.echo(str(findings_path))
    typer.echo(str(coverage_path))
    worst = any(f.severity.at_or_above(fail_on) for f in result.findings)
    raise typer.Exit(EXIT_FINDINGS if worst else EXIT_OK)


@app.command()
def report(
    analysis_dir: Annotated[Path, typer.Argument(help="Directory with findings.json and coverage.json")],
    bundle_dir: Annotated[Path, typer.Option("--bundle")],
    out: Annotated[Path, typer.Option("--out")],
    narrative_de: Annotated[Path | None, typer.Option("--narrative-de")] = None,
    narrative_en: Annotated[Path | None, typer.Option("--narrative-en")] = None,
) -> None:
    """Render report.de.md and report.en.md."""
    if (narrative_de is None) != (narrative_en is None):
        raise _fail("pass both --narrative-de and --narrative-en, or neither")
    try:
        narratives = None
        if narrative_de and narrative_en:
            narratives = {
                "de": Narrative.model_validate_json(narrative_de.read_text(encoding="utf-8")),
                "en": Narrative.model_validate_json(narrative_en.read_text(encoding="utf-8")),
            }
        inp = load_report_input(analysis_dir, load_bundle(bundle_dir))
        paths = render_reports(inp, narratives, out)
    except (BundleFormatError, BundleIntegrityError, NarrativeError, ValidationError, ValueError, OSError) as exc:
        raise _fail(str(exc)) from exc
    for path in paths.values():
        typer.echo(str(path))
```

- [ ] **Step 4: Run tests**

Run: `pdm run pytest -v && pdm run ruff check .`
Expected: all passed, ruff clean.

- [ ] **Step 5: Try the installed entry point**

```bash
pdm run k8s-baseline-audit --version
pdm run k8s-baseline-audit --help
```

Expected: `k8s-baseline-audit 0.1.0`, and help listing `collect`, `analyze`, `report`.

- [ ] **Step 6: Commit**

```bash
git add src/k8s_baseline_audit/cli.py tests/test_cli.py
git commit -m "feat: collect, analyze and report commands with exit codes"
```

---
### Task 16: Client export script with parity to the Python collector

**Files:**
- Create: `scripts/export-bundle.sh`
- Test: `tests/test_export_script.py`

**Interfaces:**
- Consumes: bundle format (Task 4), redaction rules (Task 3), sanitizers (Task 11). The script must produce a bundle that `load_bundle` verifies and whose redacted content equals the Python functions' output for the same input.
- Produces: `scripts/export-bundle.sh -o OUT_DIR [-c CONTEXT] [-k kubescape.json] [-t trivy.json] [-b NODE=kube-bench.json]...`; prints the bundle path; exit `0` ok, `2` error. Manifest `producer: "export-script"`.

- [ ] **Step 1: Write the failing test**

`tests/test_export_script.py`:

```python
import json
import os
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from k8s_baseline_audit.analyze.checks.base import AnalyzerConfig
from k8s_baseline_audit.analyze.pipeline import analyze
from k8s_baseline_audit.bundle import load_bundle
from k8s_baseline_audit.collect.redact import LAST_APPLIED, parse_secret_rows, redact_pod_list
from k8s_baseline_audit.collect.sanitize import sanitize_kubescape, sanitize_trivy
from k8s_baseline_audit.mapping.schema import load_mapping

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "export-bundle.sh"
SECRET = "s3cr3t-value-123"

pytestmark = pytest.mark.skipif(shutil.which("jq") is None, reason="jq not installed")

SHIM = """#!{python}
import json, os, sys
data = os.environ["FAKE_KUBECTL_DIR"]
args = sys.argv[1:]
if args[:1] == ["--context"]:
    args = args[2:]
with open(os.environ["FAKE_KUBECTL_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
forbidden = set(filter(None, os.environ.get("FAKE_FORBIDDEN", "").split(",")))
verb = args[0]
if verb == "config":
    sys.stdout.write("kind-test" if args[1] == "current-context" else "https://127.0.0.1:6443")
    sys.exit(0)
if verb == "version":
    print(json.dumps({"serverVersion": {"major": "1", "minor": "35"}}))
    sys.exit(0)
if verb == "auth":
    if args[3] in forbidden:
        print("no")
        sys.exit(1)
    print("yes")
    sys.exit(0)
if verb == "get":
    kind = args[1]
    if kind == "secrets":
        sys.stdout.write(open(os.path.join(data, "secrets.tsv")).read())
        sys.exit(0)
    path = os.path.join(data, kind + ".json")
    sys.stdout.write(open(path).read() if os.path.exists(path) else '{"items": []}')
    sys.exit(0)
sys.stderr.write("unexpected kubectl call: " + " ".join(args))
sys.exit(99)
"""

PODS = {
    "items": [
        {
            "metadata": {"name": "web", "namespace": "default", "annotations": {LAST_APPLIED: SECRET, "keep": "me"}},
            "spec": {
                "initContainers": [{"name": "init", "env": [{"name": "A", "value": SECRET}]}],
                "containers": [
                    {
                        "name": "app",
                        "image": "nginx:latest",
                        "env": [
                            {"name": "DB_PASSWORD", "value": SECRET},
                            {"name": "EMPTY", "value": ""},
                            {"name": "REF", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}},
                        ],
                        "args": [f"--db-password={SECRET}", "--port=8080"],
                    }
                ],
            },
        },
        {"metadata": {"name": "bare", "namespace": "default"}},
    ]
}
TSV = "default\tdb\tOpaque\tpassword,user,\nkube-system\ttok\tkubernetes.io/service-account-token\t\n"
KS = {"resources": [{"resourceID": "r", "object": {"apiVersion": "v1", "kind": "Pod",
      "metadata": {"name": "web", "namespace": "default"}, "spec": {"env": SECRET}}}], "results": []}
TV = {"Resources": [{"Kind": "Pod", "Name": "web", "Namespace": "default", "Results": [
      {"Misconfigurations": [{"ID": "KSV017", "Status": "FAIL", "CauseMetadata": {"Code": SECRET}}]},
      {"Secrets": [{"RuleID": "x", "Match": SECRET, "Code": {"Lines": [SECRET]}}]}]}]}
KB = {"Controls": []}


@pytest.fixture
def env(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "pods.json").write_text(json.dumps(PODS))
    (data / "secrets.tsv").write_text(TSV)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shim = bin_dir / "kubectl"
    shim.write_text(SHIM.replace("{python}", sys.executable))
    shim.chmod(0o755)
    for name, doc in (("ks.json", KS), ("tv.json", TV), ("kb.json", KB)):
        (tmp_path / name).write_text(json.dumps(doc))
    environ = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_KUBECTL_DIR": str(data),
        "FAKE_KUBECTL_LOG": str(tmp_path / "calls.log"),
    }
    return tmp_path, environ


def run(tmp_path, environ, *extra):
    return subprocess.run(
        ["sh", str(SCRIPT), "-o", str(tmp_path / "out"), *extra],
        env=environ, capture_output=True, text=True, check=False,
    )


def full_run(tmp_path, environ):
    proc = run(tmp_path, environ, "-k", str(tmp_path / "ks.json"), "-t", str(tmp_path / "tv.json"),
               "-b", f"cp 1={tmp_path / 'kb.json'}")
    assert proc.returncode == 0, proc.stderr
    return Path(proc.stdout.strip().splitlines()[-1])


def test_bundle_is_verified_and_matches_python_rules(env):
    tmp_path, environ = env
    root = full_run(tmp_path, environ)
    b = load_bundle(root)
    assert b.provenance_verified
    assert b.manifest["producer"] == "export-script"
    assert b.manifest["cluster"] == {"context": "kind-test", "server": "https://127.0.0.1:6443"}
    assert b.read_json("resources/pods.json") == redact_pod_list(PODS)
    assert b.read_json("resources/secrets.json") == parse_secret_rows(TSV)
    assert b.read_json("scanners/kubescape.json") == sanitize_kubescape(KS)
    assert b.read_json("scanners/trivy.json") == sanitize_trivy(TV)
    assert b.has("scanners/kube-bench-cp-1.json")
    assert b.manifest["scanners"]["kube-bench"] == {"status": "imported", "nodes": ["cp-1"]}


def test_no_secret_on_disk(env):
    tmp_path, environ = env
    root = full_run(tmp_path, environ)
    for path in root.rglob("*"):
        if path.is_file():
            assert SECRET not in path.read_text(), path


def test_only_read_commands(env):
    tmp_path, environ = env
    full_run(tmp_path, environ)
    calls = [json.loads(line) for line in (tmp_path / "calls.log").read_text().splitlines()]
    assert {c[0] for c in calls} <= {"get", "version", "auth", "config"}
    assert all(c[1] == "can-i" for c in calls if c[0] == "auth")


def test_forbidden_kind_matches_python_error(env):
    tmp_path, environ = env
    environ["FAKE_FORBIDDEN"] = "nodes"
    b = load_bundle(full_run(tmp_path, environ))
    assert b.preflight["nodes"] is False
    assert {"resource": "nodes", "reason": "forbidden: kubectl auth can-i list returned no"} in b.errors
    assert not b.has("resources/nodes.json")


def test_analyzer_accepts_export_bundle(env):
    tmp_path, environ = env
    b = load_bundle(full_run(tmp_path, environ))
    result = analyze(b, load_mapping(), AnalyzerConfig(as_of=date(2026, 9, 30)), tool_version="0.1.0")
    assert any(f.check_id == "secrets.credential_literal_env" for f in result.findings)


@pytest.mark.parametrize("case", ["no-args", "missing-value", "bad-kube-bench"])
def test_bad_arguments_exit_2(env, case):
    tmp_path, environ = env
    args = {
        "no-args": [],
        "missing-value": ["-o"],
        "bad-kube-bench": ["-o", str(tmp_path / "out"), "-b", "no-equals"],
    }[case]
    proc = subprocess.run(["sh", str(SCRIPT), *args], env=environ, capture_output=True, text=True, check=False)
    assert proc.returncode == 2
    assert not (tmp_path / "out").exists() or not any((tmp_path / "out").iterdir())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pdm run pytest tests/test_export_script.py -v`
Expected: FAIL (script missing, `returncode` 127 or 2 with "No such file").

- [ ] **Step 3: Write the script**

`scripts/export-bundle.sh`:

```sh
#!/bin/sh
# export-bundle.sh - read-only evidence export for k8s-baseline-audit.
#
# Run by the cluster operator. Needs kubectl, jq and sha256sum or shasum.
# Every kubectl call goes through kc(), which refuses anything except
# get, version, api-resources, auth can-i, config current-context and config view.
# Redaction and sanitizing rules mirror src/k8s_baseline_audit/collect/redact.py
# and sanitize.py; tests/test_export_script.py enforces parity.
set -eu

VERSION="0.1.0"
SECRET_TEMPLATE='{{range .items}}{{.metadata.namespace}}{{"\t"}}{{.metadata.name}}{{"\t"}}{{.type}}{{"\t"}}{{range $k, $v := .data}}{{$k}},{{end}}{{"\n"}}{{end}}'

JQ_UPD='def upd(k; f): if type == "object" and has(k) and .[k] != null then .[k] |= f else . end;'

JQ_REDACT_PODS="$JQ_UPD"'
def redact_args: map(if type == "string" then gsub("(?<k>(password|passwd|token|secret|api[-_]?key)[\\w-]*=)\\S+"; "\(.k)<redacted>"; "i") else . end);
def redact_container:
  upd("env"; map(if type == "object" and ((.value // "") != "") then .value = "<redacted>" else . end))
  | upd("command"; redact_args) | upd("args"; redact_args);
upd("items"; map(
  upd("metadata"; upd("annotations"; del(.["kubectl.kubernetes.io/last-applied-configuration"])))
  | upd("spec"; upd("initContainers"; map(redact_container))
               | upd("containers"; map(redact_container))
               | upd("ephemeralContainers"; map(redact_container)))
))'

JQ_SECRETS='split("\n") | map(select(test("\\S")) | split("\t") | . + ["", "", "", ""]
  | {metadata: {namespace: .[0], name: .[1]}, type: .[2], keys: (.[3] | split(",") | map(select(length > 0)) | sort)})
  | {items: .}'

JQ_SANITIZE_KUBESCAPE="$JQ_UPD"'
upd("resources"; map(if type == "object" and ((.object | type) == "object")
  then .object |= {apiVersion: .apiVersion, kind: .kind, metadata: {name: .metadata.name, namespace: .metadata.namespace}}
  else . end))'

JQ_SANITIZE_TRIVY="$JQ_UPD"'
upd("Resources"; map(upd("Results"; map(
  upd("Misconfigurations"; map(if type == "object" then del(.CauseMetadata) else . end))
  | upd("Secrets"; map(if type == "object" then del(.Match, .Code) else . end))
))))'

usage() {
  echo "usage: $0 -o OUT_DIR [-c CONTEXT] [-k kubescape.json] [-t trivy.json] [-b NODE=kube-bench.json]..." >&2
  exit 2
}
die() { echo "error: $*" >&2; exit 2; }

OUT="" CTX="" KS="" TV="" KB=""
while getopts "o:c:k:t:b:h" opt; do
  case "$opt" in
    o) OUT=$OPTARG ;;
    c) CTX=$OPTARG ;;
    k) KS=$OPTARG ;;
    t) TV=$OPTARG ;;
    b) KB="$KB
$OPTARG" ;;
    *) usage ;;
  esac
done
[ -n "$OUT" ] || usage
for tool in kubectl jq; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH"
done
for f in "$KS" "$TV"; do
  [ -z "$f" ] || [ -f "$f" ] || die "scanner file not found: $f"
done
TMP=$(mktemp -d)
trap 'rm -r "$TMP"' EXIT
: > "$TMP/commands.jsonl"
: > "$TMP/errors.jsonl"
: > "$TMP/preflight.tsv"
: > "$TMP/scanners.jsonl"
: > "$TMP/kb.nodes"
printf '%s\n' "$KB" | sed '/^$/d' > "$TMP/kb.list"
while IFS= read -r entry; do
  node=${entry%%=*}
  file=${entry#*=}
  { [ -n "$node" ] && [ "$node" != "$entry" ] && [ -f "$file" ]; } || die "-b expects NODE=FILE with an existing file, got: $entry"
done < "$TMP/kb.list"

sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

slug() { printf '%s' "$1" | tr -cs 'A-Za-z0-9._-' '-' | sed 's/^-*//; s/-*$//'; }

kc() {
  out=$1
  shift
  case "$1" in
    get|version|api-resources) ;;
    auth) [ "${2:-}" = "can-i" ] || die "refusing: kubectl $*" ;;
    config) case "${2:-}" in current-context|view) ;; *) die "refusing: kubectl $*" ;; esac ;;
    *) die "refusing: kubectl $*" ;;
  esac
  if [ -n "$CTX" ]; then set -- --context "$CTX" "$@"; fi
  set +e
  kubectl "$@" > "$out" 2> "$TMP/stderr"
  rc=$?
  set -e
  jq -cn --argjson rc "$rc" '{argv: (["kubectl"] + $ARGS.positional), exit_code: $rc}' --args "$@" >> "$TMP/commands.jsonl"
  return "$rc"
}

err() { jq -cn --arg r "$1" --arg m "$2" '{resource: $r, reason: $m}' >> "$TMP/errors.jsonl"; }
reason() {
  detail=$(tail -c 500 "$TMP/stderr" | tr '\n' ' ' | sed 's/ *$//')
  if [ -n "$detail" ]; then echo "kubectl failed: $detail"; else echo "kubectl failed"; fi
}

if kc "$TMP/ctx" config current-context && [ -s "$TMP/ctx" ]; then
  CONTEXT_NAME=$(tr -d '\n' < "$TMP/ctx")
else
  CONTEXT_NAME=${CTX:-unknown}
fi
if kc "$TMP/srv" config view --minify -o 'jsonpath={.clusters[0].cluster.server}'; then
  SERVER=$(tr -d '\n' < "$TMP/srv")
else
  SERVER=""
fi

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
NAME=$(slug "$CONTEXT_NAME")
B="$OUT/bundle-${NAME:-cluster}-$STAMP"
[ ! -e "$B" ] || die "$B already exists"
mkdir -p "$B/resources"

if kc "$TMP/ver" version -o json && jq -e . "$TMP/ver" > /dev/null 2>&1; then
  jq -S . "$TMP/ver" > "$B/resources/version.json"
else
  err version "$(reason)"
fi

for kind in namespaces nodes pods serviceaccounts roles clusterroles rolebindings clusterrolebindings networkpolicies secrets; do
  case $kind in
    pods|serviceaccounts|roles|rolebindings|networkpolicies|secrets) set -- --all-namespaces ;;
    *) set -- ;;
  esac
  if kc "$TMP/can" auth can-i list "$kind" "$@" && [ "$(tr -d '[:space:]' < "$TMP/can")" = "yes" ]; then
    printf '%s\ttrue\n' "$kind" >> "$TMP/preflight.tsv"
  else
    printf '%s\tfalse\n' "$kind" >> "$TMP/preflight.tsv"
    err "$kind" "forbidden: kubectl auth can-i list returned no"
    continue
  fi
  if [ "$kind" = secrets ]; then
    if kc "$TMP/res" get secrets "$@" -o "go-template=$SECRET_TEMPLATE"; then
      jq -R -s -S "$JQ_SECRETS" "$TMP/res" > "$B/resources/secrets.json"
    else
      err secrets "$(reason)"
    fi
    continue
  fi
  if ! kc "$TMP/res" get "$kind" "$@" -o json; then
    err "$kind" "$(reason)"
    continue
  fi
  if ! jq -e . "$TMP/res" > /dev/null 2>&1; then
    err "$kind" "kubectl returned invalid JSON"
    continue
  fi
  if [ "$kind" = pods ]; then
    jq -S "$JQ_REDACT_PODS" "$TMP/res" > "$B/resources/pods.json"
  else
    jq -S . "$TMP/res" > "$B/resources/$kind.json"
  fi
done

import_scanner() {
  name=$1 src=$2 prog=$3
  [ -n "$src" ] || return 0
  mkdir -p "$B/scanners"
  jq -S "$prog" "$src" > "$B/scanners/$name.json" || die "$src is not valid JSON"
  jq -cn --arg n "$name" '{($n): {status: "imported"}}' >> "$TMP/scanners.jsonl"
}
import_scanner kubescape "$KS" "$JQ_SANITIZE_KUBESCAPE"
import_scanner trivy "$TV" "$JQ_SANITIZE_TRIVY"

while IFS= read -r entry; do
  node=$(slug "${entry%%=*}")
  mkdir -p "$B/scanners"
  jq -S . "${entry#*=}" > "$B/scanners/kube-bench-${node:-node}.json" || die "${entry#*=} is not valid JSON"
  printf '%s\n' "${node:-node}" >> "$TMP/kb.nodes"
done < "$TMP/kb.list"
if [ -s "$TMP/kb.nodes" ]; then
  jq -R -s -c '{"kube-bench": {status: "imported", nodes: (split("\n") | map(select(length > 0)))}}' "$TMP/kb.nodes" >> "$TMP/scanners.jsonl"
fi

jq -R -s -S 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): (.[1] == "true")}) | add // {}' \
  "$TMP/preflight.tsv" > "$B/preflight.json"
jq -s -S '{errors: .}' "$TMP/errors.jsonl" > "$B/errors.json"

( cd "$B" && find . -type f | sed 's|^\./||' | LC_ALL=C sort ) > "$TMP/files"
: > "$TMP/hashes.tsv"
while IFS= read -r f; do
  printf '%s\t%s\n' "$f" "$(sha "$B/$f")" >> "$TMP/hashes.tsv"
done < "$TMP/files"

jq -n -S \
  --arg created "$NOW" --arg ctx "$CONTEXT_NAME" --arg server "$SERVER" --arg version "$VERSION" \
  --slurpfile commands "$TMP/commands.jsonl" --slurpfile scanners "$TMP/scanners.jsonl" \
  --rawfile hashes "$TMP/hashes.tsv" \
  '{schema: "k8s-baseline-audit/bundle/v1", producer: "export-script", created_at: $created,
    cluster: {context: $ctx, server: $server},
    tool: {name: "k8s-baseline-audit-export", version: $version},
    commands: $commands, scanners: ($scanners | add // {}),
    files: ($hashes | split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add // {})}' \
  > "$B/manifest.json"

echo "$B"
```

- [ ] **Step 4: Run tests and shellcheck**

```bash
chmod +x scripts/export-bundle.sh
pdm run pytest tests/test_export_script.py -v
command -v shellcheck >/dev/null && shellcheck -s sh scripts/export-bundle.sh
```

Expected: all passed; shellcheck clean (or only SC2016 for intentional single-quoted jq, which may be disabled with a directive comment on that line).

- [ ] **Step 5: Commit**

```bash
git add scripts/export-bundle.sh tests/test_export_script.py
git commit -m "feat: POSIX export script for client-side bundles with Python parity tests"
```

---

### Task 17: Portable agent skill and installer

**Files:**
- Create: `skill/k8s-baseline-audit/SKILL.md`, `scripts/install-skill.sh`
- Test: `tests/test_skill.py`

**Interfaces:**
- Consumes: CLI commands and options (Task 15), `Narrative` model (Task 14).
- Produces: an Agent Skills compliant skill folder; `scripts/install-skill.sh AGENT [--project DIR]` with agents `claude`, `cursor`, `copilot`, `agents` (generic `.agents/skills`), plus `codex` and `gemini` only if Step 1 verifies their paths.

- [ ] **Step 1: Verify each agent's skill folder from its own documentation**

```bash
firecrawl scrape https://agentskills.io --only-main-content | head -120
firecrawl scrape https://cursor.com/docs/skills --only-main-content | grep -iE 'skills/|directory|global|project'
firecrawl search "OpenAI Codex CLI agent skills SKILL.md directory" --limit 5
firecrawl search "Gemini CLI agent skills SKILL.md directory" --limit 5
firecrawl search "GitHub Copilot agent skills .github/skills ~/.copilot/skills" --limit 5
```

Record every path with its source URL in a table at the top of `scripts/install-skill.sh` (comment block). Confirm from the agentskills.io spec: allowed frontmatter keys, `name` format and length, `description` length. If the spec's limits differ from the test in Step 2, use the spec's values. **Only agents whose paths are confirmed by their vendor's documentation go into the script.** Remove `codex` or `gemini` from the `case` blocks below if unconfirmed.

- [ ] **Step 2: Write the failing test**

`tests/test_skill.py`:

```python
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from k8s_baseline_audit.report.render import Narrative

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skill" / "k8s-baseline-audit" / "SKILL.md"
INSTALL = ROOT / "scripts" / "install-skill.sh"
AGENT_SPECIFIC = ("mcp__", "Bash tool", "Read tool", "Write tool", "Skill tool", "TodoWrite", "AskUserQuestion")


def _split():
    text = SKILL.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
    assert m, "SKILL.md must start with YAML frontmatter"
    return yaml.safe_load(m.group(1)), m.group(2)


def test_frontmatter_follows_agent_skills_standard():
    front, _ = _split()
    assert set(front) == {"name", "description"}
    assert front["name"] == SKILL.parent.name
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", front["name"]) and len(front["name"]) <= 64
    assert 0 < len(front["description"]) <= 1024


def test_body_is_agent_neutral_and_uses_real_commands():
    _, body = _split()
    for token in AGENT_SPECIFIC:
        assert token not in body, token
    for cmd in ("k8s-baseline-audit collect", "k8s-baseline-audit analyze", "k8s-baseline-audit report"):
        assert cmd in body, cmd
    rules, _, steps = body.partition("## Step 0")
    assert steps, "SKILL.md needs a '## Step 0' section after the hard rules"
    for forbidden in ("kubectl apply", "kubectl delete", "kubectl patch", "kubectl exec"):
        assert forbidden in rules  # named in the prohibition list
        assert forbidden not in steps  # never used in an instruction


def test_narrative_examples_validate():
    _, body = _split()
    blocks = re.findall(r"```json\n(.*?)\n```", body, re.S)
    assert len(blocks) >= 2
    for block in blocks:
        Narrative.model_validate(json.loads(block))


def _install(agent, home, *extra):
    return subprocess.run(["sh", str(INSTALL), agent, *extra], env={**os.environ, "HOME": str(home)},
                          capture_output=True, text=True, check=False)


@pytest.mark.parametrize("agent,rel", [("claude", ".claude/skills"), ("copilot", ".copilot/skills")])
def test_user_level_install(tmp_path, agent, rel):
    proc = _install(agent, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert (tmp_path / rel / "k8s-baseline-audit" / "SKILL.md").is_file()


@pytest.mark.parametrize(
    "agent,rel", [("cursor", ".cursor/skills"), ("copilot", ".github/skills"), ("agents", ".agents/skills")]
)
def test_project_level_install(tmp_path, agent, rel):
    proj = tmp_path / "proj"
    proj.mkdir()
    proc = _install(agent, tmp_path, "--project", str(proj))
    assert proc.returncode == 0, proc.stderr
    assert (proj / rel / "k8s-baseline-audit" / "SKILL.md").is_file()


def test_existing_install_is_not_overwritten(tmp_path):
    assert _install("claude", tmp_path).returncode == 0
    second = _install("claude", tmp_path)
    assert second.returncode == 1
    assert "already installed" in second.stderr


def test_unknown_agent_and_missing_user_path(tmp_path):
    assert _install("bolt", tmp_path).returncode == 2
    assert _install("cursor", tmp_path).returncode == 2  # cursor: project-level only
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pdm run pytest tests/test_skill.py -v`
Expected: FAIL (`SKILL.md` missing).

- [ ] **Step 4: Write the skill**

`skill/k8s-baseline-audit/SKILL.md`:

````markdown
---
name: k8s-baseline-audit
description: Read-only Kubernetes security audit mapped to BSI IT-Grundschutz modules APP.4.4 (Kubernetes) and SYS.1.6 (Containerisation). Use when asked to audit, assess or harden a Kubernetes cluster, to prepare for a BSI, ISO 27001 or KRITIS audit, or to analyze an evidence bundle exported from a client cluster. Produces a German and an English report. Never changes the cluster and never applies fixes.
---

# k8s-baseline-audit

Audit a Kubernetes cluster against BSI IT-Grundschutz APP.4.4 and SYS.1.6 and hand over a German and an English report.

## Hard rules

1. Never run a command that changes a cluster. Never run `kubectl apply`, `kubectl delete`, `kubectl patch`, `kubectl edit`, `kubectl exec`, `kubectl scale`, `kubectl label`, `kubectl annotate`, `kubectl cordon`, `kubectl drain`, `helm install` or `helm upgrade`. The only commands you run are `k8s-baseline-audit ...`, `kubectl config current-context` and `kubectl config get-contexts`.
2. Never edit `findings.json` or `coverage.json`, and never change a severity.
3. Never write that a requirement is fulfilled, compliant, "erfüllt" or "konform". Use the coverage status words from the report.
4. Every statement about the cluster in your text refers to a finding ID or a requirement ID.
5. Fix commands go into the report text only. Do not execute them.
6. The bundle and the reports contain confidential client data. Do not upload or paste them anywhere outside the working directory.

## Step 0: Check the tool

```sh
k8s-baseline-audit --version
```

If it is missing, install it:

```sh
pipx install git+https://github.com/hakanyedibela/k8s-baseline-audit
```

## Step 1: Choose the mode

Ask the user which applies:

- **Live, read-only:** the user has a kubeconfig for the cluster. Show the current context with `kubectl config current-context` and get explicit confirmation that it is the cluster to audit.
- **Offline bundle:** the client ran `scripts/export-bundle.sh` and handed over a bundle directory. Ask for its path and skip Step 2.

Also ask whether the user has a list of approved image registries, and whether kube-bench result files exist (one JSON file per node).

## Step 2: Collect (live mode only)

```sh
k8s-baseline-audit collect --context <CONTEXT> --out ./audit
```

Add `--kube-bench-result <NODE>=<FILE>` once per kube-bench file. Add `--no-scanners` if the user does not want kubescape or trivy to run. The last line of output is the bundle path. Show every `warning:` line to the user; each one becomes a "not checked" item in the report.

## Step 3: Analyze

```sh
k8s-baseline-audit analyze <BUNDLE> --out ./audit/analysis --registry-allowlist <REGISTRY>
```

Repeat `--registry-allowlist` per registry, or leave it out. Exit code 0 or 1 is success (1 means findings at or above `high`). Exit code 2 is an error: show it to the user and stop.

## Step 4: Write the narratives

Read `./audit/analysis/findings.json` and `./audit/analysis/coverage.json`. Write two files with identical structure:

- `summary`: 150 to 300 words for management. Name the three to five most important risks by finding ID, say what was not checked and why, and state that this is no certification.
- `priorities`: rank the findings you consider most urgent, starting at 1. Base the reason on exposure, blast radius and ease of exploitation in this cluster. Use the same finding IDs and the same ranks in both languages.
- `fix_notes`: optional, per finding ID, for context the generic remediation text lacks. Same IDs in both languages.

`./audit/analysis/narrative.de.json`:

```json
{
  "language": "de",
  "summary": "Die Prüfung fand zwei kritische Abweichungen ...",
  "priorities": {"0123456789abcdef": {"rank": 1, "reason": "Privilegierter Pod mit Host-Netzwerk im Produktions-Namespace."}},
  "fix_notes": {"0123456789abcdef": "Vor dem Entfernen von privileged prüfen, ob der Pod Gerätezugriff braucht."}
}
```

`./audit/analysis/narrative.en.json`:

```json
{
  "language": "en",
  "summary": "The audit found two critical deviations ...",
  "priorities": {"0123456789abcdef": {"rank": 1, "reason": "Privileged pod with host network in the production namespace."}},
  "fix_notes": {"0123456789abcdef": "Before removing privileged, check whether the pod needs device access."}
}
```

## Step 5: Render

```sh
k8s-baseline-audit report ./audit/analysis --bundle <BUNDLE> --out ./audit/report \
  --narrative-de ./audit/analysis/narrative.de.json --narrative-en ./audit/analysis/narrative.en.json
```

If it fails with a narrative error, fix the narrative files and rerun. Never edit the analysis files.

## Step 6: Hand over

Tell the user:

- the two report paths
- the number of findings per severity
- the number of requirements with status "not checked" or "manual check needed"
- that the questions section is the interview checklist for the client meeting
- that the bundle holds client data and must be stored and deleted according to the engagement terms
````

- [ ] **Step 5: Write the installer**

`scripts/install-skill.sh` (adjust the path table to Step 1's verified results):

```sh
#!/bin/sh
# install-skill.sh - copy the k8s-baseline-audit skill into an agent's skill folder.
#
# Verified skill folders (fill in source URLs from Task 17 Step 1):
#   claude   user: ~/.claude/skills        project: .claude/skills
#   cursor   project: .cursor/skills        (source: https://cursor.com/docs/skills)
#   copilot  user: ~/.copilot/skills       project: .github/skills
#   agents   project: .agents/skills        (generic Agent Skills location)
#   codex    user: <verified path>          (remove if unverified)
#   gemini   user: <verified path>          (remove if unverified)
set -eu

usage() {
  echo "usage: $0 AGENT [--project DIR]   agents: claude cursor copilot agents codex gemini" >&2
  exit 2
}

AGENT=${1:-}
[ -n "$AGENT" ] || usage
shift
PROJECT=""
while [ $# -gt 0 ]; do
  case $1 in
    --project) [ $# -ge 2 ] || usage; PROJECT=$2; shift 2 ;;
    *) usage ;;
  esac
done

SRC=$(cd "$(dirname "$0")/../skill/k8s-baseline-audit" && pwd)

if [ -n "$PROJECT" ]; then
  case $AGENT in
    claude) DEST="$PROJECT/.claude/skills" ;;
    cursor) DEST="$PROJECT/.cursor/skills" ;;
    copilot) DEST="$PROJECT/.github/skills" ;;
    agents|codex|gemini) DEST="$PROJECT/.agents/skills" ;;
    *) echo "unknown agent: $AGENT" >&2; usage ;;
  esac
else
  case $AGENT in
    claude) DEST="$HOME/.claude/skills" ;;
    copilot) DEST="$HOME/.copilot/skills" ;;
    codex) DEST="$HOME/.codex/skills" ;;
    gemini) DEST="$HOME/.gemini/skills" ;;
    cursor|agents) echo "$AGENT has no verified user-level skill folder; use --project DIR" >&2; exit 2 ;;
    *) echo "unknown agent: $AGENT" >&2; usage ;;
  esac
fi

TARGET="$DEST/k8s-baseline-audit"
if [ -e "$TARGET" ]; then
  echo "already installed at $TARGET; remove it yourself to reinstall" >&2
  exit 1
fi
mkdir -p "$DEST"
cp -R "$SRC" "$TARGET"
echo "installed to $TARGET"
```

Replace the `codex` and `gemini` lines with the verified paths or delete them, and update the comment block.

- [ ] **Step 6: Run tests**

```bash
chmod +x scripts/install-skill.sh
pdm run pytest tests/test_skill.py -v
```

Expected: all passed.

- [ ] **Step 7: Commit**

```bash
git add skill scripts/install-skill.sh tests/test_skill.py
git commit -m "feat: agent-neutral skill following the Agent Skills standard, plus installer"
```

---

### Task 18: kind integration test and CI

**Files:**
- Create: `tests/integration/__init__.py` (empty), `tests/integration/test_kind.py`, `.github/workflows/ci.yml`
- Test: `tests/integration/test_kind.py` (marker `integration`)

**Interfaces:**
- Consumes: the CLI (Task 15), `examples/kind-demo/insecure.yaml` (Task 11).
- Environment: `K8S_BASELINE_AUDIT_IT_CONTEXT` = kubectl context of a kind cluster that already has `insecure.yaml` applied.

- [ ] **Step 1: Write the integration test**

`tests/integration/test_kind.py`:

```python
import json
import os
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from k8s_baseline_audit import cli

pytestmark = pytest.mark.integration
CONTEXT = os.environ.get("K8S_BASELINE_AUDIT_IT_CONTEXT")

EXPECTED_INSECURE = {
    "identity.automount_token",
    "identity.default_service_account",
    "images.latest_tag",
    "images.no_digest",
    "secrets.credential_literal_env",
    "secrets.env_secret_ref",
    "workload.added_capabilities",
    "workload.host_namespaces",
    "workload.host_path",
    "workload.privilege_escalation",
    "workload.privileged",
    "workload.resource_limits_missing",
    "workload.run_as_non_root_missing",
    "workload.run_as_root",
    "workload.seccomp_missing",
    "workload.writable_root_fs",
}
EXPECTED_HARDENED = {"images.no_digest"}


def _snapshot():
    out = subprocess.run(
        ["kubectl", "--context", CONTEXT, "get", "all,jobs,roles,rolebindings,serviceaccounts,configmaps,secrets",
         "-A", "-o", "name"],
        capture_output=True, text=True, check=True,
    ).stdout
    return sorted(out.splitlines())


@pytest.fixture(scope="module")
def analysis(tmp_path_factory):
    if not CONTEXT:
        pytest.skip("K8S_BASELINE_AUDIT_IT_CONTEXT not set")
    work = tmp_path_factory.mktemp("it")
    before = _snapshot()
    runner = CliRunner()
    collected = runner.invoke(cli.app, ["collect", "--context", CONTEXT, "--out", str(work), "--no-scanners"])
    assert collected.exit_code == 0, collected.stderr
    after = _snapshot()
    bundle = Path(collected.stdout.strip().splitlines()[-1])
    analyzed = runner.invoke(cli.app, ["analyze", str(bundle), "--out", str(work / "analysis")])
    assert analyzed.exit_code in (0, 1), analyzed.stderr
    return before, after, bundle, json.loads((work / "analysis" / "findings.json").read_text())


def _checks_for(doc, kind, namespace, name):
    return {f["check_id"] for f in doc["findings"]
            for r in f["resources"] if (r["kind"], r.get("namespace"), r["name"]) == (kind, namespace, name)}


def test_collection_did_not_change_the_cluster(analysis):
    before, after, _, _ = analysis
    assert before == after


def test_demo_pods_have_exactly_the_expected_findings(analysis):
    _, _, _, doc = analysis
    assert _checks_for(doc, "Pod", "audit-demo", "insecure") == EXPECTED_INSECURE
    assert _checks_for(doc, "Pod", "audit-demo", "hardened") == EXPECTED_HARDENED


def test_cluster_scoped_demo_findings(analysis):
    _, _, _, doc = analysis
    assert "identity.wildcard_role" in _checks_for(doc, "ClusterRole", None, "audit-demo-wildcard")
    assert "identity.anonymous_binding" in _checks_for(doc, "ClusterRoleBinding", None, "audit-demo-anon")
    ns_checks = _checks_for(doc, "Namespace", None, "audit-demo")
    assert {"isolation.psa_labels_missing", "isolation.no_network_policy"} <= ns_checks


def test_demo_secret_not_in_bundle(analysis):
    _, _, bundle, _ = analysis
    for path in bundle.rglob("*"):
        if path.is_file():
            text = path.read_text()
            assert "hunter2-demo" not in text
            assert "demo-only-not-a-real-secret" not in text
```

- [ ] **Step 2: Run it locally against kind**

```bash
kind create cluster --name kba-it
kubectl --context kind-kba-it apply -f examples/kind-demo/insecure.yaml
kubectl --context kind-kba-it -n audit-demo wait --for=condition=Ready pod/hardened --timeout=120s
K8S_BASELINE_AUDIT_IT_CONTEXT=kind-kba-it pdm run pytest -m integration -v
```

Expected: 4 passed. If the insecure pod's set differs, compare against `examples/kind-demo/insecure.yaml` line by line: a missing check is a bug in the check, an extra one means the manifest or the expectation is wrong. Fix the cause, not the expectation, unless the manifest really triggers it. Keep the cluster for Task 19.

- [ ] **Step 3: Write the CI workflow**

`.github/workflows/ci.yml`:

```yaml
name: ci
on:
  push:
    branches: ["**"]
  pull_request:

permissions:
  contents: read

jobs:
  unit:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python: ["3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: pdm-project/setup-pdm@v4
        with:
          python-version: ${{ matrix.python }}
      - run: sudo apt-get update && sudo apt-get install -y jq shellcheck
      - run: pdm install
      - run: pdm run ruff check .
      - run: shellcheck -s sh scripts/export-bundle.sh scripts/install-skill.sh
      - run: pdm run pytest -v

  integration:
    runs-on: ubuntu-latest
    needs: unit
    steps:
      - uses: actions/checkout@v4
      - uses: pdm-project/setup-pdm@v4
        with:
          python-version: "3.12"
      - uses: helm/kind-action@v1
        with:
          cluster_name: kba-ci
      - run: kubectl apply -f examples/kind-demo/insecure.yaml
      - run: kubectl -n audit-demo wait --for=condition=Ready pod/hardened --timeout=180s
      - run: pdm install
      - run: K8S_BASELINE_AUDIT_IT_CONTEXT=kind-kba-ci pdm run pytest -m integration -v
```

Check the action versions against their repositories before committing (`firecrawl search "pdm-project/setup-pdm latest release"`, same for `helm/kind-action`), and use the current major version.

- [ ] **Step 4: Commit**

```bash
git add tests/integration .github/workflows/ci.yml
git commit -m "test: kind integration test with read-only snapshot and CI workflow"
```

---

### Task 19: README, example report and acceptance run

**Files:**
- Create: `README.md` (replace stub), `examples/kind-demo/report.de.md`, `examples/kind-demo/report.en.md`, `docs/acceptance/2026-kubeadm-acceptance.md`
- Modify: `docs/superpowers/specs/2026-09-30-k8s-baseline-audit-design.md` (acceptance result)

**Interfaces:**
- Consumes: everything above. This task is run by the main thread, not delegated (user rule: build + tests and acceptance evidence are verified by the main thread).

- [ ] **Step 1: Generate the example report from the kind demo cluster**

```bash
mkdir -p /tmp/kba-example
pdm run k8s-baseline-audit collect --context kind-kba-it --out /tmp/kba-example
B=$(ls -d /tmp/kba-example/bundle-* | tail -1)
pdm run k8s-baseline-audit analyze "$B" --out /tmp/kba-example/analysis || test $? -eq 1
```

Write the two narrative files for the demo by following `skill/k8s-baseline-audit/SKILL.md` Step 4 exactly, then:

```bash
pdm run k8s-baseline-audit report /tmp/kba-example/analysis --bundle "$B" --out examples/kind-demo \
  --narrative-de /tmp/kba-example/analysis/narrative.de.json --narrative-en /tmp/kba-example/analysis/narrative.en.json
grep -c "hunter2-demo" examples/kind-demo/report.*.md   # expected 0 for both
kind delete cluster --name kba-it
```

- [ ] **Step 2: Write the README**

`README.md` must contain, in this order:

1. **Title and one-sentence purpose**: read-only Kubernetes security audit mapped to BSI IT-Grundschutz APP.4.4 and SYS.1.6, German and English reports.
2. **Disclaimer** (bold, near the top): no certification, no legal advice, not affiliated with or endorsed by the BSI.
3. **What it checks**: the check groups table from spec section 5, and the three access modes from spec section 3.
4. **What it does not check**: runtime behavior, supply chain, cloud IAM, host OS hardening, organizational requirements beyond the interview questions.
5. **Install**: `pipx install git+https://github.com/hakanyedibela/k8s-baseline-audit`, requirements (Python 3.11+, kubectl; optional kubescape, trivy; jq for the export script).
6. **Quick start** with the three commands from SKILL.md Steps 2, 3, 5.
7. **Offline bundles**: how a client runs `scripts/export-bundle.sh`, what it collects, what it redacts, that it only reads.
8. **kube-bench**: how to run the upstream Job with `--json` yourself and pass results with `--kube-bench-result`.
9. **Use with AI agents**: the install script, the list of verified agents from Task 17, the rule that the agent writes only labeled narrative text.
10. **Example report**: links to `examples/kind-demo/report.de.md` and `report.en.md`.
11. **Coverage statuses**: the table from spec section 7, including why "fulfilled" is never used.
12. **Framework versioning**: Kompendium 2023 now, Grundschutz++ later, with the source verification from Task 10 Step 1.
13. **Deutsch** section: three to five sentences in German with the keywords "IT-Grundschutz", "Kubernetes", "BSI-Audit", "KRITIS" for discoverability.
14. **License**: Apache-2.0.

- [ ] **Step 3: Acceptance run on the kubeadm cluster (main thread only)**

The collector is read-only, but this is a real cluster: confirm the context with the user before running.

```bash
switchKubeadm
kubectl config current-context        # show to the user; proceed only after their confirmation
mkdir -p ./audit
pdm run k8s-baseline-audit collect --out ./audit
B=$(ls -d ./audit/bundle-* | tail -1)
pdm run k8s-baseline-audit analyze "$B" --out ./audit/analysis; echo "exit $?"
```

Write the narratives per SKILL.md Step 4, render with SKILL.md Step 5, then review by hand and record in `docs/acceptance/2026-kubeadm-acceptance.md` (no cluster secrets, no bundle contents beyond counts):

- [ ] every finding in the report cites an evidence file and path that exists in the bundle
- [ ] `control_plane.etcd_listen_non_loopback` fires (the etcd client URL on 10.211.55.31 was found during design)
- [ ] the kubeadm default bindings produce no identity findings
- [ ] every requirement of both modules appears in the matrix
- [ ] the "not checked" appendix lists every warning the collector printed
- [ ] German and English reports list the same finding IDs in the same order
- [ ] no forbidden word appears (`grep -ciE 'erfüllt|fulfilled|compliant|konform' ./audit/report/*.md` → 0)
- [ ] no secret value appears (spot-check three secrets you know exist: `grep -c` their values across `./audit`)

Record false positives and misses as numbered issues in the acceptance file. Fix what blocks acceptance; list the rest as follow-ups.

- [ ] **Step 4: Final verification (main thread)**

```bash
pdm run ruff check .
pdm run pytest -v
shellcheck -s sh scripts/export-bundle.sh scripts/install-skill.sh
git status --short
```

Paste the real output into the handoff to the user. `./audit/` is gitignored; confirm it does not appear in `git status`.

- [ ] **Step 5: Commit**

```bash
git add README.md examples docs
git commit -m "docs: README, example report from kind demo, kubeadm acceptance record"
```

Publishing (creating the GitHub repository, pushing, a PyPI release) is **not** part of this plan. It needs the user's explicit go and a `/cso --diff` run first.

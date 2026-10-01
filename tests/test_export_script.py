"""Parity tests: scripts/export-bundle.sh must match the Python collector byte for byte in content.

The script is run against a fake kubectl (a Python shim on PATH). The Python collector is run
against the same shim, and both bundles are compared file by file.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from k8s_baseline_audit.analyze.checks.base import AnalyzerConfig
from k8s_baseline_audit.analyze.pipeline import analyze
from k8s_baseline_audit.bundle import load_bundle
from k8s_baseline_audit.collect.collector import CollectOptions, collect
from k8s_baseline_audit.collect.redact import LAST_APPLIED, parse_secret_rows, redact_pod_list
from k8s_baseline_audit.collect.runner import CommandResult, KubectlRunner
from k8s_baseline_audit.collect.sanitize import (
    sanitize_kube_bench,
    sanitize_kubescape,
    sanitize_trivy,
)
from k8s_baseline_audit.mapping.schema import load_mapping

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "export-bundle.sh"
FIXTURES = ROOT / "tests" / "fixtures" / "scanners"
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
def kinds(name):
    return set(filter(None, os.environ.get(name, "").split(",")))
LONG_ERR = os.environ.get("FAKE_STDERR") or (
    "  \\n" + "x" * 300 + "\\n" + "Error from server: " + "y" * 300 + " \\n\\n")
verb = args[0]
if verb == "config":
    sys.stdout.write("kind-test\\n" if args[1] == "current-context" else "https://127.0.0.1:6443")
    sys.exit(0)
if verb == "version":
    if os.environ.get("FAKE_VERSION_FAIL"):
        sys.stdout.write("not json")
        sys.stderr.write("Unable to connect to the server\\n")
        sys.exit(1)
    print(json.dumps({"serverVersion": {"major": "1", "minor": "35"}}))
    sys.exit(0)
if verb == "auth":
    kind = args[3]
    if kind in kinds("FAKE_FORBIDDEN"):
        print("no")
        sys.exit(1)
    if kind in kinds("FAKE_CANI_FAIL"):
        sys.stdout.write("stdout-must-not-leak")
        sys.stderr.write(os.environ.get("FAKE_STDERR") or
                         "error: You must be logged in to the server (Unauthorized)\\n")
        sys.exit(2)
    print("yes")
    sys.exit(0)
if verb == "get":
    kind = args[1]
    if kind in kinds("FAKE_GET_FAIL"):
        sys.stdout.write("stdout-must-not-leak")
        sys.stderr.write(LONG_ERR)
        sys.exit(1)
    if kind == "secrets":
        tmp = os.environ.get("TMPDIR")
        if tmp:
            for base, _dirs, files in os.walk(tmp):
                for name in files:
                    try:
                        text = open(os.path.join(base, name), errors="replace").read()
                    except OSError:
                        continue
                    if "s3cr3t-value-123" in text:
                        open(os.environ["FAKE_LEAK_FILE"], "a").write(os.path.join(base, name))
        sys.stdout.write(open(os.path.join(data, "secrets.tsv")).read())
        sys.exit(0)
    path = os.path.join(data, kind + ".json")
    sys.stdout.write(open(path).read() if os.path.exists(path) else '{"items": []}')
    sys.exit(0)
sys.stderr.write("unexpected kubectl call: " + " ".join(args))
sys.exit(99)
"""

BRIEF_PODS = {
    "items": [
        {
            "metadata": {
                "name": "web",
                "namespace": "default",
                "annotations": {LAST_APPLIED: SECRET, "keep": "me"},
            },
            "spec": {
                "initContainers": [{"name": "init", "env": [{"name": "A", "value": SECRET}]}],
                "containers": [
                    {
                        "name": "app",
                        "image": "nginx:latest",
                        "env": [
                            {"name": "DB_PASSWORD", "value": SECRET},
                            {"name": "EMPTY", "value": ""},
                            {
                                "name": "REF",
                                "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}},
                            },
                        ],
                        "args": [f"--db-password={SECRET}", "--port=8080"],
                    }
                ],
            },
        },
        {"metadata": {"name": "bare", "namespace": "default"}},
    ]
}

# Every redaction rule (A, B, C, D, safe values, probes, lifecycle, headers, volumes,
# status, annotations) and the odd-but-valid shapes the Python code tolerates.
RULE_ARGS = [
    f"--db-password={SECRET}",  # A
    f"--API_KEY={SECRET}",  # A, case-insensitive
    f'--password="{SECRET} b c"',  # A, quoted value with spaces
    f"--dsn=postgres://u:{SECRET}@h/d",  # A wins over C
    f"--password={SECRET}\n",  # A with trailing newline
    f"--password={SECRET}\nmore",  # A fails on inner newline, D applies
    f"--paſſword={SECRET}",  # A, Unicode case folding
    f"--päss-token={SECRET}",  # A, Unicode word chars in key
    "--password=",  # A, empty value stays
    "--token",
    SECRET,  # B
    "--Bearer",
    SECRET,  # B
    "--password",
    "/etc/pw",  # B, safe path
    "--secret",
    "TRUE",  # B, safe boolean
    "--password",
    "",  # B, empty next stays
    "--secret",
    "--next-flag",  # B, next is a flag
    f"DATABASE_URL=postgres://u:{SECRET}@h/d",  # C
    f"see https://admin:{SECRET}@example.com/x and ftp://u:{SECRET}@f",  # C twice
    "--enable-bootstrap-token-auth=true",  # safe values survive
    "--authentication-token-webhook=TRUE",
    "--token-auth-file=/etc/k/tokens.csv",
    "--anonymous-auth=false",
    "--encryption-provider-config=/etc/k/enc.yaml",
    "--port=8080",
    42,
    None,
    True,
    {"k": "plain"},  # non-strings pass through
    # Addendum v2.2: Turkish i folding and tightened safe values
    f"--APİ_KEY={SECRET}",
    f"--apı-key={SECRET}",
    f"--prıvate-key={SECRET}",
    f"--credentıal={SECRET}",
    "--APİKEY", SECRET,
    f"ı://u:{SECRET}@h",
    f"PASSWORD=/tmp; mysql --password={SECRET}",
    f"TOKEN_FILE=/var/run/x && app --token={SECRET}",
    "--password", f"/etc/a {SECRET}",
    "--token-auth-file=/etc/k/t.csv",
    "--audit-log-path=/var/log/x",
    "--token",  # B at the end, no next element
]
SHELL_CMD = (
    f"mysql --password={SECRET} -h x && run --token='{SECRET} b' --x=1 "
    f"--pwd=\"{SECRET}\" --flag-token=true --cfg-secret=/etc/x --secret='' "
    f"--dsn=\"/abs\" --apikey='TRUE' PASSWORD={SECRET};echo "
    f"&& PASSWORD=/tmp; mysql --password={SECRET} && TOKEN_FILE=/var/run/x "
    f"&& app --token={SECRET} --x-token='/a {SECRET}' ı://u:{SECRET}@h --apı-key={SECRET}"
)
RULE_PODS = {
    "apiVersion": "v1",
    "kind": "List",
    "items": [
        {
            "metadata": {
                "name": "rules",
                "namespace": "default",
                "annotations": {LAST_APPLIED: SECRET, "note": SECRET},
                "labels": {"app": "rules"},
            },
            "status": {"message": SECRET, "phase": "Running"},
            "spec": {
                "volumes": [
                    {
                        "name": "flex",
                        "flexVolume": {"driver": "d", "options": {"password": SECRET, "n": 1}},
                    },
                    {"name": "flex-no-opts", "flexVolume": {"driver": "d"}},
                    {"name": "csi", "csi": {"driver": "c", "volumeAttributes": {"token": SECRET}}},
                    {"name": "csi-empty", "csi": {}},
                    {"name": "host", "hostPath": {"path": "/var/lib"}},
                ],
                "containers": [
                    {
                        "name": "app",
                        "command": ["sh", "-c", SHELL_CMD],
                        "args": RULE_ARGS,
                        "env": [
                            {"name": "A", "value": SECRET},
                            {"name": "EMPTY", "value": ""},
                            {"name": "ZERO", "value": 0},
                            {"name": "NUM", "value": 7},
                            {"name": "FALSE", "value": False},
                            {"name": "NULL", "value": None},
                            {
                                "name": "REF",
                                "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}},
                            },
                        ],
                        "livenessProbe": {
                            "exec": {"command": ["sh", "-c", f"PASSWORD={SECRET} check"]}
                        },
                        "readinessProbe": {
                            "httpGet": {
                                "path": "/healthz",
                                "httpHeaders": [
                                    {"name": "Authorization", "value": f"Bearer {SECRET}"},
                                    {"name": "X-Empty", "value": ""},
                                    "not-a-dict",
                                ],
                            }
                        },
                        "startupProbe": {"exec": None, "httpGet": None},
                        "lifecycle": {
                            "postStart": {"exec": {"command": ["--token", SECRET]}},
                            "preStop": {
                                "httpGet": {"httpHeaders": [{"name": "X-Token", "value": SECRET}]}
                            },
                        },
                    },
                    {
                        "name": "odd",
                        "command": [],
                        "args": "x",
                        "env": [],
                        "livenessProbe": {"exec": {"command": ""}},
                        "readinessProbe": {"exec": {"command": {}}, "httpGet": {"httpHeaders": {}}},
                        "startupProbe": {},
                        "lifecycle": {"postStart": "not-a-dict", "preStop": None},
                    },
                    {"name": "minimal"},
                ],
                "initContainers": [{"name": "init", "args": ["--token", SECRET]}],
                "ephemeralContainers": [{"name": "debug", "command": [f"--secret={SECRET}"]}],
            },
        },
        {"metadata": None, "spec": None},
        {"metadata": {}, "spec": {"volumes": []}},
        {},
    ],
}

TSV = (
    "default\tdb\tOpaque\tuser,password,\n"
    "kube-system\ttok\tkubernetes.io/service-account-token\t\n\n"
)

KS = {
    "resources": [
        {
            "resourceID": "full",
            "object": {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "web", "namespace": "default", "annotations": {"a": SECRET}},
                "spec": {"env": SECRET},
            },
        },
        {
            "resourceID": "flat",
            "object": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "r",
                "namespace": None,
                "relatedObjects": [{"data": SECRET}],
            },
        },
        {"resourceID": "md-not-dict", "object": {"kind": "X", "metadata": SECRET.upper()}},
        {"resourceID": "string-object", "object": "kept"},
        {"resourceID": "no-object"},
    ],
    "results": [{"resourceID": "full", "controls": []}],
    "summaryDetails": {"frameworks": []},
}
TV = {
    "ClusterName": "kind-test",
    "Resources": [
        {
            "Kind": "Pod",
            "Name": "web",
            "Namespace": "default",
            "Metadata": [
                {
                    "RepoTags": ["nginx:latest"],
                    "RepoDigests": ["nginx@sha256:abc"],
                    "ImageID": "sha256:def",
                    "OS": {"Family": "debian", "Name": "12"},
                    "ImageConfig": {"config": {"Env": [f"DB_PASSWORD={SECRET}"]}},
                    "Layers": [{"DiffID": SECRET}],
                },
                "not-a-dict",
            ],
            "Results": [
                {
                    "Target": "t",
                    "Metadata": {"ImageConfig": {"history": [SECRET]}, "RepoTags": None},
                    "Misconfigurations": [
                        {"ID": "KSV017", "Status": "FAIL", "CauseMetadata": {"Code": SECRET}}
                    ],
                },
                {
                    "Secrets": [
                        {"RuleID": "x", "Match": SECRET, "Code": {"Lines": [SECRET]}, "Title": "t"},
                        {
                            "RuleID": "aws",
                            "Category": "AWS",
                            "Severity": "CRITICAL",
                            "StartLine": 1,
                            "EndLine": 2,
                            "Offset": SECRET,
                            "Layer": {
                                "Digest": "sha256:a",
                                "DiffID": "sha256:b",
                                "CreatedBy": SECRET,
                            },
                        },
                        {"RuleID": "odd-layer", "Layer": SECRET},
                    ]
                },
                {"Vulnerabilities": [{"VulnerabilityID": "CVE-1"}], "Misconfigurations": None},
            ],
        },
        {"Kind": "Node", "Metadata": {"ImageID": "x", "Extra": SECRET}},
        {"Kind": "Deployment", "Metadata": "string-meta", "Results": []},
    ],
}
KB = {
    "Controls": [
        {
            "id": "1",
            "tests": [
                {
                    "section": "1.1",
                    "results": [
                        {
                            "test_number": "1.1.1",
                            "status": "FAIL",
                            "actual_value": SECRET,
                            "AuditConfig": SECRET,
                            "AuditEnv": SECRET,
                            "expected_result": SECRET,
                            "remediation": "chmod 600",
                            "reason": SECRET,
                            "audit": SECRET,
                            "unknown_future_key": SECRET,
                            "test_desc": "Ensure x",
                            "scored": True,
                            "type": "",
                        }
                    ],
                },
                {"section": "1.2", "results": None},
            ],
        },
        {"id": "2", "tests": []},
    ],
    "Totals": {"total_fail": 1},
}


@pytest.fixture
def env(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "pods.json").write_text(json.dumps(BRIEF_PODS))
    (data / "secrets.tsv").write_text(TSV)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shim = bin_dir / "kubectl"
    shim.write_text(SHIM.replace("{python}", sys.executable))
    shim.chmod(0o755)
    for name, doc in (("ks.json", KS), ("tv.json", TV), ("kb.json", KB)):
        (tmp_path / name).write_text(json.dumps(doc))
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    environ = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_KUBECTL_DIR": str(data),
        "FAKE_KUBECTL_LOG": str(tmp_path / "calls.log"),
        "FAKE_LEAK_FILE": str(tmp_path / "leak.txt"),
        "TMPDIR": str(scratch),
    }
    return tmp_path, environ


def run(tmp_path, environ, *extra, out="out"):
    return subprocess.run(
        ["sh", str(SCRIPT), "-o", str(tmp_path / out), *extra],
        env=environ,
        capture_output=True,
        text=True,
        check=False,
    )


def full_run(tmp_path, environ, *extra):
    proc = run(
        tmp_path,
        environ,
        "-k",
        str(tmp_path / "ks.json"),
        "-t",
        str(tmp_path / "tv.json"),
        "-b",
        f"cp 1={tmp_path / 'kb.json'}",
        *extra,
    )
    assert proc.returncode == 0, proc.stderr
    return Path(proc.stdout.strip().splitlines()[-1])


def script_bundle(tmp_path, environ, *extra):
    proc = run(tmp_path, environ, *extra)
    assert proc.returncode == 0, proc.stderr
    return load_bundle(Path(proc.stdout.strip().splitlines()[-1]))


def python_bundle(tmp_path, environ, context=None):
    def shim_exec(argv):
        proc = subprocess.run(list(argv), env=environ, capture_output=True, text=True, check=False)
        return CommandResult(tuple(argv), proc.returncode, proc.stdout, proc.stderr)

    runner = KubectlRunner(context=context, exec_fn=shim_exec)
    options = CollectOptions(tool_version="0.1.0", now=datetime.now(UTC))
    return load_bundle(collect(runner, tmp_path / "py-out", options))


def assert_same_as_python(script, py):
    assert script.provenance_verified and py.provenance_verified
    assert sorted(script.manifest["files"]) == sorted(py.manifest["files"])
    for rel in py.manifest["files"]:
        assert script.read_json(rel) == py.read_json(rel), rel
    assert script.manifest["commands"] == py.manifest["commands"]
    assert script.manifest["cluster"] == py.manifest["cluster"]
    assert script.manifest["schema"] == py.manifest["schema"]


def set_pods(tmp_path, raw):
    (tmp_path / "data" / "pods.json").write_text(raw)


# --- brief tests -------------------------------------------------------------------------------


def test_bundle_is_verified_and_matches_python_rules(env):
    tmp_path, environ = env
    root = full_run(tmp_path, environ)
    b = load_bundle(root)
    assert b.provenance_verified
    assert b.manifest["producer"] == "export-script"
    assert b.manifest["cluster"] == {"context": "kind-test", "server": "https://127.0.0.1:6443"}
    assert b.read_json("resources/pods.json") == redact_pod_list(BRIEF_PODS)
    assert b.read_json("resources/secrets.json") == parse_secret_rows(TSV)
    assert b.read_json("scanners/kubescape.json") == sanitize_kubescape(KS)
    assert b.read_json("scanners/trivy.json") == sanitize_trivy(TV)
    assert b.read_json("scanners/kube-bench-cp-1.json") == sanitize_kube_bench(KB)
    assert b.manifest["scanners"] == {
        "kubescape": {"status": "imported"},
        "trivy": {"status": "imported"},
        "kube-bench": {"status": "imported", "nodes": ["cp-1"]},
    }


def test_no_secret_on_disk(env):
    tmp_path, environ = env
    set_pods(tmp_path, json.dumps(RULE_PODS))
    root = full_run(tmp_path, environ)
    for path in root.rglob("*"):
        if path.is_file():
            assert SECRET not in path.read_text(), path


def test_raw_kubectl_output_never_touches_temp_disk(env):
    # The shim scans TMPDIR for the planted secret while the script is still running
    # (at the last kubectl call, after pods were processed).
    tmp_path, environ = env
    set_pods(tmp_path, json.dumps(RULE_PODS))
    full_run(tmp_path, environ)
    assert not (tmp_path / "leak.txt").exists(), (tmp_path / "leak.txt").read_text()
    assert list((tmp_path / "scratch").iterdir()) == []


def test_only_read_commands(env):
    tmp_path, environ = env
    full_run(tmp_path, environ)
    calls = [json.loads(line) for line in (tmp_path / "calls.log").read_text().splitlines()]
    assert {c[0] for c in calls} <= {"get", "version", "auth", "config"}
    assert all(c[1] == "can-i" for c in calls if c[0] == "auth")
    assert all(c[1] in ("current-context", "view") for c in calls if c[0] == "config")


def test_script_calls_kubectl_only_through_the_allowlist():
    # Exactly one line executes kubectl, inside kc_exec, which only runs after kc_check.
    text = SCRIPT.read_text()
    assert re.findall(r"^\s*kubectl .*$", text, re.M) == [
        '  kubectl "$@" 2> "$TMP/stderr" || rc=$?'
    ]
    assert "eval" not in text


def test_forbidden_kind_matches_python_error(env):
    tmp_path, environ = env
    environ["FAKE_FORBIDDEN"] = "nodes"
    b = load_bundle(full_run(tmp_path, environ))
    assert b.preflight["nodes"] is False
    assert {
        "resource": "nodes",
        "reason": "forbidden: kubectl auth can-i list returned no",
    } in b.errors
    assert not b.has("resources/nodes.json")


def test_failed_preflight_matches_python_wording(env):
    tmp_path, environ = env
    environ["FAKE_CANI_FAIL"] = "roles"
    environ["FAKE_FORBIDDEN"] = "nodes"
    b = script_bundle(tmp_path, environ)
    assert b.preflight["roles"] is False
    assert {
        "resource": "roles",
        "reason": "preflight failed: kubectl exit 2: "
        "error: You must be logged in to the server (Unauthorized)",
    } in b.errors
    assert {
        "resource": "nodes",
        "reason": "forbidden: kubectl auth can-i list returned no",
    } in b.errors
    assert "stdout-must-not-leak" not in json.dumps(b.errors)
    assert_same_as_python(b, python_bundle(tmp_path, environ))


def test_analyzer_accepts_export_bundle(env):
    tmp_path, environ = env
    b = load_bundle(full_run(tmp_path, environ))
    result = analyze(
        b, load_mapping(), AnalyzerConfig(as_of=date(2026, 9, 30)), tool_version="0.1.0"
    )
    assert any(f.check_id == "secrets.credential_literal_env" for f in result.findings)


@pytest.mark.parametrize("case", ["no-args", "missing-value", "bad-kube-bench", "kb-missing-file"])
def test_bad_arguments_exit_2(env, case):
    tmp_path, environ = env
    args = {
        "no-args": [],
        "missing-value": ["-o"],
        "bad-kube-bench": ["-o", str(tmp_path / "out"), "-b", "no-equals"],
        "kb-missing-file": ["-o", str(tmp_path / "out"), "-b", f"n={tmp_path / 'nope.json'}"],
    }[case]
    proc = subprocess.run(
        ["sh", str(SCRIPT), *args], env=environ, capture_output=True, text=True, check=False
    )
    assert proc.returncode == 2
    assert not (tmp_path / "out").exists() or not any((tmp_path / "out").iterdir())
    assert not (tmp_path / "calls.log").exists()


# --- parity with the Python collector ----------------------------------------------------------


def test_rule_pods_match_python_redaction(env):
    tmp_path, environ = env
    set_pods(tmp_path, json.dumps(RULE_PODS))
    b = script_bundle(tmp_path, environ)
    pods = b.read_json("resources/pods.json")
    assert pods == redact_pod_list(RULE_PODS)
    app = pods["items"][0]["spec"]["containers"][0]
    assert app["args"][:3] == [
        "--db-password=<redacted>",
        "--API_KEY=<redacted>",
        "--password=<redacted>",
    ]
    assert "status" not in pods["items"][0]
    assert "annotations" not in pods["items"][0]["metadata"]
    assert_same_as_python(b, python_bundle(tmp_path, environ))


@pytest.mark.parametrize(
    "scenario",
    [
        {},
        {"FAKE_FORBIDDEN": "nodes,secrets", "FAKE_CANI_FAIL": "roles"},
        {"FAKE_GET_FAIL": "clusterroles,pods,secrets", "FAKE_VERSION_FAIL": "1"},
    ],
    ids=["clean", "preflight", "get-failures"],
)
def test_bundle_matches_python_collector(env, scenario):
    tmp_path, environ = env
    environ.update(scenario)
    assert_same_as_python(script_bundle(tmp_path, environ), python_bundle(tmp_path, environ))


def test_context_flag_matches_python_collector(env):
    tmp_path, environ = env
    script = script_bundle(tmp_path, environ, "-c", "kind-test")
    assert all(c["argv"][1:3] == ["--context", "kind-test"] for c in script.manifest["commands"])
    assert_same_as_python(script, python_bundle(tmp_path, environ, context="kind-test"))


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("{not json", "kubectl returned invalid JSON"),
        ("", "kubectl returned invalid JSON"),
        ('{"items": []} {"items": []}', "kubectl returned invalid JSON"),
        ('{"kind": "List"}', "unexpected kubectl output shape"),
        ('{"items": {"a": 1}}', "unexpected kubectl output shape"),
        ("[]", "unexpected kubectl output shape"),
        ("null", "unexpected kubectl output shape"),
    ],
)
def test_bad_pods_output_matches_python_collector(env, raw, reason):
    tmp_path, environ = env
    set_pods(tmp_path, raw)
    b = script_bundle(tmp_path, environ)
    assert {"resource": "pods", "reason": reason} in b.errors
    assert not b.has("resources/pods.json")
    assert_same_as_python(b, python_bundle(tmp_path, environ))


@pytest.mark.parametrize(
    "doc",
    [
        {"items": [1]},
        {"items": [{"metadata": "x"}]},
        {"items": [{"spec": {"containers": {"a": 1}}}]},
        {"items": [{"spec": {"containers": [{"env": [SECRET]}]}}]},
        {"items": [{"spec": {"containers": [{"command": {"a": SECRET}}]}}]},
        {"items": [{"spec": {"containers": [{"livenessProbe": {"exec": {"command": None}}}]}}]},
        {"items": [{"spec": {"volumes": [{"flexVolume": [SECRET]}]}}]},
    ],
)
def test_pod_item_shapes_python_rejects_are_not_written(env, doc):
    # Python raises (TypeError/AttributeError/KeyError) on these; the script fails closed
    # and records a shape error instead of writing pods.json.
    tmp_path, environ = env
    with pytest.raises(Exception):  # noqa: B017
        redact_pod_list(doc)
    set_pods(tmp_path, json.dumps(doc))
    b = script_bundle(tmp_path, environ)
    assert {"resource": "pods", "reason": "unexpected kubectl output shape"} in b.errors
    assert not b.has("resources/pods.json")


@pytest.mark.parametrize("name", ["kubescape.json", "trivy.json", "kube-bench-node.json"])
def test_real_scanner_fixtures_match_python(env, name):
    tmp_path, environ = env
    flag, rel, fn = {
        "kubescape.json": ("-k", "scanners/kubescape.json", sanitize_kubescape),
        "trivy.json": ("-t", "scanners/trivy.json", sanitize_trivy),
        "kube-bench-node.json": ("-b", "scanners/kube-bench-node.json", sanitize_kube_bench),
    }[name]
    value = f"node={FIXTURES / name}" if flag == "-b" else str(FIXTURES / name)
    b = script_bundle(tmp_path, environ, flag, value)
    assert b.read_json(rel) == fn(json.loads((FIXTURES / name).read_text()))


@pytest.mark.parametrize(
    ("flag", "content"),
    [
        ("-k", "[]"),
        ("-k", "{broken"),
        ("-t", '{"Resources": [1]}'),
        ("-t", '{"Resources": [{"Results": [{"Secrets": [[1]]}]}]}'),
        ("-b", '"text"'),
        ("-b", '{"Controls": [{"tests": [{"results": ["x"]}]}]}'),
        ("-b", "{}"),
        ("-b", '{"Controls": null}'),
        ("-k", '{"resources": []}'),
        ("-k", '{"results": [], "resources": null}'),
        ("-k", '{"results": {}}'),
        ("-t", '{"ClusterName": "x"}'),
        ("-t", '{"Resources": null}'),
        ("-t", '{"Resources": [{"Results": [{"Secrets": ["x"]}]}]}'),
    ],
)
def test_bad_scanner_input_exits_2_before_any_kubectl_call(env, flag, content):
    tmp_path, environ = env
    bad = tmp_path / "bad.json"
    bad.write_text(content)
    value = f"n={bad}" if flag == "-b" else str(bad)
    proc = run(tmp_path, environ, flag, value)
    assert proc.returncode == 2, proc.stderr
    assert not (tmp_path / "out").exists() or not any((tmp_path / "out").iterdir())
    assert not (tmp_path / "calls.log").exists()


def test_duplicate_kube_bench_node_exits_2(env):
    tmp_path, environ = env
    kb = tmp_path / "kb.json"
    proc = run(tmp_path, environ, "-b", f"cp 1={kb}", "-b", f"cp-1={kb}")
    assert proc.returncode == 2
    assert not (tmp_path / "calls.log").exists()


def test_python_sanitizers_reject_the_same_bad_scanner_input():
    from k8s_baseline_audit.collect.sanitize import SanitizeShapeError

    bad = {
        sanitize_kube_bench: [
            {},
            {"Controls": None},
            {"Controls": [{"tests": [{"results": ["x"]}]}]},
        ],
        sanitize_kubescape: [
            {"resources": []},
            {"results": [], "resources": None},
            {"results": {}},
        ],
        sanitize_trivy: [
            {"ClusterName": "x"},
            {"Resources": None},
            {"Resources": [{"Results": [{"Secrets": ["x"]}]}]},
        ],
    }
    for fn, docs in bad.items():
        for doc in docs:
            with pytest.raises((SanitizeShapeError, AttributeError, TypeError)):
                fn(doc)


def test_sanitized_scanner_files_drop_non_allowlisted_fields(env):
    tmp_path, environ = env
    b = load_bundle(full_run(tmp_path, environ))
    trivy = b.read_json("scanners/trivy.json")
    secrets = trivy["Resources"][0]["Results"][1]["Secrets"]
    assert secrets[1]["Layer"] == {"Digest": "sha256:a", "DiffID": "sha256:b"}
    assert secrets[2] == {"RuleID": "odd-layer"}
    result = b.read_json("scanners/kube-bench-cp-1.json")["Controls"][0]["tests"][0]["results"][0]
    assert sorted(result) == ["remediation", "scored", "status", "test_desc", "test_number", "type"]
    for rel in ("scanners/trivy.json", "scanners/kube-bench-cp-1.json"):
        assert SECRET not in json.dumps(b.read_json(rel))


LEAKY_STDERR = "Error: --password=LEAK1 dial postgres://u:LEAK2@h:5432 x token='LEAK3 y'\n"


def test_kubectl_stderr_is_redacted_like_python(env):
    tmp_path, environ = env
    environ.update(
        {
            "FAKE_STDERR": LEAKY_STDERR,
            "FAKE_GET_FAIL": "pods,clusterroles",
            "FAKE_CANI_FAIL": "roles",
        }
    )
    script = script_bundle(tmp_path, environ)
    assert "LEAK" not in json.dumps(script.errors)
    assert {
        "resource": "pods",
        "reason": "kubectl exit 1: Error: --password=<redacted> dial "
        "postgres://u:<redacted>@h:5432 x token=<redacted>",
    } in script.errors
    assert_same_as_python(script, python_bundle(tmp_path, environ))

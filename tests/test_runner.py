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

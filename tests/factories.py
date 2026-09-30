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

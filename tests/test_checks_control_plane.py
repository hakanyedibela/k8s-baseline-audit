from datetime import date

import pytest
from factories import ctx, pod, run_check

from k8s_baseline_audit.analyze.checks import control_plane
from k8s_baseline_audit.analyze.checks.base import AnalyzerConfig, ManualCheckNeeded


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
    assert (
        run_check(
            "control_plane.etcd_listen_non_loopback", ctx(pods=[static("etcd", ETCD_LOOPBACK)])
        )
        == []
    )
    hits = run_check(
        "control_plane.etcd_listen_non_loopback", ctx(pods=[static("etcd", ETCD_EXPOSED)])
    )
    assert len(hits) == 1


@pytest.fixture
def table(monkeypatch):
    t = {
        "retrieved": "2026-09-30",
        "source": "test",
        "releases": {"1.33": "2026-06-28", "1.35": "2027-02-28"},
    }
    monkeypatch.setattr(control_plane, "support_table", lambda: t)


def version(minor):
    return [{"serverVersion": {"major": "1", "minor": minor, "gitVersion": f"v1.{minor}.0"}}]


def test_version_supported(table):
    assert run_check("version.unsupported", ctx(version=version("35"))) == []


def test_version_out_of_support(table):
    hits = run_check("version.unsupported", ctx(version=version("33")))
    assert [(h.resource.key(), h.evidence.json_path) for h in hits] == [
        ("Cluster/-/cluster", "$.serverVersion")
    ]


def test_managed_minor_suffix_is_stripped(table):
    assert run_check("version.unsupported", ctx(version=version("35+"))) == []


def test_unknown_version_needs_manual_check(table):
    with pytest.raises(ManualCheckNeeded, match="not in support table"):
        run_check("version.unsupported", ctx(version=version("99")))


def test_version_older_than_table_is_out_of_support(table):
    hits = run_check("version.unsupported", ctx(version=version("20")))
    assert [h.evidence.json_path for h in hits] == ["$.serverVersion"]


@pytest.mark.parametrize("doc", [[{}], [], [{"serverVersion": {"major": "", "minor": "x"}}]])
def test_malformed_version_document_needs_manual_check(table, doc):
    with pytest.raises(ManualCheckNeeded, match="missing or malformed"):
        run_check("version.unsupported", ctx(version=doc))


def test_real_table_with_fixed_date():
    cfg = AnalyzerConfig(as_of=date(2026, 10, 1))
    assert run_check("version.unsupported", ctx(cfg, version=version("29")))
    assert run_check("version.unsupported", ctx(cfg, version=version("35"))) == []


def test_as_of_date_is_used(table):
    later = AnalyzerConfig(as_of=date(2027, 3, 1))
    assert run_check("version.unsupported", ctx(later, version=version("35")))


def test_packaged_table_is_well_formed():
    t = control_plane._load_support_table()
    assert t["source"].startswith("https://kubernetes.io/")
    assert t["releases"]
    for key, value in t["releases"].items():
        assert key.count(".") == 1
        date.fromisoformat(value)


def _ha(component, first, second):
    a = static(component, first)
    b = static(component, second)
    b["metadata"]["name"] = f"{component}-cp2"
    return [a, b]


@pytest.mark.parametrize("check_id", CP_CHECKS)
def test_ha_apiservers_are_all_checked(check_id):
    pods = _ha("kube-apiserver", HARDENED_API, KUBEADM_DEFAULT_API)
    hits = run_check(check_id, ctx(pods=pods))
    assert [h.resource.key() for h in hits] == ["Pod/kube-system/kube-apiserver-cp2"]
    assert hits[0].evidence.json_path == "$.items[1].spec.containers[0].command"
    default = _ha("kube-apiserver", KUBEADM_DEFAULT_API, KUBEADM_DEFAULT_API)
    both = run_check(check_id, ctx(pods=default))
    assert len(both) == 2


def test_ha_etcd_members_are_all_checked():
    hits = run_check(
        "control_plane.etcd_listen_non_loopback",
        ctx(pods=_ha("etcd", ETCD_LOOPBACK, ETCD_EXPOSED)),
    )
    assert [h.resource.key() for h in hits] == ["Pod/kube-system/etcd-cp2"]

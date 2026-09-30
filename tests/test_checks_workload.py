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
        pod(
            containers=[
                container(securityContext=None, resources=None, env=None)  # noqa: E501
            ],
            securityContext=None,
        ),
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
    expected = (
        "$.items[0].spec.initContainers[0].securityContext.privileged"  # noqa: E501
    )
    assert hits[0].evidence.json_path == expected


def test_run_as_root_container_and_pod_level():
    assert run_check("workload.run_as_root", ctx(pods=[bad_pod(runAsUser=0)]))
    c = hardened_container()
    del c["securityContext"]["runAsUser"]
    p = pod(containers=[c], securityContext={"runAsUser": 0})  # noqa: E501
    assert run_check("workload.run_as_root", ctx(pods=[p]))


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
    bad_caps = bad_pod(capabilities={"add": ["SYS_ADMIN"]})  # noqa: E501
    assert run_check("workload.added_capabilities", ctx(pods=[bad_caps]))
    ok = bad_pod(capabilities={"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]})
    assert run_check("workload.added_capabilities", ctx(pods=[ok])) == []


def test_host_namespaces_group_evidence():
    hits = run_check(
        "workload.host_namespaces", ctx(pods=[pod(hostNetwork=True, hostPID=True)])
    )
    expected = [
        "$.items[0].spec.hostNetwork",
        "$.items[0].spec.hostPID",  # noqa: E501
    ]
    assert [h.evidence.json_path for h in hits] == expected


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

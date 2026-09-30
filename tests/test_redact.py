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
    for name in [
        "DB_PASSWORD",
        "api_key",
        "APIKEY",
        "GITHUB_TOKEN",
        "client_secret",
        "PRIVATE_KEY",
    ]:
        assert CREDENTIAL_NAME.search(name), name
    for name in ["PORT", "LOG_LEVEL", "HOSTNAME"]:
        assert not CREDENTIAL_NAME.search(name), name


def test_parse_secret_rows():
    text = (
        "default\tdb\tOpaque\tpassword,user,\n"
        "kube-system\ttok\tkubernetes.io/service-account-token\t\n\n"
    )
    assert parse_secret_rows(text) == {
        "items": [
            {
                "metadata": {"namespace": "default", "name": "db"},
                "type": "Opaque",
                "keys": ["password", "user"],
            },
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

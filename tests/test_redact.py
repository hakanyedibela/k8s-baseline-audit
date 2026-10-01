import copy
import json

import pytest

from k8s_baseline_audit.collect.redact import (
    CREDENTIAL_NAME,
    LAST_APPLIED,
    REDACTED,
    SECRET_TEMPLATE,
    parse_secret_rows,
    redact_argv,
    redact_pod_list,
    redact_text,
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


def test_all_annotations_are_deleted():
    result = redact_pod_list(_pods())
    assert "annotations" not in result["items"][0]["metadata"]


def test_secret_like_args_redacted_with_argv_rules():
    """Args now follow redact_argv rules which are more sophisticated."""
    args = redact_pod_list(_pods())["items"][0]["spec"]["containers"][0]["args"]
    # --db-password=LEAK becomes --db-password=<redacted>
    assert args == [f"--db-password={REDACTED}", "--port=8080"]


def test_control_plane_flags_survive_with_safe_values():
    """Flags with safe values (true/false, paths) survive unchanged."""
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
                                "--enable-bootstrap-token-auth=true",
                                "--authentication-token-webhook=true",
                                "--token-auth-file=/etc/k/tokens.csv",
                            ],
                        }
                    ]
                },
            }
        ]
    }
    result = redact_pod_list(doc)
    cmd = result["items"][0]["spec"]["containers"][0]["command"]
    assert "--anonymous-auth=false" in cmd
    assert "--encryption-provider-config=/etc/k/enc.yaml" in cmd
    assert "--enable-bootstrap-token-auth=true" in cmd
    assert "--authentication-token-webhook=true" in cmd
    assert "--token-auth-file=/etc/k/tokens.csv" in cmd


def test_input_is_not_mutated():
    original = _pods()
    snapshot = copy.deepcopy(original)
    redact_pod_list(original)
    assert original == snapshot


def test_non_list_items_raises():
    """Non-list items shape raises ValueError."""
    with pytest.raises(ValueError, match="expected a kubectl List with items"):
        redact_pod_list({})
    with pytest.raises(ValueError, match="expected a kubectl List with items"):
        redact_pod_list({"items": None})
    with pytest.raises(ValueError, match="expected a kubectl List with items"):
        redact_pod_list({"items": "not-a-list"})


def test_empty_list_returns_empty():
    """Empty list passes through."""
    assert redact_pod_list({"items": []}) == {"items": []}


def test_missing_fields_are_tolerated():
    """Pods without spec, metadata, containers etc. pass through."""
    assert redact_pod_list({"items": [{"metadata": {"name": "x"}}]}) == {
        "items": [{"metadata": {"name": "x"}}]
    }


def test_status_is_deleted():
    """Pod status field is always deleted."""
    doc = {
        "items": [
            {
                "metadata": {"name": "test"},
                "spec": {"containers": []},
                "status": {
                    "phase": "Running",
                    "conditions": [{"message": "secret-found-here"}],
                },
            }
        ]
    }
    result = redact_pod_list(doc)
    assert "status" not in result["items"][0]


def test_redact_argv_two_token_flag():
    """Two-token: flag with secret word followed by non-safe value."""
    argv = ["--token", "abc", "--port", "80"]
    result = redact_argv(argv)
    assert result == ["--token", REDACTED, "--port", "80"]


def test_redact_argv_two_token_flag_safe_path():
    """Two-token with safe path value (starts with /) is unchanged."""
    argv = ["--password", "/etc/pw"]
    result = redact_argv(argv)
    assert result == ["--password", "/etc/pw"]


def test_redact_argv_key_equals_value():
    """Key=value in one element: leak becomes <key>=<redacted>."""
    argv = ["--db-password=mysecret", "--port=8080"]
    result = redact_argv(argv)
    assert result == ["--db-password=<redacted>", "--port=8080"]


def test_redact_argv_safe_boolean_values():
    """Safe values (true/false) are never masked."""
    argv = [
        "--enable-bootstrap-token-auth=true",
        "--authentication-token-webhook=true",
        "--anonymous-auth=false",
    ]
    result = redact_argv(argv)
    assert result == argv


def test_redact_argv_safe_file_paths():
    """Safe values (paths starting with /) are never masked."""
    argv = [
        "--encryption-provider-config=/etc/k/enc.yaml",
        "--token-auth-file=/etc/k/tokens.csv",
    ]
    result = redact_argv(argv)
    assert result == argv


def test_redact_argv_url_credentials():
    """URL credentials are redacted."""
    # dsn contains SECRET_WORD, so Rule A applies: entire value masked
    argv = ["--dsn=postgres://u:pw@h/d"]
    result = redact_argv(argv)
    assert result == ["--dsn=<redacted>"]

    # DATABASE_URL has no SECRET_WORD in key, so Rule C applies: only password masked
    argv2 = ["DATABASE_URL=postgres://u:pw@h/d"]
    result2 = redact_argv(argv2)
    assert result2 == ["DATABASE_URL=postgres://u:<redacted>@h/d"]


def test_redact_argv_quoted_values_with_spaces():
    """Quoted values with spaces are fully masked after =."""
    argv = ['--password="a b c"']
    result = redact_argv(argv)
    assert result == [f"--password={REDACTED}"]


def test_redact_argv_non_string_elements_untouched():
    """Non-string elements pass through unchanged."""
    argv = [123, "--port=80", None, {"key": "val"}]
    result = redact_argv(argv)
    assert result == [123, "--port=80", None, {"key": "val"}]


def test_probe_exec_command_redacted():
    """Probe exec.command is redacted like container command."""
    doc = {
        "items": [
            {
                "metadata": {"name": "test"},
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "livenessProbe": {
                                "exec": {
                                    "command": ["check-db", "--password=LEAK"]
                                }
                            },
                        }
                    ]
                },
            }
        ]
    }
    result = redact_pod_list(doc)
    cmd = result["items"][0]["spec"]["containers"][0]["livenessProbe"]["exec"]["command"]
    assert cmd == ["check-db", f"--password={REDACTED}"]


def test_probe_httpget_headers_values_redacted():
    """httpGet.httpHeaders values (non-empty) are redacted."""
    doc = {
        "items": [
            {
                "metadata": {"name": "test"},
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "readinessProbe": {
                                "httpGet": {
                                    "path": "/health",
                                    "httpHeaders": [
                                        {"name": "Authorization", "value": "Bearer LEAK"},
                                        {"name": "X-Empty", "value": ""},
                                    ],
                                }
                            },
                        }
                    ]
                },
            }
        ]
    }
    result = redact_pod_list(doc)
    headers = result["items"][0]["spec"]["containers"][0]["readinessProbe"][
        "httpGet"
    ]["httpHeaders"]
    assert headers[0]["value"] == REDACTED
    assert headers[1]["value"] == ""


def test_lifecycle_hooks_redacted():
    """Lifecycle preStop/postStart exec.command and httpHeaders redacted."""
    doc = {
        "items": [
            {
                "metadata": {"name": "test"},
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "lifecycle": {
                                "preStop": {
                                    "exec": {
                                        "command": ["shutdown.sh", "--password=LEAK"]
                                    }
                                },
                                "postStart": {
                                    "httpGet": {
                                        "path": "/init",
                                        "httpHeaders": [
                                            {
                                                "name": "X-API-Key",
                                                "value": "secret123",
                                            }
                                        ],
                                    }
                                },
                            },
                        }
                    ]
                },
            }
        ]
    }
    result = redact_pod_list(doc)
    cont = result["items"][0]["spec"]["containers"][0]
    assert cont["lifecycle"]["preStop"]["exec"]["command"] == [
        "shutdown.sh",
        f"--password={REDACTED}",
    ]
    assert cont["lifecycle"]["postStart"]["httpGet"]["httpHeaders"][0]["value"] == (
        REDACTED
    )


def test_flexvolume_options_values_redacted():
    """flexVolume.options dict values are redacted."""
    doc = {
        "items": [
            {
                "metadata": {"name": "test"},
                "spec": {
                    "volumes": [
                        {
                            "name": "flex-vol",
                            "flexVolume": {
                                "driver": "company/flock",
                                "options": {
                                    "password": "secret123",
                                    "username": "user",
                                },
                            },
                        }
                    ],
                    "containers": [],
                },
            }
        ]
    }
    result = redact_pod_list(doc)
    opts = result["items"][0]["spec"]["volumes"][0]["flexVolume"]["options"]
    assert opts["password"] == REDACTED
    assert opts["username"] == REDACTED


def test_csi_volume_attributes_values_redacted():
    """csi.volumeAttributes dict values are redacted."""
    doc = {
        "items": [
            {
                "metadata": {"name": "test"},
                "spec": {
                    "volumes": [
                        {
                            "name": "csi-vol",
                            "csi": {
                                "driver": "csi.example.com",
                                "volumeAttributes": {
                                    "auth-token": "token123",
                                    "region": "us-west",
                                },
                            },
                        }
                    ],
                    "containers": [],
                },
            }
        ]
    }
    result = redact_pod_list(doc)
    attrs = result["items"][0]["spec"]["volumes"][0]["csi"]["volumeAttributes"]
    assert attrs["auth-token"] == REDACTED
    assert attrs["region"] == REDACTED


def test_hostpath_volume_unchanged():
    """hostPath volumes are unchanged."""
    doc = {
        "items": [
            {
                "metadata": {"name": "test"},
                "spec": {
                    "volumes": [
                        {
                            "name": "host-vol",
                            "hostPath": {"path": "/var/secrets"},
                        }
                    ],
                    "containers": [],
                },
            }
        ]
    }
    result = redact_pod_list(doc)
    vol = result["items"][0]["spec"]["volumes"][0]
    assert vol == {"name": "host-vol", "hostPath": {"path": "/var/secrets"}}


def test_planted_secret_sweep():
    """Comprehensive test: no secret values survive in JSON output."""
    secrets = ["mysecret", "token-abc", "pw123", "apikey-xyz"]
    doc = {
        "items": [
            {
                "metadata": {"name": "app"},
                "spec": {
                    "containers": [
                        {
                            "name": "web",
                            "env": [
                                {"name": "DB_PASSWORD", "value": secrets[0]},
                                {"name": "TOKEN", "value": secrets[1]},
                            ],
                            "args": [
                                f"--api-key={secrets[2]}",
                                "--dsn=postgres://user:pw123@host/db",
                            ],
                            "livenessProbe": {
                                "exec": {
                                    "command": [
                                        "test",
                                        f"--password={secrets[3]}",
                                    ]
                                }
                            },
                        }
                    ],
                    "volumes": [
                        {
                            "name": "vol",
                            "flexVolume": {
                                "options": {"secret": secrets[0]}
                            },
                        }
                    ],
                },
                "status": {"message": f"secret: {secrets[0]}"},
            }
        ]
    }
    result = redact_pod_list(doc)
    output_str = json.dumps(result)
    for secret in secrets:
        assert secret not in output_str


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


def test_redact_argv_rule_d_embedded_in_shell_string():
    """Rule D: embedded key=value inside shell strings are redacted."""
    # Single quotes with embedded secret
    argv = ["sh", "-c", "mysql --password=LEAK -h x"]
    result = redact_argv(argv)
    assert result == ["sh", "-c", "mysql --password=<redacted> -h x"]

    # Double quotes with embedded secret
    argv2 = ["sh", "-c", 'run --token="secrettoken" --x=1']
    result2 = redact_argv(argv2)
    assert result2 == ["sh", "-c", 'run --token=<redacted> --x=1']

    # Mixed quoting
    argv3 = ["sh", "-c", "run --token='a b' --x=1"]
    result3 = redact_argv(argv3)
    assert result3 == ["sh", "-c", "run --token=<redacted> --x=1"]


def test_redact_argv_rule_d_safe_values_in_strings():
    """Rule D: safe values inside strings are preserved."""
    # Boolean safe value in shell string
    argv = ["sh", "-c", "start --enable-bootstrap-token-auth=true"]
    result = redact_argv(argv)
    assert result == argv

    # Path safe value in shell string
    argv2 = ["sh", "-c", "app --config=/etc/app.cfg --port=8080"]
    result2 = redact_argv(argv2)
    assert result2 == argv2


def test_redact_argv_rule_b_empty_next_element():
    """Rule B: empty string next element is not masked."""
    argv = ["--password", ""]
    result = redact_argv(argv)
    # Empty string is considered safe (not non-empty and non-safe)
    assert result == ["--password", ""]


def test_redact_pod_list_non_dict_input():
    """redact_pod_list with non-dict input raises ValueError."""
    with pytest.raises(ValueError, match="expected a kubectl List with items"):
        redact_pod_list([])
    with pytest.raises(ValueError, match="expected a kubectl List with items"):
        redact_pod_list(None)


def test_probe_with_null_exec():
    """Probe with exec: null does not raise."""
    doc = {
        "items": [
            {
                "metadata": {"name": "test"},
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "livenessProbe": {"exec": None},
                        }
                    ]
                },
            }
        ]
    }
    # Should not raise
    result = redact_pod_list(doc)
    assert result["items"][0]["spec"]["containers"][0]["livenessProbe"][
        "exec"
    ] is None


def test_probe_with_non_dict_httpget():
    """Probe with httpGet non-dict does not raise."""
    doc = {
        "items": [
            {
                "metadata": {"name": "test"},
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "readinessProbe": {"httpGet": None},
                        }
                    ]
                },
            }
        ]
    }
    # Should not raise
    result = redact_pod_list(doc)
    assert result["items"][0]["spec"]["containers"][0]["readinessProbe"][
        "httpGet"
    ] is None


def test_lifecycle_hook_with_null_exec():
    """Lifecycle hook with exec: null does not raise."""
    doc = {
        "items": [
            {
                "metadata": {"name": "test"},
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "lifecycle": {
                                "preStop": {"exec": None},
                            },
                        }
                    ]
                },
            }
        ]
    }
    # Should not raise
    result = redact_pod_list(doc)
    assert result["items"][0]["spec"]["containers"][0]["lifecycle"]["preStop"][
        "exec"
    ] is None


def test_secret_template_exact_value():
    """SECRET_TEMPLATE never prints values ($v)."""
    expected = (
        '{{range .items}}{{.metadata.namespace}}{{"\\t"}}{{.metadata.name}}'
        '{{"\\t"}}{{.type}}{{"\\t"}}'
        '{{range $k, $v := .data}}{{$k}},{{end}}{{"\\n"}}{{end}}'
    )
    assert SECRET_TEMPLATE == expected


# --- Addendum v2.2: tightened safe values, Turkish i folding ---------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["sh", "-c", "PASSWORD=/tmp; mysql --password=LEAK"],
        ["sh", "-c", "TOKEN_FILE=/var/run/x && app --token=LEAK"],
        ["--APİ_KEY=LEAK"],
        ["--apı-key=LEAK"],
        ["--prıvate-key=LEAK"],
        ["--credentıal=LEAK"],
        ["--APİKEY", "LEAK"],
        ["ı://u:LEAK@h"],
        ["--password", "/etc/a LEAK"],
        ["sh", "-c", "run --token='/x LEAK'"],
    ],
)
def test_redact_argv_v22_no_leak(argv):
    assert "LEAK" not in json.dumps(redact_argv(argv), ensure_ascii=False)


def test_redact_argv_v22_path_value_with_whitespace_fully_masked():
    assert redact_argv(["PASSWORD=/tmp; mysql --password=LEAK"]) == ["PASSWORD=<redacted>"]


@pytest.mark.parametrize(
    "argv",
    [
        ["--token-auth-file=/etc/k/t.csv"],
        ["--enable-bootstrap-token-auth=true"],
        ["--audit-log-path=/var/log/x"],
        ["--password", "/etc/pw"],
        ["sh", "-c", "run --secret-file=/etc/s --token=FALSE"],
    ],
)
def test_redact_argv_v22_safe_values_survive(argv):
    assert redact_argv(argv) == argv


@pytest.mark.parametrize(
    ("text", "want"),
    [
        ("--password=LEAK x", "--password=<redacted> x"),
        ("dial postgres://u:LEAK@h:5432/db", "dial postgres://u:<redacted>@h:5432/db"),
        ("a token='LEAK b' c", "a token=<redacted> c"),
        ("--token-auth-file=/etc/x --anonymous-auth=false",) * 2,
        ("line1\nsecret=LEAK\nline3", "line1\nsecret=<redacted>\nline3"),
        ("no secrets here", "no secrets here"),
    ],
)
def test_redact_text_applies_rules_c_and_d(text, want):
    assert redact_text(text) == want

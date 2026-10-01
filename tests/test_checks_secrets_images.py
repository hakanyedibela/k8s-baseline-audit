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
        ("localhost:5000/app", ("localhost:5000", None, None)),
        ("app:1.0@sha256:abc", ("docker.io", "1.0", "sha256:abc")),
        ("Registry.Example.com/app:1", ("registry.example.com", "1", None)),
    ],
)
def test_split_image(image, expected):
    assert split_image(image) == expected


def test_env_secret_ref():
    c = hardened_container(
        env=[{"name": "X", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}]
    )
    c2 = hardened_container("b", envFrom=[{"secretRef": {"name": "s"}}])
    hits = run_check("secrets.env_secret_ref", ctx(pods=[pod(containers=[c, c2])]))
    assert [h.evidence.json_path for h in hits] == [
        "$.items[0].spec.containers[0].env",
        "$.items[0].spec.containers[1].envFrom",
    ]


def test_credential_literal_env_redacted_or_raw():
    c = hardened_container(
        env=[
            {"name": "DB_PASSWORD", "value": REDACTED},
            {"name": "PORT", "value": REDACTED},
        ]
    )
    raw = hardened_container("raw", env=[{"name": "API_KEY", "value": "abc"}])
    empty = hardened_container("e", env=[{"name": "TOKEN", "value": ""}])
    hits = run_check(
        "secrets.credential_literal_env", ctx(pods=[pod(containers=[c, raw, empty])])
    )
    assert [h.evidence.json_path for h in hits] == [
        "$.items[0].spec.containers[0].env[0]",
        "$.items[0].spec.containers[1].env[0]",
    ]


def test_credential_env_pointing_to_a_file_or_dir_is_not_flagged():
    names = ["POSTGRES_PASSWORD_FILE", "api_token_path", "SECRET_DIR", "DB_PASSWORD"]
    c = hardened_container(env=[{"name": n, "value": "/run/secrets/x"} for n in names])
    hits = run_check("secrets.credential_literal_env", ctx(pods=[pod(containers=[c])]))
    assert [h.evidence.json_path for h in hits] == ["$.items[0].spec.containers[0].env[3]"]


def test_latest_and_digest():
    pods = [
        pod(
            containers=[
                container("a", "nginx:latest"),
                container("b", "nginx"),
                container("c", "nginx:1.27"),
            ]
        )
    ]
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
    c = ctx(
        config(registry_allowlist=("registry.example.com",)), pods=pods
    )
    hits = run_check("images.registry_not_allowed", c)
    assert [h.evidence.json_path for h in hits] == [
        "$.items[0].spec.containers[0].image"
    ]


def test_registry_allowlist_case_insensitive():
    """Test that registry comparison is case-insensitive."""
    # Image with uppercase registry, allowlist with uppercase
    pods = [
        pod(
            containers=[
                container("mixed", "Registry.Example.com/app:1"),
            ]
        )
    ]
    c = ctx(
        config(registry_allowlist=("Registry.Example.COM",)), pods=pods
    )
    hits = run_check("images.registry_not_allowed", c)
    assert len(hits) == 0  # Should be allowed (case-insensitive)


def test_secret_name_variables_are_not_flagged():
    from k8s_baseline_audit.collect.redact import REDACTED

    names = ["WEBHOOK_SECRET_NAME", "tls_secret_name", "DB_PASSWORD"]
    c = hardened_container(env=[{"name": n, "value": REDACTED} for n in names])
    hits = run_check("secrets.credential_literal_env", ctx(pods=[pod(containers=[c])]))
    assert [h.evidence.json_path for h in hits] == ["$.items[0].spec.containers[0].env[2]"]

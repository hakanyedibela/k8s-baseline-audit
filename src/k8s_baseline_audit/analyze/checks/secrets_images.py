"""Secret handling and container image checks."""

from __future__ import annotations

from ...collect.redact import CREDENTIAL_NAME  # noqa: I001
from ...models import Severity
from .base import (
    CheckContext,
    Hit,
    ManualCheckNeeded,
    check,
    container_path,
    ev,
    iter_containers,
    meta_ref,
)

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
                path = container_path(i, field_name, j) + ".image"
                hits.append(Hit(meta_ref("Pod", p), ev("pods", path)))
    return hits


@check(
    "secrets.env_secret_ref",
    POD,
    Severity.LOW,
    "Secret als Umgebungsvariable eingebunden",
    "Secret consumed as environment variable",
    "Secret als Datei-Volume einbinden; Umgebungsvariablen landen leicht in Logs und Dumps.",
    "Mount the secret as a file volume; environment variables easily leak into logs and dumps.",
)
def env_secret_ref(ctx: CheckContext) -> list[Hit]:
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        for field_name, j, c in iter_containers(p):
            base = container_path(i, field_name, j)
            env = c.get("env") or []
            has_secret_key_ref = any(
                ((e or {}).get("valueFrom") or {}).get("secretKeyRef") for e in env
            )
            if has_secret_key_ref:
                hits.append(Hit(meta_ref("Pod", p), ev("pods", base + ".env")))
            env_from = c.get("envFrom") or []
            has_secret_ref = any((e or {}).get("secretRef") for e in env_from)
            if has_secret_ref:
                hits.append(Hit(meta_ref("Pod", p), ev("pods", base + ".envFrom")))
    return hits


@check(
    "secrets.credential_literal_env",
    POD,
    Severity.HIGH,
    "Zugangsdaten als Klartext-Umgebungsvariable",
    "Credential as plain-text environment variable",
    "Wert in ein Secret verschieben und rotieren; der Klartext stand im Pod-Manifest.",
    "Move the value into a Secret and rotate it; the plain text was in the pod manifest.",
)
def credential_literal_env(ctx: CheckContext) -> list[Hit]:
    hits = []
    for i, p in enumerate(ctx.items("pods")):
        for field_name, j, c in iter_containers(p):
            for k, e in enumerate(c.get("env") or []):
                e = e or {}
                if e.get("value") and CREDENTIAL_NAME.search(e.get("name") or ""):
                    path = container_path(i, field_name, j) + f".env[{k}]"
                    hits.append(Hit(meta_ref("Pod", p), ev("pods", path)))
    return hits


@check(
    "images.latest_tag",
    POD,
    Severity.MEDIUM,
    "Image ohne feste Version (latest oder kein Tag)",
    "Image without fixed version (latest or no tag)",
    "Feste Versionsnummer oder Digest verwenden.",
    "Use a fixed version tag or a digest.",
)
def latest_tag(ctx: CheckContext) -> list[Hit]:
    def unpinned(image: str) -> bool:
        _, tag, digest = split_image(image)
        return digest is None and tag in (None, "latest")

    return _image_hits(ctx, unpinned)


@check(
    "images.no_digest",
    POD,
    Severity.LOW,
    "Image nicht per Digest fixiert",
    "Image not pinned by digest",
    "Image per @sha256-Digest referenzieren, damit der Inhalt unveränderlich ist.",
    "Reference the image by @sha256 digest so its content cannot change.",
)
def no_digest(ctx: CheckContext) -> list[Hit]:
    return _image_hits(ctx, lambda image: split_image(image)[2] is None)


@check(
    "images.registry_not_allowed",
    POD,
    Severity.MEDIUM,
    "Image aus nicht freigegebener Registry",
    "Image from a registry outside the allowlist",
    "Image in eine freigegebene Registry spiegeln oder die Freigabeliste bewusst erweitern.",
    "Mirror the image into an approved registry or deliberately extend the allowlist.",
)
def registry_not_allowed(ctx: CheckContext) -> list[Hit]:
    allowed = set(ctx.config.registry_allowlist)
    if not allowed:
        raise ManualCheckNeeded("no registry allowlist configured (use --registry-allowlist)")
    return _image_hits(ctx, lambda image: split_image(image)[0] not in allowed)

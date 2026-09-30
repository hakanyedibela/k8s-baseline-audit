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

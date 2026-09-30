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
PROBE_FIELDS = ("livenessProbe", "readinessProbe", "startupProbe")
LIFECYCLE_HOOKS = ("postStart", "preStop")

CREDENTIAL_NAME = re.compile(
    r"PASSWORD|PASSWD|TOKEN|SECRET|API_?KEY|PRIVATE_?KEY|CREDENTIAL", re.IGNORECASE
)

# Prints namespace, name, type and data KEYS. Values ($v) are never printed.
SECRET_TEMPLATE = (
    '{{range .items}}{{.metadata.namespace}}{{"\\t"}}{{.metadata.name}}'
    '{{"\\t"}}{{.type}}{{"\\t"}}'
    '{{range $k, $v := .data}}{{$k}},{{end}}{{"\\n"}}{{end}}'
)

# Regex for Rule A: key=value where key contains a SECRET_WORD
_SECRET_WORD = (
    r"password|passwd|pass|pwd|token|secret|api[-_]?key|apikey|credentials?|dsn|bearer|private[-_]?key"
)
_RULE_A = re.compile(
    rf"^(?P<key>[-\w.]*?(?:{_SECRET_WORD})[-\w.]*)=(?P<val>.*)$", re.IGNORECASE
)

# Regex for Rule B: flag with SECRET_WORD but no = (two-token style)
_RULE_B = re.compile(rf"^-{{1,2}}[-\w.]*?(?:{_SECRET_WORD})[-\w.]*$", re.IGNORECASE)

# Regex for Rule C: URL credentials
_RULE_C = re.compile(
    r"(?P<pre>[a-z][a-z0-9+.-]*://[^/:@\s]+:)[^@\s]+@", re.IGNORECASE
)

# Regex for Rule D: embedded key=value inside strings
_RULE_D = re.compile(
    rf"(?P<key>[-\w.]*?(?:{_SECRET_WORD})[-\w.]*)=(?P<val>\"[^\"]*\"|'[^']*'|[^\s\"']+)",
    re.IGNORECASE,
)


def _is_safe_value(val: str) -> bool:
    """Check if value is safe (true/false or file path starting with /)."""
    if val.lower() in ("true", "false"):
        return True
    if val.startswith("/"):
        return True
    return False


def _unquote_value(val: str) -> str:
    """Strip surrounding quotes from a value."""
    if (val.startswith('"') and val.endswith('"')) or (
        val.startswith("'") and val.endswith("'")
    ):
        return val[1:-1]
    return val


def redact_argv(argv: list) -> list:
    """Redact argv list following Rules A, B, C, D.

    Rule A: key=value where key contains SECRET_WORD and value is not safe
    Rule B: two-token flag with SECRET_WORD followed by non-empty, non-safe next element
    Rule C: URL credentials (applied after A/B)
    Rule D: embedded key=value inside strings (applied after A/B/C)
    """
    result = []
    i = 0
    while i < len(argv):
        elem = argv[i]

        # Non-strings pass through unchanged
        if not isinstance(elem, str):
            result.append(elem)
            i += 1
            continue

        # Rule A: key=value in one element
        match_a = _RULE_A.match(elem)
        if match_a:
            key = match_a.group("key")
            val = match_a.group("val")
            if val and not _is_safe_value(val):
                result.append(f"{key}={REDACTED}")
            else:
                result.append(elem)
            i += 1
            continue

        # Rule B: two-token flag
        if _RULE_B.match(elem):
            # This element is a flag with SECRET_WORD
            # Check if next element exists, is non-empty, and is not safe
            if i + 1 < len(argv):
                next_elem = argv[i + 1]
                if (
                    isinstance(next_elem, str)
                    and next_elem  # must be non-empty
                    and not (next_elem.startswith("-") or _is_safe_value(next_elem))
                ):
                    result.append(elem)
                    result.append(REDACTED)
                    i += 2
                    continue

        # Rule C: URL credentials (applied to any string)
        redacted = _RULE_C.sub(r"\g<pre><redacted>@", elem)

        # Rule D: embedded key=value inside strings (applied after A/B/C)
        def replace_embedded(match: re.Match) -> str:
            key = match.group("key")
            val = match.group("val")
            unquoted = _unquote_value(val)
            if unquoted and not _is_safe_value(unquoted):
                return f"{key}={REDACTED}"
            return match.group(0)

        redacted = _RULE_D.sub(replace_embedded, redacted)
        result.append(redacted)
        i += 1

    return result


def _redact_httpheaders(headers: list | None) -> None:
    """Redact httpHeaders list values (non-empty only)."""
    if not headers:
        return
    for header in headers:
        if isinstance(header, dict) and header.get("value"):
            header["value"] = REDACTED


def _redact_probe(probe: dict) -> None:
    """Redact exec.command and httpGet.httpHeaders in a probe."""
    if not probe or not isinstance(probe, dict):
        return
    # exec: null or non-dict is skipped
    if "exec" in probe and isinstance(probe["exec"], dict):
        if "command" in probe["exec"]:
            probe["exec"]["command"] = redact_argv(probe["exec"]["command"])
    # httpGet: null or non-dict is skipped
    if "httpGet" in probe and isinstance(probe["httpGet"], dict):
        if "httpHeaders" in probe["httpGet"]:
            _redact_httpheaders(probe["httpGet"]["httpHeaders"])


def _redact_container(container: dict) -> None:
    """Redact a container's env, command, args, probes, and lifecycle."""
    # Rule: env[].value non-empty → REDACTED
    for env in container.get("env") or []:
        if env.get("value"):
            env["value"] = REDACTED

    # Command and args via redact_argv
    if container.get("command"):
        container["command"] = redact_argv(container["command"])
    if container.get("args"):
        container["args"] = redact_argv(container["args"])

    # Probes: livenessProbe, readinessProbe, startupProbe
    for probe_field in PROBE_FIELDS:
        if probe_field in container:
            _redact_probe(container[probe_field])

    # Lifecycle hooks: postStart, preStop
    lifecycle = container.get("lifecycle")
    if lifecycle and isinstance(lifecycle, dict):
        for hook_field in LIFECYCLE_HOOKS:
            if hook_field in lifecycle:
                hook = lifecycle[hook_field]
                if not isinstance(hook, dict):
                    continue
                # exec: null or non-dict is skipped
                if "exec" in hook and isinstance(hook["exec"], dict):
                    if "command" in hook["exec"]:
                        hook["exec"]["command"] = redact_argv(hook["exec"]["command"])
                # httpGet: null or non-dict is skipped
                if "httpGet" in hook and isinstance(hook["httpGet"], dict):
                    if "httpHeaders" in hook["httpGet"]:
                        _redact_httpheaders(hook["httpGet"]["httpHeaders"])


def _redact_volumes(volumes: list | None) -> None:
    """Redact volume options (flexVolume.options and csi.volumeAttributes)."""
    if not volumes:
        return
    for volume in volumes:
        # flexVolume.options: every value becomes REDACTED
        flex = volume.get("flexVolume")
        if flex and isinstance(flex.get("options"), dict):
            for key in flex["options"]:
                flex["options"][key] = REDACTED

        # csi.volumeAttributes: every value becomes REDACTED
        csi = volume.get("csi")
        if csi and isinstance(csi.get("volumeAttributes"), dict):
            for key in csi["volumeAttributes"]:
                csi["volumeAttributes"][key] = REDACTED


def redact_pod_list(doc: dict) -> dict:
    """Redact a Kubernetes Pod list.

    Raises ValueError if input is not a dict or doc.get("items") is not a list.
    Deep copy to avoid mutating input.
    """
    # Shape validation: input must be a dict
    if not isinstance(doc, dict):
        raise ValueError("expected a kubectl List with items")
    # Shape validation: items must be a list
    items = doc.get("items")
    if not isinstance(items, list):
        raise ValueError("expected a kubectl List with items")

    out = copy.deepcopy(doc)
    for pod in out.get("items") or []:
        # Delete status entirely
        pod.pop("status", None)

        # Delete metadata.annotations entirely
        metadata = pod.get("metadata") or {}
        metadata.pop("annotations", None)

        # Redact volumes
        spec = pod.get("spec") or {}
        _redact_volumes(spec.get("volumes"))

        # Process containers
        for field_name in CONTAINER_FIELDS:
            for container in spec.get(field_name) or []:
                _redact_container(container)

    return out


def parse_secret_rows(text: str) -> dict:
    """Parse tab-separated secret listing output from kubectl.

    Format: namespace\\tname\\ttype\\tkey1,key2,...
    Returns: {"items": [{"metadata": {...}, "type": ..., "keys": [...]}]}
    """
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

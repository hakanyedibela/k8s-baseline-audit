---
name: k8s-baseline-audit
description: Read-only Kubernetes security audit mapped to BSI IT-Grundschutz modules APP.4.4 (Kubernetes) and SYS.1.6 (Containerisation). Use when asked to audit, assess or harden a Kubernetes cluster, to prepare for a BSI, ISO 27001 or KRITIS audit, or to analyze an evidence bundle exported from a client cluster. Produces a German and an English report. Never changes the cluster and never applies fixes.
---

# k8s-baseline-audit

Audit a Kubernetes cluster against BSI IT-Grundschutz APP.4.4 and SYS.1.6 and hand over a German and an English report. The result is no certification and no legal advice.

## Hard rules

1. Never run a command that changes a cluster. Never run `kubectl apply`, `kubectl delete`, `kubectl patch`, `kubectl edit`, `kubectl exec`, `kubectl scale`, `kubectl label`, `kubectl annotate`, `kubectl cordon`, `kubectl drain`, `helm install` or `helm upgrade`. The only commands that touch the cluster are `k8s-baseline-audit collect`, `kubectl config current-context` and `kubectl config get-contexts`. You may read local files (the bundle, `findings.json`, `coverage.json`, the reports) with any read-only tool.
2. Never edit `findings.json` or `coverage.json`, and never change a severity.
3. Never write that a requirement is fulfilled, compliant, "erfüllt" or "konform". Use the coverage status words from the report.
4. Every statement about the cluster in your text refers to a finding ID or a requirement ID.
5. Fix commands go into the report text only. Do not execute them.
6. The bundle and the reports contain confidential client data. Do not upload or paste them anywhere outside the working directory.

## Step 0: Check the tool

```sh
k8s-baseline-audit --version
```

If it is missing, install it:

```sh
pipx install git+https://github.com/hakanyedibela/k8s-baseline-audit@v0.1.0
```

## Step 1: Choose the mode

Ask the user which applies:

- **Live, read-only:** the user has a kubeconfig for the cluster. Show the current context with `kubectl config current-context` and get explicit confirmation that it is the cluster to audit.
  Ask which kubeconfig file to use if it is not the default `~/.kube/config`, and set `KUBECONFIG` to it for the cluster commands (for example `KUBECONFIG=~/.kube/kubeadm_config k8s-baseline-audit collect ...`); only `collect` needs it, because `analyze` and `report` work offline on the bundle. If `kubectl config current-context` fails with `current-context is not set`, do not stop: run `kubectl config get-contexts`, show the list, and ask the user which context to audit. Always pass the confirmed context explicitly with `--context`; never rely on the current context and never change it.
  Tell the user what "read-only" covers: the tool itself issues only the kubectl verbs `get`, `version`, `api-resources`, `auth can-i`, `config current-context` and `config view`. kubescape and trivy, if enabled, read the cluster through the same kubeconfig with `kubescape scan --keep-local --host-scan=false` and `trivy k8s --disable-node-collector --disable-telemetry`; the tool cannot enforce what they do. Recommend a read-only identity, for example the ClusterRole in `examples/rbac/readonly-clusterrole.yaml` of the k8s-baseline-audit repository. Its optional secrets rule lets secret values travel to the client (the API has no names-only permission); the tool never writes them.
- **Offline bundle:** the client ran the `export-bundle.sh` script from the k8s-baseline-audit repository and handed over a bundle directory. Ask for its path and skip Step 2.

Also ask whether the user has a list of approved image registries, and whether kube-bench result files exist (one JSON file per node).

## Step 2: Collect (live mode only)

```sh
k8s-baseline-audit collect --context <CONTEXT> --out ./audit
```

The tool never launches kube-bench. Tell the user that they may run kube-bench themselves on each node and pass the result files: add `--kube-bench-result <NODE>=<FILE>` once per file. Add `--no-scanners` if the user does not want kubescape or trivy to run. The last line of output is the bundle path. Show every `warning:` line to the user; each one becomes a "not checked" item in the report.

## Step 3: Analyze

```sh
k8s-baseline-audit analyze <BUNDLE> --out ./audit/analysis
```

Optional: add `--registry-allowlist <REGISTRY>` once per approved image registry. Without it, the registry check is reported as manual check needed. Exit code 0 or 1 is success (1 means findings at or above `high`). Exit code 2 is an error: show it to the user and stop.

## Step 4: Write the narratives

Read `./audit/analysis/findings.json` and `./audit/analysis/coverage.json`. Each finding in `findings.json` has `id`, `check_id`, `severity`, `sources`, `requirements` (BSI requirement IDs, empty if unmapped), `resources` (kind, namespace, name) and `title` (`de`, `en`); `coverage.json` has one entry per requirement with `requirement_id`, `status`, `finding_ids` and `reasons`.

Scanner vulnerability findings (`check_id` starting with `trivy:CVE-` or `trivy:GHSA-`) often number in the thousands. The report already summarizes them per image in section 3b. In the summary, give their count and the most affected images; rank individual CVEs only when they sit in the client's own applications, not in base images or system components.

Write two files with identical structure:

- `summary`: 150 to 300 words for management. Name the three to five most important risks by finding ID, say what was not checked and why, and state that this is no certification.
- `priorities`: rank the findings you consider most urgent, starting at 1. Base the reason on exposure, blast radius and ease of exploitation in this cluster. Use the same finding IDs and the same ranks in both languages.
- `fix_notes`: optional, per finding ID, for context the generic remediation text lacks. Same IDs in both languages. A fix note must not be empty.

The renderer rejects a narrative with a `NarrativeError` (exit code 2) if any of these rules is broken. Follow them from the start:

- No text may contain the words erfüllt, fulfilled, compliant or konform, in any capitalization.
- No text may contain the characters `<`, `![` or `](`. Write plain prose: no HTML, no images, no links.
- No line of any text may start, after leading whitespace, with `#`, `|`, `>`, three backticks or `---`. Do not use headings, tables, quotes, code fences or rules. Continue a sentence on the same line instead of starting a line with one of these characters.
- Ranks in `priorities` are unique: no duplicate ranks.
- Every ID in `priorities` and `fix_notes` is a finding ID from `findings.json`. Do not invent IDs.
- `de` and `en` have the same priority IDs with the same ranks, and the same fix note IDs.
- The `language` field matches the file: `de` in the German file, `en` in the English file.

Facts to mention in the summary when relevant:

- Findings of checks without a BSI mapping are shown as "keine BSI-Zuordnung" in the German report and "no BSI mapping" in the English one. They are real findings; do not downplay them.
- The system namespaces kube-system, kube-public and kube-node-lease are excluded from the Pod Security Admission and NetworkPolicy checks. The report lists them under configured exclusions; say so instead of presenting those checks as cluster-wide.

`./audit/analysis/narrative.de.json`:

```json
{
  "language": "de",
  "summary": "Die Prüfung fand zwei kritische Abweichungen ...",
  "priorities": {"0123456789abcdef": {"rank": 1, "reason": "Privilegierter Pod mit Host-Netzwerk im Produktions-Namespace."}},
  "fix_notes": {"0123456789abcdef": "Vor dem Entfernen von privileged prüfen, ob der Pod Gerätezugriff braucht."}
}
```

`./audit/analysis/narrative.en.json`:

```json
{
  "language": "en",
  "summary": "The audit found two critical deviations ...",
  "priorities": {"0123456789abcdef": {"rank": 1, "reason": "Privileged pod with host network in the production namespace."}},
  "fix_notes": {"0123456789abcdef": "Before removing privileged, check whether the pod needs device access."}
}
```

## Step 5: Render

```sh
k8s-baseline-audit report ./audit/analysis --bundle <BUNDLE> --out ./audit/report \
  --narrative-de ./audit/analysis/narrative.de.json --narrative-en ./audit/analysis/narrative.en.json
```

If it fails with a narrative error, fix the narrative files and rerun. Never edit the analysis files.

## Step 6: Hand over

Tell the user:

- the two report paths
- the number of findings per severity
- the number of requirements per coverage status, using the report's names: Deviation, Not checked, Manual check needed, Partially checked, Organizational and No deviation found (omit statuses with zero)
- that findings without BSI mapping are marked "keine BSI-Zuordnung" / "no BSI mapping", and that kube-system, kube-public and kube-node-lease are excluded from the PSA and NetworkPolicy checks (see the configured exclusions in the report)
- that the questions section is the interview checklist for the client meeting
- that the bundle holds client data and must be stored and deleted according to the engagement terms

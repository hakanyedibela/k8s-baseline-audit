# k8s-baseline-audit

Read-only Kubernetes security audit, mapped to the BSI IT-Grundschutz modules APP.4.4 (Kubernetes) and SYS.1.6 (Containerisation), with German and English reports.

**This tool is no certification and no legal advice. It is NOT affiliated with or endorsed by the BSI (Bundesamt für Sicherheit in der Informationstechnik).** The BSI is mentioned only as the publisher of the IT-Grundschutz standard. "No deviation found" means only that the automated checks found nothing. See also "Licence of BSI content" below.

## What it checks

30 built-in checks, plus findings imported from kubescape and trivy, mapped to the 47 requirements of the IT-Grundschutz-Kompendium Edition 2023 (APP.4.4.A1 to A21, SYS.1.6.A1 to A26). 18 of the 30 checks are mapped to a requirement; 12 are not, and each of those carries a stated reason. Findings of unmapped checks appear as "no BSI mapping" (German: "keine BSI-Zuordnung"). They are real findings.

| Group | Checks |
|---|---|
| Identity and access | cluster-admin bindings; wildcard verbs or resources in roles; bindings to `system:anonymous` or `system:unauthenticated`; workloads using the default service account; automounted service account tokens; long-lived token secrets |
| Workload hardening | privileged; runs as root; `allowPrivilegeEscalation`; added capabilities; host network, PID or IPC; hostPath mounts; writable root filesystem; missing seccomp profile; missing resource limits |
| Namespace isolation | missing Pod Security Admission labels; namespace without NetworkPolicy; no default-deny policy; allow-all policy |
| Secrets | secrets consumed as environment variables; credential-like env names with literal values |
| Images | `latest` tag or no tag; no digest pinning; registry outside a configurable allowlist |
| Control plane (kubeadm) | from static pod specs: encryption-at-rest config flag; anonymous auth; audit logging flags; etcd client URLs listening on non-loopback addresses |
| Version | Kubernetes minor version out of upstream support, from a dated table in the repo |

On managed clusters such as EKS, GKE or AKS the static pods are not visible. The control plane checks then report "manual check needed" instead of a result.

The system namespaces `kube-system`, `kube-public` and `kube-node-lease` are excluded from the Pod Security Admission and NetworkPolicy checks. The report lists them under configured exclusions, so those checks are not cluster-wide.

Access modes:

| Mode | Description |
|---|---|
| Read-only live | You run the collector with a read-only kubeconfig. The tool itself issues only the kubectl verbs `get`, `version`, `api-resources`, `auth can-i`, `config current-context` and `config view`; anything else raises before execution. kubescape and trivy, if enabled, read the cluster through your kubeconfig with `kubescape scan --keep-local --host-scan=false` and `trivy k8s --disable-node-collector --disable-telemetry`. The tool cannot enforce what those scanners do, so use a read-only identity (see below). |
| Offline bundle | The client runs the export script and hands over a bundle. The analyzer never touches the cluster. |
| Node scan (optional) | kube-bench results that you ran yourself are imported. The tool never launches kube-bench. |

### Read-only identity

The verb allow-list protects against the tool, not against the credentials you give it. Run `collect` (and the export script) with an identity that cannot write. [`examples/rbac/readonly-clusterrole.yaml`](examples/rbac/readonly-clusterrole.yaml) grants `get`, `list` and `watch` on exactly the kinds the collector reads, and nothing else.

Secrets are an optional second role in that file. The Kubernetes API has no permission that lists secret names without values: `list secrets` returns the full objects, values included, to the client. The tool requests only names, types and data keys and never writes values, but the values still travel to the machine running kubectl. Without that role the long-lived token check is reported as "not checked". kubescape and trivy read more kinds than the collector; with the minimal role they report less.

## What it does not check

- Runtime behavior (what workloads actually do while running)
- Supply chain (build pipelines, image provenance and signing)
- Cloud IAM
- Host OS hardening beyond what kube-bench results you import
- Organizational requirements beyond the interview questions in the report

## Install

```sh
pipx install git+https://github.com/hakanyedibela/k8s-baseline-audit@v0.1.0
```

This installs the tagged release. Leave out `@v0.1.0` to install the development state of `main`.

Requirements: Python 3.11+ and `kubectl`. Optional: `kubescape` and `trivy` (run by the collector unless you pass `--no-scanners`), and `jq` (only for the client export script).

`pipx` installs the CLI only. `scripts/export-bundle.sh` and `scripts/install-skill.sh` are not part of the package; run them from a checkout of this repository (`git clone --branch v0.1.0 https://github.com/hakanyedibela/k8s-baseline-audit`).

## Quick start

```sh
k8s-baseline-audit collect --context <CONTEXT> --out ./audit
k8s-baseline-audit analyze <BUNDLE> --out ./audit/analysis --registry-allowlist <REGISTRY>
k8s-baseline-audit report ./audit/analysis --bundle <BUNDLE> --out ./audit/report \
  --narrative-de ./audit/analysis/narrative.de.json --narrative-en ./audit/analysis/narrative.en.json
```

`collect` prints the bundle path as its last line. `analyze` exits 0 when ok, 1 when findings at or above `--fail-on` (default `high`) exist, 2 on errors. `--registry-allowlist` is repeatable; without it the registry check is reported as manual. The narrative files are optional text written by a person or an AI agent (see below); without them the reports contain the findings and the coverage matrix only.

## Offline bundles

A client who does not give you cluster access runs `scripts/export-bundle.sh` from a checkout of this repository on their own admin host:

```sh
sh scripts/export-bundle.sh -o ./out [-c CONTEXT] [-k kubescape.json] [-t trivy.json] [-b NODE=kube-bench.json]
```

It needs `kubectl`, `jq` 1.6+ and `sha256sum` or `shasum`, and writes the same bundle format as `collect`. It collects namespaces, nodes, pods, service accounts, roles, role bindings, cluster roles, cluster role bindings, network policies, secret metadata and the server version. It only reads: every kubectl call passes a verb allow-list first. Secret values are never requested (only names and data keys). Raw kubectl output is streamed through the redaction and never written to disk. The bundle holds a manifest with SHA-256 hashes; the analyzer verifies them and records the provenance in the report.

## Redaction

Secret values, literal `env` values, pod annotations (including `kubectl.kubernetes.io/last-applied-configuration`) and pod status never reach disk. Scanner payloads are removed structurally: kubescape `object` bodies are reduced to identity fields; trivy `CauseMetadata` snippets and image config are removed, and secret findings keep only `RuleID`, `Category`, `Severity`, `Title`, `StartLine`, `EndLine` and the layer `Digest`/`DiffID`; kube-bench results keep only `test_number`, `test_desc`, `status`, `scored`, `remediation` and `type`. Scanner output without the expected top-level structure is rejected, never stored. kubectl and scanner error messages pass through rules C and D below before they are stored.

Command and argument lists (`command`, `args`, probe commands, lifecycle hooks) are redacted by pattern. Rules: (A) `key=value` where the key contains a secret word such as password, token, secret, api key, credentials, dsn, bearer or private key; (B) a flag with a secret word followed by the next argument; (C) credentials in URLs (`scheme://user:pass@host`); (D) embedded `key=value` inside longer strings.

Known limitations of argument redaction:

- Rule B applies only after a dash-prefixed flag. `["X_PASSWD", "LEAK"]` is not masked.
- A two-token flag inside one shell string (for example `"--password hunter2"` as a single argument) is not masked.
- A value that follows an empty `--api_key=` argument is not masked.

Review the bundle before you hand it on. It still contains client data (names, images, topology).

## Known limitations

- Argument redaction has the gaps listed under "Redaction" above.
- While `collect` runs kubescape and trivy, their raw JSON output (unsanitized, including kubescape `object` bodies and trivy code snippets) exists in a private temporary directory (mode 0700) and is deleted when the scan ends; only the sanitized version enters the bundle. If the process is killed or the machine loses power during the scan, that directory may remain in the OS temp directory (`$TMPDIR` or `/tmp`). Check for leftover `tmp*` directories after an interrupted run.
- kubescape and trivy keep their own caches outside the bundle (trivy: its cache directory, for example `~/.cache/trivy` or `~/Library/Caches/trivy`; kubescape: `~/.kubescape`). The tool does not manage them.

## kube-bench

The tool never launches kube-bench, because that needs a privileged Job on the node. Run the upstream Job yourself with JSON output, for example by using the upstream `job.yaml` with `--json` appended to the kube-bench arguments, and save each node's log as JSON. Pass the files when collecting:

```sh
k8s-baseline-audit collect --context <CONTEXT> --out ./audit \
  --kube-bench-result node-a=./node-a.json --kube-bench-result node-b=./node-b.json
```

The export script takes the same input with `-b NODE=FILE`.

## Use with AI agents

The skill in `skill/k8s-baseline-audit/` drives the whole workflow (collect, analyze, narrative, render) for an AI coding agent. Install it from a checkout of this repository with:

```sh
sh scripts/install-skill.sh claude            # or: cursor copilot codex gemini agents
sh scripts/install-skill.sh claude --project ./my-repo
```

Skill folders, each verified against the vendor's documentation on 2026-10-01:

| Agent | User level | Project level |
|---|---|---|
| claude | `~/.claude/skills` | `.claude/skills` |
| cursor | `~/.cursor/skills` | `.cursor/skills` |
| copilot | `~/.copilot/skills` | `.github/skills` |
| codex | `~/.agents/skills` | `.agents/skills` |
| gemini | `~/.gemini/skills` | `.gemini/skills` |
| agents (generic) | `~/.agents/skills` | `.agents/skills` |

The script never overwrites an existing install. The agent writes only the labeled narrative text (summary, priorities, optional fix notes). It never edits `findings.json` or `coverage.json`, never changes a severity, and never runs a command that changes a cluster. The renderer rejects narratives that break these rules and marks the text as AI-generated, to be reviewed by the auditor.

## Example report

Generated from a local throwaway kind cluster with a deliberately insecure pod, role and binding (`examples/kind-demo/insecure.yaml`), including kubescape and trivy results:

- [examples/kind-demo/report.de.md](examples/kind-demo/report.de.md)
- [examples/kind-demo/report.en.md](examples/kind-demo/report.en.md)

Each report is 877 lines (933 findings in `findings.json`: 23 critical, 217 high, 408 medium, 285 low). Built-in checks get one section per check with a row per finding. Checks reported only by a scanner are summarized in one table, and image vulnerabilities are counted per scan target (image OS layer or binary); `findings.json` keeps every single finding.

## Coverage statuses

| Status | Meaning |
|---|---|
| no deviation found | All evidence checks ran and found nothing |
| deviation | At least one finding |
| partially checked | Some evidence exists, human judgment needed |
| manual check needed | Technical requirement outside the collected data |
| organizational | Needs documents or interviews |
| not checked | A check could not run, with the reason |

The word "fulfilled" (German "erfüllt") is never used. An automated tool cannot establish that a requirement is fulfilled; at most it finds no deviation in the data it saw. The renderer rejects it in narratives.

## Framework versioning

The mapping `kompendium-2023` targets IT-Grundschutz-Kompendium Edition 2023. Mappings are stored per framework edition; a Grundschutz++ mapping would be a separate file. Source check of 2026-10-01 (re-check before each release):

- The BSI "Prüfgrundlage für Zertifizierungen nach ISO 27001 auf der Basis von IT-Grundschutz nach dem IT-Grundschutz-Kompendium", version 4.8 of 01.02.2026, names the Kompendium Edition 2023 as a mandatory audit basis and sets no transition deadline for it. <https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/Zertifikat/Veroeffentl/Pruefgrundlagen_Kompendium.pdf?__blob=publicationFile&v=16>
- BSI's Grundschutz++ milestone plan (status September 2026) dates certifiability of Grundschutz++ from 2027-01-01 and the end of certifiability under IT-Grundschutz on 2031-11-30. <https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Grundschutz-in-der-Informationssicherheit/Grundschutz-Plus-Plus/grundschutz-plus-plus_node.html>
- The Kompendium page names Edition 2023 as the current edition. <https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/IT-Grundschutz-Kompendium/it-grundschutz-kompendium_node.html>

Once the Prüfgrundlage sets an end date for Edition 2023, the report must state it.

## Licence of BSI content

This repository contains only requirement IDs, levels, short own paraphrases and links. It contains no BSI text and no BSI documents. The BSI terms of use state that commercial use of content, in particular of the IT-Grundschutz, requires a licence agreement with the BSI: <https://www.bsi.bund.de/DE/Service/Nutzungsbedingungen/Nutzungsbedingungen_node.html>. Whether own paraphrases of requirements, used in paid audits, count as such use is a legal question this project cannot answer. **This tool is not cleared for commercial use of BSI content, and its mapping is licensed for non-commercial use only (CC BY-NC 4.0).** If you use it commercially, clarify the licence with the BSI yourself (contact named on that page: it-grundschutz@bsi.bund.de) or with a lawyer. Do not suggest in your reports that the BSI endorses or cooperates with you.

## Deutsch

k8s-baseline-audit ist ein Kubernetes-Sicherheitsaudit, das nur lesend arbeitet: Es ruft kubectl ausschließlich mit lesenden Befehlen auf, und die optionalen Scanner kubescape und trivy lesen den Cluster über die vorhandene kubeconfig. Empfohlen ist eine Identität mit reinen Leserechten (siehe `examples/rbac/readonly-clusterrole.yaml`). Es bildet die Ergebnisse auf die Anforderungen des IT-Grundschutz-Kompendiums (Bausteine APP.4.4 und SYS.1.6) ab und erzeugt Berichte auf Deutsch und Englisch. Es eignet sich vor allem als Vorbereitung auf ein BSI-Audit oder eine Prüfung im KRITIS-Umfeld. Das Werkzeug ist keine Zertifizierung und keine Rechtsberatung und steht in keiner Verbindung zum BSI. Anforderungen, die sich nicht aus dem Cluster ablesen lassen, erscheinen als Fragenkatalog für das Gespräch mit dem Betreiber.

## License

Two licences apply:

| Part | Licence |
|---|---|
| Code, scripts, skill, tests, report templates, Kubernetes support table | Apache-2.0, see [LICENSE](LICENSE) |
| BSI mapping `src/k8s_baseline_audit/mappings/` (requirement paraphrases, interview questions, check assignments) | CC BY-NC 4.0, see [LICENSE-MAPPING](LICENSE-MAPPING) |

The mapping is non-commercial on purpose: it describes BSI IT-Grundschutz requirements, and the BSI terms of use require a licence agreement for commercial use of that content (see above). Reports generated by the tool contain mapping text and inherit its non-commercial terms. Neither licence covers BSI content itself.

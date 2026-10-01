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
| Read-only live | You run the collector with a read-only kubeconfig. It uses only `get`, `version`, `api-resources`, `auth can-i` and `config` read verbs. Anything else raises before execution. |
| Offline bundle | The client runs the export script and hands over a bundle. The analyzer never touches the cluster. |
| Node scan (optional) | kube-bench results that you ran yourself are imported. The tool never launches kube-bench. |

## What it does not check

- Runtime behavior (what workloads actually do while running)
- Supply chain (build pipelines, image provenance and signing)
- Cloud IAM
- Host OS hardening beyond what kube-bench results you import
- Organizational requirements beyond the interview questions in the report

## Install

```sh
pipx install git+https://github.com/hakanyedibela/k8s-baseline-audit
```

Requirements: Python 3.11+ and `kubectl`. Optional: `kubescape` and `trivy` (run by the collector unless you pass `--no-scanners`), and `jq` (only for the client export script).

## Quick start

```sh
k8s-baseline-audit collect --context <CONTEXT> --out ./audit
k8s-baseline-audit analyze <BUNDLE> --out ./audit/analysis --registry-allowlist <REGISTRY>
k8s-baseline-audit report ./audit/analysis --bundle <BUNDLE> --out ./audit/report \
  --narrative-de ./audit/analysis/narrative.de.json --narrative-en ./audit/analysis/narrative.en.json
```

`collect` prints the bundle path as its last line. `analyze` exits 0 when ok, 1 when findings at or above `--fail-on` (default `high`) exist, 2 on errors. `--registry-allowlist` is repeatable; without it the registry check is reported as manual. The narrative files are optional text written by a person or an AI agent (see below); without them the reports contain the findings and the coverage matrix only.

## Offline bundles

A client who does not give you cluster access runs `scripts/export-bundle.sh` on their own admin host:

```sh
sh scripts/export-bundle.sh -o ./out [-c CONTEXT] [-k kubescape.json] [-t trivy.json] [-b NODE=kube-bench.json]
```

It needs `kubectl`, `jq` 1.6+ and `sha256sum` or `shasum`, and writes the same bundle format as `collect`. It collects namespaces, nodes, pods, service accounts, roles, role bindings, cluster roles, cluster role bindings, network policies, secret metadata and the server version. It only reads: every kubectl call passes a verb allow-list first. Secret values are never requested (only names and data keys). Raw kubectl output is streamed through the redaction and never written to disk. The bundle holds a manifest with SHA-256 hashes; the analyzer verifies them and records the provenance in the report.

## Redaction

Secret values, literal `env` values, pod annotations (including `kubectl.kubernetes.io/last-applied-configuration`) and pod status never reach disk. Scanner payloads are removed structurally: kubescape `object` bodies; trivy `CauseMetadata` snippets, `Match` and `Code` (secret matches and code snippets) and image config; kube-bench values.

Command and argument lists (`command`, `args`, probe commands, lifecycle hooks) are redacted by pattern. Rules: (A) `key=value` where the key contains a secret word such as password, token, secret, api key, credentials, dsn, bearer or private key; (B) a flag with a secret word followed by the next argument; (C) credentials in URLs (`scheme://user:pass@host`); (D) embedded `key=value` inside longer strings.

Known limitations of argument redaction:

- Rule B applies only after a dash-prefixed flag. `["X_PASSWD", "LEAK"]` is not masked.
- A two-token flag inside one shell string (for example `"--password hunter2"` as a single argument) is not masked.
- A value that follows an empty `--api_key=` argument is not masked.

Review the bundle before you hand it on. It still contains client data (names, images, topology).

## kube-bench

The tool never launches kube-bench, because that needs a privileged Job on the node. Run the upstream Job yourself with JSON output, for example by using the upstream `job.yaml` with `--json` appended to the kube-bench arguments, and save each node's log as JSON. Pass the files when collecting:

```sh
k8s-baseline-audit collect --context <CONTEXT> --out ./audit \
  --kube-bench-result node-a=./node-a.json --kube-bench-result node-b=./node-b.json
```

The export script takes the same input with `-b NODE=FILE`.

## Use with AI agents

The skill in `skill/k8s-baseline-audit/` drives the whole workflow (collect, analyze, narrative, render) for an AI coding agent. Install it with:

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

The reports are large because the scanners also flag the default cluster roles and base images.

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

- The BSI "Prüfgrundlage für Zertifizierungen nach ISO 27001 auf der Basis von IT-Grundschutz", version 4.8 of 01.02.2026, names the Kompendium Edition 2023 as a mandatory audit basis and sets no transition deadline for it. <https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/Zertifikat/Veroeffentl/Pruefgrundlagen_Kompendium.pdf?__blob=publicationFile&v=16>
- BSI's Grundschutz++ milestone plan (status September 2026) dates certifiability of Grundschutz++ from 2027-01-01 and the end of certifiability under IT-Grundschutz on 2031-11-30. <https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Grundschutz-in-der-Informationssicherheit/Grundschutz-Plus-Plus/grundschutz-plus-plus_node.html>
- The Kompendium page names Edition 2023 as the current edition. <https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/IT-Grundschutz-Kompendium/it-grundschutz-kompendium_node.html>

Once the Prüfgrundlage sets an end date for Edition 2023, the report must state it.

## Licence of BSI content

This repository contains only requirement IDs, levels, short own paraphrases and links. It contains no BSI text and no BSI documents. The BSI terms of use state that commercial use of content, in particular of the IT-Grundschutz, requires a licence agreement with the BSI: <https://www.bsi.bund.de/DE/Service/Nutzungsbedingungen/Nutzungsbedingungen_node.html>. Whether own paraphrases of requirements, used in paid audits, count as such use is a legal question this project cannot answer. **This tool is not cleared for commercial use of BSI content.** If you use it commercially, clarify the licence with the BSI yourself (contact named on that page: it-grundschutz@bsi.bund.de) or with a lawyer. Do not suggest in your reports that the BSI endorses or cooperates with you.

## Deutsch

k8s-baseline-audit ist ein Kubernetes-Sicherheitsaudit, das nur liest und nie etwas am Cluster ändert. Es bildet die Ergebnisse auf die Anforderungen des IT-Grundschutz-Kompendiums (Bausteine APP.4.4 und SYS.1.6) ab und erzeugt Berichte auf Deutsch und Englisch. Es eignet sich vor allem als Vorbereitung auf ein BSI-Audit oder eine Prüfung im KRITIS-Umfeld. Das Werkzeug ist keine Zertifizierung und keine Rechtsberatung und steht in keiner Verbindung zum BSI. Anforderungen, die sich nicht aus dem Cluster ablesen lassen, erscheinen als Fragenkatalog für das Gespräch mit dem Betreiber.

## License

Apache-2.0, see [LICENSE](LICENSE). The licence covers this tool's code and data only, not BSI content (see above).

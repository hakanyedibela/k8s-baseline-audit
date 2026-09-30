# k8s-baseline-audit — Design Spec

- **Date:** 2026-09-30
- **Status:** Draft, awaiting review
- **License:** Apache-2.0
- **Author:** Hakan Yedibela

## 1. Purpose

k8s-baseline-audit audits a Kubernetes cluster for security weaknesses and maps
every result to the BSI IT-Grundschutz (IT Baseline Protection) requirements of
modules **APP.4.4 Kubernetes** and **SYS.1.6 Containerisation**.

### 1.1 Audience and use

- **Primary:** consultants preparing clients for a BSI, ISO 27001 or KRITIS
  audit. The report must be traceable by an auditor.
- **Distribution:** public open-source repository that generates consulting
  inquiries. It needs a strong README and an example report from a demo cluster.

### 1.2 Success criteria for v1

1. One run against a real kubeadm cluster produces a German and an English
   report.
2. Every finding cites raw evidence in the bundle, by file and location.
3. Every requirement of APP.4.4 and SYS.1.6 appears in the coverage matrix with
   an explicit status. No requirement is silently missing.
4. The report lists everything that was not checked, with the reason.
5. Analyzing the same bundle twice gives byte-identical findings and coverage
   files.
6. The collector never issues a write request against the cluster.

### 1.3 Non-goals

The tool is no certification and no legal advice. It never states that a
requirement is "fulfilled". It never applies fixes.

## 2. Framework versioning

BSI launched Grundschutz++ on 2026-01-01. Third-party sources state that the
IT-Grundschutz-Kompendium Edition 2023 remains the certification basis during a
multi-year transition. This still needs confirmation from a BSI source.

Consequences:

- Mappings are stored per framework edition. v1 ships one mapping:
  `mappings/kompendium-2023.yaml`.
- A Grundschutz++ mapping is a later, separate file. No code change should be
  needed to add it.
- Every requirement entry cites its source document and edition.
- Requirement texts are **paraphrased**, never copied. BSI reuse terms have not
  been checked. Only requirement IDs and short paraphrases are stored.

## 3. Access modes

| Mode | Description | v1 |
|---|---|---|
| Read-only live | Consultant runs the collector with a read-only kubeconfig. Uses only `get`, `list` and `auth can-i`. | Yes, primary |
| Offline bundle | Client runs the export script and hands over a bundle. The analyzer never touches the cluster. | Yes, primary |
| Privileged node scan | kube-bench runs as a Job on each node. Needs an explicit flag and client consent. | Yes, optional |

## 4. Architecture

```
cluster ──► collector ──► evidence bundle ──► analyzer ──► findings.json
   │                          ▲                              coverage.json
   └─ client export script ───┘                                   │
                                                                  ▼
                                                     skill (Claude) ──► report.de.md
                                                                        report.en.md
```

### 4.1 Collector

- Calls `kubectl` as a subprocess. Every command is recorded in the manifest so
  an auditor can rerun it by hand.
- **Command allowlist:** only `get`, `list` (via `get`), `auth can-i`,
  `version` and `api-resources`. Any other verb raises an error before
  execution.
- **Preflight:** runs `kubectl auth can-i list <resource>` for every resource
  type it needs and stores the result in `preflight.json`.
- **Redaction:**
  - Secrets: only name, namespace, type and key names. Values are never
    fetched. Collection uses custom columns, not `-o yaml`.
  - Environment variables: names kept, literal values replaced by
    `<redacted>`. Names matching credential patterns such as `PASSWORD`,
    `TOKEN`, `SECRET` or `API_KEY` with a literal value are flagged.
  - ConfigMaps: keys only, no values.
- **Optional scanners**, run only if installed:
  - kubescape, JSON output.
  - trivy, JSON output. Its node-collector must be disabled in read-only mode,
    because by default it may create Jobs. Verify the exact flag during
    implementation.
  - kube-bench, only with `--privileged-node-scan`.
- Writes the evidence bundle.

### 4.2 Client export script

- A standalone POSIX shell script with no Python dependency, so a client can
  run it on an admin host.
- Produces the same bundle format as the collector, including hashes.
- Uses the same command allowlist and redaction rules.

### 4.3 Evidence bundle

```
bundle-<cluster>-<timestamp>/
  manifest.json        # timestamp, cluster identity, kubectl and server version,
                       # tool versions, every command run, SHA-256 per file
  preflight.json       # can-i results per resource
  resources/<kind>.json
  scanners/kubescape.json | trivy.json | kube-bench.json   # if present
  errors.json          # every collection failure with reason
```

- A bundle without hashes is accepted but marked "provenance unverified".

### 4.4 Analyzer

- Deterministic. No model, no network access.
- Steps:
  1. Verify hashes. Stop on any mismatch.
  2. Load resources and scanner output. Reject unknown scanner formats.
  3. Run the built-in checks (section 5).
  4. Parse scanner findings into the common finding model.
  5. Deduplicate: findings from different sources on the same resource and
     the same issue merge into one, keeping all sources as evidence.
  6. Apply the mapping to produce coverage.
  7. Write `findings.json` and `coverage.json`, sorted deterministically, with
     no timestamps inside them.

### 4.5 Mapping file

Each requirement entry contains:

- `id`, for example `APP.4.4.A3`
- `level`: basic, standard or elevated protection
- `title` and `summary` in German and English, paraphrased
- `source`: document, edition and page
- `coverage_type`:
  - `automatic`: the analyzer can decide it from data
  - `partial`: data exists, a person must judge it
  - `manual`: technical, needs node or process access
  - `organizational`: concepts, planning or documentation
- `checks`: list of check IDs that provide evidence
- `questions` in German and English, for manual and organizational items

Only APP.4.4.A1, A2 and A3 have been confirmed so far. All other IDs are
filled in from the official module documents during implementation.

### 4.6 Skill

- Runs the collector, or accepts a bundle path.
- Runs the analyzer.
- Validates `findings.json` and `coverage.json` against their schemas. Stops if
  they are invalid.
- Renders the deterministic report parts from templates in both languages.
- Writes the model parts in both languages: management summary, contextual
  priority with reasoning, and fix explanations.
- Labels every model-written section as such.
- Never executes a fix command and never changes a finding or its severity.

## 5. Built-in checks

| Group | Checks |
|---|---|
| Identity and access | cluster-admin bindings; wildcard verbs or resources in roles; bindings to `system:anonymous` or `system:unauthenticated`; workloads using the default service account; automounted service account tokens; long-lived token secrets |
| Workload hardening | privileged; runs as root; `allowPrivilegeEscalation`; added capabilities; host network, PID or IPC; hostPath mounts; writable root filesystem; missing seccomp profile; missing resource limits |
| Namespace isolation | missing Pod Security Admission labels; namespace without NetworkPolicy; no default-deny policy; allow-all policy |
| Secrets | secrets consumed as environment variables; credential-like env names with literal values |
| Images | `latest` tag or no tag; no digest pinning; registry outside a configurable allowlist |
| Control plane (kubeadm) | from static pod specs: encryption-at-rest config flag; anonymous auth; audit logging flags; etcd client URLs listening on non-loopback addresses |
| Version | Kubernetes minor version out of upstream support, from a dated table in the repo |

On managed clusters such as EKS, GKE or AKS the static pods are not visible.
The control plane checks then report `manual` instead of a result.

## 6. Finding model

```
id              stable hash of check + resource
check_id
title           {de, en}
severity        critical | high | medium | low   (never changed after analysis)
resources       list of kind/namespace/name
evidence        list of {file, json_path}
sources         built-in | kubescape | trivy | kube-bench
requirements    list of requirement IDs
remediation     {de, en} template text with commands, never executed
```

Scanner severities map directly: critical, high, medium and low keep their
level. Trivy `UNKNOWN` and kubescape scores without a level map to `low` and
carry the flag `severity_unmapped`. Built-in checks define their severity in
the check code.

The skill may add a `priority` with a reason. It is stored separately and shown
next to the severity.

## 7. Coverage statuses

| Status | Meaning |
|---|---|
| no deviation found | All evidence checks ran and found nothing |
| deviation | At least one finding |
| partially checked | Some evidence exists, human judgment needed |
| manual check needed | Technical requirement outside the collected data |
| organizational | Needs documents or interviews |
| not checked | A check could not run, with the reason |

"Fulfilled" is never used.

## 8. Report structure

Two files, `report.de.md` and `report.en.md`, with identical structure and
identical facts:

1. Cover: cluster, date, bundle hash, tool versions, access mode, scope,
   disclaimer, provenance status.
2. Management summary, model-written and labeled.
3. Coverage matrix: every requirement of both modules with status.
4. Findings by priority: ID, requirement IDs, resources, evidence location,
   fix plan.
5. Questions for manual and organizational requirements, as an interview
   checklist.
6. Appendix: evidence index with hashes, list of everything not checked,
   preflight permissions.

## 9. Error handling

- A failed or forbidden collection step produces an entry in `errors.json`.
  Every requirement depending on it gets status `not checked` with the reason.
- A missing scanner is recorded in the manifest. Its dependent requirements
  lose that evidence source, and the report says so.
- Unknown scanner output formats are rejected, not partially parsed.
- A hash mismatch stops the analyzer.
- Invalid analyzer output stops the skill.

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | No findings at or above the threshold |
| 1 | Findings at or above the threshold, default `high` |
| 2 | Errors: invalid bundle, hash mismatch, collector failure |

## 10. Testing

- Unit tests per check against fixture resources, written test-first.
- Parser tests against real output captured from pinned scanner versions.
- Mapping validation: schema, bilingual text, source citation, every
  referenced check exists, every requirement of both modules present.
- Reproducibility: the same fixture bundle analyzed twice gives
  byte-identical output.
- Redaction: a planted secret value must not appear anywhere in the bundle.
- Read-only: a mocked command runner asserts that only allowlisted verbs run.
- Integration: a kind cluster with deliberately insecure workloads, with an
  exact expected finding list. Runs in GitHub Actions.
- Language parity: German and English reports contain the same number of
  findings and matrix rows.
- Acceptance: one manual run on the author's kubeadm cluster, reviewed by hand.

## 11. Tech stack

- Python 3.11 or newer, pdm, typer, pydantic, pytest, ruff.
- kubectl as a subprocess, not the Python Kubernetes client.
- Jinja2 for report templates.
- The export script is POSIX shell plus kubectl, with `sha256sum` or
  `shasum -a 256` for hashes.

## 12. Repository layout

```
k8s-baseline-audit/
  src/k8s_baseline_audit/
    collect/          # kubectl runner, allowlist, redaction, scanners
    analyze/          # checks, parsers, dedupe, coverage
    mapping/          # loader and schema
    report/           # templates de/en, renderer
    cli.py
  mappings/kompendium-2023.yaml
  scripts/export-bundle.sh
  skill/SKILL.md
  tests/
  examples/kind-demo/  # insecure demo manifests + example report
  LICENSE
  README.md
```

## 13. v1 scope

**In:** collector, export script, analyzer, Kompendium 2023 mapping for APP.4.4
and SYS.1.6, German and English Markdown reports, skill, README, example report
from a kind demo cluster.

**Out:** Grundschutz++ mapping, PDF or HTML output, multi-cluster runs, runtime
detection, cloud IAM checks, OpenShift-specific checks.

## 14. Open items to resolve during implementation

1. Confirm on a BSI source that Kompendium 2023 is the certification basis
   during the Grundschutz++ transition.
2. Check BSI reuse terms before storing any text beyond IDs and paraphrases.
3. Verify the trivy flag that disables node-collector Jobs.
4. Extract all APP.4.4 and SYS.1.6 requirement IDs from the official module
   documents.

## 15. Amendments (2026-09-30, found while writing the implementation plan)

Each change keeps the approved design goals. Reasons are given so a reviewer
can reject any single one.

1. **Portability to other agents.** The skill follows the Agent Skills open
   standard: a `SKILL.md` with only `name` and `description` frontmatter and
   no agent-specific tool names. All logic lives in the pip-installable CLI, so
   any agent that can run shell commands can use it. An install script copies
   the skill into the skill folder of Claude Code, Cursor, GitHub Copilot and,
   where their paths are verified, Codex CLI and Gemini CLI. Bolt is out of
   scope: it runs in a browser sandbox and cannot reach a client cluster.
2. **Secrets wording corrected.** The Kubernetes API returns full Secret
   objects to kubectl even when kubectl prints only names. Correct statement:
   secret values pass through kubectl's memory and are **never written** to the
   bundle. Listing secrets therefore needs `list secrets` permission. If it is
   forbidden, the dependent checks become `not checked`.
3. **ConfigMaps dropped.** No v1 check uses them. Collecting them only adds
   data to protect.
4. **kube-bench is imported, never launched.** The operator runs kube-bench
   with the upstream Job manifest and passes the result files with
   `--kube-bench-result NODE=FILE`. The tool itself then never writes to any
   cluster, in every mode.
5. **Scanner output is sanitized before it enters the bundle.** kubescape
   JSON embeds full resource objects, including literal environment values.
   Trivy embeds manifest snippets and matched secret strings. The collector and
   the export script strip these fields. Without this step the bundle would
   leak exactly the data the redaction rules protect.
6. **The last-applied-configuration annotation is stripped from pods.** It
   contains the full original manifest, including literal environment values.
7. **The export script requires jq.** POSIX shell alone cannot redact JSON
   reliably.
8. **One localized report template.** A single template plus per-language
   labels replaces two templates. Parity between German and English then holds
   by construction instead of by discipline.
9. **The mapping file ships inside the Python package** at
   `src/k8s_baseline_audit/mappings/`, so an installed CLI finds it. The file
   also lists `unmapped_checks` with a reason, so every built-in check is
   either mapped or explicitly excluded.
10. **Image vulnerabilities get a compact table** in the report instead of one
    section per CVE, because trivy can return thousands of them.

## 16. Source verification (2026-10-01)

Resolves section 14, items 1, 2 and 4. Checked on bsi.bund.de on 2026-10-01.
Short quotes below follow the BSI citation rule (verbatim, in quotation marks,
with source).

### 16.1 Certification basis (item 1): Kompendium 2023 is still the basis

- The BSI "Prüfgrundlage für Zertifizierungen nach ISO 27001 auf der Basis von
  IT-Grundschutz nach dem IT-Grundschutz-Kompendium", Version 4.8 of
  01.02.2026, lists "IT-Grundschutz-Kompendium — Edition 2023 (Feb. 2023)" as a
  mandatory audit basis, with no transition deadline set for it.
  URL: https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/Zertifikat/Veroeffentl/Pruefgrundlagen_Kompendium.pdf?__blob=publicationFile&v=16
  (linked from the "Zertifizierungsschema" page:
  https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Zertifizierung-und-Anerkennung/Zertifizierung-von-Managementsystemen/ISO-27001-Basis-IT-Grundschutz/Zertifizierungsschema/schema_node.html).
- The Kompendium page names Edition 2023 as the current edition ("seit dem
  1. Februar 2023 verfügbar und löst damit die Edition 2022 ab"):
  https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/IT-Grundschutz-Kompendium/it-grundschutz-kompendium_node.html
- The Grundschutz++ page (milestone plan "Stand September 2026") says the new
  catalogue "löst das IT-Grundschutz-Kompendium ab", but dates certifiability
  later: "1. Januar 2027 — Der GS++ ist zertifizierbar". Pilot phase ran
  1 April to 31 August 2026; publication of the method is planned for
  27 October 2026 (it-sa).
  URL: https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Grundschutz-in-der-Informationssicherheit/Grundschutz-Plus-Plus/grundschutz-plus-plus_node.html

Consequence: the v1 mapping `kompendium-2023` targets the current audit basis.
Correction to section 2: BSI's own milestone plan does not describe a launch
of Grundschutz++ on 2026-01-01; it names 2027-01-01 as the date from which
GS++ certification can be applied for. Re-check the Prüfgrundlage before each
release; once it sets an end date ("Übergangsfrist") for Edition 2023, the
report must state it.

### 16.2 Reuse terms (item 2): commercial use needs a BSI licence

BSI "Nutzungsbedingungen":
https://www.bsi.bund.de/DE/Service/Nutzungsbedingungen/Nutzungsbedingungen_node.html

- Non-commercial use for IT security purposes is free.
- "Eine kommerzielle Verwendung von Inhalten, insbesondere denen des
  IT-Grundschutzes, bedarf einer lizenzrechtlichen Vereinbarung mit dem BSI."
  Contact named there: it-grundschutz@bsi.bund.de.
- Quoting is allowed without consent if verbatim, in quotation marks, with
  source.
- No use may suggest a cooperation with the BSI. "Die Verwendung des Namens
  des BSI als Referenz bedarf der vorherigen Zustimmung des BSI."
- Downloads of IT-Grundschutz content may be modified for implementing
  internal security measures.

Consequence: the mapping stores only requirement IDs, levels, own
paraphrases and links. Whether own paraphrases of requirements, used in paid
client audits, count as commercial use of "Inhalte des IT-Grundschutzes" is a
legal question this project cannot answer. **Open item for the owner before
commercial use:** ask it-grundschutz@bsi.bund.de (or a lawyer). Reports must
not suggest BSI endorsement or cooperation.

### 16.3 Module documents (item 4)

Both modules exist as Edition 2023 single PDFs; the Edition 2022 APP.4.4 URL
from the plan is superseded and not used.

| Module | Edition | Pages | URL | SHA-256 of the file read |
|---|---|---|---|---|
| APP.4.4 Kubernetes | 2023 | 8 | https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-GS-Kompendium_Einzel_PDFs_2023/06_APP_Anwendungen/APP_4_4_Kubernetes_Edition_2023.pdf?__blob=publicationFile&v=4 | `03c63c58909476e20e3ec4da5e2b8be4beb03cf55c7a708bf11854c8f2a6be44` |
| SYS.1.6 Containerisierung | 2023 | 9 | https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/IT-GS-Kompendium_Einzel_PDFs_2023/07_SYS_IT_Systeme/SYS_1_6_Containerisierung_Edition_2023.pdf?__blob=publicationFile&v=4 | `114d9fabc9077a93d24c778a4cb2959998bcaa233416415f6e2cbc05964f2393` |

Found via the "IT-Grundschutz-Bausteine (Edition 2023)" download page:
https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/IT-Grundschutz-Kompendium/IT-Grundschutz-Bausteine/Bausteine_Download_Edition_node.html

Requirements extracted: APP.4.4.A1–A21 (5 basic, 7 standard, 9 elevated) and
SYS.1.6.A1–A26 (8 basic, 12 standard, 6 elevated), 47 in total. None is
marked withdrawn ("ENTFALLEN"). The SYS.1.6.A5 heading is split across two
lines in the PDF text and was confirmed by hand. Page numbers in the mapping
are the PDF page on which the requirement heading appears (identical to the
printed "Seite n von m").

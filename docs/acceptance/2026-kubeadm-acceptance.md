# Acceptance run: kubeadm lab cluster (2026-10-01)

Spec success criteria 1.2, run by the controller against the author's three-node kubeadm lab
cluster (Kubernetes 1.35, Parallels VMs) with the read-only collector, scanners enabled.
No bundle contents beyond counts are recorded here.

## Results

| Check | Result |
|---|---|
| Collect exit code / collector errors | 0 / none |
| kubescape 4.0.15 | ok |
| trivy 0.74.0 | failed: trivy's own k8s scan timeout ("context deadline exceeded") |
| Analyze exit code | 1 (findings at or above high) |
| Findings (critical / high / medium / low) | 770 (6 / 142 / 498 / 124); 366 built-in-sourced, 458 kubescape-sourced |
| Coverage (deviation / manual / organizational) | 11 / 17 / 19 of 47 requirements |
| Every finding's evidence file exists in the bundle | yes (0 missing) |
| `control_plane.etcd_listen_non_loopback` fires | yes |
| kubeadm default bindings produce identity findings | no |
| All 47 requirements in the matrix (DE and EN) | yes |
| Not-checked appendix lists skipped checks and failed scanner | yes (registry allowlist manual, trivy failed) |
| DE and EN list identical finding IDs in identical order | yes (366 IDs) |
| Forbidden words in reports | 0 |
| Real Secret values (98, base64 and decoded) found in bundle or analysis | 0 |
| `last-applied-configuration` in collected pods | 0 |
| Report length | 1082 lines per language |

## Issues found

1. **trivy times out on a real cluster.** trivy's built-in `--timeout` default is too short for a
   full `trivy k8s` scan; the tool must pass an explicit `--timeout` (for example 25m, below the
   tool's 30-minute subprocess limit). Without it, image vulnerabilities are never assessed.
2. **False HIGH on `*_NAME` variables.** `secrets.credential_literal_env` flagged
   `WEBHOOK_SECRET_NAME` (tekton webhook), whose value is a Secret's name. Exclude names ending in
   `_NAME`, like `_FILE`, `_PATH` and `_DIR`.
3. **kubescape version string.** The cover shows "Your current version is: 4.0.15"; extract the
   version number.
4. **Top findings without BSI mapping.** etcd encryption and API server audit logging rank highest
   but map to no APP.4.4/SYS.1.6 requirement (correct per the mapping); the report states this.

Issues 1-3 are follow-ups; none blocks the acceptance criteria above.

## Rerun after fixes (2026-10-01, commit 3454e66)

| Check | Result |
|---|---|
| kubescape / trivy | ok (4.0.15) / ok (0.74.0) — trivy completes with `--timeout 25m` |
| Findings | 18645 (236 critical); 17259 are trivy CVE/GHSA findings |
| `WEBHOOK_SECRET_NAME` false HIGH | gone |
| Report length per language | 1248 lines (CVEs summarized per scan target) |
| Real Secret values (98) in bundle, analysis or report | 0 |
| trivy payload fields (ImageConfig, CauseMetadata, Match) in bundle | 0 |
| Analyze runtime on a 175 MB trivy bundle | 3 s |

Issues 1-3 above are resolved. New observation: the sanitized trivy output is 175 MB for this
three-node cluster, which makes bundles heavy to hand over; consider compressing bundles or
dropping per-package vulnerability detail the analyzer does not use.

# Kubernetes security audit – kind-kba-it2

> This report is no certification and no legal advice. "No deviation found" only means the automated checks found nothing. Not affiliated with or endorsed by the BSI.

| | |
|---|---|
| Cluster | kind-kba-it2 (https://127.0.0.1:55478) |
| Collected at | 2026-10-01T02:06:34Z |
| Bundle hash (SHA-256, manifest.json) | `e01720e4064efedae539fe2f844c89107af0953b2a5c7ebdcf67bb61244efe61` |
| Provenance | hashes verified |
| Produced by | collector |
| Framework | BSI IT-Grundschutz-Kompendium 2023, modules APP.4.4, SYS.1.6 |
| Tool | k8s-baseline-audit 0.1.0 |
| Scanners | kubescape: ok (Your current version is: 4.0.15), trivy: ok (Version: 0.74.0) |

## 1. Management summary

_AI-generated, to be reviewed by the auditor_

The audit of the local demo cluster kind-kba-it2 (namespace audit-demo) found 23 critical, 217 high, 408 medium and 285 low findings. This is a deliberately insecure throwaway cluster. The most important risks are: a privileged pod with host namespaces and the host file system mounted (54532d8196f6697a, 79748001703b4712, f87e6e6ec5c9e1d0) that also runs as root (186a31abb1fb1ced); a binding to the anonymous user (236c5489655114b0) together with a role that grants wildcard permissions (f64dba7e79577813); and a password stored as a plain-text environment variable (7d0e7266a1e7b40c). The API server has no audit logging (1195cfbf437e0023) and no encryption of Secrets at rest (e465d75765081e10), and the etcd client port listens on a non-loopback address (391ab1aa42b599cc). Most remaining results come from kubescape and trivy and concern default roles and base images; the report summarizes them per check and per image, and findings.json lists every single one. Findings without a BSI mapping are marked no BSI mapping and are no less serious. The system namespaces kube-system, kube-public and kube-node-lease are excluded from the Pod Security Admission and NetworkPolicy checks, so those checks are not cluster-wide. 17 requirements need a manual check and 19 are organizational and cannot be read from the cluster. No registry allowlist was given, so the registry check did not run. This report is no certification and no legal advice.

## 2. Coverage matrix

| Requirement | Level | Title | Status | Findings | Reasons |
|---|---|---|---|---|---|
| APP.4.4.A1 | Basic | Plan the separation of applications | Organizational | 0 |  |
| APP.4.4.A2 | Basic | Plan automation with CI/CD | Organizational | 0 |  |
| APP.4.4.A3 | Basic | Identity and permission management | Deviation | 3 |  |
| APP.4.4.A4 | Basic | Separate pods from each other | Manual check needed | 0 |  |
| APP.4.4.A5 | Basic | Back up the cluster | Manual check needed | 0 |  |
| APP.4.4.A6 | Standard | Initialize pods through init containers | Manual check needed | 0 |  |
| APP.4.4.A7 | Standard | Separate networks in the cluster | Deviation | 2 |  |
| APP.4.4.A8 | Standard | Protect configuration files | Organizational | 0 |  |
| APP.4.4.A9 | Standard | Use service accounts deliberately | Deviation | 1 |  |
| APP.4.4.A10 | Standard | Secure automation processes | Organizational | 0 |  |
| APP.4.4.A11 | Standard | Monitor containers with health checks | Manual check needed | 0 |  |
| APP.4.4.A12 | Standard | Secure infrastructure applications | Manual check needed | 0 |  |
| APP.4.4.A13 | Elevated | Audit the configuration automatically | Manual check needed | 0 |  |
| APP.4.4.A14 | Elevated | Nodes with dedicated roles | Manual check needed | 0 |  |
| APP.4.4.A15 | Elevated | Own clusters or nodes for very high protection needs | Organizational | 0 |  |
| APP.4.4.A16 | Elevated | Use operators | Organizational | 0 |  |
| APP.4.4.A17 | Elevated | Attest nodes | Manual check needed | 0 |  |
| APP.4.4.A18 | Elevated | Micro-segmentation | Deviation | 2 |  |
| APP.4.4.A19 | Elevated | Run Kubernetes with high availability | Manual check needed | 0 |  |
| APP.4.4.A20 | Elevated | Encrypt persistent data | Manual check needed | 0 |  |
| APP.4.4.A21 | Elevated | Restart pods regularly | Manual check needed | 0 |  |
| SYS.1.6.A1 | Basic | Plan the use of containers | Organizational | 0 |  |
| SYS.1.6.A2 | Basic | Plan container management | Organizational | 0 |  |
| SYS.1.6.A3 | Basic | Operate containerized systems securely | Organizational | 0 |  |
| SYS.1.6.A4 | Basic | Plan image provisioning | Organizational | 0 |  |
| SYS.1.6.A5 | Basic | Separate administration and access networks | Deviation | 2 |  |
| SYS.1.6.A6 | Basic | Use secure images | Deviation | 1 | images.registry_not_allowed: no registry allowlist configured (use --registry-allowlist) |
| SYS.1.6.A7 | Basic | Store container logs outside the container | Manual check needed | 0 |  |
| SYS.1.6.A8 | Basic | Store credentials securely | Deviation | 1 |  |
| SYS.1.6.A9 | Standard | Application fit for containers | Organizational | 0 |  |
| SYS.1.6.A10 | Standard | Set rules for images and container operation | Organizational | 0 |  |
| SYS.1.6.A11 | Standard | One service per container | Manual check needed | 0 |  |
| SYS.1.6.A12 | Standard | Distribute secure images | Organizational | 0 |  |
| SYS.1.6.A13 | Standard | Release images | Organizational | 0 |  |
| SYS.1.6.A14 | Standard | Update images | Organizational | 0 |  |
| SYS.1.6.A15 | Standard | Limit resources per container | Deviation | 10 |  |
| SYS.1.6.A16 | Standard | Admin access between container and host | Manual check needed | 0 |  |
| SYS.1.6.A17 | Standard | Run containers without privileges | Deviation | 13 |  |
| SYS.1.6.A18 | Standard | Host rights of container accounts | Manual check needed | 0 |  |
| SYS.1.6.A19 | Standard | Mount storage into containers | Manual check needed | 0 |  |
| SYS.1.6.A20 | Standard | Protect configuration data | Organizational | 0 |  |
| SYS.1.6.A21 | Elevated | Restrict containers with MAC policies | Deviation | 6 |  |
| SYS.1.6.A22 | Elevated | Prepare for forensic analysis | Organizational | 0 |  |
| SYS.1.6.A23 | Elevated | Immutable containers | Deviation | 8 |  |
| SYS.1.6.A24 | Elevated | Monitor container behaviour for attacks | Manual check needed | 0 |  |
| SYS.1.6.A25 | Elevated | Decide the availability level for container applications | Organizational | 0 |  |
| SYS.1.6.A26 | Elevated | Stronger container isolation | Organizational | 0 |  |

## 3. Findings by priority

_Order follows the AI-generated priority, to be reviewed by the auditor._

### 1. Privileged container

| | |
|---|---|
| Check | `workload.privileged` |
| Severity | Critical |
| Requirements | SYS.1.6.A17 |
| Sources | built-in, kubescape, trivy |
| Findings | 2 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `54532d8196f6697a` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].securityContext.privileged`<br>`scanners/kubescape.json` `$.results[63].controls[15]`<br>`scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[11]` | 1 – Privileged container with host access: escape to the node is possible. (_AI-generated, to be reviewed by the auditor_) | – |
| `6ed8e21b38a1627b` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.containers[0].securityContext.privileged`<br>`scanners/kubescape.json` `$.results[135].controls[15]`<br>`scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[9]` | – | – |

**Remediation:** Remove securityContext.privileged or set it to false.

_The commands were not executed._

### 2. hostPath volume mounted

| | |
|---|---|
| Check | `workload.host_path` |
| Severity | High |
| Requirements | no BSI mapping |
| Sources | built-in, kubescape, trivy |
| Findings | 7 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `f87e6e6ec5c9e1d0` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.volumes[0].hostPath`<br>`scanners/kubescape.json` `$.results[63].controls[13]`<br>`scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[16]` | 2 – Host file system mounted into the pod. (_AI-generated, to be reviewed by the auditor_) | – |
| `f571c2e48f813553` | `Pod/kube-system/etcd-kba-it2-control-plane` | `resources/pods.json` `$.items[4].spec.volumes[0].hostPath`<br>`resources/pods.json` `$.items[4].spec.volumes[1].hostPath`<br>`scanners/kubescape.json` `$.results[81].controls[13]`<br>`scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[10]` | – | – |
| `f8da032b5ab0c191` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.volumes[0].hostPath`<br>`resources/pods.json` `$.items[5].spec.volumes[1].hostPath`<br>`resources/pods.json` `$.items[5].spec.volumes[2].hostPath`<br>`resources/pods.json` `$.items[5].spec.volumes[3].hostPath`<br>`scanners/kubescape.json` `$.results[134].controls[13]`<br>`scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[11]` | – | – |
| `e7caf5c329029ab8` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.volumes[0].hostPath`<br>`resources/pods.json` `$.items[6].spec.volumes[1].hostPath`<br>`resources/pods.json` `$.items[6].spec.volumes[2].hostPath`<br>`resources/pods.json` `$.items[6].spec.volumes[3].hostPath`<br>`resources/pods.json` `$.items[6].spec.volumes[4].hostPath`<br>`scanners/kubescape.json` `$.results[82].controls[14]`<br>`scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[21]` | – | – |
| `1874566fde2d1459` | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` | `resources/pods.json` `$.items[7].spec.volumes[0].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[1].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[2].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[3].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[4].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[5].hostPath`<br>`scanners/kubescape.json` `$.results[83].controls[13]`<br>`scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[14]` | – | – |
| `5184726ed0cb13f3` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.volumes[1].hostPath`<br>`resources/pods.json` `$.items[8].spec.volumes[2].hostPath`<br>`scanners/kubescape.json` `$.results[135].controls[13]`<br>`scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[13]` | – | – |
| `7923c7d8b8a3d348` | `Pod/kube-system/kube-scheduler-kba-it2-control-plane` | `resources/pods.json` `$.items[9].spec.volumes[0].hostPath`<br>`scanners/kubescape.json` `$.results[84].controls[13]`<br>`scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[12]` | – | – |

**Remediation:** Replace hostPath with PersistentVolumes, ConfigMaps or emptyDir.

_The commands were not executed._

### 3. Permissions for anonymous or unauthenticated access

| | |
|---|---|
| Check | `identity.anonymous_binding` |
| Severity | Critical |
| Requirements | APP.4.4.A3 |
| Sources | built-in |
| Findings | 1 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `236c5489655114b0` | `ClusterRoleBinding/-/audit-demo-anon` | `resources/clusterrolebindings.json` `$.items[0].subjects` | 3 – Anonymous requests receive permissions in the cluster. (_AI-generated, to be reviewed by the auditor_) | – |

**Remediation:** Remove the binding to system:anonymous or system:unauthenticated.

_The commands were not executed._

### 4. Role with wildcard permissions (*)

| | |
|---|---|
| Check | `identity.wildcard_role` |
| Severity | High |
| Requirements | APP.4.4.A3 |
| Sources | built-in |
| Findings | 1 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `f64dba7e79577813` | `ClusterRole/-/audit-demo-wildcard` | `resources/clusterroles.json` `$.items[1].rules[0]` | 4 – Wildcard role, reachable through the anonymous binding. (_AI-generated, to be reviewed by the auditor_) | – |

**Remediation:** Replace wildcards in verbs and resources with explicit values.

_The commands were not executed._

### 5. Credential as plain-text environment variable

| | |
|---|---|
| Check | `secrets.credential_literal_env` |
| Severity | High |
| Requirements | SYS.1.6.A8 |
| Sources | built-in |
| Findings | 1 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `7d0e7266a1e7b40c` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].env[0]` | 5 – Password in plain text in the pod manifest. (_AI-generated, to be reviewed by the auditor_) | Treat the password as disclosed because it was in the pod manifest: rotate it and mount it through secretKeyRef. (_AI-generated, to be reviewed by the auditor_) |

**Remediation:** Move the value into a Secret and rotate it; the plain text was in the pod manifest.

_The commands were not executed._

### 6. No encryption at rest configured for etcd

| | |
|---|---|
| Check | `control_plane.encryption_at_rest` |
| Severity | High |
| Requirements | no BSI mapping |
| Sources | built-in |
| Findings | 1 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `e465d75765081e10` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.containers[0].command` | 6 – Secrets are stored unencrypted in etcd. (_AI-generated, to be reviewed by the auditor_) | – |

**Remediation:** Create an EncryptionConfiguration and set --encryption-provider-config on the API server.

_The commands were not executed._

### 7. API server audit logging not enabled

| | |
|---|---|
| Check | `control_plane.audit_logging` |
| Severity | High |
| Requirements | no BSI mapping |
| Sources | built-in |
| Findings | 1 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `1195cfbf437e0023` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.containers[0].command` | 7 – Without an audit log, access cannot be traced. (_AI-generated, to be reviewed by the auditor_) | – |

**Remediation:** Set --audit-policy-file and --audit-log-path and ship the logs centrally.

_The commands were not executed._

### 8. Added Linux capabilities

| | |
|---|---|
| Check | `workload.added_capabilities` |
| Severity | High |
| Requirements | SYS.1.6.A17 |
| Sources | built-in |
| Findings | 2 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `481f89dcaa6fdf9c` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].securityContext.capabilities.add` | – | – |
| `28b1e76c145294f5` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.containers[0].securityContext.capabilities.add` | – | – |

**Remediation:** Remove capabilities.add; only NET_BIND_SERVICE is acceptable when needed. Set drop: \[ALL\].

_The commands were not executed._

### 9. Pod uses host namespaces

| | |
|---|---|
| Check | `workload.host_namespaces` |
| Severity | High |
| Requirements | no BSI mapping |
| Sources | built-in |
| Findings | 7 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `79748001703b4712` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.hostNetwork` | – | – |
| `0e6f917d0fce0c9d` | `Pod/kube-system/etcd-kba-it2-control-plane` | `resources/pods.json` `$.items[4].spec.hostNetwork` | – | – |
| `98b15919cee02990` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.hostNetwork` | – | – |
| `a7f5305690288df4` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.hostNetwork` | – | – |
| `27a44f706aaa0f58` | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` | `resources/pods.json` `$.items[7].spec.hostNetwork` | – | – |
| `db3aa40302219491` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.hostNetwork` | – | – |
| `60d86ffadcc6998d` | `Pod/kube-system/kube-scheduler-kba-it2-control-plane` | `resources/pods.json` `$.items[9].spec.hostNetwork` | – | – |

**Remediation:** Remove hostNetwork, hostPID and hostIPC unless strictly required.

_The commands were not executed._

### 10. Container runs as root (UID 0)

| | |
|---|---|
| Check | `workload.run_as_root` |
| Severity | High |
| Requirements | SYS.1.6.A17 |
| Sources | built-in |
| Findings | 1 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `186a31abb1fb1ced` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].securityContext` | – | – |

**Remediation:** Set runAsUser to a UID above 0 and add runAsNonRoot: true.

_The commands were not executed._

### 11. Anonymous requests allowed on the API server

| | |
|---|---|
| Check | `control_plane.anonymous_auth` |
| Severity | Medium |
| Requirements | APP.4.4.A3 |
| Sources | built-in |
| Findings | 1 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `13c1aafe0491018f` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.containers[0].command` | – | – |

**Remediation:** Set --anonymous-auth=false; first confirm health probes do not rely on anonymous access.

_The commands were not executed._

### 12. etcd client port listens on a non-loopback address

| | |
|---|---|
| Check | `control_plane.etcd_listen_non_loopback` |
| Severity | Medium |
| Requirements | no BSI mapping |
| Sources | built-in |
| Findings | 1 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `391ab1aa42b599cc` | `Pod/kube-system/etcd-kba-it2-control-plane` | `resources/pods.json` `$.items[4].spec.containers[0].command` | – | – |

**Remediation:** Restrict port 2379 to control plane nodes by firewall, or bind to 127.0.0.1 only.

_The commands were not executed._

### 13. Service account token automounted

| | |
|---|---|
| Check | `identity.automount_token` |
| Severity | Medium |
| Requirements | no BSI mapping |
| Sources | built-in |
| Findings | 6 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `6a9855fb7c74ef5b` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.automountServiceAccountToken` | – | – |
| `8970d25ce3efd16a` | `Pod/kube-system/coredns-559f6c778d-b872f` | `resources/pods.json` `$.items[2].spec.automountServiceAccountToken` | – | – |
| `2c6bf8fb607b31e1` | `Pod/kube-system/coredns-559f6c778d-cdlt4` | `resources/pods.json` `$.items[3].spec.automountServiceAccountToken` | – | – |
| `4496134648c73ba3` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.automountServiceAccountToken` | – | – |
| `1be345d69e421458` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.automountServiceAccountToken` | – | – |
| `9fb31bfc975ae336` | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-7hscg` | `resources/pods.json` `$.items[10].spec.automountServiceAccountToken` | – | – |

**Remediation:** Set automountServiceAccountToken: false when the pod does not need the Kubernetes API.

_The commands were not executed._

### 14. Pod uses the default service account

| | |
|---|---|
| Check | `identity.default_service_account` |
| Severity | Medium |
| Requirements | APP.4.4.A9 |
| Sources | built-in |
| Findings | 1 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `9265c87df8caa98f` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.serviceAccountName` | – | – |

**Remediation:** Create a dedicated service account per application and set serviceAccountName.

_The commands were not executed._

### 15. Image without fixed version (latest or no tag)

| | |
|---|---|
| Check | `images.latest_tag` |
| Severity | Medium |
| Requirements | SYS.1.6.A6 |
| Sources | built-in |
| Findings | 1 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `dfd07dbdffcea6fe` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].image` | – | – |

**Remediation:** Use a fixed version tag or a digest.

_The commands were not executed._

### 16. Namespace with pods but no NetworkPolicy

| | |
|---|---|
| Check | `isolation.no_network_policy` |
| Severity | Medium |
| Requirements | APP.4.4.A7, APP.4.4.A18, SYS.1.6.A5 |
| Sources | built-in |
| Findings | 2 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `afebaf40b0c7833c` | `Namespace/-/audit-demo` | `resources/namespaces.json` `$.items[0]` | – | – |
| `e9912d622a36eae9` | `Namespace/-/local-path-storage` | `resources/namespaces.json` `$.items[5]` | – | – |

**Remediation:** Create a default-deny NetworkPolicy and explicitly allow required connections.

_The commands were not executed._

### 17. Namespace without Pod Security Admission label

| | |
|---|---|
| Check | `isolation.psa_labels_missing` |
| Severity | Medium |
| Requirements | no BSI mapping |
| Sources | built-in |
| Findings | 3 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `8169c3b7972227e6` | `Namespace/-/audit-demo` | `resources/namespaces.json` `$.items[0].metadata.labels` | – | – |
| `c5a61be346b51115` | `Namespace/-/default` | `resources/namespaces.json` `$.items[1].metadata.labels` | – | – |
| `39495e677f6b9364` | `Namespace/-/local-path-storage` | `resources/namespaces.json` `$.items[5].metadata.labels` | – | – |

**Remediation:** Set the label pod-security.kubernetes.io/enforce (baseline or restricted). Cluster-wide defaults from an AdmissionConfiguration are not visible to this tool.

_The commands were not executed._

### 18. Privilege escalation not prevented

| | |
|---|---|
| Check | `workload.privilege_escalation` |
| Severity | Medium |
| Requirements | SYS.1.6.A17 |
| Sources | built-in, kubescape, trivy |
| Findings | 8 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `bc6faa3e6ba08684` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[63].controls[3]`<br>`scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[0]` | – | – |
| `29fdc5da1b178356` | `Pod/kube-system/etcd-kba-it2-control-plane` | `resources/pods.json` `$.items[4].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[81].controls[3]`<br>`scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[0]` | – | – |
| `0893785587cd1038` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[134].controls[3]`<br>`scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[0]` | – | – |
| `103c906e6a13cb4f` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[82].controls[4]`<br>`scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[10]` | – | – |
| `922d71b315aa5232` | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` | `resources/pods.json` `$.items[7].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[83].controls[3]`<br>`scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[3]` | – | – |
| `7e302029e6c09c5f` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[135].controls[3]`<br>`scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[0]` | – | – |
| `f72a10c2a9bb9f8d` | `Pod/kube-system/kube-scheduler-kba-it2-control-plane` | `resources/pods.json` `$.items[9].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[84].controls[3]`<br>`scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[1]` | – | – |
| `1549d157e0480728` | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-7hscg` | `resources/pods.json` `$.items[10].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[137].controls[3]`<br>`scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[0]` | – | – |

**Remediation:** Set allowPrivilegeEscalation: false in the securityContext.

_The commands were not executed._

### 19. Non-root execution not enforced

| | |
|---|---|
| Check | `workload.run_as_non_root_missing` |
| Severity | Medium |
| Requirements | no BSI mapping |
| Sources | built-in, kubescape, trivy |
| Findings | 10 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `a5f8dbfd237d76c9` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[63].controls[1]`<br>`scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[6]` | – | – |
| `f28bae31abcacba0` | `Pod/kube-system/coredns-559f6c778d-b872f` | `resources/pods.json` `$.items[2].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[136].controls[1]`<br>`scanners/trivy.json` `$.Resources[170].Results[0].Misconfigurations[1]` | – | – |
| `e695fff3ef6db13d` | `Pod/kube-system/coredns-559f6c778d-cdlt4` | `resources/pods.json` `$.items[3].spec.containers[0].securityContext` | – | – |
| `03cdd6b86b8f6e88` | `Pod/kube-system/etcd-kba-it2-control-plane` | `resources/pods.json` `$.items[4].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[81].controls[1]`<br>`scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[5]` | – | – |
| `4ef9c0cf257a36cd` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[134].controls[1]`<br>`scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[5]` | – | – |
| `cdeb76384c5bbd3f` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[82].controls[2]`<br>`scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[15]` | – | – |
| `4e3b9b00a9ce7c13` | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` | `resources/pods.json` `$.items[7].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[83].controls[1]`<br>`scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[8]` | – | – |
| `bb364a26be57acbf` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[135].controls[1]`<br>`scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[5]` | – | – |
| `96b955e5d0345548` | `Pod/kube-system/kube-scheduler-kba-it2-control-plane` | `resources/pods.json` `$.items[9].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[84].controls[1]`<br>`scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[6]` | – | – |
| `a8ce1491f3a71658` | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-7hscg` | `resources/pods.json` `$.items[10].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[137].controls[1]`<br>`scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[4]` | – | – |

**Remediation:** Set runAsNonRoot: true at pod or container level.

_The commands were not executed._

### 20. No seccomp profile

| | |
|---|---|
| Check | `workload.seccomp_missing` |
| Severity | Medium |
| Requirements | SYS.1.6.A21 |
| Sources | built-in |
| Findings | 6 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `a5968a2517aa01be` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].securityContext` | – | – |
| `a46c4544b9604ede` | `Pod/kube-system/coredns-559f6c778d-b872f` | `resources/pods.json` `$.items[2].spec.containers[0].securityContext` | – | – |
| `38cad5e2d38153c3` | `Pod/kube-system/coredns-559f6c778d-cdlt4` | `resources/pods.json` `$.items[3].spec.containers[0].securityContext` | – | – |
| `204bba01fe0a1f77` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.containers[0].securityContext` | – | – |
| `daac9d1ead83ef10` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.containers[0].securityContext` | – | – |
| `34bc32de8cb327d6` | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-7hscg` | `resources/pods.json` `$.items[10].spec.containers[0].securityContext` | – | – |

**Remediation:** Set seccompProfile.type: RuntimeDefault at pod level.

_The commands were not executed._

### 21. Writable root filesystem

| | |
|---|---|
| Check | `workload.writable_root_fs` |
| Severity | Medium |
| Requirements | SYS.1.6.A23 |
| Sources | built-in, kubescape, trivy |
| Findings | 8 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `404dd121bfa00c06` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[63].controls[4]`<br>`scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[8]` | – | – |
| `da3f4eb443029f1c` | `Pod/kube-system/etcd-kba-it2-control-plane` | `resources/pods.json` `$.items[4].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[81].controls[4]`<br>`scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[6]` | – | – |
| `d5d18cd8a2a6dba8` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[134].controls[4]`<br>`scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[6]` | – | – |
| `1361f15029028af5` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[82].controls[5]`<br>`scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[16]` | – | – |
| `d283779971451670` | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` | `resources/pods.json` `$.items[7].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[83].controls[4]`<br>`scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[9]` | – | – |
| `041fcf58e8ed2264` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[135].controls[4]`<br>`scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[6]` | – | – |
| `ce937c4aa0b7d7da` | `Pod/kube-system/kube-scheduler-kba-it2-control-plane` | `resources/pods.json` `$.items[9].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[84].controls[4]`<br>`scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[7]` | – | – |
| `1d5e38f851e2bd66` | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-7hscg` | `resources/pods.json` `$.items[10].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[137].controls[4]`<br>`scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[5]` | – | – |

**Remediation:** Set readOnlyRootFilesystem: true; mount write paths as emptyDir.

_The commands were not executed._

### 22. Image not pinned by digest

| | |
|---|---|
| Check | `images.no_digest` |
| Severity | Low |
| Requirements | no BSI mapping |
| Sources | built-in |
| Findings | 11 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `f0542ad4f2143393` | `Pod/audit-demo/hardened` | `resources/pods.json` `$.items[0].spec.containers[0].image` | – | – |
| `1270f494dc5b1490` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].image` | – | – |
| `45728527e1d01612` | `Pod/kube-system/coredns-559f6c778d-b872f` | `resources/pods.json` `$.items[2].spec.containers[0].image` | – | – |
| `78c3feaae971ff9d` | `Pod/kube-system/coredns-559f6c778d-cdlt4` | `resources/pods.json` `$.items[3].spec.containers[0].image` | – | – |
| `db6deab2b2910812` | `Pod/kube-system/etcd-kba-it2-control-plane` | `resources/pods.json` `$.items[4].spec.containers[0].image` | – | – |
| `511535913eb97cae` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.containers[0].image` | – | – |
| `52c84e1adeb940b4` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.containers[0].image` | – | – |
| `dc625e0d7f1029ef` | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` | `resources/pods.json` `$.items[7].spec.containers[0].image` | – | – |
| `16cb95f27daacdad` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.containers[0].image` | – | – |
| `3300d51fb20c8086` | `Pod/kube-system/kube-scheduler-kba-it2-control-plane` | `resources/pods.json` `$.items[9].spec.containers[0].image` | – | – |
| `735d0bea9d471f9f` | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-7hscg` | `resources/pods.json` `$.items[10].spec.containers[0].image` | – | – |

**Remediation:** Reference the image by @sha256 digest so its content cannot change.

_The commands were not executed._

### 23. Secret consumed as environment variable

| | |
|---|---|
| Check | `secrets.env_secret_ref` |
| Severity | Low |
| Requirements | no BSI mapping |
| Sources | built-in |
| Findings | 1 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `01a3eb0cc5b80452` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].env` | – | – |

**Remediation:** Mount the secret as a file volume; environment variables easily leak into logs and dumps.

_The commands were not executed._

### 24. Missing CPU or memory limits

| | |
|---|---|
| Check | `workload.resource_limits_missing` |
| Severity | Low |
| Requirements | SYS.1.6.A15 |
| Sources | built-in |
| Findings | 10 |

| ID | Resources | Evidence | Priority | Note |
|---|---|---|---|---|
| `6a7964c06260102b` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].resources` | – | – |
| `5e5bcd6815ea6851` | `Pod/kube-system/coredns-559f6c778d-b872f` | `resources/pods.json` `$.items[2].spec.containers[0].resources` | – | – |
| `db831ea59915f18e` | `Pod/kube-system/coredns-559f6c778d-cdlt4` | `resources/pods.json` `$.items[3].spec.containers[0].resources` | – | – |
| `4534e961137e7b78` | `Pod/kube-system/etcd-kba-it2-control-plane` | `resources/pods.json` `$.items[4].spec.containers[0].resources` | – | – |
| `c96798e9e9d0d767` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.containers[0].resources` | – | – |
| `f703bf6352779a08` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.containers[0].resources` | – | – |
| `0a91d0737b1473f0` | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` | `resources/pods.json` `$.items[7].spec.containers[0].resources` | – | – |
| `d6ad3f9cee4a9524` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.containers[0].resources` | – | – |
| `0866b33e2075f712` | `Pod/kube-system/kube-scheduler-kba-it2-control-plane` | `resources/pods.json` `$.items[9].spec.containers[0].resources` | – | – |
| `7e42efb6bee8c490` | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-7hscg` | `resources/pods.json` `$.items[10].spec.containers[0].resources` | – | – |

**Remediation:** Set resources.limits.cpu and resources.limits.memory for every container.

_The commands were not executed._

## 3a. Other scanner findings

Checks reported only by a scanner, summarized per check. Every single finding is in findings.json.

| Check | Title | Severity | Count | Examples |
|---|---|---|---|---|
| `trivy:KSV-0041` | Manage secrets | Critical | 6 | `ClusterRole/-/admin`, `ClusterRole/-/edit`, `ClusterRole/-/system:aggregate-to-edit` and 3 more |
| `trivy:KSV-0044` | No wildcard verb and resource roles | Critical | 2 | `ClusterRole/-/audit-demo-wildcard`, `ClusterRole/-/cluster-admin` |
| `trivy:KSV-0046` | Manage all resources | Critical | 8 | `ClusterRole/-/audit-demo-wildcard`, `ClusterRole/-/cluster-admin`, `ClusterRole/-/system:controller:generic-garbage-collector` and 5 more |
| `trivy:KSV-0122` | Anonymous user access binding | Critical | 1 | `RoleBinding/kube-public/kubeadm:bootstrap-signer-clusterinfo` |
| `kubescape:C-0012` | Applications credentials in configuration files | High | 2 | `ConfigMap/kube-public/cluster-info`, `Pod/audit-demo/insecure` |
| `kubescape:C-0015` | List Kubernetes secrets | High | 9 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters`, `ServiceAccount/kube-system/bootstrap-signer` and 6 more |
| `kubescape:C-0041` | HostNetwork access | High | 7 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Pod/audit-demo/insecure` and 4 more |
| `kubescape:C-0045` | Writable hostPath mount | High | 4 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Pod/audit-demo/insecure` and 1 more |
| `kubescape:C-0046` | Insecure capabilities | High | 2 | `DaemonSet/kube-system/kindnet`, `Pod/audit-demo/insecure` |
| `kubescape:C-0187` | Minimize wildcard use in Roles and ClusterRoles | High | 2 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters` |
| `kubescape:C-0262` | Anonymous access enabled | High | 3 | `ClusterRoleBinding/-/audit-demo-anon`, `ClusterRoleBinding/-/system:public-info-viewer`, `RoleBinding/kube-public/kubeadm:bootstrap-signer-clusterinfo` |
| `kubescape:C-0270` | Ensure CPU limits are set | High | 9 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` and 6 more |
| `kubescape:C-0271` | Ensure memory limits are set | High | 8 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/local-path-storage/local-path-provisioner` and 5 more |
| `trivy:KSV-0005` | SYS_ADMIN capability added | High | 1 | `Pod/audit-demo/insecure` |
| `trivy:KSV-0009` | Access to host network | High | 7 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Pod/audit-demo/insecure` and 4 more |
| `trivy:KSV-0024` | Access to host ports | High | 4 | `Pod/kube-system/etcd-kba-it2-control-plane`, `Pod/kube-system/kube-apiserver-kba-it2-control-plane`, `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` and 1 more |
| `trivy:KSV-0053` | Exec into Pods | High | 3 | `ClusterRole/-/admin`, `ClusterRole/-/edit`, `ClusterRole/-/system:aggregate-to-edit` |
| `trivy:KSV-0056` | Manage Kubernetes networking | High | 6 | `ClusterRole/-/admin`, `ClusterRole/-/edit`, `ClusterRole/-/system:aggregate-to-edit` and 3 more |
| `trivy:KSV-0118` | Default security context configured | High | 5 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` and 2 more |
| `trivy:KSV-0119` | NET_RAW capability added | High | 1 | `DaemonSet/kube-system/kindnet` |
| `trivy:KSV-0121` | Kubernetes resource with disallowed volumes mounted | High | 1 | `Pod/audit-demo/insecure` |
| `kubescape:C-0002` | Prevent containers from allowing command execution | Medium | 2 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters` |
| `kubescape:C-0007` | Roles with delete capabilities | Medium | 21 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters`, `ServiceAccount/kube-system/cronjob-controller` and 18 more |
| `kubescape:C-0013` | Non-root containers | Medium | 1 | `Pod/audit-demo/hardened` |
| `kubescape:C-0030` | Ingress and Egress blocked | Medium | 10 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` and 7 more |
| `kubescape:C-0031` | Delete Kubernetes events | Medium | 4 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters`, `ServiceAccount/kube-system/generic-garbage-collector` and 1 more |
| `kubescape:C-0034` | Automatic mapping of service account | Medium | 9 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` and 6 more |
| `kubescape:C-0035` | Administrative Roles | Medium | 2 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters` |
| `kubescape:C-0037` | CoreDNS poisoning | Medium | 5 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters`, `ServiceAccount/kube-system/generic-garbage-collector` and 2 more |
| `kubescape:C-0044` | Container hostPort | Medium | 4 | `Pod/kube-system/etcd-kba-it2-control-plane`, `Pod/kube-system/kube-apiserver-kba-it2-control-plane`, `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` and 1 more |
| `kubescape:C-0053` | Access container service account | Medium | 52 | `ServiceAccount/kube-system/attachdetach-controller`, `ServiceAccount/kube-system/bootstrap-signer`, `ServiceAccount/kube-system/certificate-controller` and 49 more |
| `kubescape:C-0054` | Cluster internal networking | Medium | 6 | `Namespace/-/audit-demo`, `Namespace/-/default`, `Namespace/-/kube-node-lease` and 3 more |
| `kubescape:C-0055` | Linux hardening | Medium | 5 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` and 2 more |
| `kubescape:C-0063` | Portforwarding privileges | Medium | 2 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters` |
| `kubescape:C-0066` | Secret/etcd encryption enabled | Medium | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `kubescape:C-0067` | Audit logs enabled | Medium | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `kubescape:C-0188` | Minimize access to create pods | Medium | 9 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters`, `ServiceAccount/kube-system/daemon-set-controller` and 6 more |
| `kubescape:C-0260` | Missing network policy | Medium | 10 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` and 7 more |
| `trivy:KCV-0001` | Ensure that the --anonymous-auth argument is set to false | Medium | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KSV-0013` | Image tag ":latest" used | Medium | 1 | `Pod/audit-demo/insecure` |
| `trivy:KSV-0022` | Specific capabilities added | Medium | 3 | `DaemonSet/kube-system/kindnet`, `Deployment/kube-system/coredns`, `Pod/audit-demo/insecure` |
| `trivy:KSV-0036` | Protecting Pod service account tokens | Medium | 1 | `Pod/audit-demo/insecure` |
| `trivy:KSV-0037` | User resources should not be placed in kube-system namespace | Medium | 4 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` and 1 more |
| `trivy:KSV-0048` | Manage Kubernetes workloads and pods | Medium | 18 | `ClusterRole/-/admin`, `ClusterRole/-/edit`, `ClusterRole/-/system:aggregate-to-edit` and 15 more |
| `trivy:KSV-0049` | Manage configmaps | Medium | 6 | `ClusterRole/-/admin`, `ClusterRole/-/edit`, `ClusterRole/-/system:aggregate-to-edit` and 3 more |
| `trivy:KSV-01010` | ConfigMap with sensitive content | Medium | 1 | `ConfigMap/kube-system/extension-apiserver-authentication` |
| `trivy:KSV-0104` | Seccomp policies disabled | Medium | 5 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` and 2 more |
| `trivy:KSV-0111` | User with admin access | Medium | 2 | `ClusterRoleBinding/-/cluster-admin`, `ClusterRoleBinding/-/kubeadm:cluster-admins` |
| `trivy:KSV-0113` | Manage namespace secrets | Medium | 2 | `Role/kube-system/system:controller:bootstrap-signer`, `Role/kube-system/system:controller:token-cleaner` |
| `trivy:KSV-0117` | Prevent binding to privileged ports | Medium | 1 | `Deployment/kube-system/coredns` |
| `trivy:KSV-0125` | Restrict container images to trusted registries | Medium | 9 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` and 6 more |
| `kubescape:C-0068` | PSP enabled | Low | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:DLA-4792-1` | DLA-4792-1 in tzdata 2025b-0+deb12u2 | Low (not rated by the scanner) | 7 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` and 4 more |
| `trivy:DSA-6530-1` | DSA-6530-1 in libpcre2-8-0 10.46-1~deb13u2 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:GO-2026-5932` | GO-2026-5932 in golang.org/x/crypto v0.54.0 | Low (not rated by the scanner) | 6 | `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns`, `Pod/kube-system/etcd-kba-it2-control-plane` and 3 more |
| `trivy:KCV-0006` | Ensure that the --kubelet-certificate-authority argument is set as appropriate | Low | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0010` | Ensure that the admission control plugin EventRateLimit is set | Low | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0012` | Ensure that the admission control plugin AlwaysPullImages is set | Low | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0018` | Ensure that the --profiling argument is set to false | Low | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0019` | Ensure that the --audit-log-path argument is set | Low | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0020` | Ensure that the --audit-log-maxage argument is set to 30 or as appropriate | Low | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0021` | Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate | Low | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0022` | Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate | Low | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0030` | Ensure that the --encryption-provider-config argument is set as appropriate | Low | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0033` | Ensure that the --terminated-pod-gc-threshold argument is set as appropriate | Low | 1 | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` |
| `trivy:KCV-0034` | Ensure that the --profiling argument is set to false | Low | 1 | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` |
| `trivy:KCV-0038` | Ensure that the RotateKubeletServerCertificate argument is set to true | Low | 1 | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` |
| `trivy:KCV-0040` | Ensure that the --profiling argument is set to false | Low | 1 | `Pod/kube-system/kube-scheduler-kba-it2-control-plane` |
| `trivy:KSV-0003` | Default capabilities: some containers do not drop all | Low | 8 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/local-path-storage/local-path-provisioner` and 5 more |
| `trivy:KSV-0004` | Default capabilities: some containers do not drop any | Low | 8 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/local-path-storage/local-path-provisioner` and 5 more |
| `trivy:KSV-0011` | CPU not limited | Low | 9 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` and 6 more |
| `trivy:KSV-0015` | CPU requests not specified | Low | 3 | `DaemonSet/kube-system/kube-proxy`, `Deployment/local-path-storage/local-path-provisioner`, `Pod/audit-demo/insecure` |
| `trivy:KSV-0016` | Memory requests not specified | Low | 6 | `DaemonSet/kube-system/kube-proxy`, `Deployment/local-path-storage/local-path-provisioner`, `Pod/audit-demo/insecure` and 3 more |
| `trivy:KSV-0018` | Memory not limited | Low | 8 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/local-path-storage/local-path-provisioner` and 5 more |
| `trivy:KSV-0020` | Runs with UID \<= 10000 | Low | 9 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` and 6 more |
| `trivy:KSV-0021` | Runs with GID \<= 10000 | Low | 10 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` and 7 more |
| `trivy:KSV-0030` | Runtime/Default Seccomp profile not set | Low | 5 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` and 2 more |
| `trivy:KSV-0105` | Containers must not set runAsUser to 0 | Low | 1 | `Pod/audit-demo/insecure` |
| `trivy:KSV-0106` | Container capabilities must only include NET_BIND_SERVICE | Low | 8 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/local-path-storage/local-path-provisioner` and 5 more |
| `trivy:TEMP-0000000-0F03E5` | TEMP-0000000-0F03E5 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-18A2CE` | TEMP-0000000-18A2CE in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-21F713` | TEMP-0000000-21F713 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-4EF776` | TEMP-0000000-4EF776 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-78AC20` | TEMP-0000000-78AC20 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-956D99` | TEMP-0000000-956D99 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-BB5891` | TEMP-0000000-BB5891 in libde265-0 1.0.15-1+deb13u2 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-BBE297` | TEMP-0000000-BBE297 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-D1A721` | TEMP-0000000-D1A721 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-DB3DE2` | TEMP-0000000-DB3DE2 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-E66AA0` | TEMP-0000000-E66AA0 in libde265-0 1.0.15-1+deb13u2 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-F2B97A` | TEMP-0000000-F2B97A in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0290435-0B57B5` | TEMP-0290435-0B57B5 in tar 1.35+dfsg-3.1 | Low | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0517018-A83CE6` | TEMP-0517018-A83CE6 in sysvinit-utils 3.14-4 | Low | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0628843-DBAD28` | TEMP-0628843-DBAD28 in login.defs 1:4.17.4-2 | Low | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0841856-B18BAF` | TEMP-0841856-B18BAF in bash 5.2.37-2+b10 | Low | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-1147318-639065` | TEMP-1147318-639065 in liblzma5 5.8.1-1+deb13u1 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-1148137-089975` | TEMP-1148137-089975 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-1148137-126A7B` | TEMP-1148137-126A7B in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Low (not rated by the scanner) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-1149217-B31E38` | TEMP-1149217-B31E38 in libpcre2-8-0 10.42-1 | Low (not rated by the scanner) | 3 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Pod/audit-demo/insecure` |

## 3b. Image vulnerabilities

Number of distinct vulnerability IDs per image and severity. The full list is in findings.json.

| Image | Critical | High | Medium | Low | Workloads |
|---|---|---|---|---|---|
| `nginx:latest (debian 13.7)` | 1 | 28 | 68 | 76 | 1 |
| `go-runner` | 1 | 19 | 9 | 1 | 1 |
| `docker.io/kindest/kindnetd:v20260820-69b56db7 (debian 12.13)` | 1 | 11 | 31 | 34 | 1 |
| `coredns` | 0 | 26 | 9 | 0 | 1 |
| `usr/local/bin/etcd` | 0 | 13 | 3 | 1 | 1 |
| `usr/local/bin/local-path-provisioner` | 0 | 7 | 5 | 1 | 1 |
| `registry.k8s.io/kube-proxy:v1.37.0 (debian 12.14)` | 0 | 4 | 24 | 20 | 1 |
| `usr/local/bin/kube-apiserver` | 0 | 3 | 3 | 1 | 1 |
| `usr/local/bin/kube-controller-manager` | 0 | 3 | 3 | 1 | 1 |
| `usr/local/bin/kube-proxy` | 0 | 3 | 3 | 1 | 1 |
| `usr/local/bin/kube-scheduler` | 0 | 3 | 3 | 1 | 1 |
| `bin/kindnetd` | 0 | 2 | 0 | 0 | 1 |
| `Cluster/k8s.io/kubernetes` | 0 | 0 | 1 | 0 | 1 |
| `ControlPlaneComponents/k8s.io/controller-manager` | 0 | 0 | 1 | 0 | 1 |
| `ControlPlaneComponents/k8s.io/apiserver` | 0 | 0 | 0 | 1 | 1 |

## 4. Questions for manual and organizational requirements

**APP.4.4.A1 – Plan the separation of applications**
- [ ] Is there a documented separation concept for namespaces, clusters and networks? Who approved it?
- [ ] Do applications with different protection needs share a cluster? If so, what is the justification?

**APP.4.4.A2 – Plan automation with CI/CD**
- [ ] Which pipeline may deploy into which namespaces, and with which permissions?
- [ ] How are secrets stored and rotated in the pipeline?

**APP.4.4.A4 – Separate pods from each other**
- [ ] Which pods use the host network, host PID or host IPC, and is each case justified?
- [ ] Which operating system and container runtime run on the nodes, and are user namespaces enabled?

**APP.4.4.A5 – Back up the cluster**
- [ ] How are etcd and the persistent volumes backed up, how often, and when was a restore last tested?
- [ ] Are registries and infrastructure applications (e.g. CI/CD, storage) included in the backup?

**APP.4.4.A6 – Initialize pods through init containers**
- [ ] Which applications run initialization steps at start-up, and do these run in init containers?

**APP.4.4.A8 – Protect configuration files**
- [ ] Are all cluster configurations under version control (e.g. Git, GitOps), with traceable comments on changes?
- [ ] Who has read and write access to the control plane configuration?

**APP.4.4.A10 – Secure automation processes**
- [ ] With which Kubernetes permissions do the CI/CD pipelines run, and are they separated per team or application?

**APP.4.4.A11 – Monitor containers with health checks**
- [ ] Do all containers have readiness and liveness probes, and do these test the actual function of the application?

**APP.4.4.A12 – Secure infrastructure applications**
- [ ] Which infrastructure applications (registry, CI/CD, storage, GitOps) are self-operated, and how are access, encryption, logging and backup handled?

**APP.4.4.A13 – Audit the configuration automatically**
- [ ] Is there a regular automated audit (e.g. CIS benchmark), and who evaluates the results?
- [ ] Which tools enforce rules in the cluster (e.g. Pod Security Admission, Kyverno, Gatekeeper)?

**APP.4.4.A14 – Nodes with dedicated roles**
- [ ] How is it ensured that only matching pods run on control plane, bastion and storage nodes (taints, node selectors)?

**APP.4.4.A15 – Own clusters or nodes for very high protection needs**
- [ ] Which applications have very high protection needs, and do they run on their own clusters or exclusive nodes?

**APP.4.4.A16 – Use operators**
- [ ] Which critical applications and control plane components are run through operators?

**APP.4.4.A17 – Attest nodes**
- [ ] Is node integrity verified before a node joins the cluster (e.g. TPM, measured boot)?

**APP.4.4.A19 – Run Kubernetes with high availability**
- [ ] Across how many sites or fire compartments are the control plane and nodes spread, and has a site failure been rehearsed?

**APP.4.4.A20 – Encrypt persistent data**
- [ ] Are the disks of etcd and of the persistent volumes encrypted (e.g. LUKS, encrypted cloud volumes)?

**APP.4.4.A21 – Restart pods regularly**
- [ ] Are pods of applications with very high protection needs restarted regularly, and how is availability kept during restarts?

**SYS.1.6.A1 – Plan the use of containers**
- [ ] Is there a documented plan that states the purpose of using containers? Who approved it?

**SYS.1.6.A2 – Plan container management**
- [ ] Are people who build images treated like administrators regarding permissions and reviews?
- [ ] Are containers started and stopped only through Kubernetes, or also directly through the runtime on the nodes?

**SYS.1.6.A3 – Operate containerized systems securely**
- [ ] Was it assessed and documented per application whether container isolation matches its protection needs?
- [ ] Are the virtual and overlay networks modelled in the network documentation?

**SYS.1.6.A4 – Plan image provisioning**
- [ ] How do images get from build to production, and where is this process documented?

**SYS.1.6.A7 – Store container logs outside the container**
- [ ] Do the applications log to stdout/stderr or to files inside the container? Are the logs collected centrally?

**SYS.1.6.A9 – Application fit for containers**
- [ ] Was it documented for each containerized application that it copes with unexpected termination?

**SYS.1.6.A10 – Set rules for images and container operation**
- [ ] Is there a current policy for images and container operation, and how is its application verified?

**SYS.1.6.A11 – One service per container**
- [ ] Are there containers that run several services (e.g. via a process manager such as supervisord)?

**SYS.1.6.A12 – Distribute secure images**
- [ ] Where is it documented which image sources are trusted and why?
- [ ] Are images signed, and is the signature verified before start (e.g. cosign with admission control)?

**SYS.1.6.A13 – Release images**
- [ ] How are images tested and released before they go to production, and who approves them?

**SYS.1.6.A14 – Update images**
- [ ] How quickly are images rebuilt and rolled out after security-relevant updates?

**SYS.1.6.A16 – Admin access between container and host**
- [ ] Do application containers contain SSH servers or other remote maintenance access?
- [ ] Who may use kubectl exec, and is it logged?

**SYS.1.6.A18 – Host rights of container accounts**
- [ ] Which containers need access to host resources, and under which UID do they run there?

**SYS.1.6.A19 – Mount storage into containers**
- [ ] Is every hostPath mount operationally needed, and is it mounted read-only where possible?
- [ ] How are access permissions on network storage (NFS, CSI volumes) set?

**SYS.1.6.A20 – Protect configuration data**
- [ ] Are all manifests and Helm values under version control, and is every change linked to a ticket or review?

**SYS.1.6.A22 – Prepare for forensic analysis**
- [ ] Are there rules on when and how a container's state is preserved for analysis?

**SYS.1.6.A24 – Monitor container behaviour for attacks**
- [ ] Is runtime monitoring in use (e.g. Falco, Tetragon), and where do its alerts go?

**SYS.1.6.A25 – Decide the availability level for container applications**
- [ ] At which level is availability of highly available applications provided (replicas, nodes, zones)?

**SYS.1.6.A26 – Stronger container isolation**
- [ ] For applications that need stronger isolation, was it assessed whether fixed hosts, hypervisor isolation or dedicated hosts are needed?


## 5. Appendix

### 5.1 Not checked

| Check | Status | Reasons |
|---|---|---|
| `images.registry_not_allowed` | manual check needed | no registry allowlist configured (use --registry-allowlist) |

### 5.2 Permissions during collection

| Resource | Allowed |
|---|---|
| clusterrolebindings | yes |
| clusterroles | yes |
| namespaces | yes |
| networkpolicies | yes |
| nodes | yes |
| pods | yes |
| rolebindings | yes |
| roles | yes |
| secrets | yes |
| serviceaccounts | yes |

### 5.3 Configured exclusions

- `admin_subject_allowlist`: Group:system:masters, Group:kubeadm:cluster-admins
- `anonymous_binding_allowlist`: ClusterRoleBinding/-/system:public-info-viewer, RoleBinding/kube-public/kubeadm:bootstrap-signer-clusterinfo
- `registry_allowlist`: none
- `system_namespaces`: kube-system, kube-public, kube-node-lease

### 5.4 Evidence index

| File | SHA-256 |
|---|---|
| `errors.json` | `339acc3b09add3c3d0e689adf17878a1bd264d3a3f00fccce7db538630e20066` |
| `preflight.json` | `8fad141e6919cbf2293ecc0fbf1708bd3c40c4b87c179cd29c86b42782ed0c83` |
| `resources/clusterrolebindings.json` | `5db7bcfc6c18c6ca6343578893b3d3008bd88ededcbd429691cef2e4b45cc28d` |
| `resources/clusterroles.json` | `cd94114f7553732020df925adb3dba720a4befd1252b3786d677521eb595ce62` |
| `resources/namespaces.json` | `f0204d4107f43f47f95359cc79334303aaaaac310a507a42ac2f5c1fe7439456` |
| `resources/networkpolicies.json` | `90fc342f098745bb50dfae4c6eda65e986fd5a807cf01abdf668d8dd03bca0d6` |
| `resources/nodes.json` | `a3b21188d19ac7d958232779beeae1463f2c6c583445a1501056940efb6ed9de` |
| `resources/pods.json` | `d5216103ead35ef2d8ab925cf04ce00577bbe77b1844fb04d1bc508355a983b4` |
| `resources/rolebindings.json` | `19230baf0c9b5703cf7366b88716d80e70e2a502ad2cae26bbc5e5653299f529` |
| `resources/roles.json` | `8eaeec56a26e696755a796d2cc1cc469f467253a3b330cdbec7ae4965fae331c` |
| `resources/secrets.json` | `be6311737871796085002f033ef2a4e871ad02b9247463c9ab51117e6fadadcb` |
| `resources/serviceaccounts.json` | `402b75381193977759e66844b6571df3f6677be286a0057d8cf92d48bc7c1916` |
| `resources/version.json` | `c8e7ba1d3c9f9c541a44dbc1a213f795647b77eadf01f1c2bd0fd9a9a76439be` |
| `scanners/kubescape.json` | `386819f09521246174a19cf2b18a392eed654c7775cc66e8bbf338dc7cb38363` |
| `scanners/trivy.json` | `6995ff94602d32447c15dae6b493624c680ab3ff3cd99722cae14ac614a4980c` |

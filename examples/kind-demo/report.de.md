# Kubernetes-Sicherheitsaudit – kind-kba-it2

> Dieser Bericht ist keine Zertifizierung und keine Rechtsberatung. „Keine Abweichung festgestellt“ bedeutet nur, dass die automatischen Prüfungen nichts gefunden haben. Nicht mit dem BSI verbunden oder von ihm unterstützt.

| | |
|---|---|
| Cluster | kind-kba-it2 (https://127.0.0.1:55478) |
| Erhebungszeitpunkt | 2026-10-01T02:06:34Z |
| Bundle-Hash (SHA-256, manifest.json) | `e01720e4064efedae539fe2f844c89107af0953b2a5c7ebdcf67bb61244efe61` |
| Herkunft | Hashes geprüft |
| Erzeugt durch | collector |
| Regelwerk | BSI IT-Grundschutz-Kompendium 2023, Module APP.4.4, SYS.1.6 |
| Werkzeug | k8s-baseline-audit 0.1.0 |
| Scanner | kubescape: ok (Your current version is: 4.0.15), trivy: ok (Version: 0.74.0) |

## 1. Management-Zusammenfassung

_KI-generiert, vom Auditor zu prüfen_

Die Prüfung des lokalen Demo-Clusters kind-kba-it2 (Namespace audit-demo) ergab 23 kritische, 217 hohe, 408 mittlere und 285 niedrige Befunde. Es handelt sich um einen absichtlich unsicheren Wegwerf-Cluster. Die wichtigsten Risiken: ein privilegierter Pod mit Host-Namespaces und eingehängtem Host-Dateisystem (54532d8196f6697a, 79748001703b4712, f87e6e6ec5c9e1d0), der zudem als root läuft (186a31abb1fb1ced); eine Bindung an den anonymen Benutzer (236c5489655114b0) zusammen mit einer Rolle mit Wildcard-Rechten (f64dba7e79577813); und ein Passwort als Klartext-Umgebungsvariable (7d0e7266a1e7b40c). Der API-Server hat kein Audit-Logging (1195cfbf437e0023) und keine Verschlüsselung von Secrets in etcd (e465d75765081e10), und der etcd-Client-Port lauscht auf einer Nicht-Loopback-Adresse (391ab1aa42b599cc). Die meisten übrigen Ergebnisse stammen von kubescape und trivy und betreffen Standardrollen und Basis-Images; der Bericht fasst sie je Prüfung und je Image zusammen, findings.json enthält jeden einzelnen Befund. Befunde ohne BSI-Zuordnung sind als keine BSI-Zuordnung markiert und deshalb nicht weniger ernst. Die System-Namespaces kube-system, kube-public und kube-node-lease sind von den Prüfungen zu Pod Security Admission und NetworkPolicy ausgenommen; diese Prüfungen gelten also nicht clusterweit. 17 Anforderungen brauchen eine manuelle Prüfung, 19 sind organisatorisch und lassen sich nicht aus dem Cluster ablesen. Es wurde keine Registry-Allowlist angegeben, daher lief die Registry-Prüfung nicht. Dieser Bericht ist keine Zertifizierung und keine Rechtsberatung.

## 2. Abdeckungsmatrix

| Anforderung | Stufe | Titel | Status | Befunde | Begründung |
|---|---|---|---|---|---|
| APP.4.4.A1 | Basis | Trennung der Anwendungen planen | Organisatorisch | 0 |  |
| APP.4.4.A2 | Basis | Automatisierung mit CI/CD planen | Organisatorisch | 0 |  |
| APP.4.4.A3 | Basis | Identitäts- und Berechtigungsmanagement | Abweichung | 3 |  |
| APP.4.4.A4 | Basis | Pods voneinander trennen | Manuelle Prüfung nötig | 0 |  |
| APP.4.4.A5 | Basis | Cluster sichern | Manuelle Prüfung nötig | 0 |  |
| APP.4.4.A6 | Standard | Pods über Init-Container initialisieren | Manuelle Prüfung nötig | 0 |  |
| APP.4.4.A7 | Standard | Netze im Cluster trennen | Abweichung | 2 |  |
| APP.4.4.A8 | Standard | Konfigurationsdateien absichern | Organisatorisch | 0 |  |
| APP.4.4.A9 | Standard | Service-Accounts gezielt nutzen | Abweichung | 1 |  |
| APP.4.4.A10 | Standard | Automatisierungsprozesse absichern | Organisatorisch | 0 |  |
| APP.4.4.A11 | Standard | Container per Health Check überwachen | Manuelle Prüfung nötig | 0 |  |
| APP.4.4.A12 | Standard | Infrastrukturanwendungen absichern | Manuelle Prüfung nötig | 0 |  |
| APP.4.4.A13 | Erhöht | Konfiguration automatisiert auditieren | Manuelle Prüfung nötig | 0 |  |
| APP.4.4.A14 | Erhöht | Nodes mit festen Aufgaben | Manuelle Prüfung nötig | 0 |  |
| APP.4.4.A15 | Erhöht | Eigene Cluster oder Nodes bei sehr hohem Schutzbedarf | Organisatorisch | 0 |  |
| APP.4.4.A16 | Erhöht | Operatoren einsetzen | Organisatorisch | 0 |  |
| APP.4.4.A17 | Erhöht | Nodes attestieren | Manuelle Prüfung nötig | 0 |  |
| APP.4.4.A18 | Erhöht | Mikrosegmentierung | Abweichung | 2 |  |
| APP.4.4.A19 | Erhöht | Kubernetes ausfallsicher betreiben | Manuelle Prüfung nötig | 0 |  |
| APP.4.4.A20 | Erhöht | Persistente Daten verschlüsselt speichern | Manuelle Prüfung nötig | 0 |  |
| APP.4.4.A21 | Erhöht | Pods regelmäßig neu starten | Manuelle Prüfung nötig | 0 |  |
| SYS.1.6.A1 | Basis | Container-Einsatz planen | Organisatorisch | 0 |  |
| SYS.1.6.A2 | Basis | Container-Verwaltung planen | Organisatorisch | 0 |  |
| SYS.1.6.A3 | Basis | Containerisierte Systeme sicher einsetzen | Organisatorisch | 0 |  |
| SYS.1.6.A4 | Basis | Bereitstellung von Images planen | Organisatorisch | 0 |  |
| SYS.1.6.A5 | Basis | Administrations- und Zugangsnetze trennen | Abweichung | 2 |  |
| SYS.1.6.A6 | Basis | Sichere Images verwenden | Abweichung | 1 | images.registry_not_allowed: no registry allowlist configured (use --registry-allowlist) |
| SYS.1.6.A7 | Basis | Container-Protokolle außerhalb speichern | Manuelle Prüfung nötig | 0 |  |
| SYS.1.6.A8 | Basis | Zugangsdaten sicher ablegen | Abweichung | 1 |  |
| SYS.1.6.A9 | Standard | Container-Tauglichkeit der Anwendung | Organisatorisch | 0 |  |
| SYS.1.6.A10 | Standard | Regeln für Images und Containerbetrieb festlegen | Organisatorisch | 0 |  |
| SYS.1.6.A11 | Standard | Ein Dienst je Container | Manuelle Prüfung nötig | 0 |  |
| SYS.1.6.A12 | Standard | Sichere Images verteilen | Organisatorisch | 0 |  |
| SYS.1.6.A13 | Standard | Images freigeben | Organisatorisch | 0 |  |
| SYS.1.6.A14 | Standard | Images aktualisieren | Organisatorisch | 0 |  |
| SYS.1.6.A15 | Standard | Ressourcen je Container begrenzen | Abweichung | 10 |  |
| SYS.1.6.A16 | Standard | Admin-Zugriffe zwischen Container und Host | Manuelle Prüfung nötig | 0 |  |
| SYS.1.6.A17 | Standard | Container ohne Privilegien ausführen | Abweichung | 13 |  |
| SYS.1.6.A18 | Standard | Host-Rechte von Container-Accounts | Manuelle Prüfung nötig | 0 |  |
| SYS.1.6.A19 | Standard | Datenspeicher in Container einbinden | Manuelle Prüfung nötig | 0 |  |
| SYS.1.6.A20 | Standard | Konfigurationsdaten absichern | Organisatorisch | 0 |  |
| SYS.1.6.A21 | Erhöht | Container per MAC-Richtlinien einschränken | Abweichung | 6 |  |
| SYS.1.6.A22 | Erhöht | Für forensische Untersuchungen vorsorgen | Organisatorisch | 0 |  |
| SYS.1.6.A23 | Erhöht | Unveränderliche Container | Abweichung | 8 |  |
| SYS.1.6.A24 | Erhöht | Container-Verhalten auf Angriffe überwachen | Manuelle Prüfung nötig | 0 |  |
| SYS.1.6.A25 | Erhöht | Verfügbarkeitsebene für Container-Anwendungen festlegen | Organisatorisch | 0 |  |
| SYS.1.6.A26 | Erhöht | Stärkere Isolation von Containern | Organisatorisch | 0 |  |

## 3. Befunde nach Priorität

_Reihenfolge nach KI-generierter Priorität, vom Auditor zu prüfen._

### 1. Privilegierter Container

| | |
|---|---|
| Prüfung | `workload.privileged` |
| Schweregrad | Kritisch |
| Anforderungen | SYS.1.6.A17 |
| Quellen | built-in, kubescape, trivy |
| Befunde | 2 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `54532d8196f6697a` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].securityContext.privileged`<br>`scanners/kubescape.json` `$.results[63].controls[15]`<br>`scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[11]` | 1 – Privilegierter Container mit Host-Zugriff: Ausbruch auf den Knoten möglich. (_KI-generiert, vom Auditor zu prüfen_) | – |
| `6ed8e21b38a1627b` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.containers[0].securityContext.privileged`<br>`scanners/kubescape.json` `$.results[135].controls[15]`<br>`scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[9]` | – | – |

**Maßnahme:** securityContext.privileged entfernen oder auf false setzen.

_Die Befehle wurden nicht ausgeführt._

### 2. hostPath-Volume eingebunden

| | |
|---|---|
| Prüfung | `workload.host_path` |
| Schweregrad | Hoch |
| Anforderungen | keine BSI-Zuordnung |
| Quellen | built-in, kubescape, trivy |
| Befunde | 7 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `f87e6e6ec5c9e1d0` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.volumes[0].hostPath`<br>`scanners/kubescape.json` `$.results[63].controls[13]`<br>`scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[16]` | 2 – Host-Dateisystem im Pod eingehängt. (_KI-generiert, vom Auditor zu prüfen_) | – |
| `f571c2e48f813553` | `Pod/kube-system/etcd-kba-it2-control-plane` | `resources/pods.json` `$.items[4].spec.volumes[0].hostPath`<br>`resources/pods.json` `$.items[4].spec.volumes[1].hostPath`<br>`scanners/kubescape.json` `$.results[81].controls[13]`<br>`scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[10]` | – | – |
| `f8da032b5ab0c191` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.volumes[0].hostPath`<br>`resources/pods.json` `$.items[5].spec.volumes[1].hostPath`<br>`resources/pods.json` `$.items[5].spec.volumes[2].hostPath`<br>`resources/pods.json` `$.items[5].spec.volumes[3].hostPath`<br>`scanners/kubescape.json` `$.results[134].controls[13]`<br>`scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[11]` | – | – |
| `e7caf5c329029ab8` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.volumes[0].hostPath`<br>`resources/pods.json` `$.items[6].spec.volumes[1].hostPath`<br>`resources/pods.json` `$.items[6].spec.volumes[2].hostPath`<br>`resources/pods.json` `$.items[6].spec.volumes[3].hostPath`<br>`resources/pods.json` `$.items[6].spec.volumes[4].hostPath`<br>`scanners/kubescape.json` `$.results[82].controls[14]`<br>`scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[21]` | – | – |
| `1874566fde2d1459` | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` | `resources/pods.json` `$.items[7].spec.volumes[0].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[1].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[2].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[3].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[4].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[5].hostPath`<br>`scanners/kubescape.json` `$.results[83].controls[13]`<br>`scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[14]` | – | – |
| `5184726ed0cb13f3` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.volumes[1].hostPath`<br>`resources/pods.json` `$.items[8].spec.volumes[2].hostPath`<br>`scanners/kubescape.json` `$.results[135].controls[13]`<br>`scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[13]` | – | – |
| `7923c7d8b8a3d348` | `Pod/kube-system/kube-scheduler-kba-it2-control-plane` | `resources/pods.json` `$.items[9].spec.volumes[0].hostPath`<br>`scanners/kubescape.json` `$.results[84].controls[13]`<br>`scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[12]` | – | – |

**Maßnahme:** hostPath durch PersistentVolumes, ConfigMaps oder emptyDir ersetzen.

_Die Befehle wurden nicht ausgeführt._

### 3. Rechte für anonyme oder nicht authentifizierte Zugriffe

| | |
|---|---|
| Prüfung | `identity.anonymous_binding` |
| Schweregrad | Kritisch |
| Anforderungen | APP.4.4.A3 |
| Quellen | built-in |
| Befunde | 1 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `236c5489655114b0` | `ClusterRoleBinding/-/audit-demo-anon` | `resources/clusterrolebindings.json` `$.items[0].subjects` | 3 – Anonyme Anfragen erhalten Rechte im Cluster. (_KI-generiert, vom Auditor zu prüfen_) | – |

**Maßnahme:** Bindung an system:anonymous bzw. system:unauthenticated entfernen.

_Die Befehle wurden nicht ausgeführt._

### 4. Rolle mit Platzhalter-Rechten (*)

| | |
|---|---|
| Prüfung | `identity.wildcard_role` |
| Schweregrad | Hoch |
| Anforderungen | APP.4.4.A3 |
| Quellen | built-in |
| Befunde | 1 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `f64dba7e79577813` | `ClusterRole/-/audit-demo-wildcard` | `resources/clusterroles.json` `$.items[1].rules[0]` | 4 – Wildcard-Rolle, über die anonyme Bindung erreichbar. (_KI-generiert, vom Auditor zu prüfen_) | – |

**Maßnahme:** Platzhalter in verbs und resources durch konkrete Werte ersetzen.

_Die Befehle wurden nicht ausgeführt._

### 5. Zugangsdaten als Klartext-Umgebungsvariable

| | |
|---|---|
| Prüfung | `secrets.credential_literal_env` |
| Schweregrad | Hoch |
| Anforderungen | SYS.1.6.A8 |
| Quellen | built-in |
| Befunde | 1 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `7d0e7266a1e7b40c` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].env[0]` | 5 – Passwort im Klartext im Pod-Manifest. (_KI-generiert, vom Auditor zu prüfen_) | Das Passwort gilt als offengelegt, weil es im Pod-Manifest stand: rotieren und per secretKeyRef einbinden. (_KI-generiert, vom Auditor zu prüfen_) |

**Maßnahme:** Wert in ein Secret verschieben und rotieren; der Klartext stand im Pod-Manifest.

_Die Befehle wurden nicht ausgeführt._

### 6. Keine Verschlüsselung von Secrets in etcd konfiguriert

| | |
|---|---|
| Prüfung | `control_plane.encryption_at_rest` |
| Schweregrad | Hoch |
| Anforderungen | keine BSI-Zuordnung |
| Quellen | built-in |
| Befunde | 1 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `e465d75765081e10` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.containers[0].command` | 6 – Secrets liegen unverschlüsselt in etcd. (_KI-generiert, vom Auditor zu prüfen_) | – |

**Maßnahme:** EncryptionConfiguration anlegen und --encryption-provider-config am API-Server setzen.

_Die Befehle wurden nicht ausgeführt._

### 7. Audit-Logging des API-Servers nicht aktiv

| | |
|---|---|
| Prüfung | `control_plane.audit_logging` |
| Schweregrad | Hoch |
| Anforderungen | keine BSI-Zuordnung |
| Quellen | built-in |
| Befunde | 1 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `1195cfbf437e0023` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.containers[0].command` | 7 – Ohne Audit-Log sind Zugriffe nicht nachvollziehbar. (_KI-generiert, vom Auditor zu prüfen_) | – |

**Maßnahme:** --audit-policy-file und --audit-log-path setzen und Logs zentral sammeln.

_Die Befehle wurden nicht ausgeführt._

### 8. Zusätzliche Linux-Capabilities

| | |
|---|---|
| Prüfung | `workload.added_capabilities` |
| Schweregrad | Hoch |
| Anforderungen | SYS.1.6.A17 |
| Quellen | built-in |
| Befunde | 2 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `481f89dcaa6fdf9c` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].securityContext.capabilities.add` | – | – |
| `28b1e76c145294f5` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.containers[0].securityContext.capabilities.add` | – | – |

**Maßnahme:** capabilities.add entfernen; nur NET_BIND_SERVICE ist bei Bedarf vertretbar. drop: \[ALL\] setzen.

_Die Befehle wurden nicht ausgeführt._

### 9. Pod nutzt Host-Namespaces

| | |
|---|---|
| Prüfung | `workload.host_namespaces` |
| Schweregrad | Hoch |
| Anforderungen | keine BSI-Zuordnung |
| Quellen | built-in |
| Befunde | 7 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `79748001703b4712` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.hostNetwork` | – | – |
| `0e6f917d0fce0c9d` | `Pod/kube-system/etcd-kba-it2-control-plane` | `resources/pods.json` `$.items[4].spec.hostNetwork` | – | – |
| `98b15919cee02990` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.hostNetwork` | – | – |
| `a7f5305690288df4` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.hostNetwork` | – | – |
| `27a44f706aaa0f58` | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` | `resources/pods.json` `$.items[7].spec.hostNetwork` | – | – |
| `db3aa40302219491` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.hostNetwork` | – | – |
| `60d86ffadcc6998d` | `Pod/kube-system/kube-scheduler-kba-it2-control-plane` | `resources/pods.json` `$.items[9].spec.hostNetwork` | – | – |

**Maßnahme:** hostNetwork, hostPID und hostIPC entfernen, sofern nicht zwingend erforderlich.

_Die Befehle wurden nicht ausgeführt._

### 10. Container läuft als root (UID 0)

| | |
|---|---|
| Prüfung | `workload.run_as_root` |
| Schweregrad | Hoch |
| Anforderungen | SYS.1.6.A17 |
| Quellen | built-in |
| Befunde | 1 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `186a31abb1fb1ced` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].securityContext` | – | – |

**Maßnahme:** runAsUser auf eine UID größer 0 setzen und runAsNonRoot: true ergänzen.

_Die Befehle wurden nicht ausgeführt._

### 11. Anonyme Anfragen am API-Server zugelassen

| | |
|---|---|
| Prüfung | `control_plane.anonymous_auth` |
| Schweregrad | Mittel |
| Anforderungen | APP.4.4.A3 |
| Quellen | built-in |
| Befunde | 1 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `13c1aafe0491018f` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.containers[0].command` | – | – |

**Maßnahme:** --anonymous-auth=false setzen; Health-Probes vorher auf authentifizierte Endpunkte prüfen.

_Die Befehle wurden nicht ausgeführt._

### 12. etcd-Client-Port auf Nicht-Loopback-Adresse erreichbar

| | |
|---|---|
| Prüfung | `control_plane.etcd_listen_non_loopback` |
| Schweregrad | Mittel |
| Anforderungen | keine BSI-Zuordnung |
| Quellen | built-in |
| Befunde | 1 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `391ab1aa42b599cc` | `Pod/kube-system/etcd-kba-it2-control-plane` | `resources/pods.json` `$.items[4].spec.containers[0].command` | – | – |

**Maßnahme:** Erreichbarkeit von Port 2379 per Firewall auf Control-Plane-Knoten beschränken oder nur 127.0.0.1 binden.

_Die Befehle wurden nicht ausgeführt._

### 13. ServiceAccount-Token automatisch eingebunden

| | |
|---|---|
| Prüfung | `identity.automount_token` |
| Schweregrad | Mittel |
| Anforderungen | keine BSI-Zuordnung |
| Quellen | built-in |
| Befunde | 6 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `6a9855fb7c74ef5b` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.automountServiceAccountToken` | – | – |
| `8970d25ce3efd16a` | `Pod/kube-system/coredns-559f6c778d-b872f` | `resources/pods.json` `$.items[2].spec.automountServiceAccountToken` | – | – |
| `2c6bf8fb607b31e1` | `Pod/kube-system/coredns-559f6c778d-cdlt4` | `resources/pods.json` `$.items[3].spec.automountServiceAccountToken` | – | – |
| `4496134648c73ba3` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.automountServiceAccountToken` | – | – |
| `1be345d69e421458` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.automountServiceAccountToken` | – | – |
| `9fb31bfc975ae336` | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-7hscg` | `resources/pods.json` `$.items[10].spec.automountServiceAccountToken` | – | – |

**Maßnahme:** automountServiceAccountToken: false setzen, wenn der Pod die Kubernetes-API nicht braucht.

_Die Befehle wurden nicht ausgeführt._

### 14. Pod nutzt das default-ServiceAccount

| | |
|---|---|
| Prüfung | `identity.default_service_account` |
| Schweregrad | Mittel |
| Anforderungen | APP.4.4.A9 |
| Quellen | built-in |
| Befunde | 1 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `9265c87df8caa98f` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.serviceAccountName` | – | – |

**Maßnahme:** Eigenes ServiceAccount je Anwendung anlegen und serviceAccountName setzen.

_Die Befehle wurden nicht ausgeführt._

### 15. Image ohne feste Version (latest oder kein Tag)

| | |
|---|---|
| Prüfung | `images.latest_tag` |
| Schweregrad | Mittel |
| Anforderungen | SYS.1.6.A6 |
| Quellen | built-in |
| Befunde | 1 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `dfd07dbdffcea6fe` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].image` | – | – |

**Maßnahme:** Feste Versionsnummer oder Digest verwenden.

_Die Befehle wurden nicht ausgeführt._

### 16. Namespace mit Pods, aber ohne NetworkPolicy

| | |
|---|---|
| Prüfung | `isolation.no_network_policy` |
| Schweregrad | Mittel |
| Anforderungen | APP.4.4.A7, APP.4.4.A18, SYS.1.6.A5 |
| Quellen | built-in |
| Befunde | 2 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `afebaf40b0c7833c` | `Namespace/-/audit-demo` | `resources/namespaces.json` `$.items[0]` | – | – |
| `e9912d622a36eae9` | `Namespace/-/local-path-storage` | `resources/namespaces.json` `$.items[5]` | – | – |

**Maßnahme:** Default-Deny-NetworkPolicy anlegen und benötigte Verbindungen explizit erlauben.

_Die Befehle wurden nicht ausgeführt._

### 17. Namespace ohne Pod-Security-Admission-Label

| | |
|---|---|
| Prüfung | `isolation.psa_labels_missing` |
| Schweregrad | Mittel |
| Anforderungen | keine BSI-Zuordnung |
| Quellen | built-in |
| Befunde | 3 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `8169c3b7972227e6` | `Namespace/-/audit-demo` | `resources/namespaces.json` `$.items[0].metadata.labels` | – | – |
| `c5a61be346b51115` | `Namespace/-/default` | `resources/namespaces.json` `$.items[1].metadata.labels` | – | – |
| `39495e677f6b9364` | `Namespace/-/local-path-storage` | `resources/namespaces.json` `$.items[5].metadata.labels` | – | – |

**Maßnahme:** Label pod-security.kubernetes.io/enforce (baseline oder restricted) setzen. Cluster-weite Standardwerte aus einer AdmissionConfiguration sind für dieses Werkzeug nicht sichtbar.

_Die Befehle wurden nicht ausgeführt._

### 18. Rechteausweitung nicht unterbunden

| | |
|---|---|
| Prüfung | `workload.privilege_escalation` |
| Schweregrad | Mittel |
| Anforderungen | SYS.1.6.A17 |
| Quellen | built-in, kubescape, trivy |
| Befunde | 8 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `bc6faa3e6ba08684` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[63].controls[3]`<br>`scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[0]` | – | – |
| `29fdc5da1b178356` | `Pod/kube-system/etcd-kba-it2-control-plane` | `resources/pods.json` `$.items[4].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[81].controls[3]`<br>`scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[0]` | – | – |
| `0893785587cd1038` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[134].controls[3]`<br>`scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[0]` | – | – |
| `103c906e6a13cb4f` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[82].controls[4]`<br>`scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[10]` | – | – |
| `922d71b315aa5232` | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` | `resources/pods.json` `$.items[7].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[83].controls[3]`<br>`scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[3]` | – | – |
| `7e302029e6c09c5f` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[135].controls[3]`<br>`scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[0]` | – | – |
| `f72a10c2a9bb9f8d` | `Pod/kube-system/kube-scheduler-kba-it2-control-plane` | `resources/pods.json` `$.items[9].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[84].controls[3]`<br>`scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[1]` | – | – |
| `1549d157e0480728` | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-7hscg` | `resources/pods.json` `$.items[10].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[137].controls[3]`<br>`scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[0]` | – | – |

**Maßnahme:** allowPrivilegeEscalation: false im securityContext setzen.

_Die Befehle wurden nicht ausgeführt._

### 19. Nicht-root-Ausführung nicht erzwungen

| | |
|---|---|
| Prüfung | `workload.run_as_non_root_missing` |
| Schweregrad | Mittel |
| Anforderungen | keine BSI-Zuordnung |
| Quellen | built-in, kubescape, trivy |
| Befunde | 10 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
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

**Maßnahme:** runAsNonRoot: true auf Pod- oder Container-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 20. Kein Seccomp-Profil

| | |
|---|---|
| Prüfung | `workload.seccomp_missing` |
| Schweregrad | Mittel |
| Anforderungen | SYS.1.6.A21 |
| Quellen | built-in |
| Befunde | 6 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `a5968a2517aa01be` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].securityContext` | – | – |
| `a46c4544b9604ede` | `Pod/kube-system/coredns-559f6c778d-b872f` | `resources/pods.json` `$.items[2].spec.containers[0].securityContext` | – | – |
| `38cad5e2d38153c3` | `Pod/kube-system/coredns-559f6c778d-cdlt4` | `resources/pods.json` `$.items[3].spec.containers[0].securityContext` | – | – |
| `204bba01fe0a1f77` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.containers[0].securityContext` | – | – |
| `daac9d1ead83ef10` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.containers[0].securityContext` | – | – |
| `34bc32de8cb327d6` | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-7hscg` | `resources/pods.json` `$.items[10].spec.containers[0].securityContext` | – | – |

**Maßnahme:** seccompProfile.type: RuntimeDefault auf Pod-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 21. Beschreibbares Root-Dateisystem

| | |
|---|---|
| Prüfung | `workload.writable_root_fs` |
| Schweregrad | Mittel |
| Anforderungen | SYS.1.6.A23 |
| Quellen | built-in, kubescape, trivy |
| Befunde | 8 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `404dd121bfa00c06` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[63].controls[4]`<br>`scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[8]` | – | – |
| `da3f4eb443029f1c` | `Pod/kube-system/etcd-kba-it2-control-plane` | `resources/pods.json` `$.items[4].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[81].controls[4]`<br>`scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[6]` | – | – |
| `d5d18cd8a2a6dba8` | `Pod/kube-system/kindnet-vxq74` | `resources/pods.json` `$.items[5].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[134].controls[4]`<br>`scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[6]` | – | – |
| `1361f15029028af5` | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` | `resources/pods.json` `$.items[6].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[82].controls[5]`<br>`scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[16]` | – | – |
| `d283779971451670` | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` | `resources/pods.json` `$.items[7].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[83].controls[4]`<br>`scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[9]` | – | – |
| `041fcf58e8ed2264` | `Pod/kube-system/kube-proxy-qq6k9` | `resources/pods.json` `$.items[8].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[135].controls[4]`<br>`scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[6]` | – | – |
| `ce937c4aa0b7d7da` | `Pod/kube-system/kube-scheduler-kba-it2-control-plane` | `resources/pods.json` `$.items[9].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[84].controls[4]`<br>`scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[7]` | – | – |
| `1d5e38f851e2bd66` | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-7hscg` | `resources/pods.json` `$.items[10].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[137].controls[4]`<br>`scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[5]` | – | – |

**Maßnahme:** readOnlyRootFilesystem: true setzen; Schreibpfade als emptyDir einbinden.

_Die Befehle wurden nicht ausgeführt._

### 22. Image nicht per Digest fixiert

| | |
|---|---|
| Prüfung | `images.no_digest` |
| Schweregrad | Niedrig |
| Anforderungen | keine BSI-Zuordnung |
| Quellen | built-in |
| Befunde | 11 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
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

**Maßnahme:** Image per @sha256-Digest referenzieren, damit der Inhalt unveränderlich ist.

_Die Befehle wurden nicht ausgeführt._

### 23. Secret als Umgebungsvariable eingebunden

| | |
|---|---|
| Prüfung | `secrets.env_secret_ref` |
| Schweregrad | Niedrig |
| Anforderungen | keine BSI-Zuordnung |
| Quellen | built-in |
| Befunde | 1 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
|---|---|---|---|---|
| `01a3eb0cc5b80452` | `Pod/audit-demo/insecure` | `resources/pods.json` `$.items[1].spec.containers[0].env` | – | – |

**Maßnahme:** Secret als Datei-Volume einbinden; Umgebungsvariablen landen leicht in Logs und Dumps.

_Die Befehle wurden nicht ausgeführt._

### 24. Fehlende CPU- oder Speicherlimits

| | |
|---|---|
| Prüfung | `workload.resource_limits_missing` |
| Schweregrad | Niedrig |
| Anforderungen | SYS.1.6.A15 |
| Quellen | built-in |
| Befunde | 10 |

| ID | Ressourcen | Nachweise | Priorität | Hinweis |
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

**Maßnahme:** resources.limits.cpu und resources.limits.memory für jeden Container setzen.

_Die Befehle wurden nicht ausgeführt._

## 3a. Weitere Scanner-Befunde

Prüfungen, die nur ein Scanner meldet, zusammengefasst je Prüfung. Jeder einzelne Befund steht in findings.json.

| Prüfung | Titel | Schweregrad | Anzahl | Beispiele |
|---|---|---|---|---|
| `trivy:KSV-0041` | Manage secrets | Kritisch | 6 | `ClusterRole/-/admin`, `ClusterRole/-/edit`, `ClusterRole/-/system:aggregate-to-edit` und 3 weitere |
| `trivy:KSV-0044` | No wildcard verb and resource roles | Kritisch | 2 | `ClusterRole/-/audit-demo-wildcard`, `ClusterRole/-/cluster-admin` |
| `trivy:KSV-0046` | Manage all resources | Kritisch | 8 | `ClusterRole/-/audit-demo-wildcard`, `ClusterRole/-/cluster-admin`, `ClusterRole/-/system:controller:generic-garbage-collector` und 5 weitere |
| `trivy:KSV-0122` | Anonymous user access binding | Kritisch | 1 | `RoleBinding/kube-public/kubeadm:bootstrap-signer-clusterinfo` |
| `kubescape:C-0012` | Applications credentials in configuration files | Hoch | 2 | `ConfigMap/kube-public/cluster-info`, `Pod/audit-demo/insecure` |
| `kubescape:C-0015` | List Kubernetes secrets | Hoch | 9 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters`, `ServiceAccount/kube-system/bootstrap-signer` und 6 weitere |
| `kubescape:C-0041` | HostNetwork access | Hoch | 7 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Pod/audit-demo/insecure` und 4 weitere |
| `kubescape:C-0045` | Writable hostPath mount | Hoch | 4 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Pod/audit-demo/insecure` und 1 weitere |
| `kubescape:C-0046` | Insecure capabilities | Hoch | 2 | `DaemonSet/kube-system/kindnet`, `Pod/audit-demo/insecure` |
| `kubescape:C-0187` | Minimize wildcard use in Roles and ClusterRoles | Hoch | 2 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters` |
| `kubescape:C-0262` | Anonymous access enabled | Hoch | 3 | `ClusterRoleBinding/-/audit-demo-anon`, `ClusterRoleBinding/-/system:public-info-viewer`, `RoleBinding/kube-public/kubeadm:bootstrap-signer-clusterinfo` |
| `kubescape:C-0270` | Ensure CPU limits are set | Hoch | 9 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` und 6 weitere |
| `kubescape:C-0271` | Ensure memory limits are set | Hoch | 8 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/local-path-storage/local-path-provisioner` und 5 weitere |
| `trivy:KSV-0005` | SYS_ADMIN capability added | Hoch | 1 | `Pod/audit-demo/insecure` |
| `trivy:KSV-0009` | Access to host network | Hoch | 7 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Pod/audit-demo/insecure` und 4 weitere |
| `trivy:KSV-0024` | Access to host ports | Hoch | 4 | `Pod/kube-system/etcd-kba-it2-control-plane`, `Pod/kube-system/kube-apiserver-kba-it2-control-plane`, `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` und 1 weitere |
| `trivy:KSV-0053` | Exec into Pods | Hoch | 3 | `ClusterRole/-/admin`, `ClusterRole/-/edit`, `ClusterRole/-/system:aggregate-to-edit` |
| `trivy:KSV-0056` | Manage Kubernetes networking | Hoch | 6 | `ClusterRole/-/admin`, `ClusterRole/-/edit`, `ClusterRole/-/system:aggregate-to-edit` und 3 weitere |
| `trivy:KSV-0118` | Default security context configured | Hoch | 5 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` und 2 weitere |
| `trivy:KSV-0119` | NET_RAW capability added | Hoch | 1 | `DaemonSet/kube-system/kindnet` |
| `trivy:KSV-0121` | Kubernetes resource with disallowed volumes mounted | Hoch | 1 | `Pod/audit-demo/insecure` |
| `kubescape:C-0002` | Prevent containers from allowing command execution | Mittel | 2 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters` |
| `kubescape:C-0007` | Roles with delete capabilities | Mittel | 21 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters`, `ServiceAccount/kube-system/cronjob-controller` und 18 weitere |
| `kubescape:C-0013` | Non-root containers | Mittel | 1 | `Pod/audit-demo/hardened` |
| `kubescape:C-0030` | Ingress and Egress blocked | Mittel | 10 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` und 7 weitere |
| `kubescape:C-0031` | Delete Kubernetes events | Mittel | 4 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters`, `ServiceAccount/kube-system/generic-garbage-collector` und 1 weitere |
| `kubescape:C-0034` | Automatic mapping of service account | Mittel | 9 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` und 6 weitere |
| `kubescape:C-0035` | Administrative Roles | Mittel | 2 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters` |
| `kubescape:C-0037` | CoreDNS poisoning | Mittel | 5 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters`, `ServiceAccount/kube-system/generic-garbage-collector` und 2 weitere |
| `kubescape:C-0044` | Container hostPort | Mittel | 4 | `Pod/kube-system/etcd-kba-it2-control-plane`, `Pod/kube-system/kube-apiserver-kba-it2-control-plane`, `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` und 1 weitere |
| `kubescape:C-0053` | Access container service account | Mittel | 52 | `ServiceAccount/kube-system/attachdetach-controller`, `ServiceAccount/kube-system/bootstrap-signer`, `ServiceAccount/kube-system/certificate-controller` und 49 weitere |
| `kubescape:C-0054` | Cluster internal networking | Mittel | 6 | `Namespace/-/audit-demo`, `Namespace/-/default`, `Namespace/-/kube-node-lease` und 3 weitere |
| `kubescape:C-0055` | Linux hardening | Mittel | 5 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` und 2 weitere |
| `kubescape:C-0063` | Portforwarding privileges | Mittel | 2 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters` |
| `kubescape:C-0066` | Secret/etcd encryption enabled | Mittel | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `kubescape:C-0067` | Audit logs enabled | Mittel | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `kubescape:C-0188` | Minimize access to create pods | Mittel | 9 | `Group/-/kubeadm:cluster-admins`, `Group/-/system:masters`, `ServiceAccount/kube-system/daemon-set-controller` und 6 weitere |
| `kubescape:C-0260` | Missing network policy | Mittel | 10 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` und 7 weitere |
| `trivy:KCV-0001` | Ensure that the --anonymous-auth argument is set to false | Mittel | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KSV-0013` | Image tag ":latest" used | Mittel | 1 | `Pod/audit-demo/insecure` |
| `trivy:KSV-0022` | Specific capabilities added | Mittel | 3 | `DaemonSet/kube-system/kindnet`, `Deployment/kube-system/coredns`, `Pod/audit-demo/insecure` |
| `trivy:KSV-0036` | Protecting Pod service account tokens | Mittel | 1 | `Pod/audit-demo/insecure` |
| `trivy:KSV-0037` | User resources should not be placed in kube-system namespace | Mittel | 4 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` und 1 weitere |
| `trivy:KSV-0048` | Manage Kubernetes workloads and pods | Mittel | 18 | `ClusterRole/-/admin`, `ClusterRole/-/edit`, `ClusterRole/-/system:aggregate-to-edit` und 15 weitere |
| `trivy:KSV-0049` | Manage configmaps | Mittel | 6 | `ClusterRole/-/admin`, `ClusterRole/-/edit`, `ClusterRole/-/system:aggregate-to-edit` und 3 weitere |
| `trivy:KSV-01010` | ConfigMap with sensitive content | Mittel | 1 | `ConfigMap/kube-system/extension-apiserver-authentication` |
| `trivy:KSV-0104` | Seccomp policies disabled | Mittel | 5 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` und 2 weitere |
| `trivy:KSV-0111` | User with admin access | Mittel | 2 | `ClusterRoleBinding/-/cluster-admin`, `ClusterRoleBinding/-/kubeadm:cluster-admins` |
| `trivy:KSV-0113` | Manage namespace secrets | Mittel | 2 | `Role/kube-system/system:controller:bootstrap-signer`, `Role/kube-system/system:controller:token-cleaner` |
| `trivy:KSV-0117` | Prevent binding to privileged ports | Mittel | 1 | `Deployment/kube-system/coredns` |
| `trivy:KSV-0125` | Restrict container images to trusted registries | Mittel | 9 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` und 6 weitere |
| `kubescape:C-0068` | PSP enabled | Niedrig | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:DLA-4792-1` | DLA-4792-1 in tzdata 2025b-0+deb12u2 | Niedrig (vom Scanner nicht eingestuft) | 7 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` und 4 weitere |
| `trivy:DSA-6530-1` | DSA-6530-1 in libpcre2-8-0 10.46-1~deb13u2 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:GO-2026-5932` | GO-2026-5932 in golang.org/x/crypto v0.54.0 | Niedrig (vom Scanner nicht eingestuft) | 6 | `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns`, `Pod/kube-system/etcd-kba-it2-control-plane` und 3 weitere |
| `trivy:KCV-0006` | Ensure that the --kubelet-certificate-authority argument is set as appropriate | Niedrig | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0010` | Ensure that the admission control plugin EventRateLimit is set | Niedrig | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0012` | Ensure that the admission control plugin AlwaysPullImages is set | Niedrig | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0018` | Ensure that the --profiling argument is set to false | Niedrig | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0019` | Ensure that the --audit-log-path argument is set | Niedrig | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0020` | Ensure that the --audit-log-maxage argument is set to 30 or as appropriate | Niedrig | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0021` | Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate | Niedrig | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0022` | Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate | Niedrig | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0030` | Ensure that the --encryption-provider-config argument is set as appropriate | Niedrig | 1 | `Pod/kube-system/kube-apiserver-kba-it2-control-plane` |
| `trivy:KCV-0033` | Ensure that the --terminated-pod-gc-threshold argument is set as appropriate | Niedrig | 1 | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` |
| `trivy:KCV-0034` | Ensure that the --profiling argument is set to false | Niedrig | 1 | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` |
| `trivy:KCV-0038` | Ensure that the RotateKubeletServerCertificate argument is set to true | Niedrig | 1 | `Pod/kube-system/kube-controller-manager-kba-it2-control-plane` |
| `trivy:KCV-0040` | Ensure that the --profiling argument is set to false | Niedrig | 1 | `Pod/kube-system/kube-scheduler-kba-it2-control-plane` |
| `trivy:KSV-0003` | Default capabilities: some containers do not drop all | Niedrig | 8 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/local-path-storage/local-path-provisioner` und 5 weitere |
| `trivy:KSV-0004` | Default capabilities: some containers do not drop any | Niedrig | 8 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/local-path-storage/local-path-provisioner` und 5 weitere |
| `trivy:KSV-0011` | CPU not limited | Niedrig | 9 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` und 6 weitere |
| `trivy:KSV-0015` | CPU requests not specified | Niedrig | 3 | `DaemonSet/kube-system/kube-proxy`, `Deployment/local-path-storage/local-path-provisioner`, `Pod/audit-demo/insecure` |
| `trivy:KSV-0016` | Memory requests not specified | Niedrig | 6 | `DaemonSet/kube-system/kube-proxy`, `Deployment/local-path-storage/local-path-provisioner`, `Pod/audit-demo/insecure` und 3 weitere |
| `trivy:KSV-0018` | Memory not limited | Niedrig | 8 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/local-path-storage/local-path-provisioner` und 5 weitere |
| `trivy:KSV-0020` | Runs with UID \<= 10000 | Niedrig | 9 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` und 6 weitere |
| `trivy:KSV-0021` | Runs with GID \<= 10000 | Niedrig | 10 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` und 7 weitere |
| `trivy:KSV-0030` | Runtime/Default Seccomp profile not set | Niedrig | 5 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/kube-system/coredns` und 2 weitere |
| `trivy:KSV-0105` | Containers must not set runAsUser to 0 | Niedrig | 1 | `Pod/audit-demo/insecure` |
| `trivy:KSV-0106` | Container capabilities must only include NET_BIND_SERVICE | Niedrig | 8 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Deployment/local-path-storage/local-path-provisioner` und 5 weitere |
| `trivy:TEMP-0000000-0F03E5` | TEMP-0000000-0F03E5 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-18A2CE` | TEMP-0000000-18A2CE in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-21F713` | TEMP-0000000-21F713 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-4EF776` | TEMP-0000000-4EF776 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-78AC20` | TEMP-0000000-78AC20 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-956D99` | TEMP-0000000-956D99 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-BB5891` | TEMP-0000000-BB5891 in libde265-0 1.0.15-1+deb13u2 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-BBE297` | TEMP-0000000-BBE297 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-D1A721` | TEMP-0000000-D1A721 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-DB3DE2` | TEMP-0000000-DB3DE2 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-E66AA0` | TEMP-0000000-E66AA0 in libde265-0 1.0.15-1+deb13u2 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0000000-F2B97A` | TEMP-0000000-F2B97A in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0290435-0B57B5` | TEMP-0290435-0B57B5 in tar 1.35+dfsg-3.1 | Niedrig | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0517018-A83CE6` | TEMP-0517018-A83CE6 in sysvinit-utils 3.14-4 | Niedrig | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0628843-DBAD28` | TEMP-0628843-DBAD28 in login.defs 1:4.17.4-2 | Niedrig | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-0841856-B18BAF` | TEMP-0841856-B18BAF in bash 5.2.37-2+b10 | Niedrig | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-1147318-639065` | TEMP-1147318-639065 in liblzma5 5.8.1-1+deb13u1 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-1148137-089975` | TEMP-1148137-089975 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-1148137-126A7B` | TEMP-1148137-126A7B in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Niedrig (vom Scanner nicht eingestuft) | 1 | `Pod/audit-demo/insecure` |
| `trivy:TEMP-1149217-B31E38` | TEMP-1149217-B31E38 in libpcre2-8-0 10.42-1 | Niedrig (vom Scanner nicht eingestuft) | 3 | `DaemonSet/kube-system/kindnet`, `DaemonSet/kube-system/kube-proxy`, `Pod/audit-demo/insecure` |

## 3b. Image-Schwachstellen

Anzahl unterschiedlicher Schwachstellen-Kennungen je Image und Schweregrad. Die vollständige Liste steht in findings.json.

| Image | Kritisch | Hoch | Mittel | Niedrig | Workloads |
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

## 4. Fragen für manuelle und organisatorische Anforderungen

**APP.4.4.A1 – Trennung der Anwendungen planen**
- [ ] Gibt es ein dokumentiertes Trennungskonzept für Namespaces, Cluster und Netze? Wer hat es freigegeben?
- [ ] Laufen Anwendungen mit unterschiedlichem Schutzbedarf im selben Cluster? Wenn ja, mit welcher Begründung?

**APP.4.4.A2 – Automatisierung mit CI/CD planen**
- [ ] Welche Pipeline darf in welche Namespaces deployen, und mit welchen Rechten?
- [ ] Wie werden Secrets in der Pipeline gespeichert und rotiert?

**APP.4.4.A4 – Pods voneinander trennen**
- [ ] Welche Pods nutzen Host-Netz, Host-PID oder Host-IPC, und ist das für jeden dieser Pods begründet?
- [ ] Welches Betriebssystem und welche Container-Runtime laufen auf den Nodes, und sind User-Namespaces aktiv?

**APP.4.4.A5 – Cluster sichern**
- [ ] Wie werden etcd und die Persistent Volumes gesichert, wie oft, und wann wurde zuletzt eine Wiederherstellung getestet?
- [ ] Sind Registries und Infrastrukturanwendungen (z. B. CI/CD, Speicher) in der Sicherung enthalten?

**APP.4.4.A6 – Pods über Init-Container initialisieren**
- [ ] Welche Anwendungen führen beim Start Initialisierungen aus, und laufen diese in Init-Containern?

**APP.4.4.A8 – Konfigurationsdateien absichern**
- [ ] Liegen alle Cluster-Konfigurationen versioniert vor (z. B. Git, GitOps), und sind Änderungen nachvollziehbar kommentiert?
- [ ] Wer hat Lese- und Schreibzugriff auf die Konfiguration der Control Plane?

**APP.4.4.A10 – Automatisierungsprozesse absichern**
- [ ] Mit welchen Kubernetes-Rechten laufen die CI/CD-Pipelines, und sind diese je Team oder Anwendung getrennt?

**APP.4.4.A11 – Container per Health Check überwachen**
- [ ] Haben alle Container Readiness- und Liveness-Probes, und prüfen diese die eigentliche Funktion der Anwendung?

**APP.4.4.A12 – Infrastrukturanwendungen absichern**
- [ ] Welche Infrastrukturanwendungen (Registry, CI/CD, Speicher, GitOps) werden selbst betrieben, und wie sind Zugang, Verschlüsselung, Protokollierung und Sicherung geregelt?

**APP.4.4.A13 – Konfiguration automatisiert auditieren**
- [ ] Läuft ein regelmäßiges, automatisches Audit (z. B. CIS-Benchmark), und wer wertet die Ergebnisse aus?
- [ ] Mit welchen Werkzeugen werden Regeln im Cluster durchgesetzt (z. B. Pod Security Admission, Kyverno, Gatekeeper)?

**APP.4.4.A14 – Nodes mit festen Aufgaben**
- [ ] Wie ist sichergestellt, dass nur passende Pods auf Control-Plane-, Bastion- und Speicher-Nodes laufen (Taints, Node-Selektoren)?

**APP.4.4.A15 – Eigene Cluster oder Nodes bei sehr hohem Schutzbedarf**
- [ ] Welche Anwendungen haben sehr hohen Schutzbedarf, und laufen sie auf eigenen Clustern oder exklusiven Nodes?

**APP.4.4.A16 – Operatoren einsetzen**
- [ ] Welche kritischen Anwendungen und Control-Plane-Komponenten werden über Operatoren betrieben?

**APP.4.4.A17 – Nodes attestieren**
- [ ] Wird die Integrität der Nodes vor dem Clusterbeitritt nachgewiesen (z. B. TPM, Measured Boot)?

**APP.4.4.A19 – Kubernetes ausfallsicher betreiben**
- [ ] Über wie viele Standorte oder Brandabschnitte sind Control Plane und Nodes verteilt, und wurde ein Standortausfall geprobt?

**APP.4.4.A20 – Persistente Daten verschlüsselt speichern**
- [ ] Sind die Datenträger von etcd und der Persistent Volumes verschlüsselt (z. B. LUKS, verschlüsselte Cloud-Volumes)?

**APP.4.4.A21 – Pods regelmäßig neu starten**
- [ ] Werden Pods sehr schutzbedürftiger Anwendungen regelmäßig neu gestartet, und wie wird dabei die Verfügbarkeit gesichert?

**SYS.1.6.A1 – Container-Einsatz planen**
- [ ] Gibt es eine dokumentierte Planung mit dem Ziel des Container-Einsatzes? Wer hat sie freigegeben?

**SYS.1.6.A2 – Container-Verwaltung planen**
- [ ] Werden Personen, die Images bauen, bei Rechten und Überprüfungen wie Administrierende behandelt?
- [ ] Werden Container ausschließlich über Kubernetes gestartet und gestoppt, oder auch direkt über die Runtime auf den Nodes?

**SYS.1.6.A3 – Containerisierte Systeme sicher einsetzen**
- [ ] Wurde je Anwendung dokumentiert geprüft, ob die Container-Isolation ihrem Schutzbedarf genügt?
- [ ] Sind die virtuellen und Overlay-Netze in der Netzdokumentation modelliert?

**SYS.1.6.A4 – Bereitstellung von Images planen**
- [ ] Wie gelangen Images vom Build in die Produktion, und wo ist dieser Ablauf dokumentiert?

**SYS.1.6.A7 – Container-Protokolle außerhalb speichern**
- [ ] Schreiben die Anwendungen ihre Protokolle auf stdout/stderr oder in Dateien im Container? Werden die Protokolle zentral gesammelt?

**SYS.1.6.A9 – Container-Tauglichkeit der Anwendung**
- [ ] Wurde für jede containerisierte Anwendung dokumentiert, dass sie ein unerwartetes Beenden verkraftet?

**SYS.1.6.A10 – Regeln für Images und Containerbetrieb festlegen**
- [ ] Gibt es eine gültige Richtlinie für Images und Container-Betrieb, und wie wird ihre Anwendung überprüft?

**SYS.1.6.A11 – Ein Dienst je Container**
- [ ] Gibt es Container, in denen mehrere Dienste laufen (z. B. über einen Prozessmanager wie supervisord)?

**SYS.1.6.A12 – Sichere Images verteilen**
- [ ] Wo ist dokumentiert, welche Image-Quellen vertrauenswürdig sind und warum?
- [ ] Werden Images signiert, und wird die Signatur vor dem Start geprüft (z. B. cosign mit Admission-Kontrolle)?

**SYS.1.6.A13 – Images freigeben**
- [ ] Wie werden Images getestet und freigegeben, bevor sie in Produktion gehen, und wer gibt frei?

**SYS.1.6.A14 – Images aktualisieren**
- [ ] Wie schnell werden Images nach sicherheitsrelevanten Updates neu gebaut und ausgerollt?

**SYS.1.6.A16 – Admin-Zugriffe zwischen Container und Host**
- [ ] Enthalten Anwendungscontainer SSH-Server oder andere Fernwartungszugänge?
- [ ] Wer darf kubectl exec nutzen, und wird das protokolliert?

**SYS.1.6.A18 – Host-Rechte von Container-Accounts**
- [ ] Welche Container brauchen Zugriff auf Host-Ressourcen, und unter welcher UID laufen sie dort?

**SYS.1.6.A19 – Datenspeicher in Container einbinden**
- [ ] Ist jeder hostPath-Mount betrieblich nötig, und ist er wo möglich nur lesend eingebunden?
- [ ] Wie sind die Zugriffsrechte auf Netzspeicher (NFS, CSI-Volumes) gesetzt?

**SYS.1.6.A20 – Konfigurationsdaten absichern**
- [ ] Liegen alle Manifeste und Helm-Werte versioniert vor, und ist jede Änderung einem Ticket oder Review zugeordnet?

**SYS.1.6.A22 – Für forensische Untersuchungen vorsorgen**
- [ ] Gibt es Regeln, wann und wie der Zustand eines Containers für eine Untersuchung gesichert wird?

**SYS.1.6.A24 – Container-Verhalten auf Angriffe überwachen**
- [ ] Ist eine Laufzeitüberwachung im Einsatz (z. B. Falco, Tetragon), und wohin gehen ihre Meldungen?

**SYS.1.6.A25 – Verfügbarkeitsebene für Container-Anwendungen festlegen**
- [ ] Auf welcher Ebene wird die Verfügbarkeit hochverfügbarer Anwendungen hergestellt (Replikate, Nodes, Zonen)?

**SYS.1.6.A26 – Stärkere Isolation von Containern**
- [ ] Wurde für Anwendungen mit erhöhtem Isolationsbedarf geprüft, ob feste Hosts, Hypervisor-Isolation oder eigene Hosts nötig sind?


## 5. Anhang

### 5.1 Nicht geprüft

| Prüfung | Status | Begründung |
|---|---|---|
| `images.registry_not_allowed` | manuell zu prüfen | no registry allowlist configured (use --registry-allowlist) |

### 5.2 Berechtigungen bei der Erhebung

| Ressource | Erlaubt |
|---|---|
| clusterrolebindings | ja |
| clusterroles | ja |
| namespaces | ja |
| networkpolicies | ja |
| nodes | ja |
| pods | ja |
| rolebindings | ja |
| roles | ja |
| secrets | ja |
| serviceaccounts | ja |

### 5.3 Konfigurierte Ausnahmen

- `admin_subject_allowlist`: Group:system:masters, Group:kubeadm:cluster-admins
- `anonymous_binding_allowlist`: ClusterRoleBinding/-/system:public-info-viewer, RoleBinding/kube-public/kubeadm:bootstrap-signer-clusterinfo
- `registry_allowlist`: keine
- `system_namespaces`: kube-system, kube-public, kube-node-lease

### 5.4 Nachweisverzeichnis

| Datei | SHA-256 |
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

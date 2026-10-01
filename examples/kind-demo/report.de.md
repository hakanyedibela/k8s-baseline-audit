# Kubernetes-Sicherheitsaudit – kind-kba-it

> Dieser Bericht ist keine Zertifizierung und keine Rechtsberatung. „Keine Abweichung festgestellt“ bedeutet nur, dass die automatischen Prüfungen nichts gefunden haben.

| | |
|---|---|
| Cluster | kind-kba-it (https://127.0.0.1:52484) |
| Erhebungszeitpunkt | 2026-10-01T01:12:51Z |
| Bundle-Hash (SHA-256, manifest.json) | `73757bab32f23a8c530162097d2e58284b2c756cec6fa02cfeb6f2f1bdbbd8ef` |
| Herkunft | Hashes geprüft |
| Erzeugt durch | collector |
| Regelwerk | BSI IT-Grundschutz-Kompendium 2023, Module APP.4.4, SYS.1.6 |
| Werkzeug | k8s-baseline-audit 0.1.0 |
| Scanner | kubescape: ok (Your current version is: 4.0.15), trivy: ok (Version: 0.74.0) |

## 1. Management-Zusammenfassung

_KI-generiert, vom Auditor zu prüfen_

Die Prüfung des lokalen Demo-Clusters kind-kba-it (Namespace audit-demo) fand 23 kritische und 217 hohe Abweichungen. Es handelt sich um einen absichtlich unsicher aufgesetzten Wegwerf-Cluster. Die wichtigsten Risiken sind: ein privilegierter Pod mit Host-Netzwerk und eingehängtem Host-Dateisystem (54532d8196f6697a, 79748001703b4712, f87e6e6ec5c9e1d0), der zusätzlich als root läuft (186a31abb1fb1ced); eine Bindung an den anonymen Benutzer (236c5489655114b0) und eine Rolle mit Wildcard-Rechten (f64dba7e79577813), die zusammen den Zugriff über die Kubernetes-API kaum noch eingrenzen; sowie ein Passwort im Klartext als Umgebungsvariable (7d0e7266a1e7b40c). Auf dem API-Server fehlen Audit-Logging (21f3c403f597f5e9) und Verschlüsselung ruhender Secrets (fde878c33ea45cd4). Der etcd-Client-Port lauscht nicht nur auf Loopback (be74227701b4b8e4). Die meisten übrigen Treffer stammen von den eingebundenen Scannern kubescape und trivy und betreffen vor allem Standard-Rollen und Basis-Images; sie sind echte Befunde und sind im Bericht nach Schweregrad aufgeführt. Befunde ohne BSI-Zuordnung sind als keine BSI-Zuordnung gekennzeichnet und nicht weniger ernst zu nehmen. Die Systemnamespaces kube-system, kube-public und kube-node-lease sind von den Prüfungen zu Pod Security Admission und NetworkPolicy ausgenommen; diese Prüfungen gelten daher nicht clusterweit. Für 17 Anforderungen ist eine manuelle Prüfung nötig, 19 sind organisatorisch und nicht aus dem Cluster ablesbar. Es wurde keine Registry-Allowlist angegeben, deshalb wurde die Registry-Prüfung nicht ausgeführt. Dieser Bericht ist keine Zertifizierung und keine Rechtsberatung.

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
| ID | `54532d8196f6697a` |
| Prüfung | `workload.privileged` |
| Schweregrad | Kritisch |
| Priorität | 1 – Privilegierter Container im Namespace audit-demo: voller Zugriff auf den Host-Kernel und die Geräte. (_KI-generiert, vom Auditor zu prüfen_) |
| Anforderungen | SYS.1.6.A17 |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[1].spec.containers[0].securityContext.privileged`<br>`scanners/kubescape.json` `$.results[63].controls[15]`<br>`scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[11]` |

**Maßnahme:** securityContext.privileged entfernen oder auf false setzen.

_Die Befehle wurden nicht ausgeführt._

### 2. hostPath-Volume eingebunden

| | |
|---|---|
| ID | `f87e6e6ec5c9e1d0` |
| Prüfung | `workload.host_path` |
| Schweregrad | Hoch |
| Priorität | 2 – Das Host-Wurzelverzeichnis ist unter /host eingehängt; ein Ausbruch auf den Node ist damit trivial. (_KI-generiert, vom Auditor zu prüfen_) |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[1].spec.volumes[0].hostPath`<br>`scanners/kubescape.json` `$.results[63].controls[13]`<br>`scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[16]` |

**Maßnahme:** hostPath durch PersistentVolumes, ConfigMaps oder emptyDir ersetzen.

_Die Befehle wurden nicht ausgeführt._

### 3. Rechte für anonyme oder nicht authentifizierte Zugriffe

| | |
|---|---|
| ID | `236c5489655114b0` |
| Prüfung | `identity.anonymous_binding` |
| Schweregrad | Kritisch |
| Priorität | 3 – Anonyme Zugriffe erhalten Rechte; jeder mit Netzzugang zur API kann sie nutzen, ohne sich anzumelden. (_KI-generiert, vom Auditor zu prüfen_) |
| Anforderungen | APP.4.4.A3 |
| Ressourcen | `ClusterRoleBinding/-/audit-demo-anon` |
| Quellen | built-in |
| Nachweise | `resources/clusterrolebindings.json` `$.items[0].subjects` |

**Maßnahme:** Bindung an system:anonymous bzw. system:unauthenticated entfernen.

_KI-generiert, vom Auditor zu prüfen:_ Bindung entfernen und prüfen, ob ein Dienst bewusst anonyme Zugriffe braucht; falls ja, nur auf den konkreten Endpunkt beschränken.

_Die Befehle wurden nicht ausgeführt._

### 4. Rolle mit Platzhalter-Rechten (*)

| | |
|---|---|
| ID | `f64dba7e79577813` |
| Prüfung | `identity.wildcard_role` |
| Schweregrad | Hoch |
| Priorität | 4 – Wildcard-Rolle: Wer sie erhält, hat faktisch Cluster-Admin-Rechte. (_KI-generiert, vom Auditor zu prüfen_) |
| Anforderungen | APP.4.4.A3 |
| Ressourcen | `ClusterRole/-/audit-demo-wildcard` |
| Quellen | built-in |
| Nachweise | `resources/clusterroles.json` `$.items[1].rules[0]` |

**Maßnahme:** Platzhalter in verbs und resources durch konkrete Werte ersetzen.

_KI-generiert, vom Auditor zu prüfen:_ Vor dem Ersetzen der Wildcard-Rolle prüfen, welche Subjekte sie tatsächlich nutzen, und die benötigten Verben und Ressourcen einzeln auflisten.

_Die Befehle wurden nicht ausgeführt._

### 5. Zugangsdaten als Klartext-Umgebungsvariable

| | |
|---|---|
| ID | `7d0e7266a1e7b40c` |
| Prüfung | `secrets.credential_literal_env` |
| Schweregrad | Hoch |
| Priorität | 5 – Passwort im Klartext im Pod-Manifest, lesbar für jeden mit Leserechten auf Pods. (_KI-generiert, vom Auditor zu prüfen_) |
| Anforderungen | SYS.1.6.A8 |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[1].spec.containers[0].env[0]` |

**Maßnahme:** Wert in ein Secret verschieben und rotieren; der Klartext stand im Pod-Manifest.

_Die Befehle wurden nicht ausgeführt._

### 6. Keine Verschlüsselung von Secrets in etcd konfiguriert

| | |
|---|---|
| ID | `fde878c33ea45cd4` |
| Prüfung | `control_plane.encryption_at_rest` |
| Schweregrad | Hoch |
| Priorität | 6 – Secrets liegen in etcd unverschlüsselt; ein Zugriff auf etcd legt alle Secrets offen. (_KI-generiert, vom Auditor zu prüfen_) |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[6].spec.containers[0].command` |

**Maßnahme:** EncryptionConfiguration anlegen und --encryption-provider-config am API-Server setzen.

_Die Befehle wurden nicht ausgeführt._

### 7. Audit-Logging des API-Servers nicht aktiv

| | |
|---|---|
| ID | `21f3c403f597f5e9` |
| Prüfung | `control_plane.audit_logging` |
| Schweregrad | Hoch |
| Priorität | 7 – Ohne Audit-Logging lassen sich Vorfälle an der API nicht nachvollziehen. (_KI-generiert, vom Auditor zu prüfen_) |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[6].spec.containers[0].command` |

**Maßnahme:** --audit-policy-file und --audit-log-path setzen und Logs zentral sammeln.

_Die Befehle wurden nicht ausgeführt._

### 8. Manage secrets

| | |
|---|---|
| ID | `15cf551a5063d869` |
| Prüfung | `trivy:KSV-0041` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/edit` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[3].Results[0].Misconfigurations[0]`<br>`scanners/trivy.json` `$.Resources[3].Results[0].Misconfigurations[1]` |

**Maßnahme:** Manage secrets are not allowed. Remove resource 'secrets' from cluster role

_Die Befehle wurden nicht ausgeführt._

### 9. Manage secrets

| | |
|---|---|
| ID | `1b56caf6c0d13b37` |
| Prüfung | `trivy:KSV-0041` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:aggregate-to-edit` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[8].Results[0].Misconfigurations[0]`<br>`scanners/trivy.json` `$.Resources[8].Results[0].Misconfigurations[1]` |

**Maßnahme:** Manage secrets are not allowed. Remove resource 'secrets' from cluster role

_Die Befehle wurden nicht ausgeführt._

### 10. Manage secrets

| | |
|---|---|
| ID | `24a4b97d3e826da9` |
| Prüfung | `trivy:KSV-0041` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/admin` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[0].Results[0].Misconfigurations[0]`<br>`scanners/trivy.json` `$.Resources[0].Results[0].Misconfigurations[1]` |

**Maßnahme:** Manage secrets are not allowed. Remove resource 'secrets' from cluster role

_Die Befehle wurden nicht ausgeführt._

### 11. Manage secrets

| | |
|---|---|
| ID | `55b02bf226c363b0` |
| Prüfung | `trivy:KSV-0041` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:node` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[69].Results[0].Misconfigurations[0]` |

**Maßnahme:** Manage secrets are not allowed. Remove resource 'secrets' from cluster role

_Die Befehle wurden nicht ausgeführt._

### 12. Manage secrets

| | |
|---|---|
| ID | `894fa828857bac57` |
| Prüfung | `trivy:KSV-0041` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:legacy-service-account-token-cleaner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[36].Results[0].Misconfigurations[0]` |

**Maßnahme:** Manage secrets are not allowed. Remove resource 'secrets' from cluster role

_Die Befehle wurden nicht ausgeführt._

### 13. Manage secrets

| | |
|---|---|
| ID | `d488b3004677fa33` |
| Prüfung | `trivy:KSV-0041` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:kube-controller-manager` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[64].Results[0].Misconfigurations[0]`<br>`scanners/trivy.json` `$.Resources[64].Results[0].Misconfigurations[1]`<br>`scanners/trivy.json` `$.Resources[64].Results[0].Misconfigurations[2]`<br>`scanners/trivy.json` `$.Resources[64].Results[0].Misconfigurations[3]` |

**Maßnahme:** Manage secrets are not allowed. Remove resource 'secrets' from cluster role

_Die Befehle wurden nicht ausgeführt._

### 14. No wildcard verb and resource roles

| | |
|---|---|
| ID | `43d7c6c8015c627d` |
| Prüfung | `trivy:KSV-0044` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/cluster-admin` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[2].Results[0].Misconfigurations[0]` |

**Maßnahme:** Create a role which does not permit wildcard verb on wildcard resource

_Die Befehle wurden nicht ausgeführt._

### 15. No wildcard verb and resource roles

| | |
|---|---|
| ID | `7fee335ea5f8383c` |
| Prüfung | `trivy:KSV-0044` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/audit-demo-wildcard` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[1].Results[0].Misconfigurations[0]` |

**Maßnahme:** Create a role which does not permit wildcard verb on wildcard resource

_Die Befehle wurden nicht ausgeführt._

### 16. Manage all resources

| | |
|---|---|
| ID | `09f8365ec4f2aa47` |
| Prüfung | `trivy:KSV-0046` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:generic-garbage-collector` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[32].Results[0].Misconfigurations[0]` |

**Maßnahme:** Remove '*' from 'rules.resources'. Provide specific list of resources to be managed by cluster role

_Die Befehle wurden nicht ausgeführt._

### 17. Manage all resources

| | |
|---|---|
| ID | `11e98a9d2d53de4d` |
| Prüfung | `trivy:KSV-0046` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:storage-version-migrator-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[55].Results[0].Misconfigurations[0]` |

**Maßnahme:** Remove '*' from 'rules.resources'. Provide specific list of resources to be managed by cluster role

_Die Befehle wurden nicht ausgeführt._

### 18. Manage all resources

| | |
|---|---|
| ID | `82615932b80b248e` |
| Prüfung | `trivy:KSV-0046` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/cluster-admin` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[2].Results[0].Misconfigurations[1]` |

**Maßnahme:** Remove '*' from 'rules.resources'. Provide specific list of resources to be managed by cluster role

_Die Befehle wurden nicht ausgeführt._

### 19. Manage all resources

| | |
|---|---|
| ID | `90df51c1fd781d6c` |
| Prüfung | `trivy:KSV-0046` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:resourcequota-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[47].Results[0].Misconfigurations[0]` |

**Maßnahme:** Remove '*' from 'rules.resources'. Provide specific list of resources to be managed by cluster role

_Die Befehle wurden nicht ausgeführt._

### 20. Manage all resources

| | |
|---|---|
| ID | `98380ca5799e3151` |
| Prüfung | `trivy:KSV-0046` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/audit-demo-wildcard` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[1].Results[0].Misconfigurations[1]` |

**Maßnahme:** Remove '*' from 'rules.resources'. Provide specific list of resources to be managed by cluster role

_Die Befehle wurden nicht ausgeführt._

### 21. Manage all resources

| | |
|---|---|
| ID | `d2f0fc20c407896c` |
| Prüfung | `trivy:KSV-0046` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:kube-controller-manager` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[64].Results[0].Misconfigurations[4]` |

**Maßnahme:** Remove '*' from 'rules.resources'. Provide specific list of resources to be managed by cluster role

_Die Befehle wurden nicht ausgeführt._

### 22. Manage all resources

| | |
|---|---|
| ID | `e4ccd12d685ee3bd` |
| Prüfung | `trivy:KSV-0046` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:namespace-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[37].Results[0].Misconfigurations[0]` |

**Maßnahme:** Remove '*' from 'rules.resources'. Provide specific list of resources to be managed by cluster role

_Die Befehle wurden nicht ausgeführt._

### 23. Manage all resources

| | |
|---|---|
| ID | `ed33214cd03f32a3` |
| Prüfung | `trivy:KSV-0046` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:horizontal-pod-autoscaler` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[33].Results[0].Misconfigurations[0]`<br>`scanners/trivy.json` `$.Resources[33].Results[0].Misconfigurations[1]` |

**Maßnahme:** Remove '*' from 'rules.resources'. Provide specific list of resources to be managed by cluster role

_Die Befehle wurden nicht ausgeführt._

### 24. Anonymous user access binding

| | |
|---|---|
| ID | `aa79736efa1ef0c1` |
| Prüfung | `trivy:KSV-0122` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `RoleBinding/kube-public/kubeadm:bootstrap-signer-clusterinfo` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[158].Results[0].Misconfigurations[0]` |

**Maßnahme:** Remove anonymous user binding from clusterrolebinding or rolebinding.

_Die Befehle wurden nicht ausgeführt._

### 25. Privilegierter Container

| | |
|---|---|
| ID | `9c6d8606fa09b4e2` |
| Prüfung | `workload.privileged` |
| Schweregrad | Kritisch |
| Priorität | – |
| Anforderungen | SYS.1.6.A17 |
| Ressourcen | `Pod/kube-system/kube-proxy-sxldn` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[8].spec.containers[0].securityContext.privileged`<br>`scanners/kubescape.json` `$.results[135].controls[15]`<br>`scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[9]` |

**Maßnahme:** securityContext.privileged entfernen oder auf false setzen.

_Die Befehle wurden nicht ausgeführt._

### 26. Applications credentials in configuration files

| | |
|---|---|
| ID | `2426c4f016f7f379` |
| Prüfung | `kubescape:C-0012` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[63].controls[0]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0012.

_Die Befehle wurden nicht ausgeführt._

### 27. Applications credentials in configuration files

| | |
|---|---|
| ID | `cda0d05bef0f4017` |
| Prüfung | `kubescape:C-0012` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ConfigMap/kube-public/cluster-info` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[71].controls[0]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0012.

_Die Befehle wurden nicht ausgeführt._

### 28. List Kubernetes secrets

| | |
|---|---|
| ID | `19bbe130251dd233` |
| Prüfung | `kubescape:C-0015` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/generic-garbage-collector` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[18].controls[3]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0015.

_Die Befehle wurden nicht ausgeführt._

### 29. List Kubernetes secrets

| | |
|---|---|
| ID | `35a8ebdb61ea4531` |
| Prüfung | `kubescape:C-0015` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/storage-version-migrator-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[47].controls[3]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0015.

_Die Befehle wurden nicht ausgeführt._

### 30. List Kubernetes secrets

| | |
|---|---|
| ID | `53eefe0078e2250e` |
| Prüfung | `kubescape:C-0015` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/resourcequota-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[39].controls[3]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0015.

_Die Befehle wurden nicht ausgeführt._

### 31. List Kubernetes secrets

| | |
|---|---|
| ID | `5d357356e4ac815d` |
| Prüfung | `kubescape:C-0015` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `User/-/system:kube-controller-manager` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[159].controls[3]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0015.

_Die Befehle wurden nicht ausgeführt._

### 32. List Kubernetes secrets

| | |
|---|---|
| ID | `973d52dfad4aae65` |
| Prüfung | `kubescape:C-0015` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/namespace-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[29].controls[3]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0015.

_Die Befehle wurden nicht ausgeführt._

### 33. List Kubernetes secrets

| | |
|---|---|
| ID | `b337151e4771249e` |
| Prüfung | `kubescape:C-0015` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/bootstrap-signer` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[3].controls[3]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0015.

_Die Befehle wurden nicht ausgeführt._

### 34. List Kubernetes secrets

| | |
|---|---|
| ID | `de16afa73807c307` |
| Prüfung | `kubescape:C-0015` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/system:masters` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[148].controls[3]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0015.

_Die Befehle wurden nicht ausgeführt._

### 35. List Kubernetes secrets

| | |
|---|---|
| ID | `e3e85851b5efa44d` |
| Prüfung | `kubescape:C-0015` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/token-cleaner` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[48].controls[3]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0015.

_Die Befehle wurden nicht ausgeführt._

### 36. List Kubernetes secrets

| | |
|---|---|
| ID | `fdb71465bab30701` |
| Prüfung | `kubescape:C-0015` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/kubeadm:cluster-admins` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[138].controls[3]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0015.

_Die Befehle wurden nicht ausgeführt._

### 37. HostNetwork access

| | |
|---|---|
| ID | `2bfe8d8dd0ee036f` |
| Prüfung | `kubescape:C-0041` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[83].controls[9]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0041.

_Die Befehle wurden nicht ausgeführt._

### 38. HostNetwork access

| | |
|---|---|
| ID | `45a2019a76fb30e9` |
| Prüfung | `kubescape:C-0041` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[134].controls[9]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0041.

_Die Befehle wurden nicht ausgeführt._

### 39. HostNetwork access

| | |
|---|---|
| ID | `84e953d4754bce72` |
| Prüfung | `kubescape:C-0041` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[135].controls[9]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0041.

_Die Befehle wurden nicht ausgeführt._

### 40. HostNetwork access

| | |
|---|---|
| ID | `c3ded32331b0630a` |
| Prüfung | `kubescape:C-0041` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[82].controls[10]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0041.

_Die Befehle wurden nicht ausgeführt._

### 41. HostNetwork access

| | |
|---|---|
| ID | `edfc026b0da1b674` |
| Prüfung | `kubescape:C-0041` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[63].controls[9]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0041.

_Die Befehle wurden nicht ausgeführt._

### 42. HostNetwork access

| | |
|---|---|
| ID | `f5f1961bc4c57a01` |
| Prüfung | `kubescape:C-0041` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[84].controls[9]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0041.

_Die Befehle wurden nicht ausgeführt._

### 43. HostNetwork access

| | |
|---|---|
| ID | `f74d2bc45057f613` |
| Prüfung | `kubescape:C-0041` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[81].controls[9]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0041.

_Die Befehle wurden nicht ausgeführt._

### 44. Writable hostPath mount

| | |
|---|---|
| ID | `9cb2a3523ed9e9e7` |
| Prüfung | `kubescape:C-0045` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[135].controls[11]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0045.

_Die Befehle wurden nicht ausgeführt._

### 45. Writable hostPath mount

| | |
|---|---|
| ID | `b94e79897c3e9e86` |
| Prüfung | `kubescape:C-0045` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[81].controls[11]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0045.

_Die Befehle wurden nicht ausgeführt._

### 46. Writable hostPath mount

| | |
|---|---|
| ID | `c40ad0c0f539fc9f` |
| Prüfung | `kubescape:C-0045` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[63].controls[11]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0045.

_Die Befehle wurden nicht ausgeführt._

### 47. Writable hostPath mount

| | |
|---|---|
| ID | `c89c44d9be980db2` |
| Prüfung | `kubescape:C-0045` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[134].controls[11]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0045.

_Die Befehle wurden nicht ausgeführt._

### 48. Insecure capabilities

| | |
|---|---|
| ID | `2b3e8b342f308793` |
| Prüfung | `kubescape:C-0046` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[134].controls[12]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0046.

_Die Befehle wurden nicht ausgeführt._

### 49. Insecure capabilities

| | |
|---|---|
| ID | `c42a89ef235bd5b8` |
| Prüfung | `kubescape:C-0046` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[63].controls[12]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0046.

_Die Befehle wurden nicht ausgeführt._

### 50. Minimize wildcard use in Roles and ClusterRoles

| | |
|---|---|
| ID | `6bc891d49de22344` |
| Prüfung | `kubescape:C-0187` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/kubeadm:cluster-admins` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[138].controls[8]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0187.

_Die Befehle wurden nicht ausgeführt._

### 51. Minimize wildcard use in Roles and ClusterRoles

| | |
|---|---|
| ID | `9c55b0d0485c02e0` |
| Prüfung | `kubescape:C-0187` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/system:masters` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[148].controls[8]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0187.

_Die Befehle wurden nicht ausgeführt._

### 52. Anonymous access enabled

| | |
|---|---|
| ID | `2bf948789b6af18c` |
| Prüfung | `kubescape:C-0262` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRoleBinding/-/system:public-info-viewer` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[229].controls[0]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0262.

_Die Befehle wurden nicht ausgeführt._

### 53. Anonymous access enabled

| | |
|---|---|
| ID | `42cf7f6bfbaa4669` |
| Prüfung | `kubescape:C-0262` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `RoleBinding/kube-public/kubeadm:bootstrap-signer-clusterinfo` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[232].controls[0]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0262.

_Die Befehle wurden nicht ausgeführt._

### 54. Anonymous access enabled

| | |
|---|---|
| ID | `feef187e8b410ef6` |
| Prüfung | `kubescape:C-0262` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRoleBinding/-/audit-demo-anon` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[167].controls[0]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0262.

_Die Befehle wurden nicht ausgeführt._

### 55. Ensure CPU limits are set

| | |
|---|---|
| ID | `0e010dc80694d215` |
| Prüfung | `kubescape:C-0270` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[135].controls[18]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0270.

_Die Befehle wurden nicht ausgeführt._

### 56. Ensure CPU limits are set

| | |
|---|---|
| ID | `13eb244d38e61ad1` |
| Prüfung | `kubescape:C-0270` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[81].controls[18]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0270.

_Die Befehle wurden nicht ausgeführt._

### 57. Ensure CPU limits are set

| | |
|---|---|
| ID | `1aa91a0fa1d278cf` |
| Prüfung | `kubescape:C-0270` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[136].controls[18]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0270.

_Die Befehle wurden nicht ausgeführt._

### 58. Ensure CPU limits are set

| | |
|---|---|
| ID | `2573ff3c67983879` |
| Prüfung | `kubescape:C-0270` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[137].controls[18]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0270.

_Die Befehle wurden nicht ausgeführt._

### 59. Ensure CPU limits are set

| | |
|---|---|
| ID | `443af2ac80fe5c44` |
| Prüfung | `kubescape:C-0270` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[82].controls[23]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0270.

_Die Befehle wurden nicht ausgeführt._

### 60. Ensure CPU limits are set

| | |
|---|---|
| ID | `8affa3facd04a241` |
| Prüfung | `kubescape:C-0270` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[84].controls[18]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0270.

_Die Befehle wurden nicht ausgeführt._

### 61. Ensure CPU limits are set

| | |
|---|---|
| ID | `934e62e35167a7d6` |
| Prüfung | `kubescape:C-0270` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[83].controls[18]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0270.

_Die Befehle wurden nicht ausgeführt._

### 62. Ensure CPU limits are set

| | |
|---|---|
| ID | `94ac13cf9d71e798` |
| Prüfung | `kubescape:C-0270` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[63].controls[18]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0270.

_Die Befehle wurden nicht ausgeführt._

### 63. Ensure CPU limits are set

| | |
|---|---|
| ID | `f44e0a7fd1f310f0` |
| Prüfung | `kubescape:C-0270` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[134].controls[18]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0270.

_Die Befehle wurden nicht ausgeführt._

### 64. Ensure memory limits are set

| | |
|---|---|
| ID | `02cb33d32c830648` |
| Prüfung | `kubescape:C-0271` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[82].controls[24]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0271.

_Die Befehle wurden nicht ausgeführt._

### 65. Ensure memory limits are set

| | |
|---|---|
| ID | `148578c60f3cce39` |
| Prüfung | `kubescape:C-0271` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[84].controls[19]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0271.

_Die Befehle wurden nicht ausgeführt._

### 66. Ensure memory limits are set

| | |
|---|---|
| ID | `2a369d5f44796d41` |
| Prüfung | `kubescape:C-0271` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[137].controls[19]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0271.

_Die Befehle wurden nicht ausgeführt._

### 67. Ensure memory limits are set

| | |
|---|---|
| ID | `398ae1888036a063` |
| Prüfung | `kubescape:C-0271` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[83].controls[19]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0271.

_Die Befehle wurden nicht ausgeführt._

### 68. Ensure memory limits are set

| | |
|---|---|
| ID | `57c8d543a24e612e` |
| Prüfung | `kubescape:C-0271` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[134].controls[19]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0271.

_Die Befehle wurden nicht ausgeführt._

### 69. Ensure memory limits are set

| | |
|---|---|
| ID | `5ccbd931b593be92` |
| Prüfung | `kubescape:C-0271` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[135].controls[19]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0271.

_Die Befehle wurden nicht ausgeführt._

### 70. Ensure memory limits are set

| | |
|---|---|
| ID | `632ff085694f36b2` |
| Prüfung | `kubescape:C-0271` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[63].controls[19]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0271.

_Die Befehle wurden nicht ausgeführt._

### 71. Ensure memory limits are set

| | |
|---|---|
| ID | `f5d4ccf8600a4115` |
| Prüfung | `kubescape:C-0271` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[81].controls[19]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0271.

_Die Befehle wurden nicht ausgeführt._

### 72. SYS_ADMIN capability added

| | |
|---|---|
| ID | `cc8610bedbd18f8e` |
| Prüfung | `trivy:KSV-0005` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[3]` |

**Maßnahme:** Remove the SYS_ADMIN capability from 'containers\[\].securityContext.capabilities.add'.

_Die Befehle wurden nicht ausgeführt._

### 73. Access to host network

| | |
|---|---|
| ID | `047103a6fd2e6307` |
| Prüfung | `trivy:KSV-0009` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[4]` |

**Maßnahme:** Do not set 'spec.template.spec.hostNetwork' to true.

_Die Befehle wurden nicht ausgeführt._

### 74. Access to host network

| | |
|---|---|
| ID | `7a30f46f4fd5a128` |
| Prüfung | `trivy:KSV-0009` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[4]` |

**Maßnahme:** Do not set 'spec.template.spec.hostNetwork' to true.

_Die Befehle wurden nicht ausgeführt._

### 75. Access to host network

| | |
|---|---|
| ID | `7ee809ceb1c94619` |
| Prüfung | `trivy:KSV-0009` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[3]` |

**Maßnahme:** Do not set 'spec.template.spec.hostNetwork' to true.

_Die Befehle wurden nicht ausgeführt._

### 76. Access to host network

| | |
|---|---|
| ID | `9a01a7ff91dc9c45` |
| Prüfung | `trivy:KSV-0009` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[3]` |

**Maßnahme:** Do not set 'spec.template.spec.hostNetwork' to true.

_Die Befehle wurden nicht ausgeführt._

### 77. Access to host network

| | |
|---|---|
| ID | `c0f565ad4e3e0318` |
| Prüfung | `trivy:KSV-0009` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[3]` |

**Maßnahme:** Do not set 'spec.template.spec.hostNetwork' to true.

_Die Befehle wurden nicht ausgeführt._

### 78. Access to host network

| | |
|---|---|
| ID | `d7728ba451c46b57` |
| Prüfung | `trivy:KSV-0009` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[6]` |

**Maßnahme:** Do not set 'spec.template.spec.hostNetwork' to true.

_Die Befehle wurden nicht ausgeführt._

### 79. Access to host network

| | |
|---|---|
| ID | `fa8453a7c103103a` |
| Prüfung | `trivy:KSV-0009` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[13]` |

**Maßnahme:** Do not set 'spec.template.spec.hostNetwork' to true.

_Die Befehle wurden nicht ausgeführt._

### 80. Access to host ports

| | |
|---|---|
| ID | `1128ffc4d27e94e4` |
| Prüfung | `trivy:KSV-0024` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[13]` |

**Maßnahme:** Do not set spec.containers\[*\].ports\[*\].hostPort and spec.initContainers\[*\].ports\[*\].hostPort.

_Die Befehle wurden nicht ausgeführt._

### 81. Access to host ports

| | |
|---|---|
| ID | `39171e18f1e10d1a` |
| Prüfung | `trivy:KSV-0024` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[11]` |

**Maßnahme:** Do not set spec.containers\[*\].ports\[*\].hostPort and spec.initContainers\[*\].ports\[*\].hostPort.

_Die Befehle wurden nicht ausgeführt._

### 82. Access to host ports

| | |
|---|---|
| ID | `93526c2e6b92d29a` |
| Prüfung | `trivy:KSV-0024` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[22]` |

**Maßnahme:** Do not set spec.containers\[*\].ports\[*\].hostPort and spec.initContainers\[*\].ports\[*\].hostPort.

_Die Befehle wurden nicht ausgeführt._

### 83. Access to host ports

| | |
|---|---|
| ID | `f178924976482d04` |
| Prüfung | `trivy:KSV-0024` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[15]` |

**Maßnahme:** Do not set spec.containers\[*\].ports\[*\].hostPort and spec.initContainers\[*\].ports\[*\].hostPort.

_Die Befehle wurden nicht ausgeführt._

### 84. Exec into Pods

| | |
|---|---|
| ID | `597d54e0af14ba9c` |
| Prüfung | `trivy:KSV-0053` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:aggregate-to-edit` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[8].Results[0].Misconfigurations[8]` |

**Maßnahme:** Remove write permission verbs for resource 'pods/exec'

_Die Befehle wurden nicht ausgeführt._

### 85. Exec into Pods

| | |
|---|---|
| ID | `6a5358ce9cbba395` |
| Prüfung | `trivy:KSV-0053` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/edit` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[3].Results[0].Misconfigurations[8]` |

**Maßnahme:** Remove write permission verbs for resource 'pods/exec'

_Die Befehle wurden nicht ausgeführt._

### 86. Exec into Pods

| | |
|---|---|
| ID | `dec254bd980f16c9` |
| Prüfung | `trivy:KSV-0053` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/admin` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[0].Results[0].Misconfigurations[8]` |

**Maßnahme:** Remove write permission verbs for resource 'pods/exec'

_Die Befehle wurden nicht ausgeführt._

### 87. Manage Kubernetes networking

| | |
|---|---|
| ID | `035c980106fb2f38` |
| Prüfung | `trivy:KSV-0056` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:endpoint-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[27].Results[0].Misconfigurations[0]` |

**Maßnahme:** Networking resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 88. Manage Kubernetes networking

| | |
|---|---|
| ID | `3a5d88c0ef3af204` |
| Prüfung | `trivy:KSV-0056` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:aggregate-to-edit` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[8].Results[0].Misconfigurations[10]`<br>`scanners/trivy.json` `$.Resources[8].Results[0].Misconfigurations[11]`<br>`scanners/trivy.json` `$.Resources[8].Results[0].Misconfigurations[9]` |

**Maßnahme:** Networking resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 89. Manage Kubernetes networking

| | |
|---|---|
| ID | `76f4900f17a173bd` |
| Prüfung | `trivy:KSV-0056` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/admin` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[0].Results[0].Misconfigurations[10]`<br>`scanners/trivy.json` `$.Resources[0].Results[0].Misconfigurations[11]`<br>`scanners/trivy.json` `$.Resources[0].Results[0].Misconfigurations[9]` |

**Maßnahme:** Networking resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 90. Manage Kubernetes networking

| | |
|---|---|
| ID | `a6b37bc877af479e` |
| Prüfung | `trivy:KSV-0056` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:endpointslicemirroring-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[29].Results[0].Misconfigurations[0]` |

**Maßnahme:** Networking resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 91. Manage Kubernetes networking

| | |
|---|---|
| ID | `c9b3a59570158e35` |
| Prüfung | `trivy:KSV-0056` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/edit` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[3].Results[0].Misconfigurations[10]`<br>`scanners/trivy.json` `$.Resources[3].Results[0].Misconfigurations[11]`<br>`scanners/trivy.json` `$.Resources[3].Results[0].Misconfigurations[9]` |

**Maßnahme:** Networking resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 92. Manage Kubernetes networking

| | |
|---|---|
| ID | `d40e3e2d8696c4fe` |
| Prüfung | `trivy:KSV-0056` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:endpointslice-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[28].Results[0].Misconfigurations[0]` |

**Maßnahme:** Networking resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 93. Default security context configured

| | |
|---|---|
| ID | `2c8519a40eac7be0` |
| Prüfung | `trivy:KSV-0118` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[170].Results[0].Misconfigurations[9]` |

**Maßnahme:** To enhance security, it is strongly recommended not to rely on the default security context. Instead, it is advisable to explicitly define the required security parameters (such as runAsNonRoot, capabilities, readOnlyRootFilesystem, etc.) within the security context.

_Die Befehle wurden nicht ausgeführt._

### 94. Default security context configured

| | |
|---|---|
| ID | `5ba58986280910fe` |
| Prüfung | `trivy:KSV-0118` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[22]` |

**Maßnahme:** To enhance security, it is strongly recommended not to rely on the default security context. Instead, it is advisable to explicitly define the required security parameters (such as runAsNonRoot, capabilities, readOnlyRootFilesystem, etc.) within the security context.

_Die Befehle wurden nicht ausgeführt._

### 95. Default security context configured

| | |
|---|---|
| ID | `6bf23a8083e35bea` |
| Prüfung | `trivy:KSV-0118` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[14]`<br>`scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[15]` |

**Maßnahme:** To enhance security, it is strongly recommended not to rely on the default security context. Instead, it is advisable to explicitly define the required security parameters (such as runAsNonRoot, capabilities, readOnlyRootFilesystem, etc.) within the security context.

_Die Befehle wurden nicht ausgeführt._

### 96. Default security context configured

| | |
|---|---|
| ID | `d0d426e073d33c3c` |
| Prüfung | `trivy:KSV-0118` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[18]` |

**Maßnahme:** To enhance security, it is strongly recommended not to rely on the default security context. Instead, it is advisable to explicitly define the required security parameters (such as runAsNonRoot, capabilities, readOnlyRootFilesystem, etc.) within the security context.

_Die Befehle wurden nicht ausgeführt._

### 97. Default security context configured

| | |
|---|---|
| ID | `d2788405b5228333` |
| Prüfung | `trivy:KSV-0118` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[16]` |

**Maßnahme:** To enhance security, it is strongly recommended not to rely on the default security context. Instead, it is advisable to explicitly define the required security parameters (such as runAsNonRoot, capabilities, readOnlyRootFilesystem, etc.) within the security context.

_Die Befehle wurden nicht ausgeführt._

### 98. NET_RAW capability added

| | |
|---|---|
| ID | `ae11b86cd7123cda` |
| Prüfung | `trivy:KSV-0119` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[17]` |

**Maßnahme:** To mitigate potential security risks, it is strongly recommended to remove the NET_RAW capability from 'containers\[\].securityContext.capabilities.add'. It is advisable to follow the practice of dropping all capabilities and only adding the necessary ones.

_Die Befehle wurden nicht ausgeführt._

### 99. Kubernetes resource with disallowed volumes mounted

| | |
|---|---|
| ID | `01adbe0f2cd18769` |
| Prüfung | `trivy:KSV-0121` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[23]` |

**Maßnahme:** Do not Set 'spec.volumes\[*\].hostPath.path' to any of the disallowed volumes.

_Die Befehle wurden nicht ausgeführt._

### 100. Zusätzliche Linux-Capabilities

| | |
|---|---|
| ID | `481f89dcaa6fdf9c` |
| Prüfung | `workload.added_capabilities` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | SYS.1.6.A17 |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[1].spec.containers[0].securityContext.capabilities.add` |

**Maßnahme:** capabilities.add entfernen; nur NET_BIND_SERVICE ist bei Bedarf vertretbar. drop: \[ALL\] setzen.

_Die Befehle wurden nicht ausgeführt._

### 101. Zusätzliche Linux-Capabilities

| | |
|---|---|
| ID | `5e28e06d54524560` |
| Prüfung | `workload.added_capabilities` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | SYS.1.6.A17 |
| Ressourcen | `Pod/kube-system/kindnet-svn9h` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[5].spec.containers[0].securityContext.capabilities.add` |

**Maßnahme:** capabilities.add entfernen; nur NET_BIND_SERVICE ist bei Bedarf vertretbar. drop: \[ALL\] setzen.

_Die Befehle wurden nicht ausgeführt._

### 102. Pod nutzt Host-Namespaces

| | |
|---|---|
| ID | `092758741fa6b6e4` |
| Prüfung | `workload.host_namespaces` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kindnet-svn9h` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[5].spec.hostNetwork` |

**Maßnahme:** hostNetwork, hostPID und hostIPC entfernen, sofern nicht zwingend erforderlich.

_Die Befehle wurden nicht ausgeführt._

### 103. Pod nutzt Host-Namespaces

| | |
|---|---|
| ID | `1a5605e4ae584da0` |
| Prüfung | `workload.host_namespaces` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[9].spec.hostNetwork` |

**Maßnahme:** hostNetwork, hostPID und hostIPC entfernen, sofern nicht zwingend erforderlich.

_Die Befehle wurden nicht ausgeführt._

### 104. Pod nutzt Host-Namespaces

| | |
|---|---|
| ID | `79748001703b4712` |
| Prüfung | `workload.host_namespaces` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[1].spec.hostNetwork` |

**Maßnahme:** hostNetwork, hostPID und hostIPC entfernen, sofern nicht zwingend erforderlich.

_Die Befehle wurden nicht ausgeführt._

### 105. Pod nutzt Host-Namespaces

| | |
|---|---|
| ID | `bc36bd09b1662031` |
| Prüfung | `workload.host_namespaces` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-proxy-sxldn` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[8].spec.hostNetwork` |

**Maßnahme:** hostNetwork, hostPID und hostIPC entfernen, sofern nicht zwingend erforderlich.

_Die Befehle wurden nicht ausgeführt._

### 106. Pod nutzt Host-Namespaces

| | |
|---|---|
| ID | `bc5f68eb45c91b84` |
| Prüfung | `workload.host_namespaces` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[6].spec.hostNetwork` |

**Maßnahme:** hostNetwork, hostPID und hostIPC entfernen, sofern nicht zwingend erforderlich.

_Die Befehle wurden nicht ausgeführt._

### 107. Pod nutzt Host-Namespaces

| | |
|---|---|
| ID | `cf5146a8d85fa683` |
| Prüfung | `workload.host_namespaces` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[4].spec.hostNetwork` |

**Maßnahme:** hostNetwork, hostPID und hostIPC entfernen, sofern nicht zwingend erforderlich.

_Die Befehle wurden nicht ausgeführt._

### 108. Pod nutzt Host-Namespaces

| | |
|---|---|
| ID | `ea1917bc775ee92d` |
| Prüfung | `workload.host_namespaces` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[7].spec.hostNetwork` |

**Maßnahme:** hostNetwork, hostPID und hostIPC entfernen, sofern nicht zwingend erforderlich.

_Die Befehle wurden nicht ausgeführt._

### 109. hostPath-Volume eingebunden

| | |
|---|---|
| ID | `244e6b5d33e7661a` |
| Prüfung | `workload.host_path` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[7].spec.volumes[0].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[1].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[2].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[3].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[4].hostPath`<br>`resources/pods.json` `$.items[7].spec.volumes[5].hostPath`<br>`scanners/kubescape.json` `$.results[83].controls[13]`<br>`scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[14]` |

**Maßnahme:** hostPath durch PersistentVolumes, ConfigMaps oder emptyDir ersetzen.

_Die Befehle wurden nicht ausgeführt._

### 110. hostPath-Volume eingebunden

| | |
|---|---|
| ID | `29b8a96c80dfd188` |
| Prüfung | `workload.host_path` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-proxy-sxldn` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[8].spec.volumes[1].hostPath`<br>`resources/pods.json` `$.items[8].spec.volumes[2].hostPath`<br>`scanners/kubescape.json` `$.results[135].controls[13]`<br>`scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[13]` |

**Maßnahme:** hostPath durch PersistentVolumes, ConfigMaps oder emptyDir ersetzen.

_Die Befehle wurden nicht ausgeführt._

### 111. hostPath-Volume eingebunden

| | |
|---|---|
| ID | `44fd938cf0b7b0af` |
| Prüfung | `workload.host_path` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[6].spec.volumes[0].hostPath`<br>`resources/pods.json` `$.items[6].spec.volumes[1].hostPath`<br>`resources/pods.json` `$.items[6].spec.volumes[2].hostPath`<br>`resources/pods.json` `$.items[6].spec.volumes[3].hostPath`<br>`resources/pods.json` `$.items[6].spec.volumes[4].hostPath`<br>`scanners/kubescape.json` `$.results[82].controls[14]`<br>`scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[21]` |

**Maßnahme:** hostPath durch PersistentVolumes, ConfigMaps oder emptyDir ersetzen.

_Die Befehle wurden nicht ausgeführt._

### 112. hostPath-Volume eingebunden

| | |
|---|---|
| ID | `834c039209d74b8f` |
| Prüfung | `workload.host_path` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[4].spec.volumes[0].hostPath`<br>`resources/pods.json` `$.items[4].spec.volumes[1].hostPath`<br>`scanners/kubescape.json` `$.results[81].controls[13]`<br>`scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[10]` |

**Maßnahme:** hostPath durch PersistentVolumes, ConfigMaps oder emptyDir ersetzen.

_Die Befehle wurden nicht ausgeführt._

### 113. hostPath-Volume eingebunden

| | |
|---|---|
| ID | `8e390538c1ca8355` |
| Prüfung | `workload.host_path` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[9].spec.volumes[0].hostPath`<br>`scanners/kubescape.json` `$.results[84].controls[13]`<br>`scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[12]` |

**Maßnahme:** hostPath durch PersistentVolumes, ConfigMaps oder emptyDir ersetzen.

_Die Befehle wurden nicht ausgeführt._

### 114. hostPath-Volume eingebunden

| | |
|---|---|
| ID | `a27a3a8c5ce6741e` |
| Prüfung | `workload.host_path` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kindnet-svn9h` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[5].spec.volumes[0].hostPath`<br>`resources/pods.json` `$.items[5].spec.volumes[1].hostPath`<br>`resources/pods.json` `$.items[5].spec.volumes[2].hostPath`<br>`resources/pods.json` `$.items[5].spec.volumes[3].hostPath`<br>`scanners/kubescape.json` `$.results[134].controls[13]`<br>`scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[11]` |

**Maßnahme:** hostPath durch PersistentVolumes, ConfigMaps oder emptyDir ersetzen.

_Die Befehle wurden nicht ausgeführt._

### 115. Container läuft als root (UID 0)

| | |
|---|---|
| ID | `186a31abb1fb1ced` |
| Prüfung | `workload.run_as_root` |
| Schweregrad | Hoch |
| Priorität | – |
| Anforderungen | SYS.1.6.A17 |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[1].spec.containers[0].securityContext` |

**Maßnahme:** runAsUser auf eine UID größer 0 setzen und runAsNonRoot: true ergänzen.

_Die Befehle wurden nicht ausgeführt._

### 116. Anonyme Anfragen am API-Server zugelassen

| | |
|---|---|
| ID | `08158022d46e2d24` |
| Prüfung | `control_plane.anonymous_auth` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | APP.4.4.A3 |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[6].spec.containers[0].command` |

**Maßnahme:** --anonymous-auth=false setzen; Health-Probes vorher auf authentifizierte Endpunkte prüfen.

_Die Befehle wurden nicht ausgeführt._

### 117. etcd-Client-Port auf Nicht-Loopback-Adresse erreichbar

| | |
|---|---|
| ID | `be74227701b4b8e4` |
| Prüfung | `control_plane.etcd_listen_non_loopback` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[4].spec.containers[0].command` |

**Maßnahme:** Erreichbarkeit von Port 2379 per Firewall auf Control-Plane-Knoten beschränken oder nur 127.0.0.1 binden.

_Die Befehle wurden nicht ausgeführt._

### 118. ServiceAccount-Token automatisch eingebunden

| | |
|---|---|
| ID | `2e5ef2d43f018ac8` |
| Prüfung | `identity.automount_token` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kindnet-svn9h` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[5].spec.automountServiceAccountToken` |

**Maßnahme:** automountServiceAccountToken: false setzen, wenn der Pod die Kubernetes-API nicht braucht.

_Die Befehle wurden nicht ausgeführt._

### 119. ServiceAccount-Token automatisch eingebunden

| | |
|---|---|
| ID | `6303a0820ebcc804` |
| Prüfung | `identity.automount_token` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/coredns-559f6c778d-bjswk` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[2].spec.automountServiceAccountToken` |

**Maßnahme:** automountServiceAccountToken: false setzen, wenn der Pod die Kubernetes-API nicht braucht.

_Die Befehle wurden nicht ausgeführt._

### 120. ServiceAccount-Token automatisch eingebunden

| | |
|---|---|
| ID | `669550d7fe23d4a3` |
| Prüfung | `identity.automount_token` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-proxy-sxldn` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[8].spec.automountServiceAccountToken` |

**Maßnahme:** automountServiceAccountToken: false setzen, wenn der Pod die Kubernetes-API nicht braucht.

_Die Befehle wurden nicht ausgeführt._

### 121. ServiceAccount-Token automatisch eingebunden

| | |
|---|---|
| ID | `6a9855fb7c74ef5b` |
| Prüfung | `identity.automount_token` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[1].spec.automountServiceAccountToken` |

**Maßnahme:** automountServiceAccountToken: false setzen, wenn der Pod die Kubernetes-API nicht braucht.

_Die Befehle wurden nicht ausgeführt._

### 122. ServiceAccount-Token automatisch eingebunden

| | |
|---|---|
| ID | `7cef2882cadbd4d0` |
| Prüfung | `identity.automount_token` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-q5x9t` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[10].spec.automountServiceAccountToken` |

**Maßnahme:** automountServiceAccountToken: false setzen, wenn der Pod die Kubernetes-API nicht braucht.

_Die Befehle wurden nicht ausgeführt._

### 123. ServiceAccount-Token automatisch eingebunden

| | |
|---|---|
| ID | `a59ef6e289218bcd` |
| Prüfung | `identity.automount_token` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/coredns-559f6c778d-sgjj4` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[3].spec.automountServiceAccountToken` |

**Maßnahme:** automountServiceAccountToken: false setzen, wenn der Pod die Kubernetes-API nicht braucht.

_Die Befehle wurden nicht ausgeführt._

### 124. Pod nutzt das default-ServiceAccount

| | |
|---|---|
| ID | `9265c87df8caa98f` |
| Prüfung | `identity.default_service_account` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | APP.4.4.A9 |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[1].spec.serviceAccountName` |

**Maßnahme:** Eigenes ServiceAccount je Anwendung anlegen und serviceAccountName setzen.

_Die Befehle wurden nicht ausgeführt._

### 125. Image ohne feste Version (latest oder kein Tag)

| | |
|---|---|
| ID | `dfd07dbdffcea6fe` |
| Prüfung | `images.latest_tag` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A6 |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[1].spec.containers[0].image` |

**Maßnahme:** Feste Versionsnummer oder Digest verwenden.

_Die Befehle wurden nicht ausgeführt._

### 126. Namespace mit Pods, aber ohne NetworkPolicy

| | |
|---|---|
| ID | `afebaf40b0c7833c` |
| Prüfung | `isolation.no_network_policy` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | APP.4.4.A7, APP.4.4.A18, SYS.1.6.A5 |
| Ressourcen | `Namespace/-/audit-demo` |
| Quellen | built-in |
| Nachweise | `resources/namespaces.json` `$.items[0]` |

**Maßnahme:** Default-Deny-NetworkPolicy anlegen und benötigte Verbindungen explizit erlauben.

_Die Befehle wurden nicht ausgeführt._

### 127. Namespace mit Pods, aber ohne NetworkPolicy

| | |
|---|---|
| ID | `e9912d622a36eae9` |
| Prüfung | `isolation.no_network_policy` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | APP.4.4.A7, APP.4.4.A18, SYS.1.6.A5 |
| Ressourcen | `Namespace/-/local-path-storage` |
| Quellen | built-in |
| Nachweise | `resources/namespaces.json` `$.items[5]` |

**Maßnahme:** Default-Deny-NetworkPolicy anlegen und benötigte Verbindungen explizit erlauben.

_Die Befehle wurden nicht ausgeführt._

### 128. Namespace ohne Pod-Security-Admission-Label

| | |
|---|---|
| ID | `39495e677f6b9364` |
| Prüfung | `isolation.psa_labels_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Namespace/-/local-path-storage` |
| Quellen | built-in |
| Nachweise | `resources/namespaces.json` `$.items[5].metadata.labels` |

**Maßnahme:** Label pod-security.kubernetes.io/enforce (baseline oder restricted) setzen. Cluster-weite Standardwerte aus einer AdmissionConfiguration sind für dieses Werkzeug nicht sichtbar.

_Die Befehle wurden nicht ausgeführt._

### 129. Namespace ohne Pod-Security-Admission-Label

| | |
|---|---|
| ID | `8169c3b7972227e6` |
| Prüfung | `isolation.psa_labels_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Namespace/-/audit-demo` |
| Quellen | built-in |
| Nachweise | `resources/namespaces.json` `$.items[0].metadata.labels` |

**Maßnahme:** Label pod-security.kubernetes.io/enforce (baseline oder restricted) setzen. Cluster-weite Standardwerte aus einer AdmissionConfiguration sind für dieses Werkzeug nicht sichtbar.

_Die Befehle wurden nicht ausgeführt._

### 130. Namespace ohne Pod-Security-Admission-Label

| | |
|---|---|
| ID | `c5a61be346b51115` |
| Prüfung | `isolation.psa_labels_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Namespace/-/default` |
| Quellen | built-in |
| Nachweise | `resources/namespaces.json` `$.items[1].metadata.labels` |

**Maßnahme:** Label pod-security.kubernetes.io/enforce (baseline oder restricted) setzen. Cluster-weite Standardwerte aus einer AdmissionConfiguration sind für dieses Werkzeug nicht sichtbar.

_Die Befehle wurden nicht ausgeführt._

### 131. Prevent containers from allowing command execution

| | |
|---|---|
| ID | `d8050d08957f9e38` |
| Prüfung | `kubescape:C-0002` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/system:masters` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[148].controls[0]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0002.

_Die Befehle wurden nicht ausgeführt._

### 132. Prevent containers from allowing command execution

| | |
|---|---|
| ID | `ecf45f34686d44e9` |
| Prüfung | `kubescape:C-0002` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/kubeadm:cluster-admins` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[138].controls[0]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0002.

_Die Befehle wurden nicht ausgeführt._

### 133. Roles with delete capabilities

| | |
|---|---|
| ID | `127fdfd854e4c53c` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/ttl-after-finished-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[49].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 134. Roles with delete capabilities

| | |
|---|---|
| ID | `1b3bbd9068b282c0` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/deployment-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[10].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 135. Roles with delete capabilities

| | |
|---|---|
| ID | `1c99c4ec42d0584a` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/cronjob-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[8].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 136. Roles with delete capabilities

| | |
|---|---|
| ID | `1e1d88fa956bec0c` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/persistent-volume-binder` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[31].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 137. Roles with delete capabilities

| | |
|---|---|
| ID | `22f1471e92356b98` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/system:masters` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[148].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 138. Roles with delete capabilities

| | |
|---|---|
| ID | `3ae099d6b1dba83e` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/generic-garbage-collector` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[18].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 139. Roles with delete capabilities

| | |
|---|---|
| ID | `43c6f951c8cfd263` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/daemon-set-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[9].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 140. Roles with delete capabilities

| | |
|---|---|
| ID | `45f30b024c66b229` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/namespace-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[29].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 141. Roles with delete capabilities

| | |
|---|---|
| ID | `59eadff175800d43` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/kubeadm:cluster-admins` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[138].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 142. Roles with delete capabilities

| | |
|---|---|
| ID | `6735bfa2c6ae3470` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/legacy-service-account-token-cleaner` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[28].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 143. Roles with delete capabilities

| | |
|---|---|
| ID | `7ce935d3bf0bbfe7` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/local-path-storage/local-path-provisioner-service-account` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[54].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 144. Roles with delete capabilities

| | |
|---|---|
| ID | `8e78e3981afa6936` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/replicaset-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[36].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 145. Roles with delete capabilities

| | |
|---|---|
| ID | `9ac3a206fb5430db` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/token-cleaner` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[48].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 146. Roles with delete capabilities

| | |
|---|---|
| ID | `a59a9bcda2d596f3` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/device-taint-eviction-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[11].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 147. Roles with delete capabilities

| | |
|---|---|
| ID | `a60d2c7f9cdf912c` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/node-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[30].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 148. Roles with delete capabilities

| | |
|---|---|
| ID | `a85a523df2774b86` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `User/-/system:kube-scheduler` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[163].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 149. Roles with delete capabilities

| | |
|---|---|
| ID | `aab210d9f0628a51` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/job-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[20].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 150. Roles with delete capabilities

| | |
|---|---|
| ID | `c62b031dbdc67c42` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/statefulset-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[46].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 151. Roles with delete capabilities

| | |
|---|---|
| ID | `e6ea845b743324fa` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/pod-garbage-collector` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[32].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 152. Roles with delete capabilities

| | |
|---|---|
| ID | `ec352fa73d0155ef` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `User/-/system:kube-controller-manager` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[159].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 153. Roles with delete capabilities

| | |
|---|---|
| ID | `ff07f2705a668bf3` |
| Prüfung | `kubescape:C-0007` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/replication-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[37].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0007.

_Die Befehle wurden nicht ausgeführt._

### 154. Non-root containers

| | |
|---|---|
| ID | `74040633b75ba0aa` |
| Prüfung | `kubescape:C-0013` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/hardened` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[62].controls[1]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0013.

_Die Befehle wurden nicht ausgeführt._

### 155. Ingress and Egress blocked

| | |
|---|---|
| ID | `34151b8adf8ff785` |
| Prüfung | `kubescape:C-0030` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[137].controls[6]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0030.

_Die Befehle wurden nicht ausgeführt._

### 156. Ingress and Egress blocked

| | |
|---|---|
| ID | `577f134389b1b620` |
| Prüfung | `kubescape:C-0030` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[83].controls[6]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0030.

_Die Befehle wurden nicht ausgeführt._

### 157. Ingress and Egress blocked

| | |
|---|---|
| ID | `5bbc8eed14a98183` |
| Prüfung | `kubescape:C-0030` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/hardened` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[62].controls[6]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0030.

_Die Befehle wurden nicht ausgeführt._

### 158. Ingress and Egress blocked

| | |
|---|---|
| ID | `7948ea8b9dc20709` |
| Prüfung | `kubescape:C-0030` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[136].controls[6]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0030.

_Die Befehle wurden nicht ausgeführt._

### 159. Ingress and Egress blocked

| | |
|---|---|
| ID | `8888196f66eeef4f` |
| Prüfung | `kubescape:C-0030` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[135].controls[6]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0030.

_Die Befehle wurden nicht ausgeführt._

### 160. Ingress and Egress blocked

| | |
|---|---|
| ID | `8fb5b39a33495f75` |
| Prüfung | `kubescape:C-0030` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[84].controls[6]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0030.

_Die Befehle wurden nicht ausgeführt._

### 161. Ingress and Egress blocked

| | |
|---|---|
| ID | `a767ca1c5a0c8b7d` |
| Prüfung | `kubescape:C-0030` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[134].controls[6]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0030.

_Die Befehle wurden nicht ausgeführt._

### 162. Ingress and Egress blocked

| | |
|---|---|
| ID | `aec77ecc0002d82e` |
| Prüfung | `kubescape:C-0030` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[81].controls[6]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0030.

_Die Befehle wurden nicht ausgeführt._

### 163. Ingress and Egress blocked

| | |
|---|---|
| ID | `d61ac652138ce867` |
| Prüfung | `kubescape:C-0030` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[82].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0030.

_Die Befehle wurden nicht ausgeführt._

### 164. Ingress and Egress blocked

| | |
|---|---|
| ID | `db8a9b2d7bad76ad` |
| Prüfung | `kubescape:C-0030` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[63].controls[6]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0030.

_Die Befehle wurden nicht ausgeführt._

### 165. Delete Kubernetes events

| | |
|---|---|
| ID | `6bf2215235200e9f` |
| Prüfung | `kubescape:C-0031` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/generic-garbage-collector` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[18].controls[4]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0031.

_Die Befehle wurden nicht ausgeführt._

### 166. Delete Kubernetes events

| | |
|---|---|
| ID | `7e8a1586586cc116` |
| Prüfung | `kubescape:C-0031` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/namespace-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[29].controls[4]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0031.

_Die Befehle wurden nicht ausgeführt._

### 167. Delete Kubernetes events

| | |
|---|---|
| ID | `9616e6c446b31f97` |
| Prüfung | `kubescape:C-0031` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/system:masters` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[148].controls[4]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0031.

_Die Befehle wurden nicht ausgeführt._

### 168. Delete Kubernetes events

| | |
|---|---|
| ID | `b266c5aa12d33c91` |
| Prüfung | `kubescape:C-0031` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/kubeadm:cluster-admins` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[138].controls[4]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0031.

_Die Befehle wurden nicht ausgeführt._

### 169. Automatic mapping of service account

| | |
|---|---|
| ID | `1c4b672bd30fd6e5` |
| Prüfung | `kubescape:C-0034` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[81].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0034.

_Die Befehle wurden nicht ausgeführt._

### 170. Automatic mapping of service account

| | |
|---|---|
| ID | `1fcb77b20b902ef5` |
| Prüfung | `kubescape:C-0034` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[134].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0034.

_Die Befehle wurden nicht ausgeführt._

### 171. Automatic mapping of service account

| | |
|---|---|
| ID | `6b58b58625195f61` |
| Prüfung | `kubescape:C-0034` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[136].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0034.

_Die Befehle wurden nicht ausgeführt._

### 172. Automatic mapping of service account

| | |
|---|---|
| ID | `7d592ac76de61342` |
| Prüfung | `kubescape:C-0034` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[137].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0034.

_Die Befehle wurden nicht ausgeführt._

### 173. Automatic mapping of service account

| | |
|---|---|
| ID | `8f10a940cd7745e1` |
| Prüfung | `kubescape:C-0034` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[83].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0034.

_Die Befehle wurden nicht ausgeführt._

### 174. Automatic mapping of service account

| | |
|---|---|
| ID | `9927891e914374e8` |
| Prüfung | `kubescape:C-0034` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[84].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0034.

_Die Befehle wurden nicht ausgeführt._

### 175. Automatic mapping of service account

| | |
|---|---|
| ID | `ca0021b509b862d4` |
| Prüfung | `kubescape:C-0034` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[82].controls[8]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0034.

_Die Befehle wurden nicht ausgeführt._

### 176. Automatic mapping of service account

| | |
|---|---|
| ID | `d60375e0677a5ea0` |
| Prüfung | `kubescape:C-0034` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[135].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0034.

_Die Befehle wurden nicht ausgeführt._

### 177. Automatic mapping of service account

| | |
|---|---|
| ID | `da5691c902f6d1f0` |
| Prüfung | `kubescape:C-0034` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[63].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0034.

_Die Befehle wurden nicht ausgeführt._

### 178. Administrative Roles

| | |
|---|---|
| ID | `00c6c1b31230a58b` |
| Prüfung | `kubescape:C-0035` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/system:masters` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[148].controls[5]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0035.

_Die Befehle wurden nicht ausgeführt._

### 179. Administrative Roles

| | |
|---|---|
| ID | `d37f27cb2d4a16f9` |
| Prüfung | `kubescape:C-0035` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/kubeadm:cluster-admins` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[138].controls[5]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0035.

_Die Befehle wurden nicht ausgeführt._

### 180. CoreDNS poisoning

| | |
|---|---|
| ID | `0e51112a3e190ff7` |
| Prüfung | `kubescape:C-0037` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/root-ca-cert-publisher` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[40].controls[6]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0037.

_Die Befehle wurden nicht ausgeführt._

### 181. CoreDNS poisoning

| | |
|---|---|
| ID | `18a7b6d18607838e` |
| Prüfung | `kubescape:C-0037` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/kubeadm:cluster-admins` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[138].controls[6]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0037.

_Die Befehle wurden nicht ausgeführt._

### 182. CoreDNS poisoning

| | |
|---|---|
| ID | `4f6bf77628411311` |
| Prüfung | `kubescape:C-0037` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/storage-version-migrator-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[47].controls[6]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0037.

_Die Befehle wurden nicht ausgeführt._

### 183. CoreDNS poisoning

| | |
|---|---|
| ID | `97e6e5b38ceafd05` |
| Prüfung | `kubescape:C-0037` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/generic-garbage-collector` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[18].controls[6]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0037.

_Die Befehle wurden nicht ausgeführt._

### 184. CoreDNS poisoning

| | |
|---|---|
| ID | `f1d844ca282b1665` |
| Prüfung | `kubescape:C-0037` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/system:masters` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[148].controls[6]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0037.

_Die Befehle wurden nicht ausgeführt._

### 185. Container hostPort

| | |
|---|---|
| ID | `1b1c3db5c3272ab7` |
| Prüfung | `kubescape:C-0044` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[83].controls[10]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0044.

_Die Befehle wurden nicht ausgeführt._

### 186. Container hostPort

| | |
|---|---|
| ID | `3b160c1563d1c34c` |
| Prüfung | `kubescape:C-0044` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[82].controls[11]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0044.

_Die Befehle wurden nicht ausgeführt._

### 187. Container hostPort

| | |
|---|---|
| ID | `5d57edf6267f7a17` |
| Prüfung | `kubescape:C-0044` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[81].controls[10]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0044.

_Die Befehle wurden nicht ausgeführt._

### 188. Container hostPort

| | |
|---|---|
| ID | `867e8d45aa8c7a67` |
| Prüfung | `kubescape:C-0044` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[84].controls[10]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0044.

_Die Befehle wurden nicht ausgeführt._

### 189. Access container service account

| | |
|---|---|
| ID | `00fb9975ab7f09e3` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/kube-dns` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[24].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 190. Access container service account

| | |
|---|---|
| ID | `015b04f9f2ee244d` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/replication-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[37].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 191. Access container service account

| | |
|---|---|
| ID | `03de3e52094ff037` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/endpointslicemirroring-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[15].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 192. Access container service account

| | |
|---|---|
| ID | `055fd38df76945ff` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/kube-scheduler` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[26].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 193. Access container service account

| | |
|---|---|
| ID | `05a8ff02015a66a6` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/job-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[20].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 194. Access container service account

| | |
|---|---|
| ID | `06159e008c28aa2c` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/pv-protection-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[34].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 195. Access container service account

| | |
|---|---|
| ID | `08a8686eb4562a71` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/cloud-provider` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[5].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 196. Access container service account

| | |
|---|---|
| ID | `09c282623c100a51` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/legacy-service-account-token-cleaner` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[28].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 197. Access container service account

| | |
|---|---|
| ID | `0b79034c194b2722` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/token-cleaner` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[48].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 198. Access container service account

| | |
|---|---|
| ID | `171e5c815bf557ba` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/kube-controller-manager` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[23].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 199. Access container service account

| | |
|---|---|
| ID | `17ed1d7c4cfebc5d` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/route-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[41].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 200. Access container service account

| | |
|---|---|
| ID | `181487505f0c2647` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/selinux-warning-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[42].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 201. Access container service account

| | |
|---|---|
| ID | `190ea8d929e55a71` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/endpoint-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[13].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 202. Access container service account

| | |
|---|---|
| ID | `1983c2ba01b08dc1` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/daemon-set-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[9].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 203. Access container service account

| | |
|---|---|
| ID | `1b3705ecc9b4c452` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/statefulset-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[46].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 204. Access container service account

| | |
|---|---|
| ID | `1e3f276b980b5cb9` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/storage-version-migrator-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[47].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 205. Access container service account

| | |
|---|---|
| ID | `212a0e230eca6f97` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/service-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[45].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 206. Access container service account

| | |
|---|---|
| ID | `28a7383e2d2c3073` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/service-cidrs-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[44].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 207. Access container service account

| | |
|---|---|
| ID | `2d37ff945740f0b0` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/kindnet` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[21].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 208. Access container service account

| | |
|---|---|
| ID | `2ea0ffd9935cb99b` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/service-account-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[43].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 209. Access container service account

| | |
|---|---|
| ID | `33f4d87d4abffe2d` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/generic-garbage-collector` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[18].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 210. Access container service account

| | |
|---|---|
| ID | `3476e95c0d85c2dd` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/attachdetach-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[1].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 211. Access container service account

| | |
|---|---|
| ID | `3cc97ba38d95a732` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/validatingadmissionpolicy-status-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[51].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 212. Access container service account

| | |
|---|---|
| ID | `450cafe45e46ec56` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/resourcequota-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[39].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 213. Access container service account

| | |
|---|---|
| ID | `526fd8c79fd9e930` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/local-path-storage/local-path-provisioner-service-account` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[53].controls[7]`<br>`scanners/kubescape.json` `$.results[54].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 214. Access container service account

| | |
|---|---|
| ID | `537b2bf947701e17` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/namespace-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[29].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 215. Access container service account

| | |
|---|---|
| ID | `6841a5b50f240329` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/volumeattributesclass-protection-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[52].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 216. Access container service account

| | |
|---|---|
| ID | `6f83622ecdae6eec` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/persistent-volume-binder` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[31].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 217. Access container service account

| | |
|---|---|
| ID | `7e2ee02d7de21350` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/ephemeral-volume-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[16].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 218. Access container service account

| | |
|---|---|
| ID | `849d0a6802ef0555` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/ttl-after-finished-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[49].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 219. Access container service account

| | |
|---|---|
| ID | `86ce768d8356b45b` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/leader-election-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[27].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 220. Access container service account

| | |
|---|---|
| ID | `9d5169f02d666ecc` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/cronjob-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[8].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 221. Access container service account

| | |
|---|---|
| ID | `9ea69943d5459cac` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/coredns` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[7].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 222. Access container service account

| | |
|---|---|
| ID | `a0389f127997472c` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/replicaset-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[36].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 223. Access container service account

| | |
|---|---|
| ID | `a857d18d59f2d199` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/kube-proxy` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[25].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 224. Access container service account

| | |
|---|---|
| ID | `ac02bbe875500b01` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/ttl-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[50].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 225. Access container service account

| | |
|---|---|
| ID | `b0f4c0c4504025b6` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/disruption-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[12].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 226. Access container service account

| | |
|---|---|
| ID | `bcf2b194a97487e4` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/root-ca-cert-publisher` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[40].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 227. Access container service account

| | |
|---|---|
| ID | `c0b5344445190d1d` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/device-taint-eviction-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[11].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 228. Access container service account

| | |
|---|---|
| ID | `cd07050099329440` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/certificate-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[4].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 229. Access container service account

| | |
|---|---|
| ID | `ce948797bb546a62` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/pvc-protection-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[35].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 230. Access container service account

| | |
|---|---|
| ID | `cfb2333345437dda` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/expand-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[17].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 231. Access container service account

| | |
|---|---|
| ID | `d0e455159a523e8a` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/clusterrole-aggregation-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[6].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 232. Access container service account

| | |
|---|---|
| ID | `d4631fcfa33a5329` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/endpointslice-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[14].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 233. Access container service account

| | |
|---|---|
| ID | `da1c4cae3a8dd69c` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/resource-claim-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[38].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 234. Access container service account

| | |
|---|---|
| ID | `dd8cca070addcb0a` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/deployment-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[10].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 235. Access container service account

| | |
|---|---|
| ID | `e463003a534ec14e` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/node-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[30].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 236. Access container service account

| | |
|---|---|
| ID | `f5e16e3138034c87` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/podcertificaterequestcleaner` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[33].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 237. Access container service account

| | |
|---|---|
| ID | `fa54296645024c6c` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/horizontal-pod-autoscaler` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[19].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 238. Access container service account

| | |
|---|---|
| ID | `faaed70fd863ec25` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/bootstrap-signer` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[2].controls[7]`<br>`scanners/kubescape.json` `$.results[3].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 239. Access container service account

| | |
|---|---|
| ID | `fbc019703b066e33` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/pod-garbage-collector` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[32].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 240. Access container service account

| | |
|---|---|
| ID | `ff2069e8b4999b23` |
| Prüfung | `kubescape:C-0053` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/kube-apiserver-serving-clustertrustbundle-publisher` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[22].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0053.

_Die Befehle wurden nicht ausgeführt._

### 241. Cluster internal networking

| | |
|---|---|
| ID | `0583ee57871928da` |
| Prüfung | `kubescape:C-0054` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Namespace/-/kube-public` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[58].controls[0]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0054.

_Die Befehle wurden nicht ausgeführt._

### 242. Cluster internal networking

| | |
|---|---|
| ID | `09cce8eec15e417a` |
| Prüfung | `kubescape:C-0054` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Namespace/-/default` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[56].controls[0]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0054.

_Die Befehle wurden nicht ausgeführt._

### 243. Cluster internal networking

| | |
|---|---|
| ID | `0d4f51336c097cdf` |
| Prüfung | `kubescape:C-0054` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Namespace/-/kube-node-lease` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[57].controls[0]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0054.

_Die Befehle wurden nicht ausgeführt._

### 244. Cluster internal networking

| | |
|---|---|
| ID | `1ccf928bc39c8ca7` |
| Prüfung | `kubescape:C-0054` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Namespace/-/audit-demo` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[55].controls[0]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0054.

_Die Befehle wurden nicht ausgeführt._

### 245. Cluster internal networking

| | |
|---|---|
| ID | `3c22b0d6cd77cd57` |
| Prüfung | `kubescape:C-0054` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Namespace/-/local-path-storage` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[60].controls[0]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0054.

_Die Befehle wurden nicht ausgeführt._

### 246. Cluster internal networking

| | |
|---|---|
| ID | `7b81477c789a97b4` |
| Prüfung | `kubescape:C-0054` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Namespace/-/kube-system` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[59].controls[0]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0054.

_Die Befehle wurden nicht ausgeführt._

### 247. Linux hardening

| | |
|---|---|
| ID | `3ad21e373a13d681` |
| Prüfung | `kubescape:C-0055` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[134].controls[14]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0055.

_Die Befehle wurden nicht ausgeführt._

### 248. Linux hardening

| | |
|---|---|
| ID | `4001cfb92babf6e9` |
| Prüfung | `kubescape:C-0055` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[135].controls[14]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0055.

_Die Befehle wurden nicht ausgeführt._

### 249. Linux hardening

| | |
|---|---|
| ID | `616916f978a49194` |
| Prüfung | `kubescape:C-0055` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[136].controls[14]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0055.

_Die Befehle wurden nicht ausgeführt._

### 250. Linux hardening

| | |
|---|---|
| ID | `b5735555b8739d03` |
| Prüfung | `kubescape:C-0055` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[137].controls[14]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0055.

_Die Befehle wurden nicht ausgeführt._

### 251. Linux hardening

| | |
|---|---|
| ID | `fb00edbfd379e971` |
| Prüfung | `kubescape:C-0055` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[63].controls[14]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0055.

_Die Befehle wurden nicht ausgeführt._

### 252. Portforwarding privileges

| | |
|---|---|
| ID | `9454eaf81c74346e` |
| Prüfung | `kubescape:C-0063` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/kubeadm:cluster-admins` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[138].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0063.

_Die Befehle wurden nicht ausgeführt._

### 253. Portforwarding privileges

| | |
|---|---|
| ID | `9c3a487dd8f84d67` |
| Prüfung | `kubescape:C-0063` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/system:masters` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[148].controls[7]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0063.

_Die Befehle wurden nicht ausgeführt._

### 254. Secret/etcd encryption enabled

| | |
|---|---|
| ID | `c8bd2e052cda566d` |
| Prüfung | `kubescape:C-0066` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[82].controls[17]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0066.

_Die Befehle wurden nicht ausgeführt._

### 255. Audit logs enabled

| | |
|---|---|
| ID | `c2c95714e78cb900` |
| Prüfung | `kubescape:C-0067` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[82].controls[18]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0067.

_Die Befehle wurden nicht ausgeführt._

### 256. Minimize access to create pods

| | |
|---|---|
| ID | `02e9bf50e30b91d5` |
| Prüfung | `kubescape:C-0188` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/kubeadm:cluster-admins` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[138].controls[9]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0188.

_Die Befehle wurden nicht ausgeführt._

### 257. Minimize access to create pods

| | |
|---|---|
| ID | `21664394d8cacee9` |
| Prüfung | `kubescape:C-0188` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/daemon-set-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[9].controls[10]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0188.

_Die Befehle wurden nicht ausgeführt._

### 258. Minimize access to create pods

| | |
|---|---|
| ID | `500be1e67345db47` |
| Prüfung | `kubescape:C-0188` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/persistent-volume-binder` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[31].controls[10]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0188.

_Die Befehle wurden nicht ausgeführt._

### 259. Minimize access to create pods

| | |
|---|---|
| ID | `5b39dbde49a82895` |
| Prüfung | `kubescape:C-0188` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/replication-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[37].controls[10]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0188.

_Die Befehle wurden nicht ausgeführt._

### 260. Minimize access to create pods

| | |
|---|---|
| ID | `69e1de94c1cebe54` |
| Prüfung | `kubescape:C-0188` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/replicaset-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[36].controls[10]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0188.

_Die Befehle wurden nicht ausgeführt._

### 261. Minimize access to create pods

| | |
|---|---|
| ID | `a8e8643ed5ebbbe1` |
| Prüfung | `kubescape:C-0188` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/statefulset-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[46].controls[10]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0188.

_Die Befehle wurden nicht ausgeführt._

### 262. Minimize access to create pods

| | |
|---|---|
| ID | `cb47a58f1a1752a5` |
| Prüfung | `kubescape:C-0188` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Group/-/system:masters` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[148].controls[9]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0188.

_Die Befehle wurden nicht ausgeführt._

### 263. Minimize access to create pods

| | |
|---|---|
| ID | `d59a0f891881812d` |
| Prüfung | `kubescape:C-0188` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/kube-system/job-controller` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[20].controls[10]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0188.

_Die Befehle wurden nicht ausgeführt._

### 264. Minimize access to create pods

| | |
|---|---|
| ID | `d91e3a129d65a6ad` |
| Prüfung | `kubescape:C-0188` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ServiceAccount/local-path-storage/local-path-provisioner-service-account` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[54].controls[10]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0188.

_Die Befehle wurden nicht ausgeführt._

### 265. Missing network policy

| | |
|---|---|
| ID | `327685ad06230a34` |
| Prüfung | `kubescape:C-0260` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[135].controls[17]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0260.

_Die Befehle wurden nicht ausgeführt._

### 266. Missing network policy

| | |
|---|---|
| ID | `4e49c4924a0096d7` |
| Prüfung | `kubescape:C-0260` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[83].controls[17]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0260.

_Die Befehle wurden nicht ausgeführt._

### 267. Missing network policy

| | |
|---|---|
| ID | `56a0d47266177477` |
| Prüfung | `kubescape:C-0260` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[84].controls[17]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0260.

_Die Befehle wurden nicht ausgeführt._

### 268. Missing network policy

| | |
|---|---|
| ID | `61454f0657b892e8` |
| Prüfung | `kubescape:C-0260` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[81].controls[17]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0260.

_Die Befehle wurden nicht ausgeführt._

### 269. Missing network policy

| | |
|---|---|
| ID | `80f537326371414f` |
| Prüfung | `kubescape:C-0260` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[82].controls[22]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0260.

_Die Befehle wurden nicht ausgeführt._

### 270. Missing network policy

| | |
|---|---|
| ID | `98881dd3d8d8cb39` |
| Prüfung | `kubescape:C-0260` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[63].controls[17]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0260.

_Die Befehle wurden nicht ausgeführt._

### 271. Missing network policy

| | |
|---|---|
| ID | `c2b854ee5b7f027d` |
| Prüfung | `kubescape:C-0260` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[136].controls[17]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0260.

_Die Befehle wurden nicht ausgeführt._

### 272. Missing network policy

| | |
|---|---|
| ID | `d32b7be56ce54d8c` |
| Prüfung | `kubescape:C-0260` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[134].controls[17]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0260.

_Die Befehle wurden nicht ausgeführt._

### 273. Missing network policy

| | |
|---|---|
| ID | `dc9663e21b3725e2` |
| Prüfung | `kubescape:C-0260` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[137].controls[17]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0260.

_Die Befehle wurden nicht ausgeführt._

### 274. Missing network policy

| | |
|---|---|
| ID | `f6eb72f320217312` |
| Prüfung | `kubescape:C-0260` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/hardened` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[62].controls[17]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0260.

_Die Befehle wurden nicht ausgeführt._

### 275. Ensure that the --anonymous-auth argument is set to false

| | |
|---|---|
| ID | `d0f6863fece14e48` |
| Prüfung | `trivy:KCV-0001` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[0]` |

**Maßnahme:** Set '--anonymous-auth' to 'false'.

_Die Befehle wurden nicht ausgeführt._

### 276. Image tag ":latest" used

| | |
|---|---|
| ID | `c32d8b3ab06bd68a` |
| Prüfung | `trivy:KSV-0013` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[7]` |

**Maßnahme:** Use a specific container image tag that is not 'latest'.

_Die Befehle wurden nicht ausgeführt._

### 277. Specific capabilities added

| | |
|---|---|
| ID | `139edc4676117ddb` |
| Prüfung | `trivy:KSV-0022` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[10]` |

**Maßnahme:** Do not set spec.containers\[*\].securityContext.capabilities.add and spec.initContainers\[*\].securityContext.capabilities.add.

_Die Befehle wurden nicht ausgeführt._

### 278. Specific capabilities added

| | |
|---|---|
| ID | `8ba60466617eaba6` |
| Prüfung | `trivy:KSV-0022` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[170].Results[0].Misconfigurations[4]` |

**Maßnahme:** Do not set spec.containers\[*\].securityContext.capabilities.add and spec.initContainers\[*\].securityContext.capabilities.add.

_Die Befehle wurden nicht ausgeführt._

### 279. Specific capabilities added

| | |
|---|---|
| ID | `9f984ebb18fc527d` |
| Prüfung | `trivy:KSV-0022` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[15]` |

**Maßnahme:** Do not set spec.containers\[*\].securityContext.capabilities.add and spec.initContainers\[*\].securityContext.capabilities.add.

_Die Befehle wurden nicht ausgeführt._

### 280. Protecting Pod service account tokens

| | |
|---|---|
| ID | `25808f1fd4530d4d` |
| Prüfung | `trivy:KSV-0036` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[18]` |

**Maßnahme:** Disable the mounting of service account secret token by setting automountServiceAccountToken to false

_Die Befehle wurden nicht ausgeführt._

### 281. User resources should not be placed in kube-system namespace

| | |
|---|---|
| ID | `2662fa45e65e0227` |
| Prüfung | `trivy:KSV-0037` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[170].Results[0].Misconfigurations[6]` |

**Maßnahme:** Deploy the user resources into a designated namespace which is not kube-system.

_Die Befehle wurden nicht ausgeführt._

### 282. User resources should not be placed in kube-system namespace

| | |
|---|---|
| ID | `6a35f42a765ff515` |
| Prüfung | `trivy:KSV-0037` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[15]` |

**Maßnahme:** Deploy the user resources into a designated namespace which is not kube-system.

_Die Befehle wurden nicht ausgeführt._

### 283. User resources should not be placed in kube-system namespace

| | |
|---|---|
| ID | `b04e70b9e526e1a4` |
| Prüfung | `trivy:KSV-0037` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[13]` |

**Maßnahme:** Deploy the user resources into a designated namespace which is not kube-system.

_Die Befehle wurden nicht ausgeführt._

### 284. User resources should not be placed in kube-system namespace

| | |
|---|---|
| ID | `b523fb6b91e6337e` |
| Prüfung | `trivy:KSV-0037` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Service/kube-system/kube-dns` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[193].Results[0].Misconfigurations[0]` |

**Maßnahme:** Deploy the user resources into a designated namespace which is not kube-system.

_Die Befehle wurden nicht ausgeführt._

### 285. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `090363150015bcee` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:deployment-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[24].Results[0].Misconfigurations[0]`<br>`scanners/trivy.json` `$.Resources[24].Results[0].Misconfigurations[1]`<br>`scanners/trivy.json` `$.Resources[24].Results[0].Misconfigurations[2]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 286. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `231cf2af16019d25` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:job-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[34].Results[0].Misconfigurations[0]`<br>`scanners/trivy.json` `$.Resources[34].Results[0].Misconfigurations[1]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 287. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `28e66e8958893878` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:node-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[38].Results[0].Misconfigurations[0]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 288. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `2de74dda99ed48a1` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:persistent-volume-binder` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[39].Results[0].Misconfigurations[0]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 289. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `2fd76941b1475c40` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:ttl-after-finished-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[56].Results[0].Misconfigurations[0]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 290. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `33d065173865c859` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:pod-garbage-collector` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[40].Results[0].Misconfigurations[0]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 291. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `3567d1e2da8e81ce` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:kube-scheduler` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[66].Results[0].Misconfigurations[0]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 292. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `3798d36c0eae0a9f` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Role/local-path-storage/local-path-provisioner-role` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[241].Results[0].Misconfigurations[0]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 293. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `3f5403ecae4e8d39` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:replication-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[45].Results[0].Misconfigurations[0]`<br>`scanners/trivy.json` `$.Resources[45].Results[0].Misconfigurations[1]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 294. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `464bfaba4f3e4ec3` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:cronjob-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[22].Results[0].Misconfigurations[0]`<br>`scanners/trivy.json` `$.Resources[22].Results[0].Misconfigurations[1]`<br>`scanners/trivy.json` `$.Resources[22].Results[0].Misconfigurations[2]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 295. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `50e0a0cafae47cb2` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/admin` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[0].Results[0].Misconfigurations[2]`<br>`scanners/trivy.json` `$.Resources[0].Results[0].Misconfigurations[3]`<br>`scanners/trivy.json` `$.Resources[0].Results[0].Misconfigurations[4]`<br>`scanners/trivy.json` `$.Resources[0].Results[0].Misconfigurations[5]`<br>`scanners/trivy.json` `$.Resources[0].Results[0].Misconfigurations[6]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 296. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `589a4823dff7a2d1` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:replicaset-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[44].Results[0].Misconfigurations[0]`<br>`scanners/trivy.json` `$.Resources[44].Results[0].Misconfigurations[1]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 297. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `690b4422b5176c12` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:statefulset-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[54].Results[0].Misconfigurations[0]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 298. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `b0b051a47cffbf6b` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:daemon-set-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[23].Results[0].Misconfigurations[0]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 299. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `c494767287239e5e` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:aggregate-to-edit` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[8].Results[0].Misconfigurations[2]`<br>`scanners/trivy.json` `$.Resources[8].Results[0].Misconfigurations[3]`<br>`scanners/trivy.json` `$.Resources[8].Results[0].Misconfigurations[4]`<br>`scanners/trivy.json` `$.Resources[8].Results[0].Misconfigurations[5]`<br>`scanners/trivy.json` `$.Resources[8].Results[0].Misconfigurations[6]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 300. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `d285e11a0f824b8c` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/edit` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[3].Results[0].Misconfigurations[2]`<br>`scanners/trivy.json` `$.Resources[3].Results[0].Misconfigurations[3]`<br>`scanners/trivy.json` `$.Resources[3].Results[0].Misconfigurations[4]`<br>`scanners/trivy.json` `$.Resources[3].Results[0].Misconfigurations[5]`<br>`scanners/trivy.json` `$.Resources[3].Results[0].Misconfigurations[6]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 301. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `ea81dcf889d25672` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:node` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[69].Results[0].Misconfigurations[1]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 302. Manage Kubernetes workloads and pods

| | |
|---|---|
| ID | `ed0df0336b2320fa` |
| Prüfung | `trivy:KSV-0048` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:device-taint-eviction-controller` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[25].Results[0].Misconfigurations[0]` |

**Maßnahme:** Kubernetes workloads resources are only allowed for verbs 'list', 'watch', 'get'

_Die Befehle wurden nicht ausgeführt._

### 303. Manage configmaps

| | |
|---|---|
| ID | `0b3d76bd9d3d5560` |
| Prüfung | `trivy:KSV-0049` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Role/kube-public/system:controller:bootstrap-signer` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[157].Results[0].Misconfigurations[0]` |

**Maßnahme:** Remove write permission verbs for resource 'configmaps'

_Die Befehle wurden nicht ausgeführt._

### 304. Manage configmaps

| | |
|---|---|
| ID | `2e78778541f5c5ad` |
| Prüfung | `trivy:KSV-0049` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:aggregate-to-edit` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[8].Results[0].Misconfigurations[7]` |

**Maßnahme:** Remove write permission verbs for resource 'configmaps'

_Die Befehle wurden nicht ausgeführt._

### 305. Manage configmaps

| | |
|---|---|
| ID | `374828d22fe048d9` |
| Prüfung | `trivy:KSV-0049` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/system:controller:root-ca-cert-publisher` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[48].Results[0].Misconfigurations[0]` |

**Maßnahme:** Remove write permission verbs for resource 'configmaps'

_Die Befehle wurden nicht ausgeführt._

### 306. Manage configmaps

| | |
|---|---|
| ID | `39551cf855db67f2` |
| Prüfung | `trivy:KSV-0049` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Role/kube-system/system:controller:cloud-provider` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[182].Results[0].Misconfigurations[0]` |

**Maßnahme:** Remove write permission verbs for resource 'configmaps'

_Die Befehle wurden nicht ausgeführt._

### 307. Manage configmaps

| | |
|---|---|
| ID | `4eb3cbe18fab2694` |
| Prüfung | `trivy:KSV-0049` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/admin` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[0].Results[0].Misconfigurations[7]` |

**Maßnahme:** Remove write permission verbs for resource 'configmaps'

_Die Befehle wurden nicht ausgeführt._

### 308. Manage configmaps

| | |
|---|---|
| ID | `7d8c62ddffeffb09` |
| Prüfung | `trivy:KSV-0049` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRole/-/edit` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[3].Results[0].Misconfigurations[7]` |

**Maßnahme:** Remove write permission verbs for resource 'configmaps'

_Die Befehle wurden nicht ausgeführt._

### 309. ConfigMap with sensitive content

| | |
|---|---|
| ID | `42d1fe3fa90640c8` |
| Prüfung | `trivy:KSV-01010` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ConfigMap/kube-system/extension-apiserver-authentication` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[162].Results[0].Misconfigurations[0]` |

**Maßnahme:** Remove sensitive content from configMap data value

_Die Befehle wurden nicht ausgeführt._

### 310. Seccomp policies disabled

| | |
|---|---|
| ID | `4d8897e8f162e1e7` |
| Prüfung | `trivy:KSV-0104` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[14]` |

**Maßnahme:** Specify seccomp either by annotation or by seccomp profile type having allowed values as per pod security standards

_Die Befehle wurden nicht ausgeführt._

### 311. Seccomp policies disabled

| | |
|---|---|
| ID | `5328b525f1fca90f` |
| Prüfung | `trivy:KSV-0104` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[16]` |

**Maßnahme:** Specify seccomp either by annotation or by seccomp profile type having allowed values as per pod security standards

_Die Befehle wurden nicht ausgeführt._

### 312. Seccomp policies disabled

| | |
|---|---|
| ID | `8d1fb539b7b4245d` |
| Prüfung | `trivy:KSV-0104` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[12]` |

**Maßnahme:** Specify seccomp either by annotation or by seccomp profile type having allowed values as per pod security standards

_Die Befehle wurden nicht ausgeführt._

### 313. Seccomp policies disabled

| | |
|---|---|
| ID | `e714075e4f2688c7` |
| Prüfung | `trivy:KSV-0104` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[170].Results[0].Misconfigurations[7]` |

**Maßnahme:** Specify seccomp either by annotation or by seccomp profile type having allowed values as per pod security standards

_Die Befehle wurden nicht ausgeführt._

### 314. Seccomp policies disabled

| | |
|---|---|
| ID | `f8b3c120dd657267` |
| Prüfung | `trivy:KSV-0104` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[19]` |

**Maßnahme:** Specify seccomp either by annotation or by seccomp profile type having allowed values as per pod security standards

_Die Befehle wurden nicht ausgeführt._

### 315. User with admin access

| | |
|---|---|
| ID | `0b0960a7b15ca85f` |
| Prüfung | `trivy:KSV-0111` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRoleBinding/-/cluster-admin` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[79].Results[0].Misconfigurations[0]` |

**Maßnahme:** Remove binding for clusterrole 'cluster-admin', 'admin' or 'edit'

_Die Befehle wurden nicht ausgeführt._

### 316. User with admin access

| | |
|---|---|
| ID | `922c0283b0267a55` |
| Prüfung | `trivy:KSV-0111` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `ClusterRoleBinding/-/kubeadm:cluster-admins` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[82].Results[0].Misconfigurations[0]` |

**Maßnahme:** Remove binding for clusterrole 'cluster-admin', 'admin' or 'edit'

_Die Befehle wurden nicht ausgeführt._

### 317. Manage namespace secrets

| | |
|---|---|
| ID | `1ff6b62be9d57f45` |
| Prüfung | `trivy:KSV-0113` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Role/kube-system/system:controller:bootstrap-signer` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[181].Results[0].Misconfigurations[0]` |

**Maßnahme:** Manage namespace secrets are not allowed. Remove resource 'secrets' from role

_Die Befehle wurden nicht ausgeführt._

### 318. Manage namespace secrets

| | |
|---|---|
| ID | `92f2916d18e528dc` |
| Prüfung | `trivy:KSV-0113` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Role/kube-system/system:controller:token-cleaner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[183].Results[0].Misconfigurations[0]` |

**Maßnahme:** Manage namespace secrets are not allowed. Remove resource 'secrets' from role

_Die Befehle wurden nicht ausgeführt._

### 319. Prevent binding to privileged ports

| | |
|---|---|
| ID | `6e4da8a7c3e70ad0` |
| Prüfung | `trivy:KSV-0117` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[170].Results[0].Misconfigurations[8]` |

**Maßnahme:** Do not map the container ports to privileged host ports when starting a container.

_Die Befehle wurden nicht ausgeführt._

### 320. Restrict container images to trusted registries

| | |
|---|---|
| ID | `0b870f5e7a98833c` |
| Prüfung | `trivy:KSV-0125` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[170].Results[0].Misconfigurations[10]` |

**Maßnahme:** Use images from trusted registries.

_Die Befehle wurden nicht ausgeführt._

### 321. Restrict container images to trusted registries

| | |
|---|---|
| ID | `5843d6c653d1d0f3` |
| Prüfung | `trivy:KSV-0125` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[24]` |

**Maßnahme:** Use images from trusted registries.

_Die Befehle wurden nicht ausgeführt._

### 322. Restrict container images to trusted registries

| | |
|---|---|
| ID | `941355c4a3b01df9` |
| Prüfung | `trivy:KSV-0125` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[19]` |

**Maßnahme:** Use images from trusted registries.

_Die Befehle wurden nicht ausgeführt._

### 323. Restrict container images to trusted registries

| | |
|---|---|
| ID | `b3f60c594e269f2d` |
| Prüfung | `trivy:KSV-0125` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[16]` |

**Maßnahme:** Use images from trusted registries.

_Die Befehle wurden nicht ausgeführt._

### 324. Restrict container images to trusted registries

| | |
|---|---|
| ID | `b4b0cd4f69255b32` |
| Prüfung | `trivy:KSV-0125` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[17]` |

**Maßnahme:** Use images from trusted registries.

_Die Befehle wurden nicht ausgeführt._

### 325. Restrict container images to trusted registries

| | |
|---|---|
| ID | `b8574ec77da74b17` |
| Prüfung | `trivy:KSV-0125` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/hardened` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[145].Results[0].Misconfigurations[1]` |

**Maßnahme:** Use images from trusted registries.

_Die Befehle wurden nicht ausgeführt._

### 326. Restrict container images to trusted registries

| | |
|---|---|
| ID | `d2bc15fff5fe2866` |
| Prüfung | `trivy:KSV-0125` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[18]` |

**Maßnahme:** Use images from trusted registries.

_Die Befehle wurden nicht ausgeführt._

### 327. Restrict container images to trusted registries

| | |
|---|---|
| ID | `d4b8f3ac30900ad2` |
| Prüfung | `trivy:KSV-0125` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[13]` |

**Maßnahme:** Use images from trusted registries.

_Die Befehle wurden nicht ausgeführt._

### 328. Restrict container images to trusted registries

| | |
|---|---|
| ID | `e65404c97f7249df` |
| Prüfung | `trivy:KSV-0125` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[15]` |

**Maßnahme:** Use images from trusted registries.

_Die Befehle wurden nicht ausgeführt._

### 329. Rechteausweitung nicht unterbunden

| | |
|---|---|
| ID | `3f5fbe7582c8dd64` |
| Prüfung | `workload.privilege_escalation` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A17 |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[7].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[83].controls[3]`<br>`scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[3]` |

**Maßnahme:** allowPrivilegeEscalation: false im securityContext setzen.

_Die Befehle wurden nicht ausgeführt._

### 330. Rechteausweitung nicht unterbunden

| | |
|---|---|
| ID | `7258dab8f73bbcca` |
| Prüfung | `workload.privilege_escalation` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A17 |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[4].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[81].controls[3]`<br>`scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[0]` |

**Maßnahme:** allowPrivilegeEscalation: false im securityContext setzen.

_Die Befehle wurden nicht ausgeführt._

### 331. Rechteausweitung nicht unterbunden

| | |
|---|---|
| ID | `7552b94b0da2e7c4` |
| Prüfung | `workload.privilege_escalation` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A17 |
| Ressourcen | `Pod/kube-system/kube-proxy-sxldn` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[8].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[135].controls[3]`<br>`scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[0]` |

**Maßnahme:** allowPrivilegeEscalation: false im securityContext setzen.

_Die Befehle wurden nicht ausgeführt._

### 332. Rechteausweitung nicht unterbunden

| | |
|---|---|
| ID | `76dda6dfd17a65bb` |
| Prüfung | `workload.privilege_escalation` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A17 |
| Ressourcen | `Pod/kube-system/kindnet-svn9h` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[5].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[134].controls[3]`<br>`scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[0]` |

**Maßnahme:** allowPrivilegeEscalation: false im securityContext setzen.

_Die Befehle wurden nicht ausgeführt._

### 333. Rechteausweitung nicht unterbunden

| | |
|---|---|
| ID | `93df252ccf450c6b` |
| Prüfung | `workload.privilege_escalation` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A17 |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[9].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[84].controls[3]`<br>`scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[1]` |

**Maßnahme:** allowPrivilegeEscalation: false im securityContext setzen.

_Die Befehle wurden nicht ausgeführt._

### 334. Rechteausweitung nicht unterbunden

| | |
|---|---|
| ID | `bc6faa3e6ba08684` |
| Prüfung | `workload.privilege_escalation` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A17 |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[1].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[63].controls[3]`<br>`scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[0]` |

**Maßnahme:** allowPrivilegeEscalation: false im securityContext setzen.

_Die Befehle wurden nicht ausgeführt._

### 335. Rechteausweitung nicht unterbunden

| | |
|---|---|
| ID | `e08f20568b1cf1d4` |
| Prüfung | `workload.privilege_escalation` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A17 |
| Ressourcen | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-q5x9t` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[10].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[137].controls[3]`<br>`scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[0]` |

**Maßnahme:** allowPrivilegeEscalation: false im securityContext setzen.

_Die Befehle wurden nicht ausgeführt._

### 336. Rechteausweitung nicht unterbunden

| | |
|---|---|
| ID | `f56b4eb2e8caef9a` |
| Prüfung | `workload.privilege_escalation` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A17 |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[6].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[82].controls[4]`<br>`scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[10]` |

**Maßnahme:** allowPrivilegeEscalation: false im securityContext setzen.

_Die Befehle wurden nicht ausgeführt._

### 337. Nicht-root-Ausführung nicht erzwungen

| | |
|---|---|
| ID | `125645d6c876ffbd` |
| Prüfung | `workload.run_as_non_root_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[4].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[81].controls[1]`<br>`scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[5]` |

**Maßnahme:** runAsNonRoot: true auf Pod- oder Container-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 338. Nicht-root-Ausführung nicht erzwungen

| | |
|---|---|
| ID | `18eea7f16bbade9a` |
| Prüfung | `workload.run_as_non_root_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-q5x9t` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[10].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[137].controls[1]`<br>`scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[4]` |

**Maßnahme:** runAsNonRoot: true auf Pod- oder Container-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 339. Nicht-root-Ausführung nicht erzwungen

| | |
|---|---|
| ID | `654e5785d49bde9f` |
| Prüfung | `workload.run_as_non_root_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[6].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[82].controls[2]`<br>`scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[15]` |

**Maßnahme:** runAsNonRoot: true auf Pod- oder Container-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 340. Nicht-root-Ausführung nicht erzwungen

| | |
|---|---|
| ID | `8b2377c4a453f4a4` |
| Prüfung | `workload.run_as_non_root_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-proxy-sxldn` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[8].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[135].controls[1]`<br>`scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[5]` |

**Maßnahme:** runAsNonRoot: true auf Pod- oder Container-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 341. Nicht-root-Ausführung nicht erzwungen

| | |
|---|---|
| ID | `92513f9605b60b6e` |
| Prüfung | `workload.run_as_non_root_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kindnet-svn9h` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[5].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[134].controls[1]`<br>`scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[5]` |

**Maßnahme:** runAsNonRoot: true auf Pod- oder Container-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 342. Nicht-root-Ausführung nicht erzwungen

| | |
|---|---|
| ID | `9d989636984965c6` |
| Prüfung | `workload.run_as_non_root_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[9].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[84].controls[1]`<br>`scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[6]` |

**Maßnahme:** runAsNonRoot: true auf Pod- oder Container-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 343. Nicht-root-Ausführung nicht erzwungen

| | |
|---|---|
| ID | `a5f8dbfd237d76c9` |
| Prüfung | `workload.run_as_non_root_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[1].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[63].controls[1]`<br>`scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[6]` |

**Maßnahme:** runAsNonRoot: true auf Pod- oder Container-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 344. Nicht-root-Ausführung nicht erzwungen

| | |
|---|---|
| ID | `b139c4e5994d75b7` |
| Prüfung | `workload.run_as_non_root_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/coredns-559f6c778d-sgjj4` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[3].spec.containers[0].securityContext` |

**Maßnahme:** runAsNonRoot: true auf Pod- oder Container-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 345. Nicht-root-Ausführung nicht erzwungen

| | |
|---|---|
| ID | `b99efb40f1863de0` |
| Prüfung | `workload.run_as_non_root_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[7].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[83].controls[1]`<br>`scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[8]` |

**Maßnahme:** runAsNonRoot: true auf Pod- oder Container-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 346. Nicht-root-Ausführung nicht erzwungen

| | |
|---|---|
| ID | `eedf301337f874d9` |
| Prüfung | `workload.run_as_non_root_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/coredns-559f6c778d-bjswk` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[2].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[136].controls[1]`<br>`scanners/trivy.json` `$.Resources[170].Results[0].Misconfigurations[1]` |

**Maßnahme:** runAsNonRoot: true auf Pod- oder Container-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 347. Kein Seccomp-Profil

| | |
|---|---|
| ID | `10dc8a5d1832c391` |
| Prüfung | `workload.seccomp_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A21 |
| Ressourcen | `Pod/kube-system/coredns-559f6c778d-bjswk` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[2].spec.containers[0].securityContext` |

**Maßnahme:** seccompProfile.type: RuntimeDefault auf Pod-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 348. Kein Seccomp-Profil

| | |
|---|---|
| ID | `14deb71092fbac01` |
| Prüfung | `workload.seccomp_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A21 |
| Ressourcen | `Pod/kube-system/kindnet-svn9h` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[5].spec.containers[0].securityContext` |

**Maßnahme:** seccompProfile.type: RuntimeDefault auf Pod-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 349. Kein Seccomp-Profil

| | |
|---|---|
| ID | `30285c911b43f2d8` |
| Prüfung | `workload.seccomp_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A21 |
| Ressourcen | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-q5x9t` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[10].spec.containers[0].securityContext` |

**Maßnahme:** seccompProfile.type: RuntimeDefault auf Pod-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 350. Kein Seccomp-Profil

| | |
|---|---|
| ID | `83073c07780ebdb3` |
| Prüfung | `workload.seccomp_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A21 |
| Ressourcen | `Pod/kube-system/coredns-559f6c778d-sgjj4` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[3].spec.containers[0].securityContext` |

**Maßnahme:** seccompProfile.type: RuntimeDefault auf Pod-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 351. Kein Seccomp-Profil

| | |
|---|---|
| ID | `a5968a2517aa01be` |
| Prüfung | `workload.seccomp_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A21 |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[1].spec.containers[0].securityContext` |

**Maßnahme:** seccompProfile.type: RuntimeDefault auf Pod-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 352. Kein Seccomp-Profil

| | |
|---|---|
| ID | `bf0fbab7075bc274` |
| Prüfung | `workload.seccomp_missing` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A21 |
| Ressourcen | `Pod/kube-system/kube-proxy-sxldn` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[8].spec.containers[0].securityContext` |

**Maßnahme:** seccompProfile.type: RuntimeDefault auf Pod-Ebene setzen.

_Die Befehle wurden nicht ausgeführt._

### 353. Beschreibbares Root-Dateisystem

| | |
|---|---|
| ID | `08453b128c09cd08` |
| Prüfung | `workload.writable_root_fs` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A23 |
| Ressourcen | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-q5x9t` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[10].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[137].controls[4]`<br>`scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[5]` |

**Maßnahme:** readOnlyRootFilesystem: true setzen; Schreibpfade als emptyDir einbinden.

_Die Befehle wurden nicht ausgeführt._

### 354. Beschreibbares Root-Dateisystem

| | |
|---|---|
| ID | `22a120749b61b962` |
| Prüfung | `workload.writable_root_fs` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A23 |
| Ressourcen | `Pod/kube-system/kindnet-svn9h` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[5].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[134].controls[4]`<br>`scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[6]` |

**Maßnahme:** readOnlyRootFilesystem: true setzen; Schreibpfade als emptyDir einbinden.

_Die Befehle wurden nicht ausgeführt._

### 355. Beschreibbares Root-Dateisystem

| | |
|---|---|
| ID | `23010f483dedad16` |
| Prüfung | `workload.writable_root_fs` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A23 |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[6].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[82].controls[5]`<br>`scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[16]` |

**Maßnahme:** readOnlyRootFilesystem: true setzen; Schreibpfade als emptyDir einbinden.

_Die Befehle wurden nicht ausgeführt._

### 356. Beschreibbares Root-Dateisystem

| | |
|---|---|
| ID | `404dd121bfa00c06` |
| Prüfung | `workload.writable_root_fs` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A23 |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[1].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[63].controls[4]`<br>`scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[8]` |

**Maßnahme:** readOnlyRootFilesystem: true setzen; Schreibpfade als emptyDir einbinden.

_Die Befehle wurden nicht ausgeführt._

### 357. Beschreibbares Root-Dateisystem

| | |
|---|---|
| ID | `74aef947042a65d1` |
| Prüfung | `workload.writable_root_fs` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A23 |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[9].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[84].controls[4]`<br>`scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[7]` |

**Maßnahme:** readOnlyRootFilesystem: true setzen; Schreibpfade als emptyDir einbinden.

_Die Befehle wurden nicht ausgeführt._

### 358. Beschreibbares Root-Dateisystem

| | |
|---|---|
| ID | `cce2d1d2b2f9994f` |
| Prüfung | `workload.writable_root_fs` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A23 |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[7].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[83].controls[4]`<br>`scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[9]` |

**Maßnahme:** readOnlyRootFilesystem: true setzen; Schreibpfade als emptyDir einbinden.

_Die Befehle wurden nicht ausgeführt._

### 359. Beschreibbares Root-Dateisystem

| | |
|---|---|
| ID | `d0ffb7c327acb870` |
| Prüfung | `workload.writable_root_fs` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A23 |
| Ressourcen | `Pod/kube-system/kube-proxy-sxldn` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[8].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[135].controls[4]`<br>`scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[6]` |

**Maßnahme:** readOnlyRootFilesystem: true setzen; Schreibpfade als emptyDir einbinden.

_Die Befehle wurden nicht ausgeführt._

### 360. Beschreibbares Root-Dateisystem

| | |
|---|---|
| ID | `e5b615caae9a235a` |
| Prüfung | `workload.writable_root_fs` |
| Schweregrad | Mittel |
| Priorität | – |
| Anforderungen | SYS.1.6.A23 |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | built-in, kubescape, trivy |
| Nachweise | `resources/pods.json` `$.items[4].spec.containers[0].securityContext`<br>`scanners/kubescape.json` `$.results[81].controls[4]`<br>`scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[6]` |

**Maßnahme:** readOnlyRootFilesystem: true setzen; Schreibpfade als emptyDir einbinden.

_Die Befehle wurden nicht ausgeführt._

### 361. Image nicht per Digest fixiert

| | |
|---|---|
| ID | `079f6d30178e2533` |
| Prüfung | `images.no_digest` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-q5x9t` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[10].spec.containers[0].image` |

**Maßnahme:** Image per @sha256-Digest referenzieren, damit der Inhalt unveränderlich ist.

_Die Befehle wurden nicht ausgeführt._

### 362. Image nicht per Digest fixiert

| | |
|---|---|
| ID | `1270f494dc5b1490` |
| Prüfung | `images.no_digest` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[1].spec.containers[0].image` |

**Maßnahme:** Image per @sha256-Digest referenzieren, damit der Inhalt unveränderlich ist.

_Die Befehle wurden nicht ausgeführt._

### 363. Image nicht per Digest fixiert

| | |
|---|---|
| ID | `2f8894549b633762` |
| Prüfung | `images.no_digest` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kindnet-svn9h` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[5].spec.containers[0].image` |

**Maßnahme:** Image per @sha256-Digest referenzieren, damit der Inhalt unveränderlich ist.

_Die Befehle wurden nicht ausgeführt._

### 364. Image nicht per Digest fixiert

| | |
|---|---|
| ID | `3569fbda4ab8b135` |
| Prüfung | `images.no_digest` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[6].spec.containers[0].image` |

**Maßnahme:** Image per @sha256-Digest referenzieren, damit der Inhalt unveränderlich ist.

_Die Befehle wurden nicht ausgeführt._

### 365. Image nicht per Digest fixiert

| | |
|---|---|
| ID | `453609e345d955c6` |
| Prüfung | `images.no_digest` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/coredns-559f6c778d-bjswk` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[2].spec.containers[0].image` |

**Maßnahme:** Image per @sha256-Digest referenzieren, damit der Inhalt unveränderlich ist.

_Die Befehle wurden nicht ausgeführt._

### 366. Image nicht per Digest fixiert

| | |
|---|---|
| ID | `8465914ab9afe25e` |
| Prüfung | `images.no_digest` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[7].spec.containers[0].image` |

**Maßnahme:** Image per @sha256-Digest referenzieren, damit der Inhalt unveränderlich ist.

_Die Befehle wurden nicht ausgeführt._

### 367. Image nicht per Digest fixiert

| | |
|---|---|
| ID | `85e9b97fd99a1b98` |
| Prüfung | `images.no_digest` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-proxy-sxldn` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[8].spec.containers[0].image` |

**Maßnahme:** Image per @sha256-Digest referenzieren, damit der Inhalt unveränderlich ist.

_Die Befehle wurden nicht ausgeführt._

### 368. Image nicht per Digest fixiert

| | |
|---|---|
| ID | `9beec5fa47c06188` |
| Prüfung | `images.no_digest` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/coredns-559f6c778d-sgjj4` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[3].spec.containers[0].image` |

**Maßnahme:** Image per @sha256-Digest referenzieren, damit der Inhalt unveränderlich ist.

_Die Befehle wurden nicht ausgeführt._

### 369. Image nicht per Digest fixiert

| | |
|---|---|
| ID | `a705c887f4d6ca74` |
| Prüfung | `images.no_digest` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[9].spec.containers[0].image` |

**Maßnahme:** Image per @sha256-Digest referenzieren, damit der Inhalt unveränderlich ist.

_Die Befehle wurden nicht ausgeführt._

### 370. Image nicht per Digest fixiert

| | |
|---|---|
| ID | `d38fb368245944aa` |
| Prüfung | `images.no_digest` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[4].spec.containers[0].image` |

**Maßnahme:** Image per @sha256-Digest referenzieren, damit der Inhalt unveränderlich ist.

_Die Befehle wurden nicht ausgeführt._

### 371. Image nicht per Digest fixiert

| | |
|---|---|
| ID | `f0542ad4f2143393` |
| Prüfung | `images.no_digest` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/hardened` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[0].spec.containers[0].image` |

**Maßnahme:** Image per @sha256-Digest referenzieren, damit der Inhalt unveränderlich ist.

_Die Befehle wurden nicht ausgeführt._

### 372. PSP enabled

| | |
|---|---|
| ID | `1f8ae484e6e5f6e7` |
| Prüfung | `kubescape:C-0068` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | kubescape |
| Nachweise | `scanners/kubescape.json` `$.results[82].controls[19]` |

**Maßnahme:** Siehe kubescape-Dokumentation zu C-0068.

_Die Befehle wurden nicht ausgeführt._

### 373. Secret als Umgebungsvariable eingebunden

| | |
|---|---|
| ID | `01a3eb0cc5b80452` |
| Prüfung | `secrets.env_secret_ref` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[1].spec.containers[0].env` |

**Maßnahme:** Secret als Datei-Volume einbinden; Umgebungsvariablen landen leicht in Logs und Dumps.

_Die Befehle wurden nicht ausgeführt._

### 374. DLA-4792-1 in tzdata 2026b-0+deb12u1

| | |
|---|---|
| ID | `092f2d404ac58c0c` |
| Prüfung | `trivy:DLA-4792-1` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[245].Results[0].Vulnerabilities[0]` |

**Maßnahme:** Paket auf Version 2026c-0+deb12u1 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 375. DLA-4792-1 in tzdata 2026b-0+deb12u1

| | |
|---|---|
| ID | `0d72f46aad889bae` |
| Prüfung | `trivy:DLA-4792-1` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[249].Results[0].Vulnerabilities[0]` |

**Maßnahme:** Paket auf Version 2026c-0+deb12u1 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 376. DLA-4792-1 in tzdata 2026b-0+deb12u1

| | |
|---|---|
| ID | `1eb4822e92ca9109` |
| Prüfung | `trivy:DLA-4792-1` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[254].Results[0].Vulnerabilities[52]` |

**Maßnahme:** Paket auf Version 2026c-0+deb12u1 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 377. DLA-4792-1 in tzdata 2026b-0+deb12u1

| | |
|---|---|
| ID | `649260d0539a3915` |
| Prüfung | `trivy:DLA-4792-1` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[252].Results[0].Vulnerabilities[0]` |

**Maßnahme:** Paket auf Version 2026c-0+deb12u1 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 378. DLA-4792-1 in tzdata 2026b-0+deb12u1

| | |
|---|---|
| ID | `69fb280fe2b39c84` |
| Prüfung | `trivy:DLA-4792-1` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[250].Results[0].Vulnerabilities[0]` |

**Maßnahme:** Paket auf Version 2026c-0+deb12u1 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 379. DLA-4792-1 in tzdata 2026b-0+deb12u1

| | |
|---|---|
| ID | `72c5c0093913ac9d` |
| Prüfung | `trivy:DLA-4792-1` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[251].Results[0].Vulnerabilities[0]` |

**Maßnahme:** Paket auf Version 2026c-0+deb12u1 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 380. DLA-4792-1 in tzdata 2025b-0+deb12u2

| | |
|---|---|
| ID | `c98ec132da18ccf8` |
| Prüfung | `trivy:DLA-4792-1` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[253].Results[0].Vulnerabilities[81]` |

**Maßnahme:** Paket auf Version 2026c-0+deb12u1 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 381. DSA-6530-1 in libpcre2-8-0 10.46-1~deb13u2

| | |
|---|---|
| ID | `a417b8dce21193a1` |
| Prüfung | `trivy:DSA-6530-1` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[235]` |

**Maßnahme:** Paket auf Version 10.46-1~deb13u3 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 382. GO-2026-5932 in golang.org/x/crypto v0.54.0

| | |
|---|---|
| ID | `17c15cbb73dd7379` |
| Prüfung | `trivy:GO-2026-5932` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[251].Results[2].Vulnerabilities[6]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 383. GO-2026-5932 in golang.org/x/crypto v0.54.0

| | |
|---|---|
| ID | `697cfe7ec5ac2bc0` |
| Prüfung | `trivy:GO-2026-5932` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[252].Results[3].Vulnerabilities[6]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 384. GO-2026-5932 in golang.org/x/crypto v0.53.0

| | |
|---|---|
| ID | `71fcd43f59f7c73e` |
| Prüfung | `trivy:GO-2026-5932` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[245].Results[1].Vulnerabilities[20]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 385. GO-2026-5932 in golang.org/x/crypto v0.52.0

| | |
|---|---|
| ID | `839c6138536b5fd1` |
| Prüfung | `trivy:GO-2026-5932` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[249].Results[1].Vulnerabilities[6]`<br>`scanners/trivy.json` `$.Resources[249].Results[3].Vulnerabilities[3]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 386. GO-2026-5932 in golang.org/x/crypto v0.54.0

| | |
|---|---|
| ID | `f4e646863b7408d1` |
| Prüfung | `trivy:GO-2026-5932` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[250].Results[2].Vulnerabilities[6]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 387. GO-2026-5932 in golang.org/x/crypto v0.54.0

| | |
|---|---|
| ID | `f7bd3a43547d5177` |
| Prüfung | `trivy:GO-2026-5932` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[254].Results[3].Vulnerabilities[6]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 388. Ensure that the --kubelet-certificate-authority argument is set as appropriate

| | |
|---|---|
| ID | `aa9f2711205c71da` |
| Prüfung | `trivy:KCV-0006` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[1]` |

**Maßnahme:** Follow the Kubernetes documentation and setup the TLS connection between the apiserver and kubelets. 

_Die Befehle wurden nicht ausgeführt._

### 389. Ensure that the admission control plugin EventRateLimit is set

| | |
|---|---|
| ID | `21eca98fb4ff9dcc` |
| Prüfung | `trivy:KCV-0010` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[2]` |

**Maßnahme:** Follow the Kubernetes documentation and set the desired limits in a configuration file. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml and set the below parameters.

_Die Befehle wurden nicht ausgeführt._

### 390. Ensure that the admission control plugin AlwaysPullImages is set

| | |
|---|---|
| ID | `55607a4d4d4a68ca` |
| Prüfung | `trivy:KCV-0012` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[3]` |

**Maßnahme:** Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --enable-admission-plugins parameter to include AlwaysPullImages.

_Die Befehle wurden nicht ausgeführt._

### 391. Ensure that the --profiling argument is set to false

| | |
|---|---|
| ID | `0a9992622d10f79d` |
| Prüfung | `trivy:KCV-0018` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[4]` |

**Maßnahme:** Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the below parameter.

_Die Befehle wurden nicht ausgeführt._

### 392. Ensure that the --audit-log-path argument is set

| | |
|---|---|
| ID | `0699c8119a8a2d27` |
| Prüfung | `trivy:KCV-0019` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[5]` |

**Maßnahme:** Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-path parameter.

_Die Befehle wurden nicht ausgeführt._

### 393. Ensure that the --audit-log-maxage argument is set to 30 or as appropriate

| | |
|---|---|
| ID | `18eeba2edd48646d` |
| Prüfung | `trivy:KCV-0020` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[6]` |

**Maßnahme:** Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-maxage parameter to 30 or as an appropriate number of days.

_Die Befehle wurden nicht ausgeführt._

### 394. Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate

| | |
|---|---|
| ID | `fdc39e4685675dd4` |
| Prüfung | `trivy:KCV-0021` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[7]` |

**Maßnahme:** Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-maxbackup parameter to 10 or to an appropriate value.

_Die Befehle wurden nicht ausgeführt._

### 395. Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate

| | |
|---|---|
| ID | `8e7357afc40781cb` |
| Prüfung | `trivy:KCV-0022` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[8]` |

**Maßnahme:** Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-maxsize parameter to an appropriate size in MB

_Die Befehle wurden nicht ausgeführt._

### 396. Ensure that the --encryption-provider-config argument is set as appropriate

| | |
|---|---|
| ID | `18d15a75f54ac40f` |
| Prüfung | `trivy:KCV-0030` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[9]` |

**Maßnahme:** Follow the Kubernetes documentation and configure a EncryptionConfig file. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --encryption-provider-config parameter to the path of that file

_Die Befehle wurden nicht ausgeführt._

### 397. Ensure that the --terminated-pod-gc-threshold argument is set as appropriate

| | |
|---|---|
| ID | `68a29eeee4436d7f` |
| Prüfung | `trivy:KCV-0033` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[0]` |

**Maßnahme:** Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --terminated-pod-gc-threshold to an appropriate threshold.

_Die Befehle wurden nicht ausgeführt._

### 398. Ensure that the --profiling argument is set to false

| | |
|---|---|
| ID | `68bb4e938248ad26` |
| Prüfung | `trivy:KCV-0034` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[1]` |

**Maßnahme:** Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the below parameter.

_Die Befehle wurden nicht ausgeführt._

### 399. Ensure that the RotateKubeletServerCertificate argument is set to true

| | |
|---|---|
| ID | `7d70ad7f7d88fb92` |
| Prüfung | `trivy:KCV-0038` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[2]` |

**Maßnahme:** Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --feature-gates parameter to include RotateKubeletServerCertificate=true .

_Die Befehle wurden nicht ausgeführt._

### 400. Ensure that the --profiling argument is set to false

| | |
|---|---|
| ID | `701d2b297535f569` |
| Prüfung | `trivy:KCV-0040` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[0]` |

**Maßnahme:** Edit the Scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml file on the Control Plane node and set the below parameter.

_Die Befehle wurden nicht ausgeführt._

### 401. Default capabilities: some containers do not drop all

| | |
|---|---|
| ID | `2f4c42d7c50e24c5` |
| Prüfung | `trivy:KSV-0003` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[11]` |

**Maßnahme:** Add 'ALL' to containers\[\].securityContext.capabilities.drop.

_Die Befehle wurden nicht ausgeführt._

### 402. Default capabilities: some containers do not drop all

| | |
|---|---|
| ID | `50e5d9dcc48631ee` |
| Prüfung | `trivy:KSV-0003` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[1]` |

**Maßnahme:** Add 'ALL' to containers\[\].securityContext.capabilities.drop.

_Die Befehle wurden nicht ausgeführt._

### 403. Default capabilities: some containers do not drop all

| | |
|---|---|
| ID | `7ce5118ac94c4140` |
| Prüfung | `trivy:KSV-0003` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[4]` |

**Maßnahme:** Add 'ALL' to containers\[\].securityContext.capabilities.drop.

_Die Befehle wurden nicht ausgeführt._

### 404. Default capabilities: some containers do not drop all

| | |
|---|---|
| ID | `c4b82b2271d92caf` |
| Prüfung | `trivy:KSV-0003` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[1]` |

**Maßnahme:** Add 'ALL' to containers\[\].securityContext.capabilities.drop.

_Die Befehle wurden nicht ausgeführt._

### 405. Default capabilities: some containers do not drop all

| | |
|---|---|
| ID | `ca47a1621564af8c` |
| Prüfung | `trivy:KSV-0003` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[1]` |

**Maßnahme:** Add 'ALL' to containers\[\].securityContext.capabilities.drop.

_Die Befehle wurden nicht ausgeführt._

### 406. Default capabilities: some containers do not drop all

| | |
|---|---|
| ID | `cad62ba955eac02b` |
| Prüfung | `trivy:KSV-0003` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[2]` |

**Maßnahme:** Add 'ALL' to containers\[\].securityContext.capabilities.drop.

_Die Befehle wurden nicht ausgeführt._

### 407. Default capabilities: some containers do not drop all

| | |
|---|---|
| ID | `e13dfa7c25300792` |
| Prüfung | `trivy:KSV-0003` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[1]` |

**Maßnahme:** Add 'ALL' to containers\[\].securityContext.capabilities.drop.

_Die Befehle wurden nicht ausgeführt._

### 408. Default capabilities: some containers do not drop all

| | |
|---|---|
| ID | `fd6ebe676818b542` |
| Prüfung | `trivy:KSV-0003` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[1]` |

**Maßnahme:** Add 'ALL' to containers\[\].securityContext.capabilities.drop.

_Die Befehle wurden nicht ausgeführt._

### 409. Default capabilities: some containers do not drop any

| | |
|---|---|
| ID | `03eab96b3631d112` |
| Prüfung | `trivy:KSV-0004` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[12]` |

**Maßnahme:** Specify at least one unneeded capability in 'containers\[\].securityContext.capabilities.drop'

_Die Befehle wurden nicht ausgeführt._

### 410. Default capabilities: some containers do not drop any

| | |
|---|---|
| ID | `4c8742aba9216d73` |
| Prüfung | `trivy:KSV-0004` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[2]` |

**Maßnahme:** Specify at least one unneeded capability in 'containers\[\].securityContext.capabilities.drop'

_Die Befehle wurden nicht ausgeführt._

### 411. Default capabilities: some containers do not drop any

| | |
|---|---|
| ID | `7b0674aae04bcf3a` |
| Prüfung | `trivy:KSV-0004` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[2]` |

**Maßnahme:** Specify at least one unneeded capability in 'containers\[\].securityContext.capabilities.drop'

_Die Befehle wurden nicht ausgeführt._

### 412. Default capabilities: some containers do not drop any

| | |
|---|---|
| ID | `7c6255c9b3edb6bf` |
| Prüfung | `trivy:KSV-0004` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[3]` |

**Maßnahme:** Specify at least one unneeded capability in 'containers\[\].securityContext.capabilities.drop'

_Die Befehle wurden nicht ausgeführt._

### 413. Default capabilities: some containers do not drop any

| | |
|---|---|
| ID | `884bad114d35fd4e` |
| Prüfung | `trivy:KSV-0004` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[2]` |

**Maßnahme:** Specify at least one unneeded capability in 'containers\[\].securityContext.capabilities.drop'

_Die Befehle wurden nicht ausgeführt._

### 414. Default capabilities: some containers do not drop any

| | |
|---|---|
| ID | `88ba1bf79a862569` |
| Prüfung | `trivy:KSV-0004` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[2]` |

**Maßnahme:** Specify at least one unneeded capability in 'containers\[\].securityContext.capabilities.drop'

_Die Befehle wurden nicht ausgeführt._

### 415. Default capabilities: some containers do not drop any

| | |
|---|---|
| ID | `c955b0abc5da943b` |
| Prüfung | `trivy:KSV-0004` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[2]` |

**Maßnahme:** Specify at least one unneeded capability in 'containers\[\].securityContext.capabilities.drop'

_Die Befehle wurden nicht ausgeführt._

### 416. Default capabilities: some containers do not drop any

| | |
|---|---|
| ID | `e6a5348c6169eb40` |
| Prüfung | `trivy:KSV-0004` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[5]` |

**Maßnahme:** Specify at least one unneeded capability in 'containers\[\].securityContext.capabilities.drop'

_Die Befehle wurden nicht ausgeführt._

### 417. CPU not limited

| | |
|---|---|
| ID | `1e5b6ba098b0388c` |
| Prüfung | `trivy:KSV-0011` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[170].Results[0].Misconfigurations[0]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.cpu'.

_Die Befehle wurden nicht ausgeführt._

### 418. CPU not limited

| | |
|---|---|
| ID | `4074a28ff23199bf` |
| Prüfung | `trivy:KSV-0011` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[4]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.cpu'.

_Die Befehle wurden nicht ausgeführt._

### 419. CPU not limited

| | |
|---|---|
| ID | `50b2da41c1603fc9` |
| Prüfung | `trivy:KSV-0011` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[7]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.cpu'.

_Die Befehle wurden nicht ausgeführt._

### 420. CPU not limited

| | |
|---|---|
| ID | `810e3e69ae759e70` |
| Prüfung | `trivy:KSV-0011` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[5]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.cpu'.

_Die Befehle wurden nicht ausgeführt._

### 421. CPU not limited

| | |
|---|---|
| ID | `a8000f2a9b4e9b39` |
| Prüfung | `trivy:KSV-0011` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[14]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.cpu'.

_Die Befehle wurden nicht ausgeführt._

### 422. CPU not limited

| | |
|---|---|
| ID | `c60e959f6d24d4e3` |
| Prüfung | `trivy:KSV-0011` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[4]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.cpu'.

_Die Befehle wurden nicht ausgeführt._

### 423. CPU not limited

| | |
|---|---|
| ID | `cf86d336ca77785b` |
| Prüfung | `trivy:KSV-0011` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[5]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.cpu'.

_Die Befehle wurden nicht ausgeführt._

### 424. CPU not limited

| | |
|---|---|
| ID | `d8fc1b96241f70d6` |
| Prüfung | `trivy:KSV-0011` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[4]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.cpu'.

_Die Befehle wurden nicht ausgeführt._

### 425. CPU not limited

| | |
|---|---|
| ID | `fb3a3f9e38ea50fc` |
| Prüfung | `trivy:KSV-0011` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[3]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.cpu'.

_Die Befehle wurden nicht ausgeführt._

### 426. CPU requests not specified

| | |
|---|---|
| ID | `58900749535cac72` |
| Prüfung | `trivy:KSV-0015` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[6]` |

**Maßnahme:** Set 'containers\[\].resources.requests.cpu'.

_Die Befehle wurden nicht ausgeführt._

### 427. CPU requests not specified

| | |
|---|---|
| ID | `ac49297a6b586b1f` |
| Prüfung | `trivy:KSV-0015` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[7]` |

**Maßnahme:** Set 'containers\[\].resources.requests.cpu'.

_Die Befehle wurden nicht ausgeführt._

### 428. CPU requests not specified

| | |
|---|---|
| ID | `dd2de3a00e5d2336` |
| Prüfung | `trivy:KSV-0015` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[9]` |

**Maßnahme:** Set 'containers\[\].resources.requests.cpu'.

_Die Befehle wurden nicht ausgeführt._

### 429. Memory requests not specified

| | |
|---|---|
| ID | `099eb2b2a33f5e38` |
| Prüfung | `trivy:KSV-0016` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[7]` |

**Maßnahme:** Set 'containers\[\].resources.requests.memory'.

_Die Befehle wurden nicht ausgeführt._

### 430. Memory requests not specified

| | |
|---|---|
| ID | `25620e48b2619daf` |
| Prüfung | `trivy:KSV-0016` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[10]` |

**Maßnahme:** Set 'containers\[\].resources.requests.memory'.

_Die Befehle wurden nicht ausgeführt._

### 431. Memory requests not specified

| | |
|---|---|
| ID | `527a4609052a6fc3` |
| Prüfung | `trivy:KSV-0016` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[17]` |

**Maßnahme:** Set 'containers\[\].resources.requests.memory'.

_Die Befehle wurden nicht ausgeführt._

### 432. Memory requests not specified

| | |
|---|---|
| ID | `8dcdb88ba7a75405` |
| Prüfung | `trivy:KSV-0016` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[8]` |

**Maßnahme:** Set 'containers\[\].resources.requests.memory'.

_Die Befehle wurden nicht ausgeführt._

### 433. Memory requests not specified

| | |
|---|---|
| ID | `c2c5a67cac8abc4e` |
| Prüfung | `trivy:KSV-0016` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[10]` |

**Maßnahme:** Set 'containers\[\].resources.requests.memory'.

_Die Befehle wurden nicht ausgeführt._

### 434. Memory requests not specified

| | |
|---|---|
| ID | `d7c09ed2f5148b15` |
| Prüfung | `trivy:KSV-0016` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[8]` |

**Maßnahme:** Set 'containers\[\].resources.requests.memory'.

_Die Befehle wurden nicht ausgeführt._

### 435. Memory not limited

| | |
|---|---|
| ID | `037922d5b6405ff8` |
| Prüfung | `trivy:KSV-0018` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[12]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.memory'.

_Die Befehle wurden nicht ausgeführt._

### 436. Memory not limited

| | |
|---|---|
| ID | `2028f36e3ecfdb7d` |
| Prüfung | `trivy:KSV-0018` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[9]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.memory'.

_Die Befehle wurden nicht ausgeführt._

### 437. Memory not limited

| | |
|---|---|
| ID | `48377fdd35452663` |
| Prüfung | `trivy:KSV-0018` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[7]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.memory'.

_Die Befehle wurden nicht ausgeführt._

### 438. Memory not limited

| | |
|---|---|
| ID | `6ce37e56d5fe0017` |
| Prüfung | `trivy:KSV-0018` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[8]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.memory'.

_Die Befehle wurden nicht ausgeführt._

### 439. Memory not limited

| | |
|---|---|
| ID | `70eca99d6fbe6451` |
| Prüfung | `trivy:KSV-0018` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[11]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.memory'.

_Die Befehle wurden nicht ausgeführt._

### 440. Memory not limited

| | |
|---|---|
| ID | `cdc00d310c421f81` |
| Prüfung | `trivy:KSV-0018` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[10]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.memory'.

_Die Befehle wurden nicht ausgeführt._

### 441. Memory not limited

| | |
|---|---|
| ID | `db31bad017ae1af7` |
| Prüfung | `trivy:KSV-0018` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[18]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.memory'.

_Die Befehle wurden nicht ausgeführt._

### 442. Memory not limited

| | |
|---|---|
| ID | `f9f5004641c31825` |
| Prüfung | `trivy:KSV-0018` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[7]` |

**Maßnahme:** Set a limit value under 'containers\[\].resources.limits.memory'.

_Die Befehle wurden nicht ausgeführt._

### 443. Runs with UID \<= 10000

| | |
|---|---|
| ID | `15ac773124f848e6` |
| Prüfung | `trivy:KSV-0020` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[11]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsUser' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 444. Runs with UID \<= 10000

| | |
|---|---|
| ID | `30da06fa66291cfb` |
| Prüfung | `trivy:KSV-0020` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[8]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsUser' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 445. Runs with UID \<= 10000

| | |
|---|---|
| ID | `368a280182304da1` |
| Prüfung | `trivy:KSV-0020` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[8]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsUser' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 446. Runs with UID \<= 10000

| | |
|---|---|
| ID | `67ac345885eecbd4` |
| Prüfung | `trivy:KSV-0020` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[9]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsUser' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 447. Runs with UID \<= 10000

| | |
|---|---|
| ID | `6a24924266ad3ca2` |
| Prüfung | `trivy:KSV-0020` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[13]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsUser' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 448. Runs with UID \<= 10000

| | |
|---|---|
| ID | `9d2cef601123d49d` |
| Prüfung | `trivy:KSV-0020` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[12]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsUser' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 449. Runs with UID \<= 10000

| | |
|---|---|
| ID | `b293266b077bc19b` |
| Prüfung | `trivy:KSV-0020` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[19]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsUser' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 450. Runs with UID \<= 10000

| | |
|---|---|
| ID | `b92776b402a07d5c` |
| Prüfung | `trivy:KSV-0020` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[170].Results[0].Misconfigurations[2]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsUser' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 451. Runs with UID \<= 10000

| | |
|---|---|
| ID | `f806d8b0f1c7e633` |
| Prüfung | `trivy:KSV-0020` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[10]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsUser' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 452. Runs with GID \<= 10000

| | |
|---|---|
| ID | `3af4617e378247c9` |
| Prüfung | `trivy:KSV-0021` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[11]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsGroup' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 453. Runs with GID \<= 10000

| | |
|---|---|
| ID | `3b73c0a341e4ac31` |
| Prüfung | `trivy:KSV-0021` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[10]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsGroup' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 454. Runs with GID \<= 10000

| | |
|---|---|
| ID | `60a98c3782a36df4` |
| Prüfung | `trivy:KSV-0021` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/hardened` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[145].Results[0].Misconfigurations[0]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsGroup' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 455. Runs with GID \<= 10000

| | |
|---|---|
| ID | `78838d0581f459e0` |
| Prüfung | `trivy:KSV-0021` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[14]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsGroup' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 456. Runs with GID \<= 10000

| | |
|---|---|
| ID | `8c3430040b8156fe` |
| Prüfung | `trivy:KSV-0021` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[9]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsGroup' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 457. Runs with GID \<= 10000

| | |
|---|---|
| ID | `98c3a44fe5029cae` |
| Prüfung | `trivy:KSV-0021` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[9]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsGroup' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 458. Runs with GID \<= 10000

| | |
|---|---|
| ID | `9916f4d0ccc76933` |
| Prüfung | `trivy:KSV-0021` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[170].Results[0].Misconfigurations[3]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsGroup' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 459. Runs with GID \<= 10000

| | |
|---|---|
| ID | `aa51c9c3e2b6cf73` |
| Prüfung | `trivy:KSV-0021` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[20]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsGroup' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 460. Runs with GID \<= 10000

| | |
|---|---|
| ID | `e945ac869cc98f52` |
| Prüfung | `trivy:KSV-0021` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[12]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsGroup' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 461. Runs with GID \<= 10000

| | |
|---|---|
| ID | `ea6cabef128cec09` |
| Prüfung | `trivy:KSV-0021` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[13]` |

**Maßnahme:** Set 'containers\[\].securityContext.runAsGroup' to an integer \> 10000.

_Die Befehle wurden nicht ausgeführt._

### 462. Runtime/Default Seccomp profile not set

| | |
|---|---|
| ID | `2047c465ad46f587` |
| Prüfung | `trivy:KSV-0030` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[12]` |

**Maßnahme:** Set 'spec.securityContext.seccompProfile.type', 'spec.containers\[*\].securityContext.seccompProfile' and 'spec.initContainers\[*\].securityContext.seccompProfile' to 'RuntimeDefault' or undefined.

_Die Befehle wurden nicht ausgeführt._

### 463. Runtime/Default Seccomp profile not set

| | |
|---|---|
| ID | `30b502e938d75aa4` |
| Prüfung | `trivy:KSV-0030` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/kube-system/coredns` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[170].Results[0].Misconfigurations[5]` |

**Maßnahme:** Set 'spec.securityContext.seccompProfile.type', 'spec.containers\[*\].securityContext.seccompProfile' and 'spec.initContainers\[*\].securityContext.seccompProfile' to 'RuntimeDefault' or undefined.

_Die Befehle wurden nicht ausgeführt._

### 464. Runtime/Default Seccomp profile not set

| | |
|---|---|
| ID | `d2273b508f3ef326` |
| Prüfung | `trivy:KSV-0030` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[17]` |

**Maßnahme:** Set 'spec.securityContext.seccompProfile.type', 'spec.containers\[*\].securityContext.seccompProfile' and 'spec.initContainers\[*\].securityContext.seccompProfile' to 'RuntimeDefault' or undefined.

_Die Befehle wurden nicht ausgeführt._

### 465. Runtime/Default Seccomp profile not set

| | |
|---|---|
| ID | `d9d4ea0401e93daf` |
| Prüfung | `trivy:KSV-0030` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[14]` |

**Maßnahme:** Set 'spec.securityContext.seccompProfile.type', 'spec.containers\[*\].securityContext.seccompProfile' and 'spec.initContainers\[*\].securityContext.seccompProfile' to 'RuntimeDefault' or undefined.

_Die Befehle wurden nicht ausgeführt._

### 466. Runtime/Default Seccomp profile not set

| | |
|---|---|
| ID | `e2b115bea3aec365` |
| Prüfung | `trivy:KSV-0030` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[11]` |

**Maßnahme:** Set 'spec.securityContext.seccompProfile.type', 'spec.containers\[*\].securityContext.seccompProfile' and 'spec.initContainers\[*\].securityContext.seccompProfile' to 'RuntimeDefault' or undefined.

_Die Befehle wurden nicht ausgeführt._

### 467. Containers must not set runAsUser to 0

| | |
|---|---|
| ID | `b9b2a6ac50722d5f` |
| Prüfung | `trivy:KSV-0105` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[20]` |

**Maßnahme:** Set 'securityContext.runAsUser' to a non-zero integer or leave undefined.

_Die Befehle wurden nicht ausgeführt._

### 468. Container capabilities must only include NET_BIND_SERVICE

| | |
|---|---|
| ID | `18b698da51512d3d` |
| Prüfung | `trivy:KSV-0106` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[169].Results[0].Misconfigurations[17]` |

**Maßnahme:** Set 'spec.containers\[*\].securityContext.capabilities.drop' to 'ALL' and only add 'NET_BIND_SERVICE' to 'spec.containers\[*\].securityContext.capabilities.add'.

_Die Befehle wurden nicht ausgeführt._

### 469. Container capabilities must only include NET_BIND_SERVICE

| | |
|---|---|
| ID | `5f787902f51bd9ca` |
| Prüfung | `trivy:KSV-0106` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[173].Results[0].Misconfigurations[16]` |

**Maßnahme:** Set 'spec.containers\[*\].securityContext.capabilities.drop' to 'ALL' and only add 'NET_BIND_SERVICE' to 'spec.containers\[*\].securityContext.capabilities.add'.

_Die Befehle wurden nicht ausgeführt._

### 470. Container capabilities must only include NET_BIND_SERVICE

| | |
|---|---|
| ID | `b4d03e5a92114557` |
| Prüfung | `trivy:KSV-0106` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[171].Results[0].Misconfigurations[12]` |

**Maßnahme:** Set 'spec.containers\[*\].securityContext.capabilities.drop' to 'ALL' and only add 'NET_BIND_SERVICE' to 'spec.containers\[*\].securityContext.capabilities.add'.

_Die Befehle wurden nicht ausgeführt._

### 471. Container capabilities must only include NET_BIND_SERVICE

| | |
|---|---|
| ID | `bd75d47ccf321636` |
| Prüfung | `trivy:KSV-0106` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[172].Results[0].Misconfigurations[23]` |

**Maßnahme:** Set 'spec.containers\[*\].securityContext.capabilities.drop' to 'ALL' and only add 'NET_BIND_SERVICE' to 'spec.containers\[*\].securityContext.capabilities.add'.

_Die Befehle wurden nicht ausgeführt._

### 472. Container capabilities must only include NET_BIND_SERVICE

| | |
|---|---|
| ID | `be1a6e6fe76b9622` |
| Prüfung | `trivy:KSV-0106` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[168].Results[0].Misconfigurations[15]` |

**Maßnahme:** Set 'spec.containers\[*\].securityContext.capabilities.drop' to 'ALL' and only add 'NET_BIND_SERVICE' to 'spec.containers\[*\].securityContext.capabilities.add'.

_Die Befehle wurden nicht ausgeführt._

### 473. Container capabilities must only include NET_BIND_SERVICE

| | |
|---|---|
| ID | `c1f3aef8e4716dc3` |
| Prüfung | `trivy:KSV-0106` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Deployment/local-path-storage/local-path-provisioner` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[240].Results[0].Misconfigurations[13]` |

**Maßnahme:** Set 'spec.containers\[*\].securityContext.capabilities.drop' to 'ALL' and only add 'NET_BIND_SERVICE' to 'spec.containers\[*\].securityContext.capabilities.add'.

_Die Befehle wurden nicht ausgeführt._

### 474. Container capabilities must only include NET_BIND_SERVICE

| | |
|---|---|
| ID | `c2af10de5e77722b` |
| Prüfung | `trivy:KSV-0106` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[174].Results[0].Misconfigurations[14]` |

**Maßnahme:** Set 'spec.containers\[*\].securityContext.capabilities.drop' to 'ALL' and only add 'NET_BIND_SERVICE' to 'spec.containers\[*\].securityContext.capabilities.add'.

_Die Befehle wurden nicht ausgeführt._

### 475. Container capabilities must only include NET_BIND_SERVICE

| | |
|---|---|
| ID | `daa749ecdf8a6fce` |
| Prüfung | `trivy:KSV-0106` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[146].Results[0].Misconfigurations[21]` |

**Maßnahme:** Set 'spec.containers\[*\].securityContext.capabilities.drop' to 'ALL' and only add 'NET_BIND_SERVICE' to 'spec.containers\[*\].securityContext.capabilities.add'.

_Die Befehle wurden nicht ausgeführt._

### 476. TEMP-0000000-0F03E5 in libheif-plugin-dav1d 1.19.8-1+deb13u1

| | |
|---|---|
| ID | `d74ea6a56fdd81fe` |
| Prüfung | `trivy:TEMP-0000000-0F03E5` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[145]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[165]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[185]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 477. TEMP-0000000-18A2CE in libheif-plugin-dav1d 1.19.8-1+deb13u1

| | |
|---|---|
| ID | `62365ba401a3fa11` |
| Prüfung | `trivy:TEMP-0000000-18A2CE` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[146]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[166]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[186]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 478. TEMP-0000000-21F713 in libheif-plugin-dav1d 1.19.8-1+deb13u1

| | |
|---|---|
| ID | `035f34d0b7ef676d` |
| Prüfung | `trivy:TEMP-0000000-21F713` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[147]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[167]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[187]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 479. TEMP-0000000-4EF776 in libheif-plugin-dav1d 1.19.8-1+deb13u1

| | |
|---|---|
| ID | `6f4c8de35fec7cfb` |
| Prüfung | `trivy:TEMP-0000000-4EF776` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[148]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[168]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[188]` |

**Maßnahme:** Paket auf Version 1.23.4-1~deb13u1 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 480. TEMP-0000000-78AC20 in libheif-plugin-dav1d 1.19.8-1+deb13u1

| | |
|---|---|
| ID | `7080881d5df610c9` |
| Prüfung | `trivy:TEMP-0000000-78AC20` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[149]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[169]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[189]` |

**Maßnahme:** Paket auf Version 1.23.4-1~deb13u1 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 481. TEMP-0000000-956D99 in libheif-plugin-dav1d 1.19.8-1+deb13u1

| | |
|---|---|
| ID | `653212d670827fdc` |
| Prüfung | `trivy:TEMP-0000000-956D99` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[150]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[170]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[190]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 482. TEMP-0000000-BB5891 in libde265-0 1.0.15-1+deb13u2

| | |
|---|---|
| ID | `5e0858785c3f0f65` |
| Prüfung | `trivy:TEMP-0000000-BB5891` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[120]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 483. TEMP-0000000-BBE297 in libheif-plugin-dav1d 1.19.8-1+deb13u1

| | |
|---|---|
| ID | `4334b6bf30616317` |
| Prüfung | `trivy:TEMP-0000000-BBE297` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[151]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[171]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[191]` |

**Maßnahme:** Paket auf Version 1.23.4-1~deb13u1 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 484. TEMP-0000000-D1A721 in libheif-plugin-dav1d 1.19.8-1+deb13u1

| | |
|---|---|
| ID | `d5e397c7e88930ef` |
| Prüfung | `trivy:TEMP-0000000-D1A721` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[152]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[172]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[192]` |

**Maßnahme:** Paket auf Version 1.23.4-1~deb13u1 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 485. TEMP-0000000-DB3DE2 in libheif-plugin-dav1d 1.19.8-1+deb13u1

| | |
|---|---|
| ID | `ebb48e02467af0a4` |
| Prüfung | `trivy:TEMP-0000000-DB3DE2` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[153]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[173]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[193]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 486. TEMP-0000000-E66AA0 in libde265-0 1.0.15-1+deb13u2

| | |
|---|---|
| ID | `5c3562b6a85b4877` |
| Prüfung | `trivy:TEMP-0000000-E66AA0` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[121]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 487. TEMP-0000000-F2B97A in libheif-plugin-dav1d 1.19.8-1+deb13u1

| | |
|---|---|
| ID | `8fbde94f2b4a7df6` |
| Prüfung | `trivy:TEMP-0000000-F2B97A` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[154]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[174]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[194]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 488. TEMP-0290435-0B57B5 in tar 1.35+dfsg-3.1

| | |
|---|---|
| ID | `e47ccb0739a5c9ad` |
| Prüfung | `trivy:TEMP-0290435-0B57B5` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[382]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 489. TEMP-0517018-A83CE6 in sysvinit-utils 3.14-4

| | |
|---|---|
| ID | `8c6f968412e067b5` |
| Prüfung | `trivy:TEMP-0517018-A83CE6` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[377]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 490. TEMP-0628843-DBAD28 in login.defs 1:4.17.4-2

| | |
|---|---|
| ID | `10843d69b4966e06` |
| Prüfung | `trivy:TEMP-0628843-DBAD28` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[332]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[371]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 491. TEMP-0841856-B18BAF in bash 5.2.37-2+b10

| | |
|---|---|
| ID | `73ba78babcd1b1aa` |
| Prüfung | `trivy:TEMP-0841856-B18BAF` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[1]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 492. TEMP-1147318-639065 in liblzma5 5.8.1-1+deb13u1

| | |
|---|---|
| ID | `040ec3ed9e7655e7` |
| Prüfung | `trivy:TEMP-1147318-639065` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[221]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 493. TEMP-1148137-089975 in libheif-plugin-dav1d 1.19.8-1+deb13u1

| | |
|---|---|
| ID | `3e5d6510ad6ef46e` |
| Prüfung | `trivy:TEMP-1148137-089975` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[155]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[175]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[195]` |

**Maßnahme:** Paket auf Version 1.23.4-1~deb13u1 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 494. TEMP-1148137-126A7B in libheif-plugin-dav1d 1.19.8-1+deb13u1

| | |
|---|---|
| ID | `f436ab705c198517` |
| Prüfung | `trivy:TEMP-1148137-126A7B` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[156]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[176]`<br>`scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[196]` |

**Maßnahme:** Paket auf Version 1.23.4-1~deb13u1 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 495. TEMP-1149217-B31E38 in libpcre2-8-0 10.42-1

| | |
|---|---|
| ID | `14e3ba08871e4edc` |
| Prüfung | `trivy:TEMP-1149217-B31E38` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kube-proxy` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[254].Results[0].Vulnerabilities[37]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 496. TEMP-1149217-B31E38 in libpcre2-8-0 10.42-1

| | |
|---|---|
| ID | `21a71672e5b2baa4` |
| Prüfung | `trivy:TEMP-1149217-B31E38` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `DaemonSet/kube-system/kindnet` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[253].Results[0].Vulnerabilities[43]` |

**Maßnahme:** Keine korrigierte Version verfügbar.

_Die Befehle wurden nicht ausgeführt._

### 497. TEMP-1149217-B31E38 in libpcre2-8-0 10.46-1~deb13u2

| | |
|---|---|
| ID | `e899d3b089b84872` |
| Prüfung | `trivy:TEMP-1149217-B31E38` |
| Schweregrad | Niedrig (vom Scanner nicht eingestuft) |
| Priorität | – |
| Anforderungen | keine BSI-Zuordnung |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | trivy |
| Nachweise | `scanners/trivy.json` `$.Resources[248].Results[0].Vulnerabilities[236]` |

**Maßnahme:** Paket auf Version 10.46-1~deb13u3 aktualisieren.

_Die Befehle wurden nicht ausgeführt._

### 498. Fehlende CPU- oder Speicherlimits

| | |
|---|---|
| ID | `1ac6746d1771b910` |
| Prüfung | `workload.resource_limits_missing` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | SYS.1.6.A15 |
| Ressourcen | `Pod/kube-system/kindnet-svn9h` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[5].spec.containers[0].resources` |

**Maßnahme:** resources.limits.cpu und resources.limits.memory für jeden Container setzen.

_Die Befehle wurden nicht ausgeführt._

### 499. Fehlende CPU- oder Speicherlimits

| | |
|---|---|
| ID | `1c6f99f2c619939f` |
| Prüfung | `workload.resource_limits_missing` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | SYS.1.6.A15 |
| Ressourcen | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[6].spec.containers[0].resources` |

**Maßnahme:** resources.limits.cpu und resources.limits.memory für jeden Container setzen.

_Die Befehle wurden nicht ausgeführt._

### 500. Fehlende CPU- oder Speicherlimits

| | |
|---|---|
| ID | `1f05a45f526379af` |
| Prüfung | `workload.resource_limits_missing` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | SYS.1.6.A15 |
| Ressourcen | `Pod/local-path-storage/local-path-provisioner-75f7fc7dc5-q5x9t` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[10].spec.containers[0].resources` |

**Maßnahme:** resources.limits.cpu und resources.limits.memory für jeden Container setzen.

_Die Befehle wurden nicht ausgeführt._

### 501. Fehlende CPU- oder Speicherlimits

| | |
|---|---|
| ID | `5c96762585c5af9f` |
| Prüfung | `workload.resource_limits_missing` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | SYS.1.6.A15 |
| Ressourcen | `Pod/kube-system/coredns-559f6c778d-sgjj4` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[3].spec.containers[0].resources` |

**Maßnahme:** resources.limits.cpu und resources.limits.memory für jeden Container setzen.

_Die Befehle wurden nicht ausgeführt._

### 502. Fehlende CPU- oder Speicherlimits

| | |
|---|---|
| ID | `6a7964c06260102b` |
| Prüfung | `workload.resource_limits_missing` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | SYS.1.6.A15 |
| Ressourcen | `Pod/audit-demo/insecure` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[1].spec.containers[0].resources` |

**Maßnahme:** resources.limits.cpu und resources.limits.memory für jeden Container setzen.

_Die Befehle wurden nicht ausgeführt._

### 503. Fehlende CPU- oder Speicherlimits

| | |
|---|---|
| ID | `814d974f94df035c` |
| Prüfung | `workload.resource_limits_missing` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | SYS.1.6.A15 |
| Ressourcen | `Pod/kube-system/etcd-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[4].spec.containers[0].resources` |

**Maßnahme:** resources.limits.cpu und resources.limits.memory für jeden Container setzen.

_Die Befehle wurden nicht ausgeführt._

### 504. Fehlende CPU- oder Speicherlimits

| | |
|---|---|
| ID | `8eb18c1ac27ffb8f` |
| Prüfung | `workload.resource_limits_missing` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | SYS.1.6.A15 |
| Ressourcen | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[9].spec.containers[0].resources` |

**Maßnahme:** resources.limits.cpu und resources.limits.memory für jeden Container setzen.

_Die Befehle wurden nicht ausgeführt._

### 505. Fehlende CPU- oder Speicherlimits

| | |
|---|---|
| ID | `9119d94eaf2933e9` |
| Prüfung | `workload.resource_limits_missing` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | SYS.1.6.A15 |
| Ressourcen | `Pod/kube-system/coredns-559f6c778d-bjswk` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[2].spec.containers[0].resources` |

**Maßnahme:** resources.limits.cpu und resources.limits.memory für jeden Container setzen.

_Die Befehle wurden nicht ausgeführt._

### 506. Fehlende CPU- oder Speicherlimits

| | |
|---|---|
| ID | `c43bd2a727467ac2` |
| Prüfung | `workload.resource_limits_missing` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | SYS.1.6.A15 |
| Ressourcen | `Pod/kube-system/kube-proxy-sxldn` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[8].spec.containers[0].resources` |

**Maßnahme:** resources.limits.cpu und resources.limits.memory für jeden Container setzen.

_Die Befehle wurden nicht ausgeführt._

### 507. Fehlende CPU- oder Speicherlimits

| | |
|---|---|
| ID | `d369033dfa129828` |
| Prüfung | `workload.resource_limits_missing` |
| Schweregrad | Niedrig |
| Priorität | – |
| Anforderungen | SYS.1.6.A15 |
| Ressourcen | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| Quellen | built-in |
| Nachweise | `resources/pods.json` `$.items[7].spec.containers[0].resources` |

**Maßnahme:** resources.limits.cpu und resources.limits.memory für jeden Container setzen.

_Die Befehle wurden nicht ausgeführt._

## 3a. Image-Schwachstellen

| ID | Titel | Schweregrad | Ressource |
|---|---|---|---|
| `c5d8d4c83f7b0a05` | CVE-2025-68121 in stdlib v1.25.6 | Kritisch | `DaemonSet/kube-system/kindnet` |
| `760e6aed17d82510` | CVE-2026-31789 in libssl3 3.0.18-1~deb12u1 | Kritisch | `DaemonSet/kube-system/kindnet` |
| `e3197ea4232a09e0` | CVE-2026-6653 in libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | Kritisch | `Pod/audit-demo/insecure` |
| `8bcec7fd64ded268` | CVE-2023-28452 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Hoch | `Deployment/kube-system/coredns` |
| `8cfbe21aab93580c` | CVE-2025-15467 in libssl3 3.0.18-1~deb12u1 | Hoch | `DaemonSet/kube-system/kindnet` |
| `e3c937637c46fee7` | CVE-2025-47950 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Hoch | `Deployment/kube-system/coredns` |
| `238057e9ed4e07ae` | CVE-2025-69421 in libssl3 3.0.18-1~deb12u1 | Hoch | `DaemonSet/kube-system/kindnet` |
| `0182fed9b35b69bb` | CVE-2025-69720 in libtinfo6 6.5+20250216-2 | Hoch | `Pod/audit-demo/insecure` |
| `1df07c08352e033c` | CVE-2026-12064 in curl 8.14.1-2+deb13u5 | Hoch | `Pod/audit-demo/insecure` |
| `c450c2e252bcab6e` | CVE-2026-16742 in libsystemd0 257.13-1~deb13u1 | Hoch | `Pod/audit-demo/insecure` |
| `0d7e74e981ff71ff` | CVE-2026-25679 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `b932b36e01db81e4` | CVE-2026-25681 in golang.org/x/net v0.38.0 | Hoch | `Deployment/local-path-storage/local-path-provisioner` |
| `8c01d92e090944fa` | CVE-2026-26017 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Hoch | `Deployment/kube-system/coredns` |
| `2fa5a9a22f37d590` | CVE-2026-26018 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Hoch | `Deployment/kube-system/coredns` |
| `ca8f96d47bfa3a32` | CVE-2026-27136 in golang.org/x/net v0.38.0 | Hoch | `Deployment/local-path-storage/local-path-provisioner` |
| `df44f3a08b661095` | CVE-2026-27145 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `0316724df3d3586b` | CVE-2026-28387 in libssl3 3.0.18-1~deb12u1 | Hoch | `DaemonSet/kube-system/kindnet` |
| `4dc9368b1e17854b` | CVE-2026-28388 in libssl3 3.0.18-1~deb12u1 | Hoch | `DaemonSet/kube-system/kindnet` |
| `35842bd61ae0d0bb` | CVE-2026-28389 in libssl3 3.0.18-1~deb12u1 | Hoch | `DaemonSet/kube-system/kindnet` |
| `3088cd50daf3e0ff` | CVE-2026-28390 in libssl3 3.0.18-1~deb12u1 | Hoch | `DaemonSet/kube-system/kindnet` |
| `0280dbee01a4c0ba` | CVE-2026-32280 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `c126359635d56a4e` | CVE-2026-32281 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `8818d37ed7a59864` | CVE-2026-32283 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `b7e47c0c61668aea` | CVE-2026-32934 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Hoch | `Deployment/kube-system/coredns` |
| `f896420ff68b1673` | CVE-2026-32936 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Hoch | `Deployment/kube-system/coredns` |
| `68ff6a0bc35feaf7` | CVE-2026-33190 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Hoch | `Deployment/kube-system/coredns` |
| `39b49b1cc29d4d25` | CVE-2026-33489 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Hoch | `Deployment/kube-system/coredns` |
| `3d0ba2ef7077f7cc` | CVE-2026-33811 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `5facc126f7d367f5` | CVE-2026-33814 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `e1e3503c0497b8f7` | CVE-2026-33814 in golang.org/x/net v0.38.0 | Hoch | `Deployment/local-path-storage/local-path-provisioner` |
| `1918ba68b1f16c7d` | CVE-2026-33818 in stdlib v1.26.5 | Hoch | `Pod/kube-system/etcd-kba-it-control-plane` |
| `7ff4722fb3e91f6e` | CVE-2026-33818 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `9f12c48a53c24436` | CVE-2026-33818 in stdlib v1.26.5 | Hoch | `Deployment/kube-system/coredns` |
| `3e81065f40be7835` | CVE-2026-35579 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Hoch | `Deployment/kube-system/coredns` |
| `908cd3f48c2cf077` | CVE-2026-36849 in libtiff6 4.7.0-3+deb13u3 | Hoch | `Pod/audit-demo/insecure` |
| `4c3d6223e6c97a84` | CVE-2026-39820 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `8077fe76e81692aa` | CVE-2026-39821 in stdlib v1.26.5 | Hoch | `Deployment/kube-system/coredns` |
| `84ccc48b3ac6434d` | CVE-2026-39821 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `9f51f2b1c15ac3a8` | CVE-2026-39821 in stdlib v1.26.5 | Hoch | `Pod/kube-system/etcd-kba-it-control-plane` |
| `ae7509ef13cfac3b` | CVE-2026-39821 in golang.org/x/net v0.38.0 | Hoch | `Deployment/local-path-storage/local-path-provisioner` |
| `5737c9690f10d62b` | CVE-2026-39822 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `4556bd5ffd88c240` | CVE-2026-39836 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `406dc11b514c1e2f` | CVE-2026-42499 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `838758bb074a213a` | CVE-2026-42504 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `4d131f934a5f8fc0` | CVE-2026-44543 in github.com/rancher/local-path-provisioner v0.0.34 | Hoch | `Deployment/local-path-storage/local-path-provisioner` |
| `946da3e3cb7e1346` | CVE-2026-45447 in libssl3 3.0.18-1~deb12u1 | Hoch | `DaemonSet/kube-system/kindnet` |
| `36b0cf260310b6c6` | CVE-2026-46600 in golang.org/x/net v0.55.0 | Hoch | `DaemonSet/kube-system/kindnet` |
| `54e692be075b04c1` | CVE-2026-46600 in golang.org/x/net v0.55.0 | Hoch | `Pod/kube-system/etcd-kba-it-control-plane` |
| `aa15739e97f7183b` | CVE-2026-46600 in golang.org/x/net v0.38.0 | Hoch | `Deployment/local-path-storage/local-path-provisioner` |
| `e0366df1244d1365` | CVE-2026-46600 in stdlib v1.26.5 | Hoch | `Deployment/kube-system/coredns` |
| `474c05a22f8d60da` | CVE-2026-52490 in libtiff6 4.7.0-3+deb13u3 | Hoch | `Pod/audit-demo/insecure` |
| `f42d47f7bfdb3caf` | CVE-2026-54369 in libacl1 2.3.2-2+b1 | Hoch | `Pod/audit-demo/insecure` |
| `1755de48e65c2965` | CVE-2026-56852 in golang.org/x/text v0.37.0 | Hoch | `DaemonSet/kube-system/kindnet` |
| `5c67022321888d19` | CVE-2026-56852 in golang.org/x/text v0.38.0 | Hoch | `Deployment/kube-system/coredns` |
| `7cd0cbc6968c27eb` | CVE-2026-56852 in golang.org/x/text v0.23.0 | Hoch | `Deployment/local-path-storage/local-path-provisioner` |
| `bb5b2af856f599ff` | CVE-2026-56852 in golang.org/x/text v0.37.0 | Hoch | `Pod/kube-system/etcd-kba-it-control-plane` |
| `691538498bc7e775` | CVE-2026-56853 in stdlib v1.26.5 | Hoch | `Deployment/kube-system/coredns` |
| `d6a516399f035e76` | CVE-2026-56853 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `db51246e27916d15` | CVE-2026-56853 in stdlib v1.26.5 | Hoch | `Pod/kube-system/etcd-kba-it-control-plane` |
| `01e264d95cc23aad` | CVE-2026-56854 in golang.org/x/crypto v0.54.0 | Hoch | `DaemonSet/kube-system/kube-proxy` |
| `0c1f0e8ac4d07810` | CVE-2026-56854 in golang.org/x/crypto v0.52.0 | Hoch | `Pod/kube-system/etcd-kba-it-control-plane` |
| `18410f9f4851116d` | CVE-2026-56854 in golang.org/x/crypto v0.54.0 | Hoch | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| `4038b459dd6831e7` | CVE-2026-56854 in golang.org/x/crypto v0.53.0 | Hoch | `Deployment/kube-system/coredns` |
| `8521514e54ee2d6f` | CVE-2026-56854 in golang.org/x/crypto v0.54.0 | Hoch | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| `b5cf6be6a090e87d` | CVE-2026-56854 in golang.org/x/crypto v0.54.0 | Hoch | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| `2118065d589eb3fa` | CVE-2026-56858 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `2ca48b382ccd39e1` | CVE-2026-56858 in stdlib v1.26.5 | Hoch | `Deployment/kube-system/coredns` |
| `ccc78f9357874e31` | CVE-2026-56858 in stdlib v1.26.5 | Hoch | `Pod/kube-system/etcd-kba-it-control-plane` |
| `0cf300ba6e266316` | CVE-2026-56859 in stdlib v1.26.5 | Hoch | `Deployment/kube-system/coredns` |
| `7542336ca99cd6d3` | CVE-2026-56859 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `e123d7a70d003d80` | CVE-2026-56859 in stdlib v1.26.5 | Hoch | `Pod/kube-system/etcd-kba-it-control-plane` |
| `356b32d24cc032d6` | CVE-2026-56860 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `9d1b50ba9180183f` | CVE-2026-56860 in stdlib v1.26.5 | Hoch | `Pod/kube-system/etcd-kba-it-control-plane` |
| `e141eb41884c3179` | CVE-2026-56860 in stdlib v1.26.5 | Hoch | `Deployment/kube-system/coredns` |
| `5f6ab1eda212c96d` | CVE-2026-56862 in stdlib v1.25.6 | Hoch | `DaemonSet/kube-system/kindnet` |
| `747685ddea43bbae` | CVE-2026-56862 in stdlib v1.26.5 | Hoch | `Deployment/kube-system/coredns` |
| `8619a083bb809eee` | CVE-2026-56862 in stdlib v1.26.5 | Hoch | `Pod/kube-system/etcd-kba-it-control-plane` |
| `2fc47b8f3e8e1843` | CVE-2026-56864 in golang.org/x/mod v0.36.0 | Hoch | `Deployment/kube-system/coredns` |
| `1c8b9256b087e9f6` | CVE-2026-56865 in golang.org/x/mod v0.36.0 | Hoch | `Deployment/kube-system/coredns` |
| `ee0a9f70b7292c5a` | CVE-2026-66046 in libexpat1 2.8.3-1~deb13u1 | Hoch | `Pod/audit-demo/insecure` |
| `55c4e74818bb82f9` | CVE-2026-74860 in libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | Hoch | `Pod/audit-demo/insecure` |
| `6044d5fcf04f18cd` | CVE-2026-75804 in libssl3t64 3.5.7-1~deb13u2 | Hoch | `Pod/audit-demo/insecure` |
| `b144fb880a9936d3` | CVE-2026-76642 in bsdutils 1:2.41.5-0+deb13u1 | Hoch | `Pod/audit-demo/insecure` |
| `5aadbf874857dddf` | CVE-2026-76956 in libexpat1 2.8.3-1~deb13u1 | Hoch | `Pod/audit-demo/insecure` |
| `8fb4514c98499057` | CVE-2026-76957 in libexpat1 2.8.3-1~deb13u1 | Hoch | `Pod/audit-demo/insecure` |
| `116dd367a026fa74` | CVE-2026-78408 in bsdutils 1:2.41.5-0+deb13u1 | Hoch | `Pod/audit-demo/insecure` |
| `a54b030b9e79d8b7` | CVE-2026-78409 in bsdutils 1:2.41.5-0+deb13u1 | Hoch | `Pod/audit-demo/insecure` |
| `37d740c657ac1517` | CVE-2026-78410 in bsdutils 1:2.41.5-0+deb13u1 | Hoch | `Pod/audit-demo/insecure` |
| `01ef9e86505023b2` | CVE-2026-82399 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Hoch | `Deployment/kube-system/coredns` |
| `a5b519b9697a5192` | CVE-2026-8286 in curl 8.14.1-2+deb13u5 | Hoch | `Pod/audit-demo/insecure` |
| `31006d2db21d1638` | CVE-2026-84304 in google.golang.org/grpc v1.82.1 | Hoch | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| `4a3031f3706c1265` | CVE-2026-84304 in google.golang.org/grpc v1.82.1 | Hoch | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| `702456d07daf4a07` | CVE-2026-84304 in google.golang.org/grpc v1.82.1 | Hoch | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| `ab2be26e3e3422b5` | CVE-2026-84304 in google.golang.org/grpc v1.81.0 | Hoch | `Pod/kube-system/etcd-kba-it-control-plane` |
| `c09e9cbdbf25e212` | CVE-2026-84304 in google.golang.org/grpc v1.82.1 | Hoch | `DaemonSet/kube-system/kube-proxy` |
| `c26bee1753ce6266` | CVE-2026-84304 in google.golang.org/grpc v1.82.0 | Hoch | `Deployment/kube-system/coredns` |
| `09d393ba7e8df853` | CVE-2026-84445 in google.golang.org/grpc v1.82.1 | Hoch | `DaemonSet/kube-system/kube-proxy` |
| `4c8d2479561bda7f` | CVE-2026-84445 in google.golang.org/grpc v1.82.1 | Hoch | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| `ac5ee62817661726` | CVE-2026-84445 in google.golang.org/grpc v1.82.0 | Hoch | `Deployment/kube-system/coredns` |
| `adc5903cce3e4451` | CVE-2026-84445 in google.golang.org/grpc v1.82.1 | Hoch | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| `cdabaae03edc3ae9` | CVE-2026-84445 in google.golang.org/grpc v1.82.1 | Hoch | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| `d35c8a586dbef7b8` | CVE-2026-84445 in google.golang.org/grpc v1.81.0 | Hoch | `Pod/kube-system/etcd-kba-it-control-plane` |
| `ed3b9f6e2a663999` | CVE-2026-8458 in curl 8.14.1-2+deb13u5 | Hoch | `Pod/audit-demo/insecure` |
| `59ca13330751dba3` | CVE-2026-84782 in libssl3 3.0.20-1~deb12u2 | Hoch | `DaemonSet/kube-system/kube-proxy` |
| `d5ef9d1179bc20ca` | CVE-2026-84782 in libssl3 3.0.18-1~deb12u1 | Hoch | `DaemonSet/kube-system/kindnet` |
| `ec7af04e4f99a10b` | CVE-2026-84782 in libssl3t64 3.5.7-1~deb13u2 | Hoch | `Pod/audit-demo/insecure` |
| `e8d7d9993461073b` | CVE-2026-86003 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Hoch | `Deployment/kube-system/coredns` |
| `af3a067a7624ad42` | CVE-2026-86138 in libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | Hoch | `Pod/audit-demo/insecure` |
| `4ea9cf90dc72b8e2` | CVE-2026-86139 in libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | Hoch | `Pod/audit-demo/insecure` |
| `995a9e120009e1fc` | CVE-2026-86140 in libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | Hoch | `Pod/audit-demo/insecure` |
| `249fb41e82bc8de9` | CVE-2026-86142 in libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | Hoch | `Pod/audit-demo/insecure` |
| `65b048be43fe2118` | CVE-2026-86143 in libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | Hoch | `Pod/audit-demo/insecure` |
| `541798393659bd03` | CVE-2026-86144 in libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | Hoch | `Pod/audit-demo/insecure` |
| `32bd1e9f10f1c1d9` | CVE-2026-86145 in libpcre2-8-0 10.42-1 | Hoch | `DaemonSet/kube-system/kube-proxy` |
| `59a89b96e5a4d689` | CVE-2026-86145 in libpcre2-8-0 10.42-1 | Hoch | `DaemonSet/kube-system/kindnet` |
| `8cd16f0566ca355f` | CVE-2026-88806 in libx11-6 2:1.8.12-1 | Hoch | `Pod/audit-demo/insecure` |
| `0cdc3e2112a22b7a` | CVE-2026-89157 in libpcre2-8-0 10.42-1 | Hoch | `DaemonSet/kube-system/kube-proxy` |
| `8a6df4c4d2050364` | CVE-2026-89157 in libpcre2-8-0 10.42-1 | Hoch | `DaemonSet/kube-system/kindnet` |
| `1a00bde30dd07042` | CVE-2026-89161 in libpcre2-8-0 10.42-1 | Hoch | `DaemonSet/kube-system/kindnet` |
| `9457445351212b46` | CVE-2026-89161 in libpcre2-8-0 10.42-1 | Hoch | `DaemonSet/kube-system/kube-proxy` |
| `00db2b3a10fca2ef` | CVE-2026-8927 in curl 8.14.1-2+deb13u5 | Hoch | `Pod/audit-demo/insecure` |
| `5e6b49df47b160e7` | CVE-2026-93990 in libexpat1 2.8.3-1~deb13u1 | Hoch | `Pod/audit-demo/insecure` |
| `c4d5ff81c038f7e8` | CVE-2026-9538 in perl-base 5.40.1-6+deb13u1 | Hoch | `Pod/audit-demo/insecure` |
| `4d05ef074b1b8538` | GHSA-hrxh-6v49-42gf in google.golang.org/grpc v1.81.0 | Hoch | `Pod/kube-system/etcd-kba-it-control-plane` |
| `9d36b179f0cb2324` | GHSA-hrxh-6v49-42gf in google.golang.org/grpc v1.82.0 | Hoch | `Deployment/kube-system/coredns` |
| `0366be9159e36de4` | CVE-2022-2835 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Mittel | `Deployment/kube-system/coredns` |
| `e4fb8e995c3f94ef` | CVE-2022-2837 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Mittel | `Deployment/kube-system/coredns` |
| `16551e539f3830cc` | CVE-2023-30464 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Mittel | `Deployment/kube-system/coredns` |
| `fba1945351eea38e` | CVE-2024-0874 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Mittel | `Deployment/kube-system/coredns` |
| `57d0e99470019294` | CVE-2025-10911 in libxslt1.1 1.1.35-1.2+deb13u3 | Mittel | `Pod/audit-demo/insecure` |
| `0b8c83a1c2dcab49` | CVE-2025-13281 in k8s.io/controller-manager v1.37.0 | Mittel | `ControlPlaneComponents/kube-system/k8s.io/controller-manager` |
| `d0b82fa06bb70436` | CVE-2025-1767 in k8s.io/kubernetes 1.37.0 | Mittel | `Cluster/-/k8s.io/kubernetes` |
| `4780e22ce11d4739` | CVE-2025-47911 in golang.org/x/net v0.38.0 | Mittel | `Deployment/local-path-storage/local-path-provisioner` |
| `23c0bbfeae827397` | CVE-2025-58190 in golang.org/x/net v0.38.0 | Mittel | `Deployment/local-path-storage/local-path-provisioner` |
| `5aa9a3e4ef99c21e` | CVE-2025-66382 in libexpat1 2.8.3-1~deb13u1 | Mittel | `Pod/audit-demo/insecure` |
| `43669496e51d4dd1` | CVE-2025-68151 in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Mittel | `Deployment/kube-system/coredns` |
| `057960eff0979732` | CVE-2025-69419 in libssl3 3.0.18-1~deb12u1 | Mittel | `DaemonSet/kube-system/kindnet` |
| `d0297983b72b8a6b` | CVE-2026-0915 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `0a3faf1ff370680b` | CVE-2026-102010 in gcc-14-base 14.2.0-19 | Mittel | `Pod/audit-demo/insecure` |
| `19d7f2ca996a1cd5` | CVE-2026-102473 in dash 0.5.12-12 | Mittel | `Pod/audit-demo/insecure` |
| `8474a66c810654ef` | CVE-2026-102633 in libexpat1 2.8.3-1~deb13u1 | Mittel | `Pod/audit-demo/insecure` |
| `c8556c79e9a51510` | CVE-2026-10536 in curl 8.14.1-2+deb13u5 | Mittel | `Pod/audit-demo/insecure` |
| `2ef43f2f66a765b2` | CVE-2026-11856 in curl 8.14.1-2+deb13u5 | Mittel | `Pod/audit-demo/insecure` |
| `24dd69ee5b57edcb` | CVE-2026-13757 in libp11-kit0 0.25.5-3 | Mittel | `Pod/audit-demo/insecure` |
| `23f31657b301425a` | CVE-2026-15059 in libsystemd0 257.13-1~deb13u1 | Mittel | `Pod/audit-demo/insecure` |
| `d3f7dbff161bb579` | CVE-2026-15534 in perl-base 5.40.1-6+deb13u1 | Mittel | `Pod/audit-demo/insecure` |
| `24542f6a96da0979` | CVE-2026-18374 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `aaf1dff3b67d71bd` | CVE-2026-18374 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `cca1a5696ecdbf25` | CVE-2026-18374 in libc-bin 2.41-12+deb13u4 | Mittel | `Pod/audit-demo/insecure` |
| `cf9409fd5136dc94` | CVE-2026-18477 in tar 1.35+dfsg-3.1 | Mittel | `Pod/audit-demo/insecure` |
| `40ed98f200dcd291` | CVE-2026-18495 in libtiff6 4.7.0-3+deb13u3 | Mittel | `Pod/audit-demo/insecure` |
| `24b73913e1bdf2f9` | CVE-2026-18508 in tar 1.35+dfsg-3.1 | Mittel | `Pod/audit-demo/insecure` |
| `7ba9ca04c8ba4e92` | CVE-2026-18938 in libp11-kit0 0.25.5-3 | Mittel | `Pod/audit-demo/insecure` |
| `34fbd40efc44b983` | CVE-2026-19487 in perl-base 5.40.1-6+deb13u1 | Mittel | `Pod/audit-demo/insecure` |
| `3653692d38073b3e` | CVE-2026-19499 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `3fa808f8a306e271` | CVE-2026-19499 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `6695898d6d2de67c` | CVE-2026-19499 in libc-bin 2.41-12+deb13u4 | Mittel | `Pod/audit-demo/insecure` |
| `5370ea6916208185` | CVE-2026-19542 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `58a92e6bde416966` | CVE-2026-19542 in libc-bin 2.41-12+deb13u4 | Mittel | `Pod/audit-demo/insecure` |
| `b3255c8102b54477` | CVE-2026-19542 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `7ce5971b906529da` | CVE-2026-19931 in curl 8.14.1-2+deb13u5 | Mittel | `Pod/audit-demo/insecure` |
| `d2d73005dead9ff6` | CVE-2026-25680 in golang.org/x/net v0.38.0 | Mittel | `Deployment/local-path-storage/local-path-provisioner` |
| `dc80490ae8422157` | CVE-2026-27142 in stdlib v1.25.6 | Mittel | `DaemonSet/kube-system/kindnet` |
| `1b94b43d634c5985` | CVE-2026-27171 in zlib1g 1:1.3.dfsg+really1.3.1-1+b1 | Mittel | `Pod/audit-demo/insecure` |
| `7d4c9fcddd662de5` | CVE-2026-31790 in libssl3 3.0.18-1~deb12u1 | Mittel | `DaemonSet/kube-system/kindnet` |
| `e4d46f88a68946e9` | CVE-2026-3184 in bsdutils 1:2.41.5-0+deb13u1 | Mittel | `Pod/audit-demo/insecure` |
| `9a4e32e1da9cc09d` | CVE-2026-32282 in stdlib v1.25.6 | Mittel | `DaemonSet/kube-system/kindnet` |
| `b7fa2de9b7fe9076` | CVE-2026-32288 in stdlib v1.25.6 | Mittel | `DaemonSet/kube-system/kindnet` |
| `781558be07110818` | CVE-2026-32289 in stdlib v1.25.6 | Mittel | `DaemonSet/kube-system/kindnet` |
| `9c581371decf7328` | CVE-2026-34182 in libssl3 3.0.18-1~deb12u1 | Mittel | `DaemonSet/kube-system/kindnet` |
| `4f238eb57f2692c0` | CVE-2026-39823 in stdlib v1.25.6 | Mittel | `DaemonSet/kube-system/kindnet` |
| `8e83c7679cf02939` | CVE-2026-39825 in stdlib v1.25.6 | Mittel | `DaemonSet/kube-system/kindnet` |
| `e3df11e4b8317f24` | CVE-2026-39826 in stdlib v1.25.6 | Mittel | `DaemonSet/kube-system/kindnet` |
| `4f6d99a701939d90` | CVE-2026-4046 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `6112cb2c0758bf54` | CVE-2026-42250 in libbz2-1.0 1.0.8-6 | Mittel | `Pod/audit-demo/insecure` |
| `57f961a463bcdabc` | CVE-2026-42502 in golang.org/x/net v0.38.0 | Mittel | `Deployment/local-path-storage/local-path-provisioner` |
| `33192d27d2432a1d` | CVE-2026-42505 in stdlib v1.25.6 | Mittel | `DaemonSet/kube-system/kindnet` |
| `abfe7dea795c5afe` | CVE-2026-42506 in golang.org/x/net v0.38.0 | Mittel | `Deployment/local-path-storage/local-path-provisioner` |
| `1c781ce318ebcb87` | CVE-2026-42507 in stdlib v1.25.6 | Mittel | `DaemonSet/kube-system/kindnet` |
| `7f0e6b8c1871bc6d` | CVE-2026-42772 in libssl3t64 3.5.7-1~deb13u2 | Mittel | `Pod/audit-demo/insecure` |
| `0e40b877a4a1c102` | CVE-2026-4437 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `62a2583472b0c940` | CVE-2026-45445 in libssl3 3.0.18-1~deb12u1 | Mittel | `DaemonSet/kube-system/kindnet` |
| `bd8619e7d430acbe` | CVE-2026-50812 in libsqlite3-0 3.46.1-7+deb13u2 | Mittel | `Pod/audit-demo/insecure` |
| `5b8042cd2a59fd6b` | CVE-2026-50813 in libsqlite3-0 3.46.1-7+deb13u2 | Mittel | `Pod/audit-demo/insecure` |
| `70cb5d07b9116939` | CVE-2026-5435 in libc-bin 2.41-12+deb13u4 | Mittel | `Pod/audit-demo/insecure` |
| `f1e68b3a42418e46` | CVE-2026-5435 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `fb55ee66a29b691d` | CVE-2026-5435 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `95c93ebff9d5eac1` | CVE-2026-54370 in libacl1 2.3.2-2+b1 | Mittel | `Pod/audit-demo/insecure` |
| `4d946e231538f567` | CVE-2026-54371 in libattr1 1:2.5.2-3 | Mittel | `Pod/audit-demo/insecure` |
| `5b4393f49f36788d` | CVE-2026-54411 in libpam-modules 1.7.0-5 | Mittel | `Pod/audit-demo/insecure` |
| `042484a4944005ca` | CVE-2026-5450 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `e25ac9cbb2369137` | CVE-2026-5450 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `2db60b7e73aaab97` | CVE-2026-54872 in libssl3t64 3.5.7-1~deb13u2 | Mittel | `Pod/audit-demo/insecure` |
| `54bf0cc9a66c705e` | CVE-2026-54872 in libssl3 3.0.20-1~deb12u2 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `ecbb8c2b7b9d63cd` | CVE-2026-54872 in libssl3 3.0.18-1~deb12u1 | Mittel | `DaemonSet/kube-system/kindnet` |
| `7f2fd8608296392d` | CVE-2026-54873 in libssl3t64 3.5.7-1~deb13u2 | Mittel | `Pod/audit-demo/insecure` |
| `f048e0cc5f580cd5` | CVE-2026-54875 in libssl3t64 3.5.7-1~deb13u2 | Mittel | `Pod/audit-demo/insecure` |
| `3c74ab42ed23aa96` | CVE-2026-56855 in golang.org/x/crypto v0.54.0 | Mittel | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| `57c861571e6b041a` | CVE-2026-56855 in golang.org/x/crypto v0.53.0 | Mittel | `Deployment/kube-system/coredns` |
| `6c610dde8c189cd3` | CVE-2026-56855 in golang.org/x/crypto v0.52.0 | Mittel | `Pod/kube-system/etcd-kba-it-control-plane` |
| `ae5b4520363b76db` | CVE-2026-56855 in golang.org/x/crypto v0.54.0 | Mittel | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| `e16ed7212401d74c` | CVE-2026-56855 in golang.org/x/crypto v0.54.0 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `f31ba2b7c81a7975` | CVE-2026-56855 in golang.org/x/crypto v0.54.0 | Mittel | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| `c5b4e05357d000cd` | CVE-2026-5704 in tar 1.35+dfsg-3.1 | Mittel | `Pod/audit-demo/insecure` |
| `b2c9843a0c7fe6ce` | CVE-2026-58055 in libnghttp2-14 1.64.0-1.1+deb13u1 | Mittel | `Pod/audit-demo/insecure` |
| `35773e899b4c66e5` | CVE-2026-5928 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `5523e58eff02d151` | CVE-2026-5928 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `15bbc4113ce68807` | CVE-2026-6238 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `1687f3b61d9b14eb` | CVE-2026-6238 in libc-bin 2.41-12+deb13u4 | Mittel | `Pod/audit-demo/insecure` |
| `d03518907d274601` | CVE-2026-6238 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `a0a6e03e2e060422` | CVE-2026-63072 in libssl3 3.0.18-1~deb12u1 | Mittel | `DaemonSet/kube-system/kindnet` |
| `cf0187b5380add79` | CVE-2026-63072 in libssl3 3.0.20-1~deb12u2 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `4ccec91c881eec53` | CVE-2026-63076 in libssl3 3.0.20-1~deb12u2 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `5a8854fed5c5e72e` | CVE-2026-63076 in libssl3 3.0.18-1~deb12u1 | Mittel | `DaemonSet/kube-system/kindnet` |
| `36dc54d5e9e12274` | CVE-2026-6368 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `d51e1e835284d603` | CVE-2026-6368 in libc-bin 2.41-12+deb13u4 | Mittel | `Pod/audit-demo/insecure` |
| `da7e7a43189689d9` | CVE-2026-6368 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `718a6024e34df61e` | CVE-2026-6791 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `a1ab763ee26356fc` | CVE-2026-6791 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `effb2ebf175ec75e` | CVE-2026-6791 in libc-bin 2.41-12+deb13u4 | Mittel | `Pod/audit-demo/insecure` |
| `08fbe04d6e178fb3` | CVE-2026-72897 in libssl3t64 3.5.7-1~deb13u2 | Mittel | `Pod/audit-demo/insecure` |
| `1075e6ca469bf555` | CVE-2026-75805 in libssl3 3.0.18-1~deb12u1 | Mittel | `DaemonSet/kube-system/kindnet` |
| `4f0761a2470d8811` | CVE-2026-75805 in libssl3t64 3.5.7-1~deb13u2 | Mittel | `Pod/audit-demo/insecure` |
| `5ee70df0cbc24e72` | CVE-2026-75805 in libssl3 3.0.20-1~deb12u2 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `d6413c4fc79aacaf` | CVE-2026-75806 in libssl3t64 3.5.7-1~deb13u2 | Mittel | `Pod/audit-demo/insecure` |
| `daedf96ae56f4372` | CVE-2026-75806 in libssl3 3.0.18-1~deb12u1 | Mittel | `DaemonSet/kube-system/kindnet` |
| `f234be6294fa10ae` | CVE-2026-75806 in libssl3 3.0.20-1~deb12u2 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `c18c5183e57e3e55` | CVE-2026-76781 in libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | Mittel | `Pod/audit-demo/insecure` |
| `22623fefd7b32fdc` | CVE-2026-77117 in libc-bin 2.41-12+deb13u4 | Mittel | `Pod/audit-demo/insecure` |
| `8f315010a3682891` | CVE-2026-77117 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `c2eeed5b0b5fc2ba` | CVE-2026-77117 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `65d07e1ca7f0f49d` | CVE-2026-77696 in libssl3t64 3.5.7-1~deb13u2 | Mittel | `Pod/audit-demo/insecure` |
| `8b5f41ccf5c32437` | CVE-2026-77696 in libssl3 3.0.18-1~deb12u1 | Mittel | `DaemonSet/kube-system/kindnet` |
| `e12898d584864ada` | CVE-2026-77696 in libssl3 3.0.20-1~deb12u2 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `507250bdc33c48a8` | CVE-2026-78662 in golang.org/x/crypto v0.52.0 | Mittel | `Pod/kube-system/etcd-kba-it-control-plane` |
| `595a0325b3667c8d` | CVE-2026-78662 in golang.org/x/crypto v0.54.0 | Mittel | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| `80ee11085fc13a0a` | CVE-2026-78662 in golang.org/x/crypto v0.53.0 | Mittel | `Deployment/kube-system/coredns` |
| `8d7ab9deac104f3b` | CVE-2026-78662 in golang.org/x/crypto v0.54.0 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `b01a70e2cbc9efb7` | CVE-2026-78662 in golang.org/x/crypto v0.54.0 | Mittel | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| `b43ad4710b61c715` | CVE-2026-78662 in golang.org/x/crypto v0.54.0 | Mittel | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| `d93d7b55c28f3f24` | CVE-2026-80229 in curl 8.14.1-2+deb13u5 | Mittel | `Pod/audit-demo/insecure` |
| `0d2019fc7f5c1bbb` | CVE-2026-80489 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `abd1cbafe96b5fc6` | CVE-2026-80489 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `df57e1ed5d3093d2` | CVE-2026-80489 in libc-bin 2.41-12+deb13u4 | Mittel | `Pod/audit-demo/insecure` |
| `1dd39cfeaa0c12a6` | CVE-2026-84303 in google.golang.org/grpc v1.82.1 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `4ea9be4bbb2cc30f` | CVE-2026-84303 in google.golang.org/grpc v1.82.0 | Mittel | `Deployment/kube-system/coredns` |
| `78e600b8e1750db2` | CVE-2026-84303 in google.golang.org/grpc v1.82.1 | Mittel | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| `af9d9841ac55fd11` | CVE-2026-84303 in google.golang.org/grpc v1.82.1 | Mittel | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| `d2452bd6a0554f4f` | CVE-2026-84303 in google.golang.org/grpc v1.82.1 | Mittel | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| `fc1695cc6a843198` | CVE-2026-84303 in google.golang.org/grpc v1.81.0 | Mittel | `Pod/kube-system/etcd-kba-it-control-plane` |
| `21dc8ccc19c167b7` | CVE-2026-84384 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Mittel | `Pod/audit-demo/insecure` |
| `56095b1fa9547015` | CVE-2026-84446 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Mittel | `Pod/audit-demo/insecure` |
| `fab3d809d3a97d66` | CVE-2026-84447 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Mittel | `Pod/audit-demo/insecure` |
| `8ac2a6ac80208295` | CVE-2026-84448 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Mittel | `Pod/audit-demo/insecure` |
| `0f0bbf4288f9776e` | CVE-2026-84450 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Mittel | `Pod/audit-demo/insecure` |
| `021aa3a9618f1c34` | CVE-2026-84451 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Mittel | `Pod/audit-demo/insecure` |
| `df9bbdd453d04d7e` | CVE-2026-84784 in libssl3t64 3.5.7-1~deb13u2 | Mittel | `Pod/audit-demo/insecure` |
| `06c3cabd3a1f4d96` | CVE-2026-85091 in zlib1g 1:1.3.dfsg+really1.3.1-1+b1 | Mittel | `Pod/audit-demo/insecure` |
| `15dcc17c9e9c33fa` | CVE-2026-86137 in libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | Mittel | `Pod/audit-demo/insecure` |
| `5ff52bf9126f7abe` | CVE-2026-8674 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `82aa7e6e852c8ad5` | CVE-2026-8674 in libc-bin 2.41-12+deb13u4 | Mittel | `Pod/audit-demo/insecure` |
| `92c19d989135a6a9` | CVE-2026-8674 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `5cd702a97f4d53f5` | CVE-2026-86805 in libc-bin 2.41-12+deb13u4 | Mittel | `Pod/audit-demo/insecure` |
| `cdd6c2f1f588419c` | CVE-2026-86805 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `d8c0557e177de488` | CVE-2026-86805 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `8980a0f00f910d95` | CVE-2026-89092 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `c2319411b9ae7c9e` | CVE-2026-89092 in libc-bin 2.41-12+deb13u4 | Mittel | `Pod/audit-demo/insecure` |
| `e1746c8e651102d8` | CVE-2026-89092 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `1f02fcae47f8f619` | CVE-2026-89156 in libpcre2-8-0 10.42-1 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `7bae8340dc143de6` | CVE-2026-89156 in libpcre2-8-0 10.42-1 | Mittel | `DaemonSet/kube-system/kindnet` |
| `4cdb68df4f2b3443` | CVE-2026-89158 in libpcre2-8-0 10.42-1 | Mittel | `DaemonSet/kube-system/kindnet` |
| `577baa35d506d41a` | CVE-2026-89158 in libpcre2-8-0 10.42-1 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `0a8a59b7bb4e88f9` | CVE-2026-89160 in libpcre2-8-0 10.42-1 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `712b17e821c908ba` | CVE-2026-89160 in libpcre2-8-0 10.42-1 | Mittel | `DaemonSet/kube-system/kindnet` |
| `fd7125d40a178468` | CVE-2026-8924 in curl 8.14.1-2+deb13u5 | Mittel | `Pod/audit-demo/insecure` |
| `5b0d1bfaad64fb0a` | CVE-2026-8926 in curl 8.14.1-2+deb13u5 | Mittel | `Pod/audit-demo/insecure` |
| `af5d7333dacda646` | CVE-2026-8932 in curl 8.14.1-2+deb13u5 | Mittel | `Pod/audit-demo/insecure` |
| `b07ee9d3d385eb42` | CVE-2026-9079 in curl 8.14.1-2+deb13u5 | Mittel | `Pod/audit-demo/insecure` |
| `1babba3f3cff8af0` | CVE-2026-9080 in curl 8.14.1-2+deb13u5 | Mittel | `Pod/audit-demo/insecure` |
| `898fff40d85f102e` | CVE-2026-94283 in libx11-6 2:1.8.12-1 | Mittel | `Pod/audit-demo/insecure` |
| `374eeb4d7acccbd9` | CVE-2026-94284 in libx11-6 2:1.8.12-1 | Mittel | `Pod/audit-demo/insecure` |
| `a0c396fbb9f44e20` | CVE-2026-94285 in libx11-6 2:1.8.12-1 | Mittel | `Pod/audit-demo/insecure` |
| `940adf53e9fb7d77` | CVE-2026-94287 in libxpm4 1:3.5.17-1+deb13u1 | Mittel | `Pod/audit-demo/insecure` |
| `956eeb4726495c27` | CVE-2026-9545 in curl 8.14.1-2+deb13u5 | Mittel | `Pod/audit-demo/insecure` |
| `28188755f8cf8e4d` | CVE-2026-95818 in libc6 2.36-9+deb12u14 | Mittel | `DaemonSet/kube-system/kube-proxy` |
| `459a7207fa29a318` | CVE-2026-95818 in libc-bin 2.41-12+deb13u4 | Mittel | `Pod/audit-demo/insecure` |
| `5131c13e00e6e40c` | CVE-2026-95818 in libc6 2.36-9+deb12u13 | Mittel | `DaemonSet/kube-system/kindnet` |
| `d4aea8a471d6316e` | GHSA-gv9j-4w24-q7vx in github.com/coredns/coredns v0.0.0-20260710050435-424d125775cd | Mittel | `Deployment/kube-system/coredns` |
| `0b4e4dc8e05dfa10` | CVE-2005-2541 in tar 1.35+dfsg-3.1 | Niedrig | `Pod/audit-demo/insecure` |
| `1456dc9d0eda0260` | CVE-2007-5686 in login.defs 1:4.17.4-2 | Niedrig | `Pod/audit-demo/insecure` |
| `48cd057ebba39026` | CVE-2010-4756 in libc6 2.36-9+deb12u13 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `90fddd0c93969f33` | CVE-2010-4756 in libc-bin 2.41-12+deb13u4 | Niedrig | `Pod/audit-demo/insecure` |
| `d43e1856308750b3` | CVE-2010-4756 in libc6 2.36-9+deb12u14 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `9ee38c4d7b2915e0` | CVE-2011-3374 in apt 3.0.3 | Niedrig | `Pod/audit-demo/insecure` |
| `14b6ce563cd9bda0` | CVE-2011-3389 in libgnutls30t64 3.8.9-3+deb13u4 | Niedrig | `Pod/audit-demo/insecure` |
| `edcdec204d884d87` | CVE-2011-4116 in perl-base 5.40.1-6+deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `2b1548310935ab88` | CVE-2012-2663 in iptables 1.8.9-2 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `a47fbd5f76b53d36` | CVE-2012-2663 in iptables 1.8.9-2 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `547703987fc4f542` | CVE-2013-4392 in libsystemd0 257.13-1~deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `d707de888e3abedd` | CVE-2015-3276 in libldap2 2.6.10+dfsg-1 | Niedrig | `Pod/audit-demo/insecure` |
| `6cf0a66e48abf623` | CVE-2015-9019 in libxslt1.1 1.1.35-1.2+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `0d5b840f45b9ed87` | CVE-2016-2781 in coreutils 9.1-1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `5e6fd87a17c3d148` | CVE-2016-2781 in coreutils 9.1-1 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `6f599e8c69811e21` | CVE-2017-14159 in libldap2 2.6.10+dfsg-1 | Niedrig | `Pod/audit-demo/insecure` |
| `dbd2129bf37f650f` | CVE-2017-16232 in libtiff6 4.7.0-3+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `b60c5ee3072535d1` | CVE-2017-17740 in libldap2 2.6.10+dfsg-1 | Niedrig | `Pod/audit-demo/insecure` |
| `0c708225aa081cca` | CVE-2017-18018 in coreutils 9.7-3 | Niedrig | `Pod/audit-demo/insecure` |
| `6c5536eed2f666a6` | CVE-2017-18018 in coreutils 9.1-1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `bde552c8841356ee` | CVE-2017-18018 in coreutils 9.1-1 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `2e05e2ed07d4324a` | CVE-2017-9937 in libjbig0 2.1-6.1+b2 | Niedrig | `Pod/audit-demo/insecure` |
| `d0cc1b930557ccea` | CVE-2018-10126 in libtiff6 4.7.0-3+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `55b658423a039814` | CVE-2018-20796 in libc-bin 2.41-12+deb13u4 | Niedrig | `Pod/audit-demo/insecure` |
| `b48d66f35b5c259a` | CVE-2018-20796 in libc6 2.36-9+deb12u14 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `be9a9b50734abbd8` | CVE-2018-20796 in libc6 2.36-9+deb12u13 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `13b79c7152e12099` | CVE-2018-5709 in libgssapi-krb5-2 1.21.3-5+deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `4d57fdba3ea88f8a` | CVE-2018-6829 in libgcrypt20 1.11.0-7+deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `15cb62b539d140f7` | CVE-2019-1010022 in libc6 2.36-9+deb12u14 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `442217b2ee1e1097` | CVE-2019-1010022 in libc6 2.36-9+deb12u13 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `5c81aa4c9d582fb4` | CVE-2019-1010022 in libc-bin 2.41-12+deb13u4 | Niedrig | `Pod/audit-demo/insecure` |
| `16c712e557b6e65d` | CVE-2019-1010023 in libc-bin 2.41-12+deb13u4 | Niedrig | `Pod/audit-demo/insecure` |
| `1719eda09e90e5d7` | CVE-2019-1010023 in libc6 2.36-9+deb12u14 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `794be1a53645441e` | CVE-2019-1010023 in libc6 2.36-9+deb12u13 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `030430da1f249845` | CVE-2019-1010024 in libc6 2.36-9+deb12u13 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `2420f62d154a50d9` | CVE-2019-1010024 in libc-bin 2.41-12+deb13u4 | Niedrig | `Pod/audit-demo/insecure` |
| `726b8672dce71d42` | CVE-2019-1010024 in libc6 2.36-9+deb12u14 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `28b9ae9cf8b60e56` | CVE-2019-1010025 in libc6 2.36-9+deb12u14 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `c721a8abf30b37e8` | CVE-2019-1010025 in libc-bin 2.41-12+deb13u4 | Niedrig | `Pod/audit-demo/insecure` |
| `d751139ee1c6a172` | CVE-2019-1010025 in libc6 2.36-9+deb12u13 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `16c89c15229a14d2` | CVE-2019-9192 in libc-bin 2.41-12+deb13u4 | Niedrig | `Pod/audit-demo/insecure` |
| `1d4411f4eddce68f` | CVE-2019-9192 in libc6 2.36-9+deb12u13 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `e1bb18708c89ab25` | CVE-2019-9192 in libc6 2.36-9+deb12u14 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `2be88830221c4d42` | CVE-2020-15719 in libldap2 2.6.10+dfsg-1 | Niedrig | `Pod/audit-demo/insecure` |
| `af072d34dd39930c` | CVE-2021-4214 in libpng16-16t64 1.6.48-1+deb13u5 | Niedrig | `Pod/audit-demo/insecure` |
| `25184f70d517d85a` | CVE-2021-45346 in libsqlite3-0 3.46.1-7+deb13u2 | Niedrig | `Pod/audit-demo/insecure` |
| `a210a1181b41d8ef` | CVE-2022-0563 in bsdutils 1:2.41.5-0+deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `4b628b04993c2ceb` | CVE-2022-1210 in libtiff6 4.7.0-3+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `bf96368f7d83ba8a` | CVE-2023-31437 in libsystemd0 257.13-1~deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `087b8e6acf65f8e8` | CVE-2023-31438 in libsystemd0 257.13-1~deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `6fd8810a3fe4ecb6` | CVE-2023-31439 in libsystemd0 257.13-1~deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `d342d5c74741aed5` | CVE-2024-2236 in libgcrypt20 1.11.0-7+deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `ca1145fb437dc3ab` | CVE-2024-26458 in libgssapi-krb5-2 1.21.3-5+deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `095dac82a786544c` | CVE-2024-26461 in libgssapi-krb5-2 1.21.3-5+deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `766699ec5f1202bd` | CVE-2024-56433 in login.defs 1:4.17.4-2 | Niedrig | `Pod/audit-demo/insecure` |
| `15b673b5b863be22` | CVE-2024-7598 in k8s.io/apiserver v1.37.0 | Niedrig | `ControlPlaneComponents/kube-system/k8s.io/apiserver` |
| `259ea96214054d7c` | CVE-2025-10966 in curl 8.14.1-2+deb13u5 | Niedrig | `Pod/audit-demo/insecure` |
| `a4fab9c2ddc84957` | CVE-2025-11731 in libxslt1.1 1.1.35-1.2+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `3e83c567fb5e4da8` | CVE-2025-14017 in curl 8.14.1-2+deb13u5 | Niedrig | `Pod/audit-demo/insecure` |
| `25622de8393fcdf9` | CVE-2025-15079 in curl 8.14.1-2+deb13u5 | Niedrig | `Pod/audit-demo/insecure` |
| `920665790f30418e` | CVE-2025-15224 in curl 8.14.1-2+deb13u5 | Niedrig | `Pod/audit-demo/insecure` |
| `f6d2889557e119f6` | CVE-2025-15281 in libc6 2.36-9+deb12u13 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `099b2c708d64e3a1` | CVE-2025-27587 in libssl3 3.0.20-1~deb12u2 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `e52520f39c953f21` | CVE-2025-27587 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `5f231c280f8bd3a5` | CVE-2025-5278 in coreutils 9.1-1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `664f2fd4938e445b` | CVE-2025-5278 in coreutils 9.1-1 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `b7655a6df2db93b3` | CVE-2025-5278 in coreutils 9.7-3 | Niedrig | `Pod/audit-demo/insecure` |
| `c484aa680dc6f0e5` | CVE-2025-61143 in libtiff6 4.7.0-3+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `d57e533a7cc56527` | CVE-2025-61144 in libtiff6 4.7.0-3+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `83a8ce02b48800c1` | CVE-2025-61145 in libtiff6 4.7.0-3+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `e9d9c087be3f925d` | CVE-2025-6141 in libtinfo6 6.5+20250216-2 | Niedrig | `Pod/audit-demo/insecure` |
| `076bc8123be99321` | CVE-2025-68160 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `d58911246404623d` | CVE-2025-69418 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `875baa248941848c` | CVE-2025-69420 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `5f9ec02d4e7f13d4` | CVE-2025-70873 in libsqlite3-0 3.46.1-7+deb13u2 | Niedrig | `Pod/audit-demo/insecure` |
| `68c9103b72f29c91` | CVE-2025-8176 in libtiff6 4.7.0-3+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `4ca6ad656ebe25b6` | CVE-2025-8177 in libtiff6 4.7.0-3+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `854282d938f6a9ad` | CVE-2025-8534 in libtiff6 4.7.0-3+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `4ab42b4f1d79e036` | CVE-2026-0861 in libc6 2.36-9+deb12u13 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `0252eb29c4f1f538` | CVE-2026-102474 in dash 0.5.12-12 | Niedrig | `Pod/audit-demo/insecure` |
| `24b5600df515d91f` | CVE-2026-11850 in libgssapi-krb5-2 1.21.3-5+deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `0e412cc158e993a4` | CVE-2026-11979 in libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `0dd2ded5fc6015b0` | CVE-2026-13608 in curl 8.14.1-2+deb13u5 | Niedrig | `Pod/audit-demo/insecure` |
| `890e80e655282344` | CVE-2026-18924 in curl 8.14.1-2+deb13u5 | Niedrig | `Pod/audit-demo/insecure` |
| `888fd1117dea6b13` | CVE-2026-22185 in libldap2 2.6.10+dfsg-1 | Niedrig | `Pod/audit-demo/insecure` |
| `1b78b6def4aecc0b` | CVE-2026-22795 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `c705de0fa448dfe9` | CVE-2026-22796 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `e0553b2423799762` | CVE-2026-27139 in stdlib v1.25.6 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `6663b8d1f8cf9495` | CVE-2026-34180 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `addc8b70f7178c41` | CVE-2026-35189 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `cf3973269e470766` | CVE-2026-35189 in libssl3t64 3.5.7-1~deb13u2 | Niedrig | `Pod/audit-demo/insecure` |
| `f742cb9f104fd3c0` | CVE-2026-35189 in libssl3 3.0.20-1~deb12u2 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `2d7e11c11c056aa9` | CVE-2026-35191 in libssl3t64 3.5.7-1~deb13u2 | Niedrig | `Pod/audit-demo/insecure` |
| `e3e8e627b5bdce34` | CVE-2026-3713 in libpng16-16t64 1.6.48-1+deb13u5 | Niedrig | `Pod/audit-demo/insecure` |
| `557ef936b022afd4` | CVE-2026-3949 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `e1d485af27210f31` | CVE-2026-39824 in golang.org/x/sys v0.31.0 | Niedrig | `Deployment/local-path-storage/local-path-provisioner` |
| `b055de7f28188b49` | CVE-2026-40228 in libsystemd0 257.13-1~deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `5b86f999887cafff` | CVE-2026-42766 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `4aeb53b13a329d75` | CVE-2026-42767 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `e983974b28a9912e` | CVE-2026-42767 in libssl3 3.0.20-1~deb12u2 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `c8784f90a4480fbd` | CVE-2026-42770 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `80b73f255d44abdb` | CVE-2026-4438 in libc6 2.36-9+deb12u13 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `50bccaa8df707447` | CVE-2026-45446 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `943979ee793e64af` | CVE-2026-46675 in libpng16-16t64 1.6.48-1+deb13u5 | Niedrig | `Pod/audit-demo/insecure` |
| `232d61e0a53a8529` | CVE-2026-52491 in libtiff6 4.7.0-3+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `7faf58765f1fe4c1` | CVE-2026-52492 in libtiff6 4.7.0-3+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `ce33725d851aab75` | CVE-2026-53910 in diffutils 1:3.10-4 | Niedrig | `Pod/audit-demo/insecure` |
| `aadd926cfa983e0d` | CVE-2026-54874 in libssl3 3.0.20-1~deb12u2 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `f85f8810b9b0df51` | CVE-2026-54874 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `75ff55514cb3f3d6` | CVE-2026-56391 in coreutils 9.7-3 | Niedrig | `Pod/audit-demo/insecure` |
| `bc63c28a0b5688e9` | CVE-2026-56391 in coreutils 9.1-1 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `c9dcc9abf399462c` | CVE-2026-56391 in coreutils 9.1-1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `1831d611746a2fa7` | CVE-2026-56392 in coreutils 9.7-3 | Niedrig | `Pod/audit-demo/insecure` |
| `2c180b46f31a2e8b` | CVE-2026-56392 in coreutils 9.1-1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `af7517298348364c` | CVE-2026-56392 in coreutils 9.1-1 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `c01c620faacf7d07` | CVE-2026-63074 in libssl3 3.0.20-1~deb12u2 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `c092f7488619eb04` | CVE-2026-63074 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `dc51cbccd431c19d` | CVE-2026-7383 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `2c2b7d494e2a807e` | CVE-2026-75803 in libssl3 3.0.20-1~deb12u2 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `47aa1b962e13cdc7` | CVE-2026-75803 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `d10cbfb4524ba9cf` | CVE-2026-80230 in curl 8.14.1-2+deb13u5 | Niedrig | `Pod/audit-demo/insecure` |
| `242a1946f9a79c44` | CVE-2026-80255 in curl 8.14.1-2+deb13u5 | Niedrig | `Pod/audit-demo/insecure` |
| `22464f7e947215c8` | CVE-2026-81870 in go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.44.0 | Niedrig | `Pod/kube-system/kube-controller-manager-kba-it-control-plane` |
| `22678ca5e542cad3` | CVE-2026-81870 in go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.44.0 | Niedrig | `DaemonSet/kube-system/kube-proxy` |
| `2dcc53404bce11de` | CVE-2026-81870 in go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.44.0 | Niedrig | `Pod/kube-system/kube-apiserver-kba-it-control-plane` |
| `715933a1aa7925a7` | CVE-2026-81870 in go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.43.0 | Niedrig | `Pod/kube-system/etcd-kba-it-control-plane` |
| `ab0823bcf772bce2` | CVE-2026-81870 in go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.44.0 | Niedrig | `Pod/kube-system/kube-scheduler-kba-it-control-plane` |
| `2239248713db43e5` | CVE-2026-82208 in curl 8.14.1-2+deb13u5 | Niedrig | `Pod/audit-demo/insecure` |
| `17c3bb4446b1cd59` | CVE-2026-82209 in curl 8.14.1-2+deb13u5 | Niedrig | `Pod/audit-demo/insecure` |
| `7725bde7f6340457` | CVE-2026-82560 in perl-base 5.40.1-6+deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `dc722b7e0d2a900b` | CVE-2026-84444 in libheif-plugin-dav1d 1.19.8-1+deb13u1 | Niedrig | `Pod/audit-demo/insecure` |
| `38218a3d3a7f8a53` | CVE-2026-86141 in libxml2 2.12.7+dfsg+really2.9.14-2.1+deb13u3 | Niedrig | `Pod/audit-demo/insecure` |
| `f0a722441f8bbbf6` | CVE-2026-88373 in libde265-0 1.0.15-1+deb13u2 | Niedrig | `Pod/audit-demo/insecure` |
| `65475c9aefc1ca91` | CVE-2026-9076 in libssl3 3.0.18-1~deb12u1 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `2fa4a351b32a68dd` | CVE-2026-9547 in curl 8.14.1-2+deb13u5 | Niedrig | `Pod/audit-demo/insecure` |
| `0e7f61b8b70f5140` | CVE-2026-97399 in libc-bin 2.41-12+deb13u4 | Niedrig | `Pod/audit-demo/insecure` |
| `90dca58ed478085b` | CVE-2026-97399 in libc6 2.36-9+deb12u13 | Niedrig | `DaemonSet/kube-system/kindnet` |
| `d6fb2ba938d9ae34` | CVE-2026-97399 in libc6 2.36-9+deb12u14 | Niedrig | `DaemonSet/kube-system/kube-proxy` |

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
| `resources/clusterrolebindings.json` | `48943df817ca01e523b59db9f9cb9e259a555a9cee05131a30379a400c168678` |
| `resources/clusterroles.json` | `17d26531813adca002f4a7dcda0f34b6893a706eac5bd3a97703f3e3ccdecd81` |
| `resources/namespaces.json` | `072bfac7d5f8811501bbfac53a164931386ad9379b7a28ea7a00c3e4c37d9767` |
| `resources/networkpolicies.json` | `90fc342f098745bb50dfae4c6eda65e986fd5a807cf01abdf668d8dd03bca0d6` |
| `resources/nodes.json` | `a1c178101eb9e8ebae693afb9596c9f7cd314033d4d090d5ebb1d36547bd2651` |
| `resources/pods.json` | `2190ee22f45c2665405a1b9e10c0168ec2a30c248bfecb5fdb32490ff2980229` |
| `resources/rolebindings.json` | `e75edb972096eba417554a8daf7fa2e761ceed85c0f120078898808274089409` |
| `resources/roles.json` | `59668dba9b6cfd2d5c09f83980fab068141af30067af91bf8ba9a89745af488d` |
| `resources/secrets.json` | `be6311737871796085002f033ef2a4e871ad02b9247463c9ab51117e6fadadcb` |
| `resources/serviceaccounts.json` | `e2c56359b1a227c612cdf639d0a852c562541bdbc0bd0d2d69d98591c212e802` |
| `resources/version.json` | `c8e7ba1d3c9f9c541a44dbc1a213f795647b77eadf01f1c2bd0fd9a9a76439be` |
| `scanners/kubescape.json` | `b18f1d4a4a686a32bd48f1d986125fc95661ff21c537bba14c8dd1fd93f932e4` |
| `scanners/trivy.json` | `06e9fe93453cc5f9138fc180ad18d98ae415ac490e2a32d71c6bb6bb058dede9` |

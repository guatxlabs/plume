# SOC — Cahier des charges (vision complète, modulaire, multi-hôte)

> Étend `ARCHITECTURE.md` (design v1).
> Ici = la **liste de souhaits / spec cible** : tout ce qui peut être **construit si nécessaire**
> pour faire du SOC un outil **modulaire, scalable, offensif+défensif, multi-plateforme**, sans
> jamais réduire la surface de défense. Inspiré de **Splunk ES, Wazuh, Microsoft Defender XDR,
> CrowdSec, Elastic, Sigma/YARA, Atomic Red Team** — adapté aux contraintes (Rust+SQLite+Svelte,
> host-natif, <100 Mo de base, localhost least-priv, tout query-driven & rejouable).

## 0. Principes directeurs
1. **Modulaire** : chaque capacité = un module (collecteur / détecteur / responder / viz) **activable
   par hôte** via `soc.conf`. Cœur minimal ; on n'active que le nécessaire (un VPS ≠ un laptop).
2. **Observe ≠ enforce** : le SOC **détecte + répond**, mais l'**enforcement existant reste** (règle
   d'or, cf. §2). La « réponse » délègue aux bloqueurs en place (CrowdSec/fail2ban/nft).
3. **Léger par défaut, riche à la demande.** 4. **Tout query-driven** (panels = requêtes).
5. **Tout rejouable** (git + bootstrap). 6. **Le SOC ne doit pas être un trou** (least-priv,
   intégrité, RBAC, localhost/tunnel).

---

## 1. GARANTIE « zéro trou » — le MÉCANISME (réponse directe)

> La roadmap **seule** ne garantit rien. Ce qui garantit = des **mécanismes vérifiables** :

1. **Control Catalog (inventaire de contrôles)** — table déclarative de TOUT ce qui doit exister
   (chaque défense : nom, type `enforce|detect`, hôte, source attendue, « preuve de vie »). Le SOC
   **vérifie en continu** que chaque contrôle est **présent ET vivant** → **alerte si un manque**
   (jail fail2ban down, bouncer absent, règle nft de contrôle disparue, capteur muet). C'est ÇA
   qui prouve qu'« aucun composant ne manque » — pas une promesse, une vérif automatique.
2. **Cartographie MITRE ATT&CK** — chaque détection mappée à une technique → **dashboard de
   couverture** qui montre les **techniques NON couvertes** = les trous sont **visibles**, mesurés.
3. **Go/no-go de parité** (cf. §2) — on ne **retire/remplace** un composant qu'après preuve
   que l'équivalent existe (donnée dans le SOC + alerte + enforcement inchangé).
4. **Baseline + diff partout** — tout écart (port, SUID, unit, règle nft, hash fichier) = alerte →
   pas de dérive silencieuse.
5. **Auto-surveillance** — heartbeat de chaque collecteur ; intégrité de la chaîne du SOC
   (hash-chain + checkpoints Ed25519) ; « capteur muet » = alerte.
6. **BAS (preuve active)** — exécuter des techniques ATT&CK connues (sandbox) et **vérifier que le
   SOC les détecte** → preuve *active* de non-trou (pas seulement déclarative).

---

## 2. Cohabitation avec une stack existante : GARDER / REMPLACER

Plume n'arrive **jamais** en remplaçant tout : il s'ajoute, prouve la parité, puis vous décidez. La
règle de classement, applicable à **n'importe quelle** stack en place :

| Classe | Ce qui va dedans | Raison |
|---|---|---|
| **REMPLAÇABLE par Plume** | visualisation / dashboards, recherche de logs, presets de métriques, relais de collecte redondants | Plume est un **sur-ensemble** de ces fonctions (search SQL+FTS, dashboards query-driven, single-pane) |
| **GARDÉ — JAMAIS touché (enforcement)** | tout ce qui **bloque** : pare-feu hôte, bans/bouncers, IdP, NetworkPolicies, admission, gestionnaire de secrets | **Plume observe, il ne remplace pas l'enforcement** (cf. §0.2) |
| **GARDÉ (en parallèle)** | l'alerting d'exploitation (disponibilité, capacité) | alerting infra ≠ détection sécurité : complémentaires |
| **DÉCOMMISSIONNÉ (seulement après parité prouvée)** | un serveur dont Plume couvre désormais la fonction | go/no-go de parité, cf. §1.3 — jamais avant |

Méthode : **additif d'abord** → run en parallèle → vérif de parité → retrait. Voir
[`deploy/OBS.md`](deploy/OBS.md) pour la procédure concrète côté métriques/logs.

---

## 3. CAHIER DES CHARGES FONCTIONNEL

### 3.1 Collecte / ingestion (multi-source, multi-plateforme)
- **Linux/host** : journald, auditd, syslog, fichiers (tail), nft, `ss`, `/proc`, systemd units, packages/CVE.
- **Conteneurs/k8s** : docker events + API, **k8s audit log**, runtime, syscall (falco-style, option), Trivy (images).
- **Windows** : agent ETW + **Sysmon** + Windows Event Log (EVTX) + journaux Defender/ASR.
- **Réseau** : NetFlow/conntrack, Suricata/Zeek `eve.json` (option), logs DNS.
- **Stack existante (ingestion, pas re-collecte)** : décisions d'un IPS/CTI (ex. CrowdSec), agrégateur de logs déjà en place (requête bornée), métriques Prometheus, snapshot nft.
- **Agents** : rôles `standalone|agent|central` (ARCHITECTURE §13), **adaptatifs** (skip sources absentes), config-gated, ship signé (Ed25519) via WireGuard.
- **Normalisation ECS-like** : schéma commun `ts/host/source/category/severity/fields/mitre` (interop).

### 3.2 Stockage & rétention
- SQLite WAL+FTS5 (base) ; partition temporelle ; **downsample** métriques ; rétention configurable ;
  `VACUUM` ; **cap disque + alerte**. Option scale : store colonnaire (DuckDB/Parquet) pour gros volumes.

### 3.3 Recherche & langage de requête (« un SPL en Rust, > PromQL »)
- Moteur = **SQL read-only validé** (ARCHITECTURE §7) + **FTS5**.
- **DSL pipe unifié « GXQL »** (style SPL) compilé en SQL : `search source=sshd "failed" | stats count by user | where count>5 | sort -count`. **UN seul langage pour logs + métriques + events** (vs PromQL=métriques only, LogQL=logs only) = l'avantage clé.
- Fonctions : `stats/agg` (count/sum/avg/percentile/rate), `group by`, **bucket temporel**, joins (FTS+relationnel), `eval`, **lookup** (enrichissement IOC/CTI/geo/asn), regex extract, subsearch, `timechart`, `top`, `transaction` (corrélation par session).
- **Autocomplétion / aides** : lister sources, champs, valeurs dispo (le besoin « voir les jobs/labels »).
- **Coût par requête** (demandé) : profiler chaque requête — **rows scanned, CPU, RAM, + timings
  parse→exec→fetch→render→réseau** — afficher le coût + **budget/timeout/kill** (anti-requête-folle).
- **Requêtes** : sauvegardées, **planifiées** (saved search → alerte/panel), historique, **temps réel** (SSE → « voir les requêtes en live »).

### 3.4 Dashboards (création/édition/sauvegarde faciles, temps réel, exemples)
- **Tout query-driven** (panel = requête + viz ; tables `dashboard`/`panel` déjà au schéma).
- **Viz** : table, stat (single value), **timechart**, bar, top, heatmap, gauge, **geo-map** (IP),
  **graph** (relations process/host/IP), Sankey (flux).
- **Éditeur facile** : ajouter/réorganiser/redimensionner panneaux ; **variables & filtres globaux**
  (time range, host) ; **drill-down** (clic → requête filtrée) ; **éditer & sauvegarder** un dashboard.
- **Temps réel** : SSE/auto-refresh réglable.
- **Dashboards exemples livrés** (built-in, tous **éditables**) : Overview/posture · **ATT&CK coverage** ·
  Auth timeline · Firewall (+ intégrité contrôle) · CVE · Conteneurs · Réseau/IDS · Ressources ·
  Intégrité/FIM · Persistance.
- **Export/import** dashboards (JSON) → partage & migration.

### 3.5 Détection (règles, corrélation, MITRE, ML léger)
- Règles **déclaratives TOML** : requête+seuil · diff baseline · **séquence/corrélation** (multi-events, fenêtre).
- **Sigma** import/conversion → moteur (build-time, coût runtime nul).
- **YARA** scan fichiers/mémoire (IOC/malware/samples).
- **MITRE ATT&CK** mapping par règle + couverture (cf §1.2).
- **Risk-Based Alerting** (façon Splunk) : score de risque cumulé par host/user → alerte au seuil
  (réduit le bruit, priorise).
- **UEBA léger** : baselines comportementales (volume auth, process/horaires habituels) + anomalie
  (z-score/IQR — pas de ML lourd).
- **CTI / threat intel** : feeds (CrowdSec CAPI, **MISP**, blocklists, AbuseIPDB, Tor exit) → enrichissement
  auto (IP → réputation/geo/ASN) + match IOC. Dé-dup, suppression/whitelist, tuning.

### 3.6 Réponse (SOAR-lite / XDR — « détection + réponse »)
- **Playbooks déclaratifs** (TOML) : alerte → actions **auto ou semi-auto** (approbation).
- **Actions** : ban IP (**délègue** à CrowdSec/fail2ban/nft = l'enforcement existant) · isoler un host ·
  kill process · quarantine fichier (YARA) · désactiver compte · snapshot forensic · notifier (dunst/ntfy/webhook).
- **AIR** (automated investigation, façon Defender) : sur alerte, collecter le contexte (process tree,
  connexions, fichiers, user) → **dossier d'enquête** auto.
- **Live response** (façon Defender) : shell distant **borné + audité + RBAC admin + allowlist** sur un
  agent (forensic/remediation). ⚠️ opt-in, jamais arbitraire (sinon = trou de sécu).
- **Case management** (TheHive-like léger) : alertes → cases (assignation, statut, timeline, notes, IOC liés).
- Métriques SOC : **MTTD / MTTR**, faux positifs, couverture.

### 3.7 Offensif (auto-évaluation de SA PROPRE infra)
- **ASM (Attack Surface Management)** : scan de sa propre infra (ports exposés, services, certs, DNS,
  sous-domaines) → inventaire d'exposition + dérive (« qu'est-ce qu'un attaquant voit »).
- **Vuln** : arch-audit (host) · **Trivy** (images/conteneurs) · scan réseau léger borné (nmap-like) · CVE→exploitabilité.
- **BAS (Breach & Attack Simulation)** léger, **Atomic Red Team-style** : rejouer des techniques ATT&CK
  sandboxées → **vérifier que le SOC détecte** (= preuve de couverture, §1.6).
- **Garde-fou** : offensif **uniquement sur sa propre infra**, opt-in, **jamais** de mass-scan externe.

### 3.8 Posture / conformité
- **SCA/CIS** (Lynis + CIS benchmarks, façon Wazuh) → score + dérive · hardening (sysctl/cmdline/lockdown)
  · **FIM/AIDE** · inventaire système (packages/users/services/SUID) + diff · score de posture global.

---

## 4. CAHIER DES CHARGES NON-FONCTIONNEL

| Exigence | Mécanisme cible |
|---|---|
| **Modulaire** | tout = module activable par `soc.conf` (par hôte) ; cœur <100 Mo ; (futur) registre de modules |
| **Scalable & HA** | rôles standalone/agent/central → **cluster de centraux** (sharding par host) ; file d'ingestion bufferisée (disque) + backpressure ; failover |
| **Répliqué** | réplication DB (litestream/SQLite-replication → MinIO/S3) ; central secondaire |
| **Backup intégré** | snapshot SQLite + WAL → MinIO/S3/local, **chiffré, planifié**, le SOC **se backup + alerte si échec** |
| **Export facile** | events/dashboards/règles → JSON/CSV/Parquet ; API d'export |
| **Migration** | dump+restore ; **schema migrations** (`meta.schema_version`) ; upgrade `git pull→build→bootstrap` + rollback |
| **Install/deploy facile** | **1 binaire musl statique** ; `bootstrap.sh` idempotent ; packages deb/rpm/pacman(AUR) ; **conteneur OCI** ; **chart Helm (k3s/k8s)** ; one-liner signé ; Windows MSI+service |
| **Replica facile** | clone + `soc.conf` (rôle) → nouvel hôte en 1 commande |
| **Multi-plateforme** | Linux(systemd) · Windows(service/ETW/Sysmon) · macOS(option) · Docker(sidecar/socket) · **k3s/k8s (DaemonSet agent + /ingest)** ; collecteurs auto-détectent la plateforme |
| **Sécurité du SOC** | web non-root · DB read-only API · SQL read-only validé · bind loopback/tunnel · **RBAC** (viewer/editor/admin) · auth basic_auth→OIDC · **intégrité hash-chain + checkpoints Ed25519** · **toute action de réponse auditée** · secrets 0600 hors repo · agents signés |
| **Perf** | <100 Mo base · limites systemd (`MemoryMax`/`CPUQuota`) · timers (pas de polling) · rétention/downsample · FTS efficace |
| **a11y / UX** | WCAG AA (ARCHITECTURE §8/§14) · dense/rapide · sévérité = icône+texte · clavier · `prefers-*` |
| **Maintenance** | git · migrations · tests smoke · auto-monitoring · config unique · doc |

---

## 5. Inspiration → ce qu'on reprend (feature mapping)

| Outil | Ce qu'on reprend |
|---|---|
| **Splunk ES** | SPL (→ DSL GXQL), correlation searches, **risk-based alerting**, UEBA, data models, **detection versioning/rollback**, dashboards, SOAR workflow |
| **Wazuh** | **FIM**, **SCA/CIS**, **vuln detection (CVE)**, **active response**, **MITRE mapping**, system inventory, agent multi-OS |
| **Defender XDR** | **EDR** (télémétrie comportementale), **AIR** (investigation auto), **advanced hunting** (langage de requête), **live response**, **attack disruption/containment** |
| **CrowdSec** | scénarios, **bouncers** (enforcement délégué), **CAPI/CTI** communautaire |
| **Elastic SIEM** | detection rules, **timelines**, cases |
| **TheHive+Cortex** | case management, analyzers/responders |
| **MISP** | plateforme CTI / IOC |
| **Sigma / YARA / OSQuery / Velociraptor** | règles vendor-neutral / scan fichiers / requête endpoint / DFIR à distance |
| **Atomic Red Team / Caldera** | **BAS** (preuve de couverture) |

---

## 6. Priorisation (MoSCoW) & phases

- **MUST (cœur SOC, un hôte Linux couvert de bout en bout)** : collecte journald/auditd/nft + ingestion
  des sources déjà en place (P5) · search SQL+FTS + DSL GXQL (P3) · dashboards query-driven + exemples
  (P3) · règles+alertes+MITRE (P3/P4) · **Control Catalog auto-audit (§1)** · backup intégré · agent
  distant (P7).
- **SHOULD** : YARA/AIDE/SUID-persistance (P4) · RBA + UEBA léger · playbooks réponse (délégués) · case
  management · export/import · Sigma (P8) · multi-plateforme Linux+Docker+k8s.
- **COULD** : Windows/Sysmon · BAS/Atomic · ASM/exposure · live response · cluster de centraux/HA ·
  store colonnaire · macOS.
- **Phases** : le socle (P0→P8) puis **P9 Réponse/SOAR-lite**, **P10 Offensif/BAS/ASM**,
  **P11 Windows/multi-OS**. Chaque module respecte §0 (modulaire, observe≠enforce) et §1 (anti-trou).

---

### Sources d'inspiration (features étudiées)
- Splunk Enterprise Security (correlation searches, RBA, UEBA, SOAR, detection versioning).
- Wazuh (FIM, SCA/CIS, vuln detection, active response, MITRE mapping, inventory).
- Microsoft Defender XDR (EDR, automated investigation & response, advanced hunting KQL, live response, attack disruption).

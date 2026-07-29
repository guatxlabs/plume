# Plume — Catalogue de détection curé (starter pack)

> **Statut : contenu additif, vendor-agnostic, inerte par défaut.** Ce catalogue livre une
> BIBLIOTHÈQUE de règles de détection haute-valeur, mappées CIM + ATT&CK, sous
> [`config.d/rules/catalog/*.json`](../config.d/rules/catalog). Chargées au boot par le loader
> d'overlays (`daemon/src/overlays.rs`) avec `managed=1` (source git), MÊME validation
> « compile-ou-ignore » que toute règle overlay. Elles complètent — sans dupliquer — les règles
> SEEDÉES actives (`daemon/src/seeds.rs`) et les overlays racine (`config.d/rules/*.json`).

## Principe & politique enabled/disabled

- **35 règles LIVRÉES** (`ls config.d/rules/catalog/ | wc -l` = 35), dont **34 décrites** dans les tables
  ci-dessous (noms tous distincts). La règle livrée non décrite ici est `de-auditd-silent.json`
  (« Hôte : auditd muet — dead-man's-switch anti-forensics », T1562.001). Elles citent
  **26 techniques** ATT&CK distinctes qui retombent sur **13 tactiques** (mappées via
  `guatx_core::attack::CATALOG` ; aucune technique non mappée).
- **TOUTES `enabled=false` par défaut.** C'est une BIBLIOTHÈQUE : l'admin ACTIVE chaque règle
  selon la télémétrie réellement branchée, via le toggle UI (aucune règle ne se met à alerter
  sur une install fraîche ⇒ zéro bruit day-0). Le socle « universellement présent + faible FP »
  est DÉJÀ activé par la couche seed ; le catalogue est l'étendue opt-in.
- **Toutes en GXQL** (`is_soql=true`) ⇒ compilées par le compilateur FERMÉ (injection-safe par
  construction ; jamais de SQL brut). Une règle qui ne compile pas est DROPPÉE au boot ⇒ un test
  (`catalog_rules_all_compile_and_are_disabled_by_default`) exige que les 34 compilent et chargent.
- **CIM-exact** : chaque règle ne référence que des `source`/`category`/`fields.*` réellement
  émis par les collecteurs (voir [`docs/CIM.md`](CIM.md)). NB le port de destination des
  collecteurs natifs (conntrack/ufw/portscan) est `dport` (chaîne), pas `dst_port`.
- **Chaque règle porte un tag `mitre`** ⇒ la matrice de couverture ATT&CK s'allume dès activation.

### Recommandations « activer en premier » (faible FP, forte valeur)
- `Catalogue — Persistance: clé SSH ajoutée à authorized_keys` (T1098.004) — télémétrie native
  (integrity), quasi-zéro FP hors provisioning.
- `Catalogue — K8s: accès API anonyme / non-authentifié` (T1078) — si audit k8s présent, ~0 FP.
- `Catalogue — IDS: signature Suricata déclenchée (haute sévérité)` (T1190) — si Suricata présent.

### Signaux nécessitant une télémétrie NON universellement présente (note honnête)
- **Kubernetes** (`kube-audit`/`kube-rbac`) : 6 règles — inertes hors cluster k8s avec audit activé.
- **Endpoint FIM BYO-agent** (`category=integrity fim_event=*`) : 2 règles ransomware/wipe —
  nécessitent un agent Wazuh/osquery branché (distinct du FIM natif hôte `kind`/`change`).
- **MinIO audit relay** (`minio-audit`) : 3 règles — nécessitent le relais d'audit S3.
- **Suricata / Falco** : n'émettent pas de champs structurés (signal via `category`+`severity`).
- **Mail / Vault** : opt-in selon la stack déployée.
- **Impossible-travel géo** : NON livré (aucune source ne fournit de géo/ASN au CIM à ce jour) —
  gap documenté, à ouvrir quand un enrichissement géo existera.

## Index — règle → tactique → technique → télémétrie → activée par défaut


### Reconnaissance (TA0043)

| Règle | ATT&CK | Sév | Télémétrie requise | Activée |
|-------|--------|:---:|--------------------|:-------:|
| Exploit web: motif d'injection/traversal dans l'URL (origine) | `T1190` | 3 | web (path) | non |
| Recon web: forced-browsing (403-breadth par IP) | `T1595.003` | 2 | web (action, status, path) | non |
| Recon: scanner web identifié par User-Agent (sqlmap/nikto/nuclei) | `T1595.002` | 2 | web (ua) | non |

### Credential Access (TA0006)

| Règle | ATT&CK | Sév | Télémétrie requise | Activée |
|-------|--------|:---:|--------------------|:-------:|
| Brute-force auth mail (SMTP/IMAP/POP) | `T1110` | 3 | mail (collecteur mail : category=auth action=failure, src_ip promu) | non |
| Brute-force distribué (nombreuses IP sources sur l'auth) | `T1110` | 2 | toute source d'auth (category=auth : journal/auditd/mail — CIM neutre) | non |
| Brute-force sur login web (401 par IP) | `T1110` | 3 | web (reverse-proxy/app : category=web, champ status) | non |
| Password spray (comptes distincts échoués depuis une IP) | `T1110.003` | 3 | auditd (audit PAM/auth : famille de records category=auth, champ acct + addr promu src_ip) | non |
| Persistance: clé SSH ajoutée à authorized_keys (intégrité) | `T1098.004` | 4 | integrity (FIM natif hôte : kind, change — collecteur par défaut) | non |
| Vault: moisson de secrets (volume élevé par identité) | `T1552.001` | 3 | vault-audit (audit device Vault : operation, path, user) | non |

### Discovery (TA0007)

| Règle | ATT&CK | Sév | Télémétrie requise | Activée |
|-------|--------|:---:|--------------------|:-------:|
| Balayage réseau interne (une source touche de nombreux hôtes) | `T1046` | 3 | conntrack (flux : scope, dir, dst_ip — parc MULTI-HÔTES) | non |
| K8s: rafale d'accès refusés (énumération API) | `T1069` | 3 | kube-audit (audit Kubernetes : action=forbidden, user) | non |
| K8s: énumération de secrets (list massif) | `T1552.007` | 3 | kube-audit (resource, verb) | non |
| Objet-store: rafale d'AccessDenied (recon de buckets) | `T1526` | 2 | minio-audit (relay audit S3 : status, accessKey) | non |

### Lateral Movement (TA0008)

| Règle | ATT&CK | Sév | Télémétrie requise | Activée |
|-------|--------|:---:|--------------------|:-------:|
| Latéralisation SSH interne (une source -> plusieurs hôtes en 22) | `T1021.004` | 3 | conntrack (scope, dir, dport, dst_ip) | non |

### Priv-Esc / Persistence (TA0004/TA0003)

| Règle | ATT&CK | Sév | Télémétrie requise | Activée |
|-------|--------|:---:|--------------------|:-------:|
| Hôte: compte local créé/modifié (useradd/usermod) | `T1136.001` | 3 | auditd (records category=account : useradd/usermod/passwd) | non |
| Hôte: nouveau binaire SUID déposé (intégrité) | `T1548.001` | 4 | integrity (FIM natif : kind=suid, change=ajout) | non |
| K8s: (Cluster)RoleBinding créé (octroi de droits RBAC) | `T1098` | 3 | kube-audit (resource, verb) | non |
| K8s: ServiceAccount lié à cluster-admin (clés du royaume) | `T1098` | 4 | kube-rbac (snapshot RBAC : role, kind, subject) | non |

### Defense Evasion (TA0005)

| Règle | ATT&CK | Sév | Télémétrie requise | Activée |
|-------|--------|:---:|--------------------|:-------:|
| Hôte: tentative de désactivation de l'audit (auditctl) | `T1562.001` | 4 | auditd (records category=exec : exe) | non |
| SOC: modification du contenu de détection (règle créée/éditée/désactivée) | `T1562.001` | 2 | plume self (auto-audit : source=plume-config, action=config.rule.*) | non |

### Execution (TA0002)

| Règle | ATT&CK | Sév | Télémétrie requise | Activée |
|-------|--------|:---:|--------------------|:-------:|
| Hôte: exécution depuis un répertoire monde-inscriptible (/tmp) | `T1059.004` | 3 | auditd (records category=exec : exe) | non |
| IDS: signature Suricata déclenchée (haute sévérité) | `T1190` | 3 | suricata (IDS : category=alert, severity) | non |
| Runtime: activité suspecte Falco (eBPF, sév≥3) | `T1059` | 3 | falco (eBPF : category=ebpf, severity) | non |
| Webshell probable (POST -> script .php renvoyant 200) | `T1505.003` | 3 | web (method, status, path) | non |

### Collection (TA0009)

| Règle | ATT&CK | Sév | Télémétrie requise | Activée |
|-------|--------|:---:|--------------------|:-------:|
| Hôte: accès répété aux secrets/identifiants (dataaccess) | `T1552.001` | 3 | dataaccess (watch fichiers sensibles : key, action, user) | non |

### Exfiltration (TA0010)

| Règle | ATT&CK | Sév | Télémétrie requise | Activée |
|-------|--------|:---:|--------------------|:-------:|
| Exfiltration/spam: envoi sortant de masse depuis une identité | `T1048` | 2 | mail (category=mailflow, sender) | non |
| Objet-store: lecture de masse (exfiltration probable) | `T1530` | 3 | minio-audit (api, accessKey) | non |
| Égress: éventail vers de nombreuses IP externes (hors infra) | `T1071` | 2 | conntrack (dir, scope, proc, dst_ip) | non |

### Impact (TA0040)

| Règle | ATT&CK | Sév | Télémétrie requise | Activée |
|-------|--------|:---:|--------------------|:-------:|
| Destruction: suppression de masse de fichiers (FIM endpoint) | `T1485` | 4 | endpoint FIM (category=integrity, fim_event, agent_name) | non |
| K8s: suppression de masse de ressources | `T1485` | 3 | kube-audit (verb, action, user) | non |
| Ransomware: modification de masse de fichiers (FIM endpoint) | `T1486` | 4 | endpoint FIM (agent BYO : category=integrity, fim_event, agent_name) | non |
| Vague d'attaques: rafale de bannissements (fail2ban/CrowdSec) | `T1595` | 2 | bans (fail2ban/crowdsec : category=ban, src_ip promu) | non |

### Cloud / Container (TA0001/TA0004)

| Règle | ATT&CK | Sév | Télémétrie requise | Activée |
|-------|--------|:---:|--------------------|:-------:|
| K8s: accès API anonyme / non-authentifié | `T1078` | 3 | kube-audit (user) | non |
| Objet-store: bucket exposé publiquement | `T1530` | 3 | minio (snapshot policy : kind=bucket, risk=public) | non |

## Couverture ATT&CK ajoutée

Techniques nouvellement couvertes / renforcées par le catalogue : `T1021.004`, `T1046`, `T1048`, `T1059`, `T1059.004`, `T1069`, `T1071`, `T1078`, `T1098`, `T1098.004`, `T1110`, `T1110.003`, `T1136.001`, `T1190`, `T1485`, `T1486`, `T1505.003`, `T1526`, `T1530`, `T1548.001`, `T1552.001`, `T1552.007`, `T1562.001`, `T1595`, `T1595.002`, `T1595.003`.

Ces tags rejoignent la jointure de couverture (`/api/coverage/detections`) : dès qu'une règle
catalogue est activée, sa technique passe de *missed* à *detected* dans la matrice.

Deux précisions sur ce que la matrice compte, côté consommateur (la boucle purple de Forge) :

- **La technique du tag est celle qui compte, sous-technique comprise.** Activer une règle taguée de
  la technique **parente** (`T1110`) ne fait PAS passer une **sous-technique** tirée (`T1110.001`) en
  *detected* : elle est classée `detected-parent-approx` — un angle mort **nommé**, exclu du taux de
  détection et du MTTD. Une règle parente générique ne prouve pas la couverture d'un vecteur
  particulier : les trois règles `T1110` de ce catalogue sont bornées au mail (`source=mail`), bornées
  au web (`source=web status=401`), ou exigent une dispersion d'IP (`stats dc(src_ip)`) — aucune de ces
  trois n'attrape un brute-force SSH mono-source. D'autres règles `T1110` **seedées** le pourraient
  selon la télémétrie branchée : c'est justement ce que la jointure ne peut pas savoir depuis un tag,
  et pourquoi elle nomme le doute au lieu de le trancher. Pour faire passer une sous-technique au vert,
  taguez une règle **de cette sous-technique**.
- **Un tag peut porter PLUSIEURS techniques** (`"T1595.002 T1046"`, séparateurs espace/virgule/
  point-virgule — la norme SigmaHQ). L'endpoint les **éclate** : une entrée par technique, counts
  sommés, `first_ts` = la première détection. La chaîne composée n'est jamais servie telle quelle.

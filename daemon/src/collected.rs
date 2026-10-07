//! collected — INVENTAIRE DE CE QUE PLUME COLLECTE RÉELLEMENT (oracle d'inertie).
//!
//! POURQUOI CE MODULE EXISTE — SÉPARATION DE DEUX RÔLES QUI ÉTAIENT CONFONDUS.
//!
//! Deux questions DIFFÉRENTES se posent quand on importe une règle tierce (Sigma) :
//!   1. TRADUCTION — « ce nom de champ Sigma correspond à quel champ plume ? »  -> `sigma::SIGMA_FIELD_ALIAS`
//!   2. INERTIE    — « plume collecte-t-il réellement cette donnée ? »          -> CE MODULE
//!
//! Tant que les deux partagent la MÊME table, TOUT élargissement de la traduction MENT sur l'inertie :
//! `sigma_field_is_inert_extended()` commençait par `if SIGMA_FIELD_ALIAS.iter().any(..) { return false; }`,
//! si bien qu'AJOUTER UN ALIAS ÉTEIGNAIT MÉCANIQUEMENT l'avertissement d'inertie — sans qu'une seule donnée
//! nouvelle ne soit collectée. C'est du FAUX VERT : on croirait avoir gagné des détections actives, on
//! n'aurait gagné que du silence. L'oracle d'inertie se fonde DONC ici sur ce que les COLLECTEURS et l'AGENT
//! LIVRÉS écrivent réellement dans `fields.<X>`, jamais sur l'existence d'un alias.
//!
//! UN INVENTAIRE INCOMPLET MENT AUSSI — PAR BRUIT. Le sens « sûr » (sur-avertir) n'est PAS gratuit : un champ
//! réellement émis mais absent de l'inventaire produit un avertissement d'inertie FAUX. La première version
//! de ce module en comptait 52 (dont `pid`, `process`, `country`, `bucket`, `record_id` — parmi les noms
//! Sigma les plus courants). Cause MESURÉE : sa surface d'extraction ne voyait que les objets `fields` à
//! clés QUOTÉES (le JSON échappé du shell/awk) et les overlays de parseurs ; le `jq` à clés NUES de
//! `cloudflare.sh`, le `json!` de l'agent, le `.py` de MinIO et le `.ps1` Windows lui échappaient tous —
//! prouvé par mutation (ajouter un champ à chacun laissait la garde VERTE). Un avertissement auquel personne
//! ne croit ne vaut rien : la COUVERTURE de l'extraction est donc de PREMIER ordre, pas un raffinement.
//! (L'inventaire passe ainsi de 97 à 149 entrées, sans qu'un seul collecteur change : c'est la MESURE qui
//! change, pas la collecte.)
//!
//! REPRÉSENTATION — une table `(champ, fichier livré qui l'émet)`. Chaque entrée est CITÉE, et la citation
//! est VÉRIFIÉE MÉCANIQUEMENT par la garde `collected_inventory_is_backed_by_shipped_collectors`
//! (tests/detection.rs), qui contrôle les DEUX sens AVEC LE MÊME EXTRACTEUR :
//!
//!   (A) AUCUNE ENTRÉE FANTÔME — le champ doit être EXTRAIT du fichier cité, c'est-à-dire y apparaître en
//!       POSITION DE PRODUCTEUR (P1..P6 ci-dessous). Une occurrence quelconque du nom NE SUFFIT PAS : la
//!       version précédente se contentait d'une SOUS-CHAÎNE, et `("RequestPath", "web.sh")` passait au vert
//!       alors que `web.sh` ne fait que LIRE cette clé Traefik (`sval("RequestPath")`) et n'émet que
//!       `fields.path` — un faux vert re-fabricable en UNE LIGNE.
//!   (B) AUCUNE DÉRIVE SILENCIEUSE — tout champ que l'extracteur ramène d'un collecteur livré doit figurer
//!       ici, sinon la garde ROUGIT. Un collecteur qui se met à émettre un champ force son inventaire.
//!
//! MISE À JOUR QUAND UN COLLECTEUR CHANGE — c'est mécanique, pas une convention :
//!   * un collecteur commence à émettre `fields.<X>` -> la garde (B) rougit tant que `<X>` n'est pas ajouté ;
//!   * un collecteur cesse d'émettre `<X>` (ou le fichier cité disparaît) -> la garde (A) rougit tant que
//!     l'entrée n'est pas retirée -> l'avertissement d'inertie REVIENT pour les règles qui en dépendaient.
//!
//! SURFACE D'EXTRACTION — FAMILLES BALAYÉES (une par forme de collecteur réellement LIVRÉE ; le nombre
//! d'extractions de CHACUNE est planchonné par la garde, pour qu'en perdre une entière ROUGISSE) :
//!   `collectors/*.sh` · `collectors/*.py` · `collectors/windows/*.ps1` · `agent/src/source/*.rs` ·
//!   `agent/src/source/fim/*.rs` · `config.d/parsers/*.json`.
//! POSITIONS DE PRODUCTEUR RECONNUES :
//!   P1. objet LITTÉRAL `fields` (clés de PROFONDEUR 1 uniquement), quelle qu'en soit la syntaxe :
//!       `\"fields\":{…}` et `fields="{…}"` (JSON échappé de shell/awk), `fields: {…}` (jq, clés NON
//!       quotées), `fields = serde_json::json!({…})` (agent), `fields = {…}` (python), `@{ … }` /
//!       `-Fields @{ … }` (hashtable PowerShell, clés nues séparées par `;`).
//!   P2. insertion par CLÉ LITTÉRALE dans le sac : `…insert("X".into()|"X".to_string(), Value::…)` (Rust),
//!       `fields["X"] =` (python).
//!   P3. overlays de parseurs livrés : clés de `map.fields` + groupes nommés `(?P<x>…)` de `pattern` + les
//!       clés de tête de `map` que `dparsers_apply` écrit aussi dans le sac (`action` ; `src_ip`/`dst_ip`/`url`
//!       sont des colonnes cœur).
//!   P4. ajouteur de champ awk `af("X", v)` — UNIQUEMENT dans un fichier qui DÉFINIT `function af(` (c'est
//!       le cas d'`auditd.sh`) ; ailleurs, `f("X")` reste un appel quelconque, pas un producteur.
//!   P5. fragment d'objet JSON échappé `",\"X\":\"` (ou `{\"X\":\"` en tête) concaténé dans le sac (awk : le `ext` de `mail.sh`, le
//!       `fj` de `pod-logs.sh`) — UNIQUEMENT dans un `.sh` qui contient par ailleurs un objet `fields`.
//!       Une clé située AVANT l'ouverture `\"events\":[` de sa ligne est une clé d'ENVELOPPE, pas un champ.
//!   P6. 3e argument LITTÉRAL de `$(heartbeat <source> <message> {…})` (`.sh`) : `lib.sh` l'écrit tel quel
//!       sous `"fields":`, clés de profondeur 1, valeurs NUMÉRIQUES comprises (`active_bans`, `alive`…).
//! Les fichiers `.rs` sont tronqués à leur premier `#[cfg(test)]` EN COLONNE 0 : les fixtures de test ne
//! sont pas de la collecte livrée.
//!
//! CE QUE L'EXTRACTION NE VOIT PAS (mesuré, pas estimé) — chaque cas produit un SUR-AVERTISSEMENT :
//!   * la recopie VERBATIM des clés `EventData` du log Windows (`source/windows.rs`, `m.insert(name, …)`)
//!     et les champs des sources DÉCLARATIVES `[[source]]` (`source/generic.rs`) : surfaces OUVERTES,
//!     définies au DÉPLOIEMENT, donc non inventoriables statiquement ;
//!   * dans un fragment P5, une clé à valeur NON-string (`\"X\":123`, `\"X\":{`) — hors 3e argument de
//!     `heartbeat`, vu par P6. Mesuré au `P11.19-a` sur `collectors/*.sh` : les autres clés non-string sont
//!     des enveloppes `metrics`/`controls`/`firewall`, des clés LUES, ou imbriquées
//!     (`enforcement.nft_blocked_total`) — aucune n'est un champ d'événement. Pour l'oracle d'inertie c'est
//!     un SUR-avertissement ; pour la liste servie par `GET /api/sources`, ce serait une liste INCOMPLÈTE :
//!     c'est pourquoi P6 existe. CE QUI ÉTAIT FAUX (vague D) : cette limite nommait aussi « la PREMIÈRE clé
//!     d'un fragment », mais la mesure n'avait porté que sur les clés non-string ; `ns`, première clé du
//!     `fj` de pod-logs.sh, manquait à la liste servie de `k8s-log`. P5 accepte désormais l'accolade en tête,
//!     et le témoin `un_sac_assigne_a_une_variable_est_servi_en_entier` relit ces sacs SANS l'extracteur ;
//!   * les overlays `config.d/parsers/*.json` ajoutés par l'exploitant APRÈS déploiement (seuls les
//!     overlays LIVRÉS sont balayés).
//!
//! CE QUE LA GARDE (A) GARANTIT — ET SA LIMITE EXACTE. Fabriquer un faux vert ne se fait plus en ajoutant
//! une ligne d'inventaire : il faut que l'extracteur DÉRIVE le nom du fichier cité.
//!
//! DEUX CORRECTIONS D'AFFIRMATION, mesurées par une revue adverse, à ne pas reperdre :
//!   * « P1..P3 sont des positions STRUCTURELLES » était FAUX. P1 est une regex sur les octets : une ligne
//!     `# … le sac fields = {"X":"…"} reste TODO` dans un collecteur LIVRÉ suffisait à dériver `X`
//!     (mesuré, `bash -n` inchangé). L'extracteur DÉPOUILLE désormais les lignes dont le premier caractère
//!     non blanc ouvre un commentaire (`#`, `//`). Reste hors de portée, et c'est écrit plutôt qu'affirmé
//!     fermé : un commentaire de FIN de ligne après du code réel (distinguer un `#` d'un `#` dans une
//!     chaîne demanderait un vrai analyseur par langage).
//!   * P3 acceptait un overlay de parseur QUE L'INGESTION NE CHARGE JAMAIS. `parsers.rs` ne lit que
//!     `WHERE enabled=1`, et `load_overlay_dparsers` rejette un overlay sans `name` : un
//!     `{"enabled":false,"map":{"fields":{…}}}` déposé en config, plus une ligne d'inventaire, éteignait
//!     l'avertissement en gardant la garde VERTE (mesuré). L'extracteur exige maintenant qu'un overlay
//!     soit CHARGEABLE (`enabled != false` ET `name` non vide) pour valoir preuve.
//!
//! ÉCART SÉMANTIQUE QUI SUBSISTE, ET QU'AUCUN FILTRE NE FERME. Cet oracle répond à « un fichier LIVRÉ
//! déclare-t-il ce champ ? », pas à « la source qui l'alimente est-elle effectivement branchée ? ». Un
//! overlay de parseur livré et activé vaut preuve même si aucun collecteur ne produit sa source : c'est le
//! cas de `vendor` (example-cim-firewall), `fim_actor` (example-endpoint-fim), `cf_country`/`cf_rule`/
//! `cf_ua` (feed Cloudflare) et `signal` (nft forwardé) — des gabarits que l'exploitant doit alimenter.
//! Pour ces champs, l'absence d'avertissement signifie « plume SAIT parser cette donnée », pas « plume la
//! reçoit ». À traiter comme un signal INDICATIF, jamais comme une garantie de couverture.
//!
//! Ce n'est donc PAS infalsifiable : forger un faux vert exige désormais de modifier un fichier de
//! COLLECTE livré (visible en revue), et non plus d'ajouter une ligne d'inventaire.
//! Symétriquement, une SUR-extraction (un nom dérivé qui n'est pas un champ) pousserait à inventorier un
//! non-champ, donc à éteindre un avertissement à tort : c'est pourquoi la surface est syntaxiquement
//! ÉTROITE (profondeur 1, valeur string exigée en P5, `af` conditionné à sa définition).
//!
//! PÉRIMÈTRE — ce module répond pour les CHAMPS ÉTENDUS (`fields.<X>`). Les colonnes CŒUR du CIM
//! (`CIM_CORE_FIELDS`) sont l'enveloppe de tout event et sont traitées par `plume_collects_field`. L'oracle
//! de CATÉGORIE (l'avertissement `category=endpoint`) n'est PAS traité ici : il ne consulte pas la table
//! d'alias, ce n'est donc pas le rôle confondu qu'on sépare, et l'inventorier mécaniquement n'a pas été
//! mesuré. NON MESURÉ = non affirmé.

use guatx_core::cim::CIM_CORE_FIELDS;

/// Champs ÉTENDUS (`fields.<X>`) que les collecteurs/parseurs/agent LIVRÉS écrivent réellement, chacun avec
/// le FICHIER LIVRÉ qui l'émet — UN COUPLE PAR (champ, fichier) ÉMETTEUR, pas une citation par champ.
///
/// `P11.19-a` (reste 2, moitié démon) — CE QUI ÉTAIT FAUX. La table ne portait qu'UNE citation par champ
/// (169 entrées) : `action` n'y était imputé qu'à `bans.sh`, alors que quinze fichiers livrés l'émettent ;
/// `web.sh` n'y portait que 3 de ses 18 champs, `cloudflare-http.sh` aucun des 7 siens. Suffisant pour
/// l'oracle d'inertie (qui ne demande que « quelqu'un l'émet-il ? »), FAUX dès qu'on lit la table PAR
/// FICHIER — ce que font l'en-tête `# plume-emits:` des capteurs et l'inventaire `/api/sources`. Mesuré :
/// 133 couples émis manquaient. Elle porte désormais TOUS les couples que l'extracteur dérive (hors
/// colonnes cœur du CIM), et la complétude AU GRAIN DU COUPLE est tenue par
/// `champs_etendus_servis_par_source.rs` (la garde de `detection.rs` ne la tient qu'au grain du champ).
/// Lue par fichier, la table a aussi révélé une SUR-extraction que la lecture par champ masquait : le
/// fragment P5 prenait la clé d'ENVELOPPE de spool (`\"kind\":\"events\"`) pour un champ, et quatre
/// couples `kind` (web.sh, mail.sh, dataaccess.sh, dataacl.sh) ne correspondaient à aucun `fields.kind`
/// écrit. Retirés (298 couples) ; l'extracteur écarte désormais la clé qui PRÉCÈDE l'enveloppe sur sa ligne.
/// Lue comme liste CLOSE par source, elle était aussi INCOMPLÈTE : les champs NUMÉRIQUES du 3e argument
/// de `heartbeat` (`active_bans`, `alive` ×3, `hits_seen`, `scans_seen`, `blocks_seen`, `rules_allow`)
/// n'étaient dérivés par aucune position — `fail2ban` était servi sans `active_bans`. Position P6 ajoutée,
/// 8 couples (306), tenus aussi par un oracle qui relit les appels `heartbeat` sans l'extracteur.
/// Vague D, deux sous-extractions de plus, mesurées par une revue adverse : la PREMIÈRE clé d'un fragment
/// P5 (`ns` du sac de pod-logs.sh) et la clé `map.action` des overlays (que `dparsers_apply` écrit dans le
/// sac comme `map.fields`) — `k8s-log` était servi sans `ns`, `nft` et `firewall` sans `action`. 6 couples
/// (312), chacun tenu par un oracle qui relit le texte livré sans l'extracteur.
///
/// La citation est un SUFFIXE de chemin qui doit désigner UN SEUL fichier de la
/// surface balayée (`mod.rs`/`windows.rs`/`linux.rs` existent en double -> `fim/mod.rs`, `source/windows.rs`).
/// La casse est SIGNIFICATIVE : `json_extract` est sensible à la casse, un `fields.Action` ne serait pas
/// peuplé par un collecteur qui écrit `action`.
/// CETTE TABLE N'EST PAS TENUE À LA MAIN — elle est le MIROIR de ce que l'extracteur ramène : y ajouter une
/// entrée qu'il ne dérive PAS du fichier cité fait ROUGIR la garde (sens A) ; en retirer une qu'il dérive la
/// fait rougir aussi (sens B). On ne « pense pas à » la mettre à jour, le test l'exige.
pub(crate) const COLLECTED_EXTENDED_FIELDS: &[(&str, &str)] = &[
    ("access", "minio.sh"),
    ("accessKey", "minio-audit-relay.py"),
    ("acct", "auditd.sh"),
    ("action", "auditd.sh"),
    ("action", "bans.sh"),
    ("action", "cloudflare-firewall-events.json"),
    ("action", "cloudflare.sh"),
    ("action", "crowdsec.sh"),
    ("action", "dataaccess.sh"),
    ("action", "example-cim-firewall.json"),
    ("action", "example-csv-firewall.json"),
    ("action", "example-endpoint-fim.json"),
    ("action", "fim/mod.rs"),
    ("action", "kube-audit.sh"),
    ("action", "mail.sh"),
    ("action", "nft-scan-detect.json"),
    ("action", "origin-drop.sh"),
    ("action", "plume-collector.ps1"),
    ("action", "portprobe.sh"),
    ("action", "portscan.sh"),
    ("action", "source/windows.rs"),
    ("action", "ufw.sh"),
    ("action", "web.sh"),
    ("active_bans", "bans.sh"),
    ("addr", "auditd.sh"),
    ("agent_ready", "crowdsec.sh"),
    ("alive", "dataaccess.sh"),
    ("alive", "integrity.sh"),
    ("alive", "journal.sh"),
    ("api", "minio-audit-relay.py"),
    ("app", "plume-collector.ps1"),
    ("asn", "cloudflare.sh"),
    ("atype", "auditd.sh"),
    ("audit_rules_loaded", "auditd.sh"),
    ("auid", "auditd.sh"),
    ("auid", "dataaccess.sh"),
    ("backend", "fim/mod.rs"),
    ("binding", "kube-rbac.sh"),
    ("blocks_seen", "ufw.sh"),
    ("bucket", "minio-audit-relay.py"),
    ("buckets", "minio.sh"),
    ("bytes", "example-nginx.json"),
    ("bytes", "web.sh"),
    ("carve_out", "auditd.sh"),
    ("cause", "conntrack.sh"),
    ("census_capped", "plume-collector.ps1"),
    ("census_seen", "plume-collector.ps1"),
    ("cf_action", "cloudflare.sh"),
    ("cf_country", "cloudflare-firewall-events.json"),
    ("cf_rule", "cloudflare-firewall-events.json"),
    ("cf_source", "cloudflare-firewall-events.json"),
    ("cf_source", "cloudflare.sh"),
    ("cf_ua", "cloudflare-firewall-events.json"),
    ("change", "fim/mod.rs"),
    ("change", "integrity.sh"),
    ("channel", "plume-collector.ps1"),
    ("channel", "source/windows.rs"),
    ("cmdline_absent", "plume-collector.ps1"),
    ("cmdline_present", "plume-collector.ps1"),
    ("code", "kube-audit.sh"),
    ("collect_status", "lib.sh"),
    ("collect_status", "plume-collector.ps1"),
    ("collected_ids", "plume-collector.ps1"),
    ("collector", "auditd.sh"),
    ("collector", "conntrack.sh"),
    ("collector", "lib.sh"),
    ("collector", "mail.sh"),
    ("collector", "minio-audit-relay.py"),
    ("collector", "nft.sh"),
    ("collector", "plume-collector.ps1"),
    ("collector", "pod-logs.sh"),
    ("collector", "portscan.sh"),
    ("collector", "web.sh"),
    ("comm", "auditd.sh"),
    ("comm", "dataaccess.sh"),
    ("container", "pod-logs.sh"),
    ("count", "cloudflare-http.sh"),
    ("count", "conntrack.sh"),
    ("country", "cloudflare.sh"),
    ("decision", "kube-audit.sh"),
    ("desired", "engagement-adapter.sh"),
    ("detail", "lib.sh"),
    ("detail", "plume-collector.ps1"),
    ("detector", "origin-drop.sh"),
    ("detector", "portprobe.sh"),
    ("detector", "portscan.sh"),
    ("dir", "cloudflare-http.sh"),
    ("dir", "cloudflare.sh"),
    ("dir", "conntrack.sh"),
    ("dir", "origin-drop.sh"),
    ("dir", "portprobe.sh"),
    ("dir", "portscan.sh"),
    ("dir", "ufw.sh"),
    ("dir", "web.sh"),
    ("direction", "plume-collector.ps1"),
    ("dport", "conntrack.sh"),
    ("dport", "example-cim-firewall.json"),
    ("dport", "origin-drop.sh"),
    ("dport", "portscan.sh"),
    ("dport", "ufw.sh"),
    ("dst_host", "conntrack.sh"),
    ("dst_port", "example-csv-firewall.json"),
    ("dst_port", "nft-scan-detect.json"),
    ("dst_port", "plume-collector.ps1"),
    ("dur_ms", "web.sh"),
    ("enabled", "plume-collector.ps1"),
    ("enforcement", "nft.sh"),
    ("ensured", "engagement-adapter.sh"),
    ("event_id", "plume-collector.ps1"),
    ("event_id", "source/windows.rs"),
    ("exe", "auditd.sh"),
    ("exec_drop_dropped_this_run", "auditd.sh"),
    ("exec_drop_list_effective", "auditd.sh"),
    ("exec_drop_list_tier1", "auditd.sh"),
    ("exec_drop_list_tier2_recon", "auditd.sh"),
    ("exec_rule_b32", "auditd.sh"),
    ("exec_rule_b64", "auditd.sh"),
    ("failcount", "engagement-adapter.sh"),
    ("family", "origin-drop.sh"),
    ("family", "portscan.sh"),
    ("file", "yara.sh"),
    ("files_scanned", "pod-logs.sh"),
    ("filters", "auditd.sh"),
    ("filters", "conntrack.sh"),
    ("filters", "mail.sh"),
    ("filters", "minio-audit-relay.py"),
    ("filters", "pod-logs.sh"),
    ("filters", "web.sh"),
    ("fim_actor", "example-endpoint-fim.json"),
    ("fim_change", "fim/mod.rs"),
    ("fim_coverage", "fim/mod.rs"),
    ("fim_event", "example-endpoint-fim.json"),
    ("fim_event", "fim/mod.rs"),
    ("fim_gid", "fim/mod.rs"),
    ("fim_mode", "example-endpoint-fim.json"),
    ("fim_mode", "fim/mod.rs"),
    ("fim_mode_octal", "fim/mod.rs"),
    ("fim_path", "example-endpoint-fim.json"),
    ("fim_path", "fim/mod.rs"),
    ("fim_sha256", "example-endpoint-fim.json"),
    ("fim_sha256", "fim/mod.rs"),
    ("fim_sha256_before", "fim/mod.rs"),
    ("fim_size", "fim/mod.rs"),
    ("fim_size_before", "fim/mod.rs"),
    ("fim_uid", "fim/mod.rs"),
    ("flags", "dataacl.sh"),
    ("gap", "plume-collector.ps1"),
    ("group", "dataacl.sh"),
    ("hits_seen", "origin-drop.sh"),
    ("http", "engagement-adapter.sh"),
    ("inbound", "plume-collector.ps1"),
    ("key", "auditd.sh"),
    ("key", "dataaccess.sh"),
    ("kind", "integrity.sh"),
    ("kind", "kube-rbac.sh"),
    ("kind", "minio.sh"),
    ("lapi_ok", "crowdsec.sh"),
    ("last_alert_age_s", "crowdsec.sh"),
    ("level", "plume-collector.ps1"),
    ("level", "source/windows.rs"),
    ("lines_scanned", "pod-logs.sh"),
    ("local_port", "plume-collector.ps1"),
    ("max", "portscan.sh"),
    ("messageType", "macos.rs"),
    ("method", "cloudflare-http.sh"),
    ("method", "cloudflare.sh"),
    ("method", "example-nginx.json"),
    ("method", "web.sh"),
    ("mode", "dataacl.sh"),
    ("mode", "engagement-adapter.sh"),
    ("name", "kube-audit.sh"),
    ("nft_fail", "engagement-adapter.sh"),
    ("note", "auditd.sh"),
    ("note", "conntrack.sh"),
    ("note", "mail.sh"),
    ("note", "minio-audit-relay.py"),
    ("note", "nft.sh"),
    ("note", "pod-logs.sh"),
    ("note", "portscan.sh"),
    ("note", "web.sh"),
    ("ns", "kube-audit.sh"),
    ("ns", "kube-rbac.sh"),
    ("ns", "pod-logs.sh"),
    ("object", "minio-audit-relay.py"),
    ("objects", "minio.sh"),
    ("os", "plume-collector.ps1"),
    ("os_category", "macos.rs"),
    ("outbound", "plume-collector.ps1"),
    ("owner", "dataacl.sh"),
    ("path", "auditd.sh"),
    ("path", "cloudflare-firewall-events.json"),
    ("path", "cloudflare-http.sh"),
    ("path", "cloudflare.sh"),
    ("path", "dataaccess.sh"),
    ("path", "dataacl.sh"),
    ("path", "example-nginx.json"),
    ("path", "fim/mod.rs"),
    ("path", "integrity.sh"),
    ("path", "web.sh"),
    ("pid", "macos.rs"),
    ("pid", "plume-collector.ps1"),
    ("pid", "source/linux.rs"),
    ("pod", "pod-logs.sh"),
    ("policy", "minio.sh"),
    ("proc", "conntrack.sh"),
    ("proc_verdict", "conntrack.sh"),
    ("process", "macos.rs"),
    ("process", "plume-collector.ps1"),
    ("profile", "plume-collector.ps1"),
    ("proto", "conntrack.sh"),
    ("proto", "example-cim-firewall.json"),
    ("proto", "example-csv-firewall.json"),
    ("proto", "nft-scan-detect.json"),
    ("proto", "origin-drop.sh"),
    ("proto", "portscan.sh"),
    ("proto", "ufw.sh"),
    ("proto", "web.sh"),
    ("protocol", "plume-collector.ps1"),
    ("provider", "plume-collector.ps1"),
    ("provider", "source/windows.rs"),
    ("ray", "cloudflare.sh"),
    ("rcpt", "mail.sh"),
    ("reason", "lib.sh"),
    ("reason", "plume-collector.ps1"),
    ("record_id", "plume-collector.ps1"),
    ("refused", "engagement-adapter.sh"),
    ("remote_port", "plume-collector.ps1"),
    ("removed", "engagement-adapter.sh"),
    ("request_id", "minio-audit-relay.py"),
    ("res", "auditd.sh"),
    ("resource", "kube-audit.sh"),
    ("risk", "dataacl.sh"),
    ("risk", "kube-rbac.sh"),
    ("risk", "minio.sh"),
    ("role", "kube-rbac.sh"),
    ("router", "web.sh"),
    ("rule", "yara.sh"),
    ("ruleId", "cloudflare.sh"),
    ("rules_allow", "ufw.sh"),
    ("scans_seen", "portscan.sh"),
    ("scenarios_broken", "crowdsec.sh"),
    ("scenarios_loaded", "crowdsec.sh"),
    ("scope", "cloudflare-http.sh"),
    ("scope", "cloudflare.sh"),
    ("scope", "conntrack.sh"),
    ("scope", "fim/mod.rs"),
    ("scope", "integrity.sh"),
    ("scope", "kube-rbac.sh"),
    ("scope", "portprobe.sh"),
    ("scope", "web.sh"),
    ("score", "mail.sh"),
    ("sender", "mail.sh"),
    ("service", "mail.sh"),
    ("set", "portprobe.sh"),
    ("sev3_shipped", "pod-logs.sh"),
    ("sha256", "fim/mod.rs"),
    ("sha256", "integrity.sh"),
    ("sha256", "yara.sh"),
    ("signal", "nft-scan-detect.json"),
    ("size", "mail.sh"),
    ("skew", "engagement-adapter.sh"),
    ("sport", "origin-drop.sh"),
    ("src_port", "plume-collector.ps1"),
    ("state", "conntrack.sh"),
    ("state", "plume-collector.ps1"),
    ("status", "cloudflare-http.sh"),
    ("status", "example-nginx.json"),
    ("status", "minio-audit-relay.py"),
    ("status", "minio.sh"),
    ("status", "web.sh"),
    ("statusCode", "minio-audit-relay.py"),
    ("subject", "kube-rbac.sh"),
    ("subject", "minio.sh"),
    ("subsystem", "macos.rs"),
    ("success", "auditd.sh"),
    ("syscall", "auditd.sh"),
    ("tags", "yara.sh"),
    ("truncated", "mail.sh"),
    ("type", "auditd.sh"),
    ("type", "conntrack.sh"),
    ("type", "dataacl.sh"),
    ("type", "lib.sh"),
    ("type", "mail.sh"),
    ("type", "minio-audit-relay.py"),
    ("type", "nft.sh"),
    ("type", "plume-collector.ps1"),
    ("type", "pod-logs.sh"),
    ("type", "portscan.sh"),
    ("type", "web.sh"),
    ("ua", "cloudflare.sh"),
    ("ua", "web.sh"),
    ("uid", "auditd.sh"),
    ("uid", "source/linux.rs"),
    ("uncollected_events", "plume-collector.ps1"),
    ("uncollected_ids", "plume-collector.ps1"),
    ("unit", "integrity.sh"),
    ("unit_dirs_from", "integrity.sh"),
    ("unit_form", "integrity.sh"),
    ("user", "dataaccess.sh"),
    ("user", "kube-audit.sh"),
    ("user", "mail.sh"),
    ("user_agent", "minio-audit-relay.py"),
    ("vendor", "example-cim-firewall.json"),
    ("verb", "kube-audit.sh"),
    ("verdict", "mail.sh"),
    ("version_delete", "minio-audit-relay.py"),
    ("versions", "minio.sh"),
    ("vhost", "cloudflare-firewall-events.json"),
    ("vhost", "cloudflare-http.sh"),
    ("vhost", "cloudflare.sh"),
    ("vhost", "web.sh"),
    ("virus", "mail.sh"),
];

/// Plume peuple-t-il réellement ce champ plume ? = colonne CŒUR du CIM (enveloppe de TOUT event, toujours
/// présente) OU champ étendu inventorié ci-dessus. C'est L'ORACLE D'INERTIE — il ne consulte AUCUNE table
/// de traduction : ajouter un alias Sigma ne peut donc PLUS éteindre un avertissement d'inertie.
pub(crate) fn plume_collects_field(name: &str) -> bool {
    CIM_CORE_FIELDS.contains(&name) || COLLECTED_EXTENDED_FIELDS.iter().any(|(f, _)| *f == name)
}

/// SURFACE BALAYÉE par l'extracteur qui tient `COLLECTED_EXTENDED_FIELDS` : `(répertoire, extension)`.
/// MIROIR de `COLLECTED_SCAN_SURFACE` (tests de détection), tenu dans les DEUX sens par
/// `champs_etendus_servis_par_source.rs` — pas une liste libre. Elle dit OÙ l'absence de couple VAUT
/// « ce fichier n'écrit aucun champ étendu » : hors de cette surface, l'absence ne prouve rien.
pub(crate) const COLLECTED_SCAN_DIRS: &[(&str, &str)] = &[
    ("collectors", "sh"),
    ("collectors", "py"),
    ("collectors/windows", "ps1"),
    ("agent/src/source", "rs"),
    ("agent/src/source/fim", "rs"),
    ("config.d/parsers", "json"),
];

/// Une citation (suffixe de chemin) désigne-t-elle ce fichier ? Même règle que la garde de l'inventaire :
/// égalité ou suffixe AU SÉPARATEUR près (`cloudflare.sh` ne désigne pas `cloudflare-http.sh`).
pub(crate) fn citation_designe(fichier: &str, citation: &str) -> bool {
    fichier == citation || fichier.strip_suffix(citation).is_some_and(|p| p.ends_with('/'))
}

/// Le fichier est-il dans la surface balayée ? (le `tests.rs` en est exclu, comme par l'extracteur)
pub(crate) fn fichier_dans_la_surface(fichier: &str) -> bool {
    let Some((dir, base)) = fichier.rsplit_once('/') else { return false };
    let Some((_, ext)) = base.rsplit_once('.') else { return false };
    base != "tests.rs" && COLLECTED_SCAN_DIRS.iter().any(|(d, e)| *d == dir && *e == ext)
}

/// LES COUPLES DE L'AUTORITÉ, seule porte de lecture de la jointure et de ses témoins.
pub(crate) fn couples_etendus() -> Vec<(&'static str, &'static str)> {
    COLLECTED_EXTENDED_FIELDS.to_vec()
}

/// `P11.19-a` — LE CANAL D'AVEU COMMUN. `lib.sh::plume_report_availability` (et les aides qui y mènent :
/// `plume_unavailable`, `plume_lecture_echouee`, `plume_lecture_partielle`, `plume_reglage_illisible`,
/// `plume_collecte_tronquee`, `plume_adresse_illisible`, `plume_mesures_avouer`, `plume_disabled`) écrit
/// les couples cités `lib.sh` SOUS LA SOURCE PASSÉE EN PREMIER ARGUMENT. Ces sources sont celles qu'un
/// capteur livré nomme LITTÉRALEMENT en premier argument d'une de ces aides (un argument variable,
/// `"$SOURCE"` de custom.sh, n'est pas résoluble et n'est pas imputé). MIROIR tenu dans les deux sens par
/// `champs_etendus_servis_par_source.rs` contre le texte des capteurs ; pas une liste libre.
/// Sans cette table, `clamav` était servi `[]` (« aucun champ établi ») alors que ses aveux portent
/// `type`, `collector`, `collect_status`, `reason` et `detail`.
pub(crate) const FICHIER_DU_CANAL_D_AVEU: &str = "collectors/lib.sh";
pub(crate) const SOURCES_DU_CANAL_D_AVEU: &[&str] = &[
    "auditd", "clamav", "cloudflare", "cloudflare-http", "conntrack", "containerd", "controls", "crowdsec",
    "custom", "dataaccess", "fail2ban", "falco", "firewall", "integrity", "journal", "k8s", "k8s-log",
    "kube-audit", "kube-rbac", "mail", "minio", "nft", "origin-drop", "portprobe", "portscan", "prom-scrape",
    "resources", "ship", "suricata", "ufw", "update", "vuln", "web", "yara",
];

/// `P11.19-a` — LA SOURCE À LAQUELLE S'APPLIQUE CHAQUE OVERLAY DE PARSEUR LIVRÉ (`"source"` du JSON) : ses
/// champs (`map.fields`, `map.action`, groupes nommés du `pattern`) sont écrits sur les événements de CETTE source à
/// l'ingestion. MIROIR des overlays chargeables de `config.d/parsers/` (source non joker), tenu dans les
/// deux sens par `champs_etendus_servis_par_source.rs`. Sans elle, les champs de `nft-scan-detect.json`
/// (`"source": "nft"`) étaient rangés « sans source livrée » alors que la source `nft` est servie.
pub(crate) const SOURCE_DES_OVERLAYS: &[(&str, &str)] = &[
    ("config.d/parsers/cloudflare-firewall-events.json", "cloudflare"),
    ("config.d/parsers/example-cim-firewall.json", "firewall"),
    ("config.d/parsers/example-csv-firewall.json", "csv-firewall"),
    ("config.d/parsers/example-endpoint-fim.json", "fim-agent"),
    ("config.d/parsers/example-nginx.json", "nginx"),
    ("config.d/parsers/nft-scan-detect.json", "nft"),
];

-- Plume — schéma SQLite (v1). Appliqué par l'ingester au démarrage.
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
INSERT OR IGNORE INTO meta(key,value) VALUES ('schema_version','1');
-- v73 (HOTFIX SÉCU L2) — compteur de RÉVOCATION de session. Mélangé au HMAC des jetons (mint/verify_session) :
-- /api/logout et un changement de mot de passe l'INCRÉMENTENT -> tous les cookies antérieurs deviennent
-- invalides côté serveur (un cookie exfiltré ne survit plus au logout). MIROIR de la migration v73
-- (INSERT OR IGNORE) : base neuve (ici) et existante CONVERGENT. DEFAULT '0' -> INERTE tant qu'aucun bump.
INSERT OR IGNORE INTO meta(key,value) VALUES ('session_epoch','0');
-- NB : schema_version démarre à '1' ; migrate() (daemon) applique séquentiellement v2..v67 sur base neuve
-- comme existante -> CONVERGENCE. Les tables DÉRIVÉES event_rollup (v30/v33) et event_dim_rollup (v44),
-- ainsi que leur colonne `env_id` (#2d/v67 : FILTRE par environnement cohérent sur les agrégats), sont
-- posées PAR migrate() (pas ici) : reconstructibles, jamais dans schema.sql.

-- v66 (#2a-2a) — AXE ENVIRONNEMENT intra-tenant : `env_id TEXT NOT NULL DEFAULT 'prod'` sur les tables
-- de DONNÉE client scopables par environnement (event/alert/metric/snapshot ici ; action/incident/
-- incident_item/banned_ip via ALTER en migrate() v66). MIROIR de la migration v66 : une base neuve
-- (schema.sql) et une base existante (ALTER) CONVERGENT. INERTE en mode 0 (colonne posée, jamais lue ;
-- le routing par env est #2a-2b/#2d). Le contenu de détection / config UI (rule/parser/playbook/
-- dashboard/view/panel/lookup_*) n'est PAS env-scopé (tenant-wide par nature, D7).
-- Évènements de sécurité normalisés (logs)
CREATE TABLE IF NOT EXISTS event(
  id       INTEGER PRIMARY KEY,
  ts       INTEGER NOT NULL,                 -- epoch s
  source   TEXT NOT NULL,                    -- sshd, sudo, auditd, suricata, firewall...
  category TEXT,                             -- auth, exec, integrity, network...
  severity INTEGER NOT NULL DEFAULT 0,       -- 0 info | 1 low | 2 medium | 3 high | 4 critical
  host     TEXT,
  message  TEXT,
  fields   TEXT,                             -- JSON (champs parsés)
  dedup    TEXT UNIQUE,                      -- clé anti-doublon (optionnelle)
  env_id   TEXT NOT NULL DEFAULT 'prod',     -- v66 : environnement intra-tenant (#2a-2a), INERTE en mode 0
  -- v72 (HOTFIX SÉCU vague 2) — ORIGINE de l'event. Posé à 'daemon' UNIQUEMENT quand le daemon écrit LUI-MÊME
  -- un event de CONTRÔLE (audit_config_change / marqueurs operator-access / tenant-admin / auth). Un event
  -- INGÉRÉ (agent/collecteur, via ingest_once/journal/loki) porte origin='' -> il ne peut PAS (M1/M4) se
  -- faire passer pour une ligne de contrôle non-purgeable : retention_run n'exclut de la purge QUE
  -- (origin='daemon' AND source IN ('plume-config','plume-operator-access','plume-tenant-admin')). MIROIR de
  -- la migration v72 (ALTER guardé par col_exists) : base neuve (ici) et base existante CONVERGENT. DEFAULT
  -- '' -> lignes existantes inchangées ; INERTE en mode 0 (colonne posée, lue seulement par la purge).
  origin   TEXT NOT NULL DEFAULT '',
  -- v75 (MODE ENGAGEMENT AUTORISÉ) — TAG row-level de l'engagement (pentest black/grey/whitebox) auquel
  -- appartient l'event, posé à l'ingest UNIQUEMENT quand `PLUME_ENGAGEMENT_MODE=1` ET que src_ip tombe dans
  -- le scope d'un engagement ACTIF (index scope compilé, VIDE sinon). DEFAULT '' = INERTE en mode 0/off
  -- (byte-identique). N'affecte JAMAIS la détection : run_due_rules/rule_sql ne substituent PAS d'exclusion
  -- engagement (invariant SACRÉ enforcement≠détection) — le tag ROUTE l'affichage (vue Engagement), il ne
  -- CACHE rien. MIROIR de la migration v75 (ALTER guardé par col_exists) : base neuve/existante CONVERGENT.
  engagement_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_event_ts  ON event(ts);
-- idx_event_sev(severity) et idx_event_src(source) NE SONT PLUS DÉCLARÉS ICI (P10.2-c, 2026-08-05).
-- Ils sont REDONDANTS : préfixes gauches de idx_event_sev_srcip(severity, src_ip) et de
-- idx_event_src_ts(source, ts), que le planner choisit déjà. `maintenance.rs` les SUPPRIME en tâche
-- de fond depuis v110 en affirmant « une base neuve ne les crée plus : db/schema.sql ne les DÉCLARE
-- PLUS » — or ce fichier les déclarait ENCORE, et `prepare_schema()` le rejoue à CHAQUE ouverture
-- d'écriture. Résultat MESURÉ par lecture : chaque démarrage les RECONSTRUISAIT sur toute la table
-- `event` (synchronement, AVANT le bind), la tâche de fond les supprimait 29 s plus tard, et le
-- démarrage suivant recommençait. Une boucle sans fin, sur le million et plus de lignes chiffrées d'une
-- base réelle.
-- La garde `schema_ne_recree_pas_ce_que_la_reconciliation_supprime` (daemon/src/tests) LIT les DROP
-- de maintenance.rs et rougit si ce fichier en recrée un : l'allégation ne peut plus diverger du code.
-- (v108) COMPOSITE (source, ts) : la recherche brute `search source=X earliest=-Nd` compile en
-- `... FROM event WHERE source=? AND ts>=?` -> ce btree SEEK source PUIS range-prune ts en index-only
-- (COUNT pagination borné = zéro déchiffrement de la table grasse ; page = walk borné). Sur base MIGRÉE il
-- est créé EN FOND après bind (ensure_event_src_ts_index_background) car un CREATE sur des millions de lignes
-- chiffrées bloquerait le bind ; ici (base neuve, event VIDE) il est instantané. MÊME nom -> jamais en double.
CREATE INDEX IF NOT EXISTS idx_event_src_ts ON event(source, ts);
-- (P3.7-a) PARTIEL sur les BATTEMENTS DE SANTÉ. Les 8 sondes dead-man's-switch de `COLLECTORS`
-- demandent `MAX(ts) WHERE source=? AND category='health'` : `category` étant ABSENTE de
-- idx_event_src_ts, SQLite remonte la plage de la source ligne par ligne jusqu'à trouver un
-- battement -> coût = 5 VM steps x (lignes de la source depuis le dernier battement), donc O(N)
-- exactement quand le collecteur est MORT (mesuré le 2026-08-03 : x4 pour x4 lignes). PARTIEL et pas
-- (source, category, ts) : le composite plein indexe TOUTE ligne ingérée (25,5 o/ligne mesurés sur banc,
-- soit quelques dizaines de Mio extrapolés au million et demi de lignes d'une base réelle, volume relevé
-- le 2026-08-05 par `db-stats --par-objet`, + un insert btree sur le chemin d'ingest CHAUD) là où le partiel n'indexe que
-- les battements (~1,5 Mio, un insert toutes les ~37 s). `category='health'` doit rester LITTÉRAL côté requête,
-- sinon SQLite ne peut pas prouver l'implication et ignore l'index en SILENCE (cf. daemon/src/sondes.rs).
-- Sur base MIGRÉE il est créé EN FOND après bind (ensure_event_health_beat_index_background) ; ici
-- (base neuve, event VIDE) il est instantané. MÊME nom -> jamais en double.
CREATE INDEX IF NOT EXISTS idx_event_health_beat ON event(source, ts) WHERE category='health';

-- Recherche plein-texte « SPL-lite »
CREATE VIRTUAL TABLE IF NOT EXISTS event_fts USING fts5(
  message, source, category, content='event', content_rowid='id'
);
CREATE TRIGGER IF NOT EXISTS event_ai AFTER INSERT ON event BEGIN
  INSERT INTO event_fts(rowid,message,source,category)
  VALUES (new.id,new.message,new.source,new.category);
END;
CREATE TRIGGER IF NOT EXISTS event_ad AFTER DELETE ON event BEGIN
  INSERT INTO event_fts(event_fts,rowid,message,source,category)
  VALUES ('delete',old.id,old.message,old.source,old.category);
END;

-- Métriques (séries temporelles, fenêtre glissante)
CREATE TABLE IF NOT EXISTS metric(
  ts INTEGER NOT NULL, name TEXT NOT NULL, labels TEXT, value REAL NOT NULL,
  env_id TEXT NOT NULL DEFAULT 'prod'        -- v66 : environnement intra-tenant (#2a-2a), INERTE en mode 0
);
CREATE INDEX IF NOT EXISTS idx_metric ON metric(name,ts);

-- États point-in-time (firewall, ports, cve, durcissement, suid, conteneurs)
-- 'hash' permet de ne réécrire 'data' que sur changement (diff).
CREATE TABLE IF NOT EXISTS snapshot(
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, hash TEXT, data TEXT,
  env_id TEXT NOT NULL DEFAULT 'prod'        -- v66 : environnement intra-tenant (#2a-2a), INERTE en mode 0
);
CREATE INDEX IF NOT EXISTS idx_snapshot ON snapshot(kind,ts);

-- Baselines pour la détection par diff (ports, SUID, units, hashs...)
CREATE TABLE IF NOT EXISTS baseline(key TEXT PRIMARY KEY, value TEXT, updated INTEGER);

-- Alertes
CREATE TABLE IF NOT EXISTS alert(
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, rule TEXT NOT NULL,
  severity INTEGER NOT NULL, title TEXT, detail TEXT,
  status TEXT NOT NULL DEFAULT 'new',        -- new | ack | closed
  acked_at INTEGER, acked_by TEXT, dedup TEXT,
  env_id TEXT NOT NULL DEFAULT 'prod',       -- v66 : environnement intra-tenant (#2a-2a), INERTE en mode 0
  -- v75 (MODE ENGAGEMENT) — TAG engagement de l'alerte (fondation du rapport de couverture scopé
  -- `/api/coverage/detections?engagement=<id>`). DEFAULT '' = INERTE en mode 0/off. MIROIR de la migration v75.
  engagement_id TEXT NOT NULL DEFAULT '',
  -- v115 (S7) — À QUELLE(S) SOURCE(S) CETTE ALERTE SE RAPPORTE. Liste séparée par des sauts de ligne,
  -- ÉCRITE au moment où l'alerte est levée et DÉRIVÉE DE LA DONNÉE (colonne `event.source` des événements
  -- appariés ; descripteur typé de la sonde pour un capteur muet) — jamais du texte de la règle, qui est
  -- de la prose. `(source indéterminée)` = l'inconnu NOMMÉ (cf. daemon/src/imputation.rs). DEFAULT ''
  -- = alerte ANTÉRIEURE à la migration : le lecteur retombe alors sur l'extraction textuelle historique.
  -- MIROIR de la migration v115.
  sources TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alert(status,ts);
CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_dedup ON alert(dedup) WHERE dedup IS NOT NULL;
-- NB : les index de LECTURE idx_alert_rule_ts/idx_alert_host_ts (triage groupé, /api/alerts/groups) vivent
-- dans migrate() v76 — comme idx_alert_ts/idx_alert_mitre_ts (v72) — car `host` est ajouté par ALTER (v2)
-- et n'existe pas dans cette table de base ; les poser ici échouerait sur une BDD fraîche.

-- Dashboards query-driven (P3)
-- v93 (#55 observability-as-code) — `managed` : 0 = builtin/seed, 1 = overlay config.d (versionné git,
-- verrouillé en UI + prunable), 2 = ad-hoc UI. DEFAULT 2 -> un dashboard/panneau créé en UI reste éditable.
-- MIROIR de la migration v93 (ALTER guardé par col_exists) : base neuve (ici) et existante CONVERGENT.
CREATE TABLE IF NOT EXISTS dashboard(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT 'Sans titre', created INTEGER,
  managed INTEGER NOT NULL DEFAULT 2
);
CREATE TABLE IF NOT EXISTS panel(
  id INTEGER PRIMARY KEY,
  dashboard_id INTEGER NOT NULL,
  title TEXT NOT NULL DEFAULT 'Panneau',
  query TEXT NOT NULL DEFAULT '',
  is_soql INTEGER NOT NULL DEFAULT 1,
  viz TEXT NOT NULL DEFAULT 'table',
  position INTEGER NOT NULL DEFAULT 0,
  managed INTEGER NOT NULL DEFAULT 2
);
CREATE INDEX IF NOT EXISTS idx_panel_dash ON panel(dashboard_id, position);

-- Moteur de règles de détection (P4) : requête soql/SQL -> valeur -> seuil -> alerte
CREATE TABLE IF NOT EXISTS rule(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL DEFAULT 'Règle',
  enabled INTEGER NOT NULL DEFAULT 1,
  query TEXT NOT NULL DEFAULT '',
  is_soql INTEGER NOT NULL DEFAULT 1,
  op TEXT NOT NULL DEFAULT '>',
  threshold REAL NOT NULL DEFAULT 0,
  severity INTEGER NOT NULL DEFAULT 2,
  interval_s INTEGER NOT NULL DEFAULT 300,
  window_s INTEGER NOT NULL DEFAULT 3600,
  -- 0 = builtin/seed | 1 = overlay-file (config.d, versionné git) | 2 = ad-hoc UI (CRUD)
  managed INTEGER NOT NULL DEFAULT 0,
  last_run INTEGER, last_value REAL, last_fired INTEGER,
  -- v116 (P3.9-a) — évaluations CONSÉCUTIVES abandonnées par l'ordonnanceur (compilation refusée, requête en
  -- échec, budget dépassé, cellule non numérique, fil en panique) ; remis à 0 à la première évaluation
  -- réussie. Au seuil dérivé de `interval_s` (une heure d'horizon, plancher 2), une alerte « détection
  -- aveugle » est posée, résolue au retour. MIROIR de la migration v116.
  abandons_consecutifs INTEGER NOT NULL DEFAULT 0
);

-- Tables d'enrichissement (lookup, v61) : l'opérateur SOQL `lookup <name> <keyfield> [OUTPUT cols]`
-- joint `lookup_kv` en LEFT JOIN pour ajouter des colonnes extraites du JSON `val`. `lookup_meta`
-- porte les métadonnées (champ-clé, colonnes, horodatage) pour l'endpoint admin /api/lookups.
CREATE TABLE IF NOT EXISTS lookup_kv(
  name TEXT NOT NULL, key TEXT NOT NULL, val TEXT NOT NULL, PRIMARY KEY(name,key)
);
CREATE TABLE IF NOT EXISTS lookup_meta(
  name TEXT PRIMARY KEY, key_field TEXT, cols TEXT, updated INTEGER
);

-- Administration UI (v65, #1b). `setting` : réglages runtime tenant-scopables — aujourd'hui la RÉTENTION
-- éditable à chaud (retention_run relit la BDD -> la BDD gagne sur env/conf ; planchers durs appliqués).
-- `source_settings` : métadonnées DISPLAY-only par source (attendu/inattendu, label, note, catégorie) —
-- AUCUN impact ingest/collecte/règle. scope='global' = couture multi-tenant (#2), non exposée en UI.
CREATE TABLE IF NOT EXISTS setting(
  scope TEXT NOT NULL DEFAULT 'global', key TEXT NOT NULL, value TEXT NOT NULL,
  updated INTEGER, updated_by TEXT, PRIMARY KEY(scope, key)
);
CREATE TABLE IF NOT EXISTS source_settings(
  scope TEXT NOT NULL DEFAULT 'global', source TEXT NOT NULL,
  expected INTEGER NOT NULL DEFAULT 1, label TEXT, note TEXT, category TEXT,
  -- v118 (P11.3-c) : la provenance PROPRE de chaque déclaration, et la CADENCE que l'exploitant déclare
  -- pour une source que ce dépôt n'observe pas. `updated`/`updated_by` = dernier geste sur la ligne, quel
  -- qu'il soit ; `expected_par`/`cadence_par` ne bougent que sur LEUR geste — une provenance qui se
  -- réécrirait au premier changement de note ne prouverait rien. `cadence` : enum fermé partagé avec
  -- l'écriture (NATURES_DECLARABLES) ; NULL = personne ne l'a déclarée, ce qui n'est pas un défaut.
  expected_par TEXT, expected_le INTEGER,
  cadence TEXT, cadence_interval_s INTEGER, cadence_par TEXT, cadence_le INTEGER,
  updated INTEGER, updated_by TEXT, PRIMARY KEY(scope, source)
);

-- `host_settings` (v119, P11.10-a) : CE QU'ON ATTEND D'UN HÔTE, et QUI l'a déclaré. Trois valeurs dans un
-- enum fermé (`ATTENTES_DECLARABLES`) : `signal_attendu` (le silence est un incident — déclaration
-- explicite, distincte de l'absence de déclaration), `silence_attendu` (machine de test/fixture : elle
-- reste dans le parc et dans la liste, mais n'alerte plus), `retire` (décommissionnée : elle sort du
-- dénominateur, sans disparaître de la liste — `host_rollup` garde son historique). NULL = personne n'a
-- rien dit, et le défaut reste « le silence alerte » : un dead-man's-switch dont le défaut serait
-- l'inverse s'éteindrait sur toute machine que personne n'a pensé à déclarer. `attente_par`/`attente_le`
-- sont la provenance PROPRE de la déclaration et ne bougent QUE sur elle (leçon mesurée de v118).
CREATE TABLE IF NOT EXISTS host_settings(
  scope TEXT NOT NULL DEFAULT 'global', host TEXT NOT NULL,
  attente TEXT, attente_motif TEXT, attente_par TEXT, attente_le INTEGER,
  updated INTEGER, updated_by TEXT, PRIMARY KEY(scope, host)
);

-- Override d'ACTIVATION du contenu de détection (v101, #1c-toggle). `detection_override` = décision ADMIN
-- de (dés)activer une règle/parseur/playbook, keyée par (kind,name) STABLE. Sa RAISON D'ÊTRE : un overlay
-- config.d (managed=1) est ré-UPSERTé au boot depuis le fichier git versionné -> l'`enabled` du fichier
-- ré-imposerait l'état à chaque reboot et STOMPERAIT le choix de l'admin. Cet override est réappliqué PAR
-- DESSUS l'overlay au boot (apply_content_overrides, APRÈS load_overlay_*) -> git définit le CONTENU, l'admin
-- décide de l'ACTIVATION, et ce choix SURVIT au reboot. Ne porte QUE `enabled` (jamais query/is_soql : aucune
-- élévation SQL brut possible via l'override). VIDE -> boot byte-identique (0 UPDATE en mode 0). `kind` ∈
-- rule|parser|playbook (littéral serveur, jamais une entrée utilisateur) ; `name` paramétré (injection-safe).
CREATE TABLE IF NOT EXISTS detection_override(
  kind TEXT NOT NULL, name TEXT NOT NULL, enabled INTEGER NOT NULL,
  updated INTEGER NOT NULL DEFAULT 0, updated_by TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(kind, name)
);

-- v68 (#3a) — CONNECTEURS de sources externes (Microsoft Defender / Graph Security d'abord). Table
-- PAR-TENANT (config + secret + watermark dans la base du tenant, comme `notifier`/`rule` ; mode 0 =
-- base unique `default`). POSÉE PAR migrate() v68 (PAS ici), sur le modèle des tables dérivées
-- event_rollup : la colonne `secret` (= client_secret OAuth) est un CREDENTIAL — JAMAIS versionnée dans
-- schema.sql (doctrine « clé jamais dans schema.sql »), protégée at-rest par SQLCipher et déniée en
-- lecture SQL brut par l'authorizer du read-pool (comme user.hash / token.token_hash). Convergence
-- base neuve/existante garantie par migrate() (v68 tourne aussi sur une base fraîche). INERTE tant
-- qu'aucune ligne n'existe (le poll loop sélectionne les connecteurs DUS -> 0 ligne = no-op strict).

-- v75 (MODE ENGAGEMENT AUTORISÉ) — pentest natif black/grey/whitebox SANS reconfigurer le SOC, SANS angle
-- mort, auto-expirant, audité. Tables PAR-TENANT (comme `connector`/`rule` ; mode 0 = base unique `default`),
-- POSÉES PAR migrate() v75 (PAS ici) : `engagement` (déclaration : box, scope CIDRs JSON, fenêtre, autorisation,
-- statut, adaptateur enforcer) + `engagement_grant` (INTENT de provisioning par box : blackbox=aucun,
-- greybox=1 `scoped_cred`, whitebox=`scoped_cred`+`config_read`, cycle pending->issued->revoked piloté par un
-- adaptateur de provisioning pluggable, PULL — le daemon DÉCLARE l'intent + RÉVOQUE, l'adaptateur ÉMET). INVARIANT
-- SACRÉ : un engagement suppresse UNIQUEMENT l'auto-BAN des IP scopées (Arm A : action_valid) ; la collecte, les
-- règles, les alertes et la couverture restent 100 % ON (enforcement≠détection). INERTE en mode 0/off (aucune
-- ligne, index scope VIDE, flag PLUME_ENGAGEMENT_MODE absent -> byte-identique). Convergence base neuve/existante
-- garantie par migrate() (v75 tourne aussi sur une base fraîche).

-- v77 (INVENTAIRE DE FLOTTE PRÉ-AGRÉGÉ) — table DÉRIVÉE `host_rollup`, POSÉE PAR migrate() v77 (PAS ici, comme
-- event_rollup/event_dim_rollup : reconstructible depuis event∪metric∪snapshot -> jamais versionnée dans
-- schema.sql). MOTIF : /api/fleet ET /api/integrations calculaient l'inventaire par `SELECT host,MAX(ts) FROM
-- (event UNION ALL metric UNION ALL snapshot) GROUP BY host` SANS borne temporelle -> idx_event_host (host-only,
-- ne couvre PAS ts) forçait un full-scan+déchiffrement des ~4,7 M lignes (~39 s) -> le watchdog 5 s du read-pool
-- TUAIT la requête -> résultat VIDE mis en cache -> flotte FIGÉE à 0 hôte. MÊME anti-pattern que la Fraîcheur
-- (v64) : « jamais scanner event par requête au volume ». FIX = petite table KEYÉE PAR HÔTE (host, env_id) :
-- last_ts=MAX / first_ts=MIN / sig_total (heures définitives) + sig_hot (fenêtre chaude) = signals. Cardinalité =
-- taille de FLOTTE (centaines/milliers), pas volume d'events -> lecture sub-ms, watchdog jamais touché. MAINTENUE
-- périodiquement par rollup_hosts() (piggyback sur rollup_events(), MÊME mécanique watermark `host_rollup_wm` que
-- event_rollup) -> ZÉRO coût à l'ingest (ingest_events_batch INCHANGÉ ; mode 0/data-plane byte-identique). NON
-- prunée par la rétention (un hôte silencieux/mort reste VISIBLE : son last_ts colle). env_id (comme les rollups
-- v67) : mode 0 = tout 'prod', collapse sous GROUP BY host. Backfill des hôtes existants à la migration.
-- Convergence base neuve/existante garantie par migrate() (v77 tourne aussi sur une base fraîche).

-- v104 (#3 INCIDENTS + RESPONSE WIZARD, Phase 1) — MIROIR des tables créées par migrate_v104 (les 3 colonnes
-- `incident_tier`/`incident_type`/`commander` restent, elles, migration-only comme TOUTES les colonnes #4a/#39
-- de `incident`, dont la table entière n'est PAS dans schema.sql). `runbook` = gabarit de runbook keyé MITRE
-- (match_kind tactic|technique|*, seedé managed=1 par seed_runbooks) ; `runbook_step` = étapes ordonnées phasées
-- (triage|investigation|containment|eradication|recovery ; step_kind manual|search|response — une step response
-- RÉFÉRENCE l'enum d'action FERMÉ, elle NE l'exécute PAS : l'exécution reste /api/actions, approbation+ledger) ;
-- `case_step` = progression PAR-INCIDENT (fige/instancie les steps d'un runbook attaché ; status pending|done|
-- skipped). VIDES en mode 0 -> un case sans incident_tier ni runbook attaché = comportement d'aujourd'hui.
-- Ces tables sont HORS de la projection client-read (client_case_*) -> jamais exposées au MSSP.
CREATE TABLE IF NOT EXISTS runbook(
  id INTEGER PRIMARY KEY,
  key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  match_kind TEXT NOT NULL DEFAULT '*',
  match_key TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  managed INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  created INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS runbook_step(
  id INTEGER PRIMARY KEY,
  runbook_id INTEGER NOT NULL,
  ordinal INTEGER NOT NULL,
  phase TEXT NOT NULL,
  title TEXT NOT NULL,
  guidance TEXT NOT NULL DEFAULT '',
  step_kind TEXT NOT NULL DEFAULT 'manual',
  search_soql TEXT,
  action_kind TEXT
);
CREATE TABLE IF NOT EXISTS case_step(
  id INTEGER PRIMARY KEY,
  incident_id INTEGER NOT NULL,
  runbook_id INTEGER NOT NULL,
  step_id INTEGER NOT NULL,
  ordinal INTEGER NOT NULL,
  phase TEXT NOT NULL,
  title TEXT NOT NULL,
  guidance TEXT NOT NULL DEFAULT '',
  step_kind TEXT NOT NULL DEFAULT 'manual',
  search_soql TEXT,
  action_kind TEXT,
  target TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  actor TEXT,
  ts INTEGER,
  note TEXT
);
CREATE INDEX IF NOT EXISTS idx_runbook_match ON runbook(match_kind, match_key);
CREATE INDEX IF NOT EXISTS idx_runbook_step_rb ON runbook_step(runbook_id, ordinal);
CREATE INDEX IF NOT EXISTS idx_case_step_inc ON case_step(incident_id, ordinal);

-- INVENTAIRE DES COMPTES QUI ACCÈDENT (v117, `P11.5-c`). `acces_observe` = la trace, par le point de
-- passage unique de l'authentification, de CHAQUE identité qui a réellement atteint la console — quelle
-- que soit sa provenance. RAISON D'ÊTRE : la liste des comptes était `SELECT … FROM user`, donc la table
-- des comptes que le produit CRÉE ; un compte venu d'un annuaire externe (SSO d'en-têtes) n'y a jamais de
-- ligne et n'apparaissait donc nulle part, alors qu'il administrait. Personne ne pouvait répondre à
-- « qui a accès ». Chaque ligne dit d'OÙ vient le compte (`provenance`), CE QU'IL PEUT au dernier accès
-- (`role_effectif`) et d'où ce rôle est dérivé (`origine_du_role`), et QUAND il a été vu
-- (`premiere_vue`/`derniere_vue`). AUCUN secret n'y entre : ni hash, ni jeton, ni groupe brut.
-- Écriture DÉBOUNCÉE (une par identité et par fenêtre) et table PLAFONNÉE (la plus ancienne vue cède) ->
-- coût borné sur le verrou d'écriture et en octets. VIDE -> la console rend l'inventaire local seul.
CREATE TABLE IF NOT EXISTS acces_observe(
  nom TEXT NOT NULL,
  provenance TEXT NOT NULL,
  role_effectif TEXT NOT NULL,
  origine_du_role TEXT NOT NULL,
  methode TEXT NOT NULL,
  premiere_vue INTEGER NOT NULL,
  derniere_vue INTEGER NOT NULL,
  PRIMARY KEY(nom, provenance)
);

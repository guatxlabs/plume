//! Store SPI (data-plane) : DTO d'insertion (`EventRow`/`MetricRow`/`SnapshotRow`), vue de lecture
//! (`QueryStats`/`Rows`), `trait EventStore` + unique impl `SqlcipherStore` (SQLite/SQLCipher) et
//! accesseur `store()`. Émission GXQL déléguée à `guatx_core::soql` ; lecture via `run_query_ex`
//! (résolu par le glob `crate::*`). Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ====================================================================================================
// STORE SPI (readiness pivot #1 « backend de stockage enfichable »).
//
// OBJECTIF : rendre POSSIBLE un jour un backend data-plane différent (DuckDB mono-nœud, ClickHouse
// cluster) SANS que chaque écriture/lecture soit codée en dur contre SQLite/SQLCipher. On introduit une
// COUTURE (`trait EventStore`) devant laquelle passe le DATA-plane (event / metric / snapshot en écriture,
// GXQL en lecture). `SqlcipherStore` est l'UNIQUE implémentation et émet EXACTEMENT le même SQL /
// stocke des lignes BYTE-IDENTIQUES à aujourd'hui (mode 0 strictement inchangé — invariant absolu).
//
// FRONTIÈRE DATA vs CONTROL : ne passent par le store QUE les tables qui EXPLOSENT en volume et qui
// migreraient un jour — event, metric, snapshot. Le CONTROL-plane (user/token/tenant/grant/case/alert/
// rule/parser/playbook/notifier/connector/setting/dashboard/ledger) reste transactionnel bas-volume sur
// SQLite : il n'est PAS touché ici. Les écritures d'AUDIT du daemon dans `event` (origin='daemon' :
// plume-auth / plume-operator-access / plume-tenant-admin / plume-config) sont des marqueurs de contrôle
// bas-volume et restent volontairement sur le chemin direct (candidat de migration ultérieur).
//
// PRODUCTEURS data-plane encore SUR LE CHEMIN DIRECT (migration ultérieure, PAS encore derrière la couture)
// — énumérés ICI pour que la frontière documentée corresponde au code (sinon la « complétude » ci-dessus
// serait fausse) :
//   - INGEST Loki push `POST /loki/api/v1/push` (`loki_push`) : écrit des events `category='log'` via un
//     statement PRÉPARÉ à 7 colonnes (boucle chaude, jusqu'à INGEST_MAX_ENTRIES/req). Le reste de l'ingest
//     (journal / spool générique / self-detect / connecteur) passe DÉJÀ par `store().insert_event` ; Loki
//     est l'exception. Le convertir n'est PAS trivialement byte-identique (7 col vs 14 col `INSERT OR
//     IGNORE`) -> DIFFÉRÉ. Clé d'une migration propre : un accesseur `event_insert_sql()` symétrique de
//     `metric_insert_sql()` (aujourd'hui `EVENT_INSERT_SQL` est privé), pour piloter une boucle préparée.
//   - `seed_demo` (PLUME_DEMO=1, JAMAIS en prod) : ses events de démo sont insérés en direct alors que ses
//     métriques passent par `store().insert_metric` — asymétrie cosmétique, sans impact prod.
// Ces deux-là ne cassent PAS la parité mode 0 (SQL inchangé) ; c'est une note de COMPLÉTUDE/lisibilité de la
// couture, pas une régression byte-identique.
//
// RÉSOLUTION PAR-TENANT : le store est SANS état ; la connexion writer (résolue via `handle_for`/`req_db`)
// et le `db_path` (via `req_db_path`, clé du read-pool) sont passés PAR APPEL. Le routing tenant existant
// est donc préservé tel quel — `store().insert_event(tenant_conn, row)` est intrinsèquement tenant-scopé.
//
// RÈGLE DE LECTURE (design) : le GXQL TRAVERSE le store (`query_soql`/`soql_to_sql`) — le store COMPILE
// lui-même via `guatx_core::soql` (émission Dialect) ; on ne lui passe JAMAIS une chaîne SQL pré-fabriquée.
// La route-rollup Plume (optimisation qui produit du SQL brut sur les tables pré-agrégées) reste servie
// par l'exécuteur bas-niveau `run_query_ex`, comme avant.
// ====================================================================================================

// DTO PLAINS déplacés dans le cœur partagé (P1-M1) : `EventRow`/`MetricRow`/`SnapshotRow` (DTO
// d'insertion) + `QueryStats`/`Rows` (vue de lecture typée) vivent désormais dans `guatx_core::store`
// (structures pures, ZÉRO rusqlite). On les RÉ-EXPORTE ici (`pub(crate)`) : le glob `ingest::store::*`
// (ingest/mod.rs) les rend accessibles au daemon comme avant -> aucun call-site changé, byte-identique.
// Le `trait EventStore` + l'impl `SqlcipherStore` (couplés à `rusqlite::Connection`) restent CI-DESSOUS.
// `QueryStats`/`Rows` n'étaient utilisés QUE par les tests du store (d'où l'`#[allow(dead_code)]`
// d'origine) ; on conserve la même intention sur la ré-export (`unused_imports`) pour les builds non-test.
#[allow(unused_imports)]
pub(crate) use guatx_core::store::{EventRow, MetricRow, QueryStats, Rows, SnapshotRow};

/// SPI data-plane INTERNE (couplée `rusqlite`), chemin BYTE-IDENTIQUE historique. Une seule impl
/// (`SqlcipherStore`). Les écritures prennent la connexion writer du tenant (résolue par l'appelant) ;
/// la transaction/rollback/backfill restent chez l'appelant (le store n'émet QUE l'ordre SQL canonique).
/// La lecture GXQL est compilée PAR le store. Les ~82 call-sites du daemon appellent CE trait directement
/// (parité stricte). Le trait BACKEND-NEUTRE `guatx_core::store::EventStore` (GAP-1) est une COUCHE
/// ADDITIVE au-dessus : `SqlcipherStore` l'implémente en re-castant `StoreHandle::Sqlite` puis en
/// déléguant ICI. Renommé `EventStore` -> `SqlcipherEventStore` pour libérer le nom canonique au profit
/// de la SPI neutre du cœur (alignement code <-> RFC `scale-clickhouse-ha-design.md`).
pub(crate) trait SqlcipherEventStore {
    /// INSERT canonique d'un event (OR IGNORE sur `dedup UNIQUE`). Ordre/valeurs figés -> ligne stockée
    /// byte-identique aux INSERT legacy (`env_id=None` -> lié à 'prod', jamais NULL : la colonne est NOT NULL).
    fn insert_event(&self, conn: &Connection, row: &EventRow) -> rusqlite::Result<usize>;
    /// INSERT d'une métrique (série temporelle). `labels=None` -> NULL (== littéral `NULL` du legacy).
    fn insert_metric(&self, conn: &Connection, m: &MetricRow) -> rusqlite::Result<usize>;
    /// INSERT d'un snapshot point-in-time.
    fn insert_snapshot(&self, conn: &Connection, s: &SnapshotRow) -> rusqlite::Result<usize>;
    /// SQL canonique de l'INSERT métrique — exposé pour les boucles à statement PRÉPARÉ (réutilisation),
    /// source UNIQUE de vérité du texte SQL métrique.
    fn metric_insert_sql(&self) -> &'static str;
    /// ÉMISSION GXQL -> SQL (le store possède l'émission, via `guatx_core::soql` = Dialect). C'est le point
    /// unique par lequel toute lecture GXQL traverse le store (jamais de SQL pré-fabriqué passé au store).
    fn soql_to_sql(&self, soql: &str, from: i64, to: i64, env: Option<&str>) -> Result<String, String>;
    /// FIELD FILTERS (#45) — ÉMISSION GXQL -> SQL AVEC masques de champ EFFECTIFS (résolus par le daemon pour
    /// le RÔLE/tenant/env de l'appelant). VIDE -> STRICTEMENT identique à `soql_to_sql` (mode 0 byte-identique).
    /// DÉFAUT = FAIL-CLOSED : un store qui n'implémente pas le masquage (tier WARM/COLD) REFUSE une compilation
    /// masquée -> jamais de SQL NON masqué servi à un rôle restreint (protège plutôt que fuir). Seul le tier
    /// chaud SQLite (`SqlcipherStore`) sait émettre le masque -> il l'override.
    fn soql_to_sql_masked(&self, soql: &str, from: i64, to: i64, env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet) -> Result<String, String> {
        if masks.is_empty() {
            return self.soql_to_sql(soql, from, to, env);
        }
        Err("field-filters (#45) non supportés sur ce backend de stockage (tier WARM/COLD) — lecture refusée par sécurité".into())
    }
    /// KEYSET (#28) — variante keyset de `soql_to_sql_masked` : compile en AJOUTANT la clé de tri stable `id`
    /// en FIN de projection de la base `event` (`Schema::with_cursor_id(true)`), pour que le daemon pagine par
    /// curseur `(ts,id)` — parcours INTÉGRAL du match-set, SANS plafond de comptage (fin du cap 10 000 qui CACHAIT
    /// des événements). Appelée UNIQUEMENT par la branche BROWSE d'Explore (`query.rs`). TOUS les autres sites
    /// (détection `rule_sql`, panneaux `compile_panel_sql`, export) restent sur `soql_to_sql`/`soql_to_sql_masked`
    /// (cursor_id=false) -> SQL BYTE-IDENTIQUE (mode 0). No-op de projection sur une base sans `id` réel
    /// (metric/Forge). DÉFAUT : DÉLÈGUE au chemin masqué normal (cursor_id OFF) — dégradation gracieuse pour un
    /// backend qui ne sait pas projeter `id` (le daemon détecte alors l'absence de colonne curseur et n'affirme
    /// pas `has_more`) ; seul le tier chaud SQLite (`SqlcipherStore`) l'override avec le VRAI keyset.
    fn soql_to_sql_masked_keyset(&self, soql: &str, from: i64, to: i64, env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet) -> Result<String, String> {
        self.soql_to_sql_masked(soql, from, to, env, masks)
    }
    /// LECTURE GXQL de bout en bout : compile (émission Dialect) PUIS exécute sur la base `db_path` via
    /// l'exécuteur read-only borné (watchdog `budget_ms`, annulation `qid`). Renvoie la forme JSON live.
    /// PRIMITIVE de lecture du SPI (contrepartie des `insert_*`). Les handlers LIVE ne l'appellent pas
    /// directement car ils POST-TRAITENT le SQL compilé (interception rollup-route, wrap pagination,
    /// écho `compiled_sql`) : ils composent donc `soql_to_sql` (émission = store) + `run_query_ex`
    /// (exécuteur bas-niveau). L'ÉMISSION de lecture traverse ainsi le store à 100 % (via `soql_to_sql_x`).
    /// `query_soql` est exercée par le test du store (preuve de bout en bout de la traversée GXQL).
    #[allow(dead_code)]
    fn query_soql(&self, db_path: &str, soql: &str, from: i64, to: i64, env: Option<&str>, budget_ms: u64, qid: Option<&str>) -> Result<Value, String>;
}

// ====================================================================================================
// LE CLOISONNEMENT PAR HÔTE DE `event.dedup` — POSÉ CÔTÉ SERVEUR, AU POINT D'ÉCRITURE.
//
// CE QUI ÉTAIT CASSÉ, ET COMMENT ÇA SE VOYAIT (ou plutôt : comment ça NE se voyait pas). `event.dedup`
// est UNIQUE au niveau de la BASE (`db/schema.sql`) et toute écriture est un `INSERT OR IGNORE`. Or la
// clé est FABRIQUÉE PAR L'ÉMETTEUR, qui ne voit que lui-même : deux machines qui font la même chose
// produisent la même clé, et la seconde ligne est JETÉE SANS UN MOT. Mesuré des deux côtés :
//   - Windows (fiche Server 2022, 2026-08-01) : 2ᵉ machine, 311 enregistrements Sysmon envoyés,
//     266 arrivés, 45 disparus — exactement ceux que la 1ʳᵉ avait déjà expédiés ; battement de santé
//     de la 2ᵉ machine JAMAIS stocké.
//   - Linux (2026-08-02, protocole : les 36 capteurs qui sourcent `collectors/lib.sh` lancés deux fois
//     avec un shim `PLUME_LIB` ne changeant QUE `$host`, puis les fichiers spool obtenus rejoués dans le
//     VRAI `ingest_once` avec le marqueur `#H#` de chaque hôte — reproductible, aucun artefact conservé).
//     Deux hôtes auxquels il manque les MÊMES prérequis produisent 36 clés chacun, dont 26 IDENTIQUES
//     (24 `avail-*`, `acl-*`, `cfg-conntrack-*`) ; à l'ingestion : 78 événements ENVOYÉS, 52 STOCKÉS,
//     26 PERDUS, tous sur la 2ᵉ machine (39 lignes pour la 1ʳᵉ, 13 pour la 2ᵉ = 67 % de sa collecte).
//     Les 10 clés restantes ne diffèrent QUE parce que les deux passes ont eu lieu à 24 s d'écart
//     (`conntrack-…-<ts>`) : sur un parc à timers synchronisés elles collisionnent aussi — la mesure
//     MINORE donc la perte. Après cloisonnement, MÊME protocole : 78 envoyés, 78 stockés, 39 + 39.
// Le cas le plus grave est `avail-*` : c'est la clé de l'aveu « capteur aveugle », le mécanisme même
// qui existe pour qu'un capteur ne devienne pas muet en silence. Sur un parc où toutes les machines
// manquent du même prérequis — le cas le plus COURANT — une seule le signalait.
//
// POURQUOI LA CORRECTION N'EST PAS « CORRIGER LES ÉMETTEURS ». C'est le piège, et il est chiffré
// (mesuré le 2026-08-02 par extraction sur l'arbre livré) : AU MOINS 29 FORMES de clé `dedup`
// distinctes, fabriquées dans 30 FICHIERS émetteurs, en 6 langages (POSIX sh, awk, jq, Python,
// PowerShell, Rust) — 29 est un PLANCHER : c'est le nombre de PRÉFIXES distincts, et un même préfixe
// couvre parfois plusieurs formes (`cfg-auditd`, `cfg-mail`, `cfg-web`, `cfg-conntrack`…).
// L'énumération était DÉJÀ fausse — au-delà des 3 sites shell repérés, l'agent
// Rust en portait 3 autres sans hôte (`source/macos.rs`, `source/generic.rs`, l'auto-test de
// `main.rs`). Et `custom.sh`/`source/generic.rs` sont des points d'extension CLIENT : le prochain
// capteur écrit par quelqu'un d'autre se tromperait pareil. Une correction par émetteur n'est pas une
// correction, c'est une dette qui se renouvelle.
//
// LA FORME DÉRIVÉE. La question n'est pas « quelles clés portent l'hôte ? » mais « quelle est la
// PORTÉE D'UNICITÉ correcte ? ». Une clé anti-doublon vaut pour ce qu'un émetteur peut OBSERVER, et un
// émetteur n'observe QUE sa machine : la portée d'unicité DOIT être l'hôte. Le daemon, lui, connaît
// l'hôte au moment d'écrire — c'est la colonne `host` de la ligne qu'il est en train d'insérer, et
// elle est ATTESTÉE (non forgeable) quand le jeton est lié à un hôte (`spool_host_marker`/`forced_host`
// ÉCRASENT le host déclaré). On rend donc la clé STOCKÉE fonction de `(host, dedup)` de la ligne
// elle-même. Conséquence, et c'est un THÉORÈME et non une vérification : deux lignes dont la colonne
// `host` diffère ne peuvent PLUS se supprimer l'une l'autre, quelle que soit la clé fabriquée par
// l'émetteur — y compris un émetteur qui n'existe pas encore, écrit dans un langage qui n'existe pas
// encore, par quelqu'un qui n'a jamais lu ce fichier.
//
// POURQUOI CÔTÉ SERVEUR ET PAS CÔTÉ ÉMETTEUR (deuxième raison, indépendante). Le spool RÉÉMET après
// une panne (`agent/src/buffer.rs` : anneau borné rejoué au retour, sémantique at-least-once ;
// `ingest_once` remet en QUARANTAINE un fichier dont le batch a rollbacké, pour le rejouer). Le
// cloisonnement étant une fonction PURE de `(host, dedup)`, une réémission du MÊME hôte reproduit la
// MÊME clé cloisonnée et reste correctement dédoublonnée. Une correction côté émetteur, elle, change
// la clé au moment du déploiement : les fichiers déjà en vol portent l'ancienne, les réémissions la
// nouvelle, et le doublon passe. Le côté serveur est donc à la fois plus GÉNÉRAL et plus SÛR.
//
// PORTÉE — CE QUE CETTE GARDE NE FERME PAS (écrit pour être opposable, pas pour rassurer) :
//   - `alert.dedup` (index UNIQUE PROPRE, `db/schema.sql`) n'est PAS touché, et c'est DÉLIBÉRÉ : ces
//     clés-là sont fabriquées PAR LE DAEMON, qui voit toute la flotte, avec un grain DÉCLARÉ
//     (`rule-{id}` = une alerte par ÉPISODE de règle ; `rule-{id}::{unit}` dès qu'un `throttle_field`
//     — `host` compris — est posé). Cloisonner ça par hôte DÉTRUIRAIT une décision, au lieu d'en
//     réparer une (cf. `dedup_alert_reste_global_par_decision`).
//   - la voie SNAPSHOT (`kind=firewall`/`controls` -> `snapshot` + alertes `fw-lockdown-<jour>` /
//     `controls-<hash>-<jour>`) n'est PAS cloisonnée : elle compare au DERNIER snapshot du `kind`
//     TOUS HÔTES CONFONDUS. C'est un défaut VOISIN et RÉEL sur un parc, mais c'est un autre défaut
//     (table `snapshot`, table `alert`), pas celui-ci ; il est nommé ici pour ne pas être cru couvert.
//   - `event.dedup` reste UNIQUE-au-niveau-base : on ne change PAS le schéma. Passer à
//     `UNIQUE(host, dedup)` exigerait de reconstruire la table (SQLite ne sait pas retirer un index
//     UNIQUE implicite) sur une base de production de plusieurs millions de lignes, et ferait pire :
//     SQLite considère deux NULL comme DISTINCTS, donc les lignes SANS host cesseraient d'être
//     dédoublonnées du tout — on remplacerait une perte silencieuse par une DUPLICATION silencieuse.
// ====================================================================================================

/// SÉPARATEUR du cloisonnement. `\u{1}` (SOH) est RÉSERVÉ par construction : `collectors/lib.sh`
/// (`json_escape`) supprime `\000-\037` de tout ce que les capteurs shell émettent, les clés du daemon
/// et des agents sont de l'ASCII imprimable, et un curseur journald aussi. AUCUN émetteur livré ne peut
/// donc produire une clé qui ressemble à une clé cloisonnée -> l'espace des clés cloisonnées est
/// DISJOINT de celui des clés héritées (déjà en base), et une ligne ancienne n'en supprime aucune
/// nouvelle. Cf. `dedup_cloisonne_ne_collisionne_pas_avec_lheritage`.
const DEDUP_SCOPE_SEP: char = '\u{1}';

/// CLOISONNE une clé anti-doublon d'événement par l'hôte de la ligne. `None` -> `None` (pas de clé =
/// pas de dédup, inchangé). Sinon la clé stockée est `<len(host)>␁<host>␁<clé émetteur>`.
///
/// POURQUOI UN PRÉFIXE DE LONGUEUR ET PAS UN SIMPLE `host + sep + clé`. Il faut que
/// `(host, clé) -> clé stockée` soit INJECTIF, sinon on rouvre le trou qu'on ferme : avec un simple
/// séparateur, `("a", "b␁c")` et `("a␁b", "c")` produisent la même chaîne. Le host est CONTRAINT
/// (`host_marker_ok`) quand il vient d'un jeton lié, mais il est LIBRE quand il est auto-déclaré via
/// `/api/ingest` — donc fabricable. La longueur en tête rend le décodage non ambigu, donc l'encodage
/// injectif, pour TOUTE paire d'entrées, y compris hostiles. Prouvé par `dedup_cloisonnement_injectif`.
///
/// PURE et TOTALE : même entrée -> même sortie, toujours (c'est ce qui rend les réémissions du spool
/// correctement dédoublonnées). `host` absent -> lié à la chaîne vide : les lignes sans hôte partagent
/// UNE portée, exactement comme aujourd'hui, jamais moins.
pub(crate) fn dedup_scoped_by_host(host: Option<&str>, dedup: Option<&str>) -> Option<String> {
    let cle = dedup?;
    let h = host.unwrap_or("");
    Some(format!("{}{DEDUP_SCOPE_SEP}{h}{DEDUP_SCOPE_SEP}{cle}", h.len()))
}

/// UNIQUE implémentation du SPI : SQLite/SQLCipher, exactement le comportement historique de Plume.
/// Sans état -> instanciable partout (`SqlcipherStore`), la connexion/`db_path` du tenant est passée par appel.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SqlcipherStore;

impl SqlcipherStore {
    /// SQL canonique de l'INSERT event = UNION des colonnes des 3 producteurs data-plane (journal/générique/
    /// connecteur). `INSERT OR IGNORE` (dédup) figé. Les producteurs qui omettaient une colonne lient
    /// désormais explicitement la valeur == DEFAULT de la colonne -> ligne stockée BYTE-IDENTIQUE.
    const EVENT_INSERT_SQL: &'static str =
        "INSERT OR IGNORE INTO event(ts,source,category,severity,message,host,src_ip,dst_ip,url,dedup,fields,engagement_id,origin,env_id) \
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)";
    const METRIC_INSERT_SQL: &'static str =
        "INSERT INTO metric(ts,name,labels,value,host) VALUES(?1,?2,?3,?4,?5)";
    const SNAPSHOT_INSERT_SQL: &'static str =
        "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,?2,?3,?4,?5)";
}

impl SqlcipherEventStore for SqlcipherStore {
    fn insert_event(&self, conn: &Connection, row: &EventRow) -> rusqlite::Result<usize> {
        // env_id : la colonne est `NOT NULL DEFAULT 'prod'`. Les producteurs journal/générique OMETTAIENT
        // env_id (-> 'prod' par défaut) ; on lie donc 'prod' quand `None` (jamais NULL). Le connecteur passe
        // son env_id explicite. Résultat : ligne stockée IDENTIQUE aux 3 INSERT legacy.
        // prepare_cached (F2) : la clé de cache = la chaîne SQL (const `EVENT_INSERT_SQL`, stable) -> le
        // statement est compilé UNE fois par connexion writer longue durée puis réutilisé (au lieu d'un
        // prepare() par event). Params/SQL INCHANGÉS -> ligne écrite BYTE-IDENTIQUE. Le cache est porté par
        // la connexion writer persistante (jamais une connexion jetable). Aligne ces INSERTs unitaires sur
        // les chemins bulk OBS (obs.rs) qui préparaient déjà une fois.
        // CLOISONNEMENT PAR HÔTE (cf. le bandeau `dedup_scoped_by_host`) : la clé STOCKÉE est fonction de
        // `(host, dedup)` de CETTE ligne. C'est le SEUL endroit où `event.dedup` prend sa valeur sur le
        // chemin chaud -> aucun émetteur (présent ou futur, quel que soit son langage) ne peut produire une
        // clé qui collisionne entre hôtes. `dedup=None` -> `None` : rien ne change pour les lignes sans clé.
        conn.prepare_cached(Self::EVENT_INSERT_SQL)?.execute(
            params![
                row.ts, row.source, row.category, row.severity, row.message, row.host,
                row.src_ip, row.dst_ip, row.url,
                dedup_scoped_by_host(row.host.as_deref(), row.dedup.as_deref()),
                row.fields, row.engagement_id,
                row.origin, row.env_id.as_deref().unwrap_or("prod")
            ],
        )
    }
    fn insert_metric(&self, conn: &Connection, m: &MetricRow) -> rusqlite::Result<usize> {
        conn.prepare_cached(Self::METRIC_INSERT_SQL)?.execute(params![m.ts, m.name, m.labels, m.value, m.host])
    }
    fn insert_snapshot(&self, conn: &Connection, s: &SnapshotRow) -> rusqlite::Result<usize> {
        conn.prepare_cached(Self::SNAPSHOT_INSERT_SQL)?.execute(params![s.ts, s.kind, s.hash, s.data, s.host])
    }
    fn metric_insert_sql(&self) -> &'static str {
        Self::METRIC_INSERT_SQL
    }
    fn soql_to_sql(&self, soql: &str, from: i64, to: i64, env: Option<&str>) -> Result<String, String> {
        // ALIAS DE LECTURE CIM (dette de migration, péremption 2027-07-23) : `category=exec` retrouve
        // AUSSI l'historique `category=process` des collecteurs Windows d'avant le 2026-07-23. Posé ICI
        // parce que ce trait EST le point de traversée à 100 % de l'ÉMISSION de lecture (tous les sites —
        // Explore, panneaux, tableaux de bord, export, règles, rapports, datasource, NL->GXQL — passent par
        // `soql_to_sql*_x` -> `store()`, et `query_soql` ci-dessous rappelle cette méthode). Requête sans
        // cette égalité -> `Cow::Borrowed` -> GXQL et SQL BYTE-IDENTIQUES. Cf. `soql_glue::cim_read_alias_exec`.
        let soql = crate::soql_glue::cim_read_alias_exec(soql);
        // Émission via le cœur partagé (Dialect `SqliteDialect`) — BYTE-IDENTIQUE au compilo legacy.
        // #46 : KNOWLEDGE OBJECTS actifs (alias/calc/eventtype/tag) injectés dans le schéma. VIDE (aucun KO)
        // -> `with_knowledge` no-op -> SQL byte-identique (mode 0). Tenant-wide -> s'applique AUSSI aux règles.
        guatx_core::soql::to_sql(&soql, from, to,
            &guatx_core::soql::Schema::events().with_env(env).with_knowledge(crate::active_knowledge())
                .with_message_pruning(crate::soql_prune_message())) // Phase B opt-in : OFF par défaut -> byte-identique
    }
    fn soql_to_sql_masked(&self, soql: &str, from: i64, to: i64, env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet) -> Result<String, String> {
        let soql = crate::soql_glue::cim_read_alias_exec(soql); // idem soql_to_sql (dette 2027-07-23)
        // #45 : masques INJECTÉS DANS LE SCHÉMA -> émis au choke-point `soql_field` (avant agrégation). VIDE ->
        // `with_masks` no-op -> SQL byte-identique à `soql_to_sql` (mode 0). #46 : les KNOWLEDGE OBJECTS se
        // COMPOSENT avec le masque (alias résolu AVANT le masque, calc sur base masquée, eventtype/tag rejetés
        // sur champ masqué) -> un KO ne peut pas contourner un field-filter.
        guatx_core::soql::to_sql(&soql, from, to,
            &guatx_core::soql::Schema::events().with_env(env).with_masks(masks.clone()).with_knowledge(crate::active_knowledge())
                .with_message_pruning(crate::soql_prune_message())) // Phase B opt-in : OFF par défaut -> byte-identique
    }
    fn soql_to_sql_masked_keyset(&self, soql: &str, from: i64, to: i64, env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet) -> Result<String, String> {
        let soql = crate::soql_glue::cim_read_alias_exec(soql); // idem soql_to_sql (dette 2027-07-23)
        // KEYSET (#28) — SEULE différence avec `soql_to_sql_masked` : `.with_cursor_id(true)` -> le cœur AJOUTE
        // `id` (colonne RÉELLE de `event`) EN FIN de projection de la base, clé de tri stable du curseur `(ts,id)`.
        // Masques (#45) + KNOWLEDGE (#46) + pruning (Phase B) STRICTEMENT INCHANGÉS -> mêmes garanties d'autorisation
        // et de masquage que le chemin normal (l'authorizer read-pool DENY user.hash/token_hash s'applique au
        // prepare() ensuite, à l'identique ; `id` n'est JAMAIS un champ masqué). Seule la LISTE de projection
        // s'allonge de `id`. cursor_id=false partout ailleurs -> détection/panneaux/export byte-identiques (mode 0).
        guatx_core::soql::to_sql(&soql, from, to,
            &guatx_core::soql::Schema::events().with_env(env).with_masks(masks.clone()).with_knowledge(crate::active_knowledge())
                .with_message_pruning(crate::soql_prune_message()).with_cursor_id(true))
    }
    fn query_soql(&self, db_path: &str, soql: &str, from: i64, to: i64, env: Option<&str>, budget_ms: u64, qid: Option<&str>) -> Result<Value, String> {
        let sql = self.soql_to_sql(soql, from, to, env)?;
        run_query_ex(db_path, &sql, budget_ms, qid)
    }
}

/// Accès à l'UNIQUE store data-plane. Un jour, en mode 1, pourra renvoyer un backend par-tenant ; ici,
/// toujours `SqlcipherStore` (sans état) -> mode 0 strictement inchangé.
pub(crate) fn store() -> SqlcipherStore {
    SqlcipherStore
}

// ====================================================================================================
// GAP-1 — `SqlcipherStore` monte AUSSI la SPI BACKEND-NEUTRE `guatx_core::store::EventStore`.
//
// Couche ADDITIVE : elle re-caste `StoreHandle::Sqlite(&Connection)` puis DÉLÈGUE au trait interne
// `SqlcipherEventStore` (chemin rusqlite byte-identique ci-dessus) — donc mode 0 STRICTEMENT inchangé
// (aucun call-site legacy ne passe par ici ; ils appellent `SqlcipherEventStore` directement). L'intérêt :
// prouver que la SPI neutre est réellement backend-neutre (un second backend `DuckDbStore` la monte de la
// même façon). Le trait neutre est référencé en chemin PLEINEMENT QUALIFIÉ (jamais importé au niveau
// module) pour ne PAS entrer dans le glob `use crate::*` des call-sites -> zéro ambiguïté de résolution
// de méthode (`insert_event` existe sur les DEUX traits). Les erreurs `rusqlite`/émission sont mappées
// vers `StoreError` (`Backend`/`Emit`). Migration COMPLÈTE des call-sites = follow-up (RFC Phase 0).
impl guatx_core::store::EventStore for SqlcipherStore {
    fn insert_event(&self, h: guatx_core::store::StoreHandle, row: &EventRow) -> Result<usize, guatx_core::store::StoreError> {
        let conn = h.downcast::<Connection>("sqlite")?;
        SqlcipherEventStore::insert_event(self, conn, row).map_err(|e| guatx_core::store::StoreError::Backend(e.to_string()))
    }
    fn insert_metric(&self, h: guatx_core::store::StoreHandle, m: &MetricRow) -> Result<usize, guatx_core::store::StoreError> {
        let conn = h.downcast::<Connection>("sqlite")?;
        SqlcipherEventStore::insert_metric(self, conn, m).map_err(|e| guatx_core::store::StoreError::Backend(e.to_string()))
    }
    fn insert_snapshot(&self, h: guatx_core::store::StoreHandle, s: &SnapshotRow) -> Result<usize, guatx_core::store::StoreError> {
        let conn = h.downcast::<Connection>("sqlite")?;
        SqlcipherEventStore::insert_snapshot(self, conn, s).map_err(|e| guatx_core::store::StoreError::Backend(e.to_string()))
    }
    fn insert_events(&self, h: guatx_core::store::StoreHandle, rows: &[EventRow]) -> Result<usize, guatx_core::store::StoreError> {
        // Boucle à statement PRÉPARÉ sur le MÊME `EVENT_INSERT_SQL` + MÊMES params que `insert_event`
        // -> lignes stockées BYTE-IDENTIQUES à N appels unitaires (primitive d'ingest batché, GAP-3).
        let conn = h.downcast::<Connection>("sqlite")?;
        let be = |e: rusqlite::Error| guatx_core::store::StoreError::Backend(e.to_string());
        let mut stmt = conn.prepare(Self::EVENT_INSERT_SQL).map_err(be)?;
        let mut n = 0usize;
        for row in rows {
            n += stmt.execute(params![
                row.ts, row.source, row.category, row.severity, row.message, row.host,
                row.src_ip, row.dst_ip, row.url,
                dedup_scoped_by_host(row.host.as_deref(), row.dedup.as_deref()), // idem `insert_event`
                row.fields, row.engagement_id,
                row.origin, row.env_id.as_deref().unwrap_or("prod")
            ]).map_err(be)?;
        }
        Ok(n)
    }
    fn event_insert_sql(&self) -> &'static str {
        Self::EVENT_INSERT_SQL
    }
    fn metric_insert_sql(&self) -> &'static str {
        Self::METRIC_INSERT_SQL
    }
    fn soql_to_sql(&self, soql: &str, from: i64, to: i64, env: Option<&str>) -> Result<String, guatx_core::store::StoreError> {
        SqlcipherEventStore::soql_to_sql(self, soql, from, to, env).map_err(guatx_core::store::StoreError::Emit)
    }
    fn soql_to_sql_masked(&self, soql: &str, from: i64, to: i64, env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet) -> Result<String, guatx_core::store::StoreError> {
        // #45 : le tier CHAUD SQLite SAIT émettre le masque -> il OVERRIDE le fail-closed par défaut du SPI
        // neutre et délègue au chemin masqué interne (choke-point `soql_field`, byte-identique au HOT path
        // role-scopé de prod). VIDE -> identique à `soql_to_sql` (mode 0).
        SqlcipherEventStore::soql_to_sql_masked(self, soql, from, to, env, masks).map_err(guatx_core::store::StoreError::Emit)
    }
    fn query_soql(&self, db_path: &str, soql: &str, from: i64, to: i64, env: Option<&str>, budget_ms: u64, qid: Option<&str>) -> Result<Value, guatx_core::store::StoreError> {
        SqlcipherEventStore::query_soql(self, db_path, soql, from, to, env, budget_ms, qid).map_err(guatx_core::store::StoreError::Backend)
    }
    fn query_soql_masked(&self, db_path: &str, soql: &str, from: i64, to: i64, env: Option<&str>, budget_ms: u64, qid: Option<&str>, masks: &guatx_core::soql::FieldMaskSet) -> Result<Value, guatx_core::store::StoreError> {
        // #45 : émission MASQUÉE (choke-point interne) PUIS exécution read-only bornée — même exécuteur que le
        // `query_soql` non masqué. VIDE -> byte-identique au chemin non masqué.
        let sql = SqlcipherEventStore::soql_to_sql_masked(self, soql, from, to, env, masks).map_err(guatx_core::store::StoreError::Emit)?;
        run_query_ex(db_path, &sql, budget_ms, qid).map_err(guatx_core::store::StoreError::Backend)
    }
}

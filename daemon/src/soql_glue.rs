//! Glue GXQL côté daemon (le compilateur lui-même vit dans `guatx_core::soql`). Regroupe : tokenisation
//! de la barre de recherche (`search_tokens`/`field_col`), contrat CIM (`CIM_*` + `cim_category_ok`),
//! whitelist `HOT_FIELDS` des champs JSON portant un index d'expression, toggles cachés (`FTS_FIELDS_ON`)
//! et le point d'entrée unique d'émission GXQL->SQL `soql_to_sql_x` (traverse le store). Statics OnceLock +
//! accesseurs. MT-KEY: par db_path. Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// Tokenise la barre en respectant les guillemets " (regex="motif avec espaces") ; ' et ( restent
// dans le token (échappement SQL fait par chaque handler, ( = groupe regex). Pas de split sur l'espace
// à l'intérieur des guillemets.
pub(crate) fn search_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in s.chars() {
        match c {
            '"' => in_q = !in_q,
            c if c.is_whitespace() && !in_q => { if !cur.is_empty() { out.push(std::mem::take(&mut cur)); } }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() { out.push(cur); }
    out
}

// Champs filtrables depuis la barre (alias -> colonne réelle). Whitelist = anti-injection de nom de
// colonne ; regex `~` / joker `*` / exact s'appliquent ensuite à N'IMPORTE lequel (host, src_ip,
// message/event, source, category, dst_ip, url, xff, fields).
pub(crate) fn field_col(name: &str) -> Option<&'static str> {
    Some(match name {
        "source" => "source",
        "category" | "cat" => "category",
        "severity" | "sev" => "severity",
        "src_ip" | "ip" => "src_ip",
        "dst_ip" => "dst_ip",
        "host" => "host",
        "message" | "msg" | "event" => "message",
        "url" => "url",
        "xff" => "xff",
        "fields" | "field" => "fields",
        _ => return None,
    })
}
// CONTRAT CIM déplacé dans le cœur partagé (P1-M2) : `CIM_VERSION`/`CIM_CATEGORIES`/`CIM_CORE_FIELDS`/
// `CIM_ACTION_VOCAB` + le validateur pur `cim_category_ok` vivent désormais dans `guatx_core::cim`
// (constantes pures + validateur, ZÉRO rusqlite). On les RÉ-EXPORTE ici (`pub(crate)`) : le glob
// `soql_glue::*` (main.rs) les rend accessibles au daemon comme avant -> aucun call-site changé. Le
// parser du DSL d'ingest (spécifique ingest) RESTE au daemon ; seul le vocabulaire de contrat remonte.
// `CIM_CATEGORIES`/`CIM_ACTION_VOCAB` n'étaient utilisés que par le test (d'où l'`allow(dead_code)`
// d'origine) -> on préserve l'intention via `unused_imports` pour les builds non-test.
#[allow(unused_imports)]
pub(crate) use guatx_core::cim::{
    cim_category_ok, compliance_framework_ok, CIM_ACTION_VOCAB, CIM_CATEGORIES, CIM_CORE_FIELDS,
    CIM_VERSION, COMPLIANCE_FRAMEWORKS,
};

// ── GARDE-FOU CIM à la COMPILATION (ceinture ET bretelles avec le test runtime
// `cim_const_mirror_matches_config_schema`) ──────────────────────────────────────────────
// `build.rs` extrait la `"version"` du contrat CIM EMBARQUÉ dans le dépôt plume
// (`config.d/cim/cim.v1.json`) et l'émet ici en `CIM_CONFIG_VERSION`. On const-assert qu'elle
// égale `guatx_core::cim::CIM_VERSION` du cœur LINKÉ. Si un build lie un cœur STALE/faux (version
// divergente — ce qui a déjà coûté un cycle de diagnostic : scaffold contre un core v1.1 vs le
// v1.2 déployé), la COMPILATION ÉCHOUE ici avec le message ci-dessous — plus jamais un simple
// échec de test. 100 % compile-time : `const _` n'émet aucun code, `const_str_eq` n'est jamais
// appelée au runtime -> binaire byte-identique.
include!(concat!(env!("OUT_DIR"), "/cim_config_version.rs"));

// `==` sur `&str` n'est pas disponible en contexte const -> comparaison octet-à-octet.
const fn const_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

const _: () = {
    assert!(
        const_str_eq(CIM_CONFIG_VERSION, guatx_core::cim::CIM_VERSION),
        "CIM version mismatch: config.d/cim/cim.v1.json vs linked guatx_core::cim::CIM_VERSION \
         — you are building against a STALE/wrong core"
    );
};

/// Égalité de deux listes de chaînes À LA COMPILATION. Sert à rendre INEXPRIMABLE une divergence
/// entre une constante de plume et son miroir dans le crate `guatx-core` — même geste que
/// l'assertion `CIM_CONFIG_VERSION` ci-dessus.
const fn const_slice_str_eq(a: &[&str], b: &[&str]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if !const_str_eq(a[i], b[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// HOT_FIELDS EST DUPLIQUÉ DANS DEUX CRATES, ET LA DIVERGENCE ÉTAIT SILENCIEUSE (clé P10.2-c).
///
/// LE MÉCANISME, ÉTABLI LE 2026-08-05. plume crée UN index d'expression `idx_ev_f_{champ}` sur
/// `json_extract(fields,'$.{champ}')` PAR ENTRÉE de cette liste (aujourd'hui douze). Le compilateur
/// GXQL, lui, vit dans `guatx-core` (git-dep ÉPINGLÉE) et décide d'envelopper ou non d'un `CAST`
/// selon SA propre copie de `HOT_FIELDS` (`Schema::events().indexed_fields`). Ces index ne sont
/// appariables que parce que les deux listes sont AUJOURD'HUI byte-identiques, ORDRE COMPRIS.
///
/// Retirer un champ d'un côté seulement — ou en ajouter un — ferait émettre `CAST(json_extract(…))`
/// là où l'index porte la forme canonique : **tous les index deviendraient inutilisables en
/// recherche, SANS AUCUNE ERREUR DE BUILD**, et la seule trace serait une lenteur inexpliquée.
/// (Mesuré ailleurs sur ce même sujet : la forme castée dégénère de SEARCH en SCAN, ×5.)
///
/// L'assertion ci-dessous rend cette dérive IMPOSSIBLE À COMPILER. C'est la même dérivation que
/// partout ici : on ne se souvient pas de synchroniser, on est empêché de désynchroniser.
const _: () = {
    assert!(
        const_slice_str_eq(HOT_FIELDS, guatx_core::soql::HOT_FIELDS),
        "HOT_FIELDS a DIVERGÉ entre plume et guatx-core : les index d'expression idx_ev_f_* \
         deviendraient inutilisables en recherche SANS erreur de build (le compilateur émettrait un \
         CAST que l'index ne peut pas apparier). Aligner les deux listes, ou retirer les index."
    );
};

// whitelist FERMÉE des champs chauds indexés par index expression (Phase 2 v41 : les 7 premiers ;
// v49 : +verb,resource,operation ; v50 : +dir,risk). Cardinalité bornée (énumérés/identités d'un parc
// borné), tous TEXTUELS. ORDRE SIGNIFICATIF : l'assertion const ci-dessus compare ÉLÉMENT PAR ÉLÉMENT
// avec la copie de `guatx-core` -> tout ajout se fait EN QUEUE, des deux côtés, dans le même ordre.
//   v49 — FILTRES chauds des sources d'audit (kube-audit/vault-audit), validés EXPLAIN SCAN->SEARCH sur
//   l'instance : `verb` (RBAC : verb=delete/deletecollection), `resource` (qui touche secrets : resource=
//   secrets), `operation` (vault : operation=delete/create). Petits index partiels (kube-audit ~60k,
//   vault-audit ~15k lignes) -> RAM négligeable, servent la RÉPONSE-INCIDENT (rares mais doivent être
//   instantanés). DÉLIBÉRÉMENT EXCLUS : champs NUMÉRIQUES (status/dport/code) — les parsers de plume
//   stockent TOUTE valeur de champ en CHAÎNE JSON (`parsers.rs`, y compris la re-sérialisation d'un
//   nombre), donc `json_extract` rend du TEXT ; le `CAST(... AS REAL)` que le compilateur émet pour un
//   champ ABSENT de cette liste est CE QUI REND `search dport=443` JUSTE. Inscrire un champ numérique
//   ici retire ce CAST et, l'ordre inter-types de SQLite étant NULL < INTEGER/REAL < TEXT < BLOB, la
//   recherche devient SILENCIEUSEMENT VIDE. Et path/exe/key (haute cardinalité / firehose auditd 2,6M
//   -> ~73 Mo/index, budget 2 Go) — leur GROUP-BY est servi par les rollups v49.
//
//   v50 (2026-08-05) — `dir` ET `risk` ENTRENT, ET C'EST UNE RÉPARATION, PAS UN AJOUT DE CONFORT.
//   Ce commentaire a dit DEUX choses fausses de suite sur `dir`, dans deux directions opposées, et
//   il faut que la troisième version dise ce qui a été VÉRIFIÉ :
//     1. il a d'abord affirmé « exclu : déjà auto-indexé (idx_ev_auto_dir) » — faux comme
//        JUSTIFICATION : depuis que le compilateur GXQL a migré dans `guatx-core`, les crochets de
//        comptage de chaleur sont du code mort (`warning: function autoindex_note is never used`),
//        donc le mécanisme ne POUVAIT PLUS rien promouvoir. S'appuyer sur lui, c'était s'appuyer sur
//        un entretien qui n'avait plus lieu ;
//     2. il a ensuite affirmé, au retrait de ce mécanisme (P6.8), que `dir` « N'EST INDEXÉ PAR RIEN »
//        et qu'aucun `idx_ev_auto_*` n'existait — faux comme CONSTAT : `idx_ev_auto_dir`,
//        `idx_ev_auto_risk` et `idx_ev_auto_vtype` existaient RÉELLEMENT en production (ils sont
//        RELEVÉS, avec leur taille, dans `bench/profile-prod.json`, `provenance: measured`,
//        2026-07-30) et la purge de fond du retrait les a droppés. L'instrument qui avait servi à
//        conclure à leur absence (`db-stats --par-objet`, top 10) ne montre rien sous ~22 Mio : il ne
//        pouvait pas prouver une absence. Ne pas voir n'est pas mesurer — d'autant que le relevé qui
//        les montrait était DÉJÀ dans le dépôt.
//     La leçon commune aux deux : « le mécanisme est cassé AUJOURD'HUI » et « il n'a JAMAIS rien
//     produit » ne sont pas la même phrase. La première est prouvée ; la seconde ne l'est pas, et
//     trois index portant très exactement le nom qu'il émet la contredisent.
//   CE QUI LES FAIT ENTRER ICI, ET PAS AILLEURS. Deux de ces trois champs sont interrogés par du
//   contenu LIVRÉ, donc leur chaleur est DÉMONTRÉE et non supposée. Et la preuve la plus forte n'est
//   PAS le catalogue : les règles de `config.d/rules/catalog/` sont livrées `enabled=false` (une
//   bibliothèque qu'un exploitant active). Ce qui TOURNE sans que personne n'active rien, c'est le
//   contenu SEEDÉ, et il filtre sur ces deux champs :
//     `dir`  — règles d'alerte seedées, ACTIVES, ré-évaluées périodiquement : « Port-scan détecté
//              (nft PORTSCAN) » et la règle RBA « reconnaissance / port-scan » (`source=portscan
//              dir=inbound`, T1046, seeds.rs) ; « Egress externe sur port inhabituel (>1024) » et
//              « Égress: beaconing C2 probable » (`dir=outbound`, T1071) ; PLUS trois panneaux seedés
//              (« Destinations externes », « Processus sortants », « Ports de destination ») et des
//              migrations qui ré-écrivent ces requêtes (migrate.rs). PLUS trois règles du catalogue.
//     `risk` — le panneau seedé « Buckets exposés (PUBLIC) » (`source=minio kind=bucket risk=public`,
//              seeds.rs) PLUS la règle de catalogue `cl-minio-public-bucket.json`.
//   Un champ que du contenu livré ET ACTIF filtre appartient à la liste FERMÉE, MAINTENUE et vérifiée
//   par l'assertion ci-dessus — pas à un mécanisme piloté par la chaleur d'usage, qui N'EXISTE PLUS et
//   qui, SURTOUT, ne pouvait plus rien promouvoir depuis que le compilateur GXQL a migré dans
//   `guatx-core` (ses crochets y sont devenus du code mort). Formulation choisie AVEC SOIN : ce
//   paragraphe a d'abord écrit « n'a jamais rien produit », c'est-à-dire exactement la phrase que le
//   point 2 ci-dessus vient de DÉMONTER vingt lignes plus haut — trois `idx_ev_auto_*` sont relevés
//   dans `bench/profile-prod.json`. Ce qui est PROUVÉ est plus étroit que l'absolu, et c'est la
//   version étroite qui doit être écrite. `vtype` n'a AUCUN usage livré : il n'est délibérément PAS restauré (on ne
//   paie pas un index pour un champ que rien n'interroge).
//   CONFORMES À LA RÈGLE CI-DESSUS (ce n'est pas une exception) : tous deux sont TEXTUELS et de
//   cardinalité bornée — `dir` vaut inbound|outbound (posé en CHAÎNE JSON par `collectors/conntrack.sh`
//   et `collectors/portscan.sh`), `risk` vaut admin|rw|ro|diag|public (`minio.sh`, `dataacl.sh`,
//   `kube-rbac.sh`). Aucun émetteur livré ne les écrit en NOMBRE, donc la suppression du
//   `CAST(... AS REAL)` qu'entraîne leur présence ici ne peut pas rendre une recherche silencieusement
//   vide — c'est le mode d'échec qui interdit les champs numériques ci-dessus, et il ne s'applique pas.
//   COÛT — MESURÉ, PAS ESTIMÉ. `EXPR_INDEX_FIELDS` (maintenance.rs) EST un alias de cette liste -> ces
//   deux entrées font naître `idx_ev_f_dir` et `idx_ev_f_risk` en tâche de fond au prochain boot. Leur
//   DDL est celle des `idx_ev_auto_*` droppés AU NOM PRÈS — même table, même expression, même prédicat
//   partiel `WHERE json_extract(…) IS NOT NULL` — et elle n'a jamais varié sur toute la vie du
//   mécanisme retiré. On recrée donc le MÊME objet, dont la taille A ÉTÉ RELEVÉE en production dans
//   `bench/profile-prod.json` (`provenance: measured`, 2026-07-30, 1 397 446 événements) :
//       idx_ev_auto_dir   4 616 192 o = 4,40 Mio   (`dir`  sur 234 519 lignes, soit 16,8 %, card. 2)
//       idx_ev_auto_risk     12 288 o = 0,01 Mio   (`risk` sur 452 lignes, card. 7)
//   soit 4,41 Mio à restaurer, = 1,5 % des 291,5 Mio d'index sur `event` du même relevé. C'est le
//   partiel qui rend `dir` bon marché : 234 519 lignes indexées et non les 1,4 M de la table.
//   POURQUOI L'INSTRUMENT NE LES VOYAIT PAS : le 10e objet du classement est `idx_event_ts` à
//   22,75 Mio — le top 10 de `db-stats --par-objet` a un PLANCHER autour de 22 Mio, et `idx_ev_auto_dir`
//   était CINQ FOIS dessous. Le relevé par objet existait pourtant déjà : c'est le mauvais instrument
//   qui a été interrogé, pas une donnée manquante.
//   ET `vtype` : mesuré à 733 184 o pour une CARDINALITÉ DE 1 — un index sur une colonne mono-valuée
//   n'a aucune sélectivité. Deuxième raison, indépendante de l'absence d'usage, de ne pas le restaurer.
pub(crate) const HOT_FIELDS: &[&str] = &[
    "action", "user", "owner", "kind", "ns", "role", "scope",
    "verb", "resource", "operation",
    "dir", "risk",
];

/// Toggle maître Phase 1 (PLUME_FTS_FIELDS) mis en cache au boot — le search libre bascule sur
/// event_fields_fts (UNION avec event_fts) au lieu de `message LIKE '%tok%'`. 0 (OFF) par défaut.
pub(crate) static FTS_FIELDS_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub(crate) fn fts_fields_enabled() -> bool {
    FTS_FIELDS_ON.load(std::sync::atomic::Ordering::Relaxed)
}
/// Toggle Phase B (PLUME_SOQL_PRUNE_MESSAGE) — opt-in de l'ÉLAGAGE DE PROJECTION `message` du cœur
/// (`Schema::with_message_pruning` / gate `message_prunable`). OFF par défaut -> `with_message_pruning(false)`
/// -> SELECT de base STRICTEMENT INCHANGÉ = `Schema::events()` d'aujourd'hui (mode 0 byte-identique, invariant
/// ABSOLU). ON -> le compilo peut retirer `message` du SELECT QUAND prouvé inutile en aval (sinon conservé,
/// défaut conservateur) : jamais une ligne de résultat en moins, seulement une matérialisation RAM bornée.
/// Lu UNE FOIS (OnceLock) au premier compile via `cfg`/`load_config` (env PLUME_* > conf > défaut) — JAMAIS
/// un `env::var` par requête (chemin chaud). Posé au choke-point store (query `/api/query` + détection).
static SOQL_PRUNE_MESSAGE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
pub(crate) fn soql_prune_message() -> bool {
    *SOQL_PRUNE_MESSAGE.get_or_init(|| {
        let conf = load_config();
        matches!(cfg(&conf, "PLUME_SOQL_PRUNE_MESSAGE", "").trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
    })
}
// ═══════════════════════════════════════════════════════════════════════════════════════════════
//  P10.7-a — LA BARRE `/api/search` MENTAIT PAR SILENCE, ET LA GARDE ÉCRITE POUR ÇA N'ÉTAIT PAS CÂBLÉE.
//
//  LE DÉFAUT, MESURÉ le 2026-08-09 contre un moteur FTS5 (saisie -> ce que rend le moteur) :
//      10.0.0.1       -> fts5: syntax error near "."        /usr/bin/dash -> fts5: syntax error near "/"
//      kube-audit     -> no such column: audit              user:root     -> no such column: user
//      exec(1)        -> fts5: syntax error near "exec"
//  `handlers/search.rs` AVALAIT l'erreur et renvoyait `{"results": []}`. Un analyste qui cherche une
//  adresse IP dans son SOC lisait « rien ne correspond » là où le moteur avait dit « je refuse ».
//
//  CE QUI EST SUPPRIMÉ ICI, ET POURQUOI. `fts_safe(tok)` listait À LA MAIN les caractères « sûrs »
//  (`alphanumérique | _ | . | / | @`) et promettait en commentaire un repli LIKE. Elle n'avait AUCUN
//  appelant (`grep -rn fts_safe daemon/src/ web/` = 1 occurrence, sa définition ; témoin positif :
//  `search_tokens` = 5). Elle était AUSSI fausse : elle autorisait `.`, `/` et `@` — que le moteur
//  REFUSE — et interdisait `*`, `+`, `^` — qu'il ACCEPTE.
//
//  POURQUOI AUCUNE LISTE DE CARACTÈRES NE PEUT ÊTRE JUSTE. Balayage des 95 ASCII imprimables sous la
//  forme `a<c>b` (2026-08-09) : 28 refusés (`! " # $ % & ' ( ) , - . / : ; < = > ? @ [ \ ] ` { | } ~`),
//  67 acceptés. Mais l'appartenance DÉPEND DE LA POSITION — `^exec` est accepté, `exec^` est un
//  « syntax error » ; `a*b` passe, `*` seul est « unknown special query » — et elle dépend du SCHÉMA :
//  `message:x` est valide sur `event_fts` (qui a cette colonne) et invalide sur `event_fields_fts`
//  (qui ne l'a pas), donc la MÊME saisie est acceptable ou non selon le toggle `PLUME_FTS_FIELDS`.
//  Une liste ne peut pas porter ça. On DEMANDE donc au moteur, on n'énumère pas — et le balayage
//  ci-dessus n'est cité que comme CONSTAT : il est REFAIT à chaque exécution des tests, contre le
//  moteur LIÉ (SQLCipher vendoré, SQLite 3.39.4), pas contre le `sqlite3` de la machine qui l'a servi.
//
//  L'ARBITRAGE. (b) ÉCHAPPER d'abord : entre guillemets doubles, FTS5 lit une PHRASE et plus une
//  expression -> la capacité est PRÉSERVÉE au lieu d'être dégradée, et le coût est celui de l'index
//  (mesuré 2026-08-09, 1 M de lignes, base EN CLAIR, cache chaud : phrase citée 0,020 s contre
//  0,49 s pour le `LIKE '%…%'` équivalent, ×24). (a) PAS de repli LIKE : `/api/query` en GXQL EST
//  déjà ce repli (le cœur compile un terme libre en `message LIKE '%pat%'`) et il tourne sous un
//  budget interactif de 60 s, là où cette route est bornée à 5 s (`READ_WATCHDOG_BUDGET_MS`) — un
//  repli aveugle ici convertirait « aucun résultat » en « interrompu ». (c) TOUJOURS : le handler
//  remonte l'erreur brute du moteur au lieu de la manger.
//
//  CE QUE LA GARDE COÛTE, MESURÉ le 2026-08-09 (12 cœurs, profil `release`, moyenne sur 200 appels ;
//  le profil `debug` est ~4× plus lent, ce qui est le régime des tests, pas celui de la production) :
//      dérivation des miroirs   279 µs  (une fois par recherche portant du plein-texte)
//      plan, 1 terme accepté     58 µs      plan, 1 terme littéralisé  139 µs
//      plan, 3 termes           550 µs
//  soit 0,34 ms à 0,83 ms ajoutés à une route dont le budget de lecture est de 5 000 ms et dont la
//  requête FTS elle-même se compte en dizaines de millisecondes sur la base de production. La sonde
//  est une base EN MÉMOIRE d'UNE ligne : elle ne touche ni le disque, ni le pool de lecture, ni le
//  sémaphore de concurrence.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// Nom de la table du miroir. Fixe : le miroir est une base à lui tout seul.
const FTS_MIRROR_TABLE: &str = "sonde_fts";

/// MIROIR EN MÉMOIRE d'un index FTS5 RÉEL — l'ORACLE de la garde. Mêmes colonnes, même tokenizer que
/// la table interrogée, lus DANS LA BASE VIVANTE : le jour où l'une des deux change, le miroir change
/// avec elle, sans que personne n'ait à réécrire une liste.
pub(crate) struct FtsMirror {
    conn: Connection,
    doc_col: String,
}

impl FtsMirror {
    /// Dérive le miroir de la table FTS5 `table`. Colonnes : `PRAGMA table_info` (les VRAIES, dans
    /// l'ordre déclaré). Tokenizer : la clause `tokenize=…` du DDL de `sqlite_master`, RECOPIÉE
    /// verbatim — on ne l'interprète pas. `None` = table absente/illisible : l'appelant n'a alors pas
    /// d'oracle et doit le DIRE (cf. `fts_plan`), jamais deviner.
    pub(crate) fn derive(src: &Connection, table: &str) -> Option<Self> {
        let qtable = format!("\"{}\"", table.replace('"', "\"\""));
        let ddl: String = src
            .query_row("SELECT sql FROM sqlite_master WHERE type='table' AND name=?1", params![table], |r| r.get(0))
            .ok()?;
        let cols: Vec<String> = {
            let mut st = src.prepare(&format!("PRAGMA table_info({qtable})")).ok()?;
            let it = st.query_map([], |r| r.get::<_, String>(1)).ok()?;
            it.collect::<rusqlite::Result<Vec<_>>>().ok()?
        };
        let doc_col = cols.first()?.clone();
        let decl = cols.iter().map(|c| format!("\"{}\"", c.replace('"', "\"\""))).collect::<Vec<_>>().join(",");
        let tok = fts_tokenize_clause(&ddl).map(|t| format!(",{t}")).unwrap_or_default();
        let conn = Connection::open_in_memory().ok()?;
        // Miroir à contenu PROPRE (ni `content=`, ni `prefix=`) : il doit accepter un INSERT/DELETE
        // pour la sonde de tokenisation, et ces deux options ne changent NI la grammaire de requête
        // NI le découpage en tokens — seulement où le contenu est lu et quels index annexes existent.
        conn.execute_batch(&format!("CREATE VIRTUAL TABLE {FTS_MIRROR_TABLE} USING fts5({decl}{tok})")).ok()?;
        Some(Self { conn, doc_col })
    }

    /// Le moteur ACCEPTE-t-il cette expression MATCH sur ce jeu de colonnes ? C'est le parseur FTS5
    /// LIÉ qui répond. `Err` porte son message BRUT (celui qu'on remontera à l'analyste).
    pub(crate) fn accepts(&self, expr: &str) -> Result<(), String> {
        // `prepare_cached` : la sonde est appelée plusieurs fois par recherche (un étage × un token) et
        // le SQL est CONSTANT — le recompiler à chaque appel doublait le coût de la garde (mesuré).
        self.conn
            .prepare_cached(&format!("SELECT count(*) FROM {FTS_MIRROR_TABLE} WHERE {FTS_MIRROR_TABLE} MATCH ?1"))
            .and_then(|mut st| st.query_row(params![expr], |r| r.get::<_, i64>(0)))
            .map(|_: i64| ())
            .map_err(|e| e.to_string())
    }

    /// Cette expression RETROUVE-T-ELLE le texte dont elle est censée être la traduction ? On indexe
    /// `texte` seul — il est donc en TÊTE de son document, la position la plus FAVORABLE — puis on lui
    /// soumet `expr`. C'est la question qui compte : « le moteur accepte » n'a jamais voulu dire « le
    /// moteur peut le trouver », et c'est cette confusion qui laissait passer un vide silencieux.
    ///
    /// DEUX CAS MESURÉS QUE L'ACCEPTATION SEULE NE VOIT PAS (2026-08-09) :
    ///   • la PHRASE VIDE. Un terme dont le tokenizer ne tire aucun token (`...`, `-`, `_`) devient
    ///     `""`, syntaxiquement valide : seule, elle rend 0 ligne (« rien ne correspond ») ; EN
    ///     CONJONCTION (`"..." execve`), elle est purement IGNORÉE et la réponse est ÉLARGIE en
    ///     silence à ce que rend `execve` seul. Deux mensonges pour un même terme.
    ///   • l'OPÉRATEUR ATTRAPÉ AU MILIEU D'UN MOT. `a^b` est ACCEPTÉ sans la moindre erreur, mais `^`
    ///     y est l'ancre « premier token de la colonne » : l'expression demande « b en tête » et ne
    ///     retrouve donc JAMAIS une ligne contenant `a^b`. Aucune liste de caractères refusés n'aurait
    ///     pu l'attraper — le moteur ne refuse rien ici. C'est le balayage ASCII des tests qui l'a vu.
    pub(crate) fn retrieves(&self, expr: &str, texte: &str) -> bool {
        let ins = format!("INSERT INTO {FTS_MIRROR_TABLE}(\"{}\") VALUES(?1)", self.doc_col.replace('"', "\"\""));
        let pose = self
            .conn
            .prepare_cached(&format!("DELETE FROM {FTS_MIRROR_TABLE}"))
            .and_then(|mut st| st.execute([]))
            .and_then(|_| self.conn.prepare_cached(&ins).and_then(|mut st| st.execute(params![texte])));
        if pose.is_err() {
            return false;
        }
        self.conn
            .prepare_cached(&format!("SELECT count(*) FROM {FTS_MIRROR_TABLE} WHERE {FTS_MIRROR_TABLE} MATCH ?1"))
            .and_then(|mut st| st.query_row(params![expr], |r| r.get::<_, i64>(0)))
            .map(|n: i64| n == 1)
            .unwrap_or(false)
    }
}

/// Extrait la clause `tokenize=…` d'un DDL FTS5, VERBATIM (guillemets compris), ou `None` si la table
/// s'en remet au tokenizer par défaut. On la RECOPIE au lieu de la relire : `unicode61
/// remove_diacritics 2 tokenchars '_-.:/@'` porte des quotes imbriquées qu'aucune réécriture n'a de
/// raison de traverser.
pub(crate) fn fts_tokenize_clause(ddl: &str) -> Option<String> {
    let at = ddl.to_ascii_lowercase().find("tokenize")?;
    let rest = &ddl[at..];
    let after = rest[rest.find('=')? + 1..].trim_start();
    let chars: Vec<char> = after.chars().collect();
    let q = *chars.first()?;
    if q != '\'' && q != '"' {
        return None; // fts5 exige une chaîne ; autre chose = DDL qu'on ne sait pas lire -> pas de miroir
    }
    let mut i = 1;
    while i < chars.len() {
        if chars[i] == q {
            if chars.get(i + 1) == Some(&q) {
                i += 2; // guillemet DOUBLÉ = littéral, la clause continue
                continue;
            }
            return Some(format!("tokenize={}", chars[..=i].iter().collect::<String>()));
        }
        i += 1;
    }
    None
}

/// Rend un terme LITTÉRAL pour FTS5. VÉRIFIÉ contre le moteur (`fts5_quoting_is_a_literal_phrase`),
/// pas supposé : entre guillemets doubles, FTS5 lit une PHRASE (suite de tokens adjacents) et plus
/// une expression — aucun caractère n'y est un opérateur — et un `"` interne se DOUBLE.
pub(crate) fn fts_quote(tok: &str) -> String {
    format!("\"{}\"", tok.replace('"', "\"\""))
}

/// Ce que la barre peut demander au moteur pour une saisie donnée.
pub(crate) enum FtsPlan {
    /// Expression MATCH à émettre. `literal` = les termes qui ont dû être rendus LITTÉRAUX pour que
    /// le moteur les accepte : leurs caractères de syntaxe ne sont plus des opérateurs, et l'analyste
    /// doit l'apprendre par la réponse (sinon on aurait « réparé » sa requête dans son dos).
    Match { expr: String, literal: Vec<String> },
    /// AUCUNE expression MATCH ne peut porter ce terme : même en phrase citée — la forme la plus
    /// littérale qui existe — il ne retrouve pas son propre texte, parce que le tokenizer de tous les
    /// index interrogés n'en tire aucun token. C'est le seul cas que l'échappement ne sauve pas, et il
    /// doit être DIT : servir un tableau vide serait le mensonge que P10.7-a ferme.
    Unindexable { token: String },
}

/// LA GARDE. Traduit les tokens de la barre en une expression que le moteur ACCEPTE, en préservant au
/// maximum ce que l'analyste a écrit. Trois étages, du plus fidèle au plus littéral ; l'oracle de
/// chaque décision est `mirrors`, c'est-à-dire le moteur lui-même :
///   1. VERBATIM — l'expression telle quelle. Tout ce qui marche aujourd'hui (`a OR b`, `err*`,
///      `(x OR y)`, `NEAR(…)`) continue de marcher, à l'octet près.
///   2. LITTÉRALISATION SÉLECTIVE — seuls les termes que le moteur refuse SEULS sont mis entre
///      guillemets. C'est ce qui garde `fail*` opérant dans `10.0.0.1 fail*`.
///   3. LITTÉRALISATION TOTALE — filet, pour les saisies dont les morceaux ne sont fautifs qu'ensemble.
/// Une saisie ENTRE GUILLEMETS reste une PHRASE à tous les étages : un token porteur d'un blanc ne
/// peut venir que de là (`search_tokens` ne coupe sur un blanc que HORS guillemets), c'est donc une
/// propriété DÉRIVÉE du tokeniseur de la barre, pas une devinette.
pub(crate) fn fts_plan(tokens: &[String], mirrors: &[FtsMirror]) -> FtsPlan {
    let phrase = |t: &String| t.chars().any(char::is_whitespace);
    let build = |lit: &dyn Fn(&String) -> bool| -> (String, Vec<String>) {
        let mut literal = Vec::new();
        let mut parts = Vec::with_capacity(tokens.len());
        for t in tokens {
            if lit(t) {
                literal.push(t.clone());
                parts.push(fts_quote(t));
            } else {
                parts.push(t.clone());
            }
        }
        (parts.join(" "), literal)
    };
    // PAS D'ORACLE (aucun index FTS5 lisible) -> on ne DÉCIDE rien : verbatim, et l'erreur du moteur
    // remontera telle quelle. Une garde qui devine sans mesurer est exactement ce qu'on retire ici.
    if mirrors.is_empty() {
        let (expr, literal) = build(&phrase);
        return FtsPlan::Match { expr, literal };
    }
    let accepts = |e: &str| mirrors.iter().all(|m| m.accepts(e).is_ok());
    // Une pièce de GRAMMAIRE (`(`, `a)`, `OR`, `AND`…) n'est acceptée par AUCUN index isolément —
    // mesuré, pas énuméré. Elle ne porte pas de texte : c'est l'expression d'ensemble qui la valide.
    let grammaire = |r: &str| mirrors.iter().all(|m| m.accepts(r).is_err());
    // Un TERME, lui, doit retrouver son propre texte dans AU MOINS un des index interrogés (les deux
    // sont en UNION dans le SQL : trouvable dans l'un suffit).
    let porte = |r: &str, raw: &str| mirrors.iter().any(|m| m.retrieves(r, raw));
    let stages: [Box<dyn Fn(&String) -> bool>; 3] = [
        Box::new(&phrase),
        Box::new(|t| phrase(t) || !accepts(t) || !porte(t, t)),
        Box::new(|_| true),
    ];
    let dernier = stages.len() - 1;
    for (i, stage) in stages.iter().enumerate() {
        let (expr, literal) = build(&**stage);
        if !accepts(&expr) {
            continue;
        }
        // CHAQUE terme doit pouvoir retrouver son propre texte tel qu'il sera émis. Un étage qui
        // échoue ici n'est pas une erreur : c'est le signal qu'il faut littéraliser davantage.
        let fautif = tokens.iter().find(|t| {
            let rendu = if stage(t) { fts_quote(t) } else { (*t).clone() };
            !grammaire(&rendu) && !porte(&rendu, t)
        });
        match fautif {
            None => return FtsPlan::Match { expr, literal },
            // Dernier étage : même en phrase citée, ce terme ne se retrouve pas lui-même. Rien ne peut
            // le chercher — on le DIT.
            Some(t) if i == dernier => return FtsPlan::Unindexable { token: t.clone() },
            Some(_) => continue,
        }
    }
    // Le moteur refuse jusqu'au littéral total (inatteignable à notre connaissance : une phrase citée
    // est toujours grammaticale). On rend le verbatim ; le filet (c) du handler dira SON message.
    let (expr, literal) = build(&phrase);
    FtsPlan::Match { expr, literal }
}

/// Les miroirs des index que la barre interroge VRAIMENT. `fields` = toggle Phase 1
/// (`event_fields_fts` en UNION) : quand il est ON, une expression doit être acceptable par LES DEUX
/// schémas, et c'est cette fonction qui fait que la garde le sait.
pub(crate) fn fts_bar_mirrors(conn: &Connection, fields: bool) -> Vec<FtsMirror> {
    let mut v = Vec::new();
    if let Some(m) = FtsMirror::derive(conn, "event_fts") {
        v.push(m);
    }
    if fields {
        if let Some(m) = FtsMirror::derive(conn, "event_fields_fts") {
            v.push(m);
        }
    }
    v
}

// Colonnes RÉELLES de la table event (le reste vit dans le JSON `fields`).
pub(crate) const EVENT_COLS: &[&str] = &["ts", "host", "source", "category", "severity", "src_ip", "dst_ip", "url", "xff", "message", "fields", "dedup", "id"];

// Découpe sur les pipes de PREMIER niveau (ignore les `|` à l'intérieur des crochets [ ... ]).
// soql_split_pipes : SUPPRIMÉ (P1-H3) — copie locale byte-identique de
// guatx_core::soql::soql_split_pipes. Sites d'appel fully-qualifiés.

// ═══════════════════════════════════════════════════════════════════════════════════════════════
//  ALIAS DE LECTURE CIM — `exec` ⊃ `process`.  DETTE DE MIGRATION, PÉREMPTION 2027-07-23.
// ───────────────────────────────────────────────────────────────────────────────────────────────
//  LE DÉFAUT. Les deux collecteurs Windows (`collectors/windows/plume-collector.ps1`,
//  `agent/src/source/windows.rs`) ont déclaré `category='process'` pour la création de processus
//  (EventID 4688) jusqu'au 2026-07-23. `process` n'appartient PAS à `CIM_CATEGORIES` ; le nom
//  canonique de la création de processus en CIM v1.3 est `exec`. Les collecteurs émettent `exec`
//  désormais.
//
//  POURQUOI UN ALIAS ET PAS UNE MIGRATION. La rétention est de 365 jours et le tier froid est
//  SCELLÉ (Parquet chiffré + identité de seal, jamais réécrit) : l'historique portant `process` est
//  IMMUABLE par construction. Renommer la catégorie côté collecteurs sans rien d'autre rendrait
//  toute règle `category=exec` AVEUGLE sur cet historique. La réconciliation se fait donc à la
//  LECTURE, sans toucher une seule ligne stockée.
//
//  PÉREMPTION — 2027-07-23. Dernier événement `process` émis : 2026-07-23 (bascule des collecteurs).
//  Rétention 365 jours -> le dernier Parquet le portant sort de rétention le 2027-07-23. Après cette
//  date (une fois la purge passée), ce bloc ENTIER se supprime, avec ses SEULS dépendants (mesurés) :
//  `ingest/store.rs` ×3, `handlers/search.rs` ×1, la garde `carries_cim_read_alias` de
//  `cold_store/planner.rs` (et ses 2 sites), les tests `cim_read_alias_exec_finds_sealed_process_history`
//  et `cim_aliased_query_is_never_vectorized`, et la section 5.2 de `docs/CIM.md`.
//
//  CE QUE CE N'EST PAS. Pas un moteur de réécriture de requêtes : aucune table d'alias, aucune
//  config, aucun ENV. UNE équivalence, écrite en dur ci-dessous, inatteignable pour toute autre
//  valeur. La reconnaissance est DÉRIVÉE de la grammaire du cœur (mêmes opérateurs, même ordre,
//  même règle de quotation, mêmes étages que `table_conds`/`compile_where`), pas énumérée.
//
//  CONSÉQUENCES MESURÉES (lecture du cœur v0.2.1, pas une supposition) :
//   • `x in (a,b)` positif textuel est émis `COLLATE NOCASE` (`soql_in_cond`) -> une requête
//     `category=exec` devient insensible à la casse SUR CETTE COLONNE. SUR-match, jamais un
//     sous-match : aucun événement ne peut disparaître d'un résultat à cause de l'alias.
//   • `idx_event_category` (collation BINARY, `maintenance.rs`) n'est pas utilisable par un
//     `IN … COLLATE NOCASE` -> le filtre category cesse d'être servi par cet index ; la fenêtre `ts`
//     porte alors le balayage. Coût NON MESURÉ en charge réelle (pas d'accès prod ici).
//   • `extract_cold_dim_preds` (cold_store/seal.rs) REFUSE explicitement la forme ` IN ` -> aucun
//     élagage bloom/min-max sur category pour une requête aliasée -> tous les fichiers froids de la
//     fenêtre sont lus. CONSERVATEUR : jamais un fichier sauté à tort.
//
//  LIMITES CONNUES (non couvertes, délibérément — surface tenue au minimum) :
//   • une macro (`` `nom(args)` ``) dont le CORPS écrit `category=exec` : le cœur détend les macros
//     APRÈS ce pré-pass ; l'auteur de la macro écrit l'alias lui-même s'il en a besoin ;
//   • un `eventtype` (knowledge object) dont le filtre stocké écrit `category=exec` : détendu dans
//     le cœur, hors de portée d'ici ;
//   • `category!=exec` / `category=exec*` / `category=~exec` : formes NON aliasées (une négation
//     aliasée changerait le sens du prédicat ; un glob/regex est déjà l'outil de l'analyste).
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/// Nom CANONIQUE (CIM v1.3, `CIM_CATEGORIES`) de la création de processus.
pub(crate) const CIM_EXEC_CANON: &str = "exec";
/// Nom LEGACY hors taxonomie écrit par les collecteurs Windows jusqu'au 2026-07-23.
pub(crate) const CIM_EXEC_LEGACY: &str = "process";

/// L'UNIQUE équivalence, sous la forme que le cœur sait compiler dans un filtre de base ET dans un
/// `where` (clause `in (…)` entière — vérifié dans `table_conds` et `in_clause_whole`).
fn cim_exec_alias_clause() -> String {
    format!("category in ({CIM_EXEC_CANON},{CIM_EXEC_LEGACY})")
}

/// ALIAS DE LECTURE : rend le GXQL dans lequel toute ÉGALITÉ de filtre `category=exec` retrouve AUSSI
/// l'historique `category=process`. `Cow::Borrowed` (aucune allocation, aucune sémantique changée) dès
/// que la requête ne porte pas cette égalité — c'est le cas de la quasi-totalité du trafic.
pub(crate) fn cim_read_alias_exec(soql: &str) -> std::borrow::Cow<'_, str> {
    // Garde de coût : sans la sous-chaîne `exec` nulle part, il n'y a rien à faire (memchr).
    if !soql.contains(CIM_EXEC_CANON) {
        return std::borrow::Cow::Borrowed(soql);
    }
    match alias_pipeline(soql, 0) {
        Some(s) => std::borrow::Cow::Owned(s),
        None => std::borrow::Cow::Borrowed(soql),
    }
}

/// Parcourt le pipeline EXACTEMENT là où le cœur lit un filtre `champ=valeur` : le filtre de la BASE
/// `search` (étage 0, `table_conds`), l'étage `where` (`compile_where`, condition UNIQUE — d'où la
/// clause `in (…)` entière) et, récursivement, la sous-recherche entre crochets (recompilée au depth+1
/// par le cœur). Tout autre étage (`stats`/`eval`/`rename`/`fields`/`timechart`/…) est rendu VERBATIM :
/// `| eval category="exec"` n'est PAS un filtre et ne doit pas être touché. `None` = rien à réécrire.
/// Borne de récursion IDENTIQUE à `compile_depth` (> 3 = refusé par le cœur de toute façon).
fn alias_pipeline(text: &str, depth: u32) -> Option<String> {
    if depth > 3 {
        return None;
    }
    let stages = guatx_core::soql::soql_split_pipes(text);
    if stages.is_empty() {
        return None;
    }
    let mut changed = false;
    let mut out: Vec<String> = Vec::with_capacity(stages.len());
    for (i, stage) in stages.iter().enumerate() {
        let t = stage.trim();
        let rewritten = if i == 0 {
            // BASE. `table_base` (cœur) accepte DEUX écritures du MÊME filtre : `search <filtres>` et —
            // quand l'étage ne nomme AUCUNE base connue — le spec ENTIER pris comme filtres (`category=exec
            // | stats count` est une requête valide). On couvre les deux, sinon la seconde écriture rendrait
            // une réponse PARTIELLE en silence. `metric …` est la seule autre base du schéma `events()`
            // (`alts` est vide) : elle n'a pas de filtre `table_conds` -> laissée VERBATIM.
            match t.strip_prefix("search ") {
                Some(body) => alias_filter_body(body).map(|b| format!("search {b}")),
                None if t == "search" || t == "metric" || t.starts_with("metric ") => None,
                None => alias_filter_body(t),
            }
        } else if let Some(expr) = t.strip_prefix("where ") {
            alias_filter_body(expr).map(|e| format!("where {e}"))
        } else if let (Some(a), Some(b)) = (t.find('['), t.rfind(']')) {
            // SOUS-RECHERCHE (`append [search …]` / `join … [search …]`) : le cœur la recompile telle
            // quelle au depth+1 -> son filtre de base doit être aliasé de la MÊME façon.
            //
            // MAIS SEULEMENT SI C'EN EST UNE. Cette branche testait la seule PRÉSENCE de `[`…`]` sur
            // n'importe quel étage non-`where`, donc elle réécrivait aussi l'intérieur d'un LITTÉRAL :
            // mesuré, `eval label="[category=exec]"` devenait `eval label="[category in (exec,process)]"`.
            // Réécrire la CHAÎNE d'un utilisateur est une corruption silencieuse de sa requête — l'alias
            // n'a le droit de toucher qu'un FILTRE. On exige donc que l'étage soit `append`/`join` (les
            // deux seules étapes du cœur qui prennent une sous-recherche) ET que l'intérieur commence
            // par une base — sinon VERBATIM, ce que le commentaire promettait déjà.
            let is_subsearch = matches!(
                t.split_whitespace().next().map(str::to_ascii_lowercase).as_deref(),
                Some("append") | Some("join")
            ) && {
                let inner = t[a + 1..b].trim_start();
                inner == "search" || inner.starts_with("search ") || inner.starts_with("metric ")
            };
            (is_subsearch && b > a + 1)
                .then(|| alias_pipeline(&t[a + 1..b], depth + 1))
                .flatten()
                .map(|inner| format!("{}[{}]{}", &t[..a], inner, &t[b + 1..]))
        } else {
            None
        };
        match rewritten {
            Some(r) => {
                changed = true;
                out.push(r);
            }
            None => out.push(t.to_string()),
        }
    }
    // Rejoint sur ` | ` : `soql_split_pipes` trime et jette les étages vides, et le cœur RE-DÉCOUPE
    // avec la MÊME fonction -> il reverra EXACTEMENT ces étages-là (aucune dérive de découpage).
    changed.then(|| out.join(" | "))
}

/// Réécrit les JETONS d'un corps de filtre. Frontière de jeton = celle du cœur (blanc hors
/// guillemets, `soql_tokenize_marked`) ; les blancs d'origine sont recopiés à l'identique.
fn alias_filter_body(body: &str) -> Option<String> {
    let mut out = String::with_capacity(body.len() + 24);
    let mut changed = false;
    let mut in_q = false;
    let mut start: Option<usize> = None;
    for (i, c) in body.char_indices() {
        if c == '"' {
            in_q = !in_q;
        }
        if c.is_whitespace() && !in_q {
            if let Some(s) = start.take() {
                changed |= push_span(&mut out, &body[s..i]);
            }
            out.push(c);
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        changed |= push_span(&mut out, &body[s..]);
    }
    changed.then_some(out)
}

/// Pousse un jeton, ALIASÉ s'il est l'égalité `category=exec`. Rend `true` s'il a été aliasé.
fn push_span(out: &mut String, span: &str) -> bool {
    if span_is_category_exec_equality(span) {
        out.push_str(&cim_exec_alias_clause());
        true
    } else {
        out.push_str(span);
        false
    }
}

/// Ce jeton est-il l'ÉGALITÉ `category=exec` ? Reconnaissance DÉRIVÉE de la grammaire du cœur :
///  • MÊME LISTE, MÊME ORDRE d'opérateurs que `table_conds` (le FILTRE DE BASE) -> `!=`/`=~`/`>=`/`<=`
///    sont vus AVANT `=`, donc `category!=exec` et `category=~exec` sont rejetés au lieu d'être pris
///    pour des égalités ;
///    ÉCART CONNU ET MESURÉ, à ne pas re-généraliser : l'étage `where` du cœur (`stages.rs`) a une liste
///    SANS `:`. Ce prédicat étant partagé par les deux étages, `where category:exec` est reconnu ici
///    alors que le cœur REFUSE `where category:auth`. L'alias rend donc compilable une écriture que le
///    langage rejette — une TOLÉRANCE indue, jamais un changement de jeu de lignes (elle ne peut que
///    produire un `IN (exec,process)` là où l'utilisateur aurait eu une erreur de syntaxe). Corriger
///    exigerait deux listes distinctes selon l'étage ; la dette est ici plutôt que sous-entendue ;
///  • partie GAUCHE quotée = PHRASE plein-texte (règle `SoqlTok::quoted_prefix`), jamais un champ ;
///  • le nom du champ doit être la COLONNE RÉELLE `category` — `cat` est un alias de la barre
///    `/api/search` (`field_col`), que le compilateur GXQL ne résout PAS vers la colonne ;
///  • la valeur doit être EXACTEMENT `exec` (guillemets retirés comme le fait le tokeniseur) — ce qui
///    exclut MÉCANIQUEMENT `~exec` (regex), `exec*` (joker) et `execve` sans les énumérer.
fn span_is_category_exec_equality(span: &str) -> bool {
    for op in ["=~", ">=", "<=", "!=", "=", ":", ">", "<"] {
        let Some(pos) = span.find(op) else { continue };
        if op != "=" && op != ":" {
            return false;
        }
        let lhs = &span[..pos];
        if lhs.contains('"') || lhs != "category" {
            return false;
        }
        let rhs = &span[pos + op.len()..];
        return rhs.chars().filter(|c| *c != '"').eq(CIM_EXEC_CANON.chars());
    }
    false
}

/// POINT D'ENTRÉE UNIQUE de génération du SQL de base depuis une requête soql, partagé par les 3
/// sites (query / compile_panel_sql / rule_sql). Le compilo soql vit DÉSORMAIS ENTIÈREMENT dans
/// `guatx_core::soql` (cœur partagé Plume/Forge) : l'ancien compilo legacy de main.rs et le toggle
/// PLUME_SOQL_CORE ont été supprimés — `guatx_core::soql::to_sql(.., &Schema::events())` est l'UNIQUE
/// chemin de compilation.
/// NE touche PAS au rollup-route / budget / pagination / SWR / apply_rollup_stats (chemins intacts).
/// `env` (#2d) : `Some("<env>")` -> le schéma injecte `env_id='<env>'` au WHERE de la base `event`
/// (FILTRE par environnement). `None` (mode 0 / en-tête absent / `__all__`) -> SQL byte-identique au
/// legacy (invariant absolu). La détection (rule_sql) passe TOUJOURS None : les règles sont tenant-wide (D7).
pub(crate) fn soql_to_sql_x(soql: &str, from: i64, to: i64, env: Option<&str>) -> Result<String, String> {
    // COUTURE STORE : l'émission GXQL->SQL traverse désormais l'UNIQUE point qu'est le store (qui compile
    // via `guatx_core::soql` = Dialect). Corps byte-identique à l'ancien inline. Tous les sites de lecture
    // GXQL (query/panels/export/règles) passent par `soql_to_sql_x` -> donc par le store.
    store().soql_to_sql(soql, from, to, env)
}

/// FIELD FILTERS (#45) — variante de `soql_to_sql_x` avec masques de champ EFFECTIFS. Utilisée par les
/// chemins de lecture RÔLE-SCOPÉS (query/export/panels) : le daemon résout `effective_masks(db_path, role,
/// tenant, env)` PUIS compile ici. `masks` VIDE -> STRICTEMENT identique à `soql_to_sql_x` (mode 0). La
/// détection/les rollups (tenant-wide, sans appelant) continuent d'appeler `soql_to_sql_x` (jamais masqué).
pub(crate) fn soql_to_sql_masked_x(soql: &str, from: i64, to: i64, env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet) -> Result<String, String> {
    store().soql_to_sql_masked(soql, from, to, env, masks)
}

/// KEYSET (#28) — variante keyset de `soql_to_sql_masked_x` : compile avec la clé de tri stable `id` AJOUTÉE
/// en fin de projection (`with_cursor_id(true)`). Utilisée UNIQUEMENT par la branche BROWSE de `query.rs`
/// (pagination par CURSEUR `(ts,id)` : parcours INTÉGRAL du match-set sans plafond, remplace le cap 10 000 qui
/// cachait des événements). Tous les autres sites de lecture (query non-keyset/panneaux/export/détection)
/// restent sur `soql_to_sql(_masked)_x` (cursor_id=false) -> SQL byte-identique (mode 0). Traverse le store
/// (choke-point unique de compilation GXQL->SQL). `masks` VIDE -> keyset mode 0 (mêmes colonnes + `id`).
pub(crate) fn soql_to_sql_masked_keyset_x(soql: &str, from: i64, to: i64, env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet) -> Result<String, String> {
    store().soql_to_sql_masked_keyset(soql, from, to, env, masks)
}

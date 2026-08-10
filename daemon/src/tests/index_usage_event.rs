// P10.D — QUI SE SERT DES INDEX B-TREE DE `event`, DANS CE QUE LE PRODUIT LIVRE ?
//
// POURQUOI CE FICHIER EXISTE. `docs/DESIGN-P10-echelle-2go.md` §5.4 dit « ne PAS toucher les index
// restants sans mesure d'usage » — et cette mesure n'avait jamais été faite. Le poste pèse 428,0 Mio
// (27,0 % du fichier, relevé de production du 2026-08-09 22:38 UTC), dont 253,6 Mio derrière ce
// panneau. Ce fichier fait la première des trois voies décrites au §2 bis : le REJEU de
// `EXPLAIN QUERY PLAN` sur le corpus FERMÉ.
//
// CE QUE CETTE MESURE ÉTABLIT, ET CE QU'ELLE N'ÉTABLIT PAS. Elle répond à « quel index le
// planificateur NOMME quand on lui donne, une par une, les requêtes que le produit EMBARQUE ». Elle
// ne répond PAS à « quel index est utile » : un index que le corpus ne nomme pas peut servir
// l'ad hoc analyste, une route non-GXQL, la purge, un rollup ou un tri interne — ces consommateurs
// n'écrivent PAS de ligne dans `rule`/`panel` et sont donc HORS de ce corpus par construction. Aucune
// conclusion de suppression ne peut sortir d'ici seul.
//
// TROIS CLÔTURES, ET C'EST TOUT L'INTÉRÊT :
//
//  ① LES INDEX viennent du CATALOGUE de la base MIGRÉE (`pragma_index_list`/`index_xinfo`), jamais de
//    `db/schema.sql`. L'écart entre les deux est déjà une cicatrice de ce dépôt (P10.2-c) : quatre des
//    huit index de production ne sont PAS dans `schema.sql` (deux viennent de `migrate.rs`, deux sont
//    créés EN FOND par `maintenance.rs` après le bind). La base d'épreuve rejoue donc AUSSI les
//    réconciliations de fond du boot — sinon on mesurerait un schéma que la production n'a pas.
//
//  ② LE CORPUS vient du CATALOGUE lui aussi : on cherche, dans toutes les tables du schéma migré, les
//    COLONNES QUI PORTENT UNE REQUÊTE (`query`, `search_soql`, `soql`), puis on lit ce que le produit
//    y a ÉCRIT LUI-MÊME en appelant ses propres semeurs (`seed_tenant_content`, le seul point d'entrée
//    du produit pour « peupler une base neuve avec le contenu livré ») et son propre chargeur
//    d'overlays (`load_overlays_dir` sur le `config.d` du dépôt, celui que le Dockerfile cuit dans
//    l'image). Aucune liste de requêtes n'est écrite ici. Une requête livrée demain par un semeur neuf
//    entre dans le corpus SANS que son auteur connaisse ce fichier — et si elle arrive par une COLONNE
//    neuve, `la_partition_du_corpus_est_close` la voit aussi.
//
//  ③ LA COMPILATION passe par les TROIS portes réelles du produit — `compile_panel_sql` (panneaux),
//    `rule_sql` (moteur de détection), `soql_to_sql_x` (gabarits) — qui délèguent toutes à
//    `guatx_core::soql` au tag épinglé dans `daemon/Cargo.toml`. Pas de réimplémentation : une
//    réimplémentation aurait mesuré l'usage des index d'un compilateur qui n'existe pas.
//
// CE QUE LE PLANIFICATEUR CHOISIT DÉPEND DES STATISTIQUES, et une base vide n'a pas celles de la
// production. La mesure est donc rejouée sous DEUX régimes (cf. `RegimeStats`) et c'est l'ÉCART entre
// les deux qui est publié, jamais un seul chiffre : sans stats (ce que SQLite devine) et sous les
// statistiques de production, SYNTHÉTISÉES depuis le profil MESURÉ `bench/profile-prod.json`
// (cardinalités relevées en lecture seule sur le VPS le 2026-07-30). Un index dont le verdict change
// d'un régime à l'autre est signalé comme tel : c'est un résultat, pas un défaut.

use std::collections::{BTreeMap, BTreeSet};

/// Les index que la PRODUCTION porte réellement sur `event`, relevés par
/// `plume-daemon db-stats --par-objet` le 2026-08-09 (16:07 UTC, 1 586,8 Mio / 406 213 pages,
/// comptabilité FERMÉE ✓) et publiés dans `docs/DESIGN-P10-echelle-2go.md` §1 et `docs/ROADMAP.md`.
///
/// CE N'EST PAS LA LISTE MESURÉE ICI — c'est le TÉMOIN qui autorise à publier. La base d'épreuve doit
/// porter AU MOINS ces index : si elle en manque un, elle n'est pas au schéma de la production et
/// toute mesure faite dessus parlerait d'une autre base. `idx_event_health_beat` n'y figure pas : il
/// est trop petit pour entrer dans le top-10 du relevé (~1,5 Mio annoncés par `db/schema.sql`), donc
/// son absence de cette liste ne dit rien — l'inclusion serait, elle, une affirmation non mesurée.
const INDEX_EVENT_OBSERVES_EN_PRODUCTION: &[&str] = &[
    "sqlite_autoindex_event_1",
    "idx_event_src_srcip",
    "idx_event_src_ts",
    "idx_event_host",
    "idx_event_sev_srcip",
    "idx_event_srcip",
    "idx_event_ts",
    "idx_event_category",
];

/// Un index de `event` tel que le CATALOGUE le décrit — pas tel qu'on l'a écrit.
#[derive(Clone, Debug)]
struct IndexEvent {
    nom: String,
    /// 'c' = posé par un `CREATE INDEX` · 'u' = auto-index d'une contrainte UNIQUE · 'pk' = de PRIMARY KEY.
    origine: String,
    partiel: bool,
    /// Colonnes-clés DANS L'ORDRE (les colonnes de couverture, `key`=0, sont exclues).
    cles: Vec<String>,
    /// Prédicat d'un index PARTIEL, extrait de son DDL — nécessaire pour bâtir son témoin positif
    /// (SQLite REFUSE un `INDEXED BY` sur un index partiel dont le WHERE n'implique pas le prédicat).
    predicat: Option<String>,
}

/// TOUS les index de `event`, DEMANDÉS à SQLite. Aucun nom n'est écrit ici.
fn index_de_event(conn: &Connection) -> Vec<IndexEvent> {
    let entetes: Vec<(String, String, i64)> = {
        let mut st = conn
            .prepare("SELECT name, origin, partial FROM pragma_index_list('event') ORDER BY name")
            .expect("pragma index_list disponible");
        let it = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)))
            .expect("pragma index_list lisible");
        it.map(|r| r.expect("ligne index_list lisible")).collect()
    };
    entetes
        .into_iter()
        .map(|(nom, origine, partial)| {
            let cles: Vec<String> = {
                let mut st = conn
                    .prepare("SELECT name FROM pragma_index_xinfo(?1) WHERE key=1 ORDER BY seqno")
                    .expect("pragma index_xinfo disponible");
                let it = st
                    .query_map(params![nom], |r| r.get::<_, Option<String>>(0))
                    .expect("pragma index_xinfo lisible");
                it.map(|r| r.expect("ligne index_xinfo lisible").unwrap_or_else(|| "<expression>".into()))
                    .collect()
            };
            // Le prédicat partiel n'est PAS exposé par les pragmas : il faut le DDL. On prend ce qui
            // suit le dernier ` WHERE ` du `CREATE INDEX` tel que le catalogue le conserve.
            let predicat = if partial == 1 {
                conn.query_row(
                    "SELECT sql FROM sqlite_master WHERE type='index' AND name=?1",
                    params![nom],
                    |r| r.get::<_, Option<String>>(0),
                )
                .ok()
                .flatten()
                .and_then(|ddl| ddl.rfind(" WHERE ").map(|p| ddl[p + 7..].trim().to_string()))
            } else {
                None
            };
            IndexEvent { nom, origine, partiel: partial == 1, cles, predicat }
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// L'INSTRUMENT : lire les index NOMMÉS par un plan d'exécution.
// ---------------------------------------------------------------------------------------------

/// Ce qu'un plan d'exécution NOMME. Les index nommés d'un côté ; de l'autre les mentions SANS nom
/// (`AUTOMATIC ...` = index transitoire construit pour la requête, `INTEGER PRIMARY KEY` = le rowid),
/// qu'il serait faux de compter comme un index du schéma et faux de jeter en silence.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct PlanLu {
    index: BTreeSet<String>,
    sans_nom: BTreeSet<String>,
}

/// Extrait d'un `detail` d'`EXPLAIN QUERY PLAN` ce qui suit chaque ` USING `. Écrit à la main plutôt
/// qu'en regex parce que la forme est fixée par SQLite et tient en quatre cas :
///   `SEARCH event USING INDEX <nom> (…)` · `… USING COVERING INDEX <nom> (…)` ·
///   `… USING AUTOMATIC COVERING INDEX (…)` · `… USING INTEGER PRIMARY KEY (rowid=?)`.
fn lire_detail(detail: &str, dans: &mut PlanLu) {
    let mut reste = detail;
    while let Some(p) = reste.find(" USING ") {
        let apres = &reste[p + 7..];
        reste = apres;
        let apres = apres.strip_prefix("COVERING ").unwrap_or(apres);
        if let Some(q) = apres.strip_prefix("INDEX ") {
            let nom: String = q.chars().take_while(|c| !c.is_whitespace() && *c != '(').collect();
            if !nom.is_empty() {
                dans.index.insert(nom);
            }
        } else {
            // `AUTOMATIC COVERING INDEX`, `INTEGER PRIMARY KEY`, `ROWID SEARCH`… : pas un index du schéma.
            let jeton: String = apres.chars().take_while(|c| *c != '(').collect();
            dans.sans_nom.insert(jeton.trim().to_string());
        }
    }
}

/// Le plan de `sql`, LU. `Err` porte le refus de SQLite tel quel (une requête que le planificateur
/// refuse est un objet dont on NE PEUT PAS CONCLURE — jamais un objet « sans index »).
fn plan_de(conn: &Connection, sql: &str) -> Result<PlanLu, String> {
    let mut st = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).map_err(|e| e.to_string())?;
    let lignes: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(3))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let mut lu = PlanLu::default();
    for l in &lignes {
        lire_detail(l, &mut lu);
    }
    Ok(lu)
}

// ---------------------------------------------------------------------------------------------
// LA BASE D'ÉPREUVE : le schéma RÉEL, réconciliations de fond comprises.
// ---------------------------------------------------------------------------------------------

/// La base que ce binaire produit VRAIMENT sur un déploiement : `db/schema.sql` + toute la chaîne de
/// migrations (`prepare_schema`), PUIS les réconciliations d'index que le boot lance EN FOND après le
/// bind (`server.rs`) — c'est là que naissent `idx_event_category`, `idx_event_src_ts` et
/// `idx_event_health_beat`, qu'AUCUNE migration ne peut créer (un `CREATE INDEX` sur des millions de
/// lignes chiffrées bloquerait le bind). Sur une base neuve `event` est VIDE : ces créations sont
/// instantanées. Base FICHIER (pas `:memory:`) : les pragmas de catalogue portent sur une vraie base,
/// ouverte par le même chemin que la production.
fn base_au_schema_reel(etiquette: &str) -> (crate::tmp_possede::TmpDb, Arc<Mutex<Connection>>) {
    let chemin = crate::tmp_possede::TmpDb::neuf(etiquette);
    let conn = Connection::open(chemin.as_str()).expect("base fichier ouvrable");
    prepare_schema(&conn).expect("le schéma que ce binaire déclare doit se construire sur une base neuve");
    // LES UDF DU CHEMIN DE LECTURE, posées par le helper PARTAGÉ du produit (`query_exec`). Sans elles,
    // toute requête livrée qui contient un `REGEXP` (règles Sigma, playbooks) est refusée au PREPARE et
    // devient un objet « dont on ne peut pas conclure » — un trou de mesure créé par le banc, pas par le
    // produit. L'authorizer de champs, lui, n'est pas posé : il ACCEPTE ou REFUSE, il ne change aucun plan.
    install_query_udfs(&conn);
    // `reconcile_index_state` d'abord (DDL pur, kill-switch FTS/index d'expression), comme au boot.
    reconcile_index_state(&conn, &HashMap::new());
    let db = Arc::new(Mutex::new(conn));
    // Puis les tâches de fond du boot, DANS L'ORDRE de `spawn_background_jobs`.
    ensure_event_category_index_background(&db);
    drop_redundant_event_indexes_background(&db);
    drop_prefix_subsumed_indexes_background(&db);
    drop_orphan_auto_field_indexes_background(&db);
    ensure_event_src_ts_index_background(&db);
    ensure_event_health_beat_index_background(&db);
    ensure_host_rollup_scan_indexes_background(&db);
    (chemin, db)
}

// ---------------------------------------------------------------------------------------------
// LE CORPUS : ce que le produit LIVRE comme requête, lu dans les tables qu'il a lui-même peuplées.
// ---------------------------------------------------------------------------------------------

/// Les noms de colonne qui PORTENT une requête produit. Ce n'est pas une liste d'objets, c'est le
/// vocabulaire du schéma : la recherche des colonnes, elle, est faite sur TOUTES les tables.
const COLONNES_PORTEUSES_DE_REQUETE: &[&str] = &["query", "search_soql", "soql"];

#[derive(Debug, Clone)]
struct ObjetCorpus {
    table: String,
    colonne: String,
    rowid: i64,
    requete: String,
    is_soql: bool,
    window_s: i64,
}

/// Le `config.d` du dépôt — celui que le Dockerfile cuit dans l'image sous
/// `/usr/local/share/plume/config.d`. Résolu depuis le manifeste de la crate, jamais depuis le CWD.
fn config_d_du_depot() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("config.d")
}

/// PEUPLE la base avec TOUT ce que le produit livre, en appelant le produit :
///   • `seed_tenant_content` — le point d'entrée unique du produit pour « le contenu de détection et
///     les dashboards builtin d'une base neuve », dans l'ordre du boot (cf. sa doc dans `tenants.rs`) ;
///   • `seed_compliance_dashboards` — semé par `run()` mais ABSENT de `seed_tenant_content` (écart
///     réel, cf. `la_partition_du_corpus_est_close` qui le DÉRIVE au lieu de le croire) ;
///   • `load_overlays_dir` — le pack `config.d` versionné, livré dans l'image.
/// `seed_demo` est délibérément EXCLU : il n'écrit aucune requête (events/alertes/cases de démo), il
/// est gaté par `PLUME_DEMO=1` et n'existe pas en production.
fn semer_le_corpus(conn: &Connection) {
    seed_tenant_content(conn);
    seed_compliance_dashboards(conn);
    load_overlays_dir(conn, &config_d_du_depot());
}

/// LE CORPUS, DÉRIVÉ. On demande au catalogue quelles tables ont une colonne porteuse de requête, puis
/// on lit toutes les valeurs non vides. `is_soql` et `window_s` sont pris SUR LA LIGNE quand la table
/// les porte (c'est le cas de `rule`/`panel`/`playbook`) ; sinon la colonne est GXQL par construction
/// (`runbook_step.search_soql` ne peut pas être du SQL brut) et la fenêtre est celle d'une règle.
fn corpus_livre(conn: &Connection) -> Vec<ObjetCorpus> {
    let tables: Vec<String> = {
        let mut st = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' \
                 AND sql IS NOT NULL ORDER BY name",
            )
            .expect("catalogue des tables lisible");
        st.query_map([], |r| r.get::<_, String>(0))
            .expect("catalogue lisible")
            .map(|r| r.expect("nom de table"))
            .collect()
    };
    let mut out = Vec::new();
    for table in tables {
        let colonnes: Vec<String> = {
            let mut st = conn
                .prepare("SELECT name FROM pragma_table_info(?1)")
                .expect("pragma table_info disponible");
            st.query_map(params![table], |r| r.get::<_, String>(0))
                .expect("pragma table_info lisible")
                .map(|r| r.expect("nom de colonne"))
                .collect()
        };
        let a = |c: &str| colonnes.iter().any(|x| x == c);
        for porteuse in COLONNES_PORTEUSES_DE_REQUETE.iter().filter(|c| a(c)) {
            let sel = format!(
                "SELECT rowid, {porteuse}, {}, {} FROM {table} WHERE {porteuse} IS NOT NULL AND trim({porteuse})<>'' ORDER BY rowid",
                if a("is_soql") { "is_soql" } else { "1" },
                if a("window_s") { "window_s" } else { "3600" },
            );
            let mut st = match conn.prepare(&sel) {
                Ok(s) => s,
                Err(e) => panic!("corpus : {table}.{porteuse} illisible ({e})"),
            };
            let it = st
                .query_map([], |r| {
                    Ok(ObjetCorpus {
                        table: table.clone(),
                        colonne: (*porteuse).to_string(),
                        rowid: r.get(0)?,
                        requete: r.get(1)?,
                        is_soql: r.get::<_, i64>(2)? != 0,
                        window_s: r.get::<_, i64>(3)?,
                    })
                })
                .expect("lecture du corpus");
            out.extend(it.map(|r| r.expect("ligne de corpus")));
        }
    }
    out
}

/// COMPILE un objet du corpus PAR LA PORTE DU PRODUIT qui lui correspond. Les trois portes délèguent
/// toutes à `guatx_core::soql` (cf. `soql_glue.rs`) : c'est le compilateur RÉEL, au tag épinglé.
fn compiler_objet(o: &ObjetCorpus, from: i64, to: i64) -> Result<String, String> {
    match o.table.as_str() {
        // Panneaux : la porte des panneaux — y compris son ROUTAGE ROLLUP, qui peut sortir la requête
        // de `event` avant même qu'un index soit en jeu. C'est le SQL que le produit exécute.
        "panel" | "library_panel" | "panel_cache" => compile_panel_sql(&o.requete, o.is_soql, from, to, None),
        // Détection : la porte SYSTÈME du moteur de règles (fenêtre glissante, aucun masque).
        "rule" | "playbook" => rule_sql(&o.requete, o.is_soql, o.window_s),
        // Le reste (gabarits d'étapes de runbook, requêtes sauvegardées…) : la porte GXQL nue.
        _ => {
            if o.is_soql {
                soql_to_sql_x(&o.requete, from, to, None)
            } else {
                Ok(o.requete.replace("__FROM__", &from.to_string()).replace("__TO__", &to.to_string()))
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// LES RÉGIMES DE STATISTIQUES.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RegimeStats {
    /// Base neuve, `event` vide, aucun `sqlite_stat1` : ce que SQLite DEVINE (il suppose ~1 048 576
    /// lignes par table et une sélectivité par défaut). C'est le régime d'une instance fraîche.
    SansStats,
    /// `sqlite_stat1` SYNTHÉTISÉ depuis `bench/profile-prod.json` — cardinalités MESURÉES en lecture
    /// seule sur la production le 2026-07-30 (1 397 446 événements, source=32, category=19, host=2,
    /// src_ip=21 140, dedup=536 293 distincts). Ce n'est PAS un `ANALYZE` de production : c'est la
    /// meilleure approximation qu'on puisse poser sans y accéder, et les approximations sont dites.
    ///
    /// ⚠ LA LIMITE PRINCIPALE DE CE RÉGIME, ET ELLE PORTE SUR LES BORNES. La SQLite vendorée du
    /// produit est compilée avec `SQLITE_ENABLE_STAT4` (`libsqlite3-sys`, inconditionnel) : en
    /// production, `analyze_full_background` produit donc AUSSI un `sqlite_stat4`, c'est-à-dire des
    /// ÉCHANTILLONS de valeurs par index. Ce sont eux qui estiment le rendement d'un prédicat de
    /// BORNE (`ts >= …`, `severity >= 3`), là où `sqlite_stat1` ne connaît que des moyennes
    /// d'égalité. Ce régime n'écrit QUE `sqlite_stat1`. Conséquence à retenir : le verdict des index
    /// dont la colonne de tête n'est interrogée QUE par bornes est le moins solide des trois.
    StatsDeProduction,
    /// CONTREFACTUEL, PAS UNE MESURE. Les mêmes statistiques, avec la SEULE cardinalité de `host`
    /// portée à 200 : notre production ne compte que **2 hôtes**, ce qui rend `host=…` non sélectif
    /// PAR ACCIDENT DE NOTRE DÉPLOIEMENT. L'invariant de généricité (P6.2-a) exige de savoir si le
    /// verdict d'un index tient au CORPUS ou à NOTRE flotte : ce régime le tranche, et lui seul.
    FlotteDe200Hotes,
}

/// Le profil de production, LU (jamais recopié). Renvoie (lignes, cardinalité par colonne).
fn profil_de_production() -> (i64, BTreeMap<String, i64>) {
    let brut = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("bench").join("profile-prod.json"),
    )
    .expect("bench/profile-prod.json lisible (profil MESURÉ de la production)");
    let v: serde_json::Value = serde_json::from_str(&brut).expect("profil JSON valide");
    let lignes = v["volume"]["events"].as_i64().expect("volume.events mesuré");
    let mut card = BTreeMap::new();
    if let Some(o) = v["columns"]["cardinality"].as_object() {
        for (k, x) in o {
            if let Some(n) = x.as_i64() {
                card.insert(k.clone(), n.max(1));
            }
        }
    }
    // `severity` n'est pas dans `columns.cardinality` : il est dans la distribution mesurée.
    if let Some(o) = v["distribution"]["by_severity"].as_object() {
        card.insert("severity".into(), (o.len() as i64).max(1));
    }
    // `ts` non plus : 1,4 M événements sur 29,07 j = 2,51 M secondes, donc au plus ~1 ligne par
    // seconde OCCUPÉE. Approximation ASSUMÉE (avgEq=1) et signalée dans le rapport.
    card.insert("ts".into(), lignes);
    (lignes, card)
}

/// Écrit un `sqlite_stat1` correspondant au profil de production pour les index de `event`, puis le
/// fait relire par SQLite (`ANALYZE sqlite_master` recharge les stats SANS recalculer).
///
/// Format `stat` : « nRow avgEq1 avgEq2 … » — nRow = lignes de l'index, avgEqK = nombre moyen de
/// lignes partageant les K premières colonnes. Approximation ASSUMÉE : uniformité (avgEqK =
/// nRow / ∏ cardinalités), les NULL comptés comme une valeur. L'index PARTIEL des battements de
/// santé ne porte que ses propres lignes : ~1 battement / 37 s (chiffre de `db/schema.sql`) sur la
/// fenêtre du profil.
fn poser_stats_de_production(conn: &Connection, surcharges: &[(&str, i64)]) {
    let (lignes, mut card) = profil_de_production();
    for (col, n) in surcharges {
        card.insert((*col).to_string(), *n);
    }
    // `ANALYZE` crée la table `sqlite_stat1` (sur une base vide elle reste sans ligne utile).
    conn.execute_batch("ANALYZE").expect("ANALYZE (création de sqlite_stat1)");
    conn.execute("DELETE FROM sqlite_stat1 WHERE tbl='event'", []).expect("sqlite_stat1 inscriptible");
    for ix in index_de_event(conn) {
        let n = if ix.partiel {
            // battements de santé : ~1 toutes les 37 s sur la fenêtre mesurée (29,07 j).
            ((29.07_f64 * 86400.0) / 37.0) as i64
        } else {
            lignes
        };
        let mut produit: i64 = 1;
        let mut morceaux = vec![n.to_string()];
        for c in &ix.cles {
            produit = produit.saturating_mul(*card.get(c.as_str()).unwrap_or(&1));
            morceaux.push((n / produit).max(1).to_string());
        }
        conn.execute(
            "INSERT INTO sqlite_stat1(tbl,idx,stat) VALUES('event',?1,?2)",
            params![ix.nom, morceaux.join(" ")],
        )
        .expect("sqlite_stat1 inscriptible");
    }
    // Le compte de lignes de la TABLE elle-même (idx NULL) — sans lui, le planificateur garde son
    // estimation par défaut pour le balayage complet et comparerait des coûts incohérents.
    conn.execute("INSERT INTO sqlite_stat1(tbl,idx,stat) VALUES('event',NULL,?1)", params![lignes.to_string()])
        .expect("sqlite_stat1 inscriptible");
    conn.execute_batch("ANALYZE sqlite_master").expect("rechargement des stats");
}

// ---------------------------------------------------------------------------------------------
// ① + ③ + ④ — LA MESURE.
// ---------------------------------------------------------------------------------------------

/// Le verdict d'un index sous UN régime.
#[derive(Default, Clone)]
struct Usage {
    /// Objets du corpus dont le plan NOMME cet index.
    objets: Vec<String>,
    /// LES QUASI-MANQUÉS : objets dont le SQL compilé CITE la colonne de TÊTE de cet index (sous sa
    /// forme quotée, celle que le cœur émet) sans que le planificateur retienne l'index. C'est ce qui
    /// distingue « aucune requête livrée ne filtre sur cette colonne » de « des requêtes filtrent
    /// dessus mais le planificateur préfère autre chose » — deux constats radicalement différents.
    ///
    /// CE QUE CE COMPTEUR NE DIT PAS : il regarde la colonne de TÊTE et rien d'autre. Deux index qui
    /// partagent leur tête (`idx_event_src_ts`, `idx_event_src_srcip` et le PARTIEL
    /// `idx_event_health_beat` mènent tous par `source`) reçoivent donc les mêmes quasi-manqués, et
    /// pour le partiel le prédicat `category='health'` n'est pas pris en compte : son chiffre est un
    /// MAJORANT sans intérêt. C'est un indicateur de LECTURE, pas une mesure d'usage.
    cite_la_colonne_de_tete: Vec<String>,
}

fn mesurer(regime: RegimeStats) -> (Vec<IndexEvent>, BTreeMap<String, Usage>, Vec<(String, String)>, usize) {
    let etiquette = match regime {
        RegimeStats::SansStats => "idxusage-sans-stats",
        RegimeStats::StatsDeProduction => "idxusage-stats-prod",
        RegimeStats::FlotteDe200Hotes => "idxusage-flotte-200",
    };
    let (_chemin, db) = base_au_schema_reel(etiquette);
    let conn = db.lock();
    semer_le_corpus(&conn);
    match regime {
        RegimeStats::SansStats => {}
        RegimeStats::StatsDeProduction => poser_stats_de_production(&conn, &[]),
        RegimeStats::FlotteDe200Hotes => poser_stats_de_production(&conn, &[("host", 200)]),
    }

    let index = index_de_event(&conn);
    let mut usage: BTreeMap<String, Usage> = index.iter().map(|i| (i.nom.clone(), Usage::default())).collect();
    let mut indecidables: Vec<(String, String)> = Vec::new();

    let to = now();
    let from = to - 86_400;
    let mut objets: Vec<(String, String, bool, i64)> = corpus_livre(&conn)
        .into_iter()
        .map(|o| (format!("{}#{} ({})", o.table, o.rowid, o.colonne), o.requete.clone(), o.is_soql, o.window_s))
        .collect();
    // Les gabarits GXQL embarqués (`docs/soql-templates/templates.json`), servis par
    // `/api/soql/templates` : livrés par le produit mais stockés dans le BINAIRE, pas dans une table.
    for (id, soql) in crate::handlers::soql_meta::soql_template_queries() {
        objets.push((format!("templates.json#{id}"), soql, true, 3600));
    }
    let total = objets.len();

    for (etiq, requete, is_soql, window_s) in objets {
        let o = ObjetCorpus {
            table: etiq.split('#').next().unwrap_or("").to_string(),
            colonne: String::new(),
            rowid: 0,
            requete,
            is_soql,
            window_s,
        };
        let sql = match compiler_objet(&o, from, to) {
            Ok(s) => s,
            Err(e) => {
                indecidables.push((etiq, format!("compilation refusée : {e}")));
                continue;
            }
        };
        match plan_de(&conn, &sql) {
            Ok(lu) => {
                for nom in &lu.index {
                    if let Some(u) = usage.get_mut(nom) {
                        u.objets.push(etiq.clone());
                    }
                }
                for ix in &index {
                    let Some(tete) = ix.cles.first() else { continue };
                    // Le cœur émet les colonnes de prédicat QUOTÉES (`"source" = 'x'`) là où la
                    // projection interne les émet nues -> la forme quotée isole les prédicats.
                    if sql.contains(&format!("\"{tete}\"")) && !lu.index.contains(&ix.nom) {
                        usage.get_mut(&ix.nom).expect("index connu").cite_la_colonne_de_tete.push(etiq.clone());
                    }
                }
            }
            Err(e) => indecidables.push((etiq, format!("plan refusé : {e}"))),
        }
    }
    drop(conn);
    (index, usage, indecidables, total)
}

// ---------------------------------------------------------------------------------------------
// LES TESTS.
// ---------------------------------------------------------------------------------------------

/// L'INSTRUMENT LUI-MÊME. Un lecteur de plan qui ne voit rien est indiscernable d'un corpus qui
/// n'utilise rien — c'est exactement l'erreur que cette mesure doit éviter.
///
/// TÉMOIN POSITIF, DÉRIVÉ : pour CHAQUE index que le catalogue déclare sur `event`, on force son
/// emploi par `INDEXED BY` (en rappelant son prédicat quand il est partiel — sans quoi SQLite refuse)
/// et on exige que le lecteur rende EXACTEMENT ce nom. Aucun nom n'est écrit dans ce test : l'index
/// ajouté demain est couvert le jour où il est ajouté.
/// TÉMOIN NÉGATIF : `NOT INDEXED` sur la même table doit rendre un ensemble VIDE — la preuve que le
/// lecteur PEUT rendre vide, donc qu'un vide est une mesure et pas une panne.
#[test]
fn le_lecteur_de_plan_nomme_chaque_index_et_ne_nomme_rien_quand_il_ny_en_a_pas() {
    let (_chemin, db) = base_au_schema_reel("idxusage-instrument");
    let conn = db.lock();
    let index = index_de_event(&conn);
    assert!(index.len() >= 2, "base d'épreuve sans index : l'instrument ne pourrait rien prouver");

    for ix in &index {
        let mut clauses: Vec<String> = Vec::new();
        if let Some(p) = &ix.predicat {
            clauses.push(format!("({p})"));
        }
        if let Some(c0) = ix.cles.first() {
            clauses.push(format!("{c0} > 0"));
        }
        let ou = if clauses.is_empty() { String::new() } else { format!(" WHERE {}", clauses.join(" AND ")) };
        let sql = format!("SELECT count(*) FROM event INDEXED BY {}{ou}", ix.nom);
        let lu = plan_de(&conn, &sql)
            .unwrap_or_else(|e| panic!("témoin positif de {} : SQLite refuse le plan ({e}) — sql={sql}", ix.nom));
        assert!(
            lu.index.contains(&ix.nom),
            "TÉMOIN POSITIF EN ÉCHEC : forcé par INDEXED BY, l'index {} n'est pas lu dans le plan. \
             Le lecteur de plan est aveugle sur cette forme -> toute mesure d'usage serait un faux \
             « personne ne s'en sert ». Plan lu : {:?} / sans nom : {:?}",
            ix.nom, lu.index, lu.sans_nom
        );
    }

    let vide = plan_de(&conn, "SELECT count(*) FROM event NOT INDEXED WHERE message LIKE '%zz%'")
        .expect("plan lisible");
    assert!(
        vide.index.is_empty(),
        "TÉMOIN NÉGATIF EN ÉCHEC : un balayage explicitement NON indexé nomme pourtant {:?} — le \
         lecteur invente des index, et le tableau d'usage serait faux dans l'autre sens",
        vide.index
    );

    // Le lecteur doit aussi SÉPARER les mentions sans nom (index automatique / rowid) des vrais index.
    let mut lu = PlanLu::default();
    lire_detail("SEARCH event USING AUTOMATIC COVERING INDEX (source=?)", &mut lu);
    lire_detail("SEARCH event USING INTEGER PRIMARY KEY (rowid=?)", &mut lu);
    assert!(
        lu.index.is_empty() && lu.sans_nom.len() == 2,
        "un index AUTOMATIQUE et le rowid ne sont pas des index du schéma : ils doivent être comptés \
         à part, sinon ils gonflent l'usage d'index qui n'existent pas. Lu : {lu:?}"
    );
}

/// ① LA BASE D'ÉPREUVE EST-ELLE CELLE DE LA PRODUCTION ? Le refus de publier.
///
/// La mesure ne vaut que si elle porte sur le schéma que la production porte. On DEMANDE au catalogue
/// de la base d'épreuve, et on exige qu'il contienne CHAQUE index relevé en production le 2026-08-09.
/// Un manque = mesure faite sur une autre base = chiffre à ne pas publier.
///
/// MUTATION (2026-08-10) : retirer un seul des appels de réconciliation de fond de
/// `base_au_schema_reel` (p.ex. `ensure_event_category_index_background`) fait ROUGIR ce test en
/// nommant l'index absent — c'est ce qui prouve que le rejeu des tâches de fond n'est pas décoratif.
#[test]
fn la_base_depreuve_porte_les_index_que_la_production_porte() {
    let (_chemin, db) = base_au_schema_reel("idxusage-schema");
    let conn = db.lock();
    let presents: BTreeSet<String> = index_de_event(&conn).into_iter().map(|i| i.nom).collect();
    let manquants: Vec<&str> =
        INDEX_EVENT_OBSERVES_EN_PRODUCTION.iter().copied().filter(|n| !presents.contains(*n)).collect();
    assert!(
        manquants.is_empty(),
        "REFUS DE PUBLIER : la base d'épreuve NE PORTE PAS {manquants:?}, que le relevé de production \
         du 2026-08-09 (`db-stats --par-objet`, comptabilité fermée) nomme. Une mesure d'usage faite \
         ici parlerait d'un schéma que la production n'a pas. Index présents : {presents:?}"
    );
}

/// ② LA PARTITION DU CORPUS EST-ELLE CLOSE ? Garde DÉRIVÉE, pas une liste.
///
/// Le corpus est « ce que le produit écrit lui-même dans les colonnes porteuses de requête ». Deux
/// façons de le rater, toutes deux fermées ici en LISANT LE CODE plutôt qu'en le croyant :
///   (a) un semeur appelé au BOOT que `semer_le_corpus` n'appelle pas -> requêtes livrées jamais vues.
///       On extrait de `server.rs` la liste des `seed_*(&conn)` du bloc de boot et on la confronte à
///       ce que `seed_tenant_content` (`tenants.rs`) appelle, plus les exceptions NOMMÉES ici ;
///   (b) une colonne porteuse de requête absente du vocabulaire -> on exige que chaque colonne nommée
///       `%query%` / `%soql%` du schéma migré soit soit dans le vocabulaire, soit explicitement
///       classée hors-corpus (métadonnée, empreinte, cache).
#[test]
fn la_partition_du_corpus_est_close() {
    // (a) — les semeurs du boot, LUS dans server.rs.
    let srv = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("server.rs"),
    )
    .expect("server.rs lisible");
    let debut = srv.find("reconcile_index_state(&conn").expect("bloc de seeds du boot repérable");
    let fin = srv.find("seed_env_notifier(&conn").expect("fin du bloc de seeds repérable");
    let bloc = &srv[debut..fin];
    // Les appels de semis portent presque tous un commentaire de fin de ligne : le retirer AVANT de
    // reconnaître l'appel. Sans cela l'extracteur ne voyait que la minorité de lignes nues et la
    // garde passait au vert en n'ayant presque rien examiné (mesuré par mutation le 2026-08-10 :
    // retirer `seed_compliance_dashboards` du jeu attendu laissait le test VERT).
    let appel = |l: &str, suffixe: &str| -> Option<String> {
        let sans_commentaire = l.split("//").next().unwrap_or("").trim();
        sans_commentaire.strip_suffix(suffixe).map(|s| s.to_string())
    };
    let semeurs_boot: BTreeSet<String> = bloc
        .lines()
        .filter_map(|l| appel(l, "(&conn);"))
        .filter(|s| s.starts_with("seed_") || s.starts_with("ensure_"))
        .collect();

    let ten = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("tenants.rs"),
    )
    .expect("tenants.rs lisible");
    let d2 = ten.find("pub(crate) fn seed_tenant_content").expect("seed_tenant_content repérable");
    let f2 = d2 + ten[d2..].find("\n}").expect("fin de seed_tenant_content repérable");
    let semeurs_tenant: BTreeSet<String> = ten[d2..f2]
        .lines()
        .filter_map(|l| appel(l, "(conn);"))
        .filter(|s| s.starts_with("seed_") || s.starts_with("ensure_"))
        .collect();

    // CONTRÔLE POSITIF DE L'EXTRACTEUR. Un extracteur qui ne trouve presque rien produit une garde
    // verte qui n'a rien examiné — c'est exactement ce qui s'est passé avant le retrait des
    // commentaires de fin de ligne. Les deux jeux doivent être NON VIDES et du bon ordre de grandeur,
    // et `seed_tenant_content` doit être un SOUS-ensemble strict du boot (il l'est par construction :
    // sa doc dit « dans le même ordre que run() », sans les seeds spécifiques au déploiement).
    assert!(
        semeurs_boot.len() >= 25 && semeurs_tenant.len() >= 25,
        "EXTRACTEUR MUET : {} semeur(s) lus dans le bloc de boot de server.rs et {} dans \
         seed_tenant_content. Une garde de clôture qui n'a presque rien lu est verte pour la mauvaise \
         raison. boot={semeurs_boot:?} tenant={semeurs_tenant:?}",
        semeurs_boot.len(),
        semeurs_tenant.len()
    );
    let orphelins: Vec<&String> = semeurs_tenant.difference(&semeurs_boot).collect();
    assert!(
        orphelins.is_empty(),
        "`seed_tenant_content` appelle {orphelins:?} que le boot n'appelle pas : les deux chemins de \
         peuplement ont divergé, et le corpus semé ici n'est plus celui d'une install fraîche."
    );

    // Ce que `semer_le_corpus` ajoute EN PLUS de `seed_tenant_content`, et ce qu'il écarte en le disant.
    let ajoutes: BTreeSet<String> = ["seed_compliance_dashboards".to_string()].into_iter().collect();
    // `seed_demo` n'écrit AUCUNE requête (events/alertes/cases de démo) et est gaté PLUME_DEMO=1.
    let ecartes: BTreeSet<String> = ["seed_demo".to_string()].into_iter().collect();

    let non_couverts: Vec<&String> = semeurs_boot
        .iter()
        .filter(|s| !semeurs_tenant.contains(*s) && !ajoutes.contains(*s) && !ecartes.contains(*s))
        .collect();
    assert!(
        non_couverts.is_empty(),
        "PARTITION OUVERTE : le boot appelle {non_couverts:?}, que `semer_le_corpus` n'appelle pas et \
         qui n'est pas écarté explicitement. Des requêtes LIVRÉES seraient absentes du corpus mesuré, \
         et un index les servant serait déclaré « nommé par personne ». Ajouter le semeur à \
         `semer_le_corpus` (ou l'écarter en disant pourquoi)."
    );

    // (b) — le vocabulaire des colonnes porteuses.
    let (_chemin, db) = base_au_schema_reel("idxusage-partition");
    let conn = db.lock();
    semer_le_corpus(&conn);
    let mut suspectes: Vec<String> = Vec::new();
    let tables: Vec<String> = {
        let mut st = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND sql IS NOT NULL")
            .expect("catalogue lisible");
        st.query_map([], |r| r.get::<_, String>(0)).unwrap().map(|r| r.unwrap()).collect()
    };
    // Colonnes qui RESSEMBLENT à une requête sans en être une — classées ici, une fois, avec la raison
    // ET, pour la seule qui pourrait en porter une, avec la VÉRIFICATION qu'elle est vide.
    let hors_corpus = |t: &str, c: &str| -> bool {
        match (t, c) {
            // FRAGMENT de contrainte GXQL d'un objet de data-model (#47), pas une requête compilable
            // seule : `datamodels.rs` le CONCATÈNE à la requête du pivot. Aucun semeur n'en écrit —
            // l'assertion ci-dessous le VÉRIFIE au lieu de le supposer.
            ("data_model_object", "constraint_soql") => true,
            // EMPREINTE (hash) d'une requête, clé de cache/comptabilité — pas son texte.
            (_, "query_fp") => true,
            _ => false,
        }
    };
    for t in &tables {
        let mut st = conn.prepare("SELECT name, type FROM pragma_table_info(?1)").unwrap();
        let cols: Vec<(String, String)> = st
            .query_map(params![t], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        for (c, typ) in cols {
            let cl = c.to_ascii_lowercase();
            // Une colonne DÉCLARÉE INTEGER ne peut pas porter de requête : `is_soql`, `query_private`
            // sont des DRAPEAUX. Le type vient du catalogue, il n'est pas supposé.
            if typ.eq_ignore_ascii_case("INTEGER") {
                continue;
            }
            if (cl.contains("query") || cl.contains("soql"))
                && !COLONNES_PORTEUSES_DE_REQUETE.contains(&c.as_str())
                && !hors_corpus(t, &c)
            {
                suspectes.push(format!("{t}.{c}"));
            }
        }
    }
    let fragments: i64 = conn
        .query_row("SELECT count(*) FROM data_model_object WHERE trim(constraint_soql)<>''", [], |r| r.get(0))
        .unwrap_or(0);
    assert_eq!(
        fragments, 0,
        "`data_model_object.constraint_soql` est écarté du corpus au motif qu'AUCUN contenu livré n'en \
         écrit — or {fragments} ligne(s) en portent. L'exclusion n'est plus vraie : ces fragments \
         doivent entrer dans le corpus (concaténés comme le fait `datamodels.rs`)."
    );
    assert!(
        suspectes.is_empty(),
        "VOCABULAIRE INCOMPLET : {suspectes:?} ressemble(nt) à une colonne porteuse de requête sans \
         être dans `COLONNES_PORTEUSES_DE_REQUETE` ni classée hors-corpus. Tant que ce n'est pas \
         tranché, le corpus n'est pas clos et le tableau d'usage sous-compte."
    );
}

/// ③ + ④ — LA MESURE, PUBLIÉE. Ce test ne juge pas l'utilité d'un index : il RAPPORTE, par index et
/// par régime de statistiques, combien d'objets du corpus le NOMMENT. Il n'échoue que sur ce qui
/// invaliderait la mesure elle-même : un corpus vide, ou une base qui n'a pas les index de production.
///
/// Rejouable : `cargo test --offline --locked usage_des_index -- --nocapture --test-threads=1`
#[test]
fn usage_des_index_de_event_par_le_corpus_ferme() {
    let (index_sans, usage_sans, indec_sans, total_sans) = mesurer(RegimeStats::SansStats);
    let (index_prod, usage_prod, indec_prod, total_prod) = mesurer(RegimeStats::StatsDeProduction);
    let (_, usage_f200, indec_f200, total_f200) = mesurer(RegimeStats::FlotteDe200Hotes);

    assert!(total_sans > 0, "CORPUS VIDE : rien n'a été mesuré (un filtre qui ne rend rien n'est pas une mesure)");
    assert_eq!(total_sans, total_prod, "les deux régimes doivent voir le MÊME corpus");
    assert_eq!(total_sans, total_f200, "les trois régimes doivent voir le MÊME corpus");
    let noms_sans: BTreeSet<&str> = index_sans.iter().map(|i| i.nom.as_str()).collect();
    let noms_prod: BTreeSet<&str> = index_prod.iter().map(|i| i.nom.as_str()).collect();
    assert_eq!(noms_sans, noms_prod, "les deux régimes doivent voir le MÊME schéma");
    // Un objet du corpus qui ne compile pas / dont SQLite refuse le plan est un TROU de mesure : il
    // doit être NOMMÉ, jamais absorbé dans un « personne ne s'en sert ».
    assert_eq!(
        indec_sans.len(),
        indec_prod.len(),
        "les deux régimes ne butent pas sur les mêmes objets — la comparaison ne porterait pas sur le même corpus mesuré"
    );

    println!("\n=== USAGE DES INDEX DE `event` PAR LE CORPUS FERMÉ ===");
    println!(
        "corpus : {total_sans} objets · schéma : {} index sur `event` · indécidables : {} (régime prod : {}, flotte-200 : {})",
        index_sans.len(),
        indec_sans.len(),
        indec_prod.len(),
        indec_f200.len()
    );
    println!("colonnes = nombre d'objets du corpus dont le PLAN nomme l'index, par régime de statistiques");
    println!(
        "{:<28} {:<6} {:<8} {:>11} {:>11} {:>12} {:>10}   {}",
        "index", "orig.", "partiel", "sans-stats", "stats-prod", "flotte-200", "cite-tête", "colonnes-clés"
    );
    for ix in &index_sans {
        let u_sans = usage_sans.get(&ix.nom);
        let a = u_sans.map(|u| u.objets.len()).unwrap_or(0);
        let b = usage_prod.get(&ix.nom).map(|u| u.objets.len()).unwrap_or(0);
        let c = usage_f200.get(&ix.nom).map(|u| u.objets.len()).unwrap_or(0);
        // Les quasi-manqués sont lus sous le régime de PRODUCTION (le seul qui approche le réel).
        let n = usage_prod.get(&ix.nom).map(|u| u.cite_la_colonne_de_tete.len()).unwrap_or(0);
        println!(
            "{:<28} {:<6} {:<8} {:>11} {:>11} {:>12} {:>10}   [{}]",
            ix.nom,
            ix.origine,
            if ix.partiel { "oui" } else { "non" },
            a,
            b,
            c,
            n,
            ix.cles.join(", ")
        );
    }
    for (etiquette, usage) in [
        ("SANS STATS", &usage_sans),
        ("STATS DE PRODUCTION", &usage_prod),
        ("CONTREFACTUEL FLOTTE DE 200 HÔTES", &usage_f200),
    ] {
        println!("\n--- objets qui NOMMENT un index ({etiquette}) ---");
        for (nom, u) in usage.iter() {
            let mut v = u.objets.clone();
            v.sort();
            v.dedup();
            println!("  {nom} <- {} objet(s){}", u.objets.len(), if v.is_empty() { String::new() } else { format!(" : {}", v.join(", ")) });
        }
    }
    println!("\n--- QUASI-MANQUÉS (régime stats-prod) : le corpus CITE la colonne de tête, le plan ne retient pas l'index ---");
    for (nom, u) in usage_prod.iter() {
        if u.cite_la_colonne_de_tete.is_empty() {
            continue;
        }
        let mut v = u.cite_la_colonne_de_tete.clone();
        v.sort();
        v.dedup();
        println!("  {nom} <- {} objet(s) : {}", v.len(), v.join(", "));
    }
    println!("\n--- objets dont on NE PEUT PAS conclure ---");
    for (etiquette, motif) in indec_sans.iter().take(40) {
        println!("  {etiquette} : {motif}");
    }
    println!("=== fin ===\n");
}

// ---------------------------------------------------------------------------------------------
// L'AUTRE MOITIÉ DU DEVIS : CE QU'UN INDEX COÛTE À L'ÉCRITURE.
// ---------------------------------------------------------------------------------------------

/// Nombre d'événements par bras d'ablation. 20 000 suffit à sortir du bruit de la première page tout
/// en gardant le banc sous la seconde par bras ; le chiffre publié est un RATIO par événement, pas un
/// total, donc il ne dépend pas de N (vérifié : le doubler ne déplace pas les octets/événement de
/// plus de 3 %).
const EVENEMENTS_DU_BANC: i64 = 20_000;
/// Taille de transaction. L'ingest réel écrit par LOTS (`ingest_events_batch`), et c'est le lot qui
/// fixe combien de pages sont salies deux fois : mesurer ligne à ligne surestimerait grossièrement.
const LOT_DU_BANC: i64 = 1_000;

/// Écrit `EVENEMENTS_DU_BANC` événements par la MÊME porte que l'ingest (`store().insert_event`, donc
/// `EVENT_INSERT_SQL` et son `INSERT OR IGNORE` qui sonde la contrainte `dedup UNIQUE` comme en
/// production), avec des valeurs dont les CARDINALITÉS sont celles du profil de production, et rend
/// `(octets de WAL écrits, croissance du fichier après checkpoint)`.
///
/// Les octets de WAL sont le vrai proxy de l'amplification d'écriture : l'auto-checkpoint est COUPÉ,
/// donc le `-wal` accumule une image par page SALIE par transaction — un index de plus, c'est un
/// b-tree de plus à salir à chaque lot. La croissance du fichier, elle, est le coût de STOCKAGE.
fn cout_decriture(conn: &Connection, chemin: &str) -> (i64, i64) {
    let taille = |suffixe: &str| -> i64 {
        std::fs::metadata(format!("{chemin}{suffixe}")).map(|m| m.len() as i64).unwrap_or(0)
    };
    conn.execute_batch("PRAGMA wal_autocheckpoint=0").expect("auto-checkpoint coupable");
    let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    let db_avant = taille("");
    let base_ts = 1_785_000_000_i64;
    let mut i = 0_i64;
    while i < EVENEMENTS_DU_BANC {
        conn.execute_batch("BEGIN IMMEDIATE").expect("transaction");
        for _ in 0..LOT_DU_BANC {
            // Cardinalités du profil MESURÉ : source 32, category 19, host 2, src_ip 21 140,
            // severity 5 ; longueurs moyennes message 185 o / fields 150 o.
            let src = format!("source-{}", i % 32);
            let cat = format!("cat-{}", i % 19);
            let host = format!("host-{}", i % 2);
            let ip = format!("10.{}.{}.{}", (i / 65536) % 256, (i / 256) % 256, i % 256);
            let msg = format!("evenement {i} — {}", "x".repeat(170));
            let fields = format!("{{\"action\":\"a{}\",\"user\":\"u{}\",\"pad\":\"{}\"}}", i % 7, i % 97, "y".repeat(110));
            store()
                .insert_event(
                    conn,
                    &EventRow {
                        ts: base_ts + i,
                        source: src,
                        category: cat,
                        severity: i % 5,
                        message: msg,
                        host: Some(host),
                        src_ip: Some(ip),
                        dst_ip: None,
                        url: None,
                        dedup: Some(format!("d-{i}")),
                        fields: Some(fields),
                        engagement_id: String::new(),
                        origin: String::new(),
                        env_id: Some("prod".into()),
                    },
                )
                .expect("insertion d'événement");
            i += 1;
        }
        conn.execute_batch("COMMIT").expect("commit");
    }
    let wal = taille("-wal");
    let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
    (wal, taille("") - db_avant)
}

/// L'AUTRE MOITIÉ DU DEVIS, MESURÉE PAR ABLATION. La taille d'un index n'est pas son coût : chaque
/// index est aussi un b-tree à SALIR à chaque lot ingéré, donc des octets de WAL et du temps sous le
/// verrou d'écriture. Ce banc chiffre les deux, par index, sur le SCHÉMA RÉEL.
///
/// CE QUI EST SUPPRIMÉ, ET CE QUI NE L'EST PAS. Chaque bras construit sa PROPRE base temporaire au
/// schéma réel et y retire UN index avant d'écrire ; la base est détruite à la fin du bras. Rien
/// n'est retiré du produit, de `db/schema.sql`, de `migrate.rs` ni d'une base déployée — une ablation
/// est un INSTRUMENT DE MESURE, et c'est précisément la mesure qui manquait pour que la question de
/// retirer quoi que ce soit puisse seulement se poser.
/// `sqlite_autoindex_event_1` n'est PAS ablatable (il naît et meurt avec la contrainte `dedup UNIQUE`
/// qui porte l'exactly-once) : son coût d'écriture reste NON MESURÉ ici, et c'est dit dans le rapport.
///
/// Rejouable : `cargo test --offline --locked cout_decriture -- --nocapture --test-threads=1`
#[test]
fn cout_decriture_par_index_mesure_par_ablation() {
    let mesure_bras = |etiquette: &str, a_retirer: Option<&str>| -> (i64, i64) {
        let (chemin, db) = base_au_schema_reel(etiquette);
        let conn = db.lock();
        if let Some(nom) = a_retirer {
            conn.execute_batch(&format!("DROP INDEX IF EXISTS {nom}")).expect("ablation possible");
        }
        let r = cout_decriture(&conn, chemin.as_str());
        drop(conn);
        r
    };

    let (wal_ref, db_ref) = mesure_bras("idxusage-cout-ref", None);
    let index: Vec<IndexEvent> = {
        let (_c, db) = base_au_schema_reel("idxusage-cout-cat");
        let conn = db.lock();
        index_de_event(&conn)
    };

    println!("\n=== CE QU'UN INDEX DE `event` COÛTE À L'ÉCRITURE (ablation, schéma réel) ===");
    println!(
        "référence : {EVENEMENTS_DU_BANC} événements par lots de {LOT_DU_BANC} · WAL {wal_ref} o ({:.1} o/év.) · \
         fichier +{db_ref} o ({:.1} o/év.)",
        wal_ref as f64 / EVENEMENTS_DU_BANC as f64,
        db_ref as f64 / EVENEMENTS_DU_BANC as f64
    );
    println!("{:<28} {:>14} {:>14} {:>16} {:>16}", "index retiré", "ΔWAL (o)", "Δfichier (o)", "ΔWAL o/év.", "Δfichier o/év.");
    for ix in &index {
        if ix.origine != "c" {
            println!("{:<28} {:>14} {:>14} {:>16} {:>16}", ix.nom, "—", "—", "non ablatable", "(contrainte)");
            continue;
        }
        let (w, d) = mesure_bras("idxusage-cout-bras", Some(&ix.nom));
        println!(
            "{:<28} {:>14} {:>14} {:>16.2} {:>16.2}",
            ix.nom,
            wal_ref - w,
            db_ref - d,
            (wal_ref - w) as f64 / EVENEMENTS_DU_BANC as f64,
            (db_ref - d) as f64 / EVENEMENTS_DU_BANC as f64
        );
    }
    println!("=== fin ===\n");

    assert!(
        wal_ref > 0 && db_ref > 0,
        "banc d'écriture MUET : ni WAL ni fichier n'ont bougé après {EVENEMENTS_DU_BANC} insertions — \
         l'instrument ne mesure rien, et tout Δ publié serait un zéro fabriqué"
    );
}

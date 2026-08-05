// P10.2-d — LA GARDE DÉRIVÉE DES INDEX REDONDANTS.
//
// CE QUE CE FICHIER N'EST PAS : une liste de noms. Une liste de neuf index aurait attrapé les neuf index
// d'hier et RIEN d'autre — elle aurait été périmée le jour où quelqu'un écrit `migrate_v115` avec un
// `CREATE INDEX idx_truc(a)` sur une table dont la PK est `(a, b)`. Ici, aucune liste : on CONSTRUIT le
// schéma que ce binaire produit et on DEMANDE À SQLITE, via `PRAGMA index_list` / `PRAGMA index_xinfo`,
// quels index sont subsumés par un autre. Le dixième doublon introduit demain est donc attrapé PAR
// CONSTRUCTION, sans que son auteur ait à connaître ce fichier.
//
// LA RÈGLE, TELLE QUE SQLITE LA DÉFINIT. Un index B SUBSUME un index A quand la suite ORDONNÉE des
// colonnes-clés de A est un PRÉFIXE de celle de B : tout seek/range que A servait, B le sert avec la MÊME
// colonne de tête. Le DOUBLON EXACT est le cas dégénéré (une suite est un préfixe d'elle-même). C'est bien
// une comparaison de LISTES ORDONNÉES et jamais d'ensembles : `(a, b)` et `(b, a)` ne se subsument pas.
// Le sens de tri (`desc`) et la COLLATION (`coll`) font partie de la clé comparée — deux index de mêmes
// colonnes mais de tri/collation différents ne sont pas interchangeables.
//
// CE QUI EST EXCLU DE LA DÉTECTION, ET POURQUOI (sans ces exclusions, la garde produirait des FAUX POSITIFS
// et serait désarmée en une semaine) :
//   • les index PARTIELS (`partial`=1 dans `PRAGMA index_list`), des DEUX côtés de la relation. Un index
//     partiel ne couvre qu'un sous-ensemble de lignes : il ne peut pas être subsumé par un index plein
//     (il est délibérément plus petit et sert un prédicat que l'autre ne porte pas), et il ne peut subsumer
//     personne (il ne voit pas toutes les lignes). C'est cette exclusion, et elle seule, qui sauve
//     `idx_event_health_beat` (WHERE category='health') et la paire `idx_incident_active`/
//     `idx_incident_notmerged` — trois sosies qui n'en sont pas.
//   • les index d'EXPRESSION (colonne-clé sans nom : `cid`=-2 dans `PRAGMA index_xinfo`). `index_xinfo` ne
//     rend PAS le texte de l'expression, donc deux index d'expression DIFFÉRENTS y sont indiscernables :
//     les comparer produirait des égalités fausses. On leur donne un jeton UNIQUE par index, ce qui les
//     rend inertes des deux côtés (ni subsumés, ni subsumants) — conservateur, jamais faux positif.
//   • les tables internes SQLite (`sqlite_%`) et les tables-fantômes FTS5 : leur indexation appartient à
//     SQLite, pas à ce dépôt.
// Seuls les index d'ORIGINE 'c' (posés par un `CREATE INDEX`) peuvent être DÉCLARÉS redondants : un
// auto-index de contrainte ('u'/'pk') n'est pas droppable, il naît et meurt avec sa table.

/// UNE colonne-clé d'index, telle que `PRAGMA index_xinfo` la rend : nom, sens de tri, collation. Les trois
/// comptent pour décider si deux index sont interchangeables.
#[derive(PartialEq, Eq, Clone, Debug)]
struct CleIndex {
    colonne: String,
    descendant: i64,
    collation: String,
}

/// Un index tel que le catalogue le décrit — pas tel qu'on l'a écrit.
#[derive(Clone, Debug)]
struct IndexObserve {
    nom: String,
    table: String,
    /// 'c' = posé par un `CREATE INDEX` (droppable), 'u' = auto-index d'UNIQUE, 'pk' = auto-index de PRIMARY KEY.
    origine: String,
    /// Colonnes-clés, DANS L'ORDRE de l'index (les colonnes de couverture, `key`=0, sont exclues).
    cles: Vec<CleIndex>,
}

/// Ce que le catalogue de `conn` dit de TOUS les index NON PARTIELS des tables du dépôt. Rien n'est nommé
/// ici : on énumère les tables, puis leurs index, puis les colonnes-clés de chaque index.
fn index_observes(conn: &Connection) -> Vec<IndexObserve> {
    let tables: Vec<String> = {
        let mut st = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' \
                 AND name NOT IN (SELECT name FROM sqlite_master WHERE type='table' AND sql IS NULL) \
                 ORDER BY name",
            )
            .expect("catalogue des tables lisible");
        let it = st.query_map([], |r| r.get::<_, String>(0)).expect("catalogue des tables lisible");
        it.map(|r| r.expect("nom de table lisible")).collect()
    };
    let mut observes = Vec::new();
    for table in tables {
        // `PRAGMA index_list` : (seq, name, unique, origin, partial). On écarte les PARTIELS ici, donc des
        // DEUX côtés de la relation de subsomption — c'est le point qui évite les faux positifs.
        let index: Vec<(String, String)> = {
            let mut st = conn
                .prepare("SELECT name, origin FROM pragma_index_list(?1) WHERE partial=0")
                .expect("pragma index_list disponible");
            let it = st
                .query_map(params![table], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .expect("pragma index_list lisible");
            it.map(|r| r.expect("ligne index_list lisible")).collect()
        };
        for (nom, origine) in index {
            // `PRAGMA index_xinfo` : (seqno, cid, name, desc, coll, key). `key`=1 => colonne-CLÉ (les autres
            // sont les colonnes de couverture ajoutées par SQLite, qui ne participent pas au seek).
            let mut st = conn
                .prepare("SELECT seqno, name, desc, coll FROM pragma_index_xinfo(?1) WHERE key=1 ORDER BY seqno")
                .expect("pragma index_xinfo disponible");
            let it = st
                .query_map(params![nom], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?))
                })
                .expect("pragma index_xinfo lisible");
            let cles: Vec<CleIndex> = it
                .map(|r| {
                    let (seqno, colonne, descendant, collation) = r.expect("ligne index_xinfo lisible");
                    CleIndex {
                        // Colonne d'EXPRESSION (name NULL) -> jeton UNIQUE À CET INDEX : il ne peut alors
                        // ni subsumer ni être subsumé, faute de pouvoir comparer les expressions.
                        colonne: colonne.unwrap_or_else(|| format!("<expression:{nom}:{seqno}>")),
                        descendant,
                        collation,
                    }
                })
                .collect();
            observes.push(IndexObserve { nom, table: table.clone(), origine, cles });
        }
    }
    observes
}

/// LES INDEX REDONDANTS DE `conn`, DÉRIVÉS. Rend `(index redondant, ce qui le subsume)`, trié par nom pour
/// que le message d'échec soit déterministe.
///
/// Un index est redondant s'il est DROPPABLE (origine 'c') et s'il existe, SUR LA MÊME TABLE, un AUTRE index
/// dont la suite de colonnes-clés COMMENCE par la sienne. Départage du doublon exact entre deux index
/// droppables : seul celui dont le nom est le plus GRAND est déclaré redondant, sinon les deux le seraient et
/// aucun ne pourrait survivre.
fn index_redondants(conn: &Connection) -> Vec<(String, String)> {
    let observes = index_observes(conn);
    let mut trouves: Vec<(String, String)> = Vec::new();
    for a in observes.iter().filter(|i| i.origine == "c") {
        if a.cles.is_empty() {
            continue; // rien à comparer (ne devrait pas arriver, mais ne rien supposer)
        }
        for b in observes.iter() {
            if b.nom == a.nom || b.table != a.table || b.cles.len() < a.cles.len() {
                continue;
            }
            if b.cles[..a.cles.len()] != a.cles[..] {
                continue; // pas un préfixe : listes ORDONNÉES, jamais des ensembles
            }
            // Doublon EXACT entre deux index droppables : on n'en déclare qu'UN (le nom le plus grand).
            if b.cles.len() == a.cles.len() && b.origine == "c" && a.nom < b.nom {
                continue;
            }
            let colonnes: Vec<&str> = a.cles.iter().map(|c| c.colonne.as_str()).collect();
            let sub: Vec<&str> = b.cles.iter().map(|c| c.colonne.as_str()).collect();
            trouves.push((
                a.nom.clone(),
                format!(
                    "{} ({}) sur {} — subsumé par {} ({}), origine '{}'",
                    a.nom,
                    colonnes.join(", "),
                    a.table,
                    b.nom,
                    sub.join(", "),
                    b.origine
                ),
            ));
            break; // un subsumant suffit à établir la redondance
        }
    }
    trouves.sort();
    trouves
}

/// LE SCHÉMA QUE CE BINAIRE PRODUIT, sur une base FICHIER (pas `:memory:`) et SANS clé : `PRAGMA index_list`
/// / `index_xinfo` interrogent le catalogue d'une base RÉELLE, sur le même chemin d'ouverture que la
/// production. `TmpDb` possède le répertoire -> la base et ses `-wal`/`-shm` partent avec, y compris si une
/// assertion panique.
fn base_migree_sur_fichier(etiquette: &str) -> (crate::tmp_possede::TmpDb, Connection) {
    let chemin = crate::tmp_possede::TmpDb::neuf(etiquette);
    let conn = Connection::open(chemin.as_str()).expect("base fichier ouvrable");
    prepare_schema(&conn).expect("le schéma que ce binaire déclare doit se construire sur une base neuve");
    (chemin, conn)
}

/// LA GARDE. Deux invariants, tous deux DÉRIVÉS du catalogue — aucun nom d'index n'apparaît dans ce test.
///
/// 1) CE QUE LE DROPPER DE FOND DOIT COUVRIR (base LIVE). Tout index redondant que porte la base doit
///    disparaître quand on appelle LE CODE DE PRODUCTION qui les enlève. Un index redondant qui SURVIT au
///    dropper est un index qui restera indéfiniment sur toutes les bases déployées.
/// 2) CE QU'UNE MIGRATION NE DOIT PLUS POSER (base NEUVE). Après P10.2-d, la chaîne de migrations ne crée
///    plus AUCUN index subsumé : une base neuve n'en porte pas, donc le dropper n'a rien à y faire. C'est
///    l'assertion qui MORD le jour où une migration future en réintroduit un — mesuré par mutation
///    (2026-08-05 : re-poser un seul `CREATE INDEX` retiré suffit à faire ROUGIR ce test, avec le nom de
///    l'index fautif ET celui de son subsumant dans le message).
///
/// L'ordre compte : on MESURE d'abord (sur la base telle que la chaîne l'a laissée), on droppe, on
/// re-mesure, puis on assert — sinon le premier échec masquerait le second.
#[test]
fn aucun_index_du_schema_migre_nest_subsume_par_un_autre() {
    let (_chemin, conn) = base_migree_sur_fichier("idx-redondance");
    let avant = index_redondants(&conn);

    // LE CODE DE PRODUCTION, pas une simulation : les deux droppers de fond, dans l'ordre du boot.
    let db = std::sync::Arc::new(parking_lot::Mutex::new(conn));
    drop_redundant_event_indexes_background(&db);
    drop_prefix_subsumed_indexes_background(&db);
    let survivants = {
        let c = db.lock();
        index_redondants(&c)
    };

    assert!(
        survivants.is_empty(),
        "index REDONDANT non pris en charge par le dropper de fond ({} survivant(s) après \
         drop_redundant_event_indexes_background + drop_prefix_subsumed_indexes_background) :\n  - {}\n\
         Une base DÉPLOYÉE le gardera pour toujours. À ajouter dans maintenance.rs, avec sa garde si son \
         subsumant est un index explicite.",
        survivants.len(),
        survivants.iter().map(|(_, m)| m.as_str()).collect::<Vec<_>>().join("\n  - ")
    );
    assert!(
        avant.is_empty(),
        "la chaîne de migrations POSE {} index redondant(s) sur une base NEUVE :\n  - {}\n\
         Retirer le `CREATE INDEX` à sa source dans migrate.rs (une migration NE REJOUE PAS : la retirer ne \
         peut pas créer la boucle create/drop de P10.2-c) et prévoir son DROP de fond pour les bases LIVE.",
        avant.len(),
        avant.iter().map(|(_, m)| m.as_str()).collect::<Vec<_>>().join("\n  - ")
    );
}

/// L'INSTRUMENT LUI-MÊME — une garde qui ne détecte rien est indiscernable d'une garde satisfaite. Ce test
/// VALIDE le détecteur sur des cas FABRIQUÉS, sans toucher au schéma du produit : il doit voir le préfixe
/// strict et le doublon exact, et NE PAS voir le partiel, l'ordre inversé, ni la collation différente.
#[test]
fn le_detecteur_de_subsomption_voit_les_vrais_doublons_et_ignore_les_sosies() {
    let chemin = crate::tmp_possede::TmpDb::neuf("idx-detecteur");
    let conn = Connection::open(chemin.as_str()).expect("base fichier ouvrable");
    conn.execute_batch(
        "CREATE TABLE t_prefixe(a TEXT, b TEXT, c TEXT);
         CREATE INDEX ix_prefixe_a    ON t_prefixe(a);          -- REDONDANT (préfixe strict)
         CREATE INDEX ix_prefixe_ab   ON t_prefixe(a, b);       -- le subsumant
         CREATE TABLE t_exact(a TEXT, b TEXT);
         CREATE INDEX ix_exact_1      ON t_exact(a, b);         -- doublon exact : UN SEUL des deux
         CREATE INDEX ix_exact_2      ON t_exact(a, b);         -- doit être déclaré redondant
         CREATE TABLE t_contrainte(a TEXT, b TEXT, PRIMARY KEY(a, b));
         CREATE INDEX ix_contrainte_a ON t_contrainte(a);       -- REDONDANT (préfixe de l'auto-index de PK)
         CREATE TABLE t_sosies(a TEXT, b TEXT, cat TEXT);
         CREATE INDEX ix_sosie_partiel ON t_sosies(a) WHERE cat='x';  -- PARTIEL -> jamais redondant
         CREATE INDEX ix_sosie_plein   ON t_sosies(a, b);
         CREATE TABLE t_ordre(a TEXT, b TEXT);
         CREATE INDEX ix_ordre_ba     ON t_ordre(b, a);         -- (b,a) n'est PAS un préfixe de (a,b)
         CREATE INDEX ix_ordre_ab     ON t_ordre(a, b);
         CREATE TABLE t_collation(a TEXT, b TEXT);
         CREATE INDEX ix_coll_nocase  ON t_collation(a COLLATE NOCASE);
         CREATE INDEX ix_coll_binaire ON t_collation(a, b);     -- collation DIFFÉRENTE -> pas interchangeable
         CREATE TABLE t_seule(a TEXT);
         CREATE INDEX ix_seule_a      ON t_seule(a);            -- rien ne la subsume",
    )
    .expect("schéma d'épreuve créable");

    let vus: Vec<String> = index_redondants(&conn).into_iter().map(|(n, _)| n).collect();
    assert_eq!(
        vus,
        vec!["ix_contrainte_a", "ix_exact_2", "ix_prefixe_a"],
        "le détecteur doit voir le préfixe strict, le doublon exact (UN seul des deux) et le préfixe d'un \
         auto-index de contrainte — et RIEN d'autre : ni le partiel, ni l'ordre inversé, ni la collation \
         différente, ni l'index sans subsumant. Vu : {vus:?}"
    );
}

// LA RÉINDEXATION BORNÉE — `plume-daemon reindex` RÉPARE DES INDEX DÉSACCORDÉS DE LEUR TABLE, ET RIEN D'AUTRE
// ================================================================================================
// Le module `reindexation` juge d'abord par le contrôle complet d'`integrity_check`, n'écrit que si TOUTES les lignes
// sont « wrong # of entries in index X » ou « row N missing from index X », relit chaque nom au schéma, réindexe un
// index par transaction, puis rejuge.
//
// LE DÉFAUT, FABRIQUÉ DE FAÇON DÉTERMINISTE (`par_le_fantome`) : une table FANTÔME est déclarée dans `sqlite_master`
// (`PRAGMA writable_schema=ON`) sur la MÊME page racine que la table visée, sans aucun index. Une connexion neuve qui
// supprime ou insère par le fantôme modifie l'arbre de la table sans toucher ses index ; la déclaration du fantôme est
// ensuite retirée de `sqlite_master` (jamais par `DROP TABLE`, qui libérerait les pages de la table). Une suppression
// laisse une entrée d'index ORPHELINE dans chaque index ; une insertion laisse une ligne MANQUANTE de chaque index, et
// une insertion qui double une clé rend la réindexation de l'index d'unicité impossible. Les index automatiques
// (`sqlite_autoindex_*`) sont touchés comme les autres, puisque seul l'arbre de la table bouge.
//
// TÉMOINS : formes exactes des deux lignes sur le moteur lié ; réparation complète (index d'unicité automatique,
// partiel, d'expression JSON ; lectures par chaque index rendues de nouveau) ; ligne manquante ; nom d'index cité ;
// refus sur une ligne d'une autre classe (valeur, page) et sur le plafond de lignes au bord ; `--dry-run` ; drapeau
// d'acceptation absent ; nom relu au schéma ; relecture impossible ; ouverture en écriture sans création ; unicité
// violée ; base occupée au `BEGIN` et au `COMMIT` ; verrou rendu entre deux index ; contrôle d'après corrompu ou qui
// refuse de conclure ; base saine ; base chiffrée sous clé ; `cipher_integrity_check` en défaut ; contrôle interrompu
// ou sans verdict ; compagnons d'une base WAL fermée ; chaque index d'un schéma complet rebâti par l'écrivain ; `main`
// en sous-processus.
//
// MUTANTS JOUÉS (par variable d'environnement, retirés avant le commit), tous rouges : RI_CLASSE_COMPTE,
// RI_CLASSE_LIGNE, RI_CLASSE_TOUT, RI_SANS_SAUT, RI_RANGEE, RI_PLAFOND_IGNORE, RI_PLAFOND_ABSENT_OK, RI_CIPHER_IGNORE,
// RI_PLAN_DOUBLONS, RI_RELECTURE_IGNOREE, RI_RELECTURE_ERR_OK, RI_RELECTURE_OUVERTURE_OK, RI_DRY_RUN_IGNORE,
// RI_DRY_RUN_CODE, RI_DRAPEAU_IGNORE, RI_CREATION, RI_CITATION_NUE, RI_CITATION_SANS_DOUBLAGE, RI_SCHEMA_QUALIFIE,
// RI_ARRET_AU_PREMIER_ECHEC, RI_ECHECS_NON_COMPTES, RI_APRES_IGNORE, RI_SAIN_SANS_RETOUR, RI_REFUS_AVANT_CONTINUE,
// RI_TRANSACTION_UNIQUE, RI_COMMIT_IGNORE, RI_ROLLBACK_OUBLIE, RI_CAUSE_OCCUPEE, RI_CAUSE_UNICITE, RI_CODE_PRIMAIRE,
// RI_VERROU_TENU_TOUJOURS, RI_SANS_ATTENTE, RI_ECRIVAIN_SANS_CLE, RI_MAIN_SANS_CLE, RI_ARGS_INCONNU, RI_ARGS_SECOND ;
// puis V_RELU_SANS_TYPE (relecture sans `type = 'index'`), V_RELU_LIKE (`name LIKE ?1`), V_DRY_APRES_DRAPEAU (le
// drapeau jugé avant `--dry-run`), V_ECRIVAIN_SANS_BUSY (l'écrivain sans `busy_timeout`), V_SAIN_OUVRE et V_DRY_OUVRE
// (l'écrivain ouvert, lu puis fermé avant le retour « sain » ou « a_reindexer »), V_CIPHER_NUL_SOUS_CLE,
// V_CIPHER_ERREUR_IGNOREE, et l'aide de `reindex` privée de sa sortie 78 ; puis RC_APRES_REFUS_OK (un contrôle d'après
// qui n'est pas « corrompu » pris pour sain).
//
// « RIEN D'OUVERT EN ÉCRITURE » se juge sur la date du RÉPERTOIRE, pas sur l'absence de `-wal`/`-shm` au retour : sur
// une base WAL fermée, un écrivain qui ouvre puis ferme crée puis retire lui-même ses compagnons.
//
// CE QUE CE FICHIER NE TIENT PAS : la durée pendant laquelle le verrou est tenu (aucune assertion d'horloge) ; la
// course entre la relecture et l'ouverture en écriture pour un compagnon ; la propriété root des compagnons créés sous
// `sudo` ; l'effet réel sur un démon vivant (le comportement de ses écritures est établi par lecture, dans la doc du
// module).
mod reindexation_bornee {
    use crate::integrity_check::{verifier, Mode};
    use crate::reindexation::{
        analyser_les_arguments, index_desaccorde, ouvrir_l_ecrivain, plan_du_verdict, reindexer, reindexer_avec_attente,
        reindexer_un_index, Arguments, CODE_NON_REPARE, CODE_REFUS, CODE_SAIN_OU_REPARE, CROCHET_DE_PHASE,
        PHASE_APRES_LE_VERDICT_D_AVANT, PHASE_APRES_UN_INDEX, PHASE_AVANT_L_OUVERTURE_EN_ECRITURE,
    };

    const RI_ENFANT: &str = "REINDEX_ENFANT_MAIN";
    const RI_MARQUE_ENFANT: &str = "REINDEX-ENFANT-APPELLE-MAIN";
    /// Lue par `reindexation::arguments_a_analyser` sous `cfg(test)` seulement.
    const RI_ARGUMENTS: &str = "REINDEX_ARGUMENTS_DE_L_ENFANT";
    const CLE_DU_TEMOIN: &str = "temoin-reindexation";
    /// L'attente des témoins de base occupée : le refus vient de `SQLITE_BUSY`, pas de l'attente de production.
    const ATTENTE_DU_TEMOIN: std::time::Duration = std::time::Duration::from_millis(100);

    // Les phrases servies, écrites ici à la main (jamais lues dans le code de production).
    const PHRASE_ATTENDUE_DES_ECRITURES_REFUSEES: &str = "écriture non tentée : pendant chaque REINDEX le verrou d'écriture est tenu, \
     et les écritures du démon vivant qui attendent plus de 5 s sont refusées — lot d'ingestion du spool laissé en place et rejoué, \
     lot d'un récepteur HTTP rendu en 503 (à réémettre par l'émetteur), cache de panneau recalculé, mais alerte d'une règle qui tire \
     réévaluée sur une fenêtre qui a glissé : un franchissement de seuil peut se PERDRE ; relancer avec \
     --accepter-les-ecritures-refusees pour passer outre, drapeau exigé dans tous les cas (démon arrêté, aucune \
     écriture du démon n'est refusée)";
    const CAUSE_ATTENDUE_OCCUPEE: &str = "base occupée au-delà de l'attente : verrou d'écriture non pris, rien n'est écrit pour cet index";
    const CAUSE_ATTENDUE_UNICITE: &str =
        "contrainte d'unicité violée : la table porte deux lignes de même clé, l'index ne peut pas être rebâti sans décider laquelle garder";
    const CAUSE_ATTENDUE_MOTEUR: &str = "réindexation refusée par le moteur";

    /// La table des événements du témoin : un index ordinaire, un index PARTIEL, un index d'EXPRESSION sur un champ JSON
    /// (forme des index de champ chaud du démon) et l'index AUTOMATIQUE d'une contrainte d'unicité.
    const DDL_EVENEMENTS: &str = "CREATE TABLE ri_ev(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, source TEXT, category TEXT, \
         fields TEXT, dedup TEXT UNIQUE); \
         CREATE INDEX ri_ev_ts ON ri_ev(ts); \
         CREATE INDEX ri_ev_sante ON ri_ev(source, ts) WHERE category = 'health'; \
         CREATE INDEX ri_ev_f_user ON ri_ev(json_extract(fields, '$.user')) WHERE json_extract(fields, '$.user') IS NOT NULL;";
    const FANTOME_DES_EVENEMENTS: &str =
        "CREATE TABLE ri_fantome(id INTEGER PRIMARY KEY, ts INTEGER, source TEXT, category TEXT, fields TEXT, dedup TEXT)";
    /// Les quatre index de `ri_ev`, dans l'ordre où le moteur les parcourt (le dernier créé d'abord, l'automatique en
    /// dernier) : c'est l'ordre des lignes du contrôle, donc celui du plan.
    const INDEX_DES_EVENEMENTS: [&str; 4] = ["ri_ev_f_user", "ri_ev_sante", "ri_ev_ts", "sqlite_autoindex_ri_ev_1"];
    /// La ligne 6 porte les quatre index : catégorie `health`, champ `user`, clé `dedup`.
    const SUPPRIMER_LA_LIGNE_6: &str = "DELETE FROM ri_fantome WHERE id = 6";

    fn existe(p: &str) -> bool {
        std::path::Path::new(p).exists()
    }

    /// La date de modification du RÉPERTOIRE de la base : créer PUIS retirer `-wal`/`-shm` la change, même quand les
    /// deux ont disparu au retour. C'est ce qu'un `!existe(-wal)` après coup ne voit pas : sur une base WAL fermée,
    /// l'écrivain qui ouvre puis ferme retire lui-même ses compagnons.
    fn date_du_repertoire(base: &str) -> std::time::SystemTime {
        let rep = std::path::Path::new(base).parent().expect("témoin : la base a un répertoire");
        std::fs::metadata(rep).and_then(|m| m.modified()).expect("témoin : date du répertoire")
    }

    /// Entre le relevé et le geste : plus long qu'un tic de l'horloge des fichiers (un tic d'ordonnanceur, 10 ms au
    /// plus), pour qu'une création pendant le geste ne tombe pas dans le tic de la dernière modification de la fixture.
    const PAUSE_D_UN_TIC: std::time::Duration = std::time::Duration::from_millis(50);

    fn ouvrir(chemin: &str, cle: Option<&str>) -> rusqlite::Connection {
        let c = rusqlite::Connection::open(chemin).expect("fixture : ouverture");
        crate::db_open::appliquer_une_cle_explicite(&c, cle).expect("fixture : clé");
        c
    }

    /// Vingt événements ; une ligne sur deux en `health`, une sur trois avec un `user`, chacune sa clé `dedup`.
    fn base_d_evenements(chemin: &str, cle: Option<&str>, wal: bool) {
        let c = ouvrir(chemin, cle);
        if wal {
            let m: String = c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).expect("fixture : WAL");
            assert_eq!(m, "wal", "fixture : la base passe en WAL");
        }
        c.execute_batch(DDL_EVENEMENTS).expect("fixture : schéma");
        for i in 1..=20i64 {
            let categorie = if i % 2 == 0 { "health" } else { "auth" };
            let champs = if i % 3 == 0 { r#"{"user":"alice"}"# } else { "{}" };
            c.execute(
                "INSERT INTO ri_ev(id, ts, source, category, fields, dedup) VALUES(?1, ?2, 's', ?3, ?4, ?5)",
                rusqlite::params![i, 1000 + i, categorie, champs, format!("d{i}")],
            )
            .expect("fixture : ligne");
        }
    }

    /// LE GESTE QUI FABRIQUE LE DÉFAUT : `geste` est joué sur la table FANTÔME `ri_fantome` (déclarée par `ddl_fantome`
    /// sur la page racine de `table`), puis le fantôme est retiré du catalogue. Chaque étape sur une connexion neuve :
    /// une connexion garde en mémoire le catalogue qu'elle a lu.
    fn par_le_fantome(chemin: &str, cle: Option<&str>, table: &str, ddl_fantome: &str, geste: &str) {
        {
            let c = ouvrir(chemin, cle);
            let racine: i64 = c
                .query_row("SELECT rootpage FROM sqlite_master WHERE type = 'table' AND name = ?1", [table], |r| r.get(0))
                .expect("fixture : page racine");
            c.execute_batch("PRAGMA writable_schema=ON;").expect("fixture : catalogue ouvert");
            c.execute(
                "INSERT INTO sqlite_master(type, name, tbl_name, rootpage, sql) VALUES('table', 'ri_fantome', 'ri_fantome', ?1, ?2)",
                rusqlite::params![racine, ddl_fantome],
            )
            .expect("fixture : fantôme déclaré");
            c.execute_batch("PRAGMA writable_schema=OFF;").expect("fixture : catalogue refermé");
        }
        {
            let c = ouvrir(chemin, cle);
            c.execute_batch(geste).expect("fixture : geste par le fantôme");
        }
        {
            let c = ouvrir(chemin, cle);
            c.execute_batch("PRAGMA writable_schema=ON;").expect("fixture : catalogue ouvert");
            c.execute("DELETE FROM sqlite_master WHERE name = 'ri_fantome'", []).expect("fixture : fantôme retiré");
            c.execute_batch("PRAGMA writable_schema=OFF;").expect("fixture : catalogue refermé");
        }
    }

    fn orpheline(chemin: &str, cle: Option<&str>) {
        par_le_fantome(chemin, cle, "ri_ev", FANTOME_DES_EVENEMENTS, SUPPRIMER_LA_LIGNE_6);
    }

    fn lignes_du_controle(chemin: &str, cle: Option<&str>) -> Vec<String> {
        let v = verifier(chemin, Mode::Complet, cle);
        v.rapport["lignes"].as_array().cloned().unwrap_or_default().iter().map(|l| l.as_str().unwrap_or("").to_string()).collect()
    }

    fn accepter() -> Arguments {
        Arguments { sans_ecrire: false, accepter_les_ecritures_refusees: true, chemin: None }
    }

    /// Une lecture qui passe par l'index nommé et lit une colonne de la table (donc suit l'entrée de l'index jusqu'à sa
    /// ligne) : `Ok(n)` lignes, ou le code de l'erreur.
    fn lire_par(c: &rusqlite::Connection, sql: &str) -> Result<usize, Option<rusqlite::ErrorCode>> {
        let mut st = c.prepare(sql).map_err(|e| e.sqlite_error_code())?;
        let mut rows = st.query([]).map_err(|e| e.sqlite_error_code())?;
        let mut n = 0usize;
        loop {
            match rows.next() {
                Ok(Some(r)) => {
                    let _: Option<String> = r.get(1).map_err(|e| e.sqlite_error_code())?;
                    n += 1;
                }
                Ok(None) => return Ok(n),
                Err(e) => return Err(e.sqlite_error_code()),
            }
        }
    }

    /// Les quatre lectures, une par index, qui atteignent la ligne 6.
    const LECTURES_PAR_INDEX: [&str; 4] = [
        "SELECT id, fields FROM ri_ev INDEXED BY ri_ev_ts WHERE ts = 1006",
        "SELECT id, fields FROM ri_ev INDEXED BY ri_ev_sante WHERE category = 'health' AND source = 's' AND ts = 1006",
        "SELECT id, source FROM ri_ev INDEXED BY ri_ev_f_user WHERE json_extract(fields, '$.user') = 'alice'",
        "SELECT id, fields FROM ri_ev INDEXED BY sqlite_autoindex_ri_ev_1 WHERE dedup = 'd6'",
    ];

    /// Pose le crochet de phase pour ce fil, et le retire en sortie (même sur un échec d'assertion).
    struct CrochetPose;
    impl CrochetPose {
        fn poser(f: fn(&str, &str)) -> Self {
            CROCHET_DE_PHASE.with(|c| c.set(f));
            CrochetPose
        }
    }
    impl Drop for CrochetPose {
        fn drop(&mut self) {
            CROCHET_DE_PHASE.with(|c| c.set(crate::reindexation::sans_crochet));
        }
    }

    thread_local! {
        static VERROUS_PRIS_ENTRE_DEUX_INDEX: std::cell::Cell<(u32, u32)> = const { std::cell::Cell::new((0, 0)) };
        static FANTOME_APRES_LE_DERNIER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        static JOURNAL_APRES_LE_DERNIER: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    }

    // ── 1. LES FORMES DU MOTEUR LIÉ ─────────────────────────────────────────────────────────────

    #[test]
    fn reindex_les_formes_du_moteur_lie_pour_une_entree_orpheline_et_une_ligne_manquante() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-formes");
        let a = _tmp.sous("orpheline.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&a, None, false);
        orpheline(&a, None);
        let attendu: Vec<String> = INDEX_DES_EVENEMENTS.iter().map(|n| format!("wrong # of entries in index {n}")).collect();
        assert_eq!(lignes_du_controle(&a, None), attendu, "entrée orpheline : une ligne de compte par index, dans l'ordre du moteur");

        let b = _tmp.sous("manquante.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&b, None, false);
        par_le_fantome(
            &b,
            None,
            "ri_ev",
            FANTOME_DES_EVENEMENTS,
            r#"INSERT INTO ri_fantome(id, ts, source, category, fields, dedup) VALUES(100, 5000, 's', 'health', '{"user":"bob"}', 'd100')"#,
        );
        let mut attendu: Vec<String> = INDEX_DES_EVENEMENTS.iter().map(|n| format!("row 21 missing from index {n}")).collect();
        attendu.extend(INDEX_DES_EVENEMENTS.iter().map(|n| format!("wrong # of entries in index {n}")));
        assert_eq!(lignes_du_controle(&b, None), attendu, "ligne manquante : sa ligne puis le compte, par index");
        for l in &attendu {
            assert!(index_desaccorde(l).is_some_and(|n| INDEX_DES_EVENEMENTS.contains(&n)), "la classe lit le nom de l'index : {l}");
        }
    }

    #[test]
    fn reindex_la_classe_refuse_tout_ce_qui_n_est_pas_exactement_une_des_deux_formes() {
        assert_eq!(index_desaccorde("wrong # of entries in index ri_ev_ts"), Some("ri_ev_ts"));
        assert_eq!(index_desaccorde("row 12 missing from index ri_ev_ts"), Some("ri_ev_ts"));
        for refusee in [
            "wrong # of entries in index ",
            "row  missing from index ri_ev_ts",
            "row x12 missing from index ri_ev_ts",
            "row -12 missing from index ri_ev_ts",
            "row 12 missing from index ",
            "wrong # of entries in index ri_ev_ts\nPage 4: btreeInitPage() returns error code 11",
            "row 12 missing from index ri_ev_ts\rx",
            "NULL value in ri_ev.ts",
            "*** in database main ***\nPage 6: unable to get the page. error code=11",
            "ok",
            "",
        ] {
            assert_eq!(index_desaccorde(refusee), None, "hors de la classe : {refusee:?}");
        }
    }

    // ── 2. LA RÉPARATION ────────────────────────────────────────────────────────────────────────

    #[test]
    fn reindex_repare_une_entree_orpheline_index_partiel_expression_json_et_unicite_automatique() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-repare");
        // `#`, `?` et `%41` dans le nom : l'écrivain ouvre CE fichier, pas un chemin tronqué ou décodé.
        let base = _tmp.sous("evenements #1 ?x %41.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        orpheline(&base, None);
        {
            let c = ouvrir(&base, None);
            for sql in LECTURES_PAR_INDEX {
                assert_eq!(lire_par(&c, sql), Err(Some(rusqlite::ErrorCode::DatabaseCorrupt)), "avant : l'entrée orpheline rend SQLITE_CORRUPT : {sql}");
            }
        }
        let r = reindexer(&base, &accepter(), None);
        let l = &r.ligne;
        assert_eq!(r.code, CODE_SAIN_OU_REPARE, "{l}");
        assert_eq!(l["code"], CODE_SAIN_OU_REPARE);
        assert_eq!(l["verdict"], "repare", "{l}");
        assert_eq!(l["cause"], serde_json::Value::Null);
        assert_eq!(l["ligne_refusee"], serde_json::Value::Null);
        assert_eq!(l["accepte_les_ecritures_refusees"], true, "{l}");
        assert_eq!(l["dry_run"], false, "{l}");
        assert_eq!(l["cle_appliquee"], false, "{l}");
        assert_eq!(l["attente_du_verrou_ms"], 10_000, "l'attente bornée de production est dite : {l}");
        assert_eq!(l["avant"]["verdict"], "corrompu", "{l}");
        assert_eq!(l["apres"]["verdict"], "sain", "{l}");
        assert_eq!(l["plan"], serde_json::json!(INDEX_DES_EVENEMENTS), "un index par ligne, ordre des lignes, sans doublon : {l}");
        let index = l["index"].as_array().cloned().unwrap_or_default();
        assert_eq!(index.len(), INDEX_DES_EVENEMENTS.len(), "{l}");
        for (i, nom) in INDEX_DES_EVENEMENTS.iter().enumerate() {
            assert_eq!(index[i]["index"], *nom, "{l}");
            assert_eq!(index[i]["issue"], "reindexe", "{l}");
            assert!(index[i]["verrou_tenu_ms"].is_u64(), "la durée du verrou tenu est rendue : {l}");
            assert_eq!(index[i]["code"], serde_json::Value::Null);
        }
        let c = ouvrir(&base, None);
        for sql in LECTURES_PAR_INDEX {
            assert!(lire_par(&c, sql).is_ok(), "après : la lecture par l'index est de nouveau servie : {sql}");
        }
        assert_eq!(lire_par(&c, LECTURES_PAR_INDEX[0]), Ok(0), "la ligne supprimée n'est plus atteinte par l'index");
        assert_eq!(lire_par(&c, LECTURES_PAR_INDEX[2]), Ok(5), "les six lignes `alice` moins la supprimée");
    }

    #[test]
    fn reindex_repare_une_ligne_manquante_de_chaque_index() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-manquante");
        let base = _tmp.sous("manquante.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        par_le_fantome(
            &base,
            None,
            "ri_ev",
            FANTOME_DES_EVENEMENTS,
            r#"INSERT INTO ri_fantome(id, ts, source, category, fields, dedup) VALUES(100, 5000, 's', 'health', '{"user":"bob"}', 'd100')"#,
        );
        let r = reindexer(&base, &accepter(), None);
        assert_eq!(r.code, CODE_SAIN_OU_REPARE, "{}", r.ligne);
        assert_eq!(r.ligne["plan"], serde_json::json!(INDEX_DES_EVENEMENTS), "chaque nom une fois, malgré deux lignes par index : {}", r.ligne);
        let c = ouvrir(&base, None);
        let n: i64 = c
            .query_row("SELECT count(*) FROM ri_ev INDEXED BY ri_ev_f_user WHERE json_extract(fields, '$.user') = 'bob'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "la ligne manquante est de nouveau trouvée par l'index d'expression");
        let n: i64 = c.query_row("SELECT count(*) FROM ri_ev INDEXED BY sqlite_autoindex_ri_ev_1 WHERE dedup = 'd100'", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "et par l'index d'unicité automatique");
    }

    #[test]
    fn reindex_un_nom_d_index_avec_guillemet_et_espace_est_cite_comme_identifiant() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-cite");
        let base = _tmp.sous("cite.db").chemin().to_string_lossy().into_owned();
        {
            let c = ouvrir(&base, None);
            c.execute_batch(
                "CREATE TABLE ri_ci(id INTEGER PRIMARY KEY, v INTEGER); CREATE INDEX \"ri \"\"drole\"\" idx\" ON ri_ci(v); \
                 INSERT INTO ri_ci(id, v) VALUES (1, 1), (2, 2), (3, 3);",
            )
            .unwrap();
        }
        par_le_fantome(&base, None, "ri_ci", "CREATE TABLE ri_fantome(id INTEGER PRIMARY KEY, v INTEGER)", "DELETE FROM ri_fantome WHERE id = 2");
        let r = reindexer(&base, &accepter(), None);
        assert_eq!(r.ligne["plan"], serde_json::json!(["ri \"drole\" idx"]), "{}", r.ligne);
        assert_eq!(r.ligne["index"][0]["issue"], "reindexe", "{}", r.ligne);
        assert_eq!(r.code, CODE_SAIN_OU_REPARE, "{}", r.ligne);
    }

    /// Un index qui porte le nom d'une collation du moteur (`rtrim`) : sans nom de schéma, `REINDEX rtrim` rebâtirait
    /// les index qui emploient cette collation (aucun ici) et laisserait l'index nommé en défaut. La forme qualifiée
    /// `REINDEX "main"."rtrim"` désigne l'index.
    #[test]
    fn reindex_un_index_au_nom_de_collation_est_designe_par_la_forme_qualifiee() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-collation");
        let base = _tmp.sous("collation.db").chemin().to_string_lossy().into_owned();
        {
            let c = ouvrir(&base, None);
            c.execute_batch(
                "CREATE TABLE ri_rt(id INTEGER PRIMARY KEY, v INTEGER); CREATE INDEX rtrim ON ri_rt(v); \
                 INSERT INTO ri_rt(id, v) VALUES (1, 1), (2, 2), (3, 3);",
            )
            .unwrap();
        }
        par_le_fantome(&base, None, "ri_rt", "CREATE TABLE ri_fantome(id INTEGER PRIMARY KEY, v INTEGER)", "DELETE FROM ri_fantome WHERE id = 2");
        let r = reindexer(&base, &accepter(), None);
        assert_eq!(r.ligne["plan"], serde_json::json!(["rtrim"]), "{}", r.ligne);
        assert_eq!(r.ligne["apres"]["verdict"], "sain", "l'index nommé est rebâti, pas les index d'une collation : {}", r.ligne);
        assert_eq!(r.code, CODE_SAIN_OU_REPARE, "{}", r.ligne);
    }

    // ── 3. LES REFUS AVANT TOUTE ÉCRITURE ───────────────────────────────────────────────────────

    #[test]
    fn reindex_refuse_une_valeur_nulle_d_une_colonne_non_nulle_et_n_ecrit_rien() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-autre-classe");
        let base = _tmp.sous("nulle.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        par_le_fantome(
            &base,
            None,
            "ri_ev",
            FANTOME_DES_EVENEMENTS,
            "INSERT INTO ri_fantome(id, ts, source, category, fields, dedup) VALUES(100, NULL, 's', 'auth', '{}', 'd100')",
        );
        let lignes = lignes_du_controle(&base, None);
        assert!(lignes.iter().any(|l| l == "NULL value in ri_ev.ts"), "fixture : la ligne d'une autre classe : {lignes:?}");
        assert!(lignes.iter().any(|l| index_desaccorde(l).is_some()), "fixture : elle côtoie des lignes réparables : {lignes:?}");
        let octets = std::fs::read(&base).unwrap();
        let r = reindexer(&base, &accepter(), None);
        assert_eq!(r.code, CODE_REFUS, "{}", r.ligne);
        assert_eq!(r.ligne["verdict"], "refus");
        assert_eq!(r.ligne["ligne_refusee"], "NULL value in ri_ev.ts", "la ligne qui fait refuser est nommée : {}", r.ligne);
        assert_eq!(r.ligne["index"], serde_json::json!([]));
        assert_eq!(r.ligne["apres"], serde_json::Value::Null);
        assert_eq!(std::fs::read(&base).unwrap(), octets, "rien n'est écrit");
        assert!(!existe(&format!("{base}-journal")) && !existe(&format!("{base}-wal")), "aucun compagnon créé");
    }

    /// Une entrée orpheline ET un défaut de liste libre (le compte de pages libres de l'en-tête falsifié sur une base
    /// sans page libre) : le moteur rend les lignes des deux classes sans erreur ; la ligne de liste libre fait refuser.
    #[test]
    fn reindex_refuse_un_defaut_de_liste_libre_cote_a_cote_avec_des_index_et_n_ecrit_rien() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-liste-libre");
        let base = _tmp.sous("libre.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        orpheline(&base, None);
        let mut octets = std::fs::read(&base).unwrap();
        assert_eq!(&octets[32..40], &[0u8; 8], "fixture : aucune page libre");
        octets[36..40].copy_from_slice(&5u32.to_be_bytes());
        std::fs::write(&base, &octets).unwrap();
        let v = verifier(&base, Mode::Complet, None);
        assert_eq!(v.rapport["plafond_atteint"], false, "fixture : le contrôle a rendu toutes ses lignes : {}", v.rapport);
        let lignes = lignes_du_controle(&base, None);
        let etrangeres: Vec<&String> = lignes.iter().filter(|l| index_desaccorde(l).is_none()).collect();
        assert!(!etrangeres.is_empty() && lignes.iter().any(|l| index_desaccorde(l).is_some()), "fixture : deux classes : {lignes:?}");
        let r = reindexer(&base, &accepter(), None);
        assert_eq!(r.code, CODE_REFUS, "{}", r.ligne);
        assert_eq!(r.ligne["ligne_refusee"], serde_json::json!(etrangeres[0]), "{}", r.ligne);
        assert_eq!(r.ligne["index"], serde_json::json!([]));
        assert_eq!(std::fs::read(&base).unwrap(), octets, "rien n'est écrit");
    }

    /// La ligne d'une autre classe EN TÊTE, AU MILIEU et EN QUEUE d'une liste réparable : chaque position refuse.
    #[test]
    fn reindex_une_seule_ligne_d_une_autre_classe_refuse_en_tete_au_milieu_et_en_queue() {
        let rapport = |lignes: &[&str]| {
            serde_json::json!({ "plafond_atteint": false, "cle_appliquee": false, "cipher_integrity_check": serde_json::Value::Null, "lignes": lignes })
        };
        let reparables = ["wrong # of entries in index a", "row 3 missing from index b", "wrong # of entries in index b"];
        assert_eq!(plan_du_verdict(&rapport(&reparables)), Ok(vec!["a".to_string(), "b".to_string()]));
        let etrangere = "Page 9: free space corruption";
        for position in 0..=reparables.len() {
            let mut lignes = reparables.to_vec();
            lignes.insert(position, etrangere);
            match plan_du_verdict(&rapport(&lignes)) {
                Err((_, refusee)) => assert_eq!(refusee.as_deref(), Some(etrangere), "position {position}"),
                Ok(p) => panic!("position {position} : la ligne étrangère est passée, plan {p:?}"),
            }
        }
        assert!(plan_du_verdict(&serde_json::json!({ "plafond_atteint": false, "cle_appliquee": true, "cipher_integrity_check": [], "lignes": reparables })).is_ok());
        let non_texte = serde_json::json!({ "plafond_atteint": false, "cle_appliquee": false, "cipher_integrity_check": serde_json::Value::Null, "lignes": [1] });
        assert_eq!(plan_du_verdict(&non_texte).map_err(|e| e.1), Err(Some("1".to_string())), "une ligne qui n'est pas un texte refuse");
        let indisponible =
            serde_json::json!({ "plafond_atteint": false, "cle_appliquee": true, "cipher_integrity_check": "indisponible : moteur sans SQLCipher", "lignes": reparables });
        assert_eq!(plan_du_verdict(&indisponible).map_err(|e| e.1), Err(Some("indisponible : moteur sans SQLCipher".to_string())));
    }

    /// SOUS CLÉ, SEUL UN `[]` SANS ERREUR DIT « HMAC SAIN ». Une erreur sur `cipher_version` laisse la valeur absente ;
    /// un contrôle interrompu avant sa première ligne laisse `[]`, l'erreur à côté (`cipher_integrity_check_erreur`).
    /// Les deux refusent, même quand toutes les lignes de structure sont réparables.
    #[test]
    fn reindex_sous_cle_un_cipher_integrity_check_absent_ou_interrompu_refuse() {
        let reparables = ["wrong # of entries in index a"];
        let sous_cle_sain = serde_json::json!({ "plafond_atteint": false, "cle_appliquee": true, "cipher_integrity_check": [], "lignes": reparables });
        assert_eq!(plan_du_verdict(&sous_cle_sain), Ok(vec!["a".to_string()]), "contrôle : sous clé, `[]` sans erreur passe");

        let absent = serde_json::json!({ "plafond_atteint": false, "cle_appliquee": true, "lignes": reparables });
        match plan_du_verdict(&absent) {
            Err((cause, _)) => assert!(cause.starts_with("cipher_integrity_check n'a pas rendu de verdict (clé appliquée : oui)"), "{cause}"),
            Ok(p) => panic!("sous clé, une valeur absente est passée pour un HMAC sain : {p:?}"),
        }

        let erreur = "database disk image is malformed";
        let interrompu = serde_json::json!({
            "plafond_atteint": false, "cle_appliquee": true, "cipher_integrity_check": [],
            "cipher_integrity_check_erreur": erreur, "lignes": reparables,
        });
        match plan_du_verdict(&interrompu) {
            Err((cause, refusee)) => {
                assert!(cause.starts_with("cipher_integrity_check interrompu par une erreur du moteur"), "{cause}");
                assert_eq!(refusee.as_deref(), Some(erreur));
            }
            Ok(p) => panic!("un contrôle interrompu avant sa première ligne est passé pour un HMAC sain : {p:?}"),
        }

        let sans_cle_avec_valeur = serde_json::json!({ "plafond_atteint": false, "cle_appliquee": false, "cipher_integrity_check": [], "lignes": reparables });
        assert!(plan_du_verdict(&sans_cle_avec_valeur).is_err(), "sans clé, aucune valeur de HMAC n'est attendue");
    }

    /// Une table, un index : k lignes insérées par le fantôme donnent k lignes « row N missing » plus une ligne de
    /// compte. 98 lignes -> 99 lignes de contrôle, sous le plafond : plan. 99 -> 100 lignes, le plafond : refus.
    #[test]
    fn reindex_plafond_de_lignes_au_bord() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-plafond");
        let plafond = crate::integrity_check::PLAFOND_DE_LIGNES;
        for (inserees, refuse) in [(plafond - 2, false), (plafond - 1, true)] {
            let base = _tmp.sous(&format!("plafond-{inserees}.db")).chemin().to_string_lossy().into_owned();
            {
                let c = ouvrir(&base, None);
                c.execute_batch("CREATE TABLE ri_pl(id INTEGER PRIMARY KEY, v INTEGER); CREATE INDEX ri_pl_v ON ri_pl(v); INSERT INTO ri_pl VALUES (1, 1);").unwrap();
            }
            let geste = format!(
                "WITH RECURSIVE n(i) AS (SELECT 2 UNION ALL SELECT i+1 FROM n WHERE i<{}) INSERT INTO ri_fantome SELECT i, i FROM n;",
                inserees + 1
            );
            par_le_fantome(&base, None, "ri_pl", "CREATE TABLE ri_fantome(id INTEGER PRIMARY KEY, v INTEGER)", &geste);
            assert_eq!(lignes_du_controle(&base, None).len(), (inserees + 1).min(plafond), "fixture : lignes du contrôle");
            let octets = std::fs::read(&base).unwrap();
            let r = reindexer(&base, &accepter(), None);
            if refuse {
                assert_eq!(r.code, CODE_REFUS, "plafond atteint : {}", r.ligne);
                assert!(r.ligne["cause"].as_str().unwrap_or("").starts_with("le contrôle a atteint son plafond de "), "{}", r.ligne);
                assert_eq!(std::fs::read(&base).unwrap(), octets, "rien n'est écrit");
            } else {
                assert_eq!(r.code, CODE_SAIN_OU_REPARE, "sous le plafond : {}", r.ligne);
                assert_eq!(r.ligne["plan"], serde_json::json!(["ri_pl_v"]));
            }
        }
    }

    #[test]
    fn reindex_dry_run_dit_le_plan_et_n_ecrit_rien_meme_avec_l_acceptation() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-dry-run");
        let base = _tmp.sous("wal-fermee.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, true);
        orpheline(&base, None);
        assert!(!existe(&format!("{base}-wal")) && !existe(&format!("{base}-shm")), "fixture : base WAL fermée proprement");
        let octets = std::fs::read(&base).unwrap();
        let date = date_du_repertoire(&base);
        std::thread::sleep(PAUSE_D_UN_TIC);
        let args = Arguments { sans_ecrire: true, accepter_les_ecritures_refusees: true, chemin: None };
        let r = reindexer(&base, &args, None);
        assert_eq!(r.code, CODE_NON_REPARE, "{}", r.ligne);
        assert_eq!(r.ligne["verdict"], "a_reindexer");
        assert_eq!(r.ligne["dry_run"], true);
        assert_eq!(r.ligne["plan"], serde_json::json!(INDEX_DES_EVENEMENTS), "{}", r.ligne);
        assert_eq!(r.ligne["index"], serde_json::json!([]));
        assert_eq!(r.ligne["apres"], serde_json::Value::Null);
        assert_eq!(std::fs::read(&base).unwrap(), octets, "--dry-run n'écrit rien");
        assert_eq!(date_du_repertoire(&base), date, "--dry-run n'ouvre rien en écriture : aucun compagnon créé puis retiré");
    }

    /// `--dry-run` n'a pas besoin du drapeau d'acceptation : sans lui, il dit le plan et sort en 1, il ne refuse pas en
    /// 2 avec la phrase des écritures refusées. Base WAL fermée : rien n'est ouvert en écriture, même brièvement.
    #[test]
    fn reindex_dry_run_sans_le_drapeau_d_acceptation_dit_le_plan_sans_rien_ouvrir_en_ecriture() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-dry-run-seul");
        let base = _tmp.sous("wal-fermee.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, true);
        orpheline(&base, None);
        assert!(!existe(&format!("{base}-wal")) && !existe(&format!("{base}-shm")), "fixture : base WAL fermée proprement");
        let octets = std::fs::read(&base).unwrap();
        let date = date_du_repertoire(&base);
        std::thread::sleep(PAUSE_D_UN_TIC);
        let args = Arguments { sans_ecrire: true, accepter_les_ecritures_refusees: false, chemin: None };
        let r = reindexer(&base, &args, None);
        assert_eq!(r.code, CODE_NON_REPARE, "{}", r.ligne);
        assert_eq!(r.ligne["verdict"], "a_reindexer", "{}", r.ligne);
        assert_eq!(r.ligne["cause"], serde_json::Value::Null, "{}", r.ligne);
        assert_eq!(r.ligne["accepte_les_ecritures_refusees"], false, "{}", r.ligne);
        assert_eq!(r.ligne["plan"], serde_json::json!(INDEX_DES_EVENEMENTS), "{}", r.ligne);
        assert_eq!(std::fs::read(&base).unwrap(), octets, "rien n'est écrit");
        assert_eq!(date_du_repertoire(&base), date, "rien n'est ouvert en écriture : aucun compagnon créé puis retiré");
    }

    #[test]
    fn reindex_sans_le_drapeau_d_acceptation_refuse_avant_d_ecrire_et_dit_ce_qui_peut_se_perdre() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-drapeau");
        let base = _tmp.sous("drapeau.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        orpheline(&base, None);
        let octets = std::fs::read(&base).unwrap();
        let args = Arguments { sans_ecrire: false, accepter_les_ecritures_refusees: false, chemin: None };
        let r = reindexer(&base, &args, None);
        assert_eq!(r.code, CODE_REFUS, "{}", r.ligne);
        assert_eq!(r.ligne["cause"], PHRASE_ATTENDUE_DES_ECRITURES_REFUSEES, "{}", r.ligne);
        assert_eq!(r.ligne["accepte_les_ecritures_refusees"], false, "{}", r.ligne);
        assert_eq!(r.ligne["plan"], serde_json::json!(INDEX_DES_EVENEMENTS), "le plan est dit");
        assert_eq!(r.ligne["index"], serde_json::json!([]));
        assert_eq!(std::fs::read(&base).unwrap(), octets, "rien n'est écrit");
    }

    fn retirer_ri_ev_ts(phase: &str, chemin: &str) {
        if phase == PHASE_APRES_LE_VERDICT_D_AVANT {
            ouvrir(chemin, None).execute_batch("DROP INDEX ri_ev_ts;").expect("crochet : index retiré");
        }
    }

    #[test]
    fn reindex_un_index_retire_apres_le_verdict_est_relu_absent_et_refuse() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-relu");
        let base = _tmp.sous("relu.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        orpheline(&base, None);
        let _c = CrochetPose::poser(retirer_ri_ev_ts);
        let r = reindexer(&base, &accepter(), None);
        assert_eq!(r.code, CODE_REFUS, "{}", r.ligne);
        assert_eq!(r.ligne["ligne_refusee"], "ri_ev_ts", "le nom absent du schéma est nommé : {}", r.ligne);
        assert_eq!(r.ligne["index"], serde_json::json!([]));
        let restantes = lignes_du_controle(&base, None);
        assert!(restantes.iter().any(|l| l == "wrong # of entries in index ri_ev_sante"), "aucun autre index n'a été réindexé : {restantes:?}");
    }

    fn remplacer_ri_ev_ts_par_une_table(phase: &str, chemin: &str) {
        if phase == PHASE_APRES_LE_VERDICT_D_AVANT {
            ouvrir(chemin, None).execute_batch("DROP INDEX ri_ev_ts; CREATE TABLE ri_ev_ts(x INTEGER);").expect("crochet : table homonyme");
        }
    }

    /// Le nom désigne désormais une TABLE : la relecture exige `type = 'index'`. Sans elle, `REINDEX "main"."ri_ev_ts"`
    /// rebâtirait les index de cette table (aucun) et le geste sortirait en 0 sur un plan qu'il n'a pas exécuté.
    #[test]
    fn reindex_un_nom_d_index_devenu_celui_d_une_table_est_relu_absent_et_refuse() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-relu-table");
        let base = _tmp.sous("table.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        orpheline(&base, None);
        let _c = CrochetPose::poser(remplacer_ri_ev_ts_par_une_table);
        let r = reindexer(&base, &accepter(), None);
        assert_eq!(r.code, CODE_REFUS, "{}", r.ligne);
        assert_eq!(r.ligne["ligne_refusee"], "ri_ev_ts", "{}", r.ligne);
        assert_eq!(r.ligne["index"], serde_json::json!([]), "{}", r.ligne);
        let restantes = lignes_du_controle(&base, None);
        assert!(restantes.iter().any(|l| l == "wrong # of entries in index ri_ev_sante"), "rien n'est réindexé : {restantes:?}");
    }

    fn remplacer_ri_ev_ts_par_un_sosie(phase: &str, chemin: &str) {
        if phase == PHASE_APRES_LE_VERDICT_D_AVANT {
            ouvrir(chemin, None).execute_batch("DROP INDEX ri_ev_ts; CREATE INDEX riXev_ts ON ri_ev(ts);").expect("crochet : sosie");
        }
    }

    /// Un index SOSIE (`riXev_ts`, que `LIKE 'ri_ev_ts'` reconnaîtrait : `_` y vaut tout caractère) : la relecture
    /// compare par égalité exacte, le nom du plan est absent, refus.
    #[test]
    fn reindex_un_index_sosie_ne_passe_pas_la_relecture_par_egalite_exacte() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-relu-sosie");
        let base = _tmp.sous("sosie.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        orpheline(&base, None);
        let _c = CrochetPose::poser(remplacer_ri_ev_ts_par_un_sosie);
        let r = reindexer(&base, &accepter(), None);
        assert_eq!(r.code, CODE_REFUS, "{}", r.ligne);
        assert_eq!(r.ligne["ligne_refusee"], "ri_ev_ts", "{}", r.ligne);
        assert_eq!(r.ligne["index"], serde_json::json!([]), "{}", r.ligne);
    }

    fn abimer_l_en_tete(phase: &str, chemin: &str) {
        if phase == PHASE_APRES_LE_VERDICT_D_AVANT {
            let mut o = std::fs::read(chemin).unwrap();
            for b in &mut o[..16] {
                *b = 0x55;
            }
            std::fs::write(chemin, &o).unwrap();
        }
    }

    fn retirer_la_base_apres_le_verdict(phase: &str, chemin: &str) {
        if phase == PHASE_APRES_LE_VERDICT_D_AVANT {
            std::fs::remove_file(chemin).unwrap();
        }
    }

    #[test]
    fn reindex_relecture_du_schema_impossible_refuse_sans_ecrire() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-relecture");
        let base = _tmp.sous("entete.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        orpheline(&base, None);
        {
            let _c = CrochetPose::poser(abimer_l_en_tete);
            let r = reindexer(&base, &accepter(), None);
            assert_eq!(r.code, CODE_REFUS, "{}", r.ligne);
            assert!(r.ligne["cause"].as_str().unwrap_or("").starts_with("relecture du schéma refusée pour « ri_ev_f_user » ("), "{}", r.ligne);
            assert_eq!(r.ligne["index"], serde_json::json!([]));
        }
        let absente = _tmp.sous("absente.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&absente, None, false);
        orpheline(&absente, None);
        let _c = CrochetPose::poser(retirer_la_base_apres_le_verdict);
        let r = reindexer(&absente, &accepter(), None);
        assert_eq!(r.code, CODE_REFUS, "{}", r.ligne);
        assert!(r.ligne["cause"].as_str().unwrap_or("").starts_with("relecture du schéma impossible (base absente"), "{}", r.ligne);
        assert!(!existe(&absente), "rien n'est recréé");
    }

    fn retirer_la_base_avant_l_ecrivain(phase: &str, chemin: &str) {
        if phase == PHASE_AVANT_L_OUVERTURE_EN_ECRITURE {
            std::fs::remove_file(chemin).unwrap();
        }
    }

    #[test]
    fn reindex_l_ouverture_en_ecriture_ne_cree_pas_le_fichier() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-sans-creation");
        let base = _tmp.sous("disparue.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        orpheline(&base, None);
        let _c = CrochetPose::poser(retirer_la_base_avant_l_ecrivain);
        let r = reindexer(&base, &accepter(), None);
        assert_eq!(r.code, CODE_REFUS, "{}", r.ligne);
        assert!(r.ligne["cause"].as_str().unwrap_or("").starts_with("ouverture en écriture impossible ("), "{}", r.ligne);
        assert!(!existe(&base), "l'ouverture en écriture n'a PAS créé la base");
        assert!(!existe(&format!("{base}-journal")) && !existe(&format!("{base}-wal")), "ni un compagnon");
    }

    // ── 4. LES ÉCHECS PAR INDEX ─────────────────────────────────────────────────────────────────

    /// Une table, deux index ; l'index d'UNICITÉ est créé en dernier, donc parcouru le premier : c'est lui qui échoue,
    /// et le suivant doit être tenté et réindexé.
    #[test]
    fn reindex_unicite_violee_index_nomme_avec_cause_et_code_les_autres_reindexes_sortie_1() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-unicite");
        let base = _tmp.sous("unicite.db").chemin().to_string_lossy().into_owned();
        {
            let c = ouvrir(&base, None);
            c.execute_batch(
                "CREATE TABLE ri_un(id INTEGER PRIMARY KEY, ts INTEGER, k TEXT); CREATE INDEX ri_un_ts ON ri_un(ts); \
                 CREATE UNIQUE INDEX ri_un_k ON ri_un(k); INSERT INTO ri_un VALUES (1, 10, 'k1'), (2, 20, 'k2'), (3, 30, 'k3');",
            )
            .unwrap();
        }
        par_le_fantome(
            &base,
            None,
            "ri_un",
            "CREATE TABLE ri_fantome(id INTEGER PRIMARY KEY, ts INTEGER, k TEXT)",
            "INSERT INTO ri_fantome VALUES (50, 40, 'k1')",
        );
        let r = reindexer(&base, &accepter(), None);
        let l = &r.ligne;
        assert_eq!(l["plan"], serde_json::json!(["ri_un_k", "ri_un_ts"]), "fixture : l'index d'unicité vient en premier : {l}");
        assert_eq!(l["index"][0]["index"], "ri_un_k");
        assert_eq!(l["index"][0]["issue"], "echec", "{l}");
        assert_eq!(l["index"][0]["cause"], CAUSE_ATTENDUE_UNICITE, "{l}");
        assert_eq!(l["index"][0]["code"], 2067, "code étendu SQLITE_CONSTRAINT_UNIQUE : {l}");
        assert_eq!(l["index"][0]["detail"], "UNIQUE constraint failed: ri_un.k", "le texte du moteur, rendu à part : {l}");
        assert!(l["index"][0]["verrou_tenu_ms"].is_u64(), "le verrou a été pris puis rendu : {l}");
        assert_eq!(l["index"].as_array().map(Vec::len), Some(2), "le suivant est tenté : {l}");
        assert_eq!(l["index"][1]["index"], "ri_un_ts");
        assert_eq!(l["index"][1]["issue"], "reindexe", "{l}");
        assert_eq!(r.code, CODE_NON_REPARE, "{l}");
        assert_eq!(l["verdict"], "non_repare");
        assert_eq!(l["cause"], "1 index sur 2 non réindexé(s)", "{l}");
        let apres: Vec<String> = l["apres"]["lignes"].as_array().cloned().unwrap_or_default().iter().map(|x| x.as_str().unwrap_or("").to_string()).collect();
        assert!(!apres.is_empty() && apres.iter().all(|x| x.ends_with(" index ri_un_k")), "seul l'index d'unicité reste en défaut : {apres:?}");
    }

    /// Base en WAL : un écrivain d'un autre processus (ici une autre connexion) tient le verrou d'écriture pendant tout le
    /// geste. Chaque index échoue sur « base occupée », sans attendre plus que l'attente bornée, le verrou jamais pris.
    #[test]
    fn reindex_base_occupee_au_begin_un_echec_par_index_sans_blocage() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-occupee");
        let base = _tmp.sous("occupee.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, true);
        orpheline(&base, None);
        let tenant = ouvrir(&base, None);
        tenant.execute_batch("BEGIN IMMEDIATE; INSERT INTO ri_ev(id, ts, source, dedup) VALUES (500, 1, 's', 'd500');").unwrap();
        let r = reindexer_avec_attente(&base, &accepter(), None, ATTENTE_DU_TEMOIN);
        tenant.execute_batch("ROLLBACK;").unwrap();
        let l = &r.ligne;
        assert_eq!(l["index"].as_array().map(Vec::len), Some(INDEX_DES_EVENEMENTS.len()), "chaque index est tenté : {l}");
        for i in 0..INDEX_DES_EVENEMENTS.len() {
            assert_eq!(l["index"][i]["issue"], "echec", "{l}");
            assert_eq!(l["index"][i]["cause"], CAUSE_ATTENDUE_OCCUPEE, "{l}");
            assert_eq!(l["index"][i]["code"], 5, "SQLITE_BUSY : {l}");
            assert_eq!(l["index"][i]["verrou_tenu_ms"], serde_json::Value::Null, "le verrou n'a jamais été pris : {l}");
        }
        assert_eq!(r.code, CODE_NON_REPARE, "{l}");
        assert_eq!(l["cause"], "4 index sur 4 non réindexé(s)", "{l}");
        assert_eq!(l["attente_du_verrou_ms"], 100, "{l}");
    }

    /// Base en journal de retour arrière : un lecteur tient une transaction de lecture. Le `BEGIN IMMEDIATE` passe, le
    /// `REINDEX` aussi, mais le `COMMIT` demande le verrou exclusif : refusé après l'attente, la transaction est annulée
    /// et l'index nommé — le verrou a été tenu (durée rendue).
    #[test]
    fn reindex_commit_refuse_sous_un_lecteur_index_nomme_et_annule() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-commit");
        let base = _tmp.sous("commit.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        orpheline(&base, None);
        let lecteur = ouvrir(&base, None);
        lecteur.execute_batch("BEGIN;").unwrap();
        let _: i64 = lecteur.query_row("SELECT count(*) FROM ri_ev", [], |r| r.get(0)).unwrap();
        let r = reindexer_avec_attente(&base, &accepter(), None, ATTENTE_DU_TEMOIN);
        lecteur.execute_batch("COMMIT;").unwrap();
        let l = &r.ligne;
        assert_eq!(l["index"][0]["issue"], "echec", "{l}");
        assert_eq!(l["index"][0]["cause"], CAUSE_ATTENDUE_OCCUPEE, "{l}");
        assert_eq!(l["index"][0]["code"], 5, "{l}");
        assert!(l["index"][0]["verrou_tenu_ms"].is_u64(), "le verrou a été tenu jusqu'au COMMIT refusé : {l}");
        assert_eq!(r.code, CODE_NON_REPARE, "{l}");
        assert!(!existe(&format!("{base}-journal")), "la transaction est annulée, aucun journal chaud laissé");
        assert_eq!(lignes_du_controle(&base, None).len(), INDEX_DES_EVENEMENTS.len(), "rien n'est validé");
    }

    /// Le verrou est tenu par un autre écrivain qui le rend un peu plus tard : le geste ATTEND, dans sa borne, puis
    /// réindexe. Sans attente, chaque `BEGIN` serait refusé sur-le-champ.
    #[test]
    fn reindex_attend_le_verrou_dans_sa_borne_puis_reindexe() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-attente");
        let base = _tmp.sous("attente.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, true);
        orpheline(&base, None);
        let tenant = ouvrir(&base, None);
        tenant.execute_batch("BEGIN IMMEDIATE; INSERT INTO ri_ev(id, ts, source, dedup) VALUES (500, 1, 's', 'd500');").unwrap();
        let rendu = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            tenant.execute_batch("ROLLBACK;").unwrap();
        });
        let r = reindexer(&base, &accepter(), None);
        rendu.join().unwrap();
        assert_eq!(r.code, CODE_SAIN_OU_REPARE, "le verrou rendu dans la borne, chaque index est réindexé : {}", r.ligne);
    }

    /// L'ATTENTE DITE EST L'ATTENTE TENUE. Le verrou est tenu 2,5 s ; l'attente demandée est de 100 ms : le premier
    /// index échoue sur « base occupée ». Une connexion qui retomberait sur l'attente par défaut de la bibliothèque
    /// (5 s) attendrait le verrou rendu et réindexerait, alors que le JSON annonce 100 ms.
    #[test]
    fn reindex_l_ecrivain_tient_l_attente_annoncee_et_pas_celle_de_la_bibliotheque() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-attente-tenue");
        let base = _tmp.sous("attente-tenue.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, true);
        orpheline(&base, None);
        let tenant = ouvrir(&base, None);
        tenant.execute_batch("BEGIN IMMEDIATE; INSERT INTO ri_ev(id, ts, source, dedup) VALUES (500, 1, 's', 'd500');").unwrap();
        let rendu = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(2500));
            tenant.execute_batch("ROLLBACK;").unwrap();
        });
        let r = reindexer_avec_attente(&base, &accepter(), None, ATTENTE_DU_TEMOIN);
        rendu.join().unwrap();
        let l = &r.ligne;
        assert_eq!(l["attente_du_verrou_ms"], 100, "{l}");
        assert_eq!(l["index"][0]["issue"], "echec", "le premier index n'attend pas au-delà de 100 ms : {l}");
        assert_eq!(l["index"][0]["cause"], CAUSE_ATTENDUE_OCCUPEE, "{l}");
        assert_eq!(l["index"][0]["code"], 5, "{l}");
        assert_eq!(r.code, CODE_NON_REPARE, "{l}");
    }

    fn retirer_ri_ev_ts_avant_l_ecrivain(phase: &str, chemin: &str) {
        if phase == PHASE_AVANT_L_OUVERTURE_EN_ECRITURE {
            ouvrir(chemin, None).execute_batch("DROP INDEX ri_ev_ts;").expect("crochet : index retiré");
        }
    }

    /// Un index disparu entre la relecture et l'écriture : le moteur refuse le `REINDEX` (« unable to identify »),
    /// l'index est nommé avec la cause générique et le code, les autres sont réindexés.
    #[test]
    fn reindex_un_index_disparu_avant_l_ecriture_echoue_seul_avec_le_code_du_moteur() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-disparu");
        let base = _tmp.sous("disparu.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        orpheline(&base, None);
        let _c = CrochetPose::poser(retirer_ri_ev_ts_avant_l_ecrivain);
        let r = reindexer(&base, &accepter(), None);
        let l = &r.ligne;
        assert_eq!(l["index"][2]["index"], "ri_ev_ts", "{l}");
        assert_eq!(l["index"][2]["issue"], "echec", "{l}");
        assert_eq!(l["index"][2]["cause"], CAUSE_ATTENDUE_MOTEUR, "{l}");
        assert_eq!(l["index"][2]["code"], 1, "SQLITE_ERROR : {l}");
        for i in [0usize, 1, 3] {
            assert_eq!(l["index"][i]["issue"], "reindexe", "{l}");
        }
        assert_eq!(r.code, CODE_NON_REPARE, "{l}");
    }

    fn essayer_le_verrou(phase: &str, chemin: &str) {
        if phase == PHASE_APRES_UN_INDEX {
            let c = ouvrir(chemin, None);
            c.busy_timeout(std::time::Duration::from_millis(0)).unwrap();
            let pris = c.execute_batch("BEGIN IMMEDIATE; ROLLBACK;").is_ok();
            VERROUS_PRIS_ENTRE_DEUX_INDEX.with(|v| {
                let (essais, prises) = v.get();
                v.set((essais + 1, prises + u32::from(pris)));
            });
        }
    }

    #[test]
    fn reindex_le_verrou_d_ecriture_est_rendu_apres_chaque_index() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-verrou-rendu");
        let base = _tmp.sous("rendu.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, true);
        orpheline(&base, None);
        VERROUS_PRIS_ENTRE_DEUX_INDEX.with(|v| v.set((0, 0)));
        let _c = CrochetPose::poser(essayer_le_verrou);
        let r = reindexer(&base, &accepter(), None);
        assert_eq!(r.code, CODE_SAIN_OU_REPARE, "{}", r.ligne);
        let (essais, prises) = VERROUS_PRIS_ENTRE_DEUX_INDEX.with(|v| v.get());
        assert_eq!(essais as usize, INDEX_DES_EVENEMENTS.len(), "le crochet joue après chaque index");
        assert_eq!(prises, essais, "après chaque index, un autre écrivain prend le verrou sans attendre");
    }

    fn defaut_neuf_apres_le_dernier(phase: &str, chemin: &str) {
        if phase == PHASE_APRES_UN_INDEX {
            let n = FANTOME_APRES_LE_DERNIER.with(|c| {
                c.set(c.get() + 1);
                c.get()
            });
            if n as usize == INDEX_DES_EVENEMENTS.len() {
                par_le_fantome(chemin, None, "ri_ev", FANTOME_DES_EVENEMENTS, "DELETE FROM ri_fantome WHERE id = 12");
            }
        }
    }

    /// Chaque index est réindexé, mais un défaut neuf apparaît avant le contrôle d'après : la sortie n'est pas 0.
    #[test]
    fn reindex_sortie_0_seulement_si_le_controle_d_apres_est_sain() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-apres");
        let base = _tmp.sous("apres.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        orpheline(&base, None);
        FANTOME_APRES_LE_DERNIER.with(|c| c.set(0));
        let _c = CrochetPose::poser(defaut_neuf_apres_le_dernier);
        let r = reindexer(&base, &accepter(), None);
        let l = &r.ligne;
        assert!(l["index"].as_array().cloned().unwrap_or_default().iter().all(|i| i["issue"] == "reindexe"), "{l}");
        assert_eq!(l["apres"]["verdict"], "corrompu", "{l}");
        assert_eq!(r.code, CODE_NON_REPARE, "{l}");
        assert_eq!(l["cause"], "chaque index du plan est réindexé, mais le contrôle d'après ne rend pas « sain »", "{l}");
    }

    /// La cause du refus d'`integrity_check` sur un `-journal` non vide, écrite ici à la main.
    const CAUSE_ATTENDUE_JOURNAL_CHAUD: &str = "-journal non vide (journal chaud) : une ouverture en lecture seule ne le \
         rejoue pas, une ouverture immuable l'ignorerait — aucun verdict sur un état qui n'est pas celui de la base";

    /// Après le DERNIER index seulement (une transaction suivante en mode `DELETE` créerait puis retirerait son propre
    /// journal) : un `-journal` de 512 octets nuls, que le contrôle d'après refuse au `stat`, avant toute ouverture.
    fn journal_non_vide_apres_le_dernier(phase: &str, chemin: &str) {
        if phase == PHASE_APRES_UN_INDEX {
            let n = JOURNAL_APRES_LE_DERNIER.with(|c| {
                c.set(c.get() + 1);
                c.get()
            });
            if n as usize == INDEX_DES_EVENEMENTS.len() {
                std::fs::write(format!("{chemin}-journal"), [0u8; 512]).expect("fixture : -journal posé");
            }
        }
    }

    /// Chaque index est réindexé, mais le contrôle d'après REFUSE de conclure (`-journal` non vide) : un refus n'est
    /// pas « sain », la sortie est 1 et `apres` porte le refus. La base elle-même est saine (relue sans le journal) :
    /// seul le refus d'après sépare cette issue d'une réparation.
    #[test]
    fn reindex_un_controle_d_apres_qui_refuse_de_conclure_ne_sort_pas_0() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-apres-refus");
        let base = _tmp.sous("apres-refus.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        orpheline(&base, None);
        JOURNAL_APRES_LE_DERNIER.with(|c| c.set(0));
        let r = {
            let _c = CrochetPose::poser(journal_non_vide_apres_le_dernier);
            reindexer(&base, &accepter(), None)
        };
        let l = &r.ligne;
        assert_eq!(JOURNAL_APRES_LE_DERNIER.with(|c| c.get()) as usize, INDEX_DES_EVENEMENTS.len(), "le crochet joue après chaque index");
        let index = l["index"].as_array().cloned().unwrap_or_default();
        assert_eq!(index.len(), INDEX_DES_EVENEMENTS.len(), "{l}");
        for (issue, nom) in index.iter().zip(INDEX_DES_EVENEMENTS) {
            assert_eq!(issue["index"], nom, "{l}");
            assert_eq!(issue["issue"], "reindexe", "{l}");
        }
        assert_eq!(l["apres"]["verdict"], "refus", "{l}");
        assert_eq!(l["apres"]["cause"], CAUSE_ATTENDUE_JOURNAL_CHAUD, "{l}");
        assert_eq!(l["verdict"], "non_repare", "{l}");
        assert_eq!(l["cause"], "chaque index du plan est réindexé, mais le contrôle d'après ne rend pas « sain »", "{l}");
        assert_eq!(l["code"], CODE_NON_REPARE, "{l}");
        assert_eq!(r.code, CODE_NON_REPARE, "{l}");
        std::fs::remove_file(format!("{base}-journal")).expect("fixture : -journal retiré");
        let v = verifier(&base, Mode::Complet, None);
        assert_eq!(v.rapport["verdict"], "sain", "sans le journal, la base réindexée est saine : {}", v.rapport);
    }

    // ── 5. SAINE, CHIFFRÉE, INTERROMPUE ─────────────────────────────────────────────────────────

    #[test]
    fn reindex_base_saine_sort_0_sans_rien_ouvrir_en_ecriture() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-saine");
        let base = _tmp.sous("saine.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, true);
        assert!(!existe(&format!("{base}-wal")) && !existe(&format!("{base}-shm")), "fixture : base WAL fermée proprement");
        let octets = std::fs::read(&base).unwrap();
        let date = date_du_repertoire(&base);
        std::thread::sleep(PAUSE_D_UN_TIC);
        let r = reindexer(&base, &accepter(), None);
        assert_eq!(r.code, CODE_SAIN_OU_REPARE, "{}", r.ligne);
        assert_eq!(r.ligne["verdict"], "sain");
        assert_eq!(r.ligne["plan"], serde_json::json!([]));
        assert_eq!(r.ligne["index"], serde_json::json!([]));
        assert_eq!(r.ligne["apres"], serde_json::Value::Null);
        assert_eq!(std::fs::read(&base).unwrap(), octets, "rien n'est écrit");
        assert_eq!(date_du_repertoire(&base), date, "rien n'est ouvert en écriture : aucun compagnon créé puis retiré");
    }

    #[test]
    fn reindex_base_chiffree_reparee_sous_la_cle_et_refusee_sans_elle() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-chiffree");
        let base = _tmp.sous("chiffree.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, Some(CLE_DU_TEMOIN), false);
        orpheline(&base, Some(CLE_DU_TEMOIN));
        assert_ne!(&std::fs::read(&base).unwrap()[..16], b"SQLite format 3\0", "fixture : la base est chiffrée");
        let octets = std::fs::read(&base).unwrap();
        let r = reindexer(&base, &accepter(), None);
        assert_eq!(r.code, CODE_REFUS, "sans clé : aucun verdict, rien d'écrit : {}", r.ligne);
        assert_eq!(std::fs::read(&base).unwrap(), octets);
        let r = reindexer(&base, &accepter(), Some(CLE_DU_TEMOIN));
        assert_eq!(r.ligne["cle_appliquee"], true);
        assert_eq!(r.code, CODE_SAIN_OU_REPARE, "{}", r.ligne);
        assert_eq!(r.ligne["apres"]["cipher_integrity_check"], serde_json::json!([]), "le HMAC des pages réécrites est contrôlé : {}", r.ligne);
    }

    /// Base chiffrée : une entrée orpheline ET une page libre dont le HMAC est abîmé. Les lignes de structure sont toutes
    /// réparables, `cipher_integrity_check` ne l'est pas : refus.
    #[test]
    fn reindex_cipher_integrity_check_en_defaut_refuse_meme_si_les_lignes_sont_reparables() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-hmac");
        let base = _tmp.sous("hmac.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, Some(CLE_DU_TEMOIN), false);
        orpheline(&base, Some(CLE_DU_TEMOIN));
        let ps = {
            let c = ouvrir(&base, Some(CLE_DU_TEMOIN));
            c.execute_batch(
                "CREATE TABLE ri_libre(x BLOB); WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<40) \
                 INSERT INTO ri_libre SELECT randomblob(1000) FROM n; DELETE FROM ri_libre;",
            )
            .unwrap();
            let fl: i64 = c.query_row("PRAGMA freelist_count", [], |r| r.get(0)).unwrap();
            assert!(fl >= 5, "fixture : des pages libres ({fl})");
            c.query_row("PRAGMA page_size", [], |r| r.get::<_, i64>(0)).unwrap() as usize
        };
        let mut octets = std::fs::read(&base).unwrap();
        let n = octets.len();
        for o in &mut octets[n - ps + 100..n - ps + 200] {
            *o ^= 0xFF;
        }
        std::fs::write(&base, &octets).unwrap();
        let v = verifier(&base, Mode::Complet, Some(CLE_DU_TEMOIN));
        let lignes: Vec<String> = v.rapport["lignes"].as_array().cloned().unwrap_or_default().iter().map(|x| x.as_str().unwrap_or("").to_string()).collect();
        assert!(!lignes.is_empty() && lignes.iter().all(|x| index_desaccorde(x).is_some()), "fixture : structure réparable : {}", v.rapport);
        let premiere_page = v.rapport["cipher_integrity_check"][0].as_str().unwrap_or("").to_string();
        assert!(!premiere_page.is_empty(), "fixture : le HMAC est en défaut : {}", v.rapport);
        let r = reindexer(&base, &accepter(), Some(CLE_DU_TEMOIN));
        assert_eq!(r.code, CODE_REFUS, "{}", r.ligne);
        assert_eq!(r.ligne["ligne_refusee"], serde_json::json!(premiere_page), "{}", r.ligne);
        assert_eq!(std::fs::read(&base).unwrap(), octets, "rien n'est écrit");
    }

    #[test]
    fn reindex_controle_interrompu_ou_sans_verdict_refuse_sans_ecrire() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-interrompu");
        // L'arbre de `sqlite_master` abîmé, l'en-tête intact : SQLITE_CORRUPT dès la lecture du schéma, aucune ligne.
        let base = _tmp.sous("schema.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        let mut octets = std::fs::read(&base).unwrap();
        for o in &mut octets[100..4096] {
            *o = 0xFF;
        }
        std::fs::write(&base, &octets).unwrap();
        let r = reindexer(&base, &accepter(), None);
        assert_eq!(r.ligne["avant"]["verdict"], "corrompu", "fixture : {}", r.ligne);
        assert_eq!(r.code, CODE_REFUS, "{}", r.ligne);
        assert!(r.ligne["cause"].as_str().unwrap_or("").starts_with("le contrôle n'a pas rendu toutes ses lignes ("), "{}", r.ligne);
        assert_eq!(std::fs::read(&base).unwrap(), octets, "rien n'est écrit");

        // Journal chaud : le contrôle refuse de conclure, la réindexation reprend son refus.
        let chaud = _tmp.sous("chaud.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&chaud, None, false);
        orpheline(&chaud, None);
        std::fs::write(format!("{chaud}-journal"), [0u8; 512]).unwrap();
        let octets = std::fs::read(&chaud).unwrap();
        let r = reindexer(&chaud, &accepter(), None);
        assert_eq!(r.code, CODE_REFUS, "{}", r.ligne);
        assert!(r.ligne["cause"].as_str().unwrap_or("").starts_with("le contrôle d'avant n'a pas conclu (-journal non vide"), "{}", r.ligne);
        assert_eq!(std::fs::read(&chaud).unwrap(), octets, "rien n'est écrit");

        // Un seul compagnon : refus, l'autre n'est pas créé.
        let seul = _tmp.sous("seul.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&seul, None, true);
        orpheline(&seul, None);
        std::fs::write(format!("{seul}-wal"), b"").unwrap();
        let r = reindexer(&seul, &accepter(), None);
        assert_eq!(r.code, CODE_REFUS, "{}", r.ligne);
        assert!(!existe(&format!("{seul}-shm")), "le -shm manquant n'est pas créé");
    }

    /// Base en WAL fermée proprement : l'écrivain crée `-wal` et `-shm` dès sa première lecture, et la dernière
    /// connexion les retire à la fermeture. Après une réparation complète, aucun compagnon ne reste.
    #[test]
    fn reindex_sur_une_base_wal_fermee_l_ecrivain_cree_puis_retire_les_compagnons() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-compagnons");
        let base = _tmp.sous("wal.db").chemin().to_string_lossy().into_owned();
        base_d_evenements(&base, None, true);
        let (wal, shm) = (format!("{base}-wal"), format!("{base}-shm"));
        assert!(!existe(&wal) && !existe(&shm), "fixture : fermée proprement");
        {
            let w = ouvrir_l_ecrivain(&base, None, ATTENTE_DU_TEMOIN).expect("écrivain");
            let _: i64 = w.query_row("SELECT count(*) FROM ri_ev", [], |r| r.get(0)).unwrap();
            assert!(existe(&wal) && existe(&shm), "l'écrivain CRÉE -wal et -shm sur une base WAL fermée");
        }
        assert!(!existe(&wal) && !existe(&shm), "la dernière connexion les retire à la fermeture");
        orpheline(&base, None);
        let r = reindexer(&base, &accepter(), None);
        assert_eq!(r.code, CODE_SAIN_OU_REPARE, "{}", r.ligne);
        assert!(!existe(&wal) && !existe(&shm), "après la réparation, aucun compagnon ne reste");
    }

    /// CE DONT UN INDEX DU SCHÉMA A BESOIN : chaque index d'une base au schéma COMPLET (celui que prépare la porte),
    /// plus un index de champ chaud de la forme que pose `maintenance`, est rebâti par la connexion de l'écrivain, qui
    /// n'enregistre aucune fonction ni collation du démon.
    #[test]
    fn reindex_chaque_index_d_un_schema_complet_se_rebatit_par_l_ecrivain() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-schema");
        let base = _tmp.sous("plume.db").chemin().to_string_lossy().into_owned();
        {
            let c = rusqlite::Connection::open(&base).unwrap();
            crate::prepare_schema(&c).expect("fixture : schéma complet");
            c.execute_batch(
                "CREATE INDEX IF NOT EXISTS idx_ev_f_user ON event(json_extract(fields,'$.user')) WHERE json_extract(fields,'$.user') IS NOT NULL; \
                 INSERT INTO event(ts, source, category, message, fields, dedup) VALUES (1, 'sshd', 'health', 'm', '{\"user\":\"alice\"}', 'x1'); \
                 INSERT INTO event(ts, source, category, message, fields, dedup) VALUES (2, 'sshd', 'auth', 'm', '{}', 'x2');",
            )
            .unwrap();
        }
        let (noms, partiels, expressions) = {
            let c = rusqlite::Connection::open(&base).unwrap();
            let mut st = c.prepare("SELECT name, COALESCE(sql, '') FROM sqlite_master WHERE type = 'index' ORDER BY name").unwrap();
            let lus: Vec<(String, String)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(|x| x.unwrap()).collect();
            let partiels = lus.iter().filter(|(_, s)| s.to_ascii_uppercase().contains(" WHERE ")).count();
            let expressions = lus.iter().filter(|(_, s)| s.contains("json_extract(")).count();
            (lus.into_iter().map(|(n, _)| n).collect::<Vec<_>>(), partiels, expressions)
        };
        assert!(noms.len() >= 30, "le schéma complet porte ses index ({})", noms.len());
        assert!(partiels >= 2 && expressions >= 1, "des index partiels ({partiels}) et d'expression ({expressions})");
        assert!(noms.iter().any(|n| n.starts_with("sqlite_autoindex_event_")), "l'index automatique de l'unicité de `event`");
        let w = ouvrir_l_ecrivain(&base, None, ATTENTE_DU_TEMOIN).expect("écrivain");
        for nom in &noms {
            let issue = reindexer_un_index(&w, nom);
            assert_eq!(issue["issue"], "reindexe", "{nom} : {issue}");
        }
    }

    // ── 6. LES ARGUMENTS, ET `main` EN SOUS-PROCESSUS ──────────────────────────────────────────

    #[test]
    fn reindex_les_arguments_dans_tout_ordre_et_le_refus_de_l_inconnu() {
        let a = |v: &[&str]| analyser_les_arguments(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(a(&["d", "reindex"]).unwrap(), Arguments { sans_ecrire: false, accepter_les_ecritures_refusees: false, chemin: None });
        let tout = Arguments { sans_ecrire: true, accepter_les_ecritures_refusees: true, chemin: Some("/b.db".into()) };
        assert_eq!(a(&["d", "reindex", "--dry-run", "--accepter-les-ecritures-refusees", "/b.db"]).unwrap(), tout);
        assert_eq!(a(&["d", "reindex", "/b.db", "--accepter-les-ecritures-refusees", "--dry-run"]).unwrap(), tout);
        for inconnu in [&["--dry_run"][..], &["-dry-run", "/b.db"], &["/b.db", "--exact"], &["--help"]] {
            let mut v = vec!["d", "reindex"];
            v.extend_from_slice(inconnu);
            let e = a(&v).expect_err("drapeau inconnu refusé");
            assert!(e.starts_with("reindex : drapeau inconnu « "), "{e}");
        }
        let e = a(&["d", "reindex", "/a.db", "/b.db"]).expect_err("second chemin refusé");
        assert!(e.starts_with("reindex : un seul chemin attendu, « /b.db » en trop"), "{e}");
    }

    fn argv_de_l_enfant(suite: &[&str]) -> String {
        let mut v = vec!["plume-daemon", "reindex"];
        v.extend_from_slice(suite);
        serde_json::to_string(&v).expect("tableau JSON")
    }

    fn rapport_de(sortie: &std::process::Output) -> serde_json::Value {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stderr.contains(RI_MARQUE_ENFANT), "contrôle : l'enfant a atteint `main` : {stdout}\n{stderr}");
        let ligne = stdout
            .lines()
            .find_map(|l| l.find("{\"").map(|i| &l[i..]))
            .unwrap_or_else(|| panic!("aucune ligne JSON sur stdout : {stdout}\n{stderr}"));
        serde_json::from_str(ligne).unwrap_or_else(|e| panic!("JSON illisible ({e}) : {ligne}"))
    }

    /// Le VRAI binaire : base chiffrée sous la clé du démon (`PLUME_DB_KEY`), chemin explicite, la base de la
    /// configuration ailleurs. Sortie 0, une ligne JSON, la clé appliquée par `main`.
    #[test]
    fn reindex_main_repare_sous_la_cle_du_demon_et_sort_0() {
        if std::env::var_os(RI_ENFANT).is_some() {
            eprintln!("{RI_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-main");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("chiffree.db").to_string_lossy().into_owned();
        let autre = dir.join("configuree.db").to_string_lossy().into_owned();
        base_d_evenements(&base, Some(CLE_DU_TEMOIN), false);
        orpheline(&base, Some(CLE_DU_TEMOIN));
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "reindex",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::reindexation_bornee::reindex_main_repare_sous_la_cle_du_demon_et_sort_0",
            ])
            .env(RI_ENFANT, "1")
            .env(RI_ARGUMENTS, argv_de_l_enfant(&["--accepter-les-ecritures-refusees", base.as_str()]))
            .env("PLUME_DB", &autre)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .env(crate::crypto::CLE_DB_KEY, CLE_DU_TEMOIN)
            .env_remove(crate::crypto::CLE_DB_KEY_FILE)
            .env_remove(crate::crypto::CLE_DB_KEY_AUTO_PATH)
            .output()
            .expect("ré-exécution du binaire de test");
        let r = rapport_de(&sortie);
        assert_eq!(sortie.status.code(), Some(CODE_SAIN_OU_REPARE), "{r}");
        assert_eq!(r["verdict"], "repare", "{r}");
        assert_eq!(r["cle_appliquee"], true, "main transmet la clé du démon : {r}");
        assert_eq!(r["base"], serde_json::json!(base), "le chemin donné est celui réparé");
        assert!(!existe(&autre), "la base de la configuration n'est pas créée");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        assert_eq!(stdout.lines().filter(|l| l.contains("{\"")).count(), 1, "une seule ligne JSON : {stdout}");
    }

    /// Le VRAI binaire : sans le drapeau d'acceptation, sortie 2 et la ligne JSON dit pourquoi ; un drapeau inconnu
    /// sort en 2 SANS ligne JSON. Dans les deux cas la base reste à l'octet.
    #[test]
    fn reindex_main_refuse_sans_acceptation_et_sur_un_drapeau_inconnu_sans_rien_ecrire() {
        if std::env::var_os(RI_ENFANT).is_some() {
            eprintln!("{RI_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-main-refus");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("plume.db").to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        orpheline(&base, None);
        let octets = std::fs::read(&base).unwrap();
        let sans_acceptation = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "reindex",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::reindexation_bornee::reindex_main_refuse_sans_acceptation_et_sur_un_drapeau_inconnu_sans_rien_ecrire",
            ])
            .env(RI_ENFANT, "1")
            .env(RI_ARGUMENTS, argv_de_l_enfant(&[]))
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .env_remove(crate::crypto::CLE_DB_KEY)
            .env_remove(crate::crypto::CLE_DB_KEY_FILE)
            .env_remove(crate::crypto::CLE_DB_KEY_AUTO_PATH)
            .output()
            .expect("ré-exécution du binaire de test");
        let r = rapport_de(&sans_acceptation);
        assert_eq!(sans_acceptation.status.code(), Some(CODE_REFUS), "{r}");
        assert_eq!(r["cause"], PHRASE_ATTENDUE_DES_ECRITURES_REFUSEES, "{r}");
        assert_eq!(r["base"], serde_json::json!(base), "la base de la configuration est celle jugée");
        assert_eq!(std::fs::read(&base).unwrap(), octets, "rien n'est écrit");

        let inconnu = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "reindex",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::reindexation_bornee::reindex_main_refuse_sans_acceptation_et_sur_un_drapeau_inconnu_sans_rien_ecrire",
            ])
            .env(RI_ENFANT, "1")
            .env(RI_ARGUMENTS, argv_de_l_enfant(&["--accepter-les-ecritures-refusees", "--dry_run"]))
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .env_remove(crate::crypto::CLE_DB_KEY)
            .env_remove(crate::crypto::CLE_DB_KEY_FILE)
            .env_remove(crate::crypto::CLE_DB_KEY_AUTO_PATH)
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&inconnu.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&inconnu.stderr).into_owned();
        assert!(stderr.contains(RI_MARQUE_ENFANT), "l'enfant a atteint `main` : {stderr}");
        assert_eq!(inconnu.status.code(), Some(CODE_REFUS), "{stdout}\n{stderr}");
        assert!(!stdout.contains("{\""), "aucune ligne JSON : {stdout}");
        assert!(stderr.contains("reindex : drapeau inconnu « --dry_run »"), "{stderr}");
        assert_eq!(std::fs::read(&base).unwrap(), octets, "un drapeau mal écrit ne fait rien écrire");
    }

    /// `PLUME_DB_KEY_FILE` posé mais absent : `main` sort en 78 avant tout examen, sans ligne JSON, la base à l'octet ;
    /// et l'aide de `reindex` le dit, comme celle d'`integrity-check`.
    #[test]
    fn reindex_main_sort_en_78_sur_un_fichier_de_cle_illisible_et_l_aide_le_dit() {
        if std::env::var_os(RI_ENFANT).is_some() {
            eprintln!("{RI_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let aide = crate::SUBCOMMANDS.iter().find(|(nom, _)| *nom == "reindex").map(|(_, a)| *a).expect("reindex a son aide");
        assert!(aide.contains("78 = PLUME_DB_KEY_FILE posé mais illisible"), "l'aide de reindex cite la sortie 78 : {aide}");

        let _tmp = crate::tmp_possede::TmpPossede::neuf("reindex-main-78");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("plume.db").to_string_lossy().into_owned();
        base_d_evenements(&base, None, false);
        orpheline(&base, None);
        let octets = std::fs::read(&base).unwrap();
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "reindex",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::reindexation_bornee::reindex_main_sort_en_78_sur_un_fichier_de_cle_illisible_et_l_aide_le_dit",
            ])
            .env(RI_ENFANT, "1")
            .env(RI_ARGUMENTS, argv_de_l_enfant(&["--accepter-les-ecritures-refusees", base.as_str()]))
            .env("PLUME_DB", &base)
            .env("PLUME_CONFIG", dir.join("aucune.conf"))
            .env_remove(crate::crypto::CLE_DB_KEY)
            .env(crate::crypto::CLE_DB_KEY_FILE, dir.join("cle-absente"))
            .env_remove(crate::crypto::CLE_DB_KEY_AUTO_PATH)
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stderr.contains(RI_MARQUE_ENFANT), "l'enfant a atteint `main` : {stderr}");
        assert_eq!(sortie.status.code(), Some(78), "{stdout}\n{stderr}");
        assert!(!stdout.contains("{\""), "aucune ligne JSON : {stdout}");
        assert_eq!(std::fs::read(&base).unwrap(), octets, "rien n'est écrit");
    }
}

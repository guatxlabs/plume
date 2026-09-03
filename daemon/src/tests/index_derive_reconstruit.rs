// `P8.10-m` — CE QUI SÉPARE UNE RÉPARATION D'UNE PERTE DE DONNÉES.
//
// MESURÉ EN PRODUCTION le 2026-09-03 : trois heures d'arrêt TOTAL parce que la construction d'un
// index plein-texte rendait SQLITE_CORRUPT. Le refus était honnête — l'index était réellement abîmé —
// mais son prix ne l'était pas : cet index est déclaré à CONTENU EXTERNE, il ne porte aucune donnée
// propre, sa source était intacte à côté, et il s'est reconstruit en moins de trois minutes.
//
// CE QUE CES TÉMOINS TIENNENT, ET DANS LES DEUX SENS :
//   - un index DÉRIVÉ abîmé est reconstruit, et la porte sert ENSUITE (jamais l'inverse) ;
//   - un objet SOURCE manquant refuse TOUJOURS, et son message part MOT POUR MOT — le correctif ne
//     doit pas reformuler une accusation qu'il ne traite pas ;
//   - une table plein-texte SANS CONTENU n'est JAMAIS reconstruite : là, l'index EST la donnée, et la
//     rebâtir la détruirait. C'est le cas dangereux, et c'est le seul prédicat qui l'écarte ;
//   - la trace est un COMPTE, pas un booléen : une corruption qui revient fait monter un nombre que
//     rien ne purge, sinon le remède deviendrait le prochain silence.

/// Une base plume NEUVE, préparée par la porte, dans un répertoire possédé.
fn base_neuve_pour(nom: &str) -> (crate::tmp_possede::TmpPossede, String) {
    let tmp = crate::tmp_possede::TmpPossede::neuf(nom);
    let chemin = tmp.sous("plume.db").chemin().to_path_buf();
    let _ = std::fs::remove_file(&chemin);
    let p = chemin.to_str().unwrap().to_string();
    drop(crate::db_open::PreparedDb::open(&p).expect("base neuve : la porte la prépare"));
    (tmp, p)
}

/// ABÎME l'index plein-texte EXACTEMENT comme la production l'a été : la déclaration reste, une table
/// d'ombre disparaît, et le constructeur de la table virtuelle échoue. La fabrication est VÉRIFIÉE ici
/// même — un témoin qui croirait avoir abîmé quelque chose sans l'avoir fait serait vert pour rien.
fn abimer_lindex_plein_texte(p: &str) {
    {
        let c = crate::db_open::open_db(p).unwrap();
        c.execute_batch("DROP TABLE event_fts_config;").expect("table d'ombre retirée");
    }
    let c = crate::db_open::open_db(p).unwrap();
    let echec = c
        .prepare("SELECT count(*) FROM pragma_table_xinfo('event_fts')")
        .and_then(|mut st| st.query_row([], |r| r.get::<_, i64>(0)))
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        echec.contains("vtable constructor failed"),
        "la FABRICATION du témoin doit vraiment abîmer l'index (obtenu : {echec:?})"
    );
}

/// Le compte de reconstructions inscrit dans la base — `None` si aucune n'a jamais eu lieu.
fn compte_de_reconstructions(p: &str, table: &str) -> Option<String> {
    let c = crate::db_open::open_db(p).unwrap();
    c.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        [format!("index_derive_reconstruit_{table}")],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

#[test]
fn un_index_derive_abime_est_reconstruit_et_la_porte_sert_ensuite() {
    let (_tmp, p) = base_neuve_pour("index-derive-reconstruit");

    // Des lignes DANS LA SOURCE : c'est d'elles que l'index doit renaître, et sans elles le témoin
    // serait vert sur une reconstruction qui n'a rien reconstruit.
    {
        let c = crate::db_open::open_db(&p).unwrap();
        for i in 0..40 {
            c.execute(
                "INSERT INTO event(ts,host,source,category,severity,message) \
                 VALUES(?1,'h','t','c',1,?2)",
                rusqlite::params![1_700_000_000i64 + i, format!("phrase repere numero {i}")],
            )
            .unwrap();
        }
    }
    assert_eq!(compte_de_reconstructions(&p, "event_fts"), None, "rien n'a encore été réparé");

    abimer_lindex_plein_texte(&p);

    // LA PORTE : elle reconstruit, puis elle REJUGE, et c'est ce second verdict qui la fait servir.
    let prete = crate::db_open::PreparedDb::open(&p).expect("index dérivé abîmé : la porte le rebâtit");

    // L'index est VIVANT et il rend les lignes de la SOURCE — pas un index vide qui se construirait.
    let trouvees: i64 = prete
        .query_row("SELECT count(*) FROM event_fts WHERE event_fts MATCH 'repere'", [], |r| r.get(0))
        .expect("recherche plein-texte servie");
    assert_eq!(trouvees, 40, "l'index rebâti rend TOUTE la source");

    assert_eq!(
        compte_de_reconstructions(&p, "event_fts").as_deref(),
        Some("1"),
        "la première reconstruction est comptée"
    );
}

#[test]
fn le_compte_de_reconstructions_monte_et_rien_ne_le_purge() {
    let (_tmp, p) = base_neuve_pour("index-derive-compte");
    for attendu in ["1", "2", "3"] {
        abimer_lindex_plein_texte(&p);
        drop(crate::db_open::PreparedDb::open(&p).expect("rebâti"));
        assert_eq!(
            compte_de_reconstructions(&p, "event_fts").as_deref(),
            Some(attendu),
            "une corruption qui REVIENT ne peut pas se cacher derrière une réparation devenue routine"
        );
    }
}

#[test]
fn une_base_saine_ne_declenche_aucune_reconstruction() {
    let (_tmp, p) = base_neuve_pour("index-derive-base-saine");
    for _ in 0..3 {
        drop(crate::db_open::PreparedDb::open(&p).expect("base saine"));
    }
    assert_eq!(
        compte_de_reconstructions(&p, "event_fts"),
        None,
        "le chemin de réparation ne court que sur un refus, jamais en marche normale"
    );
}

#[test]
fn un_objet_source_manquant_refuse_toujours_et_le_message_part_mot_pour_mot() {
    let (_tmp, p) = base_neuve_pour("index-derive-objet-source");
    {
        let c = crate::db_open::open_db(&p).unwrap();
        c.execute("DROP TABLE net_ban", []).unwrap();
    }
    match crate::db_open::PreparedDb::open(&p) {
        Err(crate::db_open::DbOpenError::Contrat(e)) => {
            assert!(e.contains("table net_ban"), "le manque est NOMMÉ : {e}");
            // LE POINT DU TÉMOIN : le correctif ne doit RIEN ajouter à un refus qu'il ne traite pas.
            assert!(
                !e.contains("reconstruction"),
                "un refus non réparable part INTACT, sans un mot de plus : {e}"
            );
        }
        autre => panic!(
            "attendu : refus du contrat (obtenu : {})",
            autre.err().map(|e| e.to_string()).unwrap_or_else(|| "Ok".into())
        ),
    }
    // Et la porte n'a RIEN recréé en silence.
    let c = crate::db_open::open_db(&p).unwrap();
    let n: i64 = c
        .query_row("SELECT count(*) FROM sqlite_master WHERE name='net_ban'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0, "la porte CONSTATE un objet source manquant, elle ne le fabrique pas");
}

#[test]
fn seul_un_contenu_externe_non_vide_est_declare_derivable() {
    // LE CAS DANGEREUX EN PREMIER : une table FTS5 SANS CONTENU porte la donnée elle-même.
    // La reconstruire la DÉTRUIRAIT — ce prédicat est tout ce qui l'en empêche.
    let dangereux = [
        "CREATE VIRTUAL TABLE t USING fts5(a, content='')",
        "CREATE VIRTUAL TABLE t USING fts5(a, b, content = '' , tokenize='porter')",
    ];
    for d in dangereux {
        assert!(
            !crate::db_open::est_entierement_derivable(d),
            "une table plein-texte SANS CONTENU n'est JAMAIS dérivable : {d}"
        );
    }

    // Dérivables : le contenu est une AUTRE table, qui reste la source de vérité.
    let derivables = [
        "CREATE VIRTUAL TABLE event_fts USING fts5(\n  message, source, category, content='event', content_rowid='id'\n)",
        "create virtual table t using fts5(a, content='autre')",
    ];
    for d in derivables {
        assert!(crate::db_open::est_entierement_derivable(d), "contenu externe non vide : {d}");
    }

    // Tout le reste ne l'est pas — une table ordinaire porte SES données.
    let non_derivables = [
        "CREATE TABLE event(id INTEGER PRIMARY KEY, message TEXT)",
        "CREATE VIRTUAL TABLE t USING fts5(a, b)",
        "CREATE VIRTUAL TABLE t USING rtree(id, minx, maxx)",
        "CREATE VIEW v AS SELECT 1",
    ];
    for d in non_derivables {
        assert!(!crate::db_open::est_entierement_derivable(d), "pas un index dérivé : {d}");
    }
}

#[test]
fn le_nom_de_lindex_est_extrait_du_message_du_moteur_et_de_lui_seul() {
    assert_eq!(
        crate::db_open::nom_de_vtable_en_echec(
            "lecture des colonnes impossible (vtable constructor failed: event_fts)"
        )
        .as_deref(),
        Some("event_fts")
    );
    assert_eq!(
        crate::db_open::nom_de_vtable_en_echec("vtable constructor failed: ma_table_2 quelque chose")
            .as_deref(),
        Some("ma_table_2")
    );
    // Un refus qui ne parle pas d'une table virtuelle ne nomme RIEN : le chemin de réparation reste
    // fermé, et c'est ce qui garantit qu'un manque d'objet source n'y entre jamais par accident.
    for muet in [
        "l'objet suivant manque : table net_ban",
        "vtable constructor failed: ",
        "lecture de sqlite_master impossible (disk I/O error)",
    ] {
        assert_eq!(crate::db_open::nom_de_vtable_en_echec(muet), None, "aucun nom à extraire de : {muet}");
    }
}

#[test]
fn la_declaration_rebatie_est_celle_de_la_reference_et_non_celle_de_la_base() {
    // La DDL vient du binaire, pas du catalogue ouvert : c'est ce catalogue-là qu'on soupçonne au
    // moment où l'on répare. Le témoin le tient en comparant l'objet rebâti à la référence.
    let (_tmp, p) = base_neuve_pour("index-derive-reference");
    let attendue = crate::migrate::ddl_de_reference("event_fts")
        .expect("référence bâtie")
        .expect("ce binaire déclare bien cet index");
    abimer_lindex_plein_texte(&p);
    drop(crate::db_open::PreparedDb::open(&p).expect("rebâti"));
    let c = crate::db_open::open_db(&p).unwrap();
    let posee: String = c
        .query_row("SELECT sql FROM sqlite_master WHERE name='event_fts'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(posee, attendue, "l'index rebâti est DÉCLARÉ comme la référence le déclare");
}

// =====================================================================================
// `P10.20-f` — L'ESTAMPILLE DE SCHÉMA LUE À L'OUVERTURE N'EST PLUS FABRIQUÉE.
//
// LE DÉFAUT, MESURÉ LE 2026-09-16 AVANT TOUT CORRECTIF. `migrate::read_schema_version` lisait
// `meta.schema_version` par `query_row(..).ok()...unwrap_or(1)` : la même forme que les cinquante sites
// de `P10.20-b`, mais sur le chemin d'OUVERTURE. Le rang un de `P10.20-b` a corrigé la version SERVIE
// (`handlers/system.rs`) ; celle-ci n'est pas servie, elle AUTORISE. Sur une base migrée à
// `CODE_SCHEMA_MAX` et peuplée, rendue illisible de deux façons (table `meta` RENOMMÉE, puis ligne
// portant un BLOB dans la colonne lue), la lecture rendait « 1 », `schema_downgrade_guard` rendait
// `Ok(1)`, la porte OUVRAIT, et `migrate_chain` rejouait la chaîne entière de v2 à v122.
//
// CE QUE LE REJEU A DÉTRUIT, COMPTÉ AVANT ET APRÈS PAR LE BANC DE MESURE (identique sur les deux
// voies) : `event` 3 -> 1 (les purges one-time de sources de v48 et de v102/103), `banned_ip` de
// source 'ufw' 1 -> 0 (v59), le panneau « Sorties externes récentes » 1 -> 0 (v58), `event_rollup`
// 1 -> 0 (v33 : `DROP TABLE` puis repopulation depuis `event`), `host_rollup` 1 -> 2 (v77 : `DELETE`
// puis backfill à blanc). Sur la voie de la table renommée, `db/schema.sql` recrée EN PLUS une table
// `meta` VIDE à côté de l'ancienne : `session_epoch`, les watermarks de rollup et les drapeaux de
// semis deviennent hors d'atteinte, et les semis re-tournent. « 1 » n'est pas un chiffre faux parmi
// d'autres : c'est la version d'une base FRAÎCHE, donc la seule pour laquelle la chaîne entière est
// faite pour se rejouer.
//
// CE QUI SÉPARE UNE BASE NEUVE D'UNE BASE ILLISIBLE, ET CE N'EST PAS LE MESSAGE DU MOTEUR. Mesuré le
// même jour : les deux rendent `no such table: meta`, MOT POUR MOT. Ce qui les sépare est ce que le
// fichier PORTE — zéro objet au catalogue pour l'une, quatre-vingt-cinq tables pour l'autre. Le
// discriminant est donc DÉRIVÉ du fichier, et ce témoin le juge DANS LES DEUX SENS.
//
// CE QUE LES TÉMOINS TIENNENT : trois voies d'illisibilité refusent l'ouverture SANS toucher une
// ligne et SANS rejouer `db/schema.sql` (prouvé par l'absence de table `meta` neuve) ; une base
// NEUVE, une base SAINE et une base EN RETARD s'ouvrent toujours ; une base PLUS RÉCENTE garde son
// refus PROPRE ; la porte à sens unique (`migrate-check`) cesse de publier un chiffre inventé.
//
// CE QU'ILS NE TIENNENT PAS, ET IL FAUT LE LIRE ICI : aucun de ces témoins ne joue le code de sortie
// du processus — `migrate-check` est jugé sur la lecture typée, pas sur son `exit`.
//
// LE RESTE QUE CE FICHIER NOMMAIT EST FERMÉ (2026-09-16, `P10.20-i`) : la forme legacy « `meta`
// existe SANS sa ligne `schema_version` » continuait d'OUVRIR, et sur une base DÉJÀ MIGRÉE ce
// rattrapage rejouait la même chaîne destructrice — mesuré ici, chiffré, et laissé ouvert. Elle est
// désormais REFUSÉE dès que le fichier porte un schéma, et n'ouvre plus que lorsque `meta` est SEULE
// au catalogue (rien à détruire). Le témoin qui chiffrait ce prix a suivi la propriété : voir la
// section (4) ci-dessous et `tests/meta_sans_ligne_de_version_sur_une_base_qui_porte_un_schema.rs`.
// =====================================================================================

/// Une base plume MIGRÉE par la porte, dans un répertoire possédé.
fn eso_base_migree(nom: &str) -> (crate::tmp_possede::TmpPossede, String) {
    let tmp = crate::tmp_possede::TmpPossede::neuf(nom);
    let chemin = tmp.sous("plume.db").chemin().to_path_buf();
    let _ = std::fs::remove_file(&chemin);
    let p = chemin.to_str().unwrap().to_string();
    drop(crate::db_open::PreparedDb::open(&p).expect("précondition : la porte prépare une base neuve"));
    (tmp, p)
}

/// CE QUE LA BASE PORTE, aux endroits exacts que le rejeu de la chaîne détruit. Chaque ligne est
/// posée par le semis ci-dessous et visée par une étape NOMMÉE de `migrate.rs`.
fn eso_inventaire(p: &str) -> Vec<(&'static str, i64)> {
    let c = crate::db_open::open_db(p).unwrap();
    [
        ("event", "SELECT COUNT(*) FROM event"),
        ("event_purge_v48", "SELECT COUNT(*) FROM event WHERE source='agent'"),
        ("event_purge_v102", "SELECT COUNT(*) FROM event WHERE source='fortigate'"),
        ("banned_ip_ufw_v59", "SELECT COUNT(*) FROM banned_ip WHERE source='ufw'"),
        ("panel_retire_v58", "SELECT COUNT(*) FROM panel WHERE title='Sorties externes récentes'"),
        ("host_rollup_v77", "SELECT COUNT(*) FROM host_rollup WHERE host='zz'"),
        ("event_rollup_v33", "SELECT COUNT(*) FROM event_rollup WHERE source='sshd'"),
    ]
    .into_iter()
    .map(|(nom, sql)| (nom, c.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap_or(-1)))
    .collect()
}

/// Sème EXACTEMENT ce que les étapes destructrices visent, plus un témoin qu'aucune ne touche.
fn eso_semer(p: &str) {
    let c = crate::db_open::open_db(p).unwrap();
    c.execute_batch(
        "INSERT INTO event(ts,source,category,severity,host,message) VALUES(1000,'agent','auth',1,'h1','a');\
         INSERT INTO event(ts,source,category,severity,host,message) VALUES(1001,'fortigate','net',1,'h1','b');\
         INSERT INTO event(ts,source,category,severity,host,message) VALUES(1002,'sshd','auth',3,'h2','c');\
         INSERT INTO banned_ip(src_ip,source,label,first_seen,last_seen) VALUES('10.0.0.1','ufw','x',1,2);\
         INSERT INTO host_rollup(host,env_id,last_ts,first_ts,sig_total,sig_hot,updated) VALUES('zz','prod',5,5,7,0,5);\
         INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) \
           VALUES(3600,'sshd',3,'','','',42,3600,'prod');",
    )
    .expect("fixture : le semis doit passer");
    let did: i64 = c.query_row("SELECT id FROM dashboard ORDER BY id LIMIT 1", [], |r| r.get(0)).expect("un dashboard semé");
    c.execute(
        "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,cols) \
         VALUES(?1,'Sorties externes récentes','search source=sshd',1,'table',99,2)",
        params![did],
    )
    .expect("fixture : le panneau visé par v58");
}

/// Le nombre de tables nommées `meta` au catalogue. `1` = celle d'origine ; `2` = `db/schema.sql` en a
/// recréé une VIDE à côté, c'est-à-dire que le contrat a tourné et que la chaîne a été rejouée.
fn eso_tables_meta(p: &str) -> i64 {
    let c = crate::db_open::open_db(p).unwrap();
    c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'meta%'", [], |r| r.get(0))
        .unwrap()
}

/// Le refus de la porte, en texte — ou la panique si elle a OUVERT (ce qui est tout le défaut).
fn eso_refus(p: &str) -> String {
    match crate::db_open::PreparedDb::open(p) {
        Ok(_) => panic!("la porte a OUVERT une base dont l'estampille n'est pas lisible"),
        Err(e) => e.to_string(),
    }
}

/// CE QU'UN REFUS DOIT DIRE : sa cause, ce qu'il a évité, la clé à vérifier d'abord, la sauvegarde à
/// restaurer ensuite. Jugé sur des constantes du produit partout où il en existe une.
fn eso_le_refus_est_complet(refus: &str, voie: &str) {
    assert!(refus.contains(CAUSE_ESTAMPILLE_DE_SCHEMA_NON_LUE), "{voie} : le refus NOMME sa cause : {refus}");
    assert!(refus.contains("PLUME_DB_KEY"), "{voie} : le refus nomme d'ABORD la clé au repos : {refus}");
    assert!(refus.contains("plume-daemon restore"), "{voie} : le refus NOMME la sauvegarde à restaurer : {refus}");
    assert!(refus.contains("docs/DR-plume-restore.md"), "{voie} : et le runbook qui la décrit : {refus}");
    assert!(refus.contains("Aucune écriture effectuée"), "{voie} : le refus dit qu'il n'a rien écrit : {refus}");
}

// -------------------------------------------------------------------------------------
// (1) LES TROIS VOIES D'ILLISIBILITÉ — REFUS, ET LA BASE RESSORT INTACTE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : sur une base migrée et PEUPLÉE, chacune des trois voies par lesquelles
/// `meta.schema_version` cesse d'être lisible fait REFUSER l'ouverture, et l'inventaire ressort
/// IDENTIQUE à ce qu'il était — y compris `db/schema.sql`, qui n'a pas été rejoué (aucune seconde
/// table `meta`). Contrôle positif compté dans le même corps : la même base, avant qu'on l'abîme,
/// s'ouvre et porte tout.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rendre à `schema_downgrade_guard` le repli sur « 1 » — la porte
/// rouvre, la chaîne se rejoue, et sept des huit lignes d'inventaire changent.
#[test]
fn p10_20f_une_estampille_non_lue_refuse_l_ouverture_et_ne_touche_a_rien() {
    for (voie, abimer) in [
        ("table meta RENOMMÉE", "ALTER TABLE meta RENAME TO meta_hors_d_atteinte;"),
        ("ligne ILLISIBLE (blob)", "UPDATE meta SET value=x'FF' WHERE key='schema_version';"),
        ("ligne NON ENTIÈRE", "UPDATE meta SET value='cent-vingt-deux' WHERE key='schema_version';"),
    ] {
        let (_t, p) = eso_base_migree("eso-refus");
        eso_semer(&p);

        // CONTRÔLE POSITIF — tant que l'estampille est lisible, la porte ouvre et ne détruit rien.
        let avant = eso_inventaire(&p);
        drop(crate::db_open::PreparedDb::open(&p).expect("contrôle positif : base SAINE, la porte ouvre"));
        assert_eq!(eso_inventaire(&p), avant, "{voie} : contrôle positif, une ouverture saine ne touche à rien");
        assert!(avant.iter().all(|(_, n)| *n >= 1), "fixture : tout l'inventaire est posé : {avant:?}");
        let metas_avant = eso_tables_meta(&p);

        {
            let c = crate::db_open::open_db(&p).unwrap();
            c.execute_batch(abimer).expect("fixture : l'abîmage doit passer");
        }

        let refus = eso_refus(&p);
        eso_le_refus_est_complet(&refus, voie);
        assert_eq!(eso_inventaire(&p), avant, "{voie} : la base ressort INTACTE du refus");
        assert_eq!(
            eso_tables_meta(&p), metas_avant,
            "{voie} : `db/schema.sql` n'a pas été rejoué (aucune table `meta` neuve à côté)"
        );
    }
}

// -------------------------------------------------------------------------------------
// (2) CE QUI DOIT TOUJOURS OUVRIR
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : le refus ne frappe NI une base neuve, NI une base saine, NI une base en RETARD —
/// les trois entrées légitimes de la porte. Et la base PLUS RÉCENTE garde son refus PROPRE : un
/// correctif qui les confondrait rendrait le message d'un rollback d'image illisible.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : faire tomber la base neuve du côté `NonLue` (par exemple en
/// refusant dès que `meta` ne répond pas, sans interroger le catalogue) — le premier bloc tombe.
#[test]
fn p10_20f_une_base_neuve_une_base_saine_et_une_base_en_retard_s_ouvrent_toujours() {
    // (a) BASE NEUVE : un fichier qui ne porte RIEN. C'est le cas que le refus ne doit jamais frapper.
    let tmp = crate::tmp_possede::TmpPossede::neuf("eso-neuve");
    let p = tmp.sous("plume.db").chemin().to_str().unwrap().to_string();
    let _ = std::fs::remove_file(&p);
    {
        let db = crate::db_open::PreparedDb::open(&p).expect("base NEUVE : la porte la prépare");
        assert_eq!(read_schema_version(&db), CODE_SCHEMA_MAX, "base neuve migrée jusqu'à la tête");
    }

    // (b) BASE SAINE, rouverte : acceptée, version inchangée.
    assert!(crate::db_open::PreparedDb::open(&p).is_ok(), "2e ouverture d'une base à jour : acceptée");

    // (c) BASE EN RETARD : elle doit être MIGRÉE, pas refusée.
    {
        let c = crate::db_open::open_db(&p).unwrap();
        c.execute("UPDATE meta SET value=?1 WHERE key='schema_version'", params![(CODE_SCHEMA_MAX - 1).to_string()])
            .unwrap();
        assert_eq!(schema_downgrade_guard(&c), Ok(CODE_SCHEMA_MAX - 1), "une base en retard n'est pas un refus");
    }
    {
        let db = crate::db_open::PreparedDb::open(&p).expect("base EN RETARD : la porte la migre");
        assert_eq!(read_schema_version(&db), CODE_SCHEMA_MAX, "et elle est remontée à la tête");
    }

    // (d) BASE PLUS RÉCENTE : refus PROPRE, distinct de celui de l'estampille non lue.
    {
        let c = crate::db_open::open_db(&p).unwrap();
        c.execute("UPDATE meta SET value=?1 WHERE key='schema_version'", params![(CODE_SCHEMA_MAX + 1).to_string()])
            .unwrap();
    }
    match crate::db_open::PreparedDb::open(&p) {
        Err(crate::db_open::DbOpenError::PlusRecenteQueCeBinaire(v)) => assert_eq!(v, CODE_SCHEMA_MAX + 1),
        autre => panic!(
            "une base plus récente garde SON refus (obtenu : {})",
            autre.err().map(|e| e.to_string()).unwrap_or_else(|| "Ok".into())
        ),
    }
}

// -------------------------------------------------------------------------------------
// (3) LE DISCRIMINANT EST LE CATALOGUE, PAS LA PHRASE DU MOTEUR
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : une base NEUVE et une base MIGRÉE dont `meta` a disparu rendent au moteur le MÊME
/// message (`no such table: meta`) — donc aucun correctif qui lirait ce texte ne pourrait les
/// séparer. Ce qui les sépare est le CATALOGUE, et le témoin le juge dans les DEUX SENS : zéro objet
/// ouvre, des objets refusent.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : trancher sur le texte de l'erreur au lieu du catalogue — les
/// deux premiers blocs deviennent indiscernables et le dernier tombe.
#[test]
fn p10_20f_le_discriminant_est_le_catalogue_et_non_le_message_du_moteur() {
    let requete = "SELECT value FROM meta WHERE key='schema_version'";

    let tmp = crate::tmp_possede::TmpPossede::neuf("eso-catalogue-neuve");
    let neuve = tmp.sous("plume.db").chemin().to_str().unwrap().to_string();
    let _ = std::fs::remove_file(&neuve);
    let (msg_neuve, objets_neuve) = {
        let c = crate::db_open::open_db(&neuve).unwrap();
        let msg = c.query_row(requete, [], |r| r.get::<_, String>(0)).unwrap_err().to_string();
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'", [], |r| r.get(0))
            .unwrap();
        (msg, n)
    };

    let (_t2, migree) = eso_base_migree("eso-catalogue-migree");
    let (msg_migree, objets_migree) = {
        let c = crate::db_open::open_db(&migree).unwrap();
        c.execute_batch("ALTER TABLE meta RENAME TO meta_hors_d_atteinte;").unwrap();
        let msg = c.query_row(requete, [], |r| r.get::<_, String>(0)).unwrap_err().to_string();
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'", [], |r| r.get(0))
            .unwrap();
        (msg, n)
    };

    assert_eq!(msg_neuve, msg_migree, "le moteur dit la MÊME chose des deux : « {msg_neuve} »");
    assert_eq!(objets_neuve, 0, "une base neuve ne porte RIEN au catalogue");
    assert!(objets_migree > 50, "une base migrée en porte des dizaines : {objets_migree}");

    // Et la porte en tire deux conduites OPPOSÉES, sur ce seul discriminant.
    assert!(crate::db_open::PreparedDb::open(&neuve).is_ok(), "catalogue vide -> base neuve -> OUVRE");
    let refus = eso_refus(&migree);
    assert!(refus.contains("ce n'est donc PAS une base neuve"), "le refus DIT pourquoi ce n'en est pas une : {refus}");
    assert!(
        refus.contains(&format!("{objets_migree} objet(s)")),
        "et il COMPTE ce que le fichier porte, au lieu de l'affirmer : {refus}"
    );
}

// -------------------------------------------------------------------------------------
// (4) LA FORME LEGACY — TÉMOIN DÉPLACÉ LE 2026-09-16, ET VOICI POURQUOI
// -------------------------------------------------------------------------------------
//
// `p10_20f_la_forme_legacy_sans_ligne_reste_ouverte_et_son_prix_est_mesure` vivait ici. Il tenait
// deux choses : que `meta` présente SANS sa ligne `schema_version` est une absence ÉTABLIE (donc
// `EstampilleDeSchema::JamaisEstampillee` et non `NonLue`), et que la porte l'OUVRAIT — puis il
// CHIFFRAIT ce que ce rattrapage détruit sur une base déjà migrée, pour que le reste de `P10.20-f`
// soit mesuré et non annoncé.
//
// `P10.20-i` a refermé cette voie : sur un fichier qui porte un schéma, cette absence est désormais
// REFUSÉE. La moitié « la porte ouvre » du témoin est donc devenue FAUSSE, et sa moitié « voici le
// prix » reste la JUSTIFICATION du refus — elle doit continuer d'être jouée, sur le contrat cette
// fois, puisque la porte n'y mène plus. Les deux moitiés sont reprises, ensemble, dans
// `tests/meta_sans_ligne_de_version_sur_une_base_qui_porte_un_schema.rs` (préfixe `p10_20i_`), qui
// emprunte les fixtures de CE fichier — elles n'ont pas été recopiées. Rien n'a été supprimé : le
// témoin a changé de clé parce que la propriété qu'il tient a changé de propriétaire.

// -------------------------------------------------------------------------------------
// (5) LA PORTE À SENS UNIQUE LIT LA MÊME VALEUR — ET NE PUBLIE PLUS DE CHIFFRE INVENTÉ
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `migrate-check`, que l'outillage de déploiement interroge pour décider s'il fait
/// la sauvegarde pré-migration, lisait `read_schema_version` — donc le MÊME repli. Sur une base
/// illisible il imprimait « schema LIVE=1 » et sortait 0 : la DIRECTION était fail-safe par accident
/// (0 = « fais le snapshot »), mais le chiffre était inventé, et « 1 » se lit « base très ancienne ».
/// La lecture typée rend désormais `NonLue`, ce dont la sous-commande tire son code 2 — le slot que
/// son aide documente déjà pour « base illisible ». Une base neuve et une base à jour gardent leur
/// verdict.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas le processus, donc pas le code de sortie lui-même
/// (`std::process::exit` dans `main.rs`) — il juge la lecture sur laquelle ce code est décidé.
#[test]
fn p10_20f_la_porte_a_sens_unique_ne_lit_plus_un_chiffre_invente() {
    let (_t, p) = eso_base_migree("eso-porte");

    // (a) base à jour : la lecture rend la vraie version -> « À JOUR », snapshot inutile.
    {
        let c = Connection::open_with_flags(&p, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        match lire_l_estampille_de_schema(&c) {
            EstampilleDeSchema::Lue(v) => assert_eq!(v, CODE_SCHEMA_MAX, "base à jour : la version est LUE"),
            _ => panic!("une base à jour doit rendre une version lue"),
        }
    }

    // (b) estampille illisible : plus aucun chiffre, une cause.
    {
        let c = crate::db_open::open_db(&p).unwrap();
        c.execute_batch("UPDATE meta SET value=x'FF' WHERE key='schema_version';").unwrap();
    }
    {
        let c = Connection::open_with_flags(&p, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        match lire_l_estampille_de_schema(&c) {
            EstampilleDeSchema::NonLue(cause) => {
                assert!(cause.contains(CAUSE_ESTAMPILLE_DE_SCHEMA_NON_LUE), "la cause est nommée : {cause}");
                assert!(!cause.contains("LIVE=1"), "aucun chiffre n'est publié : {cause}");
            }
            EstampilleDeSchema::Lue(v) => panic!("la porte à sens unique a publié un chiffre : {v}"),
            _ => panic!("une base peuplée dont l'estampille est illisible n'est ni neuve ni legacy"),
        }
    }

    // (c) base NEUVE : verdict inchangé — migration en attente, snapshot demandé.
    let tmp = crate::tmp_possede::TmpPossede::neuf("eso-porte-neuve");
    let neuve = tmp.sous("plume.db").chemin().to_str().unwrap().to_string();
    let _ = std::fs::remove_file(&neuve);
    drop(crate::db_open::open_db(&neuve).unwrap());
    let c = Connection::open_with_flags(&neuve, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert!(
        matches!(lire_l_estampille_de_schema(&c), EstampilleDeSchema::BaseNeuve),
        "une base neuve reste une base neuve pour la porte à sens unique"
    );
}

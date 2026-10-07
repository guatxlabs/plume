// =====================================================================================
// `P10.31-l` — UNE LIGNE DE RÉTENTION LÉGALE NON LUE REFUSE LA PURGE.
//
// LE DÉFAUT (mesuré sur 23939081) : `holds_covering` aplatissait par `.flatten()` les lignes de `legal_hold`
// actives qui recouvrent le périmètre. Une ligne dont le `name` ne se décode pas DISPARAISSAIT du refus total,
// alors que `hold_guard` (qui ne compte que `active=1`) rendait le prédicat `LEGAL_HOLD_NOT_HELD` : la
// simulation passait et le plan purgeait « tout sauf les lignes tenues » — la purge partielle silencieuse que
// `purge_plan` dit ne jamais faire.
//
// CE QUE CES TÉMOINS JUGENT, DANS LES DEUX SENS :
//  - colonne `name` illisible sur UNE ligne (blob) : refus `legal_hold_unread` nommé, aucun plan, et la
//    confirmation ne supprime rien ; contrôle positif dans le même corps (nom lisible -> `legal_hold` le NOMME) ;
//  - TABLE entière lue au travers d'une VUE TEMPORAIRE de même nom qui projette `name` en blob : même refus ;
//  - ERREUR DE PAS : la lecture d'une ligne tenue échoue dans SQLite (dépassement d'entier calculé par une vue
//    temporaire) : même refus — les deux témoins précédents ne produisent qu'une erreur de DÉCODAGE ;
//  - chemin nominal : une ligne illisible que le prédicat de portée N'ATTEINT PAS (inactive, hors fenêtre,
//    autre source nommée) ne refuse pas.
// MUTATIONS (jouées, retirées du source) : `VERIF_MUT=E2_FLATTEN` (l'aplatissement restauré) rougit les
// témoins de refus ; `VERIF_MUT=E2_CAUSE_DB` (refus servi comme banale erreur base) les rougit aussi, par le
// code ; `VERIF_MUT=E2_PAS_AVALE` (les `SqliteFailure` avalées, le décodage refusé) ne rougit QUE le témoin
// d'erreur de pas ; le témoin nominal reste vert sous les trois.
// =====================================================================================

fn rln_ins_event(c: &Connection, ts: i64, source: &str) {
    c.execute(
        "INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id) \
         VALUES(?1,?2,'test',1,'preuve','h1','prod','','')",
        params![ts, source],
    )
    .unwrap();
}

fn rln_ins_hold(c: &Connection, name: &str, source: &str, start: i64, end: i64, active: i64) {
    c.execute(
        "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
         VALUES(?1,'',?2,?3,?4,?5,0,'admin')",
        params![name, source, start, end, active],
    )
    .unwrap();
}

fn rln_scope(sel: &[(&str, &str)], start: i64, end: i64) -> PurgeScope {
    let v: Vec<(String, String)> = sel.iter().map(|(k, x)| (k.to_string(), x.to_string())).collect();
    purge_scope_from_args(&v, &start.to_string(), &end.to_string(), now()).expect("périmètre valide")
}

/// Base où la purge par `env=prod` couvrirait deux sources, dont `sshd` tenue par un hold source-scopé :
/// exactement la forme où l'ancien code purgeait `flux-de-test` en épargnant `sshd`, sans un mot.
fn rln_base_tenue() -> Connection {
    let c = test_db();
    rln_ins_event(&c, 1_000, "sshd");
    rln_ins_event(&c, 1_000, "flux-de-test");
    rln_ins_hold(&c, "litige-sshd", "sshd", 0, 0, 1);
    c
}

/// Juge le refus fail-closed nommé, par la simulation ET par la voie de confirmation.
fn rln_juger_refus_non_lu(c: &Connection, voie: &str) {
    let e = match purge_plan(c, rln_scope(&[("env", "prod")], 0, 2_000)) {
        Ok(p) => panic!(
            "{voie} : la simulation a rendu un plan de {} ligne(s) malgré une rétention NON LUE (purge partielle \
             silencieuse « sauf les lignes tenues »)",
            p.rows()
        ),
        Err(e) => e,
    };
    assert_eq!(purge_refusal_code(&e), "legal_hold_unread", "{voie} : refus nommé, pas `{e}`");
    let m = e.to_string();
    assert!(m.contains("NON LUE"), "{voie} : le texte dit NON LUE : {m}");
    assert!(m.contains("`legal_hold`"), "{voie} : la cause nomme la table par le code : {m}");
    // La voie de confirmation re-simule : elle refuse par la MÊME cause, avant de comparer le jeton (un jeton
    // bidon rendrait sinon `stale_token`). Aucune assertion « rien supprimé » ici : avec un jeton bidon elle
    // serait vraie quelle que soit l'implémentation.
    let e2 = purge_confirm_and_apply(c, rln_scope(&[("env", "prod")], 0, 2_000), "jeton-quelconque", "t", "raison")
        .unwrap_err();
    assert_eq!(purge_refusal_code(&e2), "legal_hold_unread", "{voie} : confirmation refusée par la même cause");
}

/// Voie COLONNE : le `name` d'une ligne tenue est rendu illisible : un blob, non UTF-8 puis UTF-8 (c'est le TYPE qui
/// ne se décode pas, pas le contenu ; un entier ne convient pas, l'affinité TEXT le reconvertit en texte).
#[test]
fn rln_nom_de_retention_illisible_refuse_la_purge_sans_purge_partielle() {
    for (voie, illisible) in [("blob non UTF-8", "X'FFFE'"), ("blob UTF-8", "CAST('litige-sshd' AS BLOB)")] {
        let c = rln_base_tenue();
        // Contrôle positif dans le même corps : nom LISIBLE -> le refus NOMME le hold.
        let e = purge_plan(&c, rln_scope(&[("env", "prod")], 0, 2_000)).unwrap_err();
        assert_eq!(purge_refusal_code(&e), "legal_hold", "{voie} : contrôle positif");
        assert!(e.to_string().contains("litige-sshd"), "{voie} : le hold est nommé : {e}");

        c.execute_batch(&format!("UPDATE legal_hold SET name={illisible} WHERE name='litige-sshd'")).unwrap();
        rln_juger_refus_non_lu(&c, voie);
    }
}

/// Voie TABLE : `legal_hold` lue au travers d'une VUE TEMPORAIRE de même nom (elle ombre la table) qui
/// projette `name` en blob. `hold_guard` la lit sans peine (il ne compte que `active=1`) ; seule la lecture des
/// noms échoue — c'est la forme que prend une erreur de LIGNE quand `prepare` a réussi.
#[test]
fn rln_table_de_retention_lue_par_vue_illisible_refuse_la_purge() {
    let c = rln_base_tenue();
    assert_eq!(
        purge_refusal_code(&purge_plan(&c, rln_scope(&[("env", "prod")], 0, 2_000)).unwrap_err()),
        "legal_hold",
        "contrôle positif : la table lue nomme le hold"
    );
    c.execute_batch(
        "CREATE TEMP VIEW legal_hold AS \
           SELECT id, CAST(name AS BLOB) AS name, reason, scope_source, scope_start_ts, scope_end_ts, active, \
                  created, created_by, released_ts, released_by FROM main.legal_hold;",
    )
    .unwrap();
    rln_juger_refus_non_lu(&c, "vue temporaire");
}

/// Sens NOMINAL : une ligne illisible que le prédicat de portée n'atteint pas n'est pas LUE, donc ne refuse
/// pas — et le plan est le même (même jeton, mêmes lignes) que sur une base sans elle. Sans ce sens, un
/// correctif qui refuserait dès qu'une ligne illisible EXISTE passerait les témoins de refus.
#[test]
fn rln_ligne_illisible_hors_portee_ne_refuse_pas_et_le_plan_est_inchange() {
    let c = test_db();
    rln_ins_event(&c, 5_000, "flux-de-test");
    rln_ins_hold(&c, "inactive", "", 0, 0, 0);
    rln_ins_hold(&c, "hors-fenetre", "", 1, 100, 1);
    rln_ins_hold(&c, "autre-source", "sshd", 0, 0, 1);
    c.execute_batch("UPDATE legal_hold SET name=CAST(name AS BLOB)").unwrap();
    let n_blob: i64 =
        c.query_row("SELECT COUNT(*) FROM legal_hold WHERE typeof(name)='blob'", [], |r| r.get(0)).unwrap();
    assert_eq!(n_blob, 3, "précondition : les trois noms sont illisibles");

    // Seule assertion qui juge `holds_covering` dans ce sens : la simulation PASSE (ce site ne rend que des
    // noms ou un refus ; il ne peut pas changer un plan qu'il laisse passer).
    purge_plan(&c, rln_scope(&[("source", "flux-de-test")], 4_000, 6_000))
        .expect("aucune ligne illisible n'est dans la portée : la simulation passe");
}

/// Voie ERREUR DE PAS : la lecture d'une ligne tenue échoue DANS SQLite (erreur d'exécution levée au pas, pas
/// de décodage de type) — la forme d'une page corrompue, d'une interruption ou d'un cache de schéma périmé.
/// La vue temporaire calcule `name` par un dépassement d'entier (`abs` de -2^63) sur les seules lignes actives :
/// `hold_guard` (qui ne lit pas `name`) rend son prédicat, et seule la lecture des noms échoue. Sans ce témoin,
/// un correctif qui ne refuserait que les erreurs de DÉCODAGE et avalerait les `SqliteFailure` passerait.
#[test]
fn rln_erreur_de_pas_sur_une_ligne_tenue_refuse_la_purge() {
    let c = rln_base_tenue();
    c.execute_batch(
        "CREATE TEMP VIEW legal_hold AS \
           SELECT id, CASE WHEN active=1 THEN abs(-9223372036854775807 - active) ELSE name END AS name, reason, \
                  scope_source, scope_start_ts, scope_end_ts, active, created, created_by, released_ts, released_by \
             FROM main.legal_hold;",
    )
    .unwrap();
    // Précondition : l'erreur est bien une erreur SQLite au pas, pas une erreur de décodage.
    let brute = c.query_row("SELECT name FROM legal_hold WHERE active=1", [], |r| r.get::<_, String>(0)).unwrap_err();
    assert!(matches!(brute, rusqlite::Error::SqliteFailure(..)), "précondition : erreur SQLite au pas, pas `{brute:?}`");
    assert!(matches!(legal_hold_enforcement(&c), HoldEnforce::Guard(_)), "précondition : la garde rend un prédicat");
    rln_juger_refus_non_lu(&c, "erreur de pas");
}

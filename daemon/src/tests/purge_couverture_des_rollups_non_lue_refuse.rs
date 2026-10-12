// =====================================================================================
// `P10.20-b` (famille hors `handlers/` : `purge_rebuild_rollups`, ex-`meta_i64`) — UNE COUVERTURE DE ROLLUP
// NON LUE REFUSE LA PURGE AU LIEU DE DÉTRUIRE LES BUCKETS SANS LES RECONSTRUIRE.
//
// LE DÉFAUT (mesuré sur 318bf0e) : `purge_rebuild_rollups` supprimait les buckets de la bande PUIS lisait la
// couverture par `meta_i64` (`.ok()` sur `query_row`) et par `DimRollupCoverage::of` (`.ok()` aussi). Une lecture
// ratée valait « aucune couverture publiée » : pas de ré-agrégation, `rollup_reaggregated=false`, COMMIT — alors
// que la couverture publiée en base affirmait toujours que ces buckets étaient une image d'`event`. La route
// servait ensuite des buckets VIDES pour des lignes qui survivent à la purge.
//
// CE QUE CES TÉMOINS JUGENT, DANS LES DEUX SENS :
//  - `meta` entière illisible (vue temporaire de même nom sur une table disparue : erreur au `prepare`) : refus
//    `db` nommé, et le ROLLBACK est PROUVÉ PAR RELECTURE — buckets des deux rollups identiques ligne pour ligne,
//    lignes d'`event` intactes, aucune entrée de registre ; contrôle positif dans le même corps (vue retirée ->
//    la même purge passe et ré-agrège les survivants) ;
//  - erreur AU PAS sur la seule clé de couverture par dimension, puis sur la seule clé d'`event_rollup` (vue
//    temporaire qui calcule un dépassement d'entier sur cette ligne-là) : même refus, mêmes relectures ;
//  - couverture ABSENTE (ou mal formée) : reçu d'avant — purge faite, buckets de la bande supprimés et non
//    ré-agrégés, `rollup_reaggregated=false`, texte « aucune couverture publiée » ;
//  - couverture par dimension SEULE publiée : la lecture locale de `"<from>|<below>|<hot_from>|<at_id>"` s'accorde
//    avec ce que le job publie (les survivants sont ré-agrégés dans `event_dim_rollup`) ;
//  - la BORNE retenue est celle que chaque couverture publie : une ligne RETARDATAIRE (`id >` couverture, dans la
//    bande) survit à la purge et n'est agrégée ni dans `event_rollup` ni dans `event_dim_rollup` ;
//  - le miroir local du format s'ACCORDE avec `DimRollupCoverage::of` dans les deux sens, forme par forme (cinq
//    champs, trois, un seul, vide, un champ non entier à chaque rang : refusées par les deux ; nominale et `<from>`
//    négatif : acceptées par les deux, jusqu'au même `at_id`). Une forme hors de cet ensemble n'est pas jugée.
// MUTATIONS (jouées sous la variable de mutation, retirées du source) : `K4_OK_AVALE` (les deux lectures avalées comme avant)
// rougit les trois témoins de refus ; `K4_DIM_AVALE` ne rougit que celui de la clé par dimension ;
// `K4_COV_AVALE` que celui de la clé d'`event_rollup` ; `K4_DIM_FORMAT` (le miroir du format ne lit plus rien)
// rougit le témoin de la couverture par dimension seule et les trois contrôles positifs (survivants non
// ré-agrégés dans `event_dim_rollup`). Le témoin de l'absence reste vert sous les quatre. Reprise après vérification :
// `K4R_ROLLUP_BORNE` (borne d'`event_rollup` sans effet) rougit le témoin de la retardataire ; `K4R_DIM_CHAMP`
// (`<from>` retenu au lieu de `<at_id>`) rougit celui de la retardataire et celui de l'accord ; `K4R_DIM_LEN` (cinq
// champs acceptés) et `K4R_DIM_PARSE` (trois premiers champs non vérifiés) rougissent celui de l'accord.
// CE QUE CE LOT NE TIENT PAS : les itérateurs aplatis par `.flatten()` de `purge_plan` (ventilation par
// source), `purge_sample` et `cited_by_case` restent hors de ce site ; le refus sort par `PurgeRefusal::Db` (la
// 500 `refusal:"db"` partagée avec la CLI, variante propre sous `P10.29-h`) ; `RollupCoverage::of` et
// `DimRollupCoverage::of` (rollup_coverage.rs, partagé) gardent `.ok()` -> `unproven`, défaut sûr pour la route.
// =====================================================================================

/// Base : une heure DÉFINITIVE (sous la fenêtre chaude) de la source `web` (portée par le rollup par dimension),
/// trois lignes `prod` (`status=500`, la cible) et deux lignes `staging` (`status=200`, les survivantes) ; les
/// deux rollups agrégés et leurs couvertures publiées par le job réel. Rend la base et l'heure.
fn k4c_base() -> (Connection, i64) {
    let c = test_db();
    let base = (now() / 3600) * 3600 - 2 * 3600;
    for (i, (env, status)) in
        [("prod", "500"), ("prod", "500"), ("prod", "500"), ("staging", "200"), ("staging", "200")].iter().enumerate()
    {
        c.execute(
            "INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id,fields) \
             VALUES(?1,'web','test',1,'preuve','h1',?2,'','',?3)",
            params![base + i as i64, env, format!("{{\"status\":\"{status}\"}}")],
        )
        .unwrap();
    }
    rollup_events(&c);
    (c, base)
}

fn k4c_scope(base: i64) -> PurgeScope {
    let v = vec![("env".to_string(), "prod".to_string())];
    purge_scope_from_args(&v, &base.to_string(), &(base + 10).to_string(), now()).expect("périmètre valide")
}

/// Les deux rollups, LIGNE POUR LIGNE (lus dans `main`, hors de toute vue temporaire).
fn k4c_buckets(c: &Connection) -> (Vec<String>, Vec<String>) {
    let lire = |sql: &str| -> Vec<String> {
        let mut st = c.prepare(sql).unwrap();
        let v: rusqlite::Result<Vec<String>> = st.query_map([], |r| r.get::<_, String>(0)).unwrap().collect();
        v.unwrap()
    };
    (
        lire(
            "SELECT bucket||'|'||source||'|'||severity||'|'||action||'|'||n FROM main.event_rollup \
             ORDER BY bucket,source,severity,action",
        ),
        lire("SELECT bucket||'|'||source||'|'||dim||'|'||val||'|'||n FROM main.event_dim_rollup ORDER BY bucket,source,dim,val"),
    )
}

fn k4c_dim_n(c: &Connection, base: i64, val: &str) -> i64 {
    c.query_row(
        "SELECT COALESCE(SUM(n),0) FROM main.event_dim_rollup WHERE bucket=?1 AND source='web' AND dim='status' AND val=?2",
        params![base, val],
        |r| r.get(0),
    )
    .unwrap()
}

fn k4c_rollup_n(c: &Connection, base: i64) -> i64 {
    c.query_row("SELECT COALESCE(SUM(n),0) FROM main.event_rollup WHERE bucket=?1 AND source='web'", params![base], |r| {
        r.get(0)
    })
    .unwrap()
}

fn k4c_events(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM main.event WHERE origin=''", [], |r| r.get(0)).unwrap()
}

fn k4c_registre(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM main.ledger WHERE kind=?1", params![PURGE_LEDGER_KIND], |r| r.get(0)).unwrap()
}

/// Simule SANS vue (le jeton est pris sur la base saine), pose la vue hostile, exécute : la purge doit être
/// REFUSÉE et RIEN détruit — relu bucket par bucket. Puis retire la vue et rejoue : contrôle positif.
fn k4c_juger_refus(vue: &str, voie: &str) {
    let (c, base) = k4c_base();
    assert_eq!((k4c_dim_n(&c, base, "500"), k4c_dim_n(&c, base, "200")), (3, 2), "{voie} : précondition, dim peuplé");
    assert_eq!(k4c_rollup_n(&c, base), 5, "{voie} : précondition, rollup peuplé");
    let avant = k4c_buckets(&c);
    let plan = purge_plan(&c, k4c_scope(base)).unwrap();
    let tok = plan.digest().to_string();
    let confirmed = plan.confirm(&tok, "t", "raison").unwrap();

    c.execute_batch(vue).unwrap();
    let issue = purge_apply(&c, confirmed);
    c.execute_batch("DROP VIEW temp.meta;").unwrap();
    let e = match issue {
        Ok(r) => panic!(
            "{voie} : purge COMMITÉE malgré une couverture NON LUE (reaggregated={}, dim survivants={}, rollup={}) : \
             buckets détruits sans reconstruction",
            r.rollup_reaggregated,
            k4c_dim_n(&c, base, "200"),
            k4c_rollup_n(&c, base)
        ),
        Err(e) => e,
    };
    assert_eq!(purge_refusal_code(&e), "db", "{voie} : refus servi par le contrat partagé `db`, pas `{e}`");
    let m = e.to_string();
    assert!(m.contains("NON LUE") && m.contains("`meta`"), "{voie} : la cause nomme la lecture non faite : {m}");
    // ROLLBACK prouvé par RELECTURE, pas par le code de retour.
    assert_eq!(k4c_buckets(&c), avant, "{voie} : les buckets des deux rollups sont intacts, ligne pour ligne");
    assert_eq!(k4c_events(&c), 5, "{voie} : aucune ligne d'`event` supprimée");
    assert_eq!(k4c_registre(&c), 0, "{voie} : le registre n'affirme pas une purge annulée");

    // CONTRÔLE POSITIF : vue retirée, la même purge passe — le refus venait bien de la lecture de `meta`.
    let tok = purge_plan(&c, k4c_scope(base)).unwrap().digest().to_string();
    let r = purge_confirm_and_apply(&c, k4c_scope(base), &tok, "t", "raison").unwrap();
    assert_eq!(r.rows_deleted, 3, "{voie} : contrôle positif, la cible part");
    assert!(r.rollup_reaggregated, "{voie} : contrôle positif, couvertures lues -> ré-agrégé");
    assert_eq!(
        (k4c_dim_n(&c, base, "500"), k4c_dim_n(&c, base, "200"), k4c_rollup_n(&c, base)),
        (0, 2, 2),
        "{voie} : contrôle positif, seuls les survivants restent agrégés"
    );
}

#[test]
fn purge_meta_illisible_refuse_et_ne_detruit_aucun_bucket() {
    k4c_juger_refus(
        "CREATE TEMP TABLE k4c_disparue(key TEXT, value TEXT); \
         CREATE TEMP VIEW meta AS SELECT key, value FROM k4c_disparue; \
         DROP TABLE k4c_disparue;",
        "meta illisible au prepare",
    );
}

#[test]
fn purge_couverture_par_dimension_non_lue_au_pas_refuse() {
    k4c_juger_refus(
        &format!(
            "CREATE TEMP VIEW meta AS SELECT key, CASE WHEN key='{k}' THEN abs(-9223372036854775807 - (key='{k}')) \
             ELSE value END AS value FROM main.meta;",
            k = META_DIM_ROLLUP_COV
        ),
        "clé dim illisible au pas",
    );
}

#[test]
fn purge_couverture_du_rollup_non_lue_au_pas_refuse() {
    k4c_juger_refus(
        &format!(
            "CREATE TEMP VIEW meta AS SELECT key, CASE WHEN key='{k}' THEN abs(-9223372036854775807 - (key='{k}')) \
             ELSE value END AS value FROM main.meta;",
            k = META_ROLLUP_COV_ID
        ),
        "clé rollup illisible au pas",
    );
}

/// ABSENCE ÉTABLIE (puis valeur mal formée) : rien n'était affirmé sur ces buckets -> comportement d'avant.
#[test]
fn purge_couverture_absente_garde_le_recu_d_avant() {
    let mut voies_jouees = 0;
    for (voie, pose) in [
        ("absente", "DELETE FROM meta WHERE key IN (?1, ?2)"),
        ("mal formée", "UPDATE meta SET value='pas-un-entier' WHERE key IN (?1, ?2)"),
    ] {
        let (c, base) = k4c_base();
        assert_eq!(k4c_rollup_n(&c, base), 5, "{voie} : précondition, rollup peuplé");
        assert_eq!(c.execute(pose, params![META_ROLLUP_COV_ID, META_DIM_ROLLUP_COV]).unwrap(), 2, "{voie} : deux clés");
        let tok = purge_plan(&c, k4c_scope(base)).unwrap().digest().to_string();
        let r = purge_confirm_and_apply(&c, k4c_scope(base), &tok, "t", "raison").unwrap();
        assert_eq!(r.rows_deleted, 3, "{voie} : la purge a lieu");
        assert!(!r.rollup_reaggregated, "{voie} : aucune couverture exploitable -> rien n'est ré-agrégé");
        assert!(purge_receipt_text(&r).contains("aucune couverture publiée"), "{voie} : le reçu le dit");
        let (rl, dl) = k4c_buckets(&c);
        let dans_la_bande = |v: &[String]| v.iter().filter(|l| l.starts_with(&format!("{base}|"))).count();
        assert_eq!((dans_la_bande(&rl), dans_la_bande(&dl)), (0, 0), "{voie} : les buckets de la bande sont supprimés");
        assert_eq!(k4c_registre(&c), 1, "{voie} : la purge est inscrite");
        voies_jouees += 1;
    }
    assert_eq!(voies_jouees, 2, "les deux voies (absente, mal formée) ont été jouées");
}

/// Couverture par dimension SEULE : la lecture locale du format publié par le job s'accorde avec lui.
#[test]
fn purge_couverture_par_dimension_seule_reagrege_les_survivants() {
    let (c, base) = k4c_base();
    assert_eq!(c.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_COV_ID]).unwrap(), 1);
    let at_id = DimRollupCoverage::of(&c).late_floor_id();
    assert!(at_id.is_some(), "précondition : le job a publié une couverture par dimension lisible");
    let tok = purge_plan(&c, k4c_scope(base)).unwrap().digest().to_string();
    let r = purge_confirm_and_apply(&c, k4c_scope(base), &tok, "t", "raison").unwrap();
    assert!(r.rollup_reaggregated, "couverture par dimension publiée -> ré-agrégé");
    assert_eq!(
        (k4c_dim_n(&c, base, "500"), k4c_dim_n(&c, base, "200"), k4c_rollup_n(&c, base)),
        (0, 2, 0),
        "dim : survivants ré-agrégés ; event_rollup sans couverture : supprimé seulement"
    );
}

/// LA BORNE D'IDENTIFIANT RETENUE PAR LA PURGE EST CELLE QUE LA COUVERTURE PUBLIE, pour les DEUX rollups. Une ligne
/// RETARDATAIRE (`id >` la couverture, dans la bande) est servie en BRUT par la route : la ré-agréger la compterait
/// deux fois. Elle survit à la purge, et les deux rollups relus après la purge ne la contiennent pas.
/// MUTATIONS QUI LE FONT ROUGIR : `K4R_ROLLUP_BORNE` (borne d'`event_rollup` sans effet), `K4R_DIM_CHAMP` (le miroir
/// retient `<from>` au lieu de `<at_id>`).
#[test]
fn purge_ne_reagrege_pas_une_retardataire_au_dela_de_la_couverture() {
    let (c, base) = k4c_base();
    let couvert_rollup = RollupCoverage::of(&c).late_floor_id().expect("précondition : couverture event_rollup publiée");
    let couvert_dim = DimRollupCoverage::of(&c).late_floor_id().expect("précondition : couverture dim publiée");
    c.execute(
        "INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id,fields) \
         VALUES(?1,'web','test',1,'preuve','h1','staging','','','{\"status\":\"200\"}')",
        params![base + 7],
    )
    .unwrap();
    let retard = c.last_insert_rowid();
    assert!(retard > couvert_rollup && retard > couvert_dim, "précondition : la ligne est au-delà des deux couvertures");
    assert_eq!(RollupCoverage::of(&c).late_floor_id(), Some(couvert_rollup), "précondition : couverture rollup inchangée");
    assert_eq!(DimRollupCoverage::of(&c).late_floor_id(), Some(couvert_dim), "précondition : couverture dim inchangée");

    let tok = purge_plan(&c, k4c_scope(base)).unwrap().digest().to_string();
    let r = purge_confirm_and_apply(&c, k4c_scope(base), &tok, "t", "raison").unwrap();
    assert_eq!(r.rows_deleted, 3, "seule la cible part");
    assert!(r.rollup_reaggregated, "couvertures publiées -> ré-agrégé");
    assert_eq!(k4c_events(&c), 3, "les deux survivantes couvertes ET la retardataire restent dans `event`");
    assert_eq!(k4c_rollup_n(&c, base), 2, "event_rollup : retardataire hors borne, seules les survivantes couvertes");
    assert_eq!(k4c_dim_n(&c, base, "200"), 2, "event_dim_rollup : retardataire hors borne, seules les survivantes couvertes");
    assert_eq!(k4c_dim_n(&c, base, "500"), 0, "event_dim_rollup : la cible n'y est plus");
}

/// ACCORD DU MIROIR LOCAL AVEC `DimRollupCoverage::of`, jugé par le COMPORTEMENT de la purge (couverture d'`event_rollup`
/// retirée : seul le rollup par dimension décide de `rollup_reaggregated`). Chaque forme que `of` refuse ne ré-agrège
/// rien ; chaque forme qu'`of` accepte ré-agrège jusqu'à SON `at_id`. Les deux sens sont joués, et la précondition
/// `of` est vérifiée forme par forme (sinon le témoin jugerait le miroir contre lui-même).
/// MUTATIONS QUI LE FONT ROUGIR : `K4R_DIM_LEN` (cinq champs acceptés), `K4R_DIM_PARSE` (les trois premiers champs
/// ne sont plus vérifiés), `K4R_DIM_CHAMP` (la forme valide à `<from>` négatif ne ré-agrège plus les survivantes).
#[test]
fn purge_miroir_de_la_couverture_dim_s_accorde_avec_of_dans_les_deux_sens() {
    let (c0, _) = k4c_base();
    let a = DimRollupCoverage::of(&c0).late_floor_id().expect("précondition : couverture dim publiée");
    let (f, b, h) = DimRollupCoverage::of(&c0).band().expect("précondition : bande publiée");
    drop(c0);
    let refusees = [
        format!("{f}|{b}|{h}|{a}|0"),
        format!("{b}|{h}|{a}"),
        format!("x|{b}|{h}|{a}"),
        format!("{f}|y|{h}|{a}"),
        format!("{f}|{b}|z|{a}"),
        format!("{f}|{b}|{h}|w"),
        format!("{a}"),
        String::new(),
    ];
    let acceptees = [format!("{f}|{b}|{h}|{a}"), format!("-1|{b}|{h}|{a}")];
    let mut jouees = 0;
    for (valeur, attendue) in refusees.iter().map(|v| (v, false)).chain(acceptees.iter().map(|v| (v, true))) {
        let (c, base) = k4c_base();
        assert_eq!(c.execute("DELETE FROM meta WHERE key=?1", params![META_ROLLUP_COV_ID]).unwrap(), 1);
        c.execute("UPDATE meta SET value=?2 WHERE key=?1", params![META_DIM_ROLLUP_COV, valeur]).unwrap();
        let of = DimRollupCoverage::of(&c).late_floor_id();
        assert_eq!(of, attendue.then_some(a), "« {valeur} » : précondition, lecture de `of`");
        let tok = purge_plan(&c, k4c_scope(base)).unwrap().digest().to_string();
        let r = purge_confirm_and_apply(&c, k4c_scope(base), &tok, "t", "raison").unwrap();
        assert_eq!(r.rollup_reaggregated, attendue, "« {valeur} » : le miroir décide comme `of`");
        assert_eq!(
            k4c_dim_n(&c, base, "200"),
            if attendue { 2 } else { 0 },
            "« {valeur} » : survivantes ré-agrégées jusqu'à l'`at_id` d'`of`, et seulement si `of` l'accepte"
        );
        jouees += 1;
    }
    assert_eq!(jouees, refusees.len() + acceptees.len(), "toutes les formes ont été jouées");
}

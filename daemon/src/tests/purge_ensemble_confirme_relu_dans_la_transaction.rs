// =====================================================================================
// `P10.32-e` — PURGE : L'ENSEMBLE CONFIRMÉ RELU DANS LA TRANSACTION D'EXÉCUTION, PAS SEULEMENT SON COMPTE.
//
// LE DÉFAUT (relu sur d8239ceb) : dans `purge_delete_rows`, le seul contrôle d'ensemble après le `BEGIN IMMEDIATE`
// était `deleted != proof.rows_declared` (`CountMismatch`). Le jeton lie déjà rows, bornes et somme des `id`,
// bornes de `ts` et ventilation par source, mais `ConfirmedPurge` ne portait que le compte et la ventilation, et
// rien ne relisait la mesure avant le DELETE. Une rétention posée sur N lignes du périmètre (exclues par
// `NOT held`) et N lignes neuves du périmètre validées dans la même fenêtre laissaient `deleted == declared` :
// le DELETE détruisait les lignes neuves, jamais simulées ni confirmées, et le registre décrivait l'ensemble
// confirmé. Les lignes tenues restaient protégées ; c'est la preuve (registre = ce qui est détruit) qui mentait.
//
// CE QUE CES TÉMOINS JUGENT (déterministes, aucun chronomètre ; point d'arrêt = gestionnaire d'occupation du
// `BEGIN IMMEDIATE` de `purge_apply`, une seconde connexion tient le verrou et valide l'écriture pendant que la
// purge attend — instrument de `purge_controles_relus_dans_la_transaction.rs`) :
//  (a) COMPENSATION EXACTE : rétention sur les 3 lignes `flux-a` [1000,1002] ET 3 lignes `flux-a` neuves à
//      ts=1500 (périmètre, hors fenêtre de la rétention) -> même compte, même ventilation, bornes et somme
//      différentes -> refus `stale_token` (jeton confirmé rendu en `got` ; `expected` ÉGAL à l'empreinte
//      `plume-purge/v1` recalculée hors de `purge_digest` sur la mesure que le DELETE aurait atteinte, exigé pour
//      chaque refus `stale_token` de ce fichier), aucune ligne supprimée, aucune inscription au registre ;
//  (b) COMPENSATION À BORNES ÉGALES : identifiants semés avec des trous (10..60), rétention sur la seule ligne 20,
//      ligne neuve d'identifiant 25 (même source, ts dans les bornes) -> seule la somme des `id` diffère -> refus
//      `stale_token` (le mutant « somme omise » ne rougit qu'ici) ;
//  (c) contre-épreuve : la même rétention SANS insertion -> `count_mismatch` (6 déclarées, 3 supprimées), le
//      contrat servi depuis `P10.32-d`, pas `stale_token`. L'énoncé du tri disait « la purge passe » : faux, une
//      rétention qui retire des lignes du périmètre sans compensation fait diverger le compte ;
//  (d) contre-épreuve : insertions HORS périmètre (autre `env_id`, ts hors fenêtre) ou aucune écriture pendant
//      l'attente -> la purge aboutit, reçu à l'empreinte du plan (chemin nominal inchangé), lignes hors périmètre
//      intactes ;
//  (e) relecture non faite (balayage d'interruptions par `progress_handler`) : chacune des deux lectures (balayage
//      agrégé, ligne de la ventilation) est frappée au moins une fois et refuse en `db` en portant SON libellé
//      (un seul libellé par refus ; les frappes nommant l'agrégat précèdent toutes celles nommant la ligne de
//      ventilation, ordre d'exécution de `mesurer_le_perimetre`), rien supprimé, rien inscrit ;
//  (f) (g) (h) (i) (j) UNE COMPOSANTE À LA FOIS, base à identifiants troués, identifiants explicites : compensation
//      qui ne change que la ventilation (f), que la borne basse de `ts` (g), que la borne haute des `id` (h), que la
//      borne basse des `id` (i), que la borne haute de `ts` (j) -> refus `stale_token`, rien supprimé ni inscrit.
//      Avec la somme gardée par (b), chacune des six composantes comparées a son témoin propre. L'ingestion (max+1)
//      ne produit pas ces écritures, sauf celle qui déplace la borne haute des `id` ;
//  (k) la simulation garde ses codes d'avant : sous le balayage d'interruptions de `purge_plan`, la ligne de la
//      ventilation rend `plan_row_unread` sur autant de rangs que (e) en nomme, à un près, et le balayage agrégé `db`.
// MUTATIONS (jouées sous variable de mutation, retirées du source) : `P3_SANS_RELECTURE` (comparaison retirée : a, b
// rouges, les 86 autres témoins de purge et de rétention légale restent verts), `P3_HORS_TX` (mesure prise à l'entrée de `purge_apply`, avant le `BEGIN IMMEDIATE` : a, b rouges),
// `P3_COMPTE_SEUL` (seul le compte comparé : a, b rouges), `P3_SANS_IDSUM` (somme des `id` omise : b rouge seul),
// `P3_LECTURE_AVALEE` (relecture en erreur traitée comme « rien n'a bougé » : e rouge), `P3_SANS_GARDE_DE_COMPTE`
// (refus `stale_token` même à compte différent : c rouge). Reprise après vérification : `M_SANS_VENT_CMP`,
// `M_SANS_TS_CMP`, `M_SANS_BORNES_ID_CMP` (une composante vidée des deux côtés de la comparaison : f, g, h rouges
// respectivement, chacun seul), `M_NOM_ECHANGE` (libellés de l'agrégat et de la ligne de ventilation échangés : e rouge).
// Puis UN SEUL champ masqué à la fois, des deux côtés de la comparaison : `M_SANS_VENT_CMP` (f), `M_SANS_TSLO_CMP`
// (g), `M_SANS_IDHI_CMP` (h), `M_SANS_IDLO_CMP` (i), `M_SANS_TSHI_CMP` (j), `M_SANS_IDSUM_CMP` (b) — chacun ne fait
// rougir que son témoin ; `M_EXPECTED_FAUX` (somme des `id` + 1 dans l'empreinte servie : a, b, f à j rouges) ;
// `M_PLAN_AGREGAT_PRU` (échec de l'agrégat de la simulation rendu en `plan_row_unread` : k rouge).
// CE QUE CE LOT NE TIENT PAS :
//  - le libellé de l'étape « ventilation par source » (préparation et ouverture de la ventilation) n'est épinglé
//    par aucun témoin : `prepare` et la liaison des paramètres n'exécutent aucune instruction de la machine SQLite,
//    le balayage par `progress_handler` ne peut pas l'atteindre ;
//  - l'empreinte est AGRÉGÉE (compte, bornes et somme des `id`, bornes de `ts`, ventilation) : un échange de
//    lignes qui garde tout cela — deux lignes tenues remplacées par deux identifiants de même somme, mêmes bornes,
//    mêmes sources — reste invisible (déjà écrit sur `purge_digest`) ; il suppose des identifiants insérés dans des
//    trous, ce que l'ingestion (`INTEGER PRIMARY KEY`, max+1) ne fait pas, mais rien ne l'interdit ;
//  - pas de code de refus propre : `stale_token` est réutilisé (une variante neuve oblige à éditer le `match`
//    exhaustif de `purge_reponse_de_refus_servie.rs`, hors du périmètre de ce lot) ;
//  - un second balayage du périmètre sous le verrou d'écriture (agrégat + ventilation) : coût proportionnel au
//    périmètre, non mesuré sur une grosse purge ;
//  - déclenchement en production non observé (course étroite), route entière non rejouée ici (même `purge_apply`).
// =====================================================================================

/// (a) Rétention sur `flux-a` [1000,1002] (ids 1..3) et trois lignes `flux-a` neuves à ts=1500 : compensation exacte.
const PEC_COMPENSATION_EXACTE: &str = "\
    INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
      VALUES('litige-flux-a-debut','','flux-a',1000,1002,1,0,'admin'); \
    INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id) \
      VALUES(1500,'flux-a','test',1,'neuve','h1','prod','',''), \
            (1500,'flux-a','test',1,'neuve','h1','prod','',''), \
            (1500,'flux-a','test',1,'neuve','h1','prod','','');";

/// (c) La même rétention, sans insertion.
const PEC_RETENTION_SEULE: &str = "\
    INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
      VALUES('litige-flux-a-debut','','flux-a',1000,1002,1,0,'admin');";

/// (b) Sur la base à identifiants troués : rétention sur la seule ligne 20 (flux-a, ts 1001), ligne neuve id 25.
const PEC_COMPENSATION_A_BORNES_EGALES: &str = "\
    INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
      VALUES('litige-ligne-20','','flux-a',1001,1001,1,0,'admin'); \
    INSERT INTO event(id,ts,source,category,severity,message,host,env_id,origin,engagement_id) \
      VALUES(25,1002,'flux-a','test',1,'neuve','h1','prod','','');";

/// (f) VENTILATION SEULE, sur la base à identifiants troués : rétention `flux-a` [1001,1002] (lignes 20 et 30), lignes
/// neuves 15 et 35 en `flux-b` (ts 1003, 1004) -> compte, bornes et somme des `id`, bornes de `ts` égaux ; seule la
/// ventilation passe de `flux-a:3,flux-b:3` à `flux-a:1,flux-b:5`.
const PEC_VENTILATION_SEULE: &str = "\
    INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
      VALUES('litige-lignes-20-30','','flux-a',1001,1002,1,0,'admin'); \
    INSERT INTO event(id,ts,source,category,severity,message,host,env_id,origin,engagement_id) \
      VALUES(15,1003,'flux-b','test',1,'neuve','h1','prod','',''), \
            (35,1004,'flux-b','test',1,'neuve','h1','prod','','');";

/// (g) BORNES DE `ts` SEULES : même rétention, lignes neuves 15 (`flux-a`, ts 999) et 35 (`flux-a`, ts 1003) -> seule
/// la borne basse de `ts` passe de 1000 à 999.
const PEC_BORNES_TS_SEULES: &str = "\
    INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
      VALUES('litige-lignes-20-30','','flux-a',1001,1002,1,0,'admin'); \
    INSERT INTO event(id,ts,source,category,severity,message,host,env_id,origin,engagement_id) \
      VALUES(15,999,'flux-a','test',1,'neuve','h1','prod','',''), \
            (35,1003,'flux-a','test',1,'neuve','h1','prod','','');";

/// (h) BORNES D'`id` SEULES : rétentions `flux-a` [1001,1001] (ligne 20) et `flux-b` [1005,1005] (ligne 60), lignes
/// neuves 25 (`flux-a`, ts 1005) et 55 (`flux-b`, ts 1001) -> seule la borne haute des `id` passe de 60 à 55.
const PEC_BORNES_ID_SEULES: &str = "\
    INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
      VALUES('litige-ligne-20','','flux-a',1001,1001,1,0,'admin'), \
            ('litige-ligne-60','','flux-b',1005,1005,1,0,'admin'); \
    INSERT INTO event(id,ts,source,category,severity,message,host,env_id,origin,engagement_id) \
      VALUES(25,1005,'flux-a','test',1,'neuve','h1','prod','',''), \
            (55,1001,'flux-b','test',1,'neuve','h1','prod','','');";

/// (i) BORNE BASSE DES `id` SEULE : rétention `flux-a` [1001,1002] (lignes 20 et 30), lignes neuves 5 (`flux-a`, ts
/// 1000) et 45 (`flux-a`, ts 1003) -> seule la borne basse des `id` passe de 10 à 5 (somme 210, ventilation gardée).
const PEC_BORNE_BASSE_ID_SEULE: &str = "\
    INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
      VALUES('litige-lignes-20-30','','flux-a',1001,1002,1,0,'admin'); \
    INSERT INTO event(id,ts,source,category,severity,message,host,env_id,origin,engagement_id) \
      VALUES(5,1000,'flux-a','test',1,'neuve','h1','prod','',''), \
            (45,1003,'flux-a','test',1,'neuve','h1','prod','','');";

/// (j) BORNE HAUTE DE `ts` SEULE : même rétention, lignes neuves 15 (`flux-a`, ts 1006) et 35 (`flux-a`, ts 1003) ->
/// seule la borne haute de `ts` passe de 1005 à 1006.
const PEC_BORNE_HAUTE_TS_SEULE: &str = "\
    INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
      VALUES('litige-lignes-20-30','','flux-a',1001,1002,1,0,'admin'); \
    INSERT INTO event(id,ts,source,category,severity,message,host,env_id,origin,engagement_id) \
      VALUES(15,1006,'flux-a','test',1,'neuve','h1','prod','',''), \
            (35,1003,'flux-a','test',1,'neuve','h1','prod','','');";

/// (d) Insertions hors périmètre : autre environnement, et ts hors fenêtre [0,2000].
const PEC_HORS_PERIMETRE: &str = "\
    INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id) \
      VALUES(1500,'flux-a','test',1,'ailleurs','h1','staging','',''), \
            (5000,'flux-a','test',1,'plus-tard','h1','prod','','');";

/// (d) Aucune écriture : la seconde connexion relâche seulement le verrou.
const PEC_AUCUNE_ECRITURE: &str = "SELECT 1;";

/// Six lignes à identifiants troués 10..60 (flux-a 10,20,30 ; flux-b 40,50,60), ts 1000..1005, périmètre de `pcr_scope`.
fn pec_semer_troue(c: &Connection) {
    for (i, id) in [10_i64, 20, 30, 40, 50, 60].into_iter().enumerate() {
        c.execute(
            "INSERT INTO event(id,ts,source,category,severity,message,host,env_id,origin,engagement_id) \
             VALUES(?1,?2,?3,'test',1,'preuve','h1','prod','','')",
            params![id, 1_000 + i as i64, if i < 3 { "flux-a" } else { "flux-b" }],
        )
        .unwrap();
    }
}

fn pec_ids(c: &Connection) -> Vec<i64> {
    let mut st = c.prepare("SELECT id FROM event WHERE origin='' ORDER BY id").unwrap();
    let ids = st.query_map([], |r| r.get::<_, i64>(0)).unwrap().collect::<Result<Vec<i64>, _>>().unwrap();
    ids
}

/// Mesure (compte, bornes et somme des `id`, bornes de `ts`, ventilation) des lignes que le DELETE de la transaction
/// atteindrait maintenant : périmètre de `pcr_scope` (env `prod`, ts [0,2000]) moins les lignes tenues.
fn pec_mesure_atteinte(c: &Connection) -> (i64, i64, i64, i64, i64, i64, String) {
    let filtre = format!("origin='' AND env_id='prod' AND ts>=0 AND ts<=2000 AND {LEGAL_HOLD_NOT_HELD}");
    let agg = c
        .query_row(
            &format!("SELECT COUNT(*), COALESCE(MIN(id),0), COALESCE(MAX(id),0), COALESCE(SUM(id),0), COALESCE(MIN(ts),0), \
                 COALESCE(MAX(ts),0) FROM event WHERE {filtre}"),
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .unwrap();
    let ventilation: String = c
        .query_row(
            &format!(
                "SELECT COALESCE(group_concat(s || ':' || n, ','),'') FROM (SELECT source s, COUNT(*) n FROM event WHERE {filtre} \
                 GROUP BY source ORDER BY source)"
            ),
            [],
            |r| r.get(0),
        )
        .unwrap();
    (agg.0, agg.1, agg.2, agg.3, agg.4, agg.5, ventilation)
}

/// Plan + confirmation sur une base sans rétention ni tier froid, puis exécution pendant que `sql` est validé par
/// une seconde connexion dans l'attente du `BEGIN IMMEDIATE`. Rend le résultat, le jeton confirmé, les
/// identifiants et le registre d'avant, la mesure confirmée et la connexion de la purge.
#[allow(clippy::type_complexity)]
fn pec_executer_pendant_l_attente_du_verrou(
    tag: &str,
    semer: fn(&Connection),
    sql: &'static str,
) -> (
    Result<PurgeReceipt, PurgeRefusal>,
    String,
    (Vec<i64>, i64),
    (i64, i64, i64, i64, i64, i64, String),
    Connection,
    crate::tmp_possede::TmpDb,
) {
    let p = ff_tmp_path(tag);
    let a = open_db(&p).unwrap();
    a.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
    assert!(migrate(&a), "fixture P10.32-e : migrations complètes");
    semer(&a);
    assert!(!phv_table_presente(&a, "cold_seal"), "{tag} : précondition — aucun tier froid sur cette base");
    assert_eq!(phv_holds_actifs(&a), 0, "{tag} : précondition — aucune rétention au moment du plan");
    let avant = (pec_ids(&a), pcr_registre(&a));
    let mesure_confirmee = pec_mesure_atteinte(&a);
    let (confirme, jeton) = pcr_confirmer(&a);
    let b = open_db(&p).unwrap();
    b.execute_batch("BEGIN IMMEDIATE").unwrap();
    PCR_ECRITURE_CONCURRENTE.with(|x| *x.borrow_mut() = Some((b, sql)));
    a.busy_handler(Some(pcr_valider_l_ecriture_concurrente)).unwrap();
    let r = purge_apply(&a, confirme);
    a.busy_handler(None).unwrap();
    let pas_jouee = PCR_ECRITURE_CONCURRENTE.with(|x| x.borrow_mut().take().is_some());
    assert!(!pas_jouee, "{tag} : instrument — le gestionnaire d'occupation n'a pas été appelé, rien n'a été joué");
    (r, jeton, avant, mesure_confirmee, a, p)
}

/// Empreinte `plume-purge/v1` recalculée ici, hors de `purge_digest`, sur une mesure lue par `pec_mesure_atteinte`
/// et le périmètre canonique de `pcr_scope` : ce que `expected` doit valoir quand la relecture voit cette mesure.
fn pec_empreinte_de(m: &(i64, i64, i64, i64, i64, i64, String)) -> String {
    let (rows, id_lo, id_hi, id_sum, ts_lo, ts_hi, src) = m;
    sha256_hex(
        format!(
            "plume-purge/v1|{}|rows={rows}|id=[{id_lo},{id_hi}]|idsum={id_sum}|ts=[{ts_lo},{ts_hi}]|src={src}",
            pcr_scope().canonical()
        )
        .as_bytes(),
    )
}

/// Refus `stale_token` exigé : le jeton confirmé rendu en `got`, en `expected` l'empreinte de la mesure que le
/// DELETE aurait atteinte (relue après le ROLLBACK, base inchangée), les lignes d'avant ET les lignes neuves toutes
/// présentes, aucune inscription au registre.
fn pec_exiger_la_confirmation_caduque(
    tag: &str,
    r: Result<PurgeReceipt, PurgeRefusal>,
    jeton: &str,
    avant: &(Vec<i64>, i64),
    a: &Connection,
) {
    match &r {
        Err(PurgeRefusal::StaleToken { expected, got }) => {
            assert_eq!(got, jeton, "{tag} : `got` est le jeton confirmé");
            assert_ne!(expected, jeton, "{tag} : `expected` est l'empreinte relue dans la transaction, autre");
            let atteinte = pec_mesure_atteinte(a);
            assert_eq!(
                expected,
                &pec_empreinte_de(&atteinte),
                "{tag} : `expected` est l'empreinte `plume-purge/v1` de la mesure relue {atteinte:?}"
            );
        }
        Err(e) => panic!("{tag} : refus inattendu `{}` : {e}", purge_refusal_code(e)),
        Ok(recu) => panic!(
            "{tag} : l'ensemble supprimé n'est pas celui qui a été confirmé — {} ligne(s) détruite(s) (compte égal au \
             compte inscrit), le registre décrit un autre ensemble",
            recu.rows_deleted
        ),
    }
    let ids = pec_ids(a);
    for id in &avant.0 {
        assert!(ids.contains(id), "{tag} : la ligne {id} d'avant est intacte (rien supprimé) : {ids:?}");
    }
    assert!(ids.len() > avant.0.len(), "{tag} : les lignes neuves sont présentes : {ids:?}");
    assert_eq!(pcr_registre(a), avant.1, "{tag} : aucune inscription au registre (ROLLBACK)");
}

/// (a) COMPENSATION EXACTE : même compte, même ventilation, autre ensemble -> `stale_token`, rien supprimé ni inscrit.
#[test]
fn pec_compensation_exacte_pendant_l_attente_refuse_l_execution() {
    let tag = "pec-compensation-exacte";
    let (r, jeton, avant, confirmee, a, _p) = pec_executer_pendant_l_attente_du_verrou(tag, pcr_semer, PEC_COMPENSATION_EXACTE);
    assert_eq!(phv_holds_actifs(&a), 1, "{tag} : instrument — la rétention est validée et active");
    pec_exiger_la_confirmation_caduque(tag, r, &jeton, &avant, &a);
    // Instrument, lu après le refus (ROLLBACK : la base est celle que le DELETE aurait trouvée).
    let atteinte = pec_mesure_atteinte(&a);
    assert_eq!((atteinte.0, &atteinte.6), (confirmee.0, &confirmee.6), "{tag} : instrument — compensation EXACTE (compte et ventilation égaux)");
    assert_ne!(atteinte, confirmee, "{tag} : instrument — l'ensemble atteint n'est plus celui confirmé");
}

/// (b) COMPENSATION À BORNES ÉGALES : seule la somme des `id` diffère -> `stale_token`.
#[test]
fn pec_compensation_a_bornes_egales_refuse_l_execution() {
    let tag = "pec-bornes-egales";
    let (r, jeton, avant, confirmee, a, _p) =
        pec_executer_pendant_l_attente_du_verrou(tag, pec_semer_troue, PEC_COMPENSATION_A_BORNES_EGALES);
    assert_eq!(phv_holds_actifs(&a), 1, "{tag} : instrument — la rétention est validée et active");
    pec_exiger_la_confirmation_caduque(tag, r, &jeton, &avant, &a);
    // Instrument, lu après le refus (ROLLBACK : la base est celle que le DELETE aurait trouvée).
    let atteinte = pec_mesure_atteinte(&a);
    assert_eq!(
        (atteinte.0, atteinte.1, atteinte.2, atteinte.4, atteinte.5, &atteinte.6),
        (confirmee.0, confirmee.1, confirmee.2, confirmee.4, confirmee.5, &confirmee.6),
        "{tag} : instrument — compte, bornes et ventilation égaux"
    );
    assert_eq!((confirmee.3, atteinte.3), (210, 215), "{tag} : instrument — seule la somme des identifiants diffère");
}

/// (f) (g) (h) UNE COMPOSANTE DE LA MESURE À LA FOIS : sur la base à identifiants troués, la compensation laisse
/// toutes les composantes égales sauf une (ventilation, bornes de `ts`, bornes d'`id`) -> `stale_token`, rien
/// supprimé ni inscrit. Chaque cas est le seul à rougir quand sa composante est retirée de la comparaison.
fn pec_exiger_le_refus_sur_une_seule_composante(
    tag: &str,
    sql: &'static str,
    holds: i64,
    attendue: (i64, i64, i64, i64, i64, i64, &str),
) {
    let (r, jeton, avant, confirmee, a, _p) = pec_executer_pendant_l_attente_du_verrou(tag, pec_semer_troue, sql);
    assert_eq!(phv_holds_actifs(&a), holds, "{tag} : instrument — les rétentions sont validées et actives");
    assert_eq!(
        confirmee,
        (6, 10, 60, 210, 1_000, 1_005, "flux-a:3,flux-b:3".to_string()),
        "{tag} : instrument — mesure confirmée de la base à identifiants troués"
    );
    pec_exiger_la_confirmation_caduque(tag, r, &jeton, &avant, &a);
    // Instrument, lu après le refus (ROLLBACK : la base est celle que le DELETE aurait trouvée).
    let atteinte = pec_mesure_atteinte(&a);
    let attendue = (attendue.0, attendue.1, attendue.2, attendue.3, attendue.4, attendue.5, attendue.6.to_string());
    assert_eq!(atteinte, attendue, "{tag} : instrument — une seule composante diffère de la mesure confirmée");
}

/// (f) Seule la VENTILATION diffère.
#[test]
fn pec_ventilation_seule_refuse_l_execution() {
    pec_exiger_le_refus_sur_une_seule_composante(
        "pec-ventilation-seule",
        PEC_VENTILATION_SEULE,
        1,
        (6, 10, 60, 210, 1_000, 1_005, "flux-a:1,flux-b:5"),
    );
}

/// (g) Seules les BORNES DE `ts` diffèrent.
#[test]
fn pec_bornes_ts_seules_refusent_l_execution() {
    pec_exiger_le_refus_sur_une_seule_composante(
        "pec-bornes-ts-seules",
        PEC_BORNES_TS_SEULES,
        1,
        (6, 10, 60, 210, 999, 1_005, "flux-a:3,flux-b:3"),
    );
}

/// (h) Seules les BORNES D'`id` diffèrent.
#[test]
fn pec_bornes_id_seules_refusent_l_execution() {
    pec_exiger_le_refus_sur_une_seule_composante(
        "pec-bornes-id-seules",
        PEC_BORNES_ID_SEULES,
        2,
        (6, 10, 55, 210, 1_000, 1_005, "flux-a:3,flux-b:3"),
    );
}

/// (i) Seule la BORNE BASSE DES `id` diffère.
#[test]
fn pec_borne_basse_id_seule_refuse_l_execution() {
    pec_exiger_le_refus_sur_une_seule_composante(
        "pec-borne-basse-id-seule",
        PEC_BORNE_BASSE_ID_SEULE,
        1,
        (6, 5, 60, 210, 1_000, 1_005, "flux-a:3,flux-b:3"),
    );
}

/// (j) Seule la BORNE HAUTE DE `ts` diffère.
#[test]
fn pec_borne_haute_ts_seule_refuse_l_execution() {
    pec_exiger_le_refus_sur_une_seule_composante(
        "pec-borne-haute-ts-seule",
        PEC_BORNE_HAUTE_TS_SEULE,
        1,
        (6, 10, 60, 210, 1_000, 1_006, "flux-a:3,flux-b:3"),
    );
}

/// (c) Contre-épreuve : la rétention seule fait diverger le COMPTE -> `count_mismatch` (6 déclarées, 3 supprimées),
/// comme depuis `P10.32-d` ; jamais `stale_token`.
#[test]
fn pec_retention_seule_reste_un_ecart_de_compte() {
    let tag = "pec-retention-seule";
    let (r, _jeton, avant, _confirmee, a, _p) = pec_executer_pendant_l_attente_du_verrou(tag, pcr_semer, PEC_RETENTION_SEULE);
    assert_eq!(phv_holds_actifs(&a), 1, "{tag} : instrument — la rétention est validée et active");
    match &r {
        Err(PurgeRefusal::CountMismatch { declared, deleted }) => {
            assert_eq!((*declared, *deleted), (6, 3), "{tag} : compte inscrit et compte supprimé")
        }
        Err(e) => panic!("{tag} : refus inattendu `{}` : {e}", purge_refusal_code(e)),
        Ok(recu) => panic!("{tag} : {} ligne(s) détruite(s) malgré la rétention", recu.rows_deleted),
    }
    assert_eq!(pec_ids(&a), avant.0, "{tag} : rien supprimé");
    assert_eq!(pcr_registre(&a), avant.1, "{tag} : rien inscrit");
}

/// (d) Contre-épreuves : insertions hors périmètre, aucune écriture -> la purge aboutit, reçu à l'empreinte du plan.
#[test]
fn pec_ecriture_hors_perimetre_laisse_la_purge_aboutir() {
    for (tag, sql, hors_perimetre) in
        [("pec-hors-perimetre", PEC_HORS_PERIMETRE, 2_usize), ("pec-aucune-ecriture", PEC_AUCUNE_ECRITURE, 0)]
    {
        let (r, jeton, avant, _confirmee, a, _p) = pec_executer_pendant_l_attente_du_verrou(tag, pcr_semer, sql);
        let recu = r.unwrap_or_else(|e| {
            panic!("{tag} : refus abusif `{}` d'une écriture qui ne touche pas le périmètre : {e}", purge_refusal_code(&e))
        });
        assert_eq!(recu.rows_deleted, 6, "{tag} : les six lignes du périmètre sont purgées");
        assert_eq!(recu.digest, jeton, "{tag} : reçu à l'empreinte du plan (chemin nominal inchangé)");
        let ids = pec_ids(&a);
        assert_eq!(ids.len(), hors_perimetre, "{tag} : seules les lignes hors périmètre restent : {ids:?}");
        assert!(avant.0.iter().all(|id| !ids.contains(id)), "{tag} : aucune ligne d'avant ne reste");
        assert_eq!(pcr_registre(&a), avant.1 + 1, "{tag} : une inscription au registre");
    }
}

/// (e) RELECTURE NON FAITE : balayage d'interruptions de l'exécution ; les deux lectures de la relecture sont
/// frappées et refusent en `db` en se nommant, rien supprimé ni inscrit.
#[test]
fn pec_relecture_non_faite_refuse_en_la_nommant() {
    let _ = pec_frappes_de_la_relecture();
}

/// (k) SIMULATION, CODES D'AVANT : `purge_plan` lit la même mesure par `mesurer_le_perimetre`, sur la même base et
/// sous le même prédicat que la relecture de (e) : chaque lecture y exécute le même programme. Le
/// balayage d'interruptions de la simulation doit donc rendre `plan_row_unread` (site de la ventilation) sur
/// autant de rangs, à un près, que (e) en a nommés « ligne de la ventilation », et `db` sur les rangs du balayage
/// agrégé qui les précèdent immédiatement — un échec de l'agrégat rendu en `plan_row_unread` (ou une ligne de
/// ventilation rendue en `db`) change ces comptes.
#[test]
fn pec_simulation_garde_ses_codes_de_refus() {
    let (agregat, ventilation) = pec_frappes_de_la_relecture();
    let c = pcr_base();
    let total = pcr_compter_instructions(&c, |c| {
        purge_plan(c, pcr_scope()).expect("plan nominal sous rappel inerte");
    });
    let mut codes = Vec::<(u64, &'static str)>::new();
    let mut rangs_ventilation = Vec::<u64>::new();
    for cible in 1..=total {
        pcr_interrompre_a(&c, cible);
        let r = purge_plan(&c, pcr_scope());
        c.progress_handler(0, None::<fn() -> bool>);
        let Err(e) = r else { continue };
        if let PurgeRefusal::PlanRowUnread { site, .. } = &e {
            if site.contains("ventilation par source") {
                rangs_ventilation.push(cible);
            }
        }
        codes.push((cible, purge_refusal_code(&e)));
    }
    // Écart d'UN rang toléré : mesuré 163 rangs côté simulation pour 164 côté relecture (même instruction, même
    // base) ; un agrégat compté avec la ventilation en ajouterait plus de cent, une ventilation rendue en `db` les
    // retirerait tous.
    assert!(!rangs_ventilation.is_empty(), "simulation : la ligne de la ventilation est frappée : {codes:?}");
    let (premier, dernier) = (rangs_ventilation[0], rangs_ventilation[rangs_ventilation.len() - 1]);
    let voisins: Vec<&(u64, &str)> = codes
        .iter()
        .filter(|(rang, _)| (*rang + 2 >= premier && *rang <= premier) || (*rang >= dernier && *rang <= dernier + 2))
        .collect();
    assert!(
        rangs_ventilation.len().abs_diff(ventilation.len()) <= 1,
        "simulation : `plan_row_unread` (ventilation) sur autant de rangs, à un près, que la ligne de ventilation de la \
         relecture ({} contre {}) — rangs simulation {rangs_ventilation:?}, relecture agrégat {agregat:?}, relecture \
         ventilation {ventilation:?}, codes aux bords {voisins:?}",
        rangs_ventilation.len(),
        ventilation.len()
    );
    let avant: Vec<&(u64, &str)> = codes.iter().filter(|(rang, _)| *rang < premier).collect();
    assert!(avant.len() >= agregat.len(), "simulation : le balayage agrégé précède la ventilation : {codes:?}");
    let agregat_simule = &avant[avant.len() - agregat.len()..];
    assert!(
        agregat_simule.iter().all(|(_, code)| *code == "db"),
        "simulation : un échec du balayage agrégé reste `db` : {agregat_simule:?}"
    );
}

/// Balayage d'interruptions de l'exécution (e) : rend les rangs nommant le balayage agrégé et ceux nommant la ligne de
/// la ventilation, après avoir exigé `db`, rien supprimé ni inscrit, un seul libellé par refus, et l'ordre.
fn pec_frappes_de_la_relecture() -> (Vec<u64>, Vec<u64>) {
    let c = pcr_base();
    let (confirme, _) = pcr_confirmer(&c);
    let total = pcr_compter_instructions(&c, |c| {
        let _ = purge_apply(c, confirme);
    });
    assert!(total > 20, "précondition : l'exécution exécute des instructions ({total})");
    let sites = ["compte, bornes et somme des identifiants", "ligne de la ventilation par source"];
    // Rang d'interruption de chaque frappe, par libellé. `mesurer_le_perimetre` exécute le balayage agrégé AVANT
    // de parcourir la ventilation : chaque lecture porte SON libellé si toutes les frappes nommant l'agrégat
    // précèdent toutes celles nommant la ligne de ventilation (libellés échangés -> ordre inversé, rouge).
    let mut frappes = std::collections::BTreeMap::<&str, Vec<u64>>::new();
    for cible in 1..=total {
        if pcr_events(&c) == 0 {
            pcr_semer(&c);
        }
        let avant = (pcr_events(&c), pcr_registre(&c));
        let (confirme, _) = pcr_confirmer(&c);
        pcr_interrompre_a(&c, cible);
        let r = purge_apply(&c, confirme);
        c.progress_handler(0, None::<fn() -> bool>);
        if !c.is_autocommit() {
            c.execute_batch("ROLLBACK").unwrap();
        }
        let m = r.as_ref().err().map(|e| e.to_string()).unwrap_or_default();
        if !m.contains("ensemble confirmé NON RELU") {
            continue;
        }
        assert_eq!(r.as_ref().err().map(purge_refusal_code), Some("db"), "interruption {cible}/{total} : {m}");
        assert!(m.contains("interrupted"), "la cause du moteur est rendue : {m}");
        assert_eq!((pcr_events(&c), pcr_registre(&c)), avant, "interruption {cible}/{total} : rien supprimé ni inscrit");
        let nommes: Vec<&str> = sites.into_iter().filter(|site| m.contains(site)).collect();
        assert_eq!(nommes.len(), 1, "interruption {cible}/{total} : une et une seule lecture nommée : {m}");
        frappes.entry(nommes[0]).or_default().push(cible);
    }
    assert_eq!(frappes.len(), sites.len(), "chaque lecture de la relecture est frappée et nommée : {frappes:?}");
    let agregat = frappes[sites[0]].clone();
    let ventilation = frappes[sites[1]].clone();
    assert!(
        agregat.iter().max() < ventilation.iter().min(),
        "chaque lecture porte son libellé : le balayage agrégé (exécuté d'abord) est frappé avant la ligne de \
         ventilation — rangs nommant l'agrégat {agregat:?}, rangs nommant la ventilation {ventilation:?}"
    );
    (agregat, ventilation)
}

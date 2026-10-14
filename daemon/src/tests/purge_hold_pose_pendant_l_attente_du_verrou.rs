// =====================================================================================
// `P10.32-d` — PURGE : LA RÉTENTION LÉGALE POSÉE PENDANT L'ATTENTE DU VERROU D'ÉCRITURE ; LE VOLET PLEIN-TEXTE
// JOUÉ SEUL SOUS ATTENTE ; LA ROUTE D'EXÉCUTION ENTIÈRE SOUS ATTENTE.
//
// L'ÉNONCÉ (restes de `P10.32-b`) : « `holds_covering` non relu dans la transaction d'exécution, route entière non
// jouée sous attente du verrou, volet plein-texte du témoin d'attente non rougi seul ».
//
// CE QUI EST FAUX DANS L'ÉNONCÉ : l'absence de `holds_covering` dans la transaction n'est pas un trou de protection.
// `purge_delete_rows` relit `hold_guard` APRÈS l'acquisition du verrou (`BEGIN IMMEDIATE` de `purge_apply`) et le
// prédicat du DELETE porte alors `LEGAL_HOLD_NOT_HELD` : une ligne tenue ne part pas, le compte supprimé diffère du
// compte que le registre vient d'inscrire, `CountMismatch` annule tout (registre compris). Ce qui MANQUAIT est le
// témoin : aucun test ne posait une rétention entre la confirmation et le DELETE (les holds de
// `purge_controles_relus_dans_la_transaction.rs` et de `purge.rs` sont posés AVANT l'appel et refusés par le plan),
// donc `HoldGuard(None)` dans `purge_delete_rows`, ou le fragment `NOT held` retiré, ou la garde lue avant le
// `BEGIN IMMEDIATE`, restaient verts en détruisant des lignes tenues. Preuve par les mutants ci-dessous.
//
// CE QUE CES TÉMOINS JUGENT (déterministes, aucun chronomètre ; point d'arrêt = gestionnaire d'occupation du
// `BEGIN IMMEDIATE`, une seconde connexion tient le verrou et valide l'écriture pendant que la purge attend) :
//  (a) rétention ACTIVE qui recouvre une partie (source `flux-a`, 3 lignes sur 6) ou la totalité (portée globale)
//      du périmètre, validée pendant l'attente, après la confirmation -> refus `count_mismatch` (déclaré 6,
//      supprimé 3 / 0), aucune ligne supprimée, aucune inscription au registre ;
//  (b) contrôle négatif : rétention active dont la portée ne recouvre AUCUNE ligne du périmètre (source absente,
//      fenêtre disjointe) validée au même instant -> la purge aboutit. Différence ÉCRITE et assertée : le plan, lui,
//      refuse la même rétention source-scopée (`holds_covering` est conservateur sans sélecteur `source`) ; la
//      transaction ne relit que ce qui protège une ligne (`NOT held`) ;
//  (c) volet plein-texte SEUL : base sans table `cold_seal`, trigger `event_ad` retiré pendant l'attente ->
//      `fts_desync`, rien supprimé ni inscrit (le mutant « relecture plein-texte placée avant le verrou » rougit
//      ici sans dépendre du cas du tier froid) ;
//  (d) la route `purge_apply_route` ENTIÈRE sous attente : le gestionnaire d'occupation est posé sur la connexion
//      d'écriture que la route verrouille (`req_db` = `st.db` en mode 0), la porte ouverte par l'injection
//      existante `porte_de_purge_de_temoin` (non élargie) ; rétention recouvrante -> 409 `count_mismatch`, rien
//      supprimé ni inscrit ; rétention disjointe -> 200, six lignes purgées.
// MUTATIONS (jouées sous variable de mutation, retirées du source) : `O2_HOLD_NONE` (`HoldGuard(None)` dans
// `purge_delete_rows`), `O2_HOLD_HORS_TX` (garde lue à l'entrée de `purge_apply`, avant le `BEGIN IMMEDIATE`),
// `O2_SANS_NOT_HELD` (fragment legal-hold omis par `scope_predicate`), `O2_SANS_FTS` (relecture plein-texte retirée
// de `relire_tier_froid_et_index`), `O2_FTS_HORS_TX` (relecture plein-texte seule déplacée avant le verrou).
// CE QUE CE LOT NE TIENT PAS :
//  - `CountMismatch` compare un COMPTE : des lignes neuves du périmètre validées dans la même fenêtre en nombre égal
//    aux lignes tenues laisseraient le compte juste (les lignes tenues restent protégées par `NOT held`, mais le
//    registre décrirait un ensemble différent de celui du plan) — non mesuré, hors de cette clé ;
//  - déclenchement en production non observé (course étroite).
// =====================================================================================

const PHV_HOLD_FLUX_A: &str = "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
     VALUES('litige-flux-a','','flux-a',0,0,1,0,'admin')";
const PHV_HOLD_GLOBAL: &str = "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
     VALUES('litige-global','','',0,0,1,0,'admin')";
const PHV_HOLD_SOURCE_ABSENTE: &str = "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
     VALUES('litige-flux-z','','flux-z',0,0,1,0,'admin')";
const PHV_HOLD_FENETRE_DISJOINTE: &str = "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
     VALUES('litige-plus-tard','','',5000,6000,1,0,'admin')";

fn phv_base_fichier(tag: &str) -> (Connection, crate::tmp_possede::TmpDb) {
    let p = ff_tmp_path(tag);
    let a = open_db(&p).unwrap();
    a.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
    assert!(migrate(&a), "fixture P10.32-d : migrations complètes");
    pcr_semer(&a);
    (a, p)
}

fn phv_table_presente(c: &Connection, nom: &str) -> bool {
    c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1", params![nom], |r| r.get::<_, i64>(0))
        .unwrap()
        > 0
}

fn phv_holds_actifs(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM legal_hold WHERE active=1", [], |r| r.get(0)).unwrap()
}

/// Plan + confirmation sur une base sans rétention, puis exécution pendant que `sql` est validé par une seconde
/// connexion dans l'attente du `BEGIN IMMEDIATE`. Aucune table `cold_seal` : le tier froid n'intervient pas.
fn phv_executer_pendant_l_attente_du_verrou(
    tag: &str,
    sql: &'static str,
) -> (Result<PurgeReceipt, PurgeRefusal>, (i64, i64), Connection, crate::tmp_possede::TmpDb) {
    let (a, p) = phv_base_fichier(tag);
    assert!(!phv_table_presente(&a, "cold_seal"), "{tag} : précondition — aucun tier froid sur cette base");
    assert_eq!(phv_holds_actifs(&a), 0, "{tag} : précondition — aucune rétention au moment du plan");
    let avant = (pcr_events(&a), pcr_registre(&a));
    let (confirme, _) = pcr_confirmer(&a);
    let b = open_db(&p).unwrap();
    b.execute_batch("BEGIN IMMEDIATE").unwrap();
    PCR_ECRITURE_CONCURRENTE.with(|x| *x.borrow_mut() = Some((b, sql)));
    a.busy_handler(Some(pcr_valider_l_ecriture_concurrente)).unwrap();
    let r = purge_apply(&a, confirme);
    a.busy_handler(None).unwrap();
    let pas_jouee = PCR_ECRITURE_CONCURRENTE.with(|x| x.borrow_mut().take().is_some());
    assert!(!pas_jouee, "{tag} : instrument — le gestionnaire d'occupation n'a pas été appelé, rien n'a été joué");
    (r, avant, a, p)
}

/// (a) Rétention recouvrante validée pendant l'attente du verrou, après la confirmation : `count_mismatch`, les
/// lignes tenues ET les autres restent, rien n'est inscrit au registre.
#[test]
fn phv_retention_recouvrante_posee_pendant_l_attente_refuse_l_execution() {
    for (tag, sql, supprime_attendu) in
        [("phv-hold-partiel", PHV_HOLD_FLUX_A, 3), ("phv-hold-global", PHV_HOLD_GLOBAL, 0)]
    {
        let (r, avant, a, _p) = phv_executer_pendant_l_attente_du_verrou(tag, sql);
        assert_eq!(phv_holds_actifs(&a), 1, "{tag} : instrument — la rétention est validée et active");
        match &r {
            Err(PurgeRefusal::CountMismatch { declared, deleted }) => assert_eq!(
                (*declared, *deleted),
                (avant.0, supprime_attendu),
                "{tag} : le DELETE de la transaction a épargné les lignes tenues, et seulement elles"
            ),
            Err(e) => panic!("{tag} : refus inattendu `{}` : {e}", purge_refusal_code(e)),
            Ok(recu) => panic!(
                "{tag} : la rétention validée pendant l'attente n'a pas été relue — {} ligne(s) détruite(s), dont des \
                 lignes tenues",
                recu.rows_deleted
            ),
        }
        pcr_exiger_le_refus(&a, r, "count_mismatch", avant, tag);
        let tenues: i64 = a
            .query_row("SELECT COUNT(*) FROM event WHERE origin='' AND source='flux-a'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(tenues, 3, "{tag} : les lignes de `flux-a` sont intactes");
    }
}

/// (b) Contrôle négatif : une rétention active qui ne recouvre AUCUNE ligne du périmètre, validée au même instant,
/// ne refuse pas l'exécution. Le plan, lui, refuse la rétention source-scopée (conservateur) : différence assertée.
#[test]
fn phv_retention_disjointe_posee_pendant_l_attente_laisse_la_purge_aboutir() {
    for (tag, sql) in
        [("phv-hold-source-absente", PHV_HOLD_SOURCE_ABSENTE), ("phv-hold-fenetre-disjointe", PHV_HOLD_FENETRE_DISJOINTE)]
    {
        let (r, avant, a, _p) = phv_executer_pendant_l_attente_du_verrou(tag, sql);
        assert_eq!(phv_holds_actifs(&a), 1, "{tag} : instrument — la rétention est validée et active");
        let recu = r.unwrap_or_else(|e| {
            panic!("{tag} : refus abusif `{}` d'une rétention qui ne tient aucune ligne : {e}", purge_refusal_code(&e))
        });
        assert_eq!(recu.rows_deleted, avant.0, "{tag} : tout le périmètre est purgé");
        assert_eq!(pcr_events(&a), 0, "{tag} : events purgés");
        assert_eq!(pcr_registre(&a), avant.1 + 1, "{tag} : une inscription au registre");

        // Le plan relit `holds_covering`, conservateur : sans sélecteur `source`, toute rétention source-scopée
        // recouvre. La transaction d'exécution n'en hérite pas, c'est voulu (elle ne relit que `NOT held`).
        pcr_semer(&a);
        let plan = purge_plan(&a, pcr_scope());
        if sql == PHV_HOLD_SOURCE_ABSENTE {
            match plan {
                Err(PurgeRefusal::LegalHold(noms)) => assert_eq!(noms, vec!["litige-flux-z".to_string()], "{tag}"),
                Err(e) => panic!("{tag} : le plan devait refuser `legal_hold`, il rend `{e}`"),
                Ok(_) => panic!("{tag} : le plan devait refuser la rétention source-scopée (holds_covering)"),
            }
        } else {
            assert!(plan.is_ok(), "{tag} : fenêtre disjointe — le plan ne refuse pas non plus : {:?}", plan.err());
        }
    }
}

/// (c) Volet plein-texte SEUL sous attente du verrou : aucune table `cold_seal`, le trigger `event_ad` retiré
/// pendant l'attente -> `fts_desync`, l'index et les lignes restent d'accord.
#[test]
fn phv_trigger_plein_texte_retire_pendant_l_attente_seul_refuse_l_execution() {
    let (r, avant, a, _p) = phv_executer_pendant_l_attente_du_verrou("phv-fts-seul", "DROP TRIGGER event_ad");
    let trigger: i64 = a
        .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='event_ad'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(trigger, 0, "instrument — le trigger a bien été retiré pendant l'attente");
    pcr_exiger_le_refus(&a, r, "fts_desync", avant, "trigger retiré pendant l'attente, sans tier froid");
    let postings: i64 =
        a.query_row("SELECT COUNT(*) FROM event_fts WHERE event_fts MATCH 'preuve'", [], |r| r.get(0)).unwrap();
    assert_eq!(postings, 6, "l'index plein-texte et les lignes restent d'accord");
}

/// (d) La ROUTE d'exécution entière sous attente du verrou : re-simulation de la route (aucune rétention), puis la
/// rétention validée pendant que son `BEGIN IMMEDIATE` attend.
async fn phv_route_pendant_l_attente(tag: &str, sql: &'static str) -> (u16, Value, AppState, crate::tmp_possede::TmpDb) {
    let (st, p) = pcr_etat(tag);
    let au = pcr_admin();
    let (s, plan) = pcr_plan(&st, &au).await;
    assert_eq!(s, 200, "{tag} : plan servi sans rétention : {plan}");
    let jeton = plan["token"].as_str().expect("jeton servi").to_string();
    let b = open_db(&p).unwrap();
    b.execute_batch("BEGIN IMMEDIATE").unwrap();
    PCR_ECRITURE_CONCURRENTE.with(|x| *x.borrow_mut() = Some((b, sql)));
    with_write(&st, &au, |c| c.busy_handler(Some(pcr_valider_l_ecriture_concurrente)).unwrap());
    let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
    with_write(&st, &au, |c| c.busy_timeout(std::time::Duration::from_secs(5)).unwrap());
    let pas_jouee = PCR_ECRITURE_CONCURRENTE.with(|x| x.borrow_mut().take().is_some());
    assert!(!pas_jouee, "{tag} : instrument — le gestionnaire d'occupation de la route n'a pas été appelé");
    assert_eq!(with_write(&st, &au, |c| phv_holds_actifs(c)), 1, "{tag} : instrument — rétention validée");
    (statut, corps, st, p)
}

#[tokio::test]
async fn phv_route_entiere_sous_attente_du_verrou_relit_la_retention() {
    let _ouverte = porte_de_purge_de_temoin::ouvrir();
    let au = pcr_admin();

    let (s, c, st, _p) = phv_route_pendant_l_attente("phv-route-hold", PHV_HOLD_FLUX_A).await;
    pcr_juger_refus(s, &c, "count_mismatch", "route, rétention recouvrante validée pendant l'attente");
    assert_eq!(pcr_events_servis(&st, &au), 6, "route : rien supprimé");
    assert_eq!(with_write(&st, &au, |c| pcr_registre(c)), 0, "route : rien inscrit au registre");

    let (s, c, st, _p) = phv_route_pendant_l_attente("phv-route-disjointe", PHV_HOLD_FENETRE_DISJOINTE).await;
    assert_eq!(s, 200, "route, contrôle négatif : rétention disjointe -> la purge aboutit : {c}");
    assert_eq!(pcr_events_servis(&st, &au), 0, "route, contrôle négatif : six lignes purgées");
    assert_eq!(with_write(&st, &au, |c| pcr_registre(c)), 1, "route, contrôle négatif : une inscription");
}

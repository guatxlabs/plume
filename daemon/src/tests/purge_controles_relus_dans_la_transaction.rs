// =====================================================================================
// `P10.32-b` — PURGE : LE TIER FROID ET L'INDEX PLEIN-TEXTE RELUS DANS LA TRANSACTION D'EXÉCUTION ; LES DEUX
// ROUTES JOUÉES ENTIÈRES, SURFACE OUVERTE SUR LE SEUL FIL DU TÉMOIN.
//
// LE DÉFAUT (relu sur b96a8c7b) : `cold_overlap` et `fts_delete_trigger_ok` n'étaient appelés que par
// `purge_plan`. `purge_delete_rows` relisait la rétention légale et les citations, pas les sceaux du tier froid
// ni le trigger `event_ad`. Le jeton ne couvre que le périmètre et ses comptes : un sceau `cold_seal` posé, ou
// le trigger retiré, entre la simulation et le `BEGIN IMMEDIATE` ne changeait pas l'empreinte — la confirmation
// passait et le DELETE détruisait le chaud pendant que les Parquet scellés restaient lisibles, ou laissait les
// postings plein-texte du message purgé. Second volet : les deux routes n'étaient jugées servir
// `purge_refusal_response` que par lecture du source (le mutant `ROUTE_PLAN_CONTOURNE` de la vague M est resté
// vert), faute de pouvoir armer `PLUME_PURGE_API` sans troubler `purge_http_surface_is_closed_by_default`.
//
// CE QUE CES TÉMOINS JUGENT (déterministes, aucun chronomètre) :
//  - plan, confirmation, PUIS sceau recouvrant posé (ou trigger `event_ad` retiré), PUIS exécution : refus
//    `cold_tier` (`fts_desync`), events intacts, aucune inscription au registre ; contrôles négatifs : sceau hors
//    fenêtre, trigger présent -> la purge aboutit, reçu à l'empreinte du plan ;
//  - la relecture PRÉCÈDE le DELETE : une sonde `BEFORE DELETE` qui avorte n'est jamais atteinte quand le motif
//    est posé (le refus reste `cold_tier` / `fts_desync`), et elle l'est sans motif (instrument vivant) ;
//  - lecture non faite dans la transaction (présence de `cold_seal` / d'`event_fts` interrompue par l'instrument
//    `temoin_de_presence`) : refus `db` nommant la table et la cause, rien supprimé, rien inscrit ;
//  - balayage d'interruptions (`progress_handler`) de l'exécution, motif posé après la confirmation : aucune
//    exécution n'aboutit, et des passages frappent chacune des lectures (présence, index `cold_seal`, trigger) ;
//  - la relecture est faite APRÈS l'acquisition du verrou d'écriture : une seconde connexion tient
//    `BEGIN IMMEDIATE`, le gestionnaire d'occupation de la purge lui fait valider le motif pendant que la purge
//    attend le verrou -> refus `cold_tier` / `fts_desync` ; écriture neutre au même instant -> la purge aboutit ;
//  - les deux routes ENTIÈRES (`purge_plan_route`, `purge_apply_route`) avec la porte ouverte par le point
//    d'injection `porte_de_purge_de_temoin` (cfg(test), fil courant, l'environnement n'est pas touché) : 500
//    pour `plan_row_unread`, `legal_hold_undetermined`, `legal_hold_unread` (et `db`), 409 pour `legal_hold`,
//    `cold_tier`, `fts_desync`, `cited_by_case` (deux routes) et `stale_token`, 400 pour `reason_required`
//    (exécution), statut ET corps ; sans l'injection, 403 ; porte ouverte, un compte `editor` / `viewer` reçoit
//    le 403 du re-contrôle de rôle de chaque handler.
// MUTATIONS (jouées sous variable de mutation, retirées du source) : `N4_SANS_COLD`, `N4_SANS_FTS` (une relecture retirée),
// `N4_COLD_AVALE` (lecture non faite du tier froid avalée), `N4_FTS_AVALE` / `N4_FTS_FALSE`
// (`fts_delete_trigger_ok(..).unwrap_or(true|false)`), `N4_APRES_DELETE` (relecture placée après le DELETE),
// `N4_ROUTE_PLAN` (bras qui sert `plan_row_unread` en 409 avant la fabrique, sans le mot `CONFLICT`),
// `N4_ROUTE_APPLY` (`legal_hold_undetermined` en 409), `N4_ROUTE_COLD` (`cold_tier` en 500) ; reprise après
// vérification : `VM20` / `VM21` (plan : `fts_desync` / `cited_by_case` servis en 500 par un bras du corps de
// route), `VM22` / `VM23` (même chose sur l'exécution), `VM24` (`reason_required` en 409), `VM27` / `VM27P`
// (re-contrôle `au.is_admin()` sauté sur l'exécution / le plan) ; seconde reprise : `N4_HORS_TX` (relecture
// déplacée à l'entrée de `purge_apply`, avant le `BEGIN IMMEDIATE` : les témoins qui posent le motif avant
// l'appel restent verts, seul le témoin d'attente du verrou rougit).
// CE QUE CE LOT NE TIENT PAS :
//  - la fenêtre entre la re-simulation de `purge_confirm_and_apply` et l'acquisition du verrou est jouée sur
//    `purge_apply` (point d'arrêt déterministe : le gestionnaire d'occupation du `BEGIN IMMEDIATE`), pas par la
//    route entière (la connexion du pool n'y reçoit pas ce gestionnaire) ; la route appelle le même `purge_apply` ;
//  - `holds_covering` n'est pas relu dans la transaction (la garde `NOT held` + `CountMismatch` y tient lieu) ;
//  - déclenchement en production non observé (course étroite, destruction sans retour).
// =====================================================================================

fn pcr_ins(c: &Connection, ts: i64, source: &str) {
    c.execute(
        "INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id) \
         VALUES(?1,?2,'test',1,'preuve','h1','prod','','')",
        params![ts, source],
    )
    .unwrap();
}

fn pcr_semer(c: &Connection) {
    for i in 0..6 {
        pcr_ins(c, 1_000 + i, if i < 3 { "flux-a" } else { "flux-b" });
    }
}

fn pcr_scope() -> PurgeScope {
    let v = vec![("env".to_string(), "prod".to_string())];
    purge_scope_from_args(&v, "0", "2000", now()).expect("périmètre valide")
}

fn pcr_base() -> Connection {
    let c = test_db();
    pcr_semer(&c);
    c
}

fn pcr_events(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM event WHERE origin=''", [], |r| r.get(0)).unwrap()
}

fn pcr_registre(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![PURGE_LEDGER_KIND], |r| r.get(0)).unwrap()
}

/// Simulation puis confirmation au jeton du plan : rend l'exécution prête et le jeton.
fn pcr_confirmer(c: &Connection) -> (ConfirmedPurge, String) {
    let plan = purge_plan(c, pcr_scope()).expect("plan nominal : aucun motif de refus au moment de la simulation");
    let jeton = plan.digest().to_string();
    (plan.confirm(&jeton, "t", "témoin P10.32-b").expect("confirmation au jeton du plan"), jeton)
}

fn pcr_creer_cold_seal(c: &Connection) {
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS cold_seal(env_id TEXT NOT NULL, day INTEGER NOT NULL, seq INTEGER NOT NULL, \
           expected_rows INTEGER NOT NULL, sealed_ts INTEGER NOT NULL, purged INTEGER NOT NULL DEFAULT 0, \
           max_id INTEGER NOT NULL, ts_min INTEGER NOT NULL, ts_max INTEGER NOT NULL, lo_ts INTEGER NOT NULL, \
           lo_id INTEGER NOT NULL, hi_id INTEGER NOT NULL, last_file INTEGER NOT NULL DEFAULT 0, \
           PRIMARY KEY(env_id,day,seq))",
    )
    .unwrap();
}

/// Un fichier scellé sur `[ts_min, ts_max]` (jour `day`).
fn pcr_sceller(c: &Connection, day: i64, ts_min: i64, ts_max: i64) {
    pcr_creer_cold_seal(c);
    c.execute(
        "INSERT INTO cold_seal VALUES('prod',?1,0,6,0,1,99,?2,?3,?2,1,99,1)",
        params![day, ts_min, ts_max],
    )
    .unwrap();
}

/// Sonde : tout DELETE sur `event` avorte en se nommant. Prouve que le refus est rendu AVANT le DELETE.
fn pcr_poser_la_sonde(c: &Connection) {
    c.execute_batch(
        "CREATE TRIGGER pcr_sonde_delete BEFORE DELETE ON event BEGIN \
           SELECT RAISE(ABORT, 'sonde P10.32-b : DELETE atteint'); END",
    )
    .unwrap();
}

fn pcr_retirer_la_sonde(c: &Connection) {
    c.execute_batch("DROP TRIGGER pcr_sonde_delete").unwrap();
}

fn pcr_ddl_du_trigger_fts(c: &Connection) -> String {
    c.query_row("SELECT sql FROM sqlite_master WHERE type='trigger' AND name='event_ad'", [], |r| r.get(0))
        .expect("le schéma pose le trigger `event_ad`")
}

fn pcr_compter_instructions(c: &Connection, f: impl FnOnce(&Connection)) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    let compte = std::sync::Arc::new(AtomicU64::new(0));
    let k = compte.clone();
    c.progress_handler(
        1,
        Some(move || {
            k.fetch_add(1, Ordering::Relaxed);
            false
        }),
    );
    f(c);
    c.progress_handler(0, None::<fn() -> bool>);
    compte.load(Ordering::Relaxed)
}

fn pcr_interrompre_a(c: &Connection, cible: u64) {
    use std::sync::atomic::{AtomicU64, Ordering};
    let n = AtomicU64::new(0);
    c.progress_handler(1, Some(move || n.fetch_add(1, Ordering::Relaxed) + 1 == cible));
}

/// Exige un refus de code `code`, rien supprimé, rien inscrit.
fn pcr_exiger_le_refus(c: &Connection, r: Result<PurgeReceipt, PurgeRefusal>, code: &str, avant: (i64, i64), quoi: &str) {
    match r {
        Ok(recu) => panic!(
            "{quoi} : l'exécution a détruit {} ligne(s) (reçu {}) — la transaction n'a pas relu le contrôle",
            recu.rows_deleted, recu.digest
        ),
        Err(e) => assert_eq!(purge_refusal_code(&e), code, "{quoi} : refus `{e}`"),
    }
    assert_eq!(pcr_events(c), avant.0, "{quoi} : aucune ligne supprimée");
    assert_eq!(pcr_registre(c), avant.1, "{quoi} : aucune inscription au registre (ROLLBACK)");
}

/// Balayage : exige un refus (quel qu'il soit), rien supprimé, rien inscrit. Une interruption qui tombe sur le
/// `ROLLBACK` de l'appelant le laisse ouvert : il est refermé ICI (hors de ce que ce lot juge) avant de compter.
fn pcr_exiger_un_refus(c: &Connection, r: &Result<PurgeReceipt, PurgeRefusal>, avant: (i64, i64), quoi: &str) {
    if let Ok(recu) = r {
        panic!("{quoi} : l'exécution a détruit {} ligne(s) — un contrôle a été sauté", recu.rows_deleted);
    }
    if !c.is_autocommit() {
        c.execute_batch("ROLLBACK").unwrap();
    }
    assert_eq!(pcr_events(c), avant.0, "{quoi} : aucune ligne supprimée");
    assert_eq!(pcr_registre(c), avant.1, "{quoi} : aucune inscription au registre");
}

/// TIER FROID : un sceau recouvrant posé APRÈS la confirmation refuse l'exécution (`cold_tier`), avant le DELETE ;
/// un sceau hors fenêtre ne refuse rien et la purge aboutit au jeton du plan.
#[test]
fn pcr_sceau_pose_apres_la_confirmation_refuse_l_execution() {
    let c = pcr_base();
    let avant = (pcr_events(&c), pcr_registre(&c));

    let (confirme, _) = pcr_confirmer(&c);
    pcr_sceller(&c, 1, 1_000, 1_005);
    pcr_exiger_le_refus(&c, purge_apply(&c, confirme), "cold_tier", avant, "sceau posé après la confirmation");

    // AVANT LE DELETE : sonde posée, le refus reste celui du tier froid (le DELETE n'est pas atteint).
    c.execute("DELETE FROM cold_seal", []).unwrap();
    let (confirme, _) = pcr_confirmer(&c);
    pcr_sceller(&c, 1, 1_000, 1_005);
    pcr_poser_la_sonde(&c);
    pcr_exiger_le_refus(&c, purge_apply(&c, confirme), "cold_tier", avant, "sceau posé, sonde DELETE armée");

    // Instrument vivant : sans sceau, la sonde est atteinte (le DELETE suit bien les contrôles).
    c.execute("DELETE FROM cold_seal", []).unwrap();
    let (confirme, _) = pcr_confirmer(&c);
    match purge_apply(&c, confirme) {
        Ok(r) => panic!("instrument : la sonde n'a pas avorté le DELETE ({} lignes)", r.rows_deleted),
        Err(e) => assert!(e.to_string().contains("sonde P10.32-b"), "instrument : la sonde est atteinte : {e}"),
    }
    pcr_retirer_la_sonde(&c);
    assert_eq!(pcr_events(&c), avant.0, "instrument : rien supprimé");

    // Contrôle négatif : un sceau HORS fenêtre ne refuse rien ; reçu à l'empreinte du plan.
    let (confirme, jeton) = pcr_confirmer(&c);
    pcr_sceller(&c, 5, 5_000, 6_000);
    let recu = purge_apply(&c, confirme).expect("sceau hors fenêtre : la purge aboutit");
    assert_eq!((recu.rows_deleted, recu.digest.as_str()), (6, jeton.as_str()), "chemin nominal : 6 lignes, jeton du plan");
    assert_eq!(pcr_events(&c), 0, "les six lignes du périmètre sont parties");
    assert_eq!(pcr_registre(&c), avant.1 + 1, "une inscription au registre");
}

/// INDEX PLEIN-TEXTE : le trigger `event_ad` retiré APRÈS la confirmation refuse l'exécution (`fts_desync`), avant
/// le DELETE ; trigger remis, la purge aboutit.
#[test]
fn pcr_trigger_retire_apres_la_confirmation_refuse_l_execution() {
    let c = pcr_base();
    let ddl = pcr_ddl_du_trigger_fts(&c);
    let avant = (pcr_events(&c), pcr_registre(&c));

    let (confirme, _) = pcr_confirmer(&c);
    c.execute_batch("DROP TRIGGER event_ad").unwrap();
    pcr_exiger_le_refus(&c, purge_apply(&c, confirme), "fts_desync", avant, "trigger retiré après la confirmation");
    let postings: i64 =
        c.query_row("SELECT COUNT(*) FROM event_fts WHERE event_fts MATCH 'preuve'", [], |r| r.get(0)).unwrap();
    assert_eq!(postings, 6, "l'index plein-texte et les lignes restent d'accord");

    c.execute_batch(&ddl).unwrap();
    let (confirme, _) = pcr_confirmer(&c);
    c.execute_batch("DROP TRIGGER event_ad").unwrap();
    pcr_poser_la_sonde(&c);
    pcr_exiger_le_refus(&c, purge_apply(&c, confirme), "fts_desync", avant, "trigger retiré, sonde DELETE armée");
    pcr_retirer_la_sonde(&c);

    c.execute_batch(&ddl).unwrap();
    let (confirme, jeton) = pcr_confirmer(&c);
    let recu = purge_apply(&c, confirme).expect("trigger présent : la purge aboutit");
    assert_eq!((recu.rows_deleted, recu.digest.as_str()), (6, jeton.as_str()), "chemin nominal");
    let postings: i64 =
        c.query_row("SELECT COUNT(*) FROM event_fts WHERE event_fts MATCH 'preuve'", [], |r| r.get(0)).unwrap();
    assert_eq!(postings, 0, "le trigger a retiré les postings du message purgé");
}

/// LECTURE NON FAITE DANS LA TRANSACTION : présence de `cold_seal`, puis d'`event_fts`, interrompue au moment de
/// l'exécution (la simulation, elle, l'a lue) -> refus `db` nommant la table et la cause, rien supprimé.
#[test]
fn pcr_presence_non_lue_dans_la_transaction_refuse_db() {
    let c = pcr_base();
    pcr_sceller(&c, 5, 5_000, 6_000); // table présente, rien ne recouvre : seule la lecture peut refuser
    let avant = (pcr_events(&c), pcr_registre(&c));

    for table in ["cold_seal", "event_fts"] {
        let (confirme, _) = pcr_confirmer(&c);
        crate::governance::temoin_de_presence::armer(table);
        let r = purge_apply(&c, confirme);
        crate::governance::temoin_de_presence::desarmer();
        let m = r.as_ref().err().map(|e| e.to_string()).unwrap_or_default();
        pcr_exiger_le_refus(&c, r, "db", avant, &format!("présence de `{table}` non lue à l'exécution"));
        assert!(
            m.contains(&format!("`{table}`")) && m.contains("interrupted"),
            "le refus nomme la table et la cause : {m}"
        );
    }
}

/// BALAYAGE : une interruption à chaque instruction de l'exécution, motif posé après la confirmation (sceau
/// recouvrant, puis trigger retiré). Aucune exécution n'aboutit ; chaque lecture du contrôle est frappée au moins
/// une fois et refuse en `db` en la nommant.
#[test]
fn pcr_aucune_interruption_dans_la_transaction_ne_saute_les_controles() {
    // Tier froid.
    let c = pcr_base();
    let avant = (pcr_events(&c), pcr_registre(&c));
    let poser = |c: &Connection| pcr_sceller(c, 1, 1_000, 1_005);
    let lever = |c: &Connection| {
        c.execute("DELETE FROM cold_seal", []).unwrap();
    };
    pcr_creer_cold_seal(&c);
    let (confirme, _) = pcr_confirmer(&c);
    poser(&c);
    let total = pcr_compter_instructions(&c, |c| {
        let _ = purge_apply(c, confirme);
    });
    lever(&c);
    assert!(total > 20, "précondition : l'exécution exécute des instructions ({total})");
    let mut frappes = std::collections::BTreeMap::<&str, u64>::new();
    for cible in 1..=total {
        let (confirme, _) = pcr_confirmer(&c);
        poser(&c);
        pcr_interrompre_a(&c, cible);
        let r = purge_apply(&c, confirme);
        c.progress_handler(0, None::<fn() -> bool>);
        if !c.is_autocommit() {
            c.execute_batch("ROLLBACK").unwrap();
        }
        lever(&c);
        let m = r.as_ref().err().map(|e| e.to_string()).unwrap_or_default();
        pcr_exiger_un_refus(&c, &r, avant, &format!("interruption {cible}/{total}"));
        for site in ["présence de la table `cold_seal`", "index cold_seal illisible"] {
            if m.contains(site) {
                assert_eq!(r.as_ref().err().map(purge_refusal_code), Some("db"), "{m}");
                assert!(m.contains("interrupted"), "la cause du moteur est rendue : {m}");
                *frappes.entry(site).or_default() += 1;
            }
        }
    }
    assert_eq!(frappes.len(), 2, "chaque lecture du tier froid est frappée et nommée : {frappes:?}");

    // Index plein-texte.
    let c = pcr_base();
    let ddl = pcr_ddl_du_trigger_fts(&c);
    let avant = (pcr_events(&c), pcr_registre(&c));
    let (confirme, _) = pcr_confirmer(&c);
    c.execute_batch("DROP TRIGGER event_ad").unwrap();
    let total = pcr_compter_instructions(&c, |c| {
        let _ = purge_apply(c, confirme);
    });
    c.execute_batch(&ddl).unwrap();
    let mut frappes = std::collections::BTreeMap::<&str, u64>::new();
    for cible in 1..=total {
        let (confirme, _) = pcr_confirmer(&c);
        c.execute_batch("DROP TRIGGER event_ad").unwrap();
        pcr_interrompre_a(&c, cible);
        let r = purge_apply(&c, confirme);
        c.progress_handler(0, None::<fn() -> bool>);
        if !c.is_autocommit() {
            c.execute_batch("ROLLBACK").unwrap();
        }
        c.execute_batch(&ddl).unwrap();
        let m = r.as_ref().err().map(|e| e.to_string()).unwrap_or_default();
        pcr_exiger_un_refus(&c, &r, avant, &format!("interruption {cible}/{total}"));
        for site in ["présence de la table `event_fts`", "trigger `event_ad` NON LUE"] {
            if m.contains(site) {
                assert_eq!(r.as_ref().err().map(purge_refusal_code), Some("db"), "{m}");
                assert!(m.contains("interrupted"), "la cause du moteur est rendue : {m}");
                *frappes.entry(site).or_default() += 1;
            }
        }
    }
    assert_eq!(frappes.len(), 2, "chaque lecture de l'index plein-texte est frappée et nommée : {frappes:?}");
}

// --- Motif validé PENDANT l'attente du verrou d'écriture -----------------------------------------------
// Une seconde connexion tient `BEGIN IMMEDIATE` ; le gestionnaire d'occupation de la purge (appelé pendant que son
// propre `BEGIN IMMEDIATE` attend le verrou) fait écrire puis valider le motif par cette seconde connexion, qui
// relâche le verrou ; la purge l'acquiert ensuite. Seule une relecture faite APRÈS l'acquisition voit le motif :
// une relecture placée avant le `BEGIN IMMEDIATE` (mutant `N4_HORS_TX`) le manque, comme le défaut d'origine.
thread_local! {
    static PCR_ECRITURE_CONCURRENTE: std::cell::RefCell<Option<(Connection, &'static str)>> =
        const { std::cell::RefCell::new(None) };
}

fn pcr_valider_l_ecriture_concurrente(_essai: i32) -> bool {
    PCR_ECRITURE_CONCURRENTE.with(|b| {
        if let Some((cb, sql)) = b.borrow_mut().take() {
            cb.execute_batch(sql).expect("écriture concurrente");
            cb.execute_batch("COMMIT").expect("COMMIT concurrent");
        }
    });
    true
}

/// Joue l'exécution pendant que `sql` est validé par une autre connexion dans l'attente du verrou ; rend le
/// résultat, l'état d'avant (events, registre) et la connexion de la purge.
fn pcr_executer_pendant_l_attente_du_verrou(
    tag: &str,
    sql: &'static str,
) -> (Result<PurgeReceipt, PurgeRefusal>, (i64, i64), Connection, crate::tmp_possede::TmpDb) {
    let p = ff_tmp_path(tag);
    let a = open_db(&p).unwrap();
    a.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
    assert!(migrate(&a), "fixture P10.32-b : migrations complètes");
    pcr_semer(&a);
    pcr_creer_cold_seal(&a);
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

/// La relecture est faite APRÈS l'acquisition du verrou d'écriture : un sceau recouvrant (ou le retrait du trigger
/// `event_ad`) validé pendant l'attente du `BEGIN IMMEDIATE` refuse l'exécution ; une écriture neutre validée au
/// même instant laisse la purge aboutir (le chemin d'occupation lui-même ne refuse rien).
#[test]
fn pcr_motif_valide_pendant_l_attente_du_verrou_refuse_l_execution() {
    let (r, avant, a, _p) = pcr_executer_pendant_l_attente_du_verrou(
        "pcr-verrou-cold",
        "INSERT INTO cold_seal VALUES('prod',1,0,6,0,1,99,1000,1005,1000,1,99,1)",
    );
    pcr_exiger_le_refus(&a, r, "cold_tier", avant, "sceau validé pendant l'attente du verrou");

    let (r, avant, a, _p) = pcr_executer_pendant_l_attente_du_verrou("pcr-verrou-fts", "DROP TRIGGER event_ad");
    pcr_exiger_le_refus(&a, r, "fts_desync", avant, "trigger retiré pendant l'attente du verrou");

    let (r, avant, a, _p) = pcr_executer_pendant_l_attente_du_verrou(
        "pcr-verrou-neutre",
        "INSERT INTO cold_seal VALUES('prod',9,0,6,0,1,99,5000,5005,5000,1,99,1)",
    );
    let recu = r.expect("contrôle négatif : sceau hors fenêtre validé pendant l'attente -> la purge aboutit");
    assert_eq!(recu.rows_deleted, avant.0, "contrôle négatif : tout le périmètre est purgé");
    assert_eq!(pcr_events(&a), 0, "contrôle négatif : events purgés");
    assert_eq!(pcr_registre(&a), avant.1 + 1, "contrôle négatif : une inscription au registre");
}

// --- Volet route -------------------------------------------------------------------------------------

fn pcr_admin() -> AuthUser {
    AuthUser {
        name: "adm".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
        method: "basic".into(), csrf: String::new(), env: None,
    }
}

fn pcr_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
    let path = ff_tmp_path(tag);
    {
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture P10.32-b : migrations complètes");
        pcr_semer(&conn);
    }
    let st = ds_file_state(&path);
    (st, path)
}

fn pcr_corps_de_purge(jeton: Option<&str>) -> Value {
    match jeton {
        Some(t) => json!({ "env": "prod", "since": 0, "until": 2000, "token": t, "reason": "témoin P10.32-b" }),
        None => json!({ "env": "prod", "since": 0, "until": 2000 }),
    }
}

async fn pcr_lire(r: Response) -> (u16, Value) {
    let statut = r.status().as_u16();
    let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    (statut, serde_json::from_slice(&octets).unwrap_or(Value::Null))
}

async fn pcr_plan(st: &AppState, au: &AuthUser) -> (u16, Value) {
    pcr_lire(purge_plan_route(State(st.clone()), Extension(au.clone()), Json(pcr_corps_de_purge(None))).await).await
}

async fn pcr_apply(st: &AppState, au: &AuthUser, jeton: &str) -> (u16, Value) {
    pcr_lire(purge_apply_route(State(st.clone()), Extension(au.clone()), Json(pcr_corps_de_purge(Some(jeton)))).await)
        .await
}

/// Statut attendu d'un refus servi, ÉCRIT ICI (pas relu dans `statut_du_refus_de_purge`).
fn pcr_statut_attendu(code: &str) -> u16 {
    match code {
        "db" | "plan_row_unread" | "legal_hold_undetermined" | "legal_hold_unread" => 500,
        "reason_required" => 400,
        _ => 409,
    }
}

fn pcr_juger_refus(statut: u16, corps: &Value, code: &str, quoi: &str) {
    assert_eq!(corps["ok"], json!(false), "{quoi} : ok:false : {corps}");
    assert_eq!(corps["refusal"], json!(code), "{quoi} : code machine servi : {corps}");
    assert_eq!(statut, pcr_statut_attendu(code), "{quoi} : `{code}` servi en {statut} : {corps}");
}

fn pcr_ecrire(st: &AppState, au: &AuthUser, sql: &str) {
    with_write(st, au, |c| c.execute_batch(sql).expect("fixture SQL"));
}

fn pcr_events_servis(st: &AppState, au: &AuthUser) -> i64 {
    with_write(st, au, |c| pcr_events(c))
}

/// La PORTE : sans l'injection, les deux routes refusent en 403 (l'environnement n'est pas touché) ; ouverte sur
/// ce fil, la route opère ; la garde tombée, 403 de nouveau.
#[tokio::test]
async fn pcr_la_porte_reste_fermee_sans_injection() {
    let (st, _p) = pcr_etat("pcr-porte");
    let au = pcr_admin();
    assert!(!purge_api_enabled(), "défaut : porte fermée");
    assert_eq!(pcr_plan(&st, &au).await.0, 403, "plan : porte fermée");
    assert_eq!(pcr_apply(&st, &au, "x").await.0, 403, "apply : porte fermée");
    {
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        assert_eq!(pcr_plan(&st, &au).await.0, 200, "porte ouverte sur ce fil : la route opère");
    }
    assert!(!purge_api_enabled(), "garde tombée : porte refermée");
    assert_eq!(pcr_plan(&st, &au).await.0, 403, "garde tombée : 403");
    assert_eq!(pcr_events_servis(&st, &au), 6, "rien supprimé");
}

/// DÉFENSE EN PROFONDEUR : porte OUVERTE, un compte non administrateur est refusé en 403 par le re-contrôle de
/// rôle de chaque handler (pas par la porte : le corps nomme le rôle), rien supprimé ; contrôle positif admin.
#[tokio::test]
async fn pcr_un_compte_non_administrateur_est_refuse_porte_ouverte() {
    let (st, _p) = pcr_etat("pcr-role");
    let adm = pcr_admin();
    let _ouverte = porte_de_purge_de_temoin::ouvrir();
    let (s, plan) = pcr_plan(&st, &adm).await;
    assert_eq!(s, 200, "contrôle positif : admin, porte ouverte : {plan}");
    let jeton = plan["token"].as_str().expect("jeton servi").to_string();
    for role in ["editor", "viewer"] {
        let au = AuthUser { role: role.into(), name: format!("compte-{role}"), ..pcr_admin() };
        assert!(!au.is_admin(), "précondition : `{role}` n'est pas admin");
        for (quoi, (s, c)) in [("plan", pcr_plan(&st, &au).await), ("apply", pcr_apply(&st, &au, &jeton).await)] {
            assert_eq!(s, 403, "{quoi}, rôle `{role}` : 403 servi : {c}");
            let msg = c["error"].as_str().unwrap_or_default();
            assert!(msg.contains("réservé à l'administrateur"), "{quoi}, rôle `{role}` : refus de RÔLE, pas de porte : {c}");
        }
    }
    assert_eq!(pcr_events_servis(&st, &adm), 6, "rien supprimé");
    assert_eq!(with_write(&st, &adm, |c| pcr_registre(c)), 0, "rien inscrit au registre");
}

/// Balayage d'interruptions d'une route ENTIÈRE. Rend les codes de refus servis (chacun jugé statut ET corps) ;
/// un 200 n'est admis que si `succes_admis`.
async fn pcr_balayer_la_route(st: &AppState, au: &AuthUser, apply: Option<&str>, succes_admis: bool) -> std::collections::BTreeSet<String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    let compte = std::sync::Arc::new(AtomicU64::new(0));
    let k = compte.clone();
    with_write(st, au, |c| {
        c.progress_handler(
            1,
            Some(move || {
                k.fetch_add(1, Ordering::Relaxed);
                false
            }),
        )
    });
    let (statut, _) = match apply {
        Some(t) => pcr_apply(st, au, t).await,
        None => pcr_plan(st, au).await,
    };
    with_write(st, au, |c| c.progress_handler(0, None::<fn() -> bool>));
    let total = compte.load(Ordering::Relaxed);
    assert!(total > 50, "précondition : la route exécute des instructions ({total}, statut {statut})");
    let mut codes = std::collections::BTreeSet::new();
    for cible in 1..=total {
        with_write(st, au, |c| pcr_interrompre_a(c, cible));
        let (statut, corps) = match apply {
            Some(t) => pcr_apply(st, au, t).await,
            None => pcr_plan(st, au).await,
        };
        with_write(st, au, |c| c.progress_handler(0, None::<fn() -> bool>));
        if statut == 200 {
            assert!(succes_admis, "interruption {cible}/{total} : 200 servi — {corps}");
            continue;
        }
        let code = corps["refusal"].as_str().unwrap_or_else(|| panic!("interruption {cible}/{total} : refus sans code : {statut} {corps}")).to_string();
        pcr_juger_refus(statut, &corps, &code, &format!("interruption {cible}/{total}"));
        codes.insert(code);
    }
    codes
}

/// LES DEUX ROUTES ENTIÈRES, SURFACE OUVERTE : la nature d'un refus est jugée sur ce que la route SERT.
#[tokio::test]
async fn pcr_les_deux_routes_servent_la_nature_de_chaque_refus() {
    let (st, _p) = pcr_etat("pcr-routes");
    let au = pcr_admin();
    let _ouverte = porte_de_purge_de_temoin::ouvrir();

    let (statut, plan) = pcr_plan(&st, &au).await;
    assert_eq!(statut, 200, "contrôle positif : plan servi : {plan}");
    let jeton = plan["token"].as_str().expect("jeton servi").to_string();

    // Lectures non faites : 500, sur chaque route.
    let codes = pcr_balayer_la_route(&st, &au, None, true).await;
    for code in ["plan_row_unread", "legal_hold_undetermined", "db"] {
        assert!(codes.contains(code), "plan : le balayage atteint `{code}` : {codes:?}");
    }
    let codes = pcr_balayer_la_route(&st, &au, Some("jeton-perime"), false).await;
    for code in ["plan_row_unread", "legal_hold_undetermined", "db", "stale_token"] {
        assert!(codes.contains(code), "apply : le balayage atteint `{code}` : {codes:?}");
    }
    assert_eq!(pcr_events_servis(&st, &au), 6, "balayages : rien supprimé");

    // Tier froid : 409 sur les deux routes, jeton valide compris.
    with_write(&st, &au, |c| pcr_sceller(c, 1, 1_000, 1_005));
    let (s, c) = pcr_plan(&st, &au).await;
    pcr_juger_refus(s, &c, "cold_tier", "plan, sceau recouvrant");
    let (s, c) = pcr_apply(&st, &au, &jeton).await;
    pcr_juger_refus(s, &c, "cold_tier", "apply, sceau recouvrant");
    pcr_ecrire(&st, &au, "DELETE FROM cold_seal;");

    // Rétention légale active : 409.
    pcr_ecrire(
        &st,
        &au,
        "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
         VALUES('litige','','',0,0,1,0,'admin');",
    );
    let (s, c) = pcr_plan(&st, &au).await;
    pcr_juger_refus(s, &c, "legal_hold", "plan, hold actif");
    let (s, c) = pcr_apply(&st, &au, &jeton).await;
    pcr_juger_refus(s, &c, "legal_hold", "apply, hold actif");
    pcr_ecrire(&st, &au, "DELETE FROM legal_hold;");

    // Rétention au nom illisible : 500.
    pcr_ecrire(
        &st,
        &au,
        "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
         VALUES(X'FFFE','','',0,0,1,0,'admin');",
    );
    let (s, c) = pcr_plan(&st, &au).await;
    pcr_juger_refus(s, &c, "legal_hold_unread", "plan, hold illisible");
    let (s, c) = pcr_apply(&st, &au, &jeton).await;
    pcr_juger_refus(s, &c, "legal_hold_unread", "apply, hold illisible");
    pcr_ecrire(&st, &au, "DELETE FROM legal_hold;");

    // Index plein-texte désynchronisé (trigger `event_ad` retiré) : 409 sur les deux routes.
    let ddl_fts = with_write(&st, &au, |c| pcr_ddl_du_trigger_fts(c));
    pcr_ecrire(&st, &au, "DROP TRIGGER event_ad;");
    let (s, c) = pcr_plan(&st, &au).await;
    pcr_juger_refus(s, &c, "fts_desync", "plan, trigger retiré");
    let (s, c) = pcr_apply(&st, &au, &jeton).await;
    pcr_juger_refus(s, &c, "fts_desync", "apply, trigger retiré");
    pcr_ecrire(&st, &au, &format!("{ddl_fts};"));

    // Event du périmètre cité par la timeline d'un case : 409 sur les deux routes.
    let cite: i64 = with_write(&st, &au, |c| c.query_row("SELECT MIN(id) FROM event", [], |r| r.get(0)).unwrap());
    pcr_ecrire(
        &st,
        &au,
        &format!("INSERT INTO incident_item(incident_id,ts,kind,author,body,ref) VALUES(1,0,'event','adm','','event:{cite}');"),
    );
    let (s, c) = pcr_plan(&st, &au).await;
    pcr_juger_refus(s, &c, "cited_by_case", "plan, event cité");
    let (s, c) = pcr_apply(&st, &au, &jeton).await;
    pcr_juger_refus(s, &c, "cited_by_case", "apply, event cité");
    pcr_ecrire(&st, &au, "DELETE FROM incident_item;");

    // Raison absente (blancs seulement), jeton valide : 400 sur la route d'exécution (le plan n'en prend pas).
    let mut sans_raison = pcr_corps_de_purge(Some(&jeton));
    sans_raison["reason"] = json!("   ");
    let (s, c) = pcr_lire(purge_apply_route(State(st.clone()), Extension(au.clone()), Json(sans_raison)).await).await;
    pcr_juger_refus(s, &c, "reason_required", "apply, raison blanche");
    assert_eq!(pcr_events_servis(&st, &au), 6, "refus : rien supprimé");
    assert_eq!(with_write(&st, &au, |c| pcr_registre(c)), 0, "refus : rien inscrit au registre");

    // Contrôle positif : la route d'exécution aboutit au jeton du plan.
    let (s, recu) = pcr_apply(&st, &au, &jeton).await;
    assert_eq!(s, 200, "apply nominal : {recu}");
    assert_eq!((recu["rows_deleted"].clone(), recu["token"].clone()), (json!(6), json!(jeton)), "reçu servi : {recu}");
    assert_eq!(pcr_events_servis(&st, &au), 0, "les six lignes sont parties");
}

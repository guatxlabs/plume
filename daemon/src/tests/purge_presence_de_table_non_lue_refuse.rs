// =====================================================================================
// `P10.31-x` — PURGE : UNE LECTURE RATÉE DE LA PRÉSENCE D'UNE TABLE N'EST PLUS UNE TABLE ABSENTE.
//
// LE DÉFAUT (mesuré sur 80ad700a, sonde de la vérification de la vague L) : `table_present`
// (`governance.rs`) rendait `.is_ok()` d'un `query_row` sur `sqlite_master`. Une interruption (le rappel de
// progression que `armer_le_quota` pose sur toute connexion de production), un verrou ou un catalogue
// illisible valaient donc « table absente » : `cited_by_case` sautait le contrôle de citation et rendait
// `None`, `purge_plan` rendait un plan, et `purge_confirm_and_apply` détruisait un event cité par un dossier
// (citation orpheline). `purge_apply` ne relisait pas les citations et le jeton ne les couvre pas. Même famille :
// `fts_delete_trigger_ok`, dont la présence d'`event_fts` était lue de la même façon (lecture ratée = index
// absent = refus `fts_desync` SAUTÉ, fail-open) et la lecture du trigger rendait `fts_desync` sur une erreur
// (fail-closed, cause fausse).
//
// CE QUE CES TÉMOINS JUGENT :
//  - la présence en TROIS issues : présente, absence lue, lecture non faite (instrument `temoin_de_presence`,
//    cfg(test) : il pose SEULEMENT le rappel de progression, à chaque appel pour un nom donné ; c'est la requête
//    de PRODUCTION de `presence_de_table` que le moteur interrompt — l'instrument n'en porte aucune copie) ;
//  - présence de `incident_item` non lue : le PLAN refuse (`db`, nomme la table et « interrupted ») ET la
//    CONFIRMATION avec un jeton valide refuse sans rien détruire — l'event cité reste, aucune inscription ;
//  - `purge_apply` relit les citations DANS SA TRANSACTION : une citation posée après la confirmation, ou une
//    présence non lue au moment de l'exécution, refusent et ROLLBACK (registre compris) ;
//  - balayage d'interruptions à chaque instruction de la VM, base AVEC une citation : aucun plan, aucune
//    confirmation ne passe, et au moins un passage frappe la lecture de présence et le dit ;
//  - index plein-texte : `event_fts` non lu (trigger réellement absent) refuse plan et confirmation, rien
//    supprimé ; balayage : une interruption de la lecture du trigger refuse en le nommant, aucun plan ;
//  - UNE SEULE NATURE pour une même cause : sur un balayage d'interruptions d'une base sans motif de refus,
//    `db` et `plan_row_unread` sont atteints et TOUT refus sort en 500 (`statut_du_refus_de_purge`) — la
//    rétention légale non lue (`legal_hold_undetermined`, `legal_hold_unread`) y est rangée aussi ;
//  - chemin nominal : le jeton est l'empreinte d'avant, octet pour octet, et la purge aboutit ;
//  - rétention légale (`holds_covering`) et tier froid (`cold_overlap`) : présence de `legal_hold` / de
//    `cold_seal` non lue, avec un hold actif / un fichier scellé qui recouvre, refuse le plan et la confirmation
//    (`db`, table nommée), rien supprimé ; balayage d'interruptions sur chacune de ces bases.
// MUTATIONS (jouées sous VERIF_MUT, retirées du source) : `M1_IS_OK` (présence `.unwrap_or(false)`, la forme
// d'avant) rougit la présence en trois issues, le refus du plan et de l'exécution sous panne, et le balayage du
// plan ; `M1_PLAN_SEUL` (la panne refuse le plan seul, la confirmation l'avale) rougit la confirmation ;
// `M1_APPLY_SANS_CITES` (pas de relecture dans la transaction) rougit l'exécution après une citation posée ;
// `M1_FTS_IS_OK` (`fts_delete_trigger_ok` d'avant) rougit les deux témoins de l'index plein-texte ;
// `M1_NATURE_409` (`plan_row_unread` en 409) rougit le témoin de nature. Le témoin nominal reste vert sous toutes.
// Correction après vérification : l'instrument portait sa propre copie de la requête, la forme d'avant remise
// dans les lignes de PRODUCTION (`M1C_GV_AVALE`) laissait vert le témoin des trois issues ; il juge désormais la
// requête de production et rougit. `M1C_HOLD_AVALE` / `M1C_COLD_AVALE` (`.unwrap_or(false)` sur la présence de
// `legal_hold` / `cold_seal`, restés verts sur toute la suite) rougissent leur témoin (dès l'instrument : plan de
// 3 lignes « sauf les tenues », plan de 6 lignes malgré le tier froid). Sous `M1C_GV_AVALE`, le balayage
// AVEC citation du lot L (`pli_`), dont la tolérance « plan nominal » est retirée, rougit aussi.
// CE QUE CE LOT NE TIENT PAS :
//  - `purge_apply` ne relit pas la synchronisation de l'index plein-texte ni le tier froid dans sa transaction
//    (seules les citations, et la rétention légale qui y était déjà) ;
//  - les codes machine restent distincts (`db`, `plan_row_unread`) : seule la nature HTTP est unifiée ;
//  - `legal_hold_enforcement` lit déjà sa présence en trois issues par sa propre requête : non touché ;
//  - la CLI ne lit pas le statut HTTP (texte du refus, code de sortie 3) : rien n'y change.
// =====================================================================================

fn ptn_ins(c: &Connection, ts: i64, source: &str) -> i64 {
    c.execute(
        "INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id) \
         VALUES(?1,?2,'test',1,'m','h1','prod','','')",
        params![ts, source],
    )
    .unwrap();
    c.last_insert_rowid()
}

fn ptn_scope() -> PurgeScope {
    let v = vec![("env".to_string(), "prod".to_string())];
    purge_scope_from_args(&v, "0", "2000", now()).expect("périmètre valide")
}

/// Six lignes dans la fenêtre (ts 1000..1005, sources `flux-a` x3 et `flux-b` x3). Rend les ids.
fn ptn_base() -> (Connection, Vec<i64>) {
    let c = test_db();
    let ids = (0..6).map(|i| ptn_ins(&c, 1_000 + i, if i < 3 { "flux-a" } else { "flux-b" })).collect();
    (c, ids)
}

fn ptn_citer(c: &Connection, id: i64) {
    c.execute("INSERT INTO incident(ts,updated,title) VALUES(1000,1000,'enquête')", []).unwrap();
    let inc = c.last_insert_rowid();
    c.execute(
        "INSERT INTO incident_item(incident_id,ts,kind,author,body,ref) VALUES(?1,1000,'evidence','a','b',?2)",
        params![inc, format!("event:{id}")],
    )
    .unwrap();
}

fn ptn_event_present(c: &Connection, id: i64) -> bool {
    c.query_row("SELECT COUNT(*) FROM event WHERE id=?1", params![id], |r| r.get::<_, i64>(0)).unwrap() == 1
}

fn ptn_events_ingeres(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM event WHERE origin=''", [], |r| r.get(0)).unwrap()
}

fn ptn_ledger_purges(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![PURGE_LEDGER_KIND], |r| r.get(0)).unwrap()
}

/// Nombre d'instructions de VM qu'exécute `f` (rappel compté, jamais vrai).
fn ptn_compter_instructions(c: &Connection, f: impl FnOnce(&Connection)) -> u64 {
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

/// Arme une interruption à la `cible`-ième instruction de VM, une seule fois.
fn ptn_interrompre_a(c: &Connection, cible: u64) {
    use std::sync::atomic::{AtomicU64, Ordering};
    let n = AtomicU64::new(0);
    c.progress_handler(1, Some(move || n.fetch_add(1, Ordering::Relaxed) + 1 == cible));
}

/// TROIS ISSUES : présente, absence LUE, lecture NON FAITE — la dernière n'est jamais rendue `Ok(false)`.
#[test]
fn ptn_presence_de_table_en_trois_issues() {
    let c = test_db();
    assert_eq!(presence_de_table(&c, "incident_item").ok(), Some(true), "présente");
    assert_eq!(presence_de_table(&c, "table_qui_n_existe_pas").ok(), Some(false), "absence lue");
    crate::governance::temoin_de_presence::armer("incident_item");
    let lu = presence_de_table(&c, "incident_item");
    crate::governance::temoin_de_presence::desarmer();
    match lu {
        Err(e) => assert!(e.to_string().contains("interrupted"), "la cause du moteur est rendue : {e}"),
        Ok(b) => panic!("lecture interrompue rendue comme un FAIT : présence = {b}"),
    }
    assert_eq!(presence_de_table(&c, "incident_item").ok(), Some(true), "désarmé : présente de nouveau");
}

/// Présence de `incident_item` NON LUE : le plan refuse, et la CONFIRMATION avec un jeton valide refuse sans
/// rien détruire. Contrôle positif dans le même corps : panne levée -> `cited_by_case` nomme l'event.
#[test]
fn ptn_presence_non_lue_refuse_le_plan_et_la_confirmation() {
    let (c, ids) = ptn_base();
    // Le jeton ne dépend pas des citations : pris avant, il est VALIDE après la citation.
    let jeton = purge_plan(&c, ptn_scope()).expect("plan nominal").digest().to_string();
    ptn_citer(&c, ids[2]);
    let (avant, registre) = (ptn_events_ingeres(&c), ptn_ledger_purges(&c));

    crate::governance::temoin_de_presence::armer("incident_item");
    let plan = purge_plan(&c, ptn_scope());
    let confirmation = purge_confirm_and_apply(&c, ptn_scope(), &jeton, "t", "témoin P10.31-x");
    crate::governance::temoin_de_presence::desarmer();

    match plan {
        Ok(p) => panic!(
            "présence de `incident_item` non lue : la simulation a rendu un plan de {} ligne(s) (jeton {}) — \
             contrôle de citation SAUTÉ",
            p.rows(),
            p.digest()
        ),
        Err(e) => {
            assert_eq!(purge_refusal_code(&e), "db", "lecture non faite : {e}");
            let m = e.to_string();
            assert!(m.contains("`incident_item`") && m.contains("interrupted"), "le refus nomme la table et la cause : {m}");
        }
    }
    match confirmation {
        Ok(r) => panic!(
            "présence de `incident_item` non lue : la CONFIRMATION a détruit {} ligne(s) — event cité présent : {}",
            r.rows_deleted,
            ptn_event_present(&c, ids[2])
        ),
        Err(e) => assert_eq!(purge_refusal_code(&e), "db", "la confirmation refuse par la même nature : {e}"),
    }
    assert!(ptn_event_present(&c, ids[2]), "l'event cité est intact");
    assert_eq!(ptn_events_ingeres(&c), avant, "aucune ligne supprimée");
    assert_eq!(ptn_ledger_purges(&c), registre, "aucune inscription au registre");

    let e = purge_plan(&c, ptn_scope()).unwrap_err();
    assert_eq!(purge_refusal_code(&e), "cited_by_case", "contrôle positif : panne levée, la citation est jugée");
    assert!(e.to_string().contains(&format!("[{}]", ids[2])), "contrôle positif : l'id est nommé : {e}");
}

/// DÉFENSE EN PROFONDEUR : `purge_apply` relit les citations dans sa transaction. Une citation posée APRÈS la
/// confirmation refuse (`cited_by_case`) et ROLLBACK ; une présence non lue à l'exécution refuse (`db`).
#[test]
fn ptn_l_execution_relit_les_citations_dans_sa_transaction() {
    let (c, ids) = ptn_base();
    let (avant, registre) = (ptn_events_ingeres(&c), ptn_ledger_purges(&c));

    let plan = purge_plan(&c, ptn_scope()).expect("plan nominal, aucune citation");
    let jeton = plan.digest().to_string();
    let confirme = plan.confirm(&jeton, "t", "témoin P10.31-x").expect("confirmation");
    ptn_citer(&c, ids[4]);
    match purge_apply(&c, confirme) {
        Ok(r) => panic!(
            "citation posée après la confirmation : l'exécution a détruit {} ligne(s) — event cité présent : {}",
            r.rows_deleted,
            ptn_event_present(&c, ids[4])
        ),
        Err(e) => {
            assert_eq!(purge_refusal_code(&e), "cited_by_case", "{e}");
            assert!(e.to_string().contains(&format!("[{}]", ids[4])), "l'id est nommé : {e}");
        }
    }
    assert!(ptn_event_present(&c, ids[4]), "l'event cité est intact");
    assert_eq!(ptn_events_ingeres(&c), avant, "aucune ligne supprimée");
    assert_eq!(ptn_ledger_purges(&c), registre, "inscription annulée avec le reste (ROLLBACK)");

    // Présence non lue AU MOMENT DE L'EXÉCUTION (la simulation, elle, l'a lue).
    c.execute("DELETE FROM incident_item", []).unwrap();
    let plan = purge_plan(&c, ptn_scope()).expect("plan nominal, citation détachée");
    let jeton = plan.digest().to_string();
    let confirme = plan.confirm(&jeton, "t", "témoin P10.31-x").expect("confirmation");
    ptn_citer(&c, ids[1]);
    crate::governance::temoin_de_presence::armer("incident_item");
    let r = purge_apply(&c, confirme);
    crate::governance::temoin_de_presence::desarmer();
    match r {
        Ok(r) => panic!("présence non lue à l'exécution : {} ligne(s) détruite(s)", r.rows_deleted),
        Err(e) => {
            assert_eq!(purge_refusal_code(&e), "db", "{e}");
            assert!(e.to_string().contains("`incident_item`"), "le refus nomme la table : {e}");
        }
    }
    assert!(ptn_event_present(&c, ids[1]), "l'event cité est intact");
    assert_eq!(ptn_events_ingeres(&c), avant, "aucune ligne supprimée");
    assert_eq!(ptn_ledger_purges(&c), registre, "aucune inscription au registre");
}

/// BALAYAGE : une interruption à chaque instruction de la VM, base AVEC une citation. Aucune simulation ne rend
/// de plan, aucune confirmation n'aboutit, et au moins un passage frappe la lecture de présence de
/// `incident_item` et refuse en le disant (l'instruction que la sonde de la vague L avait trouvée).
#[test]
fn ptn_aucune_interruption_ne_saute_le_controle_de_citation() {
    let (c, ids) = ptn_base();
    let jeton = purge_plan(&c, ptn_scope()).expect("plan nominal").digest().to_string();
    ptn_citer(&c, ids[3]);
    let avant = ptn_events_ingeres(&c);

    let total = ptn_compter_instructions(&c, |c| {
        let _ = purge_plan(c, ptn_scope());
    });
    assert!(total > 50, "précondition : la simulation exécute des instructions ({total})");
    let mut presence_refusee = 0u64;
    for cible in 1..=total {
        ptn_interrompre_a(&c, cible);
        let r = purge_plan(&c, ptn_scope());
        c.progress_handler(0, None::<fn() -> bool>);
        match r {
            Ok(p) => panic!(
                "interruption à l'instruction {cible}/{total} : plan de {} ligne(s) rendu malgré la citation",
                p.rows()
            ),
            Err(e) => {
                let m = e.to_string();
                if m.contains("présence de la table `incident_item`") {
                    assert!(m.contains("interrupted"), "le refus porte la cause du moteur : {m}");
                    presence_refusee += 1;
                }
            }
        }
    }
    assert!(presence_refusee > 0, "précondition : au moins un passage a interrompu la lecture de présence de `incident_item`");

    let total = ptn_compter_instructions(&c, |c| {
        let _ = purge_confirm_and_apply(c, ptn_scope(), &jeton, "t", "témoin P10.31-x");
    });
    for cible in 1..=total {
        ptn_interrompre_a(&c, cible);
        let r = purge_confirm_and_apply(&c, ptn_scope(), &jeton, "t", "témoin P10.31-x");
        c.progress_handler(0, None::<fn() -> bool>);
        if let Ok(r) = r {
            panic!("interruption à l'instruction {cible}/{total} : la confirmation a détruit {} ligne(s)", r.rows_deleted);
        }
        assert!(ptn_event_present(&c, ids[3]), "interruption à l'instruction {cible}/{total} : event cité détruit");
    }
    assert_eq!(ptn_events_ingeres(&c), avant, "aucune ligne supprimée sur tout le balayage");
}

/// INDEX PLEIN-TEXTE, même famille : trigger `event_ad` RÉELLEMENT absent. `event_fts` non lu ne vaut plus
/// « index absent » (qui sautait le refus) : plan ET confirmation refusent, rien supprimé. Balayage : une
/// interruption de la lecture du trigger refuse en le nommant (et non plus `fts_desync`, cause fausse).
#[test]
fn ptn_index_plein_texte_lu_en_trois_issues() {
    let (c, _ids) = ptn_base();
    let jeton = purge_plan(&c, ptn_scope()).expect("plan nominal").digest().to_string();
    c.execute("DROP TRIGGER event_ad", []).unwrap();
    let avant = ptn_events_ingeres(&c);
    assert_eq!(purge_refusal_code(&purge_plan(&c, ptn_scope()).unwrap_err()), "fts_desync", "contrôle positif");

    crate::governance::temoin_de_presence::armer("event_fts");
    let plan = purge_plan(&c, ptn_scope());
    let confirmation = purge_confirm_and_apply(&c, ptn_scope(), &jeton, "t", "témoin P10.31-x");
    crate::governance::temoin_de_presence::desarmer();
    match plan {
        Ok(p) => panic!("`event_fts` non lu : plan de {} ligne(s) rendu, index désynchronisé ignoré", p.rows()),
        Err(e) => {
            assert_eq!(purge_refusal_code(&e), "db", "{e}");
            assert!(e.to_string().contains("`event_fts`"), "le refus nomme la table : {e}");
        }
    }
    if let Ok(r) = confirmation {
        panic!("`event_fts` non lu : la confirmation a détruit {} ligne(s) en laissant les postings", r.rows_deleted);
    }
    assert_eq!(ptn_events_ingeres(&c), avant, "aucune ligne supprimée");

    let total = ptn_compter_instructions(&c, |c| {
        let _ = purge_plan(c, ptn_scope());
    });
    let mut trigger_refuse = 0u64;
    for cible in 1..=total {
        ptn_interrompre_a(&c, cible);
        let r = purge_plan(&c, ptn_scope());
        c.progress_handler(0, None::<fn() -> bool>);
        match r {
            Ok(p) => panic!("interruption à l'instruction {cible}/{total} : plan de {} ligne(s) sans trigger", p.rows()),
            Err(e) => {
                let m = e.to_string();
                if m.contains("trigger `event_ad` NON LUE") {
                    assert!(m.contains("interrupted"), "le refus porte la cause du moteur : {m}");
                    trigger_refuse += 1;
                }
            }
        }
    }
    assert!(trigger_refuse > 0, "au moins un passage a interrompu la lecture du trigger et l'a nommée");
}

/// UNE SEULE NATURE POUR UNE MÊME CAUSE : sur une base sans aucun motif de refus, tout refus d'un balayage
/// d'interruptions vient de l'interruption. Elle frappe tantôt un `query_row` (`db`), tantôt une ligne
/// d'itérateur (`plan_row_unread`), tantôt la rétention légale : les deux premières formes sont atteintes, et
/// TOUS les refus sortent en 500. Contrôle : une décision lue reste 409, une entrée manquante 400.
#[test]
fn ptn_une_interruption_n_a_qu_une_nature_de_refus() {
    let (c, _ids) = ptn_base();
    let total = ptn_compter_instructions(&c, |c| {
        purge_plan(c, ptn_scope()).expect("plan nominal sous rappel inerte");
    });
    let mut vus: std::collections::BTreeMap<&'static str, std::collections::BTreeSet<u16>> = Default::default();
    for cible in 1..=total {
        ptn_interrompre_a(&c, cible);
        let r = purge_plan(&c, ptn_scope());
        c.progress_handler(0, None::<fn() -> bool>);
        if let Err(e) = r {
            vus.entry(purge_refusal_code(&e)).or_default().insert(statut_du_refus_de_purge(&e).as_u16());
        }
    }
    println!("balayage de nature : {total} passages — codes et statuts {vus:?}");
    assert!(
        vus.contains_key("db") && vus.contains_key("plan_row_unread"),
        "précondition : l'interruption a frappé les deux formes de lecture ({vus:?})"
    );
    let natures: std::collections::BTreeSet<u16> = vus.values().flatten().copied().collect();
    assert_eq!(natures.len(), 1, "une même cause, une seule nature de refus : {vus:?}");
    assert!(natures.contains(&500), "lecture non faite = 500 : {vus:?}");
    for e in [
        PurgeRefusal::LegalHoldUndetermined,
        PurgeRefusal::LegalHoldUnread("x".into()),
        PurgeRefusal::PlanRowUnread { site: "x", cause: "y".into() },
        PurgeRefusal::Db("x".into()),
    ] {
        assert_eq!(statut_du_refus_de_purge(&e).as_u16(), 500, "lecture non faite : {}", purge_refusal_code(&e));
    }
    assert_eq!(statut_du_refus_de_purge(&PurgeRefusal::FtsDesync).as_u16(), 409, "une décision reste 409");
    assert_eq!(
        statut_du_refus_de_purge(&PurgeRefusal::CitedByCase { ids: vec![1], total: 1 }).as_u16(),
        409,
        "une décision reste 409"
    );
    assert_eq!(statut_du_refus_de_purge(&PurgeRefusal::ReasonRequired).as_u16(), 400, "une entrée manquante reste 400");
}

/// CHEMIN NOMINAL : le jeton est l'empreinte d'avant (recalculée par la formule de `purge_digest`), et la
/// purge aboutit avec ce jeton.
#[test]
fn ptn_jeton_nominal_inchange() {
    let (c, ids) = ptn_base();
    let scope = ptn_scope();
    let canonique = scope.canonical();
    let p = purge_plan(&c, scope).expect("plan nominal");
    let somme: i64 = ids.iter().sum();
    let attendu = sha256_hex(
        format!(
            "plume-purge/v1|{canonique}|rows=6|id=[{},{}]|idsum={somme}|ts=[1000,1005]|src=flux-a:3,flux-b:3",
            ids[0], ids[5]
        )
        .as_bytes(),
    );
    assert_eq!(p.digest(), attendu, "le jeton nominal est l'empreinte d'avant, octet pour octet");
    let r = purge_confirm_and_apply(&c, ptn_scope(), &attendu, "t", "témoin P10.31-x").expect("purge nominale");
    assert_eq!(r.rows_deleted, 6);
    assert_eq!(ptn_events_ingeres(&c), 0);
}

/// Balaye une interruption à chaque instruction de `purge_plan` : aucun passage ne rend de plan, et au moins un
/// passage interrompt la lecture de présence de `table` et refuse en la nommant avec la cause du moteur.
fn ptn_balayer_la_presence(c: &Connection, table: &str, motif: &str) {
    let total = ptn_compter_instructions(c, |c| {
        let _ = purge_plan(c, ptn_scope());
    });
    assert!(total > 50, "précondition : la simulation exécute des instructions ({total})");
    let attendu = format!("présence de la table `{table}`");
    let mut presence_refusee = 0u64;
    for cible in 1..=total {
        ptn_interrompre_a(c, cible);
        let r = purge_plan(c, ptn_scope());
        c.progress_handler(0, None::<fn() -> bool>);
        match r {
            Ok(p) => panic!("interruption à l'instruction {cible}/{total} : plan de {} ligne(s) rendu malgré {motif}", p.rows()),
            Err(e) => {
                let m = e.to_string();
                if m.contains(&attendu) {
                    assert_eq!(purge_refusal_code(&e), "db", "{m}");
                    assert!(m.contains("interrupted"), "le refus porte la cause du moteur : {m}");
                    presence_refusee += 1;
                }
            }
        }
    }
    assert!(presence_refusee > 0, "précondition : au moins un passage a interrompu la lecture de présence de `{table}`");
}

/// RÉTENTION LÉGALE (`holds_covering`) : présence de `legal_hold` NON LUE, hold actif sur `flux-a` qui recouvre
/// le périmètre. Le refus n'est pas sauté : sans lui, la simulation rendrait le plan des seules lignes NON
/// tenues (le fragment `NOT held` reste au prédicat), la purge partielle « sauf les lignes tenues » que la
/// conception interdit. Plan ET confirmation refusent (`db`, table nommée), rien supprimé ; contrôle positif
/// (panne levée -> `legal_hold` nomme le hold) ; balayage d'interruptions sur la même base.
#[test]
fn ptn_presence_de_legal_hold_non_lue_refuse() {
    let (c, ids) = ptn_base();
    let jeton = purge_plan(&c, ptn_scope()).expect("plan nominal").digest().to_string();
    c.execute(
        "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
         VALUES('litige-A','','flux-a',0,0,1,0,'admin')",
        [],
    )
    .unwrap();
    let (avant, registre) = (ptn_events_ingeres(&c), ptn_ledger_purges(&c));
    let e = purge_plan(&c, ptn_scope()).unwrap_err();
    assert_eq!(purge_refusal_code(&e), "legal_hold", "contrôle positif : {e}");
    assert!(e.to_string().contains("litige-A"), "contrôle positif : le hold est nommé : {e}");

    crate::governance::temoin_de_presence::armer("legal_hold");
    let plan = purge_plan(&c, ptn_scope());
    let confirmation = purge_confirm_and_apply(&c, ptn_scope(), &jeton, "t", "témoin P10.31-x");
    crate::governance::temoin_de_presence::desarmer();
    match plan {
        Ok(p) => panic!(
            "présence de `legal_hold` non lue : plan de {} ligne(s) rendu malgré un hold actif qui recouvre \
             (purge partielle « sauf les lignes tenues »)",
            p.rows()
        ),
        Err(e) => {
            assert_eq!(purge_refusal_code(&e), "db", "lecture non faite : {e}");
            let m = e.to_string();
            assert!(m.contains("`legal_hold`") && m.contains("interrupted"), "le refus nomme la table et la cause : {m}");
        }
    }
    match confirmation {
        Ok(r) => panic!("présence de `legal_hold` non lue : la confirmation a détruit {} ligne(s)", r.rows_deleted),
        Err(e) => assert_eq!(purge_refusal_code(&e), "db", "la confirmation refuse par la même nature : {e}"),
    }
    assert!(ids.iter().all(|id| ptn_event_present(&c, *id)), "aucune ligne tenue ni libre supprimée");
    assert_eq!(ptn_events_ingeres(&c), avant, "aucune ligne supprimée");
    assert_eq!(ptn_ledger_purges(&c), registre, "aucune inscription au registre");

    ptn_balayer_la_presence(&c, "legal_hold", "un hold actif qui recouvre");
    assert_eq!(ptn_events_ingeres(&c), avant, "aucune ligne supprimée sur le balayage");
}

/// TIER FROID (`cold_overlap`) : présence de `cold_seal` NON LUE, fichier scellé qui recouvre la fenêtre. Le
/// refus n'est pas sauté : sans lui, le plan purgerait le chaud pendant que les Parquet scellés restent
/// lisibles. Plan ET confirmation refusent (`db`, table nommée), rien supprimé ; contrôle positif (panne levée
/// -> `cold_tier`) ; balayage d'interruptions sur la même base.
#[test]
fn ptn_presence_de_cold_seal_non_lue_refuse() {
    let (c, _ids) = ptn_base();
    let jeton = purge_plan(&c, ptn_scope()).expect("plan nominal").digest().to_string();
    c.execute_batch(
        "CREATE TABLE cold_seal(env_id TEXT NOT NULL, day INTEGER NOT NULL, seq INTEGER NOT NULL, \
           expected_rows INTEGER NOT NULL, sealed_ts INTEGER NOT NULL, purged INTEGER NOT NULL DEFAULT 0, \
           max_id INTEGER NOT NULL, ts_min INTEGER NOT NULL, ts_max INTEGER NOT NULL, lo_ts INTEGER NOT NULL, \
           lo_id INTEGER NOT NULL, hi_id INTEGER NOT NULL, last_file INTEGER NOT NULL DEFAULT 0, \
           PRIMARY KEY(env_id,day,seq))",
    )
    .unwrap();
    c.execute("INSERT INTO cold_seal VALUES('prod',1,0,6,0,1,99,1000,1005,1000,1,99,1)", []).unwrap();
    let (avant, registre) = (ptn_events_ingeres(&c), ptn_ledger_purges(&c));
    let e = purge_plan(&c, ptn_scope()).unwrap_err();
    assert_eq!(purge_refusal_code(&e), "cold_tier", "contrôle positif : {e}");

    crate::governance::temoin_de_presence::armer("cold_seal");
    let plan = purge_plan(&c, ptn_scope());
    let confirmation = purge_confirm_and_apply(&c, ptn_scope(), &jeton, "t", "témoin P10.31-x");
    crate::governance::temoin_de_presence::desarmer();
    match plan {
        Ok(p) => panic!("présence de `cold_seal` non lue : plan de {} ligne(s) rendu malgré le tier froid", p.rows()),
        Err(e) => {
            assert_eq!(purge_refusal_code(&e), "db", "lecture non faite : {e}");
            let m = e.to_string();
            assert!(m.contains("`cold_seal`") && m.contains("interrupted"), "le refus nomme la table et la cause : {m}");
        }
    }
    match confirmation {
        Ok(r) => panic!(
            "présence de `cold_seal` non lue : la confirmation a détruit {} ligne(s) du chaud, Parquet scellés lisibles",
            r.rows_deleted
        ),
        Err(e) => assert_eq!(purge_refusal_code(&e), "db", "la confirmation refuse par la même nature : {e}"),
    }
    assert_eq!(ptn_events_ingeres(&c), avant, "aucune ligne supprimée");
    assert_eq!(ptn_ledger_purges(&c), registre, "aucune inscription au registre");

    ptn_balayer_la_presence(&c, "cold_seal", "le tier froid");
    assert_eq!(ptn_events_ingeres(&c), avant, "aucune ligne supprimée sur le balayage");
}

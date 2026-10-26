// =====================================================================================
// `P10.31-x` (suite de vérification) — LA NATURE D'UN REFUS DE PURGE EST JUGÉE SUR LA RÉPONSE SERVIE.
//
// LE TROU (mesuré par la vérification indépendante) : le contrat « une lecture non faite a une seule nature,
// 500 » n'était témoigné que sur `statut_du_refus_de_purge`. `purge_refusal_response`, la seule fabrique de
// réponse des deux routes (`purge_plan_route`, `purge_apply_route`), pouvait reprendre son ancien `match` en
// ligne (`db` 500, tout le reste 409) sans qu'un seul test rougisse : mutant `RESP_NON_CABLE`, 2473/2473
// verts sur la suite complète.
//
// CE QUE CES TÉMOINS JUGENT :
//  - la RÉPONSE (statut ET corps) de `purge_refusal_response` pour CHAQUE variante de `PurgeRefusal` : 500 pour
//    `db`, `plan_row_unread`, `legal_hold_undetermined`, `legal_hold_unread` ; 400 pour `reason_required` ; 409
//    pour les décisions lues. Le corps porte `ok:false`, le code machine du SITE (pas `db` pour tous) et le
//    texte du refus — SAUF, depuis `P10.29-l`, pour `db`, `plan_row_unread` et `legal_hold_unread`, servis sous une
//    phrase fixe sans le texte du moteur (témoin inversé nommément : `prs_juger`). La table attendue est écrite ici, pas relue dans `statut_du_refus_de_purge` : un témoin
//    qui recopierait la fonction jugée ne jugerait rien ;
//  - des refus PRODUITS par le moteur, pas fabriqués : `plan_row_unread` et `db` atteints par un balayage
//    d'interruptions de `purge_plan` (qui atteint aussi `legal_hold_undetermined`), `legal_hold_unread` par un
//    nom de rétention en blob — chacun servi en 500 ;
//  - le CÂBLAGE : les deux routes rendent leurs refus par `purge_refusal_response` et ne fabriquent aucun 409
//    en ligne (lecture du source des deux corps de route).
// POURQUOI PAS LA ROUTE HTTP ENTIÈRE : elle n'est armée que par `PLUME_PURGE_API` dans l'environnement du
// processus ; le poser ferait courir `purge_http_surface_is_closed_by_default` (tests/purge.rs), qui ne prend
// pas le verrou d'environnement, sous `cargo test` (fils dans un même processus).
// MUTATIONS (jouées sous VERIF_MUT, retirées du source) : `RESP_NON_CABLE` (l'ancien `match` en ligne dans
// `purge_refusal_response`) rougit le témoin par variante et le témoin des refus produits ; `RESP_CODE_DB` (le
// corps dit `db` pour tout 500) rougit les mêmes par le corps.
// CE QUE CES TÉMOINS NE TIENNENT PAS : une route qui contournerait `purge_refusal_response` par un chemin que
// la lecture du source ne reconnaît pas ; la CLI (texte et code de sortie 3, pas de statut HTTP).
// =====================================================================================

fn prs_ins(c: &Connection, ts: i64, source: &str) {
    c.execute(
        "INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id) \
         VALUES(?1,?2,'test',1,'preuve','h1','prod','','')",
        params![ts, source],
    )
    .unwrap();
}

fn prs_scope() -> PurgeScope {
    let v = vec![("env".to_string(), "prod".to_string())];
    purge_scope_from_args(&v, "0", "2000", now()).expect("périmètre valide")
}

/// Statut et corps JSON de la réponse servie pour `e`.
async fn prs_servir(e: PurgeRefusal) -> (u16, serde_json::Value) {
    let r = purge_refusal_response(e);
    let statut = r.status().as_u16();
    let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    (statut, serde_json::from_slice(&octets).expect("corps JSON"))
}

/// `P10.29-l` — phrase servie pour une lecture non faite qui porte un texte du moteur, écrite ICI (pas relue dans
/// la constante de production).
const PRS_PHRASE_LECTURE_NON_FAITE: &str = "REFUS — lecture de la base NON FAITE : la purge n'a rien décidé, aucune \
     ligne supprimée. La cause est écrite au journal du démon.";

/// Phrase servie pour `db`, NEUTRE entre lecture et écriture (`db` porte aussi les écritures refusées de l'exécution),
/// écrite ICI.
const PRS_PHRASE_REFUS_DE_LA_BASE: &str = "REFUS — la base a refusé l'opération : la purge n'est pas faite, aucune ligne \
     supprimée. La cause est écrite au journal du démon, sous l'identifiant servi.";

/// Retire et rend le champ `id` d'un corps servi, après avoir jugé sa forme `plume-e<pid>-<n>`.
fn prs_retirer_l_identifiant(corps: &mut serde_json::Value, origine: &str) -> String {
    let id = corps.as_object_mut().and_then(|o| o.remove("id")).unwrap_or_else(|| panic!("{origine} : champ `id` servi : {corps}"));
    let id = id.as_str().unwrap_or_else(|| panic!("{origine} : `id` est une chaîne")).to_string();
    let reste = id.strip_prefix(&format!("plume-e{}-", std::process::id())).unwrap_or_else(|| panic!("{origine} : forme de `{id}`"));
    assert!(!reste.is_empty() && reste.bytes().all(|b| b.is_ascii_digit()), "{origine} : forme de `{id}`");
    id
}

/// Texte du moteur porté par le refus (`db`, `plan_row_unread`, `legal_hold_unread`), `None` pour les autres.
fn prs_texte_du_moteur(e: &PurgeRefusal) -> Option<String> {
    match e {
        PurgeRefusal::Db(t) | PurgeRefusal::LegalHoldUnread(t) => Some(t.clone()),
        PurgeRefusal::PlanRowUnread { cause, .. } => Some(cause.clone()),
        _ => None,
    }
}

/// Juge une réponse servie : statut attendu et corps ENTIER (`ok:false`, code machine du site, message).
/// INVERSÉ par `P10.29-l` : pour `db`, `plan_row_unread` et `legal_hold_unread`, le message n'est plus le texte du
/// refus (qui embarquait le texte du moteur) mais une phrase fixe (neutre pour `db`), le corps porte un `id` de
/// corrélation, et le texte du moteur est absent de TOUT le corps ; les autres variantes gardent leur corps à l'octet.
async fn prs_juger(e: PurgeRefusal, attendu: u16, origine: &str) {
    let code = purge_refusal_code(&e);
    let texte = e.to_string();
    let moteur = prs_texte_du_moteur(&e);
    let est_db = matches!(e, PurgeRefusal::Db(_));
    let (statut, mut corps) = prs_servir(e).await;
    assert_eq!(statut, attendu, "{origine} : `{code}` servi en {statut}, attendu {attendu} — corps {corps}");
    let message = match &moteur {
        Some(_) if est_db => PRS_PHRASE_REFUS_DE_LA_BASE.to_string(),
        Some(_) => PRS_PHRASE_LECTURE_NON_FAITE.to_string(),
        None => texte,
    };
    if moteur.is_some() {
        prs_retirer_l_identifiant(&mut corps, origine);
    }
    assert_eq!(
        corps,
        serde_json::json!({ "ok": false, "refusal": code, "message": message }),
        "{origine} : `{code}` : corps entier servi"
    );
    if let Some(m) = moteur {
        assert!(!m.is_empty(), "{origine} : instrument — le refus `{code}` porte un texte du moteur");
        assert!(!corps.to_string().contains(&m), "{origine} : `{code}` : le texte du moteur `{m}` hors du corps : {corps}");
    }
}

/// CHAQUE VARIANTE, SA RÉPONSE SERVIE. Le `match` exhaustif sans joker oblige à ranger ici toute variante
/// ajoutée à `PurgeRefusal` (sinon ce fichier ne compile plus).
#[tokio::test]
async fn prs_chaque_refus_est_servi_avec_sa_nature() {
    let variantes = vec![
        PurgeRefusal::LegalHold(vec!["litige".into()]),
        PurgeRefusal::LegalHoldUndetermined,
        PurgeRefusal::LegalHoldUnread("texte-du-moteur-hold".into()),
        PurgeRefusal::ColdTier { files: 1, days: 1 },
        PurgeRefusal::CitedByCase { ids: vec![1], total: 1 },
        PurgeRefusal::FtsDesync,
        PurgeRefusal::StaleToken { expected: "a".into(), got: "b".into() },
        PurgeRefusal::ReasonRequired,
        PurgeRefusal::CountMismatch { declared: 2, deleted: 1 },
        PurgeRefusal::PlanRowUnread { site: "sources", cause: "interrupted".into() },
        PurgeRefusal::TransactionNotOpened,
        PurgeRefusal::Db("interrupted".into()),
    ];
    let mut lecture_non_faite = 0;
    let mut moteur_hors_du_corps = 0;
    for e in variantes {
        let attendu = match &e {
            PurgeRefusal::Db(_)
            | PurgeRefusal::PlanRowUnread { .. }
            | PurgeRefusal::LegalHoldUndetermined
            | PurgeRefusal::LegalHoldUnread(_) => {
                lecture_non_faite += 1;
                500
            }
            PurgeRefusal::ReasonRequired => 400,
            // `P10.29-h` — transaction de la purge non ouverte : 503, comme une route dont le `BEGIN` est refusé.
            PurgeRefusal::TransactionNotOpened => 503,
            PurgeRefusal::LegalHold(_)
            | PurgeRefusal::ColdTier { .. }
            | PurgeRefusal::CitedByCase { .. }
            | PurgeRefusal::FtsDesync
            | PurgeRefusal::StaleToken { .. }
            | PurgeRefusal::CountMismatch { .. } => 409,
        };
        if prs_texte_du_moteur(&e).is_some() {
            moteur_hors_du_corps += 1;
        }
        prs_juger(e, attendu, "variante").await;
    }
    assert_eq!(lecture_non_faite, 4, "instrument : les quatre formes de lecture non faite sont jugées");
    assert_eq!(moteur_hors_du_corps, 3, "instrument : les trois classes qui portent un texte du moteur sont jugées");
}

/// DES REFUS PRODUITS PAR LE MOTEUR, SERVIS EN 500 : balayage d'interruptions de `purge_plan` sur une base
/// sans motif de refus (`db` et `plan_row_unread` atteints), puis une rétention légale au nom illisible
/// (`legal_hold_unread`).
#[tokio::test]
async fn prs_refus_produits_par_le_moteur_servis_en_500() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let c = test_db();
    for i in 0..6 {
        prs_ins(&c, 1_000 + i, if i < 3 { "flux-a" } else { "flux-b" });
    }
    let compte = std::sync::Arc::new(AtomicU64::new(0));
    let k = compte.clone();
    c.progress_handler(
        1,
        Some(move || {
            k.fetch_add(1, Ordering::Relaxed);
            false
        }),
    );
    purge_plan(&c, prs_scope()).expect("plan nominal sous rappel inerte");
    c.progress_handler(0, None::<fn() -> bool>);
    let total = compte.load(Ordering::Relaxed);
    let mut produits: Vec<PurgeRefusal> = Vec::new();
    for cible in 1..=total {
        let n = AtomicU64::new(0);
        c.progress_handler(1, Some(move || n.fetch_add(1, Ordering::Relaxed) + 1 == cible));
        let r = purge_plan(&c, prs_scope());
        c.progress_handler(0, None::<fn() -> bool>);
        if let Err(e) = r {
            produits.push(e);
        }
    }
    let codes: std::collections::BTreeSet<&'static str> = produits.iter().map(purge_refusal_code).collect();
    assert!(
        codes.contains("db") && codes.contains("plan_row_unread"),
        "précondition : le balayage ({total} passages) atteint les deux formes de lecture : {codes:?}"
    );
    for e in produits {
        prs_juger(e, 500, "balayage d'interruptions").await;
    }

    let c = test_db();
    prs_ins(&c, 1_000, "sshd");
    prs_ins(&c, 1_000, "flux-de-test");
    c.execute(
        "INSERT INTO legal_hold(name,reason,scope_source,scope_start_ts,scope_end_ts,active,created,created_by) \
         VALUES(X'FFFE','','sshd',0,0,1,0,'admin')",
        [],
    )
    .unwrap();
    let e = purge_plan(&c, prs_scope()).expect_err("une rétention au nom illisible refuse le plan");
    assert_eq!(purge_refusal_code(&e), "legal_hold_unread", "précondition : refus produit `{e}`");
    prs_juger(e, 500, "rétention légale illisible").await;
}

/// LE CÂBLAGE : les deux routes rendent leurs refus par `purge_refusal_response` et ne fabriquent aucun 409 en
/// ligne. Lu sur le source servi (le corps de chaque route, jusqu'à la fonction suivante).
#[test]
fn prs_les_deux_routes_servent_par_la_fabrique_de_reponse() {
    let source = include_str!("../handlers/purge.rs");
    for route in ["purge_plan_route", "purge_apply_route"] {
        let debut = source.find(&format!("async fn {route}(")).unwrap_or_else(|| panic!("route `{route}` trouvée"));
        let reste = &source[debut + 1..];
        let fin = ["\nfn ", "\npub(crate) ", "\npub fn ", "\nasync fn "]
            .iter()
            .filter_map(|m| reste.find(m))
            .min()
            .unwrap_or(reste.len());
        let corps = &reste[..fin];
        assert!(
            corps.contains("Err(e) => purge_refusal_response(e)"),
            "`{route}` rend ses refus par `purge_refusal_response`"
        );
        assert!(!corps.contains("CONFLICT"), "`{route}` ne fabrique aucun 409 en ligne");
        assert!(!corps.contains("INTERNAL_SERVER_ERROR"), "`{route}` ne fabrique aucun 500 en ligne");
    }
}

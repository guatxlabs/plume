// =====================================================================================
// `P10.20-b` (rang deux, reste) — LES DEUX DERNIÈRES FONCTIONS DE RANG DEUX HORS DES DOSSIERS.
//
// CE QUI ÉTAIT FAUX, MESURÉ SUR 2393908 (garde `check_a_single_row_read_that_failed_is_never_served_as_a_fact.py`,
// classe 3, trois entrées : `case_create` — lot voisin —, `connector_poll`, `attach_runbook`) :
//   * `connector_poll` (`connectors/mod.rs`) : `last_count`/`last_error` relus APRÈS le poll par
//     `.unwrap_or((0, None))` — une relecture ratée servait `{ok: true, count: 0, error: null}` (« poll réussi,
//     zéro event ») ET gravait `count=0` dans la ligne d'audit `config.connector.poll` ;
//   * `attach_runbook` (`incidents.rs`) : le compte des étapes déjà attachées lu `.unwrap_or(0)` — sur une
//     lecture ratée la garde « un runbook est déjà attaché (progression existante) » était SAUTÉE et les étapes
//     s'inséraient EN DOUBLE ; l'existence du dossier lue `.is_err()` rendait « incident introuvable » (400)
//     sur une lecture refusée.
//
// LA FORME DU CORRECTIF : `connector_poll` prend celle de `destination_flush` (`null` + `etat_non_relu`, deux
// causes — lecture ratée, connecteur supprimé pendant le poll —, trace « NON RELU » avec `motif_non_relu`) ;
// `attach_runbook` scrute ses deux lectures : absence établie = refus d'avant, lecture refusée =
// `RefusDAttache::NonLu` (cause constante, 503 côté route), rien d'écrit — ni étape, ni chronologie, ni registre.
//
// LES VOIES DE L'ÉCHEC : une VUE TEMPORAIRE qui coiffe `incident` (la préparation échoue) ; un AUTORISATEUR qui
// refuse la LECTURE de `case_step` sans refuser son ÉCRITURE — c'est ce qui laisse la forme d'avant DOUBLER la
// progression sous mutation (une vue coiffant `case_step` aurait aussi refusé l'insertion et masqué le doublon) ;
// un BLOB dans `last_count` (le mappeur refuse, la requête est saine) et un déclencheur qui supprime le
// connecteur pendant le poll. Une vue coiffant `connector` n'est PAS jouable : la même table porte la définition
// lue AVANT le poll, et la vue ferait refuser le poll (404) au lieu de la relecture.
//
// CE QUE CE LOT NE TIENT PAS :
//   * la CONSOLE n'est pas jugée : `web/connectors.js` ne lit pas `etat_non_relu` (un `ok: null` y serait peint
//     comme il l'interprète) ; la console des dossiers peint un 503 d'attache par sa cause, sans lecture dédiée ;
//   * le `.ok()` sur la DÉFINITION du connecteur reste (fail-closed, 404 à cause fausse), déplacé au rang quatre ;
//   * la lecture du runbook dans `attach_runbook` (`.map_err(|_| "runbook introuvable")`) rend toujours 400
//     « introuvable » sur une lecture refusée : cause fausse, aucun fait inventé, hors de la garde (elle propage) ;
//   * `case_create` (lot voisin), `step_advance` et les rangs trois et quatre ne sont pas touchés.
// =====================================================================================

fn lqr_adm() -> AuthUser {
    AuthUser { name: "adm".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false, method: "cookie".into(), csrf: String::new(), env: None }
}

async fn lqr_corps(r: Response) -> (u16, Value) {
    let statut = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
    (statut, corps)
}

/// Refuse la LECTURE de `case_step` (et elle seule) : l'insertion reste permise.
fn lqr_lecture_des_etapes_refusee(conn: &Connection) {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
        AuthAction::Read { table_name, .. } if table_name == "case_step" => Authorization::Deny,
        _ => Authorization::Allow,
    }));
}

fn lqr_autorisateur_leve(conn: &Connection) {
    use rusqlite::hooks::{AuthContext, Authorization};
    conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
}

/// (étapes, items de chronologie « runbook », lignes de registre d'attache) du dossier.
fn lqr_traces(conn: &Connection, id: i64) -> (i64, i64, i64) {
    let n = |sql: &str| -> i64 { conn.query_row(sql, params![id], |r| r.get(0)).expect("compte de témoin") };
    (
        n("SELECT COUNT(*) FROM case_step WHERE incident_id=?1"),
        n("SELECT COUNT(*) FROM incident_item WHERE incident_id=?1 AND kind='runbook'"),
        conn.query_row("SELECT COUNT(*) FROM ledger WHERE kind='case.runbook_attach'", [], |r| r.get(0)).expect("compte du registre"),
    )
}

// -------------------------------------------------------------------------------------
// (1) `attach_runbook` — une progression non lue n'est pas une progression absente
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : un dossier dont le runbook est déjà attaché (une étape posée par le geste réel). Témoin
/// INVERSE d'abord : lecture faite, le second essai rend le refus d'avant (« progression existante »), rien
/// d'écrit. Puis la lecture de `case_step` REFUSÉE (autorisateur ; l'écriture reste permise) : refus
/// `NonLu(CAUSE_PROGRESSION_NON_LUE_POUR_L_ATTACHE)`, et la progression n'est PAS doublée — étapes, chronologie et
/// registre comptés avant/après. Puis l'existence du dossier non lue (vue temporaire coiffant `incident`) :
/// `NonLu(CAUSE_DOSSIER_NON_LU_POUR_L_ATTACHE)`, jamais « incident introuvable » ; un identifiant absent rend
/// toujours « incident introuvable » (absence établie). Enfin le chemin nominal : un dossier neuf s'attache.
///
/// LES MUTATIONS QUI LE FONT ROUGIR : la mutation `attache_zero` (zéro fabriqué : l'attache passe et DOUBLE
/// l'étape) ; la mutation `attache_existence` (lecture refusée rendue « incident introuvable »).
#[test]
fn lqr_attach_runbook_ne_double_pas_une_progression_non_lue() {
    let conn = test_db();
    let (id, rb) = lqd_dossier_avec_runbook_attache(&conn);
    let avant = lqr_traces(&conn, id);
    assert_eq!(avant.0, 1, "fixture : une étape attachée");

    // TÉMOIN INVERSE — la progression est LUE : refus d'avant, inchangé.
    match attach_runbook(&conn, id, rb, "adm", &PrefillTargets::default()) {
        Err(RefusDAttache::Refuse(r)) => assert!(r.contains("progression existante"), "refus d'avant : {r}"),
        autre => panic!("une progression LUE refuse comme avant : {autre:?}"),
    }
    assert_eq!(lqr_traces(&conn, id), avant, "rien d'écrit sur le refus d'avant");

    // LA PROGRESSION NON LUE.
    lqr_lecture_des_etapes_refusee(&conn);
    let r = attach_runbook(&conn, id, rb, "adm", &PrefillTargets::default());
    lqr_autorisateur_leve(&conn);
    match &r {
        Err(RefusDAttache::NonLu(c)) => assert_eq!(*c, CAUSE_PROGRESSION_NON_LUE_POUR_L_ATTACHE, "cause nommée"),
        autre => panic!("une progression NON LUE est un refus nommé, jamais une attache : {autre:?}"),
    }
    assert_eq!(r.as_ref().map_err(|e| e.to_string()).unwrap_err(), CAUSE_PROGRESSION_NON_LUE_POUR_L_ATTACHE, "Display = la cause");
    assert_eq!(lqr_traces(&conn, id), avant, "la progression existante n'est PAS doublée, ni chronologie ni registre écrits");

    // L'EXISTENCE NON LUE — la vue temporaire coiffe `incident` (colonne `id` absente : la préparation échoue).
    conn.execute_batch("CREATE TEMP VIEW incident AS SELECT 1 AS autre;").expect("fixture : vue");
    let r = attach_runbook(&conn, id, rb, "adm", &PrefillTargets::default());
    conn.execute_batch("DROP VIEW temp.incident;").expect("fixture : vue retirée");
    match r {
        Err(RefusDAttache::NonLu(c)) => assert_eq!(c, CAUSE_DOSSIER_NON_LU_POUR_L_ATTACHE),
        autre => panic!("une existence NON LUE n'est pas « incident introuvable » : {autre:?}"),
    }
    assert_eq!(lqr_traces(&conn, id), avant, "rien d'écrit sur l'existence non lue");

    // L'ABSENCE ÉTABLIE reste l'absence.
    match attach_runbook(&conn, 987_654, rb, "adm", &PrefillTargets::default()) {
        Err(RefusDAttache::Refuse(r)) => assert_eq!(r, "incident introuvable"),
        autre => panic!("un dossier absent reste « incident introuvable » : {autre:?}"),
    }

    // CHEMIN NOMINAL — un dossier sans progression s'attache, une étape, chronologie et registre écrits.
    let neuf = dossier_seme(&conn, "adm", "intrusion-neuve", 4, "", None, 2);
    let n = attach_runbook(&conn, neuf, rb, "adm", &PrefillTargets::default()).expect("le dossier neuf s'attache");
    assert_eq!(n, 1);
    let apres = lqr_traces(&conn, neuf);
    assert_eq!((apres.0, apres.1, apres.2), (1, 1, avant.2 + 1), "attache nominale entière : {apres:?}");
}

/// CE QU'IL TIENT : la ROUTE rend 503 avec la cause (ni 400 « progression existante », ni 200 `attached`),
/// rien d'écrit ; l'autorisateur levé, elle rend le 400 d'avant.
///
/// LA MUTATION QUI LE FAIT ROUGIR : la mutation `attache_zero` (200 `attached: 1`, étape doublée).
#[tokio::test]
async fn lqr_la_route_d_attache_refuse_en_503_sur_une_progression_non_lue() {
    let (st, _p) = sp_state("lqr-attache");
    let (id, rb) = lqd_dossier_avec_runbook_attache(&st.db.lock());
    let avant = lqr_traces(&st.db.lock(), id);
    lqr_lecture_des_etapes_refusee(&st.db.lock());
    let (statut, corps) = lqr_corps(case_runbook_attach(State(st.clone()), Extension(lqr_adm()), Path(id), Json(json!({ "runbook_id": rb }))).await).await;
    lqr_autorisateur_leve(&st.db.lock());
    assert_eq!(statut, 503, "progression non lue : 503 nommé : {corps}");
    assert!(corps.to_string().contains(CAUSE_PROGRESSION_NON_LUE_POUR_L_ATTACHE), "la cause est servie : {corps}");
    assert_eq!(lqr_traces(&st.db.lock(), id), avant, "rien d'écrit");
    let (statut, corps) = lqr_corps(case_runbook_attach(State(st.clone()), Extension(lqr_adm()), Path(id), Json(json!({ "runbook_id": rb }))).await).await;
    assert_eq!(statut, 400, "lecture faite : le refus d'avant : {corps}");
    assert!(corps.to_string().contains("progression existante"), "{corps}");
}

// -------------------------------------------------------------------------------------
// (2) `connector_poll` — un bilan de poll non relu n'est ni « zéro event » ni écrit comme tel
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : connecteur de type inconnu (aucun réseau ; le poll n'écrit que `last_run`/`last_error`).
/// Contrôle positif : `last_count=7` relu, corps `{ok: false, count: 7, error: <cause du poll>}` sans
/// `etat_non_relu`, trace « (count=7) ». Puis `last_count` illisible (BLOB) : corps `ok`, `count`, `error` à
/// `null` + `etat_non_relu` = `CAUSE_ETAT_DU_POLL_MANUEL_NON_RELU`, registre et event « NON RELU » sans `count=`,
/// champs `count`/`ok` nuls, motif `relecture en échec`. Puis le connecteur supprimé pendant le poll
/// (déclencheur) : `CAUSE_CONNECTEUR_SUPPRIME_PENDANT_LE_POLL`, motif propre.
///
/// LES MUTATIONS QUI LE FONT ROUGIR : la mutation `poll_zero` (`(0, None)` fabriqué : `ok: true, count: 0`) ;
/// la mutation `poll_norows` (ligne disparue servie sous la cause de la lecture ratée).
#[tokio::test]
async fn lqr_le_bilan_du_poll_manuel_non_relu_n_est_ni_servi_ni_ecrit() {
    let (st, _p) = sp_state("lqr-poll");
    let id = {
        let conn = st.db.lock();
        conn.execute("INSERT INTO connector(type,name,enabled,last_count) VALUES('lqr-inconnu','lqr-connecteur',0,7)", []).expect("connecteur");
        conn.last_insert_rowid()
    };
    let derniere_trace = |st: &AppState| -> String {
        st.db.lock().query_row("SELECT detail FROM ledger WHERE kind='config.connector.poll' ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).expect("trace écrite")
    };
    let dernier_event = |st: &AppState| -> (String, Value) {
        let (m, f): (String, String) = st.db.lock()
            .query_row("SELECT message, fields FROM event WHERE source='plume-config' AND message LIKE '%poll manuel du connecteur externe%' ORDER BY id DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("event de contrôle écrit");
        (m, serde_json::from_str(&f).expect("champs JSON"))
    };

    // CONTRÔLE POSITIF — l'état est relu, servi tel quel.
    let (statut, nominal) = lqr_corps(connector_poll(State(st.clone()), Extension(lqr_adm()), Path(id)).await).await;
    assert_eq!(statut, 200, "{nominal}");
    assert_eq!(nominal["count"], json!(7), "compte LU : {nominal}");
    assert_eq!(nominal["ok"], json!(false), "issue LUE (type inconnu) : {nominal}");
    assert!(nominal["error"].as_str().is_some_and(|e| e.contains("non supporté")), "erreur LUE : {nominal}");
    assert!(nominal.get("etat_non_relu").is_none(), "chemin nominal MUET : {nominal}");
    assert!(derniere_trace(&st).contains("(count=7)"), "trace nominale : {}", derniere_trace(&st));

    // LA RELECTURE ÉCHOUE — `last_count` porte un BLOB (le poll d'un type inconnu ne le réécrit pas).
    st.db.lock().execute_batch(&format!("UPDATE connector SET last_count=x'FF' WHERE id={id};")).expect("fixture");
    let (statut, avoue) = lqr_corps(connector_poll(State(st.clone()), Extension(lqr_adm()), Path(id)).await).await;
    assert_eq!(statut, 200, "le poll a eu lieu : {avoue}");
    assert_eq!(avoue["etat_non_relu"], json!(CAUSE_ETAT_DU_POLL_MANUEL_NON_RELU), "aveu NOMMÉ : {avoue}");
    for champ in ["ok", "count", "error"] {
        assert_eq!(avoue[champ], Value::Null, "`{champ}` non relu : jamais une valeur fabriquée : {avoue}");
    }
    let trace = derniere_trace(&st);
    assert!(trace.contains("NON RELU") && !trace.contains("count="), "le registre avoue, sans compte : {trace}");
    assert!(trace.contains("relecture en échec"), "registre : cause nommée : {trace}");
    let (message, champs) = dernier_event(&st);
    assert!(message.contains("NON RELUS") && !message.contains("event(s)"), "event : le message avoue sans compte : {message}");
    assert_eq!(champs["count"], Value::Null, "event : aucun compte affirmé : {champs}");
    assert_eq!(champs["ok"], Value::Null, "event : aucune issue affirmée : {champs}");
    assert_eq!(champs["etat_non_relu"], json!(true), "{champs}");
    assert_eq!(champs["motif_non_relu"], json!("relecture en échec"), "{champs}");

    // LE CONNECTEUR DISPARAÎT PENDANT LE POLL.
    let id2 = {
        let conn = st.db.lock();
        conn.execute("INSERT INTO connector(type,name,enabled) VALUES('lqr-inconnu','lqr-disparu',0)", []).expect("connecteur");
        conn.last_insert_rowid()
    };
    st.db.lock().execute_batch(&format!("CREATE TEMP TRIGGER lqr_supprime AFTER UPDATE OF last_run ON connector WHEN NEW.id={id2} \
                                         BEGIN DELETE FROM connector WHERE id=NEW.id; END;")).expect("fixture");
    let (statut, disparu) = lqr_corps(connector_poll(State(st.clone()), Extension(lqr_adm()), Path(id2)).await).await;
    st.db.lock().execute_batch("DROP TRIGGER temp.lqr_supprime;").expect("fixture");
    assert_eq!(statut, 200, "{disparu}");
    let n: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM connector WHERE id=?1", [id2], |r| r.get(0)).expect("compte");
    assert_eq!(n, 0, "fixture : le connecteur a bien été supprimé pendant le poll");
    assert_eq!(disparu["etat_non_relu"], json!(CAUSE_CONNECTEUR_SUPPRIME_PENDANT_LE_POLL), "ligne disparue : sa cause propre : {disparu}");
    for champ in ["ok", "count", "error"] {
        assert_eq!(disparu[champ], Value::Null, "`{champ}` non relu : {disparu}");
    }
    let trace = derniere_trace(&st);
    assert!(trace.contains("connecteur supprimé pendant le poll") && !trace.contains("relecture en échec"), "registre : cause propre : {trace}");
    let (_, champs) = dernier_event(&st);
    assert_eq!(champs["motif_non_relu"], json!("connecteur supprimé pendant le poll"), "{champs}");
}

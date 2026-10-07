// =====================================================================================
// `P10.20-b` (rang deux, suite) — TROIS FONCTIONS QUI SERVAIENT UNE VALEUR FABRIQUÉE SUR UNE LECTURE RATÉE.
//
// CE QUI ÉTAIT FAUX, MESURÉ SUR 94e36aa :
//   * `retention_preview` (`admin_ui.rs`) : cinq `.unwrap_or((0i64, None))` — une table illisible se lisait
//     « 0 ligne à purger », servi à l'opérateur JUSTE AVANT qu'il décide d'une baisse de rétention ;
//   * `destination_flush` (`destinations.rs`) : `.unwrap_or((watermark, 0, None))` sur l'état relu après
//     l'envoi — « 0 event, filigrane inchangé, succès » servi dans le corps ET écrit dans la ligne d'audit
//     de gouvernance `P11.13-c`, sans que rien n'ait été relu ;
//   * `playbooks_list` (`playbooks.rs`) : `plume_mode` lu `.unwrap_or_else(|_| "observe")` — la console
//     disait « ce playbook PROPOSE » d'un démon peut-être `active` qui EXÉCUTE.
//
// LA FORME DU CORRECTIF (celle de `compute_freshness` et de `risk_entity_timeline`) : la lecture est un
// `Result` ; sur échec, la valeur servie est `null` et un champ NOMMÉ avoue la cause (`deleted_non_lu`,
// `etat_non_relu`, `mode_non_lu`). Sur le chemin nominal aucun de ces champs n'existe : le corps est celui
// d'avant, et un aveu inconditionnel est impossible. Chaque témoin porte son contrôle POSITIF dans le même
// corps, et le TÉMOIN INVERSE qui compte : une table VIDE rend toujours `0`, une ligne de mode ABSENTE rend
// toujours `observe` (mode jamais posé = observation établie, la règle de `mode_get`).
//
// LES DEUX VOIES DE L'ÉCHEC (reprises de `lectures_uniques_avouees_rang_deux.rs`, préfixe `lqd_`) : une VUE
// TEMPORAIRE qui coiffe la table réelle sur l'écrivain (la préparation échoue : colonne absente), et une
// ligne ILLISIBLE (un `BLOB` ou un réel là où le mappeur lit un entier ou un texte : le mappeur échoue, la
// requête reste saine). La vue se retire et la lecture revient : l'aveu suit l'état de la base, rien d'autre.
//
// CE QUE CE LOT NE TIENT PAS :
//   * la CONSOLE n'est pas jugée et n'a pas été touchée. `web/retention.js:130` (`retPreviewText`) écrirait
//     « supprimera null … » sur un aperçu non lu (il ne lit pas `deleted_non_lu`) ; `web/detection_admin.js`
//     (`loadPlaybooks`) fait `d.mode || 'observe'` et peindrait encore « PROPOSE » sur `mode: null` ;
//     `web/destinations.js` (`flushDestination`) lirait `ok: null` comme un ÉCHEC avec la cause « erreur ».
//     Trois surfaces nommées pour un lot console ;
//   * les autres sites de rang deux de la garde (`case_create`, `connector_poll`, `attach_runbook`) et le
//     jumeau de rang trois `run_playbooks` ne sont pas touchés ;
//   * le `.ok()` sur la DÉFINITION de la destination (`destination_flush`) reste : fail-closed (404 à cause
//     fausse), déplacé au rang quatre de la garde.
// =====================================================================================

fn lqe_ecrire(st: &AppState, sql: &str) {
    let conn = st.db.lock();
    conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
}

fn lqe_adm() -> AuthUser {
    AuthUser { name: "adm".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false, method: "cookie".into(), csrf: String::new(), env: None }
}

async fn lqe_corps(r: Response) -> (u16, Value) {
    let statut = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
    (statut, corps)
}

async fn lqe_apercu(st: &AppState, cle: &str, valeur: i64) -> Value {
    let q = Query(HashMap::from([("key".to_string(), cle.to_string()), ("value".to_string(), valeur.to_string())]));
    let (statut, corps) = lqe_corps(retention_preview(State(st.clone()), Extension(lqe_adm()), q).await).await;
    assert_eq!(statut, 200, "l'aperçu répond : {corps}");
    corps
}

// -------------------------------------------------------------------------------------
// (1) `retention_preview` — un compte qui n'a pas eu lieu n'est pas « rien à purger »
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : sur la famille `alert_days`, une table VIDE rend `deleted: 0` (témoin inverse), une
/// alerte close ancienne rend `deleted: 1` et son ancienneté (contrôle positif), et une table coiffée par
/// une vue illisible rend `deleted: null`, `oldest: null` et `deleted_non_lu` nommant la cause ET la
/// famille — `deleted_kind`, `approx` et `destructive` inchangés. Retirée, la vue rend le compte de nouveau.
/// Puis LES CINQ familles une à une (un site par famille), et la voie du MAPPEUR sur `event_rollup`.
///
/// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=retention_zero` rétablit le zéro fabriqué sur l'échec.
#[tokio::test]
async fn p10_20b_l_apercu_de_retention_non_lu_ne_sert_pas_zero() {
    let (st, _p) = sp_state("lqe-retention");

    // TÉMOIN INVERSE — une table vide : zéro est un FAIT, et rien n'est avoué.
    let vide = lqe_apercu(&st, "alert_days", 30).await;
    assert_eq!(vide["deleted"], json!(0), "table vide : rien à purger, et c'est établi : {vide}");
    assert_eq!(vide["oldest"], Value::Null, "table vide : pas d'ancienneté : {vide}");
    assert!(vide.get("deleted_non_lu").is_none(), "chemin nominal MUET : {vide}");

    // CONTRÔLE POSITIF — une alerte close ancienne est comptée.
    lqe_ecrire(&st, "INSERT INTO alert(ts,rule,severity,title,status) VALUES(1000,'rule.lqe',2,'close','closed');");
    let lu = lqe_apercu(&st, "alert_days", 30).await;
    assert_eq!(lu["deleted"], json!(1), "une alerte close ancienne serait purgée : {lu}");
    assert_eq!(lu["oldest"], json!(1000), "son ancienneté est servie : {lu}");
    assert!(lu.get("deleted_non_lu").is_none(), "chemin nominal MUET : {lu}");

    // LA TABLE COIFFÉE : la préparation échoue (colonne absente de la vue).
    lqe_ecrire(&st, "CREATE TEMP VIEW alert AS SELECT 1 AS autre;");
    let avoue = lqe_apercu(&st, "alert_days", 30).await;
    assert_eq!(avoue["deleted"], Value::Null, "lecture ratée : jamais « 0 à purger » : {avoue}");
    assert_eq!(avoue["oldest"], Value::Null, "lecture ratée : pas d'ancienneté inventée : {avoue}");
    let cause = avoue["deleted_non_lu"].as_str().unwrap_or_else(|| panic!("l'aveu est NOMMÉ : {avoue}"));
    assert!(cause.starts_with(CAUSE_APERCU_DE_RETENTION_NON_LU), "la cause est celle du démon : {cause}");
    assert!(cause.contains("alerts_closed"), "la cause nomme la FAMILLE non lue : {cause}");
    assert_eq!(avoue["deleted_kind"], json!("alerts_closed"), "le genre reste servi : {avoue}");
    assert_eq!(avoue["approx"], json!(false), "`approx` inchangé : {avoue}");
    assert_eq!(avoue["destructive"], json!(true), "`destructive` dérive des réglages, pas du compte : {avoue}");
    lqe_ecrire(&st, "DROP VIEW temp.alert;");
    let revenu = lqe_apercu(&st, "alert_days", 30).await;
    assert_eq!(revenu["deleted"], json!(1), "vue retirée : le compte revient — l'aveu suit la base : {revenu}");

    // LES CINQ FAMILLES, une par une : chaque site avoue sa propre famille.
    for (cle, valeur, table, genre) in [
        ("retention_days", 7, "event_rollup", "events"),
        ("snapshot_days", 7, "snapshot", "snapshots"),
        ("alert_days", 30, "alert", "alerts_closed"),
        ("metric_days", 7, "metric_rollup", "metric_rollups"),
        ("metric_raw_hours", 24, "metric", "metrics_raw"),
    ] {
        let nominal = lqe_apercu(&st, cle, valeur).await;
        assert!(nominal["deleted"].is_i64() && nominal.get("deleted_non_lu").is_none(), "{cle} : contrôle positif, un compte LU : {nominal}");
        lqe_ecrire(&st, &format!("CREATE TEMP VIEW {table} AS SELECT 1 AS autre;"));
        let a = lqe_apercu(&st, cle, valeur).await;
        assert_eq!(a["deleted"], Value::Null, "{cle} : lecture ratée, jamais un zéro : {a}");
        assert!(
            a["deleted_non_lu"].as_str().map(|c| c.starts_with(CAUSE_APERCU_DE_RETENTION_NON_LU) && c.contains(genre)).unwrap_or(false),
            "{cle} : l'aveu nomme la famille `{genre}` : {a}"
        );
        lqe_ecrire(&st, &format!("DROP VIEW temp.{table};"));
    }

    // LA VOIE DU MAPPEUR : la requête est saine, `SUM` d'un texte rend un RÉEL que le mappeur refuse en entier.
    lqe_ecrire(&st, "CREATE TEMP VIEW event_rollup AS SELECT 0 AS bucket, 'x' AS n;");
    let m = lqe_apercu(&st, "retention_days", 7).await;
    assert_eq!(m["deleted"], Value::Null, "mappeur en échec : jamais un zéro : {m}");
    assert_eq!(m["approx"], json!(true), "`approx` inchangé sur la famille events : {m}");
    assert!(m["deleted_non_lu"].as_str().map(|c| c.contains("events")).unwrap_or(false), "l'aveu nomme `events` : {m}");
    lqe_ecrire(&st, "DROP VIEW temp.event_rollup;");
}

// -------------------------------------------------------------------------------------
// (2) `destination_flush` — un bilan d'envoi non relu n'est ni servi ni écrit au registre
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : contrôle positif d'abord — l'envoi manuel d'une destination `s3` (stub, aucun réseau)
/// sert un filigrane et un compte LUS, sans `etat_non_relu`, et sa trace porte « 0 event(s), watermark 0 ->
/// 0 ». Puis `last_count` illisible (un BLOB, que le stub ne réécrit pas) : la relecture d'après coup échoue,
/// le corps sert `etat_non_relu` (cause du démon) et des `null` — ni `forwarded: 0`, ni filigrane, ni issue —
/// et la trace d'audit (registre ET event `plume-config`) dit « NON RELUS », sans compte ni filigrane
/// d'arrivée affirmés ; le filigrane d'AVANT (42, NON NUL pour qu'un zéro fabriqué rougisse), lu avant l'envoi, y
/// reste — dans le registre, le message ET le champ `watermark_before` — avec le motif `relecture en échec`.
///
/// Puis la destination SUPPRIMÉE pendant l'envoi (déclencheur temporaire) : sa cause propre
/// (`CAUSE_DESTINATION_SUPPRIMEE_PENDANT_L_ENVOI`), jamais le renvoi « relisez la liste » de la lecture ratée ; le
/// registre et l'event portent le motif `destination supprimée pendant l'envoi`.
///
/// LES MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=flush_fabrique` rétablit `(watermark, 0, None)` sur l'échec ;
/// `DF_TRACE_MSG` (message d'event « 0 event(s) … ») ; `DF_TRACE_OK` (`ok: true` au registre) ; `FLUSH_NOROWS`
/// (ligne disparue servie sous la cause de la lecture ratée) ; `F13_WM_AVANT_ZERO` / `F15_MSG_WM_AVANT_ZERO` (zéro
/// écrit à la place du filigrane d'avant, registre / message) ; `F14_TRACE_SANS_WMB` (champ `watermark_before`
/// retiré) ; `MOTIF_FUSIONNE` (un seul motif pour les deux causes).
#[tokio::test]
async fn p10_20b_le_bilan_d_envoi_manuel_non_relu_n_est_ni_servi_ni_ecrit() {
    let (st, _p) = sp_state("lqe-flush");
    let did = {
        let conn = st.db.lock();
        conn.execute("INSERT INTO destination(type,name,enabled,endpoint) VALUES('s3','lqe-stub',1,'s3://lqe')", []).expect("destination");
        conn.last_insert_rowid()
    };
    let derniere_trace = |st: &AppState| -> String {
        st.db.lock().query_row("SELECT detail FROM ledger WHERE kind='config.destination.flush' ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).expect("trace écrite")
    };
    // L'event `plume-config` : son MESSAGE et ses CHAMPS sont jugés tous deux (le message n'est pas qu'un sélecteur).
    let dernier_event = |st: &AppState| -> (String, Value) {
        let (m, f): (String, String) = st.db.lock()
            .query_row("SELECT message, fields FROM event WHERE source='plume-config' AND message LIKE '%forward MANUEL%' ORDER BY id DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("event de contrôle écrit");
        (m, serde_json::from_str(&f).expect("champs JSON"))
    };

    // CONTRÔLE POSITIF — l'état est relu.
    let (statut, nominal) = lqe_corps(destination_flush(State(st.clone()), Extension(lqe_adm()), Path(did)).await).await;
    assert_eq!(statut, 200, "l'envoi manuel répond : {nominal}");
    assert_eq!(nominal["watermark"], json!(0), "filigrane LU : {nominal}");
    assert_eq!(nominal["forwarded"], json!(0), "compte LU (le stub n'envoie rien) : {nominal}");
    assert!(nominal.get("etat_non_relu").is_none(), "chemin nominal MUET : {nominal}");
    let trace = derniere_trace(&st);
    assert!(trace.contains("0 event(s), watermark 0 -> 0"), "la trace nominale porte le bilan LU : {trace}");

    // LA RELECTURE ÉCHOUE : `last_count` porte un BLOB que le mappeur refuse en entier. Le filigrane d'AVANT est
    // NON NUL (42) : un zéro fabriqué dans la trace ne peut plus passer pour le filigrane lu.
    lqe_ecrire(&st, &format!("UPDATE destination SET last_count=x'FF', watermark=42 WHERE id={did};"));
    let (statut, avoue) = lqe_corps(destination_flush(State(st.clone()), Extension(lqe_adm()), Path(did)).await).await;
    assert_eq!(statut, 200, "l'envoi a eu lieu, la réponse le dit : {avoue}");
    assert_eq!(avoue["etat_non_relu"], json!(CAUSE_ETAT_DE_L_ENVOI_MANUEL_NON_RELU), "l'aveu est NOMMÉ : {avoue}");
    for champ in ["ok", "forwarded", "watermark", "last_error"] {
        assert_eq!(avoue[champ], Value::Null, "`{champ}` non relu : jamais une valeur fabriquée : {avoue}");
    }
    let trace = derniere_trace(&st);
    assert!(trace.contains("NON RELUS"), "la trace d'audit AVOUE : {trace}");
    assert!(!trace.contains("event(s)"), "la trace n'affirme aucun compte : {trace}");
    assert!(trace.contains("watermark avant : 42"), "le filigrane d'AVANT, lu avant l'envoi, reste : {trace}");
    assert!(trace.contains("relecture en échec"), "le registre nomme la cause (lecture ratée) : {trace}");
    let (message, champs) = dernier_event(&st);
    assert!(message.contains("NON RELUS"), "event de contrôle : le MESSAGE avoue : {message}");
    assert!(!message.contains("event(s)") && !message.contains("->"), "event de contrôle : le message n'affirme ni compte ni filigrane d'arrivée : {message}");
    assert!(message.contains("watermark avant : 42"), "event de contrôle : le filigrane d'AVANT reste : {message}");
    assert!(message.contains("relecture en échec"), "event de contrôle : la cause est nommée : {message}");
    assert_eq!(champs["watermark_before"], json!(42), "event de contrôle : le filigrane d'AVANT, LU, est un champ : {champs}");
    assert_eq!(champs["motif_non_relu"], json!("relecture en échec"), "event de contrôle : la cause se filtre : {champs}");
    assert_eq!(champs["ok"], Value::Null, "event de contrôle : aucune issue affirmée (ni succès ni échec) : {champs}");
    assert_eq!(champs["forwarded"], Value::Null, "event de contrôle : aucun compte affirmé : {champs}");
    assert_eq!(champs["watermark_after"], Value::Null, "event de contrôle : aucun filigrane d'arrivée : {champs}");
    assert_eq!(champs["etat_non_relu"], json!(true), "event de contrôle : la non-relecture se filtre : {champs}");

    // LA DESTINATION DISPARAÎT PENDANT L'ENVOI : un déclencheur temporaire la supprime quand le stub écrit son
    // `last_run`. La relecture rend `QueryReturnedNoRows` — une AUTRE cause que la lecture ratée, dont le renvoi
    // « relisez la liste » serait faux : la liste ne porte plus cette destination.
    let did2 = {
        let conn = st.db.lock();
        conn.execute("INSERT INTO destination(type,name,enabled,endpoint) VALUES('s3','lqe-disparue',1,'s3://lqe2')", []).expect("destination");
        conn.last_insert_rowid()
    };
    lqe_ecrire(&st, &format!("CREATE TEMP TRIGGER lqe_supprime AFTER UPDATE OF last_run ON destination WHEN NEW.id={did2} \
                              BEGIN DELETE FROM destination WHERE id=NEW.id; END;"));
    let (statut, disparue) = lqe_corps(destination_flush(State(st.clone()), Extension(lqe_adm()), Path(did2)).await).await;
    lqe_ecrire(&st, "DROP TRIGGER temp.lqe_supprime;");
    assert_eq!(statut, 200, "l'envoi a eu lieu : {disparue}");
    let n: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM destination WHERE id=?1", [did2], |r| r.get(0)).expect("compte");
    assert_eq!(n, 0, "fixture : la destination a bien été supprimée pendant l'envoi");
    assert_eq!(disparue["etat_non_relu"], json!(CAUSE_DESTINATION_SUPPRIMEE_PENDANT_L_ENVOI), "ligne disparue : sa cause propre, pas « relisez la liste » : {disparue}");
    for champ in ["ok", "forwarded", "watermark", "last_error"] {
        assert_eq!(disparue[champ], Value::Null, "`{champ}` non relu : {disparue}");
    }
    // Le REGISTRE garde la même distinction que le corps : la ligne disparue n'y est pas écrite « relecture en échec ».
    let trace = derniere_trace(&st);
    assert!(trace.contains("destination supprimée pendant l'envoi") && !trace.contains("relecture en échec"), "registre : cause propre de la ligne disparue : {trace}");
    let (_, champs) = dernier_event(&st);
    assert_eq!(champs["motif_non_relu"], json!("destination supprimée pendant l'envoi"), "event de contrôle : cause propre : {champs}");
    // Contrôle : la destination encore présente mais illisible garde la cause de la lecture ratée.
    let (_, encore) = lqe_corps(destination_flush(State(st.clone()), Extension(lqe_adm()), Path(did)).await).await;
    assert_eq!(encore["etat_non_relu"], json!(CAUSE_ETAT_DE_L_ENVOI_MANUEL_NON_RELU), "ligne présente et illisible : {encore}");
}

// -------------------------------------------------------------------------------------
// (3) `playbooks_list` — un mode non lu n'est pas « observe »
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `mode` LU est servi tel quel (`active`, contrôle positif) ; une ligne de mode ABSENTE
/// sert `observe` sans aveu (témoin inverse : mode jamais posé = observation établie) ; une valeur
/// illisible (BLOB, voie du mappeur) puis une table `meta` coiffée (voie de la préparation) servent
/// `mode: null` et `mode_non_lu` — la liste, lue par une autre lecture, reste servie.
///
/// Enfin la LISTE illisible (nom BLOB) : mode lu servi sans aveu, puis mode illisible aussi — `mode: null` ET
/// `mode_non_lu` en plus de l'aveu de liste.
///
/// LES MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=mode_observe` rétablit le repli `observe` sur l'échec ;
/// `PB_LISTE_RETOUR` rétablit le retour anticipé du bras liste illisible (mode null sans aveu).
#[tokio::test]
async fn p10_20b_le_mode_non_lu_des_playbooks_n_est_pas_observe() {
    let (st, _p) = sp_state("lqe-playbooks");
    lqe_ecrire(&st, "INSERT INTO playbook(name,query,action_kind) VALUES('pb-lqe','search source=web | stats count by src_ip','ban_ip');\
                     INSERT INTO meta(key,value) VALUES('plume_mode','active') ON CONFLICT(key) DO UPDATE SET value='active';");

    let lu = playbooks_list(State(st.clone()), Extension(lqe_adm())).await.0;
    assert_eq!(lu["mode"], json!("active"), "contrôle positif : le mode LU est servi : {lu}");
    assert!(lu.get("mode_non_lu").is_none(), "chemin nominal MUET : {lu}");

    lqe_ecrire(&st, "DELETE FROM meta WHERE key='plume_mode';");
    let absent = playbooks_list(State(st.clone()), Extension(lqe_adm())).await.0;
    assert_eq!(absent["mode"], json!("observe"), "aucune ligne : observation ÉTABLIE (règle de `mode_get`) : {absent}");
    assert!(absent.get("mode_non_lu").is_none(), "une absence n'est pas une lecture ratée : {absent}");

    lqe_ecrire(&st, "INSERT INTO meta(key,value) VALUES('plume_mode',x'FF');");
    let illisible = playbooks_list(State(st.clone()), Extension(lqe_adm())).await.0;
    assert_eq!(illisible["mode"], Value::Null, "mode illisible : jamais « observe » : {illisible}");
    assert_eq!(illisible["mode_non_lu"], json!(CAUSE_MODE_DES_PLAYBOOKS_NON_LU), "l'aveu est NOMMÉ : {illisible}");
    assert_eq!(illisible["playbooks"].as_array().map(Vec::len), Some(1), "la liste, lue à part, reste servie : {illisible}");
    assert!(illisible.get("error").is_none(), "la liste n'est pas déclarée illisible : {illisible}");

    lqe_ecrire(&st, "DELETE FROM meta WHERE key='plume_mode'; CREATE TEMP VIEW meta AS SELECT 1 AS autre;");
    let coiffe = playbooks_list(State(st.clone()), Extension(lqe_adm())).await.0;
    assert_eq!(coiffe["mode"], Value::Null, "table `meta` illisible : jamais « observe » : {coiffe}");
    assert_eq!(coiffe["mode_non_lu"], json!(CAUSE_MODE_DES_PLAYBOOKS_NON_LU), "l'aveu est NOMMÉ : {coiffe}");
    lqe_ecrire(&st, "DROP VIEW temp.meta;");

    // LA LISTE ILLISIBLE (un nom BLOB que le mappeur refuse en texte) : l'aveu de liste ET le mode tiennent ensemble.
    lqe_ecrire(&st, "INSERT INTO meta(key,value) VALUES('plume_mode','active'); UPDATE playbook SET name=x'FF';");
    let liste_ko = playbooks_list(State(st.clone()), Extension(lqe_adm())).await.0;
    assert!(liste_ko["error"].is_string(), "fixture : la liste est déclarée illisible : {liste_ko}");
    assert_eq!(liste_ko["mode"], json!("active"), "liste illisible, mode LU : le mode reste servi : {liste_ko}");
    assert!(liste_ko.get("mode_non_lu").is_none(), "mode lu : aucun aveu de mode : {liste_ko}");

    lqe_ecrire(&st, "UPDATE meta SET value=x'FF' WHERE key='plume_mode';");
    let deux_ko = playbooks_list(State(st.clone()), Extension(lqe_adm())).await.0;
    assert!(deux_ko["error"].is_string(), "la liste reste avouée illisible : {deux_ko}");
    assert_eq!(deux_ko["playbooks"], json!([]), "liste illisible : vide et avouée : {deux_ko}");
    assert_eq!(deux_ko["mode"], Value::Null, "liste ET mode illisibles : jamais « observe » : {deux_ko}");
    assert_eq!(deux_ko["mode_non_lu"], json!(CAUSE_MODE_DES_PLAYBOOKS_NON_LU), "liste illisible : le mode non lu est AUSSI avoué : {deux_ko}");
}

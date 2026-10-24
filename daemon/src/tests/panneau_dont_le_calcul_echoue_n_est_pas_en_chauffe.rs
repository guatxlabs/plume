// =====================================================================================
// P10.32-o — UN PANNEAU DONT LE CALCUL ÉCHOUE N'EST PAS « EN CHAUFFE » POUR TOUJOURS.
//
// MESURÉ SUR 00ea0ad1 (lecture) : un panneau au coût INCONNU part en SWR (`panel_data`,
// `(heavy || unknown) && cacheable && ttl > 0`). Deux échecs y étaient avalés :
//   (1) `serve_swr` : `compile_panneau_avoue(…).ok()` — une compilation refusée valait `None`, le MISS
//       servait `{warming:true}` + `mesure_en_cours` à CHAQUE interrogation et n'armait rien ; le chemin
//       LIVE rend pourtant `bad_req` pour la même compilation ;
//   (2) `enqueue_panel_refresh` : `if let Ok(Ok(v))` — un `Err` du moteur ou une panique du fil ne
//       laissait AUCUNE ligne de cache ni aucun coût : le panneau restait INCONNU, donc en SWR, donc
//       `warming`, sans fin.
// Les témoins passent par le HANDLER RÉEL `panel_data` sur une base de test, et attendent la tâche de
// rafraîchissement par l'ensemble `panel_refresh_inflight` (un état, pas une durée).
// La panne du moteur est une erreur d'EXÉCUTION pilotée par les DONNÉES (`json_extract` sur un texte
// malformé) et non une table retirée : le pool de lecture garde son cache de schéma, et la levée de la
// panne doit être visible sans changer le schéma.
// =====================================================================================

const T3C_GXQL_REFUSE: &str = "search source=web | inputlookup secret";
const T3C_SQL_EN_PANNE: &str = "SELECT json_extract(v,'$.a') AS a FROM t3c_source";
const T3C_SQL_SAIN: &str = "SELECT 1 AS un";

fn t3c_state(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, i64, i64, i64) {
    let path = ff_tmp_path(tag);
    let (gxql, panne, sain) = {
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture P10.32-o : migrations complètes");
        conn.execute("INSERT INTO user(name,hash,role) VALUES('adm',?1,'admin')", params![hash_pw("adminpw12345").unwrap()]).unwrap();
        conn.execute_batch("CREATE TABLE t3c_source(v TEXT); INSERT INTO t3c_source(v) VALUES('{pas du json');").unwrap();
        conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('d-adm','adm','private')", []).unwrap();
        let did = conn.last_insert_rowid();
        let mut ids = Vec::new();
        for (q, soql) in [(T3C_GXQL_REFUSE, 1), (T3C_SQL_EN_PANNE, 0), (T3C_SQL_SAIN, 0)] {
            conn.execute(
                "INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'p',?2,?3,'table')",
                params![did, q, soql],
            )
            .unwrap();
            ids.push(conn.last_insert_rowid());
        }
        (ids[0], ids[1], ids[2])
    };
    let st = ds_file_state(&path);
    (st, path, gxql, panne, sain)
}

fn t3c_admin() -> AuthUser {
    AuthUser {
        name: "adm".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
        method: "basic".into(), csrf: String::new(), env: None,
    }
}

/// Fenêtre glissante de 24 h (`to=0`) -> `cacheable` : avec un coût inconnu, le chemin SWR.
fn t3c_from() -> i64 {
    now() - 86_400
}

fn t3c_q(from: i64) -> Query<HashMap<String, String>> {
    Query(HashMap::from([("from".to_string(), from.to_string()), ("to".to_string(), "0".to_string())]))
}

async fn t3c_json(r: Response) -> (u16, Value) {
    let code = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
    (code, serde_json::from_slice(&b).unwrap_or_else(|_| json!({ "_texte": String::from_utf8_lossy(&b) })))
}

fn t3c_rien_en_vol(st: &AppState) -> bool {
    st.panel_refresh_inflight.lock().is_empty()
}

/// Attend que la tâche de rafraîchissement armée ait rendu sa place dans l'ensemble en vol. Borné en
/// NOMBRE de passages (jamais une assertion de durée) : au-delà, la tâche n'a pas abouti du tout.
async fn t3c_attendre_la_tache(st: &AppState) {
    for _ in 0..20_000 {
        if t3c_rien_en_vol(st) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    panic!("la tâche de rafraîchissement n'a jamais quitté l'ensemble en vol");
}

fn t3c_cle(st: &AppState, id: i64, from: i64) -> (String, String, i64) {
    let conn = st.db.lock();
    let (q, soql): (String, i64) =
        conn.query_row("SELECT query, is_soql FROM panel WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
    let rk = env_range_key(None, &cache_range_key(from, 0, now()));
    let (ttl_global, _) = panel_serve_cfg_de(&load_config());
    (rk, query_fingerprint(&q, soql != 0), panel_cache_ttl(&conn, id, ttl_global))
}

// -------------------------------------------------------------------------------------
// (1) UNE COMPILATION REFUSÉE, JAMAIS MESURÉE : LE REFUS DU COMPILATEUR, PAS UNE CHAUFFE.
// -------------------------------------------------------------------------------------
#[tokio::test]
async fn t3c_compilation_refusee_jamais_mesuree_rend_le_refus_et_n_arme_rien() {
    let (st, dbp, gxql, _panne, _sain) = t3c_state("p1032o-gxql");
    let au = t3c_admin();
    let from = t3c_from();
    // PRÉCONDITION : la requête est bien refusée par le compilateur (sinon le témoin ne mesure rien).
    let cause = match panneau_avoue::compile_panneau_avoue(T3C_GXQL_REFUSE, true, from, 0, None) {
        Err(e) => e,
        Ok(_) => panic!("précondition : `{T3C_GXQL_REFUSE}` devait être refusé par le compilateur"),
    };
    for passage in 0..2 {
        let r = panel_data(State(st.clone()), Extension(au.clone()), Path(gxql), t3c_q(from)).await;
        assert!(t3c_rien_en_vol(&st), "passage {passage} : une compilation refusée n'arme aucun rafraîchissement");
        let (code, v) = t3c_json(r).await;
        assert_eq!(code, 400, "passage {passage} : AVANT correctif 200 + warming à chaque interrogation ; corps {v}");
        assert_eq!(v["error"], json!(cause), "le MÊME refus que le chemin live, avec la cause du compilateur");
        assert!(v.get("warming").is_none(), "jamais `warming` pour un panneau qui ne chauffera jamais : {v}");
    }
    let (rk, fp, _) = t3c_cle(&st, gxql, from);
    let conn = st.db.lock();
    assert!(read_panel_cost(&conn, gxql, &fp).unwrap().is_none(), "aucun coût inventé");
    assert!(panneau_avoue::cache_lire(&conn, gxql, &rk, &fp).is_none(), "aucune ligne de cache écrite");
    drop(conn);
    ff_rm(&dbp);
}

// -------------------------------------------------------------------------------------
// (2) UN CALCUL EN ÉCHEC : L'ÉCHEC EST DIT, PUIS RETENTÉ À L'EXPIRATION, PUIS ÉCRASÉ PAR LE SUCCÈS.
// -------------------------------------------------------------------------------------
#[tokio::test]
async fn t3c_calcul_en_echec_est_dit_puis_retente_a_l_expiration_du_cache() {
    let (st, dbp, _gxql, panne, _sain) = t3c_state("p1032o-panne");
    let au = t3c_admin();
    let from = t3c_from();
    // PRÉCONDITION : le moteur refuse bien ce calcul (sinon on mesurerait un succès).
    let pc = panneau_avoue::compile_panneau_avoue(T3C_SQL_EN_PANNE, false, from, 0, None).unwrap();
    let cause = panneau_avoue::executer(dbp.as_str(), &HashMap::new(), pc, from)
        .expect_err("précondition : `json_extract` sur un texte malformé doit échouer");

    // 1re interrogation : jamais mesuré -> `warming` légitime, une tâche armée.
    let (code, v) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await).await;
    assert_eq!((code, v["warming"].clone()), (200, json!(true)), "1re interrogation : chauffe légitime ; corps {v}");
    t3c_attendre_la_tache(&st).await;

    // 2e et 3e : le corps d'ÉCHEC, pas une chauffe — et rien de réarmé tant que le cache est frais.
    for passage in 2..4 {
        let r = panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await;
        assert!(t3c_rien_en_vol(&st), "passage {passage} : un échec FRAIS n'est pas retenté à chaque interrogation");
        let (code, v) = t3c_json(r).await;
        assert_eq!(code, 200, "passage {passage} : corps {v}");
        assert!(v.get("warming").is_none(), "passage {passage} : AVANT correctif `warming` pour toujours ; corps {v}");
        assert_eq!(v["error"], json!(cause), "passage {passage} : la cause du moteur est servie, telle quelle");
        assert_eq!(v["stats"]["coverage"]["reason"], json!(panneau_avoue::RAISON_CALCUL_ECHOUE));
        assert_eq!(v["rows"], json!([]), "aucune ligne inventée");
        // LA NOTICE EST CELLE DE L'ÉCHEC, pas celle d'une charge utile illisible (repli de `coverage_synthetique`).
        let notice = v["stats"]["coverage"]["notice"].as_str().unwrap_or_default().to_string();
        assert!(notice.contains("le calcul de ce panneau a échoué"), "passage {passage} : notice de l'échec ; notice {notice:?}");
        let repli = panneau_avoue::coverage_synthetique(panneau_avoue::RAISON_PAYE_UTILE_ILLISIBLE, from, now(), None);
        assert_ne!(json!(notice), repli["notice"], "passage {passage} : jamais la notice d'une charge utile illisible");
    }
    let (rk, fp, ttl) = t3c_cle(&st, panne, from);
    assert!(ttl > 0, "précondition : le cache des panneaux est actif");
    {
        let conn = st.db.lock();
        assert!(read_panel_cost(&conn, panne, &fp).unwrap().is_none(), "un échec ne classe pas le panneau (aucun coût)");
        // LA PANNE EST LEVÉE, ET LE CORPS D'ÉCHEC VIEILLIT AU-DELÀ DU TTL (par le coffre, qui possède la table).
        conn.execute("UPDATE t3c_source SET v='{\"a\":7}'", []).unwrap();
        let (payload, calcule_a) = panneau_avoue::cache_lire(&conn, panne, &rk, &fp).expect("le corps d'échec est en cache");
        panneau_avoue::cache_ecrire(&conn, panne, &rk, &fp, calcule_a - ttl - 5, &payload);
    }

    // 4e : périmé -> le corps d'échec est encore servi ET une NOUVELLE TENTATIVE est armée.
    let r = panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await;
    assert!(!t3c_rien_en_vol(&st), "échec périmé : la nouvelle tentative DOIT être armée");
    let (code, v) = t3c_json(r).await;
    assert_eq!((code, v["error"].clone()), (200, json!(cause)), "le périmé reste servi pendant la tentative ; corps {v}");
    t3c_attendre_la_tache(&st).await;
    {
        // LA TENTATIVE RÉUSSIE A ÉCRASÉ L'ÉCHEC DANS LE CACHE — lu ICI, avant la 5e interrogation : le
        // panneau désormais classé léger passe par le chemin LIVE, qui écrit lui-même le cache et masquerait
        // une tentative qui n'écrit rien.
        let conn = st.db.lock();
        let (payload, _) = panneau_avoue::cache_lire(&conn, panne, &rk, &fp).expect("ligne de cache après le succès");
        let en_cache: Value = serde_json::from_str(&payload).expect("charge utile lisible");
        assert!(en_cache.get("error").is_none(), "l'échec ne reste pas en cache après le succès : {payload}");
        assert_eq!(en_cache["rows"], json!([[7]]), "le résultat du succès est en cache : {payload}");
    }

    // 5e : la tentative a réussi et ÉCRASÉ l'échec — corps nominal.
    let (code, v) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await).await;
    assert_eq!(code, 200, "corps {v}");
    assert_eq!(v["rows"], json!([[7]]), "le succès ultérieur écrase l'échec ; corps {v}");
    assert!(v.get("error").is_none() && v.get("warming").is_none(), "corps nominal : {v}");
    {
        let conn = st.db.lock();
        assert!(read_panel_cost(&conn, panne, &fp).unwrap().is_some(), "le succès classe le panneau");
    }
    ff_rm(&dbp);
}

// -------------------------------------------------------------------------------------
// (3) CONTRE-ÉPREUVE : UN PANNEAU SAIN CHAUFFE UNE FOIS, PUIS SERT SES LIGNES.
// -------------------------------------------------------------------------------------
#[tokio::test]
async fn t3c_contre_epreuve_un_panneau_sain_chauffe_une_fois_puis_sert_ses_lignes() {
    let (st, dbp, _gxql, _panne, sain) = t3c_state("p1032o-sain");
    let au = t3c_admin();
    let from = t3c_from();
    let (code, v) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(sain), t3c_q(from)).await).await;
    assert_eq!((code, v["warming"].clone()), (200, json!(true)), "corps {v}");
    assert_eq!(v["stats"]["coverage"]["reason"], json!(panneau_avoue::RAISON_MESURE_EN_COURS));
    t3c_attendre_la_tache(&st).await;
    let (code, v) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(sain), t3c_q(from)).await).await;
    assert_eq!(code, 200, "corps {v}");
    assert_eq!(v["rows"], json!([[1]]), "corps {v}");
    assert!(v.get("error").is_none() && v.get("warming").is_none(), "corps nominal : {v}");
    let (_rk, fp, _) = t3c_cle(&st, sain, from);
    assert!(read_panel_cost(&st.db.lock(), sain, &fp).unwrap().is_some(), "le succès classe le panneau");
    ff_rm(&dbp);
}

// -------------------------------------------------------------------------------------
// (4) UNE PANIQUE DU FIL DE CALCUL (`JoinError`) : LE MÊME CORPS D'ÉCHEC, CAUSE « exécution échouée ».
// L'issue est FABRIQUÉE par un vrai fil bloquant qui panique, puis remise à la fonction que la tâche
// de rafraîchissement appelle — aucun crochet de test dans le code de production.
// -------------------------------------------------------------------------------------
#[tokio::test]
async fn t3c_panique_du_fil_de_calcul_ecrit_le_corps_d_echec() {
    let (st, dbp, _gxql, _panne, sain) = t3c_state("p1032o-panique");
    let au = t3c_admin();
    let from = t3c_from();
    let (rk, fp, ttl) = t3c_cle(&st, sain, from);
    assert!(ttl > 0, "précondition : le cache des panneaux est actif");
    let (ttl_global, _) = panel_serve_cfg_de(&load_config());
    let issue = tokio::task::spawn_blocking(|| -> Result<Value, String> { panic!("t3c : panique injectée dans le fil de calcul") }).await;
    assert!(issue.is_err(), "précondition : l'issue est bien un JoinError");
    consigner_l_issue_du_rafraichissement(&st.db, sain, &rk, &fp, now(), from, ttl_global, issue);
    {
        let conn = st.db.lock();
        assert!(read_panel_cost(&conn, sain, &fp).unwrap().is_none(), "une panique ne classe pas le panneau");
        assert!(panneau_avoue::cache_lire(&conn, sain, &rk, &fp).is_some(), "AVANT : rien d'écrit, chauffe éternelle");
    }
    let r = panel_data(State(st.clone()), Extension(au.clone()), Path(sain), t3c_q(from)).await;
    assert!(t3c_rien_en_vol(&st), "échec frais : rien de réarmé");
    let (code, v) = t3c_json(r).await;
    assert_eq!(code, 200, "corps {v}");
    assert!(v.get("warming").is_none(), "plus de chauffe après une panique : {v}");
    assert_eq!(v["error"], json!("exécution échouée"), "la cause nommée de la panique : {v}");
    assert_eq!(v["stats"]["coverage"]["reason"], json!(panneau_avoue::RAISON_CALCUL_ECHOUE));
    ff_rm(&dbp);
}

// -------------------------------------------------------------------------------------
// (4b) UN ÉCHEC NEUF REMPLACE L'ÉCHEC PRÉCÉDENT : sa cause et son instant. Sans cela, un échec qui dure garde
// l'instant du premier, il est retenté à CHAQUE interrogation (au prix du budget) et la cause servie reste
// figée sur la première. Mutant `M_PRED_ERR` (la condition `error` de `charge_valide` neutralisée) : rouge.
// -------------------------------------------------------------------------------------
#[tokio::test]
async fn t3c_un_echec_neuf_remplace_l_echec_precedent_et_son_instant() {
    let (st, dbp, _gxql, panne, _sain) = t3c_state("p1032o-deux-echecs");
    let from = t3c_from();
    let (rk, fp, ttl) = t3c_cle(&st, panne, from);
    assert!(ttl > 0, "précondition : le cache des panneaux est actif");
    let (ttl_global, _) = panel_serve_cfg_de(&load_config());
    let t1 = now() - 2 * ttl - 10;
    let t2 = t1 + ttl + 5; // le premier corps d'échec est périmé : une nouvelle tentative a eu lieu
    consigner_l_issue_du_rafraichissement(&st.db, panne, &rk, &fp, t1, from, ttl_global, Ok(Err("t3c cause une".to_string())));
    {
        let conn = st.db.lock();
        let (payload, calcule_a) = panneau_avoue::cache_lire(&conn, panne, &rk, &fp).expect("1er échec écrit");
        assert_eq!(calcule_a, t1, "contrôle positif : le premier échec est écrit à son instant : {payload}");
        assert!(payload.contains("t3c cause une"), "contrôle positif : sa cause : {payload}");
    }
    consigner_l_issue_du_rafraichissement(&st.db, panne, &rk, &fp, t2, from, ttl_global, Ok(Err("t3c cause deux".to_string())));
    {
        let conn = st.db.lock();
        let (payload, calcule_a) = panneau_avoue::cache_lire(&conn, panne, &rk, &fp).expect("2e échec écrit");
        assert_eq!(calcule_a, t2, "l'échec neuf remplace le précédent et porte son instant (sinon : retenté à chaque interrogation) : {payload}");
        assert!(payload.contains("t3c cause deux") && !payload.contains("t3c cause une"), "la cause servie est la dernière : {payload}");
    }
    ff_rm(&dbp);
}

// -------------------------------------------------------------------------------------
// (5) UNE CHARGE UTILE VALIDE PÉRIMÉE N'EST PAS ÉCRASÉE PAR UN ÉCHEC (comme au pré-chauffage).
// -------------------------------------------------------------------------------------
#[tokio::test]
async fn t3c_charge_utile_valide_perimee_survit_a_un_rafraichissement_en_echec() {
    let (st, dbp, _gxql, panne, _sain) = t3c_state("p1032o-perime");
    let au = t3c_admin();
    let from = t3c_from();
    let (rk, fp, ttl) = t3c_cle(&st, panne, from);
    let vieux = now() - ttl - 5;
    {
        let conn = st.db.lock();
        record_panel_cost(&conn, panne, &fp, 10_000.0, now()); // LOURD connu -> chemin SWR
        let bon = json!({ "columns": ["a"], "rows": [[42]] }).to_string();
        panneau_avoue::cache_ecrire(&conn, panne, &rk, &fp, vieux, &bon);
    }
    let r = panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await;
    assert!(!t3c_rien_en_vol(&st), "précondition : périmé -> une tentative est armée");
    let (_, v) = t3c_json(r).await;
    assert_eq!(v["rows"], json!([[42]]), "1re interrogation : le périmé valide est servi ; corps {v}");
    t3c_attendre_la_tache(&st).await;
    {
        let conn = st.db.lock();
        let (payload, calcule_a) = panneau_avoue::cache_lire(&conn, panne, &rk, &fp).expect("ligne de cache");
        assert_eq!(calcule_a, vieux, "la ligne valide n'est pas réécrite par l'échec : {payload}");
        assert!(!payload.contains("\"error\""), "aucun corps d'échec à la place du valide : {payload}");
    }
    let (code, v) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await).await;
    assert_eq!(code, 200, "corps {v}");
    assert_eq!(v["rows"], json!([[42]]), "AVANT : corps d'échec à la place du valide ; corps {v}");
    assert!(v.get("error").is_none(), "corps {v}");
    t3c_attendre_la_tache(&st).await;
    ff_rm(&dbp);
}

// -------------------------------------------------------------------------------------
// (6) LES JOURNAUX, LUS SUR LE STDERR D'UN SOUS-PROCESSUS : l'identifiant, la cause, le geste RÉELLEMENT
// fait (écrit, conservé, refusé), jamais la requête. Phases : à la demande (écrit), valide conservé,
// écriture refusée par la base, pré-chauffage.
// -------------------------------------------------------------------------------------
const T3C_ENFANT: &str = "PLUME_T3C_JOURNAL_ENFANT";
const T3C_PHASE: &str = "T3C-PHASE:";

#[tokio::test]
async fn t3c_journaux_d_echec_disent_l_identifiant_la_cause_et_le_geste_jamais_la_requete() {
    if std::env::var(T3C_ENFANT).is_ok() {
        let au = t3c_admin();
        let from = t3c_from();
        // à la demande : corps d'échec écrit.
        let (st, dbp, _g, panne, _s) = t3c_state("p1032o-j-demande");
        let pc = panneau_avoue::compile_panneau_avoue(T3C_SQL_EN_PANNE, false, from, 0, None).unwrap();
        let cause = panneau_avoue::executer(dbp.as_str(), &HashMap::new(), pc, from).unwrap_err();
        eprintln!("T3C-ID:{panne}");
        eprintln!("T3C-CAUSE:{cause}");
        eprintln!("{T3C_PHASE}demande");
        let _ = panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await;
        t3c_attendre_la_tache(&st).await;
        ff_rm(&dbp);
        // charge utile valide périmée : conservée.
        let (st, dbp, _g, panne, _s) = t3c_state("p1032o-j-conserve");
        let (rk, fp, ttl) = t3c_cle(&st, panne, from);
        {
            let conn = st.db.lock();
            record_panel_cost(&conn, panne, &fp, 10_000.0, now());
            panneau_avoue::cache_ecrire(&conn, panne, &rk, &fp, now() - ttl - 5, &json!({ "columns": ["a"], "rows": [[42]] }).to_string());
        }
        eprintln!("{T3C_PHASE}conserve");
        let _ = panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await;
        t3c_attendre_la_tache(&st).await;
        ff_rm(&dbp);
        // écriture refusée par la base.
        let (st, dbp, _g, panne, _s) = t3c_state("p1032o-j-refus");
        let (rk, fp, _) = t3c_cle(&st, panne, from);
        let (ttl_global, _) = panel_serve_cfg_de(&load_config());
        st.db
            .lock()
            .execute_batch("CREATE TRIGGER t3c_refus BEFORE INSERT ON panel_cache BEGIN SELECT RAISE(ABORT,'cache refuse par le temoin'); END;")
            .unwrap();
        eprintln!("{T3C_PHASE}refus");
        consigner_l_issue_du_rafraichissement(&st.db, panne, &rk, &fp, now(), from, ttl_global, Ok(Err(cause.clone())));
        assert!(panneau_avoue::cache_lire(&st.db.lock(), panne, &rk, &fp).is_none(), "précondition : rien d'écrit");
        ff_rm(&dbp);
        // pré-chauffage.
        let (st, dbp, _g, _panne, _s) = t3c_state("p1032o-j-prechauffe");
        eprintln!("{T3C_PHASE}prechauffe");
        crate::rollups::cache_refresh_all_panels(&st.db, dbp.as_str(), &st.refresh_sem);
        eprintln!("{T3C_PHASE}fin");
        ff_rm(&dbp);
        return;
    }
    let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
        .args([
            "--exact",
            "--nocapture",
            "--test-threads=1",
            "tests::t3c_journaux_d_echec_disent_l_identifiant_la_cause_et_le_geste_jamais_la_requete",
        ])
        .env(T3C_ENFANT, "1")
        .output()
        .expect("ré-exécution du binaire de test");
    let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
    assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
    let lire = |marque: &str| -> String {
        stderr.lines().find_map(|l| l.strip_prefix(marque)).unwrap_or_else(|| panic!("contrôle : {marque} : {stderr}")).to_string()
    };
    let id = lire("T3C-ID:");
    let cause = lire("T3C-CAUSE:");
    let phase = |nom: &str| -> Vec<String> {
        let debut = stderr.split_once(&format!("{T3C_PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
        let corps = debut.split_once(T3C_PHASE).map(|(c, _)| c).unwrap_or(debut);
        corps.lines().filter(|l| l.starts_with("[panel]") || l.starts_with("[cache]")).map(str::to_string).collect()
    };
    let attendus = [
        ("demande", format!("[panel] WARN rafraîchissement du panneau {id} en échec ({cause})"), "corps d'échec servi"),
        ("conserve", format!("[panel] WARN rafraîchissement du panneau {id} en échec ({cause})"), "charge utile précédente conservée"),
        ("refus", format!("[panel] WARN rafraîchissement du panneau {id} en échec ({cause})"), "corps d'échec NON ÉCRIT (cache refuse par le temoin)"),
        ("prechauffe", format!("[cache] WARN pré-chauffage du panneau {id} en échec ({cause})"), "rien d'écrit"),
    ];
    for (nom, tete, geste) in attendus {
        let lignes = phase(nom);
        assert_eq!(lignes.len(), 1, "phase {nom} : une ligne et une seule : {lignes:?}\n{stderr}");
        let l = &lignes[0];
        assert!(l.starts_with(&tete), "phase {nom} : identifiant et cause : {l}");
        assert!(l.contains(geste), "phase {nom} : le geste réellement fait ({geste}) : {l}");
        for interdit in ["json_extract", "t3c_source", "SELECT"] {
            assert!(!l.contains(interdit), "phase {nom} : jamais la requête ({interdit}) : {l}");
        }
        if nom != "demande" {
            assert!(!l.contains("corps d'échec servi"), "phase {nom} : le journal ne prétend pas avoir servi un corps d'échec : {l}");
        }
    }
}

// =====================================================================================
// P7.13-a — LA PORTE « SQL BRUT = ADMIN » DU PANNEAU EMPRUNTE LA RÉSOLUTION DE L'EXÉCUTEUR.
//
// MESURÉ AVANT CORRECTIF (2026-08-03, `3256e4d`) — mêmes appels, mêmes fixtures, assertions INVERSÉES
// (elles épinglaient alors le contournement ; elles épinglent aujourd'hui sa fermeture) :
//   (a) SQL BRUT — l'`editor` était bien refusé À L'ÉCRITURE (bascule directe `is_soql:false` -> 403 ;
//       `library_panel_create is_soql:false` -> 403), mais il RATTACHAIT une définition SQL brut écrite
//       par un admin (`{"library_panel_id": N}` -> 204) et en LISAIT le résultat (`panel_data` -> 200,
//       2 lignes : [["adm","admin"],["ed","editor"]] — la table `user`).
//   (b) VISIBILITÉ — une définition PRIVÉE d'admin, ABSENTE de son inventaire (`library_panels_list`
//       -> []), se rattachait quand même (204) ; `dash_get` lui rendait le TEXTE de la requête privée
//       et `panel_data` ses DONNÉES (200, 2 lignes).
//   (c) Le MÊME trou existait à la CRÉATION : `panel_create` acceptait `library_panel_id` du corps
//       sans aucune porte (200, puis 200 + 2 lignes du SQL brut PRIVÉ d'un admin).
//   (d) SNAPSHOT — 2e volet, trouvé en RELISANT ce qui est écrit : le bandeau de `dash_ergonomics.rs`
//       annonçait « hérite #45 + RBAC ». Sur un dashboard PARTAGÉ d'autrui portant un panneau PRIVÉ, un
//       editor tiers avait `dash_get` -> `panels: []` et `panel_data` -> 403, mais `snapshot_create`
//       -> 200 avec la ligne privée FIGÉE dans le snapshot, ensuite partageable par jeton.
//   BORNE (vérifiée, pas supposée) : l'authorizer SQLite refuse TOUJOURS `user.hash` et
//   `token.token_hash` MÊME à un admin -> 400 « access to <col> is prohibited » (correctif 3e2cea6).
//
// CAUSE : deux expressions distinctes coexistaient — la porte lisait `p.is_soql`, l'exécuteur résolvait
// `COALESCE(lp.is_soql, p.is_soql)` (3 sites) ; et la portée de lecture des panneaux était écrite
// séparément dans 3 surfaces, dont une l'avait oubliée. CORRECTIF : une résolution UNIQUE et une portée
// UNIQUE (coffre `handlers/panneau_resolu.rs`) que les portes EMPRUNTENT ; `build.rs` refuse de compiler
// toute réécriture de la résolution ailleurs, `DefinitionExecutee` ne se fabrique pas hors du coffre
// (E0451), et la portée est un paramètre OBLIGATOIRE de la capture (E0061).
// =====================================================================================

fn pb_state(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
    let path = ff_tmp_path(tag);
    {
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture P7.13-a : migrations complètes");
        conn.execute("INSERT INTO user(name,hash,role) VALUES('ed',?1,'editor')", params![hash_pw("editorpw12345").unwrap()]).unwrap();
        conn.execute("INSERT INTO user(name,hash,role) VALUES('adm',?1,'admin')", params![hash_pw("adminpw12345").unwrap()]).unwrap();
    }
    let st = ds_file_state(&path);
    (st, path)
}

fn pb_au(name: &str, role: &str) -> AuthUser {
    AuthUser {
        name: name.into(), role: role.into(), tenant: "default".into(), is_superadmin: false,
        method: "basic".into(), csrf: String::new(), env: None,
    }
}

async fn pb_json(r: Response) -> (u16, Value) {
    let code = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
    (code, serde_json::from_slice(&b).unwrap_or_else(|_| json!({ "_texte": String::from_utf8_lossy(&b) })))
}

/// `from=0`/`to=100` -> `cacheable=false` dans `panel_data` -> chemin LIVE (jamais SWR/`warming`), donc
/// la réponse porte les LIGNES RÉELLEMENT rendues et non un payload de préchauffage.
fn pb_q() -> Query<HashMap<String, String>> {
    Query(HashMap::from([("from".to_string(), "0".to_string()), ("to".to_string(), "100".to_string())]))
}

/// Dashboard appartenant à `ed` + un panneau GXQL dessus (le CRUD éditorial légitime de l'editor).
fn pb_dash_panel(st: &AppState) -> (i64, i64) {
    let conn = st.db.lock();
    conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('d-ed','ed','shared')", []).unwrap();
    let did = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'mien','search source=web | table message',1,'table')",
        params![did],
    )
    .unwrap();
    (did, conn.last_insert_rowid())
}

/// Crée une définition de bibliothèque PAR LE HANDLER RÉEL et rend son id.
async fn pb_lib(st: &AppState, au: &AuthUser, corps: Value) -> (u16, i64) {
    let (c, v) = pb_json(library_panel_create(State(st.clone()), Extension(au.clone()), Json(corps)).await).await;
    (c, v.get("id").and_then(|x| x.as_i64()).unwrap_or(0))
}

fn pb_lignes(v: &Value) -> usize {
    v.get("rows").and_then(|r| r.as_array()).map(|a| a.len()).unwrap_or(0)
}

// -------------------------------------------------------------------------------------
// (a) LE SQL BRUT NE S'EXÉCUTE PLUS SOUS L'IDENTITÉ D'UN EDITOR PAR LE DÉTOUR DE LA BIBLIOTHÈQUE.
// -------------------------------------------------------------------------------------
#[tokio::test]
async fn un_editor_ne_peut_pas_executer_de_sql_brut_par_la_bibliotheque() {
    let (st, dbp) = pb_state("p713a-brut");
    let (adm, edt) = (pb_au("adm", "admin"), pb_au("ed", "editor"));
    let (_did, pid) = pb_dash_panel(&st);

    // LA PORTE QU'ON NE CASSE PAS — l'editor reste refusé à l'ÉCRITURE de SQL brut, des deux côtés.
    let direct = panel_update(State(st.clone()), Extension(edt.clone()), Path(pid), Json(json!({ "is_soql": false, "query": "SELECT name,role FROM user" }))).await;
    assert_eq!(direct.as_u16(), 403, "bascule directe du panneau en SQL brut");
    let (c, _) = pb_lib(&st, &edt, json!({ "name": "tentative", "query": "SELECT 1", "is_soql": false })).await;
    assert_eq!(c, 403, "création d'une définition de bibliothèque en SQL brut");

    // L'ADMIN crée une définition SQL BRUT (chemin légitime) — PARTAGÉE, pour isoler ce contournement-ci
    // de celui de la visibilité (test suivant) : seul le SQL brut est en cause ici.
    let (c, lib) = pb_lib(&st, &adm, json!({
        "name": "brut-admin", "title": "T", "query": "SELECT name,role FROM user ORDER BY name",
        "is_soql": false, "visibility": "shared"
    })).await;
    assert_eq!(c, 200, "l'admin, lui, a bien le droit");

    // LE CONTOURNEMENT MESURÉ, MAINTENANT FERMÉ : rattacher = exécuter, donc la porte s'applique.
    let attache = panel_update(State(st.clone()), Extension(edt.clone()), Path(pid), Json(json!({ "library_panel_id": lib }))).await;
    assert_eq!(attache.as_u16(), 403, "AVANT correctif : 204. Rattacher une définition SQL BRUT = l'exécuter.");

    // …et RIEN n'a été écrit : le panneau exécute toujours SA requête GXQL.
    {
        let conn = st.db.lock();
        let bib: Option<i64> = conn.query_row("SELECT library_panel_id FROM panel WHERE id=?1", params![pid], |r| r.get(0)).unwrap();
        assert!(bib.is_none(), "porte fail-closed : aucune référence posée");
    }
    let (cd, vd) = pb_json(panel_data(State(st.clone()), Extension(edt.clone()), Path(pid), pb_q()).await).await;
    assert_eq!(cd, 200);
    assert_eq!(vd.get("columns"), Some(&json!(["message"])), "le panneau rend SA requête GXQL, pas la table `user`");

    // L'ADMIN, lui, rattache — et lit. La capacité n'a pas été détruite, elle a été rendue à son rôle.
    let attache_adm = panel_update(State(st.clone()), Extension(adm.clone()), Path(pid), Json(json!({ "library_panel_id": lib }))).await;
    assert_eq!(attache_adm.as_u16(), 204, "l'admin garde le rattachement d'une définition SQL brut");
    let (cd, vd) = pb_json(panel_data(State(st.clone()), Extension(adm.clone()), Path(pid), pb_q()).await).await;
    assert_eq!((cd, pb_lignes(&vd)), (200, 2), "l'admin lit bien les 2 comptes");

    // …ET L'EDITOR NE PEUT PLUS ÉDITER CE PANNEAU-LÀ : il EXÉCUTE du SQL brut, même si `panel.is_soql`
    // vaut toujours 1. C'est la 2e omission que la porte d'origine laissait passer (elle lisait
    // `p.is_soql` : mesuré 204 sur un simple changement de titre).
    let titre = panel_update(State(st.clone()), Extension(edt.clone()), Path(pid), Json(json!({ "title": "renommé" }))).await;
    assert_eq!(titre.as_u16(), 403, "éditer un panneau qui EXÉCUTE du SQL brut reste admin");
    // …mais il peut le DÉTACHER (le panneau redevient le sien, en GXQL) : on ne l'enferme pas.
    let detache = panel_update(State(st.clone()), Extension(edt.clone()), Path(pid), Json(json!({ "library_panel_id": null }))).await;
    assert_eq!(detache.as_u16(), 204, "détacher rend le panneau à son propriétaire (fail-closed ≠ cul-de-sac)");
    ff_rm(&dbp);
}

/// LA BORNE, VÉRIFIÉE ET NON SUPPOSÉE : même un ADMIN en SQL brut ne lit pas les condensats de secrets.
/// (Correctif 3e2cea6 — l'authorizer SQLite DENY `user.hash` / `token.token_hash` pour tout le monde.)
#[tokio::test]
async fn meme_un_admin_en_sql_brut_ne_lit_pas_les_condensats_de_secrets() {
    let (st, dbp) = pb_state("p713a-borne");
    let adm = pb_au("adm", "admin");
    let (did, _) = pb_dash_panel(&st);
    for (colonne, sql) in [("user.hash", "SELECT name,hash FROM user"), ("token.token_hash", "SELECT token_hash FROM token")] {
        let (_, lib) = pb_lib(&st, &adm, json!({ "name": format!("s-{colonne}"), "query": sql, "is_soql": false })).await;
        let (_, v) = pb_json(panel_create(State(st.clone()), Extension(adm.clone()), Json(json!({
            "dashboard_id": did, "title": "x", "query": "", "is_soql": false, "library_panel_id": lib
        }))).await).await;
        let np = v.get("id").and_then(|x| x.as_i64()).unwrap();
        let (cs, vs) = pb_json(panel_data(State(st.clone()), Extension(adm.clone()), Path(np), pb_q()).await).await;
        assert_eq!(cs, 400, "lecture de {colonne} refusée MÊME à l'admin");
        assert_eq!(vs.get("error"), Some(&json!(format!("access to {colonne} is prohibited"))));
    }
    ff_rm(&dbp);
}

// -------------------------------------------------------------------------------------
// (b) CE QU'UN COMPTE NE VOIT PAS, IL NE PEUT PAS LE RATTACHER — CONTOURNEMENT DISTINCT DU (a).
// -------------------------------------------------------------------------------------
#[tokio::test]
async fn un_editor_ne_peut_pas_rattacher_une_definition_privee_d_autrui() {
    let (st, dbp) = pb_state("p713a-prive");
    let (adm, edt) = (pb_au("adm", "admin"), pb_au("ed", "editor"));
    let (did, pid) = pb_dash_panel(&st);
    {
        let conn = st.db.lock();
        for (t, m) in [(50i64, "SECRET-COFFRE-1"), (60, "SECRET-COFFRE-2")] {
            conn.execute("INSERT INTO event(ts,source,message) VALUES(?1,'coffre',?2)", params![t, m]).unwrap();
        }
    }
    // Définition PRIVÉE de l'admin, en GXQL : AUCUN SQL brut en jeu -> ce contournement est bien DISTINCT
    // du (a), et il ne peut pas être fermé « par accident » par la porte SQL brut.
    let (c, lib) = pb_lib(&st, &adm, json!({
        "name": "prive-admin", "title": "T", "query": "search source=coffre | table message",
        "is_soql": true, "visibility": "private"
    })).await;
    assert_eq!(c, 200);

    // L'INVENTAIRE et le RATTACHEMENT sont désormais D'ACCORD (même prédicat `lisible_par`).
    let liste = library_panels_list(State(st.clone()), Extension(edt.clone())).await;
    let vus: Vec<i64> = liste.0.get("library_panels").and_then(|a| a.as_array()).unwrap().iter().filter_map(|x| x.get("id").and_then(|i| i.as_i64())).collect();
    assert!(!vus.contains(&lib), "l'editor ne VOIT pas la définition privée d'autrui");
    let attache = panel_update(State(st.clone()), Extension(edt.clone()), Path(pid), Json(json!({ "library_panel_id": lib }))).await;
    assert_eq!(attache.as_u16(), 403, "AVANT correctif : 204. Ce qu'on ne voit pas ne se rattache pas.");

    // Ni le TEXTE ni les DONNÉES de la définition privée ne lui parviennent.
    let (cg, vg) = pb_json(dash_get(State(st.clone()), Extension(edt.clone()), Path(did)).await).await;
    let q_vue = vg.get("panels").and_then(|p| p.as_array()).and_then(|a| a.first()).and_then(|p| p.get("query")).cloned().unwrap();
    assert_eq!((cg, &q_vue), (200, &json!("search source=web | table message")), "AVANT : la requête privée d'autrui était rendue");
    let (cd, vd) = pb_json(panel_data(State(st.clone()), Extension(edt.clone()), Path(pid), pb_q()).await).await;
    assert_eq!(cd, 200);
    let rendu = serde_json::to_string(&vd).unwrap();
    assert!(!rendu.contains("SECRET-COFFRE"), "AVANT : 2 lignes du coffre étaient rendues ; obtenu {rendu}");

    // PAS D'ORACLE D'ÉNUMÉRATION : une définition INEXISTANTE répond EXACTEMENT comme une privée d'autrui.
    let inexistante = panel_update(State(st.clone()), Extension(edt.clone()), Path(pid), Json(json!({ "library_panel_id": 999_999 }))).await;
    assert_eq!(inexistante.as_u16(), attache.as_u16(), "inexistante et privée d'autrui : même réponse");

    // Le PARTAGÉ, lui, reste rattachable — l'editor garde son CRUD (invariant rbac.rs §7).
    let (_, partagee) = pb_lib(&st, &adm, json!({
        "name": "partagee", "query": "search source=coffre | table message", "is_soql": true, "visibility": "shared"
    })).await;
    let ok = panel_update(State(st.clone()), Extension(edt.clone()), Path(pid), Json(json!({ "library_panel_id": partagee }))).await;
    assert_eq!(ok.as_u16(), 204, "une définition PARTAGÉE en GXQL reste rattachable par l'editor");
    let (cd, vd) = pb_json(panel_data(State(st.clone()), Extension(edt.clone()), Path(pid), pb_q()).await).await;
    assert_eq!((cd, pb_lignes(&vd)), (200, 2), "…et elle s'exécute bien");
    ff_rm(&dbp);
}

// -------------------------------------------------------------------------------------
// (c) LA CRÉATION EST GARDÉE PAR LA MÊME PORTE QUE LA MISE À JOUR.
// -------------------------------------------------------------------------------------
#[tokio::test]
async fn la_creation_d_un_panneau_est_gardee_comme_sa_mise_a_jour() {
    let (st, dbp) = pb_state("p713a-create");
    let (adm, edt) = (pb_au("adm", "admin"), pb_au("ed", "editor"));
    let (did, _) = pb_dash_panel(&st);
    let (_, brut) = pb_lib(&st, &adm, json!({ "name": "brut", "query": "SELECT name,role FROM user", "is_soql": false, "visibility": "shared" })).await;
    let (_, prive) = pb_lib(&st, &adm, json!({ "name": "prive", "query": "search | stats count", "is_soql": true, "visibility": "private" })).await;

    // Un panneau ANODIN en GXQL qui RÉFÉRENCE une définition SQL brut : la porte juge la référence.
    for (etiquette, lib) in [("SQL brut", brut), ("privée d'autrui", prive)] {
        let (cc, _) = pb_json(panel_create(State(st.clone()), Extension(edt.clone()), Json(json!({
            "dashboard_id": did, "title": "anodin", "query": "search source=web | table message", "is_soql": true, "library_panel_id": lib
        }))).await).await;
        assert_eq!(cc, 403, "AVANT correctif : 200. Création référençant une définition {etiquette}.");
    }
    // Aucun panneau n'a été créé (fail-closed AVANT l'INSERT, pas après).
    {
        let conn = st.db.lock();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM panel WHERE dashboard_id=?1", params![did], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "seul le panneau de la fixture existe");
    }
    ff_rm(&dbp);
}

// -------------------------------------------------------------------------------------
// LE THÉORÈME : LA PORTE JUGE CE QUI S'EXÉCUTERA. On le prouve sur une FAMILLE DÉRIVÉE d'états,
// pas sur un cas nommé — et sans jamais réécrire la résolution (build.rs l'interdit de toute façon).
// -------------------------------------------------------------------------------------

/// Pour TOUT état de départ × TOUTE demande, ce que `DefinitionExecutee::projetee` a jugé est EXACTEMENT
/// ce que `DefinitionExecutee::courante` (l'exécuteur, via `panel_access`) résout APRÈS l'écriture.
/// C'est la propriété qui manquait : la porte lisait `p.is_soql`, l'exécuteur résolvait la bibliothèque.
#[test]
fn la_porte_juge_exactement_ce_que_l_executeur_resoudra() {
    let conn = test_db();
    let adm = pb_au("adm", "admin"); // admin : la LISIBILITÉ ne filtre rien -> on teste la RÉSOLUTION seule
    conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('d','adm','shared')", []).unwrap();
    let did = conn.last_insert_rowid();
    // Deux définitions de bibliothèque + le cas « pas de bibliothèque » + une référence PENDANTE.
    conn.execute("INSERT INTO library_panel(name,title,query,is_soql,visibility) VALUES('L1','T','LIB-BRUT',0,'shared')", []).unwrap();
    let l1 = conn.last_insert_rowid();
    conn.execute("INSERT INTO library_panel(name,title,query,is_soql,visibility) VALUES('L2','T','search LIB-GXQL',1,'shared')", []).unwrap();
    let l2 = conn.last_insert_rowid();
    let pendante = 424_242i64;

    let mut couples = 0usize;
    for depart in [None, Some(l1), Some(l2), Some(pendante)] {
        for (etiquette, corps) in [
            ("rien", json!({})),
            ("detache", json!({ "library_panel_id": null })),
            ("zero", json!({ "library_panel_id": 0 })),
            ("vers-l1", json!({ "library_panel_id": l1 })),
            ("vers-l2", json!({ "library_panel_id": l2 })),
            ("query-locale", json!({ "query": "PATCHÉ", "is_soql": false })),
            ("bascule-gxql", json!({ "is_soql": true })),
        ] {
            conn.execute(
                "INSERT INTO panel(dashboard_id,title,query,is_soql,library_panel_id) VALUES(?1,'p','PANNEAU-LOCAL',0,?2)",
                params![did, depart],
            )
            .unwrap();
            let pid = conn.last_insert_rowid();
            let ref_bib = RefBibliotheque::du_corps(&corps);
            let q = corps.get("query").and_then(|v| v.as_str()).unwrap_or("PANNEAU-LOCAL").to_string();
            let s = corps.get("is_soql").and_then(|v| v.as_bool()).unwrap_or(false);
            let jugee = DefinitionExecutee::projetee(&conn, &adm, depart, &ref_bib, (q, s)).expect("admin : jamais refusé");
            let (jq, js) = (jugee.query().to_string(), jugee.is_soql());
            // On APPLIQUE l'écriture exactement comme panel_update le fait…
            if let Some(v) = ref_bib.a_ecrire() {
                conn.execute("UPDATE panel SET library_panel_id=?1 WHERE id=?2", params![v, pid]).unwrap();
            }
            if let Some(v) = corps.get("query").and_then(|v| v.as_str()) {
                conn.execute("UPDATE panel SET query=?1 WHERE id=?2", params![v, pid]).unwrap();
            }
            if let Some(v) = corps.get("is_soql").and_then(|v| v.as_bool()) {
                conn.execute("UPDATE panel SET is_soql=?1 WHERE id=?2", params![v as i64, pid]).unwrap();
            }
            // …et l'EXÉCUTEUR doit trouver EXACTEMENT ce que la porte avait jugé.
            let exec = DefinitionExecutee::courante(&conn, pid).expect("panneau présent");
            assert_eq!(
                (jq.as_str(), js), (exec.query(), exec.is_soql()),
                "départ={depart:?} demande={etiquette} : la porte a jugé ({jq:?},{js}) et l'exécuteur résout ({:?},{})",
                exec.query(), exec.is_soql()
            );
            couples += 1;
        }
    }
    assert_eq!(couples, 28, "famille dérivée effectivement parcourue (4 états × 7 demandes)");
}

/// La résolution en Rust (`resoudre`, dans le coffre) et la résolution en SQL (les constantes du coffre,
/// telles que SQLite les évalue) rendent la MÊME définition. C'est l'équivalence sur laquelle repose le
/// fait que la porte, qui raisonne en Rust, juge bien ce que l'exécuteur lit en SQL.
#[test]
fn la_resolution_rust_egale_la_resolution_sql_sur_une_famille_derivee() {
    let conn = test_db();
    let adm = pb_au("adm", "admin");
    conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('d','adm','shared')", []).unwrap();
    let did = conn.last_insert_rowid();
    // Y COMPRIS les valeurs « fausses » (chaîne vide, is_soql=0) que `COALESCE` ne doit PAS confondre
    // avec NULL : c'est le cas qui piège une réécriture naïve de la résolution.
    conn.execute("INSERT INTO library_panel(name,title,query,is_soql,visibility) VALUES('vide','T','',0,'shared')", []).unwrap();
    let vide = conn.last_insert_rowid();
    conn.execute("INSERT INTO library_panel(name,title,query,is_soql,visibility) VALUES('plein','T','search X',1,'shared')", []).unwrap();
    let plein = conn.last_insert_rowid();

    let mut n = 0usize;
    for bib in [None, Some(vide), Some(plein), Some(999_999)] {
        for (q, s) in [("LOCAL", 0i64), ("", 1), ("search LOCAL", 1)] {
            conn.execute(
                "INSERT INTO panel(dashboard_id,title,query,is_soql,library_panel_id) VALUES(?1,'p',?2,?3,?4)",
                params![did, q, s, bib],
            )
            .unwrap();
            let pid = conn.last_insert_rowid();
            let rust = DefinitionExecutee::courante(&conn, pid).unwrap();
            // La MÊME chose par le chemin PROJETÉ (aucune écriture, `Inchangee`).
            let projete = DefinitionExecutee::projetee(&conn, &adm, bib, &RefBibliotheque::Inchangee, (q.to_string(), s != 0)).unwrap();
            assert_eq!((rust.query(), rust.is_soql()), (projete.query(), projete.is_soql()), "bib={bib:?} panneau=({q:?},{s})");
            n += 1;
        }
    }
    assert_eq!(n, 12, "famille dérivée effectivement parcourue");
}

/// DÉCISION ÉCRITE, ÉPINGLÉE : la révocation d'une bibliothèque n'est PAS rétroactive. Une définition
/// rattachée LICITEMENT (partagée) puis basculée en `private` par son propriétaire continue d'être
/// résolue par les panneaux qui la référencent. La porte gouverne le moment où un droit s'ACQUIERT
/// (le rattachement) ; effacer après coup blanchirait silencieusement des dashboards vivants.
#[tokio::test]
async fn une_bibliotheque_passee_privee_apres_coup_reste_resolue() {
    let (st, dbp) = pb_state("p713a-revoc");
    let (adm, edt) = (pb_au("adm", "admin"), pb_au("ed", "editor"));
    let (_did, pid) = pb_dash_panel(&st);
    {
        let conn = st.db.lock();
        conn.execute("INSERT INTO event(ts,source,message) VALUES(50,'coffre','APRES-COUP')", []).unwrap();
    }
    let (_, lib) = pb_lib(&st, &adm, json!({ "name": "p", "query": "search source=coffre | table message", "is_soql": true, "visibility": "shared" })).await;
    assert_eq!(panel_update(State(st.clone()), Extension(edt.clone()), Path(pid), Json(json!({ "library_panel_id": lib }))).await.as_u16(), 204);
    assert_eq!(library_panel_update(State(st.clone()), Extension(adm.clone()), Path(lib), Json(json!({ "visibility": "private" }))).await.as_u16(), 204);
    let (cd, vd) = pb_json(panel_data(State(st.clone()), Extension(edt.clone()), Path(pid), pb_q()).await).await;
    assert_eq!((cd, pb_lignes(&vd)), (200, 1), "RÉSIDU DÉCLARÉ : la révocation n'est pas rétroactive");
    ff_rm(&dbp);
}

/// P7.13-a (2e volet) — LA CAPTURE DE SNAPSHOT HÉRITE DE LA RBAC DES PANNEAUX, ET PAS SEULEMENT DES
/// MASQUES DE CHAMPS. Sur un dashboard PARTAGÉ d'autrui portant un panneau PRIVÉ, un editor tiers
/// mesurait `dash_get` -> `panels: []` et `panel_data` -> 403 — mais `snapshot_create` -> 200 avec la
/// ligne privée FIGÉE dans le snapshot, ensuite partageable par jeton. L'en-tête du module l'annonçait
/// pourtant comme acquis (« hérite #45 + RBAC »).
#[tokio::test]
async fn un_snapshot_ne_fige_pas_le_panneau_prive_d_un_autre_proprietaire() {
    let (st, dbp) = pb_state("p713a-snap");
    let (bob, alice, adm) = (pb_au("bob", "editor"), pb_au("alice", "editor"), pb_au("adm", "admin"));
    let (did, pid) = {
        let conn = st.db.lock();
        conn.execute("INSERT INTO event(ts,source,message) VALUES(50,'coffre','SECRET-PRIVE-ALICE')", []).unwrap();
        conn.execute("INSERT INTO event(ts,source,message) VALUES(51,'public','VISIBLE-DE-TOUS')", []).unwrap();
        conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('d-alice','alice','shared')", []).unwrap();
        let did = conn.last_insert_rowid();
        conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,visibility) VALUES(?1,'partage','search source=public | table message',1,'shared')", params![did]).unwrap();
        conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,visibility) VALUES(?1,'prive-alice','search source=coffre | table message',1,'private')", params![did]).unwrap();
        (did, conn.last_insert_rowid())
    };
    // SOCLE : bob ne voit ni le panneau ni ses données par les deux autres surfaces.
    let (_, vg) = pb_json(dash_get(State(st.clone()), Extension(bob.clone()), Path(did)).await).await;
    assert_eq!(vg.get("panels").and_then(|p| p.as_array()).unwrap().len(), 1, "bob ne voit que le panneau partagé");
    let (cd, _) = pb_json(panel_data(State(st.clone()), Extension(bob.clone()), Path(pid), pb_q()).await).await;
    assert_eq!(cd, 403, "panel_data refuse le panneau privé d'autrui");
    // LA TROISIÈME SURFACE DIT MAINTENANT LA MÊME CHOSE.
    let snap = |au: AuthUser| {
        let st = st.clone();
        async move {
            let (c, v) = pb_json(snapshot_create(State(st.clone()), Extension(au), Json(json!({ "dashboard_id": did, "from": 0, "to": 100 }))).await).await;
            let tok = v.get("token").and_then(|t| t.as_str()).unwrap_or("").to_string();
            let data: String = st.db.lock().query_row("SELECT data FROM dashboard_snapshot WHERE token=?1", params![tok], |r| r.get(0)).unwrap_or_default();
            (c, data)
        }
    };
    let (cs, data_bob) = snap(bob).await;
    assert_eq!(cs, 200, "la capture reste permise (le dashboard EST partagé)");
    assert!(data_bob.contains("VISIBLE-DE-TOUS"), "le panneau partagé est bien capturé : {data_bob}");
    assert!(!data_bob.contains("SECRET-PRIVE-ALICE"), "AVANT correctif : la ligne privée était figée dedans. Obtenu {data_bob}");
    // …et la PROPRIÉTAIRE comme l'ADMIN gardent leur capture COMPLÈTE (on n'a pas cassé la fonction).
    for (qui, au) in [("alice", alice), ("admin", adm)] {
        let (c, d) = snap(au).await;
        assert_eq!(c, 200);
        assert!(d.contains("SECRET-PRIVE-ALICE"), "{qui} capture bien le panneau privé du dashboard qu'il possède/administre : {d}");
    }
    ff_rm(&dbp);
}

/// « UN VRAI EDITOR », BOUT EN BOUT — par le ROUTEUR RÉEL (toutes ses couches, sur une socket
/// loopback), pas par un appel direct au handler. Sans ce test, « l'editor ne peut pas rattacher »
/// resterait AMBIGU : refusé par le RBAC (la route lui serait fermée) ou refusé par la PORTE ? On
/// mesure les deux : la route `POST /api/panels/:id` lui est OUVERTE (invariant rbac.rs §7,
/// « l'editor garde ce CRUD » — 204 sur une édition ordinaire), et c'est bien la PORTE qui rend le
/// 403 sur le rattachement d'une définition SQL brut.
#[tokio::test]
async fn un_vrai_editor_traverse_le_routeur_et_bute_sur_la_porte() {
    let path = ff_tmp_path("p713a-routeur");
    let (pid, lib) = {
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture routeur P7.13-a : migrations complètes");
        conn.execute("INSERT INTO user(name,hash,role) VALUES('edt',?1,'editor')", params![hash_pw("editorpw12345").unwrap()]).unwrap();
        conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('d','edt','shared')", []).unwrap();
        let did = conn.last_insert_rowid();
        conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql) VALUES(?1,'p','search source=web | table message',1)", params![did]).unwrap();
        let pid = conn.last_insert_rowid();
        conn.execute("INSERT INTO library_panel(name,title,query,is_soql,owner,visibility) VALUES('brut','T','SELECT name,role FROM user',0,'root','shared')", []).unwrap();
        (pid, conn.last_insert_rowid())
    };
    let mut st = ds_file_state(&path);
    st.user = Arc::new("root".to_string());
    st.pass_hash = Arc::new(hash_pw("rootpw1234567").unwrap());
    st.rl_auth_max = 1_000_000;
    st.rl_ip_max = 1_000_000;
    st.rl_global_max = 1_000_000;
    let addr = router_serve(st).await;

    // Requête HTTP/1.1 brute AVEC CORPS -> (statut). Même parti pris que `router_probe` : on parle le
    // protocole à la main pour traverser VRAIMENT les couches, sans dépendance nouvelle.
    async fn poster(addr: std::net::SocketAddr, chemin: &str, authz: &str, corps: &str) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let req = format!(
            "POST {chemin} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nAuthorization: {authz}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{corps}",
            corps.len()
        );
        let fut = async {
            let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
            s.write_all(req.as_bytes()).await.ok()?;
            let mut buf = vec![0u8; 64];
            let n = s.read(&mut buf).await.ok()?;
            String::from_utf8_lossy(&buf[..n]).split_whitespace().nth(1)?.parse::<u16>().ok()
        };
        tokio::time::timeout(Duration::from_secs(20), fut).await.ok().flatten().unwrap_or(0)
    }
    let editeur = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("edt:editorpw12345"));
    let chemin = format!("/api/panels/{pid}");

    // (1) LA ROUTE LUI EST BIEN OUVERTE : une édition ordinaire passe de bout en bout.
    assert_eq!(poster(addr, &chemin, &editeur, r#"{"title":"renommé par l'editor"}"#).await, 204,
        "invariant rbac.rs §7 : l'editor garde le CRUD des panneaux (si ceci rougit, la route a été fermée, \
         et le 403 du cas (2) ne prouverait plus rien sur la PORTE)");
    // (2) …ET C'EST LA PORTE QUI L'ARRÊTE sur le rattachement d'une définition SQL brut.
    assert_eq!(poster(addr, &chemin, &editeur, &format!(r#"{{"library_panel_id":{lib}}}"#)).await, 403,
        "AVANT correctif : 204 (mesuré 2026-08-03 sur `3256e4d`)");
    ff_rm(&path);
}

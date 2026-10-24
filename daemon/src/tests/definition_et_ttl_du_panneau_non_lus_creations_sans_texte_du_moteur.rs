// =====================================================================================
// `P10.20-l` (vague AK : `DefinitionExecutee::courante` dans handlers/panneau_resolu.rs, lecture du TTL du cache par
// `panel_data` dans handlers/dashboards.rs) et `P10.29-l` (vague AK : `refus_d_un_objet_non_cree` et ses six bras
// `Err`, dashboards.rs et dash_ergonomics.rs ; le 503 de capture d'`snapshot_create`).
//
// LE DÉFAUT, MESURÉ PAR LECTURE SUR 307d4dc3 AVANT LE CORRECTIF.
//   (a) `courante` lisait la définition exécutée par `.ok()` : une définition illisible devenait `None`,
//       `panel_access` rendait `Ok(None)` et `panel_data` servait 403 « panneau inaccessible » — un refus de droit
//       inventé au lieu du 503 `CAUSE_PANNEAU_NON_LU` que la vague AJ sert pour les deux autres lectures de la porte.
//   (b) `panel_cache_ttl` rendait 0 sur une lecture ratée ; `panel_data` le prenait tel quel : `ttl > 0` faux, le
//       chemin SWR était écarté et le panneau partait en exécution directe — sur la lane de rafraîchissement si elle
//       était libre, et SANS PERMIS (branche « cache off ET lane saturée ») si elle était saturée. Une lecture qui
//       n'a pas eu lieu ouvrait une exécution, et dans le second cas une charge non bornée.
//   (c) `refus_d_un_objet_non_cree(objet, cause: impl Display)` recevait le `rusqlite::Error` des six bras `Err`
//       (tableau de bord, panneau, vue, panneau de bibliothèque, liste de lecture, instantané) : le texte du moteur
//       partait au client dans le 503.
//   (d) `snapshot_create` servait « instantané REFUSÉ … ({e}) » avec le `rusqlite::Error` de la capture.
//
// LE CORRECTIF. (a) `courante` rend `rusqlite::Result<Option<_>>` (`.optional()`), `panel_access` le propage : 503
// `CAUSE_PANNEAU_NON_LU`. (b) `panel_data` lit le TTL par `lire_le_ttl_du_cache` (trois issues) : lecture ratée =
// même 503, AVANT toute compilation ni exécution ; `panel_cache_ttl` garde son repli pour l'issue d'un
// rafraîchissement de fond (après exécution, un 0 y veut dire « n'écris pas le cache »). (c) le compte de lignes
// garde `refus_d_un_objet_non_cree(objet, n)` (corps d'avant à l'octet) ; le bras moteur passe par
// `refus_d_un_objet_non_cree_par_le_moteur` : phrase fixe + objet sous identifiant, cause du moteur au journal.
// (d) même statut, même phrase sans `({e})`, cause au journal avec l'identifiant.
//
// PAR LA ROUTE : routeur réel (`build_router`, toutes ses couches), jeton du rôle le plus faible admis — `viewer`
// pour `GET /api/panels/{id}/data`, `editor` pour les six créations ; corps comparés À L'OCTET (l'identifiant de
// corrélation relu puis re-sérialisé). Les lignes de journal sont lues sur le stderr d'un sous-processus et comparées
// EN ENTIER ; la cause du moteur attendue est RE-PRODUITE sur la même base (jamais recopiée).
//
// LES EXÉCUTIONS SONT COMPTÉES par ce qu'elles laissent : une réponse qui porte le résultat de la requête du panneau
// (colonne `un`), une ligne de `panel_cost` (exécution mesurée, lane libre), une ligne de `panel_cache`, un
// rafraîchissement armé. Le chemin sans permis ne mesure ni ne met en cache : sa seule trace est la réponse servie.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : AK1_COURANTE_EN_NONE ; AK1_TTL_NON_LU_EN_ZERO,
// AK1_TTL_NUL_EN_REFUS, AK1_TTL_SANS_JOURNAL ; AK1_SITE_DASH, AK1_SITE_PANEL, AK1_SITE_VUE, AK1_SITE_LIB,
// AK1_SITE_LISTE, AK1_SITE_SNAP, AK1_OBJET_CAUSE_EXPOSEE, AK1_OBJET_SANS_JOURNAL, AK1_LIGNES_SANS_COMPTE ;
// AK1_CAPTURE_CAUSE_EXPOSEE, AK1_CAPTURE_SANS_JOURNAL.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ce que la console peint (web/ hors périmètre ; `CAUSE_PANNEAU_NON_LU` passe par
// `refusDUneLectureServie`, web/core.js, d'après la vague AJ — lu, non joué) ; le mode multi-tenant (aucune lecture
// changée ne dépend du tenant : `req_conn!` choisit la base avant) ; une lecture ratée par verrou ou table retirée (la
// conversion d'une colonne en BLOB suffit à atteindre chaque bras) ; la branche sans permis d'un TTL LÉGITIMEMENT nul,
// gardée telle quelle (conception d'avant, reste nommé : charge non bornée quand le cache est coupé et la lane saturée).
// =====================================================================================
mod definition_et_ttl_du_panneau_non_lus_creations_sans_texte_du_moteur {
    use super::*;

    const AK1_MDP_EDITEUR: &str = "editeurak1pw12345";
    const AK1_ABSENT: i64 = 987_656;
    const AK1_PHRASE_CAPTURE: &str = "instantané REFUSÉ : les panneaux de ce tableau de bord n'ont pas pu être lus — rien n'a \
                                      été capturé ni partagé, car une capture amputée serait figée et partagée comme complète. RÉESSAYER";

    fn ak1_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ak1_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn ak1_editeur() -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("edt:{AK1_MDP_EDITEUR}")))
    }

    /// Le routeur réel sur une base neuve : `vwr` (viewer, posé par la fabrique) et `edt` (editor).
    fn ak1_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = router_test_state(tag);
        st.db
            .lock()
            .execute("INSERT INTO user(name,hash,role) VALUES('edt',?1,'editor')", params![hash_pw(AK1_MDP_EDITEUR).unwrap()])
            .expect("fixture : editor posé");
        (st, p)
    }

    /// Statut, corps servi (un corps découpé en morceaux est recollé : ce sont ses octets), corps lu.
    async fn ak1_appel(addr: std::net::SocketAddr, methode: &str, chemin: &str, qui: &str, corps: &str) -> (u16, String, Value) {
        let json = [("Content-Type", "application/json")];
        let (statut, brut) = router_probe_envoi(addr, methode, chemin, Some(qui), &json, corps).await;
        let (tete, apres) = brut.split_once("\r\n\r\n").unwrap_or(("", ""));
        let c = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            let (mut out, mut reste) = (String::new(), apres);
            while let Some((taille, suite)) = reste.split_once("\r\n") {
                let n = usize::from_str_radix(taille.trim(), 16).unwrap_or(0);
                if n == 0 || suite.len() < n {
                    break;
                }
                out.push_str(&suite[..n]);
                reste = suite[n..].strip_prefix("\r\n").unwrap_or(&suite[n..]);
            }
            out
        } else {
            apres.to_string()
        };
        let v = serde_json::from_str(&c).unwrap_or(Value::Null);
        (statut, c, v)
    }

    /// Un 503 À L'OCTET : `{error: phrase, id: <corrélation>}`, re-sérialisé depuis l'identifiant relu.
    fn ak1_juger_503(quoi: &str, (statut, corps, v): &(u16, String, Value), phrase: &str) {
        assert_eq!(*statut, 503, "{quoi} : {corps}");
        let id = v["id"].as_str().unwrap_or_else(|| panic!("{quoi} : identifiant de corrélation : {corps}"));
        assert!(id.starts_with("plume-e"), "{quoi} : identifiant de corrélation : {corps}");
        assert_eq!(corps, &serde_json::to_string(&json!({ "error": phrase, "id": id })).unwrap(), "{quoi} : corps à l'octet");
        assert!(!corps.contains("Invalid column type") && !corps.contains("because it is a view") && !corps.contains("Blob"), "{quoi} : aucun texte du moteur : {corps}");
    }

    fn ak1_tableau(st: &AppState, nom: &str, proprietaire: &str, visibilite: &str) -> i64 {
        ak1_sql(st, &format!("INSERT INTO dashboard(name,created,owner,visibility) VALUES('{nom}',1000,'{proprietaire}','{visibilite}');"));
        ak1_compte(st, "SELECT MAX(id) FROM dashboard")
    }

    fn ak1_panneau(st: &AppState, did: i64) -> i64 {
        ak1_sql(st, &format!("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES({did},'p','SELECT 1 AS un',0,'table');"));
        ak1_compte(st, "SELECT MAX(id) FROM panel")
    }

    fn ak1_chemin_donnees(pid: i64) -> String {
        format!("/api/panels/{pid}/data?from={}&to=0", now() - 86_400)
    }

    /// Les traces qu'une exécution laisse pour ce panneau : (coûts mesurés, charges en cache, rafraîchissements armés).
    fn ak1_traces(st: &AppState, pid: i64) -> (i64, i64, usize) {
        (
            ak1_compte(st, &format!("SELECT COUNT(*) FROM panel_cost WHERE panel_id={pid}")),
            ak1_compte(st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={pid}")),
            st.panel_refresh_inflight.lock().len(),
        )
    }

    /// La réponse porte-t-elle le résultat de la requête du panneau (donc une exécution) ?
    fn ak1_execute(v: &Value) -> bool {
        v["columns"].as_array().is_some_and(|c| !c.is_empty())
    }

    async fn ak1_attendre_les_rafraichissements(st: &AppState) {
        for _ in 0..20_000 {
            if st.panel_refresh_inflight.lock().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }

    /// CE QU'IL TIENT (`courante` par `GET /api/panels/{id}/data`, jeton viewer) : panneau absent, `403` « panneau
    /// inaccessible » à l'octet ; panneau lu, `200` ; définition illisible (`is_soql` en BLOB : seule la lecture de
    /// `courante` échoue, celle de la fenêtre passe), `503` `CAUSE_PANNEAU_NON_LU` à l'octet, rien n'est exécuté ni
    /// armé — y compris pour un panneau d'un tableau PRIVÉ d'autrui (même règle que la vague AJ : aucun droit jugé sur
    /// une lecture ratée ; l'existence d'une ligne corrompue est la seule chose dite).
    /// MUTATION : AK1_COURANTE_EN_NONE (le `.ok()` d'avant) -> 403, les asserts du 503 tombent.
    #[tokio::test]
    async fn ak1_definition_illisible_jamais_403_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = ak1_etat("ak1-definition");
        let addr = router_serve(st.clone()).await;
        let vwr = viewer_authz();
        let r = ak1_appel(addr, "GET", &ak1_chemin_donnees(AK1_ABSENT), &vwr, "").await;
        assert_eq!((r.0, r.1.as_str()), (403, r#"{"error":"panneau inaccessible"}"#), "absence établie : le 403 d'avant, à l'octet");

        let partage = ak1_tableau(&st, "d-ak1-def", "alice", "shared");
        let pid = ak1_panneau(&st, partage);
        let r = ak1_appel(addr, "GET", &ak1_chemin_donnees(pid), &vwr, "").await;
        assert_eq!(r.0, 200, "contrôle : définition lue, servie : {}", r.1);
        ak1_attendre_les_rafraichissements(&st).await;

        let prive = ak1_tableau(&st, "d-ak1-def-prive", "alice", "private");
        let (pid_panne, pid_prive) = (ak1_panneau(&st, partage), ak1_panneau(&st, prive));
        let r = ak1_appel(addr, "GET", &ak1_chemin_donnees(pid_prive), &vwr, "").await;
        assert_eq!((r.0, r.1.as_str()), (403, r#"{"error":"panneau inaccessible"}"#), "contrôle : le privé d'alice lu reste refusé au viewer");
        ak1_sql(&st, &format!("UPDATE panel SET is_soql=X'00' WHERE id IN ({pid_panne},{pid_prive});"));
        assert_eq!(ak1_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE typeof(is_soql)='blob' AND id IN ({pid_panne},{pid_prive})")), 2, "fixture : définitions illisibles");
        let cas = [("partagé", pid_panne), ("privé d'autrui", pid_prive)];
        for (quoi, p) in cas {
            let avant = ak1_traces(&st, p);
            let r = ak1_appel(addr, "GET", &ak1_chemin_donnees(p), &vwr, "").await;
            ak1_juger_503(&format!("définition illisible ({quoi})"), &r, CAUSE_PANNEAU_NON_LU);
            assert_eq!(ak1_traces(&st, p), avant, "définition illisible ({quoi}) : rien n'est exécuté, mis en cache ni armé");
        }
    }

    /// CE QU'IL TIENT (TTL non lu par `GET /api/panels/{id}/data`, jeton viewer), sur les DEUX chemins qu'un TTL nul
    /// ouvrait : lane de rafraîchissement LIBRE puis SATURÉE (tous ses permis tenus par le témoin) — `503`
    /// `CAUSE_PANNEAU_NON_LU` à l'octet, ZÉRO exécution (aucune réponse portant le résultat, aucun coût mesuré, rien en
    /// cache, rien d'armé). Contrôles : TTL LÉGITIMEMENT nul (colonne à 0), le panneau est exécuté sur les deux chemins
    /// (avec permis lane libre : un coût mesuré ; sans permis lane saturée : la conception d'avant, gardée) ; TTL lu
    /// positif, servi. Pas d'oracle : un panneau privé d'autrui au TTL illisible rend le 403 d'avant, à l'octet, comme
    /// le même panneau au TTL lisible (le TTL n'est lu qu'après le droit).
    /// MUTATIONS : AK1_TTL_NON_LU_EN_ZERO (le repli d'avant) -> 200 exécutés ; AK1_TTL_NUL_EN_REFUS (un correctif trop
    /// large qui refuse aussi le TTL nul) -> les contrôles tombent.
    #[tokio::test]
    async fn ak1_ttl_non_lu_rien_n_est_execute_lane_libre_ni_saturee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = ak1_etat("ak1-ttl");
        let addr = router_serve(st.clone()).await;
        let vwr = viewer_authz();
        let partage = ak1_tableau(&st, "d-ak1-ttl", "alice", "shared");
        let (panne, nul, pose) = (ak1_panneau(&st, partage), ak1_panneau(&st, partage), ak1_panneau(&st, partage));
        let prive = ak1_tableau(&st, "d-ak1-ttl-prive", "alice", "private");
        let pid_prive = ak1_panneau(&st, prive);
        ak1_sql(
            &st,
            &format!(
                "UPDATE panel SET panel_cache_ttl_s=X'00' WHERE id IN ({panne},{pid_prive}); \
                 UPDATE panel SET panel_cache_ttl_s=0 WHERE id={nul}; UPDATE panel SET panel_cache_ttl_s=30 WHERE id={pose};"
            ),
        );
        assert!(crate::handlers::dashboards::lire_le_ttl_du_cache(&st.db.lock(), panne, 60).is_err(), "fixture : TTL illisible");
        assert_eq!(crate::handlers::dashboards::lire_le_ttl_du_cache(&st.db.lock(), nul, 60).ok(), Some(0), "fixture : TTL nul lu");

        let lane = st.refresh_sem.clone();
        let total = lane.available_permits();
        assert!(total >= 1, "fixture : la lane a des permis ({total})");
        // Les deux chemins sont JOUÉS avant d'être jugés : le compte d'exécutions est rendu pour chacun, si bien qu'un
        // retour du repli d'avant se lit sur la lane libre ET sur la lane saturée, pas seulement sur la première.
        let mut issues = Vec::new();
        for (chemin, saturee) in [("lane libre", false), ("lane saturée", true)] {
            let _tenus = saturee.then(|| lane.clone().try_acquire_many_owned(total as u32).expect("fixture : tous les permis tenus"));
            assert_eq!(lane.available_permits() == 0, saturee, "fixture ({chemin})");
            let avant = ak1_traces(&st, panne);
            let r = ak1_appel(addr, "GET", &ak1_chemin_donnees(panne), &vwr, "").await;
            ak1_attendre_les_rafraichissements(&st).await;
            let apres = ak1_traces(&st, panne);
            let executions = usize::from(ak1_execute(&r.2)) + usize::try_from(apres.0 - avant.0).unwrap_or(0);
            issues.push((chemin, executions, r, avant, apres));

            let avant = ak1_traces(&st, nul);
            let r = ak1_appel(addr, "GET", &ak1_chemin_donnees(nul), &vwr, "").await;
            assert_eq!((r.0, ak1_execute(&r.2)), (200, true), "contrôle TTL nul ({chemin}) : exécuté, conception d'avant : {}", r.1);
            assert_eq!(ak1_traces(&st, nul).0 - avant.0, i64::from(!saturee), "contrôle TTL nul ({chemin}) : mesuré avec permis seulement");
        }
        let comptes: Vec<(&str, usize)> = issues.iter().map(|(c, n, ..)| (*c, *n)).collect();
        assert_eq!(comptes, [("lane libre", 0), ("lane saturée", 0)], "TTL non lu : aucune exécution, sur chacun des deux chemins");
        for (chemin, _, r, avant, apres) in &issues {
            ak1_juger_503(&format!("TTL non lu ({chemin})"), r, CAUSE_PANNEAU_NON_LU);
            assert_eq!(apres, avant, "TTL non lu ({chemin}) : rien n'est exécuté, mis en cache ni armé");
        }

        let r = ak1_appel(addr, "GET", &ak1_chemin_donnees(pose), &vwr, "").await;
        assert_eq!(r.0, 200, "contrôle : TTL lu, servi : {}", r.1);
        ak1_attendre_les_rafraichissements(&st).await;

        let r = ak1_appel(addr, "GET", &ak1_chemin_donnees(pid_prive), &vwr, "").await;
        assert_eq!((r.0, r.1.as_str()), (403, r#"{"error":"panneau inaccessible"}"#), "privé d'autrui, TTL illisible : le 403 d'avant");
        ak1_sql(&st, &format!("UPDATE panel SET panel_cache_ttl_s=NULL WHERE id={pid_prive};"));
        let r2 = ak1_appel(addr, "GET", &ak1_chemin_donnees(pid_prive), &vwr, "").await;
        assert_eq!((r2.0, r2.1), (r.0, r.1), "pas d'oracle : TTL lisible ou non, même statut et même corps");
    }

    fn ak1_rendre_non_modifiable(st: &AppState, table: &str) {
        ak1_sql(st, &format!("ALTER TABLE \"{table}\" RENAME TO \"{table}_ak1\"; CREATE TEMP VIEW \"{table}\" AS SELECT * FROM \"{table}_ak1\";"));
    }

    fn ak1_rendre_modifiable(st: &AppState, table: &str) {
        ak1_sql(st, &format!("DROP VIEW \"{table}\"; ALTER TABLE \"{table}_ak1\" RENAME TO \"{table}\";"));
    }

    /// Les six créations : (objet servi, table, route, corps de la demande).
    fn ak1_creations(did: i64) -> Vec<(&'static str, &'static str, &'static str, String)> {
        vec![
            ("tableau de bord", "dashboard", "/api/dashboards", json!({ "name": "d-ak1" }).to_string()),
            ("panneau", "panel", "/api/panels", json!({ "dashboard_id": did, "title": "p", "query": "search source=web | table message", "is_soql": true }).to_string()),
            ("vue", "view", "/api/views", json!({ "name": "v-ak1" }).to_string()),
            ("panneau de bibliothèque", "library_panel", "/api/library-panels", json!({ "name": "b-ak1", "query": "search source=web | table message" }).to_string()),
            ("liste de lecture", "playlist", "/api/playlists", json!({ "name": "l-ak1" }).to_string()),
            ("instantané", "dashboard_snapshot", "/api/dashboard-snapshots", json!({ "dashboard_id": did, "from": 0, "to": 0, "name": "i-ak1" }).to_string()),
        ]
    }

    /// CE QU'IL TIENT (les six créations par la route, jeton editor) : écriture refusée par la base (table rendue non
    /// modifiable), `503` `{error: "<CAUSE_OBJET_NON_CREE> Objet : <objet>.", id}` À L'OCTET — plus de texte du moteur,
    /// aucune ligne ; insertion qui n'écrit rien (`RAISE(IGNORE)`), le corps d'avant À L'OCTET (« (0 ligne(s) écrite(s)
    /// au lieu d'une) ») ; contrôle, la création aboutit (`200`, identifiant numérique).
    /// MUTATIONS : AK1_SITE_DASH, AK1_SITE_PANEL, AK1_SITE_VUE, AK1_SITE_LIB, AK1_SITE_LISTE, AK1_SITE_SNAP (chaque bras
    /// rendu à la forme d'avant), AK1_OBJET_CAUSE_EXPOSEE, AK1_LIGNES_SANS_COMPTE.
    #[tokio::test]
    async fn ak1_six_creations_refusees_sans_texte_du_moteur_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = ak1_etat("ak1-creations");
        let addr = router_serve(st.clone()).await;
        let edt = ak1_editeur();
        let did = ak1_tableau(&st, "d-ak1-porteur", "edt", "shared");
        ak1_sql(&st, &format!("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,visibility) VALUES({did},'p','search source=web | table message',1,'table',0,'shared');"));
        let creations = ak1_creations(did);
        for (objet, table, route, corps) in creations {
            let lignes = ak1_compte(&st, &format!("SELECT COUNT(*) FROM \"{table}\""));
            ak1_rendre_non_modifiable(&st, table);
            let r = ak1_appel(addr, "POST", route, &edt, &corps).await;
            ak1_juger_503(&format!("{objet} : écriture refusée"), &r, &format!("{} Objet : {objet}.", crate::handlers::dashboards::CAUSE_OBJET_NON_CREE));
            ak1_rendre_modifiable(&st, table);
            assert_eq!(ak1_compte(&st, &format!("SELECT COUNT(*) FROM \"{table}\"")), lignes, "{objet} : aucune ligne");

            ak1_sql(&st, &format!("CREATE TEMP TRIGGER ak1_ignorer BEFORE INSERT ON main.\"{table}\" BEGIN SELECT RAISE(IGNORE); END;"));
            let r = ak1_appel(addr, "POST", route, &edt, &corps).await;
            ak1_juger_503(
                &format!("{objet} : zéro ligne écrite"),
                &r,
                &format!("{} Objet : {objet} (0 ligne(s) écrite(s) au lieu d'une).", crate::handlers::dashboards::CAUSE_OBJET_NON_CREE),
            );
            ak1_sql(&st, "DROP TRIGGER ak1_ignorer;");

            let (statut, brut, v) = ak1_appel(addr, "POST", route, &edt, &corps).await;
            assert_eq!(statut, 200, "{objet} : contrôle, la création aboutit : {brut}");
            assert_eq!(v["id"].as_i64(), Some(ak1_compte(&st, &format!("SELECT MAX(id) FROM \"{table}\""))), "{objet} : identifiant de la ligne écrite");
        }
    }

    /// CE QU'IL TIENT (capture refusée d'`snapshot_create` par la route, jeton editor) : un panneau dont le titre est
    /// illisible fait échouer la capture : `503` avec la phrase d'avant SANS la cause du moteur, à l'octet, sous
    /// identifiant ; aucun instantané écrit. Contrôle : sans ce panneau, l'instantané est écrit (`200`, jeton).
    /// MUTATION : AK1_CAPTURE_CAUSE_EXPOSEE (le `({e})` d'avant) -> le corps tombe.
    #[tokio::test]
    async fn ak1_capture_refusee_sans_texte_du_moteur_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = ak1_etat("ak1-capture");
        let addr = router_serve(st.clone()).await;
        let edt = ak1_editeur();
        let did = ak1_tableau(&st, "d-ak1-capture", "alice", "shared");
        ak1_sql(&st, &format!("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,visibility) VALUES({did},'p','search source=web | table message',1,'table',0,'shared');"));
        let corps = json!({ "dashboard_id": did, "from": 0, "to": 0, "name": "i-ak1" }).to_string();
        let (statut, brut, v) = ak1_appel(addr, "POST", "/api/dashboard-snapshots", &edt, &corps).await;
        assert_eq!((statut, v["token"].as_str().map(str::len)), (200, Some(64)), "contrôle : capture écrite : {brut}");
        ak1_sql(&st, &format!("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,visibility) VALUES({did},x'FF','search source=web | table message',1,'table',1,'shared');"));
        let avant = ak1_compte(&st, "SELECT COUNT(*) FROM dashboard_snapshot");
        let r = ak1_appel(addr, "POST", "/api/dashboard-snapshots", &edt, &corps).await;
        ak1_juger_503("capture refusée", &r, AK1_PHRASE_CAPTURE);
        assert_eq!(ak1_compte(&st, "SELECT COUNT(*) FROM dashboard_snapshot"), avant, "aucun instantané écrit");
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus et comparées EN ENTIER, une par phase, et la cause
    /// du moteur n'apparaît dans AUCUNE autre ligne de la phase (la trace `[plume-e…] HTTP 503` porte la phrase seule) :
    /// définition illisible (la ligne de `panel_data` de la vague AJ), TTL non lu, chacune des six créations refusées,
    /// capture refusée. Les nominaux n'écrivent aucune ligne `[dashboards]`.
    /// MUTATIONS : AK1_TTL_SANS_JOURNAL, AK1_OBJET_SANS_JOURNAL, AK1_CAPTURE_SANS_JOURNAL (et AK1_COURANTE_EN_NONE, qui
    /// rend la phase muette).
    #[tokio::test]
    async fn ak1_lignes_de_journal_des_lectures_et_ecritures_refusees() {
        const ENFANT: &str = "AK1_ENFANT_JOURNAL";
        const PHASE: &str = "AK1-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
            let (st, _p) = sp_state("ak1-journal");
            let adm = sp_au("adm", "admin");
            let q = || Query(HashMap::from([("from".to_string(), (now() - 86_400).to_string()), ("to".to_string(), "0".to_string())]));
            // Les panneaux cassés vivent sur leur PROPRE tableau : la capture de l'instantané (phase creation5) lit tous
            // les panneaux du tableau `did`, et une définition illisible la refuserait avant l'écriture jugée.
            let did_casse = ak1_tableau(&st, "d-ak1-journal-casse", "adm", "shared");
            let did = ak1_tableau(&st, "d-ak1-journal", "adm", "shared");
            eprintln!("{PHASE}definition");
            let pid = ak1_panneau(&st, did_casse);
            ak1_sql(&st, &format!("UPDATE panel SET is_soql=X'00' WHERE id={pid};"));
            let r = pb_json(panel_data(State(st.clone()), Extension(adm.clone()), Path(pid), q()).await).await;
            let moteur = st
                .db
                .lock()
                .query_row(
                    &format!("SELECT {},{} FROM {} WHERE p.id=?1", crate::handlers::panneau_resolu::COL_QUERY, crate::handlers::panneau_resolu::COL_IS_SOQL, crate::handlers::panneau_resolu::JOINTURE),
                    params![pid],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
                )
                .expect_err("rejouée")
                .to_string();
            println!("AK1-MARQUE-definition\t{}\t{pid}\t{}\t{moteur}", r.0, r.1["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}ttl");
            let tpid = ak1_panneau(&st, did_casse);
            ak1_sql(&st, &format!("UPDATE panel SET panel_cache_ttl_s=X'00' WHERE id={tpid};"));
            let r = pb_json(panel_data(State(st.clone()), Extension(adm.clone()), Path(tpid), q()).await).await;
            let moteur = crate::handlers::dashboards::lire_le_ttl_du_cache(&st.db.lock(), tpid, 60).expect_err("rejouée").to_string();
            println!("AK1-MARQUE-ttl\t{}\t{tpid}\t{}\t{moteur}", r.0, r.1["id"].as_str().unwrap_or(""));
            ak1_sql(&st, &format!("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,visibility) VALUES({did},'g','search source=web | table message',1,'table',5,'shared');"));
            for (i, (objet, table, _, corps)) in ak1_creations(did).into_iter().enumerate() {
                eprintln!("{PHASE}creation{i}");
                ak1_rendre_non_modifiable(&st, table);
                let b: Value = serde_json::from_str(&corps).unwrap();
                let rep = match table {
                    "dashboard" => dash_create(State(st.clone()), Extension(adm.clone()), Json(b)).await,
                    "panel" => panel_create(State(st.clone()), Extension(adm.clone()), Json(b)).await,
                    "view" => view_create(State(st.clone()), Extension(adm.clone()), Json(b)).await,
                    "library_panel" => library_panel_create(State(st.clone()), Extension(adm.clone()), Json(b)).await,
                    "playlist" => playlist_create(State(st.clone()), Extension(adm.clone()), Json(b)).await,
                    _ => snapshot_create(State(st.clone()), Extension(adm.clone()), Json(b)).await,
                };
                let r = pb_json(rep).await;
                let moteur = st.db.lock().execute(&format!("INSERT INTO \"{table}\" DEFAULT VALUES"), []).expect_err("rejouée").to_string();
                ak1_rendre_modifiable(&st, table);
                println!("AK1-MARQUE-creation{i}\t{}\t{objet}\t{}\t{moteur}", r.0, r.1["id"].as_str().unwrap_or(""));
            }
            eprintln!("{PHASE}capture");
            ak1_sql(&st, &format!("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,visibility) VALUES({did},x'FF','search source=web | table message',1,'table',9,'shared');"));
            let b = json!({ "dashboard_id": did, "from": 0, "to": 0, "name": "i" });
            let r = pb_json(snapshot_create(State(st.clone()), Extension(adm.clone()), Json(b)).await).await;
            let sql = format!(
                "SELECT {t},{q},{s},{v},{d},COALESCE(p.visibility,'shared') FROM {j} WHERE p.dashboard_id=?1 ORDER BY p.position,p.id",
                t = crate::handlers::panneau_resolu::COL_TITRE, q = crate::handlers::panneau_resolu::COL_QUERY,
                s = crate::handlers::panneau_resolu::COL_IS_SOQL, v = crate::handlers::panneau_resolu::COL_VIZ,
                d = crate::handlers::panneau_resolu::COL_DRILL, j = crate::handlers::panneau_resolu::JOINTURE,
            );
            let moteur = {
                let conn = st.db.lock();
                let mut stmt = conn.prepare(&sql).expect("rejouée : préparation");
                let lignes = stmt
                    .query_map(params![did], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?))
                    })
                    .expect("rejouée : exécution")
                    .collect::<rusqlite::Result<Vec<_>>>();
                lignes.map(|_| ()).expect_err("rejouée").to_string()
            };
            println!("AK1-MARQUE-capture\t{}\t{did}\t{}\t{moteur}", r.0, r.1["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}calme");
            let (st, _p) = sp_state("ak1-journal-calme");
            let did = ak1_tableau(&st, "d-ak1-calme", "adm", "shared");
            let pid = ak1_panneau(&st, did);
            let a = pb_json(panel_data(State(st.clone()), Extension(adm.clone()), Path(pid), q()).await).await.0;
            ak1_attendre_les_rafraichissements(&st).await;
            let b = pb_json(dash_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "name": "c" }))).await).await.0;
            let c = pb_json(snapshot_create(State(st.clone()), Extension(adm.clone()), Json(json!({ "dashboard_id": did, "from": 0, "to": 0 }))).await).await.0;
            println!("AK1-MARQUE-calme\t{a}\t{b}\t{c}");
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::definition_et_ttl_du_panneau_non_lus_creations_sans_texte_du_moteur::ak1_lignes_de_journal_des_lectures_et_ecritures_refusees",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> Vec<String> {
            let reste = stdout.split_once(&format!("AK1-MARQUE-{m}\t")).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").split('\t').map(str::to_string).collect()
        };
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().map(str::to_string).collect()
        };
        let mut attendus: Vec<(String, Vec<String>, String)> = Vec::new();
        let m = marque("definition");
        attendus.push(("definition".into(), m.clone(), format!("[dashboards] WARN panneau #{} NON lu pour l'exécution, rien n'est servi ({}) : {}", m[1], m[2], m[3])));
        let m = marque("ttl");
        attendus.push(("ttl".into(), m.clone(), format!("[dashboards] WARN panneau #{} : TTL du cache NON lu, rien n'est exécuté ({}) : {}", m[1], m[2], m[3])));
        for i in 0..6 {
            let nom = format!("creation{i}");
            let m = marque(&nom);
            attendus.push((nom, m.clone(), format!("[dashboards] WARN {} NON créé, aucun identifiant n'est rendu ({}) : {}", m[1], m[2], m[3])));
        }
        let m = marque("capture");
        attendus.push(("capture".into(), m.clone(), format!("[dashboards] WARN tableau de bord #{} : panneaux NON lus pour l'instantané, rien n'est capturé ({}) : {}", m[1], m[2], m[3])));
        for (nom, m, ligne) in &attendus {
            assert_eq!(m[0], "503", "{nom} : statut : {m:?}");
            assert!(m[2].starts_with("plume-e") && !m[3].is_empty(), "{nom} : identifiant servi et cause rejouée : {m:?}");
            let lignes = phase(nom);
            let du_module: Vec<&String> = lignes.iter().filter(|l| l.starts_with("[dashboards] ")).collect();
            assert_eq!(du_module, vec![ligne], "{nom} : UNE ligne, en entier : {stderr}");
            assert_eq!(lignes.iter().filter(|l| l.contains(m[3].as_str())).count(), 1, "{nom} : la cause du moteur n'est que dans cette ligne : {stderr}");
        }
        assert_eq!(marque("calme"), ["200", "200", "200"], "contrôle : les nominaux aboutissent");
        assert!(phase("calme").iter().all(|l| !l.starts_with("[dashboards] ")), "les nominaux n'écrivent rien : {stderr}");
    }
}

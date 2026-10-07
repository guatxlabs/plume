// =====================================================================================
// `P10.20-b` (hors `handlers/`) — L'ÉPOQUE GLOBALE DE SESSION : UNE LECTURE RATÉE N'EST PAS L'ÉPOQUE 0, UNE ÉCRITURE
// REFUSÉE N'EST PAS UNE RÉVOCATION.
//
// MESURÉ AVANT CORRECTIF (forme d'avant, ces témoins joués dessus) :
//  * `load_session_epoch` lisait `meta.session_epoch` par `.ok().and_then(parse).unwrap_or(0)` : une valeur illisible
//    ou une lecture ratée rendait l'époque 0 au démarrage — les cookies émis avant une révocation globale revalaient.
//  * `bump_session_epoch` avançait l'époque MÉMOIRE puis jetait l'écriture (`let _ = c.execute(..)`) : `meta` rendue non
//    inscriptible, la déconnexion globale d'un admin rendait 200, traçait « révoquées » au registre, et la révocation
//    tombait au redémarrage. Même chose pour toute déconnexion en mode 1.
//
// Le refus de démarrer (`exit 78` de `load_session_epoch`) est tenu en RÉ-EXÉCUTANT ce binaire de test (forme de
// `migrate.rs`, `reference_build_writes_nothing_to_stderr`) : le code de sortie et le message d'un PROCESSUS.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'appel de `load_session_epoch` par `main` (le démon n'est pas lancé) ; l'époque
// PAR COMPTE (`P10.24-d`) ; la trace d'une déconnexion de mode 1 (aucune, antérieur, `P10.31-i`).
// =====================================================================================
mod epoque_globale_lue_et_persistee {
    use super::*;
    use std::sync::atomic::Ordering;

    fn egp_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(&format!("egp-{tag}"));
        let h: String = st.db.lock().query_row("SELECT hash FROM user WHERE name='adm'", [], |r| r.get(0)).expect("fixture");
        *st.admin.lock() = Some(("adm".into(), h));
        (st, p)
    }

    fn egp_session(st: &AppState, user: &str, role: &str) -> String {
        frapper_la_session_du_compte(st, user, role).unwrap_or_else(|_| panic!("fixture : session de {user} frappée"))
    }

    fn egp_identite(st: &AppState, jeton: &str) -> Option<(String, String)> {
        let req = Request::builder()
            .uri("/api/me")
            .header(header::COOKIE, format!("plume_session={jeton}"))
            .body(axum::body::Body::empty())
            .expect("requête");
        resolve_identity(st, &req).0
    }

    fn egp_persistee(st: &AppState) -> i64 {
        lire_l_epoque_de_session(&st.db.lock()).expect("fixture : l'époque persistée se lit")
    }

    fn egp_traces_globales(st: &AppState) -> i64 {
        st.db
            .lock()
            .query_row("SELECT COUNT(*) FROM ledger WHERE kind='auth.deconnexion.globale'", [], |r| r.get(0))
            .expect("fixture : le registre se lit")
    }

    /// `meta.session_epoch` rendue non inscriptible : `ABORT` (l'écriture échoue) ou `IGNORE` (elle n'écrit rien,
    /// sans erreur — zéro ligne).
    fn egp_meta_non_inscriptible(st: &AppState, mode: &str) {
        st.db
            .lock()
            .execute_batch(&format!(
                "CREATE TRIGGER egp_refus_upd BEFORE UPDATE ON meta WHEN NEW.key='session_epoch' BEGIN SELECT RAISE({mode}{m}); END;
                 CREATE TRIGGER egp_refus_ins BEFORE INSERT ON meta WHEN NEW.key='session_epoch' BEGIN SELECT RAISE({mode}{m}); END;",
                m = if mode == "ABORT" { ", 'meta non inscriptible'" } else { "" }
            ))
            .expect("fixture : déclencheurs posés");
    }

    async fn egp_deconnexion(st: &AppState, jeton: &str, portee: Option<&str>) -> (u16, bool, Value) {
        let mut en_tetes = axum::http::HeaderMap::new();
        en_tetes.insert(header::COOKIE, format!("plume_session={jeton}").parse().expect("en-tête"));
        if let Some(p) = portee {
            en_tetes.insert(PORTEE_DE_LA_DECONNEXION, p.parse().expect("en-tête"));
        }
        let r = logout_post(State(st.clone()), en_tetes).await;
        let statut = r.status().as_u16();
        let efface = r
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.starts_with("plume_session=;") && v.contains("Max-Age=0"));
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, efface, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    /// CE QU'IL TIENT : base neuve (schéma + migrations) -> `Ok(0)` ; `'7'` -> `Ok(7)` ; un entier écrit dans `meta`
    /// y est rangé en TEXTE (affinité TEXT) et lu ; ligne ABSENTE -> `Ok(0)` (l'époque d'origine) ; valeur `'sept'`,
    /// vide, `'7 '`, un BLOB ou NULL -> `Err` nommé ; table `meta` illisible -> `Err`, jamais 0. La branche ENTIER
    /// (une `meta` sans affinité, hors schéma) est tenue sur une base à part.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=egp_lecture_avalee` (toute lecture ratée ou illisible rend 0, la
    /// forme d'avant) ; `VERIF_MUT=egp_type_autre_zero` (un BLOB ou un NULL vaut 0) ; `VERIF_MUT=egp_entier_refuse`
    /// (un entier SQL est refusé).
    #[test]
    fn egp_une_epoque_non_lue_ne_vaut_jamais_zero() {
        let (st, _p) = egp_etat("lecture");
        let c = st.db.lock();
        assert_eq!(lire_l_epoque_de_session(&c), Ok(0), "base neuve : la ligne posée à '0' se lit 0");
        c.execute("UPDATE meta SET value='7' WHERE key='session_epoch'", []).expect("fixture");
        assert_eq!(lire_l_epoque_de_session(&c), Ok(7));
        c.execute("UPDATE meta SET value=12 WHERE key='session_epoch'", []).expect("fixture");
        let rangee: String = c.query_row("SELECT typeof(value) FROM meta WHERE key='session_epoch'", [], |r| r.get(0)).expect("fixture");
        assert_eq!(rangee, "text", "affinité TEXT : l'entier écrit est rangé en texte");
        assert_eq!(lire_l_epoque_de_session(&c), Ok(12), "et lu par la branche texte");
        for illisible in ["sept", "", "7 "] {
            c.execute("UPDATE meta SET value=?1 WHERE key='session_epoch'", params![illisible]).expect("fixture");
            let lue = lire_l_epoque_de_session(&c);
            assert!(lue.as_ref().is_err_and(|cause| cause.contains("illisible")), "« {illisible} » : {lue:?}");
        }
        for (illisible, attendu) in [("X'3132'", "blob"), ("NULL", "null")] {
            c.execute(&format!("UPDATE meta SET value={illisible} WHERE key='session_epoch'"), []).expect("fixture");
            let rangee: String = c.query_row("SELECT typeof(value) FROM meta WHERE key='session_epoch'", [], |r| r.get(0)).expect("fixture");
            assert_eq!(rangee, attendu, "fixture : {illisible} rangé tel quel");
            let lue = lire_l_epoque_de_session(&c);
            assert!(lue.as_ref().is_err_and(|cause| cause.contains("illisible")), "{illisible} : {lue:?}");
        }
        c.execute("DELETE FROM meta WHERE key='session_epoch'", []).expect("fixture");
        assert_eq!(lire_l_epoque_de_session(&c), Ok(0), "ligne absente : l'époque d'origine");
        c.execute_batch("DROP TABLE meta").expect("fixture");
        let lue = lire_l_epoque_de_session(&c);
        assert!(lue.as_ref().is_err_and(|cause| cause.contains("lecture de meta ratée")), "meta illisible : {lue:?}");
    }

    /// CE QU'IL TIENT : `meta` non inscriptible (`ABORT` puis `IGNORE`) -> la déconnexion GLOBALE d'un admin rend
    /// `503` + `CAUSE_DECONNEXION_GLOBALE_NON_PERSISTEE`, n'efface aucun cookie, n'avance ni l'époque mémoire ni la
    /// persistée, n'inscrit RIEN au registre, et la session d'`alice` vaut toujours. Contrôle positif : déclencheurs
    /// retirés, le même geste rend 200, l'époque avance en mémoire ET sur disque, un maillon.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=egp_ecriture_non_comptee` (une écriture de zéro ligne vaut
    /// succès — rougit sur `IGNORE`) ; `VERIF_MUT=egp_globale_avalee` (l'échec de persistance est ignoré dans la
    /// révocation globale — rougit sur `ABORT`).
    #[tokio::test]
    async fn egp_revocation_globale_non_persistee_rend_503_et_ne_revoque_rien() {
        for mode in ["ABORT", "IGNORE"] {
            let (st, _p) = egp_etat(&format!("globale-{}", mode.to_ascii_lowercase()));
            let alice = egp_session(&st, "alice", "editor");
            let adm = egp_session(&st, "adm", "admin");
            let e0 = st.session_epoch.load(Ordering::SeqCst);
            egp_meta_non_inscriptible(&st, mode);
            let (statut, efface, corps) = egp_deconnexion(&st, &adm, Some("globale")).await;
            assert_eq!((statut, efface), (503, false), "{mode} : {corps}");
            assert_eq!(corps["error"], json!(CAUSE_DECONNEXION_GLOBALE_NON_PERSISTEE), "{mode} : {corps}");
            assert_eq!(st.session_epoch.load(Ordering::SeqCst), e0, "{mode} : époque mémoire inchangée");
            assert_eq!(egp_persistee(&st), e0, "{mode} : époque persistée inchangée");
            assert_eq!(egp_traces_globales(&st), 0, "{mode} : rien n'est tracé « révoquées »");
            assert!(egp_identite(&st, &alice).is_some(), "{mode} : alice reste connectée");

            st.db.lock().execute_batch("DROP TRIGGER egp_refus_upd; DROP TRIGGER egp_refus_ins;").expect("fixture");
            let (statut, efface, corps) = egp_deconnexion(&st, &adm, Some("globale")).await;
            assert_eq!((statut, efface), (200, true), "{mode} contrôle positif : {corps}");
            assert_eq!(st.session_epoch.load(Ordering::SeqCst), e0 + 1, "{mode} : l'époque mémoire avance");
            assert_eq!(egp_persistee(&st), e0 + 1, "{mode} : l'époque PERSISTÉE avance");
            assert_eq!(egp_traces_globales(&st), 1, "{mode} : un maillon");
            assert!(egp_identite(&st, &alice).is_none(), "{mode} : alice est révoquée");
        }
    }

    /// CE QU'IL TIENT : le registre retiré (le maillon ne s'inscrit pas) APRÈS que l'époque a été écrite dans la
    /// transaction -> `503` + `CAUSE_DECONNEXION_GLOBALE_NON_TRACEE`, et l'époque PERSISTÉE est ANNULÉE avec la trace
    /// (pas de révocation invisible qui naîtrait au redémarrage) ; époque mémoire inchangée.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=egp_persistee_sans_trace` (la trace manquante n'annule pas la
    /// transaction : l'époque persistée avance seule).
    #[tokio::test]
    async fn egp_une_trace_manquante_annule_l_epoque_persistee() {
        let (st, _p) = egp_etat("non-tracee");
        let adm = egp_session(&st, "adm", "admin");
        let e0 = st.session_epoch.load(Ordering::SeqCst);
        st.db.lock().execute_batch("DROP TABLE ledger").expect("fixture : registre retiré");
        let (statut, efface, corps) = egp_deconnexion(&st, &adm, Some("globale")).await;
        assert_eq!((statut, efface), (503, false), "{corps}");
        assert_eq!(corps["error"], json!(CAUSE_DECONNEXION_GLOBALE_NON_TRACEE), "{corps}");
        assert_eq!(st.session_epoch.load(Ordering::SeqCst), e0, "époque mémoire inchangée");
        assert_eq!(egp_persistee(&st), e0, "époque persistée ANNULÉE avec la trace");
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte");
    }

    /// CE QU'IL TIENT : mode 1, `meta` non inscriptible -> la déconnexion d'une session valide rend `503` +
    /// `CAUSE_REVOCATION_GLOBALE_NON_PERSISTEE`, efface les cookies de ce navigateur, n'avance ni l'époque mémoire ni la
    /// persistée ; `bump_session_epoch` rend la cause. Contrôle positif : déclencheurs retirés, 200 et l'époque avance
    /// en mémoire ET sur disque (le sens de `bump_session_epoch_persists_and_increments`).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=egp_mode1_avale` (l'échec de persistance du mode 1 est ignoré, la
    /// réponse est le 200 d'avant).
    #[tokio::test]
    async fn egp_mode_1_revocation_non_persistee_rend_503() {
        let (st, _p) = egp_etat("mode-1");
        let mut st1 = st.clone();
        st1.multi_tenant = true;
        let e0 = st1.session_epoch.load(Ordering::SeqCst);
        let jeton = mint_session_du_compte(st1.session_secret.as_slice(), "bob", "editor", 3600, e0, 0);
        egp_meta_non_inscriptible(&st1, "ABORT");
        let (statut, efface, corps) = egp_deconnexion(&st1, &jeton, None).await;
        assert_eq!((statut, efface), (503, true), "{corps}");
        assert_eq!(corps["error"], json!(CAUSE_REVOCATION_GLOBALE_NON_PERSISTEE), "{corps}");
        assert_eq!(st1.session_epoch.load(Ordering::SeqCst), e0, "époque mémoire inchangée");
        assert_eq!(egp_persistee(&st1), e0, "époque persistée inchangée");
        assert!(bump_session_epoch(&st1).is_err(), "bump_session_epoch rend la cause");
        assert_eq!(st1.session_epoch.load(Ordering::SeqCst), e0, "et n'avance pas la mémoire");

        st1.db.lock().execute_batch("DROP TRIGGER egp_refus_upd; DROP TRIGGER egp_refus_ins;").expect("fixture");
        let (statut, efface, corps) = egp_deconnexion(&st1, &jeton, None).await;
        assert_eq!((statut, efface), (200, true), "contrôle positif : {corps}");
        assert_eq!((st1.session_epoch.load(Ordering::SeqCst), egp_persistee(&st1)), (e0 + 1, e0 + 1));
    }

    /// CE QU'IL TIENT : la branche ENTIER, sur une `meta` SANS affinité (hors schéma : `typeof` rend `integer`) -> la
    /// valeur est lue telle quelle.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=egp_entier_refuse`.
    #[test]
    fn egp_un_entier_sql_hors_affinite_est_lu_tel_quel() {
        let c = Connection::open_in_memory().expect("fixture");
        c.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY, value); INSERT INTO meta VALUES('session_epoch', 12);").expect("fixture");
        let rangee: String = c.query_row("SELECT typeof(value) FROM meta", [], |r| r.get(0)).expect("fixture");
        assert_eq!(rangee, "integer", "fixture : rangé en entier");
        assert_eq!(lire_l_epoque_de_session(&c), Ok(12));
    }

    /// CE QU'IL TIENT : LE REFUS DE DÉMARRER, mesuré sur un PROCESSUS. Ce binaire de test est ré-exécuté sur CE seul
    /// test ; l'enfant appelle `load_session_epoch` sur une `meta` dont l'époque vaut `valeur`. Époque illisible
    /// (`'sept'`, puis `meta` absente) -> l'enfant sort en 78 et dit « FATAL » et `session_epoch` sur sa sortie d'erreur ;
    /// contrôle positif : `'5'` -> l'enfant lit 5 et sort en 0 (« 1 passed » : il a VRAIMENT joué).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=egp_demarrage_avale` (une époque non lue vaut 0 au démarrage, la forme
    /// d'avant : l'enfant sort en 0).
    #[test]
    fn egp_une_epoque_non_lue_refuse_de_demarrer_en_78() {
        const VALEUR_POUR_L_ENFANT: &str = "EGP_EPOQUE_DE_L_ENFANT";
        if let Ok(valeur) = std::env::var(VALEUR_POUR_L_ENFANT) {
            let c = Connection::open_in_memory().expect("enfant : base");
            if valeur != "SANS_META" {
                c.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)").expect("enfant : meta");
                c.execute("INSERT INTO meta VALUES('session_epoch', ?1)", params![valeur]).expect("enfant : époque");
            }
            assert_eq!(load_session_epoch(&c), 5, "enfant : seule l'époque lisible '5' rend la main");
            return;
        }
        let jouer = |valeur: &str| -> (Option<i32>, String, String) {
            let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
                .args([
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                    "tests::epoque_globale_lue_et_persistee::egp_une_epoque_non_lue_refuse_de_demarrer_en_78",
                ])
                .env(VALEUR_POUR_L_ENFANT, valeur)
                .output()
                .expect("ré-exécution du binaire de test");
            (sortie.status.code(), String::from_utf8_lossy(&sortie.stdout).into_owned(), String::from_utf8_lossy(&sortie.stderr).into_owned())
        };
        let (code, sortie, erreurs) = jouer("5");
        assert!(sortie.contains("1 passed"), "contrôle positif : l'enfant a VRAIMENT joué le test\n{sortie}\n{erreurs}");
        assert_eq!(code, Some(0), "contrôle positif : une époque lisible démarre\n{sortie}\n{erreurs}");
        for illisible in ["sept", "SANS_META"] {
            let (code, sortie, erreurs) = jouer(illisible);
            assert_eq!(code, Some(78), "{illisible} : refus de démarrer en 78 (EX_CONFIG)\n{sortie}\n{erreurs}");
            assert!(erreurs.contains("FATAL") && erreurs.contains("session_epoch"), "{illisible} : la cause est dite\n{erreurs}");
        }
    }

    /// CE QU'IL TIENT : la transaction de la révocation globale NON OUVERTE (une transaction orpheline tient l'écrivain,
    /// le phénomène de `P10.27-z`) -> `503` + `CAUSE_DECONNEXION_GLOBALE_NON_PERSISTEE`, aucun cookie effacé, époque
    /// mémoire et persistée inchangées, rien au registre, alice toujours connectée.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=egp_non_ouvert_avale` (BEGIN refusé : l'époque avance en mémoire
    /// seulement, 200).
    #[tokio::test]
    async fn egp_revocation_globale_non_ouverte_rend_503() {
        let (st, _p) = egp_etat("non-ouverte");
        let alice = egp_session(&st, "alice", "editor");
        let adm = egp_session(&st, "adm", "admin");
        let e0 = st.session_epoch.load(Ordering::SeqCst);
        st.db.lock().execute_batch("BEGIN").expect("fixture : transaction orpheline sur l'écrivain");
        let (statut, efface, corps) = egp_deconnexion(&st, &adm, Some("globale")).await;
        st.db.lock().execute_batch("ROLLBACK").expect("fixture : orpheline levée");
        assert_eq!((statut, efface), (503, false), "{corps}");
        assert_eq!(corps["error"], json!(CAUSE_DECONNEXION_GLOBALE_NON_PERSISTEE), "{corps}");
        assert_eq!(st.session_epoch.load(Ordering::SeqCst), e0, "époque mémoire inchangée");
        assert_eq!(egp_persistee(&st), e0, "époque persistée inchangée");
        assert_eq!(egp_traces_globales(&st), 0, "rien n'est tracé « révoquées »");
        assert!(egp_identite(&st, &alice).is_some(), "alice reste connectée");
    }

    /// CE QU'IL TIENT : la transaction de la révocation globale NON VALIDÉE (le `COMMIT` refusé par une clé étrangère
    /// différée qu'un déclencheur sur `meta` viole) -> `503` + `CAUSE_DECONNEXION_GLOBALE_NON_PERSISTEE`, époque mémoire
    /// et persistée inchangées, rien au registre, aucune transaction laissée ouverte, alice toujours connectée.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=egp_non_valide_avale` (COMMIT refusé : l'époque avance en mémoire
    /// seulement, 200).
    #[tokio::test]
    async fn egp_revocation_globale_non_validee_rend_503() {
        let (st, _p) = egp_etat("non-validee");
        let alice = egp_session(&st, "alice", "editor");
        let adm = egp_session(&st, "adm", "admin");
        let e0 = st.session_epoch.load(Ordering::SeqCst);
        st.db
            .lock()
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 CREATE TABLE egp_parent(id INTEGER PRIMARY KEY);
                 CREATE TABLE egp_enfant(p INTEGER REFERENCES egp_parent(id) DEFERRABLE INITIALLY DEFERRED);
                 CREATE TRIGGER egp_fk_upd AFTER UPDATE ON meta WHEN NEW.key='session_epoch' BEGIN INSERT INTO egp_enfant VALUES(999); END;
                 CREATE TRIGGER egp_fk_ins AFTER INSERT ON meta WHEN NEW.key='session_epoch' BEGIN INSERT INTO egp_enfant VALUES(999); END;",
            )
            .expect("fixture : clé étrangère différée violée par la révocation");
        let (statut, efface, corps) = egp_deconnexion(&st, &adm, Some("globale")).await;
        assert_eq!((statut, efface), (503, false), "{corps}");
        assert_eq!(corps["error"], json!(CAUSE_DECONNEXION_GLOBALE_NON_PERSISTEE), "{corps}");
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte");
        assert_eq!(st.session_epoch.load(Ordering::SeqCst), e0, "époque mémoire inchangée");
        assert_eq!(egp_persistee(&st), e0, "époque persistée inchangée");
        assert_eq!(egp_traces_globales(&st), 0, "rien n'est tracé « révoquées »");
        assert!(egp_identite(&st, &alice).is_some(), "alice reste connectée");
    }
}

// =====================================================================================
// `P11.25-f` (vague CG, deux restes de la clé) — UN PANNEAU NE SE CRÉE PAS SUR UN TABLEAU ABSENT, ADMINISTRATEUR COMPRIS ;
// UN TABLEAU DONT LE DROIT NE PEUT PAS ÊTRE ÉTABLI RÉPOND COMME UN TABLEAU ABSENT.
//
// LES ROUTES QUI ÉCRIVENT UNE LIGNE RATTACHÉE À UN TABLEAU PAR UN IDENTIFIANT FOURNI PAR L'APPELANT (handlers/dashboards.rs
// et handlers/dash_ergonomics.rs) : `POST /api/panels` (`dashboard_id`, 0 par défaut), `POST /api/views/{id}/dashboards`
// (`dashboard_ids`), `DELETE /api/views/{id}/dashboards/{dashboard_id}`, `POST /api/dashboard-snapshots` (`dashboard_id`).
// Les listes de lecture rangent des identifiants de tableaux dans `items` sans les lire, pour tout rôle : hors de ce lot.
//
// LE DÉFAUT, MESURÉ PAR LA ROUTE SUR b46ef997 (ces témoins joués sur la source d'avant) : l'administrateur créait un
// panneau sur un `dashboard_id` absent ou 0 (200, panneau orphelin écrit) là où un éditeur recevait 404 « dashboard
// introuvable » — les trois autres routes rendaient déjà le 404 de l'absent à l'administrateur ; un propriétaire ou une
// visibilité de type inattendu (BLOB, texte qui n'est pas de l'UTF-8) servait le 503 d'une lecture ratée sur les quatre
// routes et sur les gestes de panneau, pour l'éditeur, et pour l'administrateur sur les trois routes qui lisent la ligne
// elles-mêmes. Une colonne `TEXT` ne garde pas un entier : `visibility=7` est relu `text` (affinité TEXT, contrôle écrit).
//
// CE QUE CES TÉMOINS TIENNENT, par le ROUTEUR réel (alice et bob éditeurs, adm administrateur) :
//   (1) chaque route × {adm, bob} × {tableau absent, identifiant 0, tableau présent} : statut et corps exacts, et le
//       compte de la table écrite après chaque envoi ; l'administrateur reçoit sur l'absent la réponse de l'éditeur, à
//       l'octet hors `date`, et rien n'est écrit ; sur un tableau présent, chacun écrit comme avant ;
//   (2) droit de type inattendu (visibilité BLOB, propriétaire BLOB, propriétaire en UTF-8 invalide) : bob reçoit sur
//       chaque route et sur `POST`/`DELETE /api/panels/{id}` la réponse de l'identifiant absent de la même route, rien
//       n'est écrit, pas de 503 ; l'administrateur écrit sur chacune ; contrôles : visibilité écrite `7` (relue `text`,
//       bob refusé comme avant), propriétaire NULL d'un tableau commun (semé : bob écrit) ;
//   (3) une vraie lecture ratée (lecture de `dashboard.owner` refusée par l'autorisateur) : le 503 nommé de chaque route,
//       corps entier, pour l'administrateur comme pour bob, rien n'est écrit ;
//   (4) le panneau orphelin d'une base ancienne reste modifiable et supprimable par l'administrateur, absent pour bob.
//
// MUTATIONS (posées sous `cfg!(test)`, armées par la variable de mutation de l'exécuteur, vues rouges puis retirées) :
// `CG3_ADMIN_SANS_LECTURE` (la porte rend `Ouverte` à l'administrateur sans lire) -> (1) et (3) ;
// `CG3_NON_ETABLI_ADMIN_REFUSE` (droit non établi refusé à l'administrateur) -> (2) ;
// `CG3_NON_ETABLI_OUVERT` (droit non établi ouvert à tout compte) -> (2) ;
// `CG3_NULL_NON_ETABLI` (NULL lu comme un type inattendu) -> (2) contrôle semé ;
// `CG3_UTF8_LOSSY` (l'UTF-8 invalide relu avec remplacement) -> (2) propriétaire UTF-8 invalide ;
// `CG3_BLOB_EN_TEXTE` (le BLOB relu comme du texte) -> (2) visibilité BLOB ;
// `CG3_PORTE_TYPEE`, `CG3_VA_TYPEE`, `CG3_VR_TYPEE`, `CG3_SC_TYPEE` (la lecture en `String` d'avant, site par site :
// porte, rattachement, retrait, instantané) -> (2) ;
// `CG3_ORPHELIN_ADMIN_ABSENT` (le bras de l'orphelin retiré de `panneau_editable`) -> (4).
//
// CE QU'ILS NE TIENNENT PAS : les lectures typées propres de `dash_update` (visibilité, dashboards.rs) et de `dash_delete`
// (propriétaire et visibilité) servent encore le 503 d'une lecture ratée sur une valeur BLOB, comme les routes de
// lecture `dash_get` et `panel_access` ; ce que la console peint.
// =====================================================================================
mod tableau_absent_ou_droit_non_etabli_repond_comme_un_absent {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const CG3_MDP: &str = "cg3pw1234567";
    /// Un identifiant qu'aucun tableau ni panneau ne porte.
    const CG3_ABSENT: i64 = 999_999;
    const CG3_INTROUVABLE: &str = "dashboard introuvable";
    const CG3_INCONNUS: &str = "TABLEAU DE BORD INCONNU : au moins un identifiant demandé ne désigne aucun tableau de bord que vous voyez — RIEN n'est rattaché, aucun des autres non plus (tout ou rien).";
    const CG3_RATTACHEMENT_ABSENT: &str = "RATTACHEMENT ABSENT : ce tableau de bord n'est pas rangé dans cette vue — rien n'est retiré.";
    const CG3_DROIT_NON_LU: &str = "DROIT D'ÉDITION NON LU : la base a refusé la lecture du propriétaire et de la visibilité de l'objet — ce n'est pas un refus de droit, et RIEN n'est écrit. Réessayez ; si le refus persiste, la base est illisible ou verrouillée.";
    const CG3_RATTACHEMENTS_NON_LUS: &str = "RATTACHEMENTS INCHANGÉS : la base n'a pas rendu la vue, les tableaux de bord demandés ou leurs rattachements — ce n'est PAS une absence, c'est une lecture qui n'a pas eu lieu, et ni le droit ni la présence ne sont jugés. RIEN n'est rattaché ni retiré. Réessayez ; si le refus persiste, la table des vues ou des tableaux de bord est illisible.";
    const CG3_INSTANTANE_NON_LU: &str = "INSTANTANÉ NON CRÉÉ : la base n'a pas rendu ce tableau de bord (nom, propriétaire, visibilité) — ce n'est PAS « dashboard introuvable », c'est une lecture qui n'a pas eu lieu. RIEN n'est capturé ni partagé : aucun jeton n'est émis. Réessayez ; si le refus persiste, la table des tableaux de bord est illisible.";

    /// Une base de routeur sans objet de tableau de bord, trois comptes (alice et bob éditeurs, adm administrateur) et une
    /// vue commune d'alice ; rend la vue.
    fn cg3_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, i64) {
        let (st, p) = router_test_state(&format!("cg3-{tag}"));
        let h = hash_pw(CG3_MDP).expect("fixture : empreinte");
        let vue = {
            let c = st.db.lock();
            c.execute_batch(
                "DELETE FROM panel; DELETE FROM dashboard; DELETE FROM view_dashboard; DELETE FROM view; DELETE FROM dashboard_snapshot;",
            )
            .expect("fixture : base vide");
            for (nom, role) in [("alice", "editor"), ("bob", "editor"), ("adm", "admin")] {
                c.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![nom, h, role]).expect("fixture : compte");
            }
            c.execute("INSERT INTO view(name,owner,visibility) VALUES('vue commune','alice','shared')", []).expect("fixture : vue");
            c.last_insert_rowid()
        };
        (st, p, vue)
    }

    /// Un tableau d'alice sous une visibilité ; rend son identifiant.
    fn cg3_tableau(st: &AppState, nom: &str, visibilite: &str) -> i64 {
        let c = st.db.lock();
        c.execute("INSERT INTO dashboard(name,created,owner,visibility) VALUES(?1,1000,'alice',?2)", params![nom, visibilite]).expect("fixture : tableau");
        c.last_insert_rowid()
    }

    fn cg3_panneau(st: &AppState, tableau: i64, titre: &str) -> i64 {
        let c = st.db.lock();
        c.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,visibility) VALUES(?1,?2,'search | stats count',1,'table','shared')", params![tableau, titre])
            .expect("fixture : panneau");
        c.last_insert_rowid()
    }

    fn cg3_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn cg3_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture `{sql}` : {e}"))
    }

    fn cg3_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture `{sql}` : {e}"))
    }

    /// Tout ce que ces gestes écrivent, relu d'un coup (panneaux, rattachements, instantanés, tableaux).
    fn cg3_empreinte(st: &AppState) -> String {
        cg3_texte(
            st,
            "SELECT COALESCE(group_concat(x, ';'), '') FROM (SELECT x FROM (
                SELECT 'p'||id||'|'||dashboard_id||'|'||title AS x FROM panel
                UNION ALL SELECT 'r'||view_id||'|'||dashboard_id||'|'||explicite FROM view_dashboard
                UNION ALL SELECT 's'||id||'|'||dashboard_id FROM dashboard_snapshot
                UNION ALL SELECT 'd'||id||'|'||name||'|'||hex(owner)||'|'||hex(visibility) FROM dashboard
             ) ORDER BY x)",
        )
    }

    fn cg3_authz(nom: &str) -> String {
        format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{nom}:{CG3_MDP}")))
    }

    async fn cg3_envoi(addr: std::net::SocketAddr, qui: &str, methode: &str, chemin: &str, corps: &str) -> (u16, String) {
        let en_json = [("Content-Type", "application/json")];
        let entetes: &[(&str, &str)] = if corps.is_empty() { &[] } else { &en_json };
        router_probe_envoi(addr, methode, chemin, Some(&cg3_authz(qui)), entetes, corps).await
    }

    /// La réponse brute sans sa ligne `date`.
    fn cg3_sans_date(texte: &str) -> String {
        texte.split("\r\n").filter(|l| !l.to_ascii_lowercase().starts_with("date:")).collect::<Vec<_>>().join("\r\n")
    }

    /// Le corps d'une réponse (découpage `chunked` retiré quand l'en-tête l'annonce).
    fn cg3_corps(texte: &str) -> String {
        let Some((entetes, corps)) = texte.split_once("\r\n\r\n") else { return String::new() };
        if !entetes.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            return corps.to_string();
        }
        let (mut reste, mut sortie) = (corps.as_bytes(), Vec::new());
        loop {
            let Some(fin) = reste.windows(2).position(|w| w == b"\r\n") else { panic!("morceau sans taille : {texte}") };
            let taille = usize::from_str_radix(std::str::from_utf8(&reste[..fin]).unwrap_or("").trim(), 16).unwrap_or_else(|_| panic!("taille illisible : {texte}"));
            if taille == 0 {
                break;
            }
            sortie.extend_from_slice(&reste[fin + 2..fin + 2 + taille]);
            reste = &reste[fin + 2 + taille + 2..];
        }
        String::from_utf8_lossy(&sortie).into_owned()
    }

    fn cg3_json(texte: &str) -> Value {
        serde_json::from_str(&cg3_corps(texte)).unwrap_or_else(|_| panic!("corps JSON attendu : {texte}"))
    }

    fn cg3_creation(tableau: Option<i64>) -> String {
        match tableau {
            Some(d) => format!(r#"{{"dashboard_id":{d},"title":"cg3","query":"search | stats count","is_soql":true}}"#),
            None => r#"{"title":"cg3","query":"search | stats count","is_soql":true}"#.to_string(),
        }
    }

    /// Le 503 nommé d'une lecture ratée : clés exactes `error` et `id`, phrase entière, identifiant de corrélation servi.
    fn cg3_juger_503(quoi: &str, code: u16, t: &str, phrase: &str) {
        let v = cg3_json(t);
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(|k| k.as_str()).collect()).unwrap_or_default();
        assert_eq!((code, cles, v["error"].as_str()), (503, vec!["error", "id"], Some(phrase)), "{quoi} : le 503 nommé, corps entier : {t}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {t}");
    }

    // -------------------------------------------------------------------------------------
    // (1) tableau absent, identifiant 0, tableau présent — par route, pour l'administrateur et pour l'éditeur
    // -------------------------------------------------------------------------------------

    /// `POST /api/panels`. MUTATION : `CG3_ADMIN_SANS_LECTURE`.
    #[tokio::test]
    async fn cg3_creation_de_panneau_tableau_absent_ou_zero_404_administrateur_compris() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, _) = cg3_etat("pc");
        let d = cg3_tableau(&st, "commun", "shared");
        let addr = router_serve(st.clone()).await;
        let panneaux = |st: &AppState| cg3_compte(st, "SELECT COUNT(*) FROM panel");

        let (code, editeur) = cg3_envoi(addr, "bob", "POST", "/api/panels", &cg3_creation(Some(CG3_ABSENT))).await;
        assert_eq!((code, cg3_corps(&editeur).as_str()), (404, CG3_INTROUVABLE), "bob, tableau absent");
        for (quel, corps) in [("absent", cg3_creation(Some(CG3_ABSENT))), ("identifiant 0", cg3_creation(Some(0))), ("champ omis (0)", cg3_creation(None))] {
            for qui in ["adm", "bob"] {
                let (code, t) = cg3_envoi(addr, qui, "POST", "/api/panels", &corps).await;
                assert_eq!((code, cg3_corps(&t).as_str()), (404, CG3_INTROUVABLE), "({qui}) tableau {quel} : 404 « dashboard introuvable » : {t}");
                assert_eq!(cg3_sans_date(&t), cg3_sans_date(&editeur), "({qui}) tableau {quel} : la réponse de l'éditeur, à l'octet");
                assert_eq!(panneaux(&st), 0, "({qui}) tableau {quel} : aucun panneau écrit");
            }
        }
        let (code, t) = cg3_envoi(addr, "adm", "POST", "/api/panels", &cg3_creation(Some(d))).await;
        assert_eq!(code, 200, "adm, tableau présent : {t}");
        let id = cg3_compte(&st, &format!("SELECT MAX(id) FROM panel WHERE dashboard_id={d}"));
        assert_eq!(cg3_json(&t), json!({ "id": id }), "adm, tableau présent : l'identifiant écrit");
        assert_eq!(panneaux(&st), 1, "adm, tableau présent : un panneau écrit");
        let (code, t) = cg3_envoi(addr, "bob", "POST", "/api/panels", &cg3_creation(Some(d))).await;
        assert_eq!(code, 200, "bob, tableau commun présent : {t}");
        let id = cg3_compte(&st, &format!("SELECT MAX(id) FROM panel WHERE dashboard_id={d}"));
        assert_eq!(cg3_json(&t), json!({ "id": id }), "bob, tableau présent : l'identifiant écrit");
        assert_eq!(panneaux(&st), 2, "bob, tableau présent : un second panneau écrit");
    }

    /// `POST /api/views/{id}/dashboards` : l'absent était déjà refusé à l'administrateur (mesuré), tenu ici.
    #[tokio::test]
    async fn cg3_rattachement_a_une_vue_tableau_absent_ou_zero_404_administrateur_compris() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, vue) = cg3_etat("va");
        let (d_adm, d_bob) = (cg3_tableau(&st, "pour adm", "shared"), cg3_tableau(&st, "pour bob", "shared"));
        let addr = router_serve(st.clone()).await;
        let chemin = format!("/api/views/{vue}/dashboards");
        let rattachements = |st: &AppState| cg3_compte(st, "SELECT COUNT(*) FROM view_dashboard");
        for qui in ["adm", "bob"] {
            for id in [CG3_ABSENT, 0] {
                let (code, t) = cg3_envoi(addr, qui, "POST", &chemin, &format!(r#"{{"dashboard_ids":[{id}]}}"#)).await;
                assert_eq!((code, cg3_json(&t)), (404, json!({ "error": CG3_INCONNUS, "dashboard_ids": [id] })), "({qui}) tableau {id} : 404 inconnu");
                assert_eq!(rattachements(&st), 0, "({qui}) tableau {id} : rien n'est rattaché");
            }
        }
        let (code, t) = cg3_envoi(addr, "adm", "POST", &chemin, &format!(r#"{{"dashboard_ids":[{d_adm}]}}"#)).await;
        assert_eq!((code, cg3_json(&t)), (200, json!({ "added": [d_adm], "already_present": [] })), "adm, tableau présent");
        assert_eq!(rattachements(&st), 1, "adm, tableau présent : un rattachement écrit");
        let (code, t) = cg3_envoi(addr, "bob", "POST", &chemin, &format!(r#"{{"dashboard_ids":[{d_bob}]}}"#)).await;
        assert_eq!((code, cg3_json(&t)), (200, json!({ "added": [d_bob], "already_present": [] })), "bob, tableau présent");
        assert_eq!(rattachements(&st), 2, "bob, tableau présent : un second rattachement écrit");
    }

    /// `DELETE /api/views/{id}/dashboards/{dashboard_id}` : l'absent était déjà refusé à l'administrateur, tenu ici.
    #[tokio::test]
    async fn cg3_retrait_d_une_vue_tableau_absent_ou_zero_404_administrateur_compris() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, vue) = cg3_etat("vr");
        let (d_adm, d_bob) = (cg3_tableau(&st, "pour adm", "shared"), cg3_tableau(&st, "pour bob", "shared"));
        cg3_ecrire(&st, &format!("INSERT INTO view_dashboard(view_id,dashboard_id,explicite) VALUES({vue},{d_adm},1),({vue},{d_bob},1);"));
        let addr = router_serve(st.clone()).await;
        let rattachements = |st: &AppState| cg3_compte(st, "SELECT COUNT(*) FROM view_dashboard");
        for qui in ["adm", "bob"] {
            for id in [CG3_ABSENT, 0] {
                let (code, t) = cg3_envoi(addr, qui, "DELETE", &format!("/api/views/{vue}/dashboards/{id}"), "").await;
                assert_eq!((code, cg3_json(&t)), (404, json!({ "error": CG3_RATTACHEMENT_ABSENT })), "({qui}) tableau {id} : 404 rattachement absent");
                assert_eq!(rattachements(&st), 2, "({qui}) tableau {id} : rien n'est retiré");
            }
        }
        let (code, t) = cg3_envoi(addr, "adm", "DELETE", &format!("/api/views/{vue}/dashboards/{d_adm}"), "").await;
        assert_eq!((code, cg3_corps(&t).as_str()), (204, ""), "adm, tableau présent");
        assert_eq!(rattachements(&st), 1, "adm, tableau présent : un rattachement retiré");
        let (code, t) = cg3_envoi(addr, "bob", "DELETE", &format!("/api/views/{vue}/dashboards/{d_bob}"), "").await;
        assert_eq!((code, cg3_corps(&t).as_str()), (204, ""), "bob, tableau présent");
        assert_eq!(rattachements(&st), 0, "bob, tableau présent : le second retiré");
    }

    /// `POST /api/dashboard-snapshots` : l'absent était déjà refusé à l'administrateur, tenu ici.
    #[tokio::test]
    async fn cg3_instantane_tableau_absent_ou_zero_404_administrateur_compris() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, _) = cg3_etat("sc");
        let d = cg3_tableau(&st, "commun", "shared");
        let addr = router_serve(st.clone()).await;
        let instantanes = |st: &AppState| cg3_compte(st, "SELECT COUNT(*) FROM dashboard_snapshot");
        for qui in ["adm", "bob"] {
            for corps in [format!(r#"{{"dashboard_id":{CG3_ABSENT}}}"#), r#"{"dashboard_id":0}"#.to_string(), "{}".to_string()] {
                let (code, t) = cg3_envoi(addr, qui, "POST", "/api/dashboard-snapshots", &corps).await;
                assert_eq!((code, cg3_corps(&t).as_str()), (404, CG3_INTROUVABLE), "({qui}) {corps} : 404 « dashboard introuvable »");
                assert_eq!(instantanes(&st), 0, "({qui}) {corps} : rien n'est capturé");
            }
        }
        for (qui, attendu) in [("adm", 1), ("bob", 2)] {
            let (code, t) = cg3_envoi(addr, qui, "POST", "/api/dashboard-snapshots", &format!(r#"{{"dashboard_id":{d}}}"#)).await;
            let v = cg3_json(&t);
            let id = cg3_compte(&st, &format!("SELECT COALESCE(MAX(id),0) FROM dashboard_snapshot WHERE dashboard_id={d}"));
            let jeton = cg3_texte(&st, &format!("SELECT COALESCE((SELECT token FROM dashboard_snapshot WHERE id={id}),'')"));
            assert_eq!((code, v), (200, json!({ "id": id, "token": jeton })), "({qui}) tableau présent : l'instantané écrit");
            assert_eq!(instantanes(&st), attendu, "({qui}) tableau présent : un instantané de plus");
        }
    }

    // -------------------------------------------------------------------------------------
    // (2) droit de type inattendu
    // -------------------------------------------------------------------------------------

    /// Un tableau d'alice dont le droit est altéré par `alteration` (`{d}` : son identifiant), avec deux panneaux et un
    /// rattachement à la vue ; puis bob et l'administrateur sur chaque route. `bob_lit` : le droit altéré reste un droit
    /// établi que bob lit (contrôle semé), sinon bob reçoit la réponse de l'absent de chaque route. `owner_seul` : la
    /// visibilité n'est pas altérée, `POST /api/dashboard/{id}` (dont la lecture de visibilité est propre) est joué aussi.
    async fn cg3_juger_le_droit_altere(tag: &str, visibilite: &str, alteration: &str, controle_de_type: (&str, &str), bob_lit: bool, owner_seul: bool) {
        let (st, _p, vue) = cg3_etat(tag);
        let d = cg3_tableau(&st, "altéré", visibilite);
        let (p_maj, p_suppr) = (cg3_panneau(&st, d, "à modifier"), cg3_panneau(&st, d, "à supprimer"));
        cg3_ecrire(&st, &format!("INSERT INTO view_dashboard(view_id,dashboard_id,explicite) VALUES({vue},{d},1);"));
        cg3_ecrire(&st, &alteration.replace("{d}", &d.to_string()));
        assert_eq!(cg3_texte(&st, &format!("SELECT {} FROM dashboard WHERE id={d}", controle_de_type.0)), controle_de_type.1, "fixture ({tag}) : type relu");
        let addr = router_serve(st.clone()).await;
        let va = format!("/api/views/{vue}/dashboards");

        // bob
        let avant = cg3_empreinte(&st);
        // (méthode, chemin, corps, chemin de l'absent, corps de l'absent)
        let mut gestes: Vec<(&str, String, String, String, String)> = vec![
            ("POST", "/api/panels".into(), cg3_creation(Some(d)), "/api/panels".into(), cg3_creation(Some(CG3_ABSENT))),
            ("DELETE", format!("{va}/{d}"), String::new(), format!("{va}/{CG3_ABSENT}"), String::new()),
            ("POST", "/api/dashboard-snapshots".into(), format!(r#"{{"dashboard_id":{d}}}"#), "/api/dashboard-snapshots".into(), format!(r#"{{"dashboard_id":{CG3_ABSENT}}}"#)),
            ("POST", format!("/api/panels/{p_maj}"), r#"{"title":"écrit"}"#.into(), format!("/api/panels/{CG3_ABSENT}"), r#"{"title":"écrit"}"#.into()),
            ("DELETE", format!("/api/panels/{p_suppr}"), String::new(), format!("/api/panels/{CG3_ABSENT}"), String::new()),
        ];
        if owner_seul {
            gestes.push(("POST", format!("/api/dashboard/{d}"), r#"{"name":"écrit"}"#.into(), format!("/api/dashboard/{CG3_ABSENT}"), r#"{"name":"écrit"}"#.into()));
        }
        if !bob_lit {
            for (methode, chemin, corps, chemin_absent, corps_absent) in &gestes {
                let (code, t) = cg3_envoi(addr, "bob", methode, chemin, corps).await;
                let (code_absent, absent) = cg3_envoi(addr, "bob", methode, chemin_absent, corps_absent).await;
                assert_eq!((code, cg3_sans_date(&t)), (code_absent, cg3_sans_date(&absent)), "({tag}) bob {methode} {chemin} : la réponse de l'absent, à l'octet");
                assert_eq!(code, 404, "({tag}) bob {methode} {chemin} : 404, pas 503 : {t}");
                assert_eq!(cg3_empreinte(&st), avant, "({tag}) bob {methode} {chemin} : rien n'est écrit");
            }
            // Le rattachement à une vue sert l'identifiant demandé : la réponse d'un absent qui porterait ce numéro.
            let (code, t) = cg3_envoi(addr, "bob", "POST", &va, &format!(r#"{{"dashboard_ids":[{d}]}}"#)).await;
            assert_eq!((code, cg3_json(&t)), (404, json!({ "error": CG3_INCONNUS, "dashboard_ids": [d] })), "({tag}) bob rattachement : inconnu, pas 503");
            assert_eq!(cg3_empreinte(&st), avant, "({tag}) bob rattachement : rien n'est écrit");
        } else {
            let (code, t) = cg3_envoi(addr, "bob", "POST", "/api/panels", &cg3_creation(Some(d))).await;
            assert_eq!(code, 200, "({tag}) bob, droit établi qu'il lit : le panneau est créé : {t}");
            assert_eq!(cg3_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE dashboard_id={d}")), 3, "({tag}) bob : un panneau de plus");
        }

        // l'administrateur : il lit et modifie tout tableau présent, droit non établi compris.
        let panneaux = |st: &AppState| cg3_compte(st, &format!("SELECT COUNT(*) FROM panel WHERE dashboard_id={d}"));
        let base = panneaux(&st);
        let (code, t) = cg3_envoi(addr, "adm", "POST", "/api/panels", &cg3_creation(Some(d))).await;
        assert_eq!(code, 200, "({tag}) adm crée un panneau : {t}");
        assert_eq!(panneaux(&st), base + 1, "({tag}) adm : un panneau écrit");
        let (code, t) = cg3_envoi(addr, "adm", "POST", &format!("/api/panels/{p_maj}"), r#"{"title":"repris"}"#).await;
        assert_eq!(code, 204, "({tag}) adm modifie un panneau : {t}");
        assert_eq!(cg3_texte(&st, &format!("SELECT title FROM panel WHERE id={p_maj}")), "repris", "({tag}) adm : le titre écrit");
        let (code, t) = cg3_envoi(addr, "adm", "DELETE", &format!("/api/panels/{p_suppr}"), "").await;
        assert_eq!(code, 204, "({tag}) adm supprime un panneau : {t}");
        assert_eq!(cg3_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE id={p_suppr}")), 0, "({tag}) adm : le panneau supprimé");
        let (code, t) = cg3_envoi(addr, "adm", "DELETE", &format!("{va}/{d}"), "").await;
        assert_eq!((code, cg3_corps(&t).as_str()), (204, ""), "({tag}) adm retire le rattachement");
        assert_eq!(cg3_compte(&st, "SELECT COUNT(*) FROM view_dashboard"), 0, "({tag}) adm : le rattachement retiré");
        let (code, t) = cg3_envoi(addr, "adm", "POST", &va, &format!(r#"{{"dashboard_ids":[{d}]}}"#)).await;
        assert_eq!((code, cg3_json(&t)), (200, json!({ "added": [d], "already_present": [] })), "({tag}) adm rattache le tableau");
        assert_eq!(cg3_compte(&st, "SELECT COUNT(*) FROM view_dashboard"), 1, "({tag}) adm : le rattachement écrit");
        let (code, t) = cg3_envoi(addr, "adm", "POST", "/api/dashboard-snapshots", &format!(r#"{{"dashboard_id":{d}}}"#)).await;
        assert_eq!(code, 200, "({tag}) adm capture le tableau : {t}");
        assert_eq!(cg3_compte(&st, &format!("SELECT COUNT(*) FROM dashboard_snapshot WHERE dashboard_id={d}")), 1, "({tag}) adm : un instantané écrit");
        if owner_seul {
            let (code, t) = cg3_envoi(addr, "adm", "POST", &format!("/api/dashboard/{d}"), r#"{"name":"réparé"}"#).await;
            assert_eq!(code, 204, "({tag}) adm modifie le tableau : {t}");
            assert_eq!(cg3_texte(&st, &format!("SELECT name FROM dashboard WHERE id={d}")), "réparé", "({tag}) adm : le nom écrit");
        }
    }

    /// Visibilité BLOB (les octets de `shared`). MUTATIONS : `CG3_BLOB_EN_TEXTE`, `CG3_NON_ETABLI_OUVERT`,
    /// `CG3_NON_ETABLI_ADMIN_REFUSE`, `CG3_PORTE_TYPEE`, `CG3_VA_TYPEE`, `CG3_VR_TYPEE`, `CG3_SC_TYPEE`.
    #[tokio::test]
    async fn cg3_visibilite_blob_absente_pour_l_editeur_modifiable_par_l_administrateur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        cg3_juger_le_droit_altere("vis-blob", "shared", "UPDATE dashboard SET visibility=X'736861726564' WHERE id={d};", ("typeof(visibility)", "blob"), false, false).await;
    }

    /// Propriétaire BLOB (les octets de `bob`) sur un tableau COMMUN : le droit ne s'établit pas, même déclaré commun.
    /// MUTATIONS : `CG3_NON_ETABLI_OUVERT`, `CG3_NON_ETABLI_ADMIN_REFUSE`, `CG3_PORTE_TYPEE`, `CG3_VA_TYPEE`,
    /// `CG3_VR_TYPEE`, `CG3_SC_TYPEE`, `CG3_BLOB_EN_TEXTE`.
    #[tokio::test]
    async fn cg3_proprietaire_blob_absent_pour_l_editeur_modifiable_par_l_administrateur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        cg3_juger_le_droit_altere("owner-blob", "shared", "UPDATE dashboard SET owner=X'626f62' WHERE id={d};", ("typeof(owner)", "blob"), false, true).await;
    }

    /// Propriétaire en texte qui n'est pas de l'UTF-8, tableau commun. MUTATIONS : `CG3_UTF8_LOSSY`,
    /// `CG3_NON_ETABLI_OUVERT`, `CG3_NON_ETABLI_ADMIN_REFUSE`.
    #[tokio::test]
    async fn cg3_proprietaire_utf8_invalide_absent_pour_l_editeur_modifiable_par_l_administrateur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        cg3_juger_le_droit_altere("owner-utf8", "shared", "UPDATE dashboard SET owner=CAST(X'FF62' AS TEXT) WHERE id={d};", ("typeof(owner)", "text"), false, true).await;
    }

    /// Contrôle : la visibilité écrite en ENTIER est relue `text` (affinité TEXT) ; `'7'` n'est pas `shared`, bob reçoit
    /// l'absent comme pour tout tableau privé d'autrui, l'administrateur écrit.
    #[tokio::test]
    async fn cg3_visibilite_entiere_relue_en_texte_absente_pour_l_editeur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        cg3_juger_le_droit_altere("vis-entier", "shared", "UPDATE dashboard SET visibility=7 WHERE id={d};", ("typeof(visibility)||':'||visibility", "text:7"), false, false).await;
    }

    /// Contrôle : propriétaire NULL d'un tableau commun (semé) — un droit ÉTABLI, que bob lit. MUTATION : `CG3_NULL_NON_ETABLI`.
    #[tokio::test]
    async fn cg3_proprietaire_null_d_un_tableau_commun_reste_lu_par_l_editeur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        cg3_juger_le_droit_altere("owner-null", "shared", "UPDATE dashboard SET owner=NULL WHERE id={d};", ("typeof(owner)", "null"), true, true).await;
    }

    // -------------------------------------------------------------------------------------
    // (3) une vraie lecture ratée garde son 503 nommé, administrateur compris
    // -------------------------------------------------------------------------------------

    /// La lecture de `dashboard.owner` refusée par l'autorisateur : chaque route sert son 503 nommé, corps entier, à
    /// l'administrateur comme à bob, et rien n'est écrit. MUTATION : `CG3_ADMIN_SANS_LECTURE` (l'administrateur crée).
    #[tokio::test]
    async fn cg3_lecture_ratee_du_droit_garde_son_503_administrateur_compris() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, vue) = cg3_etat("lecture-ratee");
        let d = cg3_tableau(&st, "commun", "shared");
        cg3_ecrire(&st, &format!("INSERT INTO view_dashboard(view_id,dashboard_id,explicite) VALUES({vue},{d},1);"));
        let addr = router_serve(st.clone()).await;
        let avant = cg3_empreinte(&st);
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "dashboard", column_name: "owner" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let mut vus: Vec<(String, u16, String)> = Vec::new();
        for qui in ["adm", "bob"] {
            let (c, t) = cg3_envoi(addr, qui, "POST", "/api/panels", &cg3_creation(Some(d))).await;
            vus.push((format!("{qui} panel_create"), c, t));
            let (c, t) = cg3_envoi(addr, qui, "POST", &format!("/api/views/{vue}/dashboards"), &format!(r#"{{"dashboard_ids":[{d}]}}"#)).await;
            vus.push((format!("{qui} view_dashboards_add"), c, t));
            let (c, t) = cg3_envoi(addr, qui, "DELETE", &format!("/api/views/{vue}/dashboards/{d}"), "").await;
            vus.push((format!("{qui} view_dashboard_remove"), c, t));
            let (c, t) = cg3_envoi(addr, qui, "POST", "/api/dashboard-snapshots", &format!(r#"{{"dashboard_id":{d}}}"#)).await;
            vus.push((format!("{qui} snapshot_create"), c, t));
        }
        st.db.lock().authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        assert_eq!(vus.len(), 8, "contrôle : quatre routes, deux comptes");
        for (quoi, c, t) in &vus {
            let phrase = if quoi.ends_with("panel_create") {
                CG3_DROIT_NON_LU
            } else if quoi.ends_with("snapshot_create") {
                CG3_INSTANTANE_NON_LU
            } else {
                CG3_RATTACHEMENTS_NON_LUS
            };
            cg3_juger_503(quoi, *c, t, phrase);
        }
        assert_eq!(cg3_empreinte(&st), avant, "lecture ratée : rien n'est écrit");
    }

    // -------------------------------------------------------------------------------------
    // (4) le panneau orphelin d'une base ancienne
    // -------------------------------------------------------------------------------------

    /// Un panneau posé en base sur un tableau absent : bob reçoit la réponse d'un panneau absent à la suppression, rien
    /// n'est retiré ; l'administrateur le modifie puis le supprime. MUTATION : `CG3_ORPHELIN_ADMIN_ABSENT`.
    #[tokio::test]
    async fn cg3_panneau_orphelin_reste_a_l_administrateur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, _) = cg3_etat("orphelin");
        let orphelin = cg3_panneau(&st, CG3_ABSENT - 1, "orphelin");
        let addr = router_serve(st.clone()).await;
        let (code_absent, absent) = cg3_envoi(addr, "bob", "DELETE", &format!("/api/panels/{CG3_ABSENT}"), "").await;
        let (code, t) = cg3_envoi(addr, "bob", "DELETE", &format!("/api/panels/{orphelin}"), "").await;
        assert_eq!((code, cg3_sans_date(&t)), (code_absent, cg3_sans_date(&absent)), "bob : la réponse d'un panneau absent");
        assert_eq!(cg3_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE id={orphelin}")), 1, "bob : l'orphelin reste");
        let (code, t) = cg3_envoi(addr, "adm", "POST", &format!("/api/panels/{orphelin}"), r#"{"title":"repris"}"#).await;
        assert_eq!(code, 204, "adm modifie l'orphelin : {t}");
        assert_eq!(cg3_texte(&st, &format!("SELECT title FROM panel WHERE id={orphelin}")), "repris", "adm : le titre écrit");
        let (code, t) = cg3_envoi(addr, "adm", "DELETE", &format!("/api/panels/{orphelin}"), "").await;
        assert_eq!((code, cg3_corps(&t).as_str()), (204, ""), "adm supprime l'orphelin");
        assert_eq!(cg3_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE id={orphelin}")), 0, "adm : l'orphelin retiré");
    }
}

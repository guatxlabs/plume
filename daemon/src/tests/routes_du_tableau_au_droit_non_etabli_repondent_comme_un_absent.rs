// =====================================================================================
// `P11.25-f` (vague CH) — UN TABLEAU DONT LE DROIT NE PEUT PAS ÊTRE ÉTABLI RÉPOND COMME UN ABSENT SUR SES PROPRES ROUTES,
// ET L'ADMINISTRATEUR PEUT LE RETIRER.
//
// LES ROUTES (handlers/dashboards.rs) : `GET /api/dashboards` (`dash_list`, et le compte de `views_list` qui emprunte son
// filtre), `GET`, `POST` et `DELETE /api/dashboard/{id}` (`dash_get`, `dash_update`, `dash_delete`), `GET
// /api/panels/{id}/data` (`panel_data`, par `panel_access`).
//
// LE DÉFAUT, MESURÉ PAR LA ROUTE SUR 0bf7de5c : un propriétaire ou une visibilité de type inattendu (BLOB, texte qui n'est
// pas de l'UTF-8) faisait échouer la lecture typée de ces routes : 503 d'une lecture ratée sur `dash_get`, `dash_delete` et
// `panel_data`, administrateur compris, 503 sur `dash_update` d'une visibilité BLOB, et la liste entière servie illisible
// (200, `error`, aucun tableau) à tout compte qui la voyait — l'administrateur toujours. La ligne n'était réparable par
// aucune route.
//
// CE QUE CES TÉMOINS TIENNENT, par le ROUTEUR réel (alice et bob éditeurs, bob propriétaire d'un autre tableau, carol
// lectrice, adm administrateur), sur trois formes : propriétaire BLOB (les octets de `bob`, tableau commun), visibilité
// BLOB (les octets de `shared`) d'un tableau dont bob est le propriétaire en texte, propriétaire en texte qui n'est pas de
// l'UTF-8 (tableau commun) :
//   (1) bob et carol, chaque route : statut et réponse brute (hors `date`) de l'identifiant absent de la même route, pas
//       de 503, tableaux et panneaux inchangés (valeurs écrites relues) ; la liste et le compte de la vue sont ceux d'une
//       base où la ligne n'existe pas ;
//   (2) l'administrateur : la liste le sert, le total le compte, `dash_get` le sert, les champs illisibles rendus comme une
//       colonne NULL (`''`, `'shared'`), tout autre champ à l'octet de ce que la route servait avant l'altération ;
//       `dash_update` aboutit sur chaque forme ; sur une visibilité BLOB, tenue pour « pas encore commune », un corps qui
//       publie est jugé par la porte `P11.20-m` (409 qui nomme le panneau privé, rien d'écrit) et `private` la répare
//       en texte ; `panel_data` garde le 503 « panneau non lu » ; `dash_delete` aboutit : la ligne et ses panneaux
//       partent, les tableaux voisins et leurs panneaux restent ;
//   (3) une vraie lecture ratée (lecture de `dashboard.owner` refusée) garde le 503 nommé de chaque route ;
//   (4) un tableau sain : réponses entières de la liste et de la lecture, statuts et corps des écritures, accès aux données
//       d'un panneau (le contenu servi dépend du cache), joué à l'identique sur 0bf7de5c ;
//   (5) la fonction SQL du droit établi : sa règle, et sa pose qui ne redéfinit pas une fonction déjà posée.
//
// MUTATIONS (sous `cfg!(test)`, armées par la variable de mutation de l'exécuteur, vues rouges puis retirées) :
// `CH2_GET_TYPEE` (dash_get : lecture en `String`) -> (1), (2) ; `CH2_GET_LISIBLE` (décision par `lisible_par` des champs
// servis) -> (1) ; `CH2_DEL_TYPEE` (idem dash_delete) -> (1), (2) ; `CH2_DEL_LISIBLE` (droit non établi ouvert à tout
// compte) -> (1) ; `CH2_UPD_TYPEE` (visibilité lue en `String`) -> (1) ; `CH2_UPD_ADMIN_SHARED` (visibilité illisible lue
// `shared` pour l'administrateur) -> (2) ; `CH2_UPD_ADMIN_503` (le 503 « visibilité non lue » d'avant rendu à
// l'administrateur sur une visibilité BLOB) -> (2) ; `CH2_PA_TYPEE` (panel_access : lecture en `String` pour tous) -> (1) ;
// `CH2_PA_ADMIN_OUVERT` (l'administrateur exécute) -> (2) ; `CH2_FILTRE_SANS_DROIT` (le filtre sans la fonction) -> (1)
// liste et vue ; `CH2_LISTE_SANS_POSE` (dash_list) -> (1), (2), (4) ; `CH2_VUES_SANS_POSE` (views_list) -> (1), (2) ;
// `CH2_LISTE_TYPEE` (dash_list : lecture en `String`) -> (2) ; `CH2_SERVI_PRIVE` (une visibilité illisible servie
// `private`) -> (2) ; `CH2_UDF_LOSSY`, `CH2_UDF_BLOB` (la fonction relit l'UTF-8 invalide avec remplacement, le BLOB
// comme du texte) -> (1), (5) ; `CH2_POSE_TOUJOURS` (la fonction redéfinie à chaque appel) -> (5).
// (3) et (4) passent aussi sur 0bf7de5c : ils tiennent ce qui ne change pas.
//
// CE QU'ILS NE TIENNENT PAS : l'administrateur ne lit pas les données d'un panneau d'un tel tableau (503 d'avant,
// gardé) ; la porte d'une vue qu'on partage
// (`element_moins_visible_d_une_vue`, dashboards.rs, et `ElementMoinsVisible::d_une_vue`, panneau_resolu.rs) lit encore le
// propriétaire d'un tableau rangé en texte.
// =====================================================================================
mod routes_du_tableau_au_droit_non_etabli_repondent_comme_un_absent {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const CH2_MDP: &str = "ch2pw1234567";
    /// Un identifiant qu'aucun tableau ni panneau ne porte.
    const CH2_ABSENT: i64 = 999_999;
    const CH2_TABLEAU_NON_LU: &str = "TABLEAU DE BORD NON LU : la base n'a pas rendu ce tableau de bord (nom, propriétaire, visibilité) — ce n'est PAS « dashboard introuvable », c'est une lecture qui n'a pas eu lieu, et le droit de le voir n'est pas jugé. RIEN n'est servi. Réessayez ; si le refus persiste, la table des tableaux de bord est illisible.";
    const CH2_NON_SUPPRIME_NON_LU: &str = "TABLEAU DE BORD NON SUPPRIMÉ : la base n'a pas rendu ce tableau de bord (son propriétaire) — ce n'est PAS une absence, c'est une lecture qui n'a pas eu lieu, et le droit de le supprimer n'est pas jugé. RIEN n'est supprimé : le tableau de bord et ses panneaux sont intacts. Réessayez ; si le refus persiste, la table des tableaux de bord est illisible.";
    const CH2_PANNEAU_NON_LU: &str = "PANNEAU NON LU : la base n'a pas rendu ce panneau ou son tableau de bord (fenêtre, visibilité, propriétaire) — ce n'est PAS « panneau inaccessible », c'est une lecture qui n'a pas eu lieu, et le droit de le voir n'est pas jugé. RIEN n'est exécuté ni servi. Réessayez ; si le refus persiste, la table des panneaux est illisible.";
    const CH2_DROIT_NON_LU: &str = "DROIT D'ÉDITION NON LU : la base a refusé la lecture du propriétaire et de la visibilité de l'objet — ce n'est pas un refus de droit, et RIEN n'est écrit. Réessayez ; si le refus persiste, la base est illisible ou verrouillée.";

    /// Une forme de droit non établi : étiquette, altération SQL de `{d}`, contrôle du type écrit, propriétaire et visibilité
    /// que l'administrateur doit lire.
    struct Forme {
        tag: &'static str,
        alteration: &'static str,
        controle: (&'static str, &'static str),
        servis: (&'static str, &'static str),
    }

    const CH2_FORMES: [Forme; 3] = [
        Forme { tag: "owner-blob", alteration: "UPDATE dashboard SET owner=X'626f62', visibility='shared' WHERE id={d};", controle: ("typeof(owner)||'/'||typeof(visibility)", "blob/text"), servis: ("", "shared") },
        Forme { tag: "vis-blob", alteration: "UPDATE dashboard SET owner='bob', visibility=X'736861726564' WHERE id={d};", controle: ("typeof(owner)||'/'||typeof(visibility)", "text/blob"), servis: ("bob", "shared") },
        Forme { tag: "owner-utf8", alteration: "UPDATE dashboard SET owner=CAST(X'FF62' AS TEXT), visibility='shared' WHERE id={d};", controle: ("typeof(owner)||'/'||hex(owner)", "text/FF62"), servis: ("", "shared") },
    ];

    /// Les identifiants d'une fixture : le tableau à altérer (privé d'alice avant l'altération) et ses deux panneaux, le
    /// tableau commun voisin d'alice et son panneau, le tableau privé de bob et son panneau, la vue commune qui range les
    /// trois.
    struct Jeu {
        d: i64,
        p: i64,
        voisin: i64,
        p_voisin: i64,
        de_bob: i64,
        p_de_bob: i64,
        vue: i64,
    }

    fn ch2_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, Jeu) {
        let (st, p) = router_test_state(&format!("ch2-{tag}"));
        let h = hash_pw(CH2_MDP).expect("fixture : empreinte");
        let jeu = {
            let c = st.db.lock();
            c.execute_batch("DELETE FROM panel; DELETE FROM dashboard; DELETE FROM view_dashboard; DELETE FROM view; DELETE FROM dashboard_snapshot;")
                .expect("fixture : base vide");
            for (nom, role) in [("alice", "editor"), ("bob", "editor"), ("carol", "viewer"), ("adm", "admin")] {
                c.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![nom, h, role]).expect("fixture : compte");
            }
            let tableau = |nom: &str, owner: &str, vis: &str| -> i64 {
                c.execute("INSERT INTO dashboard(name,created,owner,visibility) VALUES(?1,1000,?2,?3)", params![nom, owner, vis]).expect("fixture : tableau");
                c.last_insert_rowid()
            };
            let (d, voisin, de_bob) = (tableau("altéré", "alice", "private"), tableau("voisin", "alice", "shared"), tableau("de bob", "bob", "private"));
            let panneau = |tableau: i64, titre: &str| -> i64 {
                c.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,visibility) VALUES(?1,?2,'search | stats count',1,'table','shared')", params![tableau, titre])
                    .expect("fixture : panneau");
                c.last_insert_rowid()
            };
            let p = panneau(d, "premier");
            panneau(d, "second");
            let (p_voisin, p_de_bob) = (panneau(voisin, "du voisin"), panneau(de_bob, "de bob"));
            c.execute("INSERT INTO view(name,owner,visibility) VALUES('vue commune','alice','shared')", []).expect("fixture : vue");
            let vue = c.last_insert_rowid();
            for t in [d, voisin, de_bob] {
                c.execute("INSERT INTO view_dashboard(view_id,dashboard_id,explicite) VALUES(?1,?2,1)", params![vue, t]).expect("fixture : rattachement");
            }
            Jeu { d, p, voisin, p_voisin, de_bob, p_de_bob, vue }
        };
        (st, p, jeu)
    }

    fn ch2_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ch2_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture `{sql}` : {e}"))
    }

    fn ch2_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture `{sql}` : {e}"))
    }

    fn ch2_alterer(st: &AppState, jeu: &Jeu, f: &Forme) {
        ch2_ecrire(st, &f.alteration.replace("{d}", &jeu.d.to_string()));
        assert_eq!(ch2_texte(st, &format!("SELECT {} FROM dashboard WHERE id={}", f.controle.0, jeu.d)), f.controle.1, "fixture ({}) : type relu", f.tag);
    }

    /// Tableaux et panneaux, valeurs écrites (propriétaire et visibilité en hexadécimal), relus d'un coup.
    fn ch2_empreinte(st: &AppState) -> String {
        ch2_texte(
            st,
            "SELECT COALESCE(group_concat(x, ';'), '') FROM (SELECT x FROM (
                SELECT 'd'||id||'|'||name||'|'||hex(owner)||'|'||hex(visibility) AS x FROM dashboard
                UNION ALL SELECT 'p'||id||'|'||dashboard_id||'|'||title FROM panel
             ) ORDER BY x)",
        )
    }

    fn ch2_authz(nom: &str) -> String {
        format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{nom}:{CH2_MDP}")))
    }

    async fn ch2_envoi(addr: std::net::SocketAddr, qui: &str, methode: &str, chemin: &str, corps: &str) -> (u16, String) {
        let en_json = [("Content-Type", "application/json")];
        let entetes: &[(&str, &str)] = if corps.is_empty() { &[] } else { &en_json };
        router_probe_envoi(addr, methode, chemin, Some(&ch2_authz(qui)), entetes, corps).await
    }

    fn ch2_sans_date(texte: &str) -> String {
        texte.split("\r\n").filter(|l| !l.to_ascii_lowercase().starts_with("date:")).collect::<Vec<_>>().join("\r\n")
    }

    /// Le corps d'une réponse (découpage `chunked` retiré quand l'en-tête l'annonce).
    fn ch2_corps(texte: &str) -> String {
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

    fn ch2_json(texte: &str) -> Value {
        serde_json::from_str(&ch2_corps(texte)).unwrap_or_else(|_| panic!("corps JSON attendu : {texte}"))
    }

    /// Le 503 nommé : clés exactes `error` et `id`, phrase entière, identifiant de corrélation servi.
    fn ch2_juger_503(quoi: &str, code: u16, t: &str, phrase: &str) {
        let v = ch2_json(t);
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(|k| k.as_str()).collect()).unwrap_or_default();
        assert_eq!((code, cles, v["error"].as_str()), (503, vec!["error", "id"], Some(phrase)), "{quoi} : le 503 nommé, corps entier : {t}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {t}");
    }

    /// Les gestes d'un tableau et de son panneau, avec ceux de l'identifiant absent : (méthode, chemin, corps, chemin absent).
    fn ch2_gestes(d: i64, p: i64) -> Vec<(&'static str, String, &'static str, String)> {
        vec![
            ("GET", format!("/api/dashboard/{d}"), "", format!("/api/dashboard/{CH2_ABSENT}")),
            ("POST", format!("/api/dashboard/{d}"), r#"{"name":"écrit"}"#, format!("/api/dashboard/{CH2_ABSENT}")),
            ("POST", format!("/api/dashboard/{d}"), r#"{"visibility":"private"}"#, format!("/api/dashboard/{CH2_ABSENT}")),
            ("DELETE", format!("/api/dashboard/{d}"), "", format!("/api/dashboard/{CH2_ABSENT}")),
            ("GET", format!("/api/panels/{p}/data"), "", format!("/api/panels/{CH2_ABSENT}/data")),
        ]
    }

    /// L'entrée d'un tableau dans la liste de `qui`, et le total servi.
    async fn ch2_liste(addr: std::net::SocketAddr, qui: &str) -> (u16, String, Value) {
        let (code, t) = ch2_envoi(addr, qui, "GET", "/api/dashboards", "").await;
        let v = ch2_json(&t);
        (code, t, v)
    }

    fn ch2_entree(v: &Value, id: i64) -> Option<Value> {
        v["dashboards"].as_array().and_then(|a| a.iter().find(|e| e["id"].as_i64() == Some(id)).cloned())
    }

    /// Le compte de rattachements de la vue commune servi à `qui`.
    async fn ch2_compte_de_la_vue(addr: std::net::SocketAddr, qui: &str, vue: i64) -> (u16, String, Option<i64>) {
        let (code, t) = ch2_envoi(addr, qui, "GET", "/api/views", "").await;
        let v = ch2_json(&t);
        let n = v["views"].as_array().and_then(|a| a.iter().find(|e| e["id"].as_i64() == Some(vue))).and_then(|e| e["dashboards"].as_i64());
        (code, t, n)
    }

    // -------------------------------------------------------------------------------------
    // (1) bob et carol : la réponse de l'absent, route par route
    // -------------------------------------------------------------------------------------

    /// MUTATIONS : `CH2_GET_TYPEE`, `CH2_GET_LISIBLE`, `CH2_DEL_TYPEE`, `CH2_DEL_LISIBLE`, `CH2_UPD_TYPEE`, `CH2_PA_TYPEE`.
    #[tokio::test]
    async fn ch2_routes_du_tableau_et_du_panneau_rendent_l_absent_a_l_editeur_et_au_lecteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut formes_jouees = 0;
        for f in &CH2_FORMES {
            let (st, _p, jeu) = ch2_etat(f.tag);
            ch2_alterer(&st, &jeu, f);
            let addr = router_serve(st.clone()).await;
            let avant = ch2_empreinte(&st);
            let gestes = ch2_gestes(jeu.d, jeu.p);
            assert!(gestes.len() >= 5, "plancher : les cinq gestes");
            let mut joues = 0;
            for qui in ["bob", "carol"] {
                for (methode, chemin, corps, chemin_absent) in &gestes {
                    let (code, t) = ch2_envoi(addr, qui, methode, chemin, corps).await;
                    let (code_absent, absent) = ch2_envoi(addr, qui, methode, chemin_absent, corps).await;
                    assert_eq!((code, ch2_sans_date(&t)), (code_absent, ch2_sans_date(&absent)), "({}) {qui} {methode} {chemin} {corps} : la réponse de l'absent, à l'octet", f.tag);
                    assert!(code == 404 || code == 403, "({}) {qui} {methode} {chemin} : un refus d'absent, pas 503 : {t}", f.tag);
                    assert_eq!(ch2_empreinte(&st), avant, "({}) {qui} {methode} {chemin} : rien n'est écrit", f.tag);
                    joues += 1;
                }
            }
            assert_eq!(joues, 10, "({}) contrôle : cinq gestes, deux comptes", f.tag);
            // Contrôle de l'éditeur : bob reçoit 404 sur le tableau, 403 « panneau inaccessible » sur le panneau.
            let (code, t) = ch2_envoi(addr, "bob", "GET", &format!("/api/dashboard/{}", jeu.d), "").await;
            assert_eq!((code, ch2_corps(&t).as_str()), (404, "dashboard introuvable"), "({}) bob dash_get", f.tag);
            let (code, t) = ch2_envoi(addr, "bob", "GET", &format!("/api/panels/{}/data", jeu.p), "").await;
            assert_eq!((code, ch2_json(&t)), (403, json!({ "error": "panneau inaccessible" })), "({}) bob panel_data", f.tag);
            let (code, t) = ch2_envoi(addr, "bob", "DELETE", &format!("/api/dashboard/{}", jeu.d), "").await;
            assert_eq!((code, ch2_corps(&t).as_str()), (404, ""), "({}) bob dash_delete : 404 nu", f.tag);
            formes_jouees += 1;
        }
        assert_eq!(formes_jouees, 3, "plancher : chaque forme jouée jusqu'au bout");
    }

    /// La liste et le compte de la vue : ceux d'une base où la ligne n'existe pas, pour bob et carol (page, total, réponse
    /// brute hors `date`). MUTATIONS : `CH2_FILTRE_SANS_DROIT`, `CH2_UDF_LOSSY`, `CH2_UDF_BLOB`, `CH2_LISTE_SANS_POSE`,
    /// `CH2_VUES_SANS_POSE`.
    #[tokio::test]
    async fn ch2_liste_et_compte_de_la_vue_ne_servent_ni_ne_comptent_la_ligne_a_l_editeur_et_au_lecteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut formes_jouees = 0;
        for f in &CH2_FORMES {
            let (st, _p, jeu) = ch2_etat(&format!("liste-{}", f.tag));
            ch2_alterer(&st, &jeu, f);
            let addr = router_serve(st.clone()).await;
            let mut avec: Vec<(String, (u16, String), (u16, String))> = Vec::new();
            for qui in ["bob", "carol"] {
                let (code, t, v) = ch2_liste(addr, qui).await;
                assert_eq!((code, v.get("error")), (200, None), "({}) {qui} : la liste répond : {t}", f.tag);
                assert_eq!(ch2_entree(&v, jeu.d), None, "({}) {qui} : la ligne n'est pas listée : {t}", f.tag);
                let (code_v, tv, n) = ch2_compte_de_la_vue(addr, qui, jeu.vue).await;
                assert_eq!(code_v, 200, "({}) {qui} : la liste des vues répond : {tv}", f.tag);
                let attendu = if qui == "bob" { (2, 2) } else { (1, 1) };
                assert_eq!((v["total"].as_i64(), n), (Some(attendu.0), Some(attendu.1)), "({}) {qui} : total et compte de la vue sans la ligne : {t} / {tv}", f.tag);
                avec.push((qui.to_string(), (code, ch2_sans_date(&t)), (code_v, ch2_sans_date(&tv))));
            }
            ch2_ecrire(&st, &format!("DELETE FROM panel WHERE dashboard_id={d}; DELETE FROM view_dashboard WHERE dashboard_id={d}; DELETE FROM dashboard WHERE id={d};", d = jeu.d));
            assert_eq!(avec.len(), 2, "contrôle : deux comptes");
            for (qui, liste, vues) in &avec {
                let (code, t) = ch2_envoi(addr, qui, "GET", "/api/dashboards", "").await;
                assert_eq!(&(code, ch2_sans_date(&t)), liste, "({}) {qui} : la liste d'une base sans la ligne, à l'octet", f.tag);
                let (code, t) = ch2_envoi(addr, qui, "GET", "/api/views", "").await;
                assert_eq!(&(code, ch2_sans_date(&t)), vues, "({}) {qui} : les vues d'une base sans la ligne, à l'octet", f.tag);
            }
            formes_jouees += 1;
        }
        assert_eq!(formes_jouees, 3, "plancher : chaque forme jouée jusqu'au bout");
    }

    // -------------------------------------------------------------------------------------
    // (2) l'administrateur : il trouve, lit et retire la ligne
    // -------------------------------------------------------------------------------------

    /// MUTATIONS : `CH2_LISTE_TYPEE`, `CH2_LISTE_SANS_POSE`, `CH2_SERVI_PRIVE`, `CH2_GET_TYPEE`, `CH2_DEL_TYPEE`,
    /// `CH2_UPD_ADMIN_SHARED`, `CH2_UPD_ADMIN_503`, `CH2_PA_ADMIN_OUVERT`, `CH2_VUES_SANS_POSE`.
    #[tokio::test]
    async fn ch2_administrateur_trouve_lit_et_retire_le_tableau_au_droit_non_etabli() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut formes_jouees = 0;
        for f in &CH2_FORMES {
            let (st, _p, jeu) = ch2_etat(&format!("adm-{}", f.tag));
            let addr = router_serve(st.clone()).await;
            // Ce que la route servait avant l'altération.
            let (code, t, liste_saine) = ch2_liste(addr, "adm").await;
            assert_eq!(code, 200, "({}) contrôle : liste saine : {t}", f.tag);
            let entree_saine = ch2_entree(&liste_saine, jeu.d).unwrap_or_else(|| panic!("({}) contrôle : la ligne saine est listée : {t}", f.tag));
            let (code, t) = ch2_envoi(addr, "adm", "GET", &format!("/api/dashboard/{}", jeu.d), "").await;
            assert_eq!(code, 200, "({}) contrôle : lecture saine : {t}", f.tag);
            let lecture_saine = ch2_json(&t);
            let (_, tv, vue_saine) = ch2_compte_de_la_vue(addr, "adm", jeu.vue).await;
            assert_eq!(vue_saine, Some(3), "({}) contrôle : la vue compte trois tableaux pour l'administrateur : {tv}", f.tag);

            ch2_alterer(&st, &jeu, f);
            let attendre = |mut v: Value| {
                v["owner"] = json!(f.servis.0);
                v["visibility"] = json!(f.servis.1);
                v
            };
            let (code, t, liste) = ch2_liste(addr, "adm").await;
            assert_eq!((code, liste.get("error")), (200, None), "({}) adm : la liste reste lisible : {t}", f.tag);
            assert_eq!(ch2_entree(&liste, jeu.d), Some(attendre(entree_saine.clone())), "({}) adm : la ligne listée, champs illisibles servis comme NULL : {t}", f.tag);
            assert_eq!(liste["total"], liste_saine["total"], "({}) adm : le total la compte : {t}", f.tag);
            let (_, tv, n) = ch2_compte_de_la_vue(addr, "adm", jeu.vue).await;
            assert_eq!(n, Some(3), "({}) adm : la vue la compte : {tv}", f.tag);
            let (code, t) = ch2_envoi(addr, "adm", "GET", &format!("/api/dashboard/{}", jeu.d), "").await;
            assert_eq!((code, ch2_json(&t)), (200, attendre(lecture_saine.clone())), "({}) adm : dash_get la sert, champs illisibles servis comme NULL", f.tag);

            // Données d'un panneau : le 503 d'avant, rien d'exécuté.
            let (code, t) = ch2_envoi(addr, "adm", "GET", &format!("/api/panels/{}/data", jeu.p), "").await;
            ch2_juger_503(&format!("({}) adm panel_data", f.tag), code, &t, CH2_PANNEAU_NON_LU);

            // Modification : aboutit sur chaque forme, un renommage n'est pas un geste de partage.
            let (code, t) = ch2_envoi(addr, "adm", "POST", &format!("/api/dashboard/{}", jeu.d), r#"{"name":"réparé"}"#).await;
            assert_eq!((code, ch2_corps(&t).as_str()), (204, ""), "({}) adm dash_update aboutit", f.tag);
            assert_eq!(ch2_texte(&st, &format!("SELECT name FROM dashboard WHERE id={}", jeu.d)), "réparé", "({}) adm : le nom écrit", f.tag);
            if f.tag == "vis-blob" {
                // La visibilité BLOB vaut « pas encore commune » : un corps qui publie passe par la porte `P11.20-m`.
                assert_eq!(ch2_texte(&st, &format!("SELECT typeof(visibility) FROM dashboard WHERE id={}", jeu.d)), "blob", "(vis-blob) le renommage laisse la visibilité");
                ch2_ecrire(&st, &format!("UPDATE panel SET visibility='private' WHERE id={};", jeu.p));
                let avant = ch2_empreinte(&st);
                let (code, t) = ch2_envoi(addr, "adm", "POST", &format!("/api/dashboard/{}", jeu.d), r#"{"name":"publié","visibility":"shared"}"#).await;
                assert_eq!(code, 409, "(vis-blob) adm : le partage est jugé, un panneau privé le retient : {t}");
                assert!(ch2_corps(&t).starts_with("Partage refusé : le panneau « premier »"), "(vis-blob) le 409 nomme le panneau : {t}");
                assert_eq!(ch2_empreinte(&st), avant, "(vis-blob) adm : rien n'est écrit sur le refus");
                ch2_ecrire(&st, &format!("UPDATE panel SET visibility='shared' WHERE id={};", jeu.p));
                let (code, t) = ch2_envoi(addr, "adm", "POST", &format!("/api/dashboard/{}", jeu.d), r#"{"visibility":"private"}"#).await;
                assert_eq!((code, ch2_corps(&t).as_str()), (204, ""), "(vis-blob) adm : la visibilité se répare");
                assert_eq!(
                    ch2_texte(&st, &format!("SELECT typeof(visibility)||'/'||visibility FROM dashboard WHERE id={}", jeu.d)),
                    "text/private",
                    "(vis-blob) adm : la visibilité écrite en texte"
                );
            }

            // Suppression : la ligne et ses panneaux partent, les voisins restent.
            let voisins_avant = ch2_texte(&st, &format!("SELECT group_concat(x,';') FROM (SELECT 'd'||id||'|'||name||'|'||owner||'|'||visibility AS x FROM dashboard WHERE id IN ({},{}) UNION ALL SELECT 'p'||id||'|'||dashboard_id||'|'||title FROM panel WHERE id IN ({},{}) ORDER BY x)", jeu.voisin, jeu.de_bob, jeu.p_voisin, jeu.p_de_bob));
            assert_eq!((ch2_compte(&st, "SELECT COUNT(*) FROM dashboard"), ch2_compte(&st, "SELECT COUNT(*) FROM panel")), (3, 4), "({}) contrôle : avant la suppression", f.tag);
            let (code, t) = ch2_envoi(addr, "adm", "DELETE", &format!("/api/dashboard/{}", jeu.d), "").await;
            assert_eq!((code, ch2_corps(&t).as_str()), (204, ""), "({}) adm dash_delete aboutit", f.tag);
            assert_eq!(
                (ch2_compte(&st, &format!("SELECT COUNT(*) FROM dashboard WHERE id={}", jeu.d)), ch2_compte(&st, &format!("SELECT COUNT(*) FROM panel WHERE dashboard_id={}", jeu.d))),
                (0, 0),
                "({}) adm : la ligne et ses deux panneaux partis",
                f.tag
            );
            assert_eq!((ch2_compte(&st, "SELECT COUNT(*) FROM dashboard"), ch2_compte(&st, "SELECT COUNT(*) FROM panel")), (2, 2), "({}) adm : ni plus ni moins", f.tag);
            assert_eq!(
                ch2_texte(&st, &format!("SELECT group_concat(x,';') FROM (SELECT 'd'||id||'|'||name||'|'||owner||'|'||visibility AS x FROM dashboard WHERE id IN ({},{}) UNION ALL SELECT 'p'||id||'|'||dashboard_id||'|'||title FROM panel WHERE id IN ({},{}) ORDER BY x)", jeu.voisin, jeu.de_bob, jeu.p_voisin, jeu.p_de_bob)),
                voisins_avant,
                "({}) adm : les tableaux voisins et leurs panneaux intacts",
                f.tag
            );
            formes_jouees += 1;
        }
        assert_eq!(formes_jouees, 3, "plancher : chaque forme jouée jusqu'au bout");
    }

    // -------------------------------------------------------------------------------------
    // (3) une vraie lecture ratée garde son 503 nommé
    // -------------------------------------------------------------------------------------

    #[tokio::test]
    async fn ch2_lecture_ratee_du_proprietaire_garde_le_503_nomme_de_chaque_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, jeu) = ch2_etat("lecture-ratee");
        ch2_ecrire(&st, &format!("UPDATE dashboard SET visibility='shared' WHERE id={};", jeu.d));
        let addr = router_serve(st.clone()).await;
        let avant = ch2_empreinte(&st);
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "dashboard", column_name: "owner" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let mut vus: Vec<(String, u16, String, &str)> = Vec::new();
        for qui in ["adm", "bob"] {
            let (c, t) = ch2_envoi(addr, qui, "GET", &format!("/api/dashboard/{}", jeu.d), "").await;
            vus.push((format!("{qui} dash_get"), c, t, CH2_TABLEAU_NON_LU));
            let (c, t) = ch2_envoi(addr, qui, "POST", &format!("/api/dashboard/{}", jeu.d), r#"{"name":"écrit"}"#).await;
            vus.push((format!("{qui} dash_update"), c, t, CH2_DROIT_NON_LU));
            let (c, t) = ch2_envoi(addr, qui, "DELETE", &format!("/api/dashboard/{}", jeu.d), "").await;
            vus.push((format!("{qui} dash_delete"), c, t, CH2_NON_SUPPRIME_NON_LU));
            let (c, t) = ch2_envoi(addr, qui, "GET", &format!("/api/panels/{}/data", jeu.p), "").await;
            vus.push((format!("{qui} panel_data"), c, t, CH2_PANNEAU_NON_LU));
        }
        st.db.lock().authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        assert_eq!(vus.len(), 8, "contrôle : quatre routes, deux comptes");
        for (quoi, c, t, phrase) in &vus {
            ch2_juger_503(quoi, *c, t, phrase);
        }
        assert_eq!(ch2_empreinte(&st), avant, "lecture ratée : rien n'est écrit");
    }

    // -------------------------------------------------------------------------------------
    // (4) un tableau sain : réponses entières (jouées à l'identique sur 0bf7de5c)
    // -------------------------------------------------------------------------------------

    #[tokio::test]
    async fn ch2_tableau_sain_reponses_entieres_inchangees() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, jeu) = ch2_etat("sain");
        let addr = router_serve(st.clone()).await;
        let (d, v, b) = (jeu.d, jeu.voisin, jeu.de_bob);
        let panneau = |id: i64, titre: &str| {
            json!({ "id": id, "title": titre, "query": "search | stats count", "is_soql": true, "viz": "table", "position": 0, "window_s": 0,
                    "visibility": "shared", "query_private": false, "cols": 1, "height": 0, "drill": "", "library_panel_id": null })
        };
        let entree = |id: i64, nom: &str, owner: &str, vis: &str, editable: bool, panneaux: i64| {
            json!({ "id": id, "name": nom, "owner": owner, "visibility": vis, "view_id": null, "panels": panneaux, "cols": 2, "height": 0,
                    "collapsed": false, "position": id, "editable": editable, "all_views": false, "view_ids": [jeu.vue] })
        };
        let (p2, pv, pb) = (jeu.p + 1, jeu.p_voisin, jeu.p_de_bob);
        let liste = |qui: &str, role: &str, entrees: Vec<Value>| {
            let n = entrees.len();
            json!({ "dashboards": entrees, "me": qui, "role": role, "total": n, "limit": null, "offset": 0 })
        };
        let attendus_liste = [
            ("adm", liste("adm", "admin", vec![entree(d, "altéré", "alice", "private", true, 2), entree(v, "voisin", "alice", "shared", true, 1), entree(b, "de bob", "bob", "private", true, 1)])),
            ("alice", liste("alice", "editor", vec![entree(d, "altéré", "alice", "private", true, 2), entree(v, "voisin", "alice", "shared", true, 1)])),
            ("bob", liste("bob", "editor", vec![entree(v, "voisin", "alice", "shared", true, 1), entree(b, "de bob", "bob", "private", true, 1)])),
            ("carol", liste("carol", "viewer", vec![entree(v, "voisin", "alice", "shared", true, 1)])),
        ];
        let mut listes_jugees = 0;
        for (qui, attendu) in &attendus_liste {
            let (code, t, corps) = ch2_liste(addr, qui).await;
            assert_eq!((code, corps), (200, attendu.clone()), "{qui} : la liste entière : {t}");
            listes_jugees += 1;
        }
        assert_eq!(listes_jugees, 4, "plancher : chaque compte jugé");
        let lecture = |id: i64, nom: &str, owner: &str, vis: &str, panneaux: Vec<Value>| {
            json!({ "id": id, "name": nom, "owner": owner, "visibility": vis, "view_id": null, "editable": true, "panels": panneaux })
        };
        let mut lectures_jugees = 0;
        for (qui, id, attendu) in [
            ("adm", d, Some(lecture(d, "altéré", "alice", "private", vec![panneau(jeu.p, "premier"), panneau(p2, "second")]))),
            ("alice", d, Some(lecture(d, "altéré", "alice", "private", vec![panneau(jeu.p, "premier"), panneau(p2, "second")]))),
            ("bob", d, None),
            ("carol", d, None),
            ("bob", v, Some(lecture(v, "voisin", "alice", "shared", vec![panneau(pv, "du voisin")]))),
            ("carol", v, Some(lecture(v, "voisin", "alice", "shared", vec![panneau(pv, "du voisin")]))),
            ("bob", b, Some(lecture(b, "de bob", "bob", "private", vec![panneau(pb, "de bob")]))),
        ] {
            let (code, t) = ch2_envoi(addr, qui, "GET", &format!("/api/dashboard/{id}"), "").await;
            match attendu {
                Some(a) => assert_eq!((code, ch2_json(&t)), (200, a), "{qui} dash_get {id} : la lecture entière"),
                None => assert_eq!((code, ch2_corps(&t).as_str()), (404, "dashboard introuvable"), "{qui} dash_get {id} : absent"),
            }
            lectures_jugees += 1;
        }
        assert_eq!(lectures_jugees, 7, "plancher : chaque lecture jugée");
        // Données d'un panneau : l'accès décidé (le contenu servi dépend du cache, hors de ce témoin).
        let mut acces_juges = 0;
        for (qui, p, attendu) in [("bob", jeu.p, 403), ("carol", jeu.p, 403), ("bob", pv, 200), ("alice", jeu.p, 200), ("adm", pb, 200)] {
            let (code, t) = ch2_envoi(addr, qui, "GET", &format!("/api/panels/{p}/data"), "").await;
            assert_eq!(code, attendu, "{qui} panel_data {p} : {t}");
            if attendu == 403 {
                assert_eq!(ch2_json(&t), json!({ "error": "panneau inaccessible" }), "{qui} panel_data {p}");
            }
            acces_juges += 1;
        }
        assert_eq!(acces_juges, 5, "plancher : chaque accès jugé");
        // Écritures : bob 404 sur le privé d'alice, 403 nu à la suppression du commun d'alice ; alice modifie et supprime.
        let (code, t) = ch2_envoi(addr, "bob", "POST", &format!("/api/dashboard/{d}"), r#"{"name":"écrit"}"#).await;
        assert_eq!((code, ch2_corps(&t).as_str()), (404, ""), "bob dash_update du privé d'alice");
        let (code, t) = ch2_envoi(addr, "bob", "DELETE", &format!("/api/dashboard/{v}"), "").await;
        assert_eq!((code, ch2_corps(&t).as_str()), (403, ""), "bob dash_delete du commun d'alice");
        let (code, t) = ch2_envoi(addr, "bob", "POST", &format!("/api/dashboard/{v}"), r#"{"name":"voisin repris"}"#).await;
        assert_eq!((code, ch2_corps(&t).as_str()), (204, ""), "bob dash_update du commun d'alice");
        let (code, t) = ch2_envoi(addr, "alice", "POST", &format!("/api/dashboard/{d}"), r#"{"visibility":"private","name":"repris"}"#).await;
        assert_eq!((code, ch2_corps(&t).as_str()), (204, ""), "alice dash_update de son privé");
        let (code, t) = ch2_envoi(addr, "alice", "DELETE", &format!("/api/dashboard/{d}"), "").await;
        assert_eq!((code, ch2_corps(&t).as_str()), (204, ""), "alice dash_delete de son privé");
        let mut attendu = vec![
            format!("d{b}|de bob|626F62|70726976617465"),
            format!("d{v}|voisin repris|616C696365|736861726564"),
            format!("p{pb}|{b}|de bob"),
            format!("p{pv}|{v}|du voisin"),
        ];
        attendu.sort();
        assert_eq!(ch2_empreinte(&st), attendu.join(";"), "valeurs écrites après les gestes sains");
    }

    // -------------------------------------------------------------------------------------
    // (5) la fonction SQL du droit établi
    // -------------------------------------------------------------------------------------

    /// Sa règle, valeur par valeur. MUTATIONS : `CH2_UDF_LOSSY`, `CH2_UDF_BLOB`.
    #[test]
    fn ch2_fonction_du_droit_etabli_suit_la_regle_du_droit() {
        let conn = Connection::open_in_memory().expect("connexion");
        crate::handlers::dashboards::poser_la_fonction_du_droit_etabli(&conn).expect("pose");
        let rendu: String = conn
            .query_row(
                "SELECT plume_droit_du_tableau_etabli('alice','shared')||plume_droit_du_tableau_etabli(NULL,NULL)
                       ||plume_droit_du_tableau_etabli(X'626f62','shared')||plume_droit_du_tableau_etabli('alice',X'736861726564')
                       ||plume_droit_du_tableau_etabli(CAST(X'FF62' AS TEXT),'shared')||plume_droit_du_tableau_etabli('alice',CAST(X'FF' AS TEXT))
                       ||plume_droit_du_tableau_etabli('é','privé')",
                [],
                |r| r.get(0),
            )
            .expect("appel");
        assert_eq!(rendu, "1100001", "texte et NULL établis ; BLOB et UTF-8 invalide, dans chaque colonne, non établis");
    }

    /// La pose ne redéfinit pas une fonction déjà posée : une instruction préparée de la connexion n'est pas invalidée
    /// (compteur de re-préparation de SQLite). Contrôle : une redéfinition explicite l'invalide. MUTATION : `CH2_POSE_TOUJOURS`.
    #[test]
    fn ch2_pose_de_la_fonction_n_invalide_pas_les_instructions_de_la_connexion() {
        let conn = Connection::open_in_memory().expect("connexion");
        conn.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES(1);").expect("fixture");
        crate::handlers::dashboards::poser_la_fonction_du_droit_etabli(&conn).expect("première pose");
        let mut s = conn.prepare("SELECT count(*) FROM t").expect("préparation");
        let compter = |s: &mut rusqlite::Statement<'_>| s.query_row([], |r| r.get::<_, i64>(0)).expect("pas");
        assert_eq!(compter(&mut s), 1, "contrôle : une ligne");
        let reprep = |s: &rusqlite::Statement<'_>| s.get_status(rusqlite::StatementStatus::RePrepare);
        assert_eq!(reprep(&s), 0, "contrôle : aucune re-préparation");
        crate::handlers::dashboards::poser_la_fonction_du_droit_etabli(&conn).expect("seconde pose");
        compter(&mut s);
        assert_eq!(reprep(&s), 0, "la seconde pose n'invalide pas l'instruction");
        conn.create_scalar_function("plume_droit_du_tableau_etabli", 2, rusqlite::functions::FunctionFlags::SQLITE_UTF8, |_| Ok(1_i64)).expect("redéfinition");
        compter(&mut s);
        assert_eq!(reprep(&s), 1, "contrôle : une redéfinition invalide l'instruction (l'instrument voit)");
    }
}

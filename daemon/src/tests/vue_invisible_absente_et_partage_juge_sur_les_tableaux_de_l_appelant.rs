// =====================================================================================
// `P11.25-f` (vague CB) — UNE VUE QUE L'APPELANT NE VOIT PAS EST ABSENTE POUR LUI, ET LA PORTE DE PARTAGE D'UNE VUE NE
// JUGE QUE LES TABLEAUX QUE L'APPELANT POURRAIT PARTAGER LUI-MÊME.
//
// LE DÉFAUT, MESURÉ PAR LA ROUTE SUR LA BASE : bob range SON tableau privé dans la vue commune d'alice (permis : la vue
// classe, elle ne publie pas) ; alice rend sa vue privée (204) puis la repartage : 409 « le tableau de bord « Secret de
// bob » (n° …, à bob) est privé » — le nom, le numéro et le propriétaire d'un tableau qu'elle ne peut pas lire, et sa vue
// restait bloquée (elle ne peut ni le voir ni le retirer). Même défaut sur la vue principale
// (`panneau_resolu::ElementMoinsVisible::d_une_vue`) et sur la jointure (`element_moins_visible_d_une_vue`). Et
// `view_update` / `view_delete` répondaient 403 sur la vue privée d'autrui, 404 sur un identifiant absent : l'écart
// disait l'existence de la vue privée.
//
// CE QUE CES TÉMOINS TIENNENT, par le ROUTEUR réel (comptes réels alice et bob éditeurs, carol lectrice, adm
// administrateur) sauf le dernier, qui compte les lectures du gestionnaire :
//   * le privé de bob rangé dans la vue d'alice, par la vue principale ET par la jointure (deux témoins) : alice
//     repartage -> 204, la vue est commune ; carol ne reçoit ni le tableau ni son identifiant (liste filtrée par la vue,
//     liste entière, liste des vues, fiche du tableau) ; bob voit toujours le sien dans la vue ;
//   * le privé d'alice dans sa vue : le 409 d'avant, à l'octet (nom, numéro, propriétaire, type de contenu) ; ses privés
//     mêlés à ceux de bob (vue principale et jointure) : le 409 nomme le sien et ne compte que les siens ;
//   * l'administrateur : comportement d'avant — TOUT tableau privé de la vue retient, celui de bob compris, nommé avec
//     son propriétaire et compté ;
//   * lecture de la porte non faite (nom illisible du tableau d'alice, vue principale puis jointure) : le 503 nommé
//     d'avant, corps entier ;
//   * `POST` et `DELETE /api/views/{id}` par bob sur la vue PRIVÉE d'alice : réponse identique à l'octet (statut,
//     en-têtes hors `date`, corps vide) à celle d'un identifiant absent, et la vue reste (nom, visibilité,
//     rattachements relus) ; sur la vue COMMUNE d'alice : 403 ; vue semée privée (propriétaire NULL et vide) : bob -> la
//     réponse d'un identifiant absent, l'administrateur renomme et supprime ; la propriétaire renomme et supprime la
//     sienne (204) ;
//   * la décision (propriétaire, visibilité, ce que l'appelant voit) est UNE lecture : un seul SELECT préparé par le
//     gestionnaire avant le 403 et avant le 404 (autorisateur qui compte).
//
// CE QU'ILS NE TIENNENT PAS : ce que la console peint de ces réponses (aucune face console ici ; web/ ne distingue pas
// 403 et 404 sur ces deux routes). Le compte `dashboards` de `GET /api/views` ne compte que les rattachements que le
// lecteur lit : témoigné ci-dessous (carol 1, bob 2, sur la même vue).
//
// MUTATIONS (`VERIF_MUT=<nom>`, posées sous `cfg!(test)` le temps de la vérification puis retirées) : chaque témoin
// nomme les siennes.
// =====================================================================================
mod vue_invisible_absente_et_partage_juge_sur_les_tableaux_de_l_appelant {
    use super::*;
    use rusqlite::OptionalExtension;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Le mot de passe commun des comptes de témoin.
    const CB1_MDP: &str = "cb1pw1234567";
    /// Un identifiant qu'aucune vue ne porte.
    const CB1_ABSENTE: i64 = 999_999;
    /// L'identifiant du tableau privé de bob : reconnaissable dans un corps brut.
    const CB1_SECRET_DE_BOB: i64 = 777_001;
    /// Le 503 de la porte non lue (`panneau_resolu::CAUSE_ELEMENTS_RETENANT_NON_LUS`), écrit en littéral.
    const CB1_NON_LUS: &str = "ÉLÉMENTS RETENANT LE PARTAGE NON LUS : la porte qui refuse de publier un contenant portant un élément moins visible n'a pas pu juger, donc rien n'a été écrit. Ce n'est PAS « aucun élément ne le retient ». Réessayez.";

    /// Une base de routeur sans vue ni tableau, et quatre comptes réels : alice et bob éditeurs, carol lectrice, adm
    /// administrateur.
    fn cb1_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = router_test_state(&format!("cb1-{tag}"));
        let h = hash_pw(CB1_MDP).expect("fixture : empreinte");
        {
            let c = st.db.lock();
            c.execute_batch("DELETE FROM panel; DELETE FROM dashboard; DELETE FROM view_dashboard; DELETE FROM view;").expect("fixture : base vide");
            for (nom, role) in [("alice", "editor"), ("bob", "editor"), ("carol", "viewer"), ("adm", "admin")] {
                c.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![nom, h, role]).expect("fixture : compte");
            }
        }
        (st, p)
    }

    fn cb1_authz(nom: &str) -> String {
        format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{nom}:{CB1_MDP}")))
    }

    async fn cb1_envoi(addr: std::net::SocketAddr, qui: &str, methode: &str, chemin: &str, corps: &str) -> (u16, String) {
        let en_json = [("Content-Type", "application/json")];
        let entetes: &[(&str, &str)] = if corps.is_empty() { &[] } else { &en_json };
        router_probe_envoi(addr, methode, chemin, Some(&cb1_authz(qui)), entetes, corps).await
    }

    /// La réponse brute sans sa ligne `date` (seule à varier d'une réponse à l'autre).
    fn cb1_sans_date(texte: &str) -> String {
        texte.split("\r\n").filter(|l| !l.to_ascii_lowercase().starts_with("date:")).collect::<Vec<_>>().join("\r\n")
    }

    /// Le corps d'une réponse du routeur (après les en-têtes), découpage `chunked` retiré quand l'en-tête l'annonce.
    fn cb1_corps_brut(texte: &str) -> String {
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

    fn cb1_json(texte: &str) -> Value {
        serde_json::from_str(&cb1_corps_brut(texte)).unwrap_or_else(|_| panic!("corps JSON attendu : {texte}"))
    }

    /// L'en-tête `content-type` d'une réponse brute, en minuscules.
    fn cb1_type(texte: &str) -> String {
        texte.split("\r\n").find_map(|l| l.to_ascii_lowercase().strip_prefix("content-type:").map(|v| v.trim().to_string())).unwrap_or_default()
    }

    fn cb1_vue(st: &AppState, nom: &str, owner: Option<&str>, vis: &str) -> i64 {
        let c = st.db.lock();
        c.execute("INSERT INTO view(name,owner,visibility) VALUES(?1,?2,?3)", params![nom, owner, vis]).expect("fixture : vue");
        c.last_insert_rowid()
    }

    fn cb1_tableau(st: &AppState, id: Option<i64>, nom: &str, owner: &str, vis: &str, vue: Option<i64>) -> i64 {
        let c = st.db.lock();
        c.execute(
            "INSERT INTO dashboard(id,name,created,owner,visibility,view_id,cols,height,collapsed) VALUES(?1,?2,1000,?3,?4,?5,1,0,0)",
            params![id, nom, owner, vis, vue],
        )
        .expect("fixture : tableau");
        c.last_insert_rowid()
    }

    fn cb1_rattacher(st: &AppState, vue: i64, tableau: i64) {
        st.db
            .lock()
            .execute("INSERT INTO view_dashboard(view_id,dashboard_id,explicite) VALUES(?1,?2,1)", params![vue, tableau])
            .expect("fixture : rattachement");
    }

    fn cb1_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    /// Nom, visibilité et rattachements d'une vue, relus (`None` : la vue n'existe plus).
    fn cb1_etat_de_la_vue(st: &AppState, vue: i64) -> Option<(String, String, Vec<i64>)> {
        let c = st.db.lock();
        let (nom, vis): (String, String) =
            c.query_row("SELECT name,visibility FROM view WHERE id=?1", params![vue], |r| Ok((r.get(0)?, r.get(1)?))).optional().expect("relecture de la vue")?;
        let mut s = c.prepare("SELECT dashboard_id FROM view_dashboard WHERE view_id=?1 ORDER BY dashboard_id").unwrap();
        let rattaches = s.query_map(params![vue], |r| r.get(0)).unwrap().collect::<rusqlite::Result<Vec<i64>>>().unwrap();
        Some((nom, vis, rattaches))
    }

    fn cb1_ids(v: &Value) -> Vec<i64> {
        let mut ids: Vec<i64> = v["dashboards"].as_array().unwrap_or_else(|| panic!("une liste est servie : {v}")).iter().map(|d| d["id"].as_i64().unwrap()).collect();
        ids.sort();
        ids
    }

    fn cb1_refus(nom: &str, id: i64, owner: &str, autres: i64) -> String {
        let autres = if autres > 0 { format!(" — et {autres} autre(s) élément(s) le retiennent aussi") } else { String::new() };
        format!("Partage refusé : le tableau de bord « {nom} » (n° {id}, à {owner}) est privé{autres}. Partagez d'abord cet élément, ou retirez-le, puis partagez la vue.")
    }

    /// Le 409 d'avant, jugé à l'octet : statut, type de contenu, corps.
    fn cb1_juger_le_409(quoi: &str, (code, texte): &(u16, String), attendu: &str) {
        assert_eq!((*code, cb1_type(texte), cb1_corps_brut(texte)), (409, "text/plain; charset=utf-8".to_string(), attendu.to_string()), "{quoi} : {texte}");
    }

    const PARTAGER: &str = "{\"visibility\":\"shared\"}";

    // -------------------------------------------------------------------------------------
    // (1) le privé de bob dans la vue d'alice ne retient plus son partage, et reste invisible aux lecteurs
    // -------------------------------------------------------------------------------------

    /// La chaîne du constat, par la route : bob range son tableau privé dans la vue commune d'alice (vue principale ou
    /// jointure), alice la rend privée puis la repartage.
    async fn cb1_chaine_du_partage(tag: &str, par_la_jointure: bool) {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb1_etat(tag);
        let addr = router_serve(st.clone()).await;
        let (code, t) = cb1_envoi(addr, "alice", "POST", "/api/views", "{\"name\":\"Vue d'alice\",\"visibility\":\"shared\"}").await;
        assert_eq!(code, 200, "alice crée sa vue : {t}");
        let va = cb1_json(&t)["id"].as_i64().expect("identifiant de la vue");
        let (code, t) = cb1_envoi(addr, "alice", "POST", "/api/dashboards", &format!("{{\"name\":\"Commun d'alice\",\"visibility\":\"shared\",\"view_id\":{va}}}")).await;
        assert_eq!(code, 200, "alice range un tableau commun dans sa vue : {t}");
        let commun = cb1_json(&t)["id"].as_i64().expect("identifiant du tableau commun");
        let secret = cb1_tableau(&st, Some(CB1_SECRET_DE_BOB), "Secret de bob", "bob", "private", None);
        if par_la_jointure {
            let (code, t) = cb1_envoi(addr, "bob", "POST", &format!("/api/views/{va}/dashboards"), &format!("{{\"dashboard_ids\":[{secret}]}}")).await;
            assert_eq!((code, cb1_json(&t)), (200, json!({ "added": [secret], "already_present": [] })), "bob range son privé par la jointure : {t}");
            assert_eq!(st.db.lock().query_row("SELECT view_id FROM dashboard WHERE id=?1", params![secret], |r| r.get::<_, Option<i64>>(0)).unwrap(), None, "fixture : hors vue principale");
        } else {
            let (code, t) = cb1_envoi(addr, "bob", "POST", &format!("/api/dashboard/{secret}"), &format!("{{\"view_id\":{va}}}")).await;
            assert_eq!(code, 204, "bob range son privé comme vue principale : {t}");
            assert_eq!(st.db.lock().query_row("SELECT view_id FROM dashboard WHERE id=?1", params![secret], |r| r.get::<_, Option<i64>>(0)).unwrap(), Some(va), "fixture : vue principale");
        }
        assert_eq!(cb1_etat_de_la_vue(&st, va).map(|e| e.2), Some(vec![commun, secret]), "fixture : les deux tableaux sont rangés dans la vue");
        let (code, t) = cb1_envoi(addr, "alice", "POST", &format!("/api/views/{va}"), "{\"visibility\":\"private\"}").await;
        assert_eq!(code, 204, "alice rend sa vue privée : {t}");
        // le geste du constat : avant, 409 qui nommait le tableau de bob
        let (code, t) = cb1_envoi(addr, "alice", "POST", &format!("/api/views/{va}"), PARTAGER).await;
        assert_eq!((code, cb1_corps_brut(&t)), (204, String::new()), "alice repartage sa vue : {t}");
        assert_eq!(cb1_etat_de_la_vue(&st, va).map(|e| e.1), Some("shared".to_string()), "la vue est commune");
        // carol, lectrice : ni le tableau, ni son identifiant
        let (code, t) = cb1_envoi(addr, "carol", "GET", &format!("/api/dashboards?view={va}"), "").await;
        assert_eq!(code, 200, "{t}");
        let v = cb1_json(&t);
        assert_eq!((cb1_ids(&v), v["total"].clone()), (vec![commun], json!(1)), "carol ne lit que le commun dans la vue : {t}");
        for (route, chemin) in [("liste filtrée par la vue", format!("/api/dashboards?view={va}")), ("liste entière", "/api/dashboards".to_string()), ("liste des vues", "/api/views".to_string()), ("fiche du tableau", format!("/api/dashboard/{secret}"))] {
            let (code, t) = cb1_envoi(addr, "carol", "GET", &chemin, "").await;
            assert!(code != 0, "{route} : une réponse");
            assert!(!t.contains("Secret de bob") && !t.contains(&CB1_SECRET_DE_BOB.to_string()), "{route} : carol ne reçoit ni le nom ni l'identifiant du privé de bob : {t}");
            if route == "fiche du tableau" {
                assert_ne!(code, 200, "la fiche du privé de bob n'est pas servie à carol : {t}");
            }
        }
        // bob voit toujours le sien
        let (code, t) = cb1_envoi(addr, "bob", "GET", &format!("/api/dashboards?view={va}"), "").await;
        assert_eq!((code, cb1_ids(&cb1_json(&t))), (200, vec![commun, secret]), "bob voit son privé dans la vue : {t}");
        // le compte de la liste des vues suit le lecteur : carol 1 (le commun), bob 2 (le commun et le sien)
        for (lecteur, attendu) in [("carol", 1), ("bob", 2)] {
            let (code, t) = cb1_envoi(addr, lecteur, "GET", "/api/views", "").await;
            assert_eq!(code, 200, "{t}");
            let v = cb1_json(&t);
            let compte = v["views"].as_array().and_then(|vs| vs.iter().find(|x| x["id"] == json!(va))).map(|x| x["dashboards"].clone());
            assert_eq!(compte, Some(json!(attendu)), "{lecteur} : le compte de la vue ne dit que ce qu'il lit : {t}");
        }
    }

    /// CE QU'IL TIENT : le privé de bob rangé comme VUE PRINCIPALE de la vue d'alice ne retient pas son partage (204), et
    /// carol ne le reçoit par aucune route. MUTATION : `CB1_M2_PRINCIPALE_SANS_FILTRE` (409 qui nomme le tableau de bob).
    #[tokio::test]
    async fn cb1_partage_par_la_route_prive_d_autrui_en_vue_principale_ne_retient_pas() {
        cb1_chaine_du_partage("principale", false).await;
    }

    /// CE QU'IL TIENT : le même, le privé de bob rangé par la JOINTURE (`POST /api/views/{id}/dashboards`).
    /// MUTATION : `CB1_M1_JOINTURE_SANS_FILTRE`.
    #[tokio::test]
    async fn cb1_partage_par_la_route_prive_d_autrui_par_la_jointure_ne_retient_pas() {
        cb1_chaine_du_partage("jointure", true).await;
    }

    // -------------------------------------------------------------------------------------
    // (2) les privés de l'appelant retiennent comme avant, et seuls eux sont comptés
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par la route, pour alice sur trois vues privées à elle :
    ///   * V1, son privé A1 en vue principale : le 409 d'avant à l'octet, la vue reste privée ;
    ///   * V2, B1 (bob, principale, identifiant plus petit), A1b (alice, principale), B2 (bob, jointure), A2 (alice,
    ///     jointure) : le 409 nomme A1b et compte UN autre (A2) ;
    ///   * V3, jointure seule, B3 (bob, plus petit) puis A3 (alice) : le 409 nomme A3, sans autre ; contrôle : A3 partagé,
    ///     V3 se partage (204) malgré B3.
    /// MUTATIONS : `CB1_M1_JOINTURE_SANS_FILTRE` (V2 compte 2 autres, V3 nomme B3), `CB1_M2_PRINCIPALE_SANS_FILTRE` (V2
    /// nomme B1), `CB1_M3_COMPTES_SANS_FILTRE` (V2 compte 3 autres, V3 en compte 1).
    #[tokio::test]
    async fn cb1_partage_son_prive_retient_a_l_octet_et_seuls_les_siens_sont_comptes() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb1_etat("siens");
        let v1 = cb1_vue(&st, "V1", Some("alice"), "private");
        let a1 = cb1_tableau(&st, None, "A1", "alice", "private", Some(v1));
        let v2 = cb1_vue(&st, "V2", Some("alice"), "private");
        let b1 = cb1_tableau(&st, None, "B1", "bob", "private", Some(v2));
        let a1b = cb1_tableau(&st, None, "A1b", "alice", "private", Some(v2));
        let b2 = cb1_tableau(&st, None, "B2", "bob", "private", None);
        let a2 = cb1_tableau(&st, None, "A2", "alice", "private", None);
        cb1_rattacher(&st, v2, b2);
        cb1_rattacher(&st, v2, a2);
        let v3 = cb1_vue(&st, "V3", Some("alice"), "private");
        let b3 = cb1_tableau(&st, None, "B3", "bob", "private", None);
        let a3 = cb1_tableau(&st, None, "A3", "alice", "private", None);
        cb1_rattacher(&st, v3, b3);
        cb1_rattacher(&st, v3, a3);
        assert!(b1 < a1b && b2 < a2 && b3 < a3, "fixture : le privé de bob précède celui d'alice dans chaque paire");
        let addr = router_serve(st.clone()).await;

        let r = cb1_envoi(addr, "alice", "POST", &format!("/api/views/{v1}"), PARTAGER).await;
        cb1_juger_le_409("V1, son privé", &r, &cb1_refus("A1", a1, "alice", 0));
        let r = cb1_envoi(addr, "alice", "POST", &format!("/api/views/{v2}"), PARTAGER).await;
        cb1_juger_le_409("V2, les siens et ceux de bob", &r, &cb1_refus("A1b", a1b, "alice", 1));
        let r = cb1_envoi(addr, "alice", "POST", &format!("/api/views/{v3}"), PARTAGER).await;
        cb1_juger_le_409("V3, jointure seule", &r, &cb1_refus("A3", a3, "alice", 0));
        for v in [v1, v2, v3] {
            assert_eq!(cb1_etat_de_la_vue(&st, v).map(|e| e.1), Some("private".to_string()), "un refus ne publie pas la vue {v}");
        }
        // contrôle : son privé partagé, la vue se partage malgré celui de bob
        let (code, t) = cb1_envoi(addr, "alice", "POST", &format!("/api/dashboard/{a3}"), PARTAGER).await;
        assert_eq!(code, 204, "{t}");
        let (code, t) = cb1_envoi(addr, "alice", "POST", &format!("/api/views/{v3}"), PARTAGER).await;
        assert_eq!(code, 204, "V3 se partage : {t}");
        assert_eq!(cb1_etat_de_la_vue(&st, v3).map(|e| e.1), Some("shared".to_string()));
    }

    /// CE QU'IL TIENT, par la route : l'ADMINISTRATEUR garde le comportement d'avant — tout privé de la vue retient,
    /// celui de bob compris (nommé avec son propriétaire, vue principale d'abord) et celui d'alice par la jointure est
    /// compté ; la vue reste privée. Contrôle : les deux partagés, l'administrateur partage la vue (204).
    /// MUTATION : `CB1_M4_ADMIN_COMME_NON_ADMIN` (204 au premier geste).
    #[tokio::test]
    async fn cb1_partage_par_l_admin_juge_tous_les_prives_comme_avant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb1_etat("admin");
        let v = cb1_vue(&st, "Vue d'alice", Some("alice"), "private");
        let b = cb1_tableau(&st, None, "Secret de bob", "bob", "private", Some(v));
        let a = cb1_tableau(&st, None, "Brouillon d'alice", "alice", "private", None);
        cb1_rattacher(&st, v, a);
        let addr = router_serve(st.clone()).await;
        let r = cb1_envoi(addr, "adm", "POST", &format!("/api/views/{v}"), PARTAGER).await;
        cb1_juger_le_409("l'administrateur", &r, &cb1_refus("Secret de bob", b, "bob", 1));
        assert_eq!(cb1_etat_de_la_vue(&st, v).map(|e| e.1), Some("private".to_string()), "rien n'est publié");
        cb1_ecrire(&st, &format!("UPDATE dashboard SET visibility='shared' WHERE id IN ({a},{b})"));
        let (code, t) = cb1_envoi(addr, "adm", "POST", &format!("/api/views/{v}"), PARTAGER).await;
        assert_eq!(code, 204, "contrôle : {t}");
        assert_eq!(cb1_etat_de_la_vue(&st, v).map(|e| e.1), Some("shared".to_string()));
    }

    /// CE QU'IL TIENT, par la route : la porte qui n'a pas pu lire le privé d'alice (nom illisible) rend le 503 nommé
    /// d'avant, corps entier (`error` et l'identifiant de corrélation, rien d'autre), par la vue principale puis par la
    /// jointure ; la vue reste privée. Contrôle : le nom relisible, le 409 qui le nomme.
    #[tokio::test]
    async fn cb1_porte_non_lue_rend_le_503_d_avant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb1_etat("non-lue");
        let v = cb1_vue(&st, "Vue d'alice", Some("alice"), "private");
        let a = cb1_tableau(&st, None, "Principal d'alice", "alice", "private", Some(v));
        let addr = router_serve(st.clone()).await;
        let juger_503 = |quoi: &str, (code, t): (u16, String)| {
            let corps = cb1_json(&t);
            let cles: Vec<String> = corps.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
            assert_eq!((code, cles, corps["error"].as_str()), (503, vec!["error".to_string(), "id".to_string()], Some(CB1_NON_LUS)), "{quoi} : {t}");
            assert!(corps["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {t}");
        };
        cb1_ecrire(&st, &format!("UPDATE dashboard SET name=x'FF' WHERE id={a}"));
        juger_503("vue principale illisible", cb1_envoi(addr, "alice", "POST", &format!("/api/views/{v}"), PARTAGER).await);
        cb1_ecrire(&st, &format!("UPDATE dashboard SET name='Principal d''alice', view_id=NULL WHERE id={a}"));
        let j = cb1_tableau(&st, None, "Rangé d'alice", "alice", "private", None);
        cb1_rattacher(&st, v, j);
        cb1_ecrire(&st, &format!("UPDATE dashboard SET name=x'FF' WHERE id={j}"));
        juger_503("jointure illisible", cb1_envoi(addr, "alice", "POST", &format!("/api/views/{v}"), PARTAGER).await);
        assert_eq!(cb1_etat_de_la_vue(&st, v).map(|e| e.1), Some("private".to_string()), "rien n'est publié");
        cb1_ecrire(&st, &format!("UPDATE dashboard SET name='Rangé d''alice' WHERE id={j}"));
        let r = cb1_envoi(addr, "alice", "POST", &format!("/api/views/{v}"), PARTAGER).await;
        cb1_juger_le_409("contrôle", &r, &cb1_refus("Rangé d'alice", j, "alice", 0));
    }

    // -------------------------------------------------------------------------------------
    // (3) modifier ou supprimer une vue invisible : la réponse d'une vue absente
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par la route : bob renomme et partage, puis supprime, la vue PRIVÉE d'alice ; chaque réponse est
    /// identique à l'octet (statut, en-têtes hors `date`, corps) à celle du même geste sur un identifiant absent — 404
    /// sans corps — et la vue reste (nom, visibilité, rattachements relus). MUTATIONS : `CB1_M5_UPDATE_403`,
    /// `CB1_M6_DELETE_403`.
    #[tokio::test]
    async fn cb1_vue_privee_d_autrui_repond_comme_une_vue_absente() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb1_etat("privee-absente");
        let pa = cb1_vue(&st, "Privée d'alice", Some("alice"), "private");
        let d = cb1_tableau(&st, None, "Tableau d'alice", "alice", "private", Some(pa));
        let avant = Some(("Privée d'alice".to_string(), "private".to_string(), vec![d]));
        assert_eq!(cb1_etat_de_la_vue(&st, pa), avant, "fixture");
        let addr = router_serve(st.clone()).await;
        let corps = "{\"name\":\"renommée par bob\",\"visibility\":\"shared\"}";
        let (code, absente) = cb1_envoi(addr, "bob", "POST", &format!("/api/views/{CB1_ABSENTE}"), corps).await;
        assert_eq!((code, cb1_corps_brut(&absente)), (404, String::new()), "référence : une vue absente, {absente}");
        let (_, privee) = cb1_envoi(addr, "bob", "POST", &format!("/api/views/{pa}"), corps).await;
        assert_eq!(cb1_sans_date(&privee), cb1_sans_date(&absente), "POST : la vue privée d'alice répond comme une vue absente");
        let (code, absente) = cb1_envoi(addr, "bob", "DELETE", &format!("/api/views/{CB1_ABSENTE}"), "").await;
        assert_eq!((code, cb1_corps_brut(&absente)), (404, String::new()), "référence : une vue absente, {absente}");
        let (_, privee) = cb1_envoi(addr, "bob", "DELETE", &format!("/api/views/{pa}"), "").await;
        assert_eq!(cb1_sans_date(&privee), cb1_sans_date(&absente), "DELETE : la vue privée d'alice répond comme une vue absente");
        assert_eq!(cb1_etat_de_la_vue(&st, pa), avant, "rien n'est écrit : nom, visibilité, rattachements");
    }

    /// CE QU'IL TIENT, par la route :
    ///   * la vue COMMUNE d'alice : bob reçoit 403 au renommage et à la suppression, la vue reste ;
    ///   * deux vues SEMÉES privées (propriétaire NULL, propriétaire vide) : bob reçoit la réponse d'un identifiant absent
    ///     aux deux gestes ; l'administrateur renomme (204) puis supprime (204) ;
    ///   * la propriétaire renomme (204) puis supprime (204) sa vue privée.
    /// MUTATIONS : `CB1_M7_COMMUNE_404` (403 -> 404 sur la vue commune), `CB1_P1_PREDICAT_SANS_ADMIN` (le bras
    /// administrateur du prédicat retiré : l'administrateur reçoit 404 sur la vue semée privée),
    /// `CB1_P2_PREDICAT_NUL_VU` (`COALESCE(…, 0)` -> `COALESCE(…, 1)` : la vue semée sans propriétaire devient vue, 403).
    #[tokio::test]
    async fn cb1_vue_commune_403_semee_privee_absente_sauf_admin_et_proprietaire_permis() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb1_etat("commune-semee");
        let sa = cb1_vue(&st, "Commune d'alice", Some("alice"), "shared");
        let semee_nulle = cb1_vue(&st, "Semée nulle", None, "private");
        let semee_vide = cb1_vue(&st, "Semée vide", Some(""), "private");
        let pa = cb1_vue(&st, "Privée d'alice", Some("alice"), "private");
        let addr = router_serve(st.clone()).await;
        let renommer = "{\"name\":\"renommée\"}";
        // vue commune : 403
        let (code, t) = cb1_envoi(addr, "bob", "POST", &format!("/api/views/{sa}"), renommer).await;
        assert_eq!((code, cb1_corps_brut(&t)), (403, String::new()), "renommer la vue commune d'alice : {t}");
        let (code, t) = cb1_envoi(addr, "bob", "DELETE", &format!("/api/views/{sa}"), "").await;
        assert_eq!((code, cb1_corps_brut(&t)), (403, String::new()), "supprimer la vue commune d'alice : {t}");
        assert_eq!(cb1_etat_de_la_vue(&st, sa), Some(("Commune d'alice".to_string(), "shared".to_string(), vec![])), "la vue commune reste");
        // vues semées privées : bob comme une vue absente
        let (_, absente_post) = cb1_envoi(addr, "bob", "POST", &format!("/api/views/{CB1_ABSENTE}"), renommer).await;
        let (_, absente_delete) = cb1_envoi(addr, "bob", "DELETE", &format!("/api/views/{CB1_ABSENTE}"), "").await;
        assert!(absente_post.starts_with("HTTP/1.1 404") && absente_delete.starts_with("HTTP/1.1 404"), "références : {absente_post} / {absente_delete}");
        for (quoi, semee) in [("propriétaire NULL", semee_nulle), ("propriétaire vide", semee_vide)] {
            let (_, t) = cb1_envoi(addr, "bob", "POST", &format!("/api/views/{semee}"), renommer).await;
            assert_eq!(cb1_sans_date(&t), cb1_sans_date(&absente_post), "POST, vue semée privée ({quoi})");
            let (_, t) = cb1_envoi(addr, "bob", "DELETE", &format!("/api/views/{semee}"), "").await;
            assert_eq!(cb1_sans_date(&t), cb1_sans_date(&absente_delete), "DELETE, vue semée privée ({quoi})");
        }
        assert_eq!(cb1_etat_de_la_vue(&st, semee_nulle).map(|e| e.0), Some("Semée nulle".to_string()), "rien n'est écrit");
        assert_eq!(cb1_etat_de_la_vue(&st, semee_vide).map(|e| e.0), Some("Semée vide".to_string()), "rien n'est écrit");
        // l'administrateur : permis sur les deux vues semées
        for semee in [semee_nulle, semee_vide] {
            let (code, t) = cb1_envoi(addr, "adm", "POST", &format!("/api/views/{semee}"), &format!("{{\"name\":\"renommée par adm {semee}\"}}")).await;
            assert_eq!(code, 204, "l'administrateur renomme la vue semée privée : {t}");
            assert_eq!(cb1_etat_de_la_vue(&st, semee).map(|e| e.0), Some(format!("renommée par adm {semee}")));
            let (code, t) = cb1_envoi(addr, "adm", "DELETE", &format!("/api/views/{semee}"), "").await;
            assert_eq!(code, 204, "l'administrateur supprime la vue semée privée : {t}");
            assert_eq!(cb1_etat_de_la_vue(&st, semee), None);
        }
        // la propriétaire : permis
        let (code, t) = cb1_envoi(addr, "alice", "POST", &format!("/api/views/{pa}"), renommer).await;
        assert_eq!(code, 204, "alice renomme sa vue privée : {t}");
        assert_eq!(cb1_etat_de_la_vue(&st, pa).map(|e| e.0), Some("renommée".to_string()));
        let (code, t) = cb1_envoi(addr, "alice", "DELETE", &format!("/api/views/{pa}"), "").await;
        assert_eq!(code, 204, "alice supprime sa vue privée : {t}");
        assert_eq!(cb1_etat_de_la_vue(&st, pa), None);
    }

    // -------------------------------------------------------------------------------------
    // (4) la décision est UNE lecture
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : avant le 403 (vue commune d'alice) et avant le 404 (vue privée d'alice), `view_update` et
    /// `view_delete` préparent UN SEUL `SELECT` : le propriétaire, la visibilité et ce que l'appelant voit viennent de la
    /// même lecture. Compté par un autorisateur posé sur la connexion du gestionnaire (mode 0 : `st.db`), qui compte
    /// chaque `SELECT` préparé. MUTATION : `CB1_M8_SECONDE_LECTURE` (la visibilité relue par un second énoncé).
    #[tokio::test]
    async fn cb1_la_vue_se_juge_en_une_seule_lecture() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = sp_state("cb1-une-lecture");
        cb1_ecrire(&st, "DELETE FROM panel; DELETE FROM dashboard; DELETE FROM view_dashboard; DELETE FROM view;");
        let sa = cb1_vue(&st, "Commune d'alice", Some("alice"), "shared");
        let pa = cb1_vue(&st, "Privée d'alice", Some("alice"), "private");
        let bob = AuthUser {
            name: "bob".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        };
        let selects = std::sync::Arc::new(AtomicUsize::new(0));
        let n = selects.clone();
        st.db.lock().authorizer(Some(move |ctx: rusqlite::hooks::AuthContext<'_>| {
            if matches!(ctx.action, rusqlite::hooks::AuthAction::Select) {
                n.fetch_add(1, Ordering::SeqCst);
            }
            rusqlite::hooks::Authorization::Allow
        }));
        let mut mesures: Vec<(&str, u16, usize)> = Vec::new();
        selects.store(0, Ordering::SeqCst);
        let r = view_update(State(st.clone()), Extension(bob.clone()), Path(sa), Json(json!({ "name": "x" }))).await;
        mesures.push(("view_update, vue commune", r.status().as_u16(), selects.swap(0, Ordering::SeqCst)));
        let r = view_update(State(st.clone()), Extension(bob.clone()), Path(pa), Json(json!({ "name": "x" }))).await;
        mesures.push(("view_update, vue privée", r.status().as_u16(), selects.swap(0, Ordering::SeqCst)));
        let r = view_delete(State(st.clone()), Extension(bob.clone()), Path(sa)).await;
        mesures.push(("view_delete, vue commune", r.status().as_u16(), selects.swap(0, Ordering::SeqCst)));
        let r = view_delete(State(st.clone()), Extension(bob.clone()), Path(pa)).await;
        mesures.push(("view_delete, vue privée", r.status().as_u16(), selects.swap(0, Ordering::SeqCst)));
        st.db.lock().authorizer(None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>);
        assert_eq!(
            mesures,
            vec![("view_update, vue commune", 403, 1), ("view_update, vue privée", 404, 1), ("view_delete, vue commune", 403, 1), ("view_delete, vue privée", 404, 1)],
            "un seul SELECT décide"
        );
    }
}

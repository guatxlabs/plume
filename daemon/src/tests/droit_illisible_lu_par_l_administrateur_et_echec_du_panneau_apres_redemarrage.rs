// =====================================================================================
// `P11.25-f` et `P10.32-o` (vague CI) — L'ADMINISTRATEUR LIT UN TABLEAU AU DROIT ILLISIBLE COMME UN TABLEAU SAIN, ET UN
// PANNEAU EN ÉCHEC GARDE SON ÉCHEC APRÈS UN REDÉMARRAGE.
//
// LES ROUTES (handlers/dashboards.rs) : `GET /api/panels/{id}/data` (`panel_data`, par `panel_access`, puis `serve_swr`),
// `GET /api/dashboards` (`dash_list`), `GET /api/dashboard/{id}` (`dash_get`).
//
// MESURÉ PAR LA ROUTE SUR 2b9eff27, AVANT LE LOT (ces témoins y rougissent sur (A) et (B)) : sur une ligne de `dashboard`
// dont le propriétaire ou la visibilité est d'un autre type que du texte UTF-8 (BLOB, texte qui n'est pas de l'UTF-8),
// les données d'un panneau servaient à l'administrateur le 503 « PANNEAU NON LU » (une relecture en `String` qui ne
// pouvait qu'échouer), et la liste comme la lecture lui servaient `"visibility": "shared"` pour une visibilité illisible,
// la valeur de repli d'une colonne NULL, qu'aucune porte n'applique.
//
// CE QUE CES TÉMOINS TIENNENT, par le ROUTEUR réel (adm administrateur, alice éditrice et propriétaire en texte, bob
// éditeur, carol lectrice), sur quatre formes : propriétaire BLOB, visibilité BLOB, propriétaire en texte qui n'est pas de
// l'UTF-8, visibilité en texte qui n'est pas de l'UTF-8 :
//   (A) données d'un panneau, panneau privé ET panneau commun du tableau, servis depuis une ligne de cache fraîche :
//       l'administrateur reçoit, à l'octet (hors `date`), ce que la route lui servait sur la même ligne SAINE (tableau
//       privé d'alice, dont il n'est pas propriétaire) ; rien n'est armé. Alice, bob et carol : la réponse de l'identifiant
//       de panneau absent, à l'octet ;
//   (A') une vraie lecture ratée (lecture de `dashboard.owner` refusée) : le 503 nommé, corps entier, pour
//       l'administrateur comme pour bob ;
//   (B) la liste et la lecture : l'administrateur reçoit l'entrée et la lecture SAINES, la seule colonne illisible servie
//       vide (`""`), comme le propriétaire illisible déjà ; les entrées et la lecture du tableau voisin sain sont
//       inchangées à l'octet ; alice, bob et carol : la ligne absente de leur liste, la lecture de l'identifiant absent ;
//   (C) un panneau dont le calcul échoue : son corps d'échec est ÉCRIT dans `panel_cache` ; après un redémarrage simulé
//       (état neuf sur le même fichier de base, registres de processus de cette base oubliés), le PREMIER appel sert ce
//       corps d'échec à l'octet, sans `warming`, sans rien armer ;
//   (C') la base refuse d'écrire le cache : avant le redémarrage, le 503 nommé de l'échec non écrit ; après, rien en base
//       ne porte l'échec (aucune ligne de cache) — le premier appel sert `warming` et réarme UN calcul, le suivant, une
//       fois ce calcul rendu, sert de nouveau le 503 nommé. C'est la borne mesurée du reste : une chauffe par REDÉMARRAGE
//       (le refus une fois noté au registre du processus, chaque calcul suivant est servi en 503 nommé jusqu'au
//       redémarrage d'après ; l'expiration de la durée du cache n'est pas jouée ici).
//
// MUTATIONS (sous `cfg!(test)`, armées par la variable de mutation de l'exécuteur, vues rouges puis retirées) :
// `CI2_PA_ADMIN_503` (la relecture en `String` d'avant pour l'administrateur) -> (A) ; `CI2_PA_PORTEE_PARTAGE` (portée de
// simple lecteur sur un droit non établi) -> (A) panneau privé ; `CI2_PA_NON_ETABLI_POUR_TOUS` (droit non établi ouvert à
// tout compte) -> (A) panneau commun pour alice, bob et carol ; `CI2_PA_ERREUR_OUVERTE` (lecture ratée ouverte à
// l'administrateur) -> (A') ; `CI2_SERVI_DEFAUT` (la valeur de repli d'avant) -> (B) visibilités ; `CI2_ECHEC_COMME_ABSENCE`
// (un corps d'échec en cache traité comme une absence) -> (C) ; `CI2_REFUS_IGNORE` (le registre des refus d'écriture non
// lu) -> (C').
//
// CE QU'ILS NE TIENNENT PAS : la phrase servie sous `LANG=en` (le démon n'a aucun mécanisme de langue ; la console colle la
// cause servie dans un nœud composé, que son lexique ne traduit pas) ; ce que la console peint d'une visibilité vide.
// =====================================================================================
mod droit_illisible_lu_par_l_administrateur_et_echec_du_panneau_apres_redemarrage {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const CI2_MDP: &str = "ci2pw1234567";
    /// Un identifiant qu'aucun tableau ni panneau ne porte.
    const CI2_ABSENT: i64 = 999_998;
    /// La plage absolue des données d'un panneau (cacheable, clé de cache stable).
    const CI2_FROM: i64 = 3_600;
    const CI2_TO: i64 = 7_200;
    const CI2_GXQL: &str = "search | stats count";
    const CI2_SQL_EN_PANNE: &str = "SELECT json_extract(v,'$.a') AS a FROM ci2_source";
    // Écrites ici : un témoin qui lirait la constante de production ne verrait pas qu'elle change.
    const CI2_PANNEAU_NON_LU: &str = "PANNEAU NON LU : la base n'a pas rendu ce panneau ou son tableau de bord (fenêtre, visibilité, propriétaire) — ce n'est PAS « panneau inaccessible », c'est une lecture qui n'a pas eu lieu, et le droit de le voir n'est pas jugé. RIEN n'est exécuté ni servi. Réessayez ; si le refus persiste, la table des panneaux est illisible.";
    const CI2_REQUETE_REJETEE: &str = "requête REFUSÉE par le moteur (ce n'est pas un résultat vide) : syntaxe, champ, motif ou accès rejeté — rien n'est rendu ; le détail est au journal de l'exploitant.";
    const CI2_ECHEC_NON_ECRIT: &str = "CALCUL DU PANNEAU EN ÉCHEC, ÉCHEC NON ÉCRIT : le dernier calcul de ce panneau a échoué et la base a refusé d'écrire cet échec dans le cache — ce n'est PAS une mesure en cours. RIEN n'est servi ; un nouveau calcul est armé au plus une fois par durée du cache. Cause du calcul : ";

    /// Une forme de droit non établi : étiquette, altération SQL de `{d}`, contrôle du type écrit, propriétaire et
    /// visibilité que l'administrateur doit recevoir.
    struct Forme {
        tag: &'static str,
        alteration: &'static str,
        controle: (&'static str, &'static str),
        servis: (&'static str, &'static str),
    }

    const CI2_FORMES: [Forme; 4] = [
        Forme { tag: "owner-blob", alteration: "UPDATE dashboard SET owner=X'626f62', visibility='private' WHERE id={d};", controle: ("typeof(owner)||'/'||typeof(visibility)", "blob/text"), servis: ("", "private") },
        Forme { tag: "vis-blob", alteration: "UPDATE dashboard SET visibility=X'736861726564' WHERE id={d};", controle: ("typeof(owner)||'/'||typeof(visibility)", "text/blob"), servis: ("alice", "") },
        Forme { tag: "owner-utf8", alteration: "UPDATE dashboard SET owner=CAST(X'FF62' AS TEXT) WHERE id={d};", controle: ("typeof(owner)||'/'||hex(owner)", "text/FF62"), servis: ("", "private") },
        Forme { tag: "vis-utf8", alteration: "UPDATE dashboard SET visibility=CAST(X'FF73' AS TEXT) WHERE id={d};", controle: ("typeof(visibility)||'/'||hex(visibility)", "text/FF73"), servis: ("alice", "") },
    ];

    /// Les identifiants d'une fixture : le tableau privé d'alice à altérer, son panneau privé et son panneau commun, le
    /// tableau commun voisin d'alice (qui porte un panneau commun).
    struct Jeu {
        d: i64,
        p_prive: i64,
        p_commun: i64,
        voisin: i64,
    }

    fn ci2_comptes(c: &Connection) {
        let h = hash_pw(CI2_MDP).expect("fixture : empreinte");
        for (nom, role) in [("alice", "editor"), ("bob", "editor"), ("carol", "viewer"), ("adm", "admin")] {
            c.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![nom, h, role]).expect("fixture : compte");
        }
    }

    fn ci2_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, Jeu) {
        let (st, p) = router_test_state(&format!("ci2-{tag}"));
        let jeu = {
            let c = st.db.lock();
            c.execute_batch("DELETE FROM panel; DELETE FROM dashboard; DELETE FROM view_dashboard; DELETE FROM view; DELETE FROM panel_cache; DELETE FROM panel_cost;")
                .expect("fixture : base vide");
            ci2_comptes(&c);
            let tableau = |nom: &str, vis: &str| -> i64 {
                c.execute("INSERT INTO dashboard(name,created,owner,visibility) VALUES(?1,1000,'alice',?2)", params![nom, vis]).expect("fixture : tableau");
                c.last_insert_rowid()
            };
            let (d, voisin) = (tableau("altéré", "private"), tableau("voisin", "shared"));
            let panneau = |tableau: i64, titre: &str, vis: &str| -> i64 {
                c.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz,visibility) VALUES(?1,?2,?3,1,'table',?4)", params![tableau, titre, CI2_GXQL, vis])
                    .expect("fixture : panneau");
                c.last_insert_rowid()
            };
            let (p_prive, p_commun) = (panneau(d, "privé", "private"), panneau(d, "commun", "shared"));
            panneau(voisin, "du voisin", "shared");
            Jeu { d, p_prive, p_commun, voisin }
        };
        (st, p, jeu)
    }

    /// Un état NEUF sur le même fichier de base : ce qu'un redémarrage du démon retrouve (la base), sans ce qu'il perd
    /// (l'état du processus : ensemble en vol, registres de cette base, oubliés ici comme à la destruction d'un tenant).
    fn ci2_redemarrer(path: &str) -> AppState {
        crate::handlers::panneau_avoue::oublier_les_registres_d_une_base_detruite(path);
        let mut st = ds_file_state(path);
        st.user = Arc::new("root".to_string());
        st.pass_hash = Arc::new(hash_pw("rootpw1234567").unwrap());
        st.rl_auth_max = 1_000_000;
        st.rl_ip_max = 1_000_000;
        st.rl_global_max = 1_000_000;
        st
    }

    fn ci2_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ci2_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture `{sql}` : {e}"))
    }

    fn ci2_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture `{sql}` : {e}"))
    }

    fn ci2_alterer(st: &AppState, jeu: &Jeu, f: &Forme) {
        ci2_ecrire(st, &f.alteration.replace("{d}", &jeu.d.to_string()));
        assert_eq!(ci2_texte(st, &format!("SELECT {} FROM dashboard WHERE id={}", f.controle.0, jeu.d)), f.controle.1, "fixture ({}) : type relu", f.tag);
    }

    /// Une ligne de cache FRAÎCHE (écrite maintenant) pour la plage `CI2_FROM..CI2_TO` du panneau : le service la sert
    /// telle quelle et n'arme rien.
    fn ci2_semer_le_cache(st: &AppState, p: i64, rangs: i64) {
        let rk = env_range_key(None, &cache_range_key(CI2_FROM, CI2_TO, 0));
        let fp = query_fingerprint(CI2_GXQL, true);
        let payload = json!({ "columns": ["n"], "rows": [[rangs]] }).to_string();
        crate::handlers::panneau_avoue::cache_ecrire(&st.db.lock(), p, &rk, &fp, now(), &payload);
    }

    fn ci2_authz(nom: &str) -> String {
        format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{nom}:{CI2_MDP}")))
    }

    async fn ci2_get(addr: std::net::SocketAddr, qui: &str, chemin: &str) -> (u16, String) {
        router_probe_envoi(addr, "GET", chemin, Some(&ci2_authz(qui)), &[], "").await
    }

    fn ci2_donnees(p: i64) -> String {
        format!("/api/panels/{p}/data?from={CI2_FROM}&to={CI2_TO}")
    }

    fn ci2_sans_date(texte: &str) -> String {
        texte.split("\r\n").filter(|l| !l.to_ascii_lowercase().starts_with("date:")).collect::<Vec<_>>().join("\r\n")
    }

    /// Le corps d'une réponse (découpage `chunked` retiré quand l'en-tête l'annonce).
    fn ci2_corps(texte: &str) -> String {
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

    fn ci2_json(texte: &str) -> Value {
        serde_json::from_str(&ci2_corps(texte)).unwrap_or_else(|_| panic!("corps JSON attendu : {texte}"))
    }

    /// Le 503 nommé : clés exactes `error` et `id`, phrase entière, identifiant de corrélation servi.
    fn ci2_juger_503(quoi: &str, code: u16, t: &str, phrase: &str) {
        let v = ci2_json(t);
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(|k| k.as_str()).collect()).unwrap_or_default();
        assert_eq!((code, cles, v["error"].as_str()), (503, vec!["error", "id"], Some(phrase)), "{quoi} : le 503 nommé, corps entier : {t}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {t}");
    }

    fn ci2_rien_en_vol(st: &AppState) -> bool {
        st.panel_refresh_inflight.lock().is_empty()
    }

    /// Attend que la tâche de rafraîchissement armée ait rendu sa place dans l'ensemble en vol (borné en NOMBRE de
    /// passages, jamais une assertion de durée).
    async fn ci2_attendre_la_tache(st: &AppState) {
        for _ in 0..20_000 {
            if ci2_rien_en_vol(st) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        panic!("la tâche de rafraîchissement n'a jamais quitté l'ensemble en vol");
    }

    fn ci2_entree(v: &Value, id: i64) -> Option<Value> {
        v["dashboards"].as_array().and_then(|a| a.iter().find(|e| e["id"].as_i64() == Some(id)).cloned())
    }

    // -------------------------------------------------------------------------------------
    // (A) les données d'un panneau
    // -------------------------------------------------------------------------------------

    /// MUTATIONS : `CI2_PA_ADMIN_503`, `CI2_PA_PORTEE_PARTAGE`, `CI2_PA_NON_ETABLI_POUR_TOUS`.
    #[tokio::test]
    async fn ci2_donnees_d_un_panneau_servies_a_l_administrateur_comme_sur_la_ligne_saine() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut formes_jouees = 0;
        for f in &CI2_FORMES {
            let (st, _p, jeu) = ci2_etat(&format!("donnees-{}", f.tag));
            ci2_semer_le_cache(&st, jeu.p_prive, 11);
            ci2_semer_le_cache(&st, jeu.p_commun, 22);
            let addr = router_serve(st.clone()).await;
            let panneaux = [jeu.p_prive, jeu.p_commun];
            // Ce que la route servait à l'administrateur sur la ligne SAINE (privée d'alice, il n'en est pas propriétaire).
            let mut sains = Vec::new();
            for p in panneaux {
                let (code, t) = ci2_get(addr, "adm", &ci2_donnees(p)).await;
                let v = ci2_json(&t);
                assert_eq!((code, v.get("error"), v.get("warming")), (200, None, None), "({}) contrôle : ligne saine, panneau {p} servi : {t}", f.tag);
                sains.push((p, ci2_sans_date(&t)));
            }
            assert_eq!(sains.len(), 2, "contrôle : deux panneaux");
            assert_eq!(ci2_json(&sains[0].1)["rows"], json!([[11]]), "({}) contrôle : la ligne de cache du panneau privé est servie", f.tag);

            ci2_alterer(&st, &jeu, f);
            for (p, sain) in &sains {
                let (code, t) = ci2_get(addr, "adm", &ci2_donnees(*p)).await;
                assert_eq!((code, ci2_sans_date(&t)), (200, sain.clone()), "({}) adm : panneau {p}, la réponse de la ligne saine, à l'octet", f.tag);
                assert!(ci2_rien_en_vol(&st), "({}) adm : panneau {p}, ligne fraîche, rien d'armé", f.tag);
            }
            let mut refus_juges = 0;
            for qui in ["alice", "bob", "carol"] {
                let (code_absent, absent) = ci2_get(addr, qui, &ci2_donnees(CI2_ABSENT)).await;
                assert_eq!((code_absent, ci2_json(&absent)), (403, json!({ "error": "panneau inaccessible" })), "({}) {qui} : contrôle de l'absent", f.tag);
                for p in panneaux {
                    let (code, t) = ci2_get(addr, qui, &ci2_donnees(p)).await;
                    assert_eq!((code, ci2_sans_date(&t)), (code_absent, ci2_sans_date(&absent)), "({}) {qui} panneau {p} : la réponse de l'absent, à l'octet", f.tag);
                    refus_juges += 1;
                }
            }
            assert_eq!(refus_juges, 6, "({}) contrôle : trois comptes, deux panneaux", f.tag);
            formes_jouees += 1;
        }
        assert_eq!(formes_jouees, 4, "plancher : chaque forme jouée jusqu'au bout");
    }

    /// (A') une vraie lecture ratée garde son 503 nommé, administrateur compris. MUTATION : `CI2_PA_ERREUR_OUVERTE`.
    #[tokio::test]
    async fn ci2_lecture_ratee_du_droit_garde_le_503_nomme_des_donnees() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p, jeu) = ci2_etat("lecture-ratee");
        ci2_semer_le_cache(&st, jeu.p_commun, 22);
        ci2_ecrire(&st, &format!("UPDATE dashboard SET visibility='shared' WHERE id={};", jeu.d));
        let addr = router_serve(st.clone()).await;
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "dashboard", column_name: "owner" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let mut vus = Vec::new();
        for qui in ["adm", "bob"] {
            let (c, t) = ci2_get(addr, qui, &ci2_donnees(jeu.p_commun)).await;
            vus.push((qui, c, t));
        }
        st.db.lock().authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        assert_eq!(vus.len(), 2, "contrôle : deux comptes");
        for (qui, c, t) in &vus {
            ci2_juger_503(&format!("{qui} panel_data"), *c, t, CI2_PANNEAU_NON_LU);
        }
        // Contrôle : sans le refus, la même demande est servie (la lecture refusée est bien ce qui décide).
        let (code, t) = ci2_get(addr, "bob", &ci2_donnees(jeu.p_commun)).await;
        assert_eq!((code, ci2_json(&t)["rows"].clone()), (200, json!([[22]])), "contrôle : bob lit le panneau commun d'un tableau commun : {t}");
    }

    // -------------------------------------------------------------------------------------
    // (B) la liste et la lecture
    // -------------------------------------------------------------------------------------

    /// MUTATION : `CI2_SERVI_DEFAUT`.
    #[tokio::test]
    async fn ci2_liste_et_lecture_servent_vide_la_colonne_illisible_a_l_administrateur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut formes_jouees = 0;
        for f in &CI2_FORMES {
            let (st, _p, jeu) = ci2_etat(&format!("liste-{}", f.tag));
            let addr = router_serve(st.clone()).await;
            let (code, t) = ci2_get(addr, "adm", "/api/dashboards").await;
            assert_eq!(code, 200, "({}) contrôle : liste saine : {t}", f.tag);
            let liste_saine = ci2_json(&t);
            let entree_saine = ci2_entree(&liste_saine, jeu.d).unwrap_or_else(|| panic!("({}) contrôle : la ligne saine est listée : {t}", f.tag));
            let entree_voisine = ci2_entree(&liste_saine, jeu.voisin).unwrap_or_else(|| panic!("({}) contrôle : le voisin est listé : {t}", f.tag));
            assert_eq!((entree_saine["owner"].as_str(), entree_saine["visibility"].as_str()), (Some("alice"), Some("private")), "({}) contrôle : droit sain écrit", f.tag);
            let (code, t) = ci2_get(addr, "adm", &format!("/api/dashboard/{}", jeu.d)).await;
            assert_eq!(code, 200, "({}) contrôle : lecture saine : {t}", f.tag);
            let lecture_saine = ci2_json(&t);
            let (_, voisin_avant) = ci2_get(addr, "adm", &format!("/api/dashboard/{}", jeu.voisin)).await;

            ci2_alterer(&st, &jeu, f);
            let attendre = |mut v: Value| {
                v["owner"] = json!(f.servis.0);
                v["visibility"] = json!(f.servis.1);
                v
            };
            let (code, t) = ci2_get(addr, "adm", "/api/dashboards").await;
            let mut liste_attendue = liste_saine.clone();
            for e in liste_attendue["dashboards"].as_array_mut().expect("contrôle : liste") {
                if e["id"].as_i64() == Some(jeu.d) {
                    *e = attendre(e.clone());
                }
            }
            assert_ne!(liste_attendue, liste_saine, "({}) contrôle : l'attendu diffère de la liste saine", f.tag);
            assert_eq!((code, ci2_json(&t)), (200, liste_attendue), "({}) adm : la liste entière, la seule colonne illisible servie vide : {t}", f.tag);
            assert_eq!(ci2_entree(&ci2_json(&t), jeu.voisin), Some(entree_voisine.clone()), "({}) adm : l'entrée du voisin sain inchangée", f.tag);
            let (code, t) = ci2_get(addr, "adm", &format!("/api/dashboard/{}", jeu.d)).await;
            assert_eq!((code, ci2_json(&t)), (200, attendre(lecture_saine.clone())), "({}) adm : la lecture entière, la seule colonne illisible servie vide", f.tag);
            let (_, voisin_apres) = ci2_get(addr, "adm", &format!("/api/dashboard/{}", jeu.voisin)).await;
            assert_eq!(ci2_sans_date(&voisin_apres), ci2_sans_date(&voisin_avant), "({}) adm : la lecture du voisin sain, à l'octet", f.tag);

            let mut comptes_juges = 0;
            for qui in ["alice", "bob", "carol"] {
                let (code, t) = ci2_get(addr, qui, "/api/dashboards").await;
                let v = ci2_json(&t);
                assert_eq!((code, v.get("error"), ci2_entree(&v, jeu.d)), (200, None, None), "({}) {qui} : la ligne n'est pas listée : {t}", f.tag);
                assert!(ci2_entree(&v, jeu.voisin).is_some(), "({}) {qui} : contrôle, le voisin commun est listé : {t}", f.tag);
                let (code_absent, absent) = ci2_get(addr, qui, &format!("/api/dashboard/{CI2_ABSENT}")).await;
                let (code, t) = ci2_get(addr, qui, &format!("/api/dashboard/{}", jeu.d)).await;
                assert_eq!((code, ci2_sans_date(&t)), (code_absent, ci2_sans_date(&absent)), "({}) {qui} : la lecture de l'absent, à l'octet", f.tag);
                assert_eq!((code, ci2_corps(&t).as_str()), (404, "dashboard introuvable"), "({}) {qui} : 404", f.tag);
                comptes_juges += 1;
            }
            assert_eq!(comptes_juges, 3, "({}) contrôle : trois comptes", f.tag);
            formes_jouees += 1;
        }
        assert_eq!(formes_jouees, 4, "plancher : chaque forme jouée jusqu'au bout");
    }

    // -------------------------------------------------------------------------------------
    // (C) un panneau en échec, après un redémarrage
    // -------------------------------------------------------------------------------------

    /// Un tableau de l'administrateur et un panneau en SQL brut dont le calcul échoue (`json_extract` sur un texte
    /// malformé : une erreur d'exécution pilotée par les données).
    fn ci2_panneau_en_panne(st: &AppState) -> i64 {
        let c = st.db.lock();
        c.execute_batch("DELETE FROM panel; DELETE FROM dashboard; DELETE FROM panel_cache; DELETE FROM panel_cost;
                         CREATE TABLE ci2_source(v TEXT); INSERT INTO ci2_source(v) VALUES('{pas du json');")
            .expect("fixture : source en panne");
        c.execute("INSERT INTO dashboard(name,created,owner,visibility) VALUES('d-adm',1000,'adm','private')", []).expect("fixture : tableau");
        let d = c.last_insert_rowid();
        c.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'en panne',?2,0,'table')", params![d, CI2_SQL_EN_PANNE]).expect("fixture : panneau");
        c.last_insert_rowid()
    }

    /// MUTATION : `CI2_ECHEC_COMME_ABSENCE`.
    #[tokio::test]
    async fn ci2_corps_d_echec_en_cache_servi_des_le_premier_appel_apres_redemarrage() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, path, _jeu) = ci2_etat("redemarrage");
        let p = ci2_panneau_en_panne(&st);
        let addr = router_serve(st.clone()).await;
        let chemin = format!("/api/panels/{p}/data?from={CI2_FROM}&to={CI2_TO}");
        // Avant le redémarrage : jamais mesuré, une chauffe légitime et un calcul armé, puis le corps d'échec.
        let (code, t) = ci2_get(addr, "adm", &chemin).await;
        assert_eq!((code, ci2_json(&t)["warming"].clone()), (200, json!(true)), "1er appel : chauffe d'un panneau jamais calculé : {t}");
        ci2_attendre_la_tache(&st).await;
        let (code, avant) = ci2_get(addr, "adm", &chemin).await;
        let v = ci2_json(&avant);
        assert_eq!((code, v["error"].as_str(), v.get("warming")), (200, Some(CI2_REQUETE_REJETEE), None), "2e appel : le corps d'échec : {avant}");
        assert_eq!(v["stats"]["coverage"]["reason"], json!("calcul_echoue"), "2e appel : raison de l'échec : {avant}");
        assert_eq!(ci2_compte(&st, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={p} AND payload LIKE '%\"error\"%'")), 1, "le corps d'échec est ÉCRIT en base");

        // Le redémarrage : la base telle quelle, l'état du processus neuf.
        let st2 = ci2_redemarrer(path.as_str());
        let addr2 = router_serve(st2.clone()).await;
        let mut appels = 0;
        for appel in 1..=2 {
            let (code, t) = ci2_get(addr2, "adm", &chemin).await;
            assert_eq!((code, ci2_sans_date(&t)), (200, ci2_sans_date(&avant)), "après redémarrage, appel {appel} : le corps d'échec d'avant, à l'octet, jamais `warming`");
            assert!(ci2_rien_en_vol(&st2), "après redémarrage, appel {appel} : échec frais, rien d'armé");
            appels += 1;
        }
        assert_eq!(appels, 2, "contrôle : deux appels après le redémarrage");
    }

    /// Refuse les INSERT de `panel_cache` et de `panel_cost` (le panneau reste au coût inconnu, donc en SWR).
    fn ci2_refuser_l_ecriture(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name: "panel_cache" } | AuthAction::Insert { table_name: "panel_cost" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    /// (C') le reste, mesuré : rien en base ne porte l'échec quand la base refuse d'écrire. MUTATION : `CI2_REFUS_IGNORE`.
    #[tokio::test]
    async fn ci2_ecriture_refusee_apres_redemarrage_une_chauffe_par_redemarrage_puis_le_503() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, path, _jeu) = ci2_etat("redemarrage-refus");
        let p = ci2_panneau_en_panne(&st);
        ci2_refuser_l_ecriture(&st);
        let addr = router_serve(st.clone()).await;
        let chemin = format!("/api/panels/{p}/data?from={CI2_FROM}&to={CI2_TO}");
        let phrase = format!("{CI2_ECHEC_NON_ECRIT}{CI2_REQUETE_REJETEE}");
        let (code, t) = ci2_get(addr, "adm", &chemin).await;
        assert_eq!((code, ci2_json(&t)["warming"].clone()), (200, json!(true)), "1er appel : chauffe d'un panneau jamais calculé : {t}");
        ci2_attendre_la_tache(&st).await;
        let (code, t) = ci2_get(addr, "adm", &chemin).await;
        assert_eq!((code, ci2_json(&t)["error"].as_str()), (503, Some(phrase.as_str())), "avant le redémarrage : le 503 de l'échec non écrit : {t}");

        let st2 = ci2_redemarrer(path.as_str());
        ci2_refuser_l_ecriture(&st2);
        assert_eq!(ci2_compte(&st2, &format!("SELECT COUNT(*) FROM panel_cache WHERE panel_id={p}")), 0, "rien en base ne porte l'échec");
        let addr2 = router_serve(st2.clone()).await;
        let (code, t) = ci2_get(addr2, "adm", &chemin).await;
        assert_eq!((code, ci2_json(&t)["warming"].clone()), (200, json!(true)), "après redémarrage, 1er appel : une chauffe (rien en base) : {t}");
        ci2_attendre_la_tache(&st2).await;
        let (code, t) = ci2_get(addr2, "adm", &chemin).await;
        assert_eq!((code, ci2_json(&t)["error"].as_str()), (503, Some(phrase.as_str())), "après redémarrage, le calcul rendu : de nouveau le 503 : {t}");
        assert!(ci2_rien_en_vol(&st2), "refus récent : rien de réarmé");
        st.db.lock().authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        st2.db.lock().authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    }
}

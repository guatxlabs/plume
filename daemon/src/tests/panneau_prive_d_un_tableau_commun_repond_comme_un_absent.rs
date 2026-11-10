// =====================================================================================
// `P11.25-h` (vague CB) — UN PANNEAU QUE L'APPELANT NE LIT PAS RÉPOND EXACTEMENT
// COMME UN PANNEAU ABSENT, ET AUCUN GESTE EN MASSE NE LE TOUCHE NI NE LE RÉVÈLE.
//
// LE DÉFAUT, MESURÉ PAR LA ROUTE SUR LA BASE 7c001610 : alice (éditrice) a un tableau COMMUN portant un panneau
// `private`. Sa portée de lecture est celle du propriétaire du tableau (`PorteeLecture::du_dashboard`) : bob (éditeur)
// ne le voit pas dans `GET /api/dashboard/{id}`. Mais `POST /api/panels/{id}` et `DELETE /api/panels/{id}` n'avaient
// pour porte que celle du TABLEAU (`dash_editable`), ouverte sur un tableau commun : bob publiait le panneau (204), le
// relisait ensuite avec sa requête, ou le supprimait sans l'avoir jamais vu. Trois surfaces en masse comptaient aussi
// ce panneau : le compte `panels` de `GET /api/dashboards`, le compte `used_by` de `GET /api/library-panels`, et la
// position d'un panneau créé (`MAX(position)+1` sur tous les panneaux du tableau).
//
// LA RÈGLE : un panneau est LU par l'appelant exactement quand `dash_get` le lui sert (le tableau se lit, et la portée
// de lecture qui en dérive voit la visibilité du panneau : `PorteeLecture::voit`). La porte d'un panneau
// (`panneau_editable`) emprunte cette décision ; les comptes et la position aussi.
//
// CE QUE CES TÉMOINS TIENNENT, par le ROUTEUR réel (alice et bob éditeurs, carol lectrice, adm administrateur) :
//   * pour CHAQUE route qui prend un identifiant de panneau (table `cb3_routes`, plancher compté dans la SOURCE du
//     routeur, jamais écrit en littéral) : bob et carol sur le panneau privé du tableau commun d'alice reçoivent la
//     réponse d'un identifiant de panneau absent de la MÊME route, à l'octet (ligne de statut, en-têtes hors `date`,
//     corps), et la base relue est inchangée (titre, requête, visibilité, tableau, position, cache) ; de même bob et
//     alice sur le panneau privé d'un tableau SEMÉ commun (sans propriétaire), que seul l'administrateur lit ;
//   * alice (propriétaire du tableau) et l'administrateur, chaque geste sur un panneau ENCORE PRIVÉ (un jeu neuf par
//     geste : publier rend le panneau commun, la suppression qui suivrait ne jugerait plus un panneau privé) : le
//     comportement d'avant, et le geste porte ; le panneau COMMUN du même tableau, bob : le comportement d'avant ;
//   * la chaîne de la sonde rejouée : bob publie puis lit, puis supprime -> chaque fois la réponse de l'absent, et
//     `GET /api/dashboard/{id}` relu par bob ne sert ni le panneau, ni son titre, ni sa requête ;
//   * les gestes en masse : `GET /api/dashboards` compte pour bob les seuls panneaux qu'il lit (une visibilité non
//     textuelle compte pour le propriétaire, pas pour bob, et la liste reste lisible) ; `GET /api/library-panels`
//     compte dans `used_by` les seuls référents que le lecteur lit (l'administrateur : tous, orphelin compris) ;
//     `POST /api/panels` place le panneau de bob après les seuls panneaux qu'il lit ; la capture d'un instantané par
//     bob ne fige pas le panneau privé (déjà vrai, non-régression) ;
//   * les refus GARDÉS ne dépendent pas d'un panneau illisible : 403 de rôle (carol, sur le panneau commun comme sur
//     le privé et l'absent), 403 du SQL brut (bob sur le panneau commun, alice sur son panneau privé), 409 du partage
//     qui nomme la définition de bibliothèque privée qu'exécute le panneau (alice, qui lit l'un et l'autre) ; sur le
//     panneau privé d'alice, bob reçoit la réponse de l'absent et rien n'est écrit ;
//   * les valeurs HORS NORME (qu'aucune voie d'écriture ne produit, colonne sans contrainte au schéma) : une visibilité
//     de panneau `equipe`, BLOB (`X'00'`, `X'FF'`, les octets de `shared`) ou texte en UTF-8 invalide ne rend ni
//     `GET /api/dashboards` ni `GET /api/library-panels` illisible, ne compte que pour la propriétaire et
//     l'administrateur, et ne pousse pas la position d'un panneau créé par bob ;
//   * une lecture décide : avant le 404, `panel_update` et `panel_delete` préparent les DEUX mêmes `SELECT` qu'avant
//     (le panneau, avec sa visibilité ; le tableau, propriétaire et visibilité) et pas un de plus ; une visibilité de
//     panneau illisible sert le 503 nommé de la lecture du panneau (corps entier), rien n'est écrit ; un propriétaire
//     de tableau illisible sert le 503 `DROIT D'ÉDITION NON LU`, pas le 404.
//
// CE QU'ILS NE TIENNENT PAS : ce que la console peint (web/ ne distingue pas 403 et 404 sur ces routes) ; une définition
// de bibliothèque COMMUNE modifiée ou supprimée par un autre éditeur change ce qu'exécute un panneau privé qui la
// référence (détaché à la suppression) : c'est le contrat de la bibliothèque, et la réponse ne dit rien des référents ;
// le panneau dont le tableau n'a plus de ligne (orphelin) répond comme un panneau absent sur `POST /api/panels/{id}`
// depuis la vague CC (tenu par lignes_de_panneau_bornees_et_restes_des_tableaux.rs) ; l'identifiant d'un panneau reste tiré d'une séquence commune à tous les tableaux.
//
// MUTATIONS (posées sous `cfg!(test)`, armées par la variable de mutation de l'exécuteur le temps de la vérification,
// puis retirées) : chaque témoin nomme les siennes.
// =====================================================================================
mod panneau_prive_d_un_tableau_commun_repond_comme_un_absent {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Le mot de passe commun des comptes de témoin.
    const CB3_MDP: &str = "cb3pw1234567";
    /// Un identifiant qu'aucun panneau ne porte.
    const CB3_ABSENT: i64 = 999_999;
    /// Le refus du SQL brut, écrit en littéral.
    const CB3_SQL_BRUT: &str = "SQL brut réservé à l'administrateur (utilisez GXQL)";
    /// Le 503 de `panel_update` sur une visibilité non lue (`CAUSE_VISIBILITE_NON_LUE`), écrit en littéral.
    const CB3_VISIBILITE_NON_LUE: &str = "VISIBILITÉ COURANTE NON LUE : le geste de partage ne peut pas être jugé, donc rien n'a été écrit. Ce n'est PAS « cet objet est déjà partagé » ni « un élément le retient ». Réessayez.";
    /// Le 503 de `panel_delete` sur une lecture du panneau non faite (`CAUSE_PANNEAU_NON_SUPPRIME_NON_LU`), écrit en
    /// littéral.
    const CB3_PANNEAU_NON_SUPPRIME_NON_LU: &str = "PANNEAU NON SUPPRIMÉ : la base n'a pas rendu ce panneau (le tableau de bord qui le porte) — ce n'est PAS une absence, c'est une lecture qui n'a pas eu lieu, et le droit de le supprimer n'est pas jugé. RIEN n'est supprimé : le panneau et son cache sont intacts. Réessayez ; si le refus persiste, la table des panneaux est illisible.";
    /// Le 503 de la porte sur un propriétaire de tableau non lu (`CAUSE_DROIT_D_EDITION_NON_LU`) : son début, écrit en
    /// littéral (la phrase entière est tenue par les témoins de la porte).
    const CB3_DROIT_NON_LU: &str = "DROIT D'ÉDITION NON LU";

    /// Une base de routeur sans objet de tableau de bord, et quatre comptes réels : alice et bob éditeurs, carol lectrice,
    /// adm administrateur.
    fn cb3_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = router_test_state(&format!("cb3-{tag}"));
        let h = hash_pw(CB3_MDP).expect("fixture : empreinte");
        {
            let c = st.db.lock();
            c.execute_batch(
                "DELETE FROM panel_cache; DELETE FROM panel; DELETE FROM dashboard; DELETE FROM view_dashboard; DELETE FROM view; \
                 DELETE FROM library_panel; DELETE FROM playlist; DELETE FROM dashboard_snapshot;",
            )
            .expect("fixture : base vide");
            for (nom, role) in [("alice", "editor"), ("bob", "editor"), ("carol", "viewer"), ("adm", "admin")] {
                c.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![nom, h, role]).expect("fixture : compte");
            }
        }
        (st, p)
    }

    fn cb3_authz(nom: &str) -> String {
        format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{nom}:{CB3_MDP}")))
    }

    async fn cb3_envoi(addr: std::net::SocketAddr, qui: &str, methode: &str, chemin: &str, corps: &str) -> (u16, String) {
        let en_json = [("Content-Type", "application/json")];
        let entetes: &[(&str, &str)] = if corps.is_empty() { &[] } else { &en_json };
        router_probe_envoi(addr, methode, chemin, Some(&cb3_authz(qui)), entetes, corps).await
    }

    /// La réponse brute sans sa ligne `date` (seule à varier d'une réponse à l'autre). Copie de l'outil du témoin des
    /// objets de tableau de bord illisibles.
    fn cb3_sans_date(texte: &str) -> String {
        texte.split("\r\n").filter(|l| !l.to_ascii_lowercase().starts_with("date:")).collect::<Vec<_>>().join("\r\n")
    }

    /// Le corps d'une réponse du routeur (après les en-têtes), découpage `chunked` retiré quand l'en-tête l'annonce.
    /// Copie de l'outil du témoin des objets de tableau de bord illisibles.
    fn cb3_corps_brut(texte: &str) -> String {
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

    fn cb3_json(texte: &str) -> Value {
        serde_json::from_str(&cb3_corps_brut(texte)).unwrap_or_else(|_| panic!("corps JSON attendu : {texte}"))
    }

    fn cb3_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn cb3_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture `{sql}` : {e}"))
    }

    fn cb3_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture `{sql}` : {e}"))
    }

    /// TOUT ce qu'un geste sur un panneau pourrait écrire, relu d'un coup : tableaux, panneaux (titre, requête,
    /// visibilité, tableau, position, rattachement, disposition), définitions de bibliothèque, lignes de cache. Une
    /// ligne par objet, dans l'ordre. (Adaptation de l'empreinte du témoin des objets de tableau de bord illisibles.)
    fn cb3_empreinte(st: &AppState) -> String {
        st.db
            .lock()
            .query_row(
                "SELECT COALESCE(group_concat(x, ';'), '') FROM (SELECT x FROM (
                    SELECT 'd'||id||'|'||name||'|'||COALESCE(owner,'')||'|'||COALESCE(visibility,'') AS x FROM dashboard
                    UNION ALL SELECT 'p'||id||'|'||title||'|'||dashboard_id||'|'||quote(visibility)||'|'||is_soql||'|'||query||'|'||
                        COALESCE(position,'')||'|'||COALESCE(library_panel_id,'')||'|'||COALESCE(viz,'')||'|'||COALESCE(window_s,'')||'|'||
                        COALESCE(query_private,'')||'|'||COALESCE(cols,'')||'|'||COALESCE(height,'')||'|'||COALESCE(drill,'') FROM panel
                    UNION ALL SELECT 'l'||id||'|'||title||'|'||visibility||'|'||is_soql||'|'||COALESCE(updated,0) FROM library_panel
                    UNION ALL SELECT 'c'||panel_id||'|'||range_key FROM panel_cache
                 ) ORDER BY x)",
                [],
                |r| r.get(0),
            )
            .expect("relecture de l'empreinte")
    }

    /// Un tableau d'un propriétaire (`None` : semé) sous une visibilité, portant un panneau COMMUN en position 0 et un
    /// panneau PRIVÉ en position 1 (la plus haute), qui porte une ligne de cache.
    #[derive(Clone, Copy)]
    struct Cb3Jeu {
        tableau: i64,
        prive: i64,
        commun: i64,
    }

    fn cb3_jeu(st: &AppState, etiquette: &str, owner: Option<&str>, vis: &str) -> Cb3Jeu {
        let c = st.db.lock();
        c.execute(
            "INSERT INTO dashboard(name,created,owner,visibility,cols,height,collapsed) VALUES(?1,1000,?2,?3,1,0,0)",
            params![format!("Tableau {etiquette}"), owner, vis],
        )
        .expect("fixture : tableau");
        let tableau = c.last_insert_rowid();
        c.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,visibility,position) VALUES(?1,?2,'search | stats count',1,'table','shared',0)",
            params![tableau, format!("Commun {etiquette}")],
        )
        .expect("fixture : panneau commun");
        let commun = c.last_insert_rowid();
        c.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,visibility,position) VALUES(?1,?2,?3,1,'table','private',1)",
            params![tableau, format!("Secret {etiquette}"), format!("search source=coffre{tableau} | stats count")],
        )
        .expect("fixture : panneau privé");
        let prive = c.last_insert_rowid();
        c.execute("INSERT INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,'r','fp',1,'{}')", params![prive])
            .expect("fixture : cache du panneau privé");
        Cb3Jeu { tableau, prive, commun }
    }

    /// Une route qui prend un identifiant de panneau : son gestionnaire (pour le plancher), sa méthode, son chemin rendu
    /// depuis un identifiant, son corps, et le statut d'avant (propriétaire, administrateur, panneau commun).
    struct Cb3Route {
        nom: &'static str,
        gestionnaire: &'static str,
        methode: &'static str,
        chemin: fn(i64) -> String,
        corps: &'static str,
        attendu: u16,
    }

    /// Les routes, dans l'ordre où un geste qui porte ne prive pas le suivant de son panneau (la suppression en dernier).
    fn cb3_routes() -> Vec<Cb3Route> {
        vec![
            Cb3Route { nom: "modifier", gestionnaire: "panel_update", methode: "POST", chemin: |p| format!("/api/panels/{p}"), corps: r#"{"title":"écrit","query":"search | stats count by host"}"#, attendu: 204 },
            Cb3Route { nom: "publier", gestionnaire: "panel_update", methode: "POST", chemin: |p| format!("/api/panels/{p}"), corps: r#"{"visibility":"shared","title":"publié"}"#, attendu: 204 },
            Cb3Route { nom: "lire les données", gestionnaire: "panel_data", methode: "GET", chemin: |p| format!("/api/panels/{p}/data"), corps: "", attendu: 200 },
            Cb3Route { nom: "supprimer", gestionnaire: "panel_delete", methode: "DELETE", chemin: |p| format!("/api/panels/{p}"), corps: "", attendu: 204 },
        ]
    }

    /// LE PLANCHER, COMPTÉ DANS LA SOURCE DU ROUTEUR (jamais un littéral) : les gestionnaires montés sous un chemin
    /// `/api/panels/{id}…`. Une route ajoutée demain fait grandir le compte, et la table doit la suivre.
    fn cb3_gestionnaires_d_un_panneau_dans_la_source() -> usize {
        include_str!("../server/groupes_de_routes.rs")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && l.contains(".route(\"/api/panels/{id}"))
            .map(|l| ["get(", "post(", "delete(", "put(", "patch("].iter().map(|m| l.matches(m).count()).sum::<usize>())
            .sum()
    }

    // -------------------------------------------------------------------------------------
    // (1) chaque route d'un panneau : le panneau privé du tableau commun d'autrui répond comme l'absent
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par la route, pour CHAQUE route de `cb3_routes` (plancher : les gestionnaires comptés dans la
    /// source du routeur) :
    ///   * bob (éditeur) et carol (lectrice) sur le panneau PRIVÉ du tableau COMMUN d'alice, puis bob et alice sur le
    ///     panneau privé d'un tableau SEMÉ commun : la réponse brute (statut, en-têtes hors `date`, corps) est celle de
    ///     l'identifiant absent de la même route, envoyée par le même compte ; la base relue est inchangée après chaque
    ///     envoi ;
    ///   * alice sur le panneau privé de son tableau commun, l'administrateur sur celui d'un autre tableau commun d'alice
    ///     puis sur celui d'un autre tableau semé : le statut d'avant, et chaque geste d'écriture porte ;
    ///   * bob sur le panneau COMMUN du tableau commun d'alice : le statut d'avant, et le geste porte.
    /// MUTATIONS : `CB3_PU_ROUVERT`, `CB3_PD_ROUVERT` (la porte du seul tableau rétablie, route par route),
    /// `CB3_COMMUN_ABSENT` (le panneau commun servi comme absent), `CB3_ADMIN_ABSENT` (l'administrateur perd la portée du
    /// propriétaire), `CB3_PROPRIETAIRE_ABSENT` (la propriétaire du tableau perd la sienne), `CB3C_PD_PRIVE_REFUSE` (la
    /// suppression refuse tout panneau non commun, propriétaire et administrateur compris : rouge seulement si la
    /// suppression part d'un panneau encore privé).
    #[tokio::test]
    async fn cb3_chaque_route_sert_l_absent_sur_le_panneau_prive_d_un_tableau_commun() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb3_etat("routes");
        let pour_bob = cb3_jeu(&st, "commun d'alice", Some("alice"), "shared");
        let seme = cb3_jeu(&st, "semé", None, "shared");
        let addr = router_serve(st.clone()).await;
        let routes = cb3_routes();
        let inventaire = cb3_gestionnaires_d_un_panneau_dans_la_source();
        let gestionnaires: std::collections::BTreeSet<&str> = routes.iter().map(|r| r.gestionnaire).collect();
        assert!(inventaire >= 1, "INSTRUMENT : aucun gestionnaire de panneau compté dans la source du routeur");
        assert!(gestionnaires.len() >= inventaire, "plancher : {} gestionnaire(s) dans la table pour {inventaire} compté(s) dans la source", gestionnaires.len());

        // (a) le panneau qu'ils ne lisent pas : la réponse de l'absent, rien n'est écrit.
        for (quel, panneau, comptes) in [("le panneau privé du tableau commun d'alice", pour_bob.prive, ["bob", "carol"]), ("le panneau privé d'un tableau semé", seme.prive, ["bob", "alice"])] {
            for route in &routes {
                for qui in comptes {
                    let avant = cb3_empreinte(&st);
                    let (_, absent) = cb3_envoi(addr, qui, route.methode, &(route.chemin)(CB3_ABSENT), route.corps).await;
                    assert!(absent.starts_with("HTTP/1.1 4"), "{} ({qui}) : référence, l'identifiant absent est refusé : {absent}", route.nom);
                    let (_, sur_le_cache) = cb3_envoi(addr, qui, route.methode, &(route.chemin)(panneau), route.corps).await;
                    assert_eq!(cb3_sans_date(&sur_le_cache), cb3_sans_date(&absent), "{} ({qui}) : {quel} répond comme un identifiant absent", route.nom);
                    assert_eq!(cb3_empreinte(&st), avant, "{} ({qui}, {quel}) : rien n'est écrit", route.nom);
                }
            }
        }
        // (b) la propriétaire du tableau, puis l'administrateur (tableau commun d'alice, puis tableau semé) : le
        // comportement d'avant, et chaque geste porte. CHAQUE GESTE PART D'UN PANNEAU ENCORE PRIVÉ, sur un jeu neuf :
        // « publier » rend le panneau commun, et une suppression qui le suivrait ne jugerait plus qu'un panneau commun.
        for (qui, proprietaire) in [("alice", Some("alice")), ("adm", Some("alice")), ("adm", None)] {
            for route in &routes {
                let jeu = cb3_jeu(&st, &format!("{qui}, {}, {}", route.nom, proprietaire.unwrap_or("semé")), proprietaire, "shared");
                let visibilite = cb3_texte(&st, &format!("SELECT visibility FROM panel WHERE id={}", jeu.prive));
                assert_eq!(visibilite, "private", "{} ({qui}) : INSTRUMENT, le geste part d'un panneau privé", route.nom);
                let avant = cb3_empreinte(&st);
                let (code, t) = cb3_envoi(addr, qui, route.methode, &(route.chemin)(jeu.prive), route.corps).await;
                assert_eq!(code, route.attendu, "{} ({qui}, panneau privé) : le comportement d'avant : {t}", route.nom);
                if route.methode != "GET" {
                    assert_ne!(cb3_empreinte(&st), avant, "{} ({qui}, panneau privé) : le geste porte", route.nom);
                }
                if route.methode == "DELETE" {
                    assert_eq!(cb3_entier(&st, &format!("SELECT COUNT(*) FROM panel WHERE id={}", jeu.prive)), 0, "({qui}) le panneau privé est supprimé");
                }
            }
        }
        // (c) le panneau COMMUN du tableau commun d'alice, bob : le comportement d'avant.
        for route in &routes {
            let avant = cb3_empreinte(&st);
            let (code, t) = cb3_envoi(addr, "bob", route.methode, &(route.chemin)(pour_bob.commun), route.corps).await;
            assert_eq!(code, route.attendu, "{} (bob, panneau commun) : le comportement d'avant : {t}", route.nom);
            if route.methode != "GET" {
                assert_ne!(cb3_empreinte(&st), avant, "{} (bob, panneau commun) : le geste porte", route.nom);
            }
        }
        assert_eq!(cb3_entier(&st, &format!("SELECT COUNT(*) FROM panel WHERE id={} AND visibility='private'", pour_bob.prive)), 1, "le panneau privé d'alice reste, privé");
    }

    // -------------------------------------------------------------------------------------
    // (2) la chaîne de la sonde : publier puis lire, puis supprimer
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par la route : bob publie le panneau privé du tableau commun d'alice (`{"visibility":"shared"}`),
    /// puis en lit les données, puis le supprime : chaque fois la réponse d'un identifiant de panneau absent, à l'octet ;
    /// le panneau reste `private`, avec son cache ; `GET /api/dashboard/{id}` relu par bob est servi (200) et ne porte
    /// ni l'identifiant du panneau, ni son titre, ni sa requête, mais porte le panneau commun. Contrôle : alice relit
    /// son tableau et y voit son panneau privé, requête comprise.
    /// MUTATIONS : `CB3_PU_ROUVERT`, `CB3_PD_ROUVERT`.
    #[tokio::test]
    async fn cb3_publier_puis_lire_puis_supprimer_repond_comme_un_absent() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb3_etat("chaine");
        let jeu = cb3_jeu(&st, "commun d'alice", Some("alice"), "shared");
        let titre = cb3_texte(&st, &format!("SELECT title FROM panel WHERE id={}", jeu.prive));
        let requete = cb3_texte(&st, &format!("SELECT query FROM panel WHERE id={}", jeu.prive));
        let addr = router_serve(st.clone()).await;
        let avant = cb3_empreinte(&st);
        for (geste, methode, chemin, corps) in [
            ("publier", "POST", "/api/panels/{}", r#"{"visibility":"shared"}"#),
            ("lire les données", "GET", "/api/panels/{}/data", ""),
            ("supprimer", "DELETE", "/api/panels/{}", ""),
        ] {
            let (_, absent) = cb3_envoi(addr, "bob", methode, &chemin.replace("{}", &CB3_ABSENT.to_string()), corps).await;
            let (_, t) = cb3_envoi(addr, "bob", methode, &chemin.replace("{}", &jeu.prive.to_string()), corps).await;
            assert_eq!(cb3_sans_date(&t), cb3_sans_date(&absent), "{geste} : la réponse d'un panneau absent");
            assert_eq!(cb3_empreinte(&st), avant, "{geste} : rien n'est écrit");
        }
        let (code, t) = cb3_envoi(addr, "bob", "GET", &format!("/api/dashboard/{}", jeu.tableau), "").await;
        assert_eq!(code, 200, "bob lit le tableau commun : {t}");
        let ids: Vec<i64> = cb3_json(&t)["panels"].as_array().map(|a| a.iter().filter_map(|p| p["id"].as_i64()).collect()).unwrap_or_default();
        assert_eq!(ids, vec![jeu.commun], "bob : le seul panneau commun est servi");
        let corps = cb3_corps_brut(&t);
        assert!(!corps.contains(&titre) && !corps.contains(&requete), "bob : ni le titre ni la requête du panneau privé : {corps}");
        let (_, t) = cb3_envoi(addr, "alice", "GET", &format!("/api/dashboard/{}", jeu.tableau), "").await;
        let corps = cb3_corps_brut(&t);
        assert!(corps.contains(&titre) && corps.contains(&requete), "contrôle : alice voit son panneau privé : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (3) les gestes en masse : comptes et position
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par la route :
    ///   * `GET /api/dashboards` : sur le tableau commun d'alice (un panneau commun, un privé), `panels` vaut 1 pour bob
    ///     et carol, 2 pour alice et l'administrateur ; sur un second tableau commun d'alice dont un panneau porte une
    ///     visibilité non textuelle (BLOB), la liste reste lisible (aucune clé `error`) et `panels` vaut 1 pour bob, 2
    ///     pour alice ;
    ///   * `GET /api/library-panels` : la définition commune d'alice référencée par le panneau privé de son tableau commun,
    ///     par un panneau commun du même tableau, par un panneau commun de son tableau PRIVÉ et par un panneau commun
    ///     ORPHELIN (tableau sans ligne) : `used_by` vaut 1 pour bob et carol, 3 pour alice, 4 pour l'administrateur ;
    ///   * `POST /api/panels` sur le tableau commun d'alice (commun en position 0, privé en position 1) : le panneau de bob
    ///     prend la position 1, celui d'alice puis celui de l'administrateur la position qui suit TOUS les panneaux ; sur
    ///     un tableau neuf de même forme où l'administrateur crée le PREMIER, son panneau prend la position 2 (seul ce
    ///     cas sépare « tous les panneaux » de « les panneaux communs », que les créations de bob et d'alice confondent) ;
    ///   * `POST /api/dashboard-snapshots` par bob, sur un troisième tableau commun d'alice : la capture ne fige pas le
    ///     titre du panneau privé, fige celui du commun (non-régression).
    /// MUTATIONS : `CB3_DL_COMPTE` (le compte de tous les panneaux), `CB3_DL_SANS_CAST` (la visibilité non textuelle
    /// rend la liste illisible), `CB3_UB_COMPTE` (tous les référents), `CB3_UB_TABLEAU_IGNORE` (la lisibilité du tableau
    /// du référent n'est pas jugée), `CB3_UB_SANS_PRESENT` (l'orphelin compté comme commun), `CB3_UB_SANS_ADMIN`
    /// (l'administrateur perd l'orphelin), `CB3_PC_POSITION` (la position sur tous les panneaux), `CB3_PC_ADMIN`
    /// (l'administrateur placé après les seuls panneaux communs).
    #[tokio::test]
    async fn cb3_les_gestes_en_masse_ne_comptent_ni_ne_placent_le_panneau_prive() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb3_etat("masse");
        let jeu = cb3_jeu(&st, "commun d'alice", Some("alice"), "shared");
        let avec_blob = cb3_jeu(&st, "commun d'alice, visibilité illisible", Some("alice"), "shared");
        cb3_ecrire(&st, &format!("UPDATE panel SET visibility=X'00' WHERE id={};", avec_blob.prive));
        let prive_d_alice = cb3_jeu(&st, "privé d'alice", Some("alice"), "private");
        let pour_la_capture = cb3_jeu(&st, "capturé", Some("alice"), "shared");
        let l_admin_d_abord = cb3_jeu(&st, "commun d'alice, l'administrateur crée d'abord", Some("alice"), "shared");
        cb3_ecrire(
            &st,
            &format!(
                "INSERT INTO library_panel(name,title,query,is_soql,viz,drill,owner,visibility,created,updated) VALUES('Définition commune','T','search | stats count',1,'table','','alice','shared',1000,1000);
                 UPDATE panel SET library_panel_id=(SELECT MAX(id) FROM library_panel) WHERE id IN ({},{},{});
                 INSERT INTO panel(dashboard_id,title,query,is_soql,viz,visibility,position,library_panel_id) VALUES({CB3_ABSENT},'orphelin','search | stats count',1,'table','shared',0,(SELECT MAX(id) FROM library_panel));",
                jeu.prive, jeu.commun, prive_d_alice.commun
            ),
        );
        let lib = cb3_entier(&st, "SELECT MAX(id) FROM library_panel");
        let addr = router_serve(st.clone()).await;

        // `GET /api/dashboards`.
        for (qui, attendu, attendu_blob) in [("bob", 1, 1), ("carol", 1, 1), ("alice", 2, 2), ("adm", 2, 2)] {
            let (code, t) = cb3_envoi(addr, qui, "GET", "/api/dashboards", "").await;
            let v = cb3_json(&t);
            assert_eq!((code, v.get("error").is_none()), (200, true), "({qui}) la liste est lue : {t}");
            let compte = |did: i64| v["dashboards"].as_array().and_then(|a| a.iter().find(|d| d["id"].as_i64() == Some(did))).and_then(|d| d["panels"].as_i64());
            assert_eq!((compte(jeu.tableau), compte(avec_blob.tableau)), (Some(attendu), Some(attendu_blob)), "({qui}) les panneaux comptés sont ceux que dash_get sert : {t}");
        }

        // `GET /api/library-panels`.
        for (qui, attendu) in [("bob", 1), ("carol", 1), ("alice", 3), ("adm", 4)] {
            let (code, t) = cb3_envoi(addr, qui, "GET", "/api/library-panels", "").await;
            let v = cb3_json(&t);
            let used_by = v["library_panels"].as_array().and_then(|a| a.iter().find(|l| l["id"].as_i64() == Some(lib))).and_then(|l| l["used_by"].as_i64());
            assert_eq!((code, used_by), (200, Some(attendu)), "({qui}) used_by compte les référents que le lecteur lit : {t}");
        }

        // `POST /api/panels` : la position du panneau créé.
        for (qui, attendu) in [("bob", 1), ("alice", 2), ("adm", 3)] {
            let (code, t) = cb3_envoi(addr, qui, "POST", "/api/panels", &format!(r#"{{"dashboard_id":{},"title":"neuf de {qui}","query":"search | stats count","is_soql":true}}"#, jeu.tableau)).await;
            assert_eq!(code, 200, "({qui}) création : {t}");
            let id = cb3_json(&t)["id"].as_i64().expect("identifiant créé");
            assert_eq!(cb3_entier(&st, &format!("SELECT position FROM panel WHERE id={id}")), attendu, "({qui}) la position suit les panneaux que le créateur lit");
        }
        let (code, t) = cb3_envoi(addr, "adm", "POST", "/api/panels", &format!(r#"{{"dashboard_id":{},"title":"neuf de l'administrateur","query":"search | stats count","is_soql":true}}"#, l_admin_d_abord.tableau)).await;
        assert_eq!(code, 200, "(adm, premier) création : {t}");
        let id = cb3_json(&t)["id"].as_i64().expect("identifiant créé");
        assert_eq!(cb3_entier(&st, &format!("SELECT position FROM panel WHERE id={id}")), 2, "(adm, premier) l'administrateur se place après TOUS les panneaux, le privé compris");

        // `POST /api/dashboard-snapshots` par bob.
        let (code, t) = cb3_envoi(addr, "bob", "POST", "/api/dashboard-snapshots", &format!(r#"{{"dashboard_id":{},"from":0,"to":100}}"#, pour_la_capture.tableau)).await;
        assert_eq!(code, 200, "capture par bob : {t}");
        let fige = cb3_texte(&st, "SELECT data FROM dashboard_snapshot ORDER BY id DESC LIMIT 1");
        assert!(!fige.contains("Secret capturé") && fige.contains("Commun capturé"), "la capture de bob ne fige que le panneau commun : {fige}");
    }

    // -------------------------------------------------------------------------------------
    // (4) les refus gardés ne dépendent pas d'un panneau illisible
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par la route, rien n'est écrit sur un refus :
    ///   * 403 de rôle : carol (lectrice) reçoit le même 403 sur le panneau COMMUN, sur le privé et sur l'absent, à la
    ///     modification comme à la suppression ;
    ///   * 403 du SQL brut (JSON) : bob sur le panneau commun du tableau commun d'alice, alice sur son panneau privé ;
    ///     bob sur le panneau privé : la réponse d'un panneau absent ;
    ///   * 409 du partage qui nomme la définition de bibliothèque privée qu'exécute le panneau : alice, qui lit le panneau
    ///     et la définition (la sienne) ; bob, même corps, sur le même panneau : la réponse d'un panneau absent, sans le nom
    ///     de la définition.
    /// MUTATIONS : `CB3_PU_ROUVERT`, `CB3_COMMUN_ABSENT`, `CB3_PROPRIETAIRE_ABSENT`.
    #[tokio::test]
    async fn cb3_les_refus_gardes_ne_dependent_pas_d_un_panneau_illisible() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb3_etat("gardes");
        let jeu = cb3_jeu(&st, "commun d'alice", Some("alice"), "shared");
        let addr = router_serve(st.clone()).await;
        let avant = cb3_empreinte(&st);

        // 403 de rôle.
        for (methode, corps) in [("POST", r#"{"title":"écrit"}"#), ("DELETE", "")] {
            let (code, commun) = cb3_envoi(addr, "carol", methode, &format!("/api/panels/{}", jeu.commun), corps).await;
            assert_eq!(code, 403, "carol, {methode} sur le panneau commun : le refus de rôle : {commun}");
            for panneau in [jeu.prive, CB3_ABSENT] {
                let (_, t) = cb3_envoi(addr, "carol", methode, &format!("/api/panels/{panneau}"), corps).await;
                assert_eq!(cb3_sans_date(&t), cb3_sans_date(&commun), "carol, {methode} sur #{panneau} : le même refus de rôle");
            }
        }
        assert_eq!(cb3_empreinte(&st), avant, "les refus de rôle n'écrivent rien");

        // 403 du SQL brut.
        let brut = r#"{"is_soql":false,"query":"SELECT name FROM user"}"#;
        for (qui, panneau) in [("bob", jeu.commun), ("alice", jeu.prive)] {
            let (code, t) = cb3_envoi(addr, qui, "POST", &format!("/api/panels/{panneau}"), brut).await;
            assert_eq!((code, cb3_corps_brut(&t)), (403, json!({ "error": CB3_SQL_BRUT }).to_string()), "({qui}) SQL brut : 403 JSON : {t}");
        }
        let (_, absent) = cb3_envoi(addr, "bob", "POST", &format!("/api/panels/{CB3_ABSENT}"), brut).await;
        let (_, t) = cb3_envoi(addr, "bob", "POST", &format!("/api/panels/{}", jeu.prive), brut).await;
        assert_eq!(cb3_sans_date(&t), cb3_sans_date(&absent), "bob, SQL brut sur le panneau privé : la réponse d'un panneau absent");
        assert!(absent.starts_with("HTTP/1.1 404"), "référence : {absent}");
        assert_eq!(cb3_empreinte(&st), avant, "les refus du SQL brut n'écrivent rien");

        // 409 du partage nommé.
        cb3_ecrire(
            &st,
            &format!(
                "INSERT INTO library_panel(name,title,query,is_soql,viz,drill,owner,visibility,created,updated) VALUES('Revue privée d''alice','T','search | stats count',1,'table','','alice','private',1000,1000);
                 UPDATE panel SET library_panel_id=(SELECT MAX(id) FROM library_panel) WHERE id={};",
                jeu.prive
            ),
        );
        let avant = cb3_empreinte(&st);
        let publier = r#"{"visibility":"shared"}"#;
        let (code, t) = cb3_envoi(addr, "alice", "POST", &format!("/api/panels/{}", jeu.prive), publier).await;
        assert_eq!(code, 409, "alice publie son panneau qui exécute sa définition privée : {t}");
        assert!(cb3_corps_brut(&t).contains("la définition de bibliothèque « Revue privée d'alice »"), "le refus nomme la définition : {t}");
        let (_, absent) = cb3_envoi(addr, "bob", "POST", &format!("/api/panels/{CB3_ABSENT}"), publier).await;
        let (_, t) = cb3_envoi(addr, "bob", "POST", &format!("/api/panels/{}", jeu.prive), publier).await;
        assert_eq!(cb3_sans_date(&t), cb3_sans_date(&absent), "bob publie le même panneau : la réponse d'un panneau absent");
        assert!(!t.contains("Revue privée"), "bob : la définition n'est pas nommée : {t}");
        assert_eq!(cb3_empreinte(&st), avant, "aucun de ces refus n'écrit");
    }

    // -------------------------------------------------------------------------------------
    // (5) une lecture décide, et une lecture ratée sert le 503 nommé d'avant
    // -------------------------------------------------------------------------------------

    fn cb3_au(nom: &str, role: &str) -> AuthUser {
        AuthUser {
            name: nom.into(), role: role.into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    /// CE QU'IL TIENT :
    ///   * avant le 404 de bob sur le panneau privé du tableau commun d'alice, `panel_update` et `panel_delete` préparent
    ///     chacun DEUX `SELECT` (le panneau avec sa visibilité ; le tableau, propriétaire et visibilité), les deux qu'ils
    ///     préparaient avant, et pas un de plus (autorisateur qui compte, mode 0 : `st.db`) ;
    ///   * une visibilité de panneau illisible (BLOB) : `panel_update` sert à bob, à alice et à l'administrateur le 503
    ///     `VISIBILITÉ COURANTE NON LUE` (clés exactes `error` et `id`, phrase entière), `panel_delete` le 503
    ///     `PANNEAU NON SUPPRIMÉ … NON LU` (clés exactes, phrase entière) ; le panneau reste, rien n'est écrit ;
    ///   * un propriétaire de tableau illisible : bob sur le panneau privé reçoit le 503 `DROIT D'ÉDITION NON LU` des deux
    ///     routes, pas le 404 (la lecture qui manque n'est pas une absence).
    /// MUTATIONS : `CB3_SECONDE_LECTURE` (la visibilité du panneau relue par un second énoncé), `CB3_PD_VISIBILITE_REPLI`
    /// (une visibilité illisible lue comme `shared` à la suppression).
    #[tokio::test]
    async fn cb3_une_lecture_decide_et_la_lecture_ratee_sert_le_503_d_avant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb3_etat("une-lecture");
        let jeu = cb3_jeu(&st, "commun d'alice", Some("alice"), "shared");
        let bob = cb3_au("bob", "editor");
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
        let r = panel_update(State(st.clone()), Extension(bob.clone()), Path(jeu.prive), Json(json!({ "visibility": "shared" }))).await;
        mesures.push(("panel_update", r.status().as_u16(), selects.swap(0, Ordering::SeqCst)));
        let r = panel_delete(State(st.clone()), Extension(bob.clone()), Path(jeu.prive)).await;
        mesures.push(("panel_delete", r.status().as_u16(), selects.swap(0, Ordering::SeqCst)));
        st.db.lock().authorizer(None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>);
        assert_eq!(mesures, vec![("panel_update", 404, 2), ("panel_delete", 404, 2)], "deux SELECT décident, les deux d'avant");

        // Visibilité du panneau illisible.
        cb3_ecrire(&st, &format!("UPDATE panel SET visibility=X'00' WHERE id={};", jeu.prive));
        let addr = router_serve(st.clone()).await;
        let avant = cb3_empreinte(&st);
        for qui in ["bob", "alice", "adm"] {
            for (methode, corps, phrase) in [("POST", r#"{"visibility":"shared"}"#, CB3_VISIBILITE_NON_LUE), ("DELETE", "", CB3_PANNEAU_NON_SUPPRIME_NON_LU)] {
                let (code, t) = cb3_envoi(addr, qui, methode, &format!("/api/panels/{}", jeu.prive), corps).await;
                let v = cb3_json(&t);
                let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(|k| k.as_str()).collect()).unwrap_or_default();
                assert_eq!((code, cles, v["error"].as_str()), (503, vec!["error", "id"], Some(phrase)), "({qui}, {methode}) visibilité illisible : le 503 nommé de la lecture du panneau : {t}");
            }
            assert_eq!(cb3_empreinte(&st), avant, "({qui}) visibilité illisible : rien n'est écrit");
        }

        // Propriétaire du tableau illisible : la lecture qui manque n'est pas une absence.
        cb3_ecrire(&st, &format!("UPDATE panel SET visibility='private' WHERE id={}; UPDATE dashboard SET owner=X'00' WHERE id={};", jeu.prive, jeu.tableau));
        let avant = cb3_empreinte(&st);
        for (methode, corps) in [("POST", r#"{"title":"écrit"}"#), ("DELETE", "")] {
            let (code, t) = cb3_envoi(addr, "bob", methode, &format!("/api/panels/{}", jeu.prive), corps).await;
            let v = cb3_json(&t);
            assert_eq!((code, v["error"].as_str().map(|e| e.starts_with(CB3_DROIT_NON_LU))), (503, Some(true)), "(bob, {methode}) propriétaire illisible : 503 droit non lu, pas 404 : {t}");
        }
        assert_eq!(cb3_empreinte(&st), avant, "propriétaire illisible : rien n'est écrit");
    }

    // -------------------------------------------------------------------------------------
    // (6) les valeurs hors norme : rien d'illisible, rien de compté ni de placé pour le lecteur
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par la route, sur un tableau commun d'alice : panneau commun (position 0), panneau `private` (1),
    /// puis cinq panneaux de visibilité HORS NORME — texte `equipe` (2), BLOB `X'00'` (3), BLOB `X'FF'` (4), texte en
    /// UTF-8 invalide (5), BLOB des octets de `shared` (6) ; tous référencent une même définition commune d'alice :
    ///   * `GET /api/dashboards` est lu (200, aucune clé `error`) par bob, carol, alice et l'administrateur ; `panels`
    ///     vaut 1 pour bob et carol (le seul commun : `PorteeLecture::voit` n'ouvre que le TEXTE exact `shared`, et
    ///     `dash_get` ne sert aucun de ces panneaux à un lecteur du partage), 7 pour alice et l'administrateur ;
    ///   * `GET /api/library-panels` est lu par les mêmes, `used_by` vaut 1 pour bob et carol, 7 pour alice et
    ///     l'administrateur ;
    ///   * `POST /api/panels` par bob : la position 1 (après le seul panneau qu'il lit) ; par alice : la position 7.
    /// MUTATIONS : `CB3C_DL_SANS_HEX` et `CB3C_UB_CAST_SANS_HEX` (le texte lu tel quel, la forme d'avant : l'UTF-8
    /// invalide rend la liste illisible), `CB3C_DL_SANS_TYPE` et `CB3C_UB_SANS_TYPE` (le BLOB des octets de `shared` compté
    /// pour bob), `CB3C_UB_SANS_HEX` (la visibilité du panneau passée brute aux fonctions JSON : un BLOB rend la liste
    /// illisible), `CB3C_PC_BORD` (la position calculée sur `<> 'private'`).
    #[tokio::test]
    async fn cb3_une_valeur_hors_norme_ne_rend_rien_illisible_ni_ne_compte_pour_le_lecteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb3_etat("hors-norme");
        let jeu = cb3_jeu(&st, "commun d'alice, hors norme", Some("alice"), "shared");
        let did = jeu.tableau;
        cb3_ecrire(
            &st,
            &format!(
                "INSERT INTO library_panel(name,title,query,is_soql,viz,drill,owner,visibility,created,updated) VALUES('Définition hors norme','T','search | stats count',1,'table','','alice','shared',1000,1000);
                 UPDATE panel SET library_panel_id=(SELECT MAX(id) FROM library_panel) WHERE id IN ({},{});
                 INSERT INTO panel(dashboard_id,title,query,is_soql,viz,visibility,position,library_panel_id) VALUES
                    ({did},'Équipe','search | stats count',1,'table','private',2,(SELECT MAX(id) FROM library_panel)),
                    ({did},'Nul','search | stats count',1,'table','private',3,(SELECT MAX(id) FROM library_panel)),
                    ({did},'FF','search | stats count',1,'table','private',4,(SELECT MAX(id) FROM library_panel)),
                    ({did},'UTF-8 invalide','search | stats count',1,'table','private',5,(SELECT MAX(id) FROM library_panel)),
                    ({did},'Octets de shared','search | stats count',1,'table','private',6,(SELECT MAX(id) FROM library_panel));
                 UPDATE panel SET visibility='equipe' WHERE dashboard_id={did} AND position=2;
                 UPDATE panel SET visibility=X'00' WHERE dashboard_id={did} AND position=3;
                 UPDATE panel SET visibility=X'FF' WHERE dashboard_id={did} AND position=4;
                 UPDATE panel SET visibility=CAST(X'FF' AS TEXT) WHERE dashboard_id={did} AND position=5;
                 UPDATE panel SET visibility=X'736861726564' WHERE dashboard_id={did} AND position=6;",
                jeu.prive, jeu.commun
            ),
        );
        let types = cb3_texte(&st, &format!("SELECT group_concat(typeof(visibility),',') FROM (SELECT visibility FROM panel WHERE dashboard_id={did} ORDER BY position)"));
        assert_eq!(types, "text,text,text,blob,blob,text,blob", "INSTRUMENT : les valeurs hors norme sont posées");
        let lib = cb3_entier(&st, "SELECT MAX(id) FROM library_panel");
        let addr = router_serve(st.clone()).await;

        for (qui, attendu) in [("bob", 1), ("carol", 1), ("alice", 7), ("adm", 7)] {
            let (code, t) = cb3_envoi(addr, qui, "GET", "/api/dashboards", "").await;
            let v = cb3_json(&t);
            let panels = v["dashboards"].as_array().and_then(|a| a.iter().find(|d| d["id"].as_i64() == Some(did))).and_then(|d| d["panels"].as_i64());
            assert_eq!((code, v.get("error").is_none(), panels), (200, true, Some(attendu)), "({qui}) GET /api/dashboards lu, panneaux comptés ceux que dash_get sert : {t}");
            let (code, t) = cb3_envoi(addr, qui, "GET", "/api/library-panels", "").await;
            let v = cb3_json(&t);
            let used_by = v["library_panels"].as_array().and_then(|a| a.iter().find(|l| l["id"].as_i64() == Some(lib))).and_then(|l| l["used_by"].as_i64());
            assert_eq!((code, v.get("error").is_none(), used_by), (200, true, Some(attendu)), "({qui}) GET /api/library-panels lu, référents comptés ceux que le lecteur lit : {t}");
        }

        for (qui, attendu) in [("bob", 1), ("alice", 7)] {
            let (code, t) = cb3_envoi(addr, qui, "POST", "/api/panels", &format!(r#"{{"dashboard_id":{did},"title":"neuf de {qui}","query":"search | stats count","is_soql":true}}"#)).await;
            assert_eq!(code, 200, "({qui}) création : {t}");
            let id = cb3_json(&t)["id"].as_i64().expect("identifiant créé");
            assert_eq!(cb3_entier(&st, &format!("SELECT position FROM panel WHERE id={id}")), attendu, "({qui}) la position suit les seuls panneaux que le créateur lit");
        }
    }
}

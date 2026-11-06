// =====================================================================================
// `P11.25-f` (vague CB, reste « un autre écart de réponse, hors des vues ») — UN OBJET DE TABLEAU DE BORD QUE L'APPELANT
// NE LIT PAS RÉPOND EXACTEMENT COMME UN OBJET ABSENT.
//
// LE DÉFAUT, MESURÉ PAR LA ROUTE SUR LA BASE 78c1c43c : `GET /api/dashboard/{id}` sur le tableau privé d'alice répondait
// à bob `403 dashboard privé`, et `404 dashboard introuvable` sur un identifiant qu'aucun tableau ne porte : l'écart
// disait l'existence du tableau privé d'autrui. Même écart sur chaque geste dont la porte est `dash_editable` (son
// `Refusee` est rendu EXACTEMENT quand le tableau est privé à un autre compte : un tableau commun est modifiable par tout
// lecteur) ou `lisible_par` : `POST`/`DELETE /api/dashboard/{id}`, `POST /api/panels` (par son `dashboard_id`),
// `POST`/`DELETE /api/panels/{id}`, `POST`/`DELETE /api/library-panels/{id}`, `POST`/`DELETE /api/playlists/{id}`,
// `POST /api/dashboard-snapshots` (par son `dashboard_id`), et `DELETE /api/dashboard-snapshots/id/{id}` (un instantané
// ne se lit par son numéro que par son auteur ou l'administrateur, le périmètre de `snapshots_list`).
//
// CE QUE CES TÉMOINS TIENNENT, par le ROUTEUR réel (alice et bob éditeurs, carol lectrice, adm administrateur) :
//   * pour CHAQUE site changé (table `cb2_sites`, plancher compté dans la SOURCE des deux gestionnaires, jamais écrit
//     en littéral) : bob et carol sur l'objet privé d'alice reçoivent la réponse d'un identifiant absent de la MÊME
//     route, à l'octet (ligne de statut, en-têtes hors `date`, corps), et la base relue est inchangée ;
//   * alice (propriétaire) et l'administrateur : le comportement d'avant (200 ou 204, et le geste porte) ;
//   * objet COMMUN d'alice, bob : le comportement d'avant (le geste porte ; `DELETE /api/dashboard/{id}` garde son 403) ;
//   * les 403 GARDÉS ne dépendent pas d'un objet illisible : rôle (carol, sur un objet privé comme sur un absent), SQL
//     brut réservé à l'administrateur (panneau créé ou modifié, définition de bibliothèque créée ou modifiée), suppression
//     d'un tableau commun ou semé par qui n'en est pas propriétaire ; sur l'objet privé d'autrui, chacun de ces gestes
//     reçoit la réponse de l'absent, et rien n'est écrit ;
//   * les deux sites qui répondaient DÉJÀ comme l'absent (`GET /api/panels/{id}/data`, 403 « panneau inaccessible » ;
//     la définition de bibliothèque référencée par un panneau, 403 « définition de bibliothèque inaccessible ») : à
//     l'octet, inchangés ;
//   * `DELETE /api/dashboard/{id}` décide en UNE lecture (propriétaire et visibilité du même énoncé, autorisateur qui
//     compte les `SELECT`), et une visibilité illisible sert le 503 nommé d'avant, corps entier, rien n'est supprimé.
//
// CE QU'ILS NE TIENNENT PAS : ce que la console peint (web/ ne distingue pas 403 et 404 sur ces routes : refus peint par
// la forme partagée) ; le 403 de `POST`/`DELETE /api/views/{id}` sur une vue commune dont l'appelant n'est pas
// propriétaire est tenu par `cb1_vue_commune_403_semee_privee_absente_sauf_admin_et_proprietaire_permis` ; un panneau
// PRIVÉ posé sur un tableau COMMUN reste modifiable et supprimable par un éditeur qui ne le lit pas (hors de ce reste).
//
// MUTATIONS (posées sous `cfg!(test)`, armées par la variable de mutation de l'exécuteur le temps de la vérification,
// puis retirées) : chaque témoin nomme les siennes.
// =====================================================================================
mod objet_de_tableau_de_bord_illisible_repond_comme_un_absent {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Le mot de passe commun des comptes de témoin.
    const CB2_MDP: &str = "cb2pw1234567";
    /// Un identifiant qu'aucun objet ne porte.
    const CB2_ABSENT: i64 = 999_999;
    /// Le 503 de `dash_delete` sur une lecture non faite (`CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME_NON_LU`), écrit en littéral.
    const CB2_TABLEAU_NON_SUPPRIME_NON_LU: &str = "TABLEAU DE BORD NON SUPPRIMÉ : la base n'a pas rendu ce tableau de bord (son propriétaire) — ce n'est PAS une absence, c'est une lecture qui n'a pas eu lieu, et le droit de le supprimer n'est pas jugé. RIEN n'est supprimé : le tableau de bord et ses panneaux sont intacts. Réessayez ; si le refus persiste, la table des tableaux de bord est illisible.";
    /// Les deux refus du SQL brut, écrits en littéral.
    const CB2_SQL_BRUT: &str = "SQL brut réservé à l'administrateur (utilisez GXQL)";

    /// Une base de routeur sans objet de tableau de bord, et quatre comptes réels : alice et bob éditeurs, carol lectrice,
    /// adm administrateur.
    fn cb2_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = router_test_state(&format!("cb2-{tag}"));
        let h = hash_pw(CB2_MDP).expect("fixture : empreinte");
        {
            let c = st.db.lock();
            c.execute_batch(
                "DELETE FROM panel; DELETE FROM dashboard; DELETE FROM view_dashboard; DELETE FROM view; \
                 DELETE FROM library_panel; DELETE FROM playlist; DELETE FROM dashboard_snapshot;",
            )
            .expect("fixture : base vide");
            for (nom, role) in [("alice", "editor"), ("bob", "editor"), ("carol", "viewer"), ("adm", "admin")] {
                c.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![nom, h, role]).expect("fixture : compte");
            }
        }
        (st, p)
    }

    fn cb2_authz(nom: &str) -> String {
        format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{nom}:{CB2_MDP}")))
    }

    async fn cb2_envoi(addr: std::net::SocketAddr, qui: &str, methode: &str, chemin: &str, corps: &str) -> (u16, String) {
        let en_json = [("Content-Type", "application/json")];
        let entetes: &[(&str, &str)] = if corps.is_empty() { &[] } else { &en_json };
        router_probe_envoi(addr, methode, chemin, Some(&cb2_authz(qui)), entetes, corps).await
    }

    /// La réponse brute sans sa ligne `date` (seule à varier d'une réponse à l'autre).
    fn cb2_sans_date(texte: &str) -> String {
        texte.split("\r\n").filter(|l| !l.to_ascii_lowercase().starts_with("date:")).collect::<Vec<_>>().join("\r\n")
    }

    /// Le corps d'une réponse du routeur (après les en-têtes), découpage `chunked` retiré quand l'en-tête l'annonce.
    fn cb2_corps_brut(texte: &str) -> String {
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

    fn cb2_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn cb2_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture `{sql}` : {e}"))
    }

    /// TOUT ce qu'un geste de cette famille pourrait écrire, relu d'un coup : tableaux, panneaux, définitions de
    /// bibliothèque, listes de lecture, instantanés (une ligne par objet, dans l'ordre).
    fn cb2_empreinte(st: &AppState) -> String {
        st.db
            .lock()
            .query_row(
                "SELECT COALESCE(group_concat(x, ';'), '') FROM (SELECT x FROM (
                    SELECT 'd'||id||'|'||name||'|'||COALESCE(owner,'')||'|'||COALESCE(visibility,'') AS x FROM dashboard
                    UNION ALL SELECT 'p'||id||'|'||title||'|'||dashboard_id||'|'||COALESCE(visibility,'')||'|'||is_soql||'|'||query FROM panel
                    UNION ALL SELECT 'l'||id||'|'||title||'|'||visibility||'|'||is_soql||'|'||COALESCE(updated,0) FROM library_panel
                    UNION ALL SELECT 'y'||id||'|'||name||'|'||visibility||'|'||COALESCE(updated,0) FROM playlist
                    UNION ALL SELECT 's'||id||'|'||name||'|'||token FROM dashboard_snapshot
                 ) ORDER BY x)",
                [],
                |r| r.get(0),
            )
            .expect("relecture de l'empreinte")
    }

    /// Un jeu d'objets d'un propriétaire sous une visibilité : un tableau, un panneau commun posé dessus, une définition
    /// de bibliothèque, une liste de lecture, et un instantané de ce tableau dont il est l'auteur.
    #[derive(Clone, Copy)]
    struct Cb2Jeu {
        tableau: i64,
        panneau: i64,
        bibliotheque: i64,
        liste: i64,
        instantane: i64,
    }

    /// Le jeu qu'aucun objet ne porte : chaque identifiant est absent.
    const CB2_JEU_ABSENT: Cb2Jeu = Cb2Jeu { tableau: CB2_ABSENT, panneau: CB2_ABSENT, bibliotheque: CB2_ABSENT, liste: CB2_ABSENT, instantane: CB2_ABSENT };

    fn cb2_jeu(st: &AppState, etiquette: &str, owner: Option<&str>, vis: &str) -> Cb2Jeu {
        let c = st.db.lock();
        c.execute(
            "INSERT INTO dashboard(name,created,owner,visibility,cols,height,collapsed) VALUES(?1,1000,?2,?3,1,0,0)",
            params![format!("Tableau {etiquette}"), owner, vis],
        )
        .expect("fixture : tableau");
        let tableau = c.last_insert_rowid();
        c.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,visibility) VALUES(?1,?2,'search | stats count',1,'table','shared')",
            params![tableau, format!("Panneau {etiquette}")],
        )
        .expect("fixture : panneau");
        let panneau = c.last_insert_rowid();
        c.execute(
            "INSERT INTO library_panel(name,title,query,is_soql,viz,drill,owner,visibility,created,updated) VALUES(?1,?1,'search | stats count',1,'table','',?2,?3,1000,1000)",
            params![format!("Définition {etiquette}"), owner, vis],
        )
        .expect("fixture : définition");
        let bibliotheque = c.last_insert_rowid();
        c.execute(
            "INSERT INTO playlist(name,interval_s,items,owner,visibility,created,updated) VALUES(?1,30,'[]',?2,?3,1000,1000)",
            params![format!("Liste {etiquette}"), owner, vis],
        )
        .expect("fixture : liste");
        let liste = c.last_insert_rowid();
        let jeton = format!("{:064x}", tableau * 1_000_003 + panneau);
        c.execute(
            "INSERT INTO dashboard_snapshot(dashboard_id,name,token,data,created,created_by,role_at_capture) VALUES(?1,?2,?3,'{}',1000,?4,'editor')",
            params![tableau, format!("Instantané {etiquette}"), jeton, owner],
        )
        .expect("fixture : instantané");
        let instantane = c.last_insert_rowid();
        Cb2Jeu { tableau, panneau, bibliotheque, liste, instantane }
    }

    /// Un site changé : sa route (méthode, chemin et corps rendus depuis un jeu), ce que la propriétaire et
    /// l'administrateur en reçoivent (le comportement d'avant), et ce qu'un éditeur reçoit sur l'objet COMMUN (`None` :
    /// l'objet n'a pas de forme commune).
    struct Cb2Site {
        nom: &'static str,
        methode: &'static str,
        chemin: fn(&Cb2Jeu) -> String,
        corps: fn(&Cb2Jeu) -> String,
        proprietaire: u16,
        commun: Option<u16>,
    }

    /// Les sites changés, dans l'ordre où un geste qui porte ne prive pas le suivant de son objet (les suppressions en
    /// dernier, le tableau tout à la fin).
    fn cb2_sites() -> Vec<Cb2Site> {
        vec![
            Cb2Site { nom: "dash_get", methode: "GET", chemin: |j| format!("/api/dashboard/{}", j.tableau), corps: |_| String::new(), proprietaire: 200, commun: Some(200) },
            Cb2Site { nom: "dash_update", methode: "POST", chemin: |j| format!("/api/dashboard/{}", j.tableau), corps: |_| r#"{"name":"écrit"}"#.into(), proprietaire: 204, commun: Some(204) },
            Cb2Site {
                nom: "panel_create",
                methode: "POST",
                chemin: |_| "/api/panels".into(),
                corps: |j| format!(r#"{{"dashboard_id":{},"title":"neuf","query":"search | stats count","is_soql":true}}"#, j.tableau),
                proprietaire: 200,
                commun: Some(200),
            },
            Cb2Site { nom: "panel_update", methode: "POST", chemin: |j| format!("/api/panels/{}", j.panneau), corps: |_| r#"{"title":"écrit"}"#.into(), proprietaire: 204, commun: Some(204) },
            Cb2Site { nom: "library_panel_update", methode: "POST", chemin: |j| format!("/api/library-panels/{}", j.bibliotheque), corps: |_| r#"{"title":"écrit"}"#.into(), proprietaire: 204, commun: Some(204) },
            Cb2Site { nom: "playlist_update", methode: "POST", chemin: |j| format!("/api/playlists/{}", j.liste), corps: |_| r#"{"name":"écrit"}"#.into(), proprietaire: 204, commun: Some(204) },
            Cb2Site { nom: "snapshot_create", methode: "POST", chemin: |_| "/api/dashboard-snapshots".into(), corps: |j| format!(r#"{{"dashboard_id":{}}}"#, j.tableau), proprietaire: 200, commun: Some(200) },
            Cb2Site { nom: "panel_delete", methode: "DELETE", chemin: |j| format!("/api/panels/{}", j.panneau), corps: |_| String::new(), proprietaire: 204, commun: Some(204) },
            Cb2Site { nom: "library_panel_delete", methode: "DELETE", chemin: |j| format!("/api/library-panels/{}", j.bibliotheque), corps: |_| String::new(), proprietaire: 204, commun: Some(204) },
            Cb2Site { nom: "playlist_delete", methode: "DELETE", chemin: |j| format!("/api/playlists/{}", j.liste), corps: |_| String::new(), proprietaire: 204, commun: Some(204) },
            // Un instantané n'a pas de forme commune : il ne se lit par son numéro que par son auteur ou l'administrateur.
            Cb2Site { nom: "snapshot_delete", methode: "DELETE", chemin: |j| format!("/api/dashboard-snapshots/id/{}", j.instantane), corps: |_| String::new(), proprietaire: 204, commun: None },
            // Supprimer reste un geste de propriétaire : le tableau commun d'autrui garde son 403 (il ne dit rien de plus
            // que ce que l'appelant lit déjà).
            Cb2Site { nom: "dash_delete", methode: "DELETE", chemin: |j| format!("/api/dashboard/{}", j.tableau), corps: |_| String::new(), proprietaire: 204, commun: Some(403) },
        ]
    }

    /// LE PLANCHER, COMPTÉ DANS LA SOURCE DES GESTIONNAIRES (jamais un littéral) : les bras qui servent le `Refusee` de
    /// `dash_editable`, les appels de la porte d'édition de `dash_ergonomics`, les refus rendus sur `!lisible_par`, et le
    /// jugement de l'auteur d'un instantané. Un site ajouté demain fait grandir le compte, et la table doit le suivre.
    fn cb2_inventaire() -> usize {
        let tableaux = include_str!("../handlers/dashboards.rs");
        let ergonomie = include_str!("../handlers/dash_ergonomics.rs");
        let code = |src: &'static str| src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>();
        let (tableaux, ergonomie) = (code(tableaux), code(ergonomie));
        let bras_refusee = tableaux
            .iter()
            .filter(|l| l.contains("PorteDuTableau::Refusee") && !l.contains("PorteDuTableau::Refusee if ") && !l.contains("=> PorteDuTableau::Refusee"))
            .count();
        let portes_d_edition = ergonomie.iter().filter(|l| l.contains("refus_de_la_porte_d_edition(&conn")).count();
        let refus_de_lisibilite = tableaux.iter().chain(ergonomie.iter()).filter(|l| l.contains("if !panneau_resolu::lisible_par(")).count();
        let auteur_d_instantane = ergonomie.iter().filter(|l| l.contains("by != au.name")).count();
        bras_refusee + portes_d_edition + refus_de_lisibilite + auteur_d_instantane
    }

    // -------------------------------------------------------------------------------------
    // (1) chaque site changé : l'objet privé d'autrui répond comme l'absent ; propriétaire, admin et commun inchangés
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par la route, pour CHAQUE site de `cb2_sites` (plancher : `cb2_inventaire`, compté dans la source) :
    ///   * bob (éditeur) et carol (lectrice) sur l'objet PRIVÉ d'alice : la réponse brute (statut, en-têtes hors `date`,
    ///     corps) est celle de l'identifiant absent de la même route, envoyée par le même compte ; la base relue est
    ///     inchangée après chaque envoi ; carol reçoit le 403 de rôle sur chaque geste d'écriture, privé comme absent ;
    ///   * alice sur son jeu privé, l'administrateur sur un autre jeu privé d'alice : le statut d'avant, et le geste porte ;
    ///   * bob sur le jeu COMMUN d'alice : le statut d'avant (403 gardé sur la suppression du tableau).
    /// MUTATIONS : `CB2_DU_403`, `CB2_DG_403`, `CB2_DD_403`, `CB2_PC_403`, `CB2_PU_403`, `CB2_PD_403`, `CB2_ERGO_403`,
    /// `CB2_SC_403`, `CB2_SD_403` (le 403 rétabli, site par site), `CB2_PU_ABSENCE_DU_TABLEAU` (le panneau d'un tableau
    /// privé d'autrui servi sous la phrase du tableau absent), `CB2_DD_COMMUNE_404` (le tableau commun d'autrui servi
    /// 404 à la suppression), `CB2_DG_ADMIN_404`, `CB2_DG_PROPRIETAIRE_404`, `CB2_SD_SANS_ADMIN` (l'administrateur perd
    /// l'instantané d'alice).
    #[tokio::test]
    async fn cb2_chaque_site_sert_l_absent_sur_l_objet_prive_d_autrui_et_garde_le_reste() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb2_etat("sites");
        let prive = cb2_jeu(&st, "privé d'alice", Some("alice"), "private");
        let pour_l_admin = cb2_jeu(&st, "privé d'alice pour l'admin", Some("alice"), "private");
        let commun = cb2_jeu(&st, "commun d'alice", Some("alice"), "shared");
        let addr = router_serve(st.clone()).await;
        let sites = cb2_sites();
        let inventaire = cb2_inventaire();
        assert!(inventaire >= 1, "INSTRUMENT : aucun site compté dans la source");
        assert!(sites.len() >= inventaire, "plancher : {} site(s) dans la table pour {inventaire} compté(s) dans la source", sites.len());

        // (a) bob et carol sur le privé d'alice : la réponse de l'absent, rien n'est écrit.
        for site in &sites {
            for qui in ["bob", "carol"] {
                let avant = cb2_empreinte(&st);
                let (_, absent) = cb2_envoi(addr, qui, site.methode, &(site.chemin)(&CB2_JEU_ABSENT), &(site.corps)(&CB2_JEU_ABSENT)).await;
                assert!(absent.starts_with("HTTP/1.1 4"), "{} ({qui}) : référence, l'identifiant absent est refusé : {absent}", site.nom);
                let (_, sur_le_prive) = cb2_envoi(addr, qui, site.methode, &(site.chemin)(&prive), &(site.corps)(&prive)).await;
                assert_eq!(cb2_sans_date(&sur_le_prive), cb2_sans_date(&absent), "{} ({qui}) : l'objet privé d'alice répond comme un identifiant absent", site.nom);
                assert_eq!(cb2_empreinte(&st), avant, "{} ({qui}) : rien n'est écrit", site.nom);
                if qui == "carol" && site.methode != "GET" {
                    assert!(sur_le_prive.starts_with("HTTP/1.1 403"), "{} (carol) : le refus de rôle, privé comme absent : {sur_le_prive}", site.nom);
                }
            }
        }
        // (b) la propriétaire, puis l'administrateur : le comportement d'avant, et chaque geste porte.
        for (qui, jeu) in [("alice", prive), ("adm", pour_l_admin)] {
            for site in &sites {
                let avant = cb2_empreinte(&st);
                let (code, t) = cb2_envoi(addr, qui, site.methode, &(site.chemin)(&jeu), &(site.corps)(&jeu)).await;
                assert_eq!(code, site.proprietaire, "{} ({qui}) : le comportement d'avant : {t}", site.nom);
                if site.methode != "GET" {
                    assert_ne!(cb2_empreinte(&st), avant, "{} ({qui}) : le geste porte", site.nom);
                }
            }
        }
        // (c) l'objet COMMUN d'alice, bob : le comportement d'avant.
        for site in &sites {
            let Some(attendu) = site.commun else { continue };
            let avant = cb2_empreinte(&st);
            let (code, t) = cb2_envoi(addr, "bob", site.methode, &(site.chemin)(&commun), &(site.corps)(&commun)).await;
            assert_eq!(code, attendu, "{} (bob, objet commun) : le comportement d'avant : {t}", site.nom);
            if attendu == 403 {
                assert_eq!((cb2_corps_brut(&t), cb2_empreinte(&st)), (String::new(), avant), "{} (bob, objet commun) : 403 sans corps, rien n'est écrit", site.nom);
            } else if site.methode != "GET" {
                assert_ne!(cb2_empreinte(&st), avant, "{} (bob, objet commun) : le geste porte", site.nom);
            }
        }
        assert_eq!(cb2_compte(&st, &format!("SELECT COUNT(*) FROM dashboard WHERE id={}", commun.tableau)), 1, "le tableau commun d'alice reste");
    }

    // -------------------------------------------------------------------------------------
    // (2) les 403 gardés ne dépendent pas d'un objet illisible
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par la route (bob éditeur, rien n'est écrit sur un refus) :
    ///   * SQL brut à la création d'un panneau : 403 texte sur SON tableau privé ; sur le tableau privé d'alice, la réponse
    ///     d'un tableau absent ;
    ///   * SQL brut à la modification d'un panneau : 403 JSON sur le panneau du tableau COMMUN d'alice ; sur celui de son
    ///     tableau privé, la réponse d'un panneau absent ;
    ///   * SQL brut à la modification d'une définition : 403 sans corps sur la définition commune d'alice ; sur sa privée,
    ///     la réponse d'une définition absente ; à la création d'une définition (aucun objet en cause) : 403 JSON ;
    ///   * suppression d'un tableau commun (propriétaire nommé) et d'un tableau semé (propriétaire NULL, commun) : 403 sans
    ///     corps ; du tableau privé d'alice : la réponse d'un tableau absent.
    /// Le refus de rôle (carol) est tenu par le témoin des sites. MUTATIONS : `CB2_DD_COMMUNE_404`, `CB2_PC_403`,
    /// `CB2_PU_403`, `CB2_ERGO_403`, `CB2_DD_403`.
    #[tokio::test]
    async fn cb2_les_403_gardes_ne_dependent_pas_d_un_objet_illisible() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb2_etat("gardes");
        let prive = cb2_jeu(&st, "privé d'alice", Some("alice"), "private");
        let commun = cb2_jeu(&st, "commun d'alice", Some("alice"), "shared");
        let de_bob = cb2_jeu(&st, "privé de bob", Some("bob"), "private");
        let seme = cb2_jeu(&st, "semé", None, "shared");
        let addr = router_serve(st.clone()).await;
        let brut_creation = |did: i64| format!(r#"{{"dashboard_id":{did},"title":"brut","query":"SELECT name FROM user","is_soql":false}}"#);
        let brut_modif = r#"{"is_soql":false,"query":"SELECT name FROM user"}"#;
        let avant = cb2_empreinte(&st);

        // SQL brut, création d'un panneau.
        let (code, t) = cb2_envoi(addr, "bob", "POST", "/api/panels", &brut_creation(de_bob.tableau)).await;
        assert_eq!((code, cb2_corps_brut(&t)), (403, CB2_SQL_BRUT.to_string()), "SQL brut sur son tableau : 403 texte : {t}");
        let (_, absent) = cb2_envoi(addr, "bob", "POST", "/api/panels", &brut_creation(CB2_ABSENT)).await;
        let (_, t) = cb2_envoi(addr, "bob", "POST", "/api/panels", &brut_creation(prive.tableau)).await;
        assert_eq!(cb2_sans_date(&t), cb2_sans_date(&absent), "SQL brut sur le tableau privé d'alice : la réponse d'un tableau absent");
        assert!(absent.starts_with("HTTP/1.1 404"), "référence : {absent}");

        // SQL brut, modification d'un panneau.
        let (code, t) = cb2_envoi(addr, "bob", "POST", &format!("/api/panels/{}", commun.panneau), brut_modif).await;
        assert_eq!((code, cb2_corps_brut(&t)), (403, json!({ "error": CB2_SQL_BRUT }).to_string()), "SQL brut sur le panneau d'un tableau commun : 403 JSON : {t}");
        let (_, absent) = cb2_envoi(addr, "bob", "POST", &format!("/api/panels/{CB2_ABSENT}"), brut_modif).await;
        let (_, t) = cb2_envoi(addr, "bob", "POST", &format!("/api/panels/{}", prive.panneau), brut_modif).await;
        assert_eq!(cb2_sans_date(&t), cb2_sans_date(&absent), "SQL brut sur le panneau du tableau privé d'alice : la réponse d'un panneau absent");
        assert!(absent.starts_with("HTTP/1.1 404"), "référence : {absent}");

        // SQL brut, définitions de bibliothèque.
        let (code, t) = cb2_envoi(addr, "bob", "POST", &format!("/api/library-panels/{}", commun.bibliotheque), r#"{"is_soql":false}"#).await;
        assert_eq!((code, cb2_corps_brut(&t)), (403, String::new()), "SQL brut sur la définition commune : 403 sans corps : {t}");
        let (_, absent) = cb2_envoi(addr, "bob", "POST", &format!("/api/library-panels/{CB2_ABSENT}"), r#"{"is_soql":false}"#).await;
        let (_, t) = cb2_envoi(addr, "bob", "POST", &format!("/api/library-panels/{}", prive.bibliotheque), r#"{"is_soql":false}"#).await;
        assert_eq!(cb2_sans_date(&t), cb2_sans_date(&absent), "SQL brut sur la définition privée d'alice : la réponse d'une définition absente");
        assert!(absent.starts_with("HTTP/1.1 404"), "référence : {absent}");
        let (code, t) = cb2_envoi(addr, "bob", "POST", "/api/library-panels", r#"{"name":"brute","query":"SELECT name FROM user","is_soql":false}"#).await;
        assert_eq!((code, cb2_corps_brut(&t)), (403, json!({ "error": CB2_SQL_BRUT }).to_string()), "SQL brut à la création d'une définition : 403 JSON : {t}");

        // Suppression d'un tableau dont bob n'est pas propriétaire.
        for (quoi, did) in [("commun d'alice", commun.tableau), ("semé", seme.tableau)] {
            let (code, t) = cb2_envoi(addr, "bob", "DELETE", &format!("/api/dashboard/{did}"), "").await;
            assert_eq!((code, cb2_corps_brut(&t)), (403, String::new()), "supprimer le tableau {quoi} : 403 sans corps : {t}");
        }
        let (_, absent) = cb2_envoi(addr, "bob", "DELETE", &format!("/api/dashboard/{CB2_ABSENT}"), "").await;
        let (_, t) = cb2_envoi(addr, "bob", "DELETE", &format!("/api/dashboard/{}", prive.tableau), "").await;
        assert_eq!(cb2_sans_date(&t), cb2_sans_date(&absent), "supprimer le tableau privé d'alice : la réponse d'un tableau absent");
        assert_eq!(cb2_empreinte(&st), avant, "aucun de ces refus n'écrit");
    }

    // -------------------------------------------------------------------------------------
    // (3) les deux sites qui répondaient déjà comme l'absent
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par la route : `GET /api/panels/{id}/data` sur le panneau du tableau privé d'alice répond à bob et
    /// à carol comme sur un panneau absent (403 « panneau inaccessible », à l'octet) ; un panneau créé par bob sur SON
    /// tableau en référençant la définition privée d'alice reçoit la réponse d'une définition absente (403 « définition de
    /// bibliothèque inaccessible »), rien n'est créé. Contrôle : alice lit les données de son panneau (200).
    #[tokio::test]
    async fn cb2_les_sites_deja_alignes_sur_l_absent_le_restent() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb2_etat("alignes");
        let prive = cb2_jeu(&st, "privé d'alice", Some("alice"), "private");
        let de_bob = cb2_jeu(&st, "privé de bob", Some("bob"), "private");
        let addr = router_serve(st.clone()).await;
        let avant = cb2_empreinte(&st);
        for qui in ["bob", "carol"] {
            let (_, absent) = cb2_envoi(addr, qui, "GET", &format!("/api/panels/{CB2_ABSENT}/data"), "").await;
            let (_, t) = cb2_envoi(addr, qui, "GET", &format!("/api/panels/{}/data", prive.panneau), "").await;
            assert_eq!(cb2_sans_date(&t), cb2_sans_date(&absent), "données du panneau privé d'alice ({qui}) : la réponse d'un panneau absent");
            assert_eq!((absent.starts_with("HTTP/1.1 403"), cb2_corps_brut(&absent)), (true, json!({ "error": "panneau inaccessible" }).to_string()), "référence ({qui}) : {absent}");
        }
        let reference = |lib: i64| format!(r#"{{"dashboard_id":{},"title":"réf","query":"","is_soql":true,"library_panel_id":{lib}}}"#, de_bob.tableau);
        let (_, absent) = cb2_envoi(addr, "bob", "POST", "/api/panels", &reference(CB2_ABSENT)).await;
        let (_, t) = cb2_envoi(addr, "bob", "POST", "/api/panels", &reference(prive.bibliotheque)).await;
        assert_eq!(cb2_sans_date(&t), cb2_sans_date(&absent), "référencer la définition privée d'alice : la réponse d'une définition absente");
        assert_eq!((absent.starts_with("HTTP/1.1 403"), cb2_corps_brut(&absent)), (true, "définition de bibliothèque inaccessible".to_string()), "référence : {absent}");
        assert_eq!(cb2_empreinte(&st), avant, "rien n'est écrit");
        let (code, t) = cb2_envoi(addr, "alice", "GET", &format!("/api/panels/{}/data", prive.panneau), "").await;
        assert_eq!(code, 200, "contrôle : alice lit les données de son panneau : {t}");
    }

    // -------------------------------------------------------------------------------------
    // (4) la suppression d'un tableau décide en une lecture, et sa lecture non faite reste le 503 d'avant
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : avant le 404 (tableau privé d'alice) et avant le 403 (tableau commun d'alice), `dash_delete`
    /// prépare UN SEUL `SELECT` : propriétaire et visibilité viennent du même énoncé (autorisateur qui compte, mode 0 :
    /// `st.db`). Puis, par la route : une visibilité illisible sert à alice, à bob et à l'administrateur le 503 nommé
    /// d'avant (clés exactes `error` et `id`, phrase entière), et le tableau reste.
    /// MUTATION : `CB2_DD_SECONDE_LECTURE` (la visibilité relue par un second énoncé).
    #[tokio::test]
    async fn cb2_la_suppression_d_un_tableau_decide_en_une_lecture() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cb2_etat("une-lecture");
        let prive = cb2_jeu(&st, "privé d'alice", Some("alice"), "private");
        let commun = cb2_jeu(&st, "commun d'alice", Some("alice"), "shared");
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
        let r = dash_delete(State(st.clone()), Extension(bob.clone()), Path(prive.tableau)).await;
        mesures.push(("tableau privé d'alice", r.status().as_u16(), selects.swap(0, Ordering::SeqCst)));
        let r = dash_delete(State(st.clone()), Extension(bob.clone()), Path(commun.tableau)).await;
        mesures.push(("tableau commun d'alice", r.status().as_u16(), selects.swap(0, Ordering::SeqCst)));
        st.db.lock().authorizer(None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>);
        assert_eq!(mesures, vec![("tableau privé d'alice", 404, 1), ("tableau commun d'alice", 403, 1)], "un seul SELECT décide");

        cb2_ecrire(&st, &format!("UPDATE dashboard SET visibility=X'00' WHERE id={};", prive.tableau));
        let addr = router_serve(st.clone()).await;
        for qui in ["alice", "bob", "adm"] {
            let (code, t) = cb2_envoi(addr, qui, "DELETE", &format!("/api/dashboard/{}", prive.tableau), "").await;
            let v: Value = serde_json::from_str(&cb2_corps_brut(&t)).unwrap_or_else(|_| panic!("({qui}) corps JSON attendu : {t}"));
            let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(|k| k.as_str()).collect()).unwrap_or_default();
            assert_eq!((code, cles, v["error"].as_str()), (503, vec!["error", "id"], Some(CB2_TABLEAU_NON_SUPPRIME_NON_LU)), "({qui}) visibilité illisible : le 503 nommé d'avant : {t}");
            assert_eq!(cb2_compte(&st, &format!("SELECT COUNT(*) FROM dashboard WHERE id={}", prive.tableau)), 1, "({qui}) le tableau reste");
        }
    }
}

// =====================================================================================
// `P11.25-f` (quatrième passe) — LA PAGE DE `dash_list` À SES DEUX BORDS, L'ÉCRITURE DE « TOUTES LES VUES » JAMAIS
// AVALÉE, `dash_get` QUI NE SERT PLUS L'IDENTIFIANT D'UNE VUE INVISIBLE, ET LES PORTES DES RATTACHEMENTS ALIGNÉES SUR
// CELLE DE `dash_update` QUAND IL ÉCRIT `view_id`.
//
// CE QUE CES TÉMOINS TIENNENT :
//   * `GET /api/dashboards?offset=0` est la première page (200), seul et avec `limit` ; sans `limit`, la liste ENTIÈRE
//     est servie au-delà de la borne d'une page (borne + 1 tableaux, `limit` nul, `total` juste) ;
//   * `dash_update` : l'écriture de `all_views` refusée (ABORT) ou sans effet (IGNORE) rend le 503
//     `CAUSE_TABLEAU_DE_BORD_INCHANGE` au corps entier, et le nom envoyé dans la même demande n'est pas écrit ;
//     contrôle : sans refus, 204 et les deux colonnes écrites ;
//   * `GET /api/dashboard/{id}` : `view_id` nul quand la vue principale est une vue que l'appelant ne voit pas, ou
//     qu'aucune vue ne porte ; chaque membre du périmètre (administrateur, vue commune, vue de l'appelant) a son cas ;
//     par le gestionnaire et par la route au rôle le plus faible (corps entier) ;
//   * `POST /api/views/{id}/dashboards` et `DELETE /api/views/{id}/dashboards/{dashboard_id}` : VOIR la vue (vue semée
//     sans propriétaire comprise) et pouvoir MODIFIER chaque tableau suffisent — un éditeur range son tableau (même
//     privé) dans une vue semée, y range un tableau commun d'un autre compte (`dash_editable` l'ouvre : un tableau
//     commun est modifiable par tout éditeur), l'en retire ; un tableau privé d'autrui dans la même demande : 404
//     inconnu, rien n'est écrit (tout ou rien) ; le retrait d'un tableau privé d'autrui sur une vue dont l'appelant
//     n'est pas propriétaire : réponse d'un rattachement absent, rien n'est retiré, et le propriétaire de la vue n'en a
//     pas davantage (l'oracle fermé par vues_non_visibles_traitees_comme_inconnues.rs reste fermé) ; nom et
//     suppression de la vue restent au propriétaire (403) ; par le routeur réel pour un éditeur sur une vue semée ;
//   * « lisible mais non modifiable » n'existe pas : pour chaque rôle (lecteur, éditeur, administrateur, identité sans
//     nom), chaque propriétaire (l'appelant, un autre compte, aucun) et chaque visibilité, la porte d'écriture
//     `dash_editable` s'ouvre EXACTEMENT quand `panneau_resolu::lisible_par` est vrai. C'est ce qui rend sans objet un
//     403 « lisible mais non modifiable » aux deux routes : si la règle d'écriture diverge un jour, ce témoin rougit.
//
// CE QU'ILS NE TIENNENT PAS : ce que la console peint de ces réponses (aucun volet console ici).
//
// MUTATIONS (`VERIF_MUT=<nom>`, posées sous `cfg!(test)` le temps de la vérification puis retirées) : chaque
// témoin nomme les siennes.
// =====================================================================================
mod portes_des_rattachements_alignees_et_vue_masquee {
    use super::*;

    const BX2_VUE_INCONNUE: &str = "VUE INCONNUE : aucune vue que vous voyez ne porte cet identifiant — rien n'est rattaché ni retiré.";
    const BX2_TABLEAUX_INCONNUS: &str = "TABLEAU DE BORD INCONNU : au moins un identifiant demandé ne désigne aucun tableau de bord que vous voyez — RIEN n'est rattaché, aucun des autres non plus (tout ou rien).";
    const BX2_ABSENT: &str = "RATTACHEMENT ABSENT : ce tableau de bord n'est pas rangé dans cette vue — rien n'est retiré.";
    const BX2_TABLEAU_INCHANGE: &str = "TABLEAU DE BORD INCHANGÉ : la base n'a pas pris l'écriture de la modification ou n'en a écrit aucune ligne, et la transaction est annulée — le nom, la visibilité, la vue et la disposition du tableau de bord sont ceux d'avant (un tableau privé le reste). Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
    /// Un identifiant qu'aucune vue ne porte.
    const BX2_ABSENTE: i64 = 999_999;
    /// Le texte de refus des déclencheurs de témoin : il ne doit jamais sortir dans un corps.
    const BX2_REFUS: &str = "refus de témoin bx2";

    fn bx2_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(&format!("bx2-{tag}"));
        bx2_ecrire(&st, "DELETE FROM panel; DELETE FROM dashboard; DELETE FROM view_dashboard; DELETE FROM view;");
        (st, p)
    }

    fn bx2_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn bx2_entier(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn bx2_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn bx2_vue(st: &AppState, nom: &str, owner: &str, vis: &str) -> i64 {
        let c = st.db.lock();
        c.execute("INSERT INTO view(name,owner,visibility) VALUES(?1,?2,?3)", params![nom, owner, vis]).expect("fixture : vue");
        c.last_insert_rowid()
    }

    fn bx2_tableau(st: &AppState, nom: &str, owner: &str, vis: &str, vue: Option<i64>) -> i64 {
        let c = st.db.lock();
        c.execute(
            "INSERT INTO dashboard(name,created,owner,visibility,view_id,cols,height,collapsed) VALUES(?1,1000,?2,?3,?4,1,0,0)",
            params![nom, owner, vis, vue],
        )
        .expect("fixture : tableau");
        c.last_insert_rowid()
    }

    fn bx2_rattachements(st: &AppState) -> Vec<(i64, i64)> {
        let c = st.db.lock();
        let mut s = c.prepare("SELECT view_id,dashboard_id FROM view_dashboard ORDER BY view_id,dashboard_id").unwrap();
        s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    fn bx2_principale(st: &AppState, tableau: i64) -> Option<i64> {
        st.db.lock().query_row("SELECT view_id FROM dashboard WHERE id=?1", params![tableau], |r| r.get(0)).unwrap()
    }

    async fn bx2_liste(st: &AppState, au: &AuthUser, q: &[(&str, &str)]) -> (u16, Value) {
        let q: HashMap<String, String> = q.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let r = dash_list(State(st.clone()), Extension(au.clone()), Query(q)).await;
        (r.1.as_u16(), r.0)
    }

    fn bx2_ids(v: &Value) -> Vec<i64> {
        v["dashboards"].as_array().unwrap_or_else(|| panic!("une liste est servie : {v}")).iter().map(|d| d["id"].as_i64().unwrap()).collect()
    }

    async fn bx2_ajouter(st: &AppState, au: &AuthUser, vue: i64, ids: &[i64]) -> (u16, Value) {
        pb_json(view_dashboards_add(State(st.clone()), Extension(au.clone()), Path(vue), Json(json!({ "dashboard_ids": ids }))).await).await
    }

    async fn bx2_retirer(st: &AppState, au: &AuthUser, vue: i64, tableau: i64) -> (u16, Value) {
        pb_json(view_dashboard_remove(State(st.clone()), Extension(au.clone()), Path((vue, tableau))).await).await
    }

    async fn bx2_fiche(st: &AppState, au: &AuthUser, tableau: i64) -> (u16, Value) {
        pb_json(dash_get(State(st.clone()), Extension(au.clone()), Path(tableau)).await).await
    }

    /// Le corps JSON d'une réponse brute du routeur, entre la première accolade après les en-têtes et la dernière.
    fn bx2_corps_de(texte: &str) -> Value {
        let corps = texte.split_once("\r\n\r\n").map(|(_, c)| c).unwrap_or("");
        match (corps.find('{'), corps.rfind('}')) {
            (Some(a), Some(b)) if a < b => serde_json::from_str(&corps[a..=b]).unwrap_or_else(|_| json!({ "_texte": texte })),
            _ => json!({ "_texte": texte }),
        }
    }

    // -------------------------------------------------------------------------------------
    // (1) la page de `dash_list` à ses deux bords
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `?offset=0` est admis et sert la première page : seul (liste entière, `offset` 0), et avec
    /// `limit=2` (les deux premiers, `total` 3). MUTATION : `BX2_OFFSET_ZERO_REFUSE` (`n >= 0` -> `n > 0`).
    #[tokio::test]
    async fn bx2_offset_zero_est_la_premiere_page() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = bx2_etat("offset-zero");
        let bob = sp_au("bob", "editor");
        let ids: Vec<i64> = (1..=3).map(|i| bx2_tableau(&st, &format!("O{i}"), "", "shared", None)).collect();
        let (code, v) = bx2_liste(&st, &bob, &[("offset", "0")]).await;
        assert_eq!(code, 200, "offset=0 admis : {v}");
        assert_eq!((bx2_ids(&v), v["total"].clone(), v["limit"].clone(), v["offset"].clone()), (ids.clone(), json!(3), Value::Null, json!(0)));
        let (code, v) = bx2_liste(&st, &bob, &[("limit", "2"), ("offset", "0")]).await;
        assert_eq!(code, 200, "limit=2&offset=0 admis : {v}");
        assert_eq!((bx2_ids(&v), v["total"].clone(), v["limit"].clone(), v["offset"].clone()), (ids[..2].to_vec(), json!(3), json!(2), json!(0)));
    }

    /// CE QU'IL TIENT : sans `limit`, la liste ENTIÈRE est servie au-delà de la borne d'une page : borne + 1 tableaux
    /// semés, tous servis, dans l'ordre, `limit` nul, `total` égal à leur nombre — la console d'avant ne pagine pas, et
    /// une coupe silencieuse à la borne lui ferait perdre des tableaux sans rien dire. MUTATION : `BX2_SANS_LIMITE_COUPE`
    /// (`limite.unwrap_or(-1)` -> `unwrap_or(LIMITE_DE_PAGE_DES_TABLEAUX_DE_BORD)`).
    #[tokio::test]
    async fn bx2_sans_limite_la_liste_entiere_au_dela_de_la_borne() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = bx2_etat("sans-limite");
        let bob = sp_au("bob", "editor");
        let n = LIMITE_DE_PAGE_DES_TABLEAUX_DE_BORD + 1;
        bx2_ecrire(
            &st,
            &format!(
                "WITH RECURSIVE k(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM k WHERE i<{n}) \
                 INSERT INTO dashboard(name,created,owner,visibility,cols,height,collapsed) SELECT 'S'||i,1000,'','shared',1,0,0 FROM k;"
            ),
        );
        let semes: Vec<i64> = {
            let c = st.db.lock();
            let mut s = c.prepare("SELECT id FROM dashboard ORDER BY COALESCE(position,id), id").unwrap();
            s.query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<Vec<i64>>>().unwrap()
        };
        assert_eq!(semes.len() as i64, n, "fixture : borne + 1 tableaux semés");
        let (code, v) = bx2_liste(&st, &bob, &[]).await;
        assert_eq!(code, 200, "{v}");
        assert_eq!((bx2_ids(&v), v["total"].clone(), v["limit"].clone(), v["offset"].clone()), (semes, json!(n), Value::Null, json!(0)), "liste entière");
    }

    // -------------------------------------------------------------------------------------
    // (2) l'écriture de `all_views` dans `dash_update`
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un déclencheur `BEFORE UPDATE OF all_views` en `RAISE(ABORT)` puis en `RAISE(IGNORE)` : 503 au
    /// corps ENTIER (`error` = la phrase, `id` de corrélation, rien d'autre ; ni le texte du déclencheur ni le compte de
    /// lignes), le nom envoyé dans la même demande n'est pas écrit, `all_views` reste à 0, aucune transaction pendante.
    /// Contrôle : sans déclencheur, 204 et les deux colonnes écrites. MUTATION : `BX2_TOUTES_LES_VUES_AVALEE` (le résultat
    /// de `UPDATE dashboard SET all_views` jeté au lieu de passer par `une_seule_ligne(...)?`).
    #[tokio::test]
    async fn bx2_ecriture_de_toutes_les_vues_refusee_jamais_204() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = bx2_etat("toutes-les-vues-refusee");
        let alice = sp_au("alice", "editor");
        let d = bx2_tableau(&st, "avant", "alice", "shared", None);
        let ligne = format!("SELECT name||'|'||all_views FROM dashboard WHERE id={d}");
        let corps = json!({ "name": "après", "all_views": true });
        for (voie, action) in [("abort", format!("SELECT RAISE(ABORT, '{BX2_REFUS}');")), ("ignore", "SELECT RAISE(IGNORE);".to_string())] {
            bx2_ecrire(&st, &format!("CREATE TRIGGER bx2_refus BEFORE UPDATE OF all_views ON dashboard BEGIN {action} END;"));
            let r = dash_update(State(st.clone()), Extension(alice.clone()), Path(d), Json(corps.clone())).await;
            let fermee = st.db.lock().is_autocommit();
            bx2_ecrire(&st, "DROP TRIGGER bx2_refus;");
            let (code, v) = pb_json(r).await;
            assert_eq!(code, 503, "{voie} : {v}");
            assert_eq!(v["error"], json!(BX2_TABLEAU_INCHANGE), "{voie} : phrase exacte : {v}");
            assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{voie} : identifiant de corrélation : {v}");
            assert_eq!(v.as_object().map(|o| o.len()), Some(2), "{voie} : ni plus ni moins que `error` et `id` : {v}");
            assert!(!v.to_string().contains(BX2_REFUS) && !v.to_string().contains("ligne(s)"), "{voie} : ni texte du moteur ni compte : {v}");
            assert_eq!(bx2_texte(&st, &ligne), "avant|0", "{voie} : le nom n'est pas écrit, all_views reste à 0");
            assert!(fermee, "{voie} : aucune transaction pendante");
        }
        let r = dash_update(State(st.clone()), Extension(alice.clone()), Path(d), Json(corps)).await;
        assert_eq!(pb_json(r).await.0, 204, "contrôle : sans refus, la modification passe");
        assert_eq!(bx2_texte(&st, &ligne), "après|1", "contrôle : les deux colonnes écrites");
    }

    // -------------------------------------------------------------------------------------
    // (3) `dash_get` : la vue principale invisible n'est pas servie
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : cinq tableaux communs, vue principale = vue privée de bob (PB), vue commune de bob (SB), vue
    /// privée d'alice (PA), aucune, un identifiant qu'aucune vue ne porte. `dash_get` sert `view_id` : pour alice nul,
    /// SB, PA, nul, nul ; pour bob PB, SB, nul, nul, nul ; pour l'administrateur PB, SB, PA, nul, nul. MUTATIONS :
    /// `BX2_GET_VIEW_ID_BRUT` (la forme d'avant), `BX2_GET_SANS_ADMIN`, `BX2_GET_SANS_COMMUNE`, `BX2_GET_SANS_PROPRIO`.
    #[tokio::test]
    async fn bx2_fiche_view_id_d_une_vue_invisible_est_nul() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = bx2_etat("fiche-view-id");
        let pb = bx2_vue(&st, "privée de bob", "bob", "private");
        let sb = bx2_vue(&st, "commune de bob", "bob", "shared");
        let pa = bx2_vue(&st, "privée d'alice", "alice", "private");
        let tableaux = [
            bx2_tableau(&st, "Dpb", "", "shared", Some(pb)),
            bx2_tableau(&st, "Dsb", "", "shared", Some(sb)),
            bx2_tableau(&st, "Dpa", "", "shared", Some(pa)),
            bx2_tableau(&st, "Dn", "", "shared", None),
            bx2_tableau(&st, "Dx", "", "shared", Some(BX2_ABSENTE)),
        ];
        let n = Value::Null;
        let attendus = [
            (sp_au("alice", "editor"), vec![n.clone(), json!(sb), json!(pa), n.clone(), n.clone()]),
            (sp_au("bob", "editor"), vec![json!(pb), json!(sb), n.clone(), n.clone(), n.clone()]),
            (sp_au("adm", "admin"), vec![json!(pb), json!(sb), json!(pa), n.clone(), n.clone()]),
        ];
        for (au, attendu) in attendus {
            let mut servis = Vec::new();
            for d in tableaux {
                let (code, v) = bx2_fiche(&st, &au, d).await;
                assert_eq!(code, 200, "{} #{d} : {v}", au.name);
                servis.push(v["view_id"].clone());
            }
            assert_eq!(servis, attendu, "{}", au.name);
        }
    }

    /// CE QU'IL TIENT : par le ROUTEUR réel, au rôle le plus faible admis (lecteur), la fiche d'un tableau commun dont la
    /// vue principale est la vue privée d'un autre compte : corps ENTIER, `view_id` nul. MUTATION : `BX2_GET_VIEW_ID_BRUT`.
    #[tokio::test]
    async fn bx2_fiche_par_la_route_une_vue_invisible_n_est_pas_servie() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = router_test_state("bx2-fiche-route");
        let d = {
            let c = st.db.lock();
            c.execute("INSERT INTO view(name,owner,visibility) VALUES('Privée d''autrui','autre','private')", []).unwrap();
            let privee = c.last_insert_rowid();
            c.execute("INSERT INTO dashboard(name,created,owner,visibility,view_id,cols,height,collapsed) VALUES('Commun',1000,'','shared',?1,1,0,0)", params![privee]).unwrap();
            c.last_insert_rowid()
        };
        let addr = router_serve(st.clone()).await;
        let (code, texte) = router_probe_envoi(addr, "GET", &format!("/api/dashboard/{d}"), Some(&viewer_authz()), &[], "").await;
        assert_eq!(code, 200, "{texte}");
        assert_eq!(
            bx2_corps_de(&texte),
            json!({ "id": d, "name": "Commun", "owner": "", "visibility": "shared", "view_id": null, "editable": true, "panels": [] }),
            "corps entier"
        );
    }

    // -------------------------------------------------------------------------------------
    // (4) portes des rattachements : voir la vue, modifier chaque tableau
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, pour bob (éditeur), propriétaire d'aucune vue :
    ///   * vue SEMÉE (sans propriétaire) : il y range son tableau PRIVÉ (200, `added`) et le tableau COMMUN d'alice
    ///     (200 : `dash_editable` ouvre un tableau commun à tout éditeur), puis retire son tableau (204) ;
    ///   * vue COMMUNE d'alice : une demande [commun, privé d'alice] -> 404 inconnu qui nomme le privé, le commun n'est pas
    ///     rattaché (tout ou rien) ; le retrait du privé d'alice qu'elle y a rangé -> réponse d'un rattachement absent,
    ///     rien n'est retiré, sa vue principale reste ;
    ///   * vue PRIVÉE d'alice : 404 vue inconnue aux deux routes ;
    ///   * renommer ou supprimer la vue commune d'alice : 403, la vue reste telle quelle.
    /// Et alice, PROPRIÉTAIRE de sa vue commune, n'y retire pas le tableau privé de bob qui y est rangé : réponse d'un
    /// rattachement absent, rien n'est retiré. Contrôle : elle y retire son propre tableau privé (204).
    /// MUTATIONS : `BX2_PORTE_PROPRIETAIRE` (la porte d'avant : propriétaire de la vue exigé), `BX2_PORTE_SANS_VISIBILITE`,
    /// `BX2_AJOUT_SANS_DROIT_DU_TABLEAU`, `BX2_RETRAIT_SANS_DROIT_DU_TABLEAU`, `BX2_RETRAIT_PROPRIETAIRE_DE_LA_VUE` (le
    /// propriétaire de la vue retire un tableau qu'il ne peut pas modifier).
    #[tokio::test]
    async fn bx2_voir_la_vue_et_modifier_chaque_tableau_suffisent() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = bx2_etat("portes-alignees");
        let (alice, bob) = (sp_au("alice", "editor"), sp_au("bob", "editor"));
        let semee = bx2_vue(&st, "semée", "", "shared");
        let sa = bx2_vue(&st, "commune d'alice", "alice", "shared");
        let pa = bx2_vue(&st, "privée d'alice", "alice", "private");
        let prive_bob = bx2_tableau(&st, "privé de bob", "bob", "private", None);
        let commun_alice = bx2_tableau(&st, "commun d'alice", "alice", "shared", None);
        let commun = bx2_tableau(&st, "commun", "", "shared", None);
        let prive_alice = bx2_tableau(&st, "privé d'alice", "alice", "private", Some(sa));
        let prive_bob_chez_alice = bx2_tableau(&st, "privé de bob chez alice", "bob", "private", Some(sa));
        let avant = vec![(sa, prive_alice), (sa, prive_bob_chez_alice)];
        assert_eq!(bx2_rattachements(&st), avant, "fixture : deux tableaux privés rangés dans la vue commune d'alice");
        // vue semée
        assert_eq!(bx2_ajouter(&st, &bob, semee, &[prive_bob]).await, (200, json!({ "added": [prive_bob], "already_present": [] })), "son tableau privé");
        assert_eq!(bx2_ajouter(&st, &bob, semee, &[commun_alice]).await, (200, json!({ "added": [commun_alice], "already_present": [] })), "le commun d'alice");
        assert_eq!(bx2_retirer(&st, &bob, semee, prive_bob).await.0, 204, "il retire son tableau");
        assert_eq!(bx2_rattachements(&st), vec![(semee, commun_alice), (sa, prive_alice), (sa, prive_bob_chez_alice)]);
        // vue commune d'alice
        assert_eq!(
            bx2_ajouter(&st, &bob, sa, &[commun, prive_alice]).await,
            (404, json!({ "error": BX2_TABLEAUX_INCONNUS, "dashboard_ids": [prive_alice] })),
            "le privé d'alice : inconnu"
        );
        assert_eq!(bx2_retirer(&st, &bob, sa, prive_alice).await, (404, json!({ "error": BX2_ABSENT })), "le privé d'alice : absent pour bob");
        assert_eq!(bx2_rattachements(&st), vec![(semee, commun_alice), (sa, prive_alice), (sa, prive_bob_chez_alice)], "rien n'est écrit ni retiré");
        assert_eq!(bx2_principale(&st, prive_alice), Some(sa), "la vue principale du privé d'alice reste");
        // vue privée d'alice
        let inconnue = (404, json!({ "error": BX2_VUE_INCONNUE }));
        assert_eq!(bx2_ajouter(&st, &bob, pa, &[commun]).await, inconnue, "POST, vue privée d'alice");
        assert_eq!(bx2_retirer(&st, &bob, pa, commun).await, inconnue, "DELETE, vue privée d'alice");
        // nom et suppression restent au propriétaire
        let r = view_update(State(st.clone()), Extension(bob.clone()), Path(sa), Json(json!({ "name": "renommée par bob" }))).await;
        assert_eq!(r.status().as_u16(), 403, "renommer reste au propriétaire");
        let r = view_delete(State(st.clone()), Extension(bob.clone()), Path(sa)).await;
        assert_eq!(r.status().as_u16(), 403, "supprimer reste au propriétaire");
        assert_eq!(bx2_texte(&st, &format!("SELECT name FROM view WHERE id={sa}")), "commune d'alice", "la vue reste telle quelle");
        // le propriétaire de la vue n'a pas davantage
        assert_eq!(bx2_retirer(&st, &alice, sa, prive_bob_chez_alice).await, (404, json!({ "error": BX2_ABSENT })), "le privé de bob : absent pour alice");
        assert_eq!(bx2_principale(&st, prive_bob_chez_alice), Some(sa), "la vue principale du privé de bob reste");
        assert_eq!(bx2_retirer(&st, &alice, sa, prive_alice).await.0, 204, "contrôle : alice retire son tableau privé");
        assert_eq!(bx2_rattachements(&st), vec![(semee, commun_alice), (sa, prive_bob_chez_alice)]);
    }

    /// CE QU'IL TIENT : par le ROUTEUR réel (authentification, porte de rôle, gestionnaire), un éditeur qui n'est
    /// propriétaire d'aucune vue range un tableau commun dans une vue SEMÉE (200, corps entier) puis l'en retire (204).
    /// MUTATION : `BX2_PORTE_PROPRIETAIRE`.
    #[tokio::test]
    async fn bx2_par_la_route_un_editeur_complete_une_vue_semee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = router_test_state("bx2-route-semee");
        let (semee, d) = {
            let c = st.db.lock();
            c.execute("INSERT INTO user(name,hash,role) VALUES('edt',?1,'editor')", params![hash_pw("editorpw12345").unwrap()]).unwrap();
            c.execute("INSERT INTO view(name,owner,visibility) VALUES('Semée bx2','','shared')", []).unwrap();
            let semee = c.last_insert_rowid();
            c.execute("INSERT INTO dashboard(name,created,owner,visibility,cols,height,collapsed) VALUES('Commun bx2',1000,'','shared',1,0,0)", []).unwrap();
            (semee, c.last_insert_rowid())
        };
        let addr = router_serve(st.clone()).await;
        let editeur = format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "edt:editorpw12345"));
        let en_json = [("Content-Type", "application/json")];
        let present = || bx2_entier(&st, &format!("SELECT COUNT(*) FROM view_dashboard WHERE view_id={semee} AND dashboard_id={d}"));
        let (code, texte) = router_probe_envoi(addr, "POST", &format!("/api/views/{semee}/dashboards"), Some(&editeur), &en_json, &format!("{{\"dashboard_ids\":[{d}]}}")).await;
        assert_eq!((code, bx2_corps_de(&texte)), (200, json!({ "added": [d], "already_present": [] })), "{texte}");
        assert_eq!(present(), 1, "rattaché par la route");
        let (code, texte) = router_probe_envoi(addr, "DELETE", &format!("/api/views/{semee}/dashboards/{d}"), Some(&editeur), &[], "").await;
        assert_eq!(code, 204, "{texte}");
        assert_eq!(present(), 0, "retiré par la route");
    }

    /// CE QU'IL TIENT : « lisible mais non modifiable » n'existe pas. Pour chaque appelant (lecteur, éditeur,
    /// administrateur, identité sans nom), chaque propriétaire (l'appelant, un autre compte, aucun) et chaque visibilité,
    /// `dash_editable` s'ouvre exactement quand `panneau_resolu::lisible_par` est vrai — la règle par laquelle les deux
    /// routes de rattachement jugent chaque tableau. Les deux verdicts sont atteints (sinon l'égalité serait vide).
    /// MUTATION : `BX2_EDITION_DIVERGE` (`dash_editable` réservé au propriétaire : un tableau commun d'autrui devient
    /// lisible et non modifiable).
    #[tokio::test]
    async fn bx2_un_tableau_lisible_est_un_tableau_modifiable() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = bx2_etat("lisible-modifiable");
        let appelants = [sp_au("vwr", "viewer"), sp_au("alice", "editor"), sp_au("adm", "admin"), sp_au("", "editor")];
        let mut ecarts: Vec<String> = Vec::new();
        let (mut ouvertes, mut fermees) = (0usize, 0usize);
        for au in &appelants {
            for owner in [au.name.as_str(), "bob", ""] {
                for vis in ["shared", "private"] {
                    let d = bx2_tableau(&st, "L", owner, vis, None);
                    let ouverte = matches!(dash_editable(&st.db.lock(), au, d), PorteDuTableau::Ouverte);
                    let lisible = panneau_resolu::lisible_par(owner, vis, au);
                    if ouverte {
                        ouvertes += 1;
                    } else {
                        fermees += 1;
                    }
                    if ouverte != lisible {
                        ecarts.push(format!("appelant `{}` ({}), propriétaire `{owner}`, {vis} : modifiable {ouverte}, lisible {lisible}", au.name, au.role));
                    }
                }
            }
        }
        assert!(ouvertes > 0 && fermees > 0, "les deux verdicts sont atteints : {ouvertes} ouverte(s), {fermees} fermée(s)");
        assert!(ecarts.is_empty(), "un tableau lisible et non modifiable (ou l'inverse) : {ecarts:#?}");
    }
}

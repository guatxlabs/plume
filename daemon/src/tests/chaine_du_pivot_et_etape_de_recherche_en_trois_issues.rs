// =====================================================================================
// `P10.20-l` (reste de la vague AO) — LA CHAÎNE D'UN PIVOT ET L'ÉTAPE D'UNE RECHERCHE SE LISENT EN TROIS ISSUES.
//
// VU (re-mesuré au commit de départ `ac1f43b8`) : deux lectures d'une ligne écrites
// `.query_row(..).map_err(|_| "<phrase d'absence>")?`, la forme que `garde_82` ne voyait pas.
// (a) `object_constraint_chain` (`handlers/datamodels.rs`) : un maillon de la chaîne de contraintes (l'objet de départ
//     ou un parent) qui ne se lisait pas rendait « objet introuvable ou désactivé », servi 400 par
//     `pivot_soql_from_body` — `POST /api/pivot/compile`, `POST /api/pivot/run` (lecteur) et la création d'un jeu de
//     données `pivot` (éditeur) : un défaut du CORPS reçu, pour une lecture qui n'avait pas eu lieu.
// (b) `resolve_step_search` (`handlers/incidents.rs`) : une étape illisible rendait « étape introuvable », servi 400 par
//     `GET /api/cases/{id}/steps/{step_id}/search` (lecteur).
//
// LE CORRECTIF : `.optional()` aux deux sites ; absent (ou désactivé, ou étape d'un autre dossier) = le 400 d'avant à
// l'octet ; lecture ratée = 503 nommé à phrase fixe (`CAUSE_OBJET_DU_PIVOT_NON_LU`,
// `CAUSE_RECHERCHE_DE_L_ETAPE_NON_RESOLUE_NON_LUE`), la cause du moteur au journal seul (ligne `WARN` du module).
//
// PAR LA ROUTE : routeur réel (`build_router`), jeton `viewer` (rôle le plus faible admis des trois routes de lecture),
// `editor` pour la création d'un jeu de données ; chaque lecture rendue illisible SEULE (une valeur BLOB sur SA ligne :
// les autres lignes de la même table se lisent) ; corps comparés À L'OCTET (l'identifiant de corrélation relu puis
// re-sérialisé, ensemble exact des clés). Les lignes de journal sont lues sur le stderr d'un sous-processus et comparées
// EN ENTIER, la cause du moteur RE-PRODUITE sur la même base.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit), chacun vu ROUGE : `AP2_CHAINE_EN_400` (la forme
// d'avant), `AP2_CHAINE_PARENT_EN_400` (seul le maillon parent garde la forme d'avant), `AP2_CHAINE_ABSENT_EN_503`,
// `AP2_CHAINE_MOTEUR_SERVI`, `AP2_CHAINE_SANS_JOURNAL` ; `AP2_ETAPE_EN_400` (la forme d'avant),
// `AP2_ETAPE_ABSENT_EN_503`, `AP2_ETAPE_MOTEUR_SERVI`, `AP2_ETAPE_SANS_JOURNAL` ; la borne de profondeur de la chaîne
// (relevée par la vérification : réécrite avec son code, sans témoin) : `AP2_BORNE_EN_503`, `AP2_BORNE_A_17`,
// `AP2_BORNE_A_15`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ce que la console peint (lu, non joué : la vue du Pivot reconnaît une lecture
// non faite par `OUVERTURE_DU_REFUS_D_ALLOWLIST_NON_LUE`, `web/datamodels.js`, dont la phrase neuve porte les mots —
// tenu par `ap2_la_phrase_du_pivot_non_lu_porte_les_mots_que_la_vue_reconnait` ; la recherche d'une étape passe par
// `phraseDuRefusDUneLecture`, `web/core.js`) ; la ligne `[datamodels]` ne porte pas l'identifiant de corrélation (il
// naît chez l'appelant, `err_json`) — sa trace `HTTP 503` est jugée à côté ; une lecture ratée par verrou ou table
// retirée (la valeur BLOB atteint chaque bras) ; le mode multi-tenant (`req_db`/`req_conn!` choisissent la base avant).
// =====================================================================================
mod chaine_du_pivot_et_etape_de_recherche_en_trois_issues {
    use super::*;
    use crate::handlers::datamodels::CAUSE_OBJET_DU_PIVOT_NON_LU;
    use crate::handlers::incidents::CAUSE_RECHERCHE_DE_L_ETAPE_NON_RESOLUE_NON_LUE;

    const AP2_MDP_EDITEUR: &str = "editeurap2pw12345";
    const AP2_ABSENT: i64 = 987_654;
    // La hiérarchie du modèle : racine -> enfant (valide, deux niveaux) ; un enfant sous un parent DÉSACTIVÉ ; un enfant
    // sous un parent ILLISIBLE ; un objet de départ ILLISIBLE.
    const AP2_RACINE: i64 = 10;
    const AP2_ENFANT: i64 = 11;
    const AP2_SOUS_ETEINT: i64 = 12;
    const AP2_PARENT_ETEINT: i64 = 13;
    const AP2_SOUS_ILLISIBLE: i64 = 14;
    const AP2_PARENT_ILLISIBLE: i64 = 15;
    const AP2_DEPART_ILLISIBLE: i64 = 16;
    const AP2_ABSENT_400: &str = r#"{"error":"objet introuvable ou désactivé"}"#;
    const AP2_ETAPE_ABSENTE_400: &str = r#"{"error":"étape introuvable"}"#;
    const AP2_GABARIT: &str = "search src_ip=$target$ | stats count by source";

    fn ap2_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ap2_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn ap2_editeur() -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("edt:{AP2_MDP_EDITEUR}")))
    }

    /// Le routeur réel sur une base neuve : `vwr` (viewer, posé par la fabrique) et `edt` (editor).
    fn ap2_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = router_test_state(tag);
        st.db
            .lock()
            .execute("INSERT INTO user(name,hash,role) VALUES('edt',?1,'editor')", params![hash_pw(AP2_MDP_EDITEUR).unwrap()])
            .expect("fixture : editor posé");
        (st, p)
    }

    /// Le modèle et sa hiérarchie ; chaque objet porte le champ `host`. Les deux lignes illisibles ne le sont que par
    /// leur `constraint_soql` (BLOB) : toutes les autres lignes de la table se lisent.
    fn ap2_modele(st: &AppState) {
        ap2_sql(
            st,
            &format!(
                "INSERT INTO data_model(id,name,title) VALUES(1,'ap2','AP2'); \
                 INSERT INTO data_model_object(id,model_id,name,parent_id,constraint_soql,enabled) VALUES \
                   ({AP2_RACINE},1,'racine',NULL,'category=auth',1), ({AP2_ENFANT},1,'enfant',{AP2_RACINE},'source=ssh',1), \
                   ({AP2_PARENT_ETEINT},1,'parent_eteint',NULL,'category=web',0), \
                   ({AP2_SOUS_ETEINT},1,'sous_eteint',{AP2_PARENT_ETEINT},'source=nginx',1), \
                   ({AP2_PARENT_ILLISIBLE},1,'parent_illisible',NULL,X'00',1), \
                   ({AP2_SOUS_ILLISIBLE},1,'sous_illisible',{AP2_PARENT_ILLISIBLE},'source=nginx',1), \
                   ({AP2_DEPART_ILLISIBLE},1,'depart_illisible',NULL,X'00',1); \
                 INSERT INTO data_model_field(object_id,name,ftype,expr) VALUES \
                   ({AP2_ENFANT},'host','string',''), ({AP2_SOUS_ETEINT},'host','string',''), \
                   ({AP2_SOUS_ILLISIBLE},'host','string',''), ({AP2_DEPART_ILLISIBLE},'host','string','');"
            ),
        );
        assert_eq!(
            ap2_compte(st, "SELECT COUNT(*) FROM data_model_object WHERE typeof(constraint_soql)='blob'"),
            2,
            "fixture : deux lignes illisibles, et elles seules"
        );
    }

    fn ap2_corps_pivot(oid: i64) -> String {
        json!({ "object_id": oid, "splitby": ["host"], "stats": [{ "func": "count" }] }).to_string()
    }

    /// Statut, corps servi (un corps découpé en morceaux est recollé : ce sont ses octets), corps lu.
    async fn ap2_appel(addr: std::net::SocketAddr, methode: &str, chemin: &str, qui: &str, corps: &str) -> (u16, String, Value) {
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

    /// Un 503 À L'OCTET : `{error: phrase, id: <corrélation>}` — ensemble exact des clés, re-sérialisé depuis
    /// l'identifiant relu, aucun texte du moteur.
    fn ap2_juger_503(quoi: &str, (statut, corps, v): &(u16, String, Value), phrase: &str) {
        assert_eq!(*statut, 503, "{quoi} : {corps}");
        let mut cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        cles.sort_unstable();
        assert_eq!(cles, ["error", "id"], "{quoi} : ensemble exact des clés : {corps}");
        let id = v["id"].as_str().unwrap_or_else(|| panic!("{quoi} : identifiant de corrélation : {corps}"));
        assert!(id.starts_with("plume-e"), "{quoi} : identifiant de corrélation : {corps}");
        assert_eq!(corps, &serde_json::to_string(&json!({ "error": phrase, "id": id })).unwrap(), "{quoi} : corps à l'octet");
        assert!(!corps.contains("Invalid column type") && !corps.contains("Blob"), "{quoi} : aucun texte du moteur : {corps}");
    }

    /// CE QU'IL TIENT (`POST /api/pivot/compile` et `POST /api/pivot/run`, jeton viewer) — trois issues par route :
    /// hiérarchie valide à DEUX niveaux, `200` et le GXQL porte la contrainte du parent PUIS celle de l'enfant (compile) ;
    /// objet absent ET parent désactivé, le `400` d'avant À L'OCTET ; objet de départ illisible ET parent illisible
    /// (chaîne à deux niveaux), `503` `CAUSE_OBJET_DU_PIVOT_NON_LU` à l'octet.
    /// MUTATIONS : AP2_CHAINE_EN_400 et AP2_CHAINE_PARENT_EN_400 (les 503 tombent), AP2_CHAINE_ABSENT_EN_503 (les 400
    /// tombent), AP2_CHAINE_MOTEUR_SERVI (le corps tombe).
    #[tokio::test]
    async fn ap2_chaine_du_pivot_en_trois_issues_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = ap2_etat("ap2-pivot");
        ap2_modele(&st);
        let addr = router_serve(st.clone()).await;
        let vwr = viewer_authz();
        for route in ["/api/pivot/compile", "/api/pivot/run"] {
            let r = ap2_appel(addr, "POST", route, &vwr, &ap2_corps_pivot(AP2_ENFANT)).await;
            assert_eq!(r.0, 200, "{route} : contrôle positif, hiérarchie valide à deux niveaux : {}", r.1);
            if route.ends_with("compile") {
                let soql = r.2["soql"].as_str().unwrap_or_else(|| panic!("{route} : GXQL servi : {}", r.1));
                let (parent, enfant) = (soql.find("category=auth"), soql.find("source=ssh"));
                assert!(parent.is_some() && enfant.is_some() && parent < enfant, "{route} : la racine, puis l'enfant : {soql}");
                assert!(soql.contains("by host"), "{route} : {soql}");
            }
            for (quoi, oid) in [("objet absent", AP2_ABSENT), ("parent désactivé", AP2_SOUS_ETEINT)] {
                let r = ap2_appel(addr, "POST", route, &vwr, &ap2_corps_pivot(oid)).await;
                assert_eq!((r.0, r.1.as_str()), (400, AP2_ABSENT_400), "{route} : {quoi} : le 400 d'avant, à l'octet");
            }
            for (quoi, oid) in [("objet de départ illisible", AP2_DEPART_ILLISIBLE), ("parent illisible", AP2_SOUS_ILLISIBLE)] {
                let r = ap2_appel(addr, "POST", route, &vwr, &ap2_corps_pivot(oid)).await;
                ap2_juger_503(&format!("{route} : {quoi}"), &r, CAUSE_OBJET_DU_PIVOT_NON_LU);
            }
        }
    }

    /// CE QU'IL TIENT (`POST /api/datasets` de genre `pivot`, jeton editor — le troisième appelant hérite sans édition) :
    /// parent illisible, `503` à l'octet et AUCUN jeu de données écrit ; parent désactivé, le `400` d'avant à l'octet,
    /// rien d'écrit ; contrôle, la hiérarchie valide s'enregistre (`200`, une ligne).
    /// MUTATIONS : AP2_CHAINE_PARENT_EN_400, AP2_CHAINE_ABSENT_EN_503.
    #[tokio::test]
    async fn ap2_creation_d_un_jeu_de_donnees_pivot_herite_des_trois_issues() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = ap2_etat("ap2-jeu");
        ap2_modele(&st);
        let addr = router_serve(st.clone()).await;
        let edt = ap2_editeur();
        let corps = |oid: i64| json!({ "kind": "pivot", "name": "ap2_jeu", "object_id": oid, "splitby": ["host"], "stats": [{ "func": "count" }] }).to_string();
        let r = ap2_appel(addr, "POST", "/api/datasets", &edt, &corps(AP2_SOUS_ILLISIBLE)).await;
        ap2_juger_503("jeu de données, parent illisible", &r, CAUSE_OBJET_DU_PIVOT_NON_LU);
        assert_eq!(ap2_compte(&st, "SELECT COUNT(*) FROM dataset"), 0, "parent illisible : rien n'est enregistré");
        let r = ap2_appel(addr, "POST", "/api/datasets", &edt, &corps(AP2_SOUS_ETEINT)).await;
        assert_eq!((r.0, r.1.as_str()), (400, AP2_ABSENT_400), "jeu de données, parent désactivé : le 400 d'avant");
        assert_eq!(ap2_compte(&st, "SELECT COUNT(*) FROM dataset"), 0, "parent désactivé : rien n'est enregistré");
        let r = ap2_appel(addr, "POST", "/api/datasets", &edt, &corps(AP2_ENFANT)).await;
        assert_eq!(r.0, 200, "contrôle : la hiérarchie valide s'enregistre : {}", r.1);
        assert_eq!(ap2_compte(&st, "SELECT COUNT(*) FROM dataset"), 1, "contrôle : une ligne");
    }

    /// LA BORNE DE PROFONDEUR DE LA CHAÎNE (`guard > 16`, réécrite par ce lot avec son code, `400`, dans le tuple) —
    /// atteignable PAR L'API : `object_create` ne vérifie que l'existence du parent (même modèle), aucune route ne
    /// modifie `parent_id`, donc une hiérarchie valide de dix-huit niveaux se crée par dix-huit `POST` au rôle editor.
    /// CE QU'IL TIENT (`POST /api/pivot/compile` et `POST /api/pivot/run`, jeton viewer) : la feuille de profondeur
    /// DIX-SEPT (dernier maillon admis) compile, `200`, et le GXQL porte les dix-sept contraintes de la racine à la
    /// feuille ; la feuille de profondeur DIX-HUIT, le `400` de la borne À L'OCTET ; une ligne qui se désigne elle-même
    /// comme parent (seule voie d'un cycle : posée en SQL, aucune route ne l'écrit), le même `400` à l'octet.
    /// MUTATIONS : AP2_BORNE_EN_503 (le code de la borne, 400 → 503 : les deux 400 tombent), AP2_BORNE_A_17 (cap
    /// décalé d'un cran : la profondeur dix-huit compile), AP2_BORNE_A_15 (la profondeur dix-sept est refusée).
    #[tokio::test]
    async fn ap2_borne_de_profondeur_de_la_chaine_par_la_route() {
        const BORNE_400: &str = r#"{"error":"hiérarchie d'objets trop profonde (cycle ?)"}"#;
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = ap2_etat("ap2-borne");
        ap2_sql(&st, "INSERT INTO data_model(id,name,title) VALUES(1,'ap2b','AP2B');");
        let addr = router_serve(st.clone()).await;
        let edt = ap2_editeur();
        let mut ids: Vec<i64> = Vec::new();
        for niveau in 1..=18 {
            let mut corps = json!({ "name": format!("niveau{niveau}"), "constraint": format!("source=n{niveau}") });
            if let Some(parent) = ids.last() {
                corps["parent_id"] = json!(parent);
            }
            let r = ap2_appel(addr, "POST", "/api/datamodels/1/objects", &edt, &corps.to_string()).await;
            assert_eq!(r.0, 200, "fixture par la route : niveau {niveau} créé : {}", r.1);
            ids.push(r.2["id"].as_i64().unwrap_or_else(|| panic!("fixture : identifiant du niveau {niveau} : {}", r.1)));
        }
        assert_eq!(
            ap2_compte(&st, "SELECT COUNT(*) FROM data_model_object WHERE parent_id IS NOT NULL"),
            17,
            "fixture : dix-sept liens de parenté, une seule racine"
        );
        let corps = |oid: i64| json!({ "object_id": oid, "stats": [{ "func": "count" }] }).to_string();
        let vwr = viewer_authz();
        let attendu_17 = format!("search {}", (1..=17).map(|n| format!("source=n{n}")).collect::<Vec<_>>().join(" "));
        for route in ["/api/pivot/compile", "/api/pivot/run"] {
            let r = ap2_appel(addr, "POST", route, &vwr, &corps(ids[16])).await;
            assert_eq!(r.0, 200, "{route} : profondeur dix-sept, dernier maillon admis : {}", r.1);
            if route.ends_with("compile") {
                let soql = r.2["soql"].as_str().unwrap_or_else(|| panic!("{route} : GXQL servi : {}", r.1));
                assert!(soql.starts_with(&format!("{attendu_17} ")), "{route} : dix-sept contraintes, racine d'abord : {soql}");
                assert!(!soql.contains("source=n18"), "{route} : {soql}");
            }
            let r = ap2_appel(addr, "POST", route, &vwr, &corps(ids[17])).await;
            assert_eq!((r.0, r.1.as_str()), (400, BORNE_400), "{route} : profondeur dix-huit, le 400 de la borne à l'octet");
        }
        ap2_sql(&st, &format!("UPDATE data_model_object SET parent_id=id WHERE id={}", ids[0]));
        for route in ["/api/pivot/compile", "/api/pivot/run"] {
            let r = ap2_appel(addr, "POST", route, &vwr, &corps(ids[0])).await;
            assert_eq!((r.0, r.1.as_str()), (400, BORNE_400), "{route} : ligne parente d'elle-même, le 400 de la borne à l'octet");
        }
    }

    /// LA PHRASE DU PIVOT NON LU ET LA VUE QUI LA LIT : `web/datamodels.js` ne reconnaît une lecture non faite que par
    /// `OUVERTURE_DU_REFUS_D_ALLOWLIST_NON_LUE` (sinon : « le démon refuse le corps reçu ») ; la phrase neuve en porte
    /// les mots, et n'accuse pas la déclaration de l'exploitant.
    #[test]
    fn ap2_la_phrase_du_pivot_non_lu_porte_les_mots_que_la_vue_reconnait() {
        let vue = include_str!("../../../web/datamodels.js");
        assert!(
            vue.contains("const OUVERTURE_DU_REFUS_D_ALLOWLIST_NON_LUE = /champs déclarés de l'objet NON LUS/;"),
            "la vue du Pivot a changé de discriminant : la phrase de `CAUSE_OBJET_DU_PIVOT_NON_LU` est à relire contre elle"
        );
        assert!(CAUSE_OBJET_DU_PIVOT_NON_LU.contains("champs déclarés de l'objet NON LUS"), "{CAUSE_OBJET_DU_PIVOT_NON_LU}");
        assert!(!CAUSE_OBJET_DU_PIVOT_NON_LU.contains("non déclaré dans l'objet"), "{CAUSE_OBJET_DU_PIVOT_NON_LU}");
    }

    /// Un dossier porteur de trois étapes (recherche lisible, réponse, recherche ILLISIBLE par son `step_kind` BLOB), et
    /// un second dossier : `(dossier, recherche, reponse, illisible, autre_dossier)`.
    fn ap2_dossier_et_etapes(st: &AppState) -> (i64, i64, i64, i64, i64) {
        let conn = st.db.lock();
        let cid = dossier_seme(&conn, "alice", "ap2", 3, "", None, 2);
        let autre = dossier_seme(&conn, "alice", "ap2-autre", 3, "", None, 2);
        let etape = |kind: &str, soql: Option<&str>, target: Option<&str>| -> i64 {
            conn.execute(
                &format!(
                    "INSERT INTO case_step(incident_id,runbook_id,step_id,ordinal,phase,title,step_kind,search_soql,action_kind,target) \
                     VALUES(?1,1,1,1,'triage','t',{kind},?2,'ban_ip',?3)"
                ),
                params![cid, soql, target],
            )
            .expect("fixture : étape posée");
            conn.last_insert_rowid()
        };
        let recherche = etape("'search'", Some(AP2_GABARIT), Some("203.0.113.7"));
        let reponse = etape("'response'", None, Some("203.0.113.7"));
        let illisible = etape("X'00'", Some(AP2_GABARIT), Some("203.0.113.7"));
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM case_step WHERE typeof(step_kind)='blob'", [], |r| r.get::<_, i64>(0)).expect("fixture"),
            1,
            "fixture : une étape illisible, et elle seule"
        );
        (cid, recherche, reponse, illisible, autre)
    }

    fn ap2_chemin_etape(cid: i64, sid: i64) -> String {
        format!("/api/cases/{cid}/steps/{sid}/search")
    }

    /// CE QU'IL TIENT (`GET /api/cases/{id}/steps/{step_id}/search`, jeton viewer) — étape lue, `200` à l'octet (cible
    /// pré-remplie, puis valeur fournie) ; étape absente ET étape d'un AUTRE dossier, le `400` d'avant à l'octet ; étape
    /// d'un autre genre, son `400` d'avant (le refus du gabarit reste un défaut de la demande) ; étape illisible, `503`
    /// `CAUSE_RECHERCHE_DE_L_ETAPE_NON_RESOLUE_NON_LUE` à l'octet. Pas d'oracle : l'étape illisible demandée sous un
    /// autre dossier rend le même 400 qu'une étape absente.
    /// MUTATIONS : AP2_ETAPE_EN_400 (le 503 tombe), AP2_ETAPE_ABSENT_EN_503 (les 400 tombent), AP2_ETAPE_MOTEUR_SERVI.
    #[tokio::test]
    async fn ap2_etape_de_recherche_en_trois_issues_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = ap2_etat("ap2-etape");
        let (cid, recherche, reponse, illisible, autre) = ap2_dossier_et_etapes(&st);
        let addr = router_serve(st.clone()).await;
        let vwr = viewer_authz();
        let r = ap2_appel(addr, "GET", &ap2_chemin_etape(cid, recherche), &vwr, "").await;
        let attendu = serde_json::to_string(&json!({ "kind": "search", "soql": "search src_ip=203.0.113.7 | stats count by source" })).unwrap();
        assert_eq!((r.0, r.1.as_str()), (200, attendu.as_str()), "étape lue : le GXQL de la cible pré-remplie");
        let r = ap2_appel(addr, "GET", &format!("{}?value=198.51.100.4", ap2_chemin_etape(cid, recherche)), &vwr, "").await;
        let attendu = serde_json::to_string(&json!({ "kind": "search", "soql": "search src_ip=198.51.100.4 | stats count by source" })).unwrap();
        assert_eq!((r.0, r.1.as_str()), (200, attendu.as_str()), "étape lue : le GXQL de la valeur fournie");
        let absences = [("étape absente", cid, AP2_ABSENT), ("étape d'un autre dossier", autre, recherche), ("étape illisible sous un autre dossier", autre, illisible)];
        for (quoi, dossier, etape) in absences {
            let r = ap2_appel(addr, "GET", &ap2_chemin_etape(dossier, etape), &vwr, "").await;
            assert_eq!((r.0, r.1.as_str()), (400, AP2_ETAPE_ABSENTE_400), "{quoi} : le 400 d'avant, à l'octet");
        }
        let r = ap2_appel(addr, "GET", &ap2_chemin_etape(cid, reponse), &vwr, "").await;
        assert_eq!((r.0, r.1.as_str()), (400, r#"{"error":"cette étape n'est pas une recherche"}"#), "étape d'un autre genre : son 400 d'avant");
        let r = ap2_appel(addr, "GET", &ap2_chemin_etape(cid, illisible), &vwr, "").await;
        ap2_juger_503("étape illisible", &r, CAUSE_RECHERCHE_DE_L_ETAPE_NON_RESOLUE_NON_LUE);
    }

    fn ap2_cause_de_l_objet(st: &AppState, oid: i64) -> String {
        st.db
            .lock()
            .query_row("SELECT constraint_soql, parent_id FROM data_model_object WHERE id=?1 AND enabled=1", params![oid], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?))
            })
            .expect_err("rejouée : l'objet est illisible")
            .to_string()
    }

    fn ap2_cause_de_l_etape(st: &AppState, cid: i64, sid: i64) -> String {
        st.db
            .lock()
            .query_row("SELECT step_kind,search_soql,target FROM case_step WHERE id=?1 AND incident_id=?2", params![sid, cid], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?))
            })
            .expect_err("rejouée : l'étape est illisible")
            .to_string()
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus et comparées EN ENTIER, une par phase : objet de
    /// départ illisible, parent illisible (la ligne nomme le PARENT), étape illisible (avec l'identifiant servi) ; la
    /// cause du moteur n'est dans AUCUNE autre ligne de la phase, et la trace `HTTP 503` de l'identifiant servi porte la
    /// phrase seule. Les issues lue et absente n'écrivent aucune ligne `[datamodels]` ni `[incidents]`.
    /// MUTATIONS : AP2_CHAINE_SANS_JOURNAL, AP2_ETAPE_SANS_JOURNAL (et AP2_CHAINE_EN_400 / AP2_ETAPE_EN_400, qui rendent
    /// les phases muettes).
    #[tokio::test]
    async fn ap2_lignes_de_journal_des_lectures_ratees() {
        const ENFANT: &str = "AP2_ENFANT_JOURNAL";
        const PHASE: &str = "AP2-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            let (st, _p) = sp_state("ap2-journal");
            ap2_modele(&st);
            let (cid, recherche, _reponse, illisible, _autre) = ap2_dossier_et_etapes(&st);
            let vwr = sp_au("vwr", "viewer");
            let pivot = |oid: i64| Json(serde_json::from_str::<Value>(&ap2_corps_pivot(oid)).expect("corps"));
            for (phase, depart, fautif) in [("chaine_depart", AP2_DEPART_ILLISIBLE, AP2_DEPART_ILLISIBLE), ("chaine_parent", AP2_SOUS_ILLISIBLE, AP2_PARENT_ILLISIBLE)] {
                eprintln!("{PHASE}{phase}");
                let r = pb_json(pivot_compile(State(st.clone()), Extension(vwr.clone()), pivot(depart)).await).await;
                let moteur = ap2_cause_de_l_objet(&st, fautif);
                println!("AP2-MARQUE-{phase}\t{}\t{fautif}\t{}\t{moteur}", r.0, r.1["id"].as_str().unwrap_or(""));
            }
            eprintln!("{PHASE}etape");
            let r = pb_json(case_step_search(State(st.clone()), Extension(vwr.clone()), Path((cid, illisible)), Query(HashMap::new())).await).await;
            let moteur = ap2_cause_de_l_etape(&st, cid, illisible);
            println!("AP2-MARQUE-etape\t{}\t{illisible}\t{}\t{moteur}\t{cid}", r.0, r.1["id"].as_str().unwrap_or(""));
            eprintln!("{PHASE}calme");
            let mut statuts = Vec::new();
            for oid in [AP2_ENFANT, AP2_ABSENT, AP2_SOUS_ETEINT] {
                statuts.push(pb_json(pivot_compile(State(st.clone()), Extension(vwr.clone()), pivot(oid)).await).await.0.to_string());
            }
            for sid in [recherche, AP2_ABSENT] {
                statuts.push(pb_json(case_step_search(State(st.clone()), Extension(vwr.clone()), Path((cid, sid)), Query(HashMap::new())).await).await.0.to_string());
            }
            println!("AP2-MARQUE-calme\t{}", statuts.join("\t"));
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::chaine_du_pivot_et_etape_de_recherche_en_trois_issues::ap2_lignes_de_journal_des_lectures_ratees",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> Vec<String> {
            let reste = stdout.split_once(&format!("AP2-MARQUE-{m}\t")).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").split('\t').map(str::to_string).collect()
        };
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().map(str::to_string).collect()
        };
        let mut attendus: Vec<(&str, &str, Vec<String>, String, &str)> = Vec::new();
        for nom in ["chaine_depart", "chaine_parent"] {
            let m = marque(nom);
            let ligne = format!("[datamodels] WARN objet #{} de la chaîne d'un Pivot NON lu, rien n'est compilé : {}", m[1], m[3]);
            attendus.push((nom, "[datamodels] ", m, ligne, CAUSE_OBJET_DU_PIVOT_NON_LU));
        }
        let m = marque("etape");
        let ligne = format!("[incidents] WARN étape #{} du dossier #{} NON lue, aucune recherche n'est résolue ({}) : {}", m[1], m[4], m[2], m[3]);
        attendus.push(("etape", "[incidents] ", m, ligne, CAUSE_RECHERCHE_DE_L_ETAPE_NON_RESOLUE_NON_LUE));
        assert_eq!(marque("chaine_parent")[1], AP2_PARENT_ILLISIBLE.to_string(), "contrôle : la phase parent vise le parent");
        for (nom, module, m, ligne, cause) in &attendus {
            assert_eq!(m[0], "503", "{nom} : statut : {m:?}");
            assert!(m[2].starts_with("plume-e") && !m[3].is_empty(), "{nom} : identifiant servi et cause rejouée : {m:?}");
            let lignes = phase(nom);
            let du_module: Vec<&String> = lignes.iter().filter(|l| l.starts_with(module)).collect();
            assert_eq!(du_module, vec![ligne], "{nom} : UNE ligne, en entier : {stderr}");
            assert_eq!(lignes.iter().filter(|l| l.contains(m[3].as_str())).count(), 1, "{nom} : la cause du moteur n'est que dans cette ligne : {stderr}");
            let trace = format!("[{}] HTTP 503 : {cause}", m[2]);
            assert!(lignes.contains(&trace), "{nom} : la trace de l'identifiant servi porte la phrase seule : {stderr}");
        }
        assert_eq!(marque("calme"), ["200", "400", "400", "200", "400"], "contrôle : lues et absentes gardent leur issue");
        assert!(
            phase("calme").iter().all(|l| !l.starts_with("[datamodels] ") && !l.starts_with("[incidents] ")),
            "lues et absentes n'écrivent rien : {stderr}"
        );
    }
}

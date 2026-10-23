// =====================================================================================
// `P10.20-l` (sites de la famille dans handlers/detection.rs et handlers/detection_advanced.rs) et `P10.29-l` (famille
// « texte du moteur servi ») — LA LIGNE QUI ARME LE GARDE-FOU D'UNE DÉTECTION, NON LUE, N'EST PAS UNE ABSENCE ; ET LE
// TEXTE DU MOTEUR NE PART PAS AU CLIENT.
//
// LE DÉFAUT, MESURÉ SUR f0df6162 AVANT LE CORRECTIF. La bascule d'activation (`set_content_enabled_tx`, derrière
// `rule_set_enabled`, `parser_set_enabled` et `playbook_set_enabled`), `rule_update`, `rule_delete`, `parser_update`,
// `parser_delete`, `correlation_update`, `correlation_delete`, `baseline_update` et `baseline_delete` lisaient leur
// ligne (`managed`, `is_soql`, `query`, `window_s`, `name`) par `match … { Ok(x) => x, Err(_) => not_found(…) }` : une
// lecture qui n'avait pas eu lieu (ligne qui ne se convertit pas, table retirée) se servait 404 « règle introuvable »
// (« parseur », « corrélation », « baseline », « rule/parser/playbook introuvable »), et le garde-fou que cette ligne
// arme (contenu managé réservé à l'administrateur, anti-contournement editor -> SQL brut, contenu natif non
// supprimable) n'était jamais jugé. Huit écritures refusées (création et modification d'une règle, d'un parseur, d'une
// corrélation, d'une référence UEBA) rendaient `500 échec transaction audit (aucune modification): <phrase du moteur>`,
// et la fenêtre illisible d'un playbook à armer rendait `500 … pour juger le plancher (<phrase du moteur>) — …`.
//
// LE CORRECTIF (décision par défaut de la vague AE). Trois issues : lue, le geste suit ; absente, le 404 d'avant à
// l'identique ; lecture ratée, 503 nommé (`CAUSE_*_NON_LU(E)`), RIEN n'est écrit, basculé, dérogé ni supprimé, la cause
// du moteur au journal seul (l'identifiant interne, jamais la requête, le motif, les étapes ni le nom). Les neuf 500
// gardent leur statut ; les huit écritures servent la phrase fixe `PHRASE_ECHEC_TRANSACTION_AUDIT` par
// `servir_l_echec_de_la_transaction_d_audit`, la fenêtre sa phrase sans le texte du moteur, la cause au journal avec
// l'identifiant de corrélation servi.
//
// LES PANNES ÉPROUVÉES : `managed` stocké en BLOB (la ligne existe, sa lecture comme entier échoue), la table retirée,
// `window_s` d'un playbook en BLOB ; un déclencheur `RAISE(ABORT)` sur `BEFORE INSERT ON ledger` (la trace d'audit
// refusée) ; les lignes de journal lues sur le stderr d'un sous-processus.
//
// MUTANTS (posés le temps de la preuve, retirés avant le commit) : par lecture (`BASCULE`, `REGLE_MODIF`,
// `REGLE_RETRAIT`, `PARSEUR_MODIF`, `PARSEUR_RETRAIT`, `CORRELATION_MODIF`, `CORRELATION_RETRAIT`, `REFERENCE_MODIF`,
// `REFERENCE_RETRAIT`) `AE1_<L>_LECTURE_EN_404`, `AE1_<L>_ABSENT_EN_503`, `AE1_<L>_CAUSE_EXPOSEE`,
// `AE1_<L>_SANS_JOURNAL`, `AE1_<L>_LECTURE_FAIT_LE_GESTE` ; par 500 (`REGLE_CREATION`, `REGLE_MODIF`,
// `PARSEUR_CREATION`, `PARSEUR_MODIF`, `CORRELATION_CREATION`, `CORRELATION_MODIF`, `REFERENCE_CREATION`,
// `REFERENCE_MODIF`) `AE1_<S>_MOTEUR_SERVI`, `AE1_<S>_TEXTE_SANS_JOURNAL` ; `AE1_FENETRE_MOTEUR_SERVI`,
// `AE1_FENETRE_SANS_JOURNAL` ; `AE1_<L>_DESACTIVE` (huit gestes) et `AE1_BASCULE_ECRIT` (une écriture dans le bras de la
// lecture ratée, que seule la ligne entière lue après chaque appel voit) ; `AE1_<L>_JOURNAL_NOMME`,
// `AE1_FENETRE_JOURNAL_NOMME`, `AE1_ECRITURE_JOURNAL_NOMME` (l'acteur ajouté à la ligne de journal, que seule l'égalité
// exacte de la ligne voit).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'écran n'est pas joué ici (la console peint ces refus par
// `peindreLeRefusDUnGeste` — `contentSubmit`/`contentDelete` de web/core.js, web/detadv.js, les interrupteurs de
// web/detection_admin.js — en « refus nommé » avec la phrase entière ; lu, non exécuté) ; une lecture ratée par verrou
// n'est pas jouée (la conversion et la table retirée suffisent à atteindre le bras) ; les deux autres textes du moteur
// de detection.rs (`delete_managed_row_tx`, et l'écriture refusée de la bascule) ne sont pas de ce lot.
// =====================================================================================
mod detection_lecture_ratee_et_texte_du_moteur {
    use super::*;

    /// Ce que rusqlite écrit quand une colonne n'a pas le type demandé : la cause du moteur d'une lecture ratée.
    const AE1_MOTEUR_LECTURE: &str = "Invalid column type";
    /// La phrase du déclencheur qui refuse la trace d'audit : la cause du moteur d'une écriture refusée.
    const AE1_MOTEUR_ECRITURE: &str = "registre hors d atteinte (temoin AE1)";
    /// Une requête et un motif reconnaissables : ils ne doivent paraître ni dans un corps ni dans le journal.
    const AE1_REQUETE: &str = "search source=auth outcome=fail | stats count";
    const AE1_ABSENT: i64 = 987_654;

    fn ae1_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    fn ae1_editeur() -> AuthUser {
        sp_au("alice", "editor")
    }

    fn ae1_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn ae1_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// La ligne ENTIÈRE d'un contenu, chaque colonne par son nom et sa valeur typée (`enabled`, `managed`, `name`,
    /// la requête, les horodatages…) : « rien n'est écrit, rien n'est désactivé » se lit comme son égalité exacte.
    fn ae1_ligne(st: &AppState, table: &str, id: i64) -> String {
        let c = st.db.lock();
        let mut s = c.prepare(&format!("SELECT * FROM {table} WHERE id=?1")).unwrap_or_else(|e| panic!("fixture : {table} se lit ({e})"));
        let noms: Vec<String> = s.column_names().iter().map(|n| n.to_string()).collect();
        let ligne = s
            .query_row(params![id], |r| (0..noms.len()).map(|i| r.get::<_, rusqlite::types::Value>(i).map(|v| format!("{}={v:?}", noms[i]))).collect::<Result<Vec<_>, _>>())
            .unwrap_or_else(|e| panic!("fixture : {table} #{id} se lit ({e})"));
        ligne.join(",")
    }

    /// Une ligne de journal préfixée de l'identifiant de corrélation : l'identifiant (`plume-e<pid>-<n>`) retiré, le
    /// reste rendu pour une égalité exacte.
    fn ae1_sans_identifiant(ligne: &str) -> &str {
        let (id, reste) = ligne.strip_prefix('[').and_then(|l| l.split_once("] ")).unwrap_or_else(|| panic!("identifiant de corrélation en tête : {ligne}"));
        assert!(id.starts_with("plume-e") && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'), "identifiant de corrélation : {ligne}");
        reste
    }

    async fn ae1_reponse(r: Response) -> (u16, String, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, String::from_utf8_lossy(&octets).into_owned(), v)
    }

    /// Un 5xx nommé, EN ENTIER : exactement les clés `error` et `id`, l'erreur égale à la phrase attendue, l'identifiant
    /// de corrélation, et aucune trace de la cause du moteur ni de la requête.
    fn ae1_juger_5xx(quoi: &str, (statut, corps, v): &(u16, String, Value), attendu_statut: u16, phrase: &str, moteur: &str) {
        assert_eq!(*statut, attendu_statut, "{quoi} : statut : {corps}");
        let cles: Vec<&str> = v.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"], "{quoi} : exactement `error` et `id` : {corps}");
        assert_eq!(v["error"], json!(phrase), "{quoi} : la phrase nommée, seule : {corps}");
        assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : identifiant de corrélation : {corps}");
        assert!(
            !corps.contains(moteur) && !corps.contains("Blob") && !corps.contains("no such table") && !corps.contains("hors d atteinte") && !corps.contains(AE1_REQUETE),
            "{quoi} : la cause du moteur ne sort pas : {corps}"
        );
    }

    /// L'absence établie : `404` et le corps d'avant, exactement.
    fn ae1_juger_404(quoi: &str, (statut, corps, v): &(u16, String, Value), phrase: &str) {
        assert_eq!(*statut, 404, "{quoi} : l'absence établie reste un 404 : {corps}");
        assert_eq!(*v, json!({ "error": phrase }), "{quoi} : l'absence, rien d'autre : {corps}");
    }

    async fn ae1_id(quoi: &str, r: Response) -> i64 {
        let (statut, corps, v) = ae1_reponse(r).await;
        assert_eq!(statut, 200, "fixture : {quoi} se crée : {corps}");
        v["id"].as_i64().unwrap_or_else(|| panic!("fixture : identifiant de {quoi} : {corps}"))
    }

    fn ae1_corps_de_regle(nom: &str) -> Value {
        json!({ "name": nom, "query": AE1_REQUETE, "threshold": 3 })
    }

    fn ae1_corps_de_parseur(nom: &str) -> Value {
        json!({ "name": nom, "source": "ae1", "pattern": "ae1=(?P<ae1_champ>\\w+)" })
    }

    fn ae1_corps_de_correlation(nom: &str) -> Value {
        json!({ "name": nom, "key_field": "src_ip", "entity_type": "ip", "window_s": 3600,
            "steps": [{ "name": "s1", "query": "search source=auth outcome=fail", "min_count": 3 },
                      { "name": "s2", "query": "search source=auth outcome=success", "min_count": 1 }] })
    }

    fn ae1_corps_de_reference(nom: &str) -> Value {
        json!({ "name": nom, "query": "search source=auth | stats count by host", "entity_field": "host", "entity_type": "host" })
    }

    /// Les huit gestes d'un contenu de détection dont la lecture arme le garde-fou.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Ae1Geste {
        ModifRegle,
        RetraitRegle,
        ModifParseur,
        RetraitParseur,
        ModifCorrelation,
        RetraitCorrelation,
        ModifReference,
        RetraitReference,
    }
    use Ae1Geste::*;
    const AE1_GESTES: [Ae1Geste; 8] = [ModifRegle, RetraitRegle, ModifParseur, RetraitParseur, ModifCorrelation, RetraitCorrelation, ModifReference, RetraitReference];

    impl Ae1Geste {
        fn table(self) -> &'static str {
            match self {
                ModifRegle | RetraitRegle => "rule",
                ModifParseur | RetraitParseur => "parser",
                ModifCorrelation | RetraitCorrelation => "correlation",
                ModifReference | RetraitReference => "ueba_baseline",
            }
        }
        fn absent(self) -> &'static str {
            match self {
                ModifRegle | RetraitRegle => "règle introuvable",
                ModifParseur | RetraitParseur => "parseur introuvable",
                ModifCorrelation | RetraitCorrelation => "corrélation introuvable",
                ModifReference | RetraitReference => "baseline introuvable",
            }
        }
        fn cause(self) -> &'static str {
            match self {
                ModifRegle => CAUSE_REGLE_INCHANGEE_NON_LUE,
                RetraitRegle => CAUSE_REGLE_NON_SUPPRIMEE_NON_LUE,
                ModifParseur => CAUSE_PARSEUR_INCHANGE_NON_LU,
                RetraitParseur => CAUSE_PARSEUR_NON_SUPPRIME_NON_LU,
                ModifCorrelation => CAUSE_CORRELATION_INCHANGEE_NON_LUE,
                RetraitCorrelation => CAUSE_CORRELATION_NON_SUPPRIMEE_NON_LUE,
                ModifReference => CAUSE_REFERENCE_UEBA_INCHANGEE_NON_LUE,
                RetraitReference => CAUSE_REFERENCE_UEBA_NON_SUPPRIMEE_NON_LUE,
            }
        }
        /// Le début de la ligne de journal d'une lecture ratée de ce geste (le reste est la cause du moteur).
        fn journal(self, id: i64) -> String {
            let sujet = match self {
                ModifRegle => format!("règle #{id} NON lue pour la modification, rien n'est écrit"),
                RetraitRegle => format!("règle #{id} NON lue pour la suppression, rien n'est supprimé"),
                ModifParseur => format!("parseur #{id} NON lu pour la modification, rien n'est écrit"),
                RetraitParseur => format!("parseur #{id} NON lu pour la suppression, rien n'est supprimé"),
                ModifCorrelation => format!("corrélation #{id} NON lue pour la modification, rien n'est écrit"),
                RetraitCorrelation => format!("corrélation #{id} NON lue pour la suppression, rien n'est supprimé"),
                ModifReference => format!("référence UEBA #{id} NON lue pour la modification, rien n'est écrit"),
                RetraitReference => format!("référence UEBA #{id} NON lue pour la suppression, rien n'est supprimé"),
            };
            format!("[detection] WARN {sujet} : ")
        }
        /// La cause du moteur de la lecture ratée de ce geste, exactement (rusqlite, `managed` en BLOB à sa place dans le
        /// SELECT du site) : la ligne de journal est `journal(id)` suivie de CECI, et de rien d'autre.
        fn cause_du_moteur(self) -> String {
            let index = match self {
                ModifRegle => 3,
                ModifCorrelation | ModifReference => 4,
                RetraitRegle | ModifParseur | RetraitParseur | RetraitCorrelation | RetraitReference => 0,
            };
            format!("Invalid column type Blob at index: {index}, name: managed")
        }
        fn est_une_modification(self) -> bool {
            matches!(self, ModifRegle | ModifParseur | ModifCorrelation | ModifReference)
        }
    }

    /// Un contenu lisible, créé par la route de sa table ; rend son identifiant.
    async fn ae1_creer(st: &AppState, g: Ae1Geste, nom: &str) -> i64 {
        let s = State(st.clone());
        let a = Extension(ae1_adm());
        match g.table() {
            "rule" => ae1_id(nom, rule_create(s, a, Json(ae1_corps_de_regle(nom))).await).await,
            "parser" => ae1_id(nom, parser_create(s, a, Json(ae1_corps_de_parseur(nom))).await).await,
            "correlation" => ae1_id(nom, correlation_create(s, a, Json(ae1_corps_de_correlation(nom))).await).await,
            _ => ae1_id(nom, baseline_create(s, a, Json(ae1_corps_de_reference(nom))).await).await,
        }
    }

    /// Un contenu créé par la route puis rendu illisible (son `managed` en BLOB) ; rend son identifiant.
    async fn ae1_illisible(st: &AppState, g: Ae1Geste, nom: &str) -> i64 {
        let id = ae1_creer(st, g, nom).await;
        ae1_sql(st, &format!("UPDATE {} SET managed=X'00' WHERE id={id}", g.table()));
        id
    }

    /// Joue le geste par son point d'entrée (la route), sous l'identité donnée.
    async fn ae1_jouer(st: &AppState, g: Ae1Geste, au: AuthUser, id: i64) -> (u16, String, Value) {
        let s = State(st.clone());
        let a = Extension(au);
        let renommer = || Json(json!({ "name": "ae1-renommee" }));
        let r = match g {
            ModifRegle => rule_update(s, a, Path(id), renommer()).await,
            RetraitRegle => rule_delete(s, a, Path(id)).await,
            ModifParseur => parser_update(s, a, Path(id), renommer()).await,
            RetraitParseur => parser_delete(s, a, Path(id)).await,
            ModifCorrelation => correlation_update(s, a, Path(id), renommer()).await,
            RetraitCorrelation => correlation_delete(s, a, Path(id)).await,
            ModifReference => baseline_update(s, a, Path(id), renommer()).await,
            RetraitReference => baseline_delete(s, a, Path(id)).await,
        };
        ae1_reponse(r).await
    }

    fn ae1_registre_refuse(st: &AppState) {
        ae1_sql(st, &format!("CREATE TRIGGER ae1_ledger_refuse BEFORE INSERT ON ledger BEGIN SELECT RAISE(ABORT, '{AE1_MOTEUR_ECRITURE}'); END;"));
    }

    fn ae1_registre_rendu(st: &AppState) {
        ae1_sql(st, "DROP TRIGGER ae1_ledger_refuse;");
    }

    /// CE QU'IL TIENT (les huit gestes de modification et de suppression) : absent, `404` et le corps d'avant exactement ;
    /// ligne illisible, `503` nommé de SA cause, en entier, sans la cause du moteur — jamais `404` — pour l'administrateur
    /// ET, sur une modification, pour un éditeur (le garde-fou du contenu managé n'est pas jugé sur une valeur fabriquée :
    /// ni `403`, ni `200`) ; rien n'est écrit ni désactivé (la ligne ENTIÈRE — `enabled`, `managed`, nom, requête —
    /// identique après CHAQUE appel, aucune observation retirée, aucun maillon de registre), la transaction est fermée ;
    /// table retirée, le même `503`, la ligne toujours identique. Contrôle : un contenu lisible se modifie ou se supprime
    /// (`200`).
    /// MUTATIONS : `AE1_<L>_LECTURE_EN_404` (la forme d'avant), `AE1_<L>_ABSENT_EN_503`, `AE1_<L>_CAUSE_EXPOSEE`,
    /// `AE1_<L>_LECTURE_FAIT_LE_GESTE` (une lecture ratée qui suit avec un `managed` fabriqué), `AE1_<L>_DESACTIVE`
    /// (`enabled=0` posé dans le bras de la lecture ratée, la forme du retrait d'un natif).
    #[tokio::test]
    async fn ae1_lectures_ratees_des_contenus_jamais_404_et_rien_n_est_ecrit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = sp_state("ae1-contenus");
        assert!(AE1_GESTES.len() >= 8, "plancher : les huit gestes");
        for g in AE1_GESTES {
            let quoi = format!("{g:?}");
            let r = ae1_jouer(&st, g, ae1_adm(), AE1_ABSENT).await;
            ae1_juger_404(&quoi, &r, g.absent());

            let nom = format!("ae1-illisible-{quoi}");
            let id = ae1_illisible(&st, g, &nom).await;
            if g == RetraitReference {
                ae1_sql(&st, &format!("INSERT INTO ueba_baseline_obs(baseline_id,entity_type,entity,bucket,value) VALUES({id},'host','web-01',1,1.0)"));
            }
            let maillons = ae1_compte(&st, "SELECT COUNT(*) FROM ledger");
            let table = g.table();
            let avant = ae1_ligne(&st, table, id);
            assert!(avant.contains("enabled=Integer(1)") && avant.contains("managed=Blob("), "fixture : {quoi} actif et illisible : {avant}");
            let mut identites = vec![("administrateur", ae1_adm())];
            if g.est_une_modification() {
                identites.push(("éditeur", ae1_editeur()));
            }
            for (qui, au) in identites {
                let r = ae1_jouer(&st, g, au, id).await;
                ae1_juger_5xx(&format!("{quoi} illisible ({qui})"), &r, 503, g.cause(), AE1_MOTEUR_LECTURE);
                assert_eq!(ae1_ligne(&st, table, id), avant, "{quoi} illisible ({qui}) : la ligne ENTIÈRE est inchangée — ni écrite, ni désactivée");
            }
            assert_eq!(ae1_compte(&st, &format!("SELECT COUNT(*) FROM {table} WHERE id={id} AND name='{nom}' AND typeof(managed)='blob'")), 1,
                "{quoi} : la ligne est là, nom inchangé, `managed` toujours illisible — rien n'est écrit");
            if g == RetraitReference {
                assert_eq!(ae1_compte(&st, &format!("SELECT COUNT(*) FROM ueba_baseline_obs WHERE baseline_id={id}")), 1, "{quoi} : ses observations restent");
            }
            assert_eq!(ae1_compte(&st, "SELECT COUNT(*) FROM ledger"), maillons, "{quoi} : aucun maillon de registre");
            assert!(st.db.lock().is_autocommit(), "{quoi} : la transaction est fermée");

            let lisible = ae1_creer(&st, g, &format!("ae1-lisible-{quoi}")).await;
            let (statut, corps, _) = ae1_jouer(&st, g, ae1_adm(), lisible).await;
            assert_eq!(statut, 200, "{quoi} : contrôle : un contenu lisible suit son geste : {corps}");

            ae1_sql(&st, &format!("ALTER TABLE {table} RENAME TO {table}_ae1_retiree;"));
            let r = ae1_jouer(&st, g, ae1_adm(), id).await;
            ae1_sql(&st, &format!("ALTER TABLE {table}_ae1_retiree RENAME TO {table};"));
            ae1_juger_5xx(&format!("{quoi}, table retirée"), &r, 503, g.cause(), "no such table");
            assert_eq!(ae1_ligne(&st, table, id), avant, "{quoi}, table retirée : la ligne ENTIÈRE est inchangée");
            assert!(st.db.lock().is_autocommit(), "{quoi} : la transaction est fermée");
        }
    }

    /// CE QU'IL TIENT (la bascule d'activation, par ses trois routes) : absent, `404 {"error": "<kind> introuvable"}`
    /// exactement ; ligne illisible, `503` nommé `CAUSE_ACTIVATION_DE_CONTENU_INCHANGEE_NON_LU` en entier, pour activer
    /// comme pour désactiver — jamais `404` ; `enabled` et la ligne ENTIÈRE inchangés, lus après CHAQUE appel, aucune
    /// dérogation, aucun maillon, transaction fermée ; table retirée, le même `503`. Contrôle : un contenu lisible se
    /// bascule (`200`).
    /// MUTATIONS : `AE1_BASCULE_LECTURE_EN_404`, `AE1_BASCULE_ABSENT_EN_503`, `AE1_BASCULE_CAUSE_EXPOSEE`,
    /// `AE1_BASCULE_LECTURE_FAIT_LE_GESTE`, `AE1_BASCULE_ECRIT` (la valeur demandée écrite dans le bras de la lecture
    /// ratée : 0 puis 1, qui se déferait seule si `enabled` n'était lu qu'après la boucle).
    #[tokio::test]
    async fn ae1_bascule_lecture_ratee_jamais_404_et_rien_n_est_bascule() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = sp_state("ae1-bascule");
        async fn basculer(st: &AppState, kind: &str, id: i64, en: bool) -> (u16, String, Value) {
            let (s, a, p, b) = (State(st.clone()), Extension(sp_au("adm", "admin")), Path(id), Json(json!({ "enabled": en })));
            let r = match kind {
                "rule" => rule_set_enabled(s, a, p, b).await,
                "parser" => parser_set_enabled(s, a, p, b).await,
                _ => playbook_set_enabled(s, a, p, b).await,
            };
            ae1_reponse(r).await
        }
        let creer = |kind: &'static str, nom: String| {
            let st = st.clone();
            async move {
                match kind {
                    "rule" => ae1_creer(&st, ModifRegle, &nom).await,
                    "parser" => ae1_creer(&st, ModifParseur, &nom).await,
                    _ => {
                        let c = st.db.lock();
                        c.execute(
                            "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,created_by_role) VALUES(?1,1,?2,1,'ban_ip',300,300,2,'admin')",
                            params![nom, AE1_REQUETE],
                        ).expect("fixture : playbook");
                        c.last_insert_rowid()
                    }
                }
            }
        };
        let genres = ["rule", "parser", "playbook"];
        assert!(genres.len() >= 3, "plancher : les trois routes");
        for kind in genres {
            for en in [false, true] {
                ae1_juger_404(&format!("{kind} absent ({en})"), &basculer(&st, kind, AE1_ABSENT, en).await, &format!("{kind} introuvable"));
            }
            let id = creer(kind, format!("ae1-bascule-{kind}")).await;
            ae1_sql(&st, &format!("UPDATE {kind} SET managed=X'00' WHERE id={id}"));
            let (maillons, derogations) = (ae1_compte(&st, "SELECT COUNT(*) FROM ledger"), ae1_compte(&st, "SELECT COUNT(*) FROM detection_override"));
            let avant = ae1_ligne(&st, kind, id);
            assert!(avant.contains("enabled=Integer(1)") && avant.contains("managed=Blob("), "fixture : {kind} actif et illisible : {avant}");
            // Lu après CHAQUE appel : une écriture de la valeur demandée (0 puis 1) se déferait seule sur la boucle entière.
            for en in [false, true] {
                let r = basculer(&st, kind, id, en).await;
                ae1_juger_5xx(&format!("{kind} illisible ({en})"), &r, 503, CAUSE_ACTIVATION_DE_CONTENU_INCHANGEE_NON_LU, AE1_MOTEUR_LECTURE);
                assert_eq!(ae1_compte(&st, &format!("SELECT enabled FROM {kind} WHERE id={id}")), 1, "{kind} illisible ({en}) : `enabled` inchangé");
                assert_eq!(ae1_ligne(&st, kind, id), avant, "{kind} illisible ({en}) : la ligne ENTIÈRE est inchangée");
            }
            assert_eq!(ae1_compte(&st, "SELECT COUNT(*) FROM ledger"), maillons, "{kind} : aucun maillon");
            assert_eq!(ae1_compte(&st, "SELECT COUNT(*) FROM detection_override"), derogations, "{kind} : aucune dérogation");
            assert!(st.db.lock().is_autocommit(), "{kind} : la transaction est fermée");

            let lisible = creer(kind, format!("ae1-bascule-lisible-{kind}")).await;
            let (statut, corps, _) = basculer(&st, kind, lisible, false).await;
            assert_eq!(statut, 200, "{kind} : contrôle : un contenu lisible se bascule : {corps}");

            ae1_sql(&st, &format!("ALTER TABLE {kind} RENAME TO {kind}_ae1_retiree;"));
            let r = basculer(&st, kind, id, false).await;
            ae1_sql(&st, &format!("ALTER TABLE {kind}_ae1_retiree RENAME TO {kind};"));
            ae1_juger_5xx(&format!("{kind}, table retirée"), &r, 503, CAUSE_ACTIVATION_DE_CONTENU_INCHANGEE_NON_LU, "no such table");
            assert_eq!(ae1_ligne(&st, kind, id), avant, "{kind}, table retirée : la ligne ENTIÈRE est inchangée");
        }
    }

    /// CE QU'IL TIENT (la fenêtre d'un playbook à armer, illisible) : `500` dont le corps est EXACTEMENT `{error:
    /// "playbook #<id> non activé : sa fenêtre n'a pas pu être lue pour juger le plancher — rien n'est écrit", id}`, sans
    /// la phrase du moteur ; le playbook reste éteint, aucun maillon. Contrôle : une fenêtre lisible s'arme (`200`).
    /// MUTATION : `AE1_FENETRE_MOTEUR_SERVI` (la forme d'avant).
    #[tokio::test]
    async fn ae1_fenetre_illisible_du_playbook_rend_500_sans_le_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = sp_state("ae1-fenetre");
        let inserer = |nom: &str, fenetre: &str| {
            let c = st.db.lock();
            c.execute(
                &format!("INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,created_by_role) VALUES(?1,0,?2,1,'ban_ip',300,{fenetre},2,'admin')"),
                params![nom, AE1_REQUETE],
            ).expect("fixture : playbook");
            c.last_insert_rowid()
        };
        let id = inserer("ae1-fenetre-illisible", "X'00'");
        let maillons = ae1_compte(&st, "SELECT COUNT(*) FROM ledger");
        let r = ae1_reponse(playbook_set_enabled(State(st.clone()), Extension(ae1_adm()), Path(id), Json(json!({ "enabled": true }))).await).await;
        let phrase = format!("playbook #{id} non activé : sa fenêtre n'a pas pu être lue pour juger le plancher — rien n'est écrit");
        ae1_juger_5xx("fenêtre illisible", &r, 500, &phrase, AE1_MOTEUR_LECTURE);
        assert_eq!(ae1_compte(&st, &format!("SELECT enabled FROM playbook WHERE id={id}")), 0, "le playbook reste éteint");
        assert_eq!(ae1_compte(&st, "SELECT COUNT(*) FROM ledger"), maillons, "aucun maillon");

        let lisible = inserer("ae1-fenetre-lisible", "300");
        let (statut, corps, _) = ae1_reponse(playbook_set_enabled(State(st.clone()), Extension(ae1_adm()), Path(lisible), Json(json!({ "enabled": true }))).await).await;
        assert_eq!(statut, 200, "contrôle : une fenêtre lisible s'arme : {corps}");
    }

    /// Les huit écritures refusées, jouées par leurs routes sous un registre qui refuse la trace d'audit.
    async fn ae1_huit_ecritures(st: &AppState, ids: &[i64; 4]) -> Vec<(&'static str, (u16, String, Value))> {
        let s = || State(st.clone());
        let a = || Extension(ae1_adm());
        let renommer = || Json(json!({ "name": "ae1-refusee" }));
        vec![
            ("création d'une règle", ae1_reponse(rule_create(s(), a(), Json(ae1_corps_de_regle("ae1-regle-refusee"))).await).await),
            ("modification d'une règle", ae1_reponse(rule_update(s(), a(), Path(ids[0]), renommer()).await).await),
            ("création d'un parseur", ae1_reponse(parser_create(s(), a(), Json(ae1_corps_de_parseur("ae1-parseur-refuse"))).await).await),
            ("modification d'un parseur", ae1_reponse(parser_update(s(), a(), Path(ids[1]), renommer()).await).await),
            ("création d'une corrélation", ae1_reponse(correlation_create(s(), a(), Json(ae1_corps_de_correlation("ae1-correlation-refusee"))).await).await),
            ("modification d'une corrélation", ae1_reponse(correlation_update(s(), a(), Path(ids[2]), renommer()).await).await),
            ("création d'une référence", ae1_reponse(baseline_create(s(), a(), Json(ae1_corps_de_reference("ae1-reference-refusee"))).await).await),
            ("modification d'une référence", ae1_reponse(baseline_update(s(), a(), Path(ids[3]), renommer()).await).await),
        ]
    }

    async fn ae1_quatre_contenus(st: &AppState, tag: &str) -> [i64; 4] {
        [
            ae1_creer(st, ModifRegle, &format!("ae1-{tag}-regle")).await,
            ae1_creer(st, ModifParseur, &format!("ae1-{tag}-parseur")).await,
            ae1_creer(st, ModifCorrelation, &format!("ae1-{tag}-correlation")).await,
            ae1_creer(st, ModifReference, &format!("ae1-{tag}-reference")).await,
        ]
    }

    /// CE QU'IL TIENT (les huit 500 d'écriture) : la trace d'audit refusée, chaque création et chaque modification rend
    /// `500` dont le corps est EXACTEMENT `{error: PHRASE_ECHEC_TRANSACTION_AUDIT, id}` — sans la phrase du moteur ;
    /// rien n'est écrit (aucun contenu de plus, aucun renommé) et la transaction est fermée.
    /// MUTATIONS : `AE1_<S>_MOTEUR_SERVI` (la phrase du moteur réapposée, la forme d'avant), une par site.
    #[tokio::test]
    async fn ae1_ecriture_refusee_rend_500_sans_le_texte_du_moteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement (résolveur, configuration)
        let (st, _p) = sp_state("ae1-moteur");
        let ids = ae1_quatre_contenus(&st, "moteur").await;
        ae1_registre_refuse(&st);
        let cas = ae1_huit_ecritures(&st, &ids).await;
        ae1_registre_rendu(&st);
        assert!(cas.len() >= 8, "plancher : les huit sites");
        for (quoi, r) in &cas {
            ae1_juger_5xx(quoi, r, 500, PHRASE_ECHEC_TRANSACTION_AUDIT, AE1_MOTEUR_ECRITURE);
        }
        assert!(st.db.lock().is_autocommit(), "la transaction est fermée");
        for table in ["rule", "parser", "correlation", "ueba_baseline"] {
            assert_eq!(ae1_compte(&st, &format!("SELECT COUNT(*) FROM {table} WHERE name LIKE 'ae1-%refus%'")), 0, "{table} : rien n'est créé ni renommé");
            assert_eq!(ae1_compte(&st, &format!("SELECT COUNT(*) FROM {table} WHERE name LIKE 'ae1-moteur-%'")), 1, "{table} : le contenu garde son nom");
        }
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus : chaque lecture ratée (neuf sites), la fenêtre
    /// illisible et chaque écriture refusée (huit sites) écrivent UNE ligne `[detection] WARN <sujet> : <cause du
    /// moteur>` (préfixée de l'identifiant de corrélation pour les 500), jugée LIGNE ENTIÈRE par égalité exacte : ni la
    /// requête, ni le nom du contenu, ni l'identité de l'acteur ; le nominal et les absences n'en écrivent aucune.
    /// MUTATIONS : `AE1_<L>_SANS_JOURNAL` (neuf), `AE1_<S>_TEXTE_SANS_JOURNAL` (huit), `AE1_FENETRE_SANS_JOURNAL`,
    /// `AE1_<L>_JOURNAL_NOMME` (neuf), `AE1_FENETRE_JOURNAL_NOMME`, `AE1_ECRITURE_JOURNAL_NOMME` (« par <acteur> »
    /// ajouté en fin de ligne).
    #[tokio::test]
    async fn ae1_lignes_de_journal_des_refus() {
        const ENFANT: &str = "AE1_ENFANT_JOURNAL";
        const PHASE: &str = "AE1-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
            let (st, _p) = sp_state("ae1-journal");
            let mut statuts = Vec::new();
            let mut ids = Vec::new();
            for g in AE1_GESTES {
                let id = ae1_illisible(&st, g, &format!("ae1-journal-{g:?}")).await;
                eprintln!("{PHASE}{g:?}");
                statuts.push(ae1_jouer(&st, g, ae1_adm(), id).await.0.to_string());
                ids.push(id.to_string());
            }
            let regle = ae1_illisible(&st, ModifRegle, "ae1-journal-bascule").await;
            eprintln!("{PHASE}bascule");
            statuts.push(ae1_reponse(rule_set_enabled(State(st.clone()), Extension(ae1_adm()), Path(regle), Json(json!({ "enabled": false }))).await).await.0.to_string());
            ids.push(regle.to_string());
            let pb = {
                let c = st.db.lock();
                c.execute(
                    "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,created_by_role) VALUES('ae1-journal-fenetre',0,?1,1,'ban_ip',300,X'00',2,'admin')",
                    params![AE1_REQUETE],
                ).expect("fixture : playbook");
                c.last_insert_rowid()
            };
            eprintln!("{PHASE}fenetre");
            statuts.push(ae1_reponse(playbook_set_enabled(State(st.clone()), Extension(ae1_adm()), Path(pb), Json(json!({ "enabled": true }))).await).await.0.to_string());
            ids.push(pb.to_string());
            println!("AE1-STATUTS-LECTURES:{}", statuts.join(":"));
            println!("AE1-IDS-LECTURES:{}", ids.join(":"));
            let contenus = ae1_quatre_contenus(&st, "journal").await;
            ae1_registre_refuse(&st);
            eprintln!("{PHASE}ecritures");
            let cas = ae1_huit_ecritures(&st, &contenus).await;
            eprintln!("{PHASE}apres-ecritures");
            ae1_registre_rendu(&st);
            println!("AE1-STATUTS-ECRITURES:{}", cas.iter().map(|(_, r)| r.0.to_string()).collect::<Vec<_>>().join(":"));
            println!("AE1-IDS-ECRITURES:{}", contenus.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(":"));
            let (st, _p) = sp_state("ae1-journal-calme");
            eprintln!("{PHASE}calme");
            let mut calme = Vec::new();
            for g in AE1_GESTES {
                let id = ae1_creer(&st, g, &format!("ae1-calme-{g:?}")).await;
                calme.push(ae1_jouer(&st, g, ae1_adm(), id).await.0.to_string());
                calme.push(ae1_jouer(&st, g, ae1_adm(), AE1_ABSENT).await.0.to_string());
            }
            let r = ae1_creer(&st, ModifRegle, "ae1-calme-bascule").await;
            calme.push(ae1_reponse(rule_set_enabled(State(st.clone()), Extension(ae1_adm()), Path(r), Json(json!({ "enabled": false }))).await).await.0.to_string());
            calme.push(ae1_reponse(rule_set_enabled(State(st.clone()), Extension(ae1_adm()), Path(AE1_ABSENT), Json(json!({ "enabled": false }))).await).await.0.to_string());
            eprintln!("{PHASE}fin");
            println!("AE1-STATUTS-CALME:{}", calme.join(":"));
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::detection_lecture_ratee_et_texte_du_moteur::ae1_lignes_de_journal_des_refus"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> Vec<String> {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            reste.lines().next().unwrap_or("").split(':').map(str::to_string).collect()
        };
        let statuts = marque("AE1-STATUTS-LECTURES:");
        let ids = marque("AE1-IDS-LECTURES:");
        assert_eq!(statuts[..9], ["503"; 9], "contrôle : neuf lectures ratées");
        assert_eq!(statuts[9], "500", "contrôle : la fenêtre illisible");
        assert_eq!(marque("AE1-STATUTS-ECRITURES:"), ["500"; 8], "contrôle : huit écritures refusées");
        let calme = marque("AE1-STATUTS-CALME:");
        assert_eq!(calme.len(), 18, "contrôle : neuf nominaux et neuf absences : {calme:?}");
        for (i, s) in calme.iter().enumerate() {
            assert_eq!(s, if i % 2 == 0 { "200" } else { "404" }, "contrôle : nominal puis absence : {calme:?}");
        }
        // Les lignes `[detection]` d'une phase (préfixe d'identifiant de corrélation admis), entre son marqueur et le suivant.
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.contains("[detection] ")).map(str::to_string).collect()
        };
        let propre = |l: &str| !l.contains(AE1_REQUETE) && !l.contains("ae1-journal") && !l.contains("ae1=(?P");
        assert!(AE1_GESTES.len() >= 8, "plancher : les huit gestes");
        for (i, g) in AE1_GESTES.iter().enumerate() {
            let id: i64 = ids[i].parse().expect("identifiant");
            let lignes = phase(&format!("{g:?}"));
            assert_eq!(lignes.len(), 1, "phase {g:?} : une ligne et une seule : {lignes:?}");
            // LIGNE ENTIÈRE : l'en-tête du sujet, puis exactement la cause du moteur — rien d'autre (ni nom de contenu, ni
            // identité de l'acteur, ni requête).
            assert_eq!(lignes[0].strip_prefix(&g.journal(id)), Some(g.cause_du_moteur().as_str()), "phase {g:?} : la ligne entière : {}", lignes[0]);
            assert!(propre(&lignes[0]), "phase {g:?} : ni requête ni nom : {}", lignes[0]);
        }
        let lignes = phase("bascule");
        assert_eq!(lignes.len(), 1, "phase bascule : une ligne et une seule : {lignes:?}");
        let tete = format!("[detection] WARN rule #{} NON lu pour la bascule d'activation, rien n'est basculé : ", ids[8]);
        assert_eq!(lignes[0].strip_prefix(&tete), Some("Invalid column type Blob at index: 1, name: managed"), "phase bascule : la ligne entière : {}", lignes[0]);
        let lignes = phase("fenetre");
        assert_eq!(lignes.len(), 1, "phase fenetre : une ligne et une seule : {lignes:?}");
        let attendu = format!(
            "[detection] WARN playbook #{} non activé : sa fenêtre n'a pas pu être lue pour juger le plancher, rien n'est écrit (Invalid column type Blob at index: 0, name: window_s)",
            ids[9]
        );
        assert_eq!(ae1_sans_identifiant(&lignes[0]), attendu, "phase fenetre : la ligne entière : {}", lignes[0]);
        let c = marque("AE1-IDS-ECRITURES:");
        let gestes = [
            "création d'une règle de détection".to_string(),
            format!("modification de la règle #{}", c[0]),
            "création d'un parseur".to_string(),
            format!("modification du parseur #{}", c[1]),
            "création d'une corrélation".to_string(),
            format!("modification de la corrélation #{}", c[2]),
            "création d'une référence UEBA".to_string(),
            format!("modification de la référence UEBA #{}", c[3]),
        ];
        assert!(gestes.len() >= 8, "plancher : les huit écritures");
        let lignes = phase("ecritures");
        assert_eq!(lignes.len(), gestes.len(), "phase ecritures : une ligne par écriture refusée : {lignes:?}");
        for (ligne, geste) in lignes.iter().zip(gestes.iter()) {
            let attendu = format!("[detection] WARN {geste} refusé : transaction d'audit annulée, aucune modification ({AE1_MOTEUR_ECRITURE})");
            assert_eq!(ae1_sans_identifiant(ligne), attendu, "phase ecritures : identifiant, puis la ligne entière : {ligne}");
        }
        assert!(phase("calme").is_empty(), "le nominal et les absences n'écrivent aucune ligne : {:?}", phase("calme"));
    }
}

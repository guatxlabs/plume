// =====================================================================================
// `P10.21-s` — UN SECOND FACTEUR QUE LA BASE N'A PAS CONSOMMÉ N'OUVRE AUCUNE SESSION, ET UNE DÉSACTIVATION
// QU'ELLE N'A PAS PRISE N'EST NI SERVIE NI ATTESTÉE.
// `P10.21-t` — UNE DÉCLARATION D'INCIDENT, UNE ATTACHE DE RUNBOOK ET UN SEMIS DE DÉMONSTRATION NE SONT
// ATTESTÉS QUE S'ILS SONT ÉCRITS — ET ILS SONT ÉCRITS ENTIERS OU PAS DU TOUT.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF (chaque témoin ci-dessous a été vu ROUGE sur la forme d'avant ;
// la ligne « LA MUTATION » de chacun dit comment le refaire) :
//  * `login_mfa_post` avalait l'`UPDATE user_mfa SET last_step` : sur une écriture refusée, le code juste
//    ouvrait la session (`200` + cookie) et le registre attestait « login local MFA validé », le pas restant
//    NON consommé — rejouable pendant sa fenêtre. Le code de secours avait le même geste dans
//    `recovery_consume` (`let _ = …; true`) : accepté, resté dans la liste ;
//  * la consommation n'était pas un compare-et-pose : la fraîcheur du pas était jugée sur une lecture faite
//    SOUS UN AUTRE VERROU que l'écriture, donc deux soumissions concurrentes du même code passaient toutes
//    deux ; le rejeu SÉQUENTIEL, lui, était déjà refusé quand l'écriture passait (témoin (2), vert avant) ;
//  * `mfa_disable` rendait `ok` et attestait « MFA TOTP désactivée » sur un `DELETE` avalé ;
//  * `incident_apply_tier` écrivait palier, type et pilote en trois `UPDATE` avalés : un type refusé laissait
//    un `204`, une chronologie qui NOMME le type, et un palier posé ;
//  * `attach_runbook` écrivait ses étapes en autocommit, `n += 1` compté quoi qu'il arrive : une étape
//    refusée laissait les précédentes en base, `{"attached": n}` servi, `steps={n}` au registre — et comme
//    l'attache REFUSE toute progression existante, l'amputation était DÉFINITIVE ;
//  * `seed_demo` posait son drapeau `seeded_demo` HORS transaction et AVANT les données, puis empruntait
//    `last_insert_rowid()` après un `INSERT` de dossier avalé : un dossier refusé laissait sa chronologie
//    rattachée à l'identifiant d'un ÉVÉNEMENT, et le drapeau interdisait tout nouveau semis.
//
// LES VOIES D'ÉCHEC : un AUTORISATEUR SQLite qui refuse une écriture désignée (`UPDATE`/`DELETE` d'une table,
// ou d'une seule colonne) et laisse passer toute lecture ; un DÉCLENCHEUR TEMPORAIRE qui refuse une ligne
// précise (la troisième étape, le second dossier de démonstration).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la course réelle entre deux requêtes concurrentes n'est pas jouée —
// le témoin (4) juge l'ÉNONCÉ de consommation (le compare-et-pose en base), qui est ce qui la ferme ; une
// base réellement en lecture seule ou un `SQLITE_BUSY` réel (l'autorisateur et le déclencheur les simulent) ;
// ce que la console peint des refus neufs ; la sortie d'erreur du semis de démonstration (son aveu).
// =====================================================================================
mod second_facteur_consomme_et_incident_compte {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const SFIC_GRAINE: &[u8] = b"12345678901234567890";

    async fn sfic_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    fn sfic_executer(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn sfic_compter(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// L'état mode 0 file-backed, `adm` porteur d'une MFA ACTIVE à la graine connue (`last_step = -1`) et de
    /// trois codes de secours dont les clairs sont rendus.
    fn sfic_etat_mfa(tag: &str) -> (AppState, crate::tmp_possede::TmpDb, String, Vec<String>) {
        let (st, p) = sp_state(&format!("sfic-{tag}"));
        let graine = base32_encode(SFIC_GRAINE);
        let (clairs, haches) = gen_recovery_codes(3).expect("fixture : entropie noyau");
        st.db
            .lock()
            .execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES('adm',?1,1,?2,-1,0,0)",
                params![graine, json!(haches).to_string()],
            )
            .expect("fixture : MFA active posée");
        (st, p, graine, clairs)
    }

    fn sfic_pas_courant() -> i64 {
        now() / 30
    }

    fn sfic_code(graine: &str, pas: i64) -> String {
        hotp(&base32_decode(graine).expect("graine base32"), pas as u64, 6)
    }

    /// Le second facteur tel qu'un navigateur le joue : un ticket frais de `login_post`, puis le code.
    /// Rend `(statut, session posée, corps)` — la session est jugée sur `Set-Cookie`, pas sur le statut.
    async fn sfic_second_facteur(st: &AppState, code: &str) -> (u16, bool, Value) {
        let (_, defi) = sfic_corps(mfa_challenge_response(st, "adm", "admin")).await;
        let ticket = defi["ticket"].as_str().expect("fixture : ticket de défi").to_string();
        let pair: std::net::SocketAddr = "127.0.0.1:45454".parse().expect("adresse de test");
        let r = login_mfa_post(State(st.clone()), ConnectInfo(pair), Json(json!({ "ticket": ticket, "code": code }))).await;
        let session = r.headers().get_all(header::SET_COOKIE).iter().count() > 0;
        let (statut, corps) = sfic_corps(r).await;
        (statut, session, corps)
    }

    fn sfic_connexions_attestees(st: &AppState) -> i64 {
        sfic_compter(st, "SELECT COUNT(*) FROM ledger WHERE kind='login' AND detail LIKE 'login local MFA validé%'")
    }

    fn sfic_dernier_pas(st: &AppState) -> i64 {
        sfic_compter(st, "SELECT last_step FROM user_mfa WHERE user='adm'")
    }

    fn sfic_recovery(st: &AppState) -> String {
        st.db.lock().query_row("SELECT recovery FROM user_mfa WHERE user='adm'", [], |r| r.get(0)).expect("fixture : recovery lisible")
    }

    /// L'ÉCRITURE REFUSÉE, LES LECTURES INTACTES : l'autorisateur refuse l'`UPDATE` (ou le `DELETE`) de `table`
    /// — d'une seule colonne si `colonne` est donnée — et laisse passer tout le reste, lectures comprises.
    fn sfic_refuser_l_ecriture(st: &AppState, geste: &'static str, table: &'static str, colonne: Option<&'static str>) {
        st.db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Update { table_name, column_name }
                if geste == "update" && table_name == table && colonne.map_or(true, |c| c == column_name) =>
            {
                Authorization::Deny
            }
            AuthAction::Delete { table_name } if geste == "delete" && table_name == table => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn sfic_lever_la_panne(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.21-s` — LE PAS TOTP NON CONSOMMÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un code TOTP JUSTE dont la consommation (`last_step`) est refusée par la base ne pose
    /// AUCUNE session, n'atteste AUCUNE connexion, et rend un `503` NOMMÉ ; le pas n'est pas brûlé — le MÊME
    /// code, la base revenue, ouvre la session (contrôle positif) et le pas est alors consommé.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rétablir `let _ = conn.execute("UPDATE user_mfa SET last_step…")` —
    /// la route rend `200` avec un cookie et le registre compte une connexion de plus (vu rouge avant le lot).
    #[tokio::test]
    async fn sfic_un_pas_totp_que_la_base_ne_consomme_pas_n_ouvre_aucune_session() {
        let (st, _p, graine, _) = sfic_etat_mfa("pas-refuse");
        let pas = sfic_pas_courant();
        let code = sfic_code(&graine, pas);
        let attestees = sfic_connexions_attestees(&st);

        sfic_refuser_l_ecriture(&st, "update", "user_mfa", None);
        let (statut, session, corps) = sfic_second_facteur(&st, &code).await;
        assert_eq!(statut, 503, "le pas n'est pas consommé : la connexion est REFUSÉE : {corps}");
        assert!(!session, "et SURTOUT aucune session n'est posée sur un pas rejouable");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_PAS_TOTP_NON_CONSOMME), "le refus NOMME sa cause : {corps}");
        sfic_lever_la_panne(&st);
        assert_eq!(sfic_connexions_attestees(&st), attestees, "le registre n'atteste AUCUNE connexion refusée");
        assert_eq!(sfic_dernier_pas(&st), -1, "rien n'est consommé");

        // CONTRÔLE POSITIF — le code n'a pas été brûlé : la base revenue, il ouvre la session, et il est consommé.
        let (statut, session, corps) = sfic_second_facteur(&st, &code).await;
        assert_eq!(statut, 200, "le même code, la base revenue, est accepté : {corps}");
        assert!(session, "contrôle positif : une session EST posée sur ce chemin");
        assert_eq!(sfic_connexions_attestees(&st), attestees + 1, "une connexion, une ligne de registre");
        assert_eq!(sfic_dernier_pas(&st), pas, "le pas accepté est consommé");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.21-s` — LE REJEU SÉQUENTIEL DU MÊME PAS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un pas accepté une fois est REFUSÉ au rejeu (`401`, aucune session, aucune trace), et
    /// un pas NEUF passe (contrôle positif). MESURÉ VERT AVANT LE LOT : quand l'écriture passait, le rejeu
    /// séquentiel était déjà refusé par la lecture de `last_step` ; ce témoin fixe la propriété que le lot ne
    /// doit pas perdre en déplaçant la consommation.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer la consommation du pas (le bloc `if let Some(step) = …`) — le
    /// rejeu rend `200` avec un cookie.
    #[tokio::test]
    async fn sfic_le_meme_pas_rejoue_apres_un_succes_est_refuse() {
        let (st, _p, graine, _) = sfic_etat_mfa("rejeu");
        let pas = sfic_pas_courant();
        let code = sfic_code(&graine, pas);

        let (statut, session, corps) = sfic_second_facteur(&st, &code).await;
        assert_eq!((statut, session), (200, true), "le premier usage ouvre la session : {corps}");
        let attestees = sfic_connexions_attestees(&st);

        let (statut, session, corps) = sfic_second_facteur(&st, &code).await;
        assert_eq!(statut, 401, "le MÊME pas rejoué est refusé : {corps}");
        assert!(!session, "aucune session sur un rejeu");
        assert_eq!(sfic_connexions_attestees(&st), attestees, "aucune connexion attestée sur un rejeu");

        // CONTRÔLE POSITIF — le pas SUIVANT (dans la fenêtre de dérive) est neuf, et passe.
        let (statut, session, corps) = sfic_second_facteur(&st, &sfic_code(&graine, pas + 1)).await;
        assert_eq!((statut, session), (200, true), "un pas neuf passe : {corps}");
        assert_eq!(sfic_dernier_pas(&st), pas + 1);
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.21-s` — LE CODE DE SECOURS NON CONSOMMÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un code de secours JUSTE que la base ne retire pas de la liste ne pose aucune session,
    /// rend un `503` nommé, et reste dans la liste ; la base revenue, il passe UNE fois et plus jamais.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rétablir `let _ = conn.execute("UPDATE user_mfa SET recovery…"); true`
    /// dans `recovery_consume` — la route rend `200` avec un cookie (vu rouge avant le lot).
    #[tokio::test]
    async fn sfic_un_code_de_secours_que_la_base_ne_retire_pas_n_ouvre_aucune_session() {
        let (st, _p, _graine, clairs) = sfic_etat_mfa("secours");
        let liste = sfic_recovery(&st);
        let attestees = sfic_connexions_attestees(&st);

        sfic_refuser_l_ecriture(&st, "update", "user_mfa", None);
        let (statut, session, corps) = sfic_second_facteur(&st, &clairs[0]).await;
        assert_eq!(statut, 503, "le code de secours n'est pas retiré : REFUS : {corps}");
        assert!(!session, "aucune session sur un code resté utilisable");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_CODE_DE_SECOURS_NON_CONSOMME), "{corps}");
        sfic_lever_la_panne(&st);
        assert_eq!(sfic_recovery(&st), liste, "la liste est intacte");
        assert_eq!(sfic_connexions_attestees(&st), attestees);

        // CONTRÔLE POSITIF — la base revenue, le code passe une fois, puis il est brûlé.
        let (statut, session, corps) = sfic_second_facteur(&st, &clairs[0]).await;
        assert_eq!((statut, session), (200, true), "le code de secours passe : {corps}");
        let (statut, session, corps) = sfic_second_facteur(&st, &clairs[0]).await;
        assert_eq!((statut, session), (401, false), "et ne resservira jamais : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.21-s` — LA CONSOMMATION DU PAS EST UN COMPARE-ET-POSE EN BASE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : l'énoncé qui consomme le pas REJUGE sa fraîcheur dans l'écriture. Le pas déjà posé en
    /// base — ce qu'une requête CONCURRENTE aurait écrit entre la lecture de `last_step` et cette écriture — et
    /// tout pas antérieur rendent `Refuse` ; un pas postérieur rend `Consomme` et il est posé ; une MFA qui n'est
    /// plus active refuse ; une base qui ne prend pas l'écriture rend `NonEcrite`, jamais `Consomme`.
    ///
    /// CE QU'IL NE TIENT PAS : la course elle-même (deux requêtes entrelacées entre lecture et écriture) n'est pas
    /// jouée — rien, dans un témoin, ne s'intercale entre deux instructions sans `await` d'un gestionnaire. Il
    /// juge l'énoncé que `login_mfa_post` emploie, et c'est lui qui ferme la course.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer `AND last_step<?1` de l'énoncé — le pas déjà consommé redevient
    /// `Consomme`, c'est-à-dire la seconde session d'une soumission concurrente.
    #[test]
    fn sfic_la_consommation_du_pas_rejuge_sa_fraicheur_dans_l_ecriture() {
        let (st, _p, _graine, _) = sfic_etat_mfa("compare-et-pose");
        sfic_executer(&st, "UPDATE user_mfa SET last_step=100 WHERE user='adm';");
        let c = st.db.lock();
        assert_eq!(consommer_le_pas_totp(&c, "adm", 100), ConsommationDuFacteur::Refuse, "le pas qu'un autre vient de consommer");
        assert_eq!(consommer_le_pas_totp(&c, "adm", 99), ConsommationDuFacteur::Refuse, "un pas antérieur");
        assert_eq!(consommer_le_pas_totp(&c, "adm", 101), ConsommationDuFacteur::Consomme, "contrôle positif : un pas postérieur");
        let pose: i64 = c.query_row("SELECT last_step FROM user_mfa WHERE user='adm'", [], |r| r.get(0)).expect("fixture");
        assert_eq!(pose, 101, "le pas consommé est posé");
        c.execute_batch("UPDATE user_mfa SET enabled=0 WHERE user='adm';").expect("fixture");
        assert_eq!(consommer_le_pas_totp(&c, "adm", 102), ConsommationDuFacteur::Refuse, "une MFA plus active ne consomme rien");
        c.execute_batch("UPDATE user_mfa SET enabled=1 WHERE user='adm'; ALTER TABLE user_mfa RENAME TO user_mfa_hors_d_atteinte;")
            .expect("fixture");
        assert!(
            matches!(consommer_le_pas_totp(&c, "adm", 103), ConsommationDuFacteur::NonEcrite(_)),
            "une écriture qui n'a pas lieu n'est jamais une consommation"
        );
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.21-s` — LA DÉSACTIVATION NON PRISE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une désactivation dont le `DELETE` est refusé rend un `503` nommé, le second facteur
    /// reste EN PLACE, et le registre n'atteste aucune désactivation ; la base revenue, elle aboutit et elle
    /// est attestée une fois (contrôle positif).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rétablir `let _ = conn.execute("DELETE FROM user_mfa…")` — la route rend
    /// `200 {"ok": true}` et le registre dit « désactivée » sur un compte qui exige toujours son code.
    #[tokio::test]
    async fn sfic_une_desactivation_que_la_base_ne_prend_pas_n_est_ni_servie_ni_attestee() {
        let (st, _p, graine, _) = sfic_etat_mfa("desactivation");
        let au = sp_au("adm", "admin");
        let desactivees = || sfic_compter(&st, "SELECT COUNT(*) FROM ledger WHERE kind='mfa' AND detail LIKE 'MFA TOTP désactivée%'");
        let code = sfic_code(&graine, sfic_pas_courant());

        sfic_refuser_l_ecriture(&st, "delete", "user_mfa", None);
        let (statut, corps) = sfic_corps(mfa_disable(State(st.clone()), Extension(au.clone()), Json(json!({ "code": code }))).await).await;
        assert_eq!(statut, 503, "le DELETE est refusé : la désactivation est REFUSÉE : {corps}");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_MFA_NON_DESACTIVEE), "{corps}");
        sfic_lever_la_panne(&st);
        assert_eq!(sfic_compter(&st, "SELECT COUNT(*) FROM user_mfa WHERE user='adm' AND enabled=1"), 1, "le second facteur est EN PLACE");
        assert_eq!(desactivees(), 0, "le registre n'atteste aucune désactivation");

        // CONTRÔLE POSITIF — la base revenue, la désactivation aboutit et elle est attestée.
        let (statut, corps) = sfic_corps(mfa_disable(State(st.clone()), Extension(au), Json(json!({ "code": code }))).await).await;
        assert_eq!(statut, 200, "{corps}");
        assert_eq!(sfic_compter(&st, "SELECT COUNT(*) FROM user_mfa WHERE user='adm'"), 0);
        assert_eq!(desactivees(), 1);
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.21-t` — LA DÉCLARATION D'INCIDENT
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une déclaration dont l'écriture du TYPE est refusée n'écrit RIEN — ni palier, ni pilote
    /// —, rend un `503` nommé, et ni la chronologie ni le registre ne la portent ; la base revenue, palier,
    /// type et pilote sont posés, nommés et attestés une fois (contrôle positif).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rétablir les trois `let _ = conn.execute("UPDATE incident SET …")` —
    /// la route rend `204`, le palier et le pilote sont posés, le type non, et la chronologie écrit
    /// « type intrusion » (vu rouge avant le lot).
    #[tokio::test]
    async fn sfic_une_declaration_d_incident_non_ecrite_n_est_ni_servie_ni_attestee() {
        let (st, _p) = sp_state("sfic-incident");
        let au = sp_au("alice", "editor");
        let id = dossier_seme(&st.db.lock(), "alice", "Scan suspect", 3, "", None, 3);
        let corps_demande = json!({ "tier": 2, "incident_type": "intrusion", "commander": "carol" });
        let declaration = |st: &AppState| -> (Option<i64>, Option<String>, Option<String>) {
            st.db
                .lock()
                .query_row("SELECT incident_tier,incident_type,commander FROM incident WHERE id=?1", params![id], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .expect("fixture : dossier lisible")
        };
        let traces = |st: &AppState| {
            (
                sfic_compter(st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id} AND kind='incident'")),
                sfic_compter(st, "SELECT COUNT(*) FROM ledger WHERE kind='case.incident'"),
            )
        };

        sfic_refuser_l_ecriture(&st, "update", "incident", Some("incident_type"));
        let r = incident_set(State(st.clone()), Extension(au.clone()), Path(id), Json(corps_demande.clone())).await.into_response();
        let (statut, corps) = sfic_corps(r).await;
        sfic_lever_la_panne(&st);
        assert_eq!(statut, 503, "le type n'est pas écrit : la déclaration est REFUSÉE : {corps}");
        assert!(
            corps["error"].as_str().unwrap_or("").starts_with(crate::handlers::incidents::CAUSE_DECLARATION_D_INCIDENT_NON_ECRITE),
            "le refus NOMME sa cause : {corps}"
        );
        assert_eq!(declaration(&st), (None, None, None), "RIEN n'est écrit : ni palier, ni type, ni pilote");
        assert_eq!(traces(&st), (0, 0), "ni la chronologie ni le registre ne portent la déclaration");

        // CONTRÔLE POSITIF — la base revenue, tout est posé, nommé et attesté une fois.
        let r = incident_set(State(st.clone()), Extension(au), Path(id), Json(corps_demande)).await.into_response();
        assert_eq!(r.status().as_u16(), 204);
        assert_eq!(declaration(&st), (Some(2), Some("intrusion".into()), Some("carol".into())));
        assert_eq!(traces(&st), (1, 1));
    }

    // -------------------------------------------------------------------------------------
    // (7) `P10.21-t` — L'ATTACHE DE RUNBOOK
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une attache dont la TROISIÈME étape est refusée ne laisse AUCUNE étape en base, rend un
    /// `503` nommé, et n'est ni dans la chronologie ni au registre — puis, la base revenue, l'attache n'est PAS
    /// bloquée par une progression fantôme : elle aboutit avec TOUTES les étapes, et le registre les compte.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rétablir `let _ = conn.execute("INSERT INTO case_step…"); n += 1;` sans
    /// transaction — la route rend `200 {"attached": n}` avec deux étapes en base, `steps={n}` au registre, et
    /// l'attache suivante est refusée (« progression existante ») : l'amputation est DÉFINITIVE (vu rouge avant
    /// le lot).
    #[tokio::test]
    async fn sfic_une_attache_de_runbook_amputee_n_est_ni_posee_ni_attestee() {
        let (st, _p) = sp_state("sfic-attache");
        let au = sp_au("alice", "editor");
        let (id, rb, etapes) = {
            let c = st.db.lock();
            seed_runbooks(&c);
            let id = dossier_seme(&c, "alice", "exploit", 4, "", None, 2);
            let rb = pick_runbook_id(&c, None, None).expect("lecture faite").expect("fixture : un runbook générique");
            let etapes: i64 = c.query_row("SELECT COUNT(*) FROM runbook_step WHERE runbook_id=?1", params![rb], |r| r.get(0)).expect("fixture");
            (id, rb, etapes)
        };
        assert!(etapes >= 3, "fixture : il faut au moins trois étapes pour en refuser la troisième ({etapes})");
        let posees = |st: &AppState| sfic_compter(st, &format!("SELECT COUNT(*) FROM case_step WHERE incident_id={id}"));
        let traces = |st: &AppState| {
            (
                sfic_compter(st, &format!("SELECT COUNT(*) FROM incident_item WHERE incident_id={id} AND kind='runbook'")),
                sfic_compter(st, "SELECT COUNT(*) FROM ledger WHERE kind='case.runbook_attach'"),
            )
        };

        sfic_executer(
            &st,
            "CREATE TEMP TRIGGER sfic_troisieme_etape_refusee BEFORE INSERT ON case_step \
             WHEN (SELECT COUNT(*) FROM case_step WHERE incident_id=NEW.incident_id) >= 2 \
             BEGIN SELECT RAISE(ABORT, 'troisième étape refusée par le témoin'); END;",
        );
        let r = case_runbook_attach(State(st.clone()), Extension(au.clone()), Path(id), Json(json!({ "runbook_id": rb }))).await;
        let (statut, corps) = sfic_corps(r).await;
        assert_eq!(statut, 503, "une étape n'est pas écrite : l'attache est REFUSÉE : {corps}");
        assert!(
            corps["error"].as_str().unwrap_or("").starts_with(crate::handlers::incidents::CAUSE_ETAPES_DU_RUNBOOK_NON_ECRITES),
            "le refus NOMME sa cause : {corps}"
        );
        assert_eq!(posees(&st), 0, "AUCUNE étape en base : l'attache est entière ou n'est pas");
        assert_eq!(traces(&st), (0, 0), "ni la chronologie ni le registre ne portent l'attache");
        assert!(st.db.lock().is_autocommit(), "aucune transaction laissée ouverte sur l'écrivain");

        // CONTRÔLE POSITIF — la base revenue, rien ne bloque l'attache, et elle est ENTIÈRE.
        sfic_executer(&st, "DROP TRIGGER sfic_troisieme_etape_refusee;");
        let r = case_runbook_attach(State(st.clone()), Extension(au), Path(id), Json(json!({ "runbook_id": rb }))).await;
        let (statut, corps) = sfic_corps(r).await;
        assert_eq!(statut, 200, "l'attache aboutit : aucune progression fantôme ne la bloque : {corps}");
        assert_eq!(corps["attached"], json!(etapes), "{corps}");
        assert_eq!(posees(&st), etapes, "toutes les étapes, pas une de moins");
        assert_eq!(traces(&st), (1, 1));
        assert_eq!(
            sfic_compter(&st, &format!("SELECT COUNT(*) FROM ledger WHERE kind='case.runbook_attach' AND detail LIKE '%steps={etapes} %'")),
            1,
            "le registre compte les étapes ÉCRITES"
        );
    }

    // -------------------------------------------------------------------------------------
    // (8) `P10.21-t` — LE SEMIS DE DÉMONSTRATION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un semis de démonstration dont le second dossier est refusé ne laisse RIEN — ni
    /// drapeau `seeded_demo`, ni dossier, ni élément de chronologie ORPHELIN (rattaché à l'identifiant
    /// emprunté d'une autre ligne) —, donc il est RETENTÉ au démarrage suivant ; la base revenue, il sème les
    /// deux dossiers avec leurs chronologies, sans orphelin, et pose son drapeau (contrôle positif).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rétablir le drapeau hors transaction et `let ca/cb =
    /// conn.last_insert_rowid()` après un `INSERT` avalé — le drapeau est posé, le dossier A est là, et les
    /// éléments du dossier B sont rattachés à l'identifiant d'un ÉVÉNEMENT (vu rouge avant le lot).
    #[test]
    fn sfic_un_semis_de_demonstration_refuse_ne_laisse_ni_drapeau_ni_orphelin() {
        let conn = test_db();
        let compter = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("`{sql}` ({e})")) };
        let drapeau = "SELECT COUNT(*) FROM meta WHERE key='seeded_demo'";
        let dossiers = "SELECT COUNT(*) FROM incident";
        let orphelins = "SELECT COUNT(*) FROM incident_item WHERE incident_id NOT IN (SELECT id FROM incident)";

        conn.execute_batch(
            "CREATE TEMP TRIGGER sfic_second_dossier_refuse BEFORE INSERT ON incident \
             WHEN NEW.title LIKE 'Scan de ports%' \
             BEGIN SELECT RAISE(ABORT, 'second dossier de démonstration refusé par le témoin'); END;",
        )
        .expect("fixture : déclencheur posé");
        semer_la_demonstration(&conn);
        assert_eq!(compter(orphelins), 0, "aucun élément de chronologie rattaché à un identifiant emprunté");
        assert_eq!(compter(dossiers), 0, "le semis est entier ou n'est pas : aucun dossier");
        assert_eq!(compter(drapeau), 0, "aucun drapeau : le semis sera retenté");
        assert_eq!(compter("SELECT COUNT(*) FROM event"), 0, "aucun événement de démonstration");

        // CONTRÔLE POSITIF — la base revenue, le semis aboutit entier, et une seule fois.
        conn.execute_batch("DROP TRIGGER sfic_second_dossier_refuse;").expect("fixture");
        semer_la_demonstration(&conn);
        assert_eq!(compter(dossiers), 2, "les deux dossiers de démonstration");
        assert_eq!(compter(orphelins), 0, "aucun orphelin");
        assert!(
            compter("SELECT COUNT(*) FROM incident_item i JOIN incident c ON c.id=i.incident_id WHERE c.title LIKE 'Scan de ports%'") >= 5,
            "le second dossier porte sa chronologie"
        );
        assert_eq!(compter(drapeau), 1, "le drapeau est posé avec les données");
        let evenements = compter("SELECT COUNT(*) FROM event");
        semer_la_demonstration(&conn);
        assert_eq!((compter(dossiers), compter("SELECT COUNT(*) FROM event")), (2, evenements), "une seule fois");
    }
}

// =====================================================================================
// `P10.21-m` — L'ÉVÉNEMENT D'AUDIT D'UN TENANT REND SON ISSUE, ET LA SUSPENSION LIT EN TROIS ISSUES.
// `P10.30-d` (reste de `grant_set`) — LA POSE DE DROIT NON ÉCRITE EST UN 503 NOMMÉ, SANS LA CAUSE DU MOTEUR.
//
// LE DÉFAUT, MESURÉ AVANT LE CORRECTIF. `audit_tenant_event_sur` écrivait l'événement `plume-tenant-admin`
// sous `let _ = conn.execute(…)` : une base du tenant qui refusait l'`INSERT` laissait la réponse (deux
// cents, deux cent un, deux cent quatre) et le journal de contrôle dire le geste, et le tenant ne le voyait
// jamais parmi ses propres événements, sans un mot nulle part. La suspension lisait l'existence du tenant
// par `.is_ok()` : une table illisible rendait quatre cent quatre « tenant inconnu ». `grant_set` servait
// `500 échec du grant: <cause du moteur>` sur ses bras d'écriture refusée.
//
// CE QUI ÉTAIT FAUX DANS L'ÉNONCÉ DE `P10.21-m` : « suspension ET retrait de droit servent “inconnu” quand
// leur lecture préalable échoue ». Le retrait de droit ne le fait plus depuis `P10.21-r`/`P10.21-u` (lecture
// `.optional()` dans la transaction du geste, 503 `CAUSE_DROIT_NON_LU_RETRAIT_NON_FAIT`, témoin dans
// `frein_durable_du_second_facteur_et_refus_nommes.rs`). Seule la suspension restait.
//
// LES VOIES D'ÉCHEC : un DÉCLENCHEUR TEMPORAIRE posé sur la connexion d'écriture du tenant (celle que
// `handle_for` rend, en cache) qui refuse le seul `INSERT` `plume-tenant-admin` ; la TABLE `tenant` RETIRÉE
// (renommée) au plan de contrôle pour la lecture de la suspension ; une VUE TEMPORAIRE sur `"grant"` et une
// transaction déjà ouverte sur la connexion du plan de contrôle pour la pose de droit ; un déclencheur
// temporaire `RAISE(IGNORE)` qui écarte l'événement SANS erreur (zéro ligne écrite).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ils éprouvent un déclencheur et un objet non modifiable, pas une base
// réellement pleine ou en lecture seule (le chemin refusé est le même) ; le `COMMIT` refusé de la pose de
// droit n'est pas joué (il partage son bras avec le `BEGIN` refusé, qui l'est) ; une base de tenant NON
// SERVIE (tenant suspendu, clé non résoluble) n'est pas avouée — limite écrite dans
// `EvenementDAuditDuTenant::SansBaseServie`, forme d'avant inchangée ; la console ne lit pas encore la clé
// `evenement_du_tenant_non_ecrit` (web/ hors de ce lot) ; le refus `Materialisation` de `grant_set` (compte
// plateforme non créé, `ensure_platform_user_conn` rend `None` par `.ok()?`) reste un 500 à phrase fixe
// « échec de matérialisation du compte plateforme » — sans cause du moteur, mais ni 503 ni nommé, et non
// témoigné : LIMITE ÉCRITE, la cause du moteur y est perdue avant le gestionnaire.
// =====================================================================================
mod audit_tenant_ecriture_comptee_et_suspension_trois_issues {
    use super::*;

    fn atec_plan(st: &AppState, sql: &str) {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .execute_batch(sql)
            .unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    /// Le texte EXACT que le moteur rend pour `sql` sur la connexion du plan de contrôle : le témoin de `grant_set`
    /// le cherche dans le corps entier, il ne devine pas une phrase.
    fn atec_erreur_du_plan(st: &AppState, sql: &str) -> String {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .execute(sql, [])
            .map(|n| panic!("fixture : `{sql}` doit être refusé par le moteur (il a écrit {n} ligne(s))"))
            .unwrap_err()
            .to_string()
    }

    fn atec_compte_plan(st: &AppState, sql: &str) -> i64 {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .query_row(sql, [], |r| r.get(0))
            .unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn atec_maillons(st: &AppState, genre: &str) -> i64 {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM control_ledger WHERE kind=?1", params![genre], |r| r.get(0))
            .expect("fixture : le journal de contrôle se lit")
    }

    fn atec_super_admin() -> AuthUser {
        AuthUser {
            name: "op-atec".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: true,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    /// Le déclencheur TEMPORAIRE qui refuse l'événement d'audit sur la connexion d'écriture du tenant.
    const ATEC_REFUS_DE_L_EVENEMENT: &str = "CREATE TEMP TRIGGER atec_refus BEFORE INSERT ON main.event \
         WHEN NEW.source='plume-tenant-admin' BEGIN SELECT RAISE(ABORT, 'atec : evenement refuse'); END;";
    const ATEC_REFUS_RETIRE: &str = "DROP TRIGGER temp.atec_refus;";

    /// Le déclencheur TEMPORAIRE qui ÉCARTE l'événement sans erreur : `RAISE(IGNORE)` laisse l'`INSERT` réussir avec
    /// ZÉRO ligne écrite (`Ok(0)`), le bras « compté » de `audit_tenant_event_sur`.
    const ATEC_EVENEMENT_ECARTE: &str = "CREATE TEMP TRIGGER atec_ecarte BEFORE INSERT ON main.event \
         WHEN NEW.source='plume-tenant-admin' BEGIN SELECT RAISE(IGNORE); END;";
    const ATEC_ECARTE_RETIRE: &str = "DROP TRIGGER temp.atec_ecarte;";

    fn atec_base_du_tenant(st: &AppState, tenant: &str, sql: &str) {
        let h = st.tenants.handle_for(tenant).expect("fixture : la base du tenant se résout");
        h.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn atec_evenements(st: &AppState, tenant: &str, action: &str) -> i64 {
        let h = st.tenants.handle_for(tenant).expect("fixture : la base du tenant se résout");
        let c = h.lock();
        c.query_row(
            "SELECT COUNT(*) FROM event WHERE source='plume-tenant-admin' AND json_extract(fields,'$.action')=?1",
            params![action],
            |r| r.get(0),
        )
        .expect("fixture : les événements du tenant se lisent")
    }

    fn atec_aveu(v: &Value) -> Option<&str> {
        v.get(CLE_EVENEMENT_DU_TENANT_NON_ECRIT).and_then(|x| x.as_str())
    }

    async fn atec_creer(st: &AppState, corps: Value) -> (u16, Value) {
        pb_json(tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(atec_super_admin()), Json(corps)).await).await
    }

    async fn atec_poser(st: &AppState, tenant: &str, user: &str, role: &str) -> (u16, Value) {
        pb_json(
            grant_set(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(atec_super_admin()), Path(tenant.into()), Json(json!({ "user": user, "role": role })))
                .await,
        )
        .await
    }

    // -------------------------------------------------------------------------------------
    // (1) LA SUSPENSION — présent, absent (404), illisible (503 nommé).
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la table `tenant` retirée du plan de contrôle, `POST /suspend` ET `POST /unsuspend` rendent
    /// un 503 dont l'erreur est EXACTEMENT `CAUSE_TENANT_NON_LU_BASCULE_NON_FAITE` — jamais « tenant inconnu » ;
    /// aucun maillon `tenant.suspend`/`tenant.unsuspend` ; le tenant (table remise) n'est pas suspendu. Contrôle
    /// positif : table remise, un tenant absent rend 404 « tenant inconnu », le tenant présent se suspend (200).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : mutant `atec_lecture_is_ok` (la lecture ratée servie comme l'absence,
    /// la forme `.is_ok()` d'avant) — 404 « tenant inconnu » au lieu du 503.
    #[tokio::test]
    async fn atec_une_suspension_dont_la_lecture_du_tenant_echoue_refuse_en_503_nomme() {
        let (st, _dir) = mk_mode1_state();
        let sa = atec_super_admin();
        let (statut, v) = atec_creer(&st, json!({ "id": "atec-susp", "name": "AtecSusp" })).await;
        assert_eq!(statut, 201, "fixture : {v}");

        atec_plan(&st, "ALTER TABLE tenant RENAME TO tenant_source;");
        for (geste, reponse) in [
            ("suspend", tenant_suspend(State(st.clone()), Extension(sa.clone()), Path("atec-susp".into())).await),
            ("unsuspend", tenant_unsuspend(State(st.clone()), Extension(sa.clone()), Path("atec-susp".into())).await),
        ] {
            let (statut, v) = pb_json(reponse).await;
            assert_eq!(statut, 503, "{geste} : une lecture NON FAITE n'est pas « tenant inconnu » : {v}");
            assert_eq!(v["error"], json!(CAUSE_TENANT_NON_LU_BASCULE_NON_FAITE), "{geste} : SA cause, nommée : {v}");
        }
        assert_eq!(atec_maillons(&st, "tenant.suspend") + atec_maillons(&st, "tenant.unsuspend"), 0, "rien n'est tracé");
        atec_plan(&st, "ALTER TABLE tenant_source RENAME TO tenant;");
        assert_eq!(atec_compte_plan(&st, "SELECT suspended FROM tenant WHERE id='atec-susp'"), 0, "ÉTAT RELU : le tenant n'est pas suspendu");

        // CONTRÔLE POSITIF — l'absence ÉTABLIE reste un 404, le tenant présent se suspend.
        let (statut, v) = pb_json(tenant_suspend(State(st.clone()), Extension(sa.clone()), Path("atec-absent".into())).await).await;
        assert_eq!((statut, v.get("_texte").and_then(|x| x.as_str())), (404, Some("tenant inconnu")), "{v}");
        let (statut, v) = pb_json(tenant_suspend(State(st.clone()), Extension(sa.clone()), Path("atec-susp".into())).await).await;
        assert_eq!((statut, v.get("suspended").and_then(|x| x.as_bool())), (200, Some(true)), "{v}");
    }

    // -------------------------------------------------------------------------------------
    // (2) L'ÉVÉNEMENT DU TENANT REFUSÉ — pose, retrait, suspension, réactivation : le geste fait, l'aveu à côté.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la base du tenant refusant l'événement `plume-tenant-admin`, la pose de droit rend 200 AVEC
    /// `evenement_du_tenant_non_ecrit` (= `CAUSE_EVENEMENT_DU_TENANT_NON_ECRIT`, sans la cause du moteur), le droit
    /// est posé et attesté au journal de contrôle ; le retrait rend 200 (plus le 204 nu) avec `removed` et l'aveu,
    /// le droit est retiré ; la suspension (poignée prise avant la bascule) et la réactivation rendent 200 avec
    /// l'aveu, la bascule écrite n'est PAS annulée ; aucun de ces événements n'est entré. Contrôle positif : le
    /// déclencheur retiré, les mêmes gestes n'avouent rien, le retrait est un 204 nu, chaque événement entre une fois.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : mutant `atec_evenement_avale` (l'`INSERT` refusé lu comme écrit, la forme
    /// `let _ =` d'avant) — aucun aveu ; mutant `atec_retrait_204` (la perte de l'événement ignorée au choix du
    /// 204) — le retrait rend un 204 nu sur un événement perdu.
    #[tokio::test]
    async fn atec_un_evenement_de_tenant_refuse_est_avoue_a_cote_du_geste_fait() {
        let (st, _dir) = mk_mode1_state();
        let sa = atec_super_admin();
        let (statut, v) = atec_creer(&st, json!({ "id": "atec-evt", "name": "AtecEvt" })).await;
        assert_eq!(statut, 201, "fixture : {v}");
        atec_base_du_tenant(&st, "atec-evt", ATEC_REFUS_DE_L_EVENEMENT);

        let (statut, v) = atec_poser(&st, "atec-evt", "erin", "editor").await;
        assert_eq!(statut, 200, "pose : le droit est écrit, le geste est un succès : {v}");
        assert_eq!(atec_aveu(&v), Some(CAUSE_EVENEMENT_DU_TENANT_NON_ECRIT), "pose : l'événement perdu est AVOUÉ : {v}");
        assert!(!v.to_string().contains("atec : evenement refuse"), "pose : la cause du moteur ne sort pas dans le corps : {v}");
        assert_eq!(count_grant(&st, "atec-evt", "erin"), 1, "pose : le droit est en place");
        assert_eq!(atec_maillons(&st, "grant.set"), 1, "pose : le journal de contrôle l'atteste");

        let (statut, v) = pb_json(grant_delete(State(st.clone()), Extension(sa.clone()), Path(("atec-evt".into(), "erin".into()))).await).await;
        assert_eq!((statut, v.get("removed").and_then(|x| x.as_bool())), (200, Some(true)), "retrait : un 204 ne peut rien avouer : {v}");
        assert_eq!(atec_aveu(&v), Some(CAUSE_EVENEMENT_DU_TENANT_NON_ECRIT), "retrait : l'événement perdu est AVOUÉ : {v}");
        assert_eq!(count_grant(&st, "atec-evt", "erin"), 0, "retrait : le droit est retiré");

        let (statut, v) = pb_json(tenant_suspend(State(st.clone()), Extension(sa.clone()), Path("atec-evt".into())).await).await;
        assert_eq!((statut, v.get("suspended").and_then(|x| x.as_bool())), (200, Some(true)), "suspension : la bascule écrite reste faite : {v}");
        assert_eq!(atec_aveu(&v), Some(CAUSE_EVENEMENT_DU_TENANT_NON_ECRIT), "suspension : l'événement perdu est AVOUÉ : {v}");
        assert_eq!(atec_compte_plan(&st, "SELECT suspended FROM tenant WHERE id='atec-evt'"), 1, "suspension : le tenant EST suspendu");
        let (statut, v) = pb_json(tenant_unsuspend(State(st.clone()), Extension(sa.clone()), Path("atec-evt".into())).await).await;
        assert_eq!((statut, v.get("suspended").and_then(|x| x.as_bool())), (200, Some(false)), "réactivation : {v}");
        assert_eq!(atec_aveu(&v), Some(CAUSE_EVENEMENT_DU_TENANT_NON_ECRIT), "réactivation : l'événement perdu est AVOUÉ : {v}");
        for action in ["grant.set", "grant.remove", "tenant.suspend", "tenant.unsuspend"] {
            assert_eq!(atec_evenements(&st, "atec-evt", action), 0, "BASE DU TENANT : `{action}` n'y est pas entré — c'est ce que l'aveu dit");
        }

        // CONTRÔLE POSITIF — le déclencheur retiré, les mêmes gestes n'avouent rien et leur événement entre.
        atec_base_du_tenant(&st, "atec-evt", ATEC_REFUS_RETIRE);
        let (statut, v) = atec_poser(&st, "atec-evt", "erin", "editor").await;
        assert_eq!((statut, atec_aveu(&v)), (200, None), "{v}");
        let r = grant_delete(State(st.clone()), Extension(sa.clone()), Path(("atec-evt".into(), "erin".into()))).await;
        assert_eq!(r.status(), StatusCode::NO_CONTENT, "le chemin nominal du retrait reste un 204 SANS corps");
        let (statut, v) = pb_json(tenant_suspend(State(st.clone()), Extension(sa.clone()), Path("atec-evt".into())).await).await;
        assert_eq!((statut, atec_aveu(&v)), (200, None), "{v}");
        let (statut, v) = pb_json(tenant_unsuspend(State(st.clone()), Extension(sa.clone()), Path("atec-evt".into())).await).await;
        assert_eq!((statut, atec_aveu(&v)), (200, None), "{v}");
        for action in ["grant.set", "grant.remove", "tenant.suspend", "tenant.unsuspend"] {
            assert_eq!(atec_evenements(&st, "atec-evt", action), 1, "BASE DU TENANT : `{action}` entre une fois");
        }
    }

    // -------------------------------------------------------------------------------------
    // (3) LA CRÉATION DE TENANT — deux cent un, et l'aveu de l'événement perdu.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un tenant recréé sur SA base existante (sa ligne de catalogue retirée, la même clé
    /// fournie en `key_ref`), dont la connexion d'écriture en cache refuse l'événement : la création rend 201 avec
    /// `evenement_du_tenant_non_ecrit`, le tenant existe et son maillon `tenant.create` entre. Contrôle positif :
    /// le déclencheur retiré, la même recréation rend 201 sans aveu et l'événement entre.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : mutant `atec_evenement_avale` — 201 sans aveu sur un événement perdu.
    #[tokio::test]
    async fn atec_une_creation_de_tenant_avoue_l_evenement_non_ecrit() {
        let (st, _dir) = mk_mode1_state();
        let (statut, v) = atec_creer(&st, json!({ "id": "atec-cree", "name": "AtecCree" })).await;
        assert_eq!(statut, 201, "fixture : {v}");
        let cle: String = st
            .tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .query_row("SELECT key_ref FROM tenant WHERE id='atec-cree'", [], |r| r.get(0))
            .expect("fixture : la clé du tenant se lit");
        atec_base_du_tenant(&st, "atec-cree", ATEC_REFUS_DE_L_EVENEMENT);

        atec_plan(&st, "DELETE FROM tenant WHERE id='atec-cree';");
        let (statut, v) = atec_creer(&st, json!({ "id": "atec-cree", "name": "AtecCree", "key_ref": cle })).await;
        assert_eq!(statut, 201, "le tenant est provisionné : refuser mentirait : {v}");
        assert_eq!(atec_aveu(&v), Some(CAUSE_EVENEMENT_DU_TENANT_NON_ECRIT), "l'événement perdu est AVOUÉ à côté du 201 : {v}");
        assert_eq!(atec_compte_plan(&st, "SELECT COUNT(*) FROM tenant WHERE id='atec-cree'"), 1, "le tenant existe");
        assert_eq!(atec_maillons(&st, "tenant.create"), 2, "et le journal de contrôle atteste les deux créations");
        assert_eq!(atec_evenements(&st, "atec-cree", "tenant.create"), 1, "BASE DU TENANT : seule la première création y est");

        // CONTRÔLE POSITIF — le déclencheur retiré, la même recréation n'avoue rien.
        atec_base_du_tenant(&st, "atec-cree", ATEC_REFUS_RETIRE);
        atec_plan(&st, "DELETE FROM tenant WHERE id='atec-cree';");
        let (statut, v) = atec_creer(&st, json!({ "id": "atec-cree", "name": "AtecCree", "key_ref": cle })).await;
        assert_eq!((statut, atec_aveu(&v)), (201, None), "{v}");
        assert_eq!(atec_evenements(&st, "atec-cree", "tenant.create"), 2, "BASE DU TENANT : la création y entre");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.30-d` — LA POSE DE DROIT NON ÉCRITE : 503 nommé, la cause du moteur hors du corps.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sous la vue temporaire sur `"grant"` (l'`INSERT` refusé, bras `NonEcrit`) PUIS sous une
    /// transaction déjà ouverte sur la connexion du plan de contrôle (le `BEGIN` refusé, bras `NonOuvert`), la pose
    /// rend 503 dont l'erreur est EXACTEMENT `CAUSE_DROIT_NON_POSE` — aucun mot du moteur dans le corps ; aucun
    /// droit, aucun maillon `grant.set`. Contrôle positif : la vue retirée, la transaction annulée, la même pose
    /// passe (200).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : mutant `atec_cause_moteur_exposee` (la forme d'avant, 500
    /// `échec du grant: <cause du moteur>`) ; mutant `atec_cause_en_detail` (le 503 nommé, la cause du moteur glissée
    /// dans un champ `detail`).
    #[tokio::test]
    async fn atec_une_pose_de_droit_non_ecrite_est_un_503_nomme_sans_la_cause_du_moteur() {
        let (st, _dir) = mk_mode1_state();
        let (statut, v) = atec_creer(&st, json!({ "id": "atec-droit", "name": "AtecDroit" })).await;
        assert_eq!(statut, 201, "fixture : {v}");

        atec_plan(&st, "ALTER TABLE \"grant\" RENAME TO \"grant_source\"; CREATE TEMP VIEW \"grant\" AS SELECT * FROM \"grant_source\";");
        let (statut, v) = atec_poser(&st, "atec-droit", "erin", "editor").await;
        assert_eq!(statut, 503, "INSERT refusé : un refus d'écriture n'est pas une panne interne : {v}");
        assert_eq!(v["error"], json!(CAUSE_DROIT_NON_POSE), "INSERT refusé : la phrase nommée, ET RIEN D'AUTRE : {v}");
        assert!(!v.to_string().contains("échec du grant"), "INSERT refusé : plus la forme d'avant : {v}");
        // AUCUN MOT DU MOTEUR, dans AUCUN champ : le texte que SQLite rend pour cet INSERT, relu sur la même connexion.
        let moteur = atec_erreur_du_plan(&st, "INSERT OR REPLACE INTO \"grant\"(user_id,tenant_id,role) VALUES('pu_atec','atec-droit','editor')");
        assert!(moteur.contains("cannot modify grant because it is a view"), "fixture : le refus du moteur est celui attendu : {moteur}");
        assert!(!v.to_string().contains(&moteur), "INSERT refusé : la cause du moteur ne sort dans aucun champ du corps : {v}");
        atec_plan(&st, "DROP VIEW \"grant\"; ALTER TABLE \"grant_source\" RENAME TO \"grant\";");
        assert_eq!(count_grant(&st, "atec-droit", "erin"), 0, "INSERT refusé : aucun droit posé");

        atec_plan(&st, "BEGIN;");
        let (statut, v) = atec_poser(&st, "atec-droit", "erin", "editor").await;
        let moteur = atec_erreur_du_plan(&st, "BEGIN");
        atec_plan(&st, "ROLLBACK;");
        assert_eq!(statut, 503, "BEGIN refusé : {v}");
        assert_eq!(v["error"], json!(CAUSE_DROIT_NON_POSE), "BEGIN refusé : la phrase nommée, ET RIEN D'AUTRE : {v}");
        assert!(moteur.contains("cannot start a transaction within a transaction"), "fixture : le refus du moteur est celui attendu : {moteur}");
        assert!(!v.to_string().contains(&moteur), "BEGIN refusé : la cause du moteur ne sort dans aucun champ du corps : {v}");
        assert_eq!(count_grant(&st, "atec-droit", "erin"), 0, "BEGIN refusé : aucun droit posé");
        assert_eq!(atec_maillons(&st, "grant.set"), 0, "aucune pose n'est attestée");

        // CONTRÔLE POSITIF — la même pose passe.
        let (statut, v) = atec_poser(&st, "atec-droit", "erin", "editor").await;
        assert_eq!(statut, 200, "{v}");
        assert_eq!(count_grant(&st, "atec-droit", "erin"), 1, "le droit est posé");
    }

    // -------------------------------------------------------------------------------------
    // (5) L'ÉVÉNEMENT ÉCARTÉ SANS ERREUR — zéro ligne écrite est une perte, pas un succès.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la connexion d'écriture du tenant écarte l'événement par `RAISE(IGNORE)` (l'`INSERT` rend
    /// `Ok(0)`, sans erreur — fixture vérifiée sur la même connexion) : la pose de droit rend 200 AVEC
    /// `evenement_du_tenant_non_ecrit`, le droit est posé, l'événement n'est pas entré. Contrôle positif : le
    /// déclencheur retiré, la même pose n'avoue rien et l'événement entre.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : mutant `atec_zero_ligne_ecrite` (`Ok(n)` quel que soit `n` lu comme écrit).
    #[tokio::test]
    async fn atec_un_evenement_de_tenant_ecarte_sans_erreur_est_avoue() {
        let (st, _dir) = mk_mode1_state();
        let (statut, v) = atec_creer(&st, json!({ "id": "atec-ecarte", "name": "AtecEcarte" })).await;
        assert_eq!(statut, 201, "fixture : {v}");
        atec_base_du_tenant(&st, "atec-ecarte", ATEC_EVENEMENT_ECARTE);
        {
            let h = st.tenants.handle_for("atec-ecarte").expect("fixture : la base du tenant se résout");
            let n = h
                .lock()
                .execute(
                    "INSERT INTO event(ts,source,category,severity,message,host,fields,origin) \
                     VALUES(0,'plume-tenant-admin','audit',1,'atec','plume-daemon','{}','daemon')",
                    [],
                )
                .expect("fixture : RAISE(IGNORE) n'est pas une erreur");
            assert_eq!(n, 0, "fixture : l'événement écarté rend ZÉRO ligne, sans erreur");
        }

        let (statut, v) = atec_poser(&st, "atec-ecarte", "erin", "editor").await;
        assert_eq!(statut, 200, "le droit est écrit, le geste est un succès : {v}");
        assert_eq!(atec_aveu(&v), Some(CAUSE_EVENEMENT_DU_TENANT_NON_ECRIT), "zéro ligne écrite est AVOUÉ : {v}");
        assert_eq!(count_grant(&st, "atec-ecarte", "erin"), 1, "le droit est en place");
        assert_eq!(atec_evenements(&st, "atec-ecarte", "grant.set"), 0, "BASE DU TENANT : l'événement n'y est pas entré");

        // CONTRÔLE POSITIF — le déclencheur retiré, la même pose n'avoue rien.
        atec_base_du_tenant(&st, "atec-ecarte", ATEC_ECARTE_RETIRE);
        let (statut, v) = atec_poser(&st, "atec-ecarte", "erin", "editor").await;
        assert_eq!((statut, atec_aveu(&v)), (200, None), "{v}");
        assert_eq!(atec_evenements(&st, "atec-ecarte", "grant.set"), 1, "BASE DU TENANT : l'événement entre");
    }
}

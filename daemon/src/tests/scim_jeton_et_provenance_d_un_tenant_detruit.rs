// =====================================================================================
// `P10.34-h` (suite) — LA DESTRUCTION D'UN TENANT RETIRE SES JETONS SCIM ET LA PROVENANCE DE SES IDENTITÉS, TOUT OU
// RIEN ; UN JETON SCIM D'UN TENANT ABSENT DU CATALOGUE EST REFUSÉ.
//
// CE QUI ÉTAIT FAUX (lu sur e66bb760) : `tenant_destroy` (daemon/src/tenants.rs) effaçait `token`, `"grant"` et `tenant`
// sous `let _ =`, un par un, et jamais `scim_token` ni `scim_provenance` ; le fichier chiffré était supprimé même si un
// effacement avait échoué. `scim_authenticate` (daemon/src/scim.rs) lisait `scim_token.tenant_id` sans la table `tenant`.
//
// CE QUE CES TÉMOINS TIENNENT, en mode multi-tenant avec DEUX tenants réels (`tenant_create`, bases chiffrées) :
//  * détruire A puis le recréer sous le même identifiant : l'ancien jeton SCIM de A rend `Ok(None)` et, par le routeur
//    réel, le `401` d'un jeton inconnu (statut et corps identiques) ; le plan de contrôle d'après est EXACTEMENT celui
//    d'avant, moins les lignes de A (jetons SCIM, jetons d'agent, droits, ligne du tenant) et avec la provenance de A
//    scellée sur `(tenant détruit)` : rien de B ne bouge (clause `WHERE` de chaque effacement, jeton d'agent de B
//    compris) ; une identité créée par le SCIM de A et portant un droit dans B est ÉTRANGÈRE au A recréé (`PATCH add` :
//    le `400 noTarget` d'un inconnu, `POST /Users` : `409 uniqueness`, en entier) ; une identité créée par le SCIM de A
//    SANS droit ailleurs est étrangère à B ET au A recréé (provenance scellée : effacée, elle devenait rattachable par
//    tout tenant SCIM) ;
//  * un tenant absent au moment de la transaction (deux destructions concurrentes) : `tenant_destroy` rend le refus
//    « tenant '…' inconnu », jamais la cause 503 « ce n'est PAS tenant inconnu » ;
//  * un jeton dont le tenant n'est pas au catalogue (reste d'une destruction antérieure) : `Ok(None)`, `401` identique ;
//    la table `tenant` illisible : `Err` (le `503` de `P10.21-u`), jamais `Ok(None)` ni le tenant ;
//  * chaque effacement refusé SEUL (déclencheur `RAISE(ABORT)` sur chacune des cinq tables, la première comme la
//    dernière ; la liste jouée est celle de la production, `EFFACEMENTS_DE_LA_DESTRUCTION`), le `BEGIN` refusé, la ligne
//    du tenant non relue, le `COMMIT` refusé : `503` au corps EXACT (phrase fixe, sans le texte du moteur), RIEN de
//    détruit (plan de contrôle identique, fichier présent, écrivain mémoïsé et clé du registre lus AVANT toute
//    résolution qui les reposerait, tenant résolu, jeton SCIM valide) ; puis la même demande détruit, et l'écrivain et
//    la clé sont oubliés (contrôle positif) ;
//  * les lignes `[tenants]` de ces refus, ENTIÈRES, capturées dans un processus enfant (celle du `BEGIN` refusé,
//    `ERREUR`, comprise), et le `BEGIN` refusé compté sous le journal `tenants`.
//
// MUTANTS (VERIF_MUT sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : AW5_sans_jetons_scim,
// AW5_sans_provenance, AW5_jetons_sans_where, AW5_provenance_sans_where, AW5_erreur_avalee, AW5_fichier_avant_commit,
// AW5_lecture_inconnu, AW5_begin_500, AW5_commit_500, AW5_route_500, AW5_auth_sans_jointure, AW5_journal_lecture_muet,
// AW5_journal_effacement_muet, AW5_journal_commit_muet ; puis, après vérification : V_eff_token_sans_where,
// V_lu_none_nonprise, V_begin_label, V_tombe_supprimee, V_tombe_sans_where ; puis (reprise) AX3_caches_sur_refus
// (écrivain évincé et clé désinscrite sur un effacement refusé), AX3_caches_jamais_purges (rien d'oublié après le
// COMMIT), AX3_liste_jouee_incomplete (la liste jouée privée d'un effacement de la production : le plancher rougit).
//
// LIMITES : une identité créée par le SCIM du tenant détruit et sans droit ailleurs n'est plus rattachable par AUCUN
// tenant SCIM ; seul un droit posé hors SCIM (`grant_set`) la rattache ; la ligne `tenant.destroy` du journal de
// contrôle est écrite AVANT la destruction (`P10.20-z`) et reste quand la transaction est refusée, ce que chaque phrase
// dit ; la route sert le refus « inconnu » d'une destruction concurrente en `500` (comme avant ce lot), pas en `404`.
// =====================================================================================
mod scim_jeton_et_provenance_d_un_tenant_detruit {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const SJPD_A: &str = "sjpd-a";
    const SJPD_NOM_A: &str = "SjpdA";
    const SJPD_B: &str = "sjpd-b";
    const SJPD_NOM_B: &str = "SjpdB";
    const SJPD_JETON_A: &str = "sjpd-jeton-de-test-a";
    const SJPD_JETON_A_RECREE: &str = "sjpd-jeton-de-test-a-recree";
    const SJPD_JETON_B: &str = "sjpd-jeton-de-test-b";
    const SJPD_JETON_INCONNU: &str = "sjpd-jeton-de-test-jamais-pose";
    const SJPD_JETON_ORPHELIN: &str = "sjpd-jeton-de-test-orphelin";
    const SJPD_MOTEUR: &str = "sjpd moteur : effacement refuse";
    /// Le tenant de provenance scellé, RECOPIÉ.
    const SJPD_TOMBE: &str = "(tenant détruit)";

    /// Les phrases servies, RECOPIÉES (jamais lues de la production).
    const SJPD_PHRASE_BEGIN: &str = "TENANT NON DÉTRUIT : la base n'a pas pris la transaction de la destruction (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur l'écrivain) — RIEN n'est détruit : le tenant, sa base, sa clé, ses droits et ses jetons, SCIM compris, sont intacts ; la ligne du journal de contrôle qui annonce cette destruction est déjà écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";
    const SJPD_PHRASE_EFFACEMENT: &str = "TENANT NON DÉTRUIT : la base n'a pas pris l'effacement de ce qui le rattache au plan de contrôle, et la transaction est annulée — RIEN n'est détruit : le tenant, sa base, sa clé, ses droits et ses jetons, SCIM compris, sont intacts ; la ligne du journal de contrôle qui annonce cette destruction est déjà écrite. Réessayez ; si le refus persiste, la base du plan de contrôle est en lecture seule, pleine ou verrouillée.";
    const SJPD_PHRASE_COMMIT: &str = "TENANT NON DÉTRUIT : la base n'a pas validé la transaction (COMMIT refusé) et l'a annulée — RIEN n'est détruit : le tenant, sa base, sa clé, ses droits et ses jetons, SCIM compris, sont intacts ; la ligne du journal de contrôle qui annonce cette destruction est déjà écrite. Réessayez une fois le plan de contrôle de nouveau écrivable.";
    const SJPD_PHRASE_NON_LU: &str = "TENANT NON DÉTRUIT : la base du plan de contrôle n'a pas pu relire la ligne du tenant au début de la destruction — ce n'est PAS « tenant inconnu », son existence n'est ni affirmée ni niée. RIEN n'est détruit : le tenant, sa base, sa clé, ses droits et ses jetons, SCIM compris, sont intacts ; la ligne du journal de contrôle qui annonce cette destruction est déjà écrite. Réessayez une fois le plan de contrôle de nouveau lisible.";

    async fn sjpd_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    fn sjpd_plan(st: &AppState) -> &ControlPlane {
        st.tenants.control.as_ref().expect("fixture : mode 1")
    }

    fn sjpd_poser_le_jeton(st: &AppState, jeton: &str, tenant: &str) {
        sjpd_plan(st)
            .conn
            .lock()
            .execute("INSERT INTO scim_token(hash,tenant_id,created) VALUES(?1,?2,0)", params![sha256_hex(jeton.as_bytes()), tenant])
            .expect("fixture : jeton SCIM posé");
    }

    fn sjpd_compter(st: &AppState, sql: &str, tenant: &str) -> i64 {
        sjpd_plan(st).conn.lock().query_row(sql, params![tenant], |r| r.get(0)).expect("fixture : compte lisible")
    }

    fn sjpd_chemin(st: &AppState, tenant: &str) -> String {
        sjpd_plan(st).conn.lock().query_row("SELECT db_path FROM tenant WHERE id=?1", params![tenant], |r| r.get(0)).expect("fixture : tenant catalogué")
    }

    /// TOUT ce que la destruction peut effacer, ligne par ligne, plus les identités : l'état du plan de contrôle.
    fn sjpd_instantane(st: &AppState) -> Vec<String> {
        let c = sjpd_plan(st).conn.lock();
        let mut tout = Vec::new();
        for sql in [
            "SELECT 'scim_token|'||hash||'|'||tenant_id FROM scim_token",
            "SELECT 'scim_provenance|'||user_id||'|'||tenant_id FROM scim_provenance",
            "SELECT 'token|'||hash||'|'||tenant_id FROM token",
            "SELECT 'grant|'||user_id||'|'||tenant_id||'|'||role FROM \"grant\"",
            "SELECT 'tenant|'||id||'|'||name||'|'||key_ref||'|'||db_path FROM tenant",
            "SELECT 'platform_user|'||id||'|'||name FROM platform_user",
        ] {
            let mut s = c.prepare(sql).expect("fixture");
            let lus = s.query_map([], |r| r.get::<_, String>(0)).expect("fixture").collect::<Result<Vec<_>, _>>().expect("fixture : lisible");
            tout.extend(lus);
        }
        tout.sort();
        tout
    }

    async fn sjpd_creer(st: &AppState, id: &str, nom: &str) {
        let (statut, v) = sjpd_corps(
            tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("sjpd-op")), Json(json!({ "id": id, "name": nom, "admin": format!("{id}-adm") }))).await,
        )
        .await;
        assert_eq!(statut, 201, "fixture : tenant {id} créé : {v}");
    }

    async fn sjpd_detruire(st: &AppState) -> (u16, Value) {
        sjpd_corps(tenant_delete(State(st.clone()), Extension(au_super("sjpd-op")), Path(SJPD_A.into()), Json(json!({ "confirm": SJPD_NOM_A }))).await).await
    }

    async fn sjpd_post(st: &AppState, tenant: &str, nom: &str) -> (u16, Value) {
        sjpd_corps(scim_user_create(State(st.clone()), Extension(ScimCtx { tenant: tenant.into() }), Json(json!({ "userName": nom }))).await).await
    }

    /// Deux tenants réels, un jeton SCIM chacun ; `x` créée par le SCIM de A puis portant un droit dans B ; `y` créée par
    /// le SCIM de B ; `z` créée par le SCIM de A, sans droit nulle part ; un jeton d'agent de A et un de B. Rend l'id de
    /// `x`, de `y` et de `z`.
    async fn sjpd_etat() -> (AppState, crate::tmp_possede::TmpPossede, String, String, String) {
        let (st, dir) = mk_mode1_state();
        sjpd_creer(&st, SJPD_A, SJPD_NOM_A).await;
        sjpd_creer(&st, SJPD_B, SJPD_NOM_B).await;
        sjpd_poser_le_jeton(&st, SJPD_JETON_A, SJPD_A);
        sjpd_poser_le_jeton(&st, SJPD_JETON_B, SJPD_B);
        let (statut, v) = sjpd_post(&st, SJPD_A, "sjpd-x").await;
        assert_eq!(statut, 201, "fixture : x créée par le SCIM de A : {v}");
        let x = v["id"].as_str().expect("id servi").to_string();
        let (statut, v) = sjpd_post(&st, SJPD_B, "sjpd-y").await;
        assert_eq!(statut, 201, "fixture : y créée par le SCIM de B : {v}");
        let y = v["id"].as_str().expect("id servi").to_string();
        let (statut, v) = sjpd_post(&st, SJPD_A, "sjpd-z").await;
        assert_eq!(statut, 201, "fixture : z créée par le SCIM de A : {v}");
        let z = v["id"].as_str().expect("id servi").to_string();
        {
            let c = sjpd_plan(&st).conn.lock();
            c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'viewer')", params![x, SJPD_B]).expect("fixture : droit de x dans B");
            c.execute("INSERT INTO token(hash,tenant_id,created) VALUES('sjpd-agent-a',?1,0)", params![SJPD_A]).expect("fixture : jeton d'agent de A");
            c.execute("INSERT INTO token(hash,tenant_id,created) VALUES('sjpd-agent-b',?1,0)", params![SJPD_B]).expect("fixture : jeton d'agent de B");
        }
        (st, dir, x, y, z)
    }

    /// La table qu'un énoncé d'effacement de la production vise (`DELETE FROM x …`, `UPDATE x …`).
    fn sjpd_table_visee(sql: &str) -> &str {
        let reste = sql.strip_prefix("DELETE FROM ").or_else(|| sql.strip_prefix("UPDATE ")).unwrap_or_else(|| panic!("énoncé d'effacement non reconnu : {sql}"));
        reste.split_whitespace().next().expect("table nommée").trim_matches('"')
    }

    fn sjpd_bearer(jeton: &str) -> String {
        format!("Bearer {jeton}")
    }

    fn sjpd_corps_http(brut: &str) -> String {
        brut.split_once("\r\n\r\n").map(|(_, c)| c.to_string()).unwrap_or_default()
    }

    /// CE QU'IL TIENT : détruire A (route réelle, super-admin) retire ses jetons SCIM et la provenance de ses identités,
    /// pas ceux de B ; l'ancien jeton de A est refusé avant ET après la recréation de A, par `scim_authenticate` et par le
    /// routeur réel (`401`, même statut et même corps qu'un jeton jamais posé) ; `x` (créée par le SCIM de A, droit dans
    /// B) est étrangère au A recréé : `PATCH add` rend le `400 noTarget` d'un inconnu et `POST /Users` le `409`, EN ENTIER,
    /// sans droit posé ; le jeton de B authentifie toujours.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AW5_sans_jetons_scim` (ancien jeton accepté après la recréation) ;
    /// `AW5_sans_provenance` (provenance restante, `PATCH add` 200) ; `AW5_jetons_sans_where` (jeton de B effacé) ;
    /// `AW5_provenance_sans_where` (provenance de y effacée) ; `V_eff_token_sans_where` (jeton d'agent de B effacé) ;
    /// `V_tombe_supprimee` (provenance effacée : z rattachée par B) ; `V_tombe_sans_where` (provenance de y scellée).
    #[tokio::test]
    async fn sjpd_detruire_puis_recreer_ne_rend_ni_le_jeton_ni_la_provenance() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir, x, y, z) = sjpd_etat().await;
        let cp = sjpd_plan(&st);
        // CONTRÔLE POSITIF avant la destruction.
        assert_eq!(scim_authenticate(cp, &sjpd_bearer(SJPD_JETON_A)), Ok(Some(SJPD_A.to_string())), "fixture : le jeton de A authentifie");
        assert_eq!(sjpd_compter(&st, "SELECT COUNT(*) FROM scim_provenance WHERE tenant_id=?1", SJPD_A), 2, "fixture : x et z provisionnées par A");

        let avant = sjpd_instantane(&st);
        let (statut, v) = sjpd_detruire(&st).await;
        assert_eq!(statut, 200, "destruction confirmée : {v}");
        // LE PLAN DE CONTRÔLE D'APRÈS, LIGNE POUR LIGNE : celui d'avant, moins les lignes de A, provenance de A scellée.
        let mut retirees: Vec<&str> = Vec::new();
        let mut scellees = 0usize;
        let mut attendu: Vec<String> = avant
            .iter()
            .filter_map(|ligne| {
                let champs: Vec<&str> = ligne.split('|').collect();
                match champs[0] {
                    "scim_provenance" if champs[2] == SJPD_A => {
                        scellees += 1;
                        Some(format!("scim_provenance|{}|{SJPD_TOMBE}", champs[1]))
                    }
                    "scim_token" | "token" | "grant" if champs[2] == SJPD_A => {
                        retirees.push(champs[0]);
                        None
                    }
                    "tenant" if champs[1] == SJPD_A => {
                        retirees.push("tenant");
                        None
                    }
                    _ => Some(ligne.clone()),
                }
            })
            .collect();
        attendu.sort();
        retirees.sort();
        retirees.dedup();
        assert_eq!(retirees, vec!["grant", "scim_token", "tenant", "token"], "plancher : A avait une ligne de chaque sorte effacée");
        assert_eq!(scellees, 2, "plancher : x et z provisionnées par A");
        assert!(avant.iter().any(|l| l.starts_with("token|") && l.ends_with(&format!("|{SJPD_B}"))), "plancher : B a un jeton d'agent");
        assert_eq!(sjpd_instantane(&st), attendu, "rien de B ne bouge, rien de A ne reste hors de la provenance scellée");
        assert_eq!(sjpd_compter(&st, "SELECT COUNT(*) FROM scim_token WHERE tenant_id=?1", SJPD_A), 0, "aucun jeton SCIM de A ne reste");
        assert_eq!(sjpd_compter(&st, "SELECT COUNT(*) FROM scim_provenance WHERE tenant_id=?1", SJPD_A), 0, "aucune provenance de A ne reste");
        assert_eq!(sjpd_compter(&st, "SELECT COUNT(*) FROM scim_token WHERE tenant_id=?1", SJPD_B), 1, "le jeton SCIM de B reste");
        let provenance_de_y: i64 = cp
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM scim_provenance WHERE user_id=?1 AND tenant_id=?2", params![y, SJPD_B], |r| r.get(0))
            .expect("lu");
        assert_eq!(provenance_de_y, 1, "la provenance de y (B) reste");
        assert_eq!(scim_authenticate(cp, &sjpd_bearer(SJPD_JETON_A)), Ok(None), "l'ancien jeton de A est refusé");

        // Recréation sous le même identifiant, un jeton neuf.
        sjpd_creer(&st, SJPD_A, SJPD_NOM_A).await;
        sjpd_poser_le_jeton(&st, SJPD_JETON_A_RECREE, SJPD_A);
        assert_eq!(scim_authenticate(cp, &sjpd_bearer(SJPD_JETON_A)), Ok(None), "l'ancien jeton de A est refusé par le A recréé");
        assert_eq!(scim_authenticate(cp, &sjpd_bearer(SJPD_JETON_A_RECREE)), Ok(Some(SJPD_A.to_string())), "contrôle positif : le jeton neuf");
        assert_eq!(scim_authenticate(cp, &sjpd_bearer(SJPD_JETON_B)), Ok(Some(SJPD_B.to_string())), "le jeton de B authentifie toujours");

        // PAR LE ROUTEUR RÉEL : l'ancien jeton répond comme un jeton jamais posé.
        // Hors du mode installation (l'état de test naît installation ouverte : `auth_guard` laisserait passer
        // `/scim/v2/*` sans jeton, et le gestionnaire répondrait 500 faute de contexte SCIM).
        st.installation_ouverte.store(false, std::sync::atomic::Ordering::SeqCst);
        let adresse = router_serve(st.clone()).await;
        let (s_ancien, brut_ancien) = router_probe_corps(adresse, "GET", "/scim/v2/Users", Some(&sjpd_bearer(SJPD_JETON_A)), &[]).await;
        let (s_inconnu, brut_inconnu) = router_probe_corps(adresse, "GET", "/scim/v2/Users", Some(&sjpd_bearer(SJPD_JETON_INCONNU)), &[]).await;
        let (s_neuf, brut_neuf) = router_probe_corps(adresse, "GET", "/scim/v2/Users", Some(&sjpd_bearer(SJPD_JETON_A_RECREE)), &[]).await;
        assert_eq!(s_ancien, 401, "l'ancien jeton de A : 401 : {brut_ancien}");
        assert_eq!((s_ancien, sjpd_corps_http(&brut_ancien)), (s_inconnu, sjpd_corps_http(&brut_inconnu)), "même statut, même corps qu'un jeton inconnu");
        // Le corps tel qu'il passe sur le fil (découpage HTTP/1.1 : longueur 0x16 = 22 octets, puis le bloc final).
        assert_eq!(sjpd_corps_http(&brut_ancien), "16\r\nSCIM : bearer invalide\r\n0\r\n\r\n", "le corps du 401");
        assert_eq!(s_neuf, 200, "contrôle positif par le routeur : {brut_neuf}");

        // x est ÉTRANGÈRE au A recréé.
        let droits_de_x = || -> Vec<String> {
            let c = cp.conn.lock();
            let mut s = c.prepare("SELECT tenant_id||':'||role FROM \"grant\" WHERE user_id=?1 ORDER BY tenant_id").expect("fixture");
            let lus = s.query_map(params![x], |r| r.get::<_, String>(0)).expect("fixture").collect::<Result<Vec<_>, _>>().expect("fixture");
            lus
        };
        let (statut, v) = sjpd_corps(
            scim_group_patch(
                State(st.clone()),
                Extension(ScimCtx { tenant: SJPD_A.into() }),
                Path("viewer".to_string()),
                Json(json!({ "Operations": [{ "op": "add", "value": [{ "value": x }] }] })),
            )
            .await,
        )
        .await;
        assert_eq!(statut, 400, "PATCH add de x : {v}");
        assert_eq!(
            v,
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "scimType": "noTarget",
                "detail": "opération n°1 : un membre visé n'est pas une identité connue de ce tenant ; la demande est atomique, aucune de ses opérations n'est appliquée",
                "status": "400",
            }),
            "le noTarget d'un inconnu, EN ENTIER"
        );
        let (statut, v) = sjpd_post(&st, SJPD_A, "sjpd-x").await;
        assert_eq!(statut, 409, "POST /Users de x : {v}");
        assert_eq!(
            v,
            json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                "scimType": "uniqueness",
                "detail": "userName déjà pris sur la plateforme par une identité que ce tenant ne peut pas rattacher : l'utilisateur n'est ni créé ni modifié, aucun droit n'est posé",
                "status": "409",
            }),
            "le 409, EN ENTIER, sans l'id de x"
        );
        assert_eq!(droits_de_x(), vec![format!("{SJPD_B}:viewer")], "aucun droit posé dans le A recréé");

        // z (créée par le SCIM de A, aucun droit nulle part) : sa provenance est SCELLÉE, elle est étrangère à TOUS.
        let provenance_de_z: String = cp.conn.lock().query_row("SELECT tenant_id FROM scim_provenance WHERE user_id=?1", params![z], |r| r.get(0)).expect("provenance de z lue");
        assert_eq!(provenance_de_z, SJPD_TOMBE, "la provenance de z est scellée");
        let refus_409 = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "scimType": "uniqueness",
            "detail": "userName déjà pris sur la plateforme par une identité que ce tenant ne peut pas rattacher : l'utilisateur n'est ni créé ni modifié, aucun droit n'est posé",
            "status": "409",
        });
        for tenant in [SJPD_B, SJPD_A] {
            let (statut, v) = sjpd_post(&st, tenant, "sjpd-z").await;
            assert_eq!((statut, &v), (409, &refus_409), "POST /Users de z depuis {tenant} : le 409, EN ENTIER, sans l'id de z");
            let (statut, v) = sjpd_corps(
                scim_group_patch(
                    State(st.clone()),
                    Extension(ScimCtx { tenant: tenant.into() }),
                    Path("viewer".to_string()),
                    Json(json!({ "Operations": [{ "op": "add", "value": [{ "value": z }] }] })),
                )
                .await,
            )
            .await;
            assert_eq!((statut, v["scimType"].as_str()), (400, Some("noTarget")), "PATCH add de z depuis {tenant} : {v}");
        }
        let droits_de_z: i64 = cp.conn.lock().query_row("SELECT COUNT(*) FROM \"grant\" WHERE user_id=?1", params![z], |r| r.get(0)).expect("lu");
        assert_eq!(droits_de_z, 0, "aucun droit posé à z");
    }

    /// CE QU'IL TIENT : un tenant absent du catalogue au moment de la transaction (une destruction concurrente l'a déjà
    /// retiré) : `tenant_destroy` rend le refus « tenant '…' inconnu », jamais la cause 503 d'une ligne non relue, et ne
    /// touche à rien ; contrôle positif : le même appel sur A détruit.
    /// LA MUTATION QUI LE FAIT ROUGIR : `V_lu_none_nonprise` (`Ok(None)` servi comme ligne non relue).
    #[tokio::test]
    async fn sjpd_un_tenant_absent_dans_la_transaction_est_dit_inconnu() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir, _x, _y, _z) = sjpd_etat().await;
        let avant = sjpd_instantane(&st);
        let rendu = tenant_destroy(&st.tenants, "sjpd-jamais-catalogue");
        assert!(
            matches!(&rendu, Err(crate::tenants::DestructionNonFaite::Refusee(m)) if m == "tenant 'sjpd-jamais-catalogue' inconnu"),
            "le refus d'un tenant inconnu : {rendu:?}"
        );
        assert_eq!(sjpd_instantane(&st), avant, "rien n'est touché");
        assert!(tenant_destroy(&st.tenants, SJPD_A).is_ok(), "contrôle positif : A est détruit");
        assert_eq!(sjpd_compter(&st, "SELECT COUNT(*) FROM tenant WHERE id=?1", SJPD_A), 0, "contrôle positif : la ligne de A est effacée");
    }

    /// CE QU'IL TIENT : un jeton SCIM dont le tenant n'est pas au catalogue (ligne restée d'une destruction antérieure)
    /// rend `Ok(None)`, et par le routeur réel le `401` d'un jeton inconnu, même corps ; la table `tenant` illisible SEULE,
    /// l'authentification rend `Err` (le `503` de `P10.21-u`) pour un jeton valide comme pour l'orphelin, jamais
    /// `Ok(None)` ni un tenant ; contrôle positif : un jeton d'un tenant catalogué.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AW5_auth_sans_jointure` (l'orphelin authentifie, la table illisible ne refuse pas).
    #[tokio::test]
    async fn sjpd_un_jeton_d_un_tenant_absent_est_refuse() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir, _x, _y, _z) = sjpd_etat().await;
        let cp = sjpd_plan(&st);
        sjpd_poser_le_jeton(&st, SJPD_JETON_ORPHELIN, "sjpd-tenant-jamais-catalogue");
        assert_eq!(scim_authenticate(cp, &sjpd_bearer(SJPD_JETON_ORPHELIN)), Ok(None), "l'orphelin : bearer invalide");
        assert_eq!(scim_authenticate(cp, &sjpd_bearer(SJPD_JETON_B)), Ok(Some(SJPD_B.to_string())), "contrôle positif");
        // Hors du mode installation (l'état de test naît installation ouverte : `auth_guard` laisserait passer
        // `/scim/v2/*` sans jeton, et le gestionnaire répondrait 500 faute de contexte SCIM).
        st.installation_ouverte.store(false, std::sync::atomic::Ordering::SeqCst);
        let adresse = router_serve(st.clone()).await;
        let (s_orphelin, brut_orphelin) = router_probe_corps(adresse, "GET", "/scim/v2/Users", Some(&sjpd_bearer(SJPD_JETON_ORPHELIN)), &[]).await;
        let (s_inconnu, brut_inconnu) = router_probe_corps(adresse, "GET", "/scim/v2/Users", Some(&sjpd_bearer(SJPD_JETON_INCONNU)), &[]).await;
        assert_eq!(s_orphelin, 401, "{brut_orphelin}");
        assert_eq!((s_orphelin, sjpd_corps_http(&brut_orphelin)), (s_inconnu, sjpd_corps_http(&brut_inconnu)), "même statut, même corps qu'un jeton inconnu");

        cp.conn.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "tenant", .. } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let valide = scim_authenticate(cp, &sjpd_bearer(SJPD_JETON_B));
        let orphelin = scim_authenticate(cp, &sjpd_bearer(SJPD_JETON_ORPHELIN));
        cp.conn.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert!(valide.is_err(), "table tenant illisible : ni valide ni révoqué : {valide:?}");
        assert!(orphelin.is_err(), "table tenant illisible : l'orphelin n'est pas dit absent : {orphelin:?}");
    }

    /// Les refus de la destruction, chacun SEUL (posé, la route jouée, levé), jugés un par un, puis le contrôle positif.
    async fn sjpd_jouer_les_refus(st: &AppState) {
        let cp = sjpd_plan(st);
        let chemin = sjpd_chemin(st, SJPD_A);
        let tables = ["scim_token", "scim_provenance", "token", "grant", "tenant"];
        // PLANCHER LIÉ À LA PRODUCTION : la liste jouée est EXACTEMENT celle des effacements de la destruction, dans leur
        // ordre — un effacement ajouté (ou retiré) en production sans être joué ici rougit.
        let de_la_production: Vec<&str> = crate::tenants::EFFACEMENTS_DE_LA_DESTRUCTION.iter().map(|(_, sql)| sjpd_table_visee(sql)).collect();
        assert_eq!(tables.to_vec(), de_la_production, "les effacements joués sont ceux de la production");
        let mut cas: Vec<(String, &str)> = vec![("lecture".to_string(), SJPD_PHRASE_NON_LU)];
        cas.extend(tables.iter().map(|t| (format!("effacement {t}"), SJPD_PHRASE_EFFACEMENT)));
        cas.push(("begin".to_string(), SJPD_PHRASE_BEGIN));
        cas.push(("commit".to_string(), SJPD_PHRASE_COMMIT));
        const SJPD_BEGIN_COMPTE: &str = "begin refusé tenants hors_verrou";
        // LES CACHES : l'écrivain mémoïsé de A (réchauffé ici) et la clé de A au registre, lus avant chaque refus.
        assert!(st.tenants.handle_for(SJPD_A).is_some(), "fixture : l'écrivain de A est servi");
        assert!(st.tenants.writers.lock().contains_key(SJPD_A), "fixture : l'écrivain de A est mémoïsé");
        let cle_au_registre = crate::crypto::db_key_registry().lock().get(&chemin).cloned();
        assert!(matches!(&cle_au_registre, Some(Some(_))), "fixture : la clé de A est au registre");
        for (quoi, phrase) in &cas {
            let avant = sjpd_instantane(st);
            let begins_avant = crate::comptes_de_transaction::compte_des_temoins(&cp.conn.lock(), SJPD_BEGIN_COMPTE);
            match quoi.as_str() {
                "lecture" => cp.conn.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Read { table_name: "tenant", column_name: "db_path" } => Authorization::Deny,
                    _ => Authorization::Allow,
                })),
                "begin" => cp.conn.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Transaction { operation: TransactionOperation::Begin } => Authorization::Deny,
                    _ => Authorization::Allow,
                })),
                "commit" => cp.conn.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
                    _ => Authorization::Allow,
                })),
                autre => {
                    let table = autre.trim_start_matches("effacement ");
                    cp.conn
                        .lock()
                        .execute_batch(&format!(
                            "CREATE TEMP TRIGGER sjpd_refus BEFORE DELETE ON main.\"{table}\" BEGIN SELECT RAISE(ABORT, '{SJPD_MOTEUR}'); END; \
                             CREATE TEMP TRIGGER sjpd_refus_maj BEFORE UPDATE ON main.\"{table}\" BEGIN SELECT RAISE(ABORT, '{SJPD_MOTEUR}'); END;"
                        ))
                        .expect("fixture : déclencheur posé");
                }
            }
            let (statut, v) = sjpd_detruire(st).await;
            cp.conn.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            let _ = cp.conn.lock().execute_batch("DROP TRIGGER IF EXISTS temp.sjpd_refus; DROP TRIGGER IF EXISTS temp.sjpd_refus_maj;");
            assert_eq!(statut, 503, "{quoi} : la destruction est REFUSÉE : {v}");
            let cles: Vec<&String> = v.as_object().expect("corps objet").keys().collect();
            assert_eq!(cles, vec!["error", "id"], "{quoi} : le corps EXACT, ensemble des clés : {v}");
            assert_eq!(v["error"].as_str(), Some(*phrase), "{quoi} : la phrase fixe, sans le texte du moteur : {v}");
            assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : l'identifiant de corrélation : {v}");
            assert_eq!(sjpd_instantane(st), avant, "{quoi} : RIEN n'est effacé du plan de contrôle");
            assert!(std::path::Path::new(&chemin).exists(), "{quoi} : le fichier chiffré de A est intact");
            // Lus AVANT `resolve`, qui reposerait la clé au registre.
            assert!(st.tenants.writers.lock().contains_key(SJPD_A), "{quoi} : l'écrivain mémoïsé de A n'est pas évincé");
            assert_eq!(crate::crypto::db_key_registry().lock().get(&chemin).cloned(), cle_au_registre, "{quoi} : la clé de A reste au registre");
            assert!(st.tenants.resolve(SJPD_A).is_some(), "{quoi} : le catalogue résout encore A");
            assert_eq!(scim_authenticate(cp, &sjpd_bearer(SJPD_JETON_A)), Ok(Some(SJPD_A.to_string())), "{quoi} : le jeton SCIM de A authentifie encore");
            let begins_apres = crate::comptes_de_transaction::compte_des_temoins(&cp.conn.lock(), SJPD_BEGIN_COMPTE);
            assert_eq!(begins_apres - begins_avant, u64::from(quoi == "begin"), "{quoi} : le BEGIN refusé est compté sous le journal `tenants`, et lui seul");
        }
        // CONTRÔLE POSITIF — plus rien n'est refusé : la même demande détruit.
        let (statut, v) = sjpd_detruire(st).await;
        assert_eq!(statut, 200, "le refus n'est pas inconditionnel : {v}");
        assert!(!std::path::Path::new(&chemin).exists(), "le fichier est supprimé après le COMMIT");
        assert!(!st.tenants.writers.lock().contains_key(SJPD_A), "l'écrivain de A est évincé après le COMMIT");
        assert!(!crate::crypto::db_key_registry().lock().contains_key(&chemin), "la clé de A est oubliée du registre après le COMMIT");
        assert_eq!(sjpd_compter(st, "SELECT COUNT(*) FROM tenant WHERE id=?1", SJPD_A), 0, "la ligne du tenant est effacée");
    }

    /// CE QU'IL TIENT : la ligne du tenant non relue, chacun des cinq effacements refusé seul (déclencheur), le `BEGIN`
    /// refusé, le `COMMIT` refusé : `503` au corps EXACT (`error` = la phrase fixe de la classe, `id`), RIEN de détruit
    /// (plan de contrôle identique ligne pour ligne, fichier présent, écrivain mémoïsé et clé du registre en place, tenant
    /// résolu, jeton SCIM valide) ; puis la même demande détruit, écrivain et clé oubliés.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AW5_erreur_avalee` (200, effacements partiels) ; `AW5_fichier_avant_commit`
    /// (fichier supprimé) ; `AW5_lecture_inconnu`, `AW5_begin_500`, `AW5_commit_500`, `AW5_route_500` (500) ;
    /// `AX3_caches_sur_refus`, `AX3_caches_jamais_purges`, `AX3_liste_jouee_incomplete`.
    #[tokio::test]
    async fn sjpd_un_refus_de_la_destruction_ne_detruit_rien() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir, _x, _y, _z) = sjpd_etat().await;
        sjpd_jouer_les_refus(&st).await;
    }

    /// CE QU'IL TIENT, DANS UN PROCESSUS ENFANT (sortie d'erreur lisible) : chacun des huit refus joués par
    /// `sjpd_jouer_les_refus` est DIT par sa ligne `[tenants]` qui nomme la destruction du tenant, ENTIÈRE, dans l'ordre
    /// — `WARN` pour la lecture, les cinq effacements et le `COMMIT`, `ERREUR` pour le `BEGIN` refusé (la phrase commune
    /// de `dire_la_transaction_non_ouverte`, libellés du journal et du geste compris) ; la cause du moteur y figure,
    /// aucun identifiant de tenant ni chemin.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AW5_journal_lecture_muet`, `AW5_journal_effacement_muet`, `AW5_journal_commit_muet`,
    /// `V_begin_label`.
    #[tokio::test]
    async fn sjpd_les_refus_de_la_destruction_sont_dits_au_journal() {
        const ENFANT: &str = "SJPD_REFUS_DE_LA_DESTRUCTION_ENFANT";
        if std::env::var(ENFANT).is_ok() {
            let _env = VERROU_ENV_PROCESSUS.read();
            let (st, _dir, _x, _y, _z) = sjpd_etat().await;
            sjpd_jouer_les_refus(&st).await;
            println!("SJPD-ENFANT-A-JOUE");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::scim_jeton_et_provenance_d_un_tenant_detruit::sjpd_les_refus_de_la_destruction_sont_dits_au_journal"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("SJPD-ENFANT-A-JOUE"), "contrôle : l'enfant a vraiment joué : {stdout}\n{stderr}");
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[tenants] ") && l.contains("destruction du tenant")).collect();
        let attendues = vec![
            "[tenants] WARN destruction du tenant NON faite, rien n'est détruit (ligne du tenant non relue) : access to tenant.db_path is prohibited".to_string(),
            format!("[tenants] WARN destruction du tenant NON faite, rien n'est détruit (effacement refusé : jetons SCIM) : {SJPD_MOTEUR}"),
            format!("[tenants] WARN destruction du tenant NON faite, rien n'est détruit (effacement refusé : provenance SCIM) : {SJPD_MOTEUR}"),
            format!("[tenants] WARN destruction du tenant NON faite, rien n'est détruit (effacement refusé : jetons d'agent) : {SJPD_MOTEUR}"),
            format!("[tenants] WARN destruction du tenant NON faite, rien n'est détruit (effacement refusé : droits) : {SJPD_MOTEUR}"),
            format!("[tenants] WARN destruction du tenant NON faite, rien n'est détruit (effacement refusé : ligne du tenant) : {SJPD_MOTEUR}"),
            "[tenants] ERREUR destruction du tenant NON pris(e) : BEGIN refusé par la base, et ce n'est pas un verrou (not authorized) — rien n'est écrit ; un nouvel essai sera refusé de même tant que la cause demeure (base en lecture seule, disque, E/S)".to_string(),
            "[tenants] WARN destruction du tenant NON faite, rien n'est détruit (COMMIT refusé) : not authorized".to_string(),
        ];
        // PLANCHER LIÉ À LA PRODUCTION : la lecture, un effacement par entrée de `EFFACEMENTS_DE_LA_DESTRUCTION`, le
        // `BEGIN`, le `COMMIT`.
        assert_eq!(attendues.len(), 3 + crate::tenants::EFFACEMENTS_DE_LA_DESTRUCTION.len(), "une ligne attendue par refus joué");
        assert_eq!(lignes, attendues.iter().map(String::as_str).collect::<Vec<_>>(), "les lignes ENTIÈRES, dans l'ordre :\n{stderr}");
    }
}

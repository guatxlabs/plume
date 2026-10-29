// =====================================================================================
// `P10.34-h` (suite) — UN TENANT CRÉÉ SOUS UN IDENTIFIANT DÉJÀ PORTÉ N'HÉRITE D'AUCUN JETON (SCIM, AGENT), D'AUCUN DROIT
// NI D'AUCUNE PROVENANCE ; LES CACHES DE CLÉ D'UN TENANT DÉTRUIT SONT OUBLIÉS, ET SEULEMENT APRÈS LE COMMIT ; LES REFUS
// D'AVANT DE LA DESTRUCTION.
//
// CE QUI CHANGE (daemon/src/tenants.rs, daemon/src/scim.rs) : la création d'un tenant retire, dans sa transaction, ce qui
// restait sous son identifiant dans les quatre tables à `tenant_id` (jetons SCIM, provenance scellée, jetons d'agent,
// droits) ; l'écriture refusée de sa ligne est un `503` à phrase fixe (avant : `400` « insert tenant : » et le texte du
// moteur) ; `tenant_destroy` oublie le cache Vault sous la clé où `resolve_vault_key_field` le range (`chemin#champ`).
//
// CE QUE CES TÉMOINS TIENNENT, en mode multi-tenant avec DEUX tenants réels (`tenant_create`, bases chiffrées) :
//  * des lignes laissées comme par une version antérieure de la destruction (jeton SCIM et provenance de A, ligne du
//    tenant effacée) et un droit et un jeton d'agent écrits sous A après sa destruction, puis A recréé par la route :
//    l'ancien jeton rend `Ok(None)` et, par le routeur réel, le `401` d'un jeton inconnu (statut et corps) ; aucun
//    jeton, droit ni provenance de A ne reste, celle de `z` est scellée ; `z` est étrangère au A recréé ET à B
//    (`POST /Users` : `409` en entier ; `PATCH add` : `400 noTarget`) ; les lignes de B ne bougent pas (clause `WHERE` de
//    chaque effacement) ;
//  * un droit écrit sous l'identifiant après la destruction (point de course de production de `POST /Users`) ne passe
//    pas au A recréé ; une identité créée par le SCIM de l'ancien A n'est pas rattachée au A recréé par ce même point :
//    `409` en entier, aucun droit ;
//  * « existe déjà » : `409`, et rien n'est effacé (le jeton du tenant existant authentifie encore) ;
//  * chaque refus de la transaction de la création SEUL (quatre effacements, écriture de la ligne, `BEGIN`, `COMMIT`) :
//    `503` au corps EXACT, rien de créé (ni ligne, ni fichier, ni clé au registre), les restes intacts ; puis la même
//    demande crée ; les lignes `[tenants]` de ces refus, ENTIÈRES, dans un processus enfant ;
//  * le cache Vault d'un tenant à clé `vault:chemin` : intact après une destruction refusée, oublié après le COMMIT ;
//    à clé `vault:chemin#autre` : oublié sous `chemin#autre` ;
//  * les refus d'avant que le lot a retypés : `default` et le mode 0 rendent leur phrase, rien n'est touché ; un tenant
//    retiré entre la lecture de la route et la transaction (destruction concurrente) : `500` « tenant '…' inconnu ».
//
// MUTANTS (sous `cfg!(test)`, choisis par variable d'environnement, retirés avant le commit), chacun vu ROUGE : AX3_creation_sans_jetons,
// AX3_creation_sans_provenance, AX3_creation_jetons_sans_where, AX3_creation_provenance_sans_where,
// AX3_creation_provenance_effacee, AX3_creation_sans_existe, AX3_creation_erreur_avalee, AX3_creation_begin_400,
// AX3_creation_commit_400, AX3_creation_route_400, AX3_creation_journal_effacement_muet, AX3_creation_journal_commit_muet,
// AX3_creation_begin_libelle, AX3_vault_oubli_ancien, AX3_vault_oublie_sur_refus, AX3_default_sans_garde,
// AX3_mode0_ok, AX3_route_refusee_200, AX3_restes_liste_incomplete (la liste jouée privée d'un effacement de la production :
// le plancher rougit) ; puis, après vérification : AX3C_creation_sans_droits, AX3C_creation_sans_agents,
// AX3C_creation_droits_sans_where, AX3C_creation_agents_sans_where, AX3C_insertion_400, AX3C_insertion_phrase_effacement,
// AX3C_insertion_journal_muet, AX3C_vault_champ_fixe, AX3C_rattachement_non_rejuge.
//
// LIMITES : le nom d'une identité scellée reste pris pour toujours (`POST /Users` `409`, tenant recréé compris) —
// décision voisine de l'exploitant ; une identité sans droit ni provenance reste rattachable par tout tenant
// (rétrocompatibilité, décision de l'exploitant). L'effacement placé AVANT le contrôle « existe déjà » serait annulé par
// le `ROLLBACK` du refus (`jouer_le_geste_garde`, transaction_validee.rs) : aucune observation ne le distingue.
// =====================================================================================
mod tenant_recree_sans_restes_scim {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    const TRSR_A: &str = "trsr-a";
    const TRSR_B: &str = "trsr-b";
    const TRSR_JETON_A: &str = "trsr-jeton-de-test-a";
    const TRSR_JETON_A_RECREE: &str = "trsr-jeton-de-test-a-recree";
    const TRSR_JETON_B: &str = "trsr-jeton-de-test-b";
    const TRSR_JETON_INCONNU: &str = "trsr-jeton-de-test-jamais-pose";
    const TRSR_MOTEUR: &str = "trsr moteur : effacement refuse";
    const TRSR_ADMIN_A: &str = "trsr-adm-a";
    const TRSR_ADMIN_B: &str = "trsr-adm-b";
    const TRSR_UID_ORPHELIN: &str = "trsr-uid-orphelin";
    const TRSR_AGENT_ORPHELIN: &str = "trsr-agent-orphelin";
    const TRSR_AGENT_B: &str = "trsr-agent-b";
    /// Le tenant de provenance scellé, RECOPIÉ.
    const TRSR_TOMBE: &str = "(tenant détruit)";

    /// Les phrases servies, RECOPIÉES (jamais lues de la production).
    const TRSR_PHRASE_BEGIN: &str = "TENANT NON CRÉÉ : la base n'a pas pris la transaction de la création (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur l'écrivain) — RIEN n'est créé : ni ligne au catalogue, ni base chiffrée. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";
    const TRSR_PHRASE_EFFACEMENT: &str = "TENANT NON CRÉÉ : la base n'a pas pris l'effacement de ce qui restait sous cet identifiant, et la transaction est annulée — RIEN n'est créé : ni ligne au catalogue, ni base chiffrée. Réessayez ; si le refus persiste, la base du plan de contrôle est en lecture seule, pleine ou verrouillée.";
    const TRSR_PHRASE_INSERTION: &str = "TENANT NON CRÉÉ : la base n'a pas pris l'écriture de la ligne du tenant au catalogue, et la transaction est annulée — RIEN n'est créé : ni ligne au catalogue, ni base chiffrée. Réessayez ; si le refus persiste, la base du plan de contrôle est en lecture seule, pleine ou verrouillée.";
    const TRSR_PHRASE_COMMIT: &str = "TENANT NON CRÉÉ : la base n'a pas validé la transaction (COMMIT refusé) et l'a annulée — RIEN n'est créé : ni ligne au catalogue, ni base chiffrée. Réessayez une fois le plan de contrôle de nouveau écrivable.";
    const TRSR_PHRASE_DESTRUCTION_EFFACEMENT: &str = "TENANT NON DÉTRUIT : la base n'a pas pris l'effacement de ce qui le rattache au plan de contrôle, et la transaction est annulée — RIEN n'est détruit : le tenant, sa base, sa clé, ses droits et ses jetons, SCIM compris, sont intacts ; la ligne du journal de contrôle qui annonce cette destruction est déjà écrite. Réessayez ; si le refus persiste, la base du plan de contrôle est en lecture seule, pleine ou verrouillée.";
    const TRSR_DETAIL_409: &str = "userName déjà pris sur la plateforme par une identité que ce tenant ne peut pas rattacher : l'utilisateur n'est ni créé ni modifié, aucun droit n'est posé";
    const TRSR_DETAIL_NO_TARGET: &str = "opération n°1 : un membre visé n'est pas une identité connue de ce tenant ; la demande est atomique, aucune de ses opérations n'est appliquée";

    async fn trsr_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    fn trsr_plan(st: &AppState) -> &ControlPlane {
        st.tenants.control.as_ref().expect("fixture : mode 1")
    }

    fn trsr_poser_le_jeton(st: &AppState, jeton: &str, tenant: &str) {
        trsr_plan(st)
            .conn
            .lock()
            .execute("INSERT INTO scim_token(hash,tenant_id,created) VALUES(?1,?2,0)", params![sha256_hex(jeton.as_bytes()), tenant])
            .expect("fixture : jeton SCIM posé");
    }

    fn trsr_compter(st: &AppState, sql: &str, valeur: &str) -> i64 {
        trsr_plan(st).conn.lock().query_row(sql, params![valeur], |r| r.get(0)).expect("fixture : compte lisible")
    }

    /// Les lignes que la création peut toucher (les quatre tables à `tenant_id`, `tenant`), plus les identités : l'état
    /// du plan de contrôle.
    fn trsr_instantane(st: &AppState) -> Vec<String> {
        let c = trsr_plan(st).conn.lock();
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

    async fn trsr_creer(st: &AppState, corps: Value) -> (u16, Value) {
        trsr_corps(tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("trsr-op")), Json(corps)).await).await
    }

    async fn trsr_post(st: &AppState, tenant: &str, nom: &str) -> (u16, Value) {
        trsr_corps(scim_user_create(State(st.clone()), Extension(ScimCtx { tenant: tenant.into() }), Json(json!({ "userName": nom }))).await).await
    }

    async fn trsr_patch_add(st: &AppState, tenant: &str, uid: &str) -> (u16, Value) {
        trsr_corps(
            scim_group_patch(
                State(st.clone()),
                Extension(ScimCtx { tenant: tenant.into() }),
                Path("viewer".to_string()),
                Json(json!({ "Operations": [{ "op": "add", "value": [{ "value": uid }] }] })),
            )
            .await,
        )
        .await
    }

    fn trsr_bearer(jeton: &str) -> String {
        format!("Bearer {jeton}")
    }

    fn trsr_corps_http(brut: &str) -> String {
        brut.split_once("\r\n\r\n").map(|(_, c)| c.to_string()).unwrap_or_default()
    }

    /// Deux tenants réels, un jeton SCIM chacun, B avec un administrateur et un jeton d'agent ; `z` créée par le SCIM de
    /// A (sans droit), `y` par celui de B ; puis A détruit COMME PAR UNE VERSION ANTÉRIEURE (jetons d'agent, droits, ligne
    /// du tenant, fichier, caches — jamais `scim_token` ni `scim_provenance`), et un droit et un jeton d'agent écrits sous
    /// A APRÈS sa destruction (comme par une demande admise avant elle). Rend l'id de `z` et de `y`, et le chemin de A.
    async fn trsr_restes_d_une_version_anterieure() -> (AppState, crate::tmp_possede::TmpPossede, String, String, String) {
        let (st, dir) = mk_mode1_state();
        let (statut, v) = trsr_creer(&st, json!({ "id": TRSR_A, "name": TRSR_A })).await;
        assert_eq!(statut, 201, "fixture : tenant A créé : {v}");
        let (statut, v) = trsr_creer(&st, json!({ "id": TRSR_B, "name": TRSR_B, "admin": TRSR_ADMIN_B })).await;
        assert_eq!(statut, 201, "fixture : tenant B créé : {v}");
        trsr_poser_le_jeton(&st, TRSR_JETON_A, TRSR_A);
        trsr_poser_le_jeton(&st, TRSR_JETON_B, TRSR_B);
        let (statut, v) = trsr_post(&st, TRSR_A, "trsr-z").await;
        assert_eq!(statut, 201, "fixture : z créée par le SCIM de A : {v}");
        let z = v["id"].as_str().expect("id servi").to_string();
        let (statut, v) = trsr_post(&st, TRSR_B, "trsr-y").await;
        assert_eq!(statut, 201, "fixture : y créée par le SCIM de B : {v}");
        let y = v["id"].as_str().expect("id servi").to_string();
        let chemin: String = trsr_plan(&st).conn.lock().query_row("SELECT db_path FROM tenant WHERE id=?1", params![TRSR_A], |r| r.get(0)).expect("fixture : A catalogué");
        {
            let c = trsr_plan(&st).conn.lock();
            for sql in ["DELETE FROM token WHERE tenant_id=?1", "DELETE FROM \"grant\" WHERE tenant_id=?1", "DELETE FROM tenant WHERE id=?1"] {
                c.execute(sql, params![TRSR_A]).expect("fixture : destruction d'une version antérieure");
            }
            // Écrits APRÈS la destruction, sous l'identifiant devenu hors catalogue.
            c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'admin')", params![TRSR_UID_ORPHELIN, TRSR_A]).expect("fixture : droit orphelin sous A");
            c.execute("INSERT INTO token(hash,tenant_id,created) VALUES(?1,?2,0)", params![TRSR_AGENT_ORPHELIN, TRSR_A]).expect("fixture : jeton d'agent orphelin sous A");
            c.execute("INSERT INTO token(hash,tenant_id,created) VALUES(?1,?2,0)", params![TRSR_AGENT_B, TRSR_B]).expect("fixture : jeton d'agent de B");
        }
        st.tenants.writers.lock().remove(TRSR_A);
        crate::crypto::unregister_db_key(&chemin);
        for f in [chemin.clone(), format!("{chemin}-wal"), format!("{chemin}-shm")] {
            let _ = std::fs::remove_file(f);
        }
        // PLANCHERS LUS : les restes existent bien avant la recréation.
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM scim_token WHERE tenant_id=?1", TRSR_A), 1, "fixture : le jeton SCIM de A est resté");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM scim_provenance WHERE tenant_id=?1", TRSR_A), 1, "fixture : la provenance de z (A) est restée");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM tenant WHERE id=?1", TRSR_A), 0, "fixture : A n'est plus au catalogue");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE tenant_id=?1", TRSR_A), 1, "fixture : le droit orphelin sous A");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM token WHERE tenant_id=?1", TRSR_A), 1, "fixture : le jeton d'agent orphelin sous A");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE tenant_id=?1", TRSR_B), 1, "fixture : l'administrateur de B");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM token WHERE tenant_id=?1", TRSR_B), 1, "fixture : le jeton d'agent de B");
        (st, dir, z, y, chemin)
    }

    /// CE QU'IL TIENT : A recréé par la route sur des restes d'une version antérieure n'en hérite pas — ni le droit ni le
    /// jeton d'agent orphelins (ceux de B restent), l'ancien jeton
    /// est refusé (`Ok(None)`, et par le routeur réel le `401` d'un jeton inconnu, statut et corps), aucune provenance de
    /// A ne reste, celle de `z` est scellée et `z` est étrangère au A recréé comme à B (`409` et `400 noTarget` en
    /// entier, aucun droit posé) ; le jeton et la provenance de B ne bougent pas ; contrôle positif : le jeton neuf du A
    /// recréé authentifie.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AX3_creation_sans_jetons` (l'ancien jeton authentifie) ;
    /// `AX3_creation_sans_provenance` (provenance de A restée, `POST /Users` 201) ; `AX3_creation_jetons_sans_where`
    /// (jeton de B effacé) ; `AX3_creation_provenance_sans_where` (provenance de y scellée) ;
    /// `AX3_creation_provenance_effacee` (z sans provenance, rattachée par B) ; `AX3C_creation_sans_droits` (droit orphelin
    /// resté) ; `AX3C_creation_sans_agents` (jeton d'agent orphelin resté) ; `AX3C_creation_droits_sans_where`,
    /// `AX3C_creation_agents_sans_where` (ceux de B effacés).
    #[tokio::test]
    async fn trsr_un_tenant_recree_n_herite_ni_jeton_ni_provenance() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir, z, y, _chemin) = trsr_restes_d_une_version_anterieure().await;
        let cp = trsr_plan(&st);

        let (statut, v) = trsr_creer(&st, json!({ "id": TRSR_A, "name": TRSR_A })).await;
        assert_eq!(statut, 201, "A recréé : {v}");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM scim_token WHERE tenant_id=?1", TRSR_A), 0, "aucun jeton SCIM resté sous A");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM scim_provenance WHERE tenant_id=?1", TRSR_A), 0, "aucune provenance restée sous A");
        let provenance_de_z: String = cp.conn.lock().query_row("SELECT tenant_id FROM scim_provenance WHERE user_id=?1", params![z], |r| r.get(0)).expect("provenance de z lue");
        assert_eq!(provenance_de_z, TRSR_TOMBE, "la provenance de z est scellée");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM scim_token WHERE tenant_id=?1", TRSR_B), 1, "le jeton SCIM de B reste");
        let provenance_de_y: String = cp.conn.lock().query_row("SELECT tenant_id FROM scim_provenance WHERE user_id=?1", params![y], |r| r.get(0)).expect("provenance de y lue");
        assert_eq!(provenance_de_y, TRSR_B, "la provenance de y reste celle de B");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE tenant_id=?1", TRSR_A), 0, "aucun droit resté sous A");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM token WHERE tenant_id=?1", TRSR_A), 0, "aucun jeton d'agent resté sous A");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE tenant_id=?1", TRSR_B), 1, "l'administrateur de B reste");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM token WHERE tenant_id=?1", TRSR_B), 1, "le jeton d'agent de B reste");

        trsr_poser_le_jeton(&st, TRSR_JETON_A_RECREE, TRSR_A);
        assert_eq!(scim_authenticate(cp, &trsr_bearer(TRSR_JETON_A)), Ok(None), "l'ancien jeton de A est refusé par le A recréé");
        assert_eq!(scim_authenticate(cp, &trsr_bearer(TRSR_JETON_A_RECREE)), Ok(Some(TRSR_A.to_string())), "contrôle positif : le jeton neuf");
        assert_eq!(scim_authenticate(cp, &trsr_bearer(TRSR_JETON_B)), Ok(Some(TRSR_B.to_string())), "le jeton de B authentifie toujours");

        // PAR LE ROUTEUR RÉEL, hors du mode installation (qui laisserait passer `/scim/v2/*` sans jeton).
        st.installation_ouverte.store(false, std::sync::atomic::Ordering::SeqCst);
        let adresse = router_serve(st.clone()).await;
        let (s_ancien, brut_ancien) = router_probe_corps(adresse, "GET", "/scim/v2/Users", Some(&trsr_bearer(TRSR_JETON_A)), &[]).await;
        let (s_inconnu, brut_inconnu) = router_probe_corps(adresse, "GET", "/scim/v2/Users", Some(&trsr_bearer(TRSR_JETON_INCONNU)), &[]).await;
        let (s_neuf, brut_neuf) = router_probe_corps(adresse, "GET", "/scim/v2/Users", Some(&trsr_bearer(TRSR_JETON_A_RECREE)), &[]).await;
        assert_eq!(s_ancien, 401, "l'ancien jeton de A : 401 : {brut_ancien}");
        assert_eq!((s_ancien, trsr_corps_http(&brut_ancien)), (s_inconnu, trsr_corps_http(&brut_inconnu)), "même statut, même corps qu'un jeton inconnu");
        assert_eq!(s_neuf, 200, "contrôle positif par le routeur : {brut_neuf}");

        // z est ÉTRANGÈRE au A recréé et à B.
        let refus_409 = json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "scimType": "uniqueness", "detail": TRSR_DETAIL_409, "status": "409" });
        let refus_400 = json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "scimType": "noTarget", "detail": TRSR_DETAIL_NO_TARGET, "status": "400" });
        for tenant in [TRSR_A, TRSR_B] {
            let (statut, v) = trsr_post(&st, tenant, "trsr-z").await;
            assert_eq!((statut, &v), (409, &refus_409), "POST /Users de z depuis {tenant} : le 409, EN ENTIER");
            let (statut, v) = trsr_patch_add(&st, tenant, &z).await;
            assert_eq!((statut, &v), (400, &refus_400), "PATCH add de z depuis {tenant} : le noTarget, EN ENTIER");
        }
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE user_id=?1", &z), 0, "aucun droit posé à z");
    }

    /// CE QU'IL TIENT : créer un tenant qui existe rend `409` « existe déjà » et n'efface rien sous son identifiant (son
    /// jeton SCIM authentifie encore, sa provenance reste).
    /// LA MUTATION QUI LE FAIT ROUGIR : `AX3_creation_sans_existe` (l'insertion refusée par la clé primaire : le `503` de la
    /// ligne non inscrite au lieu du `409`).
    #[tokio::test]
    async fn trsr_un_tenant_existant_n_est_ni_recree_ni_efface() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = mk_mode1_state();
        let (statut, v) = trsr_creer(&st, json!({ "id": TRSR_B, "name": TRSR_B })).await;
        assert_eq!(statut, 201, "fixture : B créé : {v}");
        trsr_poser_le_jeton(&st, TRSR_JETON_B, TRSR_B);
        let (statut, v) = trsr_post(&st, TRSR_B, "trsr-y").await;
        assert_eq!(statut, 201, "fixture : y créée par B : {v}");
        let avant = trsr_instantane(&st);
        let (statut, v) = trsr_creer(&st, json!({ "id": TRSR_B, "name": "autre nom" })).await;
        assert_eq!((statut, v), (409, Value::String(format!("tenant '{TRSR_B}' existe déjà"))), "le 409 d'avant, en entier");
        assert_eq!(trsr_instantane(&st), avant, "rien n'est effacé ni écrit");
        assert_eq!(scim_authenticate(trsr_plan(&st), &trsr_bearer(TRSR_JETON_B)), Ok(Some(TRSR_B.to_string())), "le jeton de B authentifie encore");
    }

    /// Les refus de la création, chacun SEUL (posé, la route jouée, levé), sur des restes d'une version antérieure, puis
    /// le contrôle positif.
    async fn trsr_jouer_les_refus(st: &AppState, chemin: &str) {
        let cp = trsr_plan(st);
        let tables = ["scim_token", "scim_provenance", "token", "grant"];
        // PLANCHER LIÉ À LA PRODUCTION : les effacements joués sont EXACTEMENT ceux de la création, dans leur ordre.
        let de_la_production: Vec<&str> = crate::tenants::RESTES_SOUS_UN_IDENTIFIANT_DE_TENANT
            .iter()
            .map(|(_, sql)| {
                let reste = sql.strip_prefix("DELETE FROM ").or_else(|| sql.strip_prefix("UPDATE ")).unwrap_or_else(|| panic!("énoncé non reconnu : {sql}"));
                reste.split_whitespace().next().expect("table nommée").trim_matches('"')
            })
            .collect();
        assert_eq!(tables.to_vec(), de_la_production, "les effacements joués sont ceux de la production");
        let mut cas: Vec<(String, &str)> = tables.iter().map(|t| (format!("effacement {t}"), TRSR_PHRASE_EFFACEMENT)).collect();
        cas.push(("insertion".to_string(), TRSR_PHRASE_INSERTION));
        cas.push(("begin".to_string(), TRSR_PHRASE_BEGIN));
        cas.push(("commit".to_string(), TRSR_PHRASE_COMMIT));
        for (quoi, phrase) in &cas {
            let avant = trsr_instantane(st);
            match quoi.as_str() {
                "begin" => cp.conn.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Transaction { operation: TransactionOperation::Begin } => Authorization::Deny,
                    _ => Authorization::Allow,
                })),
                "commit" => cp.conn.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
                    _ => Authorization::Allow,
                })),
                "insertion" => cp
                    .conn
                    .lock()
                    .execute_batch(&format!("CREATE TEMP TRIGGER trsr_refus BEFORE INSERT ON main.tenant BEGIN SELECT RAISE(ABORT, '{TRSR_MOTEUR}'); END;"))
                    .expect("fixture : déclencheur posé"),
                autre => {
                    let table = autre.trim_start_matches("effacement ");
                    cp.conn
                        .lock()
                        .execute_batch(&format!(
                            "CREATE TEMP TRIGGER trsr_refus BEFORE DELETE ON main.\"{table}\" BEGIN SELECT RAISE(ABORT, '{TRSR_MOTEUR}'); END; \
                             CREATE TEMP TRIGGER trsr_refus_maj BEFORE UPDATE ON main.\"{table}\" BEGIN SELECT RAISE(ABORT, '{TRSR_MOTEUR}'); END;"
                        ))
                        .expect("fixture : déclencheur posé");
                }
            }
            let (statut, v) = trsr_creer(st, json!({ "id": TRSR_A, "name": TRSR_A })).await;
            cp.conn.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
            let _ = cp.conn.lock().execute_batch("DROP TRIGGER IF EXISTS temp.trsr_refus; DROP TRIGGER IF EXISTS temp.trsr_refus_maj;");
            assert_eq!(statut, 503, "{quoi} : la création est REFUSÉE : {v}");
            let cles: Vec<&String> = v.as_object().expect("corps objet").keys().collect();
            assert_eq!(cles, vec!["error", "id"], "{quoi} : le corps EXACT, ensemble des clés : {v}");
            assert_eq!(v["error"].as_str(), Some(*phrase), "{quoi} : la phrase fixe, sans le texte du moteur : {v}");
            assert!(v["id"].as_str().is_some_and(|i| i.starts_with("plume-e")), "{quoi} : l'identifiant de corrélation : {v}");
            assert_eq!(trsr_instantane(st), avant, "{quoi} : RIEN n'est écrit ni effacé dans le plan de contrôle");
            assert!(!std::path::Path::new(chemin).exists(), "{quoi} : aucune base chiffrée n'est créée");
            assert!(!crate::crypto::db_key_registry().lock().contains_key(chemin), "{quoi} : aucune clé n'est enregistrée");
        }
        // CONTRÔLE POSITIF — plus rien n'est refusé : la même demande crée, et les restes sont retirés.
        let (statut, v) = trsr_creer(st, json!({ "id": TRSR_A, "name": TRSR_A })).await;
        assert_eq!(statut, 201, "le refus n'est pas inconditionnel : {v}");
        assert!(std::path::Path::new(chemin).exists(), "la base chiffrée est créée");
        for sql in ["SELECT COUNT(*) FROM scim_token WHERE tenant_id=?1", "SELECT COUNT(*) FROM token WHERE tenant_id=?1", "SELECT COUNT(*) FROM \"grant\" WHERE tenant_id=?1"] {
            assert_eq!(trsr_compter(st, sql, TRSR_A), 0, "les restes sont retirés : {sql}");
        }
    }

    /// CE QU'IL TIENT : chacun des quatre effacements des restes refusé seul (jetons SCIM, provenance, jetons d'agent,
    /// droits), l'inscription de la ligne du tenant refusée, le `BEGIN` refusé, le `COMMIT` refusé : `503` au corps EXACT (`error` = la phrase fixe de la classe, `id`), RIEN de créé
    /// (plan de contrôle identique, ni fichier ni clé), les restes intacts ; puis la même demande crée.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AX3_creation_erreur_avalee` (201) ; `AX3_creation_begin_400`,
    /// `AX3_creation_commit_400`, `AX3_creation_route_400` (400) ; `AX3C_insertion_400` (l'insertion refusée servie en
    /// `400` avec le texte du moteur, la forme d'avant) ; `AX3C_insertion_phrase_effacement` (sous la phrase d'un
    /// effacement).
    #[tokio::test]
    async fn trsr_un_refus_de_la_creation_ne_cree_rien() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir, _z, _y, chemin) = trsr_restes_d_une_version_anterieure().await;
        trsr_jouer_les_refus(&st, &chemin).await;
    }

    /// CE QU'IL TIENT, DANS UN PROCESSUS ENFANT (sortie d'erreur lisible) : chacun des refus joués par
    /// `trsr_jouer_les_refus` est DIT par sa ligne `[tenants]` qui nomme la création du tenant, ENTIÈRE, dans l'ordre —
    /// `WARN` pour les quatre effacements, l'insertion et le `COMMIT`, `ERREUR` pour le `BEGIN` refusé (la phrase commune de
    /// `dire_la_transaction_non_ouverte`, libellés compris) ; la cause du moteur y figure, aucun identifiant ni chemin.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AX3_creation_journal_effacement_muet`, `AX3_creation_journal_commit_muet`,
    /// `AX3_creation_begin_libelle`, `AX3C_insertion_journal_muet`.
    #[tokio::test]
    async fn trsr_les_refus_de_la_creation_sont_dits_au_journal() {
        const ENFANT: &str = "TRSR_REFUS_DE_LA_CREATION_ENFANT";
        if std::env::var(ENFANT).is_ok() {
            let _env = VERROU_ENV_PROCESSUS.read();
            let (st, _dir, _z, _y, chemin) = trsr_restes_d_une_version_anterieure().await;
            trsr_jouer_les_refus(&st, &chemin).await;
            println!("TRSR-ENFANT-A-JOUE");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::tenant_recree_sans_restes_scim::trsr_les_refus_de_la_creation_sont_dits_au_journal"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("TRSR-ENFANT-A-JOUE"), "contrôle : l'enfant a vraiment joué : {stdout}\n{stderr}");
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[tenants] ") && l.contains("création du tenant")).collect();
        let attendues = vec![
            format!("[tenants] WARN création du tenant NON faite, rien n'est créé (effacement refusé : jetons SCIM) : {TRSR_MOTEUR}"),
            format!("[tenants] WARN création du tenant NON faite, rien n'est créé (effacement refusé : provenance SCIM) : {TRSR_MOTEUR}"),
            format!("[tenants] WARN création du tenant NON faite, rien n'est créé (effacement refusé : jetons d'agent) : {TRSR_MOTEUR}"),
            format!("[tenants] WARN création du tenant NON faite, rien n'est créé (effacement refusé : droits) : {TRSR_MOTEUR}"),
            format!("[tenants] WARN création du tenant NON faite, rien n'est créé (ligne du tenant non inscrite) : {TRSR_MOTEUR}"),
            "[tenants] ERREUR création du tenant NON pris(e) : BEGIN refusé par la base, et ce n'est pas un verrou (not authorized) — rien n'est écrit ; un nouvel essai sera refusé de même tant que la cause demeure (base en lecture seule, disque, E/S)".to_string(),
            "[tenants] WARN création du tenant NON faite, rien n'est créé (COMMIT refusé) : not authorized".to_string(),
        ];
        // PLANCHER LIÉ À LA PRODUCTION : un effacement par entrée de `RESTES_SOUS_UN_IDENTIFIANT_DE_TENANT`, l'insertion,
        // le `BEGIN`, le `COMMIT`.
        assert_eq!(attendues.len(), 3 + crate::tenants::RESTES_SOUS_UN_IDENTIFIANT_DE_TENANT.len(), "une ligne attendue par refus joué");
        assert_eq!(lignes, attendues.iter().map(String::as_str).collect::<Vec<_>>(), "les lignes ENTIÈRES, dans l'ordre :\n{stderr}");
    }

    /// CE QU'IL TIENT : un tenant à clé `vault:chemin` (sans champ : rangée au cache sous `chemin#key`) — une destruction
    /// refusée (effacement des jetons SCIM) laisse le cache Vault, l'écrivain mémoïsé et la clé du registre en place ; la
    /// destruction validée les oublie tous les trois.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AX3_vault_oubli_ancien` (oubli sous `chemin`, la clé reste au cache) ;
    /// `AX3_vault_oublie_sur_refus` (cache oublié sur l'effacement refusé).
    #[tokio::test]
    async fn trsr_le_cache_vault_d_un_tenant_detruit_est_oublie_apres_le_commit() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, dir) = mk_mode1_state();
        let coffre = format!("trsr-coffre/{}", sha256_hex(format!("{dir}").as_bytes()));
        let rangement = format!("{coffre}#key");
        let cle_du_coffre = sha256_hex(rangement.as_bytes());
        crate::crypto::vault_key_cache_put(&rangement, &cle_du_coffre);
        let (statut, v) = trsr_creer(&st, json!({ "id": TRSR_A, "name": TRSR_A, "key_ref": format!("vault:{coffre}") })).await;
        assert_eq!(statut, 201, "fixture : A créé sur sa clé Vault (cache) : {v}");
        let cp = trsr_plan(&st);
        // Un jeton SCIM de A : le déclencheur de refus ne joue que sur une ligne effacée.
        trsr_poser_le_jeton(&st, TRSR_JETON_A, TRSR_A);
        let chemin: String = cp.conn.lock().query_row("SELECT db_path FROM tenant WHERE id=?1", params![TRSR_A], |r| r.get(0)).expect("fixture : A catalogué");
        assert!(st.tenants.handle_for(TRSR_A).is_some(), "fixture : l'écrivain de A est servi");
        assert_eq!(crate::crypto::db_key_registry().lock().get(&chemin).cloned(), Some(Some(cle_du_coffre.clone())), "fixture : la clé du coffre est au registre");

        cp.conn
            .lock()
            .execute_batch(&format!("CREATE TEMP TRIGGER trsr_refus BEFORE DELETE ON main.scim_token BEGIN SELECT RAISE(ABORT, '{TRSR_MOTEUR}'); END;"))
            .expect("fixture : déclencheur posé");
        let (statut, v) = trsr_corps(tenant_delete(State(st.clone()), Extension(au_super("trsr-op")), Path(TRSR_A.into()), Json(json!({ "confirm": TRSR_A }))).await).await;
        cp.conn.lock().execute_batch("DROP TRIGGER IF EXISTS temp.trsr_refus;").expect("fixture : déclencheur levé");
        assert_eq!((statut, v["error"].as_str()), (503, Some(TRSR_PHRASE_DESTRUCTION_EFFACEMENT)), "la destruction est refusée : {v}");
        assert_eq!(crate::crypto::vault_key_cache_get(&rangement), Some(cle_du_coffre.clone()), "refus : la clé reste au cache Vault");
        assert!(st.tenants.writers.lock().contains_key(TRSR_A), "refus : l'écrivain de A reste mémoïsé");
        assert_eq!(crate::crypto::db_key_registry().lock().get(&chemin).cloned(), Some(Some(cle_du_coffre.clone())), "refus : la clé reste au registre");

        let (statut, v) = trsr_corps(tenant_delete(State(st.clone()), Extension(au_super("trsr-op")), Path(TRSR_A.into()), Json(json!({ "confirm": TRSR_A }))).await).await;
        assert_eq!(statut, 200, "contrôle positif : A détruit : {v}");
        assert_eq!(crate::crypto::vault_key_cache_get(&rangement), None, "la clé du tenant détruit est oubliée du cache Vault");
        assert!(!st.tenants.writers.lock().contains_key(TRSR_A), "l'écrivain de A est évincé");
        assert!(!crate::crypto::db_key_registry().lock().contains_key(&chemin), "la clé de A est oubliée du registre");
    }

    /// CE QU'IL TIENT : les refus d'avant que le lot a retypés — `tenant_destroy("default")` rend sa phrase et ne touche à
    /// rien ; en mode 0, `tenant_destroy` et `tenant_provision` rendent leur phrase ; par la route, un tenant retiré entre
    /// la lecture de son nom et la transaction (destruction concurrente, jouée par un déclencheur sur la ligne du journal
    /// de contrôle) rend `500` « tenant '…' inconnu », le texte d'avant.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AX3_default_sans_garde` ; `AX3_mode0_ok` ; `AX3_route_refusee_200`.
    #[tokio::test]
    async fn trsr_les_refus_d_avant_de_la_destruction_restent_des_refus() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = mk_mode1_state();
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM tenant WHERE id=?1", "default"), 1, "fixture : `default` est catalogué");
        let avant = trsr_instantane(&st);
        let rendu = tenant_destroy(&st.tenants, "default");
        assert!(
            matches!(&rendu, Err(crate::tenants::DestructionNonFaite::Refusee(m)) if m == "refus : le tenant 'default' ne peut pas être détruit"),
            "`default` : {rendu:?}"
        );
        assert_eq!(trsr_instantane(&st), avant, "`default` : rien n'est touché");

        let st0 = tenant_test_state("trsr-a", "trsr-e", "trsr-s", None);
        let rendu = tenant_destroy(&st0.tenants, TRSR_A);
        assert!(
            matches!(&rendu, Err(crate::tenants::DestructionNonFaite::Refusee(m)) if m == "multi-tenant désactivé (mode 0) : destruction indisponible"),
            "mode 0, destruction : {rendu:?}"
        );
        let rendu = tenant_provision(&st0.tenants, TRSR_A, TRSR_A, "/nulle-part/trsr.db", "");
        assert!(
            matches!(&rendu, Err(crate::tenants::ProvisionNonFaite::Refusee(m)) if m == "multi-tenant désactivé (mode 0) : provisioning indisponible"),
            "mode 0, création : {rendu:?}"
        );

        let (statut, v) = trsr_creer(&st, json!({ "id": TRSR_A, "name": TRSR_A })).await;
        assert_eq!(statut, 201, "fixture : A créé : {v}");
        let cp = trsr_plan(&st);
        cp.conn
            .lock()
            .execute_batch(&format!("CREATE TEMP TRIGGER trsr_concurrente AFTER INSERT ON main.control_ledger BEGIN DELETE FROM tenant WHERE id='{TRSR_A}'; END;"))
            .expect("fixture : déclencheur posé");
        let (statut, v) = trsr_corps(tenant_delete(State(st.clone()), Extension(au_super("trsr-op")), Path(TRSR_A.into()), Json(json!({ "confirm": TRSR_A }))).await).await;
        cp.conn.lock().execute_batch("DROP TRIGGER IF EXISTS temp.trsr_concurrente;").expect("fixture : déclencheur levé");
        assert_eq!((statut, v), (500, Value::String(format!("tenant '{TRSR_A}' inconnu"))), "la destruction concurrente : le 500 d'avant, en entier");
    }

    fn trsr_droits(st: &AppState, tenant: &str) -> Vec<String> {
        let c = trsr_plan(st).conn.lock();
        let mut s = c.prepare("SELECT g.user_id||':'||g.role FROM \"grant\" g WHERE g.tenant_id=?1 ORDER BY 1").expect("fixture");
        let lus = s.query_map(params![tenant], |r| r.get::<_, String>(0)).expect("fixture").collect::<Result<Vec<_>, _>>().expect("fixture : lisible");
        lus
    }

    fn trsr_uid(st: &AppState, nom: &str) -> String {
        trsr_plan(st).conn.lock().query_row("SELECT id FROM platform_user WHERE name=?1", params![nom], |r| r.get(0)).expect("fixture : identité lue")
    }

    /// CE QU'IL TIENT : une demande SCIM de A admise AVANT la destruction de A (`POST /Users` du premier administrateur de
    /// A, sans provenance, groupe `admin`), dont la transaction des droits tombe APRÈS le `COMMIT` de la destruction
    /// (point de course de production `scim-identite-avant-ses-droits`) : le droit écrit sous l'identifiant hors catalogue
    /// (plancher : la course a bien écrit) ne passe pas au A recréé — aucun droit sous A, l'administrateur de l'ancien A
    /// n'administre rien ; le droit de l'administrateur de B reste.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AX3C_creation_sans_droits` (le A recréé hérite du droit `admin`).
    #[tokio::test]
    async fn trsr_une_demande_en_vol_pendant_la_destruction_ne_donne_aucun_droit_au_tenant_recree() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = mk_mode1_state();
        let (statut, v) = trsr_creer(&st, json!({ "id": TRSR_A, "name": TRSR_A, "admin": TRSR_ADMIN_A })).await;
        assert_eq!(statut, 201, "fixture : A créé : {v}");
        let (statut, v) = trsr_creer(&st, json!({ "id": TRSR_B, "name": TRSR_B, "admin": TRSR_ADMIN_B })).await;
        assert_eq!(statut, 201, "fixture : B créé : {v}");
        let adm_a = trsr_uid(&st, TRSR_ADMIN_A);
        let adm_b = trsr_uid(&st, TRSR_ADMIN_B);
        assert_eq!(trsr_droits(&st, TRSR_A), vec![format!("{adm_a}:admin")], "fixture : l'administrateur de l'ancien A");

        let mgr = st.tenants.clone();
        crate::handlers::transaction_validee::poser_un_crochet_de_course(&format!("scim-identite-avant-ses-droits:{}", trsr_plan(&st).db_path), move || {
            assert!(tenant_destroy(&mgr, TRSR_A).is_ok(), "fixture : A détruit pendant la demande en vol");
        });
        let _ = trsr_corps(
            scim_user_create(
                State(st.clone()),
                Extension(ScimCtx { tenant: TRSR_A.into() }),
                Json(json!({ "userName": TRSR_ADMIN_A, "groups": [{ "value": "admin" }] })),
            )
            .await,
        )
        .await;
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM tenant WHERE id=?1", TRSR_A), 0, "fixture : A est détruit");
        // PLANCHER : la course a bien écrit sous l'identifiant hors catalogue (sinon ce témoin ne prouve rien).
        assert_eq!(trsr_droits(&st, TRSR_A), vec![format!("{adm_a}:admin")], "fixture : le droit écrit après la destruction");

        let (statut, v) = trsr_creer(&st, json!({ "id": TRSR_A, "name": TRSR_A })).await;
        assert_eq!(statut, 201, "A recréé : {v}");
        assert_eq!(trsr_droits(&st, TRSR_A), Vec::<String>::new(), "le A recréé n'hérite d'aucun droit de l'ancien A");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE user_id=?1", &adm_a), 0, "l'administrateur de l'ancien A n'a de droit nulle part");
        assert_eq!(trsr_droits(&st, TRSR_B), vec![format!("{adm_b}:admin")], "le droit de B reste");
    }

    /// CE QU'IL TIENT : une demande SCIM de A admise avant la destruction, dont l'écriture tombe APRÈS la destruction ET la
    /// recréation de A (même point de course), pour une identité que le SCIM de l'ancien A a créée : la transaction des
    /// droits rejuge le rattachement (provenance scellée) et rend le `409` d'un nom pris hors du tenant, EN ENTIER ; aucun
    /// droit sous le A recréé.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AX3C_rattachement_non_rejuge` (l'étrangère admise dans la transaction : `201`).
    #[tokio::test]
    async fn trsr_une_demande_en_vol_apres_la_recreation_ne_rattache_pas_une_identite_scellee() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = mk_mode1_state();
        let (statut, v) = trsr_creer(&st, json!({ "id": TRSR_A, "name": TRSR_A })).await;
        assert_eq!(statut, 201, "fixture : A créé : {v}");
        let (statut, v) = trsr_post(&st, TRSR_A, "trsr-z").await;
        assert_eq!(statut, 201, "fixture : z créée par le SCIM de A : {v}");
        let z = v["id"].as_str().expect("id servi").to_string();

        let st_course = st.clone();
        crate::handlers::transaction_validee::poser_un_crochet_de_course(&format!("scim-identite-avant-ses-droits:{}", trsr_plan(&st).db_path), move || {
            assert!(tenant_destroy(&st_course.tenants, TRSR_A).is_ok(), "fixture : A détruit pendant la demande en vol");
            let chemin = format!("{}.recree", trsr_plan(&st_course).db_path);
            assert!(tenant_provision(&st_course.tenants, TRSR_A, TRSR_A, &chemin, "").is_ok(), "fixture : A recréé pendant la demande en vol");
        });
        let (statut, v) = trsr_corps(
            scim_user_create(State(st.clone()), Extension(ScimCtx { tenant: TRSR_A.into() }), Json(json!({ "userName": "trsr-z", "groups": [{ "value": "viewer" }] })))
                .await,
        )
        .await;
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM tenant WHERE id=?1", TRSR_A), 1, "fixture : A est recréé");
        let refus_409 = json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "scimType": "uniqueness", "detail": TRSR_DETAIL_409, "status": "409" });
        assert_eq!((statut, &v), (409, &refus_409), "la demande en vol : le 409, EN ENTIER");
        assert_eq!(trsr_droits(&st, TRSR_A), Vec::<String>::new(), "aucun droit sous le A recréé");
        assert_eq!(trsr_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE user_id=?1", &z), 0, "aucun droit posé à z");
    }

    /// CE QU'IL TIENT : un tenant à clé `vault:chemin#champ` d'un champ EXPLICITE autre que `key` : sa destruction par la
    /// route oublie la clé rangée sous `chemin#champ` (la référence par défaut est tenue par le témoin voisin).
    /// LA MUTATION QUI LE FAIT ROUGIR : `AX3C_vault_champ_fixe` (oubli sous `chemin#key` quel que soit le champ).
    #[tokio::test]
    async fn trsr_le_cache_vault_a_champ_explicite_d_un_tenant_detruit_est_oublie() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, dir) = mk_mode1_state();
        let coffre = format!("trsr-coffre-champ/{}", sha256_hex(format!("{dir}").as_bytes()));
        let rangement = format!("{coffre}#autre");
        let cle_du_coffre = sha256_hex(rangement.as_bytes());
        crate::crypto::vault_key_cache_put(&rangement, &cle_du_coffre);
        let (statut, v) = trsr_creer(&st, json!({ "id": TRSR_A, "name": TRSR_A, "key_ref": format!("vault:{rangement}") })).await;
        assert_eq!(statut, 201, "fixture : A créé sur sa clé Vault à champ explicite (cache) : {v}");
        assert_eq!(crate::crypto::vault_key_cache_get(&rangement), Some(cle_du_coffre.clone()), "fixture : la clé est au cache");
        let (statut, v) = trsr_corps(tenant_delete(State(st.clone()), Extension(au_super("trsr-op")), Path(TRSR_A.into()), Json(json!({ "confirm": TRSR_A }))).await).await;
        assert_eq!(statut, 200, "A détruit : {v}");
        assert_eq!(crate::crypto::vault_key_cache_get(&rangement), None, "la clé du tenant détruit est oubliée du cache Vault (champ explicite)");
    }
}

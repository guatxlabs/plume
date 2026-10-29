// =====================================================================================
// `P10.34-h` (suite) — UN JETON SCIM D'UN TENANT ABSENT, DÉTRUIT OU RECRÉÉ EST REFUSÉ, Y COMPRIS POUR UNE
// DEMANDE DÉJÀ ADMISE ; LA SOUS-COMMANDE `scim-token` NE FRAPPE PAS DE JETON POUR UN TENANT ABSENT DU CATALOGUE.
//
// CE QUI CHANGE (daemon/src/scim.rs, daemon/src/auth.rs, daemon/src/main.rs) : le contexte SCIM porte l'empreinte du
// jeton admis à l'entrée (`scim_authentifier_la_demande`) ; chaque transaction d'écriture SCIM (droits de `POST /Users`,
// déprovisionnement de `PUT active=false` et `DELETE`, opérations de `PATCH /Groups`) relit, sous son verrou et avant
// toute lecture ou écriture du geste, que CE jeton existe encore sous CE tenant catalogué (`scim_exiger_le_jeton_sur`) ;
// `POST /Users` le relit aussi avant de poser l'identité. Retiré : le `401` de l'entrée (même statut, même corps) ; non
// relu : `503` à phrase fixe. `scim-token <tenant>` n'inscrit le jeton que si le tenant est au catalogue.
//
// CE QUE CES TÉMOINS TIENNENT, en mode multi-tenant avec DEUX tenants réels (`tenant_create`, bases chiffrées) :
//  * PAR LE ROUTEUR RÉEL, une demande ADMISE par l'entrée (date d'usage du jeton relue posée) avant la destruction PUIS
//    la recréation de A (qui porte un jeton NEUF), achevée ensuite : `POST /Users` (avant toute pose d'identité),
//    `PUT active=false`, `PATCH /Groups` rendent le `401` de l'entrée, EN ENTIER, et l'état du plan de contrôle (jetons,
//    provenance, droits, identités, catalogue, journal de contrôle) est identique avant et après ; `DELETE` par un
//    contexte fabriqué comme l'entrée le fabrique, admis avant la recréation ;
//  * chaque route, avec le jeton NEUF du A recréé, par le routeur : le geste a lieu (contrôles positifs) ;
//  * le même secret reposé sous B après la destruction de A ne vaut pas pour une demande de A ; le jeton de A reposé
//    sous l'identifiant de A hors catalogue ne vaut rien ;
//  * la course placée au point de course de production `scim-jeton-avant-l-identite`, désormais AVANT le verrou sous
//    lequel le jeton est relu puis l'identité posée (`P10.34-q`) : le `401`, ni identité, ni provenance, ni droit ;
//  * le jeton non relu au moment d'écrire, à chaque site (avant l'identité, droits de `POST /Users`, `PUT`, `DELETE`,
//    `PATCH`) : le `503` au corps EXACT, rien d'écrit par l'étape ;
//  * `scim-token` sur un tenant absent, par `main` dans un processus enfant : sortie 2, la ligne de refus ENTIÈRE, aucun
//    jeton affiché ni inscrit ; contrôle positif sur `default`.
//
// MUTANTS (sous `cfg!(test)`, choisis par `VERIF_MUT`, retirés avant le commit), chacun vu ROUGE : AY1_precontrole_absent,
// AY1_tx_post_sans_jeton, AY1_tx_deprov_sans_jeton, AY1_tx_patch_sans_jeton, AY1_sans_empreinte, AY1_sans_tenant,
// AY1_sans_jointure, AY1_retire_admis, AY1_lecture_ratee_401, AY1_deprov_refus_404, AY1_auth_empreinte_vide,
// AY1_cli_sans_condition, AY1_cli_sortie_zero, AY1_cli_ligne_muette.
//
// LIMITES : les lignes `[scim]` des `503` sont celles de `scim_refuser_a_rejouer`, inchangée, et ne sont pas capturées
// ici. Les lectures (`GET`, `PUT active=true`) et l'existence lue par `PUT active=false`/`DELETE` sont témoignées dans
// `jeton_scim_relu_avant_toute_lecture.rs` (`P10.34-q`).
// =====================================================================================
mod jeton_scim_relu_a_chaque_ecriture {
    use super::*;

    pub(super) const JSRE_A: &str = "jsre-a";
    pub(super) const JSRE_B: &str = "jsre-b";
    pub(super) const JSRE_JETON_A: &str = "jsre-jeton-de-test-a";
    pub(super) const JSRE_JETON_A_RECREE: &str = "jsre-jeton-de-test-a-recree";
    pub(super) const JSRE_JETON_B: &str = "jsre-jeton-de-test-b";
    const JSRE_JETON_INCONNU: &str = "jsre-jeton-de-test-jamais-pose";
    /// Premier administrateur de A (sans provenance : rattachable par la création de tenant), puis du A recréé.
    pub(super) const JSRE_X: &str = "jsre-x";
    /// Second administrateur du A recréé : le déprovisionnement de X n'est pas celui du dernier administrateur.
    pub(super) const JSRE_Y: &str = "jsre-y";
    pub(super) const JSRE_UID_Y: &str = "pu_jsre_y";
    /// Une identité sans droit ni provenance (rattachable par tout tenant SCIM) : la cible d'un `PATCH add`.
    pub(super) const JSRE_W: &str = "jsre-w";
    pub(super) const JSRE_UID_W: &str = "pu_jsre_w";
    const JSRE_ADMIN_B: &str = "jsre-adm-b";
    /// Le refus de l'entrée, RECOPIÉ (jamais lu de la production).
    pub(super) const JSRE_CORPS_401: &str = "SCIM : bearer invalide";
    /// La phrase du jeton non relu, RECOPIÉE.
    const JSRE_PHRASE_NON_RELU: &str = "JETON NON REVÉRIFIÉ : la base du plan de contrôle n'a pas pu relire le jeton SCIM de cette demande au moment de la servir — sa validité n'est ni affirmée ni niée. Rien n'est lu ni écrit par cette étape : aucun droit n'est posé ni retiré, les accès en place restent en place. Rien n'est attesté ; la même demande peut être rejouée telle quelle.";
    /// La ligne de refus de `scim-token`, RECOPIÉE.
    const JSRE_LIGNE_CLI_ABSENT: &str =
        "scim-token : REFUS — le tenant 'jsre-absent' n'est pas au catalogue du plan de contrôle : aucun jeton n'est créé.";
    const JSRE_ENFANT: &str = "PLUME_TEMOIN_JSRE_ENFANT";
    const JSRE_MARQUE_ENFANT: &str = "JSRE-ENFANT-A-ATTEINT-MAIN";

    pub(super) fn jsre_plan(st: &AppState) -> &ControlPlane {
        st.tenants.control.as_ref().expect("fixture : mode 1")
    }

    pub(super) fn jsre_sql(st: &AppState, sql: &str) {
        jsre_plan(st).conn.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    pub(super) fn jsre_poser_le_jeton(st: &AppState, jeton: &str, tenant: &str) {
        jsre_plan(st)
            .conn
            .lock()
            .execute("INSERT INTO scim_token(hash,tenant_id,created) VALUES(?1,?2,0)", params![sha256_hex(jeton.as_bytes()), tenant])
            .expect("fixture : jeton SCIM posé");
    }

    pub(super) fn jsre_uid(st: &AppState, nom: &str) -> String {
        jsre_plan(st).conn.lock().query_row("SELECT id FROM platform_user WHERE name=?1", params![nom], |r| r.get(0)).expect("fixture : identité lue")
    }

    pub(super) fn jsre_compter(st: &AppState, sql: &str, valeur: &str) -> i64 {
        jsre_plan(st).conn.lock().query_row(sql, params![valeur], |r| r.get(0)).expect("fixture : compte lisible")
    }

    pub(super) fn jsre_droits(st: &AppState, tenant: &str) -> Vec<String> {
        let c = jsre_plan(st).conn.lock();
        let mut s = c.prepare("SELECT p.name||':'||g.role FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id WHERE g.tenant_id=?1 ORDER BY 1").expect("fixture");
        let lus = s.query_map(params![tenant], |r| r.get::<_, String>(0)).expect("fixture").collect::<Result<Vec<_>, _>>().expect("fixture : lisible");
        lus
    }

    /// L'état du plan de contrôle qu'une écriture SCIM peut toucher : jetons (sans leur date d'usage), provenance, droits,
    /// identités, catalogue, journal de contrôle.
    pub(super) fn jsre_instantane(st: &AppState) -> Vec<String> {
        let c = jsre_plan(st).conn.lock();
        let mut tout = Vec::new();
        for sql in [
            "SELECT 'scim_token|'||hash||'|'||tenant_id FROM scim_token",
            "SELECT 'scim_provenance|'||user_id||'|'||tenant_id FROM scim_provenance",
            "SELECT 'grant|'||user_id||'|'||tenant_id||'|'||role FROM \"grant\"",
            "SELECT 'platform_user|'||id||'|'||name FROM platform_user",
            "SELECT 'tenant|'||id||'|'||name FROM tenant",
            "SELECT 'control_ledger|'||id||'|'||kind||'|'||tenant FROM control_ledger",
        ] {
            let mut s = c.prepare(sql).expect("fixture");
            let lus = s.query_map([], |r| r.get::<_, String>(0)).expect("fixture").collect::<Result<Vec<_>, _>>().expect("fixture : lisible");
            tout.extend(lus);
        }
        tout.sort();
        tout
    }

    pub(super) async fn jsre_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    /// Le corps d'une réponse HTTP/1.1 brute, découpage `chunked` défait (le serveur découpe les corps sans longueur).
    fn jsre_corps_http(brut: &str) -> String {
        let Some((entetes, corps)) = brut.split_once("\r\n\r\n") else { return String::new() };
        if !entetes.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            return corps.to_string();
        }
        let mut reste = corps;
        let mut sortie = String::new();
        while let Some((taille, suite)) = reste.split_once("\r\n") {
            let n = usize::from_str_radix(taille.trim(), 16).expect("fixture : taille de morceau");
            if n == 0 {
                break;
            }
            sortie.push_str(&suite[..n]);
            reste = suite[n..].strip_prefix("\r\n").expect("fixture : fin de morceau");
        }
        sortie
    }

    pub(super) fn jsre_refus_non_relu() -> Value {
        json!({ "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": JSRE_PHRASE_NON_RELU, "status": "503" })
    }

    async fn jsre_creer(st: &AppState, corps: Value) -> (u16, Value) {
        jsre_corps(tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("jsre-op")), Json(corps)).await).await
    }

    /// Deux tenants réels : A (premier administrateur X) et B (son administrateur), un jeton SCIM chacun ; Y et W, deux
    /// identités sans droit ni provenance. Le mode installation est fermé (il laisserait passer `/scim/v2/*`).
    pub(super) async fn jsre_deux_tenants() -> (AppState, crate::tmp_possede::TmpPossede) {
        let (st, dir) = mk_mode1_state();
        let (statut, v) = jsre_creer(&st, json!({ "id": JSRE_A, "name": JSRE_A, "admin": JSRE_X })).await;
        assert_eq!(statut, 201, "fixture : A créé avec X : {v}");
        let (statut, v) = jsre_creer(&st, json!({ "id": JSRE_B, "name": JSRE_B, "admin": JSRE_ADMIN_B })).await;
        assert_eq!(statut, 201, "fixture : B créé : {v}");
        jsre_poser_le_jeton(&st, JSRE_JETON_A, JSRE_A);
        jsre_poser_le_jeton(&st, JSRE_JETON_B, JSRE_B);
        {
            let c = jsre_plan(&st).conn.lock();
            for (id, nom) in [(JSRE_UID_Y, JSRE_Y), (JSRE_UID_W, JSRE_W)] {
                c.execute("INSERT INTO platform_user(id,name,hash,is_superadmin,created) VALUES(?1,?2,NULL,0,0)", params![id, nom]).expect("fixture : identité");
            }
        }
        st.installation_ouverte.store(false, std::sync::atomic::Ordering::SeqCst);
        (st, dir)
    }

    /// A détruit puis recréé par la route (premier administrateur X, qui n'a plus aucun droit ni provenance et redevient
    /// donc rattachable), Y second administrateur, et le jeton NEUF du A recréé ; l'ancien jeton est effacé (lu).
    pub(super) async fn jsre_detruire_et_recreer_a(st: &AppState) {
        assert!(tenant_destroy(&st.tenants, JSRE_A).is_ok(), "fixture : A détruit");
        let (statut, v) = jsre_creer(st, json!({ "id": JSRE_A, "name": JSRE_A, "admin": JSRE_X })).await;
        assert_eq!(statut, 201, "fixture : A recréé avec X : {v}");
        jsre_plan(st)
            .conn
            .lock()
            .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'admin')", params![JSRE_UID_Y, JSRE_A])
            .expect("fixture : Y administrateur du A recréé");
        jsre_poser_le_jeton(st, JSRE_JETON_A_RECREE, JSRE_A);
        assert_eq!(jsre_compter(st, "SELECT COUNT(*) FROM scim_token WHERE hash=?1", &sha256_hex(JSRE_JETON_A.as_bytes())), 0, "fixture : l'ancien jeton de A est effacé");
        assert_eq!(jsre_droits(st, JSRE_A), vec![format!("{JSRE_X}:admin"), format!("{JSRE_Y}:admin")], "fixture : les administrateurs du A recréé");
    }

    /// Une demande SCIM ouverte ; rend la connexion une fois la demande ADMISE par l'entrée : la date d'usage du jeton,
    /// remise à vide avant l'envoi, est relue posée (`scim_authenticate` l'écrit après avoir admis).
    pub(super) async fn jsre_entetes_admis(st: &AppState, adresse: std::net::SocketAddr, methode: &str, chemin: &str, jeton: &str, corps: &str) -> tokio::net::TcpStream {
        use tokio::io::AsyncWriteExt;
        let empreinte = sha256_hex(jeton.as_bytes());
        assert_eq!(
            jsre_plan(st).conn.lock().execute("UPDATE scim_token SET last_used=NULL WHERE hash=?1", params![empreinte]).expect("fixture"),
            1,
            "fixture : le jeton est inscrit"
        );
        let entetes = format!(
            "{methode} {chemin} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/scim+json\r\nAuthorization: Bearer {jeton}\r\nContent-Length: {}\r\n\r\n",
            corps.len()
        );
        let mut s = tokio::net::TcpStream::connect(adresse).await.expect("fixture : connexion");
        s.write_all(entetes.as_bytes()).await.expect("fixture : en-têtes");
        let mut admise = false;
        for _ in 0..4000 {
            let lu: Option<i64> = jsre_plan(st).conn.lock().query_row("SELECT last_used FROM scim_token WHERE hash=?1", params![empreinte], |r| r.get(0)).expect("fixture");
            if lu.is_some() {
                admise = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(admise, "fixture : l'entrée a admis la demande avant la suite");
        s
    }

    /// La demande admise achevée ; rend le statut et le corps HTTP de la réponse.
    pub(super) async fn jsre_corps_envoye(mut s: tokio::net::TcpStream, corps: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        s.write_all(corps.as_bytes()).await.expect("fixture : corps");
        let mut brut = Vec::new();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(20), s.read_to_end(&mut brut)).await;
        let brut = String::from_utf8_lossy(&brut).into_owned();
        let statut = brut.split_whitespace().nth(1).and_then(|c| c.parse::<u16>().ok()).unwrap_or(0);
        (statut, jsre_corps_http(&brut))
    }

    /// Le `401` d'un jeton inconnu par le routeur : la référence d'égalité (statut et corps).
    pub(super) async fn jsre_refus_d_un_inconnu(adresse: std::net::SocketAddr) -> (u16, String) {
        let (s, brut) = router_probe_corps(adresse, "GET", "/scim/v2/Users", Some(&format!("Bearer {JSRE_JETON_INCONNU}")), &[]).await;
        assert_eq!((s, jsre_corps_http(&brut)), (401, JSRE_CORPS_401.to_string()), "référence : le 401 d'un jeton inconnu");
        (s, jsre_corps_http(&brut))
    }

    pub(super) async fn jsre_envoi(adresse: std::net::SocketAddr, methode: &str, chemin: &str, jeton: &str, corps: &str) -> (u16, String) {
        let (s, brut) = router_probe_envoi(adresse, methode, chemin, Some(&format!("Bearer {jeton}")), &[("Content-Type", "application/scim+json")], corps).await;
        (s, jsre_corps_http(&brut))
    }

    // -------------------------------------------------------------------------------------
    // (1) PAR LE ROUTEUR RÉEL : UNE DEMANDE ADMISE AVANT LA DESTRUCTION ET LA RECRÉATION
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `POST /Users` (groupe `admin`) admis par l'ancien jeton de A, achevé après la destruction PUIS la
    /// recréation de A (jeton neuf), avant toute pose d'identité : le `401` de l'entrée, en entier
    /// (égal à celui d'un jeton inconnu) ; rien n'est écrit (état du plan de contrôle identique, aucune identité au nom
    /// demandé). Contrôle positif : la même demande avec le jeton neuf pose l'administrateur.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AY1_precontrole_absent` (l'identité est posée, la transaction des droits rend
    /// le 401 : état changé) ; `AY1_sans_empreinte` (le jeton neuf du tenant suffit : 201) ; `AY1_retire_admis` (201) ;
    /// `AY1_auth_empreinte_vide` (le contrôle positif rend 401).
    #[tokio::test]
    async fn jsre_post_users_admis_avant_la_recreation_est_refuse_sans_rien_ecrire() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let adresse = router_serve(st.clone()).await;
        let inconnu = jsre_refus_d_un_inconnu(adresse).await;
        let corps = r#"{"userName":"jsre-intrus","groups":[{"value":"admin"}]}"#;
        let s = jsre_entetes_admis(&st, adresse, "POST", "/scim/v2/Users", JSRE_JETON_A, corps).await;
        jsre_detruire_et_recreer_a(&st).await;
        let avant = jsre_instantane(&st);
        let servi = jsre_corps_envoye(s, corps).await;
        assert_eq!(servi, (401, JSRE_CORPS_401.to_string()), "la demande admise par l'ancien jeton : le 401 de l'entrée, en entier");
        assert_eq!(servi, inconnu, "même statut, même corps qu'un jeton inconnu");
        assert_eq!(jsre_instantane(&st), avant, "rien n'est écrit : ni identité, ni provenance, ni droit, ni ligne de contrôle");
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM platform_user WHERE name=?1", "jsre-intrus"), 0, "aucune identité au nom demandé");

        let (statut, v) = jsre_envoi(adresse, "POST", "/scim/v2/Users", JSRE_JETON_A_RECREE, corps).await;
        assert_eq!(statut, 201, "contrôle positif : le jeton neuf du A recréé pose l'administrateur : {v}");
        assert!(jsre_droits(&st, JSRE_A).contains(&"jsre-intrus:admin".to_string()), "contrôle positif : le droit est écrit");
    }

    /// CE QU'IL TIENT : `PUT /Users/{X}` `active=false` admis par l'ancien jeton de A, achevé après la recréation (X
    /// administrateur du A recréé, avec Y) : le `401` en entier ; le droit de X est intact (état identique). Contrôle
    /// positif : le jeton neuf déprovisionne X.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AY1_tx_deprov_sans_jeton` (200, X déprovisionné) ; `AY1_deprov_refus_404`.
    #[tokio::test]
    async fn jsre_put_active_false_admis_avant_la_recreation_est_refuse() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let x = jsre_uid(&st, JSRE_X);
        let adresse = router_serve(st.clone()).await;
        let corps = r#"{"active":false}"#;
        let chemin = format!("/scim/v2/Users/{x}");
        let s = jsre_entetes_admis(&st, adresse, "PUT", &chemin, JSRE_JETON_A, corps).await;
        jsre_detruire_et_recreer_a(&st).await;
        let avant = jsre_instantane(&st);
        assert_eq!(jsre_corps_envoye(s, corps).await, (401, JSRE_CORPS_401.to_string()), "le 401 de l'entrée, en entier");
        assert_eq!(jsre_instantane(&st), avant, "rien n'est écrit : le droit de X est en place");

        let (statut, v) = jsre_envoi(adresse, "PUT", &chemin, JSRE_JETON_A_RECREE, corps).await;
        assert_eq!(statut, 200, "contrôle positif : le jeton neuf déprovisionne X : {v}");
        assert_eq!(jsre_droits(&st, JSRE_A), vec![format!("{JSRE_Y}:admin")], "contrôle positif : X n'a plus de droit");
    }

    /// CE QU'IL TIENT : `PATCH /Groups/admin` (`add` W) admis par l'ancien jeton de A, achevé après la recréation : le
    /// `401` en entier ; W n'a aucun droit (état identique). Contrôle positif : le jeton neuf ajoute W.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AY1_tx_patch_sans_jeton` (200, W administrateur du A recréé).
    #[tokio::test]
    async fn jsre_patch_de_groupe_admis_avant_la_recreation_est_refuse() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let adresse = router_serve(st.clone()).await;
        let corps = format!(r#"{{"Operations":[{{"op":"add","value":[{{"value":"{JSRE_UID_W}"}}]}}]}}"#);
        let s = jsre_entetes_admis(&st, adresse, "PATCH", "/scim/v2/Groups/admin", JSRE_JETON_A, &corps).await;
        jsre_detruire_et_recreer_a(&st).await;
        let avant = jsre_instantane(&st);
        assert_eq!(jsre_corps_envoye(s, &corps).await, (401, JSRE_CORPS_401.to_string()), "le 401 de l'entrée, en entier");
        assert_eq!(jsre_instantane(&st), avant, "rien n'est écrit : W n'a aucun droit");

        let (statut, v) = jsre_envoi(adresse, "PATCH", "/scim/v2/Groups/admin", JSRE_JETON_A_RECREE, &corps).await;
        assert_eq!(statut, 200, "contrôle positif : le jeton neuf ajoute W : {v}");
        assert!(jsre_droits(&st, JSRE_A).contains(&format!("{JSRE_W}:admin")), "contrôle positif : W est administrateur");
    }

    /// CE QU'IL TIENT : `DELETE /Users/{X}` (sans corps) : le contexte est fabriqué comme l'entrée le fabrique
    /// (`scim_authentifier_la_demande`), admis tant que A existe, puis le gestionnaire est joué après la recréation : le
    /// `401` en entier ; le droit de X est
    /// intact. Contrôle positif PAR LE ROUTEUR : le jeton neuf déprovisionne X (204).
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AY1_tx_deprov_sans_jeton` (204) ; `AY1_deprov_refus_404`.
    #[tokio::test]
    async fn jsre_delete_admis_avant_la_recreation_est_refuse() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let x = jsre_uid(&st, JSRE_X);
        let ctx = scim_authentifier_la_demande(jsre_plan(&st), &format!("Bearer {JSRE_JETON_A}")).expect("lu").expect("fixture : admis tant que A existe");
        jsre_detruire_et_recreer_a(&st).await;
        let avant = jsre_instantane(&st);
        let (statut, v) = jsre_corps(scim_user_delete(State(st.clone()), Extension(ctx), Path(x.clone())).await).await;
        assert_eq!((statut, v), (401, Value::String(JSRE_CORPS_401.to_string())), "le 401 de l'entrée, en entier");
        assert_eq!(jsre_instantane(&st), avant, "rien n'est écrit : le droit de X est en place");

        let adresse = router_serve(st.clone()).await;
        let (statut, v) = jsre_envoi(adresse, "DELETE", &format!("/scim/v2/Users/{x}"), JSRE_JETON_A_RECREE, "").await;
        assert_eq!(statut, 204, "contrôle positif : le jeton neuf déprovisionne X : {v}");
        assert_eq!(jsre_droits(&st, JSRE_A), vec![format!("{JSRE_Y}:admin")], "contrôle positif : X n'a plus de droit");
    }

    // -------------------------------------------------------------------------------------
    // (2) LES CLAUSES DE LA RELECTURE : LE TENANT DE LA DEMANDE, ET LE CATALOGUE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : après la destruction et la recréation de A (sans jeton), le MÊME secret est reposé sous B ;
    /// la demande de A admise avant, achevée ensuite : `401`, rien d'écrit. Le jeton existe, mais pas sous A.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AY1_sans_tenant` (201 : identité et droit posés dans A).
    #[tokio::test]
    async fn jsre_le_meme_secret_repose_sous_un_autre_tenant_ne_vaut_pas_pour_a() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let adresse = router_serve(st.clone()).await;
        let corps = r#"{"userName":"jsre-autre","groups":[{"value":"admin"}]}"#;
        let s = jsre_entetes_admis(&st, adresse, "POST", "/scim/v2/Users", JSRE_JETON_A, corps).await;
        assert!(tenant_destroy(&st.tenants, JSRE_A).is_ok(), "fixture : A détruit");
        let chemin = format!("{}.jsre-recree", jsre_plan(&st).db_path);
        assert!(tenant_provision(&st.tenants, JSRE_A, JSRE_A, &chemin, "").is_ok(), "fixture : A recréé");
        jsre_poser_le_jeton(&st, JSRE_JETON_A, JSRE_B);
        let avant = jsre_instantane(&st);
        assert_eq!(jsre_corps_envoye(s, corps).await, (401, JSRE_CORPS_401.to_string()), "le 401 de l'entrée, en entier");
        assert_eq!(jsre_instantane(&st), avant, "rien n'est écrit");
    }

    /// CE QU'IL TIENT : A détruit (non recréé), puis le jeton de A reposé sous l'identifiant de A hors catalogue (comme
    /// par une version antérieure) ; la demande admise avant, achevée ensuite : `401`, rien d'écrit.
    /// LA MUTATION QUI LE FAIT ROUGIR : `AY1_sans_jointure` (201 : identité et droit posés sous l'identifiant absent).
    #[tokio::test]
    async fn jsre_un_jeton_sous_un_identifiant_hors_catalogue_ne_vaut_rien() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let adresse = router_serve(st.clone()).await;
        let corps = r#"{"userName":"jsre-orphelin","groups":[{"value":"admin"}]}"#;
        let s = jsre_entetes_admis(&st, adresse, "POST", "/scim/v2/Users", JSRE_JETON_A, corps).await;
        assert!(tenant_destroy(&st.tenants, JSRE_A).is_ok(), "fixture : A détruit");
        jsre_poser_le_jeton(&st, JSRE_JETON_A, JSRE_A);
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM tenant WHERE id=?1", JSRE_A), 0, "fixture : A hors catalogue");
        let avant = jsre_instantane(&st);
        assert_eq!(jsre_corps_envoye(s, corps).await, (401, JSRE_CORPS_401.to_string()), "le 401 de l'entrée, en entier");
        assert_eq!(jsre_instantane(&st), avant, "rien n'est écrit");
    }

    // -------------------------------------------------------------------------------------
    // (3) LA COURSE JUSTE AVANT LA RELECTURE ET LA POSE DE L'IDENTITÉ (UN SEUL VERROU, `P10.34-q`)
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : la destruction, la recréation de A et son jeton neuf tombent au point de course de production
    /// `scim-jeton-avant-l-identite`, juste avant le verrou sous lequel le jeton est relu puis l'identité posée : le
    /// `401` ; ni identité au nom demandé, ni provenance, ni droit dans le A recréé, aucune ligne `scim.user.provision`.
    /// Avant `P10.34-q`, la relecture précédait ce point : l'identité, sans droit, était posée avec la provenance du A
    /// recréé (LIMITE alors nommée, retirée).
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AY1c_relecture_avant_le_point` (l'identité est posée : la forme d'avant) ;
    /// avec elle, `AY1_tx_post_sans_jeton` en plus rend 201.
    #[tokio::test]
    async fn jsre_une_course_juste_avant_la_relecture_et_l_identite_ne_pose_rien() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let st_course = st.clone();
        crate::handlers::transaction_validee::poser_un_crochet_de_course(&format!("scim-jeton-avant-l-identite:{}", jsre_plan(&st).db_path), move || {
            assert!(tenant_destroy(&st_course.tenants, JSRE_A).is_ok(), "fixture : A détruit pendant la demande");
            let chemin = format!("{}.jsre-course", jsre_plan(&st_course).db_path);
            assert!(tenant_provision(&st_course.tenants, JSRE_A, JSRE_A, &chemin, "").is_ok(), "fixture : A recréé pendant la demande");
            jsre_poser_le_jeton(&st_course, JSRE_JETON_A_RECREE, JSRE_A);
        });
        let adresse = router_serve(st.clone()).await;
        let servi = jsre_envoi(adresse, "POST", "/scim/v2/Users", JSRE_JETON_A, r#"{"userName":"jsre-entre","groups":[{"value":"admin"}]}"#).await;
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM scim_token WHERE hash=?1", &sha256_hex(JSRE_JETON_A_RECREE.as_bytes())), 1, "fixture : la course a eu lieu");
        assert_eq!(servi, (401, JSRE_CORPS_401.to_string()), "le 401 de l'entrée, en entier");
        assert_eq!(jsre_droits(&st, JSRE_A), Vec::<String>::new(), "aucun droit dans le A recréé");
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM control_ledger WHERE kind=?1", "scim.user.provision"), 0, "aucune ligne de contrôle");
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM platform_user WHERE name=?1", "jsre-entre"), 0, "aucune identité au nom demandé");
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM scim_provenance WHERE tenant_id=?1", JSRE_A), 0, "aucune provenance sous A");
    }

    // -------------------------------------------------------------------------------------
    // (4) LE JETON NON RELU AU MOMENT D'ÉCRIRE, À CHAQUE SITE
    // -------------------------------------------------------------------------------------

    pub(super) const JSRE_JETONS_HORS_D_ATTEINTE: &str = "ALTER TABLE scim_token RENAME TO scim_token_hors_d_atteinte;";
    pub(super) const JSRE_JETONS_REMIS: &str = "ALTER TABLE scim_token_hors_d_atteinte RENAME TO scim_token;";

    /// CE QU'IL TIENT : un contexte admis (fabriqué comme l'entrée), puis la table des jetons hors d'atteinte : chaque
    /// site rend le `503` au corps EXACT et n'écrit rien — avant l'identité de `POST /Users` (aucune identité), la
    /// transaction des droits de `POST /Users` (table retirée au point de course `scim-identite-avant-ses-droits` :
    /// identité posée, aucun droit), `PUT active=false` et `DELETE` (droit de X en place), `PATCH` (W sans droit).
    /// LA MUTATION QUI LE FAIT ROUGIR : `AY1_lecture_ratee_401` (le 401 à chaque site).
    #[tokio::test]
    async fn jsre_un_jeton_non_relu_au_moment_d_ecrire_est_un_503_nomme_a_chaque_site() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = jsre_deux_tenants().await;
        let x = jsre_uid(&st, JSRE_X);
        jsre_plan(&st).conn.lock().execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'admin')", params![JSRE_UID_Y, JSRE_A]).expect("fixture : Y");
        let ctx = scim_authentifier_la_demande(jsre_plan(&st), &format!("Bearer {JSRE_JETON_A}")).expect("lu").expect("fixture : admis");
        let attendu = (503u16, jsre_refus_non_relu());

        // Avant l'identité.
        let avant = jsre_instantane(&st);
        jsre_sql(&st, JSRE_JETONS_HORS_D_ATTEINTE);
        let servi = jsre_corps(scim_user_create(State(st.clone()), Extension(ctx.clone()), Json(json!({ "userName": "jsre-avant", "groups": [{ "value": "admin" }] }))).await).await;
        jsre_sql(&st, JSRE_JETONS_REMIS);
        assert_eq!(servi, attendu, "POST /Users, avant l'identité : le 503, EN ENTIER");
        assert_eq!(jsre_instantane(&st), avant, "POST /Users, avant l'identité : rien n'est écrit");

        // La transaction des droits de `POST /Users`.
        let st_course = st.clone();
        crate::handlers::transaction_validee::poser_un_crochet_de_course(&format!("scim-identite-avant-ses-droits:{}", jsre_plan(&st).db_path), move || {
            jsre_sql(&st_course, JSRE_JETONS_HORS_D_ATTEINTE);
        });
        let servi = jsre_corps(scim_user_create(State(st.clone()), Extension(ctx.clone()), Json(json!({ "userName": "jsre-droits", "groups": [{ "value": "admin" }] }))).await).await;
        jsre_sql(&st, JSRE_JETONS_REMIS);
        assert_eq!(servi, attendu, "POST /Users, transaction des droits : le 503, EN ENTIER");
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM platform_user WHERE name=?1", "jsre-droits"), 1, "fixture : l'identité a été posée avant la transaction");
        assert_eq!(jsre_compter(&st, "SELECT COUNT(*) FROM \"grant\" WHERE user_id=?1", &jsre_uid(&st, "jsre-droits")), 0, "aucun droit n'est posé par l'étape");

        // `PUT active=false`, `DELETE`, `PATCH`.
        let avant = jsre_instantane(&st);
        jsre_sql(&st, JSRE_JETONS_HORS_D_ATTEINTE);
        let put = jsre_corps(scim_user_replace(State(st.clone()), Extension(ctx.clone()), Path(x.clone()), Json(json!({ "active": false }))).await).await;
        let delete = jsre_corps(scim_user_delete(State(st.clone()), Extension(ctx.clone()), Path(x.clone())).await).await;
        let patch = jsre_corps(
            scim_group_patch(State(st.clone()), Extension(ctx.clone()), Path("admin".to_string()), Json(json!({ "Operations": [{ "op": "add", "value": [{ "value": JSRE_UID_W }] }] }))).await,
        )
        .await;
        jsre_sql(&st, JSRE_JETONS_REMIS);
        assert_eq!(put, attendu, "PUT active=false : le 503, EN ENTIER");
        assert_eq!(delete, attendu, "DELETE : le 503, EN ENTIER");
        assert_eq!(patch, attendu, "PATCH : le 503, EN ENTIER");
        assert_eq!(jsre_instantane(&st), avant, "PUT, DELETE, PATCH : rien n'est écrit (droit de X en place, W sans droit)");
    }

    // -------------------------------------------------------------------------------------
    // (5) `scim-token` SUR UN TENANT ABSENT DU CATALOGUE, PAR `main` DANS UN PROCESSUS ENFANT
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `plume-daemon scim-token jsre-absent` sort en 2, dit la ligne de refus ENTIÈRE sur stderr,
    /// n'affiche aucun jeton et n'inscrit rien ; contrôle positif : `scim-token default` sort en 0, affiche un jeton dont
    /// l'empreinte est inscrite sous `default`.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `AY1_cli_sans_condition` (jeton inscrit et affiché) ; `AY1_cli_sortie_zero` ;
    /// `AY1_cli_ligne_muette`.
    #[test]
    fn jsre_scim_token_refuse_un_tenant_absent_du_catalogue() {
        if std::env::var_os(JSRE_ENFANT).is_some() {
            eprintln!("{JSRE_MARQUE_ENFANT}");
            crate::main();
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("jsre-scim-token");
        let dir = _tmp.racine().chemin().to_path_buf();
        let base = dir.join("plume.db").to_string_lossy().into_owned();
        let controle = dir.join("control.db").to_string_lossy().into_owned();
        let jouer = |tenant: &str| -> std::process::Output {
            std::process::Command::new(std::env::current_exe().expect("binaire de test"))
                .args([
                    "scim-token",
                    tenant,
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                    "tests::jeton_scim_relu_a_chaque_ecriture::jsre_scim_token_refuse_un_tenant_absent_du_catalogue",
                ])
                .env(JSRE_ENFANT, "1")
                .env("PLUME_DB", &base)
                .env("PLUME_CONTROL_DB", &controle)
                .env("PLUME_CONFIG", dir.join("aucune.conf"))
                .env_remove("PLUME_CONTROL_KEY")
                .stdin(std::process::Stdio::null())
                .output()
                .expect("ré-exécution du binaire de test")
        };
        let jetons_affiches = |stdout: &str| -> Vec<String> {
            stdout.split_whitespace().filter(|m| m.len() == 64 && m.bytes().all(|b| b.is_ascii_hexdigit())).map(str::to_string).collect()
        };
        let inscrits = || -> Vec<(String, String)> {
            let c = rusqlite::Connection::open(&controle).expect("plan de contrôle lisible");
            let mut s = c.prepare("SELECT hash, tenant_id FROM scim_token ORDER BY 1").expect("lecture");
            let lus = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).expect("lecture").collect::<Result<Vec<_>, _>>().expect("lisible");
            lus
        };

        let sortie = jouer("jsre-absent");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stderr.contains(JSRE_MARQUE_ENFANT), "contrôle : l'enfant a atteint `main` : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(2), "tenant absent : sortie 2 : {stdout}\n{stderr}");
        assert!(stderr.lines().any(|l| l == JSRE_LIGNE_CLI_ABSENT), "la ligne de refus, ENTIÈRE :\nattendu : {JSRE_LIGNE_CLI_ABSENT}\nstderr :\n{stderr}");
        assert_eq!(jetons_affiches(&stdout), Vec::<String>::new(), "aucun jeton affiché : {stdout}");
        assert!(!stderr.contains("créé (Authorization"), "aucune création annoncée : {stderr}");
        assert_eq!(inscrits(), Vec::<(String, String)>::new(), "aucun jeton inscrit");

        let sortie = jouer("default");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle positif : `default` sort en 0 : {stdout}\n{stderr}");
        let affiches = jetons_affiches(&stdout);
        assert_eq!(affiches.len(), 1, "contrôle positif : un jeton affiché : {stdout}");
        assert_eq!(inscrits(), vec![(sha256_hex(affiches[0].as_bytes()), "default".to_string())], "contrôle positif : son empreinte est inscrite sous `default`");
    }
}

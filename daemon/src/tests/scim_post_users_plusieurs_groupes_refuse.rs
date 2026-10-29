// =====================================================================================
// `P10.30-c` — `POST /scim/v2/Users` AVEC DES GROUPES MENANT À DES RÔLES DISTINCTS EST REFUSÉ, PLUS « LE DERNIER GAGNE ».
// `P10.30-d` (reste `scim_token.last_used`, avancée) — l'écriture de la date d'usage refusée est COMPTÉE, sans refuser
// l'authentification.
//
// CE QUI ÉTAIT FAUX (mesuré sur la forme d'avant, `scim.rs` au commit f3d3fc38) :
//  * `groups` = `[admin, viewer]` : `201`, deux `UPSERT` sur la clé `(user_id, tenant_id)`, `viewer` (le dernier) en base,
//    et le journal de contrôle attestait `grants=[admin,viewer]` — un droit absent nommé comme posé ;
//  * `groups` = `[viewer, viewer]` : le journal attestait `grants=[viewer,viewer]` ;
//  * `let _ = conn.execute("UPDATE scim_token SET last_used=…")` : un refus de la base ne laissait aucune trace.
//
// DÉCISION (orchestrateur, la plus sûre) : rôles distincts -> `400` SCIM `invalidValue` AVANT la création de
// l'utilisateur et avant tout geste gardé ; jamais « le droit le plus élevé gagne » ; le même rôle répété est admis et
// attesté une fois ; un rôle inconnu reste ignoré.
//
// MUTATIONS (une compilation, variable de mutant sous cfg(test), retirées ensuite) : x2_roles_distincts_admis, x2_refus_apres_creation,
// x2_doublons_gardes, x2_last_used_muet ; puis, après revue : x2_metrique_absente, x2_refus_muet_au_journal,
// x2_aucune_ligne_muette.
//
// Le compte `SCIM_LAST_USED_NON_ECRITS` est servi sur `/metrics` (`plume_scim_last_used_non_ecrits_total`). La branche
// `AucuneLigne` (jeton retiré entre la lecture et l'écriture) est provoquée sans second écrivain par un déclencheur
// TEMPORAIRE `RAISE(IGNORE)`.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le DELETE concurrent lui-même (le seul `DELETE FROM scim_token` du dépôt,
// `tenants::RESTES_SOUS_UN_IDENTIFIANT_DE_TENANT`, est joué par la destruction et par la création d'un tenant, que ces
// témoins ne jouent pas en course) ;
// la série `/metrics` est lue sur `gather_prom`, pas au travers de la route HTTP.
// =====================================================================================
mod scim_post_users_plusieurs_groupes_refuse {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const SPPG_TENANT: &str = "sppg-t1";
    const SPPG_JETON_SCIM: &str = "sppg-jeton-de-test";

    /// Un plan de contrôle avec le tenant catalogué, un administrateur (l'anti-verrouillage reste hors de cause) et un
    /// membre `editor` existant.
    fn sppg_etat() -> (AppState, crate::tmp_possede::TmpDb) {
        let (cp, tmp) = mk_test_control();
        cp.conn
            .lock()
            .execute(
                "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,'SPPG','','sans-base',?2,0)",
                params![SPPG_TENANT, now()],
            )
            .expect("fixture : tenant catalogué");
        for (nom, role) in [("sppg-admin", "admin"), ("sppg-ed", "editor")] {
            let id = ensure_platform_user(&cp, nom).expect("fixture : utilisateur créé");
            cp.conn
                .lock()
                .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3)", params![id, SPPG_TENANT, role])
                .expect("fixture : droit posé");
        }
        (tenant_test_state("admins", "editors", "supers", Some(cp)), tmp)
    }

    fn sppg_plan(st: &AppState) -> &ControlPlane {
        st.tenants.control.as_ref().expect("fixture : mode 1")
    }

    fn sppg_ctx() -> ScimCtx {
        ScimCtx { tenant: SPPG_TENANT.into() }
    }

    fn sppg_utilisateurs(st: &AppState, nom: &str) -> i64 {
        sppg_plan(st).conn.lock().query_row("SELECT COUNT(*) FROM platform_user WHERE name=?1", params![nom], |r| r.get(0)).expect("fixture : lu")
    }

    /// L'ÉTAT RELU EN BASE : `(nom, rôle)` du tenant, triés par nom.
    fn sppg_droits(st: &AppState) -> Vec<(String, String)> {
        let c = sppg_plan(st).conn.lock();
        let mut s = c
            .prepare("SELECT p.name, g.role FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id WHERE g.tenant_id=?1 ORDER BY p.name")
            .expect("fixture : droits");
        let lus = s
            .query_map(params![SPPG_TENANT], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .expect("fixture : droits")
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture : droits lisibles");
        lus
    }

    fn sppg_maillons(st: &AppState) -> Vec<String> {
        let c = sppg_plan(st).conn.lock();
        let mut s = c.prepare("SELECT detail FROM control_ledger WHERE kind='scim.user.provision' ORDER BY id").expect("fixture : journal");
        let lus = s.query_map([], |r| r.get(0)).expect("fixture : journal").collect::<Result<Vec<String>, _>>().expect("fixture : journal lisible");
        lus
    }

    fn sppg_attendus(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(n, r)| (n.to_string(), r.to_string())).collect()
    }

    /// CE QU'IL TIENT : pour un utilisateur NEUF et pour un membre EXISTANT, des groupes menant à `admin` et `viewer`
    /// (dans les deux ordres) rendent un `400` SCIM `invalidValue` ; l'utilisateur neuf n'est PAS créé ; aucun droit ne
    /// bouge (le membre existant garde `editor`) ; rien n'entre au journal de contrôle.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `x2_roles_distincts_admis` (le contrôle sauté : `201`, le dernier rôle
    /// gagne) ; `x2_refus_apres_creation` (l'utilisateur créé avant le refus).
    #[tokio::test]
    async fn sppg_des_groupes_a_roles_distincts_sont_refuses_avant_toute_ecriture() {
        let (st, _tmp) = sppg_etat();
        let avant = sppg_attendus(&[("sppg-admin", "admin"), ("sppg-ed", "editor")]);
        for (nom, groupes) in [
            ("sppg-neuf", json!([{ "value": "admin" }, { "value": "viewer" }])),
            ("sppg-neuf", json!([{ "value": "viewer" }, { "value": "admin" }])),
            ("sppg-ed", json!([{ "value": "admin" }, { "value": "viewer" }])),
        ] {
            let (statut, v) = tok_resp_json(scim_user_create(State(st.clone()), Extension(sppg_ctx()), Json(json!({ "userName": nom, "groups": groupes }))).await).await;
            let quoi = format!("{nom} {groupes}");
            assert_eq!(statut, StatusCode::BAD_REQUEST, "{quoi} : rôles distincts REFUSÉS : {v}");
            assert_eq!(v["schemas"], json!(["urn:ietf:params:scim:api:messages:2.0:Error"]), "{quoi} : corps d'erreur SCIM : {v}");
            assert_eq!(v["scimType"], json!("invalidValue"), "{quoi} : scimType nommé : {v}");
            assert_eq!(v["status"], json!("400"), "{quoi} : {v}");
            assert!(v["detail"].as_str().unwrap_or("").contains("rôles distincts"), "{quoi} : la cause est dite : {v}");
            assert_eq!(sppg_utilisateurs(&st, "sppg-neuf"), 0, "{quoi} : l'utilisateur neuf n'est PAS créé");
            assert_eq!(sppg_droits(&st), avant, "{quoi} : ÉTAT RELU : aucun droit ne bouge");
            assert!(sppg_maillons(&st).is_empty(), "{quoi} : JOURNAL : rien d'attesté");
        }
    }

    /// CE QU'IL TIENT : le même rôle répété (plus un rôle inconnu, ignoré) rend `201`, le droit est posé, et le journal
    /// de contrôle l'atteste UNE fois (`grants=[viewer]`), jamais `grants=[viewer,viewer]`.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `x2_doublons_gardes` (les doublons conservés : le journal nomme deux fois).
    #[tokio::test]
    async fn sppg_le_meme_role_repete_est_admis_et_atteste_une_fois() {
        let (st, _tmp) = sppg_etat();
        let groupes = json!([{ "value": "viewer" }, { "value": "sppg-role-inconnu" }, { "value": "viewer" }]);
        let (statut, v) = tok_resp_json(scim_user_create(State(st.clone()), Extension(sppg_ctx()), Json(json!({ "userName": "sppg-neuf", "groups": groupes }))).await).await;
        assert_eq!(statut, StatusCode::CREATED, "le même rôle répété est admis : {v}");
        assert_eq!(sppg_droits(&st), sppg_attendus(&[("sppg-admin", "admin"), ("sppg-ed", "editor"), ("sppg-neuf", "viewer")]), "ÉTAT RELU");
        let maillons = sppg_maillons(&st);
        assert_eq!(maillons.len(), 1, "un maillon : {maillons:?}");
        assert!(maillons[0].ends_with("grants=[viewer]"), "JOURNAL EXACT : le droit attesté une fois : {maillons:?}");
    }

    /// Un jeton SCIM valide posé pour `SPPG_TENANT` : rend le bearer et l'empreinte (clé de `scim_token`).
    fn sppg_poser_le_jeton(cp: &ControlPlane) -> (String, String) {
        let empreinte = sha256_hex(SPPG_JETON_SCIM.as_bytes());
        cp.conn.lock().execute("INSERT INTO scim_token(hash,tenant_id,created) VALUES(?1,?2,0)", params![empreinte, SPPG_TENANT]).expect("fixture : jeton posé");
        (format!("Bearer {SPPG_JETON_SCIM}"), empreinte)
    }

    fn sppg_last_used(cp: &ControlPlane, empreinte: &str) -> Option<i64> {
        cp.conn.lock().query_row("SELECT last_used FROM scim_token WHERE hash=?1", params![empreinte], |r| r.get(0)).expect("fixture : lu")
    }

    /// UNE authentification pendant que la base REFUSE l'écriture de `scim_token` (autorisateur), retiré ensuite.
    fn sppg_authentifier_sous_refus(cp: &ControlPlane, bearer: &str) -> Result<Option<String>, String> {
        cp.conn.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Update { table_name: "scim_token", .. } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let servie = scim_authenticate(cp, bearer);
        cp.conn.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        servie
    }

    /// LA VALEUR SERVIE PAR `/metrics` (`gather_prom`, le corps que la route rend) pour les `last_used` non écrits ;
    /// `None` = série absente.
    fn sppg_compte_servi() -> Option<u64> {
        let prom = gather_prom(&test_db(), "/nonexistent-spool", "", &crate::handlers::system::VersionDeSchema::Lue(1), 80);
        assert!(prom.contains("\n# TYPE plume_scim_last_used_non_ecrits_total counter\n"), "la série est déclarée COMPTEUR");
        prom.lines().find_map(|l| l.strip_prefix("plume_scim_last_used_non_ecrits_total ")).and_then(|v| v.parse().ok())
    }

    /// CE QU'IL TIENT : l'écriture de `scim_token.last_used` refusée par la base, l'authentification d'un jeton valide
    /// est SERVIE (`Ok(Some(tenant))`) et l'échec est COMPTÉ et SERVI sur `/metrics` ; la base revenue, la date s'écrit
    /// (contrôle positif). BORNE BASSE seulement : sous `cargo test` (plusieurs fils, un seul processus) un voisin peut
    /// compter ; le compte EXACT se lit dans l'enfant de `sppg_last_used_non_ecrit_compte_exact_dit_et_servi`.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `x2_last_used_muet` (premier passage) ; `x2_metrique_absente` (la série
    /// retirée de `/metrics`).
    #[tokio::test]
    async fn sppg_last_used_refuse_est_compte_sans_refuser_l_authentification() {
        let (st, _tmp) = sppg_etat();
        let cp = sppg_plan(&st);
        let (bearer, empreinte) = sppg_poser_le_jeton(cp);
        let avant = sppg_compte_servi().expect("la série plume_scim_last_used_non_ecrits_total est servie");
        assert_eq!(sppg_authentifier_sous_refus(cp, &bearer), Ok(Some(SPPG_TENANT.to_string())), "l'authentification n'est PAS refusée pour une date d'usage");
        assert_eq!(sppg_last_used(cp, &empreinte), None, "fixture : l'écriture a bien été refusée");
        let apres = sppg_compte_servi().expect("la série est servie");
        assert!(apres > avant, "l'échec est COMPTÉ et servi ({avant} -> {apres})");

        // CONTRÔLE POSITIF — base saine.
        assert_eq!(scim_authenticate(cp, &bearer), Ok(Some(SPPG_TENANT.to_string())));
        assert!(sppg_last_used(cp, &empreinte).is_some(), "la date d'usage s'écrit");
    }

    /// CE QU'IL TIENT, DANS UN PROCESSUS ENFANT (compte exact, sortie d'erreur lisible) : les DEUX issues non écrites du
    /// `last_used` — `Refusee` (autorisateur) puis `AucuneLigne` (un déclencheur TEMPORAIRE `RAISE(IGNORE)` abandonne la
    /// ligne : 0 ligne modifiée, sans second écrivain) — servent l'authentification, laissent la date intacte, sont
    /// comptées UNE fois chacune (`/metrics` : 0 -> 2), et chacune est DITE sur la sortie d'erreur, par sa propre ligne,
    /// sans jeton, empreinte ni tenant ; une écriture prise n'est ni comptée ni dite.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `x2_refus_muet_au_journal` (la ligne de la sortie d'erreur du refus sautée) ;
    /// `x2_aucune_ligne_muette` (la branche `AucuneLigne` ni comptée ni dite) ; `x2_metrique_absente`.
    #[tokio::test]
    async fn sppg_last_used_non_ecrit_compte_exact_dit_et_servi() {
        const ENFANT: &str = "SPPG_LAST_USED_ENFANT";
        if std::env::var(ENFANT).is_ok() {
            let (st, _tmp) = sppg_etat();
            let cp = sppg_plan(&st);
            let (bearer, empreinte) = sppg_poser_le_jeton(cp);
            let servi = || sppg_compte_servi().map_or("absente".to_string(), |n| n.to_string());
            println!("SPPG-ENFANT-DEPART={}", servi());
            let refus = sppg_authentifier_sous_refus(cp, &bearer);
            println!("SPPG-ENFANT-REFUS={refus:?} LAST_USED={:?} SERVI={}", sppg_last_used(cp, &empreinte), servi());
            cp.conn
                .lock()
                .execute_batch("CREATE TEMP TRIGGER sppg_last_used_abandonne BEFORE UPDATE ON scim_token BEGIN SELECT RAISE(IGNORE); END;")
                .expect("fixture : déclencheur temporaire");
            let aucune = scim_authenticate(cp, &bearer);
            cp.conn.lock().execute_batch("DROP TRIGGER temp.sppg_last_used_abandonne;").expect("fixture : déclencheur retiré");
            println!("SPPG-ENFANT-AUCUNE-LIGNE={aucune:?} LAST_USED={:?} SERVI={}", sppg_last_used(cp, &empreinte), servi());
            let saine = scim_authenticate(cp, &bearer);
            println!("SPPG-ENFANT-SAINE={saine:?} ECRITE={} SERVI={}", sppg_last_used(cp, &empreinte).is_some(), servi());
            println!("SPPG-ENFANT-A-JOUE");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::scim_post_users_plusieurs_groupes_refuse::sppg_last_used_non_ecrit_compte_exact_dit_et_servi"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("SPPG-ENFANT-A-JOUE"), "contrôle : l'enfant a vraiment joué : {stdout}\n{stderr}");
        let servie = format!("Ok(Some(\"{SPPG_TENANT}\"))");
        assert!(stdout.contains("SPPG-ENFANT-DEPART=0\n"), "série servie, à 0 au départ : {stdout}");
        assert!(stdout.contains(&format!("SPPG-ENFANT-REFUS={servie} LAST_USED=None SERVI=1\n")), "refus : servie, date intacte, compté 1 : {stdout}");
        assert!(
            stdout.contains(&format!("SPPG-ENFANT-AUCUNE-LIGNE={servie} LAST_USED=None SERVI=2\n")),
            "aucune ligne : servie, date intacte, comptée 2 : {stdout}"
        );
        assert!(stdout.contains(&format!("SPPG-ENFANT-SAINE={servie} ECRITE=true SERVI=2\n")), "écriture prise : pas comptée : {stdout}");
        let lignes: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[scim] WARN last_used")).collect();
        assert_eq!(lignes.len(), 2, "une ligne par issue non écrite, aucune pour l'écriture prise : {lignes:#?}\n{stderr}");
        assert!(
            lignes[0] == "[scim] WARN last_used du jeton SCIM NON écrit : authentification servie, date d'usage périmée : not authorized",
            "le refus est DIT, avec la cause du moteur (l'autorisateur rend « not authorized ») : {}",
            lignes[0]
        );
        assert!(lignes[1].contains("NON écrit (aucune ligne)"), "l'absence de ligne est DITE, par sa propre ligne : {}", lignes[1]);
        let empreinte = sha256_hex(SPPG_JETON_SCIM.as_bytes());
        for l in &lignes {
            assert!(!l.contains(SPPG_JETON_SCIM) && !l.contains(&empreinte) && !l.contains(SPPG_TENANT), "ni jeton, ni empreinte, ni tenant : {l}");
        }
    }
}

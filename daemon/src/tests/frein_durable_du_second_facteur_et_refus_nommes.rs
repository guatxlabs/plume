// =====================================================================================
// `P10.22-y` — LE FREIN PAR COMPTE DU SECOND FACTEUR EST DURABLE, ET L'ESSAI Y EST COMPTÉ AVANT D'ÊTRE EXAMINÉ.
// `P10.22-z` — UN CODE FAUX À L'ACTIVATION OU À LA DÉSACTIVATION, ET LE DÉCLENCHEMENT DU FREIN, SONT VUS DU SIEM.
// `P10.23-p` — UNE ÉCRITURE D'ENRÔLEMENT REFUSÉE EST UN 503 NOMMÉ, SANS GRAINE.
// `P10.21-u` — UNE LECTURE RATÉE N'EST NI « TENANT INCONNU », NI « DERNIER ADMINISTRATEUR », NI « BEARER INVALIDE ».
// `P10.21-n` — UN ÉLÉMENT DE DOSSIER EST COMPTÉ AVANT LE 204.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF le 2026-09-28 (banc joué sur la forme d'avant, `c2d9f12` ; chaque
// témoin ci-dessous a été vu ROUGE sous la mutation qu'il nomme) :
//  * `P10.22-y` : dix codes faux freinaient le compte (le onzième : 429) ; après un redémarrage simulé, DIX codes
//    faux de plus étaient EXAMINÉS (401), puis le frein se reposait — chaque redémarrage rouvrait une fenêtre ;
//  * `P10.22-z` : trois codes faux à la désactivation, trois à l'activation -> ZÉRO événement `plume-auth` ; le
//    frein déclenché (désactivation, connexion depuis quatre adresses) -> aucun événement de sévérité quatre ;
//  * `P10.23-p` : écriture de `user_mfa` refusée à l'enrôlement -> `500 « enregistrement de l'enrôlement échoué »` ;
//  * `P10.21-u` : lecture du tenant refusée à la pose d'un droit -> `404 « tenant inconnu »` ; lecture d'existence
//    refusée au retrait (super-administrateur) -> 503 sous la cause de l'ANTI-VERROUILLAGE (« ce geste pourrait lui
//    retirer son dernier administrateur » : fausse pour un super-administrateur, que la garde ne concerne pas — le 404
//    de l'énoncé était déjà fermé par `P10.21-r`) ; lecture de `scim_token` refusée -> `None`, donc 401 ;
//  * `P10.21-n` : `INSERT` de `incident_item` refusé -> `204`, zéro élément en base.
//
// LE REDÉMARRAGE EST SIMULÉ par un second état sur le MÊME fichier, ouvert sous un chemin ÉCRIT AUTREMENT
// (`…/./base`) : l'état de processus d'avant était indexé par le chemin écrit, un processus neuf ne le connaît pas
// davantage. La forme d'après n'a plus d'état de processus (`handlers/frein_du_second_facteur.rs` n'a aucune
// `static`) : le second état ne partage avec le premier QUE la base, ce qui est exactement un redémarrage — ou une
// réplique sur la même base.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un vrai redémarrage de processus (simulé comme dit) ; une réplique sur une
// AUTRE base (le frein est celui de la base qui porte le compte) ; la course entre deux essais concurrents du même
// compte sur deux processus (la réservation est un geste gardé sous `BEGIN IMMEDIATE`, raisonné, non joué) ; le
// budget par adresse du `rate_limit` ; ce que la console peint des refus neufs ; le passage par `auth_guard` du 503
// SCIM (la réponse est jouée par sa fonction, pas par le routeur).
// =====================================================================================
mod frein_durable_du_second_facteur_et_refus_nommes {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const FDSF_GRAINE: &[u8] = b"12345678901234567890";
    const FDSF_MOT_DE_PASSE: &str = "motdepasse12345";
    const FDSF_TENANT: &str = "fdsf-t";
    /// Graine arbitraire pour fabriquer un code à six chiffres (l'identité SSO n'a aucune graine plume).
    const FDSF_GRAINE_SSO: &str = "GEZDGNBVGY3TQOJQ";
    /// Matière d'un jeton SCIM de témoin, jamais écrite en clair derrière une clé.
    const FDSF_JETON_SCIM: &str = "jeton-scim-fdsf";

    async fn fdsf_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    fn fdsf_pair(ip: &str) -> std::net::SocketAddr {
        format!("{ip}:45454").parse().expect("adresse de test")
    }

    /// `adm` porteur d'une MFA à la graine connue, ACTIVE si `active`, en attente sinon.
    fn fdsf_etat_mfa(tag: &str, active: bool) -> (AppState, crate::tmp_possede::TmpDb, String) {
        let (st, p) = sp_state(&format!("fdsf-{tag}"));
        let graine = base32_encode(FDSF_GRAINE);
        st.db
            .lock()
            .execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES('adm',?1,?2,'[]',-1,0,0)",
                params![graine, active as i64],
            )
            .expect("fixture : MFA posée");
        (st, p, graine)
    }

    fn fdsf_pas() -> i64 {
        now() / 30
    }

    fn fdsf_code(graine: &str, pas: i64) -> String {
        hotp(&base32_decode(graine).expect("graine base32"), pas as u64, 6)
    }

    /// Un code à six chiffres qui n'est le code d'AUCUN pas de [pas-3, pas+3].
    fn fdsf_code_faux(graine: &str, n: u64) -> String {
        let pas = fdsf_pas();
        let justes: Vec<String> = (-3..=3).map(|d| fdsf_code(graine, pas + d)).collect();
        let mut k = n;
        loop {
            let c = format!("{:06}", k.wrapping_mul(7919).wrapping_add(13) % 1_000_000);
            if !justes.contains(&c) {
                return c;
            }
            k += 1_000_003;
        }
    }

    fn fdsf_chemin_ecrit_autrement(p: &str) -> String {
        let i = p.rfind('/').expect("chemin absolu");
        format!("{}/.{}", &p[..i], &p[i..])
    }

    async fn fdsf_ticket(st: &AppState, ip: &str) -> String {
        let r = login_post(State(st.clone()), ConnectInfo(fdsf_pair(ip)), Json(json!({ "user": "adm", "pass": FDSF_MOT_DE_PASSE }))).await;
        let (statut, c) = fdsf_corps(r).await;
        assert_eq!(statut, 200, "fixture : le mot de passe rend un ticket : {c}");
        c["ticket"].as_str().expect("ticket").to_string()
    }

    /// Le second facteur à la connexion : `(statut, session posée, Retry-After, corps)`.
    async fn fdsf_essai(st: &AppState, ticket: &str, code: &str, ip: &str) -> (u16, bool, Option<u64>, Value) {
        let r = login_mfa_post(State(st.clone()), ConnectInfo(fdsf_pair(ip)), Json(json!({ "ticket": ticket, "code": code }))).await;
        let session = r.headers().get_all(header::SET_COOKIE).iter().count() > 0;
        let attente = r.headers().get(header::RETRY_AFTER).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
        let (statut, corps) = fdsf_corps(r).await;
        (statut, session, attente, corps)
    }

    async fn fdsf_desactiver(st: &AppState, code: &str, ip: &str) -> (u16, Value) {
        fdsf_corps(mfa_disable(State(st.clone()), ConnectInfo(fdsf_pair(ip)), Extension(sp_au("adm", "admin")), Json(json!({ "code": code }))).await).await
    }

    async fn fdsf_activer(st: &AppState, code: &str, ip: &str) -> (u16, Value) {
        fdsf_corps(mfa_verify(State(st.clone()), ConnectInfo(fdsf_pair(ip)), Extension(sp_au("adm", "admin")), Json(json!({ "code": code }))).await).await
    }

    /// `n` codes faux à la connexion, répartis sur quatre adresses (aucune n'atteint le verrou par couple), une
    /// reconnexion par le mot de passe avant chacune.
    async fn fdsf_codes_faux_a_la_connexion(st: &AppState, graine: &str, n: u64, reseau: u8) {
        let mut joues = 0u64;
        for a in 0..4u8 {
            let ip = format!("10.{reseau}.{a}.1");
            let ticket = fdsf_ticket(st, &ip).await;
            for _ in 0..n.div_ceil(4) {
                if joues == n {
                    break;
                }
                joues += 1;
                let (statut, _, _, corps) = fdsf_essai(st, &ticket, &fdsf_code_faux(graine, joues), &ip).await;
                assert_eq!(statut, 401, "l'essai {joues} (sous le seuil) est un refus ordinaire : {corps}");
            }
        }
        assert_eq!(joues, n, "fixture : exactement {n} échecs joués");
    }

    fn fdsf_echecs(st: &AppState) -> u32 {
        crate::handlers::idp::echecs_consecutifs_du_second_facteur(st, "adm")
    }

    fn fdsf_compter(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// Les événements `plume-auth` : `(sévérité, message, champs)`.
    fn fdsf_evenements(st: &AppState) -> Vec<(i64, String, Value)> {
        let conn = st.db.lock();
        let mut s = conn.prepare("SELECT severity, message, fields FROM event WHERE source='plume-auth' ORDER BY id").expect("prépare");
        s.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            .expect("lit")
            .collect::<Result<Vec<_>, _>>()
            .expect("lignes")
            .into_iter()
            .map(|(s, m, f)| (s, m, serde_json::from_str(&f).expect("champs JSON")))
            .collect()
    }

    fn fdsf_refuser_l_ecriture_du_frein(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } if table_name == "setting" => Authorization::Deny,
            AuthAction::Update { table_name, .. } if table_name == "setting" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn fdsf_lever(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.22-y` — LE FREIN SURVIT AU REDÉMARRAGE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `seuil` codes faux (quatre adresses) freinent `adm` ; un état NEUF sur la MÊME base (le
    /// redémarrage, voir l'en-tête) refuse le code JUSTE en `429` sans l'examiner — pas de session, pas de pas consommé
    /// —, et l'état vit dans `setting` (portée `frein.second_facteur`), pas ailleurs.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rétablir l'état en mémoire (lecture, écriture et oubli de l'état du frein dans
    /// une `HashMap` statique indexée par la CONNEXION et le compte — un état neuf, une mémoire neuve, comme un processus
    /// neuf) — le code juste ouvre la session après le redémarrage (vu rouge). Une première écriture de la mutation
    /// indexait par `conn.path()` : SQLite rend le chemin NORMALISÉ (`/./` retiré), la clé coïncidait, et le témoin
    /// ne rougissait que sur l'assertion de la ligne en base — d'où l'index par connexion. Sur la forme d'avant, MESURÉ
    /// (son index était le chemin ÉCRIT, `st.db_path`) : dix codes faux de plus examinés.
    #[tokio::test]
    async fn fdsf_le_frein_du_second_facteur_survit_au_redemarrage() {
        let (st, p, graine) = fdsf_etat_mfa("redemarrage", true);
        let seuil = st.lock_threshold as u64;
        fdsf_codes_faux_a_la_connexion(&st, &graine, seuil, 60).await;
        assert!(crate::handlers::idp::second_facteur_freine(&st, "adm").is_some(), "fixture : le compte est freiné");

        let redemarre = ds_file_state(&fdsf_chemin_ecrit_autrement(&p));
        let ticket = fdsf_ticket(&redemarre, "10.60.99.1").await;
        let (statut, session, attente, corps) = fdsf_essai(&redemarre, &ticket, &fdsf_code(&graine, fdsf_pas()), "10.60.99.1").await;
        assert_eq!(statut, 429, "après le redémarrage, le compte est TOUJOURS freiné : le code juste n'est pas examiné : {corps}");
        assert!(!session, "aucune session");
        assert!(attente.is_some(), "le refus dit combien attendre (Retry-After)");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_SECOND_FACTEUR_FREINE), "{corps}");
        assert_eq!(fdsf_compter(&redemarre, "SELECT last_step FROM user_mfa WHERE user='adm'"), -1, "rien n'est consommé");
        assert_eq!(
            fdsf_compter(&redemarre, "SELECT COUNT(*) FROM setting WHERE scope='frein.second_facteur' AND key='adm'"),
            1,
            "l'état du frein est une ligne de la base"
        );
        assert_eq!(fdsf_echecs(&redemarre), seuil as u32, "les échecs comptés avant le redémarrage le sont encore après");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.22-y` — LA LEVÉE, LA PROGRESSION ET L'OUBLI, JOUÉS SUR L'ÉTAT STOCKÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : au seuil, le délai vaut `lock_base_s` ; le délai écoulé (état reculé), un code faux est
    /// EXAMINÉ (401) et repose un délai DOUBLE ; celui-ci écoulé, le code juste passe et remet le compte à zéro ; et
    /// `seuil - 1` échecs suivis d'un jour sans échec repartent de un. Ce que `P10.22-m` ne jouait pas (horloge
    /// monotone non injectable).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer le doublement (`lock_base_s` à chaque armement) — le second délai vaut
    /// `lock_base_s` (vu rouge) ; retirer l'oubli d'un jour — le compte repart de `seuil` et freine (vu rouge).
    #[tokio::test]
    async fn fdsf_la_levee_la_progression_et_l_oubli_du_frein() {
        let (st, _p, graine) = fdsf_etat_mfa("levee", true);
        let seuil = st.lock_threshold as u64;
        let (base, plafond) = (st.lock_base_s, st.lock_max_s);
        assert!(2 * base <= plafond, "fixture : le doublement n'est pas plafonné ({base}, {plafond})");
        fdsf_codes_faux_a_la_connexion(&st, &graine, seuil, 64).await;
        let ticket = fdsf_ticket(&st, "10.64.99.1").await;
        let (statut, _, attente, _) = fdsf_essai(&st, &ticket, &fdsf_code_faux(&graine, 500), "10.64.99.1").await;
        assert_eq!(statut, 429);
        assert!(attente.is_some_and(|a| a <= base && a + 5 >= base), "premier délai ≈ lock_base_s ({base}) : {attente:?}");

        crate::handlers::frein_du_second_facteur::faire_passer_le_temps(&st, "adm", base as i64 + 1);
        let (statut, _, _, corps) = fdsf_essai(&st, &ticket, &fdsf_code_faux(&graine, 501), "10.64.99.1").await;
        assert_eq!(statut, 401, "le délai écoulé, un code est de nouveau EXAMINÉ : {corps}");
        let (statut, _, attente, _) = fdsf_essai(&st, &ticket, &fdsf_code(&graine, fdsf_pas()), "10.64.99.1").await;
        assert_eq!(statut, 429, "l'échec au-delà du seuil repose le frein");
        assert!(attente.is_some_and(|a| a <= 2 * base && a + 5 >= 2 * base), "second délai ≈ 2 × lock_base_s ({}) : {attente:?}", 2 * base);

        crate::handlers::frein_du_second_facteur::faire_passer_le_temps(&st, "adm", 2 * base as i64 + 1);
        let (statut, session, _, corps) = fdsf_essai(&st, &ticket, &fdsf_code(&graine, fdsf_pas()), "10.64.99.1").await;
        assert_eq!((statut, session), (200, true), "levé, le code juste passe : {corps}");
        assert_eq!(fdsf_echecs(&st), 0, "et remet le compte à zéro");

        // L'OUBLI — `seuil - 1` échecs, un jour sans échec, et le suivant compte pour un.
        fdsf_codes_faux_a_la_connexion(&st, &graine, seuil - 1, 65).await;
        assert_eq!(fdsf_echecs(&st), seuil as u32 - 1);
        crate::handlers::frein_du_second_facteur::faire_passer_le_temps(&st, "adm", 24 * 3600 + 1);
        let ticket = fdsf_ticket(&st, "10.65.99.1").await;
        let (statut, ..) = fdsf_essai(&st, &ticket, &fdsf_code_faux(&graine, 700), "10.65.99.1").await;
        assert_eq!(statut, 401);
        assert_eq!(fdsf_echecs(&st), 1, "un jour sans échec efface les échecs consécutifs");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.22-y` — UN ESSAI QUI N'EST PAS COMPTÉ N'EST PAS EXAMINÉ
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : l'écriture du frein refusée, le code JUSTE comme le code FAUX rendent le MÊME `503` nommé — aucun
    /// oracle —, aucune session, aucun pas consommé, à la connexion, à la désactivation et à l'activation ; la base
    /// revenue, le code juste passe (contrôle positif).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : traiter `EssaiRefuse::NonCompte` comme un essai admis (examiner sans avoir
    /// compté) — le code juste ouvre la session et le faux rend 401 : l'oracle sans borne revient (vu rouge).
    #[tokio::test]
    async fn fdsf_un_essai_que_le_frein_n_a_pas_compte_n_est_pas_examine() {
        let (st, _p, graine) = fdsf_etat_mfa("non-compte", true);
        let cause = json!(crate::handlers::frein_du_second_facteur::CAUSE_ESSAI_DU_SECOND_FACTEUR_NON_COMPTE);
        let ticket = fdsf_ticket(&st, "10.66.0.1").await;
        fdsf_refuser_l_ecriture_du_frein(&st);
        let juste = fdsf_essai(&st, &ticket, &fdsf_code(&graine, fdsf_pas()), "10.66.0.1").await;
        let faux = fdsf_essai(&st, &ticket, &fdsf_code_faux(&graine, 3), "10.66.0.1").await;
        let desactivation = fdsf_desactiver(&st, &fdsf_code(&graine, fdsf_pas()), "10.66.0.1").await;
        fdsf_lever(&st);
        assert_eq!((juste.0, juste.1), (503, false), "code juste, frein non écrit : ni accepté ni refusé : {:?}", juste.3);
        assert_eq!(juste.3["error"], cause, "{:?}", juste.3);
        assert_eq!((faux.0, faux.1, &faux.3["error"]), (juste.0, juste.1, &juste.3["error"]), "juste ou faux, la MÊME réponse — aucun oracle");
        assert_eq!((desactivation.0, &desactivation.1["error"]), (503, &cause), "la désactivation non plus n'examine pas le code");
        assert_eq!(fdsf_compter(&st, "SELECT last_step FROM user_mfa WHERE user='adm'"), -1, "rien n'est consommé");
        assert_eq!(fdsf_compter(&st, "SELECT COUNT(*) FROM user_mfa WHERE user='adm' AND enabled=1"), 1, "le second facteur est EN PLACE");

        let (st_attente, _p2, graine2) = fdsf_etat_mfa("non-compte-activation", false);
        fdsf_refuser_l_ecriture_du_frein(&st_attente);
        let activation = fdsf_activer(&st_attente, &fdsf_code(&graine2, fdsf_pas()), "10.66.0.2").await;
        fdsf_lever(&st_attente);
        assert_eq!((activation.0, &activation.1["error"]), (503, &cause), "l'activation non plus");
        assert_eq!(fdsf_compter(&st_attente, "SELECT enabled FROM user_mfa WHERE user='adm'"), 0, "rien n'est activé");

        // CONTRÔLE POSITIF — la base revenue, le code juste passe.
        let (statut, session, _, corps) = fdsf_essai(&st, &ticket, &fdsf_code(&graine, fdsf_pas()), "10.66.0.1").await;
        assert_eq!((statut, session), (200, true), "{corps}");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.22-z` — LES ÉCHECS ET LE FREIN, VUS DU SIEM
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un code faux à la désactivation et à l'activation écrit UN événement `plume-auth` `failure` de
    /// sévérité trois, avec l'adresse (colonne et champ), la route et `facteur: "second"`, SANS le code ; `seuil` codes
    /// faux à la connexion (quatre adresses) écrivent UN `lockout` de sévérité quatre au déclenchement, et les essais
    /// refusés pendant le délai n'en écrivent aucun ; à la désactivation, même `lockout`, une fois.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer l'écriture du `failure` de `tracer_l_echec` — zéro événement à la
    /// désactivation (vu rouge) ; retirer celle du `lockout` — aucun sévérité quatre (vu rouge). Forme d'avant, MESURÉ :
    /// zéro événement dans les quatre cas.
    #[tokio::test]
    async fn fdsf_les_echecs_et_le_frein_du_second_facteur_sont_vus_du_siem() {
        let (st, _p, graine) = fdsf_etat_mfa("siem-desactivation", true);
        let faux = fdsf_code_faux(&graine, 11);
        let (statut, corps) = fdsf_desactiver(&st, &faux, "10.67.0.1").await;
        assert_eq!(statut, 401, "{corps}");
        let ev = fdsf_evenements(&st);
        assert_eq!(ev.len(), 1, "un code faux à la désactivation : UN événement : {ev:?}");
        let (sev, message, champs) = &ev[0];
        assert_eq!(*sev, 3, "sévérité des autres échecs d'authentification");
        assert_eq!(champs["action"], json!("failure"));
        assert_eq!(champs["facteur"], json!("second"));
        assert_eq!(champs["route"], json!("desactivation"));
        assert_eq!(champs["username"], json!("adm"));
        assert_eq!(champs["src_ip"], json!("10.67.0.1"));
        assert!(!message.contains(&faux) && !champs.to_string().contains(&faux), "le code présenté n'est JAMAIS dans l'événement");
        assert!(!champs.to_string().contains(&graine), "ni la graine");
        let colonne: Option<String> = st.db.lock().query_row("SELECT src_ip FROM event WHERE source='plume-auth'", [], |r| r.get(0)).expect("lu");
        assert_eq!(colonne.as_deref(), Some("10.67.0.1"), "l'adresse en colonne (règle 37 : `stats count by src_ip`)");

        // LE FREIN À LA DÉSACTIVATION — un seul `lockout`, et rien pendant le délai.
        let seuil = st.lock_threshold as u64;
        for i in 1..seuil {
            let (statut, _) = fdsf_desactiver(&st, &fdsf_code_faux(&graine, 20 + i), "10.67.0.1").await;
            assert_eq!(statut, 401);
        }
        let (statut, _) = fdsf_desactiver(&st, &fdsf_code_faux(&graine, 99), "10.67.0.1").await;
        assert_eq!(statut, 429, "fixture : freiné");
        let ev = fdsf_evenements(&st);
        let freins: Vec<_> = ev.iter().filter(|e| e.2["action"] == json!("lockout")).collect();
        assert_eq!(freins.len(), 1, "UN déclenchement, UN événement : {ev:?}");
        assert_eq!(freins[0].0, 4, "sévérité quatre, comme le verrou par couple");
        assert_eq!((freins[0].2["facteur"].clone(), freins[0].2["route"].clone()), (json!("second"), json!("desactivation")));
        assert_eq!(freins[0].2["freine_s"], json!(st.lock_base_s));
        assert_eq!(ev.iter().filter(|e| e.2["action"] == json!("failure")).count() as u64, seuil, "un `failure` par code faux EXAMINÉ, aucun pour le refus freiné");

        // L'ACTIVATION.
        let (st, _p, graine) = fdsf_etat_mfa("siem-activation", false);
        let (statut, _) = fdsf_activer(&st, &fdsf_code_faux(&graine, 12), "10.67.1.1").await;
        assert_eq!(statut, 401);
        let ev = fdsf_evenements(&st);
        assert_eq!(ev.len(), 1, "un code faux à l'activation : UN événement : {ev:?}");
        assert_eq!((ev[0].0, ev[0].2["route"].clone(), ev[0].2["src_ip"].clone()), (3, json!("activation"), json!("10.67.1.1")));

        // LA CONNEXION — l'échec y était déjà émis (`auth_record_failure`) ; le déclenchement, non.
        let (st, _p, graine) = fdsf_etat_mfa("siem-connexion", true);
        fdsf_codes_faux_a_la_connexion(&st, &graine, seuil, 68).await;
        let ticket = fdsf_ticket(&st, "10.68.99.1").await;
        let (statut, ..) = fdsf_essai(&st, &ticket, &fdsf_code_faux(&graine, 800), "10.68.99.1").await;
        assert_eq!(statut, 429, "fixture : freiné");
        let ev = fdsf_evenements(&st);
        assert_eq!(ev.iter().filter(|e| e.2["action"] == json!("failure")).count() as u64, seuil, "un échec par code faux, pas deux : {ev:?}");
        let freins: Vec<_> = ev.iter().filter(|e| e.0 >= 4).collect();
        assert_eq!(freins.len(), 1, "le déclenchement du frein à la connexion : UN événement de sévérité quatre : {ev:?}");
        assert_eq!((freins[0].2["action"].clone(), freins[0].2["route"].clone()), (json!("lockout"), json!("connexion")));
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.22-y` — L'EXPLOITANT SERVI PAR SSO N'ÉCRIT RIEN AU FREIN
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une identité SSO par en-têtes (sans mot de passe local, sans second facteur plume — la
    /// population réelle de production) qui appelle la désactivation reçoit le `404` d'avant, et rien n'est écrit au
    /// frein ni au SIEM ; même quand l'écriture du frein est refusée (l'identité ne la traverse pas).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : réserver l'essai sans condition dans `mfa_disable` — sous l'écriture du frein
    /// refusée, `guat` reçoit un 503 qui ne le concerne pas (vu rouge ; sans la panne, la réservation puis son retour
    /// ne laissent aucune ligne : le témoin sans panne restait VERT sous cette mutation, d'où la panne).
    #[tokio::test]
    async fn fdsf_une_identite_sso_sans_second_facteur_n_ecrit_rien_au_frein() {
        let (st, _p) = sp_state("fdsf-sso");
        let guat = AuthUser { name: "guat".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false, method: "sso".into(), csrf: String::new(), env: None };
        let (statut, corps) = fdsf_corps(mfa_disable(State(st.clone()), ConnectInfo(fdsf_pair("10.69.0.1")), Extension(guat.clone()), Json(json!({ "code": fdsf_code_faux(FDSF_GRAINE_SSO, 1) }))).await).await;
        assert_eq!(statut, 404, "aucune MFA : le refus d'avant : {corps}");
        fdsf_refuser_l_ecriture_du_frein(&st);
        let (statut, corps) = fdsf_corps(mfa_disable(State(st.clone()), ConnectInfo(fdsf_pair("10.69.0.1")), Extension(guat), Json(json!({ "code": fdsf_code_faux(FDSF_GRAINE_SSO, 1) }))).await).await;
        fdsf_lever(&st);
        assert_eq!(statut, 404, "l'écriture du frein refusée ne touche pas une identité qui n'en a pas : {corps}");
        assert_eq!(fdsf_compter(&st, "SELECT COUNT(*) FROM setting WHERE scope='frein.second_facteur'"), 0, "rien au frein");
        assert!(fdsf_evenements(&st).is_empty(), "rien au SIEM");
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.23-p` — L'ENRÔLEMENT QUE LA BASE NE PREND PAS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : l'écriture de `user_mfa` refusée, l'enrôlement rend un `503` NOMMÉ sans graine ni URI, et rien
    /// n'est posé ; la base revenue, il rend sa graine (contrôle positif).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rétablir `Ok(_) | Err(_) => return server_err("enregistrement de l'enrôlement
    /// échoué")` — `500` anonyme (vu rouge ; la forme d'avant, mesurée).
    #[tokio::test]
    async fn fdsf_un_enrolement_que_la_base_ne_prend_pas_est_un_refus_nomme_sans_graine() {
        let (st, _p) = sp_state("fdsf-enrolement");
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } if table_name == "user_mfa" => Authorization::Deny,
            AuthAction::Update { table_name, .. } if table_name == "user_mfa" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let enroler = || mfa_enroll(State(st.clone()), ConnectInfo(fdsf_pair("10.70.0.1")), Extension(sp_au("adm", "admin")), Json(json!({ "password": FDSF_MOT_DE_PASSE })));
        let (statut, corps) = fdsf_corps(enroler().await).await;
        fdsf_lever(&st);
        assert_eq!(statut, 503, "l'enrôlement n'est pas écrit : REFUS NOMMÉ : {corps}");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_ENROLEMENT_NON_ECRIT), "{corps}");
        assert!(corps.get("secret").is_none() && corps.get("otpauth_uri").is_none(), "aucune graine montrée : {corps}");
        assert_eq!(fdsf_compter(&st, "SELECT COUNT(*) FROM user_mfa WHERE user='adm'"), 0, "rien n'est posé");

        // CONTRÔLE POSITIF — la base revenue, la graine est servie et posée.
        let (statut, corps) = fdsf_corps(enroler().await).await;
        assert_eq!(statut, 200, "{corps}");
        assert!(corps["secret"].as_str().is_some_and(|s| !s.is_empty()));
        assert_eq!(fdsf_compter(&st, "SELECT COUNT(*) FROM user_mfa WHERE user='adm' AND enabled=0"), 1);
    }

    // -------------------------------------------------------------------------------------
    // (7) `P10.21-u` — TROIS ISSUES : PRÉSENT, ABSENT, ILLISIBLE
    // -------------------------------------------------------------------------------------

    fn fdsf_refuser_la_lecture(cp: &ControlPlane, table: &'static str) {
        cp.conn.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == table => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn fdsf_lever_le_plan(cp: &ControlPlane) {
        cp.conn.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// CE QU'IL TIENT : la lecture du tenant refusée, la pose d'un droit rend `503` nommé (pas « tenant inconnu ») et
    /// n'écrit rien ; un tenant réellement absent garde son `404`. La lecture d'existence refusée, le retrait par un
    /// super-administrateur rend `503` sous SA cause (pas celle de l'anti-verrouillage) et l'accès reste ; un droit
    /// absent garde son `404`. La lecture de `scim_token` refusée rend `Err` (503 SCIM rejouable), jamais `None` (401) ;
    /// un jeton inconnu reste `Ok(None)`.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : rétablir `.is_err() -> 404` dans `grant_set` (vu rouge) ; rendre la lecture
    /// d'existence de `grant_delete` à `RefusDuRetrait::NonEtabli` (cause de l'anti-verrouillage, vu rouge) ; rétablir
    /// `.ok()` dans `scim_authenticate` (`Ok(None)`, vu rouge).
    #[tokio::test]
    async fn fdsf_une_lecture_ratee_du_plan_de_controle_n_est_pas_une_absence() {
        let (st, _dir) = mk_mode1_state();
        let sa = au_super("sa-fdsf");
        let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Json(json!({ "id": FDSF_TENANT, "name": "FdsfT" }))).await;
        assert_eq!(r.status(), StatusCode::CREATED, "fixture : tenant");
        let r = grant_set(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Path(FDSF_TENANT.into()), Json(json!({ "user": "fdsf-a", "role": "admin" }))).await;
        assert_eq!(r.status().as_u16(), 200, "fixture : droit posé");
        let cp = st.tenants.control.as_ref().expect("mode 1");
        let droits = || -> i64 { cp.conn.lock().query_row("SELECT COUNT(*) FROM \"grant\" WHERE tenant_id=?1", params![FDSF_TENANT], |r| r.get(0)).expect("lu") };

        // grant_set — tenant illisible, puis absent.
        fdsf_refuser_la_lecture(cp, "tenant");
        let (statut, corps) = fdsf_corps(grant_set(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Path(FDSF_TENANT.into()), Json(json!({ "user": "fdsf-b", "role": "viewer" }))).await).await;
        fdsf_lever_le_plan(cp);
        assert_eq!(statut, 503, "tenant NON LU : ce n'est pas « tenant inconnu » : {corps}");
        assert_eq!(corps["error"], json!(crate::tenants::CAUSE_TENANT_NON_LU_DROIT_NON_POSE));
        assert_eq!(droits(), 1, "aucun droit posé");
        let (statut, _) = fdsf_corps(grant_set(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(sa.clone()), Path("fdsf-absent".into()), Json(json!({ "user": "fdsf-b", "role": "viewer" }))).await).await;
        assert_eq!(statut, 404, "un tenant réellement absent garde son 404");

        // grant_delete — droit illisible, puis absent.
        fdsf_refuser_la_lecture(cp, "grant");
        let (statut, corps) = fdsf_corps(grant_delete(State(st.clone()), Extension(sa.clone()), Path((FDSF_TENANT.into(), "fdsf-a".into()))).await).await;
        fdsf_lever_le_plan(cp);
        assert_eq!(statut, 503, "{corps}");
        assert_eq!(corps["error"], json!(crate::tenants::CAUSE_DROIT_NON_LU_RETRAIT_NON_FAIT), "SA cause, pas celle de l'anti-verrouillage : {corps}");
        assert_eq!(droits(), 1, "l'accès n'est PAS retiré");
        let (statut, _) = fdsf_corps(grant_delete(State(st.clone()), Extension(sa.clone()), Path((FDSF_TENANT.into(), "fdsf-personne".into()))).await).await;
        assert_eq!(statut, 404, "un droit réellement absent garde son 404");

        // scim_authenticate — jeton illisible, inconnu, connu.
        cp.conn.lock().execute("INSERT INTO scim_token(hash,tenant_id,created) VALUES(?1,?2,0)", params![sha256_hex(FDSF_JETON_SCIM.as_bytes()), FDSF_TENANT]).expect("fixture");
        fdsf_refuser_la_lecture(cp, "scim_token");
        let illisible = scim_authenticate(cp, &format!("Bearer {FDSF_JETON_SCIM}"));
        fdsf_lever_le_plan(cp);
        assert!(illisible.is_err(), "lecture refusée : ni valide ni révoqué : {illisible:?}");
        assert_eq!(scim_authenticate(cp, &format!("Bearer {FDSF_JETON_SCIM}-inconnu")), Ok(None), "un jeton inconnu reste un bearer invalide");
        assert_eq!(scim_authenticate(cp, &format!("Bearer {FDSF_JETON_SCIM}")), Ok(Some(FDSF_TENANT.to_string())), "contrôle positif");
        let (statut, corps) = fdsf_corps(crate::scim::scim_refuser_le_jeton_non_lu("cause du moteur")).await;
        assert_eq!(statut, 503, "le garde rend un 503 rejouable");
        assert!(corps.to_string().contains("JETON NON VÉRIFIÉ") && !corps.to_string().contains("cause du moteur"), "la cause du geste, pas celle du moteur : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (8) `P10.21-n` — L'ÉLÉMENT DE DOSSIER EST COMPTÉ AVANT LE 204
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : l'`INSERT` de l'élément refusé, `case_item_add` rend un `503` nommé, aucun élément n'est
    /// rattaché et la date du dossier n'a pas bougé ; un dossier absent garde son `404` nommé ; la base revenue, le
    /// même ajout rend `204` et l'élément est là (contrôle positif).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rétablir `case_add_item(&conn, …)` à la place de `rattacher_l_element_au_dossier`
    /// — `204` sur zéro élément (vu rouge ; la forme d'avant, mesurée).
    #[tokio::test]
    async fn fdsf_un_element_de_dossier_refuse_n_est_pas_annonce() {
        let (st, _p) = sp_state("fdsf-dossier");
        st.db.lock().execute("INSERT INTO incident(id,ts,updated,title) VALUES(7,1,1,'dossier fdsf')", []).expect("fixture");
        let ajouter = || case_item_add(State(st.clone()), Extension(sp_au("adm", "admin")), Path(7), Json(json!({ "kind": "event", "ref": "event:1", "body": "rattaché" })));
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name } if table_name == "incident_item" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, corps) = fdsf_corps(ajouter().await).await;
        fdsf_lever(&st);
        assert_eq!(statut, 503, "l'élément n'est pas écrit : REFUS NOMMÉ, pas 204 : {corps}");
        assert_eq!(corps["error"], json!(crate::handlers::cases::CAUSE_ELEMENT_DE_DOSSIER_NON_AJOUTE), "{corps}");
        assert_eq!(fdsf_compter(&st, "SELECT COUNT(*) FROM incident_item WHERE incident_id=7"), 0, "rien n'est rattaché");
        assert_eq!(fdsf_compter(&st, "SELECT updated FROM incident WHERE id=7"), 1, "la date du dossier n'a pas bougé");

        let (statut, corps) = fdsf_corps(case_item_add(State(st.clone()), Extension(sp_au("adm", "admin")), Path(8), Json(json!({ "body": "x" }))).await).await;
        assert_eq!((statut, corps["error"].clone()), (404, json!(crate::handlers::cases::CAUSE_DOSSIER_INTROUVABLE)), "un dossier absent garde son 404 nommé");

        // CONTRÔLE POSITIF — la base revenue.
        let (statut, _) = fdsf_corps(ajouter().await).await;
        assert_eq!(statut, 204);
        assert_eq!(fdsf_compter(&st, "SELECT COUNT(*) FROM incident_item WHERE incident_id=7 AND kind='event'"), 1);
        assert!(fdsf_compter(&st, "SELECT first_response_ts FROM incident WHERE id=7") > 0, "un élément de réponse fige la première réponse");
    }
}

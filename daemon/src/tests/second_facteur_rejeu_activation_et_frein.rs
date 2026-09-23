// =====================================================================================
// `P10.22-k` — UN PAS TOTP DÉJÀ CONSOMMÉ NE DÉSACTIVE PAS LE SECOND FACTEUR.
// `P10.22-l` — L'ACTIVATION EST UN COMPARE-ET-POSE SUR L'ENRÔLEMENT QU'ELLE A LU, ET UNE MFA ACTIVE NE SE
// RÉACTIVE PAS.
// `P10.22-r` — UNE LISTE DE CODES DE SECOURS ILLISIBLE N'ACCUSE PERSONNE.
// `P10.22-m` — LE SECOND FACTEUR SE FREINE PAR COMPTE, QUELLES QUE SOIENT L'ADRESSE, LE TICKET ET LA ROUTE.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF le 2026-09-23 (banc joué sur la forme d'avant ; chaque témoin
// ci-dessous a été vu ROUGE sous la mutation qu'il nomme) :
//  * `P10.22-k` : connexion avec le pas p, puis `mfa_disable` avec le MÊME code -> 200, MFA supprimée ;
//  * `P10.22-l` : deux activations simultanées (deux connexions) -> deux 200, deux jeux de codes de secours
//    servis, un seul enregistré, « activée » deux fois au registre ; une graine RÉENRÔLÉE entre la lecture et
//    l'écriture était activée. CE QUE L'ÉNONCÉ NE DISAIT PAS : sur une MFA DÉJÀ ACTIVE, `mfa_verify` avec un
//    code frais rendait 200 et DIX codes de secours neufs en clair (ceux du titulaire remplacés), un code faux
//    401 — oracle sans frein ;
//  * `P10.22-r` : liste corrompue OU lecture refusée, code de secours JUSTE -> 401 « code MFA invalide » ;
//  * `P10.22-m` : une adresse et un ticket -> 10 codes faux puis 429 ; vingt adresses et UN ticket -> 200
//    codes faux, et le code juste depuis une 21e adresse ouvrait la session ; UNE adresse avec reconnexion
//    par le mot de passe toutes les neuf erreurs -> 180 codes faux, ZÉRO 429 ; `mfa_disable` et `mfa_verify`
//    -> 100 codes faux chacune, aucun échec compté.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : l'intercalage des activations concurrentes est FORCÉ (une troisième
// connexion tient le verrou d'écriture jusqu'à ce que les écrivains soient bloqués) — c'est une course réelle
// entre connexions, pas une course entre deux requêtes HTTP d'un même processus sur `st.db` ; le délai
// réel du frein (horloge monotone, non injectable) — sa levée et sa progression exponentielle ne sont pas
// jouées, seul son déclenchement et sa remise à zéro le sont ; le budget par adresse du `rate_limit` (non
// traversé par un appel direct de gestionnaire) ; ce que la console peint des refus neufs.
// =====================================================================================
mod second_facteur_rejeu_activation_et_frein {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SFRA_GRAINE: &[u8] = b"12345678901234567890";
    const SFRA_MOT_DE_PASSE: &str = "motdepasse12345";

    async fn sfra_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    fn sfra_compter(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// L'état mode 0 file-backed, `adm` porteur d'une MFA à la graine connue (`last_step = -1`), ACTIVE si
    /// `active`, en attente de vérification sinon, et de trois codes de secours dont les clairs sont rendus.
    fn sfra_etat_mfa(tag: &str, active: bool) -> (AppState, crate::tmp_possede::TmpDb, String, Vec<String>) {
        let (st, p) = sp_state(&format!("sfra-{tag}"));
        let graine = base32_encode(SFRA_GRAINE);
        let (clairs, haches) = gen_recovery_codes(3).expect("fixture : entropie noyau");
        st.db
            .lock()
            .execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES('adm',?1,?2,?3,-1,0,0)",
                params![graine, active as i64, json!(haches).to_string()],
            )
            .expect("fixture : MFA posée");
        (st, p, graine, clairs)
    }

    fn sfra_pas_courant() -> i64 {
        now() / 30
    }

    fn sfra_code(graine: &str, pas: i64) -> String {
        hotp(&base32_decode(graine).expect("graine base32"), pas as u64, 6)
    }

    /// Un code à six chiffres qui n'est le code d'AUCUN pas de [pas-3, pas+3] : faux à coup sûr pendant le témoin.
    fn sfra_code_faux(graine: &str, n: u64) -> String {
        let pas = sfra_pas_courant();
        let justes: Vec<String> = (-3..=3).map(|d| sfra_code(graine, pas + d)).collect();
        let mut k = n;
        loop {
            let c = format!("{:06}", k.wrapping_mul(7919).wrapping_add(13) % 1_000_000);
            if !justes.contains(&c) {
                return c;
            }
            k += 1_000_003;
        }
    }

    fn sfra_pair(ip: &str) -> std::net::SocketAddr {
        format!("{ip}:45454").parse().expect("adresse de test")
    }

    /// Le premier facteur tel qu'un navigateur le joue (`login_post`, vrai mot de passe) : rend le statut et
    /// le ticket du défi MFA.
    async fn sfra_ticket(st: &AppState, user: &str, ip: &str) -> (u16, String) {
        let r = login_post(State(st.clone()), ConnectInfo(sfra_pair(ip)), Json(json!({ "user": user, "pass": SFRA_MOT_DE_PASSE }))).await;
        let (statut, corps) = sfra_corps(r).await;
        (statut, corps["ticket"].as_str().unwrap_or("").to_string())
    }

    /// Le second facteur : rend `(statut, session posée, Retry-After, corps)`.
    async fn sfra_essai(st: &AppState, ticket: &str, code: &str, ip: &str) -> (u16, bool, Option<String>, Value) {
        let r = login_mfa_post(State(st.clone()), ConnectInfo(sfra_pair(ip)), Json(json!({ "ticket": ticket, "code": code }))).await;
        let session = r.headers().get_all(header::SET_COOKIE).iter().count() > 0;
        let attente = r.headers().get(header::RETRY_AFTER).and_then(|v| v.to_str().ok()).map(str::to_string);
        let (statut, corps) = sfra_corps(r).await;
        (statut, session, attente, corps)
    }

    async fn sfra_desactiver(st: &AppState, code: &str) -> (u16, Value) {
        sfra_corps(mfa_disable(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({ "code": code }))).await).await
    }

    async fn sfra_activer(st: &AppState, code: &str) -> (u16, Value) {
        sfra_corps(mfa_verify(State(st.clone()), Extension(sp_au("adm", "admin")), Json(json!({ "code": code }))).await).await
    }

    fn sfra_mfa_en_place(st: &AppState) -> i64 {
        sfra_compter(st, "SELECT COUNT(*) FROM user_mfa WHERE user='adm' AND enabled=1")
    }

    fn sfra_registre(st: &AppState, motif: &str) -> i64 {
        sfra_compter(st, &format!("SELECT COUNT(*) FROM ledger WHERE detail LIKE '{motif}%'"))
    }

    fn sfra_recovery(st: &AppState) -> String {
        st.db.lock().query_row("SELECT recovery FROM user_mfa WHERE user='adm'", [], |r| r.get(0)).expect("fixture : recovery lisible")
    }

    fn sfra_echecs(st: &AppState, user: &str) -> u32 {
        crate::handlers::idp::echecs_consecutifs_du_second_facteur(st, user)
    }

    // -------------------------------------------------------------------------------------
    // (1) `P10.22-k` — LE PAS CONSOMMÉ À LA CONNEXION NE DÉSACTIVE RIEN
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : le code qui vient d'ouvrir une session (pas p consommé) est REFUSÉ à la désactivation
    /// (`401`), le second facteur reste en place, le registre n'atteste rien, et l'échec est compté au frein ;
    /// un pas NEUF désactive (contrôle positif) et c'est attesté une fois.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : dans `desactiver_le_second_facteur`, juger le code par
    /// `totp_verify_step(..).is_some()` sans `consommer_le_pas_totp` (la forme d'avant, `totp_verify`) — la
    /// désactivation rend `200` et la MFA disparaît (mesuré tel quel sur la forme d'avant).
    #[tokio::test]
    async fn sfra_un_pas_consomme_a_la_connexion_ne_desactive_pas_la_mfa() {
        let (st, _p, graine, _) = sfra_etat_mfa("desactivation-rejeu", true);
        let pas = sfra_pas_courant();
        let code = sfra_code(&graine, pas);
        let (_, ticket) = sfra_ticket(&st, "adm", "10.7.0.1").await;
        let (statut, session, _, corps) = sfra_essai(&st, &ticket, &code, "10.7.0.1").await;
        assert_eq!((statut, session), (200, true), "fixture : le code ouvre la session et son pas est consommé : {corps}");

        let (statut, corps) = sfra_desactiver(&st, &code).await;
        assert_eq!(statut, 401, "le MÊME code, déjà consommé à la connexion, ne désactive PAS la MFA : {corps}");
        assert_eq!(sfra_mfa_en_place(&st), 1, "le second facteur est EN PLACE");
        assert_eq!(sfra_registre(&st, "MFA TOTP désactivée"), 0, "le registre n'atteste aucune désactivation");
        assert_eq!(sfra_echecs(&st, "adm"), 1, "un code consommé présenté est un échec du second facteur, compté");

        // CONTRÔLE POSITIF — un pas NEUF (dans la fenêtre de dérive) désactive, une fois, attesté.
        let (statut, corps) = sfra_desactiver(&st, &sfra_code(&graine, pas + 1)).await;
        assert_eq!(statut, 200, "un pas neuf désactive : {corps}");
        assert_eq!(sfra_compter(&st, "SELECT COUNT(*) FROM user_mfa WHERE user='adm'"), 0);
        assert_eq!(sfra_registre(&st, "MFA TOTP désactivée"), 1);
        assert_eq!(sfra_echecs(&st, "adm"), 0, "un code juste accepté remet le compte à zéro");
    }

    // -------------------------------------------------------------------------------------
    // Le banc des activations concurrentes : une TROISIÈME connexion tient le verrou d'écriture (WAL), les
    // écrivains lisent l'enrôlement puis se bloquent sur leur `UPDATE` ; leur gestionnaire d'occupation
    // signale le blocage. Rien n'est relâché avant que chacun ait LU : l'intercalage est forcé, pas espéré.
    // -------------------------------------------------------------------------------------

    static SFRA_BLOQUES_DEUX_ACTIVATIONS: AtomicUsize = AtomicUsize::new(0);
    fn sfra_signaler_deux_activations(essai: i32) -> bool {
        if essai == 0 {
            SFRA_BLOQUES_DEUX_ACTIVATIONS.fetch_add(1, Ordering::SeqCst);
        }
        std::thread::sleep(Duration::from_millis(2));
        essai < 5_000
    }

    static SFRA_BLOQUES_REENROLEMENT: AtomicUsize = AtomicUsize::new(0);
    fn sfra_signaler_reenrolement(essai: i32) -> bool {
        if essai == 0 {
            SFRA_BLOQUES_REENROLEMENT.fetch_add(1, Ordering::SeqCst);
        }
        std::thread::sleep(Duration::from_millis(2));
        essai < 5_000
    }

    /// Une activation jouée sur SA connexion, dans son fil : rend `(statut, corps)`.
    fn sfra_activer_dans_un_fil(st: AppState, code: String) -> std::thread::JoinHandle<(u16, Value)> {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime de fil");
            rt.block_on(async move { sfra_activer(&st, &code).await })
        })
    }

    fn sfra_attendre_les_ecrivains_bloques(compteur: &AtomicUsize, attendus: usize) {
        let limite = Instant::now() + Duration::from_secs(30);
        while compteur.load(Ordering::SeqCst) < attendus {
            assert!(Instant::now() < limite, "fixture : {attendus} écrivain(s) bloqué(s) attendu(s), {} vu(s)", compteur.load(Ordering::SeqCst));
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn sfra_passer_en_wal(st: &AppState) {
        let mode: String = st.db.lock().query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).expect("fixture : WAL");
        assert_eq!(mode, "wal", "fixture : la base passe en WAL (lecteurs non bloqués par l'écrivain)");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.22-l` — DEUX ACTIVATIONS SIMULTANÉES
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : deux activations du MÊME enrôlement par le MÊME code, sur DEUX connexions, qui ont
    /// toutes deux LU l'enrôlement avant que l'une n'écrive : une seule rend `200` et sert ses codes de
    /// secours, l'autre rend `409` nommé sans aucun code ; la liste persistée est EXACTEMENT celle servie ;
    /// « activée » une fois au registre.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer `AND enabled=0` de l'`UPDATE` de `mfa_verify` — deux `200` (vu
    /// rouge). Sous la forme d'avant (`WHERE user=?4`), MESURÉ sur ce banc : deux `200`, dix codes servis à
    /// chacune, UN SEUL des deux jeux persisté, « activée » deux fois au registre — l'énoncé, en entier.
    #[test]
    fn sfra_deux_activations_simultanees_n_en_servent_qu_une() {
        let (st, p, graine, _) = sfra_etat_mfa("deux-activations", false);
        sfra_passer_en_wal(&st);
        let (st1, st2) = (ds_file_state(&p), ds_file_state(&p));
        st1.db.lock().busy_handler(Some(sfra_signaler_deux_activations)).expect("fixture");
        st2.db.lock().busy_handler(Some(sfra_signaler_deux_activations)).expect("fixture");
        let tient_le_verrou = open_db(&p).expect("fixture : troisième connexion");
        tient_le_verrou.execute_batch("BEGIN IMMEDIATE").expect("fixture : verrou d'écriture pris");

        let code = sfra_code(&graine, sfra_pas_courant());
        let (a, b) = (sfra_activer_dans_un_fil(st1, code.clone()), sfra_activer_dans_un_fil(st2, code));
        sfra_attendre_les_ecrivains_bloques(&SFRA_BLOQUES_DEUX_ACTIVATIONS, 2);
        tient_le_verrou.execute_batch("COMMIT").expect("fixture : verrou relâché");
        let mut issues = vec![a.join().expect("fil 1"), b.join().expect("fil 2")];
        issues.sort_by_key(|(s, _)| *s);

        let statuts: Vec<u16> = issues.iter().map(|(s, _)| *s).collect();
        assert_eq!(statuts, vec![200, 409], "une seule activation gagne, l'autre est refusée : {issues:?}");
        assert_eq!(issues[1].1["error"], json!(crate::handlers::idp::CAUSE_ENROLEMENT_CHANGE_PENDANT_LA_VERIFICATION));
        assert!(issues[1].1.get("recovery_codes").is_none(), "le refusé ne sert AUCUN code de secours");
        let servis: Vec<String> = issues[0].1["recovery_codes"]
            .as_array()
            .expect("le gagnant sert ses codes")
            .iter()
            .map(|c| sha256_hex(c.as_str().expect("code").as_bytes()))
            .collect();
        let persistes: Vec<String> = serde_json::from_str(&sfra_recovery(&st)).expect("liste persistée");
        assert_eq!(persistes, servis, "la liste persistée est EXACTEMENT celle servie");
        assert_eq!(sfra_mfa_en_place(&st), 1);
        assert_eq!(sfra_registre(&st, "MFA TOTP activée"), 1, "« activée » UNE fois au registre");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.22-l` — LA GRAINE RÉENRÔLÉE ENTRE LA LECTURE ET L'ÉCRITURE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une activation qui a lu l'enrôlement de la graine G1, et pendant qu'elle attend
    /// d'écrire, un réenrôlement (l'écriture exacte de `mfa_enroll`) pose la graine G2 : l'activation rend
    /// `409` nommé et n'active RIEN — G2, que le code présenté n'a jamais prouvée, reste en attente.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer `AND secret=?5` de l'`UPDATE` de `mfa_verify` — `200`, G2
    /// active, le titulaire enfermé derrière une graine que son application n'a pas ; et remplacer les deux
    /// clauses par celle que l'énoncé prescrivait, `AND last_step<?2` — même rouge : le réenrôlement remet
    /// `last_step` à -1.
    #[test]
    fn sfra_une_graine_reenrolee_pendant_la_verification_n_est_pas_activee() {
        let (st, p, graine, _) = sfra_etat_mfa("reenrolement", false);
        sfra_passer_en_wal(&st);
        let st1 = ds_file_state(&p);
        st1.db.lock().busy_handler(Some(sfra_signaler_reenrolement)).expect("fixture");
        let concurrent = open_db(&p).expect("fixture : connexion du réenrôlement");
        concurrent.execute_batch("BEGIN IMMEDIATE").expect("fixture : verrou d'écriture pris");

        let activation = sfra_activer_dans_un_fil(st1, sfra_code(&graine, sfra_pas_courant()));
        sfra_attendre_les_ecrivains_bloques(&SFRA_BLOQUES_REENROLEMENT, 1);
        let graine_neuve = base32_encode(b"une-graine-neuve-G2!");
        concurrent
            .execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES(?1,?2,0,'[]',-1,?3,?3) \
                 ON CONFLICT(user) DO UPDATE SET secret=excluded.secret, enabled=0, recovery='[]', last_step=-1, updated=excluded.updated",
                params!["adm", graine_neuve, now()],
            )
            .expect("fixture : réenrôlement écrit");
        concurrent.execute_batch("COMMIT").expect("fixture : réenrôlement validé");
        let (statut, corps) = activation.join().expect("fil d'activation");

        assert_eq!(statut, 409, "l'enrôlement lu n'est plus là : rien n'est activé : {corps}");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_ENROLEMENT_CHANGE_PENDANT_LA_VERIFICATION));
        let (secret, enabled): (String, i64) = st
            .db
            .lock()
            .query_row("SELECT secret,enabled FROM user_mfa WHERE user='adm'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("fixture");
        assert_eq!((secret, enabled), (graine_neuve, 0), "la graine neuve reste EN ATTENTE, jamais activée par un code d'une autre");
        assert_eq!(sfra_registre(&st, "MFA TOTP activée"), 0);
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.22-l` — UNE MFA ACTIVE NE SE RÉACTIVE PAS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : sur une MFA ACTIVE, `mfa_verify` rend `409` AVANT d'examiner le code — juste ou faux,
    /// même réponse (aucun oracle), aucun code de secours servi, la liste du titulaire intacte, rien au
    /// registre, aucun échec compté.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer la garde `if enabled != 0 { 409 }` de `mfa_verify` — le code
    /// faux rend `401` (l'oracle revient — vu rouge sur l'assertion « aucun oracle »). La forme d'avant (ni garde
    /// ni `AND enabled=0`) rendait `200` et dix codes neufs sur le code juste : mesuré par le banc d'avant lot.
    #[tokio::test]
    async fn sfra_une_mfa_active_ne_se_reactive_pas_et_ne_rend_aucun_code() {
        let (st, _p, graine, _) = sfra_etat_mfa("reactivation", true);
        let liste = sfra_recovery(&st);

        let (statut, corps) = sfra_activer(&st, &sfra_code(&graine, sfra_pas_courant())).await;
        assert_eq!(statut, 409, "une MFA active ne se réactive pas, même avec un code juste : {corps}");
        assert!(corps.get("recovery_codes").is_none(), "AUCUN code de secours servi : {corps}");
        let (statut_faux, corps_faux) = sfra_activer(&st, &sfra_code_faux(&graine, 1)).await;
        assert_eq!(statut_faux, statut, "juste ou faux, la MÊME réponse — aucun oracle : {corps_faux}");
        assert_eq!(sfra_recovery(&st), liste, "la liste du titulaire est intacte");
        assert_eq!(sfra_registre(&st, "MFA TOTP activée"), 0);
        assert_eq!(sfra_echecs(&st, "adm"), 0, "le code n'a pas été examiné : rien n'est compté");
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.22-l` — L'ACTIVATION QUE LA BASE NE PREND PAS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une activation dont l'`UPDATE` est refusé rend un `503` NOMMÉ, ne sert aucun code de
    /// secours, laisse l'enrôlement en attente et n'atteste rien ; la base revenue, le même code active et
    /// sert ses dix codes (contrôle positif).
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : rétablir `Err(_) => return server_err("activation MFA échouée")` — un
    /// `500` anonyme au lieu du refus nommé.
    #[tokio::test]
    async fn sfra_une_activation_que_la_base_ne_prend_pas_ne_sert_aucun_code() {
        let (st, _p, graine, _) = sfra_etat_mfa("activation-refusee", false);
        let code = sfra_code(&graine, sfra_pas_courant());
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Update { table_name, .. } if table_name == "user_mfa" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, corps) = sfra_activer(&st, &code).await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(statut, 503, "l'activation n'est pas écrite : REFUS : {corps}");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_MFA_NON_ACTIVEE), "{corps}");
        assert!(corps.get("recovery_codes").is_none(), "aucun code de secours servi");
        assert_eq!(sfra_mfa_en_place(&st), 0, "l'enrôlement reste en attente");
        assert_eq!(sfra_registre(&st, "MFA TOTP activée"), 0);

        // CONTRÔLE POSITIF — la base revenue, le même code active et sert ses codes.
        let (statut, corps) = sfra_activer(&st, &code).await;
        assert_eq!(statut, 200, "{corps}");
        assert_eq!(corps["recovery_codes"].as_array().map(|a| a.len()), Some(10));
        assert_eq!(sfra_mfa_en_place(&st), 1);
        assert_eq!(sfra_registre(&st, "MFA TOTP activée"), 1);
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.22-r` — LA LISTE DE SECOURS ILLISIBLE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un code de secours JUSTE face à une liste corrompue, puis face à une lecture refusée,
    /// rend un `503` NOMMÉ (connexion ET désactivation) — ni session, ni désactivation, ni échec compté (ni au
    /// frein du compte, ni au verrou du couple) ; un code TOTP faux, liste illisible, reste un `401` COMPTÉ ; la
    /// liste revenue, le code de secours passe une fois (contrôle positif).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : dans `recovery_consume`, rétablir `serde_json::from_str(&rec)
    /// .unwrap_or_default()` — `401` « code MFA invalide » sur la liste corrompue (la forme d'avant, mesurée) ;
    /// rétablir `let Ok(rec) = … else { return Refuse }` — `401` sur la lecture refusée ; rétablir le repli
    /// `matched.is_none() && !code.is_empty()` au lieu de la forme TOTP — le code TOTP faux rend `503`, un refus
    /// qui ne compte AUCUN échec pendant tout le temps où la liste est illisible.
    #[tokio::test]
    async fn sfra_une_liste_de_secours_illisible_refuse_sans_accuser() {
        let (st, _p, graine, clairs) = sfra_etat_mfa("secours-illisible", true);
        let ip = "10.8.0.1";
        let (_, ticket) = sfra_ticket(&st, "adm", ip).await;
        let echecs_du_couple = |st: &AppState| st.auth_fails.lock().get(&("adm".to_string(), ip.to_string())).map_or(0, |f| f.count);
        let cause = json!(crate::handlers::idp::CAUSE_CODES_DE_SECOURS_ILLISIBLES);
        let liste = sfra_recovery(&st);

        // (a) la liste est corrompue.
        st.db.lock().execute_batch("UPDATE user_mfa SET recovery='{pas une liste' WHERE user='adm';").expect("fixture");
        let (statut, session, _, corps) = sfra_essai(&st, &ticket, &clairs[0], ip).await;
        assert_eq!((statut, session), (503, false), "liste corrompue : ni accepté ni accusé : {corps}");
        assert_eq!(corps["error"], cause, "{corps}");
        let (statut, corps) = sfra_desactiver(&st, &clairs[0]).await;
        assert_eq!(statut, 503, "la désactivation non plus n'accuse pas : {corps}");
        assert_eq!(corps["error"], cause, "{corps}");
        assert_eq!(sfra_mfa_en_place(&st), 1, "le second facteur est EN PLACE");
        assert_eq!((sfra_echecs(&st, "adm"), echecs_du_couple(&st)), (0, 0), "un refus nommé ne compte AUCUN échec");

        // un code TOTP faux, liste illisible : un échec ordinaire, COMPTÉ.
        let (statut, _, _, corps) = sfra_essai(&st, &ticket, &sfra_code_faux(&graine, 7), ip).await;
        assert_eq!(statut, 401, "six chiffres faux restent un 401, liste lisible ou non : {corps}");
        assert_eq!((sfra_echecs(&st, "adm"), echecs_du_couple(&st)), (1, 1), "et l'échec est compté");

        // (b) la lecture de la liste est refusée.
        st.db.lock().execute("UPDATE user_mfa SET recovery=?1 WHERE user='adm'", params![liste]).expect("fixture");
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == "user_mfa" && column_name == "recovery" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, session, _, corps) = sfra_essai(&st, &ticket, &clairs[1], ip).await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!((statut, session), (503, false), "lecture refusée : ni accepté ni accusé : {corps}");
        assert_eq!(corps["error"], cause, "{corps}");
        assert_eq!((sfra_echecs(&st, "adm"), echecs_du_couple(&st)), (1, 1), "rien de plus n'est compté");
        assert_eq!(sfra_registre(&st, "login local MFA validé"), 0);

        // CONTRÔLE POSITIF — la liste lisible, le code de secours passe une fois.
        let (statut, session, _, corps) = sfra_essai(&st, &ticket, &clairs[1], ip).await;
        assert_eq!((statut, session), (200, true), "{corps}");
        assert_eq!(serde_json::from_str::<Vec<String>>(&sfra_recovery(&st)).expect("liste").len(), 2, "le code est retiré");
    }

    // -------------------------------------------------------------------------------------
    // (7) `P10.22-m` — LE FREIN DU COMPTE, TOUTES ADRESSES ET RECONNEXIONS CONFONDUES
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `seuil` codes faux répartis sur quatre adresses, avec une reconnexion par le mot de
    /// passe avant chacune, freinent le COMPTE : le code JUSTE, présenté ensuite depuis une adresse NEUVE avec
    /// un ticket NEUF, est refusé en `429` (Retry-After, cause nommée), sans session, sans consommation, sans
    /// trace. Le premier facteur, lui, n'est pas freiné (le ticket neuf est servi). Sans le premier facteur,
    /// rien ne compte : des tickets forgés et des mots de passe faux au nom de `bob` ne freinent pas `bob`,
    /// dont le code juste passe (pas de déni de service sur le compte d'autrui).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer la consultation `second_facteur_freine` de `login_mfa_post`
    /// — le code juste ouvre la session ; retirer `compter_un_echec_du_second_facteur` du refus « code MFA
    /// invalide » — même rouge. La forme d'avant (verrou du seul couple, remis à zéro par le mot de passe)
    /// rendait `200` ici : mesuré, 180 codes faux sans un seul `429` depuis UNE adresse.
    #[tokio::test]
    async fn sfra_le_second_facteur_se_freine_par_compte_quelles_que_soient_l_adresse_et_la_reconnexion() {
        let (st, _p, graine, _) = sfra_etat_mfa("frein-du-compte", true);
        let graine_bob = base32_encode(b"abcdefghijabcdefghij");
        st.db
            .lock()
            .execute("INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES('bob',?1,1,'[]',-1,0,0)", params![graine_bob])
            .expect("fixture : MFA de bob");
        let seuil = st.lock_threshold;
        assert!(seuil >= 4, "fixture : seuil {seuil}");

        // SANS LE PREMIER FACTEUR — tickets forgés et mots de passe faux au nom de bob.
        for i in 0..(3 * seuil as u64) {
            let (statut, ..) = sfra_essai(&st, &format!("bob-forge.{i:064x}"), &sfra_code_faux(&graine_bob, i), &format!("10.9.{}.1", i % 200)).await;
            assert_eq!(statut, 401, "un ticket forgé est refusé avant tout");
        }
        for i in 0..3 {
            let r = login_post(State(st.clone()), ConnectInfo(sfra_pair(&format!("10.9.250.{i}"))), Json(json!({ "user": "bob", "pass": "pas-le-bon" }))).await;
            assert_eq!(r.status().as_u16(), 401, "mot de passe faux");
        }
        assert_eq!(sfra_echecs(&st, "bob"), 0, "rien ne s'est compté au second facteur de bob");

        // `seuil` CODES FAUX SUR adm — quatre adresses, une reconnexion par le mot de passe avant chacune.
        let mut echecs = 0u32;
        let mut n = 0u64;
        for a in 0..4 {
            let ip = format!("10.10.{a}.1");
            let (statut, ticket) = sfra_ticket(&st, "adm", &ip).await;
            assert_eq!(statut, 200, "fixture : le mot de passe rend un ticket");
            for _ in 0..seuil.div_ceil(4) {
                if echecs == seuil {
                    break;
                }
                n += 1;
                let (statut, ..) = sfra_essai(&st, &ticket, &sfra_code_faux(&graine, n), &ip).await;
                assert_eq!(statut, 401, "l'essai {} (sous le seuil) est un refus ordinaire", echecs + 1);
                echecs += 1;
            }
        }
        assert_eq!(echecs, seuil, "fixture : exactement `seuil` échecs joués");

        // LE SUIVANT — adresse NEUVE, ticket NEUF, code JUSTE : freiné.
        let (statut, ticket) = sfra_ticket(&st, "adm", "10.10.99.1").await;
        assert_eq!(statut, 200, "le PREMIER facteur n'est pas freiné par le frein du second");
        let (statut, session, attente, corps) = sfra_essai(&st, &ticket, &sfra_code(&graine, sfra_pas_courant()), "10.10.99.1").await;
        assert_eq!(statut, 429, "le compte est freiné : le code JUSTE n'est même pas examiné : {corps}");
        assert!(!session, "aucune session");
        assert!(attente.is_some(), "le refus dit combien attendre (Retry-After)");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_SECOND_FACTEUR_FREINE), "{corps}");
        assert_eq!(sfra_compter(&st, "SELECT last_step FROM user_mfa WHERE user='adm'"), -1, "rien n'est consommé");
        assert_eq!(sfra_registre(&st, "login local MFA validé"), 0, "aucune connexion attestée");

        // LE COMPTE D'À CÔTÉ N'EST PAS TOUCHÉ.
        let (statut, ticket_bob) = sfra_ticket(&st, "bob", "10.10.99.2").await;
        assert_eq!(statut, 200);
        let (statut, session, _, corps) = sfra_essai(&st, &ticket_bob, &sfra_code(&graine_bob, sfra_pas_courant()), "10.10.99.2").await;
        assert_eq!((statut, session), (200, true), "bob passe : le frein est celui d'adm seul : {corps}");
    }

    // -------------------------------------------------------------------------------------
    // (8) `P10.22-m` — UN CODE JUSTE ACCEPTÉ REMET LE COMPTE À ZÉRO
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : le frein compte des échecs CONSÉCUTIFS : `seuil - 1` échecs, un code juste accepté,
    /// puis `seuil - 1` échecs encore ne freinent pas — le code juste suivant passe. Le titulaire qui se trompe
    /// n'est jamais enfermé par l'accumulation de ses erreurs passées.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer `remettre_le_second_facteur_a_zero` de `login_mfa_post` — le
    /// compte reste à `seuil - 1` échecs après le code juste accepté (vu rouge sur cette assertion, au premier
    /// lot).
    #[tokio::test]
    async fn sfra_un_code_juste_accepte_remet_le_compte_a_zero() {
        let (st, _p, graine, _) = sfra_etat_mfa("frein-remise", true);
        let seuil = st.lock_threshold as u64;
        let pas = sfra_pas_courant();
        let mut n = 0u64;
        for (lot, ip) in ["10.11.0.1", "10.11.0.2"].into_iter().enumerate() {
            let (_, ticket) = sfra_ticket(&st, "adm", ip).await;
            for _ in 0..(seuil - 1) {
                n += 1;
                let (statut, ..) = sfra_essai(&st, &ticket, &sfra_code_faux(&graine, n), ip).await;
                assert_eq!(statut, 401, "lot {lot} : sous le seuil, refus ordinaire");
            }
            let (statut, session, _, corps) = sfra_essai(&st, &ticket, &sfra_code(&graine, pas + lot as i64), ip).await;
            assert_eq!((statut, session), (200, true), "lot {lot} : le code juste passe : {corps}");
            assert_eq!(sfra_echecs(&st, "adm"), 0, "lot {lot} : et remet le compte à zéro");
        }
    }

    // -------------------------------------------------------------------------------------
    // (9) `P10.22-m` — LA DÉSACTIVATION ET L'ACTIVATION COMPTENT AU MÊME FREIN
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `seuil` codes faux à la DÉSACTIVATION (session tenue) freinent le compte : le code juste
    /// y est ensuite refusé en `429` et la MFA reste en place — et la CONNEXION du même compte est freinée
    /// aussi (un seul frein par compte, quelle que soit la route). `seuil` codes faux à l'ACTIVATION d'un
    /// enrôlement en attente freinent de même : le code juste rend `429`, rien n'est activé.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : retirer la consultation `second_facteur_freine` de
    /// `desactiver_le_second_facteur` — le code juste désactive (`200`) ; retirer le compte de l'échec du bras
    /// `CodeRefuse` de `mfa_disable` — même rouge ; retirer la consultation de `mfa_verify` — le code juste
    /// active (`200`). Mesuré sur la forme d'avant : 100 codes faux sur chacune, aucun `429`.
    #[tokio::test]
    async fn sfra_la_desactivation_et_l_activation_comptent_au_frein_du_compte() {
        let (st, _p, graine, _) = sfra_etat_mfa("frein-desactivation", true);
        let seuil = st.lock_threshold as u64;
        for i in 0..seuil {
            let (statut, corps) = sfra_desactiver(&st, &sfra_code_faux(&graine, i)).await;
            assert_eq!(statut, 401, "sous le seuil, refus ordinaire : {corps}");
        }
        let (statut, corps) = sfra_desactiver(&st, &sfra_code(&graine, sfra_pas_courant())).await;
        assert_eq!(statut, 429, "le compte est freiné : le code juste ne désactive pas : {corps}");
        assert_eq!(corps["error"], json!(crate::handlers::idp::CAUSE_SECOND_FACTEUR_FREINE), "{corps}");
        assert_eq!(sfra_mfa_en_place(&st), 1, "le second facteur est EN PLACE");
        assert_eq!(sfra_registre(&st, "MFA TOTP désactivée"), 0);
        let (_, ticket) = sfra_ticket(&st, "adm", "10.12.0.1").await;
        let (statut, session, ..) = sfra_essai(&st, &ticket, &sfra_code(&graine, sfra_pas_courant()), "10.12.0.1").await;
        assert_eq!((statut, session), (429, false), "la connexion du même compte est freinée aussi");

        let (st, _p, graine, _) = sfra_etat_mfa("frein-activation", false);
        for i in 0..seuil {
            let (statut, corps) = sfra_activer(&st, &sfra_code_faux(&graine, i)).await;
            assert_eq!(statut, 401, "sous le seuil, refus ordinaire : {corps}");
        }
        let (statut, corps) = sfra_activer(&st, &sfra_code(&graine, sfra_pas_courant())).await;
        assert_eq!(statut, 429, "le compte est freiné : le code juste n'active pas : {corps}");
        assert!(corps.get("recovery_codes").is_none(), "aucun code de secours servi");
        assert_eq!(sfra_mfa_en_place(&st), 0, "rien n'est activé");
    }
}

// =====================================================================================
// `P10.31-b` — OUVRIR UN ENGAGEMENT EXIGE LE DROIT ET LE SECRET DES GESTES (`P10.24-m`), POUR TOUTES LES BOÎTES.
//
// LE DÉFAUT, MESURÉ SUR `ddc7530` : `engagement_create` ne jugeait que le droit (`require_admin`). Une session
// administrateur volée ouvrait un greybox ou un whitebox et recevait la crédence d'un compte `eng-cred-*` (whitebox :
// rôle administrateur) qui survit à la révocation de la session jusqu'à la fin de la fenêtre ; un blackbox, sans
// compte, suspendait l'auto-ban sur le scope demandé — sa propre adresse comprise.
//
// CE QUE CE LOT NE TIENT PAS (écrit pour être opposable) :
//   * le passage par le routeur entier n'est pas joué ici : l'extracteur `SecretDesGestesPresente` est celui des
//     autres gestes gardés (joué au routeur par `sdg_au_routeur_basic_et_sso_d_en_tetes_exigent_le_secret`) et la
//     signature du gestionnaire l'impose à la compilation ;
//   * aucune surface de la console n'appelle `/api/engagements` (le harnais le juge) : l'invite du secret n'y est pas
//     posée, et ne doit l'être qu'avec une surface qui jouerait ses refus.
// =====================================================================================
mod engagement_exige_le_secret_des_gestes {
    use super::*;
    use crate::secret_des_gestes::{
        SecretDesGestesPresente, SourceDuSecretDesGestes, CAUSE_SECRET_DES_GESTES_ABSENT, CAUSE_SECRET_DES_GESTES_FAUX,
        CAUSE_SECRET_DES_GESTES_NON_CONFIGURE,
    };

    async fn eesg_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| json!({ "_texte": String::from_utf8_lossy(&b) })))
    }

    fn eesg_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn eesg_ouvrir(st: &AppState, presente: SecretDesGestesPresente, boite: &str, reseau: &str) -> (u16, Value) {
        let corps = json!({ "box": boite, "scope": [reseau], "reason": "eesg", "window_end": now() + 3600 });
        eesg_corps(engagement_create(State(st.clone()), presente, Extension(sp_au("adm", "admin")), Json(corps)).await).await
    }

    fn eesg_refus(statut: u16, v: &Value, cause: &str, geste: &str) {
        assert_eq!(statut, 403, "{geste} : refus attendu, lu {statut} {v}");
        assert_eq!(v["cause"], json!(cause), "{geste} : la cause du contrat, lue {v}");
    }

    fn eesg_rien_d_ecrit(st: &AppState, geste: &str) {
        assert_eq!(eesg_compte(st, "SELECT COUNT(*) FROM engagement"), 0, "{geste} : aucun engagement");
        assert_eq!(eesg_compte(st, "SELECT COUNT(*) FROM engagement_grant"), 0, "{geste} : aucun permis");
        assert_eq!(eesg_compte(st, "SELECT COUNT(*) FROM user WHERE name LIKE 'eng-cred-%'"), 0, "{geste} : aucun compte frappé");
        assert_eq!(eesg_compte(st, "SELECT COUNT(*) FROM ledger WHERE kind='config.engagement.create'"), 0, "{geste} : aucune ouverture attestée");
    }

    /// CE QU'IL TIENT : greybox et whitebox (les boîtes qui frappent un compte) sans en-tête -> 403 `absent` ; secret
    /// des gestes non configuré -> 403 `non_configure`, même avec le bon secret ; secret faux -> 403 `faux`. Après ces
    /// six refus, RIEN n'est écrit (engagement, permis, compte `eng-cred-*`, attestation) et aucune exemption n'est
    /// posée. Contrôle positif : le bon secret ouvre, et la crédence est montrée.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=p1031b_sans_secret` (le jugement du secret sauté) — 200 et une
    /// crédence dès le premier refus attendu.
    #[tokio::test]
    async fn eesg_greybox_et_whitebox_sans_le_secret_ne_frappent_aucune_credence() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let (st, _p) = sp_state("eesg-frappe");
        let chemin = st.db_path.as_str().to_string();
        let mut st_non_configure = st.clone();
        st_non_configure.secret_des_gestes = Arc::new(SourceDuSecretDesGestes::NonConfiguree);
        let absent = || SecretDesGestesPresente { valeur: None, ip: "127.0.0.1".into() };
        let faux = || SecretDesGestesPresente { valeur: Some("ce-n-est-pas-le-secret-eesg".into()), ip: "127.0.0.1".into() };

        for boite in ["greybox", "whitebox"] {
            let (s, v) = eesg_ouvrir(&st, absent(), boite, "198.51.100.0/24").await;
            eesg_refus(s, &v, CAUSE_SECRET_DES_GESTES_ABSENT, &format!("{boite} sans en-tête"));
            let (s, v) = eesg_ouvrir(&st_non_configure, crate::secret_des_gestes::presente_de_test(), boite, "198.51.100.0/24").await;
            eesg_refus(s, &v, CAUSE_SECRET_DES_GESTES_NON_CONFIGURE, &format!("{boite} sans secret configuré"));
            let (s, v) = eesg_ouvrir(&st, faux(), boite, "198.51.100.0/24").await;
            eesg_refus(s, &v, CAUSE_SECRET_DES_GESTES_FAUX, &format!("{boite} secret faux"));
            assert!(v.get("credentials").is_none(), "{boite} : aucune crédence montrée : {v}");
        }
        eesg_rien_d_ecrit(&st, "après les refus");
        assert!(!ip_in_active_engagement("198.51.100.9", &chemin), "aucune exemption posée");

        let (s, v) = eesg_ouvrir(&st, crate::secret_des_gestes::presente_de_test(), "greybox", "198.51.100.0/24").await;
        assert_eq!(s, 200, "le droit ET le secret : l'engagement s'ouvre ({v})");
        assert_eq!(v["credentials"][0]["kind"], json!("scoped_cred"), "la crédence est frappée et montrée une fois : {v}");
        assert_eq!(eesg_compte(&st, "SELECT COUNT(*) FROM user WHERE name LIKE 'eng-cred-%'"), 1);
        eng_test_reset();
    }

    /// CE QU'IL TIENT (LA DÉCISION ÉCRITE POUR BLACKBOX) : un blackbox ne frappe aucun compte, mais il SUSPEND l'auto-ban
    /// sur son scope — il est gardé comme les autres boîtes. Sans en-tête -> 403 `absent`, aucun engagement, et
    /// l'adresse du scope n'est PAS exemptée. Contrôle positif : avec le secret, 200, aucune crédence, et l'adresse
    /// est exemptée.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=p1031b_blackbox_libre` (le secret exigé des seules boîtes qui
    /// frappent un compte) et `VERIF_MUT=p1031b_sans_secret` — 200 et l'exemption posée sans le secret.
    #[tokio::test]
    async fn eesg_blackbox_sans_le_secret_ne_suspend_pas_l_auto_ban() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let (st, _p) = sp_state("eesg-blackbox");
        let chemin = st.db_path.as_str().to_string();

        let (s, v) = eesg_ouvrir(&st, SecretDesGestesPresente { valeur: None, ip: "127.0.0.1".into() }, "blackbox", "203.0.113.0/24").await;
        eesg_refus(s, &v, CAUSE_SECRET_DES_GESTES_ABSENT, "blackbox sans en-tête");
        eesg_rien_d_ecrit(&st, "blackbox refusé");
        assert!(!ip_in_active_engagement("203.0.113.7", &chemin), "sans le secret, l'auto-ban n'est pas suspendu");

        let (s, v) = eesg_ouvrir(&st, crate::secret_des_gestes::presente_de_test(), "blackbox", "203.0.113.0/24").await;
        assert_eq!(s, 200, "avec le secret, le blackbox s'ouvre ({v})");
        assert_eq!(v["credentials"], json!([]), "blackbox : aucune crédence ({v})");
        assert!(ip_in_active_engagement("203.0.113.7", &chemin), "contrôle positif : l'exemption est posée");
        eng_test_reset();
    }

    /// CE QU'IL TIENT (L'ORDRE ÉCRIT DANS L'EN-TÊTE DE `engagement_create`) : le secret est jugé APRÈS le contrôle du
    /// mode et la validation du corps. Mode engagement éteint (l'état de la prod) et aucun en-tête -> 409 du mode, pas
    /// 403 du secret. Corps irrecevable (boîte inconnue, puis scope vide) avec un secret FAUX -> 400, et AUCUN échec
    /// n'est inscrit au registre `secret_des_gestes` (un corps irrecevable n'engage aucun essai). Contrôle positif : un
    /// corps recevable avec le même secret faux, lui, est inscrit — le témoin sait voir l'inscription.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=b1c_garde_avant_validation` (le jugement remonté juste après
    /// `require_admin`) — 403 `absent` au lieu de 409, puis 403 `faux` et une inscription au lieu de 400.
    #[tokio::test]
    async fn eesg_le_secret_est_juge_apres_le_mode_et_la_validation_du_corps() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        let (st, _p) = sp_state("eesg-ordre");
        let absent = || SecretDesGestesPresente { valeur: None, ip: "127.0.0.1".into() };
        let faux = || SecretDesGestesPresente { valeur: Some("ce-n-est-pas-le-secret-eesg".into()), ip: "127.0.0.1".into() };
        let inscrits = |st: &AppState| eesg_compte(st, "SELECT COUNT(*) FROM ledger WHERE kind='secret_des_gestes'");

        set_engagement_mode(false);
        let (s, v) = eesg_ouvrir(&st, absent(), "greybox", "198.51.100.0/24").await;
        assert_eq!(s, 409, "mode éteint, sans en-tête : le refus du MODE, pas celui du secret ({v})");

        set_engagement_mode(true);
        let (s, v) = eesg_ouvrir(&st, faux(), "boite-inconnue", "198.51.100.0/24").await;
        assert_eq!(s, 400, "boîte inconnue + secret faux : le corps est refusé d'abord ({v})");
        let corps = json!({ "box": "greybox", "scope": [], "reason": "eesg", "window_end": now() + 3600 });
        let (s, v) = eesg_corps(engagement_create(State(st.clone()), faux(), Extension(sp_au("adm", "admin")), Json(corps)).await).await;
        assert_eq!(s, 400, "scope vide + secret faux : le corps est refusé d'abord ({v})");
        assert_eq!(inscrits(&st), 0, "un corps irrecevable n'engage aucun essai du secret");
        eesg_rien_d_ecrit(&st, "corps irrecevables");

        let (s, v) = eesg_ouvrir(&st, faux(), "greybox", "198.51.100.0/24").await;
        eesg_refus(s, &v, CAUSE_SECRET_DES_GESTES_FAUX, "corps recevable, secret faux");
        assert_eq!(inscrits(&st), 1, "contrôle positif : l'essai d'un secret faux est inscrit");
        eng_test_reset();
    }

    /// CE QU'IL TIENT (LE CONTRAT DE `P10.24-m` APPLIQUÉ À L'OUVERTURE) : un secret faux sur un corps recevable est inscrit
    /// au registre au nom de l'ADMINISTRATEUR présenté (`'adm'`), avec le libellé du geste qui nomme la boîte et
    /// l'engagement, sans jamais porter le secret présenté ; l'échec est compté au frein du couple (administrateur,
    /// adresse). Après `lock_threshold` essais faux sous des NOMS D'ENGAGEMENT tous différents, le BON secret reçoit 429 :
    /// changer de nom d'engagement n'ouvre pas une nouvelle clé de frein. Rien n'est écrit.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=b1d_auteur_vide` (auteur `""` : le registre ne nomme plus `'adm'`),
    /// `VERIF_MUT=b1d_auteur_nom_engagement` (auteur = `name` : une clé de frein par nom, le bon secret passe en 200),
    /// `VERIF_MUT=b1d_geste_faux` (un libellé qui ne nomme pas l'ouverture de l'engagement).
    #[tokio::test]
    async fn eesg_le_faux_compte_au_frein_et_au_registre_de_l_administrateur_quel_que_soit_le_nom() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let (st, _p) = sp_state("eesg-frein");
        let faux_secret = "ce-n-est-pas-le-secret-eesg-frein";
        let ouvrir_nomme = |presente: SecretDesGestesPresente, nom: String| {
            let st = st.clone();
            async move {
                let corps = json!({ "name": nom, "box": "greybox", "scope": ["198.51.100.0/24"], "reason": "eesg", "window_end": now() + 3600 });
                eesg_corps(engagement_create(State(st), presente, Extension(sp_au("adm", "admin")), Json(corps)).await).await
            }
        };
        let faux = || SecretDesGestesPresente { valeur: Some(faux_secret.into()), ip: "127.0.0.1".into() };

        let (s, v) = ouvrir_nomme(faux(), "eesg-n0".into()).await;
        eesg_refus(s, &v, CAUSE_SECRET_DES_GESTES_FAUX, "premier essai faux");
        assert_eq!(
            st.auth_fails.lock().get(&("<secret-des-gestes:adm>".to_string(), "127.0.0.1".to_string())).map(|f| f.count),
            Some(1),
            "l'échec est compté au frein du couple (administrateur, adresse)"
        );
        let traces: Vec<String> = st
            .db
            .lock()
            .prepare("SELECT detail FROM ledger WHERE kind='secret_des_gestes'")
            .and_then(|mut s| s.query_map([], |r| r.get::<_, String>(0))?.collect())
            .expect("registre lisible");
        assert_eq!(traces.len(), 1, "une ligne au registre : {traces:?}");
        assert!(traces[0].contains("présenté par 'adm'"), "le registre nomme l'administrateur : {traces:?}");
        assert!(
            traces[0].contains("ouverture de l'engagement greybox 'eesg-n0'"),
            "le registre nomme le geste (boîte et engagement) : {traces:?}"
        );
        assert!(!traces[0].contains(faux_secret), "le registre ne porte JAMAIS le secret présenté : {traces:?}");

        for i in 1..st.lock_threshold {
            let (s, v) = ouvrir_nomme(faux(), format!("eesg-n{i}")).await;
            assert_eq!(s, 403, "essai faux {i} sous un autre nom d'engagement : {v}");
        }
        let (s, v) = ouvrir_nomme(crate::secret_des_gestes::presente_de_test(), "eesg-bon".into()).await;
        assert_eq!(s, 429, "au-delà du seuil, le frein de l'administrateur mord, quel que soit le nom : {v}");
        eesg_rien_d_ecrit(&st, "frein");
        eng_test_reset();
    }

    /// CE QU'IL TIENT : les phrases de refus du secret des gestes (non configuré, absent) NOMMENT l'ouverture d'un
    /// engagement parmi les gestes gardés : l'administrateur refusé sur `POST /api/engagements` y lit ce qu'il fait.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer « engagement » de l'une des deux phrases.
    #[test]
    fn eesg_les_phrases_de_refus_nomment_l_ouverture_d_un_engagement() {
        use crate::secret_des_gestes::{TEXTE_SECRET_DES_GESTES_ABSENT, TEXTE_SECRET_DES_GESTES_NON_CONFIGURE};
        for (nom, texte) in [("non configuré", TEXTE_SECRET_DES_GESTES_NON_CONFIGURE), ("absent", TEXTE_SECRET_DES_GESTES_ABSENT)] {
            assert!(texte.contains("engagement"), "phrase « {nom} » : l'engagement n'est pas nommé : {texte}");
        }
    }
}

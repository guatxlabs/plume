// =====================================================================================
// `P10.31-f` — LE NOM D'ENGAGEMENT EST BORNÉ ET VALIDÉ AVANT LE LIBELLÉ DU GESTE, ET AUCUNE CRÉDENCE N'EST HACHÉE AVANT LE
// JUGEMENT DU SECRET DES GESTES.
//
// LE DÉFAUT, MESURÉ SUR `94e36aa` : `engagement_create` ne faisait que `trimmed("name")`, puis passait
// `format!("ouverture de l'engagement {box} '{name}' …")` à `exiger_le_secret_des_gestes` AVANT que le secret soit
// jugé. Une session administrateur SANS le secret écrivait donc jusqu'au plafond de corps (8 Mio, `DefaultBodyLimit`
// de `server/groupes_de_routes.rs`), sauts de ligne compris, sur stderr (secret non configuré : aucun frein) et au
// registre non purgeable (secret faux : borné par le frein). Et l'ordre secret-puis-frappe n'était témoigné par rien :
// la frappe argon2 remontée avant le jugement ne coûtait que du CPU, aucun témoin ne la voyait.
//
// CE QUE CE LOT NE TIENT PAS (écrit pour être opposable) :
//   * stderr n'est pas capturé : l'absence de libellé y est prouvée STRUCTURELLEMENT — le seul `eprintln!` qui porte
//     le libellé avant le jugement est dans `exiger_le_secret_des_gestes`, et le refus 400 rendu sous un secret NON
//     CONFIGURÉ (au lieu du 403 `non_configure` que ce crochet rend toujours) prouve qu'il n'est pas atteint ;
//   * `reason`, `authorizer`, `adapter` et `idp_adapter` ne sont PAS bornés : mesurés, ils n'entrent ni dans le libellé
//     ni sur stderr avant le secret, seulement dans la ligne et l'attestation écrites APRÈS le droit ET le secret ;
//   * les caractères de mise en forme Unicode (U+202E et voisins) ne sont pas des caractères de contrôle au sens de
//     `char::is_control` et restent admis ;
//   * le passage par le routeur (et donc par le plafond de corps réel) n'est pas joué : le gestionnaire est appelé
//     directement, comme dans les témoins `eesg_` de `P10.31-b`.
// =====================================================================================
mod engagement_nom_borne_avant_le_secret {
    use super::*;
    use crate::secret_des_gestes::{
        SecretDesGestesPresente, SourceDuSecretDesGestes, CAUSE_SECRET_DES_GESTES_ABSENT, CAUSE_SECRET_DES_GESTES_FAUX,
        CAUSE_SECRET_DES_GESTES_NON_CONFIGURE,
    };

    const EESG_FAUX: &str = "ce-n-est-pas-le-secret-eesg-nom";

    async fn eesg_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| json!({ "_texte": String::from_utf8_lossy(&b) })))
    }

    fn eesg_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn eesg_faux() -> SecretDesGestesPresente {
        SecretDesGestesPresente { valeur: Some(EESG_FAUX.into()), ip: "127.0.0.1".into() }
    }

    fn eesg_non_configure(st: &AppState) -> AppState {
        let mut st = st.clone();
        st.secret_des_gestes = Arc::new(SourceDuSecretDesGestes::NonConfiguree);
        st
    }

    async fn eesg_ouvrir_nomme(st: &AppState, presente: SecretDesGestesPresente, admin: &str, boite: &str, nom: Option<&str>) -> (u16, Value) {
        let mut corps = json!({ "box": boite, "scope": ["198.51.100.0/24"], "reason": "eesg", "window_end": now() + 3600 });
        if let Some(nom) = nom {
            corps["name"] = json!(nom);
        }
        eesg_corps(engagement_create(State(st.clone()), presente, Extension(sp_au(admin, "admin")), Json(corps)).await).await
    }

    fn eesg_traces(st: &AppState) -> Vec<String> {
        st.db
            .lock()
            .prepare("SELECT detail FROM ledger WHERE kind='secret_des_gestes' ORDER BY rowid")
            .and_then(|mut s| s.query_map([], |r| r.get::<_, String>(0))?.collect())
            .expect("registre lisible")
    }

    fn eesg_hachages() -> u64 {
        HACHAGES_DE_CREDENCE_D_ENGAGEMENT.with(|n| n.get())
    }

    /// CE QU'IL TIENT : un nom de 1 Mio semé de sauts de ligne, un nom de 1 Mio sans contrôle, un nom court portant un
    /// saut de ligne, un retour chariot, un NUL, et un nom de 121 octets (un de trop) sont refusés en 400 nommé — sous un
    /// secret FAUX comme sous un secret NON CONFIGURÉ. Aucun ne laisse de ligne au registre `secret_des_gestes`, aucun
    /// n'est compté au frein, aucun n'atteint le crochet du secret (le 400 sous secret non configuré au lieu du 403
    /// `non_configure` : le seul `eprintln!` qui porte le libellé n'est pas joué), et le refus ne recopie pas le nom.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : mutant `d6_sans_borne` (la longueur n'est plus jugée : le nom de 1 Mio sans
    /// contrôle passe au secret, 403 et une ligne de 1 Mio au registre), mutant `d6_sans_controle` (le saut de ligne
    /// court passe au secret) et mutant `d6_validation_apres_secret` (la même validation, jouée APRÈS le jugement :
    /// 403 `faux` et la ligne écrite).
    #[tokio::test]
    async fn eesg_un_nom_hors_borne_ou_a_saut_de_ligne_est_refuse_avant_le_secret() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let (st, _p) = sp_state("eesg-nom-refus");
        let st_non_configure = eesg_non_configure(&st);
        let mio = 1024 * 1024;
        let mio_a_sauts: String = "x".repeat(1023).chars().chain(std::iter::once('\n')).collect::<String>().repeat(mio / 1024);
        let refuses: Vec<(&str, String)> = vec![
            ("1 Mio semé de sauts de ligne", mio_a_sauts),
            ("1 Mio sans contrôle", "a".repeat(mio)),
            ("saut de ligne court", "pentest\nFAUX secret présenté par 'quelqu'un'".into()),
            ("retour chariot court", "pentest\rforgé".into()),
            ("NUL court", "pentest\0suite".into()),
            ("121 octets", "é".repeat(60) + "a"),
        ];
        for (cas, nom) in &refuses {
            let (s, v) = eesg_ouvrir_nomme(&st, eesg_faux(), "adm", "greybox", Some(nom)).await;
            assert_eq!(s, 400, "{cas}, secret faux : le nom est refusé avant le secret ({})", v.to_string().chars().take(300).collect::<String>());
            let erreur = v["error"].as_str().unwrap_or_default();
            assert!(erreur.starts_with("name refusé"), "{cas} : le refus nomme le champ : {erreur:.300}");
            assert!(erreur.len() < 300, "{cas} : le refus ne recopie pas le nom ({} octets)", erreur.len());
            let (s, v) = eesg_ouvrir_nomme(&st_non_configure, crate::secret_des_gestes::presente_de_test(), "adm", "greybox", Some(nom)).await;
            assert_eq!(s, 400, "{cas}, secret non configuré : 400 et non le 403 du crochet, donc aucun libellé sur stderr ({})", v.to_string().chars().take(300).collect::<String>());
        }
        assert_eq!(eesg_traces(&st), Vec::<String>::new(), "aucun nom refusé n'entre au registre");
        assert!(
            st.auth_fails.lock().get(&("<secret-des-gestes:adm>".to_string(), "127.0.0.1".to_string())).is_none(),
            "aucun essai compté au frein : le secret n'a pas été jugé"
        );
        assert_eq!(eesg_compte(&st, "SELECT COUNT(*) FROM engagement"), 0, "aucun engagement");
        assert_eq!(eesg_compte(&st, "SELECT COUNT(*) FROM user WHERE name LIKE 'eng-cred-%'"), 0, "aucun compte frappé");

        // Contrôle positif de l'instrument : un nom recevable sous le même secret faux, lui, est inscrit.
        let (s, v) = eesg_ouvrir_nomme(&st, eesg_faux(), "adm", "greybox", Some("eesg-recevable")).await;
        assert_eq!((s, v["cause"].clone()), (403, json!(CAUSE_SECRET_DES_GESTES_FAUX)), "nom recevable, secret faux : {v}");
        assert_eq!(eesg_traces(&st).len(), 1, "le témoin sait voir l'inscription");
        eng_test_reset();
    }

    /// CE QU'IL TIENT : un nom VALIDE garde le comportement d'avant octet pour octet — sans nom, un nom libre (espaces,
    /// accents, tiret long, ponctuation) et un nom de 120 octets exactement (soixante `é`, la borne). Secret faux : 403
    /// `faux` et la ligne du registre est EXACTEMENT celle d'avant ; secret non configuré : 403 `non_configure` ; sans
    /// en-tête : 403 `absent` ; avec le secret : 200, et la ligne `engagement` porte le nom reçu (rogné) à l'octet.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : aucune des trois de ce lot (elles élargissent ce qui passe) ; il rougit sur une
    /// borne resserrée sous 120 octets ou un refus des accents.
    #[tokio::test]
    async fn eesg_un_nom_valide_garde_le_comportement_d_avant_a_l_octet() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let (st, _p) = sp_state("eesg-nom-valide");
        let st_non_configure = eesg_non_configure(&st);
        let borne = "é".repeat(60);
        assert_eq!(borne.len(), NOM_D_ENGAGEMENT_MAX_OCTETS, "la borne est jouée exactement");
        let valides: Vec<(&str, Option<&str>, &str)> = vec![
            ("sans nom", None, ""),
            ("nom libre", Some("  Pentest externe T4 — équipe rouge, périmètre « DMZ » (2026)  "), "Pentest externe T4 — équipe rouge, périmètre « DMZ » (2026)"),
            ("120 octets", Some(borne.as_str()), borne.as_str()),
        ];
        for (i, (cas, nom, attendu)) in valides.iter().enumerate() {
            let admin = format!("adm{i}");
            let avant = eesg_traces(&st).len();
            let (s, v) = eesg_ouvrir_nomme(&st, eesg_faux(), &admin, "greybox", *nom).await;
            assert_eq!((s, v["cause"].clone()), (403, json!(CAUSE_SECRET_DES_GESTES_FAUX)), "{cas}, secret faux : {v}");
            let traces = eesg_traces(&st);
            assert_eq!(traces.len(), avant + 1, "{cas} : une ligne au registre");
            assert_eq!(
                traces[avant],
                format!("secret des gestes FAUX présenté par '{admin}' depuis 127.0.0.1 pour « ouverture de l'engagement greybox '{attendu}' (scope : 1 réseau(x)) » — geste refusé, rien n'est écrit"),
                "{cas} : la ligne du registre est celle d'avant, à l'octet"
            );
            let (s, v) = eesg_ouvrir_nomme(&st_non_configure, crate::secret_des_gestes::presente_de_test(), &admin, "greybox", *nom).await;
            assert_eq!((s, v["cause"].clone()), (403, json!(CAUSE_SECRET_DES_GESTES_NON_CONFIGURE)), "{cas}, non configuré : le refus nommé d'avant : {v}");
            let absent = SecretDesGestesPresente { valeur: None, ip: "127.0.0.1".into() };
            let (s, v) = eesg_ouvrir_nomme(&st, absent, &admin, "greybox", *nom).await;
            assert_eq!((s, v["cause"].clone()), (403, json!(CAUSE_SECRET_DES_GESTES_ABSENT)), "{cas}, sans en-tête : {v}");
            let (s, v) = eesg_ouvrir_nomme(&st, crate::secret_des_gestes::presente_de_test(), &admin, "greybox", *nom).await;
            assert_eq!(s, 200, "{cas}, avec le secret : l'engagement s'ouvre ({v})");
            let id = v["id"].as_str().expect("identifiant rendu").to_string();
            let stocke: String = st.db.lock().query_row("SELECT name FROM engagement WHERE id=?1", [&id], |r| r.get(0)).expect("ligne écrite");
            assert_eq!(stocke, *attendu, "{cas} : le nom écrit est celui d'avant, à l'octet");
        }
        eng_test_reset();
    }

    /// CE QU'IL TIENT (L'ORDRE SECRET-PUIS-FRAPPE, SANS HORLOGE) : greybox et whitebox — les boîtes qui frappent un
    /// compte — sans en-tête, sous un secret non configuré et sous un secret faux : ZÉRO hachage argon2 de crédence
    /// (compteur de `frapper_les_credences`, lu sur le fil du test). Contrôle positif : avec le secret, un greybox en
    /// compte exactement UN.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : mutant `d6_frappe_avant_secret` (la frappe des crédences jouée AVANT le
    /// jugement du secret, son résultat gardé pour après) — un hachage dès le premier refus. Le refus, lui, reste 403 :
    /// seul ce compteur voit la mutation, que les témoins de `P10.31-b` laissaient verte.
    #[tokio::test]
    async fn eesg_aucune_credence_n_est_hachee_avant_le_jugement_du_secret() {
        let _g = ENGAGEMENT_TEST_LOCK.lock();
        eng_test_reset();
        set_engagement_mode(true);
        let (st, _p) = sp_state("eesg-nom-frappe");
        let st_non_configure = eesg_non_configure(&st);
        let depart = eesg_hachages();
        for boite in ["greybox", "whitebox"] {
            let absent = SecretDesGestesPresente { valeur: None, ip: "127.0.0.1".into() };
            let (s, _) = eesg_ouvrir_nomme(&st, absent, "adm", boite, Some("eesg-frappe")).await;
            assert_eq!(s, 403, "{boite} sans en-tête");
            assert_eq!(eesg_hachages() - depart, 0, "{boite} sans en-tête : aucune frappe argon2 avant le jugement");
            let (s, _) = eesg_ouvrir_nomme(&st_non_configure, crate::secret_des_gestes::presente_de_test(), "adm", boite, Some("eesg-frappe")).await;
            assert_eq!(s, 403, "{boite} non configuré");
            assert_eq!(eesg_hachages() - depart, 0, "{boite} non configuré : aucune frappe argon2 avant le jugement");
            let (s, _) = eesg_ouvrir_nomme(&st, eesg_faux(), "adm", boite, Some("eesg-frappe")).await;
            assert_eq!(s, 403, "{boite} secret faux");
            assert_eq!(eesg_hachages() - depart, 0, "{boite} secret faux : aucune frappe argon2 avant le jugement");
        }
        let (s, v) = eesg_ouvrir_nomme(&st, crate::secret_des_gestes::presente_de_test(), "adm", "greybox", Some("eesg-frappe")).await;
        assert_eq!(s, 200, "contrôle positif : le droit ET le secret ({v})");
        assert_eq!(eesg_hachages() - depart, 1, "contrôle positif : la frappe d'un greybox est comptée, une fois");
        eng_test_reset();
    }
}

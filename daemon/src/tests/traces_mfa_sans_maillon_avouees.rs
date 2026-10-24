// =====================================================================================
// `P10.31-u` (troisième tranche : `handlers/idp.rs`) — LES TROIS TRACES MFA AVOUENT UN MAILLON MANQUANT.
//
// LE DÉFAUT, MESURÉ SUR 2e4fe6eb AVANT LE CORRECTIF. Trois appels NUS de `ledger_append` dans `idp.rs` jetaient leur
// maillon : le refus d'enrôlement (mot de passe re-saisi faux, `mfa_enroll`), l'activation (`mfa_verify`, après
// l'UPDATE compare-et-pose) et la désactivation (`mfa_disable`, après le COMMIT). La primitive avouait la perte sur la
// sortie d'erreur ; la réponse n'en disait rien. Pire pour le refus : sa phrase (`CAUSE_MOT_DE_PASSE_REFUSE_A_L_ENROLEMENT`)
// AFFIRME « … et inscrit au registre » — un fait faux quand le maillon n'entre pas.
//
// LE CORRECTIF. Refus : maillon non inscrit -> même 403, phrase distincte qui n'affirme pas la trace
// (`CAUSE_MOT_DE_PASSE_REFUSE_A_L_ENROLEMENT_SANS_TRACE`) et `registre_sans_maillon` (`CAUSE_REFUS_SANS_TRACE`).
// Activation et désactivation : le geste a eu lieu, il n'est pas annulé — 200 et `registre_sans_maillon`
// (`CAUSE_GESTE_SANS_TRACE`) ; les `recovery_codes` clairs, servis UNE SEULE FOIS, restent dans le corps.
// Chemin nominal octet pour octet (contrôles négatifs ci-dessous).
//
// LA PANNE ÉPROUVÉE : un déclencheur `BEFORE INSERT ON ledger` qui lève `RAISE(ABORT)` (précédent :
// `attestations_d_identite_sans_maillon_avouees.rs`). Aucune autre écriture de ces trois routes ne touche `ledger`
// (vérifié : `prouver_le_premier_facteur`, le frein du second facteur et `ouvrir_la_transaction_du_geste` n'y écrivent pas).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les traces de connexion SSO (OIDC, SAML, LDAP) et du second facteur à la
// connexion, autres appels nus d'`idp.rs` ; la console ne lit pas `registre_sans_maillon` sur ces routes ; la sortie
// d'erreur de la primitive n'est pas capturée ici.
// =====================================================================================
mod traces_mfa_sans_maillon_avouees {
    use super::*;

    const TMMSA_GRAINE: &[u8] = b"12345678901234567890";

    fn tmmsa_pair(ip: &str) -> std::net::SocketAddr {
        format!("{ip}:47474").parse().expect("adresse de test")
    }

    fn tmmsa_code(graine_b32: &str) -> String {
        hotp(&base32_decode(graine_b32).expect("graine base32"), (now() / 30) as u64, 6)
    }

    /// Statut, octets bruts du corps, et sa lecture JSON.
    async fn tmmsa_reponse(r: Response) -> (u16, Vec<u8>, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, octets, v)
    }

    fn tmmsa_aveu(v: &Value) -> Option<String> {
        v.get(CLE_REGISTRE_SANS_MAILLON).and_then(|x| x.as_str()).map(str::to_string)
    }

    /// LA PANNE : le maillon ne s'écrit plus, le registre se lit toujours.
    fn tmmsa_registre_hors_d_atteinte(st: &AppState) {
        st.db
            .lock()
            .execute_batch(
                "CREATE TRIGGER tmmsa_ledger_refuse BEFORE INSERT ON ledger \
                 BEGIN SELECT RAISE(ABORT, 'registre hors d atteinte (temoin P10.31-u MFA)'); END;",
            )
            .expect("fixture : le déclencheur se pose");
    }

    fn tmmsa_lignes_mfa_au_registre(st: &AppState) -> i64 {
        st.db.lock().query_row("SELECT COUNT(*) FROM ledger WHERE kind='mfa'", [], |r| r.get(0)).expect("fixture : le registre se lit")
    }

    /// `(lignes user_mfa, enabled)` de `adm`.
    fn tmmsa_mfa_de_adm(st: &AppState) -> (i64, i64) {
        st.db
            .lock()
            .query_row("SELECT COUNT(*), COALESCE(MAX(enabled), -1) FROM user_mfa WHERE user='adm'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("fixture : user_mfa se lit")
    }

    /// `adm` porteur d'un second facteur à la graine connue, `enabled` donné, `last_step = -1`.
    fn tmmsa_etat_mfa(tag: &str, enabled: i64) -> (AppState, crate::tmp_possede::TmpDb, String) {
        let (st, p) = sp_state(&format!("tmmsa-{tag}"));
        let graine = base32_encode(TMMSA_GRAINE);
        st.db
            .lock()
            .execute(
                "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) VALUES('adm',?1,?2,'[]',-1,0,0)",
                params![graine, enabled],
            )
            .expect("fixture : second facteur posé");
        (st, p, graine)
    }

    async fn tmmsa_enroler_faux(st: &AppState, ip: &str) -> (u16, Vec<u8>, Value) {
        let corps = json!({ "password": "pas-le-bon-mot-de-passe-tmmsa" });
        tmmsa_reponse(mfa_enroll(State(st.clone()), ConnectInfo(tmmsa_pair(ip)), Extension(sp_au("adm", "admin")), Json(corps)).await).await
    }

    async fn tmmsa_activer(st: &AppState, code: &str) -> (u16, Vec<u8>, Value) {
        tmmsa_reponse(mfa_verify(State(st.clone()), ConnectInfo(tmmsa_pair("10.61.0.2")), Extension(sp_au("adm", "admin")), Json(json!({ "code": code }))).await).await
    }

    async fn tmmsa_desactiver(st: &AppState, code: &str) -> (u16, Vec<u8>, Value) {
        tmmsa_reponse(mfa_disable(State(st.clone()), ConnectInfo(tmmsa_pair("10.61.0.3")), Extension(sp_au("adm", "admin")), Json(json!({ "code": code }))).await).await
    }

    /// CE QU'IL TIENT : registre hors d'atteinte, l'enrôlement au mot de passe faux reste refusé en 403, l'échec reste
    /// compté au verrou de la connexion, aucune graine n'est posée — mais la phrase servie N'EST PAS la nominale (qui
    /// affirme « inscrit au registre ») : c'est celle qui dit le trou, et le corps porte `registre_sans_maillon`
    /// (`CAUSE_REFUS_SANS_TRACE` et la cause du moteur, sans le nom du compte). Aucune ligne `mfa` au registre.
    ///
    /// MUTATIONS QUI LE FONT ROUGIR : `tmmsa_jeter_refus` (maillon jeté à nouveau), `tmmsa_cle_perdue_refus` (phrase
    /// sans trace servie par `err_json`, clé perdue), `tmmsa_phrase_nominale` (aveu posé mais phrase nominale gardée).
    #[tokio::test]
    async fn tmmsa_refus_d_enrolement_sans_maillon_dit_le_trou() {
        let (st, _tmp) = sp_state("tmmsa-refus-panne");
        tmmsa_registre_hors_d_atteinte(&st);
        let ip = "10.61.0.1";
        let (statut, _, v) = tmmsa_enroler_faux(&st, ip).await;
        assert_eq!(statut, 403, "le refus tient, maillon ou pas : {v}");
        let error = v.get("error").and_then(|e| e.as_str()).unwrap_or_default();
        assert_ne!(error, CAUSE_MOT_DE_PASSE_REFUSE_A_L_ENROLEMENT, "la phrase qui affirme la trace n'est pas servie sans elle : {v}");
        assert!(!error.contains("et inscrit au registre"), "aucune phrase servie n'affirme une trace absente : {error}");
        assert_eq!(error, CAUSE_MOT_DE_PASSE_REFUSE_A_L_ENROLEMENT_SANS_TRACE, "la phrase du refus sans trace : {v}");
        let aveu = tmmsa_aveu(&v).unwrap_or_else(|| panic!("le refus sans trace porte `registre_sans_maillon` : {v}"));
        assert!(aveu.starts_with(CAUSE_REFUS_SANS_TRACE), "l'aveu d'un REFUS sans trace : {aveu}");
        assert!(aveu.ends_with(&format!(" ({CAUSE_MAILLON_NON_ECRIT})")) && !aveu.contains("registre hors d atteinte"), "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : l'aveu porte la phrase fixe du maillon non écrit, jamais le texte du moteur : {aveu}");
        assert!(!aveu.contains("'adm'"), "l'aveu ne recopie pas le détail du maillon (nom du compte) : {aveu}");
        assert_eq!(tmmsa_lignes_mfa_au_registre(&st), 0, "fixture : le maillon n'est pas entré");
        assert_eq!(tmmsa_mfa_de_adm(&st).0, 0, "aucune graine n'est posée");
        let echecs = st.auth_fails.lock().get(&("adm".to_string(), ip.to_string())).map_or(0, |f| f.count);
        assert_eq!(echecs, 1, "l'échec reste compté au verrou de la connexion");
    }

    /// CONTRÔLE NÉGATIF : registre sain, le refus d'enrôlement est OCTET POUR OCTET celui d'avant (la phrase nominale
    /// seule, par `err_json`) et la ligne `mfa` est posée.
    #[tokio::test]
    async fn tmmsa_refus_d_enrolement_nominal_octet_pour_octet() {
        let (st, _tmp) = sp_state("tmmsa-refus-sain");
        let (statut, octets, v) = tmmsa_enroler_faux(&st, "10.61.0.4").await;
        assert_eq!(statut, 403, "{v}");
        let attendu = serde_json::to_vec(&json!({ "error": CAUSE_MOT_DE_PASSE_REFUSE_A_L_ENROLEMENT })).unwrap();
        assert_eq!(octets, attendu, "corps nominal octet pour octet : {v}");
        assert_eq!(tmmsa_lignes_mfa_au_registre(&st), 1, "le refus est inscrit au registre");
    }

    /// CE QU'IL TIENT : registre hors d'atteinte, l'activation a lieu (la ligne passe à `enabled=1`) et n'est PAS
    /// annulée ; la réponse est 200, garde `ok` et les DIX `recovery_codes` clairs (servis une seule fois : les retirer
    /// les perdrait pour toujours) et gagne `registre_sans_maillon` (`CAUSE_GESTE_SANS_TRACE`). Aucune ligne `mfa`.
    ///
    /// MUTATIONS QUI LE FONT ROUGIR : `tmmsa_jeter_activation` (maillon jeté, aveu absent), `tmmsa_codes_perdus`
    /// (codes retirés du corps sous l'aveu).
    #[tokio::test]
    async fn tmmsa_activation_sans_maillon_reste_active_et_sert_ses_codes() {
        let (st, _tmp, graine) = tmmsa_etat_mfa("activation-panne", 0);
        tmmsa_registre_hors_d_atteinte(&st);
        let (statut, _, v) = tmmsa_activer(&st, &tmmsa_code(&graine)).await;
        assert_eq!(statut, 200, "le geste a eu lieu, il n'est pas refusé : {v}");
        assert_eq!(v.get("ok"), Some(&json!(true)), "{v}");
        let codes = v.get("recovery_codes").and_then(|c| c.as_array()).map_or(0, |a| a.len());
        assert_eq!(codes, 10, "les codes de secours clairs restent servis sous l'aveu : {v}");
        let aveu = tmmsa_aveu(&v).unwrap_or_else(|| panic!("l'activation sans trace porte `registre_sans_maillon` : {v}"));
        assert!(aveu.starts_with(CAUSE_GESTE_SANS_TRACE), "l'aveu d'un GESTE fait sans trace : {aveu}");
        assert!(aveu.ends_with(&format!(" ({CAUSE_MAILLON_NON_ECRIT})")) && !aveu.contains("registre hors d atteinte"), "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : l'aveu porte la phrase fixe du maillon non écrit, jamais le texte du moteur : {aveu}");
        assert!(!aveu.contains("'adm'"), "l'aveu ne recopie pas le détail du maillon : {aveu}");
        assert_eq!(tmmsa_mfa_de_adm(&st), (1, 1), "l'activation est écrite et n'est pas annulée");
        assert_eq!(tmmsa_lignes_mfa_au_registre(&st), 0, "fixture : le maillon n'est pas entré");
    }

    /// CONTRÔLE NÉGATIF : registre sain, le corps de l'activation n'a que `ok` et `recovery_codes`, OCTET POUR OCTET la
    /// forme d'avant, et la ligne `mfa` est posée.
    #[tokio::test]
    async fn tmmsa_activation_nominale_octet_pour_octet() {
        let (st, _tmp, graine) = tmmsa_etat_mfa("activation-sain", 0);
        let (statut, octets, v) = tmmsa_activer(&st, &tmmsa_code(&graine)).await;
        assert_eq!(statut, 200, "{v}");
        let attendu = serde_json::to_vec(&json!({ "ok": true, "recovery_codes": v["recovery_codes"].clone() })).unwrap();
        assert_eq!(octets, attendu, "corps nominal octet pour octet : {v}");
        assert!(tmmsa_aveu(&v).is_none(), "aucun aveu sur un maillon inscrit : {v}");
        assert_eq!(tmmsa_lignes_mfa_au_registre(&st), 1, "l'activation est inscrite au registre");
    }

    /// CE QU'IL TIENT : registre hors d'atteinte, la désactivation est validée (la ligne `user_mfa` a disparu) et
    /// n'est PAS annulée ; la réponse est 200, garde `ok` et gagne `registre_sans_maillon` (`CAUSE_GESTE_SANS_TRACE`).
    ///
    /// MUTATION QUI LE FAIT ROUGIR : `tmmsa_jeter_desactivation` (maillon jeté, aveu absent).
    #[tokio::test]
    async fn tmmsa_desactivation_sans_maillon_reste_faite_et_l_avoue() {
        let (st, _tmp, graine) = tmmsa_etat_mfa("desactivation-panne", 1);
        tmmsa_registre_hors_d_atteinte(&st);
        let (statut, _, v) = tmmsa_desactiver(&st, &tmmsa_code(&graine)).await;
        assert_eq!(statut, 200, "le geste a eu lieu, il n'est pas refusé : {v}");
        assert_eq!(v.get("ok"), Some(&json!(true)), "{v}");
        let aveu = tmmsa_aveu(&v).unwrap_or_else(|| panic!("la désactivation sans trace porte `registre_sans_maillon` : {v}"));
        assert!(aveu.starts_with(CAUSE_GESTE_SANS_TRACE), "l'aveu d'un GESTE fait sans trace : {aveu}");
        assert!(aveu.ends_with(&format!(" ({CAUSE_MAILLON_NON_ECRIT})")) && !aveu.contains("registre hors d atteinte"), "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : l'aveu porte la phrase fixe du maillon non écrit, jamais le texte du moteur : {aveu}");
        assert_eq!(tmmsa_mfa_de_adm(&st).0, 0, "la désactivation est validée et n'est pas annulée");
        assert_eq!(tmmsa_lignes_mfa_au_registre(&st), 0, "fixture : le maillon n'est pas entré");
    }

    /// CONTRÔLE NÉGATIF : registre sain, la désactivation rend `{"ok":true}` OCTET POUR OCTET et pose la ligne `mfa`.
    #[tokio::test]
    async fn tmmsa_desactivation_nominale_octet_pour_octet() {
        let (st, _tmp, graine) = tmmsa_etat_mfa("desactivation-sain", 1);
        let (statut, octets, v) = tmmsa_desactiver(&st, &tmmsa_code(&graine)).await;
        assert_eq!(statut, 200, "{v}");
        assert_eq!(octets, br#"{"ok":true}"#.to_vec(), "corps nominal octet pour octet : {v}");
        assert_eq!(tmmsa_lignes_mfa_au_registre(&st), 1, "la désactivation est inscrite au registre");
    }
}

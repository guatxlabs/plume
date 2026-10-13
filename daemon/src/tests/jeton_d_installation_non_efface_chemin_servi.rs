// =====================================================================================
// `P10.31-z` (volet démon) — LE JETON D'INSTALLATION RESTÉ EN CLAIR : `/api/setup` SERT SON CHEMIN.
//
// LE DÉFAUT, MESURÉ SUR 80ad700a AVANT LE CORRECTIF. Quand l'effacement du fichier de jeton échoue, `setup_post`
// (daemon/src/session.rs) nommait le chemin au journal et au registre, mais la réponse ne portait que
// `setup_token_file_removed: false` : la console ne pouvait pas dire QUEL fichier effacer — l'ATTENDU de la clé
// (« avoue le jeton non effacé avec son chemin à effacer ») était inatteignable depuis le navigateur seul.
//
// CE QUE CES TÉMOINS TIENNENT : chemin non supprimable (un répertoire non vide occupe le chemin, comme `O-5`
// d'onboarding.rs) -> 200, `setup_token_file_removed: false` ET `setup_token_file_left_at` = le chemin exact ;
// effacement réussi -> le fichier a disparu, `true`, et la clé neuve est ABSENTE (chemin nominal inchangé).
// CE QU'ILS NE TIENNENT PAS : ce que la console en fait (témoin 139 du harnais console) ; un volume en lecture seule
// (la panne est simulée par EISDIR, pas par EROFS).
// =====================================================================================
mod jeton_d_installation_non_efface_chemin_servi {
    use super::*;

    /// Le corps JSON d'une réponse HTTP/1.1 lue à la main : `onb_post` rend le corps TEL QUE TRANSMIS, découpage
    /// `chunked` compris (taille hexadécimale avant, `0` après) — on prend de la première accolade à la dernière.
    fn jdi_corps_json(body: &str) -> Value {
        let json = match (body.find('{'), body.rfind('}')) {
            (Some(d), Some(f)) if f > d => &body[d..=f],
            _ => body,
        };
        serde_json::from_str(json).unwrap_or_else(|e| panic!("corps JSON illisible ({e}) : {body}"))
    }

    #[tokio::test]
    async fn jdi_le_chemin_du_jeton_non_efface_est_servi() {
        let (st, dbp) = onb_state("jdi-residu");
        let tokfile = onb_token_path(&dbp);
        std::fs::create_dir_all(tokfile.join("occupe")).unwrap(); // chemin NON supprimable (EISDIR)
        let addr = router_serve(st).await;
        let (code, body) = onb_post(addr, "/api/setup", &format!(
            r#"{{"token":"{ONB_TOKEN}","user":"root","password":"motdepasse-tres-long"}}"#
        )).await;
        assert_eq!(code, 200, "l'administrateur est posé -> 200 (corps : {body})");
        assert!(tokfile.exists(), "fixture : le chemin du jeton est resté (sinon on ne mesure rien)");
        let v = jdi_corps_json(&body);
        assert_eq!(v.get("setup_token_file_removed"), Some(&json!(false)), "le jeton non effacé reste dit : {v}");
        assert_eq!(v.get(CLE_DU_CHEMIN_DU_JETON_NON_EFFACE), Some(&json!(tokfile.display().to_string())),
            "la réponse doit nommer le fichier À EFFACER, le chemin exact que le journal nomme : {v}");
        let _ = std::fs::remove_dir_all(&tokfile);
        ff_rm(&dbp);
    }

    #[tokio::test]
    async fn jdi_effacement_reussi_aucun_chemin_servi() {
        let (st, dbp) = onb_state("jdi-nominal");
        let tokfile = onb_token_path(&dbp);
        std::fs::write(&tokfile, ONB_TOKEN).unwrap();
        let addr = router_serve(st).await;
        let (code, body) = onb_post(addr, "/api/setup", &format!(
            r#"{{"token":"{ONB_TOKEN}","user":"root","password":"motdepasse-tres-long"}}"#
        )).await;
        assert_eq!(code, 200, "l'administrateur est posé -> 200 (corps : {body})");
        assert!(!tokfile.exists(), "fixture : le fichier de jeton a bien été effacé");
        let v = jdi_corps_json(&body);
        assert_eq!(v.get("setup_token_file_removed"), Some(&json!(true)), "effacement réussi -> true : {v}");
        assert!(v.get(CLE_DU_CHEMIN_DU_JETON_NON_EFFACE).is_none(),
            "effacement réussi -> AUCUN chemin servi : le corps nominal reste celui d'avant : {v}");
        ff_rm(&dbp);
    }
}

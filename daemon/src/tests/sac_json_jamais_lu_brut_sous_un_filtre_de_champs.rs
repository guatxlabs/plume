// =====================================================================================
// SOUS UN FILTRE DE CHAMPS, LE SAC JSON `fields` N'EST JAMAIS LU BRUT PAR LA ROUTE DE REQUETE.
//
// Le correctif vit dans le coeur (`guatx-core`, epingle par daemon/Cargo.toml) : des que le jeu de masques de
// l'appelant n'est pas vide, le compilateur retire du sac tous les noms masques partout ou il le lit, refuse un
// predicat de base sur le sac et une jointure dont la cle est le sac. Ces temoins le tiennent COTE PLUME, par la
// route `POST /api/query` (corps `{"soql": ...}`), routeur reel (`router_serve`), avec une regle ecrite dans la table
// `field_filter` et le registre recharge comme le demarrage du serveur (`field_filters_reload`), pour le lecteur
// (`vwr`) que la regle masque :
//   (A) le sac porte une cle masquee qui n'est pas une colonne (`jeton`) : `search fields=~...`, un joker, `in` et une
//       jointure dont la cle est le sac sont refuses, statut et corps entiers ; `| stats count by fields` ne distingue
//       pas deux evenements qui ne different que par la valeur masquee ; ni ce regroupement, ni `search` nu, ni
//       `| table fields` ne servent la valeur ;
//   (B) colonne reelle masquee (`src_ip`) et sac qui porte une cle du meme nom avec la meme valeur : la valeur
//       n'apparait dans aucun corps servi (`search` nu, `| table fields`, regroupement par le sac), et un predicat de
//       base sur le sac est refuse ;
//   (C) le cout ne vise que l'appelant masque : le meme lecteur sur une base sans regle, et l'administrateur que la
//       regle ne vise pas, recoivent les memes requetes servies, valeur comprise (controle positif de (A) et (B)).
// Chaque requete est bornee a la source semee (`source=k2a` / `source=k2b`) : le demon ecrit lui-meme des evenements
// (connexion, audit) dans la table `event`, ils ne doivent pas entrer dans les comptes.
// =====================================================================================
mod k2_sac_json_jamais_lu_brut_sous_un_filtre_de_champs {
    use super::*;

    /// Mot de passe de l'administrateur pose par `router_test_state` (constante nommee, jamais un litteral passe tel quel).
    const K2_MOT_DE_PASSE_ADMIN: &str = "rootpw1234567";
    /// Valeurs de la cle masquee `jeton` (cas A) : les deux evenements ne different que par elle.
    const K2_VALEUR_ALPHA: &str = "valeur-masquee-alpha";
    const K2_VALEUR_BETA: &str = "valeur-masquee-beta";
    /// Adresse portee par la colonne `src_ip` ET par la cle `src_ip` du sac (cas B), RFC 5737.
    const K2_ADRESSE: &str = "198.51.100.23";

    const K2_REFUS_PREDICAT_SUR_LE_SAC: &str = "filtrage interdit sur le sac \u{ab} fields \u{bb} : un masque de champ est actif et le sac peut porter une valeur masqu\u{e9}e (field-filter actif pour votre r\u{f4}le : un champ que vous ne pouvez pas voir ne peut pas \u{ea}tre filtr\u{e9}, m\u{ea}me \u{e0} travers le sac ; filtrer par nom de cl\u{e9})";
    const K2_REFUS_JOINTURE_SUR_LE_SAC: &str = "join : la cl\u{e9} \u{ab} fields \u{bb} est le sac JSON ; un masque de champ est actif et le sac peut porter une valeur masqu\u{e9}e (field-filter actif pour votre r\u{f4}le : une jointure sur le sac lirait cette valeur)";

    struct K2Banc {
        addr: std::net::SocketAddr,
        base: crate::tmp_possede::TmpDb,
        _st: AppState,
    }
    impl Drop for K2Banc {
        fn drop(&mut self) {
            crate::field_filter::field_filters_forget(self.base.as_str());
        }
    }

    fn k2_admin_authz() -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("root:{K2_MOT_DE_PASSE_ADMIN}")))
    }

    /// Base de routeur semee (cas A : deux evenements `k2a` qui ne different que par `jeton` ; cas B : un evenement
    /// `k2b` dont la colonne `src_ip` et la cle `src_ip` du sac portent la meme adresse), regles de filtre de champs
    /// `regles` (champ, action) ecrites dans `field_filter`, registre recharge comme au demarrage du serveur.
    async fn k2_banc(tag: &str, regles: &[(&str, &str)]) -> K2Banc {
        let (st, base) = router_test_state(tag);
        {
            let w = open_db(base.as_str()).unwrap();
            let ts = now() - 60;
            for (i, valeur) in [K2_VALEUR_ALPHA, K2_VALEUR_BETA].iter().enumerate() {
                let sac = json!({ "jeton": valeur, "act": "connexion" }).to_string();
                w.execute(
                    "INSERT INTO event(ts,source,host,fields,dedup) VALUES(?1,'k2a','hote-k2',?2,?3)",
                    params![ts, sac, format!("k2a-{i}")],
                )
                .unwrap();
            }
            let sac = json!({ "src_ip": K2_ADRESSE, "act": "connexion" }).to_string();
            w.execute(
                "INSERT INTO event(ts,source,host,src_ip,fields,dedup) VALUES(?1,'k2b','hote-k2',?2,?3,'k2b-0')",
                params![ts, K2_ADRESSE, sac],
            )
            .unwrap();
            for (i, (champ, action)) in regles.iter().enumerate() {
                w.execute(
                    "INSERT INTO field_filter(name,field,action,role) VALUES(?1,?2,?3,'')",
                    params![format!("k2-{i}"), champ, action],
                )
                .unwrap();
            }
            field_filters_reload(&w, base.as_str());
            assert_eq!(
                crate::field_filter::registre_porte_une_regle(base.as_str()),
                !regles.is_empty(),
                "controle : registre charge avec les regles ecrites"
            );
        }
        let addr = router_serve(st.clone()).await;
        K2Banc { addr, base, _st: st }
    }

    struct K2Servi {
        code: u16,
        /// Corps HTTP decode (chunked compris), tel que servi.
        texte: String,
        corps: Value,
    }
    impl K2Servi {
        fn colonne(&self, nom: &str) -> usize {
            self.corps["columns"]
                .as_array()
                .and_then(|c| c.iter().position(|x| x.as_str() == Some(nom)))
                .unwrap_or_else(|| panic!("colonne {nom} absente : {}", self.texte))
        }
        fn lignes(&self) -> Vec<Vec<Value>> {
            self.corps["rows"]
                .as_array()
                .unwrap_or_else(|| panic!("rows attendu : {}", self.texte))
                .iter()
                .map(|r| r.as_array().cloned().unwrap_or_else(|| panic!("ligne tableau attendue : {}", self.texte)))
                .collect()
        }
        /// Les valeurs de la colonne `nom`, rendues en texte.
        fn valeurs(&self, nom: &str) -> Vec<String> {
            let i = self.colonne(nom);
            self.lignes().iter().map(|l| l[i].as_str().map(str::to_string).unwrap_or_else(|| l[i].to_string())).collect()
        }
    }

    async fn k2_requete(banc: &K2Banc, authz: &str, soql: &str) -> K2Servi {
        let maintenant = now();
        let corps = json!({ "soql": soql, "from": maintenant - 3600, "to": maintenant + 3600 }).to_string();
        let entetes = [("Content-Type", "application/json")];
        let (code, brut) = router_probe_envoi(banc.addr, "POST", "/api/query", Some(authz), &entetes, &corps).await;
        let (tete, c) = brut.split_once("\r\n\r\n").unwrap_or_else(|| panic!("reponse HTTP entiere pour {soql} : {brut}"));
        let texte = if tete.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            String::from_utf8(shell_decouper(c.as_bytes()).unwrap_or_else(|| panic!("trame chunked pour {soql}"))).expect("corps UTF-8")
        } else {
            c.to_string()
        };
        let corps = serde_json::from_str(&texte).unwrap_or(Value::Null);
        K2Servi { code, texte, corps }
    }

    /// Refus attendu : 400, corps entier `{"error": phrase}`.
    fn k2_juger_refus(s: &K2Servi, phrase: &str, quoi: &str) {
        assert_eq!(s.code, 400, "{quoi} : statut : {}", s.texte);
        assert_eq!(s.corps, json!({ "error": phrase }), "{quoi} : corps entier");
    }

    fn k2_juger_servi_sans(s: &K2Servi, valeurs: &[&str], quoi: &str) {
        assert_eq!(s.code, 200, "{quoi} : servi : {}", s.texte);
        for v in valeurs {
            assert!(!s.texte.contains(v), "{quoi} : la valeur masquee {v} est servie : {}", s.texte);
        }
    }

    fn k2_juger_servi_avec(s: &K2Servi, valeurs: &[&str], quoi: &str) {
        assert_eq!(s.code, 200, "{quoi} : servi : {}", s.texte);
        for v in valeurs {
            assert!(s.texte.contains(v), "{quoi} : la valeur {v} doit etre servie a qui n'est pas masque : {}", s.texte);
        }
    }

    // ------------------------------------------------------------------------------------------------------- (A)

    #[tokio::test]
    async fn k2_a_predicat_de_base_sur_le_sac_refuse_au_lecteur_masque() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let banc = k2_banc("k2-a-predicat", &[("jeton", "mask")]).await;
        let lecteur = viewer_authz();
        let requetes = [
            ("regex", format!("search source=k2a fields=~\"{K2_VALEUR_ALPHA}\"")),
            ("joker", "search source=k2a fields=*alpha*".to_string()),
            ("in", format!("search source=k2a fields in (\"{K2_VALEUR_ALPHA}\", \"{K2_VALEUR_BETA}\")")),
        ];
        // Chaque forme est jugee, et toutes celles qui ne sont pas refusees sont nommees ensemble.
        let mut servies = Vec::new();
        for (quoi, soql) in &requetes {
            let s = k2_requete(&banc, &lecteur, soql).await;
            if s.code != 400 || s.corps != json!({ "error": K2_REFUS_PREDICAT_SUR_LE_SAC }) {
                servies.push(format!("{quoi} -> {} {}", s.code, s.texte));
            }
        }
        assert!(servies.is_empty(), "predicats sur le sac non refuses (400, corps entier attendu) : {servies:#?}");
    }

    #[tokio::test]
    async fn k2_a_jointure_sur_le_sac_refusee_au_lecteur_masque() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let banc = k2_banc("k2-a-jointure", &[("jeton", "mask")]).await;
        let s = k2_requete(&banc, &viewer_authz(), "search source=k2a | join fields [search source=k2a]").await;
        k2_juger_refus(&s, K2_REFUS_JOINTURE_SUR_LE_SAC, "join fields");
    }

    #[tokio::test]
    async fn k2_a_regroupement_par_le_sac_ne_distingue_pas_la_valeur_masquee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let banc = k2_banc("k2-a-groupe", &[("jeton", "mask")]).await;
        let s = k2_requete(&banc, &viewer_authz(), "search source=k2a | stats count by fields").await;
        k2_juger_servi_sans(&s, &[K2_VALEUR_ALPHA, K2_VALEUR_BETA], "stats count by fields");
        let lignes = s.lignes();
        assert_eq!(lignes.len(), 1, "un seul groupe : les deux evenements ne different que par la valeur masquee : {}", s.texte);
        let i = s.colonne("count");
        assert_eq!(lignes[0][i], json!(2), "le groupe compte les deux evenements : {}", s.texte);
    }

    #[tokio::test]
    async fn k2_a_sac_servi_sans_la_valeur_masquee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let banc = k2_banc("k2-a-sac", &[("jeton", "mask")]).await;
        let lecteur = viewer_authz();
        for soql in ["search source=k2a", "search source=k2a | table fields"] {
            let s = k2_requete(&banc, &lecteur, soql).await;
            k2_juger_servi_sans(&s, &[K2_VALEUR_ALPHA, K2_VALEUR_BETA], soql);
            let sacs = s.valeurs("fields");
            assert_eq!(sacs.len(), 2, "{soql} : les deux evenements sont servis : {}", s.texte);
            for sac in &sacs {
                assert_eq!(serde_json::from_str::<Value>(sac).ok(), Some(json!({ "act": "connexion" })), "{soql} : sac sans la cle masquee");
            }
        }
    }

    // ------------------------------------------------------------------------------------------------------- (B)

    #[tokio::test]
    async fn k2_b_colonne_reelle_masquee_absente_du_sac_servi() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let banc = k2_banc("k2-b-sac", &[("src_ip", "mask")]).await;
        let lecteur = viewer_authz();
        // Chaque requete est jugee, et toutes celles qui servent l'adresse sont nommees ensemble.
        let mut fuites = Vec::new();
        for soql in ["search source=k2b", "search source=k2b | table fields", "search source=k2b | stats count by fields"] {
            let s = k2_requete(&banc, &lecteur, soql).await;
            assert_eq!(s.code, 200, "{soql} : servi : {}", s.texte);
            let sacs = s.valeurs("fields");
            assert_eq!(sacs.len(), 1, "{soql} : l'evenement est servi : {}", s.texte);
            if s.texte.contains(K2_ADRESSE) || serde_json::from_str::<Value>(&sacs[0]).ok() != Some(json!({ "act": "connexion" })) {
                fuites.push(format!("{soql} -> {}", s.texte));
            }
        }
        assert!(fuites.is_empty(), "l'adresse masquee est servie par le sac : {fuites:#?}");
    }

    #[tokio::test]
    async fn k2_b_predicat_de_base_sur_le_sac_refuse_sous_une_colonne_masquee() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let banc = k2_banc("k2-b-predicat", &[("src_ip", "mask")]).await;
        let s = k2_requete(&banc, &viewer_authz(), &format!("search source=k2b fields=~\"{K2_ADRESSE}\"")).await;
        k2_juger_refus(&s, K2_REFUS_PREDICAT_SUR_LE_SAC, "regex sur le sac");
    }

    // ------------------------------------------------------------------------------------------------------- (C)

    /// Les requetes de (A) et (B), servies comme avant a qui n'est pas masque : predicats et jointure servis, le
    /// regroupement distingue les deux evenements, et chaque valeur est servie.
    async fn k2_juger_non_masque(banc: &K2Banc, authz: &str, qui: &str) {
        let regex = k2_requete(banc, authz, &format!("search source=k2a fields=~\"{K2_VALEUR_ALPHA}\"")).await;
        k2_juger_servi_avec(&regex, &[K2_VALEUR_ALPHA], &format!("{qui} : regex"));
        assert_eq!(regex.lignes().len(), 1, "{qui} : regex : le seul evenement alpha : {}", regex.texte);
        let joker = k2_requete(banc, authz, "search source=k2a fields=*alpha*").await;
        k2_juger_servi_avec(&joker, &[K2_VALEUR_ALPHA], &format!("{qui} : joker"));
        assert_eq!(joker.lignes().len(), 1, "{qui} : joker : {}", joker.texte);
        let dans = k2_requete(banc, authz, &format!("search source=k2a fields in (\"{K2_VALEUR_ALPHA}\", \"{K2_VALEUR_BETA}\")")).await;
        assert_eq!(dans.code, 200, "{qui} : in : {}", dans.texte);
        let jointure = k2_requete(banc, authz, "search source=k2a | join fields [search source=k2a]").await;
        k2_juger_servi_avec(&jointure, &[K2_VALEUR_ALPHA, K2_VALEUR_BETA], &format!("{qui} : join fields"));
        let groupe = k2_requete(banc, authz, "search source=k2a | stats count by fields").await;
        k2_juger_servi_avec(&groupe, &[K2_VALEUR_ALPHA, K2_VALEUR_BETA], &format!("{qui} : stats count by fields"));
        assert_eq!(groupe.lignes().len(), 2, "{qui} : deux groupes : {}", groupe.texte);
        for soql in ["search source=k2a", "search source=k2a | table fields"] {
            let s = k2_requete(banc, authz, soql).await;
            k2_juger_servi_avec(&s, &[K2_VALEUR_ALPHA, K2_VALEUR_BETA], &format!("{qui} : {soql}"));
        }
        for soql in ["search source=k2b", "search source=k2b | table fields", "search source=k2b | stats count by fields"] {
            let s = k2_requete(banc, authz, soql).await;
            k2_juger_servi_avec(&s, &[K2_ADRESSE], &format!("{qui} : {soql}"));
        }
        let predicat_b = k2_requete(banc, authz, &format!("search source=k2b fields=~\"{K2_ADRESSE}\"")).await;
        k2_juger_servi_avec(&predicat_b, &[K2_ADRESSE], &format!("{qui} : regex sur le sac (B)"));
        assert_eq!(predicat_b.lignes().len(), 1, "{qui} : regex sur le sac (B) : {}", predicat_b.texte);
    }

    #[tokio::test]
    async fn k2_c_lecteur_sans_regle_servi_comme_avant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let banc = k2_banc("k2-c-lecteur", &[]).await;
        k2_juger_non_masque(&banc, &viewer_authz(), "lecteur sans regle").await;
    }

    #[tokio::test]
    async fn k2_c_administrateur_non_vise_servi_comme_avant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let banc = k2_banc("k2-c-admin", &[("jeton", "mask"), ("src_ip", "mask")]).await;
        k2_juger_non_masque(&banc, &k2_admin_authz(), "administrateur").await;
    }
}

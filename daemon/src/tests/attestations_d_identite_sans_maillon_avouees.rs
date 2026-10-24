// =====================================================================================
// `P10.31-u` (première tranche : `session.rs`, `secret_des_gestes.rs`) — LES GESTES D'IDENTITÉ QUI S'INSCRIVENT AU
// REGISTRE AVOUENT UN MAILLON MANQUANT.
//
// LE DÉFAUT, MESURÉ SUR 824949d AVANT LE CORRECTIF. Quatre sites jetaient l'issue de `ledger_append` (appel nu ou
// `let _`) : l'installation du premier administrateur (`setup_post`), le changement du mot de passe de
// l'administrateur de l'assistant (`password_post`, voie sans ligne), le refus du mot de passe actuel
// (`juger_le_mot_de_passe_actuel`, partagé par `/api/password` et `/api/users/{id}`) et le secret des gestes faux
// (`exiger_le_secret_des_gestes`). La primitive avouait la perte sur la sortie d'erreur ; la réponse n'en disait rien.
//
// CE QUE L'ÉNONCÉ DU LOT AVAIT DE FAUX. Il demandait, pour les deux REFUS, de laisser la réponse « celle d'avant » et
// de s'en remettre à l'aveu de la primitive. Or les deux phrases de refus AFFIRMENT la trace :
// `CAUSE_MOT_DE_PASSE_ACTUEL_REFUSE` (« … et inscrit au registre ») et `TEXTE_SECRET_DES_GESTES_FAUX` (« … et inscrit
// au registre sous votre nom »). Se taire servait donc un fait faux. Les quatre sites avouent dans la réponse, sous la
// clé commune `registre_sans_maillon` : `CAUSE_GESTE_SANS_TRACE` à côté d'un succès (le geste a eu lieu, il n'est pas
// annulé), `CAUSE_REFUS_SANS_TRACE` (neuve) à côté d'un refus. Et un refus dont le maillon manque ne sert PLUS sa
// phrase nominale : `error` devient `CAUSE_MOT_DE_PASSE_ACTUEL_REFUSE_SANS_TRACE` / `TEXTE_SECRET_DES_GESTES_FAUX_SANS_TRACE`
// (statut et clé stable `cause` inchangés) — la console affiche `error`, pas l'aveu.
//
// LA PANNE ÉPROUVÉE : un déclencheur `BEFORE INSERT ON ledger` qui lève `RAISE(ABORT)`. La LECTURE du registre passe
// (le hachage précédent se lit), seule l'écriture du maillon tombe — la voie que `P10.20-v` a ouverte. Aucune
// écriture des gestes eux-mêmes ne touche `ledger` (vérifié : `poser_l_administrateur` n'y écrit pas).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les quelque cinquante-cinq autres appels nus de `ledger_append` (actions.rs,
// cases.rs, caseops.rs, idp.rs…), les deux `match netban_remove` des levées, l'absence de garde qui interdise un appel
// nu ; la console ne lit pas `registre_sans_maillon` sur ces routes (elle affiche la phrase `error`, qui dit le trou) ;
// le témoin `110` du harnais console ne rejoue que la phrase nominale du refus ; la sortie d'erreur de la primitive
// n'est pas capturée ici (elle porte le seul genre, `P10.20-v`).
// =====================================================================================
mod attestations_d_identite_sans_maillon_avouees {
    use super::*;
    use crate::secret_des_gestes::{
        exiger_le_secret_des_gestes, SecretDesGestesPresente, SourceDuSecretDesGestes, CAUSE_SECRET_DES_GESTES_FAUX,
        TEXTE_SECRET_DES_GESTES_FAUX, TEXTE_SECRET_DES_GESTES_FAUX_SANS_TRACE,
    };

    /// LA PHRASE SERVIE N'AFFIRME PAS UNE TRACE ABSENTE : ni la phrase nominale, ni sa promesse « et inscrit au registre ».
    fn aisa_phrase_sans_promesse_de_trace(v: &Value, nominale: &str, attendue: &str) {
        let error = v.get("error").and_then(|e| e.as_str()).unwrap_or_default();
        assert_ne!(error, nominale, "le refus dont le maillon manque NE sert PAS la phrase qui affirme la trace : {v}");
        assert!(!error.contains("et inscrit au registre"), "aucune phrase servie n'affirme une trace absente : {error}");
        assert!(error.contains("N'A PAS été inscrit au registre"), "la phrase servie DIT le trou : {error}");
        assert_eq!(error, attendue, "la phrase du refus sans trace : {v}");
    }

    const AISA_TOKEN: &str = "fedcba9876543210fedcba9876543210fedc";
    const AISA_ADMIN: &str = "racine-aisa";
    const AISA_ANCIEN: &str = "ancien-mot-de-passe-aisa-0123";

    /// Base complète sur fichier, MODE INSTALLATION (aucun administrateur, aucun mot de passe de configuration).
    fn aisa_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("aisa-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.31-u` : la chaîne de migrations doit aller au bout");
        }
        let mut st = ds_file_state(&chemin);
        st.user = Arc::new(String::new());
        st.pass_hash = Arc::new(String::new());
        *st.admin.lock() = None;
        st.setup_token = Arc::new(AISA_TOKEN.to_string());
        st.secret_des_gestes = Arc::new(SourceDuSecretDesGestes::Empreinte(crate::secret_des_gestes::empreinte_de_test()));
        (st, chemin)
    }

    /// L'administrateur de l'assistant SANS ligne `user` : la voie `DeLAssistant` de `/api/password`.
    fn aisa_etat_assistant(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, chemin) = aisa_etat(tag);
        *st.admin.lock() = Some((AISA_ADMIN.to_string(), hash_pw(AISA_ANCIEN).expect("hachage")));
        (st, chemin)
    }

    /// LA PANNE : le maillon ne s'écrit plus, le registre se lit toujours.
    fn aisa_registre_hors_d_atteinte(st: &AppState) {
        st.db
            .lock()
            .execute_batch(
                "CREATE TRIGGER aisa_ledger_refuse BEFORE INSERT ON ledger \
                 BEGIN SELECT RAISE(ABORT, 'registre hors d atteinte (temoin P10.31-u)'); END;",
            )
            .expect("fixture : le déclencheur se pose");
    }

    fn aisa_lignes(st: &AppState, genre: &str) -> i64 {
        st.db
            .lock()
            .query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![genre], |r| r.get(0))
            .expect("fixture : le registre se lit")
    }

    fn aisa_au(nom: &str) -> AuthUser {
        AuthUser {
            name: nom.into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "session".into(), csrf: String::new(), env: None,
        }
    }

    fn aisa_pair(ip: &str) -> std::net::SocketAddr {
        format!("{ip}:46464").parse().expect("adresse de test")
    }

    /// Statut, octets bruts du corps, et sa lecture JSON.
    async fn aisa_reponse(r: Response) -> (u16, Vec<u8>, Value) {
        let statut = r.status().as_u16();
        let octets = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible").to_vec();
        let v = serde_json::from_slice(&octets).unwrap_or(Value::Null);
        (statut, octets, v)
    }

    fn aisa_aveu(v: &Value) -> Option<String> {
        v.get(CLE_REGISTRE_SANS_MAILLON).and_then(|x| x.as_str()).map(str::to_string)
    }

    async fn aisa_installer(st: &AppState) -> (u16, Vec<u8>, Value) {
        let corps = json!({ "token": AISA_TOKEN, "user": AISA_ADMIN, "password": "mot-de-passe-installation-aisa" });
        aisa_reponse(setup_post(State(st.clone()), ConnectInfo(aisa_pair("192.0.2.10")), Json(corps)).await).await
    }

    async fn aisa_changer(st: &AppState, ip: &str, actuel: &str, neuf: &str) -> (u16, Vec<u8>, Value) {
        let corps = json!({ "current": actuel, "new": neuf });
        aisa_reponse(password_post(State(st.clone()), ConnectInfo(aisa_pair(ip)), Extension(aisa_au(AISA_ADMIN)), Json(corps)).await).await
    }

    fn aisa_secret_faux(st: &AppState) -> Response {
        let presente = SecretDesGestesPresente { valeur: Some("pas-le-bon-secret-aisa".into()), ip: "192.0.2.40".into() };
        exiger_le_secret_des_gestes(st, &presente, "auteur-aisa", "création d'un compte").expect_err("un secret faux est refusé")
    }

    /// CE QU'IL TIENT : registre hors d'atteinte, `/api/setup` rend 200 — l'installation a eu lieu et n'est PAS annulée
    /// (administrateur en mémoire et en base) —, garde `ok` et `setup_token_file_removed`, et gagne l'aveu
    /// `CAUSE_GESTE_SANS_TRACE` sans le nom du compte ; aucune ligne `setup`. Contrôle nominal : sur un registre sain le
    /// corps est OCTET POUR OCTET celui d'avant et la ligne `setup` est posée.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : jeter le maillon de `setup_post` (appel nu) — l'aveu disparaît.
    #[tokio::test]
    async fn aisa_installation_sans_maillon_reste_faite_et_l_avoue() {
        let (st, _tmp) = aisa_etat("setup-panne");
        aisa_registre_hors_d_atteinte(&st);
        let (statut, _, v) = aisa_installer(&st).await;
        assert_eq!(statut, 200, "l'installation a eu lieu : elle n'est pas refusée après coup : {v}");
        assert_eq!(v.get("ok"), Some(&json!(true)), "le succès garde ses champs : {v}");
        assert_eq!(v.get("setup_token_file_removed"), Some(&json!(true)), "le champ du jeton reste servi : {v}");
        let aveu = aisa_aveu(&v).unwrap_or_else(|| panic!("le maillon manquant est AVOUÉ dans la réponse : {v}"));
        assert!(aveu.starts_with(CAUSE_GESTE_SANS_TRACE), "l'aveu est celui d'un geste fait sans trace : {aveu}");
        assert!(aveu.ends_with(&format!(" ({CAUSE_MAILLON_NON_ECRIT})")) && !aveu.contains("registre hors d atteinte"), "INVERSÉ NOMMÉMENT par P10.29-l (vague AM) : l'aveu porte la phrase fixe du maillon non écrit, jamais le texte du moteur : {aveu}");
        assert!(!aveu.contains(AISA_ADMIN), "l'aveu ne porte jamais le détail du maillon (le nom du compte) : {aveu}");
        assert_eq!(st.admin.lock().as_ref().map(|(n, _)| n.clone()).as_deref(), Some(AISA_ADMIN), "geste NON annulé");
        let en_base: i64 =
            st.db.lock().query_row("SELECT COUNT(*) FROM user WHERE name=?1", params![AISA_ADMIN], |r| r.get(0)).unwrap();
        assert_eq!(en_base, 1, "le compte administrateur est écrit");
        assert_eq!(aisa_lignes(&st, "setup"), 0, "fixture : le maillon n'est bien pas entré");

        let (st, _tmp2) = aisa_etat("setup-sain");
        let (statut, octets, v) = aisa_installer(&st).await;
        assert_eq!(statut, 200);
        assert_eq!(
            octets,
            serde_json::to_vec(&json!({ "ok": true, "setup_token_file_removed": true })).unwrap(),
            "registre sain : corps octet pour octet celui d'avant : {v}"
        );
        assert_eq!(aisa_lignes(&st, "setup"), 1, "registre sain : la ligne `setup` est posée");
    }

    /// CE QU'IL TIENT : registre hors d'atteinte, l'administrateur de l'assistant (sans ligne) change son mot de passe :
    /// 200, le nouveau vaut et l'ancien non (geste NON annulé), `ok` et `user` gardés, aveu `CAUSE_GESTE_SANS_TRACE` ;
    /// aucune ligne `password`. Contrôle nominal : corps octet pour octet `{"ok":true,"user":…}`, une ligne posée.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : jeter le maillon de la voie `DeLAssistant` de `password_post`.
    #[tokio::test]
    async fn aisa_mot_de_passe_de_l_assistant_change_sans_maillon_l_avoue() {
        let neuf = "nouveau-mot-de-passe-aisa-4567";
        let (st, _tmp) = aisa_etat_assistant("assistant-panne");
        aisa_registre_hors_d_atteinte(&st);
        let (statut, _, v) = aisa_changer(&st, "192.0.2.20", AISA_ANCIEN, neuf).await;
        assert_eq!(statut, 200, "le mot de passe est changé : {v}");
        assert_eq!(v.get("ok"), Some(&json!(true)), "{v}");
        assert_eq!(v.get("user"), Some(&json!(AISA_ADMIN)), "{v}");
        let aveu = aisa_aveu(&v).unwrap_or_else(|| panic!("le maillon manquant est AVOUÉ dans la réponse : {v}"));
        assert!(aveu.starts_with(CAUSE_GESTE_SANS_TRACE), "{aveu}");
        let h = st.admin.lock().as_ref().map(|(_, h)| h.clone()).expect("administrateur en mémoire");
        assert!(verify_pw(neuf, &h) && !verify_pw(AISA_ANCIEN, &h), "geste NON annulé : le nouveau mot de passe vaut");
        assert_eq!(aisa_lignes(&st, "password"), 0, "fixture : le maillon n'est bien pas entré");

        let (st, _tmp2) = aisa_etat_assistant("assistant-sain");
        let (statut, octets, v) = aisa_changer(&st, "192.0.2.21", AISA_ANCIEN, neuf).await;
        assert_eq!(statut, 200, "{v}");
        assert_eq!(octets, serde_json::to_vec(&json!({ "ok": true, "user": AISA_ADMIN })).unwrap(), "nominal octet pour octet");
        assert_eq!(aisa_lignes(&st, "password"), 1, "registre sain : la ligne est posée");
    }

    /// CE QU'IL TIENT : registre hors d'atteinte, mot de passe actuel FAUX : 403, la phrase servie n'est PAS
    /// `CAUSE_MOT_DE_PASSE_ACTUEL_REFUSE` (qui annonce « inscrit au registre ») mais
    /// `CAUSE_MOT_DE_PASSE_ACTUEL_REFUSE_SANS_TRACE`, plus l'aveu `CAUSE_REFUS_SANS_TRACE`, sans le nom du compte ; rien
    /// n'est changé. Contrôle nominal : corps octet pour octet `{"error": CAUSE_MOT_DE_PASSE_ACTUEL_REFUSE}`, une ligne.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : jeter le maillon dans `juger_le_mot_de_passe_actuel` (forme d'avant) ; servir
    /// la phrase nominale dans `refus_du_mot_de_passe_actuel_sans_trace`.
    #[tokio::test]
    async fn aisa_refus_du_mot_de_passe_actuel_sans_maillon_ne_sert_pas_sa_trace() {
        let (st, _tmp) = aisa_etat_assistant("refus-panne");
        aisa_registre_hors_d_atteinte(&st);
        let (statut, _, v) = aisa_changer(&st, "192.0.2.30", "pas-le-bon-mot-de-passe-aisa", "neuf-mot-de-passe-aisa-99").await;
        assert_eq!(statut, 403, "le refus tient : {v}");
        aisa_phrase_sans_promesse_de_trace(&v, CAUSE_MOT_DE_PASSE_ACTUEL_REFUSE, CAUSE_MOT_DE_PASSE_ACTUEL_REFUSE_SANS_TRACE);
        let aveu = aisa_aveu(&v).unwrap_or_else(|| panic!("la trace annoncée manque : le refus le DIT : {v}"));
        assert!(aveu.starts_with(CAUSE_REFUS_SANS_TRACE), "l'aveu est celui d'un REFUS, pas d'un geste fait : {aveu}");
        assert!(!aveu.contains(AISA_ADMIN), "l'aveu ne porte jamais le détail du maillon : {aveu}");
        let h = st.admin.lock().as_ref().map(|(_, h)| h.clone()).expect("administrateur en mémoire");
        assert!(verify_pw(AISA_ANCIEN, &h), "rien n'est changé sur un refus");

        let (st, _tmp2) = aisa_etat_assistant("refus-sain");
        let (statut, octets, v) = aisa_changer(&st, "192.0.2.31", "pas-le-bon-mot-de-passe-aisa", "neuf-mot-de-passe-aisa-99").await;
        assert_eq!(statut, 403, "{v}");
        assert_eq!(
            octets,
            serde_json::to_vec(&json!({ "error": CAUSE_MOT_DE_PASSE_ACTUEL_REFUSE })).unwrap(),
            "nominal octet pour octet"
        );
        assert_eq!(aisa_lignes(&st, "password"), 1, "registre sain : le refus est inscrit");
    }

    /// CE QU'IL TIENT : registre hors d'atteinte, secret des gestes FAUX : 403, `cause` inchangée, `error` =
    /// `TEXTE_SECRET_DES_GESTES_FAUX_SANS_TRACE` (et non la phrase nominale « inscrit au registre sous votre nom »), aveu
    /// `CAUSE_REFUS_SANS_TRACE` sans le nom de l'auteur ni l'adresse. Contrôle nominal : corps octet pour octet
    /// `{"cause": …, "error": …}`, une ligne `secret_des_gestes`.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : remettre `let _ = ledger_append(…)` dans `exiger_le_secret_des_gestes` ;
    /// servir `TEXTE_SECRET_DES_GESTES_FAUX` dans la branche sans maillon.
    #[tokio::test]
    async fn aisa_secret_des_gestes_faux_sans_maillon_ne_sert_pas_sa_trace() {
        let (st, _tmp) = aisa_etat("secret-panne");
        aisa_registre_hors_d_atteinte(&st);
        let (statut, _, v) = aisa_reponse(aisa_secret_faux(&st)).await;
        assert_eq!(statut, 403, "le refus tient : {v}");
        aisa_phrase_sans_promesse_de_trace(&v, TEXTE_SECRET_DES_GESTES_FAUX, TEXTE_SECRET_DES_GESTES_FAUX_SANS_TRACE);
        assert_eq!(v.get("cause").and_then(|e| e.as_str()), Some(CAUSE_SECRET_DES_GESTES_FAUX), "clé stable inchangée : {v}");
        let aveu = aisa_aveu(&v).unwrap_or_else(|| panic!("la trace annoncée manque : le refus le DIT : {v}"));
        assert!(aveu.starts_with(CAUSE_REFUS_SANS_TRACE), "{aveu}");
        assert!(!aveu.contains("auteur-aisa") && !aveu.contains("192.0.2.40"), "jamais le détail du maillon : {aveu}");
        assert_eq!(aisa_lignes(&st, "secret_des_gestes"), 0, "fixture : le maillon n'est bien pas entré");

        let (st, _tmp2) = aisa_etat("secret-sain");
        let (statut, octets, v) = aisa_reponse(aisa_secret_faux(&st)).await;
        assert_eq!(statut, 403, "{v}");
        assert_eq!(
            octets,
            serde_json::to_vec(&json!({ "error": TEXTE_SECRET_DES_GESTES_FAUX, "cause": CAUSE_SECRET_DES_GESTES_FAUX })).unwrap(),
            "nominal octet pour octet"
        );
        assert_eq!(aisa_lignes(&st, "secret_des_gestes"), 1, "registre sain : le refus est inscrit");
    }
}

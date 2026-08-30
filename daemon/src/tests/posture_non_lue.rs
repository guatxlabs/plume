    // ==============================================================================================
    // `P10.7-e` — UNE LECTURE DE CONFORMITÉ QUI N'A PAS ABOUTI NE SE SERT PAS COMME UN CONSTAT.
    //
    // CE QUI ÉTAIT CASSÉ, ET POURQUOI CE MODULE-CI. `P10.7-c` a fermé le PORTILLON : un refus de
    // permis rend sa cause. Ce qui échoue APRÈS le portillon rendait encore la forme attendue, toutes
    // clés vides, sans un mot. Sur `compliance_posture` les deux voisins étaient dans la MÊME
    // fonction, à huit lignes l'un de l'autre — le refus du portillon, honnête ; le refus de
    // COMPILATION du langage de requête, muet.
    //
    // CE QUE CES DEUX TÉMOINS TIENNENT, ET CE QU'ILS NE TIENNENT PAS. Ils exercent les DEUX routes de
    // conformité sur une base FICHIER, dans les deux sens, et la valeur qui change d'un sens à
    // l'autre est NOMMÉE : la présence de la clé `error` dans le corps servi, à requête, identité et
    // base identiques. Ils ne sont PAS une garde de famille : ils ne disent rien des dix-neuf autres
    // corps par défaut de `read_with_watchdog`, ni de la voie que la charge déclenche réellement (la
    // requête INTERROMPUE, avalée par la closure appelante — cf. l'en-tête de `read_with_watchdog`).
    // La garde DÉRIVÉE de cette famille reste à écrire ; ceci en est le premier site fermé.
    //
    // LE TÉMOIN NÉGATIF EST LA MOITIÉ QUI COMPTE. Un corps qui avoue TOUJOURS n'avoue rien : chaque
    // témoin exerce d'abord le chemin NOMINAL et exige qu'aucun aveu n'y paraisse, après avoir
    // vérifié que la lecture a bel et bien EU LIEU (sans quoi « pas d'aveu » serait vrai par vacuité).
    // Et le second témoin sépare deux faits que le corps confondait : un journal d'intégrité VIERGE
    // (une absence ÉTABLIE, servie comme avant) et un journal NON LU (un aveu).
    // ==============================================================================================

    /// L'identité qui interroge : admin, pour qu'aucun masque de champ ne s'interpose entre le
    /// témoin et ce que la route rend.
    fn cnl_au() -> AuthUser {
        AuthUser {
            name: "p107e".into(), role: "admin".into(), tenant: "default".into(),
            is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    /// Une base FICHIER (le pool de lecture ouvre par chemin : une base en mémoire ne conviendrait
    /// pas) portant une posture SCA ingérée, pour que le chemin nominal ait quelque chose à rendre.
    fn cnl_base(etiquette: &str) -> crate::tmp_possede::TmpDb {
        let coffre = crate::tmp_possede::TmpDb::neuf(etiquette);
        let conn = open_db(coffre.as_str()).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        let mk = |ctrl: &str, res: &str| json!({ "agent": { "name": "h1" }, "data": { "sca": { "type": "check", "policy": "CIS",
            "check": { "id": ctrl, "title": "t", "result": res, "compliance": [ { "pci_dss": ["8.7"] } ] } } } });
        ingest_wazuh(&conn, coffre.as_str(), "p107e-1", mk("1", "failed"));
        ingest_wazuh(&conn, coffre.as_str(), "p107e-2", mk("2", "passed"));
        coffre
    }

    /// LE ROLLUP DE POSTURE. ① la lecture aboutit -> la synthèse est servie et RIEN n'est avoué ;
    /// ② la même route, la même identité, la même requête, mais la lecture ne peut plus aboutir ->
    /// la FORME attendue est servie INTACTE et la cause du moteur est DITE, sans être réécrite.
    #[tokio::test]
    async fn une_posture_non_lue_ne_se_sert_pas_comme_une_couverture_nulle() {
        let coffre = cnl_base("p107e-posture");
        let st = ds_file_state(coffre.as_str());
        let au = cnl_au();

        // ---- ① NOMINAL. L'instrument d'abord : la mesure a-t-elle EU LIEU ? ----
        let nominal = compliance_posture(State(st.clone()), Extension(au.clone()), Query(HashMap::new())).await.0;
        let cadres = nominal["summary"].as_array().unwrap_or_else(|| panic!("la synthèse n'est pas servie : {nominal}"));
        assert!(
            !cadres.is_empty(),
            "instrument : la posture semée doit produire au moins un cadre, sinon « aucun aveu » serait vrai par vacuité : {nominal}"
        );
        assert!(
            nominal.get("error").is_none(),
            "un aveu posé sur le chemin NOMINAL : un corps qui avoue toujours n'avoue rien — {nominal}"
        );

        // ---- ② LA LECTURE NE PEUT PLUS ABOUTIR. Rien d'autre ne change. ----
        st.db.lock().execute_batch("DROP TABLE event").unwrap();
        let refuse = compliance_posture(State(st.clone()), Extension(au), Query(HashMap::new())).await.0;
        let aveu = refuse["error"]
            .as_str()
            .unwrap_or_else(|| panic!("posture NON LUE servie sans cause — c'est le défaut que cette clé ferme : {refuse}"));
        assert!(
            aveu.contains(crate::handlers::compliance::CAUSE_POSTURE_NON_LUE),
            "l'aveu dit ce que le corps n'établit PAS : {aveu}"
        );
        assert!(
            aveu.contains("no such table"),
            "la cause du MOTEUR est conservée telle quelle, jamais remplacée par la nôtre : {aveu}"
        );
        assert!(
            refuse.get("summary").is_some() && refuse.get("frameworks").is_some(),
            "la FORME attendue par le consommateur reste servie : l'aveu s'AJOUTE, il ne retire rien — {refuse}"
        );
    }

    /// L'ANCRAGE DE PREUVE DU RAPPORT. Un journal d'intégrité VIERGE et un journal NON LU rendaient
    /// le même corps : tête vide, zéro entrée. Le premier est un FAIT et le reste ; le second devient
    /// un aveu. Le rapport n'accuse PAS au passage la posture, qui, elle, a été lue.
    #[tokio::test]
    async fn un_journal_d_integrite_non_lu_n_est_pas_un_journal_vierge() {
        let coffre = cnl_base("p107e-ancrage");
        let st = ds_file_state(coffre.as_str());
        let au = cnl_au();

        // ---- ① VIERGE : une absence ÉTABLIE. Elle est servie comme un fait, sans aveu. ----
        let vierge = compliance_report(State(st.clone()), Extension(au.clone()), Query(HashMap::new())).await.0;
        let ev = &vierge["evidence"];
        assert_eq!(ev["ledger_entries"], json!(0), "journal vierge : le compte est un FAIT — {ev}");
        assert_eq!(ev["ledger_head"], json!(""), "journal vierge : aucune tête de chaîne, et c'est un FAIT — {ev}");
        assert!(
            ev.get("error").is_none(),
            "un aveu sur un journal RÉELLEMENT vierge : l'aveu deviendrait inconditionnel — {ev}"
        );

        // ---- ② NON LU. Le compte disparaît (il n'a pas été pris) et la cause paraît. ----
        st.db.lock().execute_batch("DROP TABLE ledger").unwrap();
        let muet = compliance_report(State(st.clone()), Extension(au), Query(HashMap::new())).await.0;
        let ev = &muet["evidence"];
        let aveu = ev["error"]
            .as_str()
            .unwrap_or_else(|| panic!("journal NON LU servi comme un journal vierge : {ev}"));
        assert!(aveu.contains(crate::handlers::compliance::CAUSE_ANCRAGE_NON_LU), "l'aveu dit ce que le corps n'établit PAS : {aveu}");
        assert!(aveu.contains("no such table"), "la cause du moteur est conservée : {aveu}");
        assert!(
            ev.get("ledger_entries").is_none(),
            "un compte servi à côté de l'aveu se relirait comme une mesure : {ev}"
        );
        assert!(
            muet["posture"].get("error").is_none(),
            "l'aveu porte sur l'ANCRAGE seul : la posture, elle, a été lue, et le rapport ne doit pas l'accuser — {}",
            muet["posture"]
        );
    }

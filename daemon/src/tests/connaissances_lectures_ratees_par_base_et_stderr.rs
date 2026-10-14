// =====================================================================================
// `P10.20-b` (hors `handlers/` : `knowledge_reload`, `GET /api/knowledge`) — LE COMPTE DES LECTURES RATÉES
// DU REGISTRE DE SAVOIR EST CELUI DE LA BASE DE LA REQUÊTE, ET LA LIGNE DE STDERR PART VRAIMENT, UNE PAR
// ÉCHEC, AVEC LA BONNE SUITE.
//
// Témoins ajoutés après vérification indépendante. Les témoins du lot (`connaissances_registre_non_relu_conserve`)
// laissaient passer quatre mutants :
// - `M1` : `knowledge_list` lit le compte sous `st.db_path` (la base primaire) au lieu de `req_db_path`. En
//   mode 0 les deux sont le même chemin par construction (`req_db_path`, state.rs), donc seul un témoin en
//   mode 1 les sépare.
// - `M10` : `knowledge_reload` n'écrit plus rien sur stderr. Seul le rendu de `recharger_le_savoir` était
//   relu, jamais l'écriture.
// - `M11` : seule la première ligne d'un rechargement est rendue, le compte restant juste.
// - `M12` : la ligne dit « part en place GARDÉE » pour un registre jamais chargé.
//
// LES TÉMOINS.
// (1) Mode 1, deux bases. Le tenant `o6b-acme` a sa base propre : trois lectures ratées sur sa base, une sur
//     la base primaire. `GET /api/knowledge` d'un admin de `o6b-acme` sert 3, jamais 1. Contrôle : le
//     chemin du tenant n'est pas `st.db_path`.
// (2) Trois échecs dans un rechargement, jeu en place : trois lignes. Chacune nomme sa table (deux
//     `knowledge_alias`, une `knowledge_tag`) et dit que la part en place est gardée. Aucune ne porte la
//     valeur de cellule, ni en texte ni au format `{:?}` des octets.
// (3) Registre jamais chargé : la même base donne trois lignes, chacune « aucun registre en place », aucune
//     « GARDÉE ».
// (4) L'écriture elle-même. Le binaire de test se rejoue en sous-processus (`current_exe`, `--nocapture`).
//     L'enfant appelle `knowledge_reload` sur une base jamais chargée qui a trois lignes indécodables.
//     Le parent lit le stderr de l'enfant : trois lignes `[knowledge] lecture ratée de`, avec les tables,
//     la base de l'enfant et « aucun registre en place ».
//
// MUTANTS JOUÉS (`VERIF_MUT`, retirés du source avant le commit) :
// - `M1` (compte lu sous `st.db_path`) fait rougir (1) ;
// - `M10` (`knowledge_reload` muet) fait rougir (4) ;
// - `M11` (`truncate(1)` sur les lignes rendues) fait rougir (2) (3) (4) ;
// - `M12` (suite forcée à « gardée ») fait rougir (3) (4) ;
// - `M17` (valeurs `{:?}` des trois premières colonnes ajoutées à la cause d'une ligne indécodable,
//   dans `lire_une_table_de_savoir`) fait rougir (2).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS :
// - le mode 1 n'est joué que sur la route de liste. Le rechargement par une route CRUD d'un tenant n'est pas
//   rejoué ici : il appelle `knowledge_reload` avec `req_db_path`, qui reste hors témoin.
// - la fuite de valeur n'est cherchée qu'en texte et au format `{:?}` des octets. Un autre encodage
//   (hexadécimal, base64) n'est pas cherché.
// - les témoins du lot sont restés dans `connaissances_registre_non_relu_conserve.rs`. Ce lot y a aussi
//   réécrit la ligne `include!` de `tests/mod.rs`, ce qui a dupliqué l'include à la fusion (réparé par
//   f13f9f64). Ce fichier-ci est neuf, et son include est AJOUTÉ.
// =====================================================================================
mod connaissances_lectures_ratees_par_base_et_stderr {
    use super::*;

    const O6B_SECRET: &str = "valeur_secrete_o6b";

    /// Trois lignes indécodables : deux dans `knowledge_alias`, une dans `knowledge_tag`. Les octets de
    /// chaque cellule blob portent `O6B_SECRET`.
    fn o6b_trois_lignes_indecodables(conn: &Connection) {
        conn.execute_batch(&format!(
            "INSERT INTO knowledge_alias(canonical,source) VALUES('o6b_a1',CAST('{O6B_SECRET}' AS BLOB));
             INSERT INTO knowledge_alias(canonical,source) VALUES('o6b_a2',CAST('{O6B_SECRET}' AS BLOB));
             INSERT INTO knowledge_tag(label,field,value) VALUES('o6b_t','category',CAST('{O6B_SECRET}' AS BLOB));"
        ))
        .unwrap();
    }

    /// Le contrôle positif de la fixture : un objet valide par table, pour que le jeu en place existe.
    fn o6b_objets_valides(conn: &Connection) {
        conn.execute_batch(
            "INSERT INTO knowledge_alias(canonical,source) VALUES('o6b_ok','src_ip');
             INSERT INTO knowledge_tag(label,field,value) VALUES('o6b_ok','category','payment');",
        )
        .unwrap();
    }

    /// Les lignes d'un rechargement à trois échecs : nombre, tables, base, suite, et aucune valeur de cellule.
    fn o6b_juger_trois_lignes(lignes: &[String], dbp: &str, suite_attendue: &str, suite_interdite: &str) {
        assert_eq!(lignes.len(), 3, "trois échecs dans un rechargement = trois lignes : {lignes:?}");
        let par_table = |t: &str| lignes.iter().filter(|l| l.contains(&format!("`{t}`"))).count();
        assert_eq!(par_table("knowledge_alias"), 2, "deux lignes nomment `knowledge_alias` : {lignes:?}");
        assert_eq!(par_table("knowledge_tag"), 1, "une ligne nomme `knowledge_tag` : {lignes:?}");
        let octets = format!("{:?}", &O6B_SECRET.as_bytes()[..4]);
        let octets = octets.trim_start_matches('[').trim_end_matches(']').to_string();
        for l in lignes {
            assert!(l.starts_with("[knowledge] lecture ratée de `"), "forme de la ligne : {l}");
            assert!(l.contains(dbp), "la ligne nomme la base : {l}");
            assert!(l.contains(suite_attendue), "suite attendue « {suite_attendue} » : {l}");
            assert!(!l.contains(suite_interdite), "suite interdite « {suite_interdite} » : {l}");
            assert!(!l.contains(O6B_SECRET), "aucune valeur de cellule en texte : {l}");
            assert!(!l.contains(&octets), "aucune valeur de cellule en octets `{{:?}}` ({octets}) : {l}");
            assert!(!l.contains("Blob(["), "aucune valeur `ValueRef` au format `{{:?}}` : {l}");
        }
    }

    /// (2) Jeu en place, trois échecs dans un rechargement : trois lignes, « GARDÉE ».
    #[test]
    fn o6b_trois_echecs_jeu_en_place_trois_lignes_gardee() {
        let conn = test_db();
        let dbp = "o6b-trois-lignes-en-place";
        o6b_objets_valides(&conn);
        assert!(recharger_le_savoir(&conn, dbp).is_empty(), "contrôle : chargement nominal sans ligne");
        o6b_trois_lignes_indecodables(&conn);
        let lignes = recharger_le_savoir(&conn, dbp);
        o6b_juger_trois_lignes(&lignes, dbp, "la part en place de cette table est GARDÉE", "aucun registre en place");
        assert_eq!(knowledge_lectures_ratees_de(dbp), 3, "contrôle : trois échecs comptés");
    }

    /// (3) Registre jamais chargé : trois lignes, « aucun registre en place », jamais « GARDÉE ».
    #[test]
    fn o6b_trois_echecs_registre_jamais_charge_aucune_part_gardee() {
        let conn = test_db();
        let dbp = "o6b-trois-lignes-jamais-charge";
        o6b_objets_valides(&conn);
        o6b_trois_lignes_indecodables(&conn);
        let lignes = recharger_le_savoir(&conn, dbp);
        o6b_juger_trois_lignes(&lignes, dbp, "aucun registre en place", "GARDÉE");
        assert_eq!(knowledge_lectures_ratees_de(dbp), 3, "contrôle : trois échecs comptés");
    }

    /// (4) L'ÉCRITURE SUR STDERR. L'enfant (variable `O6B_ENFANT` posée) appelle `knowledge_reload` sur une
    /// base jamais chargée qui a trois lignes indécodables, puis rend la main. Le parent lit le stderr de
    /// l'enfant.
    #[test]
    fn o6b_knowledge_reload_ecrit_une_ligne_de_stderr_par_echec() {
        const ENFANT: &str = "O6B_ENFANT_BASE";
        if let Ok(dbp) = std::env::var(ENFANT) {
            let conn = test_db();
            o6b_objets_valides(&conn);
            o6b_trois_lignes_indecodables(&conn);
            println!("O6B-ENFANT-A-JOUE");
            knowledge_reload(&conn, &dbp);
            return;
        }
        let dbp = format!("o6b-stderr-{}", std::process::id());
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::connaissances_lectures_ratees_par_base_et_stderr::o6b_knowledge_reload_ecrit_une_ligne_de_stderr_par_echec",
            ])
            .env(ENFANT, &dbp)
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("O6B-ENFANT-A-JOUE"), "contrôle : l'enfant a vraiment joué : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let lignes: Vec<String> =
            stderr.lines().filter(|l| l.starts_with("[knowledge] lecture ratée de")).map(str::to_string).collect();
        o6b_juger_trois_lignes(&lignes, &dbp, "aucun registre en place", "GARDÉE");
    }

    /// (1) MODE 1 : le compte servi est celui de la base DU TENANT de la requête, pas celui de la base
    /// primaire. La base primaire a un échec, celle du tenant trois.
    #[tokio::test]
    async fn o6b_mode_1_le_compte_servi_est_celui_de_la_base_du_tenant() {
        let (st, _dir) = mk_mode1_state();
        let (statut, cree) = lsa_corps(
            tenant_create(
                State(st.clone()),
                crate::secret_des_gestes::presente_de_test(),
                Extension(au_super("op-o6b")),
                Json(json!({ "id": "o6b-acme", "name": "O6bAcme" })),
            )
            .await,
        )
        .await;
        assert_eq!(statut, 201, "contrôle : tenant créé : {cree}");
        let chemin_du_tenant = st.tenants.ready_db_path("o6b-acme").expect("contrôle : tenant servable");
        let primaire = st.db_path.as_ref().clone();
        assert_ne!(chemin_du_tenant, primaire, "contrôle : la base du tenant n'est pas la base primaire");

        {
            let conn = st.db.lock();
            conn.execute("INSERT INTO knowledge_alias(canonical,source) VALUES('o6b_p',x'ff')", []).unwrap();
            assert_eq!(recharger_le_savoir(&conn, &primaire).len(), 1, "contrôle : un échec sur la base primaire");
        }
        {
            let h = st.tenants.handle_for("o6b-acme").expect("contrôle : handle du tenant");
            let conn = h.lock();
            conn.execute("INSERT INTO knowledge_calc(name,expr) VALUES('o6b_calc','upper(severity)')", []).unwrap();
            o6b_trois_lignes_indecodables(&conn);
            assert_eq!(recharger_le_savoir(&conn, &chemin_du_tenant).len(), 3, "contrôle : trois échecs sur la base du tenant");
        }
        assert_eq!(knowledge_lectures_ratees_de(&primaire), 1, "contrôle : compte de la base primaire");
        assert_eq!(knowledge_lectures_ratees_de(&chemin_du_tenant), 3, "contrôle : compte de la base du tenant");

        let (statut, corps) =
            lsa_corps(knowledge_list(State(st.clone()), Extension(au_tadmin("adm-o6b", "o6b-acme"))).await).await;
        assert_eq!(statut, 200, "{corps}");
        assert_eq!(
            corps[CLE_LECTURES_DE_SAVOIR_RATEES],
            json!(3),
            "le compte servi au tenant est celui de SA base (3), pas celui de la base primaire (1) : {corps}"
        );
        assert!(
            corps["calcs"].as_array().map(|a| a.iter().any(|x| x["name"] == "o6b_calc")).unwrap_or(false),
            "contrôle : la liste est bien lue sur la base du tenant (calcul posé sur elle seule) : {corps}"
        );
    }
}

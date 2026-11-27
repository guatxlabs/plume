// =====================================================================================
// SAUVEGARDE : L'ÉCRIVAIN N'ÉMET QUE CE QUE LA RESTAURATION ADMET, ET IL DIT CE QU'IL OMET
// (`backup/dump_restauration.rs` : `admis_par_la_restauration`, `collect_dump_plan`,
// `retirer_de_l_export_ce_que_la_restauration_refuserait`, `ligne_des_objets_omis`, `backup_compressed` ;
// `backup/mod.rs` : `backup_compressed_legacy`, `BackupStats::objets_omis`, `BackupStats::phrase_des_tailles`).
//
// LE DÉFAUT, LU SUR 672758ad : la restauration refuse une archive qui porte un déclencheur ou une vue autres que ceux
// que le démon crée, mais l'écrivain émettait tout déclencheur et toute vue de la base. Une base qui en portait un de
// plus produisait, sans aucun signal, une sauvegarde que la restauration refusait (témoin aller-retour ci-dessous, rouge
// sur 672758ad : « restauration refusée … déclencheur ou vue autre que ceux que le démon crée »).
//
// DÉSORMAIS, dans les deux formats : un déclencheur ou une vue n'entre dans l'archive que si le couple (nom, texte) est
// membre de l'ensemble de référence (`migrate::declencheurs_et_vues_de_reference`), la même fonction et la même égalité
// que la restauration ; tout autre est omis, la sauvegarde réussit, et l'omission est dite : une ligne `[backup]` au
// journal (nombre, puis genre et nom des huit premiers, noms échappés et bornés) et `omis=<nombre> (<phrase fixe>)` à la fin de la
// ligne de résultat (`phrase_des_tailles`, écrite par la sous-commande `backup --compress` et par la ligne
// `[backup-sched] écrit …` de l'ordonnanceur). Au format ancien, l'objet est retiré du fichier exporté (jamais de la
// base vivante), et son texte ne survit pas dans la page (le fichier attaché hérite de `secure_delete`, que SQLCipher
// force sur la base chiffrée).
//
// LE COÛT : l'ensemble de référence est construit au plus une fois par processus, et l'écrivain ne le reconstruit ni à
// chaque déclencheur ou vue jugé ni à chaque sauvegarde (compté sur de vraies sauvegardes, par les bases en mémoire que
// la construction ouvre).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la sortie standard de la sous-commande `backup --compress` (le binaire du démon
// n'est pas celui des tests) ; elle écrit la même `phrase_des_tailles`, témoignée ici directement et par l'ordonnanceur.
//
// MUTANTS (VERIF_MUT, retirés avant le commit), chacun vu ROUGE seul : CK3_EMET_TOUT (l'écrivain émet tout, l'état
// d'avant), CK3_DECLENCHEURS_SEULS (seuls les déclencheurs sont omis), CK3_VUES_SEULES (seules les vues sont omises),
// CK3_SANS_JOURNAL (la ligne `[backup]` retirée), CK3_SANS_AVEU (le `omis=` du résultat retiré), CK3_NOM_BRUT (le nom
// écrit sans échappement), CK3_SANS_BORNE_NOMBRE, CK3_SANS_BORNE_LONGUEUR, CK3_OMET_TOUT (l'écrivain omet tout, ce que
// le témoin du chemin nominal voit), CK3_SECURE_DELETE_OFF (le fichier exporté perd `secure_delete`) ; puis M01 (la
// règle compare le nom seul), M02 (la règle compare le texte aux espaces près), M19 (au format ancien, le retrait joué
// aussi sur la base vivante `main`), M16 (l'erreur du `DELETE` avalée), M22 (la ligne `[backup]` écrite avant le
// `rename`) ; puis A3 (la règle compare le texte sans tenir compte de la casse ASCII) et A5 (l'écrivain reconstruit
// l'ensemble de référence à chaque déclencheur ou vue jugé).
// =====================================================================================

mod ck3_sauvegarde_objets_hors_reference_omis_et_dits {
    use super::*;

    const CLE: &str = "ck3-cle-de-test-de-sauvegarde";

    /// Un déclencheur que le démon ne crée pas, sur la table ordinaire `event` : il refuserait tout effacement.
    const DECLENCHEUR_ETRANGER: &str =
        "CREATE TRIGGER ck3_garde_des_evenements BEFORE DELETE ON event BEGIN SELECT RAISE(ABORT, 'ck3'); END";
    /// Une vue que le démon ne crée pas (il n'en crée aucune).
    const VUE_ETRANGERE: &str = "CREATE VIEW ck3_vue_des_graves AS SELECT id, host, message FROM event WHERE severity >= 3";
    const NOMS_ETRANGERS: [&str; 2] = ["ck3_garde_des_evenements", "ck3_vue_des_graves"];

    // Les phrases attendues, écrites ici en toutes lettres (jamais relues de la production).
    const PHRASE_DU_RESULTAT: &str =
        "déclencheurs ou vues autres que ceux que le démon crée, omis de l'archive : la restauration les refuserait";
    fn ligne_attendue(nombre: usize, noms: &str) -> String {
        format!(
            "[backup] {nombre} déclencheur(s) ou vue(s) autres que ceux que le démon crée OMIS de l'archive (la restauration \
             les refuserait ; les tables et leurs lignes sont emportées) : {noms}"
        )
    }
    const NOMS_DES_ETRANGERS: &str = "déclencheur \"ck3_garde_des_evenements\", vue \"ck3_vue_des_graves\"";

    fn chemin(racine: &std::path::Path, nom: &str) -> String {
        racine.join(nom).to_string_lossy().into_owned()
    }

    fn lignes_de(c: &rusqlite::Connection, sql: &str) -> Vec<String> {
        let mut s = c.prepare(sql).unwrap();
        let n = s.column_count();
        let mut lignes: Vec<String> = s
            .query_map([], |r| Ok((0..n).map(|i| format!("{:?}", r.get::<_, rusqlite::types::Value>(i).unwrap())).collect::<Vec<_>>().join("|")))
            .unwrap()
            .map(|l| l.unwrap())
            .collect();
        lignes.sort();
        lignes
    }

    /// Les déclencheurs et les vues d'une base : (nom, texte de `sqlite_master.sql`).
    fn declencheurs_et_vues(c: &rusqlite::Connection) -> std::collections::BTreeSet<(String, String)> {
        let mut s = c.prepare("SELECT name, sql FROM sqlite_master WHERE type IN ('trigger', 'view') AND sql IS NOT NULL").unwrap();
        s.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).unwrap().map(|r| r.unwrap()).collect()
    }

    /// Tout le schéma d'une base, hors statistiques de l'optimiseur (que l'écrivain n'emporte pas).
    const SCHEMA: &str = "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_stat%'";

    /// Une base de la tête (schéma de base puis toutes les migrations) ; avec `entretien`, l'entretien du démarrage pose
    /// le filtre de champs plein texte et ses deux déclencheurs (ce qui fait prendre le format ancien). Trois événements,
    /// dont un grave, portent des mots que les tables plein texte doivent retrouver.
    fn base_de_la_tete(c: &rusqlite::Connection, entretien: bool) {
        c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(c), "contrôle : la chaîne de migrations va au bout");
        if entretien {
            let mut conf = std::collections::HashMap::new();
            conf.insert("PLUME_FTS_FIELDS".to_string(), "1".to_string());
            let _ = crate::maintenance::reconcile_index_state(c, &conf);
        }
        c.execute_batch(
            "INSERT INTO event(ts, source, category, severity, host, message, fields) VALUES \
               (1000, 'sshd', 'auth', 1, 'web01', 'ck3premier connexion', '{\"user\":\"alice\"}'), \
               (1001, 'sudo', 'exec', 4, 'web02', 'ck3grave elevation', '{\"user\":\"bob\"}'), \
               (1002, 'auditd', 'integrity', 0, 'web01', 'ck3dernier fichier', '{\"chemin\":\"ck3champ\"}');",
        )
        .unwrap();
    }

    /// La source : une base de la tête, puis (si `etrangers`) le déclencheur et la vue étrangers. Rend (schéma,
    /// déclencheurs et vues, lignes de `event`) de la source.
    fn source(src: &str, entretien: bool, etrangers: bool) -> (Vec<String>, std::collections::BTreeSet<(String, String)>, Vec<String>) {
        let c = open_db_keyed(src, Some(CLE)).unwrap();
        base_de_la_tete(&c, entretien);
        if etrangers {
            c.execute_batch(&format!("{DECLENCHEUR_ETRANGER}; {VUE_ETRANGERE};")).unwrap();
        }
        (lignes_de(&c, SCHEMA), declencheurs_et_vues(&c), lignes_de(&c, "SELECT * FROM event"))
    }

    /// La charge entière, déchiffrée et décompressée, d'une archive à la passphrase `CLE`.
    fn charge_en_clair(archive: &str) -> Vec<u8> {
        use std::io::Read;
        let f = std::fs::File::open(archive).unwrap();
        let dec = age::Decryptor::new_buffered(std::io::BufReader::new(f)).unwrap();
        let id = age::scrypt::Identity::new(age::secrecy::SecretString::from(CLE.to_string()));
        let reader = dec.decrypt(std::iter::once(&id as &dyn age::Identity)).unwrap();
        let mut zd = zstd::Decoder::new(reader).unwrap();
        let mut tout = Vec::new();
        zd.read_to_end(&mut tout).unwrap();
        tout
    }

    fn porte(charge: &[u8], motif: &str) -> bool {
        charge.windows(motif.len()).any(|w| w == motif.as_bytes())
    }

    fn noms_omis(st: &crate::backup::BackupStats) -> Vec<(crate::backup::GenreOmis, String)> {
        st.objets_omis.iter().map(|o| (o.genre, o.nom.clone())).collect()
    }

    fn les_etrangers_omis() -> Vec<(crate::backup::GenreOmis, String)> {
        vec![
            (crate::backup::GenreOmis::Declencheur, "ck3_garde_des_evenements".to_string()),
            (crate::backup::GenreOmis::Vue, "ck3_vue_des_graves".to_string()),
        ]
    }

    // ── D : L'ALLER-RETOUR RÉEL ────────────────────────────────────────────────────────────────────────

    /// L'ALLER-RETOUR RÉEL D'UNE BASE QUI PORTE UN DÉCLENCHEUR ET UNE VUE HORS RÉFÉRENCE, DANS LES DEUX FORMATS : la
    /// sauvegarde réussit et rend les deux objets omis (genre et nom) ; la ligne de résultat finit par `omis=2 (…)` ;
    /// la charge en clair ne porte aucun des deux noms ; l'archive se restaure ; la base publiée n'a ni le déclencheur ni
    /// la vue étrangers, et tout le reste est identique à la source (schéma entier, lignes, index, déclencheurs de
    /// référence, tables virtuelles qui répondent, déclencheur de référence qui joue).
    #[test]
    fn l_archive_d_une_base_qui_porte_des_objets_hors_reference_se_restaure_sans_eux() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        for (entretien, tete) in [(false, &b"PLUMEDUMP1\n"[..]), (true, &b"SQLite format 3\0"[..])] {
            let cas = if entretien { "ck3-d-ancien" } else { "ck3-d-courant" };
            let _tmp = crate::tmp_possede::TmpPossede::neuf(cas);
            let racine = _tmp.racine().chemin().to_path_buf();
            let src = chemin(&racine, "src.db");
            let (schema, objets, evenements) = source(&src, entretien, true);
            for nom in table_declaree!(NOMS_ETRANGERS) {
                assert!(objets.iter().any(|(n, _)| n == nom), "{cas} : contrôle, la source porte {nom}");
                assert!(schema.iter().any(|l| l.contains(&format!("{nom:?}"))), "{cas} : contrôle, le schéma de la source porte {nom}");
            }
            assert!(evenements.len() == 3, "{cas} : contrôle, trois événements");
            let archive = chemin(&racine, "archive.age");
            let st = backup_compressed(&src, &archive, Some(CLE), None).unwrap_or_else(|e| panic!("{cas} : sauvegarde : {e}"));
            assert_eq!(noms_omis(&st), les_etrangers_omis(), "{cas} : les objets omis, genre et nom, dans l'ordre de la base");
            // L'omission touche l'archive, jamais la base vivante : la source garde son schéma entier, étrangers compris.
            {
                let relue = open_db_keyed(&src, Some(CLE)).unwrap();
                assert_eq!(declencheurs_et_vues(&relue), objets, "{cas} : la base vivante a perdu des déclencheurs ou des vues");
                assert_eq!(lignes_de(&relue, SCHEMA), schema, "{cas} : le schéma de la base vivante a changé");
            }
            let phrase = st.phrase_des_tailles();
            assert!(phrase.ends_with(&format!("  omis=2 ({PHRASE_DU_RESULTAT})")), "{cas} : l'aveu du résultat : {phrase}");
            assert_eq!(phrase.matches("omis=").count(), 1, "{cas} : un seul aveu : {phrase}");
            let charge = charge_en_clair(&archive);
            assert!(charge.starts_with(tete), "{cas} : format de l'archive");
            assert!(porte(&charge, "ck3premier"), "{cas} : contrôle, la charge en clair est lisible (les lignes y sont)");
            for nom in table_declaree!(NOMS_ETRANGERS) {
                assert!(!porte(&charge, nom), "{cas} : {nom} est dans la charge de l'archive");
            }
            let dest = chemin(&racine, "plume.db");
            restore_compressed(&archive, &dest, Some(CLE), false, None).unwrap_or_else(|e| panic!("{cas} : restauration refusée : {e}"));
            let dst = open_db_keyed(&dest, Some(CLE)).unwrap();
            let schema_attendu: Vec<String> =
                schema.iter().filter(|l| !NOMS_ETRANGERS.iter().any(|n| l.contains(&format!("{n:?}")))).cloned().collect();
            assert_eq!(schema_attendu.len() + 2, schema.len(), "{cas} : contrôle, deux lignes de schéma retirées");
            assert_eq!(lignes_de(&dst, SCHEMA), schema_attendu, "{cas} : le schéma publié est celui de la source sans les étrangers");
            let objets_attendus: std::collections::BTreeSet<(String, String)> =
                objets.iter().filter(|(n, _)| !NOMS_ETRANGERS.contains(&n.as_str())).cloned().collect();
            assert!(objets_attendus.len() >= 5, "{cas} : contrôle, les déclencheurs de référence");
            assert_eq!(declencheurs_et_vues(&dst), objets_attendus, "{cas} : les déclencheurs de référence, nom et texte");
            assert_eq!(lignes_de(&dst, "SELECT * FROM event"), evenements, "{cas} : les lignes de event");
            assert_eq!(
                lignes_de(&dst, "SELECT rowid FROM event_fts WHERE event_fts MATCH 'ck3grave'"),
                vec!["Integer(2)".to_string()],
                "{cas} : event_fts répond"
            );
            if entretien {
                assert_eq!(
                    lignes_de(&dst, "SELECT rowid FROM event_fields_fts WHERE event_fields_fts MATCH 'ck3champ'"),
                    vec!["Integer(3)".to_string()],
                    "{cas} : event_fields_fts répond"
                );
            }
            // Le déclencheur de référence joue dans la base publiée ; l'étranger, qui refuserait l'effacement, n'y est plus.
            dst.execute("DELETE FROM event WHERE id = 1", []).unwrap_or_else(|e| panic!("{cas} : effacement refusé : {e}"));
            assert_eq!(lignes_de(&dst, "SELECT rowid FROM event_fts WHERE event_fts MATCH 'ck3premier'"), Vec::<String>::new(), "{cas} : event_ad a joué");
        }
    }

    /// AU FORMAT ANCIEN, LE TEXTE D'UN OBJET OMIS NE SURVIT PAS DANS LA CHARGE : sur une petite base (tout son schéma
    /// tient dans la première page, aucune page n'est réorganisée par le retrait), une table plein texte sans contenu
    /// fait prendre le format ancien ; le déclencheur et la vue étrangers sont omis, et ni leur nom ni leur corps ne
    /// figurent dans la charge en clair, alors que la ligne de `t` y est. Rouge si le fichier attaché perd `secure_delete`
    /// (mutant CK3_SECURE_DELETE_OFF).
    #[test]
    fn au_format_ancien_le_texte_d_un_objet_omis_n_est_pas_dans_la_charge() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ck3-ancien-texte");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        {
            let c = open_db_keyed(&src, Some(CLE)).unwrap();
            c.execute_batch(
                "CREATE TABLE t(v TEXT); INSERT INTO t VALUES('ck3ligneordinaire'); \
                 CREATE VIRTUAL TABLE f USING fts5(v, content=''); \
                 CREATE TRIGGER ck3_declencheur_cache AFTER INSERT ON t BEGIN SELECT 'ck3corpsdudeclencheur'; END; \
                 CREATE VIEW ck3_vue_cachee AS SELECT 'ck3corpsdelavue' FROM t;",
            )
            .unwrap();
        }
        let archive = chemin(&racine, "archive.age");
        let st = backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde");
        assert_eq!(
            noms_omis(&st),
            vec![
                (crate::backup::GenreOmis::Declencheur, "ck3_declencheur_cache".to_string()),
                (crate::backup::GenreOmis::Vue, "ck3_vue_cachee".to_string()),
            ]
        );
        let charge = charge_en_clair(&archive);
        assert!(charge.starts_with(b"SQLite format 3\0"), "contrôle : format ancien");
        assert!(porte(&charge, "ck3ligneordinaire"), "contrôle : la ligne de t est dans la charge");
        for motif in ["ck3_declencheur_cache", "ck3corpsdudeclencheur", "ck3_vue_cachee", "ck3corpsdelavue"] {
            assert!(!porte(&charge, motif), "{motif} est dans la charge");
        }
        let dest = chemin(&racine, "plume.db");
        restore_compressed(&archive, &dest, Some(CLE), false, None).unwrap_or_else(|e| panic!("restauration : {e}"));
    }

    /// UN QUASI-HOMONYME D'UN DÉCLENCHEUR DE RÉFÉRENCE EST OMIS, DANS LES DEUX FORMATS : la règle de l'écrivain compare
    /// le couple (nom, texte) entier, à l'octet, comme la restauration. `event_ai` (nom de l'ensemble de référence) est
    /// recréé sous le même nom, une fois avec un autre corps, une fois avec le texte de référence plus une seule espace,
    /// une fois avec le texte de référence où `AFTER INSERT` est écrit en minuscules (le moteur range ce texte tel quel :
    /// il ne réécrit que la tête `CREATE TRIGGER`) ; chaque fois la sauvegarde l'omet (et seulement lui), l'archive se
    /// restaure, et la base publiée garde les autres déclencheurs de référence, sans `event_ai`. Rouge si la règle compare
    /// le nom seul (M01 : la variante « corps » entre dans l'archive, que la restauration refuse), le texte aux espaces
    /// près (M02 : la variante « espace ») ou le texte sans tenir compte de la casse ASCII (A3 : la variante « casse »).
    #[test]
    fn un_quasi_homonyme_d_un_declencheur_de_reference_est_omis() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        for entretien in [false, true] {
            for variante in ["corps", "espace", "casse"] {
                let cas = format!("ck3-quasi-{variante}-{}", if entretien { "ancien" } else { "courant" });
                let _tmp = crate::tmp_possede::TmpPossede::neuf(&cas);
                let racine = _tmp.racine().chemin().to_path_buf();
                let src = chemin(&racine, "src.db");
                let objets_de_la_tete = {
                    let c = open_db_keyed(&src, Some(CLE)).unwrap();
                    base_de_la_tete(&c, entretien);
                    let objets = declencheurs_et_vues(&c);
                    let reference: String = c
                        .query_row("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'event_ai'", [], |r| r.get(0))
                        .expect("contrôle : event_ai dans la base de la tête");
                    assert!(
                        crate::migrate::declencheurs_et_vues_de_reference().unwrap().contains(&("event_ai".to_string(), reference.clone())),
                        "{cas} : contrôle, le couple de la tête est dans l'ensemble de référence"
                    );
                    let quasi = match variante {
                        "corps" => "CREATE TRIGGER event_ai AFTER INSERT ON event BEGIN SELECT 'ck3autrecorps'; END".to_string(),
                        "espace" => {
                            assert!(reference.contains("BEGIN"), "{cas} : contrôle, {reference}");
                            reference.replacen("BEGIN", "BEGIN ", 1)
                        }
                        _ => {
                            assert!(reference.contains("AFTER INSERT"), "{cas} : contrôle, {reference}");
                            reference.replacen("AFTER INSERT", "after insert", 1)
                        }
                    };
                    c.execute_batch(&format!("DROP TRIGGER event_ai; {quasi};")).unwrap();
                    let relu: String = c
                        .query_row("SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'event_ai'", [], |r| r.get(0))
                        .unwrap();
                    assert_ne!(relu, reference, "{cas} : contrôle, le texte stocké diffère de la référence");
                    if variante == "espace" {
                        assert_eq!(
                            relu.split_whitespace().collect::<Vec<_>>(),
                            reference.split_whitespace().collect::<Vec<_>>(),
                            "{cas} : contrôle, seules les espaces diffèrent"
                        );
                    }
                    if variante == "casse" {
                        assert!(relu.contains("after insert"), "{cas} : contrôle, le moteur range la casse telle quelle : {relu}");
                        assert!(relu.eq_ignore_ascii_case(&reference), "{cas} : contrôle, seule la casse diffère : {relu}");
                    }
                    objets
                };
                let archive = chemin(&racine, "archive.age");
                let st = backup_compressed(&src, &archive, Some(CLE), None).unwrap_or_else(|e| panic!("{cas} : sauvegarde : {e}"));
                assert_eq!(
                    noms_omis(&st),
                    vec![(crate::backup::GenreOmis::Declencheur, "event_ai".to_string())],
                    "{cas} : seul le quasi-homonyme est omis"
                );
                let charge = charge_en_clair(&archive);
                assert!(charge.starts_with(if entretien { &b"SQLite format 3\0"[..] } else { &b"PLUMEDUMP1\n"[..] }), "{cas} : format");
                assert!(!porte(&charge, "ck3autrecorps"), "{cas} : le corps du quasi-homonyme est dans la charge");
                let dest = chemin(&racine, "plume.db");
                restore_compressed(&archive, &dest, Some(CLE), false, None).unwrap_or_else(|e| panic!("{cas} : restauration refusée : {e}"));
                let dst = open_db_keyed(&dest, Some(CLE)).unwrap();
                let attendus: std::collections::BTreeSet<(String, String)> =
                    objets_de_la_tete.into_iter().filter(|(n, _)| n != "event_ai").collect();
                assert!(attendus.len() >= 4, "{cas} : contrôle, les autres déclencheurs de référence");
                assert_eq!(declencheurs_et_vues(&dst), attendus, "{cas} : la base publiée, sans event_ai");
            }
        }
    }

    /// UNE ERREUR DU MOTEUR PENDANT LE RETRAIT FAIT ÉCHOUER LA SAUVEGARDE AU FORMAT ANCIEN : sous le crochet
    /// `retrait_refuse_par_le_moteur` (mode défensif posé sur la connexion de l'export juste avant le retrait), le
    /// `DELETE` de `sqlite_master` est refusé ; la sauvegarde rend l'erreur du retrait, aucune archive n'est publiée,
    /// aucun temporaire ne reste, et la base vivante est intacte. Rouge si l'erreur est avalée (M16 : l'objet resterait
    /// dans une archive publiée tout en étant dit omis).
    #[test]
    fn une_erreur_du_moteur_pendant_le_retrait_fait_echouer_la_sauvegarde() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ck3-retrait-refuse");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        let (schema, objets, _) = source(&src, true, true);
        let archive = chemin(&racine, "archive.age");
        let refus = {
            let _refus = crate::backup::crochet_de_l_ecrivain::retrait_refuse_par_le_moteur();
            backup_compressed(&src, &archive, Some(CLE), None).map(|st| st.phrase_des_tailles())
        };
        let refus = refus.expect_err("la sauvegarde réussit malgré le retrait refusé par le moteur");
        assert!(refus.contains("retrait d'un déclencheur que la restauration refuserait"), "l'erreur du retrait : {refus}");
        assert!(!std::path::Path::new(&archive).exists(), "une archive est publiée");
        let restes: Vec<String> = std::fs::read_dir(&racine)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("archive"))
            .collect();
        assert!(restes.is_empty(), "un temporaire reste : {restes:?}");
        let relue = open_db_keyed(&src, Some(CLE)).unwrap();
        assert_eq!(declencheurs_et_vues(&relue), objets, "la base vivante a changé");
        assert_eq!(lignes_de(&relue, SCHEMA), schema, "le schéma de la base vivante a changé");
    }

    // ── C : LE CHEMIN NOMINAL À L'OCTET ────────────────────────────────────────────────────────────────

    /// UNE BASE SANS OBJET HORS RÉFÉRENCE PRODUIT LA MÊME CHARGE QU'AVANT, DANS LES DEUX FORMATS : la charge en clair de
    /// l'écrivain est égale, à l'octet, à celle d'un écrivain qui émet tout déclencheur et toute vue
    /// (`crochet_de_l_ecrivain::tout_emettre`, l'état d'avant) ; rien n'est omis, la ligne de résultat ne porte pas
    /// `omis=`, et la charge porte bien les déclencheurs de référence.
    #[test]
    fn une_base_sans_objet_hors_reference_produit_la_meme_charge_qu_avant() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        for entretien in [false, true] {
            let cas = if entretien { "ck3-c-ancien" } else { "ck3-c-courant" };
            let _tmp = crate::tmp_possede::TmpPossede::neuf(cas);
            let racine = _tmp.racine().chemin().to_path_buf();
            let src = chemin(&racine, "src.db");
            let (_, objets, _) = source(&src, entretien, false);
            assert_eq!(objets.len(), if entretien { 7 } else { 5 }, "{cas} : contrôle, les déclencheurs de référence");
            let archive = chemin(&racine, "archive.age");
            let st = backup_compressed(&src, &archive, Some(CLE), None).unwrap_or_else(|e| panic!("{cas} : {e}"));
            assert!(st.objets_omis.is_empty(), "{cas} : rien d'omis : {:?}", st.objets_omis);
            assert!(!st.phrase_des_tailles().contains("omis"), "{cas} : {}", st.phrase_des_tailles());
            let charge = charge_en_clair(&archive);
            let avant = {
                let _ecrivain = crate::backup::crochet_de_l_ecrivain::tout_emettre();
                let archive_avant = chemin(&racine, "archive-avant.age");
                backup_compressed(&src, &archive_avant, Some(CLE), None).unwrap_or_else(|e| panic!("{cas} : {e}"));
                charge_en_clair(&archive_avant)
            };
            for (nom, _) in &objets {
                assert!(porte(&charge, nom), "{cas} : contrôle, la charge porte {nom}");
            }
            assert!(charge == avant, "{cas} : la charge diffère de celle de l'écrivain d'avant ({} o contre {} o)", charge.len(), avant.len());
        }
    }

    // ── B : CE QUE L'EXPLOITANT LIT ────────────────────────────────────────────────────────────────────

    const J_ENFANT: &str = "PLUME_TEST_CK3_JOURNAL_ENFANT";
    const J_PHASE: &str = "CK3-PHASE:";
    const J_PHASES: [&str; 9] =
        ["courant", "ancien", "nominal", "nominal_ancien", "forge", "borne", "borne_plus", "renommage_refuse", "planifie"];

    /// Le nom forgé d'une vue : `\n`, `\r`, le guillemet et (par `writable_schema`, le moteur refusant un NUL dans un
    /// identifiant écrit) un NUL, chacun suivi d'un faux préfixe de journal.
    const NOM_FORGE_SQL: &str = "\"ck3\n[backup] X\r[backup] Y\"\"[backup] Z\"";
    const NOM_FORGE_ECHAPPE: &str = "\"ck3\\n[backup] X\\r[backup] Y\\\"[backup] Z\\0[backup] W\"";

    /// Une petite base : une table `t` et les vues `noms` (créées dans cet ordre), sans déclencheur.
    fn base_aux_vues(src: &str, noms: &[String]) {
        let c = open_db_keyed(src, Some(CLE)).unwrap();
        c.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t VALUES('ck3');").unwrap();
        for nom in noms {
            c.execute_batch(&format!("CREATE VIEW \"{}\" AS SELECT v FROM t", nom.replace('"', "\"\""))).unwrap();
        }
    }

    fn vues_de_borne(n: usize, longue: &str) -> Vec<String> {
        let mut noms: Vec<String> = (1..n).map(|i| format!("ck3_v{i}")).collect();
        noms.insert(n.min(7), longue.to_string());
        noms
    }

    /// LA LIGNE `[backup]` ET L'AVEU DU RÉSULTAT, SUR LE STDERR RÉEL D'UN SOUS-PROCESSUS, ligne ENTIÈRE :
    ///  * `courant`, `ancien` : la base aux deux étrangers, dans chaque format -> une seule ligne qui les nomme ;
    ///  * `nominal`, `nominal_ancien` : la base de la tête sans étranger -> aucune ligne `[backup]` neuve ;
    ///  * `forge` : une vue au nom porteur de `\n`, `\r`, d'un guillemet et d'un NUL -> une seule ligne, nom échappé,
    ///    aucune ligne qui commence par un faux préfixe ;
    ///  * `borne` : huit vues, dont une au nom de 64 caractères multioctets -> huit noms, celui-là entier, rien de plus ;
    ///  * `borne_plus` : neuf vues, dont une au nom de 65 caractères -> huit noms, celui-là coupé à 64 caractères puis `…`,
    ///    et `, et 1 de plus` ;
    ///  * `renommage_refuse` : la base aux deux étrangers, vers une destination qui est un répertoire non vide (le
    ///    `rename` de `backup_compressed` échoue) -> la sauvegarde échoue et AUCUNE ligne `[backup]` d'objets omis n'est
    ///    écrite : la ligne ne part qu'une fois l'archive renommée sur la destination de `backup_compressed` (pas après la
    ///    publication finale par un appelant qui renomme ou retire ensuite cette destination) ;
    ///  * `planifie` : le cycle de l'ordonnanceur natif sur la base aux deux étrangers -> sa ligne `[backup-sched] écrit …`
    ///    porte `omis=2 (…)` avant `clair-sur-disque=non`, et la ligne `[backup]` est écrite une fois.
    #[test]
    fn la_ligne_du_journal_et_le_resultat_disent_les_objets_omis() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        if std::env::var(J_ENFANT).is_ok() {
            for phase in J_PHASES {
                eprintln!("{J_PHASE}{phase}");
                let _tmp = crate::tmp_possede::TmpPossede::neuf(&format!("ck3-j-{phase}"));
                let racine = _tmp.racine().chemin().to_path_buf();
                let src = chemin(&racine, "src.db");
                let archive = chemin(&racine, "archive.age");
                match phase {
                    "courant" | "ancien" => drop(source(&src, phase == "ancien", true)),
                    "nominal" | "nominal_ancien" => drop(source(&src, phase == "nominal_ancien", false)),
                    "forge" => {
                        let c = open_db_keyed(&src, Some(CLE)).unwrap();
                        c.execute_batch(&format!(
                            "CREATE TABLE t(v TEXT); CREATE VIEW {NOM_FORGE_SQL} AS SELECT v FROM t; PRAGMA writable_schema=ON; \
                             UPDATE sqlite_master SET name = name || char(0) || '[backup] W' WHERE type = 'view'; \
                             PRAGMA writable_schema=OFF;"
                        ))
                        .unwrap();
                    }
                    "borne" => base_aux_vues(&src, &vues_de_borne(8, &"é".repeat(64))),
                    "borne_plus" => base_aux_vues(&src, &vues_de_borne(9, &"é".repeat(65))),
                    "renommage_refuse" => {
                        drop(source(&src, false, true));
                        std::fs::create_dir_all(chemin(&racine, "archive.age/occupe")).unwrap();
                        let echec = backup_compressed(&src, &archive, Some(CLE), None).map(|st| st.objets_omis.len());
                        println!("CK3-RENOMMAGE-{phase}:{}", echec.is_err());
                        continue;
                    }
                    _ => {
                        drop(source(&src, false, true));
                        let dest_dir = chemin(&racine, "archives");
                        std::fs::create_dir_all(&dest_dir).unwrap();
                        let publie = crate::server::scheduled_backup_cycle(&src, &dest_dir, 3, Some(CLE), None);
                        println!("CK3-PUBLIE-{phase}:{}", publie.is_some());
                        continue;
                    }
                }
                let st = backup_compressed(&src, &archive, Some(CLE), None).unwrap_or_else(|e| panic!("{phase} : {e}"));
                println!("CK3-BILAN-{phase}:{}:{}", st.objets_omis.len(), st.phrase_des_tailles());
            }
            eprintln!("{J_PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ck3_sauvegarde_objets_hors_reference_omis_et_dits::la_ligne_du_journal_et_le_resultat_disent_les_objets_omis",
            ])
            .env(J_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(!stderr.contains('\0') && !stderr.contains('\r'), "aucun NUL ni retour chariot brut au journal : {stderr:?}");
        // Les lignes `[backup]` de la phase, hors des deux qui existaient avant (repli symétrique, repli vers le format
        // ancien) ; une ligne forgée qui commencerait par un faux préfixe y serait aussi.
        let lignes_de_la_phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{J_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(J_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps
                .lines()
                .filter(|l| l.starts_with("[backup]") && !l.starts_with("[backup] ATTENTION") && !l.starts_with("[backup] schéma non-B1"))
                .map(str::to_string)
                .collect()
        };
        let bilan = |nom: &str| -> String {
            stdout
                .lines()
                .find_map(|l| l.split_once(&format!("CK3-BILAN-{nom}:")).map(|(_, r)| r))
                .unwrap_or_else(|| panic!("contrôle : bilan {nom} : {stdout}"))
                .to_string()
        };
        for phase in ["courant", "ancien"] {
            assert_eq!(lignes_de_la_phase(phase), vec![ligne_attendue(2, NOMS_DES_ETRANGERS)], "{phase} : {stderr}");
            assert!(bilan(phase).starts_with("2:charge="), "{phase} : {}", bilan(phase));
            assert!(bilan(phase).ends_with(&format!("  omis=2 ({PHRASE_DU_RESULTAT})")), "{phase} : {}", bilan(phase));
        }
        for phase in ["nominal", "nominal_ancien"] {
            assert_eq!(lignes_de_la_phase(phase), Vec::<String>::new(), "{phase} : aucune ligne neuve : {stderr}");
            assert!(bilan(phase).starts_with("0:charge=") && !bilan(phase).contains("omis"), "{phase} : {}", bilan(phase));
        }
        assert_eq!(lignes_de_la_phase("forge"), vec![ligne_attendue(1, &format!("vue {NOM_FORGE_ECHAPPE}"))], "forge : {stderr}");
        assert!(
            !stderr.lines().any(|l| ["[backup] X", "[backup] Y", "[backup] Z", "[backup] W"].iter().any(|p| l.starts_with(p))),
            "forge : une ligne forgée : {stderr}"
        );
        let e64 = "é".repeat(64);
        let noms = |n: usize, longue: &str| -> String {
            vues_de_borne(n, longue).iter().take(8).map(|v| format!("vue \"{v}\"")).collect::<Vec<_>>().join(", ")
        };
        assert_eq!(lignes_de_la_phase("borne"), vec![ligne_attendue(8, &noms(8, &e64))], "borne : {stderr}");
        let attendue_plus = ligne_attendue(9, &format!("{}, et 1 de plus", noms(9, &e64).replace(&format!("\"{e64}\""), &format!("\"{e64}\"…"))));
        assert_eq!(lignes_de_la_phase("borne_plus"), vec![attendue_plus], "borne_plus : {stderr}");
        assert!(stdout.contains("CK3-RENOMMAGE-renommage_refuse:true"), "renommage_refuse : contrôle, la sauvegarde échoue : {stdout}");
        assert_eq!(lignes_de_la_phase("renommage_refuse"), Vec::<String>::new(), "renommage_refuse : une ligne avant le rename : {stderr}");
        // L'ordonnanceur : sa ligne de résultat, et la ligne `[backup]`.
        assert!(stdout.contains("CK3-PUBLIE-planifie:true"), "planifie : l'archive est publiée : {stdout}");
        assert_eq!(lignes_de_la_phase("planifie"), vec![ligne_attendue(2, NOMS_DES_ETRANGERS)], "planifie : {stderr}");
        let debut = stderr.split_once(&format!("{J_PHASE}planifie\n")).unwrap().1;
        let ecrit: Vec<&str> = debut.lines().filter(|l| l.starts_with("[backup-sched] écrit ")).collect();
        assert_eq!(ecrit.len(), 1, "planifie : une ligne de résultat : {stderr}");
        assert!(
            ecrit[0].ends_with(&format!("  omis=2 ({PHRASE_DU_RESULTAT})  clair-sur-disque=non")),
            "planifie : la ligne de l'ordonnanceur porte l'aveu : {}",
            ecrit[0]
        );
    }

    // ── LA BRANCHE HORS D'ATTEINTE ─────────────────────────────────────────────────────────────────────

    /// SANS ENSEMBLE DE RÉFÉRENCE (branche hors d'atteinte par une base, `crochet_de_l_ecrivain::sans_ensemble_de_reference`)
    /// L'ÉCRIVAIN OMET TOUT DÉCLENCHEUR ET TOUTE VUE, comme la restauration les refuserait tous ; la sauvegarde réussit,
    /// les cinq déclencheurs de la tête sont dits omis, et l'archive se restaure avec toutes ses lignes.
    #[test]
    fn sans_ensemble_de_reference_tout_est_omis_et_la_sauvegarde_reussit() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ck3-sans-ensemble");
        let racine = _tmp.racine().chemin().to_path_buf();
        let src = chemin(&racine, "src.db");
        let (_, objets, evenements) = source(&src, false, false);
        let archive = chemin(&racine, "archive.age");
        let st = {
            let _sans = crate::backup::crochet_de_l_ecrivain::sans_ensemble_de_reference();
            backup_compressed(&src, &archive, Some(CLE), None).expect("sauvegarde")
        };
        let mut omis: Vec<String> = st.objets_omis.iter().map(|o| o.nom.clone()).collect();
        omis.sort();
        let attendus: Vec<String> = objets.iter().map(|(n, _)| n.clone()).collect();
        assert_eq!(attendus.len(), 5, "contrôle : les cinq déclencheurs de la tête");
        assert_eq!(omis, attendus, "tous omis");
        let dest = chemin(&racine, "plume.db");
        restore_compressed(&archive, &dest, Some(CLE), false, None).unwrap_or_else(|e| panic!("restauration : {e}"));
        let dst = open_db_keyed(&dest, Some(CLE)).unwrap();
        assert!(declencheurs_et_vues(&dst).is_empty(), "aucun déclencheur dans la base publiée");
        assert_eq!(lignes_de(&dst, "SELECT * FROM event"), evenements);
    }

    // ── E : LE COÛT ────────────────────────────────────────────────────────────────────────────────────

    /// CE QUE PAIE LA PREMIÈRE SAUVEGARDE D'UN PROCESSUS : la construction de l'ensemble de référence, mesurée ici sur
    /// le banc (écrite au journal du test, aucune borne d'horloge affirmée) ; les appels suivants rendent le MÊME
    /// ensemble, sans le reconstruire (même adresse).
    #[test]
    fn l_ensemble_de_reference_se_construit_une_fois_par_processus() {
        let debut = std::time::Instant::now();
        let construit = crate::migrate::construire_les_declencheurs_et_vues_de_reference().expect("construction");
        eprintln!("CK3-COUT : construction de l'ensemble de référence : {} ms", debut.elapsed().as_millis());
        let a = crate::migrate::declencheurs_et_vues_de_reference().expect("ensemble");
        let b = crate::migrate::declencheurs_et_vues_de_reference().expect("ensemble");
        assert!(std::ptr::eq(a, b), "le même ensemble, jamais reconstruit");
        assert_eq!(*a, construit, "l'ensemble mémoïsé est celui que la construction rend");
    }

    thread_local! {
        /// Les connexions EN MÉMOIRE ouvertes par ce fil pendant que le compteur y est armé (`Some`) ; `None` hors mesure.
        static OUVERTURES_EN_MEMOIRE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    }

    /// Appelée par le moteur à chaque ouverture de connexion du processus (`sqlite3_auto_extension`) : compte, pour le
    /// seul fil armé, les connexions dont la base principale n'a pas de fichier (en mémoire). Rend toujours `SQLITE_OK`.
    unsafe extern "C" fn compter_une_ouverture_en_memoire(
        db: *mut rusqlite::ffi::sqlite3,
        _erreur: *mut *const std::os::raw::c_char,
        _routines: *const rusqlite::ffi::sqlite3_api_routines,
    ) -> std::os::raw::c_int {
        let fichier = rusqlite::ffi::sqlite3_db_filename(db, b"main\0".as_ptr().cast());
        if fichier.is_null() || *fichier == 0 {
            let _ = OUVERTURES_EN_MEMOIRE.try_with(|c| c.set(c.get().map(|n| n + 1)));
        }
        rusqlite::ffi::SQLITE_OK
    }

    /// Le crochet posé pour la durée du témoin, retiré au `Drop`.
    struct CompteurDesOuverturesEnMemoire;
    impl CompteurDesOuverturesEnMemoire {
        fn armer() -> Self {
            let rc = unsafe { rusqlite::ffi::sqlite3_auto_extension(Some(compter_une_ouverture_en_memoire)) };
            assert_eq!(rc, rusqlite::ffi::SQLITE_OK, "contrôle : crochet d'ouverture posé");
            CompteurDesOuverturesEnMemoire
        }
        /// Le résultat de `geste` et le nombre de connexions en mémoire que ce fil a ouvertes pendant lui.
        fn compter<T>(&self, geste: impl FnOnce() -> T) -> (T, u64) {
            OUVERTURES_EN_MEMOIRE.with(|c| c.set(Some(0)));
            let r = geste();
            let n = OUVERTURES_EN_MEMOIRE.with(|c| c.replace(None)).expect("contrôle : compteur armé");
            (r, n)
        }
    }
    impl Drop for CompteurDesOuverturesEnMemoire {
        fn drop(&mut self) {
            unsafe { rusqlite::ffi::sqlite3_cancel_auto_extension(Some(compter_une_ouverture_en_memoire)) };
        }
    }

    /// L'ÉCRIVAIN NE RECONSTRUIT L'ENSEMBLE DE RÉFÉRENCE NI À CHAQUE OBJET NI À CHAQUE SAUVEGARDE : la construction ouvre
    /// une base en mémoire, que compte un crochet d'ouverture limité au fil du témoin (contrôle : une construction directe
    /// en ouvre au moins une). Trois vraies sauvegardes, dans les deux formats, de bases qui portent les déclencheurs de
    /// la tête plus six déclencheurs et six vues étrangers, tous jugés par la règle : la première du processus n'ouvre
    /// pas plus de bases en mémoire qu'une construction (celle de l'ensemble, s'il n'était pas encore construit), les deux
    /// suivantes n'en ouvrent aucune. Rouge si l'écrivain reconstruit l'ensemble à chaque déclencheur ou vue jugé (A5).
    #[test]
    fn l_ecrivain_ne_reconstruit_l_ensemble_de_reference_ni_par_objet_ni_par_sauvegarde() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let compteur = CompteurDesOuverturesEnMemoire::armer();
        let (construit, par_construction) = compteur.compter(crate::migrate::construire_les_declencheurs_et_vues_de_reference);
        construit.expect("construction");
        assert!(par_construction >= 1, "contrôle : le crochet voit la base en mémoire d'une construction ({par_construction})");
        let _tmp = crate::tmp_possede::TmpPossede::neuf("ck3-cout-ecrivain");
        let racine = _tmp.racine().chemin().to_path_buf();
        let mut ouvertures = Vec::new();
        for (i, entretien) in [false, true, false].into_iter().enumerate() {
            let src = chemin(&racine, &format!("src{i}.db"));
            {
                let c = open_db_keyed(&src, Some(CLE)).unwrap();
                base_de_la_tete(&c, entretien);
                for k in 0..6 {
                    c.execute_batch(&format!(
                        "CREATE TRIGGER ck3_cout_d{k} AFTER UPDATE ON event BEGIN SELECT {k}; END; \
                         CREATE VIEW ck3_cout_v{k} AS SELECT id FROM event WHERE severity = {k};"
                    ))
                    .unwrap();
                }
            }
            let archive = chemin(&racine, &format!("archive{i}.age"));
            let (st, n) = compteur.compter(|| backup_compressed(&src, &archive, Some(CLE), None));
            let st = st.unwrap_or_else(|e| panic!("sauvegarde {i} : {e}"));
            assert_eq!(st.objets_omis.len(), 12, "sauvegarde {i} : contrôle, les douze étrangers jugés et omis");
            ouvertures.push(n);
        }
        eprintln!("CK3-COUT : bases en mémoire ouvertes par construction {par_construction}, par sauvegarde {ouvertures:?}");
        assert!(ouvertures[0] <= par_construction, "la première sauvegarde construit plus d'un ensemble : {ouvertures:?}");
        assert_eq!(ouvertures[1..], [0, 0], "une sauvegarde suivante reconstruit l'ensemble : {ouvertures:?}");
    }
}

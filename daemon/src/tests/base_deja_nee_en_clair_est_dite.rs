// `P10.33-g` (reste) — UNE BASE DÉJÀ NÉE EN CLAIR, SANS AUCUNE CLÉ, SE DIT À CHAQUE OUVERTURE
// ================================================================================================
// LE DÉFAUT, RE-MESURÉ PAR LECTURE SUR 1d9ba63c. `decision_at_rest` rend `RienAFaire` pour toute base
// existante quand aucune clé n'est configurée (bras `(false, false, _)`), `ensure_encrypted` ne sonde
// rien sans clé, et le seul signal de la porte (`signaler_la_cle_auto_si_besoin`) ne vise que la clé
// auto non mise à l'abri : une base EN CLAIR — antérieure à `P9.6-a`, née par une sous-commande avant
// la garde `refuser_une_base_absente`, ou restaurée en clair — tournait sans un mot.
//
// LA DÉCISION (exploitant, 2026-10-16) : AVEU FORT, JAMAIS DE REFUS. Le clair sans clé est le mode
// rétrocompatible supporté ; refuser casserait toute installation en clair voulue. Le levier
// `PLUME_DB_EN_CLAIR_ASSUME` (1/true/yes/on, lu par `cfg()`) DÉCLARE le clair voulu et fait taire
// l'aveu. Une clé présente (explicite ou auto) : silence — la base est chiffrée, ou le démarrage la
// refuse déjà en nommant le geste.
//
// MUTANTS JOUÉS (variable de mutation sous cfg!(test), retirés du source avant le commit) : `entete_non_lu` (en-tête jamais
// établi), `absent_pris_pour_clair`, `chiffre_pris_pour_clair`, `levier_ignore`, `cle_auto_absente`
// (clé auto comptée comme absente), `dedup_retiree`, `purgeable` (origin hors 'daemon'),
// `journal_a_chaque_fois`, `refus_au_demarrage` (exit 78 introduit à la porte) ; puis, en correction,
// `conf_vide` (la porte ne lit plus `load_config()` : le levier écrit dans le seul fichier
// `PLUME_CONFIG` du mode natif est ignoré) -> rouge sur le témoin ⑥.
//
// CE QUE CE FICHIER NE TIENT PAS : la ligne de journal du processus n'est jugée que par sa porte
// (`premiere_fois_dans_ce_processus`, drapeau local), pas sur la sortie d'erreur d'un sous-processus —
// contourner cette porte dans `signaler_la_base_en_clair_selon` laisse les témoins verts (chaque
// processus de production n'ouvre la porte d'écriture qu'une fois, donc sans effet observable
// aujourd'hui) ; les bases de TENANT ne sont pas couvertes : elles s'ouvrent par `open_keyed`, qui ne
// passe pas par l'aveu, alors que `resolve_tenant_key` peut rendre « pas de clé » (mode multi-tenant
// désactivé par défaut) ;
// la déduplication par la porte réelle n'est jugée que si les deux ouvertures tombent dans la même
// heure (la propriété elle-même est tenue, instant injecté, par le témoin de l'émetteur).
mod base_deja_nee_en_clair_est_dite {
    use super::*;

    const BNC_MOTIF: &str = "BASE EN CLAIR SUR LE DISQUE%";

    fn bnc_conf(paires: &[(&str, &str)]) -> HashMap<String, String> {
        paires.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn bnc_aveux(conn: &Connection) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM event WHERE message LIKE ?1 AND source='plume-config' AND category='health'",
            params![BNC_MOTIF],
            |r| r.get(0),
        )
        .unwrap()
    }

    // ── ① L'AIDE PURE, TOUTES LES COMBINAISONS ────────────────────────────────────────────────────

    #[test]
    fn p1033g_l_aide_ne_parle_que_sans_cle_sur_un_en_tete_en_clair_et_sans_declaration() {
        let en_tetes = [EnTeteDeLaBase::EnClair, EnTeteDeLaBase::AutreContenu, EnTeteDeLaBase::NonEtabli];
        let mut vrais = Vec::new();
        for cle in [false, true] {
            for e in en_tetes {
                for assume in [false, true] {
                    if base_en_clair_a_signaler(cle, e, assume) {
                        vrais.push((cle, e, assume));
                    }
                }
            }
        }
        assert_eq!(vrais, vec![(false, EnTeteDeLaBase::EnClair, false)],
            "l'aveu part SSI aucune clé, en-tête en clair, et clair non déclaré — rien d'autre");
    }

    // ── ② L'EN-TÊTE, SUR DE VRAIS FICHIERS ────────────────────────────────────────────────────────

    #[test]
    fn p1033g_l_en_tete_est_etabli_sur_les_octets_et_une_mesure_ratee_ne_conclut_pas() {
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033g-entete");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let p = |n: &str| dir.join(n).to_string_lossy().into_owned();

        let clair = p("clair.db");
        {
            let c = open_db_keyed(&clair, None).unwrap();
            c.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES('v');").unwrap();
        }
        assert_eq!(en_tete_de_la_base(&clair), EnTeteDeLaBase::EnClair, "base créée sans clé : EN CLAIR");

        let chiffree = p("chiffree.db");
        {
            let c = open_db_keyed(&chiffree, Some("cle-de-temoin-p1033g")).unwrap();
            c.execute_batch("CREATE TABLE t(x TEXT); INSERT INTO t VALUES('v');").unwrap();
        }
        assert_ne!(&std::fs::read(&chiffree).unwrap()[..16], b"SQLite format 3\0", "fixture : chiffrée");
        assert_eq!(en_tete_de_la_base(&chiffree), EnTeteDeLaBase::AutreContenu,
            "une base CHIFFRÉE n'a pas l'en-tête : elle ne doit jamais être prise pour du clair");

        let vide = p("vide.db");
        std::fs::write(&vide, b"").unwrap();
        let court = p("court.db");
        std::fs::write(&court, b"SQLite form").unwrap();
        for (cas, chemin) in [("absent", p("absent.db")), ("vide", vide), ("court", court), ("répertoire", p(""))] {
            assert_eq!(en_tete_de_la_base(&chemin), EnTeteDeLaBase::NonEtabli,
                "{cas} : la mesure n'établit rien, elle ne conclut pas");
        }
    }

    // ── ③ L'ÉMETTEUR : NON PURGEABLE, DÉDUPLIQUÉ À L'HEURE, ET IL DIT CE QU'IL FAUT ───────────────

    #[test]
    fn p1033g_l_aveu_est_non_purgeable_dedupe_a_l_heure_et_ne_porte_ni_valeur_ni_chemin() {
        let conn = test_db();
        let t0 = 1_800_000_000i64;
        assert!(emit_base_en_clair(&conn, t0), "premier aveu écrit");
        assert!(!emit_base_en_clair(&conn, t0 + 60), "même heure -> dédupliqué");
        assert!(emit_base_en_clair(&conn, t0 + 3600), "heure suivante -> un aveu");
        assert_eq!(bnc_aveux(&conn), 2, "deux heures, deux lignes");

        let purgeables: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM event WHERE message LIKE ?1 AND {RETENTION_NONPURGE}"),
                params![BNC_MOTIF],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(purgeables, 0, "le prédicat de rétention du PRODUIT ne doit pouvoir effacer aucun aveu");

        let (sev, org, msg, champs): (i64, String, String, String) = conn
            .query_row(
                "SELECT severity, origin, message, fields FROM event WHERE message LIKE ?1 LIMIT 1",
                params![BNC_MOTIF],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!((sev, org.as_str()), (4, "daemon"));
        for attendu in ["`sqlite3` nu", "NE PROTÈGE PAS", "chiffrer-au-repos", CLE_DB_EN_CLAIR_ASSUME, CLE_DB_KEY_ESCROWED] {
            assert!(msg.contains(attendu), "l'aveu doit dire « {attendu} » : {msg}");
        }
        assert!(!msg.contains('/') && !champs.contains('/'), "aucun chemin dans l'aveu : {msg} {champs}");
    }

    #[test]
    fn p1033g_la_ligne_de_journal_ne_part_qu_une_fois_par_processus() {
        let drapeau = std::sync::atomic::AtomicBool::new(false);
        assert!(premiere_fois_dans_ce_processus(&drapeau), "première ouverture : la ligne part");
        assert!(!premiere_fois_dans_ce_processus(&drapeau), "seconde : rien");
        assert!(!premiere_fois_dans_ce_processus(&drapeau), "troisième : rien");
    }

    // ── ④ L'ADAPTATEUR, SUR DE VRAIS FICHIERS ET UNE CONFIGURATION INJECTÉE ──────────────────────

    #[test]
    fn p1033g_une_base_en_clair_sans_cle_est_dite_et_une_cle_ou_une_declaration_la_font_taire() {
        // `cfg()` lit l'environnement AVANT la table : ⑥ y pose `PLUME_DB_KEY_AUTO_PATH` et `PLUME_DB_EN_CLAIR_ASSUME`
        // sous le verrou en écriture ; ce témoin le prend en lecture, sinon il rougit sous `cargo test` (threads).
        let _env = VERROU_ENV_PROCESSUS.read();
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033g-adaptateur");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let p = |n: &str| dir.join(n).to_string_lossy().into_owned();
        let t = 1_800_000_000i64;

        // Base EN CLAIR au schéma réel, sans signal ambiant (`open_keyed` ne passe pas par l'aveu).
        let clair = p("clair.db");
        let conn = crate::db_open::PreparedDb::open_keyed(&clair, None).expect("base en clair préparée");
        let conf = bnc_conf(&[("PLUME_DB", clair.as_str())]);
        assert!(base_en_clair_a_signaler_depuis(&conf, &clair), "aucune clé, en clair, rien déclaré -> aveu");
        assert!(signaler_la_base_en_clair_selon(&conn, &conf, t), "l'aveu est écrit, et rien n'est refusé");
        assert!(!signaler_la_base_en_clair_selon(&conn, &conf, t + 60), "même heure : pas de seconde ligne");
        assert_eq!(bnc_aveux(&conn), 1);

        // La DÉCLARATION fait taire ; toutes les formes du drapeau, et seulement elles.
        for oui in ["1", "true", "YES", "on"] {
            let c = bnc_conf(&[("PLUME_DB", clair.as_str()), (CLE_DB_EN_CLAIR_ASSUME, oui)]);
            assert!(!base_en_clair_a_signaler_depuis(&c, &clair), "déclaré par `{oui}` -> silence");
        }
        for non in ["", "0", "non"] {
            let c = bnc_conf(&[("PLUME_DB", clair.as_str()), (CLE_DB_EN_CLAIR_ASSUME, non)]);
            assert!(base_en_clair_a_signaler_depuis(&c, &clair), "`{non}` ne déclare rien -> aveu");
        }

        // Une clé EXPLICITE : silence (le démarrage refuse déjà, `RefusConversionRequise`).
        let c = bnc_conf(&[("PLUME_DB", clair.as_str()), ("PLUME_DB_KEY", "cle-apportee-p1033g")]);
        assert!(!base_en_clair_a_signaler_depuis(&c, &clair), "clé explicite -> silence");

        // Une clé AUTO présente à côté d'une base en clair : silence aussi (`RefusCleAutoOrpheline`).
        let auto = p("orpheline.key");
        cle_auto_engendrer(&auto).unwrap();
        let c = bnc_conf(&[("PLUME_DB", clair.as_str()), ("PLUME_DB_KEY_AUTO_PATH", auto.as_str())]);
        assert_eq!(en_tete_de_la_base(&clair), EnTeteDeLaBase::EnClair, "la base est toujours en clair");
        assert!(!base_en_clair_a_signaler_depuis(&c, &clair), "clé auto présente -> elle compte comme une clé");

        // Fichier absent ou vide : on ne conclut pas.
        let vide = p("vide.db");
        std::fs::write(&vide, b"").unwrap();
        for chemin in [p("absente.db"), vide] {
            let c = bnc_conf(&[("PLUME_DB", chemin.as_str())]);
            assert!(!base_en_clair_a_signaler_depuis(&c, &chemin), "{chemin} : rien d'établi, rien de dit");
        }

        // CONTRE-ÉPREUVE : la base NÉE CHIFFRÉE par la naissance du démon (même geste que
        // `p96a_une_base_absente_nait_chiffree_et_sa_cle_est_en_0600`) ne dit rien.
        let neuve = p("neuve.db");
        let conf_neuve = bnc_conf(&[("PLUME_DB", neuve.as_str())]);
        ensure_encrypted(&conf_neuve, &neuve);
        let cle = cle_auto_lire(&cle_auto_chemin(&conf_neuve)).expect("clé auto engendrée");
        let cn = crate::db_open::PreparedDb::open_keyed(&neuve, Some(&cle)).expect("base née chiffrée");
        assert_eq!(en_tete_de_la_base(&neuve), EnTeteDeLaBase::AutreContenu, "née chiffrée : pas d'en-tête");
        assert!(!signaler_la_base_en_clair_selon(&cn, &conf_neuve, t), "base née chiffrée -> silence");
        assert_eq!(bnc_aveux(&cn), 0);
    }

    // ── ⑤ LE POINT D'ENTRÉE : LA PORTE, SUR UNE INSTALLATION EN CLAIR ────────────────────────────

    /// La porte (`PreparedDb::open`, configuration ambiante) sur une base née en clair : elle OUVRE
    /// toujours (jamais de refus), et l'aveu est dans la base.
    #[test]
    fn p1033g_la_porte_ouvre_une_base_en_clair_et_y_ecrit_l_aveu_sans_jamais_refuser() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let ambiante = load_config();
        if db_key().is_some() || base_en_clair_declaree(&ambiante) {
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "p1033g_la_porte_ouvre_une_base_en_clair_et_y_ecrit_l_aveu_sans_jamais_refuser",
                "la configuration ambiante porte une clé at-rest ou déclare le clair voulu : la porte \
                 sans clé n'a PAS été exercée sur cette machine.",
            );
            return;
        }
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033g-porte");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("plume.db").to_string_lossy().into_owned();

        drop(crate::db_open::PreparedDb::open(&base).expect("naissance par la porte, sans clé"));
        assert_eq!(en_tete_de_la_base(&base), EnTeteDeLaBase::EnClair, "fixture : la base est née EN CLAIR");

        let heure_avant = now() / 3600;
        let n1 = {
            let db = crate::db_open::PreparedDb::open(&base).expect("une base en clair n'est JAMAIS refusée");
            bnc_aveux(&db)
        };
        assert!(n1 >= 1, "la porte a ouvert une base en clair sans clé et n'a rien dit");
        let n2 = {
            let db = crate::db_open::PreparedDb::open(&base).expect("seconde ouverture : toujours ouverte");
            bnc_aveux(&db)
        };
        if now() / 3600 == heure_avant {
            assert_eq!(n2, n1, "une seconde ouverture dans la même heure ne double pas l'aveu");
        }
    }

    // ── ⑥ LE LEVIER POSÉ DANS LE SEUL FICHIER `PLUME_CONFIG` (MODE NATIF), PAR LA PORTE RÉELLE ────

    /// En hôte natif, l'unité systemd pose `PLUME_CONFIG` et la déclaration vit dans ce fichier, pas
    /// dans l'environnement. La porte (`PreparedDb::open`) doit la lire là : sinon l'aveu repartirait à
    /// chaque démarrage d'une installation qui a pourtant déclaré son clair voulu. Contre-épreuves : le
    /// même fichier SANS le levier fait parler la porte (le fichier lu n'est pas un leurre), et
    /// l'environnement à `0` passe devant le fichier (`env > fichier`, contrat de `cfg()`).
    #[test]
    fn p1033g_le_levier_pose_dans_le_seul_fichier_plume_config_fait_taire_la_porte() {
        let _env = VERROU_ENV_PROCESSUS.write(); // ce test POSE `PLUME_CONFIG` et retire les clés -> exclut les lecteurs
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p1033g-levier-natif");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let p = |n: &str| dir.join(n).to_string_lossy().into_owned();

        // Aucune clé d'aucune sorte, quel que soit l'environnement de celui qui lance la suite : la clé
        // auto pointe un chemin ABSENT du dossier du témoin (posé par l'environnement, donc vu à
        // l'identique même si la porte cessait de lire le fichier).
        let _sans_fichier_de_cle = ReglageBackupPose::retire(CLE_DB_KEY_FILE);
        let _sans_cle = ReglageBackupPose::retire(CLE_DB_KEY);
        let _sans_declaration_env = ReglageBackupPose::retire(CLE_DB_EN_CLAIR_ASSUME);
        let auto_absente = p("aucune-cle-auto.key");
        let _auto = ReglageBackupPose::neuf(CLE_DB_KEY_AUTO_PATH, &auto_absente);

        let avec_levier = p("plume-avec-levier.conf");
        std::fs::write(&avec_levier, format!("# mode natif\n{CLE_DB_EN_CLAIR_ASSUME}=1\n")).unwrap();
        let sans_levier = p("plume-sans-levier.conf");
        std::fs::write(&sans_levier, "# mode natif, rien de déclaré\n").unwrap();

        // Une base EN CLAIR neuve par cas (la déduplication horaire ne mêle pas les cas) ; `open_keyed`
        // la prépare sans passer par l'aveu, puis LA PORTE l'ouvre sous la configuration du cas.
        let aveux_par_la_porte = |nom: &str, conf: &str| -> i64 {
            let base = p(nom);
            drop(crate::db_open::PreparedDb::open_keyed(&base, None).expect("base en clair préparée"));
            assert_eq!(en_tete_de_la_base(&base), EnTeteDeLaBase::EnClair, "fixture {nom} : base EN CLAIR");
            let _conf = ReglageBackupPose::neuf("PLUME_CONFIG", conf);
            assert!(db_key().is_none(), "contrôle {nom} : aucune clé at-rest résolue");
            let db = crate::db_open::PreparedDb::open(&base).expect("une base en clair n'est JAMAIS refusée");
            bnc_aveux(&db)
        };

        assert_eq!(aveux_par_la_porte("natif-declare.db", &avec_levier), 0,
            "levier à 1 dans le seul fichier PLUME_CONFIG : la porte doit se taire (mode natif)");
        assert!(aveux_par_la_porte("natif-non-declare.db", &sans_levier) >= 1,
            "contre-épreuve : le même fichier sans le levier, et la porte doit parler");
        let _env_zero = ReglageBackupPose::neuf(CLE_DB_EN_CLAIR_ASSUME, "0");
        assert!(aveux_par_la_porte("env-a-zero.db", &avec_levier) >= 1,
            "l'environnement à 0 passe devant le fichier (env > fichier) : la porte doit parler");
    }
}

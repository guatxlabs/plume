// P8.3-a — L'EXERCICE DE RESTAURATION : CE QUI EST PROUVÉ, ET CE QUI NE PEUT PAS L'ÊTRE ICI.
// ================================================================================================
// LE DÉFAUT NOMMÉ PAR LA CLÉ. Une sauvegarde dont aucune ligne n'a jamais été restaurée est une
// garantie non éprouvée, et le pire n'est pas de ne pas restaurer : c'est de croire que la
// restauration est couverte parce qu'un contrôle vert porte le mot « restore ». La vérification
// automatisée annonçait « déchiffre + ouvre la DB » ; elle restaurait vers une base jetable qu'elle
// n'ouvrait jamais. Un dump correctement chiffré, correctement rejoué, mais VIDE, en sortait vert.
//
// CE QUI RESTE HORS DE PORTÉE, ET POURQUOI C'EST DÉLIBÉRÉ. Le mode recommandé chiffre les archives
// pour un DESTINATAIRE age dont l'identité privée vit HORS du cluster. Aucun test, aucun travail
// d'intégration continue, aucun fichier de ce dépôt ne détient cette identité — l'y placer
// annulerait exactement ce que le séquestre protège. Ce fichier n'éprouve donc jamais le séquestre
// d'une installation : il éprouve (1) le chemin SYMÉTRIQUE de bout en bout, qui est déchiffrable
// sans aucun secret durable, (2) une identité age GÉNÉRÉE DANS LE TEST, qui n'existe que le temps
// d'une fonction, et (3) le fait que l'ABSENCE d'exercice se voie et vieillisse.
//
// PREUVE PAR MUTATION, à trois endroits : une archive TRONQUÉE doit faire ÉCHOUER la vérification et
// NOMMER le problème ; une archive parfaitement formée d'une base SANS LIGNE doit échouer aussi (le
// cas exact que l'ancien contrôle rendait vert) ; et le suivi doit passer de « frais » à « périmé »
// par le seul avancement de l'horloge.

    use crate::backup::{backup_compressed, restore_compressed, verify_backup, BackupKind};
    use crate::exercice_de_restauration as exercice;
    use crate::exercice_de_restauration::{Etat, Exercice};

    /// Base SQLCipher au SCHÉMA RÉEL (schema.sql + toute la chaîne de migrations) portant `n` events
    /// dont le premier contient `marqueur`. C'est la forme qu'une archive de production a.
    fn base_source(chemin: &str, cle: &str, n: i64, marqueur: &str) {
        let conn = open_db_keyed(chemin, Some(cle)).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        conn.execute_batch("BEGIN;").unwrap();
        for i in 0..n {
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,host,message,fields) \
                 VALUES(?1,'sshd','auth',3,'hote-a',?2,'{}')",
                params![now(), format!("{marqueur} tentative n={i}")],
            ).unwrap();
        }
        conn.execute_batch("COMMIT;").unwrap();
    }

    /// Comptes PAR TABLE d'une base, sur le même périmètre que l'inventaire de production : les tables
    /// de données, dérivées de `sqlite_master`, sans les tables virtuelles ni leurs tables d'ombre
    /// (l'index plein-texte est RECONSTRUIT à la restauration — ses blocs internes ne se comparent pas,
    /// alors que les lignes qu'il indexe, si).
    fn comptes_par_table(conn: &Connection) -> std::collections::BTreeMap<String, i64> {
        let mut stmt = conn.prepare(
            "SELECT name, COALESCE(sql,'') FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).unwrap();
        let declarees: Vec<(String, String)> = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        let virtuelles: Vec<&str> = declarees.iter()
            .filter(|(_, sql)| sql.trim_start().to_ascii_uppercase().starts_with("CREATE VIRTUAL TABLE"))
            .map(|(n, _)| n.as_str()).collect();
        declarees.iter()
            .filter(|(n, _)| !virtuelles.contains(&n.as_str()) && !virtuelles.iter().any(|v| n.starts_with(&format!("{v}_"))))
            .map(|(n, _)| {
                let c: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM \"{n}\""), [], |r| r.get(0)).unwrap();
                (n.clone(), c)
            })
            .collect()
    }

    /// L'EXERCICE, EN VRAI : sauvegarder, restaurer dans une base NEUVE, et comparer le CONTENU —
    /// le compte de CHAQUE table de données, puis une valeur relue. Une restauration qui ne
    /// comparerait que le schéma reproduirait le défaut qu'elle prétend fermer.
    ///
    /// Chemin SYMÉTRIQUE (passphrase = clé SQLCipher) : c'est le repli documenté du produit, et c'est
    /// le SEUL des deux modes qu'un test peut mener de bout en bout sans qu'aucune clé de séquestre
    /// n'existe nulle part. La clé utilisée ici naît et meurt dans cette fonction.
    #[test]
    fn un_exercice_de_restauration_compare_le_contenu_et_pas_seulement_le_schema() {
        let _reglages = BACKUP_ENV_LOCK.read(); // la sauvegarde RELIT des réglages que d'autres tests POSENT
        let _tmp = crate::tmp_possede::TmpPossede::neuf("p83a-exercice");
        let dir = _tmp.racine().chemin().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        let chemin = |n: &str| dir.join(n).to_string_lossy().into_owned();
        let cle = "p83a-cle-de-test-jamais-persistee";
        let marqueur = "MARQUEUR_P83A_CONTENU";
        const N: i64 = 300;

        let src = chemin("source.db");
        base_source(&src, cle, N, marqueur);
        let (avant, valeur_avant) = {
            let c = open_db_keyed(&src, Some(cle)).unwrap();
            let v: String = c.query_row("SELECT message FROM event WHERE id=1", [], |r| r.get(0)).unwrap();
            (comptes_par_table(&c), v)
        };
        assert_eq!(avant.get("event").copied(), Some(N), "pré-condition : la source porte {N} events");
        assert!(avant.get("parser").copied().unwrap_or(0) > 0, "pré-condition : les parsers natifs sont semés");

        // --- SAUVEGARDER -----------------------------------------------------------------------
        let archive = chemin("archive.age");
        backup_compressed(&src, &archive, Some(cle), None).expect("sauvegarde");

        // --- LA VÉRIFICATION DE PRODUCTION COMPTE MAINTENANT CE QUI EST REVENU ------------------
        let (genre, contenu) = verify_backup(&archive, Some(cle), None).expect("vérification complète");
        assert_eq!(genre, BackupKind::Symmetric);
        let contenu = contenu.expect("clé présente -> vérification COMPLÈTE, pas structurelle");
        assert_eq!(contenu.tables, avant.len(), "toutes les tables de données sont revenues");
        assert_eq!(contenu.lignes, avant.values().sum::<i64>(), "le compte total relu == celui de la source");
        assert_eq!(contenu.plus_grande.as_ref().map(|(t, n)| (t.as_str(), *n)), Some(("event", N)),
            "la table la plus peuplée est `event`, avec ses {N} lignes");
        assert_eq!(contenu.schema_version.as_deref(),
            Some(crate::schema_version(&open_db_keyed(&src, Some(cle)).unwrap()).to_string().as_str()),
            "la version de schéma relue est celle de la source");

        // --- RESTAURER DANS UNE BASE NEUVE, PUIS COMPARER LE CONTENU ---------------------------
        let restauree = chemin("restauree.db");
        restore_compressed(&archive, &restauree, Some(cle), true, None).expect("restauration");
        let c = open_db_keyed(&restauree, Some(cle)).unwrap();
        let apres = comptes_par_table(&c);
        assert_eq!(apres, avant, "compte de lignes IDENTIQUE, table par table, après restauration");
        let valeur_apres: String = c.query_row("SELECT message FROM event WHERE id=1", [], |r| r.get(0)).unwrap();
        assert_eq!(valeur_apres, valeur_avant, "la valeur relue est celle qui avait été écrite");
        assert!(valeur_apres.contains(marqueur), "le contenu connu est bien là : {valeur_apres}");
        // L'index plein-texte est reconstruit ET requêtable — sans quoi la recherche d'un SOC restauré
        // répondrait « aucun résultat » sur des lignes pourtant présentes.
        let n_fts: i64 = c.query_row("SELECT COUNT(*) FROM event_fts WHERE event_fts MATCH 'tentative'", [], |r| r.get(0)).unwrap();
        assert_eq!(n_fts, N, "l'index plein-texte retrouve les {N} lignes restaurées");
        drop(c);

        // --- MUTATION 1 : ARCHIVE TRONQUÉE -> LA VÉRIFICATION DOIT ÉCHOUER ET LE NOMMER ---------
        let tronquee = chemin("tronquee.age");
        let octets = std::fs::read(&archive).unwrap();
        assert!(octets.len() > 1000, "pré-condition : l'archive est assez grosse pour être tronquée utilement");
        std::fs::write(&tronquee, &octets[..octets.len() * 6 / 10]).unwrap();
        let echec = verify_backup(&tronquee, Some(cle), None)
            .expect_err("une archive TRONQUÉE ne doit JAMAIS ressortir vérifiée");
        eprintln!("[p83a] archive tronquée -> {echec}");
        // Le message est PINGLÉ sur ce qui a été MESURÉ, pas sur une formulation générique : « lecture
        // marqueur de format (charge trop courte / corrompue ?) : decryption error ». Ce sont les deux
        // moitiés qui rendent l'échec actionnable — l'étape de plume qui a lâché, et le verdict de la
        // couche de chiffrement authentifié qui l'a fait lâcher.
        assert!(echec.contains("corrompue"), "l'échec doit NOMMER la corruption : {echec}");
        assert!(echec.contains("decryption error"),
            "l'échec doit porter le verdict du chiffrement authentifié, qui est CE qui détecte la troncature : {echec}");

        // --- MUTATION 2 : ARCHIVE PARFAITE D'UNE BASE SANS LIGNE -> ÉCHEC AUSSI ----------------
        // C'est le cas que l'ancienne vérification rendait VERT : l'enveloppe est valide, le dump se
        // rejoue sans erreur, et pas une ligne n'est revenue.
        let vide = chemin("vide.db");
        {
            let c = open_db_keyed(&vide, Some(cle)).unwrap();
            c.execute_batch("CREATE TABLE t(x);").unwrap();
        }
        let archive_vide = chemin("vide.age");
        backup_compressed(&vide, &archive_vide, Some(cle), None).expect("sauvegarde d'une base sans ligne");
        let echec_vide = verify_backup(&archive_vide, Some(cle), None)
            .expect_err("une restauration sans une seule ligne n'est pas un succès");
        assert!(echec_vide.contains("VIDE"), "l'échec doit dire que la restauration est VIDE : {echec_vide}");
    }

    /// L'ATTESTATION : elle ne naît que d'un exercice réussi, elle traverse un copier-coller, et elle
    /// REFUSE de certifier une restauration qui n'a rien rendu. C'est la pièce qui permet à l'exercice
    /// HORS LIGNE — le seul possible sur le chemin d'escrow — de laisser une trace sur le nœud sans
    /// qu'aucune identité privée ne fasse le voyage inverse.
    #[test]
    fn l_attestation_porte_les_faits_de_l_exercice_et_refuse_le_vide() {
        let ex = Exercice {
            ts: 1_760_000_000,
            archive: "plume-20260815T040000Z.db.age".into(),
            archive_octets: 12_345,
            chiffrement: BackupKind::Asymmetric,
            tables: 42,
            lignes: 987_654,
        };
        let ligne = ex.attestation();
        assert!(ligne.starts_with(exercice::PREFIXE_ATTESTATION), "préfixe versionné : {ligne}");
        assert!(!ligne.contains('\n'), "UNE ligne : elle doit survivre à un terminal et à un `| ssh`");
        assert_eq!(Exercice::depuis_texte(&ligne).unwrap(), ex, "aller-retour fidèle");

        // Elle se retrouve AU MILIEU de la sortie humaine de la vérification : c'est ce qui permet
        // `backup-verify … | plume-daemon restore-drill record` sans filtrage.
        let sortie = format!("backup-verify -> /restore/x.age  kind=Asymmetric\ncontenu restauré : 42 tables\n{ligne}\n");
        assert_eq!(Exercice::depuis_texte(&sortie).unwrap(), ex);

        // MUTATION : une attestation qui n'atteste rien est REFUSÉE, et le refus le dit.
        let sans_ligne = Exercice { lignes: 0, ..ex.clone() };
        let e = Exercice::depuis_texte(&sans_ligne.attestation()).expect_err("0 ligne -> refus");
        assert!(e.contains("n'atteste rien"), "{e}");
        let sans_table = Exercice { tables: 0, ..ex.clone() };
        assert!(Exercice::depuis_texte(&sans_table.attestation()).is_err(), "0 table -> refus");

        // Un texte SANS attestation ne rend pas un exercice par défaut : il rend une erreur qui NOMME
        // ce qui est attendu.
        let e = Exercice::depuis_texte("backup-verify -> ok\n").expect_err("aucune attestation -> refus");
        assert!(e.contains(exercice::PREFIXE_ATTESTATION), "le refus doit dire ce qu'il cherchait : {e}");
        // Un préfixe d'une AUTRE version n'est pas deviné.
        assert!(Exercice::depuis_texte("PLUME-EXERCICE-RESTAURATION-2 {\"ts\":1}").is_err(), "format futur -> refus");
    }

    /// L'ABSENCE SE VOIT, ET ELLE VIEILLIT. Fonction PURE : l'horloge est injectée, donc le
    /// vieillissement se PROUVE en avançant le temps au lieu de s'attendre pendant un mois.
    #[test]
    fn l_absence_d_exercice_se_voit_et_le_temps_la_fait_vieillir() {
        const JOUR: i64 = 86_400;
        let max = 31 * JOUR;
        let t0 = 1_760_000_000;
        let ex = |ts: i64, k: BackupKind| Exercice {
            ts, archive: "plume-x.db.age".into(), archive_octets: 1024, chiffrement: k, tables: 40, lignes: 1000,
        };

        // (1) JAMAIS — l'état par défaut d'une installation qui n'a jamais rien restauré.
        let jamais = exercice::etat(None, false, t0, max);
        assert_eq!(jamais, Etat::Jamais);
        assert!(jamais.en_retard(), "un exercice jamais fait est DÛ");
        assert_eq!(jamais.sante(), "yellow", "il se VOIT dans la santé par composant");
        assert_eq!(jamais.age_s(), None, "aucun âge : publier 0 ferait lire « restauré à l'instant »");
        assert!(jamais.detail().contains("AUCUN"), "la phrase dit l'absence : {}", jamais.detail());

        // (2) FRAIS -> (3) PÉRIMÉ par le SEUL avancement de l'horloge. C'est le vieillissement.
        let frais = exercice::etat(Some(&ex(t0, BackupKind::Symmetric)), false, t0 + JOUR, max);
        assert_eq!(frais, Etat::Frais { age_s: JOUR });
        assert!(!frais.en_retard() && frais.sante() == "green");
        let perime = exercice::etat(Some(&ex(t0, BackupKind::Symmetric)), false, t0 + max + 1, max);
        assert!(matches!(perime, Etat::Perime { .. }), "au-delà de l'âge maximal -> périmé : {perime:?}");
        assert!(perime.en_retard() && perime.sante() == "yellow");
        // La BORNE elle-même : à l'âge maximal PILE, l'exercice est encore frais (strictement au-delà).
        assert!(!exercice::etat(Some(&ex(t0, BackupKind::Symmetric)), false, t0 + max, max).en_retard());

        // (4) LE MODE : sur une installation qui séquestre en ASYMÉTRIQUE, un exercice SYMÉTRIQUE tout
        // frais ne clôt rien — le chemin qui servira au sinistre n'a pas été emprunté.
        let mauvais_mode = exercice::etat(Some(&ex(t0, BackupKind::Symmetric)), true, t0 + 60, max);
        assert!(matches!(mauvais_mode, Etat::ModeNonEprouve { .. }), "{mauvais_mode:?}");
        assert!(mauvais_mode.en_retard(), "un exercice sur le mauvais chemin reste DÛ");
        assert!(mauvais_mode.detail().contains("escrow"), "{}", mauvais_mode.detail());
        // …et le MÊME exercice, mené sur une archive asymétrique, clôt l'obligation.
        assert!(!exercice::etat(Some(&ex(t0, BackupKind::Asymmetric)), true, t0 + 60, max).en_retard());
        // Sur une installation SANS escrow, l'exercice symétrique est le bon : aucune exigence de plus.
        assert!(!exercice::etat(Some(&ex(t0, BackupKind::Symmetric)), false, t0 + 60, max).en_retard());

        // (5) Le suivi DÉSACTIVÉ se voit aussi — il n'emprunte pas le vert de « frais ».
        let non_suivi = exercice::etat(None, false, t0, 0);
        assert_eq!(non_suivi, Etat::NonSuivi);
        assert_eq!(non_suivi.sante(), "idle");
        assert!(non_suivi.detail().contains(exercice::CLE_AGE_MAX_JOURS), "il NOMME la clé qui l'a désactivé");

        // (6) Horloge reculée : l'âge est borné à 0, jamais négatif (un exercice « dans le futur » de
        // quelques secondes ne doit pas produire une durée absurde).
        assert_eq!(exercice::etat(Some(&ex(t0, BackupKind::Symmetric)), false, t0 - 5, max).age_s(), Some(0));
    }

    /// L'ENREGISTREMENT NE PEUT NI SAUTER DANS LE FUTUR NI RECULER. Deux refus mécaniques, parce que
    /// les deux feraient MENTIR le suivi dans le sens qui arrange : une attestation post-datée le
    /// tiendrait au vert pendant des mois, une attestation rejouée ferait reculer la date du dernier
    /// exercice.
    #[test]
    fn l_enregistrement_refuse_le_futur_et_le_recul() {
        let c = test_db();
        let t0 = 1_760_000_000;
        let ex = |ts: i64| Exercice {
            ts, archive: "plume-y.db.age".into(), archive_octets: 2048,
            chiffrement: BackupKind::Symmetric, tables: 40, lignes: 500,
        };
        assert!(exercice::dernier_exercice(&c).is_none(), "base neuve : aucun exercice");

        exercice::enregistrer(&c, &ex(t0), t0).expect("enregistrement");
        assert_eq!(exercice::dernier_exercice(&c).unwrap(), ex(t0), "relu tel qu'attesté");

        let futur = exercice::enregistrer(&c, &ex(t0 + 7200), t0).expect_err("2 h d'avance -> refus");
        assert!(futur.contains("futur"), "{futur}");
        let recul = exercice::enregistrer(&c, &ex(t0 - 1), t0 + 10).expect_err("plus ancien -> refus");
        assert!(recul.contains("ne recule pas"), "{recul}");
        assert_eq!(exercice::dernier_exercice(&c).unwrap().ts, t0, "aucun des deux refus n'a écrit");

        // Une avance INFÉRIEURE à la tolérance d'horloge passe (deux machines ne sont jamais à la
        // seconde), et un exercice plus récent remplace bien le précédent.
        exercice::enregistrer(&c, &ex(t0 + 60), t0).expect("60 s d'avance : tolérance d'horloge");
        exercice::enregistrer(&c, &ex(t0 + 3 * 86_400), t0 + 3 * 86_400).expect("plus récent");
        assert_eq!(exercice::dernier_exercice(&c).unwrap().ts, t0 + 3 * 86_400);

        // Une valeur `meta` ILLISIBLE (format d'un binaire futur, corruption) se lit « jamais », et non
        // « exercice daté de l'époque Unix » — l'un fait agir, l'autre trompe.
        c.execute("UPDATE meta SET value='n''importe quoi' WHERE key=?1", params![exercice::CLE_META_EXERCICE]).unwrap();
        assert!(exercice::dernier_exercice(&c).is_none(), "valeur illisible -> traitée comme absente");
    }

    /// CE QU'UN EXPLOITANT LIT : le composant de santé et les jauges Prometheus. L'exercice attesté ici
    /// est ASYMÉTRIQUE à dessein — son verdict ne dépend donc pas du réglage d'escrow que d'autres
    /// tests posent dans l'environnement du processus.
    #[test]
    fn le_composant_et_les_jauges_disent_l_absence_puis_la_fraicheur() {
        let c = test_db();
        // (1) AUCUN exercice : le composant le dit, et la jauge d'alerte vaut 1.
        let comp = exercice::composant(&c, false, now());
        assert_eq!(comp["component"], exercice::COMPOSANT);
        assert_eq!(comp["drill_state"], "jamais");
        assert_eq!(comp["overdue"], true);
        assert_eq!(comp["state"], "yellow");
        assert!(comp["age_s"].is_null(), "aucun âge tant qu'aucun exercice n'a eu lieu");
        assert!(comp["last_success_ts"].is_null());

        let prom = gather_prom(&c, "/nonexistent-spool", "", 1, 80);
        assert!(prom.contains("plume_restore_drill_overdue 1"), "la jauge d'alerte vaut 1 : {prom}");
        assert!(!prom.contains("plume_restore_drill_age_seconds"),
            "l'âge est ABSENT tant qu'aucun exercice n'a eu lieu — publier 0 dirait « restauré à l'instant »");
        assert!(!prom.contains("plume_restore_drill_last_success_timestamp_seconds"));
        assert!(prom.contains(&format!("plume_component_up{{component=\"{}\"}} 0.5", exercice::COMPOSANT)),
            "le composant apparaît en jaune dans la santé par composant : {prom}");

        // (2) UN exercice attesté : le composant vire au vert, les deux jauges apparaissent.
        let t = now();
        exercice::enregistrer(&c, &Exercice {
            ts: t, archive: "plume-z.db.age".into(), archive_octets: 4096,
            chiffrement: BackupKind::Asymmetric, tables: 40, lignes: 4242,
        }, t).unwrap();
        let comp = exercice::composant(&c, true, t + 60);
        assert_eq!(comp["drill_state"], "frais");
        assert_eq!(comp["overdue"], false);
        assert_eq!(comp["state"], "green");
        assert_eq!(comp["age_s"], 60);
        assert_eq!(comp["rows_restored"], 4242);
        assert_eq!(comp["encryption"], "asymmetric");
        let prom = gather_prom(&c, "/nonexistent-spool", "", 1, 80);
        assert!(prom.contains("plume_restore_drill_overdue 0"), "{prom}");
        assert!(prom.contains(&format!("plume_restore_drill_last_success_timestamp_seconds {t}")), "{prom}");
        assert!(prom.contains("plume_restore_drill_age_seconds"), "l'âge est publié dès qu'il existe : {prom}");
    }

    /// LE SIGNAL SOC, émis depuis le chemin de sauvegarde : non-purgeable (source managée + origin
    /// daemon), dédup QUOTIDIENNE, et RIEN quand l'exercice est frais. Un signal qui partirait à chaque
    /// cycle de sauvegarde serait une tempête ; un signal qui partirait alors que tout va bien serait un
    /// mensonge.
    #[test]
    fn le_signal_soc_nomme_l_exercice_du_et_se_tait_quand_il_est_frais() {
        let c = test_db();
        let t0 = 1_760_000_000;
        let avant: i64 = c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();

        assert!(exercice::signal_exercice_du(&c, &Etat::Jamais, t0), "1er signal écrit");
        let ligne: (String, String, String, i64) = c.query_row(
            "SELECT source, category, origin, severity FROM event ORDER BY id DESC LIMIT 1",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap();
        assert_eq!(ligne.0, "plume-config", "source MANAGÉE -> non purgeable");
        assert_eq!(ligne.1, "health");
        assert_eq!(ligne.2, "daemon", "origin daemon -> un exploitant ne peut pas l'effacer");
        assert_eq!(ligne.3, 3);
        let msg: String = c.query_row("SELECT message FROM event ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap();
        assert!(msg.contains("RESTAURATION NON ÉPROUVÉE"), "{msg}");
        assert!(msg.contains("restore-drill record"), "le message dit le GESTE à faire : {msg}");

        // DÉDUP QUOTIDIENNE : le même jour, un second cycle de sauvegarde n'écrit rien de plus.
        assert!(!exercice::signal_exercice_du(&c, &Etat::Jamais, t0 + 3600), "même jour -> dédup");
        assert!(exercice::signal_exercice_du(&c, &Etat::Jamais, t0 + 86_400), "jour suivant -> un signal");

        // MUTATION : exercice FRAIS -> aucun signal, quel que soit le nombre de cycles.
        let n_avant: i64 = c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
        assert!(!exercice::signal_exercice_du(&c, &Etat::Frais { age_s: 10 }, t0 + 3 * 86_400));
        assert!(!exercice::signal_exercice_du(&c, &Etat::NonSuivi, t0 + 4 * 86_400));
        let n_apres: i64 = c.query_row("SELECT COUNT(*) FROM event", [], |r| r.get(0)).unwrap();
        assert_eq!(n_apres, n_avant, "un exercice frais n'écrit RIEN");
        assert_eq!(n_apres - avant, 2, "exactement les deux signaux des deux jours distincts");
    }

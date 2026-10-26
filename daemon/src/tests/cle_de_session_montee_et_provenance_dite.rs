// =====================================================================================
// LA CLÉ QUI SIGNE LES COOKIES SE LIT D'UN SECRET MONTÉ, ET LE DÉMARRAGE DIT D'OÙ ELLE VIENT.
//
// VU (re-mesuré sur ac4ca5cd) : `load_session_secret` (session.rs) lisait la matière à clé par `cfg` seul — ni variante
// fichier ni référence de secret, alors que `cfg_secret` (main.rs) les sert aux autres secrets. Le seul moyen de la
// tenir hors du volume de données était donc l'environnement du processus. Et le démarrage ne disait rien de la
// provenance, sauf quand la clé finissait en mémoire.
//
// LES TÉMOINS relancent le binaire de test (un enfant par cas) : le refus est un `exit(78)` et les lignes dites se lisent
// sur le stderr de l'enfant, ligne ENTIÈRE. Chaque enfant retire de son environnement les quatre leviers de la clé de
// session ; la configuration du cas est passée à la fonction, la variable d'environnement seulement quand le cas la pose.
//
// MUTANTS JOUÉS (posés le temps de la preuve, retirés avant le commit), chacun vu ROUGE : AU3_FICHIER_IGNORE, AU3_VARIABLE_GAGNE,
// AU3_MONTE_SANS_FICHIER, AU3_MONTE_SANS_REFERENCE, AU3_BLANC_MONTE_RETOMBE, AU3_LIGNE_MONTEE_COMME_CONFIG,
// AU3_LIGNE_CONFIG_MUETTE, AU3_PERSISTEE_LUE_MUETTE, AU3_ENGENDREE_MUETTE, AU3_MEMOIRE_ANCIEN_TEXTE (ce dernier rougit
// les deux témoins « mémoire » de secrets_poses_en_0600_des_la_creation.rs, inversés dans ce lot). Puis, « jamais la clé au
// journal » jugé sur TOUT le stderr des cas sans secret monté : AU3_FUITE_CONFIGURATION, AU3_FUITE_PERSISTEE,
// AU3_FUITE_ENGENDREE (la matière imprimée sur une ligne d'un autre préfixe), chacun vu ROUGE.
//
// PLANCHER DE LONGUEUR (la matière rognée se mesure en octets) : une source montée sous le plancher refuse le démarrage
// (exit 78, ligne FATAL entière, ni la matière ni le chemin au journal, rien de persisté) ; la variable nue sous le plancher
// démarre avec sa clé et une ligne WARN entière le dit ; au plancher, rien ne change. Mutants (posés le temps de la preuve, retirés avant le
// commit), chacun vu ROUGE : AU3B_LE, AU3B_SANS_PLANCHER_REF, AU3B_SANS_PLANCHER_FICHIER, AU3B_SANS_TRIM, AU3B_SANS_WARN,
// AU3B_FATAL_EN_REPLI. Puis : plancher compté en caractères au lieu d'octets (rougit le fichier monté et la variable de
// 32 octets en 16 caractères), WARN de la variable mesuré sur la variable brute au lieu de la matière rognée (rougit la
// variable de 31 octets entourée de blanc), référence imprimée sur une ligne d'un autre préfixe après le FATAL (rougit
// les deux témoins de référence sous le plancher, `file:` par le chemin, `literal:` par la référence), chacun vu ROUGE.
// =====================================================================================

mod cle_de_session_montee_et_provenance_dite {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// La variable qui fait d'un témoin l'enfant qu'il relance : `<cas>|<répertoire>`.
    const ENFANT: &str = "AU3_ENFANT";
    /// Ce que l'enfant imprime de la clé rendue (en hex) sur stdout.
    const MARQUE: &str = "AU3-ISSUE:";
    const MODULE: &str = "tests::cle_de_session_montee_et_provenance_dite::";

    /// Les quatre leviers, en littéral (le témoin ne relit pas la production).
    const LEVIER_VARIABLE: &str = "PLUME_SESSION_SECRET";
    const LEVIER_FICHIER: &str = "PLUME_SESSION_SECRET_FILE";
    const LEVIER_REFERENCE: &str = "PLUME_SESSION_SECRET_REF";
    const LEVIER_EMPLACEMENT: &str = "PLUME_SESSION_KEY";

    /// Matières de test : celle du secret monté, celle de la variable (entourée de blanc : la lecture la rogne).
    const MATIERE_MONTEE: &str = "temoin-au3-matiere-montee-de-test";
    const MATIERE_DE_LA_VARIABLE: &str = "  temoin-au3-matiere-de-la-variable  ";
    /// Une clé persistée valide : 32 octets en hex.
    const CLE_PERSISTEE_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Les lignes attendues, en littéral.
    const LIGNE_CONFIGURATION: &str =
        "[session] clé de signature des sessions : lue de la configuration (variable d'environnement ou fichier de configuration).";
    const LIGNE_MONTEE: &str =
        "[session] clé de signature des sessions : lue d'un secret monté (fichier ou référence de secret).";
    const LIGNE_MONTEE_BLANCHE: &str = "[session] FATAL : le secret monté de la clé de signature des sessions ne porte \
         que du blanc — refus de démarrer (fail-closed ; ne retombe ni sur une clé persistée ni sur une clé en mémoire).";

    /// Plancher de longueur : une matière d'un octet de moins que le plancher, et une au plancher.
    const MATIERE_COURTE: &str = "temoin-au3b-cle-courte-de-tests";
    const MATIERE_AU_PLANCHER: &str = "temoin-au3b-cle-au-plancher-test";
    const _: () = assert!(MATIERE_COURTE.len() == 31 && MATIERE_AU_PLANCHER.len() == 32);
    /// Une matière de 32 octets en 16 caractères de deux octets : au plancher compté en octets, sous lui en caractères.
    const MATIERE_MULTIOCTET: &str = "éàèùâêîôûëïüçœæÿ";
    const _: () = assert!(MATIERE_MULTIOCTET.len() == 32);
    const LIGNE_MONTEE_COURTE: &str = "[session] FATAL : le secret monté de la clé de signature des sessions porte \
         moins de 32 octets (blanc rogné) — refus de démarrer (fail-closed ; ne retombe ni sur une clé persistée ni sur une \
         clé en mémoire).";
    const LIGNE_VARIABLE_COURTE: &str = "[session] WARN : la clé de signature des sessions lue de la configuration porte \
         moins de 32 octets (blanc rogné) — le démarrage continue avec elle. Remplace-la par une clé plus longue et \
         monte-la en fichier en lecture seule par PLUME_SESSION_SECRET_FILE.";

    /// Dans l'enfant : le répertoire du cas `cas`, sinon `None` (on est le parent).
    fn repertoire_de_l_enfant(cas: &str) -> Option<String> {
        let v = std::env::var(ENFANT).ok()?;
        let (c, dir) = v.split_once('|')?;
        (c == cas).then(|| dir.to_string())
    }

    /// Dans l'enfant : la configuration du cas, puis la fonction que le démarrage appelle ; la clé rendue sur stdout.
    fn jouer_l_enfant(cas: &str, dir: &str) {
        let _env = VERROU_ENV_PROCESSUS.read();
        let mut conf = std::collections::HashMap::from([(LEVIER_EMPLACEMENT.to_string(), format!("{dir}/session.key"))]);
        match cas {
            "monte-gagne" | "fichier-blanc" | "fichier-court" | "fichier-court-entoure" | "fichier-au-plancher" | "fichier-multioctet" => {
                conf.insert(LEVIER_FICHIER.to_string(), format!("{dir}/monte/cle"));
            }
            "reference-gagne" | "reference-blanche" | "reference-au-plancher" | "reference-courte" => {
                conf.insert(LEVIER_REFERENCE.to_string(), format!("file:{dir}/monte/cle"));
            }
            "reference-litterale-courte" => {
                conf.insert(LEVIER_REFERENCE.to_string(), format!("literal:{MATIERE_COURTE}"));
            }
            "fichier-absent" => {
                conf.insert(LEVIER_FICHIER.to_string(), format!("{dir}/monte/absent"));
            }
            "fichier-vide" => {
                conf.insert(LEVIER_FICHIER.to_string(), format!("{dir}/monte/vide"));
            }
            "fichier-repertoire" => {
                conf.insert(LEVIER_FICHIER.to_string(), format!("{dir}/monte"));
            }
            _ => {}
        }
        let k = load_session_secret(&conf);
        println!("{MARQUE}{}", hex_encode(&k));
    }

    /// Relance l'enfant (la commande est construite par le témoin) en retirant les quatre leviers de son environnement,
    /// puis en posant la variable si le cas la demande.
    fn relancer(mut commande: std::process::Command, variable: Option<&str>) -> std::process::Output {
        commande.env_remove(LEVIER_VARIABLE).env_remove(LEVIER_FICHIER).env_remove(LEVIER_REFERENCE).env_remove(LEVIER_EMPLACEMENT);
        if let Some(v) = variable {
            commande.env(LEVIER_VARIABLE, v);
        }
        commande.output().expect("relance du binaire de test")
    }

    fn issues(sortie: &std::process::Output) -> Vec<String> {
        String::from_utf8_lossy(&sortie.stdout).lines().filter_map(|l| l.split_once(MARQUE).map(|(_, v)| v.to_string())).collect()
    }

    fn lignes(sortie: &std::process::Output, prefixe: &str) -> Vec<String> {
        String::from_utf8_lossy(&sortie.stderr).lines().filter(|l| l.starts_with(prefixe)).map(str::to_string).collect()
    }

    fn tout(sortie: &std::process::Output) -> String {
        format!("stdout : {}\nstderr : {}", String::from_utf8_lossy(&sortie.stdout), String::from_utf8_lossy(&sortie.stderr))
    }

    /// Les noms d'entrées d'un répertoire, triés.
    fn noms(dir: &std::path::Path) -> Vec<String> {
        let mut v: Vec<String> =
            std::fs::read_dir(dir).expect("lecture du répertoire du témoin").map(|e| e.expect("entrée").file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    /// Un secret monté : le répertoire `monte/` du témoin et, si `contenu` est donné, le fichier `monte/cle`.
    fn monter(tmp: &std::path::Path, contenu: Option<&str>) -> String {
        let monte = tmp.join("monte");
        std::fs::create_dir(&monte).expect("fixture : répertoire du secret monté");
        let cle = monte.join("cle");
        if let Some(c) = contenu {
            std::fs::write(&cle, c).expect("fixture : secret monté");
        }
        cle.to_string_lossy().into_owned()
    }

    /// L'enfant a refusé de démarrer : exit 78, aucune clé rendue, aucune clé persistée écrite.
    fn refus_de_demarrer(sortie: &std::process::Output, tmp: &std::path::Path) {
        assert_eq!(sortie.status.code(), Some(78), "refus de démarrer (exit 78) ; {}", tout(sortie));
        assert!(issues(sortie).is_empty(), "aucune clé rendue ; {}", tout(sortie));
        assert_eq!(noms(tmp), vec!["monte".to_string()], "aucune clé persistée écrite ; {}", tout(sortie));
    }

    // ---------------------------------------------------------------- le secret monté gagne

    /// Fichier monté ET variable posée : la clé est le contenu rogné du fichier, la ligne dit « secret monté » sans le
    /// chemin ni la matière, et aucune clé persistée n'est écrite.
    #[test]
    fn au3_fichier_monte_gagne_sur_la_variable_et_rien_n_est_persiste() {
        if let Some(dir) = repertoire_de_l_enfant("monte-gagne") {
            jouer_l_enfant("monte-gagne", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3-monte-gagne");
        let chemin = monter(&tmp, Some(&format!("  {MATIERE_MONTEE}\n")));
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3_fichier_monte_gagne_sur_la_variable_et_rien_n_est_persiste")])
            .env(ENFANT, format!("monte-gagne|{tmp}"));
        let sortie = relancer(commande, Some(MATIERE_DE_LA_VARIABLE));
        assert_eq!(sortie.status.code(), Some(0), "l'enfant joue jusqu'au bout ; {}", tout(&sortie));
        assert_eq!(issues(&sortie), vec![hex_encode(MATIERE_MONTEE.as_bytes())], "clé = contenu rogné du fichier ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[session]"), vec![LIGNE_MONTEE.to_string()], "{}", tout(&sortie));
        let stderr = String::from_utf8_lossy(&sortie.stderr);
        assert!(!stderr.contains(&chemin) && !stderr.contains(MATIERE_MONTEE), "ni le chemin ni la matière au journal ; {}", tout(&sortie));
        assert_eq!(noms(&tmp), vec!["monte".to_string()], "aucune clé persistée écrite ; {}", tout(&sortie));
    }

    /// Référence de secret (`file:`) ET variable posée : même verdict.
    #[test]
    fn au3_reference_montee_gagne_sur_la_variable_et_rien_n_est_persiste() {
        if let Some(dir) = repertoire_de_l_enfant("reference-gagne") {
            jouer_l_enfant("reference-gagne", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3-reference-gagne");
        let chemin = monter(&tmp, Some(MATIERE_MONTEE));
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3_reference_montee_gagne_sur_la_variable_et_rien_n_est_persiste")])
            .env(ENFANT, format!("reference-gagne|{tmp}"));
        let sortie = relancer(commande, Some(MATIERE_DE_LA_VARIABLE));
        assert_eq!(sortie.status.code(), Some(0), "l'enfant joue jusqu'au bout ; {}", tout(&sortie));
        assert_eq!(issues(&sortie), vec![hex_encode(MATIERE_MONTEE.as_bytes())], "clé = contenu de la référence ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[session]"), vec![LIGNE_MONTEE.to_string()], "{}", tout(&sortie));
        let stderr = String::from_utf8_lossy(&sortie.stderr);
        assert!(!stderr.contains(&chemin) && !stderr.contains(MATIERE_MONTEE), "ni le chemin ni la matière au journal ; {}", tout(&sortie));
        assert_eq!(noms(&tmp), vec!["monte".to_string()], "aucune clé persistée écrite ; {}", tout(&sortie));
    }

    // ---------------------------------------------------------------- un secret monté cassé refuse le démarrage

    /// Fichier monté qui ne porte que du blanc : refus nommé, jamais la clé persistée ni une clé en mémoire.
    #[test]
    fn au3_fichier_monte_blanc_refuse_le_demarrage() {
        if let Some(dir) = repertoire_de_l_enfant("fichier-blanc") {
            jouer_l_enfant("fichier-blanc", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3-fichier-blanc");
        monter(&tmp, Some(" \n\t\n"));
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3_fichier_monte_blanc_refuse_le_demarrage")])
            .env(ENFANT, format!("fichier-blanc|{tmp}"));
        let sortie = relancer(commande, None);
        refus_de_demarrer(&sortie, &tmp);
        assert_eq!(lignes(&sortie, "[session]"), vec![LIGNE_MONTEE_BLANCHE.to_string()], "{}", tout(&sortie));
    }

    /// Référence de secret qui ne porte que du blanc : même refus.
    #[test]
    fn au3_reference_montee_blanche_refuse_le_demarrage() {
        if let Some(dir) = repertoire_de_l_enfant("reference-blanche") {
            jouer_l_enfant("reference-blanche", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3-reference-blanche");
        monter(&tmp, Some("  \n"));
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3_reference_montee_blanche_refuse_le_demarrage")])
            .env(ENFANT, format!("reference-blanche|{tmp}"));
        let sortie = relancer(commande, None);
        refus_de_demarrer(&sortie, &tmp);
        assert_eq!(lignes(&sortie, "[session]"), vec![LIGNE_MONTEE_BLANCHE.to_string()], "{}", tout(&sortie));
    }

    /// Fichier monté ABSENT, variable posée : refus (exit 78), sans retomber sur la variable.
    #[test]
    fn au3_fichier_monte_absent_refuse_sans_retomber_sur_la_variable() {
        if let Some(dir) = repertoire_de_l_enfant("fichier-absent") {
            jouer_l_enfant("fichier-absent", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3-fichier-absent");
        monter(&tmp, None);
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3_fichier_monte_absent_refuse_sans_retomber_sur_la_variable")])
            .env(ENFANT, format!("fichier-absent|{tmp}"));
        let sortie = relancer(commande, Some(MATIERE_DE_LA_VARIABLE));
        refus_de_demarrer(&sortie, &tmp);
        assert_eq!(lignes(&sortie, "[session]"), Vec::<String>::new(), "{}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[FATAL]").len(), 1, "le refus est dit ; {}", tout(&sortie));
    }

    /// Fichier monté VIDE (0 octet), variable posée : refus.
    #[test]
    fn au3_fichier_monte_vide_refuse_sans_retomber_sur_la_variable() {
        if let Some(dir) = repertoire_de_l_enfant("fichier-vide") {
            jouer_l_enfant("fichier-vide", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3-fichier-vide");
        monter(&tmp, None);
        std::fs::write(tmp.join("monte").join("vide"), "").expect("fixture : fichier vide");
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3_fichier_monte_vide_refuse_sans_retomber_sur_la_variable")])
            .env(ENFANT, format!("fichier-vide|{tmp}"));
        let sortie = relancer(commande, Some(MATIERE_DE_LA_VARIABLE));
        refus_de_demarrer(&sortie, &tmp);
        assert_eq!(lignes(&sortie, "[session]"), Vec::<String>::new(), "{}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[FATAL]").len(), 1, "le refus est dit ; {}", tout(&sortie));
    }

    /// Fichier monté ILLISIBLE (l'entrée est un répertoire), variable posée : refus.
    #[test]
    fn au3_fichier_monte_illisible_refuse_sans_retomber_sur_la_variable() {
        if let Some(dir) = repertoire_de_l_enfant("fichier-repertoire") {
            jouer_l_enfant("fichier-repertoire", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3-fichier-repertoire");
        monter(&tmp, None);
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3_fichier_monte_illisible_refuse_sans_retomber_sur_la_variable")])
            .env(ENFANT, format!("fichier-repertoire|{tmp}"));
        let sortie = relancer(commande, Some(MATIERE_DE_LA_VARIABLE));
        refus_de_demarrer(&sortie, &tmp);
        assert_eq!(lignes(&sortie, "[session]"), Vec::<String>::new(), "{}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[FATAL]").len(), 1, "le refus est dit ; {}", tout(&sortie));
    }

    // ---------------------------------------------------------------- sans secret monté : l'ancien chemin, dit

    /// Variable seule : clé = variable rognée (comme avant), aucune clé persistée, et la ligne dit « configuration ».
    #[test]
    fn au3_variable_seule_est_dite_et_rien_n_est_persiste() {
        if let Some(dir) = repertoire_de_l_enfant("variable-seule") {
            jouer_l_enfant("variable-seule", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3-variable-seule");
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3_variable_seule_est_dite_et_rien_n_est_persiste")])
            .env(ENFANT, format!("variable-seule|{tmp}"));
        let sortie = relancer(commande, Some(MATIERE_DE_LA_VARIABLE));
        assert_eq!(sortie.status.code(), Some(0), "l'enfant joue jusqu'au bout ; {}", tout(&sortie));
        assert_eq!(issues(&sortie), vec![hex_encode(MATIERE_DE_LA_VARIABLE.trim().as_bytes())], "clé = variable rognée ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[session]"), vec![LIGNE_CONFIGURATION.to_string()], "{}", tout(&sortie));
        let stderr = String::from_utf8_lossy(&sortie.stderr);
        assert!(!stderr.contains(MATIERE_DE_LA_VARIABLE.trim()), "la matière n'est sur AUCUNE ligne du journal ; {}", tout(&sortie));
        assert_eq!(noms(&tmp), Vec::<String>::new(), "aucune clé persistée écrite ; {}", tout(&sortie));
    }

    /// Clé persistée valide : relue telle quelle, et la ligne dit « fichier persisté » avec son emplacement.
    #[test]
    fn au3_cle_persistee_lue_est_dite() {
        if let Some(dir) = repertoire_de_l_enfant("persistee-lue") {
            jouer_l_enfant("persistee-lue", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3-persistee-lue");
        let p = format!("{tmp}/session.key");
        std::fs::write(&p, format!("{CLE_PERSISTEE_HEX}\n")).expect("fixture : clé persistée");
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3_cle_persistee_lue_est_dite")])
            .env(ENFANT, format!("persistee-lue|{tmp}"));
        let sortie = relancer(commande, None);
        assert_eq!(sortie.status.code(), Some(0), "l'enfant joue jusqu'au bout ; {}", tout(&sortie));
        assert_eq!(issues(&sortie), vec![CLE_PERSISTEE_HEX.to_string()], "clé persistée relue ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[session]"), vec![format!("[session] clé de signature des sessions : lue du fichier persisté '{p}'.")],
            "{}", tout(&sortie));
        let stderr = String::from_utf8_lossy(&sortie.stderr);
        assert!(!stderr.contains(CLE_PERSISTEE_HEX), "la clé n'est sur AUCUNE ligne du journal ; {}", tout(&sortie));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), format!("{CLE_PERSISTEE_HEX}\n"), "rien n'est réécrit");
    }

    /// Aucune clé : engendrée, persistée en 0600, et la ligne le dit avec l'emplacement.
    #[test]
    fn au3_cle_engendree_et_persistee_est_dite() {
        if let Some(dir) = repertoire_de_l_enfant("engendree") {
            jouer_l_enfant("engendree", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3-engendree");
        let p = format!("{tmp}/session.key");
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3_cle_engendree_et_persistee_est_dite")])
            .env(ENFANT, format!("engendree|{tmp}"));
        let sortie = relancer(commande, None);
        assert_eq!(sortie.status.code(), Some(0), "l'enfant joue jusqu'au bout ; {}", tout(&sortie));
        let cle = std::fs::read_to_string(&p).expect("clé persistée");
        assert_eq!(issues(&sortie), vec![cle.clone()], "le fichier porte la clé rendue ; {}", tout(&sortie));
        assert!(!cle.trim().is_empty() && !String::from_utf8_lossy(&sortie.stderr).contains(cle.trim()),
            "la clé n'est sur AUCUNE ligne du journal ; {}", tout(&sortie));
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600, "clé en 0600");
        assert_eq!(lignes(&sortie, "[session]"), vec![format!("[session] clé de signature des sessions : engendrée et persistée en 0600 à '{p}'.")],
            "{}", tout(&sortie));
    }

    // ---------------------------------------------------------------- plancher de longueur

    /// Refus d'une source montée sous le plancher : exit 78, rien de rendu ni de persisté, la ligne FATAL ENTIÈRE et
    /// seule, et ni la matière ni le chemin monté nulle part au journal.
    fn refus_sous_le_plancher(sortie: &std::process::Output, tmp: &std::path::Path, chemin: &str) {
        refus_de_demarrer(sortie, tmp);
        assert_eq!(lignes(sortie, "[session]"), vec![LIGNE_MONTEE_COURTE.to_string()], "{}", tout(sortie));
        let stderr = String::from_utf8_lossy(&sortie.stderr);
        assert!(!stderr.contains(MATIERE_COURTE) && !stderr.contains(chemin), "ni la matière ni le chemin au journal ; {}", tout(sortie));
    }

    /// Démarrage par une source montée au plancher : la clé est la matière, la ligne dit « secret monté », seule, et rien
    /// n'est persisté.
    fn demarre_au_plancher(sortie: &std::process::Output, tmp: &std::path::Path) {
        assert_eq!(sortie.status.code(), Some(0), "l'enfant joue jusqu'au bout ; {}", tout(sortie));
        assert_eq!(issues(sortie), vec![hex_encode(MATIERE_AU_PLANCHER.as_bytes())], "clé = matière montée ; {}", tout(sortie));
        assert_eq!(lignes(sortie, "[session]"), vec![LIGNE_MONTEE.to_string()], "{}", tout(sortie));
        assert!(!String::from_utf8_lossy(&sortie.stderr).contains(MATIERE_AU_PLANCHER), "la matière n'est pas au journal ; {}", tout(sortie));
        assert_eq!(noms(tmp), vec!["monte".to_string()], "aucune clé persistée écrite ; {}", tout(sortie));
    }

    /// Fichier monté d'un octet sous le plancher, variable longue posée : refus, sans retomber sur la variable.
    #[test]
    fn au3b_fichier_monte_sous_le_plancher_refuse_le_demarrage() {
        if let Some(dir) = repertoire_de_l_enfant("fichier-court") {
            jouer_l_enfant("fichier-court", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3b-fichier-court");
        let chemin = monter(&tmp, Some(MATIERE_COURTE));
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3b_fichier_monte_sous_le_plancher_refuse_le_demarrage")])
            .env(ENFANT, format!("fichier-court|{tmp}"));
        let sortie = relancer(commande, Some(MATIERE_DE_LA_VARIABLE));
        refus_sous_le_plancher(&sortie, &tmp, &chemin);
    }

    /// Le plancher se mesure APRÈS rognage : la même matière entourée de blanc (plus longue que le plancher brute) refuse.
    #[test]
    fn au3b_fichier_monte_sous_le_plancher_une_fois_rogne_refuse_le_demarrage() {
        if let Some(dir) = repertoire_de_l_enfant("fichier-court-entoure") {
            jouer_l_enfant("fichier-court-entoure", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3b-fichier-court-entoure");
        let contenu = format!("  \t{MATIERE_COURTE}\n");
        assert!(contenu.len() > 32, "contrôle de la fixture : brute, elle passe le plancher");
        let chemin = monter(&tmp, Some(&contenu));
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3b_fichier_monte_sous_le_plancher_une_fois_rogne_refuse_le_demarrage")])
            .env(ENFANT, format!("fichier-court-entoure|{tmp}"));
        let sortie = relancer(commande, None);
        refus_sous_le_plancher(&sortie, &tmp, &chemin);
    }

    /// Fichier monté au plancher exact : démarre, provenance « secret monté ».
    #[test]
    fn au3b_fichier_monte_au_plancher_demarre() {
        if let Some(dir) = repertoire_de_l_enfant("fichier-au-plancher") {
            jouer_l_enfant("fichier-au-plancher", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3b-fichier-au-plancher");
        let chemin = monter(&tmp, Some(&format!("{MATIERE_AU_PLANCHER}\n")));
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3b_fichier_monte_au_plancher_demarre")])
            .env(ENFANT, format!("fichier-au-plancher|{tmp}"));
        let sortie = relancer(commande, None);
        demarre_au_plancher(&sortie, &tmp);
        assert!(!String::from_utf8_lossy(&sortie.stderr).contains(&chemin), "le chemin n'est pas au journal ; {}", tout(&sortie));
    }

    /// Référence littérale d'un octet sous le plancher : refus.
    #[test]
    fn au3b_reference_litterale_sous_le_plancher_refuse_le_demarrage() {
        if let Some(dir) = repertoire_de_l_enfant("reference-litterale-courte") {
            jouer_l_enfant("reference-litterale-courte", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3b-reference-litterale-courte");
        // Le répertoire `monte/` seul, que `refus_de_demarrer` attend ; la fuite jugée est la référence elle-même.
        monter(&tmp, None);
        let reference = format!("literal:{MATIERE_COURTE}");
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3b_reference_litterale_sous_le_plancher_refuse_le_demarrage")])
            .env(ENFANT, format!("reference-litterale-courte|{tmp}"));
        let sortie = relancer(commande, Some(MATIERE_DE_LA_VARIABLE));
        refus_sous_le_plancher(&sortie, &tmp, &reference);
    }

    /// Référence (`file:`) au plancher exact : démarre, provenance « secret monté ».
    #[test]
    fn au3b_reference_au_plancher_demarre() {
        if let Some(dir) = repertoire_de_l_enfant("reference-au-plancher") {
            jouer_l_enfant("reference-au-plancher", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3b-reference-au-plancher");
        monter(&tmp, Some(MATIERE_AU_PLANCHER));
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3b_reference_au_plancher_demarre")])
            .env(ENFANT, format!("reference-au-plancher|{tmp}"));
        let sortie = relancer(commande, None);
        demarre_au_plancher(&sortie, &tmp);
    }

    /// Variable nue d'un octet sous le plancher : PAS de refus (rétrocompatibilité) ; la clé sert, la ligne de provenance
    /// puis la ligne WARN ENTIÈRE, sans la matière, et rien n'est persisté.
    #[test]
    fn au3b_variable_sous_le_plancher_demarre_et_avertit() {
        if let Some(dir) = repertoire_de_l_enfant("variable-courte") {
            jouer_l_enfant("variable-courte", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3b-variable-courte");
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3b_variable_sous_le_plancher_demarre_et_avertit")])
            .env(ENFANT, format!("variable-courte|{tmp}"));
        let sortie = relancer(commande, Some(MATIERE_COURTE));
        assert_eq!(sortie.status.code(), Some(0), "l'enfant joue jusqu'au bout ; {}", tout(&sortie));
        assert_eq!(issues(&sortie), vec![hex_encode(MATIERE_COURTE.as_bytes())], "clé = variable, comme avant ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[session]"), vec![LIGNE_CONFIGURATION.to_string(), LIGNE_VARIABLE_COURTE.to_string()], "{}", tout(&sortie));
        assert!(!String::from_utf8_lossy(&sortie.stderr).contains(MATIERE_COURTE), "la matière n'est pas au journal ; {}", tout(&sortie));
        assert_eq!(noms(&tmp), Vec::<String>::new(), "aucune clé persistée écrite ; {}", tout(&sortie));
    }

    /// Variable nue au plancher exact : la ligne de provenance seule, aucun WARN.
    #[test]
    fn au3b_variable_au_plancher_n_avertit_pas() {
        if let Some(dir) = repertoire_de_l_enfant("variable-au-plancher") {
            jouer_l_enfant("variable-au-plancher", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3b-variable-au-plancher");
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3b_variable_au_plancher_n_avertit_pas")])
            .env(ENFANT, format!("variable-au-plancher|{tmp}"));
        let sortie = relancer(commande, Some(MATIERE_AU_PLANCHER));
        assert_eq!(sortie.status.code(), Some(0), "l'enfant joue jusqu'au bout ; {}", tout(&sortie));
        assert_eq!(issues(&sortie), vec![hex_encode(MATIERE_AU_PLANCHER.as_bytes())], "clé = variable ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[session]"), vec![LIGNE_CONFIGURATION.to_string()], "aucun WARN ; {}", tout(&sortie));
        assert_eq!(noms(&tmp), Vec::<String>::new(), "aucune clé persistée écrite ; {}", tout(&sortie));
    }

    /// Référence `file:` vers un fichier d'un octet sous le plancher, variable longue posée : refus, et le chemin
    /// référencé n'est pas au journal.
    #[test]
    fn au3b_reference_fichier_sous_le_plancher_refuse_le_demarrage() {
        if let Some(dir) = repertoire_de_l_enfant("reference-courte") {
            jouer_l_enfant("reference-courte", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3b-reference-courte");
        let chemin = monter(&tmp, Some(MATIERE_COURTE));
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3b_reference_fichier_sous_le_plancher_refuse_le_demarrage")])
            .env(ENFANT, format!("reference-courte|{tmp}"));
        let sortie = relancer(commande, Some(MATIERE_DE_LA_VARIABLE));
        refus_sous_le_plancher(&sortie, &tmp, &chemin);
    }

    /// Le plancher se compte en OCTETS : un fichier monté de 32 octets en 16 caractères démarre, provenance « secret
    /// monté », sans la matière au journal.
    #[test]
    fn au3b_fichier_monte_multioctet_au_plancher_en_octets_demarre() {
        if let Some(dir) = repertoire_de_l_enfant("fichier-multioctet") {
            jouer_l_enfant("fichier-multioctet", &dir);
            return;
        }
        assert!(MATIERE_MULTIOCTET.chars().count() < 32, "contrôle de la fixture : sous le plancher en caractères");
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3b-fichier-multioctet");
        let chemin = monter(&tmp, Some(&format!("{MATIERE_MULTIOCTET}\n")));
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3b_fichier_monte_multioctet_au_plancher_en_octets_demarre")])
            .env(ENFANT, format!("fichier-multioctet|{tmp}"));
        let sortie = relancer(commande, None);
        assert_eq!(sortie.status.code(), Some(0), "l'enfant joue jusqu'au bout ; {}", tout(&sortie));
        assert_eq!(issues(&sortie), vec![hex_encode(MATIERE_MULTIOCTET.as_bytes())], "clé = matière montée ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[session]"), vec![LIGNE_MONTEE.to_string()], "{}", tout(&sortie));
        let stderr = String::from_utf8_lossy(&sortie.stderr);
        assert!(!stderr.contains(MATIERE_MULTIOCTET) && !stderr.contains(&chemin), "ni la matière ni le chemin au journal ; {}", tout(&sortie));
        assert_eq!(noms(&tmp), vec!["monte".to_string()], "aucune clé persistée écrite ; {}", tout(&sortie));
    }

    /// La même matière de 32 octets en 16 caractères, en variable nue : la ligne de provenance seule, aucun WARN.
    #[test]
    fn au3b_variable_multioctet_au_plancher_en_octets_n_avertit_pas() {
        if let Some(dir) = repertoire_de_l_enfant("variable-multioctet") {
            jouer_l_enfant("variable-multioctet", &dir);
            return;
        }
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3b-variable-multioctet");
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3b_variable_multioctet_au_plancher_en_octets_n_avertit_pas")])
            .env(ENFANT, format!("variable-multioctet|{tmp}"));
        let sortie = relancer(commande, Some(MATIERE_MULTIOCTET));
        assert_eq!(sortie.status.code(), Some(0), "l'enfant joue jusqu'au bout ; {}", tout(&sortie));
        assert_eq!(issues(&sortie), vec![hex_encode(MATIERE_MULTIOCTET.as_bytes())], "clé = variable ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[session]"), vec![LIGNE_CONFIGURATION.to_string()], "aucun WARN ; {}", tout(&sortie));
        assert_eq!(noms(&tmp), Vec::<String>::new(), "aucune clé persistée écrite ; {}", tout(&sortie));
    }

    /// Le plancher de la variable nue se mesure APRÈS rognage : 31 octets entourés de blanc (plus de 32 bruts) démarrent
    /// avec la matière rognée, la ligne de provenance puis le WARN ENTIER.
    #[test]
    fn au3b_variable_sous_le_plancher_une_fois_rognee_avertit() {
        if let Some(dir) = repertoire_de_l_enfant("variable-courte-entouree") {
            jouer_l_enfant("variable-courte-entouree", &dir);
            return;
        }
        let variable = format!("  \t{MATIERE_COURTE}\n ");
        assert!(variable.len() > 32, "contrôle de la fixture : brute, elle passe le plancher");
        let tmp = crate::tmp_possede::TmpPossede::neuf("au3b-variable-courte-entouree");
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("{MODULE}au3b_variable_sous_le_plancher_une_fois_rognee_avertit")])
            .env(ENFANT, format!("variable-courte-entouree|{tmp}"));
        let sortie = relancer(commande, Some(&variable));
        assert_eq!(sortie.status.code(), Some(0), "l'enfant joue jusqu'au bout ; {}", tout(&sortie));
        assert_eq!(issues(&sortie), vec![hex_encode(MATIERE_COURTE.as_bytes())], "clé = variable rognée ; {}", tout(&sortie));
        assert_eq!(lignes(&sortie, "[session]"), vec![LIGNE_CONFIGURATION.to_string(), LIGNE_VARIABLE_COURTE.to_string()], "{}", tout(&sortie));
        assert!(!String::from_utf8_lossy(&sortie.stderr).contains(MATIERE_COURTE), "la matière n'est pas au journal ; {}", tout(&sortie));
        assert_eq!(noms(&tmp), Vec::<String>::new(), "aucune clé persistée écrite ; {}", tout(&sortie));
    }
}

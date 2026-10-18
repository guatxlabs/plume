// `P10.33-w` — UN PUITS `file` DU GRAND LIVRE N'ÉCRIT JAMAIS DANS LA BASE VIVANTE.
//
// VU (re-mesuré) : `ledger_file_target_validate` ne vérifiait que le confinement à la racine d'export, le nom simple,
// l'absence de lien symbolique et le fichier régulier. Racine d'export posée sur le répertoire de la base : `plume.db`
// est un fichier régulier dans la racine, donc ACCEPTÉ, et `ledger_sink_write` ouvrait en ajout le fichier SQLite pour y
// écrire des lignes JSONL (et pareil pour `-wal`, `-shm`, `-journal`).
//
// TENU : trois refus nommés (`REFUS_PUITS_SUR_LA_BASE_VIVANTE`) dans `ledger_file_target_validate`, donc à la création
// du puits ET à l'écriture confinée : nom d'un fichier de base, répertoire de la base, même fichier par lien dur. Chaque
// témoin isole UNE branche (les deux autres ne peuvent pas refuser son cas).
//
// MUTANTS JOUÉS (sous cfg!(test), par variable de mutation, retirés avant le commit) : `w_sans_nom`, `w_sans_repertoire`,
// `w_sans_inode` (la branche correspondante ne refuse plus), `w_lien_dur_base_seul` (le lien dur n'est cherché que vers
// la base elle-même, plus vers ses compagnons `-wal`, `-shm`, `-journal`).
mod puits_du_registre_refuse_la_base {
    use super::*;

    /// Une base factice dans son répertoire, et une racine d'export séparée. La base n'est jamais ouverte par le
    /// témoin : sa taille se lit par `metadata`.
    struct Scene {
        _dossier_de_base: crate::tmp_possede::TmpPossede,
        _racine_separee: crate::tmp_possede::TmpPossede,
        base: std::path::PathBuf,
        dossier: std::path::PathBuf,
        racine: std::path::PathBuf,
    }

    const OCTETS_DE_LA_BASE: &[u8] = b"SQLite format 3\0-base-factice-du-temoin";

    fn scene() -> Scene {
        let dossier_de_base = crate::tmp_possede::TmpPossede::neuf("p1033w-base");
        let racine_separee = crate::tmp_possede::TmpPossede::neuf("p1033w-racine");
        let base = dossier_de_base.join("plume.db");
        std::fs::write(&base, OCTETS_DE_LA_BASE).expect("base factice");
        let dossier = dossier_de_base.to_path_buf();
        let racine = racine_separee.to_path_buf();
        Scene { _dossier_de_base: dossier_de_base, _racine_separee: racine_separee, base, dossier, racine }
    }

    fn refus(r: Result<std::path::PathBuf, String>, contexte: &str) -> String {
        match r {
            Ok(p) => panic!("{contexte} : cible ACCEPTÉE ({}) alors qu'elle vise la base vivante", p.display()),
            Err(e) => {
                assert!(e.starts_with(REFUS_PUITS_SUR_LA_BASE_VIVANTE), "{contexte} : refus non nommé : {e}");
                e
            }
        }
    }

    fn taille(p: &std::path::Path) -> u64 {
        std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
    }

    /// Branche 1 (NOM) : racine SÉPARÉE (le répertoire ne refuse pas), cibles inexistantes (aucun lien dur) nommées
    /// comme un fichier de base -> refusées ; une cible sœur légitime passe.
    #[test]
    fn p1033w_un_nom_de_fichier_de_base_est_refuse_meme_hors_du_repertoire_de_la_base() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let s = scene();
        let _db = ReglageBackupPose::neuf("PLUME_DB", &s.base.to_string_lossy());
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        for suffixe in SUFFIXES_DES_FICHIERS_DE_BASE {
            let cible = s.racine.join(format!("plume.db{suffixe}"));
            let e = refus(ledger_file_target_validate(&s.racine, &cible.to_string_lossy()), &format!("nom plume.db{suffixe}"));
            assert!(e.contains(&format!("plume.db{suffixe}")), "le refus nomme le fichier : {e}");
        }
        // La base du plan de contrôle (à côté de PLUME_DB par défaut) : son nom est refusé aussi.
        refus(
            ledger_file_target_validate(&s.racine, &s.racine.join("plume-control.db-wal").to_string_lossy()),
            "nom de la base du plan de contrôle",
        );
        // Contre-épreuve : une cible sœur légitime, dans la racine séparée, est acceptée.
        let ok = s.racine.join("audit.jsonl");
        assert!(ledger_file_target_validate(&s.racine, &ok.to_string_lossy()).is_ok(), "cible légitime refusée");
        assert!(
            ledger_file_target_validate(&s.racine, &s.racine.join("plume.db.jsonl").to_string_lossy()).is_ok(),
            "un nom qui ne fait que COMMENCER par celui de la base n'est pas un fichier de base"
        );
    }

    /// Branche 2 (RÉPERTOIRE) : racine d'export = répertoire de la base, cible au nom neutre et inexistante (ni nom de
    /// base, ni lien dur) -> refusée, à la création comme à l'écriture ; la base n'a pas bougé d'un octet.
    #[test]
    fn p1033w_une_racine_d_export_sur_le_repertoire_de_la_base_refuse_toute_cible() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let s = scene();
        let _db = ReglageBackupPose::neuf("PLUME_DB", &s.base.to_string_lossy());
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        let cible = s.dossier.join("audit.jsonl");
        let e = refus(ledger_file_target_validate(&s.dossier, &cible.to_string_lossy()), "répertoire de la base (création)");
        assert!(e.contains("répertoire"), "le refus dit que c'est le répertoire de la base : {e}");
        let ecriture = ledger_sink_write("file", &cible.to_string_lossy(), &["{\"l\":1}".to_string()], Some(s.dossier.as_path()));
        let e = ecriture.expect_err("écriture confinée dans le répertoire de la base ACCEPTÉE");
        assert!(e.starts_with(REFUS_PUITS_SUR_LA_BASE_VIVANTE), "refus d'écriture non nommé : {e}");
        assert!(std::fs::symlink_metadata(&cible).is_err(), "la cible a été créée malgré le refus");
        // Le scénario de production : la base elle-même comme cible, à l'écriture -> rien n'est ajouté au fichier.
        let avant = taille(&s.base);
        let e = ledger_sink_write("file", &s.base.to_string_lossy(), &["{\"l\":1}".to_string()], Some(s.dossier.as_path()))
            .expect_err("écriture confinée sur plume.db ACCEPTÉE");
        assert!(e.starts_with(REFUS_PUITS_SUR_LA_BASE_VIVANTE), "refus d'écriture non nommé : {e}");
        assert_eq!(taille(&s.base), avant, "le fichier de base a grossi : des lignes y ont été ajoutées");
        assert_eq!(avant, OCTETS_DE_LA_BASE.len() as u64, "contrôle : la base factice a sa taille d'origine");
        // Contre-épreuve : un SOUS-répertoire du répertoire de la base (le défaut `ledger-export`) reste une racine sûre.
        let sous = s.dossier.join("ledger-export");
        std::fs::create_dir_all(&sous).expect("sous-répertoire");
        assert!(
            ledger_file_target_validate(&sous, &sous.join("audit.jsonl").to_string_lossy()).is_ok(),
            "le sous-répertoire d'export par défaut est refusé"
        );
    }

    /// Branche 3 (MÊME FICHIER) : un lien dur vers la base, au nom neutre, dans une racine séparée -> refusé ; un
    /// fichier régulier distinct au même endroit passe.
    #[test]
    fn p1033w_un_lien_dur_vers_la_base_est_refuse() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let s = scene();
        let _db = ReglageBackupPose::neuf("PLUME_DB", &s.base.to_string_lossy());
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        let lien = s.racine.join("copie.jsonl");
        // Les deux répertoires possédés sont sous la même racine temporaire : même système de fichiers.
        std::fs::hard_link(&s.base, &lien).expect("lien dur vers la base factice");
        let e = refus(ledger_file_target_validate(&s.racine, &lien.to_string_lossy()), "lien dur vers la base");
        assert!(e.contains("lien dur"), "le refus dit lien dur : {e}");
        let distinct = s.racine.join("distinct.jsonl");
        std::fs::write(&distinct, b"").expect("fichier distinct");
        assert!(ledger_file_target_validate(&s.racine, &distinct.to_string_lossy()).is_ok(), "fichier distinct refusé");
    }

    /// Branche 3 (MÊME FICHIER), compagnons : un lien dur vers `plume.db-wal`, `-shm` ou `-journal`, au nom neutre,
    /// dans une racine séparée -> refusé, et le refus nomme le compagnon. Ni le nom ni le répertoire ne peuvent refuser.
    #[test]
    fn p1033w_un_lien_dur_vers_un_compagnon_de_la_base_est_refuse() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let s = scene();
        let _db = ReglageBackupPose::neuf("PLUME_DB", &s.base.to_string_lossy());
        let _ctl = ReglageBackupPose::retire("PLUME_CONTROL_DB");
        for suffixe in ["-wal", "-shm", "-journal"] {
            let compagnon = s.dossier.join(format!("plume.db{suffixe}"));
            std::fs::write(&compagnon, b"compagnon-factice").expect("compagnon factice");
            let lien = s.racine.join(format!("neutre{suffixe}.jsonl"));
            std::fs::hard_link(&compagnon, &lien).expect("lien dur vers le compagnon factice");
            let e = refus(ledger_file_target_validate(&s.racine, &lien.to_string_lossy()), &format!("lien dur vers plume.db{suffixe}"));
            assert!(e.contains("lien dur") && e.contains(&format!("plume.db{suffixe}")), "le refus nomme le compagnon : {e}");
        }
    }
}

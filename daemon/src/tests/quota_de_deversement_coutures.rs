// ================================================================================================
// P10.1-b / P7.18-a — LES COUTURES DU QUOTA DE DÉVERSEMENT, TENUES PAR UN TÉMOIN ET PAS SEULEMENT PAR LA COMPILATION
// ================================================================================================
// Le quota est sorti de `sqlite_plafond.rs` vers le module feuille `quota_deversement.rs`. Un relevé de
// mutants a montré que deux de ses promesses n'étaient tenues par aucun test :
//   - le contrôle positif du démarrage pouvait rendre `Ok` sans rien vérifier (un répertoire où rien ne
//     s'écrit passait pour mesurable, donc un quota inexistant s'annonçait ARMÉ) ;
//   - `oublier_refus_de_quota` pouvait ne rien effacer (une note laissée par une requête précédente
//     faisait passer une annulation pour un franchissement de quota : un refus qui nomme la mauvaise cause).

#[cfg(test)]
mod quota_de_deversement_coutures {
    use crate::quota_deversement::{
        controle_positif_de_la_mesure, mesure_redescendue, oublier_refus_de_quota,
        poser_la_surveillance_du_quota, refus_de_quota_de_deversement, sonde_vue,
        TAILLE_SONDE_QUOTA_POUR_TEMOIN,
    };
    use crate::tmp_possede::TmpPossede;
    use rusqlite::Connection;

    /// Une instruction assez longue pour passer plusieurs fois par le rappel de progression.
    const LONGUE: &str = "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 2000000) \
                          SELECT count(*) FROM c";

    /// MUTATION : `controle_positif_de_la_mesure` rend `Ok(())` d'office ⇒ ce témoin ROUGIT.
    #[test]
    fn le_controle_positif_de_la_mesure_refuse_un_repertoire_ou_rien_ne_s_ecrit() {
        let r = controle_positif_de_la_mesure(std::path::Path::new("/proc/repertoire-qui-nexiste-pas"));
        assert!(
            r.is_err(),
            "un répertoire où la sonde ne peut pas s'écrire ne valide AUCUNE mesure : le quota doit sortir \
             NON MESURABLE, pas ARMÉ (rendu : {r:?})"
        );
    }

    /// MUTATION : `oublier_refus_de_quota` sans effet ⇒ la note posée reste et ce témoin ROUGIT.
    /// Témoin positif d'abord : la note est bien posée par un franchissement, et consommée à la lecture.
    #[test]
    fn une_note_de_refus_non_consommee_est_oubliee_avant_la_requete_suivante() {
        let dir = TmpPossede::neuf("quota-coutures");
        let conn = Connection::open_in_memory().expect("connexion en mémoire");
        // Quota NÉGATIF : toute mesure lue le franchit, donc l'instruction est arrêtée à coup sûr.
        poser_la_surveillance_du_quota(&conn, dir.to_path_buf(), -1);
        oublier_refus_de_quota();

        let r = conn.query_row(LONGUE, [], |l| l.get::<_, i64>(0));
        assert!(r.is_err(), "un quota franchi doit ARRÊTER l'instruction (rendu : {r:?})");
        assert!(refus_de_quota_de_deversement().is_some(), "le franchissement doit laisser sa note");
        assert!(refus_de_quota_de_deversement().is_none(), "la note est consommée à la première lecture");

        let r = conn.query_row(LONGUE, [], |l| l.get::<_, i64>(0));
        assert!(r.is_err(), "second franchissement attendu (rendu : {r:?})");
        oublier_refus_de_quota();
        assert!(
            refus_de_quota_de_deversement().is_none(),
            "une note non consommée doit être EFFACÉE par `oublier_refus_de_quota` : sinon la requête \
             suivante se verrait refuser pour une cause qui n'est pas la sienne"
        );
    }

    /// MUTATION : le deuxième temps du contrôle (sonde déliée VUE) neutralisé ⇒ ce témoin ROUGIT.
    /// Corpus RÉEL : un répertoire atteint par un LIEN SYMBOLIQUE. `/proc/self/fd` rend le chemin
    /// CANONIQUE, donc la sonde tenue n'est pas vue sous le lien : la mesure ne voit rien, et le quota
    /// doit sortir NON MESURABLE. Témoin positif d'abord : le même répertoire nommé canoniquement passe.
    #[test]
    fn le_controle_positif_refuse_une_mesure_qui_ne_voit_pas_la_sonde() {
        let racine = TmpPossede::neuf("quota-lien");
        let reel = racine.join("reel");
        std::fs::create_dir(&reel).expect("répertoire réel");
        let reel = std::fs::canonicalize(&reel).expect("chemin canonique");
        let lien = racine.join("lien");
        std::os::unix::fs::symlink(&reel, &lien).expect("lien symbolique");

        let r = controle_positif_de_la_mesure(&reel);
        assert!(r.is_ok(), "témoin positif : sous son chemin canonique, la sonde est vue (rendu : {r:?})");
        let r = controle_positif_de_la_mesure(&lien);
        assert!(
            matches!(&r, Err(e) if e.contains("n'a pas été vu")),
            "sous un lien symbolique la mesure ne voit pas la sonde : le contrôle doit le DIRE (rendu : {r:?})"
        );
    }

    /// MUTATIONS : l'un ou l'autre temps pur neutralisé ⇒ ce témoin ROUGIT. Une mesure qui rend toujours
    /// un grand nombre passe le deuxième temps ; seul le troisième (retour à la référence) la refuse.
    #[test]
    fn les_deux_temps_purs_du_controle_refusent_et_acceptent_ce_qu_ils_doivent() {
        let dir = std::path::Path::new("/d");
        let t = TAILLE_SONDE_QUOTA_POUR_TEMOIN;
        assert!(sonde_vue(dir, 100, 100 + t).is_ok(), "monté d'exactement la sonde : vue");
        assert!(sonde_vue(dir, 100, 100 + t - 1).is_err(), "monté de moins que la sonde : NON vue");
        assert!(mesure_redescendue(100, 100).is_ok(), "retour à la référence : accepté");
        assert!(
            mesure_redescendue(100, 100 + t).is_err(),
            "une mesure qui ne redescend pas (toujours grande) doit être REFUSÉE"
        );
    }
}

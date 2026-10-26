// =====================================================================================
// `P10.29-l` (correction) — UN REFUS `db` N'EST PAS SERVI COMME UNE LECTURE RATÉE, ET IL PORTE UN IDENTIFIANT.
//
// LE DÉFAUT, RELEVÉ PAR UN VÉRIFICATEUR SUR 71796725. `purge_refusal_response` servait pour `db` la phrase « lecture de
// la base NON FAITE : la purge n'a rien décidé ». Or `PurgeRefusal::Db` porte AUSSI les écritures refusées de
// l'exécution (`purge.rs` : inscription au registre, `DELETE FROM event`, reconstruction des rollups, `COMMIT`) : une
// cause fausse était servie. Sa trace : plan 200, trigger `BEFORE DELETE ON event` qui lève `RAISE(ABORT)`, exécution
// par la route -> 500 `db` « NON FAITE », six events intacts. Le corps ne portait pas non plus d'identifiant de
// corrélation.
//
// CE QUE CES TÉMOINS JUGENT, par la ROUTE `purge_apply_route` entière (porte de témoin ouverte sur ce fil, compte admin) :
//  - le `DELETE` refusé par le moteur : 500, corps ENTIER `{ok:false, refusal:"db", message:<phrase neutre>, id}`,
//    « NON FAITE » et le texte du moteur absents du corps, events et registre inchangés ;
//  - le `COMMIT` refusé (clé étrangère DIFFÉRÉE violée par le `DELETE`) : le refus direct est bien celui du `COMMIT`,
//    la route sert la même phrase neutre, et « aucune ligne supprimée » est VRAI — events et registre relus inchangés
//    sur l'écrivain, aucune transaction laissée pendante ;
//  - l'identifiant `id` est celui de la séquence de `err_json` (`plume-e<pid>-<n>`), un neuf par refus.
// MUTANTS JOUÉS (VERIF_MUT sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : `AU4C_DB_PHRASE_LECTURE`
// (`db` reçoit la phrase de lecture), `AU4C_SANS_ID` (corps sans `id`), `AU4C_ID_DIFFERENT` (la ligne de journal ne
// porte pas l'identifiant servi), `AU4C_JOURNAL_DB_LECTURE` (la ligne de `db` dit « lecture non faite »),
// `AU4C_COMMIT_SANS_ROLLBACK` (le `COMMIT` refusé n'est pas suivi du `ROLLBACK`).
// CE QUE CES TÉMOINS NE TIENNENT PAS : un `ROLLBACK` lui-même refusé après un `COMMIT` refusé (non provoqué : la
// transaction resterait pendante, non validée) ; le tenant n'est pas nommé sur la ligne `[purge]` (la fabrique ne le
// reçoit pas, l'identifiant relie la ligne au ticket) ; la reconstruction des rollups refusée n'est pas provoquée ici
// (même variante, même fabrique).
// =====================================================================================
mod purge_refus_d_ecriture_servi_sous_phrase_neutre {
    use super::*;

    /// Phrase attendue pour `db`, écrite ICI (pas relue dans la constante de production).
    const PRDE_PHRASE_DB: &str = "REFUS — la base a refusé l'opération : la purge n'est pas faite, aucune ligne \
         supprimée. La cause est écrite au journal du démon, sous l'identifiant servi.";

    /// Juge un refus `db` servi : 500, corps entier, `id` de la séquence d'`err_json`, ni « NON FAITE » ni `moteur`.
    fn prde_juger_le_refus_db(statut: u16, corps: &Value, moteur: &str) -> String {
        assert_eq!(statut, 500, "`db` servi en 500 : {corps}");
        let id = corps["id"].as_str().unwrap_or_else(|| panic!("`id` de corrélation servi : {corps}")).to_string();
        let n = id.strip_prefix(&format!("plume-e{}-", std::process::id())).unwrap_or_else(|| panic!("forme de `{id}`"));
        assert!(!n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()), "forme de `{id}`");
        assert_eq!(
            corps,
            &json!({ "ok": false, "refusal": "db", "message": PRDE_PHRASE_DB, "id": id }),
            "corps entier, phrase neutre"
        );
        let texte = corps.to_string();
        assert!(!texte.contains("NON FAITE") && !texte.contains("lecture"), "ni lecture ni « NON FAITE » : {corps}");
        assert!(!texte.contains(moteur), "le texte du moteur `{moteur}` hors du corps : {corps}");
        id
    }

    /// Plan nominal par la route : rend le jeton.
    async fn prde_jeton(st: &AppState, au: &AuthUser) -> String {
        let (statut, plan) = pcr_plan(st, au).await;
        assert_eq!(statut, 200, "précondition : plan servi : {plan}");
        plan["token"].as_str().expect("jeton servi").to_string()
    }

    /// Le `DELETE` refusé par le moteur, après un plan 200 : phrase neutre, rien supprimé, registre inchangé.
    #[tokio::test]
    async fn prde_delete_refuse_par_le_moteur_sert_la_phrase_neutre() {
        let (st, _p) = pcr_etat("prde-delete");
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        let jeton = prde_jeton(&st, &au).await;
        let registre = with_write(&st, &au, |c| pcr_registre(c));
        pcr_ecrire(&st, &au, "CREATE TRIGGER prde_refus BEFORE DELETE ON event BEGIN SELECT RAISE(ABORT, 'prde-moteur'); END;");
        let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
        let premier = prde_juger_le_refus_db(statut, &corps, "prde-moteur");
        assert_eq!(pcr_events_servis(&st, &au), 6, "aucune ligne supprimée");
        assert_eq!(with_write(&st, &au, |c| pcr_registre(c)), registre, "registre inchangé (ROLLBACK)");
        assert!(with_write(&st, &au, |c| c.is_autocommit()), "aucune transaction laissée pendante");
        let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
        let second = prde_juger_le_refus_db(statut, &corps, "prde-moteur");
        assert_ne!(premier, second, "un identifiant neuf par refus");
    }

    /// Pose une clé étrangère DIFFÉRÉE vers `event` : le `DELETE` passe, le `COMMIT` est refusé.
    fn prde_poser_la_cle_differee(st: &AppState, au: &AuthUser) {
        pcr_ecrire(
            st,
            au,
            "PRAGMA foreign_keys=ON; \
             CREATE TABLE prde_enfant(e INTEGER REFERENCES event(id) DEFERRABLE INITIALLY DEFERRED); \
             INSERT INTO prde_enfant SELECT id FROM event WHERE origin='' LIMIT 1;",
        );
        assert_eq!(with_write(st, au, |c| c.query_row("PRAGMA foreign_keys", [], |r| r.get::<_, i64>(0)).unwrap()), 1);
    }

    /// Le refus direct est bien celui du `COMMIT` : instrument du témoin de route.
    #[test]
    fn prde_commit_refuse_est_le_site_provoque() {
        let (st, _p) = pcr_etat("prde-commit-direct");
        let au = pcr_admin();
        prde_poser_la_cle_differee(&st, &au);
        let r = with_write(&st, &au, |c| {
            let plan = purge_plan(c, pcr_scope()).expect("plan nominal");
            let jeton = plan.digest().to_string();
            purge_confirm_and_apply(c, pcr_scope(), &jeton, "t", "témoin P10.29-l")
        });
        match r {
            Err(PurgeRefusal::Db(t)) => assert!(t.starts_with("COMMIT refusé"), "site provoqué : `{t}`"),
            Err(e) => panic!("refus `db` du COMMIT attendu, rendu `{e}`"),
            Ok(_) => panic!("la clé différée violée refuse le COMMIT"),
        }
        assert_eq!(with_write(&st, &au, |c| pcr_events(c)), 6, "aucune ligne supprimée");
    }

    /// Le `COMMIT` refusé, par la ROUTE : phrase neutre, et « aucune ligne supprimée » relu VRAI.
    #[tokio::test]
    async fn prde_commit_refuse_par_la_route_ne_supprime_rien() {
        let (st, _p) = pcr_etat("prde-commit");
        let au = pcr_admin();
        let _ouverte = porte_de_purge_de_temoin::ouvrir();
        prde_poser_la_cle_differee(&st, &au);
        let jeton = prde_jeton(&st, &au).await;
        let registre = with_write(&st, &au, |c| pcr_registre(c));
        let (statut, corps) = pcr_apply(&st, &au, &jeton).await;
        prde_juger_le_refus_db(statut, &corps, "FOREIGN KEY");
        assert!(with_write(&st, &au, |c| c.is_autocommit()), "transaction annulée, rien de pendant sur l'écrivain");
        assert_eq!(pcr_events_servis(&st, &au), 6, "aucune ligne supprimée : la phrase servie dit vrai");
        assert_eq!(with_write(&st, &au, |c| pcr_registre(c)), registre, "registre inchangé");
    }

    /// LA LIGNE DE JOURNAL d'un refus `db` produit par la route porte l'identifiant SERVI, et dit « refus de la base ».
    #[tokio::test]
    async fn prde_ligne_de_journal_porte_l_identifiant_servi() {
        const ENFANT: &str = "PRDE_ENFANT_JOURNAL";
        if std::env::var(ENFANT).is_ok() {
            let (st, _p) = pcr_etat("prde-journal");
            let au = pcr_admin();
            let _ouverte = porte_de_purge_de_temoin::ouvrir();
            let jeton = prde_jeton(&st, &au).await;
            pcr_ecrire(&st, &au, "CREATE TRIGGER prde_refus BEFORE DELETE ON event BEGIN SELECT RAISE(ABORT, 'prde-moteur'); END;");
            eprintln!("PRDE-DEBUT");
            let (_, corps) = pcr_apply(&st, &au, &jeton).await;
            eprintln!("PRDE-FIN");
            println!("PRDE-ID:{}", corps["id"].as_str().unwrap_or_default());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::purge_refus_d_ecriture_servi_sous_phrase_neutre::prde_ligne_de_journal_porte_l_identifiant_servi",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let id = stdout.split_once("PRDE-ID:").map(|(_, r)| r.lines().next().unwrap_or("")).unwrap_or("").to_string();
        assert!(id.starts_with("plume-e"), "contrôle : `id` servi : {stdout}");
        let fenetre = stderr
            .split_once("PRDE-DEBUT")
            .and_then(|(_, r)| r.split_once("PRDE-FIN"))
            .map(|(c, _)| c)
            .unwrap_or_else(|| panic!("contrôle : fenêtre de journal : {stderr}"));
        let lignes: Vec<&str> = fenetre.lines().filter(|l| l.contains("[purge] WARN refus servi")).collect();
        assert_eq!(lignes.len(), 1, "une ligne `[purge]` pour le refus : {fenetre}");
        let attendu = format!("[{id}] [purge] WARN refus servi, refus de la base (db) : ");
        assert!(lignes[0].starts_with(&attendu), "ligne `{}` : attendu le préfixe `{attendu}`", lignes[0]);
        assert!(lignes[0].contains("prde-moteur"), "le texte du moteur part au journal : {}", lignes[0]);
        assert!(!lignes[0].contains("lecture"), "la ligne de `db` ne dit pas « lecture » : {}", lignes[0]);
    }
}

// =====================================================================================
// `P10.20-b` — LES DEUX ISSUES DE LA RELECTURE DE `catalog_route` QUE LES TÉMOINS DU VERROU RENDU NE TENAIENT PAS.
//
// `TenantDbManager::catalog_route` lit la ligne du tenant sous le verrou du plan de contrôle, rend le verrou, résout la
// clé, puis RELIT la ligne sous le verrou :
//   * LIGNE INCHANGÉE -> la clé est enregistrée au registre `db_path -> clé` (`register_db_key`), que lisent les
//     connexions de lecture (`query_exec::read_conn_open` par `apply_key_for`). Les témoins du lot passaient par un
//     tenant tout juste provisionné, dont la création avait DÉJÀ enregistré la clé : retirer l'enregistrement les
//     laissait verts. Or après un redémarrage le registre est vide ; sans cet enregistrement, une lecture de la base du
//     tenant retombe sur la clé globale du processus et la base chiffrée devient illisible.
//   * LIGNE CHANGÉE (autre chemin ou autre clé) -> `NonOuvert`, et la cause est dite au journal du démon par
//     `dire_le_tenant_non_ouvert`. C'est la seule trace qui dit à l'exploitant POURQUOI le tenant est refusé : le
//     client ne reçoit que la phrase fixe du 503. Aucun témoin ne lisait cette ligne.
//
// MUTANTS JOUÉS (posés sous `cfg!(test)` et `VERIF_MUT`, retirés avant le commit), chacun vu rouge seul :
// `CL2C_SANS_ENREGISTREMENT` (la clé de la ligne inchangée servie sans être enregistrée) ; `CL2C_CHANGEE_SANS_DIRE` (la
// ligne changée rendue `NonOuvert` sans la dire au journal).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la ligne d'une ligne changée n'est lue que pour un chemin repointé (la clé
// changée passe par le même bras) ; le registre n'est relu qu'au chemin du tenant, pas pour chaque appelant qui le lit.
// =====================================================================================
mod catalogue_enregistre_la_cle_de_la_ligne_inchangee_et_dit_la_ligne_changee {
    use super::*;
    use super::tenant_actif_non_ouvrable_n_est_pas_un_tenant_absent::{
        cl1_issue, cl1_sans_coffre, cl2_chemin_b, cl2_registre, Cl1, Cl2Coffre, CL1_A,
    };

    const CL2C_ENFANT: &str = "CL2C_ENFANT_LIGNE_CHANGEE_DITE_AU_JOURNAL";
    const CL2C_DEBUT: &str = "CL2C-DEBUT";
    const CL2C_FIN: &str = "CL2C-FIN";

    /// La ligne attendue au journal, écrite ici en toutes lettres : le témoin ne compare jamais une sortie de la
    /// production à elle-même.
    const CL2C_LIGNE_CHANGEE: &str = "[multi-tenant] tenant 'cl1-a' : clé non résolue -> FAIL-CLOSED, base NON ouverte (la \
         ligne du tenant a changé au catalogue pendant la résolution de sa clé : aucune clé enregistrée). Ce n'est ni un \
         tenant absent ni un tenant suspendu : dit une fois jusqu'à la prochaine ouverture réussie de sa base.";

    /// CE QU'IL TIENT : A provisionné sur sa clé `vault:` (valeur au cache du client du coffre), puis un REDÉMARRAGE :
    /// l'entrée de A retirée du registre `db_path -> clé`, son écrivain retiré du cache. La ligne de A ne change pas
    /// pendant la résolution. `disponibilite_lu` rend A servi ET enregistre sa clé pour son chemin ; une lecture de la
    /// base de A par les connexions de lecture (`read_with`, qui applique la clé du registre) aboutit — sans
    /// l'enregistrement, elle s'ouvrirait sous la clé globale du processus et la base chiffrée serait illisible.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CL2C_SANS_ENREGISTREMENT`.
    #[test]
    fn cl2c_la_cle_de_la_ligne_inchangee_est_enregistree_apres_un_redemarrage() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("cl2c-redemarrage");
        let chemin_a = f.chemin_a();
        crate::crypto::unregister_db_key(&chemin_a);
        f.st.tenants.writers.lock().remove(CL1_A);
        let avant = cl2_registre(&chemin_a);
        let issue = cl1_issue(&f.st.tenants.disponibilite_lu(CL1_A));
        let apres = cl2_registre(&chemin_a);
        let lue: Result<i64, String> = crate::query_exec::read_with(&chemin_a, Err("connexion de lecture non ouverte".into()), |c| {
            c.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='event'", [], |r| r.get(0)).map_err(|e| e.to_string())
        });
        assert_eq!(avant, None, "contrôle : redémarrage, le registre n'a aucune entrée pour le chemin de A");
        assert_eq!(issue, "servie", "la ligne inchangée : A servi");
        assert_eq!(lue, Ok(1), "la base chiffrée de A se lit par les connexions de lecture, sous SA clé");
        assert_eq!(apres, Some(Some(f.cle.clone())), "la clé de A est enregistrée pour le chemin de A");
    }

    /// CE QU'IL TIENT, dans un processus neuf (mémo des lignes vide) : la clé de A hors du cache, résolue par un coffre
    /// local qui repointe le chemin de A sur celui de B avant de répondre. Entre les deux marqueurs qui encadrent la
    /// résolution, la sortie d'erreur porte EXACTEMENT une ligne `[multi-tenant]`, la ligne ENTIÈRE de la ligne changée
    /// (classe clé non résolue, son détail) ; l'enfant vérifie aussi l'issue rendue.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CL2C_CHANGEE_SANS_DIRE`.
    #[test]
    fn cl2c_la_ligne_changee_pendant_la_resolution_est_dite_au_journal() {
        if std::env::var(CL2C_ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            cl2c_enfant_ligne_changee();
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::catalogue_enregistre_la_cle_de_la_ligne_inchangee_et_dit_la_ligne_changee::cl2c_la_ligne_changee_pendant_la_resolution_est_dite_au_journal",
            ])
            .env(CL2C_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 (issue, geste du coffre) : {stdout}\n{stderr}");
        let debut = stderr.find(CL2C_DEBUT).unwrap_or_else(|| panic!("contrôle : l'enfant marque le début :\n{stderr}"));
        let fin = stderr.find(CL2C_FIN).unwrap_or_else(|| panic!("contrôle : l'enfant marque la fin :\n{stderr}"));
        let pendant: Vec<&str> = stderr[debut..fin].lines().filter(|l| l.starts_with("[multi-tenant]")).collect();
        assert_eq!(pendant, vec![CL2C_LIGNE_CHANGEE], "la ligne changée est dite au journal, entière, une fois :\n{stderr}");
    }

    fn cl2c_enfant_ligne_changee() {
        cl1_sans_coffre();
        let f = Cl1::neuf("cl2c-journal");
        let chemin_b = cl2_chemin_b(&f);
        let mgr = f.st.tenants.clone();
        let repointe = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let note = repointe.clone();
        let coffre = Cl2Coffre::neuf(f.cle.clone(), false, move || {
            let cp = mgr.control.as_ref().expect("enfant : mode 1");
            let ecrit = cp.conn.lock().execute("UPDATE tenant SET db_path=?1 WHERE id='cl1-a'", params![chemin_b]);
            note.store(matches!(ecrit, Ok(1)), std::sync::atomic::Ordering::SeqCst);
        });
        f.cle_perdue();
        coffre.brancher();
        eprintln!("{CL2C_DEBUT}");
        let issue = cl1_issue(&f.st.tenants.disponibilite_lu(CL1_A));
        eprintln!("{CL2C_FIN}");
        cl1_sans_coffre();
        assert!(repointe.load(std::sync::atomic::Ordering::SeqCst), "enfant : chemin de A repointé pendant la résolution");
        assert_eq!(coffre.requetes(), 1, "enfant : une requête au coffre");
        assert_eq!(issue, "non ouvert : clé non résolue", "enfant : la ligne changée rend A non ouvert");
    }
}

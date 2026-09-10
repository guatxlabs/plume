// =====================================================================================
// `P4.7-f` — LE CENTRAL N'ÉCRASE PLUS LE VERDICT QUE L'AGENT VIENT DE POSER. Mesuré le 2026-08-28 : le
// responder local exécutait même une action déjà RÉCLAMÉE par un agent, et sa clôture finale n'était
// gardée sur aucun statut — un « adresse épargnée » posté par l'agent devenait un succès. Deux gestes :
// la sélection consulte l'horodatage de réclamation (une seule fenêtre, partagée avec la re-remise), et
// la clôture n'écrit que sur une action encore `approved` — sinon elle conserve, et le dit au journal.
// =====================================================================================
mod verdict_de_dossier_conserve {
    use super::*;
    use crate::handlers::actions::{ACTIONS_A_RECLAMER_ICI, RECLAMATION_PERIMEE_S, SQL_CLORE_UNE_ACTION_APPROUVEE};

    fn vdc_base() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn));
        conn.execute("DELETE FROM action", []).unwrap();
        conn
    }

    fn vdc_action(conn: &Connection, status: &str, host: Option<&str>, claimed_ts: Option<i64>) -> i64 {
        conn.execute(
            "INSERT INTO action(ts,kind,target,status,dry_run,host,claimed_ts) VALUES(1000,'ban_ip','203.0.113.9',?1,0,?2,?3)",
            params![status, host, claimed_ts],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    fn vdc_selection(conn: &Connection, maintenant: i64) -> Vec<i64> {
        let mut s = conn.prepare(ACTIONS_A_RECLAMER_ICI).unwrap();
        s.query_map(params!["", 0i64, maintenant, RECLAMATION_PERIMEE_S], |r| r.get::<_, i64>(0)).unwrap().flatten().collect()
    }

    #[test]
    fn le_responder_local_laisse_une_action_reclamee_a_l_agent_tant_que_la_reclamation_vaut() {
        let conn = vdc_base();
        let maintenant = 100_000;
        let libre = vdc_action(&conn, "approved", None, None);
        let reclamee = vdc_action(&conn, "approved", None, Some(maintenant - 10));
        let perimee = vdc_action(&conn, "approved", None, Some(maintenant - RECLAMATION_PERIMEE_S - 1));
        let vues = vdc_selection(&conn, maintenant);
        assert!(vues.contains(&libre), "une action que personne n'a réclamée s'exécute ici");
        assert!(!vues.contains(&reclamee), "une action réclamée il y a dix secondes est à l'agent qui l'a réclamée");
        assert!(vues.contains(&perimee), "une réclamation périmée (agent planté) est re-remise ici, comme aux agents");
    }

    #[test]
    fn la_cloture_ne_remplace_pas_un_verdict_deja_pose_et_le_conserve() {
        let conn = vdc_base();
        let deja_jugee = vdc_action(&conn, "failed", Some("hote-a"), Some(50));
        conn.execute("UPDATE action SET result='adresse épargnée par la liste d''épargne' WHERE id=?1", params![deja_jugee]).unwrap();
        let n = conn.execute(SQL_CLORE_UNE_ACTION_APPROUVEE, params![deja_jugee, "done", "ufw insert 1 deny", 200]).unwrap();
        assert_eq!(n, 0, "le verdict de l'agent a le dernier mot");
        let (statut, resultat): (String, String) = conn
            .query_row("SELECT status, result FROM action WHERE id=?1", params![deja_jugee], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!((statut.as_str(), resultat.as_str()), ("failed", "adresse épargnée par la liste d'épargne"), "rien n'est écrasé");
        let encore_ouverte = vdc_action(&conn, "approved", None, None);
        assert_eq!(conn.execute(SQL_CLORE_UNE_ACTION_APPROUVEE, params![encore_ouverte, "done", "ok", 200]).unwrap(), 1, "contrôle positif : une action encore approuvée se clôt");
    }

    /// GARDE DÉRIVÉE : dans le responder local, AUCUNE écriture de statut ne se fait sans la garde
    /// `status='approved'` — une clôture nue réintroduirait l'écrasement.
    #[test]
    fn aucune_cloture_du_responder_local_n_est_nue() {
        let src = std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/handlers/actions.rs")).unwrap();
        let debut = src.find("pub(crate) fn respond_run() {").expect("le responder local existe");
        let fin = src[debut..].find("\n}\n").map(|x| debut + x + 3).unwrap_or(src.len());
        let corps = &src[debut..fin];
        let ecritures: Vec<&str> = corps.lines().filter(|l| l.contains("UPDATE action SET status")).collect();
        assert!(ecritures.len() >= 4, "instrument : {} écriture(s) de statut vue(s), la population attendue est d'au moins quatre", ecritures.len());
        let nues: Vec<&&str> = ecritures.iter().filter(|l| !l.contains("status='approved'")).collect();
        assert!(nues.is_empty(), "clôtures NUES (sans garde `status='approved'`) dans respond_run :\n{}", nues.iter().map(|l| l.trim()).collect::<Vec<_>>().join("\n"));
        assert!(corps.contains("SQL_CLORE_UNE_ACTION_APPROUVEE") && corps.contains("action.exec.verdict-conserve"), "la clôture finale passe par la constante gardée et dit ce qu'elle conserve");
    }

    /// LA QUESTION NON MESURÉE, MESURÉE : le vocabulaire des statuts qu'un dossier peut porter est FERMÉ
    /// et compté dans la source — sept mots, et un huitième rougit ici.
    #[test]
    fn le_vocabulaire_des_statuts_de_dossier_est_ferme_et_compte() {
        let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/handlers");
        let mut vus = std::collections::BTreeSet::new();
        let re = regex::Regex::new(r"status\s*=\s*'([a-z]+)'|status IN \(([^)]*)\)").unwrap();
        for f in ["actions.rs", "playbooks.rs"] {
            let src = std::fs::read_to_string(racine.join(f)).unwrap();
            // Seules les lignes qui parlent de la table `action` comptent : `alert.status` (new, resolved…)
            // vit dans les mêmes fichiers et n'est pas un statut de DOSSIER.
            for ligne in src.lines().filter(|l| l.contains("INTO action(") || l.contains("UPDATE action SET") || l.contains("FROM action")) {
                for c in re.captures_iter(ligne) {
                    if let Some(m) = c.get(1) { vus.insert(m.as_str().to_string()); }
                    if let Some(m) = c.get(2) { for mot in m.as_str().split(',') { vus.insert(mot.trim().trim_matches('\'').to_string()); } }
                }
            }
        }
        // `done` et `failed` n'apparaissent jamais dans un texte SQL : ils atteignent la table par PARAMÈTRE
        // (la clôture gardée et le compte rendu d'agent), depuis des littéraux Rust — comptés ici par leur forme.
        let src_actions = std::fs::read_to_string(racine.join("actions.rs")).unwrap();
        for mot in ["done", "failed"] {
            if src_actions.contains(&format!("\"{mot}\"")) { vus.insert(mot.to_string()); }
        }
        let vocabulaire: std::collections::BTreeSet<String> = ["pending", "approved", "cancelled", "blocked", "dryrun", "done", "failed"].iter().map(|s| s.to_string()).collect();
        assert_eq!(vus, vocabulaire, "le vocabulaire des statuts de dossier est exactement ces sept mots — un mot de plus ou de moins ici est une mesure à refaire, pas un plancher à déplacer");
    }
}

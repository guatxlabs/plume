// =====================================================================================
// `P10.28-l` (trois des huit semis restants) — LE FILET DR VELERO ET LES DEUX PLAYBOOKS DE BAN S'ÉCRIVENT ENTIERS SOUS
// LEUR DRAPEAU, POSÉ EN DERNIER.
//
// LE DÉFAUT, LU SUR cc71144 : `seed_velero_rule`, `seed_example_playbooks`, `seed_ssh_cve_playbook` (seeds.rs) posaient
// leur drapeau `seeded_*` EN PREMIER (écriture avalée), puis leur unique INSERT avalé (`let _`). Un INSERT refusé
// laissait le drapeau posé : la règle DR ou le playbook de riposte n'était JAMAIS resemé.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les cinq autres semis de `P10.28-l` (example_rules, obs_rules, sts_rules, slab,
// k8s : drapeau toujours posé avant les données) ; une base EN SERVICE dont le drapeau est déjà posé sans la ligne
// n'est pas réparée (le semis voit son drapeau et ne fait rien) ; l'aveu au journal (`eprintln!` de
// `semer_sous_son_drapeau`) n'est pas capturé ; la famille « Ok(0) puis `last_insert_rowid` » des semis de tableaux.
// =====================================================================================
mod semis_de_playbooks_et_filet_dr_sous_leur_drapeau {
    use super::*;

    /// (étiquette, drapeau, table, semis, SELECT qui rend la ligne semée en texte, ligne attendue octet pour octet).
    type PfdSemis = (&'static str, &'static str, &'static str, fn(&Connection), &'static str, &'static str);

    fn pfd_semis() -> [PfdSemis; 3] {
        const PLAYBOOK: &str = "SELECT name||'|'||enabled||'|'||query||'|'||is_soql||'|'||action_kind||'|'||interval_s||'|'||window_s FROM playbook WHERE name=?1";
        [
            (
                "velero",
                "seeded_velero_rule",
                "rule",
                seed_velero_rule,
                "SELECT name||'|'||query||'|'||is_soql||'|'||op||'|'||printf('%.1f',threshold)||'|'||severity||'|'||interval_s||'|'||window_s||'|'||enabled FROM rule WHERE name=?1",
                "Backup Velero en échec|metric velero_failed | stats max(value)|1|>|0.0|3|600|3600|0",
            ),
            (
                "playbooks",
                "seeded_playbooks",
                "playbook",
                seed_example_playbooks,
                PLAYBOOK,
                "SSH bruteforce -> ban IP (démo, OFF : laisser CrowdSec/fail2ban gérer)|0|search source=sshd-session severity>=3 | stats count by src_ip | where count > 10|1|ban_ip|300|3600",
            ),
            (
                "ssh_cve",
                "seeded_ssh_cve",
                "playbook",
                seed_ssh_cve_playbook,
                PLAYBOOK,
                "SSH CVE-2024-6387 (regreSSHion) -> ban IP (OFF ; remplace le scénario CrowdSec ssh-cve)|0|search source=~sshd \"Timeout before authentication\" | stats count by src_ip | where count > 5|1|ban_ip|300|3600",
            ),
        ]
    }

    /// (lignes de la table, drapeau posé).
    fn pfd_etat(conn: &Connection, table: &str, drapeau: &str) -> (i64, i64) {
        (
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).expect("compte"),
            conn.query_row("SELECT COUNT(*) FROM meta WHERE key=?1", params![drapeau], |r| r.get(0)).expect("drapeau"),
        )
    }

    fn pfd_lignes(conn: &Connection, select: &str, attendue: &str) -> Vec<String> {
        let nom = attendue.split('|').next().expect("nom");
        let mut st = conn.prepare(select).expect("select");
        st.query_map(params![nom], |r| r.get::<_, String>(0)).expect("lignes").collect::<Result<Vec<_>, _>>().expect("lignes lues")
    }

    /// INVERSE NOMINAL : sur une base neuve, chaque semis écrit UNE ligne, octet pour octet celle d'avant (nom, requête,
    /// `enabled=0`, intervalle, fenêtre…), pose son drapeau, et un second appel n'ajoute rien.
    #[test]
    fn pfd_un_semis_nominal_ecrit_sa_ligne_d_avant_et_son_drapeau_une_seule_fois() {
        for (tag, drapeau, table, semer, select, attendue) in pfd_semis() {
            let conn = test_db();
            let (base, pose) = pfd_etat(&conn, table, drapeau);
            assert_eq!(pose, 0, "`{tag}` : instrument — base neuve sans drapeau");
            semer(&conn);
            assert_eq!(pfd_etat(&conn, table, drapeau), (base + 1, 1), "`{tag}` : une ligne et le drapeau");
            assert_eq!(pfd_lignes(&conn, select, attendue), vec![attendue.to_string()], "`{tag}` : ligne semée octet pour octet");
            semer(&conn);
            assert_eq!(pfd_etat(&conn, table, drapeau), (base + 1, 1), "`{tag}` : second appel idempotent, aucun doublon");
        }
    }

    /// CE QU'IL TIENT, pour les trois semis et deux refus (`RAISE(ABORT)`, et `RAISE(IGNORE)` qui rend `Ok(0)`) : après
    /// le refus, AUCUNE ligne et AUCUN drapeau, transaction fermée ; au démarrage suivant (base revenue), la ligne
    /// attendue et le drapeau ; au démarrage d'après, rien de plus. MUTATIONS QUI LE FONT ROUGIR : le drapeau replacé en
    /// tête (`VERIF_MUT=velero_tete`, `pb_tete`, `cve_tete`), l'INSERT replacé en `let _` (`velero_let`, `pb_let`,
    /// `cve_let`).
    #[test]
    fn pfd_un_semis_refuse_ne_garde_ni_ligne_ni_drapeau_et_se_rejoue_au_demarrage_suivant() {
        for (tag, drapeau, table, semer, select, attendue) in pfd_semis() {
            for (forme, corps) in [("ABORT", "RAISE(ABORT,'pfd refus')"), ("IGNORE", "RAISE(IGNORE)")] {
                let conn = test_db();
                let (base, _) = pfd_etat(&conn, table, drapeau);
                conn.execute_batch(&format!("CREATE TRIGGER pfd_refus BEFORE INSERT ON {table} BEGIN SELECT {corps}; END;"))
                    .expect("déclencheur de refus");
                semer(&conn);
                assert_eq!(pfd_etat(&conn, table, drapeau), (base, 0), "`{tag}` ({forme}) : ni ligne, ni drapeau après le refus");
                assert!(conn.is_autocommit(), "`{tag}` ({forme}) : la transaction du semis est fermée");
                conn.execute_batch("DROP TRIGGER pfd_refus;").expect("base revenue");
                semer(&conn);
                assert_eq!(pfd_etat(&conn, table, drapeau), (base + 1, 1), "`{tag}` ({forme}) : rejoué au démarrage suivant, drapeau posé");
                assert_eq!(pfd_lignes(&conn, select, attendue), vec![attendue.to_string()], "`{tag}` ({forme}) : ligne rejouée octet pour octet");
                semer(&conn);
                assert_eq!(pfd_etat(&conn, table, drapeau), (base + 1, 1), "`{tag}` ({forme}) : aucun doublon ensuite");
            }
        }
    }
}

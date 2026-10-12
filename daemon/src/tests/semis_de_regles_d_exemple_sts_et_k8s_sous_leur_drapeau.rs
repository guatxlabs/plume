// =====================================================================================
// `P10.28-l` (trois des cinq semis restants) — LES RÈGLES D'EXEMPLE (DONT LE PIC D'ÉCHECS D'AUTHENTIFICATION T1110),
// LES RÈGLES DE READINESS STATEFULSET ET LES SEPT RÈGLES K8S « FILET DE SÉCURITÉ » S'ÉCRIVENT ENTIÈRES SOUS LEUR
// DRAPEAU, POSÉ EN DERNIER.
//
// LE DÉFAUT, LU SUR 824949d : `seed_example_rules`, `seed_sts_rules`, `seed_k8s_rules` (seeds.rs) posaient leur drapeau
// `seeded_*` EN PREMIER (écriture avalée), puis chaque INSERT avalé (`let _`). Un INSERT refusé laissait le drapeau
// posé : la règle (brute-force, StatefulSet pas prêt, nœud NotReady, certificat, stockage…) n'était JAMAIS resemée,
// et un refus à la N-ième règle laissait les N-1 premières seules.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les deux autres semis de `P10.28-l` (`seed_obs_rules`, `seed_slab_rule` :
// drapeau toujours posé avant les données) ; une base EN SERVICE dont le drapeau est déjà posé sans la ligne n'est pas
// réparée (le semis voit son drapeau et ne fait rien) ; le gabarit de runbook déjà amputé en service ; l'aveu au
// journal (`eprintln!` de `semer_sous_son_drapeau`) n'est pas capturé.
//
// `seed_sts_rules` lit `PLUME_WATCH_STS` : chaque témoin prend `VERROU_ENV_PROCESSUS.write()` et pose (ou retire)
// la variable lui-même, puis rend la valeur d'avant.
// =====================================================================================
mod semis_de_regles_d_exemple_sts_et_k8s_sous_leur_drapeau {
    use super::*;

    const SEK_LIGNE: &str = "SELECT name||'|'||query||'|'||is_soql||'|'||op||'|'||printf('%.1f',threshold)||'|'||severity||'|'||interval_s||'|'||window_s||'|'||enabled||'|'||mitre FROM rule WHERE id>?1 ORDER BY id";

    fn sek_dernier(conn: &Connection) -> i64 {
        conn.query_row("SELECT COALESCE(MAX(id),0) FROM rule", [], |r| r.get(0)).expect("max id")
    }

    fn sek_lignes(conn: &Connection, depuis: i64) -> Vec<String> {
        let mut st = conn.prepare(SEK_LIGNE).expect("select");
        st.query_map(params![depuis], |r| r.get::<_, String>(0)).expect("lignes").collect::<Result<Vec<_>, _>>().expect("lignes lues")
    }

    fn sek_drapeau(conn: &Connection, drapeau: &str) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM meta WHERE key=?1", params![drapeau], |r| r.get(0)).expect("drapeau")
    }

    fn sek_metrique(nom: &str) -> String {
        format!("SELECT value FROM metric WHERE name='{nom}' AND ts>=__FROM__ ORDER BY ts DESC LIMIT 1")
    }

    /// (étiquette, drapeau, semis, PLUME_WATCH_STS posée (None = retirée), lignes attendues octet pour octet).
    type SekSemis = (&'static str, &'static str, fn(&Connection), Option<&'static str>, Vec<String>);

    fn sek_semis() -> Vec<SekSemis> {
        let k8s = |nom: &str, q: String, soql: i64, op: &str, th: &str, sev: i64, intv: i64, win: i64| {
            format!("{nom}|{q}|{soql}|{op}|{th}|{sev}|{intv}|{win}|0|")
        };
        let sts_generique = "k8s: StatefulSet pas prêt|metric kube_sts_notready | stats max(value)|1|>|0.0|3|120|600|0|".to_string();
        vec![
            (
                "example",
                "seeded_rules",
                seed_example_rules,
                None,
                vec![
                    "Pic d'échecs d'authentification (1h)|search category=auth action=failure | stats count|1|>|100.0|3|300|3600|1|T1110".to_string(),
                    format!("CPU > 90% (10 min)|{}|0|>|90.0|2|300|600|1|", "SELECT value FROM metric WHERE name='cpu_pct' AND ts>=__FROM__ ORDER BY ts DESC LIMIT 1"),
                ],
            ),
            ("sts_sans_liste", "seeded_sts_rules", seed_sts_rules, None, vec![sts_generique.clone()]),
            (
                "sts_avec_liste",
                "seeded_sts_rules",
                seed_sts_rules,
                Some("mail/mailserver vault/vault-0"),
                vec![
                    sts_generique,
                    "mailserver indisponible (statefulset)|metric kube_sts_ready_mailserver | stats min(value)|1|<|1.0|4|120|300|0|".to_string(),
                    "vault-0 indisponible (statefulset)|metric kube_sts_ready_vault_0 | stats min(value)|1|<|1.0|4|120|300|0|".to_string(),
                ],
            ),
            (
                "k8s",
                "seeded_k8s_rules",
                seed_k8s_rules,
                None,
                vec![
                    k8s("k8s: problème pod (CrashLoop/OOMKilled)", "search source=k8s severity>=3 | stats count".to_string(), 1, ">", "0.0", 3, 120, 900),
                    k8s("k8s: deployment dégradé", sek_metrique("kube_deploy_unavailable"), 0, ">", "0.0", 3, 120, 600),
                    k8s("k8s: node NotReady", sek_metrique("kube_nodes_notready"), 0, ">", "0.0", 4, 120, 600),
                    k8s("k8s: stockage > 85%", sek_metrique("kube_storage_pct"), 0, ">", "85.0", 3, 300, 600),
                    k8s("k8s: cert expire < 14j", sek_metrique("cert_days_min"), 0, "<", "14.0", 3, 3600, 86400),
                    k8s("k8s: backup Velero en échec", sek_metrique("velero_failed"), 0, ">", "0.0", 3, 600, 86400),
                    k8s("hôte: disque / > 90%", sek_metrique("disk_root_pct"), 0, ">", "90.0", 3, 300, 600),
                ],
            ),
        ]
    }

    /// Pose (ou retire) `PLUME_WATCH_STS` sous le verrou déjà pris par l'appelant ; rend la valeur d'avant.
    fn sek_poser_la_liste(liste: Option<&str>) -> Option<String> {
        let avant = std::env::var("PLUME_WATCH_STS").ok();
        match liste {
            Some(v) => std::env::set_var("PLUME_WATCH_STS", v),
            None => std::env::remove_var("PLUME_WATCH_STS"),
        }
        avant
    }

    fn sek_rendre_la_liste(avant: Option<String>) {
        match avant {
            Some(v) => std::env::set_var("PLUME_WATCH_STS", v),
            None => std::env::remove_var("PLUME_WATCH_STS"),
        }
    }

    /// INVERSE NOMINAL : sur une base neuve, chaque semis écrit ses règles octet pour octet comme avant (nom, requête,
    /// is_soql, op, seuil, sévérité, intervalle, fenêtre, `enabled` — défaut du DDL pour les règles d'exemple, 0 pour
    /// sts/k8s —, mitre T1110 pour la règle d'authentification), pose son drapeau, et un second appel n'ajoute rien.
    #[test]
    fn sek_un_semis_nominal_ecrit_ses_regles_d_avant_et_son_drapeau_une_seule_fois() {
        let _g = VERROU_ENV_PROCESSUS.write();
        let avant = std::env::var("PLUME_WATCH_STS").ok();
        for (tag, drapeau, semer, liste, attendues) in sek_semis() {
            sek_poser_la_liste(liste);
            let conn = test_db();
            let depuis = sek_dernier(&conn);
            assert_eq!(sek_drapeau(&conn, drapeau), 0, "`{tag}` : instrument — base neuve sans drapeau");
            assert!(sek_lignes(&conn, depuis).is_empty(), "`{tag}` : instrument — aucune règle après l'existant");
            semer(&conn);
            assert_eq!(sek_lignes(&conn, depuis), attendues, "`{tag}` : règles semées octet pour octet");
            assert_eq!(sek_drapeau(&conn, drapeau), 1, "`{tag}` : drapeau posé après le succès");
            semer(&conn);
            assert_eq!(sek_lignes(&conn, depuis), attendues, "`{tag}` : second appel idempotent, aucun doublon");
        }
        sek_rendre_la_liste(avant);
    }

    /// CE QU'IL TIENT, pour chaque semis, chaque règle refusée à son tour (la PREMIÈRE, la DEUXIÈME — dont la deuxième
    /// règle de la boucle `PLUME_WATCH_STS` —, la DERNIÈRE) et deux refus (`RAISE(ABORT)`, et `RAISE(IGNORE)` qui rend
    /// `Ok(0)`) : après le refus, AUCUNE règle conservée (atomicité) et AUCUN drapeau, transaction fermée ; au démarrage
    /// suivant (base revenue), toutes les règles attendues et le drapeau ; au démarrage d'après, rien de plus.
    /// MUTATIONS QUI LE FONT ROUGIR : l'ancienne forme, drapeau en tête et INSERT avalés (`VERIF_MUT=ex_tete`,
    /// `sts_tete`, `k8s_tete`) ; l'INSERT de boucle replacé en `let _` dans le semis (`ex_let`, `sts_let`, `k8s_let`).
    #[test]
    fn sek_un_semis_refuse_ne_garde_ni_regle_ni_drapeau_et_se_rejoue_au_demarrage_suivant() {
        let _g = VERROU_ENV_PROCESSUS.write();
        let avant = std::env::var("PLUME_WATCH_STS").ok();
        for (tag, drapeau, semer, liste, attendues) in sek_semis() {
            sek_poser_la_liste(liste);
            let mut rangs: Vec<usize> = vec![0, 1, attendues.len() - 1];
            rangs.retain(|&r| r < attendues.len());
            rangs.sort_unstable();
            rangs.dedup();
            for rang in rangs {
                let refusee = attendues[rang].split('|').next().expect("nom").to_string();
                for (forme, corps) in [("ABORT", "RAISE(ABORT,'sek refus')"), ("IGNORE", "RAISE(IGNORE)")] {
                    let conn = test_db();
                    let depuis = sek_dernier(&conn);
                    conn.execute_batch(&format!(
                        "CREATE TRIGGER sek_refus BEFORE INSERT ON rule WHEN NEW.name='{}' BEGIN SELECT {corps}; END;",
                        refusee.replace('\'', "''")
                    ))
                    .expect("déclencheur de refus");
                    semer(&conn);
                    assert!(sek_lignes(&conn, depuis).is_empty(), "`{tag}` ({forme}, règle {rang} « {refusee} ») : aucune règle conservée après le refus");
                    assert_eq!(sek_drapeau(&conn, drapeau), 0, "`{tag}` ({forme}, règle {rang}) : drapeau ABSENT après le refus");
                    assert!(conn.is_autocommit(), "`{tag}` ({forme}, règle {rang}) : la transaction du semis est fermée");
                    conn.execute_batch("DROP TRIGGER sek_refus;").expect("base revenue");
                    semer(&conn);
                    assert_eq!(sek_lignes(&conn, depuis), attendues, "`{tag}` ({forme}, règle {rang}) : rejoué entier au démarrage suivant");
                    assert_eq!(sek_drapeau(&conn, drapeau), 1, "`{tag}` ({forme}, règle {rang}) : drapeau posé après le succès");
                    semer(&conn);
                    assert_eq!(sek_lignes(&conn, depuis), attendues, "`{tag}` ({forme}, règle {rang}) : aucun doublon ensuite");
                }
            }
        }
        sek_rendre_la_liste(avant);
    }

    /// Un homonyme créé à la main avant le semis ne le bloque pas (aucune unicité sur `rule.name`) : le semis écrit
    /// quand même sa règle, et l'homonyme reste.
    #[test]
    fn sek_un_homonyme_cree_a_la_main_ne_bloque_pas_le_semis() {
        let _g = VERROU_ENV_PROCESSUS.write();
        let avant = sek_poser_la_liste(None);
        let conn = test_db();
        conn.execute("INSERT INTO rule(name,query) VALUES('k8s: node NotReady','search *')", []).expect("homonyme");
        seed_k8s_rules(&conn);
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM rule WHERE name='k8s: node NotReady'", [], |r| r.get(0)).expect("compte");
        assert_eq!(n, 2, "l'homonyme et la règle semée coexistent");
        assert_eq!(sek_drapeau(&conn, "seeded_k8s_rules"), 1, "drapeau posé");
        sek_rendre_la_liste(avant);
    }
}

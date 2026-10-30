// =====================================================================================
// `P10.20-b` — LA LIGNE `[ingest]` D'UNE EMPREINTE ILLISIBLE NOMME SA SÉRIE.
//
// CE QUI MANQUAIT. Quand la dernière empreinte d'une série d'instantanés n'est pas lue (`SnapshotSeries::dernier_hash`
// en `Err`), l'ingestion du spool (`ingest/mod.rs`, voie instantané) l'écrivait au journal sans dire de QUELLE série il
// s'agissait : ni genre, ni machine. L'exploitant savait qu'une cellule était illisible, pas laquelle relire.
//
// CE QUI EST JOUÉ, PAR LE VRAI CHEMIN (`ingest_once` sur un spool), DANS UN SOUS-PROCESSUS DONT LE STDERR EST LU :
//   * `liee` : machine liée au jeton (marqueur `#H#…#H#` du nom de fichier) ET un `host` CONTRAIRE dans l'enveloppe -> la
//     ligne ENTIÈRE nomme le genre et la machine LIÉE, jamais celle que l'enveloppe déclare (même hôte que la série) ;
//   * `forgee` : genre et machine pris de l'ENVELOPPE, chacun porteur d'un `\n`, d'un `\r`, d'un NUL et d'un guillemet,
//     chacun suivi d'un faux préfixe de journal -> une seule ligne ENTIÈRE où les quatre sont échappés (`\n`, `\r`, `\0`,
//     `\"`), aucune ligne qui commence par le faux préfixe, aucun `\r` ni NUL brut au journal ;
//   * `sans_machine` : ni marqueur ni `host` dans l'enveloppe -> « sans machine », jamais une machine vide inventée.
// Dans chaque phase l'instantané est inscrit comme un état neuf (deux lignes dans la série) : le geste d'avant est gardé.
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit), chacun vu ROUGE sur `ein_la_ligne_nomme_genre_et_machine_echappes` :
//   BD4_SANS_GENRE (le genre n'est pas écrit), BD4_SANS_MACHINE (la machine n'est pas écrite), BD4_SANS_ECHAPPEMENT (genre
//   et machine écrits bruts), BD4_AUCUNE_COMME_VIDE (une machine absente écrite comme une machine vide),
//   BD4_ENVELOPPE_D_ABORD (la ligne préfère le `host` de l'enveloppe au marqueur lié) ; puis (reprise) M10 (valeurs
//   citées avec le seul `\n` échappé), BE1_NUL_BRUT (tout échappé sauf le NUL), BE1_CR_BRUT (tout échappé sauf le `\r`),
//   BE1_GUILLEMET_BRUT (tout échappé sauf le guillemet).
// =====================================================================================
mod empreinte_illisible_nomme_sa_serie {
    use super::*;

    const EIN_ENFANT: &str = "PLUME_TEST_EIN_ENFANT";
    const EIN_PHASE: &str = "EIN-PHASE:";
    // Chaque caractère qui forge une ligne est posé dans les DEUX valeurs : `\n`, `\r` (un terminal ou un lecteur ligne à
    // ligne repart en colonne zéro), `\0` (journald coupe aussi un enregistrement sur un NUL) et le guillemet (qui fermerait
    // la valeur citée et laisserait la suite se lire comme du texte du démon).
    const EIN_GENRE_FORGE: &str = "posture\n[ingest] FAUX genre\r[ingest] FAUX cr\0[ingest] FAUX nul\" FAUX guillemet";
    const EIN_MACHINE_FORGEE: &str = "srv\n[ingest] FAUX machine\r[ingest] FAUX cr\0[ingest] FAUX nul\" FAUX guillemet";
    const EIN_LIGNE_LIEE: &str = "[ingest] WARN instantané \"firewall\" du spool de la machine \"web01\" : la dernière empreinte \
         de sa série n'a pas été lue (forme_inconnue) — l'instantané est inscrit comme un état neuf, pas comme un battement";
    const EIN_LIGNE_FORGEE: &str = "[ingest] WARN instantané \"posture\\n[ingest] FAUX genre\\r[ingest] FAUX cr\\0[ingest] \
         FAUX nul\\\" FAUX guillemet\" du spool de la machine \"srv\\n[ingest] FAUX machine\\r[ingest] FAUX cr\\0[ingest] \
         FAUX nul\\\" FAUX guillemet\" : la dernière empreinte de sa série n'a pas été lue (forme_inconnue) — l'instantané \
         est inscrit comme un état neuf, pas comme un battement";
    const EIN_LIGNE_SANS_MACHINE: &str = "[ingest] WARN instantané \"firewall\" du spool sans machine : la dernière empreinte \
         de sa série n'a pas été lue (forme_inconnue) — l'instantané est inscrit comme un état neuf, pas comme un battement";

    #[test]
    fn ein_la_ligne_nomme_genre_et_machine_echappes() {
        if std::env::var(EIN_ENFANT).is_ok() {
            for phase in ["liee", "forgee", "sans_machine"] {
                eprintln!("{EIN_PHASE}{phase}");
                let (st, spool) = ing_state_with_spool();
                let t = now() - 100;
                // (genre stocké, machine stockée, enveloppe, nom de fichier)
                let (genre, machine, env, nom): (&str, Option<&str>, Value, String) = match phase {
                    "liee" => (
                        "firewall",
                        Some("web01"),
                        json!({ "ts": t, "host": "web02-usurpe", "kind": "firewall", "hash": "h-neuf", "data": {} }),
                        format!("ingest-{}-1#H#web01#H#.json", now()),
                    ),
                    "forgee" => (
                        EIN_GENRE_FORGE,
                        Some(EIN_MACHINE_FORGEE),
                        json!({ "ts": t, "host": EIN_MACHINE_FORGEE, "kind": EIN_GENRE_FORGE, "hash": "h-neuf", "data": {} }),
                        format!("ingest-{}-2.json", now()),
                    ),
                    _ => (
                        "firewall",
                        None,
                        json!({ "ts": t, "kind": "firewall", "hash": "h-neuf", "data": {} }),
                        format!("ingest-{}-3.json", now()),
                    ),
                };
                st.db
                    .lock()
                    .execute(
                        "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(?1,?2,X'00ff','{}',?3)",
                        params![t - 300, genre, machine],
                    )
                    .expect("fixture : ligne d'empreinte illisible");
                let fichier = spool.join(nom);
                std::fs::write(&fichier, env.to_string()).expect("dépôt du spool");
                ingest_once(&st.tenants, &st.spool);
                let n: i64 = st
                    .db
                    .lock()
                    .query_row("SELECT COUNT(*) FROM snapshot WHERE kind=?1 AND host IS ?2", params![genre, machine], |r| r.get(0))
                    .unwrap();
                println!("EIN-BILAN-{phase}:{n}:{}", fichier.exists());
            }
            eprintln!("{EIN_PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::empreinte_illisible_nomme_sa_serie::ein_la_ligne_nomme_genre_et_machine_echappes",
            ])
            .env(EIN_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        for phase in ["liee", "forgee", "sans_machine"] {
            assert!(
                stdout.contains(&format!("EIN-BILAN-{phase}:2:false")),
                "{phase} : inscrit comme état neuf (deux lignes), fichier consommé : {stdout}"
            );
        }
        let lignes_de = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{EIN_PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(EIN_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps
                .lines()
                .filter(|l| l.starts_with("[ingest] WARN instantané") || l.starts_with("[ingest] FAUX"))
                .map(str::to_string)
                .collect()
        };
        assert_eq!(lignes_de("liee"), vec![EIN_LIGNE_LIEE.to_string()], "genre et machine liée nommés, ligne entière : {stderr}");
        assert_eq!(
            lignes_de("forgee"),
            vec![EIN_LIGNE_FORGEE.to_string()],
            "genre et machine de l'enveloppe échappés, une seule ligne, aucun faux préfixe : {stderr}"
        );
        assert!(!stderr.lines().any(|l| l.starts_with("[ingest] FAUX")), "aucune ligne forgée : {stderr}");
        // Le `\r` et le NUL forgés ne coupent pas une ligne pour `lines()` : leur absence BRUTE du journal se juge à part.
        assert!(!stderr.contains('\r'), "aucun retour chariot brut au journal : {stderr:?}");
        assert!(!stderr.contains('\0'), "aucun NUL brut au journal : {stderr:?}");
        assert_eq!(lignes_de("sans_machine"), vec![EIN_LIGNE_SANS_MACHINE.to_string()], "machine absente dite : {stderr}");
    }
}

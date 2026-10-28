// =====================================================================================
// `P10.20-b` (correction) — LE GENRE ET LA MACHINE VENUS DU CHEMIN SONT ÉCRITS ÉCHAPPÉS AU JOURNAL.
//
// CE QUI ÉTAIT AFFIRMÉ SANS TÉMOIN. `refuser_l_instantane_non_lu` et `panel` (`handlers/overview.rs`) écrivent `{kind:?}` et
// `{host:?}` pour qu'une saisie ne forge pas de ligne de journal. Les fixtures n'utilisaient que « firewall » et « srv-z »,
// qui s'impriment pareil échappés ou non : écrire `"{kind}"` / `"{host}"` restait vert (mutants M16 et M23 de la
// vérification). Ici le genre et la machine portent un `\n` (ce que `Path` rend d'un `%0A`) suivi d'un faux préfixe de
// journal. Chaque route doit écrire UNE ligne, le `\n` échappé, et aucune ligne ne doit commencer par le faux préfixe.
// Trois lignes jugées : `[snapshot]` (cellule illisible puis table retirée), `[panel]` interrompu, `[panel]` non commencé.
//
// LA CAUSE PROPRE À CHAQUE LIGNE ILLISIBLE. Le contrôle `assert_ne!` de `parcours_des_instantanes_et_jalon_d_analyse_dits.rs`
// comparait deux constantes. Ici la cause que le moteur rend est lue pour chaque colonne illisible prise SEULE (`hash`,
// `data`), et les deux textes lus doivent différer : c'est ce qui rend non vacante « la première cause est gardée ».
//
// MUTANTS JOUÉS (commutateurs retirés avant le commit), chacun vu ROUGE : AX2C_SNAP_BRUT (`[snapshot]` écrit `"{kind}"` /
// `"{host}"`), AX2C_PANEL_I_BRUT (`[panel]` interrompu écrit `"{kind}"`), AX2C_PANEL_NC_BRUT (`[panel]` non commencé écrit
// `"{kind}"`), AX2C_FIXTURE_MEME_COLONNE (la ligne `data` rendue illisible sur `hash` : les deux causes lues coïncident).
//
// CE QUE CE FICHIER NE TIENT PAS. La console ne lit pas encore les formes neuves (`hosts_etat`, `n_hosts` nul,
// `firewall_etat`, `firewall_n_hosts` nul) : `web/` est à sa forme de base depuis c84baddc. Une liste coupée à `max=500`
// rend `Complet` et sert 500 comme taille du parc (`ingest/store.rs`, « CE QUE LA FIN NE DIT PAS (1) »).
// =====================================================================================
mod journal_des_instantanes_echappe_le_chemin {
    use super::*;
    use crate::handlers::overview::{panel, snapshot_par_genre_et_machine};
    use crate::query_exec::FinDeParcours;

    const AX2C_ENFANT: &str = "PLUME_TEST_AX2C_ENFANT_JOURNAL_ECHAPPE";
    const AX2C_PHASE: &str = "AX2C-PHASE:";
    /// Un genre qui porte un saut de ligne puis un faux préfixe de journal.
    const AX2C_GENRE: &str = "firewall\n[snapshot] WARN forgé par le genre";
    /// Une machine qui porte un saut de ligne puis un faux préfixe de journal.
    const AX2C_MACHINE: &str = "srv-z\n[panel] WARN forgé par la machine";
    const AX2C_PREFIXES: [&str; 2] = ["[snapshot] WARN", "[panel] WARN"];
    const AX2C_FORGES: [&str; 2] = ["[snapshot] WARN forgé", "[panel] WARN forgé"];
    const AX2C_SNAP: &str = "[snapshot] WARN dernier instantané \"firewall\\n[snapshot] WARN forgé par le genre\" de la machine \
         \"srv-z\\n[panel] WARN forgé par la machine\" NON lu (forme_inconnue) — servi 503 : ";
    const AX2C_PANEL_INTERROMPU: &str = "[panel] WARN instantanés \"firewall\\n[snapshot] WARN forgé par le genre\" par machine : \
         lecture interrompue (1 erreur(s) de parcours, pas un nombre de lignes) — servi avec hosts_etat et n_hosts nul : ";
    const AX2C_PANEL_NON_COMMENCE: &str = "[panel] WARN instantanés \"firewall\\n[snapshot] WARN forgé par le genre\" par machine : \
         lecture non commencée, rien n'est lu — servi 503 : ";
    /// Le texte du moteur pour une cellule BLOB lue en `TEXT`, troisième colonne (`hash`).
    const AX2C_CAUSE_HASH: &str = "Invalid column type Blob at index: 2, name: COALESCE(s.hash,'')";
    /// Le même pour la quatrième colonne (`data`).
    const AX2C_CAUSE_DATA: &str = "Invalid column type Blob at index: 3, name: COALESCE(s.data,'')";

    fn ax2c_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    /// Sous-processus dont le stderr est lu. Phase `illisible` : une machine lisible (`srv-a`) et la machine forgée, dont
    /// l'empreinte est une cellule BLOB ; `[snapshot]` et `[panel]` interrompu écrivent chacun leur ligne. Phase `retiree` :
    /// table renommée ; `[snapshot]` et `[panel]` non commencé.
    #[test]
    fn ax2c_le_genre_et_la_machine_du_chemin_ne_forgent_pas_de_ligne() {
        if std::env::var(AX2C_ENFANT).is_ok() {
            let exec = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("exécuteur de test");
            exec.block_on(async {
                let (st, _tmp) = sp_state("ax2c-journal");
                {
                    let conn = st.db.lock();
                    conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(1000,?1,'h-a','{}','srv-a')", params![AX2C_GENRE])
                        .expect("fixture : machine lisible");
                    conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(900,?1,X'00ff','{}',?2)", params![AX2C_GENRE, AX2C_MACHINE])
                        .expect("fixture : machine forgée illisible");
                }
                for (phase, geste) in [("illisible", ""), ("retiree", "ALTER TABLE snapshot RENAME TO snapshot_hors_d_atteinte;")] {
                    if !geste.is_empty() {
                        ax2c_ecrire(&st, geste);
                    }
                    eprintln!("{AX2C_PHASE}{phase}");
                    let r = snapshot_par_genre_et_machine(
                        State(st.clone()),
                        Extension(sp_au("lectrice", "viewer")),
                        Path((AX2C_GENRE.to_string(), AX2C_MACHINE.to_string())),
                    )
                    .await;
                    let p = panel(State(st.clone()), Extension(sp_au("lectrice", "viewer")), Path(AX2C_GENRE.to_string())).await;
                    println!("AX2C-ROUTES-{phase}:{}:{}", r.status().as_u16(), p.status().as_u16());
                }
                eprintln!("{AX2C_PHASE}fin");
            });
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::journal_des_instantanes_echappe_le_chemin::ax2c_le_genre_et_la_machine_du_chemin_ne_forgent_pas_de_ligne",
            ])
            .env(AX2C_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains("AX2C-ROUTES-illisible:503:200"), "contrôle : cellule illisible (503, panneau partiel) : {stdout}");
        assert!(stdout.contains("AX2C-ROUTES-retiree:503:503"), "contrôle : table retirée : {stdout}");
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{AX2C_PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(AX2C_PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| AX2C_PREFIXES.iter().any(|p| l.starts_with(p))).map(str::to_string).collect()
        };
        for (nom, attendus) in [("illisible", [AX2C_SNAP, AX2C_PANEL_INTERROMPU]), ("retiree", [AX2C_SNAP, AX2C_PANEL_NON_COMMENCE])] {
            let lignes = phase(nom);
            for l in &lignes {
                assert!(!AX2C_FORGES.iter().any(|f| l.starts_with(f)), "phase {nom} : ligne FORGÉE par le chemin : « {l} » dans {lignes:?}");
            }
            assert_eq!(lignes.len(), 2, "phase {nom} : une ligne par route, ni plus ni moins : {lignes:?}");
            for (ligne, debut) in lignes.iter().zip(attendus) {
                let reste = ligne.strip_prefix(debut).unwrap_or_else(|| panic!("phase {nom} : « {ligne} » ne commence pas par « {debut} »"));
                assert!(!reste.trim().is_empty(), "phase {nom} : le texte du moteur manque : « {ligne} »");
            }
        }
    }

    /// Chaque colonne illisible prise SEULE : la cause lue est celle de sa colonne, et les deux causes LUES diffèrent.
    #[test]
    fn ax2c_chaque_colonne_illisible_rend_sa_propre_cause() {
        let lire = |colonne: &str| -> String {
            let conn = test_db();
            conn.execute("INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(1000,'firewall','h-a','{}','srv-a')", [])
                .expect("fixture : machine lisible");
            let sql = if colonne == "hash" {
                "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(900,'firewall',X'00ff','{}','srv-z')"
            } else {
                "INSERT INTO snapshot(ts,kind,hash,data,host) VALUES(900,'firewall','h-z',X'00ff','srv-z')"
            };
            conn.execute(sql, []).expect("fixture : machine illisible");
            let lu = crate::ingest::store::dernier_instantane_par_hote(&conn, "firewall", 500);
            assert_eq!(lu.iter().map(|r| r.0.clone().unwrap_or_default()).collect::<Vec<_>>(), ["srv-a"], "la machine lisible est rendue");
            match &lu.fin {
                FinDeParcours::Interrompu { erreurs, cause } => {
                    assert_eq!(*erreurs, 1, "une ligne illisible, une erreur ({colonne})");
                    cause.clone()
                }
                autre => panic!("{colonne} : fin attendue Interrompu, pas {:?}", autre.etat()),
            }
        };
        let (cause_hash, cause_data) = (lire("hash"), lire("data"));
        assert_eq!(cause_hash, AX2C_CAUSE_HASH, "cause lue pour `hash` illisible");
        assert_eq!(cause_data, AX2C_CAUSE_DATA, "cause lue pour `data` illisible");
        assert_ne!(cause_hash, cause_data, "les deux causes LUES diffèrent : « la première est gardée » peut rougir");
    }
}

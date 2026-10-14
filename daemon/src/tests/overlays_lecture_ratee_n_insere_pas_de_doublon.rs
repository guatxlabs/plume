// =====================================================================================
// `P10.20-b` / `P10.20-l` (hors handlers/) — UN CHARGEUR D'OVERLAY DE DÉTECTION N'INSÈRE PAS DE DOUBLON SUR UNE
// LECTURE RATÉE, ET NE COMPTE « CHARGÉ » QU'UNE ÉCRITURE QUI A POSÉ SA LIGNE.
//
// VU sur `c78be971` : `overlays_oac::plan_upsert` rendait `Err(_) => UpsertPlan::Insert` — toute erreur de lecture
// (lecture refusée, interruption, verrou, cache de schéma périmé), pas seulement `QueryReturnedNoRows`, valait « le
// nom n'existe pas ». `parser`, `dparser` et `playbook` n'ont aucun UNIQUE(name) : l'INSERT passait et créait un
// DOUBLON `managed=1`, y compris à côté d'une copie personnelle `managed=2` que `SkipUser` devait protéger (un
// playbook en double rejoue deux fois sa riposte). Les trois chargeurs écrivaient par `let _ = conn.execute(…)`
// puis `ch.charges += 1` : une écriture refusée était comptée chargée.
//
// CE QUE CES TÉMOINS JUGENT, sur les trois chargeurs (`load_overlay_parsers`, `load_overlay_dparsers`,
// `load_overlay_playbooks`) :
//  - lecture de l'existant refusée (authorizer SQLite qui refuse toute lecture de la table visée ; l'INSERT, lui,
//    reste permis) : aucune ligne ajoutée, `ignores=1`, `charges=0`, la lecture a bien été refusée ;
//  - contre-épreuve sans panne : une ligne posée (`charges=1`), puis rejouée (UPDATE) : toujours une ligne ;
//  - copie personnelle `managed=2` du même nom ET lecture refusée : toujours une seule ligne, `managed=2` ;
//  - écriture refusée par le moteur (trigger `RAISE(ABORT)`), en INSERT comme en UPDATE : non comptée chargée ;
//  - écriture sans effet (trigger `RAISE(IGNORE)`, `Ok(0)`) : non comptée chargée ;
//  - la lecture refusée est DITE au journal : une ligne `[overlays] WARN` par chargeur, avec la cause du moteur,
//    lue sur le stderr d'un sous-processus ; aucune après la levée de la panne ;
//  - l'écriture refusée (`RAISE(ABORT,'olr refus')`) et l'écriture sans effet (`RAISE(IGNORE)`) sont DITES au journal,
//    en INSERT comme en UPDATE, par chargeur : exactement une ligne `[overlays] WARN <genre> '<nom>'` par geste,
//    « écriture refusée » avec la cause du moteur, « écriture sans effet (0 ligne posée) » ; aucune une fois levée.
// MUTANTS JOUÉS (variable de mutation sous cfg!(test), retirés du source avant le commit) : `R2_ERR_INSERT` (`Err(_) => Insert` rétabli dans
// `plan_upsert_lu`), `R2_CHARGES_MALGRE_REFUS` (écriture refusée comptée chargée), `R2_NONLU_SKIP_MUET` (lecture
// ratée traitée comme `SkipUser`, sans WARN), `R2_SANS_OK1` (comptage `Ok(1)` retiré : tout `Ok(_)` compté) ; à la reprise, `R2C_M13` (WARN d'écriture refusée
// retiré) et `R2C_M14` (WARN d'écriture sans effet retiré), tous deux rouges sur le témoin (7).
// CE QUE CE LOT NE TIENT PAS :
//  - les dix autres appelants de `plan_upsert` (huit chargeurs d'objets OAC d'`overlays_oac.rs`, les deux chargeurs
//    de `rule` d'`overlays.rs`) gardent « lecture ratée = Insert » par la projection `plan_upsert` ;
//  - l'absence d'UNIQUE(name) sur `parser`, `dparser` et `playbook` (schéma, porte à sens unique) ;
//  - le déclenchement en production n'est pas observé : la panne est fabriquée ;
//  - le WARN d'écriture sans effet n'est éprouvé qu'avec `Ok(0)` (`RAISE(IGNORE)`) : un `Ok(n>1)` n'est pas
//    fabricable par un UPDATE keyé par `id` ni par un INSERT d'une ligne ;
//  - le résumé « N fichier(s) de config.d IGNORÉ(S) » du boot n'est pas relu par ces témoins (seul le compte
//    `ignores` rendu par chaque chargeur l'est).
// =====================================================================================
mod overlays_lecture_ratee_n_insere_pas_de_doublon {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Arc;

    type OlrChargeur = fn(&Connection, &std::path::Path) -> crate::overlays_adossement::Chargement;

    struct OlrCas {
        table: &'static str,
        nom: &'static str,
        fichier: String,
        charger: OlrChargeur,
        /// INSERT d'une ligne du même nom, `managed` en `?2`.
        homonyme: &'static str,
    }

    fn olr_cas() -> Vec<OlrCas> {
        vec![
            OlrCas {
                table: "parser",
                nom: "olr-parser",
                fichier: r#"{"name":"olr-parser","source":"nginx","pattern":"a=(?P<a>\\d+)","enabled":true}"#.to_string(),
                charger: crate::overlays::load_overlay_parsers,
                homonyme: "INSERT INTO parser(name,source,pattern,enabled,builtin,managed,created) VALUES(?1,'sshd','b=(?P<b>\\d+)',1,0,?2,0)",
            },
            OlrCas {
                table: "dparser",
                nom: "olr-dparser",
                fichier: r#"{"name":"olr-dparser","source":"nft","enabled":true,"match":"PORTSCAN[46]?:",
                    "extract":[{"regex":"SRC=(?P<src>[0-9A-Fa-f.:]+)"}],
                    "map":{"category":"firewall","severity":2,"action":"deny","src_ip":"$src"}}"#
                    .to_string(),
                charger: crate::overlays::load_overlay_dparsers,
                homonyme: "INSERT INTO dparser(name,source,spec,enabled,builtin,managed,created) VALUES(?1,'*','{}',1,0,?2,0)",
            },
            OlrCas {
                table: "playbook",
                nom: "olr-playbook",
                fichier: r#"{"name":"olr-playbook","query":"search source=x | table src_ip","is_soql":true,"action_kind":"ban_ip","enabled":false}"#.to_string(),
                charger: crate::overlays::load_overlay_playbooks,
                homonyme: "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,managed) VALUES(?1,1,'search source=y | table src_ip',1,'ban_ip',?2)",
            },
        ]
    }

    fn olr_dossier(cas: &OlrCas) -> crate::tmp_possede::TmpPossede {
        let d = crate::tmp_possede::TmpPossede::neuf(&format!("olr-{}", cas.table));
        std::fs::write(d.join("o.json"), &cas.fichier).unwrap();
        d
    }

    fn olr_lignes(c: &Connection, cas: &OlrCas) -> i64 {
        c.query_row(&format!("SELECT COUNT(*) FROM {} WHERE name=?1", cas.table), params![cas.nom], |r| r.get(0)).unwrap()
    }

    /// Refuse TOUTE lecture de `table` (l'écriture reste permise) ; rend le compteur de refus.
    fn olr_refuser_la_lecture(c: &Connection, table: &'static str) -> Arc<AtomicUsize> {
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == table => {
                compteur.fetch_add(1, SeqCst);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        refus
    }

    fn olr_lever(c: &Connection) {
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn olr_charger(c: &Connection, cas: &OlrCas, d: &std::path::Path) -> (u32, u32) {
        let ch = (cas.charger)(c, d);
        (ch.charges, ch.ignores)
    }

    /// (1) Lecture de l'existant refusée : aucune ligne ajoutée, le fichier est ignoré, rien n'est compté chargé.
    #[test]
    fn olr_lecture_ratee_n_insere_aucune_ligne() {
        for cas in olr_cas() {
            let c = test_db();
            let d = olr_dossier(&cas);
            let refus = olr_refuser_la_lecture(&c, cas.table);
            let bilan = olr_charger(&c, &cas, &d);
            olr_lever(&c);
            assert!(refus.load(SeqCst) >= 1, "{} : fixture, la lecture de la table a été refusée", cas.table);
            assert_eq!(olr_lignes(&c, &cas), 0, "{} : aucune ligne posée sur une lecture ratée", cas.table);
            assert_eq!(bilan, (0, 1), "{} : (charges, ignores) = (0, 1)", cas.table);
        }
    }

    /// (2) Contre-épreuve sans panne : une ligne posée, puis rejouée en UPDATE, toujours une seule.
    #[test]
    fn olr_contre_epreuve_sans_panne_pose_une_ligne() {
        for cas in olr_cas() {
            let c = test_db();
            let d = olr_dossier(&cas);
            assert_eq!(olr_charger(&c, &cas, &d), (1, 0), "{} : chargé", cas.table);
            assert_eq!(olr_lignes(&c, &cas), 1, "{} : une ligne", cas.table);
            assert_eq!(olr_charger(&c, &cas, &d), (1, 0), "{} : rejoué (UPDATE), chargé", cas.table);
            assert_eq!(olr_lignes(&c, &cas), 1, "{} : toujours une ligne", cas.table);
            let mgd: i64 = c.query_row(&format!("SELECT managed FROM {} WHERE name=?1", cas.table), params![cas.nom], |r| r.get(0)).unwrap();
            assert_eq!(mgd, 1, "{} : posée par l'overlay", cas.table);
        }
    }

    /// (3) Copie personnelle `managed=2` du même nom ET lecture refusée : aucune deuxième ligne, la copie intacte.
    #[test]
    fn olr_homonyme_ad_hoc_et_lecture_ratee_reste_seul() {
        for cas in olr_cas() {
            let c = test_db();
            let d = olr_dossier(&cas);
            c.execute(cas.homonyme, params![cas.nom, 2]).unwrap();
            let refus = olr_refuser_la_lecture(&c, cas.table);
            let bilan = olr_charger(&c, &cas, &d);
            olr_lever(&c);
            assert!(refus.load(SeqCst) >= 1, "{} : fixture, lecture refusée", cas.table);
            assert_eq!(olr_lignes(&c, &cas), 1, "{} : aucune deuxième ligne du même nom", cas.table);
            let mgd: i64 = c.query_row(&format!("SELECT managed FROM {} WHERE name=?1", cas.table), params![cas.nom], |r| r.get(0)).unwrap();
            assert_eq!(mgd, 2, "{} : la copie personnelle reste managed=2", cas.table);
            assert_eq!(bilan, (0, 1), "{} : ignoré, non chargé", cas.table);
        }
    }

    /// (4) Écriture refusée par le moteur (`RAISE(ABORT)`), en INSERT puis en UPDATE : non comptée chargée.
    #[test]
    fn olr_ecriture_refusee_n_est_pas_comptee_chargee() {
        for cas in olr_cas() {
            let c = test_db();
            let d = olr_dossier(&cas);
            c.execute_batch(&format!("CREATE TRIGGER olr_refus_ins BEFORE INSERT ON {} BEGIN SELECT RAISE(ABORT,'olr refus'); END", cas.table)).unwrap();
            assert_eq!(olr_charger(&c, &cas, &d), (0, 1), "{} : INSERT refusé, non chargé", cas.table);
            assert_eq!(olr_lignes(&c, &cas), 0, "{} : fixture, rien posé", cas.table);
            c.execute_batch("DROP TRIGGER olr_refus_ins").unwrap();
            c.execute(cas.homonyme, params![cas.nom, 1]).unwrap();
            c.execute_batch(&format!("CREATE TRIGGER olr_refus_upd BEFORE UPDATE ON {} BEGIN SELECT RAISE(ABORT,'olr refus'); END", cas.table)).unwrap();
            assert_eq!(olr_charger(&c, &cas, &d), (0, 1), "{} : UPDATE refusé, non chargé", cas.table);
            assert_eq!(olr_lignes(&c, &cas), 1, "{} : la ligne d'avant, seule", cas.table);
        }
    }

    /// (5) Écriture sans effet (`RAISE(IGNORE)`, `Ok(0)`), en INSERT puis en UPDATE : non comptée chargée.
    #[test]
    fn olr_ecriture_sans_effet_n_est_pas_comptee_chargee() {
        for cas in olr_cas() {
            let c = test_db();
            let d = olr_dossier(&cas);
            c.execute_batch(&format!("CREATE TRIGGER olr_muet_ins BEFORE INSERT ON {} BEGIN SELECT RAISE(IGNORE); END", cas.table)).unwrap();
            assert_eq!(olr_charger(&c, &cas, &d), (0, 1), "{} : INSERT sans effet, non chargé", cas.table);
            assert_eq!(olr_lignes(&c, &cas), 0, "{} : fixture, rien posé", cas.table);
            c.execute_batch("DROP TRIGGER olr_muet_ins").unwrap();
            c.execute(cas.homonyme, params![cas.nom, 1]).unwrap();
            c.execute_batch(&format!("CREATE TRIGGER olr_muet_upd BEFORE UPDATE ON {} BEGIN SELECT RAISE(IGNORE); END", cas.table)).unwrap();
            assert_eq!(olr_charger(&c, &cas, &d), (0, 1), "{} : UPDATE sans effet, non chargé", cas.table);
        }
    }

    /// (6) La lecture refusée est DITE : une ligne `[overlays] WARN` par chargeur avec la cause du moteur, lue sur le
    /// stderr d'un sous-processus ; aucune après la levée de la panne (chemin nominal muet).
    #[test]
    fn olr_lecture_ratee_dit_sa_cause_au_journal() {
        const ENFANT: &str = "OLR_ENFANT_JOURNAL";
        const LEVEE: &str = "OLR-PHASE-LEVEE";
        if std::env::var(ENFANT).is_ok() {
            let c = test_db();
            let cas = olr_cas();
            let dossiers: Vec<_> = cas.iter().map(olr_dossier).collect();
            for (k, d) in cas.iter().zip(&dossiers) {
                olr_refuser_la_lecture(&c, k.table);
                let cause = plan_upsert_lu(&c, k.table, k.nom).err().expect("fixture : lecture refusée");
                println!("OLR-CAUSE:{}:{cause}", k.table);
                olr_charger(&c, k, d);
                olr_lever(&c);
            }
            eprintln!("{LEVEE}");
            for (k, d) in cas.iter().zip(&dossiers) {
                println!("OLR-NOMINAL:{}:{:?}", k.table, olr_charger(&c, k, d));
            }
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::overlays_lecture_ratee_n_insere_pas_de_doublon::olr_lecture_ratee_dit_sa_cause_au_journal",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let (avant, apres) = stderr.split_once(LEVEE).unwrap_or_else(|| panic!("contrôle : marqueur de levée : {stderr}"));
        let lignes: Vec<&str> = avant.lines().filter(|l| l.starts_with("[overlays] WARN")).collect();
        assert_eq!(lignes.len(), 3, "une ligne par chargeur, ni plus ni moins : {lignes:?}\n{stderr}");
        for (k, (ligne, genre)) in olr_cas().iter().zip(lignes.iter().zip(["parser", "parseur déclaratif", "playbook"])) {
            let cause = stdout
                .lines()
                .find_map(|l| l.split_once(&format!("OLR-CAUSE:{}:", k.table)).map(|(_, c)| c.to_string()))
                .unwrap_or_else(|| panic!("contrôle : cause du moteur rendue pour {} : {stdout}", k.table));
            assert!(!cause.trim().is_empty(), "contrôle : cause non vide");
            assert!(ligne.starts_with(&format!("[overlays] WARN {genre} '{}'", k.nom)), "le genre et le nom : {ligne}");
            assert!(ligne.contains("lecture de l'existant NON faite"), "le geste nommé : {ligne}");
            assert!(ligne.contains(&format!("({cause})")), "la cause du moteur (`{cause}`) : {ligne}");
            assert!(stdout.contains(&format!("OLR-NOMINAL:{}:(1, 0)", k.table)), "contrôle : levée, {} chargé : {stdout}", k.table);
        }
        assert_eq!(apres.lines().filter(|l| l.starts_with("[overlays] WARN")).count(), 0, "chemin nominal muet : {apres}");
    }

    /// (7) L'écriture refusée (`RAISE(ABORT)`) et l'écriture sans effet (`RAISE(IGNORE)`) sont DITES : pour chaque
    /// chargeur, en INSERT puis en UPDATE, exactement une ligne `[overlays] WARN` par geste, nommant le genre, le nom,
    /// le geste et (refus) la cause du moteur ; lue sur le stderr d'un sous-processus, phase par phase.
    #[test]
    fn olr_ecriture_refusee_ou_sans_effet_dit_sa_cause_au_journal() {
        const ENFANT: &str = "OLR_ENFANT_ECRITURE";
        const PHASE: &str = "OLR-PHASE:";
        let phases = ["ins-refus", "upd-refus", "ins-muet", "upd-muet", "nominal"];
        if std::env::var(ENFANT).is_ok() {
            for k in olr_cas() {
                let d = olr_dossier(&k);
                for (phase, quand, effet) in [
                    ("ins-refus", "INSERT", "RAISE(ABORT,'olr refus')"),
                    ("upd-refus", "UPDATE", "RAISE(ABORT,'olr refus')"),
                    ("ins-muet", "INSERT", "RAISE(IGNORE)"),
                    ("upd-muet", "UPDATE", "RAISE(IGNORE)"),
                ] {
                    let c = test_db();
                    if quand == "UPDATE" {
                        c.execute(k.homonyme, params![k.nom, 1]).unwrap();
                    }
                    c.execute_batch(&format!("CREATE TRIGGER olr_t BEFORE {quand} ON {} BEGIN SELECT {effet}; END", k.table)).unwrap();
                    eprintln!("{PHASE}{}:{phase}", k.table);
                    println!("OLR-BILAN:{}:{phase}:{:?}", k.table, olr_charger(&c, &k, &d));
                }
                let c = test_db();
                eprintln!("{PHASE}{}:nominal", k.table);
                println!("OLR-BILAN:{}:nominal:{:?}", k.table, olr_charger(&c, &k, &d));
            }
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::overlays_lecture_ratee_n_insere_pas_de_doublon::olr_ecriture_refusee_ou_sans_effet_dit_sa_cause_au_journal",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        // Découpe du stderr en segments, un par (table, phase) : les WARN d'un segment sont ceux de ce seul appel.
        let mut segments: Vec<(String, Vec<String>)> = Vec::new();
        for l in stderr.lines() {
            if let Some(etiquette) = l.strip_prefix(PHASE) {
                segments.push((etiquette.to_string(), Vec::new()));
            } else if l.starts_with("[overlays] WARN") {
                if let Some(dernier) = segments.last_mut() {
                    dernier.1.push(l.to_string());
                }
            }
        }
        let warns = |etiquette: &str| -> Vec<String> {
            segments
                .iter()
                .find(|(e, _)| e == etiquette)
                .map(|(_, w)| w.clone())
                .unwrap_or_else(|| panic!("contrôle : phase `{etiquette}` jouée : {stderr}"))
        };
        assert!(segments.iter().any(|(e, _)| e == "fin"), "contrôle : l'enfant est allé au bout : {stderr}");
        for (k, genre) in olr_cas().iter().zip(["parser", "parseur déclaratif", "playbook"]) {
            for phase in phases {
                let bilan = if phase == "nominal" { "(1, 0)" } else { "(0, 1)" };
                assert!(
                    stdout.contains(&format!("OLR-BILAN:{}:{phase}:{bilan}", k.table)),
                    "contrôle : {} {phase} rend {bilan} : {stdout}",
                    k.table
                );
                let w = warns(&format!("{}:{phase}", k.table));
                if phase == "nominal" {
                    assert!(w.is_empty(), "{} : chemin nominal muet : {w:?}", k.table);
                    continue;
                }
                assert_eq!(w.len(), 1, "{} {phase} : une ligne WARN, ni plus ni moins : {w:?}\n{stderr}", k.table);
                let ligne = &w[0];
                assert!(ligne.starts_with(&format!("[overlays] WARN {genre} '{}'", k.nom)), "{phase} : le genre et le nom : {ligne}");
                assert!(ligne.contains("overlay NON chargé"), "{phase} : la conséquence : {ligne}");
                if phase.ends_with("refus") {
                    assert!(ligne.contains("écriture refusée (") && ligne.contains("olr refus"), "{phase} : le geste et la cause du moteur : {ligne}");
                } else {
                    assert!(ligne.contains("écriture sans effet (0 ligne posée)"), "{phase} : le geste et le nombre de lignes : {ligne}");
                }
            }
        }
    }
}

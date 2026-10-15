// =====================================================================================
// `P10.20-b` (reste nommé de R2 : les deux chargeurs de `rule` d'`overlays.rs`) — UNE RÈGLE D'OVERLAY (JSON ou
// Sigma) N'EST PAS INSÉRÉE EN DOUBLE SUR UNE LECTURE RATÉE, ET N'EST COMPTÉE « CHARGÉE » QUE SI SON ÉCRITURE A
// POSÉ SA LIGNE.
//
// VU sur `ccfa0875` : `load_overlay_rules` et `load_overlay_sigma` lisaient l'existant par `plan_upsert`
// (`Err(_) => Insert`), écrivaient par `let _ = conn.execute(…)` puis `ch.charges += 1`. `rule` n'a AUCUN
// UNIQUE(name) (db/schema.sql, aucun index unique dans migrate.rs) : une lecture ratée créait un DOUBLON
// `managed=1`, y compris à côté d'une copie personnelle `managed=2` que `SkipUser` devait protéger — deux
// règles, donc deux alertes (`rule-{id}`) et deux notifications par épisode. Une écriture refusée était
// comptée chargée.
//
// CE QUE CES TÉMOINS JUGENT, pour la règle JSON (`rules/*.json`) ET la règle Sigma (`sigma/*.yml`) :
//  (1) lecture de l'existant refusée (authorizer SQLite qui refuse toute lecture de `rule`, l'INSERT reste
//      permis) : aucune ligne ajoutée, `(charges, ignores) = (0, 1)` ;
//  (2) contre-épreuve sans panne : une ligne posée puis rejouée (UPDATE), toujours une seule, `managed=1` ;
//  (3) copie `managed=2` du même nom ET lecture refusée : toujours une seule ligne, `managed=2` ;
//  (4) écriture refusée (`RAISE(ABORT)`), en INSERT puis en UPDATE : non comptée chargée ;
//  (5) écriture sans effet (`RAISE(IGNORE)`, `Ok(0)`), en INSERT puis en UPDATE : non comptée chargée ;
//  (6) la lecture refusée et l'écriture refusée sont DITES au journal (stderr d'un sous-processus) : une ligne
//      `[overlays] WARN <genre> '<nom>'` par geste, avec la cause du moteur ; aucune sur le chemin nominal.
// MUTANTS JOUÉS (variable de mutation sous cfg!(test), retirés du source avant le commit) : `S6_ERR_INSERT`
// (règle JSON relue par `plan_upsert`, lecture ratée = Insert), `S6_CHARGES_MALGRE_REFUS` (charges incrémenté
// malgré le refus), `S6_OK0_COMPTE` (`Ok(0)` compté chargé), `S6_SIGMA_NU` (chargeur Sigma laissé à l'ancien
// contrat).
// CE QUE CE LOT NE TIENT PAS :
//  - l'absence d'UNIQUE(name) sur `rule` (schéma, porte à sens unique) ;
//  - `apply_content_overrides` avale toujours le résultat de son UPDATE ;
//  - les huit chargeurs d'objets OAC d'`overlays_oac.rs` gardent `plan_upsert` (hors périmètre) ;
//  - le déclenchement en production n'est pas observé : la panne est fabriquée.
// =====================================================================================
mod overlays_de_regles_lecture_ratee_et_ecriture_comptee {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Arc;

    type OrrChargeur = fn(&Connection, &std::path::Path) -> crate::overlays_adossement::Chargement;

    struct OrrCas {
        genre: &'static str,
        nom: &'static str,
        fichier: &'static str,
        contenu: &'static str,
        charger: OrrChargeur,
    }

    fn orr_cas() -> Vec<OrrCas> {
        vec![
            OrrCas {
                genre: "règle",
                nom: "orr-regle-json",
                fichier: "r.json",
                contenu: r#"{"name":"orr-regle-json","query":"search source=x | table src_ip","is_soql":true,"op":">","threshold":0,"severity":2}"#,
                charger: crate::overlays::load_overlay_rules,
            },
            OrrCas {
                genre: "règle Sigma",
                nom: "orr-regle-sigma",
                fichier: "s.yml",
                contenu: "title: orr-regle-sigma\nlogsource:\n  category: firewall\ndetection:\n  selection:\n    action: deny\n  condition: selection\n",
                charger: crate::overlays::load_overlay_sigma,
            },
        ]
    }

    fn orr_dossier(cas: &OrrCas) -> crate::tmp_possede::TmpPossede {
        let d = crate::tmp_possede::TmpPossede::neuf(&format!("orr-{}", cas.fichier.replace('.', "-")));
        std::fs::write(d.join(cas.fichier), cas.contenu).unwrap();
        d
    }

    fn orr_lignes(c: &Connection, cas: &OrrCas) -> i64 {
        c.query_row("SELECT COUNT(*) FROM rule WHERE name=?1", params![cas.nom], |r| r.get(0)).unwrap()
    }

    fn orr_homonyme(c: &Connection, cas: &OrrCas, managed: i64) {
        c.execute(
            "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,managed) VALUES(?1,1,'search source=y | table src_ip',1,'>',0,2,?2)",
            params![cas.nom, managed],
        )
        .unwrap();
    }

    /// Refuse TOUTE lecture de `rule` (l'écriture reste permise) ; rend le compteur de refus.
    fn orr_refuser_la_lecture(c: &Connection) -> Arc<AtomicUsize> {
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == "rule" => {
                compteur.fetch_add(1, SeqCst);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        refus
    }

    fn orr_lever(c: &Connection) {
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn orr_charger(c: &Connection, cas: &OrrCas, d: &std::path::Path) -> (u32, u32) {
        let ch = (cas.charger)(c, d);
        (ch.charges, ch.ignores)
    }

    /// (1) Lecture de l'existant refusée : aucune ligne ajoutée, le document est ignoré, rien n'est compté chargé.
    #[test]
    fn orr_lecture_ratee_n_insere_aucune_regle() {
        for cas in orr_cas() {
            let c = test_db();
            let d = orr_dossier(&cas);
            let refus = orr_refuser_la_lecture(&c);
            let bilan = orr_charger(&c, &cas, &d);
            orr_lever(&c);
            assert!(refus.load(SeqCst) >= 1, "{} : fixture, la lecture de `rule` a été refusée", cas.genre);
            assert_eq!(orr_lignes(&c, &cas), 0, "{} : aucune ligne posée sur une lecture ratée", cas.genre);
            assert_eq!(bilan, (0, 1), "{} : (charges, ignores) = (0, 1)", cas.genre);
        }
    }

    /// (2) Contre-épreuve sans panne : une règle posée, puis rejouée en UPDATE, toujours une seule.
    #[test]
    fn orr_contre_epreuve_sans_panne_pose_une_regle() {
        for cas in orr_cas() {
            let c = test_db();
            let d = orr_dossier(&cas);
            assert_eq!(orr_charger(&c, &cas, &d), (1, 0), "{} : chargée", cas.genre);
            assert_eq!(orr_lignes(&c, &cas), 1, "{} : une ligne", cas.genre);
            assert_eq!(orr_charger(&c, &cas, &d), (1, 0), "{} : rejouée (UPDATE), chargée", cas.genre);
            assert_eq!(orr_lignes(&c, &cas), 1, "{} : toujours une ligne", cas.genre);
            let mgd: i64 = c.query_row("SELECT managed FROM rule WHERE name=?1", params![cas.nom], |r| r.get(0)).unwrap();
            assert_eq!(mgd, 1, "{} : posée par l'overlay", cas.genre);
        }
    }

    /// (3) Copie personnelle `managed=2` du même nom ET lecture refusée : aucune deuxième ligne, la copie intacte.
    #[test]
    fn orr_homonyme_ad_hoc_et_lecture_ratee_reste_seul() {
        for cas in orr_cas() {
            let c = test_db();
            let d = orr_dossier(&cas);
            orr_homonyme(&c, &cas, 2);
            let refus = orr_refuser_la_lecture(&c);
            let bilan = orr_charger(&c, &cas, &d);
            orr_lever(&c);
            assert!(refus.load(SeqCst) >= 1, "{} : fixture, lecture refusée", cas.genre);
            assert_eq!(orr_lignes(&c, &cas), 1, "{} : aucune deuxième règle du même nom", cas.genre);
            let mgd: i64 = c.query_row("SELECT managed FROM rule WHERE name=?1", params![cas.nom], |r| r.get(0)).unwrap();
            assert_eq!(mgd, 2, "{} : la copie personnelle reste managed=2", cas.genre);
            assert_eq!(bilan, (0, 1), "{} : ignorée, non chargée", cas.genre);
        }
    }

    /// (4) Écriture refusée par le moteur (`RAISE(ABORT)`), en INSERT puis en UPDATE : non comptée chargée.
    #[test]
    fn orr_ecriture_refusee_n_est_pas_comptee_chargee() {
        for cas in orr_cas() {
            let c = test_db();
            let d = orr_dossier(&cas);
            c.execute_batch("CREATE TRIGGER orr_refus_ins BEFORE INSERT ON rule BEGIN SELECT RAISE(ABORT,'orr refus'); END").unwrap();
            assert_eq!(orr_charger(&c, &cas, &d), (0, 1), "{} : INSERT refusé, non chargée", cas.genre);
            assert_eq!(orr_lignes(&c, &cas), 0, "{} : fixture, rien posé", cas.genre);
            c.execute_batch("DROP TRIGGER orr_refus_ins").unwrap();
            orr_homonyme(&c, &cas, 1);
            c.execute_batch("CREATE TRIGGER orr_refus_upd BEFORE UPDATE ON rule BEGIN SELECT RAISE(ABORT,'orr refus'); END").unwrap();
            assert_eq!(orr_charger(&c, &cas, &d), (0, 1), "{} : UPDATE refusé, non chargée", cas.genre);
            assert_eq!(orr_lignes(&c, &cas), 1, "{} : la ligne d'avant, seule", cas.genre);
        }
    }

    /// (5) Écriture sans effet (`RAISE(IGNORE)`, `Ok(0)`), en INSERT puis en UPDATE : non comptée chargée.
    #[test]
    fn orr_ecriture_sans_effet_n_est_pas_comptee_chargee() {
        for cas in orr_cas() {
            let c = test_db();
            let d = orr_dossier(&cas);
            c.execute_batch("CREATE TRIGGER orr_muet_ins BEFORE INSERT ON rule BEGIN SELECT RAISE(IGNORE); END").unwrap();
            assert_eq!(orr_charger(&c, &cas, &d), (0, 1), "{} : INSERT sans effet, non chargée", cas.genre);
            assert_eq!(orr_lignes(&c, &cas), 0, "{} : fixture, rien posé", cas.genre);
            c.execute_batch("DROP TRIGGER orr_muet_ins").unwrap();
            orr_homonyme(&c, &cas, 1);
            c.execute_batch("CREATE TRIGGER orr_muet_upd BEFORE UPDATE ON rule BEGIN SELECT RAISE(IGNORE); END").unwrap();
            assert_eq!(orr_charger(&c, &cas, &d), (0, 1), "{} : UPDATE sans effet, non chargée", cas.genre);
        }
    }

    /// (6) La lecture refusée et l'écriture refusée sont DITES : une ligne `[overlays] WARN <genre> '<nom>'` par
    /// geste, avec la cause du moteur, lue sur le stderr d'un sous-processus ; aucune sur le chemin nominal.
    #[test]
    fn orr_lecture_et_ecriture_refusees_disent_leur_cause_au_journal() {
        const ENFANT: &str = "ORR_ENFANT_JOURNAL";
        const PHASE: &str = "ORR-PHASE:";
        if std::env::var(ENFANT).is_ok() {
            for (i, k) in orr_cas().iter().enumerate() {
                let d = orr_dossier(k);
                let c = test_db();
                orr_refuser_la_lecture(&c);
                let cause = plan_upsert_lu(&c, "rule", k.nom).err().expect("fixture : lecture refusée");
                println!("ORR-CAUSE:{i}:{cause}");
                eprintln!("{PHASE}{i}:lecture");
                println!("ORR-BILAN:{i}:lecture:{:?}", orr_charger(&c, k, &d));
                orr_lever(&c);
                let c = test_db();
                c.execute_batch("CREATE TRIGGER orr_t BEFORE INSERT ON rule BEGIN SELECT RAISE(ABORT,'orr refus'); END").unwrap();
                eprintln!("{PHASE}{i}:ecriture");
                println!("ORR-BILAN:{i}:ecriture:{:?}", orr_charger(&c, k, &d));
                let c = test_db();
                eprintln!("{PHASE}{i}:nominal");
                println!("ORR-BILAN:{i}:nominal:{:?}", orr_charger(&c, k, &d));
            }
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::overlays_de_regles_lecture_ratee_et_ecriture_comptee::orr_lecture_et_ecriture_refusees_disent_leur_cause_au_journal",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
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
        assert!(segments.iter().any(|(e, _)| e == "fin"), "contrôle : l'enfant est allé au bout : {stderr}");
        let warns = |etiquette: &str| -> Vec<String> {
            segments
                .iter()
                .find(|(e, _)| e == etiquette)
                .map(|(_, w)| w.clone())
                .unwrap_or_else(|| panic!("contrôle : phase `{etiquette}` jouée : {stderr}"))
        };
        for (i, k) in orr_cas().iter().enumerate() {
            let cause = stdout
                .lines()
                .find_map(|l| l.split_once(&format!("ORR-CAUSE:{i}:")).map(|(_, c)| c.to_string()))
                .unwrap_or_else(|| panic!("contrôle : cause du moteur rendue pour {} : {stdout}", k.genre));
            assert!(!cause.trim().is_empty(), "contrôle : cause non vide");
            for (phase, bilan) in [("lecture", "(0, 1)"), ("ecriture", "(0, 1)"), ("nominal", "(1, 0)")] {
                assert!(stdout.contains(&format!("ORR-BILAN:{i}:{phase}:{bilan}")), "{} {phase} rend {bilan} : {stdout}", k.genre);
            }
            let tete = format!("[overlays] WARN {} '{}'", k.genre, k.nom);
            let w = warns(&format!("{i}:lecture"));
            assert_eq!(w.len(), 1, "{} lecture : une ligne WARN, ni plus ni moins : {w:?}\n{stderr}", k.genre);
            assert!(w[0].starts_with(&tete), "lecture : le genre et le nom : {}", w[0]);
            assert!(w[0].contains("lecture de l'existant NON faite"), "lecture : le geste nommé : {}", w[0]);
            assert!(w[0].contains(&format!("({cause})")), "lecture : la cause du moteur (`{cause}`) : {}", w[0]);
            let w = warns(&format!("{i}:ecriture"));
            assert_eq!(w.len(), 1, "{} écriture : une ligne WARN, ni plus ni moins : {w:?}\n{stderr}", k.genre);
            assert!(w[0].starts_with(&tete), "écriture : le genre et le nom : {}", w[0]);
            assert!(w[0].contains("écriture refusée (") && w[0].contains("orr refus"), "écriture : le geste et la cause : {}", w[0]);
            assert!(w[0].contains("overlay NON chargé"), "écriture : la conséquence : {}", w[0]);
            assert!(warns(&format!("{i}:nominal")).is_empty(), "{} : chemin nominal muet", k.genre);
        }
    }
}

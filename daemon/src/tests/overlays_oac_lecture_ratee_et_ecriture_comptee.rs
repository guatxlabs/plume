// =====================================================================================
// `P10.20-b` (reste nommé de R2) — LES CHARGEURS OAC DE SORTIE (`destination`, `connector`) N'INSÈRENT RIEN SUR
// UNE LECTURE RATÉE, CELUI DE MASQUAGE (`field_filter`, UNIQUE(name)) L'AVOUE ET POSE SON MASQUE, ET TOUS NE
// COMPTENT « CHARGÉ » QU'UNE ÉCRITURE QUI A POSÉ SA LIGNE.
//
// VU sur `ccfa0875` : ces trois chargeurs d'`overlays_oac.rs` lisaient l'existant par la projection `plan_upsert`
// (`plan_upsert_lu(..).unwrap_or(Insert)`) : toute lecture ratée valait « le nom n'existe pas ». `destination` et
// `connector` n'ont aucun UNIQUE(name) (`migrate.rs`, `CREATE TABLE … destination` et `… connector`) : l'INSERT
// passait et créait un DOUBLON `managed=1` — flux sortant doublé vers un puits externe, deux collectes portant le
// secret —, y compris à côté d'une copie UI `managed=2` que `SkipUser` devait protéger. Les écritures étaient jetées
// (`let _ = conn.execute(…)`) puis comptées (`ch.charges += 1`) : un `field_filter` (UNIQUE(name), donc sans doublon)
// dont l'écriture était refusée était annoncé chargé alors que le masquage `mask`/`deny`/`hash` n'était pas en place.
//
// CE QUE CES TÉMOINS JUGENT, sur les trois chargeurs :
//  (1) lecture de l'existant refusée (authorizer qui refuse toute lecture de la table visée ; l'écriture reste
//      permise), la lecture a bien été refusée : `destination` et `connector` n'ajoutent aucune ligne,
//      `(charges, ignores) = (0, 1)` ; `field_filter` POSE son masque (une ligne, `managed=1`, l'action du
//      fichier), `(1, 0)` — s'abstenir laisserait le champ en clair, et UNIQUE(name) borne l'INSERT (voir (3)) ;
//  (2) contre-épreuve sans panne : une ligne posée, puis rejouée (UPDATE) : toujours une ligne, `managed=1` ;
//  (3) copie UI `managed=2` du même nom ET lecture refusée : une seule ligne, `managed=2`, `(0, 1)` (pour
//      `field_filter`, l'INSERT tenté est refusé par UNIQUE(name) et compté ignoré) ;
//  (4) écriture refusée (trigger `RAISE(ABORT)`), en INSERT puis en UPDATE : non comptée chargée ;
//  (5) écriture sans effet (trigger `RAISE(IGNORE)`, `Ok(0)`), en INSERT puis en UPDATE : non comptée chargée ;
//  (6) la lecture refusée est DITE : une ligne `[oac] WARN <genre> '<nom>'` par chargeur, « lecture de l'existant
//      NON faite » avec la cause du moteur et la suite donnée (« rien écrit » ou « INSERT tenté »), lue sur le
//      stderr d'un sous-processus ; aucune après la levée ; le secret du connecteur (résolu d'un `file:`)
//      n'apparaît nulle part dans le journal ;
//  (7) l'écriture refusée et l'écriture sans effet sont DITES, une ligne par geste et par chargeur, en INSERT comme
//      en UPDATE ; aucune sur le chemin nominal ; le secret du connecteur n'apparaît nulle part.
// MUTANTS JOUÉS (variable de mutation sous cfg!(test), retirés du source avant le commit) : `S5_ERR_INSERT` (lecture
// ratée = Insert rétabli dans l'aide `[oac]`), `S5_NONLU_SKIP_MUET` (lecture ratée traitée en `SkipUser`, sans WARN de
// lecture), `S5_CHARGES_MALGRE_REFUS` (écriture refusée comptée chargée), `S5_SANS_OK1` (tout `Ok(_)` compté chargé),
// `S5_WARN_REFUS_MUET` (WARN d'écriture refusée retiré) ; puis `S5_FF_S_ABSTIENT` (`field_filter` repasse par
// l'abstention sur une lecture ratée) et `S5_FF_AVEU_MUET` (lecture ratée de `field_filter` non dite).
// CE QUE CE LOT NE TIENT PAS :
//  - cinq chargeurs OAC gardent « lecture ratée = Insert » par la projection `plan_upsert` : `notifier`,
//    `index_policy`, `library_panel`, `notification_policy`, `dashboard` (dont l'UPDATE `managed=1` reste jeté) ;
//    les appelants de `plan_upsert` hors d'`overlays_oac.rs` ne sont pas jugés ici ;
//  - sur une lecture ratée de `field_filter`, un overlay déjà posé (`managed=1`) n'est pas mis à jour : l'INSERT
//    tenté est refusé par UNIQUE(name), l'ancien masque reste en place et l'overlay est compté ignoré ;
//  - les deux paires d'aides (`[overlays]` dans `overlays.rs`, `[oac]` ici) ne sont pas unifiées dans
//    `overlays_adossement.rs` ;
//  - l'absence d'UNIQUE(name) sur `destination` et `connector` (schéma, porte à sens unique) ;
//  - le déclenchement en production n'est pas observé : la panne est fabriquée ;
//  - un `Ok(n>1)` n'est pas fabricable par un UPDATE keyé par `id` ni par un INSERT d'une ligne.
// =====================================================================================
mod overlays_oac_lecture_ratee_et_ecriture_comptee {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Arc;

    type OacChargeur = fn(&Connection, &std::path::Path) -> crate::overlays_adossement::Chargement;

    /// Valeur du secret du connecteur, résolue d'un `file:` : elle ne doit apparaître dans AUCUNE ligne de journal.
    const OAC_SECRET: &str = "s5-secret-de-connecteur-jamais-au-journal";

    struct OacCas {
        table: &'static str,
        nom: &'static str,
        genre: &'static str,
        /// Contenu du fichier d'overlay, construit à partir du dossier (le connecteur y lit son secret).
        fichier: fn(&std::path::Path) -> String,
        charger: OacChargeur,
        /// INSERT d'une ligne du même nom, `managed` en `?2`.
        homonyme: &'static str,
        /// La table porte UNIQUE(name) : une lecture ratée est avouée PUIS l'INSERT est tenté.
        nom_unique: bool,
    }

    fn oac_cas() -> Vec<OacCas> {
        vec![
            OacCas {
                table: "destination",
                nom: "oac-destination",
                genre: "destination",
                fichier: |_| r#"{"name":"oac-destination","type":"s3","endpoint":"s3://oac-puits","enabled":false}"#.to_string(),
                charger: crate::overlays_oac::load_overlay_destinations,
                homonyme: "INSERT INTO destination(type,name,enabled,endpoint,managed,created) VALUES('s3',?1,0,'s3://ui',?2,0)",
                nom_unique: false,
            },
            OacCas {
                table: "connector",
                nom: "oac-connecteur",
                genre: "connecteur",
                fichier: |d| {
                    json!({
                        "name": "oac-connecteur",
                        "type": "taxii2",
                        "config": {"api_root": "https://192.0.2.10/taxii2/", "collection_id": "c1"},
                        "secret_ref": format!("file:{}", d.join("secret.txt").display()),
                        "enabled": false
                    })
                    .to_string()
                },
                charger: crate::overlays_oac::load_overlay_connectors,
                homonyme: "INSERT INTO connector(type,name,enabled,config_json,secret,managed,created) VALUES('taxii2',?1,0,'{}','',?2,0)",
                nom_unique: false,
            },
            OacCas {
                table: "field_filter",
                nom: "oac-masque",
                genre: "field-filter",
                fichier: |_| r#"{"name":"oac-masque","field":"oac_champ","action":"mask","enabled":true}"#.to_string(),
                charger: crate::overlays_oac::load_overlay_field_filters,
                homonyme: "INSERT INTO field_filter(name,field,action,managed) VALUES(?1,'autre_champ','hash',?2)",
                nom_unique: true,
            },
        ]
    }

    fn oac_dossier(cas: &OacCas) -> crate::tmp_possede::TmpPossede {
        let d = crate::tmp_possede::TmpPossede::neuf(&format!("oac-{}", cas.table));
        std::fs::write(d.join("secret.txt"), OAC_SECRET).unwrap();
        std::fs::write(d.join("o.json"), (cas.fichier)(&d)).unwrap();
        d
    }

    fn oac_lignes(c: &Connection, cas: &OacCas) -> i64 {
        c.query_row(&format!("SELECT COUNT(*) FROM {} WHERE name=?1", cas.table), params![cas.nom], |r| r.get(0)).unwrap()
    }

    fn oac_managed(c: &Connection, cas: &OacCas) -> i64 {
        c.query_row(&format!("SELECT managed FROM {} WHERE name=?1", cas.table), params![cas.nom], |r| r.get(0)).unwrap()
    }

    /// Refuse TOUTE lecture de `table` (l'écriture reste permise) ; rend le compteur de refus.
    fn oac_refuser_la_lecture(c: &Connection, table: &'static str) -> Arc<AtomicUsize> {
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

    fn oac_lever(c: &Connection) {
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn oac_charger(c: &Connection, cas: &OacCas, d: &std::path::Path) -> (u32, u32) {
        let ch = (cas.charger)(c, d);
        (ch.charges, ch.ignores)
    }

    /// (1) Lecture de l'existant refusée : sans UNIQUE(name), aucune ligne ajoutée, le fichier est ignoré ; avec
    /// UNIQUE(name) (`field_filter`), le masque est posé — une ligne, `managed=1`, l'action du fichier — et compté.
    #[test]
    fn oac_lecture_ratee_sans_doublon_et_masque_pose() {
        let mut vus_unique = 0;
        for cas in oac_cas() {
            let c = test_db();
            let d = oac_dossier(&cas);
            let refus = oac_refuser_la_lecture(&c, cas.table);
            let bilan = oac_charger(&c, &cas, &d);
            oac_lever(&c);
            assert!(refus.load(SeqCst) >= 1, "{} : fixture, la lecture de la table a été refusée", cas.table);
            if cas.nom_unique {
                vus_unique += 1;
                assert_eq!(oac_lignes(&c, &cas), 1, "{} : le masque est posé malgré la lecture ratée", cas.table);
                assert_eq!(oac_managed(&c, &cas), 1, "{} : posé par l'overlay", cas.table);
                let action: String = c.query_row(&format!("SELECT action FROM {} WHERE name=?1", cas.table), params![cas.nom], |r| r.get(0)).unwrap();
                assert_eq!(action, "mask", "{} : l'action du fichier", cas.table);
                assert_eq!(bilan, (1, 0), "{} : (charges, ignores) = (1, 0)", cas.table);
            } else {
                assert_eq!(oac_lignes(&c, &cas), 0, "{} : aucune ligne posée sur une lecture ratée", cas.table);
                assert_eq!(bilan, (0, 1), "{} : (charges, ignores) = (0, 1)", cas.table);
            }
        }
        assert_eq!(vus_unique, 1, "contrôle : le cas field_filter a été joué");
    }

    /// (2) Contre-épreuve sans panne : une ligne posée, puis rejouée en UPDATE, toujours une seule.
    #[test]
    fn oac_contre_epreuve_sans_panne_pose_une_ligne() {
        for cas in oac_cas() {
            let c = test_db();
            let d = oac_dossier(&cas);
            assert_eq!(oac_charger(&c, &cas, &d), (1, 0), "{} : chargé", cas.table);
            assert_eq!(oac_lignes(&c, &cas), 1, "{} : une ligne", cas.table);
            assert_eq!(oac_charger(&c, &cas, &d), (1, 0), "{} : rejoué (UPDATE), chargé", cas.table);
            assert_eq!(oac_lignes(&c, &cas), 1, "{} : toujours une ligne", cas.table);
            assert_eq!(oac_managed(&c, &cas), 1, "{} : posée par l'overlay", cas.table);
        }
        // Le connecteur porte bien le secret résolu (le chemin nominal est intact).
        let cas = oac_cas().into_iter().find(|k| k.table == "connector").unwrap();
        let c = test_db();
        let d = oac_dossier(&cas);
        oac_charger(&c, &cas, &d);
        let secret: String = c.query_row("SELECT secret FROM connector WHERE name=?1", params![cas.nom], |r| r.get(0)).unwrap();
        assert_eq!(secret, OAC_SECRET, "contrôle : le secret du connecteur est résolu et posé");
    }

    /// (3) Copie UI `managed=2` du même nom ET lecture refusée : aucune deuxième ligne, la copie intacte.
    #[test]
    fn oac_homonyme_ad_hoc_et_lecture_ratee_reste_seul() {
        for cas in oac_cas() {
            let c = test_db();
            let d = oac_dossier(&cas);
            c.execute(cas.homonyme, params![cas.nom, 2]).unwrap();
            let refus = oac_refuser_la_lecture(&c, cas.table);
            let bilan = oac_charger(&c, &cas, &d);
            oac_lever(&c);
            assert!(refus.load(SeqCst) >= 1, "{} : fixture, lecture refusée", cas.table);
            assert_eq!(oac_lignes(&c, &cas), 1, "{} : aucune deuxième ligne du même nom", cas.table);
            assert_eq!(oac_managed(&c, &cas), 2, "{} : la copie UI reste managed=2", cas.table);
            assert_eq!(bilan, (0, 1), "{} : ignoré, non chargé", cas.table);
        }
    }

    /// (4) Écriture refusée par le moteur (`RAISE(ABORT)`), en INSERT puis en UPDATE : non comptée chargée.
    #[test]
    fn oac_ecriture_refusee_n_est_pas_comptee_chargee() {
        for cas in oac_cas() {
            let c = test_db();
            let d = oac_dossier(&cas);
            c.execute_batch(&format!("CREATE TRIGGER oac_refus_ins BEFORE INSERT ON {} BEGIN SELECT RAISE(ABORT,'oac refus'); END", cas.table)).unwrap();
            assert_eq!(oac_charger(&c, &cas, &d), (0, 1), "{} : INSERT refusé, non chargé", cas.table);
            assert_eq!(oac_lignes(&c, &cas), 0, "{} : fixture, rien posé", cas.table);
            c.execute_batch("DROP TRIGGER oac_refus_ins").unwrap();
            c.execute(cas.homonyme, params![cas.nom, 1]).unwrap();
            c.execute_batch(&format!("CREATE TRIGGER oac_refus_upd BEFORE UPDATE ON {} BEGIN SELECT RAISE(ABORT,'oac refus'); END", cas.table)).unwrap();
            assert_eq!(oac_charger(&c, &cas, &d), (0, 1), "{} : UPDATE refusé, non chargé", cas.table);
            assert_eq!(oac_lignes(&c, &cas), 1, "{} : la ligne d'avant, seule", cas.table);
        }
    }

    /// (5) Écriture sans effet (`RAISE(IGNORE)`, `Ok(0)`), en INSERT puis en UPDATE : non comptée chargée.
    #[test]
    fn oac_ecriture_sans_effet_n_est_pas_comptee_chargee() {
        for cas in oac_cas() {
            let c = test_db();
            let d = oac_dossier(&cas);
            c.execute_batch(&format!("CREATE TRIGGER oac_muet_ins BEFORE INSERT ON {} BEGIN SELECT RAISE(IGNORE); END", cas.table)).unwrap();
            assert_eq!(oac_charger(&c, &cas, &d), (0, 1), "{} : INSERT sans effet, non chargé", cas.table);
            assert_eq!(oac_lignes(&c, &cas), 0, "{} : fixture, rien posé", cas.table);
            c.execute_batch("DROP TRIGGER oac_muet_ins").unwrap();
            c.execute(cas.homonyme, params![cas.nom, 1]).unwrap();
            c.execute_batch(&format!("CREATE TRIGGER oac_muet_upd BEFORE UPDATE ON {} BEGIN SELECT RAISE(IGNORE); END", cas.table)).unwrap();
            assert_eq!(oac_charger(&c, &cas, &d), (0, 1), "{} : UPDATE sans effet, non chargé", cas.table);
        }
    }

    /// Arguments de la ré-exécution d'UN test de ce module par son propre binaire. La commande elle-même
    /// (`current_exe()`, `.env(`) est écrite dans chaque test : c'est ce qui le range, pour la garde des refus
    /// de conclure, dans le protocole à deux bras dont le bras de l'enfant sort tôt par construction.
    fn oac_args_de_l_enfant(nom_du_test: &str) -> [String; 4] {
        [
            "--exact".into(),
            "--nocapture".into(),
            "--test-threads=1".into(),
            format!("tests::overlays_oac_lecture_ratee_et_ecriture_comptee::{nom_du_test}"),
        ]
    }

    /// Lit la sortie de l'enfant : code 0 exigé, aucun secret de connecteur journalisé.
    fn oac_lire_l_enfant(sortie: std::process::Output) -> (String, String) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        assert!(!stderr.contains(OAC_SECRET) && !stdout.contains(OAC_SECRET), "le secret du connecteur n'est jamais journalisé : {stderr}");
        (stdout, stderr)
    }

    /// (6) La lecture refusée est DITE : une ligne `[oac] WARN` par chargeur avec la cause du moteur, lue sur le
    /// stderr d'un sous-processus ; aucune après la levée de la panne (chemin nominal muet).
    #[test]
    fn oac_lecture_ratee_dit_sa_cause_au_journal() {
        const ENFANT: &str = "OAC_S5_ENFANT_JOURNAL";
        const LEVEE: &str = "OAC-PHASE-LEVEE";
        if std::env::var(ENFANT).is_ok() {
            let c = test_db();
            let cas = oac_cas();
            let dossiers: Vec<_> = cas.iter().map(oac_dossier).collect();
            for (k, d) in cas.iter().zip(&dossiers) {
                oac_refuser_la_lecture(&c, k.table);
                let cause = plan_upsert_lu(&c, k.table, k.nom).err().expect("fixture : lecture refusée");
                println!("OAC-CAUSE:{}:{cause}", k.table);
                println!("OAC-RATEE:{}:{:?}", k.table, oac_charger(&c, k, d));
                oac_lever(&c);
            }
            eprintln!("{LEVEE}");
            for (k, d) in cas.iter().zip(&dossiers) {
                println!("OAC-NOMINAL:{}:{:?}", k.table, oac_charger(&c, k, d));
            }
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(oac_args_de_l_enfant("oac_lecture_ratee_dit_sa_cause_au_journal"))
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (stdout, stderr) = oac_lire_l_enfant(sortie);
        let (avant, apres) = stderr.split_once(LEVEE).unwrap_or_else(|| panic!("contrôle : marqueur de levée : {stderr}"));
        let lignes: Vec<&str> = avant.lines().filter(|l| l.starts_with("[oac] WARN")).collect();
        assert_eq!(lignes.len(), 3, "une ligne par chargeur, ni plus ni moins : {lignes:?}\n{stderr}");
        for (k, ligne) in oac_cas().iter().zip(lignes.iter()) {
            let cause = stdout
                .lines()
                .find_map(|l| l.split_once(&format!("OAC-CAUSE:{}:", k.table)).map(|(_, c)| c.to_string()))
                .unwrap_or_else(|| panic!("contrôle : cause du moteur rendue pour {} : {stdout}", k.table));
            assert!(!cause.trim().is_empty(), "contrôle : cause non vide");
            assert!(ligne.starts_with(&format!("[oac] WARN {} '{}'", k.genre, k.nom)), "le genre et le nom : {ligne}");
            assert!(ligne.contains("lecture de l'existant NON faite"), "le geste nommé : {ligne}");
            assert!(ligne.contains(&format!("({cause})")), "la cause du moteur (`{cause}`) : {ligne}");
            let (suite, bilan) = if k.nom_unique { ("INSERT tenté, borné par UNIQUE(name)", "(1, 0)") } else { ("overlay IGNORÉ, rien écrit", "(0, 1)") };
            assert!(ligne.contains(suite), "la suite donnée (`{suite}`) : {ligne}");
            assert!(stdout.contains(&format!("OAC-RATEE:{}:{bilan}", k.table)), "contrôle : lecture ratée, {} rend {bilan} : {stdout}", k.table);
            assert!(stdout.contains(&format!("OAC-NOMINAL:{}:(1, 0)", k.table)), "contrôle : levée, {} chargé : {stdout}", k.table);
        }
        assert_eq!(apres.lines().filter(|l| l.starts_with("[oac] WARN")).count(), 0, "chemin nominal muet : {apres}");
    }

    /// (7) L'écriture refusée (`RAISE(ABORT)`) et l'écriture sans effet (`RAISE(IGNORE)`) sont DITES : pour chaque
    /// chargeur, en INSERT puis en UPDATE, exactement une ligne `[oac] WARN` par geste, nommant le genre, le nom, le
    /// geste et (refus) la cause du moteur ; lue sur le stderr d'un sous-processus, phase par phase.
    #[test]
    fn oac_ecriture_refusee_ou_sans_effet_dit_sa_cause_au_journal() {
        const ENFANT: &str = "OAC_S5_ENFANT_ECRITURE";
        const PHASE: &str = "OAC-PHASE:";
        let phases = ["ins-refus", "upd-refus", "ins-muet", "upd-muet", "nominal"];
        if std::env::var(ENFANT).is_ok() {
            for k in oac_cas() {
                let d = oac_dossier(&k);
                for (phase, quand, effet) in [
                    ("ins-refus", "INSERT", "RAISE(ABORT,'oac refus')"),
                    ("upd-refus", "UPDATE", "RAISE(ABORT,'oac refus')"),
                    ("ins-muet", "INSERT", "RAISE(IGNORE)"),
                    ("upd-muet", "UPDATE", "RAISE(IGNORE)"),
                ] {
                    let c = test_db();
                    if quand == "UPDATE" {
                        c.execute(k.homonyme, params![k.nom, 1]).unwrap();
                    }
                    c.execute_batch(&format!("CREATE TRIGGER oac_t BEFORE {quand} ON {} BEGIN SELECT {effet}; END", k.table)).unwrap();
                    eprintln!("{PHASE}{}:{phase}", k.table);
                    println!("OAC-BILAN:{}:{phase}:{:?}", k.table, oac_charger(&c, &k, &d));
                }
                let c = test_db();
                eprintln!("{PHASE}{}:nominal", k.table);
                println!("OAC-BILAN:{}:nominal:{:?}", k.table, oac_charger(&c, &k, &d));
            }
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(oac_args_de_l_enfant("oac_ecriture_refusee_ou_sans_effet_dit_sa_cause_au_journal"))
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let (stdout, stderr) = oac_lire_l_enfant(sortie);
        // Découpe du stderr en segments, un par (table, phase) : les WARN d'un segment sont ceux de ce seul appel.
        let mut segments: Vec<(String, Vec<String>)> = Vec::new();
        for l in stderr.lines() {
            if let Some(etiquette) = l.strip_prefix(PHASE) {
                segments.push((etiquette.to_string(), Vec::new()));
            } else if l.starts_with("[oac] WARN") {
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
        for k in oac_cas() {
            for phase in phases {
                let bilan = if phase == "nominal" { "(1, 0)" } else { "(0, 1)" };
                assert!(
                    stdout.contains(&format!("OAC-BILAN:{}:{phase}:{bilan}", k.table)),
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
                assert!(ligne.starts_with(&format!("[oac] WARN {} '{}'", k.genre, k.nom)), "{phase} : le genre et le nom : {ligne}");
                assert!(ligne.contains("overlay NON chargé"), "{phase} : la conséquence : {ligne}");
                if phase.ends_with("refus") {
                    assert!(ligne.contains("écriture refusée (") && ligne.contains("oac refus"), "{phase} : le geste et la cause du moteur : {ligne}");
                } else {
                    assert!(ligne.contains("écriture sans effet (0 ligne posée)"), "{phase} : le geste et le nombre de lignes : {ligne}");
                }
            }
        }
    }
}

// =====================================================================================
// `P10.20-b` (rang trois d'`alerting.rs` : `run_advanced_rules`) et sa famille voisine (`run_baselines`) — L'ALERTE
// D'ABORD, L'ÉTAT ENSUITE : une alerte que le moteur refuse d'écrire ne laisse plus derrière elle l'état qui la tait.
//
// VU sur `d8239ceb` : `run_advanced_rules` avalait l'INSERT de l'alerte (`let _ = conn.execute(..)`) puis posait le
// throttle SANS CONDITION — l'unité était mutée pendant la fenêtre de suppression, l'alerte n'existait ni à ce tour
// ni au suivant ; le throttle était lu par `.ok()`, une lecture ratée tirait sans un mot. `run_baselines` avalait de
// même l'INSERT de l'alerte d'anomalie puis avançait `last_bucket`. RE-MESURÉ en plus de l'énoncé : ne pas avancer
// `last_bucket` ne suffisait pas — `last_run` avancé, la ligne de base n'est due qu'après `interval_s`, égal par défaut
// à `bucket_s` (3600, schéma et route de création), et le bucket clos d'alors est le SUIVANT : le bucket raté n'est
// jamais réévalué. Le correctif n'avance pas `last_bucket` de la ligne de base concernée, et pose son `last_run` au pas
// de reprise (`REPRISE_LIGNE_DE_BASE_S`, borné par `interval_s`) au lieu de l'avancer d'un intervalle entier.
//
// ATTENDU, tenu ici : le refus d'écriture est fabriqué par un trigger `RAISE(ABORT)` sur `alert` (l'`OR IGNORE` de
// l'INSERT ne l'absorbe pas). Règle avancée : le tick COMPTE l'abandon par RÈGLE (`Mesure::Lue(1)` pour deux unités
// refusées : le contrat dit « règles dues abandonnées »), ne pose pas le throttle de l'unité refusée, n'écrit pas
// `last_fired` si rien n'est entré ; le trigger retiré, l'alerte est émise au tour suivant. Cas MIXTE (deux IP, une
// seule refusée) : l'alerte entrée a son throttle, `last_fired` est écrit, un abandon. Toutes les unités MUETTES
// (fenêtre de suppression) : `last_fired` écrit comme avant. Throttle illisible (valeur texte ; puis une VUE qui
// projette un blob) : l'unité tire comme avant et ce n'est PAS un abandon (elle a été évaluée) ; son seul aveu est la
// ligne de stderr, LUE par un sous-processus (le binaire de test rejoué, modèle
// `connaissances_lectures_ratees_par_base_et_stderr`) : une ligne pour la lecture ratée, aucune pour un throttle
// lisible, aucune pour un throttle ABSENT (premier tir de l'unité : `Ok(None)`, l'absence établie n'est pas une lecture
// ratée). Dédup (`INSERT OR IGNORE` qui rend `Ok(0)`) = ENTRÉE, pas refus : règle avancée dont l'alerte est encore
// ouverte, fenêtre écoulée -> throttle reposé, `last_fired` écrit, `Lue(0)` ; ligne de base reprise après un refus
// PARTIEL (deux entités, une seule refusée) -> l'alerte déjà entrée est écartée par la dédup, la refusée entre, le
// bucket est marqué, `Lue(0)`. Ligne de base, à une
// heure FIXÉE (instrument `horloge_fixee_des_lignes_de_base`, aucun témoin ne dépend de l'heure du lancement) : `last_bucket` inchangé, `last_run`
// posé au pas de reprise (pas due au tick d'après, due `REPRISE_LIGNE_DE_BASE_S` plus tard, borné par `interval_s`),
// l'anomalie du MÊME bucket réémise alors. Contrôles négatifs : écriture réussie -> throttle posé, `last_fired`
// écrit, bucket et `last_run` avancés, `Lue(0)`, tour suivant muté ; ligne de base redue (`last_run` remis à NULL,
// alerte close et dédup vidée) sur un bucket déjà traité : rien n'est réémis.
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit) — premier passage : P6_THROTTLE_INCOND, P6_ABANDON_ADV,
// P6_THROTTLE_OK, P6_BUCKET_INCOND, P6_LASTRUN_INCOND, P6_ABANDON_BL. Correction : A6 (`last_fired` écrit seulement
// sans refus), A7 (seulement si une alerte est entrée), A8 (compteur des alertes entrées retiré), P6_COMPTE_UNITE
// (un abandon par unité refusée), P6_THROTTLE_COMPTE (lecture de throttle ratée comptée comme abandon),
// P6_REPRISE_ABSENTE (`last_run` laissé tel quel : requête relancée à chaque tour), P6_LASTRUN_INCOND (`last_run`
// avancé d'un intervalle entier) — chacun rouge sur son témoin. Seconde correction : A1 (bras `Err` de la lecture
// du throttle rendu muet), A2 (`.ok()` rétabli à la place de `.optional()`) — rouges sur le témoin de stderr ;
// P6_FILTRE_BUCKET (filtre `last_bucket >= closed` neutralisé) — rouge sur la seconde moitié du contrôle négatif de
// ligne de base, qui était vacante (à `T0 + 300` plus rien n'était dû). Troisième correction : A16 (`.optional()`
// retiré, l'absence part dans le bras `Err` et s'avoue), A17 (aveu écrit aussi sur `Ok(None)`) — rouges sur la
// troisième base (absente) du témoin de stderr ; A18 (`Ok(0)` de la dédup traité comme un refus dans
// `run_advanced_rules`) — rouge sur le témoin de l'alerte encore ouverte ; B12 (idem dans `run_baselines`) — rouge sur
// le témoin du refus partiel puis reprise.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les lignes de journal des alertes REFUSÉES (règle avancée et ligne de base :
// `eprintln!`, non lues — seule la ligne de lecture de throttle ratée l'est : les rendre muettes reste vert, et la
// cause du moteur n'existe que dans ces lignes) ; le filtre `!a_reevaluer.contains` de `run_baselines`, équivalent à
// son absence tant que l'UPDATE du pas de reprise qui le suit réussit (le retirer reste vert ; l'inverser rougit) ; le texte de la cause du moteur dans la
// ligne lue (seuls le préfixe, la règle et la suite sont jugés) ; un refus par verrou, disque plein ou
// interruption (même `Err`, non fabriqué) ; un refus qui dure au-delà de la clôture du bucket suivant (l'anomalie est
// alors perdue, mais comptée à chaque reprise) ; l'écriture du throttle elle-même et celle du pas de reprise (`let _`,
// sens bruyant : nouvel essai dès le tour suivant) ; la voie risque de `run_baselines` (`risk_event_insert`, qui rend `false`
// pour « déjà posée » comme pour « refusée ») ; le cas `!ev.ok`, qui avance toujours `last_run` ; la phrase de l'écran
// santé (« non évalués »), qui reste approximative pour une règle évaluée dont l'alerte a été refusée.
// =====================================================================================
mod alertes_ecrites_avant_d_avancer_l_etat {
    use super::*;
    use crate::mesure_environnement::Mesure;

    const AEAE_REFUS: &str = "CREATE TRIGGER aeae_refus BEFORE INSERT ON alert BEGIN SELECT RAISE(ABORT, 'alerte refusée par le témoin'); END;";
    /// Refuse la seule alerte de l'unité `8.8.8.8` (la capture structurée pose `src_ip` = valeur du champ de throttle).
    const AEAE_REFUS_8888: &str = "CREATE TRIGGER aeae_refus BEFORE INSERT ON alert WHEN NEW.src_ip='8.8.8.8' BEGIN SELECT RAISE(ABORT, 'alerte refusée par le témoin'); END;";

    fn aeae_ecrire(p: &str, sql: &str) {
        let w = open_db(p).unwrap();
        w.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    // ---------------------------------------------------------------- règle avancée (throttle par src_ip)

    /// Une règle avancée throttlée par `src_ip`, franchissante pour chaque IP de `ips` (24 événements chacune).
    /// Rend (tmp, chemin).
    fn aeae_base_regle(tag: &str, ips: &[&str]) -> (crate::tmp_possede::TmpPossede, String) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(&format!("aeae-{tag}"));
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let t = now() - 10;
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&w), "fixture : la chaîne de migrations doit aller au bout");
            w.execute(
                "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,managed,throttle_field) \
                 VALUES('exploit web par IP',1,'search source=web status>=500 | stats count by src_ip | where count > 10',1,'>',0.0,4,300,600,'T1190',2,'src_ip')",
                [],
            ).unwrap();
            for ip in ips {
                for i in 0..24 {
                    w.execute(
                        "INSERT INTO event(ts,source,severity,src_ip,fields,dedup) VALUES(?1,'web',4,?2,'{\"status\":\"500\"}',?3)",
                        params![t, ip, format!("s5-{ip}-{i}")],
                    ).unwrap();
                }
            }
        }
        (tmp, p)
    }

    /// Un tour de `run_advanced_rules` puis (bilan, alertes, throttles posés, last_fired).
    fn aeae_tour_regle(p: &str) -> (crate::bilan_de_tick::BilanDeTick, i64, i64, Option<i64>) {
        let db = Arc::new(Mutex::new(open_db(p).unwrap()));
        let bilan = run_advanced_rules(&db, p);
        let c = db.lock();
        (
            bilan,
            c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap(),
            c.query_row("SELECT COUNT(*) FROM alert_throttle WHERE typeof(last_fire)='integer'", [], |r| r.get(0)).unwrap_or(-1),
            c.query_row("SELECT last_fired FROM rule", [], |r| r.get::<_, Option<i64>>(0)).unwrap(),
        )
    }

    #[test]
    fn p10_20b_regle_avancee_controle_negatif_alerte_ecrite_puis_throttle_pose_et_tour_suivant_mute() {
        let (_t, p) = aeae_base_regle("adv-ok", &["9.9.9.9"]);
        let (bilan, alertes, throttles, last_fired) = aeae_tour_regle(&p);
        assert_eq!(bilan, Mesure::Lue(0), "nominal : rien d'abandonné");
        assert_eq!(alertes, 1, "nominal : une alerte pour l'IP franchissante");
        assert_eq!(throttles, 1, "nominal : le throttle de l'unité est posé");
        assert!(last_fired.is_some(), "nominal : last_fired écrit");
        // Le tour suivant (règle redue) est muté par la fenêtre : l'alerte fermée par le témoin ne se rouvre pas.
        aeae_ecrire(&p, "UPDATE rule SET last_run=NULL; UPDATE alert SET status='resolved', dedup=NULL;");
        let (bilan, alertes, _, _) = aeae_tour_regle(&p);
        assert_eq!(bilan, Mesure::Lue(0));
        assert_eq!(alertes, 1, "nominal : dans la fenêtre de suppression, le tour suivant ne réémet pas");
    }

    #[test]
    fn p10_20b_regle_avancee_toutes_unites_muettes_last_fired_ecrit_comme_avant() {
        // Moitié « aucun refus » de la condition : un tour où TOUTES les unités sont muettes par la fenêtre (aucune
        // alerte écrite, aucune refusée) écrit `last_fired`, comme avant le correctif.
        let (_t, p) = aeae_base_regle("adv-muet", &["9.9.9.9", "8.8.8.8"]);
        let (_, alertes, throttles, _) = aeae_tour_regle(&p);
        assert_eq!((alertes, throttles), (2, 2), "fixture : deux unités tirées, deux throttles posés");
        aeae_ecrire(&p, "UPDATE rule SET last_run=NULL, last_fired=NULL;");
        let (bilan, alertes, _, last_fired) = aeae_tour_regle(&p);
        assert_eq!(alertes, 2, "fixture : les deux unités sont muettes à ce tour");
        assert_eq!(bilan, Mesure::Lue(0), "unités muettes : rien d'abandonné");
        assert!(last_fired.is_some(), "toutes les unités muettes, aucun refus : last_fired est écrit comme avant");
    }

    #[test]
    fn p10_20b_regle_avancee_cas_mixte_une_alerte_entree_une_refusee_last_fired_ecrit_et_un_abandon() {
        // Moitié « une alerte entrée » de la condition : deux unités, le moteur refuse la seule `8.8.8.8`.
        let (_t, p) = aeae_base_regle("adv-mixte", &["9.9.9.9", "8.8.8.8"]);
        aeae_ecrire(&p, AEAE_REFUS_8888);
        let (bilan, alertes, throttles, last_fired) = aeae_tour_regle(&p);
        let c = open_db(&p).unwrap();
        let ips: Vec<String> = c.prepare("SELECT src_ip FROM alert ORDER BY src_ip").unwrap()
            .query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
        let cles: Vec<String> = c.prepare("SELECT throttle_key FROM alert_throttle ORDER BY throttle_key").unwrap()
            .query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
        assert_eq!(alertes, 1, "fixture : une alerte entrée, l'autre refusée");
        assert_eq!(ips, vec!["9.9.9.9".to_string()], "fixture : c'est bien l'alerte de 8.8.8.8 qui est refusée");
        assert_eq!((throttles, cles), (1, vec!["9.9.9.9".to_string()]), "seule l'unité dont l'alerte est entrée a son throttle");
        assert!(last_fired.is_some(), "une alerte au moins est entrée : last_fired est écrit malgré le refus de l'autre");
        assert_eq!(bilan, Mesure::Lue(1), "une règle dont une alerte est refusée : un abandon");
    }

    #[test]
    fn p10_20b_regle_avancee_deux_unites_refusees_comptent_pour_une_regle() {
        // Le contrat du bilan dit « règles dues abandonnées » : deux unités refusées de la même règle = UN abandon.
        let (_t, p) = aeae_base_regle("adv-deux-refus", &["9.9.9.9", "8.8.8.8"]);
        aeae_ecrire(&p, AEAE_REFUS);
        let (bilan, alertes, throttles, last_fired) = aeae_tour_regle(&p);
        assert_eq!((alertes, throttles), (0, 0), "fixture : les deux alertes refusées, aucun throttle");
        assert_eq!(bilan, Mesure::Lue(1), "deux unités refusées d'UNE règle : un seul abandon (des règles, pas des unités)");
        assert_eq!(last_fired, None, "aucune alerte entrée : last_fired n'est pas écrit");
    }

    #[test]
    fn p10_20b_regle_avancee_alerte_refusee_ni_throttle_ni_last_fired_et_rejouee_au_tour_suivant() {
        let (_t, p) = aeae_base_regle("adv-refus", &["9.9.9.9"]);
        aeae_ecrire(&p, AEAE_REFUS);
        let (bilan, alertes, throttles, last_fired) = aeae_tour_regle(&p);
        assert_eq!(alertes, 0, "fixture : le trigger a bien refusé l'alerte");
        assert_eq!(throttles, 0, "alerte NON écrite : le throttle n'est PAS posé (sinon le tir suivant serait muté pendant la fenêtre)");
        assert_eq!(bilan, Mesure::Lue(1), "alerte NON écrite : l'abandon est COMPTÉ dans le bilan du tick");
        assert_eq!(last_fired, None, "aucune alerte entrée : last_fired n'est pas écrit");
        // Le trigger retiré, la règle redue au prochain intervalle : l'alerte est émise.
        aeae_ecrire(&p, "DROP TRIGGER aeae_refus; UPDATE rule SET last_run=NULL;");
        let (bilan, alertes, throttles, last_fired) = aeae_tour_regle(&p);
        assert_eq!(alertes, 1, "l'alerte refusée est émise au tour suivant (rien ne la tait)");
        assert_eq!(throttles, 1, "puis le throttle est posé");
        assert_eq!(bilan, Mesure::Lue(0));
        assert!(last_fired.is_some());
    }

    #[test]
    fn p10_20b_regle_avancee_throttle_illisible_tire_et_n_est_pas_un_abandon() {
        // (a) Une valeur texte dans la colonne entière `last_fire` : la ligne existe, sa lecture échoue.
        let (_t, p) = aeae_base_regle("adv-texte", &["9.9.9.9"]);
        aeae_ecrire(&p, "INSERT INTO alert_throttle(rule_id,throttle_key,last_fire) SELECT id,'9.9.9.9','illisible' FROM rule;");
        let (bilan, alertes, throttles, _) = aeae_tour_regle(&p);
        assert_eq!(alertes, 1, "throttle illisible : l'unité tire comme avant (sens bruyant conservé)");
        assert_eq!(bilan, Mesure::Lue(0), "throttle illisible : l'unité a été évaluée et a tiré, ce n'est pas un abandon");
        assert_eq!(throttles, 1, "puis le throttle est réécrit");
        // (b) La table remplacée par une VUE qui projette un blob pour cette unité.
        let (_t2, p2) = aeae_base_regle("adv-vue", &["9.9.9.9"]);
        aeae_ecrire(&p2, "DROP TABLE alert_throttle; CREATE VIEW alert_throttle AS SELECT id AS rule_id, '9.9.9.9' AS throttle_key, x'FF' AS last_fire FROM rule;");
        let (bilan, alertes, _, _) = aeae_tour_regle(&p2);
        assert_eq!(alertes, 1, "throttle lu par une vue illisible : l'unité tire");
        assert_eq!(bilan, Mesure::Lue(0), "throttle lu par une vue illisible : pas un abandon");
    }

    const AEAE_LIGNE_THROTTLE: &str = "le throttle d'une unité n'a pas pu être lu";
    const AEAE_SEPARATEUR: &str = "AEAE-ENFANT-SEPARATEUR";
    const AEAE_SEPARATEUR_ABSENT: &str = "AEAE-ENFANT-TROISIEME-BASE";

    /// L'AVEU DE LA LECTURE DE THROTTLE RATÉE PART VRAIMENT SUR STDERR. L'enfant (variable `AEAE_ENFANT` posée) joue
    /// trois bases séparées par des séparateurs écrits sur le MÊME flux : (1) throttle illisible (valeur texte) ;
    /// (2) throttle lisible (entier ancien, hors fenêtre) ; (3) throttle ABSENT (aucune ligne : premier tir, le cas le
    /// plus courant). Les trois unités tirent (contrôle dans l'enfant : sinon il panique et sort non nul). Le parent
    /// lit le stderr de l'enfant : exactement une ligne d'aveu avant le premier séparateur, qui nomme la règle et dit
    /// la suite (« évaluée comme jamais tirée ») ; aucune pour le throttle lisible ; aucune pour le throttle absent
    /// (l'absence établie n'est pas une lecture ratée).
    #[test]
    fn p10_20b_regle_avancee_throttle_illisible_ecrit_sa_ligne_de_stderr_et_un_throttle_lisible_aucune() {
        const ENFANT: &str = "AEAE_ENFANT";
        if std::env::var(ENFANT).is_ok() {
            let (_t, p) = aeae_base_regle("adv-stderr-illisible", &["9.9.9.9"]);
            aeae_ecrire(&p, "INSERT INTO alert_throttle(rule_id,throttle_key,last_fire) SELECT id,'9.9.9.9','illisible' FROM rule;");
            let id: i64 = open_db(&p).unwrap().query_row("SELECT id FROM rule", [], |r| r.get(0)).unwrap();
            println!("AEAE-ENFANT-REGLE={id}");
            let (_, alertes, _, _) = aeae_tour_regle(&p);
            assert_eq!(alertes, 1, "contrôle enfant : throttle illisible, l'unité tire");
            eprintln!("{AEAE_SEPARATEUR}");
            let (_t2, p2) = aeae_base_regle("adv-stderr-lisible", &["9.9.9.9"]);
            aeae_ecrire(&p2, "INSERT INTO alert_throttle(rule_id,throttle_key,last_fire) SELECT id,'9.9.9.9',0 FROM rule;");
            let (_, alertes, _, _) = aeae_tour_regle(&p2);
            assert_eq!(alertes, 1, "contrôle enfant : throttle lisible hors fenêtre, l'unité tire");
            eprintln!("{AEAE_SEPARATEUR_ABSENT}");
            let (_t3, p3) = aeae_base_regle("adv-stderr-absent", &["9.9.9.9"]);
            let lignes: i64 = open_db(&p3).unwrap().query_row("SELECT COUNT(*) FROM alert_throttle", [], |r| r.get(0)).unwrap();
            assert_eq!(lignes, 0, "contrôle enfant : aucun throttle posé, l'absence est réelle");
            let (_, alertes, _, _) = aeae_tour_regle(&p3);
            assert_eq!(alertes, 1, "contrôle enfant : throttle absent (premier tir), l'unité tire");
            println!("AEAE-ENFANT-A-JOUE");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::alertes_ecrites_avant_d_avancer_l_etat::p10_20b_regle_avancee_throttle_illisible_ecrit_sa_ligne_de_stderr_et_un_throttle_lisible_aucune",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains("AEAE-ENFANT-A-JOUE"), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let id = stdout
            .lines()
            .find_map(|l| l.split("AEAE-ENFANT-REGLE=").nth(1))
            .expect("contrôle : l'enfant nomme sa règle")
            .trim()
            .to_string();
        let (avant, reste) = stderr.split_once(AEAE_SEPARATEUR).expect("contrôle : le premier séparateur est sur stderr");
        let (apres, absent) = reste.split_once(AEAE_SEPARATEUR_ABSENT).expect("contrôle : le second séparateur est sur stderr");
        let aveux = |bloc: &str| -> Vec<String> {
            bloc.lines().filter(|l| l.contains(AEAE_LIGNE_THROTTLE)).map(str::to_string).collect()
        };
        let lignes = aveux(avant);
        assert_eq!(lignes.len(), 1, "throttle illisible : UNE ligne d'aveu sur stderr : {stderr}");
        let l = &lignes[0];
        assert!(l.starts_with(&format!("[alerting] WARN règle avancée #{id} : ")), "la ligne nomme la règle : {l}");
        assert!(l.contains("l'unité est évaluée comme jamais tirée"), "la ligne dit la suite : {l}");
        assert_eq!(aveux(apres), Vec::<String>::new(), "throttle lisible : aucune ligne d'aveu : {stderr}");
        assert_eq!(aveux(absent), Vec::<String>::new(), "throttle ABSENT (premier tir) : aucune ligne d'aveu, l'absence n'est pas une lecture ratée : {stderr}");
    }

    #[test]
    fn p10_20b_regle_avancee_alerte_encore_ouverte_ecartee_par_la_dedup_vaut_entree() {
        // L'`INSERT OR IGNORE` écarté par la dédup (`Ok(0)` : l'alerte de l'unité est encore ouverte) n'est PAS un
        // refus. Fenêtre de suppression écoulée (throttle ramené à 0), règle redue : le throttle est REPOSÉ à l'heure
        // du tour, `last_fired` est écrit, rien n'est abandonné.
        let (_t, p) = aeae_base_regle("adv-dedup", &["9.9.9.9"]);
        let (_, alertes, throttles, _) = aeae_tour_regle(&p);
        assert_eq!((alertes, throttles), (1, 1), "fixture : premier tir, alerte et throttle posés");
        aeae_ecrire(&p, "UPDATE rule SET last_run=NULL, last_fired=NULL; UPDATE alert_throttle SET last_fire=0;");
        let avant = now();
        let (bilan, alertes, _, last_fired) = aeae_tour_regle(&p);
        let c = open_db(&p).unwrap();
        let statut: String = c.query_row("SELECT status FROM alert", [], |r| r.get(0)).unwrap();
        let last_fire: i64 = c.query_row("SELECT last_fire FROM alert_throttle", [], |r| r.get(0)).unwrap();
        assert_eq!((alertes, statut.as_str()), (1, "new"), "fixture : la même alerte, encore ouverte, la dédup écarte la nouvelle");
        assert_eq!(bilan, Mesure::Lue(0), "dédup d'une alerte ouverte : entrée, pas un abandon");
        assert!(last_fire >= avant, "dédup d'une alerte ouverte : le throttle est reposé à l'heure du tour (lu {last_fire}, tour à {avant})");
        assert!(last_fired.is_some(), "dédup d'une alerte ouverte : last_fired est écrit");
    }

    // ---------------------------------------------------------------- ligne de base (alerte d'anomalie)

    /// Heure FIXE des ticks de ligne de base : 1800 s après le début d'une heure, loin de toute frontière de bucket
    /// pour `T0` comme pour `T0 + REPRISE_LIGNE_DE_BASE_S`. Aucun témoin ne lit l'horloge.
    const AEAE_T0: i64 = 488_889 * 3600 + 1800;
    const AEAE_BUCKET_S: i64 = 3600;
    const AEAE_CLOS: i64 = AEAE_T0 / AEAE_BUCKET_S - 1;

    /// Une ligne de base due (interval_s = bucket_s = 3600, le défaut), dix observations basses pour `h1`, un pic de
    /// soixante événements dans le bucket clos à `AEAE_T0`. Rend (tmp, chemin).
    fn aeae_base_ligne(tag: &str) -> (crate::tmp_possede::TmpPossede, String) {
        aeae_base_ligne_hotes(tag, &["h1"])
    }

    /// Comme `aeae_base_ligne`, avec le même historique bas et le même pic pour chaque hôte de `hotes`.
    fn aeae_base_ligne_hotes(tag: &str, hotes: &[&str]) -> (crate::tmp_possede::TmpPossede, String) {
        assert!(AEAE_T0 % AEAE_BUCKET_S + REPRISE_LIGNE_DE_BASE_S < AEAE_BUCKET_S, "fixture : T0 + reprise reste dans la même heure");
        let tmp = crate::tmp_possede::TmpPossede::neuf(&format!("aeae-{tag}"));
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let bstart = AEAE_CLOS * AEAE_BUCKET_S;
        {
            let w = Connection::open(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&w), "fixture : la chaîne de migrations doit aller au bout");
            w.execute(
                "INSERT INTO ueba_baseline(name,enabled,query,is_soql,entity_type,entity_field,value_field,bucket_s,min_samples,z_threshold,window_s,interval_s,severity,mitre,risk_score,managed) \
                 VALUES('volume auth par hôte',1,'search source=auth | stats count by host',1,'host','host','',3600,5,3.0,604800,3600,3,'T1110',0,2)",
                [],
            ).unwrap();
            let bid: i64 = w.query_row("SELECT id FROM ueba_baseline", [], |r| r.get(0)).unwrap();
            for h in hotes {
                for (k, v) in [4.0, 5.0, 6.0, 5.0, 4.0, 6.0, 5.0, 4.0, 6.0, 5.0].iter().enumerate() {
                    w.execute(
                        "INSERT INTO ueba_baseline_obs(baseline_id,entity_type,entity,bucket,value,env_id) VALUES(?1,'host',?2,?3,?4,'prod')",
                        params![bid, h, AEAE_CLOS - 1 - (k as i64), v],
                    ).unwrap();
                }
                for i in 0..60 {
                    w.execute("INSERT INTO event(ts,source,host,fields,dedup) VALUES(?1,'auth',?2,'{}',?3)", params![bstart + 10, h, format!("p{h}{i}")]).unwrap();
                }
            }
        }
        (tmp, p)
    }

    /// Un tick de `run_baselines` à l'heure FIXÉE `t` puis (bilan, alertes, last_bucket, last_run).
    fn aeae_tick_ligne(p: &str, t: i64) -> (crate::bilan_de_tick::BilanDeTick, i64, Option<i64>, Option<i64>) {
        use crate::handlers::detection_advanced::horloge_fixee_des_lignes_de_base as horloge;
        let db = Arc::new(Mutex::new(open_db(p).unwrap()));
        horloge::fixer(Some(t));
        let bilan = run_baselines(&db, p);
        horloge::fixer(None);
        let c = db.lock();
        let (lb, lr) = c.query_row("SELECT last_bucket, last_run FROM ueba_baseline", [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
        (bilan, c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap(), lb, lr)
    }

    #[test]
    fn p10_20b_ligne_de_base_controle_negatif_anomalie_ecrite_puis_bucket_et_last_run_avances() {
        let (_t, p) = aeae_base_ligne("bl-ok");
        let (bilan, alertes, last_bucket, last_run) = aeae_tick_ligne(&p, AEAE_T0);
        assert_eq!(bilan, Mesure::Lue(0));
        assert_eq!(alertes, 1, "nominal : le pic est une anomalie");
        assert_eq!(last_bucket, Some(AEAE_CLOS), "nominal : le bucket clos est marqué traité");
        assert_eq!(last_run, Some(AEAE_T0), "nominal : last_run avancé à l'heure du tick");
        // Seconde moitié : la ligne de base est rendue DUE (`last_run` remis à NULL) et l'alerte close, dédup vidée — seul
        // `last_bucket` peut encore empêcher la réémission. Le bucket clos est le même : il n'est pas retraité, et
        // `last_run` avance quand même (ligne de base due dont le bucket est déjà traité).
        aeae_ecrire(&p, "UPDATE ueba_baseline SET last_run=NULL; UPDATE alert SET status='resolved', dedup=NULL;");
        let (bilan, alertes, last_bucket, last_run) = aeae_tick_ligne(&p, AEAE_T0 + REPRISE_LIGNE_DE_BASE_S);
        assert_eq!(bilan, Mesure::Lue(0));
        assert_eq!(alertes, 1, "nominal : bucket déjà traité, ligne de base redue, dédup vidée : aucune réémission");
        assert_eq!(last_bucket, Some(AEAE_CLOS), "nominal : le bucket traité reste le même");
        assert_eq!(last_run, Some(AEAE_T0 + REPRISE_LIGNE_DE_BASE_S), "nominal : ligne de base due, last_run avancé");
    }

    #[test]
    fn p10_20b_ligne_de_base_alerte_refusee_bucket_inchange_reprise_bornee_puis_anomalie_reemise() {
        let (_t, p) = aeae_base_ligne("bl-refus");
        aeae_ecrire(&p, AEAE_REFUS);
        let (bilan, alertes, last_bucket, last_run) = aeae_tick_ligne(&p, AEAE_T0);
        assert_eq!(alertes, 0, "fixture : le trigger a bien refusé l'alerte d'anomalie");
        assert_eq!(last_bucket, None, "alerte NON écrite : `last_bucket` N'AVANCE PAS");
        assert_eq!(
            last_run,
            Some(AEAE_T0 - (3600 - REPRISE_LIGNE_DE_BASE_S)),
            "alerte NON écrite : `last_run` posé au pas de reprise (ni avancé d'un intervalle entier, ni laissé tel quel)"
        );
        assert_eq!(bilan, Mesure::Lue(1), "alerte NON écrite : l'abandon est COMPTÉ dans le bilan du tick");
        aeae_ecrire(&p, "DROP TRIGGER aeae_refus;");
        // Le tour de détection d'après (20 s) : PAS encore due — la requête n'est pas relancée à chaque tour.
        let (bilan, alertes, last_bucket, _) = aeae_tick_ligne(&p, AEAE_T0 + 20);
        assert_eq!((alertes, last_bucket), (0, None), "avant le pas de reprise : la ligne de base n'est pas réévaluée");
        assert_eq!(bilan, Mesure::Lue(0));
        // Au pas de reprise — SANS remise à zéro de last_run par la fixture — l'anomalie du MÊME bucket est réémise.
        let (bilan, alertes, last_bucket, last_run) = aeae_tick_ligne(&p, AEAE_T0 + REPRISE_LIGNE_DE_BASE_S);
        assert_eq!(alertes, 1, "au pas de reprise : l'anomalie du MÊME bucket est réémise");
        assert_eq!(last_bucket, Some(AEAE_CLOS), "puis le bucket est marqué traité");
        assert_eq!(last_run, Some(AEAE_T0 + REPRISE_LIGNE_DE_BASE_S));
        assert_eq!(bilan, Mesure::Lue(0));
        let dedup: String = open_db(&p).unwrap().query_row("SELECT dedup FROM alert", [], |r| r.get(0)).unwrap();
        assert_eq!(dedup, format!("baseline-1-h1-{AEAE_CLOS}"), "c'est l'anomalie du bucket raté, pas d'un autre");
    }

    #[test]
    fn p10_20b_ligne_de_base_alerte_refusee_intervalle_court_reprise_bornee_par_l_intervalle() {
        // interval_s (60) plus court que le pas de reprise : la ligne de base redevient due après interval_s, pas
        // plus tard — `last_run` vaut l'heure du tick, jamais une heure future.
        let (_t, p) = aeae_base_ligne("bl-court");
        aeae_ecrire(&p, &format!("{AEAE_REFUS} UPDATE ueba_baseline SET interval_s=60;"));
        let (bilan, alertes, last_bucket, last_run) = aeae_tick_ligne(&p, AEAE_T0);
        assert_eq!((alertes, last_bucket), (0, None));
        assert_eq!(last_run, Some(AEAE_T0), "reprise bornée par interval_s : last_run = heure du tick");
        assert_eq!(bilan, Mesure::Lue(1));
        aeae_ecrire(&p, "DROP TRIGGER aeae_refus;");
        let (_, alertes, last_bucket, _) = aeae_tick_ligne(&p, AEAE_T0 + 60);
        assert_eq!((alertes, last_bucket), (1, Some(AEAE_CLOS)), "due après interval_s : l'anomalie est réémise");
    }

    #[test]
    fn p10_20b_ligne_de_base_refus_partiel_puis_reprise_la_dedup_vaut_entree_et_le_bucket_est_marque() {
        // Deux entités anomalies au même bucket, le moteur refuse la seule alerte de `h2`. À la reprise, l'alerte de
        // `h1` (entrée au premier passage) est écartée par la dédup (`Ok(0)`) : c'est une ENTRÉE, pas un refus. La
        // ligne de base n'est donc plus en échec : le bucket est marqué, `last_run` avancé, rien d'abandonné.
        let (_t, p) = aeae_base_ligne_hotes("bl-partiel", &["h1", "h2"]);
        aeae_ecrire(&p, "CREATE TRIGGER aeae_refus BEFORE INSERT ON alert WHEN NEW.dedup LIKE 'baseline-%-h2-%' BEGIN SELECT RAISE(ABORT, 'alerte refusée par le témoin'); END;");
        let (bilan, alertes, last_bucket, last_run) = aeae_tick_ligne(&p, AEAE_T0);
        assert_eq!(alertes, 1, "fixture : l'anomalie de h1 entre, celle de h2 est refusée");
        assert_eq!(last_bucket, None, "refus partiel : le bucket n'est pas marqué traité");
        assert_eq!(last_run, Some(AEAE_T0 - (3600 - REPRISE_LIGNE_DE_BASE_S)), "refus partiel : last_run au pas de reprise");
        assert_eq!(bilan, Mesure::Lue(1), "refus partiel : un abandon");
        aeae_ecrire(&p, "DROP TRIGGER aeae_refus;");
        let (bilan, alertes, last_bucket, last_run) = aeae_tick_ligne(&p, AEAE_T0 + REPRISE_LIGNE_DE_BASE_S);
        let dedups: Vec<String> = open_db(&p).unwrap().prepare("SELECT dedup FROM alert ORDER BY dedup").unwrap()
            .query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
        assert_eq!(
            dedups,
            vec![format!("baseline-1-h1-{AEAE_CLOS}"), format!("baseline-1-h2-{AEAE_CLOS}")],
            "reprise : h2 entre, h1 n'est pas doublée (la dédup l'écarte)"
        );
        assert_eq!(alertes, 2);
        assert_eq!(bilan, Mesure::Lue(0), "reprise : l'alerte de h1 écartée par la dédup vaut entrée, rien d'abandonné");
        assert_eq!(last_bucket, Some(AEAE_CLOS), "reprise : le bucket est marqué traité");
        assert_eq!(last_run, Some(AEAE_T0 + REPRISE_LIGNE_DE_BASE_S), "reprise : last_run avancé à l'heure du tick");
    }
}

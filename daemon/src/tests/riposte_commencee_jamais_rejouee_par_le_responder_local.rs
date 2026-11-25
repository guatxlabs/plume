// `P10.21-n` — LE RESPONDER LOCAL DU DÉMON NE REJOUE PAS UNE RIPOSTE COMMENCÉE.
//
// CE QUI SE PASSAIT. `respond_run` n'écrivait RIEN avant d'exécuter : la ligne restait `approved` jusqu'à la
// clôture. Un processus arrêté entre la commande et la clôture, ou une clôture refusée par la base, laissait
// donc la riposte telle quelle, et le passage suivant du minuteur la ré-exécutait. Une seconde exécution n'est
// pas sans effet sur le vocabulaire fermé : `cscli decisions add` pose une seconde décision, une levée
// (fail2ban, nft) d'une adresse déjà levée rend `failed` au lieu de `done`, `kill -TERM` vise un PID qui a pu
// être repris par un autre processus. Et le responder ne réclamait pas : un agent du même hôte pouvait prendre
// la même riposte pendant qu'il l'exécutait, et il reprenait lui-même une riposte dont la réclamation d'agent
// avait passé la fenêtre.
//
// CE QUI EST TENU ICI, par sous-processus qui jouent `respond_run` avec un faux `cscli` en tête de PATH :
//   (1) une exécution interrompue (le faux `cscli` tue le responder) laisse l'intention écrite ; le passage
//       suivant, dans la fenêtre, ne fait rien et ne dit rien ; passé la fenêtre, il ne rejoue pas et le dit,
//       ligne ENTIÈRE ; un agent ne la réclame pas non plus ;
//   (2) une intention refusée par la base (déclencheur ABORT sur la PREMIÈRE riposte) : rien n'est exécuté
//       pour elle, la suivante l'est, la ligne de journal est entière ; le déclencheur retiré, le passage
//       suivant l'exécute ;
//   (3) une intention sans effet (déclencheur IGNORE) : rien n'est exécuté pour elle, la suivante l'est ;
//   (4) deux réclamations de la même action, sur deux connexions entrelacées : deux responders, puis un agent
//       et un responder dans les deux ordres — une seule exécution possible ; une riposte annulée ou
//       réattribuée à un autre hôte entre la lecture et l'intention ne la prend pas ;
//   (5) une riposte réclamée par l'agent du même hôte, réclamation périmée : non exécutée ici, dite ;
//   (6) un verdict refusé après l'exécution : la riposte n'est pas rejouée passé la fenêtre, elle est dite.
// Aucune ligne du journal ne porte la cible : chaque témoin à sous-processus le vérifie, cible présente.
//
// MUTANTS (interrupteurs temporaires `VERIF_MUT`, retirés avant le commit), chacun vu rouge :
//   RCL_M_SANS_INTENTION (l'intention n'est pas écrite, rendue `Ecrite`) -> (1), (2), (3), (4), (6) ;
//   RCL_M_COMMENCEE_EXECUTEE (le bras `commencee_ici` passe) -> (1), (6) ;
//   RCL_M_COMMENCEE_MUETTE (le bras `commencee_ici` ne dit rien) -> (1), (6) ;
//   RCL_M_RECLAMEE_EXECUTEE (le bras `reclamee` passe) -> (5) ;
//   RCL_M_RECLAMEE_BREAK (le bras `reclamee` arrête le tour) -> (5) ;
//   RCL_M_NON_ECRITE_EXECUTE (une intention refusée laisse exécuter) -> (2) ;
//   RCL_M_NON_ECRITE_BREAK (une intention refusée arrête le tour) -> (2) ;
//   RCL_M_NON_PRISE_EXECUTE (une intention sans effet laisse exécuter) -> (3) ;
//   RCL_M_INTENTION_SANS_LIBRE (l'intention n'exige plus une ligne non réclamée) -> (4) ;
//   RCL_M_INTENTION_SANS_STATUT (l'intention n'exige plus une ligne approuvée) -> (4) ;
//   RCL_M_INTENTION_SANS_HOTE (l'intention ne rejoue plus la clause d'hôte) -> (4) ;
//   RCL_M_AGENT_SANS_MARQUEUR (la condition d'agent ne lit plus l'intention) -> (1), (4) ;
//   RCL_M_SELECT_SANS_COMMENCEE (la lecture ne rend plus `commencee_ici`) -> (1), (6) ;
//   RCL_M_SELECT_SANS_RECLAMEE (la lecture ne rend plus `reclamee`) -> (5).
// Les bras `commencee_ici` et `reclamee` levés, l'intention refuse encore la ligne (elle exige une ligne que
// personne n'a réclamée) : la riposte n'est pas exécutée, mais elle est dite sous une autre phrase — c'est la
// ligne de journal, comparée entière, qui rougit sous ces mutants.
mod riposte_commencee_jamais_rejouee_par_le_responder_local {
    use super::*;
    use crate::handlers::actions::{
        ecrire_l_intention_du_responder, remettre_les_actions_lues, FormeDeLaFileDActions, IntentionDuResponder,
        ACTIONS_A_RECLAMER_ICI, RECLAMATION_PERIMEE_S,
    };

    /// La mention d'intention, recopiée : le témoin ne relit pas la constante du code pour la juger.
    const RCL_INTENTION: &str = "[responder local] EXÉCUTION COMMENCÉE, verdict pas encore posé. Si cette mention reste, son exécution a été interrompue : elle ne sera PAS rejouée, à trancher (annuler la riposte, ou la recréer).";
    const RCL_COMMENCEE: &str = "son exécution a été commencée par un passage du responder local (intention écrite) et aucun verdict n'a été posé dans le délai de réclamation : elle a pu avoir lieu. Elle n'est PAS rejouée ; à trancher par l'exploitant (annuler la riposte, ou la recréer).";
    const RCL_AGENT: &str = "elle a été réclamée par un agent dont le verdict n'est pas venu dans le délai de réclamation : elle a pu être exécutée. Elle n'est PAS exécutée ici ; elle reste réclamable par l'agent.";
    const RCL_NON_PRISE: &str = "l'intention d'exécution n'a pris aucune ligne (réclamée, close ou annulée entre la lecture et l'intention, ou écriture sans effet) : rien n'est exécuté.";
    const RCL_NON_ECRITE: &str = "INTENTION NON ÉCRITE : la trace qui précède l'exécution n'a pas pu être écrite, donc la riposte n'est PAS exécutée (exécutée sans trace, une interruption la ferait rejouer) ; elle reste approuvée et un passage suivant la relit.";
    const RCL_VERDICT_NON_ECRIT: &str = "VERDICT NON ÉCRIT : la clôture de l'action n'a pas pu être écrite. L'effet système a bien eu lieu, mais la file la porte TOUJOURS comme approuvée et aucun miroir de blocage n'a été synchronisé sur ce tour. Ce n'est PAS « un verdict plus informé était déjà posé » : personne n'a tranché, la base n'a rien pris.";
    const RCL_HOTE: &str = "hote-rcl";
    const ENFANT: &str = "RCL_TEMOIN_ENFANT";

    /// Le faux `cscli` : il note chaque appel ; si le fichier `tuer` existe, il le retire et tue le responder qui
    /// l'a lancé (son parent direct) AVANT que celui-ci ne pose son verdict.
    const RCL_FAUX_CSCLI: &str = "#!/bin/sh\nprintf '%s ' \"$@\" >> \"$RCL_BAC/appels\"\necho >> \"$RCL_BAC/appels\"\nif [ -f \"$RCL_BAC/tuer\" ]; then rm -f \"$RCL_BAC/tuer\"; kill -9 \"$PPID\"; sleep 2; fi\nexit 0\n";

    fn rcl_base(chemin: &str) {
        let conn = open_db(chemin).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        conn.execute_batch("DELETE FROM playbook; DELETE FROM action; DELETE FROM net_ban;").unwrap();
    }

    /// Un bac : faux `cscli` exécutable, base migrée et vidée, PATH qui place le faux en tête.
    fn rcl_bac(tag: &str) -> (crate::tmp_possede::TmpPossede, String, String) {
        let bac = crate::tmp_possede::TmpPossede::neuf(tag);
        let faux = bac.join("cscli");
        std::fs::write(&faux, RCL_FAUX_CSCLI).expect("fixture : faux cscli écrit");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&faux, std::fs::Permissions::from_mode(0o755)).expect("fixture : faux cscli exécutable");
        }
        let base = bac.join("plume.db").to_string_lossy().to_string();
        rcl_base(&base);
        let path = format!("{}:{}", bac.display(), std::env::var("PATH").unwrap_or_default());
        (bac, base, path)
    }

    /// Complète une commande DÉJÀ construite (binaire de test et enfant posés par le test) et la lance.
    fn rcl_lancer(mut cmd: std::process::Command, bac: &crate::tmp_possede::TmpPossede, path: &str) -> std::process::Output {
        cmd.env("PATH", path)
            .env("RCL_BAC", bac.as_os_str())
            .env("PLUME_BAN_BACKEND", "crowdsec")
            .env("PLUME_EXEC_PLATFORM", "linux")
            .env("PLUME_HOST_LABEL", RCL_HOTE)
            .output()
            .expect("ré-exécution du binaire de test")
    }

    fn rcl_inserer(base: &str, cible: &str, host: Option<&str>, claimed_ts: Option<i64>) -> i64 {
        let c = open_db(base).unwrap();
        c.execute(
            "INSERT INTO action(ts,kind,target,status,dry_run,reason,host,claimed_ts) VALUES(1000,'ban_ip',?1,'approved',0,'rcl',?2,?3)",
            params![cible, host, claimed_ts],
        )
        .unwrap();
        c.last_insert_rowid()
    }

    /// (statut, résultat, claimed_ts, done_ts) d'une action.
    fn rcl_ligne(base: &str, id: i64) -> (String, Option<String>, Option<i64>, Option<i64>) {
        open_db(base)
            .unwrap()
            .query_row("SELECT status, result, claimed_ts, done_ts FROM action WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
    }

    fn rcl_appels(bac: &crate::tmp_possede::TmpPossede) -> String {
        std::fs::read_to_string(bac.join("appels")).unwrap_or_default()
    }

    fn rcl_appel(cible: &str) -> String {
        format!("decisions add --ip {cible} --duration 4h --reason plume \n")
    }

    /// (1) EXÉCUTION INTERROMPUE ENTRE L'INTENTION ET LE VERDICT, PUIS REPRISE.
    #[test]
    fn rcl_execution_interrompue_entre_l_intention_et_le_verdict_n_est_pas_rejouee() {
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let nom = "tests::riposte_commencee_jamais_rejouee_par_le_responder_local::rcl_execution_interrompue_entre_l_intention_et_le_verdict_n_est_pas_rejouee";
        let (bac, base, path) = rcl_bac("rcl-interrompue");
        let cible = "203.0.113.71";
        let id = rcl_inserer(&base, cible, None, None);
        std::fs::write(bac.join("tuer"), "").unwrap();

        // Premier passage : le faux `cscli` tue le responder après l'appel, avant le verdict.
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        cmd.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1").env("PLUME_DB", &base);
        let avant = now();
        let premier = rcl_lancer(cmd, &bac, &path);
        let apres = now();
        assert_eq!(premier.status.code(), None, "fixture : le responder est tué par un signal pendant l'exécution");
        assert_eq!(rcl_appels(&bac), rcl_appel(cible), "premier passage : une exécution");
        let (statut, resultat, reclamee, close) = rcl_ligne(&base, id);
        assert_eq!((statut.as_str(), resultat.as_deref(), close), ("approved", Some(RCL_INTENTION), None), "l'intention est écrite AVANT l'exécution, aucun verdict");
        let reclamee = reclamee.expect("l'intention pose claimed_ts");
        assert!((avant..=apres).contains(&reclamee), "claimed_ts est l'instant de l'intention : {reclamee}");

        // Second passage, dans la fenêtre : rien n'est exécuté, rien n'est dit de cette riposte.
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        cmd.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1").env("PLUME_DB", &base);
        let second = rcl_lancer(cmd, &bac, &path);
        let stderr = String::from_utf8_lossy(&second.stderr).into_owned();
        assert_eq!(second.status.code(), Some(0), "second passage : sortie 0\n{stderr}");
        assert_eq!(rcl_appels(&bac), rcl_appel(cible), "second passage : AUCUNE seconde exécution\n{stderr}");
        assert!(!stderr.contains(&format!("action {id} ")), "dans la fenêtre, la riposte n'est pas encore dite : {stderr}");
        assert_eq!(rcl_ligne(&base, id), ("approved".to_string(), Some(RCL_INTENTION.to_string()), Some(reclamee), None), "second passage : ligne intacte");

        // La fenêtre passée (claimed_ts reculé de RECLAMATION_PERIMEE_S + 1).
        let recule = reclamee - RECLAMATION_PERIMEE_S - 1;
        open_db(&base).unwrap().execute("UPDATE action SET claimed_ts=?2 WHERE id=?1", params![id, recule]).unwrap();
        // Un agent de cet hôte ne la réclame pas : la condition d'agent lit l'intention.
        {
            let c = open_db(&base).unwrap();
            let rendu = remettre_les_actions_lues(&c, &[(id, "ban_ip".to_string(), cible.to_string(), false)], RCL_HOTE, now(), FormeDeLaFileDActions::Tsv);
            assert_eq!(rendu, Ok(String::new()), "un agent ne reçoit pas une riposte commencée par le responder local");
        }
        assert_eq!(rcl_ligne(&base, id).2, Some(recule), "ni réclamée ni réattribuée par l'agent");

        // Troisième passage, fenêtre passée : non rejouée, dite, ligne entière, sans la cible.
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        cmd.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1").env("PLUME_DB", &base);
        let troisieme = rcl_lancer(cmd, &bac, &path);
        let stderr = String::from_utf8_lossy(&troisieme.stderr).into_owned();
        assert_eq!(troisieme.status.code(), Some(0), "troisième passage : sortie 0\n{stderr}");
        assert_eq!(rcl_appels(&bac), rcl_appel(cible), "troisième passage : AUCUNE seconde exécution\n{stderr}");
        let attendue = format!("[responder] WARN action {id} NON rejouée : {RCL_COMMENCEE}");
        assert_eq!(stderr.lines().filter(|l| *l == attendue).count(), 1, "le journal porte « {attendue} » : {stderr}");
        assert!(!stderr.contains(cible), "aucune ligne du journal ne porte la cible : {stderr}");
        assert_eq!(rcl_ligne(&base, id), ("approved".to_string(), Some(RCL_INTENTION.to_string()), Some(recule), None), "l'état de l'action dit toujours l'intention");
    }

    /// (2) ÉCRITURE DE L'INTENTION REFUSÉE (déclencheur ABORT sur la première riposte).
    #[test]
    fn rcl_intention_refusee_rien_n_est_execute_et_le_passage_suivant_la_relit() {
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let nom = "tests::riposte_commencee_jamais_rejouee_par_le_responder_local::rcl_intention_refusee_rien_n_est_execute_et_le_passage_suivant_la_relit";
        let (bac, base, path) = rcl_bac("rcl-refusee");
        let (premiere, suivante) = ("203.0.113.72", "203.0.113.73");
        let a = rcl_inserer(&base, premiere, None, None);
        let b = rcl_inserer(&base, suivante, None, None);
        assert!(a < b, "fixture : la riposte refusée passe la première");
        open_db(&base)
            .unwrap()
            .execute_batch(&format!(
                "CREATE TRIGGER rcl_refus BEFORE UPDATE OF claimed_ts ON action WHEN NEW.id = {a} BEGIN SELECT RAISE(ABORT, 'intention refusee par le temoin'); END;"
            ))
            .unwrap();
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        cmd.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1").env("PLUME_DB", &base);
        let premier = rcl_lancer(cmd, &bac, &path);
        let stderr = String::from_utf8_lossy(&premier.stderr).into_owned();
        assert_eq!(premier.status.code(), Some(0), "sortie 0\n{stderr}");
        assert_eq!(rcl_appels(&bac), rcl_appel(suivante), "seule la suivante est exécutée\n{stderr}");
        let attendue = format!("[responder] WARN action {a} NON exécutée ce tour-ci : {RCL_NON_ECRITE} (intention refusee par le temoin)");
        assert_eq!(stderr.lines().filter(|l| *l == attendue).count(), 1, "le journal porte « {attendue} » : {stderr}");
        assert!(!stderr.contains(premiere) && !stderr.contains(suivante), "aucune ligne du journal ne porte une cible : {stderr}");
        assert_eq!(rcl_ligne(&base, a), ("approved".to_string(), None, None, None), "refusée : ni intention, ni verdict");
        assert_eq!(rcl_ligne(&base, b).0, "done", "la suivante est exécutée et close");

        open_db(&base).unwrap().execute_batch("DROP TRIGGER rcl_refus;").unwrap();
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        cmd.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1").env("PLUME_DB", &base);
        let second = rcl_lancer(cmd, &bac, &path);
        let stderr = String::from_utf8_lossy(&second.stderr).into_owned();
        assert_eq!(second.status.code(), Some(0), "second passage : sortie 0\n{stderr}");
        assert_eq!(rcl_appels(&bac), format!("{}{}", rcl_appel(suivante), rcl_appel(premiere)), "le passage suivant l'exécute, une fois\n{stderr}");
        assert_eq!(rcl_ligne(&base, a).0, "done", "le passage suivant la clôt");
    }

    /// (3) INTENTION SANS EFFET (déclencheur IGNORE sur la première riposte : zéro ligne prise).
    #[test]
    fn rcl_intention_sans_effet_rien_n_est_execute() {
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let nom = "tests::riposte_commencee_jamais_rejouee_par_le_responder_local::rcl_intention_sans_effet_rien_n_est_execute";
        let (bac, base, path) = rcl_bac("rcl-sans-effet");
        let (premiere, suivante) = ("203.0.113.74", "203.0.113.75");
        let a = rcl_inserer(&base, premiere, None, None);
        let b = rcl_inserer(&base, suivante, None, None);
        assert!(a < b, "fixture : la riposte sans effet passe la première");
        open_db(&base)
            .unwrap()
            .execute_batch(&format!("CREATE TRIGGER rcl_ignore BEFORE UPDATE OF claimed_ts ON action WHEN NEW.id = {a} BEGIN SELECT RAISE(IGNORE); END;"))
            .unwrap();
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        cmd.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1").env("PLUME_DB", &base);
        let sortie = rcl_lancer(cmd, &bac, &path);
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "sortie 0\n{stderr}");
        assert_eq!(rcl_appels(&bac), rcl_appel(suivante), "seule la suivante est exécutée\n{stderr}");
        let attendue = format!("[responder] action {a} NON exécutée ce tour-ci : {RCL_NON_PRISE}");
        assert_eq!(stderr.lines().filter(|l| *l == attendue).count(), 1, "le journal porte « {attendue} » : {stderr}");
        assert!(!stderr.contains(premiere), "aucune ligne du journal ne porte la cible : {stderr}");
        assert_eq!(rcl_ligne(&base, a), ("approved".to_string(), None, None, None), "sans effet : ni intention, ni verdict");
        assert_eq!(rcl_ligne(&base, b).0, "done");
    }

    /// (4) DEUX RÉCLAMATIONS DE LA MÊME ACTION, sur deux connexions entrelacées après une même lecture.
    #[test]
    fn rcl_deux_reclamations_de_la_meme_action_une_seule_execution() {
        let bac = crate::tmp_possede::TmpPossede::neuf("rcl-deux");
        let base = bac.join("plume.db").to_string_lossy().to_string();
        rcl_base(&base);
        let t = 1_700_000_000i64;
        let lire = |c: &Connection, maintenant: i64| -> Vec<(i64, bool, bool)> {
            let mut s = c.prepare(ACTIONS_A_RECLAMER_ICI).unwrap();
            s.query_map(params![RCL_HOTE, 1i64, maintenant, RECLAMATION_PERIMEE_S], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, bool>(4)?, r.get::<_, bool>(5)?)))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let un = open_db(&base).unwrap();
        let deux = open_db(&base).unwrap();

        // Deux passages du responder local lisent la même action libre ; le premier écrit, le second perd.
        let x = rcl_inserer(&base, "203.0.113.76", None, None);
        assert_eq!(lire(&un, t), vec![(x, false, false)]);
        assert_eq!(lire(&deux, t), vec![(x, false, false)]);
        assert_eq!(ecrire_l_intention_du_responder(&un, x, RCL_HOTE, true, t), IntentionDuResponder::Ecrite);
        assert_eq!(ecrire_l_intention_du_responder(&deux, x, RCL_HOTE, true, t + 1), IntentionDuResponder::NonPrise, "le second passage ne prend pas l'action");
        assert_eq!(rcl_ligne(&base, x), ("approved".to_string(), Some(RCL_INTENTION.to_string()), Some(t), None), "l'intention du premier, intacte");
        // L'action commencée ne repart à personne, même la fenêtre passée.
        let rendu = remettre_les_actions_lues(&deux, &[(x, "ban_ip".to_string(), "203.0.113.76".to_string(), false)], RCL_HOTE, t + RECLAMATION_PERIMEE_S + 1, FormeDeLaFileDActions::Tsv);
        assert_eq!(rendu, Ok(String::new()), "un agent ne la reçoit pas, fenêtre passée");
        assert_eq!(lire(&un, t + RECLAMATION_PERIMEE_S + 1), vec![(x, true, true)], "relue commencée ici, fenêtre passée");
        un.execute("UPDATE action SET status='cancelled' WHERE id=?1", params![x]).unwrap();

        // Le responder lit l'action libre, un agent la réclame avant l'intention : l'intention perd.
        let y = rcl_inserer(&base, "203.0.113.77", None, None);
        assert_eq!(lire(&un, t), vec![(y, false, false)]);
        let rendu = remettre_les_actions_lues(&deux, &[(y, "ban_ip".to_string(), "203.0.113.77".to_string(), false)], RCL_HOTE, t, FormeDeLaFileDActions::Tsv);
        assert_eq!(rendu, Ok(format!("{y}\tban_ip\t203.0.113.77\t0\n")), "l'agent la réclame");
        assert_eq!(ecrire_l_intention_du_responder(&un, y, RCL_HOTE, true, t), IntentionDuResponder::NonPrise, "l'agent l'a prise : le responder n'écrit pas son intention");
        assert_eq!(rcl_ligne(&base, y), ("approved".to_string(), None, Some(t), None), "la réclamation de l'agent, intacte");
        // Fenêtre passée, le responder la relit réclamée par un agent, pas commencée ici ; il ne peut pas la prendre.
        assert_eq!(lire(&un, t + RECLAMATION_PERIMEE_S + 1), vec![(y, true, false)]);
        assert_eq!(ecrire_l_intention_du_responder(&un, y, RCL_HOTE, true, t + RECLAMATION_PERIMEE_S + 1), IntentionDuResponder::NonPrise, "une réclamation périmée reste une riposte remise");
        un.execute("UPDATE action SET status='cancelled' WHERE id=?1", params![y]).unwrap();

        // Annulée par un analyste entre la lecture et l'intention : l'intention ne la prend pas.
        let w = rcl_inserer(&base, "203.0.113.81", None, None);
        assert_eq!(lire(&un, t), vec![(w, false, false)]);
        deux.execute("UPDATE action SET status='cancelled' WHERE id=?1", params![w]).unwrap();
        assert_eq!(ecrire_l_intention_du_responder(&un, w, RCL_HOTE, true, t), IntentionDuResponder::NonPrise, "une riposte annulée ne prend pas l'intention");
        assert_eq!(rcl_ligne(&base, w), ("cancelled".to_string(), None, None, None));

        // Réattribuée à un autre hôte entre la lecture et l'intention : l'intention ne la prend pas.
        let v = rcl_inserer(&base, "203.0.113.82", None, None);
        assert_eq!(lire(&un, t), vec![(v, false, false)]);
        deux.execute("UPDATE action SET host='autre-hote' WHERE id=?1", params![v]).unwrap();
        assert_eq!(ecrire_l_intention_du_responder(&un, v, RCL_HOTE, true, t), IntentionDuResponder::NonPrise, "une riposte d'un autre hôte ne prend pas l'intention");
        assert_eq!(rcl_ligne(&base, v), ("approved".to_string(), None, None, None));
        // Contrôle positif : la même riposte rendue à cet hôte prend l'intention.
        deux.execute("UPDATE action SET host=?2 WHERE id=?1", params![v, RCL_HOTE]).unwrap();
        assert_eq!(ecrire_l_intention_du_responder(&un, v, RCL_HOTE, true, t), IntentionDuResponder::Ecrite);
    }

    /// (5) UNE RIPOSTE RÉCLAMÉE PAR L'AGENT DU MÊME HÔTE, RÉCLAMATION PÉRIMÉE : non exécutée ici, dite.
    #[test]
    fn rcl_riposte_reclamee_par_un_agent_n_est_pas_executee_ici() {
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let nom = "tests::riposte_commencee_jamais_rejouee_par_le_responder_local::rcl_riposte_reclamee_par_un_agent_n_est_pas_executee_ici";
        let (bac, base, path) = rcl_bac("rcl-agent");
        let (reclamee, suivante) = ("203.0.113.78", "203.0.113.79");
        let perimee = now() - RECLAMATION_PERIMEE_S - 60;
        let a = rcl_inserer(&base, reclamee, Some(RCL_HOTE), Some(perimee));
        let b = rcl_inserer(&base, suivante, None, None);
        assert!(a < b, "fixture : la riposte réclamée passe la première");
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        cmd.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1").env("PLUME_DB", &base);
        let sortie = rcl_lancer(cmd, &bac, &path);
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "sortie 0\n{stderr}");
        assert_eq!(rcl_appels(&bac), rcl_appel(suivante), "la riposte réclamée par l'agent n'est pas exécutée, la suivante l'est\n{stderr}");
        let attendue = format!("[responder] action {a} NON exécutée ici : {RCL_AGENT}");
        assert_eq!(stderr.lines().filter(|l| *l == attendue).count(), 1, "le journal porte « {attendue} » : {stderr}");
        assert!(!stderr.contains(reclamee), "aucune ligne du journal ne porte la cible : {stderr}");
        assert_eq!(rcl_ligne(&base, a), ("approved".to_string(), None, Some(perimee), None), "la riposte de l'agent, intacte");
        assert_eq!(rcl_ligne(&base, b).0, "done");
    }

    /// (6) VERDICT REFUSÉ APRÈS L'EXÉCUTION : la riposte n'est pas rejouée passé la fenêtre, elle est dite.
    #[test]
    fn rcl_verdict_refuse_la_riposte_n_est_pas_rejouee() {
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let nom = "tests::riposte_commencee_jamais_rejouee_par_le_responder_local::rcl_verdict_refuse_la_riposte_n_est_pas_rejouee";
        let (bac, base, path) = rcl_bac("rcl-verdict");
        let cible = "203.0.113.80";
        let id = rcl_inserer(&base, cible, None, None);
        open_db(&base)
            .unwrap()
            .execute_batch("CREATE TRIGGER rcl_verdict BEFORE UPDATE OF status ON action WHEN NEW.status IN ('done','failed') BEGIN SELECT RAISE(ABORT, 'verdict refuse par le temoin'); END;")
            .unwrap();
        let mut cmd = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        cmd.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1").env("PLUME_DB", &base);
        let premier = rcl_lancer(cmd, &bac, &path);
        let stderr = String::from_utf8_lossy(&premier.stderr).into_owned();
        assert_eq!(premier.status.code(), Some(0), "sortie 0\n{stderr}");
        assert_eq!(rcl_appels(&bac), rcl_appel(cible), "une exécution\n{stderr}");
        let attendue = format!("[responder] action {id} : {RCL_VERDICT_NON_ECRIT} (verdict refuse par le temoin)");
        assert_eq!(stderr.lines().filter(|l| *l == attendue).count(), 1, "le journal porte « {attendue} » : {stderr}");
        let (statut, resultat, reclamee, _) = rcl_ligne(&base, id);
        assert_eq!((statut.as_str(), resultat.as_deref()), ("approved", Some(RCL_INTENTION)), "verdict refusé : la ligne garde l'intention");
        let reclamee = reclamee.expect("intention posée");
        let recule = reclamee - RECLAMATION_PERIMEE_S - 1;
        open_db(&base).unwrap().execute_batch(&format!("DROP TRIGGER rcl_verdict; UPDATE action SET claimed_ts={recule} WHERE id={id};")).unwrap();

        let mut cmd = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        cmd.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1").env("PLUME_DB", &base);
        let second = rcl_lancer(cmd, &bac, &path);
        let stderr = String::from_utf8_lossy(&second.stderr).into_owned();
        assert_eq!(second.status.code(), Some(0), "second passage : sortie 0\n{stderr}");
        assert_eq!(rcl_appels(&bac), rcl_appel(cible), "le passage suivant ne la rejoue PAS\n{stderr}");
        let attendue = format!("[responder] WARN action {id} NON rejouée : {RCL_COMMENCEE}");
        assert_eq!(stderr.lines().filter(|l| *l == attendue).count(), 1, "le journal porte « {attendue} » : {stderr}");
        assert!(!stderr.contains(cible), "aucune ligne du journal ne porte la cible : {stderr}");
        assert_eq!(rcl_ligne(&base, id).0, "approved");
    }
}

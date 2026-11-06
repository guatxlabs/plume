// =====================================================================================
// `P11.25-a` (vague BY) — LA LEVÉE nft DU RESPONDER LOCAL VISE AUSSI LE SET À EXPIRATION DE L'AGENT.
//
// AVANT : sur la voie linux + nft, `unban_ip` ne jouait qu'un argv, `nft delete element inet plume blocklist
// { <ip> }`. L'agent de l'hôte (`collectors/respond.sh`), dans sa version qui applique la durée servie par le
// central, pose chaque ban dans un second set, `inet plume blocklist_ttl` (`flags timeout`) ; une version antérieure
// ne pose que dans `blocklist`. Démon et agent récent sur le même hôte : une levée exécutée par le démon manquait un
// ban posé par l'agent — le ban restait actif jusqu'à son terme, et l'action était notée `failed`. Avec un agent
// antérieur, le set n'existe pas : le second retrait rend l'absence du set et le verdict suit le premier (b).
// APRÈS (`second_retrait_nft`, `classer_le_retrait_nft`, `verdict_des_deux_retraits_nft`, `levee_nft_a_deux_sets`,
// dans `handlers/actions.rs`) : DEUX retraits, `nft delete element inet plume blocklist { <ip> }` puis
// `nft delete element inet plume blocklist_ttl { <ip> }`, argv fixes, chacun sous `LC_ALL=C` et `LANG=C`. Chaque
// retrait a TROIS issues : retirée (code 0), absente (code non nul ET « No such file or directory » sur la sortie
// d'erreur), refus (tout le reste : autre message, message traduit, commande qui ne part pas, signal). `done` SI ET
// SEULEMENT SI aucun refus ET au moins un retrait ; `failed` sinon (deux absences comprises). Le résultat nomme
// l'issue de chaque set, chaque part bornée, le tout sous 500 caractères ; le dry-run affiche les deux commandes.
//
// CE QU'ILS TIENNENT. Les témoins `lnx_*` jouent chacun `respond_run` (le point d'entrée de la sous-commande
// `respond`) dans un sous-processus, avec un faux `nft` en tête de PATH dont les sets sont des fichiers du bac et
// qui écrit chaque appel ; l'enfant reçoit `LC_ALL` et `LANG` en français, et le faux `nft` ne répond en anglais que
// s'il reçoit lui-même `LC_ALL=C` et `LANG=C` :
//   (a) adresse dans `blocklist_ttl` seul, dans `blocklist` seul, dans les deux : `done`, appels et résultats à
//       l'octet ;
//   (b) adresse dans aucun set (deux absences) : `failed` ; set `blocklist_ttl` absent, retrait de `blocklist`
//       réussi : `done` ; set `blocklist_ttl` absent, adresse absente de `blocklist` : `failed` ; dry-run qui
//       affiche les deux commandes sans rien appeler ;
//   (c) refus sur `blocklist` (« Device or resource busy ») et retrait de `blocklist_ttl` : `failed` ; retrait de
//       `blocklist` et refus sur `blocklist_ttl` : `failed` ; `nft` tué par un signal après avoir écrit le message
//       d'absence : refus, `failed` ; message d'absence sur la SORTIE STANDARD et « Device or resource busy » sur la
//       sortie d'erreur : refus, `failed` (l'absence ne se lit que sur la sortie d'erreur) ;
//   (d) `nft` absent du PATH : les deux retraits sont des refus (`exec: …`), `failed` ; la pose nft sans `nft` et
//       la levée CrowdSec sans `cscli` : `failed`, `exec: …` ; la levée CrowdSec, faux `nft` présent, n'appelle
//       aucun `nft` ;
//   (e) message localisé ignoré : un faux `nft` qui répond en français « Aucun fichier ou dossier de ce type » est
//       un refus, même sous `LC_ALL=C` ;
//   (f) `ban_ip` nft : UN argv `add element inet plume blocklist`, aucun retrait de `blocklist_ttl`, résultat et
//       dry-run à l'octet d'avant ;
//   (g) `unban_ip` CrowdSec, fail2ban et gabarit pfsense : aucun appel nft, commande et résultat à l'octet d'avant ;
//   (h) sorties longues : sur la voie à un argv, coupée à 500 caractères exactement ; sur la levée à deux sets,
//       chaque part coupée à sa borne, le second set jamais masqué par le premier.
// Les témoins `unite_*` jouent les deux fonctions pures, cas par cas.
//
// MUTANTS JOUÉS (posés sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : `M1` (refus classé absent),
// `M2` (absence classée retrait), `M3` (verdict « au moins un retrait » sans « aucun refus »), `M4` (`LC_ALL=C`
// retiré), `M5` (second retrait supprimé), `M6` (second retrait étendu à `ban_ip`), `M7` (set `blocklist` au lieu
// de `blocklist_ttl`), `M8` (borne de 500 retirée sur la voie à un argv), `M9` (commande qui ne part pas classée
// par son texte), `M10` (signal classé par le message d'absence), `M11` (parts de la levée à deux sets non bornées),
// `M12` (retrait classé sur la sortie standard ET la sortie d'erreur), `M13` (second retrait étendu à CrowdSec).
//
// CE QU'ILS NE TIENNENT PAS : un vrai `nft` (le faux rend les sorties d'erreur qu'il écrit, pas celles du noyau ; le
// message d'absence reconnu est celui de `strerror(ENOENT)` sous la locale C) ; l'agent lui-même (zone de la
// console). Le démon ne pose jamais dans `blocklist_ttl` (comportement écarté).
// =====================================================================================
mod levee_nft_couvre_le_set_a_expiration_de_l_agent {
    use super::*;
    use crate::handlers::actions::{classer_le_retrait_nft, verdict_des_deux_retraits_nft, IssueDuRetraitNft};

    /// Faux `nft` : un set existe si le fichier `set_<nom>` du bac existe, et contient les adresses qui y sont
    /// écrites, une par ligne. Chaque appel est écrit dans `appels`. Le message d'absence est en anglais SEULEMENT
    /// si l'appel reçoit `LC_ALL=C` et `LANG=C` et que le bac n'a pas de fichier `francais` ; sinon il est traduit.
    /// Un fichier `verrou_<set>_<ip>` fait refuser le retrait de ce set (« Device or resource busy ») ; un fichier
    /// `signal_<set>_<ip>` fait écrire le message d'absence puis se tuer par SIGKILL ; un fichier `stdout_<set>_<ip>`
    /// fait écrire le message d'absence sur la SORTIE STANDARD et refuser (« Device or resource busy ») sur la sortie
    /// d'erreur ; un fichier `bavard_<ip>` fait
    /// précéder l'erreur d'absence d'une longue sortie ; un fichier `refus_<ip>` fait refuser la pose, avec le
    /// contenu du fichier en sortie d'erreur.
    const LNX_FAUX_NFT: &str = r#"#!/bin/sh
printf 'nft %s\n' "$*" >> "$LNX_BAC/appels"
ip=$(printf '%s' "$6" | tr -d '{} ')
if [ "$LC_ALL" = C ] && [ "$LANG" = C ] && [ ! -f "$LNX_BAC/francais" ]; then abs='No such file or directory'; else abs='Aucun fichier ou dossier de ce type'; fi
case "$1 $2" in
  'add element')
    if [ -f "$LNX_BAC/refus_$ip" ]; then cat "$LNX_BAC/refus_$ip" >&2; exit 1; fi
    exit 0 ;;
  'delete element')
    if [ -f "$LNX_BAC/verrou_$5_$ip" ]; then printf 'Error: Could not process rule: Device or resource busy (%s)\n' "$5" >&2; exit 1; fi
    if [ -f "$LNX_BAC/stdout_$5_$ip" ]; then printf '%s (sortie standard)\n' "$abs"; printf 'Error: Could not process rule: Device or resource busy (%s)\n' "$5" >&2; exit 1; fi
    if [ -f "$LNX_BAC/signal_$5_$ip" ]; then printf 'Error: Could not process rule: %s (%s)\n' "$abs" "$5" >&2; kill -9 $$; fi
    if [ ! -f "$LNX_BAC/set_$5" ]; then printf 'Error: %s (set %s)\n' "$abs" "$5" >&2; exit 1; fi
    if grep -qx "$ip" "$LNX_BAC/set_$5"; then exit 0; fi
    if [ -f "$LNX_BAC/bavard_$ip" ]; then printf '%s:' "$5" >&2; cat "$LNX_BAC/bavard_$ip" >&2; fi
    printf 'Error: Could not process rule: %s (%s, %s)\n' "$abs" "$5" "$ip" >&2; exit 1 ;;
esac
exit 0
"#;

    /// Faux `cscli`, `fail2ban-client`, `pfctl` : écrit son nom et ses arguments, réussit sans rien dire.
    const LNX_FAUX_AUTRE: &str = "#!/bin/sh\nprintf '%s %s\\n' \"$(basename \"$0\")\" \"$*\" >> \"$LNX_BAC/appels\"\nexit 0\n";

    /// Les quatre appels d'amorçage (`ensure_nft_blocklist`) qui précèdent toute riposte nft non simulée.
    const LNX_AMORCE: &str = "nft add table inet plume\n\
nft add set inet plume blocklist { type ipv4_addr; }\n\
nft add chain inet plume input { type filter hook input priority -150; policy accept; }\n\
nft add rule inet plume input ip saddr @blocklist drop\n";

    /// Le refus « occupé » du faux `nft`, recopié (sans la parenthèse du set).
    const LNX_OCCUPE: &str = "Error: Could not process rule: Device or resource busy";

    /// L'erreur d'une commande qui ne peut pas partir, telle que le responder l'écrit.
    const LNX_EXEC_ABSENT: &str = "exec: No such file or directory (os error 2)";

    fn lnx_executable(chemin: &std::path::Path, contenu: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(chemin, contenu).expect("fixture : faux binaire écrit");
        std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(0o755)).expect("fixture : faux binaire exécutable");
    }

    /// Le bac : faux `nft`, `cscli`, `fail2ban-client`, `pfctl`, une base migrée et vidée. Rend (bac, base, PATH).
    fn lnx_bac(tag: &str) -> (crate::tmp_possede::TmpPossede, String, String) {
        let bac = crate::tmp_possede::TmpPossede::neuf(tag);
        lnx_executable(&bac.join("nft"), LNX_FAUX_NFT);
        lnx_executable(&bac.join("cscli"), LNX_FAUX_AUTRE);
        lnx_executable(&bac.join("fail2ban-client"), LNX_FAUX_AUTRE);
        lnx_executable(&bac.join("pfctl"), LNX_FAUX_AUTRE);
        let base = bac.join("plume.db").to_string_lossy().to_string();
        let conn = open_db(&base).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        conn.execute_batch("DELETE FROM playbook; DELETE FROM action; DELETE FROM net_ban;").unwrap();
        let path = format!("{}:{}", bac.display(), std::env::var("PATH").unwrap_or_default());
        (bac, base, path)
    }

    /// Pose un set du faux `nft` avec ses adresses (`blocklist` ou `blocklist_ttl`).
    fn lnx_set(bac: &std::path::Path, nom: &str, adresses: &str) {
        std::fs::write(bac.join(format!("set_{nom}")), adresses).expect("fixture : set écrit");
    }

    /// Pose un fichier marqueur du faux `nft` (`verrou_…`, `signal_…`, `bavard_…`, `refus_…`, `francais`).
    fn lnx_marque(bac: &std::path::Path, nom: &str, contenu: &str) {
        std::fs::write(bac.join(nom), contenu).expect("fixture : marqueur écrit");
    }

    fn lnx_action(base: &str, genre: &str, cible: &str, simulee: bool) {
        open_db(base)
            .unwrap()
            .execute(
                "INSERT INTO action(ts,kind,target,status,dry_run,reason) VALUES(1000,?1,?2,'approved',?3,'lnx')",
                params![genre, cible, i64::from(simulee)],
            )
            .unwrap();
    }

    fn lnx_verdict(base: &str, cible: &str) -> (String, String) {
        open_db(base)
            .unwrap()
            .query_row("SELECT status, IFNULL(result,'') FROM action WHERE target=?1", params![cible], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
    }

    fn lnx_appels(bac: &std::path::Path) -> String {
        std::fs::read_to_string(bac.join("appels")).unwrap_or_default()
    }

    /// Complète la commande DÉJÀ CONSTRUITE par le témoin (son binaire et sa variable d'enfant) avec le bac, la base,
    /// le backend, la plateforme et une locale française, la joue, exige le code 0 et rend sa sortie d'erreur.
    fn lnx_jouer(mut commande: std::process::Command, bac: &std::path::Path, base: &str, path: &str, backend: &str, plateforme: &str) -> String {
        let sortie = commande
            .env("PATH", path)
            .env("LNX_BAC", bac.as_os_str())
            .env("PLUME_DB", base)
            .env("PLUME_BAN_BACKEND", backend)
            .env("PLUME_FAIL2BAN_JAIL", "sshd")
            .env("PLUME_EXEC_PLATFORM", plateforme)
            .env("LC_ALL", "fr_FR.UTF-8")
            .env("LANG", "fr_FR.UTF-8")
            .output()
            .expect("tour du responder");
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "{backend}/{plateforme} : sortie 0\n{stderr}");
        stderr
    }

    /// (a) CE QU'IL TIENT : `blocklist_ttl` existe. Une adresse dans `blocklist_ttl` SEUL se lève (absente de
    /// `blocklist`, retirée de `blocklist_ttl` : `done`) ; une adresse dans `blocklist` seul aussi (retirée,
    /// absente) ; une adresse dans les deux aussi (retirée, retirée). Deux retraits par riposte, appels à l'octet ;
    /// résultats ENTIERS comparés. L'enfant porte une locale française : le message d'absence n'est reconnu que
    /// parce que chaque retrait reçoit `LC_ALL=C` et `LANG=C`. MUTATIONS : `M2`, `M4`, `M5`, `M7`.
    #[test]
    fn lnx_a_l_adresse_dans_un_set_ou_les_deux_est_levee_et_le_verdict_est_done() {
        const ENFANT: &str = "LNX_TEMOIN_ENFANT";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let (bac, base, path) = lnx_bac("lnx-a");
        lnx_set(&bac, "blocklist", "203.0.113.82\n203.0.113.80\n");
        lnx_set(&bac, "blocklist_ttl", "203.0.113.81\n203.0.113.80\n");
        lnx_action(&base, "unban_ip", "203.0.113.81", false);
        lnx_action(&base, "unban_ip", "203.0.113.82", false);
        lnx_action(&base, "unban_ip", "203.0.113.80", false);
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::levee_nft_couvre_le_set_a_expiration_de_l_agent::lnx_a_l_adresse_dans_un_set_ou_les_deux_est_levee_et_le_verdict_est_done"])
            .env(ENFANT, "1");
        let stderr = lnx_jouer(commande, &bac, &base, &path, "nft", "linux");
        assert_eq!(
            lnx_appels(&bac),
            format!(
                "{LNX_AMORCE}\
nft delete element inet plume blocklist {{ 203.0.113.81 }}\n\
nft delete element inet plume blocklist_ttl {{ 203.0.113.81 }}\n\
nft delete element inet plume blocklist {{ 203.0.113.82 }}\n\
nft delete element inet plume blocklist_ttl {{ 203.0.113.82 }}\n\
nft delete element inet plume blocklist {{ 203.0.113.80 }}\n\
nft delete element inet plume blocklist_ttl {{ 203.0.113.80 }}\n"
            ),
            "deux retraits par levée, blocklist puis blocklist_ttl\n{stderr}"
        );
        assert_eq!(
            lnx_verdict(&base, "203.0.113.81"),
            (
                "done".to_string(),
                "blocklist : absente (Error: Could not process rule: No such file or directory (blocklist, 203.0.113.81)) | blocklist_ttl : retirée (nft delete element inet plume blocklist_ttl { 203.0.113.81 } -> exit status: 0)".to_string()
            ),
            "adresse dans blocklist_ttl seul\n{stderr}"
        );
        assert_eq!(
            lnx_verdict(&base, "203.0.113.82"),
            (
                "done".to_string(),
                "blocklist : retirée (nft delete element inet plume blocklist { 203.0.113.82 } -> exit status: 0) | blocklist_ttl : absente (Error: Could not process rule: No such file or directory (blocklist_ttl, 203.0.113.82))".to_string()
            ),
            "adresse dans blocklist seul\n{stderr}"
        );
        assert_eq!(
            lnx_verdict(&base, "203.0.113.80"),
            (
                "done".to_string(),
                "blocklist : retirée (nft delete element inet plume blocklist { 203.0.113.80 } -> exit status: 0) | blocklist_ttl : retirée (nft delete element inet plume blocklist_ttl { 203.0.113.80 } -> exit status: 0)".to_string()
            ),
            "adresse dans les deux sets\n{stderr}"
        );
    }

    /// (b) CE QU'IL TIENT : rien n'est levé, rien n'est `done`. `blocklist_ttl` existe et l'adresse n'est dans aucun
    /// set : deux absences, `failed`. `blocklist_ttl` n'existe pas : le second retrait est TOUT DE MÊME tenté et rend
    /// l'absence du set ; avec un premier retrait réussi, `done` ; avec une adresse absente de `blocklist` aussi,
    /// `failed`. Une levée simulée affiche les deux commandes et n'appelle rien. Appels et résultats à l'octet.
    /// MUTATIONS : `M2`, `M5`, `M7`.
    #[test]
    fn lnx_b_deux_absences_rendent_failed_et_le_set_absent_est_une_absence() {
        const ENFANT: &str = "LNX_TEMOIN_ENFANT";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let nom = "tests::levee_nft_couvre_le_set_a_expiration_de_l_agent::lnx_b_deux_absences_rendent_failed_et_le_set_absent_est_une_absence";

        let (bac, base, path) = lnx_bac("lnx-b-aucun");
        lnx_set(&bac, "blocklist", "");
        lnx_set(&bac, "blocklist_ttl", "");
        lnx_action(&base, "unban_ip", "203.0.113.83", false);
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1");
        let stderr = lnx_jouer(commande, &bac, &base, &path, "nft", "linux");
        assert_eq!(
            lnx_appels(&bac),
            format!("{LNX_AMORCE}nft delete element inet plume blocklist {{ 203.0.113.83 }}\nnft delete element inet plume blocklist_ttl {{ 203.0.113.83 }}\n"),
            "{stderr}"
        );
        assert_eq!(
            lnx_verdict(&base, "203.0.113.83"),
            (
                "failed".to_string(),
                "blocklist : absente (Error: Could not process rule: No such file or directory (blocklist, 203.0.113.83)) | blocklist_ttl : absente (Error: Could not process rule: No such file or directory (blocklist_ttl, 203.0.113.83))".to_string()
            ),
            "deux absences : failed\n{stderr}"
        );

        let (bac, base, path) = lnx_bac("lnx-b-sans-set");
        lnx_set(&bac, "blocklist", "203.0.113.86\n");
        lnx_action(&base, "unban_ip", "203.0.113.86", false);
        lnx_action(&base, "unban_ip", "203.0.113.87", false);
        lnx_action(&base, "unban_ip", "203.0.113.88", true);
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1");
        let stderr = lnx_jouer(commande, &bac, &base, &path, "nft", "linux");
        assert_eq!(
            lnx_appels(&bac),
            format!(
                "{LNX_AMORCE}\
nft delete element inet plume blocklist {{ 203.0.113.86 }}\n\
nft delete element inet plume blocklist_ttl {{ 203.0.113.86 }}\n\
nft delete element inet plume blocklist {{ 203.0.113.87 }}\n\
nft delete element inet plume blocklist_ttl {{ 203.0.113.87 }}\n"
            ),
            "set absent : second retrait tenté ; la levée simulée n'appelle rien\n{stderr}"
        );
        assert_eq!(
            lnx_verdict(&base, "203.0.113.86"),
            (
                "done".to_string(),
                "blocklist : retirée (nft delete element inet plume blocklist { 203.0.113.86 } -> exit status: 0) | blocklist_ttl : absente (Error: No such file or directory (set blocklist_ttl))".to_string()
            ),
            "set blocklist_ttl absent, premier retrait réussi : done\n{stderr}"
        );
        assert_eq!(
            lnx_verdict(&base, "203.0.113.87"),
            (
                "failed".to_string(),
                "blocklist : absente (Error: Could not process rule: No such file or directory (blocklist, 203.0.113.87)) | blocklist_ttl : absente (Error: No such file or directory (set blocklist_ttl))".to_string()
            ),
            "set blocklist_ttl absent, adresse absente de blocklist : failed\n{stderr}"
        );
        assert_eq!(
            lnx_verdict(&base, "203.0.113.88"),
            (
                "dryrun".to_string(),
                "[dry-run] nft delete element inet plume blocklist { 203.0.113.88 } ; nft delete element inet plume blocklist_ttl { 203.0.113.88 }".to_string()
            ),
            "dry-run : les deux commandes\n{stderr}"
        );
    }

    /// (c) CE QU'IL TIENT : un REFUS sur l'un des deux sets rend `failed`, quoi qu'ait rendu l'autre. Adresse dans les
    /// deux sets : retrait de `blocklist` refusé (« Device or resource busy »), retrait de `blocklist_ttl` réussi →
    /// `failed` ; retrait de `blocklist` réussi, retrait de `blocklist_ttl` refusé → `failed` ; retrait de `blocklist`
    /// réussi, `nft` tué par un signal sur `blocklist_ttl` APRÈS avoir écrit le message d'absence → refus, `failed` ;
    /// retrait de `blocklist` réussi, `nft` qui écrit le message d'absence sur sa SORTIE STANDARD et « Device or
    /// resource busy » sur sa sortie d'erreur pour `blocklist_ttl` → refus, `failed` : une absence lue sur la sortie
    /// standard noterait `done` une adresse peut-être encore bannie. Résultats ENTIERS comparés.
    /// MUTATIONS : `M1`, `M3`, `M10`, `M12`.
    #[test]
    fn lnx_c_un_refus_sur_un_set_rend_failed() {
        const ENFANT: &str = "LNX_TEMOIN_ENFANT";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let (bac, base, path) = lnx_bac("lnx-c");
        lnx_set(&bac, "blocklist", "203.0.113.70\n203.0.113.71\n203.0.113.72\n203.0.113.73\n");
        lnx_set(&bac, "blocklist_ttl", "203.0.113.70\n203.0.113.71\n203.0.113.72\n203.0.113.73\n");
        lnx_marque(&bac, "verrou_blocklist_203.0.113.70", "");
        lnx_marque(&bac, "verrou_blocklist_ttl_203.0.113.71", "");
        lnx_marque(&bac, "signal_blocklist_ttl_203.0.113.72", "");
        lnx_marque(&bac, "stdout_blocklist_ttl_203.0.113.73", "");
        lnx_action(&base, "unban_ip", "203.0.113.70", false);
        lnx_action(&base, "unban_ip", "203.0.113.71", false);
        lnx_action(&base, "unban_ip", "203.0.113.72", false);
        lnx_action(&base, "unban_ip", "203.0.113.73", false);
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::levee_nft_couvre_le_set_a_expiration_de_l_agent::lnx_c_un_refus_sur_un_set_rend_failed"])
            .env(ENFANT, "1");
        let stderr = lnx_jouer(commande, &bac, &base, &path, "nft", "linux");
        assert_eq!(
            lnx_verdict(&base, "203.0.113.70"),
            (
                "failed".to_string(),
                format!("blocklist : refus ({LNX_OCCUPE} (blocklist)) | blocklist_ttl : retirée (nft delete element inet plume blocklist_ttl {{ 203.0.113.70 }} -> exit status: 0)")
            ),
            "refus sur blocklist, retrait de blocklist_ttl : failed\n{stderr}"
        );
        assert_eq!(
            lnx_verdict(&base, "203.0.113.71"),
            (
                "failed".to_string(),
                format!("blocklist : retirée (nft delete element inet plume blocklist {{ 203.0.113.71 }} -> exit status: 0) | blocklist_ttl : refus ({LNX_OCCUPE} (blocklist_ttl))")
            ),
            "retrait de blocklist, refus sur blocklist_ttl : failed\n{stderr}"
        );
        assert_eq!(
            lnx_verdict(&base, "203.0.113.72"),
            (
                "failed".to_string(),
                "blocklist : retirée (nft delete element inet plume blocklist { 203.0.113.72 } -> exit status: 0) | blocklist_ttl : refus (Error: Could not process rule: No such file or directory (blocklist_ttl))".to_string()
            ),
            "signal après le message d'absence : refus, failed\n{stderr}"
        );
        assert_eq!(
            lnx_verdict(&base, "203.0.113.73"),
            (
                "failed".to_string(),
                format!("blocklist : retirée (nft delete element inet plume blocklist {{ 203.0.113.73 }} -> exit status: 0) | blocklist_ttl : refus (No such file or directory (sortie standard)\n{LNX_OCCUPE} (blocklist_ttl))")
            ),
            "message d'absence sur la sortie standard, refus sur la sortie d'erreur : refus, failed\n{stderr}"
        );
    }

    /// (d) CE QU'IL TIENT : une commande QUI NE PEUT PAS PARTIR est un refus, jamais une absence, bien que son texte
    /// porte « No such file or directory ». Le PATH ne contient que le bac, d'où `nft` et `cscli` sont retirés : la
    /// levée nft rend `failed`, ses deux parts en refus ; la pose nft (un argv) rend `failed` et `exec: …`. Puis, faux
    /// `nft` GARDÉ et `cscli` seul retiré : la levée CrowdSec (un argv) rend `failed` et `exec: …`, et n'appelle aucun
    /// `nft` (appels vides, jugés avant le verdict). Résultats ENTIERS comparés. MUTATIONS : `M9`, `M13`.
    #[test]
    fn lnx_d_nft_absent_du_path_rend_failed_en_refus() {
        const ENFANT: &str = "LNX_TEMOIN_ENFANT";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let nom = "tests::levee_nft_couvre_le_set_a_expiration_de_l_agent::lnx_d_nft_absent_du_path_rend_failed_en_refus";

        let (bac, base, _) = lnx_bac("lnx-d-nft");
        std::fs::remove_file(bac.join("nft")).expect("fixture : faux nft retiré");
        std::fs::remove_file(bac.join("cscli")).expect("fixture : faux cscli retiré");
        let path_sans_nft = bac.display().to_string();
        lnx_action(&base, "ban_ip", "203.0.113.96", false);
        lnx_action(&base, "unban_ip", "203.0.113.97", false);
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1");
        let stderr = lnx_jouer(commande, &bac, &base, &path_sans_nft, "nft", "linux");
        assert_eq!(lnx_verdict(&base, "203.0.113.96"), ("failed".to_string(), LNX_EXEC_ABSENT.to_string()), "pose nft sans nft\n{stderr}");
        assert_eq!(
            lnx_verdict(&base, "203.0.113.97"),
            ("failed".to_string(), format!("blocklist : refus ({LNX_EXEC_ABSENT}) | blocklist_ttl : refus ({LNX_EXEC_ABSENT})")),
            "levée nft sans nft : deux refus\n{stderr}"
        );

        let (bac, base, _) = lnx_bac("lnx-d-crowdsec");
        std::fs::remove_file(bac.join("cscli")).expect("fixture : faux cscli retiré");
        let path_sans_cscli = bac.display().to_string();
        lnx_action(&base, "unban_ip", "203.0.113.98", false);
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1");
        let stderr = lnx_jouer(commande, &bac, &base, &path_sans_cscli, "crowdsec", "linux");
        assert_eq!(lnx_appels(&bac), "", "levée CrowdSec : aucun nft appelé, faux nft pourtant dans le PATH\n{stderr}");
        assert_eq!(lnx_verdict(&base, "203.0.113.98"), ("failed".to_string(), LNX_EXEC_ABSENT.to_string()), "levée CrowdSec sans cscli\n{stderr}");
    }

    /// (e) CE QU'IL TIENT : un message d'absence TRADUIT n'est pas reconnu. Le bac porte `francais` : le faux `nft`
    /// répond « Aucun fichier ou dossier de ce type » même sous `LC_ALL=C`. Adresse dans `blocklist` seul : retrait
    /// de `blocklist` réussi, l'erreur traduite sur `blocklist_ttl` est un refus → `failed`. Témoin jumeau de (a), où
    /// la même adresse rend `done` parce que le faux `nft` reçoit `LC_ALL=C` et `LANG=C`. MUTATION : `M4` (par (a)).
    #[test]
    fn lnx_e_un_message_d_absence_traduit_est_un_refus() {
        const ENFANT: &str = "LNX_TEMOIN_ENFANT";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let (bac, base, path) = lnx_bac("lnx-e");
        lnx_set(&bac, "blocklist", "203.0.113.75\n");
        lnx_set(&bac, "blocklist_ttl", "");
        lnx_marque(&bac, "francais", "");
        lnx_action(&base, "unban_ip", "203.0.113.75", false);
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::levee_nft_couvre_le_set_a_expiration_de_l_agent::lnx_e_un_message_d_absence_traduit_est_un_refus"])
            .env(ENFANT, "1");
        let stderr = lnx_jouer(commande, &bac, &base, &path, "nft", "linux");
        assert_eq!(
            lnx_verdict(&base, "203.0.113.75"),
            (
                "failed".to_string(),
                "blocklist : retirée (nft delete element inet plume blocklist { 203.0.113.75 } -> exit status: 0) | blocklist_ttl : refus (Error: Could not process rule: Aucun fichier ou dossier de ce type (blocklist_ttl, 203.0.113.75))".to_string()
            ),
            "message traduit : refus\n{stderr}"
        );
    }

    /// (f) CE QU'IL TIENT : la POSE nft ne change pas — `blocklist_ttl` existe, et un `ban_ip` joue UN argv, `nft add
    /// element inet plume blocklist { <ip> }`, sans retrait de `blocklist_ttl` (appels à l'octet) ; son résultat et
    /// le dry-run d'un `ban_ip` simulé sont ceux d'avant, à l'octet. MUTATION : `M6`.
    #[test]
    fn lnx_f_la_pose_nft_reste_un_seul_argv() {
        const ENFANT: &str = "LNX_TEMOIN_ENFANT";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let (bac, base, path) = lnx_bac("lnx-f");
        lnx_set(&bac, "blocklist", "");
        lnx_set(&bac, "blocklist_ttl", "203.0.113.85\n");
        lnx_action(&base, "ban_ip", "203.0.113.85", false);
        lnx_action(&base, "ban_ip", "203.0.113.89", true);
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::levee_nft_couvre_le_set_a_expiration_de_l_agent::lnx_f_la_pose_nft_reste_un_seul_argv"])
            .env(ENFANT, "1");
        let stderr = lnx_jouer(commande, &bac, &base, &path, "nft", "linux");
        assert_eq!(lnx_appels(&bac), format!("{LNX_AMORCE}nft add element inet plume blocklist {{ 203.0.113.85 }}\n"), "ban_ip : un seul argv\n{stderr}");
        assert_eq!(
            lnx_verdict(&base, "203.0.113.85"),
            ("done".to_string(), "nft add element inet plume blocklist { 203.0.113.85 } -> exit status: 0".to_string()),
            "{stderr}"
        );
        assert_eq!(
            lnx_verdict(&base, "203.0.113.89"),
            ("dryrun".to_string(), "[dry-run] nft add element inet plume blocklist { 203.0.113.89 }".to_string()),
            "{stderr}"
        );
    }

    /// (g) CE QU'IL TIENT : les autres voies d'une levée ne touchent pas nft — un faux `nft` est en tête de PATH à
    /// côté des autres, et `unban_ip` sous CrowdSec, sous fail2ban, puis sous le gabarit pfsense n'appelle que sa
    /// commande d'avant (appels à l'octet), avec son résultat d'avant à l'octet ; le dry-run CrowdSec aussi.
    #[test]
    fn lnx_g_les_autres_voies_de_levee_n_appellent_pas_nft() {
        const ENFANT: &str = "LNX_TEMOIN_ENFANT";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let nom = "tests::levee_nft_couvre_le_set_a_expiration_de_l_agent::lnx_g_les_autres_voies_de_levee_n_appellent_pas_nft";

        let (bac, base, path) = lnx_bac("lnx-g-crowdsec");
        lnx_set(&bac, "blocklist_ttl", "203.0.113.90\n");
        lnx_action(&base, "unban_ip", "203.0.113.90", false);
        lnx_action(&base, "unban_ip", "203.0.113.93", true);
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1");
        let stderr = lnx_jouer(commande, &bac, &base, &path, "crowdsec", "linux");
        assert_eq!(lnx_appels(&bac), "cscli decisions delete --ip 203.0.113.90\n", "crowdsec : aucun appel nft\n{stderr}");
        assert_eq!(
            lnx_verdict(&base, "203.0.113.90"),
            ("done".to_string(), "cscli decisions delete --ip 203.0.113.90 -> exit status: 0".to_string()),
            "{stderr}"
        );
        assert_eq!(
            lnx_verdict(&base, "203.0.113.93"),
            ("dryrun".to_string(), "[dry-run] cscli decisions delete --ip 203.0.113.93".to_string()),
            "{stderr}"
        );

        let (bac, base, path) = lnx_bac("lnx-g-fail2ban");
        lnx_set(&bac, "blocklist_ttl", "203.0.113.91\n");
        lnx_action(&base, "unban_ip", "203.0.113.91", false);
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1");
        let stderr = lnx_jouer(commande, &bac, &base, &path, "fail2ban", "linux");
        assert_eq!(lnx_appels(&bac), "fail2ban-client set sshd unbanip 203.0.113.91\n", "fail2ban : aucun appel nft\n{stderr}");
        assert_eq!(
            lnx_verdict(&base, "203.0.113.91"),
            ("done".to_string(), "fail2ban-client set sshd unbanip 203.0.113.91 -> exit status: 0".to_string()),
            "{stderr}"
        );

        let (bac, base, path) = lnx_bac("lnx-g-pfsense");
        lnx_set(&bac, "blocklist_ttl", "203.0.113.92\n");
        lnx_action(&base, "unban_ip", "203.0.113.92", false);
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.args(["--exact", "--nocapture", "--test-threads=1", nom]).env(ENFANT, "1");
        let stderr = lnx_jouer(commande, &bac, &base, &path, "nft", "pfsense");
        assert_eq!(lnx_appels(&bac), "pfctl -t plume_blocklist -T delete 203.0.113.92\n", "pfsense : aucun appel nft\n{stderr}");
        assert_eq!(
            lnx_verdict(&base, "203.0.113.92"),
            ("done".to_string(), "pfctl -t plume_blocklist -T delete 203.0.113.92 -> exit status: 0".to_string()),
            "{stderr}"
        );
    }

    /// (h) CE QU'IL TIENT : une sortie longue est bornée. Voie à UN argv (pose nft) : une pose refusée rend `failed`
    /// avec sa sortie d'erreur telle quelle, et une sortie longue est coupée à 500 caractères exactement. Levée à deux
    /// sets : une adresse dont les deux retraits rendent une sortie longue garde ses deux parts, chacune coupée à sa
    /// borne, le tout sous 500 caractères : la part du second set n'est pas masquée par celle du premier.
    /// MUTATIONS : `M8`, `M11`.
    #[test]
    fn lnx_h_les_sorties_longues_sont_bornees() {
        const ENFANT: &str = "LNX_TEMOIN_ENFANT";
        let _env = VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            crate::ledger::declarer_la_liste_pour_ce_temoin();
            crate::handlers::actions::respond_run();
            return;
        }
        let (bac, base, path) = lnx_bac("lnx-h");
        lnx_set(&bac, "blocklist", "");
        lnx_set(&bac, "blocklist_ttl", "");
        lnx_marque(&bac, "refus_203.0.113.94", "Error: Could not process rule: refus (blocklist)\n");
        lnx_marque(&bac, "refus_203.0.113.95", &format!("{}\n", "y".repeat(800)));
        lnx_marque(&bac, "bavard_203.0.113.84", &format!("{}\n", "x".repeat(600)));
        lnx_action(&base, "ban_ip", "203.0.113.94", false);
        lnx_action(&base, "ban_ip", "203.0.113.95", false);
        lnx_action(&base, "unban_ip", "203.0.113.84", false);
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::levee_nft_couvre_le_set_a_expiration_de_l_agent::lnx_h_les_sorties_longues_sont_bornees"])
            .env(ENFANT, "1");
        let stderr = lnx_jouer(commande, &bac, &base, &path, "nft", "linux");
        assert_eq!(
            lnx_verdict(&base, "203.0.113.94"),
            ("failed".to_string(), "Error: Could not process rule: refus (blocklist)\n".to_string()),
            "pose refusée : failed, sortie telle quelle\n{stderr}"
        );
        assert_eq!(lnx_verdict(&base, "203.0.113.95"), ("failed".to_string(), "y".repeat(500)), "sortie longue coupée à 500\n{stderr}");
        let (statut, resultat) = lnx_verdict(&base, "203.0.113.84");
        let premier: String = format!("absente (blocklist:{}", "x".repeat(600)).chars().take(230).collect();
        let second: String = format!("absente (blocklist_ttl:{}", "x".repeat(600)).chars().take(230).collect();
        assert_eq!(statut, "failed", "{stderr}");
        assert_eq!(resultat, format!("blocklist : {premier} | blocklist_ttl : {second}"), "chaque part coupée à sa borne\n{stderr}");
        assert!(resultat.chars().count() <= 500, "résultat sous 500 caractères : {}", resultat.chars().count());
    }

    /// CE QU'IL TIENT : le classement d'un retrait parti, cas par cas. Code 0 : retiré (même si la sortie d'erreur
    /// porte le message). Code non nul avec le message : absent (1 comme 2). Code non nul sans le message (occupé,
    /// vide, message traduit) : refus. Signal (`None`) avec le message : refus. MUTATIONS : `M1`, `M2`, `M10`.
    #[test]
    fn unite_classer_le_retrait_nft_en_trois_issues() {
        let absence = "Error: Could not process rule: No such file or directory\ndelete element inet plume blocklist { 203.0.113.1 }";
        assert_eq!(classer_le_retrait_nft(Some(0), ""), IssueDuRetraitNft::Retire);
        assert_eq!(classer_le_retrait_nft(Some(0), absence), IssueDuRetraitNft::Retire);
        assert_eq!(classer_le_retrait_nft(Some(1), absence), IssueDuRetraitNft::Absent);
        assert_eq!(classer_le_retrait_nft(Some(2), absence), IssueDuRetraitNft::Absent);
        assert_eq!(classer_le_retrait_nft(Some(1), "Error: Could not process rule: Device or resource busy"), IssueDuRetraitNft::Refus);
        assert_eq!(classer_le_retrait_nft(Some(1), ""), IssueDuRetraitNft::Refus);
        assert_eq!(classer_le_retrait_nft(Some(1), "Error: Could not process rule: Aucun fichier ou dossier de ce type"), IssueDuRetraitNft::Refus);
        assert_eq!(classer_le_retrait_nft(None, absence), IssueDuRetraitNft::Refus);
    }

    /// CE QU'IL TIENT : la table entière du verdict, ses neuf cas écrits un par un : `done` exactement pour (retiré,
    /// retiré), (retiré, absent), (absent, retiré). MUTATION : `M3`.
    #[test]
    fn unite_verdict_des_deux_retraits_nft_table_entiere() {
        use crate::handlers::actions::IssueDuRetraitNft::{Absent, Refus, Retire};
        assert_eq!(verdict_des_deux_retraits_nft(Retire, Retire), "done");
        assert_eq!(verdict_des_deux_retraits_nft(Retire, Absent), "done");
        assert_eq!(verdict_des_deux_retraits_nft(Absent, Retire), "done");
        assert_eq!(verdict_des_deux_retraits_nft(Absent, Absent), "failed");
        assert_eq!(verdict_des_deux_retraits_nft(Retire, Refus), "failed");
        assert_eq!(verdict_des_deux_retraits_nft(Refus, Retire), "failed");
        assert_eq!(verdict_des_deux_retraits_nft(Absent, Refus), "failed");
        assert_eq!(verdict_des_deux_retraits_nft(Refus, Absent), "failed");
        assert_eq!(verdict_des_deux_retraits_nft(Refus, Refus), "failed");
    }
}

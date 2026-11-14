// `P10.21-n` — LA FENÊTRE DE RÉCLAMATION SERVIE PAR LE DÉMON ET LE RYTHME DES DEUX UNITÉS DE RIPOSTE.
//
// Aucune garde ne liait `RECLAMATION_PERIMEE_S` au rythme des minuteurs qui lancent les répondeurs : l'un pouvait changer
// sans l'autre, et ce que le code en suppose devenait faux sans bruit. Ce témoin lit les deux minuteurs
// (`systemd/plume-respond-agent.timer`, `systemd/plume-respond.timer`) par `include_str!`, la constante du démon, et le
// répondeur de l'hôte, puis établit les relations que le code SUPPOSE aujourd'hui — chacune citée là où elle est écrite :
//
//   (1) `RECLAMATION_PERIMEE_S` (daemon/src/handlers/actions.rs, trois cents secondes) EST ÉGALE à `REJEU_TOURS`
//       (collectors/respond.sh, cinq tours) fois `OnUnitActiveSec` du minuteur de l'agent (soixante secondes).
//       collectors/respond.sh le suppose au rejeu des verdicts retenus : « au REJEU_TOURS-ieme, ABANDONNE et avoue — la
//       riposte sera alors re-servie par le central » — l'abandon d'un verdict coïncide avec la péremption de la
//       réclamation de sa riposte. Fenêtre agrandie seule : l'agent abandonne un verdict que le central ne re-sert pas
//       encore (la riposte reste ouverte sans verdict en route) ; rythme ou nombre de tours agrandi seul : le central
//       re-sert la riposte des tours avant l'abandon, et la phrase est fausse.
//   (2) Le responder local du démon tourne au rythme que deux commentaires du démon écrivent en toutes lettres
//       (daemon/src/db_open.rs : « toutes les 20 s » ; daemon/src/handlers/actions.rs : « timer 20 s »), et ce rythme
//       reste sous la fenêtre : il prend une réclamation périmée au plus un tour après sa péremption.
//   (3) collectors/respond.sh cite le rythme de l'agent en toutes lettres (`OnUnitActiveSec=<n>s`) pour dire qu'un tour
//       ne se superpose pas au suivant et pour mesurer ce que couvre la borne du registre d'exécution.
//
// Mutants vus rouges (puis remis) : `RECLAMATION_PERIMEE_S` à 600 ; `OnUnitActiveSec=120s` dans le minuteur de l'agent ;
// `REJEU_TOURS=4` ; `OnUnitActiveSec=30s` dans le minuteur du démon.
//
// NE TIENT PAS : `AccuracySec` (le minuteur peut partir en retard) et la DURÉE d'un tour ne sont pas comptés ; la
// relation porte sur le rythme livré, pas sur un hôte qui aurait réécrit ses unités.

#[cfg(test)]
mod ci1_fenetre_de_reclamation {
    const MINUTEUR_AGENT: &str = include_str!("../../../systemd/plume-respond-agent.timer");
    const MINUTEUR_DEMON: &str = include_str!("../../../systemd/plume-respond.timer");
    const REPONDEUR_HOTE: &str = include_str!("../../../collectors/respond.sh");
    const DB_OPEN: &str = include_str!("../db_open.rs");
    const ACTIONS: &str = include_str!("../handlers/actions.rs");

    /// Une durée systemd en secondes : suite de `<n><unité>` séparés ou non par des blancs (`60s`, `1min 30s`, `2min`),
    /// un nombre nu valant des secondes. `None` pour toute autre forme : l'instrument refuse alors de conclure.
    fn secondes_systemd(v: &str) -> Option<u64> {
        let mut total = 0u64;
        let mut reste = v.trim();
        if reste.is_empty() {
            return None;
        }
        while !reste.is_empty() {
            let chiffres: String = reste.chars().take_while(|c| c.is_ascii_digit()).collect();
            if chiffres.is_empty() {
                return None;
            }
            reste = &reste[chiffres.len()..];
            let unite: String = reste.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
            reste = reste[unite.len()..].trim_start();
            let facteur = match unite.as_str() {
                "" | "s" | "sec" | "second" | "seconds" => 1,
                "m" | "min" | "minute" | "minutes" => 60,
                "h" | "hr" | "hour" | "hours" => 3600,
                _ => return None,
            };
            total = total.checked_add(chiffres.parse::<u64>().ok()?.checked_mul(facteur)?)?;
        }
        Some(total)
    }

    /// La valeur de `cle=` dans la section `[Timer]` d'une unité (une seule occurrence admise).
    fn directive(unite: &str, cle: &str, fichier: &str) -> u64 {
        let valeurs: Vec<&str> = unite
            .lines()
            .map(str::trim)
            .filter_map(|l| l.strip_prefix(cle).and_then(|r| r.strip_prefix('=')))
            .collect();
        assert_eq!(valeurs.len(), 1, "INSTRUMENT : `{cle}=` présent {} fois dans `{fichier}` (une attendue)", valeurs.len());
        secondes_systemd(valeurs[0])
            .unwrap_or_else(|| panic!("INSTRUMENT : `{cle}={}` illisible dans `{fichier}`", valeurs[0]))
    }

    /// `REJEU_TOURS=<n>` du répondeur de l'hôte (une seule affectation admise).
    fn tours_de_rejeu() -> u64 {
        let valeurs: Vec<&str> = REPONDEUR_HOTE.lines().filter_map(|l| l.strip_prefix("REJEU_TOURS=")).collect();
        assert_eq!(valeurs.len(), 1, "INSTRUMENT : `REJEU_TOURS=` présent {} fois dans collectors/respond.sh", valeurs.len());
        valeurs[0].trim().parse().unwrap_or_else(|_| panic!("INSTRUMENT : `REJEU_TOURS={}` illisible", valeurs[0]))
    }

    /// La relation (1), pure : `Err` dit laquelle des trois grandeurs a bougé sans les autres.
    fn juger_fenetre_et_rejeu(fenetre_s: u64, rythme_agent_s: u64, tours: u64) -> Result<(), String> {
        if fenetre_s == tours * rythme_agent_s {
            return Ok(());
        }
        Err(format!(
            "RECLAMATION_PERIMEE_S ({fenetre_s} s) n'est plus REJEU_TOURS ({tours}) x OnUnitActiveSec de l'agent \
             ({rythme_agent_s} s) = {} s : collectors/respond.sh dit qu'au dernier tour de rejeu la riposte « sera alors \
             re-servie par le central », ce n'est plus vrai",
            tours * rythme_agent_s
        ))
    }

    fn fenetre() -> u64 {
        u64::try_from(crate::handlers::actions::RECLAMATION_PERIMEE_S).expect("RECLAMATION_PERIMEE_S négative")
    }

    /// (1) sur les valeurs LIVRÉES : la fenêtre du démon égale le rejeu de l'agent à son rythme.
    #[test]
    fn ci1_la_fenetre_de_reclamation_egale_le_rejeu_de_l_agent_a_son_rythme() {
        let rythme = directive(MINUTEUR_AGENT, "OnUnitActiveSec", "systemd/plume-respond-agent.timer");
        let tours = tours_de_rejeu();
        if let Err(e) = juger_fenetre_et_rejeu(fenetre(), rythme, tours) {
            panic!("{e}");
        }
        // La phrase de collectors/respond.sh que la relation tient, présente telle quelle.
        assert!(
            REPONDEUR_HOTE.contains("au REJEU_TOURS-ieme, ABANDONNE et avoue — la"),
            "INSTRUMENT : la phrase du rejeu qui suppose la relation n'est plus dans collectors/respond.sh"
        );
    }

    /// (1) le juge rougit dès qu'UNE grandeur bouge seule, dans chaque sens (fenêtre, rythme, tours).
    #[test]
    fn ci1_le_juge_rougit_si_une_seule_grandeur_bouge() {
        let (f, r, t) = (fenetre(), directive(MINUTEUR_AGENT, "OnUnitActiveSec", "agent"), tours_de_rejeu());
        assert!(juger_fenetre_et_rejeu(f, r, t).is_ok());
        for (nom, cas) in [
            ("fenêtre + 1", (f + 1, r, t)),
            ("fenêtre - 1", (f - 1, r, t)),
            ("rythme + 1", (f, r + 1, t)),
            ("rythme - 1", (f, r - 1, t)),
            ("tours + 1", (f, r, t + 1)),
            ("tours - 1", (f, r, t - 1)),
        ] {
            let e = juger_fenetre_et_rejeu(cas.0, cas.1, cas.2).expect_err(nom);
            assert!(e.contains("RECLAMATION_PERIMEE_S") && e.contains("re-servie par le central"), "{nom} : {e}");
        }
    }

    /// (2) le rythme du responder local du démon est celui que le démon écrit en toutes lettres, et reste sous la
    /// fenêtre de réclamation.
    #[test]
    fn ci1_le_responder_local_du_demon_tourne_au_rythme_ecrit_sous_la_fenetre() {
        let rythme = directive(MINUTEUR_DEMON, "OnUnitActiveSec", "systemd/plume-respond.timer");
        let ecrit_db_open = format!("toutes les {rythme} s (`plume-respond.timer`)");
        let ecrit_actions = format!("(systemd/plume-respond.service, timer {rythme} s)");
        assert!(DB_OPEN.contains(&ecrit_db_open), "daemon/src/db_open.rs n'écrit plus « {ecrit_db_open} » : le minuteur du démon ({rythme} s) et le commentaire divergent");
        assert!(ACTIONS.contains(&ecrit_actions), "daemon/src/handlers/actions.rs n'écrit plus « {ecrit_actions} » : le minuteur du démon ({rythme} s) et le commentaire divergent");
        assert!(rythme < fenetre(), "le responder local du démon ({rythme} s) tourne moins souvent que la fenêtre de réclamation ({} s)", fenetre());
    }

    /// (3) le rythme de l'agent que collectors/respond.sh écrit en toutes lettres est celui du minuteur livré, à chaque
    /// citation.
    #[test]
    fn ci1_le_repondeur_de_l_hote_cite_le_rythme_livre_de_son_minuteur() {
        let rythme = directive(MINUTEUR_AGENT, "OnUnitActiveSec", "systemd/plume-respond-agent.timer");
        let citations: Vec<&str> = REPONDEUR_HOTE.match_indices("`OnUnitActiveSec=").map(|(i, _)| &REPONDEUR_HOTE[i..]).collect();
        assert!(citations.len() >= 2, "INSTRUMENT : {} citation(s) du rythme dans collectors/respond.sh", citations.len());
        for c in citations {
            let valeur = c["`OnUnitActiveSec=".len()..].split('`').next().unwrap_or_default();
            assert_eq!(secondes_systemd(valeur), Some(rythme), "collectors/respond.sh cite `OnUnitActiveSec={valeur}`, le minuteur de l'agent en a {rythme} s");
        }
    }

    /// L'instrument : chaque forme de durée systemd employée, et le refus d'une forme inconnue.
    #[test]
    fn ci1_les_durees_systemd_sont_lues_ou_refusees() {
        for (v, s) in [("60s", Some(60)), ("20s", Some(20)), ("2min", Some(120)), ("1min 30s", Some(90)), ("1h", Some(3600)), ("45", Some(45))] {
            assert_eq!(secondes_systemd(v), s, "{v}");
        }
        for v in ["", "s", "60x", "1.5s", "-5s"] {
            assert_eq!(secondes_systemd(v), None, "{v:?} devait être refusée");
        }
    }
}

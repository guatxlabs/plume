// =====================================================================================
// `P7.20-a` — UNE EXEMPTION DE `PLUME_SSRF_ALLOW` NE LÈVE PAS LA POLITIQUE DU PRIVÉ POUR LES AUTRES ADRESSES DU NOM.
//
// La boucle des adresses résolues de `ssrf_check_host_selon` (daemon/src/ledger.rs) exempte une adresse listée par un
// CIDR ou une adresse nue (`ssrf_ip_allowed` → `continue`), puis juge chaque autre adresse : never-egress, puis
// politique du privé (`ssrf_blocked_policy`). Le témoin d'avant (tests/liste_d_exemption_ssrf_lue_entree_par_entree.rs,
// (d)) ne tenait cette re-vérification que sur le never-egress : `localhost` est le seul nom qui rende deux adresses
// sans réseau, et ce sont deux boucles locales. Aucun nom de la machine ne rend une adresse listée ET une adresse
// privée RFC 1918 non listée, et aucun appelant de production ne reçoit une liste déjà résolue.
//
// LE POINT D'ENTRÉE, SOUS `cfg(test)` SEULEMENT : `crate::ledger::resolution_injectee` substitue à un nom `.test`
// (réservé, jamais résolu) une liste d'adresses déjà résolue, que `ssrf_resoudre` rend à la MÊME boucle que la
// production. Rien d'autre n'est contourné : l'URL est jugée par le fetch gardé des connecteurs
// (`appel_garde_d_un_connecteur`, sans cible inscrite : origine `Api`) et par le transport d'une destination
// (`dest_transport_pour_l_objet`), le témoin de l'égress armé (aucun réseau : une URL admise est interceptée).
//
// `PLUME_SSRF_ALLOW="10.20.0.5"` (une adresse nue, privée). Table injectée, adresses RFC 1918 ou RFC 5737 seules :
//   listée seule         → [10.20.0.5]                  : part (la listée passe) ;
//   listée puis privée   → [10.20.0.5, 192.168.40.7]    : refusée pour 192.168.40.7, politique du privé ;
//   privée puis listée   → [192.168.40.7, 10.20.0.5]    : la même, l'ordre inverse ;
//   listée puis voisine  → [10.20.0.5, 10.20.0.6]       : refusée pour 10.20.0.6 (la voisine n'est pas listée) ;
//   listée puis publique → [10.20.0.5, 198.51.100.7]    : part (l'exemption ne refuse pas ce que rien ne refuse) ;
//   publique puis listée → [198.51.100.7, 10.20.0.5]    : part (l'exemption vaut aussi pour une adresse qui n'est pas
//                          la première résolue) ;
//   privée seule         → [192.168.40.7]               : refusée (contrôle de la politique sans exemption) ;
//   nom suffixe d'un autre → « seule.exemple.test », [192.168.40.7], écrit dans la table AVANT
//                          « listee-seule.exemple.test » : refusé ; la listée passe toujours (nom comparé tel qu'écrit) ;
//   nom dont un autre est le prolongement → « puis-publique.exemple.test », [192.168.40.7], écrit APRÈS
//                          « listee-puis-publique.exemple.test » qui finit par lui : refusé (comparaison dans l'autre sens).
// Joué deux fois : sous `PLUME_SSRF_BLOCK_PRIVATE=1`, puis sous la politique PAR DÉFAUT (levier absent : le privé est
// refusé pour une cible de l'API), pour que le verdict ne dépende pas du seul levier posé.
//
// Toutes les assertions d'un cas sont jugées avant l'échec, qui les liste toutes. MUTANTS JOUÉS (VERIF_MUT sous
// `cfg!(test)` dans ledger.rs, retirés avant le commit), chacun vu ROUGE sur les deux témoins, avec l'ensemble mesuré :
//   M_RETOUR_TOT (`return Ok` à la première adresse exemptée au lieu de `continue`) → listée puis privée, listée puis
//     voisine ;
//   M_LEVE_SUIVANTES (une adresse exemptée lève la politique du privé pour les adresses qui la suivent) → listée puis
//     privée, listée puis voisine ;
//   M_LEVE_TOUTES (une adresse exemptée dans la résolution lève la politique du privé pour TOUTES) → listée puis
//     privée, privée puis listée, listée puis voisine ;
//   M_SANS_POLITIQUE_RESOLUE (politique du privé retirée sur l'adresse résolue) → listée puis privée, privée puis
//     listée, listée puis voisine, privée seule ;
//   M_EXEMPTION_IGNOREE (l'adresse listée n'est plus exemptée) → la listée passe, listée puis publique, listée puis
//     privée, listée puis voisine (refusées pour 10.20.0.5, nommée la première) — ensemble mesuré par la vague BF,
//     avant le cas « publique puis listée » ;
//   M_INJECTION_IGNOREE (instrument : la table n'est pas lue, la résolution réelle échoue sur `.test`) → chaque cas ;
//   VM_EXEMPTION_PREMIERE_SEULE (vague BG : l'exemption ne vaut que pour la PREMIÈRE adresse résolue) → publique puis
//     listée, seule (refusée pour 10.20.0.5 par la politique du privé), sur les deux témoins ;
//   VM_POUR_SUFFIXE (vague BH, instrument : `resolution_injectee::pour` compare par suffixe, `host.ends_with(nom)`) →
//     la listée passe seule (refusée pour 192.168.40.7, l'adresse du nom suffixe écrit avant elle), sur les deux témoins ;
//   VM_POUR_SUFFIXE_INVERSE (vague BH, correction après vérification, instrument : `pour` rend le premier nom de la table
//     qui FINIT par l'hôte, `nom.ends_with(host)`) → nom dont un autre est le prolongement (admis : la table rend les
//     adresses de « listee-puis-publique »), sur les deux témoins. Avant ce cas, ce mutant restait vert.
// MESURÉ AUSSI : sous M_LEVE_SUIVANTES, les deux témoins (d) de liste_d_exemption_ssrf_lue_entree_par_entree.rs restent
// VERTS (leurs adresses non listées sont des boucles locales, refusées par le never-egress) : c'est le trou que ce
// fichier ferme.
//
// La liste et la politique sont figées au premier usage (OnceLock) : chaque valeur se joue dans un SOUS-PROCESSUS,
// environnement `PLUME_*` vidé, puis réglé.
// =====================================================================================
mod exemption_ssrf_ne_leve_pas_la_politique_du_prive_des_autres {
    use crate::handlers::destinations::{dest_transport_pour_l_objet, Wire};
    use crate::ledger::{resolution_injectee, temoin_de_l_egress};

    const MODULE: &str = "tests::exemption_ssrf_ne_leve_pas_la_politique_du_prive_des_autres::";
    const ENFANT: &str = "BF5_ENFANT_EXEMPTION_SSRF";
    const FIN: &str = "BF5-EXEMPTION-SSRF-A-JOUE";
    const LISTE: &str = "10.20.0.5";
    const LEVIERS: &str = "PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse privée";

    /// La table injectée : chaque nom et les adresses que la « résolution » rend, dans cet ordre.
    const TABLE: [(&str, &[&str]); 9] = [
        // Nom SUFFIXE de « listee-seule.exemple.test », placé AVANT lui : une table comparée par suffixe le trouverait
        // le premier et rendrait 192.168.40.7 pour la listée. Le nom est comparé TEL QU'ÉCRIT (`resolution_injectee::pour`).
        ("seule.exemple.test", &["192.168.40.7"]),
        ("listee-seule.exemple.test", &["10.20.0.5"]),
        ("listee-puis-privee.exemple.test", &["10.20.0.5", "192.168.40.7"]),
        ("privee-puis-listee.exemple.test", &["192.168.40.7", "10.20.0.5"]),
        ("listee-puis-voisine.exemple.test", &["10.20.0.5", "10.20.0.6"]),
        ("listee-puis-publique.exemple.test", &["10.20.0.5", "198.51.100.7"]),
        ("publique-puis-listee.exemple.test", &["198.51.100.7", "10.20.0.5"]),
        ("privee-seule.exemple.test", &["192.168.40.7"]),
        // Nom dont « listee-puis-publique.exemple.test » est un SUFFIXE INVERSE (le nom écrit AVANT finit par lui) : une
        // table qui chercherait le premier nom finissant par l'hôte rendrait 10.20.0.5 et 198.51.100.7, et l'admettrait.
        ("puis-publique.exemple.test", &["192.168.40.7"]),
    ];

    /// Ce qu'un nom doit rendre : `None` = admis, `Some(ip)` = refusé par la politique du privé pour cette adresse.
    const ATTENDUS: [(&str, &str, Option<&str>); 9] = [
        ("nom suffixe d'un autre", "seule.exemple.test", Some("192.168.40.7")),
        ("la listée passe", "listee-seule.exemple.test", None),
        ("listée puis privée", "listee-puis-privee.exemple.test", Some("192.168.40.7")),
        ("privée puis listée", "privee-puis-listee.exemple.test", Some("192.168.40.7")),
        ("listée puis voisine", "listee-puis-voisine.exemple.test", Some("10.20.0.6")),
        ("listée puis publique", "listee-puis-publique.exemple.test", None),
        ("publique puis listée", "publique-puis-listee.exemple.test", None),
        ("privée seule", "privee-seule.exemple.test", Some("192.168.40.7")),
        ("nom dont un autre est le prolongement", "puis-publique.exemple.test", Some("192.168.40.7")),
    ];

    /// Ce que l'enfant écrit pour une URL, par les deux chaînes : `admis` (et l'appel intercepté), ou le refus entier.
    fn juger_par_les_deux_chaines(url: &str) -> (String, String) {
        let avant = temoin_de_l_egress::vus().len();
        let connecteur = match crate::handlers::connectors::appel_garde_d_un_connecteur(&[], "GET", url, &[], None) {
            Ok(r) if r.status == 200 && temoin_de_l_egress::vus().len() == avant + 1 => "admis".to_string(),
            Ok(r) => format!("admis-sans-interception-{}", r.status),
            Err(e) => e,
        };
        let fil = Wire::Http { method: "POST".into(), url: url.to_string(), headers: Vec::new(), body: b"{}".to_vec() };
        let destination = match dest_transport_pour_l_objet(&fil, &[]) {
            Ok(200) => "admis".to_string(),
            Ok(s) => format!("admis-{s}"),
            Err(e) => e,
        };
        (connecteur, destination)
    }

    /// L'enfant : la table injectée et le témoin de l'égress armés, chaque nom de la table jugé par les deux chaînes.
    fn jouer_dans_l_enfant() {
        println!(); // la première ligne de l'enfant suit l'en-tête de libtest
        let _injectee = resolution_injectee::injecter(&TABLE);
        let _arme = temoin_de_l_egress::armer(|_m, _u| Ok(temoin_de_l_egress::reponse(200, &[], "{}")));
        for (nom, _) in TABLE {
            let (connecteur, destination) = juger_par_les_deux_chaines(&format!("http://{nom}/api"));
            println!("BF5-CONNECTEUR {nom}:{connecteur}");
            println!("BF5-DESTINATION {nom}:{destination}");
        }
        println!("{FIN}");
    }

    /// La valeur de la ligne `CLE:valeur` de l'enfant, présente une seule fois.
    fn lu(stdout: &str, cle: &str) -> Result<String, String> {
        let prefixe = format!("{cle}:");
        let trouves: Vec<&str> = stdout.lines().filter_map(|l| l.strip_prefix(prefixe.as_str())).collect();
        match trouves.as_slice() {
            [v] => Ok(v.to_string()),
            _ => Err(format!("{} ligne(s) {cle}", trouves.len())),
        }
    }

    /// Vide l'environnement `PLUME_*` de la commande DÉJÀ construite par le test.
    fn vider_l_environnement_plume(commande: &mut std::process::Command) {
        for (nom, _) in std::env::vars_os() {
            if nom.to_string_lossy().starts_with("PLUME_") {
                commande.env_remove(&nom);
            }
        }
    }

    /// Lance l'enfant (commande construite et réglée par le test, `current_exe()` et `.env(` dans son corps), puis juge
    /// chaque nom ; l'échec liste chaque assertion rougie, par son nom.
    fn juger(mut commande: std::process::Command, regime: &str) {
        let sortie = commande.output().expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains(FIN), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");

        let mut fautes: Vec<String> = Vec::new();
        for (assertion, nom, attendu) in ATTENDUS {
            let connecteur = lu(&stdout, &format!("BF5-CONNECTEUR {nom}"));
            let destination = lu(&stdout, &format!("BF5-DESTINATION {nom}"));
            let (connecteur, destination) = match (connecteur, destination) {
                (Ok(c), Ok(d)) => (c, d),
                (c, d) => {
                    fautes.push(format!("[{assertion}] {nom} : sortie illisible ({c:?}, {d:?})"));
                    continue;
                }
            };
            if connecteur != destination {
                fautes.push(format!("[{assertion}] {nom} : connecteur « {connecteur} » ≠ destination « {destination} »"));
                continue;
            }
            let voulu = match attendu {
                None => "admis".to_string(),
                Some(ip) => format!("SSRF: adresse privée refusée : '{nom}' résout vers {ip} — {LEVIERS}"),
            };
            if connecteur != voulu {
                fautes.push(format!("[{assertion}] {nom} : voulu « {voulu} », rendu « {connecteur} »"));
            }
        }
        assert!(fautes.is_empty(), "ASSERTIONS ROUGES ({regime}) :\n{}", fautes.join("\n"));
    }

    /// Sous `PLUME_SSRF_BLOCK_PRIVATE=1` : l'adresse listée passe, toute autre adresse privée du même nom est refusée
    /// par la politique du privé, quel que soit l'ordre de la résolution.
    #[test]
    fn bf5_une_exemption_ne_leve_pas_la_politique_du_prive_sous_le_blocage_explicite() {
        if std::env::var(ENFANT).is_ok() {
            jouer_dans_l_enfant();
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // le parent lit l'environnement pour le vider chez l'enfant
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1"])
            .arg(format!("{MODULE}bf5_une_exemption_ne_leve_pas_la_politique_du_prive_sous_le_blocage_explicite"));
        vider_l_environnement_plume(&mut commande);
        commande.env(ENFANT, "1").env("PLUME_SSRF_BLOCK_PRIVATE", "1").env("PLUME_SSRF_ALLOW", LISTE);
        juger(commande, "PLUME_SSRF_BLOCK_PRIVATE=1");
    }

    /// Sous la politique PAR DÉFAUT (levier absent) : une cible de l'API voit le privé refusé, et l'exemption d'une
    /// adresse ne le lève pas davantage pour les autres.
    #[test]
    fn bf5_une_exemption_ne_leve_pas_la_politique_du_prive_sous_la_politique_par_defaut() {
        if std::env::var(ENFANT).is_ok() {
            jouer_dans_l_enfant();
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1"])
            .arg(format!("{MODULE}bf5_une_exemption_ne_leve_pas_la_politique_du_prive_sous_la_politique_par_defaut"));
        vider_l_environnement_plume(&mut commande);
        commande.env(ENFANT, "1").env("PLUME_SSRF_ALLOW", LISTE);
        juger(commande, "politique par défaut, cible de l'API");
    }
}

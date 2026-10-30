// =====================================================================================
// `P7.20-a` — LE FORMAT DE `PLUME_SSRF_ALLOW`, TENU PAR LA VRAIE CHAÎNE D'ENVOI.
//
// L'échappatoire de l'exploitant (daemon/src/ledger.rs : `parse_ssrf_allow`, `ssrf_allowlist`, `ssrf_host_allowed`,
// `ssrf_ip_allowed`) est une liste séparée par des virgules d'hôtes EXACTS, d'adresses nues (une adresse seule) et de
// réseaux `base/N`. Aucun témoin n'en tenait le format : seule la première entrée lue, ou un hôte admis par simple
// suffixe, restaient verts sur toute la famille `p720a|ssrf|host|egress|allow`. Un hôte de la liste court-circuite
// TOUTE la garde, never-egress compris : un contrôle d'hôte assoupli (suffixe, préfixe, parent) ouvre les
// métadonnées cloud à un nom choisi par l'attaquant.
//
// Chaque URL est jugée par le fetch gardé des connecteurs (`appel_garde_d_un_connecteur`, celui de la production, sans
// cible inscrite : l'origine est donc `Api`, que la politique par défaut refuse déjà sur le privé) et par le transport
// d'une destination (`dest_transport_pour_l_objet`), le témoin de l'égress armé (aucun réseau : une URL admise est
// interceptée). `PLUME_SSRF_BLOCK_PRIVATE=1` est posé pour que le verdict ne dépende pas de la politique par défaut ;
// ce n'est pas lui qui rend le témoin non vacant.
//   (a) `PLUME_SSRF_ALLOW="svc.exemple.test,10.20.0.5"` : la DEUXIÈME entrée est appliquée (10.20.0.5 part) ;
//       l'hôte exact part ; un sous-domaine (`sub.svc.exemple.test`), un nom qui COMMENCE par l'entrée
//       (`svc.exemple.test.attaquant.test`) et le domaine PARENT (`exemple.test`) sont REFUSÉS ; les deux voisines de
//       l'adresse nue (10.20.0.6 et 10.20.0.4) sont refusées (une adresse nue ne vaut qu'elle-même, ni /31 ni /24).
//       Sur le chemin de l'adresse RÉSOLUE (`ssrf_ip_allowed`, noms en forme décimale) : un nom qui résout vers
//       10.20.0.5 part ; un nom hors liste qui résout vers 10.99.0.1 est refusé par la politique du privé, `localhost`
//       par le never-egress (une liste non vide n'exempte pas ce qu'elle ne nomme pas) ; les voisines résolues
//       10.20.0.6 et 10.20.0.4 sont refusées (ni /31 ni /24 sur ce chemin non plus).
//   (b) une entrée par trait de forme : réseau `10.30.0.0/16` (sa dernière adresse part, la suivante est refusée),
//       entrée entourée de blancs (`  10.50.0.7  `), entrée vide, entrée en capitales (`SVC.Exemple.TEST` admet
//       l'hôte en minuscules), masque hors borne (`10.40.0.0/33` n'admet rien), masque à la borne (`10.60.0.9/32`
//       admet son adresse).
//   (c) le court-circuit, never-egress compris : `PLUME_SSRF_ALLOW="localhost"` fait partir `localhost` (qui résout
//       vers le loopback) sans résolution ni never-egress, et laisse refusé le littéral `127.0.0.1` qu'il ne nomme
//       pas ; `PLUME_SSRF_ALLOW="127.0.0.1"` fait partir ce littéral loopback, et laisse refusées ses voisines
//       `127.0.0.0` et `127.0.0.2`.
//   (d) la re-vérification de CHAQUE adresse résolue quand la liste n'est pas vide : `localhost` rend `127.0.0.1` ET
//       `::1` ; listé `::1`, il est refusé pour `127.0.0.1` ; listé `127.0.0.1`, il est refusé pour `::1`. Une seule
//       adresse exemptée ne lève pas le jugement des autres, quel que soit l'ordre de la résolution. Aucun point
//       d'entrée ne reçoit une liste résolue toute faite (la boucle de `ssrf_check_host_selon` résout elle-même) :
//       `localhost` est le seul nom qui rende deux adresses sans réseau ; sur une machine où il n'en rend pas deux,
//       les deux témoins (d) refusent de conclure par le canal, ils ne passent pas en silence.
//
// Toutes les assertions d'un cas sont jugées avant l'échec, qui les liste toutes : chaque mutant montre ainsi
// l'ENSEMBLE des assertions qu'il rougit. MUTANTS JOUÉS (un site chacun, posés sous `cfg!(test)` dans ledger.rs,
// destinations.rs et connectors/mod.rs, retirés avant le commit) et ensemble mesuré des assertions rouges :
//   parse_ssrf_allow — P1 (blancs de tête seuls retirés) et P2 (de fin seuls) → blancs ; P3 (casse d'un hôte
//     gardée) → capitales ; P4 (borne IPv6 sur IPv4) → hors borne ; P5 (`/32` refusé) → à la borne ; P6 (adresse
//     nue lue /31) → voisine basse, voisine basse résolue ; P7 (réseau lu comme hôte) → réseau, à la borne ;
//     P8 (entrée vide lue 0.0.0.0/0) → hors réseau, hors borne ;
//   ssrf_allowlist — A1 (première entrée seule) → deuxième entrée, IP résolue, blancs, capitales, à la borne ;
//     A2 (première sautée) → hôte exact, réseau ; A3 (arrêt à l'entrée vide) → capitales, à la borne ;
//   ssrf_host_allowed — H1 (suffixe) → sous-domaine ; H2 (préfixe) → préfixe ; H3 (parent) → parent ; H4 (un nom
//     admis par une entrée réseau) → sous-domaine, préfixe, parent, résolue hors liste, localhost résolu, voisines
//     résolues ; H5 (toutes les entrées exigées) → hôte exact, deuxième entrée, réseau, blancs, capitales, à la borne ;
//   ssrf_ip_allowed (chemin RÉSOLU) — I1 (`return !ssrf_allowlist().is_empty()`) → résolue hors liste, localhost
//     résolu, voisine haute résolue, voisine basse résolue ; I2 (masque lu /24 au plus) → voisine haute résolue,
//     voisine basse résolue ; I4 (masque lu /31 au plus) → voisine basse résolue ; I3 (IP résolue jamais exemptée)
//     → IP résolue ;
//   ip_in_cidr — N1 (masque d'un bit trop large) → hors réseau ; N2 (d'un bit trop étroit) → réseau ;
//   ssrf_check_host_selon — C2 (liste ignorée) → hôte exact, deuxième entrée, réseau, blancs, capitales, à la borne ;
//   chaînes d'envoi — D1 (destination sans garde) et K1 (connecteur sans garde) → chaque refus des deux cas.
//   ssrf_check_host_selon, court-circuit (c) — E1 (never-egress du littéral jugé avant la liste) → loopback listé ;
//     E2 (seul un littéral listé court-circuite, un nom va à la résolution) → nom listé vers le loopback, hôte exact,
//     capitales ; E3 (aucun court-circuit) → nom listé vers le loopback, loopback listé, hôte exact, deuxième entrée,
//     réseau, blancs, capitales, à la borne ; ssrf_host_allowed — E4 (une entrée nom admet tout littéral) → littéral
//     non listé, voisines haute et basse, hors réseau, hors borne ; parse_ssrf_allow — E5 (adresse nue lue /31) →
//     voisine basse, voisine basse résolue, voisine basse du loopback listé ; E6 (lue /30) → les mêmes et les trois
//     voisines hautes ;
//   boucle de résolution (d) — R_RETOUR_TOT (`return Ok` à la première adresse exemptée au lieu de `continue`) → le
//     témoin (d) dont l'adresse listée est rendue EN PREMIER par la résolution (mesuré : `::1` d'abord, donc
//     « résolue après l'exemption de ::1 ») ; I1 → aussi les deux témoins (d).
//
// La liste est figée au premier usage (OnceLock) : chaque valeur se joue dans un SOUS-PROCESSUS, environnement
// `PLUME_*` vidé, puis réglé.
// =====================================================================================
mod liste_d_exemption_ssrf_lue_entree_par_entree {
    use crate::handlers::destinations::{dest_transport_pour_l_objet, Wire};
    use crate::ledger::temoin_de_l_egress;

    const MODULE: &str = "tests::liste_d_exemption_ssrf_lue_entree_par_entree::";
    const ENFANT: &str = "BC6_ENFANT_LISTE_SSRF";
    const URLS: &str = "BC6_URLS";
    const FIN: &str = "BC6-LISTE-SSRF-A-JOUE";
    const LISTE_DE_L_ENONCE: &str = "svc.exemple.test,10.20.0.5";
    const LISTE_DE_FORME: &str = "10.30.0.0/16,  10.50.0.7  ,,SVC.Exemple.TEST,10.40.0.0/33,10.60.0.9/32";
    const LISTE_D_UN_NOM_INTERNE: &str = "localhost";
    const LISTE_DU_LOOPBACK_V4: &str = "127.0.0.1";
    const LISTE_DU_LOOPBACK_V6: &str = "::1";
    const LEVIERS: &str = "PLUME_SSRF_ALLOW (hôte ou CIDR) l'admet, PLUME_SSRF_BLOCK_PRIVATE=0 admet toute adresse privée";

    /// Ce que l'enfant écrit pour une URL : `admis` (et l'appel intercepté), ou le refus de la garde, entier.
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

    /// L'enfant : chaque URL de `BC6_URLS` (séparées par `|`), sous le témoin de l'égress armé.
    fn jouer_dans_l_enfant() {
        println!(); // la première ligne de l'enfant suit l'en-tête de libtest
        let _arme = temoin_de_l_egress::armer(|_m, _u| Ok(temoin_de_l_egress::reponse(200, &[], "{}")));
        let urls = std::env::var(URLS).expect("URL à juger");
        for url in urls.split('|') {
            let (connecteur, destination) = juger_par_les_deux_chaines(url);
            println!("BC6-CONNECTEUR {url}:{connecteur}");
            println!("BC6-DESTINATION {url}:{destination}");
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

    /// Ce qu'une URL doit rendre.
    enum Attendu {
        Admis,
        /// Refus de la politique du privé, pour cet hôte.
        RefusPrive(&'static str),
        /// Pas d'exemption : le nom va à la résolution, qui échoue (`.test` réservé).
        RefusResolution(&'static str),
        /// Chemin de l'adresse RÉSOLUE (`ssrf_ip_allowed`) : ce nom résout vers cette adresse privée, refusée.
        RefusPriveResolu(&'static str, &'static str),
        /// Chemin de l'adresse RÉSOLUE : ce nom résout vers le loopback (`127.0.0.1` ou `::1`), never-egress.
        RefusInterneResolu(&'static str),
        /// Chemin de l'adresse RÉSOLUE : ce nom résout vers CETTE adresse never-egress, nommée dans le refus.
        RefusInterneResoluVers(&'static str, &'static str),
        /// Chemin du LITTÉRAL : cette adresse never-egress (loopback), refusée avant toute résolution.
        RefusInterneLitteral(&'static str),
    }

    /// Vide l'environnement `PLUME_*` de la commande DÉJÀ construite par le test (l'enfant ne voit que ce que le test
    /// lui pose ensuite).
    fn vider_l_environnement_plume(commande: &mut std::process::Command) {
        for (nom, _) in std::env::vars_os() {
            if nom.to_string_lossy().starts_with("PLUME_") {
                commande.env_remove(&nom);
            }
        }
    }

    /// Les URL de la table, telles que l'enfant les lit dans `BC6_URLS`.
    fn urls_de(cas: &[(&str, &str, Attendu)]) -> String {
        cas.iter().map(|(_, url, _)| *url).collect::<Vec<_>>().join("|")
    }

    /// Lance l'enfant (commande construite et réglée par le test, `current_exe()` et `.env(` dans son corps), puis juge
    /// TOUTES les URL ; l'échec liste chaque assertion rougie, par son nom.
    fn juger(mut commande: std::process::Command, liste: &str, cas: &[(&str, &str, Attendu)]) {
        let sortie = commande.output().expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert!(stdout.contains(FIN), "contrôle : l'enfant a joué jusqu'au bout : {stdout}\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");

        let mut fautes: Vec<String> = Vec::new();
        for (assertion, url, attendu) in cas {
            let connecteur = lu(&stdout, &format!("BC6-CONNECTEUR {url}"));
            let destination = lu(&stdout, &format!("BC6-DESTINATION {url}"));
            let (connecteur, destination) = match (connecteur, destination) {
                (Ok(c), Ok(d)) => (c, d),
                (c, d) => {
                    fautes.push(format!("[{assertion}] {url} : sortie illisible ({c:?}, {d:?})"));
                    continue;
                }
            };
            if connecteur != destination {
                fautes.push(format!("[{assertion}] {url} : connecteur « {connecteur} » ≠ destination « {destination} »"));
                continue;
            }
            let tenu = match attendu {
                Attendu::Admis => connecteur == "admis",
                Attendu::RefusPrive(hote) => connecteur == format!("SSRF: adresse privée refusée ({hote}) — {LEVIERS}"),
                Attendu::RefusResolution(hote) => {
                    connecteur.starts_with(&format!("SSRF: résolution de '{hote}' impossible (deny)"))
                }
                Attendu::RefusPriveResolu(hote, ip) => {
                    connecteur == format!("SSRF: adresse privée refusée : '{hote}' résout vers {ip} — {LEVIERS}")
                }
                Attendu::RefusInterneResolu(hote) => ["127.0.0.1", "::1"]
                    .iter()
                    .any(|ip| connecteur == format!("SSRF: '{hote}' résout vers une adresse interne ({ip}) — refus")),
                Attendu::RefusInterneResoluVers(hote, ip) => {
                    connecteur == format!("SSRF: '{hote}' résout vers une adresse interne ({ip}) — refus")
                }
                Attendu::RefusInterneLitteral(hote) => connecteur == format!("SSRF: cible interne interdite ({hote})"),
            };
            if !tenu {
                let voulu = match attendu {
                    Attendu::Admis => "admis".to_string(),
                    Attendu::RefusPrive(h) => format!("refus du privé ({h})"),
                    Attendu::RefusResolution(h) => format!("refus à la résolution ({h})"),
                    Attendu::RefusPriveResolu(h, ip) => format!("refus du privé résolu ({h} → {ip})"),
                    Attendu::RefusInterneResolu(h) => format!("refus du loopback résolu ({h})"),
                    Attendu::RefusInterneResoluVers(h, ip) => format!("refus du loopback résolu ({h} → {ip})"),
                    Attendu::RefusInterneLitteral(h) => format!("refus du loopback littéral ({h})"),
                };
                fautes.push(format!("[{assertion}] {url} : voulu {voulu}, rendu « {connecteur} »"));
            }
        }
        assert!(fautes.is_empty(), "ASSERTIONS ROUGES sous PLUME_SSRF_ALLOW={liste:?} :\n{}", fautes.join("\n"));
    }

    /// (a) La liste de l'énoncé : deuxième entrée appliquée, hôte exact seulement, adresse nue seule — sur le chemin du
    /// LITTÉRAL (`ssrf_host_allowed`) comme sur celui de l'adresse RÉSOLUE (`ssrf_ip_allowed`).
    #[test]
    fn bc6_la_liste_d_exemption_applique_chaque_entree_et_l_hote_exact_seul() {
        if std::env::var(ENFANT).is_ok() {
            jouer_dans_l_enfant();
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // le parent lit l'environnement pour le vider chez l'enfant
        use Attendu::*;
        // Les noms en chiffres sont des adresses en forme décimale (inet_aton) : des NOMS pour la garde, que la
        // résolution rend sans réseau ; ils passent donc par le chemin de l'adresse RÉSOLUE.
        let cas = [
            ("deuxième entrée", "http://10.20.0.5:8080/api", Admis),
            ("hôte exact", "http://svc.exemple.test/api", Admis),
            ("sous-domaine", "http://sub.svc.exemple.test/api", RefusResolution("sub.svc.exemple.test")),
            ("préfixe", "http://svc.exemple.test.attaquant.test/api", RefusResolution("svc.exemple.test.attaquant.test")),
            ("parent", "http://exemple.test/api", RefusResolution("exemple.test")),
            ("voisine haute", "http://10.20.0.6/api", RefusPrive("10.20.0.6")),
            ("voisine basse", "http://10.20.0.4/api", RefusPrive("10.20.0.4")),
            // 169082885 = 10.20.0.5.
            ("IP résolue", "http://169082885/api", Admis),
            // 174260225 = 10.99.0.1 : un nom HORS liste qui résout vers une adresse privée éloignée de toute entrée.
            ("résolue hors liste", "http://174260225/api", RefusPriveResolu("174260225", "10.99.0.1")),
            // `localhost` résout vers le loopback : la liste non vide n'exempte pas une adresse qu'elle ne nomme pas.
            ("localhost résolu", "http://localhost/api", RefusInterneResolu("localhost")),
            // 169082886 = 10.20.0.6 et 169082884 = 10.20.0.4 : les voisines de l'adresse nue, sur le chemin résolu.
            ("voisine haute résolue", "http://169082886/api", RefusPriveResolu("169082886", "10.20.0.6")),
            ("voisine basse résolue", "http://169082884/api", RefusPriveResolu("169082884", "10.20.0.4")),
        ];
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1"])
            .arg(format!("{MODULE}bc6_la_liste_d_exemption_applique_chaque_entree_et_l_hote_exact_seul"));
        vider_l_environnement_plume(&mut commande);
        commande
            .env(ENFANT, "1")
            .env(URLS, urls_de(&cas))
            .env("PLUME_SSRF_BLOCK_PRIVATE", "1")
            .env("PLUME_SSRF_ALLOW", LISTE_DE_L_ENONCE);
        juger(commande, LISTE_DE_L_ENONCE, &cas);
    }

    /// (b) La forme d'une entrée : réseau et ses bords, blancs, entrée vide, capitales, masque hors borne et à la borne.
    #[test]
    fn bc6_la_forme_des_entrees_de_la_liste_d_exemption() {
        if std::env::var(ENFANT).is_ok() {
            jouer_dans_l_enfant();
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        use Attendu::*;
        let cas = [
            ("réseau", "http://10.30.255.255/api", Admis),
            ("hors réseau", "http://10.31.0.0/api", RefusPrive("10.31.0.0")),
            ("blancs", "http://10.50.0.7/api", Admis),
            ("capitales", "http://svc.exemple.test/api", Admis),
            ("hors borne", "http://10.40.0.0/api", RefusPrive("10.40.0.0")),
            ("à la borne", "http://10.60.0.9/api", Admis),
        ];
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1"])
            .arg(format!("{MODULE}bc6_la_forme_des_entrees_de_la_liste_d_exemption"));
        vider_l_environnement_plume(&mut commande);
        commande
            .env(ENFANT, "1")
            .env(URLS, urls_de(&cas))
            .env("PLUME_SSRF_BLOCK_PRIVATE", "1")
            .env("PLUME_SSRF_ALLOW", LISTE_DE_FORME);
        juger(commande, LISTE_DE_FORME, &cas);
    }

    /// Les adresses vers lesquelles `localhost` résout sur cette machine (vide si la résolution échoue).
    fn adresses_de_localhost() -> Vec<std::net::IpAddr> {
        use std::net::ToSocketAddrs;
        ("localhost", 80u16).to_socket_addrs().map(|a| a.map(|s| s.ip()).collect()).unwrap_or_default()
    }

    /// `localhost` rend-il les DEUX loopbacks (`127.0.0.1` et `::1`) ? Sinon, aucun nom de la machine ne rend deux
    /// adresses dont une seule est listée, et le témoin (d) ne peut pas voir.
    fn localhost_rend_les_deux_loopbacks() -> Result<(), String> {
        let resolues = adresses_de_localhost();
        let v4: std::net::IpAddr = "127.0.0.1".parse().expect("adresse");
        let v6: std::net::IpAddr = "::1".parse().expect("adresse");
        if resolues.contains(&v4) && resolues.contains(&v6) {
            Ok(())
        } else {
            Err(format!(
                "`localhost` ne résout pas vers 127.0.0.1 ET ::1 sur cette machine ({resolues:?}) : aucun nom n'y rend deux \
                 adresses dont une seule est listée, la re-vérification de chaque adresse résolue n'est pas jugée"
            ))
        }
    }

    /// (c) Un NOM de la liste court-circuite toute la garde, never-egress compris : `localhost` listé part alors qu'il
    /// résout vers le loopback ; le littéral `127.0.0.1`, que la liste ne nomme pas, reste refusé.
    #[test]
    fn be4_un_nom_liste_court_circuite_la_resolution_et_le_never_egress() {
        if std::env::var(ENFANT).is_ok() {
            jouer_dans_l_enfant();
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        use Attendu::*;
        let cas = [
            ("nom listé vers le loopback", "http://localhost/api", Admis),
            ("littéral non listé", "http://127.0.0.1/api", RefusInterneLitteral("127.0.0.1")),
        ];
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1"])
            .arg(format!("{MODULE}be4_un_nom_liste_court_circuite_la_resolution_et_le_never_egress"));
        vider_l_environnement_plume(&mut commande);
        commande
            .env(ENFANT, "1")
            .env(URLS, urls_de(&cas))
            .env("PLUME_SSRF_BLOCK_PRIVATE", "1")
            .env("PLUME_SSRF_ALLOW", LISTE_D_UN_NOM_INTERNE);
        juger(commande, LISTE_D_UN_NOM_INTERNE, &cas);
    }

    /// (c) Une ADRESSE nue de la liste court-circuite le never-egress du littéral : `127.0.0.1` listé part ; ses
    /// voisines `127.0.0.0` et `127.0.0.2`, loopback elles aussi, restent refusées (l'adresse nue ne vaut qu'elle-même).
    #[test]
    fn be4_une_adresse_listee_court_circuite_le_never_egress_du_litteral() {
        if std::env::var(ENFANT).is_ok() {
            jouer_dans_l_enfant();
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        use Attendu::*;
        let cas = [
            ("loopback listé", "http://127.0.0.1:8080/api", Admis),
            ("voisine basse du loopback listé", "http://127.0.0.0/api", RefusInterneLitteral("127.0.0.0")),
            ("voisine haute du loopback listé", "http://127.0.0.2/api", RefusInterneLitteral("127.0.0.2")),
        ];
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1"])
            .arg(format!("{MODULE}be4_une_adresse_listee_court_circuite_le_never_egress_du_litteral"));
        vider_l_environnement_plume(&mut commande);
        commande
            .env(ENFANT, "1")
            .env(URLS, urls_de(&cas))
            .env("PLUME_SSRF_BLOCK_PRIVATE", "1")
            .env("PLUME_SSRF_ALLOW", LISTE_DU_LOOPBACK_V4);
        juger(commande, LISTE_DU_LOOPBACK_V4, &cas);
    }

    /// (d) CHAQUE adresse résolue est re-jugée : `::1` listé, `localhost` (qui rend `::1` ET `127.0.0.1`) est refusé
    /// pour `127.0.0.1`, quel que soit l'ordre de la résolution.
    #[test]
    fn be4_chaque_adresse_resolue_est_rejugee_apres_l_exemption_de_l_ipv6() {
        if std::env::var(ENFANT).is_ok() {
            jouer_dans_l_enfant();
            return;
        }
        if let Err(cause) = localhost_rend_les_deux_loopbacks() {
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "be4_chaque_adresse_resolue_est_rejugee_apres_l_exemption_de_l_ipv6",
                &cause,
            );
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        use Attendu::*;
        let cas = [("résolue après l'exemption de ::1", "http://localhost/api", RefusInterneResoluVers("localhost", "127.0.0.1"))];
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1"])
            .arg(format!("{MODULE}be4_chaque_adresse_resolue_est_rejugee_apres_l_exemption_de_l_ipv6"));
        vider_l_environnement_plume(&mut commande);
        commande
            .env(ENFANT, "1")
            .env(URLS, urls_de(&cas))
            .env("PLUME_SSRF_BLOCK_PRIVATE", "1")
            .env("PLUME_SSRF_ALLOW", LISTE_DU_LOOPBACK_V6);
        juger(commande, LISTE_DU_LOOPBACK_V6, &cas);
    }

    /// (d) Le même, l'autre loopback listé : `127.0.0.1` listé, `localhost` est refusé pour `::1`. L'un des deux
    /// témoins (d) liste l'adresse que la résolution rend EN PREMIER : c'est lui qui rougit sous R_RETOUR_TOT.
    #[test]
    fn be4_chaque_adresse_resolue_est_rejugee_apres_l_exemption_de_l_ipv4() {
        if std::env::var(ENFANT).is_ok() {
            jouer_dans_l_enfant();
            return;
        }
        if let Err(cause) = localhost_rend_les_deux_loopbacks() {
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "be4_chaque_adresse_resolue_est_rejugee_apres_l_exemption_de_l_ipv4",
                &cause,
            );
            return;
        }
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        use Attendu::*;
        let cas = [("résolue après l'exemption de 127.0.0.1", "http://localhost/api", RefusInterneResoluVers("localhost", "::1"))];
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande
            .args(["--exact", "--nocapture", "--test-threads=1"])
            .arg(format!("{MODULE}be4_chaque_adresse_resolue_est_rejugee_apres_l_exemption_de_l_ipv4"));
        vider_l_environnement_plume(&mut commande);
        commande
            .env(ENFANT, "1")
            .env(URLS, urls_de(&cas))
            .env("PLUME_SSRF_BLOCK_PRIVATE", "1")
            .env("PLUME_SSRF_ALLOW", LISTE_DU_LOOPBACK_V4);
        juger(commande, LISTE_DU_LOOPBACK_V4, &cas);
    }
}

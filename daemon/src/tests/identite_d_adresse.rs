// =================================================================================================
// `P4.7-g` / `P4.7-h` / `P4.7-i` / `P4.7-j` / `P4.7-k` — L'IDENTITÉ D'UNE ADRESSE EST SA VALEUR
//
// L'INVARIANT, ET SA MOITIÉ QUI MANQUAIT. L'identité d'une adresse est sa VALEUR, jamais son
// ÉCRITURE — et une chaîne dont on ne sait pas lire la valeur n'est pas une adresse, donc pas une
// cible. Corollaire, écrit parce qu'il est le seul à sauver le débruitage des panneaux :
// l'AFFICHAGE, lui, continue de comparer des CHAÎNES (c'est la bonne réponse pour rendre un
// `NOT LIKE 'préfixe%'`), et les deux politiques ne partagent plus d'analyseur.
//
// POURQUOI CE FICHIER EXISTE PLUTÔT QU'UNE LIGNE AJOUTÉE AILLEURS. La moitié de la protection
// attaquée par `P4.7-g` — la moitié CONFIGURÉE — était exactement la moitié SANS AUCUN TÉMOIN
// POSITIF, et la RAISON était MÉCANIQUE : `protected_ip_matchers()` est un `OnceLock` sur
// `load_config()`, donc inexerçable sans toucher l'environnement du processus. Les deux seules
// assertions qui existaient sur elle étaient NÉGATIVES et faites LISTE VIDE (`ingest.rs`,
// `governance.rs`). Un correctif validé sur la moitié DÉRIVÉE serait passé vert sans rien fermer :
// c'est la mécanique d'angle mort que `P4.7-b` a déjà payée une fois. Le cœur pur
// `ip_is_protected_ctx(ip, denylist)` est ce qui rend cette moitié exerçable.
//
// CE QUE CES TÉMOINS NE PROUVENT PAS, ÉCRIT PLUTÔT QUE SOUS-ENTENDU :
//   * RIEN sur la corrélation et la détection, qui tranchent TOUJOURS l'identité sur la chaîne
//     (`LEFT JOIN banned_ip ON b.src_ip=a.src_ip`, `GROUP BY src_ip`, `COUNT(DISTINCT src_ip)`,
//     entité RBA, `ti_lookup_key`). Un attaquant vu sous deux notations y reste DEUX entités ;
//   * RIEN sur ce que `nft`, `cscli` ou `fail2ban-client` font d'un littéral donné — aucun des
//     trois n'est présent dans ce dépôt ;
//   * RIEN hors de `daemon/` : ni l'agent, ni les collecteurs de messagerie/syslog, ni
//     `guatx-core::ti::normalize_ioc`, qui porte une SIXIÈME définition de « ceci est une adresse ».
// =================================================================================================

/// Racine du dépôt (le crate est `daemon/`), pour lire le corpus partagé.
fn racine_pour_corpus_d_adresse() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("INSTRUMENT : le crate n'a pas de répertoire parent")
        .to_path_buf()
}

/// Les chaînes du corpus partagé `collectors/predicat-adresse.corpus`, première colonne seule.
/// REFUSE DE CONCLURE si le fichier manque, est vide, ou ne porte plus les DEUX familles : une
/// propriété métamorphique jouée sur un corpus vide est verte en n'exerçant rien.
fn chaines_du_corpus_partage() -> Vec<String> {
    let chemin = racine_pour_corpus_d_adresse().join("collectors").join("predicat-adresse.corpus");
    let texte = std::fs::read_to_string(&chemin).unwrap_or_else(|e| {
        panic!("INSTRUMENT : corpus partagé illisible ({}) : {e} — ce témoin REFUSE de conclure", chemin.display())
    });
    let mut v = Vec::new();
    for brute in texte.lines() {
        if brute.starts_with('#') || brute.trim().is_empty() { continue; }
        let champs: Vec<&str> = brute.split('\t').collect();
        assert_eq!(champs.len(), 3, "INSTRUMENT : ligne de corpus mal formée : {brute:?}");
        v.push(champs[0].to_string());
    }
    assert!(v.len() >= 25, "INSTRUMENT : corpus trop maigre ({}) — ce témoin REFUSE de conclure", v.len());
    let analysables: Vec<&String> = v.iter().filter(|s| ssrf_norm_ip(s).is_some()).collect();
    assert!(analysables.iter().any(|s| ssrf_norm_ip(s).unwrap().is_ipv4()),
            "INSTRUMENT : plus aucune adresse v4 analysable dans le corpus — REFUS DE CONCLURE");
    assert!(analysables.iter().any(|s| ssrf_norm_ip(s).unwrap().is_ipv6()),
            "INSTRUMENT : plus aucune adresse v6 analysable dans le corpus — REFUS DE CONCLURE");
    v
}

/// TOUTES LES ÉCRITURES D'UNE MÊME VALEUR, ENGENDRÉES DEPUIS LA VALEUR — jamais une table de couples.
/// Une ligne ajoutée demain au corpus est couverte sans être nommée.
fn ecritures_de_la_meme_valeur(v: std::net::IpAddr) -> Vec<String> {
    use std::net::IpAddr;
    let mut out = vec![v.to_string()];
    match v {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            let (h, b) = (u16::from_be_bytes([o[0], o[1]]), u16::from_be_bytes([o[2], o[3]]));
            out.push(format!("::ffff:{v4}"));                       // mappée pointée
            out.push(format!("::FFFF:{v4}"));                       // mappée pointée MAJUSCULE
            out.push(format!("0:0:0:0:0:ffff:{v4}"));               // mappée EXPANSÉE
            out.push(format!("::ffff:{h:x}:{b:x}"));                // mappée HEXADÉCIMALE
            out.push(format!("::ffff:{h:04x}:{b:04x}"));            // mappée hexa à zéros de tête
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            out.push(v6.to_string().to_ascii_uppercase());           // compressée MAJUSCULE
            out.push(format!("{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
                             s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7])); // EXPANSÉE
            out.push(format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                             s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7])); // expansée sans zéros
        }
    }
    out
}

/// T1 — LA PROPRIÉTÉ EST MÉTAMORPHIQUE, ET LA GARDE EST UN GÉNÉRATEUR, PAS UNE TABLE DE COUPLES.
/// Pour chaque ligne du corpus partagé qui s'ANALYSE, toutes les réécritures de la MÊME valeur
/// doivent recevoir le MÊME verdict de `ip_is_protected_ctx`, sous un jeu de matchers tiré du
/// corpus LUI-MÊME. Aucune paire n'est écrite ici.
///
/// AVANT CE LOT (mesuré) : la moitié CONFIGURÉE comparait `low.starts_with(chaîne)`. Avec un matcher
/// `203.0.113.7`, la chaîne `::ffff:203.0.113.7` — DÉJÀ dans ce corpus depuis le 2026-08-28, mais
/// posée sous une AUTRE question — ne l'appariait pas : elle traversait la protection ET restait une
/// cible de ban acceptée. Ce témoin est donc ROUGE sur l'arbre d'avant.
///
/// ANTI-VACUITÉ INDISPENSABLE : une fonction CONSTANTE satisferait la propriété métamorphique seule.
/// Sous matchers NON VIDES on exige donc au moins une adresse PROTÉGÉE et au moins une NON protégée.
#[test]
fn identite_adresse_invariante_par_reecriture() {
    let corpus = chaines_du_corpus_partage();
    // Les matchers sont TIRÉS DU CORPUS : chaque adresse PUBLIQUE analysable y devient un réseau
    // hôte (/32 | /128). Les plages réservées sont écartées — elles sont protégées par la moitié
    // DÉRIVÉE de toute façon, et les inclure rendrait le verdict insensible aux matchers.
    let mut matchers: Vec<(std::net::IpAddr, u32)> = Vec::new();
    for s in &corpus {
        if let Some(v) = ssrf_norm_ip(s) {
            if ip_never_egress(v) || ip_is_rfc1918(v) { continue; }
            let bits = if v.is_ipv4() { 32 } else { 128 };
            if !matchers.contains(&(v, bits)) { matchers.push((v, bits)); }
        }
    }
    assert!(matchers.len() >= 3, "INSTRUMENT : {} matcher(s) tiré(s) du corpus — REFUS DE CONCLURE", matchers.len());

    let mut exercees = 0usize;
    for s in &corpus {
        let v = match ssrf_norm_ip(s) { Some(v) => v, None => continue };
        let ecritures = ecritures_de_la_meme_valeur(v);
        assert!(ecritures.len() >= 4, "INSTRUMENT : générateur dégénéré sur {v}");
        let reference = ip_is_protected_ctx(&ecritures[0], &matchers);
        for e in &ecritures {
            assert_eq!(ip_is_protected_ctx(e, &matchers), reference,
                       "« {e} » et « {} » sont la MÊME valeur ({v}) : le verdict de protection DOIT être identique \
                        (ligne de corpus : {s})", ecritures[0]);
            exercees += 1;
        }
    }
    assert!(exercees >= 40, "INSTRUMENT : seules {exercees} écritures exercées — REFUS DE CONCLURE");

    // ANTI-VACUITÉ : au moins une protégée ET au moins une non protégée, matchers NON VIDES.
    assert!(ip_is_protected_ctx("203.0.113.7", &matchers),
            "l'IP d'exemple de l'opérateur est dans les matchers -> PROTÉGÉE");
    assert!(!ip_is_protected_ctx("203.0.113.8", &matchers),
            "sa voisine n'y est pas -> NON protégée (sans quoi ce témoin serait satisfait par une constante)");
    // Et la moitié DÉRIVÉE est INCHANGÉE — c'est un témoin, pas une intention.
    for reservee in ["127.0.0.1", "::1", "10.0.0.5", "169.254.169.254", "fc00::1", "::ffff:127.0.0.1"] {
        assert!(ip_is_protected_ctx(reservee, &[]), "{reservee} : plage réservée protégée SANS aucune configuration");
    }
}

/// T2 — LA LARGEUR PROTÉGÉE EST CELLE QUI A ÉTÉ ÉCRITE (`P4.7-i`). Les quatre bornes sont DÉRIVÉES
/// de l'arithmétique du masque, dans CE témoin, sans passer par la fonction du produit : base et
/// dernière adresse du réseau -> PROTÉGÉES ; base−1 et dernière+1 -> NON protégées. Positif et
/// négatif intégrés par construction.
///
/// C'EST LE SEUL TÉMOIN QUI ATTRAPE LES DEUX DIRECTIONS À LA FOIS :
///   * SUR-protection silencieuse — `203.0.113.0/25` devenait le préfixe textuel `"203.0.113."`,
///     donc tout le /24 : `203.0.113.128` était protégée sans que personne ne l'ait demandé, et une
///     protection sur-large est un TROU D'ENFORCEMENT (un ban légitime refusé en silence) ;
///   * SOUS-protection — `128.0.0.0/1` retombait sur une ÉGALITÉ EXACTE (octets = 0) et ne
///     protégeait qu'UNE adresse. Il est désormais REFUSÉ (plancher /8) plutôt qu'accepté déformé.
#[test]
fn la_largeur_protegee_est_celle_ecrite() {
    // (item écrit, base attendue, bits attendus) — des plages de DOCUMENTATION (RFC 5737 / 3849),
    // PUBLIQUES : la moitié DÉRIVÉE n'y répond pas, donc c'est bien la moitié CONFIGURÉE qu'on mesure.
    let acceptes: &[(&str, &str, u32)] = &[
        ("203.0.113.0/25", "203.0.113.0", 25),
        ("198.51.100.0/23", "198.51.100.0", 23),
        ("192.0.2.0/24", "192.0.2.0", 24),
        ("203.0.113.*", "203.0.113.0", 24),
        ("203.0.113.7", "203.0.113.7", 32),
        ("2001:db8::/64", "2001:db8::", 64),
        ("2001:db8:*", "2001:db8::", 32),
    ];
    let mut bornes_exercees = 0usize;
    for (item, base_attendue, bits_attendus) in acceptes {
        let (net, bits) = parse_protected_item(item)
            .unwrap_or_else(|| panic!("« {item} » : item non vide, il doit rendre un verdict"))
            .unwrap_or_else(|e| panic!("« {item} » DOIT être accepté : {e}"));
        assert_eq!(bits, *bits_attendus, "« {item} » : largeur");
        let denylist = vec![(net, bits)];
        // LES QUATRE BORNES, DÉRIVÉES ICI, PAR L'ARITHMÉTIQUE DU MASQUE.
        match net {
            std::net::IpAddr::V4(_) => {
                let n: u32 = base_attendue.parse::<std::net::Ipv4Addr>().unwrap().into();
                let m: u32 = if bits >= 32 { u32::MAX } else { u32::MAX << (32 - bits) };
                let (base, dernier) = (n & m, (n & m) | !m);
                assert_eq!(base, n, "« {item} » : la base attendue n'est pas alignée sur le masque");
                for (val, attendu) in [(base, true), (dernier, true), (base - 1, false), (dernier + 1, false)] {
                    let s = std::net::Ipv4Addr::from(val).to_string();
                    assert_eq!(ip_is_protected_ctx(&s, &denylist), attendu,
                               "« {item} » ({net}/{bits}) : {s} devrait être {}",
                               if attendu { "PROTÉGÉE" } else { "NON protégée" });
                    bornes_exercees += 1;
                }
            }
            std::net::IpAddr::V6(_) => {
                let n: u128 = base_attendue.parse::<std::net::Ipv6Addr>().unwrap().into();
                let m: u128 = if bits >= 128 { u128::MAX } else { u128::MAX << (128 - bits) };
                let (base, dernier) = (n & m, (n & m) | !m);
                assert_eq!(base, n, "« {item} » : la base attendue n'est pas alignée sur le masque");
                for (val, attendu) in [(base, true), (dernier, true), (base - 1, false), (dernier + 1, false)] {
                    let s = std::net::Ipv6Addr::from(val).to_string();
                    assert_eq!(ip_is_protected_ctx(&s, &denylist), attendu,
                               "« {item} » ({net}/{bits}) : {s} devrait être {}",
                               if attendu { "PROTÉGÉE" } else { "NON protégée" });
                    bornes_exercees += 1;
                }
            }
        }
    }
    assert_eq!(bornes_exercees, acceptes.len() * 4, "INSTRUMENT : toutes les bornes n'ont pas été jouées");

    // LA DIRECTION « ON PROTÈGE MOINS », NOMMÉE ET MESURÉE. `172.16.0.0/12` devenait le préfixe
    // textuel `"172."` : tout 172/8 était protégé, soit SEIZE fois le réseau écrit. `172.15.0.1`
    // n'est ni RFC1918 ni dans le /12 — elle ÉTAIT protégée, elle ne l'est plus, et un ban jusqu'ici
    // refusé en silence partira. C'est le seul geste du lot qui RETIRE une protection écrite.
    let douze = vec![parse_protected_item("172.16.0.0/12").unwrap().unwrap()];
    assert!(!ip_is_protected_ctx("172.15.0.1", &douze),
            "AVANT : « 172. » protégeait tout 172/8 — APRÈS : seul le /12 écrit est protégé");
    assert!(ip_is_protected_ctx("172.16.0.1", &douze), "le réseau ÉCRIT, lui, est bien protégé");

    // ET L'AUTRE DIRECTION AU MÊME ENDROIT : la sur-protection d'un /25 est fermée, mais le /25
    // écrit protège TOUJOURS ses 128 adresses (on n'a pas remplacé un trou par un autre).
    let vingtcinq = vec![parse_protected_item("203.0.113.0/25").unwrap().unwrap()];
    assert!(ip_is_protected_ctx("203.0.113.127", &vingtcinq), "dernière adresse du /25 protégée");
    assert!(!ip_is_protected_ctx("203.0.113.128", &vingtcinq),
            "AVANT : « 203.0.113. » protégeait tout le /24 (x2) — un ban légitime était refusé en silence");
}

/// UNE NOTATION QUE LE PRODUIT NE SAIT PAS HONORER SE REFUSE, ELLE NE S'ACCEPTE PAS DÉFORMÉE
/// (`P4.7-i`). Chaque refus NOMME l'item et sa raison ; aucun ne devient un matcher inerte.
///
/// LE REFUS EST LA SEULE DIRECTION DU LOT QUI VA VERS LE VERROUILLAGE : il RETIRE une protection que
/// l'exploitant a ÉCRITE. Le fait qu'il soit bruyant (registre never-ban + entrée de journal au
/// démarrage) ne l'annule pas — il exige un accusé de réception AVANT le premier démarrage.
#[test]
fn la_denylist_refuse_ce_qu_elle_ne_sait_pas_honorer() {
    // (item, fragment attendu dans la raison) — le fragment vise la CAUSE, pas la formulation.
    let refuses: &[(&str, &str)] = &[
        ("8*", "frontière"),                 // joker hors frontière : exempterait 8.x ET 80-89.x
        ("203.0.113.7*", "frontière"),       // joker au milieu d'un octet
        ("2001:db*", "frontière"),           // joker hors frontière d'hextet
        ("*", "tout l'espace"),              // joker seul
        ("128.0.0.0/1", "plancher"),         // sous le plancher /8 : la moitié d'Internet
        ("10.0.0.0/4", "plancher"),          // idem
        ("fc00::/7", "plancher"),            // sous le plancher /16 (v6)
        ("soc.example.com", "NOM D'HÔTE"),   // un nom ne protège aucune adresse ici
        ("1.2.3", "NOM D'HÔTE"),             // faute de frappe : lue comme un nom, donc refusée
        ("203.0.113.7/64", "ni CIDR"),        // masque v6 sur une base v4 -> /64 > /32 : pas un réseau
        // REPRISE 2026-08-29 — LE JOKER NE RETIRE PLUS QU'UN SEUL SÉPARATEUR DE FRONTIÈRE.
        // `trim_end_matches` les retirait TOUS, et le contrôle de vacuité tournait ensuite sur un
        // corps DÉJÀ rogné : `10..*` était ACCEPTÉ et rendu `10.0.0.0/8`, `2001:db8:::*` ACCEPTÉ et
        // rendu `2001:db8::/32`. Une faute de frappe devenait une protection SILENCIEUSE là où la
        // fonction promet de refuser BRUYAMMENT. C'est la branche que la conception désignait comme
        // la seule sans antécédent dans l'arbre, donc sans témoin existant pour la rattraper.
        ("10..*", "frontière"),
        ("2001:db8:::*", "frontière"),
        ("10...*", "frontière"),
        // REPRISE 2026-08-29 — UN MASQUE SOUS /96 SUR UNE BASE MAPPÉE NE DÉCRIT AUCUN RÉSEAU IPv4.
        ("::ffff:203.0.113.0/24", "mappée"),
    ];
    for (item, fragment) in refuses {
        match parse_protected_item(item) {
            None => panic!("« {item} » n'est pas vide : il doit rendre un VERDICT, pas rien"),
            Some(Ok((net, bits))) => panic!("« {item} » a été ACCEPTÉ comme {net}/{bits} — il doit être REFUSÉ"),
            Some(Err(raison)) => {
                assert!(!raison.trim().is_empty(), "« {item} » : refus SANS raison");
                assert!(raison.contains(fragment),
                        "« {item} » : la raison doit nommer la cause « {fragment} », lue : {raison}");
            }
        }
    }
    // UN ITEM VIDE N'EST PAS UN REFUS : une virgule en trop dans le CSV ne doit rien signaler.
    for vide in ["", "   ", "\t"] {
        assert!(parse_protected_item(vide).is_none(), "« {vide:?} » : item vide -> aucun verdict, aucun bruit");
    }
    // NON-VACUITÉ : le témoin refuserait tout si l'analyseur refusait tout.
    for bon in ["203.0.113.7", "203.0.113.0/24", "203.0.113.*", "2001:db8::/32", "2001:db8:*", "8.0.0.0/8"] {
        assert!(matches!(parse_protected_item(bon), Some(Ok(_))), "« {bon} » DOIT être accepté");
    }
    // ET UN REFUS NE PROTÈGE RIEN — il ne se transforme pas en matcher inerte qui se lirait comme
    // une protection : la liste rendue est simplement plus courte, et le refus est NOMMÉ ailleurs.
    assert!(!ip_is_protected_ctx("8.8.8.8", &[]), "denylist vide -> une IP publique n'est pas protégée");
}

/// `P4.7-h` — UN REFUS D'ANALYSE N'EST PAS UNE RÉPONSE NÉGATIVE, ET L'ARBITRAGE EST ÉCRIT ICI.
/// La décision : une chaîne inanalysable est refusée EN AMONT comme CIBLE (défaut de FORME), et
/// n'est jamais « traitée comme protégée » (ce qui aurait rendu une riposte PERDUE invisible —
/// `run_playbooks` ne compte QUE les refus de forme dans `abandonnes`).
///
/// LE CONTRAT QUI EN DÉCOULE EST TENU PAR UN TÉMOIN, PAS PAR UNE PHRASE : toute cible que la borne
/// d'enforcement accepte S'ANALYSE. C'est ce qui autorise `ip_is_protected_ctx` à rendre `false` sur
/// l'inanalysable sans rouvrir de trou.
#[test]
fn une_cible_de_ban_est_toujours_analysable() {
    // LE DÉFAUT, MESURÉ : Rust refuse les zéros de tête. AVANT ce lot ces quatre chaînes étaient des
    // cibles de ban ACCEPTÉES, et `ip_is_protected` sautait ses DEUX tests de plage -> une adresse de
    // boucle locale ou privée écrite ainsi n'était PAS protégée, SANS AUCUNE CONFIGURATION.
    for zero_de_tete in ["10.0.0.01", "010.0.0.1", "127.000.000.001", "192.168.001.1"] {
        assert!(ssrf_norm_ip(zero_de_tete).is_none(), "INSTRUMENT : {zero_de_tete} s'analyse — le défaut mesuré a changé de nature");
        assert!(!crate::handlers::actions::cible_de_ban_acceptee(zero_de_tete),
                "{zero_de_tete} : le produit ne sait pas lire cette valeur -> ce n'est PAS une cible");
        assert!(action_valid("ban_ip", zero_de_tete, "default").is_err(),
                "{zero_de_tete} : ban REFUSÉ (défaut de FORME, compté dans `abandonnes`)");
    }
    // LA BORNE N'A PAS ÉTÉ ÉLARGIE — C'EST UNE CONJONCTION AJOUTÉE, RIEN DE NEUF NE PART.
    for encore_refusee in ["2001:db8::1", "::1", "fe80::1", "dead:beef", "", "not-an-ip"] {
        assert!(!crate::handlers::actions::cible_de_ban_acceptee(encore_refusee),
                "{encore_refusee} : la borne d'enforcement v1 (IPv4 pointée) reste INCHANGÉE");
    }
    // NON-VACUITÉ : ce qui était bannissable et s'analyse l'est TOUJOURS.
    for bannissable in ["203.0.113.7", "198.51.100.9", "8.8.8.8", "::ffff:203.0.113.7"] {
        assert!(crate::handlers::actions::cible_de_ban_acceptee(bannissable),
                "{bannissable} : cible ACCEPTÉE avant ce lot, et toujours acceptée après");
    }
    // LA PROPRIÉTÉ, SUR LA POPULATION DU CORPUS PARTAGÉ : accepté => analysable.
    let mut acceptees = 0usize;
    for s in chaines_du_corpus_partage() {
        if crate::handlers::actions::cible_de_ban_acceptee(&s) {
            acceptees += 1;
            assert!(ssrf_norm_ip(&s).is_some(), "« {s} » : cible acceptée mais INANALYSABLE — le contrat est rompu");
        }
    }
    assert!(acceptees >= 2, "INSTRUMENT : {acceptees} cible(s) acceptée(s) dans le corpus — REFUS DE CONCLURE");
}

/// `P4.7-k` — LA VALVE DE RÉCUPÉRATION RENDAIT « FAIT » SUR UN BAN QU'ELLE NE POUVAIT PAS LEVER.
/// AVANT / APRÈS dans le même corps : le ban est posé sous la valeur CANONIQUE (ce que fait
/// `netban_validate_ip`), puis on tente de le lever sous la saisie BRUTE — c'est exactement ce que
/// `netban_delete` faisait, et il répondait `{"ok": true}`.
#[test]
fn la_levee_de_ban_dit_ce_qu_elle_a_retire() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    // La POSE canonicalise par l'unique canonicaliseur : la forme mappée se replie sur la valeur.
    let canon = ssrf_norm_ip("::FFFF:203.0.113.7").expect("forme mappée analysable").to_string();
    assert_eq!(canon, "203.0.113.7", "`ssrf_norm_ip` REPLIE la forme mappée (`parse + to_string` NON)");
    assert!(netban_upsert(&c, &canon, None, "témoin P4.7-k", "op", "prod"), "ban posé");
    assert!(net_ban_is_blocked(&canon, now()), "le ban bloque");

    // AVANT : LE CORPS D'ALORS, RECOPIÉ ICI À DESSEIN (point de comparaison, pas une définition).
    // `DELETE FROM net_ban WHERE ip=?1` sur la SAISIE brute n'appariait AUCUNE ligne, et la route
    // répondait `{"ok": true}` sans jamais le savoir.
    let n_avant = c.execute("DELETE FROM net_ban WHERE ip=?1", params!["::FFFF:203.0.113.7"]).expect("DELETE exécutable");
    assert_eq!(n_avant, 0, "la saisie brute ne levait RIEN : c'est le défaut");
    netban_reload(&c);
    assert!(net_ban_is_blocked(&canon, now()), "le ban est TOUJOURS là après le « fait » d'hier");

    // APRÈS : la levée retire TOUTES les écritures de la MÊME VALEUR, et DIT combien.
    assert_eq!(netban_remove(&c, "::FFFF:203.0.113.7").expect("levée exécutable"), 1,
               "la MÊME saisie lève réellement la ligne : l'identité d'une adresse est sa valeur");
    assert!(!net_ban_is_blocked(&canon, now()), "le ban est levé");
    // IDEMPOTENCE PRÉSERVÉE, MAIS PLUS MUETTE : retirer une IP absente reste permis, et rend 0.
    assert_eq!(netban_remove(&c, &canon).expect("levée exécutable"), 0, "seconde levée : rien à retirer, et c'est DIT");

    // LA DIRECTION ADVERSE DU MÊME GESTE (REPRISE 2026-08-29) — UNE LIGNE ÉCRITE COMME LES POSES
    // D'AVANT LE LOT L'ÉCRIVAIENT. `parse + to_string` NE REPLIE PAS : le store peut porter
    // `::ffff:203.0.113.7`. Depuis que `real_client_ip` replie, `map.get("203.0.113.7")` — égalité
    // de chaîne EXACTE — n'aurait plus trouvé cette ligne : un ban PERMANENT aurait été
    // silencieusement levé au premier redémarrage, sans journal ni compteur. La LECTURE du store
    // replie donc, et la levée retire cette écriture-là aussi.
    c.execute("INSERT INTO net_ban(ip,reason,created_ts,expires_ts,created_by,env_id) VALUES(?1,?2,?3,NULL,?4,?5)",
              params!["::ffff:203.0.113.7", "posé AVANT le lot", now(), "op", "prod"]).expect("insertion de la ligne héritée");
    netban_reload(&c);
    assert!(net_ban_is_blocked("203.0.113.7", now()),
            "une ligne stockée sous l'écriture MAPPÉE bloque toujours l'IP réelle, que `real_client_ip` rend désormais REPLIÉE");
    assert_eq!(netban_remove(&c, "203.0.113.7").expect("levée exécutable"), 1,
               "et elle est LEVABLE par la valeur : la soupape lève TOUTES les écritures de la même adresse");
    assert!(!net_ban_is_blocked("203.0.113.7", now()), "plus rien ne bloque");

    // ET « 0 RETIRÉ » NE PEUT PLUS VOULOIR DIRE DEUX CHOSES (REPRISE 2026-08-29). Le corps faisait
    // `unwrap_or(0)` : une erreur SQL (contention de l'écrivain, base en lecture seule) rendait `0`
    // et la route répondait `{"ok": true, "retires": 0}` — EXACTEMENT ce qu'elle aurait répondu si
    // aucun ban n'existait. Un exploitant verrouillé cherchait ailleurs. Une base SANS le store est
    // le cas d'échec le plus franc : elle doit rendre Err, jamais `Ok(0)`.
    let sans_store = rusqlite::Connection::open_in_memory().expect("base mémoire");
    assert!(netban_remove(&sans_store, "203.0.113.7").is_err(),
            "store ILLISIBLE : une levée qui ÉCHOUE doit être RAPPORTÉE, jamais confondue avec « rien à retirer »");
    // ET L'AUTRE MOITIÉ DU MÊME CONTRAT, celle qui manquait : le store se LIT mais ne s'ÉCRIT pas
    // (contention de l'écrivain, base passée en lecture seule — le cas d'un exploitant verrouillé
    // qui appelle la valve pendant le tick de maintenance). Sans ce second cas, un `unwrap_or(0)`
    // remis sur le DELETE seul passerait VERT : mesuré, la mutation ne rougissait pas.
    let ecriture_refusee = test_db();
    ecriture_refusee.execute_batch("PRAGMA query_only = 1;").expect("bascule en lecture seule");
    assert!(netban_remove(&ecriture_refusee, "203.0.113.7").is_err(),
            "store NON INSCRIPTIBLE : l'échec du DELETE doit être RAPPORTÉ, jamais rendu « 0 retiré »");
    netban_cache().write().clear();
}

/// CE QUI EST PUBLIÉ EST CE QUI EST PROTÉGÉ (REPRISE 2026-08-29).
///
/// LE DÉFAUT, MESURÉ. `etendue_du_reseau` — la fonction qui alimente les TROIS surfaces où
/// l'exploitant lit son étendue (registre never-ban, journal d'amorçage, message de refus de scope
/// d'engagement) — masquait SANS replier la forme mappée, tandis que `ip_in_cidr`, le DÉCIDEUR,
/// replie des DEUX côtés avant de masquer. Conséquence : `::ffff:203.0.113.0/120` était PUBLIÉ
/// « ::ffff:203.0.113.0 .. ::ffff:203.0.113.255 » et n'en protégeait qu'UNE — 255 adresses annoncées
/// protégées étaient bannissables — et la SEULE surface de relecture CONFIRMAIT la fausse lecture,
/// sur le seul geste du lot qui RETIRE une protection écrite.
///
/// LA PROPRIÉTÉ EST DÉRIVÉE, PAS ÉNUMÉRÉE : pour tout item accepté, les DEUX bornes publiées
/// appartiennent au réseau selon le DÉCIDEUR, et les deux adresses immédiatement hors bornes n'y
/// appartiennent pas. Un item écrit demain est couvert sans être nommé.
#[test]
fn l_etendue_publiee_est_celle_qui_est_appliquee() {
    let items = [
        "203.0.113.0/25", "198.51.100.0/23", "192.0.2.0/24", "203.0.113.*", "203.0.113.7",
        "2001:db8::/64", "2001:db8:*", "172.16.0.0/12", "8.0.0.0/8",
        // LES ÉCRITURES MAPPÉES — aucune n'était portée par un témoin, et c'est là que la
        // divergence vivait. La notation que ce lot invite l'exploitant à écrire est justement
        // celle-là.
        "::ffff:203.0.113.7", "::ffff:203.0.113.0/120", "::ffff:198.51.100.0/119", "::ffff:10.0.0.0/104",
    ];
    let mut exercees = 0usize;
    for item in items {
        let (net, bits) = parse_protected_item(item)
            .unwrap_or_else(|| panic!("« {item} » : item non vide"))
            .unwrap_or_else(|e| panic!("« {item} » DOIT être accepté : {e}"));
        let (base, dernier) = etendue_du_reseau(net, bits);
        // (1) CE QUI EST PUBLIÉ EST DANS L'ENSEMBLE APPLIQUÉ.
        assert!(ip_in_cidr(base, net, bits),
                "« {item} » -> {net}/{bits} : la PREMIÈRE adresse publiée ({base}) n'est pas protégée");
        assert!(ip_in_cidr(dernier, net, bits),
                "« {item} » -> {net}/{bits} : la DERNIÈRE adresse publiée ({dernier}) n'est pas protégée");
        // (2) ET CE QUI EST PUBLIÉ EST TOUT L'ENSEMBLE APPLIQUÉ : les voisines immédiates sont dehors.
        let voisines: Vec<std::net::IpAddr> = match (base, dernier) {
            (std::net::IpAddr::V4(b), std::net::IpAddr::V4(d)) => {
                let (b, d) = (u32::from(b), u32::from(d));
                let mut v = Vec::new();
                if b > 0 { v.push(std::net::IpAddr::V4(std::net::Ipv4Addr::from(b - 1))); }
                if d < u32::MAX { v.push(std::net::IpAddr::V4(std::net::Ipv4Addr::from(d + 1))); }
                v
            }
            (std::net::IpAddr::V6(b), std::net::IpAddr::V6(d)) => {
                let (b, d) = (u128::from(b), u128::from(d));
                let mut v = Vec::new();
                if b > 0 { v.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(b - 1))); }
                if d < u128::MAX { v.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(d + 1))); }
                v
            }
            _ => panic!("« {item} » : `etendue_du_reseau` a rendu deux familles différentes"),
        };
        assert!(!voisines.is_empty(), "INSTRUMENT : aucune voisine dérivée pour « {item} »");
        for v in voisines {
            assert!(!ip_in_cidr(v, net, bits),
                    "« {item} » -> {net}/{bits} : {v} est HORS des bornes publiées et pourtant protégée");
            exercees += 1;
        }
        // (3) ET L'ÉTENDUE EST CELLE QUE LA DENYLIST APPLIQUE VRAIMENT (chemin complet, pas `ip_in_cidr` seul).
        let denylist = vec![(net, bits)];
        assert!(ip_is_protected_ctx(&base.to_string(), &denylist) || ip_never_egress(base) || ip_is_rfc1918(base),
                "« {item} » : la base publiée n'est pas protégée par la denylist elle-même");
    }
    assert!(exercees >= 20, "INSTRUMENT : {exercees} voisine(s) exercée(s) — REFUS DE CONCLURE");

    // LA DIRECTION « ON PROTÈGE PLUS », NOMMÉE : `::ffff:203.0.113.0/120` protégeait UNE adresse
    // (masque /120 appliqué à une valeur v4 = masque PLEIN) ; il protège désormais ses 256.
    let mappe = vec![parse_protected_item("::ffff:203.0.113.0/120").unwrap().unwrap()];
    assert_eq!(mappe[0], ("203.0.113.0".parse::<std::net::IpAddr>().unwrap(), 24),
               "l'item mappé est RANGÉ sous la forme où il sera appliqué");
    assert!(ip_is_protected_ctx("203.0.113.200", &mappe), "les 256 adresses écrites sont protégées");
    assert!(!ip_is_protected_ctx("203.0.114.1", &mappe), "et pas une de plus");
    // ET LA PUBLICATION NE PEUT PLUS MENTIR MÊME SUR UNE PAIRE QUI N'EST PAS PASSÉE PAR
    // L'ANALYSEUR (message de refus de scope d'engagement, appelant futur) : `etendue_du_reseau`
    // replie comme le DÉCIDEUR, donc les deux ne peuvent pas diverger, quelle que soit l'origine.
    let (b, d) = etendue_du_reseau("::ffff:203.0.113.0".parse::<std::net::IpAddr>().unwrap(), 120);
    assert_eq!((b.to_string().as_str(), d.to_string().as_str()), ("203.0.113.0", "203.0.113.0"),
               "une paire mappée NON canonicalisée publie l'étendue que `ip_in_cidr` applique \
                (masque /120 sur une valeur v4 = masque PLEIN), jamais une plage v6 inventée");
    // ET L'ASYMÉTRIE MESURÉE DISPARAÎT : le plancher tranché sur `is_ipv6()` refusait
    // `::ffff:10.0.0.0/8` là où `10.0.0.0/8` était accepté — le MÊME réseau.
    assert_eq!(parse_protected_item("::ffff:10.0.0.0/104").unwrap().unwrap(),
               parse_protected_item("10.0.0.0/8").unwrap().unwrap(),
               "la même valeur écrite de deux façons rend le MÊME réseau");
}

/// LES DEUX ANALYSEURS DU MÊME CSV, ET L'ÉCART QUI RESTE — MESURÉ, PAS SUPPOSÉ (REPRISE 2026-08-29).
///
/// La thèse du lot est la SÉPARATION des deux consommateurs de `PLUME_OPERATOR_IPS` : l'AFFICHAGE
/// compare des chaînes (seule réponse qui se rende en `NOT LIKE`), l'ENFORCEMENT compare des
/// réseaux. Séparer deux politiques ne dispense pas de MESURER leur écart — deux choses lui étaient
/// dues, et aucune n'était tenue :
///
///   (1) LA MÊME LIGNE DOIT ÊTRE ACCEPTÉE DES DEUX CÔTÉS. Mesuré : `parse_excl_item` rogne autour du
///       `/`, `parse_ssrf_allow` non — `« 172.16.0.0 /12 »` était HONORÉ côté panneau (l'exploitant
///       VOYAIT son exclusion fonctionner) et REFUSÉ côté denylist (plus AUCUNE protection). C'est
///       CORRIGÉ, et ce témoin le tient.
///   (2) L'ÉCART DE SÉMANTIQUE QUI RESTE VA DANS LE SENS « INVISIBLE **ET** NON PROTÉGÉE », et il
///       n'est pas refermable sans casser le débruitage des panneaux. Il est donc MESURÉ ici, écrit
///       dans le registre never-ban (`ecart_avec_l_affichage`), et assumé.
#[test]
fn les_deux_analyseurs_du_meme_csv_et_l_ecart_qui_reste() {
    // (1) PARITÉ D'ACCEPTATION — une ligne acceptée par l'affichage l'est par l'enforcement.
    for item in ["172.16.0.0 /12", " 203.0.113.0/25 ", "2001:db8:: /64", "203.0.113.7", "203.0.113.*"] {
        assert!(parse_excl_item(item).is_some(), "INSTRUMENT : « {item} » n'est plus lu par l'AFFICHAGE");
        assert!(matches!(parse_protected_item(item), Some(Ok(_))),
                "« {item} » : HONORÉ par l'affichage et REFUSÉ par la denylist — l'exploitant voit son                  exclusion fonctionner dans les panneaux pendant qu'il n'est plus protégé");
    }
    // (2) L'ÉCART QUI RESTE, JOUÉ SUR LE COUPLE (CACHÉE, BANNISSABLE) — la population qui PERD la
    // protection est EXACTEMENT celle que le panneau continue de CACHER. Aucun témoin ne jouait ce
    // couple : `la_largeur_protegee_est_celle_ecrite` n'assertait que la moitié enforcement.
    let (motif, prefixe) = parse_excl_item("172.16.0.0/12").expect("l'affichage lit cet item");
    assert!(prefixe && motif == "172.", "INSTRUMENT : la sémantique d'AFFICHAGE a changé — ce témoin mesure autre chose");
    let douze = vec![parse_protected_item("172.16.0.0/12").unwrap().unwrap()];
    for cachee_et_bannissable in ["172.15.0.1", "172.200.0.1"] {
        assert!(cachee_et_bannissable.starts_with(&motif),
                "{cachee_et_bannissable} est MASQUÉE par les panneaux « menace externe » (préfixe « {motif} »)");
        assert!(!ip_is_protected_ctx(cachee_et_bannissable, &douze),
                "{cachee_et_bannissable} est BANNISSABLE (hors du /12 écrit) — invisible ET non protégée,                  c'est l'écart assumé entre les deux politiques");
    }
    // NON-VACUITÉ : le réseau réellement écrit est, lui, caché ET protégé.
    assert!("172.16.0.1".starts_with(&motif) && ip_is_protected_ctx("172.16.0.1", &douze),
            "le réseau ÉCRIT est cohérent des deux côtés — l'écart n'est pas partout");
}

/// LA FORME IPv4-COMPATIBLE OBSOLÈTE N'EST PAS UNE CIBLE, ET LA LEVÉE N'EST PAS PLUS ÉTROITE QUE LA
/// POSE (REPRISE 2026-08-29). Deux corrections indépendantes de la borne d'enforcement, mesurées.
#[test]
fn la_borne_de_ban_dit_ipv4_et_la_levee_reste_ouverte() {
    use crate::handlers::actions::{cible_de_ban_acceptee, cible_de_levee_acceptee};
    // (a) `::a.b.c.d` (RFC 4291 §2.5.5.1, DÉPRÉCIÉE) et la forme mixte étaient des cibles ACCEPTÉES
    // — hexdigits + un point, et elles s'analysent — tout en étant INVISIBLES à la protection :
    // `::127.0.0.1` vaut `::7f00:1`, `Ipv6Addr::is_loopback` ne couvre que `::1`, `to_ipv4_mapped`
    // ne replie que `::ffff:`, et aucun item v4 ne peut apparier une valeur v6. Les DEUX conditions
    // de la fuite, sur une autre écriture. `2001:db8::192.0.2.1` est DANS le corpus partagé.
    for obsolete in ["::127.0.0.1", "::10.0.0.1", "2001:db8::192.0.2.1"] {
        assert!(ssrf_norm_ip(obsolete).is_some(), "INSTRUMENT : « {obsolete} » ne s'analyse plus — le défaut a changé de nature");
        assert!(!ip_is_protected_ctx(obsolete, &[]),
                "INSTRUMENT : « {obsolete} » est protégée par la moitié DÉRIVÉE — ce témoin mesurerait autre chose");
        assert!(!cible_de_ban_acceptee(obsolete),
                "« {obsolete} » : une cible de ban doit dénoter une valeur IPv4 (la borne « v1 : IPv4 »                  tranchée sur la VALEUR, plus sur la présence d'un point)");
        assert!(action_valid("ban_ip", obsolete, "default").is_err(), "« {obsolete} » : ban REFUSÉ");
    }
    // NON-VACUITÉ : la forme MAPPÉE, elle, se replie sur une v4 et reste une cible.
    for mappee in ["::ffff:203.0.113.7", "::FFFF:203.0.113.7", "0:0:0:0:0:ffff:203.0.113.7"] {
        assert!(cible_de_ban_acceptee(mappee), "« {mappee} » dénote une valeur IPv4 : cible ACCEPTÉE (INCHANGÉ)");
    }
    // (b) LA SOUPAPE LÈVE PLUS, JAMAIS MOINS. Un ban posé au pare-feu AVANT ce lot sous une notation
    // que la borne du BAN refuse doit rester LEVABLE : sinon `POST /api/actions` rend 400 et
    // `respond_run` fait passer à `blocked` toute action `unban_ip` pendante sur cette cible — le
    // ban reste sur l'hôte et plume n'a plus aucun moyen de l'exprimer.
    for posable_avant in ["010.0.0.1", "10.0.0.01", "2001:db8::192.0.2.1", "1.2.3.4.5", "cafe.beef"] {
        assert!(cible_de_levee_acceptee(posable_avant),
                "« {posable_avant} » était une cible de ban AVANT ce lot : sa LEVÉE doit rester exprimable");
        assert!(action_valid("unban_ip", posable_avant, "default").is_ok(),
                "« {posable_avant} » : `unban_ip` DOIT rester créable — une soupape ne se referme pas");
        assert!(action_valid("ban_ip", posable_avant, "default").is_err(),
                "« {posable_avant} » : le BAN, lui, est refusé — c'est la dissymétrie assumée");
    }
    // ET LA LEVÉE NE S'ÉLARGIT PAS NON PLUS : ce que l'ancienne borne refusait reste refusé.
    for jamais in ["2001:db8::1", "::1", "", "nginx", "dead:beef"] {
        assert!(!cible_de_levee_acceptee(jamais), "« {jamais} » n'a JAMAIS été une cible : la levée ne l'invente pas");
    }
}

/// `P4.7-j` / conséquence ⑥ — LE PAIR MAPPÉ EST LA MÊME MACHINE, ET RIEN DE PLUS.
/// Sous un bind double pile (`[::]`) tout pair v4 arrive en `::ffff:a.b.c.d` : l'ingress n'était donc
/// PAS de confiance, les en-têtes d'IP réelle étaient ignorés, et TOUTES les décisions visaient l'IP
/// de l'ingress. DIRECTION : identité de VALEUR seulement — aucun hôte NOUVEAU n'est jugé de
/// confiance, et l'anti-spoof est INCHANGÉ (un pair public replié reste public, donc refusé).
/// CONDITIONNEL, ÉCRIT : les manifestes livrés posent `0.0.0.0:7000` — non vérifié en prod.
#[test]
fn le_pair_mappe_est_la_meme_machine() {
    // Défaut (liste vide) : privé/loopback/ULA de confiance, public JAMAIS.
    assert!(proxy_is_trusted("10.42.0.1", &[]), "RFC1918 -> confiance par défaut (INCHANGÉ)");
    assert!(proxy_is_trusted("::ffff:10.42.0.1", &[]), "le MÊME hôte écrit mappé -> même verdict");
    assert!(proxy_is_trusted("0:0:0:0:0:ffff:10.42.0.1", &[]), "et sous sa forme expansée aussi");
    assert!(!proxy_is_trusted("203.0.113.9", &[]), "public -> jamais de confiance (INCHANGÉ)");
    assert!(!proxy_is_trusted("::ffff:203.0.113.9", &[]),
            "ANTI-SPOOF INCHANGÉ : un pair public replié reste public — aucun hôte NOUVEAU n'est de confiance");
    assert!(!proxy_is_trusted("", &[]) && !proxy_is_trusted("pas-une-ip", &[]),
            "un pair vide ou inanalysable n'est pas une machine de confiance");
    // Liste EXPLICITE : égalité de VALEUR, jamais de chaîne.
    let liste = vec!["10.42.0.1".to_string()];
    assert!(proxy_is_trusted("10.42.0.1", &liste), "IP exacte listée -> confiance (INCHANGÉ)");
    assert!(proxy_is_trusted("::ffff:10.42.0.1", &liste), "la MÊME machine écrite mappée -> confiance");
    assert!(!proxy_is_trusted("10.42.0.2", &liste), "IP privée NON listée -> refus (liste exacte, INCHANGÉ)");
    assert!(!proxy_is_trusted("127.0.0.1", &liste), "loopback non listé -> refus quand liste explicite (INCHANGÉ)");
    // La liste n'accepte PAS de CIDR dans ce lot : élargir serait un ÉLARGISSEMENT DE CONFIANCE.
    let cidr = vec!["10.42.0.0/16".to_string()];
    assert!(!proxy_is_trusted("10.42.0.1", &cidr),
            "un CIDR dans PLUME_TRUSTED_PROXIES n'apparie rien — décision distincte, hors de ce lot");
}

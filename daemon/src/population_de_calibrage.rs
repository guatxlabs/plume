//! LA POPULATION DE CALIBRAGE D'UNE RÈGLE LIVRÉE (`P4.12-g`) — sur quelles SOURCES son seuil a été
//! calibré, déclarée LISIBLE PAR LE CODE (colonne `rule.population`, sources séparées par des virgules)
//! et non plus seulement dans la documentation (docs/DETECTION-CATALOG.md, qui reste la prose de cette
//! table). Une règle dont les contributions viennent d'une source ABSENTE de sa population le dit sur
//! la surface où l'exploitant lit la règle : `rule.population_vue`, écrite AU TIR par la boucle de
//! règles à partir de l'IMPUTATION déjà calculée — aucune requête de plus (la voie évidente, une
//! ventilation par source par règle et par tour, coûtait un balayage de plus par règle active).
//! Table UNIQUE : les semeurs l'écrivent sur une base neuve, la migration v122 la rejoue sur une base
//! existante, et un témoin dérivé de la source refuse un nom de règle livrée qui n'existerait plus.

/// (nom de la règle livrée, population de calibrage). Une règle absente d'ici n'a PAS de population
/// déclarée : rien n'est dit d'elle, ni en bien ni en mal.
pub(crate) const POPULATIONS_DE_CALIBRAGE: &[(&str, &str)] = &[
    ("Brute-force auth par IP (5 min)", "sshd"),
    ("RBA : brute-force d'authentification (risque par IP source)", "sshd"),
    ("Pic d'échecs d'authentification (1h)", "sshd,mail"),
    ("Port-scan détecté (nft PORTSCAN, 10 min)", "portscan"),
    ("RBA : reconnaissance / port-scan (risque par hôte ciblé)", "portscan"),
    ("CF: scan/bot absorbé au edge (>20 challenges managés/IP)", "cloudflare"),
    ("CF: exploit WAF managé (signatures SQLi/RCE/traversal)", "cloudflare"),
    ("CF: L7 flood absorbé depuis une IP (>100 req)", "cloudflare"),
    ("CF: recon multi-vhost depuis une IP (>3 vhosts)", "cloudflare"),
    ("CF: volume de challenges managés (IP distinctes)", "cloudflare"),
];

/// Le SEUL texte qui déclare une population : ne remplit que ce qui est vide, pour ne jamais écraser
/// une déclaration posée par l'exploitant. Joué par les semeurs et par la migration v122.
pub(crate) const SQL_DECLARER_LA_POPULATION: &str = "UPDATE rule SET population=?2 WHERE name=?1 AND population=''";

pub(crate) fn declarer_les_populations(conn: &rusqlite::Connection) {
    for (nom, population) in POPULATIONS_DE_CALIBRAGE {
        let _ = conn.execute(SQL_DECLARER_LA_POPULATION, rusqlite::params![nom, population]);
    }
}

/// Les sources imputées qui NE font PAS partie de la population déclarée. Fonction PURE. Une population
/// vide (non déclarée) ne rend rien : on ne juge pas une règle dont on ne connaît pas la population ;
/// l'inconnu nommé de l'imputation (`SOURCE_INDETERMINABLE`) n'est pas une source étrangère non plus.
pub(crate) fn sources_hors_population(population: &str, sources_imputees: &[String]) -> Vec<String> {
    let declaree: Vec<&str> = population.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    if declaree.is_empty() {
        return Vec::new();
    }
    sources_imputees
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && *s != crate::imputation::SOURCE_INDETERMINABLE && !declaree.contains(s))
        .map(str::to_string)
        .collect()
}

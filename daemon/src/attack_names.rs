//! NOMS des techniques MITRE ATT&CK (Enterprise) — la table que la matrice de couverture SERT à côté de
//! l'identifiant (`P11.6-a`).
//!
//! POURQUOI ICI ET PAS DANS LE CŒUR PARTAGÉ. `guatx_core::attack::CATALOG` est une table technique ->
//! tactique, sans nom : elle sert la RBA (largeur de kill-chain) et l'énumération des angles morts, deux
//! usages qui n'ont pas besoin d'un libellé. Le nom est une donnée de PRÉSENTATION ; il vit du côté qui
//! rend la matrice, avec le même jeu d'identifiants que le catalogue, et un test (`tests/couverture_attack_nommee.rs`)
//! exige que les deux ne divergent pas : chaque entrée du catalogue a un nom, et chaque technique citée
//! par une règle LIVRÉE en a un.
//!
//! MESURÉ AVANT CORRECTION (2026-08-22) : la réponse de `/api/coverage/attack` ne portait AUCUN nom — le
//! champ `name` que lisait `web/attack.js` n'était jamais émis — et la surface web ne connaissait que
//! 14 libellés (`MITRE_NAMES` dans `core.js`, dont 2 sous-techniques), jamais consultés par la matrice.
//! Toutes les cellules de la matrice (183 techniques du catalogue) étaient donc rendues par leur seul
//! identifiant. Le constat « des numéros sans nom » était donc exact et TOTAL, pas partiel.
//!
//! RÉSOLUTION D'UNE SOUS-TECHNIQUE. Une règle livrée peut citer `T1110.003` ; la matrice compte par
//! technique PARENTE (`mitre_parents`), mais une alerte ou une règle affiche l'identifiant tel quel.
//! `technique_name` rend « Parent : Sous-technique » quand la sous-technique est connue, « Parent
//! (sous-technique .NNN) » quand seul le parent l'est — jamais une chaîne vide. `None` signifie
//! « identifiant hors catalogue » et c'est à la surface de DIRE « nom inconnu », pas de taire.
//!
//! IDENTIFIANT RETIRÉ. `T1488` (Disk Content Wipe) a été retiré d'ATT&CK (repris par `T1561.001`) ; il reste
//! dans le catalogue du cœur pour ne pas perdre une règle qui le citerait. Son nom le dit.

/// Nom canonique (anglais, tel que publié par MITRE) des techniques PARENTES du catalogue du cœur.
/// L'ordre suit `guatx_core::attack::CATALOG` (tactiques de la kill-chain) pour la relecture.
pub(crate) const TECHNIQUE_NAMES: &[(&str, &str)] = &[
    // Reconnaissance
    ("T1595", "Active Scanning"),
    ("T1592", "Gather Victim Host Information"),
    ("T1589", "Gather Victim Identity Information"),
    ("T1590", "Gather Victim Network Information"),
    ("T1591", "Gather Victim Org Information"),
    ("T1598", "Phishing for Information"),
    ("T1597", "Search Closed Sources"),
    ("T1596", "Search Open Technical Databases"),
    ("T1593", "Search Open Websites/Domains"),
    ("T1594", "Search Victim-Owned Websites"),
    // Resource Development
    ("T1583", "Acquire Infrastructure"),
    ("T1586", "Compromise Accounts"),
    ("T1584", "Compromise Infrastructure"),
    ("T1587", "Develop Capabilities"),
    ("T1588", "Obtain Capabilities"),
    ("T1608", "Stage Capabilities"),
    ("T1585", "Establish Accounts"),
    ("T1650", "Acquire Access"),
    // Initial Access
    ("T1189", "Drive-by Compromise"),
    ("T1190", "Exploit Public-Facing Application"),
    ("T1133", "External Remote Services"),
    ("T1200", "Hardware Additions"),
    ("T1566", "Phishing"),
    ("T1091", "Replication Through Removable Media"),
    ("T1195", "Supply Chain Compromise"),
    ("T1199", "Trusted Relationship"),
    ("T1078", "Valid Accounts"),
    // Execution
    ("T1059", "Command and Scripting Interpreter"),
    ("T1203", "Exploitation for Client Execution"),
    ("T1204", "User Execution"),
    ("T1559", "Inter-Process Communication"),
    ("T1053", "Scheduled Task/Job"),
    ("T1129", "Shared Modules"),
    ("T1106", "Native API"),
    ("T1072", "Software Deployment Tools"),
    ("T1569", "System Services"),
    ("T1610", "Deploy Container"),
    ("T1648", "Serverless Execution"),
    ("T1651", "Cloud Administration Command"),
    // Persistence
    ("T1098", "Account Manipulation"),
    ("T1197", "BITS Jobs"),
    ("T1547", "Boot or Logon Autostart Execution"),
    ("T1037", "Boot or Logon Initialization Scripts"),
    ("T1543", "Create or Modify System Process"),
    ("T1546", "Event Triggered Execution"),
    ("T1136", "Create Account"),
    ("T1554", "Compromise Host Software Binary"),
    ("T1525", "Implant Internal Image"),
    ("T1556", "Modify Authentication Process"),
    ("T1137", "Office Application Startup"),
    ("T1542", "Pre-OS Boot"),
    ("T1505", "Server Software Component"),
    ("T1205", "Traffic Signaling"),
    ("T1176", "Browser Extensions"),
    // Privilege Escalation
    ("T1548", "Abuse Elevation Control Mechanism"),
    ("T1134", "Access Token Manipulation"),
    ("T1484", "Domain or Tenant Policy Modification"),
    ("T1611", "Escape to Host"),
    ("T1055", "Process Injection"),
    ("T1068", "Exploitation for Privilege Escalation"),
    ("T1574", "Hijack Execution Flow"),
    // Defense Evasion
    ("T1562", "Impair Defenses"),
    ("T1070", "Indicator Removal"),
    ("T1036", "Masquerading"),
    ("T1027", "Obfuscated Files or Information"),
    ("T1218", "System Binary Proxy Execution"),
    ("T1140", "Deobfuscate/Decode Files or Information"),
    ("T1112", "Modify Registry"),
    ("T1497", "Virtualization/Sandbox Evasion"),
    ("T1620", "Reflective Code Loading"),
    ("T1211", "Exploitation for Defense Evasion"),
    ("T1222", "File and Directory Permissions Modification"),
    ("T1564", "Hide Artifacts"),
    ("T1553", "Subvert Trust Controls"),
    ("T1656", "Impersonation"),
    ("T1006", "Direct Volume Access"),
    ("T1014", "Rootkit"),
    ("T1202", "Indirect Command Execution"),
    ("T1207", "Rogue Domain Controller"),
    ("T1216", "System Script Proxy Execution"),
    ("T1221", "Template Injection"),
    ("T1480", "Execution Guardrails"),
    ("T1600", "Weaken Encryption"),
    ("T1601", "Modify System Image"),
    // Credential Access
    ("T1110", "Brute Force"),
    ("T1552", "Unsecured Credentials"),
    ("T1555", "Credentials from Password Stores"),
    ("T1003", "OS Credential Dumping"),
    ("T1056", "Input Capture"),
    ("T1558", "Steal or Forge Kerberos Tickets"),
    ("T1557", "Adversary-in-the-Middle"),
    ("T1212", "Exploitation for Credential Access"),
    ("T1187", "Forced Authentication"),
    ("T1539", "Steal Web Session Cookie"),
    ("T1606", "Forge Web Credentials"),
    ("T1621", "Multi-Factor Authentication Request Generation"),
    ("T1649", "Steal or Forge Authentication Certificates"),
    ("T1040", "Network Sniffing"),
    // Discovery
    ("T1046", "Network Service Discovery"),
    ("T1087", "Account Discovery"),
    ("T1082", "System Information Discovery"),
    ("T1083", "File and Directory Discovery"),
    ("T1057", "Process Discovery"),
    ("T1018", "Remote System Discovery"),
    ("T1016", "System Network Configuration Discovery"),
    ("T1049", "System Network Connections Discovery"),
    ("T1033", "System Owner/User Discovery"),
    ("T1069", "Permission Groups Discovery"),
    ("T1518", "Software Discovery"),
    ("T1201", "Password Policy Discovery"),
    ("T1007", "System Service Discovery"),
    ("T1010", "Application Window Discovery"),
    ("T1124", "System Time Discovery"),
    ("T1120", "Peripheral Device Discovery"),
    ("T1135", "Network Share Discovery"),
    ("T1613", "Container and Resource Discovery"),
    ("T1580", "Cloud Infrastructure Discovery"),
    ("T1526", "Cloud Service Discovery"),
    ("T1538", "Cloud Service Dashboard"),
    ("T1619", "Cloud Storage Object Discovery"),
    ("T1622", "Debugger Evasion"),
    // Lateral Movement
    ("T1021", "Remote Services"),
    ("T1210", "Exploitation of Remote Services"),
    ("T1550", "Use Alternate Authentication Material"),
    ("T1080", "Taint Shared Content"),
    ("T1563", "Remote Service Session Hijacking"),
    ("T1570", "Lateral Tool Transfer"),
    ("T1534", "Internal Spearphishing"),
    // Collection
    ("T1560", "Archive Collected Data"),
    ("T1213", "Data from Information Repositories"),
    ("T1005", "Data from Local System"),
    ("T1039", "Data from Network Shared Drive"),
    ("T1025", "Data from Removable Media"),
    ("T1074", "Data Staged"),
    ("T1114", "Email Collection"),
    ("T1115", "Clipboard Data"),
    ("T1119", "Automated Collection"),
    ("T1123", "Audio Capture"),
    ("T1125", "Video Capture"),
    ("T1113", "Screen Capture"),
    ("T1602", "Data from Configuration Repository"),
    ("T1530", "Data from Cloud Storage"),
    ("T1185", "Browser Session Hijacking"),
    // Command and Control
    ("T1071", "Application Layer Protocol"),
    ("T1105", "Ingress Tool Transfer"),
    ("T1573", "Encrypted Channel"),
    ("T1090", "Proxy"),
    ("T1095", "Non-Application Layer Protocol"),
    ("T1132", "Data Encoding"),
    ("T1568", "Dynamic Resolution"),
    ("T1571", "Non-Standard Port"),
    ("T1102", "Web Service"),
    ("T1104", "Multi-Stage Channels"),
    ("T1008", "Fallback Channels"),
    ("T1092", "Communication Through Removable Media"),
    ("T1219", "Remote Access Software"),
    ("T1572", "Protocol Tunneling"),
    ("T1001", "Data Obfuscation"),
    ("T1659", "Content Injection"),
    // Exfiltration
    ("T1041", "Exfiltration Over C2 Channel"),
    ("T1048", "Exfiltration Over Alternative Protocol"),
    ("T1567", "Exfiltration Over Web Service"),
    ("T1029", "Scheduled Transfer"),
    ("T1030", "Data Transfer Size Limits"),
    ("T1011", "Exfiltration Over Other Network Medium"),
    ("T1052", "Exfiltration Over Physical Medium"),
    ("T1020", "Automated Exfiltration"),
    ("T1537", "Transfer Data to Cloud Account"),
    // Impact
    ("T1485", "Data Destruction"),
    ("T1486", "Data Encrypted for Impact"),
    ("T1490", "Inhibit System Recovery"),
    ("T1489", "Service Stop"),
    ("T1498", "Network Denial of Service"),
    ("T1499", "Endpoint Denial of Service"),
    ("T1491", "Defacement"),
    ("T1561", "Disk Wipe"),
    ("T1565", "Data Manipulation"),
    ("T1529", "System Shutdown/Reboot"),
    ("T1496", "Resource Hijacking"),
    ("T1531", "Account Access Removal"),
    ("T1495", "Firmware Corruption"),
    ("T1657", "Financial Theft"),
    (
        "T1488",
        "Disk Content Wipe (identifiant retiré d'ATT&CK, repris par T1561.001)",
    ),
];

/// Sous-techniques NOMMÉES : celles que citent les règles livrées et les sous-techniques voisines du même
/// parent. Une sous-technique absente d'ici se résout par son parent (« Parent (sous-technique .NNN) »).
pub(crate) const SUBTECHNIQUE_NAMES: &[(&str, &str)] = &[
    ("T1021.004", "SSH"),
    ("T1059.004", "Unix Shell"),
    ("T1098.004", "SSH Authorized Keys"),
    ("T1110.001", "Password Guessing"),
    ("T1110.003", "Password Spraying"),
    ("T1110.004", "Credential Stuffing"),
    ("T1136.001", "Local Account"),
    ("T1505.003", "Web Shell"),
    ("T1548.001", "Setuid and Setgid"),
    ("T1552.001", "Credentials In Files"),
    ("T1552.007", "Container API"),
    ("T1562.001", "Disable or Modify Tools"),
    ("T1562.004", "Disable or Modify System Firewall"),
    ("T1595.001", "Scanning IP Blocks"),
    ("T1595.002", "Vulnerability Scanning"),
    ("T1595.003", "Wordlist Scanning"),
];

/// Normalise un identifiant (`t1110.003 ` -> `T1110.003`) ; `None` si ce n'est pas `T` + chiffres
/// (+ `.` + chiffres). Tolère ce que `guatx_core::attack::parent_technique` tolère.
fn normaliser(tid: &str) -> Option<String> {
    let t = tid.trim().to_ascii_uppercase();
    let mut parts = t.splitn(2, '.');
    let base = parts.next()?;
    let digits = base.strip_prefix('T')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    match parts.next() {
        None => Some(base.to_string()),
        Some(sub) if !sub.is_empty() && sub.bytes().all(|b| b.is_ascii_digit()) => {
            Some(format!("{base}.{sub}"))
        }
        Some(_) => None,
    }
}

fn nom_parent(base: &str) -> Option<&'static str> {
    TECHNIQUE_NAMES
        .iter()
        .find(|(t, _)| *t == base)
        .map(|(_, n)| *n)
}

/// Nom lisible d'une technique ou sous-technique, DÉRIVÉ de l'identifiant :
///   - technique connue -> son nom ;
///   - sous-technique connue -> « Parent : Sous-technique » ;
///   - sous-technique d'un parent connu -> « Parent (sous-technique .NNN) » ;
///   - identifiant hors catalogue ou hors format -> `None` (la surface doit DIRE « nom inconnu »).
/// Ne rend JAMAIS une chaîne vide.
pub(crate) fn technique_name(tid: &str) -> Option<String> {
    let norm = normaliser(tid)?;
    let (base, sub) = match norm.split_once('.') {
        Some((b, s)) => (b.to_string(), Some(s.to_string())),
        None => (norm.clone(), None),
    };
    let parent = nom_parent(&base)?;
    match sub {
        None => Some(parent.to_string()),
        Some(s) => match SUBTECHNIQUE_NAMES
            .iter()
            .find(|(t, _)| *t == norm)
            .map(|(_, n)| *n)
        {
            Some(n) => Some(format!("{parent}: {n}")),
            None => Some(format!("{parent} (sous-technique .{s})")),
        },
    }
}

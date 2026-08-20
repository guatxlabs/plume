//! P5.7-b — LE SOC S'ALERTE SUR SA PROPRE MISE À JOUR : CE QUI DISTINGUE UN DÉPLOIEMENT D'UN DÉPÔT.
//!
//! LE FAIT, MESURÉ SUR L'ARBRE DU 2026-08-20. `collectors/integrity.sh` surveille
//! `/etc/systemd/system/*.service|*.timer` — y déposer une unité EST un vecteur de persistance, et le
//! produit l'annonce dans son catalogue. Le dépôt rend `kind=unit … severity=3` ; la règle semée T1543
//! (`search source=integrity change=ajout severity>=3`, severity 4) le voit. Or le produit livre
//! **88 unités** (46 `.service` + 42 `.timer`), dont **27** que `bootstrap.sh` dépose dans ce même
//! répertoire et **61** qu'un chemin optionnel (`bootstrap-agent.sh`, collecteur activé) y dépose
//! ensuite. Chaque installation ou mise à jour du SOC écrit donc dans le répertoire que le SOC surveille.
//!
//! L'AMPLEUR EXACTE, DÉRIVÉE ET NON ESTIMÉE (garde `ampleur_du_recouvrement_avec_les_unites_livrees`) :
//! une passe de `bootstrap.sh` qui réécrit les 27 unités produit jusqu'à **27 événements** `kind=unit`
//! severity 3 ; la règle, elle, déduplique par épisode (`dedup='rule-<id>'`, cf. `run_due_rules`) et
//! n'en fait qu'**UNE alerte severity 4**. Une alerte à chaque déploiement suffit à apprendre à
//! l'exploitant que cette alerte-là ne veut rien dire — et c'est le capteur entier qu'il cesse alors de
//! lire. La fatigue d'alerte coûte plus cher ici qu'un faux négatif isolé.
//!
//! CE QUI RESTE ÉCARTÉ, ET POURQUOI. **Une exemption par NOM** (`plume-*`) fabrique l'angle mort qu'un
//! attaquant occupe en nommant son unité `plume-quoi-que-ce-soit.service`. Elle est écartée ici comme
//! elle l'était avant ce module. **Une fenêtre de maintenance déclarée par l'exploitant** déplace le
//! problème : elle atténue TOUT pendant sa durée, y compris ce qui n'a rien à voir avec le produit, et
//! elle repose sur une déclaration humaine qu'un attaquant peut poser lui-même s'il a la main sur l'UI.
//! **Un filtre dans la requête de la règle** effacerait le signal sans laisser de trace lisible.
//!
//! CE QUI EST FAIT — CORROBORATION, PAS EXEMPTION. Un dépôt d'unité est reclassé si, et seulement si,
//! les DEUX faits ci-dessous tiennent ENSEMBLE. Aucun des deux n'est un nom :
//!
//!   (1) LE CONTENU DÉPOSÉ EST, OCTET POUR OCTET, UNE UNITÉ QUE CE BUILD LIVRE. On compare le `sha256`
//!       que le capteur a déjà calculé au jeu `UNITES_LIVREES`, dérivé des fichiers de `systemd/` et
//!       épinglé par une garde qui les re-hache. `bootstrap.sh` installe ces fichiers par `install`,
//!       sans substitution : l'octet déposé EST l'octet livré. Un attaquant qui veut passer par là doit
//!       déposer un fichier dont le contenu est celui d'une unité de plume — c'est-à-dire une unité qui
//!       lance le collecteur de plume, et AUCUN code à lui.
//!   (2) UN DÉPLOIEMENT A EU LIEU, ET IL EST DATÉ. Au démarrage, le daemon calcule la SIGNATURE du jeu
//!       d'unités que son propre binaire livre et la compare à celle qu'il avait notée. Si elle a
//!       changé, un BUILD DIFFÉRENT tourne : le fait est daté, audité (`plume-config`, ledger
//!       tamper-evident) et ouvre une fenêtre BORNÉE de `FENETRE_DE_CORROBORATION_S`. Hors de cette
//!       fenêtre, un dépôt isolé n'est jamais reclassé — même si son contenu est authentique.
//!
//! LE NOM NE PEUT RIEN ACCORDER. Il n'intervient qu'en RESTRICTION : le nom de fichier déposé doit être
//! celui sous lequel ce contenu est livré. Un nom seul n'atténue rien (le contenu ne correspondrait pas)
//! ; un contenu authentique sous un autre nom n'atténue rien non plus. Une restriction ne peut produire
//! que PLUS d'alertes, jamais moins — c'est ce qui la sépare d'une exemption, et
//! `un_depot_hostile_qui_imite_une_mise_a_jour_reste_detecte` en fait la preuve.
//!
//! L'ÉVÉNEMENT N'EST JAMAIS EFFACÉ. Reclasser ici veut dire : `severity` passe à
//! `SEVERITE_RECLASSEE`, et la ligne GAGNE deux champs — `reclasse` (le motif) et `severite_origine`
//! (la sévérité que le capteur avait posée). `kind`, `path`, `sha256`, `change`, `scope` sont intacts.
//! `search source=integrity kind=unit` rend la même ligne qu'avant ; `search source=integrity
//! reclasse=maj-produit` rend EXACTEMENT ce qui a été atténué, et rien d'autre. Aucun DROP, aucun
//! filtre de règle, aucune ligne perdue : un SOC qui s'aveugle sur lui-même est ce que ce produit
//! existe pour éviter.
//!
//! CE QUE ÇA NE FERME PAS, ÉCRIT POUR ÊTRE OPPOSABLE.
//!   • Un exploitant qui ACTIVE un collecteur optionnel hors déploiement (le binaire ne change pas)
//!     reste alerté : la signature n'a pas bougé, donc le fait (2) manque. C'est délibéré — c'est le
//!     « dépôt isolé » que la corroboration doit précisément distinguer d'une mise à jour.
//!   • Une base neuve n'a pas de signature antérieure : la première pose est SILENCIEUSE et n'ouvre
//!     AUCUNE fenêtre (rien à corroborer, et le premier passage du capteur construit sa baseline après
//!     l'installation). Fail-closed : en cas de doute, l'alerte reste.
//!   • Le fait de déploiement est noté sur la base du tenant qui démarre. Une base tenant qui ne l'a
//!     jamais reçu porte un fait à 0 -> aucun reclassement. Fail-closed, là encore.
//!   • Un attaquant qui a déjà remplacé le BINAIRE du daemon contrôle sa signature. Ce module ne
//!     prétend pas résister à ça : il est en aval du binaire, comme tout le reste du daemon.
use crate::*;

/// La source que le capteur d'intégrité écrit sur chacune de ses lignes.
pub(crate) const SOURCE_INTEGRITE: &str = "integrity";
/// `fields.kind` d'un dépôt d'unité systemd (famille `unit` de `collectors/integrity.sh`).
const KIND_UNITE: &str = "unit";
/// Durée pendant laquelle un dépôt d'unité AUTHENTIQUE est corroboré par le déploiement daté.
/// `systemd/plume-integrity.timer` déclenche à `OnBootSec=120s` puis toutes les `OnUnitActiveSec=15min` :
/// la première passe après le redémarrage tombe à +2 min, la suivante 15 min plus tard. 30 min couvrent
/// les deux avec marge, et referment la fenêtre bien avant qu'elle ne devienne un abri.
pub(crate) const FENETRE_DE_CORROBORATION_S: i64 = 1800;
/// Sévérité d'un dépôt corroboré. 1 = informationnel : sous le plancher `severity>=3` de la règle T1543
/// comme sous tout seuil >= 2 — plus aucune règle de sévérité ne le voit, et la ligne reste entière.
pub(crate) const SEVERITE_RECLASSEE: i64 = 1;
/// Champ ajouté à `fields` : le MOTIF du reclassement (vocabulaire fermé, une seule valeur aujourd'hui).
pub(crate) const CHAMP_MOTIF: &str = "reclasse";
/// Champ ajouté à `fields` : la sévérité que le CAPTEUR avait posée. Reclasser n'efface pas ce qu'on
/// reclasse — sans ce champ la ligne mentirait sur ce que le capteur a vu.
pub(crate) const CHAMP_SEVERITE_ORIGINE: &str = "severite_origine";
/// L'unique motif : le dépôt est corroboré par une mise à jour du produit.
pub(crate) const MOTIF_MAJ_PRODUIT: &str = "maj-produit";

/// Clé `meta` — signature du jeu d'unités livré par le build qui a démarré en dernier sur cette base.
pub(crate) const CLE_META_SIGNATURE: &str = "unites_livrees_signature";
/// Clé `meta` — date du dernier CHANGEMENT de cette signature, c'est-à-dire le fait de déploiement.
pub(crate) const CLE_META_FAIT: &str = "unites_livrees_change_ts";
/// `ledger.kind` du fait de déploiement. Hors du vocabulaire `rule`/`parser` que surveille la règle de
/// catalogue « contenu de détection muté » : noter un déploiement n'est pas éditer une détection.
pub(crate) const KIND_AUDIT: &str = "config.unites_livrees.change";

/// LES UNITÉS QUE CE BUILD LIVRE — `(nom de fichier, sha256 du contenu)`, dérivé de `systemd/*.service`
/// et `systemd/*.timer`, trié par nom. `bootstrap.sh` et `bootstrap-agent.sh` les posent par `install`,
/// SANS substitution : l'octet déposé dans `/etc/systemd/system` est l'octet livré ici.
///
/// CETTE TABLE EST ÉNUMÉRÉE MAIS PAS DÉCLARATIVE : la garde
/// `les_empreintes_livrees_sont_celles_des_fichiers` re-hache les fichiers et refuse la moindre dérive —
/// nom en trop, nom manquant, empreinte périmée. Une unité modifiée sans re-hachage n'est donc pas un
/// angle mort : son dépôt cesse d'être reconnu et redevient une alerte (fail-closed), et la garde rougit.
pub(crate) const UNITES_LIVREES: [(&str, &str); 88] = [
    ("plume-auditd.service", "fa2f033a749e3eeb2376023dc1f643a1283858dca2e9becfb1f7a8859588c427"),
    ("plume-auditd.timer", "bf7034d0977df5ea57a74ce607b5fa6ff52a989a170661e6193949dda5d0ef6c"),
    ("plume-audit.service", "5c00651681a2a791593602ff238cb110d657cccc5e01344fd3e970417a2a8685"),
    ("plume-audit.timer", "e0817e9249c3907d0459cfe6b095dbe996f0557b7412dc108b67eeea82b02de8"),
    ("plume-backup.service", "3cb4e5ceae3368e97e4f65639adae7b7de9b36ecc23efae76a1863bca75b5773"),
    ("plume-backup.timer", "9444719a212c5f3396555e370079f4b630ca2d1cb0bfb8afbbb8bc2387cbac17"),
    ("plume-bans.service", "e41b292c0135c3c015ea209e267e0d54c88aae088dc27d91fa7accc57f76ae28"),
    ("plume-bans.timer", "e6a52e18e768b0d9177988f8e663cfe1005f2d7b898cac434c2a968811479db0"),
    ("plume-clamav.service", "b52724b64633aa79a1447820555c1eff39f55bcbee5012cdf043fcbac6188839"),
    ("plume-clamav.timer", "705e1c4e8624643ade8e825d6e395b929e6f6ae5110088f46780b35d29ad5945"),
    ("plume-cloudflare-http.service", "dfc9703fc2fd39a4260b654c639d426e0c61de7b2e923d9ad71e5bb54737e970"),
    ("plume-cloudflare-http.timer", "602f6ac19179fa526449f0f66c3695a7c7ec69c3052d6f601d9a793e87c73b35"),
    ("plume-cloudflare.service", "6cecf295d377503506a467d17f6149a2babf2d2a50e77f61efc4f9ed7ad98299"),
    ("plume-cloudflare.timer", "c04ff60637645d528c7ea41911b2a2bb9f3d3a18d968bc4a70b192c7e8d3259a"),
    ("plume-collector-mail.service", "6dec25664f0442339d14240e7dca53a6d4df173f1d7173ddc36babcf0019da73"),
    ("plume-collector-mail.timer", "3024a76db37b58611c8fe96914bc224dab9f361fc457b0ccf4fc0e39b521128d"),
    ("plume-collector-syslog.service", "0a3127fe84fca8577e1592d9ecc0c35ac131af258895da6547018ec19c7deb4e"),
    ("plume-conntrack.service", "3b25703af4a4eeb1373de79bf8783d028e13bd9bd8d17df8557b13e715f291c9"),
    ("plume-conntrack.timer", "8d62076f0aa68d5aea04f6c68add9f3b3b86516ba617cb5341e6776afea75193"),
    ("plume-containerd.service", "b49effac5dc42058626a19de1b0743e50d57b7d79259f11131cc02d2ca323588"),
    ("plume-containerd.timer", "83ab6d311140416447507fe368dd224a9e2efd88dca37b5ff276fbdd9acd02b5"),
    ("plume-controls.service", "1a7cf0cf74789ace588ece82220382f615114fefafa88184f8c2c060f2e94f5a"),
    ("plume-controls.timer", "0d36e32df9c9b22d1385086f6e488ac5ff936054987cb11e70159a47dfc169da"),
    ("plume-crowdsec.service", "608e34d82e877b605037e9f7281ba5a07459adf5400070ee0a7dbcb72f7efb37"),
    ("plume-crowdsec.timer", "cbffb6972a2e98ad0a19bc3bac50562ed3b886e09728dfa6ddff8061544baa17"),
    ("plume-custom.service", "dbd2cdd41e5601299a175f21daba546f0e4bd1234f9bf3b73a1676575fd46dee"),
    ("plume-custom.timer", "dc076f4709f13fc41edabf6c72833ef49fdc75b5d11ac4e71bef3d00d042076f"),
    ("plume-daemon.service", "e2e401cb109916141235cbb6a7c5f48ee2147201ff2fcee90d805fe0fccd6969"),
    ("plume-dataaccess.service", "d4bd86a8f42e8c93551f10ecb861540a74e7915f85a42b428b1fe7c437f9b046"),
    ("plume-dataaccess.timer", "ade7d8c8ad610441ee597d0962463f27dc79f8f0556dbfed30cfd3bc2a7c2550"),
    ("plume-dataacl.service", "ba2a9d01cd785d6c93db054dc8929fca4bd3a404eb2fe691f6bc3be9fe1f274e"),
    ("plume-dataacl.timer", "bbfa21cc9ae4b4bef59e0e9eea3e6e9e72981bc59909e79d0a8a6a58b86b3d5e"),
    ("plume-engagement-adapter.service", "dd195d6044ac5e1577d5c796fdcf558deebec68e356588daf76d0f5ab055c28d"),
    ("plume-engagement-adapter.timer", "d7f01d3ff3bd82be91aa925049e184eac310babb750d221e5f8fefdfb35e4ebe"),
    ("plume-engagement-revert.service", "45ca974543495bf2d3356089d1fa539316577c940a014c7c8f4b2e238b14dc4a"),
    ("plume-engagement-revert.timer", "e4702711ffa3ab2fb169a2bf30551ff7ab5ee00925defbfd6cc6578994b3b048"),
    ("plume-falco.service", "a56043a56c0e09992731bafce3f2b2f6d3ff186b9a67b8a040b5e6ab964abf9e"),
    ("plume-falco.timer", "98fd6d8d0629b99d113ea005df6e35821c31f08262cb8aa950c48bbd92b4ab35"),
    ("plume-firewall.service", "0f272f4a02874599d0fe079ad29fbd38d2187a41935bfae53422edd59a0124d2"),
    ("plume-firewall.timer", "323b4f548beb5a0ed3c1b8afcbcbf905dc2fdf8888ddd2d3ea8360a44bb096c3"),
    ("plume-imgdrift.service", "a3a891e38d007c3067ef650d971bed5fb9cc10049766c25090fd3bd53ec9c053"),
    ("plume-imgdrift.timer", "c1aad3b471ff0d43343a113bc80c9c201d72bd8c5807cdb153cedddfac06985a"),
    ("plume-integrity.service", "a416e34b257454baa3b594d3ec23ddb942392cbf417ced3336ade32a1d362d7d"),
    ("plume-integrity.timer", "7e76e4d28c40fd0ecb01233420208f30c58c7113eb41802c946d4d22e6409935"),
    ("plume-journal.service", "bc5446c95cfbb9eb9e9fcea609c3c4038c1f153e6a657fb3397ef3bb4b64a29a"),
    ("plume-journal.timer", "5b000f1e4ead6d6be246e63ea4fbd06cc66d5cff5cee520420bbd8075d6405a1"),
    ("plume-kube-audit.service", "d86535f55d9f2124674e86f357e128108677658b97a49e470f8583e427a7cfaa"),
    ("plume-kube-audit.timer", "b55ef2e7ad9ca90c3cb281865baddb7edaa652dbdb2dd2e2214af807941e25d3"),
    ("plume-kube-rbac.service", "029f5ad07b00212fbd6298e46568979f58a2d44e3b5498faf1654d99c49d29e5"),
    ("plume-kube-rbac.timer", "860336c064bf3a20a519e5743a8805205ee5d18e2a5a0e2aa0ed7db7d2e68a06"),
    ("plume-kube-state.service", "f47a44dbada220a9ca7dc414e7e46b8743198dd4ec793508f44057b9dbc76397"),
    ("plume-kube-state.timer", "6c9b24b6ea453923ce4efab7487c12771ddc9d113ccc37522dfb5210e4b52271"),
    ("plume-mail.service", "c241d82b0bae85555f59576841f4ec0052bd98f05f6664466e8d4d7f4b4cbdc2"),
    ("plume-mail.timer", "ae03cb6dd4556c46691f8cb0dc46b8e591b891b80cfced3a3cd6621cb679c4e3"),
    ("plume-minio-audit.service", "70ecd051389cb5166621e8bc43f6d449696208955bb64a3d0b5e0b7d811f1b6a"),
    ("plume-minio.service", "dd4413837c32722f8105714b3f1ba7ec0d7ca0673d4488e0c4c235cbdfa76118"),
    ("plume-minio.timer", "a845b0b65e8ddc5adccd5fd008ecbe26a79c980e33d3a3ecf54894ee50669cf8"),
    ("plume-nft.service", "d62400ab22847ccd9c714711ee7e120093a7b6435352c53f25ef18cb0879e636"),
    ("plume-nft.timer", "916e1fa39968123ba0442ac90748e492d51de4b52270512316adbdba6a0448cb"),
    ("plume-origin-drop.service", "73820ffd63e8030ac27f5588b30af820a924de5b0bac40940cb024992d1b7b02"),
    ("plume-origin-drop.timer", "23b8912f1b6b39fb904d5c64213e74118ffd90fcfc5cbbca4771bf856d2a9616"),
    ("plume-pod-logs.service", "fcd11aa3b2574985ec349d680e9667d2509cef2be923043ac6d4f2caea467edb"),
    ("plume-pod-logs.timer", "20752411e6eb4d9009426df9e8093d3a9771fbe3dd5d34631c86a8a321be3f59"),
    ("plume-portprobe.service", "43b52ce883e9efa059673db551405738838500864fd5e8bf7e458b3a281149ae"),
    ("plume-portprobe.timer", "f07bcac44dfe501e8217db76b009b89d1bda1e8760f2bc2af436c2897744cfd9"),
    ("plume-portscan-nft.service", "61849ebcb095304ba8a64b36edbf4d8f4b52ff736342d02074a0804a1f8a23dc"),
    ("plume-portscan.service", "1aed9dbbe190d78c70e9f5df2619819d5aebfd9f3b579ca1b332aa25d0339d1b"),
    ("plume-portscan.timer", "d77b61510042cc677c993e54e0d4fe1d46a5912bb09fc5a1bbc1c8d394496950"),
    ("plume-prom-scrape.service", "11ea694eb8ce2901c7f3b3bc0c78d3421fb02b84a8ebbeb99d759707bdfea795"),
    ("plume-prom-scrape.timer", "e30034fc216ab5adc9c99ad47b72a62bc26fa5bfbc93ed29b4700dbde26975a0"),
    ("plume-resources.service", "92963453004ba7a567be8d476b7223a31b04bbec915b6ce1bc0b27c49e1fae8c"),
    ("plume-resources.timer", "fabacee25fe2524c3969f48853ecd3f263f73862298eae534dbc375409020799"),
    ("plume-respond-agent.service", "47f3a2b699af9740d20fb3b2542ccd324e012e6fa8909d10d63b537837ffa0fe"),
    ("plume-respond-agent.timer", "1cb0a12707a32b178cfc0398070992209a78b4d11579e471b24831f2c662bae0"),
    ("plume-respond.service", "bfceede2c0fb06c5f1dd8cf52071e5cb55196ded669d99cc396ca87b49d3987e"),
    ("plume-respond.timer", "3824e7eeda282fe6eaaf4ee9f3a3c6cf99514400324cfa6421955ca50dcff5d8"),
    ("plume-ship.service", "f30e3182937842744cbd018f509e88615d90d38d815bcdada2f62b6b13b209d2"),
    ("plume-ship.timer", "e5cb472ef26e1e4673975eeb177cb0fca5309cd4d9ae9737b9a154c11d54f186"),
    ("plume-suricata.service", "a513425bc1d8dd0670fe022317b3b9fc8aae0f66e18c80be7b9800ce77d06de2"),
    ("plume-suricata.timer", "4860752152fa80b8e9d7fb05a7605ac0d640009df430a0841715a67268d191da"),
    ("plume-ufw.service", "77f35dfe6e325eeecb3301a7db115e45b5637a73c325abb7f6d50bd7f94840ff"),
    ("plume-ufw.timer", "af79432077c31e6318bc4d2952e478d50389e5eb78158cb11376da58a9123380"),
    ("plume-vuln.service", "bcf902d7ee74fc5de941edb31a261cacbc7350b21dbb997a104072583d75c8b1"),
    ("plume-vuln.timer", "6afe486af1d4525d597da7e1a609a55ba968e6611d93fb74941ea01935be3700"),
    ("plume-web.service", "ce29df0cd4c4b796ca9600851b9bd8c6d0bdba652aa1ae010ed0445ff49fdc5d"),
    ("plume-web.timer", "de97d683b9f3fe62e927ca0feae190bf00f1c47a5c7394771f54a7c64a92dba9"),
    ("plume-yara.service", "f7ef67857829a6f7fb31ddc58090d4e7c19d35a8b963bb3d34127857a65f9be0"),
    ("plume-yara.timer", "72fdbd444d5fd1aeb886e1053b73ccf73a9b7ffbf84e02dcc26069409cb3f151"),
];

/// L'empreinte sous laquelle ce build livre l'unité `nom`, s'il en livre une.
fn empreinte_livree(nom: &str) -> Option<&'static str> {
    UNITES_LIVREES.iter().find(|(n, _)| *n == nom).map(|(_, h)| *h)
}

/// SIGNATURE DU JEU D'UNITÉS LIVRÉ PAR CE BINAIRE. Dérivée de `UNITES_LIVREES` (donc des fichiers de
/// `systemd/`) et de la version du paquet. Deux démarrages du MÊME build portent la même signature — un
/// redémarrage sans déploiement n'ouvre donc aucune fenêtre, ce qui est exactement l'intention.
pub(crate) fn signature_des_unites_livrees() -> String {
    let mut m = String::with_capacity(UNITES_LIVREES.len() * 96);
    m.push_str(env!("CARGO_PKG_VERSION"));
    for (nom, empreinte) in UNITES_LIVREES.iter() {
        m.push('\n');
        m.push_str(nom);
        m.push('|');
        m.push_str(empreinte);
    }
    sha256_hex(m.as_bytes())
}

/// Fait de déploiement CONNU par base : date du dernier changement du jeu d'unités livré, ou 0 (aucun).
/// Chargé au démarrage par `noter_le_build_en_cours`, lu sur le chemin d'ingest sans accès disque.
pub(crate) static FAITS_DE_DEPLOIEMENT: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, i64>>> =
    std::sync::OnceLock::new();
pub(crate) fn faits_de_deploiement_cell() -> &'static parking_lot::RwLock<HashMap<String, i64>> {
    FAITS_DE_DEPLOIEMENT.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}

/// Date du fait de déploiement de `db_path`, ou 0. **0 = aucune corroboration possible** : c'est l'état
/// d'un processus qui n'a pas démarré par `noter_le_build_en_cours` (tests, outillage) et celui d'une
/// base qui n'a jamais vu deux builds différents. Fail-closed : sans fait, l'alerte reste.
pub(crate) fn fait_de_deploiement(db_path: &str) -> i64 {
    faits_de_deploiement_cell().read().get(db_path).copied().unwrap_or(0)
}

/// Lit le fait de déploiement PERSISTÉ (`meta`). Une valeur illisible vaut 0 — jamais une fenêtre ouverte.
fn fait_persiste(conn: &Connection) -> i64 {
    conn.query_row("SELECT value FROM meta WHERE key=?1", params![CLE_META_FAIT], |r| r.get::<_, String>(0))
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|t| *t > 0)
        .unwrap_or(0)
}

fn poser_meta(conn: &Connection, cle: &str, valeur: &str) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![cle, valeur],
    )
}

/// AU DÉMARRAGE — compare le jeu d'unités que CE binaire livre à celui noté sur la base, et date le
/// changement s'il y en a un. Appelé une fois par base préparée, après les migrations.
///
/// TROIS CAS, ET DEUX D'ENTRE EUX N'OUVRENT RIEN :
///   • signature IDENTIQUE -> aucun déploiement, on recharge simplement le fait déjà connu ;
///   • AUCUNE signature notée (base neuve) -> première pose SILENCIEUSE, aucune fenêtre : il n'y a pas
///     de build antérieur avec quoi corroborer, et le capteur construit sa baseline après l'installation ;
///   • signature DIFFÉRENTE -> un autre build tourne. Le fait est AUDITÉ D'ABORD (ledger tamper-evident
///     + event `plume-config`), et la fenêtre n'est ouverte QUE si cet audit a réussi : pas de trace,
///     pas d'atténuation. En cas d'échec la signature n'est pas non plus mise à jour -> le prochain
///     démarrage réessaie au lieu d'oublier en silence.
pub(crate) fn noter_le_build_en_cours(conn: &Connection, db_path: &str) {
    let signature = signature_des_unites_livrees();
    let precedente: Option<String> = conn
        .query_row("SELECT value FROM meta WHERE key=?1", params![CLE_META_SIGNATURE], |r| r.get(0))
        .ok();
    let mut fait = fait_persiste(conn);
    match precedente {
        Some(p) if p == signature => {}
        None => {
            // Base neuve : on note la signature, on n'invente pas un déploiement qui n'a pas eu lieu.
            let _ = poser_meta(conn, CLE_META_SIGNATURE, &signature);
        }
        Some(_) => {
            let ts = now();
            let detail = format!("{KIND_AUDIT}|{signature}");
            let fields = json!({
                "kind": "unites_livrees",
                "unites": UNITES_LIVREES.len(),
                "fenetre_s": FENETRE_DE_CORROBORATION_S,
                "signature": signature,
            })
            .to_string();
            match audit_config_change(
                conn,
                KIND_AUDIT,
                &detail,
                2,
                "jeu d'unités systemd livré par le binaire modifié : un déploiement a eu lieu. Les dépôts \
                 d'unités dont le contenu est celui d'une unité livrée seront reclassés en informationnel \
                 pendant la fenêtre de corroboration — l'événement d'intégrité reste écrit, avec son motif \
                 et sa sévérité d'origine.",
                &fields,
            ) {
                Ok(()) => {
                    let _ = poser_meta(conn, CLE_META_SIGNATURE, &signature);
                    let _ = poser_meta(conn, CLE_META_FAIT, &ts.to_string());
                    fait = ts;
                }
                Err(e) => {
                    // NON-SILENCE : sans sa trace d'audit, la fenêtre ne s'ouvre pas. On garde l'ancienne
                    // signature pour que le prochain démarrage RÉESSAIE.
                    eprintln!(
                        "[unites] audit du changement de jeu d'unités échoué -> AUCUNE fenêtre de \
                         corroboration ouverte (les dépôts d'unités restent alertés) : {e}"
                    );
                }
            }
        }
    }
    faits_de_deploiement_cell().write().insert(db_path.to_string(), fait);
}

/// LA DÉCISION, PURE. Reclasse `row` si — et seulement si — c'est un dépôt d'unité systemd dont le
/// CONTENU est celui d'une unité livrée par ce build, sous le NOM de fichier de cette unité, et qu'il
/// tombe dans la fenêtre ouverte par un déploiement daté `fait_ts`. Rend `true` si la ligne a été
/// reclassée.
///
/// Le nom n'ACCORDE rien : il ne sert qu'à exiger que le contenu authentique soit déposé sous le nom
/// sous lequel il est livré. Une unité hostile nommée `plume-*` ne franchit pas la comparaison de
/// contenu ; une unité livrée déposée sous un autre nom ne franchit pas la comparaison de nom. Les deux
/// restent à leur sévérité d'origine, donc visibles de la règle T1543.
///
/// AUCUNE SORTIE NE MONTE UNE SÉVÉRITÉ ni n'efface un champ : `severity` ne peut que descendre à
/// `SEVERITE_RECLASSEE`, et `fields` ne fait que GAGNER `reclasse` + `severite_origine`.
pub(crate) fn reclasser_depot_dunite_corrobore(row: &mut EventRow, fait_ts: i64) -> bool {
    if row.source != SOURCE_INTEGRITE || row.severity <= SEVERITE_RECLASSEE {
        return false;
    }
    // Fenêtre : bornée des DEUX côtés. Un événement ANTÉRIEUR au déploiement n'est pas corroboré par lui.
    if fait_ts <= 0 || row.ts < fait_ts || row.ts - fait_ts > FENETRE_DE_CORROBORATION_S {
        return false;
    }
    let brut = match row.fields.as_deref() {
        Some(f) => f,
        None => return false,
    };
    let mut v: Value = match serde_json::from_str(brut) {
        Ok(v) => v,
        Err(_) => return false, // sac illisible -> on ne touche à rien (fail-closed)
    };
    let obj = match v.as_object_mut() {
        Some(o) => o,
        None => return false,
    };
    if obj.get("kind").and_then(|x| x.as_str()) != Some(KIND_UNITE) {
        return false;
    }
    let nom = match obj.get("path").and_then(|x| x.as_str()) {
        Some(p) => p.rsplit('/').next().unwrap_or("").to_string(),
        None => return false,
    };
    let empreinte = match obj.get("sha256").and_then(|x| x.as_str()) {
        Some(h) => h.to_string(),
        None => return false,
    };
    match empreinte_livree(&nom) {
        Some(attendue) if attendue.eq_ignore_ascii_case(&empreinte) => {}
        _ => return false,
    }
    let origine = row.severity;
    obj.insert(CHAMP_MOTIF.to_string(), Value::String(MOTIF_MAJ_PRODUIT.to_string()));
    obj.insert(CHAMP_SEVERITE_ORIGINE.to_string(), Value::from(origine));
    row.fields = Some(v.to_string());
    row.severity = SEVERITE_RECLASSEE;
    true
}

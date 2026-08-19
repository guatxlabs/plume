//! SINK OBJET COMPATIBLE S3 POUR L'ORDONNANCEUR DE SAUVEGARDE — feature `s3_backup`, OFF PAR DÉFAUT.
//!
//! ── CE QUE CE MODULE FAIT ────────────────────────────────────────────────────────────────────────
//! Déposer un fichier d'archive déjà produit (`plume-<TS>.db.age`, cf. `backup::backup_compressed`)
//! sur un stockage objet parlant le protocole S3, DEPUIS LE BINAIRE, sans `mc`, sans sidecar, sans
//! init-container. Trois gestes seulement : signer (AWS Signature v4), `PUT` en flux, puis RELIRE
//! l'objet (`HEAD`) pour que « déposé » veuille dire « le service confirme l'avoir ».
//!
//! ── POURQUOI PAS UN SDK — LA MESURE QUI A TRANCHÉ (2026-08-19) ───────────────────────────────────
//! Le besoin est d'ENVOYER des octets, pas de piloter un service. Le coût de chaque option a été
//! MESURÉ (`cargo tree --prefix none | sort -u`, résolution seule, aucune compilation), en comparant
//! au graphe du démon en profil par défaut (211 caisses) :
//!
//!   | option                                   | graphe | caisses NOUVELLES pour ce démon |
//!   |------------------------------------------|--------|--------------------------------|
//!   | `aws-sdk-s3` + `aws-config`               |  183   |  103  (dont `aws-lc-sys` + `cmake`) |
//!   | `rust-s3` (sync, rustls, no-default)      |   94   |   44                            |
//!   | signature écrite ici + client HTTP interne|    —   |    0                            |
//!
//! Le SDK complet est écarté sur DEUX motifs indépendants, et le second suffirait seul :
//!   (a) +103 caisses pour trois requêtes HTTP, sur un produit dont la contrainte affichée est de
//!       tenir dans 2 Gio ;
//!   (b) il tire `aws-lc-sys`, donc `cmake` — un outillage que `Cargo.toml` déclare ABSENT de l'hôte
//!       de compilation visé, et pour lequel le même arbitrage a déjà été rendu (choix de `ring`
//!       contre `aws-lc-rs` pour rustls). Le SDK échouerait à la compilation là où il doit tourner.
//! `rust-s3` reste 44 caisses (dont une seconde pile HTTP, `attohttpc`, et un second jeu de racines
//! TLS, `webpki-roots`) pour une surface dont on n'utiliserait qu'une méthode.
//!
//! L'option retenue ne coûte AUCUNE dépendance nouvelle parce que les deux primitives nécessaires
//! existent déjà et sont compilées dans le profil par défaut :
//!   · `util::hexcrypto::{hmac_sha256, sha256_hex, hex_encode}` — HMAC-SHA256 et SHA-256, c'est-à-dire
//!     TOUTE l'arithmétique de Signature v4 ;
//!   · `util::http_client::{parse_http_addr, parse_http_full, HttpResp}` + `crypto::vault_root_store`
//!     — l'adressage, l'analyse de réponse et les racines TLS (rustls/ring) du client interne.
//! Le corps, lui, n'est PAS envoyé par `http_call` : celui-ci prend un `&[u8]`, donc l'archive
//! entière en mémoire. Ce module ouvre la socket lui-même et POUSSE le fichier par tranches d'un
//! mébioctet (`TAMPON`) — la mémoire ne suit pas la taille de l'archive.
//!
//! ── CE QUE CE MODULE NE SAIT PAS FAIRE, ÉCRIT POUR ÊTRE OPPOSABLE ────────────────────────────────
//!   · PAS de téléversement en plusieurs parties (`multipart`). Un objet est déposé par UN `PUT`,
//!     donc la limite du protocole s'applique : `PLAFOND_PUT_SIMPLE` (5 Gio). Au-delà, le dépôt est
//!     REFUSÉ AVANT d'ouvrir la moindre socket — jamais tronqué, jamais tenté à l'aveugle.
//!   · PAS de rétention côté bucket. La rétention KEEP-N reste LOCALE (`backup_keep_recent_plan`) ;
//!     l'expiration des objets distants relève d'une règle de cycle de vie du bucket, qui est le
//!     mécanisme natif de tous les fournisseurs et qu'un démon ne doit pas doubler.
//!   · PAS de restauration DEPUIS l'objet, pas de listage, pas de création de bucket, pas d'URL
//!     pré-signée, pas de `SSE-KMS`, pas de `GetObject`. Ce sink DÉPOSE.
//!   · PAS de récupération d'identifiants par rôle d'instance (IMDS/`AssumeRole`) : les identifiants
//!     viennent de la configuration ou du fournisseur de secrets, jamais d'un service de métadonnées.
//!   · PAS de signature « en morceaux » (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) : l'empreinte de la
//!     charge est calculée par une PREMIÈRE passe en flux sur le fichier. Le fichier est donc lu
//!     deux fois — c'est le prix d'une signature standard sans tampon global.
//!   · La réponse est lue APRÈS l'envoi du corps. Un service qui refuserait avant d'avoir tout lu
//!     peut donc faire échouer l'écriture ; ce cas est rattrapé (cf. `pousser_et_lire`) mais la
//!     borne reste le délai d'écriture, pas un `Expect: 100-continue`.
//!
//! ── LE MENSONGE QUE CE MODULE EXISTE POUR RENDRE IMPOSSIBLE ──────────────────────────────────────
//! Un envoi qui échoue ne doit JAMAIS ressortir en succès. La sortie n'est donc pas un booléen mais
//! `IssueDepot`, à trois états EXCLUSIFS : `Depose` (déposé ET confirmé), `Refuse` (le service a
//! répondu, et il a dit non), `Impossible` (aucun verdict — rien n'a répondu). `Depose` n'est
//! construit QU'À UN SEUL ENDROIT de ce fichier, et seulement après que la relecture `HEAD` a rendu
//! 200 avec EXACTEMENT le nombre d'octets envoyés. Un `2xx` sur le `PUT` ne suffit pas.
//!
//! ── AUCUN SECRET NULLE PART ──────────────────────────────────────────────────────────────────────
//! La matière de signature est portée par `Matiere`, un type sans `Display`, sans `as_str`, dont le
//! `Debug` imprime un masque et dont les octets ne sont lisibles que par ce module. Une ligne de
//! journal ne peut donc pas la contenir : il n'existe aucun chemin qui la transforme en texte.
//! L'identifiant d'accès est masqué de la même façon. Aucune valeur n'est écrite dans le dépôt :
//! elles viennent de `cfg`/`cfg_secret` (env > fichier de configuration, ou `_FILE`/`_REF` →
//! `file:`/`env:`/`literal:`/`vault:`), c'est-à-dire du fournisseur de secrets déjà en place.
use crate::*;

// ================================================================================================
// CONSTANTES DE PROTOCOLE
// ================================================================================================

/// Nom de service dans la portée de signature. Fixe pour l'API objet, quel que soit le fournisseur.
pub(crate) const S3_SERVICE: &str = "s3";
/// Algorithme de signature annoncé dans la chaîne à signer et dans l'en-tête d'autorisation.
pub(crate) const S3_ALGO: &str = "AWS4-HMAC-SHA256";
/// Terminaison de la portée de signature.
pub(crate) const S3_TERMINAISON: &str = "aws4_request";
/// SHA-256 d'une charge VIDE — l'empreinte à signer pour un `HEAD` (aucun corps).
pub(crate) const SHA256_CHARGE_VIDE: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Tranche de lecture/écriture (1 Mio) — MÊME borne que `backup::BACKUP_BUF`. C'est elle qui rend la
/// mémoire du dépôt indépendante de la taille de l'archive.
pub(crate) const TAMPON: usize = 1 << 20;

/// Plafond d'un dépôt en UNE requête `PUT`. C'est la limite du protocole, pas un réglage : sans
/// téléversement en plusieurs parties, un objet plus gros ne peut pas être déposé. Un dépassement
/// est refusé AVANT toute ouverture de socket.
pub(crate) const PLAFOND_PUT_SIMPLE: u64 = 5 * 1024 * 1024 * 1024;

/// Délai d'une opération de socket (connexion, écriture d'une tranche, lecture). Le dépôt d'une
/// archive dure ; c'est la TRANCHE qui est bornée, pas le transfert entier.
pub(crate) const DELAI_SOCKET: Duration = Duration::from_secs(60);

/// Longueur maximale d'une clé d'objet (limite du protocole).
pub(crate) const CLE_OBJET_MAX: usize = 1024;

// ================================================================================================
// CLÉS DE CONFIGURATION — toutes lues par `cfg`/`cfg_secret`, donc visibles depuis les TROIS modes
// de déploiement (environnement, fichier de configuration, projection de secret). P8.7-a.
// ================================================================================================

pub(crate) const CLE_S3_ENDPOINT: &str = "PLUME_BACKUP_S3_ENDPOINT";
pub(crate) const CLE_S3_REGION: &str = "PLUME_BACKUP_S3_REGION";
pub(crate) const CLE_S3_ACCESS: &str = "PLUME_BACKUP_S3_ACCESS_KEY_ID";
pub(crate) const CLE_S3_MATIERE: &str = "PLUME_BACKUP_S3_SECRET_ACCESS_KEY";
pub(crate) const CLE_S3_JETON: &str = "PLUME_BACKUP_S3_SESSION_TOKEN";
pub(crate) const CLE_S3_CHEMIN_STYLE: &str = "PLUME_BACKUP_S3_PATH_STYLE";
pub(crate) const CLE_S3_STAGING: &str = "PLUME_BACKUP_S3_STAGING_DIR";

/// Région par défaut. AUCUN fournisseur n'est privilégié : cette valeur est celle que la signature
/// v4 exige d'être non vide, et c'est aussi celle que MinIO/Ceph acceptent sans configuration.
pub(crate) const REGION_DEFAUT: &str = "us-east-1";

// ================================================================================================
// MATIÈRE DE SIGNATURE — un type qui n'a AUCUN chemin vers le texte
// ================================================================================================

/// Matière secrète (clé de signature, jeton de session). Volontairement PAUVRE : pas de `Display`,
/// pas de `as_str`, pas de `Deref`, `Debug` masqué, et le seul accès aux octets est privé au module.
/// Une garde par relecture ne serait pas nécessaire — c'est le TYPE qui rend la fuite inexprimable.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Matiere(String);

impl Matiere {
    pub(crate) fn neuve(v: impl Into<String>) -> Self {
        Matiere(v.into())
    }
    /// Les octets, pour l'arithmétique de signature UNIQUEMENT. Privé au module.
    fn octets(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub(crate) fn est_vide(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Matiere {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Matiere(<masquée>)")
    }
}

// ================================================================================================
// CIBLE — l'adresse complète d'un dépôt
// ================================================================================================

/// Destination objet résolue : où déposer, sous quelle identité, avec quel style d'adressage.
#[derive(Clone)]
pub(crate) struct CibleS3 {
    /// `http(s)://hôte[:port]` du service. Aucune valeur par défaut : un fournisseur ne se devine pas.
    pub(crate) endpoint: String,
    pub(crate) region: String,
    pub(crate) bucket: String,
    /// Préfixe de clé, sans barre initiale ni finale. Vide = dépôt à la racine du bucket.
    pub(crate) prefixe: String,
    acces: String,
    matiere: Matiere,
    jeton: Option<Matiere>,
    /// `true` = `/{bucket}/{clé}` sur l'hôte de l'endpoint (MinIO, Ceph, la plupart des passerelles).
    /// `false` = hôte virtuel `{bucket}.{hôte}`, chemin `/{clé}`.
    pub(crate) chemin_style: bool,
}

impl std::fmt::Debug for CibleS3 {
    /// Ni la matière, ni l'identifiant d'accès n'apparaissent. Ce `Debug` est écrit à la main
    /// précisément pour qu'un `{:?}` posé un jour dans un journal ne puisse rien révéler.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CibleS3")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefixe", &self.prefixe)
            .field("acces", &"<masqué>")
            .field("matiere", &self.matiere)
            .field("jeton", &self.jeton.as_ref().map(|_| "<masqué>"))
            .field("chemin_style", &self.chemin_style)
            .finish()
    }
}

impl CibleS3 {
    /// Construction EXPLICITE (tests, appelants qui ont déjà résolu leurs valeurs). La validation
    /// vit dans `depuis_reglages` ; ici on assemble ce qui a déjà été validé.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn neuve(
        endpoint: String,
        region: String,
        bucket: String,
        prefixe: String,
        acces: String,
        matiere: Matiere,
        jeton: Option<Matiere>,
        chemin_style: bool,
    ) -> Self {
        CibleS3 { endpoint, region, bucket, prefixe, acces, matiere, jeton, chemin_style }
    }

    /// Clé d'objet complète pour un nom de fichier d'archive : `<préfixe>/<nom>` (ou `<nom>` si le
    /// préfixe est vide).
    pub(crate) fn cle_objet(&self, nom: &str) -> String {
        if self.prefixe.is_empty() {
            nom.to_string()
        } else {
            format!("{}/{}", self.prefixe, nom)
        }
    }

    /// Hôte à joindre ET à signer. En style chemin c'est l'hôte de l'endpoint ; en hôte virtuel le
    /// bucket le préfixe (l'adressage DNS du fournisseur), donc la connexion, le SNI et l'en-tête
    /// `Host` bougent ENSEMBLE — une signature ne peut pas se désaccorder de la socket.
    pub(crate) fn hote_reel(&self) -> Result<(bool, String, u16), String> {
        let (https, hote, port) = parse_http_addr(&self.endpoint)
            .map_err(|e| format!("{CLE_S3_ENDPOINT} illisible : {e}"))?;
        if self.chemin_style {
            Ok((https, hote, port))
        } else {
            Ok((https, format!("{}.{}", self.bucket, hote), port))
        }
    }

    /// Valeur EXACTE de l'en-tête `Host` — le port n'y figure que s'il n'est pas celui du schéma.
    /// La chaîne canonique de signature reprend cette valeur telle quelle : les deux sont produites
    /// ici, donc elles ne peuvent pas diverger.
    pub(crate) fn entete_host(&self) -> Result<String, String> {
        let (https, hote, port) = self.hote_reel()?;
        let defaut = if https { 443 } else { 80 };
        Ok(if port == defaut { hote } else { format!("{hote}:{port}") })
    }

    /// Chemin canonique d'une requête pour cette clé, encodé RFC 3986 (la barre reste une barre).
    pub(crate) fn chemin_canonique(&self, cle: &str) -> String {
        let brut = if self.chemin_style {
            format!("/{}/{}", self.bucket, cle)
        } else {
            format!("/{cle}")
        };
        encoder_chemin(&brut)
    }
}

// ================================================================================================
// ANALYSE DE `s3://…` ET VALIDATION DES NOMS
// ================================================================================================

/// `s3://<bucket>[/<préfixe>]` -> `(bucket, préfixe)`. Le préfixe rendu n'a ni barre initiale ni
/// barre finale. TOUT écart est une erreur NOMMÉE : une destination mal écrite doit arrêter
/// l'ordonnanceur, jamais le faire écrire ailleurs en silence.
pub(crate) fn parse_url_s3(url: &str) -> Result<(String, String), String> {
    let reste = url
        .strip_prefix("s3://")
        .ok_or_else(|| format!("destination objet attendue sous la forme s3://<bucket>[/<préfixe>] (reçu : {url})"))?;
    let (bucket, prefixe) = match reste.split_once('/') {
        Some((b, p)) => (b, p),
        None => (reste, ""),
    };
    valider_bucket(bucket)?;
    let prefixe = prefixe.trim_end_matches('/');
    if !prefixe.is_empty() {
        valider_cle_objet(prefixe)?;
    }
    Ok((bucket.to_string(), prefixe.to_string()))
}

/// Règles de nommage d'un bucket, appliquées AVANT tout réseau : 3 à 63 caractères, minuscules,
/// chiffres, point ou tiret, ni au début ni à la fin, sans doublement de point.
pub(crate) fn valider_bucket(b: &str) -> Result<(), String> {
    if !(3..=63).contains(&b.len()) {
        return Err(format!("nom de bucket de longueur invalide (3 à 63 caractères) : {b:?}"));
    }
    if !b.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.') {
        return Err(format!("nom de bucket : minuscules, chiffres, '-' et '.' seulement : {b:?}"));
    }
    let premier = b.as_bytes()[0];
    let dernier = b.as_bytes()[b.len() - 1];
    if !(premier.is_ascii_lowercase() || premier.is_ascii_digit())
        || !(dernier.is_ascii_lowercase() || dernier.is_ascii_digit())
    {
        return Err(format!("nom de bucket : doit commencer et finir par une lettre ou un chiffre : {b:?}"));
    }
    if b.contains("..") {
        return Err(format!("nom de bucket : '..' interdit : {b:?}"));
    }
    Ok(())
}

/// Jeu de caractères ADMIS dans une clé d'objet. DÉLIBÉRÉMENT ÉTROIT — lettres, chiffres, `.`, `_`,
/// `-`, et la barre comme séparateur. Les noms que ce sink dépose sont fabriqués par
/// `backup::fmt_backup_ts` et tiennent dans ce jeu ; le préfixe vient de l'exploitant. Refuser tout
/// le reste supprime, par CONSTRUCTION, une famille entière de défauts d'encodage entre ce que la
/// socket envoie et ce que la signature couvre — au lieu de la traiter par un encodeur qu'il
/// faudrait ensuite prouver identique à celui du fournisseur.
pub(crate) fn valider_cle_objet(cle: &str) -> Result<(), String> {
    if cle.is_empty() {
        return Err("clé d'objet vide".to_string());
    }
    if cle.len() > CLE_OBJET_MAX {
        return Err(format!("clé d'objet trop longue ({} octets, maximum {CLE_OBJET_MAX})", cle.len()));
    }
    if cle.starts_with('/') || cle.ends_with('/') || cle.contains("//") {
        return Err(format!("clé d'objet : barre initiale, finale ou doublée interdite : {cle:?}"));
    }
    for segment in cle.split('/') {
        if segment == "." || segment == ".." {
            return Err(format!("clé d'objet : segment '.' ou '..' interdit : {cle:?}"));
        }
    }
    for c in cle.bytes() {
        let ok = c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'/');
        if !ok {
            return Err(format!(
                "clé d'objet : caractère non admis {:?} (admis : lettres, chiffres, '.', '_', '-', '/') : {cle:?}",
                c as char
            ));
        }
    }
    Ok(())
}

/// Encodage RFC 3986 d'un CHEMIN : la barre est un séparateur et reste telle quelle, tout ce qui
/// n'est pas « non réservé » est échappé. Sur le jeu admis par `valider_cle_objet`, cette fonction
/// est l'identité — elle est là pour que la propriété soit VÉRIFIÉE et non supposée.
pub(crate) fn encoder_chemin(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ================================================================================================
// SIGNATURE v4
// ================================================================================================

/// Le produit complet d'une signature. SEUL `autorisation` part sur la socket ; les quatre autres
/// pièces sont les ÉTAPES intermédiaires, exposées pour qu'un test puisse opposer chacune d'elles à
/// un oracle indépendant. Une signature qui ne coïnciderait que sur son résultat final ne dirait pas
/// OÙ elle diverge — et le jour où elle divergera, c'est cela qu'il faudra savoir.
///
/// Les quatre portent donc `allow(dead_code)` : hors `cfg(test)` elles ne sont lues par personne, et
/// c'est voulu. Les retirer ferait disparaître la possibilité même de la contre-épreuve.
pub(crate) struct SignatureV4 {
    #[allow(dead_code)]
    pub(crate) canonique: String,
    #[allow(dead_code)]
    pub(crate) a_signer: String,
    #[allow(dead_code)]
    pub(crate) signature: String,
    pub(crate) autorisation: String,
    #[allow(dead_code)]
    pub(crate) signes: String,
}

/// Clé de signature dérivée : HMAC en cascade date -> région -> service -> terminaison.
fn cle_de_signature(matiere: &Matiere, jour: &str, region: &str) -> [u8; 32] {
    let mut prefixee = Vec::with_capacity(4 + matiere.octets().len());
    prefixee.extend_from_slice(b"AWS4");
    prefixee.extend_from_slice(matiere.octets());
    let k_date = hmac_sha256(&prefixee, jour.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, S3_SERVICE.as_bytes());
    hmac_sha256(&k_service, S3_TERMINAISON.as_bytes())
}

/// Signe une requête et rend les pièces à émettre. `entetes` = les en-têtes À SIGNER, hors `Host`
/// (ajouté ici) : ils sont triés et normalisés par cette fonction, donc l'ordre d'appel n'a aucune
/// influence sur la signature.
///
/// `horodatage` est au format `AAAAMMJJTHHMMSSZ` — exactement celui de `backup::fmt_backup_ts`, ce
/// qui évite un second formateur de date dans le démon.
pub(crate) fn signer_v4(
    methode: &str,
    chemin_canonique: &str,
    requete_canonique_query: &str,
    hote: &str,
    horodatage: &str,
    region: &str,
    acces: &str,
    matiere: &Matiere,
    entetes_supplementaires: &[(String, String)],
    empreinte_charge: &str,
) -> Result<SignatureV4, String> {
    if horodatage.len() < 8 {
        return Err(format!("horodatage de signature invalide : {horodatage:?}"));
    }
    let jour = &horodatage[..8];

    // En-têtes signés : `host` + ce que l'appelant fournit. Triés PAR LE CODE (jamais par l'ordre
    // d'écriture) et valeurs réduites : c'est ce que la spécification exige, et le seul moyen que
    // la chaîne canonique du client et celle du service coïncident.
    let mut tries: Vec<(String, String)> = Vec::with_capacity(entetes_supplementaires.len() + 1);
    tries.push(("host".to_string(), hote.trim().to_string()));
    for (k, v) in entetes_supplementaires {
        tries.push((k.to_ascii_lowercase(), v.trim().to_string()));
    }
    tries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut canoniques = String::new();
    for (k, v) in &tries {
        canoniques.push_str(k);
        canoniques.push(':');
        canoniques.push_str(v);
        canoniques.push('\n');
    }
    let signes = tries.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");

    let canonique = format!(
        "{methode}\n{chemin_canonique}\n{requete_canonique_query}\n{canoniques}\n{signes}\n{empreinte_charge}"
    );
    let portee = format!("{jour}/{region}/{S3_SERVICE}/{S3_TERMINAISON}");
    let a_signer = format!(
        "{S3_ALGO}\n{horodatage}\n{portee}\n{}",
        sha256_hex(canonique.as_bytes())
    );
    let signature = hex_encode(&hmac_sha256(
        &cle_de_signature(matiere, jour, region),
        a_signer.as_bytes(),
    ));
    let autorisation =
        format!("{S3_ALGO} Credential={acces}/{portee}, SignedHeaders={signes}, Signature={signature}");
    Ok(SignatureV4 { canonique, a_signer, signature, autorisation, signes })
}

// ================================================================================================
// L'ISSUE — le type qui interdit d'annoncer un succès qu'on n'a pas obtenu
// ================================================================================================

/// L'étape à laquelle un dépôt s'est arrêté. Sert à ce qu'une ligne d'exploitation dise OÙ, sans
/// obliger le lecteur à deviner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Etape {
    /// Avant tout réseau : destination, identifiants, taille, nom d'objet.
    Configuration,
    /// Première passe sur le fichier (empreinte de la charge).
    Empreinte,
    /// La requête de dépôt elle-même.
    Envoi,
    /// La relecture qui transforme « le service a répondu 2xx » en « l'objet est là ».
    Confirmation,
}

impl Etape {
    pub(crate) fn nom(self) -> &'static str {
        match self {
            Etape::Configuration => "configuration",
            Etape::Empreinte => "empreinte",
            Etape::Envoi => "envoi",
            Etape::Confirmation => "confirmation",
        }
    }
}

/// Issue d'un dépôt. TROIS états exclusifs, et un seul vaut succès.
///
/// L'ordre des variantes n'a rien d'arbitraire : `Depose` porte la PREUVE (octets confirmés,
/// étiquette d'entité rendue par le service). Aucune conversion, aucun `Default`, aucun `From` ne
/// permet de la fabriquer ailleurs qu'au point unique de `deposer_fichier` où la relecture a réussi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IssueDepot {
    /// Déposé ET CONFIRMÉ : le dépôt a rendu 2xx, puis une relecture a rendu 200 avec exactement
    /// `octets` octets.
    Depose { octets: u64, etiquette: String },
    /// Le service a RÉPONDU, et la réponse n'établit pas le dépôt : statut non-2xx, relecture
    /// absente, ou objet distant de taille différente. Il y a un verdict, et il est négatif.
    Refuse { etape: Etape, statut: u16, detail: String },
    /// AUCUN verdict : rien n'a répondu (configuration, entrée-sortie locale, DNS, TCP, TLS,
    /// délai). Ne dit pas que l'objet n'est pas là — dit qu'on ne sait pas.
    Impossible { etape: Etape, motif: String },
}

impl IssueDepot {
    /// LE seul prédicat de succès. Un appelant ne peut pas conclure autrement sans écrire lui-même
    /// un filtrage exhaustif — et il verra alors les deux autres variantes.
    pub(crate) fn est_depose(&self) -> bool {
        matches!(self, IssueDepot::Depose { .. })
    }
}

impl std::fmt::Display for IssueDepot {
    /// La ligne d'exploitation. Les trois états ont des préfixes DIFFÉRENTS et non ambigus : aucun
    /// filtrage de journal ne peut prendre un refus pour un dépôt.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssueDepot::Depose { octets, etiquette } => write!(
                f,
                "DÉPOSÉ ET CONFIRMÉ : {octets} octets relus sur la destination objet (étiquette {etiquette})"
            ),
            IssueDepot::Refuse { etape, statut, detail } => write!(
                f,
                "REFUSÉ à l'étape {} : statut {statut} — {detail} (AUCUNE sauvegarde distante pour ce cycle)",
                etape.nom()
            ),
            IssueDepot::Impossible { etape, motif } => write!(
                f,
                "IMPOSSIBLE à l'étape {} : {motif} (aucun verdict du service — l'état distant est INCONNU)",
                etape.nom()
            ),
        }
    }
}

// ================================================================================================
// TRANSPORT — écriture en flux, lecture de la réponse
// ================================================================================================

/// Écrit la tête, POUSSE le corps par tranches bornées, puis lit la réponse entière.
///
/// LE CAS QUI MÉRITE SON PARAGRAPHE : un service qui refuse (par exemple sur la signature) peut
/// répondre puis fermer AVANT d'avoir lu tout le corps. L'écriture échoue alors avec un tuyau rompu.
/// Rendre « écriture impossible » serait EXACT mais moins utile que la vérité disponible : la
/// réponse est peut-être déjà dans le tampon de réception. On tente donc la lecture, et si elle rend
/// une réponse HTTP analysable, c'est ELLE qui fait foi. Un refus reste un refus, jamais un
/// « impossible » par accident — et jamais, dans aucune branche, un succès.
fn pousser_et_lire<S: std::io::Read + std::io::Write>(
    mut flux: S,
    tete: &[u8],
    corps: Option<&mut dyn std::io::Read>,
) -> Result<HttpResp, String> {
    let mut erreur_ecriture: Option<String> = None;
    if let Err(e) = flux.write_all(tete) {
        erreur_ecriture = Some(format!("écriture de l'en-tête : {e}"));
    }
    if erreur_ecriture.is_none() {
        if let Some(src) = corps {
            let mut tampon = vec![0u8; TAMPON];
            loop {
                let n = match src.read(&mut tampon) {
                    Ok(n) => n,
                    Err(e) => {
                        erreur_ecriture = Some(format!("lecture du fichier local : {e}"));
                        break;
                    }
                };
                if n == 0 {
                    break;
                }
                if let Err(e) = flux.write_all(&tampon[..n]) {
                    erreur_ecriture = Some(format!("écriture du corps : {e}"));
                    break;
                }
            }
        }
    }
    let _ = flux.flush();

    let mut brut = Vec::new();
    let lecture = flux.read_to_end(&mut brut);
    if brut.is_empty() {
        // Rien à interpréter : l'erreur d'écriture (si elle existe) est la seule vérité disponible.
        return Err(erreur_ecriture.unwrap_or_else(|| match lecture {
            Ok(_) => "réponse vide du service objet".to_string(),
            Err(e) => format!("lecture de la réponse : {e}"),
        }));
    }
    match parse_http_full(&brut) {
        Ok(r) => Ok(r),
        // Réponse illisible ET écriture cassée -> c'est l'écriture qu'il faut nommer.
        Err(e) => Err(erreur_ecriture.unwrap_or(e)),
    }
}

/// Ouvre la socket (TLS si le schéma l'exige), pousse, lit, analyse. Le corps est un `Read`, jamais
/// un tampon : c'est ce qui borne la mémoire.
fn aller_retour(
    https: bool,
    hote: &str,
    port: u16,
    tete: &[u8],
    corps: Option<&mut dyn std::io::Read>,
) -> Result<HttpResp, String> {
    let sock = std::net::TcpStream::connect((hote, port))
        .map_err(|e| format!("connexion {hote}:{port} : {e}"))?;
    let _ = sock.set_read_timeout(Some(DELAI_SOCKET));
    let _ = sock.set_write_timeout(Some(DELAI_SOCKET));
    if !https {
        return pousser_et_lire(sock, tete, corps);
    }
    // MÊME pile TLS que le client interne : rustls/ring, racines chargées par `vault_root_store`
    // (fail-closed si le magasin est vide). Aucun second jeu de racines n'entre dans le démon.
    let roots = vault_root_store()?;
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls versions : {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let nom = rustls::pki_types::ServerName::try_from(hote.to_string())
        .map_err(|_| format!("nom TLS invalide : {hote}"))?;
    let mut conn = rustls::ClientConnection::new(std::sync::Arc::new(config), nom)
        .map_err(|e| format!("rustls client : {e}"))?;
    let mut sock = sock;
    let tls = rustls::Stream::new(&mut conn, &mut sock);
    pousser_et_lire(tls, tete, corps)
}

/// Empreinte SHA-256 d'un fichier, calculée EN FLUX. La mémoire tenue est celle du tampon, pas celle
/// du fichier : c'est la propriété qui rend ce sink compatible avec le budget du produit.
pub(crate) fn empreinte_fichier(chemin: &std::path::Path) -> Result<(String, u64), String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(chemin).map_err(|e| format!("ouverture {} : {e}", chemin.display()))?;
    let mut h = Sha256::new();
    let mut tampon = vec![0u8; TAMPON];
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut tampon).map_err(|e| format!("lecture {} : {e}", chemin.display()))?;
        if n == 0 {
            break;
        }
        h.update(&tampon[..n]);
        total += n as u64;
    }
    Ok((hex_encode(&h.finalize()), total))
}

/// Construit la tête HTTP/1.1 d'une requête signée.
fn tete_http(
    methode: &str,
    chemin: &str,
    host: &str,
    entetes: &[(String, String)],
    autorisation: &str,
    longueur: Option<u64>,
) -> Vec<u8> {
    let mut t = format!("{methode} {chemin} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (k, v) in entetes {
        t.push_str(&format!("{k}: {v}\r\n"));
    }
    t.push_str(&format!("Authorization: {autorisation}\r\n"));
    if let Some(n) = longueur {
        t.push_str(&format!("Content-Length: {n}\r\n"));
    }
    t.push_str("\r\n");
    t.into_bytes()
}

/// En-têtes signés communs aux deux requêtes (empreinte de charge, horodatage, jeton de session).
fn entetes_signes(empreinte: &str, horodatage: &str, jeton: Option<&Matiere>) -> Vec<(String, String)> {
    let mut v = vec![
        ("x-amz-content-sha256".to_string(), empreinte.to_string()),
        ("x-amz-date".to_string(), horodatage.to_string()),
    ];
    if let Some(j) = jeton {
        // Le jeton de session EST une matière secrète, et il DOIT pourtant voyager dans un en-tête.
        // C'est le seul endroit du module où des octets de matière deviennent du texte, et il est
        // volontairement unique : la valeur part sur la socket, jamais dans un journal.
        v.push(("x-amz-security-token".to_string(), String::from_utf8_lossy(j.octets()).into_owned()));
    }
    v
}

// ================================================================================================
// LE DÉPÔT
// ================================================================================================

/// Dépose `chemin` sous la clé `<préfixe>/<nom>` de la cible, puis RELIT l'objet pour confirmer.
///
/// `horodatage` au format `AAAAMMJJTHHMMSSZ` (celui de `backup::fmt_backup_ts`) — passé en paramètre
/// et non lu de l'horloge, pour qu'un test signe un vecteur reproductible.
///
/// Aucune branche ne rend `Depose` sans être passée par la relecture : c'est la propriété centrale
/// de cette fonction, et le test `sink_s3_confirmation_qui_ment_est_un_refus` la met en défaut si
/// elle disparaît.
pub(crate) fn deposer_fichier(
    cible: &CibleS3,
    nom: &str,
    chemin: &std::path::Path,
    horodatage: &str,
) -> IssueDepot {
    // ── Étape 1 : tout ce qui peut être refusé SANS ouvrir de socket l'est ici. ───────────────────
    let cle = cible.cle_objet(nom);
    if let Err(e) = valider_cle_objet(&cle) {
        return IssueDepot::Impossible { etape: Etape::Configuration, motif: e };
    }
    if cible.matiere.est_vide() || cible.acces.is_empty() {
        return IssueDepot::Impossible {
            etape: Etape::Configuration,
            motif: format!("identifiants incomplets ({CLE_S3_ACCESS} / {CLE_S3_MATIERE})"),
        };
    }
    let (https, hote, port) = match cible.hote_reel() {
        Ok(v) => v,
        Err(e) => return IssueDepot::Impossible { etape: Etape::Configuration, motif: e },
    };
    let host = match cible.entete_host() {
        Ok(v) => v,
        Err(e) => return IssueDepot::Impossible { etape: Etape::Configuration, motif: e },
    };
    let chemin_canonique = cible.chemin_canonique(&cle);

    // ── Étape 2 : empreinte de la charge, en flux. ───────────────────────────────────────────────
    let (empreinte, taille) = match empreinte_fichier(chemin) {
        Ok(v) => v,
        Err(e) => return IssueDepot::Impossible { etape: Etape::Empreinte, motif: e },
    };
    if taille > PLAFOND_PUT_SIMPLE {
        return IssueDepot::Impossible {
            etape: Etape::Configuration,
            motif: format!(
                "archive de {taille} octets au-dessus du plafond d'un dépôt en une requête \
                 ({PLAFOND_PUT_SIMPLE} octets) — le téléversement en plusieurs parties n'est pas implémenté"
            ),
        };
    }

    // ── Étape 3 : le dépôt. ──────────────────────────────────────────────────────────────────────
    let entetes = entetes_signes(&empreinte, horodatage, cible.jeton.as_ref());
    let sig = match signer_v4(
        "PUT", &chemin_canonique, "", &host, horodatage, &cible.region,
        &cible.acces, &cible.matiere, &entetes, &empreinte,
    ) {
        Ok(s) => s,
        Err(e) => return IssueDepot::Impossible { etape: Etape::Configuration, motif: e },
    };
    let tete = tete_http("PUT", &chemin_canonique, &host, &entetes, &sig.autorisation, Some(taille));
    let mut fichier = match std::fs::File::open(chemin) {
        Ok(f) => f,
        Err(e) => {
            return IssueDepot::Impossible {
                etape: Etape::Envoi,
                motif: format!("ouverture {} : {e}", chemin.display()),
            }
        }
    };
    let reponse = match aller_retour(https, &hote, port, &tete, Some(&mut fichier)) {
        Ok(r) => r,
        Err(e) => return IssueDepot::Impossible { etape: Etape::Envoi, motif: e },
    };
    if !(200..300).contains(&reponse.status) {
        // Le corps de la réponse n'est JAMAIS remonté (invariant du client interne) : il peut
        // contenir la requête réémise par le service, donc des en-têtes d'autorisation.
        return IssueDepot::Refuse {
            etape: Etape::Envoi,
            statut: reponse.status,
            detail: format!("le service objet a refusé le dépôt de {cle}"),
        };
    }
    let etiquette = reponse.header("ETag").unwrap_or("").trim_matches('"').to_string();

    // ── Étape 4 : la CONFIRMATION. Sans elle, on ne dispose que d'une promesse. ───────────────────
    let entetes_h = entetes_signes(SHA256_CHARGE_VIDE, horodatage, cible.jeton.as_ref());
    let sig_h = match signer_v4(
        "HEAD", &chemin_canonique, "", &host, horodatage, &cible.region,
        &cible.acces, &cible.matiere, &entetes_h, SHA256_CHARGE_VIDE,
    ) {
        Ok(s) => s,
        Err(e) => return IssueDepot::Impossible { etape: Etape::Confirmation, motif: e },
    };
    let tete_h = tete_http("HEAD", &chemin_canonique, &host, &entetes_h, &sig_h.autorisation, None);
    let confirmation = match aller_retour(https, &hote, port, &tete_h, None) {
        Ok(r) => r,
        Err(e) => {
            return IssueDepot::Impossible {
                etape: Etape::Confirmation,
                motif: format!(
                    "dépôt de {cle} accepté ({}) mais IMPOSSIBLE à relire : {e}",
                    reponse.status
                ),
            }
        }
    };
    if confirmation.status != 200 {
        return IssueDepot::Refuse {
            etape: Etape::Confirmation,
            statut: confirmation.status,
            detail: format!("dépôt de {cle} accepté ({}) mais l'objet ne se relit pas", reponse.status),
        };
    }
    let annonce: Option<u64> = confirmation.header("Content-Length").and_then(|v| v.trim().parse().ok());
    match annonce {
        Some(n) if n == taille => IssueDepot::Depose { octets: taille, etiquette },
        Some(n) => IssueDepot::Refuse {
            etape: Etape::Confirmation,
            statut: confirmation.status,
            detail: format!(
                "l'objet {cle} relu annonce {n} octets au lieu de {taille} — dépôt NON établi"
            ),
        },
        None => IssueDepot::Refuse {
            etape: Etape::Confirmation,
            statut: confirmation.status,
            detail: format!("l'objet {cle} relu n'annonce aucune taille — dépôt NON établi"),
        },
    }
}

// ================================================================================================
// RÉSOLUTION DEPUIS LA CONFIGURATION
// ================================================================================================

/// Construit la cible depuis la destination `s3://…` et les réglages. FAIL-CLOSED : toute pièce
/// manquante rend une erreur NOMMÉE. L'ordonnanceur ne doit jamais retomber sur un dépôt local en
/// silence — une sauvegarde qu'on croit distante et qui reste sur le nœud est le défaut que ce
/// module existe pour ne pas fabriquer.
///
/// Les identifiants passent par `cfg_secret`, donc `_REF` (`vault:`/`file:`/`env:`/`literal:`) et
/// `_FILE` fonctionnent comme pour les autres secrets du produit ; aucune valeur ne vit dans le dépôt.
pub(crate) fn depuis_reglages(
    conf: &std::collections::HashMap<String, String>,
    dest: &str,
) -> Result<CibleS3, String> {
    let (bucket, prefixe) = parse_url_s3(dest)?;
    let endpoint = cfg(conf, CLE_S3_ENDPOINT, "");
    if endpoint.is_empty() {
        return Err(format!(
            "{CLE_S3_ENDPOINT} non configuré — l'adresse du service objet ne se devine pas \
             (exemples : https://s3.<région>.<fournisseur>, http://minio.<espace>:9000)"
        ));
    }
    parse_http_addr(&endpoint).map_err(|e| format!("{CLE_S3_ENDPOINT}={endpoint} : {e}"))?;
    let region = cfg(conf, CLE_S3_REGION, REGION_DEFAUT);
    if region.is_empty() {
        return Err(format!("{CLE_S3_REGION} vide — la signature exige une région non vide"));
    }
    let acces = cfg(conf, CLE_S3_ACCESS, "");
    if acces.is_empty() {
        return Err(format!("{CLE_S3_ACCESS} non configuré"));
    }
    let matiere = Matiere::neuve(cfg_secret(conf, CLE_S3_MATIERE));
    if matiere.est_vide() {
        return Err(format!(
            "{CLE_S3_MATIERE} non configuré (ou {CLE_S3_MATIERE}_FILE / {CLE_S3_MATIERE}_REF)"
        ));
    }
    let jeton_brut = cfg_secret(conf, CLE_S3_JETON);
    let jeton = if jeton_brut.is_empty() { None } else { Some(Matiere::neuve(jeton_brut)) };
    // Style CHEMIN par défaut : c'est celui que servent MinIO, Ceph et les passerelles, et le seul
    // qui fonctionne sans enregistrement DNS par bucket. Aucun fournisseur n'est supposé.
    let chemin_style = cfg(conf, CLE_S3_CHEMIN_STYLE, "1") != "0";
    Ok(CibleS3::neuve(endpoint, region, bucket, prefixe, acces, matiere, jeton, chemin_style))
}

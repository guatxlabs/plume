//! Lecture maildir (porte du mail-scanner-service GuatX-Infra, cf. ADR-0008).
//! Detecte le layout (PLAT <root>/<user> ou NESTED <root>/<domain>/<user>),
//! liste les comptes, enumere les messages, parse les CHAMPS (jamais de body shippe).
use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Plafond d'octets lus par fichier maildir (couvre message_size_limit + overhead MIME/base64).
pub const MAX_RAW_BYTES: usize = 15_000_000;
/// Plafond du foin passe au moteur regex sur les parties body (apres decodage MIME).
pub const MAX_HAYSTACK_BYTES: usize = 5_000_000;

pub fn validate_email(email: &str) -> Result<(&str, &str)> {
    let (local, domain) = email.split_once('@').ok_or_else(|| anyhow!("email invalide"))?;
    if local.is_empty() || domain.is_empty() {
        return Err(anyhow!("email invalide"));
    }
    if local.contains('/') || local.contains("..") || domain.contains('/') || domain.contains("..") {
        return Err(anyhow!("caracteres invalides dans l'email"));
    }
    Ok((local, domain))
}

pub fn account_path(root: &str, email: &str) -> Result<PathBuf> {
    let (local, domain) = validate_email(email)?;
    let nested = Path::new(root).join(domain).join(local);
    if nested.exists() {
        return Ok(nested);
    }
    Ok(Path::new(root).join(local))
}

/// `P10.33-m` — ce que `account_path` resout pour `email`, juge sur le DISQUE et non sur l'adresse ecrite.
pub enum CompteResolu {
    /// Rien a ce chemin : la lecture echouera « compte introuvable », sans rien ouvrir.
    Introuvable,
    /// Le chemin resolu sort de la racine (lien) : aucun compte que le balayage nomme.
    HorsRacine,
    /// Composants du chemin resolu, relatifs a la racine resolue.
    Sous(Vec<String>),
}

/// Resout le repertoire que `body` lirait pour `email` (`canonicalize` : liens et `.` suivis, un `lstat`
/// par composant du chemin — le repertoire du compte n'est ni liste ni ouvert). Toute autre erreur que
/// « introuvable » remonte : on ne lit pas une boite dont on n'a pas su dire si elle est retiree.
pub fn resoudre_compte(root: &str, email: &str) -> Result<CompteResolu> {
    let base = account_path(root, email)?;
    let racine = std::fs::canonicalize(root).with_context(|| format!("racine maildir {root}"))?;
    let resolu = match std::fs::canonicalize(&base) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CompteResolu::Introuvable),
        Err(e) => return Err(anyhow!("compte non resolu ({})", e.kind())),
    };
    Ok(match resolu.strip_prefix(&racine) {
        Ok(rel) => CompteResolu::Sous(rel.iter().map(|c| c.to_string_lossy().into_owned()).collect()),
        Err(_) => CompteResolu::HorsRacine,
    })
}

/// `P10.33-m` — UN NOM DE DOSSIER NE DESIGNE QU'UN SOUS-REPERTOIRE DU COMPTE. Il etait joint au chemin
/// du compte sans examen : `Sent/../../bob` resolvait `<racine>/bob`, une AUTRE boite, exclue ou non, et
/// le controle d'exclusion de `body` (porte sur le compte nomme) ne la voyait pas. Refus d'un nom vide,
/// d'un separateur (`/`, `\`), de `..` et de tout caractere de controle (NUL compris) — AVANT tout acces
/// au disque. Le nom n'est pas recopie dans l'erreur.
fn dossier_valide(folder: &str) -> Result<()> {
    if folder.is_empty()
        || folder.contains(['/', '\\'])
        || folder.contains("..")
        || folder.chars().any(char::is_control)
    {
        return Err(anyhow!(
            "nom de dossier refuse (vide, separateur, `..` ou caractere de controle) : un dossier ne \
             designe qu'un sous-repertoire du compte"
        ));
    }
    Ok(())
}

/// `P10.33-m` — `dir` (un dossier du compte, ou son `cur/`/`new/`) RESOUT-il sous le compte ? Un lien qui
/// en sort (`.Sent -> ../bob`) ferait enumerer une autre boite : `canonicalize` (un `lstat` par
/// composant, rien n'est liste) puis comparaison par composants au compte resolu.
fn sous_le_compte(dir: &Path, compte: &Path) -> Result<()> {
    let resolu = std::fs::canonicalize(dir).map_err(|e| anyhow!("dossier non resolu ({})", e.kind()))?;
    if !resolu.starts_with(compte) {
        return Err(anyhow!("dossier hors du compte : un lien sort de la boite, rien n'y est lu"));
    }
    Ok(())
}

fn folder_subpath(folder: &str) -> String {
    if folder == "INBOX" {
        String::new()
    } else {
        format!(".{}", folder.trim_start_matches('.'))
    }
}

fn is_maildir(path: &Path) -> bool {
    path.join("cur").is_dir() || path.join("new").is_dir()
}

/// Un repertoire de DOMAINE (layout NESTED) contient des maildirs d'utilisateurs. Un repertoire qu'on ne
/// sait pas LISTER n'est ni « domaine » ni « compte plat » : l'erreur REMONTE (`P4.1-r`). Avant, il
/// repondait `false`, et l'appelant en faisait un compte fantome `<domaine>@<mail_domain>` pendant que
/// les boites des utilisateurs qu'il contient n'etaient jamais balayees — « 0 alerte », sans trace.
/// Une entree illisible en cours de parcours remonte de meme : un parcours interrompu n'est pas un
/// parcours complet (`S36`).
///
/// `P10.33-m` — un enfant dont le nom est EXCLU pour ce domaine n'est pas sonde (aucun `stat` dans son
/// repertoire) : l'exploitant l'a nomme comme un compte de ce domaine, c'est la preuve retenue que le
/// repertoire est un domaine. Le sonder pour en decider, ce serait ouvrir le compte qu'on retire.
fn has_maildir_children(
    path: &Path,
    domaine: &str,
    exclusion: &crate::exclusion::Exclusion,
) -> std::io::Result<bool> {
    for e in std::fs::read_dir(path)? {
        let e = e?;
        if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        if exclusion.exclut(&e.file_name().to_string_lossy(), domaine) {
            return Ok(true);
        }
        if is_maildir(&e.path()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Emails des comptes (gere layout PLAT et NESTED, comme le scanner), et le NOMBRE de comptes retires
/// par `PLUME_MAIL_EXCLURE_COMPTES` (`P10.33-m`).
///
/// UN COMPTE EXCLU N'EST JAMAIS OUVERT. La decision tombe sur le NOM rendu par l'enumeration de son
/// parent, AVANT toute sonde de son repertoire (`is_maildir` y regarde deja `cur/` et `new/`) : ni
/// `stat` a l'interieur, ni `read_dir`, ni lecture de message, ni cle dans l'etat incremental — le
/// compte ne figure pas dans la liste rendue. Consequence assumee en layout IMBRIQUE : un repertoire
/// de premier niveau dont le nom egale une entree exclue (partie locale, ou `<nom>@PLUME_MAIL_DOMAIN`)
/// est retire SANS savoir s'il est un compte plat ou un domaine ; il compte alors pour un exclu.
pub fn list_account_emails(
    root: &str,
    mail_domain: &str,
    exclusion: &crate::exclusion::Exclusion,
) -> Result<(Vec<String>, usize)> {
    let mut out = Vec::new();
    let mut exclus = 0usize;
    let root_path = Path::new(root);
    if !root_path.exists() {
        return Err(anyhow!("maildir root introuvable: {}", root));
    }
    for entry in std::fs::read_dir(root_path)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        if exclusion.exclut(&name, mail_domain) {
            exclus += 1;
            continue;
        }
        let path = entry.path();
        if is_maildir(&path) {
            out.push(format!("{}@{}", name, mail_domain));
        } else if has_maildir_children(&path, &name, exclusion)? {
            let domain = name;
            for ue in std::fs::read_dir(&path)? {
                let ue = ue?;
                if !ue.file_type()?.is_dir() {
                    continue;
                }
                let user = ue.file_name().to_string_lossy().to_string();
                if user.starts_with('.') {
                    continue;
                }
                if exclusion.exclut(&user, &domain) {
                    exclus += 1;
                    continue;
                }
                out.push(format!("{}@{}", user, domain));
            }
        } else {
            out.push(format!("{}@{}", name, mail_domain));
        }
    }
    out.sort();
    out.dedup();
    Ok((out, exclus))
}

/// Chemins (dossier, fichier) des messages cur+new ; folder "*"/"all" = tous les dossiers.
/// Chemins des messages, ET le nombre de points d'enumeration que le parcours n'a pas su lire.
/// Ce second nombre n'est pas cosmetique : chaque point perdu est un ou plusieurs messages qui ne
/// seront JAMAIS analyses, et dont l'absence se lit « 0 alerte ».
pub fn message_paths(root: &str, email: &str, folder: &str) -> Result<(Vec<(String, PathBuf)>, usize)> {
    let base = account_path(root, email)?;
    if !base.exists() {
        return Err(anyhow!("compte introuvable: {}", email));
    }
    let tous = folder == "*" || folder.eq_ignore_ascii_case("all");
    if !tous && folder != "INBOX" {
        dossier_valide(folder)?;
    }
    let compte_resolu =
        std::fs::canonicalize(&base).map_err(|e| anyhow!("compte non resolu ({})", e.kind()))?;
    let mut illisibles = 0usize;
    let folder_dirs: Vec<(String, PathBuf)> = if tous {
        let mut dirs = vec![("INBOX".to_string(), base.clone())];
        // Les SOUS-DOSSIERS du compte (`.Sent`, `.Junk`…). Un compte qu'on ne sait pas lister, ou une entree
        // qui refuse l'enumeration, c'est un ou plusieurs dossiers entiers qui ne seront JAMAIS analyses :
        // COMPTE dans `illisibles` et avoue par l'appelant (`P4.1-r`) — avant, seule l'INBOX restait et
        // l'absence des autres se lisait « 0 alerte ».
        match std::fs::read_dir(&base) {
            Ok(entries) => {
                for e in entries {
                    let e = match e {
                        Ok(e) => e,
                        Err(_) => {
                            illisibles += 1;
                            continue;
                        }
                    };
                    let n = e.file_name().to_string_lossy().to_string();
                    if n.starts_with('.') && n.len() > 1 && e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        dirs.push((n.trim_start_matches('.').to_string(), e.path()));
                    }
                }
            }
            Err(_) => illisibles += 1,
        }
        dirs
    } else if folder == "INBOX" {
        vec![("INBOX".to_string(), base.clone())]
    } else {
        let p = base.join(folder_subpath(folder));
        if !p.exists() {
            return Err(anyhow!("dossier introuvable: {}", folder));
        }
        sous_le_compte(&p, &compte_resolu)?;
        vec![(folder.to_string(), p)]
    };

    let mut out = Vec::new();
    for (folder_name, folder_dir) in folder_dirs {
        for sub in ["cur", "new"] {
            let d = folder_dir.join(sub);
            if !d.exists() {
                continue;
            }
            // `cur/` ou `new/` en lien hors du compte : refuse, comme un dossier qui en sort.
            sous_le_compte(&d, &compte_resolu)?;
            // UN PARCOURS INTERROMPU N'EST PAS UN PARCOURS COMPLET (`S36`). `flatten()` sautait en
            // silence toute entree que l'enumeration refuse : la liste rendue etait alors PLUS PETITE
            // que la boite reelle, et les messages manquants n'etaient jamais analyses. Le compte est
            // remonte a l'appelant, qui l'avoue.
            for entry in WalkDir::new(&d).max_depth(1) {
                match entry {
                    Ok(entry) => {
                        if entry.file_type().is_file() {
                            out.push((folder_name.clone(), entry.path().to_path_buf()));
                        }
                    }
                    Err(_) => illisibles += 1,
                }
            }
        }
    }
    Ok((out, illisibles))
}

/// Localise un message par son id de fichier (egal ou prefixe). Pour le body-fetch gate.
pub fn find_message(root: &str, email: &str, folder: &str, id: &str) -> Result<(String, PathBuf)> {
    for (fname, p) in message_paths(root, email, folder)?.0 {
        // Un nom de fichier non UTF-8 ne peut pas egaler un identifiant texte : c'est une VALEUR (vide),
        // pas un abandon — et la fin de fonction dit « introuvable » si rien n'a correspondu.
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if !name.is_empty() && (name == id || name.starts_with(id)) {
            return Ok((fname, p));
        }
    }
    Err(anyhow!("message introuvable: {}", id))
}

pub fn read_capped(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).with_context(|| format!("open {:?}", path))?;
    let mut buf = Vec::new();
    f.by_ref().take(MAX_RAW_BYTES as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

/// En-tetes pertinents pour le triage/forensique (allowliste : spam, auth, provenance).
pub const RELEVANT_HEADERS: [&str; 8] = [
    "X-Spam-Flag", "X-Spam-Score", "X-Spam-Level", "Authentication-Results",
    "Received-SPF", "Return-Path", "Message-ID", "DKIM-Signature",
];

/// Champs parses d'un message. `text_body`/`html_body` ne sont retournes au central
/// QUE par le chemin body-fetch gate+audite ; le scan local ne shippe que des samples.
pub struct Parsed {
    /// `false` quand le decodeur MIME a REFUSE le message : les champs ci-dessous sont alors tous
    /// vides, et aucun motif ne peut s'y appliquer. Sans ce drapeau, ce cas est indiscernable d'un
    /// message parfaitement anodin (`S36`).
    pub decode: bool,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub date: String,
    pub message_id: String,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub headers: Vec<(String, String)>,
}

/// UN MESSAGE QUE LE DECODEUR REFUSE N'EST PAS UN MESSAGE VIDE (`S36`).
///
/// LE DEFAUT FERME ICI. Quand le decodeur MIME rendait `None`, cette fonction fabriquait un `Parsed`
/// entierement VIDE : ni expediteur, ni sujet, ni corps. Les motifs de detection s'appliquent ensuite
/// a ces champs — et un champ vide ne declenche RIEN. « Aucune alerte » etait donc la reponse a un
/// message qu'on n'avait pas su ouvrir.
///
/// PORTEE MESUREE, ET ELLE EST PLUS ETROITE QUE LA FIGURE. Sonde du decodeur livre (`mail-parser`
/// 0.10, sonde ecrite pour ce lot) : il n'a REFUSE qu'une entree VIDE — des octets arbitraires, des
/// blancs seuls, une ligne sans en-tete sont tous acceptes. Le cas reel couvert ici est donc celui
/// d'un fichier de message a ZERO octet : une ecriture tronquee, un fichier cree dans `new/` avant
/// d'etre rempli, un disque plein. Ce n'est pas une forme qu'un expediteur choisit, et il ne faut pas
/// promettre le contraire ; c'est en revanche exactement le genre de fichier qu'une panne laisse
/// derriere elle, et il se lisait « message sain ». Un decodeur plus strict demain elargira ce cas
/// sans qu'aucun appelant n'ait a changer.
///
/// `decode` PORTE LE FAIT, et l'appelant l'AVOUE. Le champ est le seul moyen de distinguer un message
/// reellement anodin (decode, aucun motif) d'un message jamais examine.
pub fn parse_msg(raw: &[u8]) -> Parsed {
    use mail_parser::MessageParser;
    match MessageParser::default().parse(raw) {
        Some(m) => {
            let from = m
                .from()
                .and_then(|a| a.first())
                .and_then(|a| a.address.as_deref().map(|s| s.to_string()))
                .unwrap_or_default();
            let to = m
                .to()
                .and_then(|a| a.first())
                .and_then(|a| a.address.as_deref().map(|s| s.to_string()))
                .unwrap_or_default();
            let headers = RELEVANT_HEADERS
                .iter()
                .filter_map(|h| {
                    m.header(*h)
                        .and_then(|v| v.as_text())
                        .map(|t| (h.to_string(), t.to_string()))
                })
                .collect();
            Parsed {
                decode: true,
                from,
                to,
                subject: m.subject().unwrap_or("").to_string(),
                date: m.date().map(|d| d.to_rfc3339()).unwrap_or_default(),
                message_id: m.message_id().unwrap_or("").to_string(),
                text_body: m.body_text(0).map(|s| s.into_owned()),
                html_body: m.body_html(0).map(|s| s.into_owned()),
                headers,
            }
        }
        None => Parsed {
            decode: false,
            from: String::new(),
            to: String::new(),
            subject: String::new(),
            date: String::new(),
            message_id: String::new(),
            text_body: None,
            html_body: None,
            headers: Vec::new(),
        },
    }
}


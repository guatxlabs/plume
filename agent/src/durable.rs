//! PUBLICATION DURABLE D'UN FICHIER — la VOIE UNIQUE de l'agent (`S27`).
//!
//! DEUX PROPRIÉTÉS QUE « écrire un temporaire puis renommer » NE DONNE PAS ENSEMBLE, et qu'on
//! confond constamment :
//!
//!   ATOMICITÉ DU CONTENU — après le `rename`, un lecteur voit l'ANCIEN fichier ou le NOUVEAU,
//!   jamais un fichier à moitié écrit. Le `rename` la donne, seul, et c'est ce que le code faisait.
//!
//!   DURABILITÉ — après une coupure d'alimentation ou du noyau, l'opération SURVIT. Le `rename` ne
//!   la donne PAS. Il faut deux synchronisations, et elles ne sont pas interchangeables :
//!     1. le CONTENU du temporaire, AVANT le renommage — sinon on publie un nom qui désigne des
//!        octets qui n'ont jamais atteint le disque, c'est-à-dire un fichier VIDE au redémarrage ;
//!     2. le RÉPERTOIRE, APRÈS le renommage — sinon l'entrée de répertoire peut manquer alors que
//!        le fichier existe : les octets sont là, leur NOM n'y est pas, donc personne ne les
//!        trouvera jamais. Un spool est parcouru par nom : un fichier sans entrée est un fichier
//!        perdu.
//!
//! POURQUOI CE MODULE EXISTE PLUTÔT QUE TROIS CORRECTIFS. Le motif était écrit trois fois dans ce
//! binaire (tampon d'événements, curseurs de source, base de référence FIM), avec trois variantes
//! de permissions et trois façons de nommer le temporaire — dont une qui n'assainissait pas le nom
//! du temporaire alors que le nom final l'était. Un quatrième site aurait refait le même choix. Il
//! n'y a désormais qu'un seul endroit où un fichier se publie, et `tests::aucun_autre_site_ne_
//! reinvente_la_publication` REFUSE tout `rename(` écrit ailleurs dans ce binaire : la règle n'est
//! pas une consigne, c'est une garde DÉRIVÉE de l'arbre des sources, donc valable pour le code
//! écrit demain.
//!
//! COÛT — MESURÉ le 2026-08-20 (NVMe, btrfs sur LVM, fichiers de 1 Kio à 64 Kio, 300 publications
//! par variante) : `rename` seul 0,04–0,08 ms par fichier ; `rename` + les DEUX synchronisations
//! 8–9 ms. Chaque `fsync` coûte ~4,7 ms et ce coût est celui de la BARRIÈRE d'écriture, pas de la
//! taille du fichier (identique de 1 Kio à 64 Kio). Ce prix est payable ICI et il faut dire
//! pourquoi : l'agent publie une entrée de spool par source et par cycle de collecte (`flush_
//! interval_secs`, quelques secondes au minimum) et un curseur par entrée acquittée — quelques
//! dizaines de millisecondes par minute. Le même prix sur un récepteur appelé à chaque requête HTTP
//! ne serait PAS le même arbitrage, et ce module ne prétend rien pour ces surfaces-là.
//!
//! CE QUE LA VOIE GARANTIT, PAR CIBLE — dit ici parce qu'une promesse non bornée est une promesse
//! fausse :
//!   • unix : contenu synchronisé avant publication, répertoire synchronisé après. La publication
//!     survit à une coupure dès lors que le matériel n'a pas menti sur son propre `flush`.
//!   • Windows : le contenu est synchronisé (`sync_all`), le répertoire NE L'EST PAS — un descripteur
//!     de répertoire n'y est pas ouvrable sans `FILE_FLAG_BACKUP_SEMANTICS`, hors de portée de la
//!     bibliothèque standard. La publication y est donc ATOMIQUE et son CONTENU durable, sans
//!     garantie sur l'entrée de répertoire. C'est écrit ici, dans `agent/README.md`, et le compteur
//!     de synchronisations le montre à l'exécution plutôt que de le laisser croire.

use std::cell::Cell;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

thread_local! {
    /// Synchronisations de CONTENU effectuées par CE fil d'exécution.
    static SYNC_CONTENU: Cell<u64> = const { Cell::new(0) };
    /// Synchronisations de RÉPERTOIRE effectuées par CE fil d'exécution.
    static SYNC_REPERTOIRE: Cell<u64> = const { Cell::new(0) };
}

/// `(contenus, répertoires)` synchronisés PAR LE FIL COURANT depuis son démarrage.
///
/// POURQUOI CET INSTRUMENT EXISTE : c'est le seul par lequel un test peut prouver que l'appel de
/// synchronisation est FAIT. Un test qui se contenterait de relire le fichier publié passerait tout
/// aussi bien SANS aucune synchronisation — il mesurerait le `rename`, pas la durabilité.
///
/// POURQUOI IL EST PAR FIL D'EXÉCUTION, ET C'EST UNE CORRECTION D'INSTRUMENT, PAS UNE COMMODITÉ :
/// la première version comptait dans deux atomiques GLOBALES, et le harnais de test exécute les
/// tests en parallèle — un test qui lisait « 2 synchronisations de contenu » là où il en avait
/// demandé UNE mesurait en réalité les publications d'un test voisin. Un compteur global aurait
/// donc rendu vert (ou rouge) sur un chiffre qui n'était pas le sien. Le compteur par fil mesure
/// exactement les publications de l'appelant. Coût : un `Cell` sans atomique.
pub fn compteur_synchronisations() -> (u64, u64) {
    (SYNC_CONTENU.with(|c| c.get()), SYNC_REPERTOIRE.with(|c| c.get()))
}

/// Temporaire associé à `final_path` : DOTFILE frère, dans le MÊME répertoire.
///
/// LE MÊME RÉPERTOIRE N'EST PAS UN DÉTAIL : `rename` n'est atomique qu'à l'intérieur d'un système
/// de fichiers ; un temporaire posé ailleurs (`/tmp`) transformerait la publication en copie, donc
/// en fichier partiellement visible. LE POINT INITIAL N'EN EST PAS UN NON PLUS : le spool est
/// balayé par des consommateurs qui IGNORENT les dotfiles (`ship.sh`, la boucle d'ingestion), donc
/// un temporaire caché n'est jamais expédié à moitié écrit. Dériver le nom du temporaire du nom
/// FINAL — plutôt que de le recomposer à la main sur chaque site — fait hériter ces deux
/// propriétés à tout appelant, y compris futur.
fn temporaire_de(final_path: &Path) -> std::io::Result<(PathBuf, PathBuf)> {
    let dir = final_path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let nom = final_path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("chemin de publication sans nom de fichier : {}", final_path.display()),
        )
    })?;
    let mut tmp = std::ffi::OsString::from(".");
    tmp.push(nom);
    tmp.push(".tmp");
    Ok((dir.to_path_buf(), dir.join(tmp)))
}

/// Force le CONTENU d'un fichier ouvert sur le disque.
fn synchroniser_contenu(f: &File) -> std::io::Result<()> {
    f.sync_all()?;
    SYNC_CONTENU.with(|c| c.set(c.get() + 1));
    Ok(())
}

/// Force l'ENTRÉE DE RÉPERTOIRE sur le disque (unix). Voir le bandeau pour la limite Windows.
#[cfg(unix)]
fn synchroniser_repertoire(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()?;
    SYNC_REPERTOIRE.with(|c| c.set(c.get() + 1));
    Ok(())
}

/// Windows : pas de descripteur de répertoire synchronisable via la bibliothèque standard. On ne
/// compte RIEN — un compteur qui s'incrémenterait sans rien synchroniser mentirait au test qui le lit.
#[cfg(not(unix))]
fn synchroniser_repertoire(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Publie `contenu` sous `final_path` : temporaire -> synchronisation du contenu -> `rename` ->
/// synchronisation du répertoire.
///
/// `mode` (unix) est appliqué à la CRÉATION du temporaire, jamais après coup : un `write` suivi
/// d'un `chmod` laisse le fichier exister, même brièvement, avec les permissions de l'umask — pour
/// un spool d'événements ou une base de référence FIM, cette fenêtre est lisible par n'importe qui.
/// Le temporaire résiduel d'une tentative précédente est retiré d'abord, car `O_CREAT` n'ABAISSE
/// pas les permissions d'un fichier déjà présent.
///
/// CONTRAT DU RETOUR — `Ok(())` signifie « publié ET durable ». Une erreur APRÈS le `rename` (échec
/// de la synchronisation du répertoire) signifie « publié, durabilité NON prouvée » : le fichier
/// n'est PAS retiré, car le retirer détruirait des données réelles pour honorer une propriété qui
/// n'est qu'une assurance. L'appelant journalise ; il ne doit pas conclure que rien n'a été écrit.
pub fn publier(final_path: &Path, contenu: &[u8], mode: Option<u32>) -> std::io::Result<()> {
    let (dir, tmp) = temporaire_de(final_path)?;
    let _ = std::fs::remove_file(&tmp);
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if let Some(m) = mode {
                opts.mode(m);
            }
        }
        #[cfg(not(unix))]
        let _ = mode;
        let mut f = match opts.open(&tmp) {
            Ok(f) => f,
            Err(e) => return Err(e),
        };
        if let Err(e) = f.write_all(contenu) {
            drop(f);
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        // AVANT le renommage : publier un nom dont les octets ne sont pas sur le disque, c'est
        // publier un fichier vide au redémarrage.
        if let Err(e) = synchroniser_contenu(&f) {
            drop(f);
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    } // le descripteur est fermé AVANT le rename : sous Windows renommer un fichier ouvert échoue.
    if let Err(e) = std::fs::rename(&tmp, final_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // APRÈS le renommage : sans ceci, le fichier peut exister sans que son NOM existe.
    synchroniser_repertoire(&dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mut d = std::env::temp_dir();
        d.push(format!(
            "plume-agent-durable-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// CE QUE CE TEST PROUVE : que les synchronisations sont APPELÉES sur le chemin de publication,
    /// une par contenu et (sur unix) une par répertoire.
    ///
    /// CE QU'IL NE PROUVE PAS, ET LE PRÉTENDRE SERAIT MALHONNÊTE : que la donnée survive à une
    /// coupure d'alimentation. Cela demanderait de couper le courant d'une vraie machine au bon
    /// microseconde près, ou un pilote de blocs qui simule la perte du cache d'écriture — aucun des
    /// deux n'est à la portée d'une suite de tests portable. Ce test ferme le défaut RÉEL constaté :
    /// la promesse ne reposait sur AUCUN appel. Il ne ferme pas le matériel qui ment sur son `flush`.
    #[test]
    fn la_publication_synchronise_le_contenu_puis_le_repertoire() {
        let dir = tmpdir("compte");
        // TÉMOIN NÉGATIF, d'abord : sans publication, le compteur NE BOUGE PAS. Sans lui, un
        // compteur cassé qui s'incrémenterait tout seul rendrait ce test vert pour rien.
        let (n0, m0) = compteur_synchronisations();
        let _ = std::fs::read_dir(&dir);
        let (n1, m1) = compteur_synchronisations();
        assert_eq!((n1 - n0, m1 - m0), (0, 0), "instrument : rien ne se compte hors publication");
        // TÉMOIN POSITIF : une publication compte exactement une synchronisation de chaque.
        let (c0, r0) = compteur_synchronisations();
        publier(&dir.join("a.spool"), b"charge utile", Some(0o600)).unwrap();
        let (c1, r1) = compteur_synchronisations();
        assert_eq!(c1 - c0, 1, "le CONTENU doit être synchronisé avant le renommage");
        let attendu_rep = if cfg!(unix) { 1 } else { 0 };
        assert_eq!(
            r1 - r0,
            attendu_rep,
            "le RÉPERTOIRE doit être synchronisé après le renommage (unix) — sans quoi l'entrée peut manquer alors que le fichier existe"
        );
        assert_eq!(std::fs::read(dir.join("a.spool")).unwrap(), b"charge utile");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn le_temporaire_est_un_dotfile_frere_et_ne_survit_pas() {
        let dir = tmpdir("dotfile");
        publier(&dir.join("b.spool"), b"x", None).unwrap();
        let restants: Vec<String> =
            std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(restants, vec!["b.spool".to_string()], "aucun temporaire ne subsiste après publication");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn le_mode_est_pose_a_la_creation_pas_apres_coup() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("mode");
        let p = dir.join("c.cursor");
        publier(&p, b"cur-1", Some(0o600)).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn republier_remplace_sans_laisser_de_residu() {
        let dir = tmpdir("replace");
        let p = dir.join("d.cursor");
        publier(&p, b"ancien", None).unwrap();
        publier(&p, b"nouveau", None).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"nouveau");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// GARDE DÉRIVÉE, PAS UNE LISTE : elle découvre les sources de ce binaire et refuse tout
    /// `rename(` écrit hors de ce module. Le défaut fermé par `S27` n'était pas « ces trois sites
    /// oublient la synchronisation », c'était « le motif est réécrit à la main à chaque fois » —
    /// une correction site par site aurait raté le quatrième. Le PLANCHER ferme le seul mode de
    /// panne d'une garde par balayage : un parcours cassé qui ne lit RIEN et rend un vert joyeux.
    #[test]
    fn aucun_autre_site_ne_reinvente_la_publication() {
        let racine = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        collecter_rs(&racine, &mut fichiers);
        // 20 fichiers .rs MESURÉS le 2026-08-20 ; le plancher est volontairement plus bas (ajouter
        // ou retirer un module est de la routine et ne doit pas obliger à toucher cette garde).
        assert!(
            fichiers.len() >= 15,
            "plancher : {} fichier(s) .rs balayé(s) sous {} — parcours cassé, la garde ne verrait rien",
            fichiers.len(),
            racine.display()
        );
        let moi = Path::new(file!()).file_name().unwrap().to_string_lossy().into_owned();
        let mut fautifs = Vec::new();
        for f in &fichiers {
            if f.file_name().map(|n| n.to_string_lossy() == moi).unwrap_or(false) {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap_or_default();
            for (i, ligne) in src.lines().enumerate() {
                let nu = ligne.trim_start();
                if nu.starts_with("//") || nu.starts_with("///") || nu.starts_with("//!") {
                    continue; // un bandeau qui EXPLIQUE le renommage n'en fait pas un.
                }
                if ligne.contains("rename(") {
                    // chemin RELATIF à la racine du paquet : un message de garde ne doit pas
                    // recopier l'arborescence de la machine qui l'a exécutée.
                    let rel = f.strip_prefix(&racine).unwrap_or(f);
                    fautifs.push(format!("src/{}:{}", rel.display(), i + 1));
                }
            }
        }
        assert!(
            fautifs.is_empty(),
            "publication réinventée hors de la voie unique (durable::publier) : {fautifs:?} — \
             un `rename` seul donne l'atomicité du CONTENU, jamais la DURABILITÉ"
        );
    }

    fn collecter_rs(dir: &Path, out: &mut Vec<PathBuf>) {
        let rd = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(_) => return,
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                collecter_rs(&p, out);
            } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
                out.push(p);
            }
        }
    }
}

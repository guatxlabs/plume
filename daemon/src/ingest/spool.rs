//! `S31` (temps 2) — LE POINT DE PUBLICATION DU SPOOL, DÉPORTÉ ET SYNCHRONISÉ.
//!
//! CE QUE CE MODULE FERME. Le temps 1 a mesuré SEPT gestionnaires qui écrivaient le spool
//! (`write` -> `set_permissions` -> `rename`) puis répondaient un 2xx, alors que le renommage ne donne
//! que l'ATOMICITÉ DU CONTENU : après une coupure d'alimentation, les octets peuvent exister sans que
//! leur entrée de répertoire existe, et la boucle d'ingestion parcourt le spool PAR NOM. L'émetteur,
//! lui, avait déjà effacé sa copie sur la foi de ce 2xx. Les sept ne partageaient AUCUNE fonction :
//! sept copies du même bloc de dix lignes. Ce module est le point commun, et l'extraction est PURE —
//! le corps ci-dessous est la même suite d'appels, dans le même ordre, aux deux barrières près.
//!
//! LES DEUX BARRIÈRES, ET POURQUOI IL EN FAUT DEUX.
//!   1. `fsync` du FICHIER temporaire, AVANT le renommage : sans lui, l'entrée de répertoire peut
//!      devenir durable alors que le contenu ne l'est pas — c'est-à-dire un fichier de spool VIDE que
//!      la boucle d'ingestion consommera comme un lot légitime.
//!   2. `fsync` du RÉPERTOIRE, APRÈS le renommage : sans lui, le contenu est durable mais son NOM ne
//!      l'est pas, et la boucle ne trouvera rien à ingérer.
//!
//! L'ORDRE EST UNE PROPRIÉTÉ DE CONSTRUCTION, PAS UNE ASSERTION. La première barrière est prise PAR
//! CHEMIN (ré-ouverture puis `sync_all`, la forme exacte de `cold_store::writer::fsync_file`, en
//! production depuis le tier froid). Conséquence MESURÉE le 2026-08-30 : après le renommage, ce chemin
//! N'EXISTE PLUS et la barrière rend `NotFound` (os error 2). Déplacer la barrière après le renommage
//! ne produit donc pas une durabilité silencieusement fausse : elle produit un ÉCHEC de publication sur
//! les sept routes. Le témoin de cette impossibilité est `la_barriere_par_chemin_est_impossible_apres_le_renommage`.
//!
//! POURQUOI DÉPORTER PLUTÔT QUE SYNCHRONISER SUR PLACE. Les sept gestionnaires sont des `async fn` et
//! écrivaient le spool DIRECTEMENT sur le fil de l'exécuteur. Une barrière y coûte des millisecondes
//! (mesuré 3,0 à 3,6 ms sur btrfs, 3,2 à 7,8 ms à travers gocryptfs, poste Hugo, 2026-08-30) : la
//! poser sur ce fil bloquerait un worker de l'exécuteur pour toute la durée de la barrière. La
//! publication ENTIÈRE part donc sur le pool bloquant (`spawn_blocking`) et le gestionnaire l'ATTEND
//! sans occuper son fil.
//!
//! CE QUI PAIE LE DÉPORT, MESURÉ LE 2026-08-30 (poste Hugo — Arch, btrfs `/var/tmp`, et gocryptfs sur
//! btrfs pour le dépôt) :
//!   * Le coût d'une barrière est celui de la BARRIÈRE, pas de la taille : le surcoût de `fsync` est
//!     de 3,03 ms à 1 octet, 2,98 ms à 4 Kio, 3,06 ms à 64 Kio, 3,26 ms à 512 Kio — soit 1,08× de
//!     variation pour 500 000× de taille. Il ne redevient sensible à la taille qu'à 4 Mio (3,64 ms sur
//!     btrfs, 7,78 ms à travers gocryptfs), c'est-à-dire dans la moitié haute du plafond de corps
//!     (`PLUME_INGEST_MAX_BODY_MB`, défaut 8 Mio).
//!   * La barrière s'amortit par la CONCURRENCE, et c'est le pool bloquant qui la fournit : 64
//!     publications indépendantes coûtent 6,65 ms/charge à 1 fil, 3,05 ms à 4 fils, 1,55 ms à 8 fils,
//!     0,79 ms à 16 fils (btrfs). Le système de fichiers coalesce les barrières concurrentes ; il ne
//!     coalesce PAS les barrières séquentielles.
//!   * DEUX formes de groupage ont été mesurées puis ÉCARTÉES. Un groupeur MONO-FIL (accumuler N
//!     publications, écrire les N fichiers, prendre les N barrières, puis UNE barrière de répertoire)
//!     rend 3,48 ms/charge — soit MOINS BIEN que le pool bloquant dès 4 fils, parce qu'il sérialise ce
//!     que la concurrence amortissait. Un coalesceur de barrière de RÉPERTOIRE (une seule barrière de
//!     répertoire pour toutes les publications en vol) ne rend RIEN : 6,41 contre 6,21 ms/charge à 1
//!     fil, 0,828 contre 0,830 ms à 16 fils — la barrière de répertoire qui suit immédiatement une
//!     barrière de fichier ne trouve plus rien à écrire. La complexité d'un acteur n'est donc pas
//!     payée ici, et le déport tient en une fonction.
//!
//! CE QUE CE MODULE NE PROUVE PAS. Rien ici ne démontre la survie à une coupure d'alimentation RÉELLE :
//! cela exigerait de couper le courant d'une machine et de relire le spool. Ce qui est prouvé est
//! l'APPEL des deux barrières, leur SUCCÈS, et leur ORDONNANCEMENT — c'est-à-dire que le noyau s'est vu
//! demander la barrière et l'a rendue sans erreur. Au-delà, la durabilité dépend du système de
//! fichiers et du matériel (un cache disque menteur reste un cache disque menteur), et cela ne se
//! mesure pas depuis ce processus.
use crate::*;

/// Ce qui a échoué dans une publication de spool. Les sept appelants n'ont pas la même FORME de
/// réponse d'erreur (contrat Splunk, OTLP, Firehose, Pub/Sub, ou JSON plume) : le point commun rend la
/// CAUSE, chaque appelant l'habille dans son protocole.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum EchecSpool {
    /// Le corps n'a pas pu être posé sur le disque (écriture, permissions, ou barrière de fichier).
    /// Rien n'a été publié — aucun `.tmp` orphelin ne subsiste (ING-4).
    Ecriture,
    /// Le corps est écrit mais n'a pas pu être PUBLIÉ sous son nom définitif (renommage refusé).
    Publication,
}

/// Ce qu'une publication a RÉELLEMENT obtenu — jamais ce qu'elle promet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct SpoolPublie {
    /// VRAI seulement si les DEUX barrières ont été prises ET rendues sans erreur. C'est cette valeur,
    /// et aucune constante, qui alimente le champ `durable` des accusés de réception : un accusé ne
    /// peut donc pas promettre une durabilité que la publication n'a pas obtenue.
    pub(crate) durable: bool,
    /// Combien de barrières ont été prises (0 quand la durabilité est désarmée, 2 sinon). Valeur de
    /// RETOUR et non compteur global : un test l'observe EXACTEMENT, sans course avec les autres
    /// tests du même processus.
    pub(crate) barrieres: u8,
}

/// Barrière de FICHIER, prise PAR CHEMIN. Même forme que `cold_store::writer::fsync_file`. Ré-ouvrir en
/// lecture seule suffit : `fsync(2)` n'exige aucun droit d'écriture sur le descripteur, et le coût
/// reste celui de la barrière (mesuré 3,137 ms contre 0,026 ms sans elle, btrfs, 2026-08-30).
fn barriere_fichier(chemin: &str) -> std::io::Result<()> {
    std::fs::File::open(chemin)?.sync_all()
}

/// Barrière de RÉPERTOIRE : rend l'entrée créée par le renommage durable.
fn barriere_repertoire(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// LE GESTE, BLOQUANT. N'appeler QUE depuis un fil bloquant (`publier` s'en charge) — il prend jusqu'à
/// deux barrières de plusieurs millisecondes.
///
/// `durabilite` désarmé -> suite d'appels STRICTEMENT identique à celle d'avant `S31` (écriture,
/// permissions, renommage), `durable: false`, zéro barrière : le mode dégradé n'est pas une variante
/// de code, c'est l'ancien chemin.
pub(crate) fn publier_bloquant(tmp: &str, dst: &str, corps: &[u8], durabilite: bool) -> Result<SpoolPublie, EchecSpool> {
    if std::fs::write(tmp, corps).is_err() {
        let _ = std::fs::remove_file(tmp); // ING-4 : pas d'orphelin `.tmp` sur écriture partielle
        return Err(EchecSpool::Ecriture);
    }
    // durcis le spool (0600) avant la publication atomique : umask 022 laissait les fichiers en 0644
    // (world-readable) -> dataacl.
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(0o600));
    let mut barrieres = 0u8;
    if durabilite {
        // BARRIÈRE 1 — AVANT le renommage, et par CHEMIN : l'inverser rendrait `NotFound`, pas une
        // fausse durabilité. Un échec ici est un échec d'ÉCRITURE : rien n'est publié, l'émetteur
        // garde sa copie et réémettra.
        if barriere_fichier(tmp).is_err() {
            SPOOL_BARRIERE_ECHEC_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = std::fs::remove_file(tmp);
            return Err(EchecSpool::Ecriture);
        }
        SPOOL_BARRIERE_FICHIER_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        barrieres += 1;
    }
    if std::fs::rename(tmp, dst).is_err() {
        let _ = std::fs::remove_file(tmp); // ING-4 : pas d'orphelin `.tmp` sur rename échoué
        return Err(EchecSpool::Publication);
    }
    if durabilite {
        // BARRIÈRE 2 — APRÈS le renommage. Un échec ici ne peut PAS être rendu en erreur : le fichier
        // EST publié et la boucle d'ingestion le consommera. Le rendre en erreur ferait réémettre
        // l'émetteur, donc DOUBLERAIT le lot. On rend donc le succès avec `durable: false` — la seule
        // réponse vraie — et le compteur d'échec de barrière le rend visible à l'exploitant, y compris
        // sur les quatre surfaces dont le corps de réponse appartient à un contrat étranger.
        match std::path::Path::new(dst).parent() {
            Some(dir) if barriere_repertoire(dir).is_ok() => {
                SPOOL_BARRIERE_REPERTOIRE_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                barrieres += 1;
            }
            _ => {
                SPOOL_BARRIERE_ECHEC_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(SpoolPublie { durable: false, barrieres });
            }
        }
    }
    Ok(SpoolPublie { durable: durabilite && barrieres == 2, barrieres })
}

/// LE POINT DE DÉPORT DES SEPT SURFACES DE SPOOL. La publication entière (écriture, permissions,
/// barrières, renommage) part sur le pool bloquant ; le gestionnaire `async` l'attend sans occuper son
/// fil d'exécuteur. C'est la forme déjà employée partout ailleurs dans le démon pour un geste bloquant
/// (`query_exec`, `cold_store`, les connecteurs réseau).
///
/// Une tâche bloquante annulée ou paniquée est rendue en `Ecriture` : rien n'atteste que le corps ait
/// été publié, donc l'émetteur doit garder sa copie.
pub(crate) async fn publier(tmp: String, dst: String, corps: Vec<u8>, durabilite: bool) -> Result<SpoolPublie, EchecSpool> {
    match tokio::task::spawn_blocking(move || publier_bloquant(&tmp, &dst, &corps, durabilite)).await {
        Ok(r) => r,
        Err(_) => Err(EchecSpool::Ecriture),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TÉMOIN POSITIF — la publication durable prend EXACTEMENT deux barrières, rend `durable: true`,
    /// et publie le corps sous son nom définitif en 0600.
    ///
    /// MUTATION : retirer l'un des deux appels de barrière ⇒ `barrieres` tombe à 1 et `durable` à
    /// `false` ⇒ les deux premières assertions passent au ROUGE. Le compte est une valeur de RETOUR,
    /// donc il ne dépend d'aucun compteur global partagé avec les autres tests.
    ///
    /// CE QU'IL NE PROUVE PAS : la survie à une coupure d'alimentation. Il prouve que les deux
    /// barrières ont été DEMANDÉES au noyau et rendues sans erreur.
    #[test]
    fn la_publication_durable_prend_deux_barrieres_et_le_dit() {
        let d = crate::tmp_possede::TmpPossede::neuf("s31-barriere");
        let tmp = d.join(".x.tmp").to_string_lossy().into_owned();
        let dst = d.join("x.json").to_string_lossy().into_owned();
        let p = publier_bloquant(&tmp, &dst, b"{\"kind\":\"events\"}", true).expect("publication");
        assert_eq!(p.barrieres, 2, "les DEUX barrières (fichier puis répertoire) doivent être prises");
        assert!(p.durable, "`durable` est DÉRIVÉ des barrières, pas affirmé");
        assert_eq!(std::fs::read(&dst).unwrap(), b"{\"kind\":\"events\"}".to_vec(), "le corps publié");
        assert!(!std::path::Path::new(&tmp).exists(), "aucun `.tmp` orphelin (ING-4)");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777, 0o600, "spool durci 0600");
    }

    /// TÉMOIN NÉGATIF — durabilité DÉSARMÉE : zéro barrière, `durable: false`, et le fichier est
    /// publié quand même. C'est l'ancien chemin, inchangé : le mode dégradé ne ment pas non plus.
    ///
    /// Sans ce témoin, le témoin positif ne distinguerait pas « les barrières sont prises » de « le
    /// drapeau est câblé à vrai ».
    #[test]
    fn sans_durabilite_aucune_barriere_n_est_prise_et_l_accuse_ne_promet_rien() {
        let d = crate::tmp_possede::TmpPossede::neuf("s31-sans-barriere");
        let tmp = d.join(".y.tmp").to_string_lossy().into_owned();
        let dst = d.join("y.json").to_string_lossy().into_owned();
        let p = publier_bloquant(&tmp, &dst, b"charge", false).expect("publication");
        assert_eq!(p.barrieres, 0, "durabilité désarmée -> AUCUNE barrière");
        assert!(!p.durable, "un accusé ne promet pas une durabilité non acquise");
        assert_eq!(std::fs::read(&dst).unwrap(), b"charge".to_vec(), "le spool reste publié");
    }

    /// VALIDATION DE L'INSTRUMENT — ce qui rend l'ORDRE structurel. La barrière de fichier est prise
    /// PAR CHEMIN ; après le renommage ce chemin n'existe plus. Inverser l'ordre dans
    /// `publier_bloquant` ne donnerait donc pas une durabilité fausse-mais-silencieuse : cela
    /// donnerait un échec, sur les sept routes à la fois.
    ///
    /// Ce test n'inspecte AUCUNE ligne de `publier_bloquant` : il mesure la propriété du système de
    /// fichiers sur laquelle l'ordre repose.
    #[test]
    fn la_barriere_par_chemin_est_impossible_apres_le_renommage() {
        let d = crate::tmp_possede::TmpPossede::neuf("s31-ordre");
        let tmp = d.join(".z.tmp");
        let dst = d.join("z.json");
        std::fs::write(&tmp, b"charge").unwrap();
        assert!(barriere_fichier(&tmp.to_string_lossy()).is_ok(), "AVANT le renommage : la barrière est prenable");
        std::fs::rename(&tmp, &dst).unwrap();
        let apres = barriere_fichier(&tmp.to_string_lossy());
        assert_eq!(
            apres.map(|_| ()).unwrap_err().kind(),
            std::io::ErrorKind::NotFound,
            "APRÈS le renommage : le chemin a disparu -> l'ordre inverse échoue au lieu de mentir"
        );
    }
}

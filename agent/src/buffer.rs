//! Tampon disque (at-least-once) : spool en anneau borné + backoff + persistance des curseurs.
//!
//! Modèle : une source lit un lot -> on écrit UNE `SpoolEntry` (endpoint + corps + source_id + curseur)
//! dans le spool par la voie unique `durable::publier` — ATOMIQUE (un lecteur ne voit jamais un fichier
//! à moitié écrit) ET DURABLE (contenu synchronisé avant le renommage, répertoire après ; sans le
//! second, après coupure l'entrée de répertoire peut manquer alors que le fichier existe, et le spool
//! est parcouru PAR NOM). Le shipper draine le spool ; sur ACK (202/204) il SUPPRIME l'entrée ET
//! persiste `cursor` de la source. Le curseur n'est donc JAMAIS avancé sur disque avant ship+ack ->
//! un crash rejoue (dédup côté daemon via `dedup`/`__CURSOR`). Anneau BORNÉ : au-delà de `cap`, on
//! évince les entrées les plus VIEILLES (le poste ne peut pas remplir son disque si le central est down).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Une unité expédiable, persistée dans le spool jusqu'à ship+ack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpoolEntry {
    /// Chemin d'ingest ("/api/ingest" ou "/api/ingest/journal").
    pub endpoint: String,
    /// Corps HTTP prêt à POSTer (enveloppe JSON, ou ndjson journald brut).
    pub body: String,
    /// Source d'origine (pour router la persistance du curseur après ack).
    pub source_id: String,
    /// Curseur à persister APRÈS ack (position atteinte par ce lot). `None` = source non reprenable.
    pub cursor: Option<String>,
}

/// Compteur monotone process-global -> unicité + ordre FIFO des noms de fichiers même dans la même ms.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// Spool disque en anneau borné.
pub struct Spool {
    dir: PathBuf,
    cap: usize,
}

impl Spool {
    /// Ouvre (crée) le spool dans `dir`, plafonné à `cap` entrées.
    pub fn open(dir: impl Into<PathBuf>, cap: usize) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, cap: cap.max(1) })
    }

    /// Publie une entrée DURABLEMENT, puis applique le plafond (évince les plus vieilles).
    ///
    /// La publication passe par la voie unique `durable::publier` : le renommage ne donne que
    /// l'atomicité du CONTENU, la survie à une coupure exige en plus que les octets soient sur le
    /// disque avant le renommage et l'entrée de répertoire après (cf. le bandeau de `durable`).
    /// C'est ce qui distingue un tampon at-least-once d'un tampon qui l'affirme.
    pub fn push(&self, entry: &SpoolEntry) -> std::io::Result<()> {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        // nom = <millis 013>-<seq 016>.spool -> tri lexicographique == ordre FIFO.
        let name = format!("{millis:013}-{seq:016}.spool");
        let dst = self.dir.join(&name);
        let bytes = serde_json::to_vec(entry)?;
        // 0600 posé À LA CRÉATION : l'ancienne forme écrivait puis faisait `set_permissions`, ce qui
        // laissait l'entrée de spool lisible selon l'umask pendant l'écriture.
        crate::durable::publier(&dst, &bytes, Some(0o600))?;
        self.enforce_cap();
        Ok(())
    }

    /// Liste les entrées présentes, triées FIFO (chemin + entrée désérialisée). Ignore le corrompu.
    pub fn entries(&self) -> Vec<(PathBuf, SpoolEntry)> {
        let mut paths = match self.spool_files() {
            Ok(p) => p,
            Err(e) => {
                // Rien à expédier n'est PAS la même chose que « je ne sais pas ce qu'il y a à
                // expédier ». Le drain reste vide (on ne peut pas envoyer ce qu'on n'a pas lu), mais
                // le fait est dit — sans quoi un spool devenu illisible se lit comme un spool drainé.
                eprintln!("[spool] {} illisible ({e}) — AUCUNE entrée énumérée ce cycle (file de profondeur INCONNUE, pas vide)", self.dir.display());
                Vec::new()
            }
        };
        paths.sort();
        let mut out = Vec::with_capacity(paths.len());
        for p in paths {
            match std::fs::read(&p).ok().and_then(|b| serde_json::from_slice::<SpoolEntry>(&b).ok()) {
                Some(e) => out.push((p, e)),
                None => {
                    // Entrée illisible/corrompue -> on la retire (jamais de boucle infinie dessus).
                    eprintln!("[spool] entrée corrompue supprimée : {}", p.display());
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
        out
    }

    /// Supprime une entrée (appelé après ACK).
    pub fn remove(&self, path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    /// Nombre d'entrées en attente, OU l'échec de la mesure — jamais un zéro par défaut (`S33`).
    ///
    /// L'ancienne forme rendait `0` quand le répertoire du spool n'était pas lisible. Zéro est la
    /// valeur la plus calme de cette série : une file qu'on ne sait plus lire s'y affichait
    /// « aucune entrée en attente », c'est-à-dire le contraire du fait à signaler.
    pub fn len(&self) -> std::io::Result<usize> {
        self.spool_files().map(|f| f.len())
    }

    #[allow(dead_code)] // utilisé par les tests + appelants futurs
    pub fn is_empty(&self) -> std::io::Result<bool> {
        self.len().map(|n| n == 0)
    }

    /// LES ENTRÉES DU SPOOL, OU RIEN — ET UN PARCOURS INTERROMPU N'EST PAS UN PARCOURS COMPLET.
    /// Trois replis menaient au même sous-compte : un `read_dir` en échec rendait la liste VIDE, une
    /// entrée illisible en cours de route était sautée (`filter_map(|e| e.ok())`), et une entrée dont
    /// l'extension n'était pas lisible l'était aussi. Un compte PLUS PETIT que la file réelle est,
    /// pour le plafond de l'anneau, exactement aussi dangereux qu'un zéro : il ne mord pas.
    fn spool_files(&self) -> std::io::Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        for entree in std::fs::read_dir(&self.dir)? {
            let p = entree?.path();
            if p.extension().map(|x| x == "spool").unwrap_or(false) {
                out.push(p);
            }
        }
        Ok(out)
    }

    /// Applique le plafond : tant que len > cap, supprime le plus vieux (nom lexicographiquement min).
    ///
    /// LE PLAFOND EST UNE GARDE, ET UNE GARDE QUI NE SAIT PAS COMPTER NE GARDE RIEN. Quand la mesure
    /// échoue, l'ancienne forme lisait « 0 entrée », concluait « sous le plafond » et rendait la main :
    /// le poste pouvait alors remplir son disque précisément parce qu'on ne savait plus lire le
    /// répertoire. On ne peut pas évincer ce qu'on n'a pas su énumérer — mais on le DIT, au lieu de
    /// laisser croire que la borne s'applique.
    fn enforce_cap(&self) {
        let mut files = match self.spool_files() {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "[spool] plafond de l'anneau NON APPLIQUÉ : {} illisible ({e}) — le nombre \
                     d'entrées n'a pas pu être établi, aucune éviction n'a eu lieu",
                    self.dir.display()
                );
                return;
            }
        };
        if files.len() <= self.cap {
            return;
        }
        files.sort();
        let excess = files.len() - self.cap;
        for p in files.into_iter().take(excess) {
            eprintln!("[spool] anneau plein (cap {}) -> éviction de {}", self.cap, p.display());
            let _ = std::fs::remove_file(&p);
        }
    }
}

/// Persistance des curseurs de source (un fichier par `source_id`). Écrits SEULEMENT après ship+ack.
pub struct CursorStore {
    dir: PathBuf,
}

impl CursorStore {
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, source_id: &str) -> PathBuf {
        // source_id vient de la config (contrôlé) ; on assainit tout de même les séparateurs.
        let safe: String = source_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '_' })
            .collect();
        self.dir.join(format!("{safe}.cursor"))
    }

    /// Charge le dernier curseur persisté (acké) d'une source.
    pub fn load(&self, source_id: &str) -> Option<String> {
        std::fs::read_to_string(self.path(source_id))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Persiste DURABLEMENT le curseur d'une source. No-op si `cursor` est None.
    ///
    /// L'ASYMÉTRIE EST VOULUE, ET ELLE PENCHE DU BON CÔTÉ : le curseur n'est écrit qu'APRÈS ship+ack,
    /// donc après que l'entrée correspondante a été acceptée par le central ET retirée du spool. Un
    /// curseur perdu fait REJOUER un lot déjà accepté — le daemon dédoublonne. Un curseur qui
    /// survivrait à une entrée de spool perdue ferait, lui, DISPARAÎTRE des événements ; c'est cette
    /// direction-là qui est interdite, et c'est pourquoi le spool est publié durablement lui aussi.
    ///
    /// Le temporaire est désormais dérivé du nom FINAL (donc assaini) : l'ancienne forme composait
    /// `.{source_id}.cursor.tmp` à partir du `source_id` BRUT alors que le nom final, lui, était
    /// assaini — un `source_id` porteur d'un séparateur visait donc un temporaire hors répertoire.
    pub fn save(&self, source_id: &str, cursor: &Option<String>) -> std::io::Result<()> {
        let Some(c) = cursor else { return Ok(()) };
        crate::durable::publier(&self.path(source_id), c.as_bytes(), None)
    }
}

/// Backoff exponentiel borné (avec conscience du 503). Renvoie le délai courant puis le double.
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    cur: Duration,
}

impl Backoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        Self { base, max, cur: base }
    }

    /// Délai courant (à attendre avant réessai), puis avance (×2, plafonné à `max`).
    pub fn next_delay(&mut self) -> Duration {
        let d = self.cur;
        self.cur = (self.cur * 2).min(self.max);
        d
    }

    /// 503 explicite du central (surcharge/disque) -> saute directement vers le plafond (recule plus fort).
    pub fn bump_503(&mut self) {
        self.cur = self.max;
    }

    /// Remise à zéro après un succès.
    pub fn reset(&mut self) {
        self.cur = self.base;
    }

    #[allow(dead_code)] // utilisé par les tests + inspection
    pub fn current(&self) -> Duration {
        self.cur
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        d.push(format!("plume-agent-test-{tag}-{}-{n}", std::process::id()));
        d
    }

    fn entry(body: &str, cursor: Option<&str>) -> SpoolEntry {
        SpoolEntry {
            endpoint: "/api/ingest".into(),
            body: body.into(),
            source_id: "s".into(),
            cursor: cursor.map(|c| c.into()),
        }
    }

    #[test]
    fn spool_roundtrip_fifo() {
        let dir = tmpdir("fifo");
        let s = Spool::open(&dir, 100).unwrap();
        s.push(&entry("a", Some("c1"))).unwrap();
        s.push(&entry("b", Some("c2"))).unwrap();
        s.push(&entry("c", Some("c3"))).unwrap();
        let es = s.entries();
        assert_eq!(es.len(), 3);
        assert_eq!(es[0].1.body, "a", "FIFO");
        assert_eq!(es[2].1.body, "c");
        // remove le premier -> reste 2
        s.remove(&es[0].0);
        assert_eq!(s.len().expect("spool lisible"), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `S33` — UNE FILE QU'ON NE SAIT PAS LIRE N'EST PAS UNE FILE VIDE, ET UN PLAFOND QUI NE SAIT PAS
    /// COMPTER NE PLAFONNE RIEN.
    ///
    /// ① SENS « ILLISIBLE » : le répertoire du spool disparaît -> `len()` rend une ERREUR, jamais 0.
    ///    L'ancienne forme rendait `Vec::new()`, donc « 0 entrée en attente » : la valeur la plus calme
    ///    de la série, publiée précisément quand la file cesse d'être mesurable. Et comme
    ///    `enforce_cap` en dérivait, la borne de l'anneau s'éteignait au même instant — le poste
    ///    pouvait remplir son disque exactement quand plus personne ne pouvait le voir.
    /// ② SENS « LU, VALEUR ZÉRO » : un répertoire qui EXISTE et ne contient rien rend `Ok(0)`. Sans ce
    ///    témoin, une version qui rendrait TOUJOURS une erreur passerait ① sans rien prouver, et elle
    ///    ferait disparaître le cas nominal — un agent à jour, dont la file est réellement vide.
    #[test]
    fn une_file_illisible_ne_se_lit_pas_comme_une_file_vide() {
        let dir = tmpdir("profondeur");
        let s = Spool::open(&dir, 3).unwrap();

        // ② le cas nominal, d'abord : lu, et la valeur est un VRAI zéro.
        assert_eq!(s.len().expect("un répertoire présent se lit"), 0, "file réellement vide -> 0");
        assert!(s.is_empty().expect("un répertoire présent se lit"));

        s.push(&entry("a", Some("c1"))).unwrap();
        assert_eq!(s.len().expect("un répertoire présent se lit"), 1);

        // ① la source disparaît sous les pieds du processus.
        std::fs::remove_dir_all(&dir).unwrap();
        let v = s.len();
        assert!(v.is_err(), "une file qu'on ne sait pas lire ne rend PAS 0 : {v:?}");
        // Et le plafond ne conclut pas « sous la borne » : il ne peut évincer que ce qu'il a énuméré.
        s.enforce_cap(); // ne panique pas, ne prétend pas avoir appliqué la borne
    }

    #[test]
    fn spool_ring_evicts_oldest_when_over_cap() {
        let dir = tmpdir("ring");
        let s = Spool::open(&dir, 3).unwrap();
        for i in 0..10 {
            s.push(&entry(&format!("e{i}"), Some(&format!("c{i}")))).unwrap();
        }
        assert_eq!(s.len().expect("spool lisible"), 3, "borné au cap");
        let es = s.entries();
        // les 3 plus RÉCENTES survivent (e7,e8,e9), les vieilles sont évincées.
        assert_eq!(es[0].1.body, "e7");
        assert_eq!(es[2].1.body, "e9");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spool_entry_survives_reopen() {
        let dir = tmpdir("persist");
        {
            let s = Spool::open(&dir, 10).unwrap();
            s.push(&entry("body-with\nnewline", Some("cur"))).unwrap();
        }
        let s2 = Spool::open(&dir, 10).unwrap();
        let es = s2.entries();
        assert_eq!(es.len(), 1);
        assert_eq!(es[0].1.body, "body-with\nnewline", "corps ndjson multi-lignes préservé");
        assert_eq!(es[0].1.cursor.as_deref(), Some("cur"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cursor_store_only_after_save() {
        let dir = tmpdir("cursor");
        let cs = CursorStore::open(&dir).unwrap();
        assert_eq!(cs.load("s"), None, "rien avant save");
        cs.save("s", &None).unwrap();
        assert_eq!(cs.load("s"), None, "save(None) = no-op");
        cs.save("s", &Some("cur-9".into())).unwrap();
        assert_eq!(cs.load("s").as_deref(), Some("cur-9"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(8));
        assert_eq!(b.next_delay(), Duration::from_secs(1));
        assert_eq!(b.next_delay(), Duration::from_secs(2));
        assert_eq!(b.next_delay(), Duration::from_secs(4));
        assert_eq!(b.next_delay(), Duration::from_secs(8));
        assert_eq!(b.next_delay(), Duration::from_secs(8), "plafonné");
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_secs(1));
        b.bump_503();
        assert_eq!(b.current(), Duration::from_secs(8), "503 -> plafond direct");
    }
}

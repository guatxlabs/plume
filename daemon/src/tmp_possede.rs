//! LE COFFRE DU RÉPERTOIRE TEMPORAIRE — seule détentrice d'un accès à la racine temporaire du
//! système (`$TMPDIR`, `/tmp` à défaut). Compagnon COMPILE-TIME : `build.rs` REFUSE de compiler
//! la caisse si un autre fichier de `src/` appelle la fonction de la bibliothèque standard qui
//! rend cette racine. Emprunter la voie directe ne compile donc plus : elle passe par ici.
//!
//! POURQUOI. Mesuré le 2026-08-03 sur `01a5cf0`, suite daemon complète, `$TMPDIR` détourné vers
//! un répertoire sur disque : **136 fichiers / 38,4 Mio laissés derrière PAR EXÉCUTION**. La
//! décomposition dit la cause exacte : **53 `-wal` + 53 `-shm` ORPHELINS** (100 % des `-wal` :
//! leur `.db` avait bien été effacé, pas eux). Les fixtures nettoyaient en ÉNUMÉRANT le chemin
//! qu'elles avaient nommé — et SQLite en crée deux autres à côté, que personne n'a nommés.
//!
//! LA DÉRIVATION. On n'énumère pas ce qu'il faut effacer : **on possède le contenant**. Une
//! fixture crée un RÉPERTOIRE à elle, tout naît dedans, et `Drop` efface le répertoire ENTIER.
//! Un sidecar que personne n'a nommé — `-wal`, `-shm`, `-journal`, celui qu'une bibliothèque
//! future inventera — disparaît sans avoir jamais eu à être prévu. `Drop` tourne aussi sur
//! PANIQUE, donc un test qui échoue ne fuit pas non plus (le nettoyage en fin de corps, lui,
//! était sauté à la première assertion rouge).
//!
//! LA GARDE DE PORTÉE. `sous()` ne rend pas un chemin détaché : il rend un [`CheminTmp<'_>`] qui
//! EMPRUNTE son propriétaire. Un chemin ne peut donc pas survivre au répertoire qui le contient —
//! `let p = TmpPossede::neuf("x").sous("a.db");` ne compile pas (E0716). C'est la même figure que
//! `PlaintextTempGuard` (`backup.rs`) côté production, portée cette fois par le vérificateur
//! d'emprunts au lieu d'une relecture.
//!
//! LIMITE DÉCLARÉE : `Drop` ne s'exécute pas sur SIGKILL/OOM-kill/`abort()`. Un binaire de test
//! tué de l'extérieur laisse son répertoire — un seul, nommé, et non 136 fichiers épars.

//! CE QUE LA GARDE NE PROMET PAS : un `PathBuf` détaché d'un [`TmpPossede`] (via `Deref<Path>`)
//! reste possible — c'est ce qui permet aux fixtures existantes de ne pas changer d'une ligne.
//! Il ne peut pas FUIR pour autant : ce chemin vit DANS le répertoire possédé, donc il part avec
//! lui. Détaché puis survivant à son propriétaire, il ne désigne plus rien — un échec BRUYANT au
//! premier accès, jamais un résidu silencieux. Le seul mode de fuite fermé ici est le bon :
//! « un temporaire créé hors de tout contenant possédé ».

/// LA RACINE. Seul point du programme qui interroge la racine temporaire du système, donc seul
/// point qui lit `$TMPDIR`. `build.rs` interdit toute autre occurrence dans `src/` : ajouter un
/// second accès ne compile pas. Utilisée par la production (`handlers/notifiers.rs`) comme par
/// les fixtures ci-dessous — une seule notion de « où est le temporaire », pour tout le monde.
pub(crate) fn racine_systeme() -> std::path::PathBuf {
    std::env::temp_dir()
}

/// Un temporaire de test qui SE POSSÈDE : un répertoire à lui, effacé RÉCURSIVEMENT à sa
/// destruction. Rien à énumérer, donc rien à oublier.
#[cfg(test)]
pub(crate) struct TmpPossede {
    racine: std::path::PathBuf,
}

#[cfg(test)]
impl TmpPossede {
    /// Crée un répertoire NEUF et VIDE. `etiquette` ne sert qu'à la lisibilité d'un résidu en cas
    /// de SIGKILL ; l'unicité vient du PID + d'un compteur de processus (deux fixtures
    /// simultanées du même test parallèle ne peuvent pas se marcher dessus).
    pub(crate) fn neuf(etiquette: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let racine = racine_systeme().join(format!("plume-t{}-{n}-{etiquette}", std::process::id()));
        // Un résidu homonyme d'une exécution SIGKILLée ne doit pas polluer la fixture.
        let _ = std::fs::remove_dir_all(&racine);
        std::fs::create_dir_all(&racine)
            .unwrap_or_else(|e| panic!("fixture : création impossible de {} : {e}", racine.display()));
        Self { racine }
    }

    /// Un chemin DANS le répertoire possédé. Le résultat emprunte `self` : il ne peut pas lui
    /// survivre. Le parent existe déjà — `Connection::open` et consorts peuvent y écrire directement.
    pub(crate) fn sous(&self, nom: &str) -> CheminTmp<'_> {
        CheminTmp::neuf(self.racine.join(nom))
    }

    /// Le répertoire possédé lui-même (il EXISTE déjà), pour les fixtures qui ont besoin d'un
    /// dossier plutôt que d'un fichier — spool, dossier de backup, racine de balayage.
    pub(crate) fn racine(&self) -> CheminTmp<'_> {
        CheminTmp::neuf(self.racine.clone())
    }
}

#[cfg(test)]
impl Drop for TmpPossede {
    fn drop(&mut self) {
        // Le CONTENANT, pas une liste de noms : ce qui a été créé dedans par n'importe qui part avec.
        let _ = std::fs::remove_dir_all(&self.racine);
    }
}

/// Le temporaire possédé SE COMPORTE comme le répertoire qu'il est (`join`, `display`,
/// `to_string_lossy`, `&tmp` -> `&Path`). C'est ce qui permet à une fixture qui rendait déjà un
/// `PathBuf` de répertoire de devenir possédante en changeant SON SEUL type de retour, sans
/// toucher ses appelants.
#[cfg(test)]
impl std::ops::Deref for TmpPossede {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.racine
    }
}
#[cfg(test)]
impl AsRef<std::path::Path> for TmpPossede {
    fn as_ref(&self) -> &std::path::Path {
        &self.racine
    }
}
#[cfg(test)]
impl std::fmt::Display for TmpPossede {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.racine.to_string_lossy())
    }
}

/// LA FORME DOMINANTE des fixtures : « une base SQLite dans un temporaire ». Possède le
/// RÉPERTOIRE qui contient la base, et se comporte comme le `String` de chemin qu'il remplace
/// (`Deref<str>`, `AsRef<Path>`, `Display`) — une fixture qui rendait `String` devient possédante
/// en changeant SON SEUL type de retour. Les `-wal`/`-shm` naissent à côté de la base, donc DANS
/// le répertoire possédé : ils partent avec, sans avoir jamais été nommés.
#[cfg(test)]
pub(crate) struct TmpDb {
    _dir: TmpPossede,
    chemin: String,
}

#[cfg(test)]
impl TmpDb {
    pub(crate) fn neuf(etiquette: &str) -> Self {
        let dir = TmpPossede::neuf(etiquette);
        let chemin = dir.sous("plume.db").as_str().to_owned();
        Self { _dir: dir, chemin }
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.chemin
    }
}

#[cfg(test)]
impl std::ops::Deref for TmpDb {
    type Target = str;
    fn deref(&self) -> &str {
        &self.chemin
    }
}
#[cfg(test)]
impl AsRef<std::path::Path> for TmpDb {
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.chemin)
    }
}
#[cfg(test)]
impl AsRef<str> for TmpDb {
    fn as_ref(&self) -> &str {
        &self.chemin
    }
}
#[cfg(test)]
impl AsRef<std::ffi::OsStr> for TmpDb {
    fn as_ref(&self) -> &std::ffi::OsStr {
        std::ffi::OsStr::new(&self.chemin)
    }
}
#[cfg(test)]
impl std::fmt::Display for TmpDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.chemin)
    }
}
#[cfg(test)]
impl std::fmt::Debug for TmpDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.chemin, f)
    }
}

/// Un chemin qui EMPRUNTE le temporaire qui le contient. Se substitue à un `String`/`PathBuf` de
/// chemin partout où les fixtures en attendaient un (`Deref<str>`, `AsRef<Path>`, `Display`),
/// mais porte en plus la durée de vie de son propriétaire : le détacher ne compile pas.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct CheminTmp<'a> {
    s: String,
    _proprio: std::marker::PhantomData<&'a TmpPossede>,
}

#[cfg(test)]
impl CheminTmp<'_> {
    fn neuf(p: std::path::PathBuf) -> Self {
        Self { s: p.to_string_lossy().into_owned(), _proprio: std::marker::PhantomData }
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.s
    }
    pub(crate) fn chemin(&self) -> &std::path::Path {
        std::path::Path::new(&self.s)
    }
}

#[cfg(test)]
impl std::ops::Deref for CheminTmp<'_> {
    type Target = str;
    fn deref(&self) -> &str {
        &self.s
    }
}
#[cfg(test)]
impl AsRef<std::path::Path> for CheminTmp<'_> {
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.s)
    }
}
#[cfg(test)]
impl AsRef<std::ffi::OsStr> for CheminTmp<'_> {
    fn as_ref(&self) -> &std::ffi::OsStr {
        std::ffi::OsStr::new(&self.s)
    }
}
#[cfg(test)]
impl AsRef<str> for CheminTmp<'_> {
    fn as_ref(&self) -> &str {
        &self.s
    }
}
#[cfg(test)]
impl std::fmt::Display for CheminTmp<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.s)
    }
}
#[cfg(test)]
impl std::fmt::Debug for CheminTmp<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.s, f)
    }
}

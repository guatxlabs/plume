//! LE PIC DE TAS VIVANT D'UN SEUL FIL — instrument de mesure mémoire **déterministe**, compilé
//! UNIQUEMENT sous `cfg(test)` (le binaire de production ne contient ni cet allocateur ni cette
//! mesure : `cargo build` ne pose PAS `cfg(test)`).
//!
//! POURQUOI IL EXISTE. Une propriété mémoire ne se prouve pas avec le RSS DU PROCESSUS quand la
//! suite tourne en parallèle : le RSS est une grandeur GLOBALE, les allocations des tests voisins
//! y entrent, et le verdict devient fonction du nombre de cœurs, de l'ordonnancement et de
//! l'allocateur. Un test qui n'est vert que sur certaines machines est PIRE qu'absent — il apprend
//! à ignorer le rouge. (Précédent : `backup_streaming_..._bounded_memory_delta` a refusé un build
//! du binaire livré le 2026-08-08 en mesurant, en CI, +247 Mio de RSS pour une charge de 64 Mio, alors que le
//! chemin testé n'avait pas changé.)
//!
//! CE QU'IL MESURE, EXACTEMENT. La somme des octets Rust ALLOUÉS MOINS LIBÉRÉS **par le fil
//! appelant**, et le MAXIMUM atteint par cette somme pendant la fermeture mesurée. C'est « la plus
//! grande quantité vivante à un instant donné » sur ce fil — un compteur ENTIER, pas un
//! échantillonnage : il ne peut ni rater un pic ni voir celui d'un voisin. Deux fils qui mesurent
//! en même temps ne se voient pas (comptes en TLS).
//!
//! CE QU'IL NE MESURE PAS, ET IL FAUT LE DIRE :
//!   - les allocations faites par le C LIÉ (SQLite/SQLCipher appelle `malloc` directement, pas
//!     `GlobalAlloc`) : le tampon de ligne du pager, donc la CELLULE empruntée par `ValueRef`, est
//!     INVISIBLE ici. Un test qui veut prouver « on ne retient pas la TABLE » le peut quand même —
//!     l'accumulation qu'on veut exclure serait, elle, du Rust ; mais un test ne peut pas prétendre
//!     mesurer par cet instrument le coût d'UNE cellule.
//!   - ce qu'un AUTRE fil alloue, y compris pour le compte du fil mesuré. La mesure suppose donc
//!     que la fermeture mesurée travaille sur SON fil (c'est le cas de `backup_compressed` :
//!     rusqlite, zstd et age y sont tous synchrones).
//!   - le RSS : rien ici ne dit ce que l'OS garde résident. On mesure la DEMANDE, pas la résidence.
//!
//! CE QU'IL COÛTE À LA SUITE. Hors mesure — c'est-à-dire pour la quasi-totalité des tests — le
//! chemin d'allocation ajoute UNE lecture atomique relaxée et repart : `FILS_EN_MESURE` vaut 0,
//! donc aucun accès TLS, aucune arithmétique. Le compte TLS n'est touché que pendant qu'un fil
//! mesure réellement.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Nombre de fils actuellement EN MESURE. Porte d'entrée du chemin lent : tant qu'elle vaut 0,
/// `note` ne touche pas au TLS. Relaxed suffit — aucune donnée n'est publiée à travers elle, et un
/// retard de visibilité ne peut que faire manquer des allocations À UN FIL QUI NE MESURE PAS.
static FILS_EN_MESURE: AtomicUsize = AtomicUsize::new(0);

/// Compte d'un fil. `Copy` + pas de `Drop` : le `thread_local!` s'initialise en CONST, donc son
/// premier accès n'alloue RIEN (une init paresseuse qui allouerait rentrerait dans l'allocateur).
#[derive(Clone, Copy)]
struct Compte {
    arme: bool,
    vivant: i64,
    pic: i64,
}

thread_local! {
    static COMPTE: Cell<Compte> = const { Cell::new(Compte { arme: false, vivant: 0, pic: 0 }) };
}

/// Enregistre une variation du tas vivant du fil courant. N'ALLOUE JAMAIS (sinon récursion
/// infinie dans l'allocateur). `try_with` plutôt que `with` : pendant la destruction des TLS d'un
/// fil qui se termine, l'accès peut échouer — on l'ignore au lieu de paniquer dans `dealloc`.
#[inline]
fn note(delta: i64) {
    if FILS_EN_MESURE.load(Ordering::Relaxed) == 0 {
        return;
    }
    let _ = COMPTE.try_with(|c| {
        let mut s = c.get();
        if !s.arme {
            return;
        }
        s.vivant += delta;
        if s.vivant > s.pic {
            s.pic = s.vivant;
        }
        c.set(s);
    });
}

/// Allocateur global de la SUITE DE TESTS : délègue tout au `System` (comportement d'allocation
/// IDENTIQUE au défaut de Rust) et se contente de tenir le compte ci-dessus.
pub(crate) struct AllocateurQuiCompte;

unsafe impl GlobalAlloc for AllocateurQuiCompte {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            note(l.size() as i64);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            note(l.size() as i64);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        note(-(l.size() as i64));
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, taille_neuve: usize) -> *mut u8 {
        let np = System.realloc(p, l, taille_neuve);
        if !np.is_null() {
            note(taille_neuve as i64 - l.size() as i64);
        }
        np
    }
}

/// Désarme le fil et referme la porte MÊME SI la fermeture mesurée panique — sans quoi une panique
/// laisserait toute la suite sur le chemin lent et le compte armé pour le test suivant.
struct Desarmement;
impl Drop for Desarmement {
    fn drop(&mut self) {
        FILS_EN_MESURE.fetch_sub(1, Ordering::Relaxed);
        COMPTE.with(|c| {
            let mut s = c.get();
            s.arme = false;
            c.set(s);
        });
    }
}

/// Exécute `corps` sur le fil courant et renvoie `(sa valeur, le PIC de tas vivant en octets)`.
/// Le pic est relatif au début de la mesure : le compte repart de 0 à l'armement, donc ce qui
/// vivait AVANT n'est pas compté. Une libération d'un bloc alloué avant l'armement fait descendre
/// le compte sous 0 — ça ne peut que SOUS-estimer le pic, jamais l'inventer.
pub(crate) fn pic_vivant_pendant<T>(corps: impl FnOnce() -> T) -> (T, u64) {
    COMPTE.with(|c| {
        assert!(!c.get().arme, "mesure de tas déjà armée sur ce fil — l'imbrication n'est pas supportée");
        c.set(Compte { arme: true, vivant: 0, pic: 0 });
    });
    FILS_EN_MESURE.fetch_add(1, Ordering::Relaxed);
    let _desarmement = Desarmement;
    let sortie = corps();
    let pic = COMPTE.with(|c| c.get().pic);
    (sortie, pic.max(0) as u64)
}

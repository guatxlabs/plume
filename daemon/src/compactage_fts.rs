//! LA COMPACTION DE L'INDEX PLEIN-TEXTE — rendre les octets qu'une PURGE a rendus MORTS.
//!
//! LE DÉFAUT, MESURÉ (P10.7-b, 2026-08-09). Sortir un événement de la fenêtre chaude fait **GROSSIR**
//! l'index plein-texte. Sur une base de banc au schéma RÉEL de plume (1 200 000 événements, puis un vrai
//! `DELETE FROM event` de 700 800 lignes = 58,4 %), avec la SQLite EXACTE du produit (SQLCipher 4.5.3 /
//! SQLite 3.39.4, les PRAGMA de `server::tune`) :
//!
//! ```text
//!   event_fts_docsize : 14,11 -> 5,88 Mio    (-58,3 %  — il SUIT la suppression)
//!   event_fts_data    : 135,27 -> 185,69 Mio (+37,3 %  — il GROSSIT)
//! ```
//!
//! FTS5 à contenu externe ne peut pas retirer un posting en place : le déclencheur `event_ad` écrit un
//! posting de SUPPRESSION, qui s'AJOUTE. L'espace n'est rendu qu'à la FUSION DES SEGMENTS. Et plume ne
//! fusionnait JAMAIS : aucun `'optimize'`, aucun `'merge'` nulle part dans le démon (le seul `'rebuild'`
//! vit dans `backup/dump_restauration.rs`, sur le chemin de RESTAURATION). Le poids mort ne pouvait donc que s'accumuler,
//! purge après purge — c'est ce qui explique que la part FTS soit passée de 8,1 % (banc) à 18,9 % (prod)
//! sans croissance organique correspondante.
//!
//! ─────────────────────────────────────────────────────────────────────────────────────────────────
//! POURQUOI `merge` BORNÉ ET NON `optimize` — L'ARBITRAGE, MESURÉ, PAS SUPPOSÉ
//!
//! Mesuré sur la base ci-dessus (499 200 documents restants, index gonflé à 185,69 Mio), chaque bras
//! partant d'une COPIE OCTET-À-OCTET du même état :
//!
//! ```text
//!   bras                        passes  total     verrou writer   rafale WAL   plancher   segments
//!   optimize                         1  17,08 s   17,08 s D'UN    192,6 Mio    56,56 Mio         1
//!                                                 SEUL TENANT
//!   merge=+2000 (usermerge=4)        0   0,00 s    —                0,0 Mio   185,69 Mio        15
//!     ^^^ NE FAIT RIEN, ET C'EST LE PIÈGE
//!   merge=+2000 + usermerge=2       25  30,83 s    2,14 s max     40,1 Mio    56,52 Mio         1
//!   merge=-2000                      7  15,11 s    2,44 s max     40,3 Mio    56,61 Mio         1
//!   merge=-500                      25  16,29 s    1,04 s max     13,4 Mio    56,53 Mio         1
//! ```
//!
//! ET SUR UN INDEX DÉJÀ CONVERGÉ PUIS PURGÉ — le régime de la rétention, qui compacte à chaque tick —
//! le budget positif, même à `usermerge=2`, N'ATTEINT PAS le plancher. Mesuré sur la fixture des
//! témoins (20 000 événements, `optimize`, deux lots, purge de 12 000) :
//!
//! ```text
//!   bras                        octets de event_fts_data   segments
//!   avant compaction                       5 656 576              5
//!   merge=+200 + usermerge=2               5 586 944              2   (500 passes)
//!   merge=-200 (et retrait)                1 568 768              1
//!   optimize                               1 564 672              1
//! ```
//!
//! 1. **Seul le budget NÉGATIF fusionne des niveaux DIFFÉRENTS.** Avec N positif, `fts5IndexMerge`
//!    ne fusionne qu'un niveau portant au moins `usermerge` segments (sqlite3.c:237002) ; le plus
//!    ancien segment, qui porte les postings des événements purgés, est SEUL à son niveau et n'est
//!    jamais repris tant que la cascade des petits segments ne l'a pas rattrapé en taille. Sur
//!    l'index gonflé du banc (15 segments sur 9 niveaux, aucun au quota de 4), N positif rend zéro
//!    octet en 0,00 s ; le `usermerge=2` du tableau n'atteint le plancher que sur un index frais dont
//!    les promotions de niveau ramènent tout au même niveau. Avec `-N`, FTS5 prend le chemin de
//!    l'`optimize` (`fts5IndexOptimizeStruct`, tous les segments sur un seul niveau, `nMin=2`) borné
//!    à N pages écrites : un `optimize` INCRÉMENTAL.
//! 2. **Le plancher est le MÊME** : 56,53 Mio en incrémental contre 56,56 Mio d'un coup (écart 0,05 %).
//! 3. **Le verrou d'écriture et la rafale WAL sont fixés par N, PAS par la taille de l'index.** Vérifié
//!    au DOUBLE du volume (2 400 000 événements ingérés, 998 400 restants, index gonflé à 370,7 Mio) :
//!    à `merge=-500`, la pire passe vaut **0,907 s** et le pic WAL **15,4 Mio**, contre 1,037 s et
//!    13,4 Mio à la moitié du volume. Seul le NOMBRE de passes suit la taille (48 contre 25). C'est la
//!    propriété qui rend la chose déployable sur un nœud à 2 Gio : la dépense par prise de verrou ne
//!    grandit pas avec la base.
//! 4. **Une interruption ne coûte pas la même chose.** `_exit(9)` à 8 s dans un `optimize` de 17 s :
//!    117 Mio de WAL jetés, index rendu à l'octet près à son état d'AVANT (185,69 Mio, 15 segments),
//!    `integrity-check` OK — mais **8 s de travail PERDUES, et un nœud qui redémarre plus souvent que
//!    la durée de l'optimize ne progresse JAMAIS**. `SIGKILL` réel à 5 s dans une séquence
//!    `merge=-500` : les passes déjà committées SURVIVENT (185,69 -> 163,82 Mio), `integrity-check` OK,
//!    et la reprise converge à **59 277 312 octets — le MÊME nombre, à l'octet près**, que la séquence
//!    jamais interrompue. La compaction bornée est REPRENABLE ; la rafale est tout-ou-rien.
//! 5. **La RAM n'est pas le sujet, le WAL l'est.** `sqlite3_memory_highwater` culmine à 66,3 Mio pour
//!    LES DEUX bras, à froid comme à chaud, à 499 k comme à 998 k documents : c'est le `cache_size`
//!    (`-65536`, 64 Mio) de `sqlite_plafond`, et rien d'autre. La fusion ne construit AUCUNE structure
//!    proportionnelle à l'index — elle streame segment par segment. Ce qui coûte, c'est la rafale WAL
//!    sur DISQUE : 192,6 Mio d'un coup pour l'`optimize`, 13,4 Mio pour `merge=-500`.
//!
//! ─────────────────────────────────────────────────────────────────────────────────────────────────
//! LE DÉFAUT DU BUDGET NÉGATIF : LES NIVEAUX, SANS BORNE — ET CE QUI LES BORNE
//!
//! Lu dans l'amalgamation vendorée (SQLite 3.39.4). `fts5IndexOptimizeStruct` place les segments
//! d'une structure ÉTALÉE sur plusieurs niveaux dans un niveau NEUF : `pNew->nLevel =
//! pStruct->nLevel+1` (sqlite3.c:237298) ; la fusion de ce dernier niveau écrit sa sortie dans un
//! AUTRE niveau neuf (`fts5StructureAddLevel` quand `iLvl==pStruct->nLevel-1`, sqlite3.c:236853). Deux
//! niveaux de plus, donc, chaque fois que l'ingestion a déposé un segment depuis la passe précédente.
//! Aucun code du moteur ne retire un niveau vide : seuls `rebuild` et `delete-all` réécrivent une
//! structure à zéro niveau. Et `fts5StructureDecode` refuse une structure de plus de `FTS5_MAX_SEGMENT`
//! niveaux (`#define FTS5_MAX_SEGMENT 2000`, sqlite3.c:224532 ; le refus, sqlite3.c:233443) : l'index
//! devient illisible et toute insertion dans la table qui le porte échoue. `integrity_check` ne juge
//! pas FTS5 et ne le voit pas.
//!
//! Mesuré sur la fixture des témoins, 60 cycles « tick de huit passes, lot de 500 insertions, purge
//! tous les cinq cycles » : budget négatif seul, 26, 46, 66, 86, 106 puis 126 niveaux (deux par
//! cycle, sans fin) ; budget négatif suivi du retrait, 16 niveaux à chaque relevé, et les MÊMES
//! octets. Le budget positif à `usermerge=2` garde peu de niveaux (de 7 à 10 sur cent cycles) mais son
//! index grossit (11 935 744 octets contre 10 039 296 au centième cycle) : il ne rend pas le poids mort.
//!
//! LE CORRECTIF : APRÈS CHAQUE PASSE, LES NIVEAUX VIDES EXCÉDENTAIRES SONT RETIRÉS de
//! l'enregistrement de structure (`retirer_les_niveaux_vides`), jusqu'à `NIVEAUX_CONSERVES`. C'est une
//! réécriture de `%_data` rowid 10 qui recopie chaque segment à l'octet, validée par le décodeur de
//! FTS5 lui-même avant d'être commitée ; la preuve qu'elle ne change pas le contenu est sur
//! `retrait_des_niveaux_vides`. La borne : après une passe, la structure porte au plus
//! `max(NIVEAUX_CONSERVES, niveaux peuplés)` niveaux, et une passe en ajoute au plus deux.
//! Et une GARDE (`SEUIL_NIVEAUX`) refuse toute passe au-delà : un index arrivé là par une autre voie
//! ne s'aggrave plus, et la santé le montre (`niveaux_des_index`).
//!
//! CE QUE LA COMPACTION NE FAIT PAS, ET QUI DOIT ÊTRE DIT : elle ne RÉTRÉCIT PAS LE FICHIER. Les pages
//! libérées vont à la FREELIST (mesuré : 33 753 -> 66 884 pages, +129 Mio réutilisables), `page_count`
//! ne bouge pas d'une page. L'octet « rendu » est rendu à la BASE — l'ingestion suivante le réemploie
//! au lieu d'étendre le fichier. Le rendre au SYSTÈME DE FICHIERS demanderait un `VACUUM`, qui est une
//! tout autre dépense et n'est pas ce que cette campagne décide.
//!
//! CE QUI N'A PAS ÉTÉ ÉTABLI : ces nombres viennent d'une base FABRIQUÉE au profil mesuré de la
//! production (`bench/profile-prod.json`), pas de la production elle-même — la fidélité constatée est
//! de +2,5 % sur `event_fts_data` par document et de -7,4 % sur `event_fts_docsize`, ce qui est bon,
//! mais ce n'est pas la même chose qu'une mesure sur la base réelle.

use crate::*;

// =================================================================================================
// LE RÉGLAGE — lu par `cfg()`, jamais par `std::env::var`
// =================================================================================================

/// Ce qu'un opérateur peut décider. Les TROIS voies de déploiement (systemd host-natif, Docker, k3s)
/// obtiennent le même effet parce que tout passe par `cfg()` (`env > PLUME_CONFIG > défaut`) — la
/// partition fermée par `tests/partition_config.rs`. Aucune de ces clés n'entre au registre de dette.
pub(crate) struct Reglage {
    /// `PLUME_FTS_COMPACT` — le kill-switch. `0` : la compaction ne s'exécute PAS et le dit.
    pub actif: bool,
    /// `PLUME_FTS_COMPACT_PAGES` — le BUDGET D'UNE PASSE, en pages d'index FTS5 écrites. C'est lui qui
    /// fixe la durée d'UNE prise du verrou d'écriture et la taille de la rafale WAL (mesuré : 500 ->
    /// ~1 s et ~13 Mio, indépendamment de la taille de l'index). Borné [50, 20000].
    pub pages: i64,
    /// `PLUME_FTS_COMPACT_PASSES` — combien de passes AU PLUS par tick. Le verrou est RELÂCHÉ entre
    /// deux (l'ingestion s'intercale), donc ce n'est pas une durée de verrou mais un budget de tick.
    /// Borné [1, 5000]. Ce qui n'est pas fait ce tick-ci est repris au suivant, sans perte.
    pub passes: i64,
    /// `PLUME_FTS_COMPACT_REPOS_MS` — la RESPIRATION entre deux passes (modèle
    /// `reconcile_expr_indexes_background`). Borné [0, 60000].
    pub repos_ms: u64,
}

/// Bornes DURES, appliquées à la lecture : une valeur aberrante écrite dans `soc.conf` ne peut pas
/// transformer la compaction en rafale non bornée (le défaut même qu'on refuse).
const PAGES_MIN: i64 = 50;
const PAGES_MAX: i64 = 20_000;
const PASSES_MIN: i64 = 1;
const PASSES_MAX: i64 = 5_000;

impl Reglage {
    /// PURE (prend la configuration déjà chargée) -> se teste sans toucher à l'environnement, ce qui
    /// est la condition pour que le test soit sûr en parallèle.
    pub(crate) fn depuis(conf: &HashMap<String, String>) -> Reglage {
        Reglage {
            actif: cfg(conf, "PLUME_FTS_COMPACT", "1") == "1",
            pages: cfg(conf, "PLUME_FTS_COMPACT_PAGES", "500").parse().unwrap_or(500).clamp(PAGES_MIN, PAGES_MAX),
            passes: cfg(conf, "PLUME_FTS_COMPACT_PASSES", "8").parse().unwrap_or(8).clamp(PASSES_MIN, PASSES_MAX),
            repos_ms: cfg(conf, "PLUME_FTS_COMPACT_REPOS_MS", "200").parse().unwrap_or(200).clamp(0, 60_000),
        }
    }
}

// =================================================================================================
// CE QUI S'EST PASSÉ — un type, pas une phrase
// =================================================================================================

/// L'ISSUE D'UNE COMPACTION. Elle est un TYPE et non un message parce que la propriété qui compte est
/// vérifiable : **aucune variante autre que `Rendue` ne porte d'octets rendus**, donc aucun chemin de
/// code ne peut annoncer une compaction faite quand elle a été sautée. C'est la famille de défaut de
/// ce dépôt (« rétention OK » sur une base non purgée), et elle est fermée ici par le typage.
pub(crate) enum Issue {
    /// `PLUME_FTS_COMPACT != 1`. Rien n'a été tenté, et l'index reste gonflé.
    Desactivee,
    /// Le schéma ne porte aucune table FTS5. Rien à compacter — ce n'est pas un échec.
    AucunIndex,
    /// Moins de deux segments : FTS5 LUI-MÊME n'a rien à fusionner (`fts5IndexOptimizeStruct` :
    /// `if( nSeg<2 ) return 0;`). On le CONSTATE au lieu de lancer une passe pour rien.
    DejaCompact { nom: String, octets: i64 },
    /// La seule variante qui annonce des octets. Ce qui a ARRÊTÉ la séquence est PORTÉ AVEC : une
    /// fusion coupée par une erreur SQLite ne doit pas se lire comme une fusion simplement inachevée.
    Rendue {
        nom: String,
        octets_avant: i64,
        octets_apres: i64,
        segments_avant: i64,
        segments_apres: i64,
        /// Les niveaux de la structure à l'entrée, et après la dernière passe et son retrait.
        niveaux_avant: i64,
        niveaux_apres: i64,
        docs: Option<i64>,
        passes: i64,
        duree_ms: u128,
        arret: Arret,
    },
    /// SQLite a refusé AVANT la première passe. AUCUN octet n'est annoncé — on ne sait rien.
    Echec { nom: String, message: String },
    /// LA GARDE, À L'ENTRÉE : la structure porte plus de `SEUIL_NIVEAUX` niveaux. AUCUNE passe n'est
    /// lancée et rien n'est écrit — l'index ne s'aggrave plus du fait de la compaction.
    NiveauxAuSeuil { nom: String, niveaux: i64 },
}

/// POURQUOI LA SÉQUENCE S'EST ARRÊTÉE. Ce n'est pas un booléen, et la différence n'est pas
/// cosmétique : « le budget du tick est épuisé » est un régime NORMAL (le tick suivant reprend), alors
/// qu'une erreur SQLite au milieu — disque plein, verrou tenu, E/S — est un INCIDENT. Un booléen
/// `convergee` les confondait, et la phrase produite aurait annoncé « reprise au prochain tick » sur
/// une base qui n'écrit plus. C'est exactement la famille de défaut que ce dépôt ferme.
pub(crate) enum Arret {
    /// Plancher atteint : moins de deux segments, il n'y a plus rien à fusionner.
    Convergee,
    /// `PLUME_FTS_COMPACT_PASSES` atteint. Régime normal, le tick suivant continue.
    BudgetEpuise,
    /// Une passe a échoué. Les passes PRÉCÉDENTES ont committé (leurs octets sont réels), celle-ci non.
    Erreur(String),
    /// L'enregistrement de structure FTS5 est devenu illisible en cours de route : on ne sait plus
    /// combien de segments restent, donc on s'arrête au lieu de fusionner à l'aveugle.
    StructureIllisible,
    /// LA GARDE, AVANT UNE PASSE DE LA SÉQUENCE : la structure relue porte plus de `SEUIL_NIVEAUX`
    /// niveaux, la passe n'est pas lancée. Les passes précédentes ont committé.
    NiveauxAuSeuil { niveaux: i64 },
    /// La dernière passe a committé, mais le retrait de ses niveaux vides a été refusé (cause portée,
    /// structure d'avant le retrait conservée) : la suite n'est pas tentée.
    NiveauxNonRetires(String),
}

impl Issue {
    /// La ligne de journal. Elle NOMME toujours ce qui s'est passé, y compris quand c'est « rien ».
    pub(crate) fn phrase(&self) -> String {
        let mio = |o: i64| o as f64 / (1024.0 * 1024.0);
        match self {
            Issue::Desactivee => "[fts-compact] DÉSACTIVÉE (PLUME_FTS_COMPACT!=1) : AUCUNE fusion, l'index plein-texte GARDE le poids mort de ses suppressions".into(),
            Issue::AucunIndex => "[fts-compact] aucun index FTS5 dans ce schéma : rien à compacter".into(),
            Issue::DejaCompact { nom, octets } => format!(
                "[fts-compact] {nom} DÉJÀ COMPACT (< 2 segments — FTS5 n'a rien à fusionner) : {:.2} Mio, RIEN N'A ÉTÉ FAIT",
                mio(*octets)
            ),
            Issue::Rendue { nom, octets_avant, octets_apres, segments_avant, segments_apres, niveaux_avant, niveaux_apres, docs, passes, duree_ms, arret } => {
                let rendus = octets_avant - octets_apres;
                let pct = if *octets_avant > 0 { rendus as f64 * 100.0 / *octets_avant as f64 } else { 0.0 };
                format!(
                    "[fts-compact] {nom} : {:.2} -> {:.2} Mio ({} octets rendus à la freelist, {pct:.1} %) | \
                     segments {segments_avant} -> {segments_apres} | niveaux {niveaux_avant} -> {niveaux_apres} | docs {} | \
                     {passes} passe(s) en {duree_ms} ms | {}",
                    mio(*octets_avant),
                    mio(*octets_apres),
                    rendus,
                    docs.map(|d| d.to_string()).unwrap_or_else(|| "NON MESURÉS (pas de table docsize)".into()),
                    match arret {
                        Arret::Convergee => "CONVERGÉ (plancher atteint)".to_string(),
                        Arret::BudgetEpuise => format!(
                            "BUDGET DU TICK ÉPUISÉ — il RESTE du poids mort, reprise au prochain tick (PLUME_FTS_COMPACT_PASSES={passes})"
                        ),
                        Arret::Erreur(e) => format!(
                            "ARRÊTÉ SUR ERREUR SQLite ({e}) — les {passes} passe(s) ci-dessus ont bien committé, la suivante NON ; \
                             ce n'est PAS un simple budget épuisé"
                        ),
                        Arret::StructureIllisible => "ARRÊTÉ : structure FTS5 devenue ILLISIBLE en cours de fusion — \
                             on ne sait plus combien de segments restent, la suite n'est pas tentée".to_string(),
                        Arret::NiveauxAuSeuil { niveaux } => format!(
                            "ARRÊTÉ : {niveaux} niveaux dans la structure, au-delà du seuil de {SEUIL_NIVEAUX} — la passe suivante \
                             n'est PAS lancée (le moteur refuse de lire une structure de plus de {LIMITE_DU_MOTEUR} niveaux) ; \
                             {}",
                            remede(nom)
                        ),
                        Arret::NiveauxNonRetires(cause) => format!(
                            "ARRÊTÉ : la dernière passe a committé mais ses niveaux vides n'ont PAS été retirés ({cause}) — \
                             la suite n'est pas tentée"
                        ),
                    }
                )
            }
            Issue::Echec { nom, message } => format!(
                "[fts-compact] {nom} ÉCHEC ({message}) — AUCUN octet annoncé, l'état de l'index n'est pas connu ; nouvel essai au prochain tick"
            ),
            Issue::NiveauxAuSeuil { nom, niveaux } => format!(
                "[fts-compact] {nom} : {niveaux} NIVEAUX dans la structure FTS5, au-delà du seuil de {SEUIL_NIVEAUX} — AUCUNE \
                 fusion lancée, rien n'est écrit : le moteur refuse de lire une structure de plus de {LIMITE_DU_MOTEUR} niveaux, \
                 l'index devient alors illisible et toute insertion échoue ; {}",
                remede(nom)
            ),
        }
    }

    /// Les octets rendus, ou `None` quand il n'y en a PAS EU. Sert aux gardes : une issue qui n'est pas
    /// `Rendue` ne peut pas produire un nombre, par construction.
    pub(crate) fn octets_rendus(&self) -> Option<i64> {
        match self {
            Issue::Rendue { octets_avant, octets_apres, .. } => Some(octets_avant - octets_apres),
            _ => None,
        }
    }
}

// =================================================================================================
// LES INSTRUMENTS — dérivés du schéma et de FTS5, jamais énumérés
// =================================================================================================

/// Les index FTS5 du schéma, DEMANDÉS À SQLITE. On n'écrit pas « event_fts » : `event_fields_fts`
/// (Phase 1, `PLUME_FTS_FIELDS=1`) souffre EXACTEMENT du même défaut, et une vtable ajoutée demain
/// aussi. Une liste en dur laisserait le prochain index gonfler en silence — c'est la règle du dépôt
/// (cf. `db_ventilation::classer`, `drop_orphan_auto_field_indexes_background`).
///
/// Le nom est RE-VALIDÉ par `soql_ident_ok` avant toute interpolation : il vient de `sqlite_master`
/// (jamais d'une entrée utilisateur), mais la même discipline s'applique partout.
pub(crate) fn index_plein_texte(conn: &Connection) -> Vec<String> {
    // `lower(sql)` DES DEUX CÔTÉS : un `LIKE` sur le texte tel quel n'aurait attrapé que les DDL
    // écrites en majuscules. Celles de `db/schema.sql` le sont — ce qui rend l'erreur invisible
    // aujourd'hui et vraie demain, exactement le genre de filtre qui ne rend rien sans le dire.
    let Ok(mut st) = conn.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' \
           AND lower(sql) LIKE 'create virtual table%' AND lower(sql) LIKE '%using fts5%' ORDER BY name",
    ) else {
        return Vec::new();
    };
    let Ok(rows) = st.query_map([], |r| r.get::<_, String>(0)) else {
        return Vec::new();
    };
    rows.flatten().filter(|n| soql_ident_ok(n)).collect()
}

/// UN varint SQLite. Sept bits par octet, bit de poids fort = continuation ; le NEUVIÈME octet, s'il
/// existe, apporte ses HUIT bits. Rendu : (valeur, position suivante). `None` = enregistrement tronqué
/// — on ne devine pas.
fn varint(b: &[u8], mut i: usize) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    for _ in 0..8 {
        let c = *b.get(i)?;
        i += 1;
        v = (v << 7) | (c & 0x7f) as u64;
        if c & 0x80 == 0 {
            return Some((v, i));
        }
    }
    let c = *b.get(i)?;
    Some(((v << 8) | c as u64, i + 1))
}

/// LE NOMBRE DE SEGMENTS, lu dans l'enregistrement de STRUCTURE que FTS5 tient lui-même.
///
/// POURQUOI PAS `COUNT(DISTINCT segid) FROM <nom>_idx`. Parce que ce serait FAUX en silence : un
/// segment d'UNE SEULE page n'écrit AUCUNE ligne dans `%_idx` (`fts5WriteFlushBtree` sort si
/// `iBtPage==0`). Le compte serait alors sous-évalué, et la compaction se croirait finie.
/// L'enregistrement de structure, lui, est la source que FTS5 CONSULTE pour décider : `%_data` rowid
/// 10 (`FTS5_STRUCTURE_ROWID`), quatre octets de cookie, puis `nLevel` et `nSegment` en varints
/// (`fts5StructureDecode`). C'est UNE ligne de 7 octets (index vide) à ~110 — l'instrument le moins cher ET le plus
/// fidèle. VALIDÉ le 2026-08-09 contre `COUNT(DISTINCT segid)` sur cinq états d'index distincts
/// (24 / 15 / 1 / 1 / 1) : accord exact.
///
/// `None` = on n'a pas pu lire. Un index dont on ne connaît pas la structure n'est PAS compacté (on ne
/// lance pas une fusion à l'aveugle sous le verrou d'écriture).
pub(crate) fn segments(conn: &Connection, nom: &str) -> Option<i64> {
    structure(conn, nom).map(|s| s.segments)
}

/// LES DEUX NOMBRES DE L'EN-TÊTE DE STRUCTURE : niveaux et segments, tels que FTS5 les décode
/// (`fts5StructureDecode`). Le nombre de niveaux est celui que le moteur borne : au-delà de
/// `LIMITE_DU_MOTEUR`, il refuse de décoder et l'index devient illisible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Structure {
    pub niveaux: i64,
    pub segments: i64,
}

/// L'en-tête d'un enregistrement de structure, PUR. `None` = enregistrement trop court ou varint
/// tronqué : une forme qu'on ne sait pas lire, jamais « zéro niveau ».
fn entete_de_structure(bloc: &[u8]) -> Option<Structure> {
    if bloc.len() < 6 {
        return None;
    }
    let (niveaux, i) = varint(bloc, 4)?;
    let (segments, _) = varint(bloc, i)?;
    Some(Structure { niveaux: i64::try_from(niveaux).ok()?, segments: i64::try_from(segments).ok()? })
}

/// La structure d'un index, lue en UNE ligne (`%_data` rowid 10). `None` = lecture ratée ou forme
/// inconnue.
pub(crate) fn structure(conn: &Connection, nom: &str) -> Option<Structure> {
    let bloc: Vec<u8> = conn
        .query_row(&format!("SELECT block FROM {nom}_data WHERE id=10"), [], |r| r.get(0))
        .ok()?;
    entete_de_structure(&bloc)
}

// =================================================================================================
// LES NIVEAUX — bornés par le moteur, jamais retirés par lui
// =================================================================================================

/// LA LIMITE DU MOTEUR : `FTS5_MAX_SEGMENT` (sqlite3.c:224532). `fts5StructureDecode` rend
/// `FTS5_CORRUPT` dès que `nLevel` la dépasse (sqlite3.c:233443) : l'index ne se lit plus, et toute
/// insertion dans la table qui le porte échoue.
pub(crate) const LIMITE_DU_MOTEUR: i64 = 2000;

/// LA GARDE : au-delà de ce nombre de niveaux, la compaction ne lance AUCUNE passe. Une passe ajoute
/// au plus deux niveaux (cf. l'en-tête du module) : le seuil laisse au moteur une marge de mille
/// niveaux, très au-delà de la marge d'une passe.
pub(crate) const SEUIL_NIVEAUX: i64 = 1000;

/// L'ALERTE DE SANTÉ : au-delà, le composant `store` quitte le vert. Le retrait des niveaux vides tient
/// la structure sous `NIVEAUX_CONSERVES` plus les deux niveaux d'une passe ; un index qui dépasse
/// cette alerte est un index dont le retrait ne tient plus, bien avant la garde.
pub(crate) const NIVEAUX_D_ALERTE: i64 = 64;

/// LE NOMBRE DE NIVEAUX QUE LE RETRAIT CONSERVE. Les niveaux de FTS5 sont des CLASSES DE TAILLE : la
/// fusion automatique de l'ingestion (`automerge`, quatre segments par niveau) fait monter les petits
/// segments d'un niveau à l'autre, en partant du niveau 0 où chaque lot dépose le sien
/// (`fts5FlushOneHash`). Garder des niveaux vides sous le plus ancien segment l'ÉLOIGNE de cette
/// cascade ; les retirer TOUS le placerait au niveau 0, à côté de chaque segment déposé.
pub(crate) const NIVEAUX_CONSERVES: i64 = 16;

/// LE REMÈDE, une seule phrase pour le journal et pour la santé. Il est le seul qui retire des niveaux
/// sans passer par la compaction : `rebuild` vide l'index (`sqlite3Fts5IndexReinit` réécrit une
/// structure à zéro niveau, sqlite3.c:237920) puis le rebâtit depuis sa table source. Un redémarrage
/// ne le joue PAS tant que l'index se lit : la porte d'ouverture ne rebâtit qu'une table virtuelle dont
/// le constructeur échoue (`db_open::nom_de_vtable_en_echec`), et le constructeur ne lit la structure
/// qu'au travers du décodage, qui n'échoue qu'au-delà de `LIMITE_DU_MOTEUR`.
pub(crate) fn remede(nom: &str) -> String {
    format!("remède : reconstruire l'index depuis sa source, démon arrêté : INSERT INTO {nom}({nom}) VALUES('rebuild')")
}

/// LE REMÈDE AU-DELÀ DE LA LIMITE DU MOTEUR, où `rebuild` n'est plus jouable : la table virtuelle ne se
/// construit plus (son constructeur décode la structure, `sqlite3Fts5IndexLoadConfig`,
/// sqlite3.c:239752), donc aucune commande ne l'atteint. C'est alors la porte d'ouverture qui la
/// rebâtit depuis sa source, au démarrage (`db_open::reconstruire_index_derive`).
pub(crate) fn remede_au_dela_de_la_limite() -> &'static str {
    "remède : redémarrer le démon — la porte d'ouverture rebâtit depuis sa source un index dont la table virtuelle ne se construit plus"
}

/// La phrase d'une structure qu'on ne sait pas réécrire. Le retrait ne la touche pas.
pub(crate) const STRUCTURE_DE_FORME_INCONNUE: &str =
    "enregistrement de structure FTS5 de forme inconnue (tronqué, incohérent, ou format d'une autre version du moteur) : rien n'est réécrit";

/// Un varint SQLite ÉCRIT (forme à sept bits par octet, big-endian) — l'inverse de `varint` pour les
/// valeurs sous 2^56, les seules qu'un nombre de niveaux puisse prendre ici.
fn ecrire_varint(v: u64, sortie: &mut Vec<u8>) {
    let mut groupes = vec![(v & 0x7f) as u8];
    let mut reste = v >> 7;
    while reste > 0 {
        groupes.push((reste & 0x7f) as u8 | 0x80);
        reste >>= 7;
    }
    sortie.extend(groupes.iter().rev());
}

/// LE RETRAIT DES NIVEAUX VIDES, PUR : rend l'enregistrement réécrit et (niveaux avant, niveaux après),
/// ou `None` s'il n'y a rien à retirer.
///
/// L'ENREGISTREMENT est celui qu'écrit `fts5StructureWrite` (sqlite3.c:233704) : quatre octets de
/// cookie, puis en varints `nLevel`, `nSegment`, `nWriteCounter`, puis par niveau `nMerge`, `nSeg` et
/// trois varints par segment. Il est découpé EN ENTIER ; toute incohérence (varint tronqué, octets en
/// trop, somme des segments différente de `nSegment`, `nMerge > nSeg`) le fait refuser.
///
/// POURQUOI RETIRER UN NIVEAU VIDE NE CHANGE RIEN AU CONTENU. Un niveau vide ne porte aucun segment ;
/// les segments, leurs pages et leur ordre sont recopiés à l'octet. `fts5StructureDecode`
/// (sqlite3.c:233493-233494) exige seulement qu'un niveau en cours de fusion (`nMerge>0`) soit suivi
/// d'un niveau NON vide et que le dernier niveau ne soit pas en fusion : un niveau vide n'est donc
/// jamais le successeur d'un niveau en fusion, et le retirer laisse chaque niveau en fusion devant le
/// même successeur ; le dernier niveau retiré vide laisse au sommet un niveau qui ne pouvait pas être
/// en fusion. Les niveaux retirés sont les PLUS HAUTS vides d'abord (ceux que la fusion du budget
/// négatif vient de créer sous le plus ancien segment), jamais le niveau 0, où l'ingestion dépose.
pub(crate) fn retrait_des_niveaux_vides(bloc: &[u8], conserves: i64) -> Result<Option<(Vec<u8>, i64, i64)>, &'static str> {
    let forme = STRUCTURE_DE_FORME_INCONNUE;
    if bloc.len() < 6 {
        return Err(forme);
    }
    let (n_niveaux, apres_niveaux) = varint(bloc, 4).ok_or(forme)?;
    let (n_segments, i) = varint(bloc, apres_niveaux).ok_or(forme)?;
    let (_compteur, fin_entete) = varint(bloc, i).ok_or(forme)?;
    // Aucune allocation ni multiplication sur les nombres lus : un nombre faux (énorme) épuise
    // l'enregistrement au premier varint manquant, et la lecture s'arrête là.
    let mut niveaux: Vec<(usize, usize, u64)> = Vec::new();
    let mut total = 0u64;
    let mut i = fin_entete;
    for _ in 0..n_niveaux {
        let debut = i;
        let (en_fusion, j) = varint(bloc, i).ok_or(forme)?;
        let (n_seg, mut j) = varint(bloc, j).ok_or(forme)?;
        if en_fusion > n_seg {
            return Err(forme);
        }
        for _ in 0..n_seg {
            for _ in 0..3 {
                j = varint(bloc, j).ok_or(forme)?.1;
            }
        }
        niveaux.push((debut, j, n_seg));
        total = total.saturating_add(n_seg);
        i = j;
    }
    if i != bloc.len() || total != n_segments {
        return Err(forme);
    }
    let avant = niveaux.len() as i64;
    let mut garde = vec![true; niveaux.len()];
    let mut restants = avant;
    for k in (1..niveaux.len()).rev() {
        if restants <= conserves {
            break;
        }
        if niveaux[k].2 == 0 {
            garde[k] = false;
            restants -= 1;
        }
    }
    if restants == avant {
        return Ok(None);
    }
    let mut neuf = Vec::with_capacity(bloc.len());
    neuf.extend_from_slice(&bloc[..4]);
    ecrire_varint(restants as u64, &mut neuf);
    neuf.extend_from_slice(&bloc[apres_niveaux..fin_entete]);
    for (k, &(debut, fin, _)) in niveaux.iter().enumerate() {
        if garde[k] {
            neuf.extend_from_slice(&bloc[debut..fin]);
        }
    }
    Ok(Some((neuf, avant, restants)))
}

/// LE RETRAIT, ÉCRIT : relit l'enregistrement, le réécrit sans ses niveaux vides excédentaires, puis
/// FAIT DÉCODER le résultat par FTS5 lui-même avant de valider. Rend (niveaux avant, niveaux après),
/// `None` s'il n'y avait rien à retirer, ou la cause du refus — et dans ce cas l'enregistrement est
/// celui d'avant (transaction annulée).
///
/// LA SONDE. `INSERT INTO <nom>(<nom>, rank) VALUES('merge', 0)` passe par `sqlite3Fts5IndexMerge`
/// (sqlite3.c:237359) : il LIT et DÉCODE la structure, VIDE le cache de structure de la connexion
/// (`fts5StructureInvalidate`, sqlite3.c:237363), puis `fts5IndexMerge` sort aussitôt d'un budget nul
/// (sqlite3.c:236973, `while( nRem>0 …`) sans rien écrire. Un enregistrement que le moteur refuse fait
/// échouer la sonde, et la transaction est annulée.
///
/// ELLE EST JOUÉE DEUX FOIS, ET LA PREMIÈRE N'EST PAS UNE REDITE. FTS5 garde la structure décodée par
/// connexion (`p->pStruct`) et ne la relit du disque que si `PRAGMA data_version` a bougé
/// (sqlite3.c:239344) — ce qui n'arrive pas pour une écriture de la MÊME connexion. Une sonde jouée
/// sur un cache plein validerait donc l'ancienne structure, pas celle qu'on vient d'écrire. La
/// première sonde, AVANT la réécriture, vide ce cache ; la seconde, après, décode ce qui est sur le
/// disque. Les autres connexions voient `data_version` changer et relisent.
pub(crate) fn retirer_les_niveaux_vides(conn: &Connection, nom: &str) -> Result<Option<(i64, i64)>, String> {
    // LA LECTURE EST FAITE SOUS LE VERROU D'ÉCRITURE, jamais avant : un autre écrivain (la sous-commande
    // `fts-compact` à côté du démon, par exemple) qui déposerait un segment entre une lecture libre et la
    // réécriture verrait ce segment effacé de la structure, ses pages orphelines.
    // La forme commune d'ouverture (`BEGIN IMMEDIATE`) : un refus est dit au journal `[fts-compact]` avec sa cause
    // (verrou tenu ailleurs, transaction étrangère, refus hors verrou) et compté.
    crate::handlers::transaction_validee::ouvrir_sa_transaction(conn, "fts-compact", "retrait des niveaux vides")
        .map_err(|e| format!("transaction du retrait non ouverte ({e})"))?;
    match retirer_dans_la_transaction(conn, nom) {
        Ok(None) => match conn.execute_batch("ROLLBACK") {
            Ok(()) => Ok(None),
            Err(e) => Err(annuler_le_retrait(conn, format!("rien à retirer, transaction non refermée ({e})"))),
        },
        Ok(Some(niveaux)) => match conn.execute_batch("COMMIT") {
            Ok(()) => Ok(Some(niveaux)),
            Err(e) => Err(annuler_le_retrait(conn, format!("retrait non validé ({e})"))),
        },
        Err(cause) => Err(annuler_le_retrait(conn, cause)),
    }
}

/// Le corps du retrait, DANS la transaction ouverte par `retirer_les_niveaux_vides` : lecture, découpage,
/// première sonde, réécriture, seconde sonde. Rien n'y est validé ni annulé.
fn retirer_dans_la_transaction(conn: &Connection, nom: &str) -> Result<Option<(i64, i64)>, String> {
    let bloc: Vec<u8> = conn
        .query_row(&format!("SELECT block FROM {nom}_data WHERE id=10"), [], |r| r.get(0))
        .map_err(|e| format!("structure non relue ({e})"))?;
    point_de_test(PointDeTest::ApresLaLectureDuRetrait, conn);
    let Some((neuf, avant, apres)) = retrait_des_niveaux_vides(&bloc, NIVEAUX_CONSERVES).map_err(str::to_string)? else {
        return Ok(None);
    };
    let sonde = format!("INSERT INTO {nom}({nom}, rank) VALUES('merge', 0)");
    conn.execute(&sonde, []).map_err(|e| format!("cache de structure de FTS5 non vidé ({e})"))?;
    conn.execute(&format!("UPDATE {nom}_data SET block=?1 WHERE id=10"), params![neuf])
        .map_err(|e| format!("structure non réécrite ({e})"))?;
    conn.execute(&sonde, []).map_err(|e| format!("structure réécrite REFUSÉE par FTS5 ({e})"))?;
    Ok(Some((avant, apres)))
}

/// L'ANNULATION, dite avec l'état RELU : une annulation refusée laisse la connexion en transaction, et
/// la phrase le dit au lieu de le supposer.
fn annuler_le_retrait(conn: &Connection, cause: String) -> String {
    match conn.execute_batch("ROLLBACK") {
        Ok(()) => format!("{cause} ; transaction annulée, structure d'avant conservée"),
        Err(e) => format!(
            "{cause} ; ANNULATION REFUSÉE ({e}) — connexion encore en transaction : {}",
            if conn.is_autocommit() { "non" } else { "OUI" }
        ),
    }
}

/// Les OCTETS DE PAGES du shadow `<nom>_data` — la grandeur dont parle le constat. `dbstat` contraint
/// sur `name` ne parcourt QUE ce b-tree : mesuré 0,25 s à froid et 0,03 s à chaud sur un index de
/// 185 Mio, contre 1,04 s pour un `dbstat` complet. C'est ce qui rend un rapport avant/après payable à
/// chaque tick.
///
/// `SUM(length(block))` aurait coûté 0,005 s mais aurait MENTI de 12 % (170,9 Mio de charge utile
/// contre 194,7 Mio de pages) : ce n'est pas ce que la base occupe.
pub(crate) fn octets_index(conn: &Connection, nom: &str) -> Option<i64> {
    conn.query_row("SELECT COALESCE(SUM(pgsize),0) FROM dbstat WHERE name=?1", params![format!("{nom}_data")], |r| r.get(0))
        .ok()
}

/// Le nombre de documents VIVANTS. `<nom>_docsize` porte une ligne par document — elle n'existe que si
/// `columnsize=1` (le défaut, et le cas de `event_fts`). Absente -> `None`, et le rapport ÉCRIT « non
/// mesurés » : un filtre qui ne rend rien se lit « je n'ai pas mesuré », jamais « zéro ».
pub(crate) fn documents(conn: &Connection, nom: &str) -> Option<i64> {
    conn.query_row(&format!("SELECT COUNT(*) FROM {nom}_docsize"), [], |r| r.get(0)).ok()
}

// =================================================================================================
// LA COMPACTION
// =================================================================================================

/// Compacte UN index, par passes BORNÉES, en RELÂCHANT le verrou d'écriture entre chacune.
///
/// LE BUDGET EST NÉGATIF : c'est le seul chemin du moteur qui fusionne des segments de niveaux
/// DIFFÉRENTS, donc le seul qui atteigne le plancher (cf. l'en-tête du module). Avec `-N`, FTS5 prend
/// son chemin d'`optimize` borné à N pages écrites.
///
/// ET CHAQUE PASSE EST SUIVIE DU RETRAIT DES NIVEAUX VIDES : le chemin d'`optimize` ajoute des niveaux
/// que le moteur ne retire jamais (cf. l'en-tête), et c'est ce retrait qui borne leur nombre.
///
/// LA GARDE, AVANT CHAQUE PASSE : la structure est relue sous le verrou de la passe ; au-delà de
/// `SEUIL_NIVEAUX`, la passe n'est pas lancée. À l'entrée, cela rend `NiveauxAuSeuil` sans rien
/// écrire ; en cours de séquence, l'arrêt `NiveauxAuSeuil`.
///
/// Le verrou est pris et rendu PAR PASSE (modèle `chunked_purge` / `reconcile_expr_indexes_background`),
/// jamais tenu sur la séquence : mesuré, une passe à 500 pages tient le writer ~1 s, quelle que soit la
/// taille de l'index. Une passe interrompue est perdue ; toutes les précédentes sont COMMITTÉES et la
/// reprise converge au même octet (prouvé par SIGKILL, cf. l'en-tête du module).
pub(crate) fn compacter_index(db: &Arc<Mutex<Connection>>, nom: &str, r: &Reglage) -> Issue {
    let debut = Instant::now();
    // Sonde d'entrée : structure + tailles, sous un verrou COURT. Si FTS5 lui-même n'a rien à
    // fusionner, on ne lance AUCUNE passe et on le DIT.
    let (st0, oct0, docs) = {
        let conn = db.lock();
        (structure(&conn, nom), octets_index(&conn, nom), documents(&conn, nom))
    };
    let (Some(st0), Some(oct0)) = (st0, oct0) else {
        return Issue::Echec {
            nom: nom.into(),
            message: "structure FTS5 ou dbstat illisible — aucune fusion tentée".into(),
        };
    };
    if st0.niveaux > SEUIL_NIVEAUX {
        return Issue::NiveauxAuSeuil { nom: nom.into(), niveaux: st0.niveaux };
    }
    if st0.segments < 2 {
        return Issue::DejaCompact { nom: nom.into(), octets: oct0 };
    }

    let sql = format!("INSERT INTO {nom}({nom}, rank) VALUES('merge', ?1)");
    let budget = -r.pages; // NÉGATIF : cf. supra. Le seul incrémental qui atteigne le plancher.
    let mut passes = 0i64;
    let mut courante = st0;
    let arret = loop {
        if courante.segments < 2 {
            break Arret::Convergee;
        }
        if passes >= r.passes {
            break Arret::BudgetEpuise;
        }
        let sortie = {
            let conn = db.lock();
            let sortie = match structure(&conn, nom) {
                None => Some(Arret::StructureIllisible),
                Some(s) if s.niveaux > SEUIL_NIVEAUX => Some(Arret::NiveauxAuSeuil { niveaux: s.niveaux }),
                Some(_) => match conn.execute(&sql, params![budget]) {
                    // Une passe qui échoue n'invalide PAS les précédentes : chacune a committé, leurs
                    // octets sont RÉELS. Mais l'erreur est PORTÉE — elle ne se déguise pas en budget épuisé.
                    Err(e) => Some(Arret::Erreur(e.to_string())),
                    Ok(_) => {
                        passes += 1;
                        // La structure est relue SOUS LE MÊME verrou que la passe : c'est la seule lecture
                        // qui décrive à coup sûr l'état que cette passe vient de committer. Le retrait suit,
                        // toujours sous ce verrou, quand le cache de structure de FTS5 vient d'être vidé.
                        match structure(&conn, nom) {
                            None => Some(Arret::StructureIllisible),
                            Some(s) => {
                                courante = s;
                                match retirer_les_niveaux_vides(&conn, nom) {
                                    Err(cause) => Some(Arret::NiveauxNonRetires(cause)),
                                    Ok(Some((_, apres))) => {
                                        courante.niveaux = apres;
                                        None
                                    }
                                    Ok(None) => None,
                                }
                            }
                        }
                    }
                },
            };
            point_de_test(PointDeTest::EntreLesPasses, &conn);
            sortie
        };
        if let Some(a) = sortie {
            break a;
        }
        // RESPIRATION : verrou relâché, l'ingestion et les lectures passent (anti-famine writer).
        if courante.segments >= 2 && passes < r.passes && r.repos_ms > 0 {
            std::thread::sleep(Duration::from_millis(r.repos_ms));
        }
    };

    let oct1 = { let conn = db.lock(); octets_index(&conn, nom).unwrap_or(oct0) };
    Issue::Rendue {
        nom: nom.into(),
        octets_avant: oct0,
        octets_apres: oct1,
        segments_avant: st0.segments,
        segments_apres: courante.segments,
        niveaux_avant: st0.niveaux,
        niveaux_apres: courante.niveaux,
        docs,
        passes,
        duree_ms: debut.elapsed().as_millis(),
        arret,
    }
}

/// LE POINT D'ENTRÉE. Rend UNE issue PAR index — jamais un booléen, jamais rien. L'appelant journalise ;
/// les tests, eux, lisent les octets.
pub(crate) fn compacter(db: &Arc<Mutex<Connection>>, conf: &HashMap<String, String>) -> Vec<Issue> {
    let r = Reglage::depuis(conf);
    if !r.actif {
        return vec![Issue::Desactivee];
    }
    let noms = { let conn = db.lock(); index_plein_texte(&conn) };
    if noms.is_empty() {
        return vec![Issue::AucunIndex];
    }
    noms.iter().map(|n| compacter_index(db, n, &r)).collect()
}

/// Compacte ET journalise — la forme appelée par la rétention et par la sous-commande. Le journal est
/// le SEUL endroit où l'issue devient une phrase : il n'existe pas de chemin qui imprime « fait » sans
/// passer par `Issue::phrase()`.
pub(crate) fn compacter_et_journaliser(db: &Arc<Mutex<Connection>>, conf: &HashMap<String, String>) -> Vec<Issue> {
    let issues = compacter(db, conf);
    for i in &issues {
        eprintln!("{}", i.phrase());
    }
    issues
}

// =================================================================================================
// LA SANTÉ — les niveaux de chaque index, lus en une ligne par index
// =================================================================================================

/// LES NIVEAUX DE CHAQUE INDEX PLEIN-TEXTE, pour la surface d'état. Une ligne par index (`%_data`
/// rowid 10), aucun verrou tenu au-delà de ces lectures. Le nombre servi est celui de l'en-tête, SANS
/// la borne du moteur : un index déjà au-delà de `LIMITE_DU_MOTEUR` se lit ici avec son vrai nombre.
/// Le catalogue non lu, une structure non lue ou de forme inconnue rendent la mesure ILLISIBLE, avec la
/// cause et l'index nommés — jamais zéro niveau.
pub(crate) fn niveaux_des_index(conn: &Connection) -> crate::mesure_environnement::Mesure<Vec<(String, i64)>> {
    use crate::mesure_environnement::{Mesure, CAUSE_FORME_INCONNUE, CAUSE_SOURCE_ILLISIBLE};
    let illisible = |cause: &'static str, detail: String| Mesure::Illisible { cause, detail };
    let noms: Result<Vec<String>, rusqlite::Error> = conn
        .prepare(
            "SELECT name FROM sqlite_master WHERE type='table' \
               AND lower(sql) LIKE 'create virtual table%' AND lower(sql) LIKE '%using fts5%' ORDER BY name",
        )
        .and_then(|mut st| st.query_map([], |r| r.get::<_, String>(0))?.collect());
    let noms = match noms {
        Ok(n) => n,
        Err(e) => return illisible(CAUSE_SOURCE_ILLISIBLE, format!("catalogue des index plein-texte non lu ({e})")),
    };
    let mut lus = Vec::with_capacity(noms.len());
    for nom in noms.into_iter().filter(|n| soql_ident_ok(n)) {
        let bloc: Vec<u8> = match conn.query_row(&format!("SELECT block FROM {nom}_data WHERE id=10"), [], |r| r.get(0)) {
            Ok(b) => b,
            Err(e) => return illisible(CAUSE_SOURCE_ILLISIBLE, format!("structure de `{nom}` non lue ({e})")),
        };
        match entete_de_structure(&bloc) {
            Some(s) => lus.push((nom, s.niveaux)),
            None => return illisible(CAUSE_FORME_INCONNUE, format!("structure de `{nom}` de forme inconnue")),
        }
    }
    Mesure::Lue(lus)
}

/// L'ÉTAT DU COMPOSANT `store` APRÈS LES NIVEAUX : il ne peut que DESCENDRE (`metrics::pire_des_deux`).
/// Au-delà de `LIMITE_DU_MOTEUR` : rouge, l'index ne se lit plus. Au-delà de `NIVEAUX_D_ALERTE` :
/// jaune. Une mesure illisible : jaune. Chaque index en cause ajoute sa phrase au détail ; sinon l'état
/// et le détail reviennent tels quels.
pub(crate) fn etat_de_surface_niveaux(
    etat: &'static str,
    detail: String,
    mesure: &crate::mesure_environnement::Mesure<Vec<(String, i64)>>,
) -> (&'static str, String) {
    use crate::mesure_environnement::Mesure;
    match mesure {
        Mesure::Illisible { detail: d, .. } => (
            crate::metrics::pire_des_deux(etat, "yellow"),
            format!(
                "{detail} ; niveaux de l'index plein-texte NON LUS ({d}) : impossible de dire si une structure approche la \
                 limite du moteur ({LIMITE_DU_MOTEUR} niveaux)"
            ),
        ),
        Mesure::Lue(lus) => {
            let mut etat = etat;
            let mut detail = detail;
            for (nom, niveaux) in lus {
                if *niveaux > LIMITE_DU_MOTEUR {
                    etat = crate::metrics::pire_des_deux(etat, "red");
                    detail = format!(
                        "{detail} ; `{nom}` : {niveaux} niveaux, AU-DELÀ de la limite du moteur ({LIMITE_DU_MOTEUR}) : l'index \
                         ne se lit plus et toute insertion échoue ; {}",
                        remede_au_dela_de_la_limite()
                    );
                } else if *niveaux > NIVEAUX_D_ALERTE {
                    etat = crate::metrics::pire_des_deux(etat, "yellow");
                    detail = format!(
                        "{detail} ; `{nom}` : {niveaux} niveaux dans la structure de l'index plein-texte (alerte au-delà de \
                         {NIVEAUX_D_ALERTE}, compaction suspendue au-delà de {SEUIL_NIVEAUX}, illisible au-delà de \
                         {LIMITE_DU_MOTEUR}) ; {}",
                        remede(nom)
                    );
                }
            }
            (etat, detail)
        }
    }
}

/// LE CHAMP `fts_levels` : le PLUS GRAND nombre de niveaux des index, avec le verdict de la lecture
/// (posé par `Mesure::poser_dans`, comme ses voisins). Sans aucun index, un vrai zéro.
pub(crate) fn plus_grand_nombre_de_niveaux(
    mesure: &crate::mesure_environnement::Mesure<Vec<(String, i64)>>,
) -> crate::mesure_environnement::Mesure<i64> {
    use crate::mesure_environnement::Mesure;
    match mesure {
        Mesure::Lue(lus) => Mesure::Lue(lus.iter().map(|(_, n)| *n).max().unwrap_or(0)),
        Mesure::Illisible { cause, detail } => Mesure::Illisible { cause, detail: detail.clone() },
    }
}

/// LE CHAMP `fts_levels_by_index` : chaque index et son nombre de niveaux, posé SEULEMENT quand la
/// mesure a été lue (illisible, il est absent et `fts_levels_verdict` dit pourquoi).
pub(crate) fn poser_les_niveaux_par_index(
    objet: &mut serde_json::Map<String, Value>,
    mesure: &crate::mesure_environnement::Mesure<Vec<(String, i64)>>,
) {
    if let crate::mesure_environnement::Mesure::Lue(lus) = mesure {
        let par_index: serde_json::Map<String, Value> = lus.iter().map(|(n, v)| (n.clone(), json!(v))).collect();
        objet.insert("fts_levels_by_index".into(), Value::Object(par_index));
    }
}

// =================================================================================================
// LES POINTS DE TEST — vides en production, crochets sous test (module en fin de fichier)
// =================================================================================================

/// Où un témoin peut agir : sous le verrou de chaque passe, après elle et son retrait ; dans la
/// transaction du retrait, juste après la lecture de la structure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PointDeTest {
    EntreLesPasses,
    ApresLaLectureDuRetrait,
}

#[cfg(not(test))]
#[inline(always)]
fn point_de_test(_point: PointDeTest, _conn: &Connection) {}

#[cfg(test)]
fn point_de_test(point: PointDeTest, conn: &Connection) {
    crochet_de_compaction::passer(point, conn);
}

/// Instrument de TEST seulement. PAR FIL (la compaction tourne sur le fil du témoin) : il permet à un
/// témoin d'agir EXACTEMENT à l'un des `PointDeTest`.
#[cfg(test)]
pub(crate) mod crochet_de_compaction {
    use super::PointDeTest;
    use rusqlite::Connection;
    use std::cell::RefCell;

    type Crochet = Box<dyn FnMut(&Connection)>;

    thread_local! {
        static ARME: RefCell<Option<(PointDeTest, Crochet)>> = RefCell::new(None);
    }

    pub(crate) fn armer(point: PointDeTest, f: Crochet) {
        ARME.with(|a| *a.borrow_mut() = Some((point, f)));
    }

    pub(crate) fn desarmer() {
        ARME.with(|a| *a.borrow_mut() = None);
    }

    pub(crate) fn passer(point: PointDeTest, conn: &Connection) {
        ARME.with(|a| {
            if let Some((p, f)) = a.borrow_mut().as_mut() {
                if *p == point {
                    f(conn);
                }
            }
        });
    }
}

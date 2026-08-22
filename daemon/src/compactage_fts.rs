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
//! vit dans `backup/mod.rs`, sur le chemin de RESTAURATION). Le poids mort ne pouvait donc que s'accumuler,
//! purge après purge — c'est ce qui explique que la part FTS soit passée de 8,1 % (banc) à 18,9 % (prod)
//! sans croissance organique correspondante.
//!
//! ─────────────────────────────────────────────────────────────────────────────────────────────────
//! POURQUOI `merge` BORNÉ ET NON `optimize` — L'ARBITRAGE, MESURÉ, PAS SUPPOSÉ
//!
//! Les deux commandes atteignent LE MÊME PLANCHER. Ce qui les sépare, c'est ce qu'elles coûtent au
//! reste du système pendant qu'elles y vont. Mesuré sur la base ci-dessus (499 200 documents restants,
//! index gonflé à 185,69 Mio), chaque bras partant d'une COPIE OCTET-À-OCTET du même état :
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
//! 1. **`merge` avec un N POSITIF ne rend RIEN sur cet index, et le fait instantanément.** FTS5 ne
//!    fusionne alors qu'un niveau portant au moins `usermerge` segments (défaut 4) ; ici les 15 segments
//!    sont répartis sur 9 niveaux, aucun n'atteint le quota, et FTS5 répond « rien à faire » en 0,00 s.
//!    Un opérateur qui aurait câblé `merge=N` positif aurait une compaction qui S'ANNONCE et rend
//!    EXACTEMENT ZÉRO — précisément la famille de défaut que ce dépôt ferme. C'est pourquoi le budget
//!    est passé **NÉGATIF** : `nMerge<0` fait prendre à FTS5 le chemin de l'`optimize` (toutes les
//!    segments promus, `nMin=1`) mais BORNÉ à |N| pages écrites (cf. `fts5IndexMerge`/
//!    `fts5IndexOptimizeStruct` dans l'amalgamation vendorée). C'est un `optimize` INCRÉMENTAL, et
//!    c'est le seul incrémental qui atteint le plancher.
//! 2. **Le plancher est le MÊME** : 56,53 Mio en incrémental contre 56,56 Mio d'un coup (écart 0,05 %).
//!    Un incrémental qui n'atteindrait jamais le plancher ne vaudrait pas mieux qu'une rafale ; celui-ci
//!    l'atteint.
//! 3. **Le verrou d'écriture et la rafale WAL sont fixés par N, PAS par la taille de l'index.** Vérifié
//!    au DOUBLE du volume (2 400 000 événements ingérés, 998 400 restants, index gonflé à 370,7 Mio —
//!    plus gros que la production) : à `merge=-500`, la pire passe vaut **0,907 s** et le pic WAL
//!    **15,4 Mio**, contre 1,037 s et 13,4 Mio à la moitié du volume. Seul le NOMBRE de passes suit la
//!    taille (48 contre 25). C'est la propriété qui rend la chose déployable sur un nœud à 2 Gio : la
//!    dépense par prise de verrou ne grandit pas avec la base.
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
//!    sur DISQUE : 192,6 Mio d'un coup pour l'`optimize`, 13,4 Mio pour `merge=-500`. Le budget 2 Gio
//!    de RAM n'est menacé par aucun des deux ; l'espace disque du volume l'est par le premier.
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
        docs: Option<i64>,
        passes: i64,
        duree_ms: u128,
        arret: Arret,
    },
    /// SQLite a refusé AVANT la première passe. AUCUN octet n'est annoncé — on ne sait rien.
    Echec { nom: String, message: String },
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
            Issue::Rendue { nom, octets_avant, octets_apres, segments_avant, segments_apres, docs, passes, duree_ms, arret } => {
                let rendus = octets_avant - octets_apres;
                let pct = if *octets_avant > 0 { rendus as f64 * 100.0 / *octets_avant as f64 } else { 0.0 };
                format!(
                    "[fts-compact] {nom} : {:.2} -> {:.2} Mio ({} octets rendus à la freelist, {pct:.1} %) | \
                     segments {segments_avant} -> {segments_apres} | docs {} | {passes} passe(s) en {duree_ms} ms | {}",
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
                    }
                )
            }
            Issue::Echec { nom, message } => format!(
                "[fts-compact] {nom} ÉCHEC ({message}) — AUCUN octet annoncé, l'état de l'index n'est pas connu ; nouvel essai au prochain tick"
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
    let bloc: Vec<u8> = conn
        .query_row(&format!("SELECT block FROM {nom}_data WHERE id=10"), [], |r| r.get(0))
        .ok()?;
    if bloc.len() < 6 {
        return None;
    }
    let (_niveaux, i) = varint(&bloc, 4)?;
    let (nb, _) = varint(&bloc, i)?;
    i64::try_from(nb).ok()
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
/// LE BUDGET EST NÉGATIF, ET C'EST TOUT LE CORRECTIF. `merge` avec un N positif ne fusionne qu'un
/// niveau portant au moins `usermerge` segments — mesuré : sur l'index gonflé du constat, il rend
/// EXACTEMENT ZÉRO octet en 0,00 s. Avec `-N`, FTS5 prend son chemin d'`optimize` (tous les segments
/// promus, `nMin=1`) borné à N pages écrites : même plancher que `optimize`, par tranches.
///
/// Le verrou est pris et rendu PAR PASSE (modèle `chunked_purge` / `reconcile_expr_indexes_background`),
/// jamais tenu sur la séquence : mesuré, une passe à 500 pages tient le writer ~1 s, quelle que soit la
/// taille de l'index. Une passe interrompue est perdue ; toutes les précédentes sont COMMITTÉES et la
/// reprise converge au même octet (prouvé par SIGKILL, cf. l'en-tête du module).
pub(crate) fn compacter_index(db: &Arc<Mutex<Connection>>, nom: &str, r: &Reglage) -> Issue {
    let debut = Instant::now();
    // Sonde d'entrée : structure + tailles, sous un verrou COURT. Si FTS5 lui-même n'a rien à
    // fusionner, on ne lance AUCUNE passe et on le DIT.
    let (seg0, oct0, docs) = {
        let conn = db.lock();
        (segments(&conn, nom), octets_index(&conn, nom), documents(&conn, nom))
    };
    let (Some(seg0), Some(oct0)) = (seg0, oct0) else {
        return Issue::Echec {
            nom: nom.into(),
            message: "structure FTS5 ou dbstat illisible — aucune fusion tentée".into(),
        };
    };
    if seg0 < 2 {
        return Issue::DejaCompact { nom: nom.into(), octets: oct0 };
    }

    let sql = format!("INSERT INTO {nom}({nom}, rank) VALUES('merge', ?1)");
    let budget = -r.pages; // NÉGATIF : cf. supra. Le seul incrémental qui atteigne le plancher.
    let mut passes = 0i64;
    let mut seg = seg0;
    let arret = loop {
        if seg < 2 {
            break Arret::Convergee;
        }
        if passes >= r.passes {
            break Arret::BudgetEpuise;
        }
        let sortie = {
            let conn = db.lock();
            match conn.execute(&sql, params![budget]) {
                // Une passe qui échoue n'invalide PAS les précédentes : chacune a committé, leurs
                // octets sont RÉELS. Mais l'erreur est PORTÉE — elle ne se déguise pas en budget épuisé.
                Err(e) => Some(Arret::Erreur(e.to_string())),
                Ok(_) => {
                    passes += 1;
                    // La structure est relue SOUS LE MÊME verrou que la passe : c'est la seule lecture
                    // qui décrive à coup sûr l'état que cette passe vient de committer.
                    match segments(&conn, nom) {
                        Some(s) => {
                            seg = s;
                            None
                        }
                        None => Some(Arret::StructureIllisible),
                    }
                }
            }
        };
        if let Some(a) = sortie {
            break a;
        }
        // RESPIRATION : verrou relâché, l'ingestion et les lectures passent (anti-famine writer).
        if seg >= 2 && passes < r.passes && r.repos_ms > 0 {
            std::thread::sleep(Duration::from_millis(r.repos_ms));
        }
    };

    let oct1 = { let conn = db.lock(); octets_index(&conn, nom).unwrap_or(oct0) };
    Issue::Rendue {
        nom: nom.into(),
        octets_avant: oct0,
        octets_apres: oct1,
        segments_avant: seg0,
        segments_apres: seg,
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

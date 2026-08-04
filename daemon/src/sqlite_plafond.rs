//! LE PLAFOND MÉMOIRE D'UNE LECTURE — ce qui empêche UNE requête d'emporter TOUT le processus.
//!
//! LE DÉFAUT QU'IL FERME, MESURÉ. Banc de 3 648 003 événements (`ops/.bench-10m`), un daemon NEUF par
//! cellule — le RSS est un CLIQUET, donc dans un daemon partagé la « crête » d'une requête n'est que le
//! plateau laissé par la précédente et rien n'est attribuable —, `interactive:true` et budget de requête
//! porté à 600 s : un budget de 5 s COUPE AVANT LA CRÊTE et rend un chiffre rassurant et faux.
//! Delta de RSS attribuable à UNE requête, sur la fenêtre entière :
//!
//!     search | stats dc(message)                                     +948,9 Mio
//!     search | stats count by action,source | sort -count | head 50   +853,3 Mio
//!     search | stats count by host,severity                          +322,5 Mio
//!
//! Croissance LINÉAIRE en lignes BALAYÉES (61 à 273 o/ligne selon la forme, R² ≥ 0,94), jamais rendue au
//! système. Sous les 2 Gio de production, enchaîner ces formes TUE le daemon (OOM-kill du cgroup) : ce
//! sont TOUTES les sessions qui tombent, pas la requête fautive.
//!
//! LA CAUSE, ÉTABLIE PAR LECTURE DE SQLITE (`sqlite3.c` 3.39.4 vendoré, SQLCipher 4.5.3) — trois faits
//! qui se chaînent, et c'est le troisième qui décide :
//!   1. `sqlite3TempInMemory(db)` rend `db->temp_store != 1`. SEUL `PRAGMA temp_store=FILE` (valeur 1)
//!      le met à FAUX. `MEMORY` (2) le laisse vrai — et le DÉFAUT DE COMPILATION aussi : ce binaire porte
//!      `SQLITE_TEMP_STORE=2`, donc une connexion qui ne dit RIEN trie en mémoire. Le silence est le cas
//!      dangereux, pas un réglage explicite.
//!   2. `sqlite3VdbeSorterInit` ne renseigne `pSorter->mxPmaSize` QUE dans la branche
//!      `if( !sqlite3TempInMemory(db) )`. Ailleurs il reste 0 (la structure est allouée à zéro).
//!   3. `sqlite3VdbeSorterWrite` enferme TOUT le calcul de déversement dans `if( pSorter->mxPmaSize )`.
//!   ⇒ Sous `temp_store` en mémoire, il n'existe AUCUN CHEMIN DE CODE qui déverse un tri : le trieur
//!     matérialise un enregistrement par ligne balayée jusqu'à épuisement de la RAM. Ce n'était pas un
//!     réglage trop généreux, c'était une ABSENCE DE MÉCANISME — et c'est pourquoi aucun réglage de
//!     TAILLE ne pouvait le corriger.
//!   ⇒ COROLLAIRE, la piste qu'il fallait RÉFUTER et non contourner : `soft_heap_limit` ne peut rien y
//!     faire. `sqlite3HeapNearlyFull()` n'est consulté que dans la branche `else` du bloc gardé en (3),
//!     jamais atteinte ici. SQLite ACCEPTE le réglage et ne déclenche RIEN sur un trieur.
//!   La MÊME bascule commande les B-trees ÉPHÉMÈRES : `OP_OpenEphemeral` ouvre un btree
//!   `SQLITE_OPEN_TRANSIENT_DB` dont le support est la RAM ou un fichier selon exactement le même
//!   `sqlite3TempInMemory`. C'est ce qui borne `dc(x)`, `DISTINCT`, et les listes `IN` matérialisées.
//!
//! CE QUE CE MODULE POSE — DEUX RÉGLAGES QUI NE JOUENT PAS LE MÊME RÔLE, et les confondre mène tout droit
//! à la conclusion fausse « FILE ralentit tout » :
//!   * `temp_store=FILE` est l'INTERRUPTEUR D'EXISTENCE du plafond, PAS un ralentisseur global : tant que
//!     le tri tient sous le budget, `bFlush` est FAUX à chaque ligne — AUCUN octet n'est écrit, aucune
//!     fusion n'a lieu. Le prix n'est payé QUE par les tris qui DÉPASSENT le budget. (L'accumulation ne
//!     suit pas exactement le même code des deux côtés : en mémoire, un `sqlite3Malloc` PAR
//!     ENREGISTREMENT ; en fichier, un tampon unique qui DOUBLE jusqu'au budget. C'est mesuré cellule par
//!     cellule au banc, dans les deux sens, plutôt que supposé.)
//!   * `cache_size` est la VALEUR du plafond. SQLite le lit DEUX FOIS, pour deux choses différentes : le
//!     cache de pages du pager, ET — via `mxPmaSize = MAX(250 × page_size, |cache_size| × 1024)`, borné
//!     par `SQLITE_MAX_PMASZ` (512 Mio) — le budget RAM du trieur avant déversement. SQLite n'offre aucun
//!     moyen de séparer ces deux usages : les dimensionner, c'est arbitrer entre les deux d'un seul geste.
//!
//! LA DÉRIVATION, PARCE QU'UNE CONSTANTE POSÉE À CÔTÉ D'UNE AUTRE FINIT PAR MENTIR. Le plafond total n'est
//! pas `cache_size`, c'est `cache_size × nombre de porteurs simultanés`, et il y a deux familles de
//! porteurs qui ne se comptent pas pareil :
//!   - une CONNEXION VIVANTE porte son cache de pages entre deux requêtes -> `READ_POOL_CAP` connexions
//!     idle du pool, plus les connexions hors pool (l'écrivain du daemon, la connexion de rollup) ;
//!   - un TRI EN VOL porte son propre tampon -> bornés par les sémaphores (`PLUME_QUERY_CONCURRENCY` +
//!     `PLUME_PANEL_REFRESH_CONCURRENCY`), plus les mêmes connexions hors pool.
//! D'où `cache = budget / porteurs`. Écrire `-65536` en dur à côté d'un `READ_POOL_CAP = 8` qu'un autre
//! fichier peut changer, c'est exactement la faute payée ici : les deux valeurs ne se parlaient pas.
//! Doubler le pool DIVISE maintenant le cache — le budget tient sans que personne ait à s'en souvenir.
//!
//! LE DÉFAUT NE CHANGE RIEN AU DIMENSIONNEMENT, ET C'EST VOULU. `BUDGET_DEFAUT_MO` n'est pas CHOISI, il est
//! CONSTATÉ : c'est ce que la configuration actuelle consomme au pire (`17 × 64 Mio`), de sorte que
//! `cache_size` vaut exactement `-65536` comme avant. Le SEUL changement de comportement livré ici est
//! l'EXISTENCE du plafond — donc tout écart mesuré lui est attribuable. Ce que la dérivation apporte
//! immédiatement, c'est que ce pire cas a maintenant un NOM et un seul nombre pour le réduire.
//!
//! CE QUE CE MODULE NE FERME PAS, ÉCRIT POUR ÊTRE OPPOSABLE :
//!   - CONFIDENTIALITÉ. Un tri qui déverse écrit des VALEURS D'ÉVÉNEMENT EN CLAIR hors de la base
//!     SQLCipher. C'est un ÉCHANGE, pas un gain sec : avant, ces mêmes octets étaient en RAM et le
//!     processus mourait. Ce qui est fait : le répertoire est CHOISI (à côté de la base, `0700`, jamais un
//!     `/tmp` hérité) et SQLite DÉLIE le fichier aussitôt après l'avoir ouvert (`unixOpen` :
//!     `if( isDelete ) osUnlink(zName)`), donc il n'a aucun nom dans l'arborescence et disparaît à la
//!     fermeture, y compris si le processus meurt. Ce qui N'EST PAS fait : les octets touchent le
//!     périphérique. Un déploiement dont le modèle de menace inclut le vol du VOLUME doit poser
//!     `SQLITE_TMPDIR` sur un support chiffré — c'est respecté ici (cf. `repertoire_temporaire_init`),
//!     c'est une décision d'exploitation, et elle s'écrit dans la doc de déploiement.
//!   - AUCUN QUOTA ne borne la TAILLE du déversement : un tri sur une très grande fenêtre écrit l'ordre de
//!     grandeur des données triées. C'est du disque, pas de la RAM, c'est mesuré au banc, et rien ici
//!     n'empêche de remplir le volume.
//!   - `mmap_size` est conservé TEL QUEL (256 Mio). Son effet réel sous SQLCipher n'a pas été mesuré : il
//!     n'est ni revendiqué ni modifié ici.
use crate::*;

/// Budget RAM total concédé à SQLite (Mio). Le défaut REPRODUIT EXACTEMENT le dimensionnement d'avant —
/// `1088 = 17 × 64` — pour que le SEUL changement de comportement soit l'EXISTENCE du plafond, et donc
/// que tout écart mesuré lui soit attribuable. Ce n'est pas une cible, c'est un CONSTAT : c'est ce que la
/// configuration livrée consommait déjà au pire, sauf qu'auparavant rien ne l'y tenait. Le réduire est une
/// décision SÉPARÉE, qui se prend avec la courbe (mémoire, temps) publiée au banc.
const BUDGET_DEFAUT_MO: i64 = 1088;

/// Connexions HORS pool de lecture qui coexistent avec lui : l'écrivain du daemon (`server::tune`) et la
/// connexion de rollup (`rollups`). Chacune porte un cache de pages ET peut exécuter un tri — elle compte
/// donc dans les deux familles de porteurs.
const CONNEXIONS_HORS_POOL: i64 = 2;

/// Plancher du cache par porteur. En dessous, le cache de pages ne retient plus rien d'utile et chaque
/// requête re-déchiffre depuis le disque (SQLCipher). Le trieur, lui, a de toute façon son propre plancher
/// dans SQLite : `mnPmaSize = 250 × page_size`, soit ~1 Mio en pages de 4 Kio.
const CACHE_MIN_KO: i64 = 2048;

/// Sous-répertoire des temporaires SQLite, créé À CÔTÉ de la base : le déversement suit la donnée (même
/// volume, même dimensionnement, même surveillance de capacité) au lieu d'atterrir dans un `/tmp` hérité
/// — qui est un tmpfs sur la plupart des hôtes systemd, c'est-à-dire de la RAM comptée au MÊME cgroup :
/// le plafond y serait une ILLUSION.
const SOUS_REPERTOIRE_TEMP: &str = "sqltmp";

/// La formule, isolée pour être EXERCÉE (cf. tests) : sans ça, « le budget est dérivé » resterait une
/// affirmation de commentaire.
fn cache_ko_pour(budget_ko: i64, porteurs: i64) -> i64 {
    (budget_ko / porteurs.max(1)).max(CACHE_MIN_KO)
}

/// Le budget effectif, en Kio. `PLUME_SQLITE_BUDGET_MB` le redimensionne (env puis fichier de conf, même
/// ordre que tout le reste du daemon via `cfg`).
fn budget_ko() -> i64 {
    let conf = load_config();
    let mo: i64 = cfg(&conf, "PLUME_SQLITE_BUDGET_MB", &BUDGET_DEFAUT_MO.to_string())
        .parse()
        .unwrap_or(BUDGET_DEFAUT_MO);
    mo.max(1) * 1024
}

/// Le nombre de PORTEURS de mémoire SQLite simultanés — DÉRIVÉ des bornes qui existent déjà, jamais écrit
/// en dur : des CONNEXIONS VIVANTES (chacune son cache de pages) plus des TRIS EN VOL (chacun son tampon).
/// `.max(1)` reproduit la garde de `server::boot_config` sur les deux concurrences.
fn porteurs() -> i64 {
    let conf = load_config();
    porteurs_pour(
        cfg(&conf, "PLUME_QUERY_CONCURRENCY", "3").parse().unwrap_or(3).max(1),
        cfg(&conf, "PLUME_PANEL_REFRESH_CONCURRENCY", "2").parse().unwrap_or(2).max(1),
    )
}

/// Le comptage, isolé pour être EXERCÉ sans toucher à l'environnement du processus (un test qui mute
/// `std::env` empoisonne les tests qui tournent en parallèle — ça s'est déjà payé ailleurs).
fn porteurs_pour(interactif: i64, refresh: i64) -> i64 {
    let connexions = query_exec::READ_POOL_CAP as i64 + CONNEXIONS_HORS_POOL;
    let tris = interactif + refresh + CONNEXIONS_HORS_POOL;
    connexions + tris
}

/// LES PRAGMA DE MÉMOIRE — le seul endroit du daemon qui décide du budget RAM de SQLite. Calculés une
/// fois (le budget ne change pas en cours de vie du processus) et posés IDENTIQUEMENT sur toute connexion,
/// lecture comme écriture : un `GROUP BY` lancé sur la connexion d'écriture a le même trieur que sur une
/// connexion de lecture, donc le même besoin de plafond.
pub(crate) fn pragmas_memoire() -> &'static str {
    static P: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    P.get_or_init(|| {
        format!(
            "PRAGMA temp_store=FILE; PRAGMA mmap_size=268435456; PRAGMA cache_size={};",
            -cache_ko_pour(budget_ko(), porteurs())
        )
    })
}

/// CE QUE LE PLAFOND VAUT, EN CLAIR, POUR LE JOURNAL DE DÉMARRAGE. Un plafond qu'on ne peut pas LIRE en
/// exploitation n'est pas opposable : on publie le pire cas et de quoi il est le produit.
pub(crate) fn rapport() -> String {
    let (p, c) = (porteurs(), cache_ko_pour(budget_ko(), porteurs()));
    format!(
        "budget {} Mio = {} porteurs × {} Mio (cache_size={})",
        (p * c) / 1024,
        p,
        c / 1024,
        -c
    )
}

/// Le répertoire où SQLite déversera. DOIT être appelé AVANT le premier appel SQLite du processus :
/// `sqlite3_os_init()` lit `getenv("SQLITE_TMPDIR")` UNE SEULE FOIS, à l'initialisation de SQLite. D'où
/// l'appel unique en tête de `main`, avant tout branchement de sous-commande — un appel par sous-commande
/// serait une ÉNUMÉRATION, et c'est précisément ce genre de liste qui a déjà lâché dans ce dépôt.
///
/// SONDE VALIDÉE PAR CONTRÔLE POSITIF : on n'AFFIRME pas que le répertoire est utilisable, on y ÉCRIT un
/// octet et on le RELIT. Un répertoire créé mais non inscriptible (montage RO, quota, SELinux) rendrait un
/// plafond qui ne déverse pas — c'est-à-dire des requêtes qui ÉCHOUENT au lieu de ralentir.
///
/// Un `SQLITE_TMPDIR` posé EXPLICITEMENT par l'exploitant est RESPECTÉ (et seulement contrôlé) : c'est le
/// levier par lequel un déploiement place le déversement sur un support chiffré. On ne remplace que le
/// SILENCE — et le silence, ici, vaut `/tmp`.
pub(crate) fn repertoire_temporaire_init(db_path: &str) -> Result<std::path::PathBuf, String> {
    if let Ok(explicite) = std::env::var("SQLITE_TMPDIR") {
        if !explicite.trim().is_empty() {
            let dir = std::path::PathBuf::from(explicite);
            controle_positif(&dir)?;
            return Ok(dir);
        }
    }
    let base = std::path::Path::new(db_path)
        .parent()
        .ok_or_else(|| format!("chemin de base sans répertoire parent : {db_path}"))?;
    let dir = base.join(SOUS_REPERTOIRE_TEMP);
    std::fs::create_dir_all(&dir).map_err(|e| format!("création {} : {e}", dir.display()))?;
    // 0700 : les temporaires portent des valeurs d'événement EN CLAIR. SQLite les délie aussitôt, mais le
    // mode du RÉPERTOIRE est ce qui ferme la fenêtre entre `open` et `unlink`.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    controle_positif(&dir)?;
    std::env::set_var("SQLITE_TMPDIR", &dir);
    Ok(dir)
}

/// Écrit un octet puis le relit. Une sonde qu'on n'a pas vue RÉUSSIR ne prouve rien de son sujet.
fn controle_positif(dir: &std::path::Path) -> Result<(), String> {
    let sonde = dir.join(".sonde-ecriture");
    std::fs::write(&sonde, b"1").map_err(|e| format!("écriture impossible dans {} : {e}", dir.display()))?;
    let relu = std::fs::read(&sonde).map_err(|e| format!("relecture impossible dans {} : {e}", dir.display()))?;
    let _ = std::fs::remove_file(&sonde);
    if relu != b"1" {
        return Err(format!("contrôle positif échoué dans {} (relecture divergente)", dir.display()));
    }
    Ok(())
}

#[cfg(test)]
mod plafond_tests {
    use super::*;
    // Le scanner de SOURCES est celui de `db_open` (LA PORTE) : même besoin, même dérivation des
    // fichiers de test, même règle de retrait du texte `#[cfg(test)]`. Il est RÉUTILISÉ plutôt que
    // recopié — une troisième copie du même parcours d'arborescence divergerait comme ont divergé les
    // quatre `temp_store` que ce module vient de réunir.
    use crate::db_open::door_tests::{est_test, fichiers_de_test, rs_files, texte_de_production};
    use std::path::PathBuf;

    /// La dérivation MORD : à budget constant, doubler le nombre de porteurs DIVISE le cache. Sans cette
    /// mutation, « le budget est dérivé du pool » ne serait qu'une phrase de commentaire.
    #[test]
    fn le_cache_suit_le_nombre_de_porteurs() {
        let budget = BUDGET_DEFAUT_MO * 1024;
        assert_eq!(cache_ko_pour(budget, 17), 65536, "le défaut reproduit le dimensionnement historique (-65536)");
        assert_eq!(cache_ko_pour(budget, 34), 32768, "doubler les porteurs DIVISE le cache : le budget tient tout seul");
        assert_eq!(cache_ko_pour(budget, 5000), CACHE_MIN_KO, "plancher : le cache ne descend pas sous {CACHE_MIN_KO} Kio");
        assert_eq!(cache_ko_pour(budget, 0), budget, "porteurs=0 ne divise pas par zéro");
    }

    /// Le comptage suit VRAIMENT la configuration : ce n'est pas une constante déguisée. Et le DÉFAUT
    /// livré rend bien 17 — le nombre dont `BUDGET_DEFAUT_MO` est le produit par 64 Mio.
    #[test]
    fn les_porteurs_comptent_les_deux_familles() {
        assert_eq!(porteurs_pour(3, 2), 17, "défauts livrés : (8+2) connexions + (3+2+2) tris");
        assert_eq!(porteurs_pour(6, 2), 20, "monter la concurrence interactive ajoute des tris en vol");
        assert_eq!(porteurs_pour(3, 8), 23, "monter le refresh des panneaux aussi");
        assert_eq!(
            cache_ko_pour(BUDGET_DEFAUT_MO * 1024, porteurs_pour(3, 2)),
            65536,
            "le défaut livré reproduit EXACTEMENT l'ancien `PRAGMA cache_size=-65536`"
        );
    }

    /// LE BUDGET MÉMOIRE N'A QU'UN SEUL AUTEUR. On n'énumère PAS les sites connus (ils étaient quatre, et
    /// ils avaient déjà divergé) : on interdit le MOTIF partout ailleurs. Un cinquième site écrit demain
    /// échoue le jour où il est écrit, sans que personne ait à s'en souvenir.
    ///
    /// PÉRIMÈTRE : ce test lit les SOURCES. Il attrape un site qui POSE un réglage divergent ; il
    /// n'attrape pas un site qui n'en pose AUCUN — c'est l'objet du test suivant.
    #[test]
    fn le_budget_memoire_sqlite_na_quun_seul_auteur() {
        const MOTIFS: [&str; 4] = ["temp_store", "cache_size", "soft_heap_limit", "hard_heap_limit"];
        let racine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        rs_files(&racine, &mut fichiers);
        assert!(fichiers.len() > 20, "précondition : le scanner a trouvé les sources ({})", fichiers.len());
        let marques = fichiers_de_test(&fichiers);
        let moi = racine.join("sqlite_plafond.rs");
        let (mut ici, mut violations) = (0usize, Vec::new());
        for f in &fichiers {
            if est_test(f, &marques) {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            for (n, l) in texte_de_production(f, &src) {
                if !MOTIFS.iter().any(|m| l.contains(m)) {
                    continue;
                }
                if *f == moi {
                    ici += 1;
                } else {
                    violations.push(format!("{}:{n}: {}", f.display(), l.trim()));
                }
            }
        }
        assert!(ici >= 2, "précondition : ce module décide VRAIMENT du budget ({ici} occurrences) — sinon le test passerait en ne prouvant rien");
        assert!(
            violations.is_empty(),
            "le budget mémoire SQLite se décide dans sqlite_plafond.rs et NULLE PART ailleurs. \
             Sites hors module :\n{violations:#?}"
        );
    }

    /// TOUTE CONNEXION DE LECTURE SUR UN FICHIER PORTE LE PLAFOND. Dérivé de ce qui rend un trieur non
    /// borné : le SILENCE. Une connexion qui ne pose aucun `temp_store` hérite du défaut de compilation
    /// (`SQLITE_TEMP_STORE=2` -> en mémoire -> `mxPmaSize=0` -> aucun déversement possible). Le test exige
    /// donc que le plafond soit posé À PROXIMITÉ de l'ouverture.
    ///
    /// PÉRIMÈTRE, écrit pour ne pas être surestimé : la règle est la PROXIMITÉ (15 lignes de production),
    /// pas le flot de données — un chemin qui ouvrirait ici et poserait le plafond très loin échouerait,
    /// et c'est voulu (on préfère un refus bruyant à une lecture sans plafond).
    #[test]
    fn aucune_lecture_sur_fichier_sans_plafond() {
        const FENETRE: usize = 15;
        let racine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut fichiers = Vec::new();
        rs_files(&racine, &mut fichiers);
        let marques = fichiers_de_test(&fichiers);
        let (mut ouvertures, mut violations) = (0usize, Vec::new());
        for f in &fichiers {
            if est_test(f, &marques) {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            let lignes = texte_de_production(f, &src);
            for (i, (n, l)) in lignes.iter().enumerate() {
                if !l.contains("SQLITE_OPEN_READ_ONLY") || !l.contains("Connection::open") {
                    continue;
                }
                ouvertures += 1;
                let couvert = lignes[i..lignes.len().min(i + FENETRE)]
                    .iter()
                    .any(|(_, s)| s.contains("sqlite_plafond::pragmas_memoire()"));
                if !couvert {
                    violations.push(format!("{}:{n}: {}", f.display(), l.trim()));
                }
            }
        }
        assert!(ouvertures >= 4, "précondition : le scanner voit bien les ouvertures read-only ({ouvertures})");
        assert!(
            violations.is_empty(),
            "ouverture(s) de lecture SANS plafond mémoire — le trieur y est NON BORNÉ (défaut SQLite = \
             tri en mémoire). Poser `sqlite_plafond::pragmas_memoire()` sur la connexion :\n{violations:#?}"
        );
    }

    /// Le contrôle positif du répertoire temporaire REFUSE ce qui n'est pas inscriptible — sinon il ne
    /// contrôlerait rien.
    #[test]
    fn le_controle_positif_refuse_un_repertoire_inutilisable() {
        assert!(controle_positif(std::path::Path::new("/proc/repertoire-qui-nexiste-pas")).is_err());
    }
}

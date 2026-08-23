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
//!      `SQLITE_TEMP_STORE=2` — LU au démarrage et non supposé (cf. la section S26 en fin de module :
//!      le processus INTERROGE le moteur sur une connexion nue et REFUSE de servir si la réponse est
//!      l'autre) —, donc une connexion qui ne dit RIEN trie en mémoire. Le silence est le cas
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
//! CE QUE CE MODULE POSE — TROIS RÉGLAGES QUI NE JOUENT PAS LE MÊME RÔLE, et les confondre mène tout droit
//! à la conclusion fausse « FILE ralentit tout » :
//!   * `temp_store` décide si le TRIEUR sait DÉVERSER. Il est livré sur `MEMORY` (cf. `mot_temp_store`) :
//!     AU DÉFAUT, AUCUN TRI NE DÉVERSE. Ce n'est pas un oubli, c'est un arbitrage assumé et écrit : `FILE`
//!     échange la mort du processus contre des VALEURS D'ÉVÉNEMENT EN CLAIR sur le disque, hors de la base
//!     SQLCipher (mesuré le 2026-08-04 : 323 occurrences lisibles de deux aiguilles du jeu de test dans
//!     16 Mio lus, contrôle négatif à 0). Une base chiffrée qui laisse fuir ses valeurs par le trieur
//!     n'est pas chiffrée. `PLUME_SQLITE_DEVERSEMENT=1` prend cet échange EXPLICITEMENT, pour un
//!     déploiement dont le modèle de menace exclut le vol du volume. CE QUE CE RÉGLAGE NE FAIT PAS, et
//!     c'est le point qui a manqué pendant des mois : « ne pas déverser » n'oblige pas à « ne pas
//!     s'arrêter ». Un tri qui ne peut pas déverser peut quand même ÉCHOUER — c'est ce que fait désormais
//!     le troisième réglage, sans écrire un octet nulle part.
//!     CE QUI SUIT NE VAUT DONC QUE POUR LE CHEMIN OPT-IN — et l'y lire évite la conclusion fausse
//!     « FILE ralentit tout » si un jour on l'évalue à nouveau. Tant que
//!     le tri tient sous le budget, `bFlush` est FAUX à chaque ligne — AUCUN octet n'est écrit, aucune
//!     fusion n'a lieu. Le prix n'est payé QUE par les tris qui DÉPASSENT le budget. (L'accumulation ne
//!     suit pas exactement le même code des deux côtés : en mémoire, un `sqlite3Malloc` PAR
//!     ENREGISTREMENT ; en fichier, un tampon unique qui DOUBLE jusqu'au budget. C'est mesuré cellule par
//!     cellule au banc, dans les deux sens, plutôt que supposé.)
//!   * `cache_size` est la VALEUR du budget PAR PORTEUR. SQLite le lit DEUX FOIS, pour deux choses
//!     différentes : le cache de pages du pager, ET — via `mxPmaSize = MAX(250 × page_size,
//!     |cache_size| × 1024)`, borné par `SQLITE_MAX_PMASZ` (512 Mio) — le budget RAM du trieur avant
//!     déversement. SQLite n'offre aucun moyen de séparer ces deux usages : les dimensionner, c'est
//!     arbitrer entre les deux d'un seul geste.
//!   * `hard_heap_limit` est le PLAFOND, et c'est le seul des trois qui ARRÊTE quoi que ce soit au défaut
//!     (cf. la section qui lui est consacrée plus bas). Il ne borne pas un tri : il borne TOUTE la mémoire
//!     que SQLite peut détenir dans le processus, tris compris, et il le fait dans l'allocateur.
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
//! `cache_size` vaut exactement `-65536` comme avant, ET `temp_store` reste en mémoire comme avant. Le
//! SEUL changement de comportement au DÉFAUT est donc l'EXISTENCE d'un auteur unique pour ce budget —
//! aucun écart de mémoire ni de temps n'est attendu, et tout écart mesuré serait une régression, pas un
//! effet. Ce que la dérivation apporte immédiatement : ce pire cas a maintenant un NOM et un seul nombre
//! pour le réduire.
//!
//! LE BUDGET N'ÉTAIT QU'UNE ARITHMÉTIQUE — CE QUI L'ENFORCE MAINTENANT. Tout ce qui précède CALCULE un
//! budget (`porteurs × cache`) et le PUBLIE (`rapport()`), mais RIEN ne l'imposait : `cache_size` ne borne
//! que le cache de pages, et sous `temp_store=MEMORY` le trieur n'a pas de budget du tout (cf. (1)-(3)).
//! Un chiffre annoncé que rien ne tient est un chiffre faux. `PRAGMA hard_heap_limit` le rend VRAI :
//!   * CE N'EST PAS `soft_heap_limit`, ET LA DIFFÉRENCE EST DE NATURE, PAS DE DEGRÉ. La réfutation du
//!     corollaire ci-dessus vaut pour le SOFT et pour lui seul : il agit en posant `mem0.nearlyFull`, que
//!     seul du code COOPÉRATIF consulte (`sqlite3HeapNearlyFull()`) — et le trieur ne le consulte que dans
//!     la branche `else` jamais atteinte ici. Le HARD n'a besoin d'AUCUNE coopération : `mallocWithAlarm`
//!     (`sqlite3.c` 3.39.4, l. 29141-29146) rend `*pp = 0` — l'allocation ÉCHOUE — dès que
//!     `nUsed >= mem0.hardLimit - nFull`. C'est le `sqlite3Malloc` PAR ENREGISTREMENT du trieur qui échoue,
//!     donc le trieur s'arrête, quel que soit son (absence de) mécanisme de déversement.
//!   * IL EST ARMÉ, PAS SEULEMENT ACCEPTÉ. Le test de `mallocWithAlarm` est enfermé dans
//!     `if( mem0.alarmThreshold>0 )`, et `sqlite3_hard_heap_limit64(N)` pose justement
//!     `alarmThreshold = N` quand il vaut 0 (l. 29030-29032) : poser le hard SUFFIT. La comptabilité qu'il
//!     exige (`SQLITE_STATUS_MEMORY_USED`) est active — `SQLITE_DEFAULT_MEMSTATUS` vaut 1 par défaut
//!     (l. 13571) et la construction vendorée ne le désactive pas.
//!   * CE QU'IL COÛTE, ET C'EST UN VRAI PRIX. Une requête qui dépassait le budget SANS tuer le processus
//!     (parce qu'elle tenait entre le budget et la limite du cgroup) est désormais REFUSÉE. On échange
//!     « quelques requêtes très larges répondent, et un jour l'une d'elles tue TOUTES les sessions »
//!     contre « ces requêtes-là refusent, en disant quoi faire ». `PLUME_SQLITE_PLAFOND_DUR=0` rend
//!     l'ancien comportement à qui préfère l'autre côté de l'échange.
//!   * CE QU'IL NE CHANGE PAS : le RÉSULTAT. Le plafond ne touche ni le plan, ni les valeurs, ni l'ordre.
//!     Une requête qui aboutit rend EXACTEMENT ce qu'elle rendait ; une requête qui n'aboutit pas rend une
//!     ERREUR — jamais un résultat partiel présenté comme complet (le refus vient de l'allocateur, avant
//!     qu'une seule ligne d'agrégat n'existe ; et `run_on_conn` propage l'erreur au lieu de rendre `out`).
//!
//! CE QUE CE MODULE NE FERME PAS, ÉCRIT POUR ÊTRE OPPOSABLE :
//!   - LA CAPACITÉ DE RÉPONDRE. Le plafond dur ferme la MORT DU PROCESSUS (P6.1-b : « une requête tue
//!     toutes les sessions ») ; il ne rend pas calculable ce qui ne l'était pas. `stats dc(message)` sur
//!     3,6 M d'événements demande, par nature, un enregistrement par valeur DISTINCTE : sous plafond il
//!     REFUSE proprement au lieu de tuer. La fermeture de « cette requête doit répondre » passe par moins
//!     d'octets à balayer (fenêtre, tier froid) et par une agrégation à état borné (P10.3), pas par ici.
//!   - LE PARTAGE DU BUDGET AVEC L'ÉCRIVAIN ET AVEC LA MAINTENANCE. `hard_heap_limit` est un plafond de
//!     PROCESSUS (SQLite n'en offre pas d'autre granularité) : une lecture qui occupe presque tout le
//!     budget peut faire échouer une allocation de l'INGEST, et un `VACUUM INTO` (sous-commande `backup`,
//!     `main.rs`) reconstruit les index avec le MÊME trieur — sur une base assez grande il peut désormais
//!     ÉCHOUER là où il tuait le processus. C'est un échange assumé et il va dans le bon sens, mais NON
//!     MESURÉ ici : ni le seuil d'occupation à partir duquel l'ingest voit des échecs, ni la taille de
//!     base à partir de laquelle `VACUUM INTO` franchit le budget.
//!   - LE PLAFOND NE PROTÈGE QUE S'IL EST SOUS LA LIMITE QUI TUE (cf. `Couverture`). MESURÉ au banc le
//!     2026-08-06 : dans un cgroup de 1 Gio avec le budget LIVRÉ (1088 Mio), `stats dc(message)` tue toujours le
//!     processus — l'OOM-killer arrive avant l'allocateur. Le même cgroup avec `PLUME_SQLITE_BUDGET_MB=384`
//!     refuse proprement. La bannière confronte donc les deux nombres au démarrage au lieu d'annoncer une
//!     protection qu'elle ne peut pas tenir.
//!   - CONFIDENTIALITÉ DU CHEMIN OPT-IN. Un tri qui déverse écrit des valeurs en clair hors de la base
//!     SQLCipher. Ce qui est fait pour en limiter la portée : le répertoire est CHOISI (à côté de la
//!     base, `0700`, jamais un `/tmp` hérité) et SQLite DÉLIE le fichier aussitôt après l'avoir ouvert
//!     (`unixOpen` : `if( isDelete ) osUnlink(zName)`), donc il n'a aucun nom dans l'arborescence et
//!     disparaît à la fermeture, y compris si le processus meurt. Ce qui N'EST PAS fait : les octets
//!     touchent le périphérique. Qui active ce drapeau doit poser `SQLITE_TMPDIR` sur un support chiffré
//!     (cf. `repertoire_temporaire_init`) — décision d'exploitation, écrite dans la doc de déploiement.
//!   - AUCUN QUOTA ne borne la TAILLE du déversement quand il est activé : un tri sur une très grande
//!     fenêtre écrit l'ordre de grandeur des données triées. C'est du disque, pas de la RAM, c'est mesuré
//!     au banc, et rien ici n'empêche de remplir le volume.
//!   - `mmap_size` est conservé TEL QUEL (256 Mio). Son effet réel sous SQLCipher n'a pas été mesuré : il
//!     n'est ni revendiqué ni modifié ici.
use crate::*;

/// Budget RAM total concédé à SQLite (Mio). Le défaut REPRODUIT EXACTEMENT le dimensionnement d'avant —
/// `1088 = 17 × 64` — pour qu'AUCUN écart de comportement ne soit livré avec la dérivation, et donc que
/// tout écart mesuré soit une régression à corriger. Ce n'est pas une cible, c'est un CONSTAT : c'est ce que la
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
/// LE DÉVERSEMENT EST UN CHOIX D'EXPLOITANT, PAS UN DÉFAUT — parce qu'il échange de la mémoire
/// contre de la CONFIDENTIALITÉ, et que ce n'est pas à nous de faire cet arbitrage à sa place.
///
/// `temp_store=FILE` donne à SQLite le seul mécanisme qui borne son trieur (mesuré : plateau
/// 1 236 → 749 Mio). Mais **SQLCipher chiffre le FICHIER DE BASE, pas les fichiers temporaires de
/// SQLite** : un tri qui déverse écrit les données d'événements EN CLAIR sur le disque. Mesuré le
/// 2026-08-04 : 323 occurrences de deux aiguilles du jeu de test dans 16 Mio lus, extrait lisible,
/// contrôle négatif (aiguille absente) à 0. Le fichier est délié immédiatement et le répertoire est
/// en 0700, mais il n'est PAS chiffré, et AUCUN quota n'en borne la taille (797 Mio mesurés).
///
/// DÉFAUT = `MEMORY` : c'est ce qui tourne hors tests, et c'est la recommandation de SQLCipher
/// pour cette raison exacte. Le prix est connu et assumé : sans mécanisme de déversement, un tri
/// non couvert par un index croît jusqu'à la limite du cgroup. Sur une base réelle ce plafond n'est pas
/// atteint (la RSS observée reste à une petite fraction du budget) ; il l'a été sur un banc dont les
/// événements sont 4,4× plus gros.
///
/// `PLUME_SQLITE_DEVERSEMENT=1` l'active pour qui préfère la borne mémoire — et doit alors placer
/// `SQLITE_TMPDIR` sur un support chiffré. La vraie sortie n'est ni l'un ni l'autre : c'est une
/// agrégation NATIVE à état borné, où plume décide lui-même combien de mémoire, quand déverser, et
/// sous quelle forme (cf. roadmap P10.3).
fn deversement_actif() -> bool {
    let conf = load_config();
    matches!(
        cfg(&conf, "PLUME_SQLITE_DEVERSEMENT", "0").trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// PUR, donc testable dans les DEUX sens sans toucher à l'environnement ni au `OnceLock`.
/// `false` = pas de déversement = rien en clair sur le disque (le défaut, et la production).
fn mot_temp_store(deversement: bool) -> &'static str {
    if deversement { "FILE" } else { "MEMORY" }
}

/// LE PIRE CAS, EN OCTETS — et c'est EXACTEMENT le nombre que `rapport()` publie déjà. Pas une seconde
/// constante posée à côté de la première : le plafond ENFORCÉ est, par construction, la somme que le modèle
/// de porteurs annonce. Changer `READ_POOL_CAP`, une concurrence ou `PLUME_SQLITE_BUDGET_MB` déplace les
/// DEUX du même geste — c'est la seule façon qu'ils ne divergent pas (la faute déjà payée par les quatre
/// `cache_size` que ce module a réunis).
fn plafond_dur_octets() -> i64 {
    let p = porteurs();
    p * cache_ko_pour(budget_ko(), p) * 1024
}

/// CE QUE LE PROCESSUS FAIT QUAND LE BUDGET EST ATTEINT. Deux cas EXCLUSIFS, d'où un type et des `match`
/// EXHAUSTIFS (aucun bras `_`) : un troisième mode ajouté demain ne compile pas tant que sa phrase, son
/// pragma et son refus ne sont pas écrits.
enum Plafond {
    /// DÉFAUT. Le budget est imposé par l'ALLOCATEUR de SQLite : la requête qui le franchit ÉCHOUE
    /// (`SQLITE_NOMEM` -> refus explicite), le processus et toutes les autres sessions survivent.
    Applique(i64),
    /// `PLUME_SQLITE_PLAFOND_DUR=0` : comportement historique. Le budget redevient une arithmétique que
    /// rien ne tient, et une agrégation assez large épuise la RAM du cgroup — OOM-kill du processus.
    Aucun,
}

impl Plafond {
    /// Le fragment de PRAGMA. `PRAGMA hard_heap_limit=N` n'ABAISSE que : `pragma.c` ne l'applique que si
    /// aucune limite n'est posée ou si la limite en place est PLUS HAUTE (l. 139425) — le poser à
    /// l'identique sur chaque connexion est donc idempotent, et aucun SQL ne peut le RELEVER.
    fn pragma(&self) -> String {
        match self {
            Plafond::Applique(o) => format!(" PRAGMA hard_heap_limit={o};"),
            Plafond::Aucun => String::new(),
        }
    }

    /// LA PHRASE DU JOURNAL. Un plafond qu'on ne peut pas LIRE en exploitation n'est pas opposable.
    fn phrase(&self) -> String {
        match self {
            Plafond::Applique(o) => format!(
                "APPLIQUÉ par l'allocateur (hard_heap_limit={o}) : une requête qui le franchit REFUSE, le \
                 processus survit"
            ),
            Plafond::Aucun => "NON APPLIQUÉ (PLUME_SQLITE_PLAFOND_DUR=0) : ce budget n'est qu'un calcul — \
                               une agrégation assez large épuise la RAM et TUE le processus, donc toutes \
                               les sessions"
                .to_string(),
        }
    }
}

/// PURE, donc testable dans les deux sens sans toucher à l'environnement : c'est le mot d'exploitation qui
/// décide, et le `OnceLock` de `pragmas_memoire` ne fige plus la seule branche qu'un test peut voir.
fn plafond_pour(actif: bool, octets: i64) -> Plafond {
    if actif { Plafond::Applique(octets) } else { Plafond::Aucun }
}

/// CE QUE L'INTERFACE DE GROUPES DE CONTRÔLE A DIT — trois verdicts EXCLUSIFS, et c'est LA correction que
/// ce bloc porte. « il n'y a PAS de limite » et « la lecture N'A PAS ABOUTI » étaient tous deux rendus `None`,
/// donc rendus par la même phrase « NON LISIBLE ». La confusion coûte des DEUX côtés : sur un hôte sans
/// limite — le cas ordinaire d'un service système natif sans `MemoryMax=` — la bannière accusait
/// l'instrument alors que l'instrument allait bien ; et sur un hôte où le chemin a changé de forme, elle
/// laissait croire à une propriété du déploiement alors que rien n'avait été mesuré. Un `match` exhaustif
/// (aucun bras `_`) interdit qu'un quatrième cas se glisse silencieusement dans l'un des trois.
#[derive(Debug, PartialEq)]
enum LimiteCgroup {
    /// Une limite EXISTE et vaut N octets : c'est ce nombre-là qui déclenche l'OOM-kill.
    Octets(i64),
    /// L'interface a été LUE et COMPRISE, et elle dit qu'il n'y a AUCUNE limite (v2 : le mot `max` ;
    /// v1 : la sentinelle « illimitée »). L'instrument va bien — c'est le déploiement qui ne borne rien.
    Aucune,
    /// L'interface n'a pas pu être lue, ou sa forme n'a pas été reconnue. Porte CE QUI A ÉTÉ TENTÉ : un
    /// aveu qui ne nomme pas le chemin essayé n'est pas actionnable.
    Illisible(String),
}

/// Au-delà de ce seuil, un nombre n'est plus un budget : c'est la façon dont cgroup v1 écrit « pas de
/// limite » (`i64::MAX` arrondi au multiple de page, et `u64::MAX` sur d'autres configurations — cette
/// seconde forme ne rentrait même pas dans un `i64`, donc elle était comptée comme illisible). 1 Pio est
/// des ordres de grandeur au-dessus de toute limite qu'un exploitant pose réellement ; publier « plafond
/// de 8 Eio » serait pire que se taire.
const SEUIL_SANS_LIMITE: u128 = 1 << 50;

/// LA FORME DU CONTENU D'UN FICHIER DE LIMITE — PURE, donc exerçable sur chaque variante connue sans
/// aucun groupe de contrôle sous la main. Les deux versions de l'interface écrivent « pas de limite »
/// différemment (v2 : le mot `max` ; v1 : un entier énorme) et c'est le SEUL endroit qui le sait.
/// Une forme qui n'est ni l'une ni l'autre rend `Illisible` — jamais `Aucune` : confondre les deux est
/// précisément le défaut fermé ici.
fn valeur_limite(txt: &str) -> LimiteCgroup {
    let t = txt.trim();
    if t.eq_ignore_ascii_case("max") {
        return LimiteCgroup::Aucune;
    }
    match t.parse::<u128>() {
        Ok(n) if n >= SEUIL_SANS_LIMITE => LimiteCgroup::Aucune,
        // `n < SEUIL_SANS_LIMITE` (2^50) : la conversion ne peut pas déborder un i64.
        Ok(n) => LimiteCgroup::Octets(n as i64),
        Err(_) => LimiteCgroup::Illisible(format!(
            "forme non reconnue ({:?})",
            t.chars().take(24).collect::<String>()
        )),
    }
}

/// LA LIGNÉE cgroup v2, isolée. Rend `None` quand AUCUN fichier de limite n'a pu être lu — c'est-à-dire
/// exactement le cas où le repli v1 a encore quelque chose à dire ; tout autre cas est déjà un verdict.
///
/// UN `memory.max` ABSENT À UN NIVEAU N'EST PAS UNE PANNE : le noyau n'expose pas le contrôleur mémoire
/// sur le cgroup RACINE, donc la dernière itération de la remontée ne trouve normalement rien. Un
/// `memory.max` PRÉSENT dont la forme n'est pas reconnue, lui, EN EST une, et il remonte au lieu d'être
/// avalé par le `if let Ok(...)` qui l'ignorait.
///
/// FAIL-CLOSED SUR UNE LIGNÉE PARTIELLEMENT LISIBLE : si un niveau est incompris, on ne conclut PAS sur le
/// minimum des autres. Un niveau qu'on n'a pas su lire peut porter une limite PLUS SERRÉE, et annoncer
/// « protégé » sur la foi des niveaux lisibles serait revendiquer une couverture qu'on n'a pas établie.
fn lignee_v2(racine: &std::path::Path, chemin: &str) -> Option<LimiteCgroup> {
    let mut ici = racine.join(chemin.trim_start_matches('/'));
    let (mut mini, mut lus, mut incomprises) = (None::<i64>, 0usize, Vec::new());
    loop {
        let f = ici.join("memory.max");
        if let Ok(v) = std::fs::read_to_string(&f) {
            match valeur_limite(&v) {
                LimiteCgroup::Octets(n) => {
                    lus += 1;
                    mini = Some(mini.map_or(n, |m: i64| m.min(n)));
                }
                LimiteCgroup::Aucune => lus += 1,
                LimiteCgroup::Illisible(quoi) => incomprises.push(format!("{} : {quoi}", f.display())),
            }
        }
        if ici == racine {
            break;
        }
        match ici.parent() {
            Some(p) if p.starts_with(racine) => ici = p.to_path_buf(),
            _ => break,
        }
    }
    if !incomprises.is_empty() {
        return Some(LimiteCgroup::Illisible(format!(
            "{}{}",
            incomprises.join(" ; "),
            mini.map_or(String::new(), |n| format!(
                " (un niveau lisible annonce {n} o, mais un niveau ILLISIBLE peut être plus serré)"
            ))
        )));
    }
    if let Some(n) = mini {
        return Some(LimiteCgroup::Octets(n));
    }
    if lus > 0 {
        return Some(LimiteCgroup::Aucune);
    }
    None
}

/// LA LIMITE QUI NOUS TUE, LUE SUR LE SYSTÈME — jamais supposée. PARAMÉTRÉE sur ses deux chemins, et
/// c'est ce qui la rend EXERÇABLE : les tests lui présentent une arborescence fabriquée dans un
/// temporaire possédé, donc chaque forme connue de l'interface se joue sans dépendre de l'hôte qui
/// exécute la suite. Un test qui n'aurait passé que sous conteneur aurait rougi en intégration continue,
/// et un test qui n'aurait passé que sur un hôte sans limite n'aurait rien prouvé du cas conteneurisé.
///
/// LES FORMES RECENSÉES, et pourquoi chacune existe :
///   1. cgroup v2 (hiérarchie unifiée) — `/proc/self/cgroup` porte une ligne `0::<chemin>`. La limite
///      EFFECTIVE est la PLUS PETITE de la lignée : un parent plus serré tue avant la feuille, d'où la
///      remontée jusqu'à la racine du montage.
///   2. cgroup v2, valeur `max` — la limite est ABSENTE, et le fichier le DIT en toutes lettres. C'est le
///      cas ordinaire d'un hôte systemd sans `MemoryMax=`, et c'est celui qui était pris pour une panne.
///   3. cgroup v2, RACINE du montage — la racine n'expose PAS `memory.max` (le noyau ne pose pas le
///      contrôleur mémoire sur le cgroup racine). Un fichier manquant à ce niveau est donc NORMAL, et ne
///      doit pas à lui seul faire conclure à l'illisibilité.
///   4. conteneur AVEC espace de noms de cgroup (défaut des moteurs récents) — `/proc/self/cgroup` rend
///      `0::/` et le montage EST le cgroup du conteneur : `memory.max` à la racine VISIBLE porte alors la
///      limite. C'est l'exception à (3), et c'est pourquoi la racine est lue elle aussi.
///   5. conteneur SANS espace de noms (moteurs anciens, `--cgroupns=host`) — `/proc/self/cgroup` rend le
///      chemin de l'HÔTE alors que le montage est la feuille : le chemin joint n'existe pas, aucun fichier
///      n'est lu. C'est une vraie ABSENCE DE MESURE, et elle doit se dire AVEC le chemin tenté.
///   6. cgroup v1 — aucune ligne `0::` porteuse, et le fichier historique
///      `<racine>/memory/memory.limit_in_bytes`. « Pas de limite » y est un entier énorme, pas un mot.
///   7. hybride v1+v2 — la ligne `0::` existe mais la hiérarchie unifiée ne porte pas le contrôleur
///      mémoire ; aucun `memory.max` n'est trouvé sous la racine v2, et le repli v1 tranche.
///   8. ni l'un ni l'autre (`/proc` masqué, système non Linux) — rien n'est lisible, et on le dit.
fn limite_cgroup_depuis(racine: &std::path::Path, proc_self_cgroup: &std::path::Path) -> LimiteCgroup {
    let mut tentes: Vec<String> = Vec::new();
    match std::fs::read_to_string(proc_self_cgroup) {
        Ok(txt) => match txt.lines().find_map(|l| l.strip_prefix("0::")) {
            Some(chemin) => match lignee_v2(racine, chemin.trim()) {
                Some(verdict) => return verdict,
                None => tentes.push(format!(
                    "aucun memory.max lisible sous {}",
                    racine.join(chemin.trim().trim_start_matches('/')).display()
                )),
            },
            None => tentes.push(format!(
                "{} ne porte aucune ligne `0::` (hiérarchie v1 ou hybride)",
                proc_self_cgroup.display()
            )),
        },
        Err(e) => tentes.push(format!("{} : {e}", proc_self_cgroup.display())),
    }
    let v1 = racine.join("memory").join("memory.limit_in_bytes");
    match std::fs::read_to_string(&v1) {
        Ok(txt) => match valeur_limite(&txt) {
            LimiteCgroup::Illisible(quoi) => tentes.push(format!("{} : {quoi}", v1.display())),
            verdict => return verdict,
        },
        Err(e) => tentes.push(format!("{} : {e}", v1.display())),
    }
    LimiteCgroup::Illisible(tentes.join(" ; "))
}

/// Les chemins RÉELS. Le seul endroit du module qui les nomme — tout le reste travaille sur une racine
/// passée en paramètre, donc s'exerce.
fn limite_cgroup() -> LimiteCgroup {
    limite_cgroup_depuis(
        std::path::Path::new("/sys/fs/cgroup"),
        std::path::Path::new("/proc/self/cgroup"),
    )
}

/// UN PLAFOND NE PROTÈGE QUE S'IL EST SOUS CE QUI NOUS TUE. Un budget de 1088 Mio dans un conteneur limité
/// à 1 Gio est une protection IMAGINAIRE : l'OOM-killer arrive avant l'allocateur. La bannière ne peut donc
/// pas se contenter d'annoncer le budget — elle doit le CONFRONTER à la limite réelle, ou dire lequel des
/// deux empêchements l'en prive. QUATRE cas EXCLUSIFS, `match` exhaustif : c'est la seule façon que « je
/// ne sais pas » ne se déguise ni en « tout va bien », ni en « il n'y a pas de limite ».
///
/// CE QUI SE PASSE QUAND LA LECTURE ÉCHOUE — décision, et sa raison. NI refus de démarrage, NI défaut
/// prudent : FONCTIONNEMENT DÉGRADÉ ANNONCÉ.
///   * REFUSER DE DÉMARRER serait faux au regard des modes de déploiement revendiqués. Un service système
///     natif sans `MemoryMax=` n'a légitimement AUCUNE limite ; faire d'une lecture impossible une panne
///     transformerait des installations correctes en incidents.
///   * UN DÉFAUT PRUDENT (supposer une limite basse) INVENTERAIT un nombre. Il ferait refuser des requêtes
///     qui tiennent, et surtout il PRÉTENDRAIT une mesure : c'est exactement la faute que ce bloc ferme.
///   * CE QUI RESTE TENU SANS CETTE LECTURE, et c'est pourquoi le dégradé est acceptable : le plafond dur
///     de SQLite ne dépend PAS d'elle — il est posé, et une requête qui le franchit refuse, lecture du
///     cgroup ou pas. Ce que la lecture apporte est la CONFRONTATION : savoir si ce plafond est SOUS ce
///     qui tue. Sans elle, la protection interne survit ; c'est sa VÉRIFICATION qui manque, et c'est
///     exactement cela qui est annoncé — ni plus, ni moins.
enum Couverture {
    /// Le budget tient sous la limite mesurée : le refus arrive AVANT l'OOM-killer.
    Protege { limite: i64 },
    /// La limite existe et le budget ne tient pas dessous. Le processus mourra avant de refuser.
    Depasse { limite: i64 },
    /// L'interface a été LUE : il n'y a AUCUNE limite de cgroup. Rien d'extérieur ne borne le processus.
    SansLimite,
    /// La lecture a échoué ou n'a pas été comprise. On ne prétend RIEN, et on dit ce qui a été tenté.
    Illisible(String),
}

/// PURE : la confrontation, séparée de la LECTURE, donc exerçable dans les quatre états sans cgroup sous
/// la main. `limite` vient de `limite_cgroup`.
fn couverture_pour(budget: i64, limite: LimiteCgroup) -> Couverture {
    match limite {
        LimiteCgroup::Octets(l) if budget < l => Couverture::Protege { limite: l },
        LimiteCgroup::Octets(l) => Couverture::Depasse { limite: l },
        LimiteCgroup::Aucune => Couverture::SansLimite,
        LimiteCgroup::Illisible(pourquoi) => Couverture::Illisible(pourquoi),
    }
}

impl Couverture {
    /// LE MOT DE VERDICT — stable, sans espace, un par cas : c'est LUI le signal. La bascule d'une
    /// protection annoncée à une protection absente change ce mot dans la ligne `[plafond]` du démarrage,
    /// donc une supervision qui l'observe la VOIT ; une phrase en prose, elle, se relit à l'œil et ne se
    /// surveille pas. Ces quatre valeurs sont un contrat : les renommer casse ce qui les observe.
    fn verdict(&self) -> &'static str {
        match self {
            Couverture::Protege { .. } => "protege",
            Couverture::Depasse { .. } => "depasse",
            Couverture::SansLimite => "sans-limite",
            Couverture::Illisible(_) => "illisible",
        }
    }

    /// Le plafond protège-t-il RÉELLEMENT de ce qui tue ? Un seul des quatre verdicts le permet. DÉRIVÉ,
    /// jamais énuméré une seconde fois : c'est ce prédicat qui décide du mot d'alerte de la phrase, donc
    /// un cas ajouté demain est bruyant par défaut au lieu d'être silencieusement rangé du bon côté.
    fn protege(&self) -> bool {
        matches!(self, Couverture::Protege { .. })
    }

    fn phrase(&self) -> String {
        let alerte = if self.protege() { "" } else { "AVERTISSEMENT " };
        let verdict = self.verdict();
        let corps = match self {
            Couverture::Protege { limite } => {
                format!("sous la limite mémoire du cgroup ({} Mio)", limite / 1048576)
            }
            Couverture::Depasse { limite } => format!(
                "la limite mémoire du cgroup est {} Mio : LE PLAFOND NE PROTÈGE PAS — l'OOM-killer \
                 arrivera avant le refus. Baisser PLUME_SQLITE_BUDGET_MB sous cette limite.",
                limite / 1048576
            ),
            Couverture::SansLimite =>
                "AUCUNE limite mémoire de cgroup n'est posée — l'interface a été LUE, et elle ne borne \
                 rien. Ce n'est PAS une panne de mesure : le plafond ci-dessus borne SQLite, mais RIEN \
                 n'arrête le processus avant la RAM de l'hôte, et le budget de 2 Gio du produit n'est \
                 alors qu'une intention. Le poser : MemoryMax= (unité systemd), --memory (conteneur), \
                 limits.memory (orchestrateur)."
                    .to_string(),
            Couverture::Illisible(pourquoi) => format!(
                "limite mémoire du cgroup NON LISIBLE ({pourquoi}) : impossible de dire si ce budget \
                 protège de l'OOM-killer. Ce n'est PAS « il n'y a pas de limite », c'est « il n'y a pas \
                 de mesure » — le plafond SQLite reste appliqué, sa couverture n'est pas vérifiée."
            ),
        };
        format!(", {alerte}[couverture={verdict}] {corps}")
    }
}

/// DÉFAUT = APPLIQUÉ. C'est l'inverse de `PLUME_SQLITE_DEVERSEMENT` et pour une raison qui se dit : le
/// déversement échange de la CONFIDENTIALITÉ (des valeurs en clair sur le disque), ce n'est pas à nous de
/// le décider ; le plafond dur n'échange que la RÉPONSE À UNE REQUÊTE TRÈS LARGE contre la survie du
/// processus, et personne n'a jamais demandé qu'une requête emporte les sessions des autres.
fn plafond_dur_actif() -> bool {
    let conf = load_config();
    !matches!(
        cfg(&conf, "PLUME_SQLITE_PLAFOND_DUR", "1").trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn plafond_courant() -> Plafond {
    plafond_pour(plafond_dur_actif(), plafond_dur_octets())
}

pub(crate) fn pragmas_memoire() -> &'static str {
    static P: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    P.get_or_init(|| pragmas_memoire_pour(deversement_actif()))
}

/// LE BATCH, PARAMÉTRÉ SUR LE MODE (forme de `S32`). Le processus n'a qu'un mode, et `pragmas_memoire`
/// le fige une fois pour toutes ; cette forme-ci laisse une suite de tests armer une connexion sous
/// l'AUTRE mode — c'est le seul moyen de jouer le couple « déversement demandé, connexion armée » sans
/// relancer un processus, et sans lui ce couple ne s'est jamais joué (`S38`).
fn pragmas_memoire_pour(deversement: bool) -> String {
    format!(
        "PRAGMA temp_store={}; PRAGMA mmap_size=268435456; PRAGMA cache_size={};{}",
        mot_temp_store(deversement),
        -cache_ko_pour(budget_ko(), porteurs()),
        plafond_courant().pragma()
    )
}

/// CE QUE LE PLAFOND VAUT, EN CLAIR, POUR LE JOURNAL DE DÉMARRAGE. Un plafond qu'on ne peut pas LIRE en
/// exploitation n'est pas opposable : on publie le pire cas, de quoi il est le produit, ET s'il est
/// réellement imposé — la phrase manquante était précisément celle-là.
pub(crate) fn rapport() -> String {
    let (p, c) = (porteurs(), cache_ko_pour(budget_ko(), porteurs()));
    format!(
        "budget {} Mio = {} porteurs × {} Mio (cache_size={}) — {}{}",
        (p * c) / 1024,
        p,
        c / 1024,
        -c,
        plafond_courant().phrase(),
        couverture_pour(plafond_dur_octets(), limite_cgroup()).phrase()
    )
}

/// LE REFUS, EN MOTS D'EXPLOITANT. Ce que SQLite rend est « out of memory » : vrai, inutilisable. Un refus
/// n'a de valeur que s'il dit CE QUI S'EST PASSÉ, CE QUI N'A PAS EU LIEU, et QUOI FAIRE.
/// PURE (prend le mode déjà résolu) -> les deux branches se testent sans toucher à l'environnement.
fn refus_budget_pour(p: &Plafond) -> String {
    let quoi_faire = "AUCUN résultat n'est rendu : un résultat partiel serait FAUX sans le dire. Réduisez \
                      la fenêtre de temps, ajoutez un filtre, ou groupez sur une clé de plus faible \
                      cardinalité — un `stats … by` matérialise un enregistrement par ligne BALAYÉE, pas \
                      par groupe. Un exploitant qui a la RAM peut relever PLUME_SQLITE_BUDGET_MB.";
    match p {
        Plafond::Applique(o) => format!(
            "budget mémoire dépassé : cette requête a demandé plus que les {} Mio concédés à SQLite. \
             {quoi_faire}",
            o / 1048576
        ),
        Plafond::Aucun => format!(
            "mémoire épuisée pendant l'exécution (aucun plafond dur n'est appliqué : \
             PLUME_SQLITE_PLAFOND_DUR=0). {quoi_faire}"
        ),
    }
}

/// TRADUIT une erreur rusqlite pour l'exploitant. DÉRIVÉ DU CODE D'ERREUR (`SQLITE_NOMEM`), jamais du
/// TEXTE : le texte de SQLite est une chaîne C qui n'engage personne, le code est celui que
/// `mallocWithAlarm` provoque en refusant l'allocation. Toute autre erreur est rendue TELLE QUELLE — ce
/// traducteur n'existe que pour la seule qui était illisible.
pub(crate) fn message_erreur(e: &rusqlite::Error) -> String {
    if est_manque_de_memoire(e) {
        refus_budget_pour(&plafond_courant())
    } else {
        e.to_string()
    }
}

/// La reconnaissance, isolée pour être EXERCÉE. `SQLITE_NOMEM` est le SEUL code que le franchissement du
/// plafond peut produire (`*pp = 0` dans l'allocateur -> `SQLITE_NOMEM` remonté par le VDBE).
fn est_manque_de_memoire(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::OutOfMemory)
}

/// CE QUE LE PROCESSUS FERA DE SES TRIS. Trois cas, et ils sont EXCLUSIFS — d'où un type plutôt qu'un
/// `Result`, dont le `Err` avait déjà servi à dire deux choses différentes.
pub(crate) enum Deversement {
    /// LE DÉFAUT. Pas de déversement : rien d'un événement ne touche le disque en clair, et il n'existe
    /// aucun plafond de tri (cf. l'en-tête du module — c'est un arbitrage, pas un oubli).
    Desactive,
    /// Demandé par `PLUME_SQLITE_DEVERSEMENT=1` ET obtenu : ce répertoire recevra du clair. Le second
    /// membre est ce qui y SUBSISTAIT DÉJÀ sous un nom au moment de la préparation (`S29`) : SQLite délie
    /// ses temporaires à l'ouverture, donc un nom qui subsiste est du clair qu'un processus tombé — ou un
    /// moteur qui ne délie plus — a laissé derrière lui. C'est MESURÉ, jamais supposé vide : un répertoire
    /// qu'on n'a pas su lister rend `Illisible`, et la bannière le dit tel quel.
    Vers(std::path::PathBuf, crate::mesure_environnement::Mesure<Vec<String>>),
    /// Demandé et NON obtenu — le cas qui mérite l'alerte, parce que SQLite retombera silencieusement.
    Indisponible(String),
}

/// LE SEUL point qui décide ET rapporte. La bannière était écrite dans `server/mod.rs`, qui n'a pas accès au
/// mode : elle annonçait « déversement des tris : <chemin> » À CHAQUE DÉMARRAGE, y compris quand rien ne
/// déverse — une phrase fausse dans le journal, et la branche d'erreur alertait sur un plafond inexistant.
/// La rendre ICI ferme l'écart par construction : le `match` est EXHAUSTIF (aucun bras `_`), donc un mode
/// ajouté demain ne compile pas tant que sa phrase n'est pas écrite.
///
/// PURE, et c'est délibéré : elle prend le mode DÉJÀ résolu ET le verdict DÉJÀ lu au lieu de les
/// résoudre elle-même, donc les branches se testent sans toucher au disque ni à l'environnement.
///
/// S26 — ELLE DIT CE QUI EST MESURÉ, JAMAIS CE QUI EST SUPPOSÉ. Le mode n'est qu'une DEMANDE : ce que
/// le moteur fait vraiment d'un tri se lit. Quand les deux s'accordent, la bannière publie les chiffres
/// LUS ; quand ils divergent, elle annonce le risque RÉEL et non la promesse — une bannière qui
/// annoncerait « déversement désactivé » pendant qu'il a lieu serait pire qu'une bannière absente.
///
/// S38 — LA MESURE PORTE SUR UNE CONNEXION ARMÉE, JAMAIS SUR UNE SONDE NUE. La première forme lisait
/// `tri_dune_connexion_nue()`, sur laquelle `temp_store=FILE` n'est posé par personne : sous
/// `PLUME_SQLITE_DEVERSEMENT=1` elle disait TOUJOURS « demandé mais tri en mémoire », quel que soit ce
/// que les connexions qui servent faisaient de leurs tris. Une garde qui alerte toujours ne prouve rien,
/// et elle apprend à ne plus la lire. La lecture arrive désormais sous la forme de `S32` : `Lue` quand
/// elle a été prise sur la connexion qui sert, `Illisible` quand aucune connexion armée n'était sous la
/// main — et la bannière dit alors « NON MESURÉ » au lieu de mesurer autre chose.
pub(crate) fn banniere(mode: Deversement, tri: crate::mesure_environnement::Mesure<Tri>) -> String {
    let r = rapport();
    match mode {
        Deversement::Desactive => match &tri {
            crate::mesure_environnement::Mesure::Lue(t) if desaccord_pour(t, false).is_none() => format!(
                "{r} — déversement des tris DÉSACTIVÉ (défaut), et c'est MESURÉ sur la connexion qui sert : \
                 {}. Aucune valeur d'événement en clair hors de la base chiffrée. Un tri trop large ne \
                 déverse donc pas : il ÉCHOUE au plafond ci-dessus. PLUME_SQLITE_DEVERSEMENT=1 échange \
                 cette confidentialité contre des tris qui aboutissent.",
                constat_de_tri(t)
            ),
            _ => format!("{r} — déversement des tris DÉSACTIVÉ (demandé), {}", mesure_de_tri(&tri, false)),
        },
        Deversement::Vers(d, residus) => format!(
            "{r} — déversement des tris ACTIVÉ vers {} : ce répertoire reçoit des VALEURS D'ÉVÉNEMENT EN \
             CLAIR, hors de la base SQLCipher. Il doit être sur un support chiffré. {} {}",
            d.display(),
            mesure_de_tri(&tri, true),
            constat_de_residus(&residus)
        ),
        Deversement::Indisponible(e) => format!(
            "{r} — déversement des tris DEMANDÉ mais répertoire INDISPONIBLE ({e}) : SQLite retombera sur \
             TMPDIR/var/tmp/tmp, qui est un tmpfs (donc de la RAM) sur la plupart des hôtes systemd -> le \
             déversement n'y borne RIEN. {}",
            mesure_de_tri(&tri, true)
        ),
    }
}

/// LE SEGMENT DE MESURE DE LA BANNIÈRE, avec ses trois mots stables : « MESURÉ » quand la lecture
/// confirme le mode (sous déversement : « demandé et TENU »), « MAIS LA MESURE DIT AUTRE CHOSE » quand
/// elle le contredit, « NON MESURÉ » quand aucune connexion armée n'était là pour la prendre. Le
/// troisième n'est pas un « tout va bien » : il porte la cause, et dit ce que personne ne sait.
fn mesure_de_tri(tri: &crate::mesure_environnement::Mesure<Tri>, deversement: bool) -> String {
    use crate::mesure_environnement::Mesure;
    match tri {
        Mesure::Lue(t) => match desaccord_pour(t, deversement) {
            None if deversement => format!("Déversement demandé et TENU, MESURÉ sur la connexion qui sert : {}.", constat_de_tri(t)),
            None => format!("MESURÉ sur la connexion qui sert : {}.", constat_de_tri(t)),
            Some(x) => format!("MAIS LA MESURE DIT AUTRE CHOSE : {x}"),
        },
        Mesure::Illisible { cause, detail } => format!(
            "NON MESURÉ ({cause} : {detail}) : aucune connexion armée n'était disponible pour lire ce que \
             le moteur fait d'un tri, et une sonde nue ne porte pas ce réglage. Rien ne dit ici {}.",
            if deversement { "que le tri déverse bien" } else { "qu'aucune valeur d'événement ne part en clair" }
        ),
    }
}

/// CE QUI SUBSISTE SOUS UN NOM DANS LE RÉPERTOIRE DE DÉVERSEMENT, dit avec un MOT STABLE (`S29`) :
/// `residus-en-clair=0`, `residus-en-clair=<n>` suivi des noms, ou `residus-en-clair=illisible` suivi de
/// la cause. Le mot est le contrat de supervision, comme les verdicts de `S28` ; seul `=0` est calme.
/// Rien n'est supprimé ici : ces fichiers sont du clair, donc aussi une pièce — c'est à l'exploitant de
/// décider, et la phrase se répète à chaque démarrage tant qu'il ne l'a pas fait.
pub(crate) fn constat_de_residus(residus: &crate::mesure_environnement::Mesure<Vec<String>>) -> String {
    use crate::mesure_environnement::Mesure;
    match residus {
        Mesure::Lue(noms) if noms.is_empty() => "residus-en-clair=0 (MESURÉ : aucun nom n'y subsistait).".to_string(),
        Mesure::Lue(noms) => format!(
            "residus-en-clair={} ({}) : SQLite délie ses temporaires à l'ouverture, donc un fichier qui porte \
             encore un nom est du CLAIR laissé par un processus tombé ou par un moteur qui ne délie plus. Ils \
             ne sont PAS supprimés ici : à examiner, puis à retirer.",
            noms.len(),
            noms.join(", ")
        ),
        Mesure::Illisible { cause, detail } => format!(
            "residus-en-clair=illisible ({cause} : {detail}) : le répertoire n'a PAS pu être listé, donc rien \
             ne dit qu'aucun clair n'y subsiste."
        ),
    }
}

/// Prépare le déversement SI et SEULEMENT SI il est demandé. Au défaut, on ne crée même pas le répertoire :
/// un `sqltmp` présent sur le volume laisserait croire que des tris y passent.
pub(crate) fn deversement_init(db_path: &str) -> Deversement {
    if !deversement_actif() {
        return Deversement::Desactive;
    }
    match repertoire_temporaire_init(db_path) {
        Ok(d) => {
            let residus = residus_de_deversement(&d);
            Deversement::Vers(d, residus)
        }
        Err(e) => Deversement::Indisponible(e),
    }
}

/// LA MESURE DE L'ALLÉGATION D'HÔTE « SQLite délie son temporaire aussitôt ouvert » (`S29`) : les noms qui
/// subsistent dans le répertoire de déversement, hors la sonde d'écriture qui est à nous. Si l'allégation
/// tient, cette liste est VIDE à chaque démarrage ; un nom est la preuve qu'elle a lâché au moins une fois.
/// Paramétrée sur le répertoire, donc exerçable sans toucher à l'environnement du processus.
pub(crate) fn residus_de_deversement(dir: &std::path::Path) -> crate::mesure_environnement::Mesure<Vec<String>> {
    crate::mesure_environnement::entrees_nommees_depuis(dir, &[SONDE_ECRITURE])
}

/// Le répertoire où SQLite déversera. PRIVÉ : on passe par `deversement_init`, sinon un appelant peut
/// préparer un déversement que le mode n'autorise pas. DOIT être appelé AVANT le premier appel SQLite du processus :
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
/// SILENCE — et le silence, chez le moteur vendoré (`unixTempFileDir`, lu dans `sqlite3.c`), vaut dans
/// l'ordre `TMPDIR`, puis `/var/tmp`, `/usr/tmp`, `/tmp`, puis le répertoire courant : un répertoire
/// PARTAGÉ dans tous les cas, et pas forcément `/tmp`.
fn repertoire_temporaire_init(db_path: &str) -> Result<std::path::PathBuf, String> {
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
/// Le nom de la sonde d'écriture : UN SEUL auteur, parce que la mesure des résidus doit l'ignorer par le
/// même nom que le contrôle l'écrit.
const SONDE_ECRITURE: &str = ".sonde-ecriture";

fn controle_positif(dir: &std::path::Path) -> Result<(), String> {
    let sonde = dir.join(SONDE_ECRITURE);
    std::fs::write(&sonde, b"1").map_err(|e| format!("écriture impossible dans {} : {e}", dir.display()))?;
    let relu = std::fs::read(&sonde).map_err(|e| format!("relecture impossible dans {} : {e}", dir.display()))?;
    let _ = std::fs::remove_file(&sonde);
    if relu != b"1" {
        return Err(format!("contrôle positif échoué dans {} (relecture divergente)", dir.display()));
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════════
// S26 — CE QUE LE MOTEUR FAIT D'UN TRI : LU, JAMAIS SUPPOSÉ
// ═══════════════════════════════════════════════════════════════════════════════════
//
// CE QUI ÉTAIT AFFIRMÉ. L'en-tête de ce module écrit que la construction livrée porte
// `SQLITE_TEMP_STORE=2`, donc qu'une connexion qui ne dit RIEN trie en mémoire. C'est VRAI dans la
// construction livrée — et ça l'était par AFFIRMATION : aucun code ne le relisait. La valeur ne vient
// pas de ce dépôt mais de la liaison Rust, qui ne la pose que dans la branche SQLCipher de sa
// compilation. Une version future qui livrerait `=1` ferait DÉVERSER toute connexion muette — des
// valeurs d'événement EN CLAIR hors de la base SQLCipher, cf. l'en-tête — pendant que la bannière
// continuerait d'annoncer « déversement DÉSACTIVÉ ». Une bannière qui annonce l'inverse de ce qui se
// passe est pire qu'une bannière absente : c'est sur elle qu'on s'appuiera le jour d'un incident de
// confidentialité.
//
// POURQUOI `PRAGMA temp_store` NE RÉPOND PAS À LA QUESTION, et c'est tout le piège. Il rend le réglage
// LOCAL de la connexion (`sqlite3.c` 3.39.4, l. 16931 : « 1: file 2: memory 0: default »). Sur une
// connexion muette il vaut 0 — la MÊME valeur, que le tri finisse en mémoire ou sur le disque. Le lire
// et le trouver à 0 ne prouve donc RIEN. La décision réelle est prise par `sqlite3TempInMemory`
// (l. 178609-178624), qui CROISE ce réglage local avec la valeur COMPILÉE ; et cette valeur-là ne se lit
// que dans `PRAGMA compile_options` (`TEMP_STORE=N`, que `ctime.c` émet inconditionnellement puisque
// `sqliteInt.h` définit toujours la macro, à 1 par défaut). C'est cette lecture-là qui manquait.
//
// CE QUE LE LOT POSE, DANS CET ORDRE :
//   1. `armer` — LA VOIE UNIQUE : poser les réglages ET RELIRE ce qu'ils valent sur la connexion.
//      Toute connexion de production sur un FICHIER y passe (garde
//      `toute_connexion_sur_fichier_est_armee`), soit directement, soit par la porte (`db_open`), qui
//      arme ses deux ouvertures nues — donc les 24 appelants de la porte d'un seul geste. Mesuré avant
//      correctif : 10 sites d'ouverture, dont les 2 de la porte qui ne posaient RIEN, et par eux 23 des
//      24 chemins d'ouverture de production (seul le daemon posait ces réglages, via son prélude).
//   2. `garde_du_tri_en_memoire` — LE REFUS, en tête de `main`, sur une connexion NUE : si le moteur
//      livré faisait déverser le silence alors que l'exploitant n'a rien demandé, le processus ne
//      démarre pas. Un avertissement ne suffirait pas : quand on le lirait, la fuite serait écrite.
//   3. la bannière ne DÉCRIT plus un réglage attendu, elle RAPPORTE la lecture — dans les deux sens.
//      ET LA LECTURE QU'ELLE RAPPORTE EST CELLE D'UNE CONNEXION ARMÉE (`S38`) : la sonde nue mesure
//      le silence, ce qui est la question du REFUS ; la bannière, elle, répond à « que font les
//      connexions qui servent » — et sur une sonde nue, sous déversement, la réponse était toujours
//      fausse.

/// CE QU'UNE CONNEXION FAIT DE SES TRIS. Trois cas EXCLUSIFS, d'où un type et des `match` EXHAUSTIFS :
/// « je ne sais pas » ne doit jamais pouvoir se déguiser en « tout va bien ».
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Tri {
    /// Le trieur n'a AUCUN chemin de déversement : rien d'un événement ne peut toucher le disque.
    EnMemoire { compile: i64, local: i64 },
    /// Le trieur PEUT déverser : des valeurs d'événement partiraient en clair hors de SQLCipher.
    SurDisque { compile: i64, local: i64 },
    /// Le réglage ne se LIT pas. On ne prétend rien — et l'appelant refuse.
    Illisible(String),
}

/// MIROIR EXACT de `sqlite3TempInMemory` (`sqlite3.c` 3.39.4, l. 178609-178624) : la TABLE que SQLite
/// documente lui-même, pas une intuition. PURE, donc exerçable sur toutes les combinaisons — y compris
/// celles qu'aucune construction ne produit aujourd'hui, qui sont précisément le sujet.
pub(crate) fn tri_en_memoire(compile: i64, local: i64) -> bool {
    match compile {
        1 => local == 2,  // défaut de SQLite : seul un `temp_store=MEMORY` EXPLICITE sauve le silence
        2 => local != 1,  // ce que porte la construction SQLCipher livrée
        3 => true,        // « jamais de fichier temporaire », compilé en dur
        _ => false,       // 0 ou hors bornes : SQLite rend 0 — FICHIER, quel que soit le réglage local
    }
}

/// LA DÉRIVATION, séparée de la LECTURE pour être exerçable sans moteur sous la main.
pub(crate) fn tri_pour(compile: Option<i64>, local: Option<i64>) -> Tri {
    match (compile, local) {
        (Some(c), Some(l)) if tri_en_memoire(c, l) => Tri::EnMemoire { compile: c, local: l },
        (Some(c), Some(l)) => Tri::SurDisque { compile: c, local: l },
        (None, _) => Tri::Illisible("`PRAGMA compile_options` ne nomme aucun TEMP_STORE".into()),
        (Some(_), None) => Tri::Illisible("`PRAGMA temp_store` ne se relit pas".into()),
    }
}

/// LA VALEUR COMPILÉE, LUE DANS LE MOTEUR. C'est la seule chose qui réponde à « que fait une connexion
/// qui ne dit rien » : `PRAGMA temp_store` rendrait 0, qui ne distingue pas les deux mondes.
fn temp_store_compile(conn: &Connection) -> Option<i64> {
    let mut st = conn.prepare("PRAGMA compile_options").ok()?;
    let mut lignes = st.query([]).ok()?;
    while let Ok(Some(r)) = lignes.next() {
        if let Ok(o) = r.get::<_, String>(0) {
            if let Some(v) = o.trim().strip_prefix("TEMP_STORE=") {
                return v.trim().parse().ok();
            }
        }
    }
    None
}

/// CE QUE CETTE CONNEXION-CI fera de ses tris, LU sur elle.
pub(crate) fn lire_tri(conn: &Connection) -> Tri {
    tri_pour(
        temp_store_compile(conn),
        conn.query_row("PRAGMA temp_store", [], |r| r.get::<_, i64>(0)).ok(),
    )
}

/// CE QUE FAIT UNE CONNEXION QUI NE DIT RIEN — la mesure dont dépend toute la garantie.
///
/// `open_in_memory` est DÉLIBÉRÉ et ne restreint pas la portée : `sqlite3TempInMemory` ne regarde que
/// la valeur compilée (une constante du PROCESSUS) et le réglage local de la connexion. Le fichier
/// n'entre pas dans la décision, et sonder un fichier créerait une base pour poser une question de
/// configuration.
///
/// INSTRUMENT VALIDÉ : une sonde dont le réglage local n'est pas 0 n'est PAS nue — elle ne mesure alors
/// pas le silence, et un instrument qui ne peut pas voir son sujet doit le DIRE, pas rendre vert.
pub(crate) fn tri_dune_connexion_nue() -> Tri {
    match Connection::open_in_memory() {
        Ok(c) => match lire_tri(&c) {
            Tri::EnMemoire { local, .. } | Tri::SurDisque { local, .. } if local != 0 => {
                Tri::Illisible(format!("la sonde n'est pas NUE (temp_store local={local})"))
            }
            verdict => verdict,
        },
        Err(e) => Tri::Illisible(format!("connexion de sonde impossible : {e}")),
    }
}

/// CE QUE LA CONNEXION QUI SERT FERA DE SES TRIS — la mesure que la bannière publie (`S38`).
///
/// Lue sur la connexion que la porte a ARMÉE, donc celle dont `PRAGMA temp_store` vaut ce que `armer`
/// a posé : 1 sous déversement, 2 au défaut — et 0 si l'armement n'a PAS eu lieu, auquel cas c'est la
/// contradiction qui se dit (sous déversement : « demandé mais le tri reste en mémoire »), pas un
/// « tout va bien ». Une sonde nue (`tri_dune_connexion_nue`) ne peut PAS répondre à cette question :
/// personne n'y pose `temp_store=FILE`, donc sous déversement elle contredisait le mode à chaque
/// démarrage, et une garde qui alerte toujours ne prouve rien.
///
/// Rendue sous la forme de `S32` parce que la bannière doit pouvoir dire « NON MESURÉ » : un appelant
/// qui n'a pas encore de connexion armée sous la main passe `Mesure::Illisible` avec sa cause, jamais
/// la lecture d'une autre connexion.
pub(crate) fn tri_de_la_connexion_qui_sert(conn: &Connection) -> crate::mesure_environnement::Mesure<Tri> {
    crate::mesure_environnement::Mesure::Lue(lire_tri(conn))
}

/// CE QUE LA LECTURE CONTREDIT. PURE, donc exerçable dans les DEUX sens sans toucher à l'environnement.
/// `None` = la lecture CONFIRME ce que le mode promet ; une garde qui alerterait toujours ne prouverait
/// rien.
pub(crate) fn desaccord_pour(tri: &Tri, deversement: bool) -> Option<String> {
    match (tri, deversement) {
        (Tri::EnMemoire { .. }, false) | (Tri::SurDisque { .. }, true) => None,
        (Tri::SurDisque { compile, local }, false) => Some(format!(
            "LE TRI DÉVERSE ALORS QUE RIEN NE L'A DEMANDÉ (LU : temp_store local={local}, \
             TEMP_STORE={compile} dans compile_options) : des VALEURS D'ÉVÉNEMENT partent EN CLAIR hors \
             de la base SQLCipher, qui ne chiffre PAS les fichiers temporaires de SQLite. \
             PLUME_SQLITE_DEVERSEMENT vaut 0 : cet échange n'a pas été pris."
        )),
        (Tri::EnMemoire { compile, local }, true) => Some(format!(
            "LE DÉVERSEMENT A ÉTÉ DEMANDÉ MAIS LE TRI RESTE EN MÉMOIRE (LU : temp_store local={local}, \
             TEMP_STORE={compile} dans compile_options) : la borne mémoire attendue du trieur n'existe \
             pas, un tri trop large ÉCHOUERA au plafond au lieu de déverser."
        )),
        (Tri::Illisible(e), _) => Some(format!(
            "CE QUE LE MOTEUR FAIT DE SES TRIS N'EST PAS LISIBLE ({e}) : impossible de dire si des \
             valeurs d'événement peuvent partir en clair hors de la base chiffrée."
        )),
    }
}

/// LE CONSTAT, EN CHIFFRES LUS — ce que la bannière publie quand la mesure confirme le mode.
pub(crate) fn constat_de_tri(tri: &Tri) -> String {
    match tri {
        Tri::EnMemoire { compile, local } => format!(
            "un tri reste en MÉMOIRE (temp_store local={local}, TEMP_STORE={compile} dans compile_options)"
        ),
        Tri::SurDisque { compile, local } => format!(
            "un tri DÉVERSE sur le disque (temp_store local={local}, TEMP_STORE={compile} dans compile_options)"
        ),
        Tri::Illisible(e) => format!("réglage NON LISIBLE ({e})"),
    }
}

/// LE REFUS DE DÉMARRER. UNE SEULE des deux directions arrête le processus, et la dissymétrie se dit :
/// un déversement demandé et non obtenu coûte une requête qui échoue, un déversement obtenu sans avoir
/// été demandé coûte la confidentialité — et une fuite ne se rattrape pas.
/// PUR (prend le verdict déjà lu) → les deux sens se testent sans toucher à l'environnement.
pub(crate) fn refus_de_demarrage_pour(tri: &Tri, deversement: bool) -> Option<String> {
    if deversement {
        return None;
    }
    desaccord_pour(tri, deversement).map(|quoi| {
        format!(
            "REFUS DE DÉMARRER — {quoi} Reconstruire la liaison SQLite avec SQLITE_TEMP_STORE=2 (le \
             moteur trie alors en mémoire même pour une connexion muette), ou poser \
             PLUME_SQLITE_DEVERSEMENT=1 pour prendre cet échange EXPLICITEMENT — et placer alors \
             SQLITE_TMPDIR sur un support chiffré."
        )
    })
}

/// LA GARDE DE DÉMARRAGE, appelée UNE FOIS en tête de `main` — avant tout branchement de sous-commande,
/// pour la même raison que `deversement_init` : un appel par sous-commande serait une ÉNUMÉRATION, et
/// c'est ce genre de liste qui a déjà lâché dans ce dépôt. La propriété mesurée est celle du PROCESSUS
/// (valeur compilée + mot d'exploitation), pas celle d'une commande.
pub(crate) fn garde_du_tri_en_memoire() -> Result<(), String> {
    match refus_de_demarrage_pour(&tri_dune_connexion_nue(), deversement_actif()) {
        Some(refus) => Err(refus),
        None => Ok(()),
    }
}

/// LA VOIE UNIQUE D'ARMEMENT D'UNE CONNEXION — POSER LES RÉGLAGES, PUIS RELIRE CE QU'ILS VALENT.
///
/// Les sites de production posaient `pragmas_memoire()` par `let _ = execute_batch(...)` : un batch
/// REFUSÉ (base chiffrée ouverte sans clé, nom de pragma erroné) laissait la connexion NUE sans que rien
/// ne le dise, et la garantie retombait alors sur la seule valeur compilée — c'est-à-dire sur
/// l'affirmation que ce lot remplace. Ici le verdict est RELU sur la connexion et rendu à l'appelant.
///
/// L'ALERTE EST BORNÉE À UNE LIGNE PAR PROCESSUS : le pool de lecture ouvre des connexions en continu,
/// une ligne par ouverture noierait le journal — et un journal noyé n'est pas lu.
pub(crate) fn armer(conn: &Connection) -> Tri {
    armer_avec(conn, pragmas_memoire(), deversement_actif())
}

/// LA MÊME VOIE, PARAMÉTRÉE SUR LE MODE (`S38`). Le processus n'a qu'un mode et `armer` le fige ; une
/// suite de tests tourne au défaut et ne pouvait donc JAMAIS armer une connexion sous déversement —
/// c'est pour cela que le couple « déversement demandé, connexion armée » n'avait pas de témoin. Le batch
/// est DÉRIVÉ du mode par la même fonction que celle qui sert `armer`, pas recopié. Réservée aux
/// suites : en production le mode est celui du processus, et `armer` est la seule voie.
#[cfg(test)]
pub(crate) fn armer_pour(conn: &Connection, deversement: bool) -> Tri {
    armer_avec(conn, &pragmas_memoire_pour(deversement), deversement)
}

fn armer_avec(conn: &Connection, pragmas: &str, deversement: bool) -> Tri {
    let _ = conn.execute_batch(pragmas);
    let verdict = lire_tri(conn);
    if let Some(desaccord) = desaccord_pour(&verdict, deversement) {
        static UNE_FOIS: std::sync::Once = std::sync::Once::new();
        UNE_FOIS.call_once(|| eprintln!("[plafond] {desaccord}"));
    }
    verdict
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

    /// LE DÉFAUT NE DÉVERSE PAS — donc n'écrit RIEN EN CLAIR sur le disque.
    ///
    /// Ce n'est pas une préférence de réglage, c'est une propriété du produit : SQLCipher chiffre le
    /// fichier de base, PAS les fichiers temporaires de SQLite. Mesuré le 2026-08-04 : un tri qui
    /// déverse laisse 323 occurrences lisibles de deux aiguilles du jeu de test dans 16 Mio lus
    /// (contrôle négatif à 0). Basculer ce défaut retire une garantie de confidentialité — ce test
    /// est là pour que ça ne puisse pas se faire par inadvertance.
    ///
    /// LA BANNIÈRE NE PEUT PAS ANNONCER UN DÉVERSEMENT QUI N'A PAS LIEU. C'est le défaut RÉEL corrigé
    /// ici : `server/mod.rs` imprimait « déversement des tris : <chemin> » à CHAQUE démarrage, sans accès au
    /// mode. Un journal qui décrit autre chose que ce qui se passe est pire qu'un journal muet — c'est sur
    /// lui qu'on s'appuiera le jour d'un incident de confidentialité.
    ///
    /// MUTATION : faire rendre le texte de `Vers` au bras `Desactive` ⇒ la 2ᵉ assertion passe au ROUGE.
    #[test]
    fn la_banniere_dit_le_mode_reel() {
        // La lecture d'une connexion ARMÉE au défaut : `temp_store=MEMORY` posé, relu à 2 (`S38`).
        let memoire = crate::mesure_environnement::Mesure::Lue(Tri::EnMemoire { compile: 2, local: 2 });
        let eteint = banniere(Deversement::Desactive, memoire.clone());
        assert!(eteint.contains("DÉSACTIVÉ"), "le mode doit être LISIBLE, pas déduit : {eteint}");
        // L'assertion porte sur le SEGMENT du déversement, pas sur la bannière entière : le rapport de
        // plafond qui la précède peut légitimement nommer un chemin système (`/proc/self/cgroup` quand la
        // limite n'est pas lisible), et le sujet de ce test n'a jamais été celui-là. Bornée ainsi, elle
        // reste exactement aussi forte sur ce qu'elle garde — et elle ne dépend plus de l'hôte qui exécute
        // la suite, alors qu'un `contains("/")` sur le tout aurait rougi selon la machine.
        let segment = eteint
            .split_once("— déversement")
            .unwrap_or_else(|| panic!("la bannière ne porte plus de segment de déversement : {eteint}"))
            .1;
        assert!(
            !segment.contains("/"),
            "AUCUN chemin ne doit apparaître quand rien ne déverse — c'est exactement ce qui mentait : {eteint}"
        );
        let allume = banniere(
            Deversement::Vers(std::path::PathBuf::from("/x/sqltmp"), crate::mesure_environnement::Mesure::Lue(vec![])),
            crate::mesure_environnement::Mesure::Lue(Tri::SurDisque { compile: 2, local: 1 }),
        );
        assert!(allume.contains("/x/sqltmp"), "le chemin qui reçoit du clair doit être NOMMÉ : {allume}");
        assert!(allume.contains("EN CLAIR"), "et ce qu'il reçoit doit être dit : {allume}");
        let casse = banniere(Deversement::Indisponible("montage RO".into()), memoire);
        assert!(casse.contains("INDISPONIBLE") && casse.contains("montage RO"), "la cause doit remonter : {casse}");
    }

    /// MUTATION : inverser `mot_temp_store` fait passer la 1re assertion de `MEMORY` à `FILE`.
    #[test]
    fn le_defaut_ne_deverse_pas_en_clair() {
        assert_eq!(mot_temp_store(false), "MEMORY", "DÉFAUT : aucun déversement, rien en clair sur disque");
        assert_eq!(mot_temp_store(true), "FILE", "opt-in explicite : borne la RAM, au prix du clair sur disque");
    }

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

    /// Le contrôle positif du répertoire temporaire REFUSE ce qui n'est pas inscriptible — sinon il ne
    /// contrôlerait rien.
    #[test]
    fn le_controle_positif_refuse_un_repertoire_inutilisable() {
        assert!(controle_positif(std::path::Path::new("/proc/repertoire-qui-nexiste-pas")).is_err());
    }

    /// LE BUDGET ANNONCÉ EST LE BUDGET IMPOSÉ. C'est LE défaut que ce plafond ferme : `rapport()`
    /// publiait « budget 1088 Mio » depuis le début et RIEN ne l'imposait — `cache_size` ne borne que le
    /// cache de pages, et sous `temp_store=MEMORY` le trieur n'a aucun budget. Le nombre annoncé et le
    /// nombre gravé dans le PRAGMA sortent donc de la MÊME dérivation, et ce test les confronte : écrire
    /// un littéral dans l'un des deux le fait rougir le jour où on l'écrit.
    ///
    /// MUTATION : rendre `plafond_dur_octets()` moitié moindre ⇒ le PRAGMA cesse d'égaler l'annonce
    /// (544 Mio contre 1088) et l'assertion passe au ROUGE.
    #[test]
    fn le_budget_annonce_est_le_budget_impose() {
        let annonce = rapport();
        let mio_annonces: i64 = annonce
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("`rapport()` n'annonce plus un budget en tête : {annonce}"));
        let pragma = Plafond::Applique(plafond_dur_octets()).pragma();
        let octets_graves: i64 = pragma
            .split("hard_heap_limit=")
            .nth(1)
            .and_then(|s| s.trim_end_matches(';').trim().parse().ok())
            .unwrap_or_else(|| panic!("le PRAGMA ne grave plus de plafond : {pragma}"));
        assert_eq!(
            octets_graves,
            mio_annonces * 1048576,
            "le budget PUBLIÉ ({mio_annonces} Mio) et le budget IMPOSÉ ({octets_graves} o) doivent être le \
             MÊME nombre — sinon l'un des deux ment"
        );
        assert_eq!(
            octets_graves,
            porteurs() * cache_ko_pour(budget_ko(), porteurs()) * 1024,
            "et ce nombre est le pire cas du modèle de porteurs, pas une constante posée à côté"
        );
    }

    /// LE DÉFAUT IMPOSE LE PLAFOND, ET LA PHRASE DIT LEQUEL DES DEUX MONDES ON HABITE. Un journal qui
    /// n'annonce pas que le budget est SANS effet laisserait croire à une protection inexistante — c'est
    /// exactement l'erreur que la bannière de déversement avait déjà commise.
    ///
    /// MUTATION : inverser la condition de `plafond_pour` ⇒ le mode `true` cesse de graver un PRAGMA et
    /// la 2ᵉ assertion passe au ROUGE.
    #[test]
    fn le_plafond_dur_est_applique_et_se_lit() {
        let applique = plafond_pour(true, 1_140_850_688);
        assert!(applique.pragma().contains("hard_heap_limit=1140850688"), "{}", applique.pragma());
        assert!(applique.phrase().contains("APPLIQUÉ") && applique.phrase().contains("REFUSE"), "{}", applique.phrase());
        let aucun = plafond_pour(false, 1_140_850_688);
        assert_eq!(aucun.pragma(), "", "sans plafond, AUCUN pragma n'est gravé — le comportement historique est rendu tel quel");
        assert!(
            aucun.phrase().contains("NON APPLIQUÉ") && aucun.phrase().contains("TUE le processus"),
            "un budget sans enforcement doit DIRE ce qu'il n'empêche pas : {}",
            aucun.phrase()
        );
    }

    /// LE REFUS DIT CE QUI N'A PAS EU LIEU, ET QUOI FAIRE. « out of memory » est vrai et inutilisable :
    /// l'analyste ne sait ni si on lui a rendu un résultat partiel, ni quoi changer à sa requête.
    ///
    /// MUTATION : retirer la phrase « AUCUN résultat n'est rendu » ⇒ la 2ᵉ assertion passe au ROUGE — et
    /// c'est la plus importante, parce qu'un total tronqué présenté comme complet est le pire des deux
    /// échecs possibles.
    #[test]
    fn le_refus_de_budget_est_actionnable() {
        let m = refus_budget_pour(&Plafond::Applique(1_140_850_688));
        assert!(m.contains("1088 Mio"), "le refus doit NOMMER le budget franchi : {m}");
        assert!(m.contains("AUCUN résultat"), "il doit dire qu'il ne rend RIEN, pas un partiel : {m}");
        assert!(
            m.contains("fenêtre") && m.contains("filtre") && m.contains("PLUME_SQLITE_BUDGET_MB"),
            "il doit dire quoi faire — côté analyste ET côté exploitant : {m}"
        );
        let sans = refus_budget_pour(&Plafond::Aucun);
        assert!(
            sans.contains("PLUME_SQLITE_PLAFOND_DUR=0"),
            "sans plafond, le refus doit dire que la mémoire s'est épuisée SANS borne : {sans}"
        );
    }

    /// LE REFUS EST DÉRIVÉ DU CODE D'ERREUR, PAS DU TEXTE. Une reconnaissance par sous-chaîne
    /// (`msg.contains("out of memory")`) rendrait le refus dépendant d'une chaîne C qui n'engage personne,
    /// et convertirait n'importe quelle autre erreur portant ces mots. Le contrôle NÉGATIF ci-dessous
    /// porte EXACTEMENT ce texte sous un autre code : il doit ressortir INTACT.
    ///
    /// MUTATION : remplacer le `match` sur `ErrorCode::OutOfMemory` par un `to_string().contains(...)`
    /// ⇒ le contrôle négatif passe au ROUGE (l'erreur BUSY serait traduite en refus de budget).
    #[test]
    fn le_refus_se_reconnait_au_code_pas_au_message() {
        let nomem = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(7), // SQLITE_NOMEM — ce que `mallocWithAlarm` provoque
            Some("out of memory".to_string()),
        );
        assert!(est_manque_de_memoire(&nomem), "SQLITE_NOMEM doit être reconnu");
        assert!(message_erreur(&nomem).contains("budget mémoire dépassé") || message_erreur(&nomem).contains("mémoire épuisée"));

        let menteur = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(5), // SQLITE_BUSY, avec le TEXTE de l'autre
            Some("out of memory".to_string()),
        );
        assert!(!est_manque_de_memoire(&menteur), "le TEXTE ne doit rien décider");
        assert_eq!(
            message_erreur(&menteur),
            menteur.to_string(),
            "toute erreur qui n'est pas un manque de mémoire ressort TELLE QUELLE"
        );
    }

    /// LA BANNIÈRE NE PEUT PAS SE CONTREDIRE ELLE-MÊME. Défaut RÉEL, observé sur le journal du binaire
    /// corrigé le 2026-08-06 : la phrase du plafond disait « une requête qui le franchit REFUSE, le
    /// processus survit » et, six mots plus loin, celle du déversement disait « AUCUN plafond de tri — une
    /// agrégation assez large épuise la RAM ». Les deux venaient d'auteurs différents décrivant LE MÊME
    /// fait. Un journal qui se contredit est pire qu'un journal muet : le jour de l'incident, on ne saura
    /// pas laquelle des deux phrases croire.
    ///
    /// MUTATION : rendre à la branche `Desactive` son ancienne phrase (« AUCUN plafond de tri ») ⇒ la 2ᵉ
    /// assertion passe au ROUGE.
    #[test]
    fn la_banniere_ne_se_contredit_pas_sur_le_plafond() {
        let b = banniere(
            Deversement::Desactive,
            crate::mesure_environnement::Mesure::Lue(Tri::EnMemoire { compile: 2, local: 2 }),
        );
        // Ce test ne vaut que si le plafond est bien APPLIQUÉ au défaut — sinon il passerait sans rien
        // prouver. La précondition est donc EXPLICITE.
        assert!(b.contains("APPLIQUÉ par l'allocateur"), "précondition : le défaut applique le plafond : {b}");
        assert!(
            !b.contains("AUCUN plafond"),
            "la bannière annonce un plafond APPLIQUÉ puis nie son existence — une seule des deux phrases \
             peut être vraie : {b}"
        );
        assert!(
            b.contains("ÉCHOUE au plafond"),
            "la branche déversement doit RENVOYER au plafond au lieu d'en décrire un autre : {b}"
        );
    }

    /// UN PLAFOND AU-DESSUS DE CE QUI NOUS TUE NE PROTÈGE DE RIEN, ET LA BANNIÈRE DOIT LE DIRE. C'est la
    /// limite MESURÉE de ce correctif : un budget de 1088 Mio dans un conteneur de 1 Gio laisse
    /// l'OOM-killer arriver le premier — mesuré au banc le 2026-08-06, le groupe `P` (cgroup 1 Gio, budget
    /// livré) TUE toujours, tandis que le groupe `M` (même cgroup, budget 512 Mio) refuse proprement.
    /// Annoncer « plafond APPLIQUÉ » sans confronter les deux nombres serait exactement le genre de phrase
    /// vraie et trompeuse que la bannière de déversement a déjà coûté.
    ///
    /// LES DEUX DERNIERS CAS SONT LES PLUS IMPORTANTS, ET ILS SONT DEUX : « je n'ai pas pu lire » et « il
    /// n'y a pas de limite » ne sont PAS le même verdict. Les confondre — ce que faisait un `Option`
    /// unique — accuse l'instrument sur un hôte parfaitement lisible qui ne borne simplement rien, et
    /// laisse croire à une propriété du déploiement sur un hôte dont on n'a rien mesuré.
    ///
    /// MUTATION : faire rendre `Protege` au cas `budget >= limite` ⇒ la 2ᵉ assertion passe au ROUGE ;
    /// faire rendre `SansLimite` au bras `Illisible` de `couverture_pour` ⇒ la 4ᵉ passe au ROUGE.
    #[test]
    fn la_couverture_confronte_le_budget_a_la_limite_qui_tue() {
        let gio = 1024 * 1024 * 1024;
        let p = couverture_pour(512 * 1024 * 1024, LimiteCgroup::Octets(gio)).phrase();
        assert!(p.contains("sous la limite") && p.contains("1024 Mio"), "{p}");
        assert!(p.contains("[couverture=protege]") && !p.contains("AVERTISSEMENT"), "seul ce cas est calme : {p}");
        let d = couverture_pour(1088 * 1024 * 1024, LimiteCgroup::Octets(gio)).phrase();
        assert!(
            d.contains("NE PROTÈGE PAS") && d.contains("PLUME_SQLITE_BUDGET_MB"),
            "un budget au-dessus de la limite doit être dénoncé, avec le levier pour le corriger : {d}"
        );
        assert!(d.contains("AVERTISSEMENT [couverture=depasse]"), "et la bascule doit être un SIGNAL : {d}");
        let s = couverture_pour(1088 * 1024 * 1024, LimiteCgroup::Aucune).phrase();
        assert!(
            s.contains("AUCUNE limite") && !s.contains("NON LISIBLE"),
            "« pas de limite » est une LECTURE RÉUSSIE, pas une panne d'instrument : {s}"
        );
        assert!(
            s.contains("AVERTISSEMENT [couverture=sans-limite]") && s.contains("MemoryMax="),
            "une protection absente doit crier, et dire par quoi la poser dans les trois modes : {s}"
        );
        let i = couverture_pour(1088 * 1024 * 1024, LimiteCgroup::Illisible("montage absent".into())).phrase();
        assert!(i.contains("NON LISIBLE") && i.contains("montage absent"), "l'ignorance s'avoue, AVEC sa cause : {i}");
        assert!(
            i.contains("AVERTISSEMENT [couverture=illisible]") && !i.contains("AUCUNE limite"),
            "et elle ne se déguise pas en « pas de limite » : {i}"
        );
        // LES QUATRE VERDICTS SONT DISTINCTS DEUX À DEUX — sans ça, deux d'entre eux pourraient partager
        // un mot et une supervision ne les séparerait pas.
        let mots = [
            couverture_pour(1, LimiteCgroup::Octets(gio)).verdict(),
            couverture_pour(gio, LimiteCgroup::Octets(gio)).verdict(),
            couverture_pour(1, LimiteCgroup::Aucune).verdict(),
            couverture_pour(1, LimiteCgroup::Illisible(String::new())).verdict(),
        ];
        let mut uniques = mots.to_vec();
        uniques.sort_unstable();
        uniques.dedup();
        assert_eq!(uniques.len(), 4, "les mots de verdict doivent être DISTINCTS : {mots:?}");
        // Le cas limite EXACT : budget == limite ne protège pas non plus (il ne reste rien pour le reste
        // du processus). La comparaison est STRICTE, et ce contrôle interdit de la relâcher en `<=`.
        let e = couverture_pour(gio, LimiteCgroup::Octets(gio)).phrase();
        assert!(e.contains("NE PROTÈGE PAS"), "budget == limite ne protège pas : {e}");
    }

    /// SQLITE ACCEPTE-T-IL VRAIMENT LE PRAGMA ? Deux échecs silencieux sont possibles et ce test les ferme
    /// tous les deux : (a) un nom de pragma erroné ferait échouer le batch ENTIER — `temp_store` et
    /// `cache_size` ne seraient plus posés non plus, et rien ne le dirait (le site d'appel fait `let _ =`) ;
    /// (b) SQLite pourrait ACCEPTER le réglage sans rien en faire — c'est précisément ce que fait
    /// `soft_heap_limit` sur un trieur, et c'est pour ça qu'on RELIT la valeur au lieu de supposer.
    ///
    /// CONTRÔLE POSITIF, pas une affirmation : la valeur relue vient de `sqlite3_hard_heap_limit64(-1)`,
    /// donc de l'état RÉEL de l'allocateur du processus.
    ///
    /// MUTATION : écrire `hard_heap_limitx=` dans `Plafond::pragma` ⇒ `execute_batch` échoue et la 1re
    /// assertion passe au ROUGE.
    #[test]
    fn sqlite_accepte_le_plafond_et_le_relit() {
        let conn = Connection::open_in_memory().expect("connexion mémoire");
        conn.execute_batch(pragmas_memoire())
            .unwrap_or_else(|e| panic!("le batch de PRAGMA mémoire a été REFUSÉ par SQLite : {e}"));
        let relu: i64 = conn.query_row("PRAGMA hard_heap_limit", [], |r| r.get(0)).expect("relecture du plafond");
        assert_eq!(
            relu,
            plafond_dur_octets(),
            "SQLite doit PORTER le plafond, pas seulement l'avoir accepté (relu={relu})"
        );
        // Le reste du batch a bien été appliqué : sans ça, un plafond posé au prix des deux autres réglages
        // serait une régression déguisée en correctif.
        let cache: i64 = conn.query_row("PRAGMA cache_size", [], |r| r.get(0)).expect("relecture du cache");
        assert_eq!(cache, -cache_ko_pour(budget_ko(), porteurs()), "le cache_size du même batch doit être posé");
    }

    /// FABRIQUE une arborescence de groupes de contrôle DANS un temporaire possédé : la racine du
    /// montage, le fichier qui joue `/proc/self/cgroup`, et les fichiers de limite demandés. AUCUN chemin
    /// de la machine hôte n'entre ici — c'est ce qui rend les tests ci-dessous indépendants de la machine
    /// qui les exécute : ils rendent le même verdict sur un poste sans limite et dans un conteneur borné.
    fn faux_cgroup(tmp: &crate::tmp_possede::TmpPossede, proc_txt: &str, fichiers: &[(&str, &str)]) -> (PathBuf, PathBuf) {
        let racine = tmp.join("cgroup");
        std::fs::create_dir_all(&racine).expect("fixture : racine de cgroup");
        for (rel, contenu) in fichiers {
            let f = racine.join(rel);
            std::fs::create_dir_all(f.parent().expect("fixture : parent")).expect("fixture : niveau");
            std::fs::write(&f, contenu).expect("fixture : fichier de limite");
        }
        let proc_f = tmp.join("proc-self-cgroup");
        std::fs::write(&proc_f, proc_txt).expect("fixture : /proc/self/cgroup");
        (racine, proc_f)
    }

    /// « PAS DE LIMITE » ET « PAS LISIBLE » NE S'ÉCRIVENT PAS PAREIL, ET NE SE CONCLUENT PAS PAREIL. Les
    /// deux versions de l'interface disent « pas de limite » différemment : v2 écrit le mot `max`, v1
    /// écrit un entier énorme. Une forme qui n'est NI l'une NI l'autre est une IGNORANCE, jamais une
    /// absence de limite — c'est tout le défaut que ce module ferme.
    ///
    /// LA SENTINELLE `u64::MAX` EST LE CAS QUI MANQUAIT : elle ne rentre pas dans un `i64`, donc l'ancien
    /// `parse::<i64>()` la comptait comme illisible et la bannière annonçait une panne de mesure là où
    /// l'interface avait parfaitement répondu « aucune limite ».
    ///
    /// MUTATION DANS LES DEUX SENS : faire rendre `Aucune` au bras `Err` ⇒ la dernière boucle passe au
    /// ROUGE (une forme inconnue serait prise pour une absence de limite) ; retirer le test du mot `max`
    /// ⇒ la 1re assertion passe au ROUGE (une absence de limite serait prise pour une panne).
    #[test]
    fn la_valeur_de_limite_distingue_pas_de_limite_et_pas_lisible() {
        assert_eq!(valeur_limite("max\n"), LimiteCgroup::Aucune, "cgroup v2 écrit `max` pour « aucune limite »");
        assert_eq!(valeur_limite("  max  "), LimiteCgroup::Aucune, "les espaces du fichier ne décident de rien");
        assert_eq!(valeur_limite("1073741824\n"), LimiteCgroup::Octets(1073741824), "une limite se lit telle quelle");
        assert_eq!(
            valeur_limite("9223372036854771712"),
            LimiteCgroup::Aucune,
            "cgroup v1 : `i64::MAX` arrondi à la page EST la façon d'écrire « aucune limite »"
        );
        assert_eq!(
            valeur_limite("18446744073709551615"),
            LimiteCgroup::Aucune,
            "et `u64::MAX` aussi — cette forme ne rentrait pas dans un i64 et passait donc pour illisible"
        );
        for forme in ["", "   ", "unlimited", "max 0", "-1", "1073741824 extra", "0x40000000"] {
            assert!(
                matches!(valeur_limite(forme), LimiteCgroup::Illisible(_)),
                "une forme non reconnue ({forme:?}) est une IGNORANCE, jamais une absence de limite"
            );
        }
    }

    /// LA LIGNÉE cgroup v2 EST VRAIMENT PARCOURUE, ET LE PLUS SERRÉ GAGNE. Un parent plus serré tue avant
    /// la feuille : ne lire que la feuille annoncerait une couverture qui n'existe pas. Les quatre formes
    /// jouées ici sont celles que le module recense (1) à (4).
    ///
    /// MUTATION : ne lire QUE la feuille (retirer la remontée) ⇒ la 1re assertion passe au ROUGE (elle
    /// rendrait la limite large du niveau feuille au lieu de la limite serrée du parent).
    #[test]
    fn la_lecture_du_cgroup_v2_parcourt_la_lignee() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("cgroup-v2");

        // (1) le PARENT est plus serré que la feuille : c'est lui qui tue.
        let (racine, proc_f) = faux_cgroup(
            &tmp,
            "0::/parent/feuille\n",
            &[("parent/memory.max", "268435456\n"), ("parent/feuille/memory.max", "1073741824\n")],
        );
        assert_eq!(
            limite_cgroup_depuis(&racine, &proc_f),
            LimiteCgroup::Octets(268435456),
            "la limite EFFECTIVE est la plus petite de la lignée, pas celle de la feuille"
        );

        // (2)+(3) tous les niveaux disent `max`, et la RACINE n'a pas de `memory.max` du tout — ce qui est
        // le comportement normal du noyau. Verdict : AUCUNE limite, et surtout PAS « illisible ».
        let tmp2 = crate::tmp_possede::TmpPossede::neuf("cgroup-v2-max");
        let (racine2, proc2) = faux_cgroup(
            &tmp2,
            "0::/tranche/service\n",
            &[("tranche/memory.max", "max\n"), ("tranche/service/memory.max", "max\n")],
        );
        assert_eq!(
            limite_cgroup_depuis(&racine2, &proc2),
            LimiteCgroup::Aucune,
            "une lignée entièrement lue qui ne borne rien est une ABSENCE DE LIMITE, pas une panne de mesure"
        );

        // (4) conteneur avec espace de noms de cgroup : le chemin est `/`, et la limite est à la RACINE
        // visible. C'est l'exception à (3) — si la racine n'était pas lue, la limite du conteneur, qui est
        // exactement celle qui tue, serait manquée.
        let tmp3 = crate::tmp_possede::TmpPossede::neuf("cgroup-v2-ns");
        let (racine3, proc3) = faux_cgroup(&tmp3, "0::/\n", &[("memory.max", "536870912\n")]);
        assert_eq!(
            limite_cgroup_depuis(&racine3, &proc3),
            LimiteCgroup::Octets(536870912),
            "conteneur namespacé : la racine VISIBLE porte la limite"
        );
    }

    /// LE REPLI cgroup v1, ET L'HYBRIDE. Forme (6) : aucune ligne `0::` porteuse, la limite vit dans le
    /// fichier historique. Forme (7) : la ligne `0::` existe mais la hiérarchie unifiée ne porte pas le
    /// contrôleur mémoire — aucun `memory.max` nulle part, et c'est le repli qui tranche.
    ///
    /// MUTATION : supprimer le repli v1 ⇒ les deux assertions passent au ROUGE en rendant `Illisible` là
    /// où l'interface répondait.
    #[test]
    fn la_lecture_du_cgroup_v1_et_hybride_tranchent() {
        let tmp = crate::tmp_possede::TmpPossede::neuf("cgroup-v1");
        let (racine, proc_f) = faux_cgroup(
            &tmp,
            "7:memory:/plume\n1:name=systemd:/plume\n",
            &[("memory/memory.limit_in_bytes", "2147483648\n")],
        );
        assert_eq!(limite_cgroup_depuis(&racine, &proc_f), LimiteCgroup::Octets(2147483648), "v1 pur");

        // v1 « illimité » : la sentinelle est une LECTURE RÉUSSIE.
        let tmp2 = crate::tmp_possede::TmpPossede::neuf("cgroup-v1-illimite");
        let (racine2, proc2) = faux_cgroup(
            &tmp2,
            "7:memory:/\n",
            &[("memory/memory.limit_in_bytes", "9223372036854771712\n")],
        );
        assert_eq!(limite_cgroup_depuis(&racine2, &proc2), LimiteCgroup::Aucune, "v1 sans limite");

        // hybride : la ligne `0::` existe, son arborescence ne porte aucun `memory.max`, le v1 tranche.
        let tmp3 = crate::tmp_possede::TmpPossede::neuf("cgroup-hybride");
        let (racine3, proc3) = faux_cgroup(
            &tmp3,
            "0::/unifie\n7:memory:/plume\n",
            &[("memory/memory.limit_in_bytes", "1073741824\n")],
        );
        assert_eq!(limite_cgroup_depuis(&racine3, &proc3), LimiteCgroup::Octets(1073741824), "hybride v1+v2");
    }

    /// CE QUI N'A PAS ÉTÉ LU SE DIT, AVEC LE CHEMIN TENTÉ. Trois façons de ne rien savoir : le chemin du
    /// processus ne correspond à rien sous le montage (forme 5 : conteneur SANS espace de noms), le
    /// fichier qui décrit le processus n'existe pas (forme 8), et un fichier de limite PRÉSENT dont la
    /// forme n'est pas reconnue — le cas que l'ancien `if let Ok(...)` avalait en silence.
    ///
    /// FAIL-CLOSED SUR UNE LIGNÉE PARTIELLE : un niveau illisible interdit de conclure sur le minimum des
    /// autres, parce qu'il pourrait porter une limite PLUS SERRÉE. Annoncer « protégé » sur la foi des
    /// niveaux lisibles, ce serait revendiquer une couverture non établie.
    ///
    /// MUTATION DANS LES DEUX SENS : c'est ce test-ci qui prouve le sens « forme inconnue ⇒ ILLISIBLE » ;
    /// le test de la lignée ci-dessus prouve l'autre sens, « forme valide ⇒ limite lue » — sans quoi une
    /// fonction qui rendrait TOUJOURS `Illisible` passerait celui-ci sans rien prouver.
    #[test]
    fn la_lecture_du_cgroup_avoue_au_lieu_de_conclure() {
        // (5) le chemin vient de l'HÔTE, le montage est la feuille : rien à lire sous la racine.
        let tmp = crate::tmp_possede::TmpPossede::neuf("cgroup-hors-ns");
        let (racine, proc_f) = faux_cgroup(&tmp, "0::/moteur/conteneur-absent\n", &[]);
        match limite_cgroup_depuis(&racine, &proc_f) {
            LimiteCgroup::Illisible(pourquoi) => assert!(
                pourquoi.contains("conteneur-absent") && pourquoi.contains("memory.limit_in_bytes"),
                "l'aveu doit NOMMER ce qui a été tenté, des deux côtés : {pourquoi}"
            ),
            autre => panic!("un chemin qui ne mène à rien doit rendre ILLISIBLE, pas {autre:?}"),
        }

        // (8) rien du tout : ni description du processus, ni fichier historique.
        let tmp2 = crate::tmp_possede::TmpPossede::neuf("cgroup-neant");
        let racine2 = tmp2.join("cgroup-inexistant");
        let proc2 = tmp2.join("proc-inexistant");
        match limite_cgroup_depuis(&racine2, &proc2) {
            LimiteCgroup::Illisible(pourquoi) => {
                assert!(pourquoi.contains("proc-inexistant"), "le fichier manquant se nomme : {pourquoi}")
            }
            autre => panic!("sans aucune interface, le verdict est ILLISIBLE, pas {autre:?}"),
        }

        // UNE FORME PRÉSENTE MAIS NON RECONNUE — le cœur de la clé : elle ne doit surtout pas se ranger
        // du côté « pas de limite ». Le niveau parent porte une limite parfaitement lisible : le verdict
        // reste ILLISIBLE quand même, et il le dit.
        let tmp3 = crate::tmp_possede::TmpPossede::neuf("cgroup-forme-inconnue");
        let (racine3, proc3) = faux_cgroup(
            &tmp3,
            "0::/parent/feuille\n",
            &[("parent/memory.max", "1073741824\n"), ("parent/feuille/memory.max", "illimité\n")],
        );
        match limite_cgroup_depuis(&racine3, &proc3) {
            LimiteCgroup::Illisible(pourquoi) => assert!(
                pourquoi.contains("forme non reconnue") && pourquoi.contains("plus serré"),
                "un niveau illisible interdit de conclure sur les autres, et l'aveu le DIT : {pourquoi}"
            ),
            autre => panic!("une forme non reconnue rend ILLISIBLE, jamais {autre:?}"),
        }

        // ET LE MÊME CAS, VU PAR LA BANNIÈRE : c'est la propriété qui compte pour l'exploitant.
        let dite = couverture_pour(1088 * 1024 * 1024, limite_cgroup_depuis(&racine3, &proc3)).phrase();
        assert!(
            dite.contains("[couverture=illisible]") && !dite.contains("[couverture=sans-limite]"),
            "la bascule se lit dans le mot de verdict : {dite}"
        );
    }

    /// LA LECTURE RÉELLE EST EXERCÉE, ET SON VERDICT EST L'UN DES QUATRE. Les tests ci-dessus jouent des
    /// arborescences fabriquées ; celui-ci appelle la fonction telle que la production l'appelle, sur la
    /// machine qui exécute la suite. Il n'ASSERTE PAS un verdict particulier — ce serait un test qui ne
    /// passerait que sur un hôte donné — mais il exige que le verdict soit CONSTRUIT, NOMMÉ, et cohérent
    /// avec la phrase publiée. Un `panic` de la lecture, une phrase muette ou un mot de verdict absent
    /// rougiraient ici quelle que soit la machine.
    #[test]
    fn la_lecture_reelle_rend_un_verdict_nomme() {
        let c = couverture_pour(plafond_dur_octets(), limite_cgroup());
        let mot = c.verdict();
        assert!(
            ["protege", "depasse", "sans-limite", "illisible"].contains(&mot),
            "verdict hors contrat : {mot}"
        );
        let phrase = c.phrase();
        assert!(phrase.contains(&format!("[couverture={mot}]")), "la phrase doit PORTER le verdict : {phrase}");
        assert_eq!(
            c.protege(),
            !phrase.contains("AVERTISSEMENT"),
            "le mot d'alerte est DÉRIVÉ du verdict : seul « protégé » est calme ({phrase})"
        );
        assert!(rapport().contains(&format!("[couverture={mot}]")), "et le rapport de démarrage la publie");
    }
}

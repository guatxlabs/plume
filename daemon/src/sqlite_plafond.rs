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
//!   - LE PLAFOND NE PROTÈGE QUE S'IL EST SOUS LA LIMITE QUI TUE (cf. `Couverture`). MESURÉ le 2026-08-06 :
//!     dans un cgroup de 1 Gio avec le budget LIVRÉ (1088 Mio), `stats dc(message)` tue toujours le
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
/// DÉFAUT = `MEMORY` : c'est ce qui tourne en production, et c'est la recommandation de SQLCipher
/// pour cette raison exacte. Le prix est connu et assumé : sans mécanisme de déversement, un tri
/// non couvert par un index croît jusqu'à la limite du cgroup. En production ce plafond n'est pas
/// atteint (RSS 225 Mio pour 2 Gio) ; il l'a été sur un banc dont les événements sont 4,4× plus gros.
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

/// UN PLAFOND NE PROTÈGE QUE S'IL EST SOUS CE QUI NOUS TUE. Un budget de 1088 Mio dans un conteneur limité
/// à 1 Gio est une protection IMAGINAIRE : l'OOM-killer arrive avant l'allocateur. La bannière ne peut donc
/// pas se contenter d'annoncer le budget — elle doit le CONFRONTER à la limite réelle, ou avouer qu'elle
/// ne la lit pas. Trois cas EXCLUSIFS, `match` exhaustif : c'est la seule façon que le cas « je ne sais
/// pas » ne se déguise pas en « tout va bien ».
enum Couverture {
    /// Le budget tient sous la limite mesurée : le refus arrive AVANT l'OOM-killer.
    Protege { limite: i64 },
    /// La limite existe et le budget ne tient pas dessous. Le processus mourra avant de refuser.
    Depasse { limite: i64 },
    /// Aucune limite lisible (pas de cgroup, montage absent, `max`). On ne prétend rien.
    Inconnue,
}

/// LA LIMITE QUI NOUS TUE, LUE SUR LE SYSTÈME — jamais supposée. cgroup v2 : le chemin du processus dans
/// `/proc/self/cgroup`, et la limite EFFECTIVE est la PLUS PETITE de la lignée (un parent plus serré tue
/// avant la feuille) -> on remonte jusqu'à la racine. cgroup v1 : le fichier historique. Rien de lisible
/// -> `None`, et l'appelant l'AVOUE.
fn limite_cgroup_octets() -> Option<i64> {
    let racine = std::path::Path::new("/sys/fs/cgroup");
    let mut mini: Option<i64> = None;
    if let Ok(txt) = std::fs::read_to_string("/proc/self/cgroup") {
        if let Some(chemin) = txt.lines().find_map(|l| l.strip_prefix("0::")) {
            let mut ici = racine.join(chemin.trim_start_matches('/'));
            loop {
                if let Ok(v) = std::fs::read_to_string(ici.join("memory.max")) {
                    if let Ok(n) = v.trim().parse::<i64>() {
                        mini = Some(mini.map_or(n, |m: i64| m.min(n)));
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
        }
    }
    if mini.is_none() {
        // cgroup v1 : une valeur « illimitée » y est un entier ÉNORME (i64::MAX arrondi à la page), pas un
        // mot-clef. On la traite comme absente plutôt que de publier un plafond de 8 Eio.
        if let Ok(v) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes") {
            if let Ok(n) = v.trim().parse::<i64>() {
                if n < (1 << 50) {
                    mini = Some(n);
                }
            }
        }
    }
    mini
}

/// PURE : la confrontation, séparée de la LECTURE, donc exerçable dans les trois états sans cgroup sous la
/// main. `limite` vient de `limite_cgroup_octets`.
fn couverture_pour(budget: i64, limite: Option<i64>) -> Couverture {
    match limite {
        Some(l) if budget < l => Couverture::Protege { limite: l },
        Some(l) => Couverture::Depasse { limite: l },
        None => Couverture::Inconnue,
    }
}

impl Couverture {
    fn phrase(&self) -> String {
        match self {
            Couverture::Protege { limite } => {
                format!(", sous la limite mémoire du cgroup ({} Mio)", limite / 1048576)
            }
            Couverture::Depasse { limite } => format!(
                ", MAIS la limite mémoire du cgroup est {} Mio : LE PLAFOND NE PROTÈGE PAS — l'OOM-killer \
                 arrivera avant le refus. Baisser PLUME_SQLITE_BUDGET_MB sous cette limite.",
                limite / 1048576
            ),
            Couverture::Inconnue => ", limite mémoire du cgroup NON LISIBLE : impossible de dire si ce \
                                     budget protège de l'OOM-killer"
                .to_string(),
        }
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
    P.get_or_init(|| {
        format!(
            "PRAGMA temp_store={}; PRAGMA mmap_size=268435456; PRAGMA cache_size={};{}",
            mot_temp_store(deversement_actif()),
            -cache_ko_pour(budget_ko(), porteurs()),
            plafond_courant().pragma()
        )
    })
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
        couverture_pour(plafond_dur_octets(), limite_cgroup_octets()).phrase()
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
    /// Demandé par `PLUME_SQLITE_DEVERSEMENT=1` ET obtenu : ce répertoire recevra du clair.
    Vers(std::path::PathBuf),
    /// Demandé et NON obtenu — le cas qui mérite l'alerte, parce que SQLite retombera silencieusement.
    Indisponible(String),
}

/// LE SEUL point qui décide ET rapporte. La bannière était écrite dans `server.rs`, qui n'a pas accès au
/// mode : elle annonçait « déversement des tris : <chemin> » À CHAQUE DÉMARRAGE, y compris quand rien ne
/// déverse — une phrase fausse dans le journal, et la branche d'erreur alertait sur un plafond inexistant.
/// La rendre ICI ferme l'écart par construction : le `match` est EXHAUSTIF (aucun bras `_`), donc un mode
/// ajouté demain ne compile pas tant que sa phrase n'est pas écrite.
///
/// PURE, et c'est délibéré : elle prend le mode DÉJÀ résolu au lieu de le résoudre elle-même, donc les
/// TROIS branches se testent sans toucher au disque ni à l'environnement.
pub(crate) fn banniere(mode: Deversement) -> String {
    let r = rapport();
    match mode {
        Deversement::Desactive => format!(
            "{r} — déversement des tris DÉSACTIVÉ (défaut) : aucune valeur d'événement en clair hors de \
             la base chiffrée. Un tri trop large ne déverse donc pas : il ÉCHOUE au plafond ci-dessus. \
             PLUME_SQLITE_DEVERSEMENT=1 échange cette confidentialité contre des tris qui aboutissent."
        ),
        Deversement::Vers(d) => format!(
            "{r} — déversement des tris ACTIVÉ vers {} : ce répertoire reçoit des VALEURS D'ÉVÉNEMENT EN \
             CLAIR, hors de la base SQLCipher. Il doit être sur un support chiffré.",
            d.display()
        ),
        Deversement::Indisponible(e) => format!(
            "{r} — déversement des tris DEMANDÉ mais répertoire INDISPONIBLE ({e}) : SQLite retombera sur \
             TMPDIR/var/tmp/tmp, qui est un tmpfs (donc de la RAM) sur la plupart des hôtes systemd -> le \
             déversement n'y borne RIEN"
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
        Ok(d) => Deversement::Vers(d),
        Err(e) => Deversement::Indisponible(e),
    }
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
/// SILENCE — et le silence, ici, vaut `/tmp`.
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

    /// LE DÉFAUT NE DÉVERSE PAS — donc n'écrit RIEN EN CLAIR sur le disque.
    ///
    /// Ce n'est pas une préférence de réglage, c'est une propriété du produit : SQLCipher chiffre le
    /// fichier de base, PAS les fichiers temporaires de SQLite. Mesuré le 2026-08-04 : un tri qui
    /// déverse laisse 323 occurrences lisibles de deux aiguilles du jeu de test dans 16 Mio lus
    /// (contrôle négatif à 0). Basculer ce défaut retire une garantie de confidentialité — ce test
    /// est là pour que ça ne puisse pas se faire par inadvertance.
    ///
    /// LA BANNIÈRE NE PEUT PAS ANNONCER UN DÉVERSEMENT QUI N'A PAS LIEU. C'est le défaut RÉEL corrigé
    /// ici : `server.rs` imprimait « déversement des tris : <chemin> » à CHAQUE démarrage, sans accès au
    /// mode. Un journal qui décrit autre chose que ce qui se passe est pire qu'un journal muet — c'est sur
    /// lui qu'on s'appuiera le jour d'un incident de confidentialité.
    ///
    /// MUTATION : faire rendre le texte de `Vers` au bras `Desactive` ⇒ la 2ᵉ assertion passe au ROUGE.
    #[test]
    fn la_banniere_dit_le_mode_reel() {
        let eteint = banniere(Deversement::Desactive);
        assert!(eteint.contains("DÉSACTIVÉ"), "le mode doit être LISIBLE, pas déduit : {eteint}");
        assert!(
            !eteint.contains("/") ,
            "AUCUN chemin ne doit apparaître quand rien ne déverse — c'est exactement ce qui mentait : {eteint}"
        );
        let allume = banniere(Deversement::Vers(std::path::PathBuf::from("/x/sqltmp")));
        assert!(allume.contains("/x/sqltmp"), "le chemin qui reçoit du clair doit être NOMMÉ : {allume}");
        assert!(allume.contains("EN CLAIR"), "et ce qu'il reçoit doit être dit : {allume}");
        let casse = banniere(Deversement::Indisponible("montage RO".into()));
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
        let b = banniere(Deversement::Desactive);
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
    /// LE TROISIÈME CAS EST LE PLUS IMPORTANT : ne pas savoir doit se DIRE, jamais se taire.
    ///
    /// MUTATION : faire rendre `Protege` au cas `budget >= limite` ⇒ la 2ᵉ assertion passe au ROUGE.
    #[test]
    fn la_couverture_confronte_le_budget_a_la_limite_qui_tue() {
        let gio = 1024 * 1024 * 1024;
        let p = couverture_pour(512 * 1024 * 1024, Some(gio)).phrase();
        assert!(p.contains("sous la limite") && p.contains("1024 Mio"), "{p}");
        let d = couverture_pour(1088 * 1024 * 1024, Some(gio)).phrase();
        assert!(
            d.contains("NE PROTÈGE PAS") && d.contains("PLUME_SQLITE_BUDGET_MB"),
            "un budget au-dessus de la limite doit être dénoncé, avec le levier pour le corriger : {d}"
        );
        let i = couverture_pour(1088 * 1024 * 1024, None).phrase();
        assert!(i.contains("NON LISIBLE"), "l'ignorance s'avoue : {i}");
        // Le cas limite EXACT : budget == limite ne protège pas non plus (il ne reste rien pour le reste
        // du processus). La comparaison est STRICTE, et ce contrôle interdit de la relâcher en `<=`.
        let e = couverture_pour(gio, Some(gio)).phrase();
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
}

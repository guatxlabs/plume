//! cold_store::enonces — LES ÉNONCÉS SQL DU VIEILLISSEMENT, ÉCRITS UNE SEULE FOIS, ET LA BANDE QU'ILS
//! INTERROGENT.
//!
//! POURQUOI CE MODULE EXISTE. `P10.13-a` : la passe horaire de vieillissement lisait **presque toute la
//! base** (près d'un Gio) et tenait `db.lock()` **des dizaines de secondes** pour découvrir **quelques
//! centaines de lignes** de travail (relevé sur une base réelle les 2026-08-10/11). L'INSTRUMENT A TRANCHÉ
//! le 2026-08-11 : `cold-aging-plan` a montré que ce coût est porté par UN SEUL énoncé — le dead-man's-switch
//! de retard (n° 5), `SCAN e`, un balayage complet de `event` — et que les huit autres totalisent **quelques
//! dizaines de millisecondes**, la découverte (n° 1, longtemps accusée) comprise, INDEXÉE. Le soupçon
//! portait donc sur le mauvais énoncé, et c'est la mesure, pas la relecture, qui l'a dit. Ce qui reste NON
//! établi est plus étroit : pourquoi le planificateur refuse `idx_event_ts` à CET énoncé alors qu'il
//! l'accorde aux autres — une réplique locale au même volume (mêmes 7 index, même distribution, quelques
//! dizaines de seals) ne reproduit ce refus sous AUCUNE des variantes essayées
//! (sans stats, `ANALYZE` complet, `analysis_limit` 400/2000, `sqlite_stat4` retiré, nombre de lignes
//! truqué de 100 à 800 000, littéraux vs paramètres liés) — sauf une : `idx_event_ts` ABSENT, cas exclu
//! sur la base réelle parce que `premiere_page_froide` et `compte_et_max_id_du_jour`, qui s'effondrent sans
//! lui (mesuré sur la réplique : quatre ordres de grandeur de pas de machine en plus), y tiennent dans
//! les dizaines de millisecondes.
//!
//! CE QUE LE LEVIER ① A CHANGÉ, ET CE QU'IL N'A PAS CHANGÉ (2026-08-14). L'énoncé n° 5 est INTACT —
//! même texte, mêmes bornes, même chose détectée. Ce qui change est QUAND la passe l'exécute : une fois
//! par jour au lieu de vingt-quatre. Le chiffre, relevé sur une base réelle le 2026-08-13 sur près de
//! deux jours de passes horaires : **deux passes utiles, toutes les autres sans le moindre travail** — plus
//! de 95 % du temps de `db.lock()` tenu pour rien. La columnarisation n'a lieu qu'UNE FOIS PAR JOUR (un jour franchit la fenêtre
//! chaude) ; les 23 autres passes horaires ne peuvent rien faire PAR CONSTRUCTION. Ce module porte donc
//! aussi la DÉCISION DE TIR (`tir_du_retard`, `periode_de_tir`, `TirDuRetard`), pour la même raison qu'il
//! porte déjà les bornes : la passe et la sonde doivent lire la MÊME cadence, ou la sonde décrirait une
//! passe qui n'existe pas.
//!
//! CE QUE ce module GARANTIT, ET COMMENT. La sonde de lecture seule (`sonde`) doit rejouer LES ÉNONCÉS
//! DE LA PASSE, pas des copies retapées qui pourriront à la première évolution. La garantie n'est pas
//! une convention de revue, elle est STRUCTURELLE, en trois épaisseurs :
//!   1. **UNE SEULE DÉFINITION.** Chaque énoncé est ici, et NULLE PART AILLEURS. La passe
//!      (`aging`/`seal`/`writer`) et la sonde appellent la MÊME fonction/constante. Changer la requête
//!      de découverte demain change les DEUX consommateurs, parce qu'il n'y a qu'un texte.
//!   2. **LES PARAMÈTRES AUSSI SONT DÉRIVÉS.** Un même SQL exécuté sur d'autres bornes ne mesure pas la
//!      même chose. `Bande` porte le calcul de fenêtre que `balayer` appliquait en ligne (rétention
//!      cold étendue, policies per-index, fenêtre chaude clampée, bornes de découverte) : la passe et la
//!      sonde consomment la MÊME `Bande`, donc les MÊMES bornes.
//!   3. **UN SCANNER DE SOURCE INTERDIT LA RÉCIDIVE.** Le test
//!      `aucun_enonce_de_lecture_ne_vit_hors_du_module_enonces` lit `aging.rs`/`seal.rs`/`writer.rs` et
//!      échoue si un littéral de chaîne contenant `SELECT` y réapparaît. Il n'ÉNUMÈRE aucun énoncé : il
//!      refuse la CATÉGORIE. Un énoncé de lecture ajouté demain dans la passe casse le build des tests
//!      le jour où il est ajouté — c'est ce qui rend la dérivation opposable plutôt que promise.
//!
//! PÉRIMÈTRE, ÉCRIT POUR ÊTRE OPPOSABLE. La règle du scanner est TEXTUELLE (`SELECT` dans un littéral),
//! pas sémantique : un scanner ne parse pas du SQL. Elle est donc FAIL-CLOSED — elle attrape aussi
//! `SQL_SCELLER_DERNIER_FICHIER`, une ÉCRITURE qui contient une sous-requête, et cet énoncé a donc
//! déménagé ici lui aussi. Les écritures pures du vieillissement (`CREATE TABLE cold_seal`,
//! `INSERT OR REPLACE INTO cold_seal`, `UPDATE … purged=1`, `DELETE FROM cold_seal`) restent chez leur
//! appelant : la sonde est en LECTURE SEULE, elle ne les rejouera JAMAIS, donc les centraliser
//! n'ajouterait aucune garantie — seulement de l'indirection. Ce que ce module ne couvre pas est donc
//! nommé, pas oublié.

use super::*;

// =================================================================================================
// LES ÉNONCÉS — un texte, un seul, par requête que la passe exécute
// =================================================================================================

/// (1) LA DÉCOUVERTE — les `(env_id, jour)` candidats de la bande éligible. C'EST L'ÉNONCÉ SOUS
/// SUSPICION (`P10.13-a`) : agrégation `GROUP BY` sur `event` bornée par un intervalle de `ts`, plus le
/// prédicat `RETENTION_NONPURGE` (qui porte sur `origin`/`source`, NON indexés). EXCLUT les events de
/// contrôle -> jamais agés. Consommé par `balayer` ET par la sonde.
pub(super) fn sql_decouverte_des_jours() -> String {
    format!(
        "SELECT env_id, ts/{SECS_PER_DAY} AS day FROM event \
         WHERE ts>=?1 AND ts<?2 AND {RETENTION_NONPURGE} \
         GROUP BY env_id, ts/{SECS_PER_DAY} ORDER BY env_id, day",
    )
}

/// (2) COMPTE + BORNE D'IDENTITÉ d'un jour (FIX #1) — `(N, max_id)` sur EXACTEMENT l'ensemble agéable.
/// Exécuté UNE FOIS PAR JOUR CANDIDAT FRAIS, sous le verrou writer.
pub(super) fn sql_compte_et_max_id_du_jour() -> String {
    format!(
        "SELECT COUNT(*), COALESCE(MAX(id),0) FROM event \
         WHERE env_id=?1 AND ts>=?2 AND ts<?3 AND {RETENTION_NONPURGE}",
    )
}

/// (3) LE TAIL GLOBAL DU COMPTEUR DE ROWID (garde H1). O(1) attendu (rowid le plus à droite du b-tree) —
/// et la sonde le vérifie au lieu de le supposer.
pub(super) const SQL_MAX_ID_DE_LA_TABLE: &str = "SELECT COALESCE(MAX(id),0) FROM event";

/// (4) UNE PAGE KEYSET du jour à columnariser (phase 1). C'est l'énoncé qui LIT les octets réellement
/// écrits au froid : son plan et sa durée disent le coût de la columnarisation elle-même, distinct du
/// coût de la découverte.
pub(super) fn sql_page_froide() -> String {
    format!(
        "SELECT id,ts,severity,source,category,host,src_ip,dst_ip,url,xff,dedup,engagement_id,origin,env_id,message,fields \
         FROM event WHERE env_id=?1 AND ts>=?2 AND ts<?3 AND id<=?4 AND {RETENTION_NONPURGE} \
           AND (ts>?5 OR (ts=?5 AND id>?6)) ORDER BY ts, id LIMIT ?7",
    )
}

/// (5) LE DEAD-MAN'S-SWITCH « aging cold en RETARD » — `COUNT(*)` sur `event` ANTI-JOINT à `cold_seal`.
/// Second énoncé qui BALAIE potentiellement `event` ; la passe ne l'exécute que si la rétention cold est
/// ÉTENDUE (`cold_ret > retention_days`), et la sonde le dit.
///
/// CE QU'UNE BASE RÉELLE A DIT DE LUI (`P10.13-a`, `cold-aging-plan` du 2026-08-11). Il planifiait `SCAN e`
/// — un balayage COMPLET de `event` : **toute la table, près d'un Gio lu, des dizaines de secondes**, à lui
/// seul la TOTALITÉ du coût de la passe (les huit autres énoncés : quelques dizaines de millisecondes). Et
/// il balayait pour RIEN : la bande ne contient que quelques centaines de lignes. C'est ARITHMÉTIQUE, pas
/// une impression — pas de machine / lignes balayées = **5,0016**, or une ligne REJETÉE sur `ts` coûte
/// EXACTEMENT 5 pas et une ligne RETENUE en coûte 20 (les deux mesurés sur réplique) : au plus quelques
/// centaines de lignes ont dépassé le filtre `ts`. LE COÛT N'ÉTAIT DONC PAS LA SOUS-REQUÊTE CORRÉLÉE — elle
/// ne s'est exécutée que quelques centaines de fois, pas une par ligne de la table. C'était le PLAN.
///
/// POURQUOI CE TEXTE-LÀ. La DÉCOUVERTE (énoncé 1) a le MÊME `FROM`, le MÊME prédicat `ts`, le MÊME
/// `RETENTION_NONPURGE`, sur une bande de MÊME largeur — et la même base la planifie INDEXÉE, en une
/// dizaine de millisecondes.
/// La SEULE différence textuelle était le `NOT EXISTS` corrélé DANS le `WHERE` de la boucle `event`.
/// L'anti-jointure l'en sort : la boucle `event` porte désormais exactement le prédicat de la découverte,
/// et l'appariement `cold_seal` est une boucle SÉPARÉE sur quelques dizaines de lignes en index couvrant. Le pari est nommé,
/// et la prochaine `cold-aging-plan` le tranche. S'il reste `SCAN e`, la cause n'est pas le terme corrélé
/// et le levier MESURÉ est un index PARTIEL COUVRANT `event(ts, env_id) WHERE <RETENTION_NONPURGE>`
/// (mesuré sur la réplique, sur le plan EXACT observé : balayage de toute la table -> **0 ligne**, pas de
/// machine divisés par plus de mille, octets lus d'une centaine de Mio -> **moins d'un dixième de Mio** ;
/// prix : **-8 % de débit d'ingest** et **quelques dizaines de Mio d'index**).
///
/// L'ÉQUIVALENCE EST STRUCTURELLE, PAS ESPÉRÉE — et elle survit aux deux pièges de l'anti-jointure :
///   * **MULTIPLICITÉ.** Un jour à PLUSIEURS seals (`seq` 0..k) produit k lignes jointes, toutes NON-NULL,
///     donc toutes écartées par `s.env_id IS NULL` ; un jour SANS seal produit exactement UNE ligne NULL.
///     Le compte ne peut donc ni gonfler ni manquer une ligne.
///   * **NULL.** `s.env_id IS NULL` ne peut désigner QUE l'absence d'appariement : une ligne de `cold_seal`
///     dont `env_id` serait NULL n'apparie AUCUN jour (`s.env_id=e.env_id` est UNKNOWN), donc elle est
///     invisible ici — exactement comme sous le `NOT EXISTS`. La variante `(env_id, day) NOT IN (…)`, elle,
///     rendrait **0 pour toujours** au premier NULL rencontré : MESURÉ, et c'est pourquoi elle est écartée
///     malgré son plan plus court. Un dead-man's-switch ne se paie pas en fragilité de trois-valeurs.
///
/// `RETENTION_NONPURGE` est ici QUALIFIÉ (`e.`) : l'énoncé joint désormais une SECONDE table, et une colonne
/// nue redeviendrait ambiguë le jour où `cold_seal` gagnerait un `source`/`origin` — SQLite refuserait alors
/// l'énoncé, et le détecteur se tairait. Même raison, même fonction que la purge explicite.
pub(super) fn sql_retard_de_vieillissement() -> String {
    format!(
        "SELECT COUNT(*) FROM event e \
         LEFT JOIN cold_seal s ON s.env_id=e.env_id AND s.day=e.ts/{SECS_PER_DAY} \
         WHERE e.ts >= ?1 AND e.ts < ?2 AND {} AND s.env_id IS NULL",
        retention_nonpurge_for("e")
    )
}

/// `P10.13-a` levier ① — LA CLÉ `meta` OÙ VIT L'HORODATAGE DU DERNIER TIR du dead-man's-switch.
///
/// POURQUOI `meta` ET PAS AILLEURS — mesuré, pas préféré :
///   * **pas en mémoire.** Un compteur de processus ferait tirer le détecteur à CHAQUE démarrage : un pod
///     qui redémarre souvent paierait les 27,9 s plus souvent qu'aujourd'hui, ce qui INVERSERAIT le gain.
///   * **pas dans `metric`.** La série y vit, mais elle est PURGÉE (`metric_raw_hours`, 48 h par défaut,
///     puis bucket horaire 90 j) et la fenêtre brute est CONFIGURABLE. Une cadence quotidienne dont
///     l'état s'efface au bout de `metric_raw_hours` cesserait de fonctionner dès qu'un exploitant
///     descend cette rétention sous 24 h — un couplage silencieux entre une politique de rétention et
///     une garde de sûreté. `metric_rollup` moyennerait en plus l'horodatage par bucket.
///   * **pas une table neuve.** Elle coûterait un schéma, une migration et une rétention, pour une ligne.
///   * **`meta` convient et existe** : `key TEXT PRIMARY KEY, value TEXT`, créée par la chaîne de
///     migrations sur TOUS les déploiements, et déjà le siège des watermarks de jobs de
///     fond (`event_rollup_wm`, `dim_rollup_cov`) — c'est exactement le même objet : « où en était ce
///     job la dernière fois ». Une ligne, une clé primaire, survit au redémarrage et à la restauration.
///     **LA PROPRIÉTÉ EXACTE, mesurée le 2026-08-14 — et « jamais purgée » serait FAUX** : `meta` porte
///     **14 `DELETE`**, mais **TOUS ciblent une clé nommée** (`WHERE key='…'`, retraits de watermarks à
///     la migration). Ce qui porte le raisonnement, c'est qu'il n'existe **aucune suppression non
///     filtrée** et **aucune suppression temporelle** — là où `metric` a bien un
///     `DELETE FROM metric WHERE ts < ?`. C'est cette absence-là qui rend la clé sûre, pas une immunité
///     générale qu'on lui prêterait à tort.
/// La clé est en `snake_case` anglais comme ses voisines dans `meta` : un exploitant qui fait
/// `SELECT * FROM meta` ne doit pas y trouver deux langues.
pub(super) const META_DERNIER_TIR_DU_RETARD: &str = "cold_aging_stall_last_ts";

/// (5 bis) L'HORODATAGE DU DERNIER TIR du dead-man's-switch de retard, relu dans la table `meta`.
/// C'est une LECTURE : elle vit donc ici, comme toutes les autres (la règle du scanner est textuelle et
/// fail-closed). Son ÉCRITURE, elle, reste chez son appelant — `enonces` ne centralise pas les écritures
/// pures (cf. l'en-tête) : la sonde de lecture seule ne les rejouera jamais.
pub(super) const SQL_DERNIER_TIR_DU_RETARD: &str = "SELECT value FROM meta WHERE key=?1";

/// (6) LES SEALS D'UN JOUR, triés par `seq` (préfixe de fichiers scellés). Petite table.
pub(super) const SQL_SEALS_DU_JOUR: &str =
    "SELECT seq, expected_rows, purged, max_id, ts_min, ts_max, lo_ts, lo_id, hi_id, last_file, dim_stats \
     FROM cold_seal WHERE env_id=?1 AND day=?2 ORDER BY seq";

/// (7) LE DÉTECTEUR DE SEAL BLOQUÉ (phase-2 coincée). Petite table, borné `purged=0`.
pub(super) const SQL_SEAL_BLOQUE: &str =
    "SELECT COUNT(*), COUNT(DISTINCT env_id||'/'||day), COALESCE(MIN(sealed_ts),0) \
     FROM cold_seal WHERE purged=0 AND sealed_ts < ?1";

/// (8) TOUS LES FICHIERS SCELLÉS — l'énumération que l'expiry (et l'escrow) parcourt à chaque passe.
pub(super) const SQL_TOUS_LES_SEALS: &str = "SELECT env_id, day, seq FROM cold_seal";

/// (9) LA COLONNE `dim_stats` EXISTE-T-ELLE ? (migration paresseuse #28 Phase B). Lit le SCHÉMA de la
/// connexion, pas les données du tenant : la sonde ne le rejoue PAS (il appartient au chemin d'ÉCRITURE
/// `ensure_cold_seal_table`). Il vit ici parce que la règle du scanner est textuelle et fail-closed.
pub(super) const SQL_COLONNE_DE_SEAL: &str = "SELECT 1 FROM pragma_table_info('cold_seal') WHERE name=?1";

/// (10) LE COMMIT DE FIN DE PHASE 1 (`last_file=1` sur le dernier `seq`). ÉCRITURE — la sonde ne la
/// rejoue JAMAIS. Elle est ici parce qu'elle CONTIENT une sous-requête `SELECT` et que le scanner de
/// source refuse la catégorie sans la parser (fail-closed, cf. l'en-tête).
pub(super) const SQL_SCELLER_DERNIER_FICHIER: &str =
    "UPDATE cold_seal SET last_file=1 WHERE env_id=?1 AND day=?2 AND seq=(SELECT MAX(seq) FROM cold_seal WHERE env_id=?1 AND day=?2)";

/// LA LIMITE DE LA PREMIÈRE PAGE d'un fichier — PURE, et partagée par le writer et la sonde : mesurer la
/// page avec une autre `LIMIT` que celle que la passe emploie ne mesurerait pas la passe. Double borne
/// (RAM du row-group ET plafond de taille du fichier), plancher 1.
pub(super) fn limite_premiere_page(rg_rows: usize, file_cap: usize) -> usize {
    rg_rows.min(file_cap).max(1)
}

// =================================================================================================
// LA BANDE — les BORNES que ces énoncés reçoivent, calculées une fois, partagées
// =================================================================================================

/// LA BANDE AGÉABLE D'UN TICK : tout ce que `balayer` dérivait en ligne de la configuration et des
/// policies, extrait pour que la sonde reçoive EXACTEMENT les mêmes bornes que la passe. Un même SQL sur
/// d'autres bornes ne mesure pas la même chose — c'est pourquoi la dérivation ne peut pas s'arrêter au
/// texte des requêtes.
pub(super) struct Bande {
    /// Rétention GLOBALE effective de CE tick, telle que `retention_run` l'a résolue. Portée ICI pour
    /// que le gate d'ARMEMENT du dead-man's-switch (`cold_ret > retention_days`) soit DÉRIVABLE de la
    /// bande seule : sans elle, chaque site d'appel devait re-poser la condition à la main — et c'est
    /// exactement ce qu'un troisième site oublierait.
    pub(super) retention_days: i64,
    /// Rétention TOTALE visée quand le tier cold est ON (#18 P1.5 ; défaut = `retention_days`).
    pub(super) cold_ret: i64,
    /// Rétention la PLUS LONGUE applicable (globale étendue ∪ policies) -> borne basse LARGE.
    pub(super) max_ret: i64,
    /// Fenêtre chaude EFFECTIVE (jours), clamp compris.
    pub(super) hot_window: i64,
    /// Premier jour ENCORE chaud (exclu de la découverte).
    pub(super) hi_day_excl: i64,
    /// Plus ancien jour de la bande LARGE de découverte (inclus).
    pub(super) broad_lo_day: i64,
    /// Plafond de lignes PAR FICHIER cold (split du jour).
    pub(super) file_cap: usize,
    /// Lignes par row-group intra-fichier (borne la RAM d'écriture).
    pub(super) rg_rows: usize,
    /// Policies per-index actives (#49) — la borne basse PAR-ENV en dérive.
    pub(super) policies: Vec<IndexPolicy>,
    /// `P10.13-a` levier ① — PÉRIODE MINIMALE (s) entre deux tirs du dead-man's-switch de retard.
    /// Résolue et CLAMPÉE une fois ici (cf. `periode_de_tir`) : la passe et la sonde lisent la même.
    pub(super) periode_de_tir: i64,
}

impl Bande {
    /// CALCULE la bande de CE tick. `conn` sert UNIQUEMENT à charger les policies per-index (lecture).
    /// AUCUNE écriture ici : `ensure_cold_seal_table` reste chez l'appelant, ce qui est ce qui permet à
    /// la sonde d'appeler cette fonction sur une connexion ouverte en LECTURE SEULE.
    pub(super) fn calculer(conn: &Connection, conf: &HashMap<String, String>, n: i64, retention_days: i64) -> Bande {
        let cold_ret = cold_retention_days(conf, retention_days);
        let policies = load_index_policies(conn);
        let max_ret = max_retention(&policies, cold_ret);
        let hot_window = clamp_hot_window(conf, max_ret);
        let hot_cutoff = n - hot_window * SECS_PER_DAY;
        let hi_day_excl = hot_cutoff.div_euclid(SECS_PER_DAY); // floor : jours >= celui-ci sont chauds.
        let broad_lo_day = (n - max_ret * SECS_PER_DAY + SECS_PER_DAY - 1).div_euclid(SECS_PER_DAY); // ceil
        let rg_rows: usize = cfg(conf, "PLUME_COLD_ROWGROUP_ROWS", &ROW_GROUP_ROWS.to_string())
            .parse::<usize>()
            .unwrap_or(ROW_GROUP_ROWS)
            .clamp(1, ROW_GROUP_ROWS);
        let file_cap: usize = cfg(conf, "PLUME_COLD_FILE_MAX_ROWS", &COLD_FILE_MAX_ROWS.to_string())
            .parse::<usize>()
            .unwrap_or(COLD_FILE_MAX_ROWS)
            .clamp(1, COLD_FILE_MAX_ROWS);
        Bande {
            retention_days,
            cold_ret,
            max_ret,
            hot_window,
            hi_day_excl,
            broad_lo_day,
            file_cap,
            rg_rows,
            policies,
            periode_de_tir: periode_de_tir(conf),
        }
    }

    /// Y A-T-IL UNE BANDE À BALAYER ? (fenêtre chaude + rétention peuvent se recouvrir entièrement.)
    pub(super) fn ouverte(&self) -> bool {
        self.hi_day_excl > self.broad_lo_day
    }

    /// Bornes `ts` [lo, hi) de la requête de découverte.
    pub(super) fn bornes_de_decouverte(&self) -> (i64, i64) {
        (self.broad_lo_day * SECS_PER_DAY, self.hi_day_excl * SECS_PER_DAY)
    }

    /// Rétention EFFECTIVE d'un `env_id` : sa policy per-index (>0) si définie, sinon la GLOBALE ÉTENDUE.
    pub(super) fn eff_ret(&self, env: &str) -> i64 {
        self.policies
            .iter()
            .find(|p| p.retention_days > 0 && p.name == env)
            .map(|p| p.retention_days)
            .unwrap_or(self.cold_ret)
    }

    /// UN CANDIDAT EST-IL RETENU POUR TRAITEMENT ? Deux refus, un seul verdict : `env_id` non conforme
    /// (fail-safe, pas de composant de chemin) OU jour au-delà de la rétention de SON index (laissé au
    /// hard-purge / à l'expiry, jamais columnarisé pour être supprimé aussitôt). PARTAGÉ par la boucle de
    /// `balayer` et par la sélection de candidat de la sonde -> la sonde mesure le jour que la passe
    /// aurait traité, pas un autre.
    pub(super) fn retenu(&self, env_id: &str, day: i64, n: i64) -> bool {
        if !env_id_ok(env_id) {
            return false;
        }
        let r = self.eff_ret(env_id);
        let env_lo_day = (n - r * SECS_PER_DAY + SECS_PER_DAY - 1).div_euclid(SECS_PER_DAY); // ceil
        day >= env_lo_day
    }

    /// Fenêtre `ts` du dead-man's-switch de retard pour CETTE bande — délègue à la fonction PURE.
    pub(super) fn bornes_du_retard(&self, n: i64) -> Option<(i64, i64)> {
        bornes_du_retard(self.hot_window, self.cold_ret, n)
    }

    /// LE DÉTECTEUR DE RETARD TIRE-T-IL À CETTE PASSE, ET SUR QUELLE FENÊTRE ? Délègue à la fonction
    /// PURE ci-dessous en lui donnant TOUS les termes depuis la bande — c'est ce qui fait qu'il n'y a
    /// plus rien à poser au site d'appel, donc plus rien à oublier.
    pub(super) fn tir_du_retard(&self, n: i64, dernier_tir: Option<i64>) -> TirDuRetard {
        tir_du_retard(self.hot_window, self.cold_ret, self.retention_days, self.periode_de_tir, n, dernier_tir)
    }
}

/// `P10.13-a` levier ① — PÉRIODE PAR DÉFAUT (s) entre deux tirs du dead-man's-switch de retard : **24 h**.
///
/// POURQUOI 24 H, ET PAS UN CHIFFRE ROND. Parce que la columnarisation n'a lieu qu'UNE FOIS PAR JOUR (un
/// jour franchit la fenêtre chaude), et que les 23 autres passes horaires ne peuvent rien faire PAR
/// CONSTRUCTION. Mesuré sur une base réelle le 2026-08-13, sur près de deux jours de passes horaires :
/// **deux passes utiles, toutes les autres sans le moindre travail** — plus de 95 % du temps de `db.lock()`
/// tenu pour rien, porté EN TOTALITÉ par l'énoncé n° 5 (`SCAN e`, un balayage complet de `event`, relevé
/// à `cold-aging-plan`). Ce levier ne
/// supprime AUCUN travail : il supprime des passes qui n'en avaient aucun.
pub(super) const PERIODE_TIR_RETARD_DEFAUT_S: i64 = 24 * 3600;

/// PÉRIODE EFFECTIVE (s) entre deux tirs, CLAMPÉE `[0, COLD_STALL_GRACE_DAYS jours]`.
///
/// LE PLAFOND N'EST PAS DÉCORATIF, ET IL EST DÉRIVÉ. Le détecteur a une GRÂCE (`COLD_STALL_GRACE_DAYS`)
/// : la condition qu'il surveille met ce temps-là à naître. Autoriser une cadence PLUS LONGUE que cette
/// grâce laisserait une configuration ÉMOUSSER le dead-man's-switch au-delà de ce que sa propre
/// conception admet — un knob capable d'annuler la garde qu'il règle. Le plafond suit donc la grâce
/// automatiquement : relever `COLD_STALL_GRACE_DAYS` relève le plafond, sans que personne n'y pense.
/// `0` (ou une valeur négative, clampée à `0`) DÉSARME la cadence -> tir à CHAQUE passe, c'est-à-dire le
/// comportement d'avant ce lot, rachetable à chaud sans rebuild. Une valeur ILLISIBLE, elle, retombe sur
/// le DÉFAUT et non sur `0` : un typo ne doit pas rendre au démon les ~20 min de verrou quotidien qu'on
/// vient de lui retirer.
pub(super) fn periode_de_tir(conf: &HashMap<String, String>) -> i64 {
    let brut = cfg(conf, "PLUME_COLD_STALL_CHECK_INTERVAL_S", "");
    if brut.trim().is_empty() {
        return PERIODE_TIR_RETARD_DEFAUT_S;
    }
    // Une valeur ILLISIBLE retombe sur le DÉFAUT et non sur `0` : un typo ne doit ni désarmer la
    // cadence (on reprendrait les 20 min/jour) ni allonger la latence au-delà du plafond.
    brut.trim()
        .parse::<i64>()
        .unwrap_or(PERIODE_TIR_RETARD_DEFAUT_S)
        .clamp(0, COLD_STALL_GRACE_DAYS * SECS_PER_DAY)
}

/// CE QUE LA PASSE FAIT DU DÉTECTEUR DE RETARD À CE TICK — un TYPE, pas trois `if` recopiés.
///
/// C'EST LE POINT UNIQUE EXIGÉ PAR LE LEVIER ①. Avant, la décision « le détecteur tourne-t-il ? » était
/// écrite TROIS fois : deux `if cold_ret > retention_days` dans `balayer` (sites clé-absente et
/// fin-de-passe) et un troisième dans `enonces_sans_candidat` pour la sonde. Trois copies d'une même
/// condition, dont un quatrième site aurait fatalement divergé. Elles sont maintenant DÉRIVÉES d'ici :
/// `detect_aging_stall` ne prend plus ni `hot_window`, ni `cold_ret`, ni `retention_days` — il prend la
/// `Bande`, et il n'y a plus rien à poser à l'appel.
pub(super) enum TirDuRetard {
    /// Il tire, sur cette fenêtre `ts` `[lo, hi)`.
    Du { lo: i64, hi: i64 },
    /// Il ne tire pas ; la clé (étiquette de série, cf. `vieillissement_serie::RETARD_*`) dit pourquoi.
    Ajourne(&'static str),
}

/// LA DÉCISION, PURE — donc testable sans base, sans horloge et sans tier froid compilé.
///
/// TROIS REFUS, ET LEUR ORDRE EST LOAD-BEARING :
///   1. **PAS ARMÉ** (`cold_ret <= retention_days`) : sans extension de rétention, le hot reste plafonné
///      comme avant, il n'y a AUCUN bloat nouveau à surveiller. C'est le cas par défaut, et il vient en
///      premier parce qu'aucun des deux suivants n'a de sens si le détecteur n'existe pas.
///   2. **FENÊTRE VIDE** : la fenêtre chaude + grâce couvre déjà toute la rétention cold -> rien à
///      surveiller (et pas « rien trouvé »).
///   3. **CADENCE** : le tir précédent est trop récent.
///
/// ET TOUT LE RESTE TIRE — c'est la propriété qui protège le dead-man's-switch. Jamais tiré (`None`,
/// base neuve ou démarrage), période désarmée (`<= 0`), horodatage dans le FUTUR (horloge revenue en
/// arrière, base restaurée, valeur corrompue) : chacun de ces cas rend `Du`. Un `unwrap_or` qui aurait
/// rendu « trop tôt » sur une valeur illisible aurait SILENCIEUSEMENT muselé la garde — c'est
/// littéralement le mode de panne que ce détecteur existe pour fermer, et il l'a déjà eu une fois
/// (`unwrap_or(0)` sur le compte, retiré en `P10.13-a`).
pub(super) fn tir_du_retard(
    hot_window: i64,
    cold_ret: i64,
    retention_days: i64,
    periode: i64,
    n: i64,
    dernier_tir: Option<i64>,
) -> TirDuRetard {
    if cold_ret <= retention_days {
        return TirDuRetard::Ajourne(crate::vieillissement_serie::RETARD_NON_ARME);
    }
    let Some((lo, hi)) = bornes_du_retard(hot_window, cold_ret, n) else {
        return TirDuRetard::Ajourne(crate::vieillissement_serie::RETARD_FENETRE_VIDE);
    };
    match dernier_tir {
        // `saturating_sub` : l'horodatage vient d'une COLONNE TEXTE de `meta`, donc d'une valeur qu'un
        // opérateur (ou une corruption) peut rendre absurde. Un `i64::MIN` ferait déborder la
        // soustraction et PANIQUER le démon en debug — une mesure ne doit jamais faire tomber ce
        // qu'elle mesure, et surtout pas depuis une donnée non contrôlée.
        Some(t) if periode > 0 && t <= n && n.saturating_sub(t) < periode => {
            TirDuRetard::Ajourne(crate::vieillissement_serie::RETARD_CADENCE)
        }
        _ => TirDuRetard::Du { lo, hi },
    }
}

/// FENÊTRE `ts` [lo, hi) DU DEAD-MAN'S-SWITCH DE RETARD — PURE, et SEULE définition. `None` = fenêtre vide
/// (la fenêtre chaude + grâce couvre déjà toute la rétention -> rien à surveiller).
///
/// BORNE HAUTE : plus vieux que la fenêtre chaude + grâce. BORNE BASSE = `now - cold_ret` : au-delà, la
/// donnée est HORS rétention (filet de sécurité du hard-purge chaud, PAS le rôle de l'aging) — la compter
/// comme « aurait dû être columnarisée » ferait un faux positif sur un straggler résiduel dont le seal a
/// été expiré. La bande rendue est EXACTEMENT la zone où la donnée DEVRAIT être au froid.
///
/// Prend `hot_window`/`cold_ret` NUS plutôt qu'une `Bande` : `detect_aging_stall` les reçoit ainsi de son
/// appelant (et ses tests l'appellent avec des valeurs littérales). C'est ce qui permet à la passe ET à la
/// sonde de partager la borne SANS que la première ait à construire une `Bande` qu'elle a déjà.
pub(super) fn bornes_du_retard(hot_window: i64, cold_ret: i64, n: i64) -> Option<(i64, i64)> {
    let hi = n - (hot_window + COLD_STALL_GRACE_DAYS) * SECS_PER_DAY;
    let lo = n - cold_ret * SECS_PER_DAY;
    if hi <= lo {
        None
    } else {
        Some((lo, hi))
    }
}

// =================================================================================================
// CE QUE LA SONDE REJOUE — la liste, dérivée des énoncés ci-dessus
// =================================================================================================

/// LES DEUX ÉNONCÉS DONT LA SONDE DOIT RELIRE LE RÉSULTAT pour enchaîner comme la passe enchaîne : la
/// découverte donne les candidats, le compte donne le `max_id` qui borne la page. Ce sont des CLÉS, pas
/// des textes : la sonde compare `Enonce::nom`, jamais du SQL, donc renommer une requête ne casse rien et
/// supprimer un énoncé casse le build là où sa clé est encore citée.
pub(super) const NOM_DECOUVERTE: &str = "decouverte_des_jours";
pub(super) const NOM_COMPTE_ET_MAX_ID: &str = "compte_et_max_id_du_jour";
/// `P10.13-a` — l'énoncé du dead-man's-switch de retard. Clé citée par le rendu de la sonde (qui lui
/// attache sa phrase de cadence) : une chaîne, un seul endroit.
pub(super) const NOM_RETARD: &str = "retard_de_vieillissement";

/// CE QUE LA PASSE FAIT D'UN ÉNONCÉ — TROIS états depuis `P10.13-a` levier ①, et plus deux.
///
/// LE BOOLÉEN NE SUFFISAIT PLUS, ET LE TROISIÈME ÉTAT N'EST PAS UN DÉTAIL DE RENDU. « La passe
/// l'exécute-t-elle ? » avait deux réponses tant que la seule alternative était un gate de
/// CONFIGURATION. Le dead-man's-switch de retard en a maintenant une troisième : la passe l'exécute
/// bel et bien, mais **une fois par jour** au lieu de vingt-quatre. Les confondre coûterait dans les
/// deux sens — le déclarer « non exécuté » rendrait la sonde AVEUGLE 23 h sur 24 à l'énoncé même que le
/// levier change (or elle est le SEUL instrument qui sache attribuer un coût à UN énoncé ; la série, elle,
/// ne donne que la durée totale de la passe) ; le déclarer « exécuté à chaque tick » facturerait 24 fois
/// un coût payé une fois.
pub(super) enum ParLaPasse {
    /// Exécuté à CHAQUE tick de la passe.
    ChaqueTick,
    /// Exécuté à CADENCE RÉDUITE. La phrase dit laquelle, où en est le compteur, et si CE tick tirerait.
    /// La sonde le mesure QUAND MÊME — et l'annonce, pour qu'aucune durée ne se lise « par tick ».
    ACadence(String),
    /// PAS exécuté dans cet état de configuration : plan montré, durée NON mesurée (la facturer serait
    /// un chiffre faux).
    Jamais,
}

/// UN ÉNONCÉ PRÊT À ÊTRE MESURÉ : son texte, ses paramètres RÉELS, et ce que la passe en fait. `nom` est
/// une clé stable (elle apparaît dans le rapport de la sonde) ; `role` est la phrase qu'un exploitant lit.
pub(super) struct Enonce {
    pub(super) nom: &'static str,
    pub(super) role: &'static str,
    pub(super) sql: String,
    pub(super) params: Vec<rusqlite::types::Value>,
    pub(super) par_la_passe: ParLaPasse,
}

fn ent(v: i64) -> rusqlite::types::Value {
    rusqlite::types::Value::Integer(v)
}

fn txt(v: &str) -> rusqlite::types::Value {
    rusqlite::types::Value::Text(v.to_string())
}

/// LES ÉNONCÉS QUE LA PASSE EXÉCUTE AVANT DE CONNAÎTRE UN CANDIDAT — dans l'ordre où elle les exécute.
///
/// `tir` est la décision de tir du dead-man's-switch, calculée par l'appelant avec `Bande::tir_du_retard`
/// et le `dernier_tir` relu dans `meta` — c'est-à-dire EXACTEMENT ce que `detect_aging_stall` calcule.
/// Le passer plutôt que le recalculer ici est ce qui interdit à la sonde de décrire une cadence que la
/// passe n'applique pas.
pub(super) fn enonces_sans_candidat(bande: &Bande, n: i64, tir: &TirDuRetard) -> Vec<Enonce> {
    let (lo, hi) = bande.bornes_de_decouverte();
    let mut out = vec![Enonce {
        nom: NOM_DECOUVERTE,
        role: "liste les (env_id, jour) candidats de la bande éligible — l'énoncé sous suspicion P10.13-a",
        sql: sql_decouverte_des_jours(),
        params: vec![ent(lo), ent(hi)],
        par_la_passe: if bande.ouverte() { ParLaPasse::ChaqueTick } else { ParLaPasse::Jamais },
    }];
    out.push(Enonce {
        nom: "tail_du_compteur_de_rowid",
        role: "garde H1 : MAX(id) sur TOUTE la table, une fois par jour candidat frais",
        sql: SQL_MAX_ID_DE_LA_TABLE.to_string(),
        params: vec![],
        par_la_passe: ParLaPasse::ChaqueTick,
    });
    out.push(Enonce {
        nom: "tous_les_seals",
        role: "énumération de l'index cold_seal — parcourue par l'expiry à chaque passe",
        sql: SQL_TOUS_LES_SEALS.to_string(),
        params: vec![],
        par_la_passe: ParLaPasse::ChaqueTick,
    });
    out.push(Enonce {
        nom: "seal_bloque",
        role: "détecteur de phase-2 coincée (cold_seal.purged=0 au-delà de la grâce)",
        sql: SQL_SEAL_BLOQUE.to_string(),
        params: vec![ent(n - COLD_SEAL_STUCK_GRACE_S)],
        par_la_passe: ParLaPasse::ChaqueTick,
    });
    // Le dead-man's-switch de RETARD. La sonde respecte les MÊMES gates que la passe parce qu'elle
    // consomme la MÊME décision (`TirDuRetard`) : gate d'armement, fenêtre vide, ET cadence. Les bornes
    // affichées sont celles du tir quand il a lieu ; sinon celles que la fenêtre RENDRAIT (le plan reste
    // lisible même quand l'énoncé ne tourne pas).
    let (lo_retard, hi_retard) = bande.bornes_du_retard(n).unwrap_or((0, 0));
    out.push(Enonce {
        nom: NOM_RETARD,
        role: "dead-man's-switch : lignes chaudes qui auraient dû être columnarisées (gate : rétention cold ÉTENDUE)",
        sql: sql_retard_de_vieillissement(),
        params: vec![ent(lo_retard), ent(hi_retard)],
        par_la_passe: match tir {
            // ARMÉ et cadencé : la passe le paie, mais UNE FOIS PAR `periode_de_tir`. La sonde le mesure
            // (c'est le seul instrument qui sait ce que CET énoncé coûte) et dit l'amortissement.
            TirDuRetard::Du { .. } => ParLaPasse::ACadence(phrase_de_cadence(bande, true)),
            TirDuRetard::Ajourne(cause)
                if *cause == crate::vieillissement_serie::RETARD_CADENCE =>
            {
                ParLaPasse::ACadence(phrase_de_cadence(bande, false))
            }
            // Non armé / fenêtre vide : gate de CONFIGURATION fermé -> la passe ne l'exécuterait
            // JAMAIS dans cet état, quelle que soit l'heure. Plan montré, durée NON mesurée.
            TirDuRetard::Ajourne(_) => ParLaPasse::Jamais,
        },
    });
    out
}

/// LA PHRASE DE CADENCE lue par l'exploitant sous l'énoncé du dead-man's-switch. `du` = ce tick-ci
/// tirerait. Elle dit l'AMORTISSEMENT explicitement : sans ça, la durée mesurée juste en dessous se
/// lirait « à chaque passe » — ce qu'elle n'est plus.
fn phrase_de_cadence(bande: &Bande, du: bool) -> String {
    if bande.periode_de_tir <= 0 {
        return "CADENCE DÉSARMÉE (PLUME_COLD_STALL_CHECK_INTERVAL_S=0) -> tiré à CHAQUE passe, \
                comportement d'avant P10.13-a"
            .to_string();
    }
    format!(
        "CADENCE : au plus 1 tir / {} s ({} passes horaires sur {} le sautent). CE tick : {} — la durée \
         mesurée ci-dessous est donc payée UNE FOIS PAR {} s, pas à chaque passe.",
        bande.periode_de_tir,
        (bande.periode_de_tir / 3600 - 1).max(0),
        (bande.periode_de_tir / 3600).max(1),
        if du { "TIRE" } else { "NE TIRE PAS (trop récent)" },
        bande.periode_de_tir
    )
}

/// LES ÉNONCÉS D'UN CANDIDAT QUI NE DÉPENDENT QUE DU JOUR — dans l'ordre où `age_one_day` les exécute
/// (l'état des seals décide de la phase, puis le snapshot compte/borne l'ensemble agéable).
pub(super) fn enonces_du_candidat(bande: &Bande, env_id: &str, day: i64) -> Vec<Enonce> {
    let _ = bande; // la bande ne borne pas ces deux énoncés — le jour suffit.
    let day_start = day * SECS_PER_DAY;
    let day_end = day_start + SECS_PER_DAY;
    vec![
        Enonce {
            nom: "seals_du_jour",
            role: "état des fichiers scellés de ce jour (machine à états deux phases)",
            sql: SQL_SEALS_DU_JOUR.to_string(),
            params: vec![txt(env_id), ent(day)],
            par_la_passe: ParLaPasse::ChaqueTick,
        },
        Enonce {
            nom: NOM_COMPTE_ET_MAX_ID,
            role: "compte + borne d'identité de l'ensemble agéable (sous le verrou writer)",
            sql: sql_compte_et_max_id_du_jour(),
            params: vec![txt(env_id), ent(day_start), ent(day_end)],
            par_la_passe: ParLaPasse::ChaqueTick,
        },
    ]
}

/// L'ÉNONCÉ QUI DÉPEND DU `max_id` — signature SÉPARÉE PAR DESSEIN : dans la passe, la page keyset n'est
/// constructible qu'APRÈS le snapshot (`count_and_max_id`), parce qu'elle est bornée par SON résultat.
/// Deux builders au lieu d'un `max_id` par défaut : la sonde ne PEUT PAS mesurer la page avant d'avoir la
/// borne, donc elle ne peut pas mesurer une page que la passe n'aurait jamais lue.
pub(super) fn enonce_de_la_page(bande: &Bande, env_id: &str, day: i64, max_id: i64) -> Enonce {
    let day_start = day * SECS_PER_DAY;
    let day_end = day_start + SECS_PER_DAY;
    Enonce {
        nom: "premiere_page_froide",
        role: "première page keyset de la columnarisation (LIMIT = celle du writer)",
        sql: sql_page_froide(),
        params: vec![
            txt(env_id),
            ent(day_start),
            ent(day_end),
            ent(max_id),
            ent(i64::MIN),
            ent(i64::MIN),
            ent(limite_premiere_page(bande.rg_rows, bande.file_cap) as i64),
        ],
        par_la_passe: ParLaPasse::ChaqueTick,
    }
}

//! `P10.5-i` — LE COFFRE DU PANNEAU QUI AVOUE : la compilation d'un panneau et la table `panel_cache`
//! vivent ICI, et rien ne sort d'ici sans dire jusqu'où il a pu voir.
//!
//! LE DÉFAUT FERMÉ. Un panneau de tableau de bord ne consulte jamais la bande froide : sa requête est
//! calculée sur la seule fenêtre que la rétention (et, le cas échéant, le vieillissement froid) a
//! laissée, puis rendue comme une courbe ENTIÈRE. Le nombre est faux et rien ne le dit. Ce module ne
//! CORRIGE PAS le nombre — c'est la voie (a), assumée : il le fait DIRE. Un nombre faux qui se dit
//! faux n'est plus le même défaut.
//!
//! CE QUE CE COFFRE FERME, ET CE QU'IL NE FERME PAS. Il rend impossible d'obtenir le SQL d'un panneau
//! COMPILÉ ICI sans passer par `executer`, qui estampe l'aveu INCONDITIONNELLEMENT ; et il fait de
//! `panel_cache` un mécanisme POSSÉDÉ, ce qui donne à la garde de build (`daemon/build.rs`, garde
//! `cache_de_panneau`) un motif à surveiller qui est un NOM DE TABLE et non l'orthographe d'un INSERT.
//! Il ne rend PAS impossible d'écrire un septième point d'exécution : `run_query` (`query_exec.rs`),
//! `soql_to_sql_x` et `soql_to_sql_masked_x` (`soql_glue.rs`) restent `pub(crate)` — le coffre les
//! APPELLE, il ne les possède pas. Un site qui recompilerait son SQL de panneau ailleurs n'a rien à
//! contourner ; s'il vit sous `src/handlers/**`, c'est
//! `sec_ff_no_unmasked_compile_in_caller_scoped_surfaces` (PARTIE 1) qui le voit, pas ce module.
//!
//! POURQUOI LA PROVENANCE A TROIS ÉTATS. Le geste naïf — poser `apply_rollup_stats(&mut v, &None)` sur
//! tous les chemins — AJOUTERAIT un mensonge : il écrit `served_from:"raw"` + `approx:false`, que la
//! console rend « Données brutes (scan, non pré-agrégé) — exact », sur ONZE panneaux LIVRÉS dont le SQL
//! (`dim_panel_sql`, `rollups.rs`) lit `event_dim_rollup`, pré-agrégé PLAFONNÉ en top-N (écart mesuré
//! jusqu'à x16,4, cf. `topn_cap`). Le silence d'aujourd'hui serait moins faux que l'aveu de demain. La
//! branche opaque n'appelle donc PAS `apply_rollup_stats` : elle publie `provenance_non_derivee:true`,
//! jamais un aveu d'exactitude sur une provenance inconnue.
//!
//! COÛT AJOUTÉ, ET IL EST RÉEL : UNE prise du pool de LECTURE (`read_with`, jamais le mutex writer
//! partagé) portant une lecture indexée de `setting`, par réponse de panneau, succès de cache compris.
//! AUCUNE lecture disque de configuration n'est ajoutée : `horizon` prend `&conf` en PARAMÈTRE, et
//! chaque appelant réutilise le `load_config()` qu'il fait DÉJÀ. AUCUN `MIN()` sur une grande table,
//! AUCUNE lecture Parquet, AUCUNE hydratation froide : le budget de 2 Gio n'est pas touché.

use crate::*;

// =====================================================================================================
// 1. CE QU'UN PANNEAU COMPILÉ SAIT DE LUI-MÊME
// =====================================================================================================

/// D'OÙ VIENT LE NOMBRE QU'UN PANNEAU SERT. Trois états, parce que deux ne suffisaient pas : le chemin
/// `is_soql=0` produit un SQL OPAQUE dont on ne peut RIEN affirmer sur l'axe provenance, et l'affirmer
/// quand même est exactement ce que ce module existe pour empêcher.
pub(crate) enum Provenance {
    /// La route de pré-agrégat a répondu : elle SAIT ce qu'elle sert (approximation, plafond, caveat).
    /// Les trois champs sont ceux que `try_rollup_route` produit et que l'appelant jetait.
    RouteePreagrege(bool, Cap, Option<String>),
    /// Le compilateur GXQL a compilé un scan des tables VIVES : `served_from:"raw"` + `approx:false` y
    /// est VRAI.
    CompilateurBrut,
    /// SQL brut de panneau (ou GXQL masqué) : opaque. On ne dérive AUCUNE provenance d'un texte qu'on
    /// n'analyse pas — on le DIT.
    Opaque,
}

/// UN PANNEAU COMPILÉ. Champs PRIVÉS, aucun accesseur de production : le seul moyen d'en tirer une
/// réponse est `executer`, qui estampe l'aveu. Un appelant ne peut pas prendre le SQL et l'exécuter à
/// côté.
pub(crate) struct PanneauCompile {
    sql: String,
    provenance: Provenance,
    /// `P10.5-p` — L'ENVIRONNEMENT (`env_id`) QUE CE SQL LIT, QUAND IL EST DÉTERMINÉ : `Some` seulement si le
    /// compilateur GXQL a reçu un environnement non vide, donc injecté `env_id = '<env>'` (même condition que
    /// `table_base` du compilateur et `merge_env_cond` de la route de pré-agrégat). Un SQL brut (opaque) n'est
    /// jamais filtré par environnement ici : `None`, même si l'appelant en a un. Sert à l'horizon seul, qui y
    /// lit la politique par index applicable.
    env_lu: Option<String>,
}

impl PanneauCompile {
    /// LECTURE DE TEST UNIQUEMENT. Les témoins comparent le SQL produit à celui du chemin d'avant
    /// (déplacement pur) ; la production, elle, n'a aucun moyen de sortir ce texte du coffre.
    #[cfg(test)]
    pub(crate) fn sql_de_test(&self) -> &str {
        &self.sql
    }
}

// =====================================================================================================
// 2. LES PORTES DE COMPILATION
// =====================================================================================================

/// Compile la requête d'un panneau en SQL exécutable : GXQL -> soql_to_sql, sinon substitution
/// __FROM__/__TO__. Substitue d'abord les placeholders d'exclusion self/opérateur (no-op si absents).
/// `env` (#2d) : filtre par environnement propagé au chemin GXQL des panneaux (rollup-route + compilo).
/// None (mode 0) -> aucun filtre -> SQL inchangé. NB : les panneaux is_soql=0 (SQL brut sur les rollups,
/// ex. seeds Vue d'ensemble) ne sont PAS auto-filtrés ici (SQL opaque) -> ils restent tous-env (les
/// rollups portent env_id v67, mais l'injection dans un SQL arbitraire exigerait un parseur : différé).
///
/// LE NOM EST CHOISI POUR ÊTRE UNIQUE DANS LE CRATE, et c'est une exigence de garde : le marqueur
/// `compile_panneau_avoue(` de `sec_ff_no_unmasked_compile_in_caller_scoped_surfaces` (PARTIE 2) est
/// une recherche de TEXTE dans le corps d'une fonction. Un nom court (`compile`) serait contourné par
/// un `use` puis un appel nu ; un nom qualifié (`panneau_avoue::compile`) casserait la PARTIE 1, qui
/// compare des noms NUS. Il ne matche pas non plus `compile_panneau_avoue_masque(` (parenthèse non
/// adjacente), ce qui est voulu : le masqué n'atteint pas le compilateur non masqué.
pub(crate) fn compile_panneau_avoue(query: &str, is_soql: bool, from: i64, to: i64, env: Option<&str>) -> Result<PanneauCompile, String> {
    let query = apply_excl_placeholders(query.trim(), is_soql);
    let env_lu = environnement_lu(is_soql, env);
    if is_soql {
        // Router les PANNEAUX vers le rollup comme /api/query : « … | stats count by source »
        // lit event_rollup (qq ms) au lieu de scanner event (timeout 5 s -> cache figé/périmé).
        // COUVERTURE : cette porte est PURE (aucune Connection tenant) -> elle ne peut RIEN établir, donc
        // elle AVOUE (`RollupCoverage::unproven`). L'ancienne version passait `i64::MAX` — un site d'appel qui
        // AFFIRMAIT que le rollup couvrait tout l'historique sans rien pour l'établir ; c'est exactement ce que
        // le type interdit désormais, et c'est par là que le sous-compte ×6,6 mesuré le 31/07 arrivait aussi
        // dans les panneaux. « Cache SWR = éventuellement cohérent » couvre un RETARD, pas un nombre calculé sur
        // une table incomplète. CONSÉQUENCE : un panneau `stats count by <2 dims du grain>` retombe sur le
        // compilo brut (exact, plus lent) ; les ROUTES A/B single-dim, qui n'ont jamais dépendu de la couverture,
        // sont inchangées — et aucun panneau LIVRÉ n'est multi-dim (seeds.rs : tous `count by <une dim>`).
        if let Some(rr) = try_rollup_route(&query, from, to, env, RollupCoverage::unproven(), DimRollupCoverage::unproven()) {
            return Ok(PanneauCompile { sql: rr.sql, provenance: Provenance::RouteePreagrege(rr.approx, rr.cap, rr.note), env_lu });
        }
        soql_to_sql_x(&query, from, to, env).map(|sql| PanneauCompile { sql, provenance: Provenance::CompilateurBrut, env_lu })
    } else {
        Ok(PanneauCompile {
            sql: substituer_les_marqueurs_de_fenetre(&query, from, to),
            provenance: Provenance::Opaque,
            env_lu,
        })
    }
}

/// `P10.5-p` — L'environnement que le SQL compilé filtre : celui de l'appelant si (et seulement si) la requête est
/// GXQL et l'environnement non vide — les deux conditions sous lesquelles le compilateur injecte `env_id = '<env>'`.
pub(crate) fn environnement_lu(is_soql: bool, env: Option<&str>) -> Option<String> {
    if !is_soql {
        return None;
    }
    // Un environnement VIDE n'atteint pas cette fonction depuis une route : l'authentification le rend `None`
    // (`auth.rs`, `.filter(|e| !e.is_empty())` sur l'en-tête d'environnement) et le pré-chauffage passe `None`. Le
    // filtre suit la condition du compilateur (qui n'injecte rien pour un vide) pour un appel direct : il est témoigné
    // sur ce contrat-là (`av3_opaque_et_environnement_vide_ne_sont_pas_determines`), pas par une route.
    env.filter(|e| !e.is_empty()).map(str::to_string)
}

/// LA MÊME PORTE, POUR UN APPELANT AVEC MASQUES ACTIFS. GXQL -> compilation MASQUÉE (masque émis dans
/// le SQL, avant agrégation ; la route de pré-agrégat est DÉSACTIVÉE — `event_rollup` porte src_ip/host
/// en clair). SQL brut opaque -> substitution des bornes, l'appelant masque APRÈS la requête.
///
/// PROVENANCE `Opaque` DANS LES DEUX BRAS, et ce n'est pas une paresse : un GXQL masqué ne passe pas
/// par la route de pré-agrégat (donc rien à en dire), et le masque change ce que le SQL lit.
pub(crate) fn compile_panneau_avoue_masque(
    query: &str, is_soql: bool, from: i64, to: i64, env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet,
) -> Result<PanneauCompile, String> {
    let q2 = apply_excl_placeholders(query.trim(), is_soql);
    let sql = if is_soql {
        soql_to_sql_masked_x(&q2, from, to, env, masks)?
    } else {
        substituer_les_marqueurs_de_fenetre(&q2, from, to)
    };
    Ok(PanneauCompile { sql, provenance: Provenance::Opaque, env_lu: environnement_lu(is_soql, env) })
}

/// LE SQL COMPILÉ, POUR LES TÉMOINS SEULEMENT (`#[cfg(test)]`) — la même porte que
/// `PanneauCompile::sql_de_test`, sous la forme qu'attendent les témoins qui comparaient le texte produit
/// par l'ancienne fonction. La production n'a AUCUN moyen d'obtenir ce texte.
#[cfg(test)]
pub(crate) fn compile_sql_de_test(query: &str, is_soql: bool, from: i64, to: i64, env: Option<&str>) -> Result<String, String> {
    compile_panneau_avoue(query, is_soql, from, to, env).map(|pc| pc.sql)
}

/// VALIDATION DE SYNTAXE SEULE (chargement d'overlays `config.d`). Une porte NOMMÉE évite d'ouvrir un
/// accesseur au SQL pour un besoin qui n'en a pas : ces sites jetaient déjà le `Ok`.
pub(crate) fn valider_panneau(query: &str, is_soql: bool) -> Result<(), String> {
    compile_panneau_avoue(query, is_soql, 0, 0, None).map(|_| ())
}

// =====================================================================================================
// 3. L'HORIZON — JUSQU'OÙ CETTE RÉPONSE A PU VOIR
// =====================================================================================================

/// LES FAMILLES DE TABLES QUI PORTENT UN HORIZON DE CONSERVATION : la table, la clé de rétention qui la
/// coupe, et l'UNITÉ de cette clé en secondes.
///
/// DÉRIVÉE DE L'ORDRE DE SUPPRESSION QUI COUPE CHAQUE TABLE (`rollups.rs`, `retention_run`), lu ligne à
/// ligne le 2026-08-28 — pas d'une intention, et pas du NOM de la clé :
///   * `event` / `event_rollup` / `event_dim_rollup` -> `global_cutoff = n - retention_days*86400` ;
///   * `metric` -> `DELETE FROM metric WHERE ts < ?` avec `cutoff = n - metric_raw_hours*3600` ;
///   * `metric_rollup` -> `chunked_purge(db, "metric_rollup", "ts < ?", n - metric_days*86400)` ;
///   * `alert` -> `alert_days` ; `snapshot` -> `snapshot_days`.
///
/// DEUX ALLÉGATIONS DE CE MODULE SONT RÉFUTÉES ICI, ET C'ÉTAIT UN AVEU FAUX DANS LA DIRECTION OPTIMISTE.
/// (1) `metric` N'EST PAS coupée à `metric_days` : elle est vidée à `metric_raw_hours` (défaut 48 H,
/// plancher 24 h), et `metric_days` gouverne le PRÉ-AGRÉGÉ. Écrire `("metric", "metric_days")` annonçait
/// 90 jours là où la table en porte 2 — un facteur 45 au défaut, sur LA famille du constat fondateur
/// (les quatre courbes semées lisent `FROM metric` en direct). (2) `metric_rollup` EXISTE : créée
/// (`migrate.rs`), alimentée et purgée (`rollups.rs`). Un panneau qui la lit a donc un horizon DÉRIVABLE,
/// là où le refus précédent lui répondait « on ne sait pas ».
/// CE QUI RESTE VRAI DU DOSSIER : la table qu'ampute `snapshot_days` est `snapshot` (la série
/// d'instantanés de posture), PAS `dashboard_snapshot` — celle-ci n'est purgée par aucune rétention.
///
/// L'UNITÉ EST PORTÉE ICI PARCE QUE `retention_effective` REND UN NOMBRE NU : elle rend 48 pour
/// `metric_raw_hours` comme 90 pour `metric_days`, et rien dans sa signature ne dit lequel est une heure.
/// Le témoin `chaque_famille_de_retention_nomme_une_cle_reelle_avec_sa_vraie_unite` la confronte au
/// suffixe de la clé, qui est la convention du dépôt (`RETENTION_FIELDS`, `main.rs`).
pub(crate) const FAMILLES_DE_RETENTION: &[(&str, &str, i64)] = &[
    ("event", "retention_days", 86_400),
    ("event_rollup", "retention_days", 86_400),
    ("event_dim_rollup", "retention_days", 86_400),
    ("metric", "metric_raw_hours", 3_600),
    ("metric_rollup", "metric_days", 86_400),
    ("alert", "alert_days", 86_400),
    ("snapshot", "snapshot_days", 86_400),
];

/// La fenêtre demandée n'est bornée par rien (`from=0`, l'option « Tout ») : l'horizon EXISTE et il est
/// publié, mais rien n'est « resté dehors » — c'est le témoin ANTI-FATIGUE. Sans cette distinction,
/// douze panneaux sur douze porteraient le badge sur une base où rien n'a jamais été purgé, et le
/// panneau réellement amputé serait celui qu'on ne verrait plus.
pub(crate) const RAISON_FENETRE_NON_BORNEE: &str = "fenetre_non_bornee";
/// L'horizon est le PLANCHER DE RÉTENTION de la famille la plus courte que ce SQL nomme.
pub(crate) const RAISON_RETENTION: &str = "retention_floor";
/// L'horizon est la FRONTIÈRE hot/cold : sous elle les lignes d'`event` ont quitté la base vive.
pub(crate) const RAISON_COLD: &str = "cold_boundary";
/// Le SQL ne nomme AUCUNE famille dont on sache l'horizon (cas mesuré : les panneaux `banned_ip`).
/// C'est un REFUS de conclure, jamais un horizon inventé.
pub(crate) const RAISON_PORTEE_NON_DERIVABLE: &str = "portee_non_derivable";
/// Le pool de lecture n'a pas pu être pris : l'horizon n'a PAS été mesuré. Un champ absent est un champ
/// non mesuré — jamais un plancher fabriqué hors base, qui serait indiscernable d'un plancher mesuré.
pub(crate) const RAISON_HORIZON_NON_MESURE: &str = "horizon_non_mesure";
/// SERVI DEPUIS LE CACHE, ET L'HORIZON A BOUGÉ DEPUIS L'ÉCRITURE : la fenêtre calculée reste celle des
/// lignes servies (on ne certifie pas une fenêtre que les lignes n'ont pas vue), mais le lecteur est
/// prévenu que le plancher a changé.
pub(crate) const RAISON_HORIZON_PERIME: &str = "horizon_perime";
/// SERVI DEPUIS UNE LIGNE DE CACHE ÉCRITE PAR UN BINAIRE ANTÉRIEUR : elle ne porte aucun aveu. « Non
/// dit », jamais « brut / exact ».
pub(crate) const RAISON_PAYE_UTILE_ANTERIEURE: &str = "paye_utile_anterieure";
/// La charge utile en cache n'est pas relisible (JSON illisible) : le corps servi est synthétique.
pub(crate) const RAISON_PAYE_UTILE_ILLISIBLE: &str = "paye_utile_illisible";
/// Aucun payload n'existe encore pour cette plage : la mesure est en cours (chemin `warming`).
pub(crate) const RAISON_MESURE_EN_COURS: &str = "mesure_en_cours";
/// `P10.32-o` — LA LIGNE DE CACHE DE CETTE PLAGE N'A PAS PU ÊTRE LUE (lecture refusée par la base,
/// `LectureDeCache::NonLue`) : le corps servi est un refus nommé en 503 (`error`, `id`, aucune ligne, sans `warming`) —
/// ce n'est PAS une mesure en cours, et on ne sait pas ce que la ligne porte. Raison de la couverture de ce 503, posée
/// par [`coverage_synthetique`] avec sa notice [`NOTICE_LIGNE_DE_CACHE_NON_LUE`].
pub(crate) const RAISON_LIGNE_DE_CACHE_NON_LUE: &str = "cache_non_lu";
/// La notice de [`RAISON_LIGNE_DE_CACHE_NON_LUE`] (texte du produit, jamais la cause du moteur, qui va au journal).
pub(crate) const NOTICE_LIGNE_DE_CACHE_NON_LUE: &str = "la ligne de cache de ce panneau n'a pas pu être lue (lecture \
     refusée par la base) : aucune ligne n'est servie, et ce n'est pas une mesure en cours. Ce corps vide n'établit PAS \
     une absence ; le détail est au journal de l'exploitant.";
/// `P10.32-o` (vague BH) — LA DERNIÈRE ÉCRITURE DE CETTE LIGNE DE CACHE A ÉTÉ REFUSÉE PAR LA BASE
/// (`ecriture_de_cache_refusee`) et aucune charge n'y est : le corps servi est un refus nommé en 503 (`error`, `id`,
/// aucune ligne, sans `warming`) — ce n'est PAS une mesure en cours. Raison de la couverture de ce 503, posée par
/// [`coverage_synthetique`] avec sa notice [`NOTICE_CACHE_NON_ECRIT`].
pub(crate) const RAISON_CACHE_NON_ECRIT: &str = "cache_non_ecrit";
/// La notice de [`RAISON_CACHE_NON_ECRIT`] (texte du produit, jamais la cause du moteur, qui va au journal).
pub(crate) const NOTICE_CACHE_NON_ECRIT: &str = "la base a refusé d'écrire dans le cache le résultat du dernier calcul de \
     ce panneau : aucune ligne n'est servie, et ce n'est pas une mesure en cours. Ce corps vide n'établit PAS une absence ; \
     un nouveau calcul est armé au plus une fois par durée du cache, le détail est au journal de l'exploitant.";
/// `P10.32-o` (vague BH) — la cause posée sous `stats.rafraichissement_en_echec` d'une charge VALIDE servie depuis le cache
/// quand la dernière écriture de sa ligne a été refusée : la charge servie n'est pas celle du dernier calcul.
pub(crate) const CAUSE_ECRITURE_DU_CACHE_REFUSEE: &str = "le résultat du dernier calcul n'a pas pu être écrit dans le cache \
     (écriture refusée par la base) : la charge servie est la précédente";
/// `P10.32-o` (vague BH, correction) — la cause posée sous `stats.rafraichissement_en_echec` d'une charge VALIDE servie
/// depuis le cache quand le dernier calcul a ÉCHOUÉ et que l'écriture de cet échec (l'aveu joint à la charge) a été
/// refusée. Suivie de la phrase servie de la classe d'échec, jamais du texte du moteur.
pub(crate) const CAUSE_ECHEC_DU_CALCUL_NON_ECRIT_AU_CACHE: &str = "le dernier calcul a échoué et cet échec n'a pas pu être \
     écrit dans le cache (écriture refusée par la base) : la charge servie est la précédente. Cause du calcul : ";
/// `P10.32-o` — LE CALCUL DU PANNEAU A ÉCHOUÉ (erreur du moteur, budget dépassé, panique du fil) : le
/// corps servi porte la cause dans `error` et n'établit PAS une absence. Il est écrit dans le cache à la
/// place du résultat, donc re-servi jusqu'à l'expiration du ttl, puis retenté — jamais une chauffe
/// éternelle, jamais un `warming` qui ne viendra pas.
pub(crate) const RAISON_CALCUL_ECHOUE: &str = "calcul_echoue";

/// LA PHRASE DU PLAFOND TOP-N, pour un SQL OPAQUE qui nomme `event_dim_rollup`. Elle dit qu'un plafond
/// EXISTE, PAS de combien il mord : aucune `Sonde` n'est dérivable d'un SQL qu'on n'analyse pas, donc
/// `truncated` reste ABSENT (case absente = case non mesurée, cf. `topn_cap`).
pub(crate) const NOTE_PLAFOND_TOPN_OPAQUE: &str =
    "ce panneau lit un pré-agrégé par dimension (`event_dim_rollup`) dont le plafond top-N ABANDONNE, à \
     chaque bucket horaire, les valeurs hors des plus fréquentes : le compte affiché est un PLANCHER. \
     L'AMPLEUR de ce qui est écarté n'est pas mesurable depuis ce chemin (le SQL y est opaque) — elle \
     n'est donc pas publiée, et son absence ne vaut pas zéro.";

/// Le nom de table que la branche opaque cherche pour savoir qu'un plafond top-N est en jeu.
const TABLE_DIM_ROLLUP: &str = "event_dim_rollup";

/// LE SQL PRIVÉ DE SES LITTÉRAUX DE CHAÎNE — ce que le balayage de jetons doit lire.
///
/// POURQUOI CE PASSAGE EXISTE, ET POURQUOI « FAUX POSITIF = DIRECTION SÛRE » ÉTAIT FAUX. Un nom de table
/// APPARAISSANT DANS UNE CHAÎNE (`… WHERE rule LIKE '%event%'`) faisait entrer la famille `event` dans la
/// dérivation ; l'horizon retenu étant le PLUS COURT, un panneau d'alertes (90 j) se voyait attribuer
/// l'horizon des événements (30 j) et publiait `older_outside_window: true` sur une réponse COMPLÈTE.
/// Ce n'est pas un horizon « trop prudent » : c'est un AVEU FAUX présenté comme mesuré — exactement ce
/// que le témoin anti-fatigue de ce module interdit. Les littéraux sont donc RETIRÉS avant le balayage
/// (`''` doublé = échappement SQL, traité comme tel), et la position des jetons restants est préservée
/// (les littéraux sont remplacés par un séparateur, jamais supprimés en collant leurs voisins).
fn sql_sans_litteraux(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut reste = sql.chars().peekable();
    while let Some(c) = reste.next() {
        if c != '\'' && c != '"' {
            out.push(c);
            continue;
        }
        out.push(' '); // séparateur : deux jetons voisins d'un littéral ne se recollent pas
        loop {
            match reste.next() {
                None => break,
                Some(f) if f == c => {
                    // `''` (ou `""`) DANS un littéral = un guillemet échappé, pas une fin de littéral.
                    if reste.peek() == Some(&c) {
                        reste.next();
                        continue;
                    }
                    break;
                }
                Some(_) => {}
            }
        }
    }
    out
}

/// Les CLÉS DE RÉTENTION que ce SQL met en jeu, AVEC LEUR UNITÉ, dérivées par balayage de JETONS
/// d'identifiant (même technique que `LectureDuBrasFroid::derivee_du_sql`, `cold_store/exactness.rs`),
/// sur le SQL PRIVÉ DE SES LITTÉRAUX.
///
/// CE QU'ELLE NE TIENT PAS : un ALIAS ou une colonne homonyme d'une table de famille compte encore
/// (`SELECT ts AS event …`) ; une indirection par VUE ne nomme rien et tombe dans `portee_non_derivable`
/// (un refus, jamais un horizon faux).
fn cles_de_retention_du_sql(sql: &str) -> Vec<(&'static str, i64)> {
    let sans = sql_sans_litteraux(sql);
    let mut cles: Vec<(&'static str, i64)> = Vec::new();
    for jeton in sans.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        for (table, cle, unite) in FAMILLES_DE_RETENTION {
            if jeton.eq_ignore_ascii_case(table) && !cles.iter().any(|(k, _)| k == cle) {
                cles.push((cle, *unite));
            }
        }
    }
    cles
}

/// Ce SQL nomme-t-il un identifiant donné (mêmes JETONS, même retrait des littéraux) ?
fn sql_nomme(sql: &str, ident: &str) -> bool {
    sql_sans_litteraux(sql).split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).any(|j| j.eq_ignore_ascii_case(ident))
}

/// LA FRONTIÈRE FROIDE, quand elle s'applique. Elle ne s'applique QU'À `event` : le tier froid ne
/// columnarise que cette table (`P10.5-h` — il n'existe aucun miroir froid de `metric`), et un panneau
/// qui lit `event_rollup` n'a jamais eu accès au pré-agrégé froid. L'appliquer à une autre famille
/// annoncerait un horizon PLUS RÉCENT que le vrai : un aveu faux, pas un aveu prudent.
///
/// `P10.20-b` (vague AR) — `Err(clé)` : le réglage de rétention dont la frontière dérive est écrit et illisible. Aucune
/// frontière n'est fabriquée sur le repli env/défaut ; l'horizon le dit (`RAISON_HORIZON_NON_MESURE`, `reglage_non_lu`).
#[cfg(feature = "cold_tier")]
fn borne_froide(conn: &Connection, conf: &HashMap<String, String>, now_s: i64, nomme_event: bool) -> Result<Option<i64>, &'static str> {
    if !nomme_event || !crate::cold_store::cold_tier_runtime_on(conf) {
        return Ok(None);
    }
    let Ok(rd) = retention_effective_lue(conn, conf, "retention_days") else {
        return Err("retention_days");
    };
    Ok(Some(crate::cold_store::cold_query_boundary(conn, conf, now_s, rd)))
}
#[cfg(not(feature = "cold_tier"))]
fn borne_froide(_conn: &Connection, _conf: &HashMap<String, String>, _now_s: i64, _nomme_event: bool) -> Result<Option<i64>, &'static str> {
    Ok(None)
}

/// L'HORIZON D'UNE RÉPONSE DE PANNEAU. REND TOUJOURS UN OBJET — un aveu conditionnel serait
/// indiscernable d'un aveu oublié.
///
/// `searched_from` = la borne basse RÉELLEMENT demandée ; `horizon_ts` = l'instant sous lequel cette
/// fenêtre n'a rien pu voir ; `older_outside_window` = la fenêtre demandée descend-elle sous cet
/// horizon ; `calcule_a` = quand ce verdict a été pris. La marge de comparaison est `CACHE_BUCKET_S` —
/// la granularité à laquelle le dépôt tient DÉJÀ deux fenêtres pour identiques (`cache_range_key`), pas
/// une tolérance inventée.
pub(crate) fn horizon(db_path: &str, conf: &HashMap<String, String>, pc: &PanneauCompile, from: i64) -> Value {
    horizon_et_frontiere(db_path, conf, pc, from).0
}

/// `P10.5-q` — L'HORIZON ET, À CÔTÉ, LA FRONTIÈRE FROIDE TELLE QU'ELLE A ÉTÉ MESURÉE (`None` = tier froid
/// absent, éteint, ou requête qui ne nomme pas `event`). `horizon_du_sql` la calculait déjà et la PERDAIT
/// dans une comparaison ; `executer` en a besoin pour dire, dans `stats.cold`, que cette lecture n'a pas
/// vu la bande froide — la même case et la même phrase que le pivot et les jeux de données.
pub(crate) fn horizon_et_frontiere(db_path: &str, conf: &HashMap<String, String>, pc: &PanneauCompile, from: i64) -> (Value, Option<i64>) {
    horizon_et_frontiere_selon_l_index(db_path, conf, &pc.sql, pc.env_lu.as_deref(), from, now())
}

/// Cœur testable de `horizon` : `now_s` injecté (aucune horloge murale dans les témoins).
pub(crate) fn horizon_du_sql(db_path: &str, conf: &HashMap<String, String>, sql: &str, from: i64, now_s: i64) -> Value {
    horizon_et_frontiere_du_sql(db_path, conf, sql, from, now_s).0
}

/// `horizon_du_sql` qui rend AUSSI la frontière froide mesurée (cf. `horizon_et_frontiere`). Sans panneau compilé,
/// l'environnement lu n'est pas connu : `None`, donc l'horizon prend la fenêtre la plus courte des politiques par index
/// et de la globale (`P10.5-p`).
pub(crate) fn horizon_et_frontiere_du_sql(db_path: &str, conf: &HashMap<String, String>, sql: &str, from: i64, now_s: i64) -> (Value, Option<i64>) {
    horizon_et_frontiere_selon_l_index(db_path, conf, sql, None, from, now_s)
}

/// `P10.5-p` — LA CLÉ DE RÉTENTION QUE LES POLITIQUES PAR INDEX REMPLACENT. Une `index_policy` purge `event`,
/// `event_rollup` et `event_dim_rollup` à SA fenêtre et les exclut de la purge globale (`retention_prune_table`,
/// `rollups.rs`) : ce sont exactement les trois familles de `FAMILLES_DE_RETENTION` qui portent cette clé.
const RETENTION_REMPLACEE_PAR_LES_POLITIQUES: &str = "retention_days";

/// `P10.5-p` — L'aveu d'un horizon NON MESURÉ parce qu'un plafond par index qui tourne peut couper ce que ce panneau
/// lit et que l'environnement qu'il lit n'est pas déterminé. Une politique de DURÉE seule ne le rend jamais : la plus
/// courte des fenêtres reste un plancher sûr (`PolitiqueDeLIndex::LaPlusCourte`).
pub(crate) const NOTICE_POLITIQUE_PAR_INDEX_ENVIRONNEMENT_NON_DETERMINE: &str = "l'horizon de conservation de ce panneau \
     n'est PAS établi : un plafond de lignes ou d'octets propre à un environnement est actif, et l'environnement que \
     ce panneau lit n'est pas déterminé — aucune fenêtre de rétention n'est donc un plancher sûr pour ce qu'il lit. \
     Cette réponse ne dit RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";

/// `P10.5-p` — L'aveu d'un horizon NON MESURÉ parce que l'environnement lu porte un plafond de lignes ou d'octets sur
/// `event` (`retention_apply_caps`, `rollups.rs`) QUI TOURNE (`plafonds_d_index_actifs` : jamais sous le tier froid
/// actif) : il supprime les plus anciennes au-delà du plafond, à un instant qu'aucune durée ne permet de dériver.
pub(crate) const NOTICE_POLITIQUE_PAR_INDEX_PLAFONNEE: &str = "l'horizon de conservation de ce panneau n'est PAS établi : \
     l'environnement qu'il lit porte un plafond de lignes ou d'octets, qui supprime les événements les plus anciens \
     au-delà du plafond, plus récents peut-être que toute fenêtre de rétention. Cette réponse ne dit RIEN de ce qu'elle \
     a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";

/// `P10.5-p` — L'aveu d'un horizon NON MESURÉ parce que les politiques par index n'ont pas pu être lues (énoncé refusé
/// sur une table présente, ou une ligne illisible : `rollups::lire_les_politiques_d_index`). La purge, elle, retombe
/// alors sur la rétention globale pour ce qu'elle n'a pas lu ; publier la globale comme horizon MESURÉ serait certifier
/// une fenêtre que la lecture n'a pas établie.
pub(crate) const NOTICE_POLITIQUE_PAR_INDEX_NON_LUE: &str = "l'horizon de conservation de ce panneau n'est PAS établi : les \
     politiques de rétention par environnement n'ont pas pu être lues, et aucune fenêtre n'est calculée sur la seule \
     rétention globale. Cette réponse ne dit RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";

/// `P10.5-p` — CE QUE LES POLITIQUES PAR INDEX FONT À L'HORIZON DES FAMILLES `retention_days`.
enum PolitiqueDeLIndex {
    /// Aucune politique ne mord sur ce que ce panneau lit : la rétention globale reste le plancher (octet d'avant).
    Globale,
    /// L'environnement lu a SA fenêtre, en jours, déjà bornée comme la purge la borne (`politique_validee`, partagée par ses deux lecteurs).
    /// Plus longue que la globale, elle est aussi la vraie : la purge globale exclut cet environnement.
    Propre(i64),
    /// Environnement lu non déterminé, politiques de DURÉE seules : la plus courte fenêtre (en jours) des politiques ;
    /// l'horizon prend la plus courte d'elle et de la globale — le plancher sous lequel au moins un index a pu être
    /// purgé, comme la lecture froide sans index nommé (`premier_jour_de_la_portee`).
    LaPlusCourte(i64),
    /// Un plafond qui tourne peut couper ce que ce panneau lit, et l'environnement lu n'est pas déterminé.
    EnvironnementNonDetermine,
    /// L'environnement lu porte un plafond qui tourne sur `event`, et ce panneau lit `event`.
    Plafonnee,
    /// Les politiques n'ont pas pu être lues (`rollups::lire_les_politiques_d_index` en `Err`) : rien n'est dérivé.
    NonLue,
}

/// `P10.5-p` — La politique applicable, dérivée des politiques lues comme la PURGE les valide (`politique_validee`,
/// `rollups.rs` : même plancher, même plafond, mêmes noms écartés). `plafonds_mordent` : le SQL lit `event` (les plafonds ne
/// coupent que lui) ET les plafonds tournent (`plafonds_d_index_actifs`).
fn politique_de_l_index(politiques: &[IndexPolicy], env: Option<&str>, plafonds_mordent: bool) -> PolitiqueDeLIndex {
    let plafonnee = |p: &IndexPolicy| plafonds_mordent && (p.max_rows > 0 || p.max_bytes > 0);
    match env {
        Some(e) => match politiques.iter().find(|p| p.name == e) {
            None => PolitiqueDeLIndex::Globale,
            Some(p) if plafonnee(p) => PolitiqueDeLIndex::Plafonnee,
            Some(p) if p.retention_days > 0 => PolitiqueDeLIndex::Propre(p.retention_days),
            Some(_) => PolitiqueDeLIndex::Globale,
        },
        None => {
            if politiques.iter().any(plafonnee) {
                return PolitiqueDeLIndex::EnvironnementNonDetermine;
            }
            match politiques.iter().filter(|p| p.retention_days > 0).map(|p| p.retention_days).min() {
                Some(jours) => PolitiqueDeLIndex::LaPlusCourte(jours),
                None => PolitiqueDeLIndex::Globale,
            }
        }
    }
}

/// `P10.5-p` — Lit la politique applicable, seulement si le SQL nomme une famille que les politiques gouvernent : sinon
/// aucune clé ne la consulterait (seule la clé `retention_days` la consulte, au chemin chaud comme dans la voie froide).
/// Lecture non faite : `NonLue`, jamais la globale (le repli de la purge n'est pas un horizon mesuré).
fn politique_lue(c: &Connection, nomme_une_famille_des_politiques: bool, env: Option<&str>, plafonds_mordent: bool) -> PolitiqueDeLIndex {
    politique_lue_ou_refus(c, nomme_une_famille_des_politiques, env, plafonds_mordent).unwrap_or(PolitiqueDeLIndex::NonLue)
}

/// `politique_lue`, le refus de la lecture rendu tel quel (avec son code SQLite) : la voie froide lue en tire la classe
/// occupée (`politique_de_la_voie_froide_lue`) ; l'horizon du panneau le range en `NonLue`, parce qu'il lit sous une
/// lecture tenue (`sous_la_lecture_de_l_horizon_du_panneau`) où l'occupation est déjà jugée par la sonde.
fn politique_lue_ou_refus(
    c: &Connection, nomme_une_famille_des_politiques: bool, env: Option<&str>, plafonds_mordent: bool,
) -> rusqlite::Result<PolitiqueDeLIndex> {
    if !nomme_une_famille_des_politiques {
        return Ok(PolitiqueDeLIndex::Globale);
    }
    crate::rollups::lire_les_politiques_d_index(c).map(|politiques| politique_de_l_index(&politiques, env, plafonds_mordent))
}

/// `P10.29-w` (vague BE) — la sonde qui PREND la lecture de l'horizon d'un panneau : elle lit le schéma (aucune donnée),
/// et c'est son échec, avec son CODE, qui dit une base occupée.
const SONDE_DE_L_HORIZON_DU_PANNEAU: &str = "SELECT count(*) FROM main.sqlite_master";

/// `P10.29-w` (vague BE) — L'HORIZON D'UN PANNEAU SE LIT SOUS UNE LECTURE TENUE. Avant, `horizon_et_frontiere_selon_l_index`
/// lisait les politiques par index (`politique_lue`, qui range tout refus en `NonLue`) puis chaque réglage de rétention
/// (`retention_effective_lue`, texte sans code), chacun en autocommit : sur une base occupée, la couverture disait « les
/// politiques de rétention par environnement n'ont pas pu être lues » ou « réglage `metric_raw_hours` non lu ». Même
/// patron que `HorizonDeLecture::lire` (`cold_store/reader.rs`) et `retention_de_la_famille_lue` : un point de sauvegarde
/// dont le PREMIER énoncé est la sonde, classée par son code (`classe_de_la_prise`) ; sonde passée, la lecture de `main`
/// est TENUE jusqu'à la libération, et `lire` (politiques, réglages, frontière froide) ne peut plus rencontrer le verrou
/// d'un autre écrivain. Le point est libéré sur le succès comme sur l'échec de la sonde : le pool ferme une connexion
/// rendue en transaction (`read_conn_put`). L'échec du `RELEASE` n'est pas avalé : il est rendu, classé comme la sonde,
/// et un horizon lu n'est alors PAS servi comme mesuré (témoin `be5_` (5)). En production il ne survient que si SQLite a
/// annulé la transaction d'office pendant `lire` (IOERR, NOMEM, FULL : le `RELEASE` ne trouve plus son point) ; les
/// témoins ne fabriquent pas ce retour d'office, ils refusent le `RELEASE` par un autorisateur. Quand la sonde ET le
/// `RELEASE` échouent, c'est la classe de la sonde qui est servie (témoin (8) : base prise, `RELEASE` refusé, dite
/// occupée). Un `SAVEPOINT` refusé est rendu tel quel, et `lire` n'est alors pas exécutée (témoin (6)).
fn sous_la_lecture_de_l_horizon_du_panneau<T>(c: &Connection, lire: impl FnOnce() -> T) -> Result<T, &'static str> {
    c.execute_batch("SAVEPOINT horizon_du_panneau").map_err(classe_de_la_prise)?;
    let lu = c.query_row(SONDE_DE_L_HORIZON_DU_PANNEAU, [], |r| r.get::<_, i64>(0)).map_err(classe_de_la_prise).map(|_| lire());
    let libere = c.execute_batch("RELEASE horizon_du_panneau").map_err(classe_de_la_prise);
    match (lu, libere) {
        (Err(e), _) => Err(e),
        (Ok(_), Err(e)) => Err(e),
        (Ok(v), Ok(())) => Ok(v),
    }
}

/// Le cœur de l'horizon d'un panneau : `env` = l'environnement que son SQL lit, quand il est déterminé (`P10.5-p`).
pub(crate) fn horizon_et_frontiere_selon_l_index(
    db_path: &str, conf: &HashMap<String, String>, sql: &str, env: Option<&str>, from: i64, now_s: i64,
) -> (Value, Option<i64>) {
    let mut cov = json!({ "searched_from": from, "calcule_a": now_s });
    let cles = cles_de_retention_du_sql(sql);
    if cles.is_empty() {
        cov["reason"] = json!(RAISON_PORTEE_NON_DERIVABLE);
        cov["notice"] = json!(
            "l'horizon de conservation de ce panneau n'est PAS dérivable : sa requête ne nomme aucune \
             table dont la rétention est connue. Ce n'est donc pas « rien n'a été perdu » — c'est « on \
             ne sait pas jusqu'où cette réponse a pu voir »."
        );
        return (cov, None);
    }
    let nomme_event = sql_nomme(sql, "event");
    // UNE SEULE prise du pool de LECTURE (jamais le mutex d'écriture partagé). DÉFAUT EXPLICITE : pool
    // indisponible -> `None`, et l'aveu le dit SANS horizon_ts. Un plancher calculé hors base serait
    // indiscernable d'un plancher mesuré.
    // `P10.20-b` (vague AR) — UN RÉGLAGE ÉCRIT ILLISIBLE NE FABRIQUE NI PLANCHER NI FRONTIÈRE. Avant, `retention_effective`
    // rendait le repli env/défaut et l'horizon était publié comme mesuré sur une valeur que l'admin n'a pas écrite. La
    // première clé non lue est gardée (`non_lue`) et l'aveu dit « non établi », sans `horizon_ts`.
    // `P10.5-p` — LA POLITIQUE PAR INDEX APPLICABLE remplace la rétention globale des familles qu'elle gouverne ; si
    // elle ne peut pas être dérivée (environnement non déterminé, plafond), l'horizon n'est PAS publié (`politique_muette`).
    // `P10.29-w` (vague BE) — LA LECTURE EST PRISE PUIS TENUE (`sous_la_lecture_de_l_horizon_du_panneau`) : une base
    // occupée à la prise est dite occupée (`NOTICE_HORIZON_FROID_BASE_OCCUPEE`), une prise refusée hors occupation est
    // dite non prise ; ni l'une ni l'autre n'est plus servie « politiques non lues » ni « réglage non lu ». Pool non pris
    // (connexion de lecture non ouverte, par exemple un chemin absent : ouverture en lecture seule refusée) : `None`, servi
    // sous l'aveu d'avant, `NOTICE_POOL_NON_PRIS`, distinct de la lecture non prise (témoin `be5_` (7)).
    type Lu = (Option<(i64, &'static str)>, Option<i64>, Option<&'static str>, Option<&'static str>);
    let lu: Option<Result<Lu, &'static str>> = read_with(db_path, None, |c| Some(sous_la_lecture_de_l_horizon_du_panneau(c, || {
        #[cfg(test)]
        crate::query_exec::crochet_de_l_union_froide::passer(db_path, crate::query_exec::crochet_de_l_union_froide::Etape::ApresLaPriseDeLHorizonDuPanneau);
        let mut haut: Option<(i64, &'static str)> = None;
        let mut non_lue: Option<&'static str> = None;
        let mut politique_muette: Option<&'static str> = None;
        let gouvernee = cles.iter().any(|(cle, _)| *cle == RETENTION_REMPLACEE_PAR_LES_POLITIQUES);
        let politique = politique_lue(c, gouvernee, env, nomme_event && plafonds_d_index_actifs(conf));
        for (cle, unite) in &cles {
            // UNE CLÉ INCONNUE DE `RETENTION_FIELDS` REND 0, ET UN 0 ICI SERAIT INDISCERNABLE D'UN POOL
            // INDISPONIBLE : le témoin `chaque_famille_de_retention_nomme_une_cle_reelle_avec_sa_vraie_unite`
            // interdit cet état EN AMONT, sur la table des familles, plutôt que de le rattraper ici.
            let valeur = match retention_effective_lue(c, conf, cle) {
                Ok(valeur) => valeur,
                Err(_) => {
                    non_lue.get_or_insert(*cle);
                    continue;
                }
            };
            let valeur = if *cle == RETENTION_REMPLACEE_PAR_LES_POLITIQUES {
                match politique {
                    PolitiqueDeLIndex::Globale => valeur,
                    PolitiqueDeLIndex::Propre(jours) => jours,
                    PolitiqueDeLIndex::LaPlusCourte(jours) => valeur.min(jours),
                    PolitiqueDeLIndex::EnvironnementNonDetermine => {
                        politique_muette = Some(NOTICE_POLITIQUE_PAR_INDEX_ENVIRONNEMENT_NON_DETERMINE);
                        continue;
                    }
                    PolitiqueDeLIndex::Plafonnee => {
                        politique_muette = Some(NOTICE_POLITIQUE_PAR_INDEX_PLAFONNEE);
                        continue;
                    }
                    PolitiqueDeLIndex::NonLue => {
                        politique_muette = Some(NOTICE_POLITIQUE_PAR_INDEX_NON_LUE);
                        continue;
                    }
                }
            } else {
                valeur
            };
            if valeur <= 0 {
                continue;
            }
            let ts = now_s - valeur * unite;
            // PLUSIEURS FAMILLES : on garde le `horizon_ts` LE PLUS HAUT, c'est-à-dire la rétention la
            // plus COURTE — celle qui ampute le plus.
            if haut.map(|(h, _)| ts > h).unwrap_or(true) {
                haut = Some((ts, RAISON_RETENTION));
            }
        }
        let frontiere = match borne_froide(c, conf, now_s, nomme_event) {
            Ok(frontiere) => frontiere,
            Err(cle) => {
                non_lue.get_or_insert(cle);
                None
            }
        };
        if let Some(b) = frontiere {
            if haut.map(|(h, _)| b > h).unwrap_or(true) {
                haut = Some((b, RAISON_COLD));
            }
        }
        (haut, frontiere, non_lue, politique_muette)
    })));
    let (mesure, frontiere, non_lue, politique_muette): Lu = match lu {
        None => (None, None, None, None),
        Some(Ok(lu)) => lu,
        Some(Err(notice)) => {
            cov["reason"] = json!(RAISON_HORIZON_NON_MESURE);
            cov["notice"] = json!(notice);
            return (cov, None);
        }
    };
    if let Some(cle) = non_lue {
        cov["reason"] = json!(RAISON_HORIZON_NON_MESURE);
        cov["reglage_non_lu"] = json!(cle);
        cov["notice"] = json!(notice_de_reglage_non_lu(cle));
        return (cov, frontiere);
    }
    if let Some(notice) = politique_muette {
        cov["reason"] = json!(RAISON_HORIZON_NON_MESURE);
        cov["notice"] = json!(notice);
        return (cov, frontiere);
    }
    let Some((horizon_ts, raison)) = mesure else {
        cov["reason"] = json!(RAISON_HORIZON_NON_MESURE);
        cov["notice"] = json!(NOTICE_POOL_NON_PRIS);
        return (cov, frontiere);
    };
    cov["horizon_ts"] = json!(horizon_ts);
    let dehors = from > 0 && from + CACHE_BUCKET_S < horizon_ts;
    cov["older_outside_window"] = json!(dehors);
    cov["reason"] = json!(if from <= 0 { RAISON_FENETRE_NON_BORNEE } else { raison });
    cov["notice"] = json!(notice_d_horizon(raison, dehors, from));
    (cov, frontiere)
}

/// L'aveu d'un horizon NON ÉTABLI parce que le réglage de rétention écrit `cle` n'a pas été lu. Partagé par
/// `horizon_et_frontiere_du_sql` et `horizon_de_la_voie_froide_lue` : une seule écriture de la phrase.
fn notice_de_reglage_non_lu(cle: &str) -> String {
    format!(
        "l'horizon de conservation de ce panneau n'est PAS établi : le réglage de rétention écrit `{cle}` n'a pas pu \
         être lu (valeur non entière, ou lecture refusée), et aucun horizon n'est calculé sur l'environnement ou le \
         défaut. Cette réponse ne dit donc RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas."
    )
}

/// L'aveu d'un horizon NON MESURÉ parce que le pool de lecture n'a pas pu être pris (mêmes deux appelants).
const NOTICE_POOL_NON_PRIS: &str = "le pool de lecture n'a pas pu être pris ; l'horizon n'a PAS été mesuré. Cette réponse ne \
     dit donc RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";

/// `P10.29-w` — L'aveu d'un horizon NON MESURÉ parce que la base était OCCUPÉE (verrou tenu par une autre opération)
/// quand l'horizon se lisait : sur une réponse dont le bras froid a été lu, `event` par le lecteur froid
/// (`plancher_de_l_horizon_froid`) ou une famille chaude (`retention_de_la_famille_lue`) ; sur l'horizon d'un panneau
/// (vague BE), la prise de sa lecture (`sous_la_lecture_de_l_horizon_du_panneau`). Ce n'est ni un réglage illisible ni des
/// politiques non lues, réessayer suffit.
pub(crate) const NOTICE_HORIZON_FROID_BASE_OCCUPEE: &str = "la base est occupée (verrou tenu par une autre opération) : \
     l'horizon de conservation de cette lecture n'a PAS été mesuré, réessayez dans un instant. Cette réponse ne dit donc \
     RIEN de ce qu'elle a pu voir — ni qu'elle est complète, ni qu'elle ne l'est pas.";

/// `P10.29-w` — L'aveu d'un horizon NON MESURÉ parce que la lecture de l'horizon (d'une famille sous la voie froide lue,
/// ou d'un panneau) n'a pas été prise (refus du moteur au point de sauvegarde, à la sonde ou à la libération, hors
/// occupation) : aucun réglage n'est en cause.
pub(crate) const NOTICE_HORIZON_FROID_NON_PRIS: &str = "la lecture de l'horizon de conservation n'a pas pu être prise \
     (refus de la base) ; l'horizon n'a PAS été mesuré. Cette réponse ne dit donc RIEN de ce qu'elle a pu voir — ni \
     qu'elle est complète, ni qu'elle ne l'est pas.";

/// `P10.29-w` — LE PLANCHER DE `event` SOUS LA VOIE FROIDE LUE, ET LA CLASSE DE SON ÉCHEC. Avant, tout échec de
/// `ColdUnionMeta::premier_instant_servi` était rangé sous « retention_days » : une base occupée se lisait « réglage de
/// rétention écrit non lu ». La classe vient du classeur des voies froides (`en_classant_la_voie_froide`, code SQLite
/// noté par `texte_de_la_voie_froide`), jamais du texte, sauf la cause FIXE du réglage illisible.
/// `Err(Ok(cle))` : réglage non lu ; `Err(Err(notice))` : horizon non mesuré pour une autre raison, dite.
#[cfg(feature = "cold_tier")]
pub(crate) fn plancher_de_l_horizon_froid(
    c: &rusqlite::Connection,
    conf: &HashMap<String, String>,
    boundary: i64,
    env_filter: Option<&str>,
) -> Result<i64, Result<&'static str, &'static str>> {
    use crate::query_exec::EchecDeRequete;
    crate::query_exec::en_classant_la_voie_froide(|| crate::cold_store::ColdUnionMeta::premier_instant_servi(c, conf, boundary, env_filter))
        .map_err(|echec| match echec {
            EchecDeRequete::Occupee { .. } => Err(NOTICE_HORIZON_FROID_BASE_OCCUPEE),
            e if crate::cold_store::ColdUnionMeta::est_le_reglage_non_lu(e.texte()) => Ok("retention_days"),
            _ => Err(NOTICE_HORIZON_FROID_NON_PRIS),
        })
}

/// `P10.29-w` (vague BD) — LES POLITIQUES PAR INDEX SOUS LA VOIE FROIDE LUE, ET LA CLASSE DE LEUR REFUS. Avant,
/// `politique_lue` rangeait tout refus en `NonLue` : sur une base occupée AVANT l'appel (pool chaud), `SELECT ts FROM
/// event` rendait « les politiques de rétention par environnement n'ont pas pu être lues », alors que réessayer suffit.
/// `Err(notice)` : la lecture a rencontré une base occupée (code BUSY ou LOCKED, `code_de_base_occupee`, jamais le
/// texte) ; tout autre refus (ligne illisible, table refusée) reste `NonLue`.
#[cfg(feature = "cold_tier")]
fn politique_de_la_voie_froide_lue(c: &Connection, gouvernee: bool, env: Option<&str>) -> Result<PolitiqueDeLIndex, &'static str> {
    match politique_lue_ou_refus(c, gouvernee, env, false) {
        Ok(politique) => Ok(politique),
        Err(e) if e.sqlite_error_code().map(crate::query_exec::code_de_base_occupee).unwrap_or(false) => Err(NOTICE_HORIZON_FROID_BASE_OCCUPEE),
        Err(_) => Ok(PolitiqueDeLIndex::NonLue),
    }
}

/// `P10.29-w` (vague BC) — la sonde qui PREND la lecture de `main` avant le réglage de rétention d'une famille chaude :
/// elle lit le schéma (aucune donnée), et c'est son échec, avec son CODE, qui dit une base occupée.
#[cfg(feature = "cold_tier")]
const SONDE_DE_LA_RETENTION_DE_LA_FAMILLE: &str = "SELECT count(*) FROM main.sqlite_master";

/// `P10.29-w` (vague BC) — la classe de l'échec d'un énoncé de PRISE (point de sauvegarde, sonde, libération), par son
/// CODE SQLite : occupée (`code_de_base_occupee`), sinon lecture non prise. Jamais un réglage non lu. Partagée par la voie
/// froide lue (`retention_de_la_famille_lue`) et l'horizon d'un panneau (`sous_la_lecture_de_l_horizon_du_panneau`).
fn classe_de_la_prise(e: rusqlite::Error) -> &'static str {
    let occupee = e.sqlite_error_code().map(crate::query_exec::code_de_base_occupee).unwrap_or(false);
    if occupee { NOTICE_HORIZON_FROID_BASE_OCCUPEE } else { NOTICE_HORIZON_FROID_NON_PRIS }
}

/// `P10.29-w` (vague BC) — LE RÉGLAGE DE RÉTENTION D'UNE FAMILLE CHAUDE SOUS LA VOIE FROIDE LUE, ET LA CLASSE DE SON
/// ÉCHEC. `retention_effective_lue` rend un texte sans code : sur une base occupée, la couverture disait « réglage
/// `metric_raw_hours` (ou un autre) non lu ». Même patron que `HorizonDeLecture::lire` (`cold_store/reader.rs`) : un
/// point de sauvegarde dont le PREMIER énoncé est la sonde, classée par son code (`classe_de_la_prise`) ; sonde passée,
/// la lecture de `main` est TENUE jusqu'à la libération, et le réglage se lit sans pouvoir rencontrer le verrou d'un
/// autre écrivain. Seul un réglage écrit et illisible rend `Err(Ok(cle))`. Le point est libéré sur le succès comme sur
/// l'échec ; l'échec de la libération est rendu quand la lecture avait réussi, et ne masque jamais celui de la lecture.
/// Même régime que `sous_la_lecture_de_l_horizon_du_panneau` : l'échec du `RELEASE` n'est pas avalé, classé comme la
/// sonde ; en production il ne survient que si SQLite a annulé la transaction d'office pendant la lecture (IOERR, NOMEM,
/// FULL), et le témoin `be5_` (9) le provoque par un autorisateur (un réglage lu n'est alors pas servi comme mesuré).
#[cfg(feature = "cold_tier")]
pub(crate) fn retention_de_la_famille_lue(
    c: &rusqlite::Connection,
    conf: &HashMap<String, String>,
    cle: &'static str,
) -> Result<i64, Result<&'static str, &'static str>> {
    #[cfg(test)]
    let chemin_du_crochet = c.path().unwrap_or_default().to_string();
    c.execute_batch("SAVEPOINT retention_de_la_famille").map_err(|e| Err(classe_de_la_prise(e)))?;
    let lu = (|| {
        c.query_row(SONDE_DE_LA_RETENTION_DE_LA_FAMILLE, [], |r| r.get::<_, i64>(0)).map_err(|e| Err(classe_de_la_prise(e)))?;
        #[cfg(test)]
        crate::query_exec::crochet_de_l_union_froide::passer(&chemin_du_crochet, crate::query_exec::crochet_de_l_union_froide::Etape::ApresLaPriseDeLaRetentionDeLaFamille);
        retention_effective_lue(c, conf, cle).map_err(|_| Ok(cle))
    })();
    let libere = c.execute_batch("RELEASE retention_de_la_famille").map_err(|e| Err(classe_de_la_prise(e)));
    match (lu, libere) {
        (Err(e), _) => Err(e),
        (Ok(_), Err(e)) => Err(e),
        (Ok(v), Ok(())) => Ok(v),
    }
}

/// `P10.34-n` — L'HORIZON D'UNE RÉPONSE DE `/api/query` DONT LE BRAS FROID A ÉTÉ LU.
///
/// LE DÉFAUT. `horizon_et_frontiere_du_sql` est calculé AVANT l'aiguillage, pour un panneau qui ne lit jamais la bande
/// froide : il prend pour horizon de `event` le plus haut du plancher de rétention et de la frontière chaude
/// (`RAISON_COLD`), et sa phrase dit « ce panneau n'a aucun chemin pour les lire ». Posé tel quel sur une voie froide de
/// `/api/query` (union, keyset colonnaire ou oracle, vectorisées), il disait hors fenêtre — et sans chemin — ce que
/// `stats.cold.served_from` disait lu.
///
/// ICI, L'HORIZON DE `event` EST CELUI DU LECTEUR FROID : le premier instant que la lecture froide a pu servir, par
/// index (`ColdUnionMeta::premier_instant_servi`, qui lit la même `Bande` et le même instant que `HorizonDeLecture`).
/// Les autres familles que le SQL nomme gardent leur plancher de rétention (elles n'ont aucun miroir froid) ; le plus
/// haut l'emporte, comme dans l'horizon du panneau. La raison est `RAISON_RETENTION` (sous l'horizon, la rétention —
/// froide ou chaude — peut avoir supprimé les lignes) et la phrase est celle de l'horizon de conservation : aucune ne
/// parle plus d'un chemin absent. Les cinq clés de `FAMILLES_DE_RETENTION` ont un plancher strictement positif
/// (`RETENTION_FIELDS`, `main.rs`) : aucune valeur nulle ne s'y lit, d'où l'absence du `valeur <= 0` de l'horizon du
/// panneau. Une voie qui n'a PAS lu le froid n'appelle pas cette fonction : sa couverture reste l'octet d'avant.
/// Un SQL qui ne nomme aucune famille rend l'aveu de l'horizon du panneau (portée non dérivable), à l'octet.
#[cfg(feature = "cold_tier")]
pub(crate) fn horizon_de_la_voie_froide_lue(
    db_path: &str,
    conf: &HashMap<String, String>,
    sql: &str,
    from: i64,
    now_s: i64,
    boundary: i64,
    env_filter: Option<&str>,
) -> Value {
    let familles: Vec<&(&str, &str, i64)> = FAMILLES_DE_RETENTION.iter().filter(|(table, _, _)| sql_nomme(sql, table)).collect();
    if familles.is_empty() {
        return horizon_du_sql(db_path, conf, sql, from, now_s);
    }
    let mut cov = json!({ "searched_from": from, "calcule_a": now_s });
    let env = env_filter.filter(|e| !e.is_empty());
    // `P10.5-p` — `event` suit déjà les politiques par index par le lecteur froid (`premier_instant_servi`). Ses plafonds
    // ne tournent pas ici : cette voie n'existe que sous le tier froid actif, où `retention_run` les saute
    // (`plafonds_d_index_actifs`). `event_rollup` et `event_dim_rollup` prenaient la rétention globale : ils prennent la
    // politique applicable (la plus courte fenêtre sans environnement déterminé).
    type Lu = (Option<i64>, Option<&'static str>, Option<&'static str>, Option<&'static str>);
    let (haut, non_lue, horizon_froid_non_mesure, politique_muette): Lu = read_with(db_path, (None, None, None, None), |c| {
        let mut haut: Option<i64> = None;
        let mut non_lue: Option<&'static str> = None;
        let mut horizon_froid_non_mesure: Option<&'static str> = None;
        let mut politique_muette: Option<&'static str> = None;
        let gouvernee = familles.iter().any(|(_, cle, _)| *cle == RETENTION_REMPLACEE_PAR_LES_POLITIQUES);
        // `plafonds_mordent = false` : ici le tier froid est actif, aucun plafond ne tourne, et les pré-agrégés n'en
        // portent jamais ; `Plafonnee` et `EnvironnementNonDetermine` sont donc HORS D'ATTEINTE. Lecture des politiques
        // non faite : `NonLue`, pour TOUTES les familles qu'elles gouvernent, `event` compris (le lecteur froid lit les
        // politiques par le lecteur de la purge, qui avale un refus).
        // `P10.29-w` (vague BD) — une base occupée à la lecture des politiques n'est pas une politique non lue : elle
        // rejoint l'aveu de l'horizon non mesuré, pour toutes les familles que les politiques gouvernent.
        let politique = politique_de_la_voie_froide_lue(c, gouvernee, env);
        #[cfg(test)]
        crate::query_exec::crochet_de_l_union_froide::passer(db_path, crate::query_exec::crochet_de_l_union_froide::Etape::ApresLesPolitiquesDeLaVoieFroide);
        for (table, cle, unite) in &familles {
            if *cle == RETENTION_REMPLACEE_PAR_LES_POLITIQUES {
                match &politique {
                    Err(notice) => {
                        horizon_froid_non_mesure.get_or_insert(*notice);
                        continue;
                    }
                    Ok(PolitiqueDeLIndex::NonLue) => {
                        politique_muette.get_or_insert(NOTICE_POLITIQUE_PAR_INDEX_NON_LUE);
                        continue;
                    }
                    Ok(_) => {}
                }
            }
            let plancher: Result<i64, &'static str> = if *table == "event" {
                match plancher_de_l_horizon_froid(c, conf, boundary, env_filter) {
                    Ok(ts) => Ok(ts),
                    Err(Ok(cle)) => Err(cle),
                    Err(Err(notice)) => {
                        horizon_froid_non_mesure.get_or_insert(notice);
                        continue;
                    }
                }
            } else {
                // `P10.29-w` (vague BC) — le réglage de la famille chaude se lit sous la lecture tenue, et une base
                // occupée (ou une lecture non prise) n'y est pas un réglage non lu : elle rejoint l'aveu de l'horizon non
                // mesuré, comme `event`.
                let valeur = match retention_de_la_famille_lue(c, conf, *cle) {
                    Ok(v) => Ok(v),
                    Err(Ok(cle)) => Err(cle),
                    Err(Err(notice)) => {
                        horizon_froid_non_mesure.get_or_insert(notice);
                        continue;
                    }
                };
                match (*cle == RETENTION_REMPLACEE_PAR_LES_POLITIQUES, &politique, valeur) {
                    (_, _, Err(cle)) => Err(cle),
                    (false, _, Ok(valeur)) | (true, Ok(PolitiqueDeLIndex::Globale), Ok(valeur)) => Ok(now_s - valeur * unite),
                    (true, Ok(PolitiqueDeLIndex::Propre(jours)), Ok(_)) => Ok(now_s - jours * unite),
                    (true, Ok(PolitiqueDeLIndex::LaPlusCourte(jours)), Ok(valeur)) => Ok(now_s - valeur.min(*jours) * unite),
                    // HORS D'ATTEINTE : `politique_lue_ou_refus(.., false)` ne rend jamais les deux premières variantes
                    // (`politique_de_l_index`, `plafonnee` faux), et `NonLue` comme le refus occupé sont servis avant ce
                    // `match` (garde de tête de boucle).
                    (true, Ok(PolitiqueDeLIndex::EnvironnementNonDetermine | PolitiqueDeLIndex::Plafonnee | PolitiqueDeLIndex::NonLue) | Err(_), Ok(_)) => {
                        politique_muette.get_or_insert(NOTICE_POLITIQUE_PAR_INDEX_ENVIRONNEMENT_NON_DETERMINE);
                        continue;
                    }
                }
            };
            match plancher {
                Ok(ts) => {
                    if haut.map(|h| ts > h).unwrap_or(true) {
                        haut = Some(ts);
                    }
                }
                Err(cle) => {
                    non_lue.get_or_insert(cle);
                }
            }
        }
        (haut, non_lue, horizon_froid_non_mesure, politique_muette)
    });
    let politique_muette = horizon_froid_non_mesure.or(politique_muette);
    match (non_lue, politique_muette, haut) {
        (Some(cle), _, _) => {
            cov["reason"] = json!(RAISON_HORIZON_NON_MESURE);
            cov["reglage_non_lu"] = json!(cle);
            cov["notice"] = json!(notice_de_reglage_non_lu(cle));
        }
        (None, Some(notice), _) => {
            cov["reason"] = json!(RAISON_HORIZON_NON_MESURE);
            cov["notice"] = json!(notice);
        }
        (None, None, None) => {
            cov["reason"] = json!(RAISON_HORIZON_NON_MESURE);
            cov["notice"] = json!(NOTICE_POOL_NON_PRIS);
        }
        (None, None, Some(horizon_ts)) => {
            let dehors = from > 0 && from + CACHE_BUCKET_S < horizon_ts;
            cov["horizon_ts"] = json!(horizon_ts);
            cov["older_outside_window"] = json!(dehors);
            cov["reason"] = json!(if from <= 0 { RAISON_FENETRE_NON_BORNEE } else { RAISON_RETENTION });
            cov["notice"] = json!(notice_d_horizon(RAISON_RETENTION, dehors, from));
        }
    }
    cov
}

/// LA PHRASE. Elle dit ce que le corps de la réponse n'établit PAS — sans quoi une courbe écourtée se
/// relit exactement comme une courbe entière.
///
/// ELLE PARLE DE PORTÉE, JAMAIS DE PERTE, ET C'EST UNE CORRECTION MESURÉE. La version précédente écrivait
/// « réponse INCOMPLÈTE … les lignes ont été purgées et n'existent plus nulle part ». Deux affirmations
/// que `horizon_ts` NE PERMET PAS : il est un plancher de POLITIQUE, pas une observation.
///   * Sur une base plus JEUNE que la rétention (3 jours de données, rétention 30 j, fenêtre « 90 j »),
///     rien n'a jamais été purgé et la réponse est COMPLÈTE — l'ancienne phrase mentait sur douze
///     panneaux sur douze, c'est-à-dire exactement le régime d'usure que ce module existe pour éviter.
///   * Et la purge elle-même est CONDITIONNELLE : `alert` n'est coupée que sur `status<>'new'`, `event`
///     épargne `RETENTION_NONPURGE` (audit de configuration, accès opérateur, `origin='daemon'`), et un
///     gel légal épingle event/alert/snapshot sur sa fenêtre (`rollups.rs`). Des lignes SOUS l'horizon
///     peuvent donc être là — et être servies.
/// Ce que l'horizon établit VRAIMENT est une borne de PORTÉE : sous elle, ce panneau n'est assuré de
/// rien. C'est ce que la phrase dit désormais, et c'est vrai dans les deux régimes.
fn notice_d_horizon(raison: &str, dehors: bool, from: i64) -> String {
    let ou = if raison == RAISON_COLD {
        "la frontière du vieillissement froid : sous elle, les lignes ont quitté la base vive et ce \
         panneau n'a aucun chemin pour les lire"
    } else {
        "l'horizon de conservation : sous lui, la rétention peut avoir supprimé les lignes, et ce \
         panneau n'est assuré d'en voir aucune"
    };
    if dehors {
        format!(
            "PORTÉE INCOMPLÈTE : la fenêtre demandée descend SOUS {ou}. La part antérieure à cet horizon \
             est hors de portée — un creux ou une courbe qui s'y arrête n'établit donc PAS une absence. \
             Ce n'est pas non plus l'affirmation qu'il manque quelque chose : sur une base plus jeune que \
             cet horizon, il se peut que rien n'ait jamais été supprimé."
        )
    } else if from <= 0 {
        format!(
            "fenêtre non bornée : tout ce que la base porte encore a été cherché. {ou} — ce panneau ne \
             voit rien au-delà, quelle que soit la fenêtre demandée."
        )
    } else {
        format!("la fenêtre demandée tient AU-DESSUS de {ou} : rien n'est resté dehors de ce fait.")
    }
}

// =====================================================================================================
// 4. L'EXÉCUTION — LE SEUL CONSOMMATEUR DE PRODUCTION D'UN `PanneauCompile`
// =====================================================================================================

/// POSE `stats.coverage` SANS JAMAIS PANIQUER. `v["stats"]["coverage"] = …` est un `IndexMut` de
/// serde_json : il ne tolère `Object` et `Null`, et PANIQUE sur un tableau ou un scalaire. Les corps que
/// ce module estampe viennent tantôt du moteur de requête (toujours un objet), tantôt d'une LIGNE DE
/// CACHE relue — c'est-à-dire d'un texte que rien ne contraint. Une panique y tomberait dans le handler
/// qui SERT le panneau ; ce garde-fou coûte une comparaison de variante.
fn poser_coverage(v: &mut Value, cov: Value) {
    let Some(obj) = v.as_object_mut() else { return };
    match obj.get_mut("stats").and_then(|s| s.as_object_mut()) {
        Some(stats) => {
            stats.insert("coverage".to_string(), cov);
        }
        None => {
            obj.insert("stats".to_string(), json!({ "coverage": cov }));
        }
    }
}

/// EXÉCUTE un panneau compilé et ESTAMPE l'aveu. C'est le seul chemin de production qui consomme un
/// `PanneauCompile` : l'aveu n'est donc pas quelque chose qu'un appelant peut oublier de poser.
///
/// `columns` et `rows` NE SONT PAS TOUCHÉS. Seul `stats` est enrichi — c'est ce qui distingue « dire »
/// de « corriger », et la seule preuve que la voie (a) n'a pas empiété sur (b)/(c).
/// Le nom sous lequel le coffre se désigne dans l'aveu de bande froide (`stats.cold.aveu`).
pub(crate) const CHEMIN_DU_COFFRE_DES_PANNEAUX: &str = "coffre des panneaux";

pub(crate) fn executer(db_path: &str, conf: &HashMap<String, String>, pc: PanneauCompile, from: i64) -> Result<Value, String> {
    let mut v = run_query(db_path, &pc.sql)?;
    let (couverture, frontiere) = horizon_et_frontiere(db_path, conf, &pc, from);
    // `P10.5-q` — CE COFFRE NE LIT JAMAIS LA BANDE FROIDE (`run_query` = pool chaud, jamais l'union froide).
    // Quand la fenêtre demandée commence sous la frontière, il le DIT dans `stats.cold`, avec la frontière
    // mesurée par `borne_froide` — la même case et la même phrase que le pivot et les jeux de données, que
    // la console lit déjà. Sans tier froid, ou sur une requête qui ne nomme pas `event`, rien n'est ajouté :
    // la charge utile reste byte-identique. `columns`/`rows` ne sont jamais touchés.
    if let Some(aveu) = crate::handlers::datamodels::aveu_de_bande_froide_du_chemin(from, frontiere, CHEMIN_DU_COFFRE_DES_PANNEAUX) {
        v["stats"]["cold"] = aveu;
    }
    let PanneauCompile { sql, provenance, .. } = pc;
    match provenance {
        Provenance::RouteePreagrege(approx, cap, note) => {
            // MESURE DU PLAFOND sur le pool de LECTURE, avec son AVEU par défaut (`sans_base`) : un
            // appelant ne peut pas DÉCLARER une troncature sans l'avoir chiffrée.
            //
            // LA PRISE DU POOL EST CONDITIONNÉE PAR `plafonne()`, ET C'EST UNE CORRECTION DE COÛT MESURÉE.
            // La SEULE route atteignable depuis un panneau est la ROUTE A, qui pose `Cap::Aucun`
            // (`rollup_route.rs` ; A-multi et B déclinent sur les `unproven()` que la porte de compilation
            // passe). Or `Cap::Aucun` sort de `mesurer` SANS requête — et `sans_base()` rend pour lui
            // EXACTEMENT la même valeur (`Etat::Aucun` des deux côtés, `topn_cap.rs`). La prise
            // inconditionnelle payait donc un cycle prise/rendu du pool (cap GLOBAL de
            // `READ_POOL_CAP` connexions idle, un manque ré-ouvrant une connexion SQLCipher complète :
            // dérivation de clé + trois installations d'UDF + authorizer) pour une comparaison de
            // variante. Une réponse de panneau ROUTÉE en prenait TROIS au lieu de DEUX.
            let mesure = if cap.plafonne() { read_with(db_path, cap.sans_base(), |c| cap.mesurer(c)) } else { cap.sans_base() };
            apply_rollup_stats(&mut v, &Some((approx, mesure, note)));
        }
        Provenance::CompilateurBrut => apply_rollup_stats(&mut v, &None),
        Provenance::Opaque => {
            // AUCUN `served_from`, AUCUN `approx`, AUCUN `truncated` : on ne publie pas un aveu
            // d'exactitude sur une provenance qu'on n'a pas dérivée.
            v["stats"]["provenance_non_derivee"] = json!(true);
            if sql_nomme(&sql, TABLE_DIM_ROLLUP) {
                v["stats"]["rollup_note"] = json!(NOTE_PLAFOND_TOPN_OPAQUE);
            }
        }
    }
    poser_coverage(&mut v, couverture);
    Ok(v)
}

// =====================================================================================================
// 5. `panel_cache` — LA TABLE EST POSSÉDÉE ICI, ET C'EST CE QUI DONNE SON MOTIF À LA GARDE DE BUILD
// =====================================================================================================

/// Vide TOUT le cache rendu. Constante plutôt que fonction pour les sites qui tiennent un `MigTx` et
/// non un `&Connection` : c'est la porte qui garde le nom de table dans un seul fichier sans imposer
/// une signature au moteur de migration.
pub(crate) const SQL_VIDE_TOUT_LE_CACHE: &str = "DELETE FROM panel_cache";
/// Invalide le cache d'UN panneau (`?1` = panel_id).
pub(crate) const SQL_INVALIDE_UN_PANNEAU: &str = "DELETE FROM panel_cache WHERE panel_id=?1";
const SQL_INVALIDE_UNE_BIBLIOTHEQUE: &str =
    "DELETE FROM panel_cache WHERE panel_id IN (SELECT id FROM panel WHERE library_panel_id=?1)";
const SQL_ECRIRE: &str =
    "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,?4,?5)";
const SQL_EVICTION: &str = "DELETE FROM panel_cache WHERE panel_id=?1 AND range_key NOT IN \
                            (SELECT range_key FROM panel_cache WHERE panel_id=?1 ORDER BY computed_at DESC LIMIT ?2)";
const SQL_LIRE: &str = "SELECT payload, computed_at FROM panel_cache WHERE panel_id=?1 AND range_key=?2 AND query_fp=?3";

/// Écrit un payload de panneau sans rien rendre : forme des TÉMOINS seuls, qui posent leurs fixtures. Les trois sites de
/// production (rafraîchissement à la demande, chemin live, pré-chauffage) lisent `cache_ecrire_dit` et disent son refus.
#[cfg(test)]
pub(crate) fn cache_ecrire(conn: &Connection, id: i64, range_key: &str, q_fp: &str, now_s: i64, payload: &str) {
    let _ = cache_ecrire_dit(conn, id, range_key, q_fp, now_s, payload);
}

/// `P10.32-o` — l'écriture d'une ligne de cache, qui DIT si la ligne a été écrite (cause du moteur sinon), puis l'éviction
/// des plages les plus vieilles (cap anti-explosion). Chaque issue de l'écriture est NOTÉE pour cette base, ce panneau,
/// cette plage et cette empreinte (`ECRITURES_DE_CACHE_REFUSEES`) : un refus y reste jusqu'à l'écriture suivante qui
/// réussit, et `serve_swr` le lit (`ecriture_de_cache_refusee`) au lieu de servir une chauffe qui ne finira pas.
/// L'ÉVICTION REFUSÉE N'EST PAS RENDUE, ET C'EST DÉLIBÉRÉ : la ligne est écrite (ou son refus est rendu), seul le plafond
/// de plages de ce panneau n'est pas tenu à cet instant ; l'éviction est rejouée, entière (`NOT IN` des plus récentes), à
/// chaque écriture suivante de ce panneau. Rien de ce qui est servi n'en devient faux.
pub(crate) fn cache_ecrire_dit(conn: &Connection, id: i64, range_key: &str, q_fp: &str, now_s: i64, payload: &str) -> Result<(), String> {
    cache_ecrire_et_noter(conn, id, range_key, q_fp, now_s, payload, RefusDEcritureDeCache { refusee_a: now_s, echec_du_calcul: None })
}

/// `P10.32-o` (vague BH, correction) — L'ÉCRITURE QUI PORTE L'ÉCHEC D'UN CALCUL : le corps d'échec, ou la charge
/// précédente à laquelle l'aveu de l'échec est joint. `calcule_a` est le `computed_at` écrit (l'âge de la charge
/// précédente, qui ne rajeunit pas ; l'instant de la tentative pour un corps d'échec) ; `tente_a` est l'instant de la
/// tentative, et c'est LUI qui est noté si l'écriture est refusée, avec `echec_servi` (la phrase servie de la classe,
/// jamais le texte du moteur). Avant, le refus était noté à `calcule_a` : un refus déjà plus vieux que la durée du cache,
/// donc un calcul réarmé à chaque interrogation, et une charge servie qui annonçait « le résultat du dernier calcul »
/// d'un calcul en échec.
pub(crate) fn cache_ecrire_l_echec_dit(
    conn: &Connection, id: i64, range_key: &str, q_fp: &str, calcule_a: i64, tente_a: i64, payload: &str, echec_servi: &str,
) -> Result<(), String> {
    let refus = RefusDEcritureDeCache { refusee_a: tente_a, echec_du_calcul: Some(echec_servi.to_string()) };
    cache_ecrire_et_noter(conn, id, range_key, q_fp, calcule_a, payload, refus)
}

/// Écrit la ligne (`computed_at` = `calcule_a`), note son issue (`refus` si elle est refusée), puis évince.
fn cache_ecrire_et_noter(
    conn: &Connection, id: i64, range_key: &str, q_fp: &str, calcule_a: i64, payload: &str, refus: RefusDEcritureDeCache,
) -> Result<(), String> {
    let ecrit = conn.execute(SQL_ECRIRE, params![id, range_key, q_fp, calcule_a, payload]).map(|_| ()).map_err(|e| e.to_string());
    noter_l_issue_de_l_ecriture(conn, id, range_key, q_fp, if ecrit.is_ok() { Ok(()) } else { Err(refus) });
    let _ = conn.execute(SQL_EVICTION, params![id, CACHE_MAX_RANGES_PER_PANEL]);
    ecrit
}

/// `P10.32-o` (vague BH) — un refus d'écriture noté : son instant (celui de la tentative refusée) et ce que l'écriture
/// refusée portait. `echec_du_calcul` : `None` -> le RÉSULTAT d'un calcul réussi ; `Some(phrase servie)` -> l'ÉCHEC d'un
/// calcul (corps d'échec, ou aveu joint à la charge précédente). `serve_swr` dit l'un ou l'autre, jamais l'un pour l'autre.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RefusDEcritureDeCache {
    pub(crate) refusee_a: i64,
    pub(crate) echec_du_calcul: Option<String>,
}

/// La clé d'une écriture de cache notée : (base de la connexion telle que SQLite la nomme, panneau, plage, empreinte).
/// La base est dans la clé : en mode 1, deux tenants ont chacun leur panneau `#1`, et un refus noté sur l'une ne dit rien
/// de l'autre.
pub(crate) type CleDEcritureDeCache = (String, i64, String, String);

/// `P10.32-o` (vague BH) — LES ÉCRITURES DE CACHE REFUSÉES PAR LA BASE (disque plein, base en lecture seule), depuis le
/// démarrage : clé -> dernier refus noté ([`RefusDEcritureDeCache`] : l'instant de la tentative refusée ET ce que
/// l'écriture refusée portait, résultat d'un calcul réussi ou phrase servie de l'échec d'un calcul). Avant, `cache_ecrire`
/// jetait le refus : un panneau jamais mis en cache servait `warming` / `mesure_en_cours` à chaque interrogation et
/// réarmait un calcul qui réussissait, sans fin et sans un mot. État de PROCESSUS, jamais persisté (la base refuse
/// justement d'écrire), borné par [`BORNE_DES_ECRITURES_DE_CACHE_REFUSEES`]. Les entrées d'une base sont effacées à la
/// destruction de son tenant ([`oublier_les_registres_d_une_base_detruite`], appelée par `tenants::tenant_destroy`) : un
/// tenant recréé au même chemin n'hérite d'aucun refus.
static ECRITURES_DE_CACHE_REFUSEES: std::sync::OnceLock<parking_lot::Mutex<HashMap<CleDEcritureDeCache, RefusDEcritureDeCache>>> =
    std::sync::OnceLock::new();

/// Au-delà, le refus noté le plus ANCIEN est retiré avant d'en noter un neuf : un lecteur qui demande des plages
/// toujours neuves pendant que la base refuse d'écrire ne fait pas enfler la mémoire. Le panneau dont le refus est
/// retiré redevient une absence (`warming` puis un nouveau calcul), comme avant ce registre.
pub(crate) const BORNE_DES_ECRITURES_DE_CACHE_REFUSEES: usize = 4096;

/// Note l'issue d'une écriture : un refus est retenu (`Err` : son instant et ce qu'il portait), un succès efface le refus
/// retenu.
fn noter_l_issue_de_l_ecriture(conn: &Connection, id: i64, range_key: &str, q_fp: &str, issue: Result<(), RefusDEcritureDeCache>) {
    let cle = (conn.path().unwrap_or("").to_string(), id, range_key.to_string(), q_fp.to_string());
    let mut registre = ECRITURES_DE_CACHE_REFUSEES.get_or_init(Default::default).lock();
    match issue {
        Ok(()) => {
            registre.remove(&cle);
        }
        Err(refus) => retenir_un_refus_d_ecriture(&mut registre, cle, refus),
    }
}

/// Retient un refus sous la borne : une clé déjà connue est mise à jour sans rien retirer ; une clé neuve, registre plein,
/// retire d'abord le refus le plus ancien (`refusee_a` le plus petit). Le type du registre est celui de la production :
/// les témoins de la borne la jouent sur des `RefusDEcritureDeCache` (avant, une forme générique éprouvée sur des `i64`
/// laissait le classement de la production sans témoin).
pub(crate) fn retenir_un_refus_d_ecriture(
    registre: &mut HashMap<CleDEcritureDeCache, RefusDEcritureDeCache>, cle: CleDEcritureDeCache, refus: RefusDEcritureDeCache,
) {
    if !registre.contains_key(&cle) && registre.len() >= BORNE_DES_ECRITURES_DE_CACHE_REFUSEES {
        let plus_ancien = registre.iter().min_by_key(|(_, r)| r.refusee_a).map(|(c, _)| c.clone());
        registre.retain(|c, _| Some(c) != plus_ancien.as_ref());
    }
    registre.insert(cle, refus);
}

/// `P10.32-o` (vague BK) — LES LIGNES `[panel]` QU'UN PANNEAU DANS UN ÉTAT DURABLE ÉCRIRAIT À CHAQUE INTERROGATION SONT
/// BORNÉES : au plus une par panneau, par NATURE de ligne ([`NatureDeLigneDite`]) et par durée du cache du panneau (clé :
/// base de la connexion telle que SQLite la nomme, panneau, nature). La vague BK a borné la charge périmée d'un panneau qui
/// ne compile plus ; les autres natures suivent la même borne, dans ce MÊME registre, sous une clé distincte : une ligne
/// d'une nature n'en tait jamais une d'une autre nature. Valeur : l'instant de la dernière ligne ÉCRITE (une ligne tue ne
/// le repousse pas, sinon un panneau interrogé plus souvent que sa durée du cache ne serait plus jamais dit). État de
/// PROCESSUS, borné par [`BORNE_DES_PEREMPTIONS_NON_COMPILABLES_DITES`], effacé pour une base à la destruction de son
/// tenant. Le corps servi ne dépend jamais de ce registre : il ne décide que du journal.
static PEREMPTIONS_NON_COMPILABLES_DITES: std::sync::OnceLock<parking_lot::Mutex<HashMap<CleDeLigneDiteParNature, i64>>> =
    std::sync::OnceLock::new();

/// La clé d'une ligne dite, sans sa nature : (base de la connexion telle que SQLite la nomme, panneau). Deux tenants ont
/// chacun leur `#1`.
pub(crate) type CleDeLigneDite = (String, i64);

/// La clé du registre de production : la clé d'une ligne dite ET sa nature.
pub(crate) type CleDeLigneDiteParNature = (CleDeLigneDite, NatureDeLigneDite);

/// `P10.32-o` — LA NATURE D'UNE LIGNE `[panel]` BORNÉE, un bras par ligne de `serve_swr` ou de `panel_data` qu'un état
/// durable du panneau (il ne compile plus) ou de la base (elle refuse d'écrire le cache) écrirait à chaque interrogation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum NatureDeLigneDite {
    /// Charge utile périmée servie, le panneau ne compile plus (vague BK).
    ChargePerimeeNonCompilable,
    /// Corps d'échec périmé en cache, le panneau ne compile plus : le refus du compilateur est servi (400).
    CorpsDEchecPerimeNonCompilable,
    /// Ligne de cache illisible, le panneau ne compile pas : le refus du compilateur est servi (400).
    LigneIllisibleNonCompilable,
    /// Ligne de cache illisible sous une écriture refusée notée : le refus nommé de l'écriture est servi (503).
    LigneIllisibleSousEcritureRefusee,
    /// Résultat servi en direct, son écriture au cache refusée.
    ResultatDirectNonEcrit,
}

/// Au-delà, l'entrée la plus ANCIENNE (instant le plus petit) est retirée avant d'en noter une neuve : la mémoire ne
/// suit pas le nombre de panneaux interrogés. Un panneau dont l'entrée est retirée sera dit une fois de plus.
pub(crate) const BORNE_DES_PEREMPTIONS_NON_COMPILABLES_DITES: usize = 4096;

/// La ligne de la charge périmée d'un panneau qui ne compile plus (vague BK) : [`dire_une_ligne_de_panneau`] sous la
/// nature [`NatureDeLigneDite::ChargePerimeeNonCompilable`].
pub(crate) fn dire_la_peremption_non_compilable(conn: &Connection, id: i64, now_s: i64, ttl: i64) -> bool {
    dire_une_ligne_de_panneau(conn, id, NatureDeLigneDite::ChargePerimeeNonCompilable, now_s, ttl)
}

/// Rend `true` si la ligne de cette nature doit être écrite maintenant pour ce panneau (aucune ligne de cette nature
/// dite, ou la dernière dite il y a PLUS d'une durée du cache), et note alors `now_s`. `false` : la ligne est tue,
/// l'instant noté ne bouge pas.
pub(crate) fn dire_une_ligne_de_panneau(conn: &Connection, id: i64, nature: NatureDeLigneDite, now_s: i64, ttl: i64) -> bool {
    let cle = ((conn.path().unwrap_or("").to_string(), id), nature);
    let mut registre = PEREMPTIONS_NON_COMPILABLES_DITES.get_or_init(Default::default).lock();
    noter_une_ligne_dite(&mut registre, cle, now_s, ttl)
}

/// La décision et la borne de [`dire_une_ligne_de_panneau`] (les témoins la jouent sur un registre local, du type de
/// production ou de la clé sans nature). Clé connue : écrite seulement si `now_s - dite_a > ttl`, mise à jour sans rien
/// retirer. Clé neuve, registre plein : l'entrée la plus ancienne est retirée d'abord.
pub(crate) fn noter_une_ligne_dite<K: Clone + Eq + std::hash::Hash>(registre: &mut HashMap<K, i64>, cle: K, now_s: i64, ttl: i64) -> bool {
    match registre.get(&cle) {
        Some(&dite_a) if now_s - dite_a <= ttl => false,
        Some(_) => {
            registre.insert(cle, now_s);
            true
        }
        None => {
            if registre.len() >= BORNE_DES_PEREMPTIONS_NON_COMPILABLES_DITES {
                let plus_ancienne = registre.iter().min_by_key(|(_, &a)| a).map(|(c, _)| c.clone());
                registre.retain(|c, _| Some(c) != plus_ancienne.as_ref());
            }
            registre.insert(cle, now_s);
            true
        }
    }
}

/// Antidate la dernière ligne dite d'un panneau (témoins seuls : la durée du cache ne s'attend pas, elle se simule).
#[cfg(test)]
pub(crate) fn antidater_la_peremption_dite(conn: &Connection, id: i64, dite_a: i64) {
    antidater_la_ligne_dite(conn, id, NatureDeLigneDite::ChargePerimeeNonCompilable, dite_a);
}

/// Antidate la dernière ligne dite d'une nature pour un panneau (témoins seuls).
#[cfg(test)]
pub(crate) fn antidater_la_ligne_dite(conn: &Connection, id: i64, nature: NatureDeLigneDite, dite_a: i64) {
    let cle = ((conn.path().unwrap_or("").to_string(), id), nature);
    PEREMPTIONS_NON_COMPILABLES_DITES.get_or_init(Default::default).lock().insert(cle, dite_a);
}

/// L'instant de la dernière ligne dite d'un panneau, `None` si aucune (témoins seuls).
#[cfg(test)]
pub(crate) fn peremption_dite_a(conn: &Connection, id: i64) -> Option<i64> {
    let cle = ((conn.path().unwrap_or("").to_string(), id), NatureDeLigneDite::ChargePerimeeNonCompilable);
    PEREMPTIONS_NON_COMPILABLES_DITES.get_or_init(Default::default).lock().get(&cle).copied()
}

/// `P10.32-o` (vague BK) — À LA DESTRUCTION D'UN TENANT, les entrées de sa base sont effacées des deux registres de
/// processus indexés par le chemin de la base (refus d'écriture du cache, lignes `[panel]` dites, toutes natures) : un tenant DÉTRUIT
/// puis recréé au même chemin n'hérite ni d'un refus (503 `cache_non_ecrit` sans calcul armé jusqu'à une durée du cache)
/// ni d'une ligne tue. La clé est le chemin tel que SQLite le nomme (`conn.path()`, absolu, liens résolus selon la version)
/// alors que `tenant_destroy` lit le chemin écrit dans le plan de contrôle : les formes comparées sont ce chemin tel quel
/// et sa forme résolue (`canonicalize` : `..` et liens résolus, un appel `realpath` sans descripteur ouvert sur la base),
/// d'où l'appel AVANT la suppression du fichier (un fichier absent n'a plus de forme résolue, seul le chemin tel quel
/// reste comparé). Les entrées des autres bases restent.
pub(crate) fn oublier_les_registres_d_une_base_detruite(db_path: &str) {
    let mut formes: Vec<String> = vec![db_path.to_string()];
    formes.extend(std::fs::canonicalize(db_path).ok().map(|c| c.to_string_lossy().into_owned()));
    ECRITURES_DE_CACHE_REFUSEES.get_or_init(Default::default).lock().retain(|(base, ..), _| !formes.contains(base));
    PEREMPTIONS_NON_COMPILABLES_DITES.get_or_init(Default::default).lock().retain(|((base, _), _), _| !formes.contains(base));
}

/// `P10.32-o` (vague BH) — l'instant du dernier refus d'écriture de cette ligne de cache, si la dernière écriture tentée a
/// été refusée (`None` : aucune tentative refusée depuis la dernière écriture réussie, ou depuis le démarrage).
/// Lue par les témoins (l'instant seul) ; `serve_swr` lit [`refus_d_ecriture_de_cache`].
#[cfg(test)]
pub(crate) fn ecriture_de_cache_refusee(conn: &Connection, id: i64, range_key: &str, q_fp: &str) -> Option<i64> {
    refus_d_ecriture_de_cache(conn, id, range_key, q_fp).map(|r| r.refusee_a)
}

/// `P10.32-o` (vague BH, correction) — le dernier refus d'écriture de cette ligne de cache, entier (instant et ce que
/// l'écriture refusée portait), `None` comme [`ecriture_de_cache_refusee`].
pub(crate) fn refus_d_ecriture_de_cache(conn: &Connection, id: i64, range_key: &str, q_fp: &str) -> Option<RefusDEcritureDeCache> {
    let cle = (conn.path().unwrap_or("").to_string(), id, range_key.to_string(), q_fp.to_string());
    ECRITURES_DE_CACHE_REFUSEES.get_or_init(Default::default).lock().get(&cle).cloned()
}

/// `P10.32-o` — LES LECTURES DE LIGNE DE CACHE REFUSÉES OU ILLISIBLES, depuis le démarrage (compte de processus, jamais
/// persisté). Le rang courant est porté par la cause de `cache_lire_dit`, que chaque appelant écrit à sa ligne de
/// journal ; il n'est pas servi sous `/api/system/metrics`.
static LECTURES_DE_CACHE_REFUSEES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Valeur courante de `LECTURES_DE_CACHE_REFUSEES` (lue par les témoins seuls : c'est le compte de production, non servi).
#[cfg(test)]
pub(crate) fn lectures_de_cache_refusees() -> u64 {
    LECTURES_DE_CACHE_REFUSEES.load(std::sync::atomic::Ordering::Relaxed)
}

/// `P10.32-o` — CE QUE LA LECTURE D'UNE LIGNE DE CACHE A RENDU. Une lecture refusée n'est pas une absence : un appelant qui
/// écrit sur une absence (le corps d'échec de `dashboards::memoriser_l_echec_du_rafraichissement`) écraserait une charge
/// utile VALIDE qu'il n'a simplement pas pu lire.
#[derive(Debug, PartialEq)]
pub(crate) enum LectureDeCache {
    /// Ligne lue : (payload, computed_at).
    Lue(String, i64),
    /// Aucune ligne (`.optional()` : `Ok(None)`).
    Absente,
    /// Une ligne EXISTE, la lecture a été faite, mais sa valeur ne se décode pas (type inattendu, conversion impossible,
    /// valeur hors plage : les formes de `bilan_de_tick::cause_sql`). Elle ne porte aucune charge utile valide : un corps
    /// d'échec peut la remplacer, comme une charge qui n'est pas du JSON. La cause porte le rang du compte.
    Illisible(String),
    /// Lecture REFUSÉE par le moteur (autorisateur, verrou, I/O…) : on ne sait pas ce que la ligne porte. Rien ne doit
    /// être écrit sur la foi de cette lecture. La cause porte le rang du compte.
    NonLue(String),
}

/// Lit un payload SANS prédicat de fraîcheur, en QUATRE issues (`LectureDeCache`). Les deux issues ratées sont comptées
/// (`LECTURES_DE_CACHE_REFUSEES`) ; la cause rendue nomme l'erreur (texte et code étendu du moteur : l'énoncé lu est la
/// constante `SQL_LIRE`, jamais la requête du panneau) et le rang du compte. Aucune ligne de journal ICI : chaque
/// appelant dit, à SA ligne, ce qu'il fait réellement de l'issue (servir comme un MISS, ne rien écrire, remplacer).
pub(crate) fn cache_lire_dit(conn: &Connection, id: i64, range_key: &str, q_fp: &str) -> LectureDeCache {
    use rusqlite::OptionalExtension;
    match conn.query_row(SQL_LIRE, params![id, range_key, q_fp], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).optional() {
        Ok(Some((payload, calcule_a))) => LectureDeCache::Lue(payload, calcule_a),
        Ok(None) => LectureDeCache::Absente,
        Err(e) => {
            let rang = LECTURES_DE_CACHE_REFUSEES.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            let cause = format!(
                "{} (lecture de cache ratée n° {rang} depuis le démarrage)",
                crate::sqlite_plafond::decrire_l_erreur(&e)
            );
            match e {
                rusqlite::Error::InvalidColumnType(..)
                | rusqlite::Error::FromSqlConversionFailure(..)
                | rusqlite::Error::IntegralValueOutOfRange(..) => LectureDeCache::Illisible(cause),
                _ => LectureDeCache::NonLue(cause),
            }
        }
    }
}

/// Forme `Option` de `cache_lire_dit`, pour les témoins seuls (les sites de production lisent les quatre issues).
#[cfg(test)]
pub(crate) fn cache_lire(conn: &Connection, id: i64, range_key: &str, q_fp: &str) -> Option<(String, i64)> {
    match cache_lire_dit(conn, id, range_key, q_fp) {
        LectureDeCache::Lue(payload, calcule_a) => Some((payload, calcule_a)),
        LectureDeCache::Absente | LectureDeCache::Illisible(_) | LectureDeCache::NonLue(_) => None,
    }
}

/// `P10.29-l` — Vide tout le cache rendu et DIT si l'ordre a été pris : nombre de lignes supprimées, ou l'erreur du
/// moteur. La purge (`purge::purge_delete_rows`) refuse sur l'erreur : les charges utiles portent le contenu purgé.
pub(crate) fn cache_vider_dit(conn: &Connection) -> rusqlite::Result<usize> {
    conn.execute(SQL_VIDE_TOUT_LE_CACHE, [])
}

/// Invalide le cache d'un panneau (édition / suppression).
pub(crate) fn cache_invalider_panneau(conn: &Connection, id: i64) {
    let _ = conn.execute(SQL_INVALIDE_UN_PANNEAU, params![id]);
}

/// Invalide le cache de tous les panneaux qui référencent une définition de bibliothèque.
pub(crate) fn cache_invalider_bibliotheque(conn: &Connection, id: i64) {
    let _ = conn.execute(SQL_INVALIDE_UNE_BIBLIOTHEQUE, params![id]);
}

/// RE-ESTAMPE UN PAYLOAD SERVI DEPUIS LE CACHE (SWR).
///
/// IL NE RECALCULE PAS `searched_from`, ET C'EST LA PROPRIÉTÉ. `cache_range_key` clé sur la DURÉE
/// quantifiée : un payload calculé à T0 sur [T0−24 h, T0] est LÉGITIMEMENT servi à T0+n. Recalculer
/// `searched_from` sur le `from` COURANT ferait de `coverage` le seul champ frais d'une réponse
/// périmée — et il se lit comme un certificat. On compare donc l'horizon STOCKÉ à l'horizon COURANT et,
/// s'il a bougé, on remplace la raison par `horizon_perime` et on recalcule `older_outside_window`
/// AVEC LE `searched_from` STOCKÉ.
///
/// `pc` sert UNIQUEMENT à dériver la famille de tables (le SQL est le seul endroit où elle est écrite).
/// La compilation est PURE : aucune lecture disque n'est ajoutée par ce paramètre.
pub(crate) fn cache_reestamper(
    v: &mut Value, db_path: &str, conf: &HashMap<String, String>, pc: Option<&PanneauCompile>, computed_at: i64, now_s: i64,
) {
    // UNE CHARGE UTILE QUI N'EST PAS UN OBJET N'EST PAS UNE RÉPONSE : `poser_coverage` la laisse
    // intacte au lieu de paniquer (une ligne de cache est un TEXTE que rien ne contraint).
    let stocke = v.get("stats").and_then(|s| s.get("coverage")).cloned().filter(|c| c.is_object());
    let Some(mut cov) = stocke else {
        // BINAIRE ANTÉRIEUR : la ligne ne porte aucun aveu. « Non dit », jamais « brut / exact ».
        poser_coverage(v, json!({
            "reason": RAISON_PAYE_UTILE_ANTERIEURE,
            "calcule_a": computed_at,
            "notice": "cette réponse vient d'une ligne de cache écrite AVANT que les panneaux disent leur \
                       horizon : elle ne dit rien de ce qu'elle a pu voir. L'aveu reviendra au prochain \
                       rafraîchissement.",
        }));
        return;
    };
    let Some(pc) = pc else { return }; // la portée n'est pas dérivable ici : on ne touche pas à ce qui a été mesuré
    let (courant, _) =
        horizon_et_frontiere_selon_l_index(db_path, conf, &pc.sql, pc.env_lu.as_deref(), cov["searched_from"].as_i64().unwrap_or(0), now_s);
    // `P10.5-p` — UNE POLITIQUE PAR INDEX REND DÉSORMAIS L'HORIZON NON DÉRIVABLE : l'horizon stocké (écrit sous la seule
    // rétention globale) n'est plus re-servi ; la couverture servie est celle d'un horizon non mesuré, sur la fenêtre et
    // l'instant de calcul STOCKÉS. Un corps stocké SANS horizon (échec `calcul_echoue`, …) n'a rien à retirer : il
    // garde sa raison, comme avant.
    let notice_courante = courant["notice"].as_str().unwrap_or_default();
    // Politiques NON LUES au re-service : l'horizon stocké n'est pas re-servi non plus (rien ne dit que la politique qui
    // l'a laissé tel est encore celle de la base).
    let politique_muette = notice_courante == NOTICE_POLITIQUE_PAR_INDEX_ENVIRONNEMENT_NON_DETERMINE
        || notice_courante == NOTICE_POLITIQUE_PAR_INDEX_PLAFONNEE
        || notice_courante == NOTICE_POLITIQUE_PAR_INDEX_NON_LUE;
    if politique_muette && cov.get("horizon_ts").is_some() {
        let non_mesure = json!({
            "searched_from": cov["searched_from"].clone(),
            "calcule_a": cov["calcule_a"].clone(),
            "reason": RAISON_HORIZON_NON_MESURE,
            "notice": notice_courante,
        });
        poser_coverage(v, non_mesure);
        return;
    }
    let (Some(stocke_ts), Some(courant_ts)) = (cov["horizon_ts"].as_i64(), courant["horizon_ts"].as_i64()) else {
        return;
    };
    // CE QU'ON COMPARE EST LA DURÉE DE CONSERVATION, PAS L'INSTANT DE L'HORIZON — ET C'EST LA CORRECTION
    // QUI REND CE SIGNAL LISIBLE. `horizon_ts` vaut `instant_du_calcul − rétention` : il AVANCE avec
    // l'horloge, seconde par seconde. Comparer les deux instants faisait donc basculer en
    // `horizon_perime` TOUT HIT servi ne serait-ce qu'une seconde après l'écriture — c'est-à-dire la
    // quasi-totalité d'entre eux : la raison ne distinguait plus jamais `retention_floor` de
    // `cold_boundary`, et la phrase « l'horizon a BOUGÉ depuis » était allumée en permanence, donc
    // n'informait de rien. Le témoin inverse écrit pour l'interdire ne mordait pas : il réinjectait le
    // MÊME `now_s` à l'écriture et à la lecture, un état que la production n'atteint jamais.
    // La DURÉE, elle, ne bouge QUE si la politique a changé — ce que ce signal prétend annoncer. Elle est
    // dérivée sans ajouter un mot de vocabulaire : l'instant du calcul est déjà publié (`calcule_a`).
    let calcule_a = cov["calcule_a"].as_i64().unwrap_or(computed_at);
    if courant_ts - stocke_ts == now_s - calcule_a {
        return;
    }
    cov["horizon_ts"] = json!(courant_ts);
    let from = cov["searched_from"].as_i64().unwrap_or(0);
    cov["older_outside_window"] = json!(from > 0 && from + CACHE_BUCKET_S < courant_ts);
    cov["reason"] = json!(RAISON_HORIZON_PERIME);
    cov["notice"] = json!(format!(
        "réponse servie depuis le cache : elle a été CALCULÉE sur la fenêtre indiquée, et l'horizon de \
         conservation a BOUGÉ depuis. {}",
        courant["notice"].as_str().unwrap_or("")
    ));
    poser_coverage(v, cov);
}

/// L'AVEU D'UN CORPS SYNTHÉTIQUE — un corps que le démon fabrique sans exécuter la requête (repli de
/// parsing, `warming`, calcul en échec, ligne de cache non lue servie en 503, écriture du cache refusée servie en 503). Il
/// n'a AUCUNE ligne : sans cet objet, la
/// console le lirait comme une absence. La notice suit la raison ; toute raison non nommée ci-dessous prend celle de la
/// charge utile illisible.
///
/// `horizon_mesure` = l'horizon COURANT quand il a pu être dérivé (la portée se lit dans le SQL, que
/// l'appelant a compilé de toute façon). L'horizon est une propriété de la REQUÊTE, pas des lignes : le
/// publier ici est vrai même sans lignes, et c'est ce qui permet à la console de dire, sur un corps
/// « chargement en cours », jusqu'où ce panneau pourra voir. La RAISON reste celle du corps synthétique
/// — on ne prétend pas avoir servi une réponse.
pub(crate) fn coverage_synthetique(raison: &str, from: i64, now_s: i64, horizon_mesure: Option<Value>) -> Value {
    let notice = if raison == RAISON_MESURE_EN_COURS {
        "aucune ligne n'a encore été calculée pour cette fenêtre : la mesure est en cours. Ce corps vide \
         n'établit donc PAS une absence."
    } else if raison == RAISON_CALCUL_ECHOUE {
        "le calcul de ce panneau a échoué (cause dans `error`) : aucune ligne n'a été calculée. Ce corps \
         vide n'établit PAS une absence ; une nouvelle tentative suit l'expiration du cache."
    } else if raison == RAISON_LIGNE_DE_CACHE_NON_LUE {
        NOTICE_LIGNE_DE_CACHE_NON_LUE
    } else if raison == RAISON_CACHE_NON_ECRIT {
        NOTICE_CACHE_NON_ECRIT
    } else {
        "la charge utile mise en cache n'a pas pu être relue : le corps servi est synthétique. Ce corps \
         vide n'établit PAS une absence."
    };
    let mut cov = json!({ "searched_from": from, "calcule_a": now_s });
    if let Some(h) = horizon_mesure {
        for champ in ["horizon_ts", "older_outside_window"] {
            if let Some(v) = h.get(champ) {
                cov[champ] = v.clone();
            }
        }
    }
    cov["reason"] = json!(raison);
    cov["notice"] = json!(notice);
    cov
}

/// `P10.32-o` — LE CORPS D'UN RAFRAÎCHISSEMENT EN ÉCHEC : la cause du moteur dans `error` (la console
/// le lit déjà comme un refus nommé), aucun `warming`, un aveu `calcul_echoue`. L'horizon n'est pas
/// publié : le panneau compilé a été consommé par l'exécution qui a échoué, et un champ absent est un
/// champ non mesuré.
pub(crate) fn corps_d_echec(cause: &str, from: i64, now_s: i64) -> Value {
    let mut v = json!({ "columns": [], "rows": [], "error": cause });
    v["stats"]["coverage"] = coverage_synthetique(RAISON_CALCUL_ECHOUE, from, now_s, None);
    v
}

/// Vide tout le cache rendu ; rend le nombre de lignes supprimées (0 si l'ordre échoue). Plus appelée en production
/// depuis `P10.29-l` (la purge lit `cache_vider_dit`) : gardée pour le témoin du plancher de `tests/panneau_avoue.rs`.
#[cfg(test)]
pub(crate) fn cache_vider(conn: &Connection) -> usize {
    cache_vider_dit(conn).unwrap_or(0)
}

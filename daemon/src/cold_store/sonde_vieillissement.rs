//! cold_store::sonde_vieillissement — L'INSTRUMENT QUI MANQUAIT : le PLAN et le CHRONOMÈTRE des énoncés
//! du vieillissement, sur la base VIVANTE, en LECTURE SEULE.
//!
//! CE QU'ON SAIT, ET CE QU'ON NE SAIT PAS (`P10.13-a`, relevé en production les 2026-08-10/11). La passe
//! horaire lit **968,1 Mio** et tient `db.lock()` **17–22 s** pour découvrir **≤ 478 lignes** de travail —
//! soit ~23 Gio de lectures et **7–9 min de base gelée par jour**, pour zéro ligne columnarisée. LA CAUSE
//! N'EST PAS ÉTABLIE. Une réplique locale fidèle (1 775 400 lignes, mêmes 7 index, même distribution,
//! 62 seals) planifie `SEARCH event USING INDEX idx_event_ts` et rend en **< 0,6 s, avec ET sans
//! `ANALYZE`** : elle ne reproduit donc PAS le plan de production. « Corriger » un plan qu'on n'a pas lu
//! serait exactement le défaut que cette campagne ferme. Cet outil sert à le LIRE.
//!
//! POURQUOI IL N'ACCEPTE PAS DE SQL. Une sous-commande « donne-moi le plan de CETTE requête » serait une
//! surface d'attaque neuve — et le projet a déjà une clé sur ce sujet (le SQL brut est gaté admin PLUS un
//! authorizer SQLite qui refuse `user.hash`/`token.token_hash` même à un admin). La sonde ne prend AUCUN
//! SQL : elle rejoue les énoncés de `enonces`, ceux-là mêmes que la passe exécute, avec les bornes que la
//! passe calcule (`Bande`). Un énoncé de lecture ajouté demain dans `aging`/`seal`/`writer` fait ROUGIR le
//! scanner de source tant qu'il n'est pas passé par `enonces` — la sonde SUIT donc par construction, elle
//! ne recopie rien. (Le raisonnement complet est en tête de `enonces`.)
//!
//! LA LECTURE SEULE EST PROUVÉE, PAS PROMISE — quatre épaisseurs, et deux d'entre elles ont leur témoin :
//!   1. **`SQLITE_OPEN_READ_ONLY`** au niveau du descripteur : SQLite refuse toute écriture de la base
//!      principale (`attempt to write a readonly database`). Témoin :
//!      `une_connexion_de_sonde_refuse_d_ecrire`.
//!   2. **UN AUTHORIZER DÉFAUT-DENY** posé sur la connexion : `Read`, `Select` et `Function` sont les
//!      SEULES actions permises ; tout le reste (INSERT/UPDATE/DELETE/CREATE/ALTER/ANALYZE/REINDEX/
//!      PRAGMA/ATTACH/TRANSACTION/…) est refusé DANS LE PRÉPARATEUR, donc avant la moindre exécution. Ce
//!      n'est pas une liste d'interdits, c'est le COMPLÉMENT d'une liste de permis : une action inédite
//!      d'une future version de SQLite tombe du côté refusé sans que personne n'y pense. Témoin, posé sur
//!      une connexion ÉCRIVABLE pour isoler cette garde de la précédente :
//!      `l_authorizer_de_sonde_refuse_tout_ce_qui_n_est_pas_une_lecture`.
//!   3. **AUCUN `EXPLAIN` QUI EXÉCUTE** : `EXPLAIN QUERY PLAN` ne fait que COMPILER (il rend ce que le
//!      préparateur a décidé) ; les seules exécutions sont celles des énoncés, qui sont des `SELECT`.
//!   4. **AUCUN `ANALYZE`, AUCUN `PRAGMA` D'ÉCRITURE, AUCUN `VACUUM`** — et ce n'est pas une intention :
//!      `ANALYZE` écrirait `sqlite_stat1`, donc CHANGERAIT les plans qu'on est venu mesurer. Les seuls
//!      `PRAGMA` émis (clé SQLCipher, budget mémoire) le sont AVANT que l'authorizer ne soit posé, et
//!      aucun d'eux n'écrit dans le fichier.
//!
//! CE QU'ELLE PERTURBE, ET CE QU'ELLE NE PERTURBE PAS. Processus SÉPARÉ, connexion SÉPARÉE ouverte en
//! lecture seule : en WAL un lecteur ne prend PAS le verrou d'écriture et ne bloque pas l'ingest (même
//! posture que `db-stats`, qui tourne déjà en production). Elle ne prend jamais `db.lock()` : ce mutex
//! appartient au PROCESSUS daemon, il n'existe pas ici. EN REVANCHE elle tire par le cache de pages de
//! l'OS tout ce qu'elle lit, et ce n'est pas gratuit sur un budget de 2 Gio : relevé le 2026-08-15 sur la
//! production, `MemAvailable` est passé de **1 195 Mio à 986 Mio** pendant une exécution (–209 Mio), aux
//! dépens de ce que le daemon y avait chaud. Une sonde qui se disait « sans perturbation » se trompait
//! d'axe : elle ne perturbe pas les VERROUS, elle perturbe la MÉMOIRE.
//!
//! `P10.15-a` — POURQUOI CHAQUE ÉNONCÉ EST EXÉCUTÉ **DEUX FOIS** (et pourquoi la version précédente
//! mentait). La connexion de la sonde est neuve : son cache de pages est VIDE, alors que le daemon tourne
//! sur une connexion vieille de plusieurs heures. Le rapport publiait UNE durée, sans dire laquelle des
//! deux situations elle décrivait. Ce n'était pas une nuance : mesuré le 2026-08-15 en production, la
//! sonde attribuait **3 847 ms** à `decouverte_des_jours` là où la passe VIVANTE bouclait — découverte
//! comprise, journal à l'appui — en **12 à 31 ms**. Soit un facteur ≥ 183 sur l'énoncé le plus regardé de
//! la campagne. Le même relevé confirmait l'autre énoncé au contraire : **37 471 ms** pour la sonde contre
//! **38 836 ms** pour la passe, 3,5 % d'écart — parce qu'un balayage de 1,7 M lignes ne tient dans aucun
//! cache. LES DEUX CAS EXISTENT DONC, ET RIEN DANS LA SORTIE NE PERMETTAIT DE LES DISTINGUER.
//!
//! La correction ne devine pas quels énoncés sont sensibles au cache : elle les REJOUE TOUS
//! immédiatement et publie LE COUPLE (froid, chaud). Le second passage n'est pas une redondance, c'est LA
//! mesure — l'écart entre les deux EST la part que le cache absorbe.
//!
//! `P10.15-a` (RÉSIDUEL, mesuré le 2026-08-15 EN VÉRIFIANT CE CORRECTIF) — **« FROID » N'EST PAS UNE
//! BORNE HAUTE, et le dire serait refaire la faute d'un cran plus haut.** La connexion de la sonde est
//! neuve, donc son cache de pages SQLite est vide ; mais le cache de pages de l'OS, lui, est dans un état
//! que la sonde **ne contrôle ni ne mesure**. Preuve par les chiffres, même énoncé (`decouverte_des_jours`)
//! sur la même base : **10,1 ms** le 08-10, **3 847 ms** le 08-15 à 00:20Z, **11,3 ms** le 08-15 à 05:05Z.
//! Un « majorant » qui varie de ×341 d'une exécution à l'autre n'est pas un majorant : c'est un
//! ÉCHANTILLON. Ce qui tient : **CHAUD est un plancher** (tout est en cache, la passe ne peut pas faire
//! mieux) et l'ÉCART entre les deux dit si le cache absorbe. La passe réelle est **au-dessus du chaud** ;
//! au-dessous du froid seulement si l'OS était aussi froid ce jour-là, ce que personne ne sait. Le prix est assumé et dit dans le
//! rapport : la sonde coûte désormais environ le double de ce qu'elle lisait. Un outil qui coûte deux fois
//! est préférable à un outil qui se trompe de deux ordres de grandeur. (La justification écrite ici avant
//! le 2026-08-15 — « les rejouer aurait fait payer DEUX FOIS les 17-22 s » — parlait d'un rejeu qui
//! n'apportait AUCUNE information, celui qui servait à relire un résultat ; elle ne couvrait pas celui-ci.)
//!
//! CE QU'ELLE NE MESURE PAS, ÉCRIT POUR ÊTRE OPPOSABLE :
//!   * elle ne mesure **aucune contention** : la passe réelle tient le verrou writer pendant la
//!     découverte, ce que la sonde ne peut pas imiter sans devenir intrusive ;
//!   * elle n'exécute NI la phase 2 (le `DELETE` chunké) NI l'écriture Parquet — elles ÉCRIVENT ;
//!   * elle mesure le PREMIER candidat retenu, pas les N que la passe traiterait : les énoncés par-jour
//!     se paient une fois PAR JOUR, et le rapport dit combien de jours seraient traités ;
//!   * le passage CHAUD est chaud du cache de LA SONDE, pas de celui du daemon. Il donne la borne BASSE
//!     (« voilà ce que coûte cet énoncé quand ses pages sont là »), le passage froid la borne HAUTE. La
//!     passe réelle est entre les deux, et le rapport dit exactement cela plutôt que de choisir ;
//!   * la RÉCOLTE (candidats, `max_id`) est prise pendant le passage FROID, plafonnée (`RECOLTE_MAX`) :
//!     quand elle est tronquée, le COMPTE reste exact et le rapport le dit.

use super::*;
use std::fmt::Write as _;

// =================================================================================================
// LA CONNEXION — lecture seule par le descripteur ET par l'authorizer
// =================================================================================================

/// POSE L'AUTHORIZER DÉFAUT-DENY. Extraite pour être TESTABLE SUR UNE CONNEXION ÉCRIVABLE : sur une
/// connexion déjà ouverte en `SQLITE_OPEN_READ_ONLY`, un refus ne prouverait pas QUI a refusé — les deux
/// gardes se couvriraient l'une l'autre et aucune mutation ne pourrait les départager.
///
/// ALLOWLIST, PAS DENYLIST. `Read` (une colonne d'une table), `Select` (l'énoncé) et `Function`
/// (`COUNT`, `MAX`, `COALESCE`) suffisent aux énoncés de `enonces` ; tout le reste est refusé. Le
/// complément n'est jamais énuméré.
pub(super) fn brider_en_lecture_seule(conn: &Connection) {
    conn.authorizer(Some(|ctx: rusqlite::hooks::AuthContext<'_>| {
        use rusqlite::hooks::{AuthAction, Authorization};
        match ctx.action {
            AuthAction::Read { .. } | AuthAction::Select | AuthAction::Function { .. } => Authorization::Allow,
            _ => Authorization::Deny,
        }
    }));
}

/// OUVRE la base du tenant en LECTURE SEULE, prête à mesurer. L'ORDRE EST LOAD-BEARING : le descripteur,
/// PUIS la clé SQLCipher et le budget mémoire (des `PRAGMA`, qui n'écrivent pas le fichier), PUIS
/// l'authorizer — l'inverse refuserait les `PRAGMA` d'ouverture et la base resterait illisible.
pub(super) fn ouvrir_en_lecture_seule(db_path: &str) -> Result<Connection, String> {
    let conn = Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("ouverture read-only {db_path} : {e}"))?;
    apply_key(&conn);
    let _ = crate::sqlite_plafond::armer(&conn);
    // FAIL-CLOSED, même leçon que `db-stats` (2026-08-05) : une base illisible (clé absente/incorrecte ->
    // SQLCipher rend « file is not a database » à la PREMIÈRE lecture) rendrait un rapport de plans vides,
    // qui se lit « il n'y a rien à voir » au lieu de « je n'ai rien pu lire ».
    conn.query_row("PRAGMA page_count", [], |r| r.get::<_, i64>(0)).map_err(|e| {
        format!(
            "base ILLISIBLE ({db_path}) : {e}\n  Cause la plus fréquente : PLUME_DB_KEY absente ou \
             incorrecte (base SQLCipher). AUCUN plan n'est publié — un rapport vide se lirait comme une \
             base sans travail."
        )
    })?;
    brider_en_lecture_seule(&conn);
    Ok(conn)
}

// =================================================================================================
// LA MESURE — le plan, la durée, les lignes, et les compteurs que le plan seul ne dit pas
// =================================================================================================

/// CE QU'UN ÉNONCÉ A COÛTÉ. `plan` vient de `EXPLAIN QUERY PLAN` (compilation seule) ; tout le reste vient
/// de l'exécution réelle. Les compteurs `SQLITE_STMTSTATUS_*` sont là parce qu'UN PLAN INDEXÉ QUI MET 17 s
/// DIRAIT AUTRE CHOSE QU'UN BALAYAGE : le texte du plan ne suffit pas à trancher, ces nombres si.
/// `P10.15-a` — LE SECOND PASSAGE, ou la CAUSE NOMMÉE de son absence. Jamais un `Option<f64>` nu : un
/// `None` se lit « zéro » ou « pas important » selon l'humeur du lecteur, une cause se lit.
pub(super) enum Chaud {
    /// L'énoncé a été rejoué et voici sa durée, cache chaud.
    Mesure(f64),
    /// Pas de second passage — et on dit POURQUOI.
    NonMesure(&'static str),
}

/// L'énoncé n'est PAS exécuté par la passe dans cette configuration : on montre son plan, jamais une durée
/// (cf. `plan_seul`). Il n'y a donc pas plus de passage chaud que de passage froid.
pub(super) const CHAUD_JAMAIS_EXECUTE: &str = "énoncé non exécuté par la passe — aucune durée mesurée";

/// Le rejeu a échoué là où le premier passage avait réussi (base fermée sous les pieds, E/S). On refuse de
/// publier le froid tout seul comme s'il était le prix de la passe.
pub(super) const CHAUD_REJEU_EN_ECHEC: &str =
    "rejeu en échec — la durée sur connexion neuve reste SEULE, et rien ne dit ce que le cache en absorbe";

/// AU-DELÀ DE CE FACTEUR entre froid et chaud, la durée à froid ne décrit plus ce que la passe paie : le
/// cache absorbe l'essentiel. En deçà, les deux chiffres sont du même ordre et le froid est utilisable.
///
/// CE SEUIL NE CACHE RIEN — et c'est ce qui le rend peu risqué : les DEUX durées sont imprimées dans tous
/// les cas, il ne choisit que la PHRASE qui les accompagne. Un lecteur en désaccord avec la valeur a les
/// nombres sous les yeux pour trancher lui-même.
pub(super) const FACTEUR_CACHE_DETERMINANT: f64 = 2.0;

/// PLANCHER D'INTERPRÉTATION. Sous cette durée, un rapport froid/chaud n'est que du bruit d'ordonnancement
/// (un énoncé à 0,1 ms peut « doubler » sans que rien de réel ne se soit passé). On ne conclut pas.
pub(super) const PLANCHER_INTERPRETABLE_MS: f64 = 5.0;

pub(super) struct Mesure {
    pub(super) plan: Vec<String>,
    /// Durée de la COMPILATION du plan : un plan coûteux à compiler ne se voit nulle part ailleurs.
    /// NOMMÉ `compilation_ms` ET PAS `prepare_ms` : les noms `prepare_ms`/`exec_ms`/`server_ms`/
    /// `sem_wait_ms`/`db_lock_wait_ms` sont RÉSERVÉS à `query_timing`, qui est le seul auteur du
    /// découpage du temps d'une REQUÊTE SERVIE (garde `only_query_timings_publishes_the_time_split`).
    /// Ce qu'on mesure ici n'est pas une requête servie, et lui emprunter ses noms rendrait les deux
    /// familles de chiffres confondables — exactement le défaut que cette garde a fermé.
    pub(super) compilation_ms: f64,
    /// Durée de l'EXÉCUTION complète (premier `step` -> dernière ligne consommée) sur une connexion dont
    /// le cache de pages SQLite est VIDE. `P10.15-a` résiduel : ce n'est PAS un majorant — le cache de
    /// l'OS, lui, n'est pas remis à zéro et n'est pas mesuré ici (même énoncé : 10,1 / 3 847 / 11,3 ms
    /// selon le jour). C'est un ÉCHANTILLON, dont l'écart au rejeu chaud est ce qui informe.
    pub(super) execution_froid_ms: f64,
    /// `P10.15-a` — LA MÊME EXÉCUTION, REJOUÉE IMMÉDIATEMENT, donc sur un cache chaud : BORNE BASSE. Ce
    /// n'est PAS un champ optionnel de confort. Le type force chaque site de rendu à dire ce qu'il en est,
    /// exactement comme `Crete::NonMesuree` et `Retard::NonMesure` : sans lui, on retombe sur une seule
    /// durée dont le lecteur ne sait pas si elle décrit la passe (mesuré : elle peut la surestimer ×183).
    pub(super) execution_chaud: Chaud,
    pub(super) lignes: i64,
    /// `FULLSCAN_STEP` : pas de balayage complet de table. C'est LE discriminant cherché.
    pub(super) balayage: i64,
    /// `SORT` : tris matérialisés (un `GROUP BY`/`ORDER BY` non couvert par un index en produit).
    pub(super) tris: i64,
    /// `VM_STEP` : opcodes exécutés — la mesure de travail la plus directe, insensible au cache.
    pub(super) pas_de_machine: i64,
    // CE QUI N'EST PAS ICI, ET POURQUOI. `SQLITE_STMTSTATUS_AUTOINDEX` (l'index transitoire que SQLite
    // se construit faute d'index utilisable) aurait sa place dans cette liste — mais le mot est
    // INTERDIT dans le code du daemon par `le_mecanisme_dauto_index_ne_revient_pas` (P6.8-b : le
    // mécanisme d'index adaptatif a été retiré, et la garde refuse la CATÉGORIE, pas une liste de
    // sites). Y faire une exception affaiblirait une garde utile pour un chiffre REDONDANT : le plan
    // rendu ci-dessus porte déjà « USING AUTOMATIC COVERING INDEX » quand le cas se produit. On lit
    // donc le plan, pas le compteur.
}

impl Mesure {
    /// `P10.15-a` — LA PHRASE QUI DÉPARTAGE LES DEUX PASSAGES. PURE (aucune E/S, aucune base) : c'est ce
    /// qui la rend testable sur des couples fabriqués, y compris ceux qu'on ne saurait pas provoquer en
    /// production. Elle ne CHOISIT jamais un chiffre à la place du lecteur — les deux sont imprimés par
    /// `rendre` juste au-dessus ; elle dit seulement lequel décrit la passe.
    pub(super) fn verdict_de_cache(&self) -> String {
        let froid = self.execution_froid_ms;
        let chaud = match self.execution_chaud {
            Chaud::NonMesure(cause) => return format!("NON DÉPARTAGÉ — {cause}"),
            Chaud::Mesure(c) => c,
        };
        if froid < PLANCHER_INTERPRETABLE_MS && chaud < PLANCHER_INTERPRETABLE_MS {
            return format!(
                "les DEUX passages sont sous {PLANCHER_INTERPRETABLE_MS:.0} ms — trop court pour \
                 conclure, et cet énoncé ne pèse de toute façon rien dans la passe"
            );
        }
        // Plancher au dénominateur : un chaud à 0,0 ms (énoncé entièrement servi par le cache) ne doit pas
        // produire un rapport infini dans un rapport que quelqu'un lit.
        let rapport = froid / chaud.max(0.001);
        if rapport > FACTEUR_CACHE_DETERMINANT {
            format!(
                "LE FROID SURESTIME LA PASSE (×{rapport:.0}) — le cache absorbe l'essentiel, et la passe \
                 tourne sur une connexion vieille de plusieurs heures : elle paie de l'ordre de \
                 {chaud:.1} ms, PAS {froid:.1} ms"
            )
        } else {
            format!(
                "le froid DÉCRIT la passe (écart ×{rapport:.1}, sous {FACTEUR_CACHE_DETERMINANT:.0}) — \
                 aucun cache n'absorbe ce travail, la passe paie bien de cet ordre"
            )
        }
    }
}

/// LIT LE PLAN d'un énoncé. `EXPLAIN QUERY PLAN` COMPILE, il n'exécute pas : c'est ce qui rend cette
/// lecture sûre y compris sur la requête qui dure 20 s. Rend l'arbre à plat, indenté par profondeur
/// (colonnes `id`/`parent` de la sortie EQP).
fn plan_de(conn: &Connection, e: &Enonce) -> Result<Vec<String>, String> {
    let mut st = conn.prepare(&format!("EXPLAIN QUERY PLAN {}", e.sql)).map_err(pe)?;
    let lignes: Vec<(i64, i64, String)> = st
        .query_map(rusqlite::params_from_iter(e.params.iter()), |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(3)?))
        })
        .map_err(pe)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(pe)?;
    // Profondeur = longueur de la chaîne des parents (0 = racine), BORNÉE par le nombre de lignes : un
    // `parent` incohérent ne peut donc pas faire boucler la sonde.
    Ok(lignes
        .iter()
        .map(|(id, _, detail)| {
            let mut prof = 0usize;
            let mut cur = *id;
            while prof < lignes.len() {
                match lignes.iter().find(|(i, ..)| *i == cur).map(|(_, p, _)| *p) {
                    Some(p) if p != 0 => {
                        cur = p;
                        prof += 1;
                    }
                    _ => break,
                }
            }
            format!("{}{detail}", "  ".repeat(prof))
        })
        .collect())
}

/// PLAFOND DE RÉCOLTE — la sonde ne retient JAMAIS un nombre non borné de lignes (budget 2 Gio, et
/// l'énoncé de page rend jusqu'à 262 144 lignes). 4 096 couples `(env_id, jour)` couvrent dix ans de
/// rétention sur un déploiement mono-index ; au-delà, la récolte s'arrête MAIS le comptage continue, et le
/// rapport dit que la liste est tronquée plutôt que de laisser croire qu'il y avait moins de candidats.
pub(super) const RECOLTE_MAX: usize = 4096;

/// EXÉCUTE l'énoncé et le chronomètre, SANS rien retenir. Mesurer un `prepare` sans `step` ne dirait rien
/// du coût réel ; garder les lignes ferait de la sonde un poste de RAM. Rien d'autre que des NOMBRES ne
/// sort d'ici — aucune valeur d'event.
pub(super) fn executer_et_chronometrer(conn: &Connection, e: &Enonce) -> Result<Mesure, String> {
    executer_recolter_et_chronometrer(conn, e, 0, |_| Ok(())).map(|(m, _)| m)
}

/// EXÉCUTE, CHRONOMÈTRE **ET RÉCOLTE** au plus `cap` lignes via `recolte`.
///
/// POURQUOI CETTE VARIANTE EXISTE, ET CE QU'ELLE ÉVITE. La sonde a besoin du RÉSULTAT de deux énoncés pour
/// enchaîner comme la passe enchaîne (la découverte donne les candidats ; le snapshot donne le `max_id` qui
/// borne la page). La première version les REJOUAIT après les avoir chronométrés — ce qui, en production,
/// aurait fait payer DEUX FOIS les 17-22 s de la découverte, soit ~40 s de lecture pour un outil dont tout
/// l'argument est de ne pas déranger. Ici l'exécution est UNIQUE : on compte TOUTES les lignes (le
/// chronométrage reste celui de l'énoncé complet) et on n'en RETIENT que `cap`.
///
/// `cap = 0` -> aucune allocation, aucune fermeture appelée : c'est le cas de tous les autres énoncés.
pub(super) fn executer_recolter_et_chronometrer<T>(
    conn: &Connection,
    e: &Enonce,
    cap: usize,
    mut recolte: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<(Mesure, Vec<T>), String> {
    let plan = plan_de(conn, e)?;
    let t_compil = Instant::now();
    let mut st = conn.prepare(&e.sql).map_err(pe)?;
    let compilation_ms = t_compil.elapsed().as_secs_f64() * 1000.0;
    let t_execution = Instant::now();
    let mut lignes = 0i64;
    let mut recoltees: Vec<T> = Vec::new();
    {
        let mut rows = st.query(rusqlite::params_from_iter(e.params.iter())).map_err(pe)?;
        while let Some(r) = rows.next().map_err(pe)? {
            lignes += 1;
            if recoltees.len() < cap {
                recoltees.push(recolte(r).map_err(pe)?);
            }
        }
    }
    let execution_froid_ms = t_execution.elapsed().as_secs_f64() * 1000.0;

    // `P10.15-a` — LES COMPTEURS SE LISENT **AVANT** LE REJEU, ET C'EST LOAD-BEARING.
    // `sqlite3_stmt_status(..., resetFlg=0)` — ce que fait `Statement::get_status` — rend un CUMUL sur la
    // durée de vie de l'instruction préparée, pas le coût de la dernière exécution. Les lire après le
    // second passage aurait DOUBLÉ `balayage`, `tris` et `pas_de_machine` en silence : les 1 708 241
    // balayages et 8 544 099 pas relevés en production le 2026-08-15 seraient devenus ~3,4 M et ~17 M,
    // sans qu'aucune ligne du rapport ne signale le changement d'unité. Corriger un instrument en
    // falsifiant ses autres chiffres aurait été le défaut qu'on est en train de fermer, retourné contre
    // lui-même. Témoin : `les_compteurs_ne_comptent_que_le_passage_froid`.
    use rusqlite::StatementStatus as S;
    let (balayage, tris, pas_de_machine) = (
        i64::from(st.get_status(S::FullscanStep)),
        i64::from(st.get_status(S::Sort)),
        i64::from(st.get_status(S::VmStep)),
    );

    // LE SECOND PASSAGE, IMMÉDIATEMENT, sur la MÊME instruction déjà compilée : ce qui reste entre les
    // deux mesures n'est donc que l'état du cache, ni la compilation ni un autre plan. Rien n'est récolté
    // ici (le `cap` est déjà consommé) et rien n'est retenu : que le chronomètre.
    let execution_chaud = rejouer_a_chaud(&mut st, e);

    Ok((
        Mesure { plan, compilation_ms, execution_froid_ms, execution_chaud, lignes, balayage, tris, pas_de_machine },
        recoltees,
    ))
}

/// `P10.15-a` — REJOUE l'énoncé DÉJÀ COMPILÉ et rend sa durée cache chaud, ou la CAUSE de son absence. Un
/// échec ici n'est jamais fatal : la sonde publie alors le froid en le déclarant NON DÉPARTAGÉ, ce qui est
/// exactement l'état de connaissance — et non un froid présenté comme le prix de la passe.
fn rejouer_a_chaud(st: &mut rusqlite::Statement<'_>, e: &Enonce) -> Chaud {
    let t = Instant::now();
    let Ok(mut rows) = st.query(rusqlite::params_from_iter(e.params.iter())) else {
        return Chaud::NonMesure(CHAUD_REJEU_EN_ECHEC);
    };
    loop {
        match rows.next() {
            Ok(Some(_)) => {}
            Ok(None) => return Chaud::Mesure(t.elapsed().as_secs_f64() * 1000.0),
            Err(_) => return Chaud::NonMesure(CHAUD_REJEU_EN_ECHEC),
        }
    }
}

/// LE PLAN SEUL, SANS EXÉCUTION — pour un énoncé que la passe N'EXÉCUTE PAS dans l'état actuel de la
/// configuration. Le montrer sans le chronométrer est le seul rendu honnête : une durée facturerait à la
/// passe un travail qu'elle ne fait pas. Les compteurs valent `-1` = « non mesuré », jamais `0`.
fn plan_seul(conn: &Connection, e: &Enonce) -> Result<Mesure, String> {
    Ok(Mesure {
        plan: plan_de(conn, e)?,
        compilation_ms: 0.0,
        execution_froid_ms: 0.0,
        execution_chaud: Chaud::NonMesure(CHAUD_JAMAIS_EXECUTE),
        lignes: -1,
        balayage: -1,
        tris: -1,
        pas_de_machine: -1,
    })
}

// =================================================================================================
// LE RAPPORT
// =================================================================================================

fn rendre(out: &mut String, e: &Enonce, m: &Result<Mesure, String>) {
    let _ = writeln!(out, "\n── {} — {}", e.nom, e.role);
    let _ = writeln!(out, "   SQL     : {}", e.sql.split_whitespace().collect::<Vec<_>>().join(" "));
    if !e.params.is_empty() {
        let p: Vec<String> = e
            .params
            .iter()
            .map(|v| match v {
                rusqlite::types::Value::Integer(i) => i.to_string(),
                rusqlite::types::Value::Text(s) => format!("'{s}'"),
                autre => format!("{autre:?}"),
            })
            .collect();
        let _ = writeln!(out, "   params  : [{}]", p.join(", "));
    }
    // La CADENCE se dit AVANT les chiffres : un lecteur qui s'arrête à la première ligne chiffrée ne
    // doit pas repartir avec une durée qu'il croit payée à chaque passe.
    if let ParLaPasse::ACadence(phrase) = &e.par_la_passe {
        let _ = writeln!(out, "   cadence : {phrase}");
    }
    match m {
        Err(err) => {
            let _ = writeln!(out, "   MESURE IMPOSSIBLE : {err}");
        }
        Ok(m) => {
            if m.plan.is_empty() {
                let _ = writeln!(out, "   plan    : (vide — SQLite n'a rendu aucune étape)");
            }
            for (i, l) in m.plan.iter().enumerate() {
                let _ = writeln!(out, "   {} {l}", if i == 0 { "plan    :" } else { "         " });
            }
            match e.par_la_passe {
                ParLaPasse::Jamais => {
                    let _ = writeln!(
                        out,
                        "   NON EXÉCUTÉ PAR LA PASSE dans cette configuration -> plan montré, durée NON \
                         mesurée (la facturer serait un chiffre faux)"
                    );
                }
                ParLaPasse::ChaqueTick | ParLaPasse::ACadence(_) => {
                    // `P10.15-a` — LES DEUX DURÉES, TOUJOURS, SUR LA MÊME LIGNE. Publier le froid seul
                    // était le défaut : mesuré en production le 2026-08-15, il surestimait la découverte
                    // d'un facteur ≥ 183. Le couple ne se sépare pas, et le verdict qui suit ne fait
                    // qu'aider à le lire — il ne remplace aucun des deux nombres.
                    let _ = writeln!(
                        out,
                        "   mesuré  : compilation {:.1} ms · exécution FROID {:.1} ms / CHAUD {} · {} \
                         ligne(s) rendue(s)",
                        m.compilation_ms,
                        m.execution_froid_ms,
                        match m.execution_chaud {
                            Chaud::Mesure(c) => format!("{c:.1} ms"),
                            Chaud::NonMesure(_) => "non mesuré".to_string(),
                        },
                        m.lignes
                    );
                    let _ = writeln!(out, "   cache   : {}", m.verdict_de_cache());
                    let _ = writeln!(
                        out,
                        "   travail : balayage={} tris={} pas_de_machine={} (comptés sur le SEUL passage \
                         froid — ces compteurs cumulent sur l'instruction, pas sur l'exécution)",
                        m.balayage, m.tris, m.pas_de_machine
                    );
                }
            }
        }
    }
}

/// LE PLAN DE LA PASSE DE VIEILLISSEMENT, MESURÉ SUR LA BASE VIVANTE — corps de la sous-commande
/// `cold-aging-plan`. STRICTEMENT EN LECTURE SEULE (cf. l'en-tête). Rend le rapport, ou l'erreur qui a
/// empêché de mesurer — jamais un rapport vide, qui se lirait « rien à voir ».
pub(crate) fn cold_aging_plan(conf: &HashMap<String, String>, db_path: &str) -> Result<String, String> {
    let conn = ouvrir_en_lecture_seule(db_path)?;
    let n = now();
    // MÊME résolution que `retention_run` (table `setting` > env/conf > défaut, planchers durs compris) :
    // une autre valeur donnerait d'autres bornes, donc un autre plan que celui de la passe.
    let retention_days = retention_effective(&conn, conf, "retention_days");
    let bande = Bande::calculer(&conn, conf, n, retention_days);

    let mut out = String::new();
    let _ = writeln!(out, "cold-aging-plan {db_path}");
    let _ = writeln!(
        out,
        "  LECTURE SEULE : SQLITE_OPEN_READ_ONLY + authorizer défaut-deny (Read/Select/Function seuls) — \
         aucun ANALYZE, aucun PRAGMA d'écriture, aucun verrou d'écriture pris."
    );
    // `P10.15-a` — LA MISE EN GARDE SE LIT DANS LA SORTIE, PAS DANS LE CODE. Elle existait déjà, mot pour
    // mot, en tête de ce module — donc invisible à l'opérateur qui lit `kubectl exec ... cold-aging-plan`.
    // Une garantie écrite là où le lecteur concerné ne passe jamais n'est pas une garantie : c'est la même
    // famille de défaut que « fail-loud » écrit en commentaire au-dessus d'un `unwrap_or(0)`.
    let _ = writeln!(
        out,
        "  CHAQUE ÉNONCÉ EST MESURÉ DEUX FOIS : une passe sur connexion NEUVE (cache SQLite vide) puis un \
         REJEU immédiat (tout en cache). Le CHAUD est un PLANCHER : la passe ne peut pas faire mieux. Le \
         FROID n'est PAS un majorant — le cache de l'OS n'est pas remis à zéro et cette sonde ne le \
         mesure pas : le même énoncé a rendu 10,1 ms, 3 847 ms et 11,3 ms selon le jour. C'est l'ÉCART \
         entre les deux qui informe, et la ligne `cache` de chaque énoncé le dit."
    );
    let _ = writeln!(
        out,
        "  CE QUE CETTE SONDE COÛTE : deux lectures complètes au lieu d'une, et elle tire par le cache de \
         l'OS tout ce qu'elle lit — relevé du 2026-08-15 en production, MemAvailable 1 195 -> 986 Mio \
         (-209) sur un budget de 2 Gio. Elle ne prend aucun verrou ; elle prend de la MÉMOIRE."
    );
    let _ = writeln!(out, "  maintenant = {n}");
    // LES DEUX GATES DE LA PASSE, DITS AVANT LES CHIFFRES : sans eux, un rapport de plans se lirait comme
    // la description d'un travail qui a lieu, alors que la passe peut ne pas tourner du tout.
    let tier = cfg(conf, "PLUME_COLD_TIER", "");
    if tier != "1" {
        let _ = writeln!(
            out,
            "  /!\\ PLUME_COLD_TIER={tier:?} (≠ \"1\") -> LA PASSE NE TOURNE PAS sur ce déploiement. Les \
             énoncés ci-dessous sont ceux qu'elle EXÉCUTERAIT."
        );
    }
    if retention_days <= 1 {
        let _ = writeln!(
            out,
            "  /!\\ retention_days={retention_days} (<= 1) -> la passe se suspend AVANT toute découverte \
             (cause `retention_courte`)."
        );
    }
    let (lo, hi) = bande.bornes_de_decouverte();
    let _ = writeln!(
        out,
        "  bande   : retention_days={retention_days} cold_ret={} max_ret={} fenêtre_chaude={} j",
        bande.cold_ret, bande.max_ret, bande.hot_window
    );
    let _ = writeln!(
        out,
        "            découverte sur les jours [{} .. {}) = ts [{lo} .. {hi}) — {} jour(s){}",
        ymd_from_day(bande.broad_lo_day),
        ymd_from_day(bande.hi_day_excl),
        (bande.hi_day_excl - bande.broad_lo_day).max(0),
        if bande.ouverte() { "" } else { "  /!\\ BANDE VIDE : la passe ne découvre rien" }
    );
    let _ = writeln!(
        out,
        "            file_cap={} rg_rows={} policies_per_index={}",
        bande.file_cap,
        bande.rg_rows,
        bande.policies.len()
    );
    // `P10.13-a` levier ① — LA CADENCE DU DEAD-MAN'S-SWITCH, DITE AVEC SON ÉTAT RÉEL. Le `dernier_tir`
    // est relu dans `meta` PAR LA MÊME FONCTION que la passe : la sonde ne décrit donc pas une cadence
    // théorique, elle lit celle qui s'applique à cette base à cette seconde. `SELECT` sur `meta` :
    // l'authorizer défaut-deny l'autorise (Read + Select), et rien n'est écrit.
    let dernier_tir = dernier_tir_du_retard(&conn);
    let tir = bande.tir_du_retard(n, dernier_tir);
    let _ = writeln!(
        out,
        "  retard  : période de tir {} s · dernier tir {} · verdict de CE tick : {}",
        bande.periode_de_tir,
        match dernier_tir {
            // `saturating_sub` : la valeur vient d'une colonne TEXTE de `meta`, donc d'une donnée non
            // contrôlée. Un instrument de diagnostic ne panique pas sur ce qu'il est venu diagnostiquer.
            Some(t) => format!("ts={t} (il y a {} s)", n.saturating_sub(t)),
            None => "JAMAIS (aucun horodatage dans `meta`) -> le prochain tick tire".to_string(),
        },
        match &tir {
            TirDuRetard::Du { lo, hi } => format!("TIRE sur ts [{lo} .. {hi})"),
            TirDuRetard::Ajourne(cause) => format!("N'EXÉCUTE PAS l'énoncé n° 5 (cause `{cause}`)"),
        }
    );

    // ---- Les énoncés SANS candidat, dans l'ordre de la passe. ----
    // La découverte est chronométrée UNE SEULE FOIS et sa récolte (plafonnée) sert à choisir le candidat :
    // la rejouer aurait fait payer deux fois les 17-22 s qu'on est venu mesurer.
    let mut candidats: Vec<(String, i64)> = Vec::new();
    let mut decouverts = 0i64;
    for e in enonces_sans_candidat(&bande, n, &tir) {
        if matches!(e.par_la_passe, ParLaPasse::Jamais) {
            let m = plan_seul(&conn, &e);
            rendre(&mut out, &e, &m);
            continue;
        }
        if e.nom == NOM_DECOUVERTE {
            let (total, recolte) = mesurer_et_rendre(&mut out, &conn, &e, RECOLTE_MAX, |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            });
            decouverts = total;
            candidats = recolte;
            continue;
        }
        let m = executer_et_chronometrer(&conn, &e);
        rendre(&mut out, &e, &m);
    }

    // ---- Le PREMIER candidat RETENU (MÊME prédicat que la passe) et ses énoncés par-jour. ----
    let retenus: Vec<&(String, i64)> = candidats.iter().filter(|(e, d)| bande.retenu(e, *d, n)).collect();
    let _ = writeln!(
        out,
        "\n── candidats : {decouverts} découvert(s), {} retenu(s) par `Bande::retenu` (env_id conforme ET \
         dans la rétention de son index){}",
        retenus.len(),
        if decouverts as usize > candidats.len() {
            format!("  /!\\ liste TRONQUÉE à {} : le compte ci-dessus reste exact", candidats.len())
        } else {
            String::new()
        }
    );
    let Some((env_id, day)) = retenus.first() else {
        let _ = writeln!(
            out,
            "   aucun candidat retenu -> les énoncés PAR-JOUR ne sont pas mesurés (la passe ne les \
             exécuterait pas non plus)."
        );
        return Ok(out);
    };
    let _ = writeln!(
        out,
        "   mesure du PREMIER retenu : {env_id}/{} — les énoncés ci-dessous se paient UNE FOIS PAR JOUR \
         traité, donc jusqu'à {} fois par passe.",
        ymd_from_day(*day),
        retenus.len()
    );
    let mut max_id = 0i64;
    for e in enonces_du_candidat(&bande, env_id, *day) {
        if e.nom == NOM_COMPTE_ET_MAX_ID {
            // Le `max_id` est RÉCOLTÉ pendant la mesure (2ᵉ colonne, 1 ligne), pas relu par une seconde
            // exécution : même raison que la découverte.
            let (_, v) = mesurer_et_rendre(&mut out, &conn, &e, 1, |r| r.get::<_, i64>(1));
            max_id = v.first().copied().unwrap_or(0);
            continue;
        }
        let m = executer_et_chronometrer(&conn, &e);
        rendre(&mut out, &e, &m);
    }
    // La page keyset n'est CONSTRUCTIBLE qu'ici : elle est bornée par le `max_id` que l'énoncé précédent
    // vient de rendre — exactement l'ordre de `age_one_day`, pas un artifice de la sonde.
    let page = enonce_de_la_page(&bande, env_id, *day, max_id);
    let m = executer_et_chronometrer(&conn, &page);
    rendre(&mut out, &page, &m);
    Ok(out)
}

/// MESURE `e` en récoltant au plus `cap` lignes, ÉCRIT son bloc de rapport, et rend `(lignes totales,
/// récolte)`. Le total vient du CHRONOMÈTRE, pas de la récolte : c'est ce qui permet de dire « 300
/// candidats, liste tronquée à 4096 » au lieu de laisser croire qu'il y en avait moins. Une erreur est
/// RENDUE dans le rapport (`MESURE IMPOSSIBLE`) et la récolte est vide — jamais un silence.
fn mesurer_et_rendre<T>(
    out: &mut String,
    conn: &Connection,
    e: &Enonce,
    cap: usize,
    recolte: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> (i64, Vec<T>) {
    match executer_recolter_et_chronometrer(conn, e, cap, recolte) {
        Ok((m, v)) => {
            let total = m.lignes;
            rendre(out, e, &Ok(m));
            (total, v)
        }
        Err(err) => {
            rendre(out, e, &Err(err));
            (0, Vec::new())
        }
    }
}

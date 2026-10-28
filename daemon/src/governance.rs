//! #59 GOUVERNANCE ENTREPRISE (reliquat DIFFÉRÉ de #38). TROIS primitives, cœurs PURS (testables sans
//! AppState), branchés sur les chemins existants sans les affaiblir :
//!
//!  1. LEGAL-HOLD / RÉTENTION-LOCK (`legal_hold`, per-tenant). Une ligne active ÉPINGLE les events dont la
//!     portée (source + fenêtre temporelle) matche CONTRE toute suppression par `retention_run` (purge
//!     globale + per-index #49 + plafonds). Enforcement FAIL-CLOSED : si l'état des holds ne peut être
//!     déterminé (table illisible), on S'ABSTIENT de purger `event` (jamais de suppression d'une preuve
//!     dont on ne peut prouver qu'elle n'est pas retenue). Mode 0 (aucun hold) -> AUCUN prédicat ajouté ->
//!     texte SQL byte-identique à l'historique. La portée couvre le TABLE `event` (preuve brute) ; les
//!     rollups dérivés (agrégats reconstructibles, non-preuve) ne sont PAS épinglés — assumé et documenté.
//!
//!  2. EXPORT STREAMING DU LEDGER (chaîne préservée). Cœurs `ledger_export_lines` (READ-ONLY sur `ledger`,
//!     aucun chemin de mutation) + `verifier_la_copie_du_registre` (le vérificateur HORS LIGNE que lance
//!     `ledger-verify-export`, règle dans `copie_chainee` : il recalcule la chaîne de hash sur la copie
//!     exportée -> détecte toute altération, et écarte une ligne répétée à l'identique). L'export ÉMET la chaîne complète
//!     (prev_hash + hash + id/ts/kind/detail) : c'est exactement ce que `verify_run` recompute -> une copie
//!     WORM externe reste vérifiable indépendamment. La signature ed25519 des checkpoints n'est jamais
//!     affaiblie (export = SELECT seul).
//!
//!  3. RÔLES COMPOSABLES (`role_def`, control-plane, catalogue global géré par le super-admin). Un rôle
//!     custom résout vers un `base_role` ∈ {viewer,editor,admin} : c'est SON PLAFOND (l'escalade est
//!     structurellement impossible — un rôle custom n'est jamais plus fort que sa base). Un ensemble
//!     `deny_perms` SOUSTRAIT des capacités (raw_sql, arm_response…) — jamais n'en ajoute (l'additif est
//!     DIFFÉRÉ, précisément parce que c'est le vecteur d'escalade). DEFAULT-DENY préservé : un nom de rôle
//!     INCONNU résout vers "" (rang 0 -> refusé). Le catalogue VIDE (mode 0 / pas de rôle custom) laisse
//!     `rbac_gate`/`raw_sql_allowed` byte-identiques (les rôles de base court-circuitent avant toute
//!     résolution custom).
use crate::*;

// =====================================================================================
// 1. LEGAL-HOLD — enforcement fail-closed dans le chemin de rétention
// =====================================================================================

/// Une table `event` existe-t-elle un hold ACTIF qui l'épingle ? Décision d'enforcement pour `retention_run`.
pub(crate) enum HoldEnforce {
    /// Aucun hold (table absente = pré-v96, OU zéro ligne active) -> purge INCHANGÉE (mode 0 byte-identique).
    NoHolds,
    /// >=1 hold actif -> le fragment WHERE `NOT (event est retenu)` à ANDer aux DELETE sur `event`.
    Guard(String),
    /// L'état des holds n'a PAS pu être déterminé alors que la table EXISTE -> FAIL-CLOSED : ne PAS purger
    /// `event` ce tick (on ne supprime jamais une preuve dont on ne peut prouver qu'elle n'est pas retenue).
    FailClosed,
}

/// Fragment WHERE : « cet event N'EST PAS retenu par un hold actif ». Corrélé à la ligne `event` en cours de
/// DELETE (référence `event.source`/`event.ts`, valides dans `DELETE FROM event WHERE …`). scope_source=''
/// -> tous ; fenêtre [start,end] ouverte si 0. LITTÉRAL interne (aucune entrée utilisateur interpolée).
pub(crate) const LEGAL_HOLD_NOT_HELD: &str =
    "NOT EXISTS (SELECT 1 FROM legal_hold h WHERE h.active=1 \
       AND (h.scope_source='' OR h.scope_source=event.source) \
       AND (h.scope_start_ts=0 OR event.ts>=h.scope_start_ts) \
       AND (h.scope_end_ts=0 OR event.ts<=h.scope_end_ts))";

/// COUVERTURE HOLD DES TABLES SANS COLONNE `source` (`alert` = texte d'alerte synthétisé, `snapshot` =
/// captures d'état forensiques) — CRITICAL #59. Ces deux tables portent une preuve NON-reconstructible mais
/// AUCUN `source` : un hold SCOPÉ à une source ne peut donc les matcher. La sémantique retenue : SEUL un hold
/// à portée GLOBALE (`scope_source=''`) épingle une ligne alert/snapshot, et UNIQUEMENT si sa fenêtre `ts`
/// la couvre. Autrement dit, un hold global bloque les TROIS classes (event + alert + snapshot) sur sa
/// fenêtre ; un hold source-scopé ne bloque QUE `event` (via LEGAL_HOLD_NOT_HELD). Fragment corrélé à la
/// ligne en cours de DELETE (`<tscol>` = littéral interne `ts` — jamais d'entrée utilisateur interpolée).
pub(crate) fn legal_hold_not_held_global(tscol: &str) -> String {
    format!(
        "NOT EXISTS (SELECT 1 FROM legal_hold h WHERE h.active=1 AND h.scope_source='' \
           AND (h.scope_start_ts=0 OR {tscol}>=h.scope_start_ts) \
           AND (h.scope_end_ts=0 OR {tscol}<=h.scope_end_ts))"
    )
}

/// PRÉSENCE D'UNE TABLE EN TROIS ISSUES (`P10.31-x`) : `Ok(true)` présente, `Ok(false)` ABSENCE ÉTABLIE
/// (le catalogue a été lu et ne la porte pas — base pré-migration), `Err` lecture NON FAITE (interruption par
/// le quota, verrou, catalogue illisible).
///
/// L'ancienne forme (`table_present`, `.is_ok()` d'un `query_row` sur `SELECT 1`) confondait les deux
/// dernières : sa doc annonçait distinguer « pré-v96 » d'« erreur d'accès », elle rendait `false` pour les
/// deux. Mesuré sur la purge : une interruption de la lecture de `incident_item` valait « table absente », le
/// contrôle de citation était SAUTÉ et la confirmation détruisait un event cité par un dossier. Un
/// `COUNT(*)` rend toujours une ligne : zéro est une absence lue, une erreur n'est que l'erreur.
pub(crate) fn presence_de_table(conn: &Connection, name: &str) -> rusqlite::Result<bool> {
    // Instrument de témoin (cfg(test)) : il pose SEULEMENT le rappel de progression qui fait interrompre la
    // requête par le moteur (SQLITE_INTERRUPT) ; c'est la requête de PRODUCTION ci-dessous qui s'exécute et
    // dont la lecture ratée est jugée — aucune copie de la requête n'est portée par l'instrument.
    #[cfg(test)]
    let panne = temoin_de_presence::panne_armee(name);
    #[cfg(test)]
    if panne {
        conn.progress_handler(1, Some(|| true));
    }
    let lu = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1", params![name], |r| {
        r.get::<_, i64>(0)
    });
    #[cfg(test)]
    if panne {
        conn.progress_handler(0, None::<fn() -> bool>);
    }
    lu.map(|n| n > 0)
}

/// Forme booléenne réservée aux TESTS (une erreur y fait échouer le test en la nommant) : aucun appelant de
/// production ne peut plus lire une présence de table sans traiter la lecture ratée.
#[cfg(test)]
pub(crate) fn table_present(conn: &Connection, name: &str) -> bool {
    presence_de_table(conn, name).expect("lecture du catalogue `sqlite_master`")
}

/// Instrument de témoin (`P10.31-x`) : arme une panne PERSISTANTE de la lecture de présence d'UNE table, sur le
/// fil courant. Hors `cfg(test)`, ce module n'existe pas.
#[cfg(test)]
pub(crate) mod temoin_de_presence {
    use std::cell::RefCell;
    thread_local! {
        static PANNE: RefCell<Option<String>> = const { RefCell::new(None) };
    }
    pub(crate) fn armer(name: &str) {
        PANNE.with(|p| *p.borrow_mut() = Some(name.to_string()));
    }
    pub(crate) fn desarmer() {
        PANNE.with(|p| *p.borrow_mut() = None);
    }
    pub(crate) fn panne_armee(name: &str) -> bool {
        PANNE.with(|p| p.borrow().as_deref() == Some(name))
    }
}

/// Décision d'enforcement legal-hold pour `retention_run` (FAIL-CLOSED). Cf. HoldEnforce.
pub(crate) fn legal_hold_enforcement(conn: &Connection) -> HoldEnforce {
    // 1) Présence de la table, en DISTINGUANT « absente » (pré-v96, sûr) de « schéma illisible » (incertain).
    //    Si sqlite_master lui-même n'est pas lisible -> on ne peut RIEN affirmer -> FAIL-CLOSED (ne pas purger).
    match conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='legal_hold'", [], |r| r.get::<_, i64>(0)) {
        Err(_) => HoldEnforce::FailClosed,
        Ok(0) => HoldEnforce::NoHolds, // table absente (base pré-v96) -> purge byte-identique (mode 0)
        Ok(_) => {
            // 2) Table présente : toute erreur de lecture du compte des holds actifs = incertitude -> FAIL-CLOSED.
            match conn.query_row("SELECT COUNT(*) FROM legal_hold WHERE active=1", [], |r| r.get::<_, i64>(0)) {
                Ok(0) => HoldEnforce::NoHolds,
                Ok(_) => HoldEnforce::Guard(LEGAL_HOLD_NOT_HELD.to_string()),
                Err(_) => HoldEnforce::FailClosed,
            }
        }
    }
}

/// Un event unitaire (source, ts) est-il RETENU par un hold actif ? Utilisé par les tests d'invariant (et
/// par une future prévisualisation). Pur sur &Connection. Fail-safe : erreur -> false (ne retient rien de
/// force côté LECTURE ; la garde de SUPPRESSION, elle, est fail-closed séparément dans legal_hold_enforcement).
pub(crate) fn event_is_held(conn: &Connection, source: &str, ts: i64) -> bool {
    // `P7.19-i` — ce `LIMIT 1` est SANS ORDRE et le reste : la projection est la CONSTANTE `1` et le
    // seul consommateur est `.is_ok()`. Toutes les lignes candidates se projettent à l'identique, donc
    // aucun ordre ne peut changer la réponse — c'est une EXISTENCE, pas une ligne retenue.
    conn.query_row(
        "SELECT 1 FROM legal_hold h WHERE h.active=1 \
           AND (h.scope_source='' OR h.scope_source=?1) \
           AND (h.scope_start_ts=0 OR ?2>=h.scope_start_ts) \
           AND (h.scope_end_ts=0 OR ?2<=h.scope_end_ts) LIMIT 1",
        params![source, ts],
        |_| Ok(()),
    )
    .is_ok()
}

// =====================================================================================
// 2. LEDGER — export streaming (chaîne préservée) + vérification externe
// =====================================================================================

/// Une ligne d'export du ledger, CANONIQUE : porte la chaîne complète (prev_hash + hash) pour qu'un
/// vérificateur externe recompute exactement ce que `verify_run` recompute. JSON (ordre de clés
/// déterministe via serde_json). READ-ONLY : construit depuis un SELECT, jamais réinjecté dans le ledger.
pub(crate) fn ledger_export_line(id: i64, ts: i64, kind: &str, detail: &str, prev_hash: &str, hash: &str) -> String {
    json!({
        "id": id, "ts": ts, "kind": kind, "detail": detail,
        "prev_hash": prev_hash, "hash": hash
    })
    .to_string()
}

/// Lit une TRANCHE du ledger (`id > from_id`, ordre croissant, borné `limit`) et rend (lignes JSONL,
/// dernier id, dernier hash). SELECT SEUL sur `ledger` -> AUCUN chemin de mutation (l'append-only reste
/// intact). `limit<=0` -> pas de borne (export complet).
///
/// `P10.7-s` — UNE TRANCHE QU'ON NE SAIT PAS LIRE N'EST PAS UNE TRANCHE VIDE, ET CE TYPE LE DIT. Jusqu'au
/// 2026-08-31 cette fonction APLATISSAIT : un `let Ok(…) else { return vide }` sur le préparatif, un
/// `flatten()` sur les lignes. Deux formes MESURÉES ce jour-là, et elles ne coûtent pas la même chose :
///
///  1. PRÉPARATIF RATÉ (table `ledger` absente, clé SQLCipher absente/incorrecte) -> ZÉRO ligne, curseur
///     inchangé, et `ledger_verify_export(&[], "")` rend `Ok(0)` : « export OK : 0 entrées chaînées
///     intègres ». Un verdict d'intégrité sur une copie qui n'a jamais été lue.
///  2. LIGNE ILLISIBLE (colonne d'un type inattendu — restauration partielle, écriture SQL directe). Deux
///     sous-formes, et la MESURE a REFUSÉ la version courte de l'énoncé qui a ouvert cette clé :
///       · la ligne illisible est la DERNIÈRE (3 maillons, le 3e abîmé) -> 2 lignes, `Ok(2)` du
///         vérificateur : « intègre », littéralement le faux vert annoncé. Curseur à 2 -> l'envoi suivant
///         relit la même ligne illisible, rend zéro, et la route répond `"exported": 0` : la copie WORM
///         est GELÉE, définitivement, sans un mot ;
///       · la ligne illisible est au MILIEU (le 2e des 3) -> 2 lignes AUSSI, mais le vérificateur d'export
///         les REJETTE (`rupture de chaîne`, ancrage `prev_hash`). L'énoncé disait « également déclarés
///         intègres » : c'est FAUX de cette sous-forme. Ce qui est vrai, et pire, c'est le CURSEUR : il
///         avance à 3, donc le maillon #2 n'entre JAMAIS dans la copie inaltérable — une lacune
///         PERMANENTE — et aucun appelant de production n'interroge le vérificateur sur ce chemin
///         (`ledger_sink_flush` écrit puis avance), si bien que ce refus-là n'est LU par personne.
///
/// LA LOI EST DONC CELLE DES VÉRIFICATEURS VOISINS (`verify_ledger_conn`, `control_ledger_verify_conn`),
/// À LA LETTRE : ce que la lecture ne rend PAS -> `Err`, aucun export. Ce qu'elle rend -> exporté, y
/// compris un `detail` NULL (seul nullable de la table), qui vaut chaîne vide comme en production.
///
/// CE QU'ON N'A PAS FAIT, ET C'EST DÉLIBÉRÉ : `ledger_verify_export` n'est PAS durci à rejeter un export
/// VIDE. Un export incrémental est LÉGITIMEMENT vide quand rien n'est neuf ; l'y forcer troquerait le faux
/// vert contre une fausse accusation, tous les jours. La distinction se fait ICI, à la LECTURE, où elle est
/// connue — pas plus tard, par une heuristique sur une longueur.
pub(crate) fn ledger_export_lines(conn: &Connection, from_id: i64, limit: i64) -> Result<(Vec<String>, i64, String), String> {
    let sql = if limit > 0 {
        "SELECT id,ts,kind,detail,prev_hash,hash FROM ledger WHERE id>?1 ORDER BY id ASC LIMIT ?2".to_string()
    } else {
        "SELECT id,ts,kind,detail,prev_hash,hash FROM ledger WHERE id>?1 ORDER BY id ASC".to_string()
    };
    let mut out = Vec::new();
    let (mut last_id, mut last_hash) = (from_id, String::new());
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("lecture ledger (table absente ? clé SQLCipher manquante/incorrecte ?): {e} — AUCUN export"))?;
    let bind: Vec<&dyn rusqlite::ToSql> = if limit > 0 { vec![&from_id, &limit] } else { vec![&from_id] };
    let rows = stmt
        .query_map(bind.as_slice(), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })
        .map_err(|e| format!("scan ledger: {e} — AUCUN export"))?;
    // Le rang est celui du SCAN dans la TRANCHE, pas l'`id` : l'`id` de la ligne fautive est justement ce
    // qu'on n'a pas su lire. Même formulation que les deux vérificateurs voisins.
    for (rang, ligne) in rows.enumerate() {
        let (id, ts, kind, detail, prev_hash, hash) = ligne.map_err(|e| {
            format!("maillon #{} de la tranche ILLISIBLE ({e}) — la tranche n'a pas pu être lue entièrement : AUCUN export, et le curseur NE bouge PAS", rang + 1)
        })?;
        out.push(ledger_export_line(id, ts, &kind, &detail, &prev_hash, &hash));
        last_id = id;
        last_hash = hash;
    }
    Ok((out, last_id, last_hash))
}

/// LE JOURNAL DE CONTRÔLE S'EXPORTE COMME LE JOURNAL DES TENANTS (`P10.7-r`, 2026-09-09). Mesuré la veille :
/// `verify-control` rejoue toute la chaîne hors ligne, mais aucune route ne LISAIT `control_ledger` — donc
/// aucune copie hors de la machine, et une réécriture complète re-chaînée restait invisible. Une ligne par
/// maillon, avec TOUT ce que le hachage couvre (`prev|ts|kind|actor|tenant|detail`). Cette fonction rend la seule
/// chaîne ; la route sert `control_ledger_export_lines_ancree`, qui y ajoute les points de contrôle signés de la
/// tranche, et `verify-control --export` vérifie une copie sans la base, chaîne ET ancre
/// (`verdict_hors_ligne_de_la_copie_du_journal_de_controle`) — la chaîne seule ne voyait pas une réécriture re-chaînée.
/// Même contrat de tranche que le voisin : une tranche illisible ne rend RIEN et ne bouge pas le curseur.
pub(crate) fn control_ledger_export_line(id: i64, ts: i64, kind: &str, actor: &str, tenant: &str, detail: &str, prev_hash: &str, hash: &str) -> String {
    json!({ "id": id, "ts": ts, "kind": kind, "actor": actor, "tenant": tenant, "detail": detail, "prev_hash": prev_hash, "hash": hash }).to_string()
}

pub(crate) fn control_ledger_export_lines(conn: &Connection, from_id: i64, limit: i64) -> Result<(Vec<String>, i64, String), String> {
    let sql = if limit > 0 {
        "SELECT id,ts,kind,actor,tenant,detail,prev_hash,hash FROM control_ledger WHERE id>?1 ORDER BY id ASC LIMIT ?2".to_string()
    } else {
        "SELECT id,ts,kind,actor,tenant,detail,prev_hash,hash FROM control_ledger WHERE id>?1 ORDER BY id ASC".to_string()
    };
    let mut out = Vec::new();
    let (mut last_id, mut last_hash) = (from_id, String::new());
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| format!("lecture du journal de contrôle (table absente ? clé du plan de contrôle manquante/incorrecte ?): {e} — AUCUN export"))?;
    let bind: Vec<&dyn rusqlite::ToSql> = if limit > 0 { vec![&from_id, &limit] } else { vec![&from_id] };
    let rows = stmt
        .query_map(bind.as_slice(), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                r.get::<_, Option<String>>(5)?.unwrap_or_default(),
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
            ))
        })
        .map_err(|e| format!("scan du journal de contrôle: {e} — AUCUN export"))?;
    for (rang, ligne) in rows.enumerate() {
        let (id, ts, kind, actor, tenant, detail, prev_hash, hash) = ligne.map_err(|e| {
            format!("maillon #{} de la tranche ILLISIBLE ({e}) — la tranche n'a pas pu être lue entièrement : AUCUN export, et le curseur NE bouge PAS", rang + 1)
        })?;
        out.push(control_ledger_export_line(id, ts, &kind, &actor, &tenant, &detail, &prev_hash, &hash));
        last_id = id;
        last_hash = hash;
    }
    Ok((out, last_id, last_hash))
}

/// `P10.7-r` — LE CHAMP QUI DISTINGUE, DANS UNE COPIE DU JOURNAL DE CONTRÔLE, LA LIGNE DU POINT DE CONTRÔLE DES LIGNES
/// DE MAILLON. Une ligne de maillon ne le porte jamais.
pub(crate) const CHAMP_DU_POINT_DE_CONTROLE_EXPORTE: &str = "point_de_controle";

/// `P10.7-r` — L'EXPORT DU JOURNAL DE CONTRÔLE PORTE SES POINTS DE CONTRÔLE. Jusque-là la copie téléchargée ne portait
/// que la chaîne : un tiers vérifiait sa cohérence interne, jamais qu'elle était celle que la clé du registre avait
/// signée — une copie tirée d'un journal réécrit puis re-chaîné se vérifiait intègre. La tranche reçoit, après ses
/// maillons, une ligne par point de contrôle signé d'un maillon QU'ELLE CONTIENT (`from_id < ledger_id <= last_id`),
/// dans l'ordre d'écriture : un point hors de la tranche ne serait pas vérifiable contre elle, et le juge exige un
/// point PAR maillon — le seul point du maillon le plus récent laissait passer une tranche dont les maillons
/// antérieurs avaient été réécrits avant une écriture légitime. Lus APRÈS la tranche : un point de contrôle est écrit
/// après son maillon, donc chacun désigne un maillon que la tranche a déjà lu. Tranche vide, ou aucun point dans la
/// tranche (clé absente à l'écriture) -> aucune ligne ajoutée, et la vérification hors ligne le dira. Point de
/// contrôle illisible -> `Err`, AUCUN export (même contrat que la tranche).
pub(crate) fn control_ledger_export_lines_ancree(conn: &Connection, from_id: i64, limit: i64) -> Result<(Vec<String>, i64, String), String> {
    let (mut lignes, last_id, last_hash) = control_ledger_export_lines(conn, from_id, limit)?;
    // Une tranche vide rend `last_id == from_id` : l'intervalle est vide, aucun point n'est ajouté.
    lignes.extend(points_de_controle_de_la_tranche(conn, from_id, last_id)?);
    Ok((lignes, last_id, last_hash))
}

fn points_de_controle_de_la_tranche(conn: &Connection, from_id: i64, last_id: i64) -> Result<Vec<String>, String> {
    let illisible = |e: rusqlite::Error| format!("point de contrôle de la tranche ILLISIBLE ({e}) — AUCUN export, et le curseur NE bouge PAS");
    let mut stmt = conn
        .prepare("SELECT ledger_id,ledger_hash,sig,pubkey,ts FROM control_checkpoint WHERE ledger_id>?1 AND ledger_id<=?2 ORDER BY id")
        .map_err(illisible)?;
    let lignes = stmt
        .query_map(params![from_id, last_id], |r| {
            Ok(json!({ CHAMP_DU_POINT_DE_CONTROLE_EXPORTE: {
                "ledger_id": r.get::<_, i64>(0)?,
                "ledger_hash": r.get::<_, String>(1)?,
                "sig": r.get::<_, String>(2)?,
                "pubkey": r.get::<_, String>(3)?,
                "ts": r.get::<_, i64>(4)?,
            } })
            .to_string())
        })
        .and_then(|it| it.collect::<rusqlite::Result<Vec<_>>>())
        .map_err(illisible)?;
    Ok(lignes)
}

/// `P10.27-k` — la vérification hors ligne d'une copie vit dans `copie_chainee` (la règle de répétition exacte, les deux
/// ancrages, la lecture des lignes) ; ce module n'y apporte que la recette de hachage de chacun de ses deux journaux.
pub(crate) use crate::copie_chainee::CopieChaineeVerifiee;
use crate::copie_chainee::{champ_texte, verifier_des_lignes_numerotees, verifier_une_copie_chainee, RecetteDeChaine};

/// La recette de `control_ledger_append` : `prev|ts|kind|actor|tenant|detail`.
fn texte_hache_du_journal_de_controle(prev: &str, ts: i64, v: &Value) -> String {
    format!("{prev}|{ts}|{}|{}|{}|{}", champ_texte(v, "kind"), champ_texte(v, "actor"), champ_texte(v, "tenant"), champ_texte(v, "detail"))
}

/// La recette de `ledger_append` et de `verify_run` : `prev|ts|kind|detail`.
fn texte_hache_du_registre(prev: &str, ts: i64, v: &Value) -> String {
    format!("{prev}|{ts}|{}|{}", champ_texte(v, "kind"), champ_texte(v, "detail"))
}

/// Vérification HORS LIGNE d'une copie exportée du journal de contrôle : même recette de hachage que
/// `control_ledger_append`, mêmes ancrages et même règle de répétition exacte que la copie du registre. Aucun puits
/// n'exporte ce journal ; des téléchargements recouvrants mis bout à bout produisent pourtant des répétitions, et la
/// règle ne vit qu'à un endroit. Depuis `P10.7-r`, `verify-control --export` vérifie une copie de ce journal par
/// `verdict_hors_ligne_de_la_copie_du_journal_de_controle`, qui emploie la MÊME recette sur les seules lignes de maillon
/// (`verifier_des_lignes_numerotees`, rangs d'origine) puis juge l'ancre ; cette fonction-ci, qui ne connaît pas les
/// lignes de point de contrôle, ne sert plus que les témoins et `control_ledger_verify_export` (témoins seulement).
pub(crate) fn verifier_la_copie_du_journal_de_controle(lines: &[String], expect_prev: &str) -> Result<CopieChaineeVerifiee, String> {
    verifier_une_copie_chainee(lines, expect_prev, &RECETTE_DU_JOURNAL_DE_CONTROLE)
}

const RECETTE_DU_JOURNAL_DE_CONTROLE: RecetteDeChaine =
    RecetteDeChaine { texte_hache: texte_hache_du_journal_de_controle, alteration: "hachage recalculé différent — maillon altéré" };

/// Le nombre de maillons DISTINCTS d'une copie du journal de contrôle qui se vérifie ; les répétitions exactes sont
/// rendues à part par `verifier_la_copie_du_journal_de_controle`.
#[cfg(test)]
pub(crate) fn control_ledger_verify_export(lines: &[String], expect_prev: &str) -> Result<usize, String> {
    verifier_la_copie_du_journal_de_controle(lines, expect_prev).map(|c| c.maillons)
}

/// `P10.7-r` — LA COPIE EXPORTÉE DU JOURNAL DE CONTRÔLE, VÉRIFIÉE HORS LIGNE CONTRE SES POINTS DE CONTRÔLE. Les lignes
/// qui portent `point_de_controle` sont mises à part ; les autres passent par la vérification de chaîne (mêmes
/// ancrages, même règle de répétition exacte) ; puis l'ancre est jugée par le MÊME juge que la base
/// (`juger_l_ancrage_du_journal_de_controle`), contre la clé épinglée. Une ligne de point de contrôle incomplète, ou
/// une chaîne rompue -> `Err`.
pub(crate) fn verifier_la_copie_ancree_du_journal_de_controle(
    lines: &[String],
    expect_prev: &str,
    epinglee: Option<&[u8; 32]>,
) -> Result<(CopieChaineeVerifiee, crate::rbac::AncrageDuJournalDeControle), String> {
    // (rang dans la copie, ligne) : la chaîne nomme ses ruptures par le rang D'ORIGINE, comme les points — dans une
    // copie mise bout à bout, chaque ligne de point intercalée décalerait sinon d'un cran les rangs qui la suivent.
    let mut maillons_lus: Vec<(usize, &str)> = Vec::new();
    let mut maillons: Vec<(i64, String)> = Vec::new();
    let mut points: Vec<crate::rbac::PointDeControleDuJournal> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let v: Value = serde_json::from_str(line).map_err(|e| format!("ligne {i}: JSON invalide: {e}"))?;
        let Some(p) = v.get(CHAMP_DU_POINT_DE_CONTROLE_EXPORTE) else {
            // Un maillon sans `id` lisible n'entre pas dans la table du juge : la vérification de chaîne, juste en
            // dessous, le refuse (« id manquant ») avant que le juge ne soit appelé. Une répétition exacte entre
            // deux fois : le juge indexe par identifiant.
            maillons.extend(v.get("id").and_then(|x| x.as_i64()).map(|id| (id, champ_texte(&v, "hash").to_string())));
            maillons_lus.push((i, line.as_str()));
            continue;
        };
        let (ledger_id, ledger_hash, sig) = (p.get("ledger_id").and_then(|x| x.as_i64()), p.get("ledger_hash").and_then(|x| x.as_str()), p.get("sig").and_then(|x| x.as_str()));
        let (Some(ledger_id), Some(ledger_hash), Some(sig)) = (ledger_id, ledger_hash, sig) else {
            return Err(format!("ligne {i}: point de contrôle incomplet (ledger_id, ledger_hash et sig requis)"));
        };
        points.push(crate::rbac::PointDeControleDuJournal { nom: format!("de la ligne {i}"), ledger_id, ledger_hash: ledger_hash.to_string(), sig: sig.to_string() });
    }
    let copie = verifier_des_lignes_numerotees(maillons_lus, expect_prev, &RECETTE_DU_JOURNAL_DE_CONTROLE)?;
    Ok((copie, crate::rbac::juger_l_ancrage_du_journal_de_controle(&maillons, &points, epinglee)))
}

/// `P10.7-r` — CE QUE `verify-control --export` REND : un code et UNE phrase. `0` = copie intègre ET ancrée par la clé
/// épinglée · `1` = copie compromise (rupture, ligne malformée, point de contrôle non signé ou discordant) · `2` =
/// AUCUN verdict d'ancrage (clé non épinglée, maillon de la copie sans son point de contrôle).
pub(crate) fn verdict_hors_ligne_de_la_copie_du_journal_de_controle(lines: &[String], expect_prev: &str, epinglee: Option<&[u8; 32]>) -> (i32, String) {
    match verifier_la_copie_ancree_du_journal_de_controle(lines, expect_prev, epinglee) {
        Err(e) => (1, format!("EXPORT COMPROMIS : {e}")),
        Ok((copie, ancrage)) => crate::rbac::phrase_de_l_ancrage(copie.maillons, &ancrage, "export OK", "EXPORT COMPROMIS"),
    }
}

/// VÉRIFICATION HORS LIGNE d'une copie exportée du registre des tenants — ce que `ledger-verify-export` exécute. Pour
/// chaque ligne retenue : `sha256(prev|ts|kind|detail) == hash` (intégrité du maillon) ET `prev_hash` == hachage de la
/// ligne retenue précédente (continuité de la chaîne DANS la copie). C'est la MÊME loi que `verify_run` : un tiers qui
/// tient une copie WORM détecte toute altération SANS accès à la base. `expect_prev` = hachage attendu AVANT la première
/// ligne (export incrémental : le `last_hash` du curseur ; export complet : "", l'origine). `P10.27-k` : une ligne
/// identique octet pour octet à une ligne déjà vérifiée est écartée et comptée (`copie_chainee`).
pub(crate) fn verifier_la_copie_du_registre(lines: &[String], expect_prev: &str) -> Result<CopieChaineeVerifiee, String> {
    let recette = RecetteDeChaine { texte_hache: texte_hache_du_registre, alteration: "hash altéré (recalcul != hash stocké)" };
    verifier_une_copie_chainee(lines, expect_prev, &recette)
}

/// Le nombre de maillons DISTINCTS d'une copie du registre qui se vérifie. Les répétitions exactes sont écartées sans
/// changer ce compte ; `verifier_la_copie_du_registre` les rend, et `ledger-verify-export` les DIT. Témoins seulement :
/// la sous-commande emploie `verdict_hors_ligne_de_la_copie_du_registre`, qui ne perd pas le compte des répétitions.
#[cfg(test)]
pub(crate) fn ledger_verify_export(lines: &[String], expect_prev: &str) -> Result<usize, String> {
    verifier_la_copie_du_registre(lines, expect_prev).map(|c| c.maillons)
}

/// `P10.27-k` — CE QUE `ledger-verify-export` REND : un code de sortie et UNE phrase, calculés ici pour que la phrase soit
/// éprouvée sans lancer le binaire (la sortie du processus, elle, est mesurée sur un processus par le témoin de
/// `commande_ledger_verify_export`). `0` = copie intègre, `1` = rupture nommée (« EXPORT COMPROMIS »). La phrase du cas
/// nominal — aucune répétition — est celle d'avant, octet pour octet. Une copie qui porte des répétitions exactes reste
/// intègre (`0`) ; la phrase les COMPTE et dit d'où elles viennent, pour qu'elles ne soient pas additionnées comme des
/// événements distincts.
pub(crate) fn verdict_hors_ligne_de_la_copie_du_registre(lines: &[String], expect_prev: &str) -> (i32, String) {
    match verifier_la_copie_du_registre(lines, expect_prev) {
        Err(e) => (1, format!("EXPORT COMPROMIS : {e}")),
        Ok(c) if c.lignes_repetees == 0 => (0, format!("export OK : {} entrées chaînées intègres (vérifié hors-ligne)", c.maillons)),
        Ok(c) => {
            let fin = if c.reprise_inachevee {
                " ; la copie se termine au milieu d'une reprise, avant d'avoir rejoint sa tête (écriture interrompue ou copie tronquée) — rien de ce qui a été vérifié n'y manque"
            } else {
                ""
            };
            (
                0,
                format!(
                    "export OK : {} entrées chaînées intègres (vérifié hors-ligne) ; {} ligne(s) RÉPÉTÉE(S) À L'IDENTIQUE écartée(s), en {} reprise(s) — copies exactes de lignes déjà vérifiées (tranche réécrite par un envoi dont le curseur n'a pas été validé, export relancé sur le même fichier, copies recouvrantes mises bout à bout) : ni des événements distincts, ni une altération{fin}",
                    c.maillons, c.lignes_repetees, c.reprises
                ),
            )
        }
    }
}

/// Écrit `lines` (JSONL) vers un sink APPEND-ONLY. Deux kinds sûrs et hors-réseau supportés ici (les sinks
/// réseau syslog/webhook sont un ajout mince, cf. report) : `file` (append au `target`, l'opérateur
/// synchronise ce fichier/dossier vers un object-store à object-lock = WORM) et `stdout`. Renvoie Err si
/// l'écriture échoue (l'appelant NE doit PAS avancer le curseur -> re-tentera la même tranche : at-least-once,
/// jamais de trou dans la copie WORM).
pub(crate) fn ledger_sink_write(kind: &str, target: &str, lines: &[String], confine_root: Option<&std::path::Path>) -> Result<(), String> {
    if lines.is_empty() {
        return Ok(());
    }
    let body = format!("{}\n", lines.join("\n"));
    match kind {
        "stdout" => {
            print!("{body}");
            use std::io::Write;
            std::io::stdout().flush().map_err(|e| e.to_string())
        }
        "file" => {
            use std::io::Write;
            if target.trim().is_empty() {
                return Err(REFUS_PUITS_CIBLE_VIDE.into());
            }
            // MEDIUN #59 : quand l'écriture vient du SINK WEB-configurable (`confine_root=Some`), la cible est
            // CONFINÉE à la racine d'export (canonicalisée, anti-`..`), l'ouverture est O_NOFOLLOW (jamais suivre
            // un lien substitué — anti-TOCTOU) et on RE-vérifie sur le FD ouvert que c'est un fichier RÉGULIER
            // (pas de FIFO/-device -> pas de hang/blocage/remplissage arbitraire). Le chemin CLI opérateur
            // (`confine_root=None`, shell de confiance) reste LIBRE, sauf la base vivante : `P10.33-w` (reste),
            // `refuser_une_cible_libre_sur_la_base_vivante`.
            let full: std::path::PathBuf = match confine_root {
                Some(root) => ledger_file_target_validate(root, target)?,
                None => {
                    refuser_une_cible_libre_sur_la_base_vivante(std::path::Path::new(target))?;
                    std::path::PathBuf::from(target)
                }
            };
            let mut oo = std::fs::OpenOptions::new();
            oo.create(true).append(true);
            if confine_root.is_some() {
                use std::os::unix::fs::OpenOptionsExt;
                oo.custom_flags(libc::O_NOFOLLOW);
            }
            let f = oo.open(&full).map_err(|e| format!("ouverture {}: {e}", full.display()))?;
            if confine_root.is_some() {
                let md = f.metadata().map_err(|e| format!("stat {}: {e}", full.display()))?;
                if !md.is_file() {
                    return Err(REFUS_PUITS_NON_REGULIER_A_L_OUVERTURE.into());
                }
            }
            let mut f = f;
            f.write_all(body.as_bytes()).map_err(|e| format!("écriture {}: {e}", full.display()))
        }
        other => Err(format!("sink kind non supporté: {other} (attendu: file|stdout)")),
    }
}

/// Racine d'export AUTORISÉE des sinks kind=`file` (#59) : `PLUME_LEDGER_EXPORT_DIR` si défini, sinon
/// `<répertoire de la base>/ledger-export`. Créée best-effort (doit exister pour canonicaliser). Confine
/// les écritures de ledger déclenchées par un admin WEB (rôle SOC) — jamais un chemin hôte arbitraire.
pub(crate) fn ledger_export_root(conf: &HashMap<String, String>) -> std::path::PathBuf {
    let dir = cfg(conf, "PLUME_LEDGER_EXPORT_DIR", "");
    let root = if !dir.trim().is_empty() {
        std::path::PathBuf::from(dir.trim())
    } else {
        let db = cfg(conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
        std::path::Path::new(&db).parent().unwrap_or_else(|| std::path::Path::new(".")).join("ledger-export")
    };
    let _ = std::fs::create_dir_all(&root);
    root
}

/// Valide qu'une cible de sink `file` est CONFINÉE dans `root` : le RÉPERTOIRE parent existe et se
/// canonicalise DANS la racine (résout `..`/liens du chemin), le nom de fichier est un composant simple, et —
/// s'il existe déjà — la cible n'est NI un lien symbolique NI un non-fichier-régulier. Renvoie le chemin
/// canonique complet, ou Err(message) si la cible ÉVADE la racine / est un lien / n'est pas régulière. Appelée
/// au CREATE (rejet précoce du sink) ET à l'écriture (défense en profondeur avec O_NOFOLLOW).
pub(crate) fn ledger_file_target_validate(root: &std::path::Path, target: &str) -> Result<std::path::PathBuf, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err(REFUS_PUITS_CIBLE_VIDE.into());
    }
    let root = root.canonicalize().map_err(|e| format!("racine d'export {} inaccessible: {e}", root.display()))?;
    let p = std::path::Path::new(target);
    let file_name = p.file_name().ok_or_else(|| REFUS_PUITS_NOM_DE_FICHIER_REQUIS.to_string())?;
    let parent = match p.parent() {
        Some(pp) if !pp.as_os_str().is_empty() => pp.to_path_buf(),
        _ => root.clone(),
    };
    let parent_canon = parent
        .canonicalize()
        .map_err(|e| format!("répertoire cible {} inaccessible: {e}", parent.display()))?;
    if !parent_canon.starts_with(&root) {
        return Err(format!("{REFUS_PUITS_HORS_DE_LA_RACINE} {}", root.display()));
    }
    let full = parent_canon.join(file_name);
    if let Ok(md) = std::fs::symlink_metadata(&full) {
        if md.file_type().is_symlink() {
            return Err(REFUS_PUITS_LIEN_SYMBOLIQUE.into());
        }
        if !md.is_file() {
            return Err(REFUS_PUITS_NON_REGULIER_EXISTANT.into());
        }
    }
    refuser_une_cible_sur_la_base_vivante(&parent_canon, file_name, &full)?;
    Ok(full)
}

/// `P10.29-l` — LES REFUS À TEXTE FIXE d'une cible de puits `file` : aucune partie variable, donc jamais la cible. Nommés
/// ici pour que le motif d'une écriture de copie ratée (`motif_de_l_ecriture_sans_cible`, au journal) les reconnaisse
/// sans liste recopiée qui dériverait.
pub(crate) const REFUS_PUITS_CIBLE_VIDE: &str = "sink file: target (chemin) vide";
pub(crate) const REFUS_PUITS_NOM_DE_FICHIER_REQUIS: &str = "target: nom de fichier requis (pas un répertoire)";
pub(crate) const REFUS_PUITS_LIEN_SYMBOLIQUE: &str = "target: lien symbolique refusé";
pub(crate) const REFUS_PUITS_NON_REGULIER_A_L_OUVERTURE: &str = "target: non-fichier-régulier refusé (FIFO/device/socket)";
pub(crate) const REFUS_PUITS_NON_REGULIER_EXISTANT: &str = "target: non-fichier-régulier refusé (FIFO/device/répertoire)";
pub(crate) const REFUS_PUITS_A_TEXTE_FIXE: [&str; 5] = [
    REFUS_PUITS_CIBLE_VIDE,
    REFUS_PUITS_NOM_DE_FICHIER_REQUIS,
    REFUS_PUITS_LIEN_SYMBOLIQUE,
    REFUS_PUITS_NON_REGULIER_A_L_OUVERTURE,
    REFUS_PUITS_NON_REGULIER_EXISTANT,
];
/// `P10.29-l` — début, FIXE, du refus d'une cible hors de la racine d'export (la suite nomme la racine).
pub(crate) const REFUS_PUITS_HORS_DE_LA_RACINE: &str = "target hors de la racine d'export autorisée";

/// `P10.33-w` — début de TOUTE phrase de refus d'une cible de puits `file` posée sur la base vivante.
pub(crate) const REFUS_PUITS_SUR_LA_BASE_VIVANTE: &str = "target: la base vivante n'est jamais une cible de puits";

/// `P10.33-w` — les fichiers d'une base SQLite : la base elle-même et ses compagnons, nommés par suffixe.
pub(crate) const SUFFIXES_DES_FICHIERS_DE_BASE: [&str; 4] = ["", "-wal", "-shm", "-journal"];

/// `P10.33-w` — UN PUITS `file` N'ÉCRIT JAMAIS DANS LA BASE VIVANTE. Une racine d'export posée sur le répertoire même
/// de la base laissait passer `plume.db` (fichier régulier dans la racine) : l'écriture ajoutait des lignes JSONL à la
/// fin du fichier SQLite, ou de son `-wal`. Refusés, pour la base de `PLUME_DB` et celle du plan de contrôle :
///  1. un NOM de fichier de base (la base, et la même suffixée `-wal`, `-shm`, `-journal`), dans quelque répertoire
///     que ce soit ;
///  2. une cible dont le répertoire (canonique) EST celui de la base — même chemin canonique, ou même (périphérique,
///     inode) par `stat` (montage lié). NE TIENT PAS PAR TÉMOIN : la moitié « même inode de répertoire » est
///     intestable sans droit de montage (un même chemin canonique a toujours le même inode, et un répertoire ne se lie
///     pas en dur) ; la retirer laisse tous les témoins verts. Gardée comme défense pour le montage lié ;
///  3. une cible existante qui est le MÊME fichier (périphérique, inode) qu'un fichier de base : un lien dur.
/// Tout se lit par chemins canoniques et `std::fs::metadata` (stat, aucun descripteur) : ouvrir un fichier de la base
/// vivante depuis le processus qui la tient lâcherait ses verrous POSIX (`P10.33-u`). Appelée par
/// `ledger_file_target_validate`, donc à la création du puits ET à chaque écriture confinée.
fn refuser_une_cible_sur_la_base_vivante(
    parent_canon: &std::path::Path,
    file_name: &std::ffi::OsStr,
    full: &std::path::Path,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let conf = load_config();
    let base = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
    let controle = crate::state::control_db_path(&conf, &base);
    let meme_inode = |a: &std::fs::Metadata, b: &std::fs::Metadata| a.dev() == b.dev() && a.ino() == b.ino();
    let cible = std::fs::symlink_metadata(full).ok();
    for chemin in [base.as_str(), controle.as_str()] {
        let chemin = std::path::Path::new(chemin);
        let Some(nom_de_base) = chemin.file_name() else { continue };
        let dossier = match chemin.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => std::path::Path::new("."),
        };
        for suffixe in SUFFIXES_DES_FICHIERS_DE_BASE {
            let mut nom = nom_de_base.to_os_string();
            nom.push(suffixe);
            if file_name == nom.as_os_str() {
                return Err(format!(
                    "{REFUS_PUITS_SUR_LA_BASE_VIVANTE} : le nom {} est celui d'un fichier de base ; nommer la cible autrement",
                    nom.to_string_lossy()
                ));
            }
        }
        let meme_repertoire = dossier.canonicalize().map(|d| d == parent_canon).unwrap_or(false)
            || matches!(
                (std::fs::metadata(dossier), std::fs::metadata(parent_canon)),
                (Ok(a), Ok(b)) if meme_inode(&a, &b)
            );
        if meme_repertoire {
            return Err(format!(
                "{REFUS_PUITS_SUR_LA_BASE_VIVANTE} : le répertoire {} est celui de la base ; poser la racine d'export ailleurs",
                parent_canon.display()
            ));
        }
        if let Some(cible) = cible.as_ref() {
            for suffixe in SUFFIXES_DES_FICHIERS_DE_BASE {
                let mut nom = nom_de_base.to_os_string();
                nom.push(suffixe);
                let lien_dur = std::fs::metadata(dossier.join(&nom)).map(|f| meme_inode(&f, cible)).unwrap_or(false);
                if lien_dur {
                    return Err(format!(
                        "{REFUS_PUITS_SUR_LA_BASE_VIVANTE} : la cible est le même fichier (lien dur) que {}",
                        nom.to_string_lossy()
                    ));
                }
            }
        }
    }
    Ok(())
}

/// `P10.33-w` (reste) — suite du refus d'une cible LIBRE (ligne de commande) déjà là : elle est, par `stat`, le même
/// fichier (périphérique, inode) qu'un fichier de base, nommé à la suite.
pub(crate) const CIBLE_LIBRE_EST_UN_FICHIER_DE_BASE: &str =
    "la cible de la ligne de commande est le même fichier (périphérique et inode, par chemin, lien dur ou lien symbolique) que";
/// `P10.33-w` (reste) — suite du refus d'une cible LIBRE pas encore là : la créer revient à créer, dans le répertoire de
/// la base, le fichier de base nommé à la suite (`-wal`, `-shm` ou `-journal` absents d'une base fermée).
pub(crate) const CIBLE_LIBRE_CREERAIT_UN_FICHIER_DE_BASE: &str =
    "la cible de la ligne de commande créerait, dans le répertoire de la base, le fichier de base";

/// Le chemin au bout des liens symboliques de `cible`, lus par `readlink` (aucun descripteur ouvert) ; s'arrête sur ce qui
/// n'est pas un lien (absent compris) et après 40 sauts (au-delà, l'ouverture rend elle-même `ELOOP`). Un lien PENDANT
/// vers un compagnon absent se juge ainsi sur ce que l'ouverture en création ferait naître.
fn cible_au_bout_des_liens(cible: &std::path::Path) -> std::path::PathBuf {
    let mut chemin = cible.to_path_buf();
    for _ in 0..40 {
        let Ok(md) = std::fs::symlink_metadata(&chemin) else { break };
        if !md.file_type().is_symlink() {
            break;
        }
        let Ok(destination) = std::fs::read_link(&chemin) else { break };
        chemin = if destination.is_absolute() {
            destination
        } else {
            chemin.parent().unwrap_or_else(|| std::path::Path::new(".")).join(destination)
        };
    }
    chemin
}

/// `P10.33-w` (reste) — LA CIBLE LIBRE DE `ledger-export --out` N'EST JAMAIS LA BASE VIVANTE. Le chemin de la ligne de
/// commande n'est pas confiné (shell de confiance) et ne l'est toujours pas : un chemin hors base reste accepté, y compris
/// dans le répertoire de la base. Refusés, pour la base de `PLUME_DB` et celle du plan de contrôle, chacune avec ses
/// compagnons `-wal`, `-shm`, `-journal` :
///  1. une cible DÉJÀ LÀ qui est le même fichier (périphérique, inode, par `stat` qui suit les liens) qu'un fichier de
///     base : la base nommée par son chemin, un lien dur, un lien symbolique, un montage lié ;
///  2. une cible PAS ENCORE LÀ (au bout de ses liens symboliques) qui porte le nom d'un fichier de base dans le
///     répertoire de la base (même périphérique et inode de répertoire) : l'ouverture en création ferait naître un `-wal`
///     ou un `-journal` de JSONL à côté de la base.
/// Aucune ouverture : `std::fs::metadata`, `symlink_metadata` et `read_link` seuls (`P10.33-u`). Le refus commence par
/// `REFUS_PUITS_SUR_LA_BASE_VIVANTE` ; `main` l'écrit sur stderr et sort en 2 (bras `ledger-export`).
fn refuser_une_cible_libre_sur_la_base_vivante(cible: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let conf = load_config();
    let base = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
    let controle = crate::state::control_db_path(&conf, &base);
    let meme_inode = |a: &std::fs::Metadata, b: &std::fs::Metadata| a.dev() == b.dev() && a.ino() == b.ino();
    let effective = cible_au_bout_des_liens(cible);
    let md_cible = std::fs::metadata(&effective).ok();
    let md_parent_de_la_cible = match effective.parent() {
        Some(d) if !d.as_os_str().is_empty() => std::fs::metadata(d).ok(),
        _ => std::fs::metadata(".").ok(),
    };
    for chemin in [base.as_str(), controle.as_str()] {
        let chemin = std::path::Path::new(chemin);
        let Some(nom_de_base) = chemin.file_name() else { continue };
        let dossier = match chemin.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => std::path::Path::new("."),
        };
        let md_dossier = std::fs::metadata(dossier).ok();
        for suffixe in SUFFIXES_DES_FICHIERS_DE_BASE {
            let mut nom = nom_de_base.to_os_string();
            nom.push(suffixe);
            let fichier = dossier.join(&nom);
            if let Some(md) = md_cible.as_ref() {
                if std::fs::metadata(&fichier).map(|f| meme_inode(&f, md)).unwrap_or(false) {
                    return Err(format!(
                        "{REFUS_PUITS_SUR_LA_BASE_VIVANTE} : {CIBLE_LIBRE_EST_UN_FICHIER_DE_BASE} {} ; écrire l'export ailleurs",
                        nom.to_string_lossy()
                    ));
                }
            } else if effective.file_name() == Some(nom.as_os_str())
                && matches!((md_parent_de_la_cible.as_ref(), md_dossier.as_ref()), (Some(a), Some(b)) if meme_inode(a, b))
            {
                return Err(format!(
                    "{REFUS_PUITS_SUR_LA_BASE_VIVANTE} : {CIBLE_LIBRE_CREERAIT_UN_FICHIER_DE_BASE} {} ; écrire l'export ailleurs",
                    nom.to_string_lossy()
                ));
            }
        }
    }
    Ok(())
}

// =====================================================================================
// 3. RÔLES COMPOSABLES — catalogue résolu (plafond=base, deny soustractif, default-deny)
// =====================================================================================

/// Un rôle custom résolu : plafond = `base` (∈ viewer/editor/admin), capacités RETIRÉES = `deny`.
#[derive(Clone, Debug)]
pub(crate) struct RoleDef {
    pub base: String,
    pub deny: Vec<String>,
}

/// Perms SOUSTRACTIBLES connues (enum FERMÉ). Un deny_perm HORS de cet ensemble est IGNORÉ au chargement
/// (fail-safe : jamais un flag muet qui « ouvrirait » quelque chose — le deny ne peut que retirer).
pub(crate) const KNOWN_DENY_PERMS: &[&str] =
    &["raw_sql", "arm_response", "ledger_export", "manage_users", "purge_events"];

/// Cache process-global du catalogue de rôles custom (control-plane). VIDE par défaut (mode 0 / aucun rôle
/// custom) -> tous les chemins RBAC restent byte-identiques. Rempli au boot (mode 1) + rafraîchi sur mutation.
pub(crate) static CUSTOM_ROLES: std::sync::OnceLock<Mutex<HashMap<String, RoleDef>>> = std::sync::OnceLock::new();
pub(crate) fn custom_roles_cell() -> &'static Mutex<HashMap<String, RoleDef>> {
    CUSTOM_ROLES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Un nom EST-il un rôle de base intégré ? (court-circuit : jamais résolu comme custom.)
/// #39 CORRECTIVE : `client` (rôle client-read API, rank-0 masqué, confiné aux routes client-read par
/// rbac_gate) est RÉSERVÉ ici -> custom_role_lookup("client")=None -> role_create/grant_set/valid_grant_role
/// REJETTENT le nom (impossible de définir/octroyer un rôle nommé `client` qui hériterait viewer/editor et
/// contournerait le confinement via le pipeline normal SSO/Basic). Ferme la collision de nom (couche a/2).
pub(crate) fn is_builtin_role(role: &str) -> bool {
    matches!(role, "admin" | "editor" | "viewer" | "agent" | "client")
}

/// (control-plane) Recharge le catalogue de rôles custom depuis `role_def`. base_role validé (∈ viewer/
/// editor/admin, sinon la ligne est ÉCARTÉE = fail-safe : un base invalide ne devient jamais un accès) ;
/// deny_perms filtré sur KNOWN_DENY_PERMS. Un nom qui collisionne un rôle de base est ÉCARTÉ (jamais
/// redéfinir admin/editor/viewer/agent). Idempotent, appelable à chaud.
pub(crate) fn reload_custom_roles(cp: &ControlPlane) {
    let mut map: HashMap<String, RoleDef> = HashMap::new();
    let mut raw: Vec<(String, String, String)> = Vec::new();
    let conn = cp.conn.lock();
    if let Ok(mut st) = conn.prepare("SELECT name, base_role, deny_perms FROM role_def") {
        if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))) {
            for row in rows.flatten() {
                raw.push(row);
            }
        }
    }
    drop(conn);
    for (name, base, deny_csv) in raw {
        if is_builtin_role(&name) || !matches!(base.as_str(), "admin" | "editor" | "viewer") {
            continue; // fail-safe : jamais redéfinir un rôle de base ni admettre un base invalide.
        }
        let deny: Vec<String> = deny_csv
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| KNOWN_DENY_PERMS.contains(&s.as_str()))
            .collect();
        map.insert(name, RoleDef { base, deny });
    }
    *custom_roles_cell().lock() = map;
}

/// Résout un rôle custom -> sa définition (base + deny). None pour un rôle de base OU un catalogue vide OU
/// un nom inconnu. (Un nom inconnu NON-base est traité par effective_base_role -> "" = deny.)
pub(crate) fn custom_role_lookup(role: &str) -> Option<RoleDef> {
    if is_builtin_role(role) {
        return None;
    }
    custom_roles_cell().lock().get(role).cloned()
}

/// Rôle de BASE effectif d'un nom de rôle (le PLAFOND RBAC) : rôle intégré -> lui-même ; rôle custom défini
/// -> son base_role ; nom INCONNU (ni base, ni custom défini) -> "" (rang 0 -> DEFAULT-DENY). C'est le seul
/// point où un nom devient une autorité : jamais au-dessus de sa base.
pub(crate) fn effective_base_role(role: &str) -> String {
    if is_builtin_role(role) {
        return role.to_string();
    }
    match custom_role_lookup(role) {
        Some(rd) => rd.base,
        None => String::new(), // inconnu -> aucune autorité (fail-closed)
    }
}

/// Un rôle (custom) RETIRE-t-il la permission `perm` ? Rôle de base -> jamais (pas de deny). Rôle custom ->
/// perm ∈ son deny-set. Nom inconnu -> true par prudence (il n'a de toute façon aucune base -> déjà refusé).
pub(crate) fn role_perm_denied(role: &str, perm: &str) -> bool {
    if is_builtin_role(role) {
        return false;
    }
    match custom_role_lookup(role) {
        Some(rd) => rd.deny.iter().any(|p| p == perm),
        None => true,
    }
}

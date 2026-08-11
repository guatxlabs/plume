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
//! CE QU'ELLE NE PERTURBE PAS. Processus SÉPARÉ, connexion SÉPARÉE ouverte en lecture seule : en WAL un
//! lecteur ne prend PAS le verrou d'écriture et ne bloque pas l'ingest (même posture que `db-stats`, qui
//! tourne déjà en production). Elle ne prend jamais `db.lock()` : ce mutex appartient au PROCESSUS daemon,
//! il n'existe pas ici.
//!
//! CE QU'ELLE NE MESURE PAS, ÉCRIT POUR ÊTRE OPPOSABLE :
//!   * **sa connexion n'est pas CELLE du daemon** : cache de pages neuf, pas de WAL chaud accumulé par
//!     l'ingest, cache de fichiers de l'OS dans un autre état. Une durée mesurée ici dit le PLAN et
//!     l'ORDRE DE GRANDEUR, pas la milliseconde du tick horaire ;
//!   * elle ne mesure **aucune contention** : la passe réelle tient le verrou writer pendant la
//!     découverte, ce que la sonde ne peut pas imiter sans devenir intrusive ;
//!   * elle n'exécute NI la phase 2 (le `DELETE` chunké) NI l'écriture Parquet — elles ÉCRIVENT ;
//!   * elle mesure le PREMIER candidat retenu, pas les N que la passe traiterait : les énoncés par-jour
//!     se paient une fois PAR JOUR, et le rapport dit combien de jours seraient traités ;
//!   * CHAQUE ÉNONCÉ N'EST EXÉCUTÉ QU'UNE FOIS. La sonde a besoin du RÉSULTAT de deux d'entre eux (la
//!     découverte, pour la liste des candidats ; le snapshot, pour le `max_id` qui borne la page) : elle
//!     les RÉCOLTE PENDANT la mesure, plafonnés (`RECOLTE_MAX`), au lieu de les rejouer — les rejouer
//!     aurait fait payer DEUX FOIS les 17-22 s en production, sur un outil dont tout l'argument est de ne
//!     pas déranger. Quand la récolte est tronquée, le COMPTE reste exact et le rapport le dit.

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
    let _ = conn.execute_batch(crate::sqlite_plafond::pragmas_memoire());
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
pub(super) struct Mesure {
    pub(super) plan: Vec<String>,
    /// Durée de la COMPILATION du plan : un plan coûteux à compiler ne se voit nulle part ailleurs.
    /// NOMMÉ `compilation_ms` ET PAS `prepare_ms` : les noms `prepare_ms`/`exec_ms`/`server_ms`/
    /// `sem_wait_ms`/`db_lock_wait_ms` sont RÉSERVÉS à `query_timing`, qui est le seul auteur du
    /// découpage du temps d'une REQUÊTE SERVIE (garde `only_query_timings_publishes_the_time_split`).
    /// Ce qu'on mesure ici n'est pas une requête servie, et lui emprunter ses noms rendrait les deux
    /// familles de chiffres confondables — exactement le défaut que cette garde a fermé.
    pub(super) compilation_ms: f64,
    /// Durée de l'EXÉCUTION complète (premier `step` -> dernière ligne consommée).
    pub(super) execution_ms: f64,
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
    let execution_ms = t_execution.elapsed().as_secs_f64() * 1000.0;
    use rusqlite::StatementStatus as S;
    Ok((
        Mesure {
            plan,
            compilation_ms,
            execution_ms,
            lignes,
            balayage: i64::from(st.get_status(S::FullscanStep)),
            tris: i64::from(st.get_status(S::Sort)),
            pas_de_machine: i64::from(st.get_status(S::VmStep)),
        },
        recoltees,
    ))
}

/// LE PLAN SEUL, SANS EXÉCUTION — pour un énoncé que la passe N'EXÉCUTE PAS dans l'état actuel de la
/// configuration. Le montrer sans le chronométrer est le seul rendu honnête : une durée facturerait à la
/// passe un travail qu'elle ne fait pas. Les compteurs valent `-1` = « non mesuré », jamais `0`.
fn plan_seul(conn: &Connection, e: &Enonce) -> Result<Mesure, String> {
    Ok(Mesure {
        plan: plan_de(conn, e)?,
        compilation_ms: 0.0,
        execution_ms: 0.0,
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
            if e.execute_par_la_passe {
                let _ = writeln!(
                    out,
                    "   mesuré  : compilation {:.1} ms · exécution {:.1} ms · {} ligne(s) rendue(s)",
                    m.compilation_ms, m.execution_ms, m.lignes
                );
                let _ = writeln!(
                    out,
                    "   travail : balayage={} tris={} pas_de_machine={}",
                    m.balayage, m.tris, m.pas_de_machine
                );
            } else {
                let _ = writeln!(
                    out,
                    "   NON EXÉCUTÉ PAR LA PASSE dans cette configuration -> plan montré, durée NON \
                     mesurée (la facturer serait un chiffre faux)"
                );
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

    // ---- Les énoncés SANS candidat, dans l'ordre de la passe. ----
    // La découverte est chronométrée UNE SEULE FOIS et sa récolte (plafonnée) sert à choisir le candidat :
    // la rejouer aurait fait payer deux fois les 17-22 s qu'on est venu mesurer.
    let mut candidats: Vec<(String, i64)> = Vec::new();
    let mut decouverts = 0i64;
    for e in enonces_sans_candidat(&bande, n, retention_days) {
        if !e.execute_par_la_passe {
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

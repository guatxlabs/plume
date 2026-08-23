//! Moteur de règles de détection (P4) + CRUD règles/parseurs : comparateur `cmp_op`, compilation
//! `rule_sql`/`eval_value`, ordonnanceur `run_due_rules`, normalisation MITRE `norm_mitre`, garde
//! SQL brut `raw_sql_allowed`, validation `validate_detection_content`, suppression gérée
//! `delete_managed_row*`, CRUD règles/parseurs et tests (`rule_test`/`rule_test_adhoc`/`parser_test`/
//! `parser_reparse`). Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;
use crate::detection_aveugle::AbandonDEvaluation;

// ---------- moteur de règles de détection (P4) ----------
pub(crate) fn cmp_op(a: f64, op: &str, b: f64) -> bool {
    match op {
        ">" => a > b, ">=" => a >= b, "<" => a < b, "<=" => a <= b,
        "==" | "=" => (a - b).abs() < 1e-9, "!=" => (a - b).abs() >= 1e-9,
        _ => false,
    }
}
/// COMPILATION D'UNE REQUÊTE DE RÈGLE — chemin SYSTÈME (ordonnanceur / validation / overlays).
///
/// ⚠️ AUCUN MASQUE. Réservé aux chemins qui n'ont PAS d'appelant : `run_due_rules`, `run_advanced_rules`,
/// `run_playbooks`, `run_risk_rules`, `eval_correlation`, la validation de contenu et l'import Sigma. Une
/// surface HTTP qui compile la requête d'un UTILISATEUR et lui RENVOIE le résultat NE DOIT PAS passer ici :
/// elle passe par `rule_sql_for_caller` (qui exige `AuthUser` et applique le masque #45). Cette séparation
/// est DÉFENDUE par la garde statique `sec_ff_no_unmasked_compile_in_caller_scoped_surfaces`.
pub(crate) fn rule_sql(query: &str, is_soql: bool, window_s: i64) -> Result<String, String> {
    // Masque VIDE = chemin système. `soql_to_sql_masked_x` court-circuite sur un jeu vide et retombe
    // EXACTEMENT sur `soql_to_sql_x` (cf. `EventStore::soql_to_sql_masked`) -> SQL byte-identique.
    rule_sql_masked(query, is_soql, window_s, &guatx_core::soql::FieldMaskSet::new())
}
/// Corps PARTAGÉ (unique) de la compilation d'une requête de règle : la SEULE variable est le jeu de
/// masques. Toute porte de compilation de règle passe ici -> impossible d'avoir deux sémantiques de fenêtre
/// ou de placeholder entre le chemin système et le chemin appelant.
fn rule_sql_masked(query: &str, is_soql: bool, window_s: i64, masks: &guatx_core::soql::FieldMaskSet) -> Result<String, String> {
    let from = if window_s > 0 { now() - window_s } else { 0 };
    // SÉCURITÉ — AUCUNE exclusion self/opérateur sur le chemin DÉTECTION : les règles doivent TOUT
    // voir, y compris une attaque venant de l'IP opérateur (machine opérateur compromise). On NE
    // substitue donc PAS `__OPERATOR_EXCL__` / `__SELF_EXCL__` ici (cf. compile_panel_sql pour les
    // PANNEAUX d'affichage seuls). Un éventuel placeholder résiduel dans une règle deviendrait du SQL
    // invalide -> visible au test/PREPARE, jamais un angle mort silencieux.
    // FILTRE ENVIRONNEMENT (#2d) : TOUJOURS None ici — la DÉTECTION est tenant-wide (D7) : une règle
    // s'évalue sur TOUS les environnements du tenant (une attaque sur staging doit alerter). Jamais d'env.
    if is_soql { soql_to_sql_masked_x(query, from, 0, None, masks) } else { Ok(query.replace("__FROM__", &from.to_string())) }
}

/// #45 — UNIQUE PORTE DE COMPILATION D'UNE REQUÊTE DE RÈGLE POUR UN APPELANT IDENTIFIÉ.
///
/// POURQUOI ELLE EXISTE (et pourquoi elle prend `st`+`au` et non un `FieldMaskSet` déjà résolu) : les
/// surfaces de TEST / DRY-RUN de détection (`/api/rule-test`, `/api/rules/:id/test`,
/// `/api/playbooks/:id/test`) sont EDITOR+ et RENVOIENT le résultat de la requête à l'appelant. Compilées
/// par la porte SYSTÈME (`rule_sql`, sans masque), elles étaient un ORACLE : `search src_ip=10.0.0.6 |
/// stats count` répondait `value=2` là où `search src_ip=9.9.9.9` répondait `value=0` — un bit de la valeur
/// d'un champ que le rôle ne peut PAS voir, à volonté (et pour un playbook, la valeur EN CLAIR dans
/// `targets`). C'est la famille exacte de l'incident « un viewer exfiltrait les hash par du SQL brut ».
/// La garde n'est donc PAS « ajouter search_mask_guard sur /api/rule-test » : c'est de rendre le masque
/// INSÉPARABLE de la compilation quand un appelant existe. `effective_masks` est résolu ICI, jamais par le
/// handler -> une surface ne peut pas l'oublier : soit elle a un `AuthUser` et passe par cette porte, soit
/// elle n'a pas d'appelant et n'est pas une surface d'appelant.
///
/// MODE 0 / aucun field-filter -> `masks` VIDE -> SQL BYTE-IDENTIQUE à `rule_sql` (invariant prouvé par
/// `sec_ff_caller_compile_is_byte_identical_in_mode0`).
///
/// SQL BRUT (`is_soql=false`) : opaque, le masque est INJECTABLE nulle part et la surface ne renvoie qu'un
/// scalaire (un masquage post-requête n'aurait aucun sens). Dès qu'un masque est actif pour l'appelant ->
/// REFUS fail-closed. Masque vide -> comportement inchangé (le seul cas en mode 0).
pub(crate) fn rule_sql_for_caller(st: &AppState, au: &AuthUser, query: &str, is_soql: bool, window_s: i64) -> Result<String, String> {
    let masks = effective_masks(&req_db_path(st, au), &au.role, &au.tenant, au.env_filter());
    if !is_soql && !masks.is_empty() {
        return Err("dry-run d'une requête SQL BRUTE interdit : un field-filter est actif pour votre rôle et le masque ne peut pas être appliqué à du SQL opaque (utilisez GXQL)".into());
    }
    rule_sql_masked(query, is_soql, window_s, &masks)
}

/// #45 — GARDE-ORACLE des surfaces de DRY-RUN qui n'ont PAS de porte de compilation propre : le GXQL y est
/// compilé DANS l'évaluateur PARTAGÉ avec l'ordonnanceur (`eval_correlation`, `eval_baseline`), qui doit
/// rester tenant-wide et NON masqué (D7 : une corrélation ne doit pas devenir aveugle parce qu'un rôle est
/// restreint). On ne peut donc pas y injecter le masque sans dégrader la DÉTECTION ; on garde la SURFACE :
///   (1) chaque requête fournie doit COMPILER SOUS LE MASQUE de l'appelant -> tout prédicat sur un champ
///       masqué est rejeté par le cœur (fin de l'oracle par nombre de lignes) ;
///   (2) tout champ que la surface RENVOIE EN CLAIR (clé de corrélation, champ d'entité/valeur d'une
///       baseline) doit être NON masqué pour l'appelant -> fin de l'exfiltration directe des valeurs.
/// VIDE (mode 0 / admin sans règle) -> `Ok(())` immédiat, AUCUN changement de comportement.
pub(crate) fn caller_dryrun_guard(st: &AppState, au: &AuthUser, queries: &[&str], returned_fields: &[&str], window_s: i64) -> Result<(), String> {
    let masks = effective_masks(&req_db_path(st, au), &au.role, &au.tenant, au.env_filter());
    if masks.is_empty() {
        return Ok(()); // mode 0 : chemin STRICTEMENT inchangé
    }
    for f in returned_fields.iter().filter(|f| !f.is_empty()) {
        if masks.get(f).is_some() {
            return Err(format!("dry-run interdit : le champ « {f} » est RENVOYÉ par cette surface et il est masqué pour votre rôle (un champ que vous ne pouvez pas voir ne peut pas être restitué ni sondé)"));
        }
    }
    for q in queries {
        rule_sql_masked(q, true, window_s, &masks)?;
    }
    Ok(())
}
// ======================================================================================
// LE LIEN DE RECHERCHE D'UNE ALERTE DE RÈGLE (P11.1-a) — UNE seule construction, dérivée de la
// requête de la règle et de sa fenêtre d'évaluation.
// ======================================================================================

/// Ce qu'une alerte de règle ouvre dans l'Explore : la requête DONT la règle a agrégé le résultat, sur
/// la fenêtre EXACTE sur laquelle elle l'a fait. Le compte de l'alerte se reproduit en exécutant ce lien.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LienDeRecherche {
    pub(crate) query: String,
    pub(crate) is_soql: bool,
    pub(crate) from: i64,
    pub(crate) to: i64,
}

impl LienDeRecherche {
    pub(crate) fn to_json(&self) -> Value {
        json!({ "query": self.query, "is_soql": self.is_soql, "from": self.from, "to": self.to })
    }
}

/// Un étage `stats` qui REND UN SCALAIRE : une ou plusieurs agrégations, sans `by`. C'est l'étage que
/// le moteur réduit à une valeur (`eval_value_budget` lit la dernière colonne de la première ligne) ;
/// le RETIRER rend les lignes sur lesquelles cette valeur a été calculée.
fn etage_stats_scalaire(etage: &str) -> bool {
    let mut toks = etage.split_whitespace();
    let Some(verbe) = toks.next() else { return false };
    if !verbe.eq_ignore_ascii_case("stats") {
        return false;
    }
    let reste: Vec<&str> = toks.collect();
    !reste.is_empty() && !reste.iter().any(|t| t.eq_ignore_ascii_case("by"))
}

/// Le lien d'une alerte de règle. `query`/`is_soql` = la requête TELLE QU'ELLE A COMPTÉ (recopiée dans
/// `alert.detail` à la levée) ; `window_s` = la fenêtre de la règle ; `ts` = l'instant de l'évaluation
/// qui a levé ou rafraîchi l'alerte (`alert.ts`).
///
/// FENÊTRE. `rule_sql` évalue sur `[ts - window_s, +∞)` à l'instant `ts` : le lien borne donc
/// `[ts - window_s, ts]` (bornes incluses dans le SQL émis), sans marge — une marge « pour voir
/// l'événement de bord » rendait le lien PLUS LARGE que le compte, par construction, sur toutes les règles.
///
/// REQUÊTE. GXQL : on retire le DERNIER étage s'il est un `stats` scalaire (`| stats count`,
/// `| stats max(value)`) ; ce qui reste est l'ensemble que cet étage a réduit — les événements appariés
/// pour `search … | stats count`, les GROUPES retenus pour `search … | stats dc(x) by k | where … |
/// stats count` (l'ancien lien ne gardait que la tête `search …` : il rendait tous les événements, pas
/// les groupes comptés). Sans étage scalaire terminal, la requête entière est le lien : la valeur de
/// l'alerte est la dernière colonne de sa première ligne, et c'est ce résultat qu'on montre.
/// SQL BRUT : opaque, aucun étage à isoler — le lien est le SQL lui-même, fenêtre substituée ; la porte
/// « SQL brut = admin » de l'Explore s'applique telle quelle.
pub(crate) fn lien_de_recherche_de_regle(query: &str, is_soql: bool, window_s: i64, ts: i64) -> LienDeRecherche {
    let from = if window_s > 0 { ts - window_s } else { 0 };
    let to = ts;
    if !is_soql {
        let q = query.replace("__FROM__", &from.to_string()).replace("__TO__", &to.to_string());
        return LienDeRecherche { query: q, is_soql: false, from, to };
    }
    let mut etages = guatx_core::soql::soql_split_pipes(query);
    let q = if etages.len() >= 2 && etages.last().map(|e| etage_stats_scalaire(e)).unwrap_or(false) {
        etages.pop();
        etages.join(" | ")
    } else {
        query.trim().to_string()
    };
    LienDeRecherche { query: q, is_soql: true, from, to }
}

/// Exécute la requête et renvoie la dernière colonne de la 1re ligne comme nombre. DURCISSEMENT 3b —
/// l'ÉVALUATION passe par run_query -> connexion du pool LECTURE SEULE (SQLITE_OPEN_READ_ONLY +
/// `PRAGMA query_only=ON`, cf read_conn_open) + garde `stmt.readonly()` dans run_query_ex : une règle ne
/// peut donc QUE lire (jamais muter/ATTACH/écrire), même en SQL brut. Idem pour run_playbooks (run_query).
pub(crate) fn eval_value(db_path: &str, sql: &str) -> Option<f64> {
    // budget AUTO (5 s) — conservé pour les appelants historiques (rule_test / sigma e2e).
    eval_value_budget(db_path, sql, query_budget_ms())
}
/// Comme `eval_value` mais avec un budget-temps EXPLICITE. `None` distingue TROIS cas indissociables du
/// point de vue scalaire mais tous des ÉCHECS d'évaluation : requête en erreur (SQL invalide / colonne
/// absente / UDF regexp qui rejette un motif > 512 c.), watchdog de budget dépassé (`run_query_ex` renvoie
/// Err « interrompue »), ou résultat non numérique. Le CHEMIN DÉTECTION (run_due_rules) l'appelle avec le
/// budget INTERACTIF (défaut 60 s) et NON le budget auto 5 s : une corrélation brute
/// `search source=web status>=500 | stats count by src_ip | where count>10 | stats count`, évaluée EN
/// PARALLÈLE avec toutes les autres règles dues sur une base SQLCipher volumineuse, peut franchir 5 s ->
/// watchdog -> Err -> None. run_due_rules NE convertit PLUS ce None en 0.0 « tout va bien » (cf. la garde
/// d'échec) : sinon une erreur/timeout transitoire RÉSOUDRAIT une détection réelle = angle mort SILENCIEUX
/// que le dry-run (rule_test, isolé, qui SURFACE l'erreur « évaluation échouée ») ne montrait jamais.
/// La projection en `Option` de `detection_aveugle::evaluer_valeur_de_regle`, pour les appelants qui
/// n'ont pas d'usage de la CAUSE de l'abandon. L'ordonnanceur des règles simples, lui, la conserve.
pub(crate) fn eval_value_budget(db_path: &str, sql: &str, budget_ms: u64) -> Option<f64> {
    crate::detection_aveugle::evaluer_valeur_de_regle(db_path, sql, budget_ms).ok()
}
/// CONCURRENCE ORDONNANCEUR (#detect) — nombre MAX de règles évaluées EN PARALLÈLE par `run_due_rules`.
/// Miroir de la discipline `PLUME_QUERY_CONCURRENCY` (=3) : chaque éval déchiffre SQLCipher sur sa propre
/// connexion read-only ; sur le pod 2 cœurs / 2 Gio, lancer TOUTES les règles dues d'un coup (~35 threads)
/// sature le CPU -> les corrélations lourdes (21/22 : `stats count by src_ip | where …`) franchissent le
/// budget -> Err -> éval en échec. Borner à N règle CE dépassement à la RACINE (les scans lourds finissent
/// DANS le budget et TIRENT) au lieu de ne compter que sur un budget plus large. Défaut 3, env
/// `PLUME_DETECT_CONCURRENCY` (>=1). `PLUME_QUERY_CONCURRENCY` n'est PAS réutilisé : l'ordonnanceur n'emprunte
/// pas le sémaphore async du chemin interactif (fil dédié, hors runtime tokio) -> réglage indépendant.
pub(crate) fn detect_concurrency() -> usize {
    std::env::var("PLUME_DETECT_CONCURRENCY").ok().and_then(|v| v.parse().ok()).filter(|&n: &usize| n > 0).unwrap_or(3)
}
/// S7 — L'IMPUTATION DES RÈGLES QUI TIRENT, en parallélisme BORNÉ et HORS VERROU D'ÉCRITURE.
///
/// UNE requête de plus par TIR (jamais par évaluation) : le jeu est restreint à `qui_tire`, qui vaut
/// l'ensemble VIDE dans le cas nominal d'un balayage où rien ne franchit son seuil — l'ordonnanceur ne
/// paie donc rien tant qu'il n'y a rien à imputer. Le tranchage réutilise `detect_concurrency` (le MÊME
/// plafond que la phase 2, pas un second réglage à tenir) : au plus N connexions de lecture en vol.
/// Un worker EMPOISONNÉ est simplement ABSENT de la carte -> l'appelant pose l'inconnu NOMMÉ, jamais un
/// silence. `due` est la liste telle que la phase 1 l'a lue : c'est elle qui porte `is_soql` et
/// `window_s`, que la phase 2 ne recopie pas.
type RegleDue = (i64, String, String, bool, String, f64, i64, i64, String);
fn imputations_des_regles_qui_tirent(
    db_path: &str,
    due: &[RegleDue],
    qui_tire: &std::collections::HashSet<i64>,
    cc: usize,
) -> HashMap<i64, String> {
    let mut out: HashMap<i64, String> = HashMap::new();
    if qui_tire.is_empty() {
        return out;
    }
    let tirs: Vec<&RegleDue> = due.iter().filter(|d| qui_tire.contains(&d.0)).collect();
    for chunk in tirs.chunks(cc.max(1)) {
        let part: Vec<(i64, String)> = std::thread::scope(|s| {
            chunk
                .iter()
                .map(|(id, _name, query, is_soql, _op, _th, _sev, window_s, _mitre)| {
                    s.spawn(move || (*id, imputer_alerte_de_regle(db_path, query, *is_soql, *window_s)))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .filter_map(|h| h.join().ok())
                .collect()
        });
        out.extend(part);
    }
    out
}

/// Évalue les règles dues (enabled + intervalle écoulé) -> alerte si le seuil est franchi.
///
/// REND SON BILAN (`P4.1-r`) : `Illisible` si la liste des règles dues n'a pas pu être lue — le tick
/// est alors AVEUGLE et le planificateur le publie, au lieu de marquer un tick « vert » qui n'a rien
/// évalué ; `Lue(n)` sinon, `n` étant le nombre de règles dues ABANDONNÉES (ligne indécodable,
/// compilation refusée, évaluation en échec). Chacune est re-tentée au prochain intervalle, comme
/// avant ; ce qui change est qu'elle est comptée — et, depuis `P3.9-a`, CONSIGNÉE PAR RÈGLE avec sa
/// cause (`detection_aveugle`) : au seuil dérivé de son intervalle, une règle abandonnée à répétition
/// lève une alerte de cécité, résolue à sa première évaluation réussie.
pub(crate) fn run_due_rules(db: &Arc<Mutex<Connection>>, db_path: &str) -> crate::bilan_de_tick::BilanDeTick {
    let now_ts = now();
    let mut abandonnees = 0u32;
    // mitre porté en queue du tuple -> hérité par l'alerte (mesure de couverture de détection, purple-team)
    let due: Vec<RegleDue> = {
        let conn = db.lock();
        // #24 (RBA) : les règles en MODE RISK (risk_score>0) sont exclues ICI — elles ne lèvent PAS d'alerte
        // scalaire par tir ; elles CONTRIBUENT du risque via run_risk_rules (« instead of »). COALESCE défensif
        // (colonne ADDITIVE v80, défaut 0). MODE 0 : aucune règle risk -> risk_score=0 partout -> sélection
        // STRICTEMENT IDENTIQUE à l'historique (le prédicat est vrai pour toutes les règles normales).
        // #48/#53 : les règles « avancées » (fenêtre de suppression / throttle-by-field / per-result) sont
        // EXCLUES ICI et traitées par `run_advanced_rules` (isolé, comme les règles risk `risk_score>0`). En
        // mode 0 ces colonnes valent 0/'' -> le prédicat est TOUJOURS vrai -> sélection STRICTEMENT identique
        // à l'historique (aucune règle avancée -> byte-identique).
        let mut stmt = match conn.prepare(
            "SELECT id,name,query,is_soql,op,threshold,severity,window_s,COALESCE(mitre,'') FROM rule \
             WHERE enabled=1 AND COALESCE(risk_score,0)=0 \
               AND COALESCE(suppress_window_s,0)=0 AND COALESCE(throttle_field,'')='' AND COALESCE(per_result,0)=0 \
               AND (last_run IS NULL OR ?1 - last_run >= interval_s)",
        ) {
            Ok(s) => s,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("règles", &e),
        };
        let rows = match stmt.query_map(params![now_ts], |r| {
            Ok((
                r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)? != 0,
                r.get::<_, String>(4)?, r.get::<_, f64>(5)?, r.get::<_, i64>(6)?, r.get::<_, i64>(7)?, r.get::<_, String>(8)?,
            ))
        }) {
            Ok(r) => r,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("règles", &e),
        };
        // Une ligne qui ne se décode pas est une règle qui ne sera PAS évaluée ce tick : comptée, jamais
        // sautée en silence (`.flatten()` la faisait disparaître sans même avancer `last_run`).
        let mut due = Vec::new();
        for r in rows {
            match r {
                Ok(x) => due.push(x),
                Err(_) => abandonnees += 1,
            }
        }
        due
    };
    // Phase 2 : évalue les règles dues en parallélisme BORNÉ (chaque eval = sa propre connexion lecture, WAL).
    // BACKPRESSURE (#detect) : au lieu de spawn N=len(due) threads d'un coup (~35 déchiffrements SQLCipher
    // concurrents qui saturaient les 2 cœurs -> corrélations lourdes hors budget -> Err -> angle mort), on
    // traite par TRANCHES de `detect_concurrency()` (défaut 3, miroir de query_sem) : au plus N évals en vol.
    // Le résultat est indépendant de l'ordre/tranchage (phase 3 écrit par id de règle) -> sémantique préservée.
    let cc = detect_concurrency();
    // Le VERDICT d'une évaluation : la valeur, ou l'abandon AVEC SA CAUSE (`P3.9-a`). Un seul `None`
    // fondait erreur de requête, budget dépassé, cellule non numérique et panique du fil ; la cause
    // est désormais conservée jusqu'à la phase 3, qui la consigne par règle.
    let mut results: Vec<(i64, String, String, f64, i64, i64, String, String, Result<f64, AbandonDEvaluation>)> =
        Vec::with_capacity(due.len());
    for chunk in due.chunks(cc) {
        let chunk_res: Vec<_> = std::thread::scope(|s| {
            let fils: Vec<_> = chunk.iter()
                .map(|(id, name, query, is_soql, op, threshold, severity, window_s, mitre)| {
                    s.spawn(move || match rule_sql(query, *is_soql, *window_s) {
                        // BUDGET INTERACTIF (pas le budget auto 5 s) : la détection est un balayage de FOND,
                        // hors lock d'écriture, sur sa propre connexion read-only -> tolère un scan brut de
                        // corrélation plus long. Le budget 5 s coupait ces scans sous charge parallèle -> None -> 0.0.
                        // succès -> valeur RÉELLE (comparée au seuil en phase 3). Un 0 GÉNUINE (la requête a
                        // tourné, agrégat=0) est un Ok(0.0) -> résout normalement. ÉCHEC D'ÉVAL (erreur SQL /
                        // watchdog budget / non-numérique) : Err(cause). On NE fabrique PAS un 0.0 « tout va
                        // bien » : la phase 3 re-planifie (re-tentera au prochain intervalle) SANS écrire
                        // last_value=0.0 NI résoudre une alerte ouverte, et CONSIGNE l'abandon par règle.
                        Ok(sql) => (*id, name.clone(), op.clone(), *threshold, *severity, *window_s, query.clone(), mitre.clone(),
                                    crate::detection_aveugle::evaluer_valeur_de_regle(db_path, &sql, query_budget_interactive_ms())),
                        Err(e) => (*id, name.clone(), op.clone(), *threshold, *severity, *window_s, query.clone(), mitre.clone(),
                                   Err(AbandonDEvaluation::compilation_refusee(&e))),
                    })
                })
                .collect();
            fils.into_iter()
                .zip(chunk.iter())
                // DURCISSEMENT (#25) : un worker EMPOISONNÉ (panic dans rule_sql/eval) ne doit PAS avorter
                // TOUT le balayage. On le traite comme un ÉCHEC D'ÉVAL ATTRIBUÉ À SA RÈGLE (la règle est
                // relue dans `chunk`, pas dans le fil qui a paniqué) : aucune alerte fabriquée, aucun
                // last_value=0.0 « tout clair », la règle re-tentée au prochain tick et son abandon consigné
                // avec sa cause. Même garantie fail-closed que les branches Err ci-dessus.
                .map(|(h, (id, name, query, _is_soql, op, threshold, severity, window_s, mitre))| {
                    h.join().unwrap_or_else(|_| {
                        (*id, name.clone(), op.clone(), *threshold, *severity, *window_s, query.clone(), mitre.clone(),
                         Err(AbandonDEvaluation::evaluateur_en_panne()))
                    })
                })
                .collect()
        });
        results.extend(chunk_res);
    }
    // Phase 2 bis (S7) — À QUOI LES ALERTES DE CE TIR SE RAPPORTENT. Calculée ICI, entre l'évaluation et
    // l'écriture : hors du verrou d'écriture (comme la phase 2) et SEULEMENT pour les règles qui vont
    // lever une alerte — le prédicat de tir est le MÊME que celui de la phase 3 (`cmp_op`), écrit une
    // fois et partagé, pour qu'une imputation ne puisse pas exister sans son alerte ni l'inverse.
    let qui_tire: std::collections::HashSet<i64> = results
        .iter()
        .filter(|(_, _, op, th, _, _, _, _, verdict)| verdict.as_ref().map_or(false, |val| cmp_op(*val, op, *th)))
        .map(|r| r.0)
        .collect();
    let imputations = imputations_des_regles_qui_tirent(db_path, &due, &qui_tire, cc);
    // Phase 3 : ecritures groupees sous un seul verrou
    let conn = db.lock();
    for (id, name, op, threshold, severity, _window_s, query, mitre, verdict) in results {
        let val = match verdict {
            Ok(val) => val,
            Err(abandon) => {
                // `P3.9-a` — COMPTÉ pour le bilan du tick (`P4.1-r`), et CONSIGNÉ par règle : re-planifiée
                // comme avant, son compte consécutif incrémenté, et l'alerte de cécité posée au seuil.
                abandonnees += 1;
                let _ = crate::detection_aveugle::consigner_abandon(&conn, id, &name, severity, now_ts, &abandon);
                continue;
            }
        };
        // Évaluée : `last_run`/`last_value` comme avant, compte consécutif à zéro, épisode de cécité résolu.
        crate::detection_aveugle::consigner_evaluation_reussie(&conn, id, now_ts, val);
        // Clé dedup STABLE par règle (PAS de bucket /window) -> une seule alerte+notif par épisode,
        // calquée sur check_heartbeats : INSERT OR IGNORE (no-op si déjà ouverte) + résolution au retour normal.
        let dedup = format!("rule-{id}");
        if cmp_op(val, &op, threshold) {
            let _ = conn.execute("UPDATE rule SET last_fired=?1 WHERE id=?2", params![now_ts, id]);
            let title = format!("{name} : {val} {op} {threshold}");
            // S7 — L'IMPUTATION, calculée en phase 2 bis. `unwrap_or_else` NE pose PAS la chaîne vide :
            // vide voudrait dire « alerte d'avant la migration » et ferait retomber le lecteur sur le
            // texte de la règle EN SILENCE. Un tir sans imputation calculable porte l'inconnu NOMMÉ.
            let sources = imputations.get(&id).cloned().unwrap_or_else(|| imputation_encoder(&[]));
            // l'alerte hérite du tag MITRE de la règle -> /api/coverage/detections joint sur `mitre`.
            // no-op si une alerte ouverte porte déjà la clé -> plus de renotif à chaque fenêtre.
            let _ = conn.execute(
                "INSERT OR IGNORE INTO alert(ts,rule,severity,title,detail,dedup,mitre,sources) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![now_ts, format!("rule.{id}"), severity, title, query, dedup, mitre, sources],
            );
            // rafraîchit l'affichage (ts/valeur/sévérité — utile pour les gauges type CPU dont la valeur bouge)
            // SANS toucher `notified` -> pas de renotif. S7 : l'imputation est RAFRAÎCHIE ici aussi — sur un
            // épisode déjà ouvert (l'INSERT ci-dessus est un no-op), une SECONDE source devenue muette
            // doit faire basculer SA pastille sans attendre la résolution de l'épisode.
            let _ = conn.execute(
                "UPDATE alert SET ts=?1, title=?2, severity=?3, sources=?5 WHERE dedup=?4 AND status IN ('new','ack')",
                params![now_ts, title, severity, dedup, sources],
            );
        } else {
            // retour SOUS le seuil -> résout l'alerte ouverte et libère la clé (ré-arme un futur épisode)
            let _ = conn.execute(
                "UPDATE alert SET status='resolved', dedup=NULL WHERE dedup=?1 AND status IN ('new','ack')",
                params![dedup],
            );
        }
    }
    crate::mesure_environnement::Mesure::Lue(abandonnees)
}

pub(crate) async fn rules_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    // MISC : dégrade proprement en liste vide sur erreur prepare/query (comme correlations_list/baselines_list),
    // au lieu d'un .unwrap() qui panique -> 500 (et, sur l'écrivain partagé, risque de propagation de panic).
    let mut stmt = match conn
        .prepare("SELECT id,name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,last_run,last_value,last_fired,COALESCE(mitre,''),managed,COALESCE(compliance,''),COALESCE(suppress_window_s,0),COALESCE(throttle_field,''),COALESCE(per_result,0) FROM rule ORDER BY id")
    {
        Ok(s) => s,
        Err(_) => return Json(json!({ "rules": [] })),
    };
    let rows: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "enabled": r.get::<_, i64>(2)? != 0,
                "query": r.get::<_, String>(3)?, "is_soql": r.get::<_, i64>(4)? != 0, "op": r.get::<_, String>(5)?,
                "threshold": r.get::<_, f64>(6)?, "severity": r.get::<_, i64>(7)?, "interval_s": r.get::<_, i64>(8)?,
                "window_s": r.get::<_, i64>(9)?, "last_run": r.get::<_, Option<i64>>(10)?,
                "last_value": r.get::<_, Option<f64>>(11)?, "last_fired": r.get::<_, Option<i64>>(12)?,
                // #38 : `compliance` = tags de cadre réglementaire (cadre[:contrôle], CSV) — à côté de `mitre`.
                "mitre": r.get::<_, String>(13)?, "managed": r.get::<_, i64>(14)?, "compliance": r.get::<_, String>(15)?,
                // #48 : réglages de tir avancé (0/''/false = mode historique).
                "suppress_window_s": r.get::<_, i64>(16)?, "throttle_field": r.get::<_, String>(17)?, "per_result": r.get::<_, i64>(18)? != 0
            }))
        })
        .map(|x| x.flatten().collect())
        .unwrap_or_default();
    Json(json!({ "rules": rows }))
}
// PURPLE — normalise/valide une technique MITRE ATT&CK : trim + casse haute, format ^T\d{4}(\.\d{3})?$
// (ex T1110, T1190.001). Vide -> Some("") (champ optionnel, non mappée). Format invalide -> None.
// Impl manuelle char-par-char pour ne PAS ajouter de dépendance regex sur ce chemin. Défense en
// profondeur : le front valide déjà, ici on normalise et on rejette proprement (sans 500).
pub(crate) fn norm_mitre(s: &str) -> Option<String> {
    let t = s.trim().to_uppercase();
    if t.is_empty() { return Some(String::new()); }
    let bytes = t.as_bytes();
    // 'T' + exactement 4 chiffres
    if bytes.first() != Some(&b'T') || bytes.len() < 5 { return None; }
    if !bytes[1..5].iter().all(|c| c.is_ascii_digit()) { return None; }
    match bytes.len() {
        5 => Some(t), // Txxxx
        9 if bytes[5] == b'.' && bytes[6..9].iter().all(|c| c.is_ascii_digit()) => Some(t), // Txxxx.yyy
        _ => None,
    }
}
/// DURCISSEMENT 3a — le SQL BRUT (is_soql=false) lit l'INTÉGRALITÉ de la base (tout `SELECT … FROM`),
/// donc une règle en SQL brut = lecture totale -> RÉSERVÉE à l'admin. Les règles GXQL (langage borné,
/// read-only, sur `event`) restent permises à l'editor, comme tous les parsers/playbooks. Pur (testable
/// sans AppState), utilisé par rule_create ET rule_update.
pub(crate) fn raw_sql_allowed(is_soql: bool, role: &str) -> bool {
    // #59 : plafond = base admin, ET la perm `raw_sql` non RETIRÉE par un rôle composable. Mode 0 (role de
    // base) -> effective_base_role(role)==role & role_perm_denied=false -> BYTE-IDENTIQUE à `role=="admin"`.
    is_soql || (effective_base_role(role) == "admin" && !role_perm_denied(role, "raw_sql"))
}
/// #1c — VALIDATION UNIFIÉE du contenu de détection À L'ENREGISTREMENT (garde-fous #1/#2/#3), fail-closed.
/// Pure (testable sans AppState), branchée sur create ET update des règles/parseurs/playbooks. Réutilise
/// STRICTEMENT le socle existant : `raw_sql_allowed` (SQL brut=admin), `rule_sql` (compile GXQL via
/// guatx_core::soql / substitue __FROM__ en SQL brut), `action_kind_valid` (ENUM FERMÉ dérivé d'action_valid).
/// `kind` ∈ "rule" | "playbook" | "parser". Renvoie Err((StatusCode, message clair)) -> l'appelant répond
/// directement (403 SQL brut non-admin / 400 requête ou regex qui ne compile pas / 400 action hors-enum).
pub(crate) fn validate_detection_content(
    kind: &str,
    is_soql: bool,
    query: &str,
    action_kind: &str,
    window_s: i64,
    role: &str,
) -> Result<(), (StatusCode, String)> {
    match kind {
        // Parseur : la config est une REGEX (le champ `query` porte le motif ici). Non vide, ≤1000, compile.
        "parser" => {
            if query.is_empty() || query.len() > 1000 {
                return Err((StatusCode::BAD_REQUEST, "motif vide ou trop long (≤1000 caractères)".into()));
            }
            if regex::Regex::new(query).is_err() {
                return Err((StatusCode::BAD_REQUEST, "regex invalide".into()));
            }
            Ok(())
        }
        // Règle / playbook : GXQL borné (editor OK) ou SQL brut (admin only), qui DOIT compiler.
        "rule" | "playbook" => {
            // garde-fou #2 : SQL brut (is_soql=false) = RÉSERVÉ ADMIN, enforce SERVEUR (create + update).
            if !raw_sql_allowed(is_soql, role) {
                return Err((StatusCode::FORBIDDEN, "SQL brut réservé à l'administrateur (utilisez GXQL)".into()));
            }
            // garde-fou #1 : la requête doit COMPILER (même chemin que l'éval/test/overlay -> zéro angle mort).
            if let Err(e) = rule_sql(query, is_soql, window_s) {
                return Err((StatusCode::BAD_REQUEST, format!("requête invalide : {e}")));
            }
            // garde-fou #3 : un playbook ne référence QUE l'ENUM FERMÉ d'actions (pas de surface d'exécution custom).
            if kind == "playbook" {
                if let Err(e) = action_kind_valid(action_kind) {
                    return Err((StatusCode::BAD_REQUEST, e));
                }
                // DURCISSEMENT : un playbook PORTE une action RÉPONSE (ban/unban/kill/stop —
                // l'ENUM est intégralement DESTRUCTIF). ARMER une réponse automatique = RÉSERVÉ ADMIN. Un editor
                // conserve tout le CRUD détection (règles/parseurs) mais NE POSE PAS d'action auto. Combiné au
                // marquage `created_by_role` (run_playbooks n'auto-approuve QUE l'admin), `/api/mode active` seul
                // ne suffit JAMAIS à exécuter une action posée par un editor.
                // #64 : autorité admin EFFECTIVE ET la perm `arm_response` NON RETIRÉE (soustractif, calqué sur
                // `raw_sql_allowed`). Mode 0 / rôle de base -> byte-identique à `role != "admin"` (builtin jamais
                // denied). Un rôle composable base=admin AVEC deny `arm_response` NE peut PAS armer une réponse
                // via playbook (le deny subsiste ici — surface NON couverte par route_denied_perm=/api/actions).
                if action_kind_destructive(action_kind) && !(effective_base_role(role) == "admin" && !role_perm_denied(role, "arm_response")) {
                    return Err((StatusCode::FORBIDDEN, "poser une action de réponse automatique (ban/unban/kill/stop) est réservé à l'administrateur".into()));
                }
            }
            Ok(())
        }
        _ => Err((StatusCode::BAD_REQUEST, format!("type de contenu inconnu : {kind}"))),
    }
}
/// #1c garde-fou #4/#6 — suppression MANAGED-AWARE + audit #1b, transactionnelle fail-closed. Politique :
/// - managed=2 (ad-hoc UI)      -> DELETE réel (destructif, audit sévérité 3) ;
/// - managed=0 (builtin/seed)   -> enabled=0 (DÉSACTIVÉ, jamais détruit ; durable car les seeds sont one-shot) ;
/// - managed=1 (overlay config.d) -> REFUS 409 (le fichier git le ré-imposerait au boot -> à retirer côté source).
/// Renvoie le corps JSON de succès ou (StatusCode, message) d'erreur. `table` ∈ rule|playbook|parser (nom
/// littéral -> interpolé dans le SQL : NE JAMAIS exposer à une entrée utilisateur, appelé avec des constantes).
pub(crate) fn delete_managed_row_tx(conn: &Connection, table: &str, audit_prefix: &str, id: i64, managed: i64, actor: &str) -> Result<Value, (StatusCode, String)> {
    if managed == 1 {
        return Err((StatusCode::CONFLICT, "contenu overlay (config.d) géré par fichier versionné — retirez-le côté git, pas via l'UI".into()));
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "verrou base indisponible".into()));
    }
    let outcome: rusqlite::Result<Value> = (|| {
        if managed == 2 {
            conn.execute(&format!("DELETE FROM {table} WHERE id=?1"), params![id])?;
            audit_config_change(
                conn, &format!("{audit_prefix}.delete"),
                &format!("{table} #{id} supprimé par {actor}"), 3,
                &format!("{table} de détection #{id} supprimé par {actor}"),
                &json!({ "op": "delete", "table": table, "id": id, "actor": actor }).to_string(),
            )?;
            Ok(json!({ "ok": true, "deleted": true }))
        } else {
            conn.execute(&format!("UPDATE {table} SET enabled=0 WHERE id=?1"), params![id])?;
            audit_config_change(
                conn, &format!("{audit_prefix}.disable"),
                &format!("{table} builtin #{id} désactivé par {actor}"), 2,
                &format!("{table} builtin #{id} désactivé (non supprimé) par {actor}"),
                &json!({ "op": "disable", "table": table, "id": id, "builtin": true, "actor": actor }).to_string(),
            )?;
            Ok(json!({ "ok": true, "deleted": false, "disabled": true, "message": "contenu builtin : désactivé au lieu d'être supprimé" }))
        }
    })();
    match outcome {
        Ok(body) => { let _ = conn.execute_batch("COMMIT"); Ok(body) }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); Err((StatusCode::INTERNAL_SERVER_ERROR, format!("échec transaction audit (aucune modification): {e}"))) }
    }
}
/// P11.5-c — CE QU'UNE MODIFICATION D'OVERLAY NE DIT PAS D'ELLE-MÊME.
///
/// LE DÉFAUT MESURÉ (2026-08-23, routeur réel). Un administrateur modifie une règle `managed=1` (overlay
/// `config.d`) : le serveur répond `200 {"ok":true}`, la console affiche un succès… et au prochain
/// démarrage `load_overlay_rules` réécrit la ligne depuis le fichier versionné (`UPDATE rule SET query=…,
/// threshold=…, managed=1 WHERE name=…`). La modification disparaît sans qu'un mot n'ait été dit. C'est
/// le pire des deux mondes : ni un refus nommé (comme la SUPPRESSION, qui rend 409 avec sa raison), ni un
/// changement durable. Vu de l'exploitant, « l'administrateur ne peut pas éditer les règles ».
///
/// CE QUE CETTE FONCTION REND. La phrase à joindre à la réponse d'une modification acceptée, quand le
/// contenu est un overlay — et RIEN dans tous les autres cas (`managed=0` builtin adopté en ad-hoc,
/// `managed=2` ad-hoc : la modification est durable, il n'y a rien à dire). Pure, donc testable seule.
/// `objet` est un littéral serveur ACCORDÉ (`cette règle` / `ce parseur` / `ce playbook`), jamais une
/// entrée utilisateur.
pub(crate) fn avertissement_overlay(objet: &str, managed: i64) -> Option<String> {
    (managed == 1).then(|| format!(
        "{objet} vient d'un overlay de configuration (config.d) : au prochain démarrage, le fichier \
         versionné réimpose son contenu et cette modification sera perdue. Seule la bascule actif/inactif \
         survit (elle est enregistrée à part). Pour un changement durable, modifiez le fichier côté dépôt."
    ))
}

/// La réponse d'une modification de contenu de détection ACCEPTÉE : `{"ok":true}` comme avant, plus
/// `managed` et — pour un overlay — l'avertissement ci-dessus. Un client qui ignore les champs neufs voit
/// exactement ce qu'il voyait ; un client qui les lit peut enfin le DIRE.
pub(crate) fn reponse_modification_acceptee(objet: &str, managed: i64) -> Value {
    match avertissement_overlay(objet, managed) {
        Some(a) => json!({ "ok": true, "managed": managed, "avertissement": a }),
        None => json!({ "ok": true, "managed": managed }),
    }
}

/// Enveloppe Response de `delete_managed_row_tx` (rule/playbook ; parser fait son propre reload).
pub(crate) fn delete_managed_row(conn: &Connection, table: &str, audit_prefix: &str, id: i64, managed: i64, actor: &str) -> Response {
    match delete_managed_row_tx(conn, table, audit_prefix, id, managed, actor) {
        Ok(body) => Json(body).into_response(),
        Err((code, msg)) => err_json(code, msg),
    }
}
/// #1c-toggle — CŒUR testable (sans AppState) de la bascule d'ACTIVATION d'un contenu de détection. `kind`/
/// `table` ∈ {rule|parser|playbook} sont des LITTÉRAUX serveur (jamais une entrée utilisateur -> le nom de
/// table interpolé est sûr). Politique MANAGED-AWARE, pendant symétrique de `delete_managed_row_tx` :
///  - managed=1 (overlay config.d) : UPSERT `detection_override(kind,name,enabled)` PUIS flippe la ligne live.
///    L'override est réappliqué au boot (apply_content_overrides) -> le choix SURVIT au reboot (fix du 409 :
///    on n'a plus besoin d'éditer le fichier git + redéployer pour (dés)activer un overlay depuis l'UI) ;
///  - managed=0/2 (builtin/seed | ad-hoc UI) : flippe simplement `enabled` (l'état persiste dans la ligne —
///    les seeds sont one-shot, l'ad-hoc n'est jamais re-seedé) ; AUCUN override écrit (comportement historique).
/// Transaction fail-closed + AUDIT non-purgeable (audit_config_change : ledger tamper-evident + event
/// `plume-config` alertable -> la règle de self-détection #59 voit toute (dés)activation de détection). Un
/// override ne porte QUE `enabled`, JAMAIS query/is_soql -> impossible d'activer une règle SQL brut d'autrui
/// ou d'élever quoi que ce soit via cette surface. Le nom vient de la BASE (pas du client) -> injection-safe.
pub(crate) fn set_content_enabled_tx(conn: &Connection, kind: &str, table: &str, id: i64, enabled: bool, actor: &str) -> Result<Value, (StatusCode, String)> {
    let (name, managed): (String, i64) = match conn.query_row(
        &format!("SELECT name,managed FROM {table} WHERE id=?1"),
        params![id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
    ) {
        Ok(x) => x,
        Err(_) => return Err((StatusCode::NOT_FOUND, format!("{kind} introuvable"))),
    };
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "verrou base indisponible".into()));
    }
    let en = enabled as i64;
    let (word, verb) = if enabled { ("enable", "activé") } else { ("disable", "désactivé") };
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute(&format!("UPDATE {table} SET enabled=?1 WHERE id=?2"), params![en, id])?;
        // managed=1 : PERSISTE la décision (keyé par name, stable across boots) -> gagne au prochain boot.
        if managed == 1 {
            conn.execute(
                "INSERT INTO detection_override(kind,name,enabled,updated,updated_by) VALUES(?1,?2,?3,?4,?5) \
                 ON CONFLICT(kind,name) DO UPDATE SET enabled=excluded.enabled, updated=excluded.updated, updated_by=excluded.updated_by",
                params![kind, name, en, now(), actor],
            )?;
        }
        audit_config_change(
            conn,
            &format!("config.{kind}.{word}"),
            &format!("{kind} '{name}' (#{id}) {verb} par {actor}"),
            2,
            &format!("{kind} de détection '{name}' {verb} par {actor}"),
            &json!({ "op": "set_enabled", "kind": kind, "id": id, "name": name, "enabled": enabled, "managed": managed, "override": managed == 1, "actor": actor }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Ok(json!({ "ok": true, "enabled": enabled, "managed": managed, "override": managed == 1 })) }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); Err((StatusCode::INTERNAL_SERVER_ERROR, format!("échec transaction audit (aucune modification): {e}"))) }
    }
}
/// Extrait le booléen `enabled` OBLIGATOIRE du corps ({enabled:bool}). Absent/non-booléen -> 400 explicite.
fn body_enabled(b: &Value) -> Result<bool, Response> {
    b.get("enabled").and_then(|v| v.as_bool()).ok_or_else(|| bad_req("champ 'enabled' (booléen) requis"))
}
/// POST /api/rules/:id/enabled {enabled:bool} — bascule d'activation d'une RÈGLE, ADMIN-only (gate route
/// `route_min_role` + re-check `require_admin` = default-deny en profondeur) + audité. FONCTIONNE pour TOUS les
/// managed, y compris les overlays config.d (managed=1) via un override persistant qui survit au reboot.
pub(crate) async fn rule_set_enabled(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    let enabled = match body_enabled(&b) { Ok(e) => e, Err(r) => return r };
    crate::req_conn!(st, au, conn);
    match set_content_enabled_tx(&conn, "rule", "rule", id, enabled, &au.name) {
        Ok(body) => Json(body).into_response(),
        Err((code, msg)) => err_json(code, msg),
    }
}
/// POST /api/parsers/:id/enabled — bascule d'activation d'un PARSEUR (ADMIN-only + audité). Recharge le
/// registre compilé après coup (parsers_reload) -> l'ingest reflète l'état immédiatement, comme parser_update.
pub(crate) async fn parser_set_enabled(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    let enabled = match body_enabled(&b) { Ok(e) => e, Err(r) => return r };
    crate::req_conn!(st, au, conn);
    match set_content_enabled_tx(&conn, "parser", "parser", id, enabled, &au.name) {
        Ok(body) => { parsers_reload(&conn, req_db_path(&st, &au).as_str()); Json(body).into_response() }
        Err((code, msg)) => err_json(code, msg),
    }
}
/// POST /api/playbooks/:id/enabled — bascule d'activation d'un PLAYBOOK (ADMIN-only + audité). NB : (dés)activer
/// un playbook ne change QUE `enabled` — l'ARMEMENT réel d'une réponse destructive reste gouverné par le mode
/// global + created_by_role (run_playbooks n'auto-approuve que l'admin) : ce toggle ne contourne pas ce garde.
pub(crate) async fn playbook_set_enabled(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    let enabled = match body_enabled(&b) { Ok(e) => e, Err(r) => return r };
    crate::req_conn!(st, au, conn);
    match set_content_enabled_tx(&conn, "playbook", "playbook", id, enabled, &au.name) {
        Ok(body) => Json(body).into_response(),
        Err((code, msg)) => err_json(code, msg),
    }
}
/// #48 — valide/normalise les champs de tir avancé (suppress_window_s / throttle_field / per_result).
/// `throttle_field` est borné à [a-zA-Z0-9_.] (nom de champ ; jamais concaténé à du SQL). Longueur <=64.
pub(crate) fn adv_fire_fields(b: &Value) -> Result<(i64, String, i64), String> {
    let suppress_window_s = b.i64_field("suppress_window_s", 0).max(0);
    let throttle_field = b.str_field("throttle_field").trim().to_string();
    if !throttle_field.is_empty() && (throttle_field.len() > 64 || !throttle_field.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))) {
        return Err("throttle_field : nom de champ [a-zA-Z0-9_.] (max 64) attendu".into());
    }
    let per_result = b.bool_field("per_result", false) as i64;
    Ok((suppress_window_s, throttle_field, per_result))
}

pub(crate) async fn rule_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let is_soql = b.bool_field("is_soql", true);
    let query = b.str_field("query").to_string();
    let window_s = b.i64_field("window_s", 3600);
    // #1c garde-fous #1/#2 : SQL brut=admin + la requête DOIT compiler (GXQL via core) — AVANT toute écriture.
    if let Err((code, msg)) = validate_detection_content("rule", is_soql, &query, "", window_s, &au.role) {
        return err_json(code, msg);
    }
    // normalise/valide le tag MITRE côté serveur (défense en profondeur). Invalide -> erreur explicite.
    let mitre = match norm_mitre(b.str_field("mitre")) {
        Some(m) => m,
        None => return bad_req("MITRE invalide : format attendu Txxxx ou Txxxx.yyy"),
    };
    // #38 : tags de conformité (cadre[:contrôle], CSV) — normalisés/validés serveur (cadre ∈ vocab, contrôle
    // charset-borné). Vide autorisé (règle non taguée -> mode 0). Cadre inconnu / contrôle invalide -> 400.
    let compliance = match norm_compliance(b.str_field("compliance")) {
        Some(c) => c,
        None => return bad_req("conformité invalide : attendu `cadre[:contrôle]` (cadre ∈ vocab, ex pci_dss:8.7,hipaa:164.312)"),
    };
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Règle").to_string();
    let enabled = b.bool_field("enabled", true) as i64;
    let op = b.get("op").and_then(|v| v.as_str()).unwrap_or(">").to_string();
    let threshold = b.get("threshold").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let severity = b.i64_field("severity", 2);
    let interval_s = b.i64_field("interval_s", 300);
    // #48 SUPPRESSION AVANCÉE (optionnelle ; défauts 0/''/false = comportement historique) :
    //  - suppress_window_s : mute le re-tir N s après un tir (fenêtre de suppression) ;
    //  - throttle_field : dédup par valeur d'un CHAMP (ex src_ip) — identifiant borné [a-zA-Z0-9_.] (lecture
    //    par nom en Rust, jamais concaténé à du SQL) ;
    //  - per_result : une alerte par résultat matché (au lieu d'une par règle).
    let (suppress_window_s, throttle_field, per_result) = match adv_fire_fields(&b) {
        Ok(x) => x,
        Err(m) => return bad_req(m),
    };
    crate::req_conn!(st, au, conn);
    // #1c garde-fou #6 : transaction fail-closed (patron retention_settings_put) — INSERT managed=2 + audit
    // #1b (ledger + event plume-config) ; si l'audit échoue -> ROLLBACK (mutation JAMAIS persistée sans trace).
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO rule(name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,mitre,compliance,suppress_window_s,throttle_field,per_result,managed) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,2)",
            params![name, enabled, query, is_soql as i64, op, threshold, severity, interval_s, window_s, mitre, compliance, suppress_window_s, throttle_field, per_result],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn,
            "config.rule.create",
            &format!("règle '{name}' (#{id}) créée par {}", au.name),
            2,
            &format!("règle de détection '{name}' créée par {}", au.name),
            &json!({ "op": "create", "kind": "rule", "id": id, "name": name, "is_soql": is_soql, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "id": id, "managed": 2 })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}
pub(crate) async fn rule_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    crate::req_conn!(st, au, conn);
    // État courant (is_soql/query/window/managed) pour calculer l'EFFECTIF post-PATCH et valider.
    let cur = conn.query_row(
        "SELECT is_soql,query,window_s,managed FROM rule WHERE id=?1",
        params![id],
        |r| Ok((r.get::<_, i64>(0)? != 0, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?)),
    );
    let (cur_soql, cur_query, cur_window, cur_managed) = match cur {
        Ok(x) => x,
        Err(_) => return not_found("règle introuvable"),
    };
    // #1c garde-fous #1/#2 : is_soql/query/window EFFECTIFS après le PATCH (corps si fourni, sinon base).
    // Anti-contournement : un editor ne peut ni basculer en SQL brut ni éditer une règle SQL brut ; la
    // requête effective (GXQL ou SQL brut) DOIT compiler.
    let eff_soql = b.get("is_soql").and_then(|x| x.as_bool()).unwrap_or(cur_soql);
    let eff_query = b.get("query").and_then(|x| x.as_str()).map(|s| s.to_string()).unwrap_or(cur_query);
    let eff_window = b.get("window_s").and_then(|x| x.as_i64()).unwrap_or(cur_window);
    if let Err((code, msg)) = validate_detection_content("rule", eff_soql, &eff_query, "", eff_window, &au.role) {
        return err_json(code, msg);
    }
    // FIX HIGH-1b (bypass adopt-then-toggle en 2 requêtes) : modifier une détection BASELINE (seed/builtin
    // managed=0) est RÉSERVÉ ADMIN. Racine du contournement : l'effet de bord d'adoption managed=0->2 ci-dessous
    // rend `managed` EDITOR-inscriptible sur TOUTE édition d'un seed (même un PATCH vide), puis la garde HIGH-1
    // laissait passer une désactivation via son disjoint `cur_managed==2`. En interdisant TOUTE édition non-admin
    // d'un managed=0, plus aucune adoption pour un non-admin -> `managed` ne bascule JAMAIS 0->2 pour lui -> le
    // disjoint cur_managed==2 n'est atteignable que sur du contenu ad-hoc VRAIMENT créé par l'editor (POST
    // /api/rules insère managed=2 directement). Ferme AUSSI le trou "neuter-via-query" (un editor ne peut plus
    // éditer la requête d'un seed pour qu'elle ne matche jamais). Frontière : seed(0)+overlay(1)=admin-managés ;
    // l'editor a le CRUD COMPLET sur SON PROPRE ad-hoc (managed=2). La garde HIGH-1 reste en défense-en-profondeur.
    // INVARIANT : `cur_managed != 2` (et non `== 0`) — les OVERLAYS (managed=1) sont AUSSI admin-managés.
    // Avant : seul le seed(0) était protégé ; un editor pouvait transitoirement NEUTRALISER un overlay en éditant sa
    // query/threshold (tout SAUF `enabled`, déjà gardé). Frontière effective désormais : seed(0)+overlay(1)=admin-managés ;
    // SEUL l'ad-hoc managed=2 (créé par l'editor via POST) reste editor-éditable.
    if cur_managed != 2 && !au.is_admin() {
        return err_json(StatusCode::FORBIDDEN, "modifier une détection managée (seed/builtin/overlay) est réservé à l'administrateur ; créez plutôt votre propre règle");
    }
    // FIX HIGH-1 : basculer `enabled` sur une détection MANAGÉE (managed=0 seed / managed=1 overlay) = RÉSERVÉ
    // ADMIN — sinon un editor désactive une règle de sécu seedée (SEC4) ou fait taire un overlay. Un non-admin
    // ne peut toggler `enabled` QUE sur son propre contenu ad-hoc managed=2. Évalué sur le managed COURANT (avant
    // toute adoption managed=0->2 ci-dessous). Fail-closed : on REFUSE tout le PATCH (pas d'application partielle).
    // Style calqué sur les soft-gates de validate_detection_content (raw_sql_allowed / arm_response).
    let enabled_change = b.get("enabled").and_then(|x| x.as_bool());
    if enabled_change.is_some() && !(au.is_admin() || cur_managed == 2) {
        return err_json(StatusCode::FORBIDDEN, "activer/désactiver une détection managée (seed/overlay) est réservé à l'administrateur");
    }
    // #1c garde-fou #6 : transaction fail-closed (patron retention_settings_put) + audit #1b.
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(v) = b.get("name").and_then(|x| x.as_str()) { conn.execute("UPDATE rule SET name=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("query").and_then(|x| x.as_str()) { conn.execute("UPDATE rule SET query=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("is_soql").and_then(|x| x.as_bool()) { conn.execute("UPDATE rule SET is_soql=?1 WHERE id=?2", params![v as i64, id])?; }
        if let Some(v) = b.get("op").and_then(|x| x.as_str()) { conn.execute("UPDATE rule SET op=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("threshold").and_then(|x| x.as_f64()) { conn.execute("UPDATE rule SET threshold=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("severity").and_then(|x| x.as_i64()) { conn.execute("UPDATE rule SET severity=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("interval_s").and_then(|x| x.as_i64()) { conn.execute("UPDATE rule SET interval_s=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("window_s").and_then(|x| x.as_i64()) { conn.execute("UPDATE rule SET window_s=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) { conn.execute("UPDATE rule SET enabled=?1 WHERE id=?2", params![v as i64, id])?; }
        // MITRE normalisé (trim+upper, Txxxx[.yyy]) — invalide -> ignoré (additif, le front bloque en amont).
        if let Some(v) = b.get("mitre").and_then(|x| x.as_str()) {
            if let Some(m) = norm_mitre(v) { conn.execute("UPDATE rule SET mitre=?1 WHERE id=?2", params![m, id])?; }
        }
        // #38 : tags de conformité normalisés/validés — invalide -> ignoré (additif, comme mitre ; le front bloque).
        if let Some(v) = b.get("compliance").and_then(|x| x.as_str()) {
            if let Some(c) = norm_compliance(v) { conn.execute("UPDATE rule SET compliance=?1 WHERE id=?2", params![c, id])?; }
        }
        // #48 : champs de tir avancé (fenêtre de suppression / throttle-by-field / per-result). Patch optionnel.
        if let Some(v) = b.get("suppress_window_s").and_then(|x| x.as_i64()) { conn.execute("UPDATE rule SET suppress_window_s=?1 WHERE id=?2", params![v.max(0), id])?; }
        if let Some(v) = b.get("throttle_field").and_then(|x| x.as_str()) {
            let tf = v.trim();
            if tf.is_empty() || (tf.len() <= 64 && tf.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))) {
                conn.execute("UPDATE rule SET throttle_field=?1 WHERE id=?2", params![tf, id])?;
            }
        }
        if let Some(v) = b.get("per_result").and_then(|x| x.as_bool()) { conn.execute("UPDATE rule SET per_result=?1 WHERE id=?2", params![v as i64, id])?; }
        // #1c garde-fou #4 : éditer un builtin (managed=0) l'ADOPTE en contenu ad-hoc opérateur (managed=2)
        // -> il ne sera plus ré-écrasé par un re-seed. Un overlay (managed=1) garde managed=1 (le fichier
        // config.d GAGNE au prochain boot) ; un ad-hoc (managed=2) reste 2.
        if cur_managed == 0 { conn.execute("UPDATE rule SET managed=2 WHERE id=?1", params![id])?; }
        audit_config_change(
            &conn,
            "config.rule.update",
            &format!("règle #{id} modifiée par {}", au.name),
            2,
            &format!("règle de détection #{id} modifiée par {}", au.name),
            &json!({ "op": "update", "kind": "rule", "id": id, "is_soql": eff_soql, "enabled": enabled_change, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(reponse_modification_acceptee("cette règle", cur_managed)).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}
/// #1c garde-fou #4 : la suppression DESTRUCTIVE est réservée au contenu ad-hoc UI (managed=2). Un builtin
/// (managed=0) est DÉSACTIVÉ (enabled=0), jamais supprimé (durable : les seeds sont one-shot). Un overlay
/// (managed=1) est refusé (409) : le fichier config.d le ré-imposerait au boot -> à retirer côté git.
pub(crate) async fn rule_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    let managed = match conn.query_row("SELECT managed FROM rule WHERE id=?1", params![id], |r| r.get::<_, i64>(0)) {
        Ok(m) => m,
        Err(_) => return not_found("règle introuvable"),
    };
    delete_managed_row(&conn, "rule", "config.rule", id, managed, &au.name)
}
// ---- Parsers (registre modulaire) : CRUD + test. Toute écriture -> parsers_reload (cache compilé). ----
pub(crate) async fn parsers_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    // MISC : dégrade en liste vide sur erreur (parité correlations_list/baselines_list) au lieu de paniquer.
    let mut stmt = match conn.prepare("SELECT id,name,source,pattern,enabled,builtin,managed FROM parser ORDER BY builtin DESC, source, id") {
        Ok(s) => s,
        Err(_) => return Json(json!({ "parsers": [] })),
    };
    let rows: Vec<Value> = stmt.query_map([], |r| Ok(json!({
        "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "source": r.get::<_, String>(2)?,
        "pattern": r.get::<_, String>(3)?, "enabled": r.get::<_, i64>(4)? != 0, "builtin": r.get::<_, i64>(5)? != 0,
        "managed": r.get::<_, i64>(6)?
    }))).map(|x| x.flatten().collect()).unwrap_or_default();
    Json(json!({ "parsers": rows }))
}
pub(crate) async fn parser_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let pat = b.str_field("pattern").to_string();
    // #1c garde-fou #1 : la regex doit être non vide, ≤1000, compiler — AVANT toute écriture.
    if let Err((code, msg)) = validate_detection_content("parser", true, &pat, "", 0, &au.role) {
        return err_json(code, msg);
    }
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Parser").to_string();
    let source = b.get("source").and_then(|v| v.as_str()).unwrap_or("*").to_string();
    let enabled = b.bool_field("enabled", true) as i64;
    crate::req_conn!(st, au, conn);
    // #1c garde-fous #4/#6 : INSERT builtin=0 managed=2 (ad-hoc UI) + audit #1b, transaction fail-closed.
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO parser(name,source,pattern,enabled,builtin,managed,created) VALUES(?1,?2,?3,?4,0,2,?5)",
            params![name, source, pat, enabled, now()],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.parser.create",
            &format!("parseur '{name}' (#{id}) créé par {}", au.name), 2,
            &format!("parseur '{name}' créé par {}", au.name),
            &json!({ "op": "create", "kind": "parser", "id": id, "name": name, "source": source, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => { let _ = conn.execute_batch("COMMIT"); parsers_reload(&conn, req_db_path(&st, &au).as_str()); Json(json!({ "id": id, "managed": 2 })).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}
pub(crate) async fn parser_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    crate::req_conn!(st, au, conn);
    let cur_managed = match conn.query_row("SELECT managed FROM parser WHERE id=?1", params![id], |r| r.get::<_, i64>(0)) {
        Ok(m) => m,
        Err(_) => return not_found("parseur introuvable"),
    };
    // #1c garde-fou #1 : si un motif est fourni, il DOIT compiler (≤1000) -> sinon 400 (avant écriture).
    if let Some(v) = b.get("pattern").and_then(|x| x.as_str()) {
        if let Err((code, msg)) = validate_detection_content("parser", true, v, "", 0, &au.role) {
            return err_json(code, msg);
        }
    }
    // FIX HIGH-1b (bypass adopt-then-toggle) : modifier un parseur BASELINE (seed/builtin managed=0) = ADMIN
    // seul — sinon l'adoption managed=0->2 (plus bas) sert de tremplin à une désactivation editor + ferme le
    // neuter-via-pattern. Frontière : baseline(0)+overlay(1)=admin ; editor CRUD complet sur SON ad-hoc (managed=2).
    // INVARIANT : `cur_managed != 2` — overlay(1) admin-managé au même titre que le seed(0).
    if cur_managed != 2 && !au.is_admin() {
        return err_json(StatusCode::FORBIDDEN, "modifier un parseur managé (seed/builtin/overlay) est réservé à l'administrateur ; créez plutôt votre propre parseur");
    }
    // FIX HIGH-1 : toggler `enabled` sur un parseur managé (managed=0 seed/builtin, managed=1 overlay) = ADMIN
    // seul ; un non-admin ne bascule `enabled` que sur son parseur ad-hoc managed=2. Fail-closed (refuse tout le
    // PATCH). Évalué sur le managed COURANT (avant l'adoption managed=0->2 plus bas).
    let enabled_change = b.get("enabled").and_then(|x| x.as_bool());
    if enabled_change.is_some() && !(au.is_admin() || cur_managed == 2) {
        return err_json(StatusCode::FORBIDDEN, "activer/désactiver une détection managée (seed/overlay) est réservé à l'administrateur");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(v) = b.get("name").and_then(|x| x.as_str()) { conn.execute("UPDATE parser SET name=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("source").and_then(|x| x.as_str()) { conn.execute("UPDATE parser SET source=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("pattern").and_then(|x| x.as_str()) { conn.execute("UPDATE parser SET pattern=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) { conn.execute("UPDATE parser SET enabled=?1 WHERE id=?2", params![v as i64, id])?; }
        // #1c garde-fou #4 : éditer un builtin (managed=0) l'ADOPTE en ad-hoc (managed=2, builtin=0) -> il ne
        // sera plus ré-écrasé par un re-seed. Overlay (managed=1) reste 1 (le fichier config.d gagne au boot).
        if cur_managed == 0 { conn.execute("UPDATE parser SET managed=2, builtin=0 WHERE id=?1", params![id])?; }
        audit_config_change(
            &conn, "config.parser.update",
            &format!("parseur #{id} modifié par {}", au.name), 2,
            &format!("parseur #{id} modifié par {}", au.name),
            &json!({ "op": "update", "kind": "parser", "id": id, "enabled": enabled_change, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); parsers_reload(&conn, req_db_path(&st, &au).as_str()); Json(reponse_modification_acceptee("ce parseur", cur_managed)).into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}
pub(crate) async fn parser_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    // #1c garde-fou #4 : un builtin parseur (builtin=1) a managed=0 -> traité comme builtin (désactivation).
    let managed = match conn.query_row("SELECT managed FROM parser WHERE id=?1", params![id], |r| r.get::<_, i64>(0)) {
        Ok(m) => m,
        Err(_) => return not_found("parseur introuvable"),
    };
    match delete_managed_row_tx(&conn, "parser", "config.parser", id, managed, &au.name) {
        Ok(body) => { parsers_reload(&conn, req_db_path(&st, &au).as_str()); Json(body).into_response() }
        Err((code, msg)) => err_json(code, msg),
    }
}
/// Réapplique les parsers ACTIFS aux events DÉJÀ stockés (rétroactif). RÉSERVÉ ADMIN.
/// `dry_run:true` = compte seulement (validation UI avant d'écrire) ; `source`/`days` = portée
/// (défaut : toutes sources, 30 j). Mono-connexion : on COLLECTE d'abord (curseur lecture ouvert),
/// PUIS on UPDATE (sinon "table is locked"). Plafond mémoire CAP écritures/appel (VPS RAM serrée).
/// N'ÉCRASE jamais un champ/colonne déjà présent (même politique que l'ingestion : enrichit, sans perte).
pub(crate) async fn parser_reparse(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Json<Value> {
    if !au.is_admin() { return Json(json!({ "error": "réservé admin" })); }
    let source = b.get("source").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let days = b.get("days").and_then(|v| v.as_i64()).filter(|&n| n > 0 && n <= 3650).unwrap_or(30);
    let dry = b.bool_field("dry_run", false);
    let cut = now() - days * 86400;
    const CAP: usize = 50000;
    let db = req_db(&st, &au);
    let db_path = req_db_path(&st, &au); // MT-KEY : parseurs de CE db_path pour le reparse
    let out = tokio::task::spawn_blocking(move || -> (i64, i64, i64, String) {
        let conn = db.lock();
        // H2 (#18 P1 TIER FROID) : quand le tier cold est ON, une donnée agée est IMMUABLE (columnarisée).
        // Un reparse dont la fenêtre `days` atteint un jour agé pourrait, pendant la columnarisation (verrou
        // relâché entre pages, FIX #3), muter une ligne déjà flushée en Parquet puis supprimée du hot -> perte
        // silencieuse de fidélité. On CLAMPE donc la borne basse à `hot_cutoff` (source unique partagée avec
        // l'aging) : le reparse ne mute QUE des lignes encore hot. DOUBLE GATE -> mode 0 byte-identique :
        // COMPILE (feature `cold_tier` : sans elle, cette ligne n'existe pas) + RUNTIME (`PLUME_COLD_TIER`,
        // testé DANS reparse_lower_bound : cold-off -> `cut` renvoyé INCHANGÉ). Reparser une donnée agée
        // exigerait une réécriture cold, HORS périmètre P1.
        // CONTRAT D'IMMUTABILITÉ COLD (source : cold_store.rs module doc « IMMUTABILITÉ COLD vs REPARSE (H2) » +
        // `age_one_day`) : aged/cold = IMMUABLE. Élargir la fenêtre de reparse au-delà de `hot_cutoff` quand le cold
        // est ON muterait une ligne DÉJÀ columnarisée puis la supprimerait du hot = perte de fidélité. Le clamp
        // ci-dessous est l'UNIQUE point de couplage reparse↔cold_store de ce sous-système (à préserver au refactor).
        #[cfg(feature = "cold_tier")]
        let cut = crate::cold_store::reparse_lower_bound(&conn, &load_config(), now(), cut);
        let mut changes: Vec<(i64, Option<String>, Option<String>, Option<String>)> = Vec::new();
        let (mut scanned, mut would) = (0i64, 0i64);
        {
            let mut stmt = match conn.prepare(
                "SELECT id,source,message,fields,src_ip,dst_ip FROM event WHERE ts>=?1 AND (?2 IS NULL OR source=?2) ORDER BY id"
            ) { Ok(s) => s, Err(e) => return (0, 0, 0, format!("prepare: {e}")) };
            let rows = stmt.query_map(params![cut, source], |r| Ok((
                r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?, r.get::<_, Option<String>>(4)?, r.get::<_, Option<String>>(5)?,
            )));
            if let Ok(it) = rows {
                for row in it.flatten() {
                    scanned += 1;
                    let (id, src, msg, fields, cur_src, cur_dst) = row;
                    let parsed = parsers_apply(&db_path, &src, &msg, fields.clone());
                    // EXTRACTEUR GÉNÉRIQUE (PARSER PHASE 1) au BACKFILL : opt-in par source (gate
                    // generic_sources). Décrypt+rewrite déjà fenêtré (days/CAP, admin, jamais au boot).
                    let base_gen = parsed.clone().or_else(|| fields.clone());
                    let newf = match extract_generic(&src, &msg, base_gen.as_deref().unwrap_or("{}")) {
                        Some(f) => Some(f),
                        None => parsed,
                    };
                    let f_changed = newf.is_some() && newf != fields;
                    let f_src = if f_changed { &newf } else { &fields };
                    let nsrc = if cur_src.as_deref().unwrap_or("").is_empty() { fields_ip(f_src) } else { None };
                    let ndst = if cur_dst.as_deref().unwrap_or("").is_empty() { fields_dst(f_src) } else { None };
                    if f_changed || nsrc.is_some() || ndst.is_some() {
                        would += 1;
                        if !dry && changes.len() < CAP {
                            changes.push((id, if f_changed { newf } else { None }, nsrc, ndst));
                        }
                    }
                }
            }
        }
        if dry { return (scanned, would, 0, String::new()); }
        let _ = conn.execute_batch("BEGIN IMMEDIATE");
        for (id, f, s, d) in &changes {
            if let Some(f) = f { let _ = conn.execute("UPDATE event SET fields=?1 WHERE id=?2", params![f, id]); }
            if let Some(s) = s { let _ = conn.execute("UPDATE event SET src_ip=?1 WHERE id=?2 AND (src_ip IS NULL OR src_ip='')", params![s, id]); }
            if let Some(d) = d { let _ = conn.execute("UPDATE event SET dst_ip=?1 WHERE id=?2 AND (dst_ip IS NULL OR dst_ip='')", params![d, id]); }
        }
        let _ = conn.execute_batch("COMMIT");
        (scanned, would, changes.len() as i64, String::new())
    }).await.unwrap_or((0, 0, 0, "join".into()));
    if !out.3.is_empty() { return Json(json!({ "error": out.3 })); }
    Json(json!({ "scanned": out.0, "matched": out.1, "updated": out.2, "truncated": (out.1 as usize) > CAP, "dry_run": dry, "cap": CAP }))
}
pub(crate) async fn parser_test(Json(b): Json<Value>) -> Json<Value> {
    let pat = b.str_field("pattern");
    let sample = b.str_field("sample");
    if pat.is_empty() { return Json(json!({ "error": "motif vide" })); }
    let re = match regex::Regex::new(pat) { Ok(r) => r, Err(e) => return Json(json!({ "error": format!("regex invalide : {e}") })) };
    let mut fields = serde_json::Map::new();
    let matched = if let Some(caps) = re.captures(sample) {
        for name in re.capture_names().flatten() {
            if let Some(m) = caps.name(name) { fields.insert(name.to_string(), Value::String(m.as_str().to_string())); }
        }
        true
    } else { false };
    Json(json!({ "matched": matched, "fields": fields }))
}
pub(crate) async fn rule_test(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Json<Value> {
    let row = {
        crate::req_conn!(st, au, conn);
        conn.query_row(
            "SELECT query,is_soql,op,threshold,window_s FROM rule WHERE id=?1",
            params![id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0, r.get::<_, String>(2)?, r.get::<_, f64>(3)?, r.get::<_, i64>(4)?)),
        ).ok()
    };
    let (query, is_soql, op, threshold, window_s) = match row {
        Some(x) => x,
        None => return Json(json!({ "error": "règle introuvable" })),
    };
    // #45 : porte de compilation APPELANT (masque du rôle appliqué / prédicat sur champ masqué rejeté).
    let sql = match rule_sql_for_caller(&st, &au, &query, is_soql, window_s) {
        Ok(s) => s,
        Err(e) => return Json(json!({ "error": e })),
    };
    let db_path = req_db_path(&st, &au);
    let sql2 = sql.clone();
    let val = tokio::task::spawn_blocking(move || eval_value(&db_path, &sql2)).await.ok().flatten();
    match val {
        Some(v) => Json(json!({ "value": v, "fired": cmp_op(v, &op, threshold), "sql": sql })),
        None => Json(json!({ "error": "évaluation échouée", "sql": sql })),
    }
}

/// Teste une requête de règle NON enregistrée (validation avant création/édition).
pub(crate) async fn rule_test_adhoc(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Json<Value> {
    let query = b.str_field("query").to_string();
    if query.trim().is_empty() {
        return Json(json!({ "error": "requête vide" }));
    }
    let is_soql = b.bool_field("is_soql", true);
    // #1c garde-fou #2 : le TEST ad-hoc d'une requête SQL BRUT (is_soql=false) est RÉSERVÉ ADMIN, au même
    // titre que la création/édition (validate_detection_content). Sans ce garde, un editor testerait du SQL
    // brut arbitraire (lecture read-only de TOUTES les tables : user.hash, token…) via /api/rule-test ->
    // contournement du garde-fou « SQL brut = admin only » sur la surface Règles. Le GXQL (is_soql=true)
    // reste ouvert à l'editor. Miroir exact de raw_sql_allowed (create/update).
    if !raw_sql_allowed(is_soql, &au.role) {
        return Json(json!({ "error": "SQL brut réservé à l'administrateur (utilisez GXQL)" }));
    }
    let op = b.get("op").and_then(|v| v.as_str()).unwrap_or(">").to_string();
    let threshold = b.get("threshold").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let window_s = b.i64_field("window_s", 3600);
    // #45 : porte de compilation APPELANT (masque du rôle appliqué / prédicat sur champ masqué rejeté).
    let sql = match rule_sql_for_caller(&st, &au, &query, is_soql, window_s) {
        Ok(s) => s,
        Err(e) => return Json(json!({ "error": e })),
    };
    let db_path = req_db_path(&st, &au);
    let sql2 = sql.clone();
    match tokio::task::spawn_blocking(move || run_query(&db_path, &sql2)).await {
        Ok(Ok(v)) => {
            let val = v.get("rows").and_then(|r| r.as_array()).and_then(|a| a.first())
                .and_then(|r| r.as_array()).and_then(|r| r.last())
                .and_then(|c| c.as_f64().or_else(|| c.as_i64().map(|n| n as f64)));
            match val {
                Some(value) => Json(json!({ "value": value, "fired": cmp_op(value, &op, threshold), "sql": sql })),
                None => Json(json!({ "error": "la requête ne renvoie pas de nombre (attendu : 1 ligne, dernière colonne numérique)", "sql": sql })),
            }
        }
        Ok(Err(e)) => Json(json!({ "error": e, "sql": sql })),
        Err(_) => Json(json!({ "error": "exécution échouée" })),
    }
}

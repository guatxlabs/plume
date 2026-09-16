//! #3 INCIDENTS + RESPONSE WIZARD (Phase 1) — couche de GESTION D'INCIDENT GUIDÉE posée SUR les cases (#4a/#39),
//! SANS nouvelle entité : un « incident » est un case ÉLEVÉ (`incident.incident_tier` non-NULL). Un « runbook »
//! (gabarit managé keyé MITRE) attaché à un incident INSTANCIE ses étapes en `case_step` (checklist phasée
//! triage->investigation->containment->eradication->recovery). Le wizard PRÉSENTE : (a) les steps `search`
//! (gabarit GXQL recompilé, comme workflow_action `search` — jamais de SQL brut), (b) les steps `response` qui
//! RÉFÉRENCENT l'enum d'action FERMÉ (ban_ip/kill_pid/stop_service) et pré-remplissent la cible — MAIS
//! l'EXÉCUTION reste /api/actions EXISTANT (arm/approbation/admin-gate/ledger/allowlist root/observe-vs-active
//! INCHANGÉS). AUCUN chemin d'auto-exécution : analyste-in-the-loop.
//!
//! MODE 0 BYTE-IDENTIQUE : tables VIDES + `incident_tier` NULL -> un case ordinaire ne lit/écrit RIEN de neuf.
//! Chaque élévation/attachement/avancement écrit un item de timeline TYPÉ (kinds 'incident'/'runbook'/'step',
//! HORS de l'allowlist client-read created/status/sla/merge -> jamais exposés au MSSP) + une entrée LEDGER
//! (tamper-evident, comme case.status/case.assign). Réutilise : case_add_item (timeline + MTTA), ledger_append,
//! guatx_core::attack (technique->tactique), le compilateur GXQL FERMÉ, l'enum action_kind_valid.
use crate::*;
use rusqlite::OptionalExtension;

/// `P10.20-b` (rang 2) — LA RECOMMANDATION N'EST PAS ÉTABLIE, ET CE N'EST PAS « AUCUN RUNBOOK NE CONVIENT ».
///
/// LE DÉFAUT MESURÉ LE 2026-09-16. `pick_runbook_id` essaie TROIS niveaux du plus spécifique au plus
/// général — technique, tactique, générique `'*'` — et chaque essai finissait par `.ok()`. Une lecture
/// RATÉE au niveau technique était donc indiscernable d'un « aucun runbook technique ne correspond », et la
/// fonction PASSAIT AU NIVEAU SUIVANT : la console affichait « Recommandé : <procédure de tactique> » —
/// une AUTRE procédure que celle qui était écrite pour cette technique-là, présentée avec l'aplomb d'un
/// choix fondé, et pré-sélectionnée dans le sélecteur d'attache (`web/cases.js`). Au dernier niveau, la
/// même lecture ratée rendait `recommended: null`, qui se lit « aucun runbook ne correspond à cet
/// incident » — la phrase qui fait écrire une procédure à la main pendant un incident.
pub(crate) const CAUSE_RECOMMANDATION_NON_ETABLIE: &str = "RECOMMANDATION DE RUNBOOK NON ÉTABLIE : la \
     recherche du runbook à recommander n'a pas abouti. Ce n'est PAS « aucun runbook ne correspond », et \
     aucune procédure d'un AUTRE niveau de correspondance n'est proposée à la place : un repli sur le \
     niveau suivant ferait dérouler une autre procédure que celle qui était prévue. Cause : ";

/// `P10.20-b` (rang 2) — LE RUNBOOK ATTACHÉ N'A PAS ÉTÉ LU, ET CE N'EST PAS « AUCUN RUNBOOK ATTACHÉ ».
/// Deux surfaces servaient ce `null` : la fiche de dossier (`attached_runbook_id`) et l'en-tête de la
/// checklist (`runbook`). Un analyste qui lit « aucun runbook attaché » sur un dossier qui en porte un
/// ATTACHE le sien — `attach_runbook` refusera, parce qu'une progression existe déjà, et le refus se lira
/// comme un défaut du produit plutôt que comme ce qu'il est. `P7.19-i` avait déjà fait rendre `null` à
/// l'ensemble MULTIPLE (deux runbooks sur un même dossier) : c'est un refus de NOMMER, établi sur des
/// lignes lues. Celui-ci ne l'était pas.
pub(crate) const CAUSE_RUNBOOK_ATTACHE_NON_LU: &str = "RUNBOOK ATTACHÉ NON LU : la lecture des étapes \
     figées de ce dossier a échoué. Ce n'est PAS « aucun runbook attaché » — il y en a peut-être un, et en \
     attacher un second serait refusé. Cause : ";

// ---------------------------------------------------------------------------------------------------------
// CŒUR TESTABLE (fonctions pures sur &Connection, sans AppState).
// ---------------------------------------------------------------------------------------------------------

/// Statuts CANONIQUES d'une step d'incident. None si inconnu (l'appelant refuse).
pub(crate) fn norm_step_status(v: &str) -> Option<&'static str> {
    match v.trim() {
        "pending" | "open" | "todo" => Some("pending"),
        "done" | "completed" => Some("done"),
        "skipped" | "skip" => Some("skipped"),
        _ => None,
    }
}

/// ÉLÈVE (tier non-NULL) ou RÉTROGRADE (tier NULL) un case en incident + pose type/commander optionnels. Écrit
/// un item de timeline 'incident' + ledger. false si le case n'existe pas. Un `demote` (tier NULL) N'EFFACE PAS
/// les steps déjà instanciées ni le type/commander (trace conservée) — il retire seulement la déclaration.
pub(crate) fn incident_apply_tier(conn: &Connection, id: i64, author: &str, tier: Option<i64>, itype: Option<&str>, commander: Option<&str>) -> bool {
    if conn.query_row("SELECT 1 FROM incident WHERE id=?1", params![id], |_| Ok(())).is_err() {
        return false;
    }
    let t = now();
    let _ = conn.execute("UPDATE incident SET incident_tier=?1 WHERE id=?2", params![tier, id]);
    if let Some(ty) = itype {
        let ty = ty.trim();
        let stored: Option<&str> = if ty.is_empty() { None } else { Some(ty) };
        let _ = conn.execute("UPDATE incident SET incident_type=?1 WHERE id=?2", params![stored, id]);
    }
    if let Some(cm) = commander {
        let cm = cm.trim();
        let stored: Option<&str> = if cm.is_empty() { None } else { Some(cm) };
        let _ = conn.execute("UPDATE incident SET commander=?1 WHERE id=?2", params![stored, id]);
    }
    let body = match tier {
        // MISC (off-by-one) : on teste la VALEUR trimée non-vide, pas la longueur de la chaîne préfixée (", type "
        // = 7 > 6 et ", pilote " = 9 > 8 étaient TOUJOURS vrais -> label pendouillant « , type » quand vide).
        Some(tr) => {
            let ty = itype.map(str::trim).filter(|s| !s.is_empty()).map(|s| format!(", type {s}")).unwrap_or_default();
            let pilote = commander.map(str::trim).filter(|s| !s.is_empty()).map(|s| format!(", pilote {s}")).unwrap_or_default();
            format!("incident DÉCLARÉ (tier {tr}){ty}{pilote}")
        }
        None => "incident RÉTROGRADÉ (redevient case ordinaire)".to_string(),
    };
    case_add_item(conn, id, t, "incident", author, &body, None);
    ledger_append(conn, "case.incident", &format!("#{id} tier={} by {author}", tier.map(|t| t.to_string()).unwrap_or_else(|| "none".into())));
    true
}

/// #3 PHASE 3 — Part A : les cibles pré-remplies STRUCTURÉES de l'alerte dominante (au lieu du seul `host`
/// best-effort de Phase 1/2). Chaque champ est la 1re valeur non-vide rencontrée parmi les alertes liées (même
/// heuristique « where available » que le host historique). Peuplées best-effort à la création d'alerte par les
/// moteurs row-aware ; NULL sur l'historique / les alertes du moteur scalaire de base -> repli blanc (parité).
#[derive(Debug, Clone, Default)]
pub(crate) struct PrefillTargets {
    /// IP source (attaquant) — cible d'une step `ban_ip`/`unban_ip`.
    pub(crate) src_ip: Option<String>,
    /// PID (texte) — cible d'une step `kill_pid`.
    pub(crate) pid: Option<String>,
    /// hôte observé — cible best-effort des steps `search`/`manual` (parité Phase 1/2) ET hôte d'exécution
    /// figé sur une step `kill_pid` (un PID est inactionnable sans son hôte).
    pub(crate) host: Option<String>,
}

/// VALIDE une valeur candidate de prefill contre l'enum de validation d'action EXISTANT (`action_valid_ctx`) :
/// une cible pré-remplie DOIT être une valeur que `/api/actions` accepterait (format), sinon on retombe blanc —
/// JAMAIS une cible invalide/trompeuse. `engagement_on=false` + `db_path=""` : on ne teste QUE la validité de
/// format (la clause engagement, seule consommatrice de db_path, est court-circuitée) ; l'exécution re-valide au
/// drapeau engagement RÉEL à la porte. Renvoie la valeur trimée si valide, None sinon.
fn valid_prefill<'a>(kind: &str, cand: Option<&'a str>) -> Option<&'a str> {
    let v = cand.map(str::trim).filter(|s| !s.is_empty())?;
    if action_valid_ctx(kind, v, false, "").is_ok() { Some(v) } else { None }
}

/// Détermine la TACTIQUE DOMINANTE (+ technique dominante + cibles pré-remplies STRUCTURÉES best-effort) d'un
/// case, à partir des ALERTES liées (items timeline kind='alert', ref 'alert:<id>'). Pour chaque alerte :
/// `alert.mitre` -> tactique via guatx_core::attack (sous-techniques héritent). Les cibles pré-remplies sont
/// lues des colonnes STRUCTURÉES de l'alerte dominante (`src_ip`/`pid`/`host`, #3 P3-A) — 1re valeur non-vide,
/// prefill honnête « where available ». Renvoie (tactic, technique, targets).
///
/// `P10.7-f` (rang 4, vague b) — ELLE REND UN `rusqlite::Result`, PARCE QUE SA VALEUR ENTRE DANS UNE
/// RECOMMANDATION. Avant : `.map(|x| x.flatten().collect())` puis `.unwrap_or_default()`. Ici la ligne
/// avalée ne manque pas dans une liste — elle change un VAINQUEUR : les tactiques et les techniques sont
/// comptées sur ces lignes, et `max_by_key` élit la dominante. Perdre une alerte peut donc faire basculer
/// la tactique, donc le runbook que `pick_runbook_id` recommande, donc la procédure que l'analyste
/// déroule ; et une liste ENTIÈREMENT illisible rendait `(None, None, défaut)`, indiscernable d'« aucune
/// alerte liée » — le cas où le repli générique `'*'` est LÉGITIME. Un `Result` sépare les deux : « aucune
/// alerte » reste `Ok(vec![])` et garde son repli, « pas lu » remonte, et l'appelant refuse de recommander.
/// Les cibles pré-remplies suivent le même sort : mieux vaut un champ blanc que la première valeur d'un
/// échantillon amputé, présentée comme celle de l'alerte dominante.
pub(crate) fn dominant_tactic_and_target(conn: &Connection, id: i64) -> rusqlite::Result<(Option<String>, Option<String>, PrefillTargets)> {
    // (mitre, host, src_ip, pid) des alertes liées (y compris via un case fusionné dedans, cf case_get_json).
    let rows: Vec<(String, Option<String>, Option<String>, Option<String>)> = conn
        .prepare(
            "SELECT COALESCE(a.mitre,''), a.host, a.src_ip, a.pid FROM incident_item ii \
             JOIN alert a ON a.id = CAST(substr(ii.ref,7) AS INTEGER) \
             WHERE ii.kind='alert' AND ii.ref LIKE 'alert:%' \
               AND (ii.incident_id=?1 OR ii.incident_id IN (SELECT id FROM incident WHERE merged_into=?1))",
        )
        .and_then(|mut s| {
            s.query_map(params![id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Option<String>>(3)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()
        })?;
    if rows.is_empty() {
        return Ok((None, None, PrefillTargets::default()));
    }
    use std::collections::HashMap;
    let mut tac_count: HashMap<&'static str, i64> = HashMap::new();
    let mut tech_count: HashMap<String, i64> = HashMap::new();
    let mut targets = PrefillTargets::default();
    // 1re valeur non-vide par champ (même heuristique « where available » que le host historique).
    let first_nonempty = |slot: &mut Option<String>, v: &Option<String>| {
        if slot.is_none() {
            if let Some(s) = v.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                *slot = Some(s.to_string());
            }
        }
    };
    for (mitre, host, src_ip, pid) in &rows {
        if let Some(t) = guatx_core::attack::tactic_for_technique(mitre) {
            *tac_count.entry(t).or_insert(0) += 1;
        }
        if let Some(pt) = guatx_core::attack::parent_technique(mitre) {
            *tech_count.entry(pt).or_insert(0) += 1;
        }
        first_nonempty(&mut targets.host, host);
        first_nonempty(&mut targets.src_ip, src_ip);
        first_nonempty(&mut targets.pid, pid);
    }
    // TIE-BREAK DÉTERMINISTE (INC-2) : max_by_key sur un std HashMap est NON déterministe sur égalité de compte
    // (ordre d'itération aléatoire) -> le runbook « recommandé » basculait entre requêtes. On départage par nom
    // lexicographiquement le plus PETIT (Reverse -> max_by_key retient le plus petit) : dominant STABLE.
    use std::cmp::Reverse;
    let tactic = tac_count.into_iter().max_by_key(|&(name, c)| (c, Reverse(name))).map(|(t, _)| t.to_string());
    let technique = tech_count.into_iter().max_by_key(|(name, c)| (*c, Reverse(name.clone()))).map(|(t, _)| t);
    Ok((tactic, technique, targets))
}

/// Choisit le RUNBOOK recommandé pour un incident — ADAPTIVITÉ NIVEAU-TECHNIQUE (Phase 2). Ordre de priorité
/// DÉTERMINISTE, du plus SPÉCIFIQUE au plus GÉNÉRAL :
///   (1) match_kind='technique' key=<technique parente dominante> (ex T1110) — un runbook TECHNIQUE-spécifique
///       GAGNE sur le runbook de tactique quand il existe ;
///   (2) match_kind='tactic' key=<tactique dominante> ; repli discovery->reconnaissance (port-scan T1046 = phase
///       de reconnaissance, même bucket produit) ;
///   (3) générique '*'.
/// `Ok(None)` si aucun runbook actif ne correspond (tables vides / seed absent) — une absence ÉTABLIE. Ne
/// renvoie que des runbooks ACTIFS. Passer `technique=None` reproduit EXACTEMENT le comportement Phase 1
/// (repli tactique->générique) — parité.
///
/// `P10.20-b` (rang 2) — LE REPLI D'UN NIVEAU À L'AUTRE EST UNE DÉCISION DE PRÉCÉDENCE, PAS UN RATTRAPAGE
/// D'ERREUR. Chaque niveau rend `Result<Option<i64>>` et la première lecture qui ÉCHOUE arrête la
/// recherche : descendre d'un cran sur une panne de lecture reviendrait à recommander la procédure d'un
/// niveau MOINS spécifique en la présentant comme le meilleur choix. `Ok(None)` — « ce niveau n'a pas de
/// runbook » — continue de faire descendre, exactement comme avant.
pub(crate) fn pick_runbook_id(conn: &Connection, tactic: Option<&str>, technique: Option<&str>) -> rusqlite::Result<Option<i64>> {
    let try_match = |kind: &str, key: &str| -> rusqlite::Result<Option<i64>> {
        conn.query_row(
            "SELECT id FROM runbook WHERE active=1 AND match_kind=?1 AND match_key=?2 ORDER BY id LIMIT 1",
            params![kind, key],
            |r| r.get(0),
        ).optional()
    };
    // (1) niveau TECHNIQUE (le plus spécifique) — normalise en technique parente (T1110.001 -> T1110).
    if let Some(tech) = technique {
        if let Some(pt) = guatx_core::attack::parent_technique(tech) {
            if let Some(rb) = try_match("technique", &pt)? {
                return Ok(Some(rb));
            }
        }
    }
    // (2) niveau TACTIQUE (repli).
    if let Some(tac) = tactic {
        if let Some(rb) = try_match("tactic", tac)? {
            return Ok(Some(rb));
        }
        // port-scan / énumération réseau (discovery) -> runbook de reconnaissance (même réponse produit).
        if tac == "discovery" {
            if let Some(rb) = try_match("tactic", "reconnaissance")? {
                return Ok(Some(rb));
            }
        }
    }
    // (3) repli générique '*'.
    conn.query_row("SELECT id FROM runbook WHERE active=1 AND match_kind='*' ORDER BY id LIMIT 1", [], |r| r.get(0)).optional()
}

/// Un runbook (métadonnées) en JSON. `Ok(None)` = ce runbook n'existe pas (une absence ÉTABLIE) ;
/// `Err` = la lecture n'a pas eu lieu — `P10.20-b` (rang 2) : servi `null`, ce runbook devenait une
/// recommandation VIDE sur la fiche de dossier et un en-tête de checklist SANS nom, au-dessus d'étapes
/// qui, elles, s'affichaient.
fn runbook_meta_json(conn: &Connection, rb_id: i64) -> rusqlite::Result<Option<Value>> {
    conn.query_row(
        "SELECT id,key,name,match_kind,match_key,description,managed FROM runbook WHERE id=?1",
        params![rb_id],
        |r| Ok(json!({ "id": r.get::<_,i64>(0)?, "key": r.get::<_,String>(1)?, "name": r.get::<_,String>(2)?,
            "match_kind": r.get::<_,String>(3)?, "match_key": r.get::<_,String>(4)?,
            "description": r.get::<_,String>(5)?, "managed": r.get::<_,i64>(6)? })),
    ).optional()
}

/// `P7.19-i` — LE RUNBOOK ATTACHÉ À UN CASE : LA SEULE LIGNE ADMISSIBLE, PAS LA PREMIÈRE VENUE.
///
/// LE DÉFAUT. Deux surfaces (`case_runbooks_json` -> `attached_runbook_id`, `case_steps_json` ->
/// `runbook`) lisaient `SELECT runbook_id FROM case_step WHERE incident_id=?1 LIMIT 1`, SANS ORDRE.
/// L'ensemble EST multiple par construction — `attach_runbook` écrit UNE LIGNE PAR ÉTAPE, donc un
/// case porte autant de lignes que son runbook a d'étapes — et rien dans l'énoncé ne disait laquelle
/// des N lignes devait décider. Que le `runbook_id` s'y trouve CONSTANT ne vient pas du schéma : il
/// n'y a ni contrainte d'unicité ni clé composite sur `case_step`, seulement le refus applicatif
/// `already > 0` d'`attach_runbook`. Une lecture qui se trouve rendre la bonne ligne n'est pas une
/// réponse : elle est vraie tant que l'invariant tient, muette le jour où il cède.
///
/// CE QUI EST RETENU MAINTENANT. Le runbook qui rend compte de la TOTALITÉ des étapes du case —
/// c'est-à-dire le seul admissible sous l'invariant « un runbook par case » que `attach_runbook`
/// PROMET. Le test est POSITIF (le groupe doit COUVRIR toutes les lignes ; la qualité est
/// CONSTATÉE), et la question de l'ordre ne se pose plus : l'énoncé rend AU PLUS UNE ligne par
/// construction, sans `LIMIT` et sans `ORDER BY`.
///
/// SI L'ENSEMBLE EST MULTIPLE (deux runbooks distincts sur un même case), l'énoncé rend ZÉRO ligne
/// et cette fonction rend `None` : « je ne sais pas nommer LE runbook » plutôt qu'un nom tiré au
/// sort. C'est la même loi que `P7.19-f` : refuser de publier vaut mieux que publier un nombre qu'on
/// ne sait pas lire. Les étapes, elles, restent listées — `case_steps_json` ne perd rien, il cesse
/// seulement de coiffer des étapes de DEUX runbooks du nom d'UN SEUL.
///
/// `P10.20-b` (rang 2) — ET `Err` N'EST PAS CE `None`-LÀ. Le `None` ci-dessus est un refus de NOMMER
/// ÉTABLI sur des lignes lues (l'ensemble est multiple) ; `.ok()` y versait aussi les lectures qui
/// n'avaient pas eu lieu, si bien que deux phrases opposées — « ce dossier porte deux runbooks » et « je
/// n'ai pas pu regarder » — sortaient par la même valeur, servie « aucun runbook attaché ».
fn runbook_attache(conn: &Connection, id: i64) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT cs.runbook_id FROM case_step cs WHERE cs.incident_id=?1 \
         GROUP BY cs.runbook_id \
         HAVING COUNT(*) = (SELECT COUNT(*) FROM case_step WHERE incident_id=?1)",
        params![id],
        |r| r.get::<_, i64>(0),
    )
    .optional()
}

/// Projection incident + runbook recommandé + runbooks disponibles pour un case. INTERNE (jamais client-read).
pub(crate) fn case_runbooks_json(conn: &Connection, id: i64) -> Option<Value> {
    let (tier, itype, commander): (Option<i64>, Option<String>, Option<String>) = conn
        .query_row("SELECT incident_tier,incident_type,commander FROM incident WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .ok()?;
    // `P10.7-f` (rang 4, vague b) — CE CORPS PORTE DEUX LECTURES DE LIGNES, ET L'AVEU NOMME CELLE QUI A
    // ÉCHOUÉ. C'est la forme des corps multi-listes du dépôt (`liste_bornee::corps_de_listes_illisibles`,
    // écrite à la vague A pour `knowledge_list` et `datamodels_list`, elle-même transposée du `non_etablis`
    // de `case_metrics_json` et du `non_lus` de `freshness.rs`/`fleet.rs`) : un `error` global dirait
    // « quelque chose n'a pas été lu » sans dire QUOI, et les deux moitiés de ce corps ne se remplacent pas
    // — l'une recommande, l'autre propose un choix manuel.
    //
    //   * `alertes_liees` : les alertes du dossier, d'où sortent la tactique et la technique DOMINANTES.
    //     Le nom apparaît UNIQUEMENT dans l'aveu, parce que cette liste n'est pas servie — ce sont ses
    //     DÉRIVÉS qui le sont — et c'est précisément pour cela qu'il faut la nommer : sans elle,
    //     `dominant_tactic: null` + `recommended: null` se relit « ce dossier n'a aucune alerte liée »,
    //     qui est le cas où le repli générique est LÉGITIME. Quand elle n'est pas lue, AUCUN runbook n'est
    //     recommandé : `pick_runbook_id` n'est même pas appelé, parce que recommander sur un décompte
    //     amputé, c'est dérouler la mauvaise procédure avec l'aplomb d'une procédure lue ;
    //   * `available` : le catalogue des runbooks actifs, le choix MANUEL. Un runbook avalé s'y lit
    //     « cette procédure n'existe pas », et l'analyste en écrit une à la main pendant l'incident.
    //
    // Les deux sont indépendantes : celle qui a été lue reste servie, comptée, et le lecteur sait laquelle
    // manque. Le chemin nominal ressort BYTE-IDENTIQUE (ni `error` ni `non_lus`).
    let mut non_lus: Vec<&'static str> = Vec::new();
    let (tactic, technique, targets) = match dominant_tactic_and_target(conn, id) {
        Ok(t) => t,
        Err(_) => {
            non_lus.push("alertes_liees");
            (None, None, PrefillTargets::default())
        }
    };
    // `P10.20-b` (rang 2) — LA RECOMMANDATION EST ÉTABLIE, OU ELLE DIT QU'ELLE NE L'EST PAS. Deux lectures
    // la composent — le CHOIX du runbook (`pick_runbook_id`) et sa FICHE (`runbook_meta_json`) —, et l'aveu
    // les distingue : dans un cas aucun runbook n'a pu être retenu, dans l'autre un runbook a été retenu et
    // c'est sa fiche qui manque. Le `null` servi est le MÊME ; ce qui change est la phrase posée à côté, et
    // ce que l'exploitant doit aller regarder. Ni l'un ni l'autre ne pose `recommended` dans `non_lus` : ce
    // champ est un OBJET, et `corps_de_listes_illisibles` y écrirait `[]` — une liste vide n'est pas la
    // forme d'une recommandation absente.
    let mut recommandation_non_etablie: Option<String> = None;
    let recommended = if non_lus.is_empty() {
        match pick_runbook_id(conn, tactic.as_deref(), technique.as_deref()) {
            Ok(Some(rb)) => match runbook_meta_json(conn, rb) {
                Ok(fiche) => fiche,
                Err(e) => {
                    recommandation_non_etablie =
                        Some(format!("{CAUSE_RECOMMANDATION_NON_ETABLIE}un runbook a été retenu, sa fiche n'a pas été lue : {e}"));
                    None
                }
            },
            // AUCUN runbook actif ne correspond : une absence ÉTABLIE, le cas nominal d'une base sans seed.
            Ok(None) => None,
            Err(e) => {
                recommandation_non_etablie = Some(format!("{CAUSE_RECOMMANDATION_NON_ETABLIE}{e}"));
                None
            }
        }
    } else {
        None
    };
    // `P7.19-i` — LA seule ligne admissible, pas la première venue. `P10.20-b` — et une lecture ratée
    // n'est pas cette ligne-là non plus.
    let (attached, attachement_non_lu) = match runbook_attache(conn, id) {
        Ok(rb) => (rb, None),
        Err(e) => (None, Some(format!("{CAUSE_RUNBOOK_ATTACHE_NON_LU}{e}"))),
    };
    let disponibles: rusqlite::Result<Vec<Value>> = conn
        .prepare("SELECT id,key,name,match_kind,match_key,description,managed FROM runbook WHERE active=1 ORDER BY (match_kind='*'), id")
        .and_then(|mut s| {
            s.query_map([], |r| Ok(json!({
                "id": r.get::<_,i64>(0)?, "key": r.get::<_,String>(1)?, "name": r.get::<_,String>(2)?,
                "match_kind": r.get::<_,String>(3)?, "match_key": r.get::<_,String>(4)?, "description": r.get::<_,String>(5)?,
                "managed": r.get::<_,i64>(6)? })))?
                .collect::<rusqlite::Result<Vec<_>>>()
        });
    let available = match disponibles {
        Ok(v) => v,
        Err(_) => {
            non_lus.push("available");
            Vec::new()
        }
    };
    let mut corps = json!({
        "incident_tier": tier, "incident_type": itype, "commander": commander,
        "dominant_tactic": tactic, "dominant_technique": technique,
        // `prefill_target` = host best-effort (rétrocompat UI Phase 1/2) ; #3 P3-A ajoute les cibles STRUCTURÉES
        // par-entité (le pré-remplissage réel PAR ACTION est fait côté serveur dans attach_runbook).
        "prefill_target": targets.host,
        "prefill_src_ip": targets.src_ip, "prefill_pid": targets.pid, "prefill_host": targets.host,
        "recommended": recommended, "attached_runbook_id": attached, "available": available,
    });
    // `P10.20-b` (rang 2) — LES DEUX AVEUX SONT STRICTEMENT CONDITIONNELS : sur un corps dont les deux
    // lectures ont abouti, aucune des deux clés n'existe, et la réponse est byte-identique à celle d'avant
    // cette clé. Un aveu qui serait toujours là n'avouerait rien.
    if let Some(o) = corps.as_object_mut() {
        if let Some(cause) = recommandation_non_etablie {
            o.insert("recommandation_non_etablie".to_string(), json!(cause));
        }
        if let Some(cause) = attachement_non_lu {
            o.insert("runbook_attache_non_lu".to_string(), json!(cause));
        }
    }
    Some(crate::handlers::liste_bornee::corps_de_listes_illisibles(corps, &non_lus))
}

/// INSTANCIE (fige) les steps d'un runbook en `case_step` pour un incident + pré-remplit la cible PAR ACTION
/// (#3 P3-A). Idempotent-refusant : si des steps existent DÉJÀ pour ce case (un runbook déjà attaché), renvoie
/// false (on n'écrase pas une progression en cours ; le détacher/ré-attacher serait une action explicite future).
/// Écrit un item timeline 'runbook' + ledger. false si le runbook ou le case n'existe pas.
///
/// #3 P3-A — PRÉ-REMPLISSAGE PAR `action_kind` (remplace le seul `host` appliqué à TOUTE step de Phase 1/2) :
///  - step `response` `ban_ip`/`unban_ip` -> `target := src_ip` (validé `action_valid_ctx`, sinon blanc) ;
///  - step `response` `kill_pid`          -> `target := pid` (validé, sinon blanc) + `host := targets.host` (hôte
///                                            d'exécution figé sur la step) ;
///  - step `response` `stop_service`      -> blanc (aucune source CIM ; l'analyste fournit le nom de service) ;
///  - step `search`/`manual`              -> `target := host` best-effort (PARITÉ Phase 1/2, inchangé).
/// Le prefill n'est qu'une SUGGESTION : l'analyste confirme/édite, et l'exécution reste /api/actions (arm +
/// approbation + admin-gate + ledger + allowlist root + observe/active + re-validation `action_valid_ctx`). Une
/// cible NULL/invalide ne s'auto-joue JAMAIS et est re-validée à la porte -> aucune nouvelle surface d'exécution.
pub(crate) fn attach_runbook(conn: &Connection, id: i64, runbook_id: i64, author: &str, targets: &PrefillTargets) -> Result<i64, String> {
    if conn.query_row("SELECT 1 FROM incident WHERE id=?1", params![id], |_| Ok(())).is_err() {
        return Err("incident introuvable".into());
    }
    let already: i64 = conn.query_row("SELECT COUNT(*) FROM case_step WHERE incident_id=?1", params![id], |r| r.get(0)).unwrap_or(0);
    if already > 0 {
        return Err("un runbook est déjà attaché à cet incident (progression existante)".into());
    }
    let (rb_name, rb_active): (String, i64) = conn
        .query_row("SELECT name,active FROM runbook WHERE id=?1", params![runbook_id], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(|_| "runbook introuvable".to_string())?;
    if rb_active == 0 {
        return Err("runbook inactif".into());
    }
    let steps: Vec<(i64, i64, String, String, String, String, Option<String>, Option<String>)> = conn
        .prepare("SELECT id,ordinal,phase,title,guidance,step_kind,search_soql,action_kind FROM runbook_step WHERE runbook_id=?1 ORDER BY ordinal,id")
        .and_then(|mut s| s.query_map(params![runbook_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)))?.collect::<rusqlite::Result<Vec<_>>>())
        // `P10.7-f` (lot 106) — les étapes se lisent EN BLOC : une liste tronquée par une ligne en erreur
        // attacherait un runbook AMPUTÉ en l'annonçant complet. La lecture ratée est un refus nommé.
        .map_err(|e| format!("étapes du runbook NON LUES : {e}"))?;
    if steps.is_empty() {
        return Err("runbook sans étape".into());
    }
    let host = targets.host.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let mut n = 0i64;
    for (step_id, ordinal, phase, title, guidance, step_kind, soql, act) in &steps {
        // #3 P3-A — cible + hôte PAR action_kind (validés ; blanc plutôt qu'une cible invalide/trompeuse).
        let (step_target, step_host): (Option<&str>, Option<&str>) = if step_kind == "response" {
            match act.as_deref() {
                Some(k @ ("ban_ip" | "unban_ip")) => (valid_prefill(k, targets.src_ip.as_deref()), None),
                Some("kill_pid") => (valid_prefill("kill_pid", targets.pid.as_deref()), host),
                _ => (None, None), // stop_service / inconnu : aucune source CIM -> blanc
            }
        } else {
            // search / manual : host best-effort (résout $target$ au mieux ; PARITÉ Phase 1/2).
            (host, None)
        };
        let _ = conn.execute(
            "INSERT INTO case_step(incident_id,runbook_id,step_id,ordinal,phase,title,guidance,step_kind,search_soql,action_kind,target,host,status) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'pending')",
            params![id, runbook_id, step_id, ordinal, phase, title, guidance, step_kind, soql, act, step_target, step_host],
        );
        n += 1;
    }
    case_add_item(conn, id, now(), "runbook", author, &format!("runbook « {rb_name} » attaché ({n} étapes)"), None);
    ledger_append(conn, "case.runbook_attach", &format!("#{id} runbook={runbook_id} '{rb_name}' steps={n} by {author}"));
    Ok(n)
}

/// Steps d'un incident + progression (par phase). INTERNE. `{steps, progress, runbook}` ; vide si aucun runbook.
///
/// `P10.7-f` (rang 3) — LA PROGRESSION MENTAIT AVEC LA LISTE, et c'est ce qui range ce site au rang des
/// comptes servis comme des faits. `progress.total` est DÉRIVÉ de `steps.len()` : la lecture s'écrivait
/// `.map(|x| x.flatten().collect()).unwrap_or_default()`, donc une étape dont le mappeur échoue (un blob
/// dans `phase`/`title`, une colonne qu'une migration vient d'ajouter, un cache de schéma de pool
/// périmé) disparaissait de `steps` ET du dénominateur — « 4 étapes sur 4, terminé » au-dessus d'une
/// procédure de réponse à incident amputée d'une étape, la lecture la plus dangereuse que cette vue
/// puisse produire. Une préparation ratée était pire encore : `unwrap_or_default()` rendait `0/0`.
///
/// DÉSORMAIS : le parcours est soldé en bloc (`collect::<rusqlite::Result<Vec<_>>>()`) et une lecture
/// ratée sert l'aveu sous la forme du dépôt — `liste_bornee::corps_de_liste_illisible` pose `steps: []`
/// (la clé EXISTE, vide : un client qui lit `j.steps.length` continue de fonctionner) et `error` nomme
/// la cause. `progress` DÉRIVE de la liste non lue : il vaut `null`, JAMAIS `{total:0,done:0,skipped:0}`
/// qui se lirait « ce case n'a aucune étape, et c'est établi » — exactement comme `netban.active` et
/// `field-filters.matrix` du rang 1. `runbook` vient d'une AUTRE lecture et reste servi tel quel.
pub(crate) fn case_steps_json(conn: &Connection, id: i64) -> Value {
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare("SELECT id,step_id,ordinal,phase,title,guidance,step_kind,COALESCE(search_soql,''),COALESCE(action_kind,''),COALESCE(target,''),status,COALESCE(actor,''),ts,COALESCE(note,''),COALESCE(host,'') \
                  FROM case_step WHERE incident_id=?1 ORDER BY ordinal,id")
        .and_then(|mut s| s.query_map(params![id], |r| Ok(json!({
            "id": r.get::<_,i64>(0)?, "step_id": r.get::<_,i64>(1)?, "ordinal": r.get::<_,i64>(2)?,
            "phase": r.get::<_,String>(3)?, "title": r.get::<_,String>(4)?, "guidance": r.get::<_,String>(5)?,
            "step_kind": r.get::<_,String>(6)?, "search_soql": r.get::<_,String>(7)?, "action_kind": r.get::<_,String>(8)?,
            "target": r.get::<_,String>(9)?, "status": r.get::<_,String>(10)?, "actor": r.get::<_,String>(11)?,
            "ts": r.get::<_,Option<i64>>(12)?, "note": r.get::<_,String>(13)?,
            // #3 P3-A — hôte d'exécution figé (kill_pid) ; "" quand non pertinent (parité).
            "host": r.get::<_,String>(14)? })))?
            .collect::<rusqlite::Result<Vec<_>>>());
    // `P7.19-i` — LA seule ligne admissible (cf. `runbook_attache`) ; `null` si le case porte des
    // étapes de DEUX runbooks, plutôt qu'un en-tête tiré au sort au-dessus d'étapes mélangées.
    // `P10.20-b` (rang 2) — et `null` SANS un mot quand l'une des deux lectures n'a pas eu lieu était la
    // pire forme sur cette surface : les ÉTAPES, elles, s'affichent (elles viennent d'une autre lecture),
    // donc l'analyste voyait une checklist SANS nom de procédure et concluait qu'elle n'en avait pas.
    let (runbook, runbook_non_lu) = match runbook_attache(conn, id)
        .and_then(|rb| match rb {
            Some(rb_id) => runbook_meta_json(conn, rb_id),
            None => Ok(None),
        }) {
        Ok(fiche) => (fiche, None),
        Err(e) => (None, Some(format!("{CAUSE_RUNBOOK_ATTACHE_NON_LU}{e}"))),
    };
    let steps = match lues {
        Ok(v) => v,
        // LA LISTE N'A PAS ÉTÉ LUE : ni étapes, ni progression. Le corps garde sa forme et DIT pourquoi.
        Err(_) => {
            let mut sans_etapes = crate::handlers::liste_bornee::corps_de_liste_illisible(
                json!({ "progress": Value::Null, "runbook": runbook }),
                "steps",
            );
            // Les DEUX lectures peuvent manquer à la fois, et elles ne se remplacent pas : `error` parle
            // des ÉTAPES, `runbook_non_lu` de l'EN-TÊTE.
            if let Some(cause) = runbook_non_lu {
                sans_etapes["runbook_non_lu"] = json!(cause);
            }
            return sans_etapes;
        }
    };
    let total = steps.len() as i64;
    let done = steps.iter().filter(|s| s.get("status").and_then(|v| v.as_str()) == Some("done")).count() as i64;
    let skipped = steps.iter().filter(|s| s.get("status").and_then(|v| v.as_str()) == Some("skipped")).count() as i64;
    let mut corps = json!({ "steps": steps, "progress": { "total": total, "done": done, "skipped": skipped }, "runbook": runbook });
    if let Some(cause) = runbook_non_lu {
        corps["runbook_non_lu"] = json!(cause);
    }
    corps
}

/// AVANCE une step (done/skipped/pending) d'un incident + trace timeline 'step' + ledger. Anti-IDOR : la step
/// DOIT appartenir au case (incident_id=?1). false si absente/non-appartenante ou statut invalide.
pub(crate) fn step_advance(conn: &Connection, id: i64, step_id: i64, status: &str, actor: &str, note: Option<&str>) -> bool {
    let Some(st) = norm_step_status(status) else { return false; };
    // step_id ICI = case_step.id (progression), borné au case.
    let title: String = match conn.query_row("SELECT title FROM case_step WHERE id=?1 AND incident_id=?2", params![step_id, id], |r| r.get(0)) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let t = now();
    let note_s = note.map(str::trim).filter(|s| !s.is_empty());
    let _ = conn.execute(
        "UPDATE case_step SET status=?1, actor=?2, ts=?3, note=?4 WHERE id=?5 AND incident_id=?6",
        params![st, actor, t, note_s, step_id, id],
    );
    let body = match st {
        "done" => format!("étape « {title} » marquée FAITE"),
        "skipped" => format!("étape « {title} » IGNORÉE{}", note_s.map(|n| format!(" — {n}")).unwrap_or_default()),
        _ => format!("étape « {title} » remise EN ATTENTE"),
    };
    case_add_item(conn, id, t, "step", actor, &body, None);
    ledger_append(conn, "case.step", &format!("#{id} step={step_id} -> {st} by {actor}"));
    true
}

/// RÉSOUT le gabarit GXQL d'une step 'search' pour une valeur concrète (défaut = cible pré-remplie), EXACTEMENT
/// comme workflow_action_resolve `search` : substitution `$target$` -> valeur SANITISÉE (scalaire), puis
/// RECOMPILATION par le compilateur FERMÉ (jamais de SQL brut ; l'enum/masque s'appliquent à l'exécution via
/// /api/query). Renvoie le GXQL de navigation. Err si step absente/non-search/valeur interdite/GXQL invalide.
pub(crate) fn resolve_step_search(conn: &Connection, id: i64, step_id: i64, value_override: Option<&str>) -> Result<String, String> {
    let (kind, soql, target): (String, Option<String>, Option<String>) = conn
        .query_row("SELECT step_kind,search_soql,target FROM case_step WHERE id=?1 AND incident_id=?2", params![step_id, id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(|_| "étape introuvable".to_string())?;
    if kind != "search" {
        return Err("cette étape n'est pas une recherche".into());
    }
    let template = soql.filter(|s| !s.trim().is_empty()).ok_or_else(|| "aucun gabarit de recherche sur cette étape".to_string())?;
    let value = value_override.map(str::trim).filter(|s| !s.is_empty())
        .or(target.as_deref().map(str::trim).filter(|s| !s.is_empty()));
    let soql_out = match value {
        Some(v) => {
            // MÊME prédicat de sanitisation que workflow_actions (anti-injection de fragment GXQL).
            if !crate::handlers::workflow_actions::value_scalar_ok(v) {
                return Err("valeur non substituable (caractère interdit)".into());
            }
            template.replace("$target$", v)
        }
        // pas de cible -> on laisse `$target$` que le compilateur REJETTERA (l'UI demandera une valeur).
        None => template.clone(),
    };
    // Compile-check FERMÉ (standalone OU préfixé `search`), comme validate_workflow_action.
    if guatx_core::soql::to_sql(&soql_out, 0, 0, &guatx_core::soql::Schema::events()).is_ok() {
        return Ok(soql_out);
    }
    let wrapped = format!("search {soql_out}");
    if guatx_core::soql::to_sql(&wrapped, 0, 0, &guatx_core::soql::Schema::events()).is_err() {
        return Err("GXQL de navigation invalide (fournir une cible concrète)".into());
    }
    Ok(wrapped)
}

// ---------------------------------------------------------------------------------------------------------
// HANDLERS HTTP — tous sous /api/cases/* -> héritent de l'AUTZ case existante (route_min_role) : mutation =
// editor+ (comme le statut/l'assignation d'un case), lecture = viewer+. AUCUNE autz de réponse n'est touchée :
// une step response se joue via /api/actions (admin + arm + approbation + ledger), JAMAIS ici.
// ---------------------------------------------------------------------------------------------------------

/// POST /api/cases/{id}/incident — DÉCLARE (tier) / RÉTROGRADE (demote) un case en incident + type/commander.
/// editor+ (miroir du statut/assignation d'un case). Body : {tier?, incident_type?, commander?, demote?}.
pub(crate) async fn incident_set(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> StatusCode {
    let demote = b.get("demote").and_then(|v| v.as_bool()).unwrap_or(false);
    let tier: Option<i64> = if demote {
        None
    } else {
        // tier par défaut = 1 (déclaré) ; borné 1..4 s'il est fourni.
        Some(b.get("tier").and_then(|v| v.as_i64()).unwrap_or(1).clamp(1, 4))
    };
    let itype = b.get("incident_type").and_then(|v| v.as_str());
    let commander = b.get("commander").and_then(|v| v.as_str());
    with_write(&st, &au, |conn| {
        if incident_apply_tier(&conn, id, &au.name, tier, itype, commander) {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::NOT_FOUND
        }
    })
}

/// GET /api/cases/{id}/runbooks — incident + runbook recommandé (tactique dominante) + disponibles. viewer+.
pub(crate) async fn case_runbooks_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    match case_runbooks_json(&conn, id) {
        Some(v) => Json(v).into_response(),
        None => (StatusCode::NOT_FOUND, "incident introuvable").into_response(),
    }
}

/// POST /api/cases/{id}/runbook — ATTACHE un runbook (instancie ses steps). editor+. Body : {runbook_id}.
/// La cible pré-remplie est dérivée de l'alerte dominante (best-effort) côté serveur.
pub(crate) async fn case_runbook_attach(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    let runbook_id = match b.get("runbook_id").and_then(|v| v.as_i64()) {
        Some(r) => r,
        None => return bad_req("runbook_id requis"),
    };
    crate::req_conn!(st, au, conn);
    // `P10.7-f` (rang 4, vague b) — ON N'ATTACHE PAS UN RUNBOOK SUR DES ALERTES QU'ON N'A PAS LUES. Ce
    // geste FIGE les étapes dans `case_step` et il est idempotent-REFUSANT : une progression existante
    // n'est jamais écrasée, donc des cibles pré-remplies à partir d'un échantillon amputé ne se corrigent
    // pas par un second essai. C'est le raisonnement de la capture d'instantané à la vague A — produit
    // figé, donc refus plutôt qu'aveu embarqué —, et `attach_runbook` REFUSE déjà, dans ce même esprit,
    // quand les étapes du runbook ne se lisent pas. Le refus est nommé et n'écrit RIEN ; l'appelant
    // réessaie.
    let targets = match dominant_tactic_and_target(&conn, id) {
        Ok((_, _, t)) => t,
        Err(_) => {
            return err_json(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("attachement REFUSÉ : {}", crate::handlers::liste_bornee::CAUSE_LISTE_ILLISIBLE),
            )
        }
    };
    match attach_runbook(&conn, id, runbook_id, &au.name, &targets) {
        Ok(n) => Json(json!({ "attached": n })).into_response(),
        Err(e) => bad_req(e),
    }
}

/// GET /api/cases/{id}/steps — steps de l'incident + progression. viewer+.
pub(crate) async fn case_steps_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    Json(case_steps_json(&conn, id))
}

/// POST /api/cases/{id}/steps/{step_id} — AVANCE/skip une step (+ note). editor+. Body : {status, note?}.
pub(crate) async fn case_step_set(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path((id, step_id)): Path<(i64, i64)>, Json(b): Json<Value>) -> StatusCode {
    let status = b.str_field("status");
    let note = b.get("note").and_then(|v| v.as_str());
    with_write(&st, &au, |conn| {
        if step_advance(&conn, id, step_id, status, &au.name, note) {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::NOT_FOUND
        }
    })
}

/// GET /api/cases/{id}/steps/{step_id}/search[?value=] — RÉSOUT le GXQL d'une step 'search' (recompilé, masqué à
/// l'exécution via /api/query). viewer+ (readonly_post-like GET). Ne déclenche RIEN.
pub(crate) async fn case_step_search(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path((id, step_id)): Path<(i64, i64)>, Query(q): Query<HashMap<String, String>>) -> Response {
    let value = q.get("value").map(|s| s.as_str());
    crate::req_conn!(st, au, conn);
    match resolve_step_search(&conn, id, step_id, value) {
        Ok(soql) => Json(json!({ "kind": "search", "soql": soql })).into_response(),
        Err(e) => bad_req(e),
    }
}

// =========================================================================================================
// PHASE 2 — RUNBOOKS CUSTOM (bring-your-own), CRUD ADMIN, PAR-TENANT. Coexistent avec les ~5+ gabarits MANAGÉS
// (managed=1, seedés par git). DOCTRINE detection_override RÉPLIQUÉE :
//   - un runbook managé=1 (git = baseline) est IMMUTABLE en place : on ne peut ni éditer ses étapes ni le
//     supprimer. SEULES actions permises : ACTIVER/DÉSACTIVER (bascule `active`, override persistant survivant
//     au reboot — le re-seed est INSERT-si-absent par `key`, il ne ré-active JAMAIS un managé désactivé) et
//     CLONER-pour-personnaliser (crée une COPIE managed=0 que l'admin possède/édite).
//   - CRUD complet (éditer étapes / supprimer) UNIQUEMENT sur les runbooks CUSTOM (managed=0).
//   - AUCUN chemin ne laisse un custom se faire passer pour un managé : `managed` est CÂBLÉ à 0 à la création,
//     la `key` custom est TOUJOURS préfixée `custom-` (jamais fournie par le client), l'update refuse managed=1.
// SÉCURITÉ (surface admin-authored) :
//   - step SEARCH : le gabarit GXQL `$target$` passe par le COMPILATEUR FERMÉ guatx_core::soql::to_sql au
//     TEMPS-AUTEUR (rejet si non compilable / SQL brut / injection) ET au TEMPS-RÉSOLUTION (resolve_step_search,
//     value_scalar_ok + recompilation). Masquage + tenant-scoping s'appliquent à l'exécution via /api/query,
//     EXACTEMENT comme une step managée. Un admin ne peut PAS contourner le masque, lire cross-tenant, ni injecter.
//   - step RESPONSE : `action_kind` DOIT être dans l'ENUM FERMÉ (action_kind_valid : ban_ip/unban_ip/kill_pid/
//     stop_service) — rejeté au temps-auteur sinon. L'EXÉCUTION reste /api/actions INCHANGÉ (arm+approbation+
//     admin-gate+ledger+allowlist root+observe/active). Créer un runbook n'accorde AUCUN privilège d'exécution
//     ni auto-exec ; un custom NE PEUT PAS embarquer une commande arbitraire.
//   - DoS : nb de runbooks custom + nb d'étapes/runbook + longueurs de champ BORNÉS.
// PARITÉ MODE 0 : aucun runbook custom créé -> GET /api/runbooks ne liste que les managés, les endpoints
// existants sont inchangés. Ces tables/champs NE FIGURENT JAMAIS dans la projection client-read (client_case_*).
// =========================================================================================================

/// Bornes anti-DoS (surface admin-authored, mais bornée : pas de création illimitée).
const RUNBOOK_MAX_CUSTOM: i64 = 200;   // runbooks custom par tenant
const RUNBOOK_MAX_STEPS: usize = 50;   // étapes par runbook
const RUNBOOK_MAX_NAME: usize = 200;
const RUNBOOK_MAX_KEY: usize = 80;
const RUNBOOK_MAX_DESC: usize = 2000;
const RUNBOOK_MAX_MATCHKEY: usize = 80;
const RUNBOOK_MAX_TITLE: usize = 300;
const RUNBOOK_MAX_GUIDANCE: usize = 2000;
const RUNBOOK_MAX_SOQL: usize = 2000;

/// Phase CANONIQUE d'une étape (enum FERMÉ, aligné sur le seed managé).
pub(crate) fn valid_phase(p: &str) -> bool {
    matches!(p, "triage" | "investigation" | "containment" | "eradication" | "recovery")
}
/// Genre d'étape CANONIQUE (enum FERMÉ).
pub(crate) fn valid_step_kind(k: &str) -> bool {
    matches!(k, "manual" | "search" | "response")
}

/// TEMPS-AUTEUR — VALIDE un gabarit GXQL de step 'search' AVANT persistance, EXACTEMENT comme
/// validate_workflow_action `search` (dummy-substitution de `$target$` par un scalaire sûr, puis compile-check
/// par le COMPILATEUR FERMÉ, standalone OU préfixé `search`). Rejette tout ce qui n'est PAS du GXQL compilable
/// (SQL brut, injection, pipe malformé…). Le compilateur étant fermé, aucun gabarit ne peut produire du SQL brut.
pub(crate) fn validate_search_template(tpl: &str) -> Result<(), String> {
    let dummy = tpl.replace("$target$", "x1");
    if guatx_core::soql::to_sql(&dummy, 0, 0, &guatx_core::soql::Schema::events()).is_ok() {
        return Ok(());
    }
    guatx_core::soql::to_sql(&format!("search {dummy}"), 0, 0, &guatx_core::soql::Schema::events())
        .map(|_| ()).map_err(|e| format!("gabarit search non compilable : {e}"))
}

/// TEMPS-AUTEUR — normalise+valide (match_kind, match_key) : 'tactic' -> tactique ATT&CK connue ; 'technique' ->
/// technique parente T#### ; '*' -> repli générique (match_key vidé). Rejette tout autre kind.
fn validate_match(mkind: &str, mkey: &str) -> Result<(String, String), String> {
    if mkey.len() > RUNBOOK_MAX_MATCHKEY { return Err("match_key trop long".into()); }
    match mkind {
        "*" => Ok(("*".to_string(), String::new())),
        "tactic" => {
            let k = mkey.trim().to_ascii_lowercase();
            if guatx_core::attack::TACTICS.contains(&k.as_str()) { Ok(("tactic".to_string(), k)) }
            else { Err(format!("tactique ATT&CK inconnue : {mkey}")) }
        }
        "technique" => {
            let t = guatx_core::attack::parent_technique(mkey).ok_or_else(|| format!("technique invalide (format T####) : {mkey}"))?;
            Ok(("technique".to_string(), t))
        }
        _ => Err(format!("match_kind invalide (tactic|technique|*) : {mkind}")),
    }
}

/// Étape normalisée+validée (temps-auteur) : (phase, title, guidance, step_kind, search_soql, action_kind).
pub(crate) type NewStep = (String, String, String, String, Option<String>, Option<String>);

/// TEMPS-AUTEUR — valide UNE étape JSON. Referme les enums (phase/step_kind), borne les longueurs, et surtout :
///  - step 'search' -> le gabarit GXQL passe le COMPILATEUR FERMÉ (validate_search_template) ;
///  - step 'response' -> action_kind DANS l'ENUM FERMÉ (action_kind_valid) ; JAMAIS de commande arbitraire.
/// Les champs hors-genre sont NEUTRALISÉS (une step manual/search ne porte pas d'action_kind, etc.).
fn validate_step(v: &Value) -> Result<NewStep, String> {
    let phase = v.str_field("phase").trim().to_string();
    if !valid_phase(&phase) { return Err(format!("phase invalide (triage|investigation|containment|eradication|recovery) : {phase}")); }
    let title = v.str_field("title").trim().to_string();
    if title.is_empty() { return Err("titre d'étape requis".into()); }
    if title.len() > RUNBOOK_MAX_TITLE { return Err("titre d'étape trop long".into()); }
    let guidance = v.str_field("guidance").trim().to_string();
    if guidance.len() > RUNBOOK_MAX_GUIDANCE { return Err("guidance trop longue".into()); }
    let step_kind = v.str_field("step_kind").trim().to_string();
    if !valid_step_kind(&step_kind) { return Err(format!("step_kind invalide (manual|search|response) : {step_kind}")); }
    let (soql, act) = match step_kind.as_str() {
        "search" => {
            let s = v.str_field("search_soql").trim().to_string();
            if s.is_empty() { return Err("search_soql requis pour une étape 'search'".into()); }
            if s.len() > RUNBOOK_MAX_SOQL { return Err("search_soql trop long".into()); }
            validate_search_template(&s)?; // COMPILATEUR FERMÉ (temps-auteur)
            (Some(s), None)
        }
        "response" => {
            let a = v.str_field("action_kind").trim().to_string();
            action_kind_valid(&a)?; // ENUM D'ACTION FERMÉ (temps-auteur) ; l'exécution reste /api/actions
            (None, Some(a))
        }
        _ => (None, None), // manual : ni GXQL ni action
    };
    Ok((phase, title, guidance, step_kind, soql, act))
}

/// TEMPS-AUTEUR — parse+valide la charge utile d'un runbook custom : name, (match_kind,match_key), description,
/// steps[]. Referme tout ; borne les longueurs et le NOMBRE d'étapes (DoS). Retourne les données prêtes à écrire.
fn parse_runbook_payload(b: &Value) -> Result<(String, String, String, String, Vec<NewStep>), String> {
    let name = b.str_field("name").trim().to_string();
    if name.is_empty() { return Err("nom de runbook requis".into()); }
    if name.len() > RUNBOOK_MAX_NAME { return Err("nom trop long".into()); }
    let desc = b.str_field("description").trim().to_string();
    if desc.len() > RUNBOOK_MAX_DESC { return Err("description trop longue".into()); }
    let (mkind, mkey) = validate_match(b.str_field("match_kind").trim(), b.str_field("match_key").trim())?;
    let arr = b.get("steps").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if arr.is_empty() { return Err("au moins une étape requise".into()); }
    if arr.len() > RUNBOOK_MAX_STEPS { return Err(format!("trop d'étapes (max {RUNBOOK_MAX_STEPS})")); }
    let mut steps = Vec::with_capacity(arr.len());
    for (i, s) in arr.iter().enumerate() {
        steps.push(validate_step(s).map_err(|e| format!("étape #{}: {e}", i + 1))?);
    }
    Ok((name, mkind, mkey, desc, steps))
}

/// Slug ASCII sûr pour dériver une `key` custom d'un nom (jamais fournie par le client -> pas de masquerade).
fn slugify(name: &str) -> String {
    let mut s: String = name.trim().to_ascii_lowercase().chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    while s.contains("--") { s = s.replace("--", "-"); }
    let s = s.trim_matches('-').to_string();
    if s.is_empty() { "runbook".to_string() } else { s }
}

/// `key` custom UNIQUE, TOUJOURS préfixée `custom-` (provenance explicite ; NE PEUT collisionner avec une key
/// managée ni s'y faire passer). Bornée. Fallback horodaté si saturation improbable.
fn unique_custom_key(conn: &Connection, name: &str) -> String {
    let base = slugify(name);
    let mut k = format!("custom-{base}");
    if k.len() > RUNBOOK_MAX_KEY { k.truncate(RUNBOOK_MAX_KEY); }
    let mut n = 1;
    while conn.query_row("SELECT 1 FROM runbook WHERE key=?1", params![k], |_| Ok(())).is_ok() {
        k = format!("custom-{base}-{n}");
        if k.len() > RUNBOOK_MAX_KEY { k = format!("custom-{}-{n}", now()); }
        n += 1;
        if n > 5000 { k = format!("custom-{}", now()); break; }
    }
    k
}

/// Un runbook (métadonnées + nb d'étapes) pour la vue d'AUTHORING admin. INTERNE (jamais client-read).
fn runbook_admin_json(conn: &Connection, rb_id: i64) -> Option<Value> {
    conn.query_row(
        "SELECT id,key,name,match_kind,match_key,description,managed,active,created,\
         (SELECT COUNT(*) FROM runbook_step WHERE runbook_id=runbook.id) FROM runbook WHERE id=?1",
        params![rb_id],
        |r| Ok(json!({ "id": r.get::<_,i64>(0)?, "key": r.get::<_,String>(1)?, "name": r.get::<_,String>(2)?,
            "match_kind": r.get::<_,String>(3)?, "match_key": r.get::<_,String>(4)?, "description": r.get::<_,String>(5)?,
            "managed": r.get::<_,i64>(6)?, "active": r.get::<_,i64>(7)? != 0, "created": r.get::<_,i64>(8)?,
            "steps": r.get::<_,i64>(9)? })),
    ).ok()
}

/// CŒUR testable — CRÉE un runbook CUSTOM (managed=0, active=1). `key` générée (préfixe custom-), steps validées
/// par l'appelant. Écrit runbook + steps ; renvoie l'id. Borne le NOMBRE de customs (DoS). Pas d'AppState.
pub(crate) fn create_custom_runbook(conn: &Connection, name: &str, mkind: &str, mkey: &str, desc: &str, steps: &[NewStep], active: bool) -> Result<i64, String> {
    let cnt: i64 = conn.query_row("SELECT COUNT(*) FROM runbook WHERE managed=0", [], |r| r.get(0)).unwrap_or(0);
    if cnt >= RUNBOOK_MAX_CUSTOM { return Err(format!("quota de runbooks custom atteint (max {RUNBOOK_MAX_CUSTOM})")); }
    let key = unique_custom_key(conn, name);
    conn.execute(
        "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES(?1,?2,?3,?4,?5,0,?6,?7)",
        params![key, name, mkind, mkey, desc, active as i64, now()],
    ).map_err(|e| format!("insertion runbook: {e}"))?;
    let rb_id = conn.last_insert_rowid();
    insert_steps(conn, rb_id, steps);
    Ok(rb_id)
}

/// Écrit les étapes ordonnées d'un runbook (ordinal = position). Champs hors-genre déjà neutralisés par validate_step.
fn insert_steps(conn: &Connection, rb_id: i64, steps: &[NewStep]) {
    for (i, (phase, title, guidance, kind, soql, act)) in steps.iter().enumerate() {
        let _ = conn.execute(
            "INSERT INTO runbook_step(runbook_id,ordinal,phase,title,guidance,step_kind,search_soql,action_kind) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![rb_id, i as i64, phase, title, guidance, kind, soql, act],
        );
    }
}

/// CŒUR testable — MET À JOUR un runbook CUSTOM en place (remplace name/match/description + toutes les étapes).
/// REFUSE un runbook managed=1 (baseline git immuable en place). false si introuvable/managé.
pub(crate) fn update_custom_runbook(conn: &Connection, rb_id: i64, name: &str, mkind: &str, mkey: &str, desc: &str, steps: &[NewStep]) -> Result<(), String> {
    let managed: i64 = conn.query_row("SELECT managed FROM runbook WHERE id=?1", params![rb_id], |r| r.get(0)).map_err(|_| "runbook introuvable".to_string())?;
    if managed != 0 { return Err("runbook managé (git) : non modifiable en place — clonez pour personnaliser".into()); }
    conn.execute("UPDATE runbook SET name=?1, match_kind=?2, match_key=?3, description=?4 WHERE id=?5 AND managed=0",
        params![name, mkind, mkey, desc, rb_id]).map_err(|e| format!("update: {e}"))?;
    let _ = conn.execute("DELETE FROM runbook_step WHERE runbook_id=?1", params![rb_id]);
    insert_steps(conn, rb_id, steps);
    Ok(())
}

/// CŒUR testable — CLONE un runbook (managé OU custom) en une COPIE managed=0 que l'admin possède. Copie les
/// étapes verbatim (source de confiance : managé=seed validé, ou custom=déjà validé). None si source introuvable.
pub(crate) fn clone_runbook(conn: &Connection, src_id: i64, new_name: Option<&str>) -> Result<i64, String> {
    let (sname, mkind, mkey, desc): (String, String, String, String) = conn
        .query_row("SELECT name,match_kind,match_key,description FROM runbook WHERE id=?1", params![src_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(|_| "runbook source introuvable".to_string())?;
    let cnt: i64 = conn.query_row("SELECT COUNT(*) FROM runbook WHERE managed=0", [], |r| r.get(0)).unwrap_or(0);
    if cnt >= RUNBOOK_MAX_CUSTOM { return Err(format!("quota de runbooks custom atteint (max {RUNBOOK_MAX_CUSTOM})")); }
    let name = new_name.map(str::trim).filter(|s| !s.is_empty()).map(|s| s.to_string()).unwrap_or_else(|| format!("{sname} (copie)"));
    let name = if name.len() > RUNBOOK_MAX_NAME { name.chars().take(RUNBOOK_MAX_NAME).collect() } else { name };
    let key = unique_custom_key(conn, &name);
    conn.execute("INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES(?1,?2,?3,?4,?5,0,1,?6)",
        params![key, name, mkind, mkey, desc, now()]).map_err(|e| format!("insertion clone: {e}"))?;
    let new_id = conn.last_insert_rowid();
    // copie des étapes (ordinal préservé).
    let _ = conn.execute(
        "INSERT INTO runbook_step(runbook_id,ordinal,phase,title,guidance,step_kind,search_soql,action_kind) \
         SELECT ?1,ordinal,phase,title,guidance,step_kind,search_soql,action_kind FROM runbook_step WHERE runbook_id=?2",
        params![new_id, src_id],
    );
    Ok(new_id)
}

// ---------------------------------------------------------------------------------------------------------
// HANDLERS HTTP — /api/runbooks* — AUTHORING ADMIN-ONLY (route_min_role section 3 : /api/runbooks -> Admin,
// GET compris ; re-check require_admin en tête, défense en profondeur comme workflow_action/sla-policy). Ces
// routes ne touchent AUCUNE autz de réponse : une step response se joue via /api/actions (INCHANGÉ).
// ---------------------------------------------------------------------------------------------------------

/// GET /api/runbooks — liste TOUS les runbooks (managés + custom) + état activé + nb d'étapes (vue authoring). ADMIN.
pub(crate) async fn runbooks_admin_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    crate::req_conn!(st, au, conn);
    // `P10.7-f` (rang 4, vague b) — LE CATALOGUE D'AUTHORING EST ENTIER OU AVOUÉ. Avant :
    // `.map(|x| x.flatten().collect())` puis `.unwrap_or_default()`. Un runbook avalé se lit ici « cette
    // procédure n'existe pas » — et c'est la page où l'on en CRÉE : on en écrit une seconde, qui portera
    // la même `key` (`TEXT NOT NULL UNIQUE`) et sera refusée, ou un autre nom et concurrencera la
    // première au moment du `match_kind`/`match_key`. Le compte d'étapes servi à côté (`steps`) est un
    // sous-`SELECT` de la MÊME ligne : il disparaît avec elle. L'aveu est celui du dépôt
    // (`liste_bornee::corps_de_liste_illisible` : `runbooks` présente et VIDE, `error` nomme la cause).
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare("SELECT id,key,name,match_kind,match_key,description,managed,active,created,\
                  (SELECT COUNT(*) FROM runbook_step WHERE runbook_id=runbook.id) FROM runbook ORDER BY managed DESC, id")
        .and_then(|mut s| {
            s.query_map([], |r| Ok(json!({
                "id": r.get::<_,i64>(0)?, "key": r.get::<_,String>(1)?, "name": r.get::<_,String>(2)?,
                "match_kind": r.get::<_,String>(3)?, "match_key": r.get::<_,String>(4)?, "description": r.get::<_,String>(5)?,
                "managed": r.get::<_,i64>(6)?, "active": r.get::<_,i64>(7)? != 0, "created": r.get::<_,i64>(8)?,
                "steps": r.get::<_,i64>(9)? })))?
                .collect::<rusqlite::Result<Vec<_>>>()
        });
    match lues {
        Ok(items) => Json(json!({ "runbooks": items })).into_response(),
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({}), "runbooks")).into_response(),
    }
}

/// GET /api/runbooks/{id} — un runbook + ses étapes (pour édition). ADMIN.
pub(crate) async fn runbook_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let Some(mut meta) = runbook_admin_json(&conn, id) else { return not_found("runbook introuvable"); };
    // `P10.7-f` (rang 4, vague b) — UNE PROCÉDURE EST ENTIÈRE, OU ELLE DIT QU'ELLE N'A PAS ÉTÉ LUE. Avant :
    // `.map(|x| x.flatten().collect())` puis `.unwrap_or_default()` — une étape dont la ligne ne se décode
    // pas (`guidance` corrompue, `search_soql`/`action_kind` non textuels) disparaissait de `step_list`,
    // et c'est la LISTE QU'ON SUIT : sauter une étape de confinement au milieu d'un incident se fait alors
    // sans que rien ne l'écrive, et le formulaire d'édition RÉENREGISTRE la procédure amputée (l'update
    // remplace toutes les étapes) — la troncature de lecture devient une troncature PERSISTÉE. La
    // métadonnée du runbook vient d'une AUTRE lecture, déjà faite, et reste servie ; l'aveu est celui du
    // dépôt (`liste_bornee::corps_de_liste_illisible` : `step_list` présente et VIDE, `error` nomme la
    // cause), comme `dash_get` conserve les siennes à la vague A.
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare("SELECT id,ordinal,phase,title,guidance,step_kind,COALESCE(search_soql,''),COALESCE(action_kind,'') FROM runbook_step WHERE runbook_id=?1 ORDER BY ordinal,id")
        .and_then(|mut s| {
            s.query_map(params![id], |r| Ok(json!({
                "id": r.get::<_,i64>(0)?, "ordinal": r.get::<_,i64>(1)?, "phase": r.get::<_,String>(2)?,
                "title": r.get::<_,String>(3)?, "guidance": r.get::<_,String>(4)?, "step_kind": r.get::<_,String>(5)?,
                "search_soql": r.get::<_,String>(6)?, "action_kind": r.get::<_,String>(7)? })))?
                .collect::<rusqlite::Result<Vec<_>>>()
        });
    match lues {
        Ok(steps) => {
            if let Some(o) = meta.as_object_mut() { o.insert("step_list".to_string(), json!(steps)); }
            Json(meta).into_response()
        }
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(meta, "step_list")).into_response(),
    }
}

/// POST /api/runbooks — CRÉE un runbook custom (managed=0). ADMIN. Body : {name, match_kind, match_key?,
/// description?, active?, steps:[{phase,title,guidance?,step_kind,search_soql?,action_kind?}]}.
pub(crate) async fn runbook_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    let (name, mkind, mkey, desc, steps) = match parse_runbook_payload(&b) { Ok(x) => x, Err(e) => return bad_req(e) };
    let active = b.bool_field("active", true);
    crate::req_conn!(st, au, conn);
    let tx = match Txn::begin(&conn) { Ok(t) => t, Err(_) => return server_err("verrou base indisponible") };
    let outcome: Result<i64, String> = (|| {
        let id = create_custom_runbook(&conn, &name, &mkind, &mkey, &desc, &steps, active)?;
        audit_config_change(&conn, "config.runbook.create",
            &format!("runbook custom '{name}' (#{id}, {} étapes, match {mkind}:{mkey}) par {}", steps.len(), au.name), 2,
            &format!("runbook custom '{name}' créé par {}", au.name),
            &json!({ "op":"create", "kind":"runbook", "id":id, "name":name, "match_kind":mkind, "match_key":mkey, "steps":steps.len(), "actor":au.name }).to_string())
            .map_err(|e| format!("échec audit: {e}"))?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => { let _ = tx.commit(); Json(json!({ "id": id })).into_response() }
        Err(e) => { drop(tx); bad_req(e) } // Drop -> ROLLBACK
    }
}

/// POST /api/runbooks/{id} — MET À JOUR un runbook custom (managed=1 -> 403). ADMIN.
pub(crate) async fn runbook_update_handler(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    let (name, mkind, mkey, desc, steps) = match parse_runbook_payload(&b) { Ok(x) => x, Err(e) => return bad_req(e) };
    crate::req_conn!(st, au, conn);
    let tx = match Txn::begin(&conn) { Ok(t) => t, Err(_) => return server_err("verrou base indisponible") };
    let outcome: Result<(), String> = (|| {
        update_custom_runbook(&conn, id, &name, &mkind, &mkey, &desc, &steps)?;
        audit_config_change(&conn, "config.runbook.update",
            &format!("runbook custom '{name}' (#{id}, {} étapes) mis à jour par {}", steps.len(), au.name), 2,
            &format!("runbook custom '{name}' mis à jour par {}", au.name),
            &json!({ "op":"update", "kind":"runbook", "id":id, "name":name, "steps":steps.len(), "actor":au.name }).to_string())
            .map_err(|e| format!("échec audit: {e}"))?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = tx.commit(); Json(json!({ "ok": true })).into_response() }
        Err(e) => { drop(tx); bad_req(e) } // Drop -> ROLLBACK
    }
}

/// DELETE /api/runbooks/{id} — SUPPRIME un runbook custom + ses étapes (managed=1 -> 403). ADMIN. Les case_step
/// déjà instanciées (copies figées) ne sont PAS affectées.
pub(crate) async fn runbook_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let (name, managed): (String, i64) = match conn.query_row("SELECT name,managed FROM runbook WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))) {
        Ok(v) => v, Err(_) => return not_found("runbook introuvable"),
    };
    if managed != 0 { return bad_req("runbook managé (git) : non supprimable — désactivez-le ou clonez-le"); }
    let tx = match Txn::begin(&conn) { Ok(t) => t, Err(_) => return server_err("verrou base indisponible") };
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM runbook_step WHERE runbook_id=?1", params![id])?;
        conn.execute("DELETE FROM runbook WHERE id=?1 AND managed=0", params![id])?;
        audit_config_change(&conn, "config.runbook.delete",
            &format!("runbook custom '{name}' (#{id}) supprimé par {}", au.name), 2,
            &format!("runbook custom '{name}' supprimé par {}", au.name),
            &json!({ "op":"delete", "kind":"runbook", "id":id, "name":name, "actor":au.name }).to_string())?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = tx.commit(); Json(json!({ "ok": true })).into_response() }
        Err(e) => { drop(tx); server_err(format!("échec transaction: {e}")) } // Drop -> ROLLBACK
    }
}

/// POST /api/runbooks/{id}/enabled — (DÉS)ACTIVE un runbook — MANAGÉ OU CUSTOM. ADMIN. Pour un managé, c'est
/// l'override d'activation (doctrine detection_override) : il PERSISTE et SURVIT au reboot (le re-seed est
/// INSERT-si-absent, il ne ré-active jamais). Body : {enabled: bool}.
pub(crate) async fn runbook_set_enabled(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    let enabled = b.bool_field("enabled", true);
    crate::req_conn!(st, au, conn);
    let (name, managed): (String, i64) = match conn.query_row("SELECT name,managed FROM runbook WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))) {
        Ok(v) => v, Err(_) => return not_found("runbook introuvable"),
    };
    let tx = match Txn::begin(&conn) { Ok(t) => t, Err(_) => return server_err("verrou base indisponible") };
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("UPDATE runbook SET active=?1 WHERE id=?2", params![enabled as i64, id])?;
        audit_config_change(&conn, "config.runbook.enabled",
            &format!("runbook '{name}' (#{id}, {}) {} par {}", if managed != 0 { "managé" } else { "custom" }, if enabled { "activé" } else { "désactivé" }, au.name), 2,
            &format!("runbook '{name}' {} par {}", if enabled { "activé" } else { "désactivé" }, au.name),
            &json!({ "op":"enabled", "kind":"runbook", "id":id, "name":name, "managed":managed, "enabled":enabled, "actor":au.name }).to_string())?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = tx.commit(); Json(json!({ "ok": true, "enabled": enabled })).into_response() }
        Err(e) => { drop(tx); server_err(format!("échec transaction: {e}")) } // Drop -> ROLLBACK
    }
}

/// POST /api/runbooks/{id}/clone — CLONE un runbook (managé/custom) en COPIE managed=0 éditable. ADMIN. Body : {name?}.
pub(crate) async fn runbook_clone_handler(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    let new_name = b.get("name").and_then(|v| v.as_str());
    crate::req_conn!(st, au, conn);
    let tx = match Txn::begin(&conn) { Ok(t) => t, Err(_) => return server_err("verrou base indisponible") };
    let outcome: Result<i64, String> = (|| {
        let new_id = clone_runbook(&conn, id, new_name)?;
        audit_config_change(&conn, "config.runbook.clone",
            &format!("runbook #{id} cloné en custom #{new_id} par {}", au.name), 2,
            &format!("runbook #{id} cloné par {}", au.name),
            &json!({ "op":"clone", "kind":"runbook", "src_id":id, "id":new_id, "actor":au.name }).to_string())
            .map_err(|e| format!("échec audit: {e}"))?;
        Ok(new_id)
    })();
    match outcome {
        Ok(new_id) => { let _ = tx.commit(); Json(json!({ "id": new_id })).into_response() }
        Err(e) => { drop(tx); bad_req(e) } // Drop -> ROLLBACK
    }
}

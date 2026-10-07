//! Playbooks (réponse automatisée) : listing `playbooks_list`, CRUD/test des playbooks, rendu de
//! cellule `playbook_cell`, et l'exécuteur périodique `run_playbooks`.
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;
use crate::handlers::transaction_validee::{ouvrir_la_transaction_du_geste, rendre_apres_validation};

/// Durée du ban posé par un playbook `ban_ip`, telle que les exécuteurs la posent : `--duration` CrowdSec et
/// TTL du blocage HTTP natif partagent `NETBAN_ACTION_TTL_S` (voir `action_command` et `netban_upsert`).
/// fail2ban applique la durée de son jail, nft ne pose pas d'expiration : ces deux cas sont NOMMÉS dans la
/// phrase, pas chiffrés.
pub(crate) fn ban_duration_hours() -> i64 {
    NETBAN_ACTION_TTL_S / 3600
}

/// La CONSÉQUENCE d'un `action_kind`, en une phrase : ce que l'interrupteur « actif » d'un playbook ARME.
/// `P11.2-b` : une case à cocher qui active un ban d'IP ne se lisait pas ; la phrase est servie avec la liste
/// pour que la surface n'invente pas la durée. Vocabulaire fermé = celui d'`action_kind_valid`.
pub(crate) fn action_consequence(kind: &str) -> String {
    match kind {
        "ban_ip" => format!(
            "bannit l'IP source pendant {} h (CrowdSec ou blocage HTTP natif ; fail2ban : durée du jail ; nft : jusqu'à unban) sur chaque hôte qui l'a vue dans la fenêtre",
            ban_duration_hours()
        ),
        "unban_ip" => "lève le ban de l'IP source sur chaque hôte qui l'a vue dans la fenêtre".to_string(),
        "kill_pid" => "termine le processus cible (SIGTERM) sur le central".to_string(),
        "stop_service" => "arrête le service cible (systemctl stop) sur le central".to_string(),
        other => format!("action « {other} » hors vocabulaire : refusée à l'exécution"),
    }
}

/// `P10.21-e` — LA CADENCE DE L'ORDONNANCEUR DE DÉTECTION, déclarée UNE fois : la boucle de règles
/// (`server/boucles_de_fond.rs`, `spawn_rule_scheduler`) dort ce nombre de secondes entre deux tours, et
/// le plancher de fenêtre des playbooks la lit. Deux tours sont donc séparés d'AU MOINS cette durée,
/// quel que soit l'`interval_s` d'un playbook : un intervalle plus court (zéro, négatif, ou entre un et
/// dix-neuf) n'est jamais tenu plus souvent qu'à chaque tour.
pub(crate) const TOUR_DE_DETECTION_S: u64 = 20;

/// `P10.21-e` — LE PLANCHER DE LA FENÊTRE DE DÉDUPLICATION D'UN PLAYBOOK. La seule chose qui empêche un
/// playbook dont la règle est encore vraie de poser une SECONDE riposte (et de ré-armer un ban) au
/// passage suivant est la déduplication, qui ne regarde que les ripostes des `window_s` dernières
/// secondes. Deux passages sont séparés d'au moins `interval_s`, et d'au moins un tour d'ordonnanceur :
/// une fenêtre plus courte que cet écart minimal oublie la riposte précédente avant le passage suivant.
/// Règle retenue : `window_s >= max(interval_s, TOUR_DE_DETECTION_S)`.
///
/// CE QUE CE PLANCHER NE TIENT PAS SEUL : il couvre l'écart MINIMAL entre deux passages, pas l'écart
/// réel. Un playbook n'est resélectionné qu'au premier tour où `now - last_run >= interval_s` ; les
/// tours se suivent à `TOUR_DE_DETECTION_S` PLUS la durée du travail du tour (le sommeil est placé
/// après), donc l'écart réel peut dépasser `interval_s` d'à peu près la durée d'un tour entier — et
/// aucune marge FIXE ne borne cette durée. C'est donc la déduplication elle-même qui couvre l'écart
/// réel : `debut_de_la_deduplication_du_playbook` la fait remonter jusqu'au passage précédent.
///
/// POURQUOI LE PLANCHER RESTE : `window_s` est AUSSI la fenêtre de la requête de détection
/// (`rule_sql`) et celle des hôtes d'un ban. Sous `interval_s`, les événements tombés entre deux
/// passages ne sont vus par aucun passage. Au-dessus, suivre le levier élargit la recherche : le scan
/// coûte plus et un seuil (`count > N`) porte sur une durée plus longue. Le refus le dit.
///
/// Fonction PURE, appelée par la création, la modification et l'import d'overlay, et lue par la liste
/// pour SIGNALER les lignes déjà sous le plancher sans les modifier.
/// Le refus est NOMMÉ : il cite `window_s`, `interval_s`, le plancher et le levier.
pub(crate) fn juger_le_plancher_de_fenetre_du_playbook(window_s: i64, interval_s: i64) -> Result<(), String> {
    let plancher = interval_s.max(TOUR_DE_DETECTION_S as i64);
    if window_s >= plancher {
        return Ok(());
    }
    let levier = if window_s >= TOUR_DE_DETECTION_S as i64 {
        format!("portez window_s à au moins {plancher} s, ou ramenez interval_s à {window_s} s au plus")
    } else {
        format!(
            "portez window_s à au moins {plancher} s (l'ordonnanceur passe toutes les {TOUR_DE_DETECTION_S} s : \
             abaisser interval_s sous cette durée ne rapproche pas les passages)"
        )
    };
    Err(format!(
        "FENÊTRE DE DÉDUPLICATION SOUS LE PLANCHER : window_s = {window_s} s est plus court que l'écart minimal \
         entre deux passages du playbook (interval_s = {interval_s} s, tour de l'ordonnanceur = {TOUR_DE_DETECTION_S} s, \
         plancher = {plancher} s). window_s est aussi la fenêtre de la requête de détection : sous cet écart, les \
         événements tombés entre deux passages ne seraient vus par aucun passage. L'allonger élargit d'autant la \
         recherche (scan plus coûteux, un seuil de comptage porte sur une durée plus longue). Levier : {levier}."
    ))
}

/// `P10.21-e` — LE DÉBUT DE LA FENÊTRE DE DÉDUPLICATION D'UN PASSAGE. La fenêtre nominale commence à
/// `now_ts - window_s`. Si le passage PRÉCÉDENT de ce playbook (`last_run` lu AVANT la pose du nouveau
/// marqueur — ses ripostes portent exactement cet horodatage) est plus ancien que ce début, la fenêtre
/// remonte jusqu'à lui : la riposte qu'il a posée est toujours vue par le passage qui le suit, quel que
/// soit le dépassement dû à la durée des tours. L'extension est BORNÉE : un passage précédent plus
/// ancien que `now_ts - window_s - max(interval_s, TOUR_DE_DETECTION_S)` n'est pas « le passage d'avant »
/// au sens de l'ordonnancement (démon arrêté, playbook coupé puis rallumé) — la fenêtre reste alors la
/// nominale, pour qu'une riposte périmée ne retienne pas une riposte due.
///
/// LE PLANCHER EST AUSSI TENU ICI, À L'EXÉCUTION. La fenêtre nominale de déduplication est
/// `max(window_s, interval_s, TOUR_DE_DETECTION_S)`, pas `window_s` seul : une ligne sous le plancher
/// peut être ARMÉE sans qu'aucun geste juge sa fenêtre (fichier `config.d` coupé puis dérogation
/// d'activation réappliquée au démarrage, ligne posée avant le plancher). La requête de détection
/// garde `window_s` ; seule la mémoire des ripostes est planchée, pour qu'aucune voie d'armement ne
/// fasse reposer une riposte au passage suivant.
/// Arithmétique SATURÉE : le juge admet `window_s = interval_s = i64::MAX`, qui déborderait sinon.
/// Fonction PURE, lue par `run_playbooks` (requête de déduplication).
pub(crate) fn debut_de_la_deduplication_du_playbook(now_ts: i64, window_s: i64, interval_s: i64, passage_precedent: Option<i64>) -> i64 {
    let ecart_minimal = interval_s.max(TOUR_DE_DETECTION_S as i64);
    let fenetre = window_s.max(ecart_minimal);
    let nominal = now_ts.saturating_sub(fenetre);
    let borne = nominal.saturating_sub(ecart_minimal);
    match passage_precedent {
        Some(precedent) if precedent >= borne => nominal.min(precedent),
        _ => nominal,
    }
}

// `P10.25-g` — LES `COMMIT` DES PLAYBOOKS SONT JUGÉS : un refus rend l'une de ces causes en 503, la transaction fermée.
/// `P10.25-g` — playbook non créé : le `COMMIT` de ce geste refusé.
pub(crate) const CAUSE_PLAYBOOK_NON_CREE: &str = "PLAYBOOK NON CRÉÉ : la base n'a pas validé la transaction (COMMIT \
     refusé) et l'a annulée — aucun playbook n'est écrit, aucune riposte ne sera posée par lui, et aucune trace \
     n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_PLAYBOOK_NON_CREE_TRANSACTION_NON_OUVERTE: &str = "PLAYBOOK NON CRÉÉ : la base n'a pas pris \
     la transaction de la création (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur \
     l'écrivain) — RIEN n'est écrit : aucun playbook n'est écrit, aucune riposte ne sera posée par lui, et aucune \
     trace n'est écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";
/// `P10.25-g` — playbook inchangé : le `COMMIT` de ce geste refusé.
pub(crate) const CAUSE_PLAYBOOK_INCHANGE: &str = "PLAYBOOK INCHANGÉ : la base n'a pas validé la transaction (COMMIT \
     refusé) et l'a annulée — il garde sa requête, son action et son activation d'avant, et aucune trace n'est \
     écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_PLAYBOOK_INCHANGE_TRANSACTION_NON_OUVERTE: &str = "PLAYBOOK INCHANGÉ : la base n'a pas pris \
     la transaction de la modification (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur \
     l'écrivain) — RIEN n'est écrit : il garde sa requête, son action et son activation d'avant, et aucune trace \
     n'est écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";


pub(crate) async fn playbooks_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    // `P10.7-f` (rang 2) — LA LISTE DES PLAYBOOKS EST ENTIÈRE OU AVOUÉE. Avant : DEUX `unwrap()` (une panique
    // n'est pas un aveu, et sur l'écrivain partagé elle se propage) puis `rows.flatten().collect()` — un
    // playbook dont la ligne ne se décode pas DISPARAISSAIT de la liste, avec sa `consequence` EFFECTIVE
    // (`observe` = propose / `active` = exécute). C'est la vue où l'on vérifie « qu'est-ce qui peut bannir
    // tout seul ici » : un playbook `ban_ip` avalé se lit « aucune réponse automatique n'est armée » pendant
    // qu'elle l'est. Soldé en bloc ; sur échec, l'aveu du dépôt (`corps_de_liste_illisible`) autour des deux
    // champs qui ne DÉRIVENT PAS de cette lecture (`mode` a sa propre lecture, `ban_duration_s` est une
    // constante) — les taire n'apprendrait rien et priverait la console de son bandeau de mode.
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare("SELECT id,name,enabled,query,is_soql,action_kind,interval_s,window_s,last_run,managed FROM playbook ORDER BY id")
        .and_then(|mut stmt| {
            stmt.query_map([], |r| {
                let action_kind = r.get::<_, String>(5)?;
                let (interval_s, window_s) = (r.get::<_, i64>(6)?, r.get::<_, i64>(7)?);
                // `P10.21-e` — une ligne déjà sous le plancher (posée avant lui) est SIGNALÉE, jamais
                // modifiée : la cause est servie sur la ligne, la valeur enregistrée reste celle-là.
                let sous_le_plancher = juger_le_plancher_de_fenetre_du_playbook(window_s, interval_s).err();
                Ok(json!({
                    "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "enabled": r.get::<_, i64>(2)? != 0,
                    "query": r.get::<_, String>(3)?, "is_soql": r.get::<_, i64>(4)? != 0,
                    "consequence": action_consequence(&action_kind), "action_kind": action_kind,
                    "interval_s": interval_s, "window_s": window_s, "last_run": r.get::<_, Option<i64>>(8)?,
                    "managed": r.get::<_, i64>(9)?,
                    "fenetre_sous_le_plancher": sous_le_plancher.is_some(), "cause_fenetre_sous_le_plancher": sous_le_plancher
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    // Le mode global décide si un playbook ON exécute (active) ou propose (observe) : la liste le porte pour
    // que la ligne dise la conséquence EFFECTIVE sans une seconde requête.
    let mode: String = conn.query_row("SELECT value FROM meta WHERE key='plume_mode'", [], |r| r.get(0)).unwrap_or_else(|_| "observe".into());
    match lues {
        Ok(playbooks) => Json(json!({ "playbooks": playbooks, "mode": mode, "ban_duration_s": NETBAN_ACTION_TTL_S })),
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(
            json!({ "mode": mode, "ban_duration_s": NETBAN_ACTION_TTL_S }),
            "playbooks",
        )),
    }
}
pub(crate) async fn playbook_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let is_soql = b.bool_field("is_soql", true);
    let query = b.str_field("query").to_string();
    let action_kind = b.get("action_kind").and_then(|v| v.as_str()).unwrap_or("ban_ip").to_string();
    let window_s = b.i64_field("window_s", 3600);
    // #1c garde-fous #1/#2/#3 : SQL brut=admin + requête compile + action_kind ∈ ENUM FERMÉ — avant écriture.
    if let Err((code, msg)) = validate_detection_content("playbook", is_soql, &query, &action_kind, window_s, &au.role) {
        return err_json(code, msg);
    }
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Playbook").to_string();
    let enabled = b.bool_field("enabled", true) as i64;
    let interval_s = b.i64_field("interval_s", 300);
    // `P10.21-e` — la fenêtre de déduplication couvre l'écart minimal entre deux passages, avant écriture.
    if let Err(cause) = juger_le_plancher_de_fenetre_du_playbook(window_s, interval_s) {
        return err_json(StatusCode::BAD_REQUEST, cause);
    }
    crate::req_conn!(st, au, conn);
    // #1c garde-fous #4/#6 : INSERT managed=2 (ad-hoc UI) + audit #1b, transaction fail-closed.
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "playbooks", "création d'un playbook", CAUSE_PLAYBOOK_NON_CREE_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            // DURCISSEMENT : `created_by_role` marque l'AUTEUR -> run_playbooks n'auto-approuve
            // (mode active) QUE les playbooks admin-authored. `validate_detection_content` garantit déjà que seul
            // un admin arrive ici pour un playbook à action destructive ; ce marquage DOUBLE la garde (défense
            // en profondeur : même un playbook editor résiduel resterait pending/dry_run en mode active).
            "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,created_by_role) VALUES(?1,?2,?3,?4,?5,?6,?7,2,?8)",
            params![name, enabled, query, is_soql as i64, action_kind, interval_s, window_s, au.role],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.playbook.create",
            &format!("playbook '{name}' (#{id}) créé par {}", au.name), 2,
            &format!("playbook de réponse '{name}' (action {action_kind}) créé par {}", au.name),
            &json!({ "op": "create", "kind": "playbook", "id": id, "name": name, "action_kind": action_kind, "is_soql": is_soql, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        Ok(id) => rendre_apres_validation(&conn, "playbooks", "création d'un playbook", CAUSE_PLAYBOOK_NON_CREE, || {
            Json(json!({ "id": id, "managed": 2 })).into_response()
        }),
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}
pub(crate) async fn playbook_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    crate::req_conn!(st, au, conn);
    let cur = conn.query_row(
        "SELECT is_soql,query,window_s,action_kind,managed,name,interval_s,enabled FROM playbook WHERE id=?1",
        params![id],
        |r| Ok((r.get::<_, i64>(0)? != 0, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?, r.get::<_, i64>(4)?, r.get::<_, String>(5)?, r.get::<_, i64>(6)?, r.get::<_, i64>(7)? != 0)),
    );
    let (cur_soql, cur_query, cur_window, cur_kind, cur_managed, cur_name, cur_interval, cur_enabled) = match cur {
        Ok(x) => x,
        Err(_) => return not_found("playbook introuvable"),
    };
    // #1c garde-fous #1/#2/#3 : valeurs EFFECTIVES post-PATCH ; anti-contournement editor->SQL brut ; la
    // requête compile ; action_kind effectif ∈ ENUM FERMÉ.
    let eff_soql = b.get("is_soql").and_then(|x| x.as_bool()).unwrap_or(cur_soql);
    let eff_query = b.get("query").and_then(|x| x.as_str()).map(|s| s.to_string()).unwrap_or(cur_query);
    let eff_window = b.get("window_s").and_then(|x| x.as_i64()).unwrap_or(cur_window);
    let eff_kind = b.get("action_kind").and_then(|x| x.as_str()).map(|s| s.to_string()).unwrap_or(cur_kind);
    if let Err((code, msg)) = validate_detection_content("playbook", eff_soql, &eff_query, &eff_kind, eff_window, &au.role) {
        return err_json(code, msg);
    }
    // `P10.21-e` — le plancher juge les valeurs EFFECTIVES (requête fusionnée avec la ligne), et seulement
    // quand la requête CHANGE `window_s` ou `interval_s` : un playbook posé sous le plancher avant lui
    // reste désactivable, renommable et modifiable sur ses autres champs — le refuser là empêcherait
    // précisément de couper ce qu'il arme. « Change » et non « porte » : le formulaire de la console
    // renvoie les deux champs à chaque enregistrement, inchangés le plus souvent.
    // ARMER est jugé aussi : passer une ligne ÉTEINTE à `enabled:true` (case « Activée » du formulaire)
    // sous le plancher est refusé, comme la bascule de la ligne (`playbook_set_enabled`). Même règle
    // « change » : renvoyer `enabled:true` sur une ligne déjà armée n'arme rien ; la désactiver reste admis.
    let eff_interval = b.get("interval_s").and_then(|x| x.as_i64()).unwrap_or(cur_interval);
    let touche_la_cadence = eff_window != cur_window || eff_interval != cur_interval;
    let arme = !cur_enabled && b.get("enabled").and_then(|x| x.as_bool()) == Some(true);
    if touche_la_cadence || arme {
        if let Err(cause) = juger_le_plancher_de_fenetre_du_playbook(eff_window, eff_interval) {
            return err_json(StatusCode::BAD_REQUEST, cause);
        }
    }
    // FIX HIGH-1b (bypass adopt-then-toggle) : modifier un playbook BASELINE (seed/builtin managed=0) = ADMIN
    // seul — sinon l'adoption managed=0->2 (plus bas) sert de tremplin à une désactivation editor + ferme le
    // neuter-via-query. Frontière : baseline(0)+overlay(1)=admin ; editor CRUD complet sur SON ad-hoc (managed=2).
    // INVARIANT : `cur_managed != 2` — overlay(1) admin-managé au même titre que le seed(0).
    if cur_managed != 2 && !au.is_admin() {
        return err_json(StatusCode::FORBIDDEN, "modifier un playbook managé (seed/builtin/overlay) est réservé à l'administrateur ; créez plutôt votre propre playbook");
    }
    // FIX HIGH-1 : toggler `enabled` sur un playbook managé (managed=0 seed, managed=1 overlay) = ADMIN seul ; un
    // non-admin ne bascule `enabled` que sur son playbook ad-hoc managed=2. Fail-closed (refuse tout le PATCH).
    // Évalué sur le managed COURANT (avant l'adoption managed=0->2 plus bas).
    let enabled_change = b.get("enabled").and_then(|x| x.as_bool());
    if enabled_change.is_some() && !(au.is_admin() || cur_managed == 2) {
        return err_json(StatusCode::FORBIDDEN, "activer/désactiver une détection managée (seed/overlay) est réservé à l'administrateur");
    }
    // P11.5-d : renommer un playbook adossé à un fichier config.d est REFUSÉ (409), HORS transaction.
    if let Some(n) = b.get("name").and_then(|x| x.as_str()) {
        if let Err((code, msg)) = refuser_le_renommage_d_un_overlay("playbook", cur_managed, &cur_name, n) { return err_json(code, msg); }
    }
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "playbooks", &format!("modification du playbook #{id}"), CAUSE_PLAYBOOK_INCHANGE_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(v) = b.get("name").and_then(|x| x.as_str()) { conn.execute("UPDATE playbook SET name=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("query").and_then(|x| x.as_str()) { conn.execute("UPDATE playbook SET query=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("is_soql").and_then(|x| x.as_bool()) { conn.execute("UPDATE playbook SET is_soql=?1 WHERE id=?2", params![v as i64, id])?; }
        if let Some(v) = b.get("action_kind").and_then(|x| x.as_str()) { conn.execute("UPDATE playbook SET action_kind=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("interval_s").and_then(|x| x.as_i64()) { conn.execute("UPDATE playbook SET interval_s=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = b.get("window_s").and_then(|x| x.as_i64()) { conn.execute("UPDATE playbook SET window_s=?1 WHERE id=?2", params![v, id])?; }
        // P11.5-d : la case « Activée » emprunte le MÊME point unique que l'interrupteur de la ligne.
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) {
            conn.execute("UPDATE playbook SET enabled=?1 WHERE id=?2", params![v as i64, id])?;
            persister_derogation_activation(&conn, "playbook", &cur_name, cur_managed, v, &au.name)?;
        }
        // #1c garde-fou #4 : éditer un builtin (managed=0) l'ADOPTE en ad-hoc (managed=2) ; overlay (1) reste 1.
        if cur_managed == 0 { conn.execute("UPDATE playbook SET managed=2 WHERE id=?1", params![id])?; }
        // DURCISSEMENT : ré-affirme l'auteur du CONTENU à chaque édition validée (seul un admin
        // passe validate_detection_content pour un playbook à action destructive) -> autorité d'auto-exécution.
        conn.execute("UPDATE playbook SET created_by_role=?1 WHERE id=?2", params![au.role, id])?;
        audit_config_change(
            &conn, "config.playbook.update",
            &format!("playbook #{id} modifié par {}", au.name), 2,
            &format!("playbook #{id} modifié par {}", au.name),
            &json!({ "op": "update", "kind": "playbook", "id": id, "is_soql": eff_soql, "action_kind": eff_kind, "enabled": enabled_change, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => rendre_apres_validation(&conn, "playbooks", &format!("modification du playbook #{id}"), CAUSE_PLAYBOOK_INCHANGE, || {
            Json(reponse_modification_acceptee("Ce playbook", "playbook", cur_managed)).into_response()
        }),
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}
pub(crate) async fn playbook_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    let managed = match conn.query_row("SELECT managed FROM playbook WHERE id=?1", params![id], |r| r.get::<_, i64>(0)) {
        Ok(m) => m,
        Err(_) => return not_found("playbook introuvable"),
    };
    delete_managed_row(&conn, "playbook", "config.playbook", id, managed, &au.name)
}
/// `P10.20-j` — ses refus portent leur statut (ils étaient servis en deux cents `{error}`) : un playbook absent en 404,
/// une requête enregistrée qui ne compile pas pour l'appelant ou ne s'exécute pas en 422 (définition inexploitable), une
/// tâche interrompue en 500. RESTE ÉCRIT : la lecture du playbook rend `None` sur une absence COMME sur une lecture
/// ratée (`.ok()`, entrée de rang quatre de la garde `P10.20-b`) — le 404 hérite de cette confusion, qu'il ne crée pas.
pub(crate) async fn playbook_test(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    let row = {
        crate::req_conn!(st, au, conn);
        conn.query_row("SELECT query,is_soql,action_kind,window_s FROM playbook WHERE id=?1", params![id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0, r.get::<_, String>(2)?, r.get::<_, i64>(3)?))).ok()
    };
    let (query, is_soql, kind, window_s) = match row {
        Some(x) => x,
        None => return not_found("playbook introuvable"),
    };
    // #45 — DRY-RUN = SURFACE D'APPELANT : cette route est EDITOR+ et RENVOIE les CIBLES de la requête
    // (1re colonne) à l'appelant. Compilée par la porte SYSTÈME `rule_sql`, un playbook `search | table
    // src_ip` restituait les valeurs EN CLAIR à un rôle dont src_ip est masqué (exfiltration directe, pas
    // seulement un oracle). On passe donc par la porte APPELANT (masque #45 résolu DANS la porte).
    let sql = match rule_sql_for_caller(&st, &au, &query, is_soql, window_s) {
        Ok(s) => s,
        Err(e) => return err_json(StatusCode::UNPROCESSABLE_ENTITY, e),
    };
    let db_path = req_db_path(&st, &au);
    let db_path2 = db_path.clone(); // capturé par la closure blocking ; `db_path` reste pour le guard tenant
    match tokio::task::spawn_blocking(move || run_query(&db_path2, &sql)).await {
        Ok(Ok(res)) => {
            let targets: Vec<String> = res.get("rows").and_then(|r| r.as_array())
                .map(|rows| rows.iter().filter_map(|row| row.as_array().and_then(|c| c.first()).map(playbook_cell)).filter(|t| !t.is_empty()).collect())
                .unwrap_or_default();
            let valides = targets.iter().filter(|t| action_valid(&kind, t, &db_path).is_ok()).count();
            Json(json!({ "action_kind": kind, "targets": targets, "valides": valides })).into_response()
        }
        Ok(Err(e)) => err_json(StatusCode::UNPROCESSABLE_ENTITY, e),
        Err(_) => server_err("exécution échouée"),
    }
}

/// `P10.20-w` — CE QUE L'ÉCRITURE DU MARQUEUR DE PASSAGE REND. Le marqueur `last_run` n'est pas une
/// note : il est la SEULE chose qui retire un playbook de la sélection des dus
/// (`WHERE enabled=1 AND (last_run IS NULL OR ?1-last_run>=interval_s)`). Non écrit, le playbook
/// reste dû, et le tour suivant le réévalue — requête de sélection des cibles comprise.
///
/// POURQUOI UN TYPE NOMMÉ PLUTÔT QU'UN `Result<usize, _>` — même arbitrage que `RiposteMiseEnFile`
/// (`handlers/mise_en_file_de_riposte.rs`) : un `Result` offre `.ok()` et `.unwrap_or(0)`, et c'est
/// précisément le repli qui a fait passer « la base n'a rien pris » pour « le marqueur est posé ».
/// Les trois issues ne se confondent pas, et aucune ne se tire du type sans avoir été nommée.
pub(crate) enum PassageDuPlaybook {
    /// Le marqueur est écrit : ce playbook ne sera pas resélectionné avant son intervalle.
    Marque,
    /// Aucune ligne ne porte cet identifiant — le playbook a été supprimé entre la sélection des dus
    /// et la pose du marqueur. Absence ÉTABLIE : rien n'est perdu, il n'y a plus rien à exécuter.
    PlaybookDisparu,
    /// L'écriture n'a pas eu lieu — la cause est portée. Le playbook reste dû AVEC son état d'avant.
    NonMarque(String),
}

/// Marque le passage d'un playbook, et compte les lignes écrites avant de conclure quoi que ce soit.
pub(crate) fn marquer_le_passage_du_playbook(conn: &Connection, id: i64, now_ts: i64) -> PassageDuPlaybook {
    match conn.execute("UPDATE playbook SET last_run=?1 WHERE id=?2", params![now_ts, id]) {
        Ok(0) => PassageDuPlaybook::PlaybookDisparu,
        Ok(_) => PassageDuPlaybook::Marque,
        Err(e) => PassageDuPlaybook::NonMarque(e.to_string()),
    }
}

/// `P10.20-w` — ce que la surface lit quand le marqueur de passage n'a pas été écrit.
pub(crate) const CAUSE_MARQUEUR_DE_PASSAGE_NON_ECRIT: &str =
    "MARQUEUR DE PASSAGE NON ÉCRIT : le playbook reste DÛ avec son état d'avant, donc le tour suivant \
     le réévaluera. Aucune riposte n'est posée ni aucun blocage armé sur ce tour-ci : la même \
     évaluation, rejouée, en poserait une SECONDE dès que la fenêtre de déduplication du playbook est \
     plus courte que l'écart entre deux tours.";

/// Extrait la cible d'une cellule (1re colonne d'une ligne de playbook) : string ou nombre.
pub(crate) fn playbook_cell(c: &Value) -> String {
    if let Some(s) = c.as_str() {
        s.to_string()
    } else if c.is_null() {
        String::new()
    } else {
        c.to_string()
    }
}

/// Exécute les playbooks dus : la requête renvoie des CIBLES (1re colonne) -> 1 action par cible.
/// Mode 'observe' -> pending+dry_run (on voit ce qui SERAIT fait) ; 'active' -> approved+réel (auto).
/// REND SON BILAN (`P4.1-r`, même contrat que `run_due_rules`) : `Illisible` si la liste des playbooks dus
/// n'a pas pu être lue, `Lue(n)` = ce que ce tick a ABANDONNÉ, à quelque granularité que ce soit —
/// playbook non évalué (ligne indécodable, compilation refusée, requête de sélection des cibles en
/// échec), hôte d'exécution illisible, déduplication illisible, (`P4.7-d`) CIBLE DONT LA FORME
/// N'EST PAS PORTABLE PAR CE PRODUIT (une `src_ip` IPv6 pour un `ban_ip`, un PID sous le plancher de
/// sûreté) — ce dernier cas était jeté en silence et publiait un tick à « 0 abandon » — et
/// (`P10.20-t`) RIPOSTE DONT LA LIGNE N'A PAS PU ÊTRE ÉCRITE : l'`INSERT` était avalé, et le miroir
/// de ban HTTP s'armait quand même sur une action qui n'existait pas — et (`P10.20-w`) PLAYBOOK DONT
/// LE MARQUEUR DE PASSAGE N'A PAS PU ÊTRE ÉCRIT : le tour est refusé pour ce playbook, qui reste dû.
/// CE QUE `Lue(n)` NE COMPTE PAS, ET C'EST DÉLIBÉRÉ : une cible BIEN FORMÉE que la POLITIQUE refuse
/// (IP protégée, engagement actif). Ce refus-là est écrit, la détection continue, rien n'est perdu.
pub(crate) fn run_playbooks(db: &Arc<Mutex<Connection>>, db_path: &str) -> crate::bilan_de_tick::BilanDeTick {
    let now_ts = now();
    let mut abandonnes = 0u32;
    let mode: String = {
        let conn = db.lock();
        conn.query_row("SELECT value FROM meta WHERE key='plume_mode'", [], |r| r.get(0)).unwrap_or_else(|_| "observe".into())
    };
    // DURCISSEMENT : on lit AUSSI `created_by_role` -> seuls les playbooks ADMIN-authored
    // s'auto-approuvent en mode active. Colonne NOT NULL DEFAULT 'admin' -> les seeds/overlays/playbooks
    // pré-existants restent auto-exécutables (INVARIANT prod inchangé) ; un playbook editor résiduel NON.
    // #64 : `admin_authored` = AUTORITÉ ADMIN EFFECTIVE de l'auteur ET perm `arm_response` NON retirée
    // (calqué sur la garde d'armement `detection.rs`/`validate_detection_content`). Un rôle composable
    // base=admin (ex. "gov-armer") SANS deny arm_response -> auto-approuve (le #64 lui laisse ARMER) ; AVEC
    // deny arm_response ("gov-noarm") -> reste pending/dry (le deny subsiste ici aussi) ; base non-admin ->
    // jamais. Mode 0 / rôle de base -> byte-identique à `== "admin"` (builtin jamais custom-défini, jamais denied).
    // `P10.21-e` — `interval_s` et le `last_run` d'AVANT ce passage sont lus ici, avant que le marqueur
    // ne soit reposé : ils bornent le début de la déduplication (`debut_de_la_deduplication_du_playbook`).
    type PlaybookDu = (i64, String, String, bool, String, i64, bool, i64, Option<i64>);
    let due: Vec<PlaybookDu> = {
        let conn = db.lock();
        let mut stmt = match conn.prepare("SELECT id,name,query,is_soql,action_kind,window_s,COALESCE(created_by_role,'admin'),interval_s,last_run FROM playbook WHERE enabled=1 AND (last_run IS NULL OR ?1-last_run>=interval_s)") {
            Ok(s) => s,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("playbooks", &e),
        };
        let it = match stmt.query_map(params![now_ts], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)? != 0, r.get::<_, String>(4)?, r.get::<_, i64>(5)?, { let cbr = r.get::<_, String>(6)?; effective_base_role(&cbr) == "admin" && !role_perm_denied(&cbr, "arm_response") }, r.get::<_, i64>(7)?, r.get::<_, Option<i64>>(8)?))) {
            Ok(it) => it,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("playbooks", &e),
        };
        let mut v: Vec<PlaybookDu> = Vec::new();
        for r in it {
            match r {
                Ok(x) => v.push(x),
                Err(_) => abandonnes += 1, // ligne indécodable : un playbook non évalué, compté
            }
        }
        v
    };
    for (id, name, query, is_soql, kind, window_s, admin_authored, interval_s, passage_precedent) in due {
        let debut_dedup = debut_de_la_deduplication_du_playbook(now_ts, window_s, interval_s, passage_precedent);
        let sql = match rule_sql(&query, is_soql, window_s) {
            Ok(s) => s,
            Err(_) => {
                abandonnes += 1;
                let c = db.lock();
                // Le marqueur passe par le MÊME fabricant que le site nominal : un playbook dont la
                // compilation est refusée et dont le marqueur n'entre pas serait recompilé — et
                // recompté — à chaque tour, sans que rien ne le dise. L'abandon est DÉJÀ compté pour
                // la compilation ; seule la cause du marqueur s'ajoute, sous son propre genre.
                if let PassageDuPlaybook::NonMarque(cause) = marquer_le_passage_du_playbook(&c, id, now_ts) {
                    ledger_append(&c, "playbook.marqueur-non-ecrit",
                        &format!("playbook:{name} (#{id}) : {CAUSE_MARQUEUR_DE_PASSAGE_NON_ECRIT} ({cause})"));
                }
                continue;
            }
        };
        // DURCISSEMENT 3b — l'éval du playbook passe par run_query -> connexion LECTURE SEULE (query_only
        // ON + flag READ_ONLY + garde stmt.readonly()) : la requête de sélection des cibles ne peut QUE lire.
        // Les écritures légitimes (table `action`) se font ensuite sur la connexion principale, hors éval.
        let res = run_query(db_path, &sql);
        let conn = db.lock();
        // `P10.20-w` — LE MARQUEUR DE PASSAGE EST ÉCRIT AVANT TOUT, ET SON ÉCHEC REFUSE LE TOUR. Ce
        // marqueur n'affirme rien des ripostes qui suivent : il commande la SÉLECTION des playbooks
        // dus. Avalé, il laissait ce playbook dû indéfiniment — donc réévalué à chaque tour, requête
        // de cibles comprise — pendant que le bilan du tick publiait « 0 abandon ». La seule chose
        // qui empêchait alors une SECONDE riposte et un SECOND armement était la déduplication, dont
        // la fenêtre est la colonne `window_s` de CE playbook (`P10.21-e` : planchée à l'écriture, et
        // remontée au passage précédent — qui, marqueur non écrit, reste l'ANCIEN). Le tour est donc refusé, la perte comptée, et la réévaluation gardée pour
        // le tour suivant — un état d'ordonnancement qu'on n'a pas su écrire n'arme rien.
        match marquer_le_passage_du_playbook(&conn, id, now_ts) {
            PassageDuPlaybook::Marque => {}
            PassageDuPlaybook::PlaybookDisparu => {
                // Le playbook a été supprimé entre la sélection et la marque : il n'y a plus rien à
                // exécuter, et rien n'est perdu — l'abandon ne se compte pas, la trace le dit.
                ledger_append(&conn, "playbook.disparu",
                    &format!("playbook:{name} (#{id}) retiré entre la sélection des dus et la pose du marqueur — aucune riposte posée"));
                continue;
            }
            PassageDuPlaybook::NonMarque(cause) => {
                abandonnes += 1;
                ledger_append(&conn, "playbook.marqueur-non-ecrit",
                    &format!("playbook:{name} (#{id}) : {CAUSE_MARQUEUR_DE_PASSAGE_NON_ECRIT} ({cause})"));
                continue;
            }
        }
        // Une sélection de cibles en ÉCHEC n'est pas « aucune cible » : le playbook n'a pas été évalué, compté.
        let rows = match &res {
            Ok(v) => v.get("rows").and_then(|r| r.as_array()).cloned().unwrap_or_default(),
            Err(_) => {
                abandonnes += 1;
                Vec::new()
            }
        };
        for row in rows {
            let target = row.as_array().and_then(|c| c.first()).map(playbook_cell).unwrap_or_default();
            // `P4.7-d` — UNE CIBLE QUE CE PRODUIT NE SAIT PAS PORTER N'EST PAS UN CHOIX DE POLITIQUE.
            // Cette ligne jetait la cible en SILENCE : aucune ligne dans `action`, aucun compteur, et
            // `abandonnes` — qui EST le bilan rendu du tick (`Mesure::Lue`, plus bas) — publiait « 0
            // abandon » sur une riposte qui n'est jamais partie. Le cas est réel et il est MESURÉ :
            // `extract_src_ip` garde un IPv6 nu ENTIER (`ingest/mod.rs`, « un IPv6 nu doit rester
            // entier »), donc `2001:db8::66` arrive dans `event.src_ip`, un playbook `ban_ip` le
            // sélectionne, et `cible_de_ban_acceptee` — la borne d'enforcement v1, IPv4 — le refuse.
            // Tick vert, réponse évaporée, et l'exploitant ne peut pas distinguer « aucune cible » de
            // « cible jetée ».
            // DEUX REFUS TOMBAIENT ICI SOUS UN MÊME `Err`, ET UN SEUL EST UNE PERTE :
            //   * la FORME n'est pas portable (`cible_de_forme_portable` = false) — le produit ne sait
            //     pas exprimer cette cible : c'est une perte de couverture, elle se COMPTE ;
            //   * la POLITIQUE refuse une cible pourtant bien formée (IP protégée, engagement actif) —
            //     délibéré, écrit, et la détection continue (`action_valid_ctx` le dit à son site).
            //     Rien n'est perdu, donc rien n'est compté : compter ici ferait du bilan du tick un
            //     compteur d'IP privées, c'est-à-dire un chiffre que personne ne lirait plus.
            // Le partage est DÉRIVÉ des bornes elles-mêmes, jamais du texte du message de refus.
            if target.is_empty() {
                continue;
            }
            if action_valid(&kind, &target, db_path).is_err() {
                if !crate::handlers::actions::cible_de_forme_portable(&kind, &target) {
                    abandonnes += 1;
                }
                continue;
            }
            // Cible(s) d'exécution : pour un ban d'IP, on agit sur CHAQUE hôte ayant vu cette IP sur
            // la fenêtre (chacun bannit chez lui -> enforcement là où est la menace, pas sur le central).
            // Pour les autres actions (stop_service...) -> central (host NULL).
            let hosts: Vec<Option<String>> = if kind == "ban_ip" || kind == "unban_ip" {
                // Un hôte qu'on ne sait pas lire est un hôte où la réponse ne sera PAS posée : compté comme
                // un abandon (avant, `flatten()` le taisait et la réponse partait « partout » sans lui).
                let mut h: Vec<Option<String>> = Vec::new();
                match conn.prepare("SELECT DISTINCT host FROM event WHERE src_ip=?1 AND ts>=?2 AND host IS NOT NULL AND host<>''") {
                    Ok(mut s) => match s.query_map(params![target, now_ts - window_s], |r| r.get::<_, Option<String>>(0)) {
                        Ok(it) => {
                            for r in it {
                                match r {
                                    Ok(x) => h.push(x),
                                    Err(_) => abandonnes += 1,
                                }
                            }
                        }
                        Err(_) => abandonnes += 1,
                    },
                    Err(_) => abandonnes += 1,
                }
                if h.is_empty() {
                    h.push(None); // IP vue sans hôte -> central
                }
                h
            } else {
                vec![None]
            };
            for host in hosts {
                // La déduplication est une LECTURE de la base : si elle échoue, la réponse n'est pas posée à
                // l'aveugle (elle pourrait doubler une action réelle), elle est COMPTÉE comme non posée et
                // retentée au prochain tick — le même sort qu'un hôte illisible ci-dessus (`P4.1-s`).
                let dup: i64 = match conn.query_row(
                    "SELECT COUNT(*) FROM action WHERE kind=?1 AND target=?2 AND IFNULL(host,'')=IFNULL(?3,'') AND ts>=?4",
                    params![kind, target, host, debut_dedup],
                    |r| r.get(0),
                ) {
                    Ok(n) => n,
                    Err(_) => {
                        abandonnes += 1;
                        continue;
                    }
                };
                if dup > 0 {
                    continue;
                }
                // AUTO-APPROVE (approved + dry_run=0 -> exécution réelle par le responder) UNIQUEMENT si mode
                // active ET playbook admin-authored. Un playbook editor résiduel reste pending/dry même en actif
                // (fix HIGH : `/api/mode active` seul ne suffit JAMAIS à exécuter une action posée par un editor).
                let (status, dry) = if mode == "active" && admin_authored { ("approved", 0) } else { ("pending", 1) };
                // `P10.20-t` — LA RIPOSTE EST POSÉE AVANT TOUT ARMEMENT, ET L'ÉCRITURE QUI N'A PAS EU
                // LIEU SE COMPTE. L'ancienne forme avalait cet `INSERT` (`let _ = conn.execute(..)`)
                // puis armait le miroir `net_ban` sur `status`/`dry`, deux variables LOCALES que
                // l'écriture n'avait jamais confirmées : une adresse pouvait être bloquée au niveau
                // HTTP sans qu'AUCUNE ligne n'existe pour l'exécuteur d'hôte, et le tick publiait
                // « 0 abandon » sur une riposte évaporée. La perte entre désormais dans `abandonnes`,
                // au même titre qu'un hôte illisible ou qu'une déduplication non lue (`P4.1-s`) : elle
                // sera re-tentée au prochain tick, et le bilan la DIT.
                if let crate::handlers::mise_en_file_de_riposte::RiposteMiseEnFile::NonEcrite(_) =
                    crate::handlers::mise_en_file_de_riposte::mettre_une_riposte_en_file(
                        &conn, now_ts, &kind, &target, status, dry, None, &format!("playbook:{name}"), host.as_deref(),
                    )
                {
                    abandonnes += 1;
                    continue;
                }
                // BAN NATIF PLUME (chantier ② Phase 1) : une réponse ban_ip AUTO-APPROUVÉE (mode actif + playbook
                // admin-authored) ARME AUSSI le blocage HTTP in-process (net_ban) — indépendamment de l'exécuteur
                // (responder local OU agent distant k3s). unban_ip le retire. `action_valid` a déjà écarté les IP
                // protégées / sous engagement en amont (ligne ~219). INERTE hors mode actif (status='pending').
                // OPT-IN : `PLUME_NETBAN_FROM_ACTIONS=1` requis — un auto-approve de
                // playbook ne verrouille PAS l'opérateur au HTTP plume par défaut (anti blast-radius). Canonicalise.
                if netban_from_actions_enabled() && status == "approved" && dry == 0 {
                    // `P4.7-j` — l'UNIQUE canonicaliseur (il REPLIE la forme mappée ; `parse + to_string` non).
                    let canon = match ssrf_norm_ip(target.trim()) { Some(i) => i.to_string(), None => String::new() };
                    if kind == "ban_ip" && !canon.is_empty() && !ip_is_protected(&canon) {
                        // REFUS SUR STORE PLEIN : tracé au ledger (tamper-evident). Un chemin automatique qui
                        // avale un refus laisserait croire à un blocage qui n'existe pas.
                        //
                        // `P10.20-v` — ET UNE ÉCRITURE QUI N'A PAS EU LIEU N'EST PAS UN PLAFOND. La pose
                        // rendait « armé » quoi qu'il arrive : ce tick pouvait publier « 0 abandon » sur un
                        // miroir HTTP inexistant. L'écriture ratée porte son propre genre de registre, donc
                        // elle se filtre, et elle entre dans `abandonnes` — le compte du tick est la seule
                        // grandeur que la surface d'état lit de ce chemin.
                        match netban_upsert(&conn, &canon, Some(now() + NETBAN_ACTION_TTL_S), "auto: playbook ban_ip", "playbook", "prod") {
                            PoseDeBan::Arme => {}
                            PoseDeBan::RefuseParLePlafond => {
                                let maillon = ledger_append(&conn, "netban.plafond", &format!("{canon} refusé : store live plein (playbook:{name})"));
                                abandonnes += u32::from(maillon.cause_de_non_inscription().is_some());
                            }
                            PoseDeBan::NonEcrit(cause) => {
                                ledger_append(&conn, "netban.non-arme", &format!("{canon} NON armé (playbook:{name}) : {cause}"));
                                abandonnes += 1;
                            }
                        }
                    } else if kind == "unban_ip" && !canon.is_empty() {
                        // `P4.7-k` — le compte de la levée est DIT, jamais avalé (et son ÉCHEC aussi).
                        // `P10.20-v` — et l'aveu qui n'est pas ENTRÉ au registre est lui-même un abandon :
                        // sans cela, la seule trace d'une levée ratée pourrait manquer sans que rien ne le dise.
                        let maillon = match netban_remove(&conn, &canon) {
                            Ok(retires) => ledger_append(&conn, "netban.remove", &format!("{canon} retirés={retires} (auto: playbook {name} unban_ip)")),
                            Err(e) => ledger_append(&conn, "netban.remove.echec", &format!("{canon} NON levé (auto: playbook {name} unban_ip) : {e}")),
                        };
                        abandonnes += u32::from(maillon.cause_de_non_inscription().is_some());
                    }
                }
            }
        }
    }
    crate::mesure_environnement::Mesure::Lue(abandonnes)
}

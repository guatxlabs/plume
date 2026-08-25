//! Mode Engagement autorisé (v75) — pentest natif, INERTE quand off : engagement compilé
//! `ActiveEngagement`/`ENGAGEMENT_SCOPE`, matcher/refresh de scope, cycle de vie des credentials,
//! validation `validate_engagement_scope`/`prefixes_overlap`, expiration/activation
//! (`expire`/`activate_due_engagements_conn`), les handlers engagement et `mode_get`/`mode_set`.
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// =====================================================================================
// MODE ENGAGEMENT AUTORISÉ (v75) — pentest natif black/grey/whitebox, SANS reconfigurer le SOC, SANS angle
// mort, auto-expirant, audité. INVARIANT SACRÉ (STRUCTUREL) : enforcement ≠ détection. La détection
// (run_due_rules -> alert) et le blocage (run_playbooks -> ban) sont DEUX moteurs indépendants ; la couverture
// lit la table `alert`. Un engagement suppresse UNIQUEMENT l'auto-BAN des IP scopées (Arm A : action_valid) ;
// collecte/règles/alertes/couverture restent 100 % ON. Le placeholder d'affichage `__ENGAGEMENT_EXCL__` n'est
// JAMAIS substitué dans `rule_sql` (garantie v55 pour __OPERATOR_EXCL__ : rien n'est retiré du chemin détection).
// INERTE quand `PLUME_ENGAGEMENT_MODE` absent/0 : index scope VIDE -> tag/guard/endpoint no-op -> byte-identique.
// =====================================================================================

/// Engagement ACTIF compilé (cache lecture-chaude). `matchers` = (préfixe/valeur, is_prefix) issus de
/// `parse_excl_item` (même matcher CIDR/préfixe que l'exclusion opérateur). `scope` = CIDRs bruts (endpoint pull).
#[derive(Clone)]
pub(crate) struct ActiveEngagement {
    pub(crate) engagement_id: String,
    pub(crate) scope: Vec<String>,
    pub(crate) matchers: Vec<(String, bool)>,
    pub(crate) window_end: i64,
    pub(crate) box_kind: String,
    pub(crate) adapter: String,
}
// INDEX SCOPE COMPILÉ, clé par db_path (isolation tenant : le tag d'ingest lit SA base). RAFRAÎCHI par le
// scheduler (tick 20 s) EXACTEMENT comme EXCL_CLAUSES au boot. VIDE quand aucun engagement actif / mode off ->
// ZÉRO travail chaud à l'ingest -> byte-identique.
pub(crate) static ENGAGEMENT_SCOPE: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, Vec<ActiveEngagement>>>> = std::sync::OnceLock::new();
pub(crate) fn engagement_scope_map() -> &'static parking_lot::RwLock<HashMap<String, Vec<ActiveEngagement>>> {
    ENGAGEMENT_SCOPE.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}

/// Renvoie l'engagement_id si `ip` tombe dans le scope d'un engagement ENCORE dans sa fenêtre (préfixe/exact),
/// sinon None. FIX TOCTOU (window_end) : la borne dure est vérifiée sur le CHEMIN CHAUD via `now()` — un
/// engagement dont la fenêtre est écoulée n'exempte plus AUCUNE ip, même si le rafraîchissement d'index
/// (tick 20 s : expire + engagement_scope_refresh) n'a pas encore purgé l'entrée ou si le scheduler est
/// bloqué/mort. L'expiry DB (statut + révocation des grants) reste géré par le tick ; ici on rend le
/// guard/tag AUTORITAIRES contre window_end indépendamment de la cadence de refresh.
pub(crate) fn engagement_scope_match(list: &[ActiveEngagement], ip: &str) -> Option<String> {
    let low = ip.trim().to_ascii_lowercase();
    if low.is_empty() { return None; }
    let n = now();
    for e in list {
        if e.window_end <= n { continue; } // fenêtre dure écoulée -> plus d'exemption (self-expiry chaud)
        for (val, is_prefix) in &e.matchers {
            let v = val.to_ascii_lowercase();
            let hit = if *is_prefix { low.starts_with(&v) } else { low == v };
            if hit { return Some(e.engagement_id.clone()); }
        }
    }
    None
}

/// TAG d'ingest (chemin chaud). Off OU index VIDE pour ce db_path -> "" en 1 test de drapeau atomique / 1 lookup
/// map -> l'INSERT écrit engagement_id='' (= DEFAULT de la colonne) -> ligne BYTE-IDENTIQUE. Jamais de load_config.
pub(crate) fn engagement_tag_for_ip(db_path: &str, ip: Option<&str>) -> String {
    if !engagement_enabled() { return String::new(); }
    let ip = match ip { Some(s) if !s.trim().is_empty() => s, _ => return String::new() };
    let m = engagement_scope_map().read();
    match m.get(db_path) {
        Some(list) => engagement_scope_match(list, ip).unwrap_or_default(),
        None => String::new(),
    }
}

/// GUARD Arm A : true si `ip` est dans le scope d'un engagement actif DU TENANT `db_path`. FIX isolation
/// multi-tenant : on consulte UNIQUEMENT l'index de CE db_path (`m.get(db_path)`), SYMÉTRIQUE avec le tag
/// d'ingest (`engagement_tag_for_ip`) — un engagement du tenant A ne suspend JAMAIS l'auto-ban du tenant B.
/// En mode 0 il n'y a qu'un db_path (`default`) -> comportement byte-identique. L'appelant action_valid gate
/// d'abord sur engagement_enabled(), donc off -> jamais appelé (index vide de toute façon).
pub(crate) fn ip_in_active_engagement(ip: &str, db_path: &str) -> bool {
    let ip = ip.trim();
    if ip.is_empty() { return false; }
    let m = engagement_scope_map().read();
    m.get(db_path).map(|list| engagement_scope_match(list, ip).is_some()).unwrap_or(false)
}

/// Charge les engagements ACTIFS non expirés d'une base -> liste compilée (matchers CIDR). Scope JSON invalide /
/// sans matcher -> ligne ignorée (jamais un scope vide qui matcherait tout).
pub(crate) fn load_active_engagements(conn: &Connection, now_i: i64) -> Vec<ActiveEngagement> {
    let mut out = Vec::new();
    let mut stmt = match conn.prepare(
        "SELECT id, scope, window_end, box, adapter FROM engagement WHERE status='active' AND window_end > ?1",
    ) { Ok(s) => s, Err(_) => return out };
    let rows = stmt.query_map(params![now_i], |r| Ok((
        r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?,
    )));
    if let Ok(rows) = rows {
        for (id, scope_json, wend, boxk, adapter) in rows.flatten() {
            let scope: Vec<String> = serde_json::from_str(&scope_json).unwrap_or_default();
            let matchers: Vec<(String, bool)> = scope.iter().filter_map(|c| parse_excl_item(c)).collect();
            if matchers.is_empty() { continue; }
            out.push(ActiveEngagement { engagement_id: id, scope, matchers, window_end: wend, box_kind: boxk, adapter });
        }
    }
    out
}

/// Recompile l'index scope de CE db_path (appelé au tick 20 s + à la création/clôture pour effet immédiat).
/// Off -> purge l'entrée (l'index reste VIDE -> ingest byte-identique).
pub(crate) fn engagement_scope_refresh(db_path: &str, conn: &Connection) {
    if !engagement_enabled() {
        let mut m = engagement_scope_map().write();
        m.remove(db_path);
        return;
    }
    let list = load_active_engagements(conn, now());
    let mut m = engagement_scope_map().write();
    if list.is_empty() { m.remove(db_path); } else { m.insert(db_path.to_string(), list); }
}

/// box valide (les 3 sont first-class dès le départ).
pub(crate) fn engagement_box_valid(b: &str) -> bool {
    matches!(b, "blackbox" | "greybox" | "whitebox")
}
/// INTENT de provisioning par box, déclaré en `engagement_grant` (pending) : blackbox = aucun grant (exemption +
/// scope seuls) ; greybox = 1 cred/session scopée low-priv time-boxée ; whitebox = compte full-priv scopé +
/// lecture code/config. Le privilège (low vs full) se dérive de `box` côté adaptateur de provisioning.
pub(crate) fn engagement_grant_kinds_for_box(b: &str) -> &'static [&'static str] {
    match b {
        "greybox" => &["scoped_cred"],
        "whitebox" => &["scoped_cred", "config_read"],
        _ => &[],
    }
}

// ================================================================================================
// PROVISIONING PLUME-LOCAL (adaptateur de provisioning de RÉFÉRENCE, DAEMON-INTERNE) — v75.
//
// Le système token/user/session de plume EST le daemon : on minte/révoque un credential plume SCOPÉ
// IN-PROCESS (pas d'adaptateur hôte externe — réservé aux IdP externes type Authentik, DIFFÉRÉ). Le
// credential est un COMPTE plume (`user`) au NOM RÉSERVÉ `eng-cred-*`, lié à son engagement par
// engagement_grant.ref = username. INVARIANT SACRÉ : le provisioning change ce que le TESTEUR peut
// ATTEINDRE (auth), JAMAIS ce que le SOC ENREGISTRE (event/alert/rule/rollup intacts). Mode off :
// aucun engagement créable (create 409) -> aucun mint -> byte-identique, À UNE EXCEPTION ASSUMÉE près :
// la réservation du namespace `eng-cred-*` dans user_create (rejette ce préfixe même mode off). C'est
// DÉLIBÉRÉ (un compte durable créé mode off ne doit pas pouvoir usurper le discriminant d'auth si le mode
// est activé ensuite) et sans impact détection/collecte/données -> NE PAS la déplacer sous engagement_enabled().
// ================================================================================================

/// Préfixe RÉSERVÉ des comptes plume mintés pour un engagement. user_create le REFUSE (aucun compte
/// interactif ne peut le porter) -> discriminant fiable « credential d'engagement » sur le chemin d'auth
/// (hard-expiry + jamais mis en cache d'auth). Charset compatible avec la politique de nom (`-` autorisé).
pub(crate) const ENG_CRED_PREFIX: &str = "eng-cred-";

/// Rôle plume SCOPÉ d'un credential d'engagement selon la box : greybox = viewer (lecture seule, low-priv) ;
/// whitebox = admin (élevé) MAIS borné par le marqueur d'engagement + hard-expiry (JAMAIS un admin global
/// permanent : la validité EST la fenêtre de l'engagement, re-vérifiée à CHAQUE auth). blackbox ne minte pas.
pub(crate) fn engagement_cred_role_for_box(b: &str) -> &'static str {
    match b {
        "whitebox" => "admin",
        _ => "viewer", // greybox (+ défaut défensif) : lecture seule
    }
}

/// CONTAINMENT du credential d'engagement (borne la CAPACITÉ, pas seulement la DURÉE). Un principal
/// `eng-cred-*` est un ACCÈS DE TEST BORNÉ À LA FENÊTRE ; whitebox lui donne le rôle `admin` (VISIBILITÉ
/// élevée : lire la config/couverture) MAIS un admin brut pourrait, PENDANT la fenêtre, se forger une
/// PERSISTANCE qui SURVIT à window_end — créer un compte durable role=admin (user_create ne filtre que le
/// NOM cible, jamais l'appelant), reset le mdp admin réel (/api/password), minter un autre engagement — ou
/// RÉDUIRE la détection/collecte (désactiver règles/collecteurs, POST /api/mode). Cela défait la garantie
/// hard-expiry (le compte expire, pas l'accès qu'il a fabriqué) ET l'esprit de l'invariant sacré
/// (« détection JAMAIS réduite »). RÈGLE FAIL-CLOSED (superset de tout denylist, aucune route future oubliée) :
/// un eng-cred est LECTURE SEULE — TOUTE mutation est refusée, quel que soit son rôle ; la LECTURE reste
/// ouverte (c'est le SENS MÊME du whitebox : VOIR, jamais ALTÉRER — la collecte/l'enregistrement SOC restent
/// intacts). Greybox=viewer : déjà refusé en écriture par rbac_gate (no-op ici). Gated sur le PRÉFIXE RÉSERVÉ
/// -> INERTE pour tout compte normal => hors engagement, byte-identique.
pub(crate) fn engagement_cred_write_gate(name: &str, mutating: bool) -> Result<(), (StatusCode, &'static str)> {
    if mutating && name.starts_with(ENG_CRED_PREFIX) {
        return Err((
            StatusCode::FORBIDDEN,
            "credential d'engagement : lecture seule (aucune mutation — anti-persistance post-fenêtre / détection non réductible)",
        ));
    }
    Ok(())
}

/// Hex CSPRNG (/dev/urandom). None si l'entropie noyau est indisponible -> le mint ÉCHOUE (jamais de secret
/// faible/prévisible pour un credential). Sert le secret bearer (24 o) ET le suffixe de nom (12 o).
pub(crate) fn engagement_rand_hex(nbytes: usize) -> Option<String> {
    use std::io::Read;
    let mut b = vec![0u8; nbytes];
    std::fs::File::open("/dev/urandom").ok()?.read_exact(&mut b).ok()?;
    Some(hex_encode(&b))
}

/// HARD-EXPIRY (horloge murale) d'un credential d'engagement : true SEULEMENT si le compte `username` est lié
/// (engagement_grant.ref, kind='scoped_cred', status='issued') à un engagement dont la fenêtre COURANTE est
/// OUVERTE : window_start <= now < window_end. Source de vérité UNIQUE = la fenêtre de l'engagement -> un
/// credential ne s'authentifie NI avant window_start (engagement 'scheduled'), NI après window_end (même si le
/// sweep de révocation est EN RETARD : double-garde comme l'enforcer) ; un grant 'revoked' (fin/expiry) ->
/// aucune ligne -> false. Appelé UNIQUEMENT pour les noms `eng-cred-*` (0 coût pour un compte normal).
pub(crate) fn engagement_cred_within_window(conn: &Connection, username: &str, now_i: i64) -> bool {
    conn.query_row(
        "SELECT e.window_start, e.window_end FROM engagement_grant g \
           JOIN engagement e ON e.id = g.engagement_id \
          WHERE g.ref = ?1 AND g.kind = 'scoped_cred' AND g.status = 'issued' LIMIT 1",
        params![username],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
    )
    .map(|(ws, we)| now_i >= ws && now_i < we)
    .unwrap_or(false)
}

/// RÉVOCATION du credential minté : SUPPRIME les comptes plume scopés (engagement_grant.ref) des grants
/// scoped_cred ENCORE 'issued' d'un engagement. À appeler DANS la transaction de révocation AVANT de passer
/// les grants en 'revoked' (le sous-SELECT filtre status='issued'). Après suppression, lookup_basic_ident
/// renvoie None -> l'auth du credential échoue IMMÉDIATEMENT (les eng-creds ne sont jamais mis en cache).
/// Idempotent / no-op quand aucun compte ne matche (grants sans ref, box blackbox, tests unitaires du sweep).
pub(crate) fn revoke_engagement_creds(conn: &Connection, engagement_id: &str) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM user WHERE name IN \
           (SELECT ref FROM engagement_grant \
             WHERE engagement_id = ?1 AND kind = 'scoped_cred' AND ref <> '' AND status = 'issued')",
        params![engagement_id],
    )?;
    Ok(())
}

/// Deux préfixes se CHEVAUCHENT si l'un est préfixe de l'autre (les matchers parse_excl_item finissent sur
/// une frontière d'octet '.'/':' -> comparaison de préfixe sûre).
pub(crate) fn prefixes_overlap(a: &str, b: &str) -> bool {
    !a.is_empty() && !b.is_empty() && (a.starts_with(b) || b.starts_with(a))
}
/// VALIDATION scope : REFUSE (1) route par défaut / joker (0.0.0.0/0, ::/0, *) ; (2) masque plancher (IPv4 /8,
/// IPv6 /16 : au-dessous = trop large) ; (3) chevauchement avec loopback/link-local OU une IP protégée
/// opérateur/passerelle -> jamais de blanket-exempt d'une IP qu'un ban ne doit jamais rater (self-DoS /
/// neutralisation). NB : RFC1918 (10/192.168/172.16) est ADMIS (pentest interne grey/whitebox légitime).
pub(crate) fn validate_engagement_scope(scope: &[String], protected: &[(String, bool)]) -> Result<(), String> {
    if scope.is_empty() {
        return Err("au moins un CIDR requis".into());
    }
    const NEVER: &[&str] = &["127.", "169.254.", "::1", "fe80:"];
    for raw in scope {
        let c = raw.trim();
        if c.is_empty() { return Err("entrée de scope vide".into()); }
        if c == "0.0.0.0/0" || c == "::/0" || c == "*" || c == "0.0.0.0" || c == "::" {
            return Err(format!("'{c}' : une route par défaut exempterait tout — refusé"));
        }
        // FIX (breadth cap contournable) : un suffixe joker `*` (ex "8*","2*") produit un matcher PRÉFIXE
        // SANS jamais passer par le plancher de masque (gardé par split_once('/')), donc "8*" exempterait
        // 8.x MAIS aussi 80-89.x + 8xxx:: (~11 /8) — total ~1,1 milliard d'IP. On INTERDIT le joker et on
        // n'accepte QUE des CIDR stricts (base/N) ou une IP exacte BIEN FORMÉE. Le plancher est validé sur
        // la FAMILLE RÉELLEMENT PARSÉE (IpAddr : v4 /8, v6 /16) et non sur un test de chaîne `.contains(':')`.
        if c.contains('*') {
            return Err(format!("'{c}' : joker '*' interdit dans un scope d'engagement (CIDR base/N ou IP exacte requis)"));
        }
        if let Some((base, mask)) = c.split_once('/') {
            let ip: std::net::IpAddr = match base.trim().parse() {
                Ok(ip) => ip,
                Err(_) => return Err(format!("CIDR invalide (base non-IP) : '{c}'")),
            };
            let n: u32 = match mask.trim().parse() {
                Ok(n) => n,
                Err(_) => return Err(format!("CIDR invalide (masque non numérique) : '{c}'")),
            };
            let (max, floor) = if ip.is_ipv6() { (128u32, 16u32) } else { (32u32, 8u32) };
            if n > max {
                return Err(format!("'{c}' : masque /{n} > /{max} — invalide"));
            }
            if n < floor {
                return Err(format!("'{c}' : masque /{n} < /{floor} (trop large) — refusé"));
            }
        } else if c.parse::<std::net::IpAddr>().is_err() {
            // pas de '/', pas de joker : DOIT être une IP exacte bien formée (rejette "8", "20", "foo").
            return Err(format!("scope invalide : '{c}' (CIDR base/N ou IP exacte attendu)"));
        }
        let (sval, _sp) = match parse_excl_item(c) {
            Some(m) => m,
            None => return Err(format!("CIDR invalide : '{c}'")),
        };
        let slow = sval.to_ascii_lowercase();
        for p in NEVER {
            if prefixes_overlap(&slow, &p.to_ascii_lowercase()) {
                return Err(format!("'{c}' chevauche loopback/link-local ({p}) — exemption refusée"));
            }
        }
        for (pval, _pp) in protected {
            if prefixes_overlap(&slow, &pval.to_ascii_lowercase()) {
                return Err(format!("'{c}' chevauche une IP protégée opérateur/passerelle ('{pval}') — exemption refusée"));
            }
        }
    }
    Ok(())
}

/// Identifiant d'engagement aléatoire (128 bits CSPRNG). `None` si l'entropie noyau est indisponible -> la
/// création ÉCHOUE, comme le mint du secret trois lignes plus bas (`engagement_rand_hex`).
///
/// Le repli `eng_{horodatage}` retiré ici n'était pas un secret — mais il était la MÊME FIGURE que celle
/// fermée sur la clé de tenant et sur le secret d'installation, DANS une fonction dont le voisin immédiat
/// refuse déjà de servir sans entropie : la même requête aurait rendu un identifiant horodaté et zéro
/// credential. Il portait en plus une collision réelle — deux engagements créés dans la même seconde
/// visaient la même clé primaire `engagement.id`.
pub(crate) fn engagement_new_id() -> Option<String> {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom").ok()?.read_exact(&mut b).ok()?;
    Some(format!("eng_{}", hex_encode(&b)))
}

/// Cœur TESTABLE de l'auto-expiry : passe en 'expired' les engagements ACTIFS dont la fenêtre est écoulée,
/// RÉVOQUE tout grant encore ouvert (issued/pending -> revoked, quel que soit le box : grey/whitebox ne
/// survivent jamais à la fenêtre) et AUDITE la clôture (double-write ledger + event plume-engagement
/// non-purgeable, fail-closed transactionnel PAR engagement). Renvoie le nb d'engagements expirés.
pub(crate) fn expire_due_engagements_conn(conn: &Connection, now_i: i64) -> usize {
    let due: Vec<(String, String)> = match conn.prepare(
        "SELECT id, COALESCE(name,'') FROM engagement WHERE status='active' AND window_end < ?1 ORDER BY window_end LIMIT 50",
    ) {
        Ok(mut s) => s.query_map(params![now_i], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map(|m| m.flatten().collect()).unwrap_or_default(),
        Err(_) => return 0,
    };
    let mut n = 0usize;
    for (id, name) in &due {
        if conn.execute_batch("BEGIN IMMEDIATE").is_err() { continue; }
        let outcome: rusqlite::Result<()> = (|| {
            conn.execute("UPDATE engagement SET status='expired', ended_ts=?2 WHERE id=?1 AND status='active'", params![id, now_i])?;
            revoke_engagement_creds(conn, id)?; // INVALIDE les comptes mintés (avant de révoquer les grants)
            conn.execute(
                "UPDATE engagement_grant SET status='revoked', revoked_ts=?2 WHERE engagement_id=?1 AND status IN ('issued','pending')",
                params![id, now_i],
            )?;
            audit_source_change(
                conn, "plume-engagement", "config.engagement.expire",
                &format!("engagement '{id}' ({name}) expiré (fenêtre écoulée) -> exemption levée, grants révoqués"),
                2,
                &format!("engagement autorisé '{name}' EXPIRÉ : auto-ban rétabli sur son scope, accès pentest révoqués"),
                &json!({ "engagement_id": id, "event": "expire" }).to_string(),
            )?;
            Ok(())
        })();
        match outcome {
            Ok(()) => { let _ = conn.execute_batch("COMMIT"); n += 1; }
            Err(_) => { let _ = conn.execute_batch("ROLLBACK"); }
        }
    }
    n
}
/// Cœur TESTABLE du cycle de vie 'scheduled' (FIX : la branche scheduled était morte — jamais activée, jamais
/// expirée). (1) PROMEUT scheduled->active les engagements dont window_start est atteint et window_end encore
/// future (audit config.engagement.activate, appaire la création) ; (2) EXPIRE scheduled->expired ceux dont la
/// fenêtre est écoulée AVANT toute activation (révoque les grants 'pending', audit config.engagement.expire) —
/// sinon la ligne + les grants 'pending' traînaient indéfiniment. Renvoie (activés, expirés_depuis_scheduled).
/// Fail-closed transactionnel PAR engagement (comme expire_due_engagements_conn).
pub(crate) fn activate_due_engagements_conn(conn: &Connection, now_i: i64) -> (usize, usize) {
    // (1) scheduled -> active : la fenêtre planifiée s'ouvre.
    let to_activate: Vec<(String, String)> = match conn.prepare(
        "SELECT id, COALESCE(name,'') FROM engagement WHERE status='scheduled' AND window_start <= ?1 AND window_end > ?1 ORDER BY window_start LIMIT 50",
    ) {
        Ok(mut s) => s.query_map(params![now_i], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map(|m| m.flatten().collect()).unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let mut activated = 0usize;
    for (id, name) in &to_activate {
        if conn.execute_batch("BEGIN IMMEDIATE").is_err() { continue; }
        let outcome: rusqlite::Result<()> = (|| {
            conn.execute("UPDATE engagement SET status='active' WHERE id=?1 AND status='scheduled'", params![id])?;
            audit_source_change(
                conn, "plume-engagement", "config.engagement.activate",
                &format!("engagement '{id}' ({name}) activé (window_start atteint) -> exemption auto-ban en vigueur sur son scope"),
                4,
                &format!("ENGAGEMENT AUTORISÉ '{name}' ACTIVÉ (fenêtre planifiée ouverte) : auto-ban SUSPENDU sur son scope (détection/alerte INCHANGÉES)"),
                &json!({ "engagement_id": id, "event": "activate" }).to_string(),
            )?;
            Ok(())
        })();
        match outcome {
            Ok(()) => { let _ = conn.execute_batch("COMMIT"); activated += 1; }
            Err(_) => { let _ = conn.execute_batch("ROLLBACK"); }
        }
    }
    // (2) scheduled -> expired : fenêtre écoulée SANS activation (mêmes effets que l'expiry d'un actif).
    let stale: Vec<(String, String)> = match conn.prepare(
        "SELECT id, COALESCE(name,'') FROM engagement WHERE status='scheduled' AND window_end < ?1 ORDER BY window_end LIMIT 50",
    ) {
        Ok(mut s) => s.query_map(params![now_i], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map(|m| m.flatten().collect()).unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let mut expired = 0usize;
    for (id, name) in &stale {
        if conn.execute_batch("BEGIN IMMEDIATE").is_err() { continue; }
        let outcome: rusqlite::Result<()> = (|| {
            conn.execute("UPDATE engagement SET status='expired', ended_ts=?2 WHERE id=?1 AND status='scheduled'", params![id, now_i])?;
            revoke_engagement_creds(conn, id)?; // INVALIDE les comptes mintés (scheduled expiré sans activation)
            conn.execute(
                "UPDATE engagement_grant SET status='revoked', revoked_ts=?2 WHERE engagement_id=?1 AND status IN ('issued','pending')",
                params![id, now_i],
            )?;
            audit_source_change(
                conn, "plume-engagement", "config.engagement.expire",
                &format!("engagement planifié '{id}' ({name}) expiré sans activation (fenêtre écoulée) -> grants révoqués"),
                2,
                &format!("engagement PLANIFIÉ '{name}' expiré AVANT activation : fenêtre écoulée, accès pentest révoqués"),
                &json!({ "engagement_id": id, "event": "expire", "from": "scheduled" }).to_string(),
            )?;
            Ok(())
        })();
        match outcome {
            Ok(()) => { let _ = conn.execute_batch("COMMIT"); expired += 1; }
            Err(_) => { let _ = conn.execute_batch("ROLLBACK"); }
        }
    }
    (activated, expired)
}
/// Sweep boucle-de-fond (tick 20 s, à côté de escalate_overdue_cases). SELF-GATED : hors mode engagement,
/// return AVANT tout lock/SELECT -> no-op strict (byte-identique). Cycle de vie COMPLET : activation des
/// 'scheduled' échus PUIS expiry des 'active' (+ scheduled sans activation) dont la fenêtre est écoulée.
pub(crate) fn expire_due_engagements(db: &Arc<Mutex<Connection>>) {
    if !engagement_enabled() { return; }
    let conn = db.lock();
    let now_i = now();
    activate_due_engagements_conn(&conn, now_i); // scheduled -> active | expired (branche jadis morte)
    let _ = expire_due_engagements_conn(&conn, now_i);
}

/// GET /api/engagements/active — SEAM PULL enforcer (agent token, host-bound comme /api/actions/pending).
/// [{engagement_id, scope:[CIDR], window_end, box, adapter}] pour status='active' && now<window_end ; [] sinon.
pub(crate) async fn engagements_active(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if au.role != "agent" || au.name.is_empty() {
        return (StatusCode::FORBIDDEN, "token agent lié à un hôte requis").into_response();
    }
    if !engagement_enabled() {
        return Json(json!([])).into_response();
    }
    with_write(&st, &au, |conn| {
    let list = load_active_engagements(&conn, now());
    let out: Vec<Value> = list.iter().map(|e| json!({
        "engagement_id": e.engagement_id,
        "scope": e.scope,
        "window_end": e.window_end,
        "box": e.box_kind,
        "adapter": e.adapter,
    })).collect();
    Json(json!(out)).into_response()
    })
}

// =================================================================================================
// `P11.17-f` — LA LISTE DES ENGAGEMENTS DIT CE QU'ELLE SERT, ET CE QU'ELLE NE SERT PAS
//
// LE DÉFAUT. `GET /api/engagements` bornait sa lecture à deux cents lignes et ne rendait QUE ces
// lignes : ni total, ni indicateur de troncature. Le seul chiffre disponible était donc le nombre de
// lignes SERVIES — qu'un lecteur prend pour un total alors qu'il est une fenêtre. Cette table ne
// décroît JAMAIS : aucun `DELETE` ne la touche (le cycle de vie ne fait que passer `status` à
// `expired` / `revoked`), donc les engagements clos s'y accumulent et la fenêtre en couvre une part
// toujours plus petite. Sur un registre d'AUTORISATIONS de pentest, une ligne hors d'atteinte est une
// autorisation qu'on ne sait plus avoir accordée.
//
// CE QUE LA CLÉ ET LES INDEX DE **CETTE** TABLE PERMETTENT — vérifiés plutôt que supposés :
//   * `engagement.id` est `TEXT PRIMARY KEY` (migration v75) et vaut `eng_<32 hexadécimaux tirés de
//     /dev/urandom>`. **L'ORDRE DES `id` N'EST DONC PAS CELUI DES CRÉATIONS**, contrairement à
//     `action.id` qui est un alias de `rowid` : le curseur sur l'identifiant seul de `P11.17-e` ne se
//     recopie PAS ici. Il paginerait dans un ordre ALÉATOIRE, sans rapport avec la liste servie.
//   * Le seul index de la table est `idx_engagement_status(status, window_end)`, posé pour le
//     balayage d'expiration. **`created` n'est indexé par rien**, et l'ordre servi l'enveloppe dans
//     `COALESCE(created,0)` — une expression qu'aucun index ne couvre. La fenêtre impose donc déjà un
//     parcours complet suivi d'un tri : la borne borne l'ENVOI, pas la lecture, et le total borné
//     ajouté ici coûte au pire moins que la fenêtre qu'il accompagne.
//   * UN CURSEUR `(created,id)` SERAIT CORRECT MAIS SANS SUPPORT : `created` n'est jamais réécrit
//     après la création (seuls `status` et `ended_ts` le sont), donc la clé serait STABLE — au
//     contraire de celle de l'inventaire d'indicateurs. Il n'est pas construit dans ce lot, et c'est
//     écrit tel quel : chaque page rejouerait le parcours et le tri complets, pour une table dont la
//     croissance est celle d'un geste humain audité et non celle d'un flux.
//   * CE QUE CETTE ROUTE N'A PAS, ET QUI COMPTE POUR LIRE LA SUITE : aucun module de `web/` ne la
//     consomme — relevé le 2026-08-25 par recherche sur l'arbre entier. Il n'y a pas de vue où poser
//     l'aveu ; c'est la RÉPONSE elle-même qui doit le porter, pour l'exploitant qui l'interroge.
// =================================================================================================

/// TAILLE DE LA FENÊTRE servie par `GET /api/engagements` — les `ENGAGEMENTS_WINDOW` engagements
/// déclarés le plus récemment. Nommée plutôt qu'écrite dans l'énoncé : le test la lit ici au lieu de
/// la recopier.
pub(crate) const ENGAGEMENTS_WINDOW: i64 = 200;

/// LE SEUL fabricant du COMPTAGE du registre — écrit une fois pour que le test mesure CE QUI EST ÉMIS
/// et non une copie. `LIMIT CAP+1` arrête le balayage au plafond partagé : sous le plafond le total est
/// EXACT, au-dessus il est plafonné ET annoncé.
pub(crate) fn engagements_total_sql() -> String {
    format!("SELECT COUNT(*) FROM (SELECT 1 FROM engagement LIMIT {})", PAGINATION_COUNT_CAP + 1)
}

/// LE SEUL fabricant de la FENÊTRE servie. Projection et ordre INCHANGÉS : ce correctif ajoute un
/// chiffre à côté de la liste, il ne touche pas à la liste.
pub(crate) fn engagements_window_sql() -> String {
    format!(
        "SELECT id,name,box,scope,window_start,window_end,authorizer,reason,status,adapter,created,created_by,ended_ts \
         FROM engagement ORDER BY COALESCE(created,0) DESC, id DESC LIMIT {ENGAGEMENTS_WINDOW}"
    )
}

/// Fenêtre + total borné du registre d'engagements. Fonction PURE sur `&Connection` -> testable sans
/// `AppState`.
///
/// Rend `{engagements, served, window, total, total_capped}`. `served` est le nombre de lignes RENDUES
/// et `window` la borne de la route : leur égalité est ce qui dit au lecteur que la borne MORD.
/// `total`/`total_capped` valent `null` — jamais `0` — quand le comptage n'a pas pu être lu : « non
/// compté » et « aucun engagement » sont deux faits différents.
pub(crate) fn engagements_page(conn: &Connection) -> Value {
    let rows: Vec<Value> = match conn.prepare(&engagements_window_sql()) {
        Ok(mut stmt) => stmt.query_map([], engagement_row_json).map(|m| m.flatten().collect()).unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    // COMPTAGE BORNÉ : `raw` = min(vrai_total, CAP+1). > CAP -> plafonné (CAP + `total_capped`) ; sinon
    // exact. Un comptage qui ÉCHOUE rend `null`, jamais un zéro rassurant.
    let (total, total_capped) = match conn.query_row(&engagements_total_sql(), [], |r| r.get::<_, i64>(0)) {
        Ok(raw) => {
            let capped = raw > PAGINATION_COUNT_CAP;
            (json!(if capped { PAGINATION_COUNT_CAP } else { raw }), json!(capped))
        }
        Err(_) => (Value::Null, Value::Null),
    };
    json!({
        "engagements": rows,
        "served": rows.len(),
        "window": ENGAGEMENTS_WINDOW,
        "total": total,
        "total_capped": total_capped,
    })
}

/// GET /api/engagements — fenêtre du registre, servie AVEC son total borné (admin ; double garde
/// route_min_role + re-check ici).
pub(crate) async fn engagements_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    crate::req_conn!(st, au, conn);
    Json(engagements_page(&conn)).into_response()
}

/// Ligne engagement -> JSON (partagé list/get). scope JSON -> tableau.
pub(crate) fn engagement_row_json(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    let scope_json: String = r.get(3)?;
    Ok(json!({
        "id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "box": r.get::<_, String>(2)?,
        "scope": serde_json::from_str::<Vec<String>>(&scope_json).unwrap_or_default(),
        "window_start": r.get::<_, i64>(4)?, "window_end": r.get::<_, i64>(5)?,
        "authorizer": r.get::<_, String>(6)?, "reason": r.get::<_, String>(7)?, "status": r.get::<_, String>(8)?,
        "adapter": r.get::<_, String>(9)?, "created": r.get::<_, Option<i64>>(10)?,
        "created_by": r.get::<_, Option<String>>(11)?, "ended_ts": r.get::<_, Option<i64>>(12)?,
    }))
}

/// GET /api/engagements/:id — engagement + ses grants (admin). Les grants exposent l'INTENT de provisioning :
/// un adaptateur de provisioning PULL les 'pending' (émet + écrit le ref), le sweep les passe 'revoked' — MÊME
/// pattern déclare-vs-applique que /api/engagements/active pour l'enforcer.
pub(crate) async fn engagement_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<String>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    crate::req_conn!(st, au, conn);
    let mut eng = match conn.query_row(
        "SELECT id,name,box,scope,window_start,window_end,authorizer,reason,status,adapter,created,created_by,ended_ts \
         FROM engagement WHERE id=?1",
        params![id], engagement_row_json,
    ) {
        Ok(v) => v,
        Err(_) => return not_found("engagement introuvable"),
    };
    let grants: Vec<Value> = match conn.prepare(
        "SELECT id,kind,ref,idp_adapter,issued_ts,revoked_ts,status FROM engagement_grant WHERE engagement_id=?1 ORDER BY id",
    ) {
        Ok(mut s) => s.query_map(params![id], |r| Ok(json!({
            "id": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?, "ref": r.get::<_, String>(2)?,
            "idp_adapter": r.get::<_, String>(3)?, "issued_ts": r.get::<_, Option<i64>>(4)?,
            "revoked_ts": r.get::<_, Option<i64>>(5)?, "status": r.get::<_, String>(6)?,
        }))).map(|m| m.flatten().collect()).unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    eng["grants"] = json!(grants);
    Json(eng).into_response()
}

/// POST /api/engagements — CRÉE un engagement (admin-only, break-glass, audité, transactionnel fail-closed).
/// Valide box ∈ {black,grey,white} + scope (refus 0.0.0.0/0 / overlaps opérateur-loopback) + window_end
/// OBLIGATOIRE (capé) + reason OBLIGATOIRE. Déclare status='active' (ou 'scheduled' si window_start futur) +
/// les grants d'INTENT par box. Superadmin cross-tenant : l'écriture cross-tenant exige déjà X-Plume-Breakglass
/// (auth_guard/resolve_tenant_access) -> hérité. Le SOC alerte sur l'event plume-engagement sev=4.
pub(crate) async fn engagement_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    // FIX (asymétrie /active) : symétrique avec engagements_active — hors mode engagement, l'endpoint est
    // INERTE (invariant ligne 170). Sans ce garde, un admin créait un engagement status='active' qui ne
    // suspend RIEN (action_valid_ctx + engagement_scope_refresh sont self-gated sur engagement_enabled()),
    // en écrivant une ligne + un audit non-purgeable : un pentest « autorisé » silencieusement sans effet.
    if !engagement_enabled() {
        return err_json(StatusCode::CONFLICT, "mode engagement désactivé (PLUME_ENGAGEMENT_MODE=0) : impossible de créer un engagement (il n'aurait aucun effet d'exemption)");
    }
    let name = b.trimmed("name");
    let box_kind = b.trimmed("box");
    if !engagement_box_valid(&box_kind) {
        return bad_req("box invalide (attendu blackbox|greybox|whitebox)");
    }
    let scope: Vec<String> = b.get("scope").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    if let Err(e) = validate_engagement_scope(&scope, protected_ip_matchers()) {
        return bad_req(format!("scope refusé : {e}"));
    }
    let reason = b.trimmed("reason");
    if reason.is_empty() {
        return bad_req("reason obligatoire (break-glass : justification de l'engagement)");
    }
    let authorizer = b.trimmed("authorizer");
    let adapter = b.trimmed("adapter");
    let idp_adapter = b.trimmed("idp_adapter");
    let now_i = now();
    let window_start = b.get("window_start").and_then(|v| v.as_i64()).filter(|&t| t > 0).unwrap_or(now_i);
    let window_end_req = match b.get("window_end").and_then(|v| v.as_i64()).filter(|&t| t > 0) {
        Some(t) => t,
        None => return bad_req("window_end obligatoire (epoch s : fin dure de l'engagement)"),
    };
    if window_end_req <= window_start {
        return bad_req("window_end doit suivre window_start");
    }
    if window_end_req <= now_i {
        return bad_req("window_end doit être dans le futur");
    }
    let cap = window_start.saturating_add(engagement_max_window_s(&load_config()));
    let window_end = window_end_req.min(cap);
    let capped = window_end < window_end_req;
    let status = if window_start > now_i { "scheduled" } else { "active" };
    let id = match engagement_new_id() {
        Some(i) => i,
        None => return server_err("entropie noyau indisponible : engagement NON créé (aucun identifiant dérivé d'une horloge n'est émis)"),
    };
    let scope_json = serde_json::to_string(&scope).unwrap_or_else(|_| "[]".into());
    let grant_kinds = engagement_grant_kinds_for_box(&box_kind);

    // INCOMPATIBILITÉ multi-tenant : l'adaptateur plume-local minte le compte scopé dans la
    // base du TENANT courant (req_db -> INSERT INTO user). MAIS dès qu'un control-plane est présent
    // (PLUME_MULTI_TENANT=1 fonctionnel), l'auth Basic/cookie résout les identités depuis platform_user
    // (control-plane), JAMAIS depuis la table `user` du tenant (lookup_basic_ident early-return) -> le
    // credential serait MORT (401 systématique) et le hard-expiry (ligne 4533) inatteignable. On REFUSE donc
    // AVANT tout mint, plutôt que de renvoyer un secret inutilisable + un grant 'issued' TROMPEUR. blackbox
    // (aucun scoped_cred : exemption/scope seuls) reste créable en mode 1. Le provisioning IdP-externe pour le
    // mode 1 (mint dans platform_user) est un follow-up documenté, DIFFÉRÉ (risque outpost-deadlock Authentik).
    if st.tenants.control.is_some() && grant_kinds.contains(&"scoped_cred") {
        return err_json(StatusCode::CONFLICT, "provisioning de credential scopé indisponible en mode multi-tenant (PLUME_MULTI_TENANT=1) : l'auth résout le control-plane (platform_user), pas la base du tenant — le credential ne pourrait jamais s'authentifier. Box blackbox uniquement en mode 1 (aucun credential minté), ou adaptateur IdP externe (différé).");
    }

    // PROVISIONING DAEMON-INTERNE (mint ON ISSUE) — atteint UNIQUEMENT en mode engagement (garde ci-dessus) :
    // pour chaque grant déclaré par la box, on MATÉRIALISE le credential AVANT la transaction (hash_pw = pur,
    // hors verrou DB) :
    //   - scoped_cred -> COMPTE plume scopé (rôle par box : greybox=viewer, whitebox=admin+marqueur), nom
    //     réservé `eng-cred-*`, secret bearer aléatoire fort. Seul le HASH est stocké (jamais le secret) ; le
    //     secret est renvoyé UNE SEULE FOIS dans la réponse de création (l'admin le remet au testeur) — GET ne
    //     le ré-expose jamais (il n'est stocké nulle part en clair).
    //   - config_read (whitebox) -> capacité de LECTURE seule, engagement-scopée + expirante, enregistrée
    //     'issued' (ref = marqueur `cap:config_read`, aucun secret). Réalisée via le compte scopé (lecture
    //     redacted-secrets par l'authorizer SQLite + hard-expiry) ; un endpoint snapshot-config dédié est un
    //     follow-up documenté (pas d'accès permanent aux secrets prod).
    // La validité TEMPORELLE est appliquée à CHAQUE auth (engagement_cred_within_window), pas ici.
    let cred_role = engagement_cred_role_for_box(&box_kind);
    let entropy_err = || server_err("entropie noyau indisponible : credential NON minté (engagement NON créé)");
    // plan aligné sur les grants : (kind, ref, hash_du_secret) ; `minted` = payload rendu UNE fois.
    let mut grant_plan: Vec<(&'static str, String, Option<String>)> = Vec::new();
    let mut minted: Vec<Value> = Vec::new();
    for kind in grant_kinds {
        match *kind {
            "scoped_cred" => {
                let suffix = match engagement_rand_hex(12) { Some(s) => s, None => return entropy_err() };
                let username = format!("{ENG_CRED_PREFIX}{suffix}");
                let secret = match engagement_rand_hex(24) { Some(s) => s, None => return entropy_err() };
                let hash = match hash_pw(&secret) {
                    Some(h) => h,
                    None => return server_err("échec du hachage du secret : credential NON minté"),
                };
                minted.push(json!({ "kind": "scoped_cred", "username": username, "secret": secret, "role": cred_role, "expires": window_end }));
                grant_plan.push(("scoped_cred", username, Some(hash)));
            }
            "config_read" => {
                grant_plan.push(("config_read", "cap:config_read".to_string(), None));
                minted.push(json!({ "kind": "config_read", "capability": "config_read", "scope": "read-only, engagement-scoped, expiring", "expires": window_end }));
            }
            other => { grant_plan.push((other, String::new(), None)); }
        }
    }

    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute(
            "INSERT INTO engagement(id,name,box,scope,window_start,window_end,authorizer,reason,status,adapter,env_id,created,created_by) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'prod',?11,?12)",
            params![id, name, box_kind, scope_json, window_start, window_end, authorizer, reason, status, adapter, now_i, au.name],
        )?;
        for (kind, gref, hash_opt) in &grant_plan {
            // pending -> issued : le credential est physiquement MINTÉ (ref = handle de lookup non secret :
            // username pour scoped_cred, marqueur pour config_read). Jamais le secret.
            conn.execute(
                "INSERT INTO engagement_grant(engagement_id,kind,ref,idp_adapter,issued_ts,status) \
                 VALUES(?1,?2,?3,?4,?5,'issued')",
                params![id, *kind, gref.as_str(), idp_adapter, now_i],
            )?;
            // scoped_cred -> matérialise le COMPTE plume scopé (auth Basic/cookie ; hard-expiry appliqué à l'auth).
            if let Some(hash) = hash_opt {
                conn.execute(
                    "INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)",
                    params![gref.as_str(), hash.as_str(), cred_role],
                )?;
            }
        }
        audit_source_change(
            &conn, "plume-engagement", "config.engagement.create",
            &format!("engagement '{id}' ({name}, {box_kind}) créé par {} — scope={scope_json} fin={window_end} raison={reason}", au.name),
            4,
            &format!("ENGAGEMENT AUTORISÉ '{name}' ({box_kind}) OUVERT par {} : auto-ban SUSPENDU sur {} CIDR jusqu'à {window_end} (détection/alerte INCHANGÉES). Raison : {reason}", au.name, scope.len()),
            &json!({ "engagement_id": id, "box": box_kind, "scope": scope, "window_end": window_end, "status": status, "actor": au.name, "authorizer": authorizer, "reason": reason }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            let db_path = req_db_path(&st, &au);
            engagement_scope_refresh(&db_path, &conn); // effet immédiat sans attendre le tick 20 s
            // `credentials` = secret(s) minté(s) rendus UNE SEULE FOIS ici (jamais stockés en clair, jamais
            // ré-exposés par GET). Vide pour blackbox (aucun grant). L'admin les transmet au testeur hors-bande.
            Json(json!({ "id": id, "status": status, "window_start": window_start, "window_end": window_end, "capped": capped, "box": box_kind, "grants": grant_kinds, "credentials": minted })).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (engagement NON créé): {e}"))
        }
    }
}

/// POST /api/engagements/:id/end — clôture ANTICIPÉE (admin-only, audité, transactionnel). status='revoked' +
/// révoque tout grant ouvert + exemption levée (recompile l'index). Idempotent (no-op si déjà clos).
pub(crate) async fn engagement_end(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<String>) -> Response {
    if let Err(r) = require_admin(&au) { return r; }
    // Symétrique avec /active + engagement_create : hors mode engagement, endpoint mutant INERTE.
    if !engagement_enabled() {
        return err_json(StatusCode::CONFLICT, "mode engagement désactivé (PLUME_ENGAGEMENT_MODE=0)");
    }
    let now_i = now();
    crate::req_conn!(st, au, conn);
    let exists = conn.query_row("SELECT 1 FROM engagement WHERE id=?1 AND status IN ('active','scheduled')", params![id], |_| Ok(())).is_ok();
    if !exists {
        return not_found("engagement introuvable ou déjà clos");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("UPDATE engagement SET status='revoked', ended_ts=?2 WHERE id=?1 AND status IN ('active','scheduled')", params![id, now_i])?;
        revoke_engagement_creds(&conn, &id)?; // INVALIDE les comptes mintés (avant de révoquer les grants)
        conn.execute(
            "UPDATE engagement_grant SET status='revoked', revoked_ts=?2 WHERE engagement_id=?1 AND status IN ('issued','pending')",
            params![id, now_i],
        )?;
        audit_source_change(
            &conn, "plume-engagement", "config.engagement.end",
            &format!("engagement '{id}' clos manuellement par {}", au.name),
            3,
            &format!("engagement autorisé '{id}' CLOS par {} : exemption levée, grants révoqués (auto-ban rétabli)", au.name),
            &json!({ "engagement_id": id, "event": "end", "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            let db_path = req_db_path(&st, &au);
            engagement_scope_refresh(&db_path, &conn);
            Json(json!({ "id": id, "status": "revoked" })).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (engagement inchangé): {e}"))
        }
    }
}

// ---------- mode global + playbooks (SOAR-lite) ----------
pub(crate) async fn mode_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    with_write(&st, &au, |conn| {
    let m: String = conn.query_row("SELECT value FROM meta WHERE key='plume_mode'", [], |r| r.get(0)).unwrap_or_else(|_| "observe".into());
    Json(json!({ "mode": m }))
    })
}
pub(crate) async fn mode_set(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    // DURCISSEMENT : passer en mode `active` ARME l'exécution RÉELLE des playbooks (run_playbooks
    // insère approved/dry_run=0 -> le responder root exécute ban/kill/stop). RÉSERVÉ ADMIN. Le gate classe déjà
    // /api/mode POST en Admin ; ce re-check DOUBLE la garde (défense en profondeur).
    if let Err(r) = require_admin(&au) { return r; }
    let m = if b.get("mode").and_then(|v| v.as_str()) == Some("active") { "active" } else { "observe" };
    crate::req_conn!(st, au, conn);
    // BONUS : bascule de mode AUDITÉE fail-closed (ledger + event plume-config SOC-visible,
    // sev=3 car `active` ARME l'exécution réelle des réponses). Avant : ledger_append best-effort (avalait
    // l'erreur, aucun event SOC). Fail-closed : si l'audit échoue -> ROLLBACK (le mode N'est PAS changé sans trace).
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("INSERT INTO meta(key,value) VALUES('plume_mode',?1) ON CONFLICT(key) DO UPDATE SET value=?1", params![m])?;
        audit_config_change(
            &conn,
            "config.mode",
            &format!("mode passé à '{m}' par {}", au.name),
            3,
            &format!("mode de réponse '{m}' {} par {}", if m == "active" { "ARMÉ (exécution réelle)" } else { "remis en observation" }, au.name),
            &json!({ "mode": m, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "mode": m })).into_response() }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (mode inchangé): {e}"))
        }
    }
}

//! Mode Engagement autorisé (v75) — pentest natif, INERTE quand off : engagement compilé
//! `ActiveEngagement`/`ENGAGEMENT_SCOPE`, matcher/refresh de scope, cycle de vie des credentials,
//! validation `validate_engagement_scope`/`reseaux_se_recouvrent`, expiration/activation
//! (`expire`/`activate_due_engagements_conn`), les handlers engagement et `mode_get`/`mode_set`.
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;
use crate::handlers::transaction_validee::{ouvrir_la_transaction_du_geste, valider_la_transaction};

// =====================================================================================
// MODE ENGAGEMENT AUTORISÉ (v75) — pentest natif black/grey/whitebox, SANS reconfigurer le SOC, SANS angle
// mort, auto-expirant, audité. INVARIANT SACRÉ (STRUCTUREL) : enforcement ≠ détection. La détection
// (run_due_rules -> alert) et le blocage (run_playbooks -> ban) sont DEUX moteurs indépendants ; la couverture
// lit la table `alert`. Un engagement suppresse UNIQUEMENT l'auto-BAN des IP scopées (Arm A : action_valid) ;
// collecte/règles/alertes/couverture restent 100 % ON. Le placeholder d'affichage `__ENGAGEMENT_EXCL__` n'est
// JAMAIS substitué dans `rule_sql` (garantie v55 pour __OPERATOR_EXCL__ : rien n'est retiré du chemin détection).
// INERTE quand `PLUME_ENGAGEMENT_MODE` absent/0 : index scope VIDE -> tag/guard/endpoint no-op -> byte-identique.
// =====================================================================================

/// Engagement ACTIF compilé (cache lecture-chaude). `matchers` = RÉSEAUX `(base, bits)` issus de
/// `parse_protected_item` — MÊME analyseur que la denylist never-ban, et plus `parse_excl_item`, qui
/// est l'analyseur du RENDU D'AFFICHAGE (`P4.7-i` : `172.16.0.0/12` y devient le préfixe textuel
/// `"172."`, soit tout 172/8). `scope` = CIDRs bruts (endpoint pull).
#[derive(Clone)]
pub(crate) struct ActiveEngagement {
    pub(crate) engagement_id: String,
    pub(crate) scope: Vec<String>,
    pub(crate) matchers: Vec<(std::net::IpAddr, u32)>,
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
    // `P4.7-g` — APPARTENANCE AU RÉSEAU, jamais préfixe de chaîne : une cible de pentest AUTORISÉE
    // écrite en forme mappée (`::ffff:198.51.100.9`) retrouve son exemption, et la garde qui interdit
    // d'exempter loopback/opérateur cesse de manquer un recouvrement RÉEL écrit sous une autre notation.
    // Une chaîne inanalysable n'est pas une adresse, donc n'appartient à aucun scope -> None (le
    // refus de FORME est prononcé en amont par `cible_de_ban_acceptee`, pas ici).
    let val = match ssrf_norm_ip(ip) { Some(v) => v, None => return None };
    let n = now();
    for e in list {
        if e.window_end <= n { continue; } // fenêtre dure écoulée -> plus d'exemption (self-expiry chaud)
        if e.matchers.iter().any(|(net, bits)| ip_in_cidr(val, *net, *bits)) {
            return Some(e.engagement_id.clone());
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

/// MÉMO PROCESSUS DES REFUS DE SCOPE DÉJÀ ANNONCÉS — `load_active_engagements` tourne au tick 20 s,
/// et un refus répété toutes les 20 secondes serait du bruit non purgeable, pas un signal. On annonce
/// donc UNE fois par processus et par refus distinct. Un redémarrage ré-annonce, ce qui est voulu :
/// l'exploitant doit relire ce qui ne protège plus après chaque mise à jour. Borné (le mémo est vidé
/// et l'événement dit, plutôt que de croître sans fin ou de devenir SILENCIEUX).
static REFUS_DE_SCOPE_ANNONCES: std::sync::OnceLock<parking_lot::RwLock<std::collections::HashSet<String>>> = std::sync::OnceLock::new();
const REFUS_DE_SCOPE_MEMO_CAP: usize = 1024;
fn annoncer_refus_de_scope_une_fois(conn: &Connection, detail: &str) {
    let memo = REFUS_DE_SCOPE_ANNONCES.get_or_init(|| parking_lot::RwLock::new(std::collections::HashSet::new()));
    {
        let lu = memo.read();
        if lu.contains(detail) { return; }
    }
    let mut ecr = memo.write();
    if !ecr.insert(detail.to_string()) { return; }
    if ecr.len() > REFUS_DE_SCOPE_MEMO_CAP {
        ecr.clear();
        ledger_append(conn, "engagement.scope.refus", "mémo des refus de scope PLEIN — vidé ; les refus déjà annoncés le seront à nouveau");
    }
    drop(ecr);
    ledger_append(conn, "engagement.scope.refus", detail);
}

/// Charge les engagements ACTIFS non expirés d'une base -> liste compilée (matchers CIDR). Scope JSON invalide /
/// sans matcher -> ligne ignorée (jamais un scope vide qui matcherait tout).
///
/// REPRISE 2026-08-29 — UN ITEM REFUSÉ EST NOMMÉ ICI AUSSI, PAS SEULEMENT DANS LA DENYLIST. Le lot
/// écrit que retirer une protection écrite exige un accusé bruyant, l'appliquait à la denylist
/// never-ban (registre + journal d'amorçage) et le JETAIT ici : `filter_map(|c| …ok())` écartait en
/// SILENCE toute ligne de scope que le nouvel analyseur refuse. Or `parse_protected_item` refuse ce
/// que `parse_excl_item` acceptait (joker hors frontière, masque sous plancher, nom d'hôte, base
/// inanalysable) : un engagement encore `active` en base, validé par une version ANTÉRIEURE de
/// `validate_engagement_scope`, perdait cette ligne — et s'il perdait TOUTES ses lignes il
/// disparaissait entièrement du cache chaud alors que sa fenêtre courait. `ip_in_active_engagement`
/// rendait alors false, `action_valid_ctx` cessait de suspendre l'auto-ban, et plume bannissait une
/// cible de pentest AUTORISÉE en pleine fenêtre, sans une ligne de journal. Les deux cas sont
/// désormais dits, et le second — l'engagement qui SORT du cache — est dit à part.
///
/// `P10.7-f` (rang 2) — ET LA LECTURE ELLE-MÊME REND UN `Result`. Le paragraphe ci-dessus décrit ce qui
/// arrive quand un engagement SORT du cache : l'auto-ban cesse d'être suspendu et plume bannit une cible de
/// pentest autorisée. Ce lot ferme la DERNIÈRE porte par laquelle il en sortait sans un mot : la table
/// illisible (`Err(_) => return out`, un cache VIDE servi comme « aucun engagement n'est actif ») et la
/// ligne illisible (`rows.flatten()`, un engagement retiré du cache pendant que sa fenêtre court). Le
/// `Result` force `engagement_scope_refresh` à choisir, et il choisit de GARDER ce qu'il avait.
pub(crate) fn load_active_engagements(conn: &Connection, now_i: i64) -> rusqlite::Result<Vec<ActiveEngagement>> {
    let mut out = Vec::new();
    let lignes: Vec<(String, String, i64, String, String)> = conn
        .prepare("SELECT id, scope, window_end, box, adapter FROM engagement WHERE status='active' AND window_end > ?1")
        .and_then(|mut stmt| {
            stmt.query_map(params![now_i], |r| Ok((
                r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?,
            )))?
            .collect::<rusqlite::Result<Vec<_>>>()
        })?;
    {
        for (id, scope_json, wend, boxk, adapter) in lignes {
            let scope: Vec<String> = serde_json::from_str(&scope_json).unwrap_or_default();
            // `P4.7-i` — MÊME analyseur que la denylist never-ban : un item que le produit ne sait pas
            // honorer est ÉCARTÉ (l'engagement perd cette ligne de scope), jamais accepté DÉFORMÉ —
            // et le refus est ANNONCÉ (une fois par processus), jamais avalé.
            let mut matchers: Vec<(std::net::IpAddr, u32)> = Vec::new();
            for c in &scope {
                match parse_protected_item(c) {
                    Some(Ok(m)) => matchers.push(m),
                    Some(Err(raison)) => annoncer_refus_de_scope_une_fois(conn, &format!(
                        "engagement {id} : ligne de scope « {c} » REFUSÉE — {raison} (cette ligne N'EXEMPTE PLUS RIEN ; l'auto-ban peut viser une cible autorisée)"
                    )),
                    None => {}
                }
            }
            if matchers.is_empty() {
                // L'engagement reste `active` EN BASE et sa fenêtre court, mais il sort du cache
                // chaud : plus AUCUNE de ses IP n'est exemptée. C'est le cas le plus coûteux, il est
                // dit à part.
                annoncer_refus_de_scope_une_fois(conn, &format!(
                    "engagement {id} : AUCUNE ligne de scope exploitable ({} écrite(s)) — l'engagement reste ACTIF en base mais N'EXEMPTE PLUS AUCUNE adresse", scope.len()
                ));
                continue;
            }
            out.push(ActiveEngagement { engagement_id: id, scope, matchers, window_end: wend, box_kind: boxk, adapter });
        }
    }
    Ok(out)
}

/// Recompile l'index scope de CE db_path (appelé au tick 20 s + à la création/clôture pour effet immédiat).
/// Off -> purge l'entrée (l'index reste VIDE -> ingest byte-identique).
///
/// `P10.7-f` (rang 2) — UNE LECTURE RATÉE GARDE LA VALEUR PRÉCÉDENTE ET LA COMPTE ; ELLE NE VIDE PAS LE
/// CACHE. C'est le seul site de ce rang où « ne rien faire » n'est PAS le geste neutre, et il faut le dire :
/// ce cache est une EXEMPTION, donc une défense volontairement baissée. Le vider n'est pas « perdre une
/// information », c'est ARMER l'auto-ban contre une cible de pentest autorisée, en pleine fenêtre, sans
/// qu'aucun corps ne soit servi à personne. Garder la valeur précédente est borné dans le temps par une
/// propriété STRUCTURELLE et non par la cadence de ce rafraîchissement : `engagement_scope_match` revérifie
/// `window_end <= now()` sur le CHEMIN CHAUD (self-expiry, cf. son commentaire), donc une entrée conservée
/// cesse d'exempter à la seconde où sa fenêtre s'achève, même si plus aucun rafraîchissement ne réussit.
/// La conservation ne peut donc pas prolonger une exemption au-delà de ce que l'exploitant a écrit.
/// Le tour est compté (`compter_un_tick_aveugle("engagement_scope_refresh", ..)`), qui journalise la cause.
pub(crate) fn engagement_scope_refresh(db_path: &str, conn: &Connection) {
    if !engagement_enabled() {
        let mut m = engagement_scope_map().write();
        m.remove(db_path);
        return;
    }
    let list = match load_active_engagements(conn, now()) {
        Ok(l) => l,
        Err(e) => {
            crate::metrics::compter_un_tick_aveugle("engagement_scope_refresh", &e.to_string());
            return; // l'entrée précédente reste EN PLACE — bornée par le self-expiry du chemin chaud.
        }
    };
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
///
/// `P7.19-i` — LA FENÊTRE EST CELLE DE LA SEULE LIAISON ADMISSIBLE, ET LE MULTIPLE EST UN REFUS.
///
/// LE DÉFAUT. Cette porte lisait `… WHERE g.ref = ?1 AND … status = 'issued' LIMIT 1`, SANS ORDRE.
/// Deux grants `issued` sur la même `ref` — l'un vers un engagement OUVERT, l'autre vers un
/// engagement CLOS — auraient donné une fenêtre TIRÉE AU SORT : un `LIMIT 1` sans ordre est
/// fail-OPEN une fois sur deux là où toute la fonction est écrite pour être fail-closed. C'est la
/// seule des trois lectures de `P7.19-i` dont l'arbitraire décide d'une AUTHENTIFICATION.
///
/// CE QUI EST RETENU MAINTENANT : la fenêtre du grant `scoped_cred` `issued` de cette `ref` À
/// CONDITION QU'IL SOIT SEUL (`HAVING COUNT(*) = 1`, test POSITIF : l'unicité doit être CONSTATÉE).
/// Multiple -> ZÉRO ligne -> `unwrap_or(false)` -> la porte REFUSE. L'énoncé rend au plus une ligne
/// par construction : ni `LIMIT`, ni `ORDER BY`, donc plus d'ordre à choisir.
///
/// CE REFUS N'ENFERME PERSONNE. Une `ref` de `scoped_cred` est `eng-cred-<12 octets CSPRNG>` (96
/// bits) et `user.name` est UNIQUE, donc deux liaisons `issued` sur la même `ref` ne sont pas un
/// état légitime que le produit sait produire : c'est une base trafiquée ou corrompue. Refuser y est
/// la bonne réponse — et c'est exactement le cas que l'ancienne lecture traitait au hasard.
pub(crate) fn engagement_cred_within_window(conn: &Connection, username: &str, now_i: i64) -> bool {
    conn.query_row(
        "SELECT e.window_start, e.window_end FROM engagement_grant g \
           JOIN engagement e ON e.id = g.engagement_id \
          WHERE g.ref = ?1 AND g.kind = 'scoped_cred' AND g.status = 'issued' \
          GROUP BY g.ref HAVING COUNT(*) = 1",
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

/// `P4.7-i` — DEUX RÉSEAUX SE RECOUVRENT si l'un CONTIENT l'autre, dans un sens OU dans l'autre.
/// C'était `a.starts_with(b) || b.starts_with(a)` sur des PRÉFIXES TEXTUELS, hérités de l'analyseur
/// d'affichage : la garde qui interdit d'exempter loopback / une IP opérateur ratait donc un
/// recouvrement RÉEL écrit sous une autre notation (`::ffff:127.0.0.1/128` ne commence pas par
/// « 127. »), et en inventait un qui n'existe pas (`::1a00:0/112` « commence » par « ::1 »).
/// `validate_engagement_scope` avait DÉJÀ corrigé cette figure CHEZ ELLE — « le plancher est validé
/// sur la FAMILLE RÉELLEMENT PARSÉE (IpAddr) et non sur un test de chaîne `.contains(':')` » — sans
/// la corriger chez son fournisseur de matchers.
/// Familles différentes -> aucun recouvrement (`ip_in_cidr` rend `false`), là où le texte comparait
/// `8*` contre `8.8.8.8` ET `8000::1`.
pub(crate) fn reseaux_se_recouvrent(a: (std::net::IpAddr, u32), b: (std::net::IpAddr, u32)) -> bool {
    ip_in_cidr(a.0, b.0, b.1) || ip_in_cidr(b.0, a.0, a.1)
}
/// VALIDATION scope : REFUSE (1) route par défaut / joker (0.0.0.0/0, ::/0, *) ; (2) masque plancher (IPv4 /8,
/// IPv6 /16 : au-dessous = trop large) ; (3) chevauchement avec loopback/link-local OU une IP protégée
/// opérateur/passerelle -> jamais de blanket-exempt d'une IP qu'un ban ne doit jamais rater (self-DoS /
/// neutralisation). NB : RFC1918 (10/192.168/172.16) est ADMIS (pentest interne grey/whitebox légitime).
pub(crate) fn validate_engagement_scope(scope: &[String], protected: &[(std::net::IpAddr, u32)]) -> Result<(), String> {
    if scope.is_empty() {
        return Err("au moins un CIDR requis".into());
    }
    // Les plages qu'AUCUNE exemption ne doit recouvrir, écrites en RÉSEAUX (elles l'étaient en
    // préfixes de chaîne : « 127. », « 169.254. », « ::1 », « fe80: »).
    const NEVER: &[(&str, u32)] = &[("127.0.0.0", 8), ("169.254.0.0", 16), ("::1", 128), ("fe80::", 10)];
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
        let sres = match parse_protected_item(c) {
            Some(Ok(m)) => m,
            Some(Err(raison)) => return Err(format!("CIDR invalide : '{c}' ({raison})")),
            None => return Err(format!("CIDR invalide : '{c}'")),
        };
        for (nip, nbits) in NEVER {
            let net = (nip.parse::<std::net::IpAddr>().expect("réseau NEVER littéral"), *nbits);
            if reseaux_se_recouvrent(sres, net) {
                return Err(format!("'{c}' chevauche loopback/link-local ({nip}/{nbits}) — exemption refusée"));
            }
        }
        for pnet in protected {
            if reseaux_se_recouvrent(sres, *pnet) {
                let (base, dernier) = etendue_du_reseau(pnet.0, pnet.1);
                return Err(format!("'{c}' chevauche une IP protégée opérateur/passerelle ({}/{} = {base}..{dernier}) — exemption refusée", pnet.0, pnet.1));
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
    let due: Vec<(String, String)> = match conn
        .prepare("SELECT id, COALESCE(name,'') FROM engagement WHERE status='active' AND window_end < ?1 ORDER BY window_end LIMIT 50")
        .and_then(|mut s| s.query_map(params![now_i], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>())
    {
        Ok(v) => v,
        // `P10.7-f` (lot 106) — lue EN BLOC : une ligne en erreur ne raccourcit plus la liste en silence.
        Err(e) => { crate::metrics::compter_un_tick_aveugle("engagement_expire_active", &e.to_string()); return 0; }
    };
    let mut n = 0usize;
    for (id, name) in &due {
        if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE") {
            dire_un_geste_du_cycle_non_pris("expiration", id, "BEGIN refusé", &e);
            continue;
        }
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
        clore_un_geste_du_cycle(conn, outcome, "expiration", id, &mut n);
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
    let to_activate: Vec<(String, String)> = match conn
        .prepare("SELECT id, COALESCE(name,'') FROM engagement WHERE status='scheduled' AND window_start <= ?1 AND window_end > ?1 ORDER BY window_start LIMIT 50")
        .and_then(|mut s| s.query_map(params![now_i], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>())
    {
        Ok(v) => v,
        // `P10.7-f` (lot 106) — lue EN BLOC ; refusée, ce balayage ne fait rien ce tour-ci et le dit.
        Err(e) => { crate::metrics::compter_un_tick_aveugle("engagement_activate", &e.to_string()); Vec::new() }
    };
    let mut activated = 0usize;
    for (id, name) in &to_activate {
        if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE") {
            dire_un_geste_du_cycle_non_pris("activation", id, "BEGIN refusé", &e);
            continue;
        }
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
        clore_un_geste_du_cycle(conn, outcome, "activation", id, &mut activated);
    }
    // (2) scheduled -> expired : fenêtre écoulée SANS activation (mêmes effets que l'expiry d'un actif).
    let stale: Vec<(String, String)> = match conn
        .prepare("SELECT id, COALESCE(name,'') FROM engagement WHERE status='scheduled' AND window_end < ?1 ORDER BY window_end LIMIT 50")
        .and_then(|mut s| s.query_map(params![now_i], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>())
    {
        Ok(v) => v,
        Err(e) => { crate::metrics::compter_un_tick_aveugle("engagement_expire_scheduled", &e.to_string()); Vec::new() }
    };
    let mut expired = 0usize;
    for (id, name) in &stale {
        if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE") {
            dire_un_geste_du_cycle_non_pris("expiration sans activation", id, "BEGIN refusé", &e);
            continue;
        }
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
        clore_un_geste_du_cycle(conn, outcome, "expiration sans activation", id, &mut expired);
    }
    (activated, expired)
}

// `P10.25-e` — UN GESTE DU CYCLE DE VIE QUE LA BASE N'A PAS PRIS N'EST NI COMPTÉ, NI LAISSÉ OUVERT, NI TU.
//
// LE DÉFAUT, MESURÉ LE 2026-09-24 SUR LA FORME D'AVANT (`COMMIT` refusé par un autorisateur SQLite, deux engagements
// échus par balayage) : le balayage d'expiration rendait 1 — un engagement compté expiré, qui ne l'était pas au
// redémarrage — et la transaction restait OUVERTE sur l'écrivain partagé ; le second engagement échu n'était même pas
// tenté (`BEGIN` refusé, `continue` muet), ni aucun geste d'écriture de la console jusqu'au redémarrage (500 « verrou
// base indisponible »). L'activation, de même : 1 compté, le second sauté, et le rafraîchissement de l'index de scope
// qui suit le balayage lisait la transaction pendante — l'exemption d'auto-ban d'un engagement resté `scheduled` en
// base était posée en mémoire. L'énoncé (« une révocation annoncée faite et non faite ») est IMPRÉCIS pour
// l'expiration : l'exemption et les crédences d'un engagement échu cessent de servir à `window_end` même quand le
// balayage échoue, parce que `engagement_scope_match` et `engagement_cred_within_window` revérifient la fenêtre à
// chaque usage ; ce qui manquait, c'est la révocation écrite (grants, comptes `eng-cred-*`) et sa trace.
//
// LA FORME : chaque engagement a SA transaction, jugée ; un refus la ferme (`valider_la_transaction`), n'est pas
// compté, et le journal le dit par engagement — la ligne reste due, le balayage suivant (20 s) la reprend, et
// l'index de scope, rafraîchi APRÈS le balayage, ne lit que ce que la base a validé.

/// `P10.25-e` — le journal d'un geste du cycle de vie non pris : quel geste, quel engagement, à quelle étape, pourquoi.
fn dire_un_geste_du_cycle_non_pris(geste: &str, id: &str, etape: &str, cause: &rusqlite::Error) {
    eprintln!(
        "[engagement] WARN {geste} de l'engagement '{id}' NON prise ({etape} : {cause}) — rien n'est écrit ni compté, \
         l'engagement reste dû et le balayage suivant le reprend"
    );
}

/// `P10.25-e` — solde la transaction d'un geste du cycle de vie : validée, elle est comptée ; refusée (écriture ou
/// `COMMIT`), elle est fermée et dite, jamais comptée.
fn clore_un_geste_du_cycle(conn: &Connection, outcome: rusqlite::Result<()>, geste: &str, id: &str, compte: &mut usize) {
    match outcome {
        Ok(()) => match valider_la_transaction(conn) {
            Ok(()) => *compte += 1,
            Err(e) => dire_un_geste_du_cycle_non_pris(geste, id, "COMMIT refusé", &e),
        },
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            dire_un_geste_du_cycle_non_pris(geste, id, "écriture refusée", &e);
        }
    }
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
    // `P10.7-f` (rang 2) — LA DÉCLARATION EST ENTIÈRE, OU C'EST UN REFUS NOMMÉ. Le corps nominal est un
    // TABLEAU NU : il n'a aucune clé où poser un aveu (même contrainte que `idp_providers_list` au rang un),
    // donc le refus prend le statut. MESURÉ SUR LE CONSOMMATEUR, qui est le seul : `collectors/engagement-
    // adapter.sh:471-472` n'accepte que `http == 200` ET un corps de type `array`, et son `else` est un
    // fail-closed GRADUÉ, déjà écrit, déjà gardé — HOLD (exemptions conservées, expiry seul appliqué) sous
    // le seuil d'échecs, REVERT-ALL au-delà, chaque branche journalisée. Un 200 portant un tableau AMPUTÉ,
    // lui, n'emprunte aucune de ces branches : l'adaptateur le prend pour la vérité et RÉVOQUE sur l'hôte
    // les exemptions des engagements manquants — la défense se rearme contre une cible autorisée, en
    // silence, et l'enforcer croit avoir réconcilié. Le refus explicite est donc ce que ce consommateur-là
    // sait traiter, et la seule forme qui ne fabrique pas un ordre de révocation.
    let list = match load_active_engagements(&conn, now()) {
        Ok(l) => l,
        Err(_) => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "engagements actifs NON LUS : la lecture du registre des engagements a échoué. \
                                   AUCUNE déclaration de portée n'est servie ce tour-ci — ce n'est pas « aucun engagement actif » ; réessayer." })),
        ).into_response(),
    };
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

/// LE COMPTAGE DU REGISTRE — l'énoncé n'est plus écrit ici : il est RENDU par le fabricant partagé
/// (`handlers::liste_bornee`), seul détenteur de la forme `LIMIT plafond + 1`.
pub(crate) fn engagements_total_sql() -> String {
    crate::handlers::liste_bornee::sql_du_comptage_borne("engagement")
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
/// Rend `{engagements, served, window, total, total_capped}` — forme RENDUE par le fabricant partagé
/// `handlers::liste_bornee` (`P11.22-f`) au lieu d'être recopiée ici. `served` est le nombre de lignes
/// RENDUES et `window` la borne de la route : leur égalité est ce qui dit au lecteur que la borne MORD.
/// `total`/`total_capped` valent `null` — jamais `0` — quand le comptage n'a pas pu être lu : « non
/// compté » et « aucun engagement » sont deux faits différents. Et une lecture de lignes qui ÉCHOUE
/// n'entre plus sous la forme d'un registre VIDE.
pub(crate) fn engagements_page(conn: &Connection) -> Value {
    use crate::handlers::liste_bornee as aveu;
    let lignes = aveu::lire(conn, &engagements_window_sql(), engagement_row_json);
    let total = aveu::TotalBorne::depuis_un_comptage_borne(
        conn.query_row(&engagements_total_sql(), [], |r| r.get::<_, i64>(0)),
        PAGINATION_COUNT_CAP,
    );
    aveu::corps("engagements", lignes, ENGAGEMENTS_WINDOW, total)
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

/// GET /api/engagements/{id} — engagement + ses grants (admin). Les grants exposent l'INTENT de provisioning :
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
    // `P10.7-f` (rang 4, vague b) — LA FICHE PORTE TOUS SES PERMIS, OU ELLE DIT QU'ELLE NE LES A PAS LUS.
    // Avant : `.map(|m| m.flatten().collect()).unwrap_or_default()` et `Err(_) => Vec::new()` — un permis
    // dont la ligne ne se décode pas (`ref` corrompu, colonne de migration que la connexion qui sert ne
    // voit pas encore) disparaissait de `grants`, et la fiche restait d'aspect complet. C'est la seule vue
    // où l'on relit CE QUI A ÉTÉ OCTROYÉ pour un pentest autorisé : un permis absent se lit « il n'a jamais
    // été émis », donc on n'a rien à révoquer à la clôture — un accès minté par le provisioning survit
    // alors à l'engagement, sans que personne ne le sache. L'aveu est celui du dépôt
    // (`liste_bornee::corps_de_liste_illisible` : `grants` présente et VIDE, `error` nomme la cause) ; les
    // champs de l'engagement viennent d'une AUTRE lecture, déjà faite, et restent servis — c'est
    // exactement la règle de `views_list` (`me`/`role`) et de `dash_get` (métadonnées) au rang précédent.
    let grants: rusqlite::Result<Vec<Value>> = conn
        .prepare(
            "SELECT id,kind,ref,idp_adapter,issued_ts,revoked_ts,status FROM engagement_grant WHERE engagement_id=?1 ORDER BY id",
        )
        .and_then(|mut s| {
            s.query_map(params![id], |r| Ok(json!({
                "id": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?, "ref": r.get::<_, String>(2)?,
                "idp_adapter": r.get::<_, String>(3)?, "issued_ts": r.get::<_, Option<i64>>(4)?,
                "revoked_ts": r.get::<_, Option<i64>>(5)?, "status": r.get::<_, String>(6)?,
            })))?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    match grants {
        Ok(g) => {
            eng["grants"] = json!(g);
            Json(eng).into_response()
        }
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(eng, "grants")).into_response(),
    }
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
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "engagement", "création d'un engagement", CAUSE_ENGAGEMENT_NON_CREE_TRANSACTION_NON_OUVERTE) {
        return refus;
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
            // `P10.25-e` — ni crédence montrée, ni exemption posée en mémoire avant la transaction VALIDÉE : avant, un
            // `COMMIT` refusé rendait 200 et le secret d'un compte `eng-cred-*` qui authentifiait tant que la transaction
            // restait pendante, et l'index de scope, rechargé DANS cette transaction, suspendait l'auto-ban sur le
            // scope d'un engagement qui n'existait plus au redémarrage — sans aucune trace validée.
            if let Err(e) = valider_la_transaction(&conn) {
                eprintln!("[engagement] WARN création de l'engagement '{id}' NON validée : {e}");
                return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_ENGAGEMENT_NON_CREE_COMMIT_REFUSE);
            }
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

/// POST /api/engagements/{id}/end — clôture ANTICIPÉE (admin-only, audité, transactionnel). status='revoked' +
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
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "engagement", &format!("clôture de l'engagement '{id}'"), CAUSE_ENGAGEMENT_NON_CLOS_TRANSACTION_NON_OUVERTE) {
        return refus;
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
            // `P10.25-e` — la clôture n'est annoncée, et l'index de scope rechargé, qu'une fois la transaction VALIDÉE :
            // avant, un `COMMIT` refusé rendait 200 `revoked`, la crédence refusée tant que la transaction restait
            // pendante AUTHENTIFIAIT de nouveau dès qu'elle était annulée, et l'engagement était toujours `active` en base.
            if let Err(e) = valider_la_transaction(&conn) {
                eprintln!("[engagement] WARN clôture de l'engagement '{id}' NON validée : {e}");
                return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_ENGAGEMENT_NON_CLOS_COMMIT_REFUSE);
            }
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
        // `P10.7-g` (lot 94) — un mode NON LU n'est pas « observe » : le repli reste (c'est le mode le plus sûr, il
        // n'arme rien), mais le corps dit que c'est un repli. Aucune ligne = mode jamais posé = « observe » établi.
        match conn.query_row::<String, _, _>("SELECT value FROM meta WHERE key='plume_mode'", [], |r| r.get(0)) {
            Ok(m) => Json(json!({ "mode": m })),
            Err(rusqlite::Error::QueryReturnedNoRows) => Json(json!({ "mode": "observe" })),
            Err(e) => Json(json!({ "mode": "observe", "error": format!("mode NON LU : la lecture de plume_mode a échoué ({e}) — « observe » est un repli, pas la valeur enregistrée") })),
        }
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
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "engagement", &format!("bascule du mode vers '{m}'"), CAUSE_MODE_INCHANGE_TRANSACTION_NON_OUVERTE) {
        return refus;
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
        // `P10.25-e` — la bascule n'est annoncée qu'une fois VALIDÉE : avant, un `COMMIT` refusé rendait 200 `observe`,
        // les playbooks lisaient `observe` dans la transaction pendante, et la base disait `active` au redémarrage.
        Ok(()) => match valider_la_transaction(&conn) {
            Ok(()) => Json(json!({ "mode": m })).into_response(),
            Err(e) => {
                eprintln!("[engagement] WARN bascule du mode vers '{m}' NON validée : {e}");
                err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_MODE_INCHANGE_COMMIT_REFUSE)
            }
        },
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (mode inchangé): {e}"))
        }
    }
}

/// `P10.25-e` — le `COMMIT` de la création d'un engagement refusé.
pub(crate) const CAUSE_ENGAGEMENT_NON_CREE_COMMIT_REFUSE: &str = "ENGAGEMENT NON CRÉÉ : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — aucune crédence n'est frappée ni montrée, aucune exemption d'auto-ban \
     n'est posée, et rien n'est attesté. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou \
     verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_ENGAGEMENT_NON_CREE_TRANSACTION_NON_OUVERTE: &str = "ENGAGEMENT NON CRÉÉ : la base n'a pas \
     pris la transaction de la création (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur \
     l'écrivain) — RIEN n'est écrit : aucune crédence n'est frappée ni montrée, aucune exemption d'auto-ban n'est \
     posée, et rien n'est attesté. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";

/// `P10.25-e` — le `COMMIT` de la clôture anticipée d'un engagement refusé.
pub(crate) const CAUSE_ENGAGEMENT_NON_CLOS_COMMIT_REFUSE: &str = "ENGAGEMENT NON CLOS : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — l'engagement court toujours : son exemption d'auto-ban reste posée et \
     ses crédences authentifient jusqu'à la fin de sa fenêtre. Réessayez ; si le refus persiste, la base est en lecture \
     seule, pleine ou verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_ENGAGEMENT_NON_CLOS_TRANSACTION_NON_OUVERTE: &str = "ENGAGEMENT NON CLOS : la base n'a pas \
     pris la transaction de la clôture (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur \
     l'écrivain) — RIEN n'est écrit : l'engagement court toujours : son exemption d'auto-ban reste posée et ses \
     crédences authentifient jusqu'à la fin de sa fenêtre. Réessayez ; s'il est refusé encore, l'écrivain est occupé \
     ou bloqué.";

/// `P10.25-e` — le `COMMIT` d'une bascule du mode de réponse refusé.
pub(crate) const CAUSE_MODE_INCHANGE_COMMIT_REFUSE: &str = "MODE INCHANGÉ : la base n'a pas validé la transaction \
     (COMMIT refusé) et l'a annulée — le mode de réponse reste celui d'avant, et la bascule n'est pas attestée. \
     Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_MODE_INCHANGE_TRANSACTION_NON_OUVERTE: &str = "MODE INCHANGÉ : la base n'a pas pris la \
     transaction de la bascule (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur l'écrivain) \
     — RIEN n'est écrit : le mode de réponse reste celui d'avant, et la bascule n'est pas attestée. Réessayez ; s'il \
     est refusé encore, l'écrivain est occupé ou bloqué.";

//! Autorisation (default-deny) & gouvernance multi-tenant : ordre des rôles (`role_rank`/`role_satisfies`/
//! `MinRole`/`route_min_role`/`rbac_gate`), grants SSO/per-tenant (`sso_grants`/`grant_role_for`/
//! `default_grant`/`platform_user_is_superadmin`), résolution d'accès (`TenantAccess`/`resolve_tenant_access`),
//! marqueur opérateur cross-tenant (`OPERATOR_ACCESS_*`/`operator_access_should_emit`/`emit_operator_access`/
//! `control_ledger_append`), garde de gestion tenant (`mgmt_*`/`tenant_mgmt_gate`/`can_manage_grants`/
//! `valid_grant_role`/`platform_user_name_ok`/`gen_control_id`/`ensure_platform_user`/`tenant_admin_grant_count`)
//! et l'audit (`audit_tenant_event`/`tenant_db_path`). Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

/// #2b — ordre des rôles pour MAX(grants) : admin(3) > editor(2) > viewer(1) > inconnu(0).
pub(crate) fn role_rank(role: &str) -> u8 {
    match role {
        "admin" => 3,
        "editor" => 2,
        "viewer" => 1,
        // #59 : un rôle COMPOSABLE défini rank comme sa BASE (jamais au-dessus) ; un nom inconnu -> 0
        // (DEFAULT-DENY). Les rôles de base ci-dessus court-circuitent -> mode 0 byte-identique.
        _ => match effective_base_role(role).as_str() {
            "admin" => 3,
            "editor" => 2,
            "viewer" => 1,
            _ => 0,
        },
    }
}

/// #2b (spec B.3) — parse les groupes Authentik -> (map tenant->rôle EFFECTIF, is_superadmin). Convention :
///  - `plume-superadmin` OU le groupe configuré `sso_group_superadmin` -> is_superadmin=true (anti-lockout,
///    cohérent avec sso_role du mode 0) ;
///  - `plume-<tenant>-<role>` (role ∈ admin|editor|viewer, enum FERMÉ ; slug via rsplit -> le dernier
///    segment est le rôle, le slug peut contenir des '-') -> grant (tenant, role) ;
///  - legacy mono-tenant `plume-admin|editor|viewer` (= sso_group_admin/editor, ou noms canoniques) ->
///    grant ("default", role) [rétro-compat] ;
///  - rôle EFFECTIF par tenant = MAX (un user dans plume-acme-viewer ET plume-acme-admin est admin sur acme).
/// N'est appelée QU'EN MODE 1 (auth_guard mode 0 reste sur sso_role -> INVARIANT strict).
pub(crate) fn sso_grants(st: &AppState, groups: &str) -> (HashMap<String, String>, bool) {
    let mut map: HashMap<String, String> = HashMap::new();
    let mut superadmin = false;
    let mut grant = |t: &str, role: &str| {
        let e = map.entry(t.to_string()).or_insert_with(|| "viewer".to_string());
        if role_rank(role) > role_rank(e) {
            *e = role.to_string();
        }
    };
    for g in groups.split(|c| c == '|' || c == ',') {
        let g = g.trim();
        if g.is_empty() {
            continue;
        }
        if g == "plume-superadmin" || g == st.sso_group_superadmin.as_str() {
            superadmin = true;
            continue;
        }
        // legacy mono-tenant -> tenant `default` (rétro-compat ; noms configurés admin/editor inclus).
        if g == st.sso_group_admin.as_str() || g == "plume-admin" {
            grant("default", "admin");
            continue;
        }
        if g == st.sso_group_editor.as_str() || g == "plume-editor" {
            grant("default", "editor");
            continue;
        }
        if g == "plume-viewer" {
            grant("default", "viewer");
            continue;
        }
        // convention multi-tenant : plume-<tenant>-<role>.
        if let Some(rest) = g.strip_prefix("plume-") {
            if let Some((slug, role)) = rest.rsplit_once('-') {
                if matches!(role, "admin" | "editor" | "viewer") && tenant_slug_ok(slug) {
                    grant(slug, role);
                }
            }
        }
    }
    (map, superadmin)
}

/// #2b — un `platform_user` est-il super-admin plateforme ? Mode 0 (control=None) -> false.
pub(crate) fn platform_user_is_superadmin(st: &AppState, user: &str) -> bool {
    let Some(cp) = st.tenants.control.as_ref() else {
        return false;
    };
    let conn = cp.conn.lock();
    conn.query_row("SELECT is_superadmin FROM platform_user WHERE name=?1", params![user], |r| r.get::<_, i64>(0))
        .map(|v| v != 0)
        .unwrap_or(false)
}

/// #2b — rôle de `user` POUR `tenant`. SSO : la map LIVE fait foi (révocation instantanée d'un groupe) ;
/// Basic/cookie : la table `grant` du control-plane (via resolve_user_tenant). None = aucun grant sur ce tenant.
pub(crate) fn grant_role_for(st: &AppState, user: &str, tenant: &str, sso_map: Option<&HashMap<String, String>>) -> Option<String> {
    if let Some(map) = sso_map {
        return map.get(tenant).cloned();
    }
    resolve_user_tenant(st, user, Some(tenant)).map(|(_, role)| role)
}

/// #2b — tenant par DÉFAUT (aucune sélection explicite header/param) : 1er grant en ordre STABLE. SSO : plus
/// petit slug ; Basic/cookie : 1er grant (resolve_user_tenant). None = aucun grant.
pub(crate) fn default_grant(st: &AppState, user: &str, sso_map: Option<&HashMap<String, String>>) -> Option<(String, String)> {
    if let Some(map) = sso_map {
        let mut keys: Vec<&String> = map.keys().collect();
        keys.sort();
        let t = keys.into_iter().next()?;
        return Some((t.clone(), map[t].clone()));
    }
    resolve_user_tenant(st, user, None)
}

/// #2b — accès RBAC per-tenant résolu par auth_guard (choke-point). `role` = rôle EFFECTIF pour `tenant`.
#[derive(Debug)]
pub(crate) struct TenantAccess {
    pub(crate) tenant: String,
    pub(crate) role: String,
    pub(crate) is_superadmin: bool,
    /// super-admin accédant à un tenant dont il n'est PAS membre normal -> déclenche le marqueur opérateur.
    pub(crate) cross_tenant: bool,
}

/// #2b (D3) — résout (tenant courant, rôle per-tenant, superadmin, cross-tenant) pour un USER réel (mode 1) :
///  - tenant courant = sélection explicite (header/param) sinon 1er grant ;
///  - MEMBRE (grant présent) -> son rôle per-tenant, cross_tenant=false ;
///  - PAS de grant + PAS superadmin -> 403 (aucun accès à ce tenant) ;
///  - PAS de grant + superadmin -> ACCÈS CROSS-TENANT : lecture = viewer (auditée), écriture = break-glass
///    (rôle admin BORNÉ, raison non vide) sinon 403. Le tenant doit exister/être résoluble (sinon 403).
/// Jamais d'écriture cross-tenant SILENCIEUSE : sans break-glass, une mutation d'un non-membre est refusée.
pub(crate) fn resolve_tenant_access(
    st: &AppState,
    user: &str,
    sso_map: Option<&HashMap<String, String>>,
    sso_superadmin: bool,
    requested: Option<&str>,
    mutating: bool,
    breakglass: Option<&str>,
) -> Result<TenantAccess, (StatusCode, String)> {
    let is_sa = if sso_map.is_some() { sso_superadmin } else { platform_user_is_superadmin(st, user) };
    let requested = requested.map(str::trim).filter(|s| !s.is_empty());
    // 1) Tenant courant.
    let tenant = match requested {
        Some(t) => t.to_string(),
        None => match default_grant(st, user, sso_map) {
            Some((t, _)) => t,
            None => {
                return if is_sa {
                    // super-admin sans tenant par défaut -> sélection explicite requise (jamais un tenant deviné).
                    Err((StatusCode::CONFLICT, "sélection de tenant requise (super-admin sans tenant par défaut)".into()))
                } else {
                    Err((StatusCode::FORBIDDEN, "aucun tenant accessible (grant requis)".into()))
                };
            }
        },
    };
    // 2) Membre normal du tenant -> son rôle per-tenant (admin chez A, viewer chez B).
    if let Some(role) = grant_role_for(st, user, &tenant, sso_map) {
        return Ok(TenantAccess { tenant, role, is_superadmin: is_sa, cross_tenant: false });
    }
    // 3) Non-membre : seul un super-admin peut accéder (cross-tenant, audité) ; sinon 403.
    if !is_sa {
        return Err((StatusCode::FORBIDDEN, "aucun accès à ce tenant (grant requis)".into()));
    }
    // Le tenant doit exister ET être résoluble (fail-closed : jamais d'accès à un tenant fantôme/suspendu).
    if !st.tenants.tenant_available(&tenant) {
        return Err((StatusCode::FORBIDDEN, "tenant inconnu ou indisponible".into()));
    }
    if mutating {
        // ÉCRITURE cross-tenant = break-glass EXPLICITE (raison non vide), sinon 403. Jamais silencieuse.
        match breakglass.map(str::trim).filter(|r| !r.is_empty()) {
            Some(_) => Ok(TenantAccess { tenant, role: "admin".into(), is_superadmin: true, cross_tenant: true }),
            None => Err((StatusCode::FORBIDDEN, "écriture cross-tenant interdite sans break-glass (en-tête X-Plume-Breakglass: <raison>)".into())),
        }
    } else {
        // LECTURE cross-tenant = viewer (read-only), auditée par le marqueur opérateur (émis par auth_guard).
        Ok(TenantAccess { tenant, role: "viewer".into(), is_superadmin: true, cross_tenant: true })
    }
}

/// Capability MINIMALE d'une route (modèle DEFAULT-DENY). Les rôles ne forment PAS un ordre total :
/// `agent` (ingest machine, token Bearer) est ORTHOGONAL à viewer/editor. D'où un enum + `role_satisfies`
/// plutôt qu'un simple `>=`. L'admin est traité EN AMONT (rbac_gate court-circuite -> Ok) : ici, rôles
/// NON-admin uniquement.
#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum MinRole {
    /// Lecture : viewer, editor (GET + POST de lecture query/search/cancel + assets statiques).
    Read,
    /// Écriture éditoriale : editor (CRUD détection/cases/dashboards/vues/panneaux/lookups/ack…).
    Write,
    /// Réservé administrateur (secrets/config sensibles, armement réponse, gestion users/tenants…).
    Admin,
    /// Ingest machine-to-machine : agent (Bearer) OU editor/admin (compte Basic collecteur) — JAMAIS viewer.
    Ingest,
    /// Endpoints responder agent (poll/résultat) : rôle `agent` (le handler ré-exige `agent`).
    Agent,
}

/// Un rôle NON-admin satisfait-il la capability minimale d'une route ? (l'admin est court-circuité en amont).
pub(crate) fn role_satisfies(role: &str, need: MinRole) -> bool {
    match need {
        // #39 — `client` (jeton read-scoped client-read API) satisfait UNIQUEMENT la lecture, JAMAIS write/
        //  admin/ingest/agent -> read-only strict. Orthogonal à viewer (masqué au rank 0, cf. role_rank).
        MinRole::Read => matches!(role, "viewer" | "editor" | "client"),
        MinRole::Write => role == "editor",
        MinRole::Admin => false,
        MinRole::Ingest => matches!(role, "editor" | "agent"),
        MinRole::Agent => role == "agent",
    }
}

/// #2b — TABLE DE CAPABILITIES par route (DEFAULT-DENY). Chaque route déclare sa
/// capability MINIMALE ; une route MUTANTE non déclarée retombe sur `Admin` (fail-closed) au lieu d'être
/// ouverte à l'editor (ancienne allowlist fail-open). `mutating` distingue GET (lecture) de POST/DELETE
/// pour les routes à double méthode (ex : /api/mode GET=lecture, POST=armement admin). Robuste et testable.
pub(crate) fn route_min_role(path: &str, mutating: bool) -> MinRole {
    // 0) #52 DATASOURCE — surfaces de LECTURE EXTERNE (Grafana pointe SUR plume) : GXQL-over-HTTP + Prometheus
    //    read + stub Loki. TOUJOURS Read (GET comme POST) : read-only, aucune mutation, aucun SQL brut exposé
    //    (le handler ne consomme QUE `soql`/un sélecteur de métrique). Le masque #45 + RBAC s'appliquent DANS
    //    le handler (effective_masks du rôle). Un rôle `agent` NE satisfait PAS Read -> un token agent
    //    (ingest-only) ne peut pas lire ici ; viewer/editor oui ; admin court-circuité.
    if matches!(
        path,
        "/api/ds/query" | "/api/v1/query" | "/api/v1/query_range" | "/api/v1/labels" | "/api/v1/series"
            | "/loki/api/v1/query_range"
    ) || path.starts_with("/api/v1/label/")
    {
        return MinRole::Read;
    }
    // 1) INGEST machine-to-machine (agent Bearer + compte editor/admin collecteur) — jamais viewer.
    if matches!(
        path,
        "/api/ingest" | "/api/ingest/minio" | "/api/ingest/journal" | "/api/metrics/prom" | "/api/metrics/write" | "/loki/api/v1/push"
        // HEC (#16) — bring-your-own-forwarder : collector d'events = INGEST (token HEC=agent, ou compte
        // editor/admin collecteur ; jamais viewer). /health public (jamais ici). Miroir des autres ingest.
        | "/services/collector" | "/services/collector/event"
        // OTLP (#41) — récepteur OpenTelemetry traces = INGEST (Bearer=agent host-bound ; jamais viewer).
        // Miroir des autres récepteurs d'ingest ; le handler est en plus gaté par PLUME_OTLP_TRACES.
        | "/v1/traces"
    ) {
        return MinRole::Ingest;
    }
    // 2) RESPONDER agent (réclame/rapporte les actions approuvées) — rôle `agent` (handler ré-exige agent).
    //    v75 : /api/engagements/active = SEAM PULL enforcer (mêmes garanties agent host-bound) -> AVANT le bloc
    //    admin-only /api/engagements* de la section 3 (match exact prioritaire).
    if matches!(path, "/api/actions/pending" | "/api/actions/result" | "/api/engagements/active") {
        return MinRole::Agent;
    }
    // 2bis) MFA self-service (#44) : enrôlement/vérif/désactivation de SA PROPRE MFA -> tout compte
    //    authentifié (viewer+ ; l'admin est court-circuité). Le handler opère UNIQUEMENT sur `au.name` (self)
    //    -> pas d'accès aux données d'autrui. `Read` suffit (le CSRF cookie s'applique quand même aux POST).
    if path.starts_with("/api/mfa/") {
        return MinRole::Read;
    }
    // 2ter) #62 PRÉFÉRENCES UTILISATEUR self-service : lecture/écriture de SES PROPRES préférences d'UI ->
    //    tout compte authentifié (viewer+ ; admin court-circuité). Le handler opère UNIQUEMENT sur `au.name`
    //    (self) -> aucun accès aux données d'autrui. `Read` suffit MÊME pour le PUT (mutating) : ce n'est PAS
    //    une surface admin (préférences UI, jamais de secret ni d'autz) ; le CSRF cookie s'applique au PUT.
    //    Miroir EXACT du MFA self-service (2bis).
    if path.starts_with("/api/prefs") {
        return MinRole::Read;
    }
    // 2quater) SAVED QUERIES self-service : liste/crée/édite/supprime SES PROPRES requêtes GXQL nommées ->
    //    tout compte authentifié (viewer+ ; admin court-circuité). Le handler pose TOUJOURS `owner = au.name`
    //    (list `WHERE owner=?`, mutation `WHERE id=? AND owner=?`) -> aucun accès aux requêtes d'autrui (IDOR
    //    bloqué). Ce n'est PAS une surface admin (outillage analyste personnel, aucun secret ni autz) : `Read`
    //    suffit MÊME pour POST/PUT/DELETE (le CSRF cookie s'applique au mutant). Miroir du self-service #62/MFA.
    if path.starts_with("/api/saved-queries") {
        return MinRole::Read;
    }
    // 2quinquies) #16 IA CONSEIL (feature `ai` OFF par défaut -> bloc EXCLU à la compilation ; dans le build
    //    DÉFAUT aucune route /api/ai n'existe, route_min_role n'en voit jamais). L'ANALYSTE (viewer+) peut
    //    demander une traduction NL→GXQL et lire le statut. NL→GXQL est un POST mais READ-ONLY (l'IA PROPOSE,
    //    le compilo FERMÉ dispose ; ZÉRO exécution, aucune mutation, aucun SQL brut : le handler ne renvoie que
    //    du GXQL+SQL validés à réviser). `Read` suffit ; le CSRF cookie s'applique quand même au POST. Le CRUD
    //    providers (colonne `secret`=clé API/SecretRef) + presets + politique de redaction reste ADMIN : catch
    //    fail-closed `/api/ai` -> Admin, PLACÉ APRÈS les deux routes analyste (sinon elles tomberaient admin-only).
    #[cfg(feature = "ai")]
    {
        if path == "/api/ai/nl2soql" || path == "/api/ai/status" {
            return MinRole::Read;
        }
        if path.starts_with("/api/ai") {
            return MinRole::Admin;
        }
    }
    // 3) ADMIN-ONLY toutes méthodes (GET compris car secrets/config) :
    //    - users / connectors / retention / ledger / sources/settings : historique admin-only ;
    //    - notifiers : GET expose la colonne `config` (token ntfy / user:pass SMTP) -> ADMIN (fix MEDIUM) ;
    //    - actions (list/create/approve/cancel — pending|result déjà traités en 2) : moteur de réponse ;
    //    - password : reset du mdp admin (fix CRITICAL) ; setup : bootstrap (token-gated).
    if path.starts_with("/api/users")
        || path.starts_with("/api/tokens") // provisioning jetons agent/HEC (secrets) : GET compris -> ADMIN
        || path.starts_with("/api/idp") // #44 CRUD des providers IdP (client_secret / bind pw) : GET compris -> ADMIN

        || path.starts_with("/api/connectors")
        || path.starts_with("/api/destinations") // #50 outputs/destinations : SORTIE de données SOC hors du périmètre (data-exfil surface) + `config` porte le secret d'auth du sink -> ADMIN (GET compris)
        || path.starts_with("/api/processors") // #40 processeur d'ingest (filtre/masque/route) : config d'ingestion sensible -> ADMIN (GET compris)
        || path.starts_with("/api/index-policies") // #49 indexes logiques nommés : PILOTENT une purge destructive -> ADMIN (GET compris)
        || path.starts_with("/api/field-filters") // #45 field filters (masquage par champ) : config PII qui CONTRAINT viewer/editor -> ADMIN (GET compris)
        || path.starts_with("/api/notifiers")
        || path.starts_with("/api/retention")
        || path.starts_with("/api/ledger") // #38 ledger view + #59 /api/ledger/export (chaîne préservée) : GET compris -> ADMIN
        || path.starts_with("/api/ledger-sinks") // #59 sinks d'export streaming (secret_ref) : GET compris -> ADMIN
        || path.starts_with("/api/legal-holds") // #59 legal-hold / rétention-lock (gouvernance destructive) : GET compris -> ADMIN
        // PURGE EXPLICITE D'ÉVÉNEMENTS : la seule surface qui DÉTRUIT des preuves à la demande. ADMIN-only,
        // GET compris (aucun GET n'existe aujourd'hui — le préfixe ferme d'avance toute lecture future de
        // périmètre/jeton). La route reste en plus fermée tant que `PLUME_PURGE_API` n'est pas armé.
        || path.starts_with("/api/purge")
        || path.starts_with("/api/roles") // #59 catalogue de rôles composables : GET compris -> ADMIN (super-admin en mode 1, re-check handler)
        || path.starts_with("/api/sources/settings")
        || path.starts_with("/api/suppressions") // chantier whitelists→webui : GET (config sensible) + PUT (display-only) admin-only
        || path.starts_with("/api/actions")
        // BAN NATIF PLUME (chantier ② Phase 1) : `/api/netban` (list/add/remove) = contrôle d'enforcement réseau
        // (blocage HTTP d'une IP) -> ADMIN-only, GET compris (la liste des bans est une surface sensible). C'est
        // le canal qu'admin-console (plan de contrôle) appelle. Miroir de /api/actions (moteur de réponse).
        || path.starts_with("/api/netban")
        // #3 Phase 2 — AUTHORING de runbooks (bring-your-own) : CRUD + clone + enable/disable = surface admin
        // (contenu ADMIN-AUTHORED : gabarits GXQL de step 'search' + réf d'action de step 'response'). GET compris
        // (la vue d'authoring liste key/steps/match). NB : /api/cases/:id/runbook(s) (picker/attach du wizard)
        // NE commence PAS par /api/runbooks -> reste editor+/viewer+ (section 6/7), inchangé.
        || path.starts_with("/api/runbooks")
        || path.starts_with("/api/engagements") // v75 : create/end/list/get = admin-only (break-glass) ; /active déjà capté en 2
        || path == "/api/password"
        || path == "/api/setup"
        // #51 DAY-2 OPS — bundle de diagnostic (support hand-off) : GET admin-only (résumé de config +
        // échantillon d'events opérationnels). Allowlist non-secret dans le handler + re-check require_admin.
        || path == "/api/system/diag"
    {
        return MinRole::Admin;
    }
    // 4) /api/mode : lecture = viewer+ (l'UI affiche le mode) ; ARMEMENT (POST active) = ADMIN (fix HIGH).
    if path == "/api/mode" {
        return if mutating { MinRole::Admin } else { MinRole::Read };
    }
    // 5) #4a-bis — ARCHIVE / DÉSARCHIVE de case = action DELETE-LIKE (masque un case) => ADMIN (les autres
    //    routes /api/cases/* restent editor+). Miroir du re-check `au.role=="admin"` dans les handlers.
    if path.starts_with("/api/cases/") && (path.ends_with("/archive") || path.ends_with("/unarchive")) {
        return MinRole::Admin;
    }
    // 5bis) #39 — SUPPRESSION d'une politique SLA (config gouvernante multi-niveau) = DELETE-LIKE => ADMIN
    //   (re-check `au.is_admin()` dans le handler). L'UPSERT (POST /api/sla-policies) reste editor+ (section 7).
    //   Match par présence d'un id (path plus long) + mutation -> DELETE /api/sla-policies/:id.
    if path.starts_with("/api/sla-policies/") && mutating {
        return MinRole::Admin;
    }
    // 5ter) #1c-toggle — (DÉS)ACTIVATION d'un contenu de détection (règle/parseur/playbook) via le suffixe
    //   `/enabled` (POST) = CHANGEMENT DE CONFIG SÉCU (activer/désactiver une détection modifie la posture) =>
    //   ADMIN (re-check `require_admin` dans le handler + audit non-purgeable). DOIT précéder la section 7 qui
    //   classe tout `/api/rules|/api/parsers|/api/playbooks` en editor+ (CRUD éditorial) : sans cette règle, un
    //   editor basculerait l'activation d'une règle. Fonctionne pour les overlays config.d (managed=1) via un
    //   override persistant. GET n'existe pas sur `/enabled` (capté en 6 -> viewer+, mais aucun handler GET).
    if mutating
        && path.ends_with("/enabled")
        && (path.starts_with("/api/rules/") || path.starts_with("/api/parsers/") || path.starts_with("/api/playbooks/"))
    {
        return MinRole::Admin;
    }
    // 6) LECTURE : GET/HEAD + POST de lecture (query/search/cancel, `mutating=false`) + assets statiques
    //    (fallback ServeDir) + inventaires (/api/sources, /api/me, /api/my-tenants, /api/overview…). viewer+.
    //    NB : les GET admin-only (users/notifiers/…) sont déjà captés en 3 -> jamais ici.
    if !mutating {
        return MinRole::Read;
    }
    // 7) MUTATIONS ÉDITORIALES LÉGITIMES (INVARIANT : l'editor garde ce CRUD) -> editor+.
    //    détection (rules/parsers/tests/reparse) + lookups + dashboards/vues/panneaux + playbooks (l'armement
    //    d'une action destructive est refusé PLUS LOIN, dans validate_detection_content) + cases (notes/liens/
    //    statut, hors archive) + ack d'alertes + mail/body.
    if path.starts_with("/api/rules")
        || path.starts_with("/api/parsers")
        || path == "/api/parser-test"
        || path == "/api/rule-test"
        // #37 détection avancée : corrélations + baselines = CRUD éditorial (GXQL borné, pas de SQL brut ni
        // d'action destructive) -> editor+, comme les règles. GET reste viewer+ (capté en section 6).
        || path.starts_with("/api/correlations")
        || path.starts_with("/api/baselines")
        || path.starts_with("/api/lookups")
        || path.starts_with("/api/views")
        || path.starts_with("/api/dashboards")
        || path.starts_with("/api/dashboard/")
        || path.starts_with("/api/panels")
        // #54 ergonomie dashboards : library panels / playlists / snapshots = CRUD éditorial (editor+).
        // GET (liste + snapshot par token = lecture seule) reste viewer+ (capté en section 6). Le snapshot
        // par token est read-only ; ses données sont DÉJÀ masquées à la capture (rôle du créateur).
        || path.starts_with("/api/library-panels")
        || path.starts_with("/api/playlists")
        || path.starts_with("/api/dashboard-snapshots")
        || path.starts_with("/api/playbooks")
        || path.starts_with("/api/cases")
        // #39 — UPSERT de politique SLA multi-niveau (POST /api/sla-policies) = CRUD éditorial (editor+) ; GET
        //  reste viewer+ (section 6) ; DELETE /api/sla-policies/:id = admin (section 5bis, capté avant).
        || path == "/api/sla-policies"
        || path.starts_with("/api/alerts/") // ack-all + :id/ack (la LISTE /api/alerts est GET -> lecture en 6)
        || path == "/api/mail/body"
        // #53 : politiques de notification + silences = editor+ (GET viewer+ capté en 6). NB : la CONFIG des
        // canaux (/api/notifiers, secrets) reste ADMIN (section 3) ; ici on ne fait que ROUTER/MUTER — les
        // policies référencent des canaux par id sans lire leur secret. Create/delete ledgerisés (gouvernance).
        || path.starts_with("/api/notification-policies")
        || path.starts_with("/api/silences")
        // KNOWLEDGE OBJECTS (#46) : CRUD alias/calc/eventtype/tag = editor+ (ils façonnent la recherche de
        // tout le monde, comme les règles ; GET reste viewer+ capté en 6). Pas de SQL brut (expr calc via
        // `eval`, filtre eventtype via GXQL), pas d'action destructive -> editor légitime.
        || path.starts_with("/api/knowledge")
        // DATA MODELS + DATASETS (#47) : CRUD des modèles/objets/champs/datasets = editor+ (couche sémantique
        // PARTAGÉE, comme les knowledge objects ; GET reste viewer+ capté en 6). L'EXÉCUTION de Pivot/dataset
        // (/api/pivot/*, /api/datasets/:id/run) est un POST de LECTURE (readonly_post -> mutating=false) -> capté
        // en 6 (Read) AVANT d'arriver ici. Pas de SQL brut (le Pivot génère du GXQL) -> editor légitime.
        || path.starts_with("/api/datamodels")
        || path.starts_with("/api/datasets")
        // #60 — SCHEDULED REPORTS : CRUD + run-now = editor+ (route l'exécution d'un dataset vers un notifier
        // admin-configuré, comme les notification-policies #53 ; run_as PLAFONNÉ au rôle du créateur -> pas
        // d'escalade). GET reste viewer+ (capté en 6). Le résultat est masqué #45 par le run_as, pas de SQL brut.
        || path.starts_with("/api/scheduled-reports")
        // #60 — WORKFLOW ACTIONS : CRUD = editor+ (métadonnées de menu ; kind='response' re-exige admin dans le
        // handler). GET (liste) + /resolve (readonly_post) = viewer+ (section 6). La réponse s'exécute via
        // /api/actions (admin + approbation + ledger) — jamais ici.
        || path.starts_with("/api/workflow-actions")
    {
        return MinRole::Write;
    }
    // 8) DEFAULT-DENY : toute MUTATION non déclarée (route oubliée / future) -> ADMIN (fail-closed).
    //    Les routes de GESTION DES TENANTS (/api/tenants*) tombent ICI : admin passe (court-circuit) puis
    //    `tenant_mgmt_gate` (mode 1) applique le fin superadmin/tenant-admin ; mode 0 : handlers inertes.
    MinRole::Admin
}

/// #2b — GATE RBAC per-rôle, EXTRAIT du choke-point pour testabilité (rôle = le rôle PER-TENANT résolu).
/// Modèle DEFAULT-DENY : admin=total (superuser, identique à l'historique où il passait tous les gardes) ;
/// sinon la route déclare sa capability minimale (route_min_role) et le rôle doit la satisfaire, faute de
/// quoi 403. Une mutation OUBLIÉE de la table est fermée à l'admin (jamais ouverte à l'editor).
/// #59 — mappe une route SENSIBLE vers la permission SOUSTRACTIBLE qui la garde (pour les rôles composables
/// basés-admin : un `deny` retire l'accès MÊME à un base=admin). None -> aucune perm dédiée (la capacité de
/// route de base suffit). Enum FERMÉ (KNOWN_DENY_PERMS). raw_sql est géré à part (raw_sql_allowed).
pub(crate) fn route_denied_perm(path: &str) -> Option<&'static str> {
    if path.starts_with("/api/users") || path.starts_with("/api/tokens") {
        return Some("manage_users");
    }
    if path.starts_with("/api/actions") || path.starts_with("/api/engagements") {
        return Some("arm_response");
    }
    if path.starts_with("/api/ledger") {
        return Some("ledger_export");
    }
    // Un rôle composable base=admin peut se voir RETIRER la purge sans perdre le reste de l'autorité admin :
    // « admin » n'est pas forcément le bon quantum d'autorité pour détruire des preuves. Soustractif comme
    // les autres (jamais additif), et enfermé dans l'enum `KNOWN_DENY_PERMS`.
    if path.starts_with("/api/purge") {
        return Some("purge_events");
    }
    None
}

pub(crate) fn rbac_gate(role: &str, path: &str, mutating: bool) -> Result<(), (StatusCode, &'static str)> {
    if role == "admin" {
        return Ok(());
    }
    // #39 CORRECTIVE (couche b/2) — INVARIANT d'autorisation AUTH-INDÉPENDANT : le rôle `client` (client-read
    // API) est CONFINÉ aux routes client-read PEU IMPORTE l'origine de l'identité (jeton kind='client', grant,
    // SSO, SCIM, futur). Sans ça, un `client` sur une LECTURE (/api/query,/api/cases,/api/alerts…) recevait des
    // données tenant (route Read + masquage OPT-IN -> masque vide sans field-filter). client_bearer_path est
    // l'allowlist CANONIQUE des 2 routes client-read (réutilisée ici). Hors de cette allowlist -> 403 (jamais un
    // 200 masqué-vide). SUR l'allowlist -> on RETOMBE sur la logique normale (role_satisfies) : /api/client/cases
    // en GET = Read -> Ok ; une éventuelle mutation retombe en DEFAULT-DENY=Admin -> 403 (read-only strict gardé).
    if role == "client" && !client_bearer_path(path) {
        return Err((StatusCode::FORBIDDEN, "rôle client confiné aux routes client-read"));
    }
    // #59 RÔLE COMPOSABLE : un nom NON-intégré résout vers son PLAFOND (base_role) — jamais au-dessus. Un
    // rôle de base (viewer/editor/agent) OU un catalogue VIDE (mode 0) -> custom_role_lookup=None -> le
    // chemin historique ci-dessous reste BYTE-IDENTIQUE. DEFAULT-DENY : un nom inconnu n'est pas un custom
    // défini -> il n'est pas non plus un base -> role_satisfies(inconnu, _) = false -> 403.
    if let Some(rd) = custom_role_lookup(role) {
        if rd.base == "admin" {
            // Base=admin : autorité admin MOINS les perms explicitement RETIRÉES (soustractif, jamais additif).
            if let Some(perm) = route_denied_perm(path) {
                if role_perm_denied(role, perm) {
                    return Err((StatusCode::FORBIDDEN, "capacité retirée à ce rôle (permission refusée)"));
                }
            }
            return Ok(());
        }
        // Base=viewer|editor : gate sur la capacité de route de la BASE (jamais plus haut).
        let need = route_min_role(path, mutating);
        if role_satisfies(&rd.base, need) {
            return Ok(());
        }
        return Err((StatusCode::FORBIDDEN, "réservé à l'administrateur"));
    }
    let need = route_min_role(path, mutating);
    if role_satisfies(role, need) {
        return Ok(());
    }
    // Message aligné sur l'historique : viewer en écriture = "lecture seule" ; sinon "réservé à l'admin".
    let msg = if role == "viewer" && mutating {
        "lecture seule (rôle viewer)"
    } else {
        "réservé à l'administrateur"
    };
    Err((StatusCode::FORBIDDEN, msg))
}

// #2b/D3/R9 — MARQUEUR OPÉRATEUR cross-tenant : debounce du 2e ledger (event tenant-visible) + control_ledger.
pub(crate) const OPERATOR_ACCESS_DEBOUNCE_S: i64 = 600; // 1 event tenant-visible / 10 min / (superadmin,tenant)

pub(crate) static OPERATOR_ACCESS_LAST: std::sync::OnceLock<Mutex<HashMap<(String, String), i64>>> = std::sync::OnceLock::new();

/// True si l'event operator-access DOIT être émis dans la base du tenant : `force` (break-glass) OU fenêtre
/// de debounce écoulée pour ce (superadmin, tenant). Réarme le debounce quand il renvoie true. Borné anti-OOM.
pub(crate) fn operator_access_should_emit(superadmin: &str, tenant: &str, now_i: i64, force: bool) -> bool {
    let cell = OPERATOR_ACCESS_LAST.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = cell.lock();
    if g.len() > 4096 {
        g.retain(|_, &mut last| now_i - last < OPERATOR_ACCESS_DEBOUNCE_S);
    }
    let key = (superadmin.to_string(), tenant.to_string());
    let elapsed = g.get(&key).map(|&last| now_i - last >= OPERATOR_ACCESS_DEBOUNCE_S).unwrap_or(true);
    if force || elapsed {
        g.insert(key, now_i);
        true
    } else {
        false
    }
}

/// #2b (D3) — journal d'audit hash-chaîné du CONTROL-PLANE (append-only, tamper-evident). Mode 0
/// (control=None) -> no-op. Sert superadmin.read/superadmin.write (accès cross-tenant) + futures mutations
/// catalogue. `detail` peut porter la raison du break-glass. Best-effort (n'interrompt pas la requête).
pub(crate) fn control_ledger_append(st: &AppState, kind: &str, actor: &str, tenant: &str, detail: &str) {
    let Some(cp) = st.tenants.control.as_ref() else {
        return;
    };
    let conn = cp.conn.lock();
    let ts = now();
    let prev: String = conn
        .query_row("SELECT hash FROM control_ledger ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
        .unwrap_or_default();
    let hash = sha256_hex(format!("{prev}|{ts}|{kind}|{actor}|{tenant}|{detail}").as_bytes());
    let _ = conn.execute(
        "INSERT INTO control_ledger(ts,kind,actor,tenant,detail,prev_hash,hash) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![ts, kind, actor, tenant, detail, prev, hash],
    );
}

/// #2b (D3/R9) — ÉMISSION STRUCTURELLE du marqueur d'accès opérateur cross-tenant (appelée par auth_guard,
/// JAMAIS un handler séparé -> impossible à contourner). DEUX journaux :
///  (a) control_ledger (`superadmin.read`|`superadmin.write`) : à CHAQUE accès (audit opérateur complet) ;
///  (b) event `source='plume-operator-access'` DANS la base du tenant VISITÉ (le client le voit lui-même) —
///      NON DÉSACTIVABLE. Lecture : DEBOUNCÉ (1 / OPERATOR_ACCESS_DEBOUNCE_S par (superadmin,tenant)) pour ne
///      pas flooder ; break-glass (write) : FORCÉ + sévérité élevée. La donnée reste tenant-locale (isolation).
pub(crate) fn emit_operator_access(st: &AppState, superadmin: &str, tenant: &str, write: bool, reason: Option<&str>) {
    let reason = reason.map(str::trim).filter(|r| !r.is_empty()).unwrap_or("");
    // (a) 1er ledger : control_ledger, à CHAQUE accès.
    control_ledger_append(st, if write { "superadmin.write" } else { "superadmin.read" }, superadmin, tenant, reason);
    // (b) 2e ledger : event NON-DÉSACTIVABLE dans la base du tenant (debounce en lecture, forcé en write).
    let now_i = now();
    if !operator_access_should_emit(superadmin, tenant, now_i, write) {
        return;
    }
    let Some(handle) = st.tenants.handle_for(tenant) else {
        return;
    };
    let conn = handle.lock();
    let (sev, action, msg) = if write {
        (4, "write", format!("BREAK-GLASS : l'opérateur plateforme '{superadmin}' a ÉCRIT dans vos données (raison : {reason})"))
    } else {
        (2, "read", format!("l'opérateur plateforme '{superadmin}' a consulté vos données (lecture cross-tenant)"))
    };
    let fields = json!({ "operator": superadmin, "access": action, "reason": reason }).to_string();
    let _ = conn.execute(
        // origin='daemon' (v72/M4) : marqueur d'accès opérateur NON-purgeable et NON-forgeable (cf. retention_run).
        "INSERT INTO event(ts,source,category,severity,message,host,fields,origin) \
         VALUES(?1,'plume-operator-access','audit',?2,?3,'plume-daemon',?4,'daemon')",
        params![now_i, sev, msg, fields],
    );
}

/// (#2c) Le tenant dont le RÔLE PER-TENANT compte pour l'autorisation d'une route de gestion : UNIQUEMENT
/// les routes `grants` (un tenant-admin gère les grants de SON tenant). Pour le CRUD de tenant (super-admin
/// only) ou la liste, renvoie None -> auth_guard prend le contexte `default` (toujours résoluble), afin que
/// le garde fail-closed ne bloque JAMAIS un super-admin opérateur (ni un DELETE d'un tenant suspendu).
pub(crate) fn mgmt_target_tenant(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/api/tenants/")?;
    let mut parts = rest.splitn(3, '/');
    let id = parts.next().unwrap_or("");
    let sub = parts.next();
    if sub == Some("grants") && !id.is_empty() {
        return Some(id.to_string());
    }
    None
}

/// (#2c) Rôle de l'actor SUR le tenant de gestion `grants` visé, pour l'AUTORISATION (path-guard + handler).
/// Résout le rôle PER-TENANT via les grants UNIQUEMENT (SSO map LIVE ou table `grant`) — comme
/// resolve_tenant_access. Un NON-MEMBRE (aucun grant sur ce tenant) NE doit PAS hériter du plancher
/// d'identité : un admin local/config non-superadmin (role_floor="admin", exclu du data-plane par
/// resolve_tenant_access) hériterait sinon d'un rôle admin sur un tenant tiers et gérerait ses grants
/// (escalade cross-tenant). Repli non-membre : "admin" pour un SUPER-ADMIN (accès cross-tenant légitime,
/// borné par le flag is_superadmin en aval ; conserve son rôle non-viewer pour passer rbac_gate en écriture),
/// "viewer" pour tout autre (le path-guard + rbac_gate refusent alors la gestion des grants).
pub(crate) fn mgmt_grants_role(st: &AppState, user: &str, target: &str, sso_map: Option<&HashMap<String, String>>, is_sa: bool) -> String {
    grant_role_for(st, user, target, sso_map)
        .unwrap_or_else(|| if is_sa { "admin".to_string() } else { "viewer".to_string() })
}

/// (#2c) PATH-GUARD des routes de gestion des tenants (appelé par auth_guard, MODE 1 uniquement). Double le
/// re-check des handlers (défense en profondeur). Autorisations :
///  - `/api/my-tenants`                     -> tout user authentifié (switcher) ;
///  - `/api/tenants/:id/grants[...]`        -> SUPER-ADMIN (n'importe quel tenant) OU admin de CE tenant ;
///  - toute autre `/api/tenants[...]` (CRUD/suspend/list/create) -> SUPER-ADMIN uniquement.
pub(crate) fn tenant_mgmt_gate(path: &str, role: &str, tenant: &str, is_superadmin: bool) -> Result<(), (StatusCode, &'static str)> {
    if path == "/api/my-tenants" {
        return Ok(());
    }
    let is_tenants_route = path == "/api/tenants" || path.starts_with("/api/tenants/");
    if !is_tenants_route {
        return Ok(());
    }
    if let Some(tid) = mgmt_target_tenant(path) {
        // Grants : super-admin (cross-tenant) OU tenant-admin borné à SON tenant courant.
        // #64 : AUTORITÉ ADMIN EFFECTIVE (effective_base_role) — le path-guard DOIT être cohérent avec le
        // re-check aval `can_manage_grants` (= `au.is_admin() && au.tenant==tid`, lui-même effective_base_role).
        // Un rôle composable base=admin de CE tenant gère donc ses propres grants (au lieu d'un 403 fail-closed
        // incohérent). Aucun raisonnement cross-tenant : le confinement `tenant == tid` (tenant courant du
        // caller) est INCHANGÉ. Pas de deny soustractif ici : la gestion des grants n'a PAS d'entrée dans
        // `route_denied_perm` (miroir exact de can_manage_grants, qui n'en applique aucun) -> rester cohérent.
        // Mode-0 / rôle de base -> byte-identique à `role == "admin"`.
        if is_superadmin || (effective_base_role(role) == "admin" && tenant == tid) {
            return Ok(());
        }
        return Err((StatusCode::FORBIDDEN, "gestion des grants réservée au super-admin ou à l'admin du tenant"));
    }
    // CRUD/suspend/list/create : SUPER-ADMIN uniquement (enforce SERVEUR).
    if is_superadmin {
        return Ok(());
    }
    Err((StatusCode::FORBIDDEN, "gestion des tenants réservée au super-admin plateforme"))
}

/// (#2c) Un actor peut-il gérer les grants du tenant `tid` ? Super-admin -> tout tenant ; sinon UNIQUEMENT
/// l'admin de CE tenant (jamais un autre, jamais un editor/viewer). Anti cross-tenant + anti-escalade.
pub(crate) fn can_manage_grants(au: &AuthUser, tid: &str) -> bool {
    au.is_superadmin || (au.is_admin() && au.tenant == tid)
}

/// (#2c) Rôle de grant VALIDE (enum FERMÉ). `is_superadmin` n'est JAMAIS un rôle assignable ici -> aucune
/// escalade plateforme possible via l'API de grants.
pub(crate) fn valid_grant_role(role: &str) -> bool {
    // #59 : un rôle COMPOSABLE n'est assignable que s'il est DÉFINI dans le catalogue (default-deny : un nom
    // inconnu reste rejeté). `is_superadmin` n'est JAMAIS un rôle assignable (aucune escalade plateforme).
    matches!(role, "admin" | "editor" | "viewer") || custom_role_lookup(role).is_some()
}

/// (#2c) Nom d'utilisateur plateforme valide (même politique que /api/users) : alphanumérique + `. _ -`.
pub(crate) fn platform_user_name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// (#2c) Identifiant TEXT aléatoire pour une nouvelle ligne control-plane (platform_user). 96 bits hex.
pub(crate) fn gen_control_id(prefix: &str) -> String {
    format!("{prefix}{}", &tenant_generate_key()[..24])
}

/// (#2c) Résout l'id d'un `platform_user` par nom, en le CRÉANT (SSO-only, hash NULL, is_superadmin=0) s'il
/// n'existe pas — un grant ne peut référencer qu'un platform_user existant (matérialisation du grant SSO,
/// cf. spec B.3). Ne modifie JAMAIS is_superadmin d'un compte existant.
pub(crate) fn ensure_platform_user(cp: &ControlPlane, name: &str) -> Option<String> {
    let conn = cp.conn.lock();
    if let Ok(id) = conn.query_row("SELECT id FROM platform_user WHERE name=?1", params![name], |r| r.get::<_, String>(0)) {
        return Some(id);
    }
    let id = gen_control_id("pu_");
    conn.execute(
        "INSERT INTO platform_user(id,name,hash,is_superadmin,created) VALUES(?1,?2,NULL,0,?3)",
        params![id, name, now()],
    )
    .ok()?;
    Some(id)
}

/// (#64) Compte les grants à AUTORITÉ ADMIN EFFECTIVE d'un tenant sur une connexion DÉJÀ tenue : littéral
/// `admin` OU rôle composable base=admin. SQL ne connaît pas `effective_base_role` -> on ÉNUMÈRE les rôles de
/// grant et on filtre en Rust. Sépare le comptage du verrouillage pour un usage sous-lock (SCIM group PATCH
/// tient déjà `cp.conn` -> pas de re-lock/deadlock). Mode-0 / rôles de base -> identique à `COUNT(role='admin')`.
pub(crate) fn effective_admin_grant_count_conn(conn: &Connection, tid: &str) -> i64 {
    let mut stmt = match conn.prepare("SELECT role FROM \"grant\" WHERE tenant_id=?1") {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let roles: Vec<String> = stmt
        .query_map(params![tid], |r| r.get::<_, String>(0))
        .map(|m| m.flatten().collect())
        .unwrap_or_default();
    roles.iter().filter(|r| effective_base_role(r) == "admin").count() as i64
}

/// (#2c/#64) Compte les grants à autorité admin EFFECTIVE d'un tenant (anti-lockout : ne pas retirer/rétrograder
/// le DERNIER admin d'un tenant via l'API, sauf super-admin qui peut toujours re-granter). Depuis #64 un rôle
/// composable base=admin COMPTE comme admin (sinon un tenant dont le seul admin est un rôle custom pourrait être
/// orphelin -> lockout DoS).
pub(crate) fn tenant_admin_grant_count(cp: &ControlPlane, tid: &str) -> i64 {
    let conn = cp.conn.lock();
    effective_admin_grant_count_conn(&conn, tid)
}

/// (#2c) AUDIT : écrit un event `source='plume-tenant-admin'` DANS la base du tenant visé (visible du client,
/// cf. tâche 6). Best-effort. Le tenant doit être résoluble (sinon no-op — ex. destruction déjà faite).
pub(crate) fn audit_tenant_event(st: &AppState, tenant: &str, action: &str, sev: i64, msg: &str, detail: Value) {
    let Some(handle) = st.tenants.handle_for(tenant) else {
        return;
    };
    let mut fields = serde_json::Map::new();
    fields.insert("action".into(), json!(action));
    if let Value::Object(m) = detail {
        for (k, v) in m {
            fields.insert(k, v);
        }
    }
    let conn = handle.lock();
    let _ = conn.execute(
        // origin='daemon' (v72/M4) : marqueur d'action tenant-admin NON-purgeable et NON-forgeable (cf. retention_run).
        "INSERT INTO event(ts,source,category,severity,message,host,fields,origin) \
         VALUES(?1,'plume-tenant-admin','audit',?2,?3,'plume-daemon',?4,'daemon')",
        params![now(), sev, msg, Value::Object(fields).to_string()],
    );
}

/// (#2c) db_path d'un NOUVEAU tenant : `<répertoire de PLUME_DB>/tenants/<slug>/plume.db`. Un slug déjà
/// validé (tenant_slug_ok) est sûr en composant de chemin (alnum + `_`/`-`, jamais `/`/`.`).
pub(crate) fn tenant_db_path(st: &AppState, slug: &str) -> String {
    let base = std::path::Path::new(st.db_path.as_str())
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    base.join("tenants").join(slug).join("plume.db").to_string_lossy().into_owned()
}

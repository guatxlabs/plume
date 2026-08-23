//! server::groupes_de_routes — LA TABLE DE ROUTAGE du démon : les sous-routeurs cohésifs par domaine
//! (santé/système, aperçu/recherche, alertes/couverture, conformité, requête/export, sources, tableaux de
//! bord et panneaux, comptes/jetons, IdP/MFA, listes, règles/parseurs/processeurs, index/filtres de champ,
//! connaissances, modèles de données, rapports/workflow, détection avancée, flotte/intégrations/fraîcheur,
//! ingestion (typée et brute), session, notifieurs/politiques/silences, connecteurs/destinations,
//! renseignement/risque, actions/mode/engagements, ban natif, gouvernance/rétention/registre,
//! playbooks/cas, tenants) et leur COMPOSITION dans `build_router` — les six couches globales, le
//! service de fichiers de repli et l'injection d'état, dans l'ordre exact que les tests `router_*`
//! interrogent. Sous-module de `server` (cf. `server/mod.rs`), qui ré-exporte `build_router` sous son
//! chemin d'origine.
use super::*;

// ---------- groupes de routes (refactor split #8) ----------
// Sous-routeurs cohesifs par domaine, extraits de build_router() et fusionnes via .merge() dans le
// routeur principal AVANT .fallback_service/.with_state/.layer(...). INVARIANT byte-identique : .merge()
// insere ces routes dans la MEME table matchit que des .route() inline (precedence par specificite de
// chemin, jamais par ordre d'enregistrement) ; ces sous-routeurs ne portent NI middleware NI fallback,
// donc les 6 couches globales + fallback_service + with_state posees APRES le merge les enveloppent a
// l'identique. Type d'etat pinne Router<AppState> (resolu a () au with_state). Chaque chemin vit dans
// EXACTEMENT un helper (aucune duplication -> aucun panic axum au demarrage).
fn health_system_routes() -> Router<AppState> {
    Router::<AppState>::new()
        // #51 DAY-2 OPS — endpoints d'infra STANDARD. /healthz + /readyz = UNAUTH (sondes k8s : bypass
        // host_guard + auth_guard) ; /metrics = jeton de scrape OU viewer+ (gaté dans auth_guard, bypass
        // host_guard). system/* = viewer+ (diag = admin) ; /api/bulletin GET viewer+ / POST|DELETE admin.
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_endpoint))
        .route("/api/system/metrics", get(system_metrics))
        .route("/api/system/health", get(system_health))
        .route("/api/system/diag", get(system_diag))
        .route("/api/bulletin", get(bulletin_get).post(bulletin_set).delete(bulletin_clear))
}

fn overview_search_routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/overview", get(overview))
        .route("/api/environments", get(environments)) // #2d : liste des environnements + compte (filtre X-Plume-Env)
        .route("/api/panel/:kind", get(panel))
        .route("/api/search", get(search))
}

fn alerts_coverage_routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/alerts", get(alerts))
        .route("/api/alerts/groups", get(alert_groups)) // TRIAGE GROUPÉ (viewer+) : « 1 groupe = N occurrences »
        .route("/api/alerts/ack-all", post(ack_all))
        .route("/api/alerts/:id/ack", post(ack))
        .route("/api/coverage/detections", get(coverage_detections))
        .route("/api/coverage/attack", get(coverage_attack)) // #22 (Tier-2) : matrice de couverture ATT&CK (règles+alertes par technique/tactique, blind-spots). viewer+, read-only.
}

fn compliance_routes() -> Router<AppState> {
    Router::<AppState>::new()
        // #38 CONFORMITÉ (viewer+, read-only ; GET -> route_min_role section 6 = Read) : vocab des cadres,
        // rollup de posture PAR cadre (posture SCA ingérée + règles mappées, chemin GXQL masqué #45), rapport.
        .route("/api/compliance/frameworks", get(compliance_frameworks_list))
        .route("/api/compliance/posture", get(compliance_posture))
        .route("/api/compliance/report", get(compliance_report))
}

fn query_export_routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/query", post(query))
        .route("/api/export", post(export)) // EXPORT CSV/JSON : RÉUTILISE le chemin /api/query (même compilation GXQL/admin, même run_query_ex -> même authorizer/redaction). readonly_post (viewer OK).
        .route("/api/cancel", post(cancel))
        // COMPLÉTION IDE de la barre Explore (100 % natif). GET -> route_min_role Read (section 6) : viewer+.
        // Read-only, aucune donnée sensible (noms de champs + enums fermés + noms de source déjà exposés
        // dans l'inventaire Sources). Vocabulaire issu des consts SOQL_* du cœur -> complétion ⊆ compilateur.
        .route("/api/soql/schema", get(soql_schema))
        .route("/api/soql/templates", get(soql_templates))
        // v130 LIVE VALIDATION : compile-as-you-type. POST de LECTURE (viewer+, is_readonly_post) — COMPILE
        // UNIQUEMENT via to_sql (JAMAIS d'exécution, aucun handle DB) -> renvoie {valid, error?}. Advisory.
        .route("/api/soql/validate", post(soql_validate))
}

fn datasource_routes() -> Router<AppState> {
    Router::<AppState>::new()
        // #52 plume-AS-A-DATASOURCE — surfaces de LECTURE EXTERNE (Grafana pointe SUR plume). Toutes READ-ONLY
        // (route_min_role -> Read ; readonly_post -> mutating=false), auth REQUISE (token datasource / Basic /
        // SSO / cookie via auth_guard), rate-limitées par la couche globale+per-IP. Chaque lecture hérite du
        // masque #45 + RBAC de l'appelant (soql_to_sql_masked_x / mask_named_row). Anonyme -> 401.
        .route("/api/ds/query", get(ds_query_get).post(ds_query_post)) // GXQL-over-HTTP-JSON (Infinity)
        // Prometheus-compatible read (Grafana Prometheus datasource) — sous-ensemble honnête sur `metric`.
        .route("/api/v1/query", get(prom_query).post(prom_query))
        .route("/api/v1/query_range", get(prom_query_range).post(prom_query_range))
        .route("/api/v1/label/:name/values", get(prom_label_values))
        .route("/api/v1/labels", get(prom_labels).post(prom_labels))
        .route("/api/v1/series", get(prom_series).post(prom_series))
        // Loki-query LogQL — STUB (501) + couture PLUME_LOKI_QUERY. Conception : docs/DATASOURCE.md.
        .route("/loki/api/v1/query_range", get(loki_query_range).post(loki_query_range))
}

fn dashboards_panels_routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/views", get(views_list).post(view_create))
        .route("/api/views/:id", post(view_update).delete(view_delete))
        .route("/api/dashboards", get(dash_list).post(dash_create))
        .route("/api/dashboard/:id", get(dash_get).post(dash_update).delete(dash_delete))
        .route("/api/panels", post(panel_create))
        .route("/api/panels/:id", post(panel_update).delete(panel_delete))
        .route("/api/panels/:id/data", get(panel_data))
}

fn dashboard_ergonomics_routes() -> Router<AppState> {
    Router::<AppState>::new()
        // #54 ERGONOMIE DASHBOARDS — library panels / playlists / snapshots. GET = viewer+ (section 6 Read),
        // POST/DELETE = editor+ (section 7 Write, prefixes déclarés dans route_min_role). La lecture d'un
        // snapshot PAR TOKEN (:token) est viewer+ (read-only, token-scoped) ; les données figées sont DÉJÀ
        // masquées à la capture (chemin GXQL masqué du rôle du créateur).
        .route("/api/library-panels", get(library_panels_list).post(library_panel_create))
        .route("/api/library-panels/:id", post(library_panel_update).delete(library_panel_delete))
        .route("/api/playlists", get(playlists_list).post(playlist_create))
        .route("/api/playlists/:id", post(playlist_update).delete(playlist_delete))
        .route("/api/dashboard-snapshots", get(snapshots_list).post(snapshot_create))
        .route("/api/dashboard-snapshots/:token", get(snapshot_get))
        .route("/api/dashboard-snapshots/id/:id", delete(snapshot_delete))
}

fn users_tokens_routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/users", get(users_list).post(user_create))
        .route("/api/users/:id", delete(user_delete).post(user_update))
        // JETONS (#tokens) — provisioning UI agent/HEC, pendant du CLI `plume-daemon token`. Admin-only
        // (route_min_role /api/tokens -> Admin + re-check handler). Secret CLAIR renvoyé une seule fois (POST).
        .route("/api/tokens", get(tokens_list).post(token_create))
        .route("/api/tokens/:name", delete(token_delete))
}

fn idp_auth_mfa_routes() -> Router<AppState> {
    let r = Router::<AppState>::new()
        // IdP NATIF (#44) — CRUD providers (admin-only, cf. route_min_role /api/idp -> Admin ; secret
        // write-only + redaction) + flux de login fédéré PUBLICS (auth_guard allowlist) + MFA self-service.
        .route("/api/idp/providers", get(idp_providers_list).post(idp_provider_create))
        .route("/api/idp/providers/:id", post(idp_provider_update).delete(idp_provider_delete))
        .route("/api/auth/oidc/:name/start", get(oidc_start))
        .route("/api/auth/oidc/callback", get(oidc_callback))
        // SAML 2.0 SP (#44) — SP-initié, ACS HTTP-POST. Routes PUBLIQUES (auth dans le handler : assertion
        // signée). Sans `--features saml` -> 501 (samlify non linké). CRUD providers reste /api/idp/* (admin).
        .route("/api/auth/saml/:name/start", get(saml_start))
        .route("/api/auth/saml/:name/metadata", get(saml_metadata))
        .route("/api/auth/saml/acs", post(saml_acs))
        .route("/api/auth/ldap", post(ldap_login_post))
        .route("/api/login/mfa", post(login_mfa_post))
        // #62 — PRÉFÉRENCES UTILISATEUR (self-scoped, viewer+) : GET lit / PUT remplace le blob JSON UI-only
        // de L'APPELANT (clé = identité authentifiée ; jamais un id fourni par le client). route_min_role = Read.
        .route("/api/prefs", get(prefs_get).put(prefs_put))
        // SAVED QUERIES — requêtes GXQL nommées per-user, OWNER-scoped (viewer+ self-service, cf. route_min_role
        // /api/saved-queries -> Read ; POST/PUT/DELETE restent CSRF-gardés par le middleware). GET = MES requêtes ;
        // POST crée ; PUT/DELETE /:id sont IDOR-sûrs (WHERE id=? AND owner=?). ADDITIF : table vide -> mode 0.
        .route("/api/saved-queries", get(saved_queries_list).post(saved_query_create))
        .route("/api/saved-queries/:id", put(saved_query_update).delete(saved_query_delete))
        .route("/api/mfa/status", get(mfa_status))
        .route("/api/mfa/enroll", post(mfa_enroll))
        .route("/api/mfa/verify", post(mfa_verify))
        .route("/api/mfa/disable", post(mfa_disable));
    // COUCHE IA CONSEIL (#16, feature `ai` OFF par défaut) — routes EXCLUES À LA COMPILATION sans la feature
    // (le module handler `ai` n'existe pas dans le build DÉFAUT -> mode 0 byte-identique ; pas de stub 501).
    // CRUD providers + presets + politique de redaction = ADMIN (route_min_role /api/ai -> Admin ; secret
    // write-only + redigé). NL→GXQL + status = analyste (viewer+, cf. route_min_role). Routes NON publiques
    // (auth requise) — pas d'ajout à l'allowlist auth_guard. L'ordre de `.route` n'affecte pas le matching
    // (chemins exacts distincts) : ajout en fin de chaîne via rebind cfg-gaté.
    #[cfg(feature = "ai")]
    let r = r
        .route("/api/ai/providers", get(ai_providers_list).post(ai_provider_create))
        .route("/api/ai/providers/:id", post(ai_provider_update).delete(ai_provider_delete))
        .route("/api/ai/presets", get(ai_presets_list))
        .route("/api/ai/from-preset", post(ai_from_preset))
        .route("/api/ai/redaction-policy", get(ai_redaction_policy_get).put(ai_redaction_policy_put))
        .route("/api/ai/status", get(ai_status))
        .route("/api/ai/nl2soql", post(ai_nl2soql));
    r
}

fn lookups_routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/lookups", get(lookups_list).post(lookup_upload))
        .route("/api/lookups/:name", delete(lookup_delete))
}

fn rules_parsers_processors_routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/rules", get(rules_list).post(rule_create))
        .route("/api/rules/:id", post(rule_update).delete(rule_delete))
        .route("/api/rules/:id/test", post(rule_test))
        // #1c-toggle : bascule d'activation ADMIN-only (route_min_role -> Admin + re-check require_admin),
        // fonctionne pour les overlays config.d (managed=1) via un override persistant qui survit au reboot.
        .route("/api/rules/:id/enabled", post(rule_set_enabled))
        .route("/api/parsers", get(parsers_list).post(parser_create))
        .route("/api/parsers/:id", post(parser_update).delete(parser_delete))
        .route("/api/parsers/:id/enabled", post(parser_set_enabled))
        .route("/api/parser-test", post(parser_test))
        .route("/api/parsers/reparse", post(parser_reparse))
        // #40 PROCESSEUR D'INGEST (admin-only, cf. route_min_role) : règles filtre/masque/route/échantillon.
        .route("/api/processors", get(processors_list).post(processor_create))
        .route("/api/processors/:id", post(processor_update).delete(processor_delete))
        .route("/api/processors/test", post(processor_test))
}

fn index_field_filter_routes() -> Router<AppState> {
    Router::<AppState>::new()
        // #49 INDEXES LOGIQUES NOMMÉS (admin-only, cf. route_min_role) : rétention/plafonds par env_id.
        .route("/api/index-policies", get(index_policies_list).post(index_policy_create))
        .route("/api/index-policies/:id", post(index_policy_update).delete(index_policy_delete))
        // FIELD FILTERS (#45) — CRUD masquage par champ (admin-only, cf. route_min_role /api/field-filters
        // -> Admin, GET compris : la config CONTRAINT viewer/editor). update = POST (convention du dépôt).
        .route("/api/field-filters", get(field_filters_list).post(field_filter_create))
        .route("/api/field-filters/:id", post(field_filter_update).delete(field_filter_delete))
}

fn knowledge_routes() -> Router<AppState> {
    Router::<AppState>::new()
        // KNOWLEDGE OBJECTS (#46) — CRUD alias/calc/eventtype/tag. GET = viewer+ (transparence, section 6) ;
        // POST/DELETE = editor+ (route_min_role /api/knowledge -> Write : ils façonnent la recherche de tous).
        // Auto-appliqués à la compilation GXQL suivante (Explore/panels/règles/export en héritent). ADDITIF -> mode 0 vide.
        .route("/api/knowledge", get(knowledge_list))
        .route("/api/knowledge/alias", post(alias_create))
        .route("/api/knowledge/alias/:id", delete(alias_delete))
        .route("/api/knowledge/calc", post(calc_create))
        .route("/api/knowledge/calc/:id", delete(calc_delete))
        .route("/api/knowledge/eventtype", post(eventtype_create))
        .route("/api/knowledge/eventtype/:id", delete(eventtype_delete))
        .route("/api/knowledge/tag", post(tag_create))
        .route("/api/knowledge/tag/:id", delete(tag_delete))
        // #60 — MACROS (fragment GXQL détendu par le compilateur FERMÉ) + AUTO-LOOKUPS (enrichissement auto
        // mask-aware ; GeoIP = auto-lookup BYO). Même famille que les KO -> editor+ (façonnent la recherche de
        // tous). Compile-vérifiés à la création ; auto-appliqués via `knowledge_reload`. ADDITIF -> mode 0 vide.
        .route("/api/knowledge/macro", post(macro_create))
        .route("/api/knowledge/macro/:id", delete(macro_delete))
        .route("/api/knowledge/auto-lookup", post(auto_lookup_create))
        .route("/api/knowledge/auto-lookup/:id", delete(auto_lookup_delete))
}

fn datamodels_routes() -> Router<AppState> {
    Router::<AppState>::new()
        // DATA MODELS + PIVOT + DATASETS (#47) — couche sémantique au-dessus du CIM. CRUD des modèles/objets/
        // champs/datasets = editor+ (route_min_role /api/datamodels + /api/datasets -> Write ; GET viewer+).
        // L'EXÉCUTION d'un Pivot / dataset (/api/pivot/*, /api/datasets/:id/run) = viewer+ (readonly_post) et
        // passe par le MÊME soql_to_sql_masked_x que /api/query -> masquage #45 hérité, jamais de SQL brut.
        .route("/api/datamodels", get(datamodels_list).post(model_create))
        .route("/api/datamodels/:id", delete(model_delete))
        .route("/api/datamodels/:id/objects", post(object_create))
        .route("/api/datamodels/objects/:id", delete(object_delete))
        .route("/api/datamodels/objects/:id/fields", post(field_create))
        .route("/api/datamodels/fields/:id", delete(field_delete))
        .route("/api/pivot/compile", post(pivot_compile)) // génère le GXQL (transparence report-builder ; readonly_post)
        .route("/api/pivot/run", post(pivot_run)) // exécute le Pivot via le chemin GXQL masqué (readonly_post)
        .route("/api/datasets", get(datasets_list).post(dataset_create))
        .route("/api/datasets/:id", delete(dataset_delete))
        .route("/api/datasets/:id/run", post(dataset_run)) // exécute le GXQL stocké via le chemin masqué (readonly_post)
}

fn reports_workflow_routes() -> Router<AppState> {
    Router::<AppState>::new()
        // #60 — SCHEDULED REPORTS (dataset -> notifier, masqués par run_as) : CRUD + run-now = editor+
        // (route_min_role Write ; run_as PLAFONNÉ au rôle du créateur). GET = viewer+ (section 6). Le run/tick
        // passe par le MÊME chemin masqué que /api/query. ADDITIF -> table vide = tick no-op (mode 0).
        .route("/api/scheduled-reports", get(reports_list).post(report_create))
        .route("/api/scheduled-reports/:id", delete(report_delete))
        .route("/api/scheduled-reports/:id/run", post(report_run_now))
        // #60 — WORKFLOW ACTIONS (menu contextuel) : CRUD editor+ (kind='response' re-exige admin) ; la
        // résolution (/resolve) est un POST de LECTURE (readonly_post -> viewer+) qui sanitise $field$ et ne
        // déclenche RIEN (une réponse se joue via /api/actions). ADDITIF -> table vide = aucun menu (mode 0).
        .route("/api/workflow-actions", get(workflow_actions_list).post(workflow_action_create))
        .route("/api/workflow-actions/:id", delete(workflow_action_delete))
        .route("/api/workflow-actions/:id/resolve", post(workflow_action_resolve))
}

fn detection_advanced_routes() -> Router<AppState> {
    Router::<AppState>::new()
        // #26 — cycle de vie config.d : élague les overlays orphelins (managed=1 sans fichier adossé). Admin-only.
        .route("/api/config-overlays/prune", post(config_overlays_prune))
        .route("/api/rule-test", post(rule_test_adhoc))
        // #37 — DÉTECTION AVANCÉE : corrélations de séquence (finding-groups) + baselines statistiques (UEBA).
        // GET = viewer+ (lecture posture, section 6 route_min_role) ; POST/DELETE = editor+ (Write, section 7 —
        // étapes/requêtes GXQL bornées, pas de SQL brut ni d'action destructive). ADDITIF -> mode 0 = [].
        .route("/api/correlations", get(correlations_list).post(correlation_create))
        .route("/api/correlations/:id", post(correlation_update).delete(correlation_delete))
        .route("/api/correlations/:id/test", post(correlation_test))
        .route("/api/baselines", get(baselines_list).post(baseline_create))
        .route("/api/baselines/:id", post(baseline_update).delete(baseline_delete))
        .route("/api/baselines/:id/test", post(baseline_test))
        // SLICE #7 pièce 3 — importeur Sigma (admin-only via default-deny route_min_role : hors allowlist).
        .route("/api/sigma/import", post(sigma_import))
        // SLICE #7 — import EN MASSE d'une bibliothèque Sigma (bundle multi-docs) + delta de couverture ATT&CK.
        // Admin-only (default-deny route_min_role : hors allowlist). Règles créées DÉSACTIVÉES (l'admin active).
        .route("/api/sigma/import-bulk", post(sigma_import_bulk))
}

fn fleet_integrations_freshness_routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/integrations", get(integrations))
        .route("/api/fleet", get(fleet)) // FLOTTE D'AGENTS (viewer+) : inventaire hôtes/endpoints (last-seen + statut + enrôlement). LECTURE, mode 0 inchangé.
        .route("/api/freshness", get(freshness))
}

fn ingest_routes() -> Router<AppState> {
    ingest_routes_brut()
        // LE PLAFOND DE CORPS DES ROUTES D'INGESTION EST DECIDE ICI, POUR TOUTES A LA FOIS.
        // `disable()` retire le plafond GLOBAL d'axum sur ce sous-routeur : sans lui, un
        // `PLUME_INGEST_MAX_BODY_MB` superieur a 8 serait rattrape par le plafond global, qui
        // rendrait de nouveau le message muet -> le levier ne servirait a rien (cle P4.1-o).
        .layer(axum::extract::DefaultBodyLimit::disable())
        .layer(middleware::from_fn(crate::limite_corps::borne_le_corps))
}

/// Les routes elles-memes. Separees pour que le PLAFOND ci-dessus s'applique a l'ENSEMBLE et non
/// route par route : une route ajoutee ici demain est couverte sans qu'on ait a y penser.
fn ingest_routes_brut() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/ingest", post(ingest_post))
        .route("/api/ingest/minio", post(ingest_minio_post)) // Option C étape 1 : audit_webhook MinIO natif (mTLS direct)
        .route("/api/ingest/journal", post(ingest_journal_post))
        // P-HEC — récepteur PUSH AWS Kinesis Firehose (CloudTrail/GuardDuty). Auth = clé de livraison
        // `X-Amz-Firehose-Access-Key` vérifiée DANS le handler (EXEMPTÉ d'auth_guard, comme /collector/health) ->
        // tenant + connecteur push lié, ingest-only. Body-cap `limite_corps` + rate_limit (layers) s'appliquent quand même.
        // INERTE tant qu'aucune source push n'existe (firehose_token_lookup -> None -> 403) -> mode 0 byte-identique.
        .route("/api/ingest/firehose", post(firehose_ingest_post))
        // P-HEC — récepteur PUSH GCP Pub/Sub (Cloud Audit Logs). Auth = clé de livraison en query `?token=`
        // vérifiée DANS le handler (EXEMPTÉ d'auth_guard, EXACT match) -> tenant + connecteur push lié, ingest-only.
        // Body-cap `limite_corps` + rate_limit (layers) s'appliquent. INERTE tant qu'aucune source push gcp_pubsub n'existe
        // (pubsub_token_lookup -> None -> 401) -> mode 0 byte-identique. Ack Pub/Sub : 2xx=ACK, poison=204 ack-drop.
        .route("/api/ingest/pubsub", post(pubsub_ingest_post))
        // HEC (#16) — endpoint WIRE-COMPATIBLE Splunk HTTP Event Collector (bring-your-own-forwarder).
        // /collector[/event] = ingest (auth token HEC `Splunk <tok>`/`?token=`, ingest-only, cf. auth_guard) ;
        // /health = liveness PUBLIC (exempté d'auth). ADDITIF : routes neuves -> mode 0 byte-identique.
        .route("/services/collector", post(hec_event_post))
        .route("/services/collector/event", post(hec_event_post))
        .route("/services/collector/health", get(hec_health))
        // OTLP (#41) — récepteur OpenTelemetry TRACES, protocole STANDARD OTLP/HTTP JSON. Auth = INGEST
        // (Bearer -> agent host-bound, cf. agent_bearer_path + route_min_role). INERTE par défaut : le
        // handler renvoie 404 tant que PLUME_OTLP_TRACES != 1 -> route neuve, mode 0 byte-identique.
        .route("/v1/traces", post(otlp_traces_post))
        .route("/api/mail/body", post(mail_body))
        .route("/api/metrics/prom", post(metrics_prom))
        .route("/api/metrics/write", post(metrics_write))
        .route("/loki/api/v1/push", post(loki_push))
}

fn session_routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/setup-status", get(setup_status))
        .route("/api/setup", post(setup_post))
        .route("/api/password", post(password_post))
        // FORM-LOGIN (cookie de session signé + CSRF) — 4e méthode d'auth, ADDITIVE :
        .route("/api/login", post(login_post))     // {user,pass} -> pose plume_session + plume_csrf
        .route("/api/logout", post(logout_post))   // efface les cookies
        .route("/api/me", get(me))                 // {user,role,auth_method,csrf_token} pour le SPA
}

fn notifiers_policies_silences_routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/notifiers", get(notifiers_list).post(notifier_create))
        .route("/api/notifiers/:id", post(notifier_update).delete(notifier_delete))
        .route("/api/notifiers/:id/test", post(notifier_test))
        // #53 — POLITIQUES DE NOTIFICATION (arbre de routage) + SILENCES (mute temporisé). GET = viewer+
        // (route_min_role Read) ; mutations = editor+ (allowlist éditoriale). Create/delete de silence +
        // mutations de politique LEDGERISÉS (audit_config_change). ADDITIF : routes neuves -> mode 0 = [].
        .route("/api/notification-policies", get(policies_list).post(policy_create))
        .route("/api/notification-policies/:id", post(policy_update).delete(policy_delete))
        .route("/api/silences", get(silences_list).post(silence_create))
        // P11.5-a — MODIFIER un silence (PUT/POST) : même classe de rôle (editor+), même audit fail-closed.
        .route("/api/silences/:id", put(silence_update).post(silence_update).delete(silence_delete))
}

fn connectors_destinations_routes() -> Router<AppState> {
    Router::<AppState>::new()
        // #3a — CONNECTEURS de sources externes (Defender). Admin-only (serveur) + par-tenant (req_db).
        .route("/api/connectors", get(connectors_list).post(connector_create))
        // Pont preset -> connecteur (chantier « connecteurs actifs » P1) : bibliothèque embarquée en
        // lecture-seule + instanciation 1-clic qui DÉLÈGUE à connector_create. Admin-only via le même
        // path-guard `/api/connectors` (rbac.rs). Segments STATIQUES (présent avant `/:id`).
        .route("/api/connectors/presets", get(connector_presets_list))
        .route("/api/connectors/from-preset", post(connector_from_preset))
        // P-HEC — crée une SOURCE PUSH AWS (Firehose) + minte sa clé de livraison (show-once). Admin-only
        // (require_admin + path-guard /api/connectors -> Admin). Segment STATIQUE (avant `/:id`).
        .route("/api/connectors/push-source", post(connector_push_source))
        .route("/api/connectors/:id", post(connector_update).delete(connector_delete))
        .route("/api/connectors/:id/test", post(connector_test))
        .route("/api/connectors/:id/poll", post(connector_poll)) // #3a — déclenche UN poll+ingest immédiat (admin-only, fail-safe)
        // #50 — OUTPUTS / DESTINATIONS : forward des events vers un SINK EXTERNE (data-exfil surface). Admin-only
        // (serveur + route_min_role Admin, GET compris : `config` porte le secret d'auth) + par-tenant (req_db).
        .route("/api/destinations", get(destinations_list).post(destination_create))
        .route("/api/destinations/:id", post(destination_update).delete(destination_delete))
        .route("/api/destinations/:id/flush", post(destination_flush)) // déclenche UN forward+avance immédiat (admin-only, fail-safe)
}

fn threat_intel_risk_routes() -> Router<AppState> {
    Router::<AppState>::new()
        // #23 — THREAT-INTEL : magasin d'IOC + import STIX 2.1 + coverage. Mutations admin-only (default-deny
        // route_min_role : hors allowlist éditoriale) + re-check handler ; GET coverage/list = viewer+ (donnée
        // de renseignement, pas un secret). ADDITIF : routes neuves -> mode 0 byte-identique.
        .route("/api/threat-intel/iocs", get(iocs_list).post(ioc_add))
        .route("/api/threat-intel/import", post(stix_import))
        .route("/api/threat-intel/coverage", get(ti_coverage))
        // #24 — RISK-BASED ALERTING : entités à risque + timeline par entité, servies DU ROLLUP (zéro scan
        // event). GET = viewer+ (route_min_role -> Read ; posture, pas un secret). ADDITIF -> mode 0 = [].
        .route("/api/risk/entities", get(risk_entities))
        .route("/api/risk/entity/:etype/:entity", get(risk_entity_timeline))
}

fn actions_mode_engagements_routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/actions", get(actions_list).post(action_create))
        .route("/api/actions/pending", get(actions_pending))
        .route("/api/actions/result", post(action_result))
        .route("/api/actions/:id/approve", post(action_approve))
        .route("/api/actions/:id/cancel", post(action_cancel))
        .route("/api/mode", get(mode_get).post(mode_set))
        // v75 — MODE ENGAGEMENT AUTORISÉ (pentest natif). /active = agent host-bound (seam pull enforcer) ;
        // list/get/create/end = admin-only (break-glass audité). Par-tenant (req_db). Inerte mode off.
        .route("/api/engagements", get(engagements_list).post(engagement_create))
        .route("/api/engagements/active", get(engagements_active))
        .route("/api/engagements/:id", get(engagement_get))
        .route("/api/engagements/:id/end", post(engagement_end))
}

/// BAN NATIF PLUME (chantier ② Phase 1) — API de pilotage du blocage HTTP par IP réelle. admin-only
/// (route_min_role -> Admin sur `/api/netban`) : canal appelé par admin-console (plan de contrôle).
fn netban_routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/netban", get(netban_list).post(netban_add))
        .route("/api/netban/:ip", delete(netban_delete))
}

fn governance_retention_ledger_routes() -> Router<AppState> {
    Router::<AppState>::new()
        // #1b Administration UI — rétention éditable + inventaire/métadonnées sources (admin only sauf /api/sources).
        .route("/api/retention", get(retention_settings_get).post(retention_settings_put).put(retention_settings_put))
        .route("/api/retention/preview", get(retention_preview))
        .route("/api/ledger", get(ledger_get))
        // #59 GOUVERNANCE — legal-hold (rétention-lock), export streaming du ledger (chaîne préservée) + sinks,
        // rôles composables. Toutes admin-only (route_min_role -> Admin, GET compris). Mode 0 : tables vides
        // (holds/sinks) -> inertes ; /api/roles -> 404 (control-plane requis).
        .route("/api/ledger/export", get(ledger_export_get))
        .route("/api/ledger-sinks", get(ledger_sinks_list).post(ledger_sink_create))
        .route("/api/ledger-sinks/:id", delete(ledger_sink_delete))
        .route("/api/ledger-sinks/:id/flush", post(ledger_sink_flush))
        .route("/api/legal-holds", get(legal_holds_list).post(legal_hold_create))
        .route("/api/legal-holds/:id/release", post(legal_hold_release))
        // PURGE EXPLICITE D'ÉVÉNEMENTS — deux temps. `/plan` SIMULE (aucune écriture) et rend le jeton ;
        // `/apply` RE-SIMULE, compare le jeton, inscrit au registre PUIS supprime. Les deux sont ADMIN-only
        // (préfixe `/api/purge` dans la section admin-only de `route_min_role`, GET compris) et refusent tant
        // que `PLUME_PURGE_API` n'est pas armé au déploiement. Déclarées ICI, donc automatiquement balayées
        // par les gardes de câblage du routeur (401 anonyme / 403 viewer) sans être inscrites sur une liste.
        .route("/api/purge/plan", post(purge_plan_route))
        .route("/api/purge/apply", post(purge_apply_route))
        .route("/api/roles", get(roles_list).post(role_create))
        .route("/api/roles/:name", delete(role_delete))
        // #59 SCIM 2.0 — provisioning IdP (bearer scim_token, auth DANS auth_guard, HORS session). Mode 0 :
        // control=None -> auth_guard répond 404 (inerte). Users/Groups mappent vers platform_user/grant.
        .route("/scim/v2/Users", get(scim_users_list).post(scim_user_create))
        .route("/scim/v2/Users/:id", get(scim_user_get).put(scim_user_replace).delete(scim_user_delete))
        .route("/scim/v2/Groups", get(scim_groups_list))
        .route("/scim/v2/Groups/:role", patch(scim_group_patch))
        .route("/api/sources", get(sources_inventory))
        .route("/api/sources/settings", get(source_settings_get).post(source_settings_put).put(source_settings_put))
        // P11.10-a — CE QU'ON ATTEND D'UN HÔTE : même grammaire et même gating que les sources
        // (GET viewer+, mutation editor+ via le préfixe déclaré dans `route_min_role`).
        .route("/api/hosts/settings", get(host_settings_get).post(host_settings_put).put(host_settings_put))
        // chantier whitelists→webui — panneau read-only agrégeant TOUTES les suppressions/whitelists/filtres
        // (daemon registre + collecteurs hôte + firewall). Admin only (RBAC section 3). PUT = UNIQUEMENT
        // l'exclusion display-only operator/self (le reste est read-only par conception).
        .route("/api/suppressions", get(suppressions_get).post(suppressions_put).put(suppressions_put))
}

fn playbooks_cases_routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/api/playbooks", get(playbooks_list).post(playbook_create))
        .route("/api/playbooks/:id", post(playbook_update).delete(playbook_delete))
        .route("/api/playbooks/:id/test", post(playbook_test))
        .route("/api/playbooks/:id/enabled", post(playbook_set_enabled)) // #1c-toggle : (dés)activation ADMIN-only + audité
        .route("/api/cases", get(cases_list).post(case_create))
        // #39 team case-ops — routes SPÉCIFIQUES avant /:id (axum matche l'ordre littéral) : queues + metrics.
        .route("/api/cases/queues", get(case_queues))
        .route("/api/cases/metrics", get(case_metrics))
        .route("/api/cases/:id", get(case_get).post(case_update))
        .route("/api/cases/:id/archive", post(case_archive))
        .route("/api/cases/:id/unarchive", post(case_unarchive))
        .route("/api/cases/:id/items", post(case_item_add))
        .route("/api/cases/:id/items/:item_id", delete(case_item_delete))
        // #39 — merge (soft) / unmerge (réversible) + liens (association non destructive).
        .route("/api/cases/:id/merge", post(case_merge_handler))
        .route("/api/cases/:id/unmerge", post(case_unmerge_handler))
        .route("/api/cases/:id/links", get(case_links_get).post(case_link_handler))
        .route("/api/cases/:id/links/:other", delete(case_unlink_handler))
        // #3 INCIDENTS Phase 1 — sous /api/cases/* -> héritent de l'AUTZ case (route_min_role §7 : mutation
        // editor+, §6 : lecture viewer+). Une step `response` se joue via /api/actions (admin+arm+approbation+
        // ledger) — JAMAIS ici. ADDITIF : tables vides + incident_tier NULL -> mode 0 byte-identique.
        .route("/api/cases/:id/incident", post(incident_set)) // déclare/rétrograde (tier) + type/commander : editor+
        .route("/api/cases/:id/runbooks", get(case_runbooks_get)) // recommandé (tactique dominante) + disponibles : viewer+
        .route("/api/cases/:id/runbook", post(case_runbook_attach)) // attache un runbook (instancie les steps) : editor+
        .route("/api/cases/:id/steps", get(case_steps_get)) // steps + progression : viewer+
        .route("/api/cases/:id/steps/:step_id", post(case_step_set)) // avance/skip une step (+note) : editor+
        .route("/api/cases/:id/steps/:step_id/search", get(case_step_search)) // résout le GXQL d'une step search (recompilé) : viewer+
        // #3 INCIDENTS Phase 2 — RUNBOOKS CUSTOM (bring-your-own) : CRUD ADMIN-only (route_min_role section 3 :
        // /api/runbooks -> Admin, GET compris). Managé=1 IMMUABLE en place (seulement enable/disable + clone) ;
        // CRUD complet sur custom=managed=0. Une step response reste jouée via /api/actions (INCHANGÉ). Par-tenant
        // (req_db). ADDITIF : aucun runbook custom -> liste = managés seuls, endpoints existants inchangés.
        .route("/api/runbooks", get(runbooks_admin_list).post(runbook_create)) // liste authoring / crée custom : admin
        .route("/api/runbooks/:id", get(runbook_get).post(runbook_update_handler).delete(runbook_delete)) // détail / update / delete (custom) : admin
        .route("/api/runbooks/:id/enabled", post(runbook_set_enabled)) // (dés)active (managé override + custom) : admin
        .route("/api/runbooks/:id/clone", post(runbook_clone_handler)) // clone managé/custom -> custom éditable : admin
        // #39 — SLA policies multi-niveau (CRUD) : GET viewer+, POST editor+, DELETE admin (re-check handler).
        .route("/api/sla-policies", get(sla_policies_list).post(sla_policy_upsert))
        .route("/api/sla-policies/:id", delete(sla_policy_delete))
        // #39 — CLIENT-READ API (external, read-only, tenant-scoped, masked). Cf. INVARIANT dans caseops.rs.
        .route("/api/client/cases", get(client_cases_list))
        .route("/api/client/cases/:id", get(client_case_get))
}

fn tenants_routes() -> Router<AppState> {
    Router::<AppState>::new()
        // #2c — GESTION DES TENANTS (super-admin ; grants own-tenant = tenant-admin). Path-guard dans
        // auth_guard (tenant_mgmt_gate) + re-check role/superadmin DANS chaque handler. Mode 0 : inerte.
        .route("/api/my-tenants", get(my_tenants))
        .route("/api/tenants", get(tenants_list).post(tenant_create))
        .route("/api/tenants/:id", delete(tenant_delete))
        .route("/api/tenants/:id/suspend", post(tenant_suspend))
        .route("/api/tenants/:id/unsuspend", post(tenant_unsuspend))
        .route("/api/tenants/:id/grants", get(grants_list).post(grant_set))
        .route("/api/tenants/:id/grants/:user", delete(grant_delete))
}


/// Construit la table de routage complète + les couches (auth/host/rate-limit/headers/compression/
/// catch-panic) et injecte l'état. Routes et ordre des layers IDENTIQUES.
///
/// `pub(crate)` (et non privé) DÉLIBÉRÉMENT : les gardes d'autorisation étaient toutes prouvées à la
/// COUTURE (`rbac_gate`, `route_min_role`, `is_readonly_post` — fonctions pures) et AUCUNE au CÂBLAGE. La
/// mutation a été mesurée : en RETIRANT la couche `auth_guard` de ce routeur, la suite passait 762/762 —
/// on pouvait supprimer l'authentification sans faire rougir un seul test. Les tests
/// `router_*` (tests/rbac.rs) construisent DONC ce routeur, le servent sur une socket éphémère et
/// interrogent CHAQUE route de la table : c'est la seule façon de défendre la COMPOSITION.
pub(crate) fn build_router(state: AppState, webdir: String) -> Router {
    let app = Router::<AppState>::new()
        .merge(health_system_routes())
        .merge(overview_search_routes())
        .merge(alerts_coverage_routes())
        .merge(compliance_routes())
        .merge(query_export_routes())
        .merge(datasource_routes())
        .merge(dashboards_panels_routes())
        .merge(dashboard_ergonomics_routes())
        .merge(users_tokens_routes())
        .merge(idp_auth_mfa_routes())
        .merge(lookups_routes())
        .merge(rules_parsers_processors_routes())
        .merge(index_field_filter_routes())
        .merge(knowledge_routes())
        .merge(datamodels_routes())
        .merge(reports_workflow_routes())
        .merge(detection_advanced_routes())
        .merge(fleet_integrations_freshness_routes())
        .merge(ingest_routes())
        .merge(session_routes())
        .merge(notifiers_policies_silences_routes())
        .merge(connectors_destinations_routes())
        .merge(threat_intel_risk_routes())
        .merge(actions_mode_engagements_routes())
        .merge(netban_routes())
        .merge(governance_retention_ledger_routes())
        .merge(playbooks_cases_routes())
        .merge(tenants_routes())
        // P7.8-a — ÉTIQUETAGE DE LA ROUTE POUR LA MESURE DE LA BORNE INTERACTIVE. `route_layer` (et non
        // `layer`) : la couche ne s'exécute QUE si une route a été appariée, donc APRÈS l'appariement
        // (le gabarit `MatchedPath` existe) et JAMAIS sur le `fallback_service` (fichiers statiques, qui
        // ne prennent aucun permit). Posée ICI, après tous les `.merge()` et avant le repli, elle couvre
        // toute la table matchit : aucune route ne s'étiquette elle-même, et une route ajoutée demain
        // est mesurée sans qu'on y pense. Additive : aucun en-tête, aucun statut, aucun corps changé.
        .route_layer(middleware::from_fn(semaphore_interactif::etiqueter_route))
        .fallback_service(ServeDir::new(&webdir))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state.clone(), auth_guard))
        .layer(middleware::from_fn_with_state(state.clone(), host_guard))
        // BAN NATIF PLUME (chantier ② Phase 1) — slotté ENTRE host_guard et rate_limit : l'ordre d'EXÉCUTION est
        // rate_limit -> net_ban_guard -> host_guard -> auth_guard (les layers s'exécutent du DERNIER ajouté au
        // premier). Une IP bannie prend donc un 403 AVANT toute vérif d'host/auth, sur TOUTES les routes non
        // exemptées (même non authentifiées). Sans État (cache/config globaux) -> from_fn. Fail-open + kill-switch.
        .layer(middleware::from_fn(net_ban_guard))
        .layer(middleware::from_fn_with_state(state, rate_limit))
        .layer(middleware::from_fn(security_headers))
        .layer(tower_http::compression::CompressionLayer::new()) // gzip (selon Accept-Encoding) -> JSON/JS/CSS plus legers
        .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
        // couche LA PLUS EXTERNE : tout panic (handler ou middleware) -> 500 JSON propre
        // `{"error":"erreur interne"}` au lieu d'un corps vide (« Unexpected end of JSON input »).
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(panic_to_json_response));

    app
}

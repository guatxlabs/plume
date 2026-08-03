pub(crate) mod actions;
pub(crate) mod admin_ui;
pub(crate) mod alerting; // #48/#53 : canaux (Slack/PagerDuty/générique/lookup) + suppression + politiques + silences
pub(crate) mod alerts;
pub(crate) mod cases;
pub(crate) mod caseops; // #39 team case-ops : per-assignee queues + merge/link + multi-level SLA + MTTA/MTTR + client-read API
pub(crate) mod incidents; // #3 incidents Phase 1 : élévation case->incident + runbooks managés keyés MITRE + wizard de steps (réutilise timeline/ledger/actions)
pub(crate) mod compliance; // #38 : mapping de conformité (tags de cadre par règle + rollup posture + rapport)
pub(crate) mod connectors;
pub(crate) mod dash_ergonomics; // #54 : library panels / playlists / dashboard snapshots (ergonomie)
pub(crate) mod dashboards;
pub(crate) mod panneau_resolu; // P7.13-a : LE COFFRE de la résolution « bibliothèque sinon panneau » — la porte SQL brut l'emprunte
pub(crate) mod datasource; // #52 plume-as-a-datasource : surfaces de LECTURE (GXQL-HTTP + Prometheus + stub Loki)
pub(crate) mod destinations; // #50 outputs/destinations : forward des events normalisés vers un sink externe (syslog/hec/webhook)
pub(crate) mod detection;
pub(crate) mod detection_advanced;
pub(crate) mod engagement;
pub(crate) mod field_filters; // #45 CRUD admin des field-filters (masquage par champ)
pub(crate) mod knowledge; // #46/#60 CRUD editor des knowledge objects (alias/calc/eventtype/tag + macros + auto-lookups)
pub(crate) mod datamodels; // #47 CRUD data models + objets/champs + Pivot (report-builder) + datasets
pub(crate) mod scheduled_reports; // #60 rapports planifiés (dataset -> notifier, masqués par run_as)
pub(crate) mod workflow_actions; // #60 actions de menu contextuel (navigation search/url + réponse enum-only)
pub(crate) mod fleet;
pub(crate) mod freshness;
pub(crate) mod governance; // #59 : legal-hold (rétention-lock), export streaming du ledger + sinks, rôles composables (CRUD)
pub(crate) mod purge; // PURGE EXPLICITE d'événements : surface HTTP deux temps, admin-only, FERMÉE par défaut (PLUME_PURGE_API)
pub(crate) mod idp;
#[cfg(feature = "ai")]
pub(crate) mod ai; // #16 handlers de la couche IA conseil (providers CRUD + presets + NL→GXQL + status) — feature `ai` OFF -> exclu à la compilation
pub(crate) mod index_policies; // #49 : indexes logiques nommés (rétention/plafonds par env_id)
pub(crate) mod notifiers;
pub(crate) mod overview;
pub(crate) mod playbooks;
pub(crate) mod prefs; // #62 : préférences utilisateur self-scoped (GET/PUT /api/prefs) — colonnes/favoris/réglages par vue
pub(crate) mod saved_queries; // requêtes GXQL nommées per-user, owner-scoped (CRUD /api/saved-queries) — outillage analyste
pub(crate) mod processors;
pub(crate) mod query;
pub(crate) mod soql_meta; // complétion IDE : /api/soql/schema (vocab+champs+valeurs bornées) + /api/soql/templates
pub(crate) mod search; // handler /api/search (extrait de main.rs, refactor split #25)
pub(crate) mod rba;
pub(crate) mod system; // #51 DAY-2 OPS : console d'opérabilité (healthz/readyz/metrics/diag/bulletin)
pub(crate) mod threat_intel;
pub(crate) mod tokens;
pub(crate) mod users_lookups;

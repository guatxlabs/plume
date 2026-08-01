    //! Tests de la mesure de couverture de détection (purple-team, blue-team value) : migration MITRE
    //! idempotente, propagation rule -> alert, et l'agrégation EXACTE servie par /api/coverage/detections.
    use super::*;
    use rusqlite::Connection;

include!("common.rs");
include!("rollup.rs");
include!("detection.rs");
include!("misc.rs");
include!("ingest.rs");
include!("governance.rs");
include!("engagement.rs");
include!("cases.rs");
include!("incidents.rs");
include!("connectors.rs");
include!("firehose.rs");
include!("pubsub.rs");
include!("tokens.rs");
include!("rbac.rs");
include!("tenants.rs");
include!("sec.rs");
include!("saml.rs");
include!("ai.rs"); // #16 IA conseil — tests TOUS gated `#[cfg(feature="ai")]` en interne (build DÉFAUT = no-op, miroir saml.rs)
include!("soql_completion.rs");
include!("keyset.rs");
include!("query_verify.rs"); // preuve chemin de requête sans perte silencieuse (bornes/regex/joker/combo)
include!("rollup_b2b_adverse.rs"); // B2b (merge rollup ∪ raw) — ajout tests-only
include!("rollup_parity_family.rs"); // parité route rapide == chemin brut, sur une FAMILLE dérivée (pas un cas nommé)
include!("rollup_dim_coverage.rs"); // le JUMEAU : couverture du rollup PAR DIMENSION (trou mesuré, fermeture, garde)
include!("backup_retention_adverse.rs"); // scheduler backup natif + rétention KEEP-N — tests-only
include!("netban.rs"); // chantier ② Phase 1 — ban natif HTTP (IP réelle, store net_ban, guard, API admin)
include!("purge.rs"); // PURGE EXPLICITE d'événements — refus (legal-hold/tier froid/case/FTS), caducité du jeton, registre, dérivés
include!("query_timing.rs"); // la métrique d'attente : garde SANS SEUIL (S permis >= N clients -> attente NULLE) + un seul écrivain

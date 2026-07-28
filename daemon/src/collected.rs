//! collected — INVENTAIRE DE CE QUE PLUME COLLECTE RÉELLEMENT (oracle d'inertie).
//!
//! POURQUOI CE MODULE EXISTE — SÉPARATION DE DEUX RÔLES QUI ÉTAIENT CONFONDUS.
//!
//! Deux questions DIFFÉRENTES se posent quand on importe une règle tierce (Sigma) :
//!   1. TRADUCTION — « ce nom de champ Sigma correspond à quel champ plume ? »  -> `sigma::SIGMA_FIELD_ALIAS`
//!   2. INERTIE    — « plume collecte-t-il réellement cette donnée ? »          -> CE MODULE
//!
//! Tant que les deux partagent la MÊME table, TOUT élargissement de la traduction MENT sur l'inertie :
//! `sigma_field_is_inert_extended()` commençait par `if SIGMA_FIELD_ALIAS.iter().any(..) { return false; }`,
//! si bien qu'AJOUTER UN ALIAS ÉTEIGNAIT MÉCANIQUEMENT l'avertissement d'inertie — sans qu'une seule donnée
//! nouvelle ne soit collectée. C'est du FAUX VERT : on croirait avoir gagné des détections actives, on
//! n'aurait gagné que du silence. L'oracle d'inertie se fonde DONC ici sur ce que les COLLECTEURS et l'AGENT
//! LIVRÉS écrivent réellement dans `fields.<X>`, jamais sur l'existence d'un alias.
//!
//! REPRÉSENTATION — une table `(champ, fichier qui l'émet)`. Chaque entrée est CITÉE : le fichier livré cité
//! doit contenir le nom du champ. Ce n'est pas déclaratif-sur-parole, c'est VÉRIFIÉ par la garde
//! `collected_inventory_is_backed_by_shipped_collectors` (tests/detection.rs), qui contrôle les DEUX sens :
//!
//!   (A) AUCUNE ENTRÉE FANTÔME — un champ inventorié que personne n'émet fait ROUGIR la garde. C'est le sens
//!       qui protège du faux vert : sans lui, on pourrait ré-éteindre un avertissement en inventant une ligne.
//!   (B) AUCUNE DÉRIVE SILENCIEUSE — tout champ que la garde EXTRAIT MÉCANIQUEMENT des collecteurs livrés
//!       (voir plus bas la surface d'extraction) doit figurer ici, sinon elle ROUGIT.
//!
//! MISE À JOUR QUAND UN COLLECTEUR CHANGE — c'est mécanique, pas une convention :
//!   * un collecteur commence à émettre `fields.<X>` -> la garde (B) rougit tant que `<X>` n'est pas ajouté ;
//!   * un collecteur cesse d'émettre `<X>` (ou le fichier cité disparaît) -> la garde (A) rougit tant que
//!     l'entrée n'est pas retirée -> l'avertissement d'inertie REVIENT pour les règles qui en dépendaient.
//!
//! SURFACE D'EXTRACTION MÉCANIQUE (sens B) — délibérément ÉTROITE et syntaxiquement définie :
//!   R1. tout littéral clé JSON à l'intérieur d'un objet `"fields": { … }` ou d'une affectation shell/Rust
//!       `…fields… = { … }`, dans `collectors/*.sh` et `agent/src/source/**.rs` ;
//!   R2. les overlays de parseurs livrés `config.d/parsers/*.json` : clés de `map.fields` + groupes nommés
//!       `(?P<x>…)` de `pattern` (= exactement ce que le parseur écrit dans l'event).
//! Tout le reste échappe à cette surface : champs assemblés DYNAMIQUEMENT (awk `af("k",v)` d'auditd, fragment
//! `ext` de mail.sh, `fields.insert` de l'agent Windows) et clés NON QUOTÉES du collecteur PowerShell
//! (`@{ event_id = … }`). Ils sont inventoriés à la main et restent soumis au contrôle de CITATION (A).
//! CONSÉQUENCE ASSUMÉE, STRUCTURELLE (elle découle du prédicat, pas d'une estimation) : un champ absent de
//! l'inventaire rend `plume_collects_field` faux, donc SUR-AVERTIT (une donnée collectée signalée inerte) ;
//! une incomplétude ne peut PAS produire l'inverse (déclarer vivante une donnée non collectée). L'inventaire
//! ne peut donc pas fabriquer du faux vert — seulement du bruit, dans le sens sûr.
//!
//! PÉRIMÈTRE — ce module répond pour les CHAMPS ÉTENDUS (`fields.<X>`). Les colonnes CŒUR du CIM
//! (`CIM_CORE_FIELDS`) sont l'enveloppe de tout event et sont traitées par `plume_collects_field`. L'oracle
//! de CATÉGORIE (l'avertissement `category=endpoint`) n'est PAS traité dans ce lot : il ne consulte pas la
//! table d'alias, ce n'est donc pas le rôle confondu qu'on sépare ici, et l'inventorier mécaniquement n'a
//! pas été mesuré. NON MESURÉ = non affirmé.
//!
//! L'agent Windows recopie EN PLUS, verbatim, les clés `EventData` du log Windows (`source/windows.rs`) :
//! surface OUVERTE et dépendante du déploiement, donc NON inventoriable statiquement. Ces champs restent
//! signalés inertes — sur-avertissement assumé (sens sûr), pas un silence.

use guatx_core::cim::CIM_CORE_FIELDS;

/// Champs ÉTENDUS (`fields.<X>`) que les collecteurs/parseurs/agent LIVRÉS écrivent réellement, chacun
/// avec le FICHIER LIVRÉ qui l'émet (citation vérifiée par la garde, sens A). La casse est SIGNIFICATIVE :
/// `json_extract` est sensible à la casse, un `fields.Action` ne serait pas peuplé par un collecteur qui
/// écrit `action`. NE PAS ajouter d'entrée pour « améliorer la couverture » : une entrée non émise ÉTEINT
/// un avertissement d'inertie (c'est exactement le faux vert que ce module supprime) — et la garde rougira.
/// Les entrées marquées « hors surface R1/R2 » sont celles que l'extraction mécanique ne voit pas (champ
/// assemblé dynamiquement) : elles ne sont tenues que par le contrôle de citation (sens A).
pub(crate) const COLLECTED_EXTENDED_FIELDS: &[(&str, &str)] = &[
    ("access", "minio.sh"),
    ("acct", "auditd.sh"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("action", "bans.sh"),
    ("addr", "auditd.sh"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("agent_ready", "crowdsec.sh"),
    ("atype", "auditd.sh"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("auid", "dataaccess.sh"),
    ("binding", "kube-rbac.sh"),
    ("buckets", "minio.sh"),
    ("bytes", "example-nginx.json"),
    ("cf_country", "cloudflare-firewall-events.json"),
    ("cf_rule", "cloudflare-firewall-events.json"),
    ("cf_source", "cloudflare-firewall-events.json"),
    ("cf_ua", "cloudflare-firewall-events.json"),
    ("change", "integrity.sh"),
    ("channel", "windows.rs"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("code", "kube-audit.sh"),
    ("comm", "dataaccess.sh"),
    ("count", "conntrack.sh"),
    ("decision", "kube-audit.sh"),
    ("desired", "engagement-adapter.sh"),
    ("detector", "origin-drop.sh"),
    ("dir", "conntrack.sh"),
    ("dport", "conntrack.sh"),
    ("dst_host", "conntrack.sh"),
    ("dst_port", "nft-scan-detect.json"),
    ("dur_ms", "web.sh"),
    ("ensured", "engagement-adapter.sh"),
    ("event_id", "windows.rs"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("exe", "auditd.sh"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("failcount", "engagement-adapter.sh"),
    ("family", "origin-drop.sh"),
    ("file", "yara.sh"),
    ("files_scanned", "pod-logs.sh"),
    ("fim_actor", "example-endpoint-fim.json"),
    ("fim_event", "example-endpoint-fim.json"),
    ("fim_mode", "example-endpoint-fim.json"),
    ("fim_path", "example-endpoint-fim.json"),
    ("fim_sha256", "example-endpoint-fim.json"),
    ("flags", "dataacl.sh"),
    ("group", "dataacl.sh"),
    ("http", "engagement-adapter.sh"),
    ("key", "dataaccess.sh"),
    ("kind", "integrity.sh"),
    ("lapi_ok", "crowdsec.sh"),
    ("last_alert_age_s", "crowdsec.sh"),
    ("level", "windows.rs"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("lines_scanned", "pod-logs.sh"),
    ("method", "example-nginx.json"),
    ("mode", "dataacl.sh"),
    ("name", "kube-audit.sh"),
    ("nft_fail", "engagement-adapter.sh"),
    ("ns", "kube-audit.sh"),
    ("objects", "minio.sh"),
    ("owner", "dataacl.sh"),
    ("path", "cloudflare-firewall-events.json"),
    ("policy", "minio.sh"),
    ("proc", "conntrack.sh"),
    ("proto", "conntrack.sh"),
    ("provider", "windows.rs"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("rcpt", "mail.sh"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("refused", "engagement-adapter.sh"),
    ("removed", "engagement-adapter.sh"),
    ("res", "auditd.sh"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("resource", "kube-audit.sh"),
    ("risk", "dataacl.sh"),
    ("role", "kube-rbac.sh"),
    ("router", "web.sh"),
    ("rule", "yara.sh"),
    ("scenarios_broken", "crowdsec.sh"),
    ("scenarios_loaded", "crowdsec.sh"),
    ("scope", "conntrack.sh"),
    ("score", "mail.sh"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("sender", "mail.sh"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("service", "mail.sh"),
    ("sev3_shipped", "pod-logs.sh"),
    ("sha256", "integrity.sh"),
    ("signal", "nft-scan-detect.json"),
    ("size", "mail.sh"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("skew", "engagement-adapter.sh"),
    ("sport", "origin-drop.sh"),
    ("state", "conntrack.sh"),
    ("status", "example-nginx.json"),
    ("subject", "kube-rbac.sh"),
    ("success", "auditd.sh"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("syscall", "auditd.sh"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("tags", "yara.sh"),
    ("type", "dataacl.sh"),
    ("ua", "web.sh"),
    ("uid", "auditd.sh"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("user", "dataaccess.sh"),
    ("vendor", "example-cim-firewall.json"),
    ("verb", "kube-audit.sh"),
    ("verdict", "mail.sh"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
    ("versions", "minio.sh"),
    ("vhost", "cloudflare-firewall-events.json"),
    ("virus", "mail.sh"), // hors surface R1/R2 (assemblé dynamiquement) — retenu par la CITATION seule
];

/// Plume peuple-t-il réellement ce champ plume ? = colonne CŒUR du CIM (enveloppe de TOUT event, toujours
/// présente) OU champ étendu inventorié ci-dessus. C'est L'ORACLE D'INERTIE — il ne consulte AUCUNE table
/// de traduction : ajouter un alias Sigma ne peut donc PLUS éteindre un avertissement d'inertie.
pub(crate) fn plume_collects_field(name: &str) -> bool {
    CIM_CORE_FIELDS.contains(&name) || COLLECTED_EXTENDED_FIELDS.iter().any(|(f, _)| *f == name)
}

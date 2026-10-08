//! Sources d'ingestion : l'inventaire (`GET /api/sources`), les métadonnées d'affichage par source
//! (`GET|PUT /api/sources/settings`) et — ce qui donne son sens au mot « inattendu » — la DÉRIVATION
//! d'une source ATTENDUE PAR CONSTRUCTION. Extrait de `admin_ui.rs` (P11.3-a).
//!
//! CE QUI ÉTAIT CASSÉ. Le verdict « attendu / inattendu » reposait sur une liste ÉCRITE À LA MAIN
//! (`KNOWN_EXTRA_SOURCES`, dix-sept noms) accolée aux identifiants de capteurs de `COLLECTORS`. Six
//! sources que ce dépôt LIVRE lui-même — `cloudflare-http`, `engagement-adapter`, `nft`, `origin-drop`,
//! `portprobe`, `kube-rbac`, chacune avec son collecteur sous `collectors/` et son timer sous
//! `systemd/` — n'y figuraient pas et s'affichaient « inattendu » dans l'inventaire, à côté d'un badge
//! qu'aucun éditeur ne pouvait acquitter. Une liste énumérée ne peut que vieillir ; la présente
//! dérivation est tenue par une garde qui lit les fichiers livrés.
//!
//! QUATRE DÉRIVATIONS, AUCUNE LISTE LIBRE. Une source est attendue par construction si :
//!   1. un fichier LIVRÉ l'émet (`SOURCES_LIVREES` : table MIROIR de ce que l'extracteur de la garde
//!      `sources_livrees_est_le_miroir_des_fichiers_livres` dérive des collecteurs, de l'agent, des
//!      collecteurs Rust et du démon lui-même — ajouter une entrée non dérivée ROUGIT, omettre une
//!      source dérivée ROUGIT aussi) ;
//!   2. une sonde de `COLLECTORS` l'observe (`sondes.rs`, descripteur typé) ;
//!   3. le produit l'agrège (`dim_rollup_specs` : défauts compilés + `PLUME_ROLLUP_DIMS` du déploiement) ;
//!   4. un connecteur configuré dans cette base la déclare (table `connector`).
//! Tout le reste est un SIGNAL — une source que personne n'a déclarée — jusqu'à ce qu'un éditeur la
//! marque « attendue » (`set_expected`), geste persistant, réversible, audité, et rendu dans
//! l'inventaire avec son auteur et sa date.
//!
//! CE QUE LA DÉRIVATION NE VOIT PAS : les sources DÉFINIES AU DÉPLOIEMENT — entrées scriptées de
//! `custom.sh` (`SOURCE=` dans un `.input`), sources déclaratives `[[source]]` de l'agent, identifiants du
//! journal Windows, et plus généralement toute sonde que l'exploitant installe depuis un AUTRE dépôt.
//!
//! P11.3-c — « ATTENDU » VEUT DIRE DÉCLARÉ PAR QUELQU'UN, PAS « LIVRÉ DANS CE DÉPÔT ». Les quatre
//! dérivations ci-dessus ont un plafond STRUCTUREL : elles ne connaissent que ce que ce dépôt livre,
//! observe, agrège ou configure. Une source que l'exploitant installe lui-même n'y entrera JAMAIS, et
//! la présenter indéfiniment comme un signal reviendrait à traiter comme un défaut ce qui n'est qu'une
//! absence de DÉCLARATION. Il y a donc un CINQUIÈME déclarant, aussi légitime que les autres :
//! l'exploitant. Sa déclaration est consignée (`source_settings`), elle SURVIT au redémarrage, et la
//! console dit QUI l'a faite et QUAND — avec la provenance PROPRE du geste, jamais le dernier
//! `updated_by` de la ligne (MESURÉ le 2026-08-23 : une note posée ensuite par un autre compte réécrivait
//! le nom du déclarant, et l'inventaire créditait le mauvais humain).
//!
//! LA CADENCE SUIT LA MÊME RÈGLE (cf. `sondes.rs`) : « cadence non déclarée » n'est pas un trou de
//! collecte, c'est un blanc que personne n'a comblé — et l'exploitant peut désormais le combler pour une
//! source qu'aucune sonde de ce dépôt n'observe. Une source ÉVÉNEMENTIELLE, elle, n'a pas de cadence PAR
//! NATURE : c'est une réponse, pas un trou. Ces déclarations ne pilotent que le VERDICT AFFICHÉ ; aucune
//! alerte n'en dérive (le dead-man's-switch reste celui des sondes de `COLLECTORS`).
use crate::*;
use crate::handlers::transaction_validee::{ouvrir_la_transaction_du_geste, rendre_apres_validation};

// Plafonds de longueur (caractères) des métadonnées de source éditables — bornage anti-abus avant écriture.
const LABEL_MAX: usize = 200;
const NOTE_MAX: usize = 2000;
const CAT_MAX: usize = 100;

/// BORNES d'un intervalle de cadence DÉCLARÉ PAR UN HUMAIN — les deux DÉRIVÉES, aucune choisie.
///
/// Plancher : l'intervalle le plus serré que ce dépôt livre lui-même (`COLLECTORS`). Déclarer plus serré
/// que la sonde la plus serrée du produit ferait battre le verdict « en retard » plus vite que tout ce
/// que le démon sait observer.
/// Plafond : la fenêtre de l'inventaire. Au-delà, la source n'est plus listée du tout — une cadence qu'on
/// ne pourrait jamais juger n'est pas une déclaration, c'est un piège.
fn cadence_intervalle_plancher_s() -> i64 {
    COLLECTORS.iter().map(|(_, _, i, _, _)| *i).min().unwrap_or(60)
}
fn cadence_intervalle_plafond_s() -> i64 {
    FENETRE_INVENTAIRE_S
}

/// Sources ÉMISES par un fichier LIVRÉ de ce dépôt : `(source, fichier livré qui l'émet)`. La citation est un
/// SUFFIXE de chemin qui doit désigner UN SEUL fichier de la surface balayée par la garde.
///
/// CETTE TABLE N'EST PAS TENUE À LA MAIN — elle est le MIROIR de ce que l'extracteur de la garde ramène
/// (positions de producteur reconnues : objet JSON `"source":"X"` d'un collecteur shell/python, clé `source:` nue
/// de `jq`, premier argument littéral des aides de `lib.sh` qui émettent sous un nom de source
/// (`heartbeat`, `plume_unavailable`, `plume_disabled`, `plume_lecture_echouee`, `plume_lecture_partielle`,
/// `plume_report_availability`), `INSERT INTO event(...) VALUES(?1,'X'`, `source: "X".into()`,
/// `audit_source_change(conn, "X"`, `"source": "X"` et les descripteurs `sources: &[...]` /
/// `SOURCES_JOURNAL` du démon et des collecteurs Rust). Une source est listée UNE fois, avec le fichier le
/// plus direct ; la garde exige que ce fichier la produise et qu'aucune source dérivée ne manque ici.
pub(crate) const SOURCES_LIVREES: &[(&str, &str)] = &[
    ("agent", "agent/src/main.rs"),
    ("auditd", "collectors/auditd.sh"),
    ("clamav", "collectors/clamav.sh"),
    ("cloudflare", "collectors/cloudflare.sh"),
    ("cloudflare-http", "collectors/cloudflare-http.sh"),
    ("conntrack", "collectors/conntrack.sh"),
    ("containerd", "collectors/containerd.sh"),
    ("controls", "collectors/controls.sh"),
    ("crowdsec", "collectors/crowdsec.sh"),
    ("custom", "collectors/custom.sh"),
    ("dataaccess", "collectors/dataaccess.sh"),
    ("dataacl", "collectors/dataacl.sh"),
    ("defender", "daemon/src/handlers/connectors/mod.rs"),
    ("engagement-adapter", "collectors/engagement-adapter.sh"),
    ("fail2ban", "collectors/bans.sh"),
    ("falco", "collectors/falco.sh"),
    ("firewall", "collectors/firewall.sh"),
    ("integrity", "collectors/integrity.sh"),
    ("journal", "collectors/journal.sh"),
    ("k8s", "collectors/kube-state.sh"),
    ("k8s-log", "collectors/pod-logs.sh"),
    ("kube-audit", "collectors/kube-audit.sh"),
    ("kube-rbac", "collectors/kube-rbac.sh"),
    ("mail", "collectors/mail.sh"),
    ("mail-audit", "collector-mail/src/main.rs"),
    ("minio", "collectors/minio.sh"),
    ("minio-audit", "collectors/minio-audit-relay.py"),
    ("nft", "collectors/nft.sh"),
    ("origin-drop", "collectors/origin-drop.sh"),
    ("plume-audit", "daemon/src/handlers/query.rs"),
    ("plume-auth", "daemon/src/auth.rs"),
    ("plume-authz", "daemon/src/auth.rs"),
    ("plume-config", "daemon/src/ledger.rs"),
    ("plume-disk", "daemon/src/disk.rs"),
    ("plume-engagement", "daemon/src/handlers/engagement.rs"),
    ("plume-operator-access", "daemon/src/rbac.rs"),
    ("plume-tenant-admin", "daemon/src/rbac.rs"),
    ("portprobe", "collectors/portprobe.sh"),
    ("portscan", "collectors/portscan.sh"),
    ("prom-scrape", "collectors/prom-scrape.sh"),
    ("resources", "collectors/resources.sh"),
    ("ship", "collectors/ship.sh"),
    ("sshd", "daemon/src/sondes.rs"),
    ("sshd-session", "daemon/src/sondes.rs"),
    ("su", "daemon/src/sondes.rs"),
    ("sudo", "daemon/src/sondes.rs"),
    ("suricata", "collectors/suricata.sh"),
    ("ufw", "collectors/ufw.sh"),
    ("update", "collectors/imgdrift.sh"),
    ("vuln", "collectors/vuln.sh"),
    ("web", "collectors/web.sh"),
    ("yara", "collectors/yara.sh"),
];

/// `P11.19-a` (reste 2, moitié démon) — LES FICHIERS LIVRÉS DONT LES CHAMPS ÉTENDUS ARRIVENT SOUS UNE SOURCE :
///   * le fichier qui l'émet (`SOURCES_LIVREES`), s'il est dans la surface balayée par l'extracteur ;
///   * `collectors/lib.sh`, si un capteur livré nomme littéralement cette source en premier argument d'une
///     aide du canal d'aveu (`collected::SOURCES_DU_CANAL_D_AVEU`) ;
///   * chaque overlay de parseur livré qui s'applique à cette source (`collected::SOURCE_DES_OVERLAYS`).
/// `None` quand le fichier émetteur est HORS de la surface : l'autorité ne sait rien de ce qu'il écrit, et
/// lui ajouter les seuls champs d'aveu ou d'overlay rendrait une liste partielle qui se lirait complète.
fn fichiers_de_champs_de_source(source: &str) -> Option<Vec<&'static str>> {
    let (_, fichier) = SOURCES_LIVREES.iter().find(|(s, _)| *s == source)?;
    if !crate::collected::fichier_dans_la_surface(fichier) {
        return None;
    }
    let mut fichiers = vec![*fichier];
    if crate::collected::SOURCES_DU_CANAL_D_AVEU.contains(&source) {
        fichiers.push(crate::collected::FICHIER_DU_CANAL_D_AVEU);
    }
    fichiers.extend(crate::collected::SOURCE_DES_OVERLAYS.iter().filter(|(_, s)| *s == source).map(|(f, _)| *f));
    Some(fichiers)
}

/// `P11.19-a` (reste 2, moitié démon) — LES CHAMPS ÉTENDUS QU'ÉMET UNE SOURCE, DÉRIVÉS de la jointure
/// `COLLECTED_EXTENDED_FIELDS ⨝ SOURCES_LIVREES` (la citation de l'autorité désigne, par suffixe de chemin,
/// un fichier de `fichiers_de_champs_de_source`). Aucune liste recopiée. Trois états, jamais confondus :
///   * liste non vide — les champs écrits sous la source par son fichier, le canal d'aveu et ses overlays ;
///   * liste VIDE — ce fichier est dans la surface balayée, la source ne passe par aucun canal d'aveu
///     littéral ni aucun overlay, et rien de tout cela n'écrit de champ étendu (`dataacl` n'appelle aucune
///     aide d'aveu : c'est mesuré, pas présumé) ;
///   * `None` (servi `null`) — SOURCE NON COUVERTE PAR LA JOINTURE : déclarée par l'exploitant, par un
///     connecteur, observée sans déclarant, ou émise par un fichier hors surface (agent, démon, sondes,
///     collecteur Rust). Une liste vide n'y dit JAMAIS « inconnu ».
/// LIMITE DITE : un capteur qui passe une source VARIABLE au canal d'aveu (`custom.sh`, `"$SOURCE"`) n'est
/// pas résolu ; les sources qu'il nomme ainsi ne reçoivent pas les champs d'aveu.
/// LIMITE DITE (population fixée au DÉPLOIEMENT) : la source journald de l'agent (`source/linux.rs`) écrit
/// `source = _COMM` de l'unité suivie, avec `pid`/`uid`. Si l'exploitant y suit une unité dont `_COMM` vaut
/// le nom d'une source livrée (`crowdsec`, `falco`…), `pid`/`uid` arrivent sous cette source sans figurer
/// dans sa liste : la liste dit ce que les fichiers LIVRÉS écrivent sous la source, pas ce qu'un réglage
/// d'agent y ajoute. Ces couples restent nommés à la racine (`champs_etendus_sans_source_livree`, `linux.rs`).
pub(crate) fn champs_etendus_de_source(source: &str) -> Option<Vec<&'static str>> {
    let fichiers = fichiers_de_champs_de_source(source)?;
    Some(champs_des_fichiers(&crate::collected::couples_etendus(), &fichiers))
}

/// Les champs des `couples` dont la citation désigne un des `fichiers`, TRIÉS et SANS DOUBLON. Le tri ne
/// se repose pas sur l'ordre de la table : elle est triée par champ aujourd'hui, mais rien ne l'impose, et
/// l'union de plusieurs fichiers (capteur, canal d'aveu, overlays) répète un même champ. Séparée pour
/// que le témoin le prouve sur des couples dans le désordre (`P11.19-a`, vague D : retirer le tri restait
/// vert sur la table réelle).
pub(crate) fn champs_des_fichiers(couples: &[(&'static str, &'static str)], fichiers: &[&str]) -> Vec<&'static str> {
    let mut champs: Vec<&'static str> = couples
        .iter()
        .filter(|(_, c)| fichiers.iter().any(|f| crate::collected::citation_designe(f, c)))
        .map(|(f, _)| *f)
        .collect();
    champs.sort_unstable();
    champs.dedup();
    champs
}

/// `P11.19-a` (vague D) — LES CHAMPS QUE LES PARSEURS REGEX ACTIFS DE CETTE BASE PEUVENT AJOUTER À UNE SOURCE.
/// La liste `champs_etendus` est dérivée des FICHIERS livrés ; or l'ingestion applique aussi le registre
/// regex (`parsers_apply`), dont les migrations SÈMENT des parseurs livrés dans le binaire — `user`/`uid`
/// sur `*` (toutes les sources), `jail` (fail2ban), `scenario` (crowdsec), `namespace`/`workload` (k8s)… —
/// éditables et complétés par `/api/parsers`. Servie à part, lue sur le registre RÉELLEMENT chargé pour
/// cette base (groupes nommés des parseurs visant la source ou `*`, hors colonnes cœur) : `None` (servi
/// `null`) quand aucun registre n'est chargé pour ce chemin — inconnu, pas « aucun ».
pub(crate) fn champs_des_parseurs_regex_actifs(db_path: &str, source: &str) -> Option<Vec<String>> {
    let registre = crate::parsers::parsers_cell().read();
    let parseurs = registre.get(db_path)?;
    let mut noms: Vec<String> = parseurs
        .iter()
        .filter(|(s, _)| s == "*" || s == source)
        .flat_map(|(_, re)| re.capture_names().flatten().map(str::to_string).collect::<Vec<_>>())
        .filter(|n| !guatx_core::cim::CIM_CORE_FIELDS.contains(&n.as_str()))
        .collect();
    // Les parseurs semés répètent des groupes (sshd : `user`, `rhost`, `user` sur `*`, `uid`, `rhost`) : trié, sans doublon.
    noms.sort_unstable();
    noms.dedup();
    Some(noms)
}

/// `P11.19-a` (vague D) — la source reçoit-elle des clés DYNAMIQUES (`extract_generic` : logfmt/JSON
/// aplati, jusqu'à `GENERIC_MAX_KEYS` clés par événement, `k8s-log` par défaut) ? Si oui, aucune liste
/// ne peut être close : c'est servi tel quel.
pub(crate) fn source_a_des_cles_dynamiques(source: &str) -> bool {
    crate::parsers::generic_sources().iter().any(|s| s == source)
}

/// `P11.19-a` (vague D) — CE QUE LES LISTES `champs_etendus` NE VOIENT PAS, servi à la racine de
/// l'inventaire : chaque liste est CLOSE au regard des fichiers LIVRÉS qui écrivent sous la source, pas
/// au regard de ce que le déploiement y ajoute. Une liste se lirait sinon comme l'ensemble exact des
/// champs que la source porte en base.
pub(crate) const CHAMPS_ETENDUS_NE_VOIT_PAS: &[&str] = &[
    "parseurs regex actifs (semés par les migrations ou créés par /api/parsers) : servis à part, champs_etendus_parseurs_actifs, groupes nommés que le message doit encore faire correspondre",
    "extraction générique (logfmt/JSON aplati) : clés dynamiques, champs_etendus_cles_dynamiques=true, la liste n'est alors pas close",
    "overlay de parseur déclaratif déposé par l'exploitant après déploiement : ses champs s'ajoutent à la source visée sans figurer dans aucune liste",
    "unité journald suivie par l'agent dont _COMM porte le nom d'une source livrée : l'agent poste le journal brut (/api/ingest/journal) et le démon (ingest/mod.rs, ingest_journal_lines) écrit lui-même [action, pid, uid, unit, user] sous cette source ; servies à part, champs_etendus_estampilles_par_le_demon",
    "clés fournies par l'émetteur sur les voies d'ingestion ouvertes (sac fields de /api/ingest, sac fields et objet event de HEC, attributs OTLP aplatis sous otel., étiquettes Loki d'un flux poussé sur /loki/api/v1/push, dont la source est tirée de job/service_name/service/unit/container/app/filename et peut nommer une source livrée, ingest/obs.rs) : arbitraires, aucune liste ne les borne ; les marqueurs que le démon y ajoute lui-même (sourcetype/index de HEC, champs de trace OTLP) sont servis à part, champs_etendus_estampilles_par_le_demon",
    "clé écrite par un capteur à valeur non littérale-string hors objet fields reconnu (fragment JSON à valeur numérique ou objet), ou après un commentaire de fin de ligne",
    "source passée en variable au canal d'aveu de lib.sh (custom.sh, \"$SOURCE\") : ses champs d'aveu ne sont imputés à aucune source",
    "capteur qui émet sous la source d'un AUTRE fichier livré (bans.sh : emit crowdsec, fields.action) : ses champs ne sont imputés qu'à son propre fichier, jamais à la source qu'il emprunte",
    "FIM de l'agent (agent/src/source/fim/mod.rs) : il émet sous l'id de sa source, « integrity » par défaut (agent/src/config.rs, d_fim_id) ; ses champs, nommés sous fim/mod.rs dans champs_etendus_sans_source_livree, arrivent sous integrity dès que l'exploitant active la source fim, sans figurer dans sa liste ; quand l'agent avoue cette source illisible (agent/src/lisibilite.rs, event_indisponibilite), il y écrit aussi [cause, hors_vocabulaire, verdict], hors de la liste integrity",
    "collector-mail (collector-mail/src/main.rs, hors surface balayée) émet aussi sous mail les clés [account, cause, fileid, folder, msgid, patterns, sample, scan_status] qu'aucune liste ne porte",
    "clés que le démon estampille lui-même à l'ingestion (version CIM sur chaque événement, threat-intel sur correspondance d'IOC, reclassement d'un dépôt d'unité corroboré) : servies à part, champs_etendus_estampilles_par_le_demon",
    "règle d'ingest RENAME vers fields.<clé> (/api/processors) : la clé cible s'ajoute à la source visée sans figurer dans aucune liste (MASK n'en crée aucune : il remplace la valeur d'une clé déjà présente)",
    "connecteur http-pull instancié depuis un preset livré (docs/connector-presets/, handlers/connectors/httppull.rs, httppull_map_record) : son field_map écrit ses fields.<clé> sous la source qu'il nomme ; le preset cloudflare-audit écrit ainsi sous la source livrée cloudflare [actor_type, metadata, resource_id, resource_type], hors de sa liste ; un connecteur que l'exploitant configure lui-même peut de même viser n'importe quelle source livrée",
    "normaliseur endpoint (PLUME_ENDPOINT_NORMALIZE, défaut wazuh) que l'exploitant applique à une source livrée : les champs qu'il pose (ingest/endpoint.rs) s'ajoutent à cette source sans figurer dans sa liste",
    "sources de l'agent dont l'identifiant se règle à la configuration (agent/src/config.rs : [[source]] file, command et http par name, défauts d_file_name, d_cmd_name, d_http_name ; journald, wineventlog, oslog et la source d'intégrité par id, défauts d_journald_id, d_win_id, d_mac_id, d_fim_id) : une source générique émet ses événements sous ce nom (agent/src/source/generic.rs, line_to_event), qui peut nommer une source livrée, avec pour champs les groupes nommés ou les colonnes du parseur que l'exploitant déclare (arbitraires, aucune liste ne les borne) ; quand l'agent avoue une de ces sources illisible (agent/src/main.rs, avouer_indisponibilite), il écrit sous son identifiant les clés [cause, collect_status, collector, detail, hors_vocabulaire, reason, type, verdict], qu'aucune liste ne porte à ce titre",
    "collector-syslog (hors surface balayée) émet sous la source que l'exploitant règle par PLUME_SYSLOG_SOURCE (défaut fortigate ou syslog selon le parseur, aucune des deux n'étant une source livrée ; le parseur auto range sous fortigate une trame reconnue FortiGate) : réglée sur une source livrée, celle-ci reçoit les clés [action, app, dst_ip, dst_port, log_type, observer, parse_status, product, proto, receiver_peer, src_ip, src_port, subtype, syslog_facility, syslog_host, syslog_severity, syslog_ts, url, vendor], que sa liste ne porte qu'au titre de ses propres fichiers, plus des clés dynamiques (paires brutes clé=valeur d'une ligne FortiGate, paramètres des éléments structurés de l'en-tête RFC 5424)",
];

/// `P11.19-a` (vague E) — LA PORTE DE LECTURE DES AVEUX : la route et les témoins lisent ici.
pub(crate) fn champs_etendus_ne_voit_pas() -> Vec<&'static str> {
    CHAMPS_ETENDUS_NE_VOIT_PAS.to_vec()
}

/// `P11.19-a` (vague E) — UNE FAMILLE DE CLÉS QUE LE DÉMON ÉCRIT LUI-MÊME DANS `fields` À L'INGESTION, hors de
/// tout fichier livré : aucune liste `champs_etendus` ne peut les porter, et une liste servie sans elles se
/// lirait close alors que la base les montre (mesuré : `yara` servi sans `cim`, présent sur chaque ligne).
pub(crate) struct ClesEstampillees {
    /// Les clés, triées.
    pub(crate) champs: Vec<String>,
    /// La source visée, ou `None` : toute source.
    pub(crate) source: Option<&'static str>,
    pub(crate) quand: &'static str,
    pub(crate) code: &'static str,
}

/// Les marqueurs plats et le nid que `ti_enrich` (`handlers/threat_intel.rs`) pose sur un événement dont une
/// adresse ou l'URL correspond à un IOC. Écrits ici faute de constante côté émetteur ; tenus dans les DEUX
/// sens par l'ingestion réelle (`champs_estampilles_par_le_demon.rs`) : une clé ajoutée au code ou une clé
/// fantôme ici rougit le témoin.
const CHAMPS_DE_CORRESPONDANCE_D_IOC: &[&str] = &["threat_intel", "ti_confidence", "ti_match", "ti_severity"];

/// Les marqueurs de protocole que `hec_record_to_event` (`ingest/hec.rs`) copie dans le sac quand l'enregistrement
/// HEC les porte. Écrits ici faute de constante côté émetteur ; tenus dans les deux sens par la voie HEC réelle.
const CHAMPS_DE_PROTOCOLE_HEC: &[&str] = &["index", "sourcetype"];

/// Les champs de trace que `otlp_span_to_event` (`ingest/otlp.rs`) pose sur chaque span, plus `otel.service.name`,
/// l'attribut de ressource qui ROUTE la source. Il n'est PAS toujours présent : la fusion des attributs de
/// ressource s'arrête quand le span atteint `OTLP_MAX_ATTRS_PER_SPAN` attributs. Les autres attributs `otel.*`
/// sont ceux de l'émetteur : aveu. Tenus dans les deux sens par la voie OTLP réelle.
const CHAMPS_DE_TRACE_OTLP: &[&str] = &[
    "duration_ms",
    "otel.service.name",
    "parent_span_id",
    "scope_name",
    "scope_version",
    "service",
    "span_id",
    "span_kind",
    "span_name",
    "status_message",
    "trace_id",
    "trace_status",
];

/// Le sac que `ingest_journal_lines` (`ingest/mod.rs`) écrit sur chaque ligne journald, sous la source `_COMM`.
/// Tenu dans les deux sens par la voie journald réelle.
const CHAMPS_DU_JOURNAL: &[&str] = &["action", "pid", "uid", "unit", "user"];

/// Les clés de premier niveau d'un sac `fields` sérialisé (vide si ce n'est pas un objet).
fn cles_du_sac(sac: Option<String>) -> Vec<String> {
    sac.as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Map<String, Value>>(s).ok())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

/// `P11.19-a` (vague E) — LES CLÉS ESTAMPILLÉES PAR LE DÉMON, servies à la racine de l'inventaire
/// (`champs_etendus_estampilles_par_le_demon`). DÉRIVÉES du code quand il les expose : la version CIM est lue
/// en appelant `cim_stamp` lui-même sur un sac vide, le reclassement par ses constantes (`CHAMP_MOTIF`,
/// `CHAMP_SEVERITE_ORIGINE`, `SOURCE_INTEGRITE`) ; les clés threat-intel n'ont pas de constante émettrice
/// (`CHAMPS_DE_CORRESPONDANCE_D_IOC`).
pub(crate) fn champs_estampilles_par_le_demon() -> Vec<ClesEstampillees> {
    let familles = vec![
        ClesEstampillees {
            champs: cles_du_sac(crate::cim_stamp(None)),
            source: None,
            quand: "chaque événement ingéré dont le sac est absent ou un objet JSON",
            code: "ingest/mod.rs, cim_stamp",
        },
        ClesEstampillees {
            champs: CHAMPS_DE_CORRESPONDANCE_D_IOC.iter().map(|s| s.to_string()).collect(),
            source: None,
            quand: "une adresse ou l'URL de l'événement correspond à un IOC du magasin d'indicateurs",
            code: "handlers/threat_intel.rs, ti_enrich",
        },
        ClesEstampillees {
            champs: vec![crate::CHAMP_MOTIF.to_string(), crate::CHAMP_SEVERITE_ORIGINE.to_string()],
            source: Some(crate::SOURCE_INTEGRITE),
            quand: "dépôt d'unité systemd dont le contenu est celui d'une unité livrée, dans la fenêtre d'un déploiement daté",
            code: "maj_corroboree.rs, reclasser_depot_dunite_corrobore",
        },
        ClesEstampillees {
            champs: CHAMPS_DE_PROTOCOLE_HEC.iter().map(|s| s.to_string()).collect(),
            source: None,
            quand: "événement reçu par HEC (/services/collector) dont l'enregistrement porte sourcetype ou index, sous la source qu'il nomme ; sourcetype seul, aussi, sur un enregistrement de connecteur http-pull dont la config ou le field_map donne un sourcetype sans catégorie explicite",
            code: "ingest/hec.rs, hec_record_to_event ; handlers/connectors/httppull.rs, httppull_map_record (sourcetype)",
        },
        ClesEstampillees {
            champs: CHAMPS_DE_TRACE_OTLP.iter().map(|s| s.to_string()).collect(),
            source: None,
            quand: "span reçu par OTLP (/v1/traces), sous la source que nomme son service.name",
            code: "ingest/otlp.rs, otlp_span_to_event",
        },
        ClesEstampillees {
            champs: CHAMPS_DU_JOURNAL.iter().map(|s| s.to_string()).collect(),
            source: None,
            quand: "ligne journald postée par l'agent (/api/ingest/journal), sous la source que nomme son _COMM",
            code: "ingest/mod.rs, ingest_journal_lines",
        },
    ];
    // Chaque famille vient d'une constante TRIÉE ou d'un sac `serde_json` (clés ordonnées) : aucun tri ici, le
    // témoin exige la forme servie triée et sans doublon.
    familles
}

/// La forme servie de `champs_estampilles_par_le_demon` : `sources` vaut `"*"` pour toute source.
pub(crate) fn champs_estampilles_servis() -> Value {
    Value::Array(
        champs_estampilles_par_le_demon()
            .into_iter()
            .map(|f| json!({ "champs": f.champs, "sources": f.source.unwrap_or("*"), "quand": f.quand, "code": f.code }))
            .collect(),
    )
}

/// `P11.19-a` — LES CHAMPS DE L'AUTORITÉ QU'AUCUNE LISTE DE SOURCE LIVRÉE NE PORTE : `citation -> champs`. Leur
/// fichier émetteur n'est aucun des fichiers de `fichiers_de_champs_de_source` d'une source livrée
/// (collecteur PowerShell, sources de l'agent, overlay d'une source qu'aucun fichier livré n'émet). Une source
/// livrée peut pourtant les recevoir quand le déploiement le décide : le FIM de l'agent (`fim/mod.rs`) émet sous
/// `integrity` par défaut — dit par un aveu de `CHAMPS_ETENDUS_NE_VOIT_PAS`.
/// Rendu pour que la jointure soit TOTALE : tout couple de l'autorité est servi sous une source, ou nommé ici.
pub(crate) fn champs_etendus_sans_source_livree() -> std::collections::BTreeMap<&'static str, Vec<&'static str>> {
    let portes: Vec<&'static str> =
        SOURCES_LIVREES.iter().filter_map(|(s, _)| fichiers_de_champs_de_source(s)).flatten().collect();
    couples_sans_porte(&crate::collected::couples_etendus(), &portes)
}

/// Les couples dont la citation ne désigne aucun des fichiers `portes`, regroupés par citation, chaque liste
/// TRIÉE et SANS DOUBLON. Séparée pour que le témoin le prouve sur des couples dans le désordre (`P11.19-a`,
/// vague D : la table réelle, triée par champ, laissait un tri retiré ou inversé au vert).
pub(crate) fn couples_sans_porte(
    couples: &[(&'static str, &'static str)],
    portes: &[&str],
) -> std::collections::BTreeMap<&'static str, Vec<&'static str>> {
    let mut out: std::collections::BTreeMap<&'static str, Vec<&'static str>> = std::collections::BTreeMap::new();
    for (champ, citation) in couples {
        if !portes.iter().any(|f| crate::collected::citation_designe(f, citation)) {
            out.entry(*citation).or_default().push(*champ);
        }
    }
    for v in out.values_mut() {
        v.sort_unstable();
        v.dedup();
    }
    out
}

/// QUI DÉCLARE CETTE SOURCE. Rendu tel quel dans l'inventaire (`raison_attendue`) : le lecteur voit d'où
/// vient le verdict au lieu de devoir le deviner. Les quatre premiers déclarants sont DÉRIVÉS du code et
/// de la configuration ; le cinquième est un humain de cette installation, et lui seul porte un nom et
/// une date — parce que lui seul a fait un geste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RaisonAttendue {
    /// Un fichier livré de ce dépôt l'émet.
    Livree { fichier: &'static str },
    /// Une sonde de `COLLECTORS` l'observe (identifiant du capteur).
    Sonde { capteur: &'static str },
    /// Le produit l'agrège (dimensions de rollup compilées ou déclarées au déploiement).
    Agregee,
    /// Un connecteur configuré dans cette base la déclare (identifiant du connecteur).
    Connecteur { id: i64 },
    /// L'EXPLOITANT de cette installation l'a déclarée — une source installée hors de ce dépôt est aussi
    /// voulue que les autres. `par` peut être vide sur une ligne antérieure au suivi de provenance.
    Exploitant { par: Option<String>, le: Option<i64> },
}

impl RaisonAttendue {
    /// D'OÙ vient la déclaration, en deux mots — la colonne du tableau.
    pub(crate) fn provenance(&self) -> &'static str {
        match self {
            RaisonAttendue::Livree { .. } => "ce dépôt",
            RaisonAttendue::Sonde { .. } => "le démon",
            RaisonAttendue::Agregee => "le produit",
            RaisonAttendue::Connecteur { .. } => "un connecteur",
            RaisonAttendue::Exploitant { .. } => "l'exploitant",
        }
    }
    pub(crate) fn libelle(&self) -> String {
        match self {
            RaisonAttendue::Livree { fichier } => format!("émise par un fichier livré ({fichier})"),
            RaisonAttendue::Sonde { capteur } => format!("observée par la sonde « {capteur} »"),
            RaisonAttendue::Agregee => "agrégée par le produit (dimensions de rollup)".to_string(),
            RaisonAttendue::Connecteur { id } => format!("déclarée par le connecteur #{id}"),
            RaisonAttendue::Exploitant { par, le } => format!(
                "déclarée par {}{}",
                par.clone().filter(|p| !p.is_empty()).unwrap_or_else(|| "un compte non consigné".to_string()),
                le.map(|t| format!(" (ts {t})")).unwrap_or_default()
            ),
        }
    }
}

/// LE VERDICT D'UNE SOURCE — une seule dérivation, lue par l'inventaire. Ce n'est pas « est-elle dans une
/// liste » mais « quelqu'un l'a-t-il déclarée, et qui ».
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerdictDeSource {
    /// Déclarée, et par qui.
    Declaree(RaisonAttendue),
    /// L'exploitant a RETIRÉ la déclaration (geste explicite : il veut revoir le signal), même quand la
    /// construction, elle, la déclarerait. Distinct de « personne ne l'a déclarée » : ici quelqu'un a dit non.
    Retiree { par: Option<String>, le: Option<i64> },
    /// Personne : ni ce dépôt, ni le démon, ni le produit, ni un connecteur, ni un humain.
    NonDeclaree,
}

impl VerdictDeSource {
    pub(crate) fn attendue(&self) -> bool {
        matches!(self, VerdictDeSource::Declaree(_))
    }
    pub(crate) fn libelle(&self) -> Option<String> {
        match self {
            VerdictDeSource::Declaree(r) => Some(r.libelle()),
            VerdictDeSource::Retiree { par, le } => Some(format!(
                "déclarée NON attendue par {}{}",
                par.clone().filter(|p| !p.is_empty()).unwrap_or_else(|| "un compte non consigné".to_string()),
                le.map(|t| format!(" (ts {t})")).unwrap_or_default()
            )),
            VerdictDeSource::NonDeclaree => None,
        }
    }
    pub(crate) fn provenance(&self) -> Option<&'static str> {
        match self {
            VerdictDeSource::Declaree(r) => Some(r.provenance()),
            VerdictDeSource::Retiree { .. } => Some("l'exploitant"),
            VerdictDeSource::NonDeclaree => None,
        }
    }
}

/// CE QUE PORTE LA LIGNE `source_settings` D'UNE SOURCE : deux déclarations INDÉPENDANTES (attendue,
/// cadence), chacune avec sa provenance propre, plus les métadonnées d'affichage. `updated`/`updated_by`
/// restent le DERNIER GESTE sur la ligne, quel qu'il soit — ils ne prouvent aucune des deux déclarations.
#[derive(Debug, Clone, Default)]
pub(crate) struct MarquageSource {
    pub(crate) expected: bool,
    pub(crate) expected_par: Option<String>,
    pub(crate) expected_le: Option<i64>,
    pub(crate) cadence: Option<CadenceExploitant>,
    pub(crate) label: Option<String>,
    pub(crate) note: Option<String>,
    pub(crate) category: Option<String>,
    pub(crate) updated: Option<i64>,
    pub(crate) updated_by: Option<String>,
}

/// LA DÉRIVATION DU VERDICT — fonction PURE (aucun accès base : l'appelant fournit les deux faits).
/// Le geste humain l'emporte sur la construction DANS LES DEUX SENS, et il est le seul à porter un nom.
pub(crate) fn verdict_de_source(construction: Option<RaisonAttendue>, m: Option<&MarquageSource>) -> VerdictDeSource {
    match (m, construction) {
        // Un retrait explicite : quelqu'un a dit non, même si le dépôt la livre.
        (Some(x), _) if !x.expected => VerdictDeSource::Retiree { par: x.expected_par.clone(), le: x.expected_le },
        // Déclarée par construction : la raison la plus directe l'emporte sur le geste (elle est plus
        // informative, et le geste ne fait que confirmer).
        (_, Some(r)) => VerdictDeSource::Declaree(r),
        // Reste le cinquième déclarant : l'humain.
        (Some(x), None) if x.expected => VerdictDeSource::Declaree(RaisonAttendue::Exploitant { par: x.expected_par.clone(), le: x.expected_le }),
        _ => VerdictDeSource::NonDeclaree,
    }
}

/// LES DÉCLARATIONS DE L'EXPLOITANT, lues en UNE requête (`source -> MarquageSource`). Une table absente
/// ou une colonne illisible rend une carte VIDE : l'inventaire retombe alors sur la seule construction,
/// jamais sur une erreur qui masquerait tout.
/// `P10.7-g` (lot 98) — LES DÉCLARATIONS SONT LUES OU NON LUES : une table `source_settings` illisible ne vaut plus
/// « rien de déclaré » (ce qui rendait chaque source déclarée dormante invisible et toute source « inattendue »).
pub(crate) fn marquages_de_sources_lus(conn: &Connection) -> Result<HashMap<String, MarquageSource>, rusqlite::Error> {
    let mut out: HashMap<String, MarquageSource> = HashMap::new();
    let mut s = conn.prepare(
        "SELECT source,expected,label,note,category,updated_by,updated,expected_par,expected_le,cadence,cadence_interval_s,cadence_par,cadence_le \
         FROM source_settings WHERE scope='global'",
    )?;
    let rows = s.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            MarquageSource {
                expected: r.get::<_, i64>(1)? != 0,
                label: r.get::<_, Option<String>>(2)?,
                note: r.get::<_, Option<String>>(3)?,
                category: r.get::<_, Option<String>>(4)?,
                updated_by: r.get::<_, Option<String>>(5)?,
                updated: r.get::<_, Option<i64>>(6)?,
                expected_par: r.get::<_, Option<String>>(7)?,
                expected_le: r.get::<_, Option<i64>>(8)?,
                cadence: CadenceExploitant::depuis_les_colonnes(
                    r.get::<_, Option<String>>(9)?.as_deref(),
                    r.get::<_, Option<i64>>(10)?,
                    r.get::<_, Option<String>>(11)?,
                    r.get::<_, Option<i64>>(12)?,
                ),
            },
        ))
    })?;
    for r in rows {
        let (src, m) = r?;
        out.insert(src, m);
    }
    Ok(out)
}

/// Lecture APLATIE pour la fraîcheur (`compute_freshness`), qui n'a pas encore de troisième état pour les
/// déclarations : une lecture ratée y vaut « rien de déclaré ». Reste nommé de `P10.7-g`.
pub(crate) fn marquages_de_sources(conn: &Connection) -> HashMap<String, MarquageSource> {
    marquages_de_sources_lus(conn).unwrap_or_default()
}

/// Sources déclarées par les connecteurs CONFIGURÉS dans cette base (dérivation 4). `defender` écrit sous un
/// nom fixe ; `http_pull` sous `config.source` ou, à défaut, `http:<id>` (même repli que l'ingestion) ;
/// `taxii2` n'émet pas d'événement (indicateurs), donc aucune source.
///
/// `P10.7-f` (rang 2) — REND UN `Result`. Avant : `Err(_) => Vec::new()` deux fois, puis `rows.flatten()`.
/// Les trois rendaient « aucun connecteur ne déclare quoi que ce soit », qui est un FAIT PLAUSIBLE (une
/// installation sans connecteur) et qui, ici, a une conséquence : la source retombe en `NonDeclaree`, donc
/// `unexpected: true` dans l'inventaire. Un connecteur avalé transforme une source PARFAITEMENT attendue en
/// signal — l'opérateur va enquêter sur un flux qu'il a lui-même configuré, et apprendre que les signaux de
/// cette vue ne valent rien. « Non lu » et « aucun » devaient donc cesser d'avoir la même forme.
fn sources_declarees_par_connecteurs(conn: &Connection) -> rusqlite::Result<Vec<(String, i64)>> {
    let lignes: Vec<(i64, String, String)> = conn
        .prepare("SELECT id, type, config_json FROM connector")
        .and_then(|mut s| {
            s.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()
        })?;
    Ok(lignes
        .into_iter()
        .filter_map(|(id, ctype, cfg)| match ctype.as_str() {
            "defender" => Some(("defender".to_string(), id)),
            "http_pull" => {
                let declared = serde_json::from_str::<Value>(&cfg)
                    .ok()
                    .and_then(|v| v.get("source").and_then(|x| x.as_str()).map(|s| s.trim().to_string()))
                    .filter(|s| !s.is_empty());
                Some((declared.unwrap_or_else(|| format!("http:{id}")), id))
            }
            _ => None,
        })
        .collect())
}

/// LA DÉRIVATION. `Ok(Some(raison))` si la source est attendue par construction, `Ok(None)` si aucune des
/// quatre dérivations ne la déclare, `Err` si la QUATRIÈME (les connecteurs configurés) n'a pas pu être lue.
/// L'ordre des dérivations fixe la raison RENDUE quand plusieurs s'appliquent (la plus directe d'abord) ;
/// le verdict, lui, ne dépend pas de l'ordre.
///
/// `P10.7-f` (rang 2) — POURQUOI LE `Err` REMONTE JUSQU'ICI ET PAS PLUS HAUT. Les trois premières
/// dérivations sont PURES (constantes du code, spécifications de rollup compilées) : elles ne peuvent pas
/// échouer, et elles répondent AVANT la lecture. Une source livrée par ce dépôt reste donc déclarée même
/// quand la table `connector` est illisible — c'est l'ordre des `return` qui le garantit, pas une
/// précaution. Seule une source qu'AUCUNE des trois ne couvre dépend de la lecture, et pour celle-là le
/// troisième état est le seul honnête.
pub(crate) fn raison_attendue_par_construction(conn: &Connection, source: &str) -> rusqlite::Result<Option<RaisonAttendue>> {
    if let Some((_, fichier)) = SOURCES_LIVREES.iter().find(|(s, _)| *s == source) {
        return Ok(Some(RaisonAttendue::Livree { fichier }));
    }
    for (id, _, _, sonde, _) in COLLECTORS.iter() {
        if *id == source || imputer_alerte_de_capteur(sonde).iter().any(|s| s == source) {
            return Ok(Some(RaisonAttendue::Sonde { capteur: *id }));
        }
    }
    if dim_rollup_specs().iter().any(|(s, _)| s == source) {
        return Ok(Some(RaisonAttendue::Agregee));
    }
    Ok(sources_declarees_par_connecteurs(conn)?
        .into_iter()
        .find(|(s, _)| s == source)
        .map(|(_, id)| RaisonAttendue::Connecteur { id }))
}

/// `P10.7-f` (rang 2) — CE PRÉDICAT REND UN `Result`, PARCE QU'AUCUN DES DEUX BOOLÉENS N'EST HONNÊTE ICI.
/// Son unique appelant de production est `source_settings_put`, qui s'en sert pour DEUX décisions écrites
/// dans la base : la valeur `expected` avec laquelle la ligne `source_settings` NAÎT (upsert), et la
/// SÉVÉRITÉ d'audit de `set_expected` (3 — bruyant — quand un humain reconnaît une source que rien ne
/// déclare, parce que c'est étouffer un signal). Un `true` par défaut ferait naître la ligne « attendue »
/// sans que personne ne l'ait dit — exactement le défaut que le doc-commentaire de `source_settings_put`
/// déclare avoir fermé — et ferait retomber l'audit bruyant à 2. Un `false` par défaut ferait naître la
/// ligne `expected=0`, que `verdict_de_source` lit `Retiree` : « quelqu'un a dit non », alors que personne
/// n'a rien dit. Le troisième état est donc le seul disponible, et l'appelant REFUSE le geste.
pub(crate) fn source_attendue_par_construction(conn: &Connection, source: &str) -> rusqlite::Result<bool> {
    raison_attendue_par_construction(conn, source).map(|r| r.is_some())
}

/// L'ensemble des sources attendues par construction SANS connexion (dérivations 1 à 3), pour le registre
/// d'exclusions (`daemon_excl_registry`) : ce qu'un lecteur du registre peut vérifier contre le code livré.
pub(crate) fn sources_attendues_sans_base() -> Vec<String> {
    let mut out: std::collections::BTreeSet<String> = SOURCES_LIVREES.iter().map(|(s, _)| (*s).to_string()).collect();
    for (id, _, _, sonde, _) in COLLECTORS.iter() {
        out.insert((*id).to_string());
        for s in imputer_alerte_de_capteur(sonde) {
            if s != SOURCE_INDETERMINABLE {
                out.insert(s);
            }
        }
    }
    for (s, _) in dim_rollup_specs() {
        out.insert(s.clone());
    }
    out.into_iter().collect()
}

/// `P10.7-g` (lot 98) — LE CORPS D'UN INVENTAIRE NON LU. `ok: false`, aucune source, et surtout `pipeline_fresh: null` :
/// avec la fraîcheur aplatie, une lecture ratée valait « pas frais » et la console peignait « Ingestion en panne —
/// aucune donnée reçue récemment », une panne que personne n'avait observée. La cause est nommée.
fn corps_inventaire_non_lu(now_ts: i64, cause: &str) -> Json<Value> {
    Json(json!({
        "ok": false,
        "generated": now_ts,
        "pipeline_fresh": Value::Null,
        "sources": [],
        "error": format!("inventaire NON LU : {cause} — aucune source n'est établie, et l'ingestion n'est pas dite en panne"),
    }))
}

/// GET /api/sources -> INVENTAIRE read-only dérivé (join observé x attendu x métadonnées d'affichage). Observé =
/// event_rollup GROUP BY source (budget : jamais `event`) ; attendu = `raison_attendue_par_construction` OU
/// marquage persistant (`source_settings.expected`) ; `unexpected` = SIGNAL (ni l'un ni l'autre).
/// Accessible à TOUS les rôles (pas de contrôle de mutation ici) -> PAS de guard admin (délibéré).
pub(crate) async fn sources_inventory(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let now_ts = now();
    let db_path = req_db_path(&st, &au);
    let db_path_des_parseurs = db_path.clone();
    tokio::task::spawn_blocking(move || {
        read_with_watchdog(db_path.as_str(), Json(json!({ "ok": false, "sources": [], "generated": now_ts, "error": crate::query_exec::LECTURE_NON_FAITE_SANS_CONNEXION })), move |conn| {
            let d1 = now_ts - 86400;
            let cut7 = now_ts - FENETRE_INVENTAIRE_S;
            // `P10.7-g` (lot 98) — TROIS LECTURES TYPÉES (fraîcheur du pipeline, sources observées, déclarations) : la
            // première qui échoue rend l'inventaire NON LU avec sa cause, au lieu d'une liste vide sous « ok »
            // et d'une ingestion « en panne » jamais observée.
            let pipe_fresh = match pipeline_est_frais(conn, now_ts) {
                Ok(b) => b,
                Err(e) => return corps_inventaire_non_lu(now_ts, &format!("pipeline : {e}")),
            };
            // OBSERVÉ (event_rollup uniquement : ~ms, jamais un scan de `event`). source -> (last_seen, n_24h).
            let observees: Result<Vec<(String, i64, i64)>, rusqlite::Error> = conn
                .prepare(
                    "SELECT source, COALESCE(NULLIF(MAX(last_ts),0), MAX(bucket)), SUM(CASE WHEN bucket>=?1 THEN n ELSE 0 END) \
                     FROM event_rollup WHERE bucket>=?2 AND source<>'' GROUP BY source HAVING SUM(n)>=3",
                )
                .and_then(|mut s| {
                    s.query_map(params![d1, cut7], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)))
                        .and_then(|it| it.collect())
                });
            let mut obs: std::collections::BTreeMap<String, (i64, i64)> = std::collections::BTreeMap::new();
            match observees {
                Ok(lignes) => {
                    for (src, last, n) in lignes {
                        obs.insert(src, (last, n));
                    }
                }
                Err(e) => return corps_inventaire_non_lu(now_ts, &format!("sources observées : {e}")),
            }
            // CE QUE L'EXPLOITANT A DÉCLARÉ (source_settings) : le cinquième déclarant, et la cadence des
            // sources qu'aucune sonde n'observe. Une source déclarée mais dormante reste listée (entry 0,0).
            let meta = match marquages_de_sources_lus(conn) {
                Ok(m) => m,
                Err(e) => return corps_inventaire_non_lu(now_ts, &format!("déclarations : {e}")),
            };
            for src in meta.keys() {
                obs.entry(src.clone()).or_insert((0, 0));
            }
            let mut sources: Vec<Value> = Vec::new();
            for (src, (last, n24)) in &obs {
                // `P10.7-f` (rang 2) — UNE DÉCLARATION NON LUE REND LA SOURCE « INDÉTERMINÉE », JAMAIS
                // « INATTENDUE ». `unexpected` est le SIGNAL de cette vue : c'est lui qu'un opérateur suit,
                // et le suivre pour une source que ses propres connecteurs déclarent est le plus sûr moyen
                // de lui apprendre à ne plus le suivre. Le troisième état n'est pas un `false` prudent : un
                // `false` dirait « établi : elle n'est pas inattendue », ce qui est également faux. On sert
                // donc `null` aux deux booléens dérivés, `indeterminee: true`, et une raison qui NOMME la
                // lecture manquante. Les lignes voisines, elles, restent servies : la lecture échoue par
                // source, et rendre l'inventaire entier non lu (la forme des trois lectures typées
                // ci-dessus) perdrait les verdicts qui, eux, ont bien été établis.
                let construction = raison_attendue_par_construction(conn, src);
                let m = meta.get(src);
                // UNE SEULE DÉRIVATION pour « attendue ? » et « déclarée par qui ? » (fonction pure).
                let indeterminee = construction.is_err();
                let construction = construction.unwrap_or(None);
                let verdict = verdict_de_source(construction.clone(), m);
                let expected = verdict.attendue();
                let age = now_ts - last;
                // MÊME vocabulaire que Fraîcheur : la cadence DÉCLARÉE — par la sonde du démon, sinon par
                // l'exploitant — et le statut qui en dérive (`statut_de_source`). `dormant` = ligne de
                // déclaration sans aucune donnée observée sur la fenêtre de l'inventaire.
                let cadence = cadence_du_feed("event", src, m.and_then(|x| x.cadence.as_ref()));
                let status = if *last == 0 { "dormant" } else { statut_de_source(age, pipe_fresh, Some(&cadence)) };
                // CE QU'UN HUMAIN PEUT ENCORE DÉCLARER ICI : la cadence n'est offerte que là où aucune sonde
                // n'en déclare — l'écrire ailleurs serait accepter un réglage que la préséance ignorerait.
                let cadence_declarable = cadence_declaree("event", src) == CadenceDeclaree::NonDeclaree;
                let mut entry = json!({
                    "source": src,
                    "in_collectors": construction.is_some(),
                    "raison_attendue": if indeterminee {
                        Some("déclaration par connecteur NON LUE — cette source n'est PAS classée inattendue : son verdict n'a pas pu être établi".to_string())
                    } else { verdict.libelle() },
                    "declaree_par": if indeterminee { None } else { verdict.provenance() },
                    // `P10.7-f` (rang 2) : `null` sur les deux, jamais `false` sur l'un et `true` sur l'autre.
                    "expected": if indeterminee { Value::Null } else { json!(expected) },
                    "unexpected": if indeterminee { Value::Null } else { json!(!expected) },
                    "indeterminee": indeterminee,
                    "marquage": m.map(|x| json!({ "expected": x.expected, "updated_by": x.expected_par, "updated": x.expected_le })),
                    "cadence_declarable": cadence_declarable,
                    "label": m.and_then(|x| x.label.clone()),
                    "note": m.and_then(|x| x.note.clone()),
                    "category": m.and_then(|x| x.category.clone()),
                    "updated_by": m.and_then(|x| x.updated_by.clone()),
                    "updated": m.and_then(|x| x.updated),
                    // `P4.12-b` — depuis le démarrage du processus : les événements de cette source écrits SANS adresse
                    // source, donc invisibles des règles par entité. `null` = aucun compté (pas un zéro établi).
                    "without_src_ip_since_start": crate::metrics::sans_adresse_source_de(src),
                    "last_seen": if *last == 0 { Value::Null } else { json!(last) },
                    "age_s": if *last == 0 { Value::Null } else { json!(age) },
                    "n_24h": n24,
                    "status": status,
                    // `P11.19-a` — liste, liste vide établie, ou `null` (source non couverte par la jointure).
                    "champs_etendus": champs_etendus_de_source(src),
                    // `P11.19-a` (vague D) — ce que l'ingestion ajoute hors fichiers livrés, dit à côté de la liste.
                    "champs_etendus_parseurs_actifs": champs_des_parseurs_regex_actifs(&db_path_des_parseurs, src),
                    "champs_etendus_cles_dynamiques": source_a_des_cles_dynamiques(src),
                });
                // `P10.20-g` — `Some` et non `None` : ce volume-là A ÉTÉ LU (l'inventaire refuse de conclure
                // AVANT d'arriver ici quand sa lecture échoue, cf. `corps_inventaire_non_lu`). L'option ne
                // dit pas « peut-être zéro », elle dit « peut-être pas compté » — et ici il l'a été.
                if let (Some(o), Value::Object(c)) = (entry.as_object_mut(), cadence_json(&cadence, Some(*n24))) {
                    o.extend(c);
                }
                sources.push(entry);
            }
            Json(json!({
                "ok": true,
                "generated": now_ts,
                "pipeline_fresh": pipe_fresh,
                "sources": sources,
                "champs_etendus_sans_source_livree": champs_etendus_sans_source_livree(),
                "champs_etendus_ne_voit_pas": champs_etendus_ne_voit_pas(),
                "champs_etendus_estampilles_par_le_demon": champs_estampilles_servis(),
            }))
        })
    })
    .await
    .unwrap_or_else(|_| Json(json!({ "ok": false, "sources": [], "generated": now_ts, "pipeline_fresh": Value::Null, "error": crate::query_exec::LECTURE_NON_FAITE_TACHE_INTERROMPUE })))
}

/// GET /api/sources/settings -> liste brute source_settings (métadonnées d'affichage). Lecture : tout rôle
/// (rien ici n'est secret — l'inventaire rend déjà ces colonnes) ; le path-guard RBAC applique la même règle.
pub(crate) async fn source_settings_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    // `P10.7-f` (rang 4, vague b) — LES DÉCLARATIONS DE SOURCES SONT ENTIÈRES OU AVOUÉES. Même forme, et
    // mêmes raisons, que les déclarations d'hôtes (`hotes_declares::host_settings_get`) : c'est la MÊME
    // table de déclaration à deux colonnes-clés près, et les deux routes sont voisines jusque dans leur
    // corps. Avant : `.map(|it| it.flatten().collect()).unwrap_or_default()` — une source dont la ligne ne
    // se décode pas disparaissait, et l'absence de ligne ici se lit « rien n'est déclaré pour cette
    // source » : `expected` retombe au défaut de colonne, la cadence déclarée par un humain s'évapore, et
    // la source repasse « inattendue » dans l'inventaire et la fraîcheur — sans que personne n'ait rien dit.
    // Le 500 de préparation cède la place au MÊME aveu que la ligne illisible (un seul fait, une seule
    // forme à lire), `ok` retombant à `false`.
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare(
            "SELECT source,expected,label,note,category,updated,updated_by,expected_par,expected_le,cadence,cadence_interval_s,cadence_par,cadence_le \
             FROM source_settings WHERE scope='global' ORDER BY source",
        )
        .and_then(|mut stmt| {
            stmt.query_map([], |r| {
                Ok(json!({
                    "source": r.get::<_, String>(0)?,
                    "expected": r.get::<_, i64>(1)? != 0,
                    "label": r.get::<_, Option<String>>(2)?,
                    "note": r.get::<_, Option<String>>(3)?,
                    "category": r.get::<_, Option<String>>(4)?,
                    "updated": r.get::<_, Option<i64>>(5)?,
                    "updated_by": r.get::<_, Option<String>>(6)?,
                    // La provenance PROPRE de chacune des deux déclarations — jamais le dernier geste de la ligne.
                    "expected_par": r.get::<_, Option<String>>(7)?,
                    "expected_le": r.get::<_, Option<i64>>(8)?,
                    "cadence": r.get::<_, Option<String>>(9)?,
                    "cadence_interval_s": r.get::<_, Option<i64>>(10)?,
                    "cadence_par": r.get::<_, Option<String>>(11)?,
                    "cadence_le": r.get::<_, Option<i64>>(12)?,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    match lues {
        Ok(settings) => Json(json!({ "ok": true, "settings": settings })).into_response(),
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({ "ok": false }), "settings")).into_response(),
    }
}

// `P10.25-g` — LE `COMMIT` DES MÉTADONNÉES D'UNE SOURCE EST JUGÉ : un refus rend cette cause en 503, la transaction fermée.
/// `P10.25-g` — réglages de source inchangés : le `COMMIT` de ce geste refusé.
pub(crate) const CAUSE_REGLAGES_DE_SOURCE_INCHANGES: &str = "RÉGLAGES DE SOURCE INCHANGÉS : la base n'a pas validé \
     la transaction (COMMIT refusé) et l'a annulée — la source garde ses métadonnées d'avant, et aucune trace n'est \
     écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_REGLAGES_DE_SOURCE_INCHANGES_TRANSACTION_NON_OUVERTE: &str = "RÉGLAGES DE SOURCE INCHANGÉS : \
     la base n'a pas pris la transaction du réglage (BEGIN refusé : verrou tenu, ou transaction d'un autre geste \
     pendante sur l'écrivain) — RIEN n'est écrit : la source garde ses métadonnées d'avant, et aucune trace n'est \
     écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";


/// POST|PUT /api/sources/settings {source, action, value?, interval_s?} -> DÉCLARATIONS et métadonnées
/// d'affichage par source. Enum d'actions FERMÉ : set_expected(bool) | set_cadence("continue" +
/// `interval_s` | "evenementielle" | "inconnue") | set_label(str) | set_note(str) | set_category(str) |
/// clear. EDITOR+ (déclarer une source de son propre déploiement est un geste éditorial, pas
/// d'administration) + double-audit transactionnel fail-closed. B8 : set_expected(true) sur une source que
/// RIEN ne déclare = suppression d'un SIGNAL -> sev 3 (sinon sev 2).
///
/// AUCUN champ ici ne touche l'ingest, la collecte ni les règles. `set_cadence` en particulier ne crée
/// AUCUNE alerte : il change le mot que l'inventaire et la fraîcheur affichent (« en retard » devient
/// possible pour une source qu'un humain déclare continue), pas ce que le démon surveille — le
/// dead-man's-switch reste celui des sondes de `COLLECTORS`.
///
/// LA LIGNE NAÎT AVEC LE VERDICT DE CONSTRUCTION. Poser un libellé ou une note sur une source inattendue
/// créait une ligne dont `expected` valait le DÉFAUT DE COLONNE (1) : la source passait « attendue » sans que
/// personne ne l'ait dit, et sans l'audit de sévérité 3. La ligne est désormais créée avec la valeur
/// DÉRIVÉE ; seul `set_expected` la change.
pub(crate) async fn source_settings_put(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) {
        return r;
    }
    let source = b.trimmed("source");
    if source.is_empty() {
        return (StatusCode::BAD_REQUEST, "champ 'source' requis").into_response();
    }
    if source.chars().count() > 256 {
        return (StatusCode::BAD_REQUEST, "source trop longue (max 256)").into_response();
    }
    let action = b.str_field("action");
    // ENUM FERMÉ — toute action inconnue = 400 AVANT d'ouvrir la transaction.
    if !matches!(action, "set_expected" | "set_label" | "set_note" | "set_category" | "set_cadence" | "clear") {
        return (StatusCode::BAD_REQUEST, "action inconnue (enum fermé)").into_response();
    }
    crate::req_conn!(st, au, conn);
    // `P10.7-f` (rang 2) — LE VERDICT DE CONSTRUCTION EST LU, OU LE GESTE EST REFUSÉ. Cette valeur entre
    // DANS LA BASE (l'`expected` de la ligne qui naît) et DANS L'AUDIT (la sévérité 3 de `set_expected`) :
    // une écriture faite sur un verdict non lu serait durable, signée du nom de l'exploitant, et
    // indiscernable d'une décision. Refuser est réversible — l'exploitant réessaie —, écrire ne l'est pas.
    let attendue = match source_attendue_par_construction(&conn, &source) {
        Ok(v) => v,
        Err(_) => return (
            StatusCode::SERVICE_UNAVAILABLE,
            "verdict de construction NON LU (déclarations des connecteurs) : le réglage n'est PAS écrit. \
             Une ligne créée ici naîtrait avec un « attendu » que personne n'a décidé ; réessayer.",
        ).into_response(),
    };
    // DÉCLARATION DE CADENCE : validée ENTIÈREMENT avant d'ouvrir la transaction, et REFUSÉE là où une
    // sonde du démon déclare déjà — la préséance l'ignorerait, et une écriture acceptée puis ignorée est
    // exactement la famille de défauts que cette campagne poursuit. Rend `(valeur stockée, intervalle)`.
    let cadence_a_ecrire: Option<(Option<String>, Option<i64>)> = if action == "set_cadence" {
        let nature = b.trimmed("value");
        let sonde = cadence_declaree("event", &source);
        if sonde != CadenceDeclaree::NonDeclaree {
            return (
                StatusCode::CONFLICT,
                format!(
                    "la sonde « {} » du démon déclare déjà la cadence de « {source} » : elle fait foi (elle porte aussi l'alerte « capteur muet »)",
                    sonde.capteur().unwrap_or("?")
                ),
            )
                .into_response();
        }
        match nature.as_str() {
            // « inconnue » n'est pas une nature : c'est le RETRAIT de la déclaration, et il doit exister —
            // sans lui, un humain pourrait déclarer mais jamais se dédire.
            "inconnue" => Some((None, None)),
            "evenementielle" => Some((Some("evenementielle".to_string()), None)),
            "continue" => {
                let i = b.get("interval_s").and_then(|x| x.as_i64()).unwrap_or(0);
                let (min, max) = (cadence_intervalle_plancher_s(), cadence_intervalle_plafond_s());
                if !(min..=max).contains(&i) {
                    return (StatusCode::BAD_REQUEST, format!("intervalle hors bornes ({min}..={max} s)")).into_response();
                }
                Some((Some("continue".to_string()), Some(i)))
            }
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("nature de cadence inconnue (enum fermé : {}, inconnue)", NATURES_DECLARABLES.join(", ")),
                )
                    .into_response()
            }
        }
    } else {
        None
    };
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "sources", "réglage d'une source", CAUSE_REGLAGES_DE_SOURCE_INCHANGES_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<()> = (|| {
        let ts = now();
        let (human, sev): (String, i64) = if action == "clear" {
            conn.execute("DELETE FROM source_settings WHERE scope='global' AND source=?1", params![source])?;
            ("réinitialisée (clear)".to_string(), 2)
        } else {
            // garantit la ligne (upsert, `expected` = verdict de construction à la création), puis applique le
            // champ selon l'enum fermé (col = littéral, jamais user-input).
            conn.execute(
                "INSERT INTO source_settings(scope,source,expected,updated,updated_by) VALUES('global',?1,?4,?2,?3) \
                 ON CONFLICT(scope,source) DO UPDATE SET updated=?2,updated_by=?3",
                params![source, ts, au.name.as_str(), attendue as i64],
            )?;
            match action {
                "set_expected" => {
                    let v = b.get("value").and_then(|x| x.as_bool()).unwrap_or(true);
                    // `expected_par`/`expected_le` ne bougent QUE sur ce geste : c'est ce qui fait que la
                    // console crédite le déclarant et non le dernier compte qui a touché la ligne.
                    conn.execute("UPDATE source_settings SET expected=?1,expected_par=?3,expected_le=?2,updated=?2,updated_by=?3 WHERE scope='global' AND source=?4", params![v as i64, ts, au.name.as_str(), source])?;
                    // B8 : reconnaître (expected=true) une source que rien ne déclare = étouffer un signal -> bruyant.
                    let sev = if v && !attendue { 3 } else { 2 };
                    (format!("attendu={v}"), sev)
                }
                "set_label" => {
                    let s: String = b.get("value").and_then(|x| x.as_str()).unwrap_or("").chars().take(LABEL_MAX).collect();
                    conn.execute("UPDATE source_settings SET label=?1,updated=?2,updated_by=?3 WHERE scope='global' AND source=?4", params![s, ts, au.name.as_str(), source])?;
                    (format!("label défini ({} car.)", s.chars().count()), 2)
                }
                "set_note" => {
                    let s: String = b.get("value").and_then(|x| x.as_str()).unwrap_or("").chars().take(NOTE_MAX).collect();
                    conn.execute("UPDATE source_settings SET note=?1,updated=?2,updated_by=?3 WHERE scope='global' AND source=?4", params![s, ts, au.name.as_str(), source])?;
                    ("note définie".to_string(), 2)
                }
                "set_category" => {
                    let s: String = b.get("value").and_then(|x| x.as_str()).unwrap_or("").chars().take(CAT_MAX).collect();
                    conn.execute("UPDATE source_settings SET category=?1,updated=?2,updated_by=?3 WHERE scope='global' AND source=?4", params![s, ts, au.name.as_str(), source])?;
                    (format!("catégorie définie ({} car.)", s.chars().count()), 2)
                }
                "set_cadence" => {
                    let (nature, interval) = cadence_a_ecrire.clone().expect("validée hors transaction");
                    conn.execute(
                        "UPDATE source_settings SET cadence=?1,cadence_interval_s=?2,cadence_par=?4,cadence_le=?3,updated=?3,updated_by=?4 \
                         WHERE scope='global' AND source=?5",
                        params![nature, interval, ts, au.name.as_str(), source],
                    )?;
                    let human = match (&nature, interval) {
                        (Some(n), Some(i)) if n == "continue" => format!("cadence déclarée continue, un point attendu toutes les {i} s"),
                        (Some(n), _) if n == "evenementielle" => "cadence déclarée événementielle (pas de cadence par nature)".to_string(),
                        _ => "cadence retirée (la console ne la connaît plus)".to_string(),
                    };
                    (human, 2)
                }
                _ => unreachable!("action pré-validée"),
            }
        };
        audit_config_change(
            &conn,
            "source.settings",
            &format!("{source}: {human} par {}", au.name),
            sev,
            &format!("source {source}: {human} par {}", au.name),
            &json!({ "source": source, "action": action, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => rendre_apres_validation(&conn, "sources", "réglage d'une source", CAUSE_REGLAGES_DE_SOURCE_INCHANGES, || {
            (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
        }),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : rien de persisté sans audit
            (StatusCode::INTERNAL_SERVER_ERROR, format!("échec transaction audit (aucune modification appliquée): {e}")).into_response()
        }
    }
}

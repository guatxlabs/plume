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
pub(crate) fn marquages_de_sources(conn: &Connection) -> HashMap<String, MarquageSource> {
    let mut out: HashMap<String, MarquageSource> = HashMap::new();
    let Ok(mut s) = conn.prepare(
        "SELECT source,expected,label,note,category,updated_by,updated,expected_par,expected_le,cadence,cadence_interval_s,cadence_par,cadence_le \
         FROM source_settings WHERE scope='global'",
    ) else {
        return out;
    };
    let Ok(rows) = s.query_map([], |r| {
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
    }) else {
        return out;
    };
    for (src, m) in rows.flatten() {
        out.insert(src, m);
    }
    out
}

/// Sources déclarées par les connecteurs CONFIGURÉS dans cette base (dérivation 4). `defender` écrit sous un
/// nom fixe ; `http_pull` sous `config.source` ou, à défaut, `http:<id>` (même repli que l'ingestion) ;
/// `taxii2` n'émet pas d'événement (indicateurs), donc aucune source. Table absente -> rien.
fn sources_declarees_par_connecteurs(conn: &Connection) -> Vec<(String, i64)> {
    let Ok(mut s) = conn.prepare("SELECT id, type, config_json FROM connector") else { return Vec::new() };
    let Ok(rows) = s.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))) else {
        return Vec::new();
    };
    rows.flatten()
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
        .collect()
}

/// LA DÉRIVATION. `Some(raison)` si la source est attendue par construction, `None` sinon (signal).
/// L'ordre des dérivations fixe la raison RENDUE quand plusieurs s'appliquent (la plus directe d'abord) ;
/// le verdict, lui, ne dépend pas de l'ordre.
pub(crate) fn raison_attendue_par_construction(conn: &Connection, source: &str) -> Option<RaisonAttendue> {
    if let Some((_, fichier)) = SOURCES_LIVREES.iter().find(|(s, _)| *s == source) {
        return Some(RaisonAttendue::Livree { fichier });
    }
    for (id, _, _, sonde, _) in COLLECTORS.iter() {
        if *id == source || imputer_alerte_de_capteur(sonde).iter().any(|s| s == source) {
            return Some(RaisonAttendue::Sonde { capteur: *id });
        }
    }
    if dim_rollup_specs().iter().any(|(s, _)| s == source) {
        return Some(RaisonAttendue::Agregee);
    }
    sources_declarees_par_connecteurs(conn)
        .into_iter()
        .find(|(s, _)| s == source)
        .map(|(_, id)| RaisonAttendue::Connecteur { id })
}

pub(crate) fn source_attendue_par_construction(conn: &Connection, source: &str) -> bool {
    raison_attendue_par_construction(conn, source).is_some()
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

/// GET /api/sources -> INVENTAIRE read-only dérivé (join observé x attendu x métadonnées d'affichage). Observé =
/// event_rollup GROUP BY source (budget : jamais `event`) ; attendu = `raison_attendue_par_construction` OU
/// marquage persistant (`source_settings.expected`) ; `unexpected` = SIGNAL (ni l'un ni l'autre).
/// Accessible à TOUS les rôles (pas de contrôle de mutation ici) -> PAS de guard admin (délibéré).
pub(crate) async fn sources_inventory(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    let now_ts = now();
    let db_path = req_db_path(&st, &au);
    tokio::task::spawn_blocking(move || {
        read_with_watchdog(db_path.as_str(), Json(json!({ "ok": false, "sources": [], "generated": now_ts })), move |conn| {
            let d1 = now_ts - 86400;
            let cut7 = now_ts - FENETRE_INVENTAIRE_S;
            let pipe_fresh = pipeline_is_fresh(conn, now_ts);
            // OBSERVÉ (event_rollup uniquement : ~ms, jamais un scan de `event`). source -> (last_seen, n_24h).
            let mut obs: std::collections::BTreeMap<String, (i64, i64)> = std::collections::BTreeMap::new();
            if let Ok(mut s) = conn.prepare(
                "SELECT source, COALESCE(NULLIF(MAX(last_ts),0), MAX(bucket)), SUM(CASE WHEN bucket>=?1 THEN n ELSE 0 END) \
                 FROM event_rollup WHERE bucket>=?2 AND source<>'' GROUP BY source HAVING SUM(n)>=3",
            ) {
                if let Ok(rows) = s.query_map(params![d1, cut7], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))) {
                    for (src, last, n) in rows.flatten() {
                        obs.insert(src, (last, n));
                    }
                }
            }
            // CE QUE L'EXPLOITANT A DÉCLARÉ (source_settings) : le cinquième déclarant, et la cadence des
            // sources qu'aucune sonde n'observe. Une source déclarée mais dormante reste listée (entry 0,0).
            let meta = marquages_de_sources(conn);
            for src in meta.keys() {
                obs.entry(src.clone()).or_insert((0, 0));
            }
            let mut sources: Vec<Value> = Vec::new();
            for (src, (last, n24)) in &obs {
                let construction = raison_attendue_par_construction(conn, src);
                let m = meta.get(src);
                // UNE SEULE DÉRIVATION pour « attendue ? » et « déclarée par qui ? » (fonction pure).
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
                    "raison_attendue": verdict.libelle(),
                    "declaree_par": verdict.provenance(),
                    "expected": expected,
                    "unexpected": !expected,
                    "marquage": m.map(|x| json!({ "expected": x.expected, "updated_by": x.expected_par, "updated": x.expected_le })),
                    "cadence_declarable": cadence_declarable,
                    "label": m.and_then(|x| x.label.clone()),
                    "note": m.and_then(|x| x.note.clone()),
                    "category": m.and_then(|x| x.category.clone()),
                    "updated_by": m.and_then(|x| x.updated_by.clone()),
                    "updated": m.and_then(|x| x.updated),
                    "last_seen": if *last == 0 { Value::Null } else { json!(last) },
                    "age_s": if *last == 0 { Value::Null } else { json!(age) },
                    "n_24h": n24,
                    "status": status,
                });
                if let (Some(o), Value::Object(c)) = (entry.as_object_mut(), cadence_json(&cadence, *n24)) {
                    o.extend(c);
                }
                sources.push(entry);
            }
            Json(json!({ "ok": true, "generated": now_ts, "pipeline_fresh": pipe_fresh, "sources": sources }))
        })
    })
    .await
    .unwrap_or_else(|_| Json(json!({ "ok": false, "sources": [], "generated": now_ts })))
}

/// GET /api/sources/settings -> liste brute source_settings (métadonnées d'affichage). Lecture : tout rôle
/// (rien ici n'est secret — l'inventaire rend déjà ces colonnes) ; le path-guard RBAC applique la même règle.
pub(crate) async fn source_settings_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    let mut stmt = match conn.prepare(
        "SELECT source,expected,label,note,category,updated,updated_by,expected_par,expected_le,cadence,cadence_interval_s,cadence_par,cadence_le \
         FROM source_settings WHERE scope='global' ORDER BY source",
    ) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("source_settings indisponible: {e}")).into_response(),
    };
    let settings: Vec<Value> = stmt
        .query_map([], |r| {
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
        })
        .map(|it| it.flatten().collect())
        .unwrap_or_default();
    Json(json!({ "ok": true, "settings": settings })).into_response()
}

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
    let attendue = source_attendue_par_construction(&conn, &source);
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
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "verrou base indisponible").into_response();
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
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : rien de persisté sans audit
            (StatusCode::INTERNAL_SERVER_ERROR, format!("échec transaction audit (aucune modification appliquée): {e}")).into_response()
        }
    }
}

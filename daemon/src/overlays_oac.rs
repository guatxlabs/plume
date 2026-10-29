//! #55 OBSERVABILITY-AS-CODE — overlays config.d pour les OBJETS DE CONFIG du SOC (au-delà du CONTENU de
//! détection rules/parsers/sigma déjà couvert par `overlays.rs`). MÊME contrat que `overlays.rs` :
//!   - chargé au boot APRÈS les seed_*, dans `load_overlays_dir` (un overlay GAGNE sur un seed du même nom) ;
//!   - chaque objet posé avec `managed=1` (source git) -> verrouillé en UI + prunable (#26) ;
//!   - IDEMPOTENT, keyé par `name` : re-jouer donne le MÊME état ;
//!   - VALIDÉ-OU-IGNORÉ : un objet invalide (JSON cassé, requête qui ne compile pas, type hors allowlist,
//!     matcher hors allowlist) -> WARN + skip, JAMAIS un crash du boot ;
//!   - OVERRIDE-SAFE : un overlay NE clobber JAMAIS un objet `managed=2` (ad-hoc UI) du même nom (SKIP+WARN) ;
//!     réciproquement l'UI refuse de muter/supprimer un `managed=1` (delete_managed_row_tx).
//!
//! RISQUE CLÉ — SECRETS EN GIT : un notifier/connecteur/destination porte de l'AUTH. Un overlay committé NE
//! DOIT JAMAIS contenir un secret EN CLAIR. Le secret est RÉFÉRENCÉ indirectement (`env:`/`file:`/`vault:`)
//! et RÉSOLU ICI, au chargement. Une valeur EN CLAIR dans une clé-secret -> l'objet est REJETÉ (fail-closed).
use crate::*;

// =====================================================================================================
// RÉFÉRENCES DE SECRET (indirection) — un secret n'est JAMAIS committé en clair : il est référencé.
// =====================================================================================================

/// `true` si `s` est une RÉFÉRENCE de secret résoluble (et non un secret en clair).
pub(crate) fn is_secret_ref(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("env:") || s.starts_with("file:") || s.starts_with("vault:")
}

/// Résout une référence de secret AU CHARGEMENT (fail-closed) :
///   `env:NOM`      -> variable d'environnement `NOM` (injectée hors-git : sidecar / Secret k8s).
///   `file:/chemin` -> contenu du fichier (Secret k8s monté / rendu Vault-Agent), trimmé.
///   `vault:CHEMIN` -> secret Vault SURFACÉ au loader par Vault-Agent sous la variable d'env de nom dérivé
///                     (CHEMIN sanitizé, MAJUSCULES, non-alnum -> '_') — MÊME canal que le reste de plume
///                     consomme Vault (le loader n'ouvre PAS de session Vault au boot ; cf. docs).
/// Vide -> `Ok("")` (pas de secret). Toute autre forme = SECRET EN CLAIR -> `Err` (rejet fail-closed).
pub(crate) fn resolve_secret_ref(s: &str) -> Result<String, String> {
    // PHASE 2 — dispatch via la grammaire `SecretRef` UNIFIÉE, mais SÉMANTIQUE PROPRE À L'OVERLAY (caller-4)
    // STRICTEMENT PRÉSERVÉE, VOLONTAIREMENT DIFFÉRENTE des callers 1/2/3 (NE PAS homogénéiser) :
    //   - `env:` = `env::var` BRUT (PAS de filter-vide : une var posée à "" -> `Ok("")` ; absente -> `Err`) ;
    //   - `file:` = lecture TRIMMÉE (`.trim()`), tolérante au vide (`Ok("")`) ; absent/illisible -> `Err` ;
    //   - `vault:` = ENV-PROJECTION Vault-Agent (nom d'env DÉRIVÉ du chemin), forme DISTINCTE et toujours
    //     atteignable, séparée du `vault:` HTTP (db-key/tenant/{KEY}_REF) ;
    //   - tout le reste (chemin nu / `literal:` / cleartext) -> `Err` (secret EN CLAIR interdit en git).
    // On réutilise `SecretRef` UNIQUEMENT pour classer le schéma ; les providers PURS du cœur (verbatim /
    // filter-vide) ne conviennent PAS ici (leur sémantique diffère) — on garde donc la lecture inline.
    use guatx_core::secret::SecretRef;
    let s = s.trim();
    if s.is_empty() {
        return Ok(String::new());
    }
    let r = SecretRef::parse(s);
    match r.scheme() {
        "env" => {
            let n = r.rest().trim();
            std::env::var(n)
                .map_err(|_| format!("référence secret env:{n} — variable absente de l'environnement"))
        }
        "file" => {
            let p = r.rest().trim();
            std::fs::read_to_string(p)
                .map(|t| t.trim().to_string()) // TRIM — spécifique caller-4 (PAS verbatim)
                .map_err(|e| format!("référence secret file:{p} — {e}"))
        }
        "vault" => {
            let path = r.rest().trim();
            let var: String = path
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' })
                .collect();
            std::env::var(&var).map_err(|_| {
                format!("référence secret vault:{path} — attendue projetée par Vault-Agent sous l'env {var}, absente")
            })
        }
        // Unscheme (chemin nu / cleartext) OU `literal:` (non géré en overlay) -> REJET fail-closed.
        _ => Err("valeur de secret EN CLAIR interdite dans un overlay config.d (committé en git) — référencez-la via env:/file:/vault:".into()),
    }
}

/// `true` si le NOM de clé désigne un slot porteur de SECRET (heuristique conservatrice : les clés-URL
/// `*_url`/`*_uri`/`*_endpoint` sont EXCLUES — `token_url` est un endpoint OAuth non-secret, pas un token).
pub(crate) fn oac_key_is_secretish(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    // Clés-secrets EXACTES connues (union connecteur/notifier/destination + génériques prudents).
    const EXACT: &[&str] = &[
        "secret", "secret_ref", "token", "password", "passwd", "pass", "api_key", "apikey",
        "auth_header", "routing_key", "webhook_url", "hec_token", "client_secret", "private_key",
        "bearer", "authorization",
    ];
    if EXACT.contains(&k.as_str()) {
        return true;
    }
    // Les endpoints ne sont JAMAIS des secrets (évite un faux positif sur token_url/secret_uri).
    if k.ends_with("_url") || k.ends_with("_uri") || k.ends_with("_endpoint") {
        return false;
    }
    k.ends_with("_secret")
        || k.ends_with("_token")
        || k.ends_with("_password")
        || k.ends_with("_passwd")
        || k.ends_with("_key")
        || k.ends_with("_apikey")
}

/// Parcourt (au 1er niveau) un objet de config d'overlay : toute clé-secret non vide DOIT être une RÉFÉRENCE
/// (`env:`/`file:`/`vault:`) -> résolue EN PLACE ; une valeur EN CLAIR -> `Err` (l'objet entier est REJETÉ,
/// fail-closed). Les clés non-secrètes sont laissées telles quelles.
pub(crate) fn scrub_config_secrets(cfg: &mut Value) -> Result<(), String> {
    let obj = match cfg.as_object_mut() {
        Some(o) => o,
        None => return Ok(()),
    };
    for (k, v) in obj.iter_mut() {
        if !oac_key_is_secretish(k) {
            continue;
        }
        if let Some(s) = v.as_str() {
            if s.trim().is_empty() {
                continue;
            }
            if is_secret_ref(s) {
                let resolved = resolve_secret_ref(s)?;
                *v = Value::String(resolved);
            } else {
                return Err(format!(
                    "clé secret '{k}' contient un secret EN CLAIR — référencez-la via env:/file:/vault: (jamais de secret committé en git)"
                ));
            }
        }
    }
    Ok(())
}

// =====================================================================================================
// PLAN D'UPSERT override-safe (mirroir de la discipline `managed` de overlays.rs).
// =====================================================================================================

pub(crate) enum UpsertPlan {
    Insert,
    Update(i64),
    /// ligne `managed=2` (ad-hoc UI) du même nom -> on NE clobber PAS l'objet utilisateur.
    SkipUser,
}

/// Décide de l'action pour un objet overlay keyé par `name`. `table` est un littéral fixe de l'appelant
/// (aucune injection). aucune ligne -> Insert ; managed 0/1 -> Update (l'overlay possède) ; managed 2 -> Skip.
///
/// `P10.20-b` — la décision LUE, ou l'échec du moteur : `Ok(Insert)` seulement sur une absence ÉTABLIE
/// (`QueryReturnedNoRows`). Toute autre erreur (lecture refusée, interruption, verrou, cache de schéma
/// périmé, `managed` d'un type inattendu) est RENDUE : elle ne vaut pas « le nom n'existe pas », dont
/// l'INSERT créerait un DOUBLON — `parser`, `dparser` et `playbook` n'ont aucun UNIQUE(name), et le doublon
/// porterait `managed=1` à côté de la ligne que `SkipUser` devait protéger.
pub(crate) fn plan_upsert_lu(conn: &Connection, table: &str, name: &str) -> rusqlite::Result<UpsertPlan> {
    match conn.query_row(
        &format!("SELECT id, managed FROM {table} WHERE name=?1"),
        params![name],
        |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)),
    ) {
        Ok((id, managed)) => {
            if managed == 2 {
                Ok(UpsertPlan::SkipUser)
            } else {
                Ok(UpsertPlan::Update(id))
            }
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(UpsertPlan::Insert),
        Err(e) => Err(e),
    }
}

/// `P10.20-b` — le plan d'upsert d'un objet OAC SANS UNIQUE(name) (`notifier`, `destination`, `connector`,
/// `library_panel`, `notification_policy`, `dashboard`), ou l'AVEU : une
/// lecture de l'existant NON faite ignore le fichier (compté dans `ignores` par l'appelant, WARN avec la cause
/// du moteur, jamais une valeur de cellule : le secret d'un connecteur reste hors du journal) et n'écrit rien.
/// Elle ne vaut pas « le nom n'existe pas » : `destination` et `connector` n'ont aucun UNIQUE(name), l'INSERT
/// qui suivait créait un DOUBLON (flux sortant doublé vers un puits externe, deux collectes portant le secret).
/// Même forme que `plan_de_l_overlay_ou_aveu` d'`overlays.rs`, au préfixe `[oac]` ; l'unification des deux
/// paires d'aides dans `overlays_adossement.rs` reste à faire.
fn plan_oac_ou_aveu(
    conn: &Connection,
    table: &str,
    genre: &str,
    name: &str,
    path: &std::path::Path,
) -> Option<UpsertPlan> {
    match plan_upsert_lu(conn, table, name) {
        Ok(plan) => Some(plan),
        Err(e) => {
            eprintln!("[oac] WARN {genre} '{name}' ({}) : lecture de l'existant NON faite ({e}) — overlay IGNORÉ, rien écrit", path.display());
            None
        }
    }
}

/// `P10.20-b` — le plan d'upsert d'un objet OAC dont la table porte UNIQUE(name) (`field_filter`,
/// `index_policy` : `migrate.rs`, `CREATE TABLE … field_filter`, `… index_policy`). Une lecture de l'existant NON faite est AVOUÉE (WARN avec la
/// cause du moteur) puis rend `Insert` : ici, s'abstenir ferait sauter un masquage `mask`/`deny`/`hash` (le
/// champ servi en clair jusqu'au rechargement suivant) sans rien gagner, car l'INSERT ne peut ni créer de
/// doublon ni écraser une copie UI `managed=2` — le moteur le refuse, et `compter_l_ecriture_oac` compte ce
/// refus ignoré et le dit. À ne PAS employer pour une table sans UNIQUE(name) (`plan_oac_ou_aveu`).
fn plan_oac_nom_unique_ou_aveu(
    conn: &Connection,
    table: &str,
    genre: &str,
    name: &str,
    path: &std::path::Path,
) -> UpsertPlan {
    match plan_upsert_lu(conn, table, name) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("[oac] WARN {genre} '{name}' ({}) : lecture de l'existant NON faite ({e}) — INSERT tenté, borné par UNIQUE(name)", path.display());
            UpsertPlan::Insert
        }
    }
}

/// `P10.20-b` — un objet OAC n'est compté CHARGÉ que si son écriture a posé exactement une ligne (`Ok(1)`).
/// Une écriture refusée par le moteur, ou sans effet (ligne disparue entre la lecture et l'UPDATE, trigger
/// `RAISE(IGNORE)`), est ignorée et avouée (WARN avec la cause du moteur). Pour un `field_filter`, c'est ce
/// qui empêche un masquage `mask`/`deny`/`hash` non posé d'être annoncé en place. Rend `true` sur la seule
/// écriture comptée : ce qui se trace « accepté » après coup (le SQL brut d'un panneau) ne se trace que là.
fn compter_l_ecriture_oac(
    genre: &str,
    name: &str,
    path: &std::path::Path,
    ecrit: rusqlite::Result<usize>,
    ch: &mut crate::overlays_adossement::Chargement,
) -> bool {
    match ecrit {
        Ok(1) => {
            ch.charges += 1;
            return true;
        }
        Ok(n) => {
            eprintln!("[oac] WARN {genre} '{name}' ({}) : écriture sans effet ({n} ligne posée) — overlay NON chargé", path.display());
            ch.ignores += 1;
        }
        Err(e) => {
            eprintln!("[oac] WARN {genre} '{name}' ({}) : écriture refusée ({e}) — overlay NON chargé", path.display());
            ch.ignores += 1;
        }
    }
    false
}

/// Nom d'overlay (champ `name` trimmé, non vide) ou None (WARN émis par l'appelant).
fn overlay_name(v: &Value) -> Option<String> {
    let n = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    if n.is_empty() { None } else { Some(n) }
}

// =====================================================================================================
// `P7.20-a` — LES CIBLES D'ÉGRESS D'UN OBJET, ET CE QUE LE DÉMARRAGE EN DIT.
// Une surcouche `config.d` est de la configuration : ses cibles sont inscrites APRÈS validation
// et écriture comptée (`remplacer_les_cibles_de_surcouche`, la liste de la famille REMPLACÉE à chaque chargement), et la garde d'égress les
// admet même privées sauf `PLUME_SSRF_BLOCK_PRIVATE` explicite à 1. Les mêmes fonctions disent, pour un objet stocké,
// les URL que ses envois présenteront à la garde : l'inventaire du démarrage juge exactement celles-là.
// =====================================================================================================

fn non_vide(valeur: &str) -> Option<&str> {
    let v = valeur.trim();
    if v.is_empty() { None } else { Some(v) }
}

/// Cibles d'un canal (champ, cible) : `url` d'un ntfy, webhook, email ou générique ; `config.webhook_url` d'un slack
/// (daemon/src/handlers/notifiers.rs, `notify_send`). PUR.
pub(crate) fn cibles_d_egress_d_un_canal(kind: &str, url: &str, config: &Value) -> Vec<(&'static str, crate::ledger::CibleDeConfiguration)> {
    use crate::ledger::CibleDeConfiguration;
    match kind {
        "ntfy" | "webhook" | "email" | "generic" => non_vide(url).map(|u| ("url", CibleDeConfiguration::exacte(u))).into_iter().collect(),
        "slack" => non_vide(config.str_field("webhook_url")).map(|u| ("webhook_url", CibleDeConfiguration::exacte(u))).into_iter().collect(),
        _ => Vec::new(),
    }
}

/// Cible d'une destination : l'URL d'émission que `build_wire` présente à la garde (`cible_d_emission`). PUR.
pub(crate) fn cibles_d_egress_d_une_destination(dtype: &str, endpoint: &str) -> Vec<(&'static str, crate::ledger::CibleDeConfiguration)> {
    crate::handlers::destinations::cible_d_emission(dtype, endpoint.trim())
        .and_then(|u| non_vide(&u).map(crate::ledger::CibleDeConfiguration::exacte))
        .map(|cible| ("endpoint", cible))
        .into_iter()
        .collect()
}

/// Cibles d'un connecteur : la base des pages d'un `http_pull` (`url`, ou `api_root`+`path`), suivie de ses paramètres,
/// et son point de jeton OAuth2 (`auth.token_url`) tel quel ; la base des objets d'une collection `taxii2`
/// (`api_root`/collections/…/objects/), suivie de ses paramètres — jamais la première page entière, dont `added_after`
/// change à chaque passage ; le point de jeton (`login_host`) tel quel et la base Graph (`graph_host`) suivie de ses
/// paramètres d'un `defender`. PUR.
pub(crate) fn cibles_d_egress_d_un_connecteur(ctype: &str, config: &Value) -> Vec<(&'static str, crate::ledger::CibleDeConfiguration)> {
    use crate::ledger::CibleDeConfiguration;
    match ctype {
        "http_pull" => {
            let cfg = crate::handlers::connectors::HttpPullCfg::from_json(config);
            let mut cibles = Vec::new();
            cibles.extend(non_vide(cfg.url_de_base()).map(|u| ("url", CibleDeConfiguration::suivie_d_une_requete(u))));
            cibles.extend(non_vide(cfg.url_du_jeton()).map(|u| ("auth.token_url", CibleDeConfiguration::exacte(u))));
            cibles
        }
        "taxii2" => {
            let page = crate::handlers::connectors::taxii_objects_url(&crate::handlers::connectors::TaxiiCfg::from_json(config), None, None);
            let base = page.split('?').next().unwrap_or("");
            non_vide(base).map(|b| ("api_root", CibleDeConfiguration::suivie_d_une_requete(b))).into_iter().collect()
        }
        "defender" => {
            let cfg = crate::handlers::connectors::DefenderCfg::from_json(config);
            vec![
                ("login_host", CibleDeConfiguration::exacte(&crate::handlers::connectors::defender_token_url(&cfg))),
                ("graph_host", CibleDeConfiguration::suivie_d_une_requete(&crate::handlers::connectors::graph_base_url(&cfg))),
            ]
        }
        _ => Vec::new(),
    }
}

fn sans_champ(cibles: Vec<(&'static str, crate::ledger::CibleDeConfiguration)>) -> Vec<crate::ledger::CibleDeConfiguration> {
    cibles.into_iter().map(|(_, cible)| cible).collect()
}

/// `P7.20-a` — LES CIBLES DE CONFIGURATION D'UN CANAL AU MOMENT DE SON ENVOI : celles inscrites pour lui dans la base
/// `base`, si la ligne qui émet (`kind`, `url`, `config`) les porte encore toutes et elles seules
/// (`ssrf_cibles_de_l_objet_inchange`) ; sinon aucune, et tout est de l'API.
pub(crate) fn cibles_de_configuration_d_un_canal(base: &str, id: i64, kind: &str, url: &str, config: &Value) -> Vec<crate::ledger::CibleDeConfiguration> {
    crate::ledger::ssrf_cibles_de_l_objet_inchange(base, crate::ledger::FamilleDeSurcouche::Canaux, id, &sans_champ(cibles_d_egress_d_un_canal(kind, url, config)))
}

/// `P7.20-a` — les cibles de configuration d'une destination au moment de son envoi (même règle que pour un canal).
pub(crate) fn cibles_de_configuration_d_une_destination(base: &str, id: i64, dtype: &str, endpoint: &str) -> Vec<crate::ledger::CibleDeConfiguration> {
    crate::ledger::ssrf_cibles_de_l_objet_inchange(base, crate::ledger::FamilleDeSurcouche::Destinations, id, &sans_champ(cibles_d_egress_d_une_destination(dtype, endpoint)))
}

/// `P7.20-a` — les cibles de configuration d'un connecteur au moment de son passage (même règle que pour un canal).
pub(crate) fn cibles_de_configuration_d_un_connecteur(base: &str, id: i64, ctype: &str, config: &Value) -> Vec<crate::ledger::CibleDeConfiguration> {
    crate::ledger::ssrf_cibles_de_l_objet_inchange(base, crate::ledger::FamilleDeSurcouche::Connecteurs, id, &sans_champ(cibles_d_egress_d_un_connecteur(ctype, config)))
}

/// Une cible d'égress d'un objet STOCKÉ en base, lue pour l'inventaire du démarrage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CibleStockee {
    pub(crate) genre: &'static str,
    pub(crate) famille: crate::ledger::FamilleDeSurcouche,
    pub(crate) id: i64,
    pub(crate) champ: &'static str,
    pub(crate) url: String,
    pub(crate) requete_admise: bool,
}

/// Les trois tables lues par l'inventaire : (genre dit au journal, famille de ses inscriptions, table, lecture).
const TABLES_DE_L_INVENTAIRE_D_EGRESS: [(&str, crate::ledger::FamilleDeSurcouche, &str, &str); 3] = [
    ("canal", crate::ledger::FamilleDeSurcouche::Canaux, "notifier", "SELECT id, kind, COALESCE(url,''), COALESCE(config,'') FROM notifier ORDER BY id"),
    ("destination", crate::ledger::FamilleDeSurcouche::Destinations, "destination", "SELECT id, type, COALESCE(endpoint,''), '' FROM destination ORDER BY id"),
    ("connecteur", crate::ledger::FamilleDeSurcouche::Connecteurs, "connector", "SELECT id, type, '', COALESCE(config_json,'') FROM connector ORDER BY id"),
];

/// (lignes lues, lignes illisibles) d'une lecture de l'inventaire ; Err : la lecture n'a pas été faite en entier.
fn lire_une_table_de_l_inventaire(conn: &Connection, sql: &str) -> rusqlite::Result<(Vec<(i64, String, String, String)>, u64)> {
    let mut st = conn.prepare(sql)?;
    let mut rangees = st.query([])?;
    let mut lues = Vec::new();
    let mut illisibles = 0u64;
    while let Some(r) = rangees.next()? {
        match (r.get::<_, i64>(0), r.get::<_, String>(1), r.get::<_, String>(2), r.get::<_, String>(3)) {
            (Ok(id), Ok(sorte), Ok(url), Ok(config)) => lues.push((id, sorte, url, config)),
            _ => illisibles += 1,
        }
    }
    Ok((lues, illisibles))
}

/// Les cibles d'égress des canaux, destinations et connecteurs stockés, et les aveux de ce qui n'a pas été lu (une
/// table refusée, des lignes ou une configuration illisibles) : ce qui n'est pas lu n'est pas jugé, et c'est dit.
pub(crate) fn lire_les_cibles_stockees(conn: &Connection) -> (Vec<CibleStockee>, Vec<String>) {
    let mut cibles = Vec::new();
    let mut aveux = Vec::new();
    for (genre, famille, table, sql) in TABLES_DE_L_INVENTAIRE_D_EGRESS {
        let (lues, mut illisibles) = match lire_une_table_de_l_inventaire(conn, sql) {
            Ok(lu) => lu,
            Err(e) => {
                aveux.push(format!("[ssrf] inventaire des cibles privées incomplet : la table {table} n'a pas pu être lue en entier ({e}) — aucun de ses objets n'est jugé"));
                continue;
            }
        };
        for (id, sorte, url, config_brute) in lues {
            let config: Value = if config_brute.trim().is_empty() {
                json!({})
            } else {
                match serde_json::from_str(&config_brute) {
                    Ok(v) => v,
                    Err(_) => {
                        illisibles += 1;
                        continue;
                    }
                }
            };
            let de_l_objet = match famille {
                crate::ledger::FamilleDeSurcouche::Canaux => cibles_d_egress_d_un_canal(&sorte, &url, &config),
                crate::ledger::FamilleDeSurcouche::Destinations => cibles_d_egress_d_une_destination(&sorte, &url),
                crate::ledger::FamilleDeSurcouche::Connecteurs => cibles_d_egress_d_un_connecteur(&sorte, &config),
            };
            cibles.extend(de_l_objet.into_iter().map(|(champ, cible)| CibleStockee { genre, famille, id, champ, url: cible.url, requete_admise: cible.requete_admise }));
        }
        if illisibles > 0 {
            aveux.push(format!("[ssrf] inventaire des cibles privées incomplet : {illisibles} ligne(s) de {table} illisible(s), non jugée(s)"));
        }
    }
    (cibles, aveux)
}

/// (hôte, port) d'une cible d'égress : `tcp://hôte:port` d'un syslog, sinon l'autorité d'une URL (même lecture que la
/// garde). None : la garde refuse cette forme d'office (schéma), ce n'est pas un refus d'adresse privée.
fn hote_et_port_d_une_cible_d_egress(url: &str) -> Option<(String, u16)> {
    if url.trim().to_ascii_lowercase().starts_with("tcp://") {
        crate::handlers::destinations::hote_et_port_syslog(url)
    } else {
        crate::ledger::ssrf_hote_et_port_d_une_url(url).ok()
    }
}

/// Une ligne par cible stockée que la garde d'égress refusera pour sa SEULE adresse privée — genre, id, champ et hôte,
/// jamais l'URL entière (elle peut porter un secret). L'origine de chaque cible est celle que l'envoi lui donnera : au
/// regard des seules cibles inscrites pour SON objet dans la base `base`, si la ligne les porte encore toutes
/// (`ssrf_cibles_de_l_objet_inchange`). Résout les noms : se joue hors du chemin du démarrage.
pub(crate) fn lignes_des_cibles_privees_refusees(base: &str, cibles: &[CibleStockee]) -> Vec<String> {
    let mut lignes = Vec::new();
    for c in cibles {
        let (hote, port) = match hote_et_port_d_une_cible_d_egress(&c.url) {
            Some(hp) => hp,
            None => continue, // refusée d'office par la garde, pour son schéma : hors de cet inventaire
        };
        let de_la_ligne: Vec<crate::ledger::CibleDeConfiguration> = cibles
            .iter()
            .filter(|autre| autre.famille == c.famille && autre.id == c.id)
            .map(|autre| crate::ledger::CibleDeConfiguration { url: autre.url.clone(), requete_admise: autre.requete_admise })
            .collect();
        let inscrites = crate::ledger::ssrf_cibles_de_l_objet_inchange(base, c.famille, c.id, &de_la_ligne);
        if crate::ledger::hote_refuse_pour_sa_seule_adresse_privee(&hote, port, crate::ledger::origine_de_l_url(&c.url, &inscrites)) {
            lignes.push(format!(
                "[ssrf] cible privée refusée à l'envoi : {} #{} ({}) vers l'hôte {:?} — {}",
                c.genre, c.id, c.champ, hote, crate::ledger::LEVIERS_DU_REFUS_D_ADRESSE_PRIVEE
            ));
        }
    }
    lignes
}

/// `P7.20-a` — LA LIGNE DE JOURNAL d'un canal semé par l'environnement dont la ligne n'a pas pu être lue : rien n'est
/// inscrit, et ses envois vers une adresse privée seront refusés jusqu'au démarrage suivant.
pub(crate) const LIGNE_CANAL_DE_L_ENVIRONNEMENT_NON_INSCRIT: &str = "[ssrf] canal semé par PLUME_NOTIFY_NTFY_URL NON inscrit : \
sa ligne n'a pas pu être lue — ses envois vers une adresse privée seront refusés jusqu'au prochain démarrage";

/// `P7.20-a` — LE CANAL SEMÉ PAR `PLUME_NOTIFY_NTFY_URL`, INSCRIT SOUS SON IDENTIFIANT (appelé APRÈS `seed_env_notifier`,
/// daemon/src/server/mod.rs). Son URL exacte est de configuration pour CE canal seul : la ligne `ntfy (env)` que le semis
/// vient de poser ou de remettre (la même lecture que `seed_env_notifier`, daemon/src/seeds.rs) ; une autre URL émise par
/// cette ligne reste de l'API. Réglage vide, ou aucune telle ligne : rien d'inscrit (une inscription d'avant est
/// retirée). Lecture refusée : rien d'inscrit, et c'est dit (`LIGNE_CANAL_DE_L_ENVIRONNEMENT_NON_INSCRIT`, la cause
/// du moteur à la suite).
pub(crate) fn inscrire_le_canal_de_l_environnement(conn: &Connection, conf: &HashMap<String, String>) {
    use rusqlite::OptionalExtension as _;
    let base = crate::ledger::base_de(conn);
    let url = cfg(conf, "PLUME_NOTIFY_NTFY_URL", "");
    if url.trim().is_empty() {
        crate::ledger::remplacer_le_canal_de_l_environnement(&base, None);
        return;
    }
    let lu = conn
        .query_row(
            "SELECT id FROM notifier WHERE name='ntfy (env)'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .optional();
    match lu {
        Ok(Some(id)) => crate::ledger::remplacer_le_canal_de_l_environnement(&base, Some((id, crate::ledger::CibleDeConfiguration::exacte(&url)))),
        Ok(None) => crate::ledger::remplacer_le_canal_de_l_environnement(&base, None),
        Err(e) => {
            crate::ledger::remplacer_le_canal_de_l_environnement(&base, None);
            eprintln!("{LIGNE_CANAL_DE_L_ENVIRONNEMENT_NON_INSCRIT} ({e})");
        }
    }
}

/// `P7.20-a` — CE QUE LE DÉMARRAGE DIT DE LA GARDE D'ÉGRESS, appelé APRÈS les surcouches et le canal semé par
/// l'environnement (daemon/src/server/mod.rs, `open_and_migrate_db`) : la politique retenue (une ligne), les aveux de
/// lecture, puis — sur un fil à part, parce que juger un nom le résout — une ligne par objet stocké dont la cible
/// privée sera refusée. Rend le fil (le démarrage ne l'attend pas).
pub(crate) fn dire_l_egress_au_demarrage(conn: &Connection) -> std::thread::JoinHandle<()> {
    eprintln!("{}", crate::ledger::ligne_de_la_politique_des_adresses_privees(crate::ledger::ssrf_politique_du_prive()));
    let (cibles, aveux) = lire_les_cibles_stockees(conn);
    for aveu in &aveux {
        eprintln!("{aveu}");
    }
    let base = crate::ledger::base_de(conn);
    std::thread::spawn(move || {
        for ligne in lignes_des_cibles_privees_refusees(&base, &cibles) {
            eprintln!("{ligne}");
        }
    })
}

// =====================================================================================================
// LOADERS par type d'objet. Chacun : lit config.d/<sous-dossier>/*.json, valide (MÊMES validateurs que
// l'API), UPSERT override-safe managed=1. Renvoie le nombre d'objets posés.
// =====================================================================================================

/// NOTIFIERS (canaux d'alerte). Secret dans `config` (token/pass/webhook_url/routing_key/auth_header) ->
/// référencé indirectement. `url`/`url_ref` : l'endpoint (peut porter un token pour un webhook -> `url_ref`).
pub(crate) fn load_overlay_notifiers(conn: &Connection, dir: &std::path::Path) -> crate::overlays_adossement::Chargement {
    const KINDS: &[&str] = &["ntfy", "webhook", "email", "slack", "pagerduty", "generic", "lookup"];
    let (fichiers, mut ch) = crate::overlays_adossement::Chargement::ouvrir(dir, crate::overlays_adossement::est_json);
    let mut inscrites: Vec<(i64, crate::ledger::CibleDeConfiguration)> = Vec::new(); // `P7.20-a` : inscrites APRÈS l'écriture comptée, sous l'id de la ligne écrite
    for path in fichiers {
        let v = match overlay_read_json(&path) { Some(v) => v, None => { ch.ignores += 1; continue; } };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN notifier {} sans 'name' — ignoré", path.display()); ch.ignores += 1; continue } };
        let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("ntfy").trim().to_string();
        if !KINDS.contains(&kind.as_str()) {
            eprintln!("[oac] WARN notifier '{name}' : kind '{kind}' hors allowlist — ignoré");
            ch.ignores += 1;
            continue;
        }
        // url : `url_ref` (résolu) l'emporte sur `url`. Validation `safe_url` comme notifier_create.
        let url = match v.get("url_ref").and_then(|x| x.as_str()) {
            Some(r) => match resolve_secret_ref(r) { Ok(u) => u, Err(e) => { eprintln!("[oac] WARN notifier '{name}' : url_ref — {e} — ignoré"); ch.ignores += 1; continue } },
            None => v.get("url").and_then(|x| x.as_str()).unwrap_or("").trim().to_string(),
        };
        if notifier_kind_needs_url(&kind) {
            if !safe_url(&url) { eprintln!("[oac] WARN notifier '{name}' : url requise/invalide pour kind '{kind}' — ignoré"); ch.ignores += 1; continue; }
        } else if !url.is_empty() && !safe_url(&url) {
            eprintln!("[oac] WARN notifier '{name}' : url invalide — ignoré");
            ch.ignores += 1;
            continue;
        }
        let mut config = v.get("config").cloned().unwrap_or_else(|| json!({}));
        if let Err(e) = scrub_config_secrets(&mut config) {
            eprintln!("[oac] WARN notifier '{name}' : {e} — REJETÉ");
            ch.ignores += 1;
            continue;
        }
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true) as i64;
        let min_sev = v.get("min_severity").and_then(|x| x.as_i64()).unwrap_or(2).clamp(0, 4);
        let config_s = config.to_string();
        // `P10.20-b` — une lecture de l'existant NON faite ignore le fichier (aucun UNIQUE(name) sur `notifier` : un
        // INSERT créerait un canal en DOUBLON, chaque alerte partie deux fois) ; l'écriture n'est comptée que sur `Ok(1)`.
        let Some(plan) = plan_oac_ou_aveu(conn, "notifier", "notifier", &name, &path) else {
            ch.ignores += 1;
            continue;
        };
        let id_du_plan = match &plan { UpsertPlan::Update(id) => Some(*id), _ => None }; // `P7.20-a` : l'id de la ligne qui sera écrite
        let mut id_insere = 0i64; // `P7.20-a` : lu au pied de l'insertion, retenu seulement sur une écriture comptée
        let ecrit = match plan {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN notifier '{name}' : un canal UI (managed=2) du même nom existe — overlay ignoré (renommez l'un des deux)"); ch.ignores += 1; continue; }
            UpsertPlan::Update(id) => conn.execute("UPDATE notifier SET kind=?1, enabled=?2, url=?3, min_severity=?4, config=?5, managed=1 WHERE id=?6", params![kind, enabled, url, min_sev, config_s, id]),
            UpsertPlan::Insert => {
                let ecrit = conn.execute("INSERT INTO notifier(name,kind,enabled,url,min_severity,config,managed) VALUES(?1,?2,?3,?4,?5,?6,1)", params![name, kind, enabled, url, min_sev, config_s]);
                id_insere = conn.last_insert_rowid();
                ecrit
            }
        };
        if compter_l_ecriture_oac("notifier", &name, &path, ecrit, &mut ch) {
            let id = id_du_plan.unwrap_or(id_insere); // `P7.20-a` : la ligne mise à jour, ou celle que l'insertion a rendue
            inscrites.extend(cibles_d_egress_d_un_canal(&kind, &url, &config).into_iter().map(|(_, cible)| (id, cible)));
        }
    }
    crate::ledger::remplacer_les_cibles_de_surcouche(&crate::ledger::base_de(conn), crate::ledger::FamilleDeSurcouche::Canaux, inscrites);
    ch
}

/// DESTINATIONS (#50 forward vers sink externe). Secret dans `config` (hec_token/auth_header) -> référencé.
/// `endpoint`/`endpoint_ref` non-secret (validé schéma+anti-metadata). `filter` = sélecteur allowlisté.
pub(crate) fn load_overlay_destinations(conn: &Connection, dir: &std::path::Path) -> crate::overlays_adossement::Chargement {
    let (fichiers, mut ch) = crate::overlays_adossement::Chargement::ouvrir(dir, crate::overlays_adossement::est_json);
    let mut inscrites: Vec<(i64, crate::ledger::CibleDeConfiguration)> = Vec::new(); // `P7.20-a` : inscrites APRÈS l'écriture comptée, sous l'id de la ligne écrite
    for path in fichiers {
        let v = match overlay_read_json(&path) { Some(v) => v, None => { ch.ignores += 1; continue; } };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN destination {} sans 'name' — ignorée", path.display()); ch.ignores += 1; continue } };
        let dtype = v.get("type").and_then(|x| x.as_str()).unwrap_or("webhook").trim().to_string();
        if !dest_type_ok(&dtype) { eprintln!("[oac] WARN destination '{name}' : type '{dtype}' hors allowlist — ignorée"); ch.ignores += 1; continue; }
        let endpoint = match v.get("endpoint_ref").and_then(|x| x.as_str()) {
            Some(r) => match resolve_secret_ref(r) { Ok(u) => u, Err(e) => { eprintln!("[oac] WARN destination '{name}' : endpoint_ref — {e} — ignorée"); ch.ignores += 1; continue } },
            None => v.get("endpoint").and_then(|x| x.as_str()).unwrap_or("").trim().to_string(),
        };
        // `P7.20-a` — une surcouche est de la configuration : son endpoint est jugé comme tel (adresse privée admise
        // sauf `PLUME_SSRF_BLOCK_PRIVATE` explicite à 1), puis inscrit APRÈS l'écriture.
        if !dest_endpoint_ok_selon(&dtype, &endpoint, crate::ledger::OrigineDeLaCible::Configuration) { eprintln!("[oac] WARN destination '{name}' : endpoint invalide pour type '{dtype}' — ignorée"); ch.ignores += 1; continue; }
        let filter_v = v.get("filter").cloned().unwrap_or_else(|| json!({}));
        if let Err(e) = DestFilter::from_json(&filter_v).validate() { eprintln!("[oac] WARN destination '{name}' : filtre invalide ({e}) — ignorée"); ch.ignores += 1; continue; }
        let mut config = v.get("config").cloned().unwrap_or_else(|| json!({}));
        if let Err(e) = scrub_config_secrets(&mut config) { eprintln!("[oac] WARN destination '{name}' : {e} — REJETÉE"); ch.ignores += 1; continue; }
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false) as i64;
        let batch_max = v.get("batch_max").and_then(|x| x.as_i64()).unwrap_or(500).clamp(1, 10000);
        let interval_s = v.get("interval_s").and_then(|x| x.as_i64()).unwrap_or(30).max(5);
        let (config_s, filter_s) = (config.to_string(), filter_v.to_string());
        let Some(plan) = plan_oac_ou_aveu(conn, "destination", "destination", &name, &path) else {
            ch.ignores += 1;
            continue;
        };
        let id_du_plan = match &plan { UpsertPlan::Update(id) => Some(*id), _ => None }; // `P7.20-a` : l'id de la ligne qui sera écrite
        let mut id_insere = 0i64; // `P7.20-a` : lu au pied de l'insertion, retenu seulement sur une écriture comptée
        let ecrit = match plan {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN destination '{name}' : une destination UI (managed=2) du même nom existe — overlay ignoré"); ch.ignores += 1; continue; }
            UpsertPlan::Update(id) => conn.execute("UPDATE destination SET type=?1, enabled=?2, endpoint=?3, config=?4, filter=?5, batch_max=?6, interval_s=?7, managed=1 WHERE id=?8", params![dtype, enabled, endpoint, config_s, filter_s, batch_max, interval_s, id]),
            UpsertPlan::Insert => {
                let ecrit = conn.execute("INSERT INTO destination(type,name,enabled,endpoint,config,filter,batch_max,interval_s,managed,created) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1,?9)", params![dtype, name, enabled, endpoint, config_s, filter_s, batch_max, interval_s, now()]);
                id_insere = conn.last_insert_rowid();
                ecrit
            }
        };
        if compter_l_ecriture_oac("destination", &name, &path, ecrit, &mut ch) {
            let id = id_du_plan.unwrap_or(id_insere); // `P7.20-a` : la ligne mise à jour, ou celle que l'insertion a rendue
            inscrites.extend(cibles_d_egress_d_une_destination(&dtype, &endpoint).into_iter().map(|(_, cible)| (id, cible)));
        }
    }
    crate::ledger::remplacer_les_cibles_de_surcouche(&crate::ledger::base_de(conn), crate::ledger::FamilleDeSurcouche::Destinations, inscrites);
    ch
}

/// CONNECTEURS (#3a sources externes). Credential = colonne `secret` (JAMAIS dans `config_json`) référencée
/// via `secret_ref`. `config_json` = identifiants NON-secrets (client_id/api_root/...) validés par type.
pub(crate) fn load_overlay_connectors(conn: &Connection, dir: &std::path::Path) -> crate::overlays_adossement::Chargement {
    const TYPES: &[&str] = &["defender", "taxii2", "http_pull"];
    let (fichiers, mut ch) = crate::overlays_adossement::Chargement::ouvrir(dir, crate::overlays_adossement::est_json);
    let mut inscrites: Vec<(i64, crate::ledger::CibleDeConfiguration)> = Vec::new(); // `P7.20-a` : inscrites APRÈS l'écriture comptée, sous l'id de la ligne écrite
    for path in fichiers {
        let v = match overlay_read_json(&path) { Some(v) => v, None => { ch.ignores += 1; continue; } };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN connecteur {} sans 'name' — ignoré", path.display()); ch.ignores += 1; continue } };
        let ctype = v.get("type").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        if !TYPES.contains(&ctype.as_str()) { eprintln!("[oac] WARN connecteur '{name}' : type '{ctype}' hors allowlist (defender|taxii2|http_pull) — ignoré"); ch.ignores += 1; continue; }
        let mut config = v.get("config").cloned().unwrap_or_else(|| json!({}));
        // Validation de forme PAR TYPE (miroir de connector_create).
        let cfg_ok = match ctype.as_str() {
            "http_pull" => {
                let has_url = config.get("url").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
                    || config.get("api_root").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
                let has_path = config.get("records_path").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false);
                let has_map = config.get("field_map").and_then(|x| x.as_object()).map(|o| !o.is_empty()).unwrap_or(false);
                has_url && has_path && has_map
            }
            "taxii2" => config.get("api_root").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
                && config.get("collection_id").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false),
            "defender" => config.get("azure_tenant").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
                && config.get("client_id").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false),
            _ => false,
        };
        if !cfg_ok { eprintln!("[oac] WARN connecteur '{name}' : config invalide/incomplète pour type '{ctype}' — ignoré"); ch.ignores += 1; continue; }
        // Le secret NE vit QUE dans la colonne `secret`, via `secret_ref`. Un `secret` en clair top-level -> rejet.
        if v.get("secret").map(|s| !s.is_null()).unwrap_or(false) {
            eprintln!("[oac] WARN connecteur '{name}' : champ 'secret' en clair interdit — utilisez 'secret_ref' (env:/file:/vault:) — REJETÉ");
            ch.ignores += 1;
            continue;
        }
        let secret = match resolve_secret_ref(v.get("secret_ref").and_then(|x| x.as_str()).unwrap_or("")) {
            Ok(s) => s,
            Err(e) => { eprintln!("[oac] WARN connecteur '{name}' : secret_ref — {e} — REJETÉ"); ch.ignores += 1; continue; }
        };
        // Défense en profondeur : le config_json ne DOIT pas porter de secret (le split est structurel).
        if let Err(e) = scrub_config_secrets(&mut config) { eprintln!("[oac] WARN connecteur '{name}' : {e} — REJETÉ"); ch.ignores += 1; continue; }
        let env_id = v.get("env_id").and_then(|x| x.as_str()).unwrap_or("prod").trim().to_string();
        if !env_slug_ok(&env_id) { eprintln!("[oac] WARN connecteur '{name}' : env_id '{env_id}' invalide — ignoré"); ch.ignores += 1; continue; }
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false) as i64;
        let interval_s = v.get("interval_s").and_then(|x| x.as_i64()).unwrap_or(300).max(60);
        let config_s = config.to_string();
        let Some(plan) = plan_oac_ou_aveu(conn, "connector", "connecteur", &name, &path) else {
            ch.ignores += 1;
            continue;
        };
        let id_du_plan = match &plan { UpsertPlan::Update(id) => Some(*id), _ => None }; // `P7.20-a` : l'id de la ligne qui sera écrite
        let mut id_insere = 0i64; // `P7.20-a` : lu au pied de l'insertion, retenu seulement sur une écriture comptée
        let ecrit = match plan {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN connecteur '{name}' : un connecteur UI (managed=2) du même nom existe — overlay ignoré"); ch.ignores += 1; continue; }
            UpsertPlan::Update(id) => conn.execute("UPDATE connector SET type=?1, enabled=?2, config_json=?3, secret=?4, interval_s=?5, env_id=?6, managed=1 WHERE id=?7", params![ctype, enabled, config_s, secret, interval_s, env_id, id]),
            UpsertPlan::Insert => {
                let ecrit = conn.execute("INSERT INTO connector(type,name,enabled,config_json,secret,interval_s,env_id,managed,created) VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8)", params![ctype, name, enabled, config_s, secret, interval_s, env_id, now()]);
                id_insere = conn.last_insert_rowid();
                ecrit
            }
        };
        if compter_l_ecriture_oac("connecteur", &name, &path, ecrit, &mut ch) {
            let id = id_du_plan.unwrap_or(id_insere); // `P7.20-a` : la ligne mise à jour, ou celle que l'insertion a rendue
            inscrites.extend(cibles_d_egress_d_un_connecteur(&ctype, &config).into_iter().map(|(_, cible)| (id, cible)));
        }
    }
    crate::ledger::remplacer_les_cibles_de_surcouche(&crate::ledger::base_de(conn), crate::ledger::FamilleDeSurcouche::Connecteurs, inscrites);
    ch
}

/// INDEX-POLICIES (#49). Aucun secret. name = un env_id (env_id_ok) ; rétention clampée [7,3650] si > 0.
pub(crate) fn load_overlay_index_policies(conn: &Connection, dir: &std::path::Path) -> crate::overlays_adossement::Chargement {
    let (fichiers, mut ch) = crate::overlays_adossement::Chargement::ouvrir(dir, crate::overlays_adossement::est_json);
    for path in fichiers {
        let v = match overlay_read_json(&path) { Some(v) => v, None => { ch.ignores += 1; continue; } };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN index-policy {} sans 'name' — ignorée", path.display()); ch.ignores += 1; continue } };
        if !env_id_ok(&name) { eprintln!("[oac] WARN index-policy '{name}' : nom hors allowlist env_id — ignorée"); ch.ignores += 1; continue; }
        let rdays = v.get("retention_days").and_then(|x| x.as_i64()).unwrap_or(0);
        let max_rows = v.get("max_rows").and_then(|x| x.as_i64()).unwrap_or(0);
        let max_bytes = v.get("max_bytes").and_then(|x| x.as_i64()).unwrap_or(0);
        if rdays < 0 || max_rows < 0 || max_bytes < 0 { eprintln!("[oac] WARN index-policy '{name}' : valeurs négatives interdites — ignorée"); ch.ignores += 1; continue; }
        let rd = if rdays > 0 { rdays.clamp(7, 3650) } else { 0 };
        let description = v.get("description").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true) as i64;
        // `P10.20-b` — AVANT : plan lu par la projection qui repliait une lecture ratée sur `Insert` (sans un
        // mot), écriture jetée (`let _`) puis `charges += 1` : une politique de rétention refusée par le moteur
        // était annoncée chargée alors que la base gardait l'ancienne. DÉSORMAIS la lecture ratée est avouée
        // (UNIQUE(name) borne l'INSERT tenté : ni doublon, ni copie UI écrasée) et seule une écriture `Ok(1)`
        // compte chargé ; un refus est ignoré et dit avec la cause du moteur.
        let ecrit = match plan_oac_nom_unique_ou_aveu(conn, "index_policy", "index-policy", &name, &path) {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN index-policy '{name}' : une policy UI (managed=2) du même nom existe — overlay ignorée"); ch.ignores += 1; continue; }
            UpsertPlan::Update(id) => conn.execute("UPDATE index_policy SET retention_days=?1, max_rows=?2, max_bytes=?3, description=?4, enabled=?5, managed=1, updated=?6, updated_by='config.d' WHERE id=?7", params![rd, max_rows, max_bytes, description, enabled, now(), id]),
            UpsertPlan::Insert => conn.execute("INSERT INTO index_policy(name,retention_days,max_rows,max_bytes,description,enabled,managed,created,updated,updated_by) VALUES(?1,?2,?3,?4,?5,?6,1,?7,?7,'config.d')", params![name, rd, max_rows, max_bytes, description, enabled, now()]),
        };
        compter_l_ecriture_oac("index-policy", &name, &path, ecrit, &mut ch);
    }
    ch
}

/// FIELD-FILTERS (#45 masquage par champ). Aucun secret. field/action/role validés comme field_filter_create.
pub(crate) fn load_overlay_field_filters(conn: &Connection, dir: &std::path::Path) -> crate::overlays_adossement::Chargement {
    const ACTIONS: &[&str] = &["mask", "partial", "hash", "redact", "deny"];
    const ROLES: &[&str] = &["", "viewer", "editor", "admin"];
    let (fichiers, mut ch) = crate::overlays_adossement::Chargement::ouvrir(dir, crate::overlays_adossement::est_json);
    for path in fichiers {
        let v = match overlay_read_json(&path) { Some(v) => v, None => { ch.ignores += 1; continue; } };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN field-filter {} sans 'name' — ignoré", path.display()); ch.ignores += 1; continue } };
        let field = match validate_field(v.get("field").and_then(|x| x.as_str()).unwrap_or("")) {
            Ok(f) => f,
            Err(e) => { eprintln!("[oac] WARN field-filter '{name}' : champ invalide ({e}) — ignoré"); ch.ignores += 1; continue; }
        };
        let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("mask").to_ascii_lowercase();
        if !ACTIONS.contains(&action.as_str()) { eprintln!("[oac] WARN field-filter '{name}' : action '{action}' hors allowlist — ignoré"); ch.ignores += 1; continue; }
        let role = v.get("role").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if !ROLES.contains(&role.as_str()) { eprintln!("[oac] WARN field-filter '{name}' : rôle '{role}' hors allowlist — ignoré"); ch.ignores += 1; continue; }
        let tenant = v.get("tenant").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let env = v.get("env").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        if !env.is_empty() && !env_id_ok(&env) { eprintln!("[oac] WARN field-filter '{name}' : env '{env}' invalide — ignoré"); ch.ignores += 1; continue; }
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true) as i64;
        let ord = v.get("ord").and_then(|x| x.as_i64()).unwrap_or(0);
        let plan = plan_oac_nom_unique_ou_aveu(conn, "field_filter", "field-filter", &name, &path);
        let ecrit = match plan {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN field-filter '{name}' : un filtre UI (managed=2) du même nom existe — overlay ignoré"); ch.ignores += 1; continue; }
            UpsertPlan::Update(id) => conn.execute("UPDATE field_filter SET field=?1, action=?2, role=?3, tenant=?4, env=?5, enabled=?6, ord=?7, managed=1, updated=?8 WHERE id=?9", params![field, action, role, tenant, env, enabled, ord, now(), id]),
            UpsertPlan::Insert => conn.execute("INSERT INTO field_filter(name,field,action,role,tenant,env,enabled,ord,managed,created,updated) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1,?9,?9)", params![name, field, action, role, tenant, env, enabled, ord, now()]),
        };
        compter_l_ecriture_oac("field-filter", &name, &path, ecrit, &mut ch);
    }
    ch
}

/// LE SQL BRUT D'UN OVERLAY DE PANNEAU — frontière ÉTABLIE, plus seulement constatée (P7.9-a).
///
/// Le CRUD HTTP des panneaux garde le SQL brut derrière `raw_sql_allowed` (admin, et pas de
/// permission `raw_sql` retirée) — `dash_ergonomics.rs` à l'INSERT comme à l'UPDATE. Ce chemin-ci
/// n'y passe pas, et c'est ASSUMÉ : établi par lecture le 2026-08-03, il n'est atteignable que par
/// `main() -> run() -> open_and_migrate_db -> load_overlays`, c'est-à-dire AU DÉMARRAGE. Aucune
/// route HTTP, aucune commande CLI, aucun job de fond n'y mène — donc aucun utilisateur
/// authentifié, quel que soit son rôle, ne peut le déclencher. La source est le répertoire
/// `PLUME_CONFIG_DIR`, baké dans l'image (`chmod a+rX`, process `USER soc` non-propriétaire) ou
/// monté en ConfigMap, sous `readOnlyRootFilesystem`/`read_only`. Écrire là, c'est être opérateur :
/// l'auteur d'un overlay est déjà équivalent-admin, et lui redemander un rôle n'a pas de sens.
///
/// CE QUI MANQUAIT VRAIMENT. Le chemin JUMEAU des règles/playbooks REFUSE le SQL brut au
/// chargement (`overlays.rs`), et sa raison écrite est double : « contournerait le gate admin
/// `raw_sql_allowed` ET LE LEDGER D'AUDIT plume (seul un commit git la tracerait) ». Le premier
/// motif ne vaut pas ici (pas d'utilisateur), mais LE SECOND SI : un panneau en SQL brut arrivait
/// sans laisser la moindre trace côté plume. On ne renverse donc pas la décision — on la DÉCLARE
/// et on la TRACE, comme le fait déjà son jumeau de son côté.
fn tracer_panneau_sql_brut(conn: &Connection, kind: &str, name: &str) {
    let _ = audit_config_change(
        conn,
        "config.overlay.raw_sql",
        &format!("{kind} overlay '{name}' posé en SQL brut (auteur d'overlay = équivalent-admin)"),
        3,
        &format!("overlay config.d : {kind} '{name}' en SQL brut accepté au chargement (hors gate raw_sql_allowed, tracé ici)"),
        &json!({ "op": "accept", "kind": kind, "name": name, "reason": "raw-sql-overlay-operator-authored" }).to_string(),
    );
}

/// LIBRARY-PANELS (#54 panneaux réutilisables). Aucun secret. Requête validée par `valider_panneau`.
pub(crate) fn load_overlay_library_panels(conn: &Connection, dir: &std::path::Path) -> crate::overlays_adossement::Chargement {
    let (fichiers, mut ch) = crate::overlays_adossement::Chargement::ouvrir(dir, crate::overlays_adossement::est_json);
    for path in fichiers {
        let v = match overlay_read_json(&path) { Some(v) => v, None => { ch.ignores += 1; continue; } };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN library-panel {} sans 'name' — ignoré", path.display()); ch.ignores += 1; continue } };
        let title = v.get("title").and_then(|x| x.as_str()).unwrap_or("Panneau").to_string();
        let query = v.get("query").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let is_soql = v.get("is_soql").and_then(|x| x.as_bool()).unwrap_or(true);
        if let Err(e) = panneau_avoue::valider_panneau(&query, is_soql) { eprintln!("[oac] WARN library-panel '{name}' : requête invalide ({e}) — ignoré"); ch.ignores += 1; continue; }
        let viz = v.get("viz").and_then(|x| x.as_str()).unwrap_or("table").to_string();
        let drill = v.get("drill").and_then(|x| x.as_str()).unwrap_or("").to_string();
        // `P10.20-b` — même discipline que les canaux : `library_panel` n'a aucun UNIQUE(name).
        let Some(plan) = plan_oac_ou_aveu(conn, "library_panel", "library-panel", &name, &path) else {
            ch.ignores += 1;
            continue;
        };
        let ecrit = match plan {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN library-panel '{name}' : un panneau UI (managed=2) du même nom existe — overlay ignoré"); ch.ignores += 1; continue; }
            UpsertPlan::Update(id) => conn.execute("UPDATE library_panel SET title=?1, query=?2, is_soql=?3, viz=?4, drill=?5, managed=1, updated=?6 WHERE id=?7", params![title, query, is_soql as i64, viz, drill, now(), id]),
            UpsertPlan::Insert => conn.execute("INSERT INTO library_panel(name,title,query,is_soql,viz,drill,visibility,managed,created,updated) VALUES(?1,?2,?3,?4,?5,?6,'shared',1,?7,?7)", params![name, title, query, is_soql as i64, viz, drill, now()]),
        };
        // Le SQL brut se trace « accepté » (registre non purgeable) seulement s'il a été POSÉ : une lecture ratée,
        // une copie UI ou une écriture refusée ignorent l'overlay, et la trace l'aurait affirmé accepté.
        if compter_l_ecriture_oac("library-panel", &name, &path, ecrit, &mut ch) && !is_soql {
            tracer_panneau_sql_brut(conn, "library-panel", &name);
        }
    }
    ch
}

/// NOTIFICATION-POLICIES (routage des alertes vers des canaux). Aucun secret. matchers validés (allowlist de
/// champs) ; contact_points = ids de notifiers (CSV, existence NON vérifiée, comme policy_create).
pub(crate) fn load_overlay_notification_policies(conn: &Connection, dir: &std::path::Path) -> crate::overlays_adossement::Chargement {
    let (fichiers, mut ch) = crate::overlays_adossement::Chargement::ouvrir(dir, crate::overlays_adossement::est_json);
    for path in fichiers {
        let v = match overlay_read_json(&path) { Some(v) => v, None => { ch.ignores += 1; continue; } };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN notification-policy {} sans 'name' — ignorée", path.display()); ch.ignores += 1; continue } };
        let matchers_v = v.get("matchers").cloned().unwrap_or_else(|| json!({}));
        let matchers = match parse_matchers(&matchers_v) { Ok(m) => m, Err(e) => { eprintln!("[oac] WARN notification-policy '{name}' : matchers invalides ({e}) — ignorée"); ch.ignores += 1; continue; } };
        let matchers_s = matchers_to_json(&matchers);
        let cps: Vec<i64> = v.get("contact_points").and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|e| e.as_i64()).collect()).unwrap_or_default();
        if cps.is_empty() || cps.len() > 32 { eprintln!("[oac] WARN notification-policy '{name}' : contact_points (ids de canaux) vide ou > 32 — ignorée"); ch.ignores += 1; continue; }
        let cps_s = cps.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        let cont = v.get("continue").and_then(|x| x.as_bool()).unwrap_or(false) as i64;
        let enabled = v.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true) as i64;
        // `P10.20-b` — `notification_policy` n'a aucun UNIQUE(name) : un doublon doublerait le routage des alertes.
        let Some(plan) = plan_oac_ou_aveu(conn, "notification_policy", "notification-policy", &name, &path) else {
            ch.ignores += 1;
            continue;
        };
        let ecrit = match plan {
            UpsertPlan::SkipUser => { eprintln!("[oac] WARN notification-policy '{name}' : une policy UI (managed=2) du même nom existe — overlay ignorée"); ch.ignores += 1; continue; }
            UpsertPlan::Update(id) => conn.execute("UPDATE notification_policy SET matchers=?1, contact_points=?2, continue_=?3, enabled=?4, managed=1 WHERE id=?5", params![matchers_s, cps_s, cont, enabled, id]),
            UpsertPlan::Insert => conn.execute("INSERT INTO notification_policy(name,matchers,contact_points,continue_,enabled,managed,created,created_by) VALUES(?1,?2,?3,?4,?5,1,?6,'config.d')", params![name, matchers_s, cps_s, cont, enabled, now()]),
        };
        compter_l_ecriture_oac("notification-policy", &name, &path, ecrit, &mut ch);
    }
    ch
}

/// DASHBOARDS (+ leurs PANNEAUX). Aucun secret. Chaque panneau validé par `valider_panneau`. Le jeu de
/// panneaux managed=1 d'un dashboard managed est REMPLACÉ à l'identique du fichier (idempotent).
pub(crate) fn load_overlay_dashboards(conn: &Connection, dir: &std::path::Path) -> crate::overlays_adossement::Chargement {
    let (fichiers, mut ch) = crate::overlays_adossement::Chargement::ouvrir(dir, crate::overlays_adossement::est_json);
    for path in fichiers {
        let v = match overlay_read_json(&path) { Some(v) => v, None => { ch.ignores += 1; continue; } };
        let name = match overlay_name(&v) { Some(n) => n, None => { eprintln!("[oac] WARN dashboard {} sans 'name' — ignoré", path.display()); ch.ignores += 1; continue } };
        // Valider TOUS les panneaux AVANT toute écriture (tout-ou-rien : un panneau cassé -> dashboard ignoré).
        let panels = v.get("panels").and_then(|x| x.as_array()).cloned().unwrap_or_default();
        let mut compiled: Vec<(String, String, i64, String, i64, String)> = Vec::new(); // title,query,is_soql,viz,window_s,drill
        let mut bad = false;
        for p in &panels {
            let query = p.get("query").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let is_soql = p.get("is_soql").and_then(|x| x.as_bool()).unwrap_or(true);
            if let Err(e) = panneau_avoue::valider_panneau(&query, is_soql) { eprintln!("[oac] WARN dashboard '{name}' : panneau invalide ({e}) — dashboard ignoré"); bad = true; break; }
            compiled.push((
                p.get("title").and_then(|x| x.as_str()).unwrap_or("Panneau").to_string(),
                query,
                is_soql as i64,
                p.get("viz").and_then(|x| x.as_str()).unwrap_or("table").to_string(),
                p.get("window_s").and_then(|x| x.as_i64()).unwrap_or(0),
                p.get("drill").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            ));
        }
        if bad { ch.ignores += 1; continue; }
        // Même frontière que les library-panels : un panneau de dashboard overlay en SQL brut est
        // opérateur-authoré, donc accepté — mais TRACÉ (cf. `tracer_panneau_sql_brut`), et seulement une fois
        // l'écriture VALIDÉE (après le `RELEASE`, plus bas) : une lecture ratée, une copie UI homonyme, un point de
        // reprise refusé ou une écriture annulée ignorent le tableau, et le registre non purgeable l'aurait dit
        // « accepté ».
        let sql_brut = compiled.iter().any(|(_, _, is_soql, _, _, _)| *is_soql == 0);
        // `P10.20-b` — AVANT : plan lu par la projection qui repliait une lecture ratée sur `Insert` (`dashboard`
        // n'a aucun UNIQUE(name), `db/schema.sql` : l'INSERT créait un tableau DOUBLON), UPDATE `managed=1` jeté,
        // puis `DELETE` des panneaux managés et INSERT de chacun jetés : un DELETE passé suivi d'INSERT refusés
        // VIDAIT le tableau, compté chargé. DÉSORMAIS : lecture ratée -> fichier ignoré et avoué ; les écritures
        // (tableau, DELETE, chaque panneau) tiennent sous un SAVEPOINT, la première refusée annule le tout
        // (`ROLLBACK TO` : le tableau garde ses panneaux d'avant), l'overlay est ignoré et dit avec la cause du
        // moteur ; `charges` ne bouge qu'après le `RELEASE`.
        let Some(plan) = plan_oac_ou_aveu(conn, "dashboard", "dashboard", &name, &path) else {
            ch.ignores += 1;
            continue;
        };
        if matches!(plan, UpsertPlan::SkipUser) {
            eprintln!("[oac] WARN dashboard '{name}' : un dashboard UI (managed=2) du même nom existe — overlay ignoré");
            ch.ignores += 1;
            continue;
        }
        // Le chargeur appelé hors transaction : le SAVEPOINT est alors la transaction la plus externe, et un
        // ROLLBACK complet est la même annulation (repli si `ROLLBACK TO … ; RELEASE` est refusé à son tour).
        let hors_transaction = conn.is_autocommit();
        if let Err(e) = conn.execute_batch("SAVEPOINT oac_dashboard") {
            eprintln!("[oac] WARN dashboard '{name}' ({}) : point de reprise non ouvert ({e}) — overlay ignoré, aucun panneau touché", path.display());
            ch.ignores += 1;
            continue;
        }
        match ecrire_le_tableau_oac(conn, &name, plan, &compiled) {
            Ok(()) => match conn.execute_batch("RELEASE oac_dashboard") {
                Ok(()) => {
                    ch.charges += 1;
                    // Après le `RELEASE`, hors du point de reprise du chargeur : son `ROLLBACK TO` ne peut plus emporter la trace.
                    if sql_brut {
                        tracer_panneau_sql_brut(conn, "dashboard-panel", &name);
                    }
                }
                Err(e) => {
                    let annule = annuler_le_tableau_oac(conn, hors_transaction);
                    eprintln!("[oac] WARN dashboard '{name}' ({}) : validation refusée ({e}) — overlay NON chargé, annulation : {annule}", path.display());
                    ch.ignores += 1;
                }
            },
            Err(cause) => {
                eprintln!("[oac] WARN dashboard '{name}' ({}) : {cause} — overlay NON chargé, {}", path.display(), annuler_le_tableau_oac(conn, hors_transaction));
                ch.ignores += 1;
            }
        }
    }
    ch
}

/// `P10.20-b` — annule les écritures d'un tableau sous le SAVEPOINT `oac_dashboard` et rend la phrase qui le dit.
/// `ROLLBACK TO` puis `RELEASE` ; si l'un des deux est refusé et que le chargeur a été appelé hors transaction
/// (`hors_transaction`), un `ROLLBACK` complet : la connexion n'est jamais laissée dans une transaction ouverte.
fn annuler_le_tableau_oac(conn: &Connection, hors_transaction: bool) -> String {
    match conn.execute_batch("ROLLBACK TO oac_dashboard; RELEASE oac_dashboard") {
        Ok(()) => "écritures annulées, panneaux d'avant gardés".to_string(),
        Err(e) if hors_transaction && !conn.is_autocommit() => match conn.execute_batch("ROLLBACK") {
            Ok(()) => format!("retour au point de reprise refusé ({e}), transaction annulée en entier, panneaux d'avant gardés"),
            Err(e2) => format!("ANNULATION REFUSÉE ({e} ; puis {e2})"),
        },
        Err(e) => format!("ANNULATION REFUSÉE ({e})"),
    }
}

/// `P10.20-b` — les écritures d'un tableau OAC (la ligne `dashboard`, puis le remplacement de ses panneaux
/// `managed=1`), à jouer sous le SAVEPOINT de l'appelant. Rend la cause de la PREMIÈRE écriture refusée ou sans
/// effet, et s'arrête là : l'appelant annule le tout. `plan` n'est jamais `SkipUser` ici.
fn ecrire_le_tableau_oac(
    conn: &Connection,
    name: &str,
    plan: UpsertPlan,
    compiled: &[(String, String, i64, String, i64, String)],
) -> Result<(), String> {
    let did = match plan {
        UpsertPlan::SkipUser => return Err("copie UI (managed=2) du même nom".to_string()),
        UpsertPlan::Update(id) => {
            match conn.execute("UPDATE dashboard SET managed=1 WHERE id=?1", params![id]) {
                Ok(1) => {}
                Ok(n) => return Err(format!("mise à jour du tableau sans effet ({n} ligne posée)")),
                Err(e) => return Err(format!("mise à jour du tableau refusée ({e})")),
            }
            id
        }
        // `P10.20-w` (rang six) — l'identifiant n'est lu que sous `Ok(1)` : sur un INSERT refusé,
        // `last_insert_rowid()` rendait celui d'un AUTRE objet, dont les panneaux managés étaient alors remplacés.
        UpsertPlan::Insert => match conn.execute("INSERT INTO dashboard(name,created,managed) VALUES(?1,?2,1)", params![name, now()]) {
            Ok(1) => conn.last_insert_rowid(),
            Ok(n) => return Err(format!("l'insertion du tableau a écrit {n} ligne(s) au lieu d'une")),
            Err(e) => return Err(format!("insertion du tableau refusée ({e})")),
        },
    };
    // Synchronise les panneaux managed=1 de CE dashboard sur le fichier (remplace intégralement).
    if let Err(e) = conn.execute("DELETE FROM panel WHERE dashboard_id=?1 AND managed=1", params![did]) {
        return Err(format!("retrait des panneaux managés refusé ({e})"));
    }
    for (i, (title, query, is_soql, viz, window_s, drill)) in compiled.iter().enumerate() {
        match conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,window_s,position,drill,managed) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1)",
            params![did, title, query, is_soql, viz, window_s, i as i64, drill],
        ) {
            Ok(1) => {}
            Ok(n) => return Err(format!("panneau {} posé sans effet ({n} ligne)", i + 1)),
            Err(e) => return Err(format!("panneau {} refusé ({e})", i + 1)),
        }
    }
    Ok(())
}

/// Applique TOUS les overlays d'objets de config d'un `config.d` (sous-dossiers dédiés). Racine absente ->
/// no-op. Appelé DANS `load_overlays_dir` (overlays.rs) APRÈS le contenu de détection.
/// REND LE BILAN (`P4.1-r`, même forme que `load_overlays_dir`, qui l'absorbe et le publie).
pub(crate) fn load_oac_overlays_dir(conn: &Connection, root: &std::path::Path) -> crate::overlays_adossement::ChargementTotal {
    let mut total = crate::overlays_adossement::ChargementTotal::default();
    if !root.is_dir() {
        return total;
    }
    let nn = total.absorber(load_overlay_notifiers(conn, &root.join("notifiers")));
    let nd = total.absorber(load_overlay_destinations(conn, &root.join("destinations")));
    let nc = total.absorber(load_overlay_connectors(conn, &root.join("connectors")));
    let ni = total.absorber(load_overlay_index_policies(conn, &root.join("index-policies")));
    let nf = total.absorber(load_overlay_field_filters(conn, &root.join("field-filters")));
    let nl = total.absorber(load_overlay_library_panels(conn, &root.join("library-panels")));
    let np = total.absorber(load_overlay_notification_policies(conn, &root.join("notification-policies")));
    let nb = total.absorber(load_overlay_dashboards(conn, &root.join("dashboards")));
    if nn + nd + nc + ni + nf + nl + np + nb > 0 {
        eprintln!("[oac] config.d objets appliqués : {nn} notifier(s), {nd} destination(s), {nc} connecteur(s), {ni} index-policy, {nf} field-filter(s), {nl} library-panel(s), {np} notification-policy, {nb} dashboard(s) — managed=1 (source git)");
    }
    total
}

// =====================================================================================================
// #26 — PRUNE des objets de config OAC orphelins (managed=1 sans fichier adossé). Ne touche JAMAIS
// managed=0/2. Miroir de prune_orphan_overlays (overlays.rs) pour les tables OAC.
// =====================================================================================================

#[derive(Default, Debug, PartialEq)]
pub(crate) struct OacPruneCounts {
    pub(crate) notifier: i64,
    pub(crate) destination: i64,
    pub(crate) connector: i64,
    pub(crate) index_policy: i64,
    pub(crate) field_filter: i64,
    pub(crate) library_panel: i64,
    pub(crate) notification_policy: i64,
    pub(crate) dashboard: i64,
    pub(crate) panel: i64,
}

/// Noms adossés à un fichier pour une table donnée (le `name` de chaque overlay JSON du sous-dossier).
/// FAIL-CLOSED comme `overlay_backed_names` (`P4.1-r`) : un dossier ou un fichier qu'on ne sait pas lire
/// REFUSE l'élagage au lieu de valoir « aucun nom ».
fn backed_names(root: &std::path::Path, sub: &str) -> Result<std::collections::HashSet<String>, crate::overlays_adossement::RefusDePrune> {
    use crate::overlays_adossement::{est_json, fichiers_ou_refus, RefusDePrune};
    let mut s = std::collections::HashSet::new();
    for path in fichiers_ou_refus(&root.join(sub), est_json)? {
        let v = overlay_read_json_ou_cause(&path).map_err(|(cause, pourquoi)| RefusDePrune::fichier(&path, cause, &pourquoi))?;
        let n = overlay_name(&v).ok_or_else(|| RefusDePrune::forme(&path, "sans `name` : impossible de savoir quelle ligne ce fichier adosse"))?;
        s.insert(n);
    }
    Ok(s)
}

/// Supprime les lignes managed=1 dont le `name` n'est plus adossé. `table` littéral fixe (aucune injection).
fn prune_by_name(conn: &Connection, table: &str, keep: &std::collections::HashSet<String>) -> rusqlite::Result<i64> {
    let orphan_ids: Vec<i64> = {
        let mut st = conn.prepare(&format!("SELECT id,name FROM {table} WHERE managed=1"))?;
        let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        rows.flatten().filter(|(_, n)| !keep.contains(n)).map(|(id, _)| id).collect()
    };
    let mut n = 0i64;
    for id in &orphan_ids {
        n += conn.execute(&format!("DELETE FROM {table} WHERE id=?1 AND managed=1"), params![id])? as i64;
    }
    Ok(n)
}

/// PRUNE des objets OAC orphelins contre l'état COURANT des fichiers de `root`. Idempotent. Renvoie les
/// comptes par table. Les panneaux managed=1 d'un dashboard pruné (ou dont le dashboard n'existe plus) sont
/// élagués derrière (FK logique).
pub(crate) fn prune_oac_orphans(conn: &Connection, root: &std::path::Path) -> Result<OacPruneCounts, crate::overlays_adossement::RefusDePrune> {
    // TOUS les adossements sont lus AVANT la première suppression : un refus sur le huitième sous-dossier
    // ne doit pas laisser les sept premiers élagués (l'appelant est dans une transaction, mais la règle
    // tient d'elle-même).
    let adosses = [
        ("notifier", backed_names(root, "notifiers")?),
        ("destination", backed_names(root, "destinations")?),
        ("connector", backed_names(root, "connectors")?),
        ("index_policy", backed_names(root, "index-policies")?),
        ("field_filter", backed_names(root, "field-filters")?),
        ("library_panel", backed_names(root, "library-panels")?),
        ("notification_policy", backed_names(root, "notification-policies")?),
        ("dashboard", backed_names(root, "dashboards")?),
    ];
    let mut c = OacPruneCounts {
        notifier: prune_by_name(conn, adosses[0].0, &adosses[0].1)?,
        destination: prune_by_name(conn, adosses[1].0, &adosses[1].1)?,
        connector: prune_by_name(conn, adosses[2].0, &adosses[2].1)?,
        index_policy: prune_by_name(conn, adosses[3].0, &adosses[3].1)?,
        field_filter: prune_by_name(conn, adosses[4].0, &adosses[4].1)?,
        library_panel: prune_by_name(conn, adosses[5].0, &adosses[5].1)?,
        notification_policy: prune_by_name(conn, adosses[6].0, &adosses[6].1)?,
        dashboard: prune_by_name(conn, adosses[7].0, &adosses[7].1)?,
        panel: 0,
    };
    // Panneaux managed=1 orphelins (dashboard managed pruné/absent) — jamais les panneaux managed=2 (UI).
    c.panel = conn.execute(
        "DELETE FROM panel WHERE managed=1 AND dashboard_id NOT IN (SELECT id FROM dashboard)",
        [],
    )? as i64;
    Ok(c)
}

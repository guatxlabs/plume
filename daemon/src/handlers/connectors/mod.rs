//! Connecteurs de sources externes (#3a) + connecteur Defender (Microsoft Graph Security) : config
//! `DefenderCfg`, normalisation `normalize_defender_alert` (schéma `event`), OAuth `defender_token`,
//! poll paginé `poll_defender` (closure `fetch` mockable), boucle `run_due_connectors`/
//! `poll_one_connector`, et le CRUD/test/poll admin par-tenant.
//! Extrait de main.rs (refactor split #25 — byte-identique).
//! Split #35 : Defender / TAXII / http_pull en sous-modules ; runtime partage + re-exports (pure move).
use crate::*;
use crate::handlers::transaction_validee::{ouvrir_la_transaction_du_geste, refuser_le_geste_non_valide, tracer_apres_coup, valider_la_transaction};

mod defender;
mod taxii;
mod httppull;
mod presets;
pub(crate) use defender::*;
pub(crate) use taxii::*;
pub(crate) use httppull::*;
pub(crate) use presets::*;

/// FETCH de PRODUCTION GARDÉ SSRF : `ssrf_guard(url)` AVANT tout egress RÉEL (`http_call`),
/// au CHOKE-POINT UNIQUE partagé par TOUS les chemins réseau des connecteurs — poll de fond
/// (`run_due_connectors`), dry-run test (`connector_test` TAXII/Defender/http_pull) et poll manuel admin
/// (`connector_poll`). Rejette une URL admin-configurée pointant une ClusterIP interne / metadata cloud /
/// service d'un autre tenant AVANT la requête (défense en profondeur en SUS de la NetworkPolicy egress).
/// Passé PAR VALEUR (fn-pointer) AU CALL-SITE : n'est JAMAIS interposé dans `poll_one_connector`/`poll_*`, donc
/// ne gêne PAS les fetch MOCKÉS injectés en test (qui restent passés directement). Un hôte vendeur externe
/// normal (https public) reste autorisé — voir `ssrf_guard`.
pub(crate) fn guarded_http_call(method: &str, url: &str, headers: &[(&str, &str)], body: Option<&[u8]>) -> Result<HttpResp, String> {
    ssrf_guard(url)?;
    http_call(method, url, headers, body)
}

/// POLL LOOP PAR-TENANT (#3a) — modèle de run_due_rules. Sélectionne les connecteurs DUS (enabled=1 et
/// intervalle écoulé), les traite SÉQUENTIELLEMENT (budget 2 Go : jamais de fan-out), chacun sous catch_unwind
/// (un panic ne casse ni le tick, ni les autres connecteurs). INVARIANT : table vide / aucun enabled -> 0 ligne
/// -> retour immédiat (zéro I/O réseau, zéro écriture). Appelé via for_each_active_tenant (mode 0 = `default`).
/// REND SON BILAN (`P4.1-r`) : `Illisible` si la liste des connecteurs dus n'a pas pu être lue — aucune
/// source n'a été interrogée et rien ne le disait, pendant que chaque connecteur porte pourtant un
/// `last_error` pour SES propres échecs ; `Lue(n)` = connecteurs dus abandonnés (ligne indécodable, ou
/// panic capturé — celui-ci est aussi consigné dans `last_error`).
pub(crate) fn run_due_connectors(db: &Arc<Mutex<Connection>>, db_path: &str) -> crate::bilan_de_tick::BilanDeTick {
    let now_ts = now();
    let mut abandonnes = 0u32;
    // 1) SELECT des « dus » — table vide/aucun enabled => 0 ligne => court-circuit AVANT tout réseau/écriture.
    let due: Vec<(i64, String, String, String, String, Option<String>)> = {
        let conn = db.lock();
        // P-HEC — EXCLUT les connecteurs PUSH (`type IN ('aws_firehose','gcp_pubsub')`) : ils ne pollent JAMAIS
        // (les events arrivent PUSHÉS via POST /api/ingest/firehose ou /api/ingest/pubsub). Sans ce filtre, un
        // connecteur push `enabled=1` serait sélectionné DU, puis poll_one_connector tomberait dans la branche
        // « type non supporté » et poserait un last_error trompeur à chaque tick. Le filtre par TYPE garantit
        // qu'une source push (Firehose OU Pub/Sub) n'est JAMAIS pollée.
        let mut stmt = match conn.prepare(
            "SELECT id,type,config_json,secret,env_id,watermark FROM connector \
             WHERE enabled=1 AND type NOT IN ('aws_firehose','gcp_pubsub') AND (last_run IS NULL OR ?1 - last_run >= interval_s)",
        ) {
            Ok(s) => s,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("connecteurs", &e),
        };
        let rows = match stmt.query_map(params![now_ts], |r| {
            Ok((
                r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
                r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, Option<String>>(5)?,
            ))
        }) {
            Ok(r) => r,
            Err(e) => return crate::bilan_de_tick::tick_aveugle("connecteurs", &e),
        };
        let mut due = Vec::new();
        for r in rows {
            match r {
                Ok(x) => due.push(x),
                Err(_) => abandonnes += 1, // ligne indécodable : une source non interrogée, comptée
            }
        }
        due
    };
    if due.is_empty() {
        return crate::mesure_environnement::Mesure::Lue(abandonnes); // INVARIANT prod : rien à faire, aucun effet de bord
    }
    // 2) Chaque connecteur SÉQUENTIELLEMENT, isolé par catch_unwind (fail-safe : jamais de propagation).
    for (id, ctype, cfg_json, secret, env_id, watermark) in due {
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // garde SSRF au point d'ÉGRESS RÉEL (le fetch de PRODUCTION `guarded_http_call`) — couvre
            // 1re page, pagination ET l'URL `next` pilotée par la RÉPONSE (link_header/next_path, attaquant-
            // contrôlée), pour http_pull comme pour tout connecteur. En complément du confinement réseau.
            // Le wrap est AU CALL-SITE (pas dans poll_one_connector) pour ne PAS gêner les fetch mockés en test.
            poll_one_connector(db, db_path, id, &ctype, &cfg_json, &secret, &env_id, watermark.as_deref(), now_ts, guarded_http_call);
        }));
        if res.is_err() {
            // Panic capturé -> pose last_run (respect interval_s) + last_error, et CONTINUE avec les autres.
            abandonnes += 1;
            let conn = db.lock();
            let _ = conn.execute(
                "UPDATE connector SET last_run=?1, last_error=?2 WHERE id=?3",
                params![now_ts, "panic interne du connecteur (capturé)", id],
            );
        }
    }
    crate::mesure_environnement::Mesure::Lue(abandonnes)
}

/// Traite UN connecteur : pull (poll_defender) -> ingest par lot sous le lock writer (INSERT OR IGNORE sur
/// dedup, idempotent) -> avance watermark + last_ok/last_count. Échec (réseau/OAuth/parse/429) -> last_error
/// (message SANS secret) + last_run (anti-martèlement), watermark inchangé. FAIL-SAFE : ne remonte jamais.
pub(crate) fn poll_one_connector<F>(db: &Arc<Mutex<Connection>>, db_path: &str, id: i64, ctype: &str, cfg_json: &str,
                         secret: &str, env_id: &str, watermark: Option<&str>, now_ts: i64, fetch: F)
where
    F: Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String>,
{
    // TAXII 2.1 (#23) : pull STIX -> upsert IOC (magasin threat-intel). Chemin DISTINCT de Defender (qui
    // ingère des EVENTS) : ici on écrit dans `ioc`. Le cache de match est rafraîchi par la boucle rollup
    // (~120 s, server/mod.rs) -> les nouveaux IOC deviennent actifs au match-on-ingest au tick suivant.
    if ctype == "taxii2" {
        let cfg = TaxiiCfg::from_json(&serde_json::from_str::<Value>(cfg_json).unwrap_or_else(|_| json!({})));
        // source du feed = config.source (traçabilité) sinon stable `taxii:{id}`.
        let source = serde_json::from_str::<Value>(cfg_json).ok()
            .and_then(|v| v.get("source").and_then(|x| x.as_str()).map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format!("taxii:{id}"));
        match poll_taxii(&cfg, secret, watermark, fetch, taxii_max_pages()) {
            Ok(o) => {
                let conn = db.lock();
                let count = taxii_upsert_iocs(&conn, &o.iocs, &source, env_id, now_ts);
                let _ = conn.execute(
                    "UPDATE connector SET last_run=?1, last_ok=?1, last_error=NULL, last_count=?2, watermark=COALESCE(?3, watermark) WHERE id=?4",
                    params![now_ts, count, o.watermark, id],
                );
            }
            Err(e) => {
                let conn = db.lock();
                let _ = conn.execute("UPDATE connector SET last_run=?1, last_error=?2 WHERE id=?3", params![now_ts, e, id]);
            }
        }
        return;
    }
    // http_pull (#20/#22) : connecteur GÉNÉRIQUE config-driven. Pull -> mapping field_map -> events ->
    // ingest par le chemin d'ENRICHISSEMENT `ingest_events_batch_env` (SUPERSET/consistance) : un event
    // PULLÉ passe désormais par les MÊMES traitements qu'un event ingéré nativement — parsers, extracteur
    // générique, MATCH-ON-INGEST threat-intel (-> fields.threat_intel / ti_match=1, composition RBA ti->risk)
    // — au lieu de court-circuiter par store().insert_event. `db_path` (registre parsers + cache IOC du
    // tenant) et `env_id` (PAR-CONNECTEUR) sont threadés : la ligne enrichie atterrit dans le bon tenant/env
    // avec sémantique de ligne IDENTIQUE (ts/host/source/category/severity/fields/dedup) PLUS l'enrichissement.
    // INSERT OR IGNORE dedup préservé ; `last_count` = lignes RÉELLEMENT insérées (dédup-aware). Fail-safe :
    // un ROLLBACK de batch (disque plein / verrou) -> last_error, watermark non avancé.
    if ctype == "http_pull" {
        let cfg = HttpPullCfg::from_json(&serde_json::from_str::<Value>(cfg_json).unwrap_or_else(|_| json!({})));
        match poll_http_pull(&cfg, secret, watermark, id, fetch, httppull_max_pages()) {
            Ok(o) => {
                let conn = db.lock();
                match ingest_events_batch_env(&conn, db_path, &o.events, now_ts, None, None, Some(env_id)) {
                    Ok((_processed, inserted)) => {
                        let _ = conn.execute(
                            "UPDATE connector SET last_run=?1, last_ok=?1, last_error=NULL, last_count=?2, watermark=COALESCE(?3, watermark) WHERE id=?4",
                            params![now_ts, inserted as i64, o.watermark, id],
                        );
                    }
                    Err(_) => {
                        // Batch ROLLBACK (fail-safe : ingest_events_batch_env a déjà annulé) : watermark NON
                        // avancé (rejouable au prochain tick), last_error posé, pas de martèlement (last_run).
                        let _ = conn.execute(
                            "UPDATE connector SET last_run=?1, last_error=?2 WHERE id=?3",
                            params![now_ts, "échec d'ingestion (batch annulé, rejouable)", id],
                        );
                    }
                }
            }
            Err(e) => {
                let conn = db.lock();
                let _ = conn.execute("UPDATE connector SET last_run=?1, last_error=?2 WHERE id=?3", params![now_ts, e, id]);
            }
        }
        return;
    }
    if ctype != "defender" {
        let conn = db.lock();
        let _ = conn.execute(
            "UPDATE connector SET last_run=?1, last_error=?2 WHERE id=?3",
            params![now_ts, format!("type de connecteur non supporté : {ctype}"), id],
        );
        return;
    }
    let cfg = DefenderCfg::from_json(&serde_json::from_str::<Value>(cfg_json).unwrap_or_else(|_| json!({})));
    let outcome = poll_defender(&cfg, secret, watermark, id, fetch, defender_max_pages());
    match outcome {
        Ok(o) => {
            // #31 (suivi de 224d526, qui a routé http_pull mais différé Defender) : les alertes Defender
            // passent DÉSORMAIS par le chemin d'ENRICHISSEMENT `ingest_events_batch_env` (SUPERSET/consistance)
            // au lieu de court-circuiter par store().insert_event. Un event PULLÉ reçoit donc les MÊMES
            // traitements qu'un event natif — parsers + extracteur générique + MATCH-ON-INGEST threat-intel
            // (-> fields.threat_intel / ti_match=1, composition RBA ti->risk). La sémantique de LIGNE est
            // PRÉSERVÉE À L'IDENTIQUE : `source='defender'` littéral, ts/category/severity/message/host/dedup,
            // fields (round-trip serde canonique depuis fields_json), env_id PAR-CONNECTEUR ; le SEUL ajout est
            // l'enrichissement. INSERT OR IGNORE dedup conservé (recouvrement de watermark idempotent) ;
            // `last_count` = lignes RÉELLEMENT insérées (dédup-aware), MÊME sémantique qu'avant.
            // NormEvent (Defender est LIVE) -> Value (schéma d'ingest) : mapping 1:1 des champs, `fields` reparsé
            // depuis `fields_json` (serde Map trié -> re-sérialisation byte-identique hors enrichissement).
            let evs: Vec<Value> = o.events.iter().map(|ev| json!({
                "source": "defender",
                "ts": ev.ts,
                "category": ev.category,
                "severity": ev.severity,
                "message": ev.message,
                "host": ev.host,
                "dedup": ev.dedup,
                "fields": serde_json::from_str::<Value>(&ev.fields_json).unwrap_or_else(|_| json!({})),
            })).collect();
            let conn = db.lock();
            // Ingest par LOT sous un seul lock writer. INSERT OR IGNORE sur l'index dedup UNIQUE -> le
            // recouvrement de watermark (borne inclusive) n'ajoute pas de doublon.
            match ingest_events_batch_env(&conn, db_path, &evs, now_ts, None, None, Some(env_id)) {
                Ok((_processed, inserted)) => {
                    // Avance le watermark (COALESCE : None au cold-start sans résultat -> conserve l'existant).
                    let _ = conn.execute(
                        "UPDATE connector SET last_run=?1, last_ok=?1, last_error=NULL, last_count=?2, watermark=COALESCE(?3, watermark) WHERE id=?4",
                        params![now_ts, inserted as i64, o.watermark, id],
                    );
                }
                Err(_) => {
                    // Batch ROLLBACK (fail-safe : ingest_events_batch_env a déjà annulé) : watermark NON avancé
                    // (rejouable au prochain tick), last_error posé, pas de martèlement (last_run).
                    let _ = conn.execute(
                        "UPDATE connector SET last_run=?1, last_error=?2 WHERE id=?3",
                        params![now_ts, "échec d'ingestion (batch annulé, rejouable)", id],
                    );
                }
            }
        }
        Err(e) => {
            let conn = db.lock();
            // e = message SANS secret (statut/motif). last_run posé même en échec -> pas de martèlement.
            let _ = conn.execute(
                "UPDATE connector SET last_run=?1, last_error=?2 WHERE id=?3",
                params![now_ts, e, id],
            );
        }
    }
}
// ---- #3a CONNECTEURS de sources externes (Defender) : CRUD + test. Toutes les routes ADMIN-ONLY (serveur)
//      + PAR-TENANT (req_db). Le `secret` (client_secret) n'est JAMAIS renvoyé (GET expose has_secret:bool ;
//      update avec secret vide/omis = conserve l'existant). ----
pub(crate) async fn connectors_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    crate::req_conn!(st, au, conn);
    // NB : `secret != ''` -> has_secret (booléen) ; la colonne secret n'est JAMAIS projetée dans la réponse.
    // P-HEC : `has_key` = une clé de livraison PUSH (Firehose OU Pub/Sub) est LIÉE à ce connecteur (jamais la clé
    // elle-même — seul son SHA-256 vit dans `token`). La colonne `secret` reste NON projetée (has_secret booléen).
    //
    // `P10.7-f` — LA LISTE DES CONNECTEURS EST ENTIÈRE OU REFUSÉE. Avant : `Err(_) => Vec::new()` sur la
    // PRÉPARATION et `.map(|rows| rows.flatten().collect()).unwrap_or_default()` sur le parcours — DEUX
    // voies de silence pour un seul corps. Un itérateur de lignes rusqlite rend des `Result` UNE LIGNE À
    // LA FOIS : le mappeur peut échouer sur une seule ligne sans que la requête ait échoué (cache de
    // schéma de pool périmé rendant « no such table » au PREMIER pas, colonne ajoutée par une migration
    // que la connexion qui sert ne voit pas encore, `config_json` ou `last_error` non textuel), et
    // l'aplatissement jetait CETTE ligne-là en rendant la suite sous un corps rigoureusement identique à
    // celui d'une liste complète.
    //
    // CE QUE LA LIGNE AVALÉE COÛTAIT, ET C'EST PROPRE À CETTE LISTE : un connecteur absent se lit « cette
    // source n'est pas branchée » — c'est même la phrase que la console PEINT quand le tableau est vide
    // (`web/connectors.js:29` : « aucun connecteur … rien n'est collecté »). Or le connecteur avalé
    // continue d'EXISTER et de TOURNER : `run_due_connectors` lit la table `connector`, pas cette vue, et
    // il interroge le vendeur, ingère, avance son `watermark` sous son `env_id`. On en déclare donc un
    // SECOND vers la même source, et les deux collectent en parallèle. Pire pour une surface d'EGRESS :
    // son `last_error`, son `last_ok` et son `has_key` — la seule façon de voir qu'une clé de livraison
    // PUSH est liée à ce connecteur — disparaissent avec lui, et c'est précisément ce qu'un
    // administrateur vient lire ici.
    //
    // POURQUOI UN CINQ CENTS NOMMÉ ET NON `error` DANS LE CORPS : ce corps est un TABLEAU NU
    // (`Json(Value::Array(..))`), il n'a aucune clé où poser l'aveu, et lui en donner une changerait le
    // contrat. C'est la forme des fournisseurs d'identité (`idp_providers_list`, rang un) et des deux
    // tableaux nus du rang quatre (`ai_providers_list`, `destinations_list`), reprise à la lettre :
    // `server_err(CAUSE_LISTE_ILLISIBLE)`. Elle est LUE DE BOUT EN BOUT ici — `web/connectors.js:26`
    // passe par `fetchInto`, qui écrit la cause dans le panneau sur tout non-2xx.
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare(
            "SELECT id,type,name,enabled,config_json,interval_s,env_id,watermark,last_run,last_ok,last_count,last_error,(secret != ''), \
                    EXISTS(SELECT 1 FROM token WHERE token.connector_id=connector.id AND token.kind IN ('firehose','gcp_pubsub')) \
             FROM connector ORDER BY id",
        )
        .and_then(|mut stmt| {
            stmt.query_map([], |r| {
                let cfg_json: String = r.get(4)?;
                let last_error: Option<String> = r.get(11)?;
                Ok(json!({
                    "id": r.get::<_, i64>(0)?,
                    "type": r.get::<_, String>(1)?,
                    "name": r.get::<_, String>(2)?,
                    "enabled": r.get::<_, i64>(3)? != 0,
                    "config": serde_json::from_str::<Value>(&cfg_json).unwrap_or_else(|_| json!({})),
                    "interval_s": r.get::<_, i64>(5)?,
                    "env_id": r.get::<_, String>(6)?,
                    "watermark": r.get::<_, Option<String>>(7)?,
                    "last_run": r.get::<_, Option<i64>>(8)?,
                    "last_ok": r.get::<_, Option<i64>>(9)?,
                    "last_count": r.get::<_, i64>(10)?,
                    "last_error": last_error,
                    "has_secret": r.get::<_, i64>(12)? != 0,
                    "has_key": r.get::<_, i64>(13)? != 0, // P-HEC : clé de livraison push liée (jamais la clé)
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    match lues {
        Ok(list) => Json(Value::Array(list)).into_response(),
        Err(_) => server_err(crate::handlers::liste_bornee::CAUSE_LISTE_ILLISIBLE),
    }
}

pub(crate) async fn connector_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    let ctype = b.get("type").and_then(|x| x.as_str()).unwrap_or("defender").to_string();
    if ctype != "defender" && ctype != "taxii2" && ctype != "http_pull" {
        return bad_req("type non supporté (defender | taxii2 | http_pull)");
    }
    let config = b.get("config").cloned().unwrap_or_else(|| json!({}));
    if ctype == "http_pull" {
        // GÉNÉRIQUE (#20/#22) : url (ou api_root+path) + records_path + field_map (objet non vide) requis.
        let has_url = config.get("url").and_then(|x| x.as_str()).map_or(false, |s| !s.trim().is_empty())
            || config.get("api_root").and_then(|x| x.as_str()).map_or(false, |s| !s.trim().is_empty());
        // records_path DOIT être présent (chaîne) ; chaîne vide acceptée = racine de la réponse est le tableau.
        let has_records = config.get("records_path").and_then(|x| x.as_str()).is_some();
        let fm_ok = config.get("field_map").and_then(|x| x.as_object()).map_or(false, |o| !o.is_empty());
        if !has_url {
            return bad_req("config.url (ou config.api_root) requis (http_pull)");
        }
        if !has_records {
            return bad_req("config.records_path requis (http_pull)");
        }
        if !fm_ok {
            return bad_req("config.field_map (objet non vide) requis (http_pull)");
        }
    } else if ctype == "taxii2" {
        let api_root = config.get("api_root").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let collection_id = config.get("collection_id").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        if api_root.is_empty() || collection_id.is_empty() {
            return bad_req("config.api_root et config.collection_id requis (TAXII 2.1)");
        }
    } else {
        let azure_tenant = config.get("azure_tenant").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        let client_id = config.get("client_id").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
        if azure_tenant.is_empty() || client_id.is_empty() {
            return bad_req("config.azure_tenant et config.client_id requis");
        }
    }
    let env_id = b.get("env_id").and_then(|x| x.as_str()).unwrap_or("prod").to_string();
    if !env_slug_ok(&env_id) {
        return bad_req("env_id invalide (alnum + _/-)");
    }
    let name = b.get("name").and_then(|x| x.as_str()).unwrap_or("Connecteur").to_string();
    // enabled:false par défaut à la création (l'admin TESTE avant d'activer).
    let enabled = b.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false) as i64;
    // interval_s >= 60 (plancher anti-martèlement).
    let interval_s = b.get("interval_s").and_then(|x| x.as_i64()).unwrap_or(300).max(60);
    let secret = b.get("secret").and_then(|x| x.as_str()).unwrap_or("").to_string();
    crate::req_conn!(st, au, conn);
    // M3 : création + audit fail-closed. Le `secret` (client_secret OAuth) n'est JAMAIS logué : l'audit ne
    // porte que type/name/enabled/env_id + un booléen has_secret.
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "connecteurs", &format!("création du connecteur '{name}'"), CAUSE_CONNECTEUR_NON_CREE_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute(
            "INSERT INTO connector(type,name,enabled,config_json,secret,interval_s,env_id,created) \
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![ctype, name, enabled, config.to_string(), secret, interval_s, env_id, now()],
        )?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn,
            "config.connector.create",
            &format!("connecteur '{name}' ({ctype}) créé par {}", au.name),
            3,
            &format!("connecteur externe '{name}' ({ctype}, enabled={}, env={env_id}) créé par {}", enabled != 0, au.name),
            &json!({ "id": id, "type": ctype, "enabled": enabled != 0, "env_id": env_id, "has_secret": !secret.is_empty(), "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        // `P10.26-a` — l'identifiant n'est rendu qu'une fois la transaction VALIDÉE (voir `CAUSE_CONNECTEUR_NON_CREE`).
        Ok(id) => match valider_la_transaction(&conn) {
            Ok(()) => Json(json!({ "id": id, "enabled": enabled != 0 })).into_response(),
            Err(e) => refuser_le_geste_non_valide("connecteurs", &format!("création du connecteur '{name}'"), &e, CAUSE_CONNECTEUR_NON_CREE),
        },
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

pub(crate) async fn connector_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    // Valide AVANT écriture : env_id conforme si fourni.
    if let Some(v) = b.get("env_id").and_then(|x| x.as_str()) {
        if !env_slug_ok(v) {
            return bad_req("env_id invalide (alnum + _/-)");
        }
    }
    crate::req_conn!(st, au, conn);
    if conn.query_row("SELECT 1 FROM connector WHERE id=?1", params![id], |_| Ok(())).is_err() {
        return not_found("connecteur introuvable");
    }
    // M3 : mutation + audit fail-closed. Le `secret` (rotation client_secret) n'est JAMAIS logué -> l'audit
    // note un booléen `secret_rotated` + les NOMS des champs modifiés (jamais leurs valeurs).
    if let Err(refus) = ouvrir_la_transaction_du_geste(&conn, "connecteurs", &format!("modification du connecteur #{id}"), CAUSE_CONNECTEUR_INCHANGE_TRANSACTION_NON_OUVERTE) {
        return refus;
    }
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(v) = b.get("name").and_then(|x| x.as_str()) {
            conn.execute("UPDATE connector SET name=?1 WHERE id=?2", params![v, id])?;
        }
        if let Some(v) = b.get("enabled").and_then(|x| x.as_bool()) {
            conn.execute("UPDATE connector SET enabled=?1 WHERE id=?2", params![v as i64, id])?;
        }
        if let Some(v) = b.get("interval_s").and_then(|x| x.as_i64()) {
            conn.execute("UPDATE connector SET interval_s=?1 WHERE id=?2", params![v.max(60), id])?;
        }
        if let Some(v) = b.get("env_id").and_then(|x| x.as_str()) {
            conn.execute("UPDATE connector SET env_id=?1 WHERE id=?2", params![v, id])?;
        }
        if let Some(v) = b.get("config") {
            conn.execute("UPDATE connector SET config_json=?1 WHERE id=?2", params![v.to_string(), id])?;
        }
        // SECRET : mis à jour UNIQUEMENT si fourni ET non vide -> secret omis/vide = conserver l'existant
        // (jamais d'écrasement par vide). Le secret n'est jamais renvoyé, jamais loggé.
        let mut secret_rotated = false;
        if let Some(s) = b.get("secret").and_then(|x| x.as_str()) {
            if !s.is_empty() {
                conn.execute("UPDATE connector SET secret=?1 WHERE id=?2", params![s, id])?;
                secret_rotated = true;
            }
        }
        let changed: Vec<&str> = ["name", "enabled", "interval_s", "env_id", "config"].iter().copied().filter(|k| b.get(*k).is_some()).collect();
        audit_config_change(
            &conn,
            "config.connector.update",
            &format!("connecteur #{id} modifié ({}{}) par {}", changed.join(","), if secret_rotated { ",secret" } else { "" }, au.name),
            3,
            &format!("connecteur #{id} modifié (champs: {}{}) par {}", changed.join(","), if secret_rotated { ", secret rotaté" } else { "" }, au.name),
            &json!({ "id": id, "changed": changed, "secret_rotated": secret_rotated, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        // `P10.26-a` — « modifié » n'est rendu qu'une fois la transaction VALIDÉE (voir `CAUSE_CONNECTEUR_INCHANGE`).
        Ok(()) => match valider_la_transaction(&conn) {
            Ok(()) => Json(json!({ "ok": true })).into_response(),
            Err(e) => refuser_le_geste_non_valide("connecteurs", &format!("modification du connecteur #{id}"), &e, CAUSE_CONNECTEUR_INCHANGE),
        },
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

pub(crate) async fn connector_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    crate::req_conn!(st, au, conn);
    // M3 : suppression + audit fail-closed (retirer une source externe = mutation de config auditable).
    // `P10.28-p` — LE `BEGIN` REFUSÉ EST NOMMÉ. La forme d'avant (`BEGIN IMMEDIATE` nu) rendait un 500 « verrou base
    // indisponible » et ne disait rien au journal. MESURÉ le 2026-09-25 (témoins `isdl_`) : sous un `BEGIN` refusé comme
    // sous la transaction d'un autre geste restée ouverte, 500 générique — rien n'était écrit (le connecteur et sa clé
    // de livraison restaient en place, la transaction étrangère intacte), mais personne n'apprenait que la révocation
    // des clés n'avait pas eu lieu. Désormais 503, et la cause le dit.
    if let Err(refus) = ouvrir_la_transaction_du_geste(
        &conn,
        "connecteurs",
        &format!("suppression du connecteur #{id} et révocation de ses clés de livraison"),
        CAUSE_CONNECTEUR_NON_SUPPRIME_TRANSACTION_NON_OUVERTE,
    ) {
        return refus;
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM connector WHERE id=?1", params![id])?;
        // P-HEC : révoquer DURABLEMENT la/les clé(s) de livraison PUSH liée(s) (`token.connector_id=id`) DANS LA
        // MÊME transaction que la suppression du connecteur. Sans ça, la clé orpheline survit et — via la RÉUTILISATION
        // de rowid SQLite (INTEGER PRIMARY KEY sans AUTOINCREMENT) — pourrait se ré-authentifier contre un NOUVEAU
        // connecteur qui hériterait de l'ancien id : une clé que l'admin croyait révoquée redeviendrait valide.
        // Scopé à kind IN ('firehose','gcp_pubsub') : NE touche QUE les clés de livraison push (jamais
        // datasource/client/agent/HEC, qui n'utilisent pas connector_id — explicite par sécurité).
        conn.execute("DELETE FROM token WHERE connector_id=?1 AND kind IN ('firehose','gcp_pubsub')", params![id])?;
        audit_config_change(
            &conn,
            "config.connector.delete",
            &format!("connecteur #{id} supprimé par {}", au.name),
            3,
            &format!("connecteur externe #{id} supprimé par {}", au.name),
            &json!({ "id": id, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        // `P10.26-a` — le 204 n'est rendu qu'une fois la transaction VALIDÉE : c'est elle qui révoque les clés de
        // livraison (voir `CAUSE_CONNECTEUR_NON_SUPPRIME`).
        Ok(()) => match valider_la_transaction(&conn) {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => refuser_le_geste_non_valide("connecteurs", &format!("suppression du connecteur #{id} et révocation de ses clés de livraison"), &e, CAUSE_CONNECTEUR_NON_SUPPRIME),
        },
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            server_err(format!("échec transaction audit (aucune modification): {e}"))
        }
    }
}

// `P10.26-a` — UN CONNECTEUR N'EST ANNONCÉ CRÉÉ, MODIFIÉ OU SUPPRIMÉ QU'UNE FOIS SA TRANSACTION VALIDÉE.
//
// LE DÉFAUT, MESURÉ LE 2026-09-24 SUR LA FORME D'AVANT (`COMMIT` refusé par un autorisateur SQLite, relecture à froid
// sur une connexion neuve) : les trois gestes ignoraient le résultat de leur `COMMIT` et laissaient la transaction
// PENDANTE sur l'écrivain partagé. Tout ce qui lit par cet écrivain voyait donc l'état non validé :
//  * suppression d'une source push : 204, et la clé de livraison était refusée par son récepteur tant que la
//    transaction pendait ; à froid, le connecteur ET la clé étaient là, et dès la transaction annulée la clé
//    AUTHENTIFIAIT de nouveau. C'est le geste que `DECISION_SUR_LES_JETONS_DU_COMPTE_SUPPRIME` prescrit pour une clé
//    conservée : la révocation annoncée ne l'était pas. La trace `config.connector.delete` était lisible, elle aussi,
//    par qui lit l'écrivain — un envoi de puits d'export l'aurait copiée (lu ; l'envoi est mesuré sous `P10.26-c`) ;
//  * création : 200 et un identifiant ; le connecteur activé était SÉLECTIONNÉ comme dû par la collecte de fond
//    (même requête que `run_due_connectors`), qui aurait présenté son secret au vendeur, sans connecteur à froid ;
//  * modification (désactivation + rotation du secret) : 200 ; pour ce processus désactivé et nouveau secret, à froid
//    ACTIF avec l'ANCIEN secret — au redémarrage, le connecteur désactivé collecte de nouveau, avec le secret que la
//    rotation devait retirer.
// Dans les trois cas la transaction restait ouverte, et un geste suivant qui ouvre la sienne échouait en 500 « verrou
// base indisponible » (mesuré sur une création après la suppression refusée).

/// `P10.26-a` — le `COMMIT` de la création d'un connecteur refusé.
pub(crate) const CAUSE_CONNECTEUR_NON_CREE: &str = "CONNECTEUR NON CRÉÉ : la base n'a pas validé la transaction \
     (COMMIT refusé) et l'a annulée — aucun connecteur n'est écrit, aucune collecte ne l'interrogera, et aucune trace \
     n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_CONNECTEUR_NON_CREE_TRANSACTION_NON_OUVERTE: &str = "CONNECTEUR NON CRÉÉ : la base n'a pas \
     pris la transaction de la création (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur \
     l'écrivain) — RIEN n'est écrit : aucun connecteur n'est écrit, aucune collecte ne l'interrogera, et aucune \
     trace n'est écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";

/// `P10.26-a` — le `COMMIT` de la modification d'un connecteur refusé.
pub(crate) const CAUSE_CONNECTEUR_INCHANGE: &str = "CONNECTEUR INCHANGÉ : la base n'a pas validé la transaction \
     (COMMIT refusé) et l'a annulée — ni son activation, ni sa configuration, ni son secret ne changent : un connecteur \
     que vous désactiviez collecte toujours, un secret que vous remplaciez est toujours celui qu'il présente au \
     vendeur, et aucune trace n'est écrite. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou \
     verrouillée.";
/// `P10.28-d` — le `BEGIN` de ce geste refusé (la forme d'avant rendait une réponse générique et taisait le journal).
pub(crate) const CAUSE_CONNECTEUR_INCHANGE_TRANSACTION_NON_OUVERTE: &str = "CONNECTEUR INCHANGÉ : la base n'a pas \
     pris la transaction de la modification (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante \
     sur l'écrivain) — RIEN n'est écrit : ni son activation, ni sa configuration, ni son secret ne changent : un \
     connecteur que vous désactiviez collecte toujours, un secret que vous remplaciez est toujours celui qu'il \
     présente au vendeur, et aucune trace n'est écrite. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou \
     bloqué.";

/// `P10.26-a` — le `COMMIT` de la suppression d'un connecteur, qui révoque ses clés de livraison, refusé.
pub(crate) const CAUSE_CONNECTEUR_NON_SUPPRIME: &str = "CONNECTEUR NON SUPPRIMÉ, SES CLÉS DE LIVRAISON NE SONT PAS \
     RÉVOQUÉES : la base n'a pas validé la transaction (COMMIT refusé) et l'a annulée — le connecteur est toujours là \
     et collecte toujours, chaque clé de livraison qui lui est liée AUTHENTIFIE ENCORE sur son récepteur, et aucune \
     trace n'est écrite. Réessayez : c'est ce geste qui révoque ces clés ; si le refus persiste, la base est en lecture \
     seule, pleine ou verrouillée.";

/// `P10.28-p` — le `BEGIN` de la suppression d'un connecteur refusé : rien n'est écrit, et c'est la révocation des clés
/// de livraison qui n'a pas lieu. L'ouverture est celle que la console lit comme « rien n'a changé » pour un `BEGIN`
/// refusé (`OUVERTURE_DE_LA_TRANSACTION_NON_PRISE`, `web/core.js`).
pub(crate) const CAUSE_CONNECTEUR_NON_SUPPRIME_TRANSACTION_NON_OUVERTE: &str = "CONNECTEUR NON SUPPRIMÉ, SES CLÉS DE \
     LIVRAISON NE SONT PAS RÉVOQUÉES : la base n'a pas pris la transaction du retrait (BEGIN refusé : verrou tenu, ou \
     transaction d'un autre geste pendante sur l'écrivain) — RIEN n'est écrit : le connecteur est toujours là et \
     collecte toujours, chaque clé de livraison qui lui est liée AUTHENTIFIE ENCORE sur son récepteur, et aucune trace \
     n'est écrite. Réessayez : c'est ce geste qui révoque ces clés ; s'il est refusé encore, l'écrivain est occupé ou \
     bloqué.";

/// `P10.26-x` — le poll manuel a eu lieu, mais sa trace d'audit n'a pas été écrite (champ `trace_non_ecrite` de la réponse).
pub(crate) const CAUSE_TRACE_DU_POLL_MANUEL_NON_ECRITE: &str = "TRACE NON ÉCRITE : le poll manuel a eu lieu (ce qui \
     est collecté est collecté), mais la base n'a pas pris sa trace d'audit — le registre ne dit pas qui l'a \
     déclenché ni combien d'events il a rapportés. Le journal du démon nomme le refus.";

/// DRY-RUN : OAuth + 1 page Graph, N'INGÈRE PAS et NE RENVOIE NI le contenu des alertes NI le secret —
/// seulement { ok, sample_count, error }. `error` = statut/motif (jamais le corps, jamais le secret).
pub(crate) async fn connector_test(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    let row = {
        crate::req_conn!(st, au, conn);
        conn.query_row(
            "SELECT type,config_json,secret,watermark FROM connector WHERE id=?1",
            params![id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?)),
        ).ok()
    };
    let (ctype, cfg_json, secret, watermark) = match row {
        Some(x) => x,
        None => return not_found("connecteur introuvable"),
    };
    // TAXII 2.1 : DRY-RUN = 1 page d'objets, N'UPSERT PAS ; renvoie le nombre d'IOC traduisibles observés.
    if ctype == "taxii2" {
        let cfg = TaxiiCfg::from_json(&serde_json::from_str::<Value>(&cfg_json).unwrap_or_else(|_| json!({})));
        let res = tokio::task::spawn_blocking(move || {
            // DRY-RUN TAXII gardé SSRF au point d'égress (même choke-point que la collecte) :
            // un `api_root` admin-configuré pointant une cible interne est refusé AVANT la requête.
            poll_taxii(&cfg, &secret, watermark.as_deref(), guarded_http_call, 1)
        })
        .await
        .unwrap_or_else(|_| Err("échec interne du test".to_string()));
        return match res {
            Ok(o) => Json(json!({ "ok": true, "sample_count": o.iocs.len(), "skipped": o.skipped, "error": Value::Null })).into_response(),
            Err(e) => Json(json!({ "ok": false, "sample_count": 0, "error": e })).into_response(),
        };
    }
    // http_pull (#20/#22) : DRY-RUN = 1 page, N'INGÈRE PAS ; renvoie un ÉCHANTILLON des events MAPPÉS (max
    // 5) pour prévisualisation UI (le field_map produit-il ce qu'on attend ?). Aucun secret n'y transite.
    if ctype == "http_pull" {
        let cfg = HttpPullCfg::from_json(&serde_json::from_str::<Value>(&cfg_json).unwrap_or_else(|_| json!({})));
        let res = tokio::task::spawn_blocking(move || {
            // DRY-RUN aussi gardé SSRF au point d'égress (même choke-point que la collecte).
            poll_http_pull(&cfg, &secret, watermark.as_deref(), id, guarded_http_call, 1)
        })
        .await
        .unwrap_or_else(|_| Err("échec interne du test".to_string()));
        return match res {
            Ok(o) => {
                let sample: Vec<Value> = o.events.iter().take(5).cloned().collect();
                Json(json!({ "ok": true, "sample_count": o.events.len(), "sample": sample, "error": Value::Null })).into_response()
            }
            Err(e) => Json(json!({ "ok": false, "sample_count": 0, "sample": [], "error": e })).into_response(),
        };
    }
    if ctype != "defender" {
        return Json(json!({ "ok": false, "sample_count": 0, "error": format!("type non supporté : {ctype}") })).into_response();
    }
    let cfg = DefenderCfg::from_json(&serde_json::from_str::<Value>(&cfg_json).unwrap_or_else(|_| json!({})));
    // Réseau -> spawn_blocking (ne bloque pas l'exécuteur async). 1 seule page (max_pages=1), aucun ingest.
    let res = tokio::task::spawn_blocking(move || {
        // DRY-RUN Defender gardé SSRF au point d'égress (choke-point partagé) : un
        // `azure_tenant`/endpoint admin-configuré résolvant vers une cible interne est refusé AVANT la requête.
        poll_defender(&cfg, &secret, watermark.as_deref(), id, guarded_http_call, 1)
    })
    .await
    .unwrap_or_else(|_| Err("échec interne du test".to_string()));
    match res {
        Ok(o) => Json(json!({ "ok": true, "sample_count": o.events.len(), "error": Value::Null })).into_response(),
        Err(e) => Json(json!({ "ok": false, "sample_count": 0, "error": e })).into_response(),
    }
}

/// POST /api/connectors/{id}/poll — DÉCLENCHE UN poll+ingest IMMÉDIAT de CE connecteur. ADMIN-only (serveur,
/// re-check ici EN PLUS du path-guard) + PAR-TENANT (req_db). RÉUTILISE `poll_one_connector` (#3a) : chemin
/// d'ingestion IDENTIQUE au poll loop de fond (INSERT OR IGNORE dedup, avance watermark + last_ok/last_count/
/// last_error). FAIL-SAFE : `poll_one_connector` ne remonte JAMAIS (toute erreur réseau/OAuth/parse ->
/// connector.last_error, sans secret) ; le réseau tourne dans spawn_blocking (n'occupe pas l'exécuteur async).
/// Renvoie { ok, count, error? } RELU depuis la base APRÈS le poll (feedback fidèle, jamais le secret).
pub(crate) async fn connector_poll(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    // Existence dans la base du TENANT courant (req_db) — 404 sinon (jamais de poll d'un id d'un autre tenant).
    let row = {
        crate::req_conn!(st, au, conn);
        conn.query_row(
            "SELECT type,config_json,secret,env_id,watermark FROM connector WHERE id=?1",
            params![id],
            |r| Ok((
                r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
                r.get::<_, String>(3)?, r.get::<_, Option<String>>(4)?,
            )),
        ).ok()
    };
    let (ctype, cfg_json, secret, env_id, watermark) = match row {
        Some(x) => x,
        None => return not_found("connecteur introuvable"),
    };
    // RÉUTILISE la logique de poll de fond (#3a) sur la base du tenant. spawn_blocking : le réseau/l'ingest
    // sous lock writer ne bloquent pas l'exécuteur. FAIL-SAFE : poll_one_connector avale ses erreurs (last_error).
    let rc = req_db(&st, &au);
    let db_path = req_db_path(&st, &au); // registre parsers + cache IOC du tenant courant (chemin d'enrichissement http_pull)
    let now_ts = now();
    let _ = tokio::task::spawn_blocking(move || {
        // POLL MANUEL admin gardé SSRF au point d'égress RÉEL (`guarded_http_call`), MÊME
        // choke-point que le poll de fond : un connecteur admin-configuré vers une ClusterIP/metadata/autre-tenant
        // est refusé AVANT la requête (last_error SSRF, aucun egress). Cf. run_due_connectors.
        poll_one_connector(&rc, &db_path, id, &ctype, &cfg_json, &secret, &env_id, watermark.as_deref(), now_ts, guarded_http_call);
    })
    .await;
    // Relit last_count/last_error écrits par poll_one_connector -> feedback (jamais le secret ni le corps HTTP).
    // M3 : le poll manuel déclenché par l'admin est AUDITÉ (ledger + event) -> plus d'angle mort. L'audit est
    // POST-poll (le poll lui-même est fail-safe : poll_one_connector avale ses erreurs -> last_error, jamais
    // de rollback possible du réseau) ; on trace donc l'ACTION opérateur (qui, quand, combien d'events) SANS
    // gater le réseau dans une transaction (ne jamais tenir le lock writer pendant l'I/O réseau).
    let ((count, error), trace): ((i64, Option<String>), Result<(), &'static str>) = {
        crate::req_conn!(st, au, conn);
        let ce = conn.query_row(
            "SELECT last_count,last_error FROM connector WHERE id=?1",
            params![id],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?)),
        ).unwrap_or((0, None));
        // `P10.26-x` — LA TRACE EST ÉCRITE APRÈS COUP, ET SON ABSENCE SE DIT (même forme que l'envoi manuel d'une
        // destination) : un `BEGIN`, un audit ou un `COMMIT` refusé n'est plus tu, la réponse porte `trace_non_ecrite`.
        let trace = tracer_apres_coup(&conn, "connecteurs", &format!("poll manuel du connecteur #{id}"), CAUSE_TRACE_DU_POLL_MANUEL_NON_ECRITE, || {
            audit_config_change(
                &conn,
                "config.connector.poll",
                &format!("poll manuel du connecteur #{id} par {} (count={})", au.name, ce.0),
                2,
                &format!("poll manuel du connecteur externe #{id} par {} : {} event(s)", au.name, ce.0),
                &json!({ "id": id, "count": ce.0, "ok": ce.1.is_none(), "actor": au.name }).to_string(),
            )
        });
        (ce, trace)
    };
    let mut corps = json!({ "ok": error.is_none(), "count": count, "error": error });
    if let Err(cause) = trace {
        corps["trace_non_ecrite"] = json!(cause);
    }
    Json(corps).into_response()
}

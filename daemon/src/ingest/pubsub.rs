//! P-HEC — récepteur d'ingest PUSH GCP Pub/Sub (Cloud Audit Logs), vendor-agnostic. SIBLING du récepteur
//! AWS Firehose (`ingest/firehose.rs`) : MÊME primitive de token, MÊME spool, MÊMES bornes DoS, MÊME seam
//! field-map->CIM. Les SEULES différences sont (1) le CADRAGE fil (enveloppe Pub/Sub `{"message":{…}}` vs
//! `{"records":[…]}` Firehose) et (2) le TRANSPORT d'auth (query `?token=` vs header `X-Amz-Firehose-Access-Key`).
//!
//! OBJECTIF (sur-ensemble / zéro-credential-cloud) : un client GCP branche un abonnement Pub/Sub « push » sur
//! `POST /api/ingest/pubsub?token=<clé>` et POUSSE ses Cloud Audit Logs vers plume — plume ne détient AUCUNE
//! clé GCP (aucun compte de service, aucun JWT SA). L'auth est une CLÉ DE LIVRAISON (query `?token=`, mintée par
//! plume à la création de la source push, LIÉE à un connecteur push -> son `field_map`/`env_id`).
//!
//! RÉUTILISATION MAXIMALE (aucune nouvelle primitive crypto / d'ingest / de mapping) :
//!   - AUTH : `pubsub_token_lookup` = `sha256_hex(clé)` + SELECT sur la colonne INDEXÉE `token_hash`
//!     (state.rs, kind='gcp_pubsub') — la MÊME primitive partagée (`push_token_connector`) que Firehose ; la
//!     comparaison porte sur le HASH (jamais le clair) -> pas de fuite de timing sur le secret.
//!   - DÉCODAGE / MAPPING CIM : `firehose_decode_record_data` (base64 -> objet unique / array / ND-JSON /
//!     enveloppe via `records_path`) puis `httppull_map_record` — RÉUTILISÉS TELS QUELS (le field_map du preset
//!     `gcp-audit` est TRANSPORT-INDÉPENDANT).
//!   - SPOOL / INGEST : enveloppe `{kind:events, env_id, events:[…]}` -> spool atomique 0600 -> boucle de fond
//!     `ingest_events_batch(_env)` — IDENTIQUE au Firehose/HEC.
//!   - BORNES DoS : `ingest_disk_guard`, permis `ingest_sem`, cap `otlp_gunzip_capped` (`firehose_max_decompress`),
//!     `ingest_max_events`, + limite de corps `PLUME_INGEST_MAX_BODY_MB` (défaut 8 Mio, couche `limite_corps`) + rate_limit (layers).
//!
//! SÉMANTIQUE D'ACK Pub/Sub (OPPOSÉE à Firehose sur le message-poison) : Pub/Sub considère TOUT 2xx comme ACK
//! et REJOUE sur non-2xx / timeout (jusqu'à l'ack-deadline de l'abonnement). D'où :
//!   - succès (spoolé)                       -> 200 (petit corps)  : ACK.
//!   - message POISON (base64/JSON indécodable, enveloppe absente, mappé à 0 event, expansion > cap) -> 2xx
//!     ACK-AND-DROP (204). Renvoyer 4xx/5xx ferait REJOUER le message empoisonné À L'INFINI (c'est l'INVERSE du
//!     choix Firehose 400-rejoue : Firehose peut réduire son buffer et re-livrer un BATCH plus petit ; un message
//!     Pub/Sub unique et pathologique ne guérit JAMAIS -> on l'ACK et on le compte au lieu de le boucler).
//!   - échec TRANSITOIRE (pré-saturation disque, concurrence, écriture spool) -> 5xx : Pub/Sub REJOUE (guérissable).
//!   - auth absente/mauvaise -> 401 (avant tout parse) : Pub/Sub rejoue tant que l'abonnement porte un mauvais
//!     token — l'opérateur corrige la config (on n'ACK JAMAIS un message non authentifié).
//!
//! AUTH HORS auth_guard (comme /api/ingest/firehose) : route EXEMPTÉE (EXACT match) qui s'AUTO-AUTHENTIFIE ICI
//! (clé -> tenant + connecteur). Autorité INGEST-ONLY par construction (n'écrit qu'un fichier spool events).
//! Mode 0 byte-identique (route neuve, INERTE tant qu'aucune source push gcp_pubsub n'existe -> lookup None).
//!
//! NOTE SÉCURITÉ (`?token=` en clair dans l'URL) : un secret en query PEUT fuiter dans des access-logs. plume ne
//! journalise JAMAIS la query-string (ni l'URI complète) : `security_headers` et `auth_guard` n'utilisent que
//! `req.uri().path()`, et aucun TraceLayer/access-log n'est monté. CETTE DERNIÈRE PROPRIÉTÉ N'EST PLUS TENUE PAR
//! CETTE PHRASE (S29) : elle l'était par un « À FLAGGER pour la revue », c'est-à-dire par la vigilance — or monter
//! un journal de requêtes ne casse RIEN, ne change aucune réponse et ne fait rougir aucun test ; la fuite serait
//! dans un fichier d'apparence normale, et personne ne l'apprendrait. `tests::allegations_d_environnement` ferme
//! les trois portes : la fonctionnalité `trace` de `tower-http` n'est pas compilée, aucun code exécuté ne monte de
//! couche de trace, et aucune ligne exécutée ne journalise l'URI ou la query. Si l'une des trois s'ouvre un jour,
//! la garde le dit — et la query de cette route DEVRA être rédigée avant journalisation.
use crate::*;

/// Plafond DUR d'events matérialisés par requête Pub/Sub (une push livre normalement UNE LogEntry ; un array/
/// ND-JSON défensif peut multiplier). Combiné avec `st.ingest_max_events` (le plus petit gagne) -> ACK-DROP
/// au-delà (message unique pathologique = poison, jamais un 413-rejoue). Miroir de `FIREHOSE_MAX_EVENTS`.
pub(crate) const PUBSUB_MAX_EVENTS: usize = 50_000;

/// ACK Pub/Sub de SUCCÈS (données spoolées) : HTTP 200 `{"status":"ok"}` (petit corps). 2xx -> ACK, pas de rejeu.
/// `S31` (temps 1) — accusé de RÉCEPTION, pas de DURABILITÉ : ce 200 fait ACQUITTER le message côté Pub/Sub,
/// donc disparaître la seule autre copie, alors que le spool écrit juste avant n'est pas synchronisé. Le corps
/// n'est pas étendu (Pub/Sub ne lit que le statut ; l'y écrire ne renseignerait personne). La limite est écrite
/// dans `docs/AGENTS-PROTOCOLE.md` et dans le bandeau de `ingest/mod.rs`.
fn pubsub_ok() -> Response {
    (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response()
}

/// POURQUOI un message Pub/Sub a été ACQUITTÉ SANS AVOIR ÉTÉ INGÉRÉ.
///
/// CE QUE CETTE ÉNUMÉRATION RÉPARE. Un ACK-DROP répond 204 — pour Pub/Sub, « je l'ai pris » — alors que la
/// donnée est JETÉE. C'est le bon choix (un message pathologique ne guérit jamais, le rejouer boucle à
/// l'infini), mais il n'est tenable qu'à une condition : que la perte soit COMPTÉE. Mesuré le 2026-08-05,
/// elle ne l'était pas : sur SIX sites d'ACK-DROP, TROIS jetaient le message sans laisser la moindre trace —
/// enveloppe JSON indécodable, `message.data` absent, et expansion au-delà du plafond (ce dernier jetant même
/// les événements DÉJÀ correctement mappés). Un exploitant n'avait aucun moyen de distinguer « rien n'arrive »
/// de « tout est jeté à l'entrée ».
///
/// POURQUOI UN ARGUMENT ET PAS UN DRAPEAU. Le correctif ne consiste pas à ajouter un compteur à côté des trois
/// sites fautifs : demain, un septième site oublierait à son tour. `pubsub_ackdrop` EXIGE désormais une raison,
/// et compte lui-même. Acquitter en silence n'est plus une négligence possible : c'est une ERREUR DE
/// COMPILATION. MUTATION : retirer l'argument d'un seul appel ⇒ le fichier ne compile pas.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AckDrop {
    /// Corps (compressé ou non) au-delà de `firehose_max_decompress` — TAILLE, pas mapping.
    CorpsTropGros,
    /// L'enveloppe Pub/Sub n'est pas du JSON décodable.
    EnveloppeIndecodable,
    /// Enveloppe valide mais `message.data` absent ou vide : rien à décoder.
    DonneeAbsente,
    /// Un message unique s'est expansé au-delà du plafond d'événements : le message ENTIER est jeté.
    ExpansionAuDelaDuPlafond,
    /// Batch valide, décodé, mais mappé à ZÉRO événement : `field_map`/`records_path` mal configuré.
    ZeroEvenementMappe,
}

impl AckDrop {
    /// Toutes les raisons, dans l'ordre de leur rang. Sert à EXPOSER les compteurs sans les énumérer une
    /// seconde fois dans metrics.rs : la surface d'observabilité se DÉRIVE d'ici.
    pub(crate) const TOUTES: [AckDrop; 5] = [
        AckDrop::CorpsTropGros,
        AckDrop::EnveloppeIndecodable,
        AckDrop::DonneeAbsente,
        AckDrop::ExpansionAuDelaDuPlafond,
        AckDrop::ZeroEvenementMappe,
    ];

    /// Rang dans `PUBSUB_ACKDROP`. Le `match` est EXHAUSTIF : une variante ajoutée demain ne compile pas tant
    /// qu'on ne lui a pas donné sa case — elle ne peut donc pas atterrir en silence dans celle d'une autre.
    pub(crate) const fn rang(self) -> usize {
        match self {
            AckDrop::CorpsTropGros => 0,
            AckDrop::EnveloppeIndecodable => 1,
            AckDrop::DonneeAbsente => 2,
            AckDrop::ExpansionAuDelaDuPlafond => 3,
            AckDrop::ZeroEvenementMappe => 4,
        }
    }

    /// Nom exposé dans `/metrics`. Exhaustif lui aussi : pas de raison sans libellé.
    pub(crate) const fn libelle(self) -> &'static str {
        match self {
            AckDrop::CorpsTropGros => "corps_trop_gros",
            AckDrop::EnveloppeIndecodable => "enveloppe_indecodable",
            AckDrop::DonneeAbsente => "donnee_absente",
            AckDrop::ExpansionAuDelaDuPlafond => "expansion_au_dela_du_plafond",
            AckDrop::ZeroEvenementMappe => "zero_evenement_mappe",
        }
    }
}

/// LA TABLE DES RANGS FERME — vérifié à la COMPILATION, pas à l'exécution. Trois façons de la casser, les
/// trois arrêtées ici : une variante sans rang (le `match` de `rang` refuse), une variante absente de `TOUTES`
/// ou mal ordonnée (l'assertion ci-dessous), un tableau de compteurs de mauvaise taille (l'égalité de
/// longueur). Sans cette fermeture, une raison ajoutée demain incrémenterait la case d'une autre et le
/// tableau de bord mentirait sans jamais échouer.
const _: () = {
    assert!(
        PUBSUB_ACKDROP.len() == AckDrop::TOUTES.len(),
        "PUBSUB_ACKDROP (metrics.rs) n'a pas une case par raison d'AckDrop"
    );
    let mut i = 0;
    while i < AckDrop::TOUTES.len() {
        assert!(AckDrop::TOUTES[i].rang() == i, "AckDrop::TOUTES n'est pas rangé dans l'ordre des rangs");
        i += 1;
    }
};

/// ACK-AND-DROP Pub/Sub : HTTP 204 (2xx -> ACK) SANS corps, pour un message qui ne guérira jamais. L'ACK évite
/// le rejeu infini ; le COMPTAGE, ici et non chez l'appelant, évite que la perte soit invisible.
///
/// `PUSH_ZERO_MAP_TOTAL` n'est plus incrémenté que par la raison qui porte son nom. Il comptait auparavant
/// aussi les rejets de TAILLE, ce qui envoyait l'exploitant enquêter sur un `field_map` innocent.
fn pubsub_ackdrop(raison: AckDrop) -> Response {
    PUBSUB_ACKDROP[raison.rang()].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if matches!(raison, AckDrop::ZeroEvenementMappe) {
        PUSH_ZERO_MAP_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Extrait la clé de livraison du query `?token=<clé>` (Pub/Sub push porte le token dans l'URL de l'endpoint).
/// MIROIR de la branche query de `hec_token` (ingest/hec.rs) — même parsing `token=` ; PUR, testable offline.
/// Renvoie "" si absent (auth échouera fail-closed). Ne journalise JAMAIS la valeur.
pub(crate) fn pubsub_query_token(query: Option<&str>) -> String {
    if let Some(qs) = query {
        for kv in qs.split('&') {
            if let Some(v) = kv.strip_prefix("token=") {
                if !v.is_empty() {
                    return v.to_string();
                }
            }
        }
    }
    String::new()
}

/// POST /api/ingest/pubsub?token=<clé> — récepteur PUSH GCP Pub/Sub (contrat « push subscription »). EXEMPTÉ
/// d'auth_guard : s'auto-authentifie par la clé de livraison en query (-> tenant + connecteur push lié).
/// Contrat : corps `{"message":{"data":"<base64>","attributes":{…},"messageId":"…","publishTime":"…"},
/// "subscription":"projects/…/subscriptions/…"}` — `message.data` (base64) décode UNE LogEntry GCP (une push =
/// un message). gzip optionnel (`Content-Encoding: gzip`, cap anti-bombe). NE fait AUCUN travail DB sur le worker.
pub(crate) async fn pubsub_ingest_post(
    State(st): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    body: axum::body::Bytes,
) -> Response {
    // 1) AUTH EN PREMIER — la clé de livraison (query `?token=`) est vérifiée AVANT tout travail COÛTEUX (gzip,
    //    parse JSON, base64, spool). Le corps, borné par `limite_corps` (défaut 8 Mio), a déjà été bufferisé (borné par
    //    DefaultBodyLimit + rate_limit en amont) mais AUCUN parse/décompression/écriture n'a lieu avant ce point.
    //    Absente/mauvaise -> 401 IMMÉDIAT (Pub/Sub rejoue : l'opérateur corrige le token de l'abonnement).
    let key = pubsub_query_token(query.as_deref());
    let ident = match pubsub_token_lookup(&st, &key) {
        Some(i) => i,
        None => return err_json(StatusCode::UNAUTHORIZED, "invalid or missing ?token= delivery token"),
    };
    // 2) GARDE DISQUE : 503 en pré-saturation -> TRANSITOIRE, Pub/Sub rejoue (guérissable).
    if ingest_disk_guard(&st).is_some() {
        return err_json(StatusCode::SERVICE_UNAVAILABLE, "server busy (disk pressure)");
    }
    // 3) BORNE DE CONCURRENCE : un permis d'ingest, TENU jusqu'à la fin (décompress + parse + arbre + events).
    //    Saturé -> 503 TRANSITOIRE, Pub/Sub rejoue.
    let _permit = match st.ingest_sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return err_json(StatusCode::SERVICE_UNAVAILABLE, "server busy (ingest concurrency)"),
    };
    // 4) gzip optionnel (cap anti-bombe AVANT le parse). RÉUTILISE `otlp_gunzip_capped` + `firehose_max_decompress`
    //    (même borne prudente). Un corps trop gros / une bombe = POISON (permanent) -> ACK-DROP (jamais un rejeu
    //    infini d'un message trop volumineux).
    let ce = headers.get(axum::http::header::CONTENT_ENCODING).and_then(|v| v.to_str().ok()).unwrap_or("");
    let raw: Vec<u8> = if ce.contains("gzip") {
        match otlp_gunzip_capped(body.as_ref(), firehose_max_decompress()) {
            Ok(r) => r,
            Err(_) => return pubsub_ackdrop(AckDrop::CorpsTropGros), // décompressé > cap = poison -> ACK-DROP
        }
    } else {
        if body.len() > firehose_max_decompress() {
            return pubsub_ackdrop(AckDrop::CorpsTropGros); // corps trop gros = poison -> ACK-DROP
        }
        body.to_vec()
    };
    // 5) parse l'enveloppe Pub/Sub. Indécodable / `message.data` absent = POISON -> ACK-DROP (jamais un rejeu).
    let root: Value = match serde_json::from_slice::<Value>(&raw) {
        Ok(v) => v,
        Err(_) => return pubsub_ackdrop(AckDrop::EnveloppeIndecodable),
    };
    let data_b64 = match root.get("message").and_then(|m| m.get("data")).and_then(|d| d.as_str()) {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => return pubsub_ackdrop(AckDrop::DonneeAbsente), // pas de message.data exploitable -> ACK-DROP
    };
    // 6) charge le connecteur push LIÉ (field_map + env_id + type) depuis la base du tenant (mode 0 = st.db).
    //    RE-VÉRIFIE type='gcp_pubsub' : une clé ne peut être honorée que si son binding pointe une source push
    //    VIVANTE de CE type. Connecteur supprimé / mauvais type -> 403 (binding cassé, fail-closed).
    let handle = st.tenants.handle_for(&ident.tenant).unwrap_or_else(|| st.db.clone());
    let (ctype, cfg_json, env_id): (String, String, String) = {
        let conn = handle.lock();
        match conn.query_row(
            "SELECT type,config_json,env_id FROM connector WHERE id=?1",
            params![ident.connector_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
        ) {
            Ok(x) => x,
            Err(_) => return err_json(StatusCode::FORBIDDEN, "delivery token not bound to a live push source"),
        }
    };
    if ctype != "gcp_pubsub" {
        return err_json(StatusCode::FORBIDDEN, "delivery token not bound to a Pub/Sub push source");
    }
    let cfg = HttpPullCfg::from_json(&serde_json::from_str::<Value>(&cfg_json).unwrap_or_else(|_| json!({})));
    let records_path = cfg.records_path().to_string();
    // 7) décode message.data (base64 -> LogEntry unique / array / ND-JSON via records_path) -> mappe CIM. Plafond
    //    DUR d'events : un message unique qui explose au-delà est POISON -> ACK-DROP (jamais un 413-rejoue).
    //    RÉUTILISE `firehose_decode_record_data` + `httppull_map_record` (le seam de décodage/mapping partagé).
    let max_events = PUBSUB_MAX_EVENTS.min(st.ingest_max_events);
    let mut events: Vec<Value> = Vec::new();
    for decoded in firehose_decode_record_data(&data_b64, &records_path) {
        if let Some(ev) = httppull_map_record(&decoded, &cfg, ident.connector_id) {
            events.push(ev);
            if events.len() > max_events {
                return pubsub_ackdrop(AckDrop::ExpansionAuDelaDuPlafond); // expansion > cap = poison -> ACK-DROP
            }
        }
    }
    if events.is_empty() {
        // batch ACCEPTÉ mais mappé à 0 event (base64/JSON indécodable, ou field_map/records_path mal configuré) :
        // ACK-DROP + COMPTEUR (LOW#2 : un misconfig est OBSERVABLE au lieu d'un 200 silencieux). Poison compris.
        return pubsub_ackdrop(AckDrop::ZeroEvenementMappe);
    }
    // 8) spool enveloppe events + `env_id` + marqueur tenant (mode 0 = "") -> boucle de fond (parsers/extracteur/
    //    threat-intel/masquage UNIFORMES). Écriture spool en échec = TRANSITOIRE -> 5xx (Pub/Sub rejoue).
    // `P6.9-c` — l'enveloppe DÉPLACE le lot (et `env_id` avec lui) au lieu de le recopier ; mesure et
    // propriété dans `enveloppe_events_serialisee`.
    let corps = match enveloppe_events_serialisee(events, Some(env_id)) {
        Ok(c) => c,
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "serialize failed"),
    };
    let n = INGEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mk = spool_tenant_marker_for(&st, &ident.tenant);
    let tmp = format!("{}/.ps-{}-{}.tmp", st.spool, now(), n);
    let dst = format!("{}/ps-{}-{}{}.json", st.spool, now(), n, mk);
    // `S31` (temps 2) — publication DÉPORTÉE + deux barrières AVANT l'ACK. Pub/Sub ne lit que le statut :
    // le témoin de cette surface est `plume_spool_barriere_*` dans /metrics.
    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {
        Err(crate::ingest::spool::EchecSpool::Ecriture) => err_json(StatusCode::INTERNAL_SERVER_ERROR, "spool write failed"),
        Err(crate::ingest::spool::EchecSpool::Publication) => err_json(StatusCode::INTERNAL_SERVER_ERROR, "spool publish failed"),
        Ok(_) => pubsub_ok(),
    }
}

//! Provisioning de JETONS (agent + HEC) réservé admin — pendant UI du CLI `plume-daemon token <name> [host]`.
//! ADDITIF : réutilise EXACTEMENT la table `token` + la sémantique `token_lookup` (SHA-256 stocké, jamais le
//! secret) -> un jeton créé ici s'authentifie à l'IDENTIQUE d'un jeton CLI, sur le seam agent (Bearer /
//! responder host-lié) ET sur le collector HEC (`Splunk <tok>` / `?token=` sur /services/collector). `kind`
//! (agent|hec) est un LIBELLÉ DESCRIPTIF (v82) : il n'aiguille RIEN dans l'auth (les deux chemins partagent la
//! table) ; il ne sert qu'au badge UI + à l'extrait forwarder. Le secret CLAIR n'est renvoyé QU'UNE fois, à la
//! création (show-once) ; il n'est jamais re-dérivable (seul son SHA-256 est en base). Toutes les routes sont
//! admin-only (route_min_role /api/tokens -> Admin, default-deny) AVEC re-check `au.is_admin()` dans le handler.
use crate::*;

/// CSPRNG hex (/dev/urandom). MÊME construction que le CLI `token` : 32 octets -> hex. None si l'entropie
/// noyau est indisponible -> le mint ÉCHOUE (jamais de secret faible/prévisible).
pub(crate) fn token_rand_hex() -> Option<String> {
    use std::io::Read;
    let mut b = [0u8; 32];
    std::fs::File::open("/dev/urandom").ok()?.read_exact(&mut b).ok()?;
    Some(hex_encode(&b))
}

/// Nom de jeton valide : alphanumérique + `. _ -` (comme les comptes user). Non vide.
fn token_name_ok(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

/// Host de liaison valide : hostname raisonnable (alphanumérique + `. _ -`), <= 253 car. (jamais de secret ni
/// d'injection). Vide = non lié (ingest/HEC only ; refusé sur le responder — cf. sémantique CLI/host).
fn token_host_ok(host: &str) -> bool {
    host.len() <= 253 && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

// ====================================================================================================
// LA PORTÉE D'UN JETON EST UNE DÉCLARATION, PAS UNE OMISSION (P5.2-b).
//
// CE QUI ÉTAIT CASSÉ. `plume-daemon token <nom>` — deux arguments, la forme la plus courte, celle que la
// documentation montrait — produisait un jeton NON LIÉ. MESURÉ le 2026-08-02 : avec ce jeton, une
// enveloppe `{"host":"CONTROLEUR-DE-DOMAINE-USURPE"}` sur `/api/ingest` est acceptée (HTTP 202) et
// l'événement est STOCKÉ sous ce nom-là ; même chose sur `/loki/api/v1/push` (204, `LOKI-USURPE-NONLIE`).
// Avec un jeton lié, la même enveloppe est réécrite vers l'hôte du jeton. Le troisième argument n'était
// donc pas une option de confort : c'était la différence entre une identité et un laissez-passer. Le
// message affiché après coup — « NON lié à un hôte : ingest only ; pour le responder, relancer avec un
// hôte » — présentait ce laissez-passer comme une capacité RÉDUITE. Il ne disait pas ce qu'il ouvrait.
//
// POURQUOI ON NE SUPPRIME PAS LA FORME NON LIÉE. Elle est LÉGITIME et nécessaire : un relais central
// (forwarder HEC, Alloy, Prometheus — cf. `deploy/OBS.md`) multiplexe plusieurs hôtes par construction,
// et c'est précisément son absence de liage qui, depuis P5.2-a, laisse passer l'hôte qu'il déclare.
// Supprimer la forme casserait ces déploiements ; la garder par DÉFAUT laisse le chemin le plus court
// être le chemin le moins sûr.
//
// IMPACT SUR L'EXISTANT — MESURÉ AVANT DE TRANCHER. Cette garde porte sur la CRÉATION, jamais sur la
// vérification : `token_lookup` est INCHANGÉ, aucun jeton déjà émis n'est révoqué, aucune ligne de la
// table `token` n'est touchée, et aucune migration n'est ajoutée. Un parc dont les agents portent
// aujourd'hui des jetons non liés continue d'émettre exactement comme avant (avec l'usurpation qu'on
// vient de mesurer — la re-liaison est un geste d'opérateur, pas un effet de bord d'une mise à jour).
//
// LA FORME DÉRIVÉE. On ne peut pas rendre l'omission sûre ; on peut rendre l'omission IMPOSSIBLE. La
// portée devient une somme FERMÉE à deux cas, et le point d'écriture de la table `token` n'accepte que
// cette somme — pas un `Option<String>`. Il n'y a donc plus de valeur « host absent » à interpréter :
// il y a `Machine(hôte)` ou `Relais`, tous deux ÉCRITS par celui qui provisionne. Un futur chemin de
// provisioning (nouvelle sous-commande, nouvelle route, import) ne peut pas créer un jeton sans
// trancher : `inserer_jeton` ne compile pas sans une `PorteeJeton`.
// ====================================================================================================

/// PORTÉE d'un jeton d'ingestion. Somme FERMÉE : tout jeton est l'un ou l'autre, jamais « ni l'un ni
/// l'autre par défaut ». C'est ce que `HoteIngere::resoudre` lit à chaque écriture (P5.2-a).
#[derive(Debug)]
pub(crate) enum PorteeJeton {
    /// Identité de MACHINE : le jeton est lié à cet hôte. Tout ce qu'il écrit lui est attribué, quel que
    /// soit l'hôte déclaré dans la requête — et c'est ce liage qui autorise le responder à agir dessus.
    Machine(String),
    /// RELAIS multi-hôtes DÉCLARÉ (forwarder HEC, Alloy, Prometheus, collector OTel). L'hôte des lignes
    /// reste celui que le relais DÉCLARE : non attesté, et donc usurpable par quiconque tient ce jeton.
    /// C'est le prix d'un relais, il se paie en le sachant.
    Relais,
}

impl PorteeJeton {
    /// Portée DÉCLARÉE par un provisionneur. `hote` non vide -> machine ; `relais` -> relais. Les deux à
    /// la fois, ou aucun des deux, sont des DÉCLARATIONS INCOHÉRENTES : refus explicite, jamais un défaut
    /// silencieux. Renvoie le message d'erreur destiné à l'opérateur (CLI comme API).
    pub(crate) fn declarer(hote: Option<&str>, relais: bool) -> Result<Self, String> {
        let hote = hote.map(str::trim).filter(|h| !h.is_empty());
        match (hote, relais) {
            (Some(_), true) => Err("portée contradictoire : un hôte de liaison ET --relais".into()),
            (Some(h), false) if !token_host_ok(h) => {
                Err("hôte de liaison invalide (alphanumérique, . _ - ; ≤ 253 car.)".into())
            }
            (Some(h), false) => Ok(Self::Machine(h.to_string())),
            (None, true) => Ok(Self::Relais),
            (None, false) => Err(
                "portée du jeton non déclarée. Un jeton d'agent est SOIT lié à une machine, SOIT un relais \
                 multi-hôtes — et un jeton non lié laisse usurper n'importe quel hôte (mesuré). Déclarez :\n  \
                 <hôte>     jeton lié à CETTE machine (responder autorisé sur elle)\n  \
                 --relais   forwarder/collector multi-hôtes (hôte déclaré par l'émetteur, NON attesté)"
                    .into(),
            ),
        }
    }

    /// L'hôte de liaison à écrire en colonne `host`, ou `None` pour un relais. SEULE façon d'obtenir cette
    /// valeur : elle vient forcément d'une portée déclarée.
    pub(crate) fn hote_lie(&self) -> Option<&str> {
        match self {
            Self::Machine(h) => Some(h.as_str()),
            Self::Relais => None,
        }
    }
}

/// SEUL point d'écriture d'une ligne `token` (CLI comme UI). La colonne `host` n'est pas un paramètre
/// libre : elle est DÉRIVÉE de la portée déclarée. `kind`/`role` restent `None` pour la voie CLI
/// historique -> ligne stockée IDENTIQUE à l'INSERT d'avant (colonnes omises == NULL).
pub(crate) fn inserer_jeton(
    conn: &Connection,
    name: &str,
    hash: &str,
    kind: Option<&str>,
    role: Option<&str>,
    portee: &PorteeJeton,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO token(name,token_hash,created,host,kind,role) VALUES(?1,?2,?3,?4,?5,?6)",
        params![name, hash, now(), portee.hote_lie(), kind, role],
    )
}

/// GET /api/tokens — liste les jetons (JAMAIS le secret : ni clair ni hash). Admin-only.
pub(crate) async fn tokens_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    // Le provisioning UI opère sur le magasin de jetons du MODE 0 (table `token` de la base unique), STRICTEMENT
    // comme le CLI et comme `token_lookup` en mode 0. En mode 1, les jetons vivent dans le control-plane
    // (schéma minimal sans name/last_used) -> provisionnés hors UI ; on refuse ici pour ne jamais créer de
    // jeton MORT (invisible de token_lookup control-plane).
    if st.multi_tenant {
        return err_json(StatusCode::NOT_IMPLEMENTED, "provisioning de jetons via l'UI réservé au mode mono-tenant (control-plane : voir CLI)");
    }
    let conn = st.db.lock();
    let mut stmt = conn
        .prepare("SELECT id,name,kind,host,created,last_used,role FROM token ORDER BY id")
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            let host: Option<String> = r.get(3)?;
            // kind NULL (jetons CLI historiques) -> 'agent' (défaut du CLI `plume-daemon token`).
            let kind: Option<String> = r.get(2)?;
            let role: Option<String> = r.get(6)?;
            let kind_out = match kind.as_deref() {
                Some("hec") => "hec",
                Some("datasource") => "datasource",
                Some("client") => "client", // #39 jeton client-read
                Some("firehose") => "firehose", // P-HEC : clé de livraison push AWS Firehose (liée à un connecteur)
                _ => "agent",
            };
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "name": r.get::<_, String>(1)?,
                "kind": kind_out,
                // rôle read-scoped UNIQUEMENT pour les jetons datasource (#52) ; sinon absent.
                "role": if kind_out == "datasource" { Some(role.unwrap_or_else(|| "viewer".into())) } else { None },
                "host": host.filter(|h| !h.is_empty()),
                "created": r.get::<_, Option<i64>>(4)?,
                "last_used": r.get::<_, Option<i64>>(5)?,
            }))
        })
        .unwrap();
    Json(json!({ "tokens": rows.flatten().collect::<Vec<_>>() })).into_response()
}

/// POST /api/tokens {name, kind:agent|hec, host?} — mint un jeton. Stocke le SHA-256 (jamais le clair) ;
/// renvoie le secret CLAIR UNE SEULE FOIS (show-once). Audité (config.token.create). Admin-only.
pub(crate) async fn token_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return err_json(StatusCode::NOT_IMPLEMENTED, "provisioning de jetons via l'UI réservé au mode mono-tenant (control-plane : voir CLI)");
    }
    let name = b.trimmed("name");
    let kind = match b.get("kind").and_then(|v| v.as_str()) {
        Some("hec") => "hec",
        Some("datasource") => "datasource", // #52 jeton read-scoped (Grafana/Prometheus pointe SUR plume)
        Some("client") => "client", // #39 jeton client-read (MSSP : le client voit SES cases), read-only strict
        _ => "agent", // défaut = agent (compat CLI)
    };
    // #52 — rôle de LECTURE d'un jeton datasource (viewer|editor, jamais admin/agent). NULL pour agent/hec.
    let role: Option<&str> = if kind == "datasource" {
        Some(match b.get("role").and_then(|v| v.as_str()) {
            Some("editor") => "editor",
            _ => "viewer", // défaut = viewer (moindre privilège)
        })
    } else {
        None
    };
    // #52 DÉFENSE EN PROFONDEUR : un jeton datasource est LECTURE SEULE -> JAMAIS host-lié (un host de liaison
    // n'a de sens que pour le responder agent host-scopé ; le refuser ferme indépendamment tout chemin d'action
    // host-gardé même si le filtre kind de token_lookup régressait un jour). host ignoré pour kind=datasource.
    let host = if kind == "datasource" || kind == "client" { String::new() } else { b.trimmed("host") };
    if !token_name_ok(&name) {
        return bad_req("nom de jeton invalide (alphanumérique, . _ - uniquement)");
    }
    // P5.2-b — la PORTÉE est déclarée ici aussi, sinon la garde du CLI se contournerait par le SPA (les deux
    // écrivent la MÊME table `token`). Un jeton `datasource`/`client` est LECTURE SEULE et n'est jamais
    // host-lié (cf. juste au-dessus) : sa portée n'est pas une question ouverte, elle vaut `Relais` par
    // CONSTRUCTION, pas par omission. Pour agent/HEC, `{host}` OU `{"relay":true}` — l'un des deux, jamais
    // ni l'un ni l'autre.
    let portee = if kind == "datasource" || kind == "client" {
        PorteeJeton::Relais
    } else {
        match PorteeJeton::declarer(Some(host.as_str()), b.bool_field("relay", false)) {
            Ok(p) => p,
            Err(e) => return bad_req(e),
        }
    };
    let host_opt: Option<String> = portee.hote_lie().map(|h| h.to_string());
    let Some(secret) = token_rand_hex() else {
        return server_err("entropie noyau indisponible — jeton NON créé");
    };
    let hash = sha256_hex(secret.as_bytes());
    let conn = st.db.lock();
    // Insert + audit ATOMIQUES fail-closed (aucun jeton sans trace ; si l'audit échoue -> ROLLBACK, le secret
    // renvoyé ne correspondrait à aucune ligne persistée). Le UNIQUE(token_hash) rend une collision improbable
    // -> 409. host NULL = non lié (ingest/HEC only). last_used NULL tant qu'inutilisé.
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        inserer_jeton(&conn, &name, &hash, Some(kind), role, &portee)?;
        audit_config_change(
            &conn, "config.token.create",
            &format!("jeton {kind} '{name}'{} créé par {}", host_opt.as_deref().map(|h| format!(" (hôte {h})")).unwrap_or_default(), au.name), 2,
            &format!("jeton {kind} '{name}' provisionné{} par {}", host_opt.as_deref().map(|h| format!(" lié à l'hôte '{h}'")).unwrap_or_default(), au.name),
            &json!({ "op": "create", "kind": "token", "token_kind": kind, "name": name, "host": host_opt.clone(), "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            // SHOW-ONCE : le secret CLAIR n'est renvoyé QU'ICI (jamais re-dérivable). Le SPA l'affiche une fois.
            Json(json!({
                "name": name, "kind": kind, "host": host_opt, "role": role,
                "token": secret,
                "hec_path": "/services/collector",
                "datasource_path": "/api/ds/query", // #52 : endpoint GXQL-HTTP à pointer depuis Grafana Infinity
            })).into_response()
        }
        Err(_) => {
            let _ = conn.execute_batch("ROLLBACK");
            // Collision UNIQUE(name?) — en réalité name n'est pas unique ; le seul UNIQUE est token_hash.
            (StatusCode::CONFLICT, "échec de création du jeton (collision ou audit) — réessayez").into_response()
        }
    }
}

/// DELETE /api/tokens/{name} — révoque (supprime) tous les jetons de ce nom. Audité. Admin-only.
pub(crate) async fn token_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(name): Path<String>) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return err_json(StatusCode::NOT_IMPLEMENTED, "provisioning de jetons via l'UI réservé au mode mono-tenant (control-plane : voir CLI)");
    }
    if !token_name_ok(&name) {
        return bad_req("nom de jeton invalide");
    }
    let conn = st.db.lock();
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM token WHERE name=?1", params![name], |r| r.get(0)).unwrap_or(0);
    if n == 0 {
        return not_found("jeton introuvable");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM token WHERE name=?1", params![name])?;
        audit_config_change(
            &conn, "config.token.revoke",
            &format!("jeton '{name}' révoqué par {} ({n})", au.name), 3,
            &format!("jeton '{name}' révoqué ({n} entrée·s) par {} — l'agent/forwarder porteur perd l'accès", au.name),
            &json!({ "op": "revoke", "kind": "token", "name": name, "count": n, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => { let _ = conn.execute_batch("COMMIT"); StatusCode::NO_CONTENT.into_response() }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

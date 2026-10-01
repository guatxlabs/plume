//! `P10.26-g` — LA CLÉ DE LIVRAISON D'UNE SOURCE PUSH SE RENOUVELLE PAR UNE ROUTE NOMMÉE.
//!
//! LE DÉFAUT, MESURÉ LE 2026-09-29 SUR L'ARBRE QUI LE PORTAIT. Aucune route ne refrappait la clé d'une source push
//! existante : la table de routage des connecteurs (`server/groupes_de_routes.rs`) servait la liste, la création, les
//! presets, la création d'une source push, la modification, la suppression, l'essai et la collecte, et
//! `connector_update` ne fait tourner que `connector.secret` (le credential d'une source en PULL), jamais une ligne
//! `token`. Le geste prescrit pour retirer le secret connu d'une clé — celle d'un compte supprimé
//! (`DECISION_SUR_LES_JETONS_DU_COMPTE_SUPPRIME`) ou une clé fuitée — était de supprimer la source push puis de la
//! recréer. Ce détour coûtait ce que l'énoncé ne nommait pas : le nom, l'environnement (`env_id`) et la configuration
//! ajustée de la source, son IDENTIFIANT (la source recréée en prend un autre — ou reprend le rowid libéré, mesuré par
//! `push_source_delete_revokes_delivery_token`), et une source restée SANS clé (celle d'un auteur supprimé, jamais
//! servie) ne pouvait rien recevoir sans ce détour.
//!
//! LE GESTE : `POST /api/connectors/{id}/delivery-key`. Le DROIT (administrateur) ET le secret des gestes
//! (`P10.24-m` : la clé est une crédence qui survit à la session), puis UNE transaction, sous le verrou de l'écrivain
//! (`jouer_le_geste_garde`) : relire le type du connecteur (une source qui n'est pas push est refusée, rien n'est
//! écrit), révoquer toute clé de livraison liée, frapper la neuve avec son auteur (`created_by`), tracer au registre
//! SANS le secret. La clé n'est montrée qu'une fois la transaction VALIDÉE (`P10.25-e`, `P10.26-a`).
//!
//! DÉCISION ÉCRITE : AUCUNE FENÊTRE DE RECOUVREMENT. L'ancienne clé est révoquée dans la transaction qui frappe la
//! neuve : le flux du nuage qui la présente encore est refusé par son récepteur jusqu'à ce que la nouvelle y soit
//! reportée. Garder les deux valides un temps serait laisser vivre, précisément pendant ce temps, le secret que le
//! geste veut retirer ; ce choix d'exposition revient à l'exploitant, et il n'existe pas ici. La confirmation de la
//! console et la réponse le disent.
use crate::*;
use crate::handlers::transaction_validee::{jouer_le_geste_garde, IssueDuGesteGarde};
use rusqlite::OptionalExtension;

/// Ce qu'un connecteur push reçoit, dérivé de son TYPE : le genre de sa clé (`token.kind`) et le récepteur qui
/// l'accepte. SEUL lieu de cette correspondance : la création d'une source push et le renouvellement de sa clé la lisent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LivraisonDUneSourcePush {
    /// `firehose` ou `gcp_pubsub` — isolés l'un de l'autre et du seam agent (`token_lookup`).
    pub(crate) genre: &'static str,
    /// Le récepteur borné à ce genre.
    pub(crate) point_de_livraison: &'static str,
}

/// `None` pour tout connecteur qui n'est pas une source push (il ne porte aucune clé de livraison).
pub(crate) fn livraison_d_une_source_push(type_de_connecteur: &str) -> Option<LivraisonDUneSourcePush> {
    match type_de_connecteur {
        "aws_firehose" => Some(LivraisonDUneSourcePush { genre: "firehose", point_de_livraison: "/api/ingest/firehose" }),
        "gcp_pubsub" => Some(LivraisonDUneSourcePush { genre: "gcp_pubsub", point_de_livraison: "/api/ingest/pubsub" }),
        _ => None,
    }
}

/// La réponse qui MONTRE une clé de livraison, une seule fois, dans la forme de son transport : Pub/Sub la porte en
/// requête (`delivery_token`, `transport: query_token` — l'URL complète est composée par la console, jamais incrustée
/// dans `instructions`), Firehose en en-tête (`delivery_key`, `auth_header`). La création d'une source push et le
/// renouvellement de sa clé servent cette même forme. La console lit les deux par la même lecture
/// (`lectureDeLaCleMontree`, web/connectors.js : transport, récepteur, URL qui porte la clé) et les montre sur deux
/// écrans distincts, qui gardent chacun leurs étiquettes et leurs consignes : configurer le flux à la création, y
/// remplacer la clé au renouvellement.
pub(crate) fn corps_de_la_cle_montree(connector_id: i64, cle: &str, livraison: LivraisonDUneSourcePush, instructions: &str) -> Value {
    if livraison.genre == "gcp_pubsub" {
        json!({
            "connector_id": connector_id,
            "delivery_token": cle,
            "endpoint_path": livraison.point_de_livraison,
            "transport": "query_token",
            "instructions": instructions,
        })
    } else {
        json!({
            "connector_id": connector_id,
            "delivery_key": cle,
            "endpoint_path": livraison.point_de_livraison,
            "auth_header": "X-Amz-Firehose-Access-Key",
            "instructions": instructions,
        })
    }
}

/// Pourquoi le corps du geste a refusé : la garde (connecteur absent, source qui n'est pas push), ou une lecture ou une
/// écriture que la base n'a pas prise. Dans tous les cas la transaction est ANNULÉE : rien n'est écrit.
enum RefusDuRenouvellement {
    ConnecteurIntrouvable,
    PasUneSourcePush(String),
    SourceNonLue(rusqlite::Error),
    EcritureRefusee(rusqlite::Error),
}

/// POST /api/connectors/{id}/delivery-key (ADMIN-ONLY, `P10.26-g`) — renouvelle la clé de livraison d'une source push.
/// Rend la forme de `corps_de_la_cle_montree` (clé montrée UNE fois), plus `cles_revoquees` (le nombre de clés liées
/// que la transaction a révoquées : zéro pour une source restée sans clé) et des `instructions` qui disent de reporter
/// la clé et que le flux est refusé jusque-là. Mode 1 (plan de contrôle) refusé, comme la création d'une source push.
pub(crate) async fn connector_delivery_key_rotate(
    State(st): State<AppState>,
    secret_des_gestes: crate::secret_des_gestes::SecretDesGestesPresente,
    Extension(au): Extension<AuthUser>,
    Path(id): Path<i64>,
) -> Response {
    if !au.is_admin() {
        return forbidden("réservé admin");
    }
    if st.multi_tenant {
        return err_json(StatusCode::NOT_IMPLEMENTED, "clé de livraison réservée au mode mono-tenant (clé de livraison via control-plane non supportée)");
    }
    let geste = format!("renouvellement de la clé de livraison du connecteur #{id}");
    // Le secret des gestes AVANT l'entropie et toute écriture — et avant de prendre l'écrivain : un secret faux s'inscrit
    // au registre par ce même écrivain (`exiger_le_secret_des_gestes`).
    if let Err(refus) = crate::secret_des_gestes::exiger_le_secret_des_gestes(&st, &secret_des_gestes, &au.name, &geste) {
        return refus;
    }
    let Some(cle) = token_rand_hex() else {
        return server_err("entropie noyau indisponible — clé de livraison NON renouvelée, l'ancienne authentifie toujours");
    };
    let empreinte = sha256_hex(cle.as_bytes());
    let issue = {
        crate::req_conn!(st, au, conn);
        jouer_le_geste_garde(&conn, "connecteurs", &geste, |conn| {
            // LA GARDE, DANS LA TRANSACTION : le connecteur relu sous le verrou d'écriture ne peut pas avoir été supprimé
            // puis remplacé (rowid repris) entre la lecture de son type et la frappe de sa clé.
            let type_de_connecteur: String = conn
                .query_row("SELECT type FROM connector WHERE id=?1", params![id], |r| r.get(0))
                .optional()
                .map_err(RefusDuRenouvellement::SourceNonLue)?
                .ok_or(RefusDuRenouvellement::ConnecteurIntrouvable)?;
            let Some(livraison) = livraison_d_une_source_push(&type_de_connecteur) else {
                return Err(RefusDuRenouvellement::PasUneSourcePush(type_de_connecteur));
            };
            // Même portée que la suppression d'un connecteur : toute clé de livraison liée, et elles seules.
            let revoquees = conn
                .execute("DELETE FROM token WHERE connector_id=?1 AND kind IN ('firehose','gcp_pubsub')", params![id])
                .map_err(RefusDuRenouvellement::EcritureRefusee)?;
            crate::handlers::tokens::inserer_cle_de_livraison_frappee_par(
                conn,
                &format!("{}-{id}", livraison.genre),
                &empreinte,
                livraison.genre,
                id,
                au.name.as_str(),
            )
            .map_err(RefusDuRenouvellement::EcritureRefusee)?;
            audit_config_change(
                conn,
                "config.connector.delivery_key.rotate",
                &format!("clé de livraison du connecteur #{id} renouvelée par {} ({revoquees} révoquée·s)", au.name),
                3,
                &format!(
                    "clé de livraison {} du connecteur #{id} renouvelée par {} — {revoquees} clé·s liée·s révoquée·s dans la même transaction, la neuve frappée (SHA-256 stocké)",
                    livraison.genre, au.name
                ),
                &json!({ "op": "rotate", "kind": "delivery_key", "connector_id": id, "token_kind": livraison.genre, "revoked": revoquees, "actor": au.name }).to_string(),
            )
            .map_err(RefusDuRenouvellement::EcritureRefusee)?;
            Ok((livraison, revoquees))
        })
    };
    match issue {
        IssueDuGesteGarde::Valide((livraison, revoquees)) => {
            let instructions = if livraison.genre == "gcp_pubsub" { INSTRUCTIONS_DU_RENOUVELLEMENT_PUBSUB } else { INSTRUCTIONS_DU_RENOUVELLEMENT_FIREHOSE };
            let mut corps = corps_de_la_cle_montree(id, &cle, livraison, instructions);
            corps["cles_revoquees"] = json!(revoquees);
            Json(corps).into_response()
        }
        IssueDuGesteGarde::Refuse(RefusDuRenouvellement::ConnecteurIntrouvable) => not_found("connecteur introuvable"),
        IssueDuGesteGarde::Refuse(RefusDuRenouvellement::PasUneSourcePush(type_lu)) => {
            bad_req(format!("{REFUS_CLE_DE_LIVRAISON_HORS_SOURCE_PUSH} Type lu : « {type_lu} »."))
        }
        IssueDuGesteGarde::Refuse(RefusDuRenouvellement::SourceNonLue(e)) => {
            eprintln!("[connecteurs] WARN {geste} NON fait : type du connecteur illisible ({e})");
            err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_SOURCE_NON_LUE)
        }
        IssueDuGesteGarde::Refuse(RefusDuRenouvellement::EcritureRefusee(e)) => {
            eprintln!("[connecteurs] WARN {geste} NON fait : écriture refusée ({e}), transaction annulée");
            server_err(format!("{CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_ECRITURE_REFUSEE} Refus de la base : {e}"))
        }
        IssueDuGesteGarde::NonOuvert(_) => err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_TRANSACTION_NON_OUVERTE),
        IssueDuGesteGarde::NonValide(e) => {
            eprintln!("[connecteurs] WARN {geste} NON validé : {e}");
            err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_COMMIT_REFUSE)
        }
    }
}

/// Ce que la réponse d'un renouvellement dit de faire, par transport — sans la clé, qui ne vit que dans son champ.
pub(crate) const INSTRUCTIONS_DU_RENOUVELLEMENT_PUBSUB: &str = "Remplacez l'URL de l'abonnement Pub/Sub « push » par \
     <votre-URL-Plume>/api/ingest/pubsub?token=<nouvelle-clé-de-livraison>. L'ancienne clé est RÉVOQUÉE : chaque message \
     que l'abonnement pousse encore avec elle est refusé par le récepteur jusqu'à ce report. La source garde son nom, son \
     environnement, sa configuration et son identifiant.";
pub(crate) const INSTRUCTIONS_DU_RENOUVELLEMENT_FIREHOSE: &str = "Remplacez l'« Access key » du delivery stream Kinesis \
     Firehose (destination « HTTP endpoint », en-tête X-Amz-Firehose-Access-Key) par la nouvelle clé. L'ancienne clé est \
     RÉVOQUÉE : chaque livraison qui la présente encore est refusée par le récepteur jusqu'à ce report. La source garde \
     son nom, son environnement, sa configuration et son identifiant.";

/// Le refus d'un renouvellement sur un connecteur qui n'est pas une source push (le type lu est joint).
pub(crate) const REFUS_CLE_DE_LIVRAISON_HORS_SOURCE_PUSH: &str = "CLÉ DE LIVRAISON NON RENOUVELÉE : ce connecteur n'est \
     pas une source push (aws_firehose, gcp_pubsub) — il ne porte aucune clé de livraison, et rien n'est écrit. Le \
     credential d'une source en PULL se remplace par la modification du connecteur.";

/// `P10.26-g` — le `COMMIT` du renouvellement refusé.
pub(crate) const CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_COMMIT_REFUSE: &str = "CLÉ DE LIVRAISON NON RENOUVELÉE : la base \
     n'a pas validé la transaction (COMMIT refusé) et l'a annulée — l'ancienne clé AUTHENTIFIE TOUJOURS sur son \
     récepteur, aucune clé neuve n'est écrite ni montrée, et aucune trace n'est écrite. Réessayez ; si le refus persiste, \
     la base est en lecture seule, pleine ou verrouillée.";
/// `P10.26-g` — le `BEGIN` du renouvellement refusé.
pub(crate) const CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_TRANSACTION_NON_OUVERTE: &str = "CLÉ DE LIVRAISON NON RENOUVELÉE : \
     la base n'a pas pris la transaction du renouvellement (BEGIN refusé : verrou tenu, ou transaction d'un autre geste \
     pendante sur l'écrivain) — RIEN n'est écrit : l'ancienne clé AUTHENTIFIE TOUJOURS sur son récepteur, aucune clé \
     neuve n'est écrite ni montrée, et aucune trace n'est écrite. Réessayez ; s'il est refusé encore, l'écrivain est \
     occupé ou bloqué.";
/// `P10.26-g` — le type du connecteur n'a pas pu être relu dans la transaction : rien n'est écrit.
pub(crate) const CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_SOURCE_NON_LUE: &str = "CLÉ DE LIVRAISON NON RENOUVELÉE : le \
     connecteur n'a pas pu être relu (lecture refusée par la base) — rien n'est écrit : l'ancienne clé AUTHENTIFIE \
     TOUJOURS sur son récepteur, et aucune clé neuve n'est montrée. Réessayez ; si le refus persiste, la base est \
     verrouillée ou son schéma n'est pas celui du démon.";
/// `P10.26-g` — une écriture du renouvellement refusée (révocation, frappe ou trace) : la transaction est annulée.
pub(crate) const CAUSE_CLE_DE_LIVRAISON_NON_RENOUVELEE_ECRITURE_REFUSEE: &str = "CLÉ DE LIVRAISON NON RENOUVELÉE : une \
     écriture du renouvellement a été refusée, rien n'en reste — l'ancienne clé AUTHENTIFIE TOUJOURS sur son récepteur, \
     et aucune clé neuve n'est montrée.";

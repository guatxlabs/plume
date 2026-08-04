//! LE PLAFOND DE TAILLE D'UN CORPS INGÉRÉ — et surtout, CE QU'IL DIT QUAND IL MORD (clé P4.1-o).
//!
//! LE DÉFAUT QU'IL FERME, MESURÉ LE 2026-08-03. Deux plafonds de nature différente gardent le même
//! chemin d'ingestion, et **c'est celui qui ne parle pas qui mord en premier** :
//!
//!   * `DefaultBodyLimit` d'axum — 8 Mio d'OCTETS — rendait
//!     `Failed to buffer the request body: length limit exceeded` : en anglais, sans nommer la
//!     limite, ni son unité, ni le levier pour la changer.
//!   * `PLUME_INGEST_MAX_EVENTS` — 50 000 ÉVÉNEMENTS — rend un message qui nomme le compte, le
//!     plafond ET le remède.
//!
//! Densité MESURÉE sur le banc : **531 octets par événement** (10 611 526 o pour 20 000 événements).
//! ⇒ le plafond d'octets se déclenche vers **15 810 événements**, donc **le plafond de 50 000 est
//! INATTEIGNABLE** : il faudrait des événements 3,2× plus petits que les nôtres. **Le bon message
//! était du code mort pour tout profil réaliste, et tout intégrateur recevait celui d'axum.**
//!
//! Ce n'est pas une coquetterie : plume SAIT nommer ses limites, il le fait à quelques lignes de
//! là. Le défaut est que **la garde qui parle est placée derrière celle qui ne parle pas**.
//!
//! ---------------------------------------------------------------------------------------------
//! LA COUVERTURE EST DÉRIVÉE DU ROUTEUR, PAS D'UNE LISTE DE HANDLERS.
//! Cette couche s'attache à `ingest_routes()`, le sous-routeur qui REGROUPE les chemins
//! d'ingestion. Une route d'ingestion ajoutée demain y est donc couverte **par construction**,
//! sans que personne ait à s'en souvenir — là où un extracteur à poser dans chaque handler aurait
//! été une énumération de douze signatures (`String`, `Bytes`, `Json<Value>`), c'est-à-dire une
//! liste qu'on oublie.
//! ---------------------------------------------------------------------------------------------
//!
//! CE QUE LE REFUS DIT, ET POURQUOI CHAQUE MORCEAU Y EST :
//!   - la TAILLE REÇUE quand l'émetteur l'annonce (`Content-Length`) — sinon l'intégrateur ne sait
//!     pas de combien il dépasse, donc pas de combien scinder ;
//!   - le PLAFOND et son UNITÉ — « 8 » ne veut rien dire sans « Mio », et la doc parlait
//!     d'événements alors que la limite compte des octets : c'est exactement ce qui égarait ;
//!   - le LEVIER (`PLUME_INGEST_MAX_BODY_MB`) — une limite qu'on ne peut pas ajuster est un mur ;
//!   - le GESTE (scinder le lot), parce qu'un refus sans remède fait rejouer la même requête.
//!
//! HONNÊTETÉ SUR CE QUI N'EST PAS DISTINGUÉ. Quand l'émetteur n'annonce PAS de `Content-Length`
//! (transfert chunké), `axum::body::to_bytes` rend une erreur qui ne distingue pas « plafond
//! dépassé » de « lecture interrompue ». Le message le DIT plutôt que de trancher au hasard. Le
//! cas est de toute façon marginal : les clients d'ingestion annoncent leur taille, et une lecture
//! interrompue signifie un pair déjà parti, qui ne lira aucune réponse.

use crate::*;
use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

/// Le défaut REPRODUIT EXACTEMENT le `DefaultBodyLimit::max(8 * 1024 * 1024)` qu'il remplace :
/// aucun écart de comportement n'est livré avec ce module, seul le MESSAGE change. Un écart mesuré
/// serait une régression, pas un effet.
const CORPS_MAX_MO_DEFAUT: usize = 8;

/// Le plafond en octets, décidé ICI et nulle part ailleurs. `0` est refusé (un plafond nul
/// rejetterait tout) : on retombe alors sur le défaut plutôt que de rendre l'ingestion inutilisable
/// sur une faute de frappe.
pub(crate) fn corps_max_octets() -> usize {
    static P: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *P.get_or_init(|| {
        let conf = load_config();
        let mo = cfg(&conf, "PLUME_INGEST_MAX_BODY_MB", "")
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|v| *v > 0)
            .unwrap_or(CORPS_MAX_MO_DEFAUT);
        mo * 1024 * 1024
    })
}

/// CE QUE LA LIMITE A VU. Deux cas, et ils ne se disent pas pareil — d'où un type plutôt qu'un
/// booléen : le `match` est EXHAUSTIF, donc un troisième cas ajouté demain ne compile pas tant que
/// sa phrase n'est pas écrite.
pub(crate) enum CorpsRefuse {
    /// L'émetteur a ANNONCÉ sa taille : on peut lui dire exactement de combien il dépasse.
    Annonce { recu: usize, plafond: usize },
    /// Rien n'était annoncé : la lecture s'est arrêtée au plafond, sans qu'on puisse distinguer
    /// « trop gros » de « interrompu ». On le dit.
    Lecture { plafond: usize },
}

impl CorpsRefuse {
    pub(crate) fn message(&self) -> String {
        let mio = |o: usize| format!("{:.2} Mio", o as f64 / (1024.0 * 1024.0));
        match self {
            CorpsRefuse::Annonce { recu, plafond } => format!(
                "corps trop volumineux : {recu} octets ({}) > plafond {plafond} octets ({}) — \
                 la limite qui vous arrête se compte en OCTETS, pas en événements ; \
                 scindez le lot et réémettez, ou relevez PLUME_INGEST_MAX_BODY_MB",
                mio(*recu),
                mio(*plafond)
            ),
            CorpsRefuse::Lecture { plafond } => format!(
                "corps refusé à la lecture au plafond de {plafond} octets ({}) — \
                 la taille reçue est inconnue car l'émetteur n'a pas annoncé de Content-Length \
                 (transfert chunké) : ce refus couvre aussi une lecture interrompue. \
                 La limite se compte en OCTETS, pas en événements ; \
                 scindez le lot et réémettez, ou relevez PLUME_INGEST_MAX_BODY_MB",
                mio(*plafond)
            ),
        }
    }
}

/// LA COUCHE. Elle borne le corps AVANT tout handler, et rend le refus de plume plutôt que celui
/// d'axum. Le corps lu est réinjecté tel quel : les handlers en aval ne changent pas d'un octet.
pub(crate) async fn borne_le_corps(req: Request, next: Next) -> Response {
    let plafond = corps_max_octets();
    let (parties, corps) = req.into_parts();

    // Refus AVANT lecture quand l'émetteur annonce déjà trop : on ne lit pas 8 Mio pour les jeter,
    // et le message peut nommer la taille exacte.
    if let Some(annonce) = parties
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<usize>().ok())
    {
        if annonce > plafond {
            return err_json(
                StatusCode::PAYLOAD_TOO_LARGE,
                CorpsRefuse::Annonce { recu: annonce, plafond }.message(),
            );
        }
    }

    match axum::body::to_bytes(corps, plafond).await {
        Ok(octets) => next.run(Request::from_parts(parties, Body::from(octets))).await,
        Err(_) => err_json(StatusCode::PAYLOAD_TOO_LARGE, CorpsRefuse::Lecture { plafond }.message()),
    }
}

#[cfg(test)]
mod limite_corps_tests {
    use super::*;

    /// LE REFUS NOMME LES QUATRE CHOSES SANS LESQUELLES IL EST INUTILISABLE : la taille reçue quand
    /// elle est connue, le plafond, l'UNITÉ, et le levier. C'est précisément ce que le message
    /// d'axum ne disait pas — et ce défaut a coûté une matrice de banc entière avant d'être compris.
    ///
    /// MUTATION : retirer `PLUME_INGEST_MAX_BODY_MB` du message ⇒ la 4ᵉ assertion passe au ROUGE.
    #[test]
    fn le_refus_nomme_la_limite_son_unite_et_le_levier() {
        let m = CorpsRefuse::Annonce { recu: 10_611_526, plafond: 8 * 1024 * 1024 }.message();
        assert!(m.contains("10611526"), "la taille REÇUE doit être nommée : {m}");
        assert!(m.contains("8388608"), "le PLAFOND doit être nommé en octets : {m}");
        assert!(m.contains("Mio"), "l'UNITÉ doit être lisible par un humain : {m}");
        assert!(m.contains("PLUME_INGEST_MAX_BODY_MB"), "le LEVIER doit être nommé : {m}");
        assert!(m.contains("OCTETS"), "l'unité qui ARRÊTE doit être distinguée des événements : {m}");
    }

    /// Le cas chunké ne DEVINE pas : il annonce son ignorance au lieu d'affirmer « trop gros »,
    /// parce qu'une erreur de lecture produit exactement le même symptôme.
    #[test]
    fn le_cas_sans_content_length_avoue_ce_quil_ignore() {
        let m = CorpsRefuse::Lecture { plafond: 8 * 1024 * 1024 }.message();
        assert!(m.contains("inconnue"), "l'ignorance doit être DITE, pas masquée : {m}");
        assert!(m.contains("interrompue"), "l'autre cause possible doit être nommée : {m}");
        assert!(m.contains("PLUME_INGEST_MAX_BODY_MB"), "le levier reste nommé : {m}");
    }

    /// Le DÉFAUT reproduit à l'octet le `DefaultBodyLimit::max(8 * 1024 * 1024)` remplacé : ce
    /// module ne change PAS le comportement, seulement ce qui est dit quand il mord.
    #[test]
    fn le_defaut_reproduit_exactement_lancien_plafond() {
        assert_eq!(CORPS_MAX_MO_DEFAUT * 1024 * 1024, 8 * 1024 * 1024);
    }
}

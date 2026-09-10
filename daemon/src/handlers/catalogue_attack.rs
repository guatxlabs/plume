//! `P11.6-c` — LA ROUTE DÉDIÉE DU CATALOGUE ATT&CK : `GET /api/attack/catalogue`, viewer+, lecture seule.
//!
//! POURQUOI UNE ROUTE À PART. La seule route qui portait des noms de techniques était la matrice de
//! couverture (`/api/coverage/attack`) : une AGRÉGATION sur la table des alertes, sous permis de requête,
//! qui n'énumère que des techniques PARENTES. L'appeler pour un dictionnaire, c'est payer un scan pour un
//! libellé, et elle ne saurait de toute façon nommer une sous-technique. Les surfaces dont les routes
//! servent `mitre` NU (file d'alertes, administration des règles, couverture des détections) nommaient
//! donc par une table de la console tenue à la main — 14 libellés sur 183 + 16 — et ce qu'elle ignorait
//! arrivait à l'exploitant en numéro seul (`T1562`, `T1195.002`, mesurés en usage réel le 2026-08-27).
//!
//! CE QUE CETTE ROUTE EST. Un objet CONSTANT dérivé de `attack_names` (`catalogue_attack_json`) : aucune
//! lecture de base, aucun permis, aucune donnée sensible — des identifiants publics de MITRE et leurs
//! noms. GET sous `/api/` : `route_min_role` la classe en lecture (section 6), donc viewer+ sans ligne
//! à ajouter, et une identité reste exigée comme pour tout le reste de l'API.
use crate::*;

/// GET `/api/attack/catalogue` — le catalogue nommé, entier, tel que le démon le rend partout ailleurs.
pub(crate) async fn attack_catalogue(Extension(_au): Extension<AuthUser>) -> Json<Value> {
    Json(crate::attack_names::catalogue_attack_json())
}

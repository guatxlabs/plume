//! Comptes utilisateurs (réservé admin) et tables de correspondance (lookups) : CRUD utilisateurs
//! (`users_list`/`user_create`/`user_delete`/`user_update`) et lookups (`value_to_lookup_str`/
//! `build_lookup_kv`, `lookups_list`/`lookup_upload`/`lookup_delete`).
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ---------- comptes utilisateurs (réservé admin via auth_guard) ----------
pub(crate) async fn users_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    // `P10.7-f` (rang 1) — « QUI A ACCÈS » EST LU ENTIÈREMENT OU AVOUÉ. Avant : deux `unwrap()` (une
    // panique n'est pas un aveu) puis `rows.flatten()` — un compte dont la ligne ne se décode pas
    // disparaissait de la liste que l'AUDIT lit, sans un mot. Soldé en bloc ; sur échec, la liste n'est
    // pas ÉTABLIE et le corps le dit par `error`, au lieu d'un inventaire d'accès rassurant.
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare("SELECT id,name,role,created FROM user ORDER BY id")
        .and_then(|mut stmt| {
            stmt.query_map([], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?,
                    "role": r.get::<_, String>(2)?, "created": r.get::<_, i64>(3)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    // P11.5-c — QUI A ACCÈS. `user` ne porte QUE les comptes que le produit crée : un compte d'annuaire
    // externe (SSO d'en-têtes) accède sans jamais y avoir de ligne. `acces` est l'inventaire de CEUX QUI
    // ACCÈDENT, quelle que soit leur provenance, consigné au choke-point d'authentification. Rendu À CÔTÉ
    // de `users` (jamais fondu dedans) : `users` reste la liste GÉRABLE ici (créer/éditer/supprimer),
    // `acces` est un CONSTAT, y compris pour des comptes que cette console ne peut pas administrer.
    // Aucun secret n'y figure — cf. `acces_observe`, la table n'en porte aucun.
    let acces = crate::acces_observe::inventaire_des_acces(&conn);
    match lues {
        Ok(locaux) => Json(json!({ "users": locaux, "me": au.name, "acces": acces })),
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(
            json!({ "me": au.name, "acces": acces }),
            "users",
        )),
    }
}

pub(crate) async fn user_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.trimmed("name");
    let pw = b.str_field("password");
    let role = match b.get("role").and_then(|v| v.as_str()) {
        Some("admin") => "admin",
        Some("viewer") => "viewer",
        _ => "editor",
    };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return (StatusCode::BAD_REQUEST, "nom invalide (alphanumérique, . _ - uniquement)").into_response();
    }
    // MODE ENGAGEMENT : le préfixe `eng-cred-` est RÉSERVÉ aux credentials mintés par le provisioning
    // d'engagement (compte scopé + hard-expiry). L'interdire à la création interactive garantit qu'aucun
    // compte durable ne peut usurper ce discriminant du chemin d'auth (hard-expiry + no-cache).
    if name.starts_with(ENG_CRED_PREFIX) {
        return (StatusCode::BAD_REQUEST, "préfixe 'eng-cred-' réservé aux credentials d'engagement").into_response();
    }
    // `P10.24-u` — LE NOM DE L'ADMINISTRATEUR DE CONFIGURATION EST RÉSERVÉ, ICI COMME À LA FÉDÉRATION (même règle,
    // `reserved_static_admin`). Mesuré le 2026-09-24 sur la forme d'avant : `root`, administrateur de configuration
    // (graine du second facteur active, une requête enregistrée et un instantané capturé au rôle `admin` à son nom),
    // `adm` crée `root` `viewer` — 200. Son mot de passe de configuration rend alors 401 (la ligne créée fait
    // autorité) ; il rendait encore 200, rôle `admin`, tant que le cache d'authentification gardait sa dernière
    // connexion (cinq minutes : la création ne le vide pas). Le nouveau titulaire, avec son propre mot de passe, était
    // arrêté au second facteur de l'administrateur de configuration, puis, avec un code de CETTE graine, recevait une
    // session `viewer` qui listait sa requête privée et son instantané avec le jeton. Jugé AVANT le hachage : c'est
    // un fait de configuration, aucune lecture de la base n'y entre.
    if crate::handlers::idp::reserved_static_admin(&st) == Some(name.as_str()) {
        return err_json(StatusCode::CONFLICT, CAUSE_NOM_DE_L_ADMINISTRATEUR_DE_CONFIGURATION);
    }
    // POLITIQUE MDP (item 3) — à la CRÉATION du compte uniquement (les comptes existants intacts).
    if pw.chars().count() < PASSWORD_MIN_CHARS {
        return (StatusCode::BAD_REQUEST, format!("mot de passe trop court (≥ {PASSWORD_MIN_CHARS} caractères)")).into_response();
    }
    let hash = hash_pw(pw);
    crate::req_conn!(st, au, conn);
    // AUDIT D'IDENTITÉ : création de compte = mutation d'IDENTITÉ -> AUDIT fail-closed DANS la transaction (patron
    // audit_config_change des lookups/notifiers). Sans trace, un admin compromis plante une persistance
    // (nouvel admin) invisible. Le hash n'est JAMAIS mis dans l'audit — seuls actor/target/rôle. Créer un
    // ADMIN = sévérité 4 (HIGH, alertable) ; editor/viewer = 3.
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    // `P10.24-u` — CE QUE LE NOM TIENT DÉJÀ SANS COMPTE, lu SOUS le verrou d'écriture de la création : rien ne peut
    // s'y ajouter entre la lecture et l'écriture. Voir `ce_que_le_nom_tient_sans_compte`.
    match ce_que_le_nom_tient_sans_compte(&conn, &name) {
        Ok(None) => {}
        Ok(Some(tenue)) => {
            let _ = conn.execute_batch("ROLLBACK");
            return (StatusCode::CONFLICT, Json(json!({ "error": CAUSE_NOM_TENU_PAR_UNE_IDENTITE_SANS_COMPTE, "ce_que_le_nom_tient": tenue })))
                .into_response();
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            eprintln!("[comptes] WARN création du compte '{name}' refusée : nom non vérifié ({e})");
            return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_NOM_NON_VERIFIE_COMPTE_NON_CREE);
        }
    }
    let sev = if role == "admin" { 4 } else { 3 };
    let outcome: rusqlite::Result<i64> = (|| {
        conn.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![name, hash, role])?;
        let id = conn.last_insert_rowid();
        audit_config_change(
            &conn, "config.user.create",
            &format!("compte '{name}' (rôle {role}) créé par {}", au.name), sev,
            &format!("compte utilisateur '{name}' créé (rôle {role}) par {}", au.name),
            &json!({ "action": "config.user.create", "kind": "user", "target": name, "role": role, "actor": au.name }).to_string(),
        )?;
        Ok(id)
    })();
    match outcome {
        // `P10.24-x` — l'identifiant n'est rendu qu'une fois la transaction VALIDÉE.
        Ok(id) => match valider_la_transaction(&conn) {
            Ok(()) => Json(json!({ "id": id })).into_response(),
            Err(e) => {
                eprintln!("[comptes] WARN création du compte '{name}' NON validée : {e}");
                err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_COMPTE_NON_CREE_COMMIT_REFUSE)
            }
        },
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : rien de persisté sans audit
            // distinguer un conflit de nom (UNIQUE) d'un vrai échec d'audit — même sémantique 409 qu'avant.
            let es = e.to_string();
            if es.contains("UNIQUE") || es.contains("constraint") {
                (StatusCode::CONFLICT, "ce nom de compte existe déjà").into_response()
            } else {
                server_err(format!("échec transaction audit (aucune modification): {e}"))
            }
        }
    }
}

/// `P10.24-u` — LE NOM DE L'ADMINISTRATEUR DE CONFIGURATION NE DEVIENT PAS UN COMPTE.
pub(crate) const CAUSE_NOM_DE_L_ADMINISTRATEUR_DE_CONFIGURATION: &str = "NOM RÉSERVÉ, C'EST L'ADMINISTRATEUR DE \
     CONFIGURATION : ce nom est celui du compte d'administration que pose la configuration du démon, sans ligne dans \
     la table des comptes. Un compte de ce nom le masquerait — la table des comptes fait autorité, son mot de passe de \
     configuration ne serait plus consulté — et hériterait de ce qu'il tient par son nom : graine du second facteur, \
     requêtes, tableaux de bord, instantanés. Choisissez un autre nom. Rien n'est écrit.";

/// `P10.24-u` — UN NOM TENU SANS COMPTE LOCAL NE DEVIENT PAS UN COMPTE À MOT DE PASSE.
pub(crate) const CAUSE_NOM_TENU_PAR_UNE_IDENTITE_SANS_COMPTE: &str = "NOM TENU PAR UNE IDENTITÉ SANS COMPTE LOCAL : \
     ce nom a accédé par l'annuaire externe (SSO d'en-têtes), ou tient encore, sans ligne dans la table des comptes, \
     des objets, une graine du second facteur ou des préférences — le détail est dans `ce_que_le_nom_tient`. Un compte \
     à mot de passe de ce nom en hériterait, et partagerait son nom avec une identité de l'annuaire, hors de portée de \
     l'annuaire qui la révoque. Choisissez un autre nom ; un nom de l'annuaire devient un compte par la fédération \
     (OIDC, SAML, LDAP), sans mot de passe local. Rien n'est écrit.";

/// `P10.24-u` — la vérification du nom n'a pas eu lieu : aucun compte ne se crée sur un nom non vérifié.
pub(crate) const CAUSE_NOM_NON_VERIFIE_COMPTE_NON_CREE: &str = "COMPTE NON CRÉÉ, NOM NON VÉRIFIÉ : la base n'a pas \
     pu dire si ce nom est déjà tenu par une identité sans compte local (lecture refusée ou table illisible), et un \
     compte ne se crée pas sur un nom qu'on n'a pas pu vérifier. Réessayez. Rien n'est écrit.";

/// `P10.24-x` — le `COMMIT` de la création refusé.
pub(crate) const CAUSE_COMPTE_NON_CREE_COMMIT_REFUSE: &str = "COMPTE NON CRÉÉ : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — ni le compte ni sa trace d'audit ne sont écrits. Réessayez ; si le \
     refus persiste, la base est en lecture seule, pleine ou verrouillée.";

/// `P10.24-x` — le `COMMIT` de la suppression refusé.
pub(crate) const CAUSE_COMPTE_NON_SUPPRIME_COMMIT_REFUSE: &str = "COMPTE NON SUPPRIMÉ : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — le compte, ses objets, sa graine du second facteur, ses préférences \
     et ses sessions sont intacts, et ni ses échecs de connexion ni le frein de son second facteur ne sont oubliés. \
     Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";

/// `P10.24-x` — le `COMMIT` de la modification refusé.
pub(crate) const CAUSE_COMPTE_NON_MODIFIE_COMMIT_REFUSE: &str = "COMPTE NON MODIFIÉ : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — ni son rôle ni son mot de passe n'ont changé, et ses sessions ne sont \
     pas révoquées. Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";

/// `P10.24-x` — le `COMMIT` d'un chargement ou d'une suppression de table d'enrichissement refusé.
pub(crate) const CAUSE_TABLE_D_ENRICHISSEMENT_INCHANGEE: &str = "TABLE D'ENRICHISSEMENT INCHANGÉE : la base n'a pas \
     validé la transaction (COMMIT refusé) et l'a annulée — le contenu d'avant est intact et aucune trace n'est écrite. \
     Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";

/// `P10.24-u` — LES LIGNES HORS OBJETS QUI DONNENT UNE AUTORITÉ À UN NOM : la graine du second facteur (que
/// `login_post` lit par nom) et les préférences. Ce sont celles que `user_delete` purge avec le compte (`P10.24-c`).
const LIGNES_DU_COMPTE_HORS_OBJETS: [(&str, &str); 2] = [("user_mfa", "user"), ("user_pref", "user")];

/// `P10.24-u` — TOUT CE QU'UN NOM TIENT PAR UNE COLONNE D'AUTORITÉ, `(table, colonne)`. Dérivé des listes de la
/// suppression (`P10.24-p`) : un objet que la suppression emporte ou réattribue est, du même geste, un objet que la
/// création refuse de faire hériter. Les colonnes d'ATTESTATION (`created_by` d'un dossier, `acked_by`, `author`…)
/// n'y sont pas : elles n'octroient rien.
fn colonnes_d_autorite_par_nom() -> impl Iterator<Item = (&'static str, &'static str)> {
    OBJETS_PURGES_AVEC_LE_COMPTE
        .into_iter()
        .chain(OBJETS_REATTRIBUES_A_L_AUTEUR.into_iter().map(|table| (table, "owner")))
        .chain(LIGNES_DU_COMPTE_HORS_OBJETS)
}

/// `P10.24-u` — CE QUE TIENT UN NOM QUI N'A PAS DE LIGNE DANS `user`, ET QU'UN COMPTE À MOT DE PASSE DE CE NOM
/// PRENDRAIT. `Ok(None)` : le nom a déjà un compte (la création bute sur l'unicité, comme avant) ou ne tient rien ;
/// `Ok(Some(détail))` : la création est refusée ; `Err` : la lecture n'a pas eu lieu, rien n'est conclu.
///
/// LE DÉFAUT, MESURÉ LE 2026-09-24 SUR LA FORME D'AVANT. `carol`, vue par l'annuaire (SSO d'en-têtes, groupe
/// administrateur, consignée à l'inventaire des accès) et propriétaire d'une requête privée, d'un tableau de bord
/// privé et d'un instantané capturé au rôle `admin` : `adm` crée `carol` `viewer` (200). Le nouveau compte, par son
/// mot de passe, listait la requête et l'instantané, et le jeton servait les données figées (200). Et les en-têtes
/// résolvaient toujours `carol` en `admin` : une requête que le compte local écrivait se lisait par l'identité de
/// l'annuaire — deux authentifications, un seul nom, l'une hors de portée de l'annuaire qui révoque l'autre.
///
/// DEUX CRITÈRES, INDÉPENDANTS :
///  * LE NOM A ACCÉDÉ PAR L'ANNUAIRE (`acces_observe`, méthode `sso`), qu'il tienne ou non des objets : l'annuaire
///    peut le présenter à nouveau à tout moment, et rien ici ne dit qu'il l'a retiré. L'inventaire est la seule
///    trace de ces noms ; il est plafonné, et une vue très ancienne peut en avoir cédé — d'où le second critère ;
///  * LE NOM TIENT DES LIGNES PAR UNE COLONNE D'AUTORITÉ (`colonnes_d_autorite_par_nom`) sans ligne `user` : une
///    identité de l'annuaire sortie de l'inventaire, un administrateur de configuration retiré de la configuration,
///    ou un compte supprimé avant que la suppression n'emporte ses objets (`P10.24-t`, que ce refus borne à la
///    création sans rien nettoyer).
/// Un nom vu comme compte LOCAL (mot de passe, session) puis supprimé n'est pas réservé : la suppression a emporté ce
/// qu'il tenait, et son homonyme se recrée.
///
/// QUAND UN NOM DE L'ANNUAIRE DEVIENT-IL UN COMPTE ? PAR LA FÉDÉRATION SEULEMENT. `idp_provision_user` (OIDC, SAML,
/// LDAP) pose une ligne SANS mot de passe (`IDP_HASH_SENTINEL`) : l'annuaire reste l'autorité qui l'authentifie et
/// le révoque, et c'est le pendant de ce qu'elle refuse déjà — fédérer sur un nom tenu par un compte à mot de passe.
/// Elle n'est pas touchée. Un compte LOCAL, lui, n'est jamais la même personne que l'identité de l'annuaire par la
/// seule parole de celui qui le crée : il prend un autre nom.
fn ce_que_le_nom_tient_sans_compte(conn: &Connection, nom: &str) -> rusqlite::Result<Option<Value>> {
    let a_un_compte: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM user WHERE name=?1)", params![nom], |r| r.get(0))?;
    if a_un_compte {
        return Ok(None);
    }
    let vu_par_l_annuaire: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM acces_observe WHERE nom=?1 AND methode='sso')",
        params![nom],
        |r| r.get(0),
    )?;
    let mut lignes = serde_json::Map::new();
    for (table, colonne) in colonnes_d_autorite_par_nom() {
        let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table} WHERE {colonne}=?1"), params![nom], |r| r.get(0))?;
        if n > 0 {
            lignes.insert(table.to_string(), json!(n));
        }
    }
    if !vu_par_l_annuaire && lignes.is_empty() {
        return Ok(None);
    }
    Ok(Some(json!({ "vu_par_l_annuaire": vu_par_l_annuaire, "lignes": lignes })))
}

/// `P10.24-x` — LE `COMMIT` D'UN GESTE DE CE MODULE EST JUGÉ, ET UN REFUS FERME LA TRANSACTION.
///
/// LE DÉFAUT, MESURÉ LE 2026-09-24 SUR LA FORME D'AVANT (`COMMIT` refusé par un autorisateur SQLite) : `user_create`
/// rendait 200 et l'identifiant d'un compte qui n'a jamais existé ; `user_delete` rendait 204 et avait déjà oublié les
/// échecs de connexion du compte, toujours là ; `user_update` rendait 204, `lookup_upload` 200. L'énoncé sous-comptait :
/// dans les quatre cas la transaction restait OUVERTE sur la connexion d'écriture partagée, et le geste suivant
/// (une autre création) échouait à `BEGIN IMMEDIATE` — 500 « verrou base indisponible ».
///
/// Après un `COMMIT` refusé, SQLite peut avoir annulé la transaction de lui-même ou l'avoir laissée ouverte, selon
/// l'erreur : le `ROLLBACK` couvre les deux (dans le premier cas il échoue sans effet, et cet échec n'est pas une
/// information). S'il ne ferme pas la transaction, le journal le dit : l'écrivain est alors bloqué.
fn valider_la_transaction(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("COMMIT").map_err(|refus| {
        let _ = conn.execute_batch("ROLLBACK");
        if !conn.is_autocommit() {
            eprintln!("[comptes] ERREUR transaction toujours ouverte après un COMMIT refusé puis un ROLLBACK : l'écrivain est bloqué");
        }
        refus
    })
}

/// `P10.24-n` — LE COMPTE DE L'ADMINISTRATEUR DE L'ASSISTANT NE SE SUPPRIME PAS.
pub(crate) const CAUSE_COMPTE_DE_L_ASSISTANT_NON_SUPPRIMABLE: &str = "COMPTE NON SUPPRIMÉ, C'EST L'ADMINISTRATEUR \
     DE L'INSTALLATION : ce compte a été posé par l'assistant d'installation, et le démon garde sa crédence hors de \
     la table des comptes. Supprimé, il se reconnecterait en administrateur par son mot de passe d'installation — \
     même réinitialisé, même rétrogradé — jusqu'au redémarrage ; et au redémarrage, sans mot de passe de \
     configuration, le démon repartirait en mode installation, tous les comptes refusés. Pour lui retirer l'accès, \
     réinitialisez son mot de passe : ses sessions tombent. Rien n'est écrit.";

/// `P10.24-p` — LES OBJETS QU'UN COMPTE POSSÈDE PAR SON NOM ET QUI PASSENT À L'AUTEUR DE SA SUPPRESSION (colonne
/// `owner`). Liste FERMÉE, jamais lue d'un corps : les noms entrent tels quels dans l'énoncé.
const OBJETS_REATTRIBUES_A_L_AUTEUR: [&str; 4] = ["dashboard", "view", "library_panel", "playlist"];

/// `P10.24-p` — LES OBJETS QU'UN COMPTE POSSÈDE PAR SON NOM ET QUI PARTENT AVEC LUI : `(table, colonne du nom)`.
const OBJETS_PURGES_AVEC_LE_COMPTE: [(&str, &str); 2] = [("saved_query", "owner"), ("dashboard_snapshot", "created_by")];

/// `P10.24-p` — les identifiants des lignes de `table` dont `colonne` porte `nom`, lus EN BLOC (une ligne illisible
/// fait échouer la transaction, elle ne disparaît pas du compte rendu).
fn identifiants_au_nom(conn: &Connection, table: &str, colonne: &str, nom: &str) -> rusqlite::Result<Vec<i64>> {
    conn.prepare(&format!("SELECT id FROM {table} WHERE {colonne}=?1 ORDER BY id"))?
        .query_map(params![nom], |r| r.get::<_, i64>(0))?
        .collect()
}

/// `P10.24-p` — une écriture qui doit toucher EXACTEMENT les lignes lues juste avant, dans la même transaction.
fn exactement(ecrites: usize, lues: usize) -> rusqlite::Result<()> {
    if ecrites == lues { Ok(()) } else { Err(rusqlite::Error::StatementChangedRows(ecrites)) }
}

/// `P10.24-p` — CE QUE LA SUPPRESSION FAIT DES OBJETS DU COMPTE, DANS SA TRANSACTION, ET CE QU'ELLE EN ATTESTE.
///
/// LE DÉFAUT, MESURÉ LE 2026-09-24 SUR LA FORME D'AVANT. `bob` supprimé puis recréé comme `viewer` : le nouveau `bob`
/// listait la requête enregistrée de l'ancien, son tableau de bord, sa vue, son panneau de bibliothèque et sa
/// playlist PRIVÉS — tous « modifiables » — et son INSTANTANÉ avec son jeton, capturé au rôle `admin` : des données
/// figées sans masque, servies à un `viewer` qui ne les aurait jamais vues. L'énoncé ne nommait ni les panneaux de
/// bibliothèque, ni les playlists, ni les instantanés.
///
/// LA DÉCISION, TABLE PAR TABLE. Recensement par NOM de colonne sur le schéma migré : seules celles-ci donnent une
/// autorité à un nom, avec `user_mfa` et `user_pref`, déjà purgées (`P10.24-c`). Toutes les autres ATTESTENT un
/// geste passé et ne se réécrivent pas — `created_by`, `updated_by`, `acked_by`, `author`, `actor`, `*_par`,
/// `archived_by`, `disposition_by`, `released_by`, `authorizer`, l'inventaire `acces_observe` — ou servent de filtre
/// sans rien octroyer (`incident.owner`, `incident.assignee` : tout dossier se lit par tout lecteur) :
///  * `dashboard`, `view`, `library_panel`, `playlist` : RÉATTRIBUÉS À L'AUTEUR DE LA SUPPRESSION. Ils peuvent être
///    communs et servir à d'autres (un panneau de bibliothèque rattaché ailleurs, une playlist sur un écran, une vue
///    qui regroupe des tableaux) : les purger détruirait le travail des autres. L'auteur est administrateur, et un
///    administrateur voit et modifie déjà chacun d'eux, privés compris : la réattribution n'ouvre rien à personne,
///    elle retire seulement l'objet au prochain homonyme. Leur visibilité ne change pas.
///  * `saved_query` : PURGÉES. Privées par construction — même un administrateur ne lit pas celles d'autrui —, elles
///    sont de la nature de `user_pref`, déjà purgée : les donner à l'auteur ouvrirait à un administrateur, par une
///    suppression, des notes qu'aucun administrateur ne lit.
///  * `dashboard_snapshot` : PURGÉS. Leur colonne est à la fois l'autorité (liste, jeton, suppression) et la
///    provenance affichée à qui lit le lien : la réattribuer ferait dire « capturé par » à qui ne l'a pas capturé.
///    Ce sont des données dérivées, figées au rôle d'un compte qui n'existe plus ; le tableau de bord reste, on
///    recapture.
/// Aucune désactivation : il faudrait une colonne, donc une migration. Rien n'est laissé au nom du compte supprimé.
///
/// LA TRACE : les identifiants de chaque objet réattribué ou purgé vont dans l'événement d'audit de la suppression
/// (source `plume-config`, non purgeable), leurs comptes dans la ligne du registre (chaînée) — l'ancien
/// propriétaire de chaque objet reste lisible là où rien ne s'efface.
struct ObjetsDuCompteSupprime {
    reattribues: Vec<(&'static str, Vec<i64>)>,
    purges: Vec<(&'static str, Vec<i64>)>,
}

impl ObjetsDuCompteSupprime {
    fn traiter(conn: &Connection, nom: &str, heritier: &str) -> rusqlite::Result<Self> {
        // Un héritier sans nom laisserait des objets privés SANS propriétaire, ce que rien n'écrit (`P11.20-n`) :
        // l'échec fait tomber toute la suppression.
        if heritier.is_empty() {
            return Err(rusqlite::Error::ToSqlConversionFailure("P10.24-p : auteur de la suppression sans nom, aucun héritier pour ses objets".into()));
        }
        let mut purges = Vec::new();
        for (table, colonne) in OBJETS_PURGES_AVEC_LE_COMPTE {
            let ids = identifiants_au_nom(conn, table, colonne, nom)?;
            exactement(conn.execute(&format!("DELETE FROM {table} WHERE {colonne}=?1"), params![nom])?, ids.len())?;
            purges.push((table, ids));
        }
        let mut reattribues = Vec::new();
        for table in OBJETS_REATTRIBUES_A_L_AUTEUR {
            let ids = identifiants_au_nom(conn, table, "owner", nom)?;
            exactement(conn.execute(&format!("UPDATE {table} SET owner=?1 WHERE owner=?2"), params![heritier, nom])?, ids.len())?;
            reattribues.push((table, ids));
        }
        Ok(Self { reattribues, purges })
    }

    fn en_json(liste: &[(&'static str, Vec<i64>)]) -> Value {
        Value::Object(liste.iter().map(|(table, ids)| (table.to_string(), json!(ids))).collect())
    }

    fn en_phrase(liste: &[(&'static str, Vec<i64>)]) -> String {
        liste.iter().map(|(table, ids)| format!("{table} {}", ids.len())).collect::<Vec<_>>().join(", ")
    }
}

pub(crate) async fn user_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    // `P10.24-n` — la base visée est-elle celle qui porte le compte de l'assistant ? Toujours en mode 0 ; en mode
    // multi-tenant, seulement pour le tenant `default` (un homonyme dans un autre tenant n'est pas cette crédence).
    let base_de_l_assistant = Arc::ptr_eq(&req_db(&st, &au), &st.db);
    crate::req_conn!(st, au, conn);
    let target: Option<(String, String)> = conn
        .query_row("SELECT name,role FROM user WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
        .ok();
    let Some((tname, trole)) = target else {
        return (StatusCode::NOT_FOUND, "compte introuvable").into_response();
    };
    if tname == au.name {
        return (StatusCode::BAD_REQUEST, "impossible de supprimer son propre compte").into_response();
    }
    // `P10.24-n` — LE COMPTE DE L'ADMINISTRATEUR DE L'ASSISTANT N'EST PAS UN COMPTE COMME LES AUTRES. Mesuré le
    // 2026-09-24 sur la forme d'avant : l'administrateur `wiz` posé par l'assistant, puis réinitialisé ET rétrogradé
    // `viewer` par un autre administrateur (son mot de passe d'installation refusé, 401) ; supprimé (204) — et ce
    // mot de passe d'installation se reconnectait (200), en ADMINISTRATEUR, session résolue `admin`, Basic aussi :
    // `authenticate` et la résolution de session retombent, pour un nom absent de `user`, sur `st.admin`, la
    // crédence en mémoire posée à l'installation ou au dernier `/api/password`, que ni la réinitialisation ni la
    // rétrogradation ne touchent. Et au redémarrage (LU, `server/mod.rs`) : `meta.admin_user` nomme un compte
    // absent, l'administrateur de l'assistant n'est pas rechargé, et sans mot de passe de configuration le démon
    // repart en MODE INSTALLATION — toute l'API refusée à tous, administrateurs compris.
    // POURQUOI REFUSER PLUTÔT QUE RETIRER LA CRÉDENCE AVEC LE COMPTE : l'état « installé » du démon EST cette crédence
    // (`auth_guard`, `setup_status`, `setup_post`). La retirer met l'installation en mode installation SUR-LE-CHAMP,
    // avec aucun jeton d'installation (il n'est frappé qu'au démarrage) : plus personne n'entre, puis au redémarrage
    // l'installation appartient au porteur du jeton. C'est l'installation sans administrateur que l'anti-
    // verrouillage ci-dessous interdit pour le DERNIER administrateur ; ce refus en est le pendant pour le compte
    // dont dépend l'état installé, jugé par NOM (une rétrogradation préalable ne le contourne pas). Le retrait d'accès reste possible : la
    // réinitialisation du mot de passe par un autre administrateur, qui révoque ses sessions (`P10.23-l`).
    let compte_de_l_assistant = st.admin.lock().as_ref().is_some_and(|(nom, _)| *nom == tname);
    if base_de_l_assistant && compte_de_l_assistant {
        return err_json(StatusCode::BAD_REQUEST, CAUSE_COMPTE_DE_L_ASSISTANT_NON_SUPPRIMABLE);
    }
    if trole == "admin" {
        let admins: i64 = conn.query_row("SELECT COUNT(*) FROM user WHERE role='admin'", [], |r| r.get(0)).unwrap_or(0);
        if admins <= 1 {
            return (StatusCode::BAD_REQUEST, "dernier administrateur — suppression refusée").into_response();
        }
    }
    // AUDIT D'IDENTITÉ : suppression de compte = mutation d'identité -> AUDIT fail-closed transactionnel. Supprimer un
    // ADMIN = sévérité 4. Rien n'est purgé sans trace (source=plume-config, non-purgeable).
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let sev = if trole == "admin" { 4 } else { 3 };
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM user WHERE id=?1", params![id])?;
        // `P10.24-c` — CE QUI EST LIÉ AU NOM PART AVEC LE COMPTE, ET SES JETONS AVEC LUI. Mesuré le 2026-09-24 sur la
        // forme d'avant : après cette suppression puis la création d'un homonyme, la session frappée AVANT résolvait
        // l'identité du NOUVEAU compte (son époque, restée à zéro, était celle du jeton), le ticket MFA d'avant
        // ouvrait une session avec un code de l'ANCIENNE graine, et la connexion du nouveau titulaire était arrêtée
        // au second facteur de l'ancien — `user_mfa` et `user_pref` survivaient. L'époque du compte AVANCE (sa clé
        // `meta` survit à la ligne : un homonyme repart au-delà de tout jeton frappé pour l'ancien), la graine et les
        // codes de secours sont retirés, les préférences aussi — DANS cette transaction : pas de compte supprimé dont
        // les jetons vaudraient encore pour son homonyme, ni de purge sans suppression.
        let seconds_facteurs_retires = conn.execute("DELETE FROM user_mfa WHERE user=?1", params![tname])?;
        conn.execute("DELETE FROM user_pref WHERE user=?1", params![tname])?;
        // `P10.24-p` — ses objets, dans CETTE transaction : purgés ou réattribués à l'auteur, et attestés ci-dessous.
        let objets = ObjetsDuCompteSupprime::traiter(&conn, &tname, &au.name)?;
        avancer_l_epoque_du_compte(&conn, &tname)?;
        audit_config_change(
            &conn, "config.user.delete",
            &format!(
                "compte '{tname}' (rôle {trole}) supprimé par {} ; objets réattribués à {} : {} ; purgés : {}",
                au.name,
                au.name,
                ObjetsDuCompteSupprime::en_phrase(&objets.reattribues),
                ObjetsDuCompteSupprime::en_phrase(&objets.purges),
            ),
            sev,
            &format!("compte utilisateur '{tname}' supprimé (rôle {trole}) par {}", au.name),
            &json!({
                "action": "config.user.delete", "kind": "user", "target": tname, "role": trole, "actor": au.name,
                "second_facteur_retire": seconds_facteurs_retires > 0,
                "objets_reattribues_a": au.name,
                "objets_reattribues": ObjetsDuCompteSupprime::en_json(&objets.reattribues),
                "objets_purges": ObjetsDuCompteSupprime::en_json(&objets.purges),
            })
            .to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            // `P10.24-x` — un `COMMIT` refusé n'est pas une suppression : 503 nommé, et la mémoire n'oublie rien.
            if let Err(e) = valider_la_transaction(&conn) {
                eprintln!("[comptes] WARN suppression du compte '{tname}' NON validée : {e}");
                return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_COMPTE_NON_SUPPRIME_COMMIT_REFUSE);
            }
            st.auth_cache.lock().clear(); // invalide les creds en cache du compte supprimé
            // `P10.24-o` — ce que la mémoire tient par NOM pour ce compte part avec lui, APRÈS le commit VALIDÉ : le
            // compteur d'échecs de la connexion (toutes adresses) et le frein du second facteur. Un homonyme recréé
            // repart de zéro ; une suppression refusée (ci-dessus comme ci-dessous) ne touche à rien.
            oublier_les_echecs_du_compte_supprime(&st, &tname);
            crate::handlers::idp::oublier_le_frein_du_compte_supprime(&st, &tname);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

// MAJ d'un compte (admin only via auth_guard) : rôle et/ou reset du mot de passe.
//
// `P10.24-a` — SON PROPRE MOT DE PASSE SE CHANGE PAR LE MOT DE PASSE ACTUEL, PAS PAR LA SESSION. Mesuré le 2026-09-24
// sur la forme d'avant : sous la seule session de `adm`, `{password}` sur son propre identifiant rendait 204, et
// `{password, current: <faux>}` aussi (`current` n'était pas lu) — la prise de compte que `P10.23-m` a fermée sur
// `/api/password` restait ouverte ici, et le titulaire, dont les sessions tombent avec le changement, était mis
// dehors. Quand la cible EST l'appelant et que le corps change le mot de passe, `current` est jugé par le jugement
// partagé avec `/api/password` (`juger_le_mot_de_passe_actuel`) : même preuve, même verrou (compte, adresse) que la
// connexion, mêmes refus nommés. Un compte SANS mot de passe local (fédéré) ne s'en pose pas un sur la foi de sa
// session — une session fédérée volée devenait sinon un mot de passe local, hors de portée de l'annuaire qui la
// révoque ; un AUTRE administrateur peut le poser.
//
// LE GESTE D'ADMINISTRATION SUR UN AUTRE COMPTE RESTE, SANS LE MOT DE PASSE DE SON AUTEUR. C'est son objet : le
// titulaire a oublié le sien, ou il faut lui retirer l'accès. Ce qui le borne : il est attesté au registre et au SIEM
// sous le nom de son auteur (sévérité 4, alertable, règle d'auto-détection des mutations d'identité), et le compte
// VISÉ perd ses sessions et ses tickets (`P10.23-l`). Le mot de passe de l'AUTEUR n'y est pas exigé : un
// administrateur servi par un SSO d'en-têtes n'en a pas, et la même persistance s'obtient par d'autres gestes
// d'administration (créer ou promouvoir un administrateur, frapper un jeton) — une preuve récente se décide pour eux
// tous à la fois, pas pour l'un d'eux.
pub(crate) async fn user_update(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Extension(au): Extension<AuthUser>,
    Path(id): Path<i64>,
    Json(b): Json<Value>,
) -> Response {
    let new_pw = b.get("password").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty());
    let new_role = b.get("role").and_then(|v| v.as_str());
    // LECTURE ET VALIDATION sous le verrou de la base, RELÂCHÉ avant la preuve : en mode 0 la base de la requête est
    // celle que la preuve relit (`prouver_le_premier_facteur` la verrouille à son tour).
    let (tname, trole, role_change) = {
        crate::req_conn!(st, au, conn);
        let target: Option<(String, String)> = conn
            .query_row("SELECT name,role FROM user WHERE id=?1", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .ok();
        let Some((tname, trole)) = target else { return (StatusCode::NOT_FOUND, "compte introuvable").into_response(); };
        // VALIDATION AVANT toute écriture (rôle valide, anti-lockout, longueur mdp) — inchangé, mais hors transaction.
        let role_change: Option<&str> = if let Some(nr) = new_role {
            let role = match nr { "admin" => "admin", "editor" => "editor", "viewer" => "viewer", _ => return (StatusCode::BAD_REQUEST, "rôle invalide (admin|editor|viewer)").into_response() };
            // anti-lockout : ne pas rétrograder le DERNIER admin
            if trole == "admin" && role != "admin" {
                let admins: i64 = conn.query_row("SELECT COUNT(*) FROM user WHERE role='admin'", [], |r| r.get(0)).unwrap_or(0);
                if admins <= 1 { return (StatusCode::BAD_REQUEST, "dernier administrateur — rétrogradation refusée").into_response(); }
            }
            Some(role)
        } else { None };
        if let Some(pw) = new_pw {
            if pw.chars().count() < PASSWORD_MIN_CHARS { return (StatusCode::BAD_REQUEST, format!("mot de passe trop court (≥ {PASSWORD_MIN_CHARS} caractères)")).into_response(); } // POLITIQUE MDP (item 3) — reset admin uniquement
        }
        (tname, trole, role_change)
    };
    // `P10.24-a` — jugé APRÈS la validation, comme `/api/password` : un corps irrecevable n'engage aucun essai du mot
    // de passe actuel. Un refus n'écrit RIEN, pas même le rôle demandé dans le même corps.
    let son_propre_compte = tname == au.name;
    if new_pw.is_some() && son_propre_compte {
        if let Err(refus) = juger_le_mot_de_passe_actuel(
            &st,
            &tname,
            &peer.ip().to_string(),
            b.str_field("current"),
            CAUSE_SON_PROPRE_COMPTE_SANS_MOT_DE_PASSE_LOCAL,
            &format!("réinitialisation du mot de passe de son propre compte '{tname}' refusée : mot de passe actuel refusé"),
        ) {
            return refus;
        }
    }
    crate::req_conn!(st, au, conn);
    // AUDIT D'IDENTITÉ : changement de rôle ET/OU reset mdp = mutations d'identité -> AUDIT fail-closed transactionnel
    // (un audit PAR type de changement : role_change / password_reset). Un reset mdp ou une escalade vers admin
    // = sévérité 4 (HIGH, alertable). Le nouveau hash n'est JAMAIS mis dans l'audit.
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    // `P10.24-a` — le verrou relâché pour la preuve, les écritures visent le compte LU ET JUGÉ (identifiant ET nom) :
    // un identifiant réattribué entre-temps ne reçoit pas un mot de passe prouvé pour un autre compte.
    let une_ligne = |ecrites: usize| if ecrites == 1 { Ok(()) } else { Err(rusqlite::Error::StatementChangedRows(ecrites)) };
    let outcome: rusqlite::Result<()> = (|| {
        if let Some(role) = role_change {
            une_ligne(conn.execute("UPDATE user SET role=?1 WHERE id=?2 AND name=?3", params![role, id, tname])?)?;
            let sev = if role == "admin" || trole == "admin" { 4 } else { 3 };
            audit_config_change(
                &conn, "config.user.role_change",
                &format!("compte '{tname}' : rôle {trole} -> {role} par {}", au.name), sev,
                &format!("rôle du compte '{tname}' modifié ({trole} -> {role}) par {}", au.name),
                &json!({ "action": "config.user.role_change", "kind": "user", "target": tname, "from": trole, "to": role, "actor": au.name }).to_string(),
            )?;
        }
        if let Some(pw) = new_pw {
            une_ligne(conn.execute("UPDATE user SET hash=?1 WHERE id=?2 AND name=?3", params![hash_pw(pw), id, tname])?)?;
            // `P10.23-l` — LA RÉINITIALISATION RÉVOQUE LES SESSIONS ET LES TICKETS MFA DU SEUL COMPTE RÉINITIALISÉ.
            // Mesuré le 2026-09-24 sur la forme d'avant : après ce 204, la session d'avant du compte résolvait
            // encore son identité, et un ticket MFA émis avant ouvrait encore une session — l'époque de session est
            // GLOBALE et ce chemin ne la touchait pas (l'avancer déconnecterait tous les comptes). L'époque du
            // COMPTE avance DANS cette transaction : pas de mot de passe réinitialisé sans ses jetons d'avant
            // révoqués, ni l'inverse.
            avancer_l_epoque_du_compte(&conn, &tname)?;
            // `P10.24-a` — l'attestation dit si c'est le titulaire (mot de passe actuel prouvé) ou un autre.
            let par_qui = if son_propre_compte { " (son propre compte, mot de passe actuel prouvé)" } else { "" };
            audit_config_change(
                &conn, "config.user.password_reset",
                &format!("mot de passe du compte '{tname}' réinitialisé par {}{par_qui}", au.name), 4,
                &format!("mot de passe du compte '{tname}' (rôle {trole}) réinitialisé par {}{par_qui}", au.name),
                &json!({
                    "action": "config.user.password_reset", "kind": "user", "target": tname, "actor": au.name,
                    "mot_de_passe_actuel_prouve": son_propre_compte,
                })
                .to_string(),
            )?;
        }
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            // `P10.24-x` — un `COMMIT` refusé ne change ni le rôle ni le mot de passe : 503 nommé.
            if let Err(e) = valider_la_transaction(&conn) {
                eprintln!("[comptes] WARN modification du compte '{tname}' NON validée : {e}");
                return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_COMPTE_NON_MODIFIE_COMMIT_REFUSE);
            }
            st.auth_cache.lock().clear(); // invalide le cache d'auth (rôle/mdp changés)
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

// ---------- LOOKUP : tables d'enrichissement (admin only via auth_guard) ----------
// NOYAU FONCTIONNEL : table + endpoint admin minimal + op GXQL `lookup`. L'UI de GESTION (formulaire
// d'upload CSV/JSON, édition, aperçu) est un SUIVI ULTÉRIEUR — ici seul l'endpoint REST est exposé.

/// Convertit une valeur JSON scalaire en chaîne exploitable comme clé/valeur de lookup. String -> telle
/// quelle ; nombre/bool -> représentation textuelle ; null/objet/array -> None (clé inexploitable).
pub(crate) fn value_to_lookup_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Transforme les lignes d'upload `[{...}]` en paires (key, val_json) + l'ensemble ordonné des colonnes
/// de sortie. PURE (testable sans DB). Pour chaque ligne : la valeur de `key_field` devient la CLÉ ;
/// les AUTRES paires (clé passant `soql_ident_ok`, donc requêtable via json_extract) sont sérialisées
/// dans `val`. Lignes sans clé exploitable -> ignorées. `val` est TOUJOURS du JSON valide par
/// construction (un `val` malformé ne peut donc pas naître de l'API ; le compilo garde de toute façon
/// `json_valid` en lecture).
pub(crate) fn build_lookup_kv(key_field: &str, rows: &[Value]) -> (Vec<(String, String)>, Vec<String>) {
    let mut out_cols: Vec<String> = Vec::new();
    let mut kv: Vec<(String, String)> = Vec::new();
    for row in rows {
        let Some(obj) = row.as_object() else { continue };
        let key = match obj.get(key_field).and_then(value_to_lookup_str) {
            Some(k) if !k.is_empty() => k,
            _ => continue,
        };
        let mut val = serde_json::Map::new();
        for (k, v) in obj {
            if k == key_field || !soql_ident_ok(k) {
                continue;
            }
            if !out_cols.iter().any(|c| c == k) {
                out_cols.push(k.clone());
            }
            val.insert(k.clone(), v.clone());
        }
        kv.push((key, Value::Object(val).to_string()));
    }
    (kv, out_cols)
}

/// GET /api/lookups -> liste des lookups déclarés (depuis lookup_meta) + nombre de lignes par lookup.
pub(crate) async fn lookups_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    // `P10.7-f` (rang 4, vague b) — L'INVENTAIRE DES LOOKUPS EST ENTIER OU AVOUÉ. Avant : DEUX `unwrap()`
    // (une table `lookup_meta` retirée PANIQUAIT — une panique n'est pas un aveu) puis
    // `rows.flatten().collect::<Vec<_>>()`, qui jetait la ligne dont le mappeur échoue (`name` corrompu,
    // colonne de migration que la connexion qui sert ne voit pas encore) et servait le reste comme une
    // liste complète. Un lookup absent d'ici se lit « ce lookup n'existe pas », et c'est la conclusion la
    // plus trompeuse du rang : la commande `lookup <nom> …` de GXQL CONTINUE de fonctionner sur lui (elle
    // lit `lookup_kv`, pas cette vue), donc un enrichissement qu'on croit absent est en réalité
    // INVISIBLE — on le recharge par un upload qui REMPLACE intégralement son contenu, et l'ancien est
    // perdu pour de bon. Même forme d'aveu que `users_list` dans ce fichier
    // (`liste_bornee::corps_de_liste_illisible` : `lookups` présente et VIDE, `error` nomme la cause).
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare(
            "SELECT m.name, m.key_field, m.cols, m.updated, \
             (SELECT COUNT(*) FROM lookup_kv k WHERE k.name=m.name) \
             FROM lookup_meta m ORDER BY m.name",
        )
        .and_then(|mut stmt| {
            stmt.query_map([], |r| {
                Ok(json!({
                    "name": r.get::<_, String>(0)?,
                    "key_field": r.get::<_, Option<String>>(1)?,
                    "cols": r.get::<_, Option<String>>(2)?,
                    "updated": r.get::<_, Option<i64>>(3)?,
                    "rows": r.get::<_, i64>(4)?,
                    // D12 — origine du contenu (badge managed, cohérent avec rule/parser/playbook). Les lookups
                    // n'ont ni seed builtin ni overlay config.d : tout lookup est créé via l'UI/API => 2 (perso).
                    "managed": 2,
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    match lues {
        Ok(rows) => Json(json!({ "lookups": rows })),
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({}), "lookups")),
    }
}

/// POST /api/lookups {name, key_field, rows:[{...}]} -> REMPLACE intégralement le contenu du lookup
/// `name` (UPSERT, val = JSON des colonnes hors `key_field`). Valide name/key_field via soql_ident_ok.
pub(crate) async fn lookup_upload(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.trimmed("name");
    let key_field = b.trimmed("key_field");
    // #1c garde-fou #1 (lookup) : nom + champ-clé au format identifiant GXQL (soql_ident_ok), rows = tableau.
    if !soql_ident_ok(&name) {
        return bad_req("nom de lookup invalide (alphanumérique + _)");
    }
    if !soql_ident_ok(&key_field) {
        return bad_req("champ-clé invalide (alphanumérique + _)");
    }
    let Some(rows) = b.get("rows").and_then(|v| v.as_array()) else {
        return bad_req("champ 'rows' (tableau d'objets) requis");
    };
    let (kv, out_cols) = build_lookup_kv(&key_field, rows);
    crate::req_conn!(st, au, conn);
    // #1c garde-fou #6 : remplacement ATOMIQUE fail-closed + audit #1b (ledger + event plume-config). Si un
    // write ou l'audit échoue -> ROLLBACK (aucun remplacement partiel, aucune mutation sans trace).
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM lookup_kv WHERE name=?1", params![name])?;
        {
            let mut ins = conn.prepare("INSERT OR REPLACE INTO lookup_kv(name,\"key\",val) VALUES(?1,?2,?3)")?;
            for (k, v) in &kv {
                ins.execute(params![name, k, v])?;
            }
        }
        conn.execute(
            "INSERT OR REPLACE INTO lookup_meta(name,key_field,cols,updated) VALUES(?1,?2,?3,?4)",
            params![name, key_field, out_cols.join(","), now()],
        )?;
        audit_config_change(
            &conn, "config.lookup.upload",
            &format!("lookup '{name}' ({} lignes) chargé par {}", kv.len(), au.name), 2,
            &format!("table d'enrichissement '{name}' remplacée ({} lignes) par {}", kv.len(), au.name),
            &json!({ "op": "upload", "kind": "lookup", "name": name, "rows": kv.len(), "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        // `P10.24-x` — le remplacement n'est annoncé qu'une fois la transaction VALIDÉE.
        Ok(()) => match valider_la_transaction(&conn) {
            Ok(()) => Json(json!({ "name": name, "rows": kv.len(), "cols": out_cols })).into_response(),
            Err(e) => {
                eprintln!("[lookup] WARN remplacement de '{name}' NON validé : {e}");
                err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TABLE_D_ENRICHISSEMENT_INCHANGEE)
            }
        },
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

/// DELETE /api/lookups/{name} -> supprime le lookup (lignes kv + métadonnées). #1c : audit fail-closed.
pub(crate) async fn lookup_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(name): Path<String>) -> Response {
    if !soql_ident_ok(&name) {
        return bad_req("nom de lookup invalide");
    }
    crate::req_conn!(st, au, conn);
    // existe ? (pour renvoyer 404 sans ouvrir de transaction inutile)
    if conn.query_row("SELECT 1 FROM lookup_meta WHERE name=?1", params![name], |_| Ok(())).is_err() {
        return not_found("lookup introuvable");
    }
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return server_err("verrou base indisponible");
    }
    let outcome: rusqlite::Result<()> = (|| {
        conn.execute("DELETE FROM lookup_kv WHERE name=?1", params![name])?;
        conn.execute("DELETE FROM lookup_meta WHERE name=?1", params![name])?;
        audit_config_change(
            &conn, "config.lookup.delete",
            &format!("lookup '{name}' supprimé par {}", au.name), 3,
            &format!("table d'enrichissement '{name}' supprimée par {}", au.name),
            &json!({ "op": "delete", "kind": "lookup", "name": name, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        // `P10.24-x` — la suppression n'est annoncée qu'une fois la transaction VALIDÉE.
        Ok(()) => match valider_la_transaction(&conn) {
            Ok(()) => Json(json!({ "ok": true, "deleted": true })).into_response(),
            Err(e) => {
                eprintln!("[lookup] WARN suppression de '{name}' NON validée : {e}");
                err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TABLE_D_ENRICHISSEMENT_INCHANGEE)
            }
        },
        Err(e) => { let _ = conn.execute_batch("ROLLBACK"); server_err(format!("échec transaction audit (aucune modification): {e}")) }
    }
}

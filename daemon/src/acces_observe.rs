//! L'INVENTAIRE DES COMPTES QUI ACCÈDENT (`P11.5-c`) — qui a atteint la console, d'où il vient, ce qu'il
//! peut, et quand il a été vu.
//!
//! CE QUI ÉTAIT CASSÉ. La liste des comptes servie par la console était `SELECT id,name,role,created FROM
//! user` : la table des comptes que le produit CRÉE. Un compte venu d'un annuaire externe (SSO d'en-têtes :
//! le proxy pose le nom et les groupes, le rôle est mappé depuis les groupes) n'a JAMAIS de ligne dans
//! cette table. Il administrait la console sans figurer nulle part, et personne ne pouvait répondre à
//! « qui a accès ». MESURÉ le 2026-08-23 sur le routeur réel : un compte SSO du groupe administrateur
//! obtient `role=admin` sur `/api/me` et `/api/users` ne rend que le compte local.
//!
//! CE QUE FAIT CE MODULE. Le point de passage UNIQUE de l'authentification (`auth_guard`) consigne chaque
//! identité RÉSOLUE : son nom, sa PROVENANCE (annuaire externe / compte local / jeton / démonstration), son
//! rôle EFFECTIF au dernier accès, l'ORIGINE de ce rôle, la méthode, la première et la dernière vue. La
//! provenance n'est pas devinée : elle est DÉRIVÉE de la méthode d'authentification et d'une lecture de la
//! table des comptes (« ce nom existe-t-il localement ? »), les deux étant séparés — une fonction PURE
//! décide, l'appelant fournit le fait.
//!
//! CE QU'IL NE FAIT PAS. Aucun secret n'entre dans la table : ni empreinte de mot de passe, ni jeton, ni la
//! valeur brute des groupes de l'annuaire (elle nommerait l'organisation interne du client). Ce n'est pas
//! non plus un journal d'accès : UNE ligne par (nom, provenance), écrasée à chaque vue — l'historique
//! requête par requête vit dans les événements, pas ici.
//!
//! CE QUE ÇA COÛTE. Une écriture est DÉBOUNCÉE par identité (`ACCES_OBSERVE_DEBOUNCE_S`) : le verrou
//! d'écriture n'est pris qu'une fois par fenêtre et par compte, jamais par requête. La table est
//! PLAFONNÉE (`ACCES_OBSERVE_PLAFOND`) : au-delà, la vue la plus ancienne cède — un flux d'identités
//! forgées ne peut pas faire grossir la base sans borne.
use crate::*;

/// Fenêtre de débounce d'écriture, par (nom, provenance). Une identité qui martèle la console n'écrit
/// qu'une fois par fenêtre : « quand a-t-il été vu » se répond à la minute près, pas à la requête près.
pub(crate) const ACCES_OBSERVE_DEBOUNCE_S: i64 = 300;

/// Plafond de lignes de `acces_observe`. Au-delà, les vues les plus ANCIENNES cèdent. Borne les octets ET
/// le coût de la lecture d'inventaire, y compris si un porteur du secret d'en-tête forgeait des noms.
pub(crate) const ACCES_OBSERVE_PLAFOND: i64 = 2000;

/// Longueur maximale d'un nom consigné. Un nom plus long est TRONQUÉ (jamais rejeté : un compte qui accède
/// doit apparaître). Borne l'octet écrit sans jamais faire disparaître un accès de l'inventaire.
pub(crate) const ACCES_OBSERVE_NOM_MAX: usize = 128;

/// PROVENANCE ET ORIGINE DU RÔLE, DÉRIVÉES — fonction PURE (aucun état, testable seule).
///
/// `methode` est celle que `resolve_identity` a retenue ; `connu_localement` dit si ce nom porte une ligne
/// dans la table des comptes. Les deux sont nécessaires : le mot de passe applicatif (Basic) authentifie
/// AUSSI l'administrateur du wizard et l'identifiant de configuration, qui n'ont pas de ligne — les
/// confondre avec un compte local mentirait sur « d'où il vient ».
///
/// Rend `(provenance, origine_du_role)`, deux phrases destinées à être LUES telles quelles dans la console.
pub(crate) fn provenance_de(methode: &str, connu_localement: bool) -> (&'static str, &'static str) {
    match methode {
        // Le proxy d'authentification pose le nom et les groupes ; le rôle est mappé depuis les groupes.
        "sso" => ("annuaire externe", "groupes de l'annuaire"),
        // Jetons de machine : le nom EST l'hôte lié au jeton (agent/HEC) ou le nom du jeton (source de
        // données, lecture client). Le rôle est porté par le jeton, jamais par un compte.
        "bearer" | "hec" => ("jeton d'agent", "jeton (rôle agent, lié à un hôte)"),
        "datasource" => ("jeton de source de données", "jeton (rôle de lecture)"),
        "client" => ("jeton client", "jeton (rôle client, lecture seule)"),
        // Démonstration publique : identité forcée, lecture seule, aucun compte derrière.
        "demo" => ("démonstration publique", "mode démonstration (lecture seule)"),
        // Mot de passe applicatif / cookie de session : compte local SI la table le porte, sinon
        // l'identifiant d'amorçage (wizard ou configuration) — qui n'est pas gérable dans la liste.
        _ if connu_localement => ("compte local", "table des comptes"),
        _ => ("identifiant d'amorçage", "configuration du démon (hors table des comptes)"),
    }
}

/// Registre de débounce : (tenant, nom, provenance) -> horodatage de la dernière écriture. Même patron que
/// `OPERATOR_ACCESS_LAST` (rbac) : `OnceLock<Mutex<HashMap>>`, purgé quand il enfle. LE TENANT EST DANS LA
/// CLÉ : l'inventaire vit dans la base DU TENANT, donc un compte vu sur un tenant n'a rien écrit sur un
/// autre — un débounce qui l'ignorerait ferait disparaître un accès d'une base pendant toute la fenêtre.
static ACCES_OBSERVE_DERNIERE_ECRITURE: std::sync::OnceLock<Mutex<HashMap<(String, String, String), i64>>> =
    std::sync::OnceLock::new();

/// Vrai si cette identité DOIT être écrite maintenant (fenêtre écoulée, ou jamais vue dans ce processus).
/// Réarme la fenêtre quand il rend vrai. Borné anti-OOM (purge des entrées hors fenêtre au-delà de 4096).
pub(crate) fn doit_consigner(tenant: &str, nom: &str, provenance: &str, maintenant: i64) -> bool {
    let cell = ACCES_OBSERVE_DERNIERE_ECRITURE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut g = cell.lock();
    if g.len() > 4096 {
        g.retain(|_, &mut last| maintenant - last < ACCES_OBSERVE_DEBOUNCE_S);
    }
    let cle = (tenant.to_string(), nom.to_string(), provenance.to_string());
    let ecoulee = g
        .get(&cle)
        .map(|&last| maintenant - last >= ACCES_OBSERVE_DEBOUNCE_S)
        .unwrap_or(true);
    if ecoulee {
        g.insert(cle, maintenant);
    }
    ecoulee
}

/// ÉCRIT la vue d'une identité dans `acces_observe` (UPSERT keyé par (nom, provenance)), puis applique le
/// plafond. `premiere_vue` n'est JAMAIS écrasée (le `DO UPDATE` ne touche que ce qui change). Best-effort :
/// une base en lecture seule ou une table absente n'interrompt AUCUNE requête — l'inventaire est un
/// contrôle, pas un chemin de données.
pub(crate) fn ecrire_vue(
    conn: &Connection,
    nom: &str,
    provenance: &str,
    role_effectif: &str,
    origine_du_role: &str,
    methode: &str,
    maintenant: i64,
) {
    let nom: String = nom.chars().take(ACCES_OBSERVE_NOM_MAX).collect();
    let _ = conn.execute(
        "INSERT INTO acces_observe(nom,provenance,role_effectif,origine_du_role,methode,premiere_vue,derniere_vue) \
         VALUES(?1,?2,?3,?4,?5,?6,?6) \
         ON CONFLICT(nom,provenance) DO UPDATE SET \
           role_effectif=excluded.role_effectif, origine_du_role=excluded.origine_du_role, \
           methode=excluded.methode, derniere_vue=excluded.derniere_vue",
        params![nom, provenance, role_effectif, origine_du_role, methode, maintenant],
    );
    appliquer_le_plafond(conn);
}

/// Fait céder les vues les plus ANCIENNES au-delà de `ACCES_OBSERVE_PLAFOND`. Un `DELETE … WHERE rowid NOT
/// IN (les N plus récentes)` : idempotent, sans curseur, et sans jamais dépasser le plafond même si
/// plusieurs écritures se croisent.
fn appliquer_le_plafond(conn: &Connection) {
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM acces_observe", [], |r| r.get(0))
        .unwrap_or(0);
    if n <= ACCES_OBSERVE_PLAFOND {
        return;
    }
    let _ = conn.execute(
        "DELETE FROM acces_observe WHERE rowid NOT IN \
         (SELECT rowid FROM acces_observe ORDER BY derniere_vue DESC, rowid DESC LIMIT ?1)",
        params![ACCES_OBSERVE_PLAFOND],
    );
}

/// LE POINT DE PASSAGE — appelé par `auth_guard` avec l'identité RÉSOLUE (nom, rôle effectif, méthode,
/// tenant). Débounce d'abord (aucun verrou d'écriture pris hors fenêtre), puis résout la provenance en
/// LISANT la table des comptes, puis écrit. Best-effort de bout en bout.
pub(crate) fn consigner_l_acces(st: &AppState, tenant: &str, nom: &str, role_effectif: &str, methode: &str) {
    if nom.is_empty() {
        return;
    }
    let maintenant = now();
    // La provenance dépend d'une lecture ; le débounce, lui, ne doit pas la payer. On débounce donc sur la
    // provenance PRESUMEE par la seule méthode (le cas `connu_localement` ne change la provenance QUE pour
    // les méthodes à mot de passe, et un compte ne change pas d'existence en 5 minutes).
    let (provenance_presumee, _) = provenance_de(methode, true);
    if !doit_consigner(tenant, nom, provenance_presumee, maintenant) {
        return;
    }
    let handle = if st.multi_tenant {
        match st.tenants.handle_for(tenant) {
            Some(h) => h,
            None => return, // tenant non résoluble : jamais d'écriture dans la base d'un autre
        }
    } else {
        st.db.clone()
    };
    let conn = handle.lock();
    let connu_localement = conn
        .query_row("SELECT 1 FROM user WHERE name=?1", params![nom], |r| r.get::<_, i64>(0))
        .is_ok();
    let (provenance, origine_du_role) = provenance_de(methode, connu_localement);
    ecrire_vue(&conn, nom, provenance, role_effectif, origine_du_role, methode, maintenant);
}

/// LECTURE DE L'INVENTAIRE pour la console (route déjà réservée à l'administrateur). Rend les accès du plus
/// récemment vu au plus ancien. Aucune colonne sensible n'existe dans cette table : il n'y a rien à filtrer
/// ici, et c'est la table elle-même qui le garantit. Une table absente (base d'un binaire antérieur) rend
/// une liste VIDE — jamais une erreur qui masquerait l'inventaire local.
pub(crate) fn inventaire_des_acces(conn: &Connection) -> Vec<Value> {
    let mut stmt = match conn.prepare(
        "SELECT nom,provenance,role_effectif,origine_du_role,methode,premiere_vue,derniere_vue \
         FROM acces_observe ORDER BY derniere_vue DESC, nom",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    stmt.query_map([], |r| {
        Ok(json!({
            "nom": r.get::<_, String>(0)?,
            "provenance": r.get::<_, String>(1)?,
            "role_effectif": r.get::<_, String>(2)?,
            "origine_du_role": r.get::<_, String>(3)?,
            "methode": r.get::<_, String>(4)?,
            "premiere_vue": r.get::<_, i64>(5)?,
            "derniere_vue": r.get::<_, i64>(6)?,
        }))
    })
    .map(|x| x.flatten().collect())
    .unwrap_or_default()
}

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
use rusqlite::OptionalExtension;

/// Fenêtre de débounce d'écriture, par (nom, provenance). Une identité qui martèle la console n'écrit
/// qu'une fois par fenêtre : « quand a-t-il été vu » se répond à la minute près, pas à la requête près.
pub(crate) const ACCES_OBSERVE_DEBOUNCE_S: i64 = 300;

/// Plafond de lignes de `acces_observe`. Au-delà, les vues les plus ANCIENNES cèdent. Borne les octets ET
/// le coût de la lecture d'inventaire, y compris si un porteur du secret d'en-tête forgeait des noms.
pub(crate) const ACCES_OBSERVE_PLAFOND: i64 = 2000;

/// Longueur maximale d'un nom consigné. Un nom plus long est TRONQUÉ (jamais rejeté : un compte qui accède
/// doit apparaître). Borne l'octet écrit sans jamais faire disparaître un accès de l'inventaire.
pub(crate) const ACCES_OBSERVE_NOM_MAX: usize = 128;

/// CE QUE LA TABLE DES COMPTES DIT D'UN NOM — trois issues, jamais deux (`P10.20-b`). Avant, la lecture
/// « ce nom a-t-il une ligne ? » était un `.is_ok()` : une lecture RATÉE valait « aucune ligne », et un
/// compte local authentifié par mot de passe était inscrit « identifiant d'amorçage / configuration du
/// démon (hors table des comptes) » — une provenance FAUSSE, servie telle quelle à l'administrateur qui
/// demande « qui a accès ». `NonEtablie` porte la troisième issue jusqu'à la phrase servie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExistenceLocale {
    /// La table porte une ligne à ce nom.
    Connue,
    /// La table a été LUE et ne porte aucune ligne à ce nom.
    Absente,
    /// La lecture a échoué : on ne sait pas. Ni « compte local », ni « identifiant d'amorçage ».
    NonEtablie,
}

/// La provenance inscrite quand la table des comptes n'a pas pu être lue pour une méthode à mot de passe
/// (`P10.20-b`). Elle ne choisit pas entre les deux réponses possibles : elle dit qu'aucune n'est établie.
pub(crate) const PROVENANCE_NON_ETABLIE: &str = "provenance non établie";
/// L'origine du rôle dans le même cas : ce qui n'a pas été lu, et ce qui n'est donc pas tranché.
pub(crate) const ORIGINE_NON_ETABLIE: &str =
    "table des comptes non lue à cet accès : compte local ou identifiant d'amorçage, non tranché";

/// PROVENANCE ET ORIGINE DU RÔLE, DÉRIVÉES — fonction PURE (aucun état, testable seule).
///
/// `methode` est celle que `resolve_identity` a retenue ; `connu_localement` dit si ce nom porte une ligne
/// dans la table des comptes. Les deux sont nécessaires : le mot de passe applicatif (Basic) authentifie
/// AUSSI l'administrateur du wizard et l'identifiant de configuration, qui n'ont pas de ligne — les
/// confondre avec un compte local mentirait sur « d'où il vient ».
///
/// Rend `(provenance, origine_du_role)`, deux phrases destinées à être LUES telles quelles dans la console.
/// Forme à deux issues, gardée pour les appelants qui TIENNENT le fait (débounce, témoins) ; le point de
/// passage, lui, passe par `provenance_selon` et sa troisième issue.
pub(crate) fn provenance_de(methode: &str, connu_localement: bool) -> (&'static str, &'static str) {
    provenance_selon(
        methode,
        if connu_localement { ExistenceLocale::Connue } else { ExistenceLocale::Absente },
    )
}

/// La même dérivation, sur les TROIS issues de la lecture de la table des comptes (`P10.20-b`).
pub(crate) fn provenance_selon(methode: &str, existence: ExistenceLocale) -> (&'static str, &'static str) {
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
        // Mot de passe applicatif / cookie de session : compte local SI la table le porte, l'identifiant
        // d'amorçage (wizard ou configuration) — qui n'est pas gérable dans la liste — si elle a été LUE
        // sans le porter, et NI L'UN NI L'AUTRE si elle n'a pas été lue.
        _ => match existence {
            ExistenceLocale::Connue => ("compte local", "table des comptes"),
            ExistenceLocale::Absente => ("identifiant d'amorçage", "configuration du démon (hors table des comptes)"),
            ExistenceLocale::NonEtablie => (PROVENANCE_NON_ETABLIE, ORIGINE_NON_ETABLIE),
        },
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
///
/// UN COMPTAGE RATÉ NE SAUTE PAS LA BORNE (`P10.20-b`). Avant, `.unwrap_or(0)` lisait un comptage raté comme
/// « table vide » et rendait la main : la borne de `ACCES_OBSERVE_PLAFOND` lignes était sautée en silence.
/// Le `DELETE` étant idempotent, il se joue quand le compte n'est pas lu ; le compte ne sert qu'à l'éviter.
pub(crate) fn appliquer_le_plafond(conn: &Connection) {
    match conn.query_row("SELECT COUNT(*) FROM acces_observe", [], |r| r.get::<_, i64>(0)) {
        Ok(n) if n <= ACCES_OBSERVE_PLAFOND => return,
        Ok(_) => {}
        Err(e) => eprintln!("[acces_observe] comptage de l'inventaire NON LU : plafond appliqué sans lui — {e}"),
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
    consigner_dans(&conn, nom, role_effectif, methode, maintenant);
}

/// Lit ce que la table des comptes dit de `nom`, en TROIS issues (`P10.20-b`). Une lecture ratée est dite
/// au journal par la méthode et la cause du moteur — jamais par le nom, qui n'a rien à faire dans un
/// journal d'erreur.
pub(crate) fn existence_locale(conn: &Connection, nom: &str, methode: &str) -> ExistenceLocale {
    match conn
        .query_row("SELECT 1 FROM user WHERE name=?1", params![nom], |r| r.get::<_, i64>(0))
        .optional()
    {
        Ok(Some(_)) => ExistenceLocale::Connue,
        Ok(None) => ExistenceLocale::Absente,
        Err(e) => {
            eprintln!(
                "[acces_observe] table des comptes NON LUE pour un accès par « {methode} » : provenance \
                 inscrite « {PROVENANCE_NON_ETABLIE} » — {e}"
            );
            ExistenceLocale::NonEtablie
        }
    }
}

/// Résout la provenance sur la connexion déjà tenue, puis ÉCRIT la vue — y compris quand la provenance
/// n'est pas établie : ne rien écrire ferait sortir cet accès de l'inventaire pour toute la fenêtre de
/// débounce, puisque `doit_consigner` l'a déjà compté.
pub(crate) fn consigner_dans(conn: &Connection, nom: &str, role_effectif: &str, methode: &str, maintenant: i64) {
    let existence = existence_locale(conn, nom, methode);
    let (provenance, origine_du_role) = provenance_selon(methode, existence);
    ecrire_vue(conn, nom, provenance, role_effectif, origine_du_role, methode, maintenant);
}

/// La clé que `GET /api/users` pose À CÔTÉ de `acces: []` quand l'inventaire n'a pas été lu (`P10.20-b`).
/// Absente du chemin nominal. La console la lit par son nom (`web/admin_users.js`), et le harnais console
/// relit ce nom ICI plutôt que de le recopier.
pub(crate) const CLE_ACCES_NON_LU: &str = "acces_non_lu";

/// La phrase servie sous `CLE_ACCES_NON_LU`. La cause du moteur n'y entre pas : elle va au journal seul.
pub(crate) const CAUSE_INVENTAIRE_DES_ACCES_NON_LU: &str = "INVENTAIRE DES ACCÈS NON LU : la lecture de la \
     liste des comptes qui ont accédé à cette console a échoué. La liste vide servie à côté n'établit PAS que \
     personne n'a accédé — elle n'est pas lue. Le journal du démon porte la cause.";

/// Les trois issues RATÉES de la lecture de l'inventaire (`P10.20-b`). Chacune porte la cause du moteur,
/// destinée au journal ; aucune ne sert une liste.
#[derive(Debug)]
pub(crate) enum InventaireNonLu {
    /// La requête n'a pas pu être préparée (table absente, refusée par l'autorisateur, catalogue illisible).
    Preparation(rusqlite::Error),
    /// Un pas du moteur a échoué en cours de parcours (interruption, budget, page illisible) : les lignes
    /// déjà lues ne sont PAS servies, elles ne seraient qu'un début de liste.
    Pas(rusqlite::Error),
    /// Une ligne ne se décode pas dans la forme attendue.
    LigneIndecodable(rusqlite::Error),
}

impl InventaireNonLu {
    /// Le mot du journal pour l'étape qui a échoué.
    pub(crate) fn etape(&self) -> &'static str {
        match self {
            InventaireNonLu::Preparation(_) => "préparation",
            InventaireNonLu::Pas(_) => "pas du moteur",
            InventaireNonLu::LigneIndecodable(_) => "ligne indécodable",
        }
    }
    /// La cause du moteur — pour le journal seul.
    pub(crate) fn cause(&self) -> &rusqlite::Error {
        match self {
            InventaireNonLu::Preparation(e) | InventaireNonLu::Pas(e) | InventaireNonLu::LigneIndecodable(e) => e,
        }
    }
}

/// LECTURE DE L'INVENTAIRE pour la console (route déjà réservée à l'administrateur). Rend les accès du plus
/// récemment vu au plus ancien. Aucune colonne sensible n'existe dans cette table : il n'y a rien à filtrer
/// ici, et c'est la table elle-même qui le garantit.
///
/// LUE ENTIÈREMENT OU PAS DU TOUT (`P10.20-b`). Avant, une préparation ratée rendait une liste VIDE et un
/// parcours aplati par `.flatten()` SAUTAIT une ligne indécodable ou s'arrêtait au premier pas raté : la
/// liste servie comme complète pouvait être vide ou tronquée. Le commentaire d'alors justifiait le vide
/// par « une base d'un binaire antérieur » — FAUX : `acces_observe` est déclarée dans `db/schema.sql`,
/// donc dans la forme de référence que `migrate::schema_gaps` exige, et `prepare_schema` REFUSE de servir
/// une base qui ne la porte pas. Une table absente pendant le service est une ANOMALIE (supprimée ou
/// renommée après le démarrage, lecture refusée), jamais un état légitime à rendre comme « personne ».
pub(crate) fn inventaire_des_acces(conn: &Connection) -> Result<Vec<Value>, InventaireNonLu> {
    let mut stmt = conn
        .prepare(
            "SELECT nom,provenance,role_effectif,origine_du_role,methode,premiere_vue,derniere_vue \
             FROM acces_observe ORDER BY derniere_vue DESC, nom",
        )
        .map_err(InventaireNonLu::Preparation)?;
    let mut lignes = stmt.query([]).map_err(InventaireNonLu::Pas)?;
    let mut lues = Vec::new();
    loop {
        let ligne = match lignes.next() {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(e) => return Err(InventaireNonLu::Pas(e)),
        };
        let decodee = (|| -> rusqlite::Result<Value> {
            Ok(json!({
                "nom": ligne.get::<_, String>(0)?,
                "provenance": ligne.get::<_, String>(1)?,
                "role_effectif": ligne.get::<_, String>(2)?,
                "origine_du_role": ligne.get::<_, String>(3)?,
                "methode": ligne.get::<_, String>(4)?,
                "premiere_vue": ligne.get::<_, i64>(5)?,
                "derniere_vue": ligne.get::<_, i64>(6)?,
            }))
        })()
        .map_err(InventaireNonLu::LigneIndecodable)?;
        lues.push(decodee);
    }
    Ok(lues)
}

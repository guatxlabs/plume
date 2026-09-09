//! LE COFFRE DE LA RÉSOLUTION « BIBLIOTHÈQUE SINON PANNEAU » (P7.13-a).
//!
//! POURQUOI. Mesuré le 2026-08-03 sur `3256e4d` : la porte « SQL brut = admin » de `panel_update`
//! évaluait `p.is_soql` — la colonne du PANNEAU — alors que l'exécuteur (`panel_access`) résolvait
//! `COALESCE(lp.is_soql, p.is_soql)`, où la valeur de la BIBLIOTHÈQUE gagne. Un `editor` rattachait
//! donc une définition SQL BRUT écrite par un admin (`{"library_panel_id": N}` -> **204**) et en
//! lisait le résultat (`panel_data` -> **200**, 2 lignes de la table `user`). Le même trou existait
//! à la CRÉATION (`panel_create` acceptait `library_panel_id` du corps -> **200**, 2 lignes). Et le
//! rattachement ne regardait NI `visibility` NI `owner` : une définition PRIVÉE d'autrui, ABSENTE de
//! l'inventaire de l'editor (`library_panels_list` -> `[]`), se rattachait quand même (**204**) et
//! rendait son texte (`dash_get`) comme ses données (**200**, 2 lignes).
//!
//! LA DÉRIVATION. On n'ajoute pas une seconde vérification à côté de la première : **la porte
//! EMPRUNTE la résolution de l'exécuteur**. [`DefinitionExecutee`] est le SEUL porteur du couple
//! (requête, `is_soql`) EFFECTIF ; ses champs sont privés et il n'existe aucun constructeur hors de
//! ce module — on ne peut donc pas la fabriquer à partir d'un booléen lu ailleurs. La porte n'est
//! pas une fonction libre prenant un `bool` : c'est [`DefinitionExecutee::permise_pour`], méthode de
//! la valeur résolue. Évaluer autre chose que ce qui s'exécutera n'est plus exprimable.
//!
//! LA GARDE DE COMPILATION. `build.rs` REFUSE de compiler la caisse si la jointure de résolution
//! (`LEFT JOIN library_panel`) ou une colonne résolue (`COALESCE(lp.`) apparaît AILLEURS que dans ce
//! fichier. Un quatrième site de résolution ne peut donc plus naître en silence : il ne compile pas.
//!
//! CE QUE CE COFFRE NE PROMET PAS. Il gouverne le moment de l'ÉCRITURE (rattachement). Une
//! définition rattachée LICITEMENT puis basculée en `private` par son propriétaire reste résolue par
//! les panneaux qui la référencent : la révocation n'est pas rétroactive (décision écrite, épinglée
//! par `une_bibliotheque_passee_privee_apres_coup_reste_resolue`).

use crate::*;

// ---------------------------------------------------------------------------------------------
// L'UNIQUE ÉCRITURE DE LA RÉSOLUTION — empruntée par TOUS les sites de lecture (panel_access,
// dash_get, capture_dashboard_data). `build.rs` interdit toute autre occurrence dans `src/`.
// ---------------------------------------------------------------------------------------------

/// La source résolue : le panneau, joint à la définition qu'il référence (absente -> NULL).
pub(crate) const JOINTURE: &str = "panel p LEFT JOIN library_panel lp ON lp.id=p.library_panel_id";
/// Les colonnes RÉSOLUES. `library_panel.<c>` est `NOT NULL` au schéma -> la bibliothèque gagne dès
/// que la ligne existe, et le panneau reprend la main quand la jointure ne matche pas (référence
/// absente ou pendante). C'est EXACTEMENT ce que reproduit [`DefinitionExecutee::resoudre`].
pub(crate) const COL_TITRE: &str = "COALESCE(lp.title,p.title)";
pub(crate) const COL_QUERY: &str = "COALESCE(lp.query,p.query)";
pub(crate) const COL_IS_SOQL: &str = "COALESCE(lp.is_soql,p.is_soql)";
pub(crate) const COL_VIZ: &str = "COALESCE(lp.viz,p.viz)";
pub(crate) const COL_DRILL: &str = "COALESCE(lp.drill,p.drill,'')";

/// `P11.20-n` — L'AUTORITÉ DE PROPRIÉTAIRE : admin, ou le propriétaire NOMMÉ. UNE COLONNE VIDE
/// N'OCTROIE RIEN.
///
/// LE DÉFAUT MESURÉ (2026-09-03). Douze sites écrivaient `owner.is_empty()` — ou son jumeau SQL
/// `COALESCE(owner,'')=''` — comme une CLAUSE D'OCTROI : une colonne `owner` vide y valait
/// « appartient au lecteur », donc autorité de propriétaire pour QUICONQUE. Or aucun chemin
/// d'écriture ne laisse `owner` vide : `dash_create`, `view_create`, `library_panel_create` et
/// `playlist_create` posent tous `au.name`. Les seules lignes sans propriétaire sont celles que les
/// SEMEURS écrivent — et elles portent TOUTES `visibility='shared'` (mesuré et gardé par
/// `un_objet_seme_declare_son_etat_commun`). La clause n'apportait donc RIEN au bien commun (déjà
/// porté par `shared`) et TOUT à l'accident : sur un dashboard semé,
/// `PorteeLecture::du_dashboard(quiconque, "")` rendait `Proprietaire`, et un panneau `private`
/// posé là était servi à TOUS les comptes — par `dash_get`, par `panel_data`, et FIGÉ dans un
/// snapshot partageable par jeton.
///
/// LA DÉCISION, ET CE QU'ELLE NE FAIT PAS. « Sans propriétaire » cesse d'être une propriété : c'est
/// une ABSENCE. Le bien commun se DÉCLARE, par `visibility='shared'` — colonne qui existe déjà,
/// `NOT NULL DEFAULT 'shared'` au schéma, écrite par les semeurs. AUCUN franchissement de schéma.
/// On n'a pas suivi la prescription voisine « publiques ou à nous » : elle RELÂCHERAIT le démon, qui
/// ne rend que ce qui nous appartient sur `saved_query` (aucun `shared` là-bas, et il n'en gagne pas).
///
/// LA SECONDE MOITIÉ DU MÊME DÉFAUT, TROUVÉE EN L'ÉCRIVANT : `owner == au.name` seul appariait aussi
/// une colonne vide à une IDENTITÉ SANS NOM. Le dépôt en fabrique (`AuthUser { name: String::new() }`
/// pour un relais non lié, cf. `transport_liaison`) — d'où le `!owner.is_empty()` EXPLICITE ici : il
/// REFUSE, il n'octroie pas.
pub(crate) fn autorite_de_proprietaire(owner: &str, au: &AuthUser) -> bool {
    au.is_admin() || (!owner.is_empty() && owner == au.name)
}

/// LA LISIBILITÉ d'un objet de tableau de bord (dashboard, définition de bibliothèque, playlist),
/// écrite UNE FOIS : déclaré commun (`shared`), ou autorité de propriétaire. `library_panels_list`
/// (l'inventaire) et le rattachement l'empruntent tous les deux — ce que l'editor ne VOIT pas, il ne
/// peut donc pas le rattacher — et depuis `P11.20-n` `dash_editable`, `ergo_editable`, `dash_get`,
/// `panel_access` et la capture de snapshot aussi : une seule phrase, six surfaces.
pub(crate) fn lisible_par(owner: &str, visibility: &str, au: &AuthUser) -> bool {
    visibility == "shared" || autorite_de_proprietaire(owner, au)
}

/// CE QUE LE LECTEUR D'UN DASHBOARD A LE DROIT D'Y VOIR. Énum FERMÉ, sans `Default` : tout site qui
/// rend les panneaux d'un dashboard doit TRANCHER (E0061 s'il l'oublie, E0004 s'il ajoute un cas sans
/// le traiter). `dash_get`, `panel_access` et la CAPTURE de snapshot l'empruntent — ils rendaient
/// auparavant trois décisions écrites séparément, et la capture avait oublié la sienne.
///
/// MESURÉ le 2026-08-03 sur `3256e4d` : sur un dashboard PARTAGÉ d'`alice` portant un panneau
/// `visibility='private'`, un `editor` tiers voyait `dash_get` -> `panels: []` et `panel_data` -> 403,
/// mais `snapshot_create` -> **200** avec la ligne privée FIGÉE dans le snapshot, partageable par
/// jeton. L'en-tête du module affirmait pourtant « hérite #45 + RBAC ».
pub(crate) enum PorteeLecture {
    /// Propriétaire du dashboard, ou admin : voit tout. `P11.20-n` — un dashboard SANS propriétaire
    /// n'entre plus ici : personne n'hérite d'une autorité que personne ne détient.
    Proprietaire,
    /// Simple lecteur du partage : ne voit que les panneaux `shared`.
    LecteurDuPartage,
}

impl PorteeLecture {
    /// Résolue par la MÊME règle que `dash_editable`/`dash_get`, EMPRUNTÉE et non réécrite :
    /// [`autorite_de_proprietaire`]. `P11.20-n` — un dashboard sans propriétaire rend
    /// `LecteurDuPartage` À TOUT LE MONDE : ses panneaux `shared` restent servis (le bien commun est
    /// déclaré par `visibility`), ses panneaux `private` ne sont servis à PERSONNE. C'est le prix
    /// assumé de l'absence : un panneau privé sur un objet que nul ne possède n'a pas de destinataire.
    pub(crate) fn du_dashboard(au: &AuthUser, owner: &str) -> Self {
        if autorite_de_proprietaire(owner, au) { Self::Proprietaire } else { Self::LecteurDuPartage }
    }
    /// FAIL-CLOSED : hors `Proprietaire`, seule la valeur EXACTE `shared` ouvre. `panel_access` testait
    /// `!= "private"` là où `dash_get` testait `== "shared"` — une valeur ni l'une ni l'autre (colonne
    /// sans contrainte au schéma) était donc CACHÉE par l'un et SERVIE par l'autre. Une seule règle ici.
    pub(crate) fn voit(&self, visibility: &str) -> bool {
        matches!(self, Self::Proprietaire) || visibility == "shared"
    }
    pub(crate) fn est_proprietaire(&self) -> bool {
        matches!(self, Self::Proprietaire)
    }
}

/// LA RÉFÉRENCE DE BIBLIOTHÈQUE APRÈS ÉCRITURE. Énum FERMÉ, sans `Default` : un site qui écrit un
/// panneau doit CHOISIR ce qu'il advient de la référence, et le passer à [`DefinitionExecutee::projetee`]
/// — l'oublier ne compile pas (E0061). [`Self::du_corps`] est la SEULE lecture du champ
/// `library_panel_id` d'un corps de requête, et la valeur retenue sert À LA FOIS à la porte et à
/// l'écriture : la porte ne peut pas juger d'une référence différente de celle qui sera posée.
pub(crate) enum RefBibliotheque {
    /// Le corps ne parle pas de la référence -> celle du panneau reste en place (PATCH partiel).
    Inchangee,
    /// `null` / `0` -> le panneau redevient autonome.
    Detachee,
    /// Rattachement à une définition.
    Vers(i64),
}

impl RefBibliotheque {
    /// Lit `library_panel_id` d'un corps JSON. `absent` -> `Inchangee` ; `null`/`0` -> `Detachee` ;
    /// entier > 0 -> `Vers`. Un entier NÉGATIF ou un type inattendu -> `Detachee` (fail-closed : on ne
    /// pose jamais une référence qu'on n'a pas su lire). CHANGEMENT ASSUMÉ vs l'ancien code, qui
    /// écrivait tel quel un rowid négatif (référence pendante posée par le client) et ignorait
    /// silencieusement un type inattendu (le panneau restait rattaché malgré la demande contraire).
    pub(crate) fn du_corps(b: &Value) -> Self {
        match b.get("library_panel_id") {
            None => Self::Inchangee,
            Some(v) => match v.as_i64() {
                Some(n) if n > 0 => Self::Vers(n),
                _ => Self::Detachee,
            },
        }
    }

    /// À la CRÉATION il n'y a pas d'état antérieur : `absent` vaut `Detachee` (panneau autonome).
    pub(crate) fn du_corps_a_la_creation(b: &Value) -> Self {
        match Self::du_corps(b) {
            Self::Inchangee => Self::Detachee,
            autre => autre,
        }
    }

    /// La référence EFFECTIVE après écriture, connaissant celle d'avant (`None` à la création).
    fn apres(&self, avant: Option<i64>) -> Option<i64> {
        match self {
            Self::Inchangee => avant,
            Self::Detachee => None,
            Self::Vers(n) => Some(*n),
        }
    }

    /// La valeur à ÉCRIRE dans `panel.library_panel_id`, ou `None` si le corps n'en parle pas (aucune
    /// écriture). `Some(None)` = détacher, `Some(Some(n))` = rattacher.
    pub(crate) fn a_ecrire(&self) -> Option<Option<i64>> {
        match self {
            Self::Inchangee => None,
            Self::Detachee => Some(None),
            Self::Vers(n) => Some(Some(*n)),
        }
    }
}

/// CE QU'UN PANNEAU EXÉCUTE — l'unique porteur du couple (requête, `is_soql`) EFFECTIF. Champs
/// PRIVÉS, aucun `Default`, aucun constructeur hors de ce module : la seule façon d'en obtenir une
/// est de la RÉSOUDRE, donc de lire ce qui s'exécutera vraiment.
pub(crate) struct DefinitionExecutee {
    query: String,
    is_soql: bool,
}

impl DefinitionExecutee {
    pub(crate) fn query(&self) -> &str {
        &self.query
    }
    pub(crate) fn is_soql(&self) -> bool {
        self.is_soql
    }

    /// LA PORTE « SQL BRUT = ADMIN », méthode de la définition RÉSOLUE. Le SQL brut (`is_soql=false`)
    /// = lecture arbitraire de toute la base à chaque refresh -> réservé admin (`raw_sql_allowed`,
    /// #59 : plafond base-admin ET permission `raw_sql` non retirée). Le GXQL reste ouvert à l'editor.
    /// Elle ne prend PAS de booléen : un appelant ne peut pas lui présenter un `is_soql` qui ne serait
    /// pas celui de la définition exécutée.
    pub(crate) fn permise_pour(&self, role: &str) -> bool {
        raw_sql_allowed(self.is_soql, role)
    }

    /// LA RÉSOLUTION, en Rust : la bibliothèque gagne dès que sa ligne EXISTE, sinon le panneau.
    /// Miroir exact de [`COL_QUERY`]/[`COL_IS_SOQL`] (les colonnes de `library_panel` sont `NOT NULL`,
    /// donc `COALESCE` ne retombe sur le panneau que si la jointure ne matche pas). L'équivalence
    /// est PROUVÉE par `la_resolution_rust_egale_la_resolution_sql_sur_une_famille_derivee`.
    fn resoudre(bibliotheque: Option<(String, bool)>, panneau: (String, bool)) -> Self {
        let (query, is_soql) = bibliotheque.unwrap_or(panneau);
        Self { query, is_soql }
    }

    /// L'ÉTAT COURANT d'un panneau existant — ce que `panel_access` sert à `panel_data`.
    pub(crate) fn courante(conn: &Connection, panel_id: i64) -> Option<Self> {
        conn.query_row(
            &format!("SELECT {COL_QUERY},{COL_IS_SOQL} FROM {JOINTURE} WHERE p.id=?1"),
            params![panel_id],
            |r| Ok(Self { query: r.get(0)?, is_soql: r.get::<_, i64>(1)? != 0 }),
        )
        .ok()
    }

    /// L'ÉTAT PROJETÉ : ce que le panneau EXÉCUTERA une fois l'écriture appliquée. C'est CETTE
    /// valeur que la porte juge.
    ///
    /// `bib_avant` = référence actuelle du panneau (`None` à la création) ; `demande` = ce que le
    /// corps réclame ; `panneau_apres` = les colonnes (requête, `is_soql`) du panneau APRÈS PATCH.
    ///
    /// FAIL-CLOSED SUR LA LISIBILITÉ : POSER une référence (`Vers`) vers une définition que
    /// l'appelant n'a pas le droit de VOIR est refusé — et une définition INEXISTANTE renvoie la
    /// MÊME erreur qu'une définition privée d'autrui, pour ne pas offrir d'oracle d'énumération.
    /// La lisibilité est exigée AU MOMENT OÙ LA RÉFÉRENCE EST POSÉE (c'est là qu'un droit s'acquiert) ;
    /// une référence DÉJÀ en place (`Inchangee`) est résolue telle quelle — la révocation d'une
    /// bibliothèque n'est pas rétroactive (décision écrite en tête de module).
    pub(crate) fn projetee(
        conn: &Connection,
        au: &AuthUser,
        bib_avant: Option<i64>,
        demande: &RefBibliotheque,
        panneau_apres: (String, bool),
    ) -> Result<Self, (StatusCode, &'static str)> {
        const INACCESSIBLE: (StatusCode, &str) = (StatusCode::FORBIDDEN, "définition de bibliothèque inaccessible");
        if let RefBibliotheque::Vers(n) = demande {
            match Self::ligne_bibliotheque(conn, *n) {
                Some((_, _, owner, vis)) if lisible_par(&owner, &vis, au) => {}
                _ => return Err(INACCESSIBLE), // privée d'autrui OU inexistante : même réponse
            }
        }
        // Référence PENDANTE héritée (la ligne n'existe plus) : la jointure ne matcherait pas -> le
        // panneau reprend la main. `resoudre` reproduit exactement ce cas avec `None`.
        let bibliotheque = demande
            .apres(bib_avant)
            .and_then(|id| Self::ligne_bibliotheque(conn, id))
            .map(|(q, s, _, _)| (q, s));
        Ok(Self::resoudre(bibliotheque, panneau_apres))
    }

    /// (requête, is_soql, owner, visibility) d'une définition — `None` si la ligne n'existe pas.
    fn ligne_bibliotheque(conn: &Connection, id: i64) -> Option<(String, bool, String, String)> {
        conn.query_row(
            "SELECT query,is_soql!=0,COALESCE(owner,''),COALESCE(visibility,'shared') FROM library_panel WHERE id=?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .ok()
    }
}

// =====================================================================================
// `P11.20-m` — L'ÉLÉMENT MOINS VISIBLE D'UN OBJET COMPOSÉ.
//
// DÉCISION DE PRODUIT de l'exploitant (2026-09-10) : le partage d'un contenant est REFUSÉ tant
// qu'un de ses éléments est moins visible que ce que le geste rendrait commun, et le refus NOMME
// l'élément — ni retrait silencieux, ni simple avertissement de console. La règle est la même pour
// une vue (qui porte des tableaux de bord), un tableau de bord (qui porte des panneaux) et un
// panneau (qui peut exécuter une définition de bibliothèque) : ce sont les trois arêtes que la base
// REPRÉSENTE ; la quatrième, panneau → requête enregistrée, n'existe pas (le panneau COPIE le texte,
// mesuré le 2026-09-03). « Visible » est la valeur EXACTE `shared`, même règle que [`PorteeLecture`] :
// une valeur ni `shared` ni `private` est traitée comme la moins visible, fail-closed.
//
// CE QUE CE REFUS NE FAIT PAS : il ne ferme pas une fuite. Depuis `P11.20-n`, un élément privé posé
// dans un contenant commun n'est servi qu'à qui a l'autorité dessus (`dash_get`, `panel_access`, la
// capture). Le refus rend la RÈGLE explicite au moment du geste, au lieu de laisser l'auteur croire
// qu'il a partagé ce que les lecteurs ne verront pas — et il nomme qui doit agir quand l'élément
// appartient à quelqu'un d'autre.
// =====================================================================================

/// L'élément qui retient un partage : son genre (pour la phrase), son identifiant, son nom, son
/// propriétaire quand il en a un (une définition de bibliothèque d'autrui ne se partage pas depuis
/// le tableau de bord qui l'exécute : c'est à son propriétaire de le faire), et le nombre d'éléments
/// qui retiennent, celui-ci compris — la phrase nomme le premier et compte les autres, pour que
/// l'auteur sache s'il a UN geste à faire ou plusieurs.
pub(crate) struct ElementMoinsVisible {
    pub(crate) genre: &'static str,
    pub(crate) id: i64,
    pub(crate) nom: String,
    pub(crate) proprietaire: String,
    pub(crate) retenus: i64,
}

impl ElementMoinsVisible {
    /// La phrase du refus, telle que la console l'affiche (le corps de la réponse est ce texte).
    pub(crate) fn phrase_de_refus(&self, contenant: &str) -> String {
        let a_qui = if self.proprietaire.is_empty() { String::new() } else { format!(", à {}", self.proprietaire) };
        let autres = if self.retenus > 1 {
            format!(" — et {} autre(s) élément(s) le retiennent aussi", self.retenus - 1)
        } else {
            String::new()
        };
        format!(
            "Partage refusé : {} « {} » (n° {}{a_qui}) est privé{autres}. Partagez d'abord cet élément, ou retirez-le, puis partagez {contenant}.",
            self.genre, self.nom, self.id
        )
    }

    fn premier(conn: &Connection, sql_compte: &str, sql_premier: &str, id: i64, genre: &'static str) -> Option<Self> {
        let retenus: i64 = conn.query_row(sql_compte, params![id], |r| r.get(0)).unwrap_or(0);
        if retenus == 0 {
            return None;
        }
        conn.query_row(sql_premier, params![id], |r| {
            Ok(Self { genre, id: r.get(0)?, nom: r.get(1)?, proprietaire: r.get(2)?, retenus })
        })
        .ok()
    }

    /// Une VUE porte des tableaux de bord (`dashboard.view_id`) : le premier non commun retient.
    pub(crate) fn d_une_vue(conn: &Connection, view_id: i64) -> Option<Self> {
        Self::premier(
            conn,
            "SELECT COUNT(*) FROM dashboard WHERE view_id=?1 AND COALESCE(visibility,'shared')<>'shared'",
            "SELECT id,name,COALESCE(owner,'') FROM dashboard WHERE view_id=?1 AND COALESCE(visibility,'shared')<>'shared' ORDER BY id LIMIT 1",
            view_id,
            "le tableau de bord",
        )
    }

    /// Un TABLEAU DE BORD porte des panneaux : un panneau non commun retient ; sinon, une définition
    /// de bibliothèque non commune qu'un de ses panneaux exécute retient (elle est à son propriétaire).
    pub(crate) fn d_un_tableau_de_bord(conn: &Connection, dash_id: i64) -> Option<Self> {
        Self::premier(
            conn,
            "SELECT COUNT(*) FROM panel WHERE dashboard_id=?1 AND COALESCE(visibility,'shared')<>'shared'",
            "SELECT id,title,'' FROM panel WHERE dashboard_id=?1 AND COALESCE(visibility,'shared')<>'shared' ORDER BY id LIMIT 1",
            dash_id,
            "le panneau",
        )
        .or_else(|| {
            Self::premier(
                conn,
                "SELECT COUNT(*) FROM panel p JOIN library_panel lp ON lp.id=p.library_panel_id \
                 WHERE p.dashboard_id=?1 AND COALESCE(lp.visibility,'shared')<>'shared'",
                "SELECT lp.id,lp.name,COALESCE(lp.owner,'') FROM panel p JOIN library_panel lp ON lp.id=p.library_panel_id \
                 WHERE p.dashboard_id=?1 AND COALESCE(lp.visibility,'shared')<>'shared' ORDER BY p.id LIMIT 1",
                dash_id,
                "la définition de bibliothèque",
            )
        })
    }

    /// Un PANNEAU peut exécuter une définition de bibliothèque : non commune, elle retient.
    pub(crate) fn d_un_panneau(conn: &Connection, panel_id: i64) -> Option<Self> {
        Self::premier(
            conn,
            "SELECT COUNT(*) FROM panel p JOIN library_panel lp ON lp.id=p.library_panel_id \
             WHERE p.id=?1 AND COALESCE(lp.visibility,'shared')<>'shared'",
            "SELECT lp.id,lp.name,COALESCE(lp.owner,'') FROM panel p JOIN library_panel lp ON lp.id=p.library_panel_id \
             WHERE p.id=?1 AND COALESCE(lp.visibility,'shared')<>'shared'",
            panel_id,
            "la définition de bibliothèque",
        )
    }
}

/// Le GESTE de partage : `visibility` du corps vaut `shared` ALORS QUE l'objet ne l'est pas encore.
/// Un renvoi idempotent (`shared` sur un objet déjà commun — la fiche d'édition d'un panneau renvoie
/// tous ses champs) n'est pas un geste et n'est pas jugé : rendre un élément privé APRÈS le partage
/// reste permis, c'est une réduction de visibilité, et `P11.20-n` garantit qu'il n'est servi qu'à
/// qui a l'autorité dessus.
pub(crate) fn est_un_geste_de_partage(corps: &serde_json::Value, visibilite_courante: &str) -> bool {
    corps.get("visibility").and_then(|v| v.as_str()) == Some("shared") && visibilite_courante != "shared"
}

/// La réponse du refus : 409 (l'état de l'objet contredit le geste) et la phrase en clair, que la
/// console affiche telle quelle dans son message d'échec.
pub(crate) fn refus_de_partage(element: &ElementMoinsVisible, contenant: &str) -> Response {
    (
        StatusCode::CONFLICT,
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        element.phrase_de_refus(contenant),
    )
        .into_response()
}

//! Dashboards & panneaux (P3) : contrôle d'accès (`dash_editable`/`panel_access`), CRUD dashboards/
//! panneaux/vues, et le service SWR des panneaux (clés de plage `cache_range_key`/`query_fingerprint`,
//! exclusions opérateur/self `ExclClauses`/`EXCL_CLAUSES`/`apply_excl_placeholders`,
//! rafraîchissement `enqueue_panel_refresh`/`serve_swr`, handler `panel_data`).
//! Extrait de main.rs (refactor split #25 — byte-identique).
//!
//! `P10.5-i` — LA COMPILATION D'UN PANNEAU ET LA TABLE `panel_cache` NE VIVENT PLUS ICI : elles sont
//! dans le coffre `handlers::panneau_avoue`, seul point qui sait produire un `PanneauCompile` et seul
//! point qui l'exécute — donc seul point qui estampe l'aveu de provenance et l'horizon. Ce module
//! n'écrit plus une ligne de SQL nommant `panel_cache` (garde de build `cache_de_panneau`).
use crate::*;
use rusqlite::OptionalExtension;
use crate::handlers::transaction_validee::{ouvrir_le_garde_du_geste, rendre_apres_validation_du_garde};

// ---------- dashboards (P3) ----------
// Le compte peut-il modifier ce dashboard (et ses panneaux) ?
// `P11.20-n` — LA RÈGLE EST EMPRUNTÉE, PLUS RÉÉCRITE : `panneau_resolu::lisible_par` (admin, déclaré
// `shared`, ou propriétaire NOMMÉ). Elle ne dit plus « ownership hérité (legacy/vide) » : une colonne
// vide n'octroie rien. Le dashboard SEMÉ reste éditable parce qu'il est `shared`, pas parce qu'il est
// sans propriétaire.
//
// `P10.20-l` (vague AG) — TROIS ISSUES, ET LA LECTURE RATÉE N'EST PAS UN REFUS DE DROIT. La forme d'avant
// (`Err(_) => false`) rendait 403 sur un propriétaire illisible — un refus de droit inventé, pour un tableau que le
// compte a peut-être le droit de modifier — et 403 aussi sur une ligne absente. Chaque appelant tranche désormais les
// quatre cas : droit établi, refus établi (la réponse d'absence de sa route, ci-dessous), ligne absente (404), lecture refusée (503
// `CAUSE_DROIT_D_EDITION_NON_LU`, phrase fixe déjà servie par `dash_ergonomics` ; la cause du moteur au journal seul,
// avec l'identifiant interne du tableau et l'identifiant de corrélation, jamais un nom de compte).
//
// `P11.25-f` (vague CB) — `Refusee` est rendu EXACTEMENT quand l'appelant ne lit pas le tableau : privé à un autre
// compte, ou semé privé (sans propriétaire, que seul l'administrateur lit) ; un tableau commun est modifiable par tout
// lecteur et l'administrateur ne lit pas la porte (`lisible_par`, panneau_resolu.rs).
// Un refus de droit établi est donc un tableau que l'appelant ne LIT pas, et chaque appelant le sert comme son
// identifiant absent — même statut, même corps — et n'écrit rien : un 403 disait l'existence du tableau privé d'autrui.
pub(crate) enum PorteDuTableau {
    Ouverte,
    Refusee,
    Absent,
    NonLue(Response),
}

pub(crate) fn dash_editable(conn: &Connection, au: &AuthUser, dash_id: i64) -> PorteDuTableau {
    if au.is_admin() {
        return PorteDuTableau::Ouverte;
    }
    match conn
        .query_row(
            "SELECT COALESCE(owner,''),COALESCE(visibility,'shared') FROM dashboard WHERE id=?1",
            params![dash_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()
    {
        Ok(Some((owner, vis))) if panneau_resolu::lisible_par(&owner, &vis, au) => PorteDuTableau::Ouverte,
        Ok(Some(_)) => PorteDuTableau::Refusee,
        Ok(None) => PorteDuTableau::Absent,
        Err(e) => {
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, crate::handlers::dash_ergonomics::CAUSE_DROIT_D_EDITION_NON_LU);
            eprintln!("[dashboards] WARN droit d'édition du tableau de bord #{dash_id} NON lu, rien n'est écrit ({}) : {e}", cid.unwrap_or_default());
            PorteDuTableau::NonLue(refus)
        }
    }
}

// Le compte peut-il VOIR ce panneau, et avec quelle exécution ? -> (query, is_soql, window_s, owns)
//
// `P10.20-l` (vague AJ) — TROIS ISSUES. Les deux lectures du panneau et de son tableau de bord étaient des `.ok()?` :
// une lecture ratée rendait `None`, que `panel_data` servait 403 « panneau inaccessible » — un refus de droit inventé
// pour un panneau peut-être lisible. `Ok(Some(..))` : accès établi ; `Ok(None)` : panneau ou tableau absent, ou refus de
// droit établi (le 403 d'avant) ; `Err` : une lecture n'a pas eu lieu, aucun droit n'est jugé — `panel_data` sert le 503
// nommé `CAUSE_PANNEAU_NON_LU`. `P10.20-l` (vague AK) : la première lecture, `DefinitionExecutee::courante`
// (`panneau_resolu.rs`), est elle aussi en trois issues et propagée ici — une définition illisible n'est plus un 403.
pub(crate) fn panel_access(conn: &Connection, au: &AuthUser, panel_id: i64) -> rusqlite::Result<Option<(String, bool, i64, bool)>> {
    // LIBRARY PANELS (#54) : si le panneau RÉFÉRENCE une définition réutilisable (panel.library_panel_id),
    // la requête EXÉCUTÉE et son is_soql viennent de `library_panel` (résolus à la lecture -> éditer la
    // bibliothèque met à jour partout). Cette résolution vit dans UN SEUL endroit — le coffre
    // `panneau_resolu` (P7.13-a) — et c'est CELLE-LÀ que la porte « SQL brut = admin » de
    // panel_create/panel_update emprunte : la porte ne peut donc pas juger autre chose que ce qui
    // s'exécute ici. Référence NULL (tout l'existant) -> retombe sur p.query/p.is_soql -> RÉSULTAT
    // byte-identique au mode 0. La fenêtre/visibilité restent au panneau.
    let Some(def) = DefinitionExecutee::courante(conn, panel_id)? else {
        return Ok(None);
    };
    let (query, issoql) = (def.query().to_string(), def.is_soql());
    let Some((did, window, pvis)): Option<(i64, i64, String)> = conn
        .query_row(
            "SELECT dashboard_id,window_s,COALESCE(visibility,'shared') FROM panel WHERE id=?1",
            params![panel_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
    else {
        return Ok(None);
    };
    let Some((downer, dvis)): Option<(String, String)> = conn
        .query_row(
            "SELECT COALESCE(owner,''),COALESCE(visibility,'shared') FROM dashboard WHERE id=?1",
            params![did],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
    else {
        return Ok(None);
    };
    // `P11.20-n` — MÊME phrase que `dash_editable`/`dash_get`, empruntée au coffre.
    let accessible = panneau_resolu::lisible_par(&downer, &dvis, au);
    if !accessible {
        return Ok(None);
    }
    // P7.13-a : la portée de lecture (et donc « ce panneau privé m'est-il servi ? ») vient du coffre —
    // la MÊME décision que `dash_get` et que la capture de snapshot.
    let portee = PorteeLecture::du_dashboard(au, &downer);
    if !portee.voit(&pvis) {
        return Ok(None); // panneau privé d'un autre
    }
    Ok(Some((query, issoql, window, portee.est_proprietaire())))
}

/// `P10.20-l` (vague AJ) — le panneau ou son tableau de bord n'a pas été lu à l'exécution (`panel_data`) : aucun droit
/// n'est jugé, rien n'est exécuté ni servi. Vague AK : servie aussi quand la définition exécutée
/// (`DefinitionExecutee::courante`) ou le TTL du cache du panneau n'est pas lu (même texte, aucune cause neuve).
/// Ne nomme ni `BEGIN` ni `COMMIT` : c'est la lecture qui manque. La console la peint en lecture refusée avec sa cause
/// (`refusDUneLectureServie`, web/core.js ; carte du panneau, web/dashboards.js).
pub(crate) const CAUSE_PANNEAU_NON_LU: &str = "PANNEAU NON LU : la base n'a pas rendu ce panneau ou son tableau de bord \
     (fenêtre, visibilité, propriétaire) — ce n'est PAS « panneau inaccessible », c'est une lecture qui n'a pas eu lieu, \
     et le droit de le voir n'est pas jugé. RIEN n'est exécuté ni servi. Réessayez ; si le refus persiste, la table des \
     panneaux est illisible.";

/// `P10.20-l` (vague AJ) — le tableau de bord demandé n'a pas été lu (`dash_get`) : ni son droit ni ses panneaux ne
/// sont jugés, rien n'est servi. La console la peint en lecture refusée avec sa cause (`noeudDuRefusDUneLecture`,
/// web/core.js ; `loadPanelsInto`, web/dashboards.js).
pub(crate) const CAUSE_TABLEAU_DE_BORD_NON_LU: &str = "TABLEAU DE BORD NON LU : la base n'a pas rendu ce tableau de bord \
     (nom, propriétaire, visibilité) — ce n'est PAS « dashboard introuvable », c'est une lecture qui n'a pas eu lieu, et \
     le droit de le voir n'est pas jugé. RIEN n'est servi. Réessayez ; si le refus persiste, la table des tableaux de \
     bord est illisible.";

/// `P11.25-f` — LA BORNE D'UNE PAGE DE `GET /api/dashboards`. Ce qu'elle borne n'est pas la lecture de la liste (une
/// ligne de tableau de bord est petite) : c'est ce que la console en fait, une tuile par tableau servi, et chaque tuile
/// charge ses panneaux. Cent tuiles dépassent déjà de loin ce qu'un écran montre ; au-delà, la suite se demande par
/// `offset`. Une limite hors de `1..=LIMITE_DE_PAGE_DES_TABLEAUX_DE_BORD` est REFUSÉE (400 nommé), jamais ramenée en
/// silence à la borne. Sans `limit`, la liste entière est servie, comme avant (la console d'avant ne pagine pas) ; le
/// `total` dit combien de tableaux le filtre retient, quelle que soit la page.
pub(crate) const LIMITE_DE_PAGE_DES_TABLEAUX_DE_BORD: i64 = 100;

/// `P11.25-f` — `?view=` vaut l'identifiant entier d'une vue ou `none` ; autre chose était lu comme « aucun filtre » et
/// servait la liste entière sous le nom d'un filtre.
pub(crate) const CAUSE_FILTRE_DE_VUE_INVALIDE: &str =
    "FILTRE DE VUE INVALIDE : `view` vaut l'identifiant entier d'une vue ou `none` — rien n'est servi.";
/// `P11.25-f` — `?offset=` n'est pas un entier positif ou nul.
pub(crate) const CAUSE_DECALAGE_INVALIDE: &str =
    "DÉCALAGE INVALIDE : `offset` vaut un entier positif ou nul — rien n'est servi.";

/// `P11.25-f` — la phrase d'une limite hors borne : la borne y est écrite, et la page plus grande n'est pas tronquée.
pub(crate) fn cause_limite_hors_borne() -> String {
    format!(
        "LIMITE HORS BORNE : `limit` vaut un entier de 1 à {LIMITE_DE_PAGE_DES_TABLEAUX_DE_BORD} — une page plus grande \
         n'est pas servie tronquée, elle est refusée ; demandez la suite par `offset`."
    )
}

/// `P11.25-f` — une limite de page admise : de 1 à la borne, bornes comprises.
fn limite_admise(n: i64) -> bool {
    (1..=LIMITE_DE_PAGE_DES_TABLEAUX_DE_BORD).contains(&n)
}

/// `P11.25-f` — ce que `dash_list` sert : un corps et son statut. Le corps reste le champ `.0` (les témoins de la forme
/// d'avant lisent `dash_list(…).await.0`), le statut dit 200 ou le 400 d'un paramètre refusé.
pub(crate) struct CorpsDeListe(pub(crate) Value, pub(crate) StatusCode);

impl CorpsDeListe {
    /// Un paramètre refusé : le statut s'écrit AVANT le corps, comme dans `(StatusCode, Json(…))`, pour que le refus se
    /// lise comme un refus à son site (et non comme un 200 qui ne porterait que `error`).
    fn refusee(statut: StatusCode, corps: Value) -> Self {
        CorpsDeListe(corps, statut)
    }
}

impl IntoResponse for CorpsDeListe {
    fn into_response(self) -> Response {
        (self.1, Json(self.0)).into_response()
    }
}

/// `P11.25-f` — le filtre de vue de `dash_list`, lu une fois : `Vue(id)` rend les tableaux rattachés à la vue
/// (`view_dashboard`) ou déclarés dans toutes les vues (`all_views = 1`) ; `Aucune` rend ceux qui n'ont aucun
/// rattachement et ne sont pas dans toutes les vues ; `Tous`, sans paramètre, ne filtre pas.
enum FiltreDeVue {
    Tous,
    Vue(i64),
    Aucune,
}

/// La clause commune de la page et de son total : visibilité (`?1` autorité admin, `?2` nom), puis filtre de vue (`?3`
/// mode, `?4` vue).
///
/// `P11.25-f` — UNE VUE QUE L'APPELANT NE VOIT PAS EST UNE VUE INCONNUE. Les deux filtres ne lisent que les
/// rattachements aux vues du périmètre de `views_list` (et de `view_ids` ci-dessous : administrateur, vue commune, ou
/// vue de l'appelant). `?view=<id>` d'une vue privée d'autrui rend donc ce que rend un identifiant qu'aucune vue ne
/// porte — 200, les seuls tableaux de toutes les vues — et rien de son contenu ; un 404 l'aurait distinguée d'une vue
/// absente, qui rend 200 depuis toujours. `?view=none` rend de même un tableau dont les seuls rattachements sont à des
/// vues que l'appelant ne voit pas (ses `view_ids` sont vides).
const FILTRE_DES_TABLEAUX_DE_BORD: &str = "(?1='admin' OR COALESCE(d.visibility,'shared')='shared' OR (?2<>'' AND d.owner=?2))
           AND (?3='tous'
                OR (?3='vue' AND (d.all_views=1 OR EXISTS(SELECT 1 FROM view_dashboard vd JOIN view vv ON vv.id=vd.view_id
                       WHERE vd.view_id=?4 AND vd.dashboard_id=d.id AND (?1='admin' OR vv.visibility='shared' OR vv.owner=?2))))
                OR (?3='aucune' AND d.all_views=0 AND NOT EXISTS(SELECT 1 FROM view_dashboard vd JOIN view vn ON vn.id=vd.view_id
                       WHERE vd.dashboard_id=d.id AND (?1='admin' OR vn.visibility='shared' OR vn.owner=?2))))";

pub(crate) async fn dash_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Query(q): Query<HashMap<String, String>>) -> CorpsDeListe {
    let (me, role) = (au.name.clone(), au.role.clone());
    let refus = |cause: String| CorpsDeListe::refusee(StatusCode::BAD_REQUEST, json!({ "error": cause }));
    // `P11.25-f` — les trois paramètres sont jugés AVANT toute lecture ; un paramètre refusé ne sert aucune liste.
    let filtre = match q.get("view").map(|s| s.as_str()) {
        None => FiltreDeVue::Tous,
        Some("none") => FiltreDeVue::Aucune,
        Some(v) => match v.parse::<i64>() {
            Ok(n) => FiltreDeVue::Vue(n),
            Err(_) => return refus(CAUSE_FILTRE_DE_VUE_INVALIDE.to_string()),
        },
    };
    let limite: Option<i64> = match q.get("limit") {
        None => None,
        Some(l) => match l.parse::<i64>() {
            Ok(n) if limite_admise(n) => Some(n),
            _ => return refus(cause_limite_hors_borne()),
        },
    };
    let decalage: i64 = match q.get("offset") {
        None => 0,
        Some(o) => match o.parse::<i64>() {
            Ok(n) if n >= 0 => n,
            _ => return refus(CAUSE_DECALAGE_INVALIDE.to_string()),
        },
    };
    let (mode, vue): (&str, Option<i64>) = match filtre {
        FiltreDeVue::Tous => ("tous", None),
        FiltreDeVue::Vue(n) => ("vue", Some(n)),
        FiltreDeVue::Aucune => ("aucune", None),
    };
    // `P11.25-f` — LE TOTAL ET LA PAGE SONT LUS PAR UNE SEULE INSTRUCTION, donc sur la même image de la base : le compte
    // du filtre (`t`, une ligne) joint à gauche à la page (`p`). Une page VIDE rend encore une ligne, colonnes de page
    // nulles, qui porte le total sans porter de tableau.
    let sql = format!(
        "SELECT p.id,p.name,p.owner,p.visibility,p.view_id,p.panels,p.cols,p.height,p.collapsed,p.pos,p.all_views,p.view_ids,t.total
         FROM (SELECT COUNT(*) AS total FROM dashboard d WHERE {FILTRE_DES_TABLEAUX_DE_BORD}) t
         LEFT JOIN (
             SELECT d.id AS id,d.name AS name,COALESCE(d.owner,'') AS owner,COALESCE(d.visibility,'shared') AS visibility,
                    (SELECT vp.id FROM view vp WHERE vp.id=d.view_id AND (?1='admin' OR vp.visibility='shared' OR vp.owner=?2)) AS view_id,
                    (SELECT COUNT(*) FROM panel pn WHERE pn.dashboard_id=d.id) AS panels,
                    COALESCE(d.cols,2) AS cols,COALESCE(d.height,0) AS height,COALESCE(d.collapsed,0) AS collapsed,
                    COALESCE(d.position,d.id) AS pos,d.all_views AS all_views,
                    (SELECT json_group_array(r.view_id) FROM (SELECT vd.view_id AS view_id FROM view_dashboard vd JOIN view v ON v.id=vd.view_id
                       WHERE vd.dashboard_id=d.id AND (?1='admin' OR v.visibility='shared' OR v.owner=?2) ORDER BY vd.view_id) r) AS view_ids
             FROM dashboard d
             WHERE {FILTRE_DES_TABLEAUX_DE_BORD}
             ORDER BY COALESCE(d.position,d.id), d.id
             LIMIT ?5 OFFSET ?6
         ) p ON 1
         ORDER BY p.pos, p.id"
    );
    // #64 : AUTORITÉ ADMIN EFFECTIVE (rôle composable base=admin inclus) via `is_admin()` -> `adm` sert de bind
    // SQL `?1` (visibilité). Byte-identique en mode 0 (rôle de base admin -> "admin", sinon "").
    // `role` reste la valeur brute renvoyée pour l'affichage.
    // `P11.20-n` — LE TEST D'OWNERSHIP DE LA CLOSURE NE S'ÉCRIT PLUS ICI : `ident` porte l'identité
    // complète jusqu'au coffre, qui rend le MÊME verdict que la porte. Le bind `?2` est gardé par
    // `?2<>''` parce qu'une identité SANS NOM (relais non lié) s'apparierait sinon à une colonne vide.
    let adm = if au.is_admin() { "admin" } else { "" };
    let ident = au.clone();
    let illisible = || CorpsDeListe(crate::handlers::liste_bornee::corps_de_liste_illisible(json!({ "me": &me, "role": &role }), "dashboards"), StatusCode::OK);
    let defaut = CorpsDeListe(json!({ "error": "lecture NON FAITE : aucune connexion de lecture disponible", "dashboards": [], "me": &me, "role": &role }), StatusCode::OK);
    read_with(req_db_path(&st, &au).as_str(), defaut, |conn| {
        let mut stmt = match conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return illisible(),
        };
        let mut total: i64 = 0;
        let out: Vec<Value> = match stmt.query_map(params![adm, me, mode, vue, limite.unwrap_or(-1), decalage], |r| {
            let compte: i64 = r.get(12)?;
            // La ligne d'une page vide : le total, aucun tableau.
            if r.get::<_, Option<i64>>(0)?.is_none() {
                return Ok((None, compte));
            }
            let owner: String = r.get(2)?;
            let vis: String = r.get(3)?;
            // `P11.20-n` — LE DRAPEAU DIT CE QUE LA PORTE FERA, et rien d'autre. La porte d'écriture
            // est `dash_editable`, dont le corps EST `lisible_par` : le drapeau l'emprunte donc au
            // MÊME endroit. Écrire ici `autorite_de_proprietaire` (le premier jet) rendait
            // `editable:false` sur un dashboard COMMUN que le serveur laisse pourtant modifier —
            // un drapeau qui ment sur sa propre porte, exactement le défaut d'à côté.
            let owns = panneau_resolu::lisible_par(&owner, &vis, &ident);
            // `P11.25-f` — les vues de rattachement, rendues par SQLite en tableau JSON (`[]` sans rattachement), et
            // seulement celles que l'appelant voit (le périmètre de `views_list`) : l'identifiant d'une vue privée
            // d'autrui n'est pas servi. `view_id` (vue principale) suit le même périmètre : nul quand la vue principale
            // est une vue que l'appelant ne voit pas (ou qu'aucune vue ne porte plus), comme si le tableau n'avait pas
            // de vue principale pour lui ; servi tel quel sinon, comme avant v125.
            let vues: String = r.get(11)?;
            let view_ids: Value = serde_json::from_str(&vues)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(11, rusqlite::types::Type::Text, Box::new(e)))?;
            let toutes: bool = r.get::<_, i64>(10)? != 0;
            Ok((
                Some(json!({
                    "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?,
                    "owner": owner, "visibility": vis,
                    "view_id": r.get::<_, Option<i64>>(4)?, "panels": r.get::<_, i64>(5)?,
                    "cols": r.get::<_, i64>(6)?, "height": r.get::<_, i64>(7)?,
                    "collapsed": r.get::<_, i64>(8)? != 0, "position": r.get::<_, i64>(9)?,
                    "editable": owns,
                    "all_views": toutes, "view_ids": view_ids
                })),
                compte,
            ))
        }) {
            // `P10.7-z` — une ligne en erreur (dont « no such table » rendu au premier pas) rend la liste NON ÉTABLIE.
            Ok(r) => match r.collect::<Result<Vec<(Option<Value>, i64)>, _>>() {
                Ok(v) => {
                    let mut lignes = Vec::with_capacity(v.len());
                    for (ligne, compte) in v {
                        total = compte;
                        lignes.extend(ligne);
                    }
                    lignes
                }
                Err(_) => return illisible(),
            },
            Err(_) => return illisible(),
        };
        CorpsDeListe(
            json!({ "dashboards": out, "me": &me, "role": &role, "total": total, "limit": limite, "offset": decalage }),
            StatusCode::OK,
        )
    })
}

/// `P10.20-w` (rang quatre) — UNE CRÉATION DONT LA LIGNE N'A PAS ÉTÉ ÉCRITE NE SERT AUCUN IDENTIFIANT.
/// Les six créations de ce rang (tableau de bord, panneau, vue, panneau de bibliothèque, liste de
/// lecture, instantané) avalaient leur `INSERT` puis servaient `last_insert_rowid()` : sur une écriture
/// refusée, c'était l'identifiant de la DERNIÈRE ligne insérée sur la connexion d'écriture — un maillon
/// du registre, un événement, l'objet d'un autre compte —, servi en deux cents, et la console le
/// reposait ensuite sur chaque geste visant « son » objet. Le contrat de ces routes change avec, et
/// c'est assumé : un 503 nommé là où un 200 servait un identifiant emprunté.
pub(crate) const CAUSE_OBJET_NON_CREE: &str =
    "OBJET NON CRÉÉ : la ligne n'a pas pu être écrite, donc cet objet n'existe pas et AUCUN identifiant \
     n'est rendu — celui qui était servi ici était celui de la dernière ligne insérée sur la connexion, \
     une TOUTE AUTRE ligne que la console aurait ensuite visée. Rien n'a été fait. Réessayez.";

/// Le refus commun du rang quatre. Seule la PHRASE voyage : chaque site garde son `INSERT` écrit en
/// place et lit l'identifiant au pied de son insertion, sous le bras `Ok(1)` (le fabricant partagé
/// « écriture comptée puis identifiant », qui ferait voyager le SQL comme une donnée, reste refusé).
///
/// `P10.29-l` (vague AK) — DEUX REFUS, PAR LE TYPE. La forme d'avant prenait `cause: impl Display` et ses six bras
/// `Err(e)` lui passaient un `rusqlite::Error` : le texte du moteur partait au client dans le 503. Celui-ci ne prend plus
/// que le COMPTE de lignes écrites (un fait sans texte du moteur, corps d'avant à l'octet) ; une écriture refusée par la
/// base passe par [`refus_d_un_objet_non_cree_par_le_moteur`].
pub(crate) fn refus_d_un_objet_non_cree(objet: &str, n: usize) -> Response {
    err_json(StatusCode::SERVICE_UNAVAILABLE, format!("{CAUSE_OBJET_NON_CREE} Objet : {objet} ({}).", lignes_ecrites_au_lieu_d_une(n)))
}

/// `P10.29-l` (vague AK) — l'écriture d'une création refusée par la base : la phrase fixe et l'objet, sous l'identifiant de
/// corrélation servi ; la cause du moteur va au journal avec cet identifiant, jamais au client (ni requête ni nom de
/// personne au journal : l'objet est un nom de catégorie choisi par le site).
pub(crate) fn refus_d_un_objet_non_cree_par_le_moteur(objet: &str, e: &rusqlite::Error) -> Response {
    let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, format!("{CAUSE_OBJET_NON_CREE} Objet : {objet}."));
    eprintln!("[dashboards] WARN {objet} NON créé, aucun identifiant n'est rendu ({}) : {e}", cid.unwrap_or_default());
    refus
}

/// La cause d'une écriture qui a « réussi » sans poser exactement UNE ligne (un déclencheur qui
/// ignore l'insertion) : l'identifiant de la connexion n'est alors PAS celui de l'objet.
pub(crate) fn lignes_ecrites_au_lieu_d_une(n: usize) -> String {
    format!("{n} ligne(s) écrite(s) au lieu d'une")
}

/// `P11.25-f` — `all_views` vaut `true` ou `false` ; toute autre valeur (nombre, chaîne, `null`) est refusée par
/// `dash_create` et `dash_update` avant toute écriture.
pub(crate) const CAUSE_TOUTES_LES_VUES_INVALIDE: &str =
    "« TOUTES LES VUES » INVALIDE : `all_views` vaut true ou false — rien n'est écrit.";

/// `P11.25-f` — `all_views` lu dans un corps : absent `Ok(None)`, booléen `Ok(Some(_))`, toute autre valeur le 400 nommé.
fn lire_toutes_les_vues(b: &Value) -> Result<Option<bool>, Response> {
    match b.get("all_views") {
        None => Ok(None),
        Some(Value::Bool(x)) => Ok(Some(*x)),
        Some(_) => Err(err_json(StatusCode::BAD_REQUEST, CAUSE_TOUTES_LES_VUES_INVALIDE)),
    }
}

/// `P11.25-f` — le `view_id` d'une création ou d'une modification de tableau de bord ne désigne aucune vue que
/// l'appelant voit (absente, ou privée d'un autre compte : même réponse, sans quoi elle dirait l'existence de la vue
/// privée). Rien du corps n'est écrit.
pub(crate) const CAUSE_VUE_DU_TABLEAU_INCONNUE: &str = "VUE INCONNUE : aucune vue que vous voyez ne porte l'identifiant \
     `view_id` demandé — rien n'est écrit, rien du corps n'est appliqué.";
/// `P11.25-f` — la vue nommée par `view_id` n'a pas été lue : elle n'est pas jugée, rien du corps n'est écrit. Ne nomme
/// pas une transaction annulée : c'est une lecture qui manque.
pub(crate) const CAUSE_VUE_DU_TABLEAU_NON_LUE: &str = "VUE NON LUE : la base n'a pas rendu la vue `view_id` demandée — ce \
     n'est PAS une absence, c'est une lecture qui n'a pas eu lieu, et la vue n'est pas jugée. RIEN n'est écrit, rien du \
     corps n'est appliqué. Réessayez ; si le refus persiste, la table des vues est illisible.";

/// `P11.25-f` — « L'APPELANT VOIT CETTE VUE », écrit UNE fois pour les gestes qui jugent une vue par son identifiant : le
/// périmètre de `views_list` — administrateur (`?2` vaut `'admin'`, sinon `''`), vue commune (semée sans propriétaire
/// comprise), ou vue de l'appelant (`?3`, son nom). Une vue privée sans propriétaire rend NULL pour un non-administrateur :
/// « ne la voit pas » (`EXISTS … AND` le lit faux ; `COALESCE(…, 0)` là où la valeur est lue). Ses lecteurs : la vue où
/// un tableau est rangé (`juger_la_vue_du_tableau`), les rattachements (`porte_des_rattachements`), la modification et la
/// suppression d'une vue (`view_update`, `view_delete`, dans la MÊME lecture que le propriétaire et la visibilité).
const LA_VUE_EST_VUE_PAR_L_APPELANT: &str = "(?2='admin' OR visibility='shared' OR owner=?3)";

/// `P11.25-f` — LA VUE OÙ UN TABLEAU EST RANGÉ PAR `view_id` EST UNE VUE QUE L'APPELANT VOIT : le périmètre de
/// `views_list` (administrateur, vue commune, ou vue de l'appelant). Sans ce jugement, `dash_create` et `dash_update`
/// rangeaient un tableau dans la vue privée d'un autre compte (le déclencheur v125 l'y rattache), ou sous un identifiant
/// qu'aucune vue ne porte. Absente ou invisible : 404 nommé ; lecture non faite : 503 nommé, la cause du moteur au
/// journal seul.
fn juger_la_vue_du_tableau(conn: &Connection, au: &AuthUser, view_id: i64) -> Result<(), Response> {
    let adm = if au.is_admin() { "admin" } else { "" };
    let sql = format!("SELECT EXISTS(SELECT 1 FROM view WHERE id=?1 AND {LA_VUE_EST_VUE_PAR_L_APPELANT})");
    match conn.query_row(&sql, params![view_id, adm, au.name], |r| r.get::<_, i64>(0)) {
        Ok(0) => Err(err_json(StatusCode::NOT_FOUND, CAUSE_VUE_DU_TABLEAU_INCONNUE)),
        Ok(_) => Ok(()),
        Err(e) => {
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_VUE_DU_TABLEAU_NON_LUE);
            eprintln!("[dashboards] WARN vue #{view_id} NON lue pour y ranger un tableau de bord, rien n'est écrit ({}) : {e}", cid.unwrap_or_default());
            Err(refus)
        }
    }
}

/// `P11.25-f` — `view_id` reste écrit tel quel (vue principale) ; le déclencheur `view_dashboard_suit_l_insertion`
/// (v125) pose le rattachement dans la jointure par la même instruction. `all_views` absent = 0 : un tableau créé
/// n'apparaît dans toutes les vues que si on le demande. Un `view_id` qui ne désigne aucune vue que le créateur voit est
/// refusé (`juger_la_vue_du_tableau`) avant l'insertion : aucune ligne n'est créée.
pub(crate) async fn dash_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Sans titre").to_string();
    let vis = match b.get("visibility").and_then(|v| v.as_str()) {
        Some("shared") => "shared",
        _ => "private",
    };
    let view_id = b.get("view_id").and_then(|v| v.as_i64());
    let toutes_les_vues = match lire_toutes_les_vues(&b) {
        Ok(t) => t.unwrap_or(false),
        Err(refus) => return refus,
    };
    crate::req_conn!(st, au, conn);
    if let Some(vue) = view_id {
        if let Err(refus) = juger_la_vue_du_tableau(&conn, &au, vue) {
            return refus;
        }
    }
    match conn.execute(
        "INSERT INTO dashboard(name,created,owner,visibility,view_id,all_views) VALUES(?1,?2,?3,?4,?5,?6)",
        params![name, now(), au.name, vis, view_id, toutes_les_vues as i64],
    ) {
        Ok(1) => Json(json!({ "id": conn.last_insert_rowid() })).into_response(),
        Ok(n) => refus_d_un_objet_non_cree("tableau de bord", n),
        Err(e) => refus_d_un_objet_non_cree_par_le_moteur("tableau de bord", &e),
    }
}

pub(crate) async fn dash_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    // `P11.25-f` — `all_views` jugé avant toute lecture et toute écriture : une valeur refusée n'applique rien du corps.
    let toutes_les_vues = match lire_toutes_les_vues(&b) {
        Ok(t) => t,
        Err(refus) => return refus,
    };
    crate::req_conn!(st, au, conn);
    // `P10.20-k` (2026-09-16) — L'EXISTENCE ET LA VISIBILITÉ COURANTE SE LISENT D'UN SEUL COUP, ET LES
    // TROIS ISSUES SONT DISTINCTES. Avant : un `is_ok()` sur `SELECT 1` (lecture ratée -> 404
    // « introuvable », cause fausse sur un objet qui existe), puis un `unwrap_or_else(|_| "shared")` sur
    // la visibilité — et CELUI-LÀ ouvrait une porte. `panneau_resolu::est_un_geste_de_partage` exige
    // `visibilite_courante != "shared"` : une lecture ratée déclarait le tableau de bord DÉJÀ partagé,
    // le geste cessait d'être un partage, la porte `P11.20-m` — celle qui REFUSE de publier un
    // contenant portant un élément moins visible — n'était pas interrogée, et l'écriture qui publie
    // suivait. Désormais : ligne absente = 404 (une absence ÉTABLIE) ; lecture NON FAITE = 503 nommé,
    // avant tout jugement de partage et avant toute écriture.
    let visibilite: String = match conn
        .query_row("SELECT COALESCE(visibility,'shared') FROM dashboard WHERE id=?1", params![id], |r| r.get::<_, String>(0))
        .optional()
    {
        Ok(Some(v)) => v,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return panneau_resolu::refus_de_visibilite_non_lue(),
    };
    // `P11.25-f` (vague CB) — un tableau privé d'autrui (`Refusee`) reçoit le 404 nu d'un identifiant absent, rien
    // n'est écrit ; le 403 d'avant disait qu'il existe.
    match dash_editable(&conn, &au, id) {
        PorteDuTableau::Ouverte => {}
        PorteDuTableau::Refusee | PorteDuTableau::Absent => return StatusCode::NOT_FOUND.into_response(),
        PorteDuTableau::NonLue(refus) => return refus,
    }
    // `P11.20-m` — LE GESTE DE PARTAGE EST JUGÉ AVANT TOUTE ÉCRITURE : refusé avec la raison tant
    // qu'un élément du tableau de bord est moins visible ; rien du corps n'est appliqué sur un refus.
    if panneau_resolu::est_un_geste_de_partage(&b, &visibilite) {
        // `P10.20-b` — les éléments qui retiendraient le partage NON LUS ne valent pas « rien ne
        // retient » : 503 nommé, avant toute écriture.
        match panneau_resolu::ElementMoinsVisible::d_un_tableau_de_bord(&conn, id) {
            Ok(None) => {}
            Ok(Some(element)) => return panneau_resolu::refus_de_partage(&element, "le tableau de bord"),
            Err(_) => return panneau_resolu::refus_d_elements_retenant_non_lus(),
        }
    }
    // `P10.20-l` (vague AG) — LES ÉCRITURES SOUS UN GARDE, UNE LIGNE EXIGÉE CHACUNE (le tableau vient d'être lu). La forme
    // d'avant (huit `let _` puis 204) avalait toute écriture refusée : un champ envoyé et refusé — la visibilité comprise —
    // laissait la réponse dire « modifié ». Un refus ou un effet nul annule TOUT (Drop -> ROLLBACK), 503 nommé.
    let geste = format!("modification du tableau de bord #{id}");
    let tx = match ouvrir_le_garde_du_geste(&conn, "dashboards", &geste, CAUSE_TABLEAU_DE_BORD_INCHANGE_TRANSACTION_NON_OUVERTE) {
        Ok(t) => t,
        Err(refus) => return refus,
    };
    // `P11.25-f` — la vue où le tableau est rangé est jugée avant toute écriture : une vue que l'appelant ne voit pas
    // (ou absente) n'applique rien du corps (`juger_la_vue_du_tableau`).
    if let Some(vue) = b.get("view_id").and_then(|v| v.as_i64()) {
        if let Err(refus) = juger_la_vue_du_tableau(&conn, &au, vue) {
            drop(tx); // Drop -> ROLLBACK : rien n'a été écrit.
            return refus;
        }
    }
    let ecrit: Result<(), String> = (|| {
        if let Some(name) = b.get("name").and_then(|v| v.as_str()) {
            une_seule_ligne(conn.execute("UPDATE dashboard SET name=?1 WHERE id=?2", params![name, id]), "nom")?;
        }
        if let Some(vis) = b.get("visibility").and_then(|v| v.as_str()) {
            let vis = if vis == "shared" { "shared" } else { "private" };
            une_seule_ligne(conn.execute("UPDATE dashboard SET visibility=?1 WHERE id=?2", params![vis, id]), "visibilité")?;
        }
        // `P11.25-f` — « toutes les vues », jugé booléen à l'entrée.
        if let Some(t) = toutes_les_vues {
            une_seule_ligne(conn.execute("UPDATE dashboard SET all_views=?1 WHERE id=?2", params![t as i64, id]), "toutes les vues")?;
        }
        // `P11.25-f` — écrire `view_id` est un DÉPLACEMENT de la vue principale : le déclencheur
        // `view_dashboard_suit_la_vue_principale` (v125) retire l'ancien rattachement et pose le nouveau dans la même
        // instruction, donc dans cette transaction. Il ne retire que la ligne `explicite = 0` de l'ancienne vue : un
        // rattachement posé (ou confirmé) par `POST /api/views/{id}/dashboards` reste, y compris vers une vue par
        // laquelle la vue principale est passée (A -> B -> A, nulle -> B -> nulle).
        if let Some(vv) = b.get("view_id") {
            if vv.is_null() {
                une_seule_ligne(conn.execute("UPDATE dashboard SET view_id=NULL WHERE id=?1", params![id]), "vue")?;
            } else if let Some(n) = vv.as_i64() {
                une_seule_ligne(conn.execute("UPDATE dashboard SET view_id=?1 WHERE id=?2", params![n, id]), "vue")?;
            }
        }
        // layout dans la vue (grille) : largeur en colonnes, hauteur px, ordre, replié
        if let Some(v) = b.get("cols").and_then(|v| v.as_i64()) {
            une_seule_ligne(conn.execute("UPDATE dashboard SET cols=?1 WHERE id=?2", params![v.clamp(1, 4), id]), "largeur")?;
        }
        if let Some(v) = b.get("height").and_then(|v| v.as_i64()) {
            une_seule_ligne(conn.execute("UPDATE dashboard SET height=?1 WHERE id=?2", params![v.max(0), id]), "hauteur")?;
        }
        if let Some(v) = b.get("collapsed").and_then(|v| v.as_bool()) {
            une_seule_ligne(conn.execute("UPDATE dashboard SET collapsed=?1 WHERE id=?2", params![v as i64, id]), "repli")?;
        }
        if let Some(v) = b.get("position").and_then(|v| v.as_i64()) {
            une_seule_ligne(conn.execute("UPDATE dashboard SET position=?1 WHERE id=?2", params![v, id]), "position")?;
        }
        Ok(())
    })();
    if let Err(cause) = ecrit {
        drop(tx); // Drop -> ROLLBACK : chaque champ est celui d'avant.
        return refuser_le_retrait_non_pris(&geste, &cause, CAUSE_TABLEAU_DE_BORD_INCHANGE);
    }
    rendre_apres_validation_du_garde(tx, &conn, "dashboards", &geste, CAUSE_TABLEAU_DE_BORD_INCHANGE, || StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn dash_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    // `P10.20-l` (vague AJ) — TROIS ISSUES : lu, la porte suit ; absent, le 404 d'avant à l'octet ; lecture ratée, 503
    // nommé `CAUSE_TABLEAU_DE_BORD_NON_LU` — aucun 403 décidé, rien servi, la cause du moteur au journal seul.
    // `P11.25-f` — `view_id` (vue principale) suit le périmètre de `dash_list` et de `views_list` (administrateur, vue
    // commune, ou vue de l'appelant) : nul quand la vue principale est une vue que l'appelant ne voit pas, ou qu'aucune
    // vue ne porte plus — l'identifiant d'une vue privée d'autrui n'est pas servi à qui lit le tableau. Lu par la même
    // instruction que le tableau : aucune lecture de plus qui puisse manquer.
    let adm = if au.is_admin() { "admin" } else { "" };
    let meta: Option<(String, String, String, Option<i64>)> = match conn
        .query_row(
            "SELECT d.name,COALESCE(d.owner,''),COALESCE(d.visibility,'shared'),
                    (SELECT vp.id FROM view vp WHERE vp.id=d.view_id AND (?2='admin' OR vp.visibility='shared' OR vp.owner=?3))
             FROM dashboard d WHERE d.id=?1",
            params![id, adm, au.name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
    {
        Ok(m) => m,
        Err(e) => {
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TABLEAU_DE_BORD_NON_LU);
            eprintln!("[dashboards] WARN tableau de bord #{id} NON lu pour la lecture, rien n'est servi ({}) : {e}", cid.unwrap_or_default());
            return refus;
        }
    };
    // `P11.25-f` (vague CB) — un tableau que l'appelant ne lit pas (privé d'un autre compte) reçoit la réponse d'un
    // identifiant absent, à l'octet : le 403 « dashboard privé » d'avant disait qu'il existe. Décidé sur la lecture
    // ci-dessus (existence, propriétaire, visibilité d'un seul énoncé).
    let Some((name, owner, vis, view_id)) = meta else {
        return (StatusCode::NOT_FOUND, "dashboard introuvable").into_response();
    };
    if !panneau_resolu::lisible_par(&owner, &vis, &au) {
        return (StatusCode::NOT_FOUND, "dashboard introuvable").into_response();
    }
    // P7.13-a : portée de lecture DÉRIVÉE au coffre (même décision que `panel_access` et que la capture).
    let portee = PorteeLecture::du_dashboard(&au, &owner);
    // `P11.20-n` — DEUX FAITS DISTINCTS, longtemps confondus en un seul booléen parce que la clause
    // d'octroi les rendait égaux sur les objets sans propriétaire :
    //   · `owns` = la PORTÉE DE LECTURE (voir un panneau privé, voir le TEXTE d'une requête privée).
    //     Strictement le propriétaire ou l'admin — c'est une décision de CONFIDENTIALITÉ.
    //   · `editable` = ce que la PORTE D'ÉCRITURE laissera passer (`dash_editable`), qui inclut le
    //     bien commun DÉCLARÉ. C'est une décision d'ERGONOMIE, et elle doit dire la vérité sur la
    //     porte : la vue masquerait sinon un geste que le serveur accepte.
    let owns = portee.est_proprietaire();
    // `P10.20-l` (vague AG) — LE DRAPEAU SE DÉCIDE SUR LA LECTURE QUI A DÉJÀ DÉCIDÉ L'ACCÈS (propriétaire et visibilité,
    // ci-dessus), par la règle de la porte (`dash_editable` : admin, ou `lisible_par`). La forme d'avant relisait la
    // ligne par `dash_editable`, dont l'échec valait `false` : une seconde lecture refusée servait `editable:false` sur un
    // tableau que la porte laisse modifier — un drapeau qui ment sur sa porte, et une lecture de plus qui peut manquer.
    let editable = au.is_admin() || panneau_resolu::lisible_par(&owner, &vis, &au);
    // LIBRARY PANELS (#54) : titre/requête/is_soql/viz/drill AFFICHÉS sont résolus depuis `library_panel`
    // quand le panneau la référence. La résolution est EMPRUNTÉE au coffre `panneau_resolu` (P7.13-a) —
    // elle n'est plus réécrite ici, et `build.rs` refuse de compiler toute réécriture ailleurs.
    // library_panel_id NULL (tout l'existant) -> retombe sur les colonnes du panneau -> JSON
    // byte-identique au mode 0 (+ `library_panel_id`:null).
    // `P10.7-f` (rang 4) — LE TABLEAU DE BORD SERVI EST ENTIER OU AVOUÉ. Avant : DEUX `unwrap()` (table
    // retirée -> panique, pas aveu) puis `.flatten()` entre la lecture et le filtre de portée — un panneau
    // dont le mappeur échoue (cache de schéma du pool périmé rendant « no such table » au PREMIER pas,
    // colonne de migration que la connexion qui sert ne voit pas encore, `viz` corrompue) DISPARAISSAIT
    // de la page, et la page avait l'air complète : aucune clé ne changeait, aucun compte ne manquait. Un
    // panneau absent d'un tableau de bord se lit « il n'a jamais été posé » — et c'est sur cette page que
    // l'astreinte vérifie qu'un indicateur est bien surveillé. Soldé en bloc AVANT le filtre de portée :
    // l'échec de ligne ne peut donc pas se cacher derrière « ce panneau était privé ». L'aveu est celui du
    // dépôt (`corps_de_liste_illisible` : `panels` présente et VIDE, `error` nomme la cause) ; les
    // métadonnées du dashboard sont conservées parce qu'elles viennent d'une AUTRE lecture, déjà faite.
    let lues: rusqlite::Result<Vec<_>> = conn
        .prepare(&format!(
            "SELECT p.id,{t},{q},{s},{v},p.position,p.window_s,COALESCE(p.visibility,'shared'),COALESCE(p.query_private,0),COALESCE(p.cols,1),COALESCE(p.height,0),{d},p.library_panel_id \
             FROM {j} WHERE p.dashboard_id=?1 ORDER BY p.position,p.id",
            t = panneau_resolu::COL_TITRE, q = panneau_resolu::COL_QUERY, s = panneau_resolu::COL_IS_SOQL,
            v = panneau_resolu::COL_VIZ, d = panneau_resolu::COL_DRILL, j = panneau_resolu::JOINTURE,
        ))
        .and_then(|mut stmt| {
            stmt.query_map(params![id], |r| {
                Ok((
                    r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)? != 0,
                    r.get::<_, String>(4)?, r.get::<_, i64>(5)?, r.get::<_, i64>(6)?, r.get::<_, String>(7)?, r.get::<_, i64>(8)? != 0,
                    r.get::<_, i64>(9)?, r.get::<_, i64>(10)?, r.get::<_, String>(11)?, r.get::<_, Option<i64>>(12)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    let meta = json!({
        "id": id, "name": name, "owner": owner, "visibility": vis, "view_id": view_id, "editable": editable,
    });
    let Ok(lignes) = lues else {
        return Json(crate::handlers::liste_bornee::corps_de_liste_illisible(meta, "panels")).into_response();
    };
    let panels: Vec<Value> = lignes
        .into_iter()
        .filter(|(_, _, _, _, _, _, _, pvis, _, _, _, _, _)| portee.voit(pvis)) // panneau privé -> proprio seulement
        .map(|(pid, title, query, is_soql, viz, position, window_s, pvis, qpriv, cols, height, drill, lib_id)| {
            let hide = qpriv && !owns; // requête privée masquée (et son drill)
            let qtext = if hide { String::new() } else { query };
            let dtext = if hide { String::new() } else { drill };
            json!({
                "id": pid, "title": title, "query": qtext, "is_soql": is_soql, "viz": viz,
                "position": position, "window_s": window_s, "visibility": pvis, "query_private": qpriv,
                "cols": cols, "height": height, "drill": dtext, "library_panel_id": lib_id
            })
        })
        .collect();
    let mut corps = meta;
    corps["panels"] = json!(panels);
    Json(corps).into_response()
}

/// `P10.20-l` (vague AG) — une écriture de la modification d'un tableau de bord refusée ou sans effet : la transaction est
/// annulée (`OUVERTURE_DE_L_ECRITURE_NON_PRISE`, web/core.js).
pub(crate) const CAUSE_TABLEAU_DE_BORD_INCHANGE: &str = "TABLEAU DE BORD INCHANGÉ : la base n'a pas pris l'écriture de la \
     modification ou n'en a écrit aucune ligne, et la transaction est annulée — le nom, la visibilité, la vue et la \
     disposition du tableau de bord sont ceux d'avant (un tableau privé le reste). Réessayez ; si le refus persiste, la \
     base est en lecture seule, pleine ou verrouillée.";
/// `P10.20-l` (vague AG) — le `BEGIN` de cette modification refusé (`OUVERTURE_DE_LA_TRANSACTION_NON_PRISE`).
pub(crate) const CAUSE_TABLEAU_DE_BORD_INCHANGE_TRANSACTION_NON_OUVERTE: &str = "TABLEAU DE BORD INCHANGÉ : la base n'a \
     pas pris la transaction de la modification (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur \
     l'écrivain) — RIEN n'est écrit. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";
/// `P10.20-l` (vague AG) — une écriture de la modification d'un panneau refusée ou sans effet : la transaction est
/// annulée, le cache n'est pas purgé (`OUVERTURE_DE_L_ECRITURE_NON_PRISE`, web/core.js).
pub(crate) const CAUSE_PANNEAU_INCHANGE: &str = "PANNEAU INCHANGÉ : la base n'a pas pris l'écriture de la modification \
     ou n'en a écrit aucune ligne, et la transaction est annulée — la requête, sa visualisation, sa fenêtre, sa visibilité, \
     sa disposition, son rattachement à une définition de bibliothèque et son cache sont ceux d'avant. Réessayez ; si le \
     refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.20-l` (vague AG) — le `BEGIN` de cette modification refusé (`OUVERTURE_DE_LA_TRANSACTION_NON_PRISE`).
pub(crate) const CAUSE_PANNEAU_INCHANGE_TRANSACTION_NON_OUVERTE: &str = "PANNEAU INCHANGÉ : la base n'a pas pris la \
     transaction de la modification (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur \
     l'écrivain) — RIEN n'est écrit : le panneau et son cache sont intacts. Réessayez ; s'il est refusé encore, \
     l'écrivain est occupé ou bloqué.";
/// `P10.20-l` (vague AG) — une écriture de la modification d'une vue refusée ou sans effet : la transaction est annulée
/// (`OUVERTURE_DE_L_ECRITURE_NON_PRISE`, web/core.js).
pub(crate) const CAUSE_VUE_INCHANGEE: &str = "VUE INCHANGÉE : la base n'a pas pris l'écriture de la modification ou n'en a \
     écrit aucune ligne, et la transaction est annulée — le nom et la visibilité de la vue sont ceux d'avant (une vue \
     privée le reste). Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.20-l` (vague AG) — le `BEGIN` de cette modification refusé (`OUVERTURE_DE_LA_TRANSACTION_NON_PRISE`).
pub(crate) const CAUSE_VUE_INCHANGEE_TRANSACTION_NON_OUVERTE: &str = "VUE INCHANGÉE : la base n'a pas pris la \
     transaction de la modification (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur \
     l'écrivain) — RIEN n'est écrit. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";

/// `P10.20-l` (vague AF) — le propriétaire du tableau de bord n'a pas été lu : le droit n'est pas jugé, rien n'est
/// supprimé. Ne nomme ni `BEGIN` ni `COMMIT` ni une transaction annulée : c'est la lecture qui manque (refus nommé).
pub(crate) const CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME_NON_LU: &str = "TABLEAU DE BORD NON SUPPRIMÉ : la base n'a pas rendu \
     ce tableau de bord (son propriétaire) — ce n'est PAS une absence, c'est une lecture qui n'a pas eu lieu, et le droit \
     de le supprimer n'est pas jugé. RIEN n'est supprimé : le tableau de bord et ses panneaux sont intacts. Réessayez ; si \
     le refus persiste, la table des tableaux de bord est illisible.";
/// `P10.20-l` (vague AF) — un effacement de la suppression refusé ou sans effet : la transaction est annulée. Ouverture
/// que la console lit sous « rien n'a changé » (`OUVERTURE_DE_L_ECRITURE_NON_PRISE`, web/core.js).
pub(crate) const CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME: &str = "TABLEAU DE BORD NON SUPPRIMÉ : la base n'a pas pris \
     l'effacement du tableau de bord ou de ses panneaux, ou n'a effacé aucun tableau, et la transaction est annulée — le \
     tableau de bord et tous ses panneaux existent toujours. Réessayez ; si le refus persiste, la base est en lecture \
     seule, pleine ou verrouillée.";
/// `P10.20-l` (vague AF) — le `BEGIN` de cette suppression refusé (`OUVERTURE_DE_LA_TRANSACTION_NON_PRISE`).
pub(crate) const CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME_TRANSACTION_NON_OUVERTE: &str = "TABLEAU DE BORD NON SUPPRIMÉ : la \
     base n'a pas pris la transaction de la suppression (BEGIN refusé : verrou tenu, ou transaction d'un autre geste \
     pendante sur l'écrivain) — RIEN n'est écrit : le tableau de bord et ses panneaux sont intacts. Réessayez ; s'il est \
     refusé encore, l'écrivain est occupé ou bloqué.";

/// `P10.20-l` (vague AF) — un effacement qui doit porter sur la ligne LUE juste avant : une seule, ni zéro (un
/// déclencheur qui l'ignore) ni plusieurs. (Vague AG : la même règle pour chaque écriture d'une modification.)
fn une_seule_ligne(issue: rusqlite::Result<usize>, quoi: &str) -> Result<(), String> {
    match issue {
        Ok(1) => Ok(()),
        Ok(n) => Err(format!("{quoi} : {}", lignes_ecrites_au_lieu_d_une(n))),
        Err(e) => Err(format!("{quoi} : {e}")),
    }
}

/// `P10.20-l` (vague AF) — un effacement de suppression refusé, sous le garde du geste déjà annulé par l'appelant : le
/// 503 porte la phrase fixe du geste et l'identifiant de corrélation ; la cause du moteur va au journal seul (jamais
/// dans le corps), avec le geste et l'identifiant interne de l'objet — aucun nom de compte.
/// (Vague AG : il sert aussi les modifications d'un tableau, d'un panneau et d'une vue, et la suppression d'un panneau de
/// bibliothèque — `dash_ergonomics`.)
pub(crate) fn refuser_le_retrait_non_pris(geste: &str, cause: &str, phrase: &'static str) -> Response {
    let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, phrase);
    eprintln!("[dashboards] WARN {geste} NON prise, transaction annulée ({}) : {cause}", cid.unwrap_or_default());
    refus
}

pub(crate) async fn dash_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    // `P10.20-l` (vague AE) — trois issues : lu, le droit est jugé ; absent, le 404 d'avant (sans corps) ; lecture ratée,
    // 503 — ni 403 ni suppression sur un propriétaire non lu. `P10.20-l` (vague AF) — la route rend une `Response` : le
    // 503 porte `CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME_NON_LU` en corps (la console lisait un 503 nu, « refus sans cause »),
    // la cause du moteur au journal seul. 403 et 404 restent sans corps.
    // `P11.25-f` (vague CB) — la visibilité se lit dans la MÊME lecture que le propriétaire : un tableau que l'appelant
    // ne LIT pas (privé d'un autre compte) reçoit le 404 nu d'un identifiant absent et rien n'est supprimé ; le 403
    // d'avant disait qu'il existe. Le 403 reste à qui lit le tableau sans en être propriétaire (tableau commun, semé
    // compris) : il ne dit rien qu'il ne voie déjà.
    let lecture = conn
        .query_row("SELECT COALESCE(owner,''),COALESCE(visibility,'shared') FROM dashboard WHERE id=?1", params![id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .optional();
    match lecture {
        Ok(Some((owner, vis))) => {
            if !panneau_resolu::lisible_par(&owner, &vis, &au) {
                return StatusCode::NOT_FOUND.into_response();
            }
            // `P11.20-n` — SUPPRIMER EST UN GESTE DE PROPRIÉTAIRE, et une colonne vide n'octroie pas
            // la propriété : l'objet SEMÉ (sans propriétaire) redevient admin-seul à la suppression.
            if !panneau_resolu::autorite_de_proprietaire(&owner, &au) {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME_NON_LU);
            eprintln!("[dashboards] WARN tableau de bord #{id} NON lu pour la suppression, rien n'est supprimé ({}) : {e}", cid.unwrap_or_default());
            return refus;
        }
    }
    // `P10.20-l` (vague AF) — LES DEUX EFFACEMENTS SOUS UN GARDE. La forme d'avant (`let _` puis 204) avalait les deux :
    // un DELETE du tableau refusé rendait 204 « supprimé » alors que le tableau restait, et — hors transaction — ses
    // panneaux, déjà effacés, étaient perdus. Ici l'effacement des panneaux (zéro est légitime) puis celui du tableau
    // (UNE ligne exigée : il vient d'être lu) ; un refus ou un effet nul annule TOUT (Drop -> ROLLBACK), 503 nommé.
    let geste = format!("suppression du tableau de bord #{id}");
    let tx = match ouvrir_le_garde_du_geste(&conn, "dashboards", &geste, CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME_TRANSACTION_NON_OUVERTE) {
        Ok(t) => t,
        Err(refus) => return refus,
    };
    // `P10.20-l` (vague AG) — LES PANNEAUX EFFACÉS SONT CEUX LUS, ET LEUR CACHE EST PURGÉ APRÈS LA VALIDATION. Leurs
    // identifiants se lisent dans la transaction, avant l'effacement (une lecture refusée annule tout) ; l'effacement doit
    // en ôter exactement autant (un déclencheur qui en ignore un laisserait un panneau sans tableau) ; puis, la
    // suppression validée seulement, le cache de chacun est purgé — la forme d'avant le laissait derrière, la garde
    // `query_fp` restant la seule barrière contre un rowid réutilisé.
    let ecrit: Result<Vec<i64>, String> = (|| {
        let panneaux: Vec<i64> = conn
            .prepare("SELECT id FROM panel WHERE dashboard_id=?1")
            .and_then(|mut stmt| stmt.query_map(params![id], |r| r.get::<_, i64>(0))?.collect::<rusqlite::Result<Vec<i64>>>())
            .map_err(|e| format!("lecture des panneaux du tableau : {e}"))?;
        let effaces = conn.execute("DELETE FROM panel WHERE dashboard_id=?1", params![id]).map_err(|e| format!("effacement des panneaux du tableau : {e}"))?;
        if effaces != panneaux.len() {
            return Err(format!("effacement des panneaux du tableau : {effaces} ligne(s) effacée(s) pour {} panneau(x) lu(s)", panneaux.len()));
        }
        une_seule_ligne(conn.execute("DELETE FROM dashboard WHERE id=?1", params![id]), "effacement du tableau de bord")?;
        Ok(panneaux)
    })();
    let panneaux = match ecrit {
        Ok(p) => p,
        Err(cause) => {
            drop(tx); // Drop -> ROLLBACK : les panneaux effacés reviennent avec le tableau.
            return refuser_le_retrait_non_pris(&geste, &cause, CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME);
        }
    };
    rendre_apres_validation_du_garde(tx, &conn, "dashboards", &geste, CAUSE_TABLEAU_DE_BORD_NON_SUPPRIME, || {
        for pid in &panneaux {
            panneau_avoue::cache_invalider_panneau(&conn, *pid);
        }
        StatusCode::NO_CONTENT.into_response()
    })
}

pub(crate) async fn panel_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let did = b.i64_field("dashboard_id", 0);
    let title = b.get("title").and_then(|v| v.as_str()).unwrap_or("Panneau").to_string();
    let query = b.str_field("query").to_string();
    let is_soql = if b.bool_field("is_soql", true) { 1 } else { 0 };
    let viz = b.get("viz").and_then(|v| v.as_str()).unwrap_or("table").to_string();
    let window_s = b.i64_field("window_s", 0);
    let visibility = if b.get("visibility").and_then(|v| v.as_str()) == Some("private") { "private" } else { "shared" };
    let query_private = if b.bool_field("query_private", false) { 1 } else { 0 };
    let cols = b.i64_field("cols", 1).clamp(1, 4);
    let height = b.i64_field("height", 0).max(0);
    let drill = b.str_field("drill").to_string();
    // LIBRARY PANELS (#54) : référence optionnelle à une définition réutilisable. 0/absent -> panneau autonome.
    // UNIQUE lecture du champ, et c'est CETTE valeur qui sert à la fois à la porte et à l'écriture.
    let ref_bib = RefBibliotheque::du_corps_a_la_creation(&b);
    let library_panel_id = ref_bib.a_ecrire().flatten();
    crate::req_conn!(st, au, conn);
    // `P10.20-l` (vague AG) — tableau absent : 404 en texte, à la forme du 403 voisin (la forme d'avant disait « non
    // modifiable » d'un tableau qui n'existe pas) ; droit non lu : 503 nommé, rien n'est créé.
    // `P11.25-f` (vague CB) — tableau privé d'autrui : la réponse d'un tableau absent, à l'octet, rien n'est créé (le
    // 403 « dashboard non modifiable » d'avant disait qu'il existe).
    match dash_editable(&conn, &au, did) {
        PorteDuTableau::Ouverte => {}
        PorteDuTableau::Refusee | PorteDuTableau::Absent => return (StatusCode::NOT_FOUND, "dashboard introuvable").into_response(),
        PorteDuTableau::NonLue(refus) => return refus,
    }
    // SQL BRUT = ADMIN — un panneau en SQL BRUT (is_soql=false) exécute du SQL arbitraire read-only sur
    // TOUTE la base à chaque refresh (panel_data) : RÉSERVÉ ADMIN, comme les règles et /api/query. Le
    // GXQL (is_soql=true) reste ouvert à l'editor.
    // P7.13-a — LA PORTE JUGE LA DÉFINITION QUI S'EXÉCUTERA, pas celle du corps : un panneau créé en
    // GXQL mais RÉFÉRENÇANT une définition de bibliothèque en SQL brut exécute du SQL brut (mesuré :
    // l'editor obtenait 200 + 2 lignes de la table `user`). `DefinitionExecutee::projetee` résout
    // panneau ∪ bibliothèque via le MÊME chemin que `panel_access`, et refuse au passage une définition
    // que l'appelant n'a pas le droit de VOIR. Fail-closed.
    let def = match DefinitionExecutee::projetee(&conn, &au, None, &ref_bib, (query.clone(), is_soql == 1)) {
        Ok(d) => d,
        Err((code, msg)) => return (code, msg).into_response(),
    };
    if !def.permise_pour(&au.role) {
        return (StatusCode::FORBIDDEN, "SQL brut réservé à l'administrateur (utilisez GXQL)").into_response();
    }
    match conn.execute(
        "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,window_s,visibility,query_private,cols,height,drill,library_panel_id,position) \
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,(SELECT COALESCE(MAX(position),-1)+1 FROM panel WHERE dashboard_id=?1))",
        params![did, title, query, is_soql, viz, window_s, visibility, query_private, cols, height, drill, library_panel_id],
    ) {
        Ok(1) => Json(json!({ "id": conn.last_insert_rowid() })).into_response(),
        Ok(n) => refus_d_un_objet_non_cree("panneau", n),
        Err(e) => refus_d_un_objet_non_cree_par_le_moteur("panneau", &e),
    }
}

pub(crate) async fn panel_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    crate::req_conn!(st, au, conn);
    // État courant du panneau : dashboard (droit d'édition) + ses colonnes propres + la référence de
    // bibliothèque qu'il porte AUJOURD'HUI (elle entre dans le calcul de ce qui s'exécutera).
    // `P10.20-k` (2026-09-16) — LA VISIBILITÉ COURANTE ENTRE DANS CETTE LECTURE, ET LES TROIS ISSUES
    // SONT DISTINCTES. Avant : cette lecture-ci confondait « pas de panneau » et « pas lu » en un 404,
    // et la visibilité courante se lisait DEUX lignes plus bas par `unwrap_or_else(|_| "shared")` — une
    // lecture ratée déclarait donc le panneau DÉJÀ partagé, `est_un_geste_de_partage` rendait `false`,
    // et la porte `P11.20-m` (la définition de bibliothèque privée qu'il exécute le retient) n'était
    // jamais interrogée avant l'écriture qui publie. Ligne absente = 404 ; lecture non faite = 503 nommé.
    let (did, cur_soql, cur_query, cur_bib, visibilite) = match conn
        .query_row(
            "SELECT dashboard_id, COALESCE(is_soql,1), COALESCE(query,''), library_panel_id, COALESCE(visibility,'shared') FROM panel WHERE id=?1",
            params![id],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)? != 0,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
    {
        Ok(Some(x)) => x,
        Ok(None) => return not_found("panneau introuvable"),
        Err(_) => return panneau_resolu::refus_de_visibilite_non_lue(),
    };
    // `P10.20-k` — ET LES REFUS PORTENT ENFIN LEUR PHRASE. Écart de forme nommé sous `P10.20-b` : là où
    // `panel_create` rend le motif du refus, `panel_update` rendait le CODE SEUL — la console peignait
    // « 403 » nu, et le message de `DefinitionExecutee::projetee` (dont le 503 « définition de
    // bibliothèque NON LUE ») était JETÉ sur le sol par un `Err((code, _))`.
    // `P10.20-l` (vague AG) — tableau porteur absent : 404 nommé ; droit non lu : 503 nommé ; rien n'est écrit.
    // `P11.25-f` (vague CB) — le panneau d'un tableau privé d'autrui est un panneau que l'appelant ne lit pas : il
    // reçoit la réponse d'un identifiant de panneau absent (`panneau introuvable`, ci-dessus), à l'octet, et rien n'est
    // écrit. Le 403 « dashboard non modifiable » d'avant disait que le panneau et son tableau existent.
    match dash_editable(&conn, &au, did) {
        PorteDuTableau::Ouverte => {}
        PorteDuTableau::Refusee => return not_found("panneau introuvable"),
        PorteDuTableau::Absent => return not_found("dashboard introuvable"),
        PorteDuTableau::NonLue(refus) => return refus,
    }
    // `P11.20-m` — le geste de partage d'un panneau est jugé AVANT toute écriture : la définition de
    // bibliothèque privée qu'il exécute le retient, et le refus la nomme avec son propriétaire.
    if panneau_resolu::est_un_geste_de_partage(&b, &visibilite) {
        // `P10.20-b` — les éléments qui retiendraient le partage NON LUS ne valent pas « rien ne
        // retient » : 503 nommé, avant toute écriture.
        match panneau_resolu::ElementMoinsVisible::d_un_panneau(&conn, id) {
            Ok(None) => {}
            Ok(Some(element)) => return panneau_resolu::refus_de_partage(&element, "le panneau"),
            Err(_) => return panneau_resolu::refus_d_elements_retenant_non_lus(),
        }
    }
    // LIBRARY PANELS (#54) : (dé)référencer une définition réutilisable. UNIQUE lecture du champ —
    // la valeur retenue sert À LA FOIS à la porte ci-dessous et à l'écriture plus bas.
    let ref_bib = RefBibliotheque::du_corps(&b);
    // SQL BRUT = ADMIN — la porte juge la DÉFINITION QUI S'EXÉCUTERA APRÈS ce PATCH : colonnes du
    // panneau après patch, RÉSOLUES contre la bibliothèque qu'il référencera. C'est le MÊME chemin de
    // résolution que `panel_access` (coffre `panneau_resolu`) : la porte ne peut pas juger autre chose
    // que ce qui tournera. Un editor ne peut donc NI basculer son panneau en SQL brut, NI éditer un
    // panneau qui EXÉCUTE déjà du SQL brut (le sien ou celui d'une bibliothèque), NI en RATTACHER un.
    // MESURÉ AVANT (2026-08-03, `3256e4d`) : `{"library_panel_id": N}` vers une définition SQL brut
    // d'admin -> 204, puis `panel_data` -> 200 et 2 lignes de la table `user` rendues à l'editor.
    // `projetee` refuse en outre de POSER une référence vers une définition que l'appelant n'a pas le
    // droit de VOIR (mesuré : une définition PRIVÉE d'admin, absente de son inventaire, se rattachait
    // en 204 et rendait son texte comme ses données). Fail-closed.
    let eff_query = b.get("query").and_then(|v| v.as_str()).unwrap_or(&cur_query).to_string();
    let eff_soql = b.get("is_soql").and_then(|v| v.as_bool()).unwrap_or(cur_soql);
    let def = match DefinitionExecutee::projetee(&conn, &au, cur_bib, &ref_bib, (eff_query, eff_soql)) {
        Ok(d) => d,
        Err((code, msg)) => return (code, msg).into_response(),
    };
    if !def.permise_pour(&au.role) {
        return forbidden("SQL brut réservé à l'administrateur (utilisez GXQL)");
    }
    // `P10.20-l` (vague AG) — LES ÉCRITURES SOUS UN GARDE, UNE LIGNE EXIGÉE CHACUNE (le panneau vient d'être lu). La forme
    // d'avant (douze `let _` puis 204) avalait toute écriture refusée — la visibilité, `query_private` et le rattachement
    // compris — et purgeait le cache d'un panneau resté tel quel. Un refus ou un effet nul annule TOUT (Drop -> ROLLBACK),
    // 503 nommé, cache NON purgé.
    let geste = format!("modification du panneau #{id}");
    let tx = match ouvrir_le_garde_du_geste(&conn, "dashboards", &geste, CAUSE_PANNEAU_INCHANGE_TRANSACTION_NON_OUVERTE) {
        Ok(t) => t,
        Err(refus) => return refus,
    };
    let ecrit: Result<(), String> = (|| {
        for (k, col) in [("viz", "viz"), ("title", "title"), ("query", "query")] {
            if let Some(v) = b.get(k).and_then(|v| v.as_str()) {
                une_seule_ligne(conn.execute(&format!("UPDATE panel SET {col}=?1 WHERE id=?2"), params![v, id]), col)?;
            }
        }
        if let Some(v) = b.get("is_soql").and_then(|v| v.as_bool()) {
            une_seule_ligne(conn.execute("UPDATE panel SET is_soql=?1 WHERE id=?2", params![v as i64, id]), "is_soql")?;
        }
        if let Some(v) = b.get("window_s").and_then(|v| v.as_i64()) {
            une_seule_ligne(conn.execute("UPDATE panel SET window_s=?1 WHERE id=?2", params![v, id]), "window_s")?;
        }
        if let Some(v) = b.get("visibility").and_then(|v| v.as_str()) {
            let vv = if v == "private" { "private" } else { "shared" };
            une_seule_ligne(conn.execute("UPDATE panel SET visibility=?1 WHERE id=?2", params![vv, id]), "visibility")?;
        }
        if let Some(v) = b.get("query_private").and_then(|v| v.as_bool()) {
            une_seule_ligne(conn.execute("UPDATE panel SET query_private=?1 WHERE id=?2", params![v as i64, id]), "query_private")?;
        }
        if let Some(v) = b.get("cols").and_then(|v| v.as_i64()) {
            une_seule_ligne(conn.execute("UPDATE panel SET cols=?1 WHERE id=?2", params![v.clamp(1, 4), id]), "cols")?;
        }
        if let Some(v) = b.get("height").and_then(|v| v.as_i64()) {
            une_seule_ligne(conn.execute("UPDATE panel SET height=?1 WHERE id=?2", params![v.max(0), id]), "height")?;
        }
        if let Some(v) = b.get("drill").and_then(|v| v.as_str()) {
            une_seule_ligne(conn.execute("UPDATE panel SET drill=?1 WHERE id=?2", params![v, id]), "drill")?;
        }
        if let Some(v) = b.get("position").and_then(|v| v.as_i64()) {
            une_seule_ligne(conn.execute("UPDATE panel SET position=?1 WHERE id=?2", params![v, id]), "position")?;
        }
        // LIBRARY PANELS (#54) : l'écriture de la référence rejoue EXACTEMENT la décision déjà passée par
        // la porte (`ref_bib`, lu une seule fois) — jamais une seconde lecture du corps qui pourrait en
        // différer. 0/null -> panneau autonome (détache).
        if let Some(v) = ref_bib.a_ecrire() {
            une_seule_ligne(conn.execute("UPDATE panel SET library_panel_id=?1 WHERE id=?2", params![v, id]), "library_panel_id")?;
        }
        Ok(())
    })();
    if let Err(cause) = ecrit {
        drop(tx); // Drop -> ROLLBACK : chaque champ est celui d'avant, le cache n'est pas purgé.
        return refuser_le_retrait_non_pris(&geste, &cause, CAUSE_PANNEAU_INCHANGE);
    }
    rendre_apres_validation_du_garde(tx, &conn, "dashboards", &geste, CAUSE_PANNEAU_INCHANGE, || {
        // INVALIDATION, SEULEMENT APRÈS LA VALIDATION : purge le cache du panneau à chaque update (1 ligne max) -> aucun
        // payload périmé servi après changement de requête/viz/fenêtre/visibilité. La garde query_fp (v36) couvre déjà
        // le cas requête, ceci couvre aussi viz/window/visibilité d'un coup.
        panneau_avoue::cache_invalider_panneau(&conn, id);
        StatusCode::NO_CONTENT.into_response()
    })
}

/// `P10.20-l` (vague AE) — le tableau de bord qui porte le panneau n'a pas été lu : le droit n'est pas jugé, rien n'est
/// supprimé. Ne nomme ni `BEGIN` ni `COMMIT` ni une transaction annulée : c'est la lecture qui manque (refus nommé).
pub(crate) const CAUSE_PANNEAU_NON_SUPPRIME_NON_LU: &str = "PANNEAU NON SUPPRIMÉ : la base n'a pas rendu ce panneau (le \
     tableau de bord qui le porte) — ce n'est PAS une absence, c'est une lecture qui n'a pas eu lieu, et le droit de le \
     supprimer n'est pas jugé. RIEN n'est supprimé : le panneau et son cache sont intacts. Réessayez ; si le refus \
     persiste, la table des panneaux est illisible.";

/// `P10.20-l` (vague AF) — l'effacement du panneau refusé ou sans effet : la transaction est annulée, le cache n'est pas
/// purgé (`OUVERTURE_DE_L_ECRITURE_NON_PRISE`, web/core.js).
pub(crate) const CAUSE_PANNEAU_NON_SUPPRIME: &str = "PANNEAU NON SUPPRIMÉ : la base n'a pas pris l'effacement du \
     panneau ou n'en a effacé aucune ligne, et la transaction est annulée — le panneau et son cache existent toujours. \
     Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P10.20-l` (vague AF) — le `BEGIN` de cette suppression refusé (`OUVERTURE_DE_LA_TRANSACTION_NON_PRISE`).
pub(crate) const CAUSE_PANNEAU_NON_SUPPRIME_TRANSACTION_NON_OUVERTE: &str = "PANNEAU NON SUPPRIMÉ : la base n'a pas \
     pris la transaction de la suppression (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur \
     l'écrivain) — RIEN n'est écrit : le panneau et son cache sont intacts. Réessayez ; s'il est refusé encore, \
     l'écrivain est occupé ou bloqué.";

pub(crate) async fn panel_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    // `P10.20-l` (vague AE) — trois issues : lu, le droit est jugé ; absent, le 404 d'avant (sans corps) ; lecture ratée,
    // 503 `CAUSE_PANNEAU_NON_SUPPRIME_NON_LU` — ni 403 ni suppression. La route rend désormais une `Response` (son seul
    // appelant est le routeur) : la cause est servie en corps, celle du moteur au journal seul.
    match conn.query_row("SELECT dashboard_id FROM panel WHERE id=?1", params![id], |r| r.get::<_, i64>(0)).optional() {
        // `P10.20-l` (vague AG) — le droit sur le tableau porteur, en quatre issues : la forme d'avant rendait 403 sur
        // un droit illisible (`Err(_) => false`) et sur un porteur absent.
        // `P11.25-f` (vague CB) — le panneau d'un tableau privé d'autrui reçoit le 404 nu d'un panneau absent, rien
        // n'est supprimé (le 403 d'avant disait qu'il existe).
        Ok(Some(d)) => match dash_editable(&conn, &au, d) {
            PorteDuTableau::Ouverte => {}
            PorteDuTableau::Refusee | PorteDuTableau::Absent => return StatusCode::NOT_FOUND.into_response(),
            PorteDuTableau::NonLue(refus) => return refus,
        },
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_PANNEAU_NON_SUPPRIME_NON_LU);
            eprintln!("[dashboards] WARN panneau #{id} NON lu pour la suppression, rien n'est supprimé ({}) : {e}", cid.unwrap_or_default());
            return refus;
        }
    }
    // `P10.20-l` (vague AF) — L'EFFACEMENT SOUS UN GARDE, UNE LIGNE EXIGÉE (le panneau vient d'être lu). La forme
    // d'avant (`let _` puis 204) rendait « supprimé » sur un DELETE refusé, et purgeait le cache d'un panneau resté
    // en place. Refusé ou sans effet : Drop -> ROLLBACK, 503 `CAUSE_PANNEAU_NON_SUPPRIME`, cache NON purgé.
    let geste = format!("suppression du panneau #{id}");
    let tx = match ouvrir_le_garde_du_geste(&conn, "dashboards", &geste, CAUSE_PANNEAU_NON_SUPPRIME_TRANSACTION_NON_OUVERTE) {
        Ok(t) => t,
        Err(refus) => return refus,
    };
    if let Err(cause) = une_seule_ligne(conn.execute("DELETE FROM panel WHERE id=?1", params![id]), "effacement du panneau") {
        drop(tx); // Drop -> ROLLBACK : le panneau et son cache restent.
        return refuser_le_retrait_non_pris(&geste, &cause, CAUSE_PANNEAU_NON_SUPPRIME);
    }
    rendre_apres_validation_du_garde(tx, &conn, "dashboards", &geste, CAUSE_PANNEAU_NON_SUPPRIME, || {
        // INVALIDATION, SEULEMENT APRÈS LA VALIDATION : purge le cache du panneau supprimé -> un futur panneau
        // réutilisant ce rowid (panel_id) ne servira jamais le payload de l'ancien (fuite inter-owners/visibilités).
        // La garde query_fp (v36) est une 2e barrière, mais on supprime explicitement la ligne ici.
        panneau_avoue::cache_invalider_panneau(&conn, id);
        StatusCode::NO_CONTENT.into_response()
    })
}

// Exécute la requête d'un panneau CÔTÉ SERVEUR (read-only) -> permet la requête « privée »
// (le client n'a jamais le texte) et l'accès en lecture aux rôles sans droit de requête libre.
/// Granularité du bucket de rollup (s) : les bornes de la clé de cache sont quantifiées dessus.
pub(crate) const CACHE_BUCKET_S: i64 = 3600;
/// Nombre max de plages (range_key) cachées PAR panneau : le cache est désormais
/// multi-emplacement (PK composite panel_id+range_key) ; ce cap évince les plus vieilles plages
/// (par computed_at) après chaque insert -> anti-explosion si un user zoome sur N plages distinctes.
pub(crate) const CACHE_MAX_RANGES_PER_PANEL: i64 = 8;
/// Clé de fenêtre du cache. PROBLÈME corrigé : la PWA n'envoie JAMAIS from=0/to=0 ; pour la
/// fenêtre par défaut (24 h glissantes) elle envoie `from = now-86400` (timestamp GLISSANT) et `to = 0`
/// (= maintenant). Cléer sur ces timestamps bruts -> la clé bouge à chaque seconde -> cache toujours MISS.
/// FIX : on clé sur la DURÉE de fenêtre (quantifiée au bucket), pas sur des bornes glissantes :
///   - to==0 (fenêtre « jusqu'à maintenant ») -> dur = now - from, clé = « w=<dur quantifiée> ».
///     Tous les refresh dans la même fenêtre par défaut produisent la MÊME clé -> HIT (jusqu'au TTL).
///   - bornes absolues (zoom/range custom) -> on quantifie from/to au bucket -> clé « a=<f>-<t> » stable
///     d'un refresh à l'autre tant qu'on reste dans le même bucket.
/// `now_s` = horloge courante (passée pour testabilité). Taille du cache bornée par panneau via le cap
/// CACHE_MAX_RANGES_PER_PANEL (éviction des plus vieilles plages, cf. panel_data).
pub(crate) fn cache_range_key(from: i64, to: i64, now_s: i64) -> String {
    let q = |t: i64| (t / CACHE_BUCKET_S) * CACHE_BUCKET_S; // quantifie au bucket
    if to == 0 {
        // fenêtre « jusqu'à maintenant » : on clé sur la DURÉE (glissante mais stable), quantifiée.
        let dur = (now_s - from).max(0);
        let qd = ((dur + CACHE_BUCKET_S / 2) / CACHE_BUCKET_S).max(0) * CACHE_BUCKET_S; // arrondi au bucket
        format!("w={qd}")
    } else {
        format!("a={}-{}", q(from), q(to))
    }
}

/// FILTRE ENVIRONNEMENT (#2d) : préfixe la clé de plage du cache panneau par l'environnement demandé ->
/// une même fenêtre servie pour env=staging n'écrase JAMAIS le payload env=prod (cache SÉPARÉ par env).
/// None (mode 0 / __all__) -> clé INCHANGÉE (byte-identique à cache_range_key) -> comportement identique.
pub(crate) fn env_range_key(env: Option<&str>, base: &str) -> String {
    match env.filter(|e| !e.is_empty()) {
        Some(e) => format!("e={e}|{base}"),
        None => base.to_string(),
    }
}

/// Empreinte (fingerprint) de la requête d'un panneau : sha256(is_soql|query). Stockée avec le payload
/// caché -> on ne sert le cache QUE si la requête courante a la MÊME empreinte (un
/// panel_update qui change la requête/viz, ou un rowid panel réutilisé après delete, n'expose jamais le
/// payload périmé/étranger). Court (12 hex) : la collision n'a aucune conséquence de sécurité (le
/// payload reste celui d'une requête identique), juste un anti-fuite défensif.
pub(crate) fn query_fingerprint(query: &str, is_soql: bool) -> String {
    sha256_hex(format!("{}|{}", is_soql as u8, query.trim()).as_bytes())[..12].to_string()
}

/// Réglages de SERVICE des panneaux, lus en UN SEUL accès disque (load_config) HORS du lock writer
/// (load_config() fait un accès DISQUE -> jamais appelé en tenant le Mutex sur le chemin chaud).
/// Renvoie :
///   - `ttl_global` : TTL global du cache (PLUME_PANEL_CACHE_TTL, défaut 60s ; 0 = cache désactivé) ;
///   - `live_ms` : seuil de CLASSIFICATION ADAPTATIVE (PHASE 3d, PLUME_PANEL_LIVE_MS, défaut 100). Un
///     panneau dont le coût mesuré (stats.elapsed_ms) est < seuil est servi LIVE (frais) ; >= seuil -> SWR.
/// À calculer avant de prendre le lock, puis passer à panel_cache_ttl().
///
/// `P10.5-i` — LA CONF EST UN PARAMÈTRE, ET C'EST UNE CORRECTION DE COÛT. `load_config()` fait un
/// `read_to_string` SANS mémoïsation ; l'horizon avoué a lui aussi besoin de la conf. Si chacun la
/// lisait pour son compte, un tableau de bord de douze panneaux ferait douze accès disque de plus PAR
/// RAFRAÎCHISSEMENT, succès de cache compris — contre la discipline que ce fichier énonce lui-même
/// (« HORS LOCK : lecture config … AVANT de prendre le lock writer (1 seul accès) »). `panel_data` en
/// fait donc UN, en tête, et le passe à tout ce qui suit.
pub(crate) fn panel_serve_cfg_de(conf: &HashMap<String, String>) -> (i64, i64) {
    let ttl_global = cfg(conf, "PLUME_PANEL_CACHE_TTL", "60").parse().unwrap_or(60);
    let live_ms = cfg(conf, "PLUME_PANEL_LIVE_MS", "100").parse().unwrap_or(100);
    (ttl_global, live_ms)
}

/// PHASE 3d — coût mesuré (stats.elapsed_ms) de la requête d'un panneau. Clé = panel_id (1 ligne/panneau)
/// LIÉ au query_fp courant -> la classe vaut GLOBALEMENT (panel_data est appelé par panel_id), où que le
/// panneau soit rendu (n'importe quel dashboard/vue), PAS par vue. Renvoie None si aucun coût pour ce
/// couple (panneau NOUVEAU ou requête modifiée) -> l'appelant exécute en LIVE (mesuré) et se classe seul.
/// Le filtre query_fp empêche de réutiliser le coût d'une ANCIENNE requête après un panel_update (anti-fuite,
/// cohérent avec panel_cache.query_fp).
///
/// `P10.20-l` (vague AJ) — TROIS ISSUES : `Ok(Some(c))` coût mesuré, `Ok(None)` aucun coût pour ce couple, `Err` lecture
/// qui n'a pas eu lieu. La forme d'avant (`.ok()`) rendait une lecture ratée comme « jamais mesuré » sans un mot ;
/// l'appelant (`panel_data`) la sert toujours comme un panneau jamais mesuré, mais l'écrit au journal (ligne fixe).
/// (La doc d'avant disait « None -> LIVE » : faux depuis FIX #5c, un panneau jamais mesuré part en SWR/chauffe quand il
/// est cacheable.)
pub(crate) fn read_panel_cost(conn: &Connection, panel_id: i64, q_fp: &str) -> rusqlite::Result<Option<f64>> {
    conn.query_row(
        "SELECT cost_ms FROM panel_cost WHERE panel_id=?1 AND query_fp=?2",
        params![panel_id, q_fp],
        |r| r.get::<_, f64>(0),
    )
    .optional()
}

/// PHASE 3d — mémorise le coût mesuré d'un panneau (INSERT OR REPLACE -> 1 seule ligne/panneau). Appelé
/// après CHAQUE exécution (LIVE à la demande ET refresh de fond) -> AUTO-RECLASSEMENT : un panneau cheap
/// qui ralentit (coût >= seuil) bascule SWR au prochain accès, et inversement s'il redevient rapide. Stocke
/// le query_fp courant (le coût ne vaut que pour CETTE requête ; un panel_update le rend « inconnu »).
///
/// `P10.20-b` (reste des tableaux de bord) — L'ÉCRITURE DU COÛT EST JUGÉE. La forme d'avant (`let _ = conn.execute(..)`)
/// jetait un refus sans un mot. Une écriture refusée, ou qui n'écrit aucune ligne (un déclencheur qui l'ignore), laisse
/// UNE ligne de journal fixe — le numéro interne du panneau, jamais la requête, son empreinte ni le texte du moteur — et
/// rien ne remonte à la route (signature inchangée, trois appelants : rafraîchissement de fond, exécution à la demande,
/// boucle de `rollups.rs`). Le panneau dont le coût n'est pas écrit garde sa classe d'avant (SWR ou direct) jusqu'à la
/// prochaine mesure écrite.
pub(crate) fn record_panel_cost(conn: &Connection, panel_id: i64, q_fp: &str, cost_ms: f64, now_s: i64) {
    let issue = conn.execute(
        "INSERT OR REPLACE INTO panel_cost(panel_id,query_fp,cost_ms,measured_at) VALUES(?1,?2,?3,?4)",
        params![panel_id, q_fp, cost_ms, now_s],
    );
    if !matches!(issue, Ok(1)) {
        eprintln!("[dashboards] WARN panneau #{panel_id} : coût mesuré non écrit, le panneau garde sa classe d'avant");
    }
}

/// Extrait le coût SQL mesuré (stats.elapsed_ms) d'un résultat run_query, s'il est présent.
pub(crate) fn measured_cost_ms(v: &Value) -> Option<f64> {
    v.get("stats").and_then(|s| s.get("elapsed_ms")).and_then(|e| e.as_f64())
}

/// TTL effectif du cache d'un panneau : panel.panel_cache_ttl_s (si défini) sinon `ttl_global` (déjà lu
/// hors lock). 0 (global ou par panneau) = cache désactivé pour ce panneau. NE lit PLUS la config disque
/// `ttl_global` est fourni par l'appelant (lu avant de prendre le lock).
///
/// `P10.20-l` (vague AJ) — TROIS ISSUES. La forme d'avant (`.ok().flatten()`) retombait sur `ttl_global` quand la
/// lecture ratait : un TTL par panneau posé à 0 (cache coupé pour ce panneau) ou plus court que le global se perdait en
/// silence, et une charge utile vivait plus longtemps que voulu. Ligne lue : son TTL, ou `ttl_global` si la colonne est
/// NULL ; ligne absente : `ttl_global` (comme avant) ; lecture ratée : 0, cache COUPÉ pour ce panneau (fail-closed), et
/// une ligne de journal fixe — le numéro interne du panneau, jamais la requête ni le texte du moteur.
///
/// `P10.20-l` (vague AK) — CE REPLI NE DÉCIDE PLUS DE `panel_data`. Un `0` rendu sur une lecture ratée y écartait le
/// chemin SWR et envoyait le panneau sur l'exécution directe — et, lane de rafraîchissement saturée, sur la branche
/// « cache off ET lane saturée » qui exécute SANS permis : une charge non bornée ouverte par une lecture qui n'a pas eu
/// lieu. `panel_data` lit donc le TTL par [`lire_le_ttl_du_cache`] (trois issues) et refuse en 503 nommé. Ce repli reste
/// pour l'issue d'un rafraîchissement de fond (`consigner_l_issue_du_rafraichissement` et
/// `memoriser_l_echec_du_rafraichissement`, APRÈS l'exécution : un `0` y veut dire « n'écris pas le cache », fail-closed
/// sans exécution de plus) et pour les témoins qui le tiennent ; décision écrite : deux appelants, deux sens du `0`.
pub(crate) fn panel_cache_ttl(conn: &Connection, panel_id: i64, ttl_global: i64) -> i64 {
    match lire_le_ttl_du_cache(conn, panel_id, ttl_global) {
        Ok(ttl) => ttl,
        Err(_) => {
            eprintln!("[dashboards] WARN panneau #{panel_id} : TTL du cache non lu, cache coupé pour ce panneau");
            0
        }
    }
}

/// `P10.20-l` (vague AK) — LE TTL D'UN PANNEAU EN TROIS ISSUES, pour `panel_data`. Ligne lue : son TTL, ou `ttl_global`
/// si la colonne est NULL ; ligne absente : `ttl_global` (comme [`panel_cache_ttl`]) ; lecture ratée : `Err`, que
/// l'appelant refuse au lieu d'en tirer un « cache coupé » qui décide d'une exécution.
pub(crate) fn lire_le_ttl_du_cache(conn: &Connection, panel_id: i64, ttl_global: i64) -> rusqlite::Result<i64> {
    match conn
        .query_row("SELECT panel_cache_ttl_s FROM panel WHERE id=?1", params![panel_id], |r| r.get::<_, Option<i64>>(0))
        .optional()?
    {
        Some(Some(per)) => Ok(per),
        Some(None) | None => Ok(ttl_global),
    }
}

// =====================================================================================
// DEBRUITAGE « self / opérateur » des vues ORIENTÉES MENACE EXTERNE (configurable, cache boot).
//
// PROBLÈME : le navigateur de l'opérateur sur le dashboard SOC (le vhost de l'UI) peut générer un
// volume massif de challenges edge + de 4xx web = bruit pur.
// Ce trafic SELF/OPÉRATEUR remonte EN TÊTE des panneaux « attaquants / scan / recon » et
// SUR-DÉCLENCHE les règles (« attaquant actif non banni », CF scan/flood/recon…) alors que ce
// n'est PAS une menace. On l'EXCLUT donc des vues « externe/menace », et UNIQUEMENT de celles-là
// (jamais des vues où l'activité opérateur EST le signal voulu : audit kubectl/dataaccess,
// auth/sudo, validation purple-team).
//
// CONFIGURABLE (aucune IP en dur ; DÉFAUT VIDE = build générique, valeur réelle par déploiement) :
//   PLUME_OPERATOR_IPS (CSV) — IP/préfixes de l'opérateur. Défaut VIDE (à fournir par votre
//       déploiement, via un secret/variable d'env). Un item en NOTATION CIDR (« base/N ») ou suffixé « * » ->
//       match de PRÉFIXE (NOT LIKE 'préf%') ; sinon égalité exacte (!=). Un /32 IPv6
//       « 2001:db8::/32 » -> préfixe « 2001:db8: » (RFC 5737/3849 = exemples doc).
//   PLUME_SELF_HOSTS (CSV) — vhosts de l'UI SOC elle-même. Défaut VIDE (à fournir par votre
//       déploiement, ex. « plume.example.com »).
//
// MÉCANIQUE : placeholders `__OPERATOR_EXCL__` (par src_ip) et `__SELF_EXCL__` (par vhost),
// substitués comme `__FROM__` à la compilation (compile_panneau_avoue / rule_sql), dans la BONNE
// cible : clause SQL booléenne pour le SQL natif (is_soql=0, ex. `src_ip != '203.0.113.7' AND
// src_ip NOT LIKE '2001:db8:%'`) OU termes de recherche soql (is_soql=1, ex.
// `src_ip!=203.0.113.7 src_ip!=2001:db8:*`). Liste vide -> no-op (`1=1` en SQL
// natif, terme vide en soql) = exclusion entièrement désactivable.
// =====================================================================================
// DÉFAUTS VIDES (build générique, aucune donnée perso bakée). La VRAIE valeur est fournie PAR
// DÉPLOIEMENT : PLUME_OPERATOR_IPS et PLUME_SELF_HOSTS (secret / variable d'env de VOTRE
// déploiement, ex. « plume.example.com »). Défaut vide -> exclusion no-op (dashboard
// neuf non filtré) tant qu'aucune IP/vhost n'est configuré : sûr et générique pour un client neuf.
pub(crate) const PLUME_OPERATOR_IPS_DEFAULT: &str = "";
pub(crate) const PLUME_SELF_HOSTS_DEFAULT: &str = "";

/// (valeur_à_matcher, préfixe?) pour un item de liste d'exclusion. None si item vide.
pub(crate) fn parse_excl_item(raw: &str) -> Option<(String, bool)> {
    let item = raw.trim();
    if item.is_empty() {
        return None;
    }
    // suffixe '*' explicite -> préfixe
    if let Some(p) = item.strip_suffix('*') {
        let p = p.trim();
        return if p.is_empty() { None } else { Some((p.to_string(), true)) };
    }
    // notation CIDR « base/N » -> préfixe (égalité exacte si /32 IPv4 ou /128 IPv6).
    if let Some((base, masklen)) = item.split_once('/') {
        let base = base.trim();
        let n: u32 = masklen.trim().parse().unwrap_or(0);
        if base.contains(':') {
            // IPv6 : un /64 (le défaut) -> les hextets de poids fort + ':' (préfixe NOT LIKE).
            if n >= 128 {
                return Some((base.trim_end_matches(':').to_string(), false)); // hôte exact
            }
            return Some((format!("{}:", base.trim_end_matches(':')), true));
        }
        // IPv4 : préfixe par octets (N/8). /32 (ou plus) -> exact.
        let octets = (n / 8) as usize;
        if octets >= 4 {
            return Some((base.to_string(), false));
        }
        let pref: Vec<&str> = base.split('.').take(octets).collect();
        if pref.is_empty() {
            return Some((base.to_string(), false));
        }
        return Some((format!("{}.", pref.join(".")), true));
    }
    // sinon : égalité exacte
    Some((item.to_string(), false))
}

/// Clauses d'exclusion compilées (SQL natif + termes soql) pour `src_ip` (opérateur) et `vhost`
/// (self). Générées UNE fois depuis la conf, mises en cache au boot (lues sur le chemin chaud
/// sans load_config).
#[derive(Debug)]
pub(crate) struct ExclClauses {
    pub(crate) op_sql: String,
    pub(crate) op_soql: String,
    pub(crate) self_sql: String,
    pub(crate) self_soql: String,
}
impl ExclClauses {
    /// (clause SQL native, termes soql) pour un champ donné et une liste CSV.
    pub(crate) fn build(field: &str, csv: &str) -> (String, String) {
        // champ réel (src_ip) vs champ JSON (vhost) : la clause SQL native doit json_extract un
        // champ hors-colonne pour rester valide même si elle est un jour utilisée en is_soql=0.
        let sql_field: String = if EVENT_COLS.contains(&field) {
            field.to_string()
        } else {
            format!("json_extract(fields,'$.{field}')")
        };
        let mut sqls: Vec<String> = Vec::new();
        let mut soqls: Vec<String> = Vec::new();
        for item in csv.split(',') {
            if let Some((val, is_prefix)) = parse_excl_item(item) {
                let esc = val.replace('\'', "''");
                if is_prefix {
                    sqls.push(format!("{sql_field} NOT LIKE '{esc}%'"));
                    soqls.push(format!("{field}!={val}*")); // soql `field!=val*` -> NOT LIKE
                } else {
                    sqls.push(format!("{sql_field} != '{esc}'"));
                    soqls.push(format!("{field}!={val}")); // soql `field!=val` -> <>
                }
            }
        }
        let sql = if sqls.is_empty() { "1=1".to_string() } else { sqls.join(" AND ") };
        (sql, soqls.join(" "))
    }
    pub(crate) fn from_config(conf: &HashMap<String, String>) -> Self {
        let (op_sql, op_soql) =
            Self::build("src_ip", &cfg(conf, "PLUME_OPERATOR_IPS", PLUME_OPERATOR_IPS_DEFAULT));
        let (self_sql, self_soql) =
            Self::build("vhost", &cfg(conf, "PLUME_SELF_HOSTS", PLUME_SELF_HOSTS_DEFAULT));
        ExclClauses { op_sql, op_soql, self_sql, self_soql }
    }
    /// Variante RÉSOLUE (chantier « whitelists → webui ») : la valeur d'AFFICHAGE opérateur/self peut être
    /// SURCHARGÉE par un `setting` éditable+audité (`excl_display_csv`). MÊME chaîne que `setting_days` : la
    /// BDD gagne, sinon repli sur l'env PLUME_* (défaut vide). BYTE-IDENTIQUE à `from_config` quand AUCUNE
    /// ligne `setting` n'existe (cas prod par défaut : la vraie valeur vient du Secret via l'env, pas d'override).
    /// GARANTIE display-only (§4) : le CSV résolu ici n'alimente QUE ces clauses de PANNEAUX (compile_panneau_avoue) ;
    /// il n'est JAMAIS lu par `protected_ip_matchers` (never-ban HOST) ni par `rule_sql` (détection).
    ///
    /// `P10.20-l` — TROIS ISSUES : un override lu l'emporte, une ligne absente rend le repli sur l'environnement (comme
    /// avant), une lecture RATÉE remonte en `Err` — jamais le repli, qui remplaçait en silence le réglage de
    /// l'administrateur par celui du déploiement.
    pub(crate) fn resolve(conn: &Connection, conf: &HashMap<String, String>) -> rusqlite::Result<Self> {
        let op_csv = excl_display_csv(conn, conf, EXCL_OP_SETTING, "PLUME_OPERATOR_IPS", PLUME_OPERATOR_IPS_DEFAULT)?;
        let self_csv = excl_display_csv(conn, conf, EXCL_SELF_SETTING, "PLUME_SELF_HOSTS", PLUME_SELF_HOSTS_DEFAULT)?;
        Ok(Self::depuis_les_csv(&op_csv, &self_csv))
    }
    /// Les clauses de deux CSV déjà lus (opérateur, self) : le même `build` que `from_config` et `resolve`.
    pub(crate) fn depuis_les_csv(op_csv: &str, self_csv: &str) -> Self {
        let (op_sql, op_soql) = Self::build("src_ip", op_csv);
        let (self_sql, self_soql) = Self::build("vhost", self_csv);
        ExclClauses { op_sql, op_soql, self_sql, self_soql }
    }
}
/// Clés `setting` (scope='global') portant l'override d'AFFICHAGE éditable des exclusions opérateur/self.
/// DÉLIBÉRÉMENT DISTINCTES des env `PLUME_OPERATOR_IPS`/`PLUME_SELF_HOSTS` : ces env alimentent AUSSI la
/// denylist never-ban HOST (`protected_ip_matchers`) ; l'override webui ne doit JAMAIS piloter l'enforcement
/// (invariant sacré : surfacer ≠ piloter — piège §4). Un override ne touche donc QUE le débruitage des panneaux.
pub(crate) const EXCL_OP_SETTING: &str = "excl_operator_ips";
pub(crate) const EXCL_SELF_SETTING: &str = "excl_self_hosts";
/// Résout le CSV COURANT d'une exclusion d'AFFICHAGE : `setting` override (l'admin l'emporte, hot-reload)
/// sinon env PLUME_* (défaut vide). Repli byte-identique quand aucune ligne `setting` n'existe.
///
/// `P10.20-l` — TROIS ISSUES par `.optional()` : ligne lue = l'override ; ligne ABSENTE = le repli sur l'environnement ;
/// lecture RATÉE (table illisible, valeur d'une forme inconnue) = `Err`. Avant, `.ok()` confondait les deux derniers :
/// une lecture ratée de l'override de l'ADMINISTRATEUR retombait en silence sur la valeur du déploiement, servie au
/// registre comme « en vigueur », inscrite au registre d'audit comme ancienne valeur, et chargée dans le cache des
/// panneaux. Chaque appelant dit désormais ce qu'il fait d'un `Err` (cache gardé, 503 nommé, aveu au registre).
pub(crate) fn excl_display_csv(conn: &Connection, conf: &HashMap<String, String>, setting_key: &str, env_key: &str, default: &str) -> rusqlite::Result<String> {
    let lue = conn
        .query_row("SELECT value FROM setting WHERE scope='global' AND key=?1", params![setting_key], |r| r.get::<_, String>(0))
        .optional()?;
    Ok(match lue {
        Some(s) => s.trim().to_string(),
        None => cfg(conf, env_key, default),
    })
}
pub(crate) static EXCL_CLAUSES: std::sync::OnceLock<parking_lot::RwLock<ExclClauses>> = std::sync::OnceLock::new();
/// Cache process-global des clauses d'exclusion (RwLock : RAFRAÎCHISSABLE après une édition webui audité).
/// Initialisé au boot depuis conf+setting ; lazy (défauts env) sinon. Lu sur le chemin chaud (apply_excl_*).
pub(crate) fn excl_clauses_cell() -> &'static parking_lot::RwLock<ExclClauses> {
    EXCL_CLAUSES.get_or_init(|| parking_lot::RwLock::new(ExclClauses::from_config(&load_config())))
}
/// Recompile le cache d'exclusion depuis la BDD (`setting` override) + conf. Appelé AU BOOT. JAMAIS sur le chemin
/// chaud de requête. (L'édition auditée pose ses clauses par `excl_clauses_poser`, depuis les valeurs lues DANS sa
/// transaction : aucune relecture après le `COMMIT`.)
///
/// `P10.20-l` — UN OVERRIDE NON LU NE CHARGE JAMAIS LE REPLI. La lecture ratée garde le cache d'avant (au boot : les
/// clauses de l'environnement, initialisées paresseusement) et le dit au journal ; le boot ne refuse pas.
pub(crate) fn excl_clauses_refresh(conn: &Connection, conf: &HashMap<String, String>) {
    match ExclClauses::resolve(conn, conf) {
        Ok(fresh) => excl_clauses_poser(fresh),
        Err(e) => {
            eprintln!("[exclusion] WARN override d'affichage NON lu : les panneaux gardent les clauses d'avant, jamais le repli sur l'environnement ({e})");
        }
    }
}
/// Pose des clauses déjà établies dans le cache des panneaux (hot-reload).
pub(crate) fn excl_clauses_poser(fresh: ExclClauses) {
    let mut w = excl_clauses_cell().write();
    *w = fresh;
}
/// Substitue `__OPERATOR_EXCL__` / `__SELF_EXCL__` dans la cible adaptée (SQL natif vs termes
/// soql). Fast-path : aucun placeholder -> chaîne renvoyée telle quelle (quasi-totalité des
/// requêtes). Pas de load_config sur le chemin chaud (clauses lues via le cache RwLock).
pub(crate) fn apply_excl_placeholders(query: &str, is_soql: bool) -> String {
    if !query.contains("__OPERATOR_EXCL__") && !query.contains("__SELF_EXCL__") {
        return query.to_string();
    }
    let g = excl_clauses_cell().read();
    let (op, slf) = if is_soql {
        (g.op_soql.as_str(), g.self_soql.as_str())
    } else {
        (g.op_sql.as_str(), g.self_sql.as_str())
    };
    query.replace("__OPERATOR_EXCL__", op).replace("__SELF_EXCL__", slf)
}

/// LES MARQUEURS DE FENÊTRE D'UNE REQUÊTE BRUTE, PAR UN SEUL ÉCRIVAIN (`P11.24-m`, mesuré le 2026-09-08).
/// `__FROM__` / `__TO__` sont substitués par le DÉMON, jamais par la console : un marqueur nu n'atteint
/// donc jamais SQLite. Ce que cinq sites écrivaient chacun de leur côté : `__TO__` remplacé par `to`
/// TEL QUEL — or `to == 0` veut dire « pas de borne haute » (le compilateur GXQL n'émet `ts <= to` que
/// si `to > 0`, et la console envoie `to: 0` dès qu'aucun zoom n'est posé). En SQL brut, ce zéro devenait
/// `ts <= 0` : un résultat VIDE fabriqué, présenté comme le contenu de la fenêtre. Ici, une borne haute
/// absente vaut « pas de borne » (`i64::MAX`), comme en GXQL ; `__FROM__` reste `from` (0 = depuis toujours,
/// ce que `ts >= 0` dit déjà). Fast-path : aucun marqueur -> chaîne rendue telle quelle.
pub(crate) fn substituer_les_marqueurs_de_fenetre(sql: &str, from: i64, to: i64) -> String {
    if !sql.contains("__FROM__") && !sql.contains("__TO__") {
        return sql.to_string();
    }
    let borne_haute = if to > 0 { to } else { i64::MAX };
    sql.replace("__FROM__", &from.to_string()).replace("__TO__", &borne_haute.to_string())
}

/// PHASE 3b — refresh ASYNCHRONE (SWR) d'un panneau. Déclenché par panel_data quand le cache est périmé
/// ou absent. Ne bloque JAMAIS le chemin requête :
///   - anti-stampede : un seul refresh EN VOL par clé (panel_id, range_key) via st.panel_refresh_inflight ;
///   - borné : `refresh_sem.try_acquire_owned()` (PAS await) — sémaphore SÉPARÉ du query_sem interactif
///     (CHANGEMENT 1) : un refresh NE VOLE JAMAIS de permis à /api/query ni /api/search. Si refresh_sem
///     est saturé, on abandonne ce refresh (le cache périmé reste servi) ;
///   - `panneau_avoue::executer` en spawn_blocking, puis écriture du cache par le coffre (même logique
///     que le tick de pré-chauffage).
///
/// `P10.5-i` — LA CONF EST CLONÉE AVANT LE `spawn`, PAS LUE DEDANS. La tâche a besoin de la conf pour
/// l'horizon ; la lire dans la tâche ajouterait un accès disque par rafraîchissement. Une allocation
/// remplace un `read_to_string`. `from` voyage aussi : l'aveu porte la fenêtre RÉELLEMENT calculée.
pub(crate) fn enqueue_panel_refresh(
    st: &AppState, au: &AuthUser, id: i64, range_key: String, q_fp: String, pc: PanneauCompile, from: i64,
    ttl_global: i64, conf: HashMap<String, String>,
) {
    let key = (id, range_key.clone());
    {
        // insertion atomique dans le set in-flight : si déjà présent, un refresh est en vol -> on sort.
        let mut g = st.panel_refresh_inflight.lock();
        if !g.insert(key.clone()) {
            return;
        }
    }
    let db = req_db(st, au);            // #2a-2b : cache/refresh du panneau sur la base du tenant COURANT
    let db_path = req_db_path(st, au);
    let tenant = au.tenant.clone();
    let refresh_sem = st.refresh_sem.clone(); // CHANGEMENT 1 : sémaphore refresh SÉPARÉ (jamais query_sem)
    let inflight = st.panel_refresh_inflight.clone();
    tokio::spawn(async move {
        // try_acquire_owned (PAS await) : si aucun permit libre, on renonce — le cache périmé reste servi.
        if let Ok(_permit) = refresh_sem.try_acquire_owned() {
            let now_s = now();
            // `P10.32-o` — L'ÉCHEC N'EST PLUS JETÉ : un `Err` du moteur (budget, SQL) ou une panique du fil
            // laissait la ligne de cache ABSENTE, donc un `warming` servi à chaque interrogation, pour toujours.
            // `P10.29-l` (vague AS) — la classe de l'échec est relue SUR LE FIL qui exécute (`en_classant`).
            let issue = tokio::task::spawn_blocking(move || {
                crate::query_exec::en_classant(|| panneau_avoue::executer(&db_path, &conf, pc, from))
            })
            .await;
            consigner_l_issue_du_rafraichissement(&db, &tenant, id, &range_key, &q_fp, now_s, from, ttl_global, issue);
        }
        // retrait du set in-flight (succès, abandon ou erreur) -> un futur refresh pourra repartir.
        { let mut g = inflight.lock();
            g.remove(&key);
        }
    });
}

/// `P10.32-o` — L'ISSUE D'UN RAFRAÎCHISSEMENT, telle que rendue par le fil bloquant : succès (coût +
/// cache), échec CLASSÉ du moteur (`query_exec::en_classant`) ou panique du fil (`JoinError`, cause « exécution
/// échouée »). Séparée de la tâche pour que chaque bras — panique comprise — se joue sur une issue fabriquée.
/// `tenant` est celui de l'appelant qui a armé le rafraîchissement : il n'est lu que par le journal.
pub(crate) fn consigner_l_issue_du_rafraichissement(
    db: &Arc<Mutex<Connection>>, tenant: &str, id: i64, range_key: &str, q_fp: &str, now_s: i64, from: i64, ttl_global: i64,
    issue: Result<Result<Value, crate::query_exec::EchecDeRequete>, tokio::task::JoinError>,
) {
    match issue {
        Ok(Ok(v)) => {
            let cost_ms = measured_cost_ms(&v); // PHASE 3d : mesure du refresh -> classe le panneau
            // `P10.32-o` — `Value::to_string` ne peut pas échouer et rend les mêmes octets que `serde_json::to_string` : plus
            // de branche où le succès serait jeté sans un mot (avant, `if let Ok(payload) = serde_json::to_string(&v)`).
            let payload = v.to_string();
            let conn = db.lock();
            // PHASE 3d : mémorise le coût (auto-reclassement) même si le cache est off ensuite.
            if let Some(c) = cost_ms {
                record_panel_cost(&conn, id, q_fp, c, now_s);
            }
            if panel_cache_ttl(&conn, id, ttl_global) > 0 {
                // écriture + cap anti-explosion : le coffre POSSÈDE la table (garde de build).
                // `P10.32-o` (vague BH) — LE REFUS DE L'ÉCRITURE N'EST PLUS JETÉ (avant, `cache_ecrire` et son `let _ =`) :
                // il est noté par le coffre (`serve_swr` le lit : refus nommé ou aveu, réessai borné) et dit ici.
                if let Err(e) = panneau_avoue::cache_ecrire_dit(&conn, id, range_key, q_fp, now_s, &payload) {
                    eprintln!(
                        "[panel] WARN rafraîchissement du panneau {id} réussi, résultat NON ÉCRIT au cache ({e}) — \
                         {ROUTE_DES_DONNEES_DE_PANNEAU}, tenant {tenant:?} — la charge précédente reste servie avec l'aveu, \
                         sinon un refus nommé (503) ; nouveau calcul au plus une fois par durée du cache"
                    );
                }
            }
        }
        Ok(Err(echec)) => {
            let echec = EchecMisEnCache::de_la_requete(echec);
            memoriser_l_echec_du_rafraichissement(db, tenant, id, range_key, q_fp, now_s, from, ttl_global, &echec)
        }
        Err(_) => memoriser_l_echec_du_rafraichissement(db, tenant, id, range_key, q_fp, now_s, from, ttl_global, &EchecMisEnCache::tache()),
    }
}

/// La route des données d'un panneau, nommée par les lignes de journal de ses refus (gabarit du routeur).
pub(crate) const ROUTE_DES_DONNEES_DE_PANNEAU: &str = "/api/panels/{id}/data";

/// `P10.29-l` (vague AS) — la clé qui porte, dans un corps d'échec mis en cache, la CLASSE de l'échec. Elle est
/// écrite par `memoriser_l_echec_du_rafraichissement` et retirée au HIT avant de servir (`serve_swr`) : le corps
/// servi garde sa forme d'avant. Un corps d'échec SANS elle a été écrit par une version qui servait le texte du
/// moteur : il n'est plus servi (`corps_d_echec_d_une_version_anterieure`). MARQUEUR INTERNE, JAMAIS SERVI (retiré
/// aussi par `servir_les_panneaux_d_un_instantane`) : ce n'est pas une clé d'aveu (`CLE_*`) que la console lirait.
pub(crate) const MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC: &str = "classe_d_echec";

/// Les classes qu'une version courante écrit sous [`MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC`].
pub(crate) const CLASSES_D_ECHEC_MISES_EN_CACHE: [&str; 5] = ["support", "occupee", "produit", "moteur", "tache"];

/// `P10.29-l` (vague AS) — CE QU'UN RAFRAÎCHISSEMENT EN ÉCHEC ÉCRIT DANS `panel_cache`, ET CE QU'IL JOURNALISE.
/// Le `panel_cache` est RÔLE-AGNOSTIQUE et persistant : le corps d'échec est servi à tout lecteur du panneau
/// jusqu'au succès suivant. Avant, `error` y portait le texte du moteur (le refus de l'autorisateur cite l'énoncé
/// compilé, une erreur d'ouverture le chemin de la base). La phrase servie est celle de `/api/query`
/// (`handlers::query::refus_de_requete`) : support et base occupée par leurs phrases fixes, phrase du produit à
/// l'octet, tout autre texte du moteur sous `REQUETE_REJETEE_PAR_LE_MOTEUR`. Le journal garde la cause : le
/// texte du moteur ou la phrase du produit, la seule nature du code pour le support et la base occupée (le texte
/// d'une ouverture ratée cite le chemin de la base).
pub(crate) struct EchecMisEnCache {
    classe: &'static str,
    servie: String,
    au_journal: String,
}

impl EchecMisEnCache {
    pub(crate) fn de_la_requete(echec: crate::query_exec::EchecDeRequete) -> Self {
        use crate::handlers::query::{CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE, CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE, REQUETE_REJETEE_PAR_LE_MOTEUR};
        use crate::query_exec::EchecDeRequete as Echec;
        match echec {
            Echec::Support { nature, .. } => Self { classe: "support", servie: CAUSE_REQUETE_NON_SERVIE_BASE_ILLISIBLE.to_string(), au_journal: nature },
            Echec::Occupee { nature, .. } => Self { classe: "occupee", servie: CAUSE_REQUETE_NON_SERVIE_BASE_OCCUPEE.to_string(), au_journal: nature },
            Echec::Produit(phrase) => Self { classe: "produit", servie: phrase.clone(), au_journal: phrase },
            Echec::Moteur { texte, .. } => Self { classe: "moteur", servie: REQUETE_REJETEE_PAR_LE_MOTEUR.to_string(), au_journal: texte },
        }
    }

    fn tache() -> Self {
        Self { classe: "tache", servie: "exécution échouée".to_string(), au_journal: "exécution échouée".to_string() }
    }

    /// La classe, écrite sous [`MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC`] (cache des panneaux, instantanés).
    pub(crate) fn classe(&self) -> &'static str {
        self.classe
    }

    /// La phrase servie au client.
    pub(crate) fn servie(&self) -> &str {
        &self.servie
    }

    /// La cause, pour le journal seul.
    pub(crate) fn au_journal(&self) -> &str {
        &self.au_journal
    }
}

/// `P10.29-l` (vague AS) — un corps d'échec écrit par une version ANTÉRIEURE : un objet qui porte `error` sans
/// classe reconnue. Son `error` peut être le texte du moteur ; `serve_swr` le traite comme une absence (corps
/// `warming`, rafraîchissement armé) et le prochain échec l'écrase (`charge_valide` le tient pour un échec).
pub(crate) fn corps_d_echec_d_une_version_anterieure(payload: &str) -> bool {
    match serde_json::from_str::<Value>(payload) {
        Ok(v) => {
            v.get("error").is_some()
                && !v.get(MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC).and_then(|c| c.as_str()).is_some_and(|c| CLASSES_D_ECHEC_MISES_EN_CACHE.contains(&c))
        }
        Err(_) => false,
    }
}

/// `P10.32-o` — le champ de `stats` qui, sur une charge utile VALIDE servie périmée, dit que son dernier rafraîchissement
/// a échoué : `{ "cause": <phrase de la classe, jamais le texte du moteur>, "echoue_a": <instant de l'échec> }`. Écrit
/// par [`joindre_l_echec_a_la_charge_valide`], retiré par le succès suivant (qui réécrit toute la ligne).
pub(crate) const CHAMP_DU_RAFRAICHISSEMENT_EN_ECHEC: &str = "rafraichissement_en_echec";

/// Ce que [`joindre_l_echec_a_la_charge_valide`] a trouvé et fait.
pub(crate) enum IssueDeLaChargeValide {
    /// Aucune charge utile valide en cache (absence, corps d'échec, charge qui n'est pas du JSON) : rien n'est écrit ici.
    Aucune,
    /// `P10.32-o` — une ligne de cache EXISTE et a été lue, mais sa valeur ne se décode pas
    /// (`panneau_avoue::LectureDeCache::Illisible`, cause portée) : elle ne porte aucune charge utile valide. Rien n'est
    /// écrit ici ; l'appelant à la demande la REMPLACE par le corps d'échec, le pré-chauffage la laisse à ce chemin.
    Illisible(String),
    /// `P10.32-o` — la ligne de cache n'a PAS été lue (lecture refusée par le moteur, cause de
    /// `panneau_avoue::cache_lire_dit`) : une charge utile valide peut s'y trouver. Rien n'est écrit, ni aveu ni corps
    /// d'échec, ici ni par l'appelant.
    NonLue(String),
    /// La charge utile valide est réécrite telle quelle, `stats.rafraichissement_en_echec` en plus, instant de calcul
    /// INCHANGÉ (elle reste périmée : la tentative suivante revient à la prochaine interrogation).
    Jointe,
    /// La charge utile valide est restée en cache, mais l'échec n'a pas pu y être joint (cause). Écriture refusée : le
    /// refus est noté à la tentative (registre des refus) ; `stats` qui n'est pas un objet : rien n'est écrit ni noté.
    NonJointe(String),
    /// La charge utile valide en cache a été CALCULÉE APRÈS la tentative en échec (un succès concurrent l'a écrite
    /// pendant cette tentative : `calcule_a > echoue_a`). Elle n'est pas en échec : rien n'est écrit, ni aveu ni corps
    /// d'échec.
    PlusRecenteQueLaTentative,
}

/// `P10.32-o` — UNE CHARGE UTILE VALIDE SERVIE PÉRIMÉE DIT QUE SON RAFRAÎCHISSEMENT A ÉCHOUÉ. Avant, l'échec n'était dit
/// qu'au journal : le corps périmé était servi comme si rien ne s'était passé. La charge utile n'est jamais remplacée
/// par un échec (ses lignes restent servies) ; seul `stats.rafraichissement_en_echec` est posé, avec la phrase de la
/// classe (`EchecMisEnCache::servie`) et l'instant ; un échec neuf remplace le précédent. Partagée par le rafraîchissement
/// à la demande et par le pré-chauffage (`rollups::cache_refresh_all_panels`) : la présence de l'aveu ne dépend pas de
/// qui a tenté le calcul.
pub(crate) fn joindre_l_echec_a_la_charge_valide(
    conn: &Connection, id: i64, range_key: &str, q_fp: &str, now_s: i64, echec: &EchecMisEnCache,
) -> IssueDeLaChargeValide {
    let lue = match panneau_avoue::cache_lire_dit(conn, id, range_key, q_fp) {
        panneau_avoue::LectureDeCache::Lue(payload, calcule_a) => Some((payload, calcule_a)),
        panneau_avoue::LectureDeCache::Absente => None,
        // `P10.32-o` — une ligne lue mais non décodable ne porte aucune charge valide : elle peut être remplacée.
        panneau_avoue::LectureDeCache::Illisible(cause) => return IssueDeLaChargeValide::Illisible(cause),
        // `P10.32-o` — une lecture REFUSÉE n'est pas une absence : la charge valide qu'elle cache n'est pas écrasée.
        panneau_avoue::LectureDeCache::NonLue(cause) => return IssueDeLaChargeValide::NonLue(cause),
    };
    let valide = lue.and_then(|(payload, calcule_a)| {
        serde_json::from_str::<Value>(&payload).ok().filter(|v| v.is_object() && v.get("error").is_none()).map(|v| (v, calcule_a))
    });
    let Some((mut v, calcule_a)) = valide else {
        return IssueDeLaChargeValide::Aucune;
    };
    // Un aveu ne se joint qu'à une charge calculée AU PLUS TARD à l'instant de la tentative (`echoue_a >= calcule_a`) :
    // `now_s` est pris avant l'exécution (en tête du tick au pré-chauffage, avant `spawn_blocking` à la demande), et un
    // succès concurrent a pu réécrire la ligne entre-temps.
    if calcule_a > now_s {
        return IssueDeLaChargeValide::PlusRecenteQueLaTentative;
    }
    let aveu = json!({ "cause": echec.servie(), "echoue_a": now_s });
    let pose = match v.as_object_mut().map(|o| o.entry("stats").or_insert_with(|| json!({}))) {
        Some(Value::Object(stats)) => {
            stats.insert(CHAMP_DU_RAFRAICHISSEMENT_EN_ECHEC.to_string(), aveu);
            true
        }
        _ => false,
    };
    if !pose {
        return IssueDeLaChargeValide::NonJointe("`stats` de la charge utile n'est pas un objet".to_string());
    }
    // `P10.32-o` (vague BH, correction) — la charge garde son âge (`calcule_a`), mais un refus est noté à l'instant de la
    // TENTATIVE (`now_s`) et comme l'échec d'un calcul : noté à `calcule_a`, il était déjà plus vieux que la durée du cache
    // (calcul réarmé à chaque interrogation) et la charge servie annonçait « le résultat du dernier calcul ».
    match panneau_avoue::cache_ecrire_l_echec_dit(conn, id, range_key, q_fp, calcule_a, now_s, &v.to_string(), echec.servie()) {
        Ok(()) => IssueDeLaChargeValide::Jointe,
        Err(e) => IssueDeLaChargeValide::NonJointe(e),
    }
}

/// `P10.32-o` — L'ÉCHEC D'UN RAFRAÎCHISSEMENT EST ÉCRIT, À LA PLACE D'UNE ABSENCE. Le corps d'échec
/// (`panneau_avoue::corps_d_echec` : `error` = phrase de la classe, aucun `warming`) est servi par la
/// prochaine interrogation, et la nouvelle tentative revient par le mécanisme ordinaire du cache périmé
/// (`now_s - computed_at > ttl`). Un succès ultérieur l'écrase. Le coût n'est PAS enregistré : un échec
/// ne classe pas le panneau.
/// UNE CHARGE UTILE VALIDE DÉJÀ EN CACHE N'EST PAS ÉCRASÉE (lisible, sans `error`), ni une ligne dont la lecture est
/// REFUSÉE (`IssueDeLaChargeValide::NonLue` : elle peut porter une charge valide) : périmée, elle reste
/// servie et la tentative suivante revient à la prochaine interrogation — comme au pré-chauffage, qui
/// garde le périmé quand il échoue — sauf si l'écriture qui joignait l'échec a été REFUSÉE : ce refus, noté à la
/// tentative, borne le calcul suivant à la durée du cache écoulée depuis lui (`serve_swr`), et la ligne de journal le dit.
/// Le corps d'échec ne remplace qu'une ABSENCE, un échec précédent, ou une ligne lue
/// mais non décodable (`IssueDeLaChargeValide::Illisible`, dite à sa ligne de journal : « ligne de cache ILLISIBLE »).
/// Journal : l'identifiant, la cause, la route, le tenant de l'appelant et le geste RÉELLEMENT fait (écrit,
/// conservé, refusé, cache coupé), jamais la requête.
fn memoriser_l_echec_du_rafraichissement(
    db: &Arc<Mutex<Connection>>, tenant: &str, id: i64, range_key: &str, q_fp: &str, now_s: i64, from: i64, ttl_global: i64,
    echec: &EchecMisEnCache,
) {
    let cause = &echec.au_journal;
    let tete = format!("[panel] WARN rafraîchissement du panneau {id} en échec ({cause}) — {ROUTE_DES_DONNEES_DE_PANNEAU}, tenant '{tenant}'");
    let conn = db.lock();
    if panel_cache_ttl(&conn, id, ttl_global) <= 0 {
        eprintln!("{tete} — cache des panneaux coupé, rien d'écrit");
        return;
    }
    match joindre_l_echec_a_la_charge_valide(&conn, id, range_key, q_fp, now_s, echec) {
        IssueDeLaChargeValide::Jointe => {
            eprintln!("{tete} — charge utile précédente conservée (périmée), nouvelle tentative à la prochaine interrogation");
            return;
        }
        IssueDeLaChargeValide::NonJointe(e) => {
            // `P10.32-o` (vague BI) — LA SUITE SE LIT DANS LE REGISTRE, ELLE NE SE SUPPOSE PAS. Une jonction dont l'ÉCRITURE
            // est refusée y est notée à cette tentative : `serve_swr` ne réarme alors aucun calcul avant la durée du cache
            // écoulée depuis ce refus. Une jonction impossible sans écriture (`stats` qui n'est pas un objet) ne note rien :
            // la tentative suivante revient à la prochaine interrogation. Avant, la ligne disait toujours la seconde.
            let suite = match panneau_avoue::refus_d_ecriture_de_cache(&conn, id, range_key, q_fp) {
                Some(refus) => format!(
                    "refus d'écriture noté à {} : aucun nouveau calcul avant l'expiration du cache depuis ce refus",
                    refus.refusee_a
                ),
                None => "aucun refus d'écriture noté : nouvelle tentative à la prochaine interrogation".to_string(),
            };
            eprintln!("{tete} — charge utile précédente conservée (périmée), échec NON joint au corps servi ({e}), {suite}");
            return;
        }
        IssueDeLaChargeValide::PlusRecenteQueLaTentative => {
            eprintln!("{tete} — charge utile calculée après cette tentative conservée, rien d'écrit");
            return;
        }
        IssueDeLaChargeValide::NonLue(e) => {
            eprintln!("{tete} — ligne de cache NON LUE : {e} — rien d'écrit, une charge utile précédente y reste intacte");
            return;
        }
        IssueDeLaChargeValide::Illisible(e) => {
            eprintln!("{tete} — ligne de cache ILLISIBLE (lue, non décodable) : {e} — remplacée par le corps d'échec");
        }
        IssueDeLaChargeValide::Aucune => {}
    }
    let mut corps = panneau_avoue::corps_d_echec(&echec.servie, from, now_s);
    corps[MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC] = json!(echec.classe);
    match panneau_avoue::cache_ecrire_l_echec_dit(&conn, id, range_key, q_fp, now_s, now_s, &corps.to_string(), &echec.servie) {
        Ok(()) => eprintln!("{tete} — corps d'échec servi, nouvelle tentative à l'expiration du cache"),
        Err(e) => eprintln!("{tete} — corps d'échec NON ÉCRIT ({e}), le panneau reste sans charge utile"),
    }
}

/// `P10.32-o` — ce que la lecture de la ligne de cache a rendu quand elle n'a rien à servir. Jugé par `serve_swr` : une
/// ligne NON LUE avant le refus du compilateur (elle peut cacher une charge utile valide), une ligne ILLISIBLE après lui
/// (elle ne porte rien : un panneau qui ne compile pas rend son refus) ; une absence reste un MISS. Jamais une chauffe.
enum LigneDeCacheRatee {
    Aucune,
    Illisible,
    /// L'identifiant de corrélation servi et écrit à la ligne de journal.
    NonLue(String),
}

/// `P10.32-o` — la ligne de cache de ce panneau n'a pas pu être lue (lecture refusée par la base) : servie en 503 par
/// `serve_swr`, jamais comme une chauffe. La console la peint en lecture refusée avec sa cause (`j.error`, carte du
/// panneau, web/dashboards.js ; `causeNommeeParLeDemon`, web/core.js). Ne nomme ni `BEGIN` ni `COMMIT`.
pub(crate) const CAUSE_LIGNE_DE_CACHE_DU_PANNEAU_NON_LUE: &str = "LIGNE DE CACHE NON LUE : la base n'a pas rendu la ligne \
     de cache de ce panneau — ce n'est PAS une mesure en cours ni une absence, c'est une lecture qui n'a pas eu lieu. RIEN \
     n'est servi ; un rafraîchissement est armé si le panneau compile. Réessayez ; si le refus persiste, la table du cache \
     des panneaux est illisible.";

/// `P10.32-o` (vague BH) — la dernière écriture de la ligne de cache de ce panneau a été refusée par la base (disque plein,
/// base en lecture seule : `panneau_avoue::ecriture_de_cache_refusee`) et aucune charge valide n'y est : servie en 503 par
/// `serve_swr`, jamais comme une chauffe. La console la peint comme toute lecture non servie en 503 nommé, avec sa cause
/// (`refusDUneLectureServie`, appelé par la carte du panneau sur `!r.ok`, web/dashboards.js). Ne nomme ni `BEGIN` ni
/// `COMMIT`, et ne recopie jamais la cause du moteur (elle va au journal).
/// `P10.32-o` (vague BH, correction) — le DERNIER CALCUL A ÉCHOUÉ et la base a refusé d'écrire cet échec (corps d'échec)
/// dans le cache, sans charge valide à servir : servi en 503 par `serve_swr`, suivi de la phrase servie de la classe
/// d'échec (jamais du texte du moteur), sous la raison `calcul_echoue`. Avant, ce cas servait
/// `CAUSE_RESULTAT_DU_PANNEAU_NON_ECRIT`, qui parle du « résultat » d'un calcul qui n'en a pas rendu, et la cause de
/// l'échec n'était qu'au journal.
pub(crate) const CAUSE_ECHEC_DU_PANNEAU_NON_ECRIT: &str = "CALCUL DU PANNEAU EN ÉCHEC, ÉCHEC NON ÉCRIT : le dernier calcul \
     de ce panneau a échoué et la base a refusé d'écrire cet échec dans le cache — ce n'est PAS une mesure en cours. RIEN \
     n'est servi ; un nouveau calcul est armé au plus une fois par durée du cache. Cause du calcul : ";

pub(crate) const CAUSE_RESULTAT_DU_PANNEAU_NON_ECRIT: &str = "RÉSULTAT DU PANNEAU NON ÉCRIT : la base a refusé d'écrire \
     dans le cache le résultat du dernier calcul de ce panneau — ce n'est PAS une mesure en cours. RIEN n'est servi ; un \
     nouveau calcul est armé au plus une fois par durée du cache. Si le refus persiste, la base est pleine ou en lecture \
     seule.";

/// `P10.32-o` (vague BH) — une charge en cache SERVABLE comme résultat : un objet JSON sans `error` (un corps d'échec n'en
/// est pas un) dont `stats`, s'il existe, est un objet (un aveu peut y être posé). Une ligne absente, illisible, un texte
/// qui n'est pas du JSON ou un corps d'échec ne le sont pas.
fn charge_utile_servable(v: &Value) -> bool {
    v.is_object() && v.get("error").is_none() && v.get("stats").map_or(true, Value::is_object)
}

/// Pose `stats.rafraichissement_en_echec` (`{cause, echoue_a}`) sur une charge SERVABLE (`charge_utile_servable`), au
/// service seulement : la ligne de cache n'est pas réécrite.
fn poser_l_aveu_au_service(v: &mut Value, cause: &str, echoue_a: i64) {
    v["stats"][CHAMP_DU_RAFRAICHISSEMENT_EN_ECHEC] = json!({ "cause": cause, "echoue_a": echoue_a });
}

/// PHASE 3d — sert un panneau en SWR (stale-while-revalidate), logique EXACTE de 3c : HIT cache (frais OU
/// périmé) -> service IMMÉDIAT + refresh ASYNC borné (refresh_sem, JAMAIS query_sem) si périmé ; MISS ->
/// enqueue refresh + JSON VALIDE « warming » non bloquant. Utilisé par (a) le chemin LOURD (coût >= seuil)
/// et (b) le FALLBACK du chemin CHEAP/LIVE quand la lane refresh_sem est saturée (jamais de blocage).
/// Pré-conditions (vérifiées par l'appelant) : cacheable && ttl>0.
///
/// `P10.5-i` — CE QUE LA RE-ESTAMPE NE FAIT PAS, ET C'EST LA PROPRIÉTÉ. `cache_range_key` clé sur la
/// DURÉE quantifiée : un payload calculé à T0 sur [T0−24 h, T0] est LÉGITIMEMENT servi à T0+n. On NE
/// recalcule donc PAS `coverage.searched_from` sur le `from` courant — ce serait le seul champ frais
/// d'une réponse périmée, et il se lit comme un certificat. Seul l'horizon est re-confronté, et il le
/// DIT (`horizon_perime`). Les corps synthétiques (repli de parsing, ligne de cache illisible, ligne de cache non lue
/// servie en 503, écriture du cache refusée servie en 503, MISS `warming`) reçoivent eux aussi un `stats.coverage` : un
/// corps sans lignes qui ne dit rien se relit comme une absence établie.
pub(crate) fn serve_swr(
    st: &AppState, au: &AuthUser, conf: &HashMap<String, String>, id: i64, query: &str, is_soql: bool, from: i64, to: i64,
    range_key: &str, q_fp: &str, ttl: i64, ttl_global: i64, now_s: i64, env: Option<&str>,
) -> Response {
    let (cached, refus_d_ecriture) = {
        // lecture cache SANS prédicat de fraîcheur : on récupère payload + computed_at quel que soit l'âge.
        let __rc = req_db(st, au);
        let conn = __rc.lock();
        // `P10.32-o` (vague BH) — et, sur la même base, l'instant du dernier refus d'écrire cette ligne (`None` si la
        // dernière écriture tentée a réussi) : voir `reessai_permis` plus bas.
        (panneau_avoue::cache_lire_dit(&conn, id, range_key, q_fp), panneau_avoue::refus_d_ecriture_de_cache(&conn, id, range_key, q_fp))
    };
    let ecriture_refusee_a = refus_d_ecriture.as_ref().map(|r| r.refusee_a);
    // `P10.32-o` (vague BH, correction) — la phrase servie de l'échec du calcul quand l'écriture refusée portait un ÉCHEC
    // (corps d'échec ou aveu joint), `None` quand elle portait un résultat : le 503 et l'aveu disent l'un ou l'autre.
    let echec_non_ecrit = refus_d_ecriture.and_then(|r| r.echec_du_calcul);
    // `P10.32-o` (vague BH) — LE RÉARMEMENT APRÈS UNE ÉCRITURE REFUSÉE EST BORNÉ. Avant, une base qui refusait d'écrire le
    // cache (disque plein, lecture seule) laissait la ligne absente ou périmée : chaque interrogation réarmait un calcul qui
    // réussissait, puis dont l'écriture était refusée, sans fin. Un nouveau calcul n'est armé qu'une fois la durée du cache
    // écoulée depuis le dernier refus ; le succès de l'écriture efface le refus et rend le mécanisme ordinaire.
    let reessai_permis = ecriture_refusee_a.map_or(true, |refusee_a| now_s - refusee_a > ttl);
    // COMPILÉ UNE SEULE FOIS, POUR TOUTES LES BRANCHES, ET AVANT DE JUGER LA LIGNE LUE. La compilation est PURE (aucune
    // lecture disque) ; elle sert (a) à re-confronter l'horizon du payload servi — la portée n'est écrite QUE dans le SQL
    // — (b) à armer le rafraîchissement, et (c) à dire, sur une ligne ILLISIBLE, si le refus du compilateur doit être
    // montré. Compilation en erreur -> `None` : on ne re-estampe rien (ce qui a été mesuré à l'écriture reste ce qui est
    // dit) et on n'arme rien, exactement comme avant.
    // `P10.32-o` — SUR UN MISS, LA COMPILATION REFUSÉE EST RENDUE, PLUS TUE : le `.ok()` d'origine en
    // faisait un corps `warming` servi à chaque interrogation, sans rien armer, donc sans fin — alors que
    // le chemin LIVE rend `bad_req` pour la même compilation. La cause est gardée pour la branche MISS.
    let compile = panneau_avoue::compile_panneau_avoue(query, is_soql, from, to, env);
    let (pc, refus_de_compilation) = match compile {
        Ok(pc) => (Some(pc), None),
        Err(e) => (None, Some(e)),
    };
    // `P10.32-o` — UNE LIGNE NON LUE OU ILLISIBLE N'EST JAMAIS SERVIE COMME UNE CHAUFFE. Avant, toutes deux partaient en MISS
    // (corps `warming`) : la console affichait « mesure en cours » sous une notice qui disait le contraire. Désormais :
    //  * NON LUE (lecture refusée) : un refus de lecture nommé en 503 (`CAUSE_LIGNE_DE_CACHE_DU_PANNEAU_NON_LUE`, avec
    //    l'identifiant de corrélation, la raison `cache_non_lu` et sa notice), rafraîchissement armé si le panneau compile.
    //    Jugée AVANT le refus du compilateur : la ligne non lue peut porter une charge utile valide, que le HIT sert même
    //    quand le panneau ne compile plus — on ne sait donc pas ce qui aurait été servi, et le 503 le dit ;
    //  * ILLISIBLE (lue, non décodable) : la ligne ne porte rien de servable. Le panneau compile -> le corps synthétique
    //    d'une charge utile illisible (`paye_utile_illisible`, comme la charge qui n'est pas du JSON), sans `warming`, et
    //    le rafraîchissement armé la remplacera. Le panneau ne compile pas -> le refus du compilateur, comme sur une
    //    absence : rien ne remplacera jamais la ligne, et un 200 synthétique servi à chaque interrogation masquait la
    //    seule cause actionnable (vague BF : `paye_utile_illisible` sans fin, au lieu du 400 servi sur b29051c4).
    // Chaque ligne de journal nomme le tenant de l'appelant (`{:?}`), jamais la requête.
    let mut ligne_ratee = LigneDeCacheRatee::Aucune;
    let cached = match cached {
        panneau_avoue::LectureDeCache::Lue(payload, calcule_a) => Some((payload, calcule_a)),
        panneau_avoue::LectureDeCache::Absente => None,
        panneau_avoue::LectureDeCache::Illisible(cause) => {
            if refus_de_compilation.is_some() {
                eprintln!(
                    "[panel] WARN ligne de cache ILLISIBLE (lue, non décodable), panneau #{id}, tenant {:?} : {cause} — le \
                     panneau ne compile pas : le refus du compilateur est servi (400), rien n'est armé, la ligne reste telle \
                     quelle",
                    au.tenant
                );
            } else if ecriture_refusee_a.is_some() {
                // `P10.32-o` (vague BJ, correction) — UNE ÉCRITURE REFUSÉE EST NOTÉE POUR CETTE LIGNE : le 503 nommé de
                // l'écriture refusée est servi plus bas (la ligne illisible ne porte aucune charge servable), pas le corps
                // `paye_utile_illisible`, et le réarmement suit `reessai_permis`. Avant, cette ligne annonçait le corps
                // synthétique et un rafraîchissement armé, puis la ligne suivante disait le 503 et « aucun calcul armé ».
                eprintln!(
                    "[panel] WARN ligne de cache ILLISIBLE (lue, non décodable), panneau #{id}, tenant {:?} : {cause} — une \
                     écriture refusée est notée pour cette ligne : le refus nommé de l'écriture est servi (503, ligne \
                     suivante), pas la charge illisible",
                    au.tenant
                );
            } else {
                eprintln!(
                    "[panel] WARN ligne de cache ILLISIBLE (lue, non décodable), panneau #{id}, tenant {:?} : {cause} — servie comme \
                     une charge utile illisible (corps synthétique `paye_utile_illisible`, sans `warming`), rafraîchissement armé si \
                     le panneau compile, qui la remplacera",
                    au.tenant
                );
            }
            ligne_ratee = LigneDeCacheRatee::Illisible;
            None
        }
        panneau_avoue::LectureDeCache::NonLue(cause) => {
            let cid = crate::identifiant_de_correlation();
            eprintln!(
                "[{cid}] [panel] WARN ligne de cache NON LUE, panneau #{id}, tenant {:?} : {cause} — refus de lecture nommé \
                 servi en 503 (sans `warming`), rafraîchissement armé si le panneau compile",
                au.tenant
            );
            ligne_ratee = LigneDeCacheRatee::NonLue(cid);
            None
        }
    };
    // `P10.29-l` (vague AS) — UN CORPS D'ÉCHEC D'UNE VERSION ANTÉRIEURE N'EST PLUS SERVI : son `error` peut porter le
    // texte du moteur, et le cache est rôle-agnostique. Il est traité comme une absence (MISS : `warming`, puis un
    // rafraîchissement qui écrit la phrase de sa classe).
    let cached = cached.filter(|(payload, _)| !corps_d_echec_d_une_version_anterieure(payload));
    let db_path = req_db_path(st, au);
    // L'HORIZON D'UN CORPS SYNTHÉTIQUE : mesuré quand la portée est dérivable, `None` sinon. Il n'est
    // calculé que sur les deux branches qui fabriquent un corps sans ligne — jamais sur un HIT lisible,
    // où c'est la re-estampe qui parle.
    let horizon_courant = |pc: Option<&PanneauCompile>| pc.map(|pc| panneau_avoue::horizon(&db_path, conf, pc, from));
    // `P10.32-o` (vague BH) — AUCUNE CHARGE SERVABLE EN CACHE ET LA DERNIÈRE ÉCRITURE DE LA LIGNE REFUSÉE : un refus nommé
    // en 503 (`CAUSE_RESULTAT_DU_PANNEAU_NON_ECRIT`, raison `cache_non_ecrit`), jamais `warming` / `mesure_en_cours`. Avant,
    // une base qui refusait d'écrire laissait la ligne absente : le MISS servait une chauffe à chaque interrogation, et le
    // calcul réarmé réussissait sans que rien ne soit jamais écrit. Jugé APRÈS la ligne NON LUE (on ne sait pas ce qu'elle
    // porte) et APRÈS le refus du compilateur (la cause actionnable, servie plus bas en 400) ; couvre l'absence, la ligne
    // illisible, le texte qui n'est pas du JSON et le corps d'échec. Le nouveau calcul n'est armé que si `reessai_permis`.
    // `charge_servable` est une fermeture appelée en dernier dans la garde du bras `Some` : la charge n'est décodée ici
    // que si un refus d'écriture est noté pour cette ligne (gain de coût seul, rien de servi ne change).
    let charge_servable =
        || cached.as_ref().is_some_and(|(payload, _)| serde_json::from_str::<Value>(payload).is_ok_and(|v| charge_utile_servable(&v)));
    let non_lue = matches!(ligne_ratee, LigneDeCacheRatee::NonLue(_));
    match ecriture_refusee_a {
        Some(refusee_a) if !non_lue && refus_de_compilation.is_none() && !charge_servable() => {
            let cid = crate::identifiant_de_correlation();
            let geste = if reessai_permis { "nouveau calcul armé" } else { "aucun calcul armé avant l'expiration du cache" };
            let quoi = if echec_non_ecrit.is_some() { "échec du dernier calcul" } else { "résultat du dernier calcul" };
            eprintln!(
                "[{cid}] [panel] WARN {quoi} NON ÉCRIT au cache (refus à {refusee_a}), panneau #{id}, tenant \
                 {:?} — aucune charge servable en cache : refus nommé servi en 503 (sans `warming`), {geste}",
                au.tenant
            );
            // L'échec non écrit est servi comme un échec (sa phrase, raison `calcul_echoue`), pas comme un résultat perdu.
            let (cause, raison) = match &echec_non_ecrit {
                Some(servie) => (format!("{CAUSE_ECHEC_DU_PANNEAU_NON_ECRIT}{servie}"), panneau_avoue::RAISON_CALCUL_ECHOUE),
                None => (CAUSE_RESULTAT_DU_PANNEAU_NON_ECRIT.to_string(), panneau_avoue::RAISON_CACHE_NON_ECRIT),
            };
            let mut v = json!({ "columns": [], "rows": [], "error": cause, "id": cid });
            v["stats"]["coverage"] = panneau_avoue::coverage_synthetique(raison, from, now_s, horizon_courant(pc.as_ref()));
            match pc {
                Some(pc) if reessai_permis => {
                    enqueue_panel_refresh(st, au, id, range_key.to_string(), q_fp.to_string(), pc, from, ttl_global, conf.clone())
                }
                _ => {}
            }
            return (StatusCode::SERVICE_UNAVAILABLE, Json(v)).into_response();
        }
        _ => {}
    }
    match cached {
        Some((payload, computed_at)) => {
            // HIT (frais OU périmé) -> service IMMÉDIAT. Si périmé : refresh async (hors query_sem).
            let perimee = now_s - computed_at > ttl;
            let v = match serde_json::from_str::<Value>(&payload) {
                Ok(mut v) => {
                    // La classe d'un corps d'échec sert au tri ci-dessus, pas au client : le corps servi garde sa forme.
                    if let Some(o) = v.as_object_mut() {
                        o.remove(MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC);
                    }
                    // `P10.32-o` (vague BH) — UNE CHARGE PÉRIMÉE D'UN PANNEAU QUI NE COMPILE PLUS (même requête, compilateur
                    // ou macro durcis depuis l'écriture) n'est plus servie indéfiniment sans un mot : rien ne peut la
                    // rafraîchir (`pc` est `None`, rien n'est armé). Une charge SERVABLE reste servie, le refus du
                    // compilateur joint sous `stats.rafraichissement_en_echec` (instant du service) ; un corps d'échec,
                    // qui ne porte rien de servable, cède la place au refus du compilateur (400), comme une absence.
                    // Une charge FRAÎCHE est servie telle quelle jusqu'à son expiration.
                    let servable = charge_utile_servable(&v);
                    let refus_joint = match &refus_de_compilation {
                        Some(e) if perimee && !servable => {
                            eprintln!(
                                "[panel] WARN panneau #{id}, tenant {:?} : corps d'échec périmé en cache, le panneau ne compile \
                                 plus — le refus du compilateur est servi (400), la ligne reste telle quelle",
                                au.tenant
                            );
                            return bad_req(e.clone());
                        }
                        Some(e) if perimee => {
                            // `P10.32-o` (vague BK) — LA LIGNE EST BORNÉE : au plus une par panneau de cette base et par
                            // durée du cache du panneau (`dire_la_peremption_non_compilable`, registre de processus borné),
                            // comme le pré-chauffage qui se tait pour ce panneau. Le corps servi ne change pas.
                            if panneau_avoue::dire_la_peremption_non_compilable(&req_db(st, au).lock(), id, now_s, ttl) {
                                eprintln!(
                                    "[panel] WARN panneau #{id}, tenant {:?} : charge utile périmée servie, le panneau ne compile \
                                     plus — refus du compilateur joint au corps (`stats.{CHAMP_DU_RAFRAICHISSEMENT_EN_ECHEC}`), aucun \
                                     calcul armé",
                                    au.tenant
                                );
                            }
                            poser_l_aveu_au_service(&mut v, e, now_s);
                            true
                        }
                        _ => false,
                    };
                    // `P10.32-o` (vague BH) — LA DERNIÈRE ÉCRITURE DE LA LIGNE A ÉTÉ REFUSÉE : la charge servie n'est pas
                    // celle du dernier calcul ; elle le dit (`CAUSE_ECRITURE_DU_CACHE_REFUSEE`, instant du refus). Le refus
                    // du compilateur, joint plus haut, l'emporte : c'est lui qui empêche tout calcul.
                    match ecriture_refusee_a {
                        Some(refusee_a) if servable && !refus_joint => match &echec_non_ecrit {
                            // `P10.32-o` (correction) — l'écriture refusée portait l'échec du calcul : il est dit, avec sa
                            // phrase, à l'instant de la tentative.
                            Some(servie) => poser_l_aveu_au_service(
                                &mut v, &format!("{}{servie}", panneau_avoue::CAUSE_ECHEC_DU_CALCUL_NON_ECRIT_AU_CACHE), refusee_a,
                            ),
                            None => poser_l_aveu_au_service(&mut v, panneau_avoue::CAUSE_ECRITURE_DU_CACHE_REFUSEE, refusee_a),
                        },
                        _ => {}
                    }
                    panneau_avoue::cache_reestamper(&mut v, &db_path, conf, pc.as_ref(), computed_at, now_s);
                    v
                }
                Err(_) => {
                    // `P10.32-o` (vague BG, correction) — UNE CHARGE TEXTE QUI N'EST PAS DU JSON NE PORTE RIEN DE SERVABLE,
                    // comme la ligne ILLISIBLE plus haut : si le panneau ne compile pas, rien ne la remplacera jamais, et
                    // un 200 `paye_utile_illisible` servi à chaque interrogation masquait le refus du compilateur. On rend
                    // donc ce refus (le même que le chemin live et qu'une absence) ; la ligne reste telle quelle.
                    if let Some(e) = refus_de_compilation {
                        return bad_req(e);
                    }
                    let mut v = json!({ "columns": [], "rows": [] });
                    v["stats"]["coverage"] = panneau_avoue::coverage_synthetique(
                        panneau_avoue::RAISON_PAYE_UTILE_ILLISIBLE, from, now_s, horizon_courant(pc.as_ref()),
                    );
                    v
                }
            };
            // `P10.32-o` (vague BH) — après une écriture refusée, au plus un calcul par durée du cache (`reessai_permis`).
            if perimee && reessai_permis {
                if let Some(pc) = pc {
                    enqueue_panel_refresh(st, au, id, range_key.to_string(), q_fp.to_string(), pc, from, ttl_global, conf.clone());
                }
            }
            Json(v).into_response()
        }
        None => {
            // L'ORDRE DES BRAS EST LA PROPRIÉTÉ (`P10.32-o`) : NON LUE, puis le refus du compilateur, puis ILLISIBLE, puis le
            // MISS. Voir le commentaire de la lecture plus haut. L'écriture refusée (vague BH) a déjà été servie en 503 avant ce
            // `match`, entre le refus du compilateur et ILLISIBLE : ici, aucun refus d'écriture n'est noté.
            if let LigneDeCacheRatee::NonLue(cid) = ligne_ratee {
                let mut v = json!({ "columns": [], "rows": [], "error": CAUSE_LIGNE_DE_CACHE_DU_PANNEAU_NON_LUE, "id": cid });
                v["stats"]["coverage"] = panneau_avoue::coverage_synthetique(
                    panneau_avoue::RAISON_LIGNE_DE_CACHE_NON_LUE, from, now_s, horizon_courant(pc.as_ref()),
                );
                if let Some(pc) = pc {
                    enqueue_panel_refresh(st, au, id, range_key.to_string(), q_fp.to_string(), pc, from, ttl_global, conf.clone());
                }
                return (StatusCode::SERVICE_UNAVAILABLE, Json(v)).into_response();
            }
            // `P10.32-o` : le MÊME refus que le chemin live, avec la cause du compilateur — sur une absence comme sur une
            // ligne illisible.
            if let Some(e) = refus_de_compilation {
                return bad_req(e);
            }
            if matches!(ligne_ratee, LigneDeCacheRatee::Illisible) {
                let mut v = json!({ "columns": [], "rows": [] });
                v["stats"]["coverage"] = panneau_avoue::coverage_synthetique(
                    panneau_avoue::RAISON_PAYE_UTILE_ILLISIBLE, from, now_s, horizon_courant(pc.as_ref()),
                );
                if let Some(pc) = pc {
                    enqueue_panel_refresh(st, au, id, range_key.to_string(), q_fp.to_string(), pc, from, ttl_global, conf.clone());
                }
                return Json(v).into_response();
            }
            // MISS total (jamais réchauffé) -> refresh async + JSON VALIDE non bloquant « warming ».
            // L'HORIZON EST MESURÉ AVANT L'ARMEMENT : la tâche de rafraîchissement CONSOMME le panneau
            // compilé, et la portée ne se lit que dans son SQL.
            let mut v = json!({ "columns": [], "rows": [], "warming": true });
            v["stats"]["coverage"] = panneau_avoue::coverage_synthetique(
                panneau_avoue::RAISON_MESURE_EN_COURS, from, now_s, horizon_courant(pc.as_ref()),
            );
            if let Some(pc) = pc {
                enqueue_panel_refresh(st, au, id, range_key.to_string(), q_fp.to_string(), pc, from, ttl_global, conf.clone());
            }
            Json(v).into_response()
        }
    }
}

pub(crate) async fn panel_data(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Query(q): Query<HashMap<String, String>>) -> Response {
    let from: i64 = q.get("from").and_then(|s| s.parse().ok()).unwrap_or(0);
    let to: i64 = q.get("to").and_then(|s| s.parse().ok()).unwrap_or(0);
    let info = {
        crate::req_conn!(st, au, conn);
        panel_access(&conn, &au, id)
    };
    // `P10.20-l` (vague AJ) — une lecture ratée n'est pas un refus de droit : 503 nommé, rien n'est exécuté.
    let (query, is_soql, _window, _owns) = match info {
        Ok(Some(acces)) => acces,
        Ok(None) => return forbidden("panneau inaccessible"),
        Err(e) => {
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_PANNEAU_NON_LU);
            eprintln!("[dashboards] WARN panneau #{id} NON lu pour l'exécution, rien n'est servi ({}) : {e}", cid.unwrap_or_default());
            return refus;
        }
    };
    // PHASE 3d — CLASSIFICATION ADAPTATIVE PAR PANNEAU (par COÛT MESURÉ, PAS par vue). panel_data est appelé
    // par panel_id -> le coût stocké (clé panel_id+query_fp) classe le panneau GLOBALEMENT, où qu'il soit
    // rendu. INVARIANT 3c CONSERVÉ : ni le LIVE ni le refresh ne prennent JAMAIS un permit query_sem
    // (réservé à /api/query + /api/search) -> sem_wait interactif ~0.
    //   - LOURD (coût CONNU >= PLUME_PANEL_LIVE_MS) OU INCONNU (jamais mesuré) -> SWR (3c) : sert panel_cache
    //     + refresh async si périmé ; à froid (MISS) renvoie un payload `warming` non bloquant + mesure async.
    //     (FIX #5c : un panneau inconnu ne part PLUS en LIVE synchrone -> plus de time-out proxy à froid.)
    //   - CHEAP CONFIRMÉ (coût MESURÉ < seuil) -> LIVE : requête à la demande sur la lane refresh_sem
    //     (try_acquire borné, zéro attente) -> toujours frais (un indicateur mono-valeur bascule à l'instant) ;
    //     lane saturée -> fallback cache (SWR) -> ne BLOQUE JAMAIS. Mesure + mémorise le coût à CHAQUE
    //     exécution -> auto-reclassement (un cheap qui ralentit passe SWR, et inversement).
    // range_key est clé sur la DURÉE de fenêtre (cf. cache_range_key) ; q_fp lie au COUPLE (requête, is_soql).
    let now_s = now();
    // FILTRE ENVIRONNEMENT (#2d) : env demandé (None en mode 0) -> injecté dans le SQL (compile_panneau_avoue)
    // ET dans la clé de plage du cache (env_range_key) -> payloads par-env SÉPARÉS, jamais de collision.
    let env = au.env_filter();
    // HORS LOCK, ET UNE SEULE FOIS POUR TOUS LES CHEMINS (`P10.5-i`) : `load_config()` fait un accès
    // DISQUE non mémoïsé. Il est remonté AVANT la bascule masquée parce que l'aveu d'horizon en a besoin
    // sur les DEUX chemins ; le compte par requête reste UN, celui que ce fichier s'impose déjà.
    let conf = load_config();
    let (ttl_global, live_threshold) = panel_serve_cfg_de(&conf);
    // FIELD FILTERS (#45) : le cache rendu est clé par (panel_id, range) SANS le rôle -> un blob mis en cache
    // NE PEUT PAS servir des vues différentes selon le rôle. Si l'appelant a des masques ACTIFS, on NE TOUCHE
    // donc PAS le cache (ni lecture ni écriture) : compilation masquée + exécution LIVE hors cache. VIDE
    // (mode 0 / admin sans règle) -> chemin cache/SWR historique STRICTEMENT INCHANGÉ (byte-identique).
    let masks = effective_masks(req_db_path(&st, &au).as_str(), &au.role, &au.tenant, env);
    if !masks.is_empty() {
        return panel_data_masked_live(&st, &au, &conf, &query, is_soql, from, to, env, &masks).await;
    }
    let q_fp = query_fingerprint(&query, is_soql);
    let cacheable = to == 0 || (from > 0 && to > from); // fenêtre glissante OU plage absolue bornée
    let range_key = env_range_key(env, &cache_range_key(from, to, now_s));
    // TTL effectif + coût mesuré stocké (par panneau) — 1 prise de lock.
    let (ttl, cost) = {
        crate::req_conn!(st, au, conn);
        // `P10.20-l` (vague AK) — UN TTL NON LU N'EST PAS UN CACHE COUPÉ. Le repli `0` de `panel_cache_ttl` écartait le
        // chemin SWR (`ttl > 0` exigé) : le panneau partait en exécution directe, et SANS permis quand la lane de
        // rafraîchissement était saturée (branche « cache off ET lane saturée », plus bas). Une lecture ratée ouvrait
        // ainsi une charge non bornée. Elle rend désormais le 503 nommé `CAUSE_PANNEAU_NON_LU`, AVANT toute compilation
        // ni exécution ; la cause du moteur va au journal avec l'identifiant servi, jamais la requête ni un nom.
        // Un TTL LÉGITIMEMENT nul (colonne ou global à 0) garde la branche sans permis, conception d'avant.
        let ttl = match lire_le_ttl_du_cache(&conn, id, ttl_global) {
            Ok(ttl) => ttl,
            Err(e) => {
                let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_PANNEAU_NON_LU);
                eprintln!("[dashboards] WARN panneau #{id} : TTL du cache NON lu, rien n'est exécuté ({}) : {e}", cid.unwrap_or_default());
                return refus;
            }
        };
        let cout = match read_panel_cost(&conn, id, &q_fp) {
            Ok(c) => c,
            Err(_) => {
                // `P10.20-l` (vague AJ) — servi comme un panneau jamais mesuré (le comportement d'avant), mais DIT.
                eprintln!("[dashboards] WARN panneau #{id} : coût non lu, le panneau est servi comme jamais mesuré");
                None
            }
        };
        (ttl, cout)
    };
    // LOURD = coût CONNU et >= seuil.
    let heavy = matches!(cost, Some(c) if c >= live_threshold as f64);
    // FIX #5c — coût INCONNU (jamais mesuré) : on NE PRÉSUME PLUS « cheap ». Un panneau jamais mesuré peut
    // être LOURD (source brute volumineuse) -> un LIVE SYNCHRONE à froid risque de dépasser le timeout du
    // proxy = corps vide « réponse vide ». On le sert donc en SWR/WARMING (renvoie {columns:[],rows:[],
    // warming:true} + mesure ASYNC) tant qu'il est cacheable : le coût mesuré au 1er refresh le CLASSE
    // ensuite (CHEAP confirmé -> LIVE instantané ; LOURD -> reste en SWR). Un panneau lourd à froid ne
    // time-out donc JAMAIS de façon synchrone. (Le front gère le flag `warming` + re-poll.)
    let unknown = cost.is_none();

    // ---- LOURD (connu) ou INCONNU (1re fois) : SWR (3c). Sert le cache + refresh async ; ne lance JAMAIS
    //      de live synchrone. ----
    if (heavy || unknown) && cacheable && ttl > 0 {
        return serve_swr(&st, &au, &conf, id, &query, is_soql, from, to, &range_key, &q_fp, ttl, ttl_global, now_s, env);
    }

    // ---- CHEAP / INCONNU (et le cas résiduel LOURD non-cacheable / cache off) : LIVE MESURÉ. ----
    // La requête tourne à la demande -> toujours frais. Lane refresh_sem UNIQUEMENT (jamais query_sem).
    // try_acquire_owned (borné, zéro attente) : si la lane est saturée, on NE BLOQUE PAS -> fallback cache.
    let pc = match panneau_avoue::compile_panneau_avoue(&query, is_soql, from, to, env) {
        Ok(s) => s,
        Err(e) => return bad_req(e),
    };
    match st.refresh_sem.clone().try_acquire_owned() {
        Ok(permit) => {
            let db_path = req_db_path(&st, &au);
            let conf_live = conf.clone();
            let res = tokio::task::spawn_blocking(move || crate::query_exec::en_classant(|| panneau_avoue::executer(&db_path, &conf_live, pc, from))).await;
            drop(permit); // relâche la lane refresh dès la requête finie (avant l'écriture coût/cache)
            match res {
                Ok(Ok(v)) => {
                    // MESURE : coût SQL de CETTE exécution -> mémorisé par panneau (auto-reclassement).
                    let cost_ms = measured_cost_ms(&v);
                    {
                        crate::req_conn!(st, au, conn);
                        if let Some(c) = cost_ms {
                            record_panel_cost(&conn, id, &q_fp, c, now_s);
                        }
                        // peuple aussi le cache rendu -> un futur fallback (lane saturée) sert du frais récent.
                        // `P10.32-o` — `Value::to_string`, infaillible, mêmes octets : le cache n'est plus sauté sans un mot.
                        // `P10.32-o` (vague BH) — le refus de l'écriture est noté par le coffre et dit ici (la réponse, elle,
                        // est servie fraîche) : un repli SWR ultérieur le lira au lieu de servir une chauffe.
                        if cacheable && ttl > 0 {
                            if let Err(e) = panneau_avoue::cache_ecrire_dit(&conn, id, &range_key, &q_fp, now_s, &v.to_string()) {
                                eprintln!(
                                    "[panel] WARN panneau #{id}, tenant {:?} : résultat servi en direct NON ÉCRIT au cache ({e})",
                                    au.tenant
                                );
                            }
                        }
                    }
                    Json(v).into_response()
                }
                // `P10.29-l` (vague AS) — la phrase de la classe, jamais le texte du moteur (même refus que `/api/query`).
                Ok(Err(e)) => crate::handlers::query::refus_de_requete(e, ROUTE_DES_DONNEES_DE_PANNEAU, &au.tenant),
                Err(_) => server_err("exécution échouée"),
            }
        }
        Err(_) => {
            // lane refresh SATURÉE -> NE JAMAIS BLOQUER. Fallback cache (SWR) si dispo.
            if cacheable && ttl > 0 {
                serve_swr(&st, &au, &conf, id, &query, is_soql, from, to, &range_key, &q_fp, ttl, ttl_global, now_s, env)
            } else {
                // cache off ET lane saturée (rare) : dernier recours -> live SANS permit (jamais query_sem),
                // identique à l'ancien fallback 3c. Chemin dégradé exceptionnel (pas de mesure ici).
                // `P10.5-i` : ce QUATRIÈME point d'exécution passe lui aussi par le coffre — c'est celui que
                // le cadrage avait manqué, et une garde taillée pour trois l'aurait laissé dehors.
                let db_path = req_db_path(&st, &au);
                match tokio::task::spawn_blocking(move || crate::query_exec::en_classant(|| panneau_avoue::executer(&db_path, &conf, pc, from))).await {
                    Ok(Ok(v)) => Json(v).into_response(),
                    Ok(Err(e)) => crate::handlers::query::refus_de_requete(e, ROUTE_DES_DONNEES_DE_PANNEAU, &au.tenant),
                    Err(_) => server_err("exécution échouée"),
                }
            }
        }
    }
}

/// FIELD FILTERS (#45) — chemin panneau pour un appelant AVEC masques actifs : HORS cache (le panel_cache est
/// rôle-agnostique). Panneaux GXQL -> compilation MASQUÉE (masque émis dans le SQL, avant agrégation ; rollup
/// désactivé car event_rollup porte src_ip/host en clair). Panneaux SQL BRUT (is_soql=0, opaques : impossible
/// d'injecter le masque) -> exécution puis MASQUAGE POST-REQUÊTE par nom de colonne (défense : caviarde une
/// colonne projetée directement, ex `SELECT src_ip …`). Toujours LIVE (jamais mis en cache) -> aucune fuite
/// inter-rôles via le cache partagé.
///
/// CE QU'ELLE NE PREND PAS (`P10.5-i`) : aucun permit — ni `query_sem`, ni `refresh_sem`. Elle
/// s'exécute directement sur `spawn_blocking`. LA PROPRIÉTÉ EST ÉNONCÉE SANS NOMBRE, ET C'EST LE
/// CORRECTIF (`P10.18-a`, mesuré le 2026-08-30) : la rédaction précédente adossait cette phrase à un
/// COMPTE d'acquisitions du module. Ce compte comptait des occurrences de TEXTE — les mentions en prose
/// des commentaires voisins comprises — là où seuls les APPELS engagent quelque chose, et un chiffre
/// gravé dans un commentaire redevient faux au lot suivant sans que rien ne le signale. La propriété
/// tenue est donc : AUCUNE acquisition de permis de ce module ne se trouve dans le corps de cette
/// fonction. Elle est DÉRIVÉE de ce fichier par
/// `tests::chemin_masque_sans_permis::aucune_acquisition_de_permis_dans_le_chemin_masque`, qui blanchit
/// les commentaires et les littéraux avant de compter, et dont l'instrument est validé sur des corpus
/// fabriqués — pas sur l'arbre.
///
/// ET CE QUE ÇA COÛTE, PUISQU'ELLE N'EN PREND PAS. Ses deux voisines de ce module prennent le permis de
/// rafraîchissement SANS attente et retombent sur le cache quand la lane est saturée. Ce chemin-ci est
/// HORS cache (le `panel_cache` est rôle-agnostique) : il n'a AUCUN repli, donc un `try_acquire` qui
/// échouerait y deviendrait un REFUS servi et non une réponse plus vieille — prendre le permis
/// changerait ce que l'appelant REÇOIT. La borne qui subsiste est celle du pool `spawn_blocking` du
/// runtime, que `main.rs` ne configure pas : le défaut de la dépendance (512 fils, tokio 1.53.0, lu le
/// 2026-08-30). Sous un budget de 2 Gio, ce n'est pas une borne utile, et c'est écrit ici plutôt que
/// sous-entendu. Ce qui rend le chemin tenable AUJOURD'HUI n'est pas sa rareté mais sa PORTE :
/// `panel_data` en est le seul appelant, sous `!masks.is_empty()` — la concurrence de ce chemin vaut
/// donc le nombre de requêtes de panneau simultanées émises par des rôles À MASQUES ACTIFS, et rien
/// d'autre ne la borne. Le jour où un rôle masqué devient le cas courant, il ne reste plus de borne :
/// c'est `P10.18-a`, qui reste OUVERT et n'est PAS fermé par ce commentaire.
async fn panel_data_masked_live(
    st: &AppState, au: &AuthUser, conf: &HashMap<String, String>, query: &str, is_soql: bool, from: i64, to: i64,
    env: Option<&str>, masks: &guatx_core::soql::FieldMaskSet,
) -> Response {
    // rollup-route DÉSACTIVÉ (masques actifs) : les DEUX bras du coffre masqué rendent `Provenance::Opaque`.
    let pc = match panneau_avoue::compile_panneau_avoue_masque(query, is_soql, from, to, env, masks) {
        Ok(p) => p,
        Err(e) => return bad_req(e),
    };
    let db_path = req_db_path(st, au);
    let post_mask = !is_soql; // GXQL déjà masqué dans le SQL ; SQL brut -> masquage post-requête (idempotence).
    let dbp2 = db_path.clone();
    let conf2 = conf.clone();
    let run = tokio::task::spawn_blocking(move || crate::query_exec::en_classant(|| panneau_avoue::executer(&dbp2, &conf2, pc, from))).await;
    match run {
        Ok(Ok(mut v)) => {
            // `mask_query_result` ne mute que `v["rows"]` : l'aveu posé dans `stats` lui survit — et c'est
            // MESURÉ par témoin, pas affirmé ici.
            if post_mask {
                mask_query_result(&db_path, masks, &mut v);
            }
            Json(v).into_response()
        }
        Ok(Err(e)) => crate::handlers::query::refus_de_requete(e, ROUTE_DES_DONNEES_DE_PANNEAU, &au.tenant),
        Err(_) => server_err("exécution échouée"),
    }
}

// ---------- vues (ensembles de dashboards) ----------
pub(crate) async fn views_list(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {
    crate::req_conn!(st, au, conn);
    // #64 : autorité admin EFFECTIVE (rôle composable base=admin inclus) bindée en `?1` de visibilité.
    let adm = if au.is_admin() { "admin" } else { "" };
    // `P10.7-f` (rang 4) — LE SÉLECTEUR DE VUES EST ENTIER OU AVOUÉ. Avant : DEUX `unwrap()` (une table
    // retirée sous les pieds du gestionnaire PANIQUAIT au lieu d'avouer) puis `rows.flatten().collect()`,
    // qui jetait la ligne dont le mappeur échoue et servait le reste sous un corps rigoureusement
    // identique à celui d'un sélecteur complet. Une vue avalée disparaît du menu déroulant, et la console
    // s'en sert pour FILTRER la liste des dashboards : l'exploitant conclut « ce regroupement n'existe
    // pas » et en refabrique un second, qui portera le même nom. Soldé en bloc ; sur échec, l'aveu prend
    // la forme du dépôt (`corps_de_liste_illisible` : `views` présente et VIDE, `error` nomme la cause),
    // `me` et `role` restant servis parce qu'ils ne DÉRIVENT PAS de cette lecture (ils viennent de
    // l'identité de l'appelant, et les taire priverait la console de sa garde de partage).
    // `P11.25-f` — `dashboards` compte les RATTACHEMENTS de la vue (`view_dashboard`, qui fait foi depuis v125), pas
    // les tableaux déclarés dans toutes les vues (`all_views`), qui ne sont rattachés à aucune. Vague CB : seuls ceux
    // que l'APPELANT lit (`FILTRE_DES_TABLEAUX_DE_BORD`, le filtre de la liste des tableaux) — un autre compte peut
    // ranger son tableau privé dans une vue commune, et le compte en aurait dit l'existence à chaque lecteur. `?3` vaut
    // `tous` : le filtre de vue de la constante ne joue pas, seule la visibilité du tableau compte.
    let sql_des_vues = format!(
        "SELECT id,name,COALESCE(owner,''),visibility,
                (SELECT COUNT(*) FROM view_dashboard vd JOIN dashboard d ON d.id=vd.dashboard_id
                  WHERE vd.view_id=view.id AND {FILTRE_DES_TABLEAUX_DE_BORD})
         FROM view
         WHERE ?1='admin' OR visibility='shared' OR owner=?2
         ORDER BY id"
    );
    let lues: rusqlite::Result<Vec<Value>> = conn
        .prepare(&sql_des_vues)
        .and_then(|mut stmt| {
            stmt.query_map(params![adm, au.name, "tous", 0_i64], |r| {
                Ok(json!({
                    "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?,
                    "owner": r.get::<_, String>(2)?, "visibility": r.get::<_, String>(3)?,
                    "dashboards": r.get::<_, i64>(4)?
                }))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
        });
    match lues {
        Ok(rows) => Json(json!({ "views": rows, "me": au.name, "role": au.role })),
        Err(_) => Json(crate::handlers::liste_bornee::corps_de_liste_illisible(
            json!({ "me": au.name, "role": au.role }),
            "views",
        )),
    }
}

/// `P11.25-f` — UNE VUE DE CE NOM EXISTE DÉJÀ PARMI CELLES QUE LE CRÉATEUR VOIT : rien n'est créé, et l'identifiant de
/// l'existante est servi à côté (`view_id`) pour que la console la complète au lieu d'en fabriquer une homonyme.
pub(crate) const CAUSE_VUE_DEJA_EXISTANTE: &str = "VUE DÉJÀ EXISTANTE : une vue de ce nom existe déjà parmi celles que \
     vous voyez — rien n'est créé. Complétez-la (POST /api/views/{id}/dashboards) ou choisissez un autre nom.";
/// `P11.25-f` — un renommage vers le nom d'une AUTRE vue que le renommeur voit : rien n'est renommé ni partagé, et
/// l'identifiant de l'existante est servi à côté (`view_id`), comme pour la création.
pub(crate) const CAUSE_VUE_RENOMMEE_VERS_UNE_EXISTANTE: &str = "VUE DÉJÀ EXISTANTE : une autre vue de ce nom existe déjà \
     parmi celles que vous voyez — rien n'est renommé, rien du corps n'est appliqué. Complétez-la (POST \
     /api/views/{id}/dashboards) ou choisissez un autre nom.";
/// `P11.25-f` — la recherche d'une vue homonyme avant un renommage n'a pas eu lieu : rien n'est renommé.
pub(crate) const CAUSE_VUE_INCHANGEE_HOMONYMES_NON_LUS: &str = "VUE INCHANGÉE : la base n'a pas rendu les vues de ce nom \
     — ce n'est PAS « aucune vue de ce nom », c'est une lecture qui n'a pas eu lieu, et le doublon n'est pas jugé. RIEN \
     n'est renommé ni partagé. Réessayez ; si le refus persiste, la table des vues est illisible.";
/// `P11.25-f` — la recherche d'une vue homonyme n'a pas eu lieu : ni doublon ni absence ne sont établis, rien n'est
/// créé. Ne nomme pas une transaction annulée : c'est une lecture qui manque.
pub(crate) const CAUSE_VUE_NON_CREEE_HOMONYMES_NON_LUS: &str = "VUE NON CRÉÉE : la base n'a pas rendu les vues de ce \
     nom — ce n'est PAS « aucune vue de ce nom », c'est une lecture qui n'a pas eu lieu, et le doublon n'est pas jugé. \
     RIEN n'est créé. Réessayez ; si le refus persiste, la table des vues est illisible.";
/// `P11.25-f` — le `COMMIT` de la création refusé (`OUVERTURE_DE_L_ECRITURE_NON_VALIDEE`, web/core.js) : l'identifiant lu
/// au pied de l'insertion n'est pas servi.
pub(crate) const CAUSE_VUE_NON_CREEE_NON_VALIDEE: &str = "VUE NON CRÉÉE : la base n'a pas validé la transaction (COMMIT \
     refusé) et l'a annulée — la vue n'existe pas et AUCUN identifiant n'est rendu. Réessayez ; si le refus persiste, la \
     base est en lecture seule, pleine ou verrouillée.";
/// `P11.25-f` — le `BEGIN` de la création refusé (`OUVERTURE_DE_LA_TRANSACTION_NON_PRISE`, web/core.js).
pub(crate) const CAUSE_VUE_NON_CREEE_TRANSACTION_NON_OUVERTE: &str = "VUE NON CRÉÉE : la base n'a pas pris la \
     transaction de la création (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur l'écrivain) — \
     RIEN n'est écrit. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";

/// `P11.25-f` — LE DOUBLON SE JUGE SOUS LE VERROU D'ÉCRITURE, DANS LA TRANSACTION DE L'INSERTION. Le périmètre est
/// celui que `views_list` montre au créateur (administrateur : toutes ; sinon les vues communes et les siennes) : une
/// vue homonyme qu'il ne voit pas — la vue privée d'un autre compte — n'est pas un doublon pour lui, et la refuser
/// servirait l'identifiant d'une vue privée d'autrui (un oracle). Comparaison du nom à l'identique. Le point de course
/// est posé entre le jugement et l'insertion : un geste concurrent attend l'écrivain, puis voit la vue posée.
pub(crate) async fn view_create(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("Vue").to_string();
    let vis = if b.get("visibility").and_then(|v| v.as_str()) == Some("shared") { "shared" } else { "private" };
    let adm = if au.is_admin() { "admin" } else { "" };
    let db_path = req_db_path(&st, &au);
    crate::req_conn!(st, au, conn);
    let geste = "création d'une vue";
    let tx = match ouvrir_le_garde_du_geste(&conn, "dashboards", geste, CAUSE_VUE_NON_CREEE_TRANSACTION_NON_OUVERTE) {
        Ok(t) => t,
        Err(refus) => return refus,
    };
    let sql_homonyme = "SELECT id FROM view WHERE name=?1 AND (?2='admin' OR visibility='shared' OR owner=?3) ORDER BY id LIMIT 1";
    let homonyme = conn.query_row(sql_homonyme, params![name, adm, au.name], |r| r.get::<_, i64>(0)).optional();
    match homonyme {
        Ok(None) => {}
        Ok(Some(existante)) => {
            drop(tx); // Drop -> ROLLBACK : rien n'a été écrit.
            return (StatusCode::CONFLICT, Json(json!({ "error": CAUSE_VUE_DEJA_EXISTANTE, "view_id": existante }))).into_response();
        }
        Err(e) => {
            drop(tx);
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_VUE_NON_CREEE_HOMONYMES_NON_LUS);
            eprintln!("[dashboards] WARN vues homonymes NON lues, aucune vue créée ({}) : {e}", cid.unwrap_or_default());
            return refus;
        }
    }
    crate::handlers::transaction_validee::point_de_course(&format!("vue-jugee-avant-son-insertion:{db_path}"));
    match conn.execute("INSERT INTO view(name,owner,visibility) VALUES(?1,?2,?3)", params![name, au.name, vis]) {
        Ok(1) => {
            let id = conn.last_insert_rowid();
            rendre_apres_validation_du_garde(tx, &conn, "dashboards", geste, CAUSE_VUE_NON_CREEE_NON_VALIDEE, || Json(json!({ "id": id })).into_response())
        }
        Ok(n) => {
            drop(tx);
            refus_d_un_objet_non_cree("vue", n)
        }
        Err(e) => {
            drop(tx);
            refus_d_un_objet_non_cree_par_le_moteur("vue", &e)
        }
    }
}

/// `P10.20-l` (vague AF) — le propriétaire de la vue n'a pas été lu : le droit n'est pas jugé, rien n'est délié ni
/// supprimé. Ne nomme ni `BEGIN` ni `COMMIT` ni une transaction annulée : c'est la lecture qui manque (refus nommé).
pub(crate) const CAUSE_VUE_NON_SUPPRIMEE_NON_LUE: &str = "VUE NON SUPPRIMÉE : la base n'a pas rendu cette vue (son \
     propriétaire) — ce n'est PAS une absence, c'est une lecture qui n'a pas eu lieu, et le droit de la supprimer n'est \
     pas jugé. RIEN n'est délié ni supprimé : la vue et les tableaux de bord qui y sont rangés sont intacts. Réessayez ; \
     si le refus persiste, la table des vues est illisible.";
/// `P10.20-l` (vague AF) — le détachement des tableaux ou l'effacement de la vue refusé, ou aucune vue effacée : la
/// transaction est annulée (`OUVERTURE_DE_L_ECRITURE_NON_PRISE`, web/core.js).
pub(crate) const CAUSE_VUE_NON_SUPPRIMEE: &str = "VUE NON SUPPRIMÉE : la base n'a pas pris l'effacement de la vue ou le \
     détachement de ses tableaux de bord, ou n'a effacé aucune vue, et la transaction est annulée — la vue existe \
     toujours et les tableaux de bord qui y sont rangés y restent rattachés. Réessayez ; si le refus persiste, la base est \
     en lecture seule, pleine ou verrouillée.";
/// `P10.20-l` (vague AF) — le `BEGIN` de cette suppression refusé (`OUVERTURE_DE_LA_TRANSACTION_NON_PRISE`).
pub(crate) const CAUSE_VUE_NON_SUPPRIMEE_TRANSACTION_NON_OUVERTE: &str = "VUE NON SUPPRIMÉE : la base n'a pas pris la \
     transaction de la suppression (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur \
     l'écrivain) — RIEN n'est écrit : la vue et ses rattachements sont intacts. Réessayez ; s'il est refusé encore, \
     l'écrivain est occupé ou bloqué.";

pub(crate) async fn view_delete(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    crate::req_conn!(st, au, conn);
    // `P10.20-l` (vague AE) — même forme que `dash_delete` : lecture ratée, 503, rien n'est délié ni supprimé. `P10.20-l`
    // (vague AF) — la route rend une `Response` : le 503 porte `CAUSE_VUE_NON_SUPPRIMEE_NON_LUE` en corps, la cause du
    // moteur au journal seul. 403 et 404 restent sans corps.
    // `P11.25-f` (vague CB) — une vue que l'appelant ne VOIT pas (`LA_VUE_EST_VUE_PAR_L_APPELANT`, lu dans la même
    // lecture que le propriétaire) est une vue ABSENTE pour lui : le 404 nu d'un identifiant qu'aucune vue ne porte, rien
    // n'est écrit. Le 403 d'avant disait l'existence de la vue privée d'autrui ; il reste à qui voit la vue sans en être
    // propriétaire (vue commune).
    let adm = if au.is_admin() { "admin" } else { "" };
    let sql = format!("SELECT COALESCE(owner,''),COALESCE({LA_VUE_EST_VUE_PAR_L_APPELANT},0) FROM view WHERE id=?1");
    match conn.query_row(&sql, params![id, adm, au.name], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0))).optional() {
        Ok(Some((_, false))) | Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Some((owner, true))) => {
            // `P11.20-n` — SUPPRIMER EST UN GESTE DE PROPRIÉTAIRE, et une colonne vide n'octroie pas
            // la propriété : l'objet SEMÉ (sans propriétaire) redevient admin-seul à la suppression.
            if !panneau_resolu::autorite_de_proprietaire(&owner, &au) {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
        Err(e) => {
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_VUE_NON_SUPPRIMEE_NON_LUE);
            eprintln!("[dashboards] WARN vue #{id} NON lue pour la suppression, rien n'est délié ni supprimé ({}) : {e}", cid.unwrap_or_default());
            return refus;
        }
    }
    // `P10.20-l` (vague AF) — DÉTACHEMENT ET EFFACEMENT SOUS UN GARDE. La forme d'avant (`let _` puis 204) rendait
    // « supprimée » sur un DELETE refusé, après avoir délié — hors transaction — les tableaux de la vue restée en place.
    // Le détachement (zéro tableau est légitime) puis l'effacement (UNE ligne exigée : la vue vient d'être lue) ; un
    // refus ou un effet nul annule TOUT (Drop -> ROLLBACK), 503 nommé.
    let geste = format!("suppression de la vue #{id}");
    let tx = match ouvrir_le_garde_du_geste(&conn, "dashboards", &geste, CAUSE_VUE_NON_SUPPRIMEE_TRANSACTION_NON_OUVERTE) {
        Ok(t) => t,
        Err(refus) => return refus,
    };
    let ecrit: Result<(), String> = (|| {
        // on délie, on ne supprime pas les dashboards
        conn.execute("UPDATE dashboard SET view_id=NULL WHERE view_id=?1", params![id]).map_err(|e| format!("détachement des tableaux de bord : {e}"))?;
        // `P11.25-f` — et les rattachements de la jointure (zéro est légitime) : laissés, une vue créée ensuite sous le
        // même rowid hériterait des tableaux de l'effacée.
        conn.execute("DELETE FROM view_dashboard WHERE view_id=?1", params![id]).map_err(|e| format!("retrait des rattachements : {e}"))?;
        une_seule_ligne(conn.execute("DELETE FROM view WHERE id=?1", params![id]), "effacement de la vue")
    })();
    if let Err(cause) = ecrit {
        drop(tx); // Drop -> ROLLBACK : les tableaux restent rangés dans la vue.
        return refuser_le_retrait_non_pris(&geste, &cause, CAUSE_VUE_NON_SUPPRIMEE);
    }
    rendre_apres_validation_du_garde(tx, &conn, "dashboards", &geste, CAUSE_VUE_NON_SUPPRIMEE, || StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn view_update(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    crate::req_conn!(st, au, conn);
    // `P10.20-k` (2026-09-16) — RALLIÉ À LA FORME DE SES DEUX VOISINS, BIEN QUE SON REPLI SOIT SÛR.
    // `"private"` fait JOUER la porte `P11.20-m` : aucune publication ne passait ici, et c'est ce site
    // qui servait de CONTRÔLE POSITIF aux deux autres. Mais le refus alors servi est un 409 qui NOMME
    // un élément moins visible — une cause FAUSSE pour une lecture qui n'a pas eu lieu, et une cause
    // fausse n'est pas un fait ; l'appelant en déduit qu'il doit partager un élément, alors qu'il doit
    // réessayer. Propriétaire et visibilité se lisent d'un coup, et la lecture non faite refuse.
    // `P11.25-f` (vague CB) — et ce que l'appelant VOIT de la vue (`LA_VUE_EST_VUE_PAR_L_APPELANT`) dans la MÊME lecture :
    // une vue qu'il ne voit pas est une vue ABSENTE pour lui — le 404 nu d'un identifiant qu'aucune vue ne porte, rien
    // n'est écrit. Le 403 d'avant disait l'existence de la vue privée d'autrui ; il reste à qui voit la vue sans en être
    // propriétaire (vue commune).
    let adm = if au.is_admin() { "admin" } else { "" };
    let sql = format!("SELECT COALESCE(owner,''),COALESCE(visibility,'private'),COALESCE({LA_VUE_EST_VUE_PAR_L_APPELANT},0) FROM view WHERE id=?1");
    let (owner, visibilite): (String, String) = match conn
        .query_row(&sql, params![id, adm, au.name], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? != 0)))
        .optional()
    {
        Ok(Some((owner, visibilite, true))) => (owner, visibilite),
        Ok(Some((_, _, false))) | Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return panneau_resolu::refus_de_visibilite_non_lue(),
    };
    // `P11.20-n` — MODIFIER EST UN GESTE DE PROPRIÉTAIRE, et une colonne vide n'octroie pas la
    // propriété : l'objet SEMÉ (sans propriétaire) redevient admin-seul.
    if !panneau_resolu::autorite_de_proprietaire(&owner, &au) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // `P11.20-m` — le geste de partage d'une vue est jugé AVANT toute écriture : un tableau de bord
    // privé rangé dans la vue le retient, et le refus le nomme.
    if panneau_resolu::est_un_geste_de_partage(&b, &visibilite) {
        // `P10.20-b` — les éléments qui retiendraient le partage NON LUS ne valent pas « rien ne
        // retient » : 503 nommé, avant toute écriture.
        match element_moins_visible_d_une_vue(&conn, id, &au) {
            Ok(None) => {}
            Ok(Some(element)) => return panneau_resolu::refus_de_partage(&element, "la vue"),
            Err(_) => return panneau_resolu::refus_d_elements_retenant_non_lus(),
        }
    }
    // `P10.20-l` (vague AG) — les deux écritures sous un garde, une ligne exigée chacune (la vue vient d'être lue) : la
    // forme d'avant (`let _` puis 204) disait « modifiée » d'un renommage ou d'un partage refusé. Un refus ou un effet nul
    // annule les deux (Drop -> ROLLBACK), 503 nommé.
    let geste = format!("modification de la vue #{id}");
    let tx = match ouvrir_le_garde_du_geste(&conn, "dashboards", &geste, CAUSE_VUE_INCHANGEE_TRANSACTION_NON_OUVERTE) {
        Ok(t) => t,
        Err(refus) => return refus,
    };
    // `P11.25-f` — UN RENOMMAGE NE FABRIQUE PAS LE DOUBLON QUE LA CRÉATION REFUSE. Même jugement que `view_create`, sous le
    // même verrou d'écriture : une AUTRE vue de ce nom parmi celles que le renommeur voit -> 409 avec son identifiant,
    // rien du corps n'est appliqué ; la recherche non faite -> 503 nommé. La vue renommée elle-même n'est pas un doublon.
    if let Some(name) = b.get("name").and_then(|v| v.as_str()) {
        let adm = if au.is_admin() { "admin" } else { "" };
        let sql_homonyme = "SELECT id FROM view WHERE name=?1 AND id<>?4 AND (?2='admin' OR visibility='shared' OR owner=?3) ORDER BY id LIMIT 1";
        match conn.query_row(sql_homonyme, params![name, adm, au.name, id], |r| r.get::<_, i64>(0)).optional() {
            Ok(None) => {}
            Ok(Some(existante)) => {
                drop(tx); // Drop -> ROLLBACK : rien n'a été écrit.
                return (StatusCode::CONFLICT, Json(json!({ "error": CAUSE_VUE_RENOMMEE_VERS_UNE_EXISTANTE, "view_id": existante }))).into_response();
            }
            Err(e) => {
                drop(tx);
                let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_VUE_INCHANGEE_HOMONYMES_NON_LUS);
                eprintln!("[dashboards] WARN vues homonymes NON lues, vue #{id} non renommée ({}) : {e}", cid.unwrap_or_default());
                return refus;
            }
        }
    }
    let ecrit: Result<(), String> = (|| {
        if let Some(name) = b.get("name").and_then(|v| v.as_str()) {
            une_seule_ligne(conn.execute("UPDATE view SET name=?1 WHERE id=?2", params![name, id]), "nom")?;
        }
        if let Some(vis) = b.get("visibility").and_then(|v| v.as_str()) {
            let vis = if vis == "shared" { "shared" } else { "private" };
            une_seule_ligne(conn.execute("UPDATE view SET visibility=?1 WHERE id=?2", params![vis, id]), "visibilité")?;
        }
        Ok(())
    })();
    if let Err(cause) = ecrit {
        drop(tx); // Drop -> ROLLBACK : le nom et la visibilité sont ceux d'avant.
        return refuser_le_retrait_non_pris(&geste, &cause, CAUSE_VUE_INCHANGEE);
    }
    rendre_apres_validation_du_garde(tx, &conn, "dashboards", &geste, CAUSE_VUE_INCHANGEE, || StatusCode::NO_CONTENT.into_response())
}

/// `P11.25-f` — LA PORTE DE PARTAGE D'UNE VUE LIT AUSSI LA JOINTURE. `ElementMoinsVisible::d_une_vue` ne lit que la vue
/// PRINCIPALE (`dashboard.view_id`) ; un tableau privé rangé dans la vue par `POST /api/views/{id}/dashboards` (sans
/// que ce soit sa vue principale) la retient de même. Les deux lectures se complètent sans se recouvrir
/// (`d.view_id IS NOT ?1`), et le compte servi dans la phrase est leur somme. Un tableau déclaré dans toutes les vues
/// (`all_views`) n'est rattaché à aucune et ne retient pas. Une lecture non faite rend `Err` (refus réessayable).
/// `P11.25-f` (vague CB) — les deux lectures suivent la même règle : seul un tableau que l'APPELANT pourrait partager
/// lui-même (le sien, nom non vide ; l'administrateur : tous) retient, est nommé et compté. Le privé qu'un autre compte a
/// rangé dans la vue n'est ni nommé (le 409 servait son nom, son numéro et son propriétaire à qui ne peut pas le lire) ni
/// compté, et ne bloque plus la vue : il reste invisible aux lecteurs de la vue partagée (`FILTRE_DES_TABLEAUX_DE_BORD`).
fn element_moins_visible_d_une_vue(conn: &Connection, view_id: i64, au: &AuthUser) -> rusqlite::Result<Option<panneau_resolu::ElementMoinsVisible>> {
    let principal = panneau_resolu::ElementMoinsVisible::d_une_vue(conn, view_id, au)?;
    let adm = if au.is_admin() { "admin" } else { "" };
    let sql_compte = "SELECT COUNT(*) FROM dashboard d JOIN view_dashboard vd ON vd.dashboard_id=d.id \
         WHERE vd.view_id=?1 AND d.view_id IS NOT ?1 AND COALESCE(d.visibility,'shared')<>'shared' \
         AND (?2='admin' OR (?3<>'' AND d.owner=?3))";
    let rattaches: i64 = conn.query_row(sql_compte, params![view_id, adm, au.name], |r| r.get(0))?;
    match principal {
        Some(mut element) => {
            element.retenus += rattaches;
            Ok(Some(element))
        }
        None if rattaches == 0 => Ok(None),
        None => conn
            .query_row(
                "SELECT d.id,d.name,COALESCE(d.owner,'') FROM dashboard d JOIN view_dashboard vd ON vd.dashboard_id=d.id \
                 WHERE vd.view_id=?1 AND d.view_id IS NOT ?1 AND COALESCE(d.visibility,'shared')<>'shared' \
                 AND (?2='admin' OR (?3<>'' AND d.owner=?3)) ORDER BY d.id LIMIT 1",
                params![view_id, adm, au.name],
                |r| {
                    Ok(panneau_resolu::ElementMoinsVisible {
                        genre: "le tableau de bord",
                        id: r.get(0)?,
                        nom: r.get(1)?,
                        proprietaire: r.get(2)?,
                        retenus: rattaches,
                    })
                },
            )
            .map(Some),
    }
}

// ---------- rattachements d'une vue (`P11.25-f`) ----------

/// `P11.25-f` — la vue visée par un geste de rattachement n'existe pas, ou l'appelant ne la voit pas (même phrase : elle
/// dirait sinon l'existence d'une vue privée d'autrui) : rien n'est rattaché ni retiré.
pub(crate) const CAUSE_VUE_INCONNUE: &str = "VUE INCONNUE : aucune vue que vous voyez ne porte cet identifiant — rien n'est rattaché ni retiré.";
/// `P11.25-f` — au moins un identifiant demandé ne désigne aucun tableau de bord que l'appelant voit (absent, ou privé
/// d'un autre compte : les deux cas ont la même réponse, sans quoi elle dirait l'existence d'un tableau privé). Les
/// identifiants en cause sont servis à côté (`dashboard_ids`). Tout ou rien : aucun des autres n'est rattaché.
pub(crate) const CAUSE_TABLEAUX_DE_BORD_INCONNUS: &str = "TABLEAU DE BORD INCONNU : au moins un identifiant demandé ne \
     désigne aucun tableau de bord que vous voyez — RIEN n'est rattaché, aucun des autres non plus (tout ou rien).";
/// `P11.25-f` — le tableau de bord n'est pas rangé dans cette vue : rien n'est retiré.
pub(crate) const CAUSE_RATTACHEMENT_ABSENT: &str =
    "RATTACHEMENT ABSENT : ce tableau de bord n'est pas rangé dans cette vue — rien n'est retiré.";
/// `P11.25-f` — le corps de `POST /api/views/{id}/dashboards` n'est pas `{"dashboard_ids": [<entiers>]}`.
pub(crate) const CAUSE_CORPS_DES_RATTACHEMENTS_INVALIDE: &str = "CORPS INVALIDE : `dashboard_ids` vaut un tableau \
     d'identifiants entiers de tableaux de bord — rien n'est rattaché.";
/// `P11.25-f` — la vue, les tableaux demandés ou leurs rattachements n'ont pas été lus : ni le droit ni la présence ne
/// sont jugés, rien n'est écrit. Ne nomme pas une transaction annulée : c'est une lecture qui manque.
pub(crate) const CAUSE_RATTACHEMENTS_NON_LUS: &str = "RATTACHEMENTS INCHANGÉS : la base n'a pas rendu la vue, les \
     tableaux de bord demandés ou leurs rattachements — ce n'est PAS une absence, c'est une lecture qui n'a pas eu lieu, \
     et ni le droit ni la présence ne sont jugés. RIEN n'est rattaché ni retiré. Réessayez ; si le refus persiste, la \
     table des vues ou des tableaux de bord est illisible.";
/// `P11.25-f` — une écriture d'un geste de rattachement refusée ou sans effet : la transaction est annulée
/// (`OUVERTURE_DE_L_ECRITURE_NON_PRISE`, web/core.js).
pub(crate) const CAUSE_RATTACHEMENTS_INCHANGES: &str = "RATTACHEMENTS INCHANGÉS : la base n'a pas pris l'écriture d'un \
     rattachement ou son effacement, et la transaction est annulée — la vue garde exactement ses rattachements d'avant \
     (tout ou rien). Réessayez ; si le refus persiste, la base est en lecture seule, pleine ou verrouillée.";
/// `P11.25-f` — le `BEGIN` d'un geste de rattachement refusé (`OUVERTURE_DE_LA_TRANSACTION_NON_PRISE`).
pub(crate) const CAUSE_RATTACHEMENTS_INCHANGES_TRANSACTION_NON_OUVERTE: &str = "RATTACHEMENTS INCHANGÉS : la base n'a \
     pas pris la transaction du geste (BEGIN refusé : verrou tenu, ou transaction d'un autre geste pendante sur \
     l'écrivain) — RIEN n'est écrit. Réessayez ; s'il est refusé encore, l'écrivain est occupé ou bloqué.";
/// `P11.25-f` — le `COMMIT` d'un geste de rattachement refusé (`OUVERTURE_DE_L_ECRITURE_NON_VALIDEE`).
pub(crate) const CAUSE_RATTACHEMENTS_INCHANGES_NON_VALIDES: &str = "RATTACHEMENTS INCHANGÉS : la base n'a pas validé la \
     transaction (COMMIT refusé) et l'a annulée — la vue garde exactement ses rattachements d'avant. Réessayez ; si le \
     refus persiste, la base est en lecture seule, pleine ou verrouillée.";

/// `P11.25-f` — la phrase d'une liste d'identifiants trop longue : la borne y est écrite.
pub(crate) fn cause_trop_de_rattachements() -> String {
    format!(
        "TROP DE RATTACHEMENTS : au plus {LIMITE_DE_PAGE_DES_TABLEAUX_DE_BORD} identifiants par demande — rien n'est \
         rattaché ; envoyez la suite dans une autre demande."
    )
}

/// `P11.25-f` — une liste d'identifiants au-delà de la borne d'une page.
fn trop_de_rattachements(n: usize) -> bool {
    n as i64 > LIMITE_DE_PAGE_DES_TABLEAUX_DE_BORD
}

/// `P11.25-f` — LA PORTE DE LA VUE D'UN GESTE DE RATTACHEMENT : LA MÊME QUE CELLE DE `dash_update` QUAND IL ÉCRIT
/// `view_id` (`juger_la_vue_du_tableau`). Ranger un tableau dans une vue, ou l'en sortir, CLASSE le tableau ; cela ne
/// publie rien (`FILTRE_DES_TABLEAUX_DE_BORD` exige la visibilité du TABLEAU, `dash_get` et la porte des panneaux
/// passent par `lisible_par`). La porte est donc la VISIBILITÉ de la vue, au périmètre de `views_list`
/// (administrateur, vue commune — semée sans propriétaire comprise —, ou vue de l'appelant), et le droit sur CHAQUE
/// tableau ajouté ou retiré se juge ensuite, tableau par tableau, par la règle de `dash_editable`. Une vue que
/// l'appelant ne voit pas est une vue INCONNUE pour lui — même statut, même corps qu'une vue absente (404
/// `CAUSE_VUE_INCONNUE`) ; un 403 dirait qu'elle existe. Lecture non faite : 503 nommé, la cause du moteur au journal
/// seul. Le nom, la visibilité et la suppression d'une vue restent un geste de propriétaire (`view_update`,
/// `view_delete`).
fn porte_des_rattachements(conn: &Connection, au: &AuthUser, view_id: i64) -> Result<(), Response> {
    let adm = if au.is_admin() { "admin" } else { "" };
    let lu = conn.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM view WHERE id=?1 AND {LA_VUE_EST_VUE_PAR_L_APPELANT})"),
        params![view_id, adm, au.name],
        |r| r.get::<_, i64>(0),
    );
    match lu {
        Ok(0) => Err(err_json(StatusCode::NOT_FOUND, CAUSE_VUE_INCONNUE)),
        Ok(_) => Ok(()),
        Err(e) => {
            let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_RATTACHEMENTS_NON_LUS);
            eprintln!("[dashboards] WARN vue #{view_id} NON lue pour ses rattachements, rien n'est écrit ({}) : {e}", cid.unwrap_or_default());
            Err(refus)
        }
    }
}

/// `P11.25-f` — le refus d'une lecture non faite DANS la transaction d'un geste de rattachement (le garde déjà annulé).
fn refuser_les_rattachements_non_lus(view_id: i64, e: &rusqlite::Error) -> Response {
    let (cid, refus) = crate::err_json_et_identifiant(StatusCode::SERVICE_UNAVAILABLE, CAUSE_RATTACHEMENTS_NON_LUS);
    eprintln!("[dashboards] WARN rattachements de la vue #{view_id} NON lus, rien n'est écrit ({}) : {e}", cid.unwrap_or_default());
    refus
}

/// `POST /api/views/{id}/dashboards {"dashboard_ids": [...]}` — COMPLÈTE une vue existante : n'ajoute que les
/// rattachements manquants, idempotent, et répond 200 `{"added": [...], "already_present": [...]}` dans l'ordre de la
/// demande, doublons de la demande retirés. Un identifiant inconnu (ou privé d'un autre compte), ou une vue inconnue (ou
/// que l'appelant ne voit pas) : 404 nommé et RIEN n'est écrit. Droits : VOIR la vue (`porte_des_rattachements`) et
/// pouvoir MODIFIER chaque tableau demandé (règle de `dash_editable`) — la porte de `dash_update` quand il écrit
/// `view_id` ; un éditeur complète donc une vue commune d'un autre compte ou une vue semée. N'écrit pas `dashboard.view_id` (la vue principale ne
/// change pas). Chaque rattachement de la demande est EXPLICITE (`view_dashboard.explicite = 1`) : posé à 1, ou relevé
/// à 1 s'il n'existait que comme vue principale (servi alors sous `already_present`) — le déplacement ultérieur de la
/// vue principale ne l'efface donc pas.
pub(crate) async fn view_dashboards_add(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    let Some(demandes) = b.get("dashboard_ids").and_then(|v| v.as_array()) else {
        return err_json(StatusCode::BAD_REQUEST, CAUSE_CORPS_DES_RATTACHEMENTS_INVALIDE);
    };
    if trop_de_rattachements(demandes.len()) {
        return err_json(StatusCode::BAD_REQUEST, cause_trop_de_rattachements());
    }
    let mut ids: Vec<i64> = Vec::with_capacity(demandes.len());
    for v in demandes {
        let Some(n) = v.as_i64() else {
            return err_json(StatusCode::BAD_REQUEST, CAUSE_CORPS_DES_RATTACHEMENTS_INVALIDE);
        };
        if !ids.contains(&n) {
            ids.push(n);
        }
    }
    crate::req_conn!(st, au, conn);
    if let Err(refus) = porte_des_rattachements(&conn, &au, id) {
        return refus;
    }
    let geste = format!("rattachement de tableaux de bord à la vue #{id}");
    let tx = match ouvrir_le_garde_du_geste(&conn, "dashboards", &geste, CAUSE_RATTACHEMENTS_INCHANGES_TRANSACTION_NON_OUVERTE) {
        Ok(t) => t,
        Err(refus) => return refus,
    };
    // Tous les tableaux demandés sont lus AVANT toute écriture : un seul inconnu, et rien n'est écrit. Le rattachement
    // présent est lu avec son origine (`explicite`) : `None` absent, `Some(0)` vue principale seule, `Some(1)` explicite.
    // LE DROIT SUR CHAQUE TABLEAU EST CELUI DE `dash_editable` : sa règle, après le raccourci administrateur, EST
    // `lisible_par`, qui admet l'administrateur (`autorite_de_proprietaire`, panneau_resolu.rs). Un tableau « lisible mais
    // non modifiable » n'existe donc pas : un tableau que l'appelant ne peut pas modifier est un tableau qu'il ne lit
    // pas, servi en INCONNU (404 `CAUSE_TABLEAUX_DE_BORD_INCONNUS`) — un 403 dirait l'existence d'un tableau privé
    // d'autrui. L'équivalence des deux règles a son témoin (portes_des_rattachements_alignees_et_vue_masquee.rs).
    let mut inconnus: Vec<i64> = Vec::new();
    let mut deja: Vec<i64> = Vec::new();
    let mut a_confirmer: Vec<i64> = Vec::new();
    for did in &ids {
        let lu = conn
            .query_row(
                "SELECT COALESCE(owner,''),COALESCE(visibility,'shared'),
                        (SELECT explicite FROM view_dashboard WHERE view_id=?2 AND dashboard_id=?1)
                 FROM dashboard WHERE id=?1",
                params![did, id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<i64>>(2)?)),
            )
            .optional();
        match lu {
            Ok(Some((owner, vis, present))) if panneau_resolu::lisible_par(&owner, &vis, &au) => match present {
                None => {}
                Some(0) => {
                    deja.push(*did);
                    a_confirmer.push(*did);
                }
                Some(_) => deja.push(*did),
            },
            Ok(_) => inconnus.push(*did),
            Err(e) => {
                drop(tx);
                return refuser_les_rattachements_non_lus(id, &e);
            }
        }
    }
    if !inconnus.is_empty() {
        drop(tx); // Drop -> ROLLBACK : rien n'a été écrit.
        return (StatusCode::NOT_FOUND, Json(json!({ "error": CAUSE_TABLEAUX_DE_BORD_INCONNUS, "dashboard_ids": inconnus }))).into_response();
    }
    let ajoutes: Vec<i64> = ids.iter().copied().filter(|d| !deja.contains(d)).collect();
    let ecrit: Result<(), String> = ajoutes
        .iter()
        .try_for_each(|did| {
            une_seule_ligne(
                conn.execute("INSERT INTO view_dashboard(view_id, dashboard_id, explicite) VALUES(?1,?2,1)", params![id, did]),
                &format!("rattachement du tableau de bord #{did}"),
            )
        })
        .and_then(|()| {
            // Un rattachement qui n'existait que comme vue principale devient explicite : il survivra au déplacement.
            a_confirmer.iter().try_for_each(|did| {
                une_seule_ligne(
                    conn.execute("UPDATE view_dashboard SET explicite=1 WHERE view_id=?1 AND dashboard_id=?2 AND explicite=0", params![id, did]),
                    &format!("confirmation du rattachement du tableau de bord #{did}"),
                )
            })
        });
    if let Err(cause) = ecrit {
        drop(tx); // Drop -> ROLLBACK : aucun rattachement de cette demande ne reste.
        return refuser_le_retrait_non_pris(&geste, &cause, CAUSE_RATTACHEMENTS_INCHANGES);
    }
    rendre_apres_validation_du_garde(tx, &conn, "dashboards", &geste, CAUSE_RATTACHEMENTS_INCHANGES_NON_VALIDES, || {
        Json(json!({ "added": ajoutes, "already_present": deja })).into_response()
    })
}

/// `DELETE /api/views/{id}/dashboards/{dashboard_id}` — retire UN rattachement (204), QUELLE QUE SOIT SON ORIGINE :
/// explicite, vue principale seule, ou les deux — le geste dit « ce tableau sort de cette vue ». Si la vue retirée était
/// la vue principale du tableau (`dashboard.view_id`), celle-ci est vidée dans la même transaction : la colonne ne
/// désigne jamais une vue dont le tableau n'est plus rangé. Non rangé : 404 nommé, rien n'est écrit. Une vue que
/// l'appelant ne voit pas : la réponse d'une vue absente (`porte_des_rattachements`). Un tableau que l'appelant ne
/// peut pas lire (privé d'un autre compte, rangé dans sa vue par son propriétaire) est traité comme non rangé — même
/// réponse, même phrase, rien n'est écrit — comme `view_dashboards_add` le traite en inconnu : sinon le 204 face au 404
/// dirait l'existence de ce tableau privé, et viderait sa vue principale.
///
/// Droits : ceux de `view_dashboards_add` — VOIR la vue, et pouvoir MODIFIER le tableau retiré (règle de
/// `dash_editable`, qui EST `lisible_par`). Un éditeur retire donc son tableau, ou un tableau commun, d'une vue commune
/// d'un autre compte ou d'une vue semée. Être propriétaire de la vue n'ouvre rien DE PLUS : l'administrateur modifie
/// déjà tout tableau, et le seul tableau qu'un propriétaire de vue ne peut pas modifier est un tableau privé d'autrui,
/// qu'il ne lit pas — le lui laisser retirer rouvrirait l'oracle décrit ci-dessus.
pub(crate) async fn view_dashboard_remove(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Path((id, did)): Path<(i64, i64)>) -> Response {
    crate::req_conn!(st, au, conn);
    if let Err(refus) = porte_des_rattachements(&conn, &au, id) {
        return refus;
    }
    let geste = format!("retrait du tableau de bord #{did} de la vue #{id}");
    let tx = match ouvrir_le_garde_du_geste(&conn, "dashboards", &geste, CAUSE_RATTACHEMENTS_INCHANGES_TRANSACTION_NON_OUVERTE) {
        Ok(t) => t,
        Err(refus) => return refus,
    };
    // La présence est LUE avant l'effacement : un effacement qui n'ôte rien (déclencheur qui l'ignore) n'est pas une
    // absence, et l'absence n'est dite que lue. Le propriétaire et la visibilité du tableau sont lus dans la même
    // instruction : un tableau absent, ou que l'appelant ne lit pas, est un rattachement absent pour lui.
    let lu = conn
        .query_row(
            "SELECT COALESCE(owner,''),COALESCE(visibility,'shared'),
                    EXISTS(SELECT 1 FROM view_dashboard WHERE view_id=?1 AND dashboard_id=?2)
             FROM dashboard WHERE id=?2",
            params![id, did],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? != 0)),
        )
        .optional();
    match lu {
        Ok(Some((owner, vis, true))) if panneau_resolu::lisible_par(&owner, &vis, &au) => {}
        Ok(_) => {
            drop(tx);
            return err_json(StatusCode::NOT_FOUND, CAUSE_RATTACHEMENT_ABSENT);
        }
        Err(e) => {
            drop(tx);
            return refuser_les_rattachements_non_lus(id, &e);
        }
    }
    let ecrit: Result<(), String> = (|| {
        une_seule_ligne(conn.execute("DELETE FROM view_dashboard WHERE view_id=?1 AND dashboard_id=?2", params![id, did]), "effacement du rattachement")?;
        conn.execute("UPDATE dashboard SET view_id=NULL WHERE id=?1 AND view_id=?2", params![did, id])
            .map_err(|e| format!("détachement de la vue principale : {e}"))?;
        Ok(())
    })();
    if let Err(cause) = ecrit {
        drop(tx); // Drop -> ROLLBACK : le rattachement et la vue principale sont ceux d'avant.
        return refuser_le_retrait_non_pris(&geste, &cause, CAUSE_RATTACHEMENTS_INCHANGES);
    }
    rendre_apres_validation_du_garde(tx, &conn, "dashboards", &geste, CAUSE_RATTACHEMENTS_INCHANGES_NON_VALIDES, || StatusCode::NO_CONTENT.into_response())
}

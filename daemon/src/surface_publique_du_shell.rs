//! surface_publique_du_shell — P4.13-a : LES SEULS OCTETS QU'UN VISITEUR NON AUTHENTIFIÉ REÇOIT.
//!
//! QUATRE listes EXACTES, DÉRIVÉES et non énumérées, que `auth_guard` (`auth.rs`) laisse passer en
//! GET/HEAD avant toute résolution d'identité, plus l'UNIQUE prédicat (`est_publique`) qui les lit.
//! Elles vivent ICI, hors du choke-point, parce que ce sont des DONNÉES avec leur justification :
//! `auth.rs` porte la décision (« ce bloc s'applique »), ce module porte l'ensemble sur lequel elle
//! s'applique — et `tests/fermeture_shell_spa.rs` le RECALCULE à chaque `cargo test` en comparant
//! dans les deux sens.
//!
//! LE PRÉDICAT A UN SECOND LECTEUR DEPUIS LA REPRISE : `budget_du_shell_public`, qui borne ce que
//! cette porte COÛTE. Ouvrir le shell a fait passer le prix d'un anonyme de 12 octets à 1,9 Mio et
//! de 0,21 ms à ~6,5 ms d'UC (compression) — les plafonds de `rate_limit` avaient été dimensionnés
//! sur l'ancien prix. Un seul ensemble, deux mécanismes : la porte et son budget ne peuvent pas
//! diverger sur ce qu'ils appellent « la surface publique ».

/// P4.13-a — LES OCTETS SANS LESQUELS L'ÉCRAN DE LOGIN NE PEUT PAS S'AFFICHER, DÉRIVÉS ET NON ÉNUMÉRÉS.
///
/// LE DÉFAUT, MESURÉ SUR UN DÉMON LANCÉ. Le statique est servi par le `fallback_service` (`ServeDir`),
/// lequel est ENVELOPPÉ par les couches globales dont `auth_guard` : sans mandataire devant, `GET /`
/// répondait `401 auth requise` — douze octets de texte brut — et `GET /app.js` la même chose. Le module
/// qui PEINT l'écran de login (`login.js`, déclenché par le 401 de `/api/me`) n'était donc jamais chargé :
/// un visiteur non authentifié ne voyait pas un formulaire, il voyait une phrase. Les modes `host` et
/// `docker` atteignent le démon EN DIRECT (`docs/TROIS-MODES.md` §3.1) ; seul `k3s` passe par un
/// mandataire qui laisse déjà passer `/` — c'est l'INFRASTRUCTURE qui masquait le défaut, pas le produit.
///
/// POURQUOI DEUX LISTES EXACTES ET SURTOUT PAS UN PRÉFIXE. Un `starts_with("/")`, ou même un
/// `ends_with(".js")`, rendrait PUBLIC tout fichier déposé demain sous `web/` sans qu'aucune décision ne
/// soit prise ni vue. La propriété que l'allowlist voisine (favicons/manifeste/service-worker) a choisie
/// est d'être EXACTE et de ne pas pouvoir s'élargir par accident ; on la garde. Ce qui change, c'est que
/// l'ensemble n'est plus écrit à la main : il est DÉRIVÉ, et un témoin le RECALCULE.
///
/// CE QUE LA DÉRIVATION CALCULE. `SHELL_JS_CLOSURE` est la fermeture des imports ES **statiques**
/// atteignable depuis `/app.js` — le seul script que `index.html` charge. `INDEX_DIRECT_ASSETS` est ce que
/// le document d'entrée et sa feuille de style référencent DIRECTEMENT (le document lui-même sous ses deux
/// noms, la feuille, le logo de la carte de login, les quatre fontes). Le test
/// `tests/fermeture_shell_spa.rs` recalcule les deux à chaque `cargo test` et compare DANS LES DEUX SENS :
/// atteignable mais absent -> le login casse ; présent mais plus atteignable -> surface publique morte.
/// Un fichier ajouté à `web/` n'est donc PAS exempté automatiquement : il fait ROUGIR le test tant que
/// personne n'a pris la décision de l'inscrire ici. C'est la vérifiabilité qu'on achète, pas l'étroitesse
/// — mesuré : la fermeture atteint 49 des 50 modules de la console, le cinquantième étant `sw.js`, déjà
/// exempté ci-dessous à un autre titre.
///
/// CE QUE CETTE LISTE NE PEUT PAS FAIRE, ET C'EST STRUCTUREL : elle ne contient que des noms de fichiers
/// EXACTS, aucun ne commençant par `/api/`. Aucune route d'interface ne peut être élargie par elle ; les
/// témoins de `fermeture_shell_spa.rs` le vérifient en SERVANT, sur plusieurs routes.
///
/// AUCUN SECRET N'EST ASSIGNÉ EN DUR dans ces fichiers : ce sont des surfaces qui MANIPULENT des clés et
/// des jetons (`keys.js`, `idp.js`, `admin_users.js`), toutes alimentées par des routes `/api/*` qui,
/// elles, restent gatées. Ce que le public obtient est le code de l'interface, pas ses données.
///
/// L'ORDRE EST STRICTEMENT CROISSANT : la recherche est DICHOTOMIQUE (le bloc est traversé par CHAQUE
/// requête, y compris les `/api/*`), et le tri strict interdit du même geste les doublons. Le témoin
/// `l_ordre_strict_est_ce_que_la_dichotomie_exige` le tient.
pub(crate) const SHELL_JS_CLOSURE: &[&str] = &[
    "/admin_users.js", "/ai.js", "/alerting.js",
    "/alerts.js", "/app.js", "/attack.js",
    "/audit.js", "/cases.js", "/composer_depuis_lexistant.js",
    "/connectors.js", "/copie_et_selection.js", "/core.js",
    "/dashboards.js", "/dataaccess.js", "/datamodels.js",
    "/destinations.js", "/detadv.js", "/detection_admin.js",
    "/fieldfilters.js", "/fleet.js", "/freshness.js",
    "/help.js", "/help_registry.js", "/i18n.js",
    "/i18n_observer.js", "/idp.js", "/index_policies.js",
    "/keys.js", "/knowledge.js", "/login.js",
    "/lookups.js", "/multitenant.js", "/navigation.js",
    "/prefs.js", "/processors.js", "/producer_ui.js",
    "/recherche_de_liste.js", "/retention.js", "/risk.js",
    "/runbooks.js", "/savedqueries.js", "/sigmaimport.js",
    "/soql_complete.js", "/sources.js", "/state.js",
    "/suppressions.js", "/system.js", "/threatintel.js",
    "/viz.js",
];

/// P4.13-a — le document d'entrée et ce qu'il référence DIRECTEMENT, hors JavaScript (cf. `SHELL_JS_CLOSURE`).
/// `/` et `/index.html` désignent le MÊME fichier (`ServeDir` sert l'index d'un répertoire) : les deux
/// chemins existent pour un visiteur, les deux sont donc écrits. Les fontes et le logo ne sont pas
/// « cosmétiques » : gatés, la carte de login s'affiche avec une image cassée et une police de repli.
pub(crate) const INDEX_DIRECT_ASSETS: &[&str] = &[
    "/", "/fonts/inter-latin-ext.woff2",
    "/fonts/inter-latin.woff2", "/fonts/jetbrains-mono-latin-ext.woff2",
    "/fonts/jetbrains-mono-latin.woff2", "/index.html",
    "/quetzal.svg", "/style.css",
];

/// P4.13-a — les quatre assets que le NAVIGATEUR va chercher de lui-même, extraits du `matches!` qui les
/// portait pour qu'il n'existe qu'UN SEUL auteur de l'ensemble public : la dérivation de
/// `fermeture_shell_spa.rs` doit pouvoir dire « ce chemin est déjà exempté ailleurs » sans recopier la
/// liste — deux listes de la même population divergent. Déplacement PUR : mêmes quatre chaînes, même
/// gate GET/HEAD, même point du flux.
pub(crate) const PWA_PUBLIC_ASSETS: &[&str] =
    &["/favicon-plume.svg", "/favicon.svg", "/manifest.webmanifest", "/sw.js"];

/// P4.13-a (reprise) — LA LICENCE ACCOMPAGNE LA FONTE, PARCE QUE LA FONTE EST DISTRIBUÉE.
///
/// LE DÉFAUT, VU PAR LA CRITIQUE ADVERSE ET CONFIRMÉ ICI. `INDEX_DIRECT_ASSETS` a rendu publics les quatre
/// `.woff2` (176 380 octets) — c'est la voie NOMINALE depuis ce lot : `style.css` les déclare en `@font-face`
/// et le navigateur d'un visiteur ANONYME va les chercher. Servir un fichier de fonte par HTTP EST une
/// distribution ; la SIL Open Font License 1.1 exige que l'avis de copyright et le texte de la licence
/// accompagnent TOUTE distribution du logiciel de fonte. Or les deux textes vivent dans le MÊME répertoire
/// et restaient gatés — ils figuraient nommément parmi les chemins que le lot VÉRIFIAIT rester en 401. On
/// distribuait la fonte en retenant sa licence, par construction de la liste.
///
/// POURQUOI UNE LISTE À PART ET PAS UNE ENTRÉE DE PLUS DANS `INDEX_DIRECT_ASSETS`. Cette dernière est
/// DÉRIVÉE de ce que le document et sa feuille référencent : ni `index.html` ni `style.css` ne pointent une
/// licence, donc l'y inscrire ferait rougir la dérivation (« surface publique morte ») — et l'assouplir pour
/// l'accepter détruirait la propriété qui la rend vérifiable. La règle de CETTE liste est autre, et elle est
/// DÉRIVÉE elle aussi : *pour tout répertoire de `web/` dont un fichier de fonte est public, TOUS les textes
/// de licence de ce répertoire sont publics*. `fermeture_shell_spa.rs` la recalcule depuis l'ARBRE, dans les
/// deux sens — une fonte ajoutée sans sa licence rougit, une licence exemptée sans fonte publique aussi.
pub(crate) const LICENCES_DES_FONTES: &[&str] =
    &["/fonts/OFL-Inter.txt", "/fonts/OFL-JetBrainsMono.txt"];

/// P4.13-a (reprise) — L'UNIQUE PRÉDICAT « CE CHEMIN EST-IL DE LA SURFACE PUBLIQUE ? ».
///
/// Il existe parce que DEUX mécanismes en dépendent désormais et qu'ils doivent parler du MÊME ensemble :
/// la porte de `auth_guard` (qui laisse passer) et le budget d'octets de `budget_du_shell_public` (qui borne
/// ce que cette porte coûte). Deux lectures de la même population divergent ; il n'y en a qu'une.
///
/// Recherche DICHOTOMIQUE sur quatre listes STRICTEMENT triées (le témoin `l_ordre_strict_…` le tient) :
/// ce prédicat est traversé par CHAQUE requête, `/api/*` comprises.
pub(crate) fn est_publique(chemin: &str) -> bool {
    PWA_PUBLIC_ASSETS.binary_search(&chemin).is_ok()
        || INDEX_DIRECT_ASSETS.binary_search(&chemin).is_ok()
        || LICENCES_DES_FONTES.binary_search(&chemin).is_ok()
        || SHELL_JS_CLOSURE.binary_search(&chemin).is_ok()
}

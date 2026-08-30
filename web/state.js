// state.js — shared mutable UI-state container for the Plume web app.
//
// WHY: the app was split from a single app.js monolith into ES modules. ES-module
// imports are read-only *bindings*, so a module cannot reassign an imported `let`
// (e.g. `evState = x` from another file is a TypeError). The fix is a single
// mutable namespace object: modules import `const S` and mutate `S.evState = x`
// — that mutates the object's property, not the (const) binding, so it works
// across module boundaries and every importer sees the same live value.
//
// This holds EVERY module-level mutable var that the tangled seams (viz/Explore,
// cases, connectors, multitenant, fleet, sources, audit, dashboards, alerts,
// detection, …) read AND write. Behaviour-preserving: initial values are the
// exact initializers the vars had in app.js (localStorage reads run at first
// import of this module, i.e. before app.js body runs — same effective timing).
// `P4.13-a` (reprise) — LIRE LE STOCKAGE DU SITE PEUT JETER, ET CE MODULE EST LA RACINE DU GRAPHE.
// `window.localStorage` ne rend pas `null` quand le navigateur BLOQUE le stockage de site (Chrome
// « bloquer tous les cookies » sur l'origine, contextes durcis, profils d'entreprise) : l'ACCÈS LUI-MÊME
// jette `SecurityError`. SEPT lectures s'exécutaient à l'ÉVALUATION d'un module, donc AVANT tout `catch`
// applicatif : le graphe ES ne se liait pas, `initAuthGate()` n'était jamais atteint, et le visiteur voyait
// un écran muet. SEPT, et non quatre : la lecture STATIQUE qui les a signalées n'en voyait que quatre
// (`state.js` ×2, `core.js` ×2) — c'est la MESURE (sous-banc « stockage refusé » de `web_esm_harnais.mjs`,
// qui EXÉCUTE les modules) qui a montré que le graphe restait cassé et nommé les trois autres :
// `detection_admin.js` ×2 et `app.js` ×1. Le défaut est PRÉEXISTANT — mais c'est `P4.13-a`
// qui rend ce chemin atteignable par un ANONYME en mode `host`/`docker` : avant, le shell n'était jamais
// servi sans identité, donc ce code ne s'exécutait jamais chez un visiteur non authentifié.
// QUE CE SOIT UNE EXCEPTION ET NON UNE POLITIQUE SE LIT DANS CE DÉPÔT : `prefs.js`, `multitenant.js`,
// `freshness.js` et le reste de `core.js` enveloppent DÉJÀ chaque accès ; seules ces sept lignes-là ne
// l'étaient pas. Le lecteur vit ICI parce que `state.js` est le feuillet du graphe (il n'importe rien) :
// `core.js` l'importe déjà, donc un seul auteur, et aucun cycle. Un refus rend `null` — exactement ce que
// rend une clé absente, donc les valeurs de repli déjà écrites (`|| 'id'`, `|| 'fr'`…) s'appliquent.
export function lireLeStockageDuSite(cle) {
  try {
    return localStorage.getItem(cle);
  } catch (e) {
    return null;
  }
}

// `P4.13-b` — ÉCRIRE PEUT JETER AUSSI, ET UN JET AU MILIEU D'UN GESTE EST PIRE QU'UNE PERTE.
// `P4.13-a` (ci-dessus) a gardé les LECTURES ; les ÉCRITURES sont restées NUES. MESURÉ le 2026-08-30,
// sous le mode « stockage refusé » du harnais (`PLUME_HARNAIS_STOCKAGE_REFUSE=1`), en exerçant le
// basculement de thème : `data-theme` passe de (absent) à `light`, PUIS `localStorage.setItem` jette
// `SecurityError` DANS le gestionnaire de clic — `paint()`, `refresh()` et `loadDashboard()` ne sont
// jamais atteints. L'icône reste `sun` (celle du thème SOMBRE) sur une interface passée en CLAIR, et les
// graphes gardent l'ancienne couleur. LA DIRECTION DE L'ERREUR EST CE QUI COMPTE : le geste ne rend pas
// MOINS, il rend un état INCOHÉRENT — l'exploitant n'a rien à lire pour le comprendre.
//
// POURQUOI UN ÉCRIVAIN PARTAGÉ, ET PAS UN `try` DE PLUS SUR CHAQUE SITE. Le dépôt porte 22 appels
// d'écriture, dont 15 DÉJÀ gardés — chacun par son propre `try {} catch (e) {}` recopié sur place
// (mesuré le 2026-08-30 par le critère « appel non enclos lexicalement dans un `try` »). Recopier la
// forme quatre fois de plus dans `app.js` la porterait à 19 et n'apprendrait toujours RIEN au site
// appelant : un `catch` vide AVALE le refus, si bien que l'exploitant croirait son choix retenu — on
// aurait échangé un état incohérent contre une perte MUETTE. Cet écrivain REND donc le fait au lieu de
// l'absorber (`true` = retenu, `false` = refusé), et c'est cette valeur qui laisse chaque site décider :
// DIRE la perte quand il y en a une, ou constater qu'il n'y en a pas (un miroir dont le vrai magasin est
// ailleurs n'a rien à annoncer). Il vit ICI parce que `state.js` est le feuillet du graphe — il n'importe
// rien : les modules qui lisent déjà le stockage par ce module (`app.js`, `core.js`, `detection_admin.js`)
// l'atteignent sans introduire de cycle. `null`/`undefined` EFFACE la clé, parce que c'est la forme que
// les sites d'appel écrivaient déjà à la main (`if (v) setItem(…) else removeItem(…)`).
export function ecrireDansLeStockageDuSite(cle, valeur) {
  try {
    if (valeur === null || valeur === undefined) localStorage.removeItem(cle);
    else localStorage.setItem(cle, String(valeur));
    return true;
  } catch (e) {
    return false;
  }
}

// `P4.13-c` — LE SILENCE EST PARFOIS JUSTE, MAIS IL NE DOIT PAS ÊTRE UNE ABSENCE DE CODE.
// `P4.13-b` (ci-dessus) a fait RENDRE le refus ; il n'a rien dit des sites qui choisissent de SE TAIRE.
// MESURÉ le 2026-08-30 sur tout `web/**/*.js`, avec l'analyseur lexical de
// `check_no_naked_site_storage_write.py` (témoins fabriqués dans les deux sens) : SEIZE mutations du
// stockage de site, dont QUATORZE dans une capture au corps VIDE, réparties sur SEPT modules. Une capture
// vide satisfait cette garde — elle le DIT elle-même en clôture — si bien que RIEN ne distingue le site
// qui se tait À DESSEIN de celui qui a simplement oublié. Le défaut n'est pas le silence : c'est que le
// silence n'était tenu par rien.
//
// POURQUOI PAS UN TROISIÈME VERDICT DANS LE RETOUR DE `ecrireDansLeStockageDuSite`. Deux mesures du
// 2026-08-30, et la seconde est la vraie :
//   1. L'écrivain a SEPT appelants, dont SIX lisent sa valeur dans un contexte BOOLÉEN (`if (…)`,
//      `if (!retenu)`). Élargir le retour les casse EN SILENCE : en lui faisant rendre une CHAÎNE au lieu
//      de `false`, le banc ESM passe de 0 à 1 — l'avis du basculement de thème disparaît, parce qu'une
//      chaîne est VRAIE — et les deux sites qui rechargent (`#tz`, `#lang`) prennent leur branche
//      `location.reload()`, qui DÉTRUIT le choix faute de l'avoir écrit : exactement la direction que
//      `P4.13-b` a fermée. Mesure obtenue par MUTATION, puis l'empreinte du fichier a été restaurée.
//   2. « À DESSEIN » n'est PAS ce que le geste de l'écrivain a produit. Il ne sait que ce qui s'est
//      passé — retenu, ou refusé ; l'intention est une connaissance de l'APPELANT, en amont. La faire
//      porter par le RETOUR ferait affirmer à un témoin ce que son propre geste n'a pas produit.
//      LA DÉCLARATION ENTRE, ELLE NE SORT PAS.
//
// LE TROISIÈME ÉTAT VIT DONC DANS LE CHOIX DE LA PORTE, PAS DANS LE TYPE DE RETOUR. Celle-ci ne rend
// RIEN, et c'est le propos : il n'y a aucun verdict à lire ici, PAR DÉCLARATION. L'écrivain à deux
// verdicts garde ses deux verdicts, et pas un seul de ses sept appelants ne change.
//
// QUAND SE TAIRE — LA SEULE RÈGLE QUI TRANCHE. Un geste de PRÉFÉRENCE (thème, langue, fuseau, densité,
// tri : un contrôle qu'on règle puis qu'on quitte) DIT sa perte — rien d'autre ne l'apprendra à
// l'exploitant, et l'avis ne part qu'une poignée de fois par session. Un geste de NAVIGATION (plier un
// panneau ; réordonner un miroir dont le vrai magasin est ailleurs) SE TAIT — il se répète, et son état
// se relit à l'œil au chargement suivant.
//
// LE NOM DE LA PORTE PORTE SEUL LA DÉCLARATION, ET CE N'ÉTAIT PAS LE PREMIER CHOIX — C'EST UNE MESURE.
// La forme écrite d'abord prenait la raison en TROISIÈME ARGUMENT, sur le patron de
// `confirmWithConsequence` (web/core.js) qui REFUSE une confirmation dont la conséquence n'est pas
// nommée : une raison posée SUR la ligne d'appel ne se détache pas, là où un commentaire dérive. MESURÉ
// le 2026-08-30, et c'est ce qui l'a fait retirer : chaque raison ainsi posée est un littéral de plus
// que `check_i18n_lexicon_covers_displayed_strings.py` ne sait pas classer — `app.js` passait de 22 à 23
// littéraux HORS-REGARD et `detection_admin.js` de 28 à 29, les DEUX plafonds franchis, la garde de 0
// à 1. Les loger aurait demandé de RELEVER deux cliquets pour y faire tenir de la prose neuve, ce que
// cette garde-là refuse par écrit. Une constante NOMMÉE ne sauve rien non plus : le plafond de
// `state.js` vaut ZÉRO. La raison vit donc dans le commentaire du site d'appel — où vivent déjà toutes
// les raisons de ce dépôt — et ce qu'une garde lit, c'est le NOM de la porte franchie.
//
// RIEN NE REFUSE À L'EXÉCUTION, ET CE N'EST PAS UN OUBLI. `state.js` est le FEUILLET du graphe : il
// n'importe RIEN, ce qui est exactement ce qui lui permet d'être importé partout sans cycle. Il ne peut
// donc pas avertir (`toast` vit dans `core.js`, qui importe CE module), et il ne doit pas jeter —
// jeter dans un gestionnaire d'écriture EST le défaut que `P4.13-b` a fermé.
//
// PIÈGE, ÉCRIT ICI PARCE QU'AUCUNE GARDE NE LE VOIT — trouvé par une relecture adverse le 2026-08-30.
// Cette porte NE REND RIEN. Or les six autres sites d'écriture de la console emploient tous le même
// patron : `if (!ecrireDansLeStockageDuSite(k, v)) toast(…)`. Recopié sur CETTE porte, ce patron
// avertirait TOUJOURS — y compris quand l'écriture a RÉUSSI — parce qu'une valeur absente est fausse.
// Le nom, la signature et tout ce qui précède n'en prévenaient pas.
//
// POURQUOI NE PAS RENDRE UN BOOLÉEN POUR AUTANT : ce serait rendre les deux portes indiscernables à
// l'appel, alors que le CHOIX DE LA PORTE est précisément ce qui déclare l'intention. Et rendre une
// valeur VRAIE ne corrigerait rien, cela retournerait le défaut — l'avertissement ne partirait alors
// JAMAIS, y compris sur un vrai refus. Aucune des deux valeurs n'est bonne : c'est l'USAGE EN POSITION
// DE VALEUR qui est fautif, et le langage ne sait pas l'interdire.
//
// LE GESTE QUI FERMERAIT VRAIMENT CE PIÈGE est une propriété dérivée — « la porte silencieuse n'est
// jamais LUE comme une valeur » — à ajouter à `check_no_naked_site_storage_write.py`, qui analyse déjà
// ce corpus lexicalement. Elle n'est PAS écrite : le piège est LATENT (les deux appels d'aujourd'hui
// l'emploient bien comme une instruction), et il reste ouvert sous `P4.13-c` plutôt que tu ici.
export function ecrireSansDireLeRefus(cle, valeur) {
  ecrireDansLeStockageDuSite(cle, valeur);
}

export const S = {
  // --- auth / tenancy ---
  AUTH: null,
  CURRENT_TENANT: '',
  MY_TENANTS: null,
  CURRENT_ENV: '',
  isAdmin: false,
  // --- net ---
  _netInflight: 0,
  // --- alerts / detection ---
  alertMitreFilter: '',
  alertHistPage: 0,
  alertGroupBy: '',
  alertGroupAll: false,
  alertGroupPage: 0,
  alertSourceFilter: '',
  alertUncased: true,
  editingRule: null,
  ruleSort: lireLeStockageDuSite('soc_rule_sort') || 'id',
  // --- freshness / sources ---
  freshnessRepollTimer: null,
  freshCollapsed: (() => { try { const raw = localStorage.getItem('soc_fresh_collapsed'); if (raw === null) return new Set(['cat:calme']); return new Set(JSON.parse(raw) || []); } catch (e) { return new Set(); } })(),
  // --- diff/audit window ---
  daWin: 'all',
  RET_STATE: null,
  // --- explore / viz / charts ---
  zoomRange: null,
  _charttip: undefined,
  _qidSeq: 0,
  exploreInflight: null,
  _colsMenuClose: null,
  _colsMenuOwner: null,
  lastResult: null,
  evState: { q: '', isSoql: false, page: 0, pageSize: 100, total: 0, shown: 0, totalCapped: false },
  qHist: [],
  qHistIdx: -1,
  qHistReplay: false,
  // --- dashboards / views / panels ---
  editing: false,
  dashList: [],
  viewList: [],
  // identité pour le partage de vue (#17 team) : renseignées par loadViews (/api/views renvoie me+role).
  // Permet de savoir si l'utilisateur courant peut BASCULER le scope partagé/privé d'une vue (owner ou admin).
  viewsMe: '',
  viewsRole: '',
  panelCards: [],
  panelObserver: null,
  // --- notifiers / parsers / playbooks ---
  editingNotif: null,
  editingParser: null,
  parserSort: lireLeStockageDuSite('soc_parser_sort') || 'default',
  editingPb: null,
  // --- cases ---
  caseSelectedId: null,
  casePager: null,
  // --- connectors ---
  editingConnector: null,
  // --- ledger ---
  LEDGER_LIMIT: 100,
  // --- auto-refresh ---
  autoTimer: null,
  autoPaused: false,
};

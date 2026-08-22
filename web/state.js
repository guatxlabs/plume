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
  ruleSort: localStorage.getItem('soc_rule_sort') || 'id',
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
  lastSearchQ: '',
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
  parserSort: localStorage.getItem('soc_parser_sort') || 'default',
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

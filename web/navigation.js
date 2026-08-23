// Navigation à deux niveaux : le MODÈLE des espaces et de leurs sous-onglets (`SPACES`), la résolution de
// l'onglet courant depuis le hash (alias historiques, repli d'un onglet interdit ou inconnu SANS réécrire le
// lien profond), le rendu des deux niveaux et le routage vers les chargeurs de chaque vue. Extrait d'`app.js`
// par déplacement pur ; l'écoute du hash, les clics de la sidebar et des sous-onglets et le burger sont posés
// par `initNavigation()`, appelée par `app.js` au point où ce bloc vivait. `app.js` garde l'amorçage (le
// premier `route()` et les initialisations qui suivent) et ré-exporte `SPACES`, `currentTab`,
// `currentViewName`, `renderNav` et `route` pour les modules seam. N'importe pas `app.js`.
import { $ } from './core.js';
import { S } from './state.js';
import { loadDashboards } from './dashboards.js';
import { renderDataAccess } from './dataaccess.js';
import { loadCases } from './cases.js';
import { loadFleetView } from './fleet.js';
import { loadSourcesView } from './sources.js';
import { loadSystemView } from './system.js';
import { loadLedger } from './audit.js';
import { loadConnectors } from './connectors.js';
import { loadDestinations } from './destinations.js';
import { loadIdpProviders, loadMfa } from './idp.js';
import { loadRouting } from './alerting.js';
import { loadFieldFilters } from './fieldfilters.js';
import { loadProcessors } from './processors.js';
import { loadIndexPolicies } from './index_policies.js';
import { loadThreatIntel } from './threatintel.js';
import { loadRiskView } from './risk.js';
import { loadDetAdv } from './detadv.js';
import { loadAttackMatrix } from './attack.js';
import { loadTenantsView, multiTenantMode, uiIsAdmin } from './multitenant.js';
import { loadKnowledge } from './knowledge.js';
import { loadDataModels } from './datamodels.js';
import { renderFreshness } from './freshness.js';
import { renderAlerts } from './alerts.js';
import { renderCoverage, loadActions, loadMode, loadPlaybooks } from './detection_admin.js';
import { loadRunbooks } from './runbooks.js';
import { loadTokens } from './admin_users.js';
import { loadRetention } from './retention.js';
import { loadSuppressions } from './suppressions.js';
import { renderHelpGuide } from './help.js';

// --- navigation à 2 niveaux : ESPACES (1er niveau, sidebar) -> SOUS-ONGLETS (2e niveau) -> sections <main> ---
// Chaque espace regroupe des sous-onglets ; chaque sous-onglet mappe une/des sections existantes (ids PRÉSERVÉS).
// Le hash = l'id du sous-onglet (unique sur tous les espaces) -> deep-link conservé. Espace à 1 seul onglet
// = pas de barre de sous-onglets (Vue d'ensemble, Recherche, Dashboards). admin:true sur un ESPACE => espace
// entier réservé admin (Administration) ; admin:true sur un ONGLET => onglet réservé admin mais espace visible
// (Lookups dans Données). 1er onglet = onglet par défaut de l'espace. Chaque id d'espace a son lien
// `data-space` dans la sidebar d'index.html (le harnais ESM tient les deux listes égales).
// P11.7-a : « Recherche » = l'éditeur de requête et ses résultats ; « Cas » = le flux alerte -> cas.
const SPACES = [
  { id: 'overview', tabs: [
    { id: 'overview', label: "Vue d'ensemble", sections: ['firewall', 'controls', 'integrations', 'freshness'] },
  ] },
  { id: 'search', tabs: [
    { id: 'explore', label: 'Recherche', sections: ['query'] },
  ] },
  { id: 'cases', tabs: [
    { id: 'alerts', label: 'Alertes', sections: ['alerts'] },
    { id: 'cases', label: 'Cas', sections: ['cases'] },
  ] },
  { id: 'dashboards', tabs: [
    { id: 'dashboards', label: 'Dashboards', sections: ['dashboards'] },
  ] },
  { id: 'detresp', tabs: [
    { id: 'detection', label: 'Détection', sections: ['coverage', 'rules'] },
    { id: 'attack', label: 'ATT&CK', sections: ['attack-panel'] }, // matrice de couverture MITRE ATT&CK (lecture viewer+) — GET /api/coverage/attack
    // C8 — Réponse scindée : Playbooks (détection -> réponse auto, + le toggle de mode) et Actions (file de riposte).
    { id: 'playbooks', label: 'Playbooks', sections: ['playbooks-panel', 'runbooks-panel'] }, // + #3 Phase 2 : authoring runbooks (admin-only, masqué au non-admin)
    { id: 'actions', label: 'Actions', sections: ['actions-panel'] },
    { id: 'risk', label: 'Risque', sections: ['risk-panel'] }, // #24 : Risk-Based Alerting — entités à risque (lecture viewer+)
    { id: 'detadv', label: 'Avancée', sections: ['detadv-panel'] }, // #37 : corrélations de séquence + baselines UEBA (lecture viewer+, CRUD éditeur+)
    { id: 'routing', label: 'Routage & silences', sections: ['routing-panel'] }, // #53 : politiques de notification + silences (lecture viewer+, CRUD éditeur+)
  ] },
  { id: 'data', tabs: [
    { id: 'sources', label: 'Sources', sections: ['sources-panel'] },
    { id: 'freshness-view', label: 'Fraîcheur', sections: ['freshness-panel'] }, // onglet SIBLING de Sources ; rend le détail complet (renderFreshness). Détail migré depuis la Vue d'ensemble (qui garde un pulse compact).
    { id: 'system', label: 'Système', sections: ['system-panel'] }, // #51 DAY-2 OPS : self-métriques + santé R/J/V par composant + (admin) bulletin/diag. LECTURE viewer+.
    { id: 'fleet', label: 'Flotte', sections: ['fleet-panel'] }, // P0 UI : inventaire des hôtes/endpoints (last-seen + statut + enrôlement). LECTURE viewer+.
    { id: 'connectors', label: 'Connecteurs', sections: ['connectors-panel'], admin: true }, // #3/#3a : sources externes en PULL (Defender) — admin-only (API 403 hors admin)
    { id: 'destinations', label: 'Destinations', sections: ['destinations-panel'], admin: true }, // #50 : sorties/forward des events vers un sink externe (syslog/HEC/webhook) — admin-only (data-exfil surface)
    { id: 'processors', label: "Processeur d'ingest", sections: ['processors-panel'], admin: true }, // #40 : pipeline filtre/masque/route/échantillon à l'ingest — admin-only
    { id: 'indexes', label: 'Indexes & rétention', sections: ['index-policies-panel'], admin: true }, // #49 : indexes logiques nommés (rétention/plafonds par env_id) — admin-only
    { id: 'parsers', label: 'Parseurs', sections: ['parsers'] },
    { id: 'lookups', label: 'Lookups', sections: ['lookups'] }, // #1c : lecture tous rôles ; CRUD éditeur/admin (viewer = lecture seule)
    { id: 'knowledge', label: 'Savoir', sections: ['knowledge-panel'] }, // #46 : objets de savoir search-time (alias/calc/eventtype/tag). Lecture viewer+ ; CRUD éditeur+ (crud-btn masqué au viewer)
    { id: 'datamodels', label: 'Modèles & Pivot', sections: ['datamodels-panel'] }, // #47 : couche sémantique + report-builder Pivot + datasets. Lecture/exécution viewer+ ; CRUD éditeur+
    { id: 'dataaccess', label: 'Accès données (DLP)', sections: ['dataaccess-view'] },
  ] },
  { id: 'admin', admin: true, tabs: [
    { id: 'settings', label: 'Compte', sections: ['settings'] },
    { id: 'users', label: 'Users', sections: ['users'] },
    { id: 'tokens', label: 'Jetons', sections: ['tokens'], admin: true }, // provisioning jetons agent/HEC (secrets) — admin-only (API 403 hors admin)
    { id: 'idp', label: 'Identité (SSO)', sections: ['idp-panel'], admin: true }, // #44 : fournisseurs OIDC/LDAP — admin-only (secrets ; API 403 hors admin)
    { id: 'fieldfilters', label: 'Field filters', sections: ['field-filter-panel'], admin: true }, // #45 : masquage PII par champ — admin-only (config qui contraint viewer/editor ; API 403 hors admin)
    { id: 'tenants', label: 'Tenants', sections: ['tenants-panel'], mtOnly: true }, // #2c : multi-tenant only (masqué en mode 0)
    { id: 'notifiers', label: 'Canaux', sections: ['notifiers'] },
    { id: 'threatintel', label: 'Threat Intel', sections: ['threatintel-panel'] }, // #23 : magasin d'IOC (couverture + liste + ajout/import) — espace admin => admin-only ; API GET viewer+ / POST admin
    { id: 'suppressions', label: 'Suppressions', sections: ['suppressions-panel'] }, // chantier whitelists→webui : panneau RO + operator/self éditable (admin)
    { id: 'retention', label: 'Rétention', sections: ['retention-panel'] },
    { id: 'ledger', label: 'Audit', sections: ['ledger-panel'] },
  ] },
  // #4c : espace Aide / Guide — documentation in-app 100% statique (sommaire des espaces + glossaire).
  // Visible pour tous les rôles ; 1 seul onglet => pas de barre de sous-onglets. Aucun appel réseau.
  { id: 'help', tabs: [
    { id: 'help', label: 'Aide', sections: ['help-panel'] },
  ] },
];
// index dérivés : id onglet -> {onglet, espace}
const TAB = {}, SPACE_OF_TAB = {}, SPACE_BY_ID = {};
SPACES.forEach(sp => { SPACE_BY_ID[sp.id] = sp; sp.tabs.forEach(t => { TAB[t.id] = t; SPACE_OF_TAB[t.id] = sp; }); });
// alias rétro-compat : anciens hash de 1er niveau -> nouvel onglet (deep-links existants conservés)
const TAB_ALIAS = { query: 'explore', notifications: 'alerts', data: 'dataaccess', response: 'playbooks' };
// un onglet est accessible si ni son espace ni lui-même ne sont admin-only quand on n'est pas admin
// (uiIsAdmin = admin per-tenant OU super-admin plateforme). #2c : un onglet `mtOnly` n'apparaît qu'en mode 1.
function tabAllowed(id) {
  const t = TAB[id], sp = SPACE_OF_TAB[id]; if (!t || !sp) return false;
  if ((sp.admin || t.admin) && !uiIsAdmin()) return false;
  if (t.mtOnly && !multiTenantMode()) return false;
  return true;
}
// onglet courant résolu (alias + repli si inaccessible/inconnu) — NE mute PAS location.hash (deep-link conservé)
function currentTab() {
  let h = location.hash.slice(1) || 'overview';
  if (!TAB[h] && TAB_ALIAS[h]) h = TAB_ALIAS[h];
  if (!TAB[h] || !tabAllowed(h)) h = 'overview';
  return h;
}
// alias historique conservé (timeZoomEnabled, refreshCurrentView) : la « vue » == l'onglet courant
function currentViewName() { return currentTab(); }
// rendu de la nav 2 niveaux : 1er niveau (espaces, sidebar) + 2e niveau (sous-onglets de l'espace actif)
function renderNav(tabId) {
  const sp = SPACE_OF_TAB[tabId] || SPACE_BY_ID.overview;
  // niveau 1 : espaces. Administration masquée hors admin ; actif = data-space de l'espace courant.
  document.querySelectorAll('#nav a[data-space]').forEach(a => {
    const spc = SPACE_BY_ID[a.dataset.space];
    a.hidden = !!(spc && spc.admin && !uiIsAdmin());
    a.classList.toggle('on', a.dataset.space === sp.id);
  });
  // niveau 2 : sous-onglets de l'espace actif (admin-only masqués hors admin ; mtOnly masqués hors mode 1). 1 onglet => pas de barre.
  const sub = $('#subnav'); if (!sub) return;
  const tabs = sp.tabs.filter(t => !(t.admin && !uiIsAdmin()) && !(t.mtOnly && !multiTenantMode()));
  if (tabs.length <= 1) { sub.hidden = true; sub.replaceChildren(); return; }
  sub.hidden = false;
  sub.replaceChildren(...tabs.map(t => {
    const a = document.createElement('a');
    a.href = '#' + t.id; a.textContent = t.label; a.dataset.tab = t.id;
    a.className = 'subtab' + (t.id === tabId ? ' on' : '');
    a.setAttribute('role', 'tab'); a.setAttribute('aria-selected', t.id === tabId ? 'true' : 'false');
    return a;
  }));
}
function showView(tabId) {
  const t = TAB[tabId]; if (!t) return;
  const secs = new Set(t.sections);
  document.querySelectorAll('main > section').forEach(s => { s.hidden = !secs.has(s.id); });
  if (!S.isAdmin && $('#users')) $('#users').hidden = true; // gestion des comptes : admin uniquement, jamais ailleurs
  // #1c : lookups lisibles par tous les rôles (GET /api/lookups ouvert) ; la section reste pilotée par showView,
  // le CRUD (bouton + delete) est masqué au viewer via CSS (role-viewer). Plus de hard-hide admin-only ici.
  renderNav(tabId);
  // barre de recherche : seulement sur Explore.
  if ($('#q')) $('#q').hidden = (tabId !== 'explore');
  // refresh auto : vues temporelles (explore/dashboards/overview).
  const refreshView = (tabId === 'explore' || tabId === 'dashboards' || tabId === 'overview');
  if ($('#refresh')) $('#refresh').hidden = !refreshView;
  // picker de plage de la NAVBAR : DASHBOARDS UNIQUEMENT. Explore a son propre picker local (#qrange) ;
  // Overview est live-only (ignore la plage). Le zoombadge global ne concerne plus que les dashboards.
  const rangeView = (tabId === 'dashboards');
  if ($('#range')) $('#range').hidden = !rangeView;
  if ($('#rangepick')) $('#rangepick').hidden = !rangeView;
  if ($('#zoombadge') && !rangeView) $('#zoombadge').hidden = true;
  if (tabId === 'detection') renderCoverage(); // panneau couverture ATT&CK rafraîchi à l'entrée (idempotent)
  if (tabId === 'attack') loadAttackMatrix(); // matrice ATT&CK rafraîchie à l'entrée (idempotent, dégrade si endpoint absent)
  if (tabId === 'playbooks') { loadPlaybooks(); loadMode(); loadRunbooks(); } // C8 — playbooks + toggle de mode ; #3 Phase 2 — authoring runbooks (admin-only) (idempotent)
  if (tabId === 'actions') loadActions(); // C8 — file de riposte rafraîchie à l'entrée (idempotent)
  if (tabId === 'alerts') renderAlerts(); // file des alertes rafraîchie à l'entrée de l'onglet
  if (tabId === 'dataaccess') renderDataAccess(); // gouvernance d'accès (lecture seule) rafraîchie à l'entrée
}

function route() {
  // reset du scroll EN TÊTE : on revient en haut à chaque changement de vue (header sticky 57px reste en
  // place) -> plus d'à-coup vers le bas hérité de la vue précédente.
  window.scrollTo(0, 0);
  const t = currentTab();
  showView(t);
  // ANTI-RÉSIDU (FOUC hard-refresh) : showView() a fixé la visibilité des sections de l'espace courant (les autres,
  // dont Administration, sont masquées) -> on révèle <main> (règle inline `html:not(.app-ready) main{visibility:hidden}`).
  // Posé ICI (avant les loaders async) : la révélation ne dépend pas du succès d'un chargement de données. Idempotent.
  document.documentElement.classList.add('app-ready');
  if (t === 'cases') loadCases();
  else if (t === 'help') renderHelpGuide();         // #4c — page Aide / Guide (statique, aucun réseau)
  else if (t === 'sources') loadSourcesView();     // #1b — inventaire des sources (tous rôles)
  else if (t === 'freshness-view') renderFreshness(); // détail complet de la fraîcheur (santé de collecte par feed), onglet Données → Fraîcheur
  else if (t === 'system') loadSystemView();       // #51 — console d'opérabilité (self-métriques + santé + admin outils)
  else if (t === 'fleet') loadFleetView();         // P0 UI — inventaire de la flotte d'agents (hôtes/endpoints, viewer+)
  else if (t === 'connectors') loadConnectors();   // #3/#3a — connecteurs de sources externes (Defender, admin-only)
  else if (t === 'destinations') loadDestinations(); // #50 — destinations de sortie (forward vers sink externe, admin-only)
  else if (t === 'processors') loadProcessors();   // #40 — processeur d'ingest (filtre/masque/route/échantillon, admin-only)
  else if (t === 'indexes') loadIndexPolicies();   // #49 — indexes logiques nommés (rétention/plafonds par index, admin-only)
  else if (t === 'threatintel') loadThreatIntel(); // #23 — magasin d'IOC (couverture + liste + ajout/import, admin-only)
  else if (t === 'knowledge') loadKnowledge();     // #46 — objets de savoir (alias/calc/eventtype/tag) — lecture viewer+, CRUD éditeur+
  else if (t === 'datamodels') loadDataModels();   // #47 — modèles de données + Pivot + datasets — lecture/exécution viewer+, CRUD éditeur+
  else if (t === 'risk') loadRiskView();           // #24 — Risk-Based Alerting : entités à risque (lecture viewer+)
  else if (t === 'detadv') loadDetAdv();           // #37 — détection avancée : corrélations + baselines UEBA
  else if (t === 'routing') loadRouting();         // #53 — politiques de notification (routage) + silences (mute)
  else if (t === 'attack') loadAttackMatrix();     // matrice de couverture MITRE ATT&CK (lecture viewer+)
  else if (t === 'suppressions') loadSuppressions(); // chantier whitelists→webui — panneau RO + operator/self éditable (admin)
  else if (t === 'retention') loadRetention();     // #1b — rétention (admin)
  else if (t === 'ledger') loadLedger();           // #1b — journal d'audit (admin) + #2c accès opérateur
  else if (t === 'tenants') loadTenantsView();     // #2c — gestion des tenants / grants (mode 1 only)
  else if (t === 'tokens') loadTokens();           // jetons agent/HEC — provisioning (admin-only)
  else if (t === 'idp') loadIdpProviders();        // #44 — fournisseurs d'identité fédérée OIDC/LDAP (admin-only)
  else if (t === 'fieldfilters') loadFieldFilters(); // #45 — field filters (masquage PII par champ, admin-only)
  if (t === 'settings') loadMfa();                 // #44 — MFA TOTP self-service (dans la section Compte, tous rôles)
}
// navigation par hash MANUELLE : preventDefault tue le scroll-into-view natif des ancres dont l'id existe
// réellement (#dashboards/#parsers/#playbooks/#cases/#settings) -> plus d'à-coup vers le bas.
function navTo(href) {
  if (!href || !href.startsWith('#')) return;
  const v = href.slice(1);
  if (location.hash.slice(1) === v) route();        // même hash : hashchange ne se déclenche pas -> route() direct
  else location.hash = v;                            // sinon hashchange -> route()
}
// niveau 1 (espaces, statiques) : clic direct ; href = 1er sous-onglet de l'espace (onglet par défaut).
// niveau 2 (sous-onglets, rendus dynamiquement) : délégation sur #subnav.
// Le burger est la SOURCE UNIQUE du repli à toute largeur. ≤1024px on démarre replié (visuel
// icônes-seules inchangé) -> le burger déplie réellement (labels + sous-onglets atteignables) ; >1024px inchangé.

function initNavigation() {
  window.addEventListener('hashchange', route);
  document.querySelectorAll('#nav a').forEach(a => a.addEventListener('click', e => { e.preventDefault(); navTo(a.getAttribute('href')); }));
  if ($('#subnav')) $('#subnav').addEventListener('click', e => { const a = e.target.closest('a'); if (!a) return; e.preventDefault(); navTo(a.getAttribute('href')); });
  { const l0 = document.querySelector('.layout'); if (l0 && window.matchMedia('(max-width:1024px)').matches) l0.classList.add('collapsed'); }
  if ($('#navtoggle')) $('#navtoggle').onclick = () => { const l = document.querySelector('.layout'); if (l) l.classList.toggle('collapsed'); };
}

export { initNavigation, SPACES, currentTab, currentViewName, renderNav, route };

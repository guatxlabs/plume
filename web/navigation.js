// Navigation à deux niveaux : le MODÈLE des espaces et de leurs sous-onglets (`SPACES`), la résolution de
// l'onglet courant depuis le hash (alias historiques, repli d'un onglet interdit ou inconnu SANS réécrire le
// lien profond), le rendu des deux niveaux et le routage vers les chargeurs de chaque vue. Extrait d'`app.js`
// par déplacement pur ; l'écoute du hash, les clics de la sidebar et des sous-onglets et le burger sont posés
// par `initNavigation()`, appelée par `app.js` au point où ce bloc vivait. `app.js` garde l'amorçage (le
// premier `route()` et les initialisations qui suivent) et ré-exporte `SPACES`, `currentTab`,
// `currentViewName`, `renderNav` et `route` pour les modules seam. N'importe pas `app.js`.
import { $ } from './core.js';
import { S } from './state.js';
import { loadDashboards, refreshPanels } from './dashboards.js';
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
import { renderFreshness, renderFreshnessPulse, renderIntegrations } from './freshness.js';
import { renderAlerts } from './alerts.js';
import { renderCoverage, loadActions, loadMode, loadNotifiers, loadParsers, loadPlaybooks, loadRules } from './detection_admin.js';
import { loadRunbooks } from './runbooks.js';
import { loadTokens, loadUsers } from './admin_users.js';
import { loadRetention } from './retention.js';
import { loadSuppressions } from './suppressions.js';
import { renderHelpGuide } from './help.js';
import { loadLookups } from './lookups.js';

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
    { id: 'dashboards', label: 'Dashboards', sections: ['dashboards'], plageGlobale: true }, // seul onglet piloté par le sélecteur de plage de la barre (Recherche a le sien, la Vue d'ensemble ignore la plage)
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
// =================================================================================================
// LE REGISTRE DES CHARGES (`P11.14-e`, `P11.17-d`).
//
// CE QU'IL REMPLACE, ET POURQUOI. Ce qui PEINT une section vivait jusqu'ici dans deux chaînes de
// conditions écrites à la main sur l'identifiant de l'onglet — l'une dans `showView`, l'autre dans
// `route`. Mesuré le 2026-08-25 sur les 37 onglets du modèle : SIX onglets n'avaient aucune charge du
// tout, l'onglet ATT&CK en avait DEUX (il figurait dans les deux chaînes, et sa matrice partait donc
// deux fois à chaque entrée), et QUATRE panneaux — dont celui des règles de détection — n'étaient
// peints qu'à l'évaluation de leur module : une lecture ratée au démarrage ne se réparait JAMAIS,
// aucun geste ne la rejouant. C'est la cause mesurée du « il faut recharger la page » de `P11.14-a`.
//
// CE QU'UNE CHARGE DÉCLARE, ET RIEN DE PLUS :
//   `cible` — l'élément qu'elle peint. L'ONGLET auquel elle appartient n'est PAS déclaré : il se
//             DÉDUIT, parce que la cible vit dans une section et que `sections` dit déjà quelle
//             section un onglet montre. Rien n'est écrit deux fois, donc rien ne peut diverger, et un
//             onglet ajouté demain hérite des charges de ses sections sans qu'on y pense.
//   `vive`  — la lecture change TOUTE SEULE (état d'un capteur, file d'alertes) et mérite donc la
//             cadence. Son absence n'est pas un oubli : une charge sans `vive` est un CATALOGUE, elle
//             rejoue à l'ENTRÉE de la vue — ce qui répare un démarrage manqué — mais pas toutes les
//             trente secondes. C'est la déclaration dont la cadence dérive son périmètre (`P11.17-a`).
//
// CE QUE CE REGISTRE EST ET N'EST PAS. Il ÉNUMÈRE ses charges, et le commentaire qui l'a précédé
// prétendait le contraire ; c'est ce mensonge que `P11.14-e` a nommé, parce qu'il éteint la vigilance
// de qui ajoute le panneau suivant. Ce qui est DÉRIVÉ ici, c'est l'APPARTENANCE d'une charge à un
// onglet et le périmètre d'un tir — jamais la liste elle-même. Une liste écrite à la main s'oublie :
// c'est pourquoi le harnais refuse qu'une section de la page ne soit peinte par aucune charge, et
// exige que celles qui n'en ont délibérément pas se déclarent ci-dessous avec leur raison.
// =================================================================================================
const CHARGES_DE_LA_CONSOLE = [
  // `pose` = la cible et la cadence se déclarent ICI, avec les autres ; la fonction qui peint est
  // attachée par le module où vit le panneau (`poserUneCharge`). La pastille de posture vit dans
  // l'en-tête, hors de <main> : aucune vue ne la montre ni ne la masque, seule la cadence la rejoue.
  { cible: 'posture', pose: true, vive: true },        // peinte par app.js (peindreLaPosture)
  { cible: 'alerts', charger: () => renderAlerts(), vive: true },
  { cible: 'firewall', pose: true, vive: true },       // peinte par app.js (renderFirewall)
  { cible: 'controls', pose: true, vive: true },       // peinte par app.js (renderControls)
  { cible: 'integrations', charger: () => renderIntegrations(), vive: true },
  { cible: 'freshness', charger: () => renderFreshnessPulse(), vive: true },
  // DEUX charges sur la même section, et c'est la distinction qui compte : la LISTE des dashboards est
  // un catalogue (elle rejoue à l'entrée, ce qui répare une lecture ratée au démarrage — elle n'avait
  // aucun autre moyen de se réparer), les DONNÉES des panneaux sont une lecture vive (cadence, et
  // déjà bornée aux panneaux chargés ET visibles par `dashboards.js`).
  { cible: 'dashview', charger: () => loadDashboards() },
  { cible: 'dashboards', charger: () => refreshPanels(), vive: true },
  { cible: 'coverage', charger: () => renderCoverage() },
  { cible: 'rules', charger: () => loadRules() },
  { cible: 'notifiers', charger: () => loadNotifiers() },
  { cible: 'routing-panel', charger: () => loadRouting() },
  { cible: 'parsers', charger: () => loadParsers() },
  { cible: 'playbooks-panel', charger: () => loadPlaybooks(), vive: true },
  { cible: 'mode-toggle', charger: () => loadMode(), vive: true },
  { cible: 'runbooks-panel', charger: () => loadRunbooks() },
  { cible: 'actions-panel', charger: () => loadActions(), vive: true },
  { cible: 'risk-panel', charger: () => loadRiskView() },
  { cible: 'knowledge-panel', charger: () => loadKnowledge() },
  { cible: 'datamodels-panel', charger: () => loadDataModels() },
  { cible: 'detadv-panel', charger: () => loadDetAdv() },
  { cible: 'attack-panel', charger: () => loadAttackMatrix() },
  { cible: 'cases', charger: () => loadCases() },
  { cible: 'settings', charger: () => loadMfa() },
  { cible: 'users', charger: () => loadUsers() },
  { cible: 'tokens', charger: () => loadTokens() },
  { cible: 'idp-panel', charger: () => loadIdpProviders() },
  { cible: 'field-filter-panel', charger: () => loadFieldFilters() },
  { cible: 'lookups', charger: () => loadLookups() },
  { cible: 'dataaccess-view', charger: () => renderDataAccess() },
  { cible: 'system-panel', charger: () => loadSystemView() },
  { cible: 'sources-panel', charger: () => loadSourcesView() },
  { cible: 'freshness-panel', charger: () => renderFreshness() },
  { cible: 'fleet-panel', charger: () => loadFleetView() },
  { cible: 'processors-panel', charger: () => loadProcessors() },
  { cible: 'index-policies-panel', charger: () => loadIndexPolicies() },
  { cible: 'connectors-panel', charger: () => loadConnectors() },
  { cible: 'destinations-panel', charger: () => loadDestinations() },
  { cible: 'suppressions-panel', charger: () => loadSuppressions() },
  { cible: 'retention-panel', charger: () => loadRetention() },
  { cible: 'ledger-panel', charger: () => loadLedger() },
  { cible: 'tenants-panel', charger: () => loadTenantsView() },
  { cible: 'threatintel-panel', charger: () => loadThreatIntel() },
  { cible: 'help-panel', charger: () => renderHelpGuide() },
];
// LES SECTIONS QU'AUCUNE CHARGE NE PEINT, ET POURQUOI. Un oubli ne doit pas pouvoir se déguiser en
// décision : le harnais refuse toute section que rien ne peint et que cette liste ne nomme pas, et il
// exige que la raison soit écrite JUSTE AU-DESSUS avec la clé de roadmap qui en a décidé — clé qu'il
// va vérifier dans l'index public. Une raison libre servirait à se rassurer ; une clé renvoie à ce qui
// a été mesuré et à ce qui a été réfuté.
//   `query` — l'éditeur de recherche, décidé par `P11.17-a`. La recherche ne part JAMAIS d'elle-même :
//   une requête lourde relancée en boucle par une console laissée ouverte est précisément le danger que
//   cette clé refuse. Elle ne part que d'un geste, et le bouton Rafraîchir est ce geste.
const SECTIONS_SANS_CHARGE = ['query'];
// ATTACHE la fonction qui peint à une charge DÉJÀ déclarée ci-dessus. Remonter ces peintres ici
// ferait de ce fichier un fourre-tout ; les déclarer ailleurs rouvrirait la divergence que ce registre
// ferme. Une cible inconnue est REFUSÉE plutôt qu'ajoutée en douce : sans cela, une faute de frappe
// créerait une charge fantôme qu'aucune section ne montre et qu'aucun témoin ne verrait.
function poserUneCharge(cible, charger) {
  const c = CHARGES_DE_LA_CONSOLE.find(x => x.cible === cible && x.pose);
  if (!c) throw new Error('charge non déclarée : ' + cible);
  c.charger = charger;
}

// AFFICHÉE = ni la cible ni aucun de ses parents ne porte `hidden`. `showView` masque les sections des
// autres onglets : c'est cette lecture-là, et non un nom d'onglet, qui donne le périmètre.
// CE QU'ELLE NE VOIT PAS, écrit ici et non passé sous silence : un masquage par FEUILLE DE STYLE
// (`display:none`) n'est pas l'attribut `hidden` — une charge masquée par ce seul moyen partirait.
function cibleAffichee(id) {
  let n = $('#' + id);
  if (!n) return false;
  for (; n && n !== document.body; n = n.parentNode) if (n.hidden) return false;
  return true;
}
function chargeAffichee(c) {
  return !!c.charger && cibleAffichee(c.cible);  // déclarée sans peintre attaché : rien à peindre
}
// DANS LA VUE = la cible vit sous <main>, donc un onglet la montre ou la masque. Hors de <main>
// (en-tête, pied de page) une cible est visible partout : elle suit la cadence, pas les entrées de vue.
function chargeDansLaVue(c) {
  for (let n = $('#' + c.cible); n && n !== document.body; n = n.parentNode) if (n.tagName === 'MAIN') return true;
  return false;
}
function chargesAffichees() { return CHARGES_DE_LA_CONSOLE.filter(chargeAffichee); }
function chargesDeLaVueAffichees() { return chargesAffichees().filter(chargeDansLaVue); }
function chargesVivesAffichees() { return chargesAffichees().filter(c => c.vive); }

// LE COUREUR, PARTAGÉ par l'entrée de vue et par la cadence — deux appelants, une seule mécanique de
// fraîcheur et de non-recouvrement (`P11.17-a`).
//   `depuis` absent  => GESTE EXPLICITE : tout part, et chaque charge est DATÉE.
//   `depuis` présent => TIR DE CADENCE : ne part pas non plus ce qu'un geste a lancé depuis cette
//                       borne. Un tir ne date rien — dater ses propres charges retournerait la règle
//                       contre elle (mesuré : un tir sur deux perdu, en silence).
// UNE CHARGE EN VOL NE REPART JAMAIS, quel que soit celui qui la demande. Ce n'est pas de la fraîcheur
// mais de la RÉENTRANCE, et elle vaut aussi pour un geste : relancer ce qui tourne déjà n'apporte rien,
// puisque la charge en cours peindra. Mesuré le 2026-08-25 en dérivant les charges de la vue : la
// charge des comptes rappelle `route()` — elle a besoin du rôle pour recomposer la navigation — et
// `route()` relance les charges de la vue, donc elle-même : RÉCURSION SANS FIN, que le harnais a
// fait apparaître aussitôt. La borne posée ici la ferme par construction, pour toutes les charges.
function lancerLesCharges(liste, depuis) {
  const cadence = typeof depuis === 'number';
  const partantes = liste.filter(c => !c._enVol && (!cadence || !(c._demande > depuis)));
  const promesses = partantes.map(c => {
    if (!cadence) c._demande = Date.now();
    c._enVol = true;
    return Promise.resolve().then(c.charger).finally(() => { c._enVol = false; });
  });
  // L'ÉCHEC D'UNE CHARGE SE DIT, QUEL QUE SOIT CELUI QUI L'A LANCÉE. Écrit ICI et non chez l'appelant :
  // seule la cadence avait un `catch` qui portait l'aveu au pied de page ; une charge lancée à l'entrée
  // d'une vue échouait donc EN SILENCE — et un `Promise.all` non rattrapé aurait fait pire, un rejet
  // non traité qui n'affiche rien du tout. `allSettled` : une charge qui échoue n'empêche pas les
  // autres de peindre, et la première cause est celle qu'on nomme.
  return Promise.allSettled(promesses).then(bilans => {
    const rate = bilans.find(b => b.status === 'rejected');
    const st = $('#status');
    if (st && partantes.length) st.textContent = rate ? ('hors-ligne (' + ((rate.reason && rate.reason.message) || rate.reason) + ')') : 'connecté';
    return partantes.length;
  });
}

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
  // Barre de recherche de l'en-tête : c'est un RACCOURCI vers l'éditeur de requête, donc elle se montre
  // là où l'éditeur est affiché. Lu sur le document, pas sur un nom d'onglet.
  if ($('#q')) $('#q').hidden = !cibleAffichee('sql');
  // `P11.17-d` — LE SÉLECTEUR DE CADENCE SE MONTRE LÀ OÙ LA CADENCE A QUELQUE CHOSE À FAIRE, et cela
  // se DÉDUIT : il apparaît si la vue courante affiche au moins une charge déclarée VIVE. Le triplet
  // qu'il remplace (`explore || dashboards || overview`) était écrit à la main, il CONTENAIT la
  // recherche — la vue même où l'exploitant ne veut pas de cadence — et il manquait les vues qui en
  // ont une (alertes, playbooks, actions). Retirer le contrôle plutôt que le dériver l'aurait laissé
  // visible partout, y compris là où rien ne se rafraîchit : un contrôle qui ment sur ce qu'il pilote.
  // La pastille de posture, hors de <main>, ne compte pas : elle ne dépend d'aucune vue.
  if ($('#refresh')) $('#refresh').hidden = !chargesDeLaVueAffichees().some(c => c.vive);
  // Sélecteur de plage de la BARRE : l'onglet DÉCLARE s'il est piloté par elle (`plageGlobale`), au
  // lieu d'être nommé ici. La Recherche a son propre sélecteur local, la Vue d'ensemble ignore la plage.
  const rangeView = !!t.plageGlobale;
  if ($('#range')) $('#range').hidden = !rangeView;
  if ($('#rangepick')) $('#rangepick').hidden = !rangeView;
  if ($('#zoombadge') && !rangeView) $('#zoombadge').hidden = true;
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
  // `P11.17-d` — L'ENTRÉE DANS UNE VUE REJOUE LES CHARGES DE CETTE VUE, et lesquelles se DÉDUIT :
  // `showView` vient de masquer les sections des autres onglets, donc « affichée » désigne exactement
  // ce que cet onglet montre. La chaîne de conditions qui vivait ici égrenait un identifiant d'onglet
  // par ligne ; elle avait OUBLIÉ six onglets, en avait servi un DEUX FOIS, et laissait quatre
  // panneaux sans aucun moyen de se réparer après une lecture ratée au démarrage (`P11.14-e`).
  // Rejouer est un GESTE de l'exploitant : les charges sont datées, et un tir de cadence qui suivrait
  // aussitôt ne les doublera pas.
  lancerLesCharges(chargesDeLaVueAffichees());
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

export { CHARGES_DE_LA_CONSOLE, SECTIONS_SANS_CHARGE, chargesAffichees, chargesDeLaVueAffichees, chargesVivesAffichees, cibleAffichee, initNavigation, lancerLesCharges, poserUneCharge, SPACES, currentTab, currentViewName, renderNav, route };

// Navigation à deux niveaux : le MODÈLE des espaces et de leurs sous-onglets (`SPACES`), la résolution de
// l'onglet courant depuis le hash (alias historiques, repli d'un onglet interdit ou inconnu SANS réécrire le
// lien profond), le rendu des deux niveaux et le routage vers les chargeurs de chaque vue. Extrait d'`app.js`
// par déplacement pur ; l'écoute du hash, les clics de la sidebar et des sous-onglets et le burger sont posés
// par `initNavigation()`, appelée par `app.js` au point où ce bloc vivait. `app.js` garde l'amorçage (le
// premier `route()` et les initialisations qui suivent) et ré-exporte `SPACES`, `currentTab`,
// `currentViewName`, `renderNav` et `route` pour les modules seam. N'importe pas `app.js`.
// Ce module porte aussi LE NOM D'UNE DESTINATION (`P11.18-o`) : il ne l'écrit pas, il le DÉRIVE de la
// page — titre du panneau, ou lien de barre latérale quand l'espace n'a qu'un onglet — et le pose là
// où il manque. Voir le bloc de nommage sous `SPACES`.
import { $, LANG } from './core.js';
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
// `P11.18-o` — CE MARQUEUR EST LA DÉCLARATION D'UN NOM NON ÉCRIT. Un onglet porte toujours un
// `label` — c'est ce qui le distingue d'un espace, pour ce module comme pour la garde de surface
// d'exploitation — mais le nom lui-même n'est PAS recopié ici : il est DÉRIVÉ de la destination, plus
// bas, par `nomDeLaDestination`. Un onglet qui écrit un vrai libellé déclare, par ce seul fait, qu'il
// est un GROUPE que nul panneau unique ne nomme.
const NOM_DERIVE = '';
const SPACES = [
  { id: 'overview', tabs: [
    { id: 'overview', label: NOM_DERIVE, sections: ['firewall', 'controls', 'integrations', 'freshness'] },
  ] },
  { id: 'search', tabs: [
    { id: 'explore', label: NOM_DERIVE, sections: ['query'] },
  ] },
  { id: 'cases', tabs: [
    { id: 'alerts', label: NOM_DERIVE, sections: ['alerts'] },
    { id: 'cases', label: NOM_DERIVE, sections: ['cases'] },
  ] },
  { id: 'dashboards', tabs: [
    { id: 'dashboards', label: NOM_DERIVE, sections: ['dashboards'], plageGlobale: true }, // seul onglet piloté par le sélecteur de plage de la barre (Recherche a le sien, la Vue d'ensemble ignore la plage)
  ] },
  { id: 'detresp', tabs: [
    { id: 'detection', label: 'Détection', sections: ['coverage', 'rules'] },
    { id: 'attack', label: NOM_DERIVE, sections: ['attack-panel'] }, // matrice de couverture MITRE ATT&CK (lecture viewer+) — GET /api/coverage/attack
    // C8 — Réponse scindée : Playbooks (détection -> réponse auto, + le toggle de mode) et Actions (file de riposte).
    { id: 'playbooks', label: 'Playbooks', sections: ['playbooks-panel', 'runbooks-panel'] }, // + #3 Phase 2 : authoring runbooks (admin-only, masqué au non-admin)
    { id: 'actions', label: NOM_DERIVE, sections: ['actions-panel'] },
    { id: 'risk', label: NOM_DERIVE, sections: ['risk-panel'] }, // #24 : Risk-Based Alerting — entités à risque (lecture viewer+)
    { id: 'detadv', label: NOM_DERIVE, sections: ['detadv-panel'] }, // #37 : corrélations de séquence + baselines UEBA (lecture viewer+, CRUD éditeur+)
    { id: 'routing', label: NOM_DERIVE, sections: ['routing-panel'] }, // #53 : politiques de notification + silences (lecture viewer+, CRUD éditeur+)
  ] },
  { id: 'data', tabs: [
    { id: 'sources', label: NOM_DERIVE, sections: ['sources-panel'] },
    { id: 'freshness-view', label: NOM_DERIVE, sections: ['freshness-panel'] }, // onglet SIBLING de Sources ; rend le détail complet (renderFreshness). Détail migré depuis la Vue d'ensemble (qui garde un pulse compact).
    { id: 'system', label: NOM_DERIVE, sections: ['system-panel'] }, // #51 DAY-2 OPS : self-métriques + santé R/J/V par composant + (admin) bulletin/diag. LECTURE viewer+.
    { id: 'fleet', label: NOM_DERIVE, sections: ['fleet-panel'] }, // P0 UI : inventaire des hôtes/endpoints (last-seen + statut + enrôlement). LECTURE viewer+.
    { id: 'connectors', label: NOM_DERIVE, sections: ['connectors-panel'], admin: true }, // #3/#3a : sources externes en PULL (Defender) — admin-only (API 403 hors admin)
    { id: 'destinations', label: NOM_DERIVE, sections: ['destinations-panel'], admin: true }, // #50 : sorties/forward des events vers un sink externe (syslog/HEC/webhook) — admin-only (data-exfil surface)
    { id: 'processors', label: NOM_DERIVE, sections: ['processors-panel'], admin: true }, // #40 : pipeline filtre/masque/route/échantillon à l'ingest — admin-only
    { id: 'indexes', label: NOM_DERIVE, sections: ['index-policies-panel'], admin: true }, // #49 : indexes logiques nommés (rétention/plafonds par env_id) — admin-only
    { id: 'parsers', label: NOM_DERIVE, sections: ['parsers'] },
    { id: 'lookups', label: NOM_DERIVE, sections: ['lookups'] }, // #1c : lecture tous rôles ; CRUD éditeur/admin (viewer = lecture seule)
    { id: 'knowledge', label: NOM_DERIVE, sections: ['knowledge-panel'] }, // #46 : objets de savoir search-time (alias/calc/eventtype/tag). Lecture viewer+ ; CRUD éditeur+ (crud-btn masqué au viewer)
    { id: 'datamodels', label: NOM_DERIVE, sections: ['datamodels-panel'] }, // #47 : couche sémantique + report-builder Pivot + datasets. Lecture/exécution viewer+ ; CRUD éditeur+
    { id: 'dataaccess', label: NOM_DERIVE, sections: ['dataaccess-view'] },
  ] },
  { id: 'admin', admin: true, tabs: [
    { id: 'settings', label: NOM_DERIVE, sections: ['settings'] },
    { id: 'users', label: NOM_DERIVE, sections: ['users'] },
    { id: 'tokens', label: NOM_DERIVE, sections: ['tokens'], admin: true }, // provisioning jetons agent/HEC (secrets) — admin-only (API 403 hors admin)
    { id: 'idp', label: NOM_DERIVE, sections: ['idp-panel'], admin: true }, // #44 : fournisseurs OIDC/LDAP — admin-only (secrets ; API 403 hors admin)
    { id: 'fieldfilters', label: NOM_DERIVE, sections: ['field-filter-panel'], admin: true }, // #45 : masquage PII par champ — admin-only (config qui contraint viewer/editor ; API 403 hors admin)
    { id: 'tenants', label: NOM_DERIVE, sections: ['tenants-panel'], mtOnly: true }, // #2c : multi-tenant only (masqué en mode 0)
    { id: 'notifiers', label: NOM_DERIVE, sections: ['notifiers'] },
    { id: 'threatintel', label: NOM_DERIVE, sections: ['threatintel-panel'] }, // #23 : magasin d'IOC (couverture + liste + ajout/import) — espace admin => admin-only ; API GET viewer+ / POST admin
    { id: 'suppressions', label: NOM_DERIVE, sections: ['suppressions-panel'] }, // chantier whitelists→webui : panneau RO + operator/self éditable (admin)
    { id: 'retention', label: NOM_DERIVE, sections: ['retention-panel'] },
    { id: 'ledger', label: NOM_DERIVE, sections: ['ledger-panel'] },
  ] },
  // #4c : espace Aide / Guide — documentation in-app 100% statique (sommaire des espaces + glossaire).
  // Visible pour tous les rôles ; 1 seul onglet => pas de barre de sous-onglets. Aucun appel réseau.
  { id: 'help', tabs: [
    { id: 'help', label: NOM_DERIVE, sections: ['help-panel'] },
  ] },
];
// =================================================================================================
// `P11.18-o` — UN NOM DÉSIGNE UNE CHOSE, ET C'EST LE MÊME PARTOUT OÙ L'ON Y RENVOIE.
//
// CE QUI A ÉTÉ MESURÉ (2026-08-25), et qui n'était pas une exception mais la règle. Sur les 34 onglets
// qui ouvrent UN SEUL panneau, 31 portaient un libellé DIFFÉRENT du titre de ce panneau : qui cherchait
// « Inventaire des sources » devait deviner « Sources », « Comptes & accès » devait deviner « Users ».
// Et DEUX sections portaient le MÊME titre de niveau deux — la vignette de fraîcheur de la Vue
// d'ensemble et le panneau de fraîcheur —, si bien qu'un même nom désignait deux endroits.
//
// LA PROPRIÉTÉ EST TENUE PAR CONSTRUCTION, PAS PAR RELECTURE. `P11.18-e` l'a tenue sur les renvois en
// ôtant le libellé du renvoi : il est DÉRIVÉ de la destination, et une destination que la table ne
// nomme pas est rendue AVEC SON AVEU. Ici le geste est le même, un cran plus haut : un libellé
// d'onglet n'est plus écrit, il est DÉRIVÉ. Corriger les 31 écarts à la main aurait laissé le 32e
// s'écrire dès le prochain panneau.
//
// OÙ LE NOM S'ÉCRIT — UNE SEULE RÈGLE, ET ELLE SUIT LÀ OÙ LE NOM EST PERMANENT :
//   * un onglet qui ouvre UN SEUL panneau -> le nom est le TITRE DE CE PANNEAU (ce qu'on trouve à
//     l'arrivée) ; le libellé de l'onglet en dérive ;
//   * un espace qui n'a QU'UN onglet n'affiche aucune barre de sous-onglets : son lien de barre
//     latérale est alors le seul nom permanent, donc c'est LUI qui nomme, et le titre du panneau en
//     dérive (`nommerLesPanneaux`). C'est ce qui ferme le troisième écart mesuré : la barre latérale
//     nommait une destination par son ESPACE pendant que le panneau s'appelait autrement — l'éditeur
//     de requête s'annonçait « Plume panel » sous un lien « Recherche » ;
//   * un onglet qui montre PLUSIEURS sections est lui-même un GROUPE, comme un espace : il n'y a pas
//     de panneau unique à nommer, il déclare donc son libellé (`label`) — deux cas, Détection et
//     Playbooks, et la garde du lexique les voit comme des libellés affichés ;
//   * rien de tout cela -> AVEU. Une destination sans nom est rendue en le disant, jamais en silence.
//
// POURQUOI LE NOM EST LU SUR LE DOCUMENT ET NON RECOPIÉ ICI. Recopier les 34 titres dans une table de
// ce module rouvrirait exactement le défaut : deux endroits où le même nom s'écrit, donc deux endroits
// qui peuvent diverger. La page est la source, et le lexique fr/en la couvre déjà — un libellé dérivé
// est donc traduit par le MÊME chemin que le titre dont il vient, sans une seule entrée de plus.
// CE QUE CE MÉCANISME NE TIENT PAS, écrit plutôt que tu : il ne rend pas DEUX panneaux incapables de
// porter le même titre. Il retire les deux sources de divergence mesurées (le libellé recopié, la
// vignette qui usurpait le nom de son panneau) ; un titre écrit deux fois dans la page resterait un
// défaut de relecture.
// =================================================================================================

// Le nom qu'un PANNEAU se donne : le texte de son titre de niveau deux, GESTES EXCLUS. Le « ? » de
// l'aide et les boutons d'outil vivent DANS le titre sans en faire partie ; les lire ferait entrer un
// point d'interrogation dans le libellé de l'onglet. Rendu vide si la page ne porte pas ce panneau ou
// si son titre n'est pas écrit : c'est l'appelant qui décide quoi en faire, la lecture n'invente rien.
function nomEcritSurLePanneau(idSection) {
  const h = document.querySelector('#' + idSection + ' h2');
  if (!h) return '';
  return Array.from(h.childNodes || [])
    .filter(n => n && !n.tagName)
    .map(n => String(n.textContent || ''))
    .join('')
    .replace(/\s+/g, ' ')
    .trim();
}

// Le nom qu'un ESPACE porte dans la barre latérale (le libellé du lien, l'icône exclue).
function nomEcritSurLaBarreLaterale(idEspace) {
  const a = $('#nav a[data-space="' + idEspace + '"]');
  const s = a && a.querySelector ? a.querySelector('span') : null;
  return s ? String(s.textContent || '').replace(/\s+/g, ' ').trim() : '';
}

// L'AVEU — même forme que celui des renvois (`P11.18-e`) : une destination que rien ne nomme est
// rendue avec son identifiant et le mot qui dit qu'elle n'est pas nommée. C'est ce qui oblige la
// prochaine destination à se déclarer au lieu de se fondre dans la surface.
function aveuDeDestinationNonNommee(cle) {
  return '« ' + cle + ' » ' + (LANG === 'en' ? '(destination not named)' : '(destination non nommée)');
}

// LE NOM D'UNE DESTINATION, DÉRIVÉ — l'ordre suit la règle écrite ci-dessus.
function nomDeLaDestination(sp, t) {
  if (t.sections.length === 1) {
    const n = nomEcritSurLePanneau(t.sections[0]);
    if (n) return n;
  }
  if (sp.tabs.length === 1) {
    const n = nomEcritSurLaBarreLaterale(sp.id);
    if (n) return n;
  }
  if (t.label) return t.label;                 // GROUPE déclaré (plusieurs sections, espace partagé)
  return aveuDeDestinationNonNommee(t.id);
}

// ÉCRIT le titre d'une section SANS toucher aux gestes qu'il porte : le bouton d'aide et les outils
// restent, à leur rang, après le nom. Les morceaux sont posés en nœuds texte SÉPARÉS parce que le
// lexique traduit un nœud dont la valeur ENTIÈRE est une clé : un nom collé à son complément ne serait
// plus traduisible, alors que le nom seul l'est déjà — et le complément, lui, est bilingue par
// construction. Un blanc sépare le dernier morceau du premier geste.
function ecrireLeTitre(h, morceaux) {
  const gestes = Array.from(h.childNodes || []).filter(n => n && n.tagName);
  const noeuds = morceaux.filter(m => m !== '' && m != null).map(m => document.createTextNode(m));
  if (noeuds.length && gestes.length) noeuds.push(document.createTextNode(' '));
  h.replaceChildren(...noeuds, ...gestes);
}

// UN PANNEAU QUI NE SE NOMME PAS LUI-MÊME REÇOIT LE NOM DE SA DESTINATION. Aucun titre n'est ÉCRASÉ :
// là où la page écrit un nom, elle reste la source. C'est le cas des espaces à un seul onglet, dont le
// nom permanent est le lien de la barre latérale.
function nommerLesPanneaux() {
  SPACES.forEach(sp => sp.tabs.forEach(t => {
    if (t.sections.length !== 1) return;
    if (nomEcritSurLePanneau(t.sections[0])) return;
    const h = document.querySelector('#' + t.sections[0] + ' h2');
    if (h) ecrireLeTitre(h, [t.label]);
  }));
}

// UNE VIGNETTE N'EST PAS SA DESTINATION. Une section qui déclare `data-resume-de` RÉSUME un panneau :
// elle en porte le nom — DÉRIVÉ de ce panneau, jamais recopié — suivi du mot qui dit qu'elle n'en est
// que le résumé. Sans cela deux endroits portent le même nom et le lecteur croit avoir déjà vu ce qui
// l'attend ailleurs : c'est le défaut mesuré sur la fraîcheur (la vignette de la Vue d'ensemble et le
// panneau de Données -> Fraîcheur s'appelaient tous deux « Fraîcheur des sources »).
function nommerLesResumes() {
  document.querySelectorAll('section[data-resume-de]').forEach(sec => {
    const cible = sec.getAttribute('data-resume-de');
    const h = sec.querySelector ? sec.querySelector('h2') : null;
    if (!h) return;
    const nom = nomEcritSurLePanneau(cible);
    if (nom) ecrireLeTitre(h, [nom, LANG === 'en' ? ' — summary' : ' — résumé']);
    else ecrireLeTitre(h, [aveuDeDestinationNonNommee(cible)]);
  });
}

// LA DÉRIVATION, UNE FOIS, À L'ÉVALUATION DU MODULE. Le libellé doit être une donnée du modèle (la
// navigation le rend, et le banc le lit comme tel) : il est donc POSÉ ici, pas calculé à chaque rendu.
// Le document est déjà analysé quand ce module s'évalue — la console charge `app.js` en fin de corps.
SPACES.forEach(sp => sp.tabs.forEach(t => { t.label = nomDeLaDestination(sp, t); }));
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
  // LES NOMS AVANT TOUT RENDU (`P11.18-o`) : un panneau qui ne se nomme pas lui-même et une vignette
  // qui résume une destination reçoivent leur nom AVANT que la marche du lexique ne passe (`app.js`
  // pose l'observateur plus loin), pour qu'il soit traduit par le même chemin que les titres écrits.
  nommerLesPanneaux();
  nommerLesResumes();
  window.addEventListener('hashchange', route);
  document.querySelectorAll('#nav a').forEach(a => a.addEventListener('click', e => { e.preventDefault(); navTo(a.getAttribute('href')); }));
  if ($('#subnav')) $('#subnav').addEventListener('click', e => { const a = e.target.closest('a'); if (!a) return; e.preventDefault(); navTo(a.getAttribute('href')); });
  { const l0 = document.querySelector('.layout'); if (l0 && window.matchMedia('(max-width:1024px)').matches) l0.classList.add('collapsed'); }
  if ($('#navtoggle')) $('#navtoggle').onclick = () => { const l = document.querySelector('.layout'); if (l) l.classList.toggle('collapsed'); };
}

export { CHARGES_DE_LA_CONSOLE, SECTIONS_SANS_CHARGE, chargesAffichees, chargesDeLaVueAffichees, chargesVivesAffichees, cibleAffichee, initNavigation, lancerLesCharges, poserUneCharge, SPACES, currentTab, currentViewName, nomEcritSurLePanneau, nomEcritSurLaBarreLaterale, nommerLesPanneaux, nommerLesResumes, renderNav, route };

import {
  $, CSSV, socTZ, LANG, LOC, tzOpts, fmtTs, SEV, sev, bool, esc, ICONS, ic, closeModals, withBusy, toast, showErr, modal, confirmModal, csvCell, downloadText, tsSlug, exportPDF, exportBar, closeMiniMenu, api, apiSend, muted, colComparator, pageNums, pagedList,
  setSocTZ,
  socIsAdmin, formMsg,
  confirmWithConsequence, disclosure,
  ouvrirLaModaleDePlage
} from './core.js';
import { installI18nObserver } from './i18n_observer.js';
import { S, ecrireDansLeStockageDuSite, ecrireSansDireLeRefus, lireLeStockageDuSite } from './state.js';
import { banIp, clearDrillCrumb, clearZoom, evLoad, exploreFrom, exploreTo, qHistGo, renderViz, runQuery, setZoom, stopExplore, updateZoomBadge } from './viz.js';
import { initDashboards, loadDashboard, loadDashboards, refreshPanels } from './dashboards.js';
import { initLookups } from './lookups.js';
import { loadFleetView } from './fleet.js';
import { chargesAffichees, chargesVivesAffichees, cibleAffichee, initNavigation, lancerLesCharges, poserUneCharge, SPACES, currentTab, currentViewName, renderNav, route } from './navigation.js';
import { initAuthGate, fetchMe, setAuthUI } from './login.js';
import { loadSourcesView } from './sources.js';
import { loadSystemView } from './system.js'; // #51 DAY-2 OPS — console d'opérabilité + bandeau MOTD
import { loadLedger } from './audit.js';
import { applyConnectorType, loadConnectors, openConnectorForm, httpPullFormConfig, addFieldMapRow, addStMapRow, previewHttpPull, openPresetPicker } from './connectors.js';
import { loadDestinations, openDestinationForm } from './destinations.js';
import { loadProcessors, openProcessorForm } from './processors.js';
import { loadIndexPolicies, openIndexPolicyForm } from './index_policies.js';
import { initThreatIntel } from './threatintel.js';
import { loadRiskView } from './risk.js';
import { loadDetAdv } from './detadv.js';
import { loadAttackMatrix } from './attack.js';
import { initSigmaImport } from './sigmaimport.js';
import { loadOperatorAudit, loadTenantsView } from './multitenant.js';
import { addToCase, canEditCases, createCase, loadCases, openCase } from './cases.js';
import { prefGet, prefSet, prefsReady } from './prefs.js'; // #62 — préférences utilisateur self-scoped (favoris, réglages par vue, plage par défaut)
import { initKeyboardNav } from './keys.js'; // #62 — navigation clavier (/, g+touche, j/k, ?) non-intrusive
import { initSoqlComplete } from './soql_complete.js'; // complétion IDE-like NATIVE de la barre Explore (schema/templates)
import { initSavedQueries } from './savedqueries.js'; // requêtes GXQL nommées per-user (owner-scoped) + historique récent (localStorage)
import { renderFreshness } from './freshness.js'; // découpe par concern (le pulse et les intégrations sont des charges du registre)
import { setAlertMitreFilter, setAlertSourceFilter } from './alerts.js'; // decoupe par concern (alerts ; la liste est une charge du registre)
import { loadActions } from './detection_admin.js';   // ré-exporté pour les modules seam ; les autres charges passent par le registre
import { ROLE_LABEL, loadUsers } from './admin_users.js';
import { openHelpModal, openFreshnessHelp } from './help.js'; // #4c — aide in-app (split H1) : page Aide + modales GXQL/Fraîcheur, câblage #qhelp/#fresh-help ci-dessous


// --- authentification (form-login) + CSRF -------------------------------------------------------
// État d'auth renseigné par GET /api/me : {user, role, auth_method, csrf_token}. null = non authentifié.
// auth_method ∈ {cookie, basic, sso, bearer, demo}. Le CSRF n'est requis QU'en session cookie côté daemon.
/* state: AUTH -> S (state.js) */
// #2c multi-tenant : tenant courant du SOC (client sélectionné via le switcher). '' = aucun (mode 0 /
// mono-tenant / avant résolution) -> AUCUN entête X-Plume-Tenant posé -> résolution serveur par défaut
// -> INVARIANT mode 0 strictement préservé. Ne devient non vide QU'EN mode 1, après initTenants().
/* state: CURRENT_TENANT -> S (state.js) */
/* state: MY_TENANTS -> S (state.js) */ // cache de GET /api/my-tenants (null = pas encore chargé) — pilote le gating UI multi-tenant.
// #2d environnement courant (prod/staging/site…) DANS le tenant. '' = « Tous » : AUCUN entête X-Plume-Env,
// aucun filtre -> INVARIANT mono-env / mode 0 strictement préservé (le serveur renvoie un unique env `prod`
// en mode 0 -> sélecteur caché, CURRENT_ENV reste '' ). Ne devient non vide QUE si le tenant courant expose
// > 1 environnement (initEnvironments) ET qu'un env précis est sélectionné.
/* state: CURRENT_ENV -> S (state.js) */
function getCookie(name) {
  const m = document.cookie.match('(?:^|; )' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)');
  return m ? decodeURIComponent(m[1]) : '';
}
// Token CSRF : priorité au /api/me, sinon cookie lisible plume_csrf (les deux sont équivalents).
function csrfToken() { return (S.AUTH && S.AUTH.csrf_token) || getCookie('plume_csrf') || ''; }
// Endpoints exemptés de CSRF : POST de LECTURE (query/search/cancel — cf. daemon) + auth publique
// (login/logout). Doit refléter `readonly_post` côté Rust pour ne PAS poser de header inutile.
const CSRF_EXEMPT = new Set(['/api/query', '/api/search', '/api/cancel', '/api/export', '/api/login', '/api/logout']);
// Mutation = méthode non sûre (POST/PUT/DELETE/PATCH) HORS endpoints de lecture/auth ci-dessus.
function isMutation(method, path) {
  const m = (method || 'GET').toUpperCase();
  if (m === 'GET' || m === 'HEAD' || m === 'OPTIONS') return false;
  return !CSRF_EXEMPT.has(path);
}

// --- voyant de chargement GLOBAL : barre de progression fine pilotée par le nombre de requêtes réseau
// EN VOL. On enveloppe window.fetch une seule fois -> couvre TOUS les appels (overview, panneaux,
// freshness, explore, intégrations, POST d'actions, dashboards…), pas seulement api(). Discret : barre
// animée tant que le compteur > 0. Indépendant du bouton STOP de l'Explore (qui, lui, ANNULE une requête
// précise) : ici on ne fait qu'indiquer l'activité réseau.
/* state: _netInflight -> S (state.js) */
function _netProgEl() {
  let el = document.getElementById('netprog');
  if (!el) { el = document.createElement('div'); el.id = 'netprog'; el.hidden = true; el.setAttribute('aria-hidden', 'true'); (document.body || document.documentElement).appendChild(el); }
  return el;
}
function _netProgSync() { _netProgEl().hidden = S._netInflight <= 0; }
if (typeof window !== 'undefined' && typeof window.fetch === 'function' && !window._netFetchWrapped) {
  const _origFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    // CSRF (item 4) : on AJOUTE X-CSRF-Token aux requêtes MUTANTES (POST/PUT/DELETE hors lectures).
    // Inoffensif en SSO/Basic/Bearer (csrfToken() vide -> header non posé ; le daemon n'exige le CSRF
    // qu'en session cookie). Best-effort : ne JAMAIS faire échouer une requête à cause du wiring CSRF.
    try {
      const method = (init && init.method) || (input && typeof input !== 'string' && input.method) || 'GET';
      const rawUrl = typeof input === 'string' ? input : (input && input.url) || '';
      const path = rawUrl.split('?')[0].replace(/^[a-z]+:\/\/[^/]+/i, '');
      if (isMutation(method, path)) {
        const tok = csrfToken();
        if (tok) {
          init = Object.assign({}, init);
          const h = new Headers((init.headers) || (typeof input !== 'string' && input && input.headers) || undefined);
          if (!h.has('X-CSRF-Token')) h.set('X-CSRF-Token', tok);
          init.headers = h;
        }
      }
      // #2c multi-tenant : pose X-Plume-Tenant sur les requêtes /api quand un tenant est sélectionné (switcher).
      // CURRENT_TENANT ne devient non vide QU'EN mode 1 (initTenants) -> en mode 0 l'entête n'est JAMAIS posé
      // (et le serveur l'ignore de toute façon en mode 0) -> comportement STRICTEMENT identique. Les routes de
      // gestion (/api/tenants*) l'ignorent côté serveur (tenant résolu du chemin) -> pose inoffensive.
      if (S.CURRENT_TENANT && /^\/api\//.test(path)) {
        init = Object.assign({}, init);
        const th = new Headers((init.headers) || (typeof input !== 'string' && input && input.headers) || undefined);
        if (!th.has('X-Plume-Tenant')) th.set('X-Plume-Tenant', S.CURRENT_TENANT);
        init.headers = th;
      }
      // #2d environnement : pose X-Plume-Env sur les requêtes /api quand un env PRÉCIS est sélectionné.
      // CURRENT_ENV ne devient non vide QUE si le tenant expose > 1 env (initEnvironments) -> mono-env / mode 0
      // = entête JAMAIS posé (et le serveur l'ignore hors multi_tenant) -> comportement STRICTEMENT identique.
      // « Tous » (CURRENT_ENV vide) = pas d'entête = agrégat de tous les environnements.
      if (S.CURRENT_ENV && /^\/api\//.test(path)) {
        init = Object.assign({}, init);
        const eh = new Headers((init.headers) || (typeof input !== 'string' && input && input.headers) || undefined);
        if (!eh.has('X-Plume-Env')) eh.set('X-Plume-Env', S.CURRENT_ENV);
        init.headers = eh;
      }
    } catch (e) { /* CSRF/tenant/env best-effort : on n'altère pas la requête en cas d'imprévu */ }
    S._netInflight++; _netProgSync();
    return _origFetch(input, init).finally(() => { S._netInflight = Math.max(0, S._netInflight - 1); _netProgSync(); });
  };
  window._netFetchWrapped = true;
}

// EXPORT EXPLORE : re-exécute la requête courante côté serveur (/api/export) pour le JEU COMPLET borné,
// puis télécharge. Même dérivation GXQL/SQL-brut que runQuery (le SQL brut non-admin est refusé côté serveur).
async function exploreExport(format) {
  const q = ($('#sql') && $('#sql').value.trim()) || '';
  if (!q) { toast('Aucune requête à exporter', 'info'); return; }
  const isSoql = /^\s*search\b/i.test(q) || q.includes('|');
  if (!isSoql && !socIsAdmin()) { toast("SQL brut réservé à l'administrateur — utilisez GXQL", 'bad'); return; }
  const body = isSoql ? { soql: q } : { sql: q };
  body.from = exploreFrom(); body.to = exploreTo(); body.format = format; body.name = 'explore';
  let r;
  try { r = await fetch('/api/export', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); }
  catch (e) { toast('Export échoué : ' + e.message, 'bad'); return; }
  if (!r.ok) { let m = ''; try { m = (await r.json()).error || ''; } catch (_) {} toast('Export refusé' + (m ? ' : ' + m : ' (' + r.status + ')'), 'bad'); return; }
  const text = await r.text();
  const trunc = r.headers.get('x-plume-truncated') === '1';
  // P7.3-b — LE NOM DU FICHIER PORTE L'AVEU. Le serveur le met déjà dans son `Content-Disposition`,
  // mais CE client ne le lit pas : il refabrique le nom ici, donc c'est ICI que l'aveu doit être
  // reposé — sinon le fichier qui atterrit sur le disque de l'analyste reste d'apparence complète,
  // et le toast qui l'accompagnait aura disparu bien avant qu'on rouvre le fichier.
  // P7.3-c — avec son AMPLEUR quand le serveur a su la mesurer, « ampleur inconnue » sinon : on ne
  // fabrique pas un chiffre qu'on n'a pas.
  const ecartes = parseInt(r.headers.get('x-plume-truncated-ecartes') || '', 10);
  const marque = !trunc ? '' : (Number.isFinite(ecartes) && ecartes > 0 ? `-TRONQUE-${ecartes}-lignes-manquantes` : '-TRONQUE-ampleur-inconnue');
  downloadText(`plume-explore-${tsSlug()}${marque}.${format}`, format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json', text);
  const combien = Number.isFinite(ecartes) && ecartes > 0 ? ` — ${ecartes} ligne(s) manquante(s)` : ' — ampleur non mesurée par le serveur (plafond de lignes) : resserrez la fenêtre pour un export complet';
  toast('Export ' + format.toUpperCase() + ' téléchargé' + (trunc ? ` (TRONQUÉ${combien})` : ''), trunc ? 'info' : 'ok');
}


// =================================================================================================
// `P11.17-a` / `P11.14-e` — CE QU'UNE CADENCE A LE DROIT DE RELANCER.
//
// LE CHEMIN QUI ÉTAIT OUVERT, MESURÉ LE 2026-08-25. Un unique minuteur global relançait la MÊME
// batterie de NEUF appels toutes les 30 s (valeur par défaut du sélecteur), à l'identique sur les neuf
// vues mesurées — Recherche et Aide comprises, alors qu'AUCUNE des cartes peintes par ces neuf appels
// n'y est affichée. `showView()` déclarait déjà l'intention (« refresh auto : vues temporelles ») mais
// ne l'appliquait qu'au SÉLECTEUR : le contrôle disparaissait de la barre, le minuteur, lui, continuait
// de tirer. Le geste existait ; il était posé sur l'affichage du contrôle et non sur la boucle.
//
// OÙ VIT LA DÉCLARATION, ET POURQUOI PAS ICI. Le premier correctif a posé dans ce fichier une liste de
// neuf cibles dont le commentaire affirmait qu'elle « rend le périmètre dérivable ». C'était faux, et
// `P11.14-e` l'a nommé : la liste ÉNUMÉRAIT, quatre panneaux frères n'y étaient pas, et leur charge de
// démarrage ratée ne se réparait jamais. Le registre vit désormais dans `navigation.js`, à côté des
// sections que chaque onglet déclare — un seul registre pour l'entrée dans une vue ET pour la cadence,
// de sorte qu'un panneau ne peut plus être servi par l'un et oublié par l'autre. Ce fichier n'en garde
// que ce qu'il peint lui-même, ATTACHÉ à une charge déjà déclarée là-bas (`poserUneCharge` refuse une
// cible inconnue, pour qu'une faute de frappe ne crée pas une charge fantôme).
//
// CE QUE LA CADENCE DÉRIVE : les charges déclarées VIVES dont la cible est AFFICHÉE. Aucun nom de vue
// n'apparaît ici ni là-bas ; une vue posée demain hérite de la règle par ses sections.
// =================================================================================================

// L'en-tête et le pied de page vivent HORS de `<main>` : leur cible est affichée sur toutes les vues,
// et c'est pour cela que la posture est une charge comme les autres au lieu d'être un cas à part.
async function peindreLaPosture() {
  const ov = await api('/overview');
  $('#updated').textContent = fmtTs(ov.ts);
  const p = $('#posture');
  p.textContent = ov.open_alerts > 0 ? `${ov.open_alerts} alerte(s)` : 'OK ';
  p.className = 'posture ' + (ov.open_alerts > 0 ? 'bad' : 'ok');
}
// Les trois charges que ce fichier PEINT : leur cible et leur cadence sont déclarées dans le registre,
// seule la fonction est attachée ici. Posé AVANT le premier `route()` (plus bas), sans quoi la
// première entrée dans la Vue d'ensemble ne peindrait rien.
// `P11.21-f` — CES TROIS ATTACHES SONT LE PREMIER DES SIX GESTES DE CE CORPS QUI ATTEIGNENT
// `navigation.js` AU PREMIER NIVEAU (avec `initNavigation()`, `route()` et le `refresh()` d'amorçage).
// Ils sont sûrs parce que `index.html` n'ouvre le graphe QUE par ce fichier ; ils JETTENT en zone morte
// dès qu'un autre module en est le point d'entrée — mesuré le 2026-08-30, entrer par `navigation.js`
// empêche alors vingt-trois modules sur quarante-neuf de se charger. Les DIFFÉRER a été essayé et
// refusé par le témoin (53c) du harnais ESM. Le raisonnement complet est en tête de `web/navigation.js`.
poserUneCharge('posture', peindreLaPosture);
poserUneCharge('firewall', () => renderFirewall());
poserUneCharge('controls', () => renderControls());

// FRAÎCHEUR — « ne pas relancer ce qui est déjà chargé ». La borne est l'instant du tir de cadence
// PRÉCÉDENT : une charge qu'un GESTE EXPLICITE a déjà lancée depuis cette borne ne repart pas. La règle
// et son piège sont écrits avec le coureur partagé, dans `navigation.js` : les deux appelants —
// l'entrée dans une vue et la cadence — passent par la même mécanique, sans quoi elle vaudrait pour
// l'un et pas pour l'autre.
let dernierTirDeCadence = 0;

// `refresh()` — les charges dont la cible est AFFICHÉE.
//   `opts.depuis` présent  => tir de CADENCE : les charges déclarées VIVES seulement, plus la fraîcheur
//                             et le non-recouvrement. C'est là que la déclaration `vive` sert.
//   `opts` absent          => geste EXPLICITE (bouton Rafraîchir, changement de thème ou de plage,
//                             bascule de tenant) : TOUT ce qui est affiché repart, catalogues compris,
//                             et sans exception de fraîcheur — un opérateur qui demande une lecture
//                             doit toujours l'obtenir.
// `#status` (« connecté » / « hors-ligne ») est écrit par le coureur partagé, une fois les charges
// retombées : l'aveu appartient à celui qui sait si elles ont abouti, pas à chaque appelant.
function refresh(opts) {
  const depuis = (opts && typeof opts.depuis === 'number') ? opts.depuis : undefined;
  // Lu SYNCHRONEMENT : l'appelant avance la borne juste après.
  return lancerLesCharges(depuis === undefined ? chargesAffichees() : chargesVivesAffichees(), depuis);
}


// DÉNOMINATEUR EXPLICITE (règle des surfaces réconciliées) — un panneau d'INSTANTANÉ montre l'état d'UNE
// machine ; tant qu'il ne dit pas laquelle ni combien il y en a, il AFFIRME une complétude qu'il n'a pas.
// L'API rend désormais `host` + `hosts[]` + `n_hosts` (cf. handlers/overview.rs::panel).
function snapScope(r) {
  const n = r.n_hosts || 0;
  if (n <= 1) return r.host ? `hôte ${esc(r.host)}` : '';
  return `hôte ${esc(r.host || '?')} — <b>1 machine sur ${n}</b>`;
}
async function renderFirewall() {
  const r = await api('/panel/firewall');
  const b = $('#firewall .body');
  if (!r.data) { b.innerHTML = '<div class="muted">aucune donnée (le capteur tourne toutes les 2 min)</div>'; return; }
  const c = r.data.control_docker_lockdown;   // omis hors hôte laptop (wlan0) -> n/a, pas un faux ABSENT
  const lockdown = c
    ? `<div class="kv"><span>Contrôle docker-lockdown</span><b class="${c.ok ? 'ok' : 'bad'}">${c.ok ? 'OK ' + ic('check') : 'ABSENT ' + ic('warn')}</b></div>
    <div class="kv"><span>DOCKER-USER v4</span><b>${bool(c.docker_user_v4)}</b></div>
    <div class="kv"><span>INPUT v4 / v6</span><b>${bool(c.input_v4)} / ${bool(c.input_v6)}</b></div>`
    : `<div class="kv"><span>Contrôle docker-lockdown</span><b class="muted">n/a (pas d'interface lockdown sur cet hôte)</b></div>`;
  const sc = snapScope(r);
  b.innerHTML = lockdown + `<div class="muted">ruleset ${esc((r.data.ruleset_sha256 || '').slice(0, 12))}... - ${fmtTs(r.ts)}${sc ? ' · ' + sc : ''}</div>`;
}
async function renderControls() {
  const r = await api('/panel/controls');
  const b = $('#controls .body');
  // `P11.18-i` — UN CATALOGUE VIDE N'EST PAS « 0 MANQUANT ». Trois cas, pas deux, et le tableau
  // JavaScript vide est le piège : il est *truthy*, donc `!r.data.controls` le laissait passer, `map()`
  // rendait la chaîne vide, et le panneau affichait « 0 manquant(s) » — un tableau de bord RASSURANT là
  // où RIEN n'est mesuré. Mesuré le 2026-08-25 en même temps que le capteur cessait de se taire à vide.
  //   charge illisible  -> on attend (une absence de données, `muted`) ;
  //   liste VIDE        -> on le DIT (un trou de couverture, `bad`) — « 0 manquant » ne mesure rien ;
  //   liste non vide    -> le rendu ordinaire.
  // La condition est DÉRIVÉE de la liste, jamais de la RAISON du vide : outil absent, catalogue retiré
  // ou contrôles tous désactivés y tombent de la même façon, donc l'invariant tiendra encore quand la
  // console saura désactiver un contrôle.
  const liste = r.data && Array.isArray(r.data.controls) ? r.data.controls : null;
  if (!r.data || liste === null) { b.innerHTML = '<div class="muted">en attente du capteur (5 min)...</div>'; return; }
  if (liste.length === 0) {
    b.innerHTML = `<div class="bad">${esc(LANG === 'en'
      ? 'No defence control is evaluated here — the expected catalogue is EMPTY: "0 missing" measures nothing.'
      : "Aucun contrôle de défense n'est évalué ici — le catalogue attendu est VIDE : « 0 manquant » ne mesure rien.")}</div>`;
    return;
  }
  // `failed` de la machine affichée ; le total PARC est la somme sur `hosts[]` — sans lui, un parc dont
  // une seule machine est saine se lit « 0 manquant ».
  const hs = Array.isArray(r.hosts) ? r.hosts : [];
  const parc = hs.reduce((a, h) => a + ((h.data && h.data.failed) || 0), 0);
  const enDefaut = hs.filter(h => h.data && h.data.failed > 0).length;
  const sc = snapScope(r);
  const total = hs.length > 1
    ? ` · parc : ${parc} manquant(s) sur ${enDefaut}/${hs.length} machine(s)`
    : '';
  // S36 — TROIS VERDICTS, PAS DEUX. `ok === null` veut dire « la sonde n'a pas pu conclure » (verrou
  // xtables, /proc masqué, pas de gestionnaire de services joignable). Le rendre ROUGE comme un
  // contrôle manquant, c'est afficher une alerte que le capteur n'a pas émise — et c'est exactement
  // ce que fait un `c.ok ? … : …` sur `null`. L'indéterminé se lit comme tel, et ne compte pas dans
  // le total de manquants (le capteur ne l'y compte pas non plus).
  b.innerHTML = r.data.controls.map(c => {
    const ind = (c.ok === null || c.ok === undefined);
    const cls = ind ? 'muted' : (c.ok ? 'ok' : 'bad');
    const txt = ind ? 'NON ÉTABLI ' + ic('warn') : (c.ok ? 'OK ' + ic('check') : 'MANQUANT ' + ic('warn'));
    return `<div class="kv"><span>${esc(c.id)}</span><b class="${cls}" title="${esc(ind ? ('non établi : ' + (c.cause || 'cause non dite')) : (c.detail || ''))}">${txt}</b></div>`;
  }).join('') + `<div class="muted">${r.data.failed || 0} manquant(s) - ${fmtTs(r.ts)}${sc ? ' · ' + sc : ''}${total}</div>`;
}


// --- barre de recherche de l'en-tête : un RACCOURCI vers l'éditeur de requête de l'espace Recherche ---
// (P11.7-a) Elle recopie le texte dans l'éditeur, ouvre l'onglet, exécute. Il n'y a qu'un seul moteur de
// résultats : celui de l'éditeur (`#qresult`). L'ancienne section « résultats de recherche » était inatteignable.
$('#q').addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  const v = e.target.value.trim(); if (!v) return;
  location.hash = 'explore';
  $('#sql').value = (/^\s*(search|select)\b/i.test(v) || v.includes('|')) ? v : ('search ' + v); // texte simple -> search
  clearDrillCrumb();   // recherche MANUELLE (barre d'en-tête) -> le fil d'Ariane de drill n'a plus lieu d'être
  runQuery();
});

// --- Requête SQL (P3) : tableau rendu en DOM sûr (textContent) -> anti-XSS ---
// --- helpers requête + viz (réutilisés par le panneau ad hoc ET les dashboards) ---
/* state: zoomRange -> S (state.js) */ // {from,to} : zoom temporel, prioritaire sur le preset #range
// --- infobulle de graphe qui suit le curseur (remplace le <title> SVG natif) ---
/* state: _charttip -> S (state.js) */

// qid client unique : crypto.randomUUID si dispo, sinon préfixe + compteur croissant (jamais Math.random).
/* state: _qidSeq -> S (state.js) */
// UNE SEULE requête explore en vol : { qid, sig, ctrl(AbortController) }. sig = signature (GXQL + fenêtre
// + zoom + page) -> dédup d'un clic identique ; sinon cancel-previous (abort + /api/cancel) puis relance.
/* state: exploreInflight -> S (state.js) */
// sélecteur de colonnes : un seul menu ouvert à la fois (échappe l'overflow de .qresult via position:fixed)
/* state: _colsMenuClose, _colsMenuOwner -> S (state.js) */

// --- panneau requête ad hoc ---
/* state: lastResult -> S (state.js) */
/* state: evState -> S (state.js) */
// HISTORIQUE de requêtes Explore (en mémoire) : pile {sql, win} des requêtes exécutées + position
// courante. Modèle back/forward de navigateur — une NOUVELLE requête tronque la branche « avant ».
// ◀ rejoue la précédente, ▶ la suivante. Remplace l'ancien drilldown « ← Retour » (supprimé).
/* state: qHist, qHistIdx, qHistReplay -> S (state.js) */
if ($('#run')) $('#run').addEventListener('click', () => { clearDrillCrumb(); runQuery(); });   // exécution MANUELLE -> efface le fil d'Ariane de drill
// ITEM 6 : flèches historique ◀ ▶ (haut-gauche d'Explore) — rejouent la requête précédente / suivante.
if ($('#qprev')) { $('#qprev').innerHTML = ic('chevleft'); $('#qprev').addEventListener('click', () => qHistGo(-1)); }
if ($('#qnext')) { $('#qnext').innerHTML = ic('chevright'); $('#qnext').addEventListener('click', () => qHistGo(1)); }
if ($('#sql')) $('#sql').addEventListener('keydown', e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); clearDrillCrumb(); runQuery(); } });
if ($('#viz')) $('#viz').addEventListener('change', renderViz);
if ($('#qsize')) $('#qsize').addEventListener('change', () => { if (S.evState.q) { S.evState.page = 0; evLoad(); } });
if ($('#qexport-csv')) $('#qexport-csv').addEventListener('click', () => exploreExport('csv'));
if ($('#qexport-json')) $('#qexport-json').addEventListener('click', () => exploreExport('json'));
if ($('#qexport-pdf')) $('#qexport-pdf').addEventListener('click', () => exportPDF('explore'));
if ($('#qstop')) $('#qstop').addEventListener('click', stopExplore);   // STOP : abort + /api/cancel de la requête explore en vol
if ($('#qrange')) $('#qrange').addEventListener('change', () => {     // changer la fenêtre = re-run immédiat (standard SOC type Splunk)
  if (S.zoomRange) { S.zoomRange = null; updateZoomBadge(); if (typeof updateRangeBtn === 'function') updateRangeBtn(); }   // une fenêtre relative annule le zoom figé
  if (typeof updateQRangeBtn === 'function') updateQRangeBtn();
  if ($('#sql') && $('#sql').value.trim()) runQuery();
});

initDashboards();   // dashboards, panneaux, instantané, diaporama, vues : câblage des boutons + chargements initiaux (dashboards.js)


// --- Réglages : wizard (1er run) + changement de mot de passe ---
async function loadSettings() {
  const f = $('#setup-form'); if (!f) return;
  let configured = true;
  try { ({ configured } = await api('/setup-status')); } catch (e) {}
  const b = $('#setup-banner'); if (b) b.hidden = configured;
  const u = $('#set-user'); if (u) u.hidden = configured;
  const t = $('#set-token'); if (t) t.hidden = configured;
}
if ($('#setup-form')) $('#setup-form').addEventListener('submit', async e => {
  e.preventDefault();
  const pw = $('#set-pw').value, res = $('#set-result');
  if (pw.length < 12) { res.textContent = 'mot de passe >= 12 caractères'; return; }
  let configured = true;
  try { ({ configured } = await api('/setup-status')); } catch (e) {}
  if (configured && !await confirmModal('Changer le mot de passe ? Tu devras te reconnecter avec le nouveau.', { okText: 'Changer', danger: true })) return;
  try {
    if (configured) await apiSend('/password', 'POST', { new: pw });
    else await apiSend('/setup', 'POST', { token: $('#set-token').value.trim(), user: ($('#set-user').value.trim() || 'admin'), password: pw });
  } catch (err) { res.textContent = '' + ((err && err.message) || err); return; }
  res.textContent = 'enregistré - reconnecte-toi avec les nouveaux identifiants';
  $('#set-pw').value = ''; loadSettings();
});
loadSettings();


initLookups();   // lookups (tables d'enrichissement GXQL) : câblage des boutons + premier chargement (lookups.js)
/* state: caseSelectedId -> S (state.js) */   // case affiché dans le panneau de détail (surligné dans la liste)
/* state: casePager -> S (state.js) */   // instance pagedList (server) courante -> re-highlight de la sélection sans refetch
if ($('#case-new')) $('#case-new').addEventListener('click', () => withBusy($('#case-new'), createCase));
if ($('#case-filter')) $('#case-filter').addEventListener('change', loadCases);
if ($('#case-prio-filter')) $('#case-prio-filter').addEventListener('change', loadCases);
if ($('#case-assignee-filter')) $('#case-assignee-filter').addEventListener('change', loadCases);
if ($('#case-overdue-filter')) $('#case-overdue-filter').addEventListener('change', loadCases);
if ($('#case-archived-filter')) $('#case-archived-filter').addEventListener('change', loadCases);
if ($('#case-sort')) $('#case-sort').addEventListener('change', loadCases);   // BATCH 1 : tri serveur -> refetch page 0
// #17 team — MA FILE DE TRAVAIL : bascule « À moi » = filtre serveur assignee=<utilisateur courant> (S.AUTH.user,
// renseigné par GET /api/me). Réutilise l'endpoint EXISTANT ?assignee= (aucun backend). NOTE (suivi backend) :
// « non assigné » n'est pas exprimable côté serveur aujourd'hui (assignee='' = pas de filtre) — il faudrait un
// sentinel dédié dans cases_list ; hors scope web-only, laissé en suivi.
if ($('#case-mine')) $('#case-mine').addEventListener('click', () => {
  const inp = $('#case-assignee-filter'), btn = $('#case-mine'); if (!inp) return;
  const me = (S.AUTH && S.AUTH.user) || '';
  if (!me) { toast('Utilisateur courant inconnu (session ?).', 'bad'); return; }
  const on = btn.getAttribute('aria-pressed') !== 'true';   // bascule
  inp.value = on ? me : '';
  btn.setAttribute('aria-pressed', on ? 'true' : 'false');
  loadCases();
});
// si l'assigné est édité à la main, l'état visuel du bouton « À moi » se resynchronise (pressé ssi == moi).
if ($('#case-assignee-filter')) $('#case-assignee-filter').addEventListener('input', () => {
  const btn = $('#case-mine'); if (!btn) return;
  const me = (S.AUTH && S.AUTH.user) || '';
  btn.setAttribute('aria-pressed', (me && $('#case-assignee-filter').value.trim() === me) ? 'true' : 'false');
});

// ============================================================================================
// Chantier #1b — Administration UI : RÉTENTION (durées éditables) · SOURCES (inventaire +
// métadonnées display-only) · AUDIT (journal ledger, lecture seule). Contrat daemon EXACT :
//   GET  /api/retention            -> {ok,retention_days,snapshot_days,alert_days,metric_days,
//                                        metric_raw_hours, bounds:{<key>:{min,max,default,unit}}} (effectives)
//   PUT  /api/retention            <- sous-ensemble {clé:i64} -> {ok,changed,applied}
//   GET  /api/retention/preview?key=<clé>&value=<n> -> {ok,key,unit,current,new,destructive,
//                                        deleted,deleted_kind,oldest,approx} (destructive = new<current)
//   GET  /api/sources              -> {ok,generated,pipeline_fresh,sources:[{source,in_collectors,
//                                        expected,unexpected,label,note,category,updated_by,updated,
//                                        last_seen,age_s,n_24h,status,type}]} (tous rôles)
//   PUT  /api/sources/settings     <- {source,action,value?} ; action ∈ set_expected|set_label|
//                                        set_note|set_category|clear (admin, audité, rollback si échec)
//   GET  /api/ledger?limit=<n>[&window_days=<n>][&cursor=<id>|&offset=<n>][&count=0]
//        -> {ok,entries:[{id,ts,kind,detail,hash}],total,total_capped,has_more,next_cursor,limit} (id DESC, admin).
//        `P11.16-d` : fenêtre de temps (`window_days`) + pagination PAR CLÉ (`cursor` = un identifiant, SEUL —
//        la chaîne d'intégrité est construite et revérifiée dans cet ordre, trier par horodatage la romprait).
//        `count=0` n'exige pas le total (`total`/`total_capped` valent alors null) : il n'est demandé qu'une
//        fois par fenêtre. Au-delà du plafond de comptage, `total_capped` est vrai et la vue retire le dernier
//        numéro de page au lieu de rendre des pages inatteignables.
// INVARIANTS : aucun contrôle de collecte/hôte ; label/note/category = texte libre rendu en textContent
// (B7, jamais innerHTML) ; toute BAISSE de rétention -> modal destructif AVANT le PUT (H3) ; mutations
// cachées au non-admin côté UI (isAdmin), la vraie garde reste serveur.
// --------------------------------------------------------------------------------------------


if ($('#sources-refresh')) $('#sources-refresh').onclick = loadSourcesView;
if ($('#system-refresh')) $('#system-refresh').onclick = loadSystemView; // #51 DAY-2 OPS
if ($('#fleet-refresh')) $('#fleet-refresh').onclick = loadFleetView;

/* state: editingConnector -> S (state.js) */

// P11.4-a — les quatre boutons de création (preset / Defender / TAXII / HTTP) passent par le composant
// de dépli partagé (`disclosure`, core.js) : un second clic REFERME la carte ouverte, le bouton porte son
// état (aria-expanded + .on, accent) et n'est jamais grisé. Avant : chaque bouton ne savait qu'OUVRIR.
const connectorFormClose = () => { $('#cf-secret').value = ''; $('#connector-form').classList.add('hidden'); if ($('#connector-preset-picker')) $('#connector-preset-picker').classList.add('hidden'); };
const connectorFormShows = type => !$('#connector-form').classList.contains('hidden') && S.editingConnector == null && ($('#cf-type').value || 'defender') === type;
const connectorDisclosures = [];
if ($('#connector-new-preset') && $('#connector-preset-picker')) connectorDisclosures.push(disclosure($('#connector-new-preset'), $('#connector-preset-picker'), { open: openPresetPicker })); // P1 — picker de presets vendeur (pré-remplit le form)
[['#connector-new', 'defender'], ['#connector-new-taxii', 'taxii2'], ['#connector-new-http', 'http_pull']].forEach(([sel, type]) => { // #23/#24 TAXII 2.1 ; #20/#22 http_pull générique (bring-your-own-vendor)
  if ($(sel) && $('#connector-form')) connectorDisclosures.push(disclosure($(sel), $('#connector-form'), { isOpen: () => connectorFormShows(type), open: () => openConnectorForm(null, type), close: connectorFormClose }));
});
if ($('#cf-type')) $('#cf-type').addEventListener('change', () => { applyConnectorType(); connectorDisclosures.forEach(d => d && d.paint()); }); // bascule les champs Defender ↔ TAXII ↔ HTTP (+ l'état des boutons de dépli)
if ($('#cf-taxii-auth')) $('#cf-taxii-auth').addEventListener('change', applyConnectorType); // ré-ajuste l'indice du secret selon l'auth
// http_pull : les sélecteurs auth/méthode/pagination re-basculent les sous-champs (applyConnectorType -> applyHttpSubfields)
if ($('#cf-http-auth')) $('#cf-http-auth').addEventListener('change', applyConnectorType);
if ($('#cf-http-method')) $('#cf-http-method').addEventListener('change', applyConnectorType);
if ($('#cf-http-page')) $('#cf-http-page').addEventListener('change', applyConnectorType);
if ($('#cf-http-fm-add')) $('#cf-http-fm-add').onclick = () => addFieldMapRow('', '');   // + champ (field_map)
if ($('#cf-http-st-add')) $('#cf-http-st-add').onclick = () => addStMapRow('', '');       // + mapping (sourcetype_map)
if ($('#cf-http-preview')) $('#cf-http-preview').onclick = () => withBusy($('#cf-http-preview'), previewHttpPull); // Test / Prévisualiser (dry-run + rendu échantillon)
if ($('#cf-cancel')) $('#cf-cancel').onclick = connectorFormClose;
if ($('#connectors-refresh')) $('#connectors-refresh').onclick = loadConnectors;
// #50 destinations de sortie (admin-only) : recharge + ouverture du formulaire d'ajout.
if ($('#destinations-refresh')) $('#destinations-refresh').onclick = loadDestinations;
if ($('#destination-new') && $('#destination-form-host')) disclosure($('#destination-new'), $('#destination-form-host'), { isOpen: () => !!$('#destination-form-host').querySelector('#destination-form') && !$('#destination-form-host').querySelector('#destination-form').dataset.editing, open: () => openDestinationForm(null), close: () => $('#destination-form-host').replaceChildren() }); // P11.4-a — dépli partagé (le formulaire est RENDU dans l'hôte ; ouvert = présent et en création)
// #40 processeur d'ingest (admin-only) : recharge + ouverture du formulaire d'ajout de règle.
if ($('#processors-refresh')) $('#processors-refresh').onclick = loadProcessors;
if ($('#processor-new') && $('#processor-form')) disclosure($('#processor-new'), $('#processor-form'), { open: openProcessorForm, close: () => { $('#processor-form').hidden = true; $('#processor-form').replaceChildren(); } }); // P11.4-a — dépli partagé
if ($('#index-policies-refresh')) $('#index-policies-refresh').onclick = loadIndexPolicies;
if ($('#index-policy-new') && $('#index-policy-form')) disclosure($('#index-policy-new'), $('#index-policy-form'), { isOpen: () => !$('#index-policy-form').hidden && !$('#index-policy-form').dataset.editing, open: () => openIndexPolicyForm(), close: () => { $('#index-policy-form').hidden = true; $('#index-policy-form').replaceChildren(); } }); // P11.4-a — dépli partagé
if ($('#connector-form')) $('#connector-form').addEventListener('submit', async e => {
  e.preventDefault();
  const type = $('#cf-type').value || 'defender';
  const secret = $('#cf-secret').value;   // NE PAS trim un secret (espaces potentiellement significatifs)
  let config, defaultName;
  if (type === 'taxii2') {
    // #23/#24 — feed de renseignement TAXII 2.1 (miroir du form Defender). config { api_root, collection, auth, username? }.
    const url = $('#cf-taxii-url').value.trim();
    const collection = $('#cf-taxii-collection').value.trim();
    const auth = $('#cf-taxii-auth').value || 'none';
    const username = $('#cf-taxii-user').value.trim();
    if (!url || !collection) { formMsg('#cf-result', "l'URL (discovery/api-root) et l'id de collection sont requis.", true); return; }
    // secret requis à la création UNIQUEMENT si l'auth en réclame un (basic/token) ; jamais pour auth=none.
    if (!S.editingConnector && auth !== 'none' && !secret) { formMsg('#cf-result', 'un secret (token / mot de passe) est requis à la création pour cette auth.', true); return; }
    config = { api_root: url, collection, auth };
    if (auth === 'basic' && username) config.username = username;
    defaultName = 'Connecteur TAXII';
  } else if (type === 'http_pull') {
    // #20/#22 — connecteur générique (bring-your-own-vendor). La config est construite/validée dans connectors.js.
    const built = httpPullFormConfig();
    if (built.error) { formMsg('#cf-result', built.error, true); return; }
    // credential requis à la création UNIQUEMENT si l'auth en réclame un (jamais pour auth=none). Miroir TAXII.
    if (!S.editingConnector && built.authKind !== 'none' && !secret) { formMsg('#cf-result', 'un credential est requis à la création pour cette authentification.', true); return; }
    config = built.config;
    defaultName = built.defaultName;
  } else {
    const azure = $('#cf-azure').value.trim();
    const client = $('#cf-client').value.trim();
    if (!azure || !client) { formMsg('#cf-result', 'azure_tenant et client_id sont requis.', true); return; }
    if (!S.editingConnector && !secret) { formMsg('#cf-result', 'le client secret est requis à la création.', true); return; }
    config = {
      azure_tenant: azure,
      client_id: client,
      resource: $('#cf-resource').value === 'incidents' ? 'incidents' : 'alerts',
      lookback_days: Math.max(1, Math.min(3650, Number($('#cf-lookback').value) || 7)),
    };
    defaultName = 'Connecteur Defender';
  }
  const body = {
    type,
    name: $('#cf-name').value.trim() || defaultName,
    env_id: $('#cf-env').value.trim() || 'prod',
    interval_s: Math.max(60, Number($('#cf-interval').value) || 300),
    enabled: $('#cf-enabled').checked,
    config,
  };
  // secret ré-envoyé UNIQUEMENT s'il a été (re)saisi -> omis/vide = conserver l'existant côté serveur.
  if (secret) body.secret = secret;
  const url = S.editingConnector ? '/connectors/' + S.editingConnector : '/connectors';
  try { await apiSend(url, 'POST', body); }
  catch (err) { const m = (err && err.message) || 'échec'; formMsg('#cf-result', m, true); toast(m, 'bad'); return; }
  $('#cf-secret').value = '';   // ne jamais laisser traîner le secret dans le DOM
  $('#connector-form').classList.add('hidden');
  toast(S.editingConnector ? 'connecteur mis à jour' : 'connecteur créé (désactivé — teste la connexion puis active-le)', 'ok', 4200);
  loadConnectors();
});

// ============ THREAT INTEL / IOC (#23, admin-only) ============
// Panneau self-câblé (boutons refresh/ajout/import/recherche dans threatintel.js) ; la nav/route reste ici.
initThreatIntel();

// ============ RISQUE PAR ENTITÉ (RBA #24, lecture viewer+) ============
if ($('#risk-refresh')) $('#risk-refresh').onclick = loadRiskView;
if ($('#detadv-refresh')) $('#detadv-refresh').onclick = loadDetAdv;

// ============ MATRICE ATT&CK (couverture, lecture viewer+) ============
if ($('#attack-refresh')) $('#attack-refresh').onclick = loadAttackMatrix;

// ============ AUDIT / LEDGER (lecture seule) ============
/* state: LEDGER_LIMIT -> S (state.js) */
if ($('#ledger-refresh')) $('#ledger-refresh').onclick = loadLedger;
if ($('#ledger-limit')) $('#ledger-limit').addEventListener('change', () => { S.LEDGER_LIMIT = parseInt($('#ledger-limit').value, 10) || 100; loadLedger(); });
// onboarding (super-admin) : POST /api/tenants {id, name?, admin?, key_ref?}
if ($('#tenant-onboard') && $('#tenant-form')) disclosure($('#tenant-onboard'), $('#tenant-form')); // P11.4-a — dépli partagé
if ($('#tf-cancel')) $('#tf-cancel').onclick = () => { const f = $('#tenant-form'); if (f) f.classList.add('hidden'); };
if ($('#tenant-refresh')) $('#tenant-refresh').onclick = loadTenantsView;
if ($('#tenant-form')) $('#tenant-form').addEventListener('submit', async e => {
  e.preventDefault();
  const res = $('#tf-result'); if (res) { res.textContent = '…'; res.className = 'muted'; }
  const id = $('#tf-id').value.trim();
  if (!id) { if (res) { res.textContent = 'identifiant requis'; res.className = 'bad'; } return; }
  const body = { id };
  const name = $('#tf-name').value.trim(); if (name) body.name = name;
  const admin = $('#tf-admin').value.trim(); if (admin) body.admin = admin;
  const key = $('#tf-key').value.trim(); if (key) body.key_ref = key;
  // P11.5-b : provisionner un tenant crée une base chiffrée et, si un premier admin est nommé, lui ACCORDE le
  // rôle admin sur ce tenant (un droit naît) -> confirmation partagée qui nomme la conséquence.
  if (!await confirmWithConsequence('Provisionner le tenant « ' + id + ' »', 'une base chiffrée dédiée est créée avec sa clé' + (admin ? ', et « ' + admin + ' » en devient administrateur (accès complet à ce tenant)' : '') + '. Action auditée.', { okText: 'Provisionner', danger: !!admin })) { if (res) res.textContent = ''; return; }
  let out;
  try { out = await apiSend('/tenants', 'POST', body); }
  catch (err) { if (res) { res.textContent = (err && err.message) || 'échec'; res.className = 'bad'; } return; }
  out = out || {};
  if (res) { res.textContent = 'tenant créé' + (out.first_admin ? ' — 1er admin : ' + out.first_admin : ''); res.className = 'muted'; }
  ['#tf-id', '#tf-name', '#tf-admin', '#tf-key'].forEach(s => { const el = $(s); if (el) el.value = ''; });
  const f = $('#tenant-form'); if (f) f.classList.add('hidden');
  toast('tenant « ' + (out.name || id) + ' » provisionné', 'ok');
  loadTenantsView();
});
if ($('#opaccess-refresh')) $('#opaccess-refresh').onclick = loadOperatorAudit;
if ($('#opaccess-src')) $('#opaccess-src').addEventListener('change', loadOperatorAudit);

// ============ DENSITÉ D'AFFICHAGE DES TABLEAUX (`P11.15-b`) ============
// LE JUMEAU EST `initTheme` (plus bas), ET LE CHEMIN EST EXACTEMENT LE SIEN : contrôle dans le gabarit,
// valeur dans le STOCKAGE DU SITE, application sur `documentElement`. Le magasin de préférences par
// utilisateur (`prefs.js`) n'est PAS touché, et il n'a besoin d'aucune ligne — arbitrage de l'exploitant du
// 2026-08-29 : la densité est un confort attaché à l'ÉCRAN qu'on a devant soi, pas une propriété du compte.
// Ce que la décision coûte est dit : qui travaille sur deux postes règle la densité deux fois, exactement
// comme le thème. La troisième voie — défaut porté par le compte, surchargeable par appareil — est REFUSÉE :
// ce serait un TROISIÈME mécanisme à tenir.
//
// POURQUOI ICI, AVANT `route()`, ET NON À CÔTÉ DE SON JUMEAU. `route()` pose `.app-ready`, et c'est CE geste
// qui lève `html:not(.app-ready) main{visibility:hidden}` (règle en ligne d'index.html). Poser l'attribut
// AVANT lui fait reposer « appliqué avant la première peinture » sur l'ORDRE DU SOURCE, et non sur le
// raisonnement « tout le corps d'app.js tient dans une seule tâche, donc le navigateur ne peint pas entre les
// deux » — vrai aujourd'hui (aucun `await` de premier niveau, mesuré), mais qu'un futur `await` rendrait faux
// EN SILENCE. C'est la seule différence avec le jumeau, et elle est en faveur d'ici : `initTheme` s'exécute
// APRÈS `route()`, donc sa garantie tient au raisonnement, pas à l'ordre. Le gabarit ne contient AUCUNE
// `.qtable` (mesuré) : les seules surfaces que la densité touche (`.qtable th,.qtable td`, `td.plcut`,
// `.plmore` dans style.css) sont bâties par les modules, donc après ce point — aucun réagencement ne peut
// être vu.
//
// TROIS POSITIONS, ET PAS UN CRAN DE PLUS. La feuille sait rendre TROIS densités : son défaut (`:root`,
// l'attribut ABSENT) et les DEUX crans qu'elle nomme (`compact`, `comfortable`). Le défaut n'est pas un
// troisième cran, c'est l'ABSENCE d'attribut — et l'offrir est obligatoire : sans lui, le cran par défaut,
// qui est celui de tout le monde aujourd'hui, deviendrait inatteignable dès le premier choix.
//
// UNE VALEUR ABSENTE, INCONNUE OU ILLISIBLE VAUT LE DÉFAUT, JAMAIS UN ÉTAT INTERMÉDIAIRE : l'attribut n'est
// alors pas posé du tout, et `:root` reprend la main. `lireLeStockageDuSite` rend `null` — au lieu de jeter —
// quand le navigateur REFUSE le stockage de site (`P4.13-a`), donc ce chemin couvre aussi la navigation
// privée durcie ; l'ÉCRITURE est gardée ici pour la même raison, parce qu'elle jette dans le même cas.
//
// LE CONTRÔLE DIT SON ÉTAT, ET IL EN DIT PLUS QUE SON JUMEAU. Le bouton de thème porte un `aria-label` FIXE
// (« Changer de thème ») : une aide technique entend l'action, jamais le thème COURANT. Un `<select>` annonce
// son option choisie par construction, dans les trois positions et sans qu'aucun code n'ait à la repeindre.
(function initDensity() {
  const CRANS = [
    { v: '', fr: 'Normale', en: 'Normal' },              // '' = le défaut de la feuille : aucun attribut
    { v: 'compact', fr: 'Compacte', en: 'Compact' },     // style.css — [data-density="compact"]
    { v: 'comfortable', fr: 'Aérée', en: 'Roomy' }       // style.css — [data-density="comfortable"]
  ];
  const connu = v => CRANS.some(c => c.v && c.v === v);
  const appliquer = v => {
    if (connu(v)) document.documentElement.setAttribute('data-density', v);
    else document.documentElement.removeAttribute('data-density');
  };
  const lu = lireLeStockageDuSite('soc-density');   // UNE seule lecture du stockage, gardée par `state.js`
  const cran = connu(lu) ? lu : '';
  appliquer(cran);
  const sel = $('#density');
  if (!sel) return;
  sel.setAttribute('aria-label', LANG === 'en' ? 'Table display density' : "Densité d'affichage des tableaux");
  sel.setAttribute('title', LANG === 'en'
    ? 'Table display density — kept on THIS device, like the theme'
    : "Densité d'affichage des tableaux — retenue sur CE poste, comme le thème");
  // ON VIDE AVANT DE PEUPLER, ET CE N'EST PAS UNE PRÉFÉRENCE D'ÉCRITURE : C'EST UNE MESURE. Une première
  // version se contentait d'AJOUTER les options ; sondée sur le simulacre du harnais ESM (arbre réel du
  // gabarit, `app.js` importé), le contrôle en rendait SIX au lieu de trois — ce banc importe `app.js` DEUX
  // fois (une seconde instance sous `?plume-lang=en` pour le témoin du lexique) et un ajout CUMULE là où une
  // pose idempotente REMPLACE. Le navigateur n'importe le module qu'une fois, donc le défaut n'y était pas
  // visible ; le jumeau (`initTheme`) est idempotent lui aussi (`btn.innerHTML = ic(…)`), et une pose qui ne
  // dépend d'aucune hypothèse sur le nombre d'évaluations du module est simplement plus solide.
  // LA VALEUR EST POSÉE EN PROPRIÉTÉ, PAS EN ATTRIBUT, ET C'EST MESURÉ AUSSI : peupler par une chaîne HTML
  // (`<option value="compact">`) rendait les trois options avec une valeur VIDE sur ce même simulacre, qui
  // ne reflète pas l'attribut `value` vers la propriété. Un navigateur les aurait rendues justes, mais le
  // banc qui juge ce code ne l'aurait pas vu — et un contrôle dont toutes les options valent « » ne choisit
  // plus rien.
  sel.innerHTML = '';   // REMPLACER, ne jamais AJOUTER (voir ci-dessus) ; la VALEUR est posée en propriété
  CRANS.forEach(c => { const o = document.createElement('option'); o.value = c.v; o.textContent = LANG === 'en' ? c.en : c.fr; sel.append(o); });
  sel.value = cran;
  sel.onchange = () => {
    const v = connu(sel.value) ? sel.value : '';
    appliquer(v);
    // `P4.13-c` — CE CRAN EST UNE PRÉFÉRENCE, ET UNE PRÉFÉRENCE DIT SA PERTE. Une capture VIDE tenait ce
    // silence : le choix était appliqué, jamais retenu, et l'exploitant n'avait RIEN à lire. Or c'est le
    // SIXIÈME contrôle de préférence de la console — trois partagent sa barre (`#tz`, `#lang`, `#theme`,
    // juste au-dessus dans `index.html`), deux vivent dans l'administration de la détection (tri des
    // règles, tri des parsers) — et les cinq autres annoncent TOUS le refus, lui seul se taisait.
    // « Il a déjà été prévenu ailleurs » n'est pas une propriété du code, c'est un pari sur
    // l'ORDRE DES CLICS : qui ne touche QUE la densité n'apprend jamais rien. Et ce n'est pas du bruit —
    // `onchange` ne part qu'au changement RÉEL du sélecteur, jamais à la pose `sel.value = cran`, donc
    // quelques fois par session au plus, et seulement chez un navigateur qui refuse le stockage.
    // `v || null` conserve la forme d'avant : le cran « Normale » vaut `''`, et l'écrivain EFFACE la clé
    // sur `null` — c'est exactement ce que faisait le `removeItem` de la branche `else`.
    if (!ecrireDansLeStockageDuSite('soc-density', v || null)) toast(LANG === 'en' ? 'Density applied for this session only: this browser refuses site storage, so it will not be kept on the next load.' : "Densité appliquée pour cette session seulement : ce navigateur refuse le stockage de site, elle ne sera pas retenue au prochain chargement.", 'info', 5000);
  };
})();

initNavigation();   // navigation à 2 niveaux : écoute du hash, clics sidebar/sous-onglets, burger (navigation.js)
route();
initKeyboardNav();   // #62 — raccourcis clavier power-user (non-intrusifs ; `?` = aide). Indépendant de l'auth.
initSoqlComplete();  // complétion IDE-like de la barre Explore (dropdown contextuel + palette de modèles). Additif, non-intrusif.
initSavedQueries();  // requêtes GXQL nommées (serveur, owner-scoped) + historique récent (localStorage). Additif, non-intrusif.
// #62 — quand les préférences serveur sont réconciliées (potentiellement depuis un AUTRE poste), re-applique
// les réglages par-vue déjà rendus : ordre de la Vue d'ensemble + favoris de dashboards (si la vue est ouverte).
prefsReady(() => {
  try { applyOvOrder(); } catch (e) {}
  const dv = $('#dashboards'); if (dv && !dv.hidden) { try { loadDashboards(); } catch (e) {} }
});

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});

// --- thème clair / sombre (Aurora, variante k) ---
(function initTheme() {
  const saved = lireLeStockageDuSite('soc-theme');
  if (saved) document.documentElement.dataset.theme = saved;
  const btn = $('#theme');
  const paint = () => { if (btn) btn.innerHTML = ic(document.documentElement.dataset.theme === 'light' ? 'moon' : 'sun'); };
  paint();
  if (btn) btn.onclick = () => {
    const t = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = t;
    // `P4.13-b` — LA PERSISTANCE NE COMMANDE PLUS LA CHAÎNE. Elle est TENTÉE, son résultat est retenu,
    // et le reste du geste s'exécute quoi qu'il arrive. Nue, cette ligne jetait ICI, après la pose de
    // l'attribut : le fond basculait, l'icône restait celle de l'ANCIEN thème et les graphes gardaient
    // l'ancienne couleur (mesuré le 2026-08-30 sous le mode « stockage refusé » du harnais).
    const retenu = ecrireDansLeStockageDuSite('soc-theme', t);
    paint();
    refresh();          // recolore les graphes SVG (ils lisent les variables CSS au rendu)
    loadDashboard();
    // ET LE REFUS SE DIT — DERNIER, pour qu'aucun avis ne s'interpose dans la chaîne. Se taire ici
    // échangerait l'incohérence contre une perte SILENCIEUSE : l'exploitant retrouverait l'ancien thème
    // au prochain chargement sans jamais savoir pourquoi son choix n'a pas tenu.
    if (!retenu) toast(LANG === 'en' ? 'Theme applied, but this browser refuses site storage: the choice will not be kept.' : 'Thème appliqué, mais ce navigateur refuse le stockage de site : le choix ne sera pas retenu.', 'info', 5000);
  };
})();

// --- fenêtre temporelle + rafraîchissement auto ---
/* state: autoTimer -> S (state.js) */
/* state: autoPaused -> S (state.js) */   // toggle Stop/Start : coupe la boucle d'auto-refresh sans toucher au select #refresh
// UN TIR DE CADENCE (`P11.17-a`). Il ne relance QUE les charges dont la cible est affichée, QUE celles
// qui ne sont pas déjà parties depuis le tir précédent, et QUE celles qui ne sont pas encore en vol.
// La borne est avancée AVANT l'appel : `refresh()` calcule son filtre synchronement, et un tir qui
// s'attarderait ne rendrait pas la borne du suivant fausse.
// UNE CONSOLE LAISSÉE OUVERTE dans un onglet d'arrière-plan ne tire pas du tout — `document.hidden` est
// une lecture de l'état du navigateur, pas une liste de cas. Le retour au premier plan tire aussitôt,
// donc la vue ne reste jamais figée sans que le geste de retour la remette à jour.
function tirDeCadence() {
  if (document.hidden) return;
  const borne = dernierTirDeCadence;
  dernierTirDeCadence = Date.now();
  refresh({ depuis: borne });   // les panneaux de dashboard sont une charge VIVE du registre, comme les autres
}
function applyAutoRefresh() {
  if (S.autoTimer) clearInterval(S.autoTimer);
  S.autoTimer = null;
  if (S.autoPaused) return;   // boucle suspendue par l'utilisateur
  const s = Number(($('#refresh') && $('#refresh').value) || 0);
  // La borne part de l'ARMEMENT, jamais de zéro : à zéro, le premier tir prendrait tout ce que
  // l'amorçage vient de charger pour « déjà fait depuis la borne » et ne relancerait rien — la vue
  // resterait figée une période de plus, et le défaut serait invisible puisque le tir suivant, lui,
  // repartirait normalement.
  dernierTirDeCadence = Date.now();
  if (s > 0) S.autoTimer = setInterval(tirDeCadence, s * 1000); // P5 : refresh cible, pas de rebuild complet
}
if ($('#refresh')) $('#refresh').addEventListener('change', applyAutoRefresh);
// Rattrapage au retour au premier plan : sans lui, couper les tirs en arrière-plan ferait attendre une
// période entière devant une vue qu'on vient de rouvrir.
document.addEventListener('visibilitychange', () => { if (!document.hidden && S.autoTimer) tirDeCadence(); });
// Refresh MANUEL — TOUT ce qui est à l'écran repart, vives et catalogues, sans exception de fraîcheur :
// un opérateur qui demande une lecture doit toujours l'obtenir. La chaîne de conditions sur le nom de la
// vue qui vivait ici (`detection` -> couverture, `cases` -> cas, `dashboards` -> panneaux) a disparu avec
// les deux autres : ces chargements sont des charges du registre, donc déjà couverts par « affiché ».
// LA RECHERCHE RESTE À PART, et c'est la seule : aucune charge ne la porte, délibérément (`P11.17-a` —
// une requête lourde ne part jamais d'elle-même). Le bouton Rafraîchir EST le geste qui l'autorise, et
// la condition se lit sur le document — l'éditeur est-il affiché et porte-t-il un texte — non sur un nom.
function refreshCurrentView() {
  refresh();
  if (cibleAffichee('sql') && $('#sql').value.trim()) runQuery();
}
if ($('#manual-refresh')) $('#manual-refresh').onclick = refreshCurrentView;
// toggle Stop/Start de l'auto-refresh + état visuel (pastille verte = actif, grise = en pause).
const _autoBtn = $('#auto-toggle');
function paintAutoToggle() {
  if (!_autoBtn) return;
  _autoBtn.classList.toggle('off', S.autoPaused);
  _autoBtn.setAttribute('aria-pressed', S.autoPaused ? 'false' : 'true');
  _autoBtn.title = S.autoPaused ? 'Auto-refresh suspendu — cliquer pour reprendre' : 'Auto-refresh actif — cliquer pour suspendre';
  _autoBtn.innerHTML = '<span class="autodot"></span><span class="autolbl">' + (S.autoPaused ? 'auto off' : 'auto on') + '</span>';
}
if (_autoBtn) _autoBtn.onclick = () => { S.autoPaused = !S.autoPaused; applyAutoRefresh(); paintAutoToggle(); };
paintAutoToggle();
// #range (navbar) = DASHBOARDS uniquement désormais : ne pilote plus la recherche FTS (Explore a son picker local #qrange).
if ($('#range')) $('#range').addEventListener('change', () => { if (S.zoomRange) { S.zoomRange = null; updateZoomBadge(); } if (typeof updateRangeBtn === 'function') updateRangeBtn(); loadDashboard(); refresh(); });
// P6 : selecteur date/heure absolu (debut/fin) -> reutilise le mecanisme de zoom (from/to)
// Plage temporelle : un seul modal (presets relatifs LARGES + intervalle absolu précis). Les events
// peuvent arriver n'importe quand -> du 5 min au 1 an, ou un intervalle figé exact.
const RANGE_PRESETS = [[300, '5 min'], [900, '15 min'], [1800, '30 min'], [3600, '1 h'], [10800, '3 h'], [21600, '6 h'], [43200, '12 h'], [86400, '24 h'], [172800, '2 j'], [604800, '7 j'], [2592000, '30 j'], [7776000, '90 j'], [31536000, '1 an'], [0, 'Tout']];
function rangeLabel(sel) {
  if (S.zoomRange) return `${fmtTs(S.zoomRange.from)} → ${fmtTs(S.zoomRange.to)}`;
  const r = Number(($(sel || '#range') && $(sel || '#range').value) || 0);
  const p = RANGE_PRESETS.find(x => x[0] === r);
  return p ? p[1] : (r ? r + 's' : 'Tout');
}
function updateRangeBtn() { const el = $('#rangelbl'); if (el) el.textContent = rangeLabel('#range'); }
// Explore : même picker que les Dashboards mais piloté par #qrange (état local) -> son propre libellé.
function updateQRangeBtn() { const el = $('#qrangelbl'); if (el) el.textContent = rangeLabel('#qrange'); }
// `P11.18-s` — LE GESTE EST LEVÉ AU POINT COMMUN (`ouvrirLaModaleDePlage`, `web/core.js`) ET IL SERT
// QUATRE VUES. Ce qui restait ici — un modal offrant paliers ET intervalle absolu, avec son propre
// lecteur de saisie et ses deux refus — n'était pas exporté, si bien que le journal d'audit et la
// prévention des fuites en avaient reçu un SECOND. Ce qui reste ICI est ce qui appartient VRAIMENT à
// ces deux vues : leurs paliers (`RANGE_PRESETS`, de 5 min à 1 an) et la cible où leur plage se pose.
//
// LA CIBLE DES DEUX PICKERS D'INSTANTS : `S.zoomRange`. Les deux vues ne diffèrent que par leur
// sélecteur de paliers — `#range` pour les tableaux de bord, `#qrange` pour l'Explore — et c'est le
// seul paramètre de cette fabrique. Le grain est `minute` : cet état tient un intervalle d'INSTANTS
// en secondes (le champ est `datetime-local`), là où le journal d'audit tient des JOURS entiers.
function cibleDeZoom(rangeSel) {
  return {
    grain: 'minute',
    paliers: RANGE_PRESETS,
    palier: () => Number(($(rangeSel) && $(rangeSel).value) || 0),
    // Choisir un palier RETIRE la plage : le listener de `#range` / `#qrange` efface `S.zoomRange` et recharge.
    poserLePalier: v => { if ($(rangeSel)) { $(rangeSel).value = v; $(rangeSel).dispatchEvent(new Event('change')); } },
    lire: () => (S.zoomRange ? { debut: S.zoomRange.from, fin: S.zoomRange.to } : null),
    poser: p => { if (p) setZoom(p.debut, p.fin); else clearZoom(); },
  };
}
// CE QUE LA ROUTE DE CES DEUX VUES SAIT PORTER : une borne HAUTE. `POST /api/query` accepte `to`, et
// depuis `P11.18-r` le fabricant client la POSE au lieu de l'hériter d'une autre vue. Il n'y a donc
// aucune phrase de refus à écrire ici — celle du journal d'audit vit là où elle est vraie.
const PORTE_DE_ZOOM = { borneHaute: true };
if ($('#rangepick')) $('#rangepick').onclick = () => ouvrirLaModaleDePlage(cibleDeZoom('#range'), PORTE_DE_ZOOM, updateRangeBtn);
// Explore : même geste, même style, même refus — seule la cible du palier change.
if ($('#qrangepick')) $('#qrangepick').onclick = () => ouvrirLaModaleDePlage(cibleDeZoom('#qrange'), PORTE_DE_ZOOM, updateQRangeBtn);
// fuseau horaire d'affichage (stockage UTC) : recharge pour re-rendre tous les temps affichés
// `P4.13-b` — LE RECHARGEMENT EST LE MOYEN DE LA PERSISTANCE, JAMAIS L'INVERSE. `socTZ` se RELIT du
// stockage à l'évaluation de `core.js` : recharger sans avoir écrit DÉTRUIRAIT le choix — la liste
// reviendrait d'elle-même à l'ancien fuseau, sans un mot. On applique donc en mémoire, on re-rend par
// `refresh()` au lieu de recharger (les temps affichés passent par `fmtTs`, qui lit `socTZ` au rendu),
// et on DIT que le choix ne survivra pas à un rechargement. Nue, l'écriture jetait entre `setSocTZ` et
// `location.reload()` : le fuseau était posé en mémoire, RIEN n'était re-rendu, et la liste affichait
// un fuseau que pas un seul horodatage de la page n'employait.
if ($('#tz')) {
  $('#tz').value = socTZ;
  $('#tz').onchange = () => {
    setSocTZ($('#tz').value);
    if (ecrireDansLeStockageDuSite('soc_tz', socTZ)) { location.reload(); return; }
    refresh();
    toast(LANG === 'en' ? 'Time zone applied for this session only: this browser refuses site storage, so the choice will not survive a reload.' : 'Fuseau appliqué pour cette session seulement : ce navigateur refuse le stockage de site, le choix ne survivra pas à un rechargement.', 'info', 5000);
  };
}
if ($('#qhelp')) $('#qhelp').onclick = openHelpModal;
if ($('#fresh-help')) $('#fresh-help').onclick = openFreshnessHelp;
if ($('#fresh-refresh')) $('#fresh-refresh').onclick = () => renderFreshness(true); // refresh manuel -> barre .tableprog (idem Explore/Dashboards)
updateRangeBtn();
updateQRangeBtn();
// AMORÇAGE — `route()` a déjà peint les charges DE LA VUE ; celui-ci prend le reste, c'est-à-dire ce
// qui vit hors de `<main>` et qu'aucune vue ne montre : la pastille de posture et l'horodatage du pied
// de page. Le retirer a été essayé, puis MESURÉ le 2026-08-25 : un appel de moins à l'amorçage, et
// c'était celui de la posture — le badge restait vide jusqu'au premier tir de cadence. Rien ne part
// deux fois pour autant : une charge en vol ne repart jamais, et celles de la vue le sont encore.
refresh();
applyAutoRefresh();

// --- aide a la saisie / completion du champ Explore (GXQL + champs) ---
const SOQL_KW = ['search', 'metric', 'stats', 'eventstats', 'timechart', 'rate', 'where', 'eval', 'rex', 'top', 'rare', 'dedup', 'table', 'fields', 'sort', 'head', 'append', 'join', 'by', 'count', 'sum(', 'avg(', 'min(', 'max(', 'dc('];
const SOQL_FIELDS = ['ts', 'host', 'source', 'category', 'severity', 'src_ip', 'dst_ip', 'url', 'xff', 'message'];
function acWord(ta) { const v = ta.value, c = ta.selectionStart; let i = c; while (i > 0 && /[\w(]/.test(v[i - 1])) i--; return { word: v.slice(i, c), start: i, end: c }; }
function acApply(ta, s) {
  const { start, end } = acWord(ta), v = ta.value, tail = s.endsWith('(') ? '' : ' ';
  ta.value = v.slice(0, start) + s + tail + v.slice(end);
  const pos = start + s.length + tail.length; ta.focus(); ta.setSelectionRange(pos, pos); acUpdate();
}
function acUpdate() {
  const ta = $('#sql'), hint = $('#sqlhint'); if (!ta || !hint) return;
  const { word } = acWord(ta);
  if (word.length < 1) { hint.replaceChildren(); return; }
  const w = word.toLowerCase();
  const cand = [...SOQL_KW, ...SOQL_FIELDS].filter(k => k.toLowerCase().startsWith(w) && k.toLowerCase() !== w).slice(0, 8);
  hint.replaceChildren(...cand.map(c => { const b = document.createElement('button'); b.type = 'button'; b.className = 'acchip'; b.textContent = c; b.onmousedown = (e) => { e.preventDefault(); acApply(ta, c); }; return b; }));
}
if ($('#sql')) {
  $('#sql').addEventListener('input', acUpdate);
  $('#sql').addEventListener('keydown', e => {
    if (e.key === 'Tab') { const f = $('#sqlhint') && $('#sqlhint').querySelector('.acchip'); if (f) { e.preventDefault(); acApply($('#sql'), f.textContent); } }
    else if (e.key === 'Escape') { $('#sqlhint').replaceChildren(); }
  });
  $('#sql').addEventListener('blur', () => setTimeout(() => { const h = $('#sqlhint'); if (h) h.replaceChildren(); }, 150));
}

// --- Vue d'ensemble RÉARRANGEABLE : glisser la poignée d'une carte pour la déplacer (ordre gardé en local) ---
// les Alertes ont migré vers l'onglet Notifications -> hors du réordonnancement de la Vue d'ensemble.
const OV_CARDS = ['firewall', 'controls', 'integrations', 'freshness'];
const OV_DT = 'text/soc-ov';   // type drag dédié -> pas de conflit avec le réordre de colonnes des tables
// #62 — l'ordre des cartes de la Vue d'ensemble est désormais une PRÉFÉRENCE PAR-UTILISATEUR (cross-device)
// via le store self-scoped : `prefGet('ovOrder')` (miroir localStorage inclus) fait foi ; on retombe sur
// l'ancienne clé `soc_ov_order` pour les sessions déjà persistées (compat ascendante, zéro perte).
function ovOrder() {
  const a = prefGet('ovOrder', null);
  if (Array.isArray(a)) return a;
  try { return JSON.parse(localStorage.getItem('soc_ov_order')) || []; } catch (e) { return []; }
}
function applyOvOrder() {
  const main = document.querySelector('main'); if (!main) return;
  const present = OV_CARDS.filter(id => $('#' + id));
  const ord = ovOrder();
  present.sort((a, b) => { const ia = ord.indexOf(a), ib = ord.indexOf(b); return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib); });
  present.forEach(id => main.appendChild($('#' + id)));   // ré-insère dans l'ordre voulu (les sections des autres vues restent masquées)
}
function saveOvDrop(from, to) {
  const present = OV_CARDS.filter(id => $('#' + id));
  let o = ovOrder().filter(x => present.includes(x));
  present.forEach(x => { if (!o.includes(x)) o.push(x); });   // complète avec d'éventuelles nouvelles cartes
  o.splice(o.indexOf(from), 1);
  o.splice(o.indexOf(to), 0, from);
  // `P4.13-b` — CE MIROIR N'EST QU'UN MIROIR, et son refus ne doit RIEN emporter avec lui. Nu, il jetait
  // AVANT `prefSet` — la persistance serveur, qui est la vraie — et AVANT `applyOvOrder()` : un
  // glisser-déposer ne réordonnait alors rien et ne gardait rien, sur un poste où tout aurait pu être
  // gardé. LE REFUS N'EST PAS DIT ICI, et c'est une décision mesurée, pas un silence : il n'y a aucune
  // perte à annoncer — l'ordre reste tenu par le store self-scoped, inter-postes. Seule la relecture
  // HORS-LIGNE de cet ordre est perdue, et elle l'est déjà pour tout le reste sur un tel navigateur.
  // `P4.13-c` — CE SILENCE-LÀ ÉTAIT DÉJÀ ARGUMENTÉ (juste au-dessus), MAIS LE CODE N'EN DISAIT RIEN : le
  // verdict de l'écrivain était simplement JETÉ, et une valeur jetée ne distingue pas un choix d'un
  // oubli. Il passe donc par la porte qui NE REND RIEN, dont le NOM déclare le silence.
  ecrireSansDireLeRefus('soc_ov_order', JSON.stringify(o));   // miroir sync (compat + hors-ligne)
  prefSet('ovOrder', o);                                          // #62 — persiste côté serveur (cross-device)
  applyOvOrder();
}
function initOverviewLayout() {
  OV_CARDS.forEach(id => {
    const sec = $('#' + id); if (!sec || sec._ovInit) return; sec._ovInit = true;
    sec.style.position = 'relative';
    const grip = document.createElement('span'); grip.className = 'ovgrip'; grip.title = 'Glisser pour réorganiser la vue'; grip.innerHTML = ic('grip'); grip.draggable = true;
    grip.addEventListener('dragstart', e => { e.dataTransfer.setData(OV_DT, id); e.dataTransfer.effectAllowed = 'move'; sec.classList.add('ovdragging'); });
    grip.addEventListener('dragend', () => sec.classList.remove('ovdragging'));
    sec.addEventListener('dragover', e => { if (e.dataTransfer.types.includes(OV_DT)) { e.preventDefault(); sec.classList.add('ovdragover'); } });
    sec.addEventListener('dragleave', () => sec.classList.remove('ovdragover'));
    sec.addEventListener('drop', e => {
      if (!e.dataTransfer.types.includes(OV_DT)) return;
      e.preventDefault(); sec.classList.remove('ovdragover');
      const from = e.dataTransfer.getData(OV_DT); if (from && from !== id) saveOvDrop(from, id);
    });
    sec.appendChild(grip);
  });
  applyOvOrder();
}
initOverviewLayout();

// completion flottante de la barre de recherche (#q) : suggere les champs (source:, host:, ...)
(function qComplete() {
  const inp = $('#q'); if (!inp) return;
  const box = document.createElement('div'); box.id = 'qac'; box.className = 'qac'; box.hidden = true; document.body.appendChild(box);
  const curWord = () => { const v = inp.value, c = inp.selectionStart; let i = c; while (i > 0 && /\w/.test(v[i - 1])) i--; return { w: v.slice(i, c), s: i, e: c }; };
  const hide = () => { box.hidden = true; };
  const upd = () => {
    const { w } = curWord(); if (w.length < 1) return hide();
    const wl = w.toLowerCase();
    const cand = SOQL_FIELDS.filter(f => f.startsWith(wl) && f !== wl).slice(0, 8);
    if (!cand.length) return hide();
    const r = inp.getBoundingClientRect();
    box.style.left = r.left + 'px'; box.style.top = (r.bottom + 4) + 'px'; box.style.minWidth = r.width + 'px';
    box.hidden = false;
    box.replaceChildren(...cand.map(f => { const b = document.createElement('button'); b.type = 'button'; b.className = 'acchip'; b.textContent = f + ':'; b.onmousedown = (e) => { e.preventDefault(); const o = curWord(); inp.value = inp.value.slice(0, o.s) + f + ':' + inp.value.slice(o.e); inp.focus(); upd(); }; return b; }));
  };
  inp.addEventListener('input', upd);
  inp.addEventListener('blur', () => setTimeout(hide, 150));
  inp.addEventListener('keydown', e => { if (e.key === 'Escape') hide(); });
})();

installI18nObserver();   // amorçage du lexique sous LANG='en' : marche initiale + observateur des nœuds/attributs ajoutés après coup (i18n_observer.js)
// `P4.13-b` — SANS STOCKAGE LA LANGUE NE PEUT PAS CHANGER, ET LA LISTE NE DOIT PAS PRÉTENDRE LE CONTRAIRE.
// `LANG` est lu UNE fois, du stockage, à l'évaluation de `core.js` : aucun chemin en mémoire ne le change,
// et recharger sans avoir écrit ramènerait la langue d'avant. Le choix est donc REFUSÉ pour de bon — la
// liste est remise sur la langue RÉELLE, sans quoi elle afficherait « English » au-dessus d'une interface
// restée française : exactement l'état à moitié basculé que cette clé ferme. Nue, l'écriture jetait avant
// `location.reload()`, ce qui laissait déjà la liste sur une langue que l'interface n'employait pas.
if ($('#lang')) {
  $('#lang').value = LANG;
  $('#lang').onchange = () => {
    if (ecrireDansLeStockageDuSite('soc_lang', $('#lang').value)) { location.reload(); return; }
    $('#lang').value = LANG;
    toast(LANG === 'en' ? 'Language unchanged: this browser refuses site storage, and the language is read from it at startup.' : 'Langue inchangée : ce navigateur refuse le stockage de site, or la langue y est lue au démarrage.', 'info', 5000);
  };
}

// ============ tous les fuseaux IANA (Intl) — favoris en tête, le reste ajouté dynamiquement ============
(function fillTz() {
  const s = $('#tz'); if (!s || !window.Intl || !Intl.supportedValuesOf) return;
  let zones = []; try { zones = Intl.supportedValuesOf('timeZone'); } catch (e) { return; }
  const have = new Set([...s.options].map(o => o.value));
  const grp = document.createElement('optgroup'); grp.label = LANG === 'en' ? 'All time zones' : 'Tous les fuseaux';
  zones.forEach(z => { if (!have.has(z)) { const o = document.createElement('option'); o.value = z; o.textContent = z; grp.appendChild(o); } });
  s.appendChild(grp); s.value = socTZ;
})();

initAuthGate();   // écran de connexion, déconnexion, état d'auth : câblage + GET /api/me qui ouvre l'app ou l'overlay (login.js)

/* ==== exports consumed by seam modules (auto-managed) ==== */
export { ROLE_LABEL, SPACES, currentTab, currentViewName, fetchMe, loadActions, loadDashboard, loadUsers, refresh, refreshCurrentView, refreshPanels, renderNav, route, setAlertMitreFilter, setAlertSourceFilter, setAuthUI, updateQRangeBtn, updateRangeBtn };

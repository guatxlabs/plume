import {
  $, CSSV, socTZ, LANG, LOC, tzOpts, fmtTs, SEV, sev, bool, esc, ICONS, ic, closeModals, withBusy, toast, showErr, modal, confirmModal, csvCell, downloadText, tsSlug, exportPDF, exportBar, closeMiniMenu, api, apiSend, muted, colComparator, pageNums, pagedList,
  setSocTZ,
  socIsAdmin, formMsg,
  confirmWithConsequence, disclosure
} from './core.js';
import { installI18nObserver } from './i18n_observer.js';
import { S } from './state.js';
import { banIp, clearDrillCrumb, evLoad, exploreFrom, exploreTo, qHistGo, renderViz, runQuery, setZoom, stopExplore, updateZoomBadge } from './viz.js';
import { initDashboards, loadDashboard, loadDashboards, refreshPanels } from './dashboards.js';
import { renderDataAccess } from './dataaccess.js';
import { initLookups } from './lookups.js';
import { loadFleetView } from './fleet.js';
import { initAuthGate, fetchMe, setAuthUI } from './login.js';
import { loadSourcesView } from './sources.js';
import { loadSystemView } from './system.js'; // #51 DAY-2 OPS — console d'opérabilité + bandeau MOTD
import { loadLedger } from './audit.js';
import { applyConnectorType, loadConnectors, openConnectorForm, httpPullFormConfig, addFieldMapRow, addStMapRow, previewHttpPull, openPresetPicker } from './connectors.js';
import { loadDestinations, openDestinationForm } from './destinations.js';
import { loadIdpProviders, loadMfa } from './idp.js'; // #44 — IdP natif (fournisseurs OIDC/LDAP admin + MFA TOTP self-service)
import { loadRouting } from './alerting.js'; // #53 — politiques de notification (routage) + silences (mute temporisé)
import { loadFieldFilters } from './fieldfilters.js'; // #45 — field filters (masquage PII par champ, admin-only)
import { loadProcessors, openProcessorForm } from './processors.js';
import { loadIndexPolicies, openIndexPolicyForm } from './index_policies.js';
import { initThreatIntel, loadThreatIntel } from './threatintel.js';
import { loadRiskView } from './risk.js';
import { loadDetAdv } from './detadv.js';
import { loadAttackMatrix } from './attack.js';
import { initSigmaImport } from './sigmaimport.js';
import { loadOperatorAudit, loadTenantsView, multiTenantMode, uiIsAdmin } from './multitenant.js';
import { addToCase, canEditCases, createCase, loadCases, openCase } from './cases.js';
import { loadKnowledge } from './knowledge.js'; // #46 — objets de savoir (alias/calc/eventtype/tag) : lecture viewer+, CRUD éditeur+
import { loadDataModels } from './datamodels.js'; // #47 — modèles de données + Pivot (report-builder) + datasets : lecture/exécution viewer+, CRUD éditeur+
import { prefGet, prefSet, prefsReady } from './prefs.js'; // #62 — préférences utilisateur self-scoped (favoris, réglages par vue, plage par défaut)
import { initKeyboardNav } from './keys.js'; // #62 — navigation clavier (/, g+touche, j/k, ?) non-intrusive
import { initSoqlComplete } from './soql_complete.js'; // complétion IDE-like NATIVE de la barre Explore (schema/templates)
import { initSavedQueries } from './savedqueries.js'; // requêtes GXQL nommées per-user (owner-scoped) + historique récent (localStorage)
import { renderFreshness, renderFreshnessPulse, renderIntegrations } from './freshness.js'; // découpe par concern ; pulse compact de la Vue d'ensemble
import { renderAlerts, setAlertMitreFilter, setAlertSourceFilter } from './alerts.js'; // decoupe par concern (alerts)
import { renderCoverage, loadActions, loadMode, loadPlaybooks } from './detection_admin.js';
import { loadRunbooks } from './runbooks.js'; // #3 Phase 2 — authoring runbooks (bring-your-own), admin-only
import { ROLE_LABEL, loadUsers, loadTokens } from './admin_users.js';
import { loadRetention } from './retention.js';
import { loadSuppressions } from './suppressions.js'; // panneau « Suppressions & whitelists » + silences (créer/modifier/supprimer)
import { renderHelpGuide, openHelpModal, openFreshnessHelp } from './help.js'; // #4c — aide in-app (split H1) : page Aide + modales GXQL/Fraîcheur, câblage #qhelp/#fresh-help ci-dessous


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


async function refresh() {
  try {
    // les 3 requêtes en parallèle (pas en série)
    const [ov] = await Promise.all([api('/overview'), renderAlerts(), renderFirewall(), renderControls(), renderIntegrations(), renderFreshnessPulse(), loadActions(), loadMode(), loadPlaybooks()]);
    $('#status').textContent = 'connecté';
    $('#updated').textContent = fmtTs(ov.ts);
    const p = $('#posture');
    p.textContent = ov.open_alerts > 0 ? `${ov.open_alerts} alerte(s)` : 'OK ';
    p.className = 'posture ' + (ov.open_alerts > 0 ? 'bad' : 'ok');
  } catch (e) {
    $('#status').textContent = 'hors-ligne (' + e.message + ')';
  }
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
  if (!r.data || !r.data.controls) { b.innerHTML = '<div class="muted">en attente du capteur (5 min)...</div>'; return; }
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
//   GET  /api/ledger?limit=<n>     -> {ok,entries:[{id,ts,kind,detail,hash}]} (id DESC, admin)
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
window.addEventListener('hashchange', route);
// navigation par hash MANUELLE : preventDefault tue le scroll-into-view natif des ancres dont l'id existe
// réellement (#dashboards/#parsers/#playbooks/#cases/#settings) -> plus d'à-coup vers le bas.
function navTo(href) {
  if (!href || !href.startsWith('#')) return;
  const v = href.slice(1);
  if (location.hash.slice(1) === v) route();        // même hash : hashchange ne se déclenche pas -> route() direct
  else location.hash = v;                            // sinon hashchange -> route()
}
// niveau 1 (espaces, statiques) : clic direct ; href = 1er sous-onglet de l'espace (onglet par défaut).
document.querySelectorAll('#nav a').forEach(a => a.addEventListener('click', e => { e.preventDefault(); navTo(a.getAttribute('href')); }));
// niveau 2 (sous-onglets, rendus dynamiquement) : délégation sur #subnav.
if ($('#subnav')) $('#subnav').addEventListener('click', e => { const a = e.target.closest('a'); if (!a) return; e.preventDefault(); navTo(a.getAttribute('href')); });
// Le burger est la SOURCE UNIQUE du repli à toute largeur. ≤1024px on démarre replié (visuel
// icônes-seules inchangé) -> le burger déplie réellement (labels + sous-onglets atteignables) ; >1024px inchangé.
{ const l0 = document.querySelector('.layout'); if (l0 && window.matchMedia('(max-width:1024px)').matches) l0.classList.add('collapsed'); }
if ($('#navtoggle')) $('#navtoggle').onclick = () => { const l = document.querySelector('.layout'); if (l) l.classList.toggle('collapsed'); };
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
  const saved = localStorage.getItem('soc-theme');
  if (saved) document.documentElement.dataset.theme = saved;
  const btn = $('#theme');
  const paint = () => { if (btn) btn.innerHTML = ic(document.documentElement.dataset.theme === 'light' ? 'moon' : 'sun'); };
  paint();
  if (btn) btn.onclick = () => {
    const t = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = t;
    localStorage.setItem('soc-theme', t);
    paint();
    refresh();          // recolore les graphes SVG (ils lisent les variables CSS au rendu)
    loadDashboard();
  };
})();

// --- fenêtre temporelle + rafraîchissement auto ---
/* state: autoTimer -> S (state.js) */
/* state: autoPaused -> S (state.js) */   // toggle Stop/Start : coupe la boucle d'auto-refresh sans toucher au select #refresh
function applyAutoRefresh() {
  if (S.autoTimer) clearInterval(S.autoTimer);
  S.autoTimer = null;
  if (S.autoPaused) return;   // boucle suspendue par l'utilisateur
  const s = Number(($('#refresh') && $('#refresh').value) || 0);
  if (s > 0) S.autoTimer = setInterval(() => { refresh(); refreshPanels(); }, s * 1000); // P5 : refresh cible, pas de rebuild complet
}
if ($('#refresh')) $('#refresh').addEventListener('change', applyAutoRefresh);
// Refresh MANUEL : relance les chargements de la vue courante (refresh() couvre overview/notifications +
// intégrations/fraîcheur/réponse ; refreshPanels() les panneaux ; + le loader spécifique à la vue).
function refreshCurrentView() {
  const v = currentViewName();
  refresh();
  refreshPanels();
  if (v === 'detection') renderCoverage();
  else if (v === 'cases') loadCases();
  else if (v === 'dashboards') loadDashboard();
  else if (v === 'explore') { if ($('#sql') && $('#sql').value.trim()) runQuery(); }
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
// Modal unique RÉUTILISÉ par les Dashboards (#range/#rangepick) ET par l'Explore (#qrange/#qrangepick) :
// opts = { rangeSel, updateBtn } ; sans opts -> cible Dashboards (#range) par défaut.
function openRangeModal(opts) {
  const cfg = opts || {};
  const rangeSel = cfg.rangeSel || '#range';
  const updateBtn = cfg.updateBtn || updateRangeBtn;
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal rangemodal';
  const cur = Number(($(rangeSel) && $(rangeSel).value) || 0);
  const toLocal = d => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  const now = new Date();
  const f0 = S.zoomRange ? new Date(S.zoomRange.from * 1000) : new Date(now.getTime() - 3600000);
  const t0 = S.zoomRange ? new Date(S.zoomRange.to * 1000) : now;
  box.innerHTML = `
    <h3>Plage temporelle</h3>
    <div class="rmsub">Relatif — depuis maintenant (suit l'heure courante)</div>
    <div class="rmgrid">${RANGE_PRESETS.map(([s, l]) => `<button type="button" class="rmp${!S.zoomRange && s === cur ? ' on' : ''}" data-s="${s}">${l}</button>`).join('')}</div>
    <div class="rmsub">Absolu — intervalle précis (figé)</div>
    <div class="rmabs">
      <label>Début<input type="datetime-local" id="rm-from" value="${toLocal(f0)}"></label>
      <label>Fin<input type="datetime-local" id="rm-to" value="${toLocal(t0)}"></label>
      <button type="button" id="rm-abs">Appliquer l'intervalle</button>
    </div>
    <div class="modal-err" hidden></div>
    <div class="modal-act"><button type="button" class="m-cancel">Fermer</button></div>`;
  ov.appendChild(box); document.body.appendChild(ov);
  const close = () => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  ov.onclick = e => { if (e.target === ov) close(); };
  box.querySelector('.m-cancel').onclick = close;
  box.querySelectorAll('.rmp').forEach(b => b.onclick = () => {
    if ($(rangeSel)) { $(rangeSel).value = b.dataset.s; $(rangeSel).dispatchEvent(new Event('change')); }  // relatif -> clear zoom + reload (cf listener #range / #qrange)
    updateBtn(); close();
  });
  box.querySelector('#rm-abs').onclick = () => {
    const a = new Date(box.querySelector('#rm-from').value).getTime(), b = new Date(box.querySelector('#rm-to').value).getTime();
    const err = box.querySelector('.modal-err');
    if (isNaN(a) || isNaN(b)) { err.textContent = 'Dates invalides.'; err.hidden = false; return; }
    if (a >= b) { err.textContent = 'Le début doit précéder la fin.'; err.hidden = false; return; }
    setZoom(a / 1000, b / 1000); updateBtn(); close();
  };
}
if ($('#rangepick')) $('#rangepick').onclick = () => openRangeModal();
// Explore : même control/design que les Dashboards (presets jusqu'à 1 an + intervalle précis), piloté par #qrange.
if ($('#qrangepick')) $('#qrangepick').onclick = () => openRangeModal({ rangeSel: '#qrange', updateBtn: updateQRangeBtn });
// fuseau horaire d'affichage (stockage UTC) : recharge pour re-rendre tous les temps affichés
if ($('#tz')) { $('#tz').value = socTZ; $('#tz').onchange = () => { setSocTZ($('#tz').value); localStorage.setItem('soc_tz', socTZ); location.reload(); }; }
if ($('#qhelp')) $('#qhelp').onclick = openHelpModal;
if ($('#fresh-help')) $('#fresh-help').onclick = openFreshnessHelp;
if ($('#fresh-refresh')) $('#fresh-refresh').onclick = () => renderFreshness(true); // refresh manuel -> barre .tableprog (idem Explore/Dashboards)
updateRangeBtn();
updateQRangeBtn();
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
  localStorage.setItem('soc_ov_order', JSON.stringify(o));   // miroir sync (compat + hors-ligne)
  prefSet('ovOrder', o);                                     // #62 — persiste côté serveur (cross-device)
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
if ($('#lang')) { $('#lang').value = LANG; $('#lang').onchange = () => { localStorage.setItem('soc_lang', $('#lang').value); location.reload(); }; }

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

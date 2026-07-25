import {
  $, CSSV, socTZ, LANG, LOC, tzOpts, fmtTs, SEV, sev, bool, esc, ICONS, ic, flashStopped, stopBtn, closeModals, withBusy, toast, showErr, modal, confirmModal, csvCell, toCSV, downloadText, tsSlug, exportPDF, exportBar, closeMiniMenu, miniMenu, api, apiSend, transientGatewayMsg, muted, colComparator, makePager, pageNums, pagedList,
  setSocTZ,
  socIsAdmin, managedBadge, formMsg, contentDelete
} from './core.js';
import { i18nWalk } from './i18n.js';
import { S } from './state.js';
import { banIp, clearDrillCrumb, currentFrom, currentTo, doSearch, evLoad, exploreFrom, exploreTo, qHistGo, queryCount, renderViz, runQ, runQuery, setZoom, stopExplore, tableEl, updateZoomBadge, vizElement } from './viz.js';
import { loadFleetView } from './fleet.js';
import { loadSourcesView } from './sources.js';
import { loadSystemView, loadBulletin } from './system.js'; // #51 DAY-2 OPS — console d'opérabilité + bandeau MOTD
import { loadLedger } from './audit.js';
import { applyConnectorType, loadConnectors, openConnectorForm, httpPullFormConfig, addFieldMapRow, addStMapRow, previewHttpPull, openPresetPicker } from './connectors.js';
import { loadDestinations, openDestinationForm } from './destinations.js';
import { loadIdpProviders, loadMfa } from './idp.js'; // #44 — IdP natif (fournisseurs OIDC/LDAP admin + MFA TOTP self-service)
import { initAiAssist } from './ai.js'; // #16 — assistant IA (NL→SOQL) dans Explore ; révélé UNIQUEMENT si /api/ai/status = enabled (feature off -> reste caché)
import { loadRouting } from './alerting.js'; // #53 — politiques de notification (routage) + silences (mute temporisé)
import { loadFieldFilters } from './fieldfilters.js'; // #45 — field filters (masquage PII par champ, admin-only)
import { loadProcessors, openProcessorForm } from './processors.js';
import { loadIndexPolicies, openIndexPolicyForm } from './index_policies.js';
import { initThreatIntel, loadThreatIntel } from './threatintel.js';
import { loadRiskView } from './risk.js';
import { loadDetAdv } from './detadv.js';
import { loadAttackMatrix } from './attack.js';
import { initSigmaImport } from './sigmaimport.js';
import { initEnvironments, initTenants, loadOperatorAudit, loadTenantsView, multiTenantMode, uiIsAdmin } from './multitenant.js';
import { addToCase, canEditCases, createCase, loadCases, openCase } from './cases.js';
import { loadKnowledge } from './knowledge.js'; // #46 — objets de savoir (alias/calc/eventtype/tag) : lecture viewer+, CRUD éditeur+
import { loadDataModels } from './datamodels.js'; // #47 — modèles de données + Pivot (report-builder) + datasets : lecture/exécution viewer+, CRUD éditeur+
import { prefGet, prefSet, prefsInit, prefsReady } from './prefs.js'; // #62 — préférences utilisateur self-scoped (favoris, réglages par vue, plage par défaut)
import { initKeyboardNav } from './keys.js'; // #62 — navigation clavier (/, g+touche, j/k, ?) non-intrusive
import { initSoqlComplete } from './soql_complete.js'; // complétion IDE-like NATIVE de la barre Explore (schema/templates)
import { initSavedQueries } from './savedqueries.js'; // requêtes SOQL nommées per-user (owner-scoped) + historique récent (localStorage)
import { renderFreshness, renderFreshnessPulse, renderIntegrations } from './freshness.js'; // découpe par concern ; pulse compact de la Vue d'ensemble
import { renderAlerts, setAlertMitreFilter, setAlertSourceFilter } from './alerts.js'; // decoupe par concern (alerts)
import { renderCoverage, loadActions, loadMode, loadPlaybooks } from './detection_admin.js';
import { loadRunbooks } from './runbooks.js'; // #3 Phase 2 — authoring runbooks (bring-your-own), admin-only
import { ROLE_LABEL, loadUsers, loadTokens } from './admin_users.js';
import { loadRetention, loadSuppressions } from './retention.js';
import { renderHelpGuide, openHelpModal, openFreshnessHelp } from './help.js'; // #4c — aide in-app (split H1) : page Aide + modales SOQL/Fraîcheur, câblage #qhelp/#fresh-help ci-dessous


// --- CRUD contenu de détection (#1c) : rôles UI + « managed » + remontée d'erreurs serveur ------
// Défense en profondeur : la VRAIE garde reste serveur (le daemon renvoie 400/403/404/409 + {error}).
// On reflète le rôle courant sur <body> (classes role-admin/role-editor/role-viewer) -> le CSS masque
// les contrôles d'écriture de façon RÉTROACTIVE (indépendant de l'ordre de rendu des listes). AUTH.role
// (GET /api/me) fait foi ; à défaut on hérite de la classe posée par les dashboards/vues.
function applyRoleClass(role) {
  if (!role || !document.body) return;
  document.body.classList.toggle('role-admin', role === 'admin');
  document.body.classList.toggle('role-editor', role === 'editor');
  document.body.classList.toggle('role-viewer', role === 'viewer');
}

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
// puis télécharge. Même dérivation SOQL/SQL-brut que runQuery (le SQL brut non-admin est refusé côté serveur).
async function exploreExport(format) {
  const q = ($('#sql') && $('#sql').value.trim()) || '';
  if (!q) { toast('Aucune requête à exporter', 'info'); return; }
  const isSoql = /^\s*search\b/i.test(q) || q.includes('|');
  if (!isSoql && !socIsAdmin()) { toast("SQL brut réservé à l'administrateur — utilisez SOQL", 'bad'); return; }
  const body = isSoql ? { soql: q } : { sql: q };
  body.from = exploreFrom(); body.to = exploreTo(); body.format = format; body.name = 'explore';
  let r;
  try { r = await fetch('/api/export', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); }
  catch (e) { toast('Export échoué : ' + e.message, 'bad'); return; }
  if (!r.ok) { let m = ''; try { m = (await r.json()).error || ''; } catch (_) {} toast('Export refusé' + (m ? ' : ' + m : ' (' + r.status + ')'), 'bad'); return; }
  const text = await r.text();
  const trunc = r.headers.get('x-plume-truncated') === '1';
  downloadText(`plume-explore-${tsSlug()}.${format}`, format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json', text);
  toast('Export ' + format.toUpperCase() + ' téléchargé' + (trunc ? ' (tronqué au plafond de lignes)' : ''), trunc ? 'info' : 'ok');
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
  b.innerHTML = lockdown + `<div class="muted">ruleset ${esc((r.data.ruleset_sha256 || '').slice(0, 12))}... - ${fmtTs(r.ts)}</div>`;
}
async function renderControls() {
  const r = await api('/panel/controls');
  const b = $('#controls .body');
  if (!r.data || !r.data.controls) { b.innerHTML = '<div class="muted">en attente du capteur (5 min)...</div>'; return; }
  b.innerHTML = r.data.controls.map(c =>
    `<div class="kv"><span>${esc(c.id)}</span><b class="${c.ok ? 'ok' : 'bad'}">${c.ok ? 'OK ' + ic('check') : 'MANQUANT ' + ic('warn')}</b></div>`
  ).join('') + `<div class="muted">${r.data.failed || 0} manquant(s) - ${fmtTs(r.ts)}</div>`;
}


// --- DLP / gouvernance d'accès (style Varonis) — onglet LECTURE SEULE (Phase 1) -------------------
// "Qui touche quoi", intégrité (FIM) et droits (ACL/RBAC). Chaque panneau s'appuie sur une requête
// EXISTANTE (runQ -> /api/query, scan toute la fenêtre), AUCUN nouvel endpoint, AUCUNE mutation hôte.
// Ce n'est PAS du DLP de contenu : c'est de la gouvernance d'accès en lecture seule.
const DATA_PANELS = [
  { id: 'whoami', title: 'Qui touche quoi (accès données)', queries: [{ soql: 'search source=dataaccess | stats count by path,user | sort -count | head 30' }] },
  { id: 'tamper', title: 'Fichiers sensibles / tamper', queries: [{ soql: 'search source=auditd severity>=4 | sort -ts | head 30' }] },
  { id: 'fim', title: 'Intégrité (FIM)', queries: [{ soql: 'search source=integrity | sort -ts | head 30' }] },
  { id: 'acl',  title: 'ACL fichiers (dataacl)',      queries: [{ soql: 'search source=dataacl | sort -ts | head 20' }] },
  { id: 'rbac', title: 'RBAC Kubernetes (kube-rbac)', queries: [{ soql: 'search source=kube-rbac | sort -ts | head 20' }] },
];
// chemins surveillés côté hôte (clés de watch auditd) — affichage informatif, édition = Phase 2
const DATA_WATCHED = ['/etc', '/etc/rancher/k3s', '/opt/local-path-provisioner', '/etc/shadow', '/etc/sudoers', 'binaires SUID', 'unités systemd'];
// D12 — fenêtre d'analyse des panneaux DLP. Défaut 'all' (from=0 = toute la rétention, cappé top-N par head).
// Le sélecteur câble fromOverride (3e arg de runQ). Libellés VISIBLES au-dessus des panneaux.
/* state: daWin -> S (state.js) */
const DA_WINLBL = { all: 'toute la rétention (~30 j)', '7d': '7 derniers jours', '24h': 'dernières 24 h' };
function daFromValue() { return S.daWin === 'all' ? 0 : Math.floor(Date.now() / 1000) - (S.daWin === '7d' ? 604800 : 86400); }
async function renderDataAccess() {
  const host = $('#da-body'); if (!host) return;
  host.replaceChildren();
  const intro = document.createElement('p'); intro.className = 'muted'; intro.style.margin = '0 0 12px';
  intro.textContent = "Gouvernance d'accès (style Varonis) : qui touche quoi, intégrité et droits. Lecture seule — pas de DLP de contenu, aucune action depuis cet onglet.";
  // BATCH 2 (B6) : le ? d'aide est désormais dans l'en-tête visible (index.html, .panelhead > h2 > .ihelp.vhelp)
  // au lieu d'être collé dans ce paragraphe d'intro. Handler .vhelp toujours délégué.
  host.appendChild(intro);
  // D12 — indicateur de fenêtre VISIBLE + sélecteur (24 h / 7 j / tout) câblant fromOverride.
  const bar = document.createElement('div'); bar.className = 'da-winbar';
  const wlbl = document.createElement('span'); wlbl.className = 'muted';
  wlbl.textContent = 'Fenêtre : ' + DA_WINLBL[S.daWin] + ' · top N par panneau';
  const wsel = document.createElement('select'); wsel.className = 'k-theme'; wsel.setAttribute('aria-label', "Fenêtre d'analyse (DLP)");
  wsel.title = "Fenêtre d'analyse : borne le `from` des requêtes (le nombre de lignes reste cappé par panneau)";
  [['24h', '24 h'], ['7d', '7 j'], ['all', 'Tout']].forEach(([v, t]) => { const o = document.createElement('option'); o.value = v; o.textContent = t; if (v === S.daWin) o.selected = true; wsel.appendChild(o); });
  wsel.onchange = () => { S.daWin = wsel.value; renderDataAccess(); };
  bar.append(wlbl, wsel); host.appendChild(bar);
  const daFrom = daFromValue();
  const emptyTxt = 'Aucun changement récent (' + DA_WINLBL[S.daWin] + ') — ou capteur inactif';
  for (const p of DATA_PANELS) {
    const card = document.createElement('section'); card.className = 'card'; card.dataset.da = p.id;
    const h = document.createElement('h2'); h.textContent = p.title; card.appendChild(h);
    const slots = p.queries.map(q => {
      if (q.label) { const lab = document.createElement('div'); lab.className = 'fldname'; lab.textContent = q.label; card.appendChild(lab); }
      const slot = document.createElement('div'); slot.className = 'body'; slot.textContent = '...'; card.appendChild(slot); return slot;
    });
    host.appendChild(card);
    // requêtes EN PARALLÈLE (placeholder déjà rendu) ; from=daFrom (0 = toute la rétention ; head N borne le coût)
    p.queries.forEach((q, i) => {
      const slot = slots[i];
      runQ(q.soql, true, daFrom).then(j => {
        if (!j || j.error || !Array.isArray(j.rows) || !j.rows.length) { slot.replaceChildren(muted(emptyTxt)); return; }
        // conteneur scrollable (comme l'Explore) -> les tables larges (dataacl : ~17 colonnes, chemins
        // /opt/local-path-provisioner/pvc-… longs) défilent DANS la card au lieu de déborder la mise en page.
        const wrap = document.createElement('div'); wrap.className = 'qresult daresult';
        wrap.appendChild(tableEl(j.columns, j.rows, q.soql));
        slot.replaceChildren(wrap);
      }).catch(() => slot.replaceChildren(muted(emptyTxt)));
    });
  }
  // note de gouvernance : périmètre surveillé (auditd) + cap sur la Phase 2
  const note = document.createElement('section'); note.className = 'card da-note';
  const nh = document.createElement('h2'); nh.textContent = 'Périmètre surveillé (hôte)'; note.appendChild(nh);
  const chips = document.createElement('div'); chips.style.cssText = 'display:flex;flex-wrap:wrap;gap:6px;margin-bottom:4px';
  DATA_WATCHED.forEach(w => { const c = document.createElement('span'); c.className = 'plugchip'; c.textContent = w; chips.appendChild(c); });
  note.appendChild(chips);
  note.appendChild(muted("Configuration côté hôte (auditd). Édition depuis l'UI = Phase 2 (à venir)."));
  host.appendChild(note);
  initDaLayout();
}

// réorganisation par glisser-déposer des cards d'accès données (grille 2×2), ordre persisté localement
const DA_DT = 'text/soc-da';
function daOrder(){ try { return JSON.parse(localStorage.getItem('soc_da_order')) || []; } catch(e){ return []; } }
function applyDaOrder(){ const host=$('#da-body'); if(!host) return; const note=host.querySelector('.da-note'); const cards=[...host.querySelectorAll('.card[data-da]')]; const ord=daOrder(); cards.sort((a,b)=>{const ia=ord.indexOf(a.dataset.da),ib=ord.indexOf(b.dataset.da); return (ia<0?99:ia)-(ib<0?99:ib);}); cards.forEach(c=>host.insertBefore(c,note)); }
function saveDaDrop(from,to){ const ids=[...$('#da-body').querySelectorAll('.card[data-da]')].map(c=>c.dataset.da); let o=daOrder().filter(x=>ids.includes(x)); ids.forEach(x=>{if(!o.includes(x))o.push(x);}); o.splice(o.indexOf(from),1); o.splice(o.indexOf(to),0,from); localStorage.setItem('soc_da_order',JSON.stringify(o)); applyDaOrder(); }
function initDaLayout(){ $('#da-body').querySelectorAll('.card[data-da]').forEach(card=>{ const id=card.dataset.da; const grip=document.createElement('span'); grip.className='ovgrip'; grip.title='Glisser pour réorganiser'; grip.innerHTML=ic('grip'); grip.draggable=true; grip.addEventListener('dragstart',e=>{e.dataTransfer.setData(DA_DT,id); e.dataTransfer.effectAllowed='move'; card.classList.add('ovdragging');}); grip.addEventListener('dragend',()=>card.classList.remove('ovdragging')); card.addEventListener('dragover',e=>{ if(e.dataTransfer.types.includes(DA_DT)){e.preventDefault(); card.classList.add('ovdragover');} }); card.addEventListener('dragleave',()=>card.classList.remove('ovdragover')); card.addEventListener('drop',e=>{ if(!e.dataTransfer.types.includes(DA_DT))return; e.preventDefault(); card.classList.remove('ovdragover'); const from=e.dataTransfer.getData(DA_DT); if(from&&from!==id) saveDaDrop(from,id); }); card.appendChild(grip); }); applyDaOrder(); }

// --- recherche style Splunk : timeline + fields sidebar + events ---
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
// UNE SEULE requête explore en vol : { qid, sig, ctrl(AbortController) }. sig = signature (soql + fenêtre
// + zoom + page) -> dédup d'un clic identique ; sinon cancel-previous (abort + /api/cancel) puis relance.
/* state: exploreInflight -> S (state.js) */
// sélecteur de colonnes : un seul menu ouvert à la fois (échappe l'overflow de .qresult via position:fixed)
/* state: _colsMenuClose, _colsMenuOwner -> S (state.js) */

// --- panneau requête ad hoc ---
/* state: lastResult -> S (state.js) */
/* state: lastSearchQ -> S (state.js) */ // derniere recherche FTS (pour re-render au zoom)
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
  if (S.lastSearchQ) doSearch(S.lastSearchQ);   // le picker LOCAL pilote AUSSI la recherche FTS (#q) — une seule fenêtre Explore
});

// --- dashboards (P3) ---
/* state: editing, dashList, viewList, panelCards -> S (state.js) */ // mode édition + listes + cartes panneaux
const panelInflight = new Set();   // AbortControllers des panneaux en vol (bouton STOP de la vue Dashboards)
// #dash-stop visible TANT QU'un panneau est en vol ; load()'s finally rappelle ceci -> auto-masquage propre.
function syncDashStop(){ const sb=$('#dash-stop'); if(sb) sb.hidden = panelInflight.size===0; }
function stopDashboards() {
  panelInflight.forEach(c => { try { c.abort(); } catch (e) {} });
  panelInflight.clear();
  S.panelCards.forEach(card => { if (card._warmTimer) { clearTimeout(card._warmTimer); card._warmTimer = null; } });
  const sb = $('#dash-stop'); if (sb) sb.hidden = true;
}
function refreshDashboards() {
  const sb = $('#dash-stop'); if (sb) sb.hidden = false;
  S.panelCards.forEach(c => { if (c.isConnected && c._panel && c._panel.loaded) c._panel.reload(); });
  syncDashStop();   // load()'s finally rappelle syncDashStop -> le bouton se masque quand le dernier load se termine
}
// LAZY-LOAD des panneaux : on ne fait le fetch /api/panels/:id/data QUE lorsque la carte entre dans le
// viewport (IntersectionObserver). Évite la RAFALE de N requêtes au chargement (tous les dashboards de la
// vue + tous leurs panneaux d'un coup), y compris ceux de l'onglet Dashboards encore caché, des dashboards
// repliés et des panneaux hors-écran. rootMargin 200px = précharge juste avant l'entrée à l'écran.
/* state: panelObserver -> S (state.js) */
function getPanelObserver() {
  if (S.panelObserver || !('IntersectionObserver' in window)) return S.panelObserver;
  S.panelObserver = new IntersectionObserver((entries) => {
    for (const en of entries) {
      const pn = en.target._panel; if (!pn) continue;
      pn.visible = en.isIntersecting;
      if (en.isIntersecting && !pn.loaded) { pn.loaded = true; pn.reload(); } // 1er fetch à l'apparition
    }
  }, { rootMargin: '200px' });
  return S.panelObserver;
}
// P5 : auto-refresh -> ne recharge QUE les panneaux suivant le global (window_s=0) ;
// un panneau a fenetre manuelle est fige (resync = remettre la fenetre a 0 dans l'edition).
// auto-refresh : ne recharge QUE les panneaux déjà chargés ET visibles (window_s===0) -> ne force pas le
// fetch des panneaux hors-écran/cachés à chaque tick (le lazy-load s'en charge à leur apparition).
function refreshPanels() { S.panelCards.forEach(c => { const pn = c._panel; if (c.isConnected && pn && pn.window_s === 0 && pn.loaded && pn.visible) pn.reload(); }); }
const VIZOPTS = [{ value: 'table', label: 'Table' }, { value: 'bar', label: 'Barres' }, { value: 'line', label: 'Courbe' }, { value: 'stat', label: 'Stat' }, { value: 'gauge', label: 'Jauge' }, { value: 'pie', label: 'Camembert' }, { value: 'donut', label: 'Donut' }, { value: 'heatmap', label: 'Heatmap' }, { value: 'histogram', label: 'Histogramme' }];
async function createPanelModal(did, query = '') {
  // #54 — LIBRARY PANELS : proposer de RÉFÉRENCER une définition réutilisable (édité une fois, à jour partout).
  let libs = [];
  try { libs = (await api('/library-panels')).library_panels || []; } catch (e) {}
  const libOpts = [{ value: '', label: '— aucun (panneau autonome) —' }, ...libs.map(l => ({ value: String(l.id), label: l.name + ' (' + l.viz + ')' }))];
  const r = await modal({
    title: 'Nouveau panneau', okText: 'Créer', fields: [
      { name: 'library_panel_id', label: 'Panneau de bibliothèque (réutilisable)', type: 'select', value: '', options: libOpts },
      { name: 'title', label: 'Titre', required: true, value: 'Panneau' },
      { name: 'query', label: 'Requête (soql ou SQL) — ignorée si un panneau de bibliothèque est choisi', type: 'textarea', required: false, value: query, placeholder: 'search source=sudo | stats count by source' },
      { name: 'viz', label: 'Visualisation', type: 'select', value: 'table', options: VIZOPTS },
      { name: 'visibility', label: 'Panneau', type: 'select', value: 'shared', options: [{ value: 'shared', label: 'public' }, { value: 'private', label: 'privé' }] },
      { name: 'query_private', label: 'Requête privée (cacher le texte aux autres)', type: 'checkbox', value: false },
      { name: 'drill', label: 'Requête au clic / drill (optionnel : $value, $from, $to)', type: 'textarea', value: '', placeholder: 'search source=$value | table ts,source,src_ip,message' },
    ],
  });
  if (!r) return;
  const libId = Number(r.library_panel_id) || 0;
  // Panneau RÉFÉRENÇANT une bibliothèque : la requête/viz sont héritées -> pas de garde SQL brut ici (le
  // library_panel a été gardé à SA création). Sinon, panneau autonome : requête requise + garde SQL brut.
  if (libId) {
    await apiSend('/panels', 'POST', { dashboard_id: Number(did), title: r.title.trim(), library_panel_id: libId, query: '', is_soql: true, visibility: r.visibility });
    await loadDashboards(); toast('Panneau (bibliothèque) créé', 'ok'); return;
  }
  const qq = r.query.trim(); if (!qq) { toast('Requête requise (ou choisis un panneau de bibliothèque).', 'bad'); return; }
  const isSoql = /^\s*search\b/i.test(qq) || qq.includes('|');
  // FAILLE B (UI) — un panneau en SQL brut (saisie non-SOQL) est réservé admin (miroir serveur panel_create).
  if (!isSoql && !socIsAdmin()) { toast('SQL brut réservé à l\'administrateur (utilisez SOQL)', 'bad'); return; }
  await apiSend('/panels', 'POST', { dashboard_id: Number(did), title: r.title.trim(), query: qq, is_soql: isSoql, viz: r.viz, visibility: r.visibility, query_private: !!r.query_private, drill: (r.drill || '').trim() });
  await loadDashboards(); toast('Panneau créé', 'ok');
}
// La VUE courante affiche TOUS ses dashboards ; chaque dashboard = une tuile (carte) avec sa grille de panneaux.
async function loadDashboards() {
  const wrap = $('#dashview'); if (!wrap) return;
  try {
    const view = $('#view') ? $('#view').value : '';
    const data = await api('/dashboards' + (view ? '?view=' + encodeURIComponent(view) : ''));
    S.dashList = data.dashboards || [];
    applyRoleClass(data.role); // reflète le rôle sur <body> -> le CSS masque les contrôles d'écriture
    renderView();
  } catch (e) {}
}
// rafraichit seulement les DONNEES des panneaux (zoom / intervalle) sans rebatir le layout
// changement de plage/zoom : recharge les panneaux VISIBLES tout de suite ; INVALIDE les non-visibles
// (loaded=false) -> ils se rechargeront avec la nouvelle plage à leur prochaine apparition (pas de rafale).
function loadDashboard() {
  S.panelCards.forEach(c => { const pn = c._panel; if (pn && pn.window_s === 0 && !pn.visible) pn.loaded = false; });
  refreshPanels();
}
function patchDash(id, body) { return apiSend('/dashboard/' + id, 'POST', body); }
// #62 — FAVORIS de dashboards (per-user), stockés dans le store de préférences self-scoped (/api/prefs,
// clé `favDash` = liste d'ids). AUCUN schéma dashboard partagé n'est touché (les favoris sont propres à
// chaque compte). Les favoris remontent en tête (tri STABLE, hors mode édition -> jamais de conflit avec le
// réordonnancement manuel persisté) et portent une étoile pleine.
function favDashIds() { const a = prefGet('favDash', []); return Array.isArray(a) ? a.map(Number) : []; }
function isFavDash(id) { return favDashIds().includes(Number(id)); }
function toggleFavDash(id) {
  id = Number(id);
  const cur = favDashIds().filter(x => x !== id);
  if (!isFavDash(id)) cur.unshift(id);   // ajout -> en tête (ordre = récence d'ajout) ; retrait -> déjà filtré
  prefSet('favDash', cur);
}
// largeur d'une tuile = c/4 de la ligne (flex-basis) ; flex-grow=1 -> remplit la largeur restante, passe a la ligne quand plein
const tileBasis = c => 'calc(' + (Math.max(1, Math.min(4, c)) * 25) + '% - 12px)';
function renderView() {
  const wrap = $('#dashview'); if (!wrap) return;
  wrap.classList.toggle('editing', S.editing);
  if (S.panelObserver) { S.panelObserver.disconnect(); S.panelObserver = null; } // repart propre (cartes recréées)
  S.panelCards = [];
  wrap.replaceChildren();
  if (!S.dashList.length) {
    const es = document.createElement('div'); es.className = 'emptystate';
    es.append(Object.assign(document.createElement('div'), { textContent: 'Aucun dashboard' + ($('#view') && $('#view').value ? ' dans cette vue' : '') + '.' }));
    const b = document.createElement('button'); b.textContent = '+ Dashboard'; b.onclick = () => $('#dash-new').click(); es.appendChild(b);
    wrap.replaceChildren(es); return;
  }
  // #62 — hors mode édition, les FAVORIS remontent en tête (tri STABLE : ordre serveur préservé DANS chaque
  // groupe). En mode édition on garde l'ordre canonique S.dashList (le drag-réordonne persiste par index).
  let list = S.dashList;
  if (!S.editing) {
    const favs = favDashIds();
    list = S.dashList.map((d, i) => [d, i]).sort((a, b) => {
      const fa = favs.includes(Number(a[0].id)), fb = favs.includes(Number(b[0].id));
      if (fa !== fb) return fa ? -1 : 1;
      return a[1] - b[1];
    }).map(x => x[0]);
  }
  list.forEach(d => wrap.appendChild(renderDashboard(d)));
}
function renderDashboard(d) {
  const editable = d.editable !== false;
  const tile = document.createElement('section'); tile.className = 'dashtile card2'; tile.dataset.id = d.id;
  const cols = Math.max(1, Math.min(4, d.cols || 2));
  tile.style.flexBasis = tileBasis(cols);
  if (d.collapsed) tile.classList.add('collapsed');
  // --- en-tete : plier + (poignee) + titre + outils ---
  const head = document.createElement('div'); head.className = 'dashtile-head';
  const chev = document.createElement('button'); chev.type = 'button'; chev.className = 'chev picon'; chev.title = 'Plier / deplier'; chev.innerHTML = ic(d.collapsed ? 'chevright' : 'chevdown');
  const grip = document.createElement('span'); grip.className = 'grip editonly'; grip.innerHTML = ic('grip'); grip.title = 'Glisser l\'en-tete pour reordonner';
  const h = document.createElement('h3'); h.textContent = d.name;
  const meta = document.createElement('span'); meta.className = 'dashmeta'; meta.textContent = `${d.panels} panneau(x)${d.visibility === 'private' ? ' - prive' : ''}`;
  const tools = document.createElement('div'); tools.className = 'paneltools';
  // #62 — étoile FAVORI (tous rôles : préférence perso, pas une mutation partagée). Toggle instantané : on
  // repeint l'étoile et, à l'ajout, on remonte la tuile en tête sans recharger les panneaux (le tri complet
  // favoris-en-tête s'applique au prochain rendu de la vue).
  const fav = document.createElement('button'); fav.type = 'button'; fav.className = 'picon favstar';
  const paintFav = () => { const on = isFavDash(d.id); fav.classList.toggle('on', on); fav.innerHTML = ic(on ? 'starfill' : 'star'); fav.title = on ? 'Retirer des favoris' : 'Ajouter aux favoris'; };
  paintFav();
  fav.onclick = () => {
    const wasFav = isFavDash(d.id);
    toggleFavDash(d.id); paintFav();
    if (!wasFav) { const w = $('#dashview'); if (w && tile.parentElement === w) w.insertBefore(tile, w.firstChild); }
  };
  const addp = document.createElement('button'); addp.type = 'button'; addp.className = 'picon'; addp.innerHTML = ic('plus'); addp.title = 'Ajouter un panneau';
  // refresh PAR DASHBOARD (non editonly : un viewer peut rafraîchir) -> recharge UNIQUEMENT les panneaux de CETTE grille
  const dref = document.createElement('button'); dref.type = 'button'; dref.className = 'picon'; dref.innerHTML = ic('refresh'); dref.title = 'Rafraîchir ce dashboard';
  dref.onclick = () => {
    const sb = $('#dash-stop'); if (sb) sb.hidden = false;
    grid.querySelectorAll('.panel').forEach(c => { if (c._panel && c._panel.loaded) c._panel.reload(); });
    syncDashStop();
  };
  const ren = document.createElement('button'); ren.type = 'button'; ren.className = 'picon editonly'; ren.innerHTML = ic('pencil'); ren.title = 'Renommer le dashboard';
  const wsel = document.createElement('select'); wsel.className = 'picon editonly'; wsel.title = 'Largeur (colonnes)';
  [1, 2, 3, 4].forEach(n => { const o = document.createElement('option'); o.value = n; o.textContent = n + ' col'; wsel.appendChild(o); });
  wsel.value = String(cols);
  const del = document.createElement('button'); del.type = 'button'; del.className = 'picon editonly'; del.innerHTML = ic('x'); del.title = 'Supprimer le dashboard';
  // EXPORT dashboard : PDF (impression de la surface #dashboards) ; CSV/JSON se font par panneau.
  const dpdf = document.createElement('button'); dpdf.type = 'button'; dpdf.className = 'picon'; dpdf.innerHTML = ic('print'); dpdf.title = 'Imprimer / exporter ce dashboard en PDF';
  dpdf.onclick = () => exportPDF('dashboards');
  // #54 — INSTANTANÉ : capture le rendu courant (données DÉJÀ masquées côté serveur au rôle de l'appelant),
  // partageable en lecture seule via un token. editor+ (le bouton n'apparaît qu'à eux ; le serveur re-garde).
  const dsnap = document.createElement('button'); dsnap.type = 'button'; dsnap.className = 'picon editonly'; dsnap.innerHTML = ic('save'); dsnap.title = 'Capturer un instantané partageable (lecture seule)';
  dsnap.onclick = () => captureSnapshot(d);
  tools.append(fav, dref, addp, dpdf);
  if (editable) tools.append(dsnap, ren, wsel, del);
  head.append(chev, grip, h, meta, tools);
  tile.appendChild(head);
  // --- corps : grille de panneaux ---
  const body = document.createElement('div'); body.className = 'dashtile-body';
  const grid = document.createElement('div'); grid.className = 'dashgrid'; grid.textContent = '...'; body.appendChild(grid);
  tile.appendChild(body);
  if (d.height > 0) { body.style.height = d.height + 'px'; body.style.overflow = 'auto'; }
  // un dashboard REPLIÉ ne charge même pas sa liste de panneaux : différé jusqu'à la 1re expansion.
  if (!d.collapsed) loadPanelsInto(grid, d);
  else grid._deferredLoad = () => { grid._deferredLoad = null; loadPanelsInto(grid, d); };
  chev.onclick = () => {
    const c = !tile.classList.contains('collapsed');
    tile.classList.toggle('collapsed', c); chev.innerHTML = ic(c ? 'chevright' : 'chevdown');
    d.collapsed = c; // garde dashList a jour -> les re-render ne reviennent pas a l'ancien etat
    if (!c && grid._deferredLoad) grid._deferredLoad(); // expansion -> charge les panneaux (1re fois)
    if (editable) patchDash(d.id, { collapsed: c });
  };
  addp.onclick = () => createPanelModal(d.id);
  ren.onclick = async () => {
    const r = await modal({ title: 'Renommer le dashboard', okText: 'Enregistrer', fields: [{ name: 'name', label: 'Nom', required: true, value: d.name }], validate: v => S.dashList.some(x => x.id !== d.id && x.name === v.name.trim()) ? 'Un dashboard porte deja ce nom.' : null });
    if (!r) return; await patchDash(d.id, { name: r.name.trim() }); loadDashboards();
  };
  wsel.onchange = () => { const n = Number(wsel.value); d.cols = n; tile.style.flexBasis = tileBasis(n); patchDash(d.id, { cols: n }); };
  del.onclick = async () => { if (await confirmModal('Supprimer ce dashboard et ses panneaux ?', { danger: true })) { await apiSend('/dashboard/' + d.id, 'DELETE'); loadDashboards(); } };
  if (editable) {
    // coin de redimensionnement : hauteur px + largeur 1-4 col (calee sur le quart de ligne = garde-fou)
    const corner = document.createElement('div'); corner.className = 'dcorner editonly'; corner.title = 'Redimensionner (glisser)';
    tile.appendChild(corner);
    corner.onmousedown = e => {
      e.preventDefault();
      const y0 = e.clientY, h0 = body.clientHeight || body.scrollHeight, gw = tile.parentElement;
      const slot = gw ? gw.clientWidth / 4 : 320; // largeur d'une colonne (quart de ligne)
      const left = tile.getBoundingClientRect().left;
      let ncols = cols, nh = h0;
      const mv = ev => {
        nh = Math.max(120, h0 + ev.clientY - y0); body.style.height = nh + 'px'; body.style.overflow = 'auto';
        ncols = Math.max(1, Math.min(4, Math.round((ev.clientX - left) / slot)));
        tile.style.flexBasis = tileBasis(ncols); wsel.value = String(ncols);
      };
      const up = () => { document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up); d.cols = ncols; d.height = Math.round(nh); patchDash(d.id, { cols: ncols, height: Math.round(nh) }); };
      document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
    };
    // glisser-deposer pour reordonner (uniquement en mode edition ; poignee = en-tete)
    head.draggable = true;
    head.addEventListener('dragstart', e => { if (!S.editing) { e.preventDefault(); return; } e.dataTransfer.setData('text/plain', String(d.id)); e.dataTransfer.effectAllowed = 'move'; tile.classList.add('dragging'); });
    head.addEventListener('dragend', () => tile.classList.remove('dragging'));
    tile.addEventListener('dragover', e => { if (S.editing) { e.preventDefault(); tile.classList.add('dragover'); } });
    tile.addEventListener('dragleave', () => tile.classList.remove('dragover'));
    tile.addEventListener('drop', e => {
      e.preventDefault(); tile.classList.remove('dragover');
      if (!S.editing) return;
      const from = Number(e.dataTransfer.getData('text/plain'));
      if (from && from !== d.id) reorderDash(from, d.id);
    });
  }
  return tile;
}
async function loadPanelsInto(grid, d) {
  try {
    const j = await api('/dashboard/' + d.id);
    const panels = j.panels || [];
    if (!panels.length) {
      const es = document.createElement('div'); es.className = 'emptystate';
      es.append(Object.assign(document.createElement('div'), { textContent: 'Dashboard vide.' }));
      if (j.editable !== false) { const b = document.createElement('button'); b.textContent = '+ Ajouter un panneau'; b.onclick = () => createPanelModal(d.id); es.appendChild(b); }
      grid.replaceChildren(es); return;
    }
    const frag = document.createDocumentFragment();
    for (const p of panels) { const c = await renderPanel(p, j.editable !== false); S.panelCards.push(c); frag.appendChild(c); }
    grid.replaceChildren(frag);
  } catch (e) { grid.replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'erreur : ' + e.message })); }
}
// reordonne les dashboards (place `from` juste avant `target`) et persiste les positions
function reorderDash(fromId, targetId) {
  const arr = S.dashList.slice();
  const fi = arr.findIndex(x => x.id === fromId);
  if (fi < 0) return;
  const [m] = arr.splice(fi, 1);
  const ti = arr.findIndex(x => x.id === targetId);
  arr.splice(ti < 0 ? arr.length : ti, 0, m);
  arr.forEach((x, i) => { if (x.position !== i) { x.position = i; patchDash(x.id, { position: i }); } });
  S.dashList = arr; renderView();
}
function patchPanel(id, body) { return apiSend('/panels/' + id, 'POST', body); }
// reordonne les PANNEAUX dans une grille de dashboard (place `from` avant `target`) et persiste position
function reorderPanels(grid, fromId, targetId, after) {
  const panels = () => [...grid.children].filter(c => c.classList && c.classList.contains('panel'));
  const cards = panels();
  const fromCard = cards.find(c => c._panelId === fromId), targetCard = cards.find(c => c._panelId === targetId);
  if (!fromCard || !targetCard || fromCard === targetCard) return;
  grid.insertBefore(fromCard, after ? targetCard.nextSibling : targetCard); // avant/apres selon le curseur
  panels().forEach((c, i) => patchPanel(c._panelId, { position: i }));
}
// EXPORT PANNEAU : menu CSV/JSON sur les données courantes du panneau (result = {columns, rows}).
function panelExport(anchor, p, result) {
  if (!result || !result.rows || !result.rows.length) { toast('Aucune donnée à exporter', 'info'); return; }
  const columns = result.columns || [];
  const cols = columns.map(c => ({ key: c, label: c }));
  const objs = result.rows.map(row => { const o = {}; columns.forEach((c, i) => { o[c] = row[i]; }); return o; });
  const base = 'panneau-' + String(p.title || p.id).replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 40);
  miniMenu(anchor, [
    { label: 'CSV', fn: () => downloadText(`plume-${base}-${tsSlug()}.csv`, 'text/csv;charset=utf-8', toCSV(cols, objs)) },
    { label: 'JSON', fn: () => downloadText(`plume-${base}-${tsSlug()}.json`, 'application/json', JSON.stringify(objs, null, 2)) },
  ]);
}
async function renderPanel(p, editable = true) {
  const card = document.createElement('section'); card.className = 'card panel'; card._panelId = p.id;
  const head = document.createElement('div'); head.className = 'panelhead';
  const pgrip = document.createElement('span'); pgrip.className = 'pgrip editonly'; pgrip.innerHTML = ic('grip'); pgrip.title = 'Glisser pour deplacer le panneau'; pgrip.draggable = true;
  const t = document.createElement('h3'); t.textContent = p.title;
  const tools = document.createElement('div'); tools.className = 'paneltools';
  let curViz = p.viz;
  const seg = document.createElement('div'); seg.className = 'seg'; seg.setAttribute('role', 'group'); seg.setAttribute('aria-label', 'Visualisation');
  const btns = {};
  const VIZIC = { table: 'table', bar: 'bars', line: 'activity', stat: 'hash', gauge: 'gauge', pie: 'pie', donut: 'pie', heatmap: 'grid', histogram: 'histogram' };
  [['table', 'Table'], ['bar', 'Barres'], ['line', 'Courbe'], ['stat', 'Stat'], ['gauge', 'Jauge'], ['pie', 'Camembert'], ['donut', 'Donut'], ['heatmap', 'Heatmap'], ['histogram', 'Histogramme']].forEach(([m, lab]) => {
    const b = document.createElement('button'); b.innerHTML = ic(VIZIC[m]); b.title = lab; b.setAttribute('aria-label', lab);
    if (m === curViz) b.classList.add('on');
    b.onclick = () => {
      curViz = m; Object.values(btns).forEach(x => x.classList.remove('on')); b.classList.add('on'); draw();
      if (editable) patchPanel(p.id, { viz: m });
    };
    btns[m] = b; seg.appendChild(b);
  });
  const open = document.createElement('button'); open.className = 'picon'; open.innerHTML = ic('ext'); open.title = 'Ouvrir dans Explore';
  open.onclick = () => { $('#sql').value = p.query; location.hash = 'explore'; runQuery(); };
  const edit = document.createElement('button'); edit.className = 'picon editonly'; edit.innerHTML = ic('pencil'); edit.title = 'Éditer le panneau';
  const del = document.createElement('button'); del.className = 'picon editonly'; del.innerHTML = ic('x'); del.title = 'Supprimer le panneau';
  del.onclick = async () => { if (await confirmModal('Supprimer ce panneau ?', { danger: true })) { await apiSend('/panels/' + p.id, 'DELETE'); loadDashboards(); } };
  const wsel = document.createElement('select'); wsel.className = 'picon editonly'; wsel.title = 'Largeur (colonnes)';
  [1, 2, 3, 4].forEach(n => { const o = document.createElement('option'); o.value = n; o.textContent = n + ' col'; wsel.appendChild(o); });
  wsel.value = String(p.cols || 1);
  wsel.onchange = () => { const n = Number(wsel.value); card.style.flexBasis = tileBasis(n); patchPanel(p.id, { cols: n }); };
  tools.appendChild(seg);
  // refresh + STOP par panneau (non editonly : un viewer peut rafraîchir / arrêter SON chargement)
  const pref = document.createElement('button'); pref.type = 'button'; pref.className = 'picon'; pref.innerHTML = ic('refresh'); pref.title = 'Rafraîchir ce panneau'; pref.onclick = () => load();
  const pstop = stopBtn('Arrêter ce panneau', () => { if (card._loadCtrl) { try { card._loadCtrl.abort(); } catch (e) {} } }); pstop.hidden = true;
  // EXPORT panneau (CSV / JSON) : sérialise les données DÉJÀ chargées (panel_data, déjà caviardé/gated).
  const pexp = document.createElement('button'); pexp.type = 'button'; pexp.className = 'picon'; pexp.innerHTML = ic('download'); pexp.title = 'Exporter les données de ce panneau (CSV / JSON)';
  pexp.onclick = (e) => { e.stopPropagation(); panelExport(pexp, p, result); };
  tools.append(pref, pstop, pexp);
  if (p.query) tools.appendChild(open);          // pas d'ouverture si la requête est privée (texte masqué)
  if (editable) tools.append(wsel, edit, del);
  head.append(pgrip, t, tools); card.appendChild(head);
  // deplacer le panneau dans son dashboard (glisser la poignee ; mode Edition uniquement)
  if (editable) {
    pgrip.addEventListener('dragstart', e => { if (!S.editing) { e.preventDefault(); return; } e.dataTransfer.setData('text/plain', 'panel:' + p.id); e.dataTransfer.effectAllowed = 'move'; card.classList.add('dragging'); });
    pgrip.addEventListener('dragend', () => card.classList.remove('dragging'));
    card.addEventListener('dragover', e => { if (!S.editing) return; e.preventDefault(); e.stopPropagation(); card.classList.add('dragover'); });
    card.addEventListener('dragleave', () => card.classList.remove('dragover'));
    card.addEventListener('drop', e => {
      e.preventDefault(); e.stopPropagation(); card.classList.remove('dragover');
      if (!S.editing) return;
      const dt = e.dataTransfer.getData('text/plain');
      if (!dt.startsWith('panel:')) return; // ignore un drag de dashboard
      const fromId = Number(dt.slice(6));
      if (fromId && fromId !== p.id && card.parentElement) {
        const r = card.getBoundingClientRect();
        reorderPanels(card.parentElement, fromId, p.id, (e.clientX - r.left) > r.width / 2);
      }
    });
  }
  card.style.flexBasis = tileBasis(p.cols || 1);
  const vistag = p.visibility === 'private' ? '  [privé]' : '';
  const qline = document.createElement('code'); qline.className = 'panelq';
  qline.textContent = (p.query || '(requête privée)') + (p.window_s ? `  - fenêtre fixe ${p.window_s}s (épinglé)` : '') + vistag;
  qline.title = (p.is_soql ? 'soql' : 'SQL') + (p.window_s ? " - fenêtre fixe : ignore l'intervalle/refresh global (édite, mets 0 pour resync)" : ''); card.appendChild(qline);
  // formulaire d'édition par panneau (titre / requête / viz / fenêtre)
  const ef = document.createElement('form'); ef.className = 'ruleform'; ef.hidden = true;
  ef.innerHTML = `<input class="pe-title" placeholder="titre"><textarea class="pe-query" rows="2" spellcheck="false"></textarea>`
    + `<div class="rf-row"><label>Viz <select class="pe-viz"><option value="table">Table</option><option value="bar">Barres</option><option value="line">Courbe</option><option value="stat">Stat</option><option value="gauge">Jauge</option><option value="pie">Camembert</option><option value="donut">Donut</option><option value="heatmap">Heatmap</option><option value="histogram">Histogramme</option></select></label>`
    + `<label>Fenêtre(s) (0 = globale) <input class="pe-win" type="number" value="0"></label></div>`
    + `<div class="rf-row"><label>Panneau <select class="pe-vis"><option value="shared">public</option><option value="private">privé</option></select></label>`
    + `<label><input class="pe-qpriv" type="checkbox"> requête privée (cacher le texte aux autres)</label></div>`
    + `<label class="pe-drill-l">Requête au clic / drill (vide = défaut) <textarea class="pe-drill" rows="2" spellcheck="false" placeholder="search source=$value | table ts,source,src_ip,message"></textarea></label>`
    + `<div class="rf-hint">Marqueurs au clic : $value (valeur cliquée, mise entre guillemets) ; $from / $to (bornes du bucket). Un clic temporel restreint déjà la fenêtre au bucket.</div>`
    + `<div class="rf-actions"><button type="submit">Enregistrer</button><button type="button" class="pe-cancel">Annuler</button></div>`;
  ef.querySelector('.pe-title').value = p.title; ef.querySelector('.pe-query').value = p.query; ef.querySelector('.pe-viz').value = p.viz; ef.querySelector('.pe-win').value = p.window_s || 0;
  ef.querySelector('.pe-vis').value = p.visibility || 'shared'; ef.querySelector('.pe-qpriv').checked = !!p.query_private;
  ef.querySelector('.pe-drill').value = p.drill || '';
  edit.onclick = () => { ef.hidden = !ef.hidden; };
  ef.querySelector('.pe-cancel').onclick = () => { ef.hidden = true; };
  ef.onsubmit = async (e) => {
    e.preventDefault();
    const q = ef.querySelector('.pe-query').value.trim();
    const isSoql = /^\s*search\b/i.test(q) || q.includes('|');
    // FAILLE B (UI) — éditer un panneau en SQL brut (saisie non-SOQL) est réservé admin (miroir serveur panel_update).
    if (!isSoql && !socIsAdmin()) { toast('SQL brut réservé à l\'administrateur (utilisez SOQL)', 'bad'); return; }
    const upd = { title: ef.querySelector('.pe-title').value.trim() || 'Panneau', query: q, viz: ef.querySelector('.pe-viz').value, is_soql: isSoql, window_s: Number(ef.querySelector('.pe-win').value) || 0, visibility: ef.querySelector('.pe-vis').value, query_private: ef.querySelector('.pe-qpriv').checked, drill: ef.querySelector('.pe-drill').value.trim() };
    await patchPanel(p.id, upd);
    loadDashboards();
  };
  card.appendChild(ef);
  const prog = document.createElement('div'); prog.className = 'tableprog'; prog.hidden = true; prog.setAttribute('aria-hidden', 'true'); card.appendChild(prog);
  const body = document.createElement('div'); body.className = 'panelbody'; body.textContent = '...'; card.appendChild(body);
  if (p.height > 0) { body.style.height = p.height + 'px'; body.style.maxHeight = 'none'; }
  let lastH = p.height || 0;
  if (editable && 'ResizeObserver' in window) {
    new ResizeObserver(() => {
      if (!S.editing) return; // ne persiste qu'en mode édition
      const h = Math.round(body.clientHeight);
      if (h && Math.abs(h - lastH) > 8) { lastH = h; clearTimeout(body._t); body._t = setTimeout(() => patchPanel(p.id, { height: h }), 500); }
    }).observe(body);
  }
  // P7 : poignee de coin -> resize LIBRE (hauteur en px + largeur calee sur la grille, 1-4 col)
  if (editable) {
    const corner = document.createElement('div'); corner.className = 'rcorner editonly'; corner.title = 'Redimensionner (glisser)';
    card.appendChild(corner);
    corner.onmousedown = e => {
      e.preventDefault();
      const y0 = e.clientY, h0 = body.clientHeight, grid = card.parentElement;
      const slot = grid ? grid.clientWidth / 4 : 240; // un quart de la largeur du dashboard
      const left = card.getBoundingClientRect().left;
      const mv = ev => {
        body.style.maxHeight = 'none';
        body.style.height = Math.max(120, h0 + ev.clientY - y0) + 'px';
        const ncols = Math.max(1, Math.min(4, Math.round((ev.clientX - left) / slot)));
        card.style.flexBasis = tileBasis(ncols); card.dataset.cols = ncols;
      };
      const up = () => {
        document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up);
        const ncols = Number(card.dataset.cols) || (p.cols || 1);
        if (wsel) wsel.value = String(ncols);
        patchPanel(p.id, { cols: ncols }); // hauteur sauvee par le ResizeObserver
      };
      document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
    };
  }
  let result = null;
  let pFrom = 0, pTo = 0;                                            // bornes de la dernière requête -> count_only
  const drawCount = { total: null, capped: false, fired: false };   // vrai total (count_only) pour une table cliente tronquée
  // PAGINATION GÉNÉRIQUE — extension du modèle Explore aux panneaux. Décision par FORME (viz + agrégation),
  // jamais par nom de champ. isAgg = pipe d'agrégation. Un panneau TABLE non-agrégé = LISTE DE LIGNES ->
  // pagination SERVEUR (scale 1M via /api/query + count_only, exactement comme Explore). Un panneau TABLE
  // agrégé = groupes déjà en mémoire -> pagination CLIENT du DOM (tableEl opts) + vrai total (count_only si tronqué).
  const pIsSoql = !!p.is_soql || /^\s*search\b/i.test(p.query || '') || (p.query || '').includes('|');
  const pIsAgg = pIsSoql && /\|\s*(stats|timechart|top|rare|eventstats)\b/i.test(p.query || '');
  // PROJECTION `| table`/`| fields` : retire la clé de tri (ts,id) -> keyset impossible (le daemon dégrade
  // vers l'offset, cf soql_projects_away_keyset). Le web DOIT s'aligner : sinon il enverrait un CURSEUR pour
  // les pages séquentielles (que le daemon en mode offset ignore -> renverrait la page 0). -> ces panneaux
  // paginent en OFFSET côté web AUSSI (déterministe, sans trou). Mirroir EXACT de la détection daemon.
  const pIsProjected = pIsSoql && /\|\s*(table|fields)\b/i.test(p.query || '');
  const PANEL_PAGE = 50;
  // état pager SERVEUR PAR-PANNEAU (isolé des autres panneaux — plusieurs panneaux paginent indépendamment).
  // ① KEYSET (MIRROIR d'Explore `evLoad`, modèle Splunk) : un browse brut SOQL (`search` nu, from_soql) pagine par
  // CURSEUR en SÉQUENTIEL (Préc/Suiv = récup INTÉGRALE sans cap) MAIS garde le pager NUMÉROTÉ « 1..N » du COUNT ; un
  // clic sur un numéro de page NON atteint séquentiellement fait un SAUT OFFSET ponctuel (capé pour les pages très
  // lointaines = follow-up offset-dans-le-colonnaire). `cursors[i]` = curseur {ts,id} pour ATTEINDRE la page i (page 0
  // = null = sommet), capturé depuis `next_cursor` de la page i-1. Le SQL brut (admin, non-from_soql) reste en OFFSET.
  const panelKeyset = pIsSoql && !pIsProjected; // le daemon: do_keyset = keyset && from_soql && !projection
  const spg = { page: 0, pageSize: PANEL_PAGE, total: 0, shown: 0, totalCapped: false, countFired: false, realTotal: false, cols: null, rows: null,
    keyset: panelKeyset, cursors: [null] };
  // ne serveur-pagine QUE les listes de lignes (table + non-agrégé) ET seulement quand /api/query est autorisé
  // pour l'appelant (SOQL ouvert à tous ; SQL brut réservé admin) -> sinon repli sur la pagination CLIENT.
  const serverPaged = () => curViz === 'table' && !pIsAgg && (pIsSoql || socIsAdmin());
  function panelWindow() {
    const from = p.window_s > 0 ? Math.floor(Date.now() / 1000) - p.window_s : (currentFrom() || 0);
    const to = p.window_s > 0 ? 0 : currentTo();
    return { from, to };
  }
  function panelBad(m) { body.replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'Erreur : ' + m })); }
  function renderServerPaged() {
    if (!spg.rows) return;
    if (!spg.rows.length && !spg.total) { body.replaceChildren(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'aucune donnée sur la fenêtre' })); return; }
    body.replaceChildren();
    const go = pp => loadServerPage(pp);
    const top = makePager(spg, go); if (top) body.appendChild(top);
    body.appendChild(tableEl(spg.cols, spg.rows, p.query, p.drill || ''));
    const bot = makePager(spg, go); if (bot) body.appendChild(bot);
  }
  // PAGE SERVEUR d'une liste de lignes : une seule page en mémoire (LIMIT/OFFSET) + total COUNT -> scale 1M.
  async function loadServerPage(page) {
    if (card._loadCtrl) { try { card._loadCtrl.abort(); } catch (e) {} }
    const ctrl = new AbortController(); card._loadCtrl = ctrl; panelInflight.add(ctrl);
    if (prog) prog.hidden = false; if (pstop) pstop.hidden = false;
    try {
      const { from, to } = panelWindow(); pFrom = from; pTo = to;
      // ① : la fenêtre a changé -> les curseurs {ts,id} capturés pour l'ancienne fenêtre sont obsolètes -> on
      // repart de la page 0 (curseur sommet) et on recompte le total. (L'offset, lui, reste valide sur toute fenêtre.)
      if (spg.keyset && spg.win && (spg.win.from !== from || spg.win.to !== to)) { page = 0; spg.cursors = [null]; spg.countFired = false; spg.realTotal = false; }
      spg.win = { from, to };
      const pg = Math.max(0, page);
      const reqBody = pIsSoql ? { soql: p.query } : { sql: p.query };
      reqBody.from = from; reqBody.to = to; reqBody.limit = spg.pageSize;
      if (spg.keyset) {
        // ① (mirroir evLoad) : curseur {ts,id} pour atteindre pg en SÉQUENTIEL ; page non atteinte (clic numéro loin /
        // dernière) -> SAUT OFFSET ponctuel. Le serveur renvoie next_cursor/has_more (séquentiel sans cap) OU total (saut).
        reqBody.keyset = true;
        const cur = spg.cursors[pg];
        const jumpOff = (!cur && pg > 0) ? pg * spg.pageSize : 0;
        if (cur) reqBody.cursor = { ts: cur.ts, id: cur.id };
        else if (jumpOff) reqBody.offset = jumpOff;
      } else {
        reqBody.offset = pg * spg.pageSize;
      }
      const r = await fetch('/api/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(reqBody), signal: ctrl.signal });
      const txt = await r.text().catch(() => '');
      const tg = transientGatewayMsg(r.status, r.ok ? '' : txt);
      if (tg) { panelBad(tg); return; }
      if (!txt) { panelBad('réponse vide (timeout proxy ou requête trop lourde ?)'); return; }
      let j;
      try { j = JSON.parse(txt); }
      catch { const tg2 = transientGatewayMsg(r.status, txt); if (tg2) { panelBad(tg2); return; } panelBad('réponse non-JSON (tronquée ? timeout ?)'); return; }
      if (!r.ok || j.error) { panelBad(j.error || r.status); return; }
      spg.page = Math.max(0, page); spg.cols = j.columns || []; spg.rows = j.rows || []; spg.shown = spg.rows.length;
      // ① KEYSET : mémorise le curseur de continuation (Suivant SÉQUENTIEL rapide, sans cap). Le total reste celui du
      // COUNT (pager NUMÉROTÉ commun) — un saut OFFSET renvoie `total`, une page séquentielle non (on garde l'ancien).
      if (spg.keyset) {
        const nc = j.next_cursor;
        spg.cursors[spg.page + 1] = (nc && typeof nc.ts === 'number' && typeof nc.id === 'number') ? { ts: nc.ts, id: nc.id } : null;
      }
      if (!spg.realTotal && typeof j.total === 'number') { spg.total = j.total; spg.totalCapped = !!j.total_capped; }
      else if (!spg.realTotal && !spg.keyset) { spg.total = spg.rows.length; }
      result = { columns: spg.cols, rows: spg.rows, stats: j.stats };   // export du panneau = page courante
      renderServerPaged();
      // VRAI total NON plafonné (une seule fois) quand le COUNT serveur est plafonné OU keyset séquentiel (pas
      // de `total` inline) -> pager numéroté juste + saut-à-la-page possible. Réutilise le count_only NON plafonné.
      if (!spg.countFired && (spg.totalCapped || (spg.keyset && !spg.realTotal))) {
        spg.countFired = true;
        queryCount(p.query, pIsSoql, from, to).then(tot => { if (typeof tot === 'number' && tot >= 0) { spg.total = tot; spg.totalCapped = false; spg.realTotal = true; renderServerPaged(); } });
      }
    } catch (e) {
      if (e && e.name === 'AbortError') { flashStopped(prog); return; }
      body.textContent = 'erreur : ' + e.message;
    } finally {
      panelInflight.delete(ctrl); if (card._loadCtrl === ctrl) card._loadCtrl = null;
      if (prog && !prog.classList.contains('stopped')) prog.hidden = true;
      if (pstop) pstop.hidden = true; syncDashStop();
    }
  }
  function draw() {
    if (!result) return;
    // TABLE serveur-paginée (liste de lignes) : re-rendu de la page en mémoire, ou 1re page si pas encore chargée.
    if (serverPaged()) { if (spg.rows) renderServerPaged(); else loadServerPage(spg.page || 0); return; }
    if (!result.rows.length) { body.replaceChildren(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'aucune donnée sur la fenêtre' })); return; }
    // TABLE (agrégation = groupes en mémoire ; OU liste de lignes SQL-brut vue par un viewer, non serveur-paginée) :
    // pagination CLIENT du DOM + vrai total = nb de lignes en mémoire, remplacé par un count_only NON plafonné si le
    // résultat a atteint le plafond run_query (aucune ligne/groupe caché en silence). Les autres viz (chart/stat) inchangées.
    if (curViz === 'table') {
      const total = drawCount.total != null ? drawCount.total : result.rows.length;
      body.replaceChildren(tableEl(result.columns, result.rows, p.query, p.drill || '', { pager: true, pageSize: PANEL_PAGE, total, totalCapped: drawCount.capped }));
      if (!drawCount.fired && result.stats && result.stats.truncated) {
        drawCount.fired = true; drawCount.capped = true;
        queryCount(p.query, pIsSoql, pFrom, pTo).then(tot => { if (typeof tot === 'number' && tot >= 0) { drawCount.total = tot; drawCount.capped = false; draw(); } });
      }
      return;
    }
    body.replaceChildren(vizElement(curViz, result.columns, result.rows, p.query, p.drill || ''));
  }
  // chargement NON bloquant -> carte rendue tout de suite, requetes EN PARALLELE (WAL).
  async function load() {
    if (serverPaged()) return loadServerPage(spg.page || 0);
    if (card._loadCtrl) { try { card._loadCtrl.abort(); } catch (e) {} }
    const ctrl = new AbortController(); card._loadCtrl = ctrl; panelInflight.add(ctrl);
    if (prog) prog.hidden = false;
    if (pstop) pstop.hidden = false;
    try {
      const from = p.window_s > 0 ? Math.floor(Date.now() / 1000) - p.window_s : (currentFrom() || 0);
      const to = p.window_s > 0 ? 0 : currentTo(); // un panneau a fenetre fixe ignore le zoom global
      pFrom = from; pTo = to;
      const r = await fetch(`/api/panels/${p.id}/data?from=${from}&to=${to}`, { signal: ctrl.signal });
      const txt = await r.text().catch(() => '');   // texte d'abord -> gère réponse vide/tronquée (timeout proxy)
      const bad = m => body.replaceChildren(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'Erreur : ' + m }));
      // PANNE TRANSITOIRE DE PASSERELLE : (502/503/504 ou corps HTML « no available server » pendant
      // un rollout) -> message propre au lieu du corps brut Traefik.
      const tg = transientGatewayMsg(r.status, r.ok ? '' : txt);   // ok=200 -> corps vérifié plus bas (cas HTML servi en 200)
      if (tg) { bad(tg); return; }
      if (!txt) { bad('réponse vide (timeout proxy ou requête trop lourde ?)'); return; }
      let j;
      try { j = JSON.parse(txt); }
      catch {
        const tg2 = transientGatewayMsg(r.status, txt);   // corps HTML « no available server » servi en 200 -> transitoire
        if (tg2) { bad(tg2); return; }
        bad('réponse non-JSON (tronquée ? timeout ?) : ' + txt.slice(0, 120)); return;
      }
      if (!r.ok || j.error) { bad(j.error || r.status); return; }
      // FROID : 1er affichage d'un panneau jamais mesuré -> le daemon renvoie {warming:true} sans bloquer.
      // On montre un placeholder « chargement… » et on re-poll (3s) jusqu'aux vraies données -> plus de
      // « aucune donnée » à tort au retour sur Dashboards.
      if (j.warming === true) {
        body.replaceChildren(Object.assign(document.createElement('div'), { className: 'muted', textContent: '… chargement (mesure en cours)' }));
        clearTimeout(card._warmTimer);
        card._warmTimer = setTimeout(load, 3000);
        return;
      }
      clearTimeout(card._warmTimer); card._warmTimer = null;
      drawCount.total = null; drawCount.capped = false; drawCount.fired = false;   // ré-évalue la troncature à chaque (re)chargement
      result = { columns: j.columns, rows: j.rows, stats: j.stats }; draw();
    } catch (e) {
      if (e && e.name === 'AbortError') { flashStopped(prog); return; }   // STOP : feedback DISCRET via la barre (pas de texte)
      body.textContent = 'erreur : ' + e.message;
    } finally {
      panelInflight.delete(ctrl); if (card._loadCtrl === ctrl) card._loadCtrl = null;
      if (prog && !prog.classList.contains('stopped')) prog.hidden = true;   // ne pas couper le flash STOP en cours
      if (pstop) pstop.hidden = true; syncDashStop();
    }
  }
  // P5 : refresh par panneau ; un panneau a fenetre MANUELLE (window_s>0) ignore l'intervalle/refresh global
  // LAZY : on n'appelle PAS load() ici ; l'IntersectionObserver déclenche le 1er fetch quand la carte
  // devient visible (anti-rafale). Fallback sans IO -> chargement immédiat (comportement historique).
  card._panel = { window_s: p.window_s || 0, reload: load, loaded: false, visible: false };
  const obs = getPanelObserver();
  if (obs) obs.observe(card);
  else { card._panel.loaded = true; card._panel.visible = true; load(); }
  return card;
}
// Ajouter un dashboard a la vue : soit en RATTACHER un existant (select), soit en CREER un nouveau.
async function addDashboardFlow() {
  const view = $('#view') ? $('#view').value : '';
  let all = [];
  try { all = (await api('/dashboards')).dashboards || []; } catch (e) {}
  // dashboards editables pas deja dans cette vue (rattacher = deplacer ; le schema = 1 vue par dashboard)
  const attachable = view ? all.filter(d => d.editable !== false && String(d.view_id || '') !== String(view)) : [];
  const fields = [];
  if (attachable.length) fields.push({ name: 'existing', label: 'Rattacher un dashboard existant', type: 'select', value: '', options: [{ value: '', label: '+ Creer un nouveau dashboard' }, ...attachable.map(d => ({ value: String(d.id), label: d.name + (d.view_id ? ' (deplace depuis une autre vue)' : '') }))] });
  fields.push({ name: 'name', label: attachable.length ? 'Nom (si nouveau)' : 'Nom', placeholder: 'ex: Plume vue d ensemble', value: '' });
  fields.push({ name: 'visibility', label: 'Visibilité (si nouveau)', type: 'select', value: 'private', options: [{ value: 'private', label: 'Privé (vous + admin)' }, { value: 'shared', label: 'Partagé (groupe)' }] });
  const r = await modal({
    title: 'Ajouter un dashboard', okText: 'Ajouter', fields,
    validate: v => {
      if (v.existing) return null; // rattachement d'un existant
      if (!v.name || !v.name.trim()) return 'Donne un nom, ou choisis un dashboard existant.';
      if (all.some(d => d.name === v.name.trim())) return 'Un dashboard porte déjà ce nom.';
      return null;
    },
  });
  if (!r) return;
  if (r.existing) {
    await patchDash(Number(r.existing), { view_id: view ? Number(view) : null });
    toast('Dashboard rattaché à la vue', 'ok');
  } else {
    await apiSend('/dashboards', 'POST', { name: r.name.trim(), visibility: r.visibility, view_id: view ? Number(view) : null });
    toast('Dashboard créé', 'ok');
  }
  await loadDashboards(); await loadViews();
}
if ($('#dash-new')) $('#dash-new').addEventListener('click', addDashboardFlow);
if ($('#dash-refresh')) $('#dash-refresh').addEventListener('click', refreshDashboards);
if ($('#dash-stop')) $('#dash-stop').addEventListener('click', stopDashboards);
if ($('#dash-edit')) $('#dash-edit').addEventListener('click', () => {
  S.editing = !S.editing;
  const v = $('#dashview'); if (v) v.classList.toggle('editing', S.editing);
  $('#dash-edit').classList.toggle('on', S.editing);
});

// ===================== #54 — INSTANTANÉ (snapshot partageable, lecture seule) =====================
// Capture les données rendues du dashboard via le chemin SOQL MASQUÉ côté serveur (au rôle de l'appelant) ->
// jamais un champ hors de sa portée. Renvoie {id, token}. On affiche un aperçu (rendu par les MÊMES
// vizElement) + un lien de partage read-only copiable (l'API renvoie le JSON figé au token).
async function captureSnapshot(d) {
  const from = currentFrom() || 0, to = currentTo();
  const j = await apiSend('/dashboard-snapshots', 'POST', { dashboard_id: d.id, from, to, name: d.name });
  if (!j || j.error) { toast('Instantané : ' + ((j && j.error) || 'échec'), 'bad'); return; }
  const url = location.origin + '/api/dashboard-snapshots/' + encodeURIComponent(j.token);
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal snapview';
  const close = () => { ov.classList.add('out'); setTimeout(() => ov.remove(), 160); };
  const h = document.createElement('h3'); h.textContent = 'Instantané : ' + d.name;
  const meta = document.createElement('div'); meta.className = 'muted'; meta.style.cssText = 'font-size:12px;margin:4px 0 8px';
  meta.textContent = 'Lecture seule, figé maintenant (données déjà masquées à votre rôle). Lien partageable :';
  const linkRow = document.createElement('div'); linkRow.className = 'rf-row';
  const inp = document.createElement('input'); inp.value = url; inp.readOnly = true; inp.style.flex = '1';
  const copy = document.createElement('button'); copy.type = 'button'; copy.textContent = 'Copier';
  copy.onclick = () => { try { navigator.clipboard.writeText(url); toast('Lien copié', 'ok'); } catch (e) { inp.select(); } };
  linkRow.append(inp, copy);
  const prev = document.createElement('div'); prev.className = 'snapprev';
  const act = document.createElement('div'); act.className = 'modal-act';
  const cl = document.createElement('button'); cl.type = 'button'; cl.className = 'm-cancel'; cl.textContent = 'Fermer'; cl.onclick = close;
  act.appendChild(cl);
  box.append(h, meta, linkRow, prev, act);
  ov.onclick = e => { if (e.target === ov) close(); };
  ov.appendChild(box); document.body.appendChild(ov);
  // aperçu : relit le snapshot par token (read-only) et rend chaque panneau avec les vizElement natifs.
  try {
    const snap = await api('/dashboard-snapshots/' + encodeURIComponent(j.token));
    const panels = (snap && snap.data && snap.data.panels) || [];
    prev.replaceChildren(...panels.map(p => {
      const card = document.createElement('div'); card.className = 'snapcard';
      const t = document.createElement('div'); t.className = 'snaptitle'; t.textContent = p.title || '';
      card.appendChild(t);
      if (p.error) { card.appendChild(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'erreur : ' + p.error })); }
      else if (!p.rows || !p.rows.length) { card.appendChild(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'aucune donnée' })); }
      else card.appendChild(vizElement(p.viz || 'table', p.columns || [], p.rows || [], '', ''));
      return card;
    }));
  } catch (e) { prev.appendChild(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'aperçu indisponible' })); }
}

// ===================== #54 — DIAPORAMA (playlist / NOC wall-board) =====================
// Fait défiler les dashboards de la vue courante (S.dashList) un à un, sur un intervalle. Prev/next manuels.
// Autonome (aucune config serveur requise) ; la table `playlist` reste dispo pour persister des rotations nommées.
const PLAY = { on: false, idx: 0, timer: null };
function playTiles() { return [...($('#dashview') ? $('#dashview').querySelectorAll('.dashtile') : [])]; }
function playShow(i) {
  const tiles = playTiles(); if (!tiles.length) { playStop(); return; }
  PLAY.idx = ((i % tiles.length) + tiles.length) % tiles.length;
  tiles.forEach((t, k) => { t.style.display = k === PLAY.idx ? '' : 'none'; });
  const tile = tiles[PLAY.idx]; if (tile && tile._panel) {} // (le lazy-load des panneaux se déclenche à l'affichage)
  const pos = $('#dash-playpos'); if (pos) pos.textContent = (PLAY.idx + 1) + '/' + tiles.length;
  tiles[PLAY.idx].scrollIntoView({ block: 'nearest' });
}
function playTick() {
  const step = () => { playShow(PLAY.idx + 1); schedule(); };
  const schedule = () => { const s = Math.max(3, Math.min(3600, Number(($('#dash-playint') && $('#dash-playint').value) || 30))); PLAY.timer = setTimeout(step, s * 1000); };
  clearTimeout(PLAY.timer); schedule();
}
function playStart() {
  if (!playTiles().length) { toast('Aucun dashboard à faire défiler dans cette vue.', 'bad'); return; }
  PLAY.on = true; PLAY.idx = 0;
  const bar = $('#dash-playbar'); if (bar) bar.hidden = false;
  const btn = $('#dash-play'); if (btn) btn.classList.add('on');
  playShow(0); playTick();
}
function playStop() {
  PLAY.on = false; clearTimeout(PLAY.timer); PLAY.timer = null;
  playTiles().forEach(t => { t.style.display = ''; });
  const bar = $('#dash-playbar'); if (bar) bar.hidden = true;
  const btn = $('#dash-play'); if (btn) btn.classList.remove('on');
}
if ($('#dash-play')) $('#dash-play').addEventListener('click', () => { PLAY.on ? playStop() : playStart(); });
if ($('#dash-playstop')) $('#dash-playstop').addEventListener('click', playStop);
if ($('#dash-prev')) $('#dash-prev').addEventListener('click', () => { if (PLAY.on) { playShow(PLAY.idx - 1); playTick(); } });
if ($('#dash-next')) $('#dash-next').addEventListener('click', () => { if (PLAY.on) { playShow(PLAY.idx + 1); playTick(); } });
if ($('#dash-playint')) $('#dash-playint').addEventListener('change', () => { if (PLAY.on) playTick(); });
// "Sauver comme panneau" depuis Explore : choisit le dashboard cible dans la vue courante
if ($('#save-panel')) $('#save-panel').addEventListener('click', async () => {
  const q = $('#sql').value.trim(); if (!q) { toast("Écris une requête d'abord.", 'bad'); return; }
  const editables = S.dashList.filter(d => d.editable !== false);
  if (!editables.length) { toast('Crée d\'abord un dashboard (onglet Dashboards -> + Dashboard).', 'bad'); return; }
  let did = editables[0].id;
  if (editables.length > 1) {
    const r = await modal({ title: 'Ajouter le panneau à', okText: 'Continuer', fields: [{ name: 'did', label: 'Dashboard', type: 'select', value: String(did), options: editables.map(d => ({ value: String(d.id), label: d.name })) }] });
    if (!r) return; did = Number(r.did);
  }
  await createPanelModal(did, q);
});

// --- vues (ensembles de dashboards) ---
async function loadViews() {
  const sel = $('#view'); if (!sel) return;
  try {
    const { views, role, me } = await api('/views');
    S.viewList = views || [];
    if (role) { applyRoleClass(role); S.viewsRole = role; }
    if (me != null) S.viewsMe = me;   // #17 team — identité pour la garde de partage (bascule scope)
    const cur = sel.value;
    sel.replaceChildren();
    const all = document.createElement('option'); all.value = ''; all.textContent = '— Sans filtre de vue —'; sel.appendChild(all);
    // #17 team — le label distingue explicitement une vue PARTAGÉE (équipe) d'une vue privée -> l'équipe
    // voit d'un coup d'œil quels regroupements de dashboards sont communs.
    (views || []).forEach(v => { const o = document.createElement('option'); o.value = v.id; o.textContent = `${v.name}${v.visibility === 'shared' ? ' (équipe)' : ' (privé)'} (${v.dashboards})`; sel.appendChild(o); });
    if (cur) sel.value = cur;
  } catch (e) {}
  updateViewShareBtn();
}
// #17 team — SAVED-VIEW SHARING : bascule du scope d'une vue partagée<->privée. Backend prêt (view_update
// accepte {visibility} ; views_list renvoie owner/visibility/me/role). Garde MIROIR de view_update (admin,
// propriétaire, ou vue sans owner legacy) ; le daemon refait foi (défense en profondeur).
function viewCanShare(v) { return !!v && (S.viewsRole === 'admin' || !v.owner || v.owner === S.viewsMe); }
function updateViewShareBtn() {
  const btn = $('#view-share'), sel = $('#view'); if (!btn || !sel) return;
  const v = S.viewList.find(x => String(x.id) === String(sel.value));
  if (!v || !viewCanShare(v)) { btn.hidden = true; return; }
  const shared = v.visibility === 'shared';
  btn.hidden = false; btn.innerHTML = ic('users'); btn.classList.toggle('on', shared);
  btn.setAttribute('aria-pressed', shared ? 'true' : 'false');
  const owner = v.owner ? ' (propriétaire : ' + v.owner + ')' : '';
  btn.title = shared ? `Vue partagée avec l'équipe${owner} — cliquer pour la rendre privée`
                     : `Vue privée${owner} — cliquer pour la partager avec l'équipe`;
}
if ($('#view')) { $('#view').addEventListener('change', loadDashboards); $('#view').addEventListener('change', updateViewShareBtn); }
if ($('#view-share')) $('#view-share').addEventListener('click', async () => {
  const sel = $('#view'); const id = sel && sel.value;
  const v = S.viewList.find(x => String(x.id) === String(id));
  if (!v) { toast('Sélectionne une vue à partager (pas « — Sans filtre de vue — »).', 'bad'); return; }
  if (!viewCanShare(v)) { toast('Seuls le propriétaire ou un admin peuvent changer le partage.', 'bad'); return; }
  const next = v.visibility === 'shared' ? 'private' : 'shared';
  try { await apiSend('/views/' + id, 'POST', { visibility: next }); }
  catch (e) { toast('Changement de partage refusé (' + (e && e.message ? e.message : e) + ')', 'bad'); return; }
  await loadViews(); sel.value = id; updateViewShareBtn();
  toast(next === 'shared' ? 'Vue partagée avec l\'équipe' : 'Vue rendue privée', 'ok');
});
if ($('#view-new')) $('#view-new').addEventListener('click', async () => {
  const r = await modal({
    title: 'Nouvelle vue', okText: 'Créer', fields: [
      { name: 'name', label: 'Nom', required: true, placeholder: 'ex: Production' },
      { name: 'visibility', label: 'Visibilité', type: 'select', value: 'private', options: [{ value: 'private', label: 'Privé (vous + admin)' }, { value: 'shared', label: 'Partagé (groupe)' }] },
    ], validate: v => S.viewList.some(x => x.name === v.name.trim()) ? 'Une vue porte déjà ce nom.' : null,
  });
  if (!r) return;
  const cr = await apiSend('/views', 'POST', { name: r.name.trim(), visibility: r.visibility });
  await loadViews(); if (cr.id) $('#view').value = cr.id; loadDashboards(); toast('Vue créée', 'ok');
});
if ($('#view-del')) $('#view-del').addEventListener('click', async () => {
  const sel = $('#view'); if (!sel.value) { toast('Sélectionne une vue à supprimer.', 'bad'); return; }
  if (!await confirmModal('Supprimer cette vue ? Les dashboards sont conservés (détachés de la vue).', { danger: true })) return;
  await apiSend('/views/' + sel.value, 'DELETE');
  sel.value = ''; await loadViews(); loadDashboards();
});
if ($('#view-rename')) {
  $('#view-rename').innerHTML = ic('pencil');
  $('#view-rename').addEventListener('click', async () => {
    const sel = $('#view'); const id = sel && sel.value;
    if (!id) { toast('Sélectionne une vue à renommer (pas « — Sans filtre de vue — »).', 'bad'); return; }
    const v = S.viewList.find(x => String(x.id) === String(id));
    const r = await modal({ title: 'Renommer la vue', okText: 'Enregistrer', fields: [{ name: 'name', label: 'Nom', required: true, value: v ? v.name : '' }], validate: x => S.viewList.some(y => String(y.id) !== String(id) && y.name === x.name.trim()) ? 'Une vue porte déjà ce nom.' : null });
    if (!r) return;
    await apiSend('/views/' + id, 'POST', { name: r.name.trim() });
    await loadViews(); $('#view').value = id; toast('Vue renommée', 'ok');
  });
}
loadViews();
loadDashboards();


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
  if (pw.length < 6) { res.textContent = 'mot de passe >= 6 caractères'; return; }
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


// --- Lookups (tables d'enrichissement SOQL ; réservé admin ; vit sous Réglages, comme les Comptes) ---
// Un lookup = table de référence nommée (clé -> colonnes JSON) jointe en LEFT JOIN par l'op SOQL
// `lookup <nom> <champ-clé> [OUTPUT cols]`. #1c : GET /api/lookups est LISIBLE par tous les rôles
// (viewer/editor/admin) ; le CRUD (POST upload / DELETE) est autorisé éditeur+admin, le viewer est
// bloqué serveur (403 via le gate `mutating`) ET côté UI (boutons .crud-btn masqués en role-viewer).
// Les mutations reçoivent X-CSRF-Token automatiquement via le wrapper window.fetch global.
// API : GET /api/lookups -> {lookups:[{name,key_field,cols,updated,rows}]} ; POST {name,key_field,rows:[{...}]}
// -> {name,rows,cols:[...]} (REMPLACE tout le lookup) ; DELETE /api/lookups/:name -> {ok,deleted:true}.
const LK_NAME_RE = /^[A-Za-z0-9_]+$/;   // miroir de soql_ident_ok côté daemon (alphanumérique + _, non vide)
// Import CSV (collage) -> tableau d'objets, en pendant du collage JSON. RFC 4180 simplifié : séparateur
// virgule, guillemets doubles pour échapper virgule/retour-ligne/guillemet interne ("" -> "). La 1re ligne
// non vide = en-têtes (= noms de colonnes) ; chaque ligne suivante -> {en-tête: valeur(string)}. Les valeurs
// restent des CHAÎNES (le lookup enrichit par texte) et ne sont JAMAIS interpolées en SQL (le serveur valide
// name/key_field/colonnes via soql_ident_ok, la jointure est bornée + paramétrée). Lève une Error claire.
function parseCsvRows(text) {
  const records = []; let field = '', row = [], inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false; }
      else field += c;
    } else if (c === '"') inQ = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.length > 1 || row[0] !== '') records.push(row);
      row = [];
    } else field += c;
  }
  if (field !== '' || row.length) { row.push(field); if (row.length > 1 || row[0] !== '') records.push(row); }
  if (records.length < 2) throw new Error('CSV : une ligne d\'en-têtes + au moins une ligne de données sont requises');
  const headers = records[0].map(h => h.trim());
  if (!headers.every(Boolean)) throw new Error('CSV : les en-têtes de colonnes ne peuvent pas être vides');
  return records.slice(1).map(rec => {
    const obj = {}; headers.forEach((h, idx) => { obj[h] = rec[idx] !== undefined ? rec[idx] : ''; }); return obj;
  });
}
async function loadLookups() {
  const wrap = $('#lookup-list'); if (!wrap) return;
  let lookups = [];
  try { ({ lookups } = await api('/lookups')); } catch (e) { return; } // 403 (non-admin) -> section masquée de toute façon
  wrap.replaceChildren();
  if (!lookups.length) { wrap.appendChild(muted('aucun lookup - clique " + Nouveau lookup " (tables d\'enrichissement : geoip, asn, threat-intel...).')); return; }
  lookups.forEach(l => wrap.appendChild(lookupRow(l)));
}
function lookupRow(l) {
  const row = document.createElement('div'); row.className = 'rulerow';
  const name = document.createElement('span'); name.className = 'rulename'; name.textContent = l.name;
  name.appendChild(managedBadge(l.managed)); // D12 — origine du contenu (builtin/overlay/perso), comme ruleRow
  const key = document.createElement('code'); key.className = 'rulecond'; key.textContent = 'clé=' + (l.key_field || '?');
  const colList = (l.cols || '').split(',').filter(Boolean);
  const meta = document.createElement('span'); meta.className = 'rulemeta muted';
  meta.textContent = `${l.rows} ligne(s)` + (colList.length ? ' - ' + colList.join(', ') : ' - aucune colonne de sortie') + (l.updated ? ' - ' + fmtTs(l.updated) : '');
  meta.title = colList.length ? 'colonnes de sortie (OUTPUT) : ' + colList.join(', ') : 'aucune colonne hors champ-clé';
  const del = document.createElement('button'); del.className = 'crud-btn'; del.innerHTML = ic('x'); del.title = 'Supprimer';
  del.onclick = async () => {
    if (!await confirmModal('Supprimer le lookup "' + l.name + '" (' + l.rows + ' ligne(s)) ?', { danger: true })) return;
    if (await contentDelete('/lookups/' + encodeURIComponent(l.name), 'lookup')) loadLookups();
  };
  row.append(name, key, meta, del);
  return row;
}
if ($('#lookup-new')) $('#lookup-new').onclick = () => { const f = $('#lookup-form'); f.classList.toggle('hidden'); if (!f.classList.contains('hidden')) $('#lk-name').focus(); };
if ($('#lk-cancel')) $('#lk-cancel').onclick = () => $('#lookup-form').classList.add('hidden');
if ($('#lookup-form')) $('#lookup-form').addEventListener('submit', async e => {
  e.preventDefault();
  const res = $('#lk-result');
  const fail = m => { res.textContent = m; res.className = 'bad'; };
  const name = $('#lk-name').value.trim(), key = $('#lk-key').value.trim();
  if (!LK_NAME_RE.test(name)) return fail('nom invalide (alphanumérique + _, non vide)');
  if (!LK_NAME_RE.test(key)) return fail('champ-clé invalide (alphanumérique + _, non vide)');
  // Collage JSON (tableau d'objets) OU CSV (en-têtes + lignes) — détection : '[' / '{' -> JSON, sinon CSV.
  let rows;
  const raw = $('#lk-rows').value.trim();
  if (!raw) return fail('aucune ligne à charger');
  if (raw[0] === '[' || raw[0] === '{') {
    try { rows = JSON.parse(raw); } catch (_) { return fail('JSON invalide (attendu : tableau d\'objets [{...}])'); }
    if (!Array.isArray(rows)) return fail('le JSON doit être un TABLEAU d\'objets : [{...}, ...]');
  } else {
    try { rows = parseCsvRows(raw); } catch (e) { return fail(e.message); }
  }
  if (!rows.length) return fail('aucune ligne à charger');
  if (!rows.every(r => r && typeof r === 'object' && !Array.isArray(r))) return fail('chaque ligne doit être un objet {champ: valeur}');
  if (!rows.every(r => Object.prototype.hasOwnProperty.call(r, key))) return fail(`chaque ligne doit contenir le champ-clé "${key}"`);
  res.textContent = '...'; res.className = 'muted';
  let j;
  try { j = await apiSend('/lookups', 'POST', { name, key_field: key, rows }); }
  catch (e) { return fail((e && e.message) || 'échec'); }
  j = j || {};
  res.textContent = ''; res.className = 'muted';
  toast(`lookup "${name}" chargé : ${j.rows} ligne(s)` + (j.cols && j.cols.length ? ' - colonnes ' + j.cols.join(', ') : ' - aucune colonne hors clé'), 'ok');
  $('#lk-rows').value = ''; $('#lookup-form').classList.add('hidden');
  loadLookups();
});
loadLookups();
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

if ($('#connector-new-preset')) $('#connector-new-preset').onclick = openPresetPicker; // P1 — picker de presets vendeur (pré-remplit le form)
if ($('#connector-new')) $('#connector-new').onclick = () => openConnectorForm(null, 'defender');
if ($('#connector-new-taxii')) $('#connector-new-taxii').onclick = () => openConnectorForm(null, 'taxii2'); // #23/#24 — feed de renseignement TAXII 2.1
if ($('#connector-new-http')) $('#connector-new-http').onclick = () => openConnectorForm(null, 'http_pull'); // #20/#22 — connecteur générique http_pull (bring-your-own-vendor)
if ($('#cf-type')) $('#cf-type').addEventListener('change', applyConnectorType); // bascule les champs Defender ↔ TAXII ↔ HTTP
if ($('#cf-taxii-auth')) $('#cf-taxii-auth').addEventListener('change', applyConnectorType); // ré-ajuste l'indice du secret selon l'auth
// http_pull : les sélecteurs auth/méthode/pagination re-basculent les sous-champs (applyConnectorType -> applyHttpSubfields)
if ($('#cf-http-auth')) $('#cf-http-auth').addEventListener('change', applyConnectorType);
if ($('#cf-http-method')) $('#cf-http-method').addEventListener('change', applyConnectorType);
if ($('#cf-http-page')) $('#cf-http-page').addEventListener('change', applyConnectorType);
if ($('#cf-http-fm-add')) $('#cf-http-fm-add').onclick = () => addFieldMapRow('', '');   // + champ (field_map)
if ($('#cf-http-st-add')) $('#cf-http-st-add').onclick = () => addStMapRow('', '');       // + mapping (sourcetype_map)
if ($('#cf-http-preview')) $('#cf-http-preview').onclick = () => withBusy($('#cf-http-preview'), previewHttpPull); // Test / Prévisualiser (dry-run + rendu échantillon)
if ($('#cf-cancel')) $('#cf-cancel').onclick = () => { $('#cf-secret').value = ''; $('#connector-form').classList.add('hidden'); if ($('#connector-preset-picker')) $('#connector-preset-picker').classList.add('hidden'); };
if ($('#connectors-refresh')) $('#connectors-refresh').onclick = loadConnectors;
// #50 destinations de sortie (admin-only) : recharge + ouverture du formulaire d'ajout.
if ($('#destinations-refresh')) $('#destinations-refresh').onclick = loadDestinations;
if ($('#destination-new')) $('#destination-new').onclick = () => openDestinationForm(null);
// #40 processeur d'ingest (admin-only) : recharge + ouverture du formulaire d'ajout de règle.
if ($('#processors-refresh')) $('#processors-refresh').onclick = loadProcessors;
if ($('#processor-new')) $('#processor-new').onclick = openProcessorForm;
if ($('#index-policies-refresh')) $('#index-policies-refresh').onclick = loadIndexPolicies;
if ($('#index-policy-new')) $('#index-policy-new').onclick = openIndexPolicyForm;
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
if ($('#tenant-onboard')) $('#tenant-onboard').onclick = () => { const f = $('#tenant-form'); if (f) f.classList.toggle('hidden'); };
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

// --- navigation à 2 niveaux : 6 ESPACES (1er niveau) -> SOUS-ONGLETS (2e niveau) -> sections <main> ---
// Chaque espace regroupe des sous-onglets ; chaque sous-onglet mappe une/des sections existantes (ids PRÉSERVÉS).
// Le hash = l'id du sous-onglet (unique sur tous les espaces) -> deep-link conservé. Espace à 1 seul onglet
// = pas de barre de sous-onglets (Vue d'ensemble, Dashboards). admin:true sur un ESPACE => espace entier
// réservé admin (Administration) ; admin:true sur un ONGLET => onglet réservé admin mais espace visible
// (Lookups dans Données). 1er onglet = onglet par défaut de l'espace.
const SPACES = [
  { id: 'overview', tabs: [
    { id: 'overview', label: "Vue d'ensemble", sections: ['firewall', 'controls', 'integrations', 'freshness'] },
  ] },
  { id: 'investigation', tabs: [
    { id: 'explore', label: 'Recherche & Explore', sections: ['query', 'search-results'] },
    { id: 'alerts', label: 'Alertes', sections: ['alerts'] },
    { id: 'cases', label: 'Cases', sections: ['cases'] },
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
initSavedQueries();  // requêtes SOQL nommées (serveur, owner-scoped) + historique récent (localStorage). Additif, non-intrusif.
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
  else if (v === 'explore') { if (S.lastSearchQ) doSearch(S.lastSearchQ); if ($('#sql') && $('#sql').value.trim()) runQuery(); }
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

// --- aide a la saisie / completion du champ Explore (soql + champs) ---
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

if (LANG === 'en') {
  i18nWalk(document.body);
  // bloc d'intro Parsers (HTML riche, trop fragmenté pour le walk) -> version EN dédiée
  const pi = $('#parsers-intro');
  if (pi) pi.innerHTML = 'Extracts fields (regex named groups <code>(?&lt;name&gt;…)</code>) from the message <b>at ingestion, for all sources</b> (k3s / host / container — parsing is central, mode-independent). Built-in defaults (toggleable) + your custom parsers. <code>source=*</code> = all.<br><b>When?</b> a parser is <b>effective on save</b>, for <b>new</b> events. For <b>old</b> ones: <b>↻ Re-apply</b> (retroactive, with confirmation) — or <code>| rex</code> on the fly in a search.<br><b>IP direction:</b> name <code>src_ip</code> = the <b>initiator</b> (the attacker when inbound), <code>dst_ip</code> = the <b>target</b>. <code>src_ip</code>/<code>rhost</code> are promoted to a searchable column; an IP of uncertain direction → leave it in a neutral field (e.g. <code>ip</code>), never <code>src_ip</code>.';
  new MutationObserver(ms => ms.forEach(m => m.addedNodes.forEach(nd => { if (nd.nodeType === 1) i18nWalk(nd); }))).observe(document.body, { childList: true, subtree: true });
}
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

// ============ AUTH : écran de login (form-login), logout, état d'auth =============================
// Contrat daemon :
//   GET  /api/me     -> 200 {user,role,auth_method,csrf_token} si authentifié ; 401 sinon.
//   POST /api/login  {user,pass} -> 200 {ok,user,role} (pose plume_session HttpOnly + plume_csrf JS) ;
//                                     401 {error} (identifiants) ; 429 {error}+Retry-After (lockout).
//   POST /api/logout -> 200 (efface les cookies).
// FLUX SSO k3s INTACT : derrière le forward-auth Authentik, /api/me répond 200 (auth_method="sso")
// -> AUTH renseigné, overlay JAMAIS affiché, l'app charge normalement. Idem mode démo (auth_method
// ="demo"). L'écran de login ne s'affiche QU'au 401 (accès direct/standalone sans session cookie).
const $login = () => $('#login-ov');
function setAuthUI() {
  const box = $('#authbox'), id = $('#auth-id');
  if (!box) return;
  if (S.AUTH && S.AUTH.user) {
    if (id) {
      const role = S.AUTH.role ? ' · ' + S.AUTH.role : '';
      // auth_method affiché seulement s'il n'est pas la session cookie (sso/basic/bearer/demo) -> contexte
      const am = (S.AUTH.auth_method && S.AUTH.auth_method !== 'cookie') ? ' (' + S.AUTH.auth_method + ')' : '';
      id.textContent = S.AUTH.user + role + am;
      id.title = 'Connecté : ' + S.AUTH.user + (S.AUTH.role ? ' (' + S.AUTH.role + ')' : '') + (S.AUTH.auth_method ? ' — ' + S.AUTH.auth_method : '');
    }
    box.hidden = false;
  } else {
    box.hidden = true;
  }
}
function showLogin(show) {
  const ov = $login(); if (!ov) return;
  ov.hidden = !show;
  document.body.classList.toggle('login-locked', !!show);
  if (show) {
    // coupe l'auto-refresh : inutile de marteler l'API en 401 derrière l'overlay (le reload post-login réarme)
    if (typeof S.autoTimer !== 'undefined' && S.autoTimer) { clearInterval(S.autoTimer); S.autoTimer = null; }
    const u = $('#login-user'); if (u) setTimeout(() => { try { u.focus(); } catch (e) {} }, 40);
  }
}
async function fetchMe() {
  // api() jette sur 401/non-2xx/réseau -> on retombe sur null (= non authentifié), comme l'ancien !r.ok.
  try { return await api('/me'); }
  catch (e) { return null; }
}
async function doLogin(user, pass) {
  // /api/login est PUBLIC + exempté de CSRF (pas encore de session). Retourne {ok:true,...} sur succès.
  const r = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ user, pass }),
  });
  if (r.ok) return { ok: true };
  if (r.status === 429) {
    const ra = parseInt(r.headers.get('Retry-After') || '', 10);
    return { ok: false, status: 429, retry: Number.isFinite(ra) && ra > 0 ? ra : 0 };
  }
  if (r.status === 401) return { ok: false, status: 401 };
  let msg = ''; try { msg = (await r.text()).slice(0, 160); } catch (e) {}
  return { ok: false, status: r.status, msg };
}
function bindLoginForm() {
  const f = $('#login-form'); if (!f || f._bound) return; f._bound = true;
  const err = $('#login-err'), btn = $('#login-submit');
  const fail = m => { if (err) { err.textContent = m; err.hidden = false; } };
  f.addEventListener('submit', async e => {
    e.preventDefault();
    if (err) err.hidden = true;
    const user = ($('#login-user') ? $('#login-user').value : '').trim();
    const pass = $('#login-pass') ? $('#login-pass').value : '';
    if (!user || !pass) { fail('Renseigne identifiant et mot de passe.'); return; }
    if (btn) { btn.disabled = true; btn.dataset._t = btn.textContent; btn.textContent = '...'; }
    let res;
    try { res = await doLogin(user, pass); }
    catch (ex) { res = { ok: false, status: 0, msg: ex && ex.message }; }
    if (btn) { btn.disabled = false; btn.textContent = btn.dataset._t || 'Se connecter'; }
    if (res.ok) {
      // succès : cookies plume_session + plume_csrf posés -> rechargement = boot AUTHENTIFIÉ propre
      // (route()/refresh()/loaders re-exécutés avec une session valide, zéro état partiel résiduel).
      location.reload();
      return;
    }
    if (res.status === 429) fail(res.retry ? `Trop de tentatives, réessaie dans ${res.retry}s.` : 'Trop de tentatives, réessaie plus tard.');
    else if (res.status === 401) fail('Identifiants invalides.');
    else fail('Échec de connexion' + (res.msg ? ' : ' + res.msg : '') + (res.status ? ' (' + res.status + ')' : ''));
    const p = $('#login-pass'); if (p) { p.value = ''; try { p.focus(); } catch (e) {} }
  });
}
async function doLogout() {
  if (!await confirmModal('Se déconnecter de Plume ?', { okText: 'Déconnexion', danger: false })) return;
  try { await apiSend('/logout', 'POST'); } catch (e) {}
  S.AUTH = null;
  // reload -> /api/me 401 (cookie effacé) -> écran de login. En SSO, l'identité vient de l'amont
  // (forward-auth) : /api/me reste 200 -> l'app recharge (la déconnexion SSO se fait côté Authentik).
  location.reload();
}
(function authGate() {
  bindLoginForm();
  const lo = $('#logout'); if (lo && !lo._bound) { lo._bound = true; lo.onclick = doLogout; }
  fetchMe().then(me => {
    if (me && me.user) {
      S.AUTH = me; setAuthUI(); applyRoleClass(me.role); showLogin(false);   // SSO/cookie/démo : app directe
      prefsInit();      // #62 — charge les préférences self-scoped du compte (favoris + réglages par vue) puis rejoue les callbacks
      loadBulletin();   // #51 DAY-2 OPS — bandeau MOTD (aucun bulletin -> reste caché ; invariant mode 0)
      initAiAssist();   // #16 — assistant IA (NL→SOQL) dans Explore : révélé UNIQUEMENT si /api/ai/status = enabled (feature off -> reste caché)
      // #2c switcher tenant, PUIS #2d sélecteur d'environnement (résolu APRÈS le tenant : les env sont
      // cloisonnés par tenant). initEnvironments(true) : si un env persisté est restauré, il recharge la vue.
      initTenants().then(() => initEnvironments(true)).catch(() => { try { initEnvironments(true); } catch (e) {} });
    } else { S.AUTH = null; setAuthUI(); showLogin(true); document.documentElement.classList.add('app-ready'); }   // 401 : écran de login (overlay au-dessus ; on révèle <main> pour ne pas le laisser bloqué masqué)
  });
})();

/* ==== exports consumed by seam modules (auto-managed) ==== */
export { ROLE_LABEL, applyRoleClass, currentTab, currentViewName, fetchMe, loadActions, loadDashboard, loadUsers, refresh, refreshCurrentView, refreshPanels, renderNav, route, setAlertMitreFilter, setAlertSourceFilter, setAuthUI, updateQRangeBtn, updateRangeBtn };

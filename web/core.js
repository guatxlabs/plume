// core.js — primitives partagées de l'UI Plume (extraites de app.js, refactor ES-modules).
// AUCUN état métier ni dépendance vers app.js : uniquement des helpers autonomes (DOM, esc/ic, i18n
// date/langue, modales/toasts, export CSV/JSON/PDF, api()/apiSend(), pagination). app.js et les futurs
// modules importent depuis ici. Comportement identique au monolithe (mêmes fonctions, juste relocalisées).
// state.js est un pur leaf (aucun import) -> l'importer ici ne crée aucun cycle. Utilisé par socRole/socIsAdmin
// (helpers partagés relocalisés depuis app.js, audit H1 — cassent les deps circulaires app<->vues).
import { S } from './state.js';

const $ = s => document.querySelector(s);
// lit une variable de thème CSS (graphes SVG theme-aware : se recolorent au changement clair/sombre)
const CSSV = (n, d) => (getComputedStyle(document.documentElement).getPropertyValue(n).trim() || d);
// Fuseau d'AFFICHAGE : '' = navigateur ; 'UTC' ou 'Europe/Paris' = forcé. Le stockage reste UTC
// partout (ts = epoch) ; on ne change QUE le rendu (sélecteur #tz). Répond à « UTC 0 + Paris configurable ».
let socTZ = localStorage.getItem('soc_tz') || '';
const LANG = localStorage.getItem('soc_lang') || 'fr';   // langue UI (fr par défaut) ; EN via dico FR->EN
const LOC = LANG === 'en' ? 'en-US' : 'fr-FR';            // locale des dates/heures
const tzOpts = () => (socTZ ? { timeZone: socTZ } : {});
const fmtTs = t => t ? new Date(t * 1000).toLocaleString(LOC, tzOpts()) : '-';
const SEV = ['info', 'low', 'medium', 'high', 'critical'];
const sev = n => SEV[n] || '?';
const bool = v => v === true ? ic('check', 'ok') : (v === false ? ic('x', 'bad') : '-');
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
// --- icônes SVG inline (zéro caractère non-ASCII dans l'UI ; héritent la couleur via currentColor) ---
const ICONS = {
  home: '<path d="M3 11l9-8 9 8M5 10v10h5v-6h4v6h5V10"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/>',
  flask: '<path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-9V3"/><path d="M7 14h10"/>',
  layout: '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/>',
  activity: '<path d="M3 12h4l3 8 4-16 3 8h4"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
  wrench: '<path d="M21 4a5 5 0 0 1-6 6L7 18l-3-3 8-8a5 5 0 0 1 6-6l-3 3 2 2z"/>',
  bell: '<path d="M6 9a6 6 0 0 1 12 0c0 7 3 7 3 7H3s3 0 3-7"/><path d="M10 21a2 2 0 0 0 4 0"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="1"/><rect x="3" y="13" width="18" height="7" rx="1"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  plug: '<path d="M9 3v6M15 3v6M7 9h10v3a5 5 0 0 1-10 0zM12 17v4"/>',
  sliders: '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="9" cy="6" r="2"/><circle cx="15" cy="12" r="2"/><circle cx="8" cy="18" r="2"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  users: '<circle cx="9" cy="8" r="3.2"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 5.1a3.2 3.2 0 0 1 0 5.8"/><path d="M18 13.2a6.5 6.5 0 0 1 3.5 6.8"/>',
  save: '<path d="M5 3h11l3 3v15H5z"/><path d="M8 3v6h7M8 21v-6h8v6"/>',
  play: '<path d="M7 4l13 8-13 8z"/>',
  menu: '<path d="M3 6h18M3 12h18M3 18h18"/>',
  pencil: '<path d="M4 20h4L20 8l-4-4L4 16z"/>',
  x: '<path d="M5 5l14 14M19 5L5 19"/>',
  ext: '<path d="M14 4h6v6M20 4l-9 9M19 13v6H5V5h6"/>',
  check: '<path d="M4 12l5 5L20 6"/>',
  warn: '<path d="M12 3l10 18H2z"/><path d="M12 10v4M12 18h.01"/>',
  ban: '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/>',
  moon: '<path d="M21 13A9 9 0 1 1 11 3a7 7 0 0 0 10 10z"/>',
  bars: '<path d="M4 20V10M10 20V4M16 20v-7M2 20h20"/>',
  hash: '<path d="M4 9h16M4 15h16M10 3L8 21M16 3l-2 18"/>',
  // #54 — types de panneaux supplémentaires (parité Grafana/Splunk)
  gauge: '<path d="M4 18a8 8 0 1 1 16 0"/><path d="M12 18l4-5"/>',
  pie: '<path d="M12 3v9h9a9 9 0 1 0-9-9z"/><path d="M21 12a9 9 0 0 1-9 9"/>',
  grid: '<rect x="3" y="3" width="18" height="18" rx="1"/><path d="M9 3v18M15 3v18M3 9h18M3 15h18"/>',
  histogram: '<path d="M3 20h18"/><rect x="4" y="12" width="3" height="8"/><rect x="9" y="7" width="3" height="13"/><rect x="14" y="10" width="3" height="10"/><rect x="19" y="14" width="2" height="6"/>',
  table: '<rect x="3" y="4" width="18" height="16" rx="1"/><path d="M3 10h18M9 4v16"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  chevdown: '<path d="M6 9l6 6 6-6"/>',
  chevright: '<path d="M9 6l6 6-6 6"/>',
  chevleft: '<path d="M15 6l-6 6 6 6"/>',
  grip: '<circle cx="9" cy="6" r="1"/><circle cx="15" cy="6" r="1"/><circle cx="9" cy="12" r="1"/><circle cx="15" cy="12" r="1"/><circle cx="9" cy="18" r="1"/><circle cx="15" cy="18" r="1"/>',
  case: '<rect x="3" y="8" width="18" height="12" rx="1"/><path d="M8 8V6a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-3-6.7M21 4v5h-5"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="1.5"/>',
  // sidebar-matching (C9 aide) : Données (base), Administration (engrenage), Aide (?) — chemins identiques à la nav
  database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>',
  gear: '<circle cx="12" cy="12" r="3.2"/><path d="M12 2v3M12 19v3M22 12h-3M5 12H2M19.1 4.9l-2.1 2.1M7 17l-2.1 2.1M19.1 19.1 17 17M7 7 4.9 4.9"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.6 9a2.4 2.4 0 1 1 3.4 2.2c-.9.5-1.5 1-1.5 2.1"/><path d="M12 17h.01"/>',
  // P11.7-a — espace Cas (dossier d'enquête) : chemin identique à la sidebar d'index.html.
  folder: '<path d="M3 6a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/>',
  download: '<path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/>',
  print: '<path d="M6 9V3h12v6"/><rect x="6" y="14" width="12" height="7"/><path d="M6 18H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-2"/>',
  // #62 — favoris de dashboards (étoile contour / pleine). `starfill` porte fill=currentColor inline (le <svg>
  // parent est fill=none) -> l'étoile pleine se voit même sans classe CSS dédiée.
  star: '<path d="M12 3l2.9 5.9 6.5.9-4.7 4.6 1.1 6.5L12 18.8 6.2 21.4l1.1-6.5L2.6 9.8l6.5-.9z"/>',
  starfill: '<path fill="currentColor" stroke="none" d="M12 3l2.9 5.9 6.5.9-4.7 4.6 1.1 6.5L12 18.8 6.2 21.4l1.1-6.5L2.6 9.8l6.5-.9z"/>',
};
const ic = (n, cls = '') => `<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ''}</svg>`;
// STOP unifié : carré SVG + feedback DISCRET via la barre .tableprog (flash bref puis disparition, aucun texte/popup).
function flashStopped(prog){ if(!prog) return; prog.hidden=false; prog.classList.add('stopped'); clearTimeout(prog._stopT); prog._stopT=setTimeout(()=>{ prog.classList.remove('stopped'); prog.hidden=true; },650); }
function stopBtn(title, cb){ const b=document.createElement('button'); b.type='button'; b.className='stopbtn picon'; b.title=title; b.innerHTML=ic('stop'); b.onclick=cb; return b; }
function closeModals(){ document.querySelectorAll('.modal-ov').forEach(o => o.remove()); }
function withBusy(el, fn){
  if (!el || el.dataset.busy) return Promise.resolve();
  el.dataset.busy = '1'; if ('disabled' in el) el.disabled = true; el.classList.add('btn-busy');
  return Promise.resolve().then(fn).finally(() => { delete el.dataset.busy; if ('disabled' in el) el.disabled = false; el.classList.remove('btn-busy'); });
}

// --- modales + toasts in-page (remplacent alert/confirm/prompt de Chrome) ---
function toast(msg, kind = 'info', ms = 3200) {
  let host = $('#toasts');
  if (!host) { host = document.createElement('div'); host.id = 'toasts'; document.body.appendChild(host); }
  const t = document.createElement('div'); t.className = 'toast ' + kind; t.textContent = msg;
  host.appendChild(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 220); }, ms);
}
function showErr(form, msg) { const e = form.querySelector('.modal-err'); if (e) { e.textContent = msg; e.hidden = false; } }
// modale générique -> Promise(valeurs|null). opts: {title,message,fields,okText,cancelText,danger,validate}
function modal(opts = {}) {
  return new Promise(resolve => {
    closeModals();
    const ov = document.createElement('div'); ov.className = 'modal-ov';
    const box = document.createElement('div'); box.className = 'modal' + (opts.danger ? ' danger' : '');
    const form = document.createElement('form');
    let html = '';
    if (opts.title) html += `<h3>${esc(opts.title)}</h3>`;
    if (opts.message) html += `<p class="modal-msg">${esc(opts.message)}</p>`;
    // conséquence d'une action sensible : ligne DISTINCTE du message (le lecteur la voit avant de cliquer).
    if (opts.consequence) html += `<p class="modal-consequence">${esc(opts.consequence)}</p>`;
    (opts.fields || []).forEach(f => {
      html += `<label class="modal-f"><span>${esc(f.label || f.name)}</span>`;
      if (f.type === 'select') html += `<select data-n="${esc(f.name)}">${(f.options || []).map(o => `<option value="${esc(o.value)}"${String(o.value) === String(f.value) ? ' selected' : ''}>${esc(o.label)}</option>`).join('')}</select>`;
      else if (f.type === 'checkbox') html += `<input type="checkbox" data-n="${esc(f.name)}"${f.value ? ' checked' : ''}>`;
      else if (f.type === 'textarea') html += `<textarea data-n="${esc(f.name)}" rows="2" spellcheck="false" placeholder="${esc(f.placeholder || '')}">${esc(f.value == null ? '' : f.value)}</textarea>`;
      else html += `<input type="${esc(f.type || 'text')}" data-n="${esc(f.name)}" value="${esc(f.value == null ? '' : f.value)}" placeholder="${esc(f.placeholder || '')}"${f.required ? ' required' : ''}>`;
      html += `</label>`;
    });
    html += `<div class="modal-err" hidden></div>`;
    html += `<div class="modal-act"><button type="button" class="m-cancel">${esc(opts.cancelText || 'Annuler')}</button><button type="submit" class="m-ok${opts.danger ? ' danger' : ''}">${esc(opts.okText || 'OK')}</button></div>`;
    form.innerHTML = html; box.appendChild(form); ov.appendChild(box); document.body.appendChild(ov);
    const close = val => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); resolve(val); };
    const onKey = e => { if (e.key === 'Escape') close(null); };
    document.addEventListener('keydown', onKey);
    const first = form.querySelector('input,select,textarea'); if (first) setTimeout(() => first.focus(), 30);
    form.querySelector('.m-cancel').onclick = () => close(null);
    ov.onclick = e => { if (e.target === ov) close(null); };
    form.onsubmit = e => {
      e.preventDefault();
      const vals = {}; form.querySelectorAll('[data-n]').forEach(el => { vals[el.dataset.n] = el.type === 'checkbox' ? el.checked : el.value; });
      for (const f of (opts.fields || [])) { if (f.required && !String(vals[f.name] || '').trim()) { showErr(form, `"${f.label || f.name}" est requis.`); return; } }
      if (opts.validate) { const err = opts.validate(vals); if (err) { showErr(form, err); return; } }
      close(vals);
    };
  });
}
async function confirmModal(message, opts = {}) {
  const r = await modal({ title: opts.title || 'Confirmer', message, okText: opts.okText || 'Confirmer', cancelText: opts.cancelText, danger: opts.danger !== false });
  return r !== null;
}
// CONFIRMATION D'UNE ACTION SENSIBLE — la confirmation partagée qui NOMME LA CONSÉQUENCE (P11.5-b).
// `action` = ce que l'utilisateur s'apprête à faire (titre) ; `consequence` = ce qui en découle et ne se
// défait pas d'un clic (données détruites, droit élevé, réponse automatique armée). La garde de CI
// `.github/scripts/check_sensitive_routes_are_confirmed.py` dérive les routes sensibles du démon et exige
// que chaque appelant web passe par une confirmation exportée d'ici. Sans conséquence nommée, la fenêtre
// n'est pas posée et l'appelant est arrêté : on ne peut pas « confirmer » sans dire ce qui va se passer.
async function confirmWithConsequence(action, consequence, opts = {}) {
  if (!String(consequence || '').trim()) throw new Error('confirmWithConsequence : la conséquence doit être nommée');
  // `fields`/`validate` passent à la modale (ex. retaper le nom d'un tenant avant sa destruction) ; le retour
  // reste booléen sauf si des champs sont demandés (alors les valeurs saisies, ou null).
  const r = await modal({ title: action, message: opts.message, consequence, okText: opts.okText || 'Confirmer', cancelText: opts.cancelText, danger: opts.danger !== false, fields: opts.fields, validate: opts.validate });
  return opts.fields ? r : r !== null;
}

// ============ EXPORT (CSV / JSON / PDF) — P0 ==================================================
// CSV/JSON pour l'Explore = export SERVEUR borné (/api/export : MÊME redaction/RBAC que /api/query, jeu
// complet borné, jamais limité à la page affichée). CSV/JSON pour alertes/case/panneaux = sérialisation
// CLIENTE des données DÉJÀ chargées (endpoints déjà caviardés, sans colonne secrète) -> on ne reformate
// que ce que le serveur a légitimement renvoyé, aucune donnée nouvelle. PDF = feuille @media print +
// window.print (aucun serveur). Aucun de ces chemins ne peut exposer user.hash / token.token_hash.
function csvCell(v) {
  if (v == null) return '';
  let s = (typeof v === 'object') ? JSON.stringify(v) : String(v);
  if (/^[=+@\t\r]/.test(s)) s = "'" + s;                 // anti-injection formule (tableur)
  if (/[",\n\r]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';  // RFC 4180
  return s;
}
// `cols` = ['key',...] ou [{key,label},...] ; `rows` = tableau d'OBJETS.
function toCSV(cols, rows) {
  const C = cols.map(c => typeof c === 'string' ? { key: c, label: c } : c);
  const head = C.map(c => csvCell(c.label)).join(',');
  const body = rows.map(r => C.map(c => csvCell(r[c.key])).join(',')).join('\r\n');
  return head + '\r\n' + body + (rows.length ? '\r\n' : '');
}
function downloadText(filename, mime, text) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
function tsSlug() { const d = new Date(); const p = n => String(n).padStart(2, '0'); return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`; }
// Impression / PDF : window.print (la feuille @media print retire le chrome). `scope` (optionnel) pose une
// classe data-print sur <body> -> le CSS n'imprime QUE la surface visée (explore/alerts/case/dashboards).
function exportPDF(scope) {
  if (scope) document.body.setAttribute('data-print', scope);
  const done = () => { document.body.removeAttribute('data-print'); window.removeEventListener('afterprint', done); };
  window.addEventListener('afterprint', done);
  setTimeout(() => { window.print(); if (scope) setTimeout(done, 800); }, 40); // filet si afterprint ne fire pas
}
// Barre d'export réutilisable (CSV / JSON / PDF) pour des données CLIENTES. `getData()` -> {cols, rows}
// (rows = objets) ; `name` = préfixe fichier ; `pdfScope` = surface à imprimer. `opts` masque des boutons.
function exportBar(name, getData, pdfScope, opts) {
  opts = opts || {};
  const wrap = document.createElement('span'); wrap.className = 'export-actions noprint';
  // ui-regression — l'export « déjà chargé » ne porte que la PAGE COURANTE sur une vue paginée.
  // opts.partial={shown,total} -> on prévient (toast) au clic quand total>shown, pour ne pas laisser croire à un
  // jeu complet (l'export Explore, lui, re-tourne côté serveur /api/export pour le jeu complet borné).
  const warnPartial = () => { const p = opts.partial; if (p && typeof p.total === 'number' && p.total > p.shown) toast(`Export : page courante uniquement (${p.shown}/${p.total} lignes) — filtrez ou paginez pour le reste`, 'info'); };
  const mk = (label, title, fn) => { const b = document.createElement('button'); b.type = 'button'; b.className = 'exportbtn'; b.title = title; b.textContent = label; b.onclick = fn; return b; };
  if (opts.csv !== false) wrap.appendChild(mk('CSV', 'Exporter en CSV', () => { warnPartial(); const d = getData(); downloadText(`plume-${name}-${tsSlug()}.csv`, 'text/csv;charset=utf-8', toCSV(d.cols, d.rows)); }));
  if (opts.json !== false) wrap.appendChild(mk('JSON', 'Exporter en JSON', () => { warnPartial(); const d = getData(); downloadText(`plume-${name}-${tsSlug()}.json`, 'application/json', JSON.stringify(d.rows, null, 2)); }));
  if (opts.pdf !== false) wrap.appendChild(mk('PDF', 'Imprimer / exporter en PDF', () => exportPDF(pdfScope)));
  return wrap;
}
// Petit menu popover (position:fixed) — items = [{label,fn}]. Un seul ouvert à la fois.
let _miniMenuClose = null;
function closeMiniMenu() { if (_miniMenuClose) { const f = _miniMenuClose; _miniMenuClose = null; f(); } }
function miniMenu(anchor, items) {
  closeMiniMenu();
  const menu = document.createElement('div'); menu.className = 'minimenu noprint';
  items.forEach(it => { const b = document.createElement('button'); b.type = 'button'; b.className = 'minimenu-item'; b.textContent = it.label; b.onclick = () => { closeMiniMenu(); it.fn(); }; menu.appendChild(b); });
  document.body.appendChild(menu);
  const r = anchor.getBoundingClientRect();
  menu.style.position = 'fixed'; menu.style.top = (r.bottom + 4) + 'px'; menu.style.left = Math.max(6, r.right - menu.offsetWidth) + 'px';
  const onDoc = e => { if (!menu.contains(e.target) && e.target !== anchor) closeMiniMenu(); };
  const onKey = e => { if (e.key === 'Escape') closeMiniMenu(); };
  setTimeout(() => { document.addEventListener('mousedown', onDoc); document.addEventListener('keydown', onKey); }, 0);
  _miniMenuClose = () => { document.removeEventListener('mousedown', onDoc); document.removeEventListener('keydown', onKey); menu.remove(); };
}

// PANNE TRANSITOIRE DE PASSERELLE : détecte un 502/503/504 de reverse-proxy (ou un corps HTML « no available
// server » servi pendant la fenêtre de rollout) et renvoie un message propre — au lieu de surfacer le corps brut
// (« réponse non-JSON … no available server »). null = ce n'est PAS transitoire (comportement inchangé).
function transientGatewayMsg(status, body) {
  if (status === 502 || status === 503 || status === 504) return 'Service momentanément indisponible, réessaie dans un instant.';
  if (body && /no available server|<!doctype|<html/i.test(body)) return 'Service momentanément indisponible, réessaie dans un instant.';
  return null;
}

async function api(path) {
  // Sur panne transitoire de passerelle -> réessais GET-only (idempotents) ~400ms puis ~800ms, sinon
  // message propre. Toute autre erreur garde EXACTEMENT le comportement d'avant (statut+corps / vide / non-JSON).
  const backoffs = [400, 800];
  for (let attempt = 0; ; attempt++) {
    const r = await fetch('/api' + path, { headers: { Accept: 'application/json' } });
    const body = await r.text().catch(() => '');   // lit en texte d'abord -> gère réponse vide/tronquée
    const tg = transientGatewayMsg(r.status, r.ok ? '' : body);   // ok=200 -> corps vérifié plus bas (cas HTML servi en 200)
    if (tg) {
      if (attempt < backoffs.length) { await new Promise(res => setTimeout(res, backoffs[attempt])); continue; }
      throw new Error(tg);
    }
    if (!r.ok) throw new Error(r.status + (body ? ' ' + body.slice(0, 200) : ''));
    if (!body) throw new Error('réponse vide du serveur (timeout proxy ou requête trop lourde ?)');
    try { return JSON.parse(body); }
    catch {
      const tg2 = transientGatewayMsg(r.status, body);   // corps HTML « no available server » servi en 200 -> transitoire
      if (tg2) { if (attempt < backoffs.length) { await new Promise(res => setTimeout(res, backoffs[attempt])); continue; } throw new Error(tg2); }
      throw new Error('réponse non-JSON (tronquée ? timeout ?) : ' + body.slice(0, 120));
    }
  }
}

// apiSend — sœur MUTANTE de api() (POST/PUT/DELETE vers /api, corps JSON optionnel). MÊME forme de requête
// que les sites inline qu'elle remplace : on ne pose QUE Content-Type quand il y a un corps ; le X-CSRF-Token
// (+ X-Plume-Tenant/Env) est ajouté AUTOMATIQUEMENT par le wrapper window.fetch global -> requête byte-identique.
// Erreur lisible IDENTIQUE à api() sur !ok (statut + jusqu'à 200 car. du corps serveur). Corps vide (204 /
// StatusCode sans JSON, ex panel_update) -> null : une mutation renvoie souvent un corps vide, on ne JETTE PAS
// comme api() (qui, lui, sert des GET toujours-JSON). Corps non-JSON inattendu en succès -> null (best-effort).
async function apiSend(path, method = 'POST', body) {
  const init = { method };
  if (body !== undefined) { init.headers = { 'Content-Type': 'application/json' }; init.body = JSON.stringify(body); }
  const r = await fetch('/api' + path, init);
  const text = await r.text().catch(() => '');   // texte d'abord -> corps d'erreur dispo + gère réponse vide
  if (!r.ok) throw new Error(r.status + (text ? ' ' + text.slice(0, 200) : ''));
  if (!text) return null;
  try { return JSON.parse(text); } catch { return null; }
}

function muted(t) { return Object.assign(document.createElement('div'), { className: 'muted', textContent: t }); }

// fetchInto — boilerplate GET-and-render partagé (audit H2). Remplace le motif copié ~partout :
//   let d; try { d = await api('/x'); } catch (e) { host.replaceChildren(muted('erreur : '+…)); return; }
// -> const d = await fetchInto(host, '/x'); if (!d) return;
// Rend le MÊME message d'erreur (« erreur : » + message/erreur) DANS `host` et renvoie null sur échec
// (l'appelant early-return sur !d). Succès -> renvoie le JSON d'api() (toujours truthy pour ces endpoints).
async function fetchInto(host, path){ try { return await api(path); } catch(e){ host.replaceChildren(muted('erreur : '+((e&&e.message)||e))); return null; } }

function colComparator(rows, get) {
  const ipv4 = s => /^(\d{1,3}\.){3}\d{1,3}$/.test(s);
  const ne = rows.filter(r => { const v = get(r); return v != null && v !== ''; });
  const isIp = ne.length > 0 && ne.some(r => ipv4(String(get(r)))) && ne.every(r => { const v = String(get(r)); return ipv4(v) || v.includes(':'); });
  const numeric = !isIp && rows.every(r => { const v = get(r); return v == null || v === '' || !isNaN(Number(v)); });
  return (a, b) => {
    const x = get(a), y = get(b);
    if (isIp) {
      const xs = String(x == null ? '' : x), ys = String(y == null ? '' : y);
      const xo = ipv4(xs) ? xs.split('.').map(Number) : null;
      const yo = ipv4(ys) ? ys.split('.').map(Number) : null;
      if (xo && yo) { for (let i = 0; i < 4; i++) if (xo[i] !== yo[i]) return xo[i] - yo[i]; return 0; }
      if (xo) return -1;            // IPv4 avant IPv6/vide
      if (yo) return 1;
      return xs.localeCompare(ys);
    }
    if (numeric) return (Number(x) || 0) - (Number(y) || 0);
    return String(x == null ? '' : x).localeCompare(String(y == null ? '' : y));
  };
}

function makePager(state, onGo) {
  const PS = state.pageSize, total = state.total, numbered = total >= 0;
  const pages = numbered ? Math.max(1, Math.ceil(total / PS)) : state.page + (state.shown >= PS ? 2 : 1);
  if (numbered && pages <= 1) return null;   // une seule page -> pas de pager
  const from = state.page * PS;
  const wrap = document.createElement('div'); wrap.className = 'evpager';
  const prev = document.createElement('button'); prev.type = 'button'; prev.className = 'evprev'; prev.title = 'précédent'; prev.textContent = '◀'; prev.disabled = state.page === 0;
  prev.onclick = () => { if (state.page > 0) onGo(state.page - 1); };
  wrap.appendChild(prev);
  if (numbered) {
    pageNums(state.page, pages, state.keyset).forEach(n => {
      if (n === '…') { const s = document.createElement('span'); s.className = 'evdots'; s.textContent = '…'; wrap.appendChild(s); }
      else { const b = document.createElement('button'); b.type = 'button'; b.className = 'evnum' + (n - 1 === state.page ? ' on' : ''); b.textContent = String(n); b.onclick = () => onGo(n - 1); wrap.appendChild(b); }
    });
  } else {
    const s = document.createElement('span'); s.className = 'evdots'; s.textContent = 'page ' + (state.page + 1); wrap.appendChild(s);
  }
  const next = document.createElement('button'); next.type = 'button'; next.className = 'evnext'; next.title = 'suivant'; next.textContent = '▶';
  next.disabled = numbered ? state.page >= pages - 1 : state.shown < PS;
  next.onclick = () => onGo(state.page + 1);
  wrap.appendChild(next);
  const tot = document.createElement('span'); tot.className = 'evtot';
  // COUNT BORNÉ : `state.totalCapped` -> le serveur a plafonné le total (> 10 000) -> on rend « 10 000+ »
  // (le total exact resterait honnête mais coûterait un scan complet). Absent/false -> total exact, inchangé.
  const totLbl = total >= 0 ? (total + (state.totalCapped ? '+' : '') + ' · ') : '';
  tot.textContent = totLbl + (from + 1) + '–' + (from + state.shown);
  wrap.appendChild(tot);
  return wrap;
}

// cur 0-based -> numéros 1-based cliquables + ellipses.
// `keyset` (modèle Splunk) : la pagination par CURSEUR rend Préc/Suiv fiables et
// illimités, mais un saut vers une page LOINTAINE = OFFSET profond coûteux (budget). On n'affiche donc PAS la
// dernière page (saut le plus lourd) ; à la place, des REPÈRES ESPACÉS (10,20,30,50,100…) donnent des sauts
// approximatifs, et un saut trop lourd dégrade gracieusement (message, pas de page vide) côté evLoad. Le total
// exact reste affiché à part. Mode OFFSET (non-keyset : tables cases/alertes/ledger, bon marché) -> inchangé
// (fenêtre proche + première + DERNIÈRE page), backward-compatible (state.keyset absent = falsy).
function pageNums(cur, pages, keyset) {
  const c = cur + 1;
  if (keyset) {
    // KEYSET : bande PROCHE large (~10 pages contiguës, ancrée pour montrer 1..10 en début) + REPÈRES espacés
    // (20,30,50,100…) pour sauts approximatifs, SANS dernière page (saut OFFSET le plus lourd). Préc/Suiv (curseur)
    // restent le parcours fiable ; un saut trop lourd dégrade gracieusement (evLoad). Total exact affiché à part.
    const s = new Set([1]), lo = Math.max(1, c - 4);   // 1 TOUJOURS présent : retour au sommet = curseur null, rapide et fiable
    for (let i = lo; i <= Math.min(pages, lo + 9); i++) s.add(i);
    for (const m of [20, 30, 50, 100, 200, 500, 1000, 2000]) if (m <= pages && m > c + 5) s.add(m);
    const arr = [...s].sort((a, b) => a - b), out = []; let prev = 0;
    for (const n of arr) { if (n - prev > 1) out.push('…'); out.push(n); prev = n; }
    return out;
  }
  // OFFSET (tables bon marché : cases/alertes/ledger) : fenêtre proche + première + DERNIÈRE page (inchangé).
  const s = new Set([1, pages]);
  for (let i = c - 2; i <= c + 2; i++) if (i >= 1 && i <= pages) s.add(i);
  const arr = [...s].sort((a, b) => a - b), out = []; let prev = 0;
  for (const n of arr) { if (n - prev > 1) out.push('…'); out.push(n); prev = n; }
  return out;
}
// LISTE PAGINÉE PARTAGÉE (BATCH 1 — scalabilité) : pager haut+bas (makePager, auto-caché si <=1 page),
// tri, et sortie tableau enveloppée dans un conteneur overflow:auto (corrige aussi le débordement table-
// dans-carte). Deux modes :
//   - 'client' : `rows` complet fourni ; tri (colComparator) + slice EN JS, re-slice au changement de
//     page/tri (aucun fetch). Petit/moyen volume déjà chargé.
//   - 'server' : `fetchPage({limit,offset,sort,dir})` -> {rows,total} ; page/tri => re-fetch (le navigateur
//     ne tient qu'une page). Grand volume.
// opts.columns=[{key,label,sortable,align:'l|c|r',render:(row)=>Node|string,sortVal:(row)=>v}] (rendu en
// <table.qtable>) OU opts.renderRow:(row)=>Node (liste libre, ex. lignes badge/action). `render`/`renderRow`
// renvoient des NŒUDS -> badges & boutons d'action survivent. opts: {mode,pageSize=50,rows,fetchPage,columns,
// renderRow,sort:{key,dir},emptyText,onRowClick}. Renvoie {reload,state}.
function pagedList(host, opts) {
  const pageSize = opts.pageSize || 50;
  const state = { page: 0, pageSize, total: 0, shown: 0 };
  const columns = opts.columns || null;
  let sort = opts.sort ? { key: opts.sort.key, dir: opts.sort.dir || 1 } : null;   // dir : 1 asc / -1 desc
  const clientRows = opts.mode === 'client' ? (opts.rows || []) : null;
  const alignOf = a => (a === 'r' ? 'right' : a === 'c' ? 'center' : '');
  function rowNode(row) {
    if (opts.renderRow) {
      const n = opts.renderRow(row);
      if (opts.onRowClick) { n.style.cursor = 'pointer'; n.addEventListener('click', () => opts.onRowClick(row)); }
      return n;
    }
    const tr = document.createElement('tr');
    columns.forEach(c => {
      const td = document.createElement('td');
      const v = c.render ? c.render(row) : (row[c.key] == null ? '' : row[c.key]);
      if (v instanceof Node) td.appendChild(v); else td.textContent = String(v);
      const al = alignOf(c.align); if (al) td.style.textAlign = al;
      tr.appendChild(td);
    });
    if (opts.onRowClick) { tr.style.cursor = 'pointer'; tr.onclick = () => opts.onRowClick(row); }
    return tr;
  }
  // corps : renderRow -> nœuds empilés directement (pas de <table>, layout inchangé) ; columns -> table
  // .qtable enveloppée dans .plscroll (overflow:auto).
  function bodyNode(rows) {
    if (opts.renderRow) { const frag = document.createDocumentFragment(); rows.forEach(r => frag.appendChild(rowNode(r))); return frag; }
    const scroll = document.createElement('div'); scroll.className = 'plscroll';
    const table = document.createElement('table'); table.className = 'qtable';
    const thead = document.createElement('thead'); const htr = document.createElement('tr');
    columns.forEach(c => {
      const th = document.createElement('th'); th.textContent = c.label != null ? c.label : c.key;
      const al = alignOf(c.align); if (al) th.style.textAlign = al;
      if (c.sortable) {
        th.style.cursor = 'pointer'; th.title = 'Trier par ' + (c.label != null ? c.label : c.key);
        if (sort && sort.key === c.key) { const ar = document.createElement('span'); ar.className = 'sortar'; ar.textContent = sort.dir > 0 ? ' ▲' : ' ▼'; th.appendChild(ar); }
        th.onclick = () => { if (sort && sort.key === c.key) sort.dir = -sort.dir; else sort = { key: c.key, dir: 1 }; state.page = 0; reload(); };
      }
      htr.appendChild(th);
    });
    thead.appendChild(htr); table.appendChild(thead);
    const tb = document.createElement('tbody'); rows.forEach(r => tb.appendChild(rowNode(r))); table.appendChild(tb);
    scroll.appendChild(table); return scroll;
  }
  function paint(rows) {
    host.replaceChildren();
    if (!rows.length && !state.total) { host.appendChild(muted(opts.emptyText || 'aucune donnée')); return; }
    const go = p => { state.page = p; reload(); };
    const top = makePager(state, go); if (top) host.appendChild(top);
    host.appendChild(bodyNode(rows));
    const bot = makePager(state, go); if (bot) host.appendChild(bot);
  }
  function sliceClient() {
    let rows = clientRows.slice();
    if (sort) {
      const col = columns ? columns.find(c => c.key === sort.key) : null;
      const get = col && col.sortVal ? col.sortVal : (r => r[sort.key]);
      const cmp = colComparator(rows, get);
      rows.sort((a, b) => cmp(a, b) * sort.dir);
    }
    state.total = clientRows.length;
    const start = state.page * state.pageSize;
    const page = rows.slice(start, start + state.pageSize);
    state.shown = page.length;
    paint(page);
  }
  async function loadServer() {
    let r;
    try { r = await opts.fetchPage({ limit: state.pageSize, offset: state.page * state.pageSize, sort: sort ? sort.key : '', dir: sort ? (sort.dir > 0 ? 'asc' : 'desc') : '' }); }
    catch (e) { host.replaceChildren(muted('erreur : ' + (e && e.message ? e.message : e))); return; }
    const rows = (r && r.rows) || [];
    state.total = (r && typeof r.total === 'number') ? r.total : rows.length;
    state.shown = rows.length;
    paint(rows);
  }
  function reload() { if (opts.mode === 'server') loadServer(); else sliceClient(); }
  reload();
  return { reload, state };
}

// ============ HELPERS PARTAGÉS (relocalisés depuis app.js — audit H1) ============================
// Ces helpers vivaient dans app.js mais étaient réimportés par de nombreuses vues (deps CIRCULAIRES
// app<->vues). Déplacés ici VERBATIM (comportement identique). AUCUNE dépendance vers app.js.

// rôle courant : S.AUTH.role fait foi, sinon on hérite des classes role-* posées sur <body>. Fail-closed.
function socRole() {
  if (S.AUTH && S.AUTH.role) return S.AUTH.role;
  const c = document.body ? document.body.classList : null;
  if (!c) return '';
  return c.contains('role-admin') ? 'admin' : c.contains('role-editor') ? 'editor' : c.contains('role-viewer') ? 'viewer' : '';
}
// SQL brut = admin uniquement (garde-fou #2/#5). Fail-closed : rôle inconnu -> non-admin.
function socIsAdmin() { return socRole() === 'admin'; }

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

// « managed » (garde-fou #4) : 0=builtin (seed), 1=overlay (config.d), 2=perso (créé via l'UI). Le CRUD
// UI ne crée que du managed=2. La suppression DESTRUCTIVE est réservée au managed=2 ; un builtin se
// DÉSACTIVE (case « actif »), un overlay est géré par fichier (réimposé au boot). Le serveur applique la
// même sémantique (disable/409) — ceci n'est que l'UX correspondante.
const MANAGED_LABEL = { 0: 'builtin', 1: 'overlay', 2: 'perso' };
const MANAGED_HINT = {
  0: 'contenu par défaut (seed) — non supprimable ; passez l’interrupteur sur OFF pour le désactiver',
  1: 'contenu overlay (config.d) — géré par fichier, réimposé au démarrage ; non supprimable ici',
  2: 'contenu créé via l’interface — modifiable et supprimable',
};
function managedBadge(m) {
  m = Number(m) || 0;
  const b = document.createElement('span');
  b.className = 'mgbadge mg-' + m;
  b.textContent = MANAGED_LABEL[m] || ('managed=' + m);   // textContent -> anti-XSS
  b.title = MANAGED_HINT[m] || '';
  return b;
}
// Applique la garde de suppression sur un bouton delete selon `managed`. managed=2 -> supprimable
// (l'appelant câble onclick) ; 0/1 -> bouton grisé + désactivé + libellé explicatif. Retourne true si
// la suppression destructive est permise.
function gateDeleteBtn(btn, m) {
  m = Number(m) || 0;
  if (m === 2) return true;
  btn.disabled = true;
  btn.classList.add('mg-nodel');
  btn.title = m === 1
    ? 'contenu overlay (config.d) : non supprimable ici (géré par fichier)'
    : 'contenu builtin : non supprimable — passez l’interrupteur sur OFF pour le désactiver';
  return false;
}
// petite aide : écrit un message d'état dans un <span> de formulaire (#rf-result, #pf-result, …).
function formMsg(sel, msg, bad) { const el = $(sel); if (el) { el.textContent = msg; el.className = bad ? 'bad' : 'muted'; } }
// POST une mutation de CONTENU (règle/parseur/playbook) et REMONTE l'erreur serveur dans le <span> resSel
// SANS fermer le formulaire. Retour: true si 2xx. Fin wrapper d'UX autour d'apiSend (plus de fetch brut).
async function contentSubmit(path, body, resSel) {
  formMsg(resSel, '…', false);
  try { await apiSend(path, 'POST', body); }
  catch (e) { const m = (e && e.message) || 'échec'; formMsg(resSel, m, true); toast(m, 'bad'); return false; }
  formMsg(resSel, '', false); return true;
}
// DELETE managed-aware : 200 {deleted:true} -> supprimé ; 200 {deleted:false,disabled:true,message}
// -> builtin désactivé (message serveur) ; 409/404 {error} -> refusé/introuvable (apiSend jette). Retour:
// true si la liste doit être rechargée (succès OU désactivation). Fin wrapper managed-aware autour d'apiSend.
async function contentDelete(path, label) {
  let j;
  try { j = await apiSend(path, 'DELETE'); }
  catch (e) { toast((e && e.message) || 'échec', 'bad'); return false; }
  j = j || {};
  if (j.deleted === false && j.disabled) toast(j.message || ((label || 'contenu') + ' builtin : désactivé (non supprimé)'), 'info');
  else toast((label || 'contenu') + ' supprimé', 'ok');
  return true;
}

// couleurs par sévérité (var CSS) — partagé alertes/détection.
const SEVCOL = { 1: 'var(--sev1)', 2: 'var(--sev2)', 3: 'var(--sev3)', 4: 'var(--sev4)' };
function lsSet(storeKey) { try { return new Set(JSON.parse(localStorage.getItem(storeKey)) || []); } catch (e) { return new Set(); } }
// groupe repliable RÉUTILISABLE (même chrome que renderFreshness : .fgroup/.fgrouphd/.fgbody).
// `set` = Set d'état plié (chargé via lsSet), `storeKey` = clé localStorage où le persister, `key` = clé
// du groupe dans le Set. `nodes` = lignes DOM du corps. `dotHtml` (optionnel) = pastille de tête.
function collapsibleGroup(set, storeKey, key, label, count, nodes, dotHtml) {
  const collapsed = set.has(key);
  const wrap = document.createElement('div'); wrap.className = 'fgroup' + (collapsed ? ' collapsed' : '');
  const hd = document.createElement('button'); hd.type = 'button'; hd.className = 'fgrouphd';
  hd.setAttribute('aria-expanded', collapsed ? 'false' : 'true'); hd.title = 'Plier / déplier ' + label;
  hd.innerHTML = ic('chevdown') + (dotHtml || '') + `<span class="fglbl">${esc(label)}</span><span class="fgcount">${count}</span>`;
  const body = document.createElement('div'); body.className = 'fgbody';
  nodes.forEach(n => body.appendChild(n));
  hd.onclick = () => {
    const nowCollapsed = wrap.classList.toggle('collapsed');
    hd.setAttribute('aria-expanded', nowCollapsed ? 'false' : 'true');
    if (nowCollapsed) set.add(key); else set.delete(key);
    try { localStorage.setItem(storeKey, JSON.stringify([...set])); } catch (e) {}
  };
  wrap.append(hd, body);
  return wrap;
}

// DÉPLI PARTAGÉ d'un panneau par un bouton (P11.4-a) — formulaire, picker, éditeur en ligne. UN comportement
// pour toute la console : le bouton OUVRE et REFERME (second clic = repli), il porte son état
// (`aria-expanded` + `.on`, accent) et n'est JAMAIS désactivé pendant que le panneau est ouvert — un bouton
// de dépli actif n'est pas un bouton grisé. Plusieurs boutons peuvent piloter le même panneau avec des
// contenus différents (connecteurs : preset / Defender / TAXII / HTTP) : `isOpen` dit si CE bouton est
// celui dont le contenu est affiché, `open` pose le contenu. Une fermeture faite ailleurs (« Annuler »
// dans le panneau, `hidden` posé par un autre module) est observée sur le panneau lui-même, de sorte
// que l'état du bouton suit toujours le panneau et non l'inverse.
function disclosure(btn, panel, opts = {}) {
  if (!btn || !panel) return null;
  const visible = () => !panel.hidden && !panel.classList.contains('hidden');
  const isOpen = opts.isOpen || visible;
  const show = opts.open || (() => { panel.hidden = false; panel.classList.remove('hidden'); });
  const hide = opts.close || (() => { panel.hidden = true; panel.classList.add('hidden'); });
  const paint = () => {
    const o = !!isOpen();
    btn.setAttribute('aria-expanded', o ? 'true' : 'false');
    btn.classList.toggle('on', o);
    if (btn.disabled) btn.disabled = false;
  };
  if (panel.id) btn.setAttribute('aria-controls', panel.id);
  btn.onclick = () => { if (isOpen()) hide(); else show(); paint(); };
  try { new MutationObserver(paint).observe(panel, { attributes: true, attributeFilter: ['hidden', 'class'] }); } catch (e) {}
  paint();
  return { open: () => { show(); paint(); }, close: () => { hide(); paint(); }, toggle: btn.onclick, isOpen, paint };
}

// MITRE ATT&CK — noms statiques (l'API ne renvoie que l'ID). Fallback sous-technique : strip .NNN -> parent.
const MITRE_NAMES = { T1046: "Network Service Discovery", T1071: "Application Layer Protocol", T1110: "Brute Force", T1190: "Exploit Public-Facing Application", T1204: "User Execution", T1490: "Inhibit System Recovery", T1498: "Network Denial of Service", T1543: "Create or Modify System Process", T1552: "Unsecured Credentials", T1554: "Compromise Host Software Binary", "T1562.001": "Impair Defenses: Disable or Modify Tools", T1565: "Data Manipulation", T1595: "Active Scanning", "T1595.002": "Active Scanning: Vulnerability Scanning" };
function mitreName(id) { return MITRE_NAMES[id] || MITRE_NAMES[(id || "").split(".")[0]] || ""; }

// âge humain : secondes -> « N s / N min / N h / N j » (borné, compact ; utilisé par fleet/sources/risk/…).
const humanAge = s => { s = Number(s) || 0; return s < 90 ? s + ' s' : s < 5400 ? Math.round(s / 60) + ' min' : s < 172800 ? Math.round(s / 3600) + ' h' : Math.round(s / 86400) + ' j'; };

// socTZ est un binding vivant (import en lecture seule côté consommateurs) ; setter dédié pour l'unique
// site d'écriture (sélecteur #tz, suivi d'un location.reload()).
export function setSocTZ(v) { socTZ = v; }
export {
  $, CSSV, socTZ, LANG, LOC, tzOpts, fmtTs, SEV, sev, bool, esc, ICONS, ic, flashStopped, stopBtn, closeModals, withBusy, toast, showErr, modal, confirmModal, csvCell, toCSV, downloadText, tsSlug, exportPDF, exportBar, closeMiniMenu, miniMenu, api, apiSend, transientGatewayMsg, muted, fetchInto, colComparator, makePager, pageNums, pagedList,
  socRole, socIsAdmin, applyRoleClass, managedBadge, gateDeleteBtn, formMsg, contentSubmit, contentDelete, SEVCOL, lsSet, collapsibleGroup, mitreName, humanAge,
  confirmWithConsequence, disclosure
};

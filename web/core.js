// core.js — primitives partagées de l'UI Plume (extraites de app.js, refactor ES-modules).
// AUCUN état métier ni dépendance vers app.js : uniquement des helpers autonomes (DOM, esc/ic, i18n
// date/langue, modales/toasts, export CSV/JSON/PDF, api()/apiSend(), pagination). app.js et les futurs
// modules importent depuis ici. Comportement identique au monolithe (mêmes fonctions, juste relocalisées).
// state.js est un pur leaf (aucun import) -> l'importer ici ne crée aucun cycle. Utilisé par socRole/socIsAdmin
// (helpers partagés relocalisés depuis app.js, audit H1 — cassent les deps circulaires app<->vues).
import { S } from './state.js';
// `P11.18-m` — LA RECHERCHE D'UNE LISTE N'EST PAS RÉÉCRITE ICI : elle vit dans le module qui la porte
// déjà pour toute la console. `recherche_de_liste.js` est un feuillet — il n'importe rien — donc
// l'importer depuis le cœur ne crée aucun cycle, et le prédicat, le filtre et la phrase de résumé
// restent écrits UNE fois.
import { champDeRecherche, filtrerParRecherche, resumeDeRecherche, souvenirDeRecherche, texteCherchable } from './recherche_de_liste.js';

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
  // P11.4-h : le geste de copie de la console (deux feuilles superposées). Une icône et une seule :
  // c'est ce qui rend le geste reconnaissable partout où il est offert.
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M6 15H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v1"/>',
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
// modale générique -> Promise(valeurs|null). opts: {title,message,fields,body,okText,cancelText,danger,validate}
// `body` (P11.13-a) : un NŒUD inséré avant la zone d'erreur, pour une modale qui doit porter autre chose
// qu'une suite de champs — une liste cherchable, par exemple. TROIS surfaces de la console avaient dû se
// fabriquer leur propre calque faute de cette fente (la palette de modèles, le dropdown des requêtes
// enregistrées, le formulaire de règle) ; ouvrir la fente coûte une ligne et retire la raison d'en écrire
// un quatrième. Les valeurs des champs `[data-n]` que le nœud contient sont collectées comme les autres.
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
    form.innerHTML = html;
    if (opts.body) form.insertBefore(opts.body, form.querySelector('.modal-err'));
    box.appendChild(form); ov.appendChild(box); document.body.appendChild(ov);
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
// ==================================================================================================
// `P11.18-m` — LA RECHERCHE EST UNE OPTION DE LA FABRIQUE, ET SON TEXTE SE DÉRIVE
// --------------------------------------------------------------------------------------------------
// LE CONSTAT, MESURÉ le 2026-08-25 sur `web/`. La fabrique rend TRENTE-QUATRE surfaces de liste (trente-
// cinq appels : le panneau des règles en fait deux, la branche « recherche posée » et la branche
// groupée). QUATRE d'entre elles portent une recherche, et le câblage est réécrit à chaque fois : un
// champ, un état de module, un prédicat, une phrase. TROIS déclarent un groupement, toutes les trois dans
// le même fichier. Le même écart sur deux gestes voisins — et la trente-cinquième liste posée repartira
// sans rien, comme les trente précédentes, tant que l'un et l'autre se recâblent à la main.
//
// LE TEXTE CHERCHÉ EST CE QUI EST AFFICHÉ, ET IL EST DÉRIVÉ — AUCUNE LISTE DE CHAMPS N'EST ÉCRITE.
// VINGT-QUATRE des trente-quatre surfaces DÉCLARENT leurs colonnes, et la fabrique sait déjà rendre
// chaque cellule : le texte d'une ligne est donc le texte de ses cellules, et la propriété devient « ce
// qui est affiché se cherche ». C'est plus qu'un raccourci d'écriture : une colonne qui rend « critical »
// pour une gravité valant 4 se cherche par le mot LU, pas par le chiffre stocké — chercher les champs
// rendrait « aucun résultat » sur ce que l'exploitant a sous les yeux. Les listes qui rendent leur ligne
// à la main n'ont pas de cellules : le nœud qu'elles rendent EST leur affichage, et son texte fait
// l'affaire ; celles qui veulent en décider autrement fournissent `texteDeLaLigne`.
// LE COÛT EST BORNÉ PAR UN SOUVENIR PAR LISTE. Dériver le texte construit les cellules de TOUTES les
// lignes, pas seulement de la page rendue ; le résultat est donc retenu par ligne, pour la durée de cette
// liste — la première frappe le paie, les suivantes ne le repaient pas.
//
// LA PORTÉE, LA FABRIQUE LA CONNAÎT DÉJÀ ; LE SEUL POINT À DÉCLARER EST LA FENÊTRE. Une liste servie par
// page (`mode: 'server'`) ne tient QUE la page affichée — la recherche ne peut porter que sur elle, et
// elle le DIT. Une liste qui a reçu ses lignes les tient toutes : la recherche porte sur tout ce qu'on
// lui a remis. Reste ce que la fabrique ne peut pas mesurer : ce qu'on lui a remis est-il lui-même une
// FENÊTRE d'un magasin plus grand ? La route le sait, la fabrique non — c'est le seul mot à déclarer
// (`recherche: { fenetre: true }`), et taire cette limite ferait rendre « aucun résultat » pour une ligne
// qui EXISTE, l'erreur qui va dans le sens dangereux sur une console de sécurité.
//
// UNE OPTION, JAMAIS UNE RÈGLE QUI VISE LE CONTENEUR. Rien n'est imposé aux trente-quatre : une liste
// sans `recherche` rend exactement ce qu'elle rendait, au nœud près, et la barre n'existe pas. C'est le
// piège `P11.4-m` — une règle qui vise le conteneur atteint ce qu'on ne visait pas — et il est évité ici
// par construction : l'option s'active liste par liste, là où elle a un sens.
// ==================================================================================================
const MOT_RECHERCHE_LISTE_INVITE = LANG === 'en' ? 'Search this list…' : 'Rechercher dans cette liste…';
const MOT_RECHERCHE_LISTE_ETIQUETTE = LANG === 'en' ? 'Search this list' : 'Rechercher dans cette liste';
// Les trois portées, écrites EN ENTIER dans les deux langues à l'endroit du rendu : une phrase recollée à
// l'exécution ne serait jamais égale à une clé du lexique et resterait en français.
const MOT_RECHERCHE_LISTE_AIDE_TOUT = LANG === 'en'
  ? 'Searches the DISPLAYED text of each row, that text alone; the whole list is held here, so nothing escapes it. It composes with sorting and grouping. Esc clears the search.'
  : "Cherche dans le texte AFFICHÉ de chaque ligne, celui-là seul ; la liste est tenue ici en entier, rien ne lui échappe. Se combine avec le tri et le regroupement. Échap efface la recherche.";
const MOT_RECHERCHE_LISTE_AIDE_FENETRE = LANG === 'en'
  ? 'Searches the DISPLAYED text of each SERVED row; it does not reach beyond the served window, so an older row may exist without being reachable from here. Esc clears the search.'
  : "Cherche dans le texte AFFICHÉ de chaque ligne SERVIE ; elle ne descend pas au-delà de la fenêtre servie : une ligne plus ancienne peut exister sans être atteignable depuis ici. Échap efface la recherche.";
const MOT_RECHERCHE_LISTE_AIDE_PAGE = LANG === 'en'
  ? 'Searches the DISPLAYED text of the rows on THIS page; the other pages are not held here. Esc clears the search.'
  : "Cherche dans le texte AFFICHÉ des lignes de CETTE page ; les autres pages ne sont pas tenues ici. Échap efface la recherche.";
const MOT_RECHERCHE_LISTE_FILTRE_TOUT = LANG === 'en'
  ? 'row(s) — the search covers the whole list, held here in full; sorting and grouping stay as they are'
  : "ligne(s) — la recherche porte sur toute la liste, tenue ici en entier ; le tri et le regroupement restent posés";
const MOT_RECHERCHE_LISTE_FILTRE_FENETRE = LANG === 'en'
  ? 'row(s) among the SERVED lines — the search does not reach beyond that window; sorting and grouping stay as they are'
  : "ligne(s) parmi les lignes SERVIES — la recherche ne descend pas au-delà de cette fenêtre ; le tri et le regroupement restent posés";
const MOT_RECHERCHE_LISTE_FILTRE_PAGE = LANG === 'en'
  ? 'row(s) on the page displayed — the search does not reach the other pages; sorting stays as it is'
  : "ligne(s) de la page affichée — la recherche n'atteint pas les autres pages ; le tri reste posé";
const MOT_RECHERCHE_LISTE_RIEN_TOUT = LANG === 'en'
  ? 'No row displays these words — and the whole list is held here, so none carries them. Esc clears the search.'
  : "Aucune ligne n'affiche ces mots — et la liste est tenue ici en entier : aucune ne les porte. Échap efface la recherche.";
const MOT_RECHERCHE_LISTE_RIEN_FENETRE = LANG === 'en'
  ? 'No SERVED row displays these words — and the search does not reach beyond the served window, so a row may exist without being reachable from here. Esc clears the search.'
  : "Aucune ligne SERVIE n'affiche ces mots — et la recherche ne descend pas au-delà de la fenêtre servie : une ligne peut exister sans être atteignable depuis ici. Échap efface la recherche.";
const MOT_RECHERCHE_LISTE_RIEN_PAGE = LANG === 'en'
  ? 'No row on the page displayed carries these words — the other pages are not held here; turn the page to search them. Esc clears the search.'
  : "Aucune ligne de la page affichée ne porte ces mots — les autres pages ne sont pas tenues ici : changer de page pour y chercher. Échap efface la recherche.";
const AIDE_PAR_PORTEE = { tout: MOT_RECHERCHE_LISTE_AIDE_TOUT, fenetre: MOT_RECHERCHE_LISTE_AIDE_FENETRE, page: MOT_RECHERCHE_LISTE_AIDE_PAGE };
const FILTRE_PAR_PORTEE = { tout: MOT_RECHERCHE_LISTE_FILTRE_TOUT, fenetre: MOT_RECHERCHE_LISTE_FILTRE_FENETRE, page: MOT_RECHERCHE_LISTE_FILTRE_PAGE };
const RIEN_PAR_PORTEE = { tout: MOT_RECHERCHE_LISTE_RIEN_TOUT, fenetre: MOT_RECHERCHE_LISTE_RIEN_FENETRE, page: MOT_RECHERCHE_LISTE_RIEN_PAGE };

// ==================================================================================================
// `P11.18-z` — UNE RECHERCHE POSÉE SURVIT AU RECHARGEMENT DE LA VUE, ET CE QUE CONSERVER CACHE SE DIT
// --------------------------------------------------------------------------------------------------
// LE CONSTAT, MESURÉ le 2026-08-25. Le champ appartient à la LISTE, pas au gabarit : chaque geste
// éditorial recharge la vue, la vue reconstruit son hôte, et la recherche repart à zéro — l'exploitant
// qui travaillait sur une liste filtrée retrouve la liste entière après avoir déclaré un hôte, retiré
// une déclaration ou levé un silence.
//
// DEUX REMÈDES ONT ÉTÉ RÉFUTÉS PAR LA MESURE AVANT D'ÊTRE LIVRÉS, et ils ne sont pas rejoués ici.
//   (1) « QUE LA DISTINCTION VIENNE DU GESTE » — créer efface, modifier conserve. La seule trace du
//       geste dans le transport est le VERBE, et il ne porte pas cette distinction : beaucoup de `POST`
//       de la console ne créent rien (activer une règle, relancer une analyse, archiver un cas), et
//       jusqu'à des LECTURES ne sont des `POST` que pour porter un corps. Le chemin ne le porte pas
//       davantage. Dériver du verbe ferait retomber des vues du mauvais côté.
//   (2) « RELIRE LA VALEUR DANS LE CHAMP que le rendu s'apprête à jeter ». Le rechargement ne redessine
//       pas dans le même hôte : il vide son conteneur et FABRIQUE un élément neuf. Pire que l'échec,
//       cela aurait marché pour les listes dont l'hôte survit et pas pour les autres — deux vues
//       voisines, deux comportements, sans que rien ne l'explique.
//
// LA VOIE RETENUE DÉRIVE DU RÉSULTAT, PAS DE L'INTENTION. On conserve TOUJOURS, et l'on traite le seul
// cas où conserver nuit : une ligne apparue que la recherche masque. Ce cas se constate APRÈS COUP, sur
// les NOMBRES seuls (combien de lignes cette recherche cache-t-elle de plus qu'au dernier geste de
// l'exploitant sur elle ?), donc aucun appelant n'a à déclarer la nature de son geste et une vue future
// en hérite sans y penser. ET LE DIRE VAUT MIEUX QUE L'EFFACER : effacer la recherche détruit le travail
// de l'exploitant pour lui montrer une ligne, alors que la liste sait DÉJÀ déclarer qu'elle cache des
// lignes — il ne lui manquait que de dire qu'elle en cache DAVANTAGE, et le geste de tout revoir.
//
// CE QUE CET AVIS NE TIENT PAS, ET IL L'ÉCRIT LUI-MÊME. C'est une DIFFÉRENCE entre deux comptes : il ne
// nomme pas les lignes, et il ne distingue pas une ligne NEUVE d'une ligne qui a cessé de correspondre.
// Il n'est ARMÉ que là où le compte a un sens d'un rendu à l'autre : une liste qui tient ses lignes.
// En mode servi, `total` est la page SERVIE — tourner la page changerait le compte sans qu'aucune ligne
// n'apparaisse, et l'avis dirait un nombre faux. La recherche, elle, y est quand même conservée.
//
// L'IDENTITÉ SUIT LE MOTIF QUE LE DÉPÔT PORTE DÉJÀ : la clé de rangement d'une liste groupée
// (`opts.group.storeKey`). Une liste qui en déclare une l'hérite sans un mot ; une liste qui n'en
// déclare aucune n'a PAS de mémoire et se comporte exactement comme aujourd'hui.
// ==================================================================================================
const MOT_RECHERCHE_LISTE_AIDE_MEMOIRE = LANG === 'en'
  ? ' This search stays put when the view is redrawn; emptying it, or reloading the page, forgets it.'
  : " Cette recherche reste posée quand la vue est redessinée ; la vider, ou recharger la page, l'oublie.";
const MOT_RECHERCHE_LISTE_MASQUEES = LANG === 'en'
  ? ' more row(s) are hidden by this search than at the last keystroke on it — they exist, they are simply not displayed. This is a DIFFERENCE between two counts: it does not name the rows, and it does not say whether they are new or merely stopped matching.'
  : " ligne(s) de plus sont masquées par cette recherche que lors de la dernière frappe — elles existent, elles ne sont simplement pas affichées. C'est une DIFFÉRENCE entre deux comptes : elle ne nomme pas les lignes, et ne dit pas si elles sont neuves ou si elles ont cessé de correspondre.";
const MOT_RECHERCHE_LISTE_REVELER = LANG === 'en' ? 'Show every row' : 'Afficher toutes les lignes';
const MOT_RECHERCHE_LISTE_REVELER_AIDE = LANG === 'en'
  ? 'Empties the search: the whole list comes back, and this notice goes with it.'
  : "Vide la recherche : la liste entière revient, et cet avis avec elle.";

// L'IDENTITÉ D'UNE LISTE — la clé de rangement qu'elle porte déjà, jamais un second motif. Vide = pas
// d'identité = pas de mémoire ; c'est le défaut, et il est le comportement d'aujourd'hui. AUCUNE IDENTITÉ
// N'EST DEVINÉE, et c'est délibéré : la position d'un hôte dans son parent et le libellé d'une liste ont
// tous deux été écartés, parce qu'une section conditionnelle qui paraît ou disparaît les décale — deux
// listes voisines échangeraient alors leur recherche, ce qui est pire que pas de mémoire du tout. Deux
// listes qui déclarent la MÊME clé partagent donc la même mémoire : la clé doit être unique par liste,
// comme elle l'est déjà pour le pli.
function identiteDeLaListe(opts) {
  return String(opts.storeKey || (opts.group && opts.group.storeKey) || '').trim();
}

// L'avis, et le GESTE de le lever. `surReveler` vide la recherche : c'est le seul chemin proposé, et il
// est celui que l'exploitant aurait fait à la main.
function annonceDesLignesMasquees(dePlus, surReveler) {
  const el = document.createElement('div');
  el.className = 'muted recherche-annonce';
  const compte = document.createElement('b');
  compte.textContent = String(dePlus);
  el.append(compte, document.createTextNode(MOT_RECHERCHE_LISTE_MASQUEES), document.createTextNode(' '));
  const btn = document.createElement('button');
  btn.type = 'button'; btn.className = 'btn btn-sm';
  btn.textContent = MOT_RECHERCHE_LISTE_REVELER;
  btn.title = MOT_RECHERCHE_LISTE_REVELER_AIDE;
  btn.onclick = surReveler;
  el.appendChild(btn);
  return el;
}

// Ce que la fabrique sait de la portée sans qu'on le lui dise, et le seul mot qu'elle ne peut pas mesurer.
function porteeDeLaRecherche(opts) {
  if (opts.mode === 'server') return 'page';
  const conf = opts.recherche === true ? {} : (opts.recherche || {});
  return conf.fenetre ? 'fenetre' : 'tout';
}

// LA BARRE EST POSÉE UNE FOIS, HORS DE LA ZONE REPEINTE. Le champ appartient à la liste et non au
// document : la fabrique le construit, faute d'exister dans le gabarit — c'est ce que le lot précédent
// avait dû écrire à la main dans un panneau. S'il vivait DANS la zone que chaque frappe repeint, il
// serait détruit et reconstruit à chaque lettre, et le curseur partirait avec lui : le corps de la liste
// est donc un nœud à part, et c'est LUI que la peinture remplace.
function poserLaRechercheDeLaListe(host, opts) {
  const portee = porteeDeLaRecherche(opts);
  // `P11.18-z` — LA MÉMOIRE EST OPT-IN PAR L'IDENTITÉ, ET TOUT CE QUI SUIT RETOMBE À L'IDENTIQUE SANS
  // ELLE : pas de zone d'avis dans l'hôte, pas de phrase de plus au champ, pas d'écriture nulle part.
  const souvenir = souvenirDeRecherche(identiteDeLaListe(opts));
  const barre = document.createElement('div'); barre.className = 'hdtools';
  const champ = document.createElement('input');
  champ.type = 'search';
  champ.placeholder = MOT_RECHERCHE_LISTE_INVITE;
  champ.title = AIDE_PAR_PORTEE[portee] + (souvenir ? MOT_RECHERCHE_LISTE_AIDE_MEMOIRE : '');
  champ.setAttribute('aria-label', MOT_RECHERCHE_LISTE_ETIQUETTE);
  // LA VALEUR EST POSÉE AVANT LE CÂBLAGE : `champDeRecherche` lit le champ, il n'a rien à apprendre de
  // plus, et aucun rappel ne part pour une frappe qui n'a pas eu lieu.
  const reference = souvenir ? souvenir.lire() : null;
  if (reference && reference.requete) champ.value = reference.requete;
  barre.appendChild(champ);
  const zoneAnnonce = souvenir ? document.createElement('div') : null;
  const zoneResume = document.createElement('div');
  const corps = document.createElement('div');
  host.replaceChildren(...(zoneAnnonce ? [barre, zoneAnnonce, zoneResume, corps] : [barre, zoneResume, corps]));
  let surChangement = () => {};
  // LE GESTE DE L'EXPLOITANT SUR CETTE INSTANCE, ET RIEN D'AUTRE. Tant qu'il n'a pas frappé, ce que la
  // liste montre vient d'un souvenir : c'est le seul moment où l'avis a un sens, et le seul où la
  // référence ne doit PAS bouger — sans quoi elle rattraperait le compte et l'avis disparaîtrait tout
  // seul au rechargement suivant, en emportant ce que personne n'a encore vu.
  let gesteFait = false;
  const poignee = champDeRecherche(champ, { auChangement: () => { gesteFait = true; surChangement(); } });
  // L'avis n'est armé que là où le compte a le MÊME sens d'un rendu à l'autre (voir l'en-tête) : une
  // page servie n'est pas un ensemble stable, et un nombre qui varie avec la page mentirait.
  const annonceArmee = opts.mode !== 'server';
  return {
    corps,
    valeur: poignee.valeur,
    auChangement: f => { surChangement = f; },
    // Recherche vide -> le MÊME tableau, par identité : rien ne s'interpose entre les lignes reçues et
    // ce que la fabrique en fait tant qu'aucune lettre n'est frappée.
    filtrer: (lignes, texteDeLaLigne) => {
      const q = poignee.valeur();
      return q ? filtrerParRecherche(lignes, q, texteDeLaLigne) : lignes;
    },
    // Une liste qui cache des lignes le DIT, et elle dit CE QU'ELLE COUVRE. Sans recherche posée : rien.
    // `P11.18-z` — C'EST AUSSI LE SEUL ENDROIT OÙ LES DEUX NOMBRES SONT CONNUS, donc c'est ici que la
    // mémoire se tient à jour et que l'écart se lit. Aucun appelant n'a à le savoir.
    resumer: (affichees, total) => {
      zoneResume.replaceChildren();
      const q = poignee.valeur();
      if (souvenir) {
        const masquees = Math.max(0, (Number(total) || 0) - (Number(affichees) || 0));
        if (gesteFait) { souvenir.noter(q, masquees); zoneAnnonce.replaceChildren(); }
        else {
          const dePlus = (annonceArmee && reference && q && q === reference.requete) ? masquees - reference.masquees : 0;
          if (dePlus > 0) zoneAnnonce.replaceChildren(annonceDesLignesMasquees(dePlus, () => poignee.vider()));
          else zoneAnnonce.replaceChildren();
        }
      }
      if (!q) return;
      zoneResume.appendChild(resumeDeRecherche(affichees, total, {
        filtre: document.createTextNode(FILTRE_PAR_PORTEE[portee]),
        vide: document.createTextNode(RIEN_PAR_PORTEE[portee]),
      }));
    },
  };
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
// `opts.storeKey` (facultatif) = L'IDENTITÉ DE CETTE LISTE, stable d'un rendu à l'autre — la même clé
// de rangement que le regroupement emploie déjà (`opts.group.storeKey`, qui vaut identité à lui seul).
// Cette identité, et elle seule, arme la mémoire de recherche de `P11.18-z` : sans elle, la liste n'a
// aucune mémoire et se comporte exactement comme avant cette clé.
function pagedList(host, opts) {
  const pageSize = opts.pageSize || 50;
  const state = { page: 0, pageSize, total: 0, shown: 0 };
  const columns = opts.columns || null;
  // `P11.18-m` — SANS L'OPTION, `cible` EST `host` : la peinture, la liste groupée et le message d'erreur
  // écrivent exactement où ils écrivaient, et rien n'est interposé.
  const chercheur = opts.recherche ? poserLaRechercheDeLaListe(host, opts) : null;
  const cible = chercheur ? chercheur.corps : host;
  // Le texte AFFICHÉ d'une ligne, retenu pour la durée de CETTE liste (le souvenir est propre à
  // l'instance : deux listes peuvent afficher les mêmes objets sous des colonnes différentes).
  const texteRetenu = new WeakMap();
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
  // LE TEXTE CHERCHABLE D'UNE LIGNE — DÉRIVÉ DE CE QUI EST AFFICHÉ, jamais d'une liste de champs écrite
  // quelque part. Colonnes déclarées -> le texte de chaque cellule RENDUE ; ligne rendue à la main -> le
  // texte du nœud rendu ; `texteDeLaLigne` l'emporte sur les deux. Un rendu qui échoue ne fait pas tomber
  // la recherche : il ne contribue rien, et la ligne reste cherchable par ses autres cellules.
  function texteAffiche(row) {
    if (row == null || typeof row !== 'object') return String(row == null ? '' : row);
    const memo = texteRetenu.get(row);
    if (memo !== undefined) return memo;
    const conf = opts.recherche === true ? {} : (opts.recherche || {});
    let texte = '';
    if (conf.texteDeLaLigne) { try { texte = String(conf.texteDeLaLigne(row) || ''); } catch (e) { texte = ''; } }
    else if (columns && !opts.renderRow) {
      texte = texteCherchable(columns.map(c => {
        try { const v = c.render ? c.render(row) : row[c.key]; return v instanceof Node ? v.textContent : v; }
        catch (e) { return ''; }
      }));
    } else if (opts.renderRow) {
      try { const n = opts.renderRow(row); texte = n && n.textContent != null ? String(n.textContent) : ''; } catch (e) { texte = ''; }
    }
    texteRetenu.set(row, texte);
    return texte;
  }
  const lignesRetenues = lignes => (chercheur ? chercheur.filtrer(lignes || [], texteAffiche) : lignes);
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
    cible.replaceChildren();
    // UNE RECHERCHE POSÉE PARLE À LA PLACE DU VIDE DE LA LISTE (`P11.18-m`). « aucune donnée » à côté d'une
    // recherche qui ne trouve rien est un second message, et il est FAUX : la liste porte des lignes, c'est
    // la recherche qui les cache. La phrase du résumé, elle, dit ce qui a été cherché ET jusqu'où. Sans
    // l'option, `chercheur` est nul et le message d'origine est rendu exactement comme avant.
    if (!rows.length && !state.total) { if (!chercheur || !chercheur.valeur()) cible.appendChild(muted(opts.emptyText || 'aucune donnée')); return; }
    const go = p => { state.page = p; reload(); };
    const top = makePager(state, go); if (top) cible.appendChild(top);
    cible.appendChild(bodyNode(rows));
    const bot = makePager(state, go); if (bot) cible.appendChild(bot);
    programmerLaMesureDesCellules(cible);   // `P11.15-a` : la fabrique pose le geste de lecture elle-même
  }
  function sliceClient() {
    const source = lignesRetenues(clientRows);
    let rows = source.slice();
    if (sort) {
      const col = columns ? columns.find(c => c.key === sort.key) : null;
      const get = col && col.sortVal ? col.sortVal : (r => r[sort.key]);
      const cmp = colComparator(rows, get);
      rows.sort((a, b) => cmp(a, b) * sort.dir);
    }
    state.total = source.length;
    const start = state.page * state.pageSize;
    const page = rows.slice(start, start + state.pageSize);
    state.shown = page.length;
    paint(page);
  }
  async function loadServer() {
    let r;
    try { r = await opts.fetchPage({ limit: state.pageSize, offset: state.page * state.pageSize, sort: sort ? sort.key : '', dir: sort ? (sort.dir > 0 ? 'asc' : 'desc') : '' }); }
    catch (e) { cible.replaceChildren(muted('erreur : ' + (e && e.message ? e.message : e))); return; }
    const rows = (r && r.rows) || [];
    state.total = (r && typeof r.total === 'number') ? r.total : rows.length;
    // LE PAGINATEUR DIT LA PAGE, LA RECHERCHE DIT CE QU'ELLE MONTRE DEDANS. `shown` reste le nombre de
    // lignes SERVIES : c'est lui qui borne « 1–50 » et qui arme le bouton suivant, et le faire varier avec
    // la recherche ferait mentir le paginateur sur la page où l'on se trouve.
    state.shown = rows.length;
    const retenues = lignesRetenues(rows);
    if (chercheur) chercheur.resumer(retenues.length, rows.length);
    paint(retenues);
  }
  function reload() { if (opts.mode === 'server') loadServer(); else sliceClient(); }
  // `P11.15-b` — LE REGROUPEMENT EST UNE OPTION DE CETTE FABRIQUE, PAS UNE VUE À PART. Il n'a de sens
  // que sur un ensemble COMPLET : le mode serveur ne tient qu'une page et ne peut pas partitionner ce
  // qu'il n'a pas, donc il rend plat. Et il ne s'applique que si les LIGNES portent une dimension connue :
  // sans quoi la liste plate d'aujourd'hui est rendue telle quelle, rien n'est caché.
  // `P11.18-m` — ET LA RECHERCHE SE COMPOSE AVEC LUI AU LIEU DE LE DÉFAIRE : la partition est refaite sur
  // les lignes TROUVÉES, un groupe sans correspondance disparaît, et le compte de chaque en-tête est celui
  // des lignes retenues. Les lignes sont toutes en mémoire et l'en-tête ANNONCE son compte : un groupe
  // replié qui affiche « 3 » ne cache pas ses correspondances, il les résume.
  function peindreUnePasse() {
    if (opts.group && opts.mode !== 'server' && clientRows) {
      const groupe = peindreEnGroupes(cible, lignesRetenues(clientRows), opts);
      if (groupe) return groupe;
    }
    reload();
    return null;
  }
  if (!chercheur) {
    const groupe = peindreUnePasse();
    if (groupe) return groupe;
    return { reload, state };
  }
  // Avec l'option, la poignée rendue est STABLE d'une frappe à l'autre : elle est rendue une fois, alors
  // que la passe, elle, est refaite à chaque lettre.
  const repeindre = () => {
    if (clientRows) chercheur.resumer(lignesRetenues(clientRows).length, clientRows.length);
    peindreUnePasse();
  };
  chercheur.auChangement(() => { state.page = 0; repeindre(); });   // une recherche neuve se lit depuis sa première page
  repeindre();
  return { reload: repeindre, state };
}

// ==================================================================================================
// `P11.18-s` — CHOISIR UNE PLAGE DE TEMPS : UN SEUL GESTE, QUATRE CONSOMMATEURS.
//
// LE CONSTAT, MESURÉ le 2026-08-25 — cinquième occurrence du même motif (le geste existe, il n'est pas
// là où on le cherche). Un contrôle de plage offrant DÉJÀ paliers ET intervalle absolu vivait dans
// `web/app.js`, avec ses deux refus écrits et ses règles de style posées (`.rangemodal`, `.rmgrid`,
// `.rmabs`). Il n'était pas exporté, et il écrivait directement dans `S.zoomRange`. Faute de pouvoir
// l'atteindre, le journal d'audit et la prévention des fuites en ont reçu un SECOND, dans
// `web/audit.js` : deux lecteurs de saisie, deux jeux de refus, deux écrivains — le défaut sous une
// autre forme.
//
// CE QUI EST PARTAGÉ ICI, ET CE QUI NE L'EST PAS.
//   * PARTAGÉ : le LECTEUR d'une saisie (`lireUnePlage`, PURE — deux textes et un instant contre une
//     plage ou un refus), les cinq familles de REFUS qu'il rend, la question « la borne haute choisie
//     couvre-t-elle maintenant ? », l'ÉCRITURE sur la cible, et le reflet des contrôles posés.
//   * NON PARTAGÉ, et c'est mesuré, pas concédé : les PALIERS. Ceux des tableaux de bord vont de
//     5 min à 1 an, ceux du journal sont 7/30/90/365 jours, ceux de la prévention des fuites
//     24 h/7 j/tout. Trois jeux pour trois questions : les fondre inventerait un raccourci qu'aucune
//     vue n'a demandé. Ils restent donc chez leur consommateur et arrivent PAR LA CIBLE, puisque
//     choisir un palier écrit sur la même cible que choisir une plage — et la retire.
//
// LES DEUX PARAMÈTRES SONT EXACTEMENT LES DEUX FAITS QUI DISTINGUENT LES QUATRE CONSOMMATEURS.
//   (a) LA CIBLE — l'état où la plage se pose, et le GRAIN qu'il sait tenir. `S.zoomRange` tient un
//       intervalle d'INSTANTS en secondes : son champ est `datetime-local`. La plage du journal et de
//       la prévention des fuites tient des JOURS du calendrier — parce que la route du journal ne
//       borne qu'en jours entiers depuis maintenant — : son champ est `date`, et la fin INCLUT son
//       jour. LA PRÉSENTATION SUIT LA CIBLE et n'est pas un troisième réglage : la cible d'instants
//       est déjà servie par un BOUTON d'en-tête (`#rangepick`, `#qrangepick`), donc une modale ; la
//       cible de jours vit DANS le panneau, à côté du sélecteur de paliers de la vue, donc une barre.
//   (b) CE QUE LA ROUTE DE L'APPELANT SAIT PORTER — une borne HAUTE, ou pas. `POST /api/query` la
//       porte ; `GET /api/ledger` ne prend qu'un NOMBRE DE JOURS depuis maintenant et n'en porte
//       aucune. Quand elle manque, une plage dont la FIN est antérieure à maintenant est REFUSÉE, et
//       le refus nomme la raison de l'APPELANT — écrite là où elle est vraie, jamais ici.
//
// CE QUE CE PARTAGE NE FAIT PAS, écrit plutôt que tu : il ne fond pas les deux PRÉSENTATIONS en une.
// Elles existent toutes deux, sont toutes deux déjà stylées, et chacune est celle que sa vue offre
// déjà. Ce qui a fondu, c'est ce qui était réellement écrit deux fois : lire, refuser, écrire.
// ==================================================================================================

// Un jour du calendrier, tel qu'un champ `type=date` le rend (« AAAA-MM-JJ »), en secondes epoch à
// l'heure LOCALE de l'analyste : il choisit un jour de SON calendrier, pas un instant UTC.
// `finDeJournee` -> la DERNIÈRE seconde du jour choisi (la fin d'un jour INCLUT ce jour).
// `null` = illisible. Un jour inexistant (2026-02-31) est REPORTÉ par `Date` sur le mois suivant : on
// le refuse au lieu de laisser cette correction silencieuse passer pour un choix.
function jourEnSecondes(texte, finDeJournee) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(texte == null ? '' : texte).trim());
  if (!m) return null;
  const a = Number(m[1]), mo = Number(m[2]), j = Number(m[3]);
  const d = new Date(a, mo - 1, j, 0, 0, 0, 0);
  if (d.getFullYear() !== a || d.getMonth() !== mo - 1 || d.getDate() !== j) return null;
  if (!finDeJournee) return Math.floor(d.getTime() / 1000);
  d.setDate(d.getDate() + 1);
  return Math.floor(d.getTime() / 1000) - 1;
}

// Un INSTANT, tel qu'un champ `type=datetime-local` le rend (« AAAA-MM-JJThh:mm »), en secondes epoch
// à l'heure LOCALE. Même contrat que `jourEnSecondes` — `null` = illisible — pour que le lecteur
// n'ait qu'une seule forme de réponse à traiter, quel que soit le grain. Le report silencieux d'une
// date inexistante est refusé ici aussi, et pour la même raison.
function instantEnSecondes(texte) {
  const m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?$/.exec(String(texte == null ? '' : texte).trim());
  if (!m) return null;
  const a = Number(m[1]), mo = Number(m[2]), j = Number(m[3]), h = Number(m[4]), mi = Number(m[5]);
  const d = new Date(a, mo - 1, j, h, mi, Number(m[6] || 0), 0);
  if (d.getFullYear() !== a || d.getMonth() !== mo - 1 || d.getDate() !== j || d.getHours() !== h || d.getMinutes() !== mi) return null;
  return Math.floor(d.getTime() / 1000);
}

// LE GRAIN D'UNE CIBLE — ce que l'état où la plage se pose sait TENIR, et rien d'autre. Tout ce qui
// diffère entre un choix de JOURS et un choix d'INSTANTS est ici, dérivé de cette seule question :
// le type du champ, la lecture des deux bornes, la forme attendue nommée dans un refus, et les mots
// des deux champs de la barre. Le grain `minute` n'a aujourd'hui aucun consommateur EN BARRE (sa
// vue l'offre en modale) ; ses mots sont écrits pour qu'une barre posée demain sur une cible
// d'instants ne rende pas un libellé vide.
const GRAINS = {
  jour: {
    typeDeChamp: 'date',
    lireDebut: t => jourEnSecondes(t, false),
    lireFin: t => jourEnSecondes(t, true),
    motDebut: LANG === 'en' ? 'From (day)' : 'Du (jour)',
    motFin: LANG === 'en' ? 'To (day)' : 'Au (jour)',
    motAttendu: LANG === 'en' ? '. A calendar day is expected, written YYYY-MM-DD. Nothing was sent.' : ". Un jour du calendrier est attendu, écrit AAAA-MM-JJ. Rien n'a été envoyé.",
  },
  minute: {
    typeDeChamp: 'datetime-local',
    lireDebut: instantEnSecondes,
    lireFin: instantEnSecondes,
    motDebut: LANG === 'en' ? 'From (instant)' : "Du (instant)",
    motFin: LANG === 'en' ? 'To (instant)' : "Au (instant)",
    motAttendu: LANG === 'en' ? '. An instant is expected, written YYYY-MM-DD hh:mm. Nothing was sent.' : ". Un instant est attendu, écrit AAAA-MM-JJ hh:mm. Rien n'a été envoyé.",
  },
};

// LE SEUL LECTEUR d'une plage choisie — fonction PURE (deux textes + un instant + un grain -> une
// plage OU un refus), ce qui la rend éprouvable sans document ni réseau. Elle ne CORRIGE jamais :
// chaque saisie qu'elle ne sait pas lire produit un REFUS qui dit POURQUOI, et aucune fenêtre ne
// part. Rendre une plage « la plus proche » d'une saisie fautive serait répondre à une question que
// personne n'a posée.
function lireUnePlage(texteDebut, texteFin, maintenant, grain) {
  const g = GRAINS[grain] || GRAINS.jour;
  const td = String(texteDebut == null ? '' : texteDebut).trim();
  const tf = String(texteFin == null ? '' : texteFin).trim();
  if (!td || !tf) {
    return { refus: (LANG === 'en' ? 'A range needs TWO dates — a start and an end. Missing: ' : 'Une plage demande DEUX dates — un début et une fin. Manque : ')
      + (!td ? (LANG === 'en' ? 'the start' : 'le début') : '') + (!td && !tf ? (LANG === 'en' ? ' and ' : ' et ') : '')
      + (!tf ? (LANG === 'en' ? 'the end' : 'la fin') : '') + '.' };
  }
  const debut = g.lireDebut(td), fin = g.lireFin(tf);
  if (debut == null || fin == null) {
    return { refus: (LANG === 'en' ? 'Unreadable date: ' : 'Date illisible : ')
      + (debut == null ? td : tf) + g.motAttendu };
  }
  if (debut > fin) {
    return { refus: (LANG === 'en' ? 'Reversed range: the start (' : 'Plage inversée : le début (') + td
      + (LANG === 'en' ? ') is AFTER the end (' : ') est APRÈS la fin (') + tf
      + (LANG === 'en' ? '). The two dates are kept as typed and nothing was sent — swapping them here would answer a question nobody asked.' : "). Les deux dates restent telles qu'elles ont été saisies et rien n'a été envoyé — les échanger ici répondrait à une question que personne n'a posée.") };
  }
  // DURÉE NULLE — atteignable au seul grain des instants : au grain du jour, la fin est la dernière
  // seconde de son jour, donc deux jours égaux font une fenêtre d'un jour entier. Une fenêtre sans
  // durée ne peut être que vide, et un vide se lit comme une absence : c'est la même raison que
  // celle du début dans le futur, et le refus le dit de la même façon.
  if (debut === fin) {
    return { refus: (LANG === 'en' ? 'Range with no duration: the start and the end are the SAME instant (' : 'Plage sans durée : le début et la fin sont le MÊME instant (') + td
      + (LANG === 'en' ? '). Such a window can only be empty — and an empty window reads as an absence. Nothing was sent.' : "). Une telle fenêtre ne peut être que vide — et une fenêtre vide se lit comme une absence. Rien n'a été envoyé.") };
  }
  if (debut > maintenant) {
    return { refus: (LANG === 'en' ? 'Start date in the future: ' : 'Date de début dans le futur : ') + td
      + (LANG === 'en' ? '. Nothing has been recorded after now, so this range can only be empty — and an empty window reads as an absence. Nothing was sent.' : ". Rien n'est enregistré après maintenant, donc cette plage ne peut être que vide — et une fenêtre vide se lit comme une absence. Rien n'a été envoyé.") };
  }
  return { debut, fin, texteDebut: td, texteFin: tf };
}

// La borne HAUTE choisie couvre-t-elle l'instant présent ? C'est la SEULE question qui décide si une
// plage est exprimable par une route qui ne borne qu'en bas. Une fin posée au jour courant la
// couvre : au grain du jour, la fin est la DERNIÈRE seconde du jour choisi.
function borneHauteCouvreMaintenant(plage, maintenant) { return plage.fin >= maintenant; }

// LES CONTRÔLES POSÉS, par clé de vue — une vue repeinte REMPLACE le sien (aucune accumulation). Ils
// servent à REFLÉTER la plage de LEUR cible : un changement fait dans une autre vue posée sur la
// MÊME cible ne doit pas laisser des dates affichées que la fenêtre envoyée n'a plus.
const controlesDePlage = new Map();

// LE SEUL ÉCRIVAIN de la plage d'une cible. Écrire ailleurs laisserait un contrôle afficher autre
// chose que ce qui part au démon. Les contrôles posés sur CETTE cible se remettent au reflet ; ceux
// d'une autre cible ne bougent pas — deux cibles sont deux fenêtres, pas une.
function poserLaPlageSurLaCible(cible, plage) {
  cible.poser(plage);
  const p = cible.lire();
  controlesDePlage.forEach(c => {
    if (c.cible !== cible) return;
    c.debut.value = p ? p.texteDebut : '';
    c.fin.value = p ? p.texteFin : '';
  });
}

// LE CONTRÔLE EN BARRE : deux champs, un bouton qui APPLIQUE, un bouton qui RETIRE, et UNE ligne qui
// porte le refus. Rien ne part tant qu'une saisie est refusée, et la plage précédente reste intacte
// — un refus ne modifie pas la fenêtre, il explique pourquoi elle n'a pas bougé.
// `cle` : la vue qui pose (une seule inscription par vue). `cible` : où la plage se pose (a).
// `porte.borneHaute` : ce que la route de l'appelant sait porter (b) ; `porte.refus(plage)` : la
// phrase, propre à la vue appelante, qui dit pourquoi SON chemin ne porte pas de borne haute —
// écrite là où elle est vraie, pas ici. `surChangement` n'est rappelé QUE lorsque la plage a
// effectivement changé.
function poserLeChoixDeDates(cle, cible, porte, surChangement) {
  const g = GRAINS[cible.grain] || GRAINS.jour;
  const barre = document.createElement('div');
  barre.className = 'rmabs';
  barre.setAttribute('role', 'group');
  barre.setAttribute('aria-label', LANG === 'en' ? 'Exact dates (start and end)' : 'Dates exactes (début et fin)');
  const champ = texte => {
    const l = document.createElement('label');
    const i = document.createElement('input');
    i.type = g.typeDeChamp;
    l.append(texte, i);
    barre.appendChild(l);
    return i;
  };
  const debut = champ(g.motDebut);
  const fin = champ(g.motFin);
  const appliquer = document.createElement('button');
  appliquer.type = 'button';
  appliquer.className = 'btn btn-sm';
  appliquer.textContent = LANG === 'en' ? 'Apply these dates' : 'Appliquer ces dates';
  const retirer = document.createElement('button');
  retirer.type = 'button';
  retirer.className = 'linklike';
  retirer.textContent = LANG === 'en' ? 'Back to the shortcut' : 'Revenir au raccourci';
  // La ligne de refus occupe toute la largeur de la barre : une phrase qui explique un refus ne se lit
  // pas coincée entre deux champs. `hidden` tant qu'il n'y a rien à dire — jamais un vide qui se
  // confondrait avec un espace réservé.
  const refus = document.createElement('div');
  refus.className = 'bad';
  refus.setAttribute('role', 'alert');
  refus.style.cssText = 'flex-basis:100%;margin:4px 0 0';
  refus.hidden = true;
  const direLeRefus = texte => { refus.textContent = texte; refus.hidden = !texte; };
  // Retoucher une date EFFACE le refus : il porte sur ce qui était saisi, pas sur ce qui l'est.
  debut.addEventListener('input', () => direLeRefus(''));
  fin.addEventListener('input', () => direLeRefus(''));
  appliquer.addEventListener('click', () => {
    const maintenant = Math.floor(Date.now() / 1000);
    const lue = lireUnePlage(debut.value, fin.value, maintenant, cible.grain);
    if (lue.refus) { direLeRefus(lue.refus); return; }
    if (!porte.borneHaute && !borneHauteCouvreMaintenant(lue, maintenant)) { direLeRefus(porte.refus(lue)); return; }
    direLeRefus('');
    poserLaPlageSurLaCible(cible, lue);
    surChangement();
  });
  retirer.addEventListener('click', () => {
    debut.value = ''; fin.value = ''; direLeRefus('');
    if (cible.lire()) { poserLaPlageSurLaCible(cible, null); surChangement(); }
  });
  barre.append(appliquer, retirer, refus);
  const controle = { barre, debut, fin, appliquer, retirer, refus, direLeRefus, cible };
  controlesDePlage.set(cle, controle);
  const posee = cible.lire();
  debut.value = posee ? posee.texteDebut : '';
  fin.value = posee ? posee.texteFin : '';
  return controle;
}

// LE CONTRÔLE EN MODALE : les paliers de la cible (raccourcis relatifs) ET l'intervalle absolu, dans
// la même fenêtre — les deux répondent à la même question, et choisir l'un retire l'autre. Le
// gabarit est celui qui vivait dans `web/app.js`, inchangé ; ce qui change est ce qu'il APPELLE :
// le lecteur partagé et l'écrivain de la cible, au lieu de son propre couple.
function ouvrirLaModaleDePlage(cible, porte, surChangement) {
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal rangemodal';
  const plage = cible.lire();
  const cur = cible.palier ? cible.palier() : 0;
  const toLocal = d => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  const now = new Date();
  const f0 = plage ? new Date(plage.debut * 1000) : new Date(now.getTime() - 3600000);
  const t0 = plage ? new Date(plage.fin * 1000) : now;
  box.innerHTML = `
    <h3>Plage temporelle</h3>
    <div class="rmsub">Relatif — depuis maintenant (suit l'heure courante)</div>
    <div class="rmgrid">${(cible.paliers || []).map(([s, l]) => `<button type="button" class="rmp${!plage && s === cur ? ' on' : ''}" data-s="${s}">${l}</button>`).join('')}</div>
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
    cible.poserLePalier(b.dataset.s);   // relatif -> retire la plage + recharge (le geste est celui de la vue)
    surChangement(); close();
  });
  box.querySelector('#rm-abs').onclick = () => {
    const err = box.querySelector('.modal-err');
    const maintenant = Math.floor(Date.now() / 1000);
    // LE MÊME LECTEUR QUE LA BARRE, ET LES MÊMES REFUS. Ce chemin n'en avait que deux (« Dates
    // invalides. », « Le début doit précéder la fin. ») et laissait passer en silence les trois
    // autres familles — début dans le futur, durée nulle, borne haute que la route ne porte pas.
    const lue = lireUnePlage(box.querySelector('#rm-from').value, box.querySelector('#rm-to').value, maintenant, cible.grain);
    if (lue.refus) { err.textContent = lue.refus; err.hidden = false; return; }
    if (!porte.borneHaute && !borneHauteCouvreMaintenant(lue, maintenant)) { err.textContent = porte.refus(lue); err.hidden = false; return; }
    err.hidden = true;
    poserLaPlageSurLaCible(cible, lue); surChangement(); close();
  };
  return { ov, box, close };
}

// ==================================================================================================
// `P11.15-b` / `P11.17-c` — REGROUPER SANS CONSTRUIRE : LA CLÉ VIENT DES LIGNES, LE COÛT SUIT LE PLI
// --------------------------------------------------------------------------------------------------
// CE QUI EXISTAIT, ET OÙ. Le mécanisme demandé n'était pas à inventer : deux panneaux le tenaient déjà à
// la main dans `detection_admin.js` — les règles partitionnées par gravité, les parseurs par source —
// chacun avec sa boucle, sa `Map`, sa clé de pliage et son libellé. La file des actions et celle des
// playbooks, elles, rendaient UN groupe unique contenant toute la liste. Trois écritures d'une même idée,
// et la quatrième vue rendait plat faute d'avoir été écrite.
//
// LA CLÉ EST DÉRIVÉE DE CE QUE LA LIGNE PORTE, JAMAIS DE LA VUE QUI L'AFFICHE. Une dimension déclare
// COMMENT SE LIT sa valeur sur une ligne ; elle s'applique dès qu'au moins une ligne la porte, et les
// dimensions applicables sont offertes dans un ORDRE UNIQUE. Cet ordre seul reproduit ce que les deux
// panneaux écrivaient : une règle porte `severity` donc elle se groupe par gravité, un parseur porte
// `source` donc par source, une action ne porte ni l'une ni l'autre mais nomme la règle qui l'a produite
// donc par règle. Aucun nom de vue n'apparaît ici, et la vue posée demain hérite du même arbitrage.
//
// CE QUE CE MÉCANISME ÉVITE DE CONSTRUIRE, ET C'EST LÀ QU'EST L'ÉCHELLE. Replier après avoir construit ne
// résout rien : la feuille masquait un corps déjà payé. Ici le corps d'un groupe est bâti au PREMIER dépli
// (`collapsibleGroup`), et la liste des groupes est elle-même paginée par cette fabrique — sinon
// l'explosion remonterait d'un étage dès qu'il y a mille clés distinctes. Sur N lignes réparties en G
// groupes, l'arbre construit passe de N lignes à `min(G, pageSize)` en-têtes, plus les lignes de la seule
// page des seuls groupes ouverts. La partition, elle, se fait sur les OBJETS déjà en mémoire — une passe,
// aucun nœud.
//
// LE TOTAL SE RECOMPOSE (`P11.16-b`). Chaque ligne tombe dans un groupe et un seul, y compris celle qui ne
// porte pas la dimension : elle n'est pas écartée, elle rejoint un groupe NOMMÉ (« sans règle ») compté
// comme les autres et rendu en dernier. La somme des comptes d'en-tête vaut donc le total annoncé, et le
// résumé le dit au lieu de laisser le lecteur le vérifier.
// ==================================================================================================

// Les mots du regroupement, écrits dans les DEUX langues à l'endroit du rendu : ils se recollent autour de
// nombres et de noms de données, donc aucun nœud texte rendu ne serait jamais égal à une clé du lexique.
const MOT_GROUPER_PAR = LANG === 'en' ? 'Group by' : 'Grouper par';
const MOT_LIGNES_EN = LANG === 'en' ? ' row(s) in ' : ' ligne(s) en ';
const MOT_GROUPES_PAR = LANG === 'en' ? ' group(s) by ' : ' groupe(s) par ';
const MOT_SOMME_DES_GROUPES = LANG === 'en' ? ' — the group counts add up to that total' : ' — les comptes des groupes s’additionnent à ce total';
const MOT_SANS = LANG === 'en' ? 'no ' : 'sans ';

// LA RÈGLE QUI A PRODUIT UNE LIGNE, LUE SUR LA LIGNE — et non le nom de la ligne elle-même : une règle
// s'appelle `name`, ce champ-là n'est PAS lu ici, sans quoi chaque règle formerait son propre groupe.
// Trois champs possibles, dans l'ordre où les charges de ce produit servent le nom d'une automatisation.
// À défaut, le producteur ÉCRIT dans la raison : la file des actions ne porte aucun identifiant de règle
// (`daemon/src/handlers/actions.rs` sert id/ts/kind/target/status/dry_run/reason/result/done_ts/host), et
// le moteur de réponse inscrit son producteur dans la raison sous la forme `famille:nom`
// (`daemon/src/handlers/playbooks.rs`). Une raison SAISIE par l'exploitant n'est pas un producteur : le
// préfixe doit être une famille de contenu du produit, sinon la ligne ne porte pas la dimension et rejoint
// le groupe « sans règle », compté et nommé plutôt que fondu dans les autres.
const FAMILLES_PRODUCTRICES = ['playbook', 'rule', 'runbook'];
function nomDeLaRegleProductrice(r) {
  if (!r) return '';
  const direct = r.rule_name || r.rule || r.playbook;
  if (direct) return String(direct);
  const raison = r.reason == null ? '' : String(r.reason);
  const i = raison.indexOf(':');
  if (i <= 0) return '';
  const famille = raison.slice(0, i).trim().toLowerCase(), nom = raison.slice(i + 1).trim();
  return (nom && FAMILLES_PRODUCTRICES.indexOf(famille) >= 0) ? nom : '';
}

// LES DIMENSIONS, DANS L'ORDRE OÙ ELLES SONT OFFERTES. Chacune : `lire(ligne)` rend la clé du groupe ou ''
// quand la ligne ne porte pas la dimension ; `libelle(clé)` rend l'en-tête ; `ordre` classe les clés ;
// `pastille` rend le point de couleur de l'en-tête. Ce sont les axes que le produit groupe DÉJÀ quelque
// part — gravité et source dans l'administration de la détection, règle / hôte / technique dans la file
// des alertes, que le démon agrège par les mêmes trois axes. Rien n'est inventé ici, tout est remonté.
const DIMENSIONS_DE_REGROUPEMENT = [
  {
    cle: 'severity',
    nom: LANG === 'en' ? 'severity' : 'gravité',
    lire: r => (r && r.severity != null && r.severity !== '' ? String(Number(r.severity) || 0) : ''),
    libelle: k => sev(Number(k)),
    ordre: (a, b) => Number(b) - Number(a),
    pastille: k => '<span class="fdot" style="background:' + (SEVCOL[Number(k)] || 'var(--mut)') + '"></span>',
  },
  {
    cle: 'regle',
    nom: LANG === 'en' ? 'rule' : 'règle',
    lire: nomDeLaRegleProductrice,
    libelle: k => k,
  },
  {
    // L'ÉTAT VIENT APRÈS LA RÈGLE, ET C'EST DÉLIBÉRÉ. Grouper par règle reclasse la file : le tri « en
    // attente d'abord » ne vaut plus qu'À L'INTÉRIEUR d'un groupe, plus en travers du panneau. C'est le
    // prix demandé, et il est rendu réversible ici plutôt que discuté ailleurs — l'axe qui rend la file
    // par état existe, il se choisit, et il n'a coûté qu'une entrée de ce registre.
    cle: 'statut',
    nom: LANG === 'en' ? 'status' : 'état',
    lire: r => (r && r.status ? String(r.status) : ''),
    libelle: k => k,
  },
  {
    cle: 'source',
    nom: LANG === 'en' ? 'source' : 'source',
    lire: r => (r && r.source ? String(r.source) : ''),
    libelle: k => k,
  },
  {
    cle: 'host',
    nom: LANG === 'en' ? 'host' : 'hôte',
    lire: r => (r && r.host ? String(r.host) : ''),
    libelle: k => k,
  },
  {
    cle: 'mitre',
    nom: LANG === 'en' ? 'ATT&CK technique' : 'technique ATT&CK',
    lire: r => (r && r.mitre ? String(r.mitre) : ''),
    libelle: k => (mitreName(k) ? k + ' — ' + mitreName(k) : k),
  },
];

// Les dimensions que CES lignes portent. Mesure, jamais déclaration : une dimension qu'aucune ligne ne
// porte n'est pas offerte, et la lecture s'arrête à la première ligne qui la porte.
function dimensionsApplicables(rows) {
  if (!rows || !rows.length) return [];
  return DIMENSIONS_DE_REGROUPEMENT.filter(d => rows.some(r => d.lire(r) !== ''));
}

// L'en-tête d'un groupe. La clé vide n'est pas un groupe anonyme : elle est NOMMÉE par la dimension qui
// manque, pour qu'un lecteur sache ce qu'il regarde au lieu de le déduire.
function libelleDuGroupe(dim, cle) { return cle === '' ? MOT_SANS + dim.nom : dim.libelle(cle); }

// La partition, faite sur les OBJETS : une passe, aucun nœud construit. Le groupe « sans … » ferme la
// marche — il existe toujours quand il n'est pas vide, jamais quand il l'est.
function grouperLesLignes(rows, dim) {
  const par = new Map();
  rows.forEach(r => {
    const k = dim.lire(r), c = k == null ? '' : String(k);
    if (!par.has(c)) par.set(c, []);
    par.get(c).push(r);
  });
  const ordre = dim.ordre || ((a, b) => String(a).localeCompare(String(b)));
  return [...par.keys()]
    .sort((a, b) => (a === '' ? 1 : b === '' ? -1 : ordre(a, b)))
    .map(c => ({ cle: c, lignes: par.get(c) }));
}

// LE RÉSUMÉ, ET LE CHOIX DE L'AXE. Le sélecteur n'apparaît que si les lignes portent PLUSIEURS dimensions :
// offrir un choix unique serait un contrôle qui ne choisit rien. Le résumé dit le total, le nombre de
// groupes, l'axe courant, et que les comptes d'en-tête s'additionnent à ce total (`P11.16-b`).
function barreDeRegroupement(dims, dim, nLignes, nGroupes, onChoisir) {
  const bar = document.createElement('div'); bar.className = 'flegend';
  if (dims.length > 1) {
    const sel = document.createElement('select'); sel.className = 'picon'; sel.title = MOT_GROUPER_PAR;
    dims.forEach(d => {
      const o = document.createElement('option'); o.value = d.cle; o.textContent = d.nom;
      if (d.cle === dim.cle) { o.selected = true; sel.value = d.cle; }
      sel.appendChild(o);
    });
    sel.onchange = () => onChoisir(sel.value);
    bar.appendChild(sel);
  }
  const resume = document.createElement('span'); resume.className = 'muted';
  resume.textContent = nLignes + MOT_LIGNES_EN + nGroupes + MOT_GROUPES_PAR + dim.nom + MOT_SOMME_DES_GROUPES;
  bar.appendChild(resume);
  return bar;
}

// Le corps d'UN groupe : la même fabrique, sans regroupement (pas de récursion possible) et sur les seules
// lignes de ce groupe. Il n'est appelé qu'au premier dépli.
function hoteDesLignesDUnGroupe(lignes, opts) {
  const h = document.createElement('div');
  pagedList(h, {
    mode: 'client', pageSize: opts.pageSize || 50, rows: lignes,
    columns: opts.columns, renderRow: opts.renderRow, sort: opts.sort,
    onRowClick: opts.onRowClick, emptyText: opts.emptyText,
  });
  return h;
}

// Rend la liste groupée dans `host`, ou `null` si aucune dimension ne s'applique (l'appelant retombe alors
// sur la liste plate — rien n'est caché, rien n'est deviné).
function peindreEnGroupes(host, rows, opts) {
  const dims = dimensionsApplicables(rows);
  if (!dims.length) return null;
  // `P11.18-z` — UNE SEULE IDENTITÉ PAR LISTE, LUE PAR UN SEUL GESTE : le pli et la recherche ne
  // peuvent plus se ranger sous deux clés différentes. Pour les appelants d'aujourd'hui, qui ne
  // déclarent que `group.storeKey`, la valeur lue est exactement celle d'avant.
  const storeKey = identiteDeLaListe(opts);
  const cleDuChoix = storeKey ? storeKey + ':dim' : '';
  const dimensionChoisie = () => {
    let c = '';
    try { c = cleDuChoix ? (localStorage.getItem(cleDuChoix) || '') : ''; } catch (e) { c = ''; }
    return dims.find(d => d.cle === c) || dims[0];
  };
  let interne = null;
  function peindre() {
    const dim = dimensionChoisie();
    const groupes = grouperLesLignes(rows, dim);
    const plie = lsSet(storeKey);
    host.replaceChildren();
    host.appendChild(barreDeRegroupement(dims, dim, rows.length, groupes.length, k => {
      try { if (cleDuChoix) localStorage.setItem(cleDuChoix, k); } catch (e) {}
      peindre();
    }));
    // UN ENSEMBLE QUI NE TIENT PAS DANS UNE PAGE ARRIVE REPLIÉ. Le seuil n'est pas un nombre choisi : c'est
    // LA PAGE, le seul budget que cette fabrique connaisse déjà. En deçà, la liste se lit d'un coup comme
    // avant ; au-delà, ce sont les GROUPES qu'on lit — chacun annonce combien de lignes il contient — et
    // l'on ouvre celui dont on a besoin. Sans ce défaut, grouper COÛTERAIT plus cher que ne pas grouper :
    // une page de lignes par groupe ouvert, au lieu d'une page pour toute la liste. Même parti que la file
    // d'alertes groupée, dont les occurrences ne sont chargées qu'au premier dépli.
    const pageSizeGroupes = opts.pageSize || 50;
    const defautPlie = rows.length > pageSizeGroupes;
    const hoteDesGroupes = document.createElement('div');
    interne = pagedList(hoteDesGroupes, {
      mode: 'client', pageSize: pageSizeGroupes, rows: groupes,
      renderRow: g => collapsibleGroup(plie, storeKey, dim.cle + ':' + g.cle,
        libelleDuGroupe(dim, g.cle), g.lignes.length,
        () => [hoteDesLignesDUnGroupe(g.lignes, opts)],
        dim.pastille ? dim.pastille(g.cle) : '', defautPlie),
    });
    host.appendChild(hoteDesGroupes);
  }
  peindre();
  return { reload: peindre, state: (interne && interne.state) || { page: 0, pageSize: opts.pageSize || 50, total: rows.length, shown: rows.length } };
}

// ==================================================================================================
// `P11.15-a` — UNE LIGNE TROP LONGUE SE LIT EN ENTIER, ET LE GESTE VIENT DE LA FABRIQUE
// --------------------------------------------------------------------------------------------------
// LE DÉFAUT, ET POURQUOI IL EST REVENU. La feuille plafonne `.qtable td` à une largeur, masque le
// débordement et pose des points de suspension ; elle annonçait à côté « valeur complète au survol
// (title) + au clic (détail) ». MESURÉ le 2026-08-25 dans web/ : la fabrique de tableau ne posait
// AUCUN `title`, et le clic d'une ligne, là où il mène quelque part, mène AILLEURS (drilldown,
// ouverture d'un détail) — un chemin de fichier, un message d'audit ou une requête étaient donc
// coupés sans recours. Le même défaut avait déjà été fermé sur UN panneau (`P11.4-g`) : le remède y
// était local, celui-ci ne l'est pas.
//
// LA PROPRIÉTÉ EST MESURÉE, JAMAIS ÉNUMÉRÉE. Aucune liste de colonnes, de vues ni de panneaux : une
// cellule reçoit le geste quand SON CONTENU EST PLUS LARGE QUE SA PLACE (`scrollWidth` > `clientWidth`).
// La colonne posée demain est jugée par la même mesure, sans qu'on y pense.
//
// LE GESTE EST LE DÉPLI PARTAGÉ, PAS UN GESTE DE PLUS. `disclosure` est celui des cases et des groupes :
// un bouton qui DIT son état (`aria-expanded`), atteignable au clavier, et dont l'icône bascule — la
// marque ne tient donc pas à la seule couleur. Le dépli se fait SUR PLACE : la cellule garde sa largeur
// et s'enroule, la ligne grandit en hauteur. Le clic du bouton est ARRÊTÉ là : une ligne de tableau
// porte souvent son propre clic, et lire une valeur ne doit pas faire changer de vue.
//
// POURQUOI PAS UN OBSERVATEUR DE MUTATIONS SUR LE CORPS DU DOCUMENT. Ce serait le geste évident, et il
// est exclu : la liaison des modules ne doit poser AUCUN observateur sur le corps du document — le seul
// admis est celui du lexique, posé par l'amorçage sous `LANG='en'`, et le harnais ESM l'épingle. Le
// geste s'accroche donc à ce qui existe déjà : la peinture de la liste paginée partagée, et UN capteur
// en phase de capture qui mesure la table que l'on survole ou dans laquelle on entre au clavier. Les
// tableaux `.qtable` construits hors de la fabrique (résultats de recherche, aperçu de connecteur) sont
// ainsi couverts sans qu'une ligne leur soit écrite.
//
// `P11.18-b` — LA PLACE RÉSERVÉE NE BORNAIT QUE CE QUE LA CELLULE METTAIT EN LIGNE ELLE-MÊME
// --------------------------------------------------------------------------------------------------
// LE RELEVÉ, ET LA DIFFÉRENCE QU'IL DÉSIGNE. Le chevron recouvrait le texte qu'il sert à révéler, mais
// pas partout : dans le journal d'audit il était bien placé. Un seul mécanisme, deux rendus — la
// différence tient à CE QUE LA CELLULE CONTIENT, et elle se mesure. Relevé le 2026-08-25, à l'encre
// réellement peinte (deux captures d'un navigateur réel, texte peint contre texte transparent) : dans une
// cellule dont le contenu est INLINE — le journal d'audit n'en construit pas d'autres — l'encre s'arrête
// 5 px AVANT le bord de la boîte de contenu et 11 px avant le chevron, soit 0 px sous le chevron ; dans
// une cellule qui porte une SOUS-LIGNE de niveau bloc — l'inventaire des sources, la flotte — l'encre va
// 23 px AU-DELÀ de ce même bord, jusqu'à la coupe, dont 17 px SOUS le chevron (≈ 2,4 caractères).
//
// POURQUOI. La place réservée est un REMBOURRAGE de la cellule, et `text-overflow` ne s'hérite pas : la
// coupe à trois points ne borne QUE les lignes que la cellule met en page elle-même. Un enfant de niveau
// bloc est un autre conteneur — sa valeur par défaut y est `clip`, sa ligne n'est donc pas raccourcie, et
// `overflow:hidden` ne la coupe qu'à la boîte de REMBOURRAGE, c'est-à-dire à l'autre bout de la place
// réservée. Ce contenu-là traversait donc la réservation et passait sous le bouton. RÉFUTÉ au passage :
// la réservation n'était pas de la mauvaise taille — la supprimer ne change rien à la cellule inline
// (l'encre reste au même pixel), et l'élargir n'aurait pas déplacé d'un pixel une ligne qu'elle ne borne
// pas. Ce n'est pas non plus un décalage du bouton qu'il fallait : le défaut est que la cellule PEIGNAIT
// là où le bouton est posé.
//
// LE REMÈDE EST UNE BOÎTE, ET IL VAUT POUR TOUTES LES CELLULES. La valeur reçoit sa propre boîte
// (`CELL_VALEUR`), qui occupe la boîte de contenu et coupe ce qui dépasse : tout ce qu'une vue met dans
// une cellule — inline, bloc, imbriqué, posé demain — est mis en page et coupé DANS cette boîte, donc
// s'arrête où la place du bouton commence. Le bouton est alors posé À CÔTÉ de la valeur et non par-dessus,
// et la propriété ne dépend plus de ce que la cellule contient. Ce qui a été écarté : borner les enfants
// depuis la cellule (`td.plcut > *`) atteindrait des éléments qu'on ne vise pas — c'est `P11.4-m` — et
// laisserait dehors les boîtes anonymes, qu'aucun sélecteur ne nomme ; rétrécir la coupe de la cellule
// (`overflow-clip-margin`, une bordure large) emporterait le bouton avec, puisqu'il est posé DANS la
// bande — la seule borne qui coupe la valeur sans couper le contrôle est une boîte qui ne contient que
// la valeur.
// ==================================================================================================
const CELL_COUPEE = 'plcut', CELL_DEPLIEE = 'plopen', CELL_VALEUR = 'plval';

// « plus large que sa place » — la seule question posée à une cellule. Sur un arbre sans mise en page
// (aucune largeur mesurable), la réponse est NON : le geste ne se pose jamais au hasard.
function celluleDeborde(td) {
  const contenu = td.scrollWidth, place = td.clientWidth;
  return Number.isFinite(contenu) && Number.isFinite(place) && contenu > place + 1;
}

function boutonDeDepli(td) {
  const enfants = td.childNodes ? Array.from(td.childNodes) : [];
  return enfants.find(n => n && String(n.tagName || '').toLowerCase() === 'button'
    && n.classList && n.classList.contains('plmore')) || null;
}

// La BOÎTE DE VALEUR d'une cellule marquée, ou rien. Même lecture que pour le bouton — par la classe et
// non par un rang : une vue peut poser ce qu'elle veut dans la cellule, l'ordre ne fait foi nulle part.
function boiteDeValeur(td) {
  const enfants = td && td.childNodes ? Array.from(td.childNodes) : [];
  return enfants.find(n => n && n.classList && n.classList.contains(CELL_VALEUR)) || null;
}

function poserLeDepliDeCellule(td) {
  if (td.classList.contains(CELL_COUPEE)) return false;
  const entier = td.textContent == null ? '' : String(td.textContent);   // AVANT d'ajouter le bouton
  td.classList.add(CELL_COUPEE);
  // Recours immédiat, sans aucun geste : la valeur entière au survol. Une infobulle déjà écrite par la
  // vue (elle en sait plus que la fabrique) n'est jamais remplacée.
  if (entier && !td.getAttribute('title')) td.title = entier;
  // `P11.18-b` — LA VALEUR PASSE DANS SA PROPRE BOÎTE, ET C'EST ELLE QUI S'ARRÊTE OÙ LE BOUTON COMMENCE.
  // La place réservée par la feuille ne borne que ce que la CELLULE met en ligne elle-même ; ce qu'un
  // enfant de niveau BLOC met en ligne lui échappe (voir l'en-tête de section). La boîte rend la borne
  // commune : tout le contenu, quel qu'il soit, est mis en page et coupé dans une boîte qui finit AVANT
  // la place du bouton. Elle est posée AVANT le bouton, qui reste le dernier enfant de la cellule.
  const boite = document.createElement('span');
  boite.className = CELL_VALEUR;
  while (td.firstChild) boite.appendChild(td.firstChild);
  td.appendChild(boite);
  const btn = document.createElement('button');
  btn.type = 'button'; btn.className = 'plmore';
  btn.title = 'Plier / déplier';
  btn.innerHTML = ic('chevdown');
  disclosure(btn, td, {
    observe: false,
    isOpen: () => td.classList.contains(CELL_DEPLIEE),
    open: () => td.classList.add(CELL_DEPLIEE),
    close: () => td.classList.remove(CELL_DEPLIEE),
  });
  btn.addEventListener('click', e => { if (e && e.stopPropagation) e.stopPropagation(); });
  td.appendChild(btn);
  return true;
}

// Rend la cellule TELLE QU'ELLE ÉTAIT : le bouton part, et la boîte de valeur est dépliée sur place —
// les nœuds que la vue a construits reviennent à leur rang, elle n'en perd aucun.
function retirerLeDepliDeCellule(td) {
  td.classList.remove(CELL_COUPEE);
  const b = boutonDeDepli(td); if (b && b.remove) b.remove();
  const boite = boiteDeValeur(td);
  if (boite) { while (boite.firstChild) td.insertBefore(boite.firstChild, boite); boite.remove(); }
}

// Les cellules à mesurer sous `racine` : celles des tableaux habillés `.qtable`, d'où qu'ils viennent.
// SONT HORS MESURE, et c'est dérivé et non listé : un tableau qui a DÉJÀ dé-plafonné ses cellules
// (`.onecol`, la ligne longue s'y lit par défilement) et la ligne de détail d'un drilldown (`.rowdetail`,
// elle s'enroule déjà). `racine` peut être la table elle-même, l'hôte d'une liste paginée, ou le document.
function cellulesAMesurer(racine) {
  if (!racine || typeof racine.querySelectorAll !== 'function') return [];
  const cl = racine.classList;
  const estTable = String(racine.tagName || '').toLowerCase() === 'table' && cl && cl.contains('qtable');
  if (estTable && cl.contains('onecol')) return [];
  const sel = estTable ? 'tbody > tr:not(.rowdetail) > td'
    : 'table.qtable:not(.onecol) > tbody > tr:not(.rowdetail) > td';
  try { return Array.from(racine.querySelectorAll(sel)); } catch (e) { return []; }
}

// Une cellule d'ACTIONS ne porte pas une valeur à lire, elle porte des gestes à faire : y poser un
// bouton de dépli mettrait un contrôle de plus au milieu des autres, et l'infobulle rendrait la suite
// des libellés de boutons collés. La distinction est DÉRIVÉE de ce que la cellule contient — un
// contrôle —, jamais du nom d'une colonne ; le bouton de dépli lui-même ne compte pas.
const CONTROLES = ['button', 'a', 'input', 'select', 'textarea'];
function cellulePorteUnControle(td) {
  const enfants = td && td.childNodes ? Array.from(td.childNodes) : [];
  return enfants.some(n => {
    if (!n || !n.tagName) return false;
    if (n.classList && n.classList.contains('plmore')) return false;
    return CONTROLES.includes(String(n.tagName).toLowerCase()) || cellulePorteUnControle(n);
  });
}

// Pose (ou retire) le geste sur les cellules de `racine`. Rend le NOMBRE de cellules nouvellement
// équipées — c'est ce compte qui rend la mesure vérifiable au lieu d'être crue sur parole.
function marquerLesCellulesTronquees(racine) {
  let posees = 0;
  for (const td of cellulesAMesurer(racine)) {
    if (!td || !td.classList) continue;
    if (td.classList.contains(CELL_DEPLIEE)) continue;   // déplié : la mesure ne dit plus rien de lui
    if (cellulePorteUnControle(td)) continue;
    const marquee = td.classList.contains(CELL_COUPEE);
    // UNE CELLULE MARQUÉE SE MESURE PAR SA BOÎTE DE VALEUR, pas par elle-même : la boîte coupe ce qui
    // dépasse, donc la cellule ne déborde plus, et la mesurer ELLE ferait retirer le geste à la première
    // re-mesure (survol, focus, redimensionnement) — le recours disparaîtrait dès qu'on s'en approche.
    const mesuree = marquee ? (boiteDeValeur(td) || td) : td;
    if (celluleDeborde(mesuree)) { if (!marquee && poserLeDepliDeCellule(td)) posees++; }
    else if (marquee) retirerLeDepliDeCellule(td);       // la fenêtre s'est élargie : plus rien à déplier
  }
  return posees;
}

// Mesurer force un calcul de mise en page : on le fait une fois par image, sur les racines demandées.
let mesuresEnAttente = null;
function programmerLaMesureDesCellules(racine) {
  const cible = racine || (typeof document !== 'undefined' ? document : null);
  if (!cible) return;
  if (mesuresEnAttente) { mesuresEnAttente.add(cible); return; }
  mesuresEnAttente = new Set([cible]);
  const differer = typeof requestAnimationFrame === 'function' ? requestAnimationFrame : (f => setTimeout(f, 0));
  differer(() => {
    const lot = mesuresEnAttente; mesuresEnAttente = null;
    lot.forEach(r => { try { marquerLesCellulesTronquees(r); } catch (e) {} });
  });
}

// La table `.qtable` qui porte `el`, ou rien. Remonte la chaîne des parents (aucune dépendance à
// `closest`, absent des arbres fabriqués — même raison qu'au capteur de refus d'écriture).
function tableTronquableSous(el) {
  for (let n = el, i = 0; n && i < 16; n = n.parentNode, i++) {
    if (String(n.tagName || '').toLowerCase() === 'table' && n.classList && n.classList.contains('qtable')) return n;
  }
  return null;
}

try {
  const surUneTable = e => { const t = e && e.target ? tableTronquableSous(e.target) : null; if (t) programmerLaMesureDesCellules(t); };
  if (typeof document !== 'undefined' && document.addEventListener) {
    document.addEventListener('pointerover', surUneTable, true);
    document.addEventListener('focusin', surUneTable, true);
  }
  // Une fenêtre qui s'élargit peut RENDRE lisible ce qui était coupé ; celle qui se resserre coupe ce
  // qui ne l'était pas. La mesure suit, sinon le geste mentirait dans les deux sens.
  if (typeof window !== 'undefined' && window.addEventListener) {
    window.addEventListener('resize', () => programmerLaMesureDesCellules(document));
  }
} catch (e) { /* environnement sans document (harnais, service worker) : rien à câbler */ }

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
  if (role === 'viewer') cablerLeRefusDEcriture();
}

// --- P11.4-l : UN GESTE D'ÉCRITURE REFUSÉ AU LECTEUR RESTE, INERTE, AVEC SA RAISON -------------
// La feuille EFFAÇAIT `crud-btn` pour un lecteur (`display:none`) pendant que l'interrupteur voisin de la
// MÊME ligne restait visible, inerte et motivé : deux grammaires opposées à un centimètre l'une de l'autre.
// Ce que la mesure a tranché : la garde qui LIE est SERVEUR (un viewer ne satisfait ni l'écriture éditoriale
// ni l'administration — toute mutation lui rend 403), l'effacement ne protégeait donc rien ; il ôtait
// seulement au lecteur la connaissance que le geste existe et que c'est SON rôle qui le borne.
// POURQUOI `aria-disabled` ET NON `disabled` : un contrôle désactivé ne reçoit plus le survol ni le focus —
// son infobulle ne s'afficherait jamais, et la raison serait écrite sans pouvoir être lue. L'inertie vient
// donc d'ailleurs : UN capteur unique, en phase de CAPTURE, qui précède tout gestionnaire posé par un module
// et survit à un bouton réactivé après coup. Il DIT la raison au lieu de laisser un geste sans effet.
// La raison est posée par le CODE ; une feuille de style ne sait pas écrire un motif.

// Le contrôle d'écriture qui porte `el`, ou `el` lui-même — l'icône d'un bouton est la cible du clic, pas
// le bouton. Remonte la chaîne des parents (aucune dépendance à `closest`, absent des arbres fabriqués).
function controleDEcritureSous(el) {
  for (let n = el; n; n = n.parentNode) if (n.classList && n.classList.contains('crud-btn')) return n;
  return null;
}
// Pose le refus SUR le contrôle : marque accessible + raison ajoutée à l'infobulle déjà écrite (celle du
// contenu livré, quand elle existe, n'est pas remplacée). Idempotent. Rend false si rien n'était à poser.
function motiverLeRefusAuLecteur(btn) {
  if (!btn || !btn.classList || !btn.classList.contains('crud-btn') || socRole() !== 'viewer') return false;
  if (btn.dataset.refusLecteur) return true;
  btn.dataset.refusLecteur = '1';
  btn.setAttribute('aria-disabled', 'true');
  btn.title = (btn.title ? btn.title + ' · ' : '') + 'rôle lecteur : ce geste demande le rôle éditeur (le serveur le refuse aussi)';
  return true;
}
// --- P11.4-m : LE GESTE MIXTE — effet LOCAL permis, PERSISTANCE refusee -----------------------
// Plier une tuile, changer la visualisation d'un panneau : l'effet a l'ecran est un geste de LECTURE, que
// rien ne refuse a un lecteur. Mais la console PERSISTE cet etat, et la persistance est une mutation
// editoriale que le demon borne a l'editeur — le lecteur recevait donc un 403 dont personne ne lisait la
// reponse, a chaque pli. Poser `crud-btn` sur ces controles couperait le geste PERMIS ; les laisser
// emettre fait partir une requete qu'on sait refusee. La console ne l'ENVOIE donc pas : la vue locale
// suit, le serveur n'est pas sollicite pour rien, et le refus reste celui du demon.
// MEME VOCABULAIRE que le refus d'ecriture ci-dessus (`socRole`), pour qu'il n'y en ait pas deux.
function roleSansEcriturePartagee() { return socRole() === 'viewer'; }
let refusDEcritureCable = false;
function cablerLeRefusDEcriture() {
  if (refusDEcritureCable || !document.addEventListener) return;
  refusDEcritureCable = true;
  document.addEventListener('click', ev => {
    if (socRole() !== 'viewer') return;
    const btn = controleDEcritureSous(ev && ev.target);
    if (!btn) return;
    ev.preventDefault(); ev.stopPropagation();
    motiverLeRefusAuLecteur(btn);
    toast(btn.title, 'bad', 4200);
  }, true);
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
  let j;
  try { j = await apiSend(path, 'POST', body); }
  catch (e) { const m = (e && e.message) || 'échec'; formMsg(resSel, m, true); toast(m, 'bad'); return false; }
  // P11.5-c : une modification ACCEPTÉE peut quand même ne pas SURVIVRE — un contenu d'overlay config.d est
  // réimposé par son fichier au prochain démarrage. Le serveur le DIT (`avertissement`) ; le taire ici
  // rendrait un succès qui se défait tout seul, ce qui se lit « l'administrateur ne peut pas éditer ».
  if (j && j.avertissement) toast(j.avertissement, 'info');
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

// ==================================================================================================
// `P11.18-l` — LE PLI SE MÉMORISE ABSOLUMENT ; UN GESTE NE SE RETOURNE PAS PARCE QU'UN SEUIL A BOUGÉ
// --------------------------------------------------------------------------------------------------
// LE DÉFAUT, MESURÉ le 2026-08-25, ET IL PRÉEXISTE À LA RECHERCHE QUI L'A RÉVÉLÉ. Le jeu persisté ne
// disait pas « replié » mais « ÉCART au défaut », et le défaut d'une liste groupée est DÉRIVÉ : elle
// dépasse la taille d'une page, ou non. Les deux se lisent ensemble, donc quand le défaut bouge —
// la liste passant sous le seuil — le même jeu se lit à l'envers : un groupe explicitement OUVERT
// revient REPLIÉ, et ceux qu'on n'a jamais touchés s'ouvrent. Relevé sur un banc à répartiteur
// d'événements réel : un groupe ouvert par clic rendait `fgroup` / `aria-expanded="true"`, et le
// rendu suivant, sous le seuil et sans qu'aucun geste ne soit fait, `fgroup collapsed` /
// `aria-expanded="false"` — le magasin, lui, n'avait pas changé.
//
// CE QUI EST MÉMORISÉ MAINTENANT : L'ÉTAT, PAS L'ÉCART. Le magasin porte une TABLE `{clé: replié}` où
// la valeur est ce que l'exploitant a laissé, vrai ou faux. Le défaut ne s'applique plus qu'à une clé
// ABSENTE de la table — c'est-à-dire jamais touchée. Un seuil qui bouge ne peut donc plus rien
// retourner : il ne décide que du sort des clés dont personne n'a rien dit.
//
// LA MIGRATION, ET POURQUOI ELLE NE RETOURNE AUCUN GESTE. Des plis sont déjà mémorisés sous l'ancienne
// écriture (un TABLEAU de clés en écart). Ils ne sont ni jetés ni devinés : à la PREMIÈRE lecture, chaque
// clé du tableau devient l'état que l'ancien mécanisme AURAIT RENDU à cet instant, c'est-à-dire
// `!defautPlie`. Le premier rendu après migration est donc, groupe par groupe, exactement celui d'avant —
// une migration qui changerait ce que l'exploitant voit au moment où elle a lieu retournerait elle-même
// un geste. Ce qu'elle ne peut PAS faire, et qui est écrit plutôt que tu : retrouver l'intention d'un
// geste que l'ancienne écriture avait déjà perdue. Si le seuil a bougé entre le geste et cette lecture,
// l'état affiché est DÉJÀ l'inverse de l'intention ; la migration le fige tel quel — elle ne l'inverse pas
// une seconde fois, et à partir de là il ne bougera plus. La forme du magasin distingue les deux
// écritures sans qu'aucun drapeau ne soit gardé : un tableau est l'ancienne, une table est la nouvelle.
//
// UNE LECTURE PAR PEINTURE, PAS UNE PAR GROUPE. La table est mémoïsée SUR LE JEU que l'appelant passe :
// `peindreEnGroupes` en construit un par peinture et le partage entre ses groupes, donc la lecture du
// magasin garde exactement la cadence d'avant, et deux groupes de la même peinture voient les écritures
// l'un de l'autre. Un jeu neuf (peinture suivante, autre onglet) relit le magasin.
// ==================================================================================================
const PLIS_PAR_JEU = new WeakMap();
function persisterLesPlis(storeKey, plis) {
  const table = {};
  plis.forEach((replie, cle) => { table[cle] = !!replie; });
  try { localStorage.setItem(storeKey, JSON.stringify(table)); } catch (e) {}
}
function plisMemorises(set, storeKey, defautPlie) {
  const jeu = set && typeof set === 'object' ? set : null;
  if (jeu && PLIS_PAR_JEU.has(jeu)) return PLIS_PAR_JEU.get(jeu);
  const plis = new Map();
  let brut = null;
  try { brut = localStorage.getItem(storeKey); } catch (e) { brut = null; }
  if (typeof brut === 'string' && brut.trim().charAt(0) === '{') {
    let table = null;
    try { table = JSON.parse(brut); } catch (e) { table = null; }
    if (table && typeof table === 'object') Object.keys(table).forEach(k => plis.set(k, !!table[k]));
  } else if (jeu && typeof jeu.forEach === 'function' && jeu.size) {
    jeu.forEach(k => plis.set(String(k), !defautPlie));   // l'état que l'ancienne écriture rendait À CET INSTANT
    persisterLesPlis(storeKey, plis);
  }
  if (jeu) { try { PLIS_PAR_JEU.set(jeu, plis); } catch (e) {} }
  return plis;
}
// groupe repliable RÉUTILISABLE (même chrome que renderFreshness : .fgroup/.fgrouphd/.fgbody).
// `set` = Set d'état plié (chargé via lsSet), `storeKey` = clé localStorage où le persister, `key` = clé
// du groupe dans le Set. `nodes` = lignes DOM du corps. `dotHtml` (optionnel) = pastille de tête.
// `defautPlie` (défaut : déplié) — l'état d'un groupe que PERSONNE n'a encore touché, et RIEN D'AUTRE
// (`P11.18-l`) : le magasin retient l'état LAISSÉ, pas un écart à ce défaut, de sorte qu'un défaut qui
// bouge ne retourne aucun geste. `set` reste le contrat des appelants : c'est la lecture ANCIENNE du
// magasin, et elle ne sert plus qu'à la migration décrite au-dessus de `plisMemorises`.
function collapsibleGroup(set, storeKey, key, label, count, nodes, dotHtml, defautPlie) {
  const plis = plisMemorises(set, storeKey, defautPlie);
  const collapsed = plis.has(key) ? plis.get(key) : !!defautPlie;
  const wrap = document.createElement('div'); wrap.className = 'fgroup' + (collapsed ? ' collapsed' : '');
  const hd = document.createElement('button'); hd.type = 'button'; hd.className = 'fgrouphd';
  hd.title = 'Plier / déplier ' + label;
  hd.innerHTML = ic('chevdown') + (dotHtml || '') + `<span class="fglbl">${esc(label)}</span><span class="fgcount">${count}</span>`;
  const body = document.createElement('div'); body.className = 'fgbody';
  // `P11.15-b` — LE CORPS N'EST BÂTI QUE S'IL EST VU. `nodes` accepte désormais une FONCTION, appelée au
  // PREMIER dépli et une seule fois. Un groupe replié ne coûtait pas moins cher qu'un groupe ouvert : la
  // feuille masque son corps (`.fgroup.collapsed .fgbody{display:none}`) mais le corps était déjà construit,
  // donc replier allégeait l'écran sans rien retirer du travail. Un tableau reste accepté — les appelants
  // dont le corps est déjà bâti gardent exactement le comportement d'avant.
  let bati = false;
  const batir = () => {
    if (bati) return; bati = true;
    const ns = typeof nodes === 'function' ? (nodes() || []) : (nodes || []);
    ns.forEach(n => body.appendChild(n));
  };
  const memoriserLePli = plie => { plis.set(key, !!plie); persisterLesPlis(storeKey, plis); };
  // `P11.15-b` — UN SEUL DÉPLI DANS LA CONSOLE. Ce groupe écrivait son `aria-expanded`, son clic et sa
  // bascule à côté de `disclosure`, qui est déjà le dépli des panneaux et des cellules trop longues : deux
  // mécanismes de pliage pour un même geste, dans le même fichier. L'état, la marque accessible et la
  // bascule viennent maintenant de lui ; `.collapsed` sur l'enveloppe reste le seul vocabulaire que la
  // feuille connaîsse, et le chevron continue de basculer par elle.
  // `observe: false` : l'état est porté par l'ENVELOPPE et non par le panneau (rien à observer sur lui), et
  // une liste repeinte à chaque chargement ajouterait sinon un observateur par groupe — la raison même
  // pour laquelle cette option existe.
  disclosure(hd, body, {
    observe: false,
    isOpen: () => !wrap.classList.contains('collapsed'),
    open: () => { wrap.classList.remove('collapsed'); batir(); memoriserLePli(false); },
    close: () => { wrap.classList.add('collapsed'); memoriserLePli(true); },
  });
  if (!collapsed) batir();
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
// `observe: false` retire cette surveillance, et l'appelant reprend la charge de repeindre par la poignée
// rendue (`paint`). Réservé au cas où le MÊME panneau est piloté par un grand nombre de boutons REMPLACÉS
// à chaque page rendue (la liste des cas, `P11.11-a`) : un nœud observé retient ses observateurs, donc
// chaque page ajouterait autant de rappels au panneau, et chaque rappel retiendrait sa ligne morte.
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
  if (opts.observe !== false) { try { new MutationObserver(paint).observe(panel, { attributes: true, attributeFilter: ['hidden', 'class'] }); } catch (e) {} }
  paint();
  return { open: () => { show(); paint(); }, close: () => { hide(); paint(); }, toggle: btn.onclick, isOpen, paint };
}

// MITRE ATT&CK — LES SEULS LIBELLÉS QUE LA CONSOLE CONNAISSE SANS LE DÉMON, ET CE N'EST PAS LE CATALOGUE.
// P11.6-c. Le catalogue vit d'un seul côté : `daemon/src/attack_names.rs`, 183 techniques parentes et
// 16 sous-techniques nommées. Cette table-ci n'en est ni une copie ni un résumé fidèle — c'est un
// sous-ensemble, et il faut dire lequel plutôt que laisser croire à un repli.
//
// QUI LA LIT, ET POURQUOI ELLE SURVIT. La matrice de couverture ne la lit plus : sa route sert le nom avec
// l'identifiant. Restent la file d'alertes et l'administration des règles, dont les routes servent `mitre`
// NU — aucun nom n'y voyage. Là, cette table n'est pas un repli : c'est la source, la seule.
//
// CE QU'ELLE NE COUVRE PAS, DIT PLUTÔT QUE PASSÉ SOUS SILENCE. Les identifiants qu'elle ignore rendent leur NUMÉRO SEUL,
// sans libellé — et les appelants n'écrivent rien à la place d'un nom absent. MESURÉ le 2026-08-24 sur les
// règles LIVRÉES avec le produit : elles citent 19 techniques, cette table en nomme 14, donc 5 arrivent à
// l'exploitant en numéro nu (dont `T1562`, alors même que sa sous-technique `T1562.001` est nommée ici —
// l'incohérence qu'une liste tenue à la main finit par produire). Le remède est une route DÉDIÉE et bon
// marché servant le catalogue : la seule route qui porte aujourd'hui des noms est une AGRÉGATION sur la
// table des alertes qui prend un permis de requête, et l'appeler pour un dictionnaire serait payer un scan
// pour un libellé. Cette route n'existe pas ; le résidu reste porté par `P11.6-c`.
//
// CE QUI EST TENU. Aucune valeur d'ici n'est écrite à la main : le harnais ESM DÉRIVE de
// `daemon/src/attack_names.rs` le nom que le démon émettrait pour chaque clé listée, et REFUSE la moindre
// différence, dans les deux sens — un libellé qui s'écarte, une clé que le catalogue ne connaît pas. La
// table ne peut donc plus vieillir en silence : elle peut être INCOMPLÈTE, jamais FAUSSE.
// Repli sous-technique : strip .NNN -> parent (le nom du parent, moins précis que celui du démon).
const MITRE_NAMES = { T1046: "Network Service Discovery", T1071: "Application Layer Protocol", T1110: "Brute Force", T1190: "Exploit Public-Facing Application", T1204: "User Execution", T1490: "Inhibit System Recovery", T1498: "Network Denial of Service", T1543: "Create or Modify System Process", T1552: "Unsecured Credentials", T1554: "Compromise Host Software Binary", "T1562.001": "Impair Defenses: Disable or Modify Tools", T1565: "Data Manipulation", T1595: "Active Scanning", "T1595.002": "Active Scanning: Vulnerability Scanning" };
function mitreName(id) { return MITRE_NAMES[id] || MITRE_NAMES[(id || "").split(".")[0]] || ""; }

// âge humain : secondes -> « N s / N min / N h / N j » (borné, compact ; utilisé par fleet/sources/risk/…).
const humanAge = s => { s = Number(s) || 0; return s < 90 ? s + ' s' : s < 5400 ? Math.round(s / 60) + ' min' : s < 172800 ? Math.round(s / 3600) + ' h' : Math.round(s / 86400) + ' j'; };

// socTZ est un binding vivant (import en lecture seule côté consommateurs) ; setter dédié pour l'unique
// site d'écriture (sélecteur #tz, suivi d'un location.reload()).
export function setSocTZ(v) { socTZ = v; }
export {
  $, CSSV, socTZ, LANG, LOC, tzOpts, fmtTs, SEV, sev, bool, esc, ICONS, ic, flashStopped, stopBtn, closeModals, withBusy, toast, showErr, modal, confirmModal, csvCell, toCSV, downloadText, tsSlug, exportPDF, exportBar, closeMiniMenu, miniMenu, api, apiSend, transientGatewayMsg, muted, fetchInto, colComparator, makePager, pageNums, pagedList,
  socRole, socIsAdmin, applyRoleClass, controleDEcritureSous, motiverLeRefusAuLecteur, roleSansEcriturePartagee, managedBadge, gateDeleteBtn, formMsg, contentSubmit, contentDelete, SEVCOL, lsSet, collapsibleGroup, mitreName, humanAge,
  confirmWithConsequence, disclosure, marquerLesCellulesTronquees, celluleDeborde,
  jourEnSecondes, instantEnSecondes, lireUnePlage, borneHauteCouvreMaintenant, poserLaPlageSurLaCible, poserLeChoixDeDates, ouvrirLaModaleDePlage
};

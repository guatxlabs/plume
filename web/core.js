// core.js — primitives partagées de l'UI Plume (extraites de app.js, refactor ES-modules).
// AUCUN état métier ni dépendance vers app.js : uniquement des helpers autonomes (DOM, esc/ic, i18n
// date/langue, modales/toasts, export CSV/JSON/PDF, api()/apiSend(), pagination). app.js et les futurs
// modules importent depuis ici. Comportement identique au monolithe (mêmes fonctions, juste relocalisées).
// state.js est un pur leaf (aucun import) -> l'importer ici ne crée aucun cycle. Utilisé par socRole/socIsAdmin
// (helpers partagés relocalisés depuis app.js, audit H1 — cassent les deps circulaires app<->vues).
import { S, ecrireDansLeStockageDuSite, ecrireSansDireLeRefus, lireLeStockageDuSite, RAISONS_DE_SILENCE } from './state.js';
// `P11.18-m` — LA RECHERCHE D'UNE LISTE N'EST PAS RÉÉCRITE ICI : elle vit dans le module qui la porte
// déjà pour toute la console. `recherche_de_liste.js` est un feuillet — il n'importe rien — donc
// l'importer depuis le cœur ne crée aucun cycle, et le prédicat, le filtre et la phrase de résumé
// restent écrits UNE fois.
import { champDeRecherche, filtrerParRecherche, resumeDeRecherche, souvenirDeRecherche, texteCherchable } from './recherche_de_liste.js';
import { nomDeTechnique } from './catalogue_attack.js'; // `P11.6-c` : le nom d'une technique est dérivé du catalogue servi, jamais d'une table d'ici

const $ = s => document.querySelector(s);
// lit une variable de thème CSS (graphes SVG theme-aware : se recolorent au changement clair/sombre)
const CSSV = (n, d) => (getComputedStyle(document.documentElement).getPropertyValue(n).trim() || d);
// Fuseau d'AFFICHAGE : '' = navigateur ; 'UTC' ou 'Europe/Paris' = forcé. Le stockage reste UTC
// partout (ts = epoch) ; on ne change QUE le rendu (sélecteur #tz). Répond à « UTC 0 + Paris configurable ».
// `P4.13-a` (reprise) — ces deux lectures s'exécutent à l'ÉVALUATION de `core.js`, racine effective du
// graphe (`login.js` et `app.js` l'importent tous deux) : un accès NU à `localStorage` y jette
// `SecurityError` chez un navigateur qui bloque le stockage de site, le graphe ne se lie pas et l'écran de
// connexion n'apparaît jamais. Le lecteur gardé vit dans `state.js` (un seul auteur ; voir son en-tête).
let socTZ = lireLeStockageDuSite('soc_tz') || '';
const LANG = lireLeStockageDuSite('soc_lang') || 'fr';   // langue UI (fr par défaut) ; EN via dico FR->EN
const LOC = LANG === 'en' ? 'en-US' : 'fr-FR';            // locale des dates/heures
// `P11.21-n` — LE DOCUMENT DÉCLARE LA LANGUE QU'IL REND. `web/index.html` fixe `lang="fr"` dans son
// balisage, et c'est le BON amorçage : tant que le graphe ES n'est pas lié, la seule chose que la page
// puisse afficher est l'aveu `#init-echec`, écrit en français quoi qu'il arrive. Mais dès que ce module
// s'évalue, la langue est CONNUE — mesuré le 2026-08-31, une console dont tous les libellés sont peints en
// anglais (« Overview », « Sign in », « Password ») annonçait encore `lang="fr"` : un lecteur d'écran y
// prononce l'anglais avec la phonétique française. La déclaration suit donc la MÊME condition que `LOC`
// (une seule ligne à toucher le jour d'une troisième langue) et se pose ICI, à la racine effective du
// graphe — `login.js` et `app.js` importent tous deux ce module, donc l'écran de connexion est couvert
// autant que la console. Le geste est INERTE POUR LA PEINTURE, et c'est mesuré : `web/style.css` et
// `web/index.html` ne portent AUCUN sélecteur `:lang()` ni `[lang]`, ni règle `quotes`/`hyphens` — cet
// attribut ne parle qu'aux technologies d'assistance et aux sélecteurs de langue à venir. La langue par
// défaut est INCHANGÉE : sans choix en stockage, `LANG` vaut `'fr'` et le document déclare `fr`.
document.documentElement.lang = LANG === 'en' ? 'en' : 'fr';
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
// BORNER UN POPOVER SUR L'ESPACE QUI EXISTE SOUS SON ANCRE — pas sur une fraction d'écran (`P11.22-z`).
//
// LE DÉFAUT QUE CE GESTE FERME. Un popover `position:fixed` posé à `rect.bottom + 4` ne bouge PAS quand la
// page défile : ce qui tombe sous le bord bas de la fenêtre n'y remonte par AUCUN geste. Une borne écrite
// en `vh` dans la feuille de style borne la HAUTEUR de la boîte, jamais sa POSITION — `max-height:60vh` ne
// garantit donc la visibilité que si l'ancre siège dans les 40 % hauts de l'écran, ce qu'aucune de ces
// ancres ne peut promettre : la barre d'un tableau de résultats vit aussi dans un panneau de dashboard,
// posé n'importe où sur la page. MESURÉ le 2026-08-30 sur le sélecteur de colonnes, ancre à 712 px d'une
// fenêtre de 800 : la boîte descendait à 1196 px — 396 px hors écran, une quinzaine de lignes — SANS
// erreur, SANS barre de défilement (le contenu tenait sous le plafond `60vh`, donc rien ne débordait DE
// LA BOÎTE) et sans qu'un mot dise que des colonnes existaient au-delà du bord.
//
// CE QUE LE GESTE POSE. La hauteur maximale RÉELLE, en pixels, à l'ouverture ; `overflow-y:auto` fait
// alors paraître la barre de défilement, qui est ce qui DIT que la liste continue. Quand l'espace sous
// l'ancre est trop mince pour être utile, le popover BASCULE au-dessus d'elle — c'est la seule sortie
// honnête : un plancher en pixels rendrait le débordement au lieu de le fermer.
//
// CE QU'IL NE FAIT PAS : rien sur l'axe horizontal (chaque appelant a sa propre logique d'alignement), et
// il ne re-mesure RIEN après coup — un redimensionnement de la fenêtre, menu ouvert, n'est pas repris.
// Renvoie `{ versLeHaut, hauteurMax }` : deux grandeurs qu'un témoin peut lire sans deviner.
export function bornerLePopoverSousSonAncre(popover, rect, marge) {
  const m = (marge == null ? 8 : marge), ecart = 4, H = window.innerHeight;
  const sous = H - rect.bottom - ecart - m;        // espace RÉEL sous l'ancre
  const sur = rect.top - ecart - m;                // espace RÉEL au-dessus
  const versLeHaut = sous < Math.min(160, sur);    // trop peu dessous ET mieux dessus -> bascule
  const hauteurMax = Math.max(0, Math.round(versLeHaut ? sur : sous));
  popover.style.maxHeight = hauteurMax + 'px';
  popover.style.overflowY = 'auto';
  if (versLeHaut) { popover.style.top = ''; popover.style.bottom = Math.round(H - rect.top + ecart) + 'px'; }
  else { popover.style.bottom = ''; popover.style.top = Math.round(rect.bottom + ecart) + 'px'; }
  return { versLeHaut, hauteurMax };
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
  menu.style.position = 'fixed'; menu.style.left = Math.max(6, r.right - menu.offsetWidth) + 'px';
  bornerLePopoverSousSonAncre(menu, r);   // `P11.22-z` : ce menu n'avait AUCUNE borne de hauteur — ni ici, ni dans la feuille de style
  const onDoc = e => { if (!menu.contains(e.target) && e.target !== anchor) closeMiniMenu(); };
  const onKey = e => { if (e.key === 'Escape') closeMiniMenu(); };
  setTimeout(() => { document.addEventListener('mousedown', onDoc); document.addEventListener('keydown', onKey); }, 0);
  _miniMenuClose = () => { document.removeEventListener('mousedown', onDoc); document.removeEventListener('keydown', onKey); menu.remove(); };
}

// PANNE TRANSITOIRE DE PASSERELLE : détecte un 502/503/504 de reverse-proxy (ou un corps HTML « no available
// server » servi pendant la fenêtre de rollout) et renvoie un message propre — au lieu de surfacer le corps brut
// (« réponse non-JSON … no available server »). null = ce n'est PAS transitoire (comportement inchangé).
// `P10.22-b` — la reconnaissance d'une page de passerelle est PARTAGÉE avec `apiSend` (plus bas) : un seul motif.
const RESSEMBLE_A_UNE_PAGE_DE_PASSERELLE = /no available server|<!doctype|<html/i;
// `P10.27-c` — LA PHRASE D'UNE PANNE DE PASSERELLE ET LE PRÉFIXE D'UNE LECTURE REFUSÉE ONT LEURS DEUX FACES. Mesuré
// avant ce lot (témoin 116c) : sous `LANG='en'`, `fetchInto` peignait « erreur : Service momentanément indisponible,
// réessaie dans un instant. » — deux fragments qu'aucun nœud entier ne porte, donc que le lexique ne peut pas
// traduire —, et la liste paginée côté serveur (`pagedList`, plus bas) collait le même « erreur : ». La phrase est
// aussi le MESSAGE de l'erreur jetée par `api()` (un cinq cent deux, trois ou quatre qui ne nomme rien) et des
// panneaux de tableau de bord qui lisent `transientGatewayMsg` : la face se choisit ici, une fois, à la langue de
// l'écran. La face française est celle d'avant, au caractère près (le témoin 115p et le 116c l'ancrent).
const MOTS_D_UNE_LECTURE_QUI_N_EST_PAS_SERVIE = {
  panne_de_passerelle: {
    fr: 'Service momentanément indisponible, réessaie dans un instant.',
    en: 'Service temporarily unavailable, try again in a moment.' },
  prefixe_de_la_lecture_refusee: {
    fr: 'erreur : ',
    en: 'error: ' },
};
const motDUneLectureQuiNEstPasServie = (cle) => (LANG === 'en' ? MOTS_D_UNE_LECTURE_QUI_N_EST_PAS_SERVIE[cle].en : MOTS_D_UNE_LECTURE_QUI_N_EST_PAS_SERVIE[cle].fr);
function transientGatewayMsg(status, body) {
  if (status === 502 || status === 503 || status === 504) return motDUneLectureQuiNEstPasServie('panne_de_passerelle');
  if (body && RESSEMBLE_A_UNE_PAGE_DE_PASSERELLE.test(body)) return motDUneLectureQuiNEstPasServie('panne_de_passerelle');
  return null;
}

// `P10.20-b` — LA CAUSE QUE LE DÉMON NOMME DANS UN REFUS NE SE PERD PAS EN CHEMIN. `err_json`
// (daemon/src/main.rs) rend TOUT refus en `{"error": <phrase>, "id": …}` ; une panne de passerelle, elle,
// rend du HTML ou rien. Le message composé par `api()` sur `!r.ok` COUPE le corps à 200 caractères, et le
// repli « transitoire » d'un 503 le REMPLACE entièrement : dans les deux cas la phrase que le démon a
// écrite pour être lue n'atteint pas l'écran. Elle est donc extraite ici et portée À CÔTÉ du message
// (`causeDuDemon`), sans rien changer au message lui-même — les surfaces qui ne la lisent pas se
// comportent exactement comme avant. Rend '' quand le corps n'est pas un objet JSON qui nomme sa cause.
// Les refus de forme sont écrits UN PAR UN, jamais fondus en une condition : un corps vide, un corps qui
// n'est pas un objet et un objet qui ne nomme rien ne sont pas le même fait, et une garde du dépôt
// (`check_a_refusal_is_not_rendered_as_an_absence.py`) refuse précisément qu'on les confonde.
function causeNommeeParLeDemon(corps) {
  if (!corps) return '';
  let o; try { o = JSON.parse(corps); } catch { return ''; }
  if (!o) return '';
  if (typeof o !== 'object') return '';
  if (Array.isArray(o)) return '';
  if (typeof o.error !== 'string') return '';
  return o.error.trim();
}
// Attache la cause nommée à une erreur déjà formée : un seul point d'écriture pour les deux sorties
// d'`api()` qui peuvent porter un refus du démon (le repli transitoire, et le rejet `!r.ok`).
function avecLaCauseDuDemon(err, cause) { if (cause) err.causeDuDemon = cause; return err; }
// `P10.26-o` — LE STATUT D'UNE RÉPONSE LUE VOYAGE AUSSI À CÔTÉ DU MESSAGE D'`api()`, comme il le fait depuis
// `P10.22-n` à côté de celui d'`apiSend`. Sans lui, la liste des comptes ne pouvait séparer le refus du RÔLE (un
// quatre cent trois) d'aucun autre refus qu'en relisant le message composé ici pour être lu. Il est posé sur TOUTE
// erreur jetée APRÈS qu'une réponse a été lue — refus, repli transitoire, corps vide ou illisible — et jamais sur un
// rejet du transport : `laDemandeNAPasAbouti` vaut donc désormais pour les deux fabriques.
function avecLeStatutDuRefus(err, statut) { err.statutDuRefus = statut; return err; }
// `P10.25-i` — L'OBJET D'UN REFUS NOMMÉ VOYAGE ENTIER, À CÔTÉ DE SA CAUSE. Un refus peut porter, en plus de
// `error`, un DÉTAIL que le démon a écrit pour être lu : `user_create` (daemon/src/handlers/users_lookups.rs) sert
// en quatre cent neuf ce qu'un nom tient déjà sans compte local (`ce_que_le_nom_tient`). Le message composé par
// `apiSend` coupe le corps à deux cents caractères — et la cause de ce refus en compte cinq cent cinquante-huit à
// elle seule —, `causeDuDemon` ne garde que `error` : le détail n'atteignait aucune surface. Seul un corps qui
// NOMME sa cause porte un objet ici ; tout autre (texte brut, page de passerelle, JSON sans `error`) n'en porte
// aucun, et rien ne change pour les surfaces qui ne le lisent pas.
function objetDuRefusNomme(corps) {
  if (!causeNommeeParLeDemon(corps)) return null;
  return JSON.parse(corps);   // lisible, et objet : `causeNommeeParLeDemon` vient de l'établir
}

// `P10.20-k` (2026-09-16) — LA PHRASE D'UN REFUS, QUEL QUE SOIT LE MOULE OÙ LE DÉMON L'A COULÉE.
// `causeNommeeParLeDemon` ci-dessus ne lit qu'UNE forme : le corps JSON `{"error": …}` d'`err_json`.
// Or les refus d'un même handler n'ont PAS tous ce moule, et `panel_update` le montre : ses quatre refus
// partent en DEUX formes distinctes — trois par `err_json` (`not_found("panneau introuvable")`,
// `forbidden("dashboard non modifiable")`, `forbidden("SQL brut réservé à l'administrateur (utilisez
// GXQL)")`), qui donnent un objet JSON ; et le quatrième par `(code, msg).into_response()` sur le couple
// que rend `DefinitionExecutee::projetee`, qui donne du TEXTE BRUT. Sur la seconde forme, `causeDuDemon`
// reste vide et le seul porteur de la phrase est le message composé par `api()`/`apiSend()` :
// « <code> <corps> ». Une surface qui ne lit que `causeDuDemon` peint alors un vide là où le démon a
// écrit une phrase ; une surface qui ne lit que `message` peint du JSON brut, qui n'est pas un texte
// d'écran. CE LECTEUR REND LA PHRASE DANS LES DEUX CAS, et il est écrit ICI, une fois, pour que les
// surfaces ne se fabriquent pas chacune leur extraction — elles dériveraient.
// CE QU'IL NE FAIT PAS : il n'invente rien. Quand il ne reconnaît ni l'une ni l'autre forme (un corps
// vide, un message sans code), il rend le message TEL QUEL — moins lisible, jamais faux.
function phraseDuRefusDuDemon(e) {
  const nommee = (e && e.causeDuDemon) ? String(e.causeDuDemon).trim() : '';
  if (nommee) return nommee;
  const brut = String((e && e.message) || e || '').trim();
  const m = brut.match(/^\d{3}\s+([\s\S]+)$/);
  if (!m) return brut;
  const corps = m[1].trim();
  // Un corps qui COMMENCE par une accolade ou un crochet est du JSON que `causeNommeeParLeDemon` n'a pas
  // su nommer (objet sans `error`, tableau, JSON tronqué par la coupe à 200 caractères) : le rendre
  // écrirait de la syntaxe à l'écran. On garde alors le message entier, qui dit au moins le code.
  if (corps.startsWith('{') || corps.startsWith('[')) return brut;
  return corps;
}

// `P10.20-t` — LE REFUS D'UNE MISE EN FILE DE RIPOSTE, LU AU POINT COMMUN DE SES DEUX SURFACES.
//
// POURQUOI CE LECTEUR VIT ICI, ET PAS DANS LE MODULE DE LA FILE DE RIPOSTE — C'EST MESURÉ. Les deux
// surfaces qui CRÉENT une riposte envoient le MÊME corps à la MÊME route : le formulaire du panneau
// Réponse (`web/detection_admin.js`) et le geste « bannir » d'une ligne de résultats (`web/viz.js`).
// Écrire la phrase deux fois la laisserait diverger. La faire venir de `detection_admin.js` a été
// ESSAYÉ et REFUSÉ par le harnais : l'arête `viz.js -> detection_admin.js` change l'ordre d'évaluation
// du graphe, et la porte d'entrée `attack.js` se met à JETER (`ReferenceError: Cannot access 'PORTES'
// before initialization`, site de premier niveau `web/detection_admin.js`) — la famille de défauts que
// `P11.21-f` a fermée, et qui rend l'écran VIDE. Ce module-ci n'importe aucun module de vue et les deux
// surfaces l'importent déjà ; c'est aussi là que vivent les trois autres lecteurs d'un refus du démon.
//
// LE DISCRIMINANT est ancré sur l'OUVERTURE du littéral que le démon écrit (`CAUSE_RIPOSTE_NON_MISE_EN_FILE`,
// daemon/src/handlers/actions.rs) : le corps servi est `<cause> (<détail>)`, la cause est donc en tête.
// Un motif large confondrait ce refus avec les autres phrases de riposte que cette console lit déjà.
const OUVERTURE_DE_LA_RIPOSTE_NON_MISE_EN_FILE = /^RIPOSTE NON MISE EN FILE\b/;
function laRiposteNAPasEteMiseEnFile(e) { return OUVERTURE_DE_LA_RIPOSTE_NON_MISE_EN_FILE.test(phraseDuRefusDuDemon(e)); }
// Les deux phrases, FR et EN côte à côte : aucune des deux langues ne peut partir sans l'autre. Chacune
// dit ce que le démon N'A PAS fait — sans quoi l'exploitant recommence un geste peut-être déjà pris.
const MOTS_DE_LA_CREATION_DE_RIPOSTE = {
  riposte_non_mise_en_file: {
    fr: "Riposte NON MISE EN FILE : la ligne n'a pas pu être écrite, donc AUCUNE riposte n'attend d'approbation, le registre n'en porte aucune trace et aucun identifiant n'est rendu. Rien n'a été fait. Le démon en nomme la cause —",
    en: 'Response NOT QUEUED: the line could not be written, so NO response is awaiting approval, the ledger carries no trace of it and no identifier is returned. Nothing was done. The daemon names the cause —' },
  creation_refusee: {
    fr: "Création de la riposte REFUSÉE : le démon a refusé ce geste et en nomme la cause —",
    en: 'Response creation REFUSED: the daemon refused this gesture and names the cause —' },
};
function motDuRefusDeCreationDeRiposte(e) {
  const mots = MOTS_DE_LA_CREATION_DE_RIPOSTE[laRiposteNAPasEteMiseEnFile(e) ? 'riposte_non_mise_en_file' : 'creation_refusee'];
  return LANG === 'en' ? mots.en : mots.fr;
}
// L'aveu à DEUX nœuds : la phrase posée au puits (`dit.textContent = …`) — c'est là, et seulement là,
// que le lexique la voit —, la cause SERVIE par le démon collée dans un SECOND nœud. Rendu en `span` :
// ses deux surfaces l'accrochent dans une ligne de formulaire, pas dans un bloc.
function aveuDeLaCreationDeRiposte(e) {
  const aveu = document.createElement('span'); aveu.className = 'bad';
  const dit = document.createElement('span');
  dit.textContent = motDuRefusDeCreationDeRiposte(e);
  aveu.append(dit, ' \u00ab ' + phraseDuRefusDuDemon(e) + ' \u00bb');
  aveu.dataset.refusDeRiposte = '1';   // marque de POSE, pas de style : aucune règle CSS ne la vise
  return aveu;
}
// LA MÊME PHRASE QUAND AUCUN NŒUD NE PEUT LA PORTER. Un avis est une CHAÎNE : la surface qui n'a pas de
// puits ouvert — le geste « bannir » part d'une ligne de résultats — reçoit la phrase et la cause dans
// un seul nœud. C'est le repli déjà livré ailleurs pour un aveu sans hôte, pas une seconde grammaire.
function phraseDeLaCreationDeRiposteRefusee(e) {
  return motDuRefusDeCreationDeRiposte(e) + ' \u00ab ' + phraseDuRefusDuDemon(e) + ' \u00bb';
}

// `P10.21-a` \u2014 LE GESTE A EU LIEU ET SA TRACE MANQUE : LE LECTEUR PART AU POINT COMMUN, \u00c0 DEUX USAGES.
//
// CE QUE LE D\u00c9MON SERT. Depuis que `ledger_append` (daemon/src/ledger.rs) rend l'issue de son \u00e9criture
// au lieu de l'avaler, `action_create` (daemon/src/handlers/actions.rs) pose la riposte, constate que le
// registre tamper-evident n'a pas pris la ligne, et le DIT dans son corps de SUCC\u00c8S sous la cl\u00e9
// `registre_sans_maillon` \u2014 l'identifiant reste servi, parce que la ligne de riposte, elle, existe.
// Refuser serait faux ; se taire laisserait un geste de riposte hors de la trace non purgeable.
//
// POURQUOI CE LECTEUR VIT ICI MAINTENANT, ET PAS AVANT. `P10.20-y` l'a \u00e9crit dans `web/cases.js` en
// posant la r\u00e8gle : un lecteur qui n'a qu'un usage D\u00c9RIVE de cet usage, et il attend la deuxi\u00e8me
// surface pour partir au point commun. Les TROIS surfaces qui mettent une riposte en file par
// `POST /api/actions` re\u00e7oivent la m\u00eame cl\u00e9 ; deux de plus la lisent, donc le lecteur part \u2014 m\u00eame
// route, m\u00eame cl\u00e9, m\u00eame phrase, et le NOM de la cl\u00e9 \u00e9crit \u00e0 UN seul endroit. C'est le chemin d\u00e9j\u00e0 pris
// par le refus de mise en file juste au-dessus, pour la m\u00eame raison et vers le m\u00eame module : celui-ci
// n'importe aucun module de vue, et les trois surfaces l'importent d\u00e9j\u00e0.
// D\u00c9PLACEMENT PUR : la table des deux faces et sa fabrique de phrase viennent de `web/cases.js` mot
// pour mot ; ce qui s'y ajoute est le lecteur de la cl\u00e9, la fabrique du n\u0153ud et le repli en cha\u00eene \u2014
// les trois formes que les surfaces r\u00e9\u00e9criraient chacune de son c\u00f4t\u00e9.
const CLE_DU_REGISTRE_SANS_MAILLON = 'registre_sans_maillon';
// LE NOM DE LA CL\u00c9 N'EST \u00c9CRIT QU'ICI. Une surface qui lirait `j.registre_sans_maillon` \u00e0 la main
// l'\u00e9crirait une fois de plus, et le jour o\u00f9 ce nom change il en resterait des muettes \u2014 sans un mot,
// puisque l'aveu se rend sur un corps de SUCC\u00c8S. Rend la cause SERVIE, ou la cha\u00eene vide : un corps
// sans la cl\u00e9 n'a rien \u00e0 avouer.
function causeDeLaTraceManquante(j) {
  const cause = j && j[CLE_DU_REGISTRE_SANS_MAILLON];
  return cause ? String(cause).trim() : '';
}
// Les deux faces c\u00f4te \u00e0 c\u00f4te : aucune des deux langues ne peut partir sans l'autre. La phrase dit ce
// qui EXISTE quand m\u00eame (la riposte est en file), ce qui MANQUE (la ligne du registre), et ce qu'un
// second geste ferait \u2014 sans quoi l'exploitant recommence et pose une seconde riposte.
const MOTS_DE_LA_TRACE_MANQUANTE = {
  fr: "Riposte EN FILE, mais SANS TRACE D'AUDIT : la ligne est \u00e9crite et attend son approbation \u2014 ne recommencez PAS, vous en poseriez une seconde. Ce qui manque est la ligne du registre tamper-evident qui l'atteste. Le d\u00e9mon en nomme la cause \u2014",
  en: 'Response QUEUED, but WITHOUT AUDIT TRACE: the line is written and awaits approval \u2014 do NOT start over, you would queue a second one. What is missing is the tamper-evident ledger line attesting it. The daemon names the cause \u2014',
};
const motDeLaTraceManquante = () => (LANG === 'en' ? MOTS_DE_LA_TRACE_MANQUANTE.en : MOTS_DE_LA_TRACE_MANQUANTE.fr);
// L'aveu \u00e0 DEUX n\u0153uds : la phrase pos\u00e9e au puits (`dit.textContent = \u2026`) \u2014 c'est l\u00e0, et seulement l\u00e0,
// que le lexique et `i18nWalk` la voient \u2014, la cause SERVIE par le d\u00e9mon coll\u00e9e dans un SECOND n\u0153ud.
// LA BALISE EST CELLE DU PUITS QUI L'ACCUEILLE, et c'est la seule chose qui diff\u00e8re d'une surface \u00e0
// l'autre : un bloc dans le d\u00e9tail d'un dossier, une ligne dans une barre de formulaire. Le style reste
// au site : ce module ne sait pas dans quoi il est accroch\u00e9.
// `P10.21-h` \u2014 LA FABRIQUE DU N\u0152UD SORT DE SON USAGE, LA PHRASE Y RESTE. Le journal du plan de contr\u00f4le
// (`registre_sans_maillon` sur les gestes d'administration des tenants) porte la m\u00eame cl\u00e9 et la m\u00eame
// forme d'aveu, mais pas la m\u00eame phrase : \u00ab Riposte EN FILE \u00bb y serait faux. D\u00c9PLACEMENT PUR : le corps
// ci-dessous est celui d'`aveuDeLaTraceManquante`, la phrase en param\u00e8tre ; ce module ne sait toujours
// pas quel geste il avoue.
function aveuDUneTraceManquante(mot, cause, balise) {
  const aveu = document.createElement(balise || 'div'); aveu.className = 'bad';
  const dit = document.createElement('span');
  dit.textContent = mot;
  aveu.append(dit, ' \u00ab ' + cause + ' \u00bb');
  aveu.dataset.traceManquante = '1';   // marque de POSE, pas de style : aucune r\u00e8gle CSS ne la vise
  return aveu;
}
function aveuDeLaTraceManquante(cause, balise) { return aveuDUneTraceManquante(motDeLaTraceManquante(), cause, balise); }
// LA M\u00caME PHRASE QUAND AUCUN N\u0152UD NE PEUT LA PORTER. Un avis est une CHA\u00ceNE : la surface sans puits
// ouvert \u2014 le geste \u00ab bannir \u00bb d'une ligne de r\u00e9sultats, un dossier qui n'est pas celui affich\u00e9 \u2014
// re\u00e7oit la phrase et la cause dans un seul n\u0153ud. Repli d\u00e9j\u00e0 livr\u00e9 ailleurs, pas une seconde grammaire.
function phraseDeLaTraceManquante(cause) {
  return motDeLaTraceManquante() + ' \u00ab ' + cause + ' \u00bb';
}

// `P10.22-a` et `P10.22-c` — UN IDENTIFIANT SERVI OU ABSENT : LA PARTITION ET SA FACE « ABSENT » PARTENT AU
// POINT COMMUN, PARCE QU'ELLES ONT TROIS USAGES.
//
// CE QUE LE DÉMON SERT. `action_create` (daemon/src/handlers/actions.rs) ne rend un succès qu'avec son
// `id`. Un deux cents dont le corps est VIDE ou n'est pas du JSON — une page de passerelle servie en deux cents
// en est un, et la requête n'a alors peut-être jamais atteint le démon — arrive aux surfaces comme `null`
// (`apiSend`, ou `unDeuxCentsSansCorpsLisible` dans leur `catch`, plus bas). Rien, sur ces deux formes, n'établit qu'une riposte a été créée.
//
// POURQUOI ICI. `P10.21-y` a écrit la partition dans `web/viz.js` pour le geste « bannir », seul usage
// alors. Les deux autres surfaces qui créent une riposte par la même route la lisent désormais : l'étape
// « réponse » d'un runbook (`web/cases.js`) et le formulaire du panneau Réponse (`web/detection_admin.js`).
// Ce dernier n'importe pas `web/viz.js`, et l'arête `viz.js -> detection_admin.js` a déjà été mesurée
// fatale à l'ordre d'évaluation (`P10.20-t`, ci-dessus) : le point commun est le seul module que les
// trois importent déjà. DÉPLACEMENT PUR de la partition — même lecture, mot pour mot (`j.id` vrai) —, et
// `web/viz.js` la RÉÉMET pour que tout module qui l'y lisait la lise encore.
// LA FACE « ABSENT » PART AVEC ELLE, et c'est la phrase de `P10.21-y` mot pour mot, le geste en paramètre
// au lieu de `ban_ip` écrit en dur : trois rédactions du même fait sur la même route dériveraient. Elle
// N'AFFIRME ni la création ni la mise en file, et dit de retrouver la riposte avant de rejouer le geste,
// qui en poserait une seconde. Les faces « servi », elles, restent à leurs surfaces : chacune nomme son
// geste à sa façon (« créée », « mise en file »), et le formulaire n'en peint aucune — il se referme.
const cleDeLIdentifiantDeRiposte = (j) => (j && j.id ? 'identifiant_servi' : 'identifiant_absent');
const MOTS_DE_LA_RIPOSTE_SANS_IDENTIFIANT = {
  fr: "Le démon a répondu sans rendre AUCUN identifiant : rien ici n'établit que l'action {geste} {cible} a été créée. Elle ne peut pas être désignée par un numéro — la chercher dans l'onglet Réponse par son geste et sa cible avant de l'approuver, ou avant de rejouer ce geste, qui en poserait une seconde.",
  en: 'The daemon answered without returning ANY identifier: nothing here establishes that the {geste} {cible} action was created. It cannot be designated by a number — look for it in the Response tab by its gesture and target before approving it, or before replaying this gesture, which would queue a second one.',
};
function motDeLaRiposteSansIdentifiant(geste, cible) {
  return (LANG === 'en' ? MOTS_DE_LA_RIPOSTE_SANS_IDENTIFIANT.en : MOTS_DE_LA_RIPOSTE_SANS_IDENTIFIANT.fr)
    .replace('{geste}', String(geste)).replace('{cible}', String(cible));
}

// `P10.22-n` — LES REFUS DU SECOND FACTEUR, LUS PAR LEUR CAUSE AU POINT COMMUN DE LEURS DEUX ÉCRANS.
//
// CE QUE LE DÉMON SERT (daemon/src/handlers/idp.rs, `P10.21-s` puis `P10.22-k`, `-l`, `-m`, `-r`). Trois
// routes jugent un second facteur — la connexion (`/api/login/mfa`, écran de `web/login.js`), la
// désactivation et l'activation (`/api/mfa/disable`, `/api/mfa/verify`, panneau de `web/idp.js`) — et leurs
// refus nommés ne disent pas la même chose de la personne devant l'écran : un code JUSTE que la base n'a pas
// consommé, une liste de codes de secours ILLISIBLE (code ni accepté ni refusé), un compte FREINÉ (codes
// refusés sans examen), une écriture refusée, un enrôlement changé pendant la vérification. Le statut ne
// suffit plus à les séparer — trois de ces causes partagent le cinq cent trois —, la CAUSE servie le fait.
//
// LES OUVERTURES S'ANCRENT EN TÊTE, BORNÉES PAR UNICODE, comme celles des refus de dossier (`web/cases.js`) :
// le démon sert chaque cause en tête de son corps `{error}`. Aucune n'est recopiée ailleurs : le témoin 108
// relit chaque constante du démon et exige qu'elle soit reconnue ICI, dans les deux sens.
// POURQUOI ICI : deux causes (`codes_de_secours_illisibles`, `second_facteur_freine`) sont servies aux DEUX
// écrans, qui n'importent l'un de l'autre rien ; leurs phrases partent avec le lecteur.
const OUVERTURES_DES_REFUS_DU_SECOND_FACTEUR = [
  ['code_juste_non_consomme', /^(?:SECOND FACTEUR|CODE DE SECOURS) NON CONSOMMÉ(?![\p{L}\p{N}])/u],
  ['codes_de_secours_illisibles', /^CODES DE SECOURS NON LUS(?![\p{L}\p{N}])/u],
  ['second_facteur_freine', /^TROP D'ÉCHECS DU SECOND FACTEUR(?![\p{L}\p{N}])/u],
  ['mfa_non_desactivee', /^DOUBLE AUTHENTIFICATION TOUJOURS ACTIVE(?![\p{L}\p{N}])/u],
  ['mfa_non_activee', /^DOUBLE AUTHENTIFICATION NON ACTIVÉE(?![\p{L}\p{N}])/u],
  ['enrolement_change', /^ENRÔLEMENT CHANGÉ PENDANT LA VÉRIFICATION(?![\p{L}\p{N}])/u],
  // `P10.22-x` (démon) — le ticket de la connexion refusé, expiré ou RÉVOQUÉ (il suit désormais la révocation des
  // sessions) : quatre cent un comme le code refusé, mais le code n'y est PAS examiné. Lu par l'écran de connexion.
  ['ticket_refuse', /^TICKET MFA REFUSÉ(?![\p{L}\p{N}])/u],
  // `P10.20-b` — le statut du second facteur non lu (`mfa_status`, `mfa_enroll`) ; et `P10.23-b` (démon) — la preuve
  // du premier facteur exigée à l'ENRÔLEMENT : ses cinq refus nommés, lus par le panneau MFA (`web/idp.js`).
  ['statut_mfa_non_lu', /^STATUT DE DOUBLE AUTHENTIFICATION NON LU(?![\p{L}\p{N}])/u],
  ['mot_de_passe_exige', /^MOT DE PASSE EXIGÉ POUR ENRÔLER(?![\p{L}\p{N}])/u],
  ['mot_de_passe_refuse', /^MOT DE PASSE REFUSÉ, AUCUNE GRAINE ENRÔLÉE(?![\p{L}\p{N}])/u],
  ['mot_de_passe_verrouille', /^TROP D'ÉCHECS DU MOT DE PASSE(?![\p{L}\p{N}])/u],
  ['sans_mot_de_passe_local', /^ENRÔLEMENT REFUSÉ, CE COMPTE N'A PAS DE MOT DE PASSE LOCAL(?![\p{L}\p{N}])/u],
  ['compte_non_lu', /^COMPTE NON LU, ENRÔLEMENT NI ACCEPTÉ NI REFUSÉ(?![\p{L}\p{N}])/u],
];
// Rend la nature du refus, ou '' quand la phrase n'ouvre sur aucune cause connue — l'appelant retombe alors
// sur son refus générique, qui colle la phrase sans rien en affirmer.
function natureDuRefusDuSecondFacteur(phrase) {
  const p = String(phrase || '').trim();
  const trouvee = OUVERTURES_DES_REFUS_DU_SECOND_FACTEUR.find(([, ouverture]) => ouverture.test(p));
  return trouvee ? trouvee[0] : '';
}
// Les deux faces communes aux deux écrans ; `{delai}` est le délai servi (`Retry-After`), en secondes.
const MOTS_DES_REFUS_DU_SECOND_FACTEUR = {
  codes_de_secours_illisibles: {
    fr: "Ton code n'est ni accepté ni refusé : la liste des codes de secours de ce compte n'a pas pu être lue, aucun échec n'est compté et rien n'est modifié. Réessaie, ou présente un code TOTP. Le démon en nomme la cause —",
    en: 'Your code is neither accepted nor refused: the recovery code list of this account could not be read, no failure is counted and nothing is changed. Try again, or present a TOTP code. The daemon names the cause —' },
  second_facteur_freine: {
    fr: "Second facteur FREINÉ sur ce compte : trop d'échecs, les codes sont refusés SANS être examinés — réessaie dans {delai} s. Se reconnecter par mot de passe ne lève pas le frein. Le démon en nomme la cause —",
    en: 'Second factor THROTTLED on this account: too many failures, codes are refused WITHOUT being examined — try again in {delai} s. Signing in again with the password does not lift it. The daemon names the cause —' },
  second_facteur_freine_sans_delai: {
    fr: "Second facteur FREINÉ sur ce compte : trop d'échecs, les codes sont refusés SANS être examinés jusqu'à la fin du délai. Se reconnecter par mot de passe ne lève pas le frein. Le démon en nomme la cause —",
    en: 'Second factor THROTTLED on this account: too many failures, codes are refused WITHOUT being examined until the delay ends. Signing in again with the password does not lift it. The daemon names the cause —' },
};
function motDuRefusDuSecondFacteur(cle, delai) {
  const cleServie = cle === 'second_facteur_freine' && !(delai > 0) ? 'second_facteur_freine_sans_delai' : cle;
  const mots = MOTS_DES_REFUS_DU_SECOND_FACTEUR[cleServie];
  return (LANG === 'en' ? mots.en : mots.fr).replace('{delai}', String(delai));
}

async function api(path) {
  // Sur panne transitoire de passerelle -> réessais GET-only (idempotents) ~400ms puis ~800ms, sinon
  // message propre. Toute autre erreur garde EXACTEMENT le comportement d'avant (statut+corps / vide / non-JSON).
  const backoffs = [400, 800];
  for (let attempt = 0; ; attempt++) {
    const r = await fetch('/api' + path, { headers: { Accept: 'application/json' } });
    const body = await r.text().catch(() => '');   // lit en texte d'abord -> gère réponse vide/tronquée
    // `P10.20-b` — LE REFUS NOMMÉ EST LU AVANT TOUTE MISE EN FORME, ET IL NE CHANGE AUCUN AIGUILLAGE.
    // Un 503 qui nomme sa cause reste traité comme transitoire — c'est délibéré : la saturation du
    // portillon de requêtes (`daemon/src/handlers/query.rs`) en est un, les deux réessais sont sa
    // respiration, et la cause des refus de lecture dit elle-même « réessayez ». Seul CHANGE le fait
    // que la phrase survive au message de passerelle.
    const cause = r.ok ? '' : causeNommeeParLeDemon(body);
    const tg = transientGatewayMsg(r.status, r.ok ? '' : body);   // ok=200 -> corps vérifié plus bas (cas HTML servi en 200)
    if (tg) {
      if (attempt < backoffs.length) { await new Promise(res => setTimeout(res, backoffs[attempt])); continue; }
      // `P10.26-p` — UN CINQ CENT TROIS QUI NOMME SA CAUSE LA MONTRE, après ses deux réessais. La phrase de passerelle
      // la REMPLAÇAIT : toute surface qui lit le message (`fetchInto` et ses « erreur : … », les avis) disait
      // « Service momentanément indisponible » là où le démon écrit précisément ce qui n'est pas servi, et souvent
      // que réessayer n'y changera rien (base en lecture seule, pleine ou verrouillée ; nom non vérifié). Le
      // message devient la cause ENTIÈRE ; un cinq cent trois qui ne nomme rien (page de passerelle, corps vide)
      // garde la phrase d'avant. Même règle pour les cinq cent deux que le démon nomme (découverte OIDC,
      // `daemon/src/handlers/idp.rs`) : c'est sa phrase, pas celle d'un intermédiaire.
      throw avecLeStatutDuRefus(avecLaCauseDuDemon(new Error(cause || tg), cause), r.status);
    }
    if (!r.ok) throw avecLeStatutDuRefus(avecLaCauseDuDemon(new Error(r.status + (body ? ' ' + body.slice(0, 200) : '')), cause), r.status);
    if (!body) throw avecLeStatutDuRefus(new Error('réponse vide du serveur (timeout proxy ou requête trop lourde ?)'), r.status);
    try { return JSON.parse(body); }
    catch {
      const tg2 = transientGatewayMsg(r.status, body);   // corps HTML « no available server » servi en 200 -> transitoire
      if (tg2) { if (attempt < backoffs.length) { await new Promise(res => setTimeout(res, backoffs[attempt])); continue; } throw avecLeStatutDuRefus(new Error(tg2), r.status); }
      throw avecLeStatutDuRefus(new Error('réponse non-JSON (tronquée ? timeout ?) : ' + body.slice(0, 120)), r.status);
    }
  }
}

// `P10.22-b` — UNE RÉPONSE QUI NE VIENT PAS (LISIBLEMENT) DU DÉMON SE NOMME, AU POINT COMMUN.
//
// CE QUE LE DÉMON SERT À UNE MUTATION, RELU GESTIONNAIRE PAR GESTIONNAIRE (daemon/src/server/groupes_de_routes.rs,
// puis chaque gestionnaire POST/PUT/DELETE ; le témoin 109 refait la dérivation) : un succès est un corps JSON,
// ou un corps VIDE (deux cent quatre — `incident_set`, `case_update`, `ack`, `view_update`… ) ; un refus est un
// objet JSON `{error}` (`err_json`) ou, sur quelques gestionnaires, du TEXTE BRUT (`sources.rs`, `tenants.rs`,
// le filtre d'hôte d'`auth.rs`). JAMAIS de HTML, et jamais un cinq cent deux ni un cinq cent quatre sans cause
// nommée — le seul cinq cent deux du démon passe par `err_json`. Ce qui sort de ces formes vient d'un
// INTERMÉDIAIRE (passerelle, page d'accès, proxy qui coupe), ou a été abîmé en route.
//
// DEUX NATURES, ET RIEN D'AUTRE :
//   · `page_de_passerelle` — un corps HTML ou « no available server », QUEL QUE SOIT le statut ; un cinq cent
//     deux ou un cinq cent quatre qui ne nomme aucune cause ; un cinq cent trois à corps VIDE ;
//   · `corps_illisible` — un deux cents dont le corps non vide n'est pas du JSON (tronqué en route ?).
// Rend '' pour tout le reste — un refus nommé, un refus du démon en texte brut (sa phrase reste la cause), un
// succès JSON, un corps vide — : ce qui n'est pas reconnu garde exactement le chemin d'avant.
// CE QU'ELLE NE SAIT PAS DIRE : si le démon a PRIS la demande. Un cinq cent quatre peut suivre une écriture
// faite ; une page d'accès servie en deux cents ne l'a sans doute jamais laissée passer. Les faces le disent :
// rien ici ne l'établit.
function natureDeLaReponseHorsDemon(statut, corps) {
  const texte = String(corps || '');
  const vide = !texte.trim();
  if (statut >= 200 && statut < 300) {
    if (vide) return '';
    try { JSON.parse(texte); return ''; } catch { /* rangé ci-dessous */ }
    return RESSEMBLE_A_UNE_PAGE_DE_PASSERELLE.test(texte) ? 'page_de_passerelle' : 'corps_illisible';
  }
  if (causeNommeeParLeDemon(texte)) return '';
  if (RESSEMBLE_A_UNE_PAGE_DE_PASSERELLE.test(texte)) return 'page_de_passerelle';
  if (statut === 502 || statut === 504) return 'page_de_passerelle';
  if (statut === 503 && vide) return 'page_de_passerelle';
  return '';
}
// Les deux faces, FR et EN côte à côte. Aucune ne colle le corps reçu : du HTML n'est pas un texte d'écran, et un
// corps tronqué ne dit rien de sûr. Chacune dit ce que la console NE SAIT PAS, et le geste prudent qui en découle.
const MOTS_DE_LA_REPONSE_HORS_DEMON = {
  page_de_passerelle: {
    fr: "Réponse d'une PASSERELLE, pas du démon : le service est peut-être momentanément injoignable, ou un intermédiaire a répondu à sa place. Rien ici n'établit ce que le démon a fait de cette demande — vérifie son effet avant de la rejouer.",
    en: 'Answer from a GATEWAY, not from the daemon: the service may be momentarily unreachable, or an intermediary answered in its place. Nothing here establishes what the daemon did with this request — check its effect before replaying it.' },
  corps_illisible: {
    fr: "Réponse ILLISIBLE : un statut de succès est arrivé, mais son corps n'est pas du JSON (tronqué en route ?). Rien ici n'établit ce que le démon a fait de cette demande — vérifie son effet avant de la rejouer.",
    en: 'UNREADABLE answer: a success status arrived, but its body is not JSON (truncated on the way?). Nothing here establishes what the daemon did with this request — check its effect before replaying it.' },
};
const motDeLaReponseHorsDemon = (nature) => (LANG === 'en' ? MOTS_DE_LA_REPONSE_HORS_DEMON[nature].en : MOTS_DE_LA_REPONSE_HORS_DEMON[nature].fr);
// Le refus porte sa nature (`reponseHorsDemon`) à côté du statut : une surface qui sait dire l'absence de son
// corps de succès la reconnaît sans relire un message que ce module fabrique pour être lu.
function refusHorsDemon(nature, statut) {
  const refus = new Error(motDeLaReponseHorsDemon(nature));
  refus.reponseHorsDemon = nature;
  refus.statutDuRefus = statut;
  return refus;
}

// apiSend — sœur MUTANTE de api() (POST/PUT/DELETE vers /api, corps JSON optionnel). MÊME forme de requête
// que les sites inline qu'elle remplace : on ne pose QUE Content-Type quand il y a un corps ; le X-CSRF-Token
// (+ X-Plume-Tenant/Env) est ajouté AUTOMATIQUEMENT par le wrapper window.fetch global -> requête byte-identique.
// Erreur lisible IDENTIQUE à api() sur !ok (statut + jusqu'à 200 car. du corps serveur). Corps vide (204 /
// StatusCode sans JSON, ex panel_update) -> null : une mutation renvoie souvent un corps vide, on ne JETTE PAS
// comme api() (qui, lui, sert des GET toujours-JSON).
// `P10.22-b` — UN DEUX CENTS NON JSON N'EST PLUS UN SUCCÈS. Il rendait `null`, comme un corps vide légitime, et
// toute surface qui ne lit pas le corps annonçait son succès sur une page de passerelle (« Incident déclaré »,
// « supprimé », « rétention mise à jour », la préférence tenue pour acquittée…). Il JETTE désormais un refus
// NOMMÉ (`refusHorsDemon`) ; le cinq cents de passerelle aussi, au lieu de coller son HTML comme cause. Le corps
// VIDE, lui, reste `null` : c'est le succès des routes à deux cent quatre.
async function apiSend(path, method = 'POST', body) {
  const init = { method };
  if (body !== undefined) { init.headers = { 'Content-Type': 'application/json' }; init.body = JSON.stringify(body); }
  const r = await fetch('/api' + path, init);
  const text = await r.text().catch(() => '');   // texte d'abord -> corps d'erreur dispo + gère réponse vide
  const horsDemon = natureDeLaReponseHorsDemon(r.status, text);
  // `P10.20-b` — MÊME PORTAGE QUE DANS `api()` : la coupe à 200 caractères tronque les phrases longues que
  // le démon écrit pour être lues (un refus de lecture en fait 250 et plus), et le JSON brut n'est pas un
  // texte d'écran. Le message ne bouge pas ; la cause voyage à côté.
  // `P10.22-n` — LE STATUT VOYAGE AUSSI À CÔTÉ DU MESSAGE. Sur une même route, le démon sépare par lui des
  // refus qui ne disent pas la même chose de l'utilisateur : `mfa_disable` rend quatre cent un quand le
  // code est refusé, cinq cent trois quand le code est bon et que la base n'a pas pris l'écriture. Le
  // relire dans le message composé serait analyser une chaîne que ce module fabrique pour être lue.
  // Le délai d'un refus freiné (en-tête de nouvel essai, en secondes) voyage de même : le second facteur
  // freiné le sert, et « réessaie plus tard » ne dit pas quand.
  if (!r.ok) {
    const refus = horsDemon ? refusHorsDemon(horsDemon, r.status)
      : avecLaCauseDuDemon(new Error(r.status + (text ? ' ' + text.slice(0, 200) : '')), causeNommeeParLeDemon(text));
    refus.statutDuRefus = r.status;
    const objet = horsDemon ? null : objetDuRefusNomme(text);
    if (objet) refus.objetDuRefus = objet;   // `P10.25-i`
    const delai = r.headers && typeof r.headers.get === 'function' ? parseInt(r.headers.get('retry-after') || '', 10) : NaN;
    if (Number.isFinite(delai) && delai > 0) refus.delaiDuRefus = delai;
    throw refus;
  }
  if (horsDemon) throw refusHorsDemon(horsDemon, r.status);
  if (!text.trim()) return null;
  return JSON.parse(text);   // lisible : `natureDeLaReponseHorsDemon` vient de l'établir
}

// `P10.22-b` — LES SURFACES QUI LISENT LE CORPS DE SUCCÈS DE LEUR ROUTE ET SAVENT DIRE SON ABSENCE. Six gestes lisent
// le seul corps de succès que leur route sert (`{attached}`, `{id}`, `{ok}`, `{ok, recovery_codes}`) et portent
// déjà une face « rien ici n'établit » pour un deux cents qui ne le porte pas : l'attache d'un runbook et l'étape
// « réponse » (`web/cases.js`), le formulaire du panneau Réponse (`web/detection_admin.js`), le geste « bannir »
// (`web/viz.js`), l'activation et la désactivation de la MFA (`web/idp.js`). Pour eux, un deux cents sans corps
// lisible n'est pas un refus — le démon a pu prendre le geste — et le cadre de leur refus l'écrirait « REFUSÉ » ou
// « le démon a refusé ce geste ». Ce prédicat le reconnaît dans leur `catch`, qui retombe alors sur la face
// « non établie » ; tout autre refus (cinq cents de passerelle compris) garde son chemin. L'appel reste un
// `apiSend('<chemin>', '<méthode>', …)` LITTÉRAL : la garde des routes sensibles le dérive à son site.
function unDeuxCentsSansCorpsLisible(e) {
  return !!(e && e.reponseHorsDemon && e.statutDuRefus >= 200 && e.statutDuRefus < 300);
}
// `P10.25-x` — UNE DEMANDE QUI N'A PAS ABOUTI N'EST PAS UN REFUS. `apiSend` pose `statutDuRefus` sur TOUT ce qu'il
// jette après avoir reçu une réponse — refus du démon, en JSON ou en texte brut, comme réponse de passerelle. Une
// erreur qui n'en porte pas vient du transport : `fetch` rejeté (réseau coupé, requête abandonnée), aucune réponse
// lue. Le démon n'a rien refusé, et rien ici ne dit s'il a pris le geste avant que la réponse ne se perde : une face
// qui dirait « le démon a refusé » ou « NON supprimé » affirmerait ce que personne n'a vu. Les trois gestes des
// comptes (création, modification, suppression) lisent ce prédicat, et la forme partagée du refus d'un geste
// (ci-dessous) aussi. Il vaut pour une erreur jetée par `apiSend` comme par `api()`, qui pose le même statut depuis
// `P10.26-o`.
function laDemandeNAPasAbouti(e) {
  return !(e && typeof e.statutDuRefus === 'number');
}

// `P10.26-o` — LE REFUS DU RÔLE, ET LUI SEUL. `rbac_gate` (daemon/src/rbac.rs) refuse une route d'administration en
// quatre cent trois TEXTE, par l'une de ces quatre phrases (la quatrième ne sert qu'une écriture). C'est le SEUL
// refus qui établit qu'un compte n'administre pas : un refus de l'annuaire, une lecture refusée par la base, une
// page de passerelle ou une demande qui n'aboutit pas ne disent rien de son rôle. Chaque phrase est un MOTIF ancré aux
// deux bouts (reconnue entière, rien de plus), comme les ouvertures des refus nommés ; le témoin 115 relit les
// phrases dans le démon et exige qu'à chacune réponde exactement un motif, et à chaque motif exactement une phrase.
const REFUS_DU_ROLE_SUR_UNE_ROUTE_D_ADMINISTRATION = Object.freeze([
  /^réservé à l'administrateur$/u,
  /^rôle client confiné aux routes client-read$/u,
  /^capacité retirée à ce rôle \(permission refusée\)$/u,
  /^lecture seule \(rôle viewer\)$/u,
]);
function leRefusEstCeluiDuRole(e) {
  if (!e || e.statutDuRefus !== 403 || e.causeDuDemon) return false;   // le refus du rôle est un TEXTE, jamais un objet nommé
  const phrase = phraseDuRefusDuDemon(e);
  return REFUS_DU_ROLE_SUR_UNE_ROUTE_D_ADMINISTRATION.some(motif => motif.test(phrase));
}

// =================================================================================================
// `P10.26-q` — LE REFUS D'UN GESTE D'ÉCRITURE A UNE FORME, UNE SEULE, ET ELLE RESTE SOUS LES YEUX.
//
// CE QUE LE DÉMON SERT DEPUIS `P10.25-e` ET `P10.25-f` : quand la base ne valide pas la transaction d'un geste, il
// rend cinq cent trois JSON `{error: <cause>, id}` et la cause dit ce qui N'A PAS changé — « JETON NON FRAPPÉ »,
// « JETON NON RÉVOQUÉ », « MASQUE DE CHAMP INCHANGÉ », « FOURNISSEUR D'IDENTITÉ INCHANGÉ », « SOURCE PUSH NON
// CRÉÉE », « ENGAGEMENT NON CRÉÉ », « ENGAGEMENT NON CLOS », « MODE INCHANGÉ » (et, avant eux, les comptes et les
// tables d'enrichissement). Toutes s'ouvrent par la même phrase, relue ici au caractère près.
// CE QUE LA CONSOLE EN FAISAIT, MESURÉ AVANT CE LOT (témoin 115) : un AVIS qui s'efface au bout de trois secondes,
// « 503 {"error":"JETON NON FRAPPÉ : la base n'a pas validé la transaction… » — le JSON brut coupé à deux cents
// caractères, qui n'atteignait jamais ce qui reste vrai (le jeton qui authentifie toujours, les masques servis
// d'avant) ; le formulaire d'un fournisseur d'identité l'écrivait derrière « erreur : » ; la bascule du mode de
// réponse n'avait AUCUNE capture — rien n'était dit, et la promesse rejetée partait sans être traitée.
// LA FORME : un PUITS par surface, posé à côté de ce qu'elle liste, hors de ce qu'elle repeint ; la phrase dans un
// nœud texte ENTIER (FR et EN côte à côte), la cause servie ENTIÈRE dans un second nœud, telle quelle.
// `data-refus-d-un-geste` porte la nature (marque de POSE pour le harnais) :
//   · `ecriture_non_validee` — cinq cent trois dont la cause s'ouvre par la phrase du COMMIT refusé : RIEN N'A
//     CHANGÉ, c'est le démon qui l'établit, et la face le dit sans accuser personne ;
//   · `demande_non_aboutie` — aucune réponse lue (`laDemandeNAPasAbouti`) : ni refus ni effet établis ;
//   · `reponse_hors_demon` — une passerelle a répondu (`apiSend` l'a nommée) : sa propre phrase ;
//   · `refus_sans_cause` — un refus dont le corps est vide : le statut, rien d'autre n'est inventé ;
//   · `refus_nomme` — tout autre refus : la phrase que le démon a écrite, en JSON ou en texte brut.
// =================================================================================================
// L'en-tête est en capitales, et peut porter une apostrophe (« FOURNISSEUR D'IDENTITÉ ») ou une virgule (« CONNECTEUR
// NON SUPPRIMÉ, SES CLÉS DE LIVRAISON NE SONT PAS RÉVOQUÉES ») ; la phrase qui suit est lue au caractère près.
const OUVERTURE_DE_L_ECRITURE_NON_VALIDEE = /^[\p{Lu}', ]+ : la base n'a pas validé la transaction \(COMMIT refusé\) et l'a annulée(?![\p{L}\p{N}])/u;
function natureDuRefusDUnGeste(e) {
  if (e && e.reponseHorsDemon) return 'reponse_hors_demon';
  if (laDemandeNAPasAbouti(e)) return 'demande_non_aboutie';
  const cause = e.causeDuDemon ? String(e.causeDuDemon).trim() : '';
  if (e.statutDuRefus === 503 && OUVERTURE_DE_L_ECRITURE_NON_VALIDEE.test(cause)) return 'ecriture_non_validee';
  if (!cause && /^\d{3}$/.test(String(e.message || '').trim())) return 'refus_sans_cause';
  return 'refus_nomme';
}
const MOTS_DU_REFUS_D_UN_GESTE = {
  ecriture_non_validee: {
    fr: "RIEN N'A CHANGÉ : la base n'a pas validé l'écriture et l'a annulée. Le démon en nomme la cause —",
    en: 'NOTHING CHANGED: the database did not commit the write and rolled it back. The daemon names the cause —' },
  demande_non_aboutie: {
    fr: "Geste NON confirmé : la demande n'a pas abouti, et rien ici n'établit s'il a été pris — vérifier son effet avant de le rejouer. Cause —",
    en: 'Action NOT confirmed: the request did not complete, and nothing here establishes whether it was taken — check its effect before replaying it. Cause —' },
  refus_sans_cause: {
    fr: 'Le démon a refusé ce geste sans en nommer la cause — statut',
    en: 'The daemon refused this action without naming the cause — status' },
  refus_nomme: {
    fr: 'Le démon a refusé ce geste et en nomme la cause —',
    en: 'The daemon refused this action and names the cause —' },
};
const motDuRefusDUnGeste = (nature) => (LANG === 'en' ? MOTS_DU_REFUS_D_UN_GESTE[nature].en : MOTS_DU_REFUS_D_UN_GESTE[nature].fr);
// Le puits d'une surface : UN par surface (`surface` le nomme), enfant de `parent`, posé avant `avant` (ou en fin).
// Retrouvé par son nom au geste suivant ; hors de l'hôte que la surface repeint, il survit au rechargement de sa liste.
function puitsDuRefusDUnGeste(parent, surface, avant) {
  if (!parent) return null;
  let puits = [...parent.children].find(n => n.getAttribute && n.getAttribute('data-puits-du-refus-d-un-geste') === surface) || null;
  if (!puits) {
    puits = document.createElement('div'); puits.className = 'bad'; puits.hidden = true;
    puits.setAttribute('role', 'alert');
    puits.style.cssText = 'margin:0 0 8px;font-size:12px';
    puits.dataset.puitsDuRefusDUnGeste = surface;
    if (avant && avant.parentNode === parent) parent.insertBefore(puits, avant); else parent.appendChild(puits);
  }
  return puits;
}
// Un refus précédent s'efface au geste suivant : il ne décrit plus la demande en cours.
function effacerLeRefusDUnGeste(puits) {
  if (!puits) return;
  puits.hidden = true; puits.replaceChildren(); delete puits.dataset.refusDUnGeste;
}
// Rend la nature peinte ('' sans puits).
function peindreLeRefusDUnGeste(puits, e) {
  if (!puits) return '';
  const nature = natureDuRefusDUnGeste(e);
  const dit = document.createElement('span');
  if (nature === 'reponse_hors_demon') {
    dit.textContent = String(e.message || '');
    puits.replaceChildren(dit);
  } else {
    dit.textContent = motDuRefusDUnGeste(nature);
    const cause = nature === 'demande_non_aboutie' ? String((e && e.message) || e)
      : nature === 'refus_sans_cause' ? String(e.statutDuRefus) : phraseDuRefusDuDemon(e);
    puits.replaceChildren(dit, document.createTextNode(' « ' + cause.trim() + ' »'));
  }
  puits.dataset.refusDUnGeste = nature;
  puits.hidden = false;
  return nature;
}

function muted(t) { return Object.assign(document.createElement('div'), { className: 'muted', textContent: t }); }

// fetchInto — boilerplate GET-and-render partagé (audit H2). Remplace le motif copié ~partout :
//   let d; try { d = await api('/x'); } catch (e) { host.replaceChildren(muted('erreur : '+…)); return; }
// -> const d = await fetchInto(host, '/x'); if (!d) return;
// Rend le MÊME message d'erreur (« erreur : » + message/erreur) DANS `host` et renvoie null sur échec
// (l'appelant early-return sur !d). Succès -> renvoie le JSON d'api() (toujours truthy pour ces endpoints).
// `P10.27-c` — le préfixe suit la langue de l'écran (« error: » sous `LANG='en'`).
async function fetchInto(host, path){ try { return await api(path); } catch(e){ host.replaceChildren(muted(motDUneLectureQuiNEstPasServie('prefixe_de_la_lecture_refusee')+((e&&e.message)||e))); return null; } }

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

// =================================================================================================
// `P10.21-a`, déplacé ici par `P10.21-x` — LA SUITE D'UNE PAGE SERVIE, LUE UNE FOIS POUR TOUTE LA CONSOLE.
//
// CE QUE LE DÉMON SERT. Deux routes posent `has_more`, et aucune ne dit « d'autres lignes EXISTENT » :
//   · `ledger_page` (daemon/src/handlers/admin_ui.rs) : `has_more` vaut `!next_cursor.is_null()`, et le
//     curseur n'est servi que sur une page PLEINE — un registre de cinquante entrées exactement le rend
//     vrai sans qu'aucune ligne ne soit derrière ;
//   · `keyset_finalize` (daemon/src/handlers/query.rs), pour le parcours par curseur de l'Explore :
//     `has_more` vaut « page pleine OU tronquée au plafond, ET curseur formé ». Il est FAUX sur une page
//     pleine dont le curseur n'a pas pu être formé (colonnes `ts`/`id` absentes : le démon préfère
//     s'arrêter que boucler), et il est ABSENT quand la compilation du curseur a échoué et que la page
//     est servie par décalage (`keyset_compile_failed`).
// Ce qui se lit en commun, et seulement ça : trois issues — une suite PEUT venir, le démon dit qu'il n'y
// en a pas, le démon n'a rien dit. Une valeur d'un autre type n'est ni une suite ni une fin.
//
// POURQUOI ICI, ET PLUS DANS `web/retention.js`. Le fabricant de pager, juste en dessous, lit désormais
// ces issues pour armer sa flèche « suivant » quand aucun total n'est servi ; or ce module ne peut pas
// importer `retention.js` — c'est la racine du graphe, que `retention.js` importe lui-même. Garder le
// discriminant là-bas aurait obligé à RÉÉCRIRE ses clés ici, c'est-à-dire à tenir deux fois le même
// vocabulaire.
// `P10.22-h` — LE NOM DIT CE QU'IL LIT. Il nommait le registre alors qu'il lit aussi la suite du parcours
// de l'Explore, qui n'est pas un registre : un lecteur qui cherchait ce que la ligne d'état de l'Explore
// fait de `has_more` ne pouvait pas le trouver par son nom. Il nomme désormais ce qui est commun aux trois
// vues — la suite SERVIE avec une page —, et il a été renommé partout en une fois, harnais compris.
// =================================================================================================
function cleDeLaSuiteServie(j) {
  if (!j || typeof j.has_more !== 'boolean') return 'suite_non_dite';
  return j.has_more ? 'il_en_existe_peut_etre_d_autres' : 'aucune_suite';
}
// LA FLÈCHE « SUIVANT » D'UN PARCOURS SANS TOTAL, PILOTÉE PAR LA SUITE SERVIE. Une suite servie l'offre,
// même sur une page que le plafond du démon a tronquée sous sa taille ; un « pas de suite » la retire,
// même sur une page pleine dont le curseur n'a pas pu être formé. Quand le démon n'a rien dit — ou
// qu'une vue ne sert aucune suite (alertes, tableaux de bord) —, la page pleine reste le seul indice, et
// c'est la règle d'avant, inchangée pour ces vues.
function laSuiteOffreLaPageSuivante(suite, servies, taille) {
  if (suite === 'il_en_existe_peut_etre_d_autres') return true;
  if (suite === 'aucune_suite') return false;
  return servies >= taille;
}

// `P10.24-z` — UNE PAGE AU-DELÀ DU TOTAL SE DIT TELLE, UNE FOIS POUR TOUTE LA CONSOLE.
//
// MESURÉ LE 2026-09-24 SUR LES MODULES RÉELS. Une page devient « au-delà du total » quand le compte arrive, ou
// change, APRÈS qu'elle a été atteinte : l'Explore atteint la page 2 par le curseur d'une page pleine, puis le
// compte dit trois résultats — la ligne d'état écrivait « 3 résultats · page 2 / 1 », le parcours par décalage
// « page 2/1 » ; un panneau de tableau de bord, une liste de journal ou les occurrences d'un groupe d'alertes
// dont le total baisse entre deux pages (purge, acquittement) y arrivent de même. Le pager n'y écrivait que
// « 3 · — ». CE QUI SE DIT ICI : la page, et la dernière page du total compté — sans cause devinée (le compte
// est-il arrivé tard, ou a-t-il baissé ?) que rien ici n'établit. Un total PLAFONNÉ n'établit aucune dernière
// page : il n'est jamais « dépassé ». Les faces sont côte à côte, choisies par `LANG` au moment d'écrire (le
// nœud est composé d'un nombre, le lexique ne l'atteindrait pas).
const MOTS_DE_LA_PAGE_AU_DELA_DU_TOTAL = {
  au_dela_de_la_derniere: {
    fr: 'page {page} au-delà de la dernière ({pages})',
    en: 'page {page} beyond the last one ({pages})' },
  page_vide_au_dela: {
    fr: 'page vide : elle est au-delà de la dernière page du total compté — ◀ pour revenir',
    en: 'empty page: it lies beyond the last page of the counted total — ◀ to go back' },
};
const pagesDuTotal = (total, taille) => Math.max(1, Math.ceil(total / taille));
function laPageEstAuDelaDuTotal(indexDePage, total, taille, totalPlafonne) {
  if (totalPlafonne) return false;
  if (!(typeof total === 'number' && total >= 0)) return false;
  if (!(taille > 0) || !(indexDePage > 0)) return false;
  return indexDePage >= pagesDuTotal(total, taille);
}
function motDeLaPageAuDelaDuTotal(indexDePage, total, taille) {
  const mots = MOTS_DE_LA_PAGE_AU_DELA_DU_TOTAL.au_dela_de_la_derniere;
  const valeurs = { page: indexDePage + 1, pages: pagesDuTotal(total, taille) };
  return (LANG === 'en' ? mots.en : mots.fr).replace(/\{(\w+)\}/g, (brut, nom) => (nom in valeurs ? String(valeurs[nom]) : brut));
}
// La phrase d'une liste dont le corps serait sinon une ABSENCE (« Aucune alerte… ») : une page vide au-delà du
// total n'établit rien sur ce que la liste porte. La clé est portée par le nœud (marque de POSE pour le harnais).
function noeudDeLaPageVideAuDelaDuTotal() {
  const noeud = document.createElement('div'); noeud.className = 'muted';
  const mots = MOTS_DE_LA_PAGE_AU_DELA_DU_TOTAL.page_vide_au_dela;
  noeud.textContent = LANG === 'en' ? mots.en : mots.fr;
  noeud.dataset.pageAuDelaDuTotal = 'page_vide_au_dela';
  return noeud;
}

// `P10.25-a` / `P10.25-n` — UNE PAGE VIDE DE RANG SUPÉRIEUR SE DIT DANS LE CORPS, SUR TOUTE SURFACE PAGINÉE.
//
// MESURÉ LE 2026-09-24 SUR LES MODULES RÉELS. La table paginée de l'Explore (`| table`, `| fields`, `| rex`, résultat
// non événementiel), la liste paginée partagée (`pagedList`) et un panneau de table de tableau de bord rendaient,
// sur une page vide de rang supérieur, le pager et un TABLEAU D'EN-TÊTES, sans une phrase : seul le pager disait
// « page 2 au-delà de la dernière (1) » — et rien du tout quand le total n'est pas compté (une liste paginée par
// curseur, comme le journal d'audit, dont la page pleine exacte mène à une page vide). Pas une fausse absence : un
// silence. La liste d'événements, elle, dit « page vide, fin du résultat » depuis `P10.22-d`.
//
// DEUX PHRASES, ET LE CHOIX ENTRE ELLES EST UN FAIT, PAS UNE DEVINETTE. Un total COMPTÉ (ni inconnu, ni plafonné)
// que la page dépasse : « au-delà de la dernière page du total compté » (`noeudDeLaPageVideAuDelaDuTotal`, la
// phrase des listes d'alertes). Sans total compté, cette phrase affirmerait un compte qui n'existe pas : la page
// vide venue après une page servie dit « fin du résultat » — la phrase de la liste d'événements, qui vit ici
// désormais pour n'être écrite qu'une fois. La première page n'est jamais concernée : chaque surface y garde sa
// phrase de fenêtre vide. Un saut direct sans rendu (fin NON établie) n'existe que dans l'Explore, qui le dit
// lui-même (`web/viz.js`).
const MOTS_DE_LA_FIN_DU_RESULTAT = {
  fr: 'page vide, fin du résultat — ◀ pour revenir',
  en: 'empty page, end of the result — ◀ to go back',
};
function noeudDeLaFinDuResultat() {
  const noeud = document.createElement('div'); noeud.className = 'muted';
  noeud.textContent = LANG === 'en' ? MOTS_DE_LA_FIN_DU_RESULTAT.en : MOTS_DE_LA_FIN_DU_RESULTAT.fr;
  noeud.dataset.pageVide = 'fin_du_resultat';   // marque de POSE (harnais), la même que celle de l'Explore
  return noeud;
}
// `P10.25-z` — UNE PAGE VIDE DANS LE TOTAL COMPTÉ N'EST PAS LA FIN DU RÉSULTAT : ELLE DIT L'ÉCART.
//
// MESURÉ LE 2026-09-24 SUR LES MODULES RÉELS. Une page de rang supérieur servie vide alors qu'un total compté place
// des lignes sur elle (son début est EN DEÇÀ du total) se disait « page vide, fin du résultat » — dans une liste
// paginée, dans un panneau de table, et dans l'Explore, qui choisit sa phrase ailleurs (`cleDeLaPageVide`,
// web/viz.js) mais sur la même partition. Le compte promet des lignes que la page ne rend pas : dire « fin » sous
// un pager qui annonce trente lignes affirme une fin que le compte contredit. Le cas n'est pas théorique : un
// compte est une lecture, la page une autre, et des lignes retirées entre les deux (rétention, purge) suffisent.
//
// CE QUI SE DIT : l'écart lui-même — le compte place des lignes sur cette page, la lecture n'en rend aucune, des
// lignes comptées ont disparu entre les deux —, sans cause devinée au-delà (rien ici ne dit lesquelles ni
// pourquoi), sans accuser, et le retour. Un total PLAFONNÉ est un compte arrêté à sa borne : il établit AU MOINS
// ce nombre de lignes, et une page qui commence en deçà est dans l'écart de la même façon (le nombre porte alors
// son « + », comme dans le pager). Au-delà du total, ou sans total, les deux phrases d'avant restent vraies.
const MOTS_DE_LA_PAGE_VIDE_DANS_LE_TOTAL = {
  fr: 'page vide DANS le total compté ({total}) : le compte place des lignes sur cette page, la lecture n\'en rend aucune — des lignes comptées ont disparu entre le compte et la page — ◀ pour revenir',
  en: 'empty page WITHIN the counted total ({total}): the count places rows on this page, the read returns none — counted rows disappeared between the count and the page — ◀ to go back',
};
// Le début de la page est-il EN DEÇÀ d'un total compté (exact ou plafonné) ? Faux sans total, ou sur un total nul.
function laPageEstDansLeTotal(indexDePage, total, taille) {
  if (!(typeof total === 'number' && total > 0)) return false;
  if (!(taille > 0) || !(indexDePage >= 0)) return false;
  return indexDePage * taille < total;
}
function noeudDeLaPageVideDansLeTotal(total, totalPlafonne) {
  const noeud = document.createElement('div'); noeud.className = 'muted';
  const valeur = String(total) + (totalPlafonne ? '+' : '');
  noeud.textContent = (LANG === 'en' ? MOTS_DE_LA_PAGE_VIDE_DANS_LE_TOTAL.en : MOTS_DE_LA_PAGE_VIDE_DANS_LE_TOTAL.fr).replace('{total}', () => valeur);
  noeud.dataset.pageVide = 'dans_le_total';   // marque de POSE (harnais), lue comme celle de la fin du résultat
  return noeud;
}
// Rend le nœud de la phrase d'une page vide de rang supérieur, ou `null` sur la première page.
function noeudDeLaPageVideDeRangSuperieur(indexDePage, total, taille, totalPlafonne) {
  if (!(indexDePage > 0)) return null;
  if (laPageEstAuDelaDuTotal(indexDePage, total, taille, totalPlafonne)) return noeudDeLaPageVideAuDelaDuTotal();
  if (laPageEstDansLeTotal(indexDePage, total, taille)) return noeudDeLaPageVideDansLeTotal(total, totalPlafonne);   // `P10.25-z`
  return noeudDeLaFinDuResultat();
}

function makePager(state, onGo) {
  const PS = state.pageSize, total = state.total, numbered = total >= 0;
  const pages = numbered ? Math.max(1, Math.ceil(total / PS)) : state.page + (state.shown >= PS ? 2 : 1);
  // `P10.22-d` — « UNE SEULE PAGE » NE RETIRE LE PAGER QUE SUR LA PREMIÈRE. Une page de rang supérieur au
  // total — vide, atteinte par ▶ avant que le compte n'arrive et ne dise « une page » — garde sa flèche ◀
  // et le numéro 1 : sans eux, elle était un cul-de-sac que seule une nouvelle recherche quittait.
  if (numbered && pages <= 1 && state.page <= 0) return null;   // une seule page, et on y est -> pas de pager
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
  // `P10.21-x` — sans total, la flèche suit la suite SERVIE (`state.suite`, une clé de
  // `cleDeLaSuiteServie`) et non plus la seule page pleine ; une vue qui n'en pose aucune garde la
  // règle d'avant.
  next.disabled = numbered ? state.page >= pages - 1 : !laSuiteOffreLaPageSuivante(state.suite, state.shown, PS);
  next.onclick = () => onGo(state.page + 1);
  wrap.appendChild(next);
  const tot = document.createElement('span'); tot.className = 'evtot';
  // COUNT BORNÉ : `state.totalCapped` -> le serveur a plafonné le total (> 10 000) -> on rend « 10 000+ »
  // (le total exact resterait honnête mais coûterait un scan complet). Absent/false -> total exact, inchangé.
  const totLbl = total >= 0 ? (total + (state.totalCapped ? '+' : '') + ' · ') : '';
  // `P10.22-d` — une page VIDE ne rend pas une plage à l'envers (« 101–100 ») : un tiret, dans les deux langues.
  // `P10.24-z` — une page AU-DELÀ du total compté le dit, et garde sa plage si des lignes y sont servies.
  const plage = state.shown > 0 ? (from + 1) + '–' + (from + state.shown) : '';
  const auDela = numbered && laPageEstAuDelaDuTotal(state.page, total, PS, state.totalCapped);
  tot.textContent = totLbl + (auDela ? motDeLaPageAuDelaDuTotal(state.page, total, PS) + (plage ? ' · ' + plage : '') : (plage || '—'));
  if (auDela) tot.dataset.pageAuDelaDuTotal = 'au_dela_de_la_derniere';
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
//   - 'server' : `fetchPage({limit,offset,sort,dir})` -> {rows,total,suite?} ; page/tri => re-fetch (le
//     navigateur ne tient qu'une page). Grand volume. `suite` (facultatif, `P10.21-x`) = la clé que
//     `cleDeLaSuiteServie` rend du corps servi : elle arme la flèche « suivant » quand `total` manque.
// opts.columns=[{key,label,sortable,align:'l|c|r',render:(row)=>Node|string,sortVal:(row)=>v}] (rendu en
// <table.qtable>) OU opts.renderRow:(row)=>Node (liste libre, ex. lignes badge/action). `render`/`renderRow`
// renvoient des NŒUDS -> badges & boutons d'action survivent. opts: {mode,pageSize=50,rows,fetchPage,columns,
// renderRow,sort:{key,dir},emptyText,onRowClick}. Renvoie {reload,state}.
// `opts.storeKey` (facultatif) = L'IDENTITÉ DE CETTE LISTE, stable d'un rendu à l'autre — la même clé
// de rangement que le regroupement emploie déjà (`opts.group.storeKey`, qui vaut identité à lui seul).
// Cette identité, et elle seule, arme la mémoire de recherche de `P11.18-z` : sans elle, la liste n'a
// aucune mémoire et se comporte exactement comme avant cette clé.
// `P11.15-a` — LA LARGEUR QU'UNE MAIN CHOISIT SURVIT AU REDESSIN, ET LE GESTE EST LE MÊME PARTOUT.
// Mesuré le 2026-08-27 : la poignée d'élargissement n'existait que sur la table des résultats de requête,
// et la largeur choisie vivait dans une variable locale reconstruite à chaque redessin — perdue au tri,
// à la page suivante, au rechargement. Ici vit le geste UNIQUE, appelé par les deux fabriques (`pagedList`
// et `tableEl` de viz.js). Ce qu'il retient est PAR PERSONNE (arbitrage de `P11.18-q`, repris tel quel :
// la table n'a aucune fente pour une largeur, et une largeur d'écran n'appartient pas à l'objet partagé),
// sous UNE clé de préférence (`colw`) qui porte { <identité de table>: { <nom de colonne>: px } } — par
// NOM de colonne, pas par position, pour survivre au réordonnancement et au masquage.
// LE MAGASIN EST BRANCHÉ, PAS IMPORTÉ : `prefs.js` importe ce module, donc ce module ne peut pas
// l'importer en retour. Tant que rien n'est branché, le stockage du site tient le rôle (même contrat, une
// durabilité par navigateur) ; `prefs.js` se branche à son chargement et apporte la durabilité par compte.
let magasinDeLargeurs = null;
export function brancherLeMagasinDeLargeurs(magasin) { magasinDeLargeurs = magasin; }
const CLE_DE_STOCKAGE_DES_LARGEURS = 'plume.colw';
function toutesLesLargeurs() {
  if (magasinDeLargeurs) { const v = magasinDeLargeurs.lire(); return v && typeof v === 'object' ? v : {}; }
  try { const v = JSON.parse(lireLeStockageDuSite(CLE_DE_STOCKAGE_DES_LARGEURS) || '{}'); return v && typeof v === 'object' ? v : {}; } catch (e) { return {}; }
}
function ecrireToutesLesLargeurs(tout) {
  if (magasinDeLargeurs) { magasinDeLargeurs.ecrire(tout); return; }
  ecrireSansDireLeRefus(CLE_DE_STOCKAGE_DES_LARGEURS, JSON.stringify(tout), RAISONS_DE_SILENCE.CONVENANCE_PAR_NAVIGATEUR);
}
export const LARGEUR_MINIMALE_DE_COLONNE = 40;
export function largeursDeColonnes(identite) {
  const cle = identite ? String(identite) : '';
  const memoire = {};   // sans identité : la largeur survit au redessin de CETTE table, pas au rechargement
  const lues = () => (cle ? (toutesLesLargeurs()[cle] || {}) : memoire);
  const soi = {
    lire(nom) { const px = Number(lues()[nom]); return Number.isFinite(px) && px >= LARGEUR_MINIMALE_DE_COLONNE ? px : undefined; },
    poser(nom, px) {
      const v = Math.max(LARGEUR_MINIMALE_DE_COLONNE, Math.round(Number(px) || 0));
      if (!cle) { memoire[nom] = v; return; }
      const tout = toutesLesLargeurs(); tout[cle] = Object.assign({}, tout[cle] || {}, { [nom]: v }); ecrireToutesLesLargeurs(tout);
    },
    appliquer(th, nom) { const px = soi.lire(nom); if (px) th.style.width = px + 'px'; },
    // La poignée : une bande à droite de l'en-tête ; glisser change la largeur pendant le geste et la
    // POSE au relâchement (une seule écriture par geste, pas une par pixel).
    poignee(th, nom) {
      const rsz = document.createElement('span'); rsz.className = 'rsz'; th.appendChild(rsz);
      rsz.onmousedown = e => {
        e.preventDefault(); e.stopPropagation();
        // `offsetWidth` est un nombre dans un navigateur ; ailleurs (une boîte non mesurée) il vaut 0, jamais NaN.
        const x0 = e.clientX, w0 = Number(th.offsetWidth) || 0; let w = w0;
        const mv = ev => { w = Math.max(LARGEUR_MINIMALE_DE_COLONNE, w0 + ev.clientX - x0); th.style.width = w + 'px'; };
        const up = () => { document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up); soi.poser(nom, w); };
        document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
      };
      return rsz;
    },
  };
  return soi;
}

function pagedList(host, opts) {
  const pageSize = opts.pageSize || 50;
  const state = { page: 0, pageSize, total: 0, shown: 0 };
  const columns = opts.columns || null;
  // `P11.15-a` — les largeurs choisies : par personne quand la liste a une identité (`storeKey` ou l'id
  // de son hôte), sinon pour la vie de cette liste (elles survivent quand même au tri et à la page).
  const largeurs = largeursDeColonnes(opts.storeKey || (host && host.id) || '');
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
        // un clic sur la poignée n'est pas un tri
        th.onclick = e => { if (e && e.target && e.target.classList && e.target.classList.contains('rsz')) return; if (sort && sort.key === c.key) sort.dir = -sort.dir; else sort = { key: c.key, dir: 1 }; state.page = 0; reload(); };
      }
      largeurs.appliquer(th, c.key); largeurs.poignee(th, c.key);   // `P11.15-a`
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
    // `P10.25-n` — UNE PAGE DE RANG SUPÉRIEUR SERVIE VIDE DIT CE QU'ELLE EST, À LA PLACE D'UN TABLEAU D'EN-TÊTES, et
    // garde son retour. `shown` compte les lignes SERVIES : une page que la recherche a vidée n'est pas une page vide.
    const pageVide = (!rows.length && !state.shown) ? noeudDeLaPageVideDeRangSuperieur(state.page, state.total, state.pageSize, state.totalCapped) : null;
    if (pageVide) {
      cible.appendChild(pageVide);
      const retour = makePager(state, go); if (retour) cible.appendChild(retour);
      return;
    }
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
    catch (e) { cible.replaceChildren(muted(motDUneLectureQuiNEstPasServie('prefixe_de_la_lecture_refusee') + (e && e.message ? e.message : e))); return; }   // `P10.27-c`
    const rows = (r && r.rows) || [];
    // `P10.21-x` — SANS TOTAL SERVI, LA SUITE SERVIE DÉCIDE S'IL Y A UNE PAGE SUIVANTE. Le repli d'avant
    // (`total` = lignes servies) faisait de toute page une page UNIQUE : aucun pager n'était rendu, et une
    // page pleine que la vue venait de DIRE (« un curseur de suite est servi ») n'était pas atteignable.
    // Une vue qui rend `suite` (une clé de `cleDeLaSuiteServie`) passe donc en pager NON NUMÉROTÉ
    // (`total` = -1, « inconnu ») dès qu'une page suivante est offerte ou qu'on n'est plus sur la première ;
    // sinon — une seule page, ou une vue qui ne sert aucune suite — la règle d'avant tient.
    state.suite = (r && typeof r.suite === 'string') ? r.suite : undefined;
    if (r && typeof r.total === 'number') state.total = r.total;
    else if (state.suite !== undefined && (state.page > 0 || laSuiteOffreLaPageSuivante(state.suite, rows.length, state.pageSize))) state.total = -1;
    else state.total = rows.length;
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
//       porte (`to`) ; `GET /api/ledger` la porte depuis `P11.18-t` (`until_ts`). Le mécanisme reste :
//       quand elle manque, une plage dont la FIN est antérieure à maintenant est REFUSÉE, et le refus
//       nomme la raison de l'APPELANT — écrite là où elle est vraie, jamais ici. Aujourd'hui aucun des
//       quatre consommateurs n'est dans ce cas ; la porte le dirait le jour où l'un y retomberait.
//
// CE QUE CE PARTAGE NE FAIT PAS, écrit plutôt que tu : il ne fond pas les deux PRÉSENTATIONS en une.
// Elles existent toutes deux, sont toutes deux déjà stylées, et chacune est celle que sa vue offre
// déjà. Ce qui a fondu, c'est ce qui était réellement écrit deux fois : lire, refuser, écrire.
// ==================================================================================================


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
    libelle: k => { const n = nomDeTechnique(k); return n.nom ? k + ' — ' + n.nom : k; },
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

// `P4.13-e` — LA DIMENSION CHOISIE, RETENUE POUR LA SESSION. Clé de choix -> dimension, posée par le geste
// et lue par la repeinte. Elle DOUBLE le magasin, elle ne le remplace pas : le magasin porte le choix d'un
// chargement à l'autre, celle-ci le porte d'une repeinte à l'autre quand le navigateur refuse le stockage.
const choixDeDimensionEnSession = new Map();

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
  // `P4.13-e` — LE CHOIX TIENT LA SESSION MÊME QUAND LE STOCKAGE EST REFUSÉ, ET C'EST CE QUI REND L'AVEU
  // VRAI. MESURÉ le 2026-08-31 au banc ESM, refus posé autour du seul clic : la dimension « statut » était
  // choisie, la barre revenait à « gravité » — `dims[0]`. La cause est ici : la repeinte RELIT le choix dans
  // le magasin, si bien qu'un refus le ramène au défaut À CHAQUE passe. L'aveu posé par `P4.13-d` annonçait
  // alors « appliqué pour cette session seulement » sur un geste qui n'avait RIEN appliqué, pas même pour ce
  // clic — une surface qui affirme ce que le code ne fait pas, ce qui est pire que le silence qu'elle
  // remplaçait. Le repli n'est pas un troisième état : c'est le geste que `saveDaDrop` (web/dataaccess.js)
  // a déjà payé pour le même défaut sur l'ordre des cartes, dont la persistance n'a pas non plus de jumeau
  // serveur. Il vit AU MODULE et non dans la fermeture, parce que l'appelant refabrique la liste entière à
  // chaque rendu (`renderRules()` rappelle `pagedList`) : une mémoire de fermeture serait perdue au premier
  // rafraîchissement, c'est-à-dire au moment même où l'exploitant croirait son choix tenu.
  // QUAND LE MAGASIN RÉPOND, RIEN NE CHANGE : les deux sources portent alors la même valeur.
  const dimensionChoisie = () => {
    const c = choixDeDimensionEnSession.get(cleDuChoix) || (cleDuChoix ? (lireLeStockageDuSite(cleDuChoix) || '') : '');
    return dims.find(d => d.cle === c) || dims[0];
  };
  let interne = null;
  function peindre() {
    const dim = dimensionChoisie();
    const groupes = grouperLesLignes(rows, dim);
    const plie = lsSet(storeKey);
    host.replaceChildren();
    host.appendChild(barreDeRegroupement(dims, dim, rows.length, groupes.length, k => {
      // `P4.13-d` — PRÉFÉRENCE : LE REGROUPEMENT DIT SA PERTE. Ce qui vivait ici était une capture au corps
      // VIDE, c'est-à-dire la forme même que `P4.13-b` avait fermée ailleurs et laissée intacte ici : le
      // refus du stockage était AVALÉ, l'exploitant quittait le panneau en croyant sa dimension retenue et
      // retrouvait `dims[0]` au chargement suivant, sans un mot. C'est un contrôle qu'on RÈGLE PUIS QU'ON
      // QUITTE — la famille des tris persistés (`soc_rule_sort`, `soc_parser_sort`), qui avertissent déjà —
      // et non un geste de navigation qui se répète : l'avis part une poignée de fois par session.
      // L'ORDRE COMPTE : on écrit, on repeint, PUIS on avoue. L'aveu est ainsi le dernier fait posé, et
      // la barre qu'il qualifie est déjà celle que l'exploitant lit.
      if (cleDuChoix) choixDeDimensionEnSession.set(cleDuChoix, k);   // `P4.13-e` — le choix tient la session
      const retenu = !cleDuChoix || ecrireDansLeStockageDuSite(cleDuChoix, k);
      peindre();
      if (!retenu) toast(LANG === 'en' ? 'Grouping applied for this session only: this browser refuses site storage, so it will not be kept on the next load.' : "Regroupement appliqué pour cette session seulement : ce navigateur refuse le stockage de site, il ne sera pas retenu au prochain chargement.", 'info', 5000);
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
// LA PROPRIÉTÉ EST GARDÉE DEPUIS LE 2026-08-26, ET ELLE NE L'ÉTAIT PAS. Le mécanisme a vécu un jour sans
// aucun témoin, pour une raison écrite en section 0 du harnais ESM : le simulacre n'a pas de mise en page,
// donc le prédicat de débordement y vaut TOUJOURS faux et tout ceci passait sans être exercé. Le témoin
// `[cellule-coupee]` POSE lui-même les deux largeurs et juge alors ce que le code en fait — où il équipe,
// où il refuse, ce qu'il rend quand la mesure change. Il ne prouve rien de l'encre peinte, et il le dit.
// DEUX FAUTES D'INSTRUMENT ONT ÉTÉ MESURÉES ET FERMÉES EN L'ÉCRIVANT, toutes deux dans le simulacre : le
// sélecteur ci-dessous n'y était pas LISIBLE (`:not(…)` hors grammaire ⇒ liste VIDE, sans un mot), et
// `type` n'y était pas reflété en attribut — un bouton correctement typé s'y lisait comme un bouton nu.
//
// ET LE RECOURS PART AVEC LA COUPE (2026-08-26). Le retrait laissait derrière lui l'infobulle que cette
// fabrique avait posée : une fenêtre élargie rendait la valeur entièrement lisible ET la répétait au
// survol. Le geste doit exister EXACTEMENT quand la valeur est coupée, donc il se retire entièrement ;
// l'infobulle qu'une VUE a écrite, elle, n'a jamais été à nous et reste (voir `TITRES_DE_LA_FABRIQUE`).
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

// L'INFOBULLE QUE LA FABRIQUE A POSÉE, ET ELLE SEULE. Le recours doit exister EXACTEMENT quand la valeur
// est coupée : posé au marquage, il doit partir avec lui. Sans ce souvenir, la fabrique ne saurait pas
// distinguer son infobulle de celle qu'une vue a écrite, et retirerait donc soit les deux, soit aucune —
// une fenêtre élargie laissait jusqu'ici une infobulle qui répète mot pour mot le texte déjà lisible.
// Un jeu FAIBLE plutôt qu'un attribut : rien n'est ajouté au document, et le souvenir meurt avec la
// cellule, que la fabrique reconstruit à chaque peinture.
const TITRES_DE_LA_FABRIQUE = new WeakSet();

function poserLeDepliDeCellule(td) {
  if (td.classList.contains(CELL_COUPEE)) return false;
  const entier = td.textContent == null ? '' : String(td.textContent);   // AVANT d'ajouter le bouton
  td.classList.add(CELL_COUPEE);
  // Recours immédiat, sans aucun geste : la valeur entière au survol. Une infobulle déjà écrite par la
  // vue (elle en sait plus que la fabrique) n'est jamais remplacée.
  if (entier && !td.getAttribute('title')) { td.title = entier; try { TITRES_DE_LA_FABRIQUE.add(td); } catch (e) {} }
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
  // Le recours part avec la coupe — mais SEULEMENT s'il vient d'ici (voir `TITRES_DE_LA_FABRIQUE`).
  if (TITRES_DE_LA_FABRIQUE.has(td)) { TITRES_DE_LA_FABRIQUE.delete(td); td.removeAttribute('title'); }
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
  // `P4.13-d` — NAVIGATION, ET LE SILENCE EST DÉCLARÉ PAR LA PORTE FRANCHIE. Plier un groupe est un geste
  // qui SE RÉPÈTE (chaque tête de groupe, à chaque peinture) et dont l'état se RELIT À L'ŒIL au chargement
  // suivant : il n'y a aucun choix d'exploitant à annoncer, et un avis par pli userait celui qui compte.
  // Rien n'est donc dit — mais plus par une capture VIDE, où rien ne distinguait le silence VOULU de l'oubli.
  ecrireSansDireLeRefus(storeKey, JSON.stringify(table), RAISONS_DE_SILENCE.CONVENANCE_PAR_NAVIGATEUR);
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

// MITRE ATT&CK — LA CONSOLE NE PORTE PLUS AUCUN LIBELLÉ DE TECHNIQUE. `P11.6-c` (2026-09-10) : la table de
// 14 noms qui vivait ici est retirée ; le démon sert son catalogue entier par une route dédiée, et
// `catalogue_attack.js` (module feuille) en dérive chaque nom ou DIT pourquoi il manque. Voir ce module.

// âge humain : secondes -> « N s / N min / N h / N j » (borné, compact ; utilisé par fleet/sources/risk/…).
const humanAge = s => { s = Number(s) || 0; return s < 90 ? s + ' s' : s < 5400 ? Math.round(s / 60) + ' min' : s < 172800 ? Math.round(s / 3600) + ' h' : Math.round(s / 86400) + ' j'; };

// socTZ est un binding vivant (import en lecture seule côté consommateurs) ; setter dédié pour l'unique
// site d'écriture (sélecteur #tz, suivi d'un location.reload()).
export function setSocTZ(v) { socTZ = v; }
export {
  $, CSSV, socTZ, LANG, LOC, tzOpts, fmtTs, SEV, sev, bool, esc, ICONS, ic, flashStopped, stopBtn, closeModals, withBusy, toast, showErr, modal, confirmModal, csvCell, toCSV, downloadText, tsSlug, exportPDF, exportBar, closeMiniMenu, miniMenu, api, apiSend, transientGatewayMsg, muted, fetchInto, colComparator, makePager, pageNums, pagedList,
  // `P10.21-x` — le discriminant de la suite d'une page et la règle de la flèche qu'il arme : lus par le
  // panneau de rétention, l'onglet Audit et la ligne d'état de l'Explore, jugés par le harnais ESM.
  cleDeLaSuiteServie, laSuiteOffreLaPageSuivante,
  // `P10.24-z` — la page au-delà du total compté, lue par le fabricant de pager, la ligne d'état de l'Explore
  // et les listes d'alertes (plate et groupée), qui ne rendent aucun pager sur une page vide.
  laPageEstAuDelaDuTotal, motDeLaPageAuDelaDuTotal, noeudDeLaPageVideAuDelaDuTotal,
  // `P10.25-a` / `P10.25-n` — la phrase d'une page vide de rang supérieur : la fin du résultat (lue aussi par
  // l'Explore) et le choix entre elle et la page au-delà du total (panneau de table d'un tableau de bord).
  noeudDeLaFinDuResultat, noeudDeLaPageVideDeRangSuperieur,
  // `P10.25-z` — la page vide DANS le total compté, lue aussi par l'Explore (qui choisit sa phrase lui-même).
  laPageEstDansLeTotal, noeudDeLaPageVideDansLeTotal,
  socRole, socIsAdmin, applyRoleClass, controleDEcritureSous, motiverLeRefusAuLecteur, roleSansEcriturePartagee, managedBadge, gateDeleteBtn, formMsg, contentSubmit, contentDelete, SEVCOL, lsSet, collapsibleGroup, humanAge,
  confirmWithConsequence, disclosure, marquerLesCellulesTronquees, celluleDeborde,
  // `P10.20-b` (rang 2) — LE LECTEUR DE CAUSE EST EXPOSÉ, PAS RECOPIÉ. `api()` et `apiSend()` attachent
  // déjà la cause à l'erreur jetée ; l'écran de connexion, lui, ne peut passer par aucun des deux (la
  // route `/api/login` est publique, exemptée de CSRF, et son 429 se lit dans un EN-TÊTE que ces deux
  // fabriques ne rendent pas), et il tient sa propre requête. Lui faire réécrire l'extraction ferait
  // deux lecteurs d'un même contrat de refus, qui dériveraient l'un de l'autre.
  causeNommeeParLeDemon, laRiposteNAPasEteMiseEnFile, motDuRefusDeCreationDeRiposte, aveuDeLaCreationDeRiposte, phraseDeLaCreationDeRiposteRefusee,
  // `P10.21-a` — ET LE LECTEUR DE L'AVEU QUE LE SUCCÈS DE LA MÊME ROUTE PORTE : les trois surfaces de
  // mise en file le partagent, faute de quoi chacune écrirait le nom de la clé et sa propre phrase, et
  // l'une d'elles finirait par avouer autre chose que les deux autres sur le même fait.
  CLE_DU_REGISTRE_SANS_MAILLON, causeDeLaTraceManquante, motDeLaTraceManquante, aveuDUneTraceManquante, aveuDeLaTraceManquante, phraseDeLaTraceManquante,
  // `P10.22-a` / `P10.22-c` — la partition identifiant servi / absent et sa face « absent », pour les mêmes
  // trois surfaces et pour la même raison.
  cleDeLIdentifiantDeRiposte, motDeLaRiposteSansIdentifiant,
  // `P10.22-n` — la nature d'un refus du second facteur et les deux faces communes à ses deux écrans.
  natureDuRefusDuSecondFacteur, motDuRefusDuSecondFacteur,
  // `P10.22-b` — la nature d'une réponse qui ne vient pas lisiblement du démon (lue aussi par l'écran de
  // connexion, qui tient sa propre requête), ses deux faces, et le prédicat des six gestes qui lisent leur
  // corps de succès.
  natureDeLaReponseHorsDemon, motDeLaReponseHorsDemon, unDeuxCentsSansCorpsLisible,
  // `P10.25-x` — et celui d'une demande qui n'a pas abouti (aucune réponse lue), lu par les trois gestes des comptes.
  laDemandeNAPasAbouti,
  // `P10.26-o` — le refus du rôle, et lui seul (la liste des comptes ; l'ensemble est relu par le témoin 115).
  REFUS_DU_ROLE_SUR_UNE_ROUTE_D_ADMINISTRATION, leRefusEstCeluiDuRole,
  // `P10.26-q` — la forme partagée du refus d'un geste d'écriture : sa nature, ses faces, son puits.
  natureDuRefusDUnGeste, motDuRefusDUnGeste, puitsDuRefusDUnGeste, effacerLeRefusDUnGeste, peindreLeRefusDUnGeste,
  // `P10.27-c` — les deux faces d'une lecture qui n'est pas servie (la phrase d'une panne de passerelle, le préfixe
  // d'une lecture refusée), jugées sous les deux instances de langue par le témoin 116.
  motDUneLectureQuiNEstPasServie,
  // `P10.20-k` — ET LE LECTEUR QUI TIENT LES DEUX MOULES DE REFUS (JSON `error` et texte brut) : les
  // tableaux de bord et les modèles de données le PARTAGENT, faute de quoi chacun écrirait son
  // extraction et l'un des deux finirait par ne plus reconnaître la forme que l'autre lit.
  phraseDuRefusDuDemon,
};

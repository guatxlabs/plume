// threatintel.js — panneau Threat Intel / IOC (#23). ADDITIF, comportement-préservant.
// Vit dans l'espace ADMINISTRATION (admin-only : tabAllowed court-circuite déjà les non-admins ;
// la VRAIE garde reste serveur — POST /iocs et /import répondent 403 hors admin ; GET coverage/iocs
// sont viewer+). Défense en profondeur côté client : uiIsAdmin() court-circuite les fetch inutiles.
// Endpoints (déjà LIVE, vérifiés 200) :
//   GET  /api/threat-intel/coverage -> {total, active, expired, by_type:[{type,n}], by_source:[{source,n}], hits_query}
//   GET  /api/threat-intel/iocs     -> [ {id,type,value,source,confidence,severity,first_seen,last_seen,expires,expired,stix_id,env_id} ]  (cappé 2000, tableau NU)
//   POST /api/threat-intel/iocs     <- {type,value,source?,confidence?,severity?,expires?,env_id?} OU {iocs:[…],source?,env_id?}  -> {added, skipped:[…]}
//   POST /api/threat-intel/import   <- {bundle:{…}, source?, env_id?}  -> {imported, skipped:[…]}
// SÉCU UI : tout en textContent/esc (anti-XSS) ; le contenu IOC n'est pas un secret (renseignement).
import { $, api, apiSend, disclosure, fetchInto, fmtTs, humanAge, modal, muted, pagedList, sev, toast } from './core.js';
import { uiIsAdmin } from './multitenant.js';

// vocabulaire des types d'IOC — MIROIR de guatx_core::ti::IOC_TYPES (le serveur ignore tout type hors liste).
const IOC_TYPES = ['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256', 'email'];

let _allIocs = [];      // dernier jeu chargé (tableau NU) — filtré côté client par la recherche.
let _iocSearch = '';    // filtre de recherche courant (valeur/type/source).

// ---- chargement du panneau : tuile de couverture + liste des IOC (+ resync du filtre) ----
async function loadThreatIntel() {
  const cov = $('#ti-coverage'); const list = $('#ti-ioc-list');
  if (!cov && !list) return;
  // admin-only (aligné sur tabAllowed) : on court-circuite côté client — le serveur garde de toute façon.
  if (!uiIsAdmin()) { if (cov) cov.replaceChildren(muted("réservé à l'administrateur.")); if (list) list.replaceChildren(); return; }
  loadCoverage();
  loadIocs();
}

async function loadCoverage() {
  const host = $('#ti-coverage'); if (!host) return;
  const d = await fetchInto(host, '/threat-intel/coverage'); if (!d) return;
  host.replaceChildren();
  // tuiles chiffrées : total / actifs / expirés (état du magasin d'IOC — CHEAP, aucun scan d'events).
  const tiles = document.createElement('div'); tiles.className = 'ti-tiles';
  const tile = (label, val, cls) => {
    const b = document.createElement('div'); b.className = 'ti-tile' + (cls ? ' ' + cls : '');
    const n = document.createElement('div'); n.className = 'ti-tile-n'; n.textContent = String(val == null ? 0 : val);
    const l = document.createElement('div'); l.className = 'ti-tile-l'; l.textContent = label;
    b.append(n, l); return b;
  };
  tiles.append(
    tile('IOC au total', d.total, ''),
    tile('actifs', d.active, 'ok'),
    tile('expirés', d.expired, 'warn'),
  );
  host.appendChild(tiles);
  // ventilations par type et par source (chips) — chacune en textContent (anti-XSS).
  const chips = (title, arr, keyName) => {
    const box = document.createElement('div'); box.className = 'ti-break';
    const h = document.createElement('span'); h.className = 'ti-break-h muted'; h.textContent = title;
    box.appendChild(h);
    if (!arr || !arr.length) { const m = document.createElement('span'); m.className = 'muted'; m.textContent = '—'; box.appendChild(m); return box; }
    arr.forEach(row => {
      const c = document.createElement('span'); c.className = 'badge ti-chip';
      c.textContent = (row[keyName] == null ? '?' : row[keyName]) + ' · ' + (row.n == null ? 0 : row.n);
      box.appendChild(c);
    });
    return box;
  };
  host.appendChild(chips('Par type', d.by_type, 'type'));
  host.appendChild(chips('Par source', d.by_source, 'source'));
  // indice : les HITS dans le temps se requêtent en GXQL (aucun scan serveur ici).
  if (d.hits_query) {
    const hint = document.createElement('div'); hint.className = 'muted ti-hint'; hint.style.cssText = 'margin-top:8px;font-size:11px';
    const pre = document.createElement('code'); pre.textContent = d.hits_query;
    hint.append(document.createTextNode('Hits dans le temps (Explore) : '), pre);
    host.appendChild(hint);
  }
}

async function loadIocs() {
  const host = $('#ti-ioc-list'); if (!host) return;
  const d = await fetchInto(host, '/threat-intel/iocs'); if (!d) return;
  _allIocs = Array.isArray(d) ? d : [];
  renderIocList();
}

function renderIocList() {
  const host = $('#ti-ioc-list'); if (!host) return;
  const q = _iocSearch.trim().toLowerCase();
  const rows = q
    ? _allIocs.filter(x => [x.value, x.type, x.source].some(v => String(v == null ? '' : v).toLowerCase().includes(q)))
    : _allIocs.slice();
  const nowS = Math.floor(Date.now() / 1000);
  const columns = [
    { key: 'type', label: 'Type', sortable: true, sortVal: r => r.type || '', render: r => { const c = document.createElement('code'); c.textContent = r.type || '?'; return c; } },
    { key: 'value', label: 'Valeur', sortable: true, sortVal: r => r.value || '', render: r => { const s = document.createElement('span'); s.textContent = r.value == null ? '' : r.value; s.title = s.textContent; return s; } },
    { key: 'source', label: 'Source', sortable: true, sortVal: r => r.source || '', render: r => r.source || '—' },
    { key: 'confidence', label: 'Conf.', sortable: true, align: 'r', sortVal: r => r.confidence || 0, render: r => (r.confidence == null ? 0 : r.confidence) + '%' },
    { key: 'severity', label: 'Sévérité', sortable: true, sortVal: r => r.severity || 0, render: r => { const s = document.createElement('span'); s.className = 'sev'; s.textContent = sev(r.severity); return s; } },
    { key: 'last_seen', label: 'Vu', sortable: true, sortVal: r => r.last_seen || 0, render: r => { const s = document.createElement('span'); s.textContent = r.last_seen ? 'il y a ' + humanAge(nowS - r.last_seen) : '—'; if (r.last_seen) s.title = fmtTs(r.last_seen); return s; } },
    { key: 'expires', label: 'Expiration', sortable: true, sortVal: r => r.expires || Infinity, render: r => {
      const s = document.createElement('span');
      if (!r.expires) { s.className = 'muted'; s.textContent = 'jamais'; return s; }
      s.textContent = fmtTs(r.expires); s.title = String(r.expires);
      if (r.expired) { const b = document.createElement('span'); b.className = 'badge'; b.textContent = 'expiré'; b.style.cssText = 'margin-left:6px;color:var(--warn);border-color:color-mix(in srgb,var(--warn) 40%,transparent)'; const f = document.createDocumentFragment(); f.append(s, b); return f; }
      return s;
    } },
    { key: 'env_id', label: 'Env', sortable: true, sortVal: r => r.env_id || '', render: r => { const c = document.createElement('code'); c.textContent = r.env_id || 'prod'; return c; } },
  ];
  pagedList(host, { mode: 'client', pageSize: 50, rows, columns, sort: { key: 'last_seen', dir: -1 }, emptyText: q ? 'aucun IOC ne correspond au filtre' : 'aucun IOC — ajoute-en un ou importe un feed / bundle STIX.' });
}

// ---- ajout MANUEL d'un IOC (modale) — POST /threat-intel/iocs {type,value,…} ----
async function addIocPrompt() {
  const r = await modal({
    title: 'Ajouter un IOC', okText: 'Ajouter',
    fields: [
      { name: 'type', label: 'Type', type: 'select', value: 'ip', options: IOC_TYPES.map(t => ({ value: t, label: t })) },
      { name: 'value', label: 'Valeur', required: true, placeholder: 'ex : 203.0.113.9 / evil.example / …' },
      { name: 'source', label: 'Source', value: 'manual', placeholder: 'manual' },
      { name: 'confidence', label: 'Confiance (0-100)', type: 'number', value: 50 },
      { name: 'severity', label: 'Sévérité (0-4)', type: 'number', value: 2 },
      { name: 'env_id', label: 'Environnement', value: 'prod', placeholder: 'prod' },
    ],
  });
  if (!r) return;
  const body = {
    type: r.type, value: String(r.value || '').trim(),
    source: String(r.source || '').trim() || 'manual',
    confidence: Math.max(0, Math.min(100, Number(r.confidence) || 0)),
    severity: Math.max(0, Math.min(4, Number(r.severity) || 0)),
    env_id: String(r.env_id || '').trim() || 'prod',
  };
  let res;
  try { res = await apiSend('/threat-intel/iocs', 'POST', body); }
  catch (e) { toast('échec : ' + ((e && e.message) || e), 'bad', 4200); return; }
  const added = res && res.added != null ? res.added : 0;
  const skipped = res && Array.isArray(res.skipped) ? res.skipped.length : 0;
  toast(added ? added + ' IOC ajouté/mis à jour' + (skipped ? ' (' + skipped + ' ignoré)' : '') : 'aucun IOC ajouté' + (skipped ? ' (' + skipped + ' ignoré — type/valeur invalide)' : ''), added ? 'ok' : 'bad', 4200);
  loadThreatIntel();
}

// ---- import EN MASSE : liste « type,valeur » OU bundle STIX 2.1 (JSON) ----
function toggleImport() {
  const f = $('#ti-import-form'); if (!f) return;
  const willShow = f.classList.contains('hidden');
  f.classList.toggle('hidden');
  if (willShow) { const t = $('#ti-imp-body'); if (t) t.focus(); const res = $('#ti-imp-result'); if (res) res.textContent = ''; }
}

// parse une liste texte -> [{type,value}] ; chaque ligne « type,valeur » ou « type valeur » (séparateur , ; ou espaces).
function parseIocLines(text) {
  const out = [];
  String(text || '').split(/\r?\n/).forEach(line => {
    const s = line.trim(); if (!s || s.startsWith('#')) return;
    const parts = s.split(/[,;\s]+/).filter(Boolean);
    if (parts.length < 2) return;
    out.push({ type: parts[0].toLowerCase(), value: parts.slice(1).join(' ') });
  });
  return out;
}

async function doImport(e) {
  if (e) e.preventDefault();
  const fmt = $('#ti-imp-fmt') ? $('#ti-imp-fmt').value : 'lines';
  const source = ($('#ti-imp-source') ? $('#ti-imp-source').value : '').trim();
  const env = ($('#ti-imp-env') ? $('#ti-imp-env').value : '').trim() || 'prod';
  const raw = $('#ti-imp-body') ? $('#ti-imp-body').value : '';
  const res = $('#ti-imp-result');
  const setMsg = (m, bad) => { if (res) { res.textContent = m; res.className = bad ? 'bad' : 'muted'; } };
  if (!raw.trim()) { setMsg('rien à importer.', true); return; }
  let path, body;
  if (fmt === 'stix') {
    let bundle;
    try { bundle = JSON.parse(raw); } catch (err) { setMsg('JSON invalide : ' + ((err && err.message) || err), true); return; }
    path = '/threat-intel/import';
    body = { bundle, source: source || 'stix-import', env_id: env };
  } else {
    const iocs = parseIocLines(raw);
    if (!iocs.length) { setMsg('aucune ligne « type,valeur » exploitable.', true); return; }
    path = '/threat-intel/iocs';
    body = { iocs, source: source || 'manual', env_id: env };
  }
  let r;
  try { r = await apiSend(path, 'POST', body); }
  catch (err) { setMsg('échec : ' + ((err && err.message) || err), true); toast('import : échec', 'bad'); return; }
  const okN = r ? (r.imported != null ? r.imported : (r.added != null ? r.added : 0)) : 0;
  const skN = r && Array.isArray(r.skipped) ? r.skipped.length : 0;
  setMsg(okN + ' importé(s)/mis à jour' + (skN ? ' · ' + skN + ' ignoré(s)' : ''), false);
  toast(okN + ' IOC importé(s)' + (skN ? ' (' + skN + ' ignoré)' : ''), okN ? 'ok' : 'bad', 4200);
  if ($('#ti-imp-body')) $('#ti-imp-body').value = '';
  loadThreatIntel();
}

// ---- câblage (self-wiring, appelé UNE fois depuis app.js) ----
function initThreatIntel() {
  if ($('#ti-refresh')) $('#ti-refresh').onclick = loadThreatIntel;
  if ($('#ti-add')) $('#ti-add').onclick = addIocPrompt;
  if ($('#ti-import-toggle') && $('#ti-import-form')) disclosure($('#ti-import-toggle'), $('#ti-import-form'), { open: toggleImport }); // P11.4-a : dépli partagé (second clic = repli, état visible)
  if ($('#ti-imp-cancel')) $('#ti-imp-cancel').onclick = () => { const f = $('#ti-import-form'); if (f) f.classList.add('hidden'); };
  if ($('#ti-import-form')) $('#ti-import-form').addEventListener('submit', doImport);
  if ($('#ti-search')) { $('#ti-search').classList.add('field'); $('#ti-search').addEventListener('input', () => { _iocSearch = $('#ti-search').value || ''; renderIocList(); }); } // P11.4-b : le cadre du filtre prend le chrome partagé `.field` (il était natif)
}

export { loadThreatIntel, initThreatIntel };

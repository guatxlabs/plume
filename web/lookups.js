// Lookups (tables d'enrichissement GXQL) : liste, ligne, collage JSON/CSV, suppression. Extrait d'`app.js` par
// déplacement pur ; le câblage des boutons et le premier chargement sont exposés par `initLookups()`, appelé par
// `app.js` au point où ce bloc vivait (un module s'exécute à l'import, avant l'enveloppe `fetch` d'`app.js`).
// `lookupRow` et `parseCsvRows` sont exportés pour le harnais. N'importe pas `app.js`.
import { $, api, apiSend, confirmModal, contentDelete, disclosure, fmtTs, ic, managedBadge, muted, toast } from './core.js';

// --- Lookups (tables d'enrichissement GXQL ; réservé admin ; vit sous Réglages, comme les Comptes) ---
// Un lookup = table de référence nommée (clé -> colonnes JSON) jointe en LEFT JOIN par l'op GXQL
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
function initLookups() {
  if ($('#lookup-new') && $('#lookup-form')) disclosure($('#lookup-new'), $('#lookup-form'), { open: () => { $('#lookup-form').classList.remove('hidden'); $('#lk-name').focus(); } }); // P11.4-a — dépli partagé
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
}

export { initLookups, loadLookups, lookupRow, parseCsvRows };

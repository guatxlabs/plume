// Lookups (tables d'enrichissement GXQL) : liste, ligne, collage JSON/CSV, suppression. Extrait d'`app.js` par
// déplacement pur ; le câblage des boutons et le premier chargement sont exposés par `initLookups()`, appelé par
// `app.js` au point où ce bloc vivait (un module s'exécute à l'import, avant l'enveloppe `fetch` d'`app.js`).
// `lookupRow` et `parseCsvRows` sont exportés pour le harnais. N'importe pas `app.js`.
import { $, api, apiSend, confirmModal, contentDelete, disclosure, effacerLeRefusDUnGeste, fmtTs, ic, managedBadge, muted, peindreLeRefusDUnGeste, puitsDuRefusDUnGeste, toast, faceDansLaLangue } from './core.js';
// `P10.28-t` — L'AVIS D'UN LOOKUP CHARGÉ, DANS LES DEUX LANGUES. MESURÉ AVANT CE LOT (témoin 119t) : « lookup "geo"
// chargé : 3 ligne(s) - colonnes pays » restait français sous `LANG='en'`.
const MOTS_DU_CHARGEMENT_DE_LOOKUP = {
  avec_colonnes: { fr: 'lookup "{nom}" chargé : {n} ligne(s) - colonnes {colonnes}', en: 'lookup "{nom}" loaded: {n} row(s) - columns {colonnes}' },
  sans_colonne: { fr: 'lookup "{nom}" chargé : {n} ligne(s) - aucune colonne hors clé', en: 'lookup "{nom}" loaded: {n} row(s) - no column besides the key' },
};

// --- Lookups (tables d'enrichissement GXQL ; réservé admin ; vit sous Réglages, comme les Comptes) ---
// Un lookup = table de référence nommée (clé -> colonnes JSON) jointe en LEFT JOIN par l'op GXQL
// `lookup <nom> <champ-clé> [OUTPUT cols]`. #1c : GET /api/lookups est LISIBLE par tous les rôles
// (viewer/editor/admin) ; le CRUD (POST upload / DELETE) est autorisé éditeur+admin, le viewer est
// bloqué serveur (403 via le gate `mutating`) ET côté UI (boutons .crud-btn masqués en role-viewer).
// Les mutations reçoivent X-CSRF-Token automatiquement via le wrapper window.fetch global.
// API : GET /api/lookups -> {lookups:[{name,key_field,cols,updated,rows}]} ; POST {name,key_field,rows:[{...}]}
// -> {name,rows,cols:[...]} (REMPLACE tout le lookup) ; DELETE /api/lookups/{name} -> {ok,deleted:true}.
const LK_NAME_RE = /^[A-Za-z0-9_]+$/;   // miroir de soql_ident_ok côté daemon (alphanumérique + _, non vide)
// `P10.7-f` — LE DRAPEAU EST POSÉ PAR LA CHARGE ET LU PAR LE FORMULAIRE, câblé par le dépli partagé, hors
// d'elle : la marque accessible de l'inertie se VOIT sur « + Nouveau lookup », seul le point de soumission
// EMPÊCHE le remplacement.
let LOOKUPS_NON_LUS = false;
// `P10.27-d` — LE PUITS DES GESTES SUR LES LOOKUPS, juste avant la liste (et après le formulaire) : chargement et retrait.
// Hors de ce que `loadLookups` repeint, il survit au rechargement ; la forme est celle du point commun
// (`peindreLeRefusDUnGeste`, core.js). MESURÉ AVANT CE LOT (témoin 118) : le chargement refusé écrivait « 503 {"error":
// "TABLE D'ENRICHISSEMENT INCHANGÉE : … » coupé dans la ligne du formulaire, le retrait refusé un avis qui s'efface.
function puitsDesLookups() { const liste = $('#lookup-list'); return liste && liste.parentNode ? puitsDuRefusDUnGeste(liste.parentNode, 'lookups', liste) : null; }
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
  let lookups = [], reponse = null;
  // `P10.7-f` (rang 4) — LA RÉPONSE ENTIÈRE EST TENUE, PAS SEULEMENT LA CLÉ ATTENDUE. Le démon sert, en 200,
  // `{lookups: [], error: <cause>}` quand la lecture échoue (`corps_de_liste_illisible`,
  // daemon/src/handlers/users_lookups.rs) ; `api()` ne jette que sur `!r.ok`, et la déconstruction
  // `({ lookups } = …)` jetait la cause servie à côté. Le texte de vide rendu plus bas affirme qu'AUCUNE
  // table d'enrichissement n'existe — et le geste qu'il propose REMPLACE intégralement le contenu du lookup
  // portant ce nom : conclure « il n'y en a pas » puis en « créer » un écrase des données qui existent.
  try { reponse = await api('/lookups'); lookups = Array.isArray(reponse.lookups) ? reponse.lookups : []; } catch (e) { return; } // 403 (non-admin) -> section masquée de toute façon
  const neuf = $('#lookup-new');
  if (reponse.error) {
    LOOKUPS_NON_LUS = true;
    const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
    const dit = document.createElement('span');
    dit.textContent = 'Lookups NON LUS : le démon a refusé et en nomme la cause —';
    aveu.append(dit, ' « ' + String(reponse.error).trim() + ' »');
    wrap.replaceChildren(aveu);
    if (neuf) { neuf.setAttribute('aria-disabled', 'true'); neuf.title = "Les lookups n'ont PAS été lus : « créer » ici REMPLACE intégralement le contenu du lookup portant ce nom — celui que cette lecture n'a pas pu rendre serait écrasé sans un mot."; }
    const form = $('#lookup-form');
    if (form) form.classList.add('hidden');
    return;
  }
  LOOKUPS_NON_LUS = false;
  if (neuf) { neuf.removeAttribute('aria-disabled'); neuf.removeAttribute('title'); }
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
    if (await contentDelete('/lookups/' + encodeURIComponent(l.name), 'lookup', puitsDesLookups())) loadLookups();
  };
  row.append(name, key, meta, del);
  return row;
}
function initLookups() {
  if ($('#lookup-new') && $('#lookup-form')) disclosure($('#lookup-new'), $('#lookup-form'), { open: () => { $('#lookup-form').classList.remove('hidden'); $('#lk-name').focus(); } }); // P11.4-a — dépli partagé
  if ($('#lk-cancel')) $('#lk-cancel').onclick = () => $('#lookup-form').classList.add('hidden');
  if ($('#lookup-form')) $('#lookup-form').addEventListener('submit', chargerLeLookupDuFormulaire);
  loadLookups();
}
// Le geste du formulaire, nommé et exporté (il était l'écouteur anonyme d'`initLookups`, déplacé tel quel ; seul son refus
// change : le puits des lookups, la forme partagée).
async function chargerLeLookupDuFormulaire(e) {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    // La MÊME phrase qu'au survol du bouton, jamais deux formulations du même refus.
    if (LOOKUPS_NON_LUS) { toast("Les lookups n'ont PAS été lus : « créer » ici REMPLACE intégralement le contenu du lookup portant ce nom — celui que cette lecture n'a pas pu rendre serait écrasé sans un mot.", 'bad', 9000); return; }
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
    const puits = puitsDesLookups(); effacerLeRefusDUnGeste(puits);
    let j;
    try { j = await apiSend('/lookups', 'POST', { name, key_field: key, rows }); }
    catch (err) { res.textContent = ''; res.className = 'muted'; peindreLeRefusDUnGeste(puits, err); return; }
    j = j || {};
    res.textContent = ''; res.className = 'muted';
    // `P10.28-t` — l'avis du chargement, dans les deux langues (composé : un nom et un nombre s'y collent).
    toast(faceDansLaLangue(j.cols && j.cols.length ? MOTS_DU_CHARGEMENT_DE_LOOKUP.avec_colonnes : MOTS_DU_CHARGEMENT_DE_LOOKUP.sans_colonne, { nom: name, n: j.rows, colonnes: (j.cols || []).join(', ') }), 'ok');
    $('#lk-rows').value = ''; $('#lookup-form').classList.add('hidden');
    loadLookups();
}

export { initLookups, loadLookups, lookupRow, parseCsvRows, chargerLeLookupDuFormulaire };

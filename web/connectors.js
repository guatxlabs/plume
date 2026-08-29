// connectors.js — extracted from app.js (DEEP state-container split). Behaviour-preserving.
// Connecteurs (sources externes en PULL, #3/#3a, admin-only): liste/form/test/poll.
import { $, api, apiSend, confirmModal, confirmWithConsequence, fetchInto, fmtTs, humanAge, ic, muted, pagedList, sev, toast, withBusy } from './core.js';
import { enabledSwitch } from './producer_ui.js';
import { S } from './state.js';
import { uiIsAdmin } from './multitenant.js';

// ============ CONNECTEURS (sources externes en PULL — #3/#3a, admin-only) ============
// Un ADMIN configure une source externe (Microsoft Defender d'abord) ; le daemon PULL les alertes, les
// normalise (source=defender, sévérité mappée, entités -> champs) et les INGÈRE dans la base du tenant.
// API admin-only : GET /api/connectors (tableau NU, JAMAIS le secret) ; POST /api/connectors (create) ;
// POST /api/connectors/{id} (update PARTIEL) ; DELETE /api/connectors/{id} ; POST /api/connectors/{id}/test
// (dry-run OAuth + 1 page, N'INGÈRE PAS, renvoie {ok,sample_count,error} sans secret ni contenu d'alerte).
// SÉCU UI : rendu textContent (anti-XSS) ; le client_secret est un CREDENTIAL -> champ password, JAMAIS
// réaffiché (masqué •••), ré-envoyé UNIQUEMENT s'il est re-saisi (omis/vide = conservé côté serveur).
// La vraie garde reste serveur (403 hors admin) ; ceci est la défense en profondeur / l'UX correspondante.
const CONNECTOR_TYPES = { defender: 'Microsoft Defender', taxii2: 'TAXII 2.1', http_pull: 'Generic HTTP' };
// #20/#22 — seed de field_map pour un NOUVEAU connecteur générique (scaffold de départ ; l'admin ajuste).
const DEFAULT_FIELD_MAP = ['ts', 'message', 'severity', 'host', 'src_ip'];

async function loadConnectors() {
  const wrap = $('#connector-list'); if (!wrap) return;
  // admin-only : côté client on court-circuite (le serveur renvoie 403 de toute façon) — pas de fetch inutile.
  // Aligné sur la garde d'onglet (tabAllowed -> uiIsAdmin) ; la VRAIE garde reste serveur (au.role==admin).
  if (!uiIsAdmin()) { wrap.replaceChildren(muted('réservé à l\'administrateur.')); return; }
  let list = await fetchInto(wrap, '/connectors'); if (!list) return;
  if (!Array.isArray(list)) list = [];
  if (!list.length) {
    wrap.replaceChildren(muted('aucun connecteur — clique « + Connecteur Defender » pour brancher une source externe. Tant qu\'aucun connecteur n\'est activé, rien n\'est collecté (comportement inchangé).'));
    return;
  }
  // BATCH #13 — liste growable paginée (pattern canonique) : renderRow=connectorRow (Node), mode client.
  pagedList(wrap, { mode: 'client', pageSize: 50, rows: list, renderRow: connectorRow });
}

function connectorRow(c) {
  const row = document.createElement('div'); row.className = 'rulerow';
  // enable/disable (POST /api/connectors/{id} {enabled}) — COMMUTATEUR PARTAGÉ (`P11.13-c`) : la case nue ne
  // disait pas ce qu'elle coupe. `enabledSwitch` écrit la conséquence à côté de l'interrupteur dans les DEUX
  // états, avant la bascule, et remet la case à son état précédent si le serveur refuse.
  const en = enabledSwitch({
    enabled: !!c.enabled, name: c.name || '(sans nom)', allowed: true, confirmOnEnable: false,
    consequence: 'plume interroge ' + (CONNECTOR_TYPES[c.type] || c.type || '?') + ' et ingère ce qu\'il rend ; OFF, la collecte s\'arrête et rien n\'est rattrapé du temps passé hors ligne',
    onToggle: (next) => apiSend('/connectors/' + c.id, 'POST', { enabled: next }),
  });
  // nom + type + environnement (textContent — anti-XSS)
  const name = document.createElement('span'); name.className = 'rulename'; name.textContent = c.name || '(sans nom)';
  const type = document.createElement('code'); type.className = 'rulecond'; type.textContent = CONNECTOR_TYPES[c.type] || c.type || '?';
  const env = document.createElement('code'); env.className = 'rulecond'; env.textContent = 'env ' + (c.env_id || 'prod'); env.title = 'Environnement d\'ingestion';
  // secret : JAMAIS affiché — badge masqué (••• configuré) ou avertissement (manquant).
  const sec = document.createElement('span'); sec.className = 'badge';
  if (c.has_secret) { sec.textContent = '••• secret'; sec.title = 'client_secret configuré (chiffré au repos, jamais affiché)'; sec.style.cssText = 'color:var(--ok);border-color:color-mix(in srgb,var(--ok) 40%,transparent)'; }
  else { sec.textContent = 'secret manquant'; sec.title = 'aucun credential enregistré — édite le connecteur pour saisir le client secret'; sec.style.cssText = 'color:var(--warn);border-color:color-mix(in srgb,var(--warn) 45%,transparent)'; }
  // état de collecte : dernier pull + volume du dernier lot (+ ISO watermark en title).
  const meta = document.createElement('span'); meta.className = 'rulemeta muted';
  const nowS = Math.floor(Date.now() / 1000);
  const bits = [];
  if (c.last_run) bits.push('pull il y a ' + humanAge(nowS - c.last_run));
  else bits.push('jamais collecté');
  bits.push((c.last_count != null ? c.last_count : 0) + ' event(s) au dernier lot');
  meta.textContent = bits.join(' · ');
  meta.title = (c.last_ok ? 'dernier succès : ' + fmtTs(c.last_ok) : 'aucun succès enregistré') + (c.watermark ? '\nwatermark : ' + c.watermark : '');
  // dernière erreur (le serveur ne met JAMAIS le secret ni le corps HTTP dans last_error — statut/motif seul).
  const errRow = document.createElement('span'); errRow.className = 'rulemeta';
  if (c.last_error) { errRow.textContent = 'dernière erreur : ' + c.last_error; errRow.title = c.last_error; errRow.style.cssText = 'color:var(--warn)'; }
  // actions : Tester / Éditer / Supprimer
  const test = document.createElement('button'); test.type = 'button'; test.textContent = 'Tester la connexion';
  test.title = 'OAuth + 1 page Graph, sans ingérer — feedback succès/erreur (jamais le secret)';
  test.onclick = () => withBusy(test, () => testConnector(c));
  // D10b — collecte immédiate : POST /api/connectors/{id}/poll (admin-only + fail-safe côté serveur). Ingère
  // pour de vrai (réutilise le poll de fond) ; feedback = nombre d'events ingérés / erreur (jamais le secret).
  const poll = document.createElement('button'); poll.type = 'button'; poll.textContent = 'Collecter maintenant';
  poll.title = 'Déclencher un pull + ingest immédiat de ce connecteur (ne montre jamais le secret)';
  poll.onclick = () => withBusy(poll, () => pollConnector(c));
  const edit = document.createElement('button'); edit.type = 'button'; edit.textContent = 'Éditer'; edit.onclick = () => openConnectorForm(c);
  const del = document.createElement('button'); del.type = 'button'; del.innerHTML = ic('x'); del.title = 'Supprimer le connecteur'; del.onclick = () => deleteConnector(c);
  row.append(en, name, type, env, sec, meta);
  if (c.last_error) row.append(errRow);
  row.append(test, poll, edit, del);
  return row;
}

// DRY-RUN de connexion : POST /api/connectors/{id}/test -> {ok,sample_count,error}. N'ingère pas, ne renvoie
// NI le secret NI le contenu des alertes ; `error` = statut/motif seul. Feedback par toast (succès/erreur).
async function testConnector(c) {
  let j;
  try { j = await apiSend('/connectors/' + c.id + '/test', 'POST'); }
  catch (e) { toast('échec du test : ' + ((e && e.message) || e), 'bad'); return; }
  j = j || {};
  if (j.ok) toast('connexion OK — ' + (j.sample_count != null ? j.sample_count : 0) + ' alerte(s) en échantillon', 'ok', 4200);
  else toast('échec : ' + (j.error || 'erreur inconnue'), 'bad', 4200);
}

// D10b — POST /api/connectors/{id}/poll : déclenche UN pull+ingest IMMÉDIAT (admin-only + fail-safe serveur).
// Feedback = nombre d'events ingérés au dernier lot / erreur (jamais le secret). Rafraîchit la liste ensuite
// (last_run / last_count / last_error reflètent le poll qui vient de s'exécuter).
//
// CONFIRMATION AVEC CONSÉQUENCE (`P11.13-c`) — POURQUOI ICI ET PAS SUR « Tester la connexion ». Les deux
// boutons sont des POST ; un seul ÉCRIT. Mesuré le 2026-08-29 dans le démon : `connector_poll` réutilise
// `poll_one_connector`, qui INGÈRE les alertes dans la base du tenant et, EN CAS DE SUCCÈS SEULEMENT, avance
// le curseur `connector.watermark` — le lot qui vient d'entrer ne sera donc plus jamais retiré par ce
// connecteur. Le démon le dit lui-même : il AUDITE ce geste (`config.connector.poll`), et c'est ce
// critère-là — le démon inscrit un changement — qui rend une route sensible. `connector_test`, lui,
// n'exécute AUCUN `execute` : dry-run, une page, rien d'ingéré, rien d'audité, curseur immobile. Lui poser
// une confirmation apprendrait à cliquer sans lire, et userait celle-ci.
function consequenceDuPoll(c) {
  return 'les alertes disponibles chez ' + (CONNECTOR_TYPES[c.type] || c.type || 'la source externe')
    + ' sont tirées MAINTENANT et ingérées dans plume (env ' + (c.env_id || 'prod') + ', détection comprise) ; '
    + 'en cas de succès le curseur avance et ce lot ne sera plus jamais retiré par ce connecteur. Refuser ne '
    + 'tire rien et ne change rien à l\'état du connecteur — ni sa collecte périodique, ni son curseur.';
}

async function pollConnector(c) {
  if (!await confirmWithConsequence('Collecter maintenant « ' + (c.name || c.id) + ' » ?', consequenceDuPoll(c))) return;
  let j;
  try { j = await apiSend('/connectors/' + c.id + '/poll', 'POST'); }
  catch (e) { toast('échec de la collecte : ' + ((e && e.message) || e), 'bad'); loadConnectors(); return; }
  j = j || {};
  if (j.ok) toast('collecte OK — ' + (j.count != null ? j.count : 0) + ' event(s) ingéré(s)', 'ok', 4200);
  else toast('collecte : ' + (j.error || 'erreur inconnue'), 'bad', 4200);
  loadConnectors();   // reflète last_run / last_count / last_error mis à jour par le poll
}

// Affiche/masque les champs spécifiques au type (Defender ↔ TAXII 2.1 ↔ Generic HTTP) + adapte l'indice du
// secret. Appelée à l'ouverture du formulaire ET au changement de #cf-type / #cf-taxii-auth / #cf-http-*
// (listeners câblés dans app.js). Defender/TAXII inchangés (comportement byte-identique).
function applyConnectorType() {
  const type = ($('#cf-type') && $('#cf-type').value) || 'defender';
  const isTaxii = type === 'taxii2';
  const isHttp = type === 'http_pull';
  const isDefender = !isTaxii && !isHttp;
  document.querySelectorAll('.cf-defender-fields').forEach(el => { el.hidden = !isDefender; });
  document.querySelectorAll('.cf-taxii-fields').forEach(el => { el.hidden = !isTaxii; });
  document.querySelectorAll('.cf-http-fields').forEach(el => { el.hidden = !isHttp; });
  // pour TAXII : le secret dépend du mode d'auth (aucun secret si auth=none).
  const sh = $('#cf-secret-hint');
  const editing = !!S.editingConnector;
  if (isHttp) { applyHttpSubfields(editing); return; }   // http_pull gère ses propres sous-champs + indice de secret
  if (isTaxii) {
    const auth = ($('#cf-taxii-auth') && $('#cf-taxii-auth').value) || 'none';
    if ($('#cf-secret')) $('#cf-secret').placeholder = auth === 'token' ? 'Token (bearer / api-key) — credential, jamais réaffiché' : (auth === 'basic' ? 'Mot de passe — credential, jamais réaffiché' : 'Aucun secret requis (auth = aucune)');
    if (sh) sh.textContent = auth === 'none'
      ? 'Auth « aucune » : aucun credential requis.'
      : (editing ? 'Un secret est déjà enregistré — laisse vide pour le conserver, ou saisis-en un nouveau pour le remplacer.' : 'Saisis le token / mot de passe (il ne sera plus jamais réaffiché).');
  } else {
    if ($('#cf-secret')) $('#cf-secret').placeholder = 'Client secret (credential — jamais réaffiché)';
    if (sh) sh.textContent = editing
      ? 'Un client secret est déjà enregistré — laisse ce champ vide pour le conserver, ou saisis-en un nouveau pour le remplacer.'
      : 'Saisis le client secret de l\'app Azure (il ne sera plus jamais réaffiché).';
  }
}

// ============ CONNECTEUR GÉNÉRIQUE http_pull (#20/#22) — UI ============
// Sous-champs conditionnels (auth / méthode / pagination) + indice de secret dépendant de l'auth. Le
// credential vit TOUJOURS dans #cf-secret (jamais dans la config). Miroir de la logique TAXII.
function applyHttpSubfields(editing) {
  const ak = ($('#cf-http-auth') && $('#cf-http-auth').value) || 'none';
  const isHdr = ak === 'token' || ak === 'header';                 // en-tête custom + préfixe
  const isOauth = ak === 'oauth2_client_credentials';              // token_url / client_id / scope
  document.querySelectorAll('.cf-http-hdr').forEach(el => { el.hidden = !isHdr; });
  document.querySelectorAll('.cf-http-oauth').forEach(el => { el.hidden = !isOauth; });
  const method = ($('#cf-http-method') && $('#cf-http-method').value) || 'GET';
  document.querySelectorAll('.cf-http-post').forEach(el => { el.hidden = method !== 'POST'; });
  const pk = ($('#cf-http-page') && $('#cf-http-page').value) || 'none';
  document.querySelectorAll('.cf-http-pagep').forEach(el => { el.hidden = !(pk === 'offset' || pk === 'page' || pk === 'cursor'); });
  document.querySelectorAll('.cf-http-pagesize').forEach(el => { el.hidden = !(pk === 'offset' || pk === 'page'); });
  document.querySelectorAll('.cf-http-pagestart').forEach(el => { el.hidden = !(pk === 'offset' || pk === 'page'); });
  document.querySelectorAll('.cf-http-pagecursor').forEach(el => { el.hidden = pk !== 'cursor'; });
  document.querySelectorAll('.cf-http-pagelink').forEach(el => { el.hidden = pk !== 'link_header'; });
  // indice de secret selon l'auth (none = aucun credential).
  const sec = $('#cf-secret'); const sh = $('#cf-secret-hint');
  if (ak === 'none') {
    if (sec) sec.placeholder = 'Aucun credential requis (auth = aucune)';
    if (sh) sh.textContent = 'Auth « aucune » : aucun credential requis.';
  } else {
    const ph = ak === 'basic' ? 'Credential « user:pass » (basic) — jamais réaffiché'
      : ak === 'oauth2_client_credentials' ? 'client_secret OAuth2 — jamais réaffiché'
      : ak === 'bearer' ? 'Token bearer — jamais réaffiché'
      : 'Token / clé d\'API — jamais réaffiché';
    if (sec) sec.placeholder = ph;
    if (sh) sh.textContent = editing
      ? 'Un credential est déjà enregistré — laisse vide pour le conserver, ou saisis-en un nouveau pour le remplacer.'
      : 'Saisis le credential (il ne sera plus jamais réaffiché).';
  }
}

// Rangée clé -> valeur (field_map / sourcetype_map). textContent/inputs (anti-XSS). `del` retire la rangée.
function kvRow(host, key, val, keyPh, valPh, listId) {
  if (!host) return;
  const row = document.createElement('div'); row.className = 'cf-kvrow';
  const k = document.createElement('input'); k.className = 'cf-kvk'; k.placeholder = keyPh; k.value = key == null ? '' : key; k.autocomplete = 'off'; k.spellcheck = false;
  if (listId) k.setAttribute('list', listId);
  const arrow = document.createElement('span'); arrow.className = 'cf-kvarrow'; arrow.textContent = '→';
  const v = document.createElement('input'); v.className = 'cf-kvv'; v.placeholder = valPh; v.value = val == null ? '' : val; v.autocomplete = 'off'; v.spellcheck = false;
  const del = document.createElement('button'); del.type = 'button'; del.className = 'picon'; del.innerHTML = ic('x'); del.title = 'Retirer ce champ'; del.onclick = () => row.remove();
  row.append(k, arrow, v, del); host.appendChild(row);
}
function addFieldMapRow(key, val) { kvRow($('#cf-http-fieldmap'), key, val, 'champ (ts, message, src_ip, fields.x…)', 'JSONPath ou =constante', 'cf-http-fmkeys'); }
function addStMapRow(key, val) { kvRow($('#cf-http-stmap'), key, val, 'sourcetype', 'catégorie CIM (ex: network, authentication)'); }

// Collecte un objet { clé: valeur } depuis un conteneur de rangées (clé vide -> ignorée).
function collectKv(sel) {
  const out = {}; const host = $(sel); if (!host) return out;
  host.querySelectorAll('.cf-kvrow').forEach(row => {
    const kEl = row.querySelector('.cf-kvk'); const vEl = row.querySelector('.cf-kvv');
    const k = (kEl && kEl.value || '').trim(); const v = (vEl && vEl.value || '').trim();
    if (k) out[k] = v;
  });
  return out;
}

// Bloc pagination (null si aucune) — miroir de HttpPage côté daemon.
function collectPagination() {
  const kind = ($('#cf-http-page') && $('#cf-http-page').value) || 'none';
  if (kind === 'none') return null;
  const p = { kind };
  const param = ($('#cf-http-page-param') && $('#cf-http-page-param').value || '').trim(); if (param) p.param = param;
  const size = parseInt(($('#cf-http-page-size') && $('#cf-http-page-size').value) || '', 10); if (size > 0) p.size = size;
  const sp = ($('#cf-http-page-sizeparam') && $('#cf-http-page-sizeparam').value || '').trim(); if (sp) p.size_param = sp;
  const startRaw = ($('#cf-http-page-start') && $('#cf-http-page-start').value) || '';
  if (String(startRaw).trim() !== '') { const st = parseInt(startRaw, 10); if (!Number.isNaN(st)) p.start = st; }
  const cp = ($('#cf-http-page-cursor') && $('#cf-http-page-cursor').value || '').trim(); if (cp) p.cursor_path = cp;
  const np = ($('#cf-http-page-next') && $('#cf-http-page-next').value || '').trim(); if (np) p.next_path = np;
  return p;
}

// Construit la config http_pull depuis le formulaire. Renvoie { config, defaultName, authKind } ou { error }.
// Appelée par le submit (app.js). Le secret n'est PAS ici (envoyé à part par le submit).
function httpPullFormConfig() {
  const val = id => (($(id) && $(id).value) || '').trim();
  const url = val('#cf-http-url'); const apiroot = val('#cf-http-apiroot'); const path = val('#cf-http-path');
  if (!url && !apiroot) return { error: 'URL complète OU api-root requis.' };
  const ak = ($('#cf-http-auth') && $('#cf-http-auth').value) || 'none';
  const auth = { kind: ak };
  if (ak === 'token' || ak === 'header') {
    const h = val('#cf-http-header'); if (h) auth.header_name = h;
    const pfx = ($('#cf-http-prefix') && $('#cf-http-prefix').value) || ''; if (pfx) auth.prefix = pfx; // préfixe : espaces significatifs -> pas de trim
  }
  if (ak === 'oauth2_client_credentials') {
    const tu = val('#cf-http-tokenurl'); if (!tu) return { error: 'token_url requis pour OAuth2 client-credentials.' };
    auth.token_url = tu;
    const ci = val('#cf-http-clientid'); if (ci) auth.client_id = ci;
    const sc = val('#cf-http-scope'); if (sc) auth.scope = sc;
  }
  const fieldMap = collectKv('#cf-http-fieldmap');
  if (!Object.keys(fieldMap).length) return { error: 'au moins un champ dans le field-map est requis (ex: message → JSONPath).' };
  const config = {
    method: (($('#cf-http-method') && $('#cf-http-method').value) === 'POST') ? 'POST' : 'GET',
    records_path: val('#cf-http-records'),
    field_map: fieldMap,
    auth,
  };
  if (url) config.url = url; else { config.api_root = apiroot; if (path) config.path = path; }
  const src = val('#cf-http-source'); if (src) config.source = src;
  const st = val('#cf-http-sourcetype'); if (st) config.sourcetype = st;
  const body = ($('#cf-http-body') && $('#cf-http-body').value) || '';
  if (config.method === 'POST' && body.trim()) config.body = body;
  const page = collectPagination(); if (page) config.pagination = page;
  const stMap = collectKv('#cf-http-stmap'); if (Object.keys(stMap).length) config.sourcetype_map = stMap;
  const wmField = val('#cf-http-wm-field');
  if (wmField) {
    const wm = { field_path: wmField, format: (($('#cf-http-wm-format') && $('#cf-http-wm-format').value) === 'epoch') ? 'epoch' : 'iso8601' };
    const wp = val('#cf-http-wm-param'); if (wp) wm.param = wp;
    const wt = ($('#cf-http-wm-template') && $('#cf-http-wm-template').value) || ''; if (wt.trim()) wm.template = wt;
    config.watermark = wm;
  }
  return { config, defaultName: 'Connecteur HTTP', authKind: ak };
}

// TEST / PRÉVISUALISATION http_pull : POST /api/connectors/{id}/test (dry-run) -> {ok,sample_count,sample:[…events
// mappés]} SANS ingérer ni révéler le secret. Rend l'échantillon mappé pour vérifier le field_map AVANT d'activer.
// Nécessite un connecteur ENREGISTRÉ (le /test lit la config en base) : sinon on invite à enregistrer d'abord.
async function previewHttpPull() {
  const out = $('#cf-http-preview-out'); if (!out) return;
  if (!S.editingConnector) { toast('Enregistre d\'abord le connecteur (créé désactivé), puis prévisualise.', 'info', 4200); return; }
  out.hidden = false; out.replaceChildren(muted('test en cours…'));
  let j;
  try { j = await apiSend('/connectors/' + S.editingConnector + '/test', 'POST'); }
  catch (e) { out.replaceChildren(muted('échec du test : ' + ((e && e.message) || e))); return; }
  renderHttpPreview(out, j || {});
}

// Rendu de la valeur d'une cellule de preview (ts -> date lisible ; severity -> label ; objet -> JSON compact).
function previewCell(k, v) {
  if (v == null) return '';
  if (k === 'ts') return typeof v === 'number' ? fmtTs(v) : String(v);
  if (k === 'severity') return sev(Number(v)) + ' (' + v + ')';
  if (k === 'fields' || (typeof v === 'object')) return JSON.stringify(v);
  return String(v);
}
// Table des events mappés (échantillon). Colonnes = union ordonnée des clés présentes. textContent (anti-XSS).
function renderHttpPreview(out, j) {
  out.replaceChildren();
  if (!j.ok) { out.appendChild(muted('échec : ' + (j.error || 'erreur inconnue'))); return; }
  const sample = Array.isArray(j.sample) ? j.sample : [];
  const head = document.createElement('div'); head.className = 'muted'; head.style.cssText = 'margin:8px 0 6px;font-size:12px';
  head.textContent = 'Test OK — ' + (j.sample_count != null ? j.sample_count : 0) + ' event(s) au 1er lot ; aperçu de ' + sample.length + ' event(s) mappé(s) (aucune ingestion) :';
  out.appendChild(head);
  if (!sample.length) { out.appendChild(muted('aucun event mappé — vérifie records_path et le field-map (le serveur a répondu, mais aucun record n\'a produit d\'event).')); return; }
  const ORDER = ['ts', 'source', 'category', 'severity', 'message', 'host', 'src_ip', 'dst_ip', 'url', 'dedup', 'fields'];
  const keys = [];
  ORDER.forEach(k => { if (sample.some(e => e && e[k] != null)) keys.push(k); });
  sample.forEach(e => Object.keys(e || {}).forEach(k => { if (!keys.includes(k)) keys.push(k); }));
  const scroll = document.createElement('div'); scroll.className = 'plscroll';
  const table = document.createElement('table'); table.className = 'qtable';
  const thead = document.createElement('thead'); const htr = document.createElement('tr');
  keys.forEach(k => { const th = document.createElement('th'); th.textContent = k; htr.appendChild(th); });
  thead.appendChild(htr); table.appendChild(thead);
  const tb = document.createElement('tbody');
  sample.forEach(e => {
    const tr = document.createElement('tr');
    keys.forEach(k => { const td = document.createElement('td'); const cell = previewCell(k, e ? e[k] : undefined); td.textContent = cell; td.title = cell; tr.appendChild(td); });
    tb.appendChild(tr);
  });
  table.appendChild(tb); scroll.appendChild(table); out.appendChild(scroll);
}

function openConnectorForm(c, presetType) {
  // CREATE si `c` est absent OU si c'est un objet SYNTHÉTIQUE sans id (pré-rempli depuis un preset) —
  // un tel objet porte `config`/`type` pour pré-remplir le form mais doit passer par POST /api/connectors
  // (create), pas par l'update. Les connecteurs réels portent toujours un `id`.
  S.editingConnector = (c && c.id != null) ? c.id : null;
  const cfg = (c && c.config) || {};
  $('#connector-form').classList.remove('hidden');
  $('#cf-name').value = c ? (c.name || '') : '';
  $('#cf-type').value = c ? (c.type || 'defender') : (presetType || 'defender');
  $('#cf-env').value = c ? (c.env_id || 'prod') : 'prod';
  $('#cf-interval').value = c ? (c.interval_s || 300) : 300;
  $('#cf-enabled').checked = c ? !!c.enabled : false;
  // Defender
  $('#cf-azure').value = cfg.azure_tenant || '';
  $('#cf-client').value = cfg.client_id || '';
  $('#cf-resource').value = cfg.resource === 'incidents' ? 'incidents' : 'alerts';
  $('#cf-lookback').value = cfg.lookback_days || 7;
  // TAXII 2.1 (#23/#24) — config { api_root, collection, auth, username? }
  if ($('#cf-taxii-url')) $('#cf-taxii-url').value = cfg.api_root || cfg.url || '';
  if ($('#cf-taxii-collection')) $('#cf-taxii-collection').value = cfg.collection || '';
  if ($('#cf-taxii-auth')) $('#cf-taxii-auth').value = ['basic', 'token', 'none'].includes(cfg.auth) ? cfg.auth : 'none';
  if ($('#cf-taxii-user')) $('#cf-taxii-user').value = cfg.username || '';
  // Generic HTTP (#20/#22) — config { url|api_root+path, method, records_path, source?, sourcetype?, field_map{},
  // sourcetype_map{}, auth{}, pagination{}, watermark{} }.
  const isHttp = ($('#cf-type').value === 'http_pull');
  if ($('#cf-http-url')) $('#cf-http-url').value = cfg.url || '';
  if ($('#cf-http-apiroot')) $('#cf-http-apiroot').value = cfg.api_root || '';
  if ($('#cf-http-path')) $('#cf-http-path').value = cfg.path || '';
  if ($('#cf-http-method')) $('#cf-http-method').value = cfg.method === 'POST' ? 'POST' : 'GET';
  if ($('#cf-http-body')) $('#cf-http-body').value = cfg.body || '';
  if ($('#cf-http-records')) $('#cf-http-records').value = cfg.records_path || '';
  if ($('#cf-http-source')) $('#cf-http-source').value = cfg.source || '';
  if ($('#cf-http-sourcetype')) $('#cf-http-sourcetype').value = cfg.sourcetype || '';
  const hauth = cfg.auth || {};
  if ($('#cf-http-auth')) $('#cf-http-auth').value = ['basic', 'bearer', 'token', 'header', 'oauth2_client_credentials'].includes(hauth.kind) ? hauth.kind : 'none';
  if ($('#cf-http-header')) $('#cf-http-header').value = hauth.header_name || '';
  if ($('#cf-http-prefix')) $('#cf-http-prefix').value = hauth.prefix || '';
  if ($('#cf-http-tokenurl')) $('#cf-http-tokenurl').value = hauth.token_url || '';
  if ($('#cf-http-clientid')) $('#cf-http-clientid').value = hauth.client_id || '';
  if ($('#cf-http-scope')) $('#cf-http-scope').value = hauth.scope || '';
  const hpage = cfg.pagination || {};
  if ($('#cf-http-page')) $('#cf-http-page').value = ['offset', 'page', 'cursor', 'link_header'].includes(hpage.kind) ? hpage.kind : 'none';
  if ($('#cf-http-page-param')) $('#cf-http-page-param').value = hpage.param || '';
  if ($('#cf-http-page-size')) $('#cf-http-page-size').value = hpage.size != null ? hpage.size : '';
  if ($('#cf-http-page-sizeparam')) $('#cf-http-page-sizeparam').value = hpage.size_param || '';
  if ($('#cf-http-page-start')) $('#cf-http-page-start').value = hpage.start != null ? hpage.start : '';
  if ($('#cf-http-page-cursor')) $('#cf-http-page-cursor').value = hpage.cursor_path || '';
  if ($('#cf-http-page-next')) $('#cf-http-page-next').value = hpage.next_path || '';
  const wm = cfg.watermark || {};
  if ($('#cf-http-wm-field')) $('#cf-http-wm-field').value = wm.field_path || '';
  if ($('#cf-http-wm-param')) $('#cf-http-wm-param').value = wm.param || '';
  if ($('#cf-http-wm-format')) $('#cf-http-wm-format').value = wm.format === 'epoch' ? 'epoch' : 'iso8601';
  if ($('#cf-http-wm-template')) $('#cf-http-wm-template').value = wm.template || '';
  // field_map + sourcetype_map : reconstruit les rangées (scaffold par défaut si nouveau connecteur HTTP).
  const fmHost = $('#cf-http-fieldmap');
  if (fmHost) {
    fmHost.replaceChildren();
    const fm = (cfg.field_map && typeof cfg.field_map === 'object') ? cfg.field_map : {};
    const ks = Object.keys(fm);
    if (ks.length) ks.forEach(k => addFieldMapRow(k, typeof fm[k] === 'string' ? fm[k] : JSON.stringify(fm[k])));
    else if (isHttp && !c) DEFAULT_FIELD_MAP.forEach(k => addFieldMapRow(k, ''));
  }
  const stHost = $('#cf-http-stmap');
  if (stHost) { stHost.replaceChildren(); const sm = (cfg.sourcetype_map && typeof cfg.sourcetype_map === 'object') ? cfg.sourcetype_map : {}; Object.keys(sm).forEach(k => addStMapRow(k, sm[k])); }
  const pvOut = $('#cf-http-preview-out'); if (pvOut) { pvOut.hidden = true; pvOut.replaceChildren(); }
  $('#cf-secret').value = '';   // le secret n'est JAMAIS réaffiché — vide = conserver l'existant (édition)
  applyConnectorType();         // montre les champs du bon type + ajuste l'indice du secret
  $('#cf-result').textContent = '';
  $('#cf-name').focus();
}

// ============ P1 « connecteurs actifs » — PICKER DE PRESETS ============
// GET /api/connectors/presets (admin-only) sert une bibliothèque EMBARQUÉE (métadonnée + template
// http_pull, JAMAIS de secret). Sélectionner un preset INSTANCIABLE pré-remplit le formulaire existant
// (openConnectorForm sur un objet SYNTHÉTIQUE sans id -> chemin CREATE), l'admin saisit le secret + les
// placeholders puis crée (désactivé) et teste — 100 % du flux existant (create -> test -> enable). Les
// presets EXCLUS (AWS SigV4 / GCP SA-JWT) sont affichés grisés (bientôt / via push -> HEC), non cliquables.
async function openPresetPicker() {
  const host = $('#connector-preset-picker'); if (!host) return;
  if (!uiIsAdmin()) { toast('réservé à l\'administrateur.', 'bad'); return; }
  $('#connector-form').classList.add('hidden');   // referme le form si ouvert
  host.classList.remove('hidden');
  host.replaceChildren(muted('chargement des presets…'));
  const data = await fetchInto(host, '/connectors/presets'); if (!data) return;
  const presets = (data && Array.isArray(data.presets)) ? data.presets : [];
  renderPresetPicker(host, presets);
}

// Rend le picker (textContent — anti-XSS). Instanciables cliquables (pré-remplissent le form) ; exclus grisés.
function renderPresetPicker(host, presets) {
  host.replaceChildren();
  const head = document.createElement('div'); head.className = 'cf-kvhead';
  const title = document.createElement('b'); title.textContent = 'Partir d\'un preset vendeur';
  const close = document.createElement('button'); close.type = 'button'; close.className = 'cf-kvadd'; close.textContent = 'Fermer';
  close.onclick = () => host.classList.add('hidden');
  head.append(title, close);
  const sub = document.createElement('p'); sub.className = 'muted'; sub.style.cssText = 'margin:4px 0 8px;font-size:12px';
  sub.textContent = 'Sélectionne un connecteur : le formulaire se pré-remplit (auth, endpoint, field-map). Renseigne le secret et les valeurs surlignées, puis crée-le (désactivé) et teste-le. Aucun secret n\'est transmis par cette liste.';
  host.append(head, sub);

  const usable = presets.filter(p => p && p.instantiable);
  // P-HEC : presets PUSH (AWS Firehose) — instanciables en source push (bouton réel), distincts des grisés.
  const push = presets.filter(p => p && !p.instantiable && p.push_source);
  const later = presets.filter(p => p && !p.instantiable && !p.push_source);

  usable.forEach(p => host.appendChild(presetRow(p, 'usable')));
  if (push.length) {
    const sep = document.createElement('div'); sep.className = 'muted'; sep.style.cssText = 'margin:10px 0 4px;font-size:12px;font-weight:600';
    sep.textContent = 'Source PUSH — le cloud pousse vers Plume (aucune clé cloud stockée)';
    host.appendChild(sep);
    push.forEach(p => host.appendChild(presetRow(p, 'push')));
  }
  if (later.length) {
    const sep = document.createElement('div'); sep.className = 'muted'; sep.style.cssText = 'margin:10px 0 4px;font-size:12px;font-weight:600';
    sep.textContent = 'Bientôt — livraison push (auth SA-JWT à venir)';
    host.appendChild(sep);
    later.forEach(p => host.appendChild(presetRow(p, 'soon')));
  }
}

// Une rangée preset. `mode` : 'usable' (poll http_pull, pré-remplit le form) | 'push' (P-HEC : crée une
// source push + minte la clé de livraison) | 'soon' (grisé, non cliquable, affiche la note d'orientation).
function presetRow(p, mode) {
  const row = document.createElement('div'); row.className = 'rulerow';
  if (mode === 'soon') row.style.opacity = '0.6';
  const vendor = document.createElement('code'); vendor.className = 'rulecond'; vendor.textContent = p.vendor || '?';
  const label = document.createElement('span'); label.className = 'rulename'; label.textContent = p.label || p.id || '?';
  const auth = document.createElement('span'); auth.className = 'badge';
  auth.textContent = mode === 'push' ? 'push' : (p.auth_kind || 'none');
  auth.title = mode === 'push' ? 'Livraison PUSH — le cloud pousse vers Plume via une clé de livraison' : 'Méthode d\'authentification';
  const desc = document.createElement('span'); desc.className = 'rulemeta muted';
  desc.textContent = (p.description || '').slice(0, 160); desc.title = p.description || '';
  row.append(vendor, label, auth, desc);
  if (mode === 'usable') {
    const use = document.createElement('button'); use.type = 'button'; use.className = 'btn btn-sm'; use.textContent = 'Utiliser ce preset'; // P11.4-b : classe partagée
    use.title = 'Pré-remplit le formulaire (tu saisis le secret + les valeurs manquantes, puis crées désactivé)';
    use.onclick = () => instantiatePreset(p);
    row.append(use);
  } else if (mode === 'push') {
    const note = document.createElement('span'); note.className = 'rulemeta muted'; // P11.4-b : `--muted` n'existe pas ; la classe du thème
    note.textContent = (p.note || '').slice(0, 120); note.title = p.note || '';
    const use = document.createElement('button'); use.type = 'button'; use.className = 'btn btn-sm'; use.textContent = 'Créer source push'; // P11.4-b : classe partagée
    use.title = 'Crée un connecteur push + minte une clé de livraison (montrée une seule fois). Plume ne stocke AUCUNE clé cloud.';
    use.onclick = () => createPushSource(p);
    row.append(note, use);
  } else {
    const note = document.createElement('span'); note.className = 'rulemeta'; note.style.cssText = 'color:var(--warn)';
    note.textContent = p.note || 'disponible dans une phase ultérieure'; note.title = p.note || '';
    row.append(note);
  }
  return row;
}

// P-HEC — crée une SOURCE PUSH (AWS Firehose OU GCP Pub/Sub) à partir d'un preset push : POST
// /api/connectors/push-source -> Firehose { delivery_key, auth_header } OU Pub/Sub { delivery_token,
// transport:'query_token' }. showPushKey affiche la clé/URL UNE SEULE FOIS (jamais re-dérivable). Admin-only.
async function createPushSource(p) {
  if (!uiIsAdmin()) { toast('réservé à l\'administrateur.', 'bad'); return; }
  // P11.5-b : créer une source push FRAPPE un jeton de livraison (affiché une seule fois) — une élévation, donc
  // la confirmation partagée nomme la conséquence et recueille nom et environnement au même geste.
  const r = await confirmWithConsequence(`Créer une source push « ${p.label || p.id} »`,
    'un jeton de livraison sera frappé et affiché UNE SEULE FOIS : quiconque le détient peut pousser des événements dans cet environnement.',
    { okText: 'Créer et frapper le jeton', cancelText: 'Annuler',
      fields: [
        { name: 'name', label: 'Nom de la source push', placeholder: (p.label || p.id) + ' (push)' },
        { name: 'env', label: 'Environnement (env_id)', placeholder: 'prod' },
      ] });
  if (!r) return;
  const name = String(r.name || '').trim(), env = String(r.env || '').trim();
  let res;
  try { res = await apiSend('/connectors/push-source', 'POST', { preset_id: p.id, name: name || undefined, env_id: env || 'prod' }); }
  catch (e) { toast('échec création source push : ' + ((e && e.message) || e), 'bad'); return; }
  showPushKey(res, p);
  if (typeof loadConnectors === 'function') loadConnectors();
}

// Affiche (dans le picker) la clé de livraison SHOW-ONCE + l'endpoint. textContent (anti-XSS). Deux transports :
//  - GCP Pub/Sub (res.transport==='query_token' / res.delivery_token) : le token voyage en QUERY -> on montre
//    l'URL push COMPLÈTE (endpoint + ?token=<token>) à coller dans l'abonnement Pub/Sub push ; pas de header.
//  - AWS Firehose (res.delivery_key) : header X-Amz-Firehose-Access-Key + Access key séparés (INCHANGÉ).
function showPushKey(res, p) {
  const host = $('#connector-preset-picker'); if (!host || !res) return;
  host.replaceChildren();
  const head = document.createElement('div'); head.className = 'cf-kvhead';
  const title = document.createElement('b'); title.textContent = 'Source push créée — clé de livraison (affichée UNE seule fois)';
  const close = document.createElement('button'); close.type = 'button'; close.className = 'cf-kvadd'; close.textContent = 'Fermer';
  close.onclick = () => host.classList.add('hidden');
  head.append(title, close); host.append(head);
  const line = (lbl, val) => {
    const d = document.createElement('div'); d.style.cssText = 'margin:6px 0;font-size:12px';
    const b = document.createElement('b'); b.textContent = lbl + ' ';
    const code = document.createElement('code'); code.className = 'rulecond'; code.textContent = val;
    d.append(b, code); return d;
  };
  const isPubsub = res.transport === 'query_token' || !!res.delivery_token;
  if (isPubsub) {
    // GCP Pub/Sub — URL push complète (le secret est dans l'URL, montré une seule fois).
    const base = location.origin + (res.endpoint_path || '/api/ingest/pubsub');
    const pushUrl = base + '?token=' + (res.delivery_token || '');
    host.append(line('Endpoint (URL de l\'abonnement Pub/Sub push) :', base));
    const urlWrap = document.createElement('div'); urlWrap.style.cssText = 'margin:6px 0;font-size:12px';
    const ub = document.createElement('b'); ub.textContent = 'URL push complète (avec token) : ';
    const uc = document.createElement('code'); uc.className = 'rulecond'; uc.style.cssText = 'color:var(--warn);user-select:all'; uc.textContent = pushUrl;
    urlWrap.append(ub, uc); host.append(urlWrap);
    const warn = document.createElement('p'); warn.className = 'muted'; warn.style.cssText = 'margin:8px 0;font-size:12px;color:var(--warn)';
    warn.textContent = 'Copie cette URL maintenant : le token n\'est PLUS récupérable (seul son empreinte est stockée). Crée un log sink -> topic Pub/Sub, puis un abonnement « push » qui POSTe vers l\'URL ci-dessus. Chaque message push encapsule une LogEntry (mappée en CIM). Aucune clé GCP n\'est partagée avec Plume.';
    host.append(warn);
    return;
  }
  // AWS Firehose — inchangé.
  const url = location.origin + (res.endpoint_path || '/api/ingest/firehose');
  host.append(line('Endpoint (destination HTTP Firehose) :', url));
  host.append(line('Header d\'accès :', res.auth_header || 'X-Amz-Firehose-Access-Key'));
  const keyWrap = document.createElement('div'); keyWrap.style.cssText = 'margin:6px 0;font-size:12px';
  const kb = document.createElement('b'); kb.textContent = 'Clé de livraison (Access key) : ';
  const kc = document.createElement('code'); kc.className = 'rulecond'; kc.style.cssText = 'color:var(--warn);user-select:all'; kc.textContent = res.delivery_key || '';
  keyWrap.append(kb, kc); host.append(keyWrap);
  const warn = document.createElement('p'); warn.className = 'muted'; warn.style.cssText = 'margin:8px 0;font-size:12px;color:var(--warn)';
  warn.textContent = 'Copie cette clé maintenant : elle n\'est PLUS récupérable (seul son empreinte est stockée). Configure ton delivery stream Kinesis Firehose (destination « HTTP endpoint ») sur l\'URL ci-dessus, en collant la clé dans le champ « Access key ». Aucune clé AWS n\'est partagée avec Plume.';
  host.append(warn);
}

// Pré-remplit le form http_pull à partir d'un preset (objet synthétique SANS id -> chemin CREATE). Guide
// l'admin sur les placeholders `needs` restants + le secret. Le secret et les valeurs sont saisis À LA MAIN.
function instantiatePreset(p) {
  const picker = $('#connector-preset-picker'); if (picker) picker.classList.add('hidden');
  const synthetic = { name: p.label || p.id || 'Connecteur', type: 'http_pull', config: p.config || {}, env_id: 'prod', interval_s: 300 };
  openConnectorForm(synthetic);   // objet sans id -> S.editingConnector=null -> create via POST /api/connectors
  const needs = Array.isArray(p.needs) ? p.needs : [];
  const res = $('#cf-result');
  if (res) {
    const parts = [];
    if (needs.length) parts.push('remplace les placeholders (' + needs.join(', ') + ')');
    if (p.requires_secret !== false) parts.push('saisis le secret (' + (p.auth_kind || 'auth') + ')');
    parts.push('puis crée (désactivé) et teste la connexion.');
    res.textContent = 'Preset « ' + (p.label || p.id) + ' » chargé — ' + parts.join(' · ');
  }
  toast('Preset chargé' + (needs.length ? ' — ' + needs.length + ' placeholder(s) à renseigner + le secret' : ' — saisis le secret'), 'info', 4200);
}

async function deleteConnector(c) {
  if (!await confirmModal('Supprimer le connecteur « ' + (c.name || ('#' + c.id)) + ' » ? Sa configuration ET le credential stocké seront définitivement effacés, et la collecte de cette source s\'arrête.', { danger: true, okText: 'Supprimer' })) return;
  try { await apiSend('/connectors/' + c.id, 'DELETE'); }
  catch (e) { toast((e && e.message) || 'échec', 'bad'); return; }
  toast('connecteur supprimé', 'ok');
  loadConnectors();
}


export { loadConnectors, openConnectorForm, applyConnectorType, httpPullFormConfig, addFieldMapRow, addStMapRow, previewHttpPull, openPresetPicker };

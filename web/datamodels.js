// datamodels.js — #47 DATA MODELS + PIVOT + DATASETS : couche sémantique (modèles -> objets -> champs) +
// report-builder « Pivot » SANS GXQL/SPL à la main + datasets (pivots/recherches enregistrés, réutilisables).
// Vit dans l'espace DONNÉES. Lecture + exécution (Pivot / dataset run) = viewer+ ; CRUD (modèles/objets/
// champs/datasets) = éditeur+ (boutons crud-btn masqués au viewer via CSS + garde SERVEUR editor+).
//
// Réutilise 100% les endpoints #47 EXISTANTS — AUCUNE surface nouvelle, AUCUN chemin de requête/masquage
// touché. Le Pivot ne fabrique jamais de SQL : /api/pivot/run compile un GXQL puis l'exécute par le MÊME
// chemin masqué que /api/query (masquage #45 du rôle appliqué côté serveur) :
//   GET    /api/datamodels                 -> {models,objects,fields,field_types,stat_funcs,filter_ops}
//   POST   /api/datamodels | /{id}/objects | /objects/{id}/fields         (editor+)
//   DELETE /api/datamodels/{id} | /objects/{id} | /fields/{id}             (editor+)
//   POST   /api/pivot/compile  (GXQL généré, transparence)  |  /api/pivot/run  (exécution masquée)  viewer+
//   GET    /api/datasets  |  POST /api/datasets  (editor+)  |  POST /api/datasets/{id}/run  (viewer+)
//   DELETE /api/datasets/{id}                                            (editor+)
// SÉCU UI : tout en textContent/esc (anti-XSS). Mutations via apiSend (jeton CSRF auto).
import { $, api, apiSend, fetchInto, muted, pagedList, toast, modal, confirmModal, managedBadge, gateDeleteBtn } from './core.js';

// État module : cache du GET /api/datamodels + sélection courante (modèle -> objet).
let DM = { models: [], objects: [], fields: [], field_types: [], stat_funcs: [], filter_ops: [] };
let selModel = null, selObject = null;

// Fenêtres temporelles du Pivot (le panneau est hors Explore : range propre, from glissant depuis maintenant).
const RANGES = [
  { value: 3600, label: 'Dernière heure' },
  { value: 21600, label: '6 heures' },
  { value: 86400, label: '24 heures' },
  { value: 604800, label: '7 jours' },
  { value: 2592000, label: '30 jours' },
  { value: 0, label: 'Tout' },
];

// ---- helpers de rendu communs ----
function codeCell(text) { const c = document.createElement('code'); c.textContent = text == null || text === '' ? '—' : String(text); return c; }
function nameCell(text, enabled) { const s = document.createElement('span'); s.textContent = text || ''; if (enabled === false) { s.style.opacity = '.5'; s.title = 'désactivé'; } return s; }
function delBtn(managed, onDel) {
  const b = document.createElement('button'); b.type = 'button'; b.className = 'picon crud-btn'; b.textContent = 'Suppr.'; b.title = 'Supprimer';
  if (managed == null) { b.onclick = e => { e.stopPropagation(); onDel(); }; }
  else if (gateDeleteBtn(b, managed)) b.onclick = e => { e.stopPropagation(); onDel(); };
  return b;
}
// Champs déclarés de l'objet sélectionné -> options {label: nom public, value: nom SOURCE (expr||name)}.
// C'est le nom SOURCE que le Pivot injecte réellement (l'allowlist serveur = source), le label reste lisible.
function objectFieldOptions(objectId) {
  return DM.fields.filter(f => f.object_id === objectId).map(f => {
    const src = (f.expr && f.expr.trim()) ? f.expr.trim() : f.name;
    return { label: f.name + (src !== f.name ? ' (' + src + ')' : '') + ' · ' + f.type, value: src };
  });
}

// ============================ MODÈLES ============================
function renderModels() {
  const host = $('#dm-models-list'); if (!host) return;
  pagedList(host, {
    mode: 'client', pageSize: 12, rows: DM.models, sort: { key: 'name', dir: 1 },
    columns: [
      { key: 'name', label: 'Modèle', sortable: true, sortVal: r => r.name || '', render: r => { const s = nameCell(r.title || r.name, r.enabled); if (r.id === selModel) s.style.fontWeight = '700'; return s; } },
      { key: 'category', label: 'Catégorie CIM', render: r => codeCell(r.category) },
      { key: 'objs', label: 'Objets', align: 'r', render: r => String(DM.objects.filter(o => o.model_id === r.id).length) },
      { key: 'managed', label: 'Origine', render: r => managedBadge(r.managed) },
      { key: 'act', label: '', render: r => delBtn(r.managed, () => delModel(r)) },
    ],
    renderRow: null,
    emptyText: 'aucun modèle — créez un modèle sémantique (ex. « Authentication ») puis ses objets et champs pour piloter le Pivot sans écrire de GXQL.',
    onRowClick: r => selectModel(r.id),
  });
}
function selectModel(id) { selModel = id; selObject = null; renderModels(); renderObjects(); renderFields(); renderPivotBuilder(); syncButtons(); }

async function delModel(r) {
  if (!(await confirmModal('Supprimer le modèle « ' + (r.title || r.name) + " » et tous ses objets/champs ?", { okText: 'Supprimer', danger: true }))) return;
  try { await apiSend('/datamodels/' + r.id, 'DELETE'); toast('modèle supprimé', 'ok'); await reload(); }
  catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); }
}
async function newModel() {
  const v = await modal({ title: 'Nouveau modèle de données', okText: 'Créer', fields: [
    { name: 'name', label: 'Nom (identifiant)', required: true, placeholder: 'authentication' },
    { name: 'title', label: 'Titre', placeholder: 'Authentification' },
    { name: 'description', label: 'Description', type: 'textarea', placeholder: 'événements d’auth (login/logout/échecs)' },
    { name: 'category', label: 'Catégorie CIM (optionnelle)', placeholder: 'authentication' },
    { name: 'enabled', label: 'Actif', type: 'checkbox', value: true },
  ] });
  if (!v) return;
  try {
    await apiSend('/datamodels', 'POST', { name: (v.name || '').trim(), title: (v.title || '').trim(), description: (v.description || '').trim(), category: (v.category || '').trim(), enabled: !!v.enabled });
    toast('modèle créé', 'ok'); await reload();
  } catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); }
}

// ============================ OBJETS ============================
function renderObjects() {
  const host = $('#dm-objects-list'); if (!host) return;
  const ctx = $('#dm-obj-ctx'); const model = DM.models.find(m => m.id === selModel);
  if (ctx) ctx.textContent = model ? '— ' + (model.title || model.name) : '(sélectionnez un modèle)';
  if (!selModel) { host.replaceChildren(muted('sélectionnez un modèle pour voir ses objets.')); return; }
  const rows = DM.objects.filter(o => o.model_id === selModel);
  pagedList(host, {
    mode: 'client', pageSize: 12, rows, sort: { key: 'name', dir: 1 },
    columns: [
      { key: 'name', label: 'Objet', sortable: true, sortVal: r => r.name || '', render: r => { const s = nameCell(r.name, r.enabled); if (r.id === selObject) s.style.fontWeight = '700'; return s; } },
      { key: 'parent', label: 'Parent', render: r => { const p = DM.objects.find(o => o.id === r.parent_id); return codeCell(p ? p.name : ''); } },
      { key: 'constraint', label: 'Contrainte (GXQL)', render: r => codeCell(r.constraint) },
      { key: 'flds', label: 'Champs', align: 'r', render: r => String(DM.fields.filter(f => f.object_id === r.id).length) },
      { key: 'act', label: '', render: r => delBtn(null, () => delObject(r)) },
    ],
    emptyText: 'aucun objet — ajoutez un objet (contrainte GXQL optionnelle, ex. action=failure) ; ses champs alimenteront le Pivot.',
    onRowClick: r => selectObject(r.id),
  });
}
function selectObject(id) { selObject = id; renderObjects(); renderFields(); renderPivotBuilder(); syncButtons(); }

async function delObject(r) {
  if (!(await confirmModal('Supprimer l’objet « ' + r.name + ' » et ses champs ?', { okText: 'Supprimer', danger: true }))) return;
  try { await apiSend('/datamodels/objects/' + r.id, 'DELETE'); toast('objet supprimé', 'ok'); if (selObject === r.id) selObject = null; await reload(); }
  catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); }
}
async function newObject() {
  if (!selModel) return;
  const parents = DM.objects.filter(o => o.model_id === selModel);
  const v = await modal({ title: 'Nouvel objet', okText: 'Créer', fields: [
    { name: 'name', label: 'Nom (identifiant)', required: true, placeholder: 'failed_logins' },
    { name: 'constraint', label: 'Contrainte (fragment GXQL, optionnel)', placeholder: 'action=failure' },
    { name: 'parent_id', label: 'Parent (héritage de contrainte)', type: 'select', value: '', options: [{ value: '', label: '(racine)' }].concat(parents.map(p => ({ value: p.id, label: p.name }))) },
    { name: 'enabled', label: 'Actif', type: 'checkbox', value: true },
  ] });
  if (!v) return;
  const body = { name: (v.name || '').trim(), constraint: (v.constraint || '').trim(), enabled: !!v.enabled };
  if (v.parent_id) body.parent_id = Number(v.parent_id);
  try { await apiSend('/datamodels/' + selModel + '/objects', 'POST', body); toast('objet créé', 'ok'); await reload(); }
  catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); }
}

// ============================ CHAMPS ============================
function renderFields() {
  const host = $('#dm-fields-list'); if (!host) return;
  const ctx = $('#dm-field-ctx'); const obj = DM.objects.find(o => o.id === selObject);
  if (ctx) ctx.textContent = obj ? '— ' + obj.name : '(sélectionnez un objet)';
  if (!selObject) { host.replaceChildren(muted('sélectionnez un objet pour voir/ajouter ses champs.')); return; }
  const rows = DM.fields.filter(f => f.object_id === selObject);
  pagedList(host, {
    mode: 'client', pageSize: 12, rows, sort: { key: 'name', dir: 1 },
    columns: [
      { key: 'name', label: 'Champ', sortable: true, sortVal: r => r.name || '', render: r => nameCell(r.name) },
      { key: 'type', label: 'Type', render: r => codeCell(r.type) },
      { key: 'expr', label: 'Source (si renommage)', render: r => codeCell(r.expr) },
      { key: 'act', label: '', render: r => delBtn(null, () => delField(r)) },
    ],
    emptyText: 'aucun champ déclaré — sans champ, le Pivot ne peut ni découper ni agréger (fail-closed). Ajoutez au moins un champ.',
  });
}
async function delField(r) {
  if (!(await confirmModal('Supprimer le champ « ' + r.name + ' » ?', { okText: 'Supprimer', danger: true }))) return;
  try { await apiSend('/datamodels/fields/' + r.id, 'DELETE'); toast('champ supprimé', 'ok'); await reload(); }
  catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); }
}
async function newField() {
  if (!selObject) return;
  const v = await modal({ title: 'Nouveau champ', okText: 'Créer', fields: [
    { name: 'name', label: 'Nom public', required: true, placeholder: 'source_ip' },
    { name: 'type', label: 'Type', type: 'select', value: 'string', options: DM.field_types.map(t => ({ value: t, label: t })) },
    { name: 'expr', label: 'Champ source (optionnel — renomme un champ existant)', placeholder: 'src_ip' },
  ] });
  if (!v) return;
  try { await apiSend('/datamodels/objects/' + selObject + '/fields', 'POST', { name: (v.name || '').trim(), type: v.type, expr: (v.expr || '').trim() }); toast('champ créé', 'ok'); await reload(); }
  catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); }
}

// ============================ PIVOT (report-builder) ============================
// Construit les commandes dynamiques (chips split-by, lignes stats, lignes filtres) pour l'objet sélectionné.
function renderPivotBuilder() {
  const wrap = $('#dm-pivot'); if (!wrap) return;
  const obj = DM.objects.find(o => o.id === selObject);
  const hint = $('#dm-pivot-hint');
  if (!obj) { wrap.hidden = true; if (hint) hint.hidden = false; return; }
  if (hint) hint.hidden = true;
  wrap.hidden = false;
  $('#dm-pivot-obj').textContent = obj.name;
  const opts = objectFieldOptions(selObject);
  // split-by : chips à bascule (source en data-src, label public en texte).
  const sb = $('#dm-pivot-splitby'); sb.replaceChildren();
  if (!opts.length) { sb.appendChild(muted('déclarez des champs sur cet objet pour découper/agréger.')); }
  opts.forEach(o => {
    const chip = document.createElement('button'); chip.type = 'button'; chip.className = 'pv-chip'; chip.textContent = o.label; chip.dataset.src = o.value;
    chip.onclick = () => chip.classList.toggle('on');
    sb.appendChild(chip);
  });
  // reset des lignes stats/filtres + une ligne stats par défaut (count).
  $('#dm-pivot-stats').replaceChildren();
  $('#dm-pivot-filters').replaceChildren();
  addStatRow('count', '');
  $('#dm-pivot-soql').hidden = true; $('#dm-pivot-soql').textContent = '';
  $('#dm-pivot-result').replaceChildren();
}
function fieldSelect(cls, withCount, sel) {
  const s = document.createElement('select'); s.className = cls;
  if (withCount) { const o = document.createElement('option'); o.value = ''; o.textContent = '(count : sans champ)'; s.appendChild(o); }
  objectFieldOptions(selObject).forEach(opt => { const o = document.createElement('option'); o.value = opt.value; o.textContent = opt.label; if (opt.value === sel) o.selected = true; s.appendChild(o); });
  return s;
}
function addStatRow(func, field) {
  const row = document.createElement('div'); row.className = 'pv-row pv-statrow';
  const fn = document.createElement('select'); fn.className = 'pv-func';
  DM.stat_funcs.forEach(f => { const o = document.createElement('option'); o.value = f; o.textContent = f; if (f === func) o.selected = true; fn.appendChild(o); });
  const fld = fieldSelect('pv-field', true, field);
  const rm = document.createElement('button'); rm.type = 'button'; rm.className = 'picon pv-del'; rm.textContent = '×'; rm.title = 'Retirer'; rm.onclick = () => row.remove();
  row.append(fn, fld, rm);
  $('#dm-pivot-stats').appendChild(row);
}
function addFilterRow() {
  const row = document.createElement('div'); row.className = 'pv-row pv-filterrow';
  const fld = fieldSelect('pv-ffield', false, '');
  const op = document.createElement('select'); op.className = 'pv-fop';
  DM.filter_ops.forEach(o2 => { const o = document.createElement('option'); o.value = o2; o.textContent = o2; op.appendChild(o); });
  const val = document.createElement('input'); val.className = 'pv-fval'; val.placeholder = 'valeur'; val.autocomplete = 'off'; val.spellcheck = false;
  const rm = document.createElement('button'); rm.type = 'button'; rm.className = 'picon pv-del'; rm.textContent = '×'; rm.title = 'Retirer'; rm.onclick = () => row.remove();
  row.append(fld, op, val, rm);
  $('#dm-pivot-filters').appendChild(row);
}
// Lit la PivotSpec depuis le DOM du builder (aucune saisie GXQL/SPL libre).
function collectSpec() {
  const splitby = [...document.querySelectorAll('#dm-pivot-splitby .pv-chip.on')].map(el => el.dataset.src);
  const stats = [...document.querySelectorAll('#dm-pivot-stats .pv-statrow')].map(r => ({ func: r.querySelector('.pv-func').value, field: r.querySelector('.pv-field').value || null })).filter(s => s.func);
  const filters = [...document.querySelectorAll('#dm-pivot-filters .pv-filterrow')].map(r => ({ field: r.querySelector('.pv-ffield').value, op: r.querySelector('.pv-fop').value, value: r.querySelector('.pv-fval').value })).filter(f => f.field && f.value !== '');
  const span = ($('#dm-pivot-span').value || '').trim();
  const limit = Number($('#dm-pivot-limit').value) || 1000;
  return { object_id: selObject, splitby, stats, filters, span, limit };
}
function rangeFromTo() { const w = Number($('#dm-pivot-range').value) || 0; const now = Math.floor(Date.now() / 1000); return { from: w > 0 ? now - w : 0, to: 0 }; }

async function pivotCompile() {
  try {
    const d = await apiSend('/pivot/compile', 'POST', collectSpec());
    const el = $('#dm-pivot-soql'); el.hidden = false; el.textContent = d && d.soql ? d.soql : '(vide)';
  } catch (e) { toast('compilation : ' + ((e && e.message) || e), 'err', 6000); }
}
async function pivotRun() {
  const { from, to } = rangeFromTo();
  try {
    const d = await apiSend('/pivot/run', 'POST', Object.assign(collectSpec(), { from, to }));
    if (d && d.soql) { const el = $('#dm-pivot-soql'); el.hidden = false; el.textContent = d.soql; }
    renderResults($('#dm-pivot-result'), d);
  } catch (e) { toast('exécution : ' + ((e && e.message) || e), 'err', 6000); $('#dm-pivot-result').replaceChildren(muted('erreur : ' + ((e && e.message) || e))); }
}
async function pivotSave() {
  const v = await modal({ title: 'Enregistrer comme dataset', okText: 'Enregistrer', fields: [{ name: 'name', label: 'Nom du dataset', required: true, placeholder: 'echecs_auth_par_ip' }] });
  if (!v) return;
  try { await apiSend('/datasets', 'POST', Object.assign(collectSpec(), { kind: 'pivot', name: (v.name || '').trim() })); toast('dataset enregistré', 'ok'); loadDatasets(); }
  catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); }
}

// Rend un résultat {columns:[], rows:[[…]], stats} en table paginée (colonnes dynamiques).
function renderResults(host, d) {
  if (!host) return;
  const cols = (d && Array.isArray(d.columns)) ? d.columns : [];
  const raw = (d && Array.isArray(d.rows)) ? d.rows : [];
  const rows = raw.map(arr => { const o = {}; cols.forEach((c, i) => { o[c] = arr[i]; }); return o; });
  const columns = cols.map(c => ({ key: c, label: c, sortable: true, sortVal: r => r[c], render: r => { const s = document.createElement('span'); const v = r[c]; s.textContent = v == null ? '' : String(v); return s; } }));
  const box = document.createElement('div');
  if (d && d.stats) { const p = document.createElement('div'); p.className = 'muted'; p.style.margin = '4px 0'; p.textContent = d.stats.rows + ' ligne(s)' + (d.stats.truncated ? ' (tronqué)' : '') + ' — ' + d.stats.elapsed_ms + ' ms'; box.appendChild(p); }
  const listHost = document.createElement('div'); box.appendChild(listHost);
  host.replaceChildren(box);
  if (!cols.length) { listHost.appendChild(muted('aucune colonne (résultat vide).')); return; }
  pagedList(listHost, { mode: 'client', pageSize: 20, rows, columns, emptyText: 'aucune ligne sur la fenêtre choisie.' });
}

// ============================ DATASETS ============================
async function loadDatasets() {
  const host = $('#dm-datasets-list'); if (!host) return;
  const d = await fetchInto(host, '/datasets'); if (!d) return;
  const rows = (d && Array.isArray(d.datasets)) ? d.datasets : [];
  pagedList(host, {
    mode: 'client', pageSize: 12, rows, sort: { key: 'name', dir: 1 },
    columns: [
      { key: 'name', label: 'Dataset', sortable: true, sortVal: r => r.name || '', render: r => nameCell(r.name, r.enabled) },
      { key: 'kind', label: 'Type', render: r => codeCell(r.kind) },
      { key: 'soql', label: 'GXQL', render: r => codeCell(r.soql) },
      { key: 'managed', label: 'Origine', render: r => managedBadge(r.managed) },
      { key: 'act', label: '', render: r => {
        const wrap = document.createElement('span'); wrap.className = 'row-actions';
        const run = document.createElement('button'); run.type = 'button'; run.className = 'picon'; run.textContent = 'Exécuter'; run.title = 'Exécuter sur la fenêtre courante du Pivot';
        run.onclick = e => { e.stopPropagation(); runDataset(r); };
        wrap.append(run, delBtn(r.managed, () => delDataset(r)));
        return wrap;
      } },
    ],
    emptyText: 'aucun dataset — construisez un Pivot puis « Enregistrer comme dataset » pour le réutiliser.',
  });
}
async function runDataset(r) {
  const { from, to } = rangeFromTo();
  let d;
  try { d = await apiSend('/datasets/' + r.id + '/run', 'POST', { from, to, limit: 1000 }); }
  catch (e) { toast('exécution : ' + ((e && e.message) || e), 'err', 6000); return; }
  const body = document.createElement('div'); renderResults(body, d);
  resultModal('Dataset — ' + r.name, body);
}
async function delDataset(r) {
  if (!(await confirmModal('Supprimer le dataset « ' + r.name + ' » ?', { okText: 'Supprimer', danger: true }))) return;
  try { await apiSend('/datasets/' + r.id, 'DELETE'); toast('dataset supprimé', 'ok'); loadDatasets(); }
  catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); }
}

// ---- petite modale de résultat (lecture seule) ----
function resultModal(title, bodyEl) {
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal'; box.style.maxWidth = '760px';
  const h = document.createElement('h3'); h.textContent = title; box.appendChild(h); box.appendChild(bodyEl);
  const act = document.createElement('div'); act.className = 'modal-act';
  const ok = document.createElement('button'); ok.type = 'button'; ok.className = 'm-ok'; ok.textContent = 'Fermer';
  const close = () => { ov.classList.add('out'); setTimeout(() => ov.remove(), 160); };
  ok.onclick = close; act.appendChild(ok); box.appendChild(act);
  ov.onclick = e => { if (e.target === ov) close(); };
  ov.appendChild(box); document.body.appendChild(ov);
}

// ---- activation/désactivation des boutons selon la sélection ----
function syncButtons() {
  const objBtn = $('#dm-obj-new'); if (objBtn) objBtn.disabled = !selModel;
  const fldBtn = $('#dm-field-new'); if (fldBtn) fldBtn.disabled = !selObject;
}

// ---- (re)chargement des données + rendu ----
async function reload() {
  let d;
  try { d = await api('/datamodels'); }
  catch (e) { const h = $('#dm-models-list'); if (h) h.replaceChildren(muted('erreur : ' + ((e && e.message) || e))); return; }
  DM = {
    models: Array.isArray(d.models) ? d.models : [], objects: Array.isArray(d.objects) ? d.objects : [], fields: Array.isArray(d.fields) ? d.fields : [],
    field_types: Array.isArray(d.field_types) ? d.field_types : ['string'], stat_funcs: Array.isArray(d.stat_funcs) ? d.stat_funcs : ['count'], filter_ops: Array.isArray(d.filter_ops) ? d.filter_ops : ['='],
  };
  if (selModel && !DM.models.some(m => m.id === selModel)) selModel = null;
  if (selObject && !DM.objects.some(o => o.id === selObject)) selObject = null;
  renderModels(); renderObjects(); renderFields(); renderPivotBuilder(); syncButtons();
}

let _wired = false;
function wireOnce() {
  if (_wired) return; _wired = true;
  const bind = (id, fn) => { const el = $(id); if (el) el.onclick = fn; };
  bind('#dm-model-new', newModel); bind('#dm-obj-new', newObject); bind('#dm-field-new', newField);
  bind('#dm-pivot-addstat', () => addStatRow('count', '')); bind('#dm-pivot-addfilter', addFilterRow);
  bind('#dm-pivot-compile', pivotCompile); bind('#dm-pivot-run', pivotRun); bind('#dm-pivot-save', pivotSave);
  // range select : peuplé une fois.
  const rg = $('#dm-pivot-range');
  if (rg && !rg.options.length) RANGES.forEach(r => { const o = document.createElement('option'); o.value = r.value; o.textContent = r.label; if (r.value === 86400) o.selected = true; rg.appendChild(o); });
}

function loadDataModels() { wireOnce(); reload(); loadDatasets(); }

export { loadDataModels };

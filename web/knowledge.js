// knowledge.js — #46 KNOWLEDGE OBJECTS : gestion des objets de savoir « search-time » (alias de champ,
// champs calculés, event types, tags). Vit dans l'espace DONNÉES. Lecture viewer+ (transparence de la
// politique : ces objets façonnent la recherche de TOUT LE MONDE) ; CRUD éditeur+ (boutons masqués au
// viewer via CSS role-viewer + garde SERVEUR editor+). Réutilise 100% les endpoints #46 EXISTANTS :
//   GET    /api/knowledge                 -> {aliases:[], calcs:[], eventtypes:[], tags:[]}
//   POST   /api/knowledge/alias|calc|eventtype|tag         (editor+)
//   DELETE /api/knowledge/alias|calc|eventtype|tag/:id     (editor+)
// SÉCU UI : tout en textContent/esc (anti-XSS). Mutations via apiSend (jeton CSRF auto). Aucune surface
// nouvelle ni chemin de requête/masquage touché — pure UI sur des routes déjà en place.
import { $, api, apiSend, muted, pagedList, toast, modal, confirmModal, managedBadge, gateDeleteBtn } from './core.js';

// Cellule d'actions (Éditer masqué : les KO se recréent ; on n'expose que Suppr. gardé par « managed »).
function delCell(managed, onDel) {
  const wrap = document.createElement('span'); wrap.className = 'row-actions';
  const dl = document.createElement('button'); dl.type = 'button'; dl.className = 'picon crud-btn'; dl.textContent = 'Suppr.'; dl.title = 'Supprimer';
  if (gateDeleteBtn(dl, managed)) dl.onclick = e => { e.stopPropagation(); onDel(); };
  wrap.appendChild(dl);
  return wrap;
}
function nameCell(text, enabled) {
  const s = document.createElement('span'); s.textContent = text || '';
  if (!enabled) { s.style.opacity = '.5'; s.title = 'désactivé'; }
  return s;
}
function codeCell(text) { const c = document.createElement('code'); c.textContent = text == null ? '' : String(text); return c; }

async function del(kind, id, label, human) {
  if (!(await confirmModal('Supprimer ' + human + ' « ' + label + ' » ?', { okText: 'Supprimer', danger: true }))) return;
  try { await apiSend('/knowledge/' + kind + '/' + id, 'DELETE'); toast(human + ' supprimé', 'ok'); loadKnowledge(); }
  catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); }
}
async function create(kind, human, fields, payloadFn) {
  const v = await modal({ title: 'Nouvel objet — ' + human, okText: 'Créer', fields });
  if (!v) return;
  try { await apiSend('/knowledge/' + kind, 'POST', payloadFn(v)); toast(human + ' créé', 'ok'); loadKnowledge(); }
  catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); }
}

// ---- rendu des 4 familles (chaque liste = pagedList, croissante) ----
function renderAliases(rows) {
  pagedList($('#ko-alias-list'), {
    mode: 'client', pageSize: 15, rows, sort: { key: 'canonical', dir: 1 },
    columns: [
      { key: 'canonical', label: 'Nom canonique', sortable: true, sortVal: r => r.canonical || '', render: r => nameCell(r.canonical, r.enabled) },
      { key: 'source', label: 'Champ source', sortable: true, sortVal: r => r.source || '', render: r => codeCell(r.source) },
      { key: 'managed', label: 'Origine', render: r => managedBadge(r.managed) },
      { key: 'act', label: '', render: r => delCell(r.managed, () => del('alias', r.id, r.canonical, "l'alias")) },
    ],
    emptyText: 'aucun alias — mappez un nom canonique (ex. client_ip) vers un champ source (ex. src_ip) pour l’harmoniser dans toute recherche.',
  });
}
function renderCalcs(rows) {
  pagedList($('#ko-calc-list'), {
    mode: 'client', pageSize: 15, rows, sort: { key: 'ord', dir: 1 },
    columns: [
      { key: 'name', label: 'Nom', sortable: true, sortVal: r => r.name || '', render: r => nameCell(r.name, r.enabled) },
      { key: 'expr', label: 'Expression', render: r => codeCell(r.expr) },
      { key: 'ord', label: 'Ordre', align: 'r', sortable: true, sortVal: r => r.ord || 0, render: r => String(r.ord == null ? 0 : r.ord) },
      { key: 'managed', label: 'Origine', render: r => managedBadge(r.managed) },
      { key: 'act', label: '', render: r => delCell(r.managed, () => del('calc', r.id, r.name, 'le champ calculé')) },
    ],
    emptyText: 'aucun champ calculé — définissez un champ dérivé (ex. sev_up = upper(severity)) réutilisable partout.',
  });
}
function renderEventtypes(rows) {
  pagedList($('#ko-eventtype-list'), {
    mode: 'client', pageSize: 15, rows, sort: { key: 'name', dir: 1 },
    columns: [
      { key: 'name', label: 'Nom', sortable: true, sortVal: r => r.name || '', render: r => nameCell(r.name, r.enabled) },
      { key: 'filter', label: 'Filtre (GXQL)', render: r => codeCell(r.filter) },
      { key: 'managed', label: 'Origine', render: r => managedBadge(r.managed) },
      { key: 'act', label: '', render: r => delCell(r.managed, () => del('eventtype', r.id, r.name, "l'event type")) },
    ],
    emptyText: 'aucun event type — nommez une classe d’événements (ex. web_attack = source=web severity=HIGH) pour la réutiliser comme eventtype=web_attack.',
  });
}
function renderTags(rows) {
  pagedList($('#ko-tag-list'), {
    mode: 'client', pageSize: 15, rows, sort: { key: 'label', dir: 1 },
    columns: [
      { key: 'label', label: 'Label', sortable: true, sortVal: r => r.label || '', render: r => nameCell(r.label, r.enabled) },
      { key: 'field', label: 'Champ', sortable: true, sortVal: r => r.field || '', render: r => codeCell(r.field) },
      { key: 'value', label: 'Valeur', render: r => codeCell(r.value) },
      { key: 'managed', label: 'Origine', render: r => managedBadge(r.managed) },
      { key: 'act', label: '', render: r => delCell(r.managed, () => del('tag', r.id, r.label, 'le tag')) },
    ],
    emptyText: 'aucun tag — étiquetez des événements (ex. tag « pci » sur category=payment) pour les rechercher par tag.',
  });
}

// ---- formulaires de création (le serveur valide/refuse ; on ne fait que remonter l'erreur) ----
function newAlias() {
  create('alias', 'alias de champ',
    [{ name: 'canonical', label: 'Nom canonique', required: true, placeholder: 'client_ip' },
     { name: 'source', label: 'Champ source', required: true, placeholder: 'src_ip' },
     { name: 'enabled', label: 'Actif', type: 'checkbox', value: true }],
    v => ({ canonical: (v.canonical || '').trim(), source: (v.source || '').trim(), enabled: !!v.enabled }));
}
function newCalc() {
  create('calc', 'champ calculé',
    [{ name: 'name', label: 'Nom', required: true, placeholder: 'sev_up' },
     { name: 'expr', label: 'Expression', type: 'textarea', required: true, placeholder: 'upper(severity)' },
     { name: 'ord', label: 'Ordre (résolution)', type: 'number', value: 0 },
     { name: 'enabled', label: 'Actif', type: 'checkbox', value: true }],
    v => ({ name: (v.name || '').trim(), expr: (v.expr || '').trim(), ord: Number(v.ord) || 0, enabled: !!v.enabled }));
}
function newEventtype() {
  create('eventtype', 'event type',
    [{ name: 'name', label: 'Nom', required: true, placeholder: 'web_attack' },
     { name: 'filter', label: 'Filtre (GXQL)', type: 'textarea', required: true, placeholder: 'source=web severity=HIGH' },
     { name: 'enabled', label: 'Actif', type: 'checkbox', value: true }],
    v => ({ name: (v.name || '').trim(), filter: (v.filter || '').trim(), enabled: !!v.enabled }));
}
function newTag() {
  create('tag', 'tag',
    [{ name: 'label', label: 'Label', required: true, placeholder: 'pci' },
     { name: 'field', label: 'Champ', required: true, placeholder: 'category' },
     { name: 'value', label: 'Valeur', required: true, placeholder: 'payment' },
     { name: 'enabled', label: 'Actif', type: 'checkbox', value: true }],
    v => ({ label: (v.label || '').trim(), field: (v.field || '').trim(), value: (v.value || '').trim(), enabled: !!v.enabled }));
}

// ---- entrée : charge les 4 familles + branche les boutons « Nouveau » ----
async function loadKnowledge() {
  const na = $('#ko-alias-new'); if (na) na.onclick = newAlias;
  const nc = $('#ko-calc-new'); if (nc) nc.onclick = newCalc;
  const ne = $('#ko-eventtype-new'); if (ne) ne.onclick = newEventtype;
  const nt = $('#ko-tag-new'); if (nt) nt.onclick = newTag;
  let d;
  try { d = await api('/knowledge'); }
  catch (e) {
    ['#ko-alias-list', '#ko-calc-list', '#ko-eventtype-list', '#ko-tag-list'].forEach(s => { if ($(s)) $(s).replaceChildren(muted('erreur : ' + ((e && e.message) || e))); });
    return;
  }
  renderAliases(Array.isArray(d.aliases) ? d.aliases : []);
  renderCalcs(Array.isArray(d.calcs) ? d.calcs : []);
  renderEventtypes(Array.isArray(d.eventtypes) ? d.eventtypes : []);
  renderTags(Array.isArray(d.tags) ? d.tags : []);
}

export { loadKnowledge };

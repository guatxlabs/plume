// knowledge.js — #46 KNOWLEDGE OBJECTS : gestion des objets de savoir « search-time » (alias de champ,
// champs calculés, event types, tags). Vit dans l'espace DONNÉES. Lecture viewer+ (transparence de la
// politique : ces objets façonnent la recherche de TOUT LE MONDE) ; CRUD éditeur+ (boutons masqués au
// viewer via CSS role-viewer + garde SERVEUR editor+). Réutilise 100% les endpoints #46 EXISTANTS :
//   GET    /api/knowledge                 -> {aliases:[], calcs:[], eventtypes:[], tags:[]}
//   POST   /api/knowledge/alias|calc|eventtype|tag         (editor+)
//   DELETE /api/knowledge/alias|calc|eventtype|tag/{id}    (editor+)
// SÉCU UI : tout en textContent/esc (anti-XSS). Mutations via apiSend (jeton CSRF auto). Aucune surface
// nouvelle ni chemin de requête/masquage touché — pure UI sur des routes déjà en place.
import { $, api, apiSend, effacerLeRefusDUnGeste, muted, pagedList, peindreLeRefusDUnGeste, prefixeDUnEchecRenduTelQuel, puitsDuRefusDUnGeste, toast, modal, confirmModal, managedBadge, gateDeleteBtn, faceDansLaLangue } from './core.js';

// `P10.7-f` (rang 4) — LES SIX FAMILLES VIENNENT DANS UN SEUL CORPS, ET L'AVEU NOMME CELLES QUI N'ONT PAS
// ÉTÉ LUES. `/api/knowledge` rend `{aliases, calcs, eventtypes, tags, macros, auto_lookups}` ; quand une
// lecture échoue, `corps_de_listes_illisibles` (daemon/src/handlers/liste_bornee.rs) laisse SA clé présente
// et VIDE, NOMME la famille dans `non_lus` et ouvre `error` sur la cause. Les autres familles restent
// SERVIES : l'aveu se peint donc sur la famille NOMMÉE seulement — un aveu global suspecterait cinq familles
// honnêtes avec la sixième, et c'est précisément ce que le démon a refusé d'écrire. Ce module ne consomme
// que QUATRE des six (`macros` et `auto_lookups` n'ont aucun panneau ici) : une famille non lue qu'il
// n'affiche pas ne se peint nulle part, et c'est dit plutôt que sous-entendu.
const FAMILLES_DE_SAVOIR = [
  { cle: 'aliases', kind: 'alias', liste: '#ko-alias-list', neuf: '#ko-alias-new',
    textContent: 'Alias de champ NON LUS : le démon a refusé et en nomme la cause —' },
  { cle: 'calcs', kind: 'calc', liste: '#ko-calc-list', neuf: '#ko-calc-new',
    textContent: 'Champs calculés NON LUS : le démon a refusé et en nomme la cause —' },
  { cle: 'eventtypes', kind: 'eventtype', liste: '#ko-eventtype-list', neuf: '#ko-eventtype-new',
    textContent: 'Event types NON LUS : le démon a refusé et en nomme la cause —' },
  { cle: 'tags', kind: 'tag', liste: '#ko-tag-list', neuf: '#ko-tag-new',
    textContent: 'Tags NON LUS : le démon a refusé et en nomme la cause —' },
];
// Les familles que la DERNIÈRE lecture n'a pas rendues. Le drapeau est posé par la charge et LU par le geste
// de création, qui vit hors d'elle : c'est le seul lien entre une famille non lue et l'objet qu'on écrirait
// par-dessus (grammaire de `P11.4-l`, déjà livrée pour les politiques d'index).
const FAMILLES_NON_LUES = new Set();

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

// `P10.27-d` — LE PUITS D'UNE FAMILLE, juste avant sa liste (hors de ce qu'elle repeint) : création et retrait. La forme
// est celle du point commun (`peindreLeRefusDUnGeste`, core.js). MESURÉ AVANT CE LOT (témoin 118) : « erreur : 503
// {"error":"OBJET DE SAVOIR NON ÉCRIT : … » dans un avis qui s'efface, coupé avant ce qui reste vrai.
function puitsDeLaFamille(kind) {
  const famille = FAMILLES_DE_SAVOIR.find(f => f.kind === kind), liste = famille ? $(famille.liste) : null;
  return liste && liste.parentNode ? puitsDuRefusDUnGeste(liste.parentNode, 'objets_de_savoir:' + kind, liste) : null;
}
// `P10.28-t` — LES AVIS DE SUCCÈS DES OBJETS DE SAVOIR, DANS LES DEUX LANGUES, PAR FAMILLE. MESURÉ AVANT CE LOT (témoin
// 119t) : `human + ' créé'` et `human + ' supprimé'` — un nom français collé à un participe, que le lexique ne pouvait
// pas atteindre — restaient français sous `LANG='en'`. Les faces françaises sont celles d'avant, au caractère près ; une
// famille qui n'y serait pas garderait son nom collé, sous la face générique de sa langue.
const MOTS_DES_SUCCES_DE_SAVOIR = {
  alias: { cree: { fr: 'alias de champ créé', en: 'field alias created' }, supprime: { fr: "l'alias supprimé", en: 'alias deleted' } },
  calc: { cree: { fr: 'champ calculé créé', en: 'calculated field created' }, supprime: { fr: 'le champ calculé supprimé', en: 'calculated field deleted' } },
  eventtype: { cree: { fr: 'event type créé', en: 'event type created' }, supprime: { fr: "l'event type supprimé", en: 'event type deleted' } },
  tag: { cree: { fr: 'tag créé', en: 'tag created' }, supprime: { fr: 'le tag supprimé', en: 'tag deleted' } },
  generique: { cree: { fr: '{objet} créé', en: '{objet} created' }, supprime: { fr: '{objet} supprimé', en: '{objet} deleted' } },
};
const motDUnSuccesDeSavoir = (kind, geste, human) => faceDansLaLangue((MOTS_DES_SUCCES_DE_SAVOIR[kind] || MOTS_DES_SUCCES_DE_SAVOIR.generique)[geste], { objet: human });
async function del(kind, id, label, human) {
  if (!(await confirmModal('Supprimer ' + human + ' « ' + label + ' » ?', { okText: 'Supprimer', danger: true }))) return;
  const puits = puitsDeLaFamille(kind); effacerLeRefusDUnGeste(puits);
  try { await apiSend('/knowledge/' + kind + '/' + id, 'DELETE'); toast(motDUnSuccesDeSavoir(kind, 'supprime', human), 'ok'); loadKnowledge(); }
  catch (e) { peindreLeRefusDUnGeste(puits, e); }
}
async function create(kind, human, fields, payloadFn) {
  // `P10.7-f` — LE GESTE PROMIS EST REFUSÉ, ET IL LE DIT. Le bouton « + … » de cette famille porte déjà la
  // marque accessible de l'inertie et sa raison ; seul ce point-ci peut EMPÊCHER l'écriture, et la MÊME
  // phrase est écrite aux deux endroits, jamais deux formulations du même refus.
  if (FAMILLES_NON_LUES.has(kind)) { toast("Cette famille d'objets de savoir n'a PAS été lue : en créer un ici, c'est peut-être en écrire un SECOND par-dessus celui que cette lecture n'a pas pu rendre — l'insertion sera refusée par l'unicité du nom, ou le doublon façonnera toute recherche du produit.", 'bad', 9000); return; }
  const v = await modal({ title: 'Nouvel objet — ' + human, okText: 'Créer', fields });
  if (!v) return;
  const puits = puitsDeLaFamille(kind); effacerLeRefusDUnGeste(puits);
  try { await apiSend('/knowledge/' + kind, 'POST', payloadFn(v)); toast(motDUnSuccesDeSavoir(kind, 'cree', human), 'ok'); loadKnowledge(); }
  catch (e) { peindreLeRefusDUnGeste(puits, e); }
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
    ['#ko-alias-list', '#ko-calc-list', '#ko-eventtype-list', '#ko-tag-list'].forEach(s => { if ($(s)) $(s).replaceChildren(muted(prefixeDUnEchecRenduTelQuel() + ((e && e.message) || e))); });
    return;
  }
  // `P10.7-f` — UNE FAMILLE NON LUE N'EST PAS UNE FAMILLE VIDE. `api()` ne jette que sur `!r.ok` : l'aveu
  // arrive en 200, forme intacte, et `Array.isArray([])` est VRAI sur la clé vidée. Les quatre phrases de
  // vide rendues plus bas se lisent alors « ce champ n'est pas renommé », « cette catégorie n'existe pas »,
  // « ce tag n'est pas posé » — sur des objets qui façonnent la recherche de TOUT LE MONDE et qu'on
  // réécrira par-dessus. La famille nommée rend son aveu À SA PLACE ; les autres restent peintes.
  const nonLus = Array.isArray(d.non_lus) ? d.non_lus.map(String) : [];
  const RENDU = { aliases: renderAliases, calcs: renderCalcs, eventtypes: renderEventtypes, tags: renderTags };
  FAMILLES_NON_LUES.clear();
  FAMILLES_DE_SAVOIR.forEach(f => {
    const bouton = $(f.neuf);
    if (nonLus.includes(f.cle)) {
      FAMILLES_NON_LUES.add(f.kind);
      const hote = $(f.liste);
      if (hote) {
        const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
        const dit = document.createElement('span');
        dit.textContent = f.textContent;
        aveu.append(dit, ' « ' + String(d.error || '').trim() + ' »');
        hote.replaceChildren(aveu);
      }
      if (bouton) { bouton.setAttribute('aria-disabled', 'true'); bouton.title = "Cette famille d'objets de savoir n'a PAS été lue : en créer un ici, c'est peut-être en écrire un SECOND par-dessus celui que cette lecture n'a pas pu rendre — l'insertion sera refusée par l'unicité du nom, ou le doublon façonnera toute recherche du produit."; }
      return;
    }
    if (bouton) { bouton.removeAttribute('aria-disabled'); bouton.removeAttribute('title'); }
    RENDU[f.cle](Array.isArray(d[f.cle]) ? d[f.cle] : []);
  });
}

// `loadKnowledge` et `create` sont exposés pour le harnais ESM (témoin 95 : l'aveu PAR FAMILLE et le refus
// du geste de création, rendus par leur fabrique réelle et non par une copie) ; `create` n'a aucun usage
// applicatif hors de ce module.
export { create, del, loadKnowledge };

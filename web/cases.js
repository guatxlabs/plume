// cases.js — extracted from app.js (DEEP state-container split). Behaviour-preserving.
// Cases (gestion d'incident, first-class #4a): liste/detail/CRUD + rattachement d'items.
import { $, api, apiSend, phraseDuRefusDuDemon, aveuDeLaTraceManquante, causeDeLaTraceManquante, confirmModal, confirmWithConsequence, disclosure, downloadText, exportPDF, fmtTs, ic, LANG, modal, motDeLaTraceManquante, muted, pagedList, phraseDeLaCreationDeRiposteRefusee, phraseDeLaTraceManquante, sev, toCSV, toast, tsSlug, withBusy, socIsAdmin, socRole } from './core.js';
import { phraseDAffichagePartiel, phraseDEchantillonCoupe, phraseDeCoupe } from './coupe_de_liste.js'; // `P11.22-g` : une liste bornée dit sa coupe
import { S } from './state.js';
import { refresh } from './app.js';
// #3 incidents : « Lancer la recherche » d'une step ouvre l'Explore avec le GXQL recompilé (réutilise le
// chemin de recherche existant). Cycle app<->viz bénin (appel à l'EXÉCUTION seulement, après await).
import { runQuery } from './viz.js';

// ---------- Cases (gestion d'incident, first-class #4a) ----------
// Master-detail PLEINE LARGEUR dans #cases : liste filtrable + tri (gauche/haut), détail inline (bas)
// avec header, timeline TYPÉE et barre d'actions. Données OPÉRATIONNELLES par-tenant (le daemon route via
// req_db) ; la timeline = historique/audit du case. Contrat daemon : GET/POST /api/cases[/{id}[/items[/{iid}]]].
// Toutes les E/S passent par api()/apiSend() (core.js) : erreurs REMONTÉES (toast) au lieu d'être avalées.

// Statuts : vocabulaire CANONIQUE new->triage->in_progress->resolved->closed (ce que le daemon ÉCRIT),
// + alias LEGACY tolérés (open/investigating/contained) que d'anciens cases portent encore et que le daemon
// ne réécrit JAMAIS (invariant de préservation). On AFFICHE les deux ; les actions envoient le canonique.
const CASE_STATUS = {
  new: 'Nouveau', triage: 'Triage', in_progress: 'En cours', resolved: 'Résolu', closed: 'Clos',
  open: 'Ouvert', investigating: 'Enquête', contained: 'Contenu',
};

const CASE_STATUS_COL = {
  new: 'var(--sev1)', open: 'var(--sev1)', triage: 'var(--warn)',
  in_progress: 'var(--sev3)', investigating: 'var(--sev3)',
  resolved: 'var(--ok)', contained: 'var(--ok)', closed: 'var(--mut)',
};

const CASE_TERMINAL = new Set(['resolved', 'closed', 'contained']);

const CASE_STEPS = ['new', 'triage', 'in_progress'];   // états de TRAVAIL (transitions terminales via boutons)

const CASE_KIND = { created: 'créé', note: 'note', status: 'statut', assign: 'assigné', priority: 'priorité', alert: 'alerte', event: 'event', sla: 'SLA', action: 'action', archive: 'archivé', unarchive: 'désarchivé', disposition: 'verdict' };

// #4a DISPOSITION — verdict analyste FERMÉ (miroir de DISPOSITION_VALUES daemon ; '' = non défini). INTERNE
// (jamais projeté au client). L'ordre pilote le <select> ; la 1re entrée '' = « non défini » (unset).
const DISPOSITION_LABEL = { '': 'Non défini', true_positive: 'Vrai positif', false_positive: 'Faux positif', benign: 'Bénin', duplicate: 'Doublon' };

// priorité 1..4 (miroir de parse_priority / priority_label / sla_target_s du daemon).
const PRIO_LABEL = { 1: 'P1 critique', 2: 'P2 haute', 3: 'P3 moyenne', 4: 'P4 basse' };

const PRIO_COL = { 1: 'var(--sev4)', 2: 'var(--sev3)', 3: 'var(--sev2)', 4: 'var(--mut)' };

// canonique effectif d'un statut legacy (miroir de norm_case_status) -> présélection propre des <select>.
function caseCanonStatus(s) { return ({ open: 'new', investigating: 'in_progress', contained: 'resolved' })[s] || s; }

// éditer les cases = editor/admin ; viewer = lecture seule. Fail-closed : rôle inconnu -> lecture seule
// (défense en profondeur ; le daemon refuse aussi via rbac_gate côté serveur).
function canEditCases() { const r = socRole(); return r === 'editor' || r === 'admin'; }

function mkLabel(text) { const l = document.createElement('label'); l.appendChild(Object.assign(document.createElement('span'), { textContent: text })); return l; }

function caseBtn(label, kind) {
  const b = document.createElement('button'); b.type = 'button'; b.textContent = label;
  // P11.4-b : le jeu de classes partagé (style.css), plus aucun style en ligne — primaire / destructif / secondaire.
  b.className = kind === 'primary' ? 'btn-primary btn-sm' : kind === 'danger' ? 'btn btn-sm btn-danger' : 'btn btn-sm';
  return b;
}

// ======================================================================================================
// `P11.14-d` — LA SORTIE D'UN ÉTAT TERMINAL SE DIT LÀ OÙ CET ÉTAT SE CONSTATE.
// LE CONSTAT D'ORIGINE — « on ne peut pas rouvrir un cas » — EST RÉFUTÉ SUR LE MÉCANISME, et la réfutation
// est REMESURÉE ici le 2026-08-26, pas recopiée : le bouton « Rouvrir » existe (plus bas dans ce fichier,
// premier geste de la barre d'actions d'un cas terminé), `CASE_TERMINAL` contient bien `resolved`, et la
// barre se RECOMPOSE sans rechargement — `caseUpdate` enchaîne `loadCases()` puis `refreshCaseDetail()`,
// qui relit le cas et redessine le détail. Ni le geste ni son rafraîchissement ne manquaient.
// CE QUI MANQUAIT, MESURÉ : HORS DU DÉTAIL, AUCUNE SURFACE NE NOMMAIT CE GESTE. Le seul porteur du fait
// « ce cas est terminé » ailleurs que dans le détail est le cadre d'état ci-dessous — rendu par la ligne de
// la liste COMME par l'en-tête du détail — et son survol promettait une réouverture (« tant qu'il n'est pas
// rouvert ») sans dire NI où le geste attend NI si CE lecteur-ci le verra jamais. Un lecteur sans droit
// d'écriture lisait donc, sur la même page, une promesse de réouverture et un « aucune action n'est
// proposée » qui ne nommait aucune action : deux surfaces, un lecteur, aucun lien entre elles.
// LE REMÈDE N'AJOUTE AUCUN GESTE, ET C'EST LA MOITIÉ QUI COMPTE. Un second bouton posé dans la liste ferait
// deux chemins à maintenir pour une transition qui n'en a qu'un, et le constat ne portait pas sur un geste
// absent mais sur un geste INTROUVABLE. Seule sa trouvabilité change : le cadre d'état le NOMME, dit où il
// attend, et dit quand le rôle en cours l'empêche de paraître.
// UN SEUL AUTEUR, DEUX VALEURS DÉJÀ CONNUES AU RENDU : l'état est-il terminal (`CASE_TERMINAL`) et ce
// lecteur peut-il écrire (`canEditCases`). Le cadre d'état et la raison portée par le sélecteur inerte du
// détail sortent de la MÊME table. Écrire la sortie à deux endroits est exactement ce qui a produit un
// survol qui promettait et une phrase qui refusait, sans que l'un réponde à l'autre.
// CE QUE CETTE TABLE NE DIT PAS, ET NE PEUT PAS DIRE : POURQUOI la personne n'a pas trouvé le geste. Elle
// ferme la piste mesurable — rien ne le nommait hors du détail — et laisse les deux autres pistes du
// constat réfutées par la mesure ci-dessus (le rafraîchissement) ou dites en clair (le rôle).
// BILINGUE PAR CONSTRUCTION (`{fr, en}` choisi par LANG), comme les mots du pivot d'une alerte : les deux
// langues sont côte à côte, et aucune ne peut vieillir sans l'autre.
const SORTIE_MOTS = {
  encours: {
    fr: "Cas en cours : son état peut encore changer",
    en: 'Open case: its status can still change',
  },
  terminal: {
    fr: "Cas terminé : son état n'évolue plus tant qu'il n'est pas rouvert. Le geste porte le nom « Rouvrir » et il attend dans la barre d'actions du détail de ce cas.",
    en: 'Finished case: its status no longer changes until it is reopened. The gesture is named "Reopen" and it waits in this case\'s detail action bar.',
  },
  terminal_sans_droit: {
    fr: "Cas terminé : son état n'évolue plus tant qu'il n'est pas rouvert, et « Rouvrir » demande le rôle éditeur ou administrateur — avec le rôle en cours, ce geste n'est proposé nulle part.",
    en: 'Finished case: its status no longer changes until it is reopened, and "Reopen" requires the editor or administrator role — with the current role, that gesture is offered nowhere.',
  },
  inerte: {
    fr: "Inerte par nature : un cas terminé ne change plus d'état. « Rouvrir », dans la barre d'actions ci-dessous, le ramène en cours.",
    en: 'Inert by nature: a finished case no longer changes status. "Reopen", in the action bar below, brings it back in progress.',
  },
};
const motDeLaSortie = (etat) => (LANG === 'en' ? SORTIE_MOTS[etat].en : SORTIE_MOTS[etat].fr);
// L'ÉTAT DE SORTIE EST DÉRIVÉ, JAMAIS ÉNUMÉRÉ PAR APPELANT : un appelant de plus hérite de la distinction
// au lieu de la réécrire, et un statut terminal ajouté à `CASE_TERMINAL` la reçoit sans toucher ici.
function sortieDunCas(status) {
  if (!CASE_TERMINAL.has(status)) return 'encours';
  return canEditCases() ? 'terminal' : 'terminal_sans_droit';
}

// badges color-codés (textContent -> pas d'injection ; couleur en inline-style car style.css n'est pas édité).
// P11.11-a — le cadre d'état DIT pourquoi il est terne : `closed` est gris par palette et la ligne d'un cas
// terminé est estompée, ce qui se lit comme un contrôle désactivé alors que rien ne l'est. L'infobulle
// tranche entre les deux lectures : inerte PAR NATURE (le cas est terminé) ou encore modifiable.
// `P11.14-d` — et, quand le cas est terminé, elle NOMME la sortie et son emplacement : c'est le seul endroit
// de la liste où le fait « terminé » est écrit, donc le seul où la sortie peut être trouvée sans ouvrir.
function caseStatusBadge(status) {
  const s = document.createElement('span'); s.className = 'casest'; const col = CASE_STATUS_COL[status] || 'var(--mut)';
  s.style.color = col; s.style.borderColor = 'color-mix(in srgb,' + col + ' 45%,transparent)';
  s.title = motDeLaSortie(sortieDunCas(status));
  s.textContent = CASE_STATUS[status] || status; return s;
}

function casePrioBadge(prio) {
  const p = document.createElement('span'); p.className = 'badge'; const col = PRIO_COL[prio] || 'var(--mut)';
  p.style.color = col; p.style.borderColor = 'color-mix(in srgb,' + col + ' 45%,transparent)';
  p.textContent = 'P' + prio; p.title = PRIO_LABEL[prio] || ('priorité ' + prio); return p;
}

function caseOverdueBadge(sla_due) {
  const o = document.createElement('span'); o.className = 'badge';
  o.style.color = 'var(--bad)'; o.style.borderColor = 'color-mix(in srgb,var(--bad) 50%,transparent)'; o.style.fontWeight = '700';
  o.textContent = 'RETARD'; o.title = 'SLA dépassé' + (sla_due ? ' (échéance ' + fmtTs(sla_due) + ')' : ''); return o;
}

function caseFilterQuery() {
  const p = new URLSearchParams();
  const st = $('#case-filter') ? $('#case-filter').value : '';
  const pr = $('#case-prio-filter') ? $('#case-prio-filter').value : '';
  const as = $('#case-assignee-filter') ? $('#case-assignee-filter').value.trim() : '';
  const od = $('#case-overdue-filter') ? $('#case-overdue-filter').checked : false;
  const ar = $('#case-archived-filter') ? $('#case-archived-filter').checked : false;
  if (st) p.set('status', st);
  if (pr) p.set('priority', pr);
  if (as) p.set('assignee', as);
  if (od) p.set('overdue', '1');
  if (ar) p.set('archived', '1');   // #4a-bis : vue dédiée « Archivés » (masqués de la liste par défaut)
  const q = p.toString(); return q ? '?' + q : '';
}

// tri CLIENT (le serveur renvoie déjà overdue-first) : sans refetch, sur la liste déjà chargée.
function caseSortRows(rows) {
  const sort = $('#case-sort') ? $('#case-sort').value : '';
  if (!sort) return rows;
  const r = rows.slice();
  if (sort === 'updated') r.sort((a, b) => (b.updated || 0) - (a.updated || 0));
  else if (sort === 'priority') r.sort((a, b) => (a.priority || 4) - (b.priority || 4) || (b.updated || 0) - (a.updated || 0));
  else if (sort === 'sla') r.sort((a, b) => (a.sla_due == null ? Infinity : a.sla_due) - (b.sla_due == null ? Infinity : b.sla_due));
  return r;
}

// construit une ligne de case (.caserow) — extrait pour être réutilisé par pagedList (renderRow).
// P11.11-a — la ligne est le BOUTON DE DÉPLI du détail : elle ouvre le cas, et le MÊME clic le referme.
// Le mécanisme est celui de toute la console (`disclosure`, core.js, `P11.4-a`) — pas un second écrit ici :
// l'état vit sur la ligne (`aria-expanded`, `.on`) au lieu d'une bordure posée en style en ligne, et la
// ligne n'est jamais grisée. `observe:false` : le panneau `#case-detail` ne change ni `hidden` ni `class`
// (le détail se pose et se retire par ses ENFANTS), et une page en porte cinquante — la repeinte est faite
// par `renderCaseList` à partir de la poignée gardée sur la ligne.
function caseRow(c) {
  const row = document.createElement('button'); row.className = 'caserow' + (CASE_TERMINAL.has(c.status) ? ' closed' : '');
  row.dataset.cid = c.id;
  if (CASE_TERMINAL.has(c.status)) row.title = 'Cas terminé : la ligne est estompée parce que le cas ne bouge plus, pas parce qu\'elle serait inactive — elle s\'ouvre et se referme comme les autres';
  row._disc = disclosure(row, $('#case-detail'), {
    observe: false,
    isOpen: () => c.id === S.caseSelectedId,
    open: () => showCaseDetail(c.id),
    close: () => closeCaseDetail(),
  });
  row.appendChild(Object.assign(document.createElement('span'), { className: 'badge sevb-' + c.severity, textContent: sev(c.severity) }));
  row.appendChild(casePrioBadge(c.priority));
  row.appendChild(caseStatusBadge(c.status));
  if (c.overdue) row.appendChild(caseOverdueBadge(c.sla_due));
  if (c.archived) { const ab = document.createElement('span'); ab.className = 'badge'; ab.textContent = 'ARCHIVÉ'; ab.style.color = 'var(--mut)'; ab.style.borderColor = 'color-mix(in srgb,var(--mut) 45%,transparent)'; row.appendChild(ab); }
  row.appendChild(Object.assign(document.createElement('span'), { className: 'casetitle', textContent: c.title }));
  const meta = document.createElement('span'); meta.className = 'casemeta';
  meta.textContent = c.items + ' élément(s)' + (c.assignee ? ' · ' + c.assignee : (c.owner ? ' · ' + c.owner : '')) + ' · ' + fmtTs(c.updated);
  row.appendChild(meta);
  return row;
}

// `P10.7-d` — UN REFUS DU DÉMON ARRIVE EN 200, ET IL DOIT ÊTRE LU.
//
// Depuis `P10.7-c`, trois routes de ce panneau peuvent rendre un corps 200 qui garde sa FORME et y ajoute
// la cause sous `error` : `/api/cases` (liste), `/api/cases/queues` et `/api/cases/metrics`, quand le
// portillon de concurrence est CLOS (`daemon/src/handlers/portillon.rs`). `api()` (core.js) ne jette que
// sur `!r.ok` : ce module recevait donc `{"cases":[],"total":0,error:…}` et en tirait « aucun case », et
// `{queues:[]}` / `{}` faisaient simplement DISPARAÎTRE le bandeau de charge. Dans les deux cas une lecture
// NON EXÉCUTÉE se lisait comme une absence établie.
//
// LE TEST EST SÉPARÉ DE CELUI DU VIDE (`check_a_refusal_is_not_rendered_as_an_absence.py`), et la cause
// n'est PAS recopiée ici : elle est écrite une seule fois, dans le démon.
// DIRECTION DE L'ERREUR : le refus l'emporte sur des lignes éventuellement servies à côté — rendre la table
// présenterait un résultat incomplet comme complet. Cette surface rend MOINS, jamais plus.
function causeDuRefusServi(r) {
  return (r && r.error != null) ? String(r.error).trim() : '';
}

async function loadCases() {
  const wrap = $('#cases-list'); if (!wrap) return;
  const nb = $('#case-new'); if (nb) nb.style.display = canEditCases() ? '' : 'none';   // + Case : editor/admin
  // BATCH 1 : pagination + tri SERVEUR (filtres status/assignee/priority/overdue/archived PRÉSERVÉS). Le tri
  // (#case-sort) est replié serveur (caseSortRows reste un repli client idempotent sur la page renvoyée).
  S.casePager = pagedList(wrap, {
    mode: 'server',
    pageSize: 50,
    // `P11.18-x` — même arbitrage que le journal d'audit : recherche activée sur la page servie, portée
    // dite par la fabrique ; une recherche serveur sur le titre d'un cas n'a pas d'index et n'est pas posée.
    recherche: true, storeKey: 'cases',
    renderRow: caseRow,
    emptyText: 'aucun case',
    fetchPage: async ({ limit, offset }) => {
      const base = caseFilterQuery();                 // '' | '?status=...'
      const sortSel = $('#case-sort') ? $('#case-sort').value : '';
      let url = '/cases' + base + (base ? '&' : '?') + 'limit=' + limit + '&offset=' + offset;
      if (sortSel) url += '&sort=' + encodeURIComponent(sortSel);
      const j = await api(url);   // erreur -> pagedList/loadServer affiche « erreur : … »
      // `P10.7-d` — LE REFUS EMPRUNTE LE CHEMIN D'ÉCHEC DÉJÀ EN PLACE. `loadServer` rend « erreur : … » sur
      // un rejet et `emptyText` (« aucun case ») sur zéro ligne : ce sont DEUX issues distinctes, et jeter
      // ici est ce qui met le refus dans la bonne. Rien de neuf n'est peint.
      const refus = causeDuRefusServi(j);
      if (refus) throw new Error(refus);
      return { rows: caseSortRows(j.cases || []), total: j.total };
    },
  });
  loadCaseOpsSummary(); // #39 : bandeau charge/MTTA-MTTR (async, non bloquant ; vide en mode 0)
}

// re-marquage de la sélection SANS refetch. P11.11-a : la ligne porte son état par le dépli partagé, donc
// on ne repeint plus une bordure à la main — on redemande à chaque poignée de se relire (`paint`).
function renderCaseList() {
  const wrap = $('#cases-list'); if (!wrap) return;
  if (!wrap.querySelector('.caserow')) { if (!S.casePager) loadCases(); return; }
  wrap.querySelectorAll('.caserow').forEach(el => { if (el._disc) el._disc.paint(); });
}

// P11.11-a — UN SEUL chemin de fermeture, emprunté par la ligne (second clic) comme par le bouton du
// détail : sans lui, refermer d'un côté laisserait l'autre affirmer que le cas est encore ouvert.
function closeCaseDetail() {
  S.caseSelectedId = null;
  const host = $('#case-detail'); if (host) host.replaceChildren();
  renderCaseList();
}

async function showCaseDetail(id) {
  S.caseSelectedId = id;
  renderCaseList();
  const host = $('#case-detail'); if (!host) return;
  let c;
  try { c = await api('/cases/' + id); }
  catch (e) { host.replaceChildren(muted('case introuvable')); return; }
  renderCaseDetail(host, c);
  host.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function refreshCaseDetail(id) {
  if (S.caseSelectedId !== id) return;
  const host = $('#case-detail'); if (!host) return;
  try { renderCaseDetail(host, await api('/cases/' + id)); } catch (e) {}   // refresh silencieux (background) — pas de toast
}

// EXPORT CASE (client) : CSV = timeline (items déjà chargés) ; JSON = le case complet ; PDF = impression.
// Le case provient de /api/cases/{id} (déjà caviardé/gated) -> aucune donnée secrète.
function caseExportBar(c) {
  const wrap = document.createElement('span'); wrap.className = 'export-actions noprint';
  const mk = (label, title, fn) => { const b = document.createElement('button'); b.type = 'button'; b.className = 'exportbtn'; b.title = title; b.textContent = label; b.onclick = fn; return b; };
  wrap.appendChild(mk('CSV', 'Exporter la timeline en CSV', () => {
    const cols = [{ key: 'ts', label: 'ts' }, { key: 'author', label: 'author' }, { key: 'kind', label: 'kind' }, { key: 'ref', label: 'ref' }, { key: 'body', label: 'body' }];
    const rows = (c.items || []).map(it => ({ ts: fmtTs(it.ts), author: it.author || '', kind: it.kind || '', ref: it.ref || '', body: it.body || '' }));
    downloadText(`plume-case-${c.id}-${tsSlug()}.csv`, 'text/csv;charset=utf-8', toCSV(cols, rows));
  }));
  wrap.appendChild(mk('JSON', 'Exporter le case complet en JSON', () => downloadText(`plume-case-${c.id}-${tsSlug()}.json`, 'application/json', JSON.stringify(c, null, 2))));
  wrap.appendChild(mk('PDF', 'Imprimer / exporter le case en PDF', () => exportPDF('case')));
  return wrap;
}

function renderCaseDetail(host, c) {
  const edit = canEditCases();
  host.replaceChildren();
  const box = document.createElement('div'); box.className = 'caseview';
  box.style.cssText = 'margin-top:16px;border-top:1px solid var(--bd);padding-top:14px';
  // --- header : titre + badges (statut/priorité/retard) + repli ---
  const head = document.createElement('div'); head.className = 'panelhead';
  const h = document.createElement('h3'); h.style.margin = '0'; h.style.minWidth = '0'; h.textContent = '#' + c.id + ' · ' + c.title;
  const hr = document.createElement('span'); hr.style.cssText = 'display:inline-flex;gap:8px;align-items:center;flex-wrap:wrap';
  hr.appendChild(caseStatusBadge(c.status));
  hr.appendChild(casePrioBadge(c.priority));
  if (c.overdue) hr.appendChild(caseOverdueBadge(c.sla_due));
  if (c.archived) { const ab = document.createElement('span'); ab.className = 'badge'; ab.textContent = 'ARCHIVÉ'; ab.style.color = 'var(--mut)'; ab.style.borderColor = 'color-mix(in srgb,var(--mut) 45%,transparent)'; ab.title = 'Case archivé' + (c.archived_by ? ' par ' + c.archived_by : '') + (c.archived_ts ? ' le ' + fmtTs(c.archived_ts) : '') + ' — masqué de la liste par défaut, historique conservé'; hr.appendChild(ab); }
  const collapse = document.createElement('button'); collapse.type = 'button'; collapse.className = 'picon'; collapse.title = 'Fermer le détail'; collapse.innerHTML = ic('x'); // P11.4-b : bouton-icône partagé
  collapse.onclick = closeCaseDetail;   // P11.11-a : le même chemin que le second clic sur la ligne
  hr.appendChild(caseExportBar(c));   // EXPORT : CSV (timeline) / JSON (case complet) / PDF (impression)
  hr.appendChild(collapse);
  head.append(h, hr); box.appendChild(head);
  // --- ligne meta (créé / assigné / SLA / MTTA / clôture) ---
  const meta = document.createElement('div'); meta.className = 'casemeta'; meta.style.cssText = 'margin:2px 0 10px;display:flex;gap:14px;flex-wrap:wrap';
  const mk = t => Object.assign(document.createElement('span'), { textContent: t });
  meta.appendChild(mk('créé ' + fmtTs(c.ts) + (c.owner ? ' par ' + c.owner : '')));
  meta.appendChild(mk('assigné : ' + (c.assignee || '—')));
  meta.appendChild(mk('SLA : ' + (c.sla_due ? fmtTs(c.sla_due) : '—') + (c.overdue ? ' (dépassé)' : '')));
  if (c.first_response_ts) meta.appendChild(mk('1re réponse ' + fmtTs(c.first_response_ts)));
  if (c.closed_ts) meta.appendChild(mk('clos ' + fmtTs(c.closed_ts)));
  // #4a — verdict (disposition) affiché dès qu'il est posé (lecture pour tous, y compris viewer).
  if (c.disposition) meta.appendChild(mk('verdict : ' + (DISPOSITION_LABEL[c.disposition] || c.disposition) + (c.disposition_by ? ' (' + c.disposition_by + ')' : '')));
  // #39 — SLA multi-niveau (visible seulement si une politique gouverne le case). ack masqué une fois acquitté.
  if (c.ack_due && !c.first_response_ts) meta.appendChild(mk('SLA ack : ' + fmtTs(c.ack_due) + (c.ack_breached ? ' (BREACH)' : '') + (c.sla_paused ? ' [en pause]' : '')));
  if (c.resolve_due) meta.appendChild(mk('SLA résolution : ' + fmtTs(c.resolve_due) + (c.resolve_breached ? ' (BREACH)' : '')));
  box.appendChild(meta);
  // --- barre d'ACTIONS (editor/admin) : statut / priorité / assigner / résoudre-clore-rouvrir / rattacher ---
  // P11.11-a — sans droit d'écriture la barre disparaissait en silence, et l'absence se confondait avec
  // l'inertie d'un cas terminé. Les deux se disent maintenant, et se disent DIFFÉREMMENT : ici c'est un
  // DROIT qui manque, pas un état qui ne bouge plus.
  if (!edit) box.appendChild(muted('Lecture seule : modifier un cas demande le rôle éditeur ou administrateur — aucune action n\'est proposée.'));
  if (edit) {
    const terminal = CASE_TERMINAL.has(c.status);
    const act = document.createElement('div'); act.className = 'caserowtop';
    // P11.11-a — le sélecteur de statut existe TOUJOURS. Sur un cas terminé il était simplement ABSENT :
    // le lecteur voyait Priorité/Verdict/Assigné sans Statut, sans un mot, et devait deviner. Il est
    // désormais PRÉSENT et inerte, avec sa raison EN CLAIR à côté — un `title` ne suffirait pas, un
    // contrôle `disabled` ne reçoit pas la souris et n'affiche donc pas d'infobulle.
    const stLab = mkLabel('Statut'); const stSel = document.createElement('select');
    if (terminal) {
      const o = document.createElement('option'); o.value = c.status; o.textContent = CASE_STATUS[c.status] || c.status; o.selected = true; stSel.appendChild(o);
      stSel.disabled = true;
      stLab.appendChild(stSel);
      // `P11.14-d` — MÊME AUTEUR que le cadre d'état : la sortie ne s'écrit pas deux fois.
      stLab.appendChild(muted(motDeLaSortie('inerte')));
    } else {
      CASE_STEPS.forEach(s => { const o = document.createElement('option'); o.value = s; o.textContent = CASE_STATUS[s]; if (caseCanonStatus(c.status) === s) o.selected = true; stSel.appendChild(o); });
      stSel.onchange = () => caseUpdate(c.id, { status: stSel.value });
      stLab.appendChild(stSel);
    }
    act.appendChild(stLab);
    const prLab = mkLabel('Priorité'); const prSel = document.createElement('select');
    [1, 2, 3, 4].forEach(p => { const o = document.createElement('option'); o.value = String(p); o.textContent = PRIO_LABEL[p]; if (p === c.priority) o.selected = true; prSel.appendChild(o); });
    prSel.onchange = () => caseUpdate(c.id, { priority: Number(prSel.value) });
    prLab.appendChild(prSel); act.appendChild(prLab);
    // #4a — VERDICT (disposition) : sélecteur FERMÉ (unset + 4 valeurs) posé au fil de la résolution/clôture.
    // Le verdict s'accumule comme label (futur apprentissage, différé). Reste INTERNE (hors vue client).
    const dsLab = mkLabel('Verdict'); const dsSel = document.createElement('select');
    Object.keys(DISPOSITION_LABEL).forEach(v => { const o = document.createElement('option'); o.value = v; o.textContent = DISPOSITION_LABEL[v]; if (v === (c.disposition || '')) o.selected = true; dsSel.appendChild(o); });
    dsSel.onchange = () => caseUpdate(c.id, { disposition: dsSel.value });
    dsLab.appendChild(dsSel); act.appendChild(dsLab);
    const asLab = mkLabel('Assigné'); const asWrap = document.createElement('span'); asWrap.style.cssText = 'display:flex;gap:6px';
    const asInp = document.createElement('input'); asInp.value = c.assignee || ''; asInp.placeholder = 'utilisateur…';
    const asBtn = caseBtn('Assigner', 'ghost');
    const doAssign = () => { const v = asInp.value.trim(); if (v === (c.assignee || '')) return; return caseUpdate(c.id, { assignee: v }); };
    asBtn.onclick = () => withBusy(asBtn, doAssign);
    asInp.onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); doAssign(); } };
    asWrap.append(asInp, asBtn); asLab.appendChild(asWrap); act.appendChild(asLab);
    box.appendChild(act);
    const bar = document.createElement('div'); bar.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 4px';
    if (terminal) {
      // P11.11-a — c'est la SEULE sortie de l'état inerte, et la raison affichée à côté du sélecteur y
      // renvoie : elle dit donc ce qu'elle engage, par la confirmation partagée (rien de destructif).
      const reopen = caseBtn('Rouvrir', 'ghost');
      reopen.onclick = () => withBusy(reopen, async () => { if (await confirmWithConsequence('Rouvrir le case', 'le case quitte son état terminal et revient dans la file de travail', { okText: 'Rouvrir', danger: false })) await caseUpdate(c.id, { status: 'in_progress' }); });
      bar.appendChild(reopen);
    } else {
      const resolve = caseBtn('Résoudre', 'ghost');
      resolve.onclick = () => withBusy(resolve, async () => { if (await confirmModal('Marquer le case #' + c.id + ' comme résolu ?', { okText: 'Résoudre', danger: false })) await caseUpdate(c.id, { status: 'resolved' }); });
      bar.appendChild(resolve);
    }
    if (c.status !== 'closed') {
      const close = caseBtn('Clore', 'danger');
      close.onclick = () => withBusy(close, async () => { if (await confirmModal('Clore le case #' + c.id + ' ? (réouvrable ensuite)', { okText: 'Clore', danger: true })) await caseUpdate(c.id, { status: 'closed' }); });
      bar.appendChild(close);
    }
    const attach = caseBtn('Rattacher un élément…', 'ghost');
    attach.onclick = () => attachToCasePrompt(c.id);
    bar.appendChild(attach);
    // #39 — fusion (soft, non destructive) + lien (association). editor+ (le daemon revérifie via rbac_gate).
    const mergeBtn = caseBtn('Fusionner…', 'ghost');
    mergeBtn.onclick = () => mergeCasePrompt(c.id);
    bar.appendChild(mergeBtn);
    const linkBtn = caseBtn('Lier…', 'ghost');
    linkBtn.onclick = () => linkCasePrompt(c.id);
    bar.appendChild(linkBtn);
    // `P10.7-f` — LA POIGNÉE SUR LE GESTE, POUR QUE `renderCaseLinks` PUISSE LE MARQUER. La barre est
    // construite ici, la liste des liens est chargée plus bas (fetch séparé) : sans cette poignée, l'aveu
    // de lecture ne pourrait pas poser sa marque sur le bouton qu'il concerne.
    BOUTON_LIER.set(c.id, linkBtn);
    // #4a-bis — ARCHIVER / DÉSARCHIVER : ADMIN uniquement (action delete-like ; le daemon refuse aussi hors
    // admin via rbac_gate + re-check handler). Archiver MASQUE le case de la liste par défaut, l'historique
    // (timeline) est conservé et l'action est réversible.
    if (socIsAdmin()) {
      if (c.archived) {
        const unarch = caseBtn('Désarchiver', 'ghost');
        unarch.onclick = () => withBusy(unarch, () => caseUnarchive(c.id));
        bar.appendChild(unarch);
      } else {
        const arch = caseBtn('Archiver', 'danger');
        arch.onclick = () => withBusy(arch, () => caseArchive(c.id));
        bar.appendChild(arch);
      }
    }
    box.appendChild(bar);
  }
  // --- résumé (éditable pour editor/admin, lecture seule sinon) ---
  if (edit || c.summary) {
    box.appendChild(Object.assign(document.createElement('div'), { className: 'casesec', textContent: 'Résumé' }));
    if (edit) {
      const ta = document.createElement('textarea'); ta.className = 'c-summary'; ta.rows = 2; ta.spellcheck = false; ta.value = c.summary || '';
      ta.placeholder = 'contexte / résumé de l\'incident';
      const sv = caseBtn('Enregistrer le résumé', 'ghost'); sv.style.marginTop = '6px';
      sv.onclick = () => withBusy(sv, () => { const v = ta.value; if (v === (c.summary || '')) return; return caseUpdate(c.id, { summary: v }); });
      box.append(ta, sv);
    } else {
      const sd = document.createElement('div'); sd.style.cssText = 'font-size:13px;white-space:pre-wrap'; sd.textContent = c.summary; box.appendChild(sd);
    }
  }
  // --- #39 : liens & fusion (association non destructive ; fusionné-dans + dé-fusion) ---
  renderCaseLinks(box, c);
  // --- #3 incidents : runbook / réponse guidée (tier + wizard de steps). Chargé en async (fetch séparé :
  // les données incident/runbook restent HORS de la projection case_get_json -> parité mode 0). ---
  renderWizardPanel(box, c, edit, hr);
  // --- TIMELINE typée (chaque item daté + auteur ; refs alert/event résolues ; détach pour editor) ---
  box.appendChild(Object.assign(document.createElement('div'), { className: 'casesec', textContent: 'Timeline' }));
  const tl = document.createElement('div'); tl.className = 'casetl';
  const items = c.items || [];
  if (!items.length) tl.appendChild(Object.assign(document.createElement('div'), { className: 'muted', textContent: '(vide)' }));
  else items.forEach(it => tl.appendChild(caseItemEl(c.id, it, edit)));
  box.appendChild(tl);
  // --- ajout de note (editor/admin) ---
  if (edit) {
    const nf = document.createElement('form'); nf.className = 'c-noteform';
    const ni = document.createElement('input'); ni.className = 'c-note'; ni.placeholder = 'Ajouter une note…'; ni.required = true;
    const nb = document.createElement('button'); nb.type = 'submit'; nb.className = 'btn-primary'; nb.textContent = 'Note'; // P11.4-b : classe partagée (primaire)
    nf.append(ni, nb);
    nf.onsubmit = e => { e.preventDefault(); const v = ni.value.trim(); if (!v) return; withBusy(nb, async () => { try { await apiSend('/cases/' + c.id + '/items', 'POST', { kind: 'note', body: v }); } catch (err) { toast('Note refusée : ' + ((err && err.message) || err), 'bad'); return; } ni.value = ''; await refreshCaseDetail(c.id); await loadCases(); }); };
    box.appendChild(nf);
  }
  host.appendChild(box);
}

// `P10.20-p` (2026-09-16) — UNE CIBLE NON LUE N'EST PAS UNE CIBLE SUPPRIMÉE, ET CETTE LIGNE LE DISAIT.
// `resolve_case_ref` (daemon/src/handlers/cases.rs) rendait `(None, None)` dans les DEUX cas — la ligne
// n'existe plus, ou la lecture n'a pas eu lieu — et cette vue peignait alors, en toutes lettres,
// « (cible introuvable — supprimée ou expirée) » sur une alerte qui EXISTE : l'analyste en déduit que la
// rétention a emporté sa preuve, et il cesse de chercher. Depuis `P10.20-p` le démon pose `ref_non_lu:
// true` sur l'élément — et SEULEMENT quand il y a quelque chose à avouer (chemin nominal byte-identique).
// CE QUE CE MOT NE PORTE PAS, ET C'EST LE DÉMON QUI NE LE SERT PAS : la CAUSE. `case_get_lu` insère un
// booléen, rien d'autre — l'erreur `rusqlite` est perdue dans `Err(_) => (None, None, true)`. Le second
// nœud de l'aveu ne peut donc rien citer ici : ce qui est dit, c'est que la lecture n'a PAS eu lieu, et
// que ce n'est PAS l'absence. Inventer une cause serait exactement le défaut qu'on ferme.
const CIBLE_DE_CHRONOLOGIE_MOTS = {
  non_lue: { fr: 'cible NON LUE', en: 'target NOT READ' },
  non_lue_detail: {
    fr: "Cible NON LUE : le démon n'a PAS pu lire cet élément de chronologie — ce n'est PAS « supprimée ou expirée », et l'alerte ou l'événement visé existe peut-être. Cette route ne sert pas la cause ; rouvrez la cible par sa référence.",
    en: 'Target NOT READ: the daemon could NOT read this timeline item — this is NOT “deleted or expired”, and the alert or event may well exist. This route does not serve the cause; reopen the target by its reference.' },
  absente: { fr: '(cible introuvable — supprimée ou expirée)', en: '(target not found — deleted or expired)' },
};
const motDeLaCibleDeChronologie = (cle) => (LANG === 'en' ? CIBLE_DE_CHRONOLOGIE_MOTS[cle].en : CIBLE_DE_CHRONOLOGIE_MOTS[cle].fr);
function caseItemEl(caseId, it, edit) {
  const el = document.createElement('div'); el.className = 'caseitem k-' + (it.kind || 'note');
  el.appendChild(Object.assign(document.createElement('time'), { textContent: fmtTs(it.ts) }));
  el.appendChild(Object.assign(document.createElement('span'), { className: 'who', textContent: it.author || '—' }));
  el.appendChild(Object.assign(document.createElement('span'), { className: 'kind', textContent: CASE_KIND[it.kind] || it.kind }));
  const body = document.createElement('span'); body.className = 'body';
  if (it.ref) {
    const nonLue = it.ref_non_lu === true;
    const chip = document.createElement('span'); chip.className = 'casechip';
    chip.textContent = it.ref_title ? (it.ref + ' · ' + it.ref_title) : it.ref;
    chip.title = it.ref_title || (nonLue ? motDeLaCibleDeChronologie('non_lue_detail') : motDeLaCibleDeChronologie('absente'));
    if (!it.ref_title) chip.style.opacity = '.7';
    if (it.ref_severity != null) chip.title += ' — ' + sev(it.ref_severity);
    body.appendChild(chip);
    // L'AVEU EST UN NŒUD, PAS SEULEMENT UNE INFOBULLE : une infobulle ne se lit qu'au survol, et c'est
    // précisément la ligne qu'un analyste parcourt sans s'arrêter. Le mot est posé au puits (le lexique
    // ne voit qu'un nœud texte ENTIER), à côté de la pastille dont il qualifie la référence.
    if (nonLue) {
      const dit = document.createElement('span'); dit.className = 'bad'; dit.style.cssText = 'margin-left:6px;font-size:11px';
      dit.textContent = motDeLaCibleDeChronologie('non_lue');
      dit.title = motDeLaCibleDeChronologie('non_lue_detail');
      body.appendChild(dit);
    }
    if (it.body && it.body !== it.ref_title) { body.appendChild(document.createTextNode(' ')); body.appendChild(Object.assign(document.createElement('span'), { textContent: it.body })); }
  } else {
    body.textContent = it.body || '';
  }
  if (edit) {
    const del = document.createElement('button'); del.type = 'button'; del.className = 'casebtn'; del.title = 'Détacher cet élément'; del.style.color = 'var(--mut)'; del.innerHTML = ic('x');
    del.onclick = e => { e.stopPropagation(); withBusy(del, () => detachCaseItem(caseId, it.id)); };
    body.appendChild(document.createTextNode(' ')); body.appendChild(del);
  }
  el.appendChild(body);
  return el;
}

async function caseUpdate(id, patch) {
  try { await apiSend('/cases/' + id, 'POST', patch); }
  catch (e) { toast('Action refusée : ' + ((e && e.message) || e), 'bad'); return; }
  toast('Case mis à jour', 'ok');
  await loadCases();          // statut/priorité/overdue peuvent avoir changé -> re-tri de la liste
  await refreshCaseDetail(id);
}

// #4a-bis — ARCHIVE (soft-delete) : masque le case de la liste par défaut, l'historique est conservé (append-
// only côté daemon) et l'action est réversible. ADMIN uniquement (confirmModal explicite ; le daemon revérifie).
async function caseArchive(id) {
  if (!await confirmModal('Archiver le case #' + id + ' ?\n\nArchiver = MASQUER de la liste par défaut. L\'historique (timeline) est conservé et l\'action est réversible (bouton « Désarchiver » dans la vue Archivés).', { okText: 'Archiver', danger: true })) return;
  try { await apiSend('/cases/' + id + '/archive', 'POST'); }
  catch (e) { toast('Archivage refusé : ' + ((e && e.message) || e), 'bad'); return; }
  toast('Case #' + id + ' archivé', 'ok');
  await loadCases();            // disparaît de la liste par défaut (réapparaît sous « Archivés »)
  await refreshCaseDetail(id);  // le détail reste ouvert -> désarchivage possible dans la foulée
}

async function caseUnarchive(id) {
  if (!await confirmModal('Désarchiver le case #' + id + ' ? Il réapparaîtra dans la liste par défaut.', { okText: 'Désarchiver', danger: false })) return;
  try { await apiSend('/cases/' + id + '/unarchive', 'POST'); }
  catch (e) { toast('Désarchivage refusé : ' + ((e && e.message) || e), 'bad'); return; }
  toast('Case #' + id + ' désarchivé', 'ok');
  await loadCases();
  await refreshCaseDetail(id);
}

async function detachCaseItem(caseId, itemId) {
  if (!await confirmModal('Détacher cet élément de la timeline ? (une note de traçabilité est conservée)', { okText: 'Détacher', danger: true })) return;
  try { await apiSend('/cases/' + caseId + '/items/' + itemId, 'DELETE'); }
  catch (e) { toast('Détachement refusé : ' + ((e && e.message) || e), 'bad'); return; }
  toast('Élément détaché', 'ok');
  await refreshCaseDetail(caseId); await loadCases();
}

// rattache un event/alerte/action au case courant : ref facultative (alert:ID / event:ID -> résolue en
// titre+sévérité par le daemon ; autre ref ou vide -> item libre horodaté). #4a.
async function attachToCasePrompt(caseId) {
  const r = await modal({ title: 'Rattacher un élément', okText: 'Rattacher', fields: [
    { name: 'kind', label: 'Type', type: 'select', value: 'event', options: [
      { value: 'event', label: 'Événement' }, { value: 'alert', label: 'Alerte' }, { value: 'action', label: 'Action / observation' }] },
    { name: 'ref', label: 'Référence (optionnel : alert:ID ou event:ID)', placeholder: 'ex : alert:42' },
    { name: 'body', label: 'Description', placeholder: 'contexte de l\'élément rattaché' },
  ], validate: v => (!String(v.ref || '').trim() && !String(v.body || '').trim()) ? 'Renseigne une référence ou une description.' : null });
  if (!r) return;
  const payload = { kind: r.kind };
  const ref = String(r.ref || '').trim(); if (ref) payload.ref = ref;
  const body = String(r.body || '').trim(); if (body) payload.body = body;
  try { await apiSend('/cases/' + caseId + '/items', 'POST', payload); }
  catch (e) { toast('Rattachement refusé : ' + ((e && e.message) || e), 'bad'); return; }
  toast('Élément rattaché', 'ok');
  await refreshCaseDetail(caseId); await loadCases();
}

// #39 — durée lisible (MTTA/MTTR) : s -> s/min/h/j. null -> '—'.
function fmtDur(s) {
  if (s == null) return '—'; s = Number(s);
  if (s < 60) return s + 's';
  if (s < 3600) return Math.round(s / 60) + 'min';
  if (s < 86400) return (s / 3600).toFixed(1) + 'h';
  return (s / 86400).toFixed(1) + 'j';
}

// #39 — BANDEAU CHARGE + MTTA/MTTR (queues par assignee + KPI). Vide (masqué) tant qu'aucun case -> mode 0
// n'affiche rien. Lecture seule (viewer+). Les chips de file filtrent la liste sur l'assignee (per-assignee queue).
const FILES_AFFICHEES = 12; // la coupe de la console sur les puces de file — dite par `phraseDAffichagePartiel`
async function loadCaseOpsSummary() {
  const host = $('#caseops-summary'); if (!host) return;
  let queues = [], metrics = {}, refus = '';
  let reponseDesFiles = null;
  try { reponseDesFiles = await api('/cases/queues'); refus = causeDuRefusServi(reponseDesFiles); queues = reponseDesFiles.queues || []; } catch (e) {}
  try { metrics = await api('/cases/metrics'); refus = refus || causeDuRefusServi(metrics); } catch (e) {}
  host.replaceChildren();
  // `P10.7-d` — LE BANDEAU DISPARAISSAIT SUR UN REFUS, exactement comme il disparaît en mode 0 (aucun cas).
  // Un panneau qui s'efface ne dit rien, et « rien » se lit ici comme « aucune charge » : c'est une absence
  // rendue à la place d'un refus. Le refus est maintenant DIT, avec la cause du démon telle quelle ; le mode
  // 0, lui, continue de ne rien afficher — il n'y a pas de refus à rapporter, et le test est SÉPARÉ.
  if (refus) {
    host.appendChild(Object.assign(document.createElement('div'), { className: 'bad', textContent: 'Charge et SLA NON LUS — ' + refus }));
    return;
  }
  const o = metrics.overall || {};
  if (!(queues && queues.length) && !(o.open_now || o.resolved)) return; // rien à montrer
  const kpi = (label, val, title) => {
    const b = document.createElement('div'); b.style.cssText = 'border:1px solid var(--bd);border-radius:10px;padding:6px 12px;min-width:96px;background:var(--card)'; if (title) b.title = title;
    b.appendChild(Object.assign(document.createElement('div'), { textContent: label, style: 'font-size:11px;color:var(--mut)' }));
    b.appendChild(Object.assign(document.createElement('div'), { textContent: val, style: 'font-size:18px;font-weight:700' }));
    return b;
  };
  const row = document.createElement('div'); row.style.cssText = 'display:flex;flex-wrap:wrap;gap:8px;align-items:stretch';
  row.appendChild(kpi('Ouverts', String(o.open_now ?? 0)));
  row.appendChild(kpi('En retard', String(o.overdue_now ?? 0), 'SLA dépassé'));
  row.appendChild(kpi('MTTA', fmtDur(o.mtta_mean), 'Temps moyen d\'acquittement (fenêtre 30 j)'));
  row.appendChild(kpi('MTTR', fmtDur(o.mttr_mean), 'Temps moyen de résolution (fenêtre 30 j)'));
  row.appendChild(kpi('Résolus', String(o.resolved ?? 0), 'Sur la fenêtre'));
  const breaches = (o.ack_breaches || 0) + (o.resolve_breaches || 0);
  if (breaches > 0) row.appendChild(kpi('Breach SLA', String(breaches), 'Manquements SLA multi-niveau (fenêtre)'));
  host.appendChild(row);
  if (queues && queues.length) {
    const qwrap = document.createElement('div'); qwrap.style.cssText = 'display:flex;flex-wrap:wrap;gap:6px;margin-top:8px';
    qwrap.appendChild(Object.assign(document.createElement('span'), { textContent: 'Files :', className: 'muted', style: 'font-size:12px;align-self:center' }));
    queues.slice(0, FILES_AFFICHEES).forEach(q => {
      const chip = document.createElement('button'); chip.type = 'button'; chip.className = 'casechip'; chip.style.cursor = 'pointer';
      chip.textContent = q.assignee + ' · ' + q.open + (q.overdue ? ' (' + q.overdue + ' retard)' : '') + (q.breach ? ' ⚠' + q.breach : '');
      chip.title = 'Filtrer la file de ' + q.assignee;
      chip.onclick = () => { const inp = $('#case-assignee-filter'); if (inp && q.assignee !== '(none)') { inp.value = q.assignee; loadCases(); } };
      qwrap.appendChild(chip);
    });
    // `P11.22-g` — deux coupes DITES : celle du démon (files servies à la borne) et celle de la console (12 puces).
    const coupes = [phraseDAffichagePartiel(Math.min(queues.length, FILES_AFFICHEES), queues.length), phraseDeCoupe(reponseDesFiles, '')].filter(Boolean).join(' · ');
    if (coupes) { const c = document.createElement('span'); c.className = 'muted coupe-de-liste'; c.style.cssText = 'font-size:12px;align-self:center'; c.textContent = coupes; qwrap.appendChild(c); }
    host.appendChild(qwrap);
  }
  // `P11.22-g` — un échantillon MTTA/MTTR coupé se présente comme coupé, pas comme la mesure de la fenêtre.
  const echantillon = phraseDEchantillonCoupe(metrics);
  if (echantillon) { const e = document.createElement('div'); e.className = 'muted coupe-de-liste'; e.style.cssText = 'font-size:12px;margin-top:4px'; e.textContent = echantillon; host.appendChild(e); }
}

// =================================================================================================
// `P10.21-a` — LE TYPE D'UN LIEN DE DOSSIER EST DIT, PAS RECOPIÉ.
//
// CE QUE LE DÉMON ÉCRIT, MESURÉ AVANT D'ÊTRE DIT. `case_link_handler` (daemon/src/handlers/caseops.rs)
// prend le `kind` du corps TEL QUEL et le passe à `case_link_add` — qui, lui, le RAMÈNE à
// `duplicate | blocks | related`, tout autre mot devenant `related` avant l'INSERT. Le vocabulaire
// ÉCRIT par la route est donc CLOS, et c'est exactement celui que le formulaire « Lier… » de cette vue
// propose. La colonne, elle, reste ouverte (`kind TEXT NOT NULL DEFAULT 'related'`, aucun `CHECK`, cf.
// daemon/src/migrate.rs) : une ligne posée par un binaire plus ancien ou par une écriture directe peut
// porter autre chose, et `case_links_json` la SERT telle quelle.
//
// CE QUE CETTE VUE EN FAISAIT. Elle peignait le jeton nu entre parenthèses — « #12 (blocks) » : un mot
// de machine, en anglais, là où le reste de la puce est une phrase, et rien ne disait si ce mot venait
// du vocabulaire connu ou d'une valeur qu'aucun formulaire ne propose. Les deux cas se lisaient pareil.
//
// CE QU'ELLE EN FAIT. Les trois valeurs connues rendent leur phrase dans la langue de l'écran ; toute
// autre est rendue comme un jeton DIT LIBRE, gardé entre guillemets — le mot du démon reste lisible et
// recopiable, et sa nature de valeur hors vocabulaire est écrite à côté. Un type SERVI VIDE a sa propre
// phrase : le démon ne le produit pas (la colonne est `NOT NULL` et la normalisation le remplirait),
// mais un nœud vide se lirait comme un lien sans type plutôt que comme un type sans valeur.
// LES PARENTHÈSES ONT DISPARU DE LA PUCE et c'est la phrase libre qui les emporte : elle en porte
// elle-même, et « (lien de type « x » (valeur libre)) » se lirait comme une incise dans une incise.
// AUCUN CHANGEMENT AU DÉMON n'est demandé par cette clé : le vocabulaire est déjà clos à l'écriture.
// =================================================================================================
const MOTS_DU_GENRE_DE_LIEN = {
  related: { fr: 'Relié', en: 'Related' },
  duplicate: { fr: 'Doublon', en: 'Duplicate' },
  blocks: { fr: 'Bloque', en: 'Blocks' },
};
const MOTS_DU_GENRE_DE_LIEN_HORS_VOCABULAIRE = {
  jeton_libre: {
    fr: 'lien de type « {jeton} » (valeur libre)',
    en: 'link of type “{jeton}” (free value)' },
  jeton_absent: {
    fr: 'lien SANS type servi (aucune valeur rendue pour ce lien)',
    en: 'link with NO type served (no value returned for this link)' },
};
function motDuGenreDeLien(genre) {
  const jeton = String(genre == null ? '' : genre).trim();
  const connu = Object.prototype.hasOwnProperty.call(MOTS_DU_GENRE_DE_LIEN, jeton) ? MOTS_DU_GENRE_DE_LIEN[jeton] : null;
  if (connu) return LANG === 'en' ? connu.en : connu.fr;
  const mots = MOTS_DU_GENRE_DE_LIEN_HORS_VOCABULAIRE[jeton ? 'jeton_libre' : 'jeton_absent'];
  return (LANG === 'en' ? mots.en : mots.fr).replace('{jeton}', jeton);
}

// =================================================================================================
// `P10.21-d` — LES REFUS NEUFS D'OUVERTURE DE DOSSIER ET DE LIEN, LUS SUR LA PHRASE DU DÉMON.
//
// CE QUE LE DÉMON SERT. `case_create` (daemon/src/handlers/cases.rs) refuse en cinq cent trois
// `CAUSE_DOSSIER_NON_OUVERT` AVANT tout registre et tout identifiant ; `case_link_handler` et
// `case_unlink_handler` (daemon/src/handlers/caseops.rs) séparent l'écriture ratée — cinq cent trois
// `CAUSE_LIEN_NON_POSE` / `CAUSE_LIEN_NON_RETIRE`, servis `<cause> (<détail>)` — du quatre cent quatre,
// resté NU à dessein : aucun corps, aucune cause. Sur la pose, ce quatre cent quatre couvre trois faits
// que le démon ne sépare pas (un dossier absent, un lien d'un dossier vers lui-même, une relecture du
// dossier qui échoue) ; sur le retrait, un seul (aucun lien entre les deux). La console ne choisit donc
// pas entre eux : elle dit le code et qu'aucune cause n'est nommée.
//
// CE QUE LA CONSOLE EN FAISAIT, MESURÉ. Les deux créations de dossier n'avaient AUCUN `catch` : le rejet
// sortait du geste sans un mot. La pose et le retrait captaient le rejet, mais peignaient `e.message` —
// « 503 {"error":"LIEN NON POSÉ : la ligne n'a pas pu… » coupé à deux cents caractères — et, sur le
// quatre cent quatre nu, le seul mot « 404 ».
//
// LES OUVERTURES S'ANCRENT EN TÊTE, BORNÉES PAR UNICODE. Deux des trois finissent sur « É », hors de
// la classe ASCII de `\b` : `/^LIEN NON POSÉ\b/` ne reconnaîtrait JAMAIS la phrase servie (aucune
// frontière entre « É » et l'espace), et accepterait « LIEN NON POSÉE ». La troisième finit sur une
// lettre ASCII, où `\b` accepterait encore une lettre accentuée juste après ; même borne pour les trois.
const OUVERTURE_DU_DOSSIER_NON_OUVERT = /^DOSSIER NON OUVERT(?![\p{L}\p{N}])/u;
const OUVERTURE_DU_LIEN_NON_POSE = /^LIEN NON POSÉ(?![\p{L}\p{N}])/u;
const OUVERTURE_DU_LIEN_NON_RETIRE = /^LIEN NON RETIRÉ(?![\p{L}\p{N}])/u;
// Un refus SANS corps : `apiSend` compose alors un message qui n'est que le code. C'est le seul cas où
// la console sait que le démon n'a RIEN nommé — et donc le seul où elle doit le dire au lieu de citer.
const refusNu = (e) => !(e && e.causeDuDemon) && /^\d{3}$/.test(String((e && e.message) || '').trim());
// Chaque phrase dit ce qui reste en base — sans quoi l'exploitant recommence un geste pris, ou renonce
// à un geste rejouable. Celles qui citent se terminent par un tiret : la cause suit, dans un second nœud.
const MOTS_DES_REFUS_DE_DOSSIER = {
  dossier_non_ouvert: {
    fr: "Dossier NON OUVERT : la ligne n'a pas pu être écrite, donc AUCUN dossier n'existe, rien n'y est rattaché et aucun identifiant n'est rendu. Le geste peut être rejoué. Le démon en nomme la cause —",
    en: 'Case NOT OPENED: the line could not be written, so NO case exists, nothing is attached to it and no identifier is returned. The gesture can be replayed. The daemon names the cause —' },
  creation_refusee: {
    fr: "Création du dossier REFUSÉE : aucun identifiant n'est rendu, rien n'est rattaché. Le démon a répondu —",
    en: 'Case creation REFUSED: no identifier is returned, nothing is attached. The daemon answered —' },
  dossier_sans_identifiant: {
    fr: "Dossier : le démon a accepté la création sans rendre d'identifiant — la console ne sait pas quel dossier ouvrir, et n'y rattache rien.",
    en: 'Case: the daemon accepted the creation without returning an identifier — the console does not know which case to open, and attaches nothing to it.' },
  lien_non_pose: {
    fr: "Lien NON POSÉ : les deux dossiers ne sont PAS liés et rien n'en garde trace — ce n'est pas « déjà liés ». Le geste peut être rejoué. Le démon en nomme la cause —",
    en: 'Link NOT SET: the two cases are NOT linked and nothing keeps a trace of it — this is not "already linked". The gesture can be replayed. The daemon names the cause —' },
  lien_introuvable_sans_cause: {
    fr: "Lien NON POSÉ : le démon a répondu « introuvable » (404) sans nommer de cause. Rien n'a été lié.",
    en: 'Link NOT SET: the daemon answered "not found" (404) without naming a cause. Nothing was linked.' },
  lien_refuse: {
    fr: "Lien REFUSÉ : le démon n'a pas confirmé la pose. Il a répondu —",
    en: 'Link REFUSED: the daemon did not confirm it. It answered —' },
  lien_non_retire: {
    fr: "Lien NON RETIRÉ : la suppression n'a pas pu être écrite, les deux dossiers sont TOUJOURS liés. Le geste peut être rejoué. Le démon en nomme la cause —",
    en: 'Link NOT REMOVED: the deletion could not be written, the two cases are STILL linked. The gesture can be replayed. The daemon names the cause —' },
  retrait_introuvable_sans_cause: {
    fr: "Retrait sans effet : le démon a répondu « introuvable » (404) sans nommer de cause. Rien n'a été retiré.",
    en: 'Removal without effect: the daemon answered "not found" (404) without naming a cause. Nothing was removed.' },
  retrait_refuse: {
    fr: "Retrait du lien REFUSÉ : le démon n'a pas confirmé la suppression. Il a répondu —",
    en: 'Link removal REFUSED: the daemon did not confirm the deletion. It answered —' },
};
const motDuRefusDeDossier = (cle) => (LANG === 'en' ? MOTS_DES_REFUS_DE_DOSSIER[cle].en : MOTS_DES_REFUS_DE_DOSSIER[cle].fr);
// LE DISCRIMINANT, un par geste, jugé par le harnais dans les deux sens sur les littéraux du démon.
// `geste` : 'ouvrir' (création de dossier), 'lier' (pose), 'delier' (retrait).
function cleDuRefusDeDossier(geste, e) {
  const phrase = phraseDuRefusDuDemon(e);
  if (geste === 'ouvrir') return OUVERTURE_DU_DOSSIER_NON_OUVERT.test(phrase) ? 'dossier_non_ouvert' : 'creation_refusee';
  if (geste === 'lier') {
    if (OUVERTURE_DU_LIEN_NON_POSE.test(phrase)) return 'lien_non_pose';
    return refusNu(e) && phrase === '404' ? 'lien_introuvable_sans_cause' : 'lien_refuse';
  }
  if (OUVERTURE_DU_LIEN_NON_RETIRE.test(phrase)) return 'lien_non_retire';
  return refusNu(e) && phrase === '404' ? 'retrait_introuvable_sans_cause' : 'retrait_refuse';
}
// La phrase et la cause SÉPARÉES : la cause est ce que le démon a servi, ou rien quand la phrase de la
// console dit déjà qu'il n'a rien nommé — citer « 404 » après « a répondu 404 » serait un bégaiement.
function refusDeDossier(geste, e) {
  const cle = cleDuRefusDeDossier(geste, e);
  return { cle, mot: motDuRefusDeDossier(cle), cause: /_sans_cause$/.test(cle) ? '' : phraseDuRefusDuDemon(e) };
}
// L'avis, pour les gestes dont la modale s'est refermée : phrase et cause dans une seule chaîne.
function phraseDuRefusDeDossier(geste, e) {
  const r = refusDeDossier(geste, e);
  return r.cause ? r.mot + ' « ' + r.cause + ' »' : r.mot;
}
// L'aveu à DEUX nœuds, là où un puits reste ouvert : la phrase au puits (`dit.textContent = …`), la
// cause servie dans un second nœud. La marque de pose sert au harnais, aucune règle CSS ne la vise.
function aveuDuRefusDeDossier(geste, e) {
  const r = refusDeDossier(geste, e);
  const aveu = document.createElement('div'); aveu.className = 'bad';
  const dit = document.createElement('span');
  dit.textContent = r.mot;
  aveu.append(dit);
  if (r.cause) aveu.append(' « ' + r.cause + ' »');
  aveu.dataset.refusDeDossier = r.cle;
  return aveu;
}
// Le retrait part d'une puce de la section des liens, qui reste affichée : l'aveu s'y pose, en
// remplaçant celui d'un retrait précédent — deux refus empilés se liraient comme deux liens en panne.
function poserLAveuDuRetrait(sec, e) {
  const avant = sec.querySelector('[data-refus-de-dossier]');
  if (avant) avant.remove();
  sec.appendChild(aveuDuRefusDeDossier('delier', e));
}

// #39 — section LIENS & FUSION du détail : "fusionné dans #N" (+ dé-fusion editor) + chips de liens (cliquables).
async function renderCaseLinks(box, c) {
  const sec = document.createElement('div');
  if (c.merged_into) {
    const m = document.createElement('div'); m.className = 'muted'; m.style.cssText = 'font-size:12px;margin:6px 0';
    m.appendChild(document.createTextNode('Fusionné dans '));
    const a = document.createElement('a'); a.href = '#cases'; a.textContent = '#' + c.merged_into; a.onclick = e => { e.preventDefault(); showCaseDetail(c.merged_into); };
    m.appendChild(a);
    if (canEditCases()) {
      const u = caseBtn('Dé-fusionner', 'ghost'); u.style.marginLeft = '8px';
      u.onclick = () => withBusy(u, async () => { try { await apiSend('/cases/' + c.id + '/unmerge', 'POST'); } catch (err) { toast('Refusé : ' + ((err && err.message) || err), 'bad'); return; } toast('Dé-fusionné', 'ok'); await loadCases(); refreshCaseDetail(c.id); });
      m.appendChild(u);
    }
    sec.appendChild(m);
  }
  let links = [], reponseDesLiens = null;
  try { reponseDesLiens = await api('/cases/' + c.id + '/links'); links = reponseDesLiens.links || []; } catch (e) {}
  // `P10.7-f` (rang 4) — DES LIENS NON LUS NE SONT PAS « CE DOSSIER N'EN A AUCUN ». Le démon sert, en 200,
  // `{links: [], served: 0, window: 200, total: null, total_capped: null, error: <cause>}`
  // (`liste_bornee::corps`, daemon/src/handlers/caseops.rs) : `api()` ne jette que sur `!r.ok`, et
  // `reponseDesLiens.links || []` en refaisait une absence. Ici l'absence ne se PEINT même pas — la section
  // « Liens » disparaît —, et un dossier fusionné, doublonné ou bloquant se lit isolé sur la SEULE vue qui
  // montre ses rattachements. Le geste d'écriture se retire avec la liste : « Lier… » porte la marque
  // accessible de l'inertie avec sa raison, et le clic DIT le refus (grammaire de `P11.4-l`).
  const boutonLier = BOUTON_LIER.get(c.id);
  if (reponseDesLiens && reponseDesLiens.error) {
    LIENS_NON_LUS.add(c.id);
    const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:6px 0;font-size:12px';
    const dit = document.createElement('span');
    dit.textContent = 'Liens du dossier NON LUS : le démon a refusé et en nomme la cause —';
    aveu.append(dit, ' « ' + String(reponseDesLiens.error).trim() + ' »');
    sec.appendChild(aveu);
    if (boutonLier) { boutonLier.setAttribute('aria-disabled', 'true'); boutonLier.title = "Les liens de ce dossier n'ont PAS été lus : en ajouter un ici, c'est peut-être recréer un rattachement qui existe déjà et que cette lecture n'a pas pu rendre."; }
    box.appendChild(sec);
    return;
  }
  LIENS_NON_LUS.delete(c.id);
  if (boutonLier) { boutonLier.removeAttribute('aria-disabled'); boutonLier.removeAttribute('title'); }
  if (links && links.length) {
    sec.appendChild(Object.assign(document.createElement('div'), { className: 'casesec', textContent: 'Liens' }));
    const wrap = document.createElement('div'); wrap.style.cssText = 'display:flex;flex-wrap:wrap;gap:6px';
    links.forEach(l => {
      const chip = document.createElement('span'); chip.className = 'casechip'; chip.style.cursor = 'pointer';
      chip.textContent = '#' + l.id + ' · ' + motDuGenreDeLien(l.kind) + ' · ' + l.title; chip.title = l.note || '';
      chip.onclick = () => showCaseDetail(l.id);
      if (canEditCases()) {
        const x = document.createElement('button'); x.type = 'button'; x.className = 'casebtn'; x.title = 'Retirer le lien'; x.style.marginLeft = '4px'; x.innerHTML = ic('x');
        x.onclick = e => { e.stopPropagation(); withBusy(x, async () => { if (!await confirmWithConsequence(`Retirer le lien vers #${l.id}`, 'les deux cas ne seront plus rattachés ; le lien se recrée à la main, sans son historique.', { okText: 'Retirer', danger: true })) return; try { await apiSend('/cases/' + c.id + '/links/' + l.id, 'DELETE'); } catch (err) { poserLAveuDuRetrait(sec, err); return; } toast('Lien retiré', 'ok'); refreshCaseDetail(c.id); }); };
        chip.appendChild(x);
      }
      wrap.appendChild(chip);
    });
    // `P11.22-g` — un dossier qui porte plus de liens que la borne le dit.
    const coupe = phraseDeCoupe(reponseDesLiens, '');
    if (coupe) { const c = document.createElement('span'); c.className = 'muted coupe-de-liste'; c.style.cssText = 'font-size:12px;align-self:center'; c.textContent = coupe; wrap.appendChild(c); }
    sec.appendChild(wrap);
  }
  if (sec.childNodes.length) box.appendChild(sec);
}

// #39 — FUSION (soft) : fusionne le case courant DANS une cible choisie (le courant est clos + rattaché ;
// timeline combinée dans la cible ; réversible). editor+.
async function mergeCasePrompt(id) {
  let cases = [], refus = '';
  try { const j = await api('/cases?limit=200'); refus = causeDuRefusServi(j); cases = j.cases; } catch (e) {}
  // `P10.7-d` — LA DÉCONSTRUCTION JETAIT L'AVEU. `({ cases } = await api(…))` ne garde que la clé attendue :
  // la cause servie à côté disparaissait, `cases` valait `undefined`, et le sélecteur annonçait « Aucune
  // autre case cible » — une absence AFFIRMÉE sur une lecture qui n'a pas eu lieu. La réponse entière est
  // désormais tenue, et le refus est dit AVANT le compte.
  if (refus) { toast('Cases NON LUS — ' + refus, 'bad', 8000); return; }
  const opts = (cases || []).filter(c => c.id !== id).map(c => ({ value: String(c.id), label: '#' + c.id + ' · ' + c.title }));
  if (!opts.length) { toast('Aucune autre case cible', 'bad'); return; }
  const r = await modal({ title: 'Fusionner le case #' + id, okText: 'Fusionner', fields: [
    { name: 'into', label: 'Fusionner DANS (cible) — #' + id + ' sera clos, rattaché et réversible', type: 'select', options: opts },
  ] });
  if (!r) return;
  try { await apiSend('/cases/' + id + '/merge', 'POST', { into: Number(r.into) }); }
  catch (e) { toast('Fusion refusée : ' + ((e && e.message) || e), 'bad'); return; }
  toast('Case #' + id + ' fusionné dans #' + r.into, 'ok');
  await loadCases(); showCaseDetail(Number(r.into));
}

// #39 — LIEN (association non destructive) entre le case courant et un autre. editor+.
async function linkCasePrompt(id) {
  // La MÊME phrase qu'au survol du bouton, jamais deux formulations du même refus.
  if (LIENS_NON_LUS.has(id)) { toast("Les liens de ce dossier n'ont PAS été lus : en ajouter un ici, c'est peut-être recréer un rattachement qui existe déjà et que cette lecture n'a pas pu rendre.", 'bad', 9000); return; }
  let cases = [], refus = '';
  try { const j = await api('/cases?limit=200'); refus = causeDuRefusServi(j); cases = j.cases; } catch (e) {}
  if (refus) { toast('Cases NON LUS — ' + refus, 'bad', 8000); return; }   // `P10.7-d`, cf. mergeCasePrompt
  const opts = (cases || []).filter(c => c.id !== id).map(c => ({ value: String(c.id), label: '#' + c.id + ' · ' + c.title }));
  if (!opts.length) { toast('Aucune autre case à lier', 'bad'); return; }
  const r = await modal({ title: 'Lier le case #' + id, okText: 'Lier', fields: [
    { name: 'to', label: 'Case à lier', type: 'select', options: opts },
    // `P10.21-a` — LES TROIS TYPES OFFERTS SONT CEUX QUE LA PUCE SAIT DIRE, et ils viennent de la MÊME
    // table : deux listes du même vocabulaire finiraient par ne plus se répondre, et un type qu'on peut
    // choisir sans savoir le rendre se relirait en jeton libre le lendemain.
    { name: 'kind', label: 'Type de lien', type: 'select', value: 'related',
      options: Object.keys(MOTS_DU_GENRE_DE_LIEN).map(g => ({ value: g, label: motDuGenreDeLien(g) })) },
    { name: 'note', label: 'Note (optionnel)' },
  ] });
  if (!r) return;
  // `P10.21-d` — la modale est refermée : un avis, phrase du refus et cause servie ensemble.
  try { await apiSend('/cases/' + id + '/links', 'POST', { to: Number(r.to), kind: r.kind, note: r.note || '' }); }
  catch (e) { toast(phraseDuRefusDeDossier('lier', e), 'bad', 9000); return; }
  toast('Cases liés', 'ok');
  await refreshCaseDetail(id);
}

// bascule sur l'onglet Cases + ouvre le détail inline (appelé depuis une alerte/un event rattaché).
async function openCase(id) {
  if (location.hash.slice(1) !== 'cases') location.hash = 'cases';
  await loadCases();
  showCaseDetail(id);
}

async function createCase() {
  const r = await modal({ title: 'Nouveau case', okText: 'Créer', fields: [
    { name: 'title', label: 'Titre', required: true, placeholder: 'ex: Bruteforce SSH 203.0.113.7' },
    { name: 'severity', label: 'Sévérité', type: 'select', value: '2', options: [0, 1, 2, 3, 4].map(n => ({ value: String(n), label: sev(n) })) },
    { name: 'priority', label: 'Priorité', type: 'select', value: '3', options: [1, 2, 3, 4].map(p => ({ value: String(p), label: PRIO_LABEL[p] })) },
    { name: 'assignee', label: 'Assigné (optionnel)', placeholder: 'utilisateur' },
    { name: 'summary', label: 'Résumé (optionnel)', type: 'textarea', placeholder: 'contexte initial' },
  ] });
  if (!r) return;
  const body = { title: r.title.trim(), severity: Number(r.severity), priority: Number(r.priority) };
  if (r.assignee && r.assignee.trim()) body.assignee = r.assignee.trim();
  if (r.summary && r.summary.trim()) body.summary = r.summary.trim();
  // `P10.21-d` — un refus d'ouverture est DIT, et rien n'est ouvert : aucun identifiant n'existe.
  let j;
  try { j = await apiSend('/cases', 'POST', body); }
  catch (e) { toast(phraseDuRefusDeDossier('ouvrir', e), 'bad', 9000); return; }
  await loadCases();
  if (j && j.id) showCaseDetail(j.id);
  else toast(motDuRefusDeDossier('dossier_sans_identifiant'), 'bad', 9000);
}

// ajoute un element (alerte/event) a un case existant OU nouveau. ref facultative (event depuis l'Explore =
// sans id -> item 'event' libre ; alerte -> ref='alert:ID').
async function addToCase(kind, body, ref) {
  let cases = [], refus = '';
  try { const j = await api('/cases'); refus = causeDuRefusServi(j); cases = j.cases; } catch (e) {}
  // `P10.7-d` — C'EST ICI QUE L'ABSENCE FABRIQUÉE COÛTAIT LE PLUS CHER. Sur un refus, `cases` valait
  // `undefined` : le sélecteur n'offrait plus que « + Nouveau case », et l'analyste créait un DOUBLON du cas
  // qui existait déjà — un refus de lecture se soldait par une ÉCRITURE fausse. Le geste est refusé, et dit.
  if (refus) { toast('Cases NON LUS — ' + refus + " Aucun cas n'est proposé : rien n'a été lu, et créer ici ferait un doublon.", 'bad', 9000); return; }
  const active = (cases || []).filter(c => !CASE_TERMINAL.has(c.status));   // le daemon écrit 'new' (plus 'open' legacy)
  const opts = [{ value: 'new', label: '+ Nouveau case' }, ...active.map(c => ({ value: String(c.id), label: '#' + c.id + ' · ' + c.title }))];
  const r = await modal({ title: 'Ajouter à un case', okText: 'Ajouter', fields: [
    { name: 'cid', label: 'Case', type: 'select', value: active[0] ? String(active[0].id) : 'new', options: opts },
    { name: 'newtitle', label: 'Titre (si nouveau case)', value: String(body).slice(0, 80) },
  ] });
  if (!r) return;
  let id = r.cid;
  if (id === 'new') {
    // `P10.21-d` — SANS DOSSIER OUVERT, RIEN N'EST RATTACHÉ. Le refus sortait en rejet muet ; et un
    // succès sans identifiant (corps vide, qu'`apiSend` rend `null`) aurait posté l'élément sous
    // `/cases/undefined/items`. Les deux s'arrêtent ici, et se disent.
    let j;
    try { j = await apiSend('/cases', 'POST', { title: (r.newtitle || body).trim() || 'Incident', severity: 2 }); }
    catch (e) { toast(phraseDuRefusDeDossier('ouvrir', e), 'bad', 9000); return; }
    if (!(j && j.id)) { toast(motDuRefusDeDossier('dossier_sans_identifiant'), 'bad', 9000); return; }
    id = j.id;
  }
  const payload = { kind, body }; if (ref) payload.ref = ref;
  await apiSend('/cases/' + id + '/items', 'POST', payload);
  toast('Ajouté au case #' + id, 'ok');
  if (typeof refresh === 'function') refresh(); // ré-affiche les alertes -> la pastille "case #N" apparait
  openCase(id); // bascule sur Cases + ouvre le détail (timeline avec l'élément rattaché)
}


// ================================ #3 INCIDENTS + RESPONSE WIZARD (Phase 1) ================================
// Panneau « Runbook / réponse guidée » : élévation case->incident (tier), runbook recommandé (par tactique
// MITRE dominante des alertes liées) + attach, checklist PHASÉE avec suivi de progression. Une step 'search'
// ouvre l'Explore (GXQL recompilé côté serveur) ; une step 'response' PRÉPARE l'action existante — l'exécution
// passe par /api/actions (admin + arm + approbation + ledger) INCHANGÉ, JAMAIS d'auto-exec. Les données
// incident/runbook sont chargées PAR UN FETCH SÉPARÉ (hors case_get_json -> parité mode 0 côté détail).
const PHASE_LABEL = { triage: 'Triage', investigation: 'Investigation', containment: 'Containment', eradication: 'Éradication', recovery: 'Rétablissement' };
const STEP_MARK = { pending: '○', done: '✓', skipped: '⊘' };
// `P10.7-f` (rang 4) — CE QU'UNE LECTURE RATÉE LAISSE DERRIÈRE ELLE, PAR DOSSIER. `LIENS_NON_LUS` est posé
// par `renderCaseLinks` et LU par `linkCasePrompt`, qui vit hors d'elle : c'est le seul point qui EMPÊCHE
// d'écrire un lien sur une liste non lue. `BOUTON_LIER` porte la poignée du geste, pour que la marque
// accessible de l'inertie se pose sur le bouton que la barre a construit AVANT le chargement des liens.
const LIENS_NON_LUS = new Set();
const BOUTON_LIER = new Map();

async function renderWizardPanel(box, c, edit, hr) {
  const sec = document.createElement('div');
  box.appendChild(Object.assign(document.createElement('div'), { className: 'casesec', textContent: 'Runbook / réponse guidée' }));
  box.appendChild(sec);
  sec.appendChild(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'chargement…' }));
  let rb, steps;
  try { rb = await api('/cases/' + c.id + '/runbooks'); } catch (e) { sec.replaceChildren(Object.assign(document.createElement('div'), { className: 'muted', textContent: 'runbook indisponible' })); return; }
  try { steps = await api('/cases/' + c.id + '/steps'); } catch (e) { steps = { steps: [], progress: { total: 0, done: 0, skipped: 0 }, runbook: null }; }
  sec.replaceChildren();
  // badge INCIDENT dans le header (injecté après fetch : les champs incident ne sont pas dans case_get_json).
  if (rb.incident_tier != null && hr) {
    const ib = document.createElement('span'); ib.className = 'badge'; ib.textContent = 'INCIDENT · T' + rb.incident_tier;
    ib.style.color = 'var(--bad)'; ib.style.borderColor = 'color-mix(in srgb,var(--bad) 50%,transparent)';
    ib.title = 'Case élevé en incident' + (rb.incident_type ? ' — type ' + rb.incident_type : '') + (rb.commander ? ' — pilote ' + rb.commander : '');
    hr.insertBefore(ib, hr.firstChild);
  }
  // --- ligne incident : tier + type/commander + boutons déclarer/rétrograder (editor) ---
  const inc = document.createElement('div'); inc.style.cssText = 'display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:8px';
  if (rb.incident_tier != null) {
    inc.appendChild(Object.assign(document.createElement('span'), { textContent: 'Incident déclaré (tier ' + rb.incident_tier + ')' + (rb.incident_type ? ' · ' + rb.incident_type : '') + (rb.commander ? ' · pilote ' + rb.commander : ''), style: 'font-weight:600' }));
    if (edit) { const dem = caseBtn('Rétrograder', 'ghost'); dem.onclick = () => withBusy(dem, () => incidentDemote(c)); inc.appendChild(dem); }
  } else {
    inc.appendChild(muted('Case ordinaire — non élevé en incident.'));
    if (edit) { const dec = caseBtn('Déclarer incident', 'ghost'); dec.onclick = () => incidentDeclare(c); inc.appendChild(dec); }
  }
  sec.appendChild(inc);
  // `P10.7-f` (rang 4) — CE CORPS PORTE DEUX LECTURES DE LIGNES, ET L'AVEU NOMME CELLE QUI A ÉCHOUÉ. Le
  // démon sert, en 200, `{…, non_lus: ["alertes_liees"|"available"], error: <cause>}`
  // (`corps_de_listes_illisibles`, daemon/src/handlers/incidents.rs, `case_runbooks_json`). Les deux moitiés
  // ne se remplacent pas :
  //   · `alertes_liees` n'est PAS servie — ce sont ses DÉRIVÉS qui le sont. Non lue, `dominant_tactic`,
  //     `dominant_technique` et `recommended` valent `null`, et la console n'écrivait alors RIEN : ni la
  //     ligne de tactique (sa condition est fausse), ni la recommandation. Ce silence se lit « ce dossier
  //     n'a aucune alerte liée », le cas EXACT où le repli générique est légitime. La recommandation ne doit
  //     donc pas non plus être offerte comme établie : le démon n'en calcule aucune, et c'est dit.
  //   · `available` est le catalogue, c'est-à-dire le choix MANUEL. Non lu, la console offrait un sélecteur
  //     VIDE ou la phrase « aucun runbook disponible » — l'analyste en écrit alors une à la main, pendant
  //     l'incident. Sous l'aveu, aucun geste d'attache ne s'offre.
  // L'AVEU PASSE AVANT LES DEUX, comme celui des étapes : la ligne incident vient d'une lecture indépendante.
  const rbNonLus = Array.isArray(rb.non_lus) ? rb.non_lus.map(String) : [];
  // La phrase est écrite AU PUITS (`dit.textContent = …`), jamais passée en argument : le lexique ne regarde
  // que le puits, et une phrase qui n'y est pas ne se traduit pas.
  const boiteDAveuDuRunbook = () => {
    const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0 0 6px;font-size:12px';
    const dit = document.createElement('span');
    aveu.appendChild(dit);
    sec.appendChild(aveu);
    return { aveu, dit };
  };
  if (rbNonLus.includes('alertes_liees')) {
    const { aveu, dit } = boiteDAveuDuRunbook();
    dit.textContent = 'Alertes liées du dossier NON LUES : le démon a refusé et en nomme la cause —';
    aveu.append(' « ' + String(rb.error || '').trim() + ' »');
  }
  if (rbNonLus.includes('available')) {
    const { aveu, dit } = boiteDAveuDuRunbook();
    dit.textContent = 'Catalogue de runbooks NON LU : le démon a refusé et en nomme la cause —';
    aveu.append(' « ' + String(rb.error || '').trim() + ' »');
  }
  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // `P10.20-b` (rang 2) — LES DEUX LECTURES D'UNE SEULE LIGNE DE CE PANNEAU, ET CE QUE LEUR SILENCE
  // DISAIT.
  //
  //   · LA RECOMMANDATION. `pick_runbook_id` essayait trois niveaux de correspondance en avalant
  //     chaque échec ; le démon rend maintenant `recommended: null` PLUS `recommandation_non_etablie`
  //     (daemon/src/handlers/incidents.rs). La console ne lisait que `rb.recommended` : un `null`
  //     n'écrivait RIEN, ce qui se lit « aucun runbook ne correspond à cet incident » — la phrase qui
  //     fait écrire une procédure à la main pendant un incident.
  //   · L'ATTACHE. `runbook_attache` avalait de même ; le démon rend `attached_runbook_id: null` plus
  //     `runbook_attache_non_lu` sur la fiche, et `runbook: null` plus `runbook_non_lu` sur la
  //     checklist — c'est LA MÊME lecture, donc UNE seule phrase à l'écran. Le silence se lisait
  //     « aucun runbook attaché », et le geste d'attache S'OFFRAIT : `attach_runbook` refuse dès
  //     qu'une étape existe, et ce refus se lit comme un défaut du produit.
  //
  // CE QUI ÉTAIT PLUS GRAVE QUE L'ÉNONCÉ NE LE DISAIT, MESURÉ ICI : sur une attache non lue, la
  // checklist n'avait pas « un en-tête vide » — elle N'ÉTAIT PAS RENDUE DU TOUT. `hasRunbook` valant
  // faux, le panneau prenait la branche « aucun runbook attaché », y RETOURNAIT, et les étapes servies
  // (lecture indépendante, aboutie) disparaissaient de l'écran avec leur progression.
  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  const recommandationNonEtablie = String(rb.recommandation_non_etablie || '').trim();
  const attacheNonLue = String(rb.runbook_attache_non_lu || (steps && steps.runbook_non_lu) || '').trim();
  // LE MOTIF DU REFUS DE L'ATTACHE, écrit AU PUITS et au MÊME littéral aux deux endroits où il paraît
  // (le survol du bouton inerte, et le clic qui dit son refus) : une phrase passée en argument d'un
  // aide tomberait hors du regard de la garde du lexique, donc hors de l'anglais. Il dit ce que le
  // geste FERAIT, pas seulement qu'il est refusé (grammaire `P11.4-l`).
  const refuserLAttache = (bouton) => {
    bouton.setAttribute('aria-disabled', 'true');
    bouton.title = 'Le runbook attaché à ce dossier n\'a PAS été lu : en attacher un ici, c\'est peut-être poser une SECONDE procédure par-dessus celle que cette lecture n\'a pas pu rendre — le démon refuse l\'attache dès qu\'une étape existe, et ce bouton ne doit pas la promettre.';
    bouton.onclick = () => toast('Le runbook attaché à ce dossier n\'a PAS été lu : en attacher un ici, c\'est peut-être poser une SECONDE procédure par-dessus celle que cette lecture n\'a pas pu rendre — le démon refuse l\'attache dès qu\'une étape existe, et ce bouton ne doit pas la promettre.', 'bad', 9000);
  };
  // L'AVEU DE L'ATTACHE, UNE SEULE RÉDACTION POUR SES TROIS SITES : sous des étapes illisibles, au-dessus
  // du geste d'attache refusé, et EN TÊTE de la checklist à la place du nom de la procédure. La phrase
  // est un nœud texte ENTIER (la seule forme que le lexique sait traduire), la cause SERVIE par le démon
  // est collée dans un SECOND nœud.
  const avouerLAttacheNonLue = (hote) => {
    const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
    const dit = document.createElement('span');
    dit.textContent = 'Runbook attaché à ce dossier NON LU : le démon a refusé et en nomme la cause —';
    aveu.append(dit, ' « ' + attacheNonLue + ' »');
    hote.appendChild(aveu);
  };
  if (recommandationNonEtablie) {
    const { aveu, dit } = boiteDAveuDuRunbook();
    dit.textContent = 'Recommandation de runbook NON ÉTABLIE : le démon a refusé et en nomme la cause —';
    aveu.append(' « ' + recommandationNonEtablie + ' »');
  }
  // --- tactique dominante inférée + runbook recommandé / attach ---
  if (rb.dominant_tactic || rb.dominant_technique) {
    const info = muted('Tactique dominante des alertes liées : ' + (rb.dominant_tactic || '—') + (rb.dominant_technique ? ' (' + rb.dominant_technique + ')' : ''));
    info.style.marginBottom = '6px'; sec.appendChild(info);
  }
  // `P10.7-f` — DES ÉTAPES NON LUES NE SONT NI UN RUNBOOK SANS PROGRESSION, NI UNE PROGRESSION NULLE. Le
  // démon sert, en 200, `{steps: [], progress: null, runbook, error: <cause>}` quand la lecture de
  // `case_step` échoue (`corps_de_liste_illisible`, daemon/src/handlers/incidents.rs, `case_steps_json`) :
  // la forme est intacte, `runbook` vient d'une AUTRE lecture et reste servi. Ce module ne lisait pas
  // `error` et retombait sur `{total: 0, done: 0, skipped: 0}` : la tête écrivait « 0/0 traitées » et la
  // barre se peignait VIDE — deux façons d'affirmer qu'aucune étape n'a été traitée sur un runbook dont
  // l'analyste attend précisément de savoir où il en est. Et sans runbook attaché servi, la branche
  // d'en dessous proposerait d'en ATTACHER un, ce que le démon refuse dès qu'une étape existe.
  // L'AVEU PASSE AVANT LES DEUX : la ligne incident et la tactique dominante, elles, viennent de `rb`
  // (lecture indépendante, aboutie) et restent peintes au-dessus.
  if (steps && steps.error) {
    const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
    const dit = document.createElement('span');
    dit.textContent = 'Étapes du runbook NON LUES : le démon a refusé et en nomme la cause —';
    aveu.append(dit, ' « ' + String(steps.error).trim() + ' »');
    sec.appendChild(aveu);
    // `P10.20-b` (rang 2) — LES DEUX LECTURES PEUVENT MANQUER À LA FOIS, et le démon les sert séparées
    // pour cette raison (`error` parle des ÉTAPES, `runbook_non_lu` de l'EN-TÊTE) : la seconde ne se
    // perd pas dans le retour anticipé de la première.
    if (attacheNonLue) avouerLAttacheNonLue(sec);
    return;
  }
  const hasRunbook = steps.runbook != null;
  // `P10.20-b` (rang 2) — LA CHECKLIST SE REND DÈS QU'IL Y A DES ÉTAPES, MÊME SANS EN-TÊTE ÉTABLI. Sans
  // cette seconde condition, une attache non lue renvoyait l'analyste vers « attacher un runbook » et
  // faisait disparaître les étapes SERVIES avec leur progression.
  const etapesServies = (steps.steps || []).length > 0;
  if (!hasRunbook && !(attacheNonLue && etapesServies)) {
    const pick = document.createElement('div'); pick.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px';
    // L'aveu PRÉCÈDE le geste : un bouton inerte rencontré avant sa raison se lit comme une panne.
    if (attacheNonLue) avouerLAttacheNonLue(pick);
    if (rb.recommended) pick.appendChild(Object.assign(document.createElement('span'), { textContent: 'Recommandé : ' + rb.recommended.name, style: 'font-weight:600' }));
    // Le sélecteur et « Attacher le runbook » ne se présentent PAS sur un catalogue non lu : ils diraient
    // que le choix offert est le choix qui existe. La phrase « aucun runbook disponible » ne s'écrit pas
    // davantage — c'est une absence établie, et rien ne l'a établie.
    if (edit && !rbNonLus.includes('available')) {
      const sel = document.createElement('select');
      // le picker liste custom + managés ACTIFS (les désactivés sont exclus serveur) ; recommandation NIVEAU-TECHNIQUE.
      (rb.available || []).forEach(r => { const o = document.createElement('option'); o.value = String(r.id); o.textContent = r.name + (r.managed ? '' : ' [custom]'); if (rb.recommended && r.id === rb.recommended.id) o.selected = true; sel.appendChild(o); });
      const at = caseBtn('Attacher le runbook', 'primary');
      // `P10.20-b` (rang 2) — LE GESTE RESTE OFFERT, INERTE ET MOTIVÉ (grammaire `P11.4-l`) : le retirer
      // se lirait « ce dossier ne peut pas recevoir de runbook », qui est encore une affirmation que
      // personne n'a établie. Seul ce point-ci peut EMPÊCHER l'appel.
      if (attacheNonLue) refuserLAttache(at);
      else at.onclick = () => withBusy(at, () => attachRunbook(c, Number(sel.value)));
      if (rb.available && rb.available.length) pick.append(sel, at); else pick.appendChild(muted('aucun runbook disponible'));
    }
    sec.appendChild(pick);
    return;
  }
  // --- runbook attaché : progression + checklist phasée ---
  const p = steps.progress || { total: 0, done: 0, skipped: 0 };
  const head = document.createElement('div'); head.style.cssText = 'display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:6px';
  // `P10.20-b` (rang 2) — L'EN-TÊTE PORTE LE NOM DE LA PROCÉDURE, OU DIT QU'IL N'A PAS ÉTÉ LU. Un
  // en-tête vide au-dessus d'une checklist se lit « cette checklist n'a pas de procédure », et c'est
  // exactement ce que la lecture ratée n'a PAS établi.
  if (hasRunbook) head.appendChild(Object.assign(document.createElement('span'), { textContent: steps.runbook.name, style: 'font-weight:600' }));
  else avouerLAttacheNonLue(head);
  head.appendChild(muted((p.done + p.skipped) + '/' + p.total + ' traitées'));
  // barre de progression (done + skipped comptent comme traité ; done en accent).
  const bar = document.createElement('div'); bar.style.cssText = 'flex:1;min-width:120px;height:8px;border-radius:6px;background:var(--bd);overflow:hidden;display:flex';
  const pctDone = p.total ? Math.round(100 * p.done / p.total) : 0;
  const pctSkip = p.total ? Math.round(100 * p.skipped / p.total) : 0;
  const seg1 = document.createElement('div'); seg1.style.cssText = 'height:100%;width:' + pctDone + '%;background:var(--acc)';
  const seg2 = document.createElement('div'); seg2.style.cssText = 'height:100%;width:' + pctSkip + '%;background:var(--mut)';
  bar.append(seg1, seg2); head.appendChild(bar); sec.appendChild(head);
  // groupement par phase (l'ordre serveur = ordinal ; on garde l'ordre d'apparition des phases).
  const byPhase = [];
  (steps.steps || []).forEach(s => { let g = byPhase.find(x => x.phase === s.phase); if (!g) { g = { phase: s.phase, items: [] }; byPhase.push(g); } g.items.push(s); });
  byPhase.forEach(g => {
    sec.appendChild(Object.assign(document.createElement('div'), { textContent: (PHASE_LABEL[g.phase] || g.phase).toUpperCase(), style: 'font-size:11px;font-weight:700;color:var(--mut);margin:8px 0 2px' }));
    g.items.forEach(s => sec.appendChild(stepEl(c, s, edit)));
  });
}

function stepEl(c, s, edit) {
  const el = document.createElement('div'); el.style.cssText = 'display:flex;gap:8px;align-items:flex-start;padding:5px 0;border-bottom:1px solid color-mix(in srgb,var(--bd) 50%,transparent)';
  const mark = document.createElement('span'); mark.textContent = STEP_MARK[s.status] || '○';
  mark.style.cssText = 'font-weight:700;min-width:14px;' + (s.status === 'done' ? 'color:var(--acc)' : s.status === 'skipped' ? 'color:var(--mut)' : '');
  el.appendChild(mark);
  const body = document.createElement('div'); body.style.cssText = 'flex:1;min-width:0';
  const title = document.createElement('div'); title.textContent = s.title; title.style.cssText = 'font-weight:600;font-size:13px' + (s.status !== 'pending' ? ';opacity:.7' : '');
  body.appendChild(title);
  if (s.guidance) body.appendChild(Object.assign(document.createElement('div'), { textContent: s.guidance, style: 'font-size:12px;color:var(--mut)' }));
  if (s.status !== 'pending' && s.actor) body.appendChild(muted((s.status === 'done' ? 'fait' : 'ignoré') + ' par ' + s.actor + (s.ts ? ' · ' + fmtTs(s.ts) : '') + (s.note ? ' — ' + s.note : '')));
  // actions par step.
  const acts = document.createElement('div'); acts.style.cssText = 'display:flex;gap:6px;flex-wrap:wrap;margin-top:4px';
  if (s.step_kind === 'search' && s.search_soql) {
    const rs = caseBtn('Lancer la recherche', 'ghost'); rs.onclick = () => runStepSearch(c, s); acts.appendChild(rs);
  }
  if (s.step_kind === 'response' && s.action_kind) {
    if (socIsAdmin()) {
      const rp = caseBtn('Réponse : ' + s.action_kind + ' ▸', 'ghost'); rp.title = 'Prépare l\'action via /api/actions (approbation + ledger)'; rp.onclick = () => prepareResponse(c, s); acts.appendChild(rp);
    } else {
      acts.appendChild(muted('réponse ' + s.action_kind + ' — nécessite un admin (arm/approbation)'));
    }
  }
  if (edit && s.status === 'pending') {
    const done = caseBtn('Faite', 'ghost'); done.onclick = () => withBusy(done, () => advanceStep(c, s, 'done', null)); acts.appendChild(done);
    const skip = caseBtn('Ignorer…', 'ghost'); skip.onclick = () => skipStep(c, s); acts.appendChild(skip);
  } else if (edit && s.status !== 'pending') {
    const undo = caseBtn('Rouvrir', 'ghost'); undo.onclick = () => withBusy(undo, () => advanceStep(c, s, 'pending', null)); acts.appendChild(undo);
  }
  if (acts.childNodes.length) body.appendChild(acts);
  el.appendChild(body);
  return el;
}

async function incidentDeclare(c) {
  const r = await modal({ title: 'Déclarer un incident', okText: 'Déclarer', fields: [
    { name: 'tier', label: 'Tier (1=critique … 4=bas)', type: 'select', value: '1', options: [{ value: '1', label: 'Tier 1 (critique)' }, { value: '2', label: 'Tier 2' }, { value: '3', label: 'Tier 3' }, { value: '4', label: 'Tier 4 (bas)' }] },
    { name: 'incident_type', label: 'Type (optionnel)', value: '' },
    { name: 'commander', label: 'Pilote / commander (optionnel)', value: '' },
  ] });
  if (!r) return;
  try { await apiSend('/cases/' + c.id + '/incident', 'POST', { tier: Number(r.tier) || 1, incident_type: (r.incident_type || '').trim(), commander: (r.commander || '').trim() }); }
  catch (e) { toast('Élévation refusée : ' + ((e && e.message) || e), 'bad'); return; }
  toast('Incident déclaré', 'ok'); await refreshCaseDetail(c.id);
}

async function incidentDemote(c) {
  if (!await confirmModal('Rétrograder l\'incident #' + c.id + ' en case ordinaire ?', { okText: 'Rétrograder', danger: false })) return;
  try { await apiSend('/cases/' + c.id + '/incident', 'POST', { demote: true }); }
  catch (e) { toast('Rétrogradation refusée : ' + ((e && e.message) || e), 'bad'); return; }
  toast('Incident rétrogradé', 'ok'); await refreshCaseDetail(c.id);
}

async function attachRunbook(c, runbookId) {
  if (!runbookId) return;
  try { await apiSend('/cases/' + c.id + '/runbook', 'POST', { runbook_id: runbookId }); }
  catch (e) { toast('Attachement refusé : ' + ((e && e.message) || e), 'bad'); return; }
  toast('Runbook attaché', 'ok'); await refreshCaseDetail(c.id);
}

async function advanceStep(c, s, status, note) {
  try { await apiSend('/cases/' + c.id + '/steps/' + s.id, 'POST', note ? { status, note } : { status }); }
  catch (e) { toast('Étape refusée : ' + ((e && e.message) || e), 'bad'); return; }
  await refreshCaseDetail(c.id);
}

async function skipStep(c, s) {
  const r = await modal({ title: 'Ignorer l\'étape', okText: 'Ignorer', fields: [{ name: 'note', label: 'Raison (auditée)', value: '' }] });
  if (!r) return;
  await advanceStep(c, s, 'skipped', (r.note || '').trim());
}

// « Lancer la recherche » : résout le GXQL de la step (recompilé côté serveur), demande une cible si aucune
// n'est pré-remplie, puis ouvre l'Explore (chemin de recherche existant). Aucune exécution d'action.
async function runStepSearch(c, s) {
  let path = '/cases/' + c.id + '/steps/' + s.id + '/search';
  if (!s.target) {
    const r = await modal({ title: 'Cible de la recherche', okText: 'Rechercher', fields: [{ name: 'value', label: 'Valeur ($target$)', value: '' }] });
    if (!r || !(r.value || '').trim()) return;
    path += '?value=' + encodeURIComponent(r.value.trim());
  }
  let j;
  try { j = await api(path); } catch (e) { toast('Recherche refusée : ' + ((e && e.message) || e), 'bad'); return; }
  if (!j || !j.soql) { toast('GXQL indisponible', 'bad'); return; }
  location.hash = 'explore';
  if ($('#sql')) { $('#sql').value = j.soql; runQuery(); }
}

// =================================================================================================
// `P10.20-y` — LA TROISIÈME SURFACE QUI MET UNE RIPOSTE EN FILE LIT SON REFUS COMME LES DEUX AUTRES.
//
// CE QUE LE DÉMON SERT. `action_create` (daemon/src/handlers/actions.rs) refuse de DEUX façons, et
// elles n'arrivent pas par le même chemin : la ligne qui n'a pas pu être écrite part en 503 nommé
// (`CAUSE_RIPOSTE_NON_MISE_EN_FILE`), qu'`apiSend` transforme en REJET ; une saisie que `action_valid`
// écarte part, elle, en 200 avec un corps `{error}`, qui se lit donc dans le corps. Les deux existent,
// et l'une ne couvre pas l'autre.
//
// CE QUE CETTE ÉTAPE EN FAISAIT. Le rejet était bien capté, mais peint par `e.message` : le message
// composé par `apiSend` est « <code> <corps coupé à deux cents caractères> », donc l'exploitant lisait
// « Action refusée : 503 {"error":"RIPOSTE NON MISE EN FILE …","id":"plume-e2-0"} » — de la syntaxe, un
// identifiant d'incident, et une phrase tronquée en son milieu. C'est le défaut que `P10.20-k` a fermé
// ailleurs, et la phrase existe déjà au point commun : elle est LUE, pas réécrite.
//
// L'AVEU PART À L'AVIS, ET C'EST MESURÉ. Cette étape n'a aucun puits ouvert où poser deux nœuds : la
// modale de saisie s'est refermée en rendant ses valeurs, et la ligne de l'étape est sur le point
// d'être redessinée par la relecture du dossier. C'est le même repli que le geste « bannir » d'une
// ligne de résultats (`web/viz.js`), avec la même phrase et la même fabrique.
// =================================================================================================

// L'IDENTIFIANT N'EST PEINT QUE QUAND LE DÉMON EN SERT UN. `apiSend` rend `null` sur un corps vide ou
// illisible, et la concaténation d'avant écrivait alors « Action mise en file (#null) » : un numéro
// qu'aucune ligne ne porte, que l'analyste ira chercher dans l'onglet Réponse. Le refus de la clé
// `P10.20-t` vient précisément de là — le démon rendait l'identifiant d'une AUTRE ligne —, et une
// console qui invente le sien referait le défaut d'un cran plus loin.
const MOTS_DE_LA_RIPOSTE_MISE_EN_FILE = {
  identifiant_servi: {
    fr: 'Action mise en file (#{identifiant}) — approbation requise',
    en: 'Action queued (#{identifiant}) — approval required' },
  identifiant_absent: {
    fr: "Action mise en file — approbation requise. Le démon n'a rendu AUCUN identifiant : cette riposte ne peut pas être désignée par un numéro, elle se retrouve dans l'onglet Réponse par son geste et sa cible.",
    en: 'Action queued — approval required. The daemon returned NO identifier: this response cannot be designated by a number, it is found in the Response tab by its gesture and target.' },
};
function motDeLaRiposteMiseEnFile(j) {
  const identifiant = j && j.id;
  const mots = MOTS_DE_LA_RIPOSTE_MISE_EN_FILE[identifiant ? 'identifiant_servi' : 'identifiant_absent'];
  return (LANG === 'en' ? mots.en : mots.fr).replace('{identifiant}', String(identifiant));
}

// `P10.20-v`, lu ici sous `P10.20-y` — LE GESTE A EU LIEU, ET SA TRACE MANQUE : LES DEUX SE DISENT.
//
// CE QUE LE DÉMON SERT. Depuis que `ledger_append` (daemon/src/ledger.rs) rend l'issue de son écriture
// au lieu de l'avaler, `action_create` pose la riposte, constate que le registre tamper-evident n'a pas
// pris la ligne `action.queued`, et le DIT dans son corps de SUCCÈS sous la clé partagée
// `registre_sans_maillon` — l'identifiant reste servi, parce que la ligne de riposte, elle, existe.
// Refuser serait faux ; se taire laisserait un geste de riposte hors de la trace non purgeable.
//
// POURQUOI L'AVEU N'EST PAS UN AVIS ICI. Un avis s'efface, et celui-ci demande une action humaine que
// le démon nomme lui-même : faire vérifier le journal d'intégrité. Il est donc posé DANS le dossier,
// après sa relecture — la relecture remplace les enfants de l'hôte, un aveu posé avant partirait avec
// eux. Il y reste jusqu'au dessin suivant. Quand ce dossier n'est pas à l'écran — la relecture ne
// redessine que le dossier SÉLECTIONNÉ —, il n'y a aucun puits et l'aveu part à l'avis : c'est le repli
// déjà livré pour un aveu sans hôte, pas une seconde grammaire.
//
// CE QUE CET AVEU NE COUVRAIT PAS, ET QUI EST FERMÉ PAR `P10.21-a` : les deux AUTRES surfaces qui
// mettent une riposte en file par la même route (le formulaire du panneau Réponse et le geste
// « bannir » d'une ligne de résultats) recevaient la même clé et la laissaient tomber. Le lecteur
// n'avait alors qu'UN usage et serait parti de cet usage ; il en a trois, il vit donc au point commun
// (`web/core.js`) — la clé nommée une fois, la phrase écrite une fois, la fabrique du nœud une fois.
// CE QUI RESTE ICI est ce qui appartient à CETTE surface : le PUITS où l'aveu se pose, et le moment.
function avouerLaTraceManquante(cause) {
  const hote = $('#case-detail');
  if (!hote) { toast(phraseDeLaTraceManquante(cause), 'bad', 9000); return; }
  const aveu = aveuDeLaTraceManquante(cause);
  aveu.style.cssText = 'margin:6px 0;font-size:12px';   // le style appartient au site, pas au point commun
  hote.append(aveu);
}

// Step 'response' : PRÉPARE l'action existante. Ouvre un modal (kind figé + cible éditable + dry-run) et POST
// vers /api/actions EXISTANT — admin-gated, arm/approbation/ledger/allowlist root INCHANGÉS. AUCUN auto-exec :
// l'action est créée en 'pending' et reste soumise à approbation (console actions). La step peut être marquée
// « faite » séparément (traçabilité). Le wizard ne fait que RÉFÉRENCER l'action.
async function prepareResponse(c, s) {
  const r = await modal({ title: 'Préparer la réponse : ' + s.action_kind, okText: 'Mettre en file', fields: [
    { name: 'target', label: 'Cible (' + s.action_kind + ')', value: s.target || '' },
    { name: 'dry_run', label: 'Simulation (dry-run)', type: 'select', value: '1', options: [{ value: '1', label: 'Oui (dry-run)' }, { value: '0', label: 'Non (réel, requiert approbation)' }] },
  ] });
  if (!r || !(r.target || '').trim()) return;
  let j;
  try { j = await apiSend('/actions', 'POST', { kind: s.action_kind, target: r.target.trim(), dry_run: r.dry_run === '1', reason: 'runbook step #' + s.id + ' (case #' + c.id + ')' }); }
  catch (e) { toast(phraseDeLaCreationDeRiposteRefusee(e), 'bad', 9000); return; }
  // `action_valid` (daemon/src/handlers/actions.rs) refuse la SAISIE par un corps `{error}` servi en 200 :
  // ce chemin-là, contrairement au 503, n'est pas un rejet et il faut le lire dans le corps. La cause est
  // passée au lecteur commun sous le nom qu'il attend, pour que les deux refus rendent la même grammaire.
  if (j && j.error) { toast(phraseDeLaCreationDeRiposteRefusee({ causeDuDemon: String(j.error).trim() }), 'bad', 9000); return; }
  toast(motDeLaRiposteMiseEnFile(j), j && j.id ? 'ok' : 'info');
  await refreshCaseDetail(c.id);
  // APRÈS la relecture : elle remplace les enfants de l'hôte, et l'aveu posé avant partirait avec eux.
  // La clé est lue par le lecteur commun (`P10.21-a`) : son nom n'est plus écrit dans cette vue.
  const sansMaillon = causeDeLaTraceManquante(j);
  if (sansMaillon) avouerLaTraceManquante(sansMaillon);
}

// caseBtn : rendu pur, jugé par le harnais ESM (P11.4-b). caseRow / renderCaseDetail : rendus purs eux
// aussi, jugés par le témoin 21 (P11.11-a) — dépli d'une ligne et raison d'un état inerte.
// `loadCaseOpsSummary` est exporté pour la même raison que `renderResults` de datamodels.js : le refus
// du démon sur les deux routes du bandeau ne se prouve qu'en le RENDANT.
// `renderWizardPanel` est exposé pour le harnais ESM (témoin 94 : l'aveu de lecture des étapes, rendu par SA
// fabrique réelle et non par une copie) ; aucun usage applicatif hors de ce module.
// `renderCaseLinks` et `linkCasePrompt` sont exposés pour le harnais ESM (témoin 95 : l'aveu de lecture des
// liens et le refus du geste qui en ajouterait un, rendus par LEUR fabrique réelle) ; aucun usage applicatif
// hors de ce module.
// `P10.20-p` — `caseItemEl` est exposé pour le harnais ESM (témoin 100) : « cible NON LUE » et « cible
// introuvable » ne se distinguent qu'en RENDANT les deux éléments par LEUR fabrique réelle, sur la même
// référence. Aucun usage applicatif hors de ce module.
// `P10.20-y` — `prepareResponse`, `motDeLaRiposteMiseEnFile` et `motDeLaTraceManquante` partent pour le harnais ESM (témoin 102) :
// le refus de mise en file d'une étape de runbook ne se mesure qu'en JOUANT le geste — la modale, l'envoi,
// l'avis —, et l'identifiant peint ou tu ne se juge que sur la fonction qui décide. Aucun usage applicatif
// hors de ce module. `P10.21-a` : `motDeLaTraceManquante` vient désormais du point commun et n'est plus
// que RÉÉMIS ici — le témoin qui l'y lisait mesure ainsi la phrase que cette surface rend VRAIMENT, et il
// rougirait si elle cessait de venir du lecteur partagé.
// `P10.21-a` — `motDuGenreDeLien` part nu (témoin 103) : le vocabulaire des liens de dossier se juge dans
// les DEUX sens — les trois valeurs que le démon écrit, et le jeton qu'aucune allowlist ne produit plus.
export { OUVERTURE_DU_DOSSIER_NON_OUVERT, OUVERTURE_DU_LIEN_NON_POSE, OUVERTURE_DU_LIEN_NON_RETIRE, cleDuRefusDeDossier, motDuRefusDeDossier, phraseDuRefusDeDossier, addToCase, canEditCases, caseBtn, caseItemEl, caseRow, createCase, linkCasePrompt, loadCaseOpsSummary, loadCases, motDeLaRiposteMiseEnFile, motDeLaTraceManquante, motDuGenreDeLien, openCase, prepareResponse, renderCaseDetail, renderCaseLinks, renderWizardPanel };

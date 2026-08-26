// cases.js — extracted from app.js (DEEP state-container split). Behaviour-preserving.
// Cases (gestion d'incident, first-class #4a): liste/detail/CRUD + rattachement d'items.
import { $, api, apiSend, confirmModal, confirmWithConsequence, disclosure, downloadText, exportPDF, fmtTs, ic, modal, muted, pagedList, sev, toCSV, toast, tsSlug, withBusy, socIsAdmin, socRole } from './core.js';
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

// badges color-codés (textContent -> pas d'injection ; couleur en inline-style car style.css n'est pas édité).
// P11.11-a — le cadre d'état DIT pourquoi il est terne : `closed` est gris par palette et la ligne d'un cas
// terminé est estompée, ce qui se lit comme un contrôle désactivé alors que rien ne l'est. L'infobulle
// tranche entre les deux lectures : inerte PAR NATURE (le cas est terminé) ou encore modifiable.
function caseStatusBadge(status) {
  const s = document.createElement('span'); s.className = 'casest'; const col = CASE_STATUS_COL[status] || 'var(--mut)';
  s.style.color = col; s.style.borderColor = 'color-mix(in srgb,' + col + ' 45%,transparent)';
  if (CASE_TERMINAL.has(status)) s.title = 'Cas terminé : son état n\'évolue plus tant qu\'il n\'est pas rouvert';
  else s.title = 'Cas en cours : son état peut encore changer';
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

async function loadCases() {
  const wrap = $('#cases-list'); if (!wrap) return;
  const nb = $('#case-new'); if (nb) nb.style.display = canEditCases() ? '' : 'none';   // + Case : editor/admin
  // BATCH 1 : pagination + tri SERVEUR (filtres status/assignee/priority/overdue/archived PRÉSERVÉS). Le tri
  // (#case-sort) est replié serveur (caseSortRows reste un repli client idempotent sur la page renvoyée).
  S.casePager = pagedList(wrap, {
    mode: 'server',
    pageSize: 50,
    renderRow: caseRow,
    emptyText: 'aucun case',
    fetchPage: async ({ limit, offset }) => {
      const base = caseFilterQuery();                 // '' | '?status=...'
      const sortSel = $('#case-sort') ? $('#case-sort').value : '';
      let url = '/cases' + base + (base ? '&' : '?') + 'limit=' + limit + '&offset=' + offset;
      if (sortSel) url += '&sort=' + encodeURIComponent(sortSel);
      const j = await api(url);   // erreur -> pagedList/loadServer affiche « erreur : … »
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
      stLab.appendChild(muted('Inerte par nature : un cas terminé ne change plus d\'état. « Rouvrir » le ramène en cours.'));
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

function caseItemEl(caseId, it, edit) {
  const el = document.createElement('div'); el.className = 'caseitem k-' + (it.kind || 'note');
  el.appendChild(Object.assign(document.createElement('time'), { textContent: fmtTs(it.ts) }));
  el.appendChild(Object.assign(document.createElement('span'), { className: 'who', textContent: it.author || '—' }));
  el.appendChild(Object.assign(document.createElement('span'), { className: 'kind', textContent: CASE_KIND[it.kind] || it.kind }));
  const body = document.createElement('span'); body.className = 'body';
  if (it.ref) {
    const chip = document.createElement('span'); chip.className = 'casechip';
    chip.textContent = it.ref_title ? (it.ref + ' · ' + it.ref_title) : it.ref;
    chip.title = it.ref_title || '(cible introuvable — supprimée ou expirée)';
    if (!it.ref_title) chip.style.opacity = '.7';
    if (it.ref_severity != null) chip.title += ' — ' + sev(it.ref_severity);
    body.appendChild(chip);
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
async function loadCaseOpsSummary() {
  const host = $('#caseops-summary'); if (!host) return;
  let queues = [], metrics = {};
  try { ({ queues } = await api('/cases/queues')); } catch (e) {}
  try { metrics = await api('/cases/metrics'); } catch (e) {}
  host.replaceChildren();
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
    queues.slice(0, 12).forEach(q => {
      const chip = document.createElement('button'); chip.type = 'button'; chip.className = 'casechip'; chip.style.cursor = 'pointer';
      chip.textContent = q.assignee + ' · ' + q.open + (q.overdue ? ' (' + q.overdue + ' retard)' : '') + (q.breach ? ' ⚠' + q.breach : '');
      chip.title = 'Filtrer la file de ' + q.assignee;
      chip.onclick = () => { const inp = $('#case-assignee-filter'); if (inp && q.assignee !== '(none)') { inp.value = q.assignee; loadCases(); } };
      qwrap.appendChild(chip);
    });
    host.appendChild(qwrap);
  }
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
  let links = [];
  try { ({ links } = await api('/cases/' + c.id + '/links')); } catch (e) {}
  if (links && links.length) {
    sec.appendChild(Object.assign(document.createElement('div'), { className: 'casesec', textContent: 'Liens' }));
    const wrap = document.createElement('div'); wrap.style.cssText = 'display:flex;flex-wrap:wrap;gap:6px';
    links.forEach(l => {
      const chip = document.createElement('span'); chip.className = 'casechip'; chip.style.cursor = 'pointer';
      chip.textContent = '#' + l.id + ' (' + l.kind + ') · ' + l.title; chip.title = l.note || '';
      chip.onclick = () => showCaseDetail(l.id);
      if (canEditCases()) {
        const x = document.createElement('button'); x.type = 'button'; x.className = 'casebtn'; x.title = 'Retirer le lien'; x.style.marginLeft = '4px'; x.innerHTML = ic('x');
        x.onclick = e => { e.stopPropagation(); withBusy(x, async () => { if (!await confirmWithConsequence(`Retirer le lien vers #${l.id}`, 'les deux cas ne seront plus rattachés ; le lien se recrée à la main, sans son historique.', { okText: 'Retirer', danger: true })) return; try { await apiSend('/cases/' + c.id + '/links/' + l.id, 'DELETE'); } catch (err) { toast('Retrait refusé : ' + ((err && err.message) || err), 'bad'); return; } toast('Lien retiré', 'ok'); refreshCaseDetail(c.id); }); };
        chip.appendChild(x);
      }
      wrap.appendChild(chip);
    });
    sec.appendChild(wrap);
  }
  if (sec.childNodes.length) box.appendChild(sec);
}

// #39 — FUSION (soft) : fusionne le case courant DANS une cible choisie (le courant est clos + rattaché ;
// timeline combinée dans la cible ; réversible). editor+.
async function mergeCasePrompt(id) {
  let cases = [];
  try { ({ cases } = await api('/cases?limit=200')); } catch (e) {}
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
  let cases = [];
  try { ({ cases } = await api('/cases?limit=200')); } catch (e) {}
  const opts = (cases || []).filter(c => c.id !== id).map(c => ({ value: String(c.id), label: '#' + c.id + ' · ' + c.title }));
  if (!opts.length) { toast('Aucune autre case à lier', 'bad'); return; }
  const r = await modal({ title: 'Lier le case #' + id, okText: 'Lier', fields: [
    { name: 'to', label: 'Case à lier', type: 'select', options: opts },
    { name: 'kind', label: 'Type de lien', type: 'select', value: 'related', options: [
      { value: 'related', label: 'Relié' }, { value: 'duplicate', label: 'Doublon' }, { value: 'blocks', label: 'Bloque' }] },
    { name: 'note', label: 'Note (optionnel)' },
  ] });
  if (!r) return;
  try { await apiSend('/cases/' + id + '/links', 'POST', { to: Number(r.to), kind: r.kind, note: r.note || '' }); }
  catch (e) { toast('Lien refusé : ' + ((e && e.message) || e), 'bad'); return; }
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
  const j = await apiSend('/cases', 'POST', body);
  await loadCases();
  if (j.id) showCaseDetail(j.id);
}

// ajoute un element (alerte/event) a un case existant OU nouveau. ref facultative (event depuis l'Explore =
// sans id -> item 'event' libre ; alerte -> ref='alert:ID').
async function addToCase(kind, body, ref) {
  let cases = [];
  try { ({ cases } = await api('/cases')); } catch (e) {}
  const active = (cases || []).filter(c => !CASE_TERMINAL.has(c.status));   // le daemon écrit 'new' (plus 'open' legacy)
  const opts = [{ value: 'new', label: '+ Nouveau case' }, ...active.map(c => ({ value: String(c.id), label: '#' + c.id + ' · ' + c.title }))];
  const r = await modal({ title: 'Ajouter à un case', okText: 'Ajouter', fields: [
    { name: 'cid', label: 'Case', type: 'select', value: active[0] ? String(active[0].id) : 'new', options: opts },
    { name: 'newtitle', label: 'Titre (si nouveau case)', value: String(body).slice(0, 80) },
  ] });
  if (!r) return;
  let id = r.cid;
  if (id === 'new') {
    const j = await apiSend('/cases', 'POST', { title: (r.newtitle || body).trim() || 'Incident', severity: 2 });
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
  // --- tactique dominante inférée + runbook recommandé / attach ---
  if (rb.dominant_tactic || rb.dominant_technique) {
    const info = muted('Tactique dominante des alertes liées : ' + (rb.dominant_tactic || '—') + (rb.dominant_technique ? ' (' + rb.dominant_technique + ')' : ''));
    info.style.marginBottom = '6px'; sec.appendChild(info);
  }
  const hasRunbook = steps.runbook != null;
  if (!hasRunbook) {
    const pick = document.createElement('div'); pick.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px';
    if (rb.recommended) pick.appendChild(Object.assign(document.createElement('span'), { textContent: 'Recommandé : ' + rb.recommended.name, style: 'font-weight:600' }));
    if (edit) {
      const sel = document.createElement('select');
      // le picker liste custom + managés ACTIFS (les désactivés sont exclus serveur) ; recommandation NIVEAU-TECHNIQUE.
      (rb.available || []).forEach(r => { const o = document.createElement('option'); o.value = String(r.id); o.textContent = r.name + (r.managed ? '' : ' [custom]'); if (rb.recommended && r.id === rb.recommended.id) o.selected = true; sel.appendChild(o); });
      const at = caseBtn('Attacher le runbook', 'primary');
      at.onclick = () => withBusy(at, () => attachRunbook(c, Number(sel.value)));
      if (rb.available && rb.available.length) pick.append(sel, at); else pick.appendChild(muted('aucun runbook disponible'));
    }
    sec.appendChild(pick);
    return;
  }
  // --- runbook attaché : progression + checklist phasée ---
  const p = steps.progress || { total: 0, done: 0, skipped: 0 };
  const head = document.createElement('div'); head.style.cssText = 'display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:6px';
  head.appendChild(Object.assign(document.createElement('span'), { textContent: steps.runbook.name, style: 'font-weight:600' }));
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
  catch (e) { toast('Action refusée : ' + ((e && e.message) || e), 'bad'); return; }
  if (j && j.error) { toast('Action refusée : ' + j.error, 'bad'); return; }
  toast('Action mise en file (#' + (j && j.id) + ') — approbation requise', 'ok');
  await refreshCaseDetail(c.id);
}

// caseBtn : rendu pur, jugé par le harnais ESM (P11.4-b). caseRow / renderCaseDetail : rendus purs eux
// aussi, jugés par le témoin 21 (P11.11-a) — dépli d'une ligne et raison d'un état inerte.
export { addToCase, canEditCases, caseBtn, caseRow, createCase, loadCases, openCase, renderCaseDetail };

// runbooks.js — #3 INCIDENTS Phase 2 : AUTHORING de runbooks (bring-your-own), ADMIN-only.
// Surface d'édition des GABARITS de runbook : liste (managés vs custom, état activé), création/édition d'un
// runbook CUSTOM (nom, clé MITRE tactic/technique, étapes phasées avec guidance, step_kind manual|search|
// response, le GXQL des étapes 'search', l'action_kind des étapes 'response'), clone d'un managé, (dés)activation,
// suppression d'un custom. Le SERVEUR est la vraie garde (route /api/runbooks* = admin-only ; validation temps-
// auteur du GXQL fermé + enum d'action) ; ici l'admin-only n'est que COSMÉTIQUE (panneau masqué au non-admin).
// L'exécution d'une réponse reste /api/actions (INCHANGÉ) — un runbook ne fait que RÉFÉRENCER une action.
//
// P11.2-a : la ligne d'un runbook passe par la MÊME fabrique que celle d'un playbook ou d'une règle
// (`producer_ui.js`) — mêmes classes `.rulerow`, même interrupteur ON/OFF, même badge d'origine, mêmes
// classes de bouton. Les étapes d'un runbook LIVRÉ se lisent (« Étapes ») sans passer par l'éditeur, qui
// reste réservé aux custom. L'éditeur utilise `.ruleform/.rf-row/.rf-actions` comme le formulaire des
// playbooks : aucun style en ligne, aucune classe sans règle CSS.
import { $, api, apiSend, confirmModal, modal, muted, toast, socIsAdmin, gateDeleteBtn, ic } from './core.js';
import { producerRow, rowButton, announceCreated, takePendingNote, destinationNote } from './producer_ui.js';

const RB_PHASES = ['triage', 'investigation', 'containment', 'eradication', 'recovery'];
const RB_KINDS = ['manual', 'search', 'response'];
const RB_ACTIONS = ['ban_ip', 'unban_ip', 'kill_pid', 'stop_service'];
const RB_TACTICS = ['reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'];
const PHASE_LABEL = { triage: 'Triage', investigation: 'Investigation', containment: 'Containment', eradication: 'Éradication', recovery: 'Rétablissement' };

function mkSelect(opts, val) {
  const s = document.createElement('select');
  opts.forEach(o => { const e = document.createElement('option'); e.value = o; e.textContent = o; if (o === val) e.selected = true; s.appendChild(e); });
  return s;
}
function mkInput(ph, val) { const i = document.createElement('input'); i.placeholder = ph || ''; i.value = val || ''; return i; }
function mkLabel(text, ctl) { const l = document.createElement('label'); l.appendChild(document.createTextNode(text + ' ')); l.appendChild(ctl); return l; }

async function loadRunbooks() {
  const panel = $('#runbooks-panel');
  const wrap = $('#rb-list');
  if (!wrap) return;
  // ADMIN-only COSMÉTIQUE — la vraie garde est serveur (403). Un non-admin ne voit pas l'authoring.
  if (!socIsAdmin()) { if (panel) panel.style.display = 'none'; return; }
  if (panel) panel.style.display = '';
  let runbooks = [];
  try { ({ runbooks } = await api('/runbooks')); } catch (e) { wrap.replaceChildren(muted('runbooks indisponibles')); return; }
  wrap.replaceChildren();
  const note = takePendingNote('runbooks'); if (note) wrap.appendChild(note); // P11.1-e : où arrive ce qui vient d'être créé
  if (!runbooks.length) { wrap.appendChild(muted('aucun runbook')); return; }
  runbooks.forEach(r => wrap.appendChild(rbRow(r)));
}

// Origine d'un runbook dans la convention PARTAGÉE des badges (0 builtin / 1 overlay / 2 perso) : la table
// `runbook` code le seed `managed=1` et le custom `managed=0`, à l'INVERSE de `rule`/`playbook` (seed=0,
// perso=2). La normalisation se fait ici, à la frontière, pour qu'une seule fabrique de ligne serve tout.
function runbookOrigin(r) { return r.managed ? 0 : 2; }

// Modèle de ligne d'un runbook : la MÊME forme que playbookRowModel / ruleRowModel (`producer_ui.js`).
// Conséquence de l'interrupteur : être PROPOSÉ dans les cas (rien d'automatique — une étape `response` ne
// fait que préparer une action soumise à approbation) ; donc pas de confirmation à l'activation.
function runbookRowModel(r) {
  return {
    family: 'runbook', name: r.name, origin: runbookOrigin(r), enabled: !!r.active,
    consequence: 'proposé dans un cas élevé en incident ' + (r.match_kind === '*' ? 'quand aucun runbook plus spécifique ne s\'applique' : 'dont la ' + (r.match_kind === 'tactic' ? 'tactique' : 'technique') + ' dominante est ' + r.match_key) + ' ; rien d\'automatique (une étape response prépare une action soumise à approbation)',
    toggleAllowed: socIsAdmin(), toggleDeniedReason: "l'activation/désactivation d'un runbook est réservée à l'administrateur",
    confirmOnEnable: false,
    // override d'activation — persiste, survit au reboot ; managé compris.
    onToggle: next => apiSend('/runbooks/' + r.id + '/enabled', 'POST', { enabled: next }),
    summary: r.match_kind === '*' ? 'défaut' : r.match_kind + ':' + r.match_key,
    summaryTitle: r.description || '',
    meta: r.steps + ' étape(s)',
  };
}
function rbRow(r) {
  const row = producerRow(runbookRowModel(r));
  const meta = row.metaEl;
  // Étapes : lecture seule, pour TOUS (un livré n'ouvrait aucune vue de ses étapes — « ni les étapes »).
  row.appendChild(rowButton('Étapes', { title: 'Voir les étapes phasées (lecture seule)', onClick: () => toggleSteps(row, r.id, meta) }));
  // clone (managé OU custom -> copie custom éditable).
  row.appendChild(rowButton('Cloner', { title: 'Copie custom éditable', onClick: async () => {
    const m = await modal({ title: 'Cloner le runbook', okText: 'Cloner', fields: [{ name: 'name', label: 'Nom de la copie', value: r.name + ' (copie)' }] });
    if (!m) return;
    try { await apiSend('/runbooks/' + r.id + '/clone', 'POST', { name: (m.name || '').trim() }); } catch (e) { toast('Clone refusé : ' + ((e && e.message) || e), 'bad'); return; }
    toast('Runbook cloné', 'ok'); loadRunbooks();
  } }));
  // édition / suppression : CUSTOM uniquement (un managé est immuable en place — seuls enable/disable + clone).
  const locked = !!r.managed;
  row.appendChild(rowButton('Éditer', { cls: 'crud-btn', disabled: locked, title: locked ? 'runbook livré (baseline git) : immuable en place — clonez pour éditer' : 'Modifier', onClick: locked ? null : () => openEditor(r.id) }));
  const del = rowButton('', { cls: 'crud-btn', icon: ic('x'), title: 'Supprimer' });
  if (gateDeleteBtn(del, locked ? 0 : 2)) del.onclick = async () => {
    if (!await confirmModal('Supprimer le runbook custom « ' + r.name + ' » ?', { danger: true })) return;
    try { await apiSend('/runbooks/' + r.id, 'DELETE'); } catch (e) { toast('Suppression refusée : ' + ((e && e.message) || e), 'bad'); return; }
    toast('Runbook supprimé', 'ok'); loadRunbooks();
  };
  row.appendChild(del);
  return row;
}

// Vue LECTURE SEULE des étapes d'un runbook (livré ou custom), dépliée sous sa ligne. Second clic : replie.
async function toggleSteps(row, id, meta) {
  if (row.stepsEl) { row.stepsEl.remove(); row.stepsEl = null; return; }
  let data;
  try { data = await api('/runbooks/' + id); } catch (e) { meta.textContent = 'étapes indisponibles'; return; }
  const box = document.createElement('div'); box.className = 'rb-steps';
  box.style.cssText = 'flex-basis:100%;padding:4px 0 4px 28px';
  if (data.description) box.appendChild(muted(data.description));
  let lastPhase = null;
  (data.step_list || []).forEach(s => {
    if (s.phase !== lastPhase) { lastPhase = s.phase; const h = document.createElement('div'); h.className = 'muted'; h.style.cssText = 'font-size:11px;font-weight:700;margin-top:6px'; h.textContent = (PHASE_LABEL[s.phase] || s.phase).toUpperCase(); box.appendChild(h); }
    const line = document.createElement('div'); line.style.cssText = 'font-size:12px;padding:2px 0';
    const t = document.createElement('b'); t.textContent = s.title; line.appendChild(t);
    if (s.step_kind === 'search') { const c = document.createElement('code'); c.className = 'rulecond'; c.textContent = s.search_soql || 'search'; c.style.marginLeft = '6px'; line.appendChild(c); }
    if (s.step_kind === 'response') { const c = document.createElement('code'); c.className = 'rulecond'; c.textContent = 'réponse : ' + (s.action_kind || ''); c.style.marginLeft = '6px'; line.appendChild(c); }
    if (s.guidance) { line.appendChild(document.createTextNode(' ')); const g = document.createElement('span'); g.className = 'muted'; g.textContent = s.guidance; line.appendChild(g); }
    box.appendChild(line);
  });
  if (!(data.step_list || []).length) box.appendChild(muted('aucune étape'));
  row.appendChild(box); row.stepsEl = box;
}

// Éditeur INLINE (création si id=null, édition sinon). Gabarits d'étapes phasées ajoutables/supprimables.
// Mêmes classes que le formulaire des playbooks (`.ruleform`, `.rf-row`, `.rf-actions`, submit = primaire).
async function openEditor(id) {
  const box = $('#rb-editor'); if (!box) return;
  let data = { name: '', match_kind: '*', match_key: '', description: '', step_list: [], active: true };
  if (id != null) { try { data = await api('/runbooks/' + id); } catch (e) { toast('chargement échoué', 'bad'); return; } }
  box.replaceChildren(); box.classList.remove('hidden');
  const form = document.createElement('form'); form.className = 'ruleform';
  form.appendChild(Object.assign(document.createElement('div'), { textContent: id != null ? 'Éditer le runbook (guide d\'incident)' : 'Nouveau runbook (guide d\'incident)', style: 'font-weight:700' }));

  const row1 = document.createElement('div'); row1.className = 'rf-row';
  const nameI = mkInput('Nom du runbook', data.name); nameI.setAttribute('aria-label', 'Nom du runbook'); nameI.style.flex = '1'; nameI.style.minWidth = '220px';
  const mkindS = mkSelect(['*', 'tactic', 'technique'], data.match_kind);
  const mkeyWrap = document.createElement('span'); mkeyWrap.style.cssText = 'display:inline-flex;gap:4px;align-items:center';
  const rebuildMkey = () => {
    mkeyWrap.replaceChildren();
    if (mkindS.value === 'tactic') { const s = mkSelect(RB_TACTICS, data.match_key); s.dataset.mkey = '1'; mkeyWrap.appendChild(s); }
    else if (mkindS.value === 'technique') { const i = mkInput('T1110', data.match_key); i.dataset.mkey = '1'; mkeyWrap.appendChild(i); }
    else { mkeyWrap.appendChild(muted('repli générique')); }
  };
  mkindS.onchange = rebuildMkey; rebuildMkey();
  row1.append(mkLabel('Nom', nameI), mkLabel('Match', mkindS), mkeyWrap);
  // « ON à l'enregistrement » à la création, comme le formulaire des playbooks (l'API accepte `active`) ; en
  // édition, la bascule vit sur la ligne (override d'activation), le champ n'est pas réécrit.
  let activeCb = null;
  if (id == null) { activeCb = document.createElement('input'); activeCb.type = 'checkbox'; activeCb.checked = true; const l = document.createElement('label'); l.title = 'Coché : le guide est proposé dans les cas dès l\'enregistrement ; décoché : créé OFF, à activer dans la liste'; l.append(activeCb, document.createTextNode(' ON à l\'enregistrement')); row1.appendChild(l); }
  form.appendChild(row1);

  const descI = document.createElement('textarea'); descI.rows = 2; descI.placeholder = 'Description / quand appliquer ce runbook'; descI.value = data.description || '';
  form.appendChild(descI);

  form.appendChild(Object.assign(document.createElement('div'), { textContent: 'ÉTAPES (phasées, ordonnées)', style: 'font-size:11px;font-weight:700;color:var(--mut)' }));
  const stepsBox = document.createElement('div'); form.appendChild(stepsBox);
  const addStep = (s) => stepsBox.appendChild(stepEditor(s || { phase: 'triage', title: '', guidance: '', step_kind: 'manual', search_soql: '', action_kind: 'ban_ip' }));
  (data.step_list || []).forEach(addStep);
  if (!(data.step_list || []).length) addStep();

  const acts = document.createElement('div'); acts.className = 'rf-actions';
  const addBtn = rowButton('+ Étape', { onClick: () => addStep() });
  const saveBtn = document.createElement('button'); saveBtn.type = 'submit'; saveBtn.className = 'btn-primary'; saveBtn.textContent = 'Enregistrer'; // P11.4-b : classe partagée (primaire)
  const cancelBtn = rowButton('Annuler', { onClick: () => { box.classList.add('hidden'); box.replaceChildren(); } });
  const result = document.createElement('span'); result.className = 'muted';
  result.appendChild(destinationNote('cases', '', '')); // P11.1-e : la destination est dite AVANT d'enregistrer
  acts.append(addBtn, saveBtn, cancelBtn, result);
  form.appendChild(acts);
  form.onsubmit = async e => {
    e.preventDefault();
    const steps = [...stepsBox.children].map(readStep).filter(Boolean);
    const mkeyEl = mkeyWrap.querySelector('[data-mkey]');
    const body = {
      name: nameI.value.trim(),
      match_kind: mkindS.value,
      match_key: mkeyEl ? (mkeyEl.value || '').trim() : '',
      description: descI.value.trim(),
      steps,
    };
    if (activeCb) body.active = activeCb.checked;
    if (!body.name) { toast('nom requis', 'bad'); return; }
    if (!steps.length) { toast('au moins une étape', 'bad'); return; }
    const path = id != null ? '/runbooks/' + id : '/runbooks';
    try { await apiSend(path, 'POST', body); } catch (e) { result.textContent = 'Enregistrement refusé : ' + ((e && e.message) || e); toast('Enregistrement refusé : ' + ((e && e.message) || e), 'bad'); return; }
    box.classList.add('hidden'); box.replaceChildren();
    announceCreated('runbooks', 'cases', body.name, body.active === false ? 'OFF : activez-le dans la liste' : ''); // P11.1-e
    loadRunbooks();
  };
  box.appendChild(form);
}

// Une ligne d'éditeur d'étape : phase, titre, guidance, genre, et champ conditionnel (GXQL si search /
// action_kind si response). Les champs hors-genre sont neutralisés côté serveur (validate_step).
function stepEditor(s) {
  // `.rulerow` : la même ligne que les listes (ses boutons portent la charte via `.rulerow button`).
  const el = document.createElement('div'); el.className = 'rulerow rb-step';
  const phase = mkSelect(RB_PHASES, s.phase); phase.dataset.f = 'phase';
  const title = mkInput('Titre de l\'étape', s.title); title.dataset.f = 'title'; title.style.flex = '1';
  const guide = mkInput('Guidance (optionnel)', s.guidance); guide.dataset.f = 'guidance'; guide.style.flex = '1';
  const kind = mkSelect(RB_KINDS, s.step_kind); kind.dataset.f = 'kind';
  const cond = document.createElement('span'); cond.style.cssText = 'display:inline-flex;gap:4px;align-items:center;flex:1;min-width:160px';
  const rebuild = () => {
    cond.replaceChildren();
    if (kind.value === 'search') { const i = mkInput('search host=$target$ | stats count by source', s.search_soql); i.dataset.f = 'soql'; i.style.flex = '1'; cond.append(muted('GXQL'), i); }
    else if (kind.value === 'response') { const sel = mkSelect(RB_ACTIONS, s.action_kind || 'ban_ip'); sel.dataset.f = 'action'; cond.append(muted('action'), sel); }
    else { cond.appendChild(muted('—')); }
  };
  kind.onchange = rebuild; rebuild();
  const rm = rowButton('×', { title: 'retirer l\'étape', onClick: () => el.remove() });
  el.append(phase, title, guide, kind, cond, rm);
  return el;
}
function readStep(el) {
  const g = (f) => { const e = el.querySelector('[data-f="' + f + '"]'); return e ? e.value : ''; };
  const kind = g('kind');
  const step = { phase: g('phase'), title: (g('title') || '').trim(), guidance: (g('guidance') || '').trim(), step_kind: kind };
  if (!step.title) return null;
  if (kind === 'search') step.search_soql = (g('soql') || '').trim();
  if (kind === 'response') step.action_kind = g('action');
  return step;
}

// bouton "+ Runbook" (créer) — câblé au chargement du module.
(function wireNew() {
  const nb = $('#rb-new');
  if (nb) nb.onclick = () => openEditor(null);
})();

loadRunbooks();

export { loadRunbooks, runbookRowModel, rbRow };

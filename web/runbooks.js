// runbooks.js — #3 INCIDENTS Phase 2 : AUTHORING de runbooks (bring-your-own), ADMIN-only.
// Surface d'édition des GABARITS de runbook : liste (managés vs custom, état activé), création/édition d'un
// runbook CUSTOM (nom, clé MITRE tactic/technique, étapes phasées avec guidance, step_kind manual|search|
// response, le GXQL des étapes 'search', l'action_kind des étapes 'response'), clone d'un managé, (dés)activation,
// suppression d'un custom. Le SERVEUR est la vraie garde (route /api/runbooks* = admin-only ; validation temps-
// auteur du GXQL fermé + enum d'action) ; ici l'admin-only n'est que COSMÉTIQUE (panneau masqué au non-admin).
// L'exécution d'une réponse reste /api/actions (INCHANGÉ) — un runbook ne fait que RÉFÉRENCER une action.
import { $, api, apiSend, confirmModal, modal, muted, toast, socIsAdmin } from './core.js';

const RB_PHASES = ['triage', 'investigation', 'containment', 'eradication', 'recovery'];
const RB_KINDS = ['manual', 'search', 'response'];
const RB_ACTIONS = ['ban_ip', 'unban_ip', 'kill_pid', 'stop_service'];
const RB_TACTICS = ['reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'];

function mkSelect(opts, val) {
  const s = document.createElement('select');
  opts.forEach(o => { const e = document.createElement('option'); e.value = o; e.textContent = o; if (o === val) e.selected = true; s.appendChild(e); });
  return s;
}
function mkInput(ph, val) { const i = document.createElement('input'); i.placeholder = ph || ''; i.value = val || ''; i.style.minWidth = '160px'; return i; }
function btn(txt, cls) { const b = document.createElement('button'); b.type = 'button'; b.textContent = txt; if (cls) b.className = cls; return b; }

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
  if (!runbooks.length) { wrap.appendChild(muted('aucun runbook')); return; }
  runbooks.forEach(r => wrap.appendChild(rbRow(r)));
}

function rbRow(r) {
  const el = document.createElement('div'); el.style.cssText = 'display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:6px 0;border-bottom:1px solid color-mix(in srgb,var(--bd) 60%,transparent)';
  const badge = document.createElement('span'); badge.className = 'badge'; badge.textContent = r.managed ? 'managé' : 'custom';
  if (r.managed) { badge.title = 'baseline git — non modifiable en place (clonez pour personnaliser)'; } else { badge.style.borderColor = 'color-mix(in srgb,var(--acc) 50%,transparent)'; badge.style.color = 'var(--acc)'; }
  el.appendChild(badge);
  el.appendChild(Object.assign(document.createElement('span'), { textContent: r.name, style: 'font-weight:600' }));
  el.appendChild(muted(r.match_kind === '*' ? 'défaut' : r.match_kind + ':' + r.match_key));
  el.appendChild(muted(r.steps + ' étape(s)'));
  // activer/désactiver (override d'activation — persiste, survit au reboot ; managé compris).
  const enLbl = document.createElement('label'); enLbl.style.cssText = 'display:flex;gap:4px;align-items:center;font-size:12px';
  const en = document.createElement('input'); en.type = 'checkbox'; en.checked = !!r.active;
  en.onchange = () => apiSend('/runbooks/' + r.id + '/enabled', 'POST', { enabled: en.checked })
    .then(() => toast('runbook ' + (en.checked ? 'activé' : 'désactivé'), 'ok'))
    .catch(err => { en.checked = !en.checked; toast('Bascule refusée : ' + ((err && err.message) || err), 'bad'); });
  enLbl.append(en, document.createTextNode('actif'));
  el.appendChild(enLbl);
  // clone (managé OU custom -> copie custom éditable).
  const cl = btn('Cloner', 'ghost');
  cl.onclick = async () => {
    const m = await modal({ title: 'Cloner le runbook', okText: 'Cloner', fields: [{ name: 'name', label: 'Nom de la copie', value: r.name + ' (copie)' }] });
    if (!m) return;
    try { await apiSend('/runbooks/' + r.id + '/clone', 'POST', { name: (m.name || '').trim() }); } catch (e) { toast('Clone refusé : ' + ((e && e.message) || e), 'bad'); return; }
    toast('Runbook cloné', 'ok'); loadRunbooks();
  };
  el.appendChild(cl);
  // édition / suppression : CUSTOM uniquement (un managé est immuable en place — seuls enable/disable + clone).
  if (!r.managed) {
    const ed = btn('Éditer', 'ghost'); ed.onclick = () => openEditor(r.id); el.appendChild(ed);
    const del = btn('Suppr.', 'ghost');
    del.onclick = async () => {
      if (!await confirmModal('Supprimer le runbook custom « ' + r.name + ' » ?', { danger: true })) return;
      try { await apiSend('/runbooks/' + r.id, 'DELETE'); } catch (e) { toast('Suppression refusée : ' + ((e && e.message) || e), 'bad'); return; }
      toast('Runbook supprimé', 'ok'); loadRunbooks();
    };
    el.appendChild(del);
  } else {
    el.appendChild(muted('immuable (clonez pour éditer)'));
  }
  return el;
}

// Éditeur INLINE (création si id=null, édition sinon). Gabarits d'étapes phasées ajoutables/supprimables.
async function openEditor(id) {
  const box = $('#rb-editor'); if (!box) return;
  let data = { name: '', match_kind: '*', match_key: '', description: '', step_list: [] };
  if (id != null) { try { data = await api('/runbooks/' + id); } catch (e) { toast('chargement échoué', 'bad'); return; } }
  box.replaceChildren(); box.style.display = '';
  box.appendChild(Object.assign(document.createElement('div'), { textContent: id != null ? 'Éditer le runbook custom' : 'Nouveau runbook custom', style: 'font-weight:700;margin-bottom:8px' }));

  const row1 = document.createElement('div'); row1.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px';
  const nameI = mkInput('Nom du runbook', data.name); nameI.style.flex = '1'; nameI.style.minWidth = '220px';
  const mkindS = mkSelect(['*', 'tactic', 'technique'], data.match_kind);
  const mkeyWrap = document.createElement('span'); mkeyWrap.style.cssText = 'display:flex;gap:4px;align-items:center';
  const rebuildMkey = () => {
    mkeyWrap.replaceChildren();
    if (mkindS.value === 'tactic') { const s = mkSelect(RB_TACTICS, data.match_key); s.dataset.mkey = '1'; mkeyWrap.appendChild(s); }
    else if (mkindS.value === 'technique') { const i = mkInput('T1110', data.match_key); i.dataset.mkey = '1'; mkeyWrap.appendChild(i); }
    else { mkeyWrap.appendChild(muted('repli générique')); }
  };
  mkindS.onchange = rebuildMkey; rebuildMkey();
  row1.append(muted('Nom'), nameI, muted('Match'), mkindS, mkeyWrap);
  box.appendChild(row1);

  const descI = document.createElement('textarea'); descI.rows = 2; descI.placeholder = 'Description / quand appliquer ce runbook'; descI.value = data.description || ''; descI.style.cssText = 'width:100%;margin-bottom:8px';
  box.appendChild(descI);

  box.appendChild(Object.assign(document.createElement('div'), { textContent: 'ÉTAPES (phasées, ordonnées)', style: 'font-size:11px;font-weight:700;color:var(--mut);margin:4px 0' }));
  const stepsBox = document.createElement('div'); box.appendChild(stepsBox);
  const addStep = (s) => stepsBox.appendChild(stepEditor(s || { phase: 'triage', title: '', guidance: '', step_kind: 'manual', search_soql: '', action_kind: 'ban_ip' }));
  (data.step_list || []).forEach(addStep);
  if (!(data.step_list || []).length) addStep();

  const acts = document.createElement('div'); acts.style.cssText = 'display:flex;gap:8px;margin-top:10px;flex-wrap:wrap';
  const addBtn = btn('+ Étape'); addBtn.onclick = () => addStep();
  const saveBtn = btn('Enregistrer', 'primary');
  const cancelBtn = btn('Annuler');
  cancelBtn.onclick = () => { box.style.display = 'none'; box.replaceChildren(); };
  saveBtn.onclick = async () => {
    const steps = [...stepsBox.children].map(readStep).filter(Boolean);
    const mkeyEl = mkeyWrap.querySelector('[data-mkey]');
    const body = {
      name: nameI.value.trim(),
      match_kind: mkindS.value,
      match_key: mkeyEl ? (mkeyEl.value || '').trim() : '',
      description: descI.value.trim(),
      steps,
    };
    if (!body.name) { toast('nom requis', 'bad'); return; }
    if (!steps.length) { toast('au moins une étape', 'bad'); return; }
    const path = id != null ? '/runbooks/' + id : '/runbooks';
    try { await apiSend(path, 'POST', body); } catch (e) { toast('Enregistrement refusé : ' + ((e && e.message) || e), 'bad'); return; }
    toast('Runbook enregistré', 'ok'); box.style.display = 'none'; box.replaceChildren(); loadRunbooks();
  };
  acts.append(addBtn, saveBtn, cancelBtn);
  box.appendChild(acts);
}

// Une ligne d'éditeur d'étape : phase, titre, guidance, genre, et champ conditionnel (GXQL si search /
// action_kind si response). Les champs hors-genre sont neutralisés côté serveur (validate_step).
function stepEditor(s) {
  const el = document.createElement('div'); el.style.cssText = 'display:flex;gap:6px;flex-wrap:wrap;align-items:center;padding:6px;margin-bottom:6px;border:1px solid var(--bd);border-radius:6px';
  const phase = mkSelect(RB_PHASES, s.phase); phase.dataset.f = 'phase';
  const title = mkInput('Titre de l\'étape', s.title); title.dataset.f = 'title'; title.style.flex = '1';
  const guide = mkInput('Guidance (optionnel)', s.guidance); guide.dataset.f = 'guidance'; guide.style.flex = '1';
  const kind = mkSelect(RB_KINDS, s.step_kind); kind.dataset.f = 'kind';
  const cond = document.createElement('span'); cond.style.cssText = 'display:flex;gap:4px;align-items:center;flex:1;min-width:160px';
  const rebuild = () => {
    cond.replaceChildren();
    if (kind.value === 'search') { const i = mkInput('search host=$target$ | stats count by source', s.search_soql); i.dataset.f = 'soql'; i.style.flex = '1'; cond.append(muted('GXQL'), i); }
    else if (kind.value === 'response') { const sel = mkSelect(RB_ACTIONS, s.action_kind || 'ban_ip'); sel.dataset.f = 'action'; cond.append(muted('action'), sel); }
    else { cond.appendChild(muted('—')); }
  };
  kind.onchange = rebuild; rebuild();
  const rm = btn('×'); rm.title = 'retirer l\'étape'; rm.onclick = () => el.remove();
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

export { loadRunbooks };

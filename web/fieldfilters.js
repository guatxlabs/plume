// fieldfilters.js — FIELD FILTERS (#45) : UI admin du masquage AU NIVEAU CHAMP (équivalent « Field filters »
// Splunk ; PCI/PII). Additif : tant qu'aucune règle n'existe, toute lecture est inchangée (mode 0). La garde
// réelle est SERVEUR (/api/field-filters admin-only ; le masque est émis DANS le SQL compilé). Anti-XSS : tout
// texte via textContent/esc. La config CONTRAINT viewer/editor — l'admin voit en clair par défaut.
import { $, apiSend, confirmModal, esc, fmtTs, muted, toast, withBusy } from './core.js';
import { uiIsAdmin } from './multitenant.js';

const ACTION_LABEL = {
  mask: 'Masquer (***)',
  partial: 'Partiel (***+4 derniers)',
  hash: 'Hacher (corrélable)',
  redact: 'Supprimer (NULL)',
  deny: 'Interdire (tous, admin compris)',
};
const ROLE_LABEL = { '': 'viewer + editor (défaut)', viewer: 'viewer seul', editor: 'viewer + editor', admin: 'tous (admin compris)' };

let LAST = { rules: [], matrix: {}, actions: [], roles: [] };

export async function loadFieldFilters() {
  const wrap = $('#field-filter-list'); if (!wrap) return;
  const btn = $('#field-filter-new'); if (btn) btn.onclick = () => openForm(null);
  if (!uiIsAdmin()) { wrap.replaceChildren(muted('réservé à l\'administrateur.')); return; }
  let data = null;
  try {
    const r = await fetch('/api/field-filters', { headers: { Accept: 'application/json' } });
    if (!r.ok) { wrap.replaceChildren(muted('erreur (' + r.status + ')')); return; }
    data = await r.json().catch(() => null);
  } catch (e) { wrap.replaceChildren(muted('erreur : ' + ((e && e.message) || e))); return; }
  if (!data) { wrap.replaceChildren(muted('erreur de chargement')); return; }
  LAST = { rules: data.rules || [], matrix: data.matrix || {}, actions: data.actions || ['mask', 'partial', 'hash', 'redact', 'deny'], roles: data.roles || ['', 'viewer', 'editor', 'admin'] };
  render(wrap);
}

function render(wrap) {
  const frag = document.createDocumentFragment();
  if (!LAST.rules.length) {
    frag.appendChild(muted('aucune règle — clique « + Règle » pour masquer un champ (ex : src_user, email, message, src_ip) pour viewer/editor. Tant qu\'aucune règle n\'existe, toute lecture est inchangée (mode 0).'));
  } else {
    for (const r of LAST.rules) frag.appendChild(ruleRow(r));
    frag.appendChild(matrixTable());
  }
  wrap.replaceChildren(frag);
}

function ruleRow(r) {
  const row = document.createElement('div');
  row.style.cssText = 'display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--line,#2c3550)';
  const dot = document.createElement('span');
  dot.textContent = r.enabled ? '●' : '○'; dot.style.color = r.enabled ? 'var(--ok,#4ade80)' : 'var(--muted,#8b93a7)';
  dot.title = r.enabled ? 'activée' : 'désactivée';
  const name = document.createElement('b'); name.textContent = r.name;
  const field = document.createElement('code'); field.textContent = r.field; field.style.cssText = 'font-size:12px';
  const act = document.createElement('span'); act.className = 'muted'; act.style.fontSize = '12px';
  act.textContent = ACTION_LABEL[r.action] || r.action;
  const scope = document.createElement('span'); scope.className = 'muted'; scope.style.cssText = 'font-size:11px';
  const parts = [ROLE_LABEL[r.role] || r.role];
  if (r.tenant) parts.push('tenant=' + r.tenant);
  if (r.env) parts.push('env=' + r.env);
  scope.textContent = parts.join(' · ');
  const meta = document.createElement('span'); meta.className = 'muted'; meta.style.cssText = 'font-size:11px;margin-left:auto';
  meta.textContent = r.updated ? 'maj ' + fmtTs(r.updated) : '';
  const toggle = mkBtn(r.enabled ? 'Désactiver' : 'Activer', async () => {
    await withBusy(toggle, async () => {
      try { await apiSend('/field-filters/' + r.id, 'POST', { enabled: !r.enabled }); toast('mis à jour', 'ok'); loadFieldFilters(); }
      catch (e) { toast('erreur : ' + e.message, 'bad'); }
    });
  });
  const edit = mkBtn('Éditer', () => openForm(r));
  const del = mkBtn('Supprimer', async () => {
    if (!(await confirmModal('Supprimer la règle « ' + r.name + ' » ?'))) return;
    try { await apiSend('/field-filters/' + r.id, 'DELETE'); toast('supprimée', 'ok'); loadFieldFilters(); }
    catch (e) { toast('erreur : ' + e.message, 'bad'); }
  });
  del.style.color = 'var(--bad,#f87171)';
  row.append(dot, name, field, act, scope, meta, toggle, edit, del);
  return row;
}

// Matrice « quel champ est masqué pour quel rôle » (transparence de la politique PII).
function matrixTable() {
  const box = document.createElement('div'); box.style.cssText = 'margin-top:14px;overflow-x:auto';
  const cap = document.createElement('div'); cap.className = 'muted'; cap.style.cssText = 'font-size:12px;margin-bottom:6px';
  cap.textContent = 'Effet par rôle (champ → action appliquée) :';
  const fields = Array.from(new Set(LAST.rules.map((r) => (r.field || '').replace(/^fields\./, '')))).filter(Boolean).sort();
  const roles = ['viewer', 'editor', 'admin'];
  const table = document.createElement('table'); table.style.cssText = 'border-collapse:collapse;font-size:12px';
  const thead = document.createElement('tr');
  thead.appendChild(th('champ'));
  for (const role of roles) thead.appendChild(th(role));
  table.appendChild(thead);
  for (const f of fields) {
    const tr = document.createElement('tr');
    const c0 = document.createElement('td'); c0.style.cssText = cellCss(); const code = document.createElement('code'); code.textContent = f; c0.appendChild(code); tr.appendChild(c0);
    for (const role of roles) {
      const td = document.createElement('td'); td.style.cssText = cellCss();
      const a = (LAST.matrix[role] || {})[f];
      if (a) { td.textContent = a; td.style.color = a === 'deny' ? 'var(--bad,#f87171)' : 'var(--accent,#7aa2f7)'; }
      else { td.textContent = 'en clair'; td.style.color = 'var(--muted,#8b93a7)'; }
      tr.appendChild(td);
    }
    table.appendChild(tr);
  }
  box.append(cap, table);
  return box;
}
function th(t) { const e = document.createElement('th'); e.textContent = t; e.style.cssText = cellCss() + ';text-align:left;font-weight:600'; return e; }
function cellCss() { return 'border:1px solid var(--line,#2c3550);padding:4px 10px'; }

function mkBtn(label, fn) {
  const b = document.createElement('button'); b.type = 'button'; b.textContent = label; b.style.fontSize = '12px'; b.onclick = fn; return b;
}

function openForm(existing) {
  const host = $('#field-filter-form-host'); if (!host) return;
  const e = existing || {};
  const form = document.createElement('form'); form.style.cssText = 'margin:10px 0;padding:10px;border:1px solid var(--line,#2c3550);border-radius:8px;display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end';
  const mkField = (label, node) => {
    const l = document.createElement('label'); l.style.cssText = 'display:flex;flex-direction:column;gap:3px;font-size:12px';
    l.append(document.createTextNode(label), node); return l;
  };
  const mkInput = (val, ph) => { const i = document.createElement('input'); i.type = 'text'; i.value = val || ''; i.placeholder = ph || ''; i.style.minWidth = '120px'; return i; };
  const mkSelect = (opts, val, labeler) => {
    const s = document.createElement('select');
    for (const o of opts) { const op = document.createElement('option'); op.value = o; op.textContent = labeler ? (labeler[o] || o) : o; if (o === val) op.selected = true; s.appendChild(op); }
    return s;
  };
  const nameI = mkInput(e.name, 'nom de la règle');
  const fieldI = mkInput(e.field, 'src_user | email | message | src_ip');
  const actionS = mkSelect(LAST.actions, e.action || 'mask', ACTION_LABEL);
  const roleS = mkSelect(LAST.roles, e.role || '', ROLE_LABEL);
  const tenantI = mkInput(e.tenant, 'tenant (vide = tous)');
  const envI = mkInput(e.env, 'env (vide = tous)');
  form.append(
    mkField('Nom', nameI),
    mkField('Champ', fieldI),
    mkField('Action', actionS),
    mkField('Portée rôle', roleS),
    mkField('Tenant', tenantI),
    mkField('Env', envI),
  );
  const save = document.createElement('button'); save.type = 'submit'; save.textContent = existing ? 'Enregistrer' : 'Créer';
  const cancel = document.createElement('button'); cancel.type = 'button'; cancel.textContent = 'Annuler'; cancel.onclick = () => host.replaceChildren();
  form.append(save, cancel);
  form.onsubmit = async (ev) => {
    ev.preventDefault();
    const body = {
      name: nameI.value.trim(), field: fieldI.value.trim(), action: actionS.value,
      role: roleS.value, tenant: tenantI.value.trim(), env: envI.value.trim(),
    };
    if (!body.name || !body.field) { toast('nom et champ requis', 'bad'); return; }
    await withBusy(save, async () => {
      try {
        if (existing) await apiSend('/field-filters/' + existing.id, 'POST', body);
        else await apiSend('/field-filters', 'POST', body);
        toast('enregistrée', 'ok'); host.replaceChildren(); loadFieldFilters();
      } catch (err) { toast('erreur : ' + err.message, 'bad'); }
    });
  };
  host.replaceChildren(form);
}

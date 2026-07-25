// index_policies.js — #49 Indexes logiques nommés (rétention / plafonds PAR index), admin-only.
// Un index = la valeur env_id d'un event : le MÊME axe que route l'action ROUTE du processeur d'ingest
// (#40) et qu'agrègent les rollups. Un admin définit une rétention propre + des plafonds par index ; un
// index sans politique hérite de la rétention globale. API admin-only :
//   GET  /api/index-policies         -> { global_retention_days, bounds, indexes:[{name,events,oldest_ts,
//                                         size_bytes_est, retention_days, max_rows, max_bytes, has_policy, id, …}] }
//   POST /api/index-policies         -> create ; POST /api/index-policies/:id -> update ; DELETE …/:id
// SÉCU UI : rendu textContent (anti-XSS) ; la VRAIE garde reste serveur (403 hors admin). Défense en
// profondeur : on court-circuite le fetch hors admin.
import { $, api, apiSend, fetchInto, muted, pagedList, toast } from './core.js';
import { uiIsAdmin } from './multitenant.js';

function num(v) { return typeof v === 'number' ? v : 0; }
function fmtBytes(n) {
  n = num(n); if (n < 1024) return n + ' o';
  const u = ['Ko', 'Mo', 'Go', 'To']; let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + ' ' + u[i];
}
function fmtTs(ts) {
  if (!ts) return '—';
  const d = new Date(num(ts) * 1000);
  return d.toISOString().slice(0, 10);
}

export async function loadIndexPolicies() {
  const wrap = $('#index-policy-list'); if (!wrap) return;
  if (!uiIsAdmin()) { wrap.replaceChildren(muted("réservé à l'administrateur.")); return; }
  const data = await fetchInto(wrap, '/index-policies'); if (!data) return;
  const indexes = Array.isArray(data.indexes) ? data.indexes : [];
  const globalDays = num(data.global_retention_days);

  const frag = document.createDocumentFragment();
  const head = document.createElement('div');
  head.className = 'muted'; head.style.cssText = 'margin:0 0 10px;font-size:12px';
  const gb = document.createElement('b'); gb.textContent = globalDays + ' j';
  head.append('Rétention globale (PLUME_RETENTION_DAYS) : ', gb, ' — un index sans politique hérite de cette valeur.');
  frag.appendChild(head);

  const listBox = document.createElement('div');
  if (!indexes.length) {
    listBox.appendChild(muted("aucun index — la rétention globale s'applique à tout (mode 0). Clique « + Index » pour définir une rétention/plafond par env_id, ou route des events vers un env via une règle #40."));
  } else {
    pagedList(listBox, { mode: 'client', pageSize: 50, rows: indexes, renderRow: (r) => indexRow(r, globalDays) });
  }
  frag.appendChild(listBox);
  wrap.replaceChildren(frag);
}

function indexRow(r, globalDays) {
  const row = document.createElement('div'); row.className = 'rulerow';
  row.style.cssText = 'display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:6px 0;border-bottom:1px solid var(--bd,#2222)';

  const name = document.createElement('b'); name.textContent = r.name;
  const stats = document.createElement('span'); stats.className = 'muted'; stats.style.fontSize = '12px';
  stats.textContent = `${num(r.events).toLocaleString('fr')} events · ~${fmtBytes(r.size_bytes_est)} · plus ancien ${fmtTs(r.oldest_ts)}`;

  // Régime de rétention : politique propre OU héritage du global.
  const ret = document.createElement('code');
  if (r.has_policy && num(r.retention_days) > 0) ret.textContent = `${num(r.retention_days)} j`;
  else ret.textContent = `hérite (${globalDays} j)`;
  ret.title = 'rétention effective de cet index';

  const caps = document.createElement('span'); caps.className = 'muted'; caps.style.fontSize = '12px';
  const capParts = [];
  if (num(r.max_rows) > 0) capParts.push(`≤ ${num(r.max_rows).toLocaleString('fr')} lignes`);
  if (num(r.max_bytes) > 0) capParts.push(`≤ ${fmtBytes(r.max_bytes)}`);
  caps.textContent = capParts.length ? '· ' + capParts.join(' · ') : '';

  const spacer = document.createElement('span'); spacer.style.marginLeft = 'auto';

  row.append(name, ret, caps, stats, spacer);

  if (r.has_policy) {
    // toggle actif
    const en = document.createElement('input'); en.type = 'checkbox'; en.checked = r.enabled !== false; en.title = 'active';
    en.onchange = async () => {
      const want = en.checked;
      try { await apiSend('/index-policies/' + r.id, 'POST', { enabled: want }); r.enabled = want; toast(want ? 'index activé' : 'index désactivé', 'ok'); }
      catch (e) { en.checked = !want; toast('échec : ' + ((e && e.message) || e), 'bad'); }
    };
    const edit = document.createElement('button'); edit.type = 'button'; edit.textContent = 'éditer'; edit.className = 'picon';
    edit.onclick = () => openIndexPolicyForm(r);
    const del = document.createElement('button'); del.type = 'button'; del.textContent = 'suppr'; del.className = 'picon';
    del.onclick = async () => {
      if (!confirm('Supprimer la politique de l’index « ' + r.name + ' » ? (l’index retombera sur la rétention globale ; aucun event n’est supprimé)')) return;
      try { await apiSend('/index-policies/' + r.id, 'DELETE'); toast('politique supprimée', 'ok'); loadIndexPolicies(); }
      catch (e) { toast('échec : ' + ((e && e.message) || e), 'bad'); }
    };
    row.append(en, edit, del);
  } else {
    // index découvert sans politique -> proposer d'en créer une (préremplit le nom).
    const define = document.createElement('button'); define.type = 'button'; define.textContent = '+ définir'; define.className = 'picon';
    define.title = 'définir une rétention/plafond pour cet index';
    define.onclick = () => openIndexPolicyForm({ name: r.name });
    row.append(define);
  }
  return row;
}

// Formulaire création/édition. `existing` (facultatif) : { name, id?, retention_days?, max_rows?, max_bytes?,
// description? }. Si id présent -> édition (nom verrouillé) ; sinon création (nom éditable, ou préverrouillé
// s'il vient d'un index découvert).
export function openIndexPolicyForm(existing) {
  const host = $('#index-policy-form'); if (!host) return;
  const isEdit = !!(existing && existing.id != null);
  const prefillName = existing && existing.name ? String(existing.name) : '';
  // toggle-fermeture si on reclique « + Index » à vide.
  if (!host.hidden && !existing) { host.hidden = true; host.replaceChildren(); return; }
  host.hidden = false;
  const mk = (tag, attrs = {}, txt) => { const e = document.createElement(tag); Object.assign(e, attrs); if (txt != null) e.textContent = txt; return e; };

  const name = mk('input', { placeholder: 'Nom de l’index (= env_id, ex: auth)', autocomplete: 'off', value: prefillName });
  if (isEdit || prefillName) name.disabled = true; // le nom (identité) n'est pas renommable
  const ret = mk('input', { type: 'number', min: '0', value: String((existing && existing.retention_days) || 0), title: 'rétention en jours (0 = hérite du global ; sinon planché à 7 j, plafond 3650)' });
  const rows = mk('input', { type: 'number', min: '0', value: String((existing && existing.max_rows) || 0), title: 'plafond de lignes (0 = aucun)' });
  const bytes = mk('input', { type: 'number', min: '0', value: String((existing && existing.max_bytes) || 0), title: 'plafond de taille estimée en octets (0 = aucun)' });
  const desc = mk('input', { placeholder: 'description (optionnel)', autocomplete: 'off', value: (existing && existing.description) || '' });

  const save = mk('button', { type: 'button' }, isEdit ? 'Enregistrer' : 'Créer');
  save.onclick = async () => {
    const body = {
      retention_days: parseInt(ret.value, 10) || 0,
      max_rows: parseInt(rows.value, 10) || 0,
      max_bytes: parseInt(bytes.value, 10) || 0,
      description: desc.value.trim(),
    };
    try {
      if (isEdit) await apiSend('/index-policies/' + existing.id, 'POST', body);
      else await apiSend('/index-policies', 'POST', Object.assign({ name: name.value.trim() }, body));
      toast(isEdit ? 'index enregistré' : 'index créé', 'ok');
      host.hidden = true; host.replaceChildren(); loadIndexPolicies();
    } catch (e) { toast('refus : ' + ((e && e.message) || e), 'bad'); }
  };
  const cancel = mk('button', { type: 'button', className: 'picon' }, 'annuler');
  cancel.onclick = () => { host.hidden = true; host.replaceChildren(); };

  const lab = (t, el) => { const l = mk('label'); l.style.cssText = 'display:flex;flex-direction:column;font-size:11px;gap:2px'; l.append(mk('span', { className: 'muted' }, t), el); return l; };
  const rowA = mk('div', { className: 'rf-row' }); rowA.style.cssText = 'display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end';
  rowA.append(lab('index (env_id)', name), lab('rétention (j, 0=hérite)', ret), lab('max lignes (0=∞)', rows), lab('max octets (0=∞)', bytes), lab('description', desc), save, cancel);
  const hint = mk('div', { className: 'muted' }, 'La rétention 0 = hérite du global. Une valeur > 0 est planchée à 7 j (anti-effacement). Les plafonds gardent les events les PLUS RÉCENTS ; les events de contrôle du daemon ne sont jamais purgés.');
  hint.style.cssText = 'font-size:11px;margin-top:6px';
  host.replaceChildren(rowA, hint);
}

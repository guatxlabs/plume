// processors.js — #40 Processeur d'ingest (edge/ingest pipeline), admin-only.
// Un ADMIN définit des règles ORDONNÉES qui filtrent/masquent/routent/échantillonnent un event AVANT son
// indexation (levier de rétention #1 : « décider ce qu'on n'ingère PAS »). API admin-only :
//   GET /api/processors            -> { rules:[…], counters:{ per_rule, totals, reload_errors } }
//   POST /api/processors           -> create ; POST /api/processors/:id -> update ; DELETE …/:id
//   POST /api/processors/test      -> dry-run { event } -> { verdict, result }
// NON-SILENCE : on affiche les compteurs dropped/masked/routed/sampled_out (la donnée non-indexée est
// VISIBLE — philosophie garde-disque 503). SÉCU UI : rendu textContent (anti-XSS) ; la VRAIE garde reste
// serveur (403 hors admin). Défense en profondeur : on court-circuite le fetch hors admin.
import { $, api, apiSend, fetchInto, muted, pagedList, toast } from './core.js';
import { uiIsAdmin } from './multitenant.js';

const FIELDS = ['category', 'source', 'severity', 'host', 'src_ip', 'dst_ip', 'url', 'message', 'fields.<clé>'];
const OPS = ['eq', 'ne', 'contains', 'regex', 'any'];
const ACTIONS = ['drop', 'mask', 'route', 'sample'];

function num(v) { return typeof v === 'number' ? v : 0; }

export async function loadProcessors() {
  const wrap = $('#processor-list'); if (!wrap) return;
  if (!uiIsAdmin()) { wrap.replaceChildren(muted("réservé à l'administrateur.")); return; }
  const data = await fetchInto(wrap, '/processors'); if (!data) return;
  const rules = Array.isArray(data.rules) ? data.rules : [];
  const counters = data.counters || { per_rule: {}, totals: {}, reload_errors: 0 };

  const frag = document.createDocumentFragment();
  frag.appendChild(totalsBar(counters));
  if (num(counters.reload_errors) > 0) {
    const w = document.createElement('div'); w.className = 'muted';
    w.style.color = 'var(--bad, #c33)';
    w.textContent = `⚠ ${counters.reload_errors} règle(s) invalide(s) ignorée(s) (fail-safe : les events concernés sont indexés inchangés). Corrige-les ci-dessous.`;
    frag.appendChild(w);
  }
  const listBox = document.createElement('div');
  if (!rules.length) {
    listBox.appendChild(muted("aucune règle — l'ingest est byte-identique (tout event est indexé). Clique « + Règle » pour filtrer/masquer/router/échantillonner une source bruyante."));
  } else {
    pagedList(listBox, { mode: 'client', pageSize: 50, rows: rules, renderRow: (r) => ruleRow(r, counters) });
  }
  frag.appendChild(listBox);
  wrap.replaceChildren(frag);
}

function totalsBar(counters) {
  const t = counters.totals || {};
  const bar = document.createElement('div'); bar.className = 'statrow'; bar.style.cssText = 'display:flex;gap:14px;flex-wrap:wrap;margin:0 0 10px;font-size:12px';
  const stat = (label, val, hint) => {
    const s = document.createElement('span'); s.title = hint || '';
    const b = document.createElement('b'); b.textContent = String(num(val));
    s.append(label + ' : ', b);
    return s;
  };
  bar.append(
    stat('non-indexés (policy)', t.not_indexed, 'events NON indexés par une règle DROP ou SAMPLE — comptés, jamais silencieux'),
    stat('droppés', t.dropped),
    stat('masqués', t.masked),
    stat('routés', t.routed),
    stat('échantillonnés-out', t.sampled_out),
  );
  return bar;
}

function ruleRow(r, counters) {
  const row = document.createElement('div'); row.className = 'rulerow';
  row.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:6px 0;border-bottom:1px solid var(--bd,#2222)';

  // actif (POST /api/processors/:id {enabled}) — rollback visuel si le serveur refuse.
  const en = document.createElement('input'); en.type = 'checkbox'; en.checked = !!r.enabled; en.title = 'active';
  en.onchange = async () => {
    const want = en.checked;
    try { await apiSend('/processors/' + r.id, 'POST', { enabled: want }); r.enabled = want; toast(want ? 'règle activée' : 'règle désactivée', 'ok'); }
    catch (e) { en.checked = !want; toast('échec : ' + ((e && e.message) || e), 'bad'); }
  };

  const ord = document.createElement('span'); ord.className = 'muted'; ord.textContent = '#' + num(r.ord); ord.title = "ordre d'évaluation";
  const name = document.createElement('b'); name.textContent = r.name || '(sans nom)';

  // Prédicat lisible : « champ op valeur » (any -> « tout event »).
  const pred = document.createElement('code');
  pred.textContent = r.match_op === 'any' ? 'tout event' : `${r.match_field} ${r.match_op} ${JSON.stringify(r.match_value)}`;

  const arrow = document.createElement('span'); arrow.textContent = '→'; arrow.className = 'muted';

  // Action lisible.
  const act = document.createElement('code');
  const argTxt = r.action_arg ? ` ${r.action_arg}` : '';
  act.textContent = r.action + argTxt;
  act.style.fontWeight = '600';

  // Compteurs par-règle.
  const pr = (counters.per_rule || {})[String(r.id)] || {};
  const cnt = document.createElement('span'); cnt.className = 'muted'; cnt.style.marginLeft = 'auto';
  cnt.textContent = `matched ${num(pr.matched)} · drop ${num(pr.dropped)} · mask ${num(pr.masked)} · route ${num(pr.routed)} · sample-out ${num(pr.sampled_out)}`;

  const del = document.createElement('button'); del.type = 'button'; del.textContent = 'suppr'; del.className = 'picon';
  del.onclick = async () => {
    if (!confirm('Supprimer la règle « ' + (r.name || r.id) + ' » ?')) return;
    try { await apiSend('/processors/' + r.id, 'DELETE'); toast('règle supprimée', 'ok'); loadProcessors(); }
    catch (e) { toast('échec : ' + ((e && e.message) || e), 'bad'); }
  };

  row.append(en, ord, name, pred, arrow, act, cnt, del);
  return row;
}

// Formulaire d'ajout (construit en JS -> pas de markup lourd en index.html). Révélé par « + Règle ».
export function openProcessorForm() {
  const host = $('#processor-form'); if (!host) return;
  if (!host.hidden) { host.hidden = true; host.replaceChildren(); return; }
  host.hidden = false;
  const mk = (tag, attrs = {}, txt) => { const e = document.createElement(tag); Object.assign(e, attrs); if (txt != null) e.textContent = txt; return e; };
  const sel = (opts, val) => { const s = document.createElement('select'); opts.forEach(o => { const op = document.createElement('option'); op.value = o; op.textContent = o; if (o === val) op.selected = true; s.appendChild(op); }); return s; };

  const name = mk('input', { placeholder: 'Nom (ex: drop debug logs)', autocomplete: 'off' });
  const ord = mk('input', { type: 'number', value: '0', title: "ordre d'évaluation (asc)", size: 4 });
  const field = sel(FIELDS, 'category');
  const op = sel(OPS, 'eq');
  const val = mk('input', { placeholder: 'valeur (ou regex)', autocomplete: 'off' });
  const action = sel(ACTIONS, 'drop');
  const arg = mk('input', { placeholder: 'arg : mask=champ · route=env · sample=N', autocomplete: 'off' });

  const hint = mk('span', { className: 'muted' }, '');
  const syncHint = () => {
    const a = action.value;
    hint.textContent = a === 'mask' ? 'arg = champ à masquer (message/host/src_ip/dst_ip/url/fields.<clé>)'
      : a === 'route' ? "arg = environnement cible (classe de rétention / index)"
      : a === 'sample' ? 'arg = N (garde 1 event sur N)'
      : 'DROP : n’indexe pas (compté dropped-by-policy)';
    arg.disabled = (a === 'drop');
    val.disabled = (op.value === 'any');
    field.disabled = (op.value === 'any');
  };
  action.onchange = syncHint; op.onchange = syncHint; syncHint();

  const save = mk('button', { type: 'button' }, 'Créer');
  save.onclick = async () => {
    const body = {
      name: name.value.trim(), ord: parseInt(ord.value, 10) || 0,
      match_field: field.value === 'fields.<clé>' ? (prompt('Clé du champ (fields.<clé>) :', 'fields.') || '') : field.value,
      match_op: op.value, match_value: val.value,
      action: action.value, action_arg: arg.value.trim(),
    };
    try { await apiSend('/processors', 'POST', body); toast('règle créée', 'ok'); host.hidden = true; host.replaceChildren(); loadProcessors(); }
    catch (e) { toast('refus : ' + ((e && e.message) || e), 'bad'); }
  };

  const rowA = mk('div', { className: 'rf-row' }); rowA.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;align-items:center';
  rowA.append(name, ord, field, op, val, mk('span', {}, '→'), action, arg, save);
  const rowB = mk('div', {}); rowB.append(hint);
  host.replaceChildren(rowA, rowB);
}

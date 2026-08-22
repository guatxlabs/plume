// retention.js — rétention (durées éditables + aperçu destructif). Le panneau « Suppressions & whitelists »
// vit dans suppressions.js (extrait d'ici : même patron, un concern par module).
// Extrait d'app.js (decoupe par concern — meme patron que freshness.js).
// PURE MOVE : corps de fonctions IDENTIQUES au monolithe, seuls les import/export sont ajoutes.
// Le cycle app<->module est benin : les fonctions importees d'app.js ne sont appelees qu'a
// l'EXECUTION (handlers/async apres await), jamais a l'evaluation du module.
import { $, muted, api, apiSend, fmtTs, confirmWithConsequence, toast, LOC, tzOpts } from './core.js';
import { S } from './state.js';

const fmtDate = ts => ts ? new Date(ts * 1000).toLocaleDateString(LOC, tzOpts()) : '—';

// ============ RÉTENTION ============
const RET_KEYS = ['retention_days', 'snapshot_days', 'alert_days', 'metric_days', 'metric_raw_hours'];
const RET_LABEL = {
  retention_days: 'Événements', snapshot_days: 'Snapshots', alert_days: 'Alertes closes',
  metric_days: 'Rollups métriques', metric_raw_hours: 'Métriques brutes',
};
const RET_HINT = {
  retention_days: 'logs bruts + rollups horaires',
  snapshot_days: 'instantanés (firewall, contrôles…)',
  alert_days: 'alertes non-ouvertes (les alertes actives sont conservées)',
  metric_days: 'agrégats de métriques',
  metric_raw_hours: 'points de métriques bruts (avant agrégation)',
};
// libellés FR de deleted_kind renvoyé par le preview (events/snapshots/alerts_closed/metric_rollups/metrics_raw)
const DELETED_KIND_LABEL = {
  events: 'événements', snapshots: 'snapshots', alerts_closed: 'alertes closes',
  metric_rollups: 'rollups métriques', metrics_raw: 'points métriques bruts',
};
const unitAbbr = u => u === 'hours' ? 'h' : 'j';
const unitWord = u => u === 'hours' ? 'heures' : 'jours';
/* state: RET_STATE -> S (state.js) */           // {values:{clé:n effectif}, bounds:{clé:{min,max,default,unit}}}
const _retTimers = {};          // debounce du preview par champ

async function loadRetention() {
  const wrap = $('#retention-fields'); if (!wrap) return;
  let d;
  try { d = await api('/retention'); } catch (e) { wrap.replaceChildren(muted('accès refusé ou erreur : ' + e.message)); return; }
  S.RET_STATE = { values: {}, bounds: d.bounds || {} };
  RET_KEYS.forEach(k => { S.RET_STATE.values[k] = Number(d[k]); });
  wrap.replaceChildren(...RET_KEYS.map(retentionField));
  loadRetentionLast();
}
function retentionField(k) {
  const b = S.RET_STATE.bounds[k] || {};
  const unit = b.unit || (k === 'metric_raw_hours' ? 'hours' : 'days');
  const row = document.createElement('div');
  row.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:8px 4px;border-bottom:1px solid var(--bd)';
  const lab = document.createElement('label'); lab.style.cssText = 'display:flex;flex-direction:column;gap:2px;min-width:210px';
  const strong = document.createElement('span'); strong.style.fontWeight = '600'; strong.textContent = RET_LABEL[k] || k;
  const sub = document.createElement('span'); sub.className = 'muted'; sub.style.cssText = 'font-size:11px;margin-top:0'; sub.textContent = RET_HINT[k] || '';
  lab.append(strong, sub);
  const inp = document.createElement('input'); inp.type = 'number'; inp.dataset.key = k; inp.step = '1'; inp.className = 'field'; // P11.4-b : chrome partagé
  inp.value = String(S.RET_STATE.values[k]); inp.style.width = '110px';
  if (b.min != null) inp.min = String(b.min);
  if (b.max != null) inp.max = String(b.max);
  const u = document.createElement('span'); u.className = 'muted'; u.textContent = unitWord(unit);
  const note = document.createElement('span'); note.className = 'muted'; note.dataset.note = k; note.style.cssText = 'font-size:12px;flex:1 1 260px;margin-top:0';
  if (b.min != null && b.max != null) note.title = `plancher ${b.min} · plafond ${b.max} ${unitWord(unit)}`;
  inp.addEventListener('input', () => retPreview(k, inp, note));
  row.append(lab, inp, u, note);
  return row;
}
// aperçu par champ : hausse -> message local (0 purge) ; baisse -> GET /api/retention/preview (compte + ancienneté)
function retPreview(k, inp, note) {
  const cur = S.RET_STATE.values[k];
  const val = parseInt(inp.value, 10);
  const unit = (S.RET_STATE.bounds[k] || {}).unit;
  note.className = 'muted';
  if (!Number.isFinite(val)) { note.textContent = ''; return; }
  if (val === cur) { note.textContent = 'inchangé'; return; }
  if (val > cur) { note.className = 'ok'; note.textContent = `+${val - cur} ${unitAbbr(unit)} · aucune purge`; return; }
  note.textContent = 'calcul de l\'aperçu…';
  clearTimeout(_retTimers[k]);
  _retTimers[k] = setTimeout(async () => {
    let p;
    try { p = await api(`/retention/preview?key=${encodeURIComponent(k)}&value=${val}`); }
    catch (e) { note.className = 'muted'; note.textContent = 'aperçu indisponible'; return; }
    note.className = 'fwarn'; note.textContent = retPreviewText(p);
  }, 300);
}
function retPreviewText(p) {
  const kind = DELETED_KIND_LABEL[p.deleted_kind] || p.deleted_kind || 'entrées';
  const approx = p.approx ? '~' : '';
  const when = p.oldest ? ` (les plus anciens depuis ${fmtDate(p.oldest)})` : '';
  return `supprimera ${approx}${p.deleted} ${kind}${when}`;
}
// dernier changement audité (rend l'audit visible côté rétention) — lu dans le ledger, textContent (B7)
async function loadRetentionLast() {
  const el = $('#retention-last'); if (!el) return;
  let j;
  try { j = await api('/ledger?limit=50'); } catch (e) { el.textContent = ''; return; }
  const entries = j.entries || [];
  const ent = entries.find(x => /retention|config|setting/i.test(x.kind || '')) || entries[0];
  if (!ent) { el.textContent = 'Aucun changement audité pour l\'instant.'; return; }
  el.replaceChildren();
  const pre = document.createElement('span'); pre.className = 'muted'; pre.textContent = 'Dernier changement audité : ';
  const kind = document.createElement('b'); kind.textContent = ent.kind || '?';
  const rest = document.createElement('span'); rest.className = 'muted';
  rest.textContent = (ent.detail ? ' — ' + ent.detail : '') + ' · ' + fmtTs(ent.ts) + ' (voir onglet Audit)';
  el.append(pre, kind, rest);
}
if ($('#retention-refresh')) $('#retention-refresh').onclick = loadRetention;
if ($('#retention-form')) $('#retention-form').addEventListener('submit', async e => {
  e.preventDefault();
  if (!S.RET_STATE) return;
  const res = $('#retention-result');
  const body = {}, decreases = [];
  RET_KEYS.forEach(k => {
    const inp = $(`#retention-fields input[data-key="${k}"]`); if (!inp) return;
    const val = parseInt(inp.value, 10);
    if (!Number.isFinite(val) || val === S.RET_STATE.values[k]) return;
    body[k] = val;
    if (val < S.RET_STATE.values[k]) decreases.push(k);
  });
  if (!Object.keys(body).length) { toast('aucune modification', 'info'); return; }
  // P11.5-b : la rétention est une route SENSIBLE (le démon audite « destructive » quand elle baisse) ->
  // la confirmation partagée est posée À CHAQUE enregistrement et NOMME la conséquence dans les deux sens :
  // une BAISSE purge (aperçu compte + ancienneté, irréversible) ; une HAUSSE ne purge rien mais retient plus
  // longtemps (disque, taille de base). Avant : seule la baisse confirmait, et une hausse partait d'un clic.
  const previews = await Promise.all(decreases.map(k =>
    api(`/retention/preview?key=${encodeURIComponent(k)}&value=${body[k]}`).catch(() => null)));
  const fmtChange = k => { const ua = unitAbbr((S.RET_STATE.bounds[k] || {}).unit); return `${RET_LABEL[k]} ${S.RET_STATE.values[k]}${ua} → ${body[k]}${ua}`; };
  const baisses = decreases.map((k, i) => `${fmtChange(k)} (${previews[i] ? retPreviewText(previews[i]) : 'purge de données anciennes'})`);
  const hausses = Object.keys(body).filter(k => !decreases.includes(k)).map(fmtChange);
  const consequence = (baisses.length ? `PURGE IRRÉVERSIBLE au prochain cycle horaire — ${baisses.join(' ; ')}. ` : '')
    + (hausses.length ? `Conservation allongée, aucune purge — ${hausses.join(' ; ')} : plus d'espace disque et une base plus grande.` : '');
  if (!await confirmWithConsequence('Enregistrer la rétention', consequence.trim(), { danger: baisses.length > 0, okText: baisses.length ? 'Réduire (destructif)' : 'Enregistrer' })) return;
  res.textContent = '...';
  let j;
  try { j = await apiSend('/retention', 'PUT', body); }
  catch (e) { res.textContent = ''; toast((e && e.message) || 'échec', 'bad'); return; }
  j = j || {};
  res.textContent = '';
  toast(`rétention mise à jour (${j.changed != null ? j.changed : Object.keys(body).length} champ(s))`, 'ok');
  loadRetention();
});

export { loadRetention };

// retention.js — retention (durees editables + apercu destructif) & suppressions/whitelists (RO + operator/self)
// Extrait d'app.js (decoupe par concern — meme patron que freshness.js).
// PURE MOVE : corps de fonctions IDENTIQUES au monolithe, seuls les import/export sont ajoutes.
// Le cycle app<->module est benin : les fonctions importees d'app.js ne sont appelees qu'a
// l'EXECUTION (handlers/async apres await), jamais a l'evaluation du module.
import { $, muted, api, apiSend, fetchInto, fmtTs, humanAge, confirmModal, toast, modal, pagedList, ic, LOC, tzOpts } from './core.js';
import { S } from './state.js';
import { uiIsAdmin } from './multitenant.js';

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
  const inp = document.createElement('input'); inp.type = 'number'; inp.dataset.key = k; inp.step = '1';
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
  // H3 : toute BAISSE -> modal destructif avec aperçu (compte + ancienneté), AVANT le PUT.
  if (decreases.length) {
    const previews = await Promise.all(decreases.map(k =>
      api(`/retention/preview?key=${encodeURIComponent(k)}&value=${body[k]}`).catch(() => null)));
    const parts = decreases.map((k, i) => {
      const ua = unitAbbr((S.RET_STATE.bounds[k] || {}).unit);
      const detail = previews[i] ? retPreviewText(previews[i]) : 'purge de données anciennes';
      return `${RET_LABEL[k]} ${S.RET_STATE.values[k]}${ua} → ${body[k]}${ua} (${detail})`;
    });
    const msg = `Réduction destructive de la rétention — ${parts.join(' ; ')}. La purge s'appliquera au prochain cycle horaire et est IRRÉVERSIBLE.`;
    if (!await confirmModal(msg, { title: 'Confirmer la purge', danger: true, okText: 'Réduire (destructif)' })) return;
  }
  res.textContent = '...';
  let j;
  try { j = await apiSend('/retention', 'PUT', body); }
  catch (e) { res.textContent = ''; toast((e && e.message) || 'échec', 'bad'); return; }
  j = j || {};
  res.textContent = '';
  toast(`rétention mise à jour (${j.changed != null ? j.changed : Object.keys(body).length} champ(s))`, 'ok');
  loadRetention();
});

// =================================================================================================
// SUPPRESSIONS & WHITELISTS ACTIVES (chantier « whitelists → webui ») — panneau READ-ONLY agrégeant
// TOUS les filtres/suppressions/whitelists (daemon registre A1..A9 + collecteurs hôte category=config +
// firewall) via GET /api/suppressions (admin-only). Chaque entrée porte son TYPE + la garantie « collecte/
// règles NON modifiées ». SEULE l'exclusion d'affichage operator/self (display-only prouvée, jamais dans
// rule_sql) est éditable (PUT confirmé + audité sev 3) ; collection-reducing / host = mirror-only.
// INVARIANT UI : centraliser la VISIBILITÉ ≠ centraliser le CONTRÔLE — cette console ne pilote AUCUN filtre
// de collecte ni l'hôte ; la seule écriture est un de-bruitage d'affichage qui ne peut créer aucun angle mort.
// =================================================================================================
const SUPP_TYPE_TITLE = {
  'display-only': 'de-bruite un panneau seul — jamais retiré du stockage ni de la détection (rule_sql)',
  'collection-reducing': "réduit l'ingestion/le stockage — read-only ici, contrôle à la frontière hôte",
  'host': 'état firewall/enforcement à la frontière hôte — read-only, visibilité seule',
};
function suppTypeBadge(type) {
  const b = document.createElement('span'); b.className = 'badge'; b.textContent = type || '—';
  const c = type === 'display-only' ? 'var(--ok)' : type === 'collection-reducing' ? 'var(--warn)' : 'var(--mut)';
  b.style.color = c; b.style.borderColor = 'color-mix(in srgb,' + c + ' 40%,transparent)';
  b.title = SUPP_TYPE_TITLE[type] || '';
  return b;
}
function suppSectionTitle(txt, sub) {
  const h = document.createElement('div'); h.className = 'alerthead'; h.style.marginTop = '16px';
  const s = document.createElement('span'); const b = document.createElement('b'); b.textContent = txt; s.appendChild(b);
  if (sub) { const m = document.createElement('span'); m.className = 'muted'; m.style.marginLeft = '8px'; m.textContent = '· ' + sub; s.appendChild(m); }
  h.appendChild(s); return h;
}
async function suppressionsPut(action, value) {
  const b = { action }; if (value !== undefined) b.value = value;
  try { await apiSend('/suppressions', 'PUT', b); }
  catch (e) { toast((e && e.message) || 'échec', 'bad'); return false; }
  return true;
}
async function editSuppression(e) {
  const setAction = e.edit_key === 'operator' ? 'set_operator_excl' : 'set_self_excl';
  const fieldLabel = e.edit_key === 'operator' ? 'IP / préfixes opérateur (CSV)' : 'vhosts self (CSV)';
  const ph = e.edit_key === 'operator' ? 'ex: 203.0.113.7, 2001:db8::/32' : 'ex: plume.example.com';
  const r = await modal({
    title: 'Éditer : ' + e.label, okText: 'Enregistrer', danger: true,
    message: "Exclusion d'AFFICHAGE uniquement — de-bruite les panneaux « menace externe ». N'affecte JAMAIS la collecte, la détection (règles) ni le never-ban (HOST). Action auditée (sev 3).",
    fields: [{ name: 'value', label: fieldLabel, type: 'text', value: e.value || '', placeholder: ph }],
  });
  if (!r) return;
  const val = (r.value || '').trim();
  if (val === (e.value || '')) { toast('aucune modification', 'info'); return; }
  if (!await confirmModal("Appliquer cette exclusion d'AFFICHAGE ? Panneaux uniquement — collecte/détection inchangées. Auditée sev 3.", { danger: true, okText: 'Appliquer' })) return;
  if (await suppressionsPut(setAction, val)) { toast("exclusion d'affichage mise à jour", 'ok'); loadSuppressions(); }
}
async function clearSuppression(e) {
  const clrAction = e.edit_key === 'operator' ? 'clear_operator_excl' : 'clear_self_excl';
  if (!await confirmModal("Réinitialiser l'exclusion d'affichage « " + e.label + " » (retour au défaut / env) ? Panneaux uniquement, audité.", { danger: true, okText: 'Réinitialiser' })) return;
  if (await suppressionsPut(clrAction)) { toast('réinitialisé', 'ok'); loadSuppressions(); }
}
async function loadSuppressions() {
  const wrap = $('#suppressions-body'); if (!wrap) return;
  if (!uiIsAdmin()) { wrap.replaceChildren(muted("réservé à l'administrateur.")); return; }
  const d = await fetchInto(wrap, '/suppressions'); if (!d) return;
  wrap.replaceChildren();
  const valCell = v => { const sp = document.createElement('span'); sp.style.cssText = 'font-family:var(--mono,monospace);font-size:11px;word-break:break-word'; sp.textContent = (v === '' ? '(vide)' : v); sp.title = v; return sp; };
  // ---- (1) DAEMON — registre déclaratif A1..A9 ----
  wrap.appendChild(suppSectionTitle('Daemon — registre déclaratif', (d.daemon || []).length + ' exclusions (lues live)'));
  const dt = document.createElement('div'); wrap.appendChild(dt);
  const dcols = [
    { key: 'label', label: 'Exclusion', sortable: true, sortVal: e => e.label || '', render: e => { const sp = document.createElement('span'); sp.textContent = e.label || e.name; sp.title = e.name; return sp; } },
    { key: 'type', label: 'Type', sortable: true, sortVal: e => e.type || '', render: e => suppTypeBadge(e.type) },
    { key: 'value', label: 'Valeur active', render: e => valCell(e.value) },
    { key: 'scope', label: 'Périmètre', render: e => { const sp = document.createElement('span'); sp.className = 'muted'; sp.style.fontSize = '11px'; sp.textContent = e.scope || ''; sp.title = e.scope || ''; return sp; } },
    { key: 'source', label: 'Provenance (code)', render: e => { const sp = document.createElement('span'); sp.className = 'muted'; sp.style.fontSize = '11px'; sp.textContent = e.source || ''; sp.title = e.source || ''; return sp; } },
    { key: 'actions', label: '', render: e => {
      const box = document.createElement('span'); box.style.whiteSpace = 'nowrap';
      if (e.editable) {
        const ed = document.createElement('button'); ed.type = 'button'; ed.className = 'picon'; ed.innerHTML = ic('pencil');
        ed.title = "Éditer l'exclusion d'affichage (display-only, audité)"; ed.onclick = ev => { ev.stopPropagation(); editSuppression(e); };
        const cl = document.createElement('button'); cl.type = 'button'; cl.className = 'picon'; cl.style.marginLeft = '6px'; cl.innerHTML = ic('x');
        cl.title = 'Réinitialiser (retour au défaut/env)'; cl.onclick = ev => { ev.stopPropagation(); clearSuppression(e); };
        box.append(ed, cl);
      } else {
        const ro = document.createElement('span'); ro.className = 'muted'; ro.style.fontSize = '11px'; ro.textContent = 'read-only'; ro.title = 'contrôle hors de cette console (frontière / lifecycle)'; box.appendChild(ro);
      }
      return box;
    } },
  ];
  pagedList(dt, { mode: 'client', pageSize: 50, rows: d.daemon || [], columns: dcols, emptyText: 'aucune exclusion' });
  // ---- (2) COLLECTEURS HÔTE — auto-report config (category=config) ----
  wrap.appendChild(suppSectionTitle('Collecteurs hôte — filtres auto-reportés', (d.collectors || []).length + ' collecteurs (read-only)'));
  if (!(d.collectors || []).length) {
    wrap.appendChild(muted("aucun collecteur n'a encore auto-reporté sa configuration (event source=<collecteur> category=config). Les filtres apparaîtront dès le prochain passage des collecteurs instrumentés."));
  } else {
    const ct = document.createElement('div'); wrap.appendChild(ct);
    const ccols = [
      { key: 'source', label: 'Collecteur', sortable: true, sortVal: c => c.source || '', render: c => {
        const sp = document.createElement('span'); sp.textContent = c.source || '';
        // PROVENANCE (anti-empoisonnement) : un auto-report NON attesté (host auto-déclaré) ou CONTESTÉ
        // (plusieurs hôtes revendiquent la même source) NE fait PAS foi — badge d'alerte visible pour que
        // le `type` déclaré ne masque jamais silencieusement un vrai filtre.
        if (c.contested || c.attested === false) {
          const w = document.createElement('span'); w.className = 'badge'; w.style.cssText = 'margin-left:6px;background:#c0392b22;color:#e74c3c;border:1px solid #e74c3c55;font-size:10px;padding:1px 5px;border-radius:4px';
          w.textContent = c.contested ? '⚠ hôtes contestés' : '⚠ non attesté';
          w.title = c.contested ? "Plusieurs hôtes distincts auto-reportent cette source — provenance à vérifier (un report peut en usurper un autre)." : "Report auto-déclaré (token non lié à un host) — provenance NON attestée : le type déclaré ne fait pas foi.";
          sp.appendChild(w);
        }
        return sp;
      } },
      { key: 'type', label: 'Type', sortable: true, sortVal: c => c.type || '', render: c => suppTypeBadge(c.type) },
      { key: 'filters', label: 'Filtres déclarés', render: c => {
        const f = (c.fields && c.fields.filters) || null; const box = document.createElement('div');
        if (!f || !Object.keys(f).length) { box.className = 'muted'; box.style.fontSize = '11px'; box.textContent = (c.fields && (c.fields.note || c.fields.enforcement && JSON.stringify(c.fields.enforcement))) || '—'; return box; }
        Object.entries(f).forEach(([k, v]) => {
          const line = document.createElement('div'); line.style.fontSize = '11px';
          const kk = document.createElement('b'); kk.textContent = k + ': '; line.appendChild(kk);
          const vv = document.createElement('span'); vv.textContent = Array.isArray(v) ? (v.join(', ') || '(vide)') : (v === '' ? '(vide)' : String(v)); line.appendChild(vv);
          box.appendChild(line);
        });
        return box;
      } },
      { key: 'ts', label: 'Dernier report', sortable: true, sortVal: c => c.ts || 0, render: c => { const sp = document.createElement('span'); sp.textContent = c.ts ? 'il y a ' + humanAge(Math.max(0, (d.generated || Math.floor(Date.now() / 1000)) - c.ts)) : '—'; if (c.ts) sp.title = fmtTs(c.ts) + (c.host ? ' · ' + c.host : ''); return sp; } },
    ];
    pagedList(ct, { mode: 'client', pageSize: 50, rows: d.collectors, columns: ccols, emptyText: 'aucun' });
  }
  // ---- (3) ÉTAT FIREWALL (hôte) ----
  if (d.firewall && d.firewall.data != null) {
    wrap.appendChild(suppSectionTitle('État firewall (hôte)', 'snapshot' + (d.firewall.host ? ' · ' + d.firewall.host : '')));
    const fw = document.createElement('pre'); fw.style.cssText = 'font-family:var(--mono,monospace);font-size:11px;overflow:auto;max-height:220px;background:var(--bg2,#0002);padding:8px;border-radius:6px;margin:0';
    try { fw.textContent = JSON.stringify(d.firewall.data, null, 2); } catch { fw.textContent = String(d.firewall.data); }
    wrap.appendChild(fw);
  }
  // ---- légende ----
  const legend = document.createElement('div'); legend.className = 'muted'; legend.style.cssText = 'margin-top:14px;font-size:11px';
  legend.textContent = "Types — display-only : de-bruite un panneau seul (jamais la collecte/détection ; operator/self = éditable+audité) · collection-reducing : réduit l'ingestion (read-only, contrôle à la frontière hôte) · host : état firewall/enforcement (read-only). Toute entrée garantit « collecte/règles NON modifiées ». Une édition d'exclusion d'affichage prend effet immédiatement sur les panneaux et est inscrite au journal d'audit (sev 3).";
  wrap.appendChild(legend);
}
if ($('#suppressions-refresh')) $('#suppressions-refresh').onclick = loadSuppressions;

export { loadRetention, loadSuppressions };

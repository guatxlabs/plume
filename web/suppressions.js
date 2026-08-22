// suppressions.js — panneau « Suppressions & whitelists actives » (administration). Extrait de retention.js
// (déplacement pur du panneau), puis complété : les SILENCES d'alertes y reçoivent les trois gestes de
// l'administrateur (créer, modifier, supprimer), chacun audité côté démon.
import { $, muted, api, apiSend, fetchInto, fmtTs, humanAge, confirmWithConsequence, toast, modal, pagedList, ic } from './core.js';
import { uiIsAdmin } from './multitenant.js';

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
  if (!await confirmWithConsequence("Appliquer l'exclusion d'affichage", "ces adresses ou vhosts disparaissent des panneaux « menace externe » (affichage seul : collecte, détection et never-ban inchangés). Action auditée.", { okText: 'Appliquer' })) return;
  if (await suppressionsPut(setAction, val)) { toast("exclusion d'affichage mise à jour", 'ok'); loadSuppressions(); }
}
async function clearSuppression(e) {
  const clrAction = e.edit_key === 'operator' ? 'clear_operator_excl' : 'clear_self_excl';
  if (!await confirmWithConsequence("Réinitialiser l'exclusion d'affichage « " + e.label + " »", 'retour à la valeur par défaut ou à celle de l\'environnement : ce qui était exclu des panneaux y réapparaît. Action auditée.', { okText: 'Réinitialiser' })) return;
  if (await suppressionsPut(clrAction)) { toast('réinitialisé', 'ok'); loadSuppressions(); }
}
// =================================================================================================
// SILENCES D'ALERTES — les « suppressions » que l'administrateur CRÉE, MODIFIE et SUPPRIME (P11.5-a).
// Un silence mute les NOTIFICATIONS des alertes qui correspondent à {champ=valeur,…} jusqu'à son expiration
// (TTL borné côté démon : jamais permanent). Les alertes restent stockées et visibles dans la file : un
// silence ne crée aucun angle mort de détection, seulement un silence de notification. Routes : POST /silences
// (créer), PUT /silences/:id (modifier — ajoutée pour ce panneau), DELETE /silences/:id (lever) ; chacune
// est auditée (ledger + event plume-config, sévérité 3).
// =================================================================================================
const SILENCE_FIELDS = ['severity', 'mitre', 'host', 'source', 'env', 'tag']; // miroir de MATCHER_FIELDS (alerting.rs)
function silenceMatchersFromText(raw) {
  const out = {};
  String(raw || '').split(',').map(x => x.trim()).filter(Boolean).forEach(pair => {
    const i = pair.indexOf('=');
    if (i < 0) throw new Error('matcher invalide (attendu champ=valeur) : ' + pair);
    const k = pair.slice(0, i).trim(), v = pair.slice(i + 1).trim();
    if (!SILENCE_FIELDS.includes(k)) throw new Error("champ non autorisé : '" + k + "' (autorisés : " + SILENCE_FIELDS.join(', ') + ')');
    if (!v) throw new Error('valeur vide pour ' + k);
    out[k] = v;
  });
  return out;
}
function silenceMatchersToText(obj) { return Object.entries(obj || {}).map(([k, v]) => k + '=' + v).join(', '); }

// Fenêtre partagée de création / modification : la confirmation NOMME la conséquence au-dessus des champs.
async function silenceDialog(existing) {
  const isEdit = !!existing;
  const minutesLeft = isEdit ? Math.max(1, Math.round((existing.expires_at - Math.floor(Date.now() / 1000)) / 60)) : 60;
  const r = await confirmWithConsequence(isEdit ? 'Modifier le silence #' + existing.id : 'Créer un silence d\'alertes',
    'les alertes qui correspondent à ces matchers ne seront PLUS NOTIFIÉES jusqu\'à l\'expiration ; elles restent stockées et visibles dans la file. Action auditée.', {
    danger: true, okText: isEdit ? 'Enregistrer' : 'Créer le silence',
    fields: [
      { name: 'matchers', label: 'Matchers (champ=valeur, …)', value: isEdit ? silenceMatchersToText(existing.matchers) : '', placeholder: 'ex : host=web-01, severity=2', required: true },
      { name: 'minutes', label: isEdit ? 'Durée restante (min)' : 'Durée (min)', type: 'number', value: String(minutesLeft), required: true },
      { name: 'reason', label: 'Raison', value: isEdit ? (existing.reason || '') : '', placeholder: 'ex : maintenance planifiée' },
    ],
    validate: v => {
      try { if (!Object.keys(silenceMatchersFromText(v.matchers)).length) return 'au moins un matcher requis'; } catch (e) { return e.message; }
      if (!(parseInt(v.minutes, 10) > 0)) return 'durée en minutes > 0 requise';
      return null;
    },
  });
  if (!r) return;
  const body = { matchers: silenceMatchersFromText(r.matchers), duration_s: parseInt(r.minutes, 10) * 60, reason: String(r.reason || '').trim() };
  try {
    if (isEdit) await apiSend('/silences/' + existing.id, 'PUT', body);
    else await apiSend('/silences', 'POST', body);
  } catch (e) { toast((e && e.message) || 'échec', 'bad'); return; }
  toast(isEdit ? 'silence modifié' : 'silence créé', 'ok');
  loadSuppressions();
}
async function deleteSilence(s) {
  if (!await confirmWithConsequence('Lever le silence #' + s.id, 'les alertes « ' + silenceMatchersToText(s.matchers) + ' » seront de nouveau notifiées dès la prochaine occurrence. Action auditée.', { okText: 'Lever' })) return;
  try { await apiSend('/silences/' + s.id, 'DELETE'); } catch (e) { toast((e && e.message) || 'échec', 'bad'); return; }
  toast('silence levé', 'ok'); loadSuppressions();
}
function silencesSection(wrap, d) {
  const rows = (d && Array.isArray(d.silences)) ? d.silences : [];
  const head = suppSectionTitle('Silences d\'alertes', rows.filter(x => x.active).length + ' actif(s) sur ' + rows.length + ' — notifications mutées, alertes conservées');
  const add = document.createElement('button'); add.type = 'button'; add.className = 'btn btn-sm'; add.textContent = '+ Silence'; add.title = 'Créer un silence (mute temporisé des notifications)';
  add.onclick = () => silenceDialog(null);
  head.appendChild(add);
  wrap.appendChild(head);
  const host = document.createElement('div'); wrap.appendChild(host);
  const cols = [
    { key: 'matchers', label: 'Matchers', render: s => { const c = document.createElement('code'); c.className = 'rulecond'; c.textContent = silenceMatchersToText(s.matchers); return c; } },
    { key: 'state', label: 'État', sortable: true, sortVal: s => s.active ? 1 : 0, render: s => { const b = document.createElement('span'); b.className = 'badge'; b.textContent = s.active ? 'actif' : 'expiré'; b.style.color = s.active ? 'var(--warn)' : 'var(--mut)'; return b; } },
    { key: 'expires_at', label: 'Expire', sortable: true, sortVal: s => s.expires_at || 0, render: s => fmtTs(s.expires_at) },
    { key: 'reason', label: 'Raison', render: s => { const sp = document.createElement('span'); sp.className = 'muted'; sp.textContent = s.reason || '—'; return sp; } },
    { key: 'created_by', label: 'Par', render: s => { const sp = document.createElement('span'); sp.className = 'muted'; sp.textContent = s.created_by || '—'; return sp; } },
    { key: 'actions', label: '', render: s => {
      const box = document.createElement('span'); box.style.whiteSpace = 'nowrap';
      const ed = document.createElement('button'); ed.type = 'button'; ed.className = 'picon'; ed.innerHTML = ic('pencil'); ed.title = 'Modifier (matchers, durée, raison)'; ed.onclick = ev => { ev.stopPropagation(); silenceDialog(s); };
      const dl = document.createElement('button'); dl.type = 'button'; dl.className = 'picon'; dl.style.marginLeft = '6px'; dl.innerHTML = ic('x'); dl.title = 'Lever le silence'; dl.onclick = ev => { ev.stopPropagation(); deleteSilence(s); };
      box.append(ed, dl); return box;
    } },
  ];
  pagedList(host, { mode: 'client', pageSize: 50, rows, columns: cols, emptyText: 'aucun silence — « + Silence » pour muter temporairement les notifications d\'une règle, d\'un hôte ou d\'une source.' });
}

async function loadSuppressions() {
  const wrap = $('#suppressions-body'); if (!wrap) return;
  if (!uiIsAdmin()) { wrap.replaceChildren(muted("réservé à l'administrateur.")); return; }
  const d = await fetchInto(wrap, '/suppressions'); if (!d) return;
  // les silences viennent de leur propre route (viewer+ en lecture) ; une erreur ici ne vide pas le panneau.
  let silences = null; try { silences = await api('/silences'); } catch (e) { silences = { silences: [], error: (e && e.message) || String(e) }; }
  wrap.replaceChildren();
  const valCell = v => { const sp = document.createElement('span'); sp.style.cssText = 'font-family:var(--font-mono);font-size:11px;word-break:break-word'; sp.textContent = (v === '' ? '(vide)' : v); sp.title = v; return sp; };
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
  // ---- (1bis) SILENCES D'ALERTES — créer / modifier / supprimer (P11.5-a) ----
  silencesSection(wrap, silences);
  if (silences && silences.error) wrap.appendChild(muted('silences indisponibles : ' + silences.error));
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
    // DÉNOMINATEUR EXPLICITE : cette section montrait l'état d'UNE machine sans jamais dire combien il y
    // en avait (mesuré : 1 hôte rendu pour un parc de 50). `firewall_n_hosts` est le dénominateur.
    const nfw = d.firewall_n_hosts || 0;
    wrap.appendChild(suppSectionTitle('État firewall (hôte)', 'snapshot' + (d.firewall.host ? ' · ' + d.firewall.host : '')
      + (nfw > 1 ? ` · 1 machine sur ${nfw} (voir Flotte pour les autres)` : '')));
    const fw = document.createElement('pre'); fw.style.cssText = 'font-family:var(--font-mono);font-size:11px;overflow:auto;max-height:220px;background:var(--card);border:1px solid var(--bd);padding:8px;border-radius:6px;margin:0'; // P11.4-c : variables de thème réelles (`--bg2`/`--mono` n'existaient pas)
    try { fw.textContent = JSON.stringify(d.firewall.data, null, 2); } catch { fw.textContent = String(d.firewall.data); }
    wrap.appendChild(fw);
  }
  // ---- légende ----
  const legend = document.createElement('div'); legend.className = 'muted'; legend.style.cssText = 'margin-top:14px;font-size:11px';
  legend.textContent = "Types — display-only : de-bruite un panneau seul (jamais la collecte/détection ; operator/self = éditable+audité) · collection-reducing : réduit l'ingestion (read-only, contrôle à la frontière hôte) · host : état firewall/enforcement (read-only). Toute entrée garantit « collecte/règles NON modifiées ». Une édition d'exclusion d'affichage prend effet immédiatement sur les panneaux et est inscrite au journal d'audit (sev 3).";
  wrap.appendChild(legend);
}
if ($('#suppressions-refresh')) $('#suppressions-refresh').onclick = loadSuppressions;

export { loadSuppressions };

// detadv.js — #37 Détection avancée : corrélations multi-événements (finding-groups) + baselines UEBA.
// Vit dans l'espace DÉTECTION & RÉPONSE. Lecture viewer+ ; CRUD éditeur+ (le viewer voit en lecture seule,
// boutons masqués via CSS role-viewer + garde SERVEUR editor+). Endpoints :
//   GET  /api/correlations            -> {correlations:[{id,name,enabled,key_field,entity_type,steps,window_s,interval_s,severity,mitre,risk_score,last_run,last_fired,managed}]}
//   POST /api/correlations            -> crée ; POST /api/correlations/:id -> édite ; DELETE -> supprime
//   POST /api/correlations/:id/test   -> backtest {ok,matched,entities:[{entity,detail}]}
//   GET  /api/baselines / POST … /:id / DELETE … / POST …/:id/test (aperçu {ok,bucket,observed,anomalies,hits})
// SÉCU UI : tout en textContent/esc (anti-XSS). Mutations via apiSend (CSRF auto).
import { $, api, apiSend, esc, fetchInto, fmtTs, humanAge, muted, pagedList, sev, toast, modal, confirmModal } from './core.js';

// ---- helpers ----
function stepCount(stepsJson) {
  try { const a = JSON.parse(stepsJson || '[]'); return Array.isArray(a) ? a.length : 0; } catch { return 0; }
}
function actionsCell(onTest, onEdit, onDel) {
  const wrap = document.createElement('span'); wrap.className = 'row-actions';
  const mk = (label, title, cls, fn) => { const b = document.createElement('button'); b.type = 'button'; b.className = 'picon' + (cls ? ' ' + cls : ''); b.textContent = label; b.title = title; b.onclick = e => { e.stopPropagation(); fn(); }; return b; };
  wrap.appendChild(mk('Test', 'Backtest / aperçu sur la fenêtre courante', '', onTest));
  const ed = mk('Éditer', 'Modifier', 'crud-btn', onEdit);   // masqué au viewer (CSS body.role-viewer .crud-btn)
  const dl = mk('Suppr.', 'Supprimer', 'crud-btn', onDel);
  wrap.append(ed, dl);
  return wrap;
}

// ============================ CORRÉLATIONS ============================

async function loadCorrelations() {
  const host = $('#detadv-corr-list'); if (!host) return;
  const d = await fetchInto(host, '/correlations'); if (!d) return;
  const rows = (d && Array.isArray(d.correlations)) ? d.correlations : [];
  const nowS = Math.floor(Date.now() / 1000);
  pagedList(host, {
    mode: 'client', pageSize: 25, rows,
    sort: { key: 'id', dir: 1 },
    columns: [
      { key: 'name', label: 'Nom', sortable: true, sortVal: r => r.name || '', render: r => { const s = document.createElement('span'); s.textContent = r.name || ''; if (!r.enabled) { s.style.opacity = '.5'; s.title = 'désactivée'; } return s; } },
      { key: 'entity_type', label: 'Entité', sortable: true, sortVal: r => r.entity_type || '', render: r => { const c = document.createElement('code'); c.textContent = (r.entity_type || '?') + ' (' + (r.key_field || '?') + ')'; return c; } },
      { key: 'steps', label: 'Étapes', align: 'r', render: r => String(stepCount(r.steps)) },
      { key: 'window_s', label: 'Fenêtre', align: 'r', sortable: true, sortVal: r => r.window_s || 0, render: r => humanAge(r.window_s || 0) },
      { key: 'severity', label: 'Sév.', sortable: true, sortVal: r => r.severity || 0, render: r => { const s = document.createElement('span'); s.className = 'sev'; s.textContent = sev(r.severity); return s; } },
      { key: 'mode', label: 'Mode', render: r => (r.risk_score > 0 ? 'RBA +' + r.risk_score : 'alerte') },
      { key: 'mitre', label: 'MITRE', sortable: true, sortVal: r => r.mitre || '', render: r => { const c = document.createElement('code'); c.textContent = r.mitre || '—'; return c; } },
      { key: 'last_fired', label: 'Dernier tir', sortable: true, sortVal: r => r.last_fired || 0, render: r => { const s = document.createElement('span'); s.textContent = r.last_fired ? 'il y a ' + humanAge(nowS - r.last_fired) : '—'; if (r.last_fired) s.title = fmtTs(r.last_fired); return s; } },
      { key: 'act', label: '', render: r => actionsCell(() => testCorrelation(r), () => editCorrelation(r), () => deleteCorrelation(r)) },
    ],
    emptyText: 'aucune corrélation définie — crée une séquence (ex. « échec auth ×N puis succès même IP ») pour lever des finding-groups.',
  });
}

function corrFields(c) {
  c = c || {};
  return [
    { name: 'name', label: 'Nom', value: c.name || '', required: true },
    { name: 'key_field', label: 'Champ de clé (entité)', value: c.key_field || 'src_ip', placeholder: 'src_ip | user | host' },
    { name: 'entity_type', label: "Type d'entité", value: c.entity_type || 'ip', placeholder: 'ip | user | host' },
    { name: 'steps', label: 'Étapes (JSON ordonné)', type: 'textarea', value: c.steps || '[{"name":"échec","query":"search source=auth outcome=fail","min_count":3},{"name":"succès","query":"search source=auth outcome=success","min_count":1}]', placeholder: '[{"name":"…","query":"search …","min_count":1}]' },
    { name: 'window_s', label: 'Fenêtre (s)', type: 'number', value: c.window_s == null ? 3600 : c.window_s },
    { name: 'interval_s', label: 'Intervalle éval (s)', type: 'number', value: c.interval_s == null ? 300 : c.interval_s },
    { name: 'severity', label: 'Sévérité (0-4)', type: 'number', value: c.severity == null ? 3 : c.severity },
    { name: 'mitre', label: 'MITRE (Txxxx)', value: c.mitre || '' },
    { name: 'risk_score', label: 'Score RBA (0 = alerte directe)', type: 'number', value: c.risk_score == null ? 0 : c.risk_score },
    { name: 'enabled', label: 'Activée', type: 'checkbox', value: c.enabled == null ? true : !!c.enabled },
  ];
}
function corrPayload(v) {
  let steps; try { steps = JSON.parse(v.steps || '[]'); } catch { steps = null; }
  return {
    name: v.name, key_field: (v.key_field || '').trim(), entity_type: (v.entity_type || '').trim(),
    steps: steps == null ? v.steps : steps, // laisse le serveur rejeter un JSON invalide avec un message clair
    window_s: Number(v.window_s) || 3600, interval_s: Number(v.interval_s) || 300,
    severity: Number(v.severity) || 0, mitre: (v.mitre || '').trim(), risk_score: Number(v.risk_score) || 0,
    enabled: !!v.enabled,
  };
}
async function editCorrelation(c) {
  const isNew = !c;
  const v = await modal({ title: isNew ? 'Nouvelle corrélation' : 'Éditer la corrélation', okText: isNew ? 'Créer' : 'Enregistrer', fields: corrFields(c) });
  if (!v) return;
  try {
    await apiSend(isNew ? '/correlations' : '/correlations/' + c.id, 'POST', corrPayload(v));
    toast(isNew ? 'corrélation créée' : 'corrélation enregistrée', 'ok');
    loadCorrelations();
  } catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); }
}
async function deleteCorrelation(c) {
  if (!(await confirmModal('Supprimer la corrélation « ' + c.name + ' » ?', { okText: 'Supprimer', danger: true }))) return;
  try { await apiSend('/correlations/' + c.id, 'DELETE'); toast('corrélation supprimée', 'ok'); loadCorrelations(); }
  catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); }
}
async function testCorrelation(c) {
  let d;
  try { d = await apiSend('/correlations/' + c.id + '/test', 'POST', {}); } catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); return; }
  if (!d || d.error) { toast('échec : ' + ((d && d.error) || 'inconnu'), 'err', 6000); return; }
  const ents = Array.isArray(d.entities) ? d.entities : [];
  const body = document.createElement('div');
  const h = document.createElement('p'); h.textContent = d.matched + ' entité(s) complètent la séquence sur la fenêtre courante.'; body.appendChild(h);
  const list = document.createElement('div');
  pagedList(list, { mode: 'client', pageSize: 15, rows: ents, columns: [
    { key: 'entity', label: 'Entité', render: r => { const c2 = document.createElement('code'); c2.textContent = r.entity || ''; return c2; } },
    { key: 'detail', label: 'Séquence', render: r => { const s = document.createElement('span'); s.textContent = r.detail || ''; return s; } },
  ], emptyText: 'aucune entité ne complète la séquence (rien à lever).' });
  body.appendChild(list);
  showResultModal('Backtest — ' + c.name, body);
}

// ============================ BASELINES (UEBA) ============================

async function loadBaselines() {
  const host = $('#detadv-base-list'); if (!host) return;
  const d = await fetchInto(host, '/baselines'); if (!d) return;
  const rows = (d && Array.isArray(d.baselines)) ? d.baselines : [];
  pagedList(host, {
    mode: 'client', pageSize: 25, rows, sort: { key: 'id', dir: 1 },
    columns: [
      { key: 'name', label: 'Nom', sortable: true, sortVal: r => r.name || '', render: r => { const s = document.createElement('span'); s.textContent = r.name || ''; if (!r.enabled) { s.style.opacity = '.5'; s.title = 'désactivée'; } return s; } },
      { key: 'entity_type', label: 'Entité', render: r => { const c = document.createElement('code'); c.textContent = (r.entity_type || '?') + ' (' + (r.entity_field || '?') + ')'; return c; } },
      { key: 'bucket_s', label: 'Bucket', align: 'r', render: r => humanAge(r.bucket_s || 0) },
      { key: 'z_threshold', label: 'Seuil z', align: 'r', sortable: true, sortVal: r => r.z_threshold || 0, render: r => String(r.z_threshold) },
      { key: 'min_samples', label: 'Min éch.', align: 'r', render: r => String(r.min_samples) },
      { key: 'mode', label: 'Mode', render: r => (r.risk_score > 0 ? 'RBA +' + r.risk_score : 'alerte') },
      { key: 'mitre', label: 'MITRE', render: r => { const c = document.createElement('code'); c.textContent = r.mitre || '—'; return c; } },
      { key: 'act', label: '', render: r => actionsCell(() => testBaseline(r), () => editBaseline(r), () => deleteBaseline(r)) },
    ],
    emptyText: 'aucune baseline définie — crée une métrique par entité (ex. « volume auth par hôte ») pour détecter les déviations (z-score).',
  });
}

function baseFields(b) {
  b = b || {};
  return [
    { name: 'name', label: 'Nom', value: b.name || '', required: true },
    { name: 'query', label: 'Requête GXQL (entité + valeur)', type: 'textarea', value: b.query || 'search source=auth | stats count by host', placeholder: 'search … | stats count by host' },
    { name: 'entity_field', label: "Champ d'entité", value: b.entity_field || 'host', required: true },
    { name: 'value_field', label: 'Champ de valeur (vide = dernière colonne)', value: b.value_field || '' },
    { name: 'entity_type', label: "Type d'entité", value: b.entity_type || 'host' },
    { name: 'bucket_s', label: 'Bucket (s)', type: 'number', value: b.bucket_s == null ? 3600 : b.bucket_s },
    { name: 'min_samples', label: 'Échantillons min.', type: 'number', value: b.min_samples == null ? 5 : b.min_samples },
    { name: 'z_threshold', label: 'Seuil de déviation (z)', type: 'number', value: b.z_threshold == null ? 3 : b.z_threshold },
    { name: 'window_s', label: 'Horizon baseline (s)', type: 'number', value: b.window_s == null ? 604800 : b.window_s },
    { name: 'interval_s', label: 'Intervalle éval (s)', type: 'number', value: b.interval_s == null ? 3600 : b.interval_s },
    { name: 'severity', label: 'Sévérité (0-4)', type: 'number', value: b.severity == null ? 2 : b.severity },
    { name: 'mitre', label: 'MITRE (Txxxx)', value: b.mitre || '' },
    { name: 'risk_score', label: 'Score RBA (0 = alerte directe)', type: 'number', value: b.risk_score == null ? 0 : b.risk_score },
    { name: 'enabled', label: 'Activée', type: 'checkbox', value: b.enabled == null ? true : !!b.enabled },
  ];
}
function basePayload(v) {
  return {
    name: v.name, query: v.query, entity_field: (v.entity_field || '').trim(), value_field: (v.value_field || '').trim(),
    entity_type: (v.entity_type || '').trim(), bucket_s: Number(v.bucket_s) || 3600, min_samples: Number(v.min_samples) || 5,
    z_threshold: Number(v.z_threshold) || 3, window_s: Number(v.window_s) || 604800, interval_s: Number(v.interval_s) || 3600,
    severity: Number(v.severity) || 0, mitre: (v.mitre || '').trim(), risk_score: Number(v.risk_score) || 0, enabled: !!v.enabled,
  };
}
async function editBaseline(b) {
  const isNew = !b;
  const v = await modal({ title: isNew ? 'Nouvelle baseline' : 'Éditer la baseline', okText: isNew ? 'Créer' : 'Enregistrer', fields: baseFields(b) });
  if (!v) return;
  try {
    await apiSend(isNew ? '/baselines' : '/baselines/' + b.id, 'POST', basePayload(v));
    toast(isNew ? 'baseline créée' : 'baseline enregistrée', 'ok');
    loadBaselines();
  } catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); }
}
async function deleteBaseline(b) {
  if (!(await confirmModal('Supprimer la baseline « ' + b.name + ' » ?', { okText: 'Supprimer', danger: true }))) return;
  try { await apiSend('/baselines/' + b.id, 'DELETE'); toast('baseline supprimée', 'ok'); loadBaselines(); }
  catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); }
}
async function testBaseline(b) {
  let d;
  try { d = await apiSend('/baselines/' + b.id + '/test', 'POST', {}); } catch (e) { toast('erreur : ' + ((e && e.message) || e), 'err', 6000); return; }
  if (!d || d.error) { toast('échec : ' + ((d && d.error) || 'inconnu'), 'err', 6000); return; }
  const hits = Array.isArray(d.hits) ? d.hits : [];
  const body = document.createElement('div');
  const h = document.createElement('p'); h.textContent = 'Bucket ' + d.bucket + ' — ' + d.observed + ' entité(s) observée(s), ' + d.anomalies + ' anomalie(s) (aucune écriture).'; body.appendChild(h);
  const list = document.createElement('div');
  pagedList(list, { mode: 'client', pageSize: 15, rows: hits, sort: { key: 'z', dir: -1 }, columns: [
    { key: 'entity', label: 'Entité', render: r => { const c = document.createElement('code'); c.textContent = r.entity || ''; return c; } },
    { key: 'value', label: 'Valeur', align: 'r', sortable: true, sortVal: r => r.value || 0, render: r => String(r.value) },
    { key: 'z', label: 'Déviation z', align: 'r', sortable: true, sortVal: r => r.z || 0, render: r => { const s = document.createElement('b'); s.textContent = (r.z == null ? '' : r.z.toFixed(2)); s.style.color = 'var(--sev4)'; return s; } },
  ], emptyText: 'aucune anomalie au dernier bucket clos (les valeurs restent dans la baseline).' });
  body.appendChild(list);
  showResultModal('Aperçu baseline — ' + b.name, body);
}

// ---- petite modale de résultat (lecture seule) réutilisée par les deux "Test" ----
function showResultModal(title, bodyEl) {
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal'; box.style.maxWidth = '640px';
  const h = document.createElement('h3'); h.textContent = title; box.appendChild(h);
  box.appendChild(bodyEl);
  const act = document.createElement('div'); act.className = 'modal-act';
  const ok = document.createElement('button'); ok.type = 'button'; ok.className = 'm-ok'; ok.textContent = 'Fermer';
  const close = () => { ov.classList.add('out'); setTimeout(() => ov.remove(), 160); };
  ok.onclick = close; act.appendChild(ok); box.appendChild(act);
  ov.onclick = e => { if (e.target === ov) close(); };
  ov.appendChild(box); document.body.appendChild(ov);
}

// ---- entrée : charge les deux listes + branche les boutons "Nouveau" ----
function loadDetAdv() {
  const nc = $('#detadv-corr-new'); if (nc) nc.onclick = () => editCorrelation(null);
  const nb = $('#detadv-base-new'); if (nb) nb.onclick = () => editBaseline(null);
  loadCorrelations();
  loadBaselines();
}

export { loadDetAdv };
